//! Builtins seguros (gateados por capability). Port de `capabilities/enforcer.py`
//! (SecureOperations) + `capabilities/builtins.py` (register_secure_builtins).
//!
//! Reemplazan I/O cruda por operaciones chequeadas. La violación produce un
//! `Runtime error: Capability not granted: <cap>` (sin ubicación — la
//! capabilityViolation no la lleva; el prefijo de categoría lo agrega el motor).
//!
//! Capa 5: read_file/write_file/run hacen la op real (filesystem/proceso). El HTTP
//! (fetch/http_*) vive en synsema-stdlib/http.rs, gateado por `net`.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};
use indexmap::IndexMap;
use regex::RegexBuilder;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{
    syn_bool, syn_bytes, syn_float, syn_int, syn_list, syn_map, syn_text, SynValue,
};

use crate::model::{
    fnmatch, normalize_path, Capability, CapabilityAuditEntry, CapabilityType, CapabilitySet, BUNDLED_ASSET,
};

/// `str(value.raw)` estilo Python (texto crudo).
fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i)
        .ok_or_else(|| Control::Error(RuntimeError::new("missing argument")))
}

/// Lectura servida desde el bundle (`synsema build`): el asset es PARTE del programa,
/// así que no pide `file.read` — pero queda en el audit, con la razón explícita. Pública
/// para que cualquier builtin que lea un asset del bundle (el `from` de `zip_create`, las
/// `fonts` de `svg_to_*`) deje la misma línea que `read_file`.
pub fn bundled_audit(caps: &Rc<RefCell<CapabilitySet>>, ty: CapabilityType, path: &str, source: &str) {
    caps.borrow_mut().push_audit(CapabilityAuditEntry {
        capability: Capability::new(ty, Some(path.to_string())),
        granted: true,
        source: source.to_string(),
        reason: BUNDLED_ASSET.to_string(),
        origin: "runtime",
    });
}

/// Un path que está en el bundle es de sólo lectura: escribirlo sería mentir (la próxima
/// lectura seguiría viniendo del bundle).
fn reject_bundled_write(path: &str) -> Result<(), Control> {
    if synsema_core::bundle::get(path).is_some() {
        return Err(Control::Error(RuntimeError::new(format!(
            "\"{}\" is part of the bundle (read-only)",
            path
        ))));
    }
    Ok(())
}

/// v0.6.20 — prefijos de espacio: `bundle:<ruta>` fuerza el bundle de `synsema build`;
/// `disk:<ruta>` fuerza el disco aunque el bundle tenga esa ruta. Devuelve
/// `(espacio, ruta normalizada sin el prefijo)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Space {
    Auto,
    Bundle,
    Disk,
}

fn bundle_prefix(raw: &str) -> (Space, String) {
    if let Some(rest) = raw.strip_prefix("bundle:") {
        (Space::Bundle, normalize_path(rest))
    } else if let Some(rest) = raw.strip_prefix("disk:") {
        (Space::Disk, normalize_path(rest))
    } else {
        (Space::Auto, normalize_path(raw))
    }
}

/// v0.6.20 — de dónde se lee un archivo. Los assets del PROGRAMA (todo lo que `synsema build`
/// empaquetó: módulos, plantillas y lo pasado con `--include`) se resuelven contra el BUNDLE,
/// sin `file.read` (son el programa, no un recurso del host) y con su línea de audit: un
/// archivo dejado en el cwd jamás los sombrea. Todo lo demás es un archivo del USUARIO y va
/// al disco con `file.read`. `bundle:`/`disk:` fuerzan un espacio cuando una herramienta lo
/// necesita. La separación de espacios es lo que arregla al CLI construido con `synsema
/// build`: `list_dir` (abajo) lista SÓLO el disco.
enum Located {
    Disk(String),
    Bundled(String, &'static [u8]),
}

fn locate_for_read(caps: &Rc<RefCell<CapabilitySet>>, raw: &str, source: &str) -> Result<Located, Control> {
    let (space, path) = bundle_prefix(raw);
    if space != Space::Disk {
        if let Some(bytes) = synsema_core::bundle::get(&path) {
            bundled_audit(caps, CapabilityType::FileRead, &path, source);
            return Ok(Located::Bundled(path, bytes));
        }
        if space == Space::Bundle {
            return Err(Control::Error(RuntimeError::new(format!(
                "\"bundle:{}\" is not in the bundle (the program was not built with it, or the name differs)",
                path
            ))));
        }
    }
    require(caps, Capability::new(CapabilityType::FileRead, Some(path.clone())), source)?;
    Ok(Located::Disk(path))
}

/// Rango de líneas 1-based (EOL preservado) sobre un texto en memoria (bundle).
fn lines_range_str(s: &str, offset: usize, limit: Option<usize>) -> String {
    s.split_inclusive('\n')
        .skip(offset.saturating_sub(1))
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

/// Chequea una capability; convierte la violación en `Control::Error` SIN ubicación.
fn require(caps: &Rc<RefCell<CapabilitySet>>, cap: Capability, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&cap, source)
        .map_err(|v| Control::Error(v.into_error()))
}

/// Hostname de un URL, como `urlparse().hostname` de Python: minúsculas, sin
/// userinfo ni puerto. `None` si no hay esquema `scheme://`.
pub fn url_hostname(url: &str) -> Option<String> {
    let after = url.find("://").map(|i| &url[i + 3..])?;
    let end = after
        .find(['/', '?', '#'])
        .unwrap_or(after.len());
    let netloc = &after[..end];
    let host_port = match netloc.rfind('@') {
        Some(i) => &netloc[i + 1..],
        None => netloc,
    };
    let host = match host_port.rfind(':') {
        Some(i) => &host_port[..i],
        None => host_port,
    };
    Some(host.to_lowercase())
}

// -- Helpers de time (UTC, como gmtime del oráculo) --

fn arg_f64(v: &SynValue) -> Result<f64, Control> {
    match v {
        SynValue::Number(n) => Ok(n.to_f64()),
        SynValue::Text(s) => s
            .trim()
            .parse::<f64>()
            .map_err(|_| Control::Error(RuntimeError::new("expected a number"))),
        _ => Err(Control::Error(RuntimeError::new("expected a number"))),
    }
}

/// Igual que `arg_f64` pero entero (trunca hacia cero).
fn arg_i64(v: &SynValue) -> Result<i64, Control> {
    Ok(arg_f64(v)?.trunc() as i64)
}

/// Escritura ATÓMICA: temp en el mismo dir (rename intra-FS, sin cross-device) + rename.
/// Crea los dirs padre si faltan. Limpia el temp si el rename falla. Reusado por
/// `write_file` y `edit_file`.
fn atomic_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = format!("{}.synsema.tmp", path);
    std::fs::write(&tmp, data)
        .and_then(|_| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

/// Lee todo el stream pero guarda como mucho `cap` bytes; si hubo más, marca truncado.
/// Sigue drenando tras el tope (descartando) para que el hijo no se bloquee al escribir
/// en un pipe lleno. Usado por `run()` para capturar stdout/stderr en threads.
fn read_capped<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let take = (cap - out.len()).min(n);
                    out.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true; // ya lleno: drenar y descartar
                }
            }
            Err(_) => break,
        }
    }
    (out, truncated)
}

/// Junta los archivos a buscar para `grep`: si `path` es archivo → `[path]`; si es
/// carpeta → recursivo, filtrando por nombre con `glob` (fnmatch). Rutas con `/`.
fn grep_collect(path: &str, glob: &Option<String>, out: &mut Vec<String>) -> Result<(), Control> {
    let md = std::fs::metadata(path).map_err(|_| {
        Control::Error(RuntimeError::new(format!("grep: path not found: {}", path)))
    })?;
    if md.is_file() {
        out.push(path.to_string());
        return Ok(());
    }
    fn walk(dir: &str, glob: &Option<String>, out: &mut Vec<String>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(x) => x,
            Err(_) => return,
        };
        for e in rd.flatten() {
            let p = e.path();
            let ps = p.to_string_lossy().replace('\\', "/");
            if p.is_dir() {
                walk(&ps, glob, out);
            } else {
                let name = e.file_name().to_string_lossy().into_owned();
                let inc = match glob {
                    Some(g) => fnmatch(&name, g),
                    None => true,
                };
                if inc {
                    out.push(ps);
                }
            }
        }
    }
    walk(path, glob, out);
    Ok(())
}

/// Lee un archivo como líneas SIN el EOL (para el campo `text` de `grep`). Streamea por
/// línea (`read_until`); líneas no-UTF-8 se leen lossy (no se saltean en silencio).
fn grep_lines(path: &str) -> std::io::Result<Vec<String>> {
    let f = std::fs::File::open(path)?;
    let mut r = BufReader::new(f);
    let mut buf = Vec::new();
    let mut lines = Vec::new();
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let mut s = String::from_utf8_lossy(&buf).into_owned();
        while s.ends_with('\n') || s.ends_with('\r') {
            s.pop();
        }
        lines.push(s);
    }
    Ok(lines)
}

/// Lee las líneas `[offset, offset+limit)` 1-based, PRESERVANDO los EOL. Streamea por
/// línea con `read_until(b'\n')` (no carga el archivo entero ni corta multibyte: UTF-8
/// es auto-sincronizante en `\n`; `from_utf8_lossy` es por robustez). `limit=None` → hasta
/// el fin del archivo.
fn read_lines_range(path: &str, offset: usize, limit: Option<usize>) -> std::io::Result<String> {
    let f = std::fs::File::open(path)?;
    let mut reader = BufReader::new(f);
    let start = offset.saturating_sub(1); // 1-based → 0-based inclusivo
    let end = limit.map(|n| start.saturating_add(n)); // exclusivo
    let mut buf = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    let mut idx = 0usize;
    loop {
        if let Some(e) = end {
            if idx >= e {
                break;
            }
        }
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break; // EOF
        }
        if idx >= start {
            out.extend_from_slice(&buf); // read_until conserva el \n
        }
        idx += 1;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Patrón strftime opcional (2º arg de tipo texto).
fn opt_pattern(args: &[SynValue]) -> Option<String> {
    match args.get(1) {
        Some(SynValue::Text(s)) => Some(s.to_string()),
        _ => None,
    }
}

fn ts_to_utc(ts: f64) -> Result<DateTime<Utc>, Control> {
    let secs = ts.trunc() as i64;
    let nanos = ((ts - ts.trunc()) * 1e9).round() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .ok_or_else(|| Control::Error(RuntimeError::new("invalid timestamp")))
}

/// Inverso de format_time. Sin patrón parsea ISO-8601 (acepta 'Z'); naive→UTC.
fn parse_time_ts(s: &str, pattern: Option<&str>) -> Result<f64, Control> {
    if let Some(p) = pattern {
        // Un patrón de SÓLO fecha ("%Y-%m-%d") es medianoche UTC (antes: "input is not enough
        // for unique date and time").
        let naive = match NaiveDateTime::parse_from_str(s, p) {
            Ok(n) => n,
            Err(e) => match chrono::NaiveDate::parse_from_str(s, p) {
                Ok(d) => d.and_time(chrono::NaiveTime::MIN),
                Err(_) => return Err(Control::Error(RuntimeError::new(format!("invalid time: {}", e)))),
            },
        };
        return Ok(naive.and_utc().timestamp() as f64);
    }
    let s2 = s.replace('Z', "+00:00");
    if let Ok(dt) = DateTime::parse_from_rfc3339(&s2) {
        return Ok(dt.timestamp() as f64);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s2, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.and_utc().timestamp() as f64);
    }
    Err(Control::Error(RuntimeError::new(format!("invalid time: {}", s))))
}

/// Builtins de filesystem del PERFIL PURO: sin disco, pero el BUNDLE (`synsema build`)
/// sigue disponible — es parte del programa, no filesystem. Las lecturas sirven del
/// bundle o fallan con el error puro; las escrituras siempre fallan. Sobrescriben (por
/// nombre) a los builtins normales cuando el motor entra en perfil puro.
pub fn register_pure_fs(interp: &Interpreter, hint: &'static str) {
    fn no_fs(name: &str, hint: &str) -> Control {
        Control::Error(RuntimeError::new(format!(
            "{}: not available in the pure profile — this run has no filesystem ({})",
            name, hint
        )))
    }
    interp.register_builtin("read_file", -1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        match synsema_core::bundle::get(&path) {
            Some(bytes) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                if args.len() < 2 {
                    return Ok(syn_text(text));
                }
                let offset = arg_i64(arg(args, 1)?)?;
                if offset < 1 {
                    return Err(Control::Error(RuntimeError::new("read_file: offset must be >= 1")));
                }
                let limit = match args.get(2) {
                    Some(v) => Some(arg_i64(v)?.max(0) as usize),
                    None => None,
                };
                Ok(syn_text(lines_range_str(&text, offset as usize, limit)))
            }
            None => Err(no_fs("read_file", hint)),
        }
    }));
    interp.register_builtin("read_file_bytes", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        match synsema_core::bundle::get(&path) {
            Some(bytes) => Ok(syn_bytes(bytes.to_vec())),
            None => Err(no_fs("read_file_bytes", hint)),
        }
    }));
    interp.register_builtin("file_exists", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        Ok(syn_bool(synsema_core::bundle::get(&path).is_some()))
    }));
    interp.register_builtin("file_info", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        let mut m = IndexMap::new();
        match synsema_core::bundle::get(&path) {
            Some(bytes) => {
                m.insert("exists".to_string(), syn_bool(true));
                m.insert("is_dir".to_string(), syn_bool(false));
                m.insert("size".to_string(), syn_int(bytes.len() as i64));
                m.insert("modified".to_string(), SynValue::Nothing);
                m.insert("bundled".to_string(), syn_bool(true));
            }
            None => {
                m.insert("exists".to_string(), syn_bool(false));
                m.insert("is_dir".to_string(), syn_bool(false));
                m.insert("size".to_string(), syn_int(0));
                m.insert("modified".to_string(), SynValue::Nothing);
            }
        }
        Ok(syn_map(m))
    }));
    // v0.6.20 — borrar y `cwd()` no existen sin filesystem (ni sobre el bundle: es de sólo lectura).
    for name in ["delete_file", "delete_dir", "cwd"] {
        interp.register_builtin(name, -1, Rc::new(move |_i, _args, _loc| Err(no_fs(name, hint))));
    }
    interp.register_builtin("list_dir", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        let Some(b) = synsema_core::bundle::mounted() else {
            return Err(no_fs("list_dir", hint));
        };
        let under = b.list(&path);
        if under.is_empty() {
            return Err(no_fs("list_dir", hint));
        }
        let root = path.trim_matches(|c| c == '.' || c == '/' || c == '\\').is_empty();
        let prefix_len = match synsema_core::bundle::normalize_name(&path) {
            Some(n) if !root => n.len() + 1,
            _ => 0,
        };
        let mut seen: Vec<(String, bool, i64)> = Vec::new();
        for (name, size) in under {
            let rest = &name[prefix_len.min(name.len())..];
            let (entry, is_dir) = match rest.split_once('/') {
                Some((d, _)) => (d.to_string(), true),
                None => (rest.to_string(), false),
            };
            if !seen.iter().any(|(n, _, _)| *n == entry) {
                seen.push((entry, is_dir, if is_dir { 0 } else { size as i64 }));
            }
        }
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(syn_list(seen.into_iter().map(|(name, is_dir, size)| {
            let mut m = IndexMap::new();
            m.insert("name".to_string(), syn_text(name));
            m.insert("is_dir".to_string(), syn_bool(is_dir));
            m.insert("size".to_string(), syn_int(size));
            syn_map(m)
        }).collect()))
    }));
    for name in ["write_file", "append_file", "edit_file", "grep"] {
        let name: &'static str = name;
        interp.register_builtin(name, -1, Rc::new(move |_i, _args, _loc| Err(no_fs(name, hint))));
    }
}

/// Registra los builtins seguros en el intérprete, compartiendo el `CapabilitySet`.
pub fn register_secure_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // read_file(path, offset?, limit?) → text. Requiere file_read("<path>").
    // arity-1: archivo completo (idéntico a hoy). arity-2/3: rango por LÍNEAS 1-based,
    // preservando los EOL; fin de archivo observable (sin truncado silencioso).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "read_file",
            -1,
            Rc::new(move |_i, args, _loc| {
                // v0.6.20 — assets del programa desde el bundle; archivos del usuario desde el disco
                // (ver locate_for_read).
                let (path, bundled) = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "read_file()")? {
                    Located::Disk(p) => (p, None),
                    Located::Bundled(p, b) => (p, Some(b)),
                };
                // arity-1: archivo completo, idéntico a hoy (read_to_string estricto).
                if args.len() < 2 {
                    if let Some(bytes) = bundled {
                        return Ok(syn_text(String::from_utf8_lossy(bytes).into_owned()));
                    }
                    return match std::fs::read_to_string(&path) {
                        Ok(c) => Ok(syn_text(c)),
                        Err(_) => Err(Control::Error(RuntimeError::new(format!(
                            "File not found: {}",
                            path
                        )))),
                    };
                }
                // rango por líneas (1-based)
                let offset = arg_i64(arg(args, 1)?)?;
                if offset < 1 {
                    return Err(Control::Error(RuntimeError::new(
                        "read_file: offset must be >= 1",
                    )));
                }
                let limit = match args.get(2) {
                    Some(v) => {
                        let n = arg_i64(v)?;
                        if n < 0 {
                            return Err(Control::Error(RuntimeError::new(
                                "read_file: limit must be >= 0",
                            )));
                        }
                        Some(n as usize)
                    }
                    None => None,
                };
                if let Some(bytes) = bundled {
                    return Ok(syn_text(lines_range_str(&String::from_utf8_lossy(bytes), offset as usize, limit)));
                }
                match read_lines_range(&path, offset as usize, limit) {
                    Ok(s) => Ok(syn_text(s)),
                    Err(_) => Err(Control::Error(RuntimeError::new(format!(
                        "File not found: {}",
                        path
                    )))),
                }
            }),
        );
    }

    // list_dir(path) → list de {name, is_dir, size}, ordenada por name. NO recursivo.
    // Incluye ocultos. path inexistente/no-carpeta → error. Requiere file_read("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "list_dir",
            1,
            Rc::new(move |_i, args, _loc| {
                let (space, path) = bundle_prefix(&raw_str(arg(args, 0)?));
                // v0.6.20 — el DISCO es el directorio; el bundle sólo con `bundle:` explícito
                // (`list_dir("bundle:")` = su raíz). Antes el bundle sombreaba el cwd y un CLI
                // construido con `synsema build` listaba sus propios assets en vez de la carpeta
                // donde lo invocaron.
                if space == Space::Bundle {
                    let Some(b) = synsema_core::bundle::mounted() else {
                        return Err(Control::Error(RuntimeError::new(
                            "list_dir(\"bundle:…\"): this program has no bundle (it was not built with `synsema build`)",
                        )));
                    };
                    let under = b.list(&path);
                    if under.is_empty() {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "list_dir: \"bundle:{}\" is not a directory in the bundle",
                            path
                        ))));
                    }
                    {
                        bundled_audit(&caps, CapabilityType::FileRead, &path, "list_dir()");
                        let root = path.trim_matches(|c| c == '.' || c == '/' || c == '\\').is_empty();
                        let prefix_len = match synsema_core::bundle::normalize_name(&path) {
                            Some(n) if !root => n.len() + 1,
                            _ => 0,
                        };
                        let mut seen: Vec<(String, bool, i64)> = Vec::new();
                        for (name, size) in under {
                            let rest = &name[prefix_len.min(name.len())..];
                            let (entry, is_dir) = match rest.split_once('/') {
                                Some((d, _)) => (d.to_string(), true),
                                None => (rest.to_string(), false),
                            };
                            if !seen.iter().any(|(n, _, _)| *n == entry) {
                                seen.push((entry, is_dir, if is_dir { 0 } else { size as i64 }));
                            }
                        }
                        seen.sort_by(|a, b| a.0.cmp(&b.0));
                        let items: Vec<SynValue> = seen
                            .into_iter()
                            .map(|(name, is_dir, size)| {
                                let mut m = IndexMap::new();
                                m.insert("name".to_string(), syn_text(name));
                                m.insert("is_dir".to_string(), syn_bool(is_dir));
                                m.insert("size".to_string(), syn_int(size));
                                syn_map(m)
                            })
                            .collect();
                        return Ok(syn_list(items));
                    }
                }
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "list_dir()",
                )?;
                let rd = std::fs::read_dir(&path).map_err(|_| {
                    Control::Error(RuntimeError::new(format!("Not a directory: {}", path)))
                })?;
                let mut entries: Vec<(String, bool, i64)> = Vec::new();
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let md = e.metadata().ok();
                    let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                    let size = if is_dir {
                        0
                    } else {
                        md.as_ref().map(|m| m.len() as i64).unwrap_or(0)
                    };
                    entries.push((name, is_dir, size));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0)); // orden estable por nombre
                let items = entries
                    .into_iter()
                    .map(|(name, is_dir, size)| {
                        let mut m = IndexMap::new();
                        m.insert("name".to_string(), syn_text(name));
                        m.insert("is_dir".to_string(), syn_bool(is_dir));
                        m.insert("size".to_string(), syn_int(size));
                        syn_map(m)
                    })
                    .collect();
                Ok(syn_list(items))
            }),
        );
    }

    // file_info(path) → {exists, is_dir, size, modified}. Si no existe, forma estable
    // {exists:false,...} (NO error: chequear existencia es su trabajo). Requiere file_read.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "file_info",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "file_info()")? {
                    Located::Bundled(_, bytes) => {
                        let mut m = IndexMap::new();
                        m.insert("exists".to_string(), syn_bool(true));
                        m.insert("is_dir".to_string(), syn_bool(false));
                        m.insert("size".to_string(), syn_int(bytes.len() as i64));
                        m.insert("modified".to_string(), SynValue::Nothing);
                        m.insert("bundled".to_string(), syn_bool(true));
                        return Ok(syn_map(m));
                    }
                    Located::Disk(p) => p,
                };
                let mut m = IndexMap::new();
                match std::fs::metadata(&path) {
                    Ok(md) => {
                        let modified = md
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| syn_int(d.as_secs() as i64))
                            .unwrap_or(SynValue::Nothing);
                        let is_dir = md.is_dir();
                        m.insert("exists".to_string(), syn_bool(true));
                        m.insert("is_dir".to_string(), syn_bool(is_dir));
                        m.insert(
                            "size".to_string(),
                            syn_int(if is_dir { 0 } else { md.len() as i64 }),
                        );
                        m.insert("modified".to_string(), modified);
                    }
                    Err(_) => {
                        m.insert("exists".to_string(), syn_bool(false));
                        m.insert("is_dir".to_string(), syn_bool(false));
                        m.insert("size".to_string(), syn_int(0));
                        m.insert("modified".to_string(), SynValue::Nothing);
                    }
                }
                Ok(syn_map(m))
            }),
        );
    }

    // file_exists(path) → bool. Azúcar de file_info(path).exists. Requiere file_read.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "file_exists",
            1,
            Rc::new(move |_i, args, _loc| {
                match locate_for_read(&caps, &raw_str(arg(args, 0)?), "file_exists()")? {
                    Located::Bundled(..) => Ok(syn_bool(true)),
                    Located::Disk(path) => Ok(syn_bool(std::fs::metadata(&path).is_ok())),
                }
            }),
        );
    }

    // grep(target, pattern, opts?) → {matches:[{file,line,col,text}], truncated}.
    // Busca en disco SIN cargar archivos enteros (streamea por línea). target archivo →
    // ese archivo; carpeta → recursivo. pattern LITERAL por defecto (opts.regex para RE2).
    // Un solo chequeo de file.read sobre el target (granularidad de IO-P1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "grep",
            -1,
            Rc::new(move |_i, args, _loc| {
                let pattern = raw_str(arg(args, 1)?);
                let target = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "grep()")? {
                    Located::Bundled(p, _) => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "grep: \"{}\" is a bundled asset — grep runs over the filesystem; use read_file() on it",
                            p
                        ))))
                    }
                    Located::Disk(p) => p,
                };
                if pattern.is_empty() {
                    return Err(Control::Error(RuntimeError::new("grep: empty pattern")));
                }

                // -- opts --
                let map_get = |k: &str| -> Option<SynValue> {
                    match args.get(2) {
                        Some(SynValue::Map(m)) => m.borrow().get(k).cloned(),
                        _ => None,
                    }
                };
                let ignore_case = matches!(map_get("ignore_case"), Some(SynValue::Bool(true)));
                let use_regex = matches!(map_get("regex"), Some(SynValue::Bool(true)));
                let glob = match map_get("glob") {
                    Some(SynValue::Text(s)) => Some(s.to_string()),
                    _ => None,
                };
                let max_results = match map_get("max_results") {
                    Some(SynValue::Number(n)) => Some(n.to_f64() as usize),
                    _ => None,
                };

                // -- matcher --
                let re = if use_regex {
                    Some(
                        RegexBuilder::new(&pattern)
                            .case_insensitive(ignore_case)
                            .build()
                            .map_err(|e| {
                                Control::Error(RuntimeError::new(format!(
                                    "grep: invalid regex pattern: {}",
                                    e
                                )))
                            })?,
                    )
                } else {
                    None
                };
                let needle = if ignore_case {
                    pattern.to_lowercase()
                } else {
                    pattern.clone()
                };

                // -- recorrido (orden estable: por ruta, luego por línea) --
                let mut files = Vec::new();
                grep_collect(&target, &glob, &mut files)?;
                files.sort();

                let mut out_matches: Vec<SynValue> = Vec::new();
                let mut truncated = false;
                'files: for f in &files {
                    let lines = match grep_lines(f) {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    for (i, line) in lines.iter().enumerate() {
                        let col_byte = if let Some(re) = &re {
                            re.find(line).map(|m| m.start())
                        } else if ignore_case {
                            line.to_lowercase().find(&needle)
                        } else {
                            line.find(&needle)
                        };
                        if let Some(b) = col_byte {
                            // col 1-based en chars (best-effort; bajo ignore_case literal se
                            // mide sobre el prefijo en minúsculas, misma cuenta de chars).
                            let prefix = if ignore_case && re.is_none() {
                                line.to_lowercase()
                            } else {
                                line.clone()
                            };
                            let col = prefix.get(..b).map(|p| p.chars().count()).unwrap_or(0) + 1;
                            let mut m = IndexMap::new();
                            m.insert("file".to_string(), syn_text(f.clone()));
                            m.insert("line".to_string(), syn_int((i as i64) + 1));
                            m.insert("col".to_string(), syn_int(col as i64));
                            m.insert("text".to_string(), syn_text(line.clone()));
                            out_matches.push(syn_map(m));
                            if let Some(max) = max_results {
                                if out_matches.len() >= max {
                                    truncated = true;
                                    break 'files;
                                }
                            }
                        }
                    }
                }
                let mut out = IndexMap::new();
                out.insert("matches".to_string(), syn_list(out_matches));
                out.insert("truncated".to_string(), syn_bool(truncated));
                Ok(syn_map(out))
            }),
        );
    }

    // read_file_bytes(path) → bytes (crudo, NO lossy). Requiere file_read("<path>"),
    // mismo gating que read_file. Cierra el punto lossy de read_file para binario.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "read_file_bytes",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "read_file_bytes()")? {
                    Located::Bundled(_, bytes) => return Ok(syn_bytes(bytes.to_vec())),
                    Located::Disk(p) => p,
                };
                match std::fs::read(&path) {
                    Ok(b) => Ok(syn_bytes(b)),
                    Err(_) => Err(Control::Error(RuntimeError::new(format!(
                        "File not found: {}",
                        path
                    )))),
                }
            }),
        );
    }

    // v0.6.20 — delete_file(path) → true. Requiere file_write("<path>"): el MISMO scope que
    // escribir (quien puede crear puede deshacer). Un asset del bundle es de sólo lectura.
    // Antes, borrar un archivo propio exigía `exec("rm")`: no tenerlo EMPEORABA la seguridad.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "delete_file",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "delete_file()",
                )?;
                reject_bundled_write(&path)?;
                match std::fs::metadata(&path) {
                    Err(_) => Err(Control::Error(RuntimeError::new(format!("File not found: {}", path)))),
                    Ok(md) if md.is_dir() => Err(Control::Error(RuntimeError::new(format!(
                        "delete_file: \"{}\" is a directory (use delete_dir)",
                        path
                    )))),
                    Ok(_) => std::fs::remove_file(&path).map(|_| syn_bool(true)).map_err(|e| {
                        Control::Error(RuntimeError::new(format!("Cannot delete file {}: {}", path, e)))
                    }),
                }
            }),
        );
    }

    // v0.6.20 — delete_dir(path, opts?) → true. Sólo vacío por defecto; `{"recursive": true}`
    // borra el árbol entero. Requiere file_write("<path>") (el scope debe cubrir el dir).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "delete_dir",
            -1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                let recursive = match args.get(1) {
                    None | Some(SynValue::Nothing) => false,
                    Some(SynValue::Map(m)) => {
                        for (k, v) in m.borrow().iter() {
                            if k != "recursive" {
                                return Err(Control::Error(RuntimeError::new(format!(
                                    "delete_dir: unknown option {:?} (valid options: recursive)",
                                    k
                                ))));
                            }
                            if !matches!(v, SynValue::Bool(_)) {
                                return Err(Control::Error(RuntimeError::new(
                                    "delete_dir: option `recursive` must be true or false",
                                )));
                            }
                        }
                        matches!(m.borrow().get("recursive"), Some(SynValue::Bool(true)))
                    }
                    Some(other) => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: opts must be a map, got {}",
                            other.type_name()
                        ))))
                    }
                };
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "delete_dir()",
                )?;
                reject_bundled_write(&path)?;
                match std::fs::metadata(&path) {
                    Err(_) => {
                        return Err(Control::Error(RuntimeError::new(format!("Directory not found: {}", path))))
                    }
                    Ok(md) if !md.is_dir() => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: \"{}\" is a file (use delete_file)",
                            path
                        ))))
                    }
                    Ok(_) => {}
                }
                // Auditoría externa — recursivo: `file.write` sobre CADA ruta del árbol antes de borrar
                // nada (el mismo scope que exigiría borrarlas una a una).
                if recursive {
                    let mut stack = vec![std::path::PathBuf::from(&path)];
                    let mut all: Vec<String> = Vec::new();
                    while let Some(dir) = stack.pop() {
                        let rd = std::fs::read_dir(&dir).map_err(|e| {
                            Control::Error(RuntimeError::new(format!("Cannot read directory {}: {}", dir.display(), e)))
                        })?;
                        for e in rd.flatten() {
                            let p = e.path();
                            all.push(normalize_path(&p.to_string_lossy()));
                            if e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false) {
                                stack.push(p);
                            }
                        }
                    }
                    for p in &all {
                        require(&caps, Capability::new(CapabilityType::FileWrite, Some(p.clone())), "delete_dir()")?;
                    }
                }
                let result = if recursive { std::fs::remove_dir_all(&path) } else { std::fs::remove_dir(&path) };
                match result {
                    Ok(_) => Ok(syn_bool(true)),
                    Err(e) if !recursive && e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                        Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: \"{}\" is not empty (pass {{\"recursive\": true}} to delete its contents)",
                            path
                        ))))
                    }
                    Err(e) => Err(Control::Error(RuntimeError::new(format!(
                        "Cannot delete directory {}: {}",
                        path, e
                    )))),
                }
            }),
        );
    }

    // v0.6.20 — cwd() → el directorio de trabajo real, normalizado. Bajo `file.read(".")`:
    // el nombre absoluto de `.` es información del host (bajo --sandbox no se filtra gratis) y
    // es exactamente la misma grant que exige `list_dir(".")`; `file.read("./*")` y `"*"`
    // también la cubren. Bajo un binario de `synsema build` es el cwd de verdad, nunca el
    // overlay del bundle.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "cwd",
            0,
            Rc::new(move |_i, _args, _loc| match std::env::current_dir() {
                Ok(p) => {
                    require(&caps, Capability::new(CapabilityType::FileRead, Some(".".to_string())), "cwd()")?;
                    Ok(syn_text(normalize_path(&p.to_string_lossy())))
                }
                Err(e) => Err(Control::Error(RuntimeError::new(format!("cwd: {}", e)))),
            }),
        );
    }

    // write_file(path, content) → true. Requiere file_write("<path>"). Despacha por
    // tipo: si `content` es bytes, escribe los bytes crudos (binario, NO lossy); si no,
    // texto (raw_str). Escritura ATÓMICA: temp en el mismo dir + rename (sin lectores que
    // vean un archivo a medias). Mismo retorno/errores que antes.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "write_file",
            2,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "write_file()",
                )?;
                reject_bundled_write(&path)?;
                // Escritura atómica (temp+rename); crea dirs padre. Despacha por tipo.
                let result = match arg(args, 1)? {
                    SynValue::Bytes(b) => atomic_write(&path, &b[..]),
                    other => atomic_write(&path, raw_str(other).as_bytes()),
                };
                match result {
                    Ok(_) => Ok(syn_bool(true)),
                    Err(e) => Err(Control::Error(RuntimeError::new(format!(
                        "Cannot write file {}: {}",
                        path, e
                    )))),
                }
            }),
        );
    }

    // edit_file(path, old, new, replace_all?) → {replaced:N}. Reemplaza por match exacto
    // de string. Sin replace_all exige UNICIDAD (0 → not found; >1 → ambiguo). Escritura
    // atómica. Solo file.write: lee internamente para localizar `old` pero NO expone el
    // contenido (solo devuelve `replaced`), así que no es canal de lectura.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "edit_file",
            -1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                let old = raw_str(arg(args, 1)?);
                let new = raw_str(arg(args, 2)?);
                let replace_all = matches!(args.get(3), Some(SynValue::Bool(true)));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "edit_file()",
                )?;
                reject_bundled_write(&path)?;
                if old.is_empty() {
                    return Err(Control::Error(RuntimeError::new("edit_file: empty pattern")));
                }
                let content = std::fs::read_to_string(&path).map_err(|_| {
                    Control::Error(RuntimeError::new(format!("File not found: {}", path)))
                })?;
                let count = content.matches(&old).count();
                if count == 0 {
                    return Err(Control::Error(RuntimeError::new("edit_file: pattern not found")));
                }
                if count > 1 && !replace_all {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "edit_file: ambiguous, {} occurrences (use replace_all to replace all)",
                        count
                    ))));
                }
                let (updated, replaced) = if replace_all {
                    (content.replace(&old, &new), count)
                } else {
                    (content.replacen(&old, &new, 1), 1)
                };
                atomic_write(&path, updated.as_bytes()).map_err(|e| {
                    Control::Error(RuntimeError::new(format!("Cannot write file {}: {}", path, e)))
                })?;
                let mut m = IndexMap::new();
                m.insert("replaced".to_string(), syn_int(replaced as i64));
                Ok(syn_map(m))
            }),
        );
    }

    // append_file(path, content) → true. Agrega al final (crea si no existe, + dirs padre).
    // bytes → crudo; si no, texto. Append REAL (OpenOptions::append), no temp+rename: el
    // sentido de append es no reescribir el archivo. Requiere file.write("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "append_file",
            2,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "append_file()",
                )?;
                reject_bundled_write(&path)?;
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|e| {
                        Control::Error(RuntimeError::new(format!(
                            "Cannot write file {}: {}",
                            path, e
                        )))
                    })?;
                let res = match arg(args, 1)? {
                    SynValue::Bytes(b) => f.write_all(&b[..]),
                    other => f.write_all(raw_str(other).as_bytes()),
                };
                res.map_err(|e| {
                    Control::Error(RuntimeError::new(format!("Cannot write file {}: {}", path, e)))
                })?;
                Ok(syn_bool(true))
            }),
        );
    }

    // run(cmd, args_list?, timeout?, opts?) → {exit_code, stdout, stderr,
    // stdout_truncated, stderr_truncated}. Gateado por exec("<cmd>"). SIN shell: args es
    // lista (sin inyección de quoting). exit≠0 NO es error (dato en exit_code); timeout
    // mata+raise; no-se-puede-lanzar → raise. std-only (timeout por polling try_wait+kill;
    // captura en threads para no deadlockear con pipes llenos).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "run",
            -1,
            Rc::new(move |i, args, _loc| {
                let cmd = raw_str(arg(args, 0)?);
                // args_list (opcional; si está, debe ser lista).
                let arg_list: Vec<String> = match args.get(1) {
                    None | Some(SynValue::Nothing) => Vec::new(),
                    Some(SynValue::List(l)) => l.borrow().iter().map(raw_str).collect(),
                    Some(_) => {
                        return Err(Control::Error(RuntimeError::new("run: args must be a list")))
                    }
                };
                // capability: scope = cmd tal como se pasa (pre-PATH).
                require(
                    &caps,
                    Capability::new(CapabilityType::Exec, Some(cmd.clone())),
                    "run()",
                )?;

                // timeout (default 120s).
                let timeout_secs = match args.get(2) {
                    Some(SynValue::Nothing) | None => 120.0,
                    Some(v) => arg_f64(v)?,
                };
                // opts.
                let opt = |k: &str| -> Option<SynValue> {
                    match args.get(3) {
                        Some(SynValue::Map(m)) => m.borrow().get(k).cloned(),
                        _ => None,
                    }
                };
                let cwd = match opt("cwd") {
                    Some(SynValue::Text(s)) => Some(s.to_string()),
                    _ => None,
                };
                let stdin_data: Option<Vec<u8>> = match opt("stdin") {
                    Some(SynValue::Bytes(b)) => Some(b[..].to_vec()),
                    Some(SynValue::Text(s)) => Some(s.as_bytes().to_vec()),
                    _ => None,
                };
                let max_output = match opt("max_output") {
                    Some(SynValue::Number(n)) => n.to_f64() as usize,
                    _ => 10 * 1024 * 1024,
                };

                // construir el comando.
                let mut c = Command::new(&cmd);
                c.args(&arg_list)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(dir) = &cwd {
                    c.current_dir(dir);
                }
                // F3: sacar las variables SECRETAS de Synsema (claves de proveedor,
                // secretos del `.env`) del entorno del hijo — un programa con `exec` pero
                // sin `env`/`secret` no debe exfiltrarlas por `run("printenv")`. El
                // programa que de verdad necesita una la pasa explícita por `opts.env`.
                for name in i.sensitive_env() {
                    c.env_remove(name);
                }
                if let Some(SynValue::Map(m)) = opt("env") {
                    for (k, v) in m.borrow().iter() {
                        c.env(k, raw_str(v)); // override explícito (gana sobre el strip)
                    }
                }

                let mut child = c.spawn().map_err(|e| {
                    Control::Error(RuntimeError::new(format!(
                        "run: cannot start \"{}\": {}",
                        cmd, e
                    )))
                })?;

                // stdin: escribir en un thread (evita deadlock con stdin grande) y cerrar
                // (EOF). Sin data → `si` se dropea acá y cierra stdin.
                if let Some(si) = child.stdin.take() {
                    if let Some(data) = stdin_data {
                        std::thread::spawn(move || {
                            let mut si = si;
                            let _ = si.write_all(&data);
                        });
                    }
                }

                // captura concurrente (threads) para no bloquear con pipes llenos.
                let out = child.stdout.take().unwrap();
                let err = child.stderr.take().unwrap();
                let out_h = std::thread::spawn(move || read_capped(out, max_output));
                let err_h = std::thread::spawn(move || read_capped(err, max_output));

                // esperar con timeout (polling try_wait + kill); sin crate externa.
                let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs.max(0.0));
                let mut timed_out = false;
                let status = loop {
                    match child.try_wait() {
                        Ok(Some(st)) => break Some(st),
                        Ok(None) => {
                            // Cancelación cooperativa: no dejar el hijo huérfano.
                            if i.is_cancelled() {
                                let _ = child.kill();
                                let _ = child.wait();
                                i.check_cancel()?;
                            }
                            if Instant::now() >= deadline {
                                let _ = child.kill();
                                let _ = child.wait();
                                timed_out = true;
                                break None;
                            }
                            std::thread::sleep(Duration::from_millis(15));
                        }
                        Err(_) => break None,
                    }
                };

                let (out_bytes, out_trunc) = out_h.join().unwrap_or((Vec::new(), false));
                let (err_bytes, err_trunc) = err_h.join().unwrap_or((Vec::new(), false));

                if timed_out {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "run: \"{}\" timed out after {}s",
                        cmd, timeout_secs as i64
                    ))));
                }
                let exit_code = status.and_then(|s| s.code()).unwrap_or(-1);

                let mut m = IndexMap::new();
                m.insert("exit_code".to_string(), syn_int(exit_code as i64));
                m.insert(
                    "stdout".to_string(),
                    syn_text(String::from_utf8_lossy(&out_bytes).into_owned()),
                );
                m.insert(
                    "stderr".to_string(),
                    syn_text(String::from_utf8_lossy(&err_bytes).into_owned()),
                );
                m.insert("stdout_truncated".to_string(), syn_bool(out_trunc));
                m.insert("stderr_truncated".to_string(), syn_bool(err_trunc));
                Ok(syn_map(m))
            }),
        );
    }

    // (fetch vive ahora en synsema-stdlib/http.rs: cliente HTTP real, gateado por net —
    // junto con http/http_get/http_post/http_put/http_delete. El stub "capa 6" se removió.)

    // -- Builtins de time (todos requieren la capability `time`; UTC) --

    // now() → timestamp unix (float).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "now",
            0,
            Rc::new(move |_i, _args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "now()")?;
                Ok(syn_float(synsema_core::clock::now_secs_f64()))
            }),
        );
    }

    // sleep(seconds) → pausa (cap a 1h). Requiere time (como now()).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "sleep()")?;
                let secs = args.first().and_then(|v| arg_f64(v).ok()).unwrap_or(0.0);
                let secs = secs.clamp(0.0, 3600.0);
                // Dormir en tramos: una cancelación cooperativa (timeout de handler,
                // shutdown, agent_stop) corta el sleep en ≤100 ms, no al vencer.
                let deadline = Instant::now() + std::time::Duration::from_secs_f64(secs);
                loop {
                    i.check_cancel()?;
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(100)));
                }
                Ok(SynValue::Nothing)
            }),
        );
    }

    // format_time(ts | date | datetime, pattern?) → text. Default ISO-8601 ("…Z" para un
    // timestamp). PURO desde v0.6.29: formatear no lee el reloj (sólo `now()` pide `time`).
    {
        interp.register_builtin(
            "format_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                if let SynValue::Time(t) = arg(args, 0)? {
                    return match opt_pattern(args) {
                        Some(p) => Ok(syn_text(synsema_core::temporal::format(t, &p)?)),
                        None => Ok(syn_text(t.to_string())),
                    };
                }
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let out = match opt_pattern(args) {
                    Some(p) => dt.format(&p).to_string(),
                    None => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                };
                Ok(syn_text(out))
            }),
        );
    }

    // parse_time(text, pattern?) → timestamp (float). Inverso de format_time. PURO (v0.6.29).
    {
        interp.register_builtin(
            "parse_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                let s = raw_str(arg(args, 0)?);
                let ts = parse_time_ts(&s, opt_pattern(args).as_deref())?;
                Ok(syn_float(ts))
            }),
        );
    }

    // date_parts(ts | date | datetime) → {year, month, day, hour, minute, second, …}. PURO
    // (v0.6.29); con un date/datetime, en su zona y con weekday/yearday.
    {
        interp.register_builtin(
            "date_parts",
            1,
            Rc::new(move |_i, args, _loc| {
                if let SynValue::Time(t) = arg(args, 0)? {
                    return synsema_core::temporal::parts(t)
                        .ok_or_else(|| Control::Error(RuntimeError::new("date_parts: a duration has no calendar parts")));
                }
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let mut m = IndexMap::new();
                m.insert("year".to_string(), syn_int(dt.year() as i64));
                m.insert("month".to_string(), syn_int(dt.month() as i64));
                m.insert("day".to_string(), syn_int(dt.day() as i64));
                m.insert("hour".to_string(), syn_int(dt.hour() as i64));
                m.insert("minute".to_string(), syn_int(dt.minute() as i64));
                m.insert("second".to_string(), syn_int(dt.second() as i64));
                // v0.6.29: las mismas claves que con un date/datetime (un timestamp es UTC).
                m.insert("weekday".to_string(), syn_int(dt.weekday().number_from_monday() as i64));
                m.insert("yearday".to_string(), syn_int(dt.ordinal() as i64));
                m.insert("zone".to_string(), syn_text("UTC"));
                Ok(syn_map(m))
            }),
        );
    }

    // -- Builtins de random (requieren la capability `random`) --
    // paridad con el oráculo: random() = float [0,1), random_int(lo,hi) = entero INCLUSIVO
    // [lo,hi]. RNG no-cripto como el `random` de Python (Mersenne Twister); los valores no
    // son byte-idénticos al oráculo (RNG distinto) — el contrato es rango+tipo+capability.

    // random() → float en [0,1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random",
            -1,
            Rc::new(move |i, args, loc| {
                // v0.6.29 (DATOS-12): `random(g)` con un generador de `rng(seed)` es PURO y
                // reproducible; `random()` sin generador sigue pidiendo la capability.
                if let Some(g) = args.first() {
                    return Ok(syn_float(synsema_core::rng::uniform(i, g, "random", loc)?));
                }
                require(&caps, Capability::new(CapabilityType::Random, None), "random()")?;
                Ok(syn_float(rand::random::<f64>()))
            }),
        );
    }

    // random_int(min, max) → entero inclusivo [min, max].
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random_int",
            -1,
            Rc::new(move |i, args, loc| {
                // Límites ENTEROS (v0.6.29): 1.7 ya no se trunca en silencio.
                let whole = |v: &SynValue, what: &str| -> Result<i64, Control> {
                    match v {
                        SynValue::Number(n) if n.is_integer() => n
                            .to_i64_trunc()
                            .ok_or_else(|| Control::Error(RuntimeError::new(format!("random_int: {} out of range", what)))),
                        other => Err(Control::Error(RuntimeError::new(format!(
                            "random_int: {} must be an integer, got {}",
                            what, other
                        )))),
                    }
                };
                // `random_int(g, min, max)` con un generador de `rng(seed)`: puro y reproducible.
                if args.len() == 3 {
                    let lo = whole(arg(args, 1)?, "min")?;
                    let hi = whole(arg(args, 2)?, "max")?;
                    let g = arg(args, 0)?.clone();
                    return Ok(syn_int(synsema_core::rng::int_in(i, &g, lo, hi, "random_int", loc)?));
                }
                require(&caps, Capability::new(CapabilityType::Random, None), "random_int()")?;
                let lo = whole(arg(args, 0)?, "min")?;
                let hi = whole(arg(args, 1)?, "max")?;
                if lo > hi {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "random_int: min ({}) is greater than max ({})",
                        lo, hi
                    ))));
                }
                use rand::Rng;
                Ok(syn_int(rand::thread_rng().gen_range(lo..=hi)))
            }),
        );
    }
}

#[cfg(test)]
mod v0620_tests {
    use super::*;
    use synsema_core::parser::parse_source;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!("synsema-caps-v0620-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn slash(p: &std::path::Path) -> String {
        p.to_string_lossy().replace('\\', "/")
    }

    /// Corre un `.syn` con los builtins seguros y los grants dados; devuelve lo impreso.
    fn run(grants: &[(CapabilityType, Option<String>)], src: &str) -> Result<Vec<String>, String> {
        let mut interp = Interpreter::new();
        let mut set = CapabilitySet::new("test");
        for (ty, scope) in grants {
            set.grant(Capability::new(ty.clone(), scope.clone()));
        }
        register_secure_builtins(&interp, Rc::new(RefCell::new(set)));
        let program = parse_source(src, "<test>").map_err(|e| e.to_string())?;
        match interp.execute(&program) {
            Ok(_) => Ok(std::mem::take(&mut interp.output)),
            Err(Control::Error(e)) => Err(e.to_string()),
            Err(_) => Err("control flow escaped the program".to_string()),
        }
    }

    #[test]
    fn bundle_prefix_is_recognized_and_stripped() {
        assert_eq!(bundle_prefix("bundle:data/x.json"), (Space::Bundle, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("bundle:./data/../x"), (Space::Bundle, "x".to_string()));
        assert_eq!(bundle_prefix("disk:data/x.json"), (Space::Disk, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("data/x.json"), (Space::Auto, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("bundle:"), (Space::Bundle, ".".to_string()));
    }

    /// §4.1 — borrar bajo file.write: sin grant deniega; con grant borra; tipos y ausencias
    /// se dicen con claridad.
    #[test]
    fn delete_file_requires_file_write_and_is_honest() {
        let d = scratch("delete-file");
        let f = d.join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let scope = format!("{}/*", slash(&d));
        let fp = slash(&f);
        let denied = run(&[], &format!("print(delete_file(\"{}\"))", fp)).unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        assert!(f.exists(), "sin grant no se toca nada");
        let out = run(&[(CapabilityType::FileWrite, Some(scope.clone()))], &format!("print(delete_file(\"{}\"))", fp)).unwrap();
        assert_eq!(out, vec!["true"]);
        assert!(!f.exists());
        let missing = run(&[(CapabilityType::FileWrite, Some(scope.clone()))], &format!("print(delete_file(\"{}\"))", fp)).unwrap_err();
        assert!(missing.contains("File not found"), "{}", missing);
        // El scope `<dir>/*` cubre lo que está DENTRO del dir (no el dir mismo): el caso "es un
        // directorio" se prueba sobre un subdirectorio cubierto.
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let on_dir = run(&[(CapabilityType::FileWrite, Some(scope))], &format!("print(delete_file(\"{}\"))", slash(&sub))).unwrap_err();
        assert!(on_dir.contains("is a directory"), "{}", on_dir);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn delete_dir_is_non_recursive_by_default() {
        let d = scratch("delete-dir");
        let sub = d.join("sub");
        std::fs::create_dir_all(sub.join("deep")).unwrap();
        std::fs::write(sub.join("deep").join("f.txt"), "x").unwrap();
        let empty = d.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let scope = format!("{}/*", slash(&d));
        let g = [(CapabilityType::FileWrite, Some(scope))];
        assert_eq!(run(&g, &format!("print(delete_dir(\"{}\"))", slash(&empty))).unwrap(), vec!["true"]);
        assert!(!empty.exists());
        let not_empty = run(&g, &format!("print(delete_dir(\"{}\"))", slash(&sub))).unwrap_err();
        assert!(not_empty.contains("is not empty"), "{}", not_empty);
        assert!(sub.exists(), "sin recursive no se borra nada");
        let bad_opt = run(&g, &format!("print(delete_dir(\"{}\", {{\"force\": true}}))", slash(&sub))).unwrap_err();
        assert!(bad_opt.contains("unknown option"), "{}", bad_opt);
        assert_eq!(run(&g, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&sub))).unwrap(), vec!["true"]);
        assert!(!sub.exists());
        let on_file = {
            let f = d.join("f.txt");
            std::fs::write(&f, "x").unwrap();
            run(&g, &format!("print(delete_dir(\"{}\"))", slash(&f))).unwrap_err()
        };
        assert!(on_file.contains("is a file"), "{}", on_file);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// §4.2 — cwd() bajo `file.read(".")` (la misma grant que `list_dir(".")`): sin grant o
    /// con una grant que no cubre `.` deniega; con `.`, `./*` o `*` la devuelve normalizada.
    #[test]
    fn cwd_requires_file_read_on_dot() {
        let want = normalize_path(&std::env::current_dir().unwrap().to_string_lossy());
        let denied = run(&[], "print(cwd())").unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        let denied = run(&[(CapabilityType::FileRead, Some("./data/*".to_string()))], "print(cwd())").unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        for scope in [".", "./*", "*"] {
            assert_eq!(run(&[(CapabilityType::FileRead, Some(scope.to_string()))], "print(cwd())").unwrap(), vec![want.clone()], "scope {}", scope);
        }
    }

    /// Auditoría externa — borrar recursivo exige `file.write` sobre cada ruta del árbol.
    #[test]
    fn delete_dir_recursive_requires_file_write_on_every_path() {
        let d = scratch("delete-tree-scope");
        let tree = d.join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::write(tree.join("sub").join("f.txt"), "x").unwrap();
        // Scope exacto sobre el dir raíz: cubre borrarlo a él, no a lo que tiene adentro.
        let exact = [(CapabilityType::FileWrite, Some(slash(&tree)))];
        let e = run(&exact, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&tree))).unwrap_err();
        assert!(e.contains("Capability not granted"), "{}", e);
        assert!(tree.join("sub").join("f.txt").exists(), "nada borrado");
        let wide = [(CapabilityType::FileWrite, Some(format!("{}/*", slash(&d))))];
        assert_eq!(run(&wide, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&tree))).unwrap(), vec!["true"]);
        assert!(!tree.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// §4.4 — sin bundle montado: el disco manda y `bundle:` explícito falla claro.
    #[test]
    fn user_files_go_to_disk_and_explicit_bundle_prefix_without_a_bundle() {
        let d = scratch("disk-first");
        let f = d.join("data.txt");
        std::fs::write(&f, "hola").unwrap();
        let g = [(CapabilityType::FileRead, Some(format!("{}/*", slash(&d))))];
        assert_eq!(run(&g, &format!("print(read_file(\"{}\"))", slash(&f))).unwrap(), vec!["hola"]);
        assert_eq!(run(&g, &format!("print(file_exists(\"{}\"))", slash(&f))).unwrap(), vec!["true"]);
        let e = run(&g, &format!("print(read_file(\"bundle:{}\"))", slash(&f))).unwrap_err();
        assert!(e.contains("is not in the bundle"), "{}", e);
        let e = run(&g, "print(list_dir(\"bundle:\"))").unwrap_err();
        assert!(e.contains("has no bundle"), "{}", e);
        // list_dir sobre el disco sigue igual (sobre un subdir cubierto por el scope `<dir>/*`).
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("one.txt"), "1").unwrap();
        let out = run(&g, &format!("print(length(list_dir(\"{}\")))", slash(&sub))).unwrap();
        assert_eq!(out, vec!["1"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
