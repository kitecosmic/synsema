//! Builtins seguros (gateados por capability). Port de `capabilities/enforcer.py`
//! (SecureOperations) + `capabilities/builtins.py` (register_secure_builtins).
//!
//! Reemplazan I/O cruda por operaciones chequeadas. La violación produce un
//! `Runtime error: Capability not granted: <cap>` (sin ubicación — la
//! CapabilityViolation no la lleva; el prefijo de categoría lo agrega el motor).
//!
//! Capa 5: read_file/write_file hacen la op real de filesystem; fetch sólo chequea
//! la capability (el HTTP real es capa 6).

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

use crate::model::{fnmatch, normalize_path, Capability, CapabilityType, CapabilitySet};

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

/// Chequea una capability; convierte la violación en `Control::Error` SIN ubicación.
fn require(caps: &Rc<RefCell<CapabilitySet>>, cap: Capability, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&cap, source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// Hostname de un URL, como `urlparse().hostname` de Python: minúsculas, sin
/// userinfo ni puerto. `None` si no hay esquema `scheme://`.
pub fn url_hostname(url: &str) -> Option<String> {
    let after = url.find("://").map(|i| &url[i + 3..])?;
    let end = after
        .find(|c| c == '/' || c == '?' || c == '#')
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
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e
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
        let naive = NaiveDateTime::parse_from_str(s, p)
            .map_err(|e| Control::Error(RuntimeError::new(format!("invalid time: {}", e))))?;
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
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "read_file()",
                )?;
                // arity-1: archivo completo, idéntico a hoy (read_to_string estricto).
                if args.len() < 2 {
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
                let path = normalize_path(&raw_str(arg(args, 0)?));
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
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "file_info()",
                )?;
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
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "file_exists()",
                )?;
                Ok(syn_bool(std::fs::metadata(&path).is_ok()))
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
                let target = normalize_path(&raw_str(arg(args, 0)?));
                let pattern = raw_str(arg(args, 1)?);
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(target.clone())),
                    "grep()",
                )?;
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
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "read_file_bytes()",
                )?;
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
            Rc::new(move |_i, args, _loc| {
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
                    Some(SynValue::Number(n)) => (n.to_f64() as usize).max(0),
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
                if let Some(SynValue::Map(m)) = opt("env") {
                    for (k, v) in m.borrow().iter() {
                        c.env(k, raw_str(v)); // hereda environ + override
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

    // fetch(url) — sólo chequeo de capability (HTTP real es capa 6).
    // Requiere net("<hostname>") (hostname del URL, no el URL completo).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "fetch",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(arg(args, 0)?);
                let host = match url_hostname(&url) {
                    Some(h) if !h.is_empty() => h,
                    _ => url.clone(),
                };
                require(&caps, Capability::new(CapabilityType::Net, Some(host)), "fetch()")?;
                // Capability concedida: el HTTP real llega en capa 6.
                Err(Control::Error(RuntimeError::new(
                    "fetch: the HTTP runtime is not available yet (capa 6)",
                )))
            }),
        );
    }

    // -- Builtins de time (todos requieren la capability `time`; UTC) --

    // now() → timestamp unix (float).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "now",
            0,
            Rc::new(move |_i, _args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "now()")?;
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                Ok(syn_float(secs))
            }),
        );
    }

    // sleep(seconds) → pausa (cap a 1h). Requiere time (como now()).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "sleep()")?;
                let secs = args.first().and_then(|v| arg_f64(v).ok()).unwrap_or(0.0);
                let secs = secs.clamp(0.0, 3600.0);
                std::thread::sleep(std::time::Duration::from_secs_f64(secs));
                Ok(SynValue::Nothing)
            }),
        );
    }

    // format_time(ts, pattern?) → text. Default ISO-8601 UTC ("…Z").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "format_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "format_time()")?;
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

    // parse_time(text, pattern?) → timestamp (float). Inverso de format_time.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "parse_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "parse_time()")?;
                let s = raw_str(arg(args, 0)?);
                let ts = parse_time_ts(&s, opt_pattern(args).as_deref())?;
                Ok(syn_float(ts))
            }),
        );
    }

    // date_parts(ts) → {year, month, day, hour, minute, second} (UTC).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "date_parts",
            1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "date_parts()")?;
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let mut m = IndexMap::new();
                m.insert("year".to_string(), syn_int(dt.year() as i64));
                m.insert("month".to_string(), syn_int(dt.month() as i64));
                m.insert("day".to_string(), syn_int(dt.day() as i64));
                m.insert("hour".to_string(), syn_int(dt.hour() as i64));
                m.insert("minute".to_string(), syn_int(dt.minute() as i64));
                m.insert("second".to_string(), syn_int(dt.second() as i64));
                Ok(syn_map(m))
            }),
        );
    }

    // -- Builtins de random (requieren la capability `random`) --
    // Paridad con el oráculo: random() = float [0,1), random_int(lo,hi) = entero INCLUSIVO
    // [lo,hi]. RNG no-cripto como el `random` de Python (Mersenne Twister); los valores no
    // son byte-idénticos al oráculo (RNG distinto) — el contrato es rango+tipo+capability.

    // random() → float en [0,1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random",
            0,
            Rc::new(move |_i, _args, _loc| {
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
            2,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Random, None), "random_int()")?;
                // int(arg) trunca hacia cero, como `int(args[i].raw)` del oráculo.
                let lo = arg_f64(arg(args, 0)?)?.trunc() as i64;
                let hi = arg_f64(arg(args, 1)?)?.trunc() as i64;
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
