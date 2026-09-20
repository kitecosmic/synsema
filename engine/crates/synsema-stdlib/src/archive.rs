//! v0.6.20 — archivos comprimidos: `zip_create`/`zip_extract`/`tar_create`/`tar_extract`.
//! SÓLO perfil native (extraer toca disco; en el perfil puro los cuatro son stubs).
//!
//! - `zip_create(entries, opts?) → bytes` y `tar_create(entries, opts?) → bytes`. `entries` es
//!   una lista de `{"path": texto, "bytes": bytes}` o `{"path": texto, "from": ruta}`; `from`
//!   lee un asset del bundle de `synsema build` sin `file.read` (con su línea de audit, como
//!   `read_file`) y cualquier otra ruta del disco con `file.read`. `tar_create`
//!   acepta `{"gzip": true}`. Los paths dentro del archivo se normalizan a `/`, sin `..` ni
//!   absolutos. Deterministas: mismas entradas → mismos bytes (mtime fijo, sin reloj).
//! - `zip_extract(bytes, dest, opts?) → [rutas]` y `tar_extract(bytes, dest, opts?) → [rutas]`
//!   (tar detecta gzip por magic). **Cada ruta escrita pasa por `file.write`** (la misma grant
//!   que pediría `write_file` para esa ruta: `file.write("./out/*")` extrae en `./out`); `dest`
//!   no se exige aparte ni se crea si el archivo no trae nada. **Zip-slip**: cada entrada se
//!   normaliza léxicamente y debe quedar bajo `dest`; si no, error y nada escrito. Symlinks y
//!   hardlinks se omiten (no se materializan). `opts.max_entries` (10 000) y `opts.max_bytes`
//!   (512 MB) contra bombas: se cuentan los bytes REALES descomprimidos, y "nada escrito" se
//!   paga reteniendo el contenido en memoria (hasta `max_bytes`) antes de escribir; para
//!   archivos grandes, bajar `max_bytes` o extraer por partes.
//! - `.gitignore` no se interpreta acá: es política del CLI, que arma `entries`.
//!

use std::cell::RefCell;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use indexmap::IndexMap;

use synsema_capabilities::model::{normalize_path, Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bytes, syn_list, syn_text, SynValue};

const DEFAULT_MAX_ENTRIES: u64 = 10_000;
const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn require(caps: &Rc<RefCell<CapabilitySet>>, ty: CapabilityType, scope: &str, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&Capability::new(ty, Some(scope.to_string())), source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// Path DENTRO de un archivo: separadores `/`, sin `./`, sin `..`, sin absolutos ni unidades.
fn archive_name(raw: &str, who: &str) -> Result<String, Control> {
    let s = raw.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(err(format!("{}: entry path {:?} contains '..'", who, raw))),
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err(err(format!("{}: entry path {:?} is empty", who, raw)));
    }
    if s.starts_with('/') || (s.len() > 1 && s.as_bytes()[1] == b':') {
        return Err(err(format!("{}: entry path {:?} must be relative", who, raw)));
    }
    Ok(parts.join("/"))
}

struct Entry {
    name: String,
    data: Vec<u8>,
}

fn entries_arg(caps: &Rc<RefCell<CapabilitySet>>, v: Option<&SynValue>, who: &str) -> Result<Vec<Entry>, Control> {
    let list = match v {
        Some(SynValue::List(l)) => l.borrow().clone(),
        Some(other) => {
            return Err(err(format!(
                "{}: entries must be a list of {{path, bytes}} or {{path, from}}, got {}",
                who,
                other.type_name()
            )))
        }
        None => return Err(err(format!("{}(entries, opts?) takes the list of entries", who))),
    };
    if list.is_empty() {
        return Err(err(format!("{}: entries is empty", who)));
    }
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let SynValue::Map(m) = item else {
            return Err(err(format!("{}: entry {} must be a map, got {}", who, i, item.type_name())));
        };
        let m = m.borrow();
        for k in m.keys() {
            if !matches!(k.as_str(), "path" | "bytes" | "from") {
                return Err(err(format!(
                    "{}: entry {} has an unknown key {:?} (valid: path, bytes, from)",
                    who, i, k
                )));
            }
        }
        let name = match m.get("path") {
            Some(SynValue::Text(s)) => archive_name(s, who)?,
            _ => return Err(err(format!("{}: entry {} needs a text \"path\"", who, i))),
        };
        let data = match (m.get("bytes"), m.get("from")) {
            (Some(SynValue::Bytes(b)), None) => b.to_vec(),
            (Some(SynValue::Text(t)), None) => t.as_bytes().to_vec(),
            (Some(other), None) => {
                return Err(err(format!(
                    "{}: entry {} \"bytes\" must be bytes or text, got {}",
                    who,
                    i,
                    other.type_name()
                )))
            }
            (None, Some(SynValue::Text(from))) => {
                // Assets del programa desde el bundle (sin file.read); lo demás, del disco.
                let path = normalize_path(from);
                if let Some(b) = synsema_core::bundle::get(&path) {
                    synsema_capabilities::secure::bundled_audit(caps, CapabilityType::FileRead, &path, &format!("{}()", who));
                    b.to_vec()
                } else {
                    require(caps, CapabilityType::FileRead, &path, &format!("{}()", who))?;
                    std::fs::read(&path).map_err(|e| err(format!("{}: cannot read {}: {}", who, path, e)))?
                }
            }
            (None, Some(other)) => {
                return Err(err(format!("{}: entry {} \"from\" must be a path, got {}", who, i, other.type_name())))
            }
            (Some(_), Some(_)) => {
                return Err(err(format!("{}: entry {} has both \"bytes\" and \"from\"; pass one", who, i)))
            }
            (None, None) => return Err(err(format!("{}: entry {} needs \"bytes\" or \"from\"", who, i))),
        };
        out.push(Entry { name, data });
    }
    Ok(out)
}

fn opts_arg(v: Option<&SynValue>, who: &str, valid: &[&str]) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(IndexMap::new()),
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for k in m.keys() {
                if !valid.contains(&k.as_str()) {
                    return Err(err(format!(
                        "{}: unknown option {:?}; valid options are: {}",
                        who,
                        k,
                        valid.join(", ")
                    )));
                }
            }
            Ok(m.clone())
        }
        Some(other) => Err(err(format!("{}: opts must be a map, got {}", who, other.type_name()))),
    }
}

fn opt_flag(opts: &IndexMap<String, SynValue>, k: &str, who: &str) -> Result<bool, Control> {
    match opts.get(k) {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(err(format!("{}: option {:?} must be true or false, got {}", who, k, other.type_name()))),
    }
}

fn opt_limit(opts: &IndexMap<String, SynValue>, k: &str, default: u64, who: &str) -> Result<u64, Control> {
    match opts.get(k) {
        None | Some(SynValue::Nothing) => Ok(default),
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if f >= 1.0 && f.is_finite() {
                Ok(f as u64)
            } else {
                Err(err(format!("{}: option {:?} must be a positive number, got {}", who, k, f)))
            }
        }
        Some(other) => Err(err(format!("{}: option {:?} must be a number, got {}", who, k, other.type_name()))),
    }
}

// ---------------------------------------------------------------------------------
// crear
// ---------------------------------------------------------------------------------

fn zip_create(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "zip_create";
    let entries = entries_arg(caps, args.first(), F)?;
    let _opts = opts_arg(args.get(1), F, &[])?;
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for e in &entries {
        w.start_file(e.name.as_str(), options)
            .map_err(|x| err(format!("{}: {}: {}", F, e.name, x)))?;
        w.write_all(&e.data).map_err(|x| err(format!("{}: {}: {}", F, e.name, x)))?;
    }
    let cursor = w.finish().map_err(|x| err(format!("{}: {}", F, x)))?;
    Ok(syn_bytes(cursor.into_inner()))
}

fn tar_create(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "tar_create";
    let entries = entries_arg(caps, args.first(), F)?;
    let opts = opts_arg(args.get(1), F, &["gzip"])?;
    let gzip = opt_flag(&opts, "gzip", F)?;
    let mut builder = tar::Builder::new(Vec::new());
    for e in &entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(e.data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, e.name.as_str(), &e.data[..])
            .map_err(|x| err(format!("{}: {}: {}", F, e.name, x)))?;
    }
    let raw = builder.into_inner().map_err(|x| err(format!("{}: {}", F, x)))?;
    if !gzip {
        return Ok(syn_bytes(raw));
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&raw).map_err(|x| err(format!("{}: gzip: {}", F, x)))?;
    Ok(syn_bytes(enc.finish().map_err(|x| err(format!("{}: gzip: {}", F, x)))?))
}

// ---------------------------------------------------------------------------------
// extraer
// ---------------------------------------------------------------------------------

struct Extract {
    dest: PathBuf,
    max_entries: u64,
    max_bytes: u64,
}

fn extract_args(args: &[SynValue], who: &str) -> Result<(Vec<u8>, Extract), Control> {
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(bytes, dest, opts?) takes 2 or 3 arguments", who)));
    }
    let data = match args.first() {
        Some(SynValue::Bytes(b)) => b.to_vec(),
        Some(other) => return Err(err(format!("{}: the archive must be bytes, got {}", who, other.type_name()))),
        None => unreachable!(),
    };
    let dest = match args.get(1) {
        Some(SynValue::Text(s)) if !s.trim().is_empty() => normalize_path(s.trim()),
        _ => return Err(err(format!("{}: dest must be a non-empty directory path", who))),
    };
    let opts = opts_arg(args.get(2), who, &["max_entries", "max_bytes"])?;
    // La puerta es `file.write` sobre CADA ruta escrita (`target_of`), como `write_file`, que
    // también crea los padres que falten: `dest` no se exige aparte (el idioma
    // `file.write("./out/*")` debe poder extraer en `./out`).
    Ok((
        data,
        Extract {
            dest: PathBuf::from(dest),
            max_entries: opt_limit(&opts, "max_entries", DEFAULT_MAX_ENTRIES, who)?,
            max_bytes: opt_limit(&opts, "max_bytes", DEFAULT_MAX_BYTES, who)?,
        },
    ))
}

/// Destino final de una entrada: bajo `dest` o error (zip-slip). Devuelve el path relativo
/// normalizado y el real en disco. **Exige `file.write` sobre ESA ruta** : el
/// scope que cubre `write_file("./out/a.txt")` es el mismo que cubre extraerlo; sólo el
/// destino raíz no alcanza.
fn target_of(caps: &Rc<RefCell<CapabilitySet>>, x: &Extract, raw: &str, who: &str) -> Result<(String, PathBuf), Control> {
    let name = archive_name(raw, who).map_err(|_| {
        err(format!(
            "{}: entry {:?} would escape the destination directory (rejected, nothing written)",
            who, raw
        ))
    })?;
    let target = x.dest.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
    require(caps, CapabilityType::FileWrite, &normalize_path(&target.to_string_lossy()), &format!("{}()", who))?;
    Ok((name, target))
}

/// Lee una entrada acotando los bytes REALES : el tamaño declarado en el
/// header de un zip/tar puede mentir; lo que cuenta es lo que sale del descompresor.
fn read_capped<R: Read>(r: &mut R, remaining: u64, name: &str, who: &str, max_bytes: u64) -> Result<Vec<u8>, Control> {
    let mut buf = Vec::new();
    r.by_ref()
        .take(remaining.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| err(format!("{}: {}: {}", who, name, e)))?;
    if buf.len() as u64 > remaining {
        return Err(err(format!(
            "{}: uncompressed size above max_bytes {} (nothing written)",
            who, max_bytes
        )));
    }
    Ok(buf)
}

fn write_entry(path: &Path, data: &[u8], who: &str) -> Result<(), Control> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| err(format!("{}: {}: {}", who, parent.display(), e)))?;
    }
    std::fs::write(path, data).map_err(|e| err(format!("{}: {}: {}", who, path.display(), e)))
}

fn zip_extract(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "zip_extract";
    let (data, x) = extract_args(args, F)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| err(format!("{}: not a zip: {}", F, e)))?;
    if archive.len() as u64 > x.max_entries {
        return Err(err(format!("{}: {} entries, above max_entries {}", F, archive.len(), x.max_entries)));
    }
    // Primero se valida y se LEE todo (paths, file.write por entrada y bytes REALES acotados);
    // recién después se escribe: si algo falla, no queda ni un archivo a medias.
    let mut plan: Vec<(String, PathBuf, Vec<u8>, bool)> = Vec::new();
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(|e| err(format!("{}: entry {}: {}", F, i, e)))?;
        let raw = f.name().to_string();
        let is_symlink = f.unix_mode().map(|m| m & 0o170000 == 0o120000).unwrap_or(false);
        if is_symlink {
            continue;
        }
        let is_dir = f.is_dir();
        let (name, target) = target_of(caps, &x, &raw, F)?;
        if is_dir {
            plan.push((name, target, Vec::new(), true));
            continue;
        }
        let buf = read_capped(&mut f, x.max_bytes.saturating_sub(total), &name, F, x.max_bytes)?;
        total = total.saturating_add(buf.len() as u64);
        plan.push((name, target, buf, false));
    }
    let mut written: Vec<SynValue> = Vec::new();
    for (name, target, buf, is_dir) in plan {
        if is_dir {
            std::fs::create_dir_all(&target).map_err(|e| err(format!("{}: {}: {}", F, target.display(), e)))?;
            continue;
        }
        write_entry(&target, &buf, F)?;
        written.push(syn_text(name));
    }
    Ok(syn_list(written))
}

fn tar_extract(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "tar_extract";
    let (data, x) = extract_args(args, F)?;
    let raw: Vec<u8> = if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut dec = flate2::read::GzDecoder::new(Cursor::new(&data));
        let mut out = Vec::new();
        // Un gzip que descomprime a más de max_bytes es una bomba: se corta al límite.
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = dec.read(&mut chunk).map_err(|e| err(format!("{}: gzip: {}", F, e)))?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            if out.len() as u64 > x.max_bytes {
                return Err(err(format!("{}: uncompressed size above max_bytes {} (nothing written)", F, x.max_bytes)));
            }
        }
        out
    } else {
        data
    };
    // Dos pasadas: validar (paths, límites) y recién después escribir.
    let mut plan: Vec<(String, PathBuf, Vec<u8>, bool)> = Vec::new();
    let mut total: u64 = 0;
    let mut count: u64 = 0;
    let mut archive = tar::Archive::new(Cursor::new(&raw));
    for entry in archive.entries().map_err(|e| err(format!("{}: not a tar: {}", F, e)))? {
        let mut entry = entry.map_err(|e| err(format!("{}: {}", F, e)))?;
        count += 1;
        if count > x.max_entries {
            return Err(err(format!("{}: more than max_entries {} entries (nothing written)", F, x.max_entries)));
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }
        let path = entry.path().map_err(|e| err(format!("{}: {}", F, e)))?.to_string_lossy().to_string();
        let (name, target) = target_of(caps, &x, &path, F)?;
        if kind.is_dir() {
            plan.push((name, target, Vec::new(), true));
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let buf = read_capped(&mut entry, x.max_bytes.saturating_sub(total), &name, F, x.max_bytes)?;
        total = total.saturating_add(buf.len() as u64);
        plan.push((name, target, buf, false));
    }
    let mut written: Vec<SynValue> = Vec::new();
    for (name, target, buf, is_dir) in plan {
        if is_dir {
            std::fs::create_dir_all(&target).map_err(|e| err(format!("{}: {}: {}", F, target.display(), e)))?;
        } else {
            write_entry(&target, &buf, F)?;
            written.push(syn_text(name));
        }
    }
    Ok(syn_list(written))
}

pub fn register_archive_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    {
        let caps = caps.clone();
        interp.register_builtin("zip_create", -1, Rc::new(move |_i, a, _l| zip_create(&caps, a)));
    }
    {
        let caps = caps.clone();
        interp.register_builtin("zip_extract", -1, Rc::new(move |_i, a, _l| zip_extract(&caps, a)));
    }
    {
        let caps = caps.clone();
        interp.register_builtin("tar_create", -1, Rc::new(move |_i, a, _l| tar_create(&caps, a)));
    }
    interp.register_builtin("tar_extract", -1, Rc::new(move |_i, a, _l| tar_extract(&caps, a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_map;

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!("synsema-archive-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn caps_for(dir: &Path) -> Rc<RefCell<CapabilitySet>> {
        let mut set = CapabilitySet::new("test");
        let scope = normalize_path(&dir.to_string_lossy());
        set.grant(Capability::new(CapabilityType::FileWrite, Some(scope.clone())));
        set.grant(Capability::new(CapabilityType::FileWrite, Some(format!("{}/*", scope))));
        set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/*", scope))));
        Rc::new(RefCell::new(set))
    }

    fn entry(path: &str, data: &str) -> SynValue {
        let mut m = IndexMap::new();
        m.insert("path".to_string(), syn_text(path));
        m.insert("bytes".to_string(), syn_bytes(data.as_bytes().to_vec()));
        syn_map(m)
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn bytes_of(v: SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b.to_vec(),
            other => panic!("esperaba bytes, got {}", other),
        }
    }

    #[test]
    fn zip_round_trip_is_deterministic_and_lists_written_files() {
        let d = scratch("zip");
        let caps = caps_for(&d);
        let entries = syn_list(vec![entry("a.txt", "hola"), entry("dir/b.txt", "mundo")]);
        let z1 = bytes_of(ok(zip_create(&caps, &[entries.clone()])));
        let z2 = bytes_of(ok(zip_create(&caps, &[entries])));
        assert_eq!(z1, z2, "mismas entradas → mismos bytes");
        let dest = d.join("out");
        let dest_s = dest.to_string_lossy().replace('\\', "/");
        let list = ok(zip_extract(&caps, &[syn_bytes(z1), syn_text(dest_s.as_str())]));
        assert_eq!(list.to_string(), "[a.txt, dir/b.txt]");
        assert_eq!(std::fs::read_to_string(dest.join("dir").join("b.txt")).unwrap(), "mundo");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tar_and_tar_gz_round_trip() {
        let d = scratch("tar");
        let caps = caps_for(&d);
        let entries = syn_list(vec![entry("x/y.txt", "1"), entry("z.txt", "22")]);
        let plain = bytes_of(ok(tar_create(&caps, &[entries.clone()])));
        let mut gz_opts = IndexMap::new();
        gz_opts.insert("gzip".to_string(), SynValue::Bool(true));
        let gz = bytes_of(ok(tar_create(&caps, &[entries, syn_map(gz_opts)])));
        assert_eq!(&gz[..2], &[0x1f, 0x8b]);
        assert!(gz.len() < plain.len());
        for (tag, data) in [("plain", plain), ("gz", gz)] {
            let dest = d.join(tag);
            let dest_s = dest.to_string_lossy().replace('\\', "/");
            let list = ok(tar_extract(&caps, &[syn_bytes(data), syn_text(dest_s.as_str())]));
            assert_eq!(list.to_string(), "[x/y.txt, z.txt]", "{}", tag);
            assert_eq!(std::fs::read_to_string(dest.join("z.txt")).unwrap(), "22");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_slip_is_rejected_before_writing_anything() {
        let d = scratch("slip");
        let caps = caps_for(&d);
        // Un zip armado a mano con una entrada `../evil.txt` (zip_create no la dejaría pasar).
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("ok.txt", o).unwrap();
        w.write_all(b"fine").unwrap();
        w.start_file("../evil.txt", o).unwrap();
        w.write_all(b"pwned").unwrap();
        let z = w.finish().unwrap().into_inner();
        let dest = d.join("out");
        let dest_s = dest.to_string_lossy().replace('\\', "/");
        let e = match zip_extract(&caps, &[syn_bytes(z), syn_text(dest_s.as_str())]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba rechazo"),
        };
        assert!(e.contains("would escape"), "{}", e);
        assert!(!dest.join("ok.txt").exists(), "nada escrito");
        assert!(!d.join("evil.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un zip cuyo header MIENTE el tamaño (declara poco, trae mucho) no pasa
    /// el techo de bytes reales, y nada queda escrito.
    #[test]
    fn extract_caps_real_bytes_not_declared_size_and_writes_nothing_on_failure() {
        let d = scratch("bomb");
        let caps = caps_for(&d);
        // 2 MB de ceros comprimen a casi nada; el header declara el tamaño real (2 MB), pero el
        // test acota a 1000 bytes: debe fallar por los bytes REALES leídos, no por el header.
        let big = vec![0u8; 2 * 1024 * 1024];
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.start_file("small.txt", o).unwrap();
        w.write_all(b"ok").unwrap();
        w.start_file("big.bin", o).unwrap();
        w.write_all(&big).unwrap();
        let z = w.finish().unwrap().into_inner();
        assert!(z.len() < 10_000, "comprimido: {}", z.len());
        let dest = d.join("out");
        let dest_s = dest.to_string_lossy().replace('\\', "/");
        let mut opts = IndexMap::new();
        opts.insert("max_bytes".to_string(), SynValue::Number(synsema_core::number::Number::Int(1000)));
        let e = match zip_extract(&caps, &[syn_bytes(z.clone()), syn_text(dest_s.as_str()), syn_map(opts)]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba rechazo por max_bytes"),
        };
        assert!(e.contains("above max_bytes"), "{}", e);
        assert!(!dest.join("small.txt").exists(), "nada escrito, ni la entrada válida previa");
        // Con techo suficiente, sale entero.
        let list = ok(zip_extract(&caps, &[syn_bytes(z), syn_text(dest_s.as_str())]));
        assert_eq!(list.to_string(), "[small.txt, big.bin]");
        assert_eq!(std::fs::metadata(dest.join("big.bin")).unwrap().len(), 2 * 1024 * 1024);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Segunda ronda — el idioma `file.write("./out/*")` (sin grant sobre `out` en sí) extrae en
    /// `./out` aunque no exista todavía: la puerta es por ruta escrita, como `write_file`.
    #[test]
    fn extract_works_with_a_glob_scope_that_does_not_cover_dest_itself() {
        let d = scratch("glob-only");
        let dest = d.join("out");
        let dest_s = dest.to_string_lossy().replace('\\', "/");
        let mut set = CapabilitySet::new("test");
        set.grant(Capability::new(CapabilityType::FileWrite, Some(format!("{}/*", normalize_path(&dest_s)))));
        let caps = Rc::new(RefCell::new(set));
        let z = bytes_of(ok(zip_create(&caps_for(&d), &[syn_list(vec![entry("a/b.txt", "x"), entry("c.txt", "y")])])));
        assert!(!dest.exists());
        let list = ok(zip_extract(&caps, &[syn_bytes(z), syn_text(dest_s.as_str())]));
        assert_eq!(list.to_string(), "[a/b.txt, c.txt]");
        assert_eq!(std::fs::read_to_string(dest.join("a").join("b.txt")).unwrap(), "x");
        // Un archivo sin entradas no crea `dest` (no hay nada que escribir ni grant que lo cubra).
        let empty_dest = d.join("never");
        // (`zip_create` rechaza una lista vacía a propósito; el zip vacío se arma a mano.)
        let empty = zip::ZipWriter::new(Cursor::new(Vec::new())).finish().unwrap().into_inner();
        let list = ok(zip_extract(&caps_for(&d), &[syn_bytes(empty), syn_text(empty_dest.to_string_lossy().replace('\\', "/").as_str())]));
        assert_eq!(list.to_string(), "[]");
        assert!(!empty_dest.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Extraer exige `file.write` sobre CADA ruta escrita, no sólo sobre el
    /// destino raíz: con un scope exacto (sin comodín) no se escribe nada dentro.
    #[test]
    fn extract_requires_file_write_per_entry() {
        let d = scratch("per-entry");
        let dest = d.join("exact");
        std::fs::create_dir_all(&dest).unwrap();
        let dest_s = dest.to_string_lossy().replace('\\', "/");
        let mut set = CapabilitySet::new("test");
        set.grant(Capability::new(CapabilityType::FileWrite, Some(normalize_path(&dest_s))));
        let caps = Rc::new(RefCell::new(set));
        let z = bytes_of(ok(zip_create(&caps_for(&d), &[syn_list(vec![entry("d/b.txt", "x")])])));
        let e = match zip_extract(&caps, &[syn_bytes(z), syn_text(dest_s.as_str())]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba denegación por entrada"),
        };
        assert!(e.contains("Capability not granted"), "{}", e);
        assert!(!dest.join("d").exists(), "nada escrito");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_rejects_bad_entry_paths_and_extract_needs_file_write() {
        let d = scratch("gates");
        let caps = caps_for(&d);
        let e = match zip_create(&caps, &[syn_list(vec![entry("../x", "1")])]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!(),
        };
        assert!(e.contains("contains '..'"), "{}", e);
        let z = bytes_of(ok(zip_create(&caps, &[syn_list(vec![entry("a", "1")])])));
        let no_caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
        let e = match zip_extract(&no_caps, &[syn_bytes(z), syn_text("somewhere")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!(),
        };
        assert!(e.contains("Capability not granted"), "{}", e);
        let _ = std::fs::remove_dir_all(&d);
    }
}
