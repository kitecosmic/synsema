//! v0.6.58 (§3, §8 de `specs/v0.6.58-diseno.md`): el proyecto de un programa.
//!
//! El proyecto es la carpeta del `synsema.json` más cercano hacia arriba desde la carpeta del archivo
//! de entrada; sin ninguno, la carpeta de la entrada, como antes. Se resuelve **una vez por corrida**
//! (lo guarda la [`RunScope`](crate::run_scope::RunScope)) y lo comparten todos los intérpretes de
//! esa corrida: el principal, los workers de `serve` y `parallel_map`, los agentes y `spawn`.
//! Ningún intérprete captura su raíz de su primer `use` (D-4).
//!
//! Todo esto es frío: corre antes de la primera sentencia y nunca en el camino de una llamada.
//!
//! El chequeo del dueño del archivo (§3, E-8) necesita al sistema operativo (el uid en Unix, el SID
//! en Windows), y el núcleo no habla con el sistema operativo: lo registra la stdlib con
//! [`set_owner_check`]. En un host nativo sin chequeo registrado, el `synsema.json` se ignora con
//! aviso (falla cerrado). En wasm no hay chequeo: los límites los pone quien arma el host (§12).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// La versión de este motor cuando el binario no es de un release (`cargo build`). Se sube al abrir
/// la versión siguiente; `engine_version_is_not_behind_the_changelog` no deja que quede atrás.
pub const DEV_VERSION: &str = "0.6.60";

/// La versión del motor: la del release (`SYNSEMA_VERSION`, el tag, lo setea `release.yml`) o
/// [`DEV_VERSION`] en un build de desarrollo (que cuenta como esa versión, §8).
pub fn engine_version() -> (u32, u32, u32) {
    let raw = option_env!("SYNSEMA_VERSION").unwrap_or(DEV_VERSION);
    let core = raw.trim_start_matches('v');
    let core = core.split(['-', '+']).next().unwrap_or(core);
    parse_three(core).unwrap_or_else(|| parse_three(DEV_VERSION).expect("DEV_VERSION is X.Y.Z"))
}

/// `X.Y.Z`, sólo dígitos ASCII, sin ceros a la izquierda de más.
pub fn parse_three(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let mut num = || -> Option<u32> {
        let p = it.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        p.parse().ok()
    };
    let v = (num()?, num()?, num()?);
    if it.next().is_some() {
        return None;
    }
    Some(v)
}

pub fn show_version(v: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Las claves de un `synsema.json`. Un paquete es un proyecto que además se publica.
pub const PROJECT_KEYS: [&str; 3] = ["synsema", "modules", "indirect"];
pub const PACKAGE_KEYS: [&str; 4] = ["id", "version", "main", "files"];
/// Las claves de una entrada de `modules`.
pub const MODULE_KEYS: [&str; 5] = ["url", "id", "version", "hash", "requires"];
/// Las claves de una entrada de `indirect` (la clave de la entrada es su `id`).
pub const INDIRECT_KEYS: [&str; 4] = ["url", "version", "hash", "requires"];

/// Una dependencia declarada en `modules` (§3) o en `indirect` (§11).
#[derive(Clone, Debug, PartialEq)]
pub struct ModEntry {
    pub url: String,
    pub id: Option<String>,
    pub version: Option<String>,
    pub hash: Option<String>,
    pub requires: Vec<String>,
}

/// Un archivo del índice de un paquete (§4.2).
#[derive(Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
}

/// Un `synsema.json` ya leído y validado en su forma.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Manifest {
    /// El mínimo del motor (`"synsema"`), si lo declara.
    pub min: Option<(u32, u32, u32)>,
    /// `modules`, en el orden del archivo.
    pub modules: Vec<(String, ModEntry)>,
    /// `indirect`, en el orden del archivo: `id → entrada`.
    pub indirect: Vec<(String, ModEntry)>,
    pub id: Option<String>,
    pub version: Option<String>,
    pub main: Option<String>,
    pub files: Option<Vec<FileEntry>>,
}

impl Manifest {
    pub fn module(&self, name: &str) -> Option<&ModEntry> {
        self.modules.iter().find(|(n, _)| n == name).map(|(_, e)| e)
    }
}

/// `^[a-z][a-z0-9_-]{0,63}$` (§4.1).
pub fn is_module_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// El texto de un error de JSON sin el «at line N column M» del final (la posición va adelante).
fn json_error_text(e: &serde_json::Error) -> String {
    let s = e.to_string();
    match s.rfind(" at line ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// `synsema.json` → [`Manifest`]. `label` es como se nombra el archivo en los errores
/// (`synsema.json`, o el del paquete). El mínimo del motor se revisa **antes** que las claves (P6):
/// un proyecto escrito para un motor más nuevo puede tener claves que éste no conoce.
pub fn parse_manifest(bytes: &[u8], label: &str) -> Result<Manifest, String> {
    parse_manifest_of(bytes, label, None)
}

/// Como `parse_manifest`, para el índice de un paquete: el mínimo (que se mira antes que las claves,
/// como en el proyecto) da el texto de N14 con el nombre y la versión del módulo.
pub fn parse_manifest_of(bytes: &[u8], label: &str, module: Option<(&str, &str)>) -> Result<Manifest, String> {
    parse_manifest_with(bytes, label, module, true)
}

/// B17 (ronda 1): el `synsema.json` de un binario construido (§8/§9): el mínimo se revisó al construir
/// y el motor es el que lleva el binario; aquí no se revisa otra vez (la forma sí).
pub fn parse_manifest_built(bytes: &[u8], label: &str) -> Result<Manifest, String> {
    parse_manifest_with(bytes, label, None, false)
}

fn parse_manifest_with(bytes: &[u8], label: &str, module: Option<(&str, &str)>, check: bool) -> Result<Manifest, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("{}:{}:{}: {}", label, e.line(), e.column(), json_error_text(&e)))?;
    let serde_json::Value::Object(obj) = value else {
        return Err(format!("{}: the file is a JSON object ({{\"modules\": {{…}}}})", label));
    };
    let mut m = Manifest::default();
    if let Some(v) = obj.get("synsema") {
        let shown = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let min = match v {
            serde_json::Value::String(s) => parse_three(s),
            _ => None,
        };
        let Some(min) = min else {
            return Err(format!(
                "{}: \"synsema\" is a minimum version like \"{}\" (three numbers), not \"{}\"",
                label,
                DEV_VERSION,
                shown.replace('"', "\\\"")
            ));
        };
        if check {
            check_min(min, module)?;
        }
        m.min = Some(min);
    }
    for key in obj.keys() {
        if !PROJECT_KEYS.contains(&key.as_str()) && !PACKAGE_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "{}: unknown key \"{}\" (known: \"synsema\", \"modules\", \"indirect\"; a package also has \"id\", \"version\", \"main\", \"files\")",
                label, key
            ));
        }
    }
    let text = |key: &str, v: &serde_json::Value, what: &str| -> Result<String, String> {
        match v {
            serde_json::Value::String(s) => Ok(s.clone()),
            _ => Err(format!("{}: {} is a text ({})", label, key, what)),
        }
    };
    if let Some(v) = obj.get("modules") {
        let serde_json::Value::Object(mods) = v else {
            return Err(format!("{}: \"modules\" is an object of name → {{\"url\": …}}", label));
        };
        for (name, e) in mods {
            if !is_module_name(name) {
                return Err(format!(
                    "{}: \"{}\" is not a module name (lowercase letters, digits, '-' and '_', starting with a letter, up to 64)",
                    label, name
                ));
            }
            m.modules.push((name.clone(), parse_entry(label, &format!("module \"{}\"", name), e, &MODULE_KEYS)?));
        }
    }
    if let Some(v) = obj.get("indirect") {
        let serde_json::Value::Object(ind) = v else {
            return Err(format!("{}: \"indirect\" is an object of id → {{\"url\": …}} (synsema get writes it)", label));
        };
        for (id, e) in ind {
            let mut entry = parse_entry(label, &format!("indirect \"{}\"", id), e, &INDIRECT_KEYS)?;
            entry.id = Some(id.clone());
            m.indirect.push((id.clone(), entry));
        }
    }
    if let Some(v) = obj.get("id") {
        m.id = Some(text("\"id\"", v, "a URL prefix")?);
    }
    if let Some(v) = obj.get("version") {
        m.version = Some(text("\"version\"", v, "like \"0.1.0\"")?);
    }
    if let Some(v) = obj.get("main") {
        m.main = Some(text("\"main\"", v, "the path of the entry .syn")?);
    }
    if let Some(v) = obj.get("files") {
        let serde_json::Value::Array(items) = v else {
            return Err(format!("{}: \"files\" is a list of {{\"path\": …, \"sha256\": …}}", label));
        };
        let mut files = Vec::with_capacity(items.len());
        for it in items {
            let serde_json::Value::Object(f) = it else {
                return Err(format!("{}: each entry of \"files\" is {{\"path\": …, \"sha256\": …}}", label));
            };
            for k in f.keys() {
                if k != "path" && k != "sha256" {
                    return Err(format!("{}: unknown key \"{}\" in \"files\" (known: \"path\", \"sha256\")", label, k));
                }
            }
            let (Some(serde_json::Value::String(path)), Some(serde_json::Value::String(sha))) = (f.get("path"), f.get("sha256"))
            else {
                return Err(format!("{}: each entry of \"files\" has a text \"path\" and a text \"sha256\"", label));
            };
            files.push(FileEntry { path: path.clone(), sha256: sha.clone() });
        }
        m.files = Some(files);
    }
    Ok(m)
}

fn parse_entry(label: &str, what: &str, e: &serde_json::Value, known: &[&str]) -> Result<ModEntry, String> {
    let serde_json::Value::Object(o) = e else {
        return Err(format!("{}: {} is an object like {{\"url\": \"https://…\"}}", label, what));
    };
    for k in o.keys() {
        if !known.contains(&k.as_str()) {
            let list: Vec<String> = known.iter().map(|k| format!("\"{}\"", k)).collect();
            return Err(format!("{}: {} has an unknown key \"{}\" (known: {})", label, what, k, list.join(", ")));
        }
    }
    let opt = |k: &str| -> Result<Option<String>, String> {
        match o.get(k) {
            None => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{}: \"{}\" of {} is a text", label, k, what)),
        }
    };
    let Some(url) = opt("url")? else {
        return Err(format!("{}: {} has no \"url\"", label, what));
    };
    let requires = match o.get("requires") {
        None => Vec::new(),
        Some(serde_json::Value::Array(xs)) => {
            let mut out = Vec::with_capacity(xs.len());
            for x in xs {
                let serde_json::Value::String(s) = x else {
                    return Err(format!("{}: \"requires\" of {} is a list of texts", label, what));
                };
                out.push(s.clone());
            }
            out
        }
        Some(_) => return Err(format!("{}: \"requires\" of {} is a list of texts", label, what)),
    };
    Ok(ModEntry { url, id: opt("id")?, version: opt("version")?, hash: opt("hash")?, requires })
}

/// El mínimo contra este motor. `module` nombra al paquete que lo pide (N14); sin él, es el proyecto
/// (P3).
pub fn check_min(min: (u32, u32, u32), module: Option<(&str, &str)>) -> Result<(), String> {
    let me = engine_version();
    if min <= me {
        return Ok(());
    }
    Err(match module {
        None => format!("this project needs synsema >= {}; this is {}: synsema update", show_version(min), show_version(me)),
        Some((name, ver)) => format!(
            "module {} ({}) needs synsema >= {}; this is {}: synsema update",
            name,
            ver,
            show_version(min),
            show_version(me)
        ),
    })
}

/// ¿El archivo abierto es del usuario que corre? `Ok(true)` lo acepta. Lo registra la stdlib.
pub type OwnerCheck = fn(&std::fs::File) -> Result<bool, String>;

static OWNER_CHECK: OnceLock<OwnerCheck> = OnceLock::new();

/// La stdlib registra el chequeo del dueño (una vez por proceso; las siguientes no cambian nada).
pub fn set_owner_check(f: OwnerCheck) {
    let _ = OWNER_CHECK.set(f);
}

/// ¿Hay un chequeo del dueño registrado? (el anti-rot del host nativo lo mira).
pub fn owner_check_registered() -> bool {
    OWNER_CHECK.get().is_some()
}

/// El proyecto de una corrida (§3).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Project {
    /// La raíz: acota `use "../x.syn"` y es donde se buscan los nombres. `None` para un programa sin
    /// archivo (`<stdin>`, `<test>`).
    pub root: Option<PathBuf>,
    /// El `synsema.json` de la raíz, si hay uno que se usa.
    pub manifest: Option<Manifest>,
    /// Los avisos de la búsqueda (un `synsema.json` ignorado), en el orden en que pasaron.
    pub warnings: Vec<String>,
}

impl Project {
    /// La carpeta del `synsema.json` (sólo si hay uno que se usa).
    pub fn manifest_dir(&self) -> Option<&Path> {
        self.manifest.as_ref().and(self.root.as_deref())
    }
}

/// Lo que guarda la corrida: el proyecto, resuelto la primera vez que alguien lo pide.
#[derive(Default)]
pub struct ProjectSlot(OnceLock<Result<Arc<Project>, String>>);

impl ProjectSlot {
    pub fn get_or_resolve(&self, entry: &str) -> Result<Arc<Project>, String> {
        self.0.get_or_init(|| preflighted(entry).map(Ok).unwrap_or_else(|| resolve_fresh(entry).map(Arc::new))).clone()
    }

    /// El host ya resolvió el proyecto (o lo trae de un bundle): lo fija si nadie lo pidió antes.
    pub fn install(&self, p: Result<Arc<Project>, String>) {
        let _ = self.0.set(p);
    }

    pub fn get(&self) -> Option<&Result<Arc<Project>, String>> {
        self.0.get()
    }
}

/// La carpeta de un archivo de entrada, como hoy la tomaba `use`: `""` pasa a `"."`.
pub fn entry_dir(entry: &str) -> Option<PathBuf> {
    if entry.starts_with('<') {
        return None;
    }
    let parent = Path::new(entry).parent()?;
    Some(if parent.as_os_str().is_empty() { PathBuf::from(".") } else { parent.to_path_buf() })
}

fn absolute(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf())
    };
    crate::templates::lexical_normalize(&abs)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => absolute(a) == absolute(b),
    }
}

/// `SYNSEMA_SAFE_PROJECT`: `*` o carpetas separadas por el separador de rutas del sistema.
fn safe_listed(dir: &Path) -> bool {
    let Some(raw) = std::env::var_os("SYNSEMA_SAFE_PROJECT") else { return false };
    if raw == "*" {
        return true;
    }
    std::env::split_paths(&raw).any(|p| !p.as_os_str().is_empty() && same_dir(&p, dir))
}

/// N5 (ronda 1): abre para leer; en Unix con `O_NONBLOCK`, así un FIFO no cuelga el `open` (el que
/// llama después rechaza todo lo que no sea un archivo común).
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(0o4000);
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(0x0004);
    }
    o.open(path)
}

/// Un aviso por carpeta y por proceso (lo mismo se resuelve en el chequeo previo y al ejecutar).
fn warn_once(msg: &str) {
    static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut g = SEEN.lock().unwrap_or_else(|p| p.into_inner());
    if !g.iter().any(|m| m == msg) {
        g.push(msg.to_string());
        eprintln!("{}", msg);
    }
}

/// Resuelve el proyecto de un archivo de entrada (§3): sube desde su carpeta hasta el primer
/// `synsema.json` (la búsqueda no sigue después del primero), mira el dueño sobre el archivo ya
/// abierto y parsea esos mismos bytes.
pub fn resolve(entry: &str) -> Result<Project, String> {
    // B14 (ronda 1): lo que resolvió el chequeo previo de esta misma entrada no se busca de nuevo (§3:
    // una vez por programa; lo que corre ve lo mismo que se revisó).
    if let Some(p) = preflighted(entry) {
        return Ok((*p).clone());
    }
    resolve_fresh(entry)
}

/// Los proyectos que resolvió [`preflight`] en este proceso, por entrada (el último gana).
static PREFLIGHTED: std::sync::Mutex<Vec<(String, Arc<Project>)>> = std::sync::Mutex::new(Vec::new());

fn preflighted(entry: &str) -> Option<Arc<Project>> {
    let g = PREFLIGHTED.lock().unwrap_or_else(|e| e.into_inner());
    g.iter().find(|(e, _)| e == entry).map(|(_, p)| p.clone())
}

fn resolve_fresh(entry: &str) -> Result<Project, String> {
    // v0.6.58 (§9, D-13): con un bundle montado, el proyecto sale sólo del bundle. La raíz es la del
    // bundle (la del proyecto al construir) y nada se busca en el disco: un `synsema.json` roto en
    // una carpeta de arriba no cambia lo que corre (B5).
    if let Some(b) = crate::bundle::mounted() {
        let manifest = match b.get("synsema.json") {
            Some(bytes) => Some(parse_manifest_built(bytes, "synsema.json (in this binary)")?),
            None => None,
        };
        return Ok(Project { root: Some(PathBuf::from(".")), manifest, warnings: Vec::new() });
    }
    // §12: lo mismo con el proyecto que pasó el host de wasm-web o el guest (`call_json`).
    if let Some(bytes) = crate::modtable::host_manifest() {
        let manifest = parse_manifest(&bytes, "synsema.json (from the host)")?;
        return Ok(Project { root: Some(PathBuf::from(".")), manifest: Some(manifest), warnings: Vec::new() });
    }
    let Some(dir) = entry_dir(entry) else {
        return Ok(Project::default());
    };
    // Una sola ruta que sube: se le pone `synsema.json`, se prueba, se saca y se sube un nivel (corre
    // en cada arranque: sin una ruta nueva por carpeta).
    let mut probe = absolute(&dir);
    let mut up = 0usize;
    let found = loop {
        probe.push("synsema.json");
        if probe.is_file() {
            break true;
        }
        probe.pop();
        if !probe.pop() {
            break false;
        }
        up += 1;
    };
    if !found {
        return Ok(Project { root: Some(dir), manifest: None, warnings: Vec::new() });
    }
    let path = probe;
    let pdir = path.parent().expect("tiene synsema.json adentro").to_path_buf();
    let mut warnings = Vec::new();
    let shown = pdir.display().to_string();
    let ignore = |why: String, warnings: &mut Vec<String>| {
        let msg = format!("ignoring synsema.json in {}: {}", shown, why);
        warn_once(&msg);
        warnings.push(msg);
    };
    // Como Go: un `synsema.json` justo en la raíz del temporal del sistema no es de nadie. En wasm
    // no hay temporal del sistema (en wasip1 `temp_dir()` hace panic) ni chequeo de dueño: las
    // carpetas las elige el que arma el host con `--dir` (§12, E-8).
    if !cfg!(target_family = "wasm") && same_dir(&pdir, &std::env::temp_dir()) {
        ignore("it is in the system temp directory".to_string(), &mut warnings);
        return Ok(Project { root: Some(dir), manifest: None, warnings });
    }
    // B11 (ronda 1): uno que no se puede abrir (de otro usuario, sin permiso de lectura) se ignora
    // con aviso, como uno de otro dueño (P9): no corta a todo lo que está debajo.
    let mut file = match open_nonblocking(&path) {
        Ok(f) => f,
        Err(e) => {
            ignore(format!("it cannot be opened ({})", e), &mut warnings);
            return Ok(Project { root: Some(dir), manifest: None, warnings });
        }
    };
    // N5 (ronda 1): lo abierto tiene que ser un archivo común (se mira sobre el handle, no sobre la
    // ruta): un FIFO o un dispositivo que aparece en la carrera se ignora con aviso, no cuelga.
    if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
        ignore("it is not a regular file".to_string(), &mut warnings);
        return Ok(Project { root: Some(dir), manifest: None, warnings });
    }
    if !safe_listed(&pdir) {
        let verdict = match OWNER_CHECK.get() {
            Some(check) => check(&file),
            None if cfg!(target_family = "wasm") => Ok(true),
            None => Err("this host has no owner check".to_string()),
        };
        match verdict {
            Ok(true) => {}
            Ok(false) => {
                ignore(
                    format!("it belongs to another user (set SYNSEMA_SAFE_PROJECT={} if it is yours)", shown),
                    &mut warnings,
                );
                return Ok(Project { root: Some(dir), manifest: None, warnings });
            }
            Err(e) => {
                ignore(
                    format!("its owner could not be checked ({}; set SYNSEMA_SAFE_PROJECT={} if it is yours)", e, shown),
                    &mut warnings,
                );
                return Ok(Project { root: Some(dir), manifest: None, warnings });
            }
        }
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| format!("{}: cannot read synsema.json: {}", shown, e))?;
    let manifest = parse_manifest(&bytes, "synsema.json")?;
    // La raíz conserva la forma en que se escribió la entrada cuando es su misma carpeta (las rutas
    // resueltas de los `use` siguen siendo las de siempre); si el archivo está más arriba, la carpeta
    // absoluta donde se encontró.
    let root = if up == 0 { dir } else { pdir };
    Ok(Project { root: Some(root), manifest: Some(manifest), warnings })
}

/// El chequeo previo de los comandos (P3: antes de parsear la entrada): resuelve el proyecto y
/// revisa su mínimo. B14 (ronda 1): el resultado queda para la corrida de esta entrada, que no lo
/// vuelve a buscar. Sólo para los comandos de una corrida (`run`, `serve`, `test`, `check`,
/// `openapi`); un proceso que vive (el MCP de `code`) usa [`check`].
pub fn preflight(entry: &str) -> Result<Arc<Project>, String> {
    let p = Arc::new(resolve_fresh(entry)?);
    let mut g = PREFLIGHTED.lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|(e, _)| e != entry);
    g.push((entry.to_string(), p.clone()));
    Ok(p)
}

/// El mismo chequeo sin guardar nada: cada llamada mira el disco de nuevo.
pub fn check(entry: &str) -> Result<(), String> {
    resolve_fresh(entry).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N5 (ronda 1): un FIFO no cuelga el `open` y no pasa como archivo común.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_does_not_hang_and_is_not_a_file() {
        let dir = std::env::temp_dir().join(format!("syn-n5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("synsema.json");
        let _ = std::fs::remove_file(&p);
        assert!(std::process::Command::new("mkfifo").arg(&p).status().unwrap().success());
        let f = open_nonblocking(&p).expect("abre sin colgarse");
        assert!(!f.metadata().unwrap().is_file());
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn three_numbers_only() {
        assert_eq!(parse_three("0.6.58"), Some((0, 6, 58)));
        for bad in ["v0.6.58", ">=0.6.58", "0.6", "0.6.58.1", "0.06.1", "", "a.b.c", "0.6.-1", " 0.6.58"] {
            assert_eq!(parse_three(bad), None, "{}", bad);
        }
    }

    #[test]
    fn the_minimum_is_checked_before_the_keys() {
        let e = parse_manifest(br#"{"synsema": "99.0.0", "module": {}}"#, "synsema.json").unwrap_err();
        assert!(e.starts_with("this project needs synsema >= 99.0.0; this is "), "{}", e);
        assert!(e.ends_with(": synsema update"), "{}", e);
        let e = parse_manifest(br#"{"module": {}}"#, "synsema.json").unwrap_err();
        assert_eq!(
            e,
            "synsema.json: unknown key \"module\" (known: \"synsema\", \"modules\", \"indirect\"; a package also has \"id\", \"version\", \"main\", \"files\")"
        );
        let e = parse_manifest(br#"{"synsema": "v0.6.58"}"#, "synsema.json").unwrap_err();
        // El ejemplo del mensaje es la versión de este motor: sube con `DEV_VERSION`.
        assert_eq!(e, format!("synsema.json: \"synsema\" is a minimum version like \"{}\" (three numbers), not \"v0.6.58\"", DEV_VERSION));
        let e = parse_manifest(b"{\n  \"modules\": {,}\n}", "synsema.json").unwrap_err();
        assert!(e.starts_with("synsema.json:2:"), "{}", e);
    }

    #[test]
    fn engine_version_is_not_behind_the_changelog() {
        let changelog = include_str!("../../../../CHANGELOG.md");
        let top = changelog
            .lines()
            .find_map(|l| l.strip_prefix("## v").map(|r| r.split_whitespace().next().unwrap_or("").to_string()))
            .expect("CHANGELOG has a ## vX.Y.Z heading");
        let top = parse_three(&top).expect("the top CHANGELOG heading is vX.Y.Z");
        assert!(parse_three(DEV_VERSION).unwrap() >= top, "DEV_VERSION {} is behind the CHANGELOG ({:?})", DEV_VERSION, top);
    }
}
