//! v0.6.58 (§4.3, §5 de `specs/v0.6.58-diseno.md`): la tabla del proceso.
//!
//! Antes de ejecutar, el host recorre el árbol estático de `use` del programa (el mismo de
//! `program_sha`), resuelve cada nombre contra `synsema.json` y la selección escrita (§11), lee **una
//! vez** cada archivo de cada paquete alcanzado y de cada módulo de archivo, verifica cada hash y
//! deja todo acá. Después nadie vuelve a abrir el caché: el cargador, `attest`, los workers, los
//! agentes y el recibo leen de la tabla.
//!
//! Lo que falta, lo que no coincide o lo que está mal escrito es un error **antes de la primera
//! sentencia** (D-2): ningún error de un nombre depende del flujo del programa. Un módulo de archivo
//! que no resuelve queda como antes (P1b): no entra a la tabla y su `use` falla si corre.
//!
//! Todo es frío: corre una vez por corrida.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

use crate::project::{self, Manifest, ModEntry, Project};

/// Topes de un paquete (§4.3): constantes con error propio, sin knob.
pub const MAX_FILES: usize = 256;
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 128;
pub const MAX_PACKAGES: usize = 1024;
pub const MAX_DEP_DEPTH: usize = 64;

/// La clave de un módulo (§5.3): un tipo propio, que no comparte espacio con las rutas.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ModKey {
    /// Un módulo de archivo, por su ruta resuelta (la de siempre).
    File(String),
    /// Un archivo de un paquete: el hash de su árbol y su ruta adentro.
    Pkg { hash: String, path: String },
    /// Un módulo de confianza (`use "trusted:nombre"`), del host.
    Trusted(String),
}

impl ModKey {
    /// Cómo se muestra (errores, `code sha`). Sólo se muestra: nunca se resuelve desde este texto.
    pub fn display(&self) -> String {
        match self {
            ModKey::File(p) => p.clone(),
            ModKey::Pkg { hash, path } => format!("pkg:{}/{}", hash.replacen(':', "-", 1), path),
            ModKey::Trusted(n) => format!("trusted:{}", n),
        }
    }
}

/// `tree-sha256:<64 hex>`.
pub fn is_tree_hash(h: &str) -> bool {
    h.strip_prefix("tree-sha256:").is_some_and(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// El hash del árbol (§4.3), como el `h1:` de Go: por cada archivo (también el `synsema.json` del
/// paquete) una línea `<sha256 hex>  <ruta>\n`; las líneas ordenadas por bytes y el sha256 de la
/// concatenación. Sin normalizar fines de línea ni contar permisos.
pub fn tree_hash<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<String> = files.into_iter().map(|(path, sha)| format!("{}  {}\n", sha, path)).collect();
    lines.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut h = Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
    }
    format!("tree-sha256:{}", hex(&h.finalize()))
}

const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

fn reserved_windows_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return true;
    }
    let b = stem.as_bytes();
    b.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && b[3].is_ascii_digit()
}

/// Una ruta de un paquete (§4.3): relativa, con `/`, cada segmento `^[A-Za-z0-9_][A-Za-z0-9._-]*$`, sin
/// `..`, sin segmentos vacíos ni punto final, sin nombres reservados de Windows, hasta 128 bytes.
pub fn check_pkg_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(format!("the path '{}' is empty or longer than {} bytes", path, MAX_PATH_BYTES));
    }
    for seg in path.split('/') {
        let b = seg.as_bytes();
        let ok_first = b.first().is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
        let ok_rest = b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
        if !ok_first || !ok_rest || seg.ends_with('.') || seg == ".." {
            return Err(format!(
                "the path '{}' is not a package path (relative, '/' between segments of letters, digits, '.', '_' and '-')",
                path
            ));
        }
        if reserved_windows_name(seg) {
            return Err(format!("the path '{}' uses a name Windows reserves ('{}')", path, seg));
        }
    }
    Ok(())
}

/// Las rutas de un índice juntas (§4.3, D-19, D-20): ninguna es `synsema.json`, ninguna repetida sin
/// importar mayúsculas y ninguna es prefijo de carpeta de otra.
pub fn check_pkg_paths(paths: &[&str]) -> Result<(), String> {
    if paths.len() > MAX_FILES {
        return Err(format!("the package has {} files; the limit is {}", paths.len(), MAX_FILES));
    }
    let mut lower: Vec<String> = Vec::with_capacity(paths.len());
    for p in paths {
        check_pkg_path(p)?;
        let l = p.to_ascii_lowercase();
        if l == "synsema.json" {
            return Err("\"files\" cannot name synsema.json (the index is hashed on its own)".to_string());
        }
        lower.push(l);
    }
    let mut sorted = lower.clone();
    sorted.sort();
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            return Err(format!("two paths differ only in case or repeat: '{}'", w[0]));
        }
    }
    for a in &lower {
        for b in &lower {
            if b.len() > a.len() && b.starts_with(a.as_str()) && b.as_bytes()[a.len()] == b'/' {
                return Err(format!("the path '{}' is a folder of '{}'", a, b));
            }
        }
    }
    Ok(())
}

/// El home del usuario (§5.1): en Windows `USERPROFILE` y después `HOME`; en el resto `HOME`. Un
/// valor vacío o relativo cuenta como ausente.
pub fn home_dir() -> Option<PathBuf> {
    let pick = |k: &str| -> Option<PathBuf> {
        let v = std::env::var_os(k)?;
        let p = PathBuf::from(v);
        (!p.as_os_str().is_empty() && p.is_absolute()).then_some(p)
    };
    if cfg!(windows) {
        pick("USERPROFILE").or_else(|| pick("HOME"))
    } else {
        pick("HOME")
    }
}

/// N2 (ronda 1, N13): la ruta del knob con los separadores del sistema.
fn knob_path(v: &std::ffi::OsStr) -> PathBuf {
    Path::new(v).components().collect()
}

/// La carpeta del caché (§5.1): `SYNSEMA_MODULE_CACHE` (relativo a la raíz del proyecto) o
/// `<home>/.synsema/modules`. En wasm, sólo el knob (§12, W10).
pub fn cache_dir(root: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(v) = std::env::var_os("SYNSEMA_MODULE_CACHE").filter(|v| !v.is_empty()) {
        // N2 (ronda 1, N13): con los separadores del sistema (en Windows, una barra `/` del knob pasa a
        // ser la del sistema): la carpeta que nombran los errores se puede copiar tal cual.
        let p = knob_path(&v);
        if p.is_absolute() {
            return Ok(p);
        }
        return match root {
            Some(r) => Ok(r.join(p)),
            None => Err(format!(
                "SYNSEMA_MODULE_CACHE={} is relative and this program has no project to be relative to: give an absolute path",
                p.display()
            )),
        };
    }
    if cfg!(target_family = "wasm") {
        return Err("this host has no module cache: pass SYNSEMA_MODULE_CACHE (and the folder with --dir)".to_string());
    }
    match home_dir() {
        Some(h) => Ok(h.join(".synsema").join("modules")),
        None => Err("there is no home folder for the module cache: set SYNSEMA_MODULE_CACHE".to_string()),
    }
}

/// La carpeta de un paquete en el caché: `<cache>/tree-sha256-<hex>/`.
pub fn package_dir(cache: &Path, hash: &str) -> PathBuf {
    cache.join(hash.replacen(':', "-", 1))
}

/// Un paquete leído y verificado.
#[derive(Debug)]
pub struct Package {
    /// La marca de su código (§6.1): su índice en la tabla, desde 1 (0 es el programa).
    pub mark: u32,
    /// Cómo lo nombra el proyecto (el nombre directo) o, si es transitivo, su `id`.
    pub name: String,
    pub id: String,
    pub version: String,
    pub hash: String,
    pub index: Manifest,
    /// Los bytes del `synsema.json` del paquete (entran al hash).
    pub index_bytes: Arc<[u8]>,
    /// Los archivos del índice, con sus bytes ya verificados.
    pub files: HashMap<String, Arc<[u8]>>,
}

/// La tabla del proceso (§5.2).
#[derive(Debug, Default)]
pub struct ModTable {
    /// Los módulos de archivo alcanzados, por ruta resuelta.
    pub files: HashMap<String, Arc<str>>,
    /// Los paquetes, en el orden en que el recorrido los alcanzó (`mark - 1`).
    pub packages: Vec<Arc<Package>>,
    /// El dominio de cada paquete (§6.1), por marca (`mark - 1`, como `packages`): la unión de los
    /// `require` de los `.syn` que `main` alcanza por `use`, a cualquier profundidad, leída del AST
    /// de los bytes de la tabla. Un `Vec` y no un mapa: se lee en cada cruce.
    pub domains: Vec<Vec<(String, Option<String>)>>,
    /// El AST de cada módulo que el recorrido parseó (por el nombre con que lo carga el cargador:
    /// la ruta resuelta o la clave mostrada de un paquete), con los bytes que parseó. El cargador lo
    /// usa si los bytes son los mismos, en vez de parsear otra vez.
    /// N7 (ronda 1): los bytes son los mismos de `files` o de `Package::files` (el mismo `Arc`), no
    /// una copia.
    pub parsed: HashMap<String, (Arc<[u8]>, Arc<crate::ast::Program>)>,
    /// B15 (ronda 1): los módulos de archivo que el recorrido vio y no estaban (ruta resuelta). Un
    /// `use` de uno de estos falla como al arrancar: un archivo que aparece después no se lee del
    /// disco (lo que corre es lo que se leyó antes, R10), en ningún worker. Ronda 2 (N-r2-6): con el
    /// porqué que dice el error (no estaba, o estaba y no se pudo leer como texto).
    pub missing: HashMap<String, String>,
    /// B18 (ronda 1): los nombres con que el programa (o un módulo de archivo suyo) hace `use`, con
    /// la marca del paquete: el `direct` del recibo.
    pub direct: std::collections::BTreeMap<String, u32>,
}

/// Los `require` de un programa, a cualquier profundidad, como `(capability, scope)`. Un paquete
/// los escribe con literales (G20, lo revisa `check_package_syn`), así que se leen sin correr nada.
pub fn require_pairs(program: &crate::ast::Program) -> Vec<(String, Option<String>)> {
    require_pairs_in(&program.statements)
}

/// Los `require` de unos nodos (los de una task, para imprimir lo que pide cada una).
pub fn require_pairs_in(nodes: &[crate::ast::Node]) -> Vec<(String, Option<String>)> {
    use crate::ast::NodeKind;
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for stmt in nodes {
        crate::ast_api::walk(stmt, &mut |n| {
            if let NodeKind::RequireStatement { capability, scope, bound_to } = &n.kind {
                let (cap, mut sc) = crate::route_meta::require_pair(capability, scope);
                if let (Some(hosts), Some(name)) = (bound_to, sc.as_deref()) {
                    let hs: Vec<String> = hosts
                        .iter()
                        .filter_map(|h| match &h.kind {
                            NodeKind::TextLiteral { value } => Some(crate::capscope::net_host_scope(value)),
                            _ => None,
                        })
                        .collect();
                    sc = Some(format!("{}@{}", name, hs.join("|")));
                }
                if !out.iter().any(|(c, s)| *c == cap && *s == sc) {
                    out.push((cap, sc));
                }
            }
        });
    }
    out
}

impl ModTable {
    pub fn package(&self, mark: u32) -> Option<&Arc<Package>> {
        (mark as usize).checked_sub(1).and_then(|i| self.packages.get(i))
    }

    /// El dominio del paquete de `mark` (vacío si no tiene `require`).
    pub fn domain(&self, mark: u32) -> &[(String, Option<String>)] {
        (mark as usize).checked_sub(1).and_then(|i| self.domains.get(i)).map(Vec::as_slice).unwrap_or(&[])
    }

    /// El AST que el recorrido parseó para `name`, si lo parseó de estos mismos bytes.
    pub fn parsed_for(&self, name: &str, source: &str) -> Option<Arc<crate::ast::Program>> {
        self.parsed.get(name).filter(|(src, _)| src.as_ref() == source.as_bytes()).map(|(_, p)| p.clone())
    }

    fn by_hash(&self, hash: &str) -> Option<&Arc<Package>> {
        self.packages.iter().find(|p| p.hash == hash)
    }

    /// El fuente de un módulo de la tabla.
    pub fn source(&self, key: &ModKey) -> Option<Arc<str>> {
        match key {
            ModKey::File(p) => self.files.get(p).cloned(),
            ModKey::Pkg { hash, path } => {
                let bytes = self.by_hash(hash)?.files.get(path)?;
                std::str::from_utf8(bytes).ok().map(Arc::from)
            }
            ModKey::Trusted(_) => None,
        }
    }
}

/// Lo que guarda la corrida: la tabla, armada la primera vez que alguien la pide.
#[derive(Default)]
pub struct TableSlot(OnceLock<Result<Arc<ModTable>, String>>);

impl TableSlot {
    pub fn get_or_build(&self, f: impl FnOnce() -> Result<ModTable, String>) -> Result<Arc<ModTable>, String> {
        self.0.get_or_init(|| f().map(Arc::new)).clone()
    }

    pub fn get(&self) -> Option<Arc<ModTable>> {
        self.0.get().and_then(|r| r.as_ref().ok().cloned())
    }

    pub fn install(&self, t: Result<Arc<ModTable>, String>) {
        let _ = self.0.set(t);
    }
}

/// Qué es el texto de un `use` (§4.1).
#[derive(Debug, PartialEq)]
pub enum UseKind<'a> {
    Trusted(&'a str),
    File,
    Name,
}

/// Clasifica el texto de un `use`: un nombre, una ruta a un `.syn` o `trusted:`. Lo demás es un
/// error que explica qué hacer (N6, N7).
pub fn classify(raw: &str) -> Result<UseKind<'_>, String> {
    if let Some(n) = raw.strip_prefix("trusted:") {
        return Ok(UseKind::Trusted(n));
    }
    // Una URL va antes que la ruta: `https://x.com/t.syn` termina en `.syn` y no es un archivo.
    if raw.contains("://") {
        let stem = raw.rsplit('/').next().unwrap_or("").split('.').next().unwrap_or("").to_ascii_lowercase();
        let name = if project::is_module_name(&stem) { stem } else { "m".to_string() };
        return Err(format!(
            "use \"{}\": a module from a URL goes in synsema.json, not in the code: add {{\"modules\": {{\"{}\": {{\"url\": \"{}\"}}}}}}, run synsema get, then use \"{}\" as {}",
            raw, name, raw, name, name
        ));
    }
    // Una ruta (también una que no termina en `.syn`, que da el error de siempre al resolverla).
    if raw.ends_with(".syn") || raw.starts_with("./") || raw.starts_with("../") {
        return Ok(UseKind::File);
    }
    if project::is_module_name(raw) {
        return Ok(UseKind::Name);
    }
    Err(format!(
        "use \"{}\": not a module name (lowercase letters, digits, '-' and '_') nor a path to a .syn file",
        raw
    ))
}

/// Dónde está parado un `use`: el programa (con la carpeta del importador) o un paquete (con la ruta
/// del importador adentro del paquete).
#[derive(Clone, Debug)]
pub enum Importer {
    Program(String),
    Package { mark: u32, path: String },
}

/// §13: lo que el recibo dice de los paquetes de una corrida. Sale de la tabla, así que entran
/// sólo los que alcanza el recorrido (R2), también por una rama privada (R3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunModules {
    /// Cada nombre del proyecto que se alcanzó → el `id` al que apunta (R12).
    pub direct: std::collections::BTreeMap<String, String>,
    /// `id` → `(version, hash)`.
    pub packages: std::collections::BTreeMap<String, (String, String)>,
}

impl RunModules {
    /// `{"direct": {…}, "packages": {id: {"version", "hash"}}}`, con las claves en orden: es lo que
    /// pliega `config_sha`, así que tiene que salir igual siempre.
    pub fn to_json(&self) -> serde_json::Value {
        let mut direct = serde_json::Map::new();
        for (n, id) in &self.direct {
            direct.insert(n.clone(), serde_json::Value::String(id.clone()));
        }
        let mut packages = serde_json::Map::new();
        for (id, (v, h)) in &self.packages {
            let mut o = serde_json::Map::new();
            o.insert("hash".to_string(), serde_json::Value::String(h.clone()));
            o.insert("version".to_string(), serde_json::Value::String(v.clone()));
            packages.insert(id.clone(), serde_json::Value::Object(o));
        }
        let mut o = serde_json::Map::new();
        o.insert("direct".to_string(), serde_json::Value::Object(direct));
        o.insert("packages".to_string(), serde_json::Value::Object(packages));
        serde_json::Value::Object(o)
    }
}

impl ModTable {
    /// Los paquetes de la tabla para el recibo, o `None` si no hay ninguno (§13: no va).
    pub fn run_modules(&self) -> Option<RunModules> {
        if self.packages.is_empty() {
            return None;
        }
        let mut m = RunModules { direct: Default::default(), packages: Default::default() };
        for p in &self.packages {
            m.packages.insert(p.id.clone(), (p.version.clone(), p.hash.clone()));
        }
        // B18 (ronda 1): los nombres que usa el programa, cada uno con el `id` del paquete al que apunta.
        for (name, mark) in &self.direct {
            if let Some(p) = self.package(*mark) {
                m.direct.insert(name.clone(), p.id.clone());
            }
        }
        Some(m)
    }
}

/// Los paquetes que alcanzaría el programa `source` (en `filename`): la misma tabla que arma la
/// corrida, para lo que se calcula antes o fuera de ella (`--replay`, la atestación, el sellado).
/// v0.6.58 (A2 de la ronda 1): la tabla que armó la corrida de cada programa (por su archivo de
/// entrada), la primera vez. El recibo sellado y `run --attest` nombran lo que corrió, de acá: nunca
/// vuelven a leer `synsema.json` ni el caché al final (§1, §13).
static RUN_TABLES: std::sync::Mutex<Vec<(String, Arc<ModTable>)>> = std::sync::Mutex::new(Vec::new());

/// Anota la tabla de la corrida de `entry` (la primera gana: es la que leyó el proceso).
pub fn note_run_table(entry: &str, t: &Arc<ModTable>) {
    let mut v = RUN_TABLES.lock().unwrap_or_else(|p| p.into_inner());
    if !v.iter().any(|(e, _)| e == entry) {
        v.push((entry.to_string(), t.clone()));
    }
}

/// Ronda 2 (M-r2-1): las entradas cuya corrida falló al armar su proyecto o su tabla, antes de la
/// primera sentencia. No corrió nada: el recibo sellado sale sin `modules` (como un programa sin
/// paquetes), en vez de negarse.
static RUN_TABLES_FAILED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn note_run_table_failed(entry: &str) {
    let mut v = RUN_TABLES_FAILED.lock().unwrap_or_else(|p| p.into_inner());
    if !v.iter().any(|e| e == entry) {
        v.push(entry.to_string());
    }
}

/// ¿La corrida de `entry` falló al armar su tabla (y no la armó)?
pub fn run_table_failed(entry: &str) -> bool {
    RUN_TABLES_FAILED.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|e| e == entry)
}

/// La tabla que armó la corrida de `entry`, si la armó.
pub fn run_table_of(entry: &str) -> Option<Arc<ModTable>> {
    RUN_TABLES.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|(e, _)| e == entry).map(|(_, t)| t.clone())
}

/// La tabla de `source` (en `filename`) para un host que la necesita antes de correr (la identidad de
/// `serve --attested`): la misma que después instala en la corrida. `None` sin `use`.
pub fn table_for(source: &str, filename: &str) -> Result<Option<ModTable>, String> {
    let program = crate::parser::parse_source(source, filename).map_err(|e| e.to_string())?;
    let uses = crate::loaded_modules::use_paths(&program);
    if uses.is_empty() {
        return Ok(None);
    }
    let project = project::resolve(filename)?;
    build(&project, filename, uses).map(Some)
}

pub fn run_modules_of(source: &str, filename: &str) -> Result<Option<RunModules>, String> {
    let program = crate::parser::parse_source(source, filename).map_err(|e| e.to_string())?;
    let uses = crate::loaded_modules::use_paths(&program);
    if uses.is_empty() {
        return Ok(None);
    }
    let project = project::resolve(filename)?;
    Ok(build(&project, filename, uses)?.run_modules())
}

/// Arma la tabla (§5.2) para el programa `entry` cuyos `use` son `uses`.
pub fn build(project: &Project, entry: &str, uses: Vec<String>) -> Result<ModTable, String> {
    let mut b = Builder { project, table: ModTable::default(), cache: None, stack: Vec::new(), seen: Default::default() };
    b.walk(&Importer::Program(entry.to_string()), uses, 0)?;
    Ok(b.table)
}

struct Builder<'a> {
    project: &'a Project,
    table: ModTable,
    cache: Option<Result<PathBuf, String>>,
    /// Los `id` de los paquetes que se están recorriendo (un ciclo de módulos de un paquete se
    /// reporta al cargar, como siempre).
    stack: Vec<String>,
    /// Los `.syn` de paquetes ya recorridos.
    seen: std::collections::HashSet<ModKey>,
}

impl Builder<'_> {
    fn cache(&mut self) -> Result<PathBuf, String> {
        let root = self.project.root.clone();
        self.cache.get_or_insert_with(|| cache_dir(root.as_deref())).clone()
    }

    fn walk(&mut self, importer: &Importer, uses: Vec<String>, depth: usize) -> Result<(), String> {
        for raw in uses {
            match classify(&raw)? {
                UseKind::Trusted(_) => {}
                UseKind::File => self.file(importer, &raw, depth)?,
                UseKind::Name => {
                    let mark = self.name(importer, &raw, depth)?;
                    // B18 (ronda 1): `direct` del recibo lleva los nombres que usa el programa (§13), no
                    // los que el proyecto declara y el programa alcanza sólo por un paquete.
                    if matches!(importer, Importer::Program(_)) {
                        self.table.direct.insert(raw.clone(), mark);
                    }
                    let pkg = self.table.package(mark).expect("paquete recién agregado").clone();
                    let main = pkg.index.main.clone().unwrap_or_default();
                    if self.stack.contains(&pkg.id) {
                        continue;
                    }
                    if !self.seen.contains(&ModKey::Pkg { hash: pkg.hash.clone(), path: main.clone() }) {
                        self.package_module(&pkg, &main, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Un módulo de archivo del programa: a la tabla si resuelve; si no, queda como antes (P1b).
    fn file(&mut self, importer: &Importer, raw: &str, depth: usize) -> Result<(), String> {
        match importer {
            Importer::Program(file) => {
                let base = Path::new(file).parent().map(Path::to_path_buf).unwrap_or_default();
                let Ok(resolved) = crate::templates::resolve_module_path(raw, &base, self.project.root.as_deref()) else {
                    // B15 (ronda 1): un archivo que no está al arrancar queda anotado: si aparece
                    // después no se lee (el cargador da «did not exist when the program started»).
                    if let Ok(r) = crate::templates::module_path_lexical(raw, &base, self.project.root.as_deref()) {
                        self.table.missing.insert(r, "it did not exist when the program started".to_string());
                    }
                    return Ok(());
                };
                if self.table.files.contains_key(&resolved) {
                    return Ok(());
                }
                let src = match crate::bundle::get(&resolved) {
                    Some(b) => String::from_utf8(b.to_vec()).map_err(|_| "it is not UTF-8 text".to_string()),
                    None => std::fs::read_to_string(&resolved).map_err(|e| e.to_string()),
                };
                let src = match src {
                    Ok(s) => s,
                    Err(why) => {
                        // N-r2-6: estaba pero no se pudo leer: el error dice eso, no «no existía».
                        self.table.missing.insert(resolved, format!("it could not be read when the program started: {}", why));
                        return Ok(());
                    }
                };
                let src: Arc<str> = Arc::from(src);
                self.table.files.insert(resolved.clone(), src.clone());
                // Un módulo que no parsea falla igual cuando corre (con el error del cargador).
                if let Ok(program) = crate::parser::parse_source(&src, &resolved) {
                    let sub = crate::loaded_modules::use_paths(&program);
                    self.table.parsed.insert(resolved.clone(), (Arc::<[u8]>::from(src), Arc::new(program)));
                    self.walk(&Importer::Program(resolved), sub, depth)?;
                }
                Ok(())
            }
            Importer::Package { mark, path } => {
                let pkg = self.table.package(*mark).expect("paquete de la tabla").clone();
                // N2 (ronda 1): el texto de K2, sin prefijo: el mismo que da el cargador.
                let target = pkg_relative(path, raw)?;
                if !pkg.files.contains_key(&target) {
                    // K3: lo que no está en `files` no existe; falla al cargar con el texto de siempre.
                    return Ok(());
                }
                if self.seen.contains(&ModKey::Pkg { hash: pkg.hash.clone(), path: target.clone() }) {
                    return Ok(());
                }
                self.package_module(&pkg, &target, depth)
            }
        }
    }

    /// Recorre un `.syn` de un paquete (lo marca como visto con su clave mostrada).
    fn package_module(&mut self, pkg: &Arc<Package>, path: &str, depth: usize) -> Result<(), String> {
        let key = ModKey::Pkg { hash: pkg.hash.clone(), path: path.to_string() };
        let shown = key.display();
        let Some(bytes) = pkg.files.get(path) else { return Ok(()) };
        let Ok(src) = std::str::from_utf8(bytes) else {
            return Err(format!("{}: the file is not UTF-8", shown));
        };
        self.seen.insert(key);
        // Un `.syn` de un paquete que no parsea, o que tiene lo que un paquete no puede tener (§10.3,
        // paso 3), es un error antes de ejecutar: `get` no lo habría instalado (K5, K6, K37).
        let program = crate::parser::parse_source(src, &shown).map_err(|e| e.to_string())?;
        // N2 (ronda 1, K5): el módulo que se nombra es el paquete (su `main`); el lugar, el archivo.
        let main_shown = ModKey::Pkg { hash: pkg.hash.clone(), path: pkg.index.main.clone().unwrap_or_default() }.display();
        check_package_syn(&program, src, &pkg.name, &main_shown, path)?;
        let i = pkg.mark as usize - 1;
        if self.table.domains.len() <= i {
            self.table.domains.resize_with(i + 1, Vec::new);
        }
        let dom = &mut self.table.domains[i];
        for pair in require_pairs(&program) {
            if !dom.contains(&pair) {
                dom.push(pair);
            }
        }
        let sub = crate::loaded_modules::use_paths(&program);
        self.table.parsed.insert(shown.clone(), (bytes.clone(), Arc::new(program)));
        self.stack.push(pkg.id.clone());
        let r = self.walk(&Importer::Package { mark: pkg.mark, path: path.to_string() }, sub, depth);
        self.stack.pop();
        r
    }

    /// Un nombre: del proyecto (desde el programa) o de las dependencias del paquete (desde un
    /// paquete), y la versión elegida por el proyecto (§11.3). Devuelve la marca del paquete.
    fn name(&mut self, importer: &Importer, name: &str, depth: usize) -> Result<u32, String> {
        if depth >= MAX_DEP_DEPTH {
            return Err(format!("use \"{}\": the dependencies are more than {} levels deep", name, MAX_DEP_DEPTH));
        }
        let (shown_name, entry): (String, ModEntry) = match importer {
            Importer::Program(_) => {
                let Some(m) = self.project.manifest.as_ref() else {
                    return Err(match self.project.root.as_deref() {
                        None => format!(
                            "use \"{}\": a module by name is declared in synsema.json, and a program without a file has no synsema.json",
                            name
                        ),
                        Some(r) => format!(
                            "use \"{}\": a module by name is declared in synsema.json, and there is none in {} or above; add {{\"modules\": {{\"{}\": {{\"url\": \"…\"}}}}}} and run synsema get",
                            name,
                            shown_dir(r),
                            name
                        ),
                    });
                };
                let Some(e) = m.module(name) else {
                    return Err(format!(
                        "use \"{}\": synsema.json ({}) has no module \"{}\"; add it under \"modules\" and run synsema get",
                        name,
                        self.project.root.as_deref().map(shown_dir).unwrap_or_default(),
                        name
                    ));
                };
                (name.to_string(), e.clone())
            }
            Importer::Package { mark, .. } => {
                let pkg = self.table.package(*mark).expect("paquete de la tabla").clone();
                let Some(dep) = pkg.index.module(name) else {
                    return Err(format!("use \"{}\" in {}: the package does not declare \"{}\" in its synsema.json", name, pkg.name, name));
                };
                let id = dep.id.clone().unwrap_or_default();
                let chosen = self.chosen(&id);
                let Some(e) = chosen else {
                    return Err(format!("use \"{}\" in {}: the dependency {} is not in synsema.json: run synsema get", name, pkg.name, id));
                };
                (self.direct_name(&id).unwrap_or(id), e)
            }
        };
        let Some(hash) = entry.hash.clone().filter(|h| !h.is_empty()) else {
            return Err(format!("use \"{}\": module {} has no hash yet: run synsema get (it needs the network)", name, shown_name));
        };
        if !is_tree_hash(&hash) {
            return Err(format!("use \"{}\": the hash of {} is not tree-sha256:<64 hex>: run synsema get", name, shown_name));
        }
        if let Some(p) = self.table.by_hash(&hash) {
            return Ok(p.mark);
        }
        if self.table.packages.len() >= MAX_PACKAGES {
            return Err(format!("the program reaches more than {} packages", MAX_PACKAGES));
        }
        let ver = entry.version.clone().unwrap_or_default();
        let mark_new = self.table.packages.len() as u32 + 1;
        // Con un bundle montado, los paquetes salen sólo de su sección (D-13): ni el caché ni el home.
        // Con un proyecto del host (§12), sólo de lo que pasó el host.
        let pkg = if crate::bundle::mounted().is_some() {
            load_bundled_package(&hash, &shown_name, &ver, name, mark_new)?
        } else if host_call_active() {
            load_host_package(&hash, &shown_name, &ver, name, mark_new)?
        } else {
            let cache = self.cache().map_err(|e| format!("use \"{}\": {}", name, e))?;
            load_package(&package_dir(&cache, &hash), &hash, &shown_name, &ver, name, mark_new)?
        };
        let mark = pkg.mark;
        self.table.packages.push(Arc::new(pkg));
        Ok(mark)
    }

    /// La entrada elegida para un `id` (§11.3, paso 4): la directa con ese `id` o la de `indirect`.
    fn chosen(&self, id: &str) -> Option<ModEntry> {
        let m = self.project.manifest.as_ref()?;
        let want = normalize_id(id);
        m.modules
            .iter()
            .map(|(_, e)| e)
            .find(|e| e.id.as_deref().map(normalize_id).as_deref() == Some(want.as_str()))
            .or_else(|| m.indirect.iter().map(|(_, e)| e).find(|e| e.id.as_deref().map(normalize_id).as_deref() == Some(want.as_str())))
            .cloned()
    }

    fn direct_name(&self, id: &str) -> Option<String> {
        let m = self.project.manifest.as_ref()?;
        let want = normalize_id(id);
        m.modules
            .iter()
            .find(|(_, e)| e.id.as_deref().map(normalize_id).as_deref() == Some(want.as_str()))
            .map(|(n, _)| n.clone())
    }
}

fn shown_dir(p: &Path) -> String {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf())
    };
    crate::templates::lexical_normalize(&abs).display().to_string()
}

/// El `id` normalizado (§11.2): esquema y host en minúsculas, sin el puerto por defecto.
pub fn normalize_id(id: &str) -> String {
    let Some((scheme, rest)) = id.split_once("://") else { return id.to_string() };
    let scheme = scheme.to_ascii_lowercase();
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut host = host.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else if scheme == "http" { ":80" } else { "" };
    if !default_port.is_empty() && host.ends_with(default_port) {
        host.truncate(host.len() - default_port.len());
    }
    format!("{}://{}{}", scheme, host, path)
}

/// Una ruta relativa adentro de un paquete (K2): `../` no sale del paquete.
pub fn pkg_relative(importer_path: &str, raw: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = importer_path.split('/').collect();
    parts.pop();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!("module path escapes the package: '{}'", raw));
                }
            }
            s => parts.push(s),
        }
    }
    if raw.starts_with('/') || raw.contains('\\') || raw.contains(':') {
        return Err(format!("module path escapes the package: '{}'", raw));
    }
    Ok(parts.join("/"))
}

/// Lee un paquete del caché y lo verifica entero (§5.2): el índice, cada archivo contra su sha256 y el
/// árbol contra el hash escrito en el proyecto. Lee sólo lo que nombra el índice (K3).
pub fn load_package(dir: &Path, hash: &str, shown_name: &str, version: &str, used_as: &str, mark: u32) -> Result<Package, String> {
    load_package_with(&|p: &str| std::fs::read(dir.join(p)).ok(), Origin::Cache(dir), hash, shown_name, version, used_as, mark)
}

/// v0.6.58 (§9, D-13): un paquete de la sección del bundle montado, verificado igual que desde el
/// caché (el hash del árbol se recalcula sobre estos bytes).
pub fn load_bundled_package(hash: &str, shown_name: &str, version: &str, used_as: &str, mark: u32) -> Result<Package, String> {
    let files = crate::bundle::package(hash);
    let read = |p: &str| files.and_then(|fs| fs.iter().find(|(n, _)| n == p)).map(|(_, b)| b.clone());
    load_package_with(&read, Origin::Bundle, hash, shown_name, version, used_as, mark)
}

// ---------------------------------------------------------------------------------------------
// v0.6.58 (§12): el proyecto y los paquetes que pasa el host (wasm-web y el guest de Vela, por
// `call_json`). El host los pone al entrar a la llamada y los saca al salir; mientras están, el
// proyecto sale sólo de ahí y los paquetes sólo de ahí (como con un bundle, D-13). Lo verificado
// queda en la instancia por su hash: una llamada que trae (o nombra) un hash ya verificado no lo
// vuelve a hashear (W9). El hash es del contenido, así que guardarlo no cambia lo que corre otra
// llamada: el proyecto de cada una fija qué hashes usa.
// ---------------------------------------------------------------------------------------------

/// Los archivos de un paquete como los pasa el host: ruta adentro del paquete → bytes.
pub type HostFiles = Vec<(String, Vec<u8>)>;

struct HostCall {
    manifest: Vec<u8>,
    packages: HashMap<String, HostFiles>,
}

thread_local! {
    // Del hilo de la llamada (en wasm hay uno solo; en los tests nativos, cada uno el suyo). La tabla
    // se arma en ese hilo antes de la primera sentencia.
    static HOST_CALL: std::cell::RefCell<Option<HostCall>> = const { std::cell::RefCell::new(None) };
}
static HOST_VERIFIED: std::sync::Mutex<Option<Held>> = std::sync::Mutex::new(None);

/// N8 (ronda 1): lo verificado que guarda la instancia, con tope en bytes. Al terminar cada llamada
/// se descartan los menos usados hasta quedar bajo el tope (nunca en medio de una llamada: lo que
/// el host no mandó porque estaba guardado sigue ahí hasta el final). `packages_held` de la
/// respuesta dice lo que quedó, así que el host vuelve a mandar lo descartado. La instancia es el
/// límite de confianza: quien comparte una ve los hashes que verificó otro proyecto (el hash es del
/// contenido; nunca mezcla código). Un inquilino por instancia si eso importa.
pub const MAX_HOST_HELD_BYTES: u64 = 4 * MAX_PACKAGE_BYTES;

#[derive(Default)]
struct Held {
    pkgs: HashMap<String, (Arc<Package>, u64)>,
    clock: u64,
    bytes: u64,
}

fn package_bytes(p: &Package) -> u64 {
    p.index_bytes.len() as u64 + p.files.values().map(|b| b.len() as u64).sum::<u64>()
}

/// Descarta los menos usados hasta quedar bajo `cap`.
fn trim_held(h: &mut Held, cap: u64) {
    while h.bytes > cap {
        let Some(oldest) = h.pkgs.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone()) else { break };
        if let Some((p, _)) = h.pkgs.remove(&oldest) {
            h.bytes -= package_bytes(&p);
        }
    }
}

/// N8: el tope de esta instancia (los tests lo bajan).
static HELD_CAP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(MAX_HOST_HELD_BYTES);

/// Para los tests: el tope de bytes guardados (W9/N8).
pub fn set_host_held_cap(bytes: u64) {
    HELD_CAP.store(bytes, std::sync::atomic::Ordering::Relaxed);
}
static HOST_HASHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Pone (o saca, con `None`) el proyecto de esta llamada: el texto de `synsema.json` y los paquetes.
pub fn set_host_call(call: Option<(Vec<u8>, HashMap<String, HostFiles>)>) {
    let ending = call.is_none();
    HOST_CALL.with(|c| *c.borrow_mut() = call.map(|(manifest, packages)| HostCall { manifest, packages }));
    if ending {
        let mut g = HOST_VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = g.as_mut() {
            trim_held(h, HELD_CAP.load(std::sync::atomic::Ordering::Relaxed));
        }
    }
}

/// ¿Hay una llamada del host con proyecto?
pub fn host_call_active() -> bool {
    HOST_CALL.with(|c| c.borrow().is_some())
}

/// El `synsema.json` que pasó el host en esta llamada, si hay una llamada con proyecto.
pub fn host_manifest() -> Option<Vec<u8>> {
    HOST_CALL.with(|c| c.borrow().as_ref().map(|c| c.manifest.clone()))
}

/// Los hashes que esta instancia ya verificó, ordenados (el host no los vuelve a mandar, W9).
pub fn host_packages_held() -> Vec<String> {
    let g = HOST_VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let mut v: Vec<String> = g.as_ref().map(|h| h.pkgs.keys().cloned().collect()).unwrap_or_default();
    v.sort();
    v
}

/// Cuántos paquetes hasheó esta instancia desde que arrancó (W9: el test cuenta con esto).
pub fn host_packages_hashed() -> u64 {
    HOST_HASHED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Un paquete del host: el ya verificado por su hash, o el de esta llamada, verificado entero.
fn load_host_package(hash: &str, shown_name: &str, version: &str, used_as: &str, mark: u32) -> Result<Package, String> {
    let known = {
        let mut g = HOST_VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
        g.as_mut().and_then(|h| {
            h.clock += 1;
            let now = h.clock;
            h.pkgs.get_mut(hash).map(|(p, t)| {
                *t = now;
                p.clone()
            })
        })
    };
    if let Some(p) = known {
        return Ok(Package {
            mark,
            name: shown_name.to_string(),
            id: p.id.clone(),
            version: p.version.clone(),
            hash: p.hash.clone(),
            index: p.index.clone(),
            index_bytes: p.index_bytes.clone(),
            files: p.files.clone(),
        });
    }
    let files = HOST_CALL.with(|c| c.borrow().as_ref().and_then(|c| c.packages.get(hash).cloned()));
    let read = |p: &str| files.as_ref().and_then(|fs| fs.iter().find(|(n, _)| n == p)).map(|(_, b)| b.clone());
    let pkg = load_package_with(&read, Origin::Host, hash, shown_name, version, used_as, mark)?;
    HOST_HASHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut g = HOST_VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let h = g.get_or_insert_with(Held::default);
    h.clock += 1;
    let kept = Arc::new(Package {
        mark: 0,
        name: String::new(),
        id: pkg.id.clone(),
        version: pkg.version.clone(),
        hash: pkg.hash.clone(),
        index: pkg.index.clone(),
        index_bytes: pkg.index_bytes.clone(),
        files: pkg.files.clone(),
    });
    let size = package_bytes(&kept);
    if let Some((old, _)) = h.pkgs.insert(hash.to_string(), (kept, h.clock)) {
        h.bytes -= package_bytes(&old);
    }
    h.bytes += size;
    Ok(pkg)
}

/// De dónde salen los bytes de un paquete: cambia sólo los textos de error.
#[derive(Clone, Copy)]
enum Origin<'a> {
    /// La carpeta del paquete en el caché.
    Cache(&'a Path),
    /// La sección de paquetes del bundle de este binario.
    Bundle,
    /// Los `packages` que pasó el host en la llamada.
    Host,
}

/// Lee y verifica un paquete con `read` (ruta adentro del paquete → bytes).
fn load_package_with(
    read: &dyn Fn(&str) -> Option<Vec<u8>>,
    from: Origin,
    hash: &str,
    shown_name: &str,
    version: &str,
    used_as: &str,
    mark: u32,
) -> Result<Package, String> {
    let index_bytes = match read("synsema.json") {
        Some(b) => b,
        None => {
            let v = if version.is_empty() { String::new() } else { format!(" {}", version) };
            return Err(match from {
                Origin::Cache(_) => format!("use \"{}\": module {}{} is not downloaded: run synsema get (it needs the network)", used_as, shown_name, v),
                Origin::Bundle => format!("use \"{}\": module {}{} is not in this binary (build it again with the package in the cache)", used_as, shown_name, v),
                Origin::Host => format!("use \"{}\": module {}{} is not in the packages the host passed", used_as, shown_name, v),
            });
        }
    };
    let changed = || match from {
        Origin::Cache(dir) => format!(
            "use \"{}\": the cached files of {} ({}) no longer match their hash (changed on disk?); delete {} and run synsema get",
            used_as,
            shown_name,
            short_hash(hash),
            dir.display()
        ),
        Origin::Bundle | Origin::Host => format!("use \"{}\": the files of {} ({}) do not match their hash", used_as, shown_name, short_hash(hash)),
    };
    // El mínimo del paquete va antes que todo lo demás (N14): un motor viejo no entiende las claves
    // de un índice nuevo y no tiene que decir que el caché cambió. Cualquier otro error del índice
    // es un caché que no es el que se bajó.
    let index = match project::parse_manifest_of(&index_bytes, &format!("{} synsema.json", shown_name), Some((shown_name, version))) {
        Ok(i) => i,
        Err(e) if e.starts_with(&format!("module {} (", shown_name)) && e.contains(" needs synsema >= ") => return Err(e),
        Err(_) => return Err(changed()),
    };
    let (Some(id), Some(ver), Some(main), Some(files)) = (index.id.clone(), index.version.clone(), index.main.clone(), index.files.clone())
    else {
        return Err(changed());
    };
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    check_pkg_paths(&paths).map_err(|_| changed())?;
    let mut out = HashMap::with_capacity(files.len());
    let mut total: u64 = index_bytes.len() as u64;
    for f in &files {
        let bytes = read(&f.path).ok_or_else(changed)?;
        total += bytes.len() as u64;
        if bytes.len() as u64 > MAX_FILE_BYTES || total > MAX_PACKAGE_BYTES {
            return Err(changed());
        }
        if sha256_hex(&bytes) != f.sha256 {
            return Err(changed());
        }
        out.insert(f.path.clone(), Arc::from(bytes.into_boxed_slice()));
    }
    let index_sha = sha256_hex(&index_bytes);
    let tree = tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.sha256.as_str()))
            .chain(std::iter::once(("synsema.json", index_sha.as_str()))),
    );
    if tree != hash {
        return Err(changed());
    }
    if !out.contains_key(&main) {
        return Err(changed());
    }
    Ok(Package {
        mark,
        name: shown_name.to_string(),
        id,
        version: ver,
        hash: hash.to_string(),
        index,
        index_bytes: Arc::from(index_bytes.into_boxed_slice()),
        files: out,
    })
}

/// ¿Un argumento de `require` es literal? (§6.2, D-8): textos, números, booleanos, `nothing`, y
/// listas o mapas de literales.
fn is_literal(n: &crate::ast::Node) -> bool {
    use crate::ast::NodeKind as K;
    match &n.kind {
        K::TextLiteral { .. } | K::NumberLiteral { .. } | K::BoolLiteral { .. } | K::NothingLiteral => true,
        K::ListLiteral { elements } => elements.iter().all(is_literal),
        K::MapLiteral { pairs } => pairs.iter().all(|(k, v)| is_literal(k) && is_literal(v)),
        _ => false,
    }
}

/// El texto de una sentencia `require` en su línea, sin la palabra (`net(H)`), para los mensajes.
fn require_text(src: &str, n: &crate::ast::Node) -> String {
    let rest = src.get(n.location.offset..).unwrap_or("");
    let line = rest.lines().next().unwrap_or("").trim();
    line.strip_prefix("require").unwrap_or(line).trim().to_string()
}

/// Lo que un `.syn` de un paquete no puede tener (§10.3, paso 3; lo revisa `get` y también el
/// cargador, con el mismo texto): `serve` arriba de todo, un `require` fuera de una task a cualquier
/// profundidad (E-1) o adentro de un bloque `test` (F-9), un `require` con argumentos que no son
/// literales (D-8) y `use "trusted:…"` (F-3). `name` es el nombre del paquete; `path`, el archivo.
pub fn check_package_syn(program: &crate::ast::Program, src: &str, name: &str, shown: &str, path: &str) -> Result<(), String> {
    check_package_syn_as(program, src, name, shown, path, false)
}

/// Lo mismo que [`check_package_syn`], con los textos de `get` (G12, G36, G49): `get` habla de lo que
/// el autor del paquete tiene que cambiar; el cargador, de un caché que no es el que se bajó.
pub fn check_package_syn_get(program: &crate::ast::Program, src: &str, name: &str, path: &str) -> Result<(), String> {
    check_package_syn_as(program, src, name, path, path, true).map_err(|e| if e.starts_with("get: ") { e } else { format!("get: {}", e) })
}

fn check_package_syn_as(program: &crate::ast::Program, src: &str, name: &str, shown: &str, path: &str, get: bool) -> Result<(), String> {
    use crate::ast::{Node, NodeKind as K};
    for stmt in &program.statements {
        if matches!(stmt.kind, K::ServeBlock { .. }) {
            if get {
                return Err(format!(
                    "get: {}: {}:{} has a 'serve' block; a package does not serve, the program that uses it does",
                    name, path, stmt.location.line
                ));
            }
            return Err(format!("module '{}' must not contain a 'serve' block", shown));
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn go(n: &Node, task: Option<&str>, in_test: bool, src: &str, name: &str, shown: &str, path: &str, get: bool) -> Result<(), String> {
        match &n.kind {
            K::RequireStatement { scope, bound_to, .. } => {
                if in_test {
                    if get {
                        return Err(format!(
                            "get: {}: require {} in {}:{} is inside a test block; a package's tests do not declare capabilities",
                            name,
                            require_text(src, n),
                            path,
                            n.location.line
                        ));
                    }
                    return Err(format!(
                        "module '{}' has a 'require' inside a test block ({}:{}); a test runs with what the program grants",
                        shown, path, n.location.line
                    ));
                }
                let Some(t) = task else {
                    if get {
                        return Err(format!(
                            "get: {}: require {} in {}:{} is outside a task; a package declares its capabilities inside its tasks",
                            name,
                            require_text(src, n),
                            path,
                            n.location.line
                        ));
                    }
                    return Err(format!("module '{}' has a 'require' outside a task ({}:{})", shown, path, n.location.line));
                };
                let lit = scope.as_deref().map_or(true, is_literal) && bound_to.as_deref().map_or(true, |b| b.iter().all(is_literal));
                if !lit {
                    return Err(format!(
                        "{}: require {} in task {} is not a literal; a package declares its capabilities with literals so they can be reviewed",
                        name,
                        require_text(src, n),
                        t
                    ));
                }
                Ok(())
            }
            K::UseImport { path: raw, .. } if raw.starts_with("trusted:") => Err(format!(
                "{}: use \"{}\" in {}: a package cannot use the host's trusted tools; the program passes it a callback instead",
                name, raw, path
            )),
            K::TaskDefinition { name: tn, .. } => {
                for c in crate::ast_api::children(n) {
                    go(c, Some(tn), in_test, src, name, shown, path, get)?;
                }
                Ok(())
            }
            K::TestBlock { .. } => {
                for c in crate::ast_api::children(n) {
                    go(c, task, true, src, name, shown, path, get)?;
                }
                Ok(())
            }
            _ => {
                for c in crate::ast_api::children(n) {
                    go(c, task, in_test, src, name, shown, path, get)?;
                }
                Ok(())
            }
        }
    }
    for stmt in &program.statements {
        go(stmt, None, false, src, name, shown, path, get)?;
    }
    Ok(())
}

/// La ruta adentro de `pkg` de un archivo que se muestra como `pkg:tree-sha256-…/ruta` (la ubicación de
/// un `use` adentro de un paquete).
pub fn pkg_path_of(pkg: &Package, shown_file: &str) -> String {
    let prefix = ModKey::Pkg { hash: pkg.hash.clone(), path: String::new() }.display();
    shown_file.strip_prefix(prefix.as_str()).unwrap_or(shown_file).to_string()
}

/// v0.6.58 (N16; N6 de la ronda 1): para `code`, el paquete que un `use "nombre"` alcanza, resuelto,
/// leído y verificado como al correr (la carpeta en el caché y la ruta de su `main`). La raíz del
/// proyecto la da quien llama:
/// el proyecto es siempre el de `project_entry`. Un `use "nombre"` escrito en un archivo de un
/// paquete del caché sigue la dependencia del índice de ese paquete con la versión que eligió el
/// proyecto (§11.3: la directa con ese `id` o la de `indirect`), como al correr; nunca toma el índice
/// del paquete como si fuera el proyecto.
pub fn static_main_path_in(project_entry: &str, importer: &str, name: &str) -> Result<(PathBuf, String), String> {
    let project = project::resolve(project_entry)?;
    let cache = cache_dir(project.root.as_deref())?;
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let (cache_c, importer_c) = (canon(&cache), canon(Path::new(importer)));
    let Ok(rest) = importer_c.strip_prefix(&cache_c) else {
        let table = build(&project, importer, vec![name.to_string()])?;
        let pkg = table.packages.first().ok_or_else(|| format!("use \"{}\": no package", name))?;
        return Ok((package_dir(&cache, &pkg.hash), pkg.index.main.clone().unwrap_or_default()));
    };
    let pkg_dir = rest.components().next().map(|c| cache_c.join(c)).ok_or_else(|| format!("use \"{}\": not in a package", name))?;
    let index = std::fs::read(pkg_dir.join("synsema.json")).map_err(|e| format!("{}: {}", pkg_dir.display(), e))?;
    let index = project::parse_manifest(&index, "synsema.json (package)")?;
    let dep = index.module(name).ok_or_else(|| format!("use \"{}\": the package does not declare \"{}\" in its synsema.json", name, name))?;
    let id = normalize_id(dep.id.as_deref().unwrap_or_default());
    let m = project.manifest.as_ref().ok_or_else(|| format!("use \"{}\": no synsema.json in the project", name))?;
    let chosen = m
        .modules
        .iter()
        .map(|(_, e)| e)
        .chain(m.indirect.iter().map(|(_, e)| e))
        .find(|e| e.id.as_deref().map(normalize_id).as_deref() == Some(id.as_str()))
        .ok_or_else(|| format!("use \"{}\": the dependency {} is not in synsema.json: run synsema get", name, id))?;
    let hash = chosen.hash.clone().filter(|h| is_tree_hash(h)).ok_or_else(|| format!("use \"{}\": {} has no hash yet: run synsema get", name, id))?;
    let dir = package_dir(&cache, &hash);
    let pkg = load_package(&dir, &hash, &id, chosen.version.as_deref().unwrap_or_default(), name, 1)?;
    Ok((dir, pkg.index.main.clone().unwrap_or_default()))
}

/// v0.6.58 (N16): para `openapi`, el `main` del paquete que el programa `entry` usa con `use "nombre"`,
/// resuelto, leído y verificado como al correr, con su fuente (y cómo se muestra).
pub fn static_main(entry: &str, name: &str) -> Result<(String, Arc<str>), String> {
    let project = project::resolve(entry)?;
    let table = build(&project, entry, vec![name.to_string()])?;
    let pkg = table.packages.first().ok_or_else(|| format!("use \"{}\": no package", name))?;
    let main = pkg.index.main.clone().unwrap_or_default();
    let key = ModKey::Pkg { hash: pkg.hash.clone(), path: main };
    let src = table.source(&key).ok_or_else(|| format!("use \"{}\": the main file is not UTF-8", name))?;
    Ok((key.display(), src))
}

/// `tree-sha256:83c1…` para los mensajes.
pub fn short_hash(h: &str) -> String {
    match h.strip_prefix("tree-sha256:") {
        Some(x) if x.len() > 4 => format!("tree-sha256:{}…", &x[..4]),
        _ => h.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N2 (ronda 1, N13): la carpeta del knob se muestra con los separadores del sistema.
    #[cfg(windows)]
    #[test]
    fn the_cache_knob_uses_the_system_separators() {
        assert_eq!(super::knob_path(std::ffi::OsStr::new("C:/x/cache")).display().to_string(), r"C:\x\cache");
        assert_eq!(super::knob_path(std::ffi::OsStr::new("rel/cache")).display().to_string(), r"rel\cache");
    }

    #[test]
    fn tree_hash_sorts_lines_by_bytes() {
        let a = tree_hash([("b.syn", "11"), ("a.syn", "22")]);
        let b = tree_hash([("a.syn", "22"), ("b.syn", "11")]);
        assert_eq!(a, b);
        // "11  b.syn\n" < "22  a.syn\n": el orden es el de las líneas, no el de las rutas.
        let mut h = Sha256::new();
        h.update(b"11  b.syn\n22  a.syn\n");
        assert_eq!(a, format!("tree-sha256:{}", hex(&h.finalize())));
    }

    #[test]
    fn the_tree_hash_of_a_known_package() {
        // Ronda 3 (M-r3-1): el mismo vector que `verify.syn` (PKG_HASH), calculado aparte con
        // sha256sum sobre las líneas ordenadas: el motor y el verificador hashean igual.
        let index = br#"{"id": "https://r.example/p", "version": "0.1.0", "main": "m.syn", "files": [{"path": "m.syn", "sha256": "21bbab734f4f606cb951fe6f7f586606da275a417852e54ec1f406fe4321503d"}]}"#;
        assert_eq!(sha256_hex(b"export let P be 1\n"), "21bbab734f4f606cb951fe6f7f586606da275a417852e54ec1f406fe4321503d");
        let isha = sha256_hex(index);
        let t = tree_hash([("m.syn", "21bbab734f4f606cb951fe6f7f586606da275a417852e54ec1f406fe4321503d"), ("synsema.json", isha.as_str())]);
        assert_eq!(t, "tree-sha256:3164aa678c8f770b5c57bd2d5d9daef3b69425c84320c50db0be0717b369b6cf");
    }

    #[test]
    fn package_paths() {
        for ok in ["a.syn", "lib/x.syn", "_x/y-z.html", "v1.2/a.syn"] {
            check_pkg_path(ok).unwrap_or_else(|e| panic!("{}: {}", ok, e));
        }
        for bad in ["", "../a.syn", "a//b.syn", "/a.syn", "a\\b.syn", "a:b.syn", "a/.", "a.", ".a", "con.syn", "lpt1/x.syn", "Aux"] {
            assert!(check_pkg_path(bad).is_err(), "{}", bad);
        }
        assert!(check_pkg_path(&"a".repeat(129)).is_err());
        assert!(check_pkg_paths(&["a.syn", "A.syn"]).is_err());
        assert!(check_pkg_paths(&["a", "a/b.syn"]).is_err());
        assert!(check_pkg_paths(&["A", "a/b.syn"]).is_err());
        assert!(check_pkg_paths(&["SynSema.JSON"]).is_err());
        assert!(check_pkg_paths(&["ab.syn", "a/b.syn"]).is_ok());
    }

    #[test]
    fn classify_texts() {
        assert_eq!(classify("tok"), Ok(UseKind::Name));
        assert_eq!(classify("./a.syn"), Ok(UseKind::File));
        assert_eq!(classify("./orders.txt"), Ok(UseKind::File));
        assert_eq!(classify("trusted:x"), Ok(UseKind::Trusted("x")));
        assert_eq!(
            classify("https://x.com/t.syn").unwrap_err(),
            "use \"https://x.com/t.syn\": a module from a URL goes in synsema.json, not in the code: add {\"modules\": {\"t\": {\"url\": \"https://x.com/t.syn\"}}}, run synsema get, then use \"t\" as t"
        );
        for bad in ["Tok", "a/b", "a.b"] {
            assert_eq!(
                classify(bad).unwrap_err(),
                format!("use \"{}\": not a module name (lowercase letters, digits, '-' and '_') nor a path to a .syn file", bad)
            );
        }
    }

    #[test]
    fn relative_inside_a_package() {
        assert_eq!(pkg_relative("main.syn", "./capas.syn").unwrap(), "capas.syn");
        assert_eq!(pkg_relative("lib/a.syn", "../b.syn").unwrap(), "b.syn");
        assert_eq!(pkg_relative("main.syn", "../x.syn").unwrap_err(), "module path escapes the package: '../x.syn'");
    }

    #[test]
    fn id_normalization() {
        assert_eq!(normalize_id("HTTPS://Reg.Example:443/Tok"), "https://reg.example/Tok");
        assert_eq!(normalize_id("http://localhost:80/x"), "http://localhost/x");
    }
}
