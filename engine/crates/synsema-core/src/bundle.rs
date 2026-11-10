//! Bundle de `synsema build`: el programa (`.syn` principal + módulos `use` + templates +
//! `--include`) anexado al final del ejecutable del motor, con un trailer fijo.
//!
//! Layout del archivo producido:
//!
//! ```text
//! [ ejecutable del motor, byte a byte ][ payload ][ trailer de 64 bytes ]
//! payload = manifest_len u32 LE | manifest (JSON) | n u32 LE
//!           | n × ( name_len u16 LE | name (UTF-8, '/'-separado) | len u64 LE | bytes )
//! trailer = offset u64 LE | payload_len u64 LE | sha256(payload) 32 B | "SYNSEMA-BUNDLE-1"
//! ```
//!
//! El bundle es INMUTABLE y de sólo lectura: se monta una vez por proceso (`mount`) y los
//! sitios de lectura del programa (`use`, templates, `read_file` & co.) lo consultan
//! ANTES del disco. Los nombres son relativos a la raíz del bundle (el directorio del
//! `.syn` principal en el build), con `/`, normalizados léxicamente; un nombre que escape
//! (`..`) o sea absoluto se rechaza al construir y al parsear.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 16] = b"SYNSEMA-BUNDLE-1";
pub const TRAILER_LEN: u64 = 8 + 8 + 32 + 16;
pub const FORMAT: u64 = 1;

/// Lo que el build hornea junto al programa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub format: u64,
    /// Versión del motor que hizo el build (informativa).
    pub engine: String,
    /// Nombre (normalizado) del `.syn` principal dentro del bundle.
    pub main: String,
    /// Techo horneado, en la sintaxis de `--cap-set` (`"sandbox"` para `--sandbox`).
    /// `None` = sin techo, como `synsema run` pelado.
    pub ceiling: Option<String>,
    /// `"native"` | `"pure"`.
    pub profile: String,
    pub built_at: String,
    /// Cómo corre el binario: `Run` (el programa termina cuando termina) o `Serve` (el
    /// runtime de `synsema serve`: bloquea, sirve, cron, agentes). Ausente en el JSON = `Run`,
    /// así un bundle sin `--serve` es byte a byte el de siempre.
    pub mode: BundleMode,
    /// Los flags de despliegue de `synsema serve` horneados con `--serve` (`--bind` es
    /// obligatorio: un distribuible no adivina en qué interfaz escucha).
    pub serve: Option<ServeSettings>,
    /// v0.6.20 — `--audit` horneado por `synsema build` (misma sintaxis que el flag:
    /// `json` | `<ruta>` | `fd:N` | `unix:<ruta>`). Ausente en el JSON = sin audit, así un
    /// bundle anterior se lee igual y uno sin `--audit` no cambia ni un byte.
    pub audit: Option<String>,
    /// v0.6.58 (§9, §5.3): los hashes de los paquetes del grafo, en el orden de su sección. Vacío =
    /// sin la clave en el JSON y sin la sección: un bundle sin paquetes no cambia ni un byte.
    pub packages: Vec<String>,
}

/// Modo de ejecución del binario construido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleMode {
    Run,
    Serve,
}

/// Overrides de despliegue horneados (espejo de `ServeOverrides` del runtime, sin el techo:
/// el techo va en `ceiling`). Las rutas de `tls_cert`/`tls_key` se leen del DISCO al
/// arrancar — la clave privada no viaja dentro del binario.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServeSettings {
    pub bind: String,
    pub port: Option<u16>,
    pub domains: Option<Vec<String>>,
    pub tls_auto: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub secure: bool,
}

impl ServeSettings {
    fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("bind".into(), serde_json::Value::from(self.bind.clone()));
        m.insert("port".into(), self.port.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null));
        m.insert(
            "domains".into(),
            match &self.domains {
                Some(d) => serde_json::Value::from(d.clone()),
                None => serde_json::Value::Null,
            },
        );
        for (k, v) in [("tls_auto", &self.tls_auto), ("tls_cert", &self.tls_cert), ("tls_key", &self.tls_key)] {
            m.insert(k.into(), v.clone().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null));
        }
        m.insert("secure".into(), serde_json::Value::from(self.secure));
        serde_json::Value::Object(m)
    }

    fn from_json(v: &serde_json::Value) -> Result<ServeSettings, String> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
        let bind = s("bind").filter(|b| !b.is_empty()).ok_or("bundle manifest: serve.bind is required")?;
        let port = match v.get("port") {
            None | Some(serde_json::Value::Null) => None,
            Some(p) => Some(
                p.as_u64()
                    .filter(|n| (1..=65535).contains(n))
                    .map(|n| n as u16)
                    .ok_or("bundle manifest: serve.port must be a port number")?,
            ),
        };
        let domains = match v.get("domains") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Array(a)) => {
                Some(a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            }
            Some(_) => return Err("bundle manifest: serve.domains must be a list".to_string()),
        };
        Ok(ServeSettings {
            bind,
            port,
            domains,
            tls_auto: s("tls_auto"),
            tls_cert: s("tls_cert"),
            tls_key: s("tls_key"),
            secure: v.get("secure").and_then(|x| x.as_bool()).unwrap_or(false),
        })
    }
}

impl Manifest {
    fn to_json(&self) -> String {
        let mut m = serde_json::Map::new();
        m.insert("format".into(), serde_json::Value::from(self.format));
        m.insert("engine".into(), serde_json::Value::from(self.engine.clone()));
        m.insert("main".into(), serde_json::Value::from(self.main.clone()));
        m.insert(
            "ceiling".into(),
            match &self.ceiling {
                Some(c) => serde_json::Value::from(c.clone()),
                None => serde_json::Value::Null,
            },
        );
        m.insert("profile".into(), serde_json::Value::from(self.profile.clone()));
        m.insert("built_at".into(), serde_json::Value::from(self.built_at.clone()));
        // Sólo cuando hay algo que decir: un bundle de `run` no cambia ni un byte.
        if self.mode == BundleMode::Serve {
            m.insert("mode".into(), serde_json::Value::from("serve"));
        }
        if let Some(s) = &self.serve {
            m.insert("serve".into(), s.to_json());
        }
        if let Some(a) = &self.audit {
            m.insert("audit".into(), serde_json::Value::from(a.clone()));
        }
        if !self.packages.is_empty() {
            m.insert("packages".into(), serde_json::Value::from(self.packages.clone()));
        }
        serde_json::Value::Object(m).to_string()
    }

    fn from_json(s: &str) -> Result<Manifest, String> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("bundle manifest is not JSON: {}", e))?;
        let str_field = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
                .ok_or_else(|| format!("bundle manifest: missing `{}`", k))
        };
        let format = v.get("format").and_then(|x| x.as_u64()).unwrap_or(0);
        if format != FORMAT {
            return Err(format!("bundle format {} is not supported by this engine (expects {})", format, FORMAT));
        }
        let ceiling = match v.get("ceiling") {
            Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        let profile = str_field("profile")?;
        if profile != "native" && profile != "pure" {
            return Err(format!("bundle manifest: unknown profile '{}'", profile));
        }
        let mode = match v.get("mode").and_then(|x| x.as_str()) {
            None | Some("run") => BundleMode::Run,
            Some("serve") => BundleMode::Serve,
            Some(other) => return Err(format!("bundle manifest: unknown mode '{}'", other)),
        };
        let serve = match v.get("serve") {
            None | Some(serde_json::Value::Null) => None,
            Some(s) => Some(ServeSettings::from_json(s)?),
        };
        if mode == BundleMode::Serve && serve.is_none() {
            return Err("bundle manifest: mode 'serve' without serve settings".to_string());
        }
        if mode == BundleMode::Serve && profile == "pure" {
            return Err("bundle manifest: a serve bundle cannot run under the pure profile".to_string());
        }
        let audit = match v.get("audit") {
            Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        let packages = match v.get("packages") {
            None => Vec::new(),
            Some(serde_json::Value::Array(xs)) => {
                let mut out = Vec::with_capacity(xs.len());
                for x in xs {
                    match x.as_str() {
                        Some(h) if crate::modtable::is_tree_hash(h) && !out.iter().any(|o: &String| o == h) => out.push(h.to_string()),
                        _ => return Err("bundle manifest: packages is a list of distinct tree-sha256 hashes".to_string()),
                    }
                }
                out
            }
            Some(_) => return Err("bundle manifest: packages is a list of distinct tree-sha256 hashes".to_string()),
        };
        Ok(Manifest {
            format,
            engine: str_field("engine")?,
            main: str_field("main")?,
            ceiling,
            profile,
            built_at: v.get("built_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            mode,
            serve,
            audit,
            packages,
        })
    }
}

/// Un paquete de la sección de paquetes: su hash y sus archivos (con su `synsema.json`), por ruta
/// adentro del paquete.
pub type BundledPackage = (String, Vec<(String, Vec<u8>)>);

/// El bundle en memoria.
#[derive(Debug)]
pub struct Bundle {
    pub manifest: Manifest,
    files: HashMap<String, Vec<u8>>,
    /// Nombres en orden de inserción (determinismo del serializado y de `list`).
    order: Vec<String>,
    /// v0.6.58 (§9, §5.3): la sección de paquetes, aparte de `files`. Nada que lea por ruta
    /// (`get`, `list`, `render`, `static`, `read_file`) la ve: sólo la tabla, por hash.
    packages: Vec<BundledPackage>,
}

/// Normaliza un nombre de bundle: `\` → `/`, colapsa `.`/`..`, sin `/` inicial ni final.
/// `None` si escapa de la raíz (`..` de más) o es absoluto (unidad o `/` inicial).
pub fn normalize_name(path: &str) -> Option<String> {
    let p = path.replace('\\', "/");
    if p.starts_with('/') || p.chars().nth(1) == Some(':') {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            s => out.push(s),
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join("/"))
}

/// v0.6.58: la clave de la carpeta de un mount estático dentro del bundle. Como `normalize_name`,
/// pero la raíz (`.`, `./`, `""`) es `Some("")`: `static "/" from "."` sirve lo que viaja en el
/// binario (antes daba `None`, el mount caía al disco y en otra carpeta todo era 404).
pub fn mount_key(dir: &str) -> Option<String> {
    // N10 (ronda 1): la misma normalización que `normalize_name`, pero lo que queda vacío (`.`,
    // `a/..`) es la raíz: antes `a/..` daba `None` y el mount caía al disco.
    let p = dir.replace('\\', "/");
    if p.starts_with('/') || p.chars().nth(1) == Some(':') {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            s => out.push(s),
        }
    }
    Some(out.join("/"))
}

/// Ronda 2 (M-r2-3): un nombre leído de un bundle ya viene normalizado (`build` sólo escribe esa
/// forma). Otra forma (`./app.syn`, `a\b`, `x/../y`) se rechaza en vez de reescribirse: así lo que
/// corre el motor y lo que muestra un verificador (`verify.syn`) son la misma entrada.
fn stored_name(name: &str) -> Result<(), String> {
    if normalize_name(name).as_deref() == Some(name) {
        Ok(())
    } else {
        Err(format!("bundle: entry name '{}' is not normalized", name))
    }
}

impl Bundle {
    /// Construye un bundle validando cada nombre.
    pub fn new(manifest: Manifest, entries: Vec<(String, Vec<u8>)>) -> Result<Bundle, String> {
        let mut files = HashMap::new();
        let mut order = Vec::new();
        for (name, bytes) in entries {
            let key = normalize_name(&name)
                .ok_or_else(|| format!("bundle: invalid entry name '{}' (must stay under the bundle root)", name))?;
            if key.len() > u16::MAX as usize {
                return Err(format!("bundle: entry name too long: '{}'", name));
            }
            // Ronda 2 (M-r2-3): una sola entrada por nombre normalizado. Con `app.syn` y `./app.syn`
            // el motor corría la última y un verificador que mira el nombre escrito veía la primera
            // (`parse` además exige el nombre ya normalizado: lo que viaja no se reescribe).
            if files.contains_key(&key) {
                return Err(format!("bundle: the entry '{}' appears twice", name));
            }
            files.insert(key.clone(), bytes);
            order.push(key);
        }
        if normalize_name(&manifest.main).as_deref() != Some(manifest.main.as_str()) {
            return Err(format!("bundle: main '{}' is not a normalized bundle name", manifest.main));
        }
        if !files.contains_key(&manifest.main) {
            return Err(format!("bundle: main '{}' is not among the entries", manifest.main));
        }
        if !manifest.packages.is_empty() {
            return Err("bundle: the manifest lists packages but the bundle has no package section".to_string());
        }
        Ok(Bundle { manifest, files, order, packages: Vec::new() })
    }

    /// v0.6.58 (§9): un bundle con la sección de paquetes. Sus hashes son los del manifiesto, en
    /// el mismo orden; cada uno trae su `synsema.json`. Lo que lleva cada uno se verifica al armar
    /// la tabla (el hash del árbol se recalcula sobre estos bytes), como desde el caché.
    pub fn with_packages(mut manifest: Manifest, entries: Vec<(String, Vec<u8>)>, packages: Vec<BundledPackage>) -> Result<Bundle, String> {
        let hashes: Vec<String> = packages.iter().map(|(h, _)| h.clone()).collect();
        if !manifest.packages.is_empty() && manifest.packages != hashes {
            return Err("bundle: the package section does not match the manifest".to_string());
        }
        manifest.packages = Vec::new();
        let mut b = Bundle::new(manifest, entries)?;
        // Ronda 3 (M-r3-1): una ruta repetida adentro de un paquete, o un paquete repetido, es la
        // regla de `Bundle::new` en la sección de paquetes: el motor leería el primero y un
        // verificador podría mostrar el otro.
        let mut seen_hash = std::collections::HashSet::new();
        for (h, files) in &packages {
            if !seen_hash.insert(h.as_str()) {
                return Err(format!("bundle: the package {} appears twice", h));
            }
            if !crate::modtable::is_tree_hash(h) || !files.iter().any(|(p, _)| p == "synsema.json") {
                return Err(format!("bundle: package {} has no synsema.json", h));
            }
            if files.iter().any(|(p, _)| p.len() > u16::MAX as usize) {
                return Err(format!("bundle: a path of package {} is too long", h));
            }
            let mut seen = std::collections::HashSet::new();
            if let Some((p, _)) = files.iter().find(|(p, _)| !seen.insert(p.as_str())) {
                return Err(format!("bundle: package {} has the path '{}' twice", h, p));
            }
        }
        b.manifest.packages = hashes;
        b.packages = packages;
        Ok(b)
    }

    /// Los archivos de un paquete de la sección, por su hash.
    pub fn package(&self, hash: &str) -> Option<&[(String, Vec<u8>)]> {
        self.packages.iter().find(|(h, _)| h == hash).map(|(_, f)| f.as_slice())
    }

    pub fn get(&self, path: &str) -> Option<&[u8]> {
        let key = normalize_name(path)?;
        self.files.get(&key).map(|v| v.as_slice())
    }

    pub fn contains(&self, path: &str) -> bool {
        self.get(path).is_some()
    }

    /// Entradas (nombre, tamaño) bajo un prefijo de directorio (`""` = todas), en orden.
    /// `true` si el bundle tiene al menos una entrada bajo `dir/` (un mount estático
    /// declarado en el programa cuyos archivos viajan dentro del binario).
    pub fn has_prefix(&self, dir: &str) -> bool {
        match mount_key(dir) {
            Some(d) if d.is_empty() => !self.order.is_empty(),
            Some(d) => {
                let p = format!("{}/", d);
                self.order.iter().any(|n| n.starts_with(&p))
            }
            None => false,
        }
    }

    /// `true` si `key` es un "directorio" del bundle (tiene entradas debajo).
    pub fn is_dir(&self, key: &str) -> bool {
        let p = format!("{}/", key.trim_end_matches('/'));
        !key.is_empty() && self.order.iter().any(|n| n.starts_with(&p))
    }

    pub fn list(&self, dir: &str) -> Vec<(String, usize)> {
        let prefix = match dir.trim_matches(|c| c == '/' || c == '\\') {
            "" | "." => String::new(),
            d => match normalize_name(d) {
                Some(n) => format!("{}/", n),
                None => return Vec::new(),
            },
        };
        self.order
            .iter()
            .filter(|n| n.starts_with(&prefix))
            .map(|n| (n.clone(), self.files[n].len()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn names(&self) -> &[String] {
        &self.order
    }

    /// El payload (sin trailer).
    pub fn payload(&self) -> Vec<u8> {
        let manifest = self.manifest.to_json();
        let mut out = Vec::new();
        out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        out.extend_from_slice(manifest.as_bytes());
        out.extend_from_slice(&(self.order.len() as u32).to_le_bytes());
        for name in &self.order {
            let bytes = &self.files[name];
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        // v0.6.58: la sección de paquetes, sólo si hay (el manifiesto la anuncia).
        // `n u32 | n × (hash_len u16 | hash | m u32 | m × (name_len u16 | name | len u64 | bytes))`.
        if !self.packages.is_empty() {
            out.extend_from_slice(&(self.packages.len() as u32).to_le_bytes());
            for (hash, files) in &self.packages {
                out.extend_from_slice(&(hash.len() as u16).to_le_bytes());
                out.extend_from_slice(hash.as_bytes());
                out.extend_from_slice(&(files.len() as u32).to_le_bytes());
                for (name, bytes) in files {
                    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    out.extend_from_slice(name.as_bytes());
                    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }

    /// `payload + trailer`, listo para anexar a un ejecutable de `base_len` bytes.
    pub fn serialize(&self, base_len: u64) -> Vec<u8> {
        let mut out = self.payload();
        let payload_len = out.len() as u64;
        let sha = Sha256::digest(&out);
        out.extend_from_slice(&base_len.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&sha);
        out.extend_from_slice(MAGIC);
        out
    }

    /// Parsea un payload (ya verificado por sha).
    pub fn parse(payload: &[u8]) -> Result<Bundle, String> {
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8], String> {
            let end = pos.checked_add(n).ok_or("bundle: truncated")?;
            let s = payload.get(*pos..end).ok_or("bundle: truncated")?;
            *pos = end;
            Ok(s)
        };
        let manifest_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
        let manifest_src = std::str::from_utf8(take(&mut pos, manifest_len)?)
            .map_err(|_| "bundle manifest is not UTF-8".to_string())?;
        let manifest = Manifest::from_json(manifest_src)?;
        let n = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
        // B16 (ronda 1): `n` viene del payload; cada entrada ocupa al menos 10 bytes (largo del nombre y
        // del contenido), así que la reserva no pasa de lo que queda: un `n` enorme da «truncated».
        let mut entries = Vec::with_capacity(n.min(payload.len().saturating_sub(pos) / 10));
        for _ in 0..n {
            let name_len = u16::from_le_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
            let name = std::str::from_utf8(take(&mut pos, name_len)?)
                .map_err(|_| "bundle entry name is not UTF-8".to_string())?
                .to_string();
            stored_name(&name)?;
            let len = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            let len = usize::try_from(len).map_err(|_| "bundle: entry too large".to_string())?;
            let bytes = take(&mut pos, len)?.to_vec();
            entries.push((name, bytes));
        }
        let mut packages: Vec<BundledPackage> = Vec::new();
        if !manifest.packages.is_empty() {
            // N10 (ronda 1): el payload terminó con las entradas: no es un bundle cortado, es uno sin la
            // sección (el mismo texto que `Bundle::new`).
            if pos == payload.len() {
                return Err("bundle: the manifest lists packages but the bundle has no package section".to_string());
            }
            let n = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
            for _ in 0..n {
                let hl = u16::from_le_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
                let hash = std::str::from_utf8(take(&mut pos, hl)?).map_err(|_| "bundle package hash is not UTF-8".to_string())?.to_string();
                let m = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
                let mut files = Vec::with_capacity(m.min(4096));
                for _ in 0..m {
                    let nl = u16::from_le_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
                    let name = std::str::from_utf8(take(&mut pos, nl)?).map_err(|_| "bundle package path is not UTF-8".to_string())?.to_string();
                    stored_name(&name)?;
                    let len = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
                    let len = usize::try_from(len).map_err(|_| "bundle: entry too large".to_string())?;
                    files.push((name, take(&mut pos, len)?.to_vec()));
                }
                packages.push((hash, files));
            }
        }
        if pos != payload.len() {
            return Err("bundle: trailing bytes after the last entry".to_string());
        }
        if packages.is_empty() {
            Bundle::new(manifest, entries)
        } else {
            Bundle::with_packages(manifest, entries, packages)
        }
    }
}

/// Qué hay al final de un ejecutable.
pub enum Detected {
    /// Sin trailer: un binario del motor normal.
    Plain,
    /// Con trailer y sha válido.
    Bundle(Bundle),
}

/// Lee el trailer de `exe`; si tiene el magic, verifica el sha256 del payload entero y
/// lo parsea. `Err` = trailer presente pero corrupto (NUNCA se ejecuta nada en ese caso).
pub fn detect(exe: &Path) -> Result<Detected, String> {
    let mut f = std::fs::File::open(exe).map_err(|e| format!("cannot open {}: {}", exe.display(), e))?;
    let total = f.metadata().map_err(|e| e.to_string())?.len();
    if total < TRAILER_LEN {
        return Ok(Detected::Plain);
    }
    f.seek(SeekFrom::End(-(TRAILER_LEN as i64))).map_err(|e| e.to_string())?;
    let mut trailer = [0u8; TRAILER_LEN as usize];
    f.read_exact(&mut trailer).map_err(|e| e.to_string())?;
    if &trailer[48..64] != MAGIC {
        return Ok(Detected::Plain);
    }
    let offset = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    let payload_len = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
    let sha: [u8; 32] = trailer[16..48].try_into().unwrap();
    if offset.checked_add(payload_len).map(|e| e + TRAILER_LEN) != Some(total) {
        return Err("bundle corrupt (trailer offsets do not match the file size)".to_string());
    }
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut payload = vec![0u8; payload_len as usize];
    f.read_exact(&mut payload).map_err(|e| format!("bundle corrupt (short read): {}", e))?;
    let got = Sha256::digest(&payload);
    if got[..] != sha[..] {
        return Err("bundle corrupt (sha256 mismatch)".to_string());
    }
    let bundle = Bundle::parse(&payload).map_err(|e| format!("bundle corrupt ({})", e))?;
    Ok(Detected::Bundle(bundle))
}

/// v0.6.58 (§12): un bundle entero en memoria (`payload ‖ trailer`, lo que [`Bundle::serialize`]
/// escribe), con las mismas verificaciones que [`detect`]: el magic, que los largos cierren con el
/// tamaño y el sha256 del payload. Es lo que lleva el slot `APPSLOT2` del guest de Vela: ahí no hay
/// ejecutable adelante, así que el `offset` del trailer es 0.
pub fn from_serialized(bytes: &[u8]) -> Result<Bundle, String> {
    let total = bytes.len() as u64;
    if total < TRAILER_LEN || &bytes[bytes.len() - 16..] != MAGIC {
        return Err("not a Synsema bundle (no SYNSEMA-BUNDLE-1 trailer)".to_string());
    }
    let trailer = &bytes[bytes.len() - TRAILER_LEN as usize..];
    let offset = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    let payload_len = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
    if offset != 0 || payload_len.checked_add(TRAILER_LEN) != Some(total) {
        return Err("bundle corrupt (trailer offsets do not match its size)".to_string());
    }
    let payload = &bytes[..payload_len as usize];
    if Sha256::digest(payload)[..] != trailer[16..48] {
        return Err("bundle corrupt (sha256 mismatch)".to_string());
    }
    Bundle::parse(payload).map_err(|e| format!("bundle corrupt ({})", e))
}

/// ¿Este ejecutable ya lleva un bundle? (sin verificar el sha: sólo el magic).
pub fn is_built(exe: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(exe) else { return false };
    let Ok(total) = f.metadata().map(|m| m.len()) else { return false };
    if total < TRAILER_LEN || f.seek(SeekFrom::End(-16)).is_err() {
        return false;
    }
    let mut magic = [0u8; 16];
    f.read_exact(&mut magic).is_ok() && &magic == MAGIC
}

static MOUNTED: OnceLock<Bundle> = OnceLock::new();

/// Monta el bundle del proceso (una vez). `false` si ya había uno montado.
pub fn mount(bundle: Bundle) -> bool {
    MOUNTED.set(bundle).is_ok()
}

/// El bundle montado en este proceso (sólo en "modo programa" de un binario `build`).
pub fn mounted() -> Option<&'static Bundle> {
    MOUNTED.get()
}

/// Atajo: los bytes de `path` en el bundle montado, si hay bundle y lo contiene.
pub fn get(path: &str) -> Option<&'static [u8]> {
    MOUNTED.get().and_then(|b| b.get(path))
}

/// v0.6.58 (§9): un paquete de la sección del bundle montado, por su hash.
pub fn package(hash: &str) -> Option<&'static [(String, Vec<u8>)]> {
    MOUNTED.get().and_then(|b| b.package(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            format: FORMAT,
            engine: "vtest".into(),
            main: "lamp.syn".into(),
            ceiling: Some("stdout,net=api.example.com".into()),
            profile: "pure".into(),
            built_at: "2026-08-30T00:00:00Z".into(),
            mode: BundleMode::Run,
            serve: None,
            audit: None,
            packages: Vec::new(),
        }
    }

    /// v0.6.58 (§12): un bundle en memoria (el slot `APPSLOT2`) se lee con las verificaciones de
    /// `detect`: el offset tiene que ser 0, los largos cerrar y el sha256 del payload coincidir.
    #[test]
    fn from_serialized_checks_like_detect() {
        let b = Bundle::new(manifest(), vec![("lamp.syn".into(), b"print(1)\n".to_vec())]).unwrap();
        let bytes = b.serialize(0);
        let back = from_serialized(&bytes).unwrap();
        assert_eq!(back.get("lamp.syn"), Some(&b"print(1)\n"[..]));
        // Detrás de un ejecutable (offset ≠ 0) no es un slot.
        assert!(from_serialized(&b.serialize(7)).unwrap_err().contains("trailer offsets"));
        let mut changed = bytes.clone();
        changed[10] ^= 1;
        assert!(from_serialized(&changed).unwrap_err().contains("sha256 mismatch"));
        assert!(from_serialized(&bytes[1..]).unwrap_err().contains("trailer offsets"));
        assert!(from_serialized(b"short").unwrap_err().contains("not a Synsema bundle"));
    }

    /// v0.6.58 (B4): la carpeta raíz de un mount (`static "/" from "."`) tiene clave: la vacía.
    /// Antes `normalize_name(".")` daba `None` y el mount del binario caía al disco.
    #[test]
    fn the_root_of_a_static_mount_is_in_the_bundle() {
        for root in [".", "./", "", ".\\", "./."] {
            assert_eq!(mount_key(root).as_deref(), Some(""), "{:?}", root);
        }
        assert_eq!(mount_key("./public/").as_deref(), Some("public"));
        assert_eq!(mount_key("/"), None);
        assert_eq!(mount_key("../x"), None);
        // N10 (ronda 1): lo que vuelve a la raíz es la raíz; lo que sale, nada.
        assert_eq!(mount_key("a/..").as_deref(), Some(""));
        assert_eq!(mount_key("a/../b").as_deref(), Some("b"));
        assert_eq!(mount_key("a/../.."), None);
        assert_eq!(mount_key("C:/x"), None);
        let b = Bundle::new(manifest(), vec![("lamp.syn".into(), b"print(1)\n".to_vec())]).unwrap();
        assert!(b.has_prefix("."));
        assert!(!b.has_prefix("./public"));
    }

    /// Un manifest `run` no escribe `mode`/`serve` (byte a byte el de v0.6.14); uno `serve`
    /// los lleva y vuelve igual; los inválidos se rechazan al parsear.
    #[test]
    fn manifest_mode_and_serve_round_trip() {
        let run = manifest();
        let j = run.to_json();
        assert!(!j.contains("\"mode\"") && !j.contains("\"serve\""), "{}", j);
        assert_eq!(Manifest::from_json(&j).unwrap(), run);

        let mut srv = manifest();
        srv.profile = "native".into();
        srv.mode = BundleMode::Serve;
        srv.serve = Some(ServeSettings {
            bind: "127.0.0.1".into(),
            port: Some(8123),
            domains: Some(vec!["a.example".into()]),
            tls_auto: None,
            tls_cert: Some("cert.pem".into()),
            tls_key: Some("key.pem".into()),
            secure: true,
        });
        let j = srv.to_json();
        assert!(j.contains("\"mode\":\"serve\""), "{}", j);
        assert_eq!(Manifest::from_json(&j).unwrap(), srv);

        let bad = j.replace("\"mode\":\"serve\"", "\"mode\":\"daemon\"");
        assert!(Manifest::from_json(&bad).unwrap_err().contains("unknown mode"));
        let no_bind = j.replace("\"bind\":\"127.0.0.1\"", "\"bind\":\"\"");
        assert!(Manifest::from_json(&no_bind).unwrap_err().contains("serve.bind is required"));
        let pure = j.replace("\"profile\":\"native\"", "\"profile\":\"pure\"");
        assert!(Manifest::from_json(&pure).unwrap_err().contains("pure profile"));
    }

    /// v0.6.20 — `audit` horneado: ausente = None (bundles anteriores), presente vuelve igual.
    #[test]
    fn manifest_audit_round_trip() {
        let plain = manifest();
        assert!(!plain.to_json().contains("\"audit\""));
        assert_eq!(Manifest::from_json(&plain.to_json()).unwrap().audit, None);
        let mut with = manifest();
        with.audit = Some("fd:3".into());
        let j = with.to_json();
        assert!(j.contains("\"audit\":\"fd:3\""), "{}", j);
        assert_eq!(Manifest::from_json(&j).unwrap(), with);
    }

    #[test]
    fn bundle_round_trip() {
        let b = Bundle::new(
            manifest(),
            vec![
                ("lamp.syn".into(), b"print(\"hi\")\n".to_vec()),
                ("lib\\m.syn".into(), b"export task f()\n    give 1\n".to_vec()),
                ("./assets/a.json".into(), b"{}".to_vec()),
            ],
        )
        .unwrap();
        let bytes = b.serialize(1000);
        assert_eq!(&bytes[bytes.len() - 16..], MAGIC);
        let payload_len = u64::from_le_bytes(bytes[bytes.len() - 56..bytes.len() - 48].try_into().unwrap());
        let payload = &bytes[..payload_len as usize];
        let back = Bundle::parse(payload).unwrap();
        assert_eq!(back.manifest, manifest());
        assert_eq!(back.get("lib/m.syn").unwrap(), b"export task f()\n    give 1\n");
        assert_eq!(back.get("assets\\a.json").unwrap(), b"{}");
        assert!(back.get("../lamp.syn").is_none());
        assert_eq!(back.list("lib").len(), 1);
        assert_eq!(back.list("").len(), 3);
    }

    /// N10 (ronda 1): un manifiesto con paquetes y un payload sin la sección lo dice, no «truncated».
    #[test]
    fn packages_without_their_section_say_so() {
        let b = Bundle::new(manifest(), vec![("lamp.syn".into(), b"print(1)\n".to_vec())]).unwrap();
        let mut m = manifest();
        m.packages = vec![format!("tree-sha256:{}", "0".repeat(64))];
        let mj = m.to_json();
        let mut payload = (mj.len() as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(mj.as_bytes());
        let old = b.payload();
        let oldm = u32::from_le_bytes(old[0..4].try_into().unwrap()) as usize;
        payload.extend_from_slice(&old[4 + oldm..]);
        assert_eq!(Bundle::parse(&payload).err().as_deref(), Some("bundle: the manifest lists packages but the bundle has no package section"));
    }

    /// B16 (ronda 1): un `n` de entradas enorme con el payload chico es «truncated», no un pánico al
    /// reservar.
    #[test]
    fn a_huge_entry_count_is_truncated_not_a_panic() {
        let b = Bundle::new(manifest(), vec![("lamp.syn".into(), b"print(1)\n".to_vec())]).unwrap();
        let mut payload = b.payload();
        let m = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
        payload[4 + m..8 + m].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Bundle::parse(&payload).err().as_deref(), Some("bundle: truncated"));
    }

    #[test]
    fn entry_name_with_dotdot_rejected() {
        let r = Bundle::new(manifest(), vec![("lamp.syn".into(), vec![]), ("../x".into(), vec![])]);
        assert!(r.is_err());
        let r = Bundle::new(manifest(), vec![("lamp.syn".into(), vec![]), ("/etc/passwd".into(), vec![])]);
        assert!(r.is_err());
    }

    /// Ronda 2 (M-r2-3): un nombre sin normalizar o repetido no entra (con `lamp.syn` y
    /// `./lamp.syn` el motor corría uno y un verificador veía el otro), tampoco al leer un slot.
    #[test]
    fn a_name_that_is_not_normalized_or_appears_twice_is_rejected() {
        let honest = ("lamp.syn".to_string(), b"print(1)\n".to_vec());
        let r = Bundle::new(manifest(), vec![honest.clone(), ("./lamp.syn".into(), b"print(2)\n".to_vec())]);
        assert_eq!(r.err().as_deref(), Some("bundle: the entry './lamp.syn' appears twice"));
        let r = Bundle::new(manifest(), vec![honest.clone(), honest.clone()]);
        assert_eq!(r.err().as_deref(), Some("bundle: the entry 'lamp.syn' appears twice"));
        // Al leer (el slot del guest, un `.built`): un nombre escrito en otra forma no se reescribe.
        let b = Bundle::new(manifest(), vec![honest, ("x/y.syn".into(), b"print(2)\n".to_vec())]).unwrap();
        let bytes = b.serialize(1000);
        let payload_len = u64::from_le_bytes(bytes[bytes.len() - 56..bytes.len() - 48].try_into().unwrap()) as usize;
        let mut payload = bytes[..payload_len].to_vec();
        assert!(Bundle::parse(&payload).is_ok());
        let at = payload.windows(7).position(|w| w == b"x/y.syn").unwrap();
        for (form, says) in [(&b"./y.syn"[..], "'./y.syn'"), (b"x\\y.syn", "'x\\y.syn'"), (b"x/../ys", "'x/../ys'")] {
            payload[at..at + 7].copy_from_slice(form);
            let e = Bundle::parse(&payload).err().unwrap();
            assert_eq!(e, format!("bundle: entry name {} is not normalized", says));
        }
    }

    #[test]
    fn a_package_with_a_path_twice_or_twice_in_the_section_is_rejected() {
        // Ronda 3 (M-r3-1): lo que arma `build` (cada ruta una vez) se lee; una ruta repetida adentro
        // de un paquete, o el mismo paquete dos veces, no (al armar y al leer el slot).
        let h = format!("tree-sha256:{}", "a".repeat(64));
        let app = vec![("lamp.syn".to_string(), b"print(1)\n".to_vec())];
        let honest = vec![("synsema.json".to_string(), b"{}".to_vec()), ("m.syn".to_string(), b"export let P be 1\n".to_vec())];
        let mut m = manifest();
        m.packages = vec![h.clone()];
        let b = Bundle::with_packages(m.clone(), app.clone(), vec![(h.clone(), honest.clone())]).unwrap();
        let bytes = b.serialize(0);
        let payload_len = u64::from_le_bytes(bytes[bytes.len() - 56..bytes.len() - 48].try_into().unwrap()) as usize;
        assert!(Bundle::parse(&bytes[..payload_len]).is_ok());

        let mut dup = honest.clone();
        dup.push(("m.syn".to_string(), b"export let P be \"senuelo\"\n".to_vec()));
        let e = Bundle::with_packages(m.clone(), app.clone(), vec![(h.clone(), dup.clone())]).err().unwrap();
        assert_eq!(e, format!("bundle: package {} has the path 'm.syn' twice", h));
        let mut m2 = manifest();
        m2.packages = vec![h.clone(), h.clone()];
        let e = Bundle::with_packages(m2, app.clone(), vec![(h.clone(), honest.clone()), (h.clone(), honest.clone())]).err().unwrap();
        assert_eq!(e, format!("bundle: the package {} appears twice", h));

        // Al leer: el payload con la sección escrita a mano (un `m.syn` más al final del paquete).
        let mut payload = bytes[..payload_len].to_vec();
        let count_at = payload.windows(h.len()).rposition(|w| w == h.as_bytes()).unwrap() + h.len();
        let n = u32::from_le_bytes(payload[count_at..count_at + 4].try_into().unwrap());
        payload[count_at..count_at + 4].copy_from_slice(&(n + 1).to_le_bytes());
        let extra = b"export let P be \"senuelo\"\n";
        payload.extend_from_slice(&(5u16).to_le_bytes());
        payload.extend_from_slice(b"m.syn");
        payload.extend_from_slice(&(extra.len() as u64).to_le_bytes());
        payload.extend_from_slice(extra);
        assert_eq!(Bundle::parse(&payload).err().unwrap(), format!("bundle: package {} has the path 'm.syn' twice", h));
    }

    #[test]
    fn trailer_missing_is_plain_and_sha_mismatch_is_corrupt() {
        let dir = std::env::temp_dir().join(format!("synsema-bundle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.bin");
        std::fs::write(&plain, b"just an executable").unwrap();
        assert!(matches!(detect(&plain).unwrap(), Detected::Plain));
        assert!(!is_built(&plain));

        let b = Bundle::new(manifest(), vec![("lamp.syn".into(), b"print(1)".to_vec())]).unwrap();
        let mut file = b"just an executable".to_vec();
        let base = file.len() as u64;
        file.extend_from_slice(&b.serialize(base));
        let built = dir.join("built.bin");
        std::fs::write(&built, &file).unwrap();
        assert!(is_built(&built));
        assert!(matches!(detect(&built).unwrap(), Detected::Bundle(_)));

        // Un byte del payload alterado → corrupt.
        file[base as usize + 6] ^= 0xff;
        std::fs::write(&built, &file).unwrap();
        let err = detect(&built).err().unwrap();
        assert!(err.contains("bundle corrupt"), "{}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
