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
        Ok(Manifest {
            format,
            engine: str_field("engine")?,
            main: str_field("main")?,
            ceiling,
            profile,
            built_at: v.get("built_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            mode,
            serve,
        })
    }
}

/// El bundle en memoria.
#[derive(Debug)]
pub struct Bundle {
    pub manifest: Manifest,
    files: HashMap<String, Vec<u8>>,
    /// Nombres en orden de inserción (determinismo del serializado y de `list`).
    order: Vec<String>,
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
            if files.insert(key.clone(), bytes).is_none() {
                order.push(key);
            }
        }
        if normalize_name(&manifest.main).as_deref() != Some(manifest.main.as_str()) {
            return Err(format!("bundle: main '{}' is not a normalized bundle name", manifest.main));
        }
        if !files.contains_key(&manifest.main) {
            return Err(format!("bundle: main '{}' is not among the entries", manifest.main));
        }
        Ok(Bundle { manifest, files, order })
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
        match normalize_name(dir) {
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
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let name_len = u16::from_le_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
            let name = std::str::from_utf8(take(&mut pos, name_len)?)
                .map_err(|_| "bundle entry name is not UTF-8".to_string())?
                .to_string();
            let len = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            let len = usize::try_from(len).map_err(|_| "bundle: entry too large".to_string())?;
            let bytes = take(&mut pos, len)?.to_vec();
            entries.push((name, bytes));
        }
        if pos != payload.len() {
            return Err("bundle: trailing bytes after the last entry".to_string());
        }
        Bundle::new(manifest, entries)
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
        }
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

    #[test]
    fn entry_name_with_dotdot_rejected() {
        let r = Bundle::new(manifest(), vec![("lamp.syn".into(), vec![]), ("../x".into(), vec![])]);
        assert!(r.is_err());
        let r = Bundle::new(manifest(), vec![("lamp.syn".into(), vec![]), ("/etc/passwd".into(), vec![])]);
        assert!(r.is_err());
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
