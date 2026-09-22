//! Resolución de modelos: encontrar el archivo sin descargar nada.
//!
//! La pieza de mejor retorno del crate, porque es DX pura y cuesta poco: un dev que ya tiene
//! Ollama instalado corre su primer `.syn` con LLM local **sin bajar un byte**.
//!
//! ## El orden, de más específico a más general
//!
//! 1. **Una ruta a un archivo** que existe (lo de siempre: `SYNSEMA_LLM_MODEL=/ruta/modelo.gguf`).
//! 2. **El cache de Ollama** — `~/.ollama/models`, o `OLLAMA_MODELS` si está seteada.
//! 3. **El cache de Hugging Face** — `~/.cache/huggingface/hub`, o `HF_HOME`.
//!
//! No hay paso 4: **este crate no descarga nada**. Bajar un modelo es una acción de red con
//! consecuencias (tamaño, tiempo, procedencia) y le corresponde al runtime decidirla, igual que
//! decide todo lo demás que sale a la red.
//!
//! ## Por qué el store de Ollama es tan cómodo
//!
//! Guarda **GGUF crudos, sin formato propietario**: `models/blobs/sha256-<hash>` es el archivo
//! tal cual, y `models/manifests/<registry>/<ns>/<modelo>/<tag>` es un JSON tipo OCI que mapea el
//! nombre a los digests de sus capas. Se lee el manifest, se busca la capa de pesos y se abre ese
//! archivo. Cero conversión, cero copia.
//!
//! Y el regalo: el store es **content-addressed por SHA-256**, así que el hash de procedencia que
//! necesitamos para el audit **ya está en el nombre del archivo**. No hay que calcularlo ni
//! confiar en nadie para obtenerlo — para un modelo de 4 GB, eso son varios segundos que no se
//! pagan.
//!
//! ## Quién elige, y por qué esto no abre una puerta
//!
//! Descubrir el cache **no** le da al programa `.syn` la capacidad de leer el disco: el `.syn`
//! nunca nombra un modelo. Lo que hace es ofrecerle al **operador** una lista de candidatos para
//! que elija por nombre en su configuración (spec §4.1). La resolución corre en el runtime, con
//! los permisos del runtime, antes de que el programa exista.

use std::path::{Path, PathBuf};

/// De dónde salió un modelo. Va al audit: saber *qué* corrió incluye saber de dónde vino.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelOrigin {
    /// Una ruta explícita en disco.
    Path,
    /// El cache de Ollama, con el `modelo:tag` que lo nombra.
    Ollama { tag: String },
    /// El cache de Hugging Face, con el repo y la revisión del snapshot.
    HuggingFace { repo: String, revision: String },
}

impl ModelOrigin {
    /// Etiqueta corta para `llm status` y el audit.
    pub fn label(&self) -> String {
        match self {
            ModelOrigin::Path => "path".to_string(),
            ModelOrigin::Ollama { tag } => format!("ollama:{}", tag),
            ModelOrigin::HuggingFace { repo, revision } => {
                format!("hf:{}@{}", repo, short_rev(revision))
            }
        }
    }
}

/// Un modelo encontrado y listo para abrir.
#[derive(Clone, Debug)]
pub struct ResolvedModel {
    pub path: PathBuf,
    pub origin: ModelOrigin,
    /// SHA-256 de los pesos **si se conoce sin leerlos**. Ollama lo regala en el nombre del
    /// blob; para una ruta suelta o un snapshot de HF hay que calcularlo, y eso lo decide quien
    /// cargue (ver `Session`), no esta resolución.
    pub digest: Option<String>,
}

/// Dónde buscar. Se construye explícitamente para que se vea que el entorno se lee **una vez, en
/// el runtime**, y no en cualquier rincón del crate.
#[derive(Clone, Debug, Default)]
pub struct StoreConfig {
    pub ollama_dir: Option<PathBuf>,
    pub hf_hub_dir: Option<PathBuf>,
}

impl StoreConfig {
    /// Los directorios que la plataforma usa por convención, respetando `OLLAMA_MODELS` y
    /// `HF_HOME`. Es el único lugar del crate que mira el entorno, y mira **dónde está el cache**,
    /// nunca **qué modelo usar** — esa decisión sigue siendo del operador (§4.1).
    pub fn from_env() -> Self {
        let home = home_dir();
        let ollama_dir = std::env::var_os("OLLAMA_MODELS")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".ollama").join("models")));
        let hf_hub_dir = std::env::var_os("HF_HOME")
            .map(|h| PathBuf::from(h).join("hub"))
            .or_else(|| {
                home.as_ref().map(|h| h.join(".cache").join("huggingface").join("hub"))
            });
        StoreConfig { ollama_dir, hf_hub_dir }
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn short_rev(rev: &str) -> &str {
    if rev.len() > 8 {
        &rev[..8]
    } else {
        rev
    }
}

/// Encuentra el modelo que nombra `spec`, en el orden de la cabecera.
///
/// El error no dice sólo "no está": dice **dónde se buscó** y, si hay modelos disponibles,
/// sugiere los que sí están. Un error que no indica la salida es medio error.
pub fn resolve(spec: &str, cfg: &StoreConfig) -> Result<ResolvedModel, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("no se indicó ningún modelo".to_string());
    }

    // 1. Ruta a un archivo que existe.
    let as_path = Path::new(spec);
    if as_path.is_file() {
        return Ok(ResolvedModel {
            path: as_path.to_path_buf(),
            origin: ModelOrigin::Path,
            digest: None,
        });
    }

    // Si parece una ruta y no existe, decirlo en vez de buscarlo como nombre de modelo: quien
    // escribió `/models/qwen.gguf` quiere ese archivo, no uno parecido en otro lado.
    if looks_like_path(spec) {
        return Err(format!("el archivo del modelo no existe: {}", spec));
    }

    // 2. El cache de Ollama.
    if let Some(dir) = &cfg.ollama_dir {
        match ollama_lookup(dir, spec) {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => {}
            // Un manifest roto no debe tapar al cache de HF: se sigue buscando.
            Err(_) => {}
        }
    }

    // 3. El cache de Hugging Face.
    if let Some(dir) = &cfg.hf_hub_dir {
        if let Some(found) = hf_lookup(dir, spec) {
            return Ok(found);
        }
    }

    Err(not_found_message(spec, cfg))
}

fn looks_like_path(spec: &str) -> bool {
    spec.starts_with('/')
        || spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with('~')
        || spec.contains('\\')
        || spec.ends_with(".gguf")
        || (spec.len() > 2 && spec.as_bytes()[1] == b':') // C:\… en Windows
}

fn not_found_message(spec: &str, cfg: &StoreConfig) -> String {
    let mut msg = format!("no se encontró el modelo '{}'. Se buscó en:", spec);
    msg.push_str("\n  - como ruta a un archivo");
    match &cfg.ollama_dir {
        Some(d) => msg.push_str(&format!("\n  - el cache de Ollama ({})", d.display())),
        None => msg.push_str("\n  - el cache de Ollama (no se pudo ubicar el home)"),
    }
    match &cfg.hf_hub_dir {
        Some(d) => msg.push_str(&format!("\n  - el cache de Hugging Face ({})", d.display())),
        None => msg.push_str("\n  - el cache de Hugging Face (no se pudo ubicar el home)"),
    }
    let available = discover(cfg);
    if available.is_empty() {
        msg.push_str(
            "\nNo hay modelos locales. Bajá uno con `ollama pull <modelo>` o indicá la ruta a un .gguf.",
        );
    } else {
        msg.push_str("\nModelos locales disponibles:");
        for m in available.iter().take(12) {
            msg.push_str(&format!("\n  - {}", m.name));
        }
        if available.len() > 12 {
            msg.push_str(&format!("\n  … y {} más", available.len() - 12));
        }
    }
    msg
}

// =========================================================
// Ollama
// =========================================================

/// El mediaType de la capa que contiene los pesos en un manifest de Ollama. Las otras capas son
/// el template, los parámetros y la licencia — abrir la equivocada daría un error de parseo
/// confuso, así que se elige por tipo y no por tamaño.
const OLLAMA_MODEL_MEDIA_TYPE: &str = "application/vnd.ollama.image.model";

/// Busca `modelo:tag` en el cache de Ollama. `None` = no está; `Err` = está pero el manifest no
/// se pudo leer.
fn ollama_lookup(models_dir: &Path, spec: &str) -> Result<Option<ResolvedModel>, String> {
    let (name, tag) = split_tag(spec);
    let manifests = models_dir.join("manifests");
    if !manifests.is_dir() {
        return Ok(None);
    }
    let Some(manifest_path) = find_manifest(&manifests, &name, &tag) else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("no se pudo leer el manifest de Ollama: {}", e))?;
    let digest = model_layer_digest(&raw)
        .ok_or_else(|| format!("el manifest de Ollama no declara una capa de pesos: {}", spec))?;
    let blob = models_dir.join("blobs").join(digest.replace(':', "-"));
    if !blob.is_file() {
        return Err(format!(
            "el manifest de Ollama apunta a un blob que no está: {}",
            blob.display()
        ));
    }
    // El digest viene del nombre content-addressed: procedencia gratis.
    let sha = digest.strip_prefix("sha256:").map(|s| s.to_string());
    Ok(Some(ResolvedModel {
        path: blob,
        origin: ModelOrigin::Ollama { tag: format!("{}:{}", name, tag) },
        digest: sha,
    }))
}

/// `qwen3:8b` → `("qwen3", "8b")`; sin tag, Ollama asume `latest`.
fn split_tag(spec: &str) -> (String, String) {
    match spec.rsplit_once(':') {
        Some((n, t)) if !n.is_empty() && !t.is_empty() => (n.to_string(), t.to_string()),
        _ => (spec.to_string(), "latest".to_string()),
    }
}

/// Los manifests viven en `manifests/<registry>/<namespace>/<modelo>/<tag>`, y el usuario escribe
/// sólo `<modelo>:<tag>`. Se recorre el árbol buscando el primero cuyo nombre de carpeta coincida
/// — también acepta que el usuario haya escrito el nombre completo con namespace.
fn find_manifest(manifests_root: &Path, name: &str, tag: &str) -> Option<PathBuf> {
    let wanted: Vec<&str> = name.split('/').collect();
    let mut stack = vec![manifests_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // ¿El final de esta rama coincide con el nombre pedido?
                if ends_with_components(&p, &wanted) {
                    let candidate = p.join(tag);
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
                stack.push(p);
            }
        }
    }
    None
}

fn ends_with_components(path: &Path, wanted: &[&str]) -> bool {
    let parts: Vec<String> =
        path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    if wanted.len() > parts.len() {
        return false;
    }
    parts[parts.len() - wanted.len()..]
        .iter()
        .zip(wanted.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Saca el digest de la capa de pesos de un manifest OCI de Ollama.
///
/// Función PURA sobre el texto del manifest: se testea sin Ollama instalado, que es el patrón de
/// la casa para todo lo que parsea formato ajeno.
pub fn model_layer_digest(manifest_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let layers = v.get("layers")?.as_array()?;
    for layer in layers {
        if layer.get("mediaType")?.as_str()? == OLLAMA_MODEL_MEDIA_TYPE {
            return Some(layer.get("digest")?.as_str()?.to_string());
        }
    }
    None
}

// =========================================================
// Hugging Face
// =========================================================

/// Busca un repo en el cache de HF y devuelve el primer `.gguf` de su snapshot más reciente.
///
/// El layout es `models--<org>--<name>/snapshots/<rev>/…`. Si el spec trae `@revisión`, se usa
/// esa; si no, la única que haya (o la más reciente por mtime cuando hay varias).
fn hf_lookup(hub_dir: &Path, spec: &str) -> Option<ResolvedModel> {
    let (repo, wanted_rev) = match spec.split_once('@') {
        Some((r, rev)) => (r.to_string(), Some(rev.to_string())),
        None => (spec.to_string(), None),
    };
    if !repo.contains('/') {
        return None; // un repo de HF siempre es `org/nombre`
    }
    let dir = hub_dir.join(format!("models--{}", repo.replace('/', "--")));
    let snapshots = dir.join("snapshots");
    if !snapshots.is_dir() {
        return None;
    }
    let revision = match wanted_rev {
        Some(rev) if snapshots.join(&rev).is_dir() => rev,
        Some(_) => return None,
        None => newest_subdir(&snapshots)?,
    };
    let snap = snapshots.join(&revision);
    let weights = first_gguf(&snap)?;
    Some(ResolvedModel {
        path: weights,
        origin: ModelOrigin::HuggingFace { repo, revision },
        // El snapshot no es content-addressed: quien cargue decide si paga el hash.
        digest: None,
    })
}

fn newest_subdir(dir: &Path) -> Option<String> {
    let mut best: Option<(std::time::SystemTime, String)> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let mtime = e.metadata().ok().and_then(|m| m.modified().ok());
        let mtime = mtime.unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, name));
        }
    }
    best.map(|(_, n)| n)
}

fn first_gguf(dir: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x.eq_ignore_ascii_case("gguf")).unwrap_or(false))
        .collect();
    // Orden estable: dos corridas sobre el mismo cache eligen el mismo archivo.
    found.sort();
    found.into_iter().next()
}

// =========================================================
// Descubrimiento (para `llm status`)
// =========================================================

/// Un modelo que está en disco y se podría usar.
#[derive(Clone, Debug)]
pub struct DiscoveredModel {
    /// Cómo nombrarlo en la configuración: es literalmente lo que se pone en el knob del modelo.
    pub name: String,
    pub origin: ModelOrigin,
    pub path: PathBuf,
    pub digest: Option<String>,
}

/// Lista los modelos locales, para que `llm status` pueda decir "tenés esto, usá este nombre".
///
/// Nunca falla: un cache ausente o ilegible simplemente no aporta entradas. Listar es
/// informativo y no debe romper un diagnóstico.
pub fn discover(cfg: &StoreConfig) -> Vec<DiscoveredModel> {
    let mut out = Vec::new();
    if let Some(dir) = &cfg.ollama_dir {
        discover_ollama(dir, &mut out);
    }
    if let Some(dir) = &cfg.hf_hub_dir {
        discover_hf(dir, &mut out);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

fn discover_ollama(models_dir: &Path, out: &mut Vec<DiscoveredModel>) {
    let manifests = models_dir.join("manifests");
    let mut stack = vec![manifests.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            // Un archivo dentro de manifests es un tag; su carpeta padre es el modelo.
            let Some(tag) = p.file_name().map(|s| s.to_string_lossy().into_owned()) else {
                continue;
            };
            let Some(model) = p.parent().and_then(|d| d.file_name()) else { continue };
            let name = format!("{}:{}", model.to_string_lossy(), tag);
            let Ok(raw) = std::fs::read_to_string(&p) else { continue };
            let Some(digest) = model_layer_digest(&raw) else { continue };
            let blob = models_dir.join("blobs").join(digest.replace(':', "-"));
            if blob.is_file() {
                out.push(DiscoveredModel {
                    name: name.clone(),
                    origin: ModelOrigin::Ollama { tag: name },
                    path: blob,
                    digest: digest.strip_prefix("sha256:").map(|s| s.to_string()),
                });
            }
        }
    }
}

fn discover_hf(hub_dir: &Path, out: &mut Vec<DiscoveredModel>) {
    let Ok(entries) = std::fs::read_dir(hub_dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let Some(dir_name) = p.file_name().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        let Some(rest) = dir_name.strip_prefix("models--") else { continue };
        let repo = rest.replace("--", "/");
        let snapshots = p.join("snapshots");
        let Some(revision) = newest_subdir(&snapshots) else { continue };
        let Some(weights) = first_gguf(&snapshots.join(&revision)) else { continue };
        out.push(DiscoveredModel {
            name: repo.clone(),
            origin: ModelOrigin::HuggingFace { repo, revision },
            path: weights,
            digest: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- model_layer_digest: puro, sin Ollama instalado --

    #[test]
    fn picks_the_weights_layer_not_the_others() {
        let manifest = r#"{
            "schemaVersion": 2,
            "layers": [
                {"mediaType": "application/vnd.ollama.image.license", "digest": "sha256:lic"},
                {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:abc123"},
                {"mediaType": "application/vnd.ollama.image.template", "digest": "sha256:tpl"}
            ]
        }"#;
        assert_eq!(model_layer_digest(manifest).as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn manifest_without_weights_layer_is_none() {
        let manifest = r#"{"layers": [{"mediaType": "application/vnd.ollama.image.license",
                                       "digest": "sha256:lic"}]}"#;
        assert!(model_layer_digest(manifest).is_none());
    }

    #[test]
    fn malformed_manifest_is_none_not_panic() {
        assert!(model_layer_digest("no soy json").is_none());
        assert!(model_layer_digest("{}").is_none());
        assert!(model_layer_digest(r#"{"layers": "no soy un array"}"#).is_none());
    }

    // -- split_tag --

    #[test]
    fn tag_defaults_to_latest() {
        assert_eq!(split_tag("qwen3"), ("qwen3".to_string(), "latest".to_string()));
        assert_eq!(split_tag("qwen3:8b"), ("qwen3".to_string(), "8b".to_string()));
        assert_eq!(
            split_tag("library/qwen3:8b"),
            ("library/qwen3".to_string(), "8b".to_string())
        );
    }

    // -- looks_like_path: distinguir una ruta de un nombre de modelo --

    #[test]
    fn paths_and_model_names_are_told_apart() {
        assert!(looks_like_path("/models/qwen.gguf"));
        assert!(looks_like_path("./qwen.gguf"));
        assert!(looks_like_path("C:\\models\\qwen.gguf"));
        assert!(looks_like_path("~/models/qwen.gguf"));
        assert!(!looks_like_path("qwen3:8b"));
        assert!(!looks_like_path("convaiinnovations/laya"));
    }

    // -- resolve: una ruta inexistente NO se confunde con un nombre de modelo --

    #[test]
    fn missing_file_path_says_so_instead_of_searching_caches() {
        let cfg = StoreConfig::default();
        let err = resolve("/no/existe/modelo.gguf", &cfg).unwrap_err();
        assert!(err.contains("no existe"), "esperaba error de archivo, got: {}", err);
        assert!(!err.contains("Ollama"), "no debía buscarlo como nombre de modelo: {}", err);
    }

    #[test]
    fn empty_spec_is_rejected() {
        assert!(resolve("   ", &StoreConfig::default()).is_err());
    }

    /// El error de "no está" tiene que decir DÓNDE se buscó: es la mitad de su utilidad.
    #[test]
    fn not_found_lists_where_it_looked() {
        let cfg = StoreConfig {
            ollama_dir: Some(PathBuf::from("/tmp/no-existe-ollama")),
            hf_hub_dir: Some(PathBuf::from("/tmp/no-existe-hf")),
        };
        let err = resolve("qwen3:8b", &cfg).unwrap_err();
        assert!(err.contains("Ollama"), "{}", err);
        assert!(err.contains("Hugging Face"), "{}", err);
        assert!(err.contains("ollama pull"), "debe sugerir la salida: {}", err);
    }

    // -- resolve: una ruta que SÍ existe gana sobre todo lo demás --

    #[test]
    fn existing_file_resolves_as_path() {
        // Cualquier archivo que exista seguro: el propio ejecutable de test no siempre es
        // accesible, así que se usa un temporal.
        let dir = std::env::temp_dir().join("synsema-infer-store-test");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("modelo.gguf");
        std::fs::write(&f, b"no importa el contenido").unwrap();
        let r = resolve(f.to_str().unwrap(), &StoreConfig::default()).unwrap();
        assert_eq!(r.origin, ModelOrigin::Path);
        assert_eq!(r.path, f);
        assert!(r.digest.is_none(), "una ruta suelta no regala el digest");
        let _ = std::fs::remove_file(&f);
    }

    // -- origin labels --

    #[test]
    fn origin_labels_are_short_and_unambiguous() {
        assert_eq!(ModelOrigin::Path.label(), "path");
        assert_eq!(ModelOrigin::Ollama { tag: "qwen3:8b".into() }.label(), "ollama:qwen3:8b");
        let hf = ModelOrigin::HuggingFace {
            repo: "convaiinnovations/laya".into(),
            revision: "abcdef1234567890".into(),
        };
        assert_eq!(hf.label(), "hf:convaiinnovations/laya@abcdef12");
    }
}
