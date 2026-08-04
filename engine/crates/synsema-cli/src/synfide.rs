//! `synsema init --synfide` — instala el framework Synfide en el proyecto.
//!
//! FRAMEWORK, no template: la instalación es VERSIONADA (el último release de
//! kitecosmic/synfide), cada archivo se verifica contra el sha256 declarado en el
//! `manifest.json` de ese tag, y `synfide/VERSION` deja registrado qué versión quedó
//! vendoreada. Re-ejecutar el comando con un release más nuevo ACTUALIZA los archivos
//! del framework (los del directorio `synfide/`, que son del framework); los archivos
//! del usuario (`app.syn`, `.env.example`, …) JAMÁS se pisan — contrato de `init`.
//!
//! Disciplina de red (espejo de `synsema update`): primero se descarga y verifica
//! TODO, recién después se escribe — una falla de red o de checksum no deja un
//! scaffold a medias. Reusa el cliente HTTP interno y los helpers de update.rs; cero
//! dependencias nuevas.

use std::path::Path;

use synsema_stdlib::http::http_request;

use crate::update::{download, gh_headers, sha256_hex};

const API_LATEST: &str = "https://api.github.com/repos/kitecosmic/synfide/releases/latest";
const RAW_BASE: &str = "https://raw.githubusercontent.com/kitecosmic/synfide";

/// Un archivo del manifest ya descargado y verificado, listo para escribir.
struct Fetched {
    dest: String,
    bytes: Vec<u8>,
    /// Los archivos bajo `synfide/` son del FRAMEWORK: se actualizan al re-instalar.
    /// El resto (`app.syn`) es del usuario: solo se crea si no existe.
    framework_owned: bool,
}

/// Tag del último release de Synfide.
fn latest_tag() -> Result<String, String> {
    let r = http_request("GET", API_LATEST, Some(&gh_headers()), None, None, 30);
    if r.status == 0 {
        return Err(r.error.unwrap_or_else(|| "request failed".to_string()));
    }
    if !r.ok {
        return Err(format!("GitHub API returned HTTP {}", r.status));
    }
    let v: serde_json::Value =
        serde_json::from_str(&r.body).map_err(|e| format!("invalid JSON from GitHub: {}", e))?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "release without tag_name".to_string())
}

/// Un `dest` del manifest es válido solo si es relativo, sin `..` ni raro — el
/// manifest viaja por la red y no se le confía la forma (defensa supply-chain).
fn dest_is_safe(dest: &str) -> bool {
    !dest.is_empty()
        && !dest.starts_with('/')
        && !dest.contains(':')
        && !dest.contains('\\')
        && !dest.split('/').any(|seg| seg == ".." || seg.is_empty())
}

/// Descarga el manifest del tag y luego CADA archivo, verificando su sha256. Todo o
/// nada: cualquier falla aborta sin haber escrito un byte.
fn fetch_all(tag: &str) -> Result<Vec<Fetched>, String> {
    let manifest_url = format!("{}/{}/manifest.json", RAW_BASE, tag);
    let manifest_bytes = download(&manifest_url, 5)
        .map_err(|e| format!("cannot download manifest.json at {}: {}", tag, e))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("invalid manifest.json: {}", e))?;
    let files = manifest
        .get("files")
        .and_then(|f| f.as_array())
        .ok_or_else(|| "manifest.json without a files list".to_string())?;
    if files.is_empty() {
        return Err("manifest.json lists no files".to_string());
    }
    let mut out = Vec::new();
    for f in files {
        let src = f
            .get("src")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "manifest entry without src".to_string())?;
        let dest = f
            .get("dest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "manifest entry without dest".to_string())?;
        let want = f
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("manifest entry '{}' without sha256", dest))?;
        if !dest_is_safe(dest) {
            return Err(format!("manifest dest '{}' is not a safe relative path", dest));
        }
        let url = format!("{}/{}/{}", RAW_BASE, tag, src);
        let bytes =
            download(&url, 5).map_err(|e| format!("cannot download {}: {}", src, e))?;
        let got = sha256_hex(&bytes);
        if got != want.to_lowercase() {
            return Err(format!(
                "sha256 mismatch for {} (expected {}, got {}) — refusing to install",
                dest, want, got
            ));
        }
        out.push(Fetched {
            dest: dest.to_string(),
            bytes,
            framework_owned: dest.starts_with("synfide/"),
        });
    }
    Ok(out)
}

/// Instala/actualiza Synfide en `base`. Devuelve mensajes ya impresos; `Err` = nada
/// escrito (o error de escritura puntual, informado con la ruta).
pub(crate) fn install(base: &Path) -> Result<(), String> {
    let tag = latest_tag()?;
    let version_path = base.join("synfide").join("VERSION");
    let installed = std::fs::read_to_string(&version_path)
        .ok()
        .map(|s| s.trim().to_string());
    if installed.as_deref() == Some(tag.as_str()) {
        println!("init: synfide {} ya está instalado y al día.", tag);
        return Ok(());
    }
    let fetched = fetch_all(&tag)?; // todo verificado ANTES de escribir
    let upgrading = installed.is_some();
    for f in &fetched {
        let path = base.join(&f.dest);
        if !f.framework_owned && path.exists() {
            println!("init: {} ya existe — no se toca", path.display());
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        std::fs::write(&path, &f.bytes)
            .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        println!(
            "init: {} {}",
            path.display(),
            if f.framework_owned && upgrading { "actualizado" } else { "creado" }
        );
    }
    if let Some(parent) = version_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&version_path, format!("{}\n", tag))
        .map_err(|e| format!("cannot write {}: {}", version_path.display(), e))?;
    match installed {
        Some(old) => println!("init: synfide {} → {} (los archivos del framework se actualizaron; los tuyos no se tocaron)", old, tag),
        None => println!("init: synfide {} instalado.", tag),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // La única lógica pura y peligrosa del módulo: la validación de rutas del
    // manifest (viaja por la red — un dest malicioso no puede escribir fuera del
    // proyecto). El resto es red + escritura, cubierto por la sonda E2E del release.
    #[test]
    fn manifest_dest_paths_are_validated() {
        for ok in ["app.syn", "synfide/store.syn", "a/b/c.syn"] {
            assert!(dest_is_safe(ok), "debería ser válido: {}", ok);
        }
        for bad in [
            "",
            "/etc/passwd",
            "../fuera.syn",
            "synfide/../../fuera.syn",
            "C:/x.syn",
            "a\\b.syn",
            "a//b.syn",
        ] {
            assert!(!dest_is_safe(bad), "debería rechazarse: {}", bad);
        }
    }
}
