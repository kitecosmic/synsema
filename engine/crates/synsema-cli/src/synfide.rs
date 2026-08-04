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

/// ¿Qué hacer con un archivo del FRAMEWORK en un upgrade? Pura y testeable.
/// `recorded` = sha256 que quedó registrado al instalarlo (synfide/MANIFEST.json);
/// `on_disk` = sha256 de lo que hay ahora. Si difieren, el usuario lo EDITÓ:
/// jamás pisar trabajo en silencio — se conserva el suyo y la versión nueva
/// aterriza al lado como `<archivo>.new` (patrón conffiles de apt/pacman).
#[derive(PartialEq, Debug)]
enum UpgradeAction {
    Write,
    KeepUserVersion,
}

fn upgrade_action(recorded: Option<&str>, on_disk: Option<&str>, new_hash: &str) -> UpgradeAction {
    match (recorded, on_disk) {
        // No existe en disco → instalar normal (también repone un borrado).
        (_, None) => UpgradeAction::Write,
        // Instalado por nosotros y sin tocar desde entonces → actualizar.
        (Some(r), Some(d)) if r == d => UpgradeAction::Write,
        // Instalado por nosotros y EDITADO por el usuario → conservar el suyo.
        (Some(_), Some(_)) => UpgradeAction::KeepUserVersion,
        // SIN MANIFEST (instalación pre-manifest, o un directorio `synfide/` que ya
        // existía por otra razón — pasó de verdad: un scaffold corrido en un cwd cuyo
        // `synfide/` era OTRA cosa). Contenido de origen desconocido: si ya es
        // byte-idéntico al release, escribir es un no-op seguro; si difiere, JAMÁS
        // pisarlo — conservar y dejar el release al lado como `.new`.
        (None, Some(d)) => {
            if d == new_hash {
                UpgradeAction::Write
            } else {
                UpgradeAction::KeepUserVersion
            }
        }
    }
}

/// Instala/actualiza Synfide en `base`. Devuelve mensajes ya impresos; `Err` = nada
/// escrito (o error de escritura puntual, informado con la ruta).
pub(crate) fn install(base: &Path) -> Result<(), String> {
    let tag = latest_tag()?;
    let version_path = base.join("synfide").join("VERSION");
    let manifest_path = base.join("synfide").join("MANIFEST.json");
    let installed = std::fs::read_to_string(&version_path)
        .ok()
        .map(|s| s.trim().to_string());
    if installed.as_deref() == Some(tag.as_str()) {
        println!("init: synfide {} ya está instalado y al día.", tag);
        return Ok(());
    }
    // Hashes registrados en la instalación ANTERIOR (dest → sha256). Con esto un
    // archivo del framework editado por el usuario se detecta y NO se pisa.
    let recorded: serde_json::Value = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    let fetched = fetch_all(&tag)?; // todo verificado ANTES de escribir
    let upgrading = installed.is_some();
    let mut kept: Vec<String> = Vec::new();
    let mut new_hashes = serde_json::Map::new();
    for f in &fetched {
        let path = base.join(&f.dest);
        // TODO archivo del manifest queda registrado (dest → sha256 del release):
        // así el próximo upgrade puede distinguir "sin tocar" de "editado" también
        // para los archivos del USUARIO (app.syn/console.syn/tests), y actualizar
        // los que siguen prístinos — sin el registro, un fix a la consola jamás
        // llegaba a proyectos existentes.
        let new_hash = sha256_hex(&f.bytes);
        new_hashes.insert(f.dest.clone(), serde_json::Value::String(new_hash.clone()));
        let disk_hash = std::fs::read(&path).ok().map(|b| sha256_hex(&b));
        let rec = recorded.get(&f.dest).and_then(|v| v.as_str());
        if !f.framework_owned {
            match (disk_hash.as_deref(), rec) {
                (None, _) => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                    }
                    std::fs::write(&path, &f.bytes)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    println!("init: {} creado", path.display());
                }
                // Prístino (idéntico a lo que el scaffold instaló) → recibir la
                // versión nueva es seguro: todavía no es "su" código.
                (Some(d), Some(r)) if d == r && d != new_hash => {
                    std::fs::write(&path, &f.bytes)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    println!("init: {} actualizado (estaba sin ediciones tuyas)", path.display());
                }
                (Some(d), Some(r)) if d == r => {
                    println!("init: {} al día", path.display());
                }
                // Editado, o sin registro previo con el que verificar → es SUYO.
                _ => println!("init: {} ya existe — no se toca", path.display()),
            }
            continue;
        }
        match upgrade_action(rec, disk_hash.as_deref(), &new_hash) {
            UpgradeAction::Write => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                }
                std::fs::write(&path, &f.bytes)
                    .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                println!(
                    "init: {} {}",
                    path.display(),
                    if upgrading { "actualizado" } else { "creado" }
                );
            }
            UpgradeAction::KeepUserVersion => {
                let new_path = base.join(format!("{}.new", f.dest));
                std::fs::write(&new_path, &f.bytes)
                    .map_err(|e| format!("cannot write {}: {}", new_path.display(), e))?;
                // Sin registro previo NO podemos afirmar que el usuario lo editó
                // (instalación con un binario pre-manifest, o un synfide/ que ya
                // existía): el mensaje dice la verdad — "no puedo verificarlo" —
                // en vez de acusar una edición que quizás nunca ocurrió.
                if rec.is_some() {
                    println!(
                        "init: ⚠ {} fue MODIFICADO por vos — se conserva TU versión; la nueva quedó en {}",
                        path.display(),
                        new_path.display()
                    );
                } else {
                    println!(
                        "init: ⚠ {} difiere del release y no hay registro previo para verificar si lo editaste — se conserva por las dudas; la nueva quedó en {}. Si NO lo tocaste: reemplazalo con el .new (o borralo y re-corré init --synfide)",
                        path.display(),
                        new_path.display()
                    );
                }
                kept.push(f.dest.clone());
            }
        }
    }
    if let Some(parent) = version_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&version_path, format!("{}\n", tag))
        .map_err(|e| format!("cannot write {}: {}", version_path.display(), e))?;
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&serde_json::Value::Object(new_hashes))
            .unwrap_or_else(|_| "{}".to_string()),
    )
    .map_err(|e| format!("cannot write {}: {}", manifest_path.display(), e))?;
    match installed {
        Some(old) => println!("init: synfide {} → {} (framework actualizado; tus archivos no se tocaron)", old, tag),
        None => println!("init: synfide {} instalado.", tag),
    }
    if !kept.is_empty() {
        println!();
        println!("⚠ Archivos del framework con EDICIONES TUYAS (conservados; el release nuevo quedó como .new):");
        for k in &kept {
            println!("    {}", k);
        }
        println!("  Para mantener cambios propios a un paquete, movelo a TU carpeta (p.ej. mylib/) e importá esa —");
        println!("  los upgrades jamás tocan tus carpetas. Si ya no querés tu versión: borrala y re-corré init --synfide.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // La única lógica pura y peligrosa del módulo: la validación de rutas del
    // manifest (viaja por la red — un dest malicioso no puede escribir fuera del
    // proyecto). El resto es red + escritura, cubierto por la sonda E2E del release.
    // La regla de upgrade que protege trabajo del usuario: un archivo del
    // framework EDITADO localmente (hash de disco ≠ hash registrado) jamás se
    // pisa — se conserva y el nuevo va a `.new`. Borrado → se repone; sin
    // MANIFEST (instalación pre-manifest) → comportamiento histórico.
    #[test]
    fn user_modified_framework_files_are_never_clobbered() {
        use super::UpgradeAction::*;
        assert_eq!(upgrade_action(Some("aaa"), Some("aaa"), "nnn"), Write, "sin tocar → actualiza");
        assert_eq!(
            upgrade_action(Some("aaa"), Some("bbb"), "nnn"),
            KeepUserVersion,
            "editado → se conserva el del usuario"
        );
        assert_eq!(upgrade_action(Some("aaa"), None, "nnn"), Write, "borrado → se repone");
        assert_eq!(upgrade_action(None, None, "nnn"), Write, "instalación nueva");
        // Sin MANIFEST y con contenido de origen desconocido: byte-idéntico al
        // release → no-op seguro; distinto → JAMÁS pisar (el caso real: un
        // `synfide/` preexistente que era OTRA cosa en ese cwd).
        assert_eq!(upgrade_action(None, Some("nnn"), "nnn"), Write, "ya idéntico al release");
        assert_eq!(
            upgrade_action(None, Some("bbb"), "nnn"),
            KeepUserVersion,
            "desconocido y distinto → conservar + .new"
        );
    }

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
