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
const API_RELEASES: &str = "https://api.github.com/repos/kitecosmic/synfide/releases?per_page=30";
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

/// Todo sha256 que CADA archivo tuvo en algún release del framework (`dest` → hashes).
///
/// Es la "huella de fábrica". Sin ella, la única prueba de que un archivo no fue
/// editado era el `MANIFEST.json` de la instalación anterior, y eso falla justo en
/// los casos reales: proyectos instalados antes de que el manifest existiera, o que
/// vienen arrastrando archivos de varias versiones distintas porque los upgrades
/// nunca se los actualizaron. El resultado era acusar de "editado" a un archivo
/// intacto y congelarlo para siempre. Coincidir con CUALQUIER release es prueba
/// suficiente de que el contenido salió de fábrica: nadie escribe a mano, byte por
/// byte, un archivo idéntico a un release histórico.
///
/// Sólo se consulta cuando hace falta (algún archivo no matchea el registro), y una
/// falla de red degrada a "no pude verificarlo" — nunca a pisar trabajo ajeno.
fn factory_hashes() -> std::collections::HashMap<String, Vec<String>> {
    let mut out: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let r = http_request("GET", API_RELEASES, Some(&gh_headers()), None, None, 30);
    if r.status == 0 || !r.ok {
        return out;
    }
    let Ok(releases) = serde_json::from_str::<serde_json::Value>(&r.body) else { return out };
    let Some(list) = releases.as_array() else { return out };
    for rel in list {
        let Some(tag) = rel.get("tag_name").and_then(|t| t.as_str()) else { continue };
        let url = format!("{}/{}/manifest.json", RAW_BASE, tag);
        let m = http_request("GET", &url, Some(&gh_headers()), None, None, 30);
        if m.status == 0 || !m.ok {
            continue; // un tag sin manifest no invalida al resto
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&m.body) else { continue };
        let Some(files) = v.get("files").and_then(|f| f.as_array()) else { continue };
        for f in files {
            let (Some(dest), Some(sha)) = (
                f.get("dest").and_then(|d| d.as_str()),
                f.get("sha256").and_then(|s| s.as_str()),
            ) else {
                continue;
            };
            let e = out.entry(dest.to_string()).or_default();
            let sha = sha.to_lowercase();
            if !e.contains(&sha) {
                e.push(sha);
            }
        }
    }
    out
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
#[derive(PartialEq, Debug, Clone, Copy)]
enum UpgradeAction {
    Write,
    KeepUserVersion,
}

/// `factory` = el contenido en disco coincide con lo que ALGÚN release del framework
/// publicó para ese archivo (ver [`factory_hashes`]). Es la prueba de procedencia que
/// el registro por sí solo no da: un proyecto que arrastra archivos de varias
/// versiones —porque los upgrades anteriores no se los actualizaban— tiene el
/// registro desfasado y sin embargo NO editó nada.
fn upgrade_action(
    recorded: Option<&str>,
    on_disk: Option<&str>,
    new_hash: &str,
    factory: bool,
) -> UpgradeAction {
    match (recorded, on_disk) {
        // No existe en disco → instalar normal (también repone un borrado).
        (_, None) => UpgradeAction::Write,
        // Instalado por nosotros y sin tocar desde entonces → actualizar.
        (Some(r), Some(d)) if r == d => UpgradeAction::Write,
        // Ya es byte-idéntico al release nuevo → escribir es un no-op seguro.
        (_, Some(d)) if d == new_hash => UpgradeAction::Write,
        // El registro no coincide, PERO el contenido salió de fábrica (matchea un
        // release histórico): no hay trabajo del usuario que proteger → actualizar.
        // Éste es el caso que antes se acusaba de "editado" y quedaba congelado.
        (_, Some(_)) if factory => UpgradeAction::Write,
        // Difiere del registro y de todo release conocido → es del usuario, o de
        // origen desconocido (instalación pre-manifest, o un `synfide/` que ya
        // existía y era otra cosa). JAMÁS pisarlo.
        (_, Some(_)) => UpgradeAction::KeepUserVersion,
    }
}

/// La línea que se imprime cuando un archivo se CONSERVA. Dos situaciones muy
/// distintas y el mensaje no las mezcla: o se pudo comprobar la procedencia y el
/// contenido no salió de ningún release (es del usuario), o no se pudo comprobar
/// (sin red). En ninguno de los dos casos se le encarga trabajo al usuario: su
/// archivo queda intacto y el del release al lado. Decirle "si no lo tocaste,
/// reemplazalo vos" es pedirle que resuelva a mano lo que la herramienta no supo.
fn kept_line(provenance_known: bool, path: &Path, new_path: &Path) -> String {
    if provenance_known {
        format!(
            "{} tiene cambios tuyos — se conserva; el del release quedó en {}",
            path.display(),
            new_path.display()
        )
    } else {
        format!(
            "{} no se pudo verificar (sin conexión para consultar los releases) — se conserva intacto; el del release quedó en {}",
            path.display(),
            new_path.display()
        )
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
    // Hashes registrados en la instalación ANTERIOR (dest → sha256). Con esto un
    // archivo del framework editado por el usuario se detecta y NO se pisa.
    let recorded: serde_json::Value = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    // Mismo tag instalado NO garantiza que el proyecto esté sano: un archivo borrado
    // por accidente, o uno que quedó de una versión anterior porque un upgrade viejo
    // no lo actualizaba, sobreviven al chequeo de versión. Antes se retornaba acá y
    // esos proyectos no tenían forma de repararse — el comando decía "al día" sobre
    // un scaffold incompleto. Ahora la versión sólo evita la descarga cuando el disco
    // COINCIDE con lo registrado; si algo no cuadra, se sigue al camino completo.
    if installed.as_deref() == Some(tag.as_str()) {
        let intact = recorded.as_object().is_some_and(|m| {
            !m.is_empty()
                && m.iter().all(|(dest, sha)| {
                    let want = sha.as_str().unwrap_or_default();
                    std::fs::read(base.join(dest))
                        .map(|b| sha256_hex(&b) == want)
                        .unwrap_or(false)
                })
        });
        if intact {
            println!("init: synfide {} ya está instalado y al día.", tag);
            return Ok(());
        }
        println!("init: synfide {} instalado, pero hay archivos que no coinciden con lo registrado — verificando…", tag);
    }
    let fetched = fetch_all(&tag)?; // todo verificado ANTES de escribir
    let upgrading = installed.is_some();
    let mut kept: Vec<String> = Vec::new();
    let mut written = 0usize;
    let mut new_hashes = serde_json::Map::new();
    // Estado del disco ANTES de escribir nada, y qué archivos no matchean el
    // registro. Sólo si hay alguno se paga la consulta de procedencia (§factory).
    let disk: Vec<Option<String>> =
        fetched.iter().map(|f| std::fs::read(base.join(&f.dest)).ok().map(|b| sha256_hex(&b))).collect();
    let needs_provenance = fetched.iter().zip(&disk).any(|(f, d)| {
        let rec = recorded.get(&f.dest).and_then(|v| v.as_str());
        match d.as_deref() {
            None => false,
            Some(d) => Some(d) != rec && d != sha256_hex(&f.bytes),
        }
    });
    let factory = if needs_provenance && upgrading {
        factory_hashes()
    } else {
        std::collections::HashMap::new()
    };
    // ¿Se pudo consultar la procedencia? Si hacía falta y volvió vacía, fue la red.
    // El mensaje lo dice en vez de insinuar que el usuario editó algo.
    let provenance_known = !needs_provenance || !upgrading || !factory.is_empty();
    for (f, disk_hash) in fetched.iter().zip(&disk) {
        let path = base.join(&f.dest);
        let new_hash = sha256_hex(&f.bytes);
        let rec = recorded.get(&f.dest).and_then(|v| v.as_str());
        let is_factory = disk_hash
            .as_deref()
            .map(|d| factory.get(&f.dest).is_some_and(|hs| hs.iter().any(|h| h == d)))
            .unwrap_or(false);
        let action = upgrade_action(rec, disk_hash.as_deref(), &new_hash, is_factory);
        // El registro debe describir lo que QUEDA en disco, no lo que traía el
        // release: si se conserva la versión del usuario, anotar el hash nuevo haría
        // que el próximo upgrade viera una diferencia inexistente y lo acusara de
        // editado para siempre. Se preserva el registro anterior (o ninguno).
        match action {
            UpgradeAction::Write => {
                new_hashes.insert(f.dest.clone(), serde_json::Value::String(new_hash.clone()));
            }
            UpgradeAction::KeepUserVersion => {
                if let Some(r) = rec {
                    new_hashes.insert(f.dest.clone(), serde_json::Value::String(r.to_string()));
                }
            }
        }
        // Los archivos del USUARIO (app.syn, console.syn, tests…) siguen la misma
        // regla que los del framework: se actualizan mientras sigan de fábrica y se
        // conservan apenas tengan una edición. Lo único distinto es el tono del
        // mensaje: son suyos por contrato, no del framework.
        if !f.framework_owned {
            match action {
                UpgradeAction::Write if disk_hash.is_none() => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                    }
                    std::fs::write(&path, &f.bytes)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    println!("init: {} creado", path.display());
                    written += 1;
                }
                UpgradeAction::Write if disk_hash.as_deref() == Some(new_hash.as_str()) => {
                    println!("init: {} ya está al día", path.display());
                }
                UpgradeAction::Write => {
                    std::fs::write(&path, &f.bytes)
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    println!("init: {} actualizado (estaba sin ediciones tuyas)", path.display());
                    written += 1;
                }
                UpgradeAction::KeepUserVersion => {
                    let new_path = base.join(format!("{}.new", f.dest));
                    std::fs::write(&new_path, &f.bytes)
                        .map_err(|e| format!("cannot write {}: {}", new_path.display(), e))?;
                    println!("init: {}", kept_line(provenance_known, &path, &new_path));
                    kept.push(f.dest.clone());
                }
            }
            continue;
        }
        match action {
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
                written += 1;
            }
            UpgradeAction::KeepUserVersion => {
                let new_path = base.join(format!("{}.new", f.dest));
                std::fs::write(&new_path, &f.bytes)
                    .map_err(|e| format!("cannot write {}: {}", new_path.display(), e))?;
                println!("init: {}", kept_line(provenance_known, &path, &new_path));
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
    // El resumen dice lo que PASÓ, no una fórmula: prometer "tus archivos no se
    // tocaron" cuando sí se actualizaron (porque seguían de fábrica) es la clase de
    // mensaje que hace desconfiar de todo lo demás.
    match installed {
        Some(old) if old != tag => println!("init: synfide {} → {}", old, tag),
        Some(_) if written > 0 => {
            println!("init: synfide {} verificado ({} archivo(s) repuestos al release).", tag, written)
        }
        Some(_) => println!("init: synfide {} verificado.", tag),
        None => println!("init: synfide {} instalado.", tag),
    }
    if kept.is_empty() {
        println!("      Todo lo que había seguía siendo de fábrica: nada tuyo se pisó.");
    }
    if !kept.is_empty() {
        println!();
        println!("⚠ Archivos con cambios que no salieron de ningún release (conservados; el del release quedó como .new):");
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
        // (registro, disco, release nuevo, ¿el disco salió de fábrica?)
        assert_eq!(upgrade_action(Some("aaa"), Some("aaa"), "nnn", false), Write, "sin tocar → actualiza");
        assert_eq!(
            upgrade_action(Some("aaa"), Some("bbb"), "nnn", false),
            KeepUserVersion,
            "editado → se conserva el del usuario"
        );
        assert_eq!(upgrade_action(Some("aaa"), None, "nnn", false), Write, "borrado → se repone");
        assert_eq!(upgrade_action(None, None, "nnn", false), Write, "instalación nueva");
        assert_eq!(upgrade_action(None, Some("nnn"), "nnn", false), Write, "ya idéntico al release");
        assert_eq!(
            upgrade_action(None, Some("bbb"), "nnn", false),
            KeepUserVersion,
            "desconocido y distinto → conservar + .new"
        );
        // Procedencia: el disco no coincide con el registro, pero SÍ con un release
        // histórico. Es el caso real que rompía — un proyecto que arrastra archivos
        // de varias versiones porque los upgrades nunca se los actualizaron. No hay
        // trabajo del usuario que proteger: se actualiza.
        assert_eq!(
            upgrade_action(Some("aaa"), Some("v034"), "nnn", true),
            Write,
            "de fábrica pero de otra versión → actualiza"
        );
        assert_eq!(
            upgrade_action(None, Some("v032"), "nnn", true),
            Write,
            "sin registro pero de fábrica → actualiza"
        );
        // La prueba de procedencia NO puede volverse una licencia para pisar: si el
        // contenido no matchea ningún release, sigue siendo intocable.
        assert_eq!(
            upgrade_action(Some("aaa"), Some("mío"), "nnn", false),
            KeepUserVersion,
            "editado de verdad → jamás se pisa, aunque haya red"
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
