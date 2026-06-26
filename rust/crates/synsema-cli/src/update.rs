//! `synsema update` + aviso de versión desactualizada.
//!
//! La versión del binario es la del **release** (el tag que lo compiló), no el commit
//! de main: `release.yml` setea `SYNSEMA_VERSION=<tag>` al build. Tanto el update como
//! el aviso se anclan a los GitHub Releases del repo — el sello de "esto funciona".
//!
//! Reusa el cliente HTTP/HTTPS interno (`synsema_stdlib::http`, rustls+ring) — sin
//! dependencias nuevas más allá de `sha2` (ya en el workspace, para verificar el asset).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use synsema_stdlib::http::{http_request, http_request_bytes};

const API_LATEST: &str = "https://api.github.com/repos/kitecosmic/synsema/releases/latest";

/// Versión del binario. Oficial = el tag del release (`SYNSEMA_VERSION`, lo setea
/// `release.yml`). Build desde fuente = `CARGO_PKG_VERSION` con sufijo `-dev`, para no
/// confundirse con un release publicado.
pub fn current_version() -> String {
    match option_env!("SYNSEMA_VERSION") {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => format!("v{}-dev", env!("CARGO_PKG_VERSION")),
    }
}

/// Headers para la API de GitHub. El `User-Agent` es **obligatorio** (sin él, 403).
fn gh_headers() -> Vec<(String, String)> {
    vec![
        ("User-Agent".to_string(), format!("synsema-cli/{}", current_version())),
        ("Accept".to_string(), "application/vnd.github+json".to_string()),
    ]
}

/// Nombre del asset del release para esta plataforma. DEBE coincidir con los `asset`
/// de `.github/workflows/release.yml`.
fn asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("synsema-linux-x86_64"),
        ("macos", "aarch64") => Some("synsema-macos-aarch64"),
        ("macos", "x86_64") => Some("synsema-macos-x86_64"),
        ("windows", "x86_64") => Some("synsema-windows-x86_64.exe"),
        _ => None,
    }
}

/// (mayor, menor, patch) de un tag tipo `v0.3.2`, `0.3.2` o `0.3.2-dev`. `None` si no
/// parsea (se ignora en las comparaciones, fail-safe).
fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let t = tag.trim().trim_start_matches('v');
    let core = t.split('-').next().unwrap_or(t); // descarta -dev / -rc.N
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

/// ¿`latest` es estrictamente mayor que `current`?
fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Consulta el último release y devuelve el JSON parseado.
fn latest_release_json() -> Result<serde_json::Value, String> {
    let r = http_request("GET", API_LATEST, Some(&gh_headers()), None, None, 30);
    if r.status == 0 {
        return Err(r.error.unwrap_or_else(|| "request failed".to_string()));
    }
    if !r.ok {
        return Err(format!("GitHub API returned HTTP {}", r.status));
    }
    serde_json::from_str(&r.body).map_err(|e| format!("invalid JSON from GitHub: {}", e))
}

/// Busca la `browser_download_url` de un asset por nombre exacto en el JSON del release.
fn asset_url(json: &serde_json::Value, name: &str) -> Option<String> {
    json.get("assets")?.as_array()?.iter().find_map(|a| {
        if a.get("name")?.as_str()? == name {
            a.get("browser_download_url")?.as_str().map(|s| s.to_string())
        } else {
            None
        }
    })
}

/// GET siguiendo redirects (GitHub redirige los assets a otro host), devolviendo bytes.
fn download(url: &str, max_redirects: u32) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();
    for _ in 0..=max_redirects {
        let (status, body, headers) = http_request_bytes("GET", &current, Some(&gh_headers()), 120)?;
        if (300..400).contains(&status) {
            current = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| "redirect without Location header".to_string())?;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {}", status));
        }
        return Ok(body);
    }
    Err("too many redirects".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// `synsema update`: descarga el último release para esta plataforma, verifica su
/// sha256 y reemplaza el binario en ejecución.
pub fn cmd_update() -> ExitCode {
    let current = current_version();
    println!("Versión actual: {}", current);

    let json = match latest_release_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("synsema update: no se pudo consultar el último release: {}", e);
            return ExitCode::from(1);
        }
    };
    let tag = json.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
    if tag.is_empty() {
        eprintln!("synsema update: la respuesta de GitHub no trae 'tag_name'");
        return ExitCode::from(1);
    }
    if !is_newer(tag, &current) {
        println!("Ya estás en la última versión ({}).", current);
        return ExitCode::SUCCESS;
    }
    println!("Nueva versión: {} — descargando…", tag);

    let asset = match asset_name() {
        Some(a) => a,
        None => {
            eprintln!(
                "synsema update: no hay binario precompilado para {}-{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            return ExitCode::from(1);
        }
    };
    let bin_url = match asset_url(&json, asset) {
        Some(u) => u,
        None => {
            eprintln!("synsema update: el release {} no incluye el asset '{}'", tag, asset);
            return ExitCode::from(1);
        }
    };

    let bytes = match download(&bin_url, 5) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("synsema update: falló la descarga: {}", e);
            return ExitCode::from(1);
        }
    };

    // Verificación de integridad: si el release publica el `.sha256`, debe coincidir.
    if let Some(sha_url) = asset_url(&json, &format!("{}.sha256", asset)) {
        match download(&sha_url, 5) {
            Ok(sb) => {
                let expected =
                    String::from_utf8_lossy(&sb).split_whitespace().next().unwrap_or("").to_lowercase();
                let got = sha256_hex(&bytes);
                if !expected.is_empty() && expected != got {
                    eprintln!(
                        "synsema update: sha256 no coincide (esperado {}, obtenido {}). Abortado por seguridad.",
                        expected, got
                    );
                    return ExitCode::from(1);
                }
            }
            Err(e) => eprintln!("synsema update: aviso — no se pudo verificar el sha256 ({})", e),
        }
    }

    match replace_running_exe(&bytes) {
        Ok(()) => {
            println!("✓ Actualizado a {}. Volvé a ejecutar synsema.", tag);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("synsema update: no se pudo reemplazar el binario: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Reemplaza el ejecutable en ejecución de forma cross-platform. En Unix se puede
/// renombrar sobre el binario corriendo; en Windows no se puede sobrescribir un .exe en
/// uso, pero sí renombrarlo: movemos el actual a `.old` y ponemos el nuevo en su lugar.
fn replace_running_exe(new_bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or_else(|| "no se pudo determinar el directorio del binario".to_string())?;
    // Temp en el MISMO directorio para que el rename sea atómico (mismo filesystem).
    let tmp = dir.join(".synsema-update.tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(new_bytes).map_err(|e| e.to_string())?;
        f.flush().map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }

    #[cfg(windows)]
    {
        let old = dir.join("synsema.exe.old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&exe, &old).map_err(|e| format!("no se pudo mover el binario actual: {}", e))?;
        if let Err(e) = std::fs::rename(&tmp, &exe) {
            let _ = std::fs::rename(&old, &exe); // rollback
            return Err(format!("no se pudo instalar el nuevo binario: {}", e));
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(&tmp, &exe).map_err(|e| format!("no se pudo instalar el nuevo binario: {}", e))?;
    }
    Ok(())
}

// --- Aviso no intrusivo de versión desactualizada (comandos interactivos) ---

fn cache_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(".synsema").join("update-check")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_cache(p: &Path) -> Option<(u64, String)> {
    let s = std::fs::read_to_string(p).ok()?;
    let mut it = s.trim().splitn(2, '\t');
    let ts = it.next()?.parse().ok()?;
    let tag = it.next()?.to_string();
    Some((ts, tag))
}

fn write_cache(p: &Path, ts: u64, tag: &str) {
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, format!("{}\t{}", ts, tag));
}

/// Si hay una versión más nueva, devuelve `Some(tag)`. Cacheado 24 h en disco;
/// desactivable con `SYNSEMA_NO_UPDATE_CHECK`. Nunca falla ruidosamente (red caída →
/// `None`). No se usa en `run`/`serve`/`test` para no meter red/latencia en producción.
pub fn check_for_update() -> Option<String> {
    if std::env::var_os("SYNSEMA_NO_UPDATE_CHECK").is_some() {
        return None;
    }
    let current = current_version();
    parse_semver(&current)?; // builds `-dev` sin semver válido no avisan

    let cache = cache_path();
    let now = now_secs();
    let latest_tag = match read_cache(&cache) {
        Some((ts, tag)) if now.saturating_sub(ts) < 24 * 3600 => tag,
        previous => match latest_release_json()
            .ok()
            .and_then(|j| j.get("tag_name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        {
            Some(tag) => {
                write_cache(&cache, now, &tag);
                tag
            }
            None => previous.map(|(_, t)| t).unwrap_or_default(),
        },
    };

    if !latest_tag.is_empty() && is_newer(&latest_tag, &current) {
        Some(latest_tag)
    } else {
        None
    }
}

/// Imprime a stderr un aviso si hay update disponible. Lo llaman comandos interactivos.
pub fn notify_if_outdated() {
    if let Some(tag) = check_for_update() {
        eprintln!("\nsynsema {} disponible (tenés {}) — corré `synsema update`", tag, current_version());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parsing() {
        assert_eq!(parse_semver("v0.3.2"), Some((0, 3, 2)));
        assert_eq!(parse_semver("0.3.2"), Some((0, 3, 2)));
        assert_eq!(parse_semver("v0.1.0-dev"), Some((0, 1, 0)));
        assert_eq!(parse_semver("v1.2"), Some((1, 2, 0)));
        assert_eq!(parse_semver("nope"), None);
    }

    #[test]
    fn newer_comparison() {
        assert!(is_newer("v0.3.2", "v0.3.1"));
        assert!(is_newer("v0.4.0", "v0.3.9"));
        assert!(is_newer("v1.0.0", "v0.9.9"));
        assert!(!is_newer("v0.3.1", "v0.3.1"));
        assert!(!is_newer("v0.3.0", "v0.3.1"));
        // -dev compara por su core semver.
        assert!(is_newer("v0.3.2", "v0.3.1-dev"));
    }

    #[test]
    fn asset_url_extraction() {
        let json = serde_json::json!({
            "tag_name": "v0.3.2",
            "assets": [
                {"name": "synsema-linux-x86_64", "browser_download_url": "https://example/bin"},
                {"name": "synsema-linux-x86_64.sha256", "browser_download_url": "https://example/sha"}
            ]
        });
        assert_eq!(asset_url(&json, "synsema-linux-x86_64").as_deref(), Some("https://example/bin"));
        assert_eq!(asset_url(&json, "synsema-linux-x86_64.sha256").as_deref(), Some("https://example/sha"));
        assert_eq!(asset_url(&json, "nope"), None);
    }
}
