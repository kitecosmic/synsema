//! A2 batch 2 — ACME / auto-HTTPS (Let's Encrypt) sobre `instant-acme`.
//!
//! El servidor sigue siendo std::net thread-per-conn; este módulo usa un runtime
//! tokio **acotado** sólo para obtener/renovar el certificado vía el challenge
//! HTTP-01. El challenge se sirve desde el listener :80 (`server::serve_acme_http`),
//! que comparte un [`ChallengeStore`] con el flujo ACME.
//!
//! Configuración por entorno (defaults = producción Let's Encrypt):
//! - `SYNTECNIA_ACME_DIRECTORY` — URL del directorio ACME (default LE producción).
//! - `SYNTECNIA_ACME_CA` — PEM de una CA a confiar (para PKI de prueba como Pebble).
//! - `SYNTECNIA_CERT_DIR` — dónde guardar cert+key (default `~/.syntecnia/certs`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};

use crate::server::{self, ChallengeStore, SharedServerConfig};

/// Vida asumida de un cert LE (90 días) y umbral de renovación (renovar cuando
/// faltan <30 días, es decir, a los 60 de vida).
const CERT_LIFETIME_DAYS: u64 = 90;
const RENEW_BEFORE_DAYS: u64 = 30;
const DAY_SECS: u64 = 24 * 60 * 60;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Directorio de almacenamiento de certs (`SYNTECNIA_CERT_DIR` o `~/.syntecnia/certs`).
pub fn certs_dir() -> PathBuf {
    if let Ok(d) = std::env::var("SYNTECNIA_CERT_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    Path::new(&home).join(".syntecnia").join("certs")
}

fn sanitize(domain: &str) -> String {
    domain
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// (cert.pem, key.pem, .issued) para un dominio dentro de `certs_dir()`.
pub fn cert_paths(domain: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = certs_dir();
    let base = sanitize(domain);
    (
        dir.join(format!("{}.pem", base)),
        dir.join(format!("{}.key.pem", base)),
        dir.join(format!("{}.issued", base)),
    )
}

/// ¿Hay un cert utilizable (archivos presentes y aún lejos de la expiración)?
/// La edad se mide con el sidecar `.issued` (unix secs de emisión).
pub fn has_fresh_cert(domain: &str) -> bool {
    let (cert, key, issued) = cert_paths(domain);
    if !cert.is_file() || !key.is_file() {
        return false;
    }
    match std::fs::read_to_string(&issued).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(t) => {
            let age = now_secs().saturating_sub(t);
            age < (CERT_LIFETIME_DAYS - RENEW_BEFORE_DAYS) * DAY_SECS
        }
        None => false,
    }
}

fn save_cert(domain: &str, cert_pem: &str, key_pem: &str) -> Result<(PathBuf, PathBuf), String> {
    let (cert, key, issued) = cert_paths(domain);
    if let Some(parent) = cert.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("could not create certs dir: {}", e))?;
    }
    std::fs::write(&cert, cert_pem).map_err(|e| format!("could not write cert {}: {}", cert.display(), e))?;
    std::fs::write(&key, key_pem).map_err(|e| format!("could not write key {}: {}", key.display(), e))?;
    let _ = std::fs::write(&issued, now_secs().to_string());
    Ok((cert, key))
}

/// Obtiene un cert vía ACME HTTP-01 y lo guarda en disco. Devuelve (cert_path, key_path).
/// El listener de challenge HTTP **debe** estar corriendo y compartir `store`.
pub fn obtain_and_save(
    domain: &str,
    email: Option<&str>,
    store: ChallengeStore,
) -> Result<(PathBuf, PathBuf), String> {
    let (cert_pem, key_pem) = provision_certificate(domain, email, store)?;
    save_cert(domain, &cert_pem, &key_pem)
}

/// Flujo ACME completo (cuenta → orden → HTTP-01 → finalize → cert). Devuelve los
/// PEM (cert chain, private key). Arranca un runtime tokio acotado internamente.
pub fn provision_certificate(
    domain: &str,
    email: Option<&str>,
    store: ChallengeStore,
) -> Result<(String, String), String> {
    // Provider por defecto para los ClientConfig internos de rustls (idempotente).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let directory_url = std::env::var("SYNTECNIA_ACME_DIRECTORY")
        .unwrap_or_else(|_| instant_acme::LetsEncrypt::Production.url().to_owned());
    let ca_root = std::env::var("SYNTECNIA_ACME_CA").ok();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start ACME runtime: {}", e))?;

    let domain = domain.to_string();
    let email = email.map(|s| s.to_string());
    rt.block_on(async move {
        acme_flow(&domain, email.as_deref(), &directory_url, ca_root.as_deref(), store).await
    })
}

async fn acme_flow(
    domain: &str,
    email: Option<&str>,
    directory_url: &str,
    ca_root: Option<&str>,
    store: ChallengeStore,
) -> Result<(String, String), String> {
    let builder = match ca_root {
        Some(path) => {
            Account::builder_with_root(path).map_err(|e| format!("ACME custom CA error: {}", e))?
        }
        None => Account::builder().map_err(|e| format!("ACME client error: {}", e))?,
    };

    let contacts: Vec<String> = email.map(|e| format!("mailto:{}", e)).into_iter().collect();
    let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let (account, _creds) = builder
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await
        .map_err(|e| format!("ACME account creation failed: {}", e))?;

    // Un identifier IP (p.ej. "127.0.0.1") va como Identifier::Ip; lo demás como DNS.
    let identifier = match domain.parse::<std::net::IpAddr>() {
        Ok(ip) => Identifier::Ip(ip),
        Err(_) => Identifier::Dns(domain.to_string()),
    };
    let identifiers = [identifier];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME new order failed: {}", e))?;

    // Provisiona cada challenge HTTP-01 pendiente en el store y lo marca listo.
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| format!("ACME authorization failed: {}", e))?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => return Err(format!("unexpected ACME authorization status: {:?}", other)),
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| "ACME server offered no HTTP-01 challenge".to_string())?;
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        store.lock().unwrap().insert(token, key_auth);
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("ACME order polling failed: {}", e))?;
    if status != OrderStatus::Ready {
        return Err(format!("ACME order did not become ready (status: {:?})", status));
    }

    // `finalize()` genera keypair+CSR internamente (feature rcgen) y devuelve la key PEM.
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("ACME finalize failed: {}", e))?;
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("ACME certificate retrieval failed: {}", e))?;
    Ok((cert_pem, key_pem))
}

/// Carga el cert en disco si está fresco; si no, lo obtiene vía ACME. Construye y
/// devuelve la config TLS. El listener de challenge debe compartir `store`.
pub fn load_or_obtain_config(
    domain: &str,
    email: Option<&str>,
    store: ChallengeStore,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let (cert_path, key_path) = if has_fresh_cert(domain) {
        let (c, k, _) = cert_paths(domain);
        (c, k)
    } else {
        obtain_and_save(domain, email, store)?
    };
    server::build_tls_config(&cert_path.to_string_lossy(), &key_path.to_string_lossy())
}

/// Lanza un hilo de renovación: cada 12h chequea la frescura del cert y, si entra
/// en la ventana de renovación (<30 días), re-emite y hot-swappea `cell`.
pub fn spawn_renewal_thread(
    domain: String,
    email: Option<String>,
    store: ChallengeStore,
    cell: SharedServerConfig,
) {
    std::thread::Builder::new()
        .name(format!("acme-renew:{}", domain))
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(12 * 60 * 60));
            if has_fresh_cert(&domain) {
                continue;
            }
            match obtain_and_save(&domain, email.as_deref(), store.clone()) {
                Ok((cert, key)) => {
                    if let Ok(cfg) =
                        server::build_tls_config(&cert.to_string_lossy(), &key.to_string_lossy())
                    {
                        if let Ok(mut w) = cell.write() {
                            *w = cfg;
                        }
                        println!("ACME: renewed certificate for {}", domain);
                    }
                }
                Err(e) => eprintln!("ACME: renewal failed for {}: {}", domain, e),
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_domain_for_filename() {
        assert_eq!(sanitize("example.com"), "example.com");
        assert_eq!(sanitize("*.example.com"), "_.example.com");
        assert_eq!(sanitize("a/b:c"), "a_b_c");
    }

    #[test]
    fn fresh_cert_logic_via_sidecar() {
        let dir = std::env::temp_dir().join("syn_acme_fresh_test");
        let _ = std::fs::create_dir_all(&dir);
        // Aísla certs_dir a un temporal.
        std::env::set_var("SYNTECNIA_CERT_DIR", &dir);
        let domain = "fresh.example.com";
        let (cert, key, issued) = cert_paths(domain);
        std::fs::write(&cert, "x").unwrap();
        std::fs::write(&key, "y").unwrap();

        // Emitido recién → fresco.
        std::fs::write(&issued, now_secs().to_string()).unwrap();
        assert!(has_fresh_cert(domain));

        // Emitido hace 75 días → dentro de la ventana de renovación → NO fresco.
        let old = now_secs().saturating_sub(75 * DAY_SECS);
        std::fs::write(&issued, old.to_string()).unwrap();
        assert!(!has_fresh_cert(domain));

        // Sin sidecar → NO fresco.
        let _ = std::fs::remove_file(&issued);
        assert!(!has_fresh_cert(domain));

        std::env::remove_var("SYNTECNIA_CERT_DIR");
    }
}
