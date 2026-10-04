//! v0.6.42 — certificados automáticos sin los problemas de "uno por uno" (spec v0.6.42 §3).
//!
//! Lo que cambia respecto de `acme.rs` (que queda para el camino histórico y sus tests):
//! - **La cuenta ACME se guarda y se reusa** (`account-<directorio>.json` en `SYNSEMA_CERT_DIR`).
//!   Antes cada emisión creaba una cuenta nueva y sumaba contra los límites de la CA.
//! - **Un certificado por nombre**, en memoria y en disco. Agregar un dominio no reemite los
//!   demás; la renovación es por nombre y mira el vencimiento REAL del certificado (`notAfter`),
//!   no un archivo aparte.
//! - **Wildcards** (`*.ejemplo.app`) por DNS-01, publicando el TXT con una task del programa
//!   (`tls dns <task>`): el motor no conoce a ningún proveedor de DNS (interfaz `libdns`).
//! - **Bajo demanda** (`domain ask <task>`): un SNI sin certificado se le pregunta a la task del
//!   programa y, si dice que sí, se emite durante el handshake (reto TLS-ALPN-01, sin depender
//!   del puerto 80). Sin `ask` no hay emisión bajo demanda (decisión del 2026-09-11): cualquiera
//!   que apunte un DNS a la IP agotaría la cuota de la CA.
//! - **Topes propios**: `SYNSEMA_ACME_MAX_PER_HOUR` emisiones por hora y backoff por nombre ante
//!   fallos; la respuesta de `ask` se recuerda (sí: 1 h, no: 10 min).
//!
//! Variables de entorno (además de las de `acme.rs`: `SYNSEMA_ACME_DIRECTORY`, `SYNSEMA_ACME_CA`,
//! `SYNSEMA_CERT_DIR`): `SYNSEMA_ACME_MAX_PER_HOUR` (default 20) y `SYNSEMA_ACME_DNS_WAIT`
//! (segundos de propagación del TXT antes de pedir la validación, default 20).

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::sign::CertifiedKey;

use crate::server::ChallengeStore;

/// `domain ask <task>`: ¿se emite un certificado para este nombre?
pub type AskFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// `tls dns <task>`: `(nombre, valor, "set" | "clear")` publica o retira el TXT del reto DNS-01.
pub type DnsFn = Arc<dyn Fn(&str, &str, &str) -> Result<(), String> + Send + Sync>;

/// Lo que el `serve` declara.
pub struct AcmeOptions {
    pub email: Option<String>,
    /// Nombres fijos (`domain …`), con o sin `*.`.
    pub domains: Vec<String>,
    pub ask: Option<AskFn>,
    pub dns: Option<DnsFn>,
    /// El store del listener HTTP-01 de `:80`, si está levantado.
    pub http_store: Option<ChallengeStore>,
}

const RENEW_BEFORE: i64 = 30 * 24 * 3600;
const ASK_YES_TTL: Duration = Duration::from_secs(3600);
const ASK_NO_TTL: Duration = Duration::from_secs(600);
const ASK_TIMEOUT: Duration = Duration::from_secs(10);
/// Lo que espera un handshake a que se emita su certificado.
pub const ISSUE_TIMEOUT: Duration = Duration::from_secs(10);
/// ALPN del reto TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(default)
}

/// El nombre de archivo de un dominio (`*.x` → `_.x`), como `acme::cert_paths`.
fn file_base(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect()
}

pub struct CertManager {
    opts: AcmeOptions,
    dir: PathBuf,
    directory_url: String,
    ca_root: Option<String>,
    account: tokio::sync::Mutex<Option<Account>>,
    /// Una emisión a la vez (son raras; así dos handshakes del mismo nombre no piden dos certs).
    issuing: tokio::sync::Mutex<()>,
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    not_after: Mutex<HashMap<String, i64>>,
    /// Certificados de reto TLS-ALPN-01 vigentes, por nombre.
    alpn: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    failures: Mutex<HashMap<String, (Instant, u32)>>,
    issued: Mutex<VecDeque<Instant>>,
    ask_cache: Mutex<HashMap<String, (bool, Instant)>>,
    max_per_hour: usize,
    dns_wait: Duration,
}

impl CertManager {
    pub fn new(opts: AcmeOptions) -> Arc<CertManager> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Arc::new(CertManager {
            opts,
            dir: crate::acme::certs_dir(),
            directory_url: std::env::var("SYNSEMA_ACME_DIRECTORY")
                .unwrap_or_else(|_| instant_acme::LetsEncrypt::Production.url().to_owned()),
            ca_root: std::env::var("SYNSEMA_ACME_CA").ok(),
            account: tokio::sync::Mutex::new(None),
            issuing: tokio::sync::Mutex::new(()),
            certs: RwLock::new(HashMap::new()),
            not_after: Mutex::new(HashMap::new()),
            alpn: RwLock::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            issued: Mutex::new(VecDeque::new()),
            ask_cache: Mutex::new(HashMap::new()),
            max_per_hour: env_u64("SYNSEMA_ACME_MAX_PER_HOUR", 20) as usize,
            dns_wait: Duration::from_secs(env_u64("SYNSEMA_ACME_DNS_WAIT", 20)),
        })
    }

    /// ¿Hay un `ask`? (sin él, un nombre desconocido nunca se emite).
    pub fn on_demand(&self) -> bool {
        self.opts.ask.is_some()
    }

    // -------------------------------------------------------------------------
    // Resolución (síncrona, la llama rustls en el handshake)
    // -------------------------------------------------------------------------

    /// El certificado para un SNI: el exacto, o el `*.` del padre (un solo nivel, como TLS).
    pub fn cert_for(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let sni = sni.trim_end_matches('.').to_ascii_lowercase();
        let certs = self.certs.read().ok()?;
        if let Some(c) = certs.get(&sni) {
            return Some(c.clone());
        }
        let parent = sni.split_once('.').map(|(_, p)| p)?;
        certs.get(&format!("*.{}", parent)).cloned()
    }

    /// Sin SNI (acceso por IP): el primer nombre fijo que tenga certificado.
    fn default_cert(&self) -> Option<Arc<CertifiedKey>> {
        let certs = self.certs.read().ok()?;
        self.opts.domains.iter().find_map(|d| certs.get(&d.to_ascii_lowercase()).cloned())
    }

    fn alpn_cert(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.alpn.read().ok()?.get(&sni.to_ascii_lowercase()).cloned()
    }

    // -------------------------------------------------------------------------
    // Disco
    // -------------------------------------------------------------------------

    fn paths(&self, name: &str) -> (PathBuf, PathBuf) {
        let base = file_base(name);
        (self.dir.join(format!("{}.pem", base)), self.dir.join(format!("{}.key.pem", base)))
    }

    fn account_path(&self) -> PathBuf {
        let host = self
            .directory_url
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or("acme");
        self.dir.join(format!("account-{}.json", file_base(host)))
    }

    /// Carga un certificado del disco: la clave firmante y su `notAfter`.
    fn load(&self, name: &str) -> Option<(Arc<CertifiedKey>, i64)> {
        let (cert, key) = self.paths(name);
        let cert_pem = std::fs::read(&cert).ok()?;
        let key_pem = std::fs::read(&key).ok()?;
        certified_from_pem(&cert_pem, &key_pem).ok()
    }

    fn install(&self, name: &str, ck: Arc<CertifiedKey>, not_after: i64) {
        if let Ok(mut c) = self.certs.write() {
            c.insert(name.to_ascii_lowercase(), ck);
        }
        if let Ok(mut n) = self.not_after.lock() {
            n.insert(name.to_ascii_lowercase(), not_after);
        }
    }

    // -------------------------------------------------------------------------
    // Emisión
    // -------------------------------------------------------------------------

    async fn account(&self) -> Result<Account, String> {
        let mut slot = self.account.lock().await;
        if let Some(a) = slot.as_ref() {
            return Ok(a.clone());
        }
        let builder = || match &self.ca_root {
            Some(path) => Account::builder_with_root(path).map_err(|e| format!("ACME custom CA error: {}", e)),
            None => Account::builder().map_err(|e| format!("ACME client error: {}", e)),
        };
        let path = self.account_path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&text) {
                match builder()?.from_credentials(creds).await {
                    Ok(a) => {
                        *slot = Some(a.clone());
                        return Ok(a);
                    }
                    Err(e) => eprintln!("ACME: stored account at {} not usable ({}); creating a new one", path.display(), e),
                }
            }
        }
        let contacts: Vec<String> = self.opts.email.iter().map(|e| format!("mailto:{}", e)).collect();
        let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
        let (account, creds) = builder()?
            .create(
                &NewAccount { contact: &contact_refs, terms_of_service_agreed: true, only_return_existing: false },
                self.directory_url.clone(),
                None,
            )
            .await
            .map_err(|e| format!("ACME account creation failed: {}", e))?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string(&creds) {
            Ok(json) => {
                if let Err(e) = write_private(&path, json.as_bytes()) {
                    eprintln!("ACME: could not save the account to {}: {} (a new one will be created next start)", path.display(), e);
                }
            }
            Err(e) => eprintln!("ACME: could not serialize the account: {}", e),
        }
        *slot = Some(account.clone());
        Ok(account)
    }

    /// ¿Se puede pedir otra emisión ahora? (tope por hora y backoff del nombre).
    fn admit(&self, name: &str) -> Result<(), String> {
        if let Ok(f) = self.failures.lock() {
            if let Some((at, n)) = f.get(name) {
                let wait = Duration::from_secs(60u64.saturating_mul(1 << (*n).min(6))).min(Duration::from_secs(3600));
                if at.elapsed() < wait {
                    return Err(format!("{}: issuance failed recently; retrying in {}s", name, (wait - at.elapsed()).as_secs()));
                }
            }
        }
        let mut q = self.issued.lock().map_err(|_| "ACME: internal lock".to_string())?;
        while q.front().map(|t| t.elapsed() > Duration::from_secs(3600)).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= self.max_per_hour {
            return Err(format!(
                "{}: SYNSEMA_ACME_MAX_PER_HOUR ({}) certificates were already issued in the last hour",
                name, self.max_per_hour
            ));
        }
        q.push_back(Instant::now());
        Ok(())
    }

    fn note_failure(&self, name: &str) {
        if let Ok(mut f) = self.failures.lock() {
            let n = f.get(name).map(|(_, n)| n + 1).unwrap_or(0);
            f.insert(name.to_string(), (Instant::now(), n));
        }
    }

    /// Emite (o renueva) el certificado de UN nombre y lo instala.
    pub async fn issue(&self, name: &str) -> Result<(), String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let _one = self.issuing.lock().await;
        self.admit(&name)?;
        match self.issue_inner(&name).await {
            Ok(()) => {
                if let Ok(mut f) = self.failures.lock() {
                    f.remove(&name);
                }
                println!("ACME: certificate ready for {}", name);
                Ok(())
            }
            Err(e) => {
                self.note_failure(&name);
                Err(e)
            }
        }
    }

    async fn issue_inner(&self, name: &str) -> Result<(), String> {
        let wildcard = name.starts_with("*.");
        if wildcard && self.opts.dns.is_none() {
            return Err(format!("{}: a wildcard certificate needs the DNS-01 challenge — add `tls dns <task>` to the serve block", name));
        }
        let account = self.account().await?;
        let identifier = match name.parse::<std::net::IpAddr>() {
            Ok(ip) => Identifier::Ip(ip),
            Err(_) => Identifier::Dns(name.to_string()),
        };
        let mut order = account
            .new_order(&NewOrder::new(&[identifier]))
            .await
            .map_err(|e| format!("ACME new order failed for {}: {}", name, e))?;
        let mut dns_published: Vec<(String, String)> = Vec::new();
        let mut alpn_names: Vec<String> = Vec::new();
        let result: Result<(), String> = async {
            let mut authorizations = order.authorizations();
            while let Some(r) = authorizations.next().await {
                let mut authz = r.map_err(|e| format!("ACME authorization failed: {}", e))?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => return Err(format!("unexpected ACME authorization status: {:?}", other)),
                }
                let ident = authz.identifier().to_string();
                let base = ident.trim_start_matches("*.").to_string();
                let use_dns = authz.wildcard || (self.opts.dns.is_some() && self.opts.http_store.is_none() && !self.on_demand());
                if use_dns {
                    let dns = self.opts.dns.clone().ok_or_else(|| format!("{}: DNS-01 needs `tls dns <task>`", ident))?;
                    let mut ch = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| format!("{}: the CA offered no DNS-01 challenge", ident))?;
                    let record = format!("_acme-challenge.{}", base);
                    let value = ch.key_authorization().dns_value();
                    let (r2, v2) = (record.clone(), value.clone());
                    tokio::task::spawn_blocking(move || dns(&r2, &v2, "set"))
                        .await
                        .map_err(|e| format!("tls dns task panicked: {}", e))?
                        .map_err(|e| format!("tls dns task failed to publish {}: {}", record, e))?;
                    dns_published.push((record, value));
                    if !self.dns_wait.is_zero() {
                        tokio::time::sleep(self.dns_wait).await;
                    }
                    ch.set_ready().await.map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
                    continue;
                }
                // TLS-ALPN-01 (no depende del :80); si la CA no lo ofrece, HTTP-01 con el :80.
                if authz.challenges.iter().any(|c| c.r#type == ChallengeType::TlsAlpn01) {
                    let mut ch = authz.challenge(ChallengeType::TlsAlpn01).expect("ofrecido");
                    let digest = ch.key_authorization().digest().as_ref().to_vec();
                    let ck = alpn_challenge_cert(&base, &digest)?;
                    if let Ok(mut a) = self.alpn.write() {
                        a.insert(base.to_ascii_lowercase(), Arc::new(ck));
                    }
                    alpn_names.push(base.to_ascii_lowercase());
                    ch.set_ready().await.map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
                    continue;
                }
                let store = self
                    .opts
                    .http_store
                    .clone()
                    .ok_or_else(|| format!("{}: the CA offered neither TLS-ALPN-01 nor DNS-01 and there is no :80 listener for HTTP-01", ident))?;
                let mut ch = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| format!("{}: the CA offered no usable challenge", ident))?;
                if let Ok(mut s) = store.lock() {
                    s.insert(ch.token.clone(), ch.key_authorization().as_str().to_string());
                }
                ch.set_ready().await.map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
            }
            let status = order
                .poll_ready(&RetryPolicy::default())
                .await
                .map_err(|e| format!("ACME order polling failed: {}", e))?;
            if status != OrderStatus::Ready {
                return Err(format!("ACME order for {} did not become ready (status: {:?})", name, status));
            }
            Ok(())
        }
        .await;
        // Limpieza SIEMPRE (también si falló): el TXT se retira y el cert de reto se suelta.
        if let Ok(mut a) = self.alpn.write() {
            for n in &alpn_names {
                a.remove(n);
            }
        }
        if let Some(dns) = self.opts.dns.clone() {
            for (record, value) in dns_published {
                let d = dns.clone();
                let _ = tokio::task::spawn_blocking(move || d(&record, &value, "clear")).await;
            }
        }
        result?;
        let key_pem = order.finalize().await.map_err(|e| format!("ACME finalize failed: {}", e))?;
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| format!("ACME certificate retrieval failed: {}", e))?;
        let (ck, not_after) = certified_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        let (cp, kp) = self.paths(name);
        if let Some(parent) = cp.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("could not create certs dir: {}", e))?;
        }
        std::fs::write(&cp, &cert_pem).map_err(|e| format!("could not write cert {}: {}", cp.display(), e))?;
        write_private(&kp, key_pem.as_bytes()).map_err(|e| format!("could not write key {}: {}", kp.display(), e))?;
        self.install(name, ck, not_after);
        Ok(())
    }

    /// Bajo demanda: asegura un certificado para el SNI de un handshake. Sin `ask`, o con un no,
    /// no se emite nada (la conexión sigue y el handshake falla sin certificado ajeno).
    pub async fn ensure(&self, sni: &str) -> Result<(), String> {
        let sni = sni.trim_end_matches('.').to_ascii_lowercase();
        if sni.is_empty() || self.cert_for(&sni).is_some() {
            return Ok(());
        }
        let Some(ask) = self.opts.ask.clone() else { return Err(format!("{}: no certificate and no `domain ask`", sni)) };
        // `ask` recordado.
        let cached = self
            .ask_cache
            .lock()
            .ok()
            .and_then(|c| c.get(&sni).copied())
            .filter(|(yes, at)| at.elapsed() < if *yes { ASK_YES_TTL } else { ASK_NO_TTL })
            .map(|(yes, _)| yes);
        let allowed = match cached {
            Some(v) => v,
            None => {
                let s = sni.clone();
                let v = match tokio::time::timeout(ASK_TIMEOUT, tokio::task::spawn_blocking(move || ask(&s))).await {
                    Ok(Ok(v)) => v,
                    // Un error o un timeout de la task cuenta como NO.
                    _ => false,
                };
                if let Ok(mut c) = self.ask_cache.lock() {
                    c.insert(sni.clone(), (v, Instant::now()));
                }
                v
            }
        };
        if !allowed {
            return Err(format!("{}: `domain ask` said no", sni));
        }
        self.issue(&sni).await
    }

    // -------------------------------------------------------------------------
    // Arranque y renovación
    // -------------------------------------------------------------------------

    /// Al arrancar: cada nombre fijo con un certificado vigente en disco se carga; los demás se
    /// emiten (bloquea hasta tenerlos: no se sirve HTTPS sin ellos, como antes).
    pub fn bootstrap(self: &Arc<Self>) -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("could not start ACME runtime: {}", e))?;
        for name in self.opts.domains.clone() {
            let name = name.to_ascii_lowercase();
            match self.load(&name) {
                Some((ck, not_after)) if not_after - now_unix() > RENEW_BEFORE => self.install(&name, ck, not_after),
                _ => {
                    let me = self.clone();
                    let n = name.clone();
                    rt.block_on(async move { me.issue(&n).await })?;
                }
            }
        }
        Ok(())
    }

    /// Cada 12 h renueva lo que vence en menos de 30 días (fijos y bajo demanda).
    pub fn spawn_renewal(self: &Arc<Self>) {
        let me = self.clone();
        let _ = std::thread::Builder::new().name("acme-renew".to_string()).spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("ACME: renewal thread could not start: {}", e);
                    return;
                }
            };
            loop {
                std::thread::sleep(Duration::from_secs(12 * 3600));
                let due: Vec<String> = me
                    .not_after
                    .lock()
                    .map(|n| n.iter().filter(|(_, t)| **t - now_unix() < RENEW_BEFORE).map(|(k, _)| k.clone()).collect())
                    .unwrap_or_default();
                for name in due {
                    if let Err(e) = rt.block_on(me.issue(&name)) {
                        eprintln!("ACME: renewal failed for {}: {}", name, e);
                    }
                }
            }
        });
    }
}

/// El resolver de rustls: el reto TLS-ALPN-01 primero, después el certificado del nombre, y sin
/// SNI el primero fijo. Si no hay certificado devuelve `None`: el handshake falla, nunca se
/// entrega el certificado de OTRO nombre.
pub struct ManagedResolver(pub Arc<CertManager>);

impl std::fmt::Debug for ManagedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedResolver")
    }
}

impl rustls::server::ResolvesServerCert for ManagedResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name().map(|s| s.to_string());
        let wants_challenge = hello.alpn().map(|mut a| a.any(|p| p == ACME_TLS_ALPN)).unwrap_or(false);
        match sni {
            Some(s) if wants_challenge => self.0.alpn_cert(&s),
            Some(s) => self.0.cert_for(&s),
            None => self.0.default_cert(),
        }
    }
}

/// La config TLS del servidor con certificados administrados (ALPN h2/http1.1 + el del reto).
pub fn managed_server_config(mgr: Arc<CertManager>) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {}", e))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ManagedResolver(mgr)));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

/// Cadena PEM + clave PEM → la clave firmante de rustls y el `notAfter` (unix) de la hoja.
fn certified_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<(Arc<CertifiedKey>, i64), String> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate PEM: {}", e))?;
    let leaf = certs.first().ok_or_else(|| "no certificate in the PEM".to_string())?;
    let not_after = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("could not parse the certificate: {}", e))?
        .1
        .validity()
        .not_after
        .timestamp();
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("invalid key PEM: {}", e))?
        .ok_or_else(|| "no private key in the PEM".to_string())?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("unsupported key: {}", e))?;
    Ok((Arc::new(CertifiedKey::new(certs, signing)), not_after))
}

/// El certificado de reto TLS-ALPN-01 (RFC 8737): autofirmado para `name` con la extensión
/// `acmeIdentifier` = sha256(key authorization).
fn alpn_challenge_cert(name: &str, digest: &[u8]) -> Result<CertifiedKey, String> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| format!("TLS-ALPN-01 cert: {}", e))?;
    params.custom_extensions.push(rcgen::CustomExtension::new_acme_identifier(digest));
    let kp = rcgen::KeyPair::generate().map_err(|e| format!("TLS-ALPN-01 key: {}", e))?;
    let cert = params.self_signed(&kp).map_err(|e| format!("TLS-ALPN-01 cert: {}", e))?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(kp.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("TLS-ALPN-01 key: {}", e))?;
    Ok(CertifiedKey::new(vec![cert.der().clone()], signing))
}

/// Escribe un archivo con la clave o la cuenta: en Unix sólo legible por el dueño (0600).
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(domains: &[&str]) -> Arc<CertManager> {
        CertManager::new(AcmeOptions {
            email: None,
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ask: None,
            dns: None,
            http_store: None,
        })
    }

    fn self_signed(name: &str) -> (String, String) {
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap().self_signed(&kp).unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    #[test]
    fn the_real_expiry_is_read_from_the_certificate() {
        let (c, k) = self_signed("a.example");
        let (_, not_after) = certified_from_pem(c.as_bytes(), k.as_bytes()).unwrap();
        // rcgen pone notAfter en 4096: lo que importa es que sale del certificado, no de un archivo.
        assert!(not_after > now_unix() + 365 * 24 * 3600, "{}", not_after);
    }

    #[test]
    fn sni_resolves_exact_then_one_level_wildcard() {
        let m = manager(&["a.example"]);
        let (c, k) = self_signed("x");
        let (ck, t) = certified_from_pem(c.as_bytes(), k.as_bytes()).unwrap();
        m.install("*.tun.example", ck.clone(), t);
        m.install("a.example", ck, t);
        assert!(m.cert_for("A.Example.").is_some());
        assert!(m.cert_for("k7f3q9.tun.example").is_some());
        assert!(m.cert_for("a.b.tun.example").is_none(), "un wildcard cubre un solo nivel");
        assert!(m.cert_for("other.example").is_none(), "nunca el certificado de otro nombre");
        assert!(m.default_cert().is_some());
    }

    #[test]
    fn a_wildcard_without_tls_dns_is_refused_and_ask_is_required() {
        let m = manager(&["*.x.example"]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let e = rt.block_on(m.issue("*.x.example")).unwrap_err();
        assert!(e.contains("tls dns"), "{}", e);
        let e = rt.block_on(m.ensure("new.example")).unwrap_err();
        assert!(e.contains("domain ask"), "{}", e);
    }

    #[test]
    fn the_hourly_cap_and_backoff_hold() {
        std::env::set_var("SYNSEMA_ACME_MAX_PER_HOUR", "2");
        let m = manager(&[]);
        std::env::remove_var("SYNSEMA_ACME_MAX_PER_HOUR");
        assert!(m.admit("a").is_ok());
        assert!(m.admit("b").is_ok());
        assert!(m.admit("c").unwrap_err().contains("SYNSEMA_ACME_MAX_PER_HOUR"));
        let m = manager(&[]);
        m.note_failure("z");
        assert!(m.admit("z").unwrap_err().contains("failed recently"));
    }

    #[test]
    fn the_tls_alpn_challenge_cert_is_built() {
        let ck = alpn_challenge_cert("a.example", &[7u8; 32]).unwrap();
        assert_eq!(ck.cert.len(), 1);
    }
}
