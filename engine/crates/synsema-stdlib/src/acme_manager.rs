//! v0.6.42 — certificados automáticos sin los problemas de "uno por uno" (spec v0.6.42 §3).
//!
//! Lo que cambia respecto de `acme.rs` (que queda para el camino histórico y sus tests):
//! - **La cuenta ACME se guarda y se reusa** (`account-<directorio>.json` en `SYNSEMA_CERT_DIR`).
//!   Antes cada emisión creaba una cuenta nueva y sumaba contra los límites de la CA.
//! - **Un certificado por nombre**, en memoria y en disco. Agregar un dominio no reemite los
//!   demás; la renovación es por nombre y mira el vencimiento REAL del certificado (`notAfter`).
//! - **Wildcards** (`*.ejemplo.app`) por DNS-01, publicando el TXT con una task del programa
//!   (`tls dns <task>`): el motor no conoce a ningún proveedor de DNS (interfaz `libdns`).
//! - **Bajo demanda** (`domain ask <task>`): un SNI sin certificado se le pregunta a la task del
//!   programa y, si dice que sí, se emite durante el handshake. Sin `ask` no hay emisión bajo
//!   demanda (decisión del 2026-09-11): cualquiera que apunte un DNS a la IP agotaría la cuota.
//!
//! Defensas (auditoría de v0.6.42):
//! - **Una emisión por nombre a la vez**: las conexiones paralelas de un navegador esperan la
//!   misma y reusan su resultado (Let's Encrypt permite 5 certificados idénticos por semana).
//! - **Lo que está en disco se usa**: un reinicio no reemite (ni los bajo demanda).
//! - **`ask` no se atasca desde la red**: corre en hilos propios con pila grande, con un
//!   semáforo que rechaza de inmediato lo que no entra, un tope de nombres nuevos por segundo y
//!   caché sólo de respuestas definitivas (sí: 1 h, no: 10 min), con tope de tamaño.
//! - **El arranque no se aborta por un nombre**: lo vigente se instala aunque esté por vencer,
//!   un nombre que falla va al log y la renovación sigue en segundo plano. La emisión inicial y
//!   las renovaciones no gastan `SYNSEMA_ACME_MAX_PER_HOUR` (que es para la emisión bajo demanda).
//! - **Claves**: escritura atómica (archivo temporal + rename), validadas contra el certificado,
//!   0600 en Unix y el directorio 0700.
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
/// `ask` corriendo a la vez como mucho (lo demás se rechaza en el acto, sin caché).
const ASK_CONCURRENCY: usize = 8;
/// Nombres NUEVOS (sin certificado ni respuesta en caché) que se consideran por segundo.
const NEW_NAMES_PER_SEC: u32 = 20;
/// Entradas de las cachés (`ask`, fallos) antes de barrer.
const CACHE_CAP: usize = 10_000;
/// Lo que puede tardar la task de `tls dns` en publicar o retirar el TXT.
const DNS_TIMEOUT: Duration = Duration::from_secs(60);
/// Pila de los hilos que corren tasks del programa (`ask`, `tls dns`): la del intérprete de
/// `serve`, no los 2 MB por defecto (un desborde ahí abortaría el proceso).
const TASK_STACK: usize = 64 * 1024 * 1024;
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

/// Por qué se emite: sólo la emisión bajo demanda gasta el tope por hora.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Why {
    Fixed,
    OnDemand,
    Renewal,
}

/// Corre `f` (una task del programa) en un hilo propio con pila grande y espera hasta `timeout`.
/// `None` si venció o si el hilo no arrancó; un hilo vencido termina solo cuando la task termina.
async fn run_task<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static, timeout: Duration) -> Option<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new().name("acme-task".to_string()).stack_size(TASK_STACK).spawn(move || {
        let _ = tx.send(f());
    });
    if spawned.is_err() {
        return None;
    }
    tokio::time::timeout(timeout, rx).await.ok()?.ok()
}

pub struct CertManager {
    opts: AcmeOptions,
    dir: PathBuf,
    directory_url: String,
    ca_root: Option<String>,
    account: tokio::sync::Mutex<Option<Account>>,
    /// Un lock por nombre: las emisiones del mismo nombre se esperan entre sí; las de nombres
    /// distintos no (un `tls dns` lento no frena a los demás).
    name_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    not_after: Mutex<HashMap<String, i64>>,
    /// Certificados de reto TLS-ALPN-01 vigentes, por nombre.
    alpn: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    failures: Mutex<HashMap<String, (Instant, u32)>>,
    issued: Mutex<VecDeque<Instant>>,
    ask_cache: Mutex<HashMap<String, (bool, Instant)>>,
    ask_slots: Arc<tokio::sync::Semaphore>,
    new_names: Mutex<(Instant, u32)>,
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
            name_locks: Mutex::new(HashMap::new()),
            certs: RwLock::new(HashMap::new()),
            not_after: Mutex::new(HashMap::new()),
            alpn: RwLock::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            issued: Mutex::new(VecDeque::new()),
            ask_cache: Mutex::new(HashMap::new()),
            ask_slots: Arc::new(tokio::sync::Semaphore::new(ASK_CONCURRENCY)),
            new_names: Mutex::new((Instant::now(), 0)),
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

    /// ¿Hay un certificado instalado para exactamente este nombre y lejos de vencer?
    fn fresh(&self, name: &str) -> bool {
        self.not_after.lock().ok().and_then(|n| n.get(name).copied()).map(|t| t - now_unix() > RENEW_BEFORE).unwrap_or(false)
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

    /// Instala lo que haya en disco para `name` si todavía no venció. `true` si quedó instalado.
    fn load_installed(&self, name: &str) -> bool {
        match self.load(name) {
            Some((ck, not_after)) if not_after > now_unix() => {
                self.install(name, ck, not_after);
                true
            }
            _ => false,
        }
    }

    fn install(&self, name: &str, ck: Arc<CertifiedKey>, not_after: i64) {
        if let Ok(mut c) = self.certs.write() {
            c.insert(name.to_ascii_lowercase(), ck);
        }
        if let Ok(mut n) = self.not_after.lock() {
            n.insert(name.to_ascii_lowercase(), not_after);
        }
    }

    fn ensure_dir(&self) -> Result<(), String> {
        create_private_dir(&self.dir).map_err(|e| format!("could not create certs dir {}: {}", self.dir.display(), e))
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
        self.ensure_dir()?;
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

    fn name_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = self.name_locks.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(name.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    }

    /// ¿Se puede pedir esta emisión? El backoff del nombre vale siempre; el tope por hora sólo
    /// para la emisión bajo demanda (la inicial y las renovaciones no lo gastan).
    fn admit(&self, name: &str, counts: bool) -> Result<(), String> {
        if let Ok(f) = self.failures.lock() {
            if let Some((at, n)) = f.get(name) {
                let wait = Duration::from_secs(60u64.saturating_mul(1 << (*n).min(6))).min(Duration::from_secs(3600));
                if at.elapsed() < wait {
                    return Err(format!(
                        "{}: issuance failed recently; retrying in {}s",
                        name,
                        wait.saturating_sub(at.elapsed()).as_secs()
                    ));
                }
            }
        }
        if !counts {
            return Ok(());
        }
        let mut q = self.issued.lock().map_err(|_| "ACME: internal lock".to_string())?;
        while q.front().map(|t| t.elapsed() > Duration::from_secs(3600)).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= self.max_per_hour {
            return Err(format!(
                "{}: SYNSEMA_ACME_MAX_PER_HOUR ({}) certificates were already issued on demand in the last hour",
                name, self.max_per_hour
            ));
        }
        q.push_back(Instant::now());
        Ok(())
    }

    fn note_failure(&self, name: &str) {
        if let Ok(mut f) = self.failures.lock() {
            if f.len() >= CACHE_CAP {
                f.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(3600));
                if f.len() >= CACHE_CAP {
                    f.clear();
                }
            }
            let n = f.get(name).map(|(_, n)| n + 1).unwrap_or(0);
            f.insert(name.to_string(), (Instant::now(), n));
        }
    }

    /// Emite (o renueva) el certificado de UN nombre fijo y lo instala.
    pub async fn issue(&self, name: &str) -> Result<(), String> {
        self.issue_for(name, Why::Fixed).await
    }

    async fn issue_for(&self, name: &str, why: Why) -> Result<(), String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let lock = self.name_lock(&name);
        let _one = lock.lock().await;
        // Otra conexión pudo emitirlo mientras ésta esperaba el lock: se reusa (B4).
        if self.fresh(&name) {
            return Ok(());
        }
        self.admit(&name, why == Why::OnDemand)?;
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
        let mut http_tokens: Vec<String> = Vec::new();
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
                    match run_task(move || dns(&r2, &v2, "set"), DNS_TIMEOUT).await {
                        Some(Ok(())) => {}
                        Some(Err(e)) => return Err(format!("tls dns task failed to publish {}: {}", record, e)),
                        None => return Err(format!("tls dns task did not publish {} within {}s", record, DNS_TIMEOUT.as_secs())),
                    }
                    dns_published.push((record, value));
                    if !self.dns_wait.is_zero() {
                        tokio::time::sleep(self.dns_wait).await;
                    }
                    ch.set_ready().await.map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
                    continue;
                }
                // HTTP-01 si está el listener de :80 (en `serve` siempre: también vale al arrancar,
                // antes de que el HTTPS acepte conexiones); si no, TLS-ALPN-01 desde el mismo
                // resolver (necesita el HTTPS ya sirviendo: la emisión bajo demanda).
                let offers = |t: ChallengeType| authz.challenges.iter().any(|c| c.r#type == t);
                if let (Some(store), true) = (self.opts.http_store.clone(), offers(ChallengeType::Http01)) {
                    let mut ch = authz.challenge(ChallengeType::Http01).expect("ofrecido");
                    if let Ok(mut s) = store.lock() {
                        s.insert(ch.token.clone(), ch.key_authorization().as_str().to_string());
                    }
                    http_tokens.push(ch.token.clone());
                    ch.set_ready().await.map_err(|e| format!("ACME set challenge ready failed: {}", e))?;
                    continue;
                }
                if !offers(ChallengeType::TlsAlpn01) {
                    return Err(format!(
                        "{}: no usable challenge (no :80 listener for HTTP-01 and the CA offered no TLS-ALPN-01)",
                        ident
                    ));
                }
                let mut ch = authz.challenge(ChallengeType::TlsAlpn01).expect("ofrecido");
                let digest = ch.key_authorization().digest().as_ref().to_vec();
                let ck = alpn_challenge_cert(&base, &digest)?;
                if let Ok(mut a) = self.alpn.write() {
                    a.insert(base.to_ascii_lowercase(), Arc::new(ck));
                }
                alpn_names.push(base.to_ascii_lowercase());
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
        // Limpieza SIEMPRE (también si falló): el TXT se retira, el cert de reto se suelta y los
        // tokens de HTTP-01 se borran.
        if let Ok(mut a) = self.alpn.write() {
            for n in &alpn_names {
                a.remove(n);
            }
        }
        if let Some(store) = &self.opts.http_store {
            if let Ok(mut s) = store.lock() {
                for t in &http_tokens {
                    s.remove(t);
                }
            }
        }
        if let Some(dns) = self.opts.dns.clone() {
            for (record, value) in dns_published {
                let d = dns.clone();
                let _ = run_task(move || d(&record, &value, "clear"), DNS_TIMEOUT).await;
            }
        }
        result?;
        let key_pem = order.finalize().await.map_err(|e| format!("ACME finalize failed: {}", e))?;
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| format!("ACME certificate retrieval failed: {}", e))?;
        // Validados ANTES de tocar el disco: la clave tiene que corresponder al certificado.
        let (ck, not_after) = certified_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        self.ensure_dir()?;
        let (cp, kp) = self.paths(name);
        // La clave primero y el certificado después, cada uno atómico: un disco lleno a mitad de
        // camino deja el par anterior entero (o ninguno), nunca uno roto.
        write_private(&kp, key_pem.as_bytes()).map_err(|e| format!("could not write key {}: {}", kp.display(), e))?;
        write_atomic(&cp, cert_pem.as_bytes(), false).map_err(|e| format!("could not write cert {}: {}", cp.display(), e))?;
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
        // Un certificado que quedó en disco de una corrida anterior se usa (B4: un reinicio no
        // reemite).
        if self.load_installed(&sni) {
            return Ok(());
        }
        let Some(ask) = self.opts.ask.clone() else { return Err(format!("{}: no certificate and no `domain ask`", sni)) };
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
                // Tope de nombres nuevos por segundo y de `ask` a la vez: lo que no entra se
                // rechaza en el acto y SIN caché (un cliente real que llega en medio de un ataque
                // vuelve a intentar enseguida, no queda bloqueado 10 minutos).
                {
                    let mut w = self.new_names.lock().unwrap_or_else(|e| e.into_inner());
                    if w.0.elapsed() >= Duration::from_secs(1) {
                        *w = (Instant::now(), 0);
                    }
                    if w.1 >= NEW_NAMES_PER_SEC {
                        return Err(format!("{}: too many new names right now; try again", sni));
                    }
                    w.1 += 1;
                }
                let Ok(slot) = self.ask_slots.clone().try_acquire_owned() else {
                    return Err(format!("{}: `domain ask` is busy; try again", sni));
                };
                let s = sni.clone();
                // El permiso viaja con el hilo: una task colgada ocupa su lugar hasta terminar.
                let answer = run_task(
                    move || {
                        let _slot = slot;
                        ask(&s)
                    },
                    ASK_TIMEOUT,
                )
                .await;
                let Some(v) = answer else {
                    return Err(format!("{}: `domain ask` did not answer within {}s", sni, ASK_TIMEOUT.as_secs()));
                };
                if let Ok(mut c) = self.ask_cache.lock() {
                    if c.len() >= CACHE_CAP {
                        c.retain(|_, (yes, at)| at.elapsed() < if *yes { ASK_YES_TTL } else { ASK_NO_TTL });
                        if c.len() >= CACHE_CAP {
                            c.clear();
                        }
                    }
                    c.insert(sni.clone(), (v, Instant::now()));
                }
                v
            }
        };
        if !allowed {
            return Err(format!("{}: `domain ask` said no", sni));
        }
        self.issue_for(&sni, Why::OnDemand).await
    }

    // -------------------------------------------------------------------------
    // Arranque y renovación
    // -------------------------------------------------------------------------

    /// Al arrancar: todo nombre fijo con un certificado vigente en disco se instala (aunque esté
    /// por vencer: la renovación sigue en segundo plano); los que faltan se emiten. Un nombre que
    /// falla va al log y NO aborta el arranque (B6). Devuelve los nombres que quedaron sin
    /// certificado.
    pub fn bootstrap(self: &Arc<Self>) -> Result<Vec<String>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("could not start ACME runtime: {}", e))?;
        let mut missing = Vec::new();
        for name in self.opts.domains.clone() {
            let name = name.to_ascii_lowercase();
            let have = self.load_installed(&name);
            if have && self.fresh(&name) {
                continue;
            }
            let me = self.clone();
            let n = name.clone();
            if let Err(e) = rt.block_on(async move { me.issue_for(&n, Why::Fixed).await }) {
                eprintln!("ACME: {}", e);
                if !have {
                    missing.push(name);
                }
            }
        }
        Ok(missing)
    }

    /// Cada hora mira qué vence en menos de 30 días y lo renueva (con el backoff de cada nombre).
    /// Un nombre bajo demanda se le vuelve a preguntar a `ask` antes de renovarlo.
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
                std::thread::sleep(Duration::from_secs(3600));
                let due: Vec<String> = me
                    .not_after
                    .lock()
                    .map(|n| n.iter().filter(|(_, t)| **t - now_unix() < RENEW_BEFORE).map(|(k, _)| k.clone()).collect())
                    .unwrap_or_default();
                for name in due {
                    let fixed = me.opts.domains.iter().any(|d| d.eq_ignore_ascii_case(&name));
                    if !fixed {
                        if let Some(ask) = me.opts.ask.clone() {
                            let n = name.clone();
                            if rt.block_on(run_task(move || ask(&n), ASK_TIMEOUT)) != Some(true) {
                                continue; // `ask` ya no lo aprueba: se deja vencer.
                            }
                        }
                    }
                    if let Err(e) = rt.block_on(me.issue_for(&name, Why::Renewal)) {
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

/// Cadena PEM + clave PEM → la clave firmante de rustls y el `notAfter` (unix) de la hoja. Falla
/// si la clave no corresponde al certificado.
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
    let ck = CertifiedKey::new(certs, signing);
    ck.keys_match().map_err(|e| format!("the private key does not match the certificate: {}", e))?;
    Ok((Arc::new(ck), not_after))
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

/// El directorio de certificados: en Unix sólo del dueño (0700), también si ya existía.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Escribe atómico: a un archivo temporal del mismo directorio y `rename` encima. `private` =
/// en Unix 0600 (también si el archivo ya existía con otros permisos).
fn write_atomic(path: &std::path::Path, data: &[u8], private: bool) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(if private { 0o600 } else { 0o644 });
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// La clave o la cuenta: atómica y sólo legible por el dueño en Unix. En Windows el archivo
/// hereda la ACL del directorio: `SYNSEMA_CERT_DIR` tiene que apuntar a un lugar del usuario del
/// servicio (el default es su perfil), no a una carpeta compartida.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic(path, data, true)
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
    fn a_key_that_does_not_match_its_certificate_is_refused() {
        let (c, _) = self_signed("a.example");
        let (_, other_key) = self_signed("b.example");
        let e = certified_from_pem(c.as_bytes(), other_key.as_bytes()).err().unwrap();
        assert!(e.contains("does not match"), "{}", e);
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
    fn the_hourly_cap_is_for_on_demand_and_backoff_holds() {
        std::env::set_var("SYNSEMA_ACME_MAX_PER_HOUR", "2");
        let m = manager(&[]);
        std::env::remove_var("SYNSEMA_ACME_MAX_PER_HOUR");
        assert!(m.admit("a", true).is_ok());
        assert!(m.admit("b", true).is_ok());
        assert!(m.admit("c", true).unwrap_err().contains("SYNSEMA_ACME_MAX_PER_HOUR"));
        assert!(m.admit("fixed", false).is_ok(), "la emisión inicial y las renovaciones no gastan el tope");
        let m = manager(&[]);
        m.note_failure("z");
        assert!(m.admit("z", false).unwrap_err().contains("failed recently"));
    }

    #[test]
    fn a_certificate_on_disk_is_used_instead_of_issuing_again() {
        let dir = std::env::temp_dir().join(format!("syn_acme_disk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("SYNSEMA_CERT_DIR", &dir);
        let m = manager(&[]);
        std::env::remove_var("SYNSEMA_CERT_DIR");
        let (c, k) = self_signed("ondemand.example");
        create_private_dir(&dir).unwrap();
        let (cp, kp) = m.paths("ondemand.example");
        write_private(&kp, k.as_bytes()).unwrap();
        write_atomic(&cp, c.as_bytes(), false).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        // Sin `ask` igual se sirve: está en disco y vigente (un reinicio no reemite).
        rt.block_on(m.ensure("ondemand.example")).unwrap();
        assert!(m.cert_for("ondemand.example").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ask_runs_with_a_big_stack_and_overload_is_refused_without_caching() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        // Una "task" que usa mucha pila: con los 2 MB de spawn_blocking abortaría el proceso.
        let deep = rt.block_on(run_task(
            || {
                fn rec(n: u32) -> u32 {
                    let buf = [n as u8; 4096];
                    if n == 0 { buf[0] as u32 } else { rec(n - 1).wrapping_add(buf[100] as u32) }
                }
                rec(4000)
            },
            Duration::from_secs(10),
        ));
        assert!(deep.is_some());
        let ask: AskFn = Arc::new(|_| {
            std::thread::sleep(Duration::from_millis(300));
            true
        });
        let m = CertManager::new(AcmeOptions { email: None, domains: vec![], ask: Some(ask), dns: None, http_store: None });
        let all = (0..ASK_CONCURRENCY).map(|_| m.ask_slots.clone().try_acquire_owned().unwrap()).collect::<Vec<_>>();
        let e = rt.block_on(m.ensure("busy.example")).unwrap_err();
        assert!(e.contains("busy"), "{}", e);
        assert!(m.ask_cache.lock().unwrap().get("busy.example").is_none(), "lo rechazado por carga no queda en caché");
        drop(all);
    }

    #[test]
    fn the_tls_alpn_challenge_cert_is_built() {
        let ck = alpn_challenge_cert("a.example", &[7u8; 32]).unwrap();
        assert_eq!(ck.cert.len(), 1);
    }
}
