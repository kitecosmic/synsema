//! Servidor HTTP nativo. Port de `synsema/stdlib/server.py`.
//!
//! Implementa el constructo `serve on PORT`. La lógica del lenguaje (capability,
//! aislamiento por request, auth, validación) la pone el engine vía closures
//! inyectados; este módulo es el plumbing HTTP + el *contrato de respuesta*.
//!
//! Concurrencia: thread-per-connection con `std::thread` (paridad con
//! `ThreadingHTTPServer`). Los recursos compartidos (db/blackboard) se envuelven
//! en `Arc`/`Mutex` antes de wirearse a los handlers.
//!
//! Este archivo cubre, por subsistemas (cada uno gateado con su differential):
//!   1. routing/match  — `specificity`, `path_match`, `match_route`, `methods_for_path`
//!   2. contrato de respuesta — pendiente (envelopes/paginación)
//!      … y siguen: static, negotiation, rate-limit, SSE, discovery, CORS, max_body

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use indexmap::IndexMap;

// Lote 2 — rewrite async (hyper/tokio/rustls). El intérprete sigue sync (spawn_blocking).
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};

use synsema_core::interpreter::CancelToken;
use synsema_core::route_meta::ApiRoute;
use synsema_core::types::{ServerValue, SynValue};

use crate::ws::ServerSocketLink;

use crate::discovery::{self, ApiInfo};

// =========================================================
// Constantes
// =========================================================

/// Tope por defecto del body bufferizado en memoria (no es tope duro: `max_body`
/// lo overridea y los bodies grandes spillean a disco).
pub const MAX_BODY: i64 = 1_048_576;
/// Sobre este tamaño el body se streamea a un temp file en vez de memoria.
pub const MEM_SPILL: usize = 1_048_576;
/// Tope por defecto de streams SSE concurrentes.
pub const DEFAULT_MAX_STREAMS: i64 = 100;

/// Content-types pinneados para servir estáticos: el resultado nunca depende del
/// registro de mimetypes del host (p.ej. Windows mapea .js → text/plain).
pub fn web_content_type(ext: &str) -> Option<&'static str> {
    Some(match ext {
        ".html" | ".htm" => "text/html; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".json" | ".map" => "application/json; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".ico" => "image/x-icon",
        ".woff" => "font/woff",
        ".woff2" => "font/woff2",
        ".ttf" => "font/ttf",
        ".txt" => "text/plain; charset=utf-8",
        ".xml" => "application/xml; charset=utf-8",
        ".wasm" => "application/wasm",
        ".pdf" => "application/pdf",
        _ => return None,
    })
}

/// Una respuesta escrita verbatim (no JSON), con Content-Type explícito.
/// Producida por html()/respond()/render() y por el servido de estáticos.
#[derive(Clone, Debug)]
/// Resultado de servir un estático de producción: status + body + content-type +
/// headers extra (ETag, Accept-Ranges, Content-Range, Content-Encoding, Vary).
struct StaticResp {
    status: u16,
    body: Vec<u8>,
    content_type: String,
    extra: Vec<(String, String)>,
}

/// ETag débil-equivalente derivado de tamaño + mtime (como hace nginx por defecto).
fn etag_for(path: &Path, size: usize) -> String {
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{:x}-{:x}\"", size, mtime)
}

/// Tipos comprimibles con gzip (html/css/js/json/svg/txt + xml por extensión común).
fn is_compressible(content_type: &str) -> bool {
    let c = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        c,
        "text/html"
            | "text/css"
            | "text/javascript"
            | "application/javascript"
            | "application/json"
            | "image/svg+xml"
            | "text/plain"
            | "application/xml"
            | "text/xml"
    )
}

/// Comprime con gzip (flate2 / miniz_oxide puro-Rust). None si falla.
fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::{write::GzEncoder, Compression};
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).ok()?;
    e.finish().ok()
}

/// Parsea un header `Range: bytes=START-END` (un solo rango). Soporta sufijo
/// `bytes=-N`. Devuelve `(start, end)` inclusivos, o None si el rango es inválido.
fn parse_range(range: &str, size: usize) -> Option<(usize, usize)> {
    if size == 0 {
        return None;
    }
    let r = range.trim().strip_prefix("bytes=")?;
    let (s, e) = r.split_once('-')?;
    let (s, e) = (s.trim(), e.trim());
    let (start, end) = if s.is_empty() {
        // Sufijo: últimos N bytes.
        let n: usize = e.parse().ok()?;
        if n == 0 {
            return None;
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start: usize = s.parse().ok()?;
        let end = if e.is_empty() {
            size - 1
        } else {
            e.parse::<usize>().ok()?.min(size - 1)
        };
        (start, end)
    };
    if start > end || start >= size {
        return None;
    }
    Some((start, end))
}

// =========================================================
// max_body
// =========================================================

/// Resuelve un setting de max-body a bytes, o None para ilimitado.
/// Acepta número (bytes) o string con unidad ("512kb", "10mb", "1gb") o
/// "unlimited"/"none" para desactivar.
pub fn parse_body_size_str(value: &str) -> Option<i64> {
    let s = value.trim().to_lowercase();
    if matches!(s.as_str(), "unlimited" | "none" | "off" | "0") {
        return None;
    }
    // ^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$
    let mut end = 0;
    let mut seen_dot = false;
    for (idx, c) in s.char_indices() {
        if c.is_ascii_digit() {
            end = idx + 1;
        } else if c == '.' && !seen_dot {
            seen_dot = true;
            end = idx + 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return Some(MAX_BODY);
    }
    let num = &s[..end];
    let rest = s[end..].trim_start();
    let mult: i64 = match rest {
        "" | "b" => 1,
        "kb" => 1024,
        "mb" => 1024 * 1024,
        "gb" => 1024 * 1024 * 1024,
        _ => return Some(MAX_BODY),
    };
    match num.parse::<f64>() {
        Ok(n) => Some((n * mult as f64) as i64),
        Err(_) => Some(MAX_BODY),
    }
}

// =========================================================
// JSON de salida + árbol de contenido como data: EXTRAÍDOS a json.rs (módulo puro,
// compartido con el perfil wasm; server.rs conserva los renderers HTML/Markdown).
// Re-export público: los callers externos (runtime, tests) siguen usando
// server::{Json, dumps, syn_to_json, json_to_syn} sin cambios.
// =========================================================

pub use crate::json::{dumps, json_to_syn, syn_to_json, Json};
// Router + contrato de respuesta + Ctx + forms + árbol de contenido: EXTRAÍDOS a
// routing.rs (módulo puro, compartido con el handler-mode del perfil wasm). Re-export
// glob: los callers (runtime, tests) siguen usando server::{Ctx, path_match, …}.
pub use crate::routing::*;
use crate::json::obj;

// =========================================================
// Rate limiter (token bucket, paridad con RateLimiter del oráculo)
// =========================================================

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant, f64)>>,
    cleanup_interval: f64,
    last_cleanup: Mutex<Option<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            cleanup_interval: 30.0,
            last_cleanup: Mutex::new(None),
        }
    }

    /// (allowed, remaining, retry_after, reset_seconds).
    pub fn check(&self, key: &str, capacity: i64, window: f64) -> (bool, i64, f64, f64) {
        let now = Instant::now();
        let rate = capacity as f64 / window;
        let mut buckets = self.buckets.lock().unwrap();
        // limpieza perezosa de buckets stale (no vistos por > 2× su ventana)
        {
            let mut lc = self.last_cleanup.lock().unwrap();
            let due = match *lc {
                None => true,
                Some(t) => now.duration_since(t).as_secs_f64() >= self.cleanup_interval,
            };
            if due {
                *lc = Some(now);
                buckets.retain(|_, (_t, last, w)| now.duration_since(*last).as_secs_f64() <= 2.0 * *w);
            }
        }
        let (mut tokens, last, _w) =
            buckets.get(key).copied().unwrap_or((capacity as f64, now, window));
        tokens = (capacity as f64).min(tokens + now.duration_since(last).as_secs_f64() * rate);
        let allowed;
        let retry_after;
        if tokens >= 1.0 {
            tokens -= 1.0;
            allowed = true;
            retry_after = 0.0;
        } else {
            allowed = false;
            retry_after = (1.0 - tokens) / rate;
        }
        buckets.insert(key.to_string(), (tokens, now, window));
        let remaining = tokens as i64;
        let reset = (capacity as f64 - tokens) / rate;
        (allowed, remaining, retry_after, reset)
    }
}

// =========================================================
// ServeRuntime
// =========================================================

/// Spec de un mount estático tal como lo declara el programa: prefijo + dir +
/// las cláusulas opcionales `cache` (Cache-Control) y `fallback` (SPA).
#[derive(Clone, Debug)]
pub struct StaticMountSpec {
    pub prefix: String,
    pub dir: String,
    /// Valor YA resuelto de Cache-Control (el runtime valida la spec con
    /// `cache_control_value` al construir el serve — fail-fast).
    pub cache: Option<String>,
    /// Archivo relativo al mount servido con 200 cuando el path no existe
    /// (history-fallback de SPA, estilo `try_files ... /index.html`).
    pub fallback: Option<String>,
}

/// Traduce la spec de `cache "<...>"` a un valor de header `Cache-Control`.
/// Acepta: `"immutable"` (assets fingerprinteados), `"no-store"`, un número crudo
/// (segundos) o `<N><s|m|h|d>` (`"30s"`, `"5m"`, `"1h"`, `"7d"`). Cualquier otra
/// cosa es error (fail-loud al construir el serve, nunca en un request).
pub fn cache_control_value(spec: &str) -> Result<String, String> {
    let s = spec.trim().to_ascii_lowercase();
    match s.as_str() {
        "immutable" => return Ok("public, max-age=31536000, immutable".to_string()),
        "no-store" => return Ok("no-store".to_string()),
        _ => {}
    }
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s.as_str(), 1),
        _ => ("", 1),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "invalid cache spec '{}' — use \"immutable\", \"no-store\", raw seconds, or <N>s/m/h/d (e.g. \"1h\", \"7d\")",
            spec
        ));
    }
    let secs: u64 = digits.parse().map_err(|_| format!("invalid cache spec '{}'", spec))?;
    Ok(format!("public, max-age={}", secs * mult))
}

/// Un mount estático ya resuelto (realpath + prefijo normalizado).
struct Mount {
    prefix: String,
    base: PathBuf,
    cache: Option<String>,
    fallback: Option<String>,
}

/// Tabla de ruteo de un host: rutas + estáticos + auth propios. El host `default`
/// (pattern=None) es el comportamiento de siempre; los vhosts (Lote 1) agregan
/// dominios con su propia tabla, seleccionados por el header `Host`.
pub struct HostRouter {
    /// None = host default (serve-level). Some("a.com") exacto, Some("*.a.com") wildcard.
    pattern: Option<String>,
    routes: Vec<RouteSpec>,
    static_mounts: Vec<Mount>,
    auth_handler: Option<AuthHandler>,
}

impl HostRouter {
    fn new(
        pattern: Option<String>,
        mut routes: Vec<RouteSpec>,
        static_mounts: Vec<StaticMountSpec>,
        auth_handler: Option<AuthHandler>,
    ) -> Self {
        // Orden por especificidad (más específica primero): el primer match gana.
        routes.sort_by_key(|a| specificity(&a.path));
        // Mounts: prefijo normalizado + realpath del directorio, prefijo más largo primero.
        let mut mounts: Vec<Mount> = static_mounts
            .into_iter()
            .map(|m| {
                let real =
                    Path::new(&m.dir).canonicalize().unwrap_or_else(|_| PathBuf::from(&m.dir));
                Mount { prefix: norm_prefix(&m.prefix), base: real, cache: m.cache, fallback: m.fallback }
            })
            .collect();
        mounts.sort_by_key(|m| std::cmp::Reverse(m.prefix.len()));
        HostRouter { pattern, routes, static_mounts: mounts, auth_handler }
    }

    /// ¿Este host (con patrón exacto o `*.dominio`) cubre `host`?
    fn matches_host(&self, host: &str) -> bool {
        match &self.pattern {
            None => true,
            Some(p) => {
                if let Some(suffix) = p.strip_prefix("*.") {
                    let h = host.to_ascii_lowercase();
                    let s = suffix.to_ascii_lowercase();
                    h == s || h.ends_with(&format!(".{}", s))
                } else {
                    host.eq_ignore_ascii_case(p)
                }
            }
        }
    }

    fn match_route(&self, method: &str, path: &str) -> Option<(usize, IndexMap<String, String>)> {
        for (i, route) in self.routes.iter().enumerate() {
            if route.method != method {
                continue;
            }
            if let Some(params) = path_match(&route.path, path) {
                return Some((i, params));
            }
        }
        None
    }

    fn methods_for_path(&self, path: &str) -> Vec<String> {
        let mut methods: Vec<String> = Vec::new();
        for route in &self.routes {
            if path_match(&route.path, path).is_some() && !methods.contains(&route.method) {
                methods.push(route.method.clone());
            }
        }
        methods.sort();
        methods
    }

    /// Sirve un estático de producción: ETag + 304 (If-None-Match), Range/206, gzip
    /// (Accept-Encoding + tipo comprimible). Devuelve status + body + headers extra.
    fn serve_static_full(&self, url_path: &str, headers: &[(String, String)]) -> Option<StaticResp> {
        for mount in &self.static_mounts {
            let (prefix, base) = (&mount.prefix, &mount.base);
            let rel = if prefix == "/" {
                url_path.to_string()
            } else if url_path == prefix.trim_end_matches('/') {
                String::new()
            } else if url_path.starts_with(prefix.as_str()) {
                url_path[prefix.len()..].to_string()
            } else {
                continue;
            };
            // Miss dentro del mount + `fallback` declarado → servir ese archivo con
            // 200 (history-fallback de SPA, semántica try_files). Sin fallback, se
            // sigue probando el próximo mount (comportamiento histórico).
            let target = match resolve_in(base, &rel) {
                Some(t) => t,
                None => match &mount.fallback {
                    Some(fb) => match resolve_in(base, fb) {
                        Some(t) => t,
                        None => continue,
                    },
                    None => continue,
                },
            };
            let data = match std::fs::read(&target) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let ct = static_content_type(&target);
            let etag = etag_for(&target, data.len());
            // `cache "<...>"` del mount → header Cache-Control en 200/206/304.
            let finish = |mut sr: StaticResp| {
                if let Some(c) = &mount.cache {
                    if sr.status != 416 {
                        sr.extra.push(("Cache-Control".into(), c.clone()));
                    }
                }
                Some(sr)
            };

            // If-None-Match → 304 (sin body).
            let inm = header_value(headers, "if-none-match");
            if !inm.is_empty() && inm.trim() == etag {
                return finish(StaticResp {
                    status: 304,
                    body: Vec::new(),
                    content_type: ct,
                    extra: vec![("ETag".into(), etag), ("Accept-Ranges".into(), "bytes".into())],
                });
            }
            // Range → 206 (sin gzip).
            let range = header_value(headers, "range");
            if !range.is_empty() {
                return finish(match parse_range(&range, data.len()) {
                    Some((start, end)) => StaticResp {
                        status: 206,
                        body: data[start..=end].to_vec(),
                        content_type: ct,
                        extra: vec![
                            ("ETag".into(), etag),
                            ("Accept-Ranges".into(), "bytes".into()),
                            ("Content-Range".into(), format!("bytes {}-{}/{}", start, end, data.len())),
                        ],
                    },
                    None => StaticResp {
                        status: 416,
                        body: Vec::new(),
                        content_type: ct,
                        extra: vec![("Content-Range".into(), format!("bytes */{}", data.len()))],
                    },
                });
            }
            // gzip si el cliente lo acepta y el tipo es comprimible.
            let ae = header_value(headers, "accept-encoding").to_lowercase();
            if ae.contains("gzip") && is_compressible(&ct) {
                if let Some(gz) = gzip_bytes(&data) {
                    return finish(StaticResp {
                        status: 200,
                        body: gz,
                        content_type: ct,
                        extra: vec![
                            ("ETag".into(), etag),
                            ("Accept-Ranges".into(), "bytes".into()),
                            ("Content-Encoding".into(), "gzip".into()),
                            ("Vary".into(), "Accept-Encoding".into()),
                        ],
                    });
                }
            }
            return finish(StaticResp {
                status: 200,
                body: data,
                content_type: ct,
                extra: vec![("ETag".into(), etag), ("Accept-Ranges".into(), "bytes".into())],
            });
        }
        None
    }
}

/// Resumen de una aprobación pendiente para `GET /approvals` — NUNCA incluye el token
/// (el token se distribuye por la consola del server al encolar).
#[derive(Clone, Debug)]
pub struct ApprovalSummary {
    pub id: String,
    pub message: String,
    /// "approve" | "confirm" | "ask" | "review"
    pub ty: String,
    /// Vencimiento en epoch-segundos.
    pub expires_at: i64,
}

/// Resultado de un intento de respuesta vía `POST /approvals/{id}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Token correcto: la pendiente se consumió (un solo uso) y el gate despertó.
    Accepted,
    /// id inexistente, ya consumido o vencido → 404.
    NotFound,
    /// Token incorrecto → 403 (la pendiente sigue viva).
    BadToken,
}

/// Backend de las rutas reservadas `/approvals` (cola de gates humanos bajo serve).
/// La cola real vive fuera de stdlib (en el runtime); acá sólo el contrato — el
/// runtime la cablea en `ServeRuntime.approvals` al armar el server.
pub trait ApprovalsGateway: Send + Sync {
    /// Pendientes actuales, sin tokens.
    fn list(&self) -> Vec<ApprovalSummary>;
    /// Respuesta humana: `decision` para approve/confirm/review, `value` para ask.
    fn respond(
        &self,
        id: &str,
        token: &str,
        decision: Option<bool>,
        value: Option<&str>,
    ) -> ApprovalOutcome;
}

pub struct ServeRuntime {
    pub port: u16,
    pub host: String,
    pub secure: bool,
    /// A2: TLS activo → se emite HSTS y los `redirect https` apuntan a https://.
    pub tls_enabled: bool,
    /// Cola de aprobaciones humanas (A1.v2) — `None` si el runtime no la cableó
    /// (las rutas `/approvals` no existen y todo sigue como antes).
    pub approvals: Option<Arc<dyn ApprovalsGateway>>,
    /// Host por defecto (rutas/estáticos/auth a nivel de `serve`).
    default_host: HostRouter,
    /// Hosts virtuales (Lote 1): seleccionados por el header `Host`.
    vhosts: Vec<HostRouter>,
    pub max_body: Option<i64>,
    pub max_streams: i64,
    cors_origin: Option<String>,
    intent: Option<String>,
    describe_about: Option<String>,
    describe_api: Vec<String>,
    private: bool,
    /// `domain` del serve block → base URL absoluta de sitemap/openapi (si no, `Host`).
    pub domain: Option<String>,
    /// `describe version: "…"` → `info.version` de `/openapi.json` (default "0.0.0").
    pub describe_version: Option<String>,
    /// `docs off` apaga la página `/docs` (el `/openapi.json` sigue publicado).
    pub docs_enabled: bool,
    rate_limiter: RateLimiter,
    active_streams: Mutex<i64>,
    /// `errors with <task>` (serve-level): da forma a 401/404/405/500.
    error_handler: Option<ErrorHandler>,
    /// `timeout N` del serve block: techo de vida por defecto de los handlers (segundos).
    /// `None` = sin límite (comportamiento histórico). Una route lo sobreescribe.
    pub default_timeout: Option<f64>,
    /// Shutdown ordenado en curso (SIGINT/SIGTERM): no se aceptan requests nuevas
    /// (503 + `Connection: close`) mientras se drenan las que están en vuelo.
    shutting_down: AtomicBool,
    /// Requests en vuelo (jobs del intérprete corriendo o encolados).
    inflight: AtomicUsize,
    /// Tokens de cancelación de los jobs en vuelo (`dedicated` = stream/socket): el
    /// drain los cancela — primero los long-lived, al vencer la gracia todos.
    active_cancels: Mutex<Vec<(CancelToken, bool)>>,
    /// Hook del runtime al iniciar el drain (parar cron, cancelar agentes).
    on_shutdown: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

/// El resultado de `dispatch`: una respuesta lista, o un hand-off a streaming SSE /
/// a un socket entrante.
pub enum Dispatched {
    Response { status: u16, body: ResponseBody, headers: Vec<(String, String)> },
    Stream { stream_handler: Option<StreamHandler>, ctx: Box<Ctx> },
    /// Ruta `socket`: el handler corre en hilo dedicado con el enlace al transporte.
    Socket { socket_handler: Option<SocketHandler>, ctx: Box<Ctx> },
    /// Ruta `proxy to`: auth/rate-limit ya pasaron; el lado async forwardea al
    /// upstream en streaming (SSE, WebSocket, bodies grandes). `headers` = rate-limit.
    Proxy { target: String, headers: Vec<(String, String)> },
}

/// Cómo atender una request, resuelto ANTES de correr el intérprete (vhost + match).
#[derive(Clone, Copy, Debug, Default)]
pub struct RoutePlan {
    /// Hilo dedicado (stream/socket/approvals) en vez del pool acotado.
    pub dedicated: bool,
    /// La ruta es un `socket` (WebSocket entrante).
    pub socket: bool,
    /// La ruta es un `proxy to` (el transporte la atiende en streaming).
    pub proxy: bool,
    /// Techo de vida del handler (route > serve); `None` = sin límite.
    pub timeout: Option<f64>,
}

#[allow(clippy::too_many_arguments)]
impl ServeRuntime {
    pub fn new(
        port: u16,
        host: String,
        routes: Vec<RouteSpec>,
        auth_handler: Option<AuthHandler>,
        max_body: Option<i64>,
        max_streams: i64,
        static_mounts: Vec<StaticMountSpec>,
        cors_origin: Option<String>,
        intent: Option<String>,
        describe_about: Option<String>,
        describe_api: Vec<String>,
        private: bool,
        secure: bool,
    ) -> Self {
        ServeRuntime {
            port,
            host,
            secure,
            tls_enabled: false,
            approvals: None,
            default_host: HostRouter::new(None, routes, static_mounts, auth_handler),
            vhosts: Vec::new(),
            max_body,
            max_streams,
            cors_origin,
            intent,
            describe_about,
            describe_api,
            private,
            domain: None,
            describe_version: None,
            docs_enabled: true,
            rate_limiter: RateLimiter::new(),
            active_streams: Mutex::new(0),
            error_handler: None,
            default_timeout: None,
            shutting_down: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
            active_cancels: Mutex::new(Vec::new()),
            on_shutdown: Mutex::new(None),
        }
    }

    /// `timeout N` del serve block (segundos; `None` = sin límite).
    pub fn set_default_timeout(&mut self, secs: Option<f64>) {
        self.default_timeout = secs.filter(|s| s.is_finite() && *s > 0.0);
    }

    /// Hook que corre al iniciar el drain del shutdown (lo cablea el runtime).
    pub fn set_on_shutdown(&self, f: Box<dyn Fn() + Send + Sync>) {
        if let Ok(mut g) = self.on_shutdown.lock() {
            *g = Some(f);
        }
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(AtomicOrd::Relaxed)
    }

    /// Requests en vuelo (para el drain y la observabilidad).
    pub fn inflight(&self) -> usize {
        self.inflight.load(AtomicOrd::Relaxed)
    }

    fn begin_request(&self, cancel: &CancelToken, dedicated: bool) {
        self.inflight.fetch_add(1, AtomicOrd::Relaxed);
        if let Ok(mut g) = self.active_cancels.lock() {
            g.push((cancel.clone(), dedicated));
        }
    }

    fn end_request(&self, cancel: &CancelToken) {
        self.inflight.fetch_sub(1, AtomicOrd::Relaxed);
        if let Ok(mut g) = self.active_cancels.lock() {
            let id = cancel.id();
            g.retain(|(t, _)| t.id() != id);
        }
    }

    /// Inicia el drain: no más requests nuevas; cancela los handlers long-lived
    /// (stream/socket) — los sized terminan solos dentro de la gracia. Devuelve
    /// cuántas requests quedaban en vuelo.
    pub fn begin_shutdown(&self) -> usize {
        self.shutting_down.store(true, AtomicOrd::SeqCst);
        if let Ok(g) = self.on_shutdown.lock() {
            if let Some(f) = g.as_ref() {
                f();
            }
        }
        if let Ok(g) = self.active_cancels.lock() {
            for (t, dedicated) in g.iter() {
                if *dedicated {
                    t.cancel("server shutting down");
                }
            }
        }
        self.inflight()
    }

    /// Vencida la gracia: cancela TODO lo que siga en vuelo.
    pub fn cancel_all_requests(&self) -> usize {
        let mut n = 0;
        if let Ok(g) = self.active_cancels.lock() {
            for (t, _) in g.iter() {
                t.cancel("server shutting down (grace period elapsed)");
                n += 1;
            }
        }
        n
    }

    /// Cablea la task de `errors with` (el runtime la construye como el auth handler).
    pub fn set_error_handler(&mut self, h: ErrorHandler) {
        self.error_handler = Some(h);
    }

    /// Registra un vhost (Lote 1): dominio exacto o `*.dominio` con su propia tabla
    /// (rutas/estáticos/auth). Se selecciona por el header `Host`.
    pub fn add_vhost(
        &mut self,
        pattern: String,
        routes: Vec<RouteSpec>,
        static_mounts: Vec<StaticMountSpec>,
        auth_handler: Option<AuthHandler>,
    ) {
        self.vhosts.push(HostRouter::new(Some(pattern), routes, static_mounts, auth_handler));
    }

    /// Selecciona el host por el header `Host`: exacto → wildcard → default.
    fn select_host(&self, host_header: &str) -> &HostRouter {
        if self.vhosts.is_empty() {
            return &self.default_host;
        }
        let h = host_header.split(':').next().unwrap_or("").trim();
        for vh in &self.vhosts {
            if matches!(&vh.pattern, Some(p) if !p.starts_with("*.") && h.eq_ignore_ascii_case(p)) {
                return vh;
            }
        }
        for vh in &self.vhosts {
            if matches!(&vh.pattern, Some(p) if p.starts_with("*.")) && vh.matches_host(h) {
                return vh;
            }
        }
        &self.default_host
    }

    pub fn route_count(&self) -> usize {
        self.default_host.routes.len()
    }
    pub fn cors_origin(&self) -> Option<&str> {
        self.cors_origin.as_deref()
    }

    fn try_acquire_stream(&self) -> bool {
        let mut n = self.active_streams.lock().unwrap();
        if *n >= self.max_streams {
            return false;
        }
        *n += 1;
        true
    }
    fn release_stream(&self) {
        let mut n = self.active_streams.lock().unwrap();
        if *n > 0 {
            *n -= 1;
        }
    }

    /// Métodos permitidos en `path` para el host default (lo usa OPTIONS).
    pub fn methods_for_path(&self, path: &str) -> Vec<String> {
        self.default_host.methods_for_path(path)
    }

    // -- discoverability --

    /// Base URL absoluta (spec discovery §1.3): `domain` del serve block si está; si
    /// no, el `Host` de la request. Esquema: https si hay TLS o el proxy de adelante
    /// dice `X-Forwarded-Proto: https`. Sin `Host` ni `domain` no hay verdad → None.
    fn base_url(&self, headers: &[(String, String)]) -> Option<String> {
        let fwd = header_value(headers, "x-forwarded-proto");
        let https = self.tls_enabled
            || fwd.split(',').next().map(|s| s.trim().eq_ignore_ascii_case("https")).unwrap_or(false);
        let host = match &self.domain {
            Some(d) => d.clone(),
            None => {
                let h = header_value(headers, "host");
                if h.is_empty() {
                    return None;
                }
                h
            }
        };
        Some(format!("{}://{}", if https { "https" } else { "http" }, host))
    }

    /// La tabla de un host como rutas "secas" (lo que discovery emite).
    fn api_routes(host: &HostRouter) -> Vec<ApiRoute> {
        host.routes
            .iter()
            .map(|r| ApiRoute {
                method: r.method.clone(),
                path: r.path.clone(),
                param_names: r.param_names.clone(),
                requires_auth: r.requires_auth,
                streaming: r.streaming,
                socket: r.socket,
                rate_limit: r.rate_limit,
                rate_unlimited: r.rate_unlimited,
                proxy: r.proxy_target.is_some(),
                meta: r.meta.clone(),
            })
            .collect()
    }

    fn api_info(&self, host: &HostRouter, headers: &[(String, String)]) -> ApiInfo {
        let title = ApiInfo::title_of(self.describe_about.as_deref(), self.intent.as_deref());
        ApiInfo {
            title,
            description: self.intent.clone(),
            version: self.describe_version.clone().unwrap_or_else(|| "0.0.0".to_string()),
            base_url: self.base_url(headers),
            has_auth: host.auth_handler.is_some() && host.routes.iter().any(|r| r.requires_auth),
            describe_api: self.describe_api.clone(),
        }
    }

    fn llms_txt(&self, host: &HostRouter) -> String {
        let title = ApiInfo::title_of(self.describe_about.as_deref(), self.intent.as_deref());
        let mut lines = vec![format!("# {}", title)];
        if let Some(intent) = &self.intent {
            if *intent != title {
                lines.push(String::new());
                lines.push(format!("> {}", intent));
            }
        }
        let routes = Self::api_routes(host);
        let mut endpoints: Vec<(String, String, String)> = routes
            .iter()
            .map(|r| (r.path.clone(), r.method.clone(), discovery::caps_suffix(r)))
            .collect();
        endpoints.sort();
        endpoints.dedup();
        if !endpoints.is_empty() {
            lines.push(String::new());
            lines.push("## Endpoints".to_string());
            for (p, m, caps) in &endpoints {
                // Sufijo `[net:host, llm]`: lo que la ruta PUEDE tocar según su contrato.
                lines.push(format!("- {} {}{}", m, p, caps));
            }
        }
        if !self.describe_api.is_empty() {
            lines.push(String::new());
            lines.push("## API".to_string());
            for item in &self.describe_api {
                lines.push(format!("- {}", item));
            }
        }
        lines.push(String::new());
        lines.push("## Machine-readable".to_string());
        lines.push("- /openapi.json".to_string());
        if self.docs_enabled {
            lines.push("- /docs".to_string());
        }
        lines.push("- /sitemap.xml".to_string());
        lines.push("- /.well-known/synsema-auth".to_string());
        lines.join("\n") + "\n"
    }

    fn robots_txt(&self, base: Option<&str>) -> String {
        if self.private {
            return "User-agent: *\nDisallow: /\n".to_string();
        }
        match base {
            Some(b) => format!("User-agent: *\nAllow: /\nSitemap: {}/sitemap.xml\n", b),
            None => "User-agent: *\nAllow: /\n".to_string(),
        }
    }

    /// T6.5 — descubrimiento máquina-a-máquina: qué formas de autenticación
    /// entiende este server, en JSON. `/llms.txt` le dice a un agente QUÉ hace el
    /// servicio; esto le dice CÓMO autenticarse, sin leer documentación humana.
    ///
    /// Se deriva de lo que el server realmente tiene cableado (no es una promesa
    /// declarativa): si ninguna ruta pide auth, la lista de mecanismos va vacía.
    fn auth_discovery(&self) -> String {
        let requires_auth = self.default_host.routes.iter().any(|r| r.requires_auth)
            || self.vhosts.iter().any(|h| h.routes.iter().any(|r| r.requires_auth));
        let has_handler = self.default_host.auth_handler.is_some()
            || self.vhosts.iter().any(|h| h.auth_handler.is_some());
        let mut mechanisms: Vec<Json> = Vec::new();
        if requires_auth && has_handler {
            // El transporte del credencial siempre es el mismo (Authorization:
            // Bearer o cookie de sesión); lo que varía es QUÉ se manda, y eso lo
            // resuelve el auth task del programa. Se anuncian las formas que el
            // engine sabe verificar de fábrica.
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("bearer".into())),
                ("transport", Json::Str("Authorization: Bearer <token>".into())),
                (
                    "token_types",
                    Json::Array(vec![
                        Json::Str("captoken".into()),
                        Json::Str("jwt".into()),
                        Json::Str("opaque".into()),
                    ]),
                ),
            ]));
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("cookie".into())),
                ("transport", Json::Str("Cookie: <name>=<session id>".into())),
            ]));
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("http-message-signature".into())),
                ("profile", Json::Str("rfc9421-pinned".into())),
                (
                    "covered",
                    Json::Array(vec![
                        Json::Str("@method".into()),
                        Json::Str("@target-uri".into()),
                        Json::Str("content-digest".into()),
                    ]),
                ),
                (
                    "algorithms",
                    Json::Array(vec![Json::Str("ed25519".into()), Json::Str("hmac-sha256".into())]),
                ),
            ]));
        }
        // Rutas protegidas: un agente sabe adónde puede ir sin probar a ciegas.
        let mut protected: Vec<Json> = self
            .default_host
            .routes
            .iter()
            .filter(|r| r.requires_auth)
            .map(|r| Json::Str(format!("{} {}", r.method, r.path)))
            .collect();
        protected.sort_by(|a, b| match (a, b) {
            (Json::Str(x), Json::Str(y)) => x.cmp(y),
            _ => std::cmp::Ordering::Equal,
        });
        dumps(&obj(vec![
            ("service", Json::Str(self.describe_about.clone().or_else(|| self.intent.clone()).unwrap_or_else(|| "Synsema service".to_string()))),
            ("authentication", Json::Array(mechanisms)),
            ("protected_endpoints", Json::Array(protected)),
        ]))
    }

    /// Las superficies auto-generadas. Se consultan DESPUÉS de las rutas declaradas
    /// y de los estáticos (dispatch), así una `route "GET /docs"` propia gana. Con
    /// `private` sólo queda `/robots.txt` (y dice `Disallow: /`).
    fn discovery_response(
        &self,
        path: &str,
        headers: &[(String, String)],
        host: &HostRouter,
    ) -> Option<RawResponse> {
        if path == "/llms.txt" && !self.private {
            return Some(RawResponse::text(self.llms_txt(host), "text/plain; charset=utf-8", 200));
        }
        if path == "/openapi.json" && !self.private {
            let info = self.api_info(host, headers);
            let doc = discovery::openapi_json(&info, &Self::api_routes(host));
            return Some(RawResponse::text(dumps(&doc), "application/json; charset=utf-8", 200));
        }
        if path == "/sitemap.xml" && !self.private {
            let base = self.base_url(headers)?;
            return Some(RawResponse::text(
                discovery::sitemap_xml(&base, &Self::api_routes(host)),
                "application/xml; charset=utf-8",
                200,
            ));
        }
        if path == "/docs" && !self.private && self.docs_enabled {
            // Negociada como `content()`: HTML para humanos, Markdown para agentes.
            let info = self.api_info(host, headers);
            let fmt = negotiate_format(&header_value(headers, "accept"));
            return Some(if fmt == "md" {
                RawResponse::text(discovery::docs_markdown(&info, &Self::api_routes(host)), "text/markdown; charset=utf-8", 200)
            } else {
                RawResponse::text(discovery::docs_html(&info), "text/html; charset=utf-8", 200)
            });
        }
        // Mismo criterio de `private` que /llms.txt: un server interno no publica
        // su superficie de auth.
        if path == "/.well-known/synsema-auth" && !self.private {
            return Some(RawResponse::text(
                self.auth_discovery(),
                "application/json; charset=utf-8",
                200,
            ));
        }
        if path == "/robots.txt" {
            let base = self.base_url(headers);
            return Some(RawResponse::text(self.robots_txt(base.as_deref()), "text/plain; charset=utf-8", 200));
        }
        None
    }

    /// 500 con `errors with`: el detalle SIEMPRE va al log del server (server_error);
    /// a la task le llega el mismo texto que vería el cliente (redactado bajo --secure,
    /// para que una página de error custom jamás re-filtre internals en producción).
    fn shape_500(
        &self,
        detail: &str,
        ctx: &Ctx,
        extra: &mut Vec<(String, String)>,
    ) -> (u16, ResponseBody) {
        let default_body = self.server_error(detail);
        let msg = if self.secure { "internal server error" } else { detail };
        if let Some((st, body, hdrs)) = self.custom_error(500, msg, ctx) {
            extra.extend(hdrs);
            return (st, body);
        }
        (500, default_body)
    }

    /// `errors with`: intenta dar forma custom a un error del runtime. El STATUS del
    /// error SE CONSERVA (jamás un 200 para un 404 — nada de soft-404), con una sola
    /// excepción: si la task devuelve `redirect()`, su 3xx + Location se respetan
    /// (patrón "401 → redirect al login"). `nothing` (o un error en la task) → None
    /// y el JSON por defecto sigue intacto.
    fn custom_error(
        &self,
        status: u16,
        message: &str,
        ctx: &Ctx,
    ) -> Option<(u16, ResponseBody, Vec<(String, String)>)> {
        let handler = self.error_handler.as_ref()?;
        let v = handler(i64::from(status), message, ctx)?;
        if matches!(v, SynValue::Nothing) {
            return None;
        }
        // with_header()/set_cookie(): desenvolver el wrapper, igual que en dispatch.
        let mut hdrs: Vec<(String, String)> = Vec::new();
        let v = match v {
            SynValue::Server(s) => match &*s {
                ServerValue::WithHeaders { inner, headers } => {
                    hdrs = headers.clone();
                    (**inner).clone()
                }
                _ => SynValue::Server(s),
            },
            other => other,
        };
        // content() → negociado por Accept: la misma página de error sale como HTML
        // al navegador y Markdown/JSON a un agente.
        let is_content =
            matches!(&v, SynValue::Server(s) if matches!(&**s, ServerValue::Content(_)));
        if is_content {
            let fmt = negotiate_format(&header_value(&ctx.headers, "accept"));
            let raw = render_content(&v, &fmt);
            return Some((status, ResponseBody::Raw(raw), hdrs));
        }
        match build_response(Some(&v), &ctx.query) {
            Ok((st, body)) => match body {
                ResponseBody::Redirect { .. } => Some((st, body, hdrs)),
                other => Some((status, other, hdrs)),
            },
            Err(_) => None,
        }
    }

    fn server_error(&self, detail: &str) -> ResponseBody {
        // Un handler CANCELADO (timeout de la ruta → el cliente ya recibió 504; shutdown)
        // no es un 500 del programa: el log lo dice con su nombre.
        if detail.starts_with("cancelled") {
            eprintln!("[serve:{}] handler {}", self.port, detail);
        } else {
            eprintln!("[serve:{}] 500 {}", self.port, detail);
        }
        let body = if self.secure {
            obj(vec![("error", Json::Str("internal server error".into())), ("status", Json::Int(500))])
        } else {
            obj(vec![("error", Json::Str(detail.to_string())), ("status", Json::Int(500))])
        };
        ResponseBody::Json(body)
    }

    // -- dispatch --

    /// ¿La ruta que matchearía esta request está declarada como `stream`? Resuelve sólo
    /// vhost + match de ruta (mismo criterio que el primer match de `dispatch`), sin correr
    /// auth ni el handler. Sirve para elegir el hilo: streams → hilo dedicado; sized → pool.
    pub fn route_is_streaming(&self, method: &str, path: &str, headers: &[(String, String)]) -> bool {
        self.route_plan(method, path, headers).dedicated
    }

    /// Plan de atención de la request (hilo, socket, timeout) — resolución barata
    /// (vhost + match de ruta, sin auth ni handler). Los streams y sockets (long-lived,
    /// `Ctx` !Send) van a hilo dedicado; el timeout efectivo es route > serve.
    pub fn route_plan(&self, method: &str, path: &str, headers: &[(String, String)]) -> RoutePlan {
        let host = self.select_host(&header_value(headers, "host"));
        match host.match_route(method, path) {
            Some((i, _)) => {
                let r = &host.routes[i];
                RoutePlan {
                    dedicated: r.streaming || r.socket,
                    socket: r.socket,
                    proxy: r.proxy_target.is_some(),
                    timeout: r.timeout.or(self.default_timeout).filter(|t| t.is_finite() && *t > 0.0),
                }
            }
            None => RoutePlan::default(),
        }
    }

    /// ¿La request es de las rutas reservadas `/approvals`? (Sólo si el runtime cableó
    /// la cola.) Lo usa también el lado de conexión para atenderlas en un hilo DEDICADO
    /// (no el pool del intérprete): un gate bloqueado espera su respuesta ocupando un
    /// worker — la respuesta no puede quedar en cola detrás de él.
    /// Formas: `GET /approvals` (lista), `POST /approvals/{id}` (respuesta con token en
    /// el body), `GET /approvals/{id}/{token}` (link de decisión sí/no, A1.v3).
    pub fn is_approvals_route(&self, method: &str, path: &str) -> bool {
        if self.approvals.is_none() {
            return false;
        }
        if method == "GET" && path == "/approvals" {
            return true;
        }
        let Some(rest) = path.strip_prefix("/approvals/") else { return false };
        let segs: Vec<&str> = rest.split('/').collect();
        match (method, segs.as_slice()) {
            ("POST", [id]) => !id.is_empty(),
            ("GET", [id, token]) => !id.is_empty() && !token.is_empty(),
            _ => false,
        }
    }

    /// Página HTML mínima autocontenida de un link de aprobación (A1.v3) — para el
    /// humano que abrió la URL desde SMS/chat. NUNCA incluye el token.
    fn approval_link_page(status: u16, title: &str, detail: &str) -> Dispatched {
        let html = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Synsema approval</title>\
             </head><body style=\"font-family: system-ui, sans-serif; max-width: 40rem; \
             margin: 4rem auto; padding: 0 1rem;\"><h1>{}</h1><p>{}</p></body></html>",
            title, detail
        );
        Dispatched::Response {
            status,
            body: ResponseBody::Raw(RawResponse::text(html, "text/html; charset=utf-8", status)),
            headers: vec![],
        }
    }

    /// Atiende las rutas reservadas `/approvals`. D4: `GET /approvals` lista las
    /// pendientes SIN tokens; `POST /approvals/{id}` con `{"token", "decision"}` (o
    /// `{"token", "value"}` para ask) responde el gate → 200/400/403/404; el link
    /// `GET /approvals/{id}/{token}?d=yes|no` (A1.v3) responde SOLO decisión sí/no
    /// (mismo camino: token de un solo uso) y devuelve HTML para el humano.
    fn approvals_response(
        &self,
        method: &str,
        path: &str,
        query: &IndexMap<String, String>,
        body_str: &str,
    ) -> Dispatched {
        let gw = self.approvals.as_ref().expect("is_approvals_route lo garantiza");
        let resp = |status, body| Dispatched::Response { status, body, headers: vec![] };
        let err = |status: u16, msg: &str| {
            resp(
                status,
                ResponseBody::Json(obj(vec![
                    ("error", Json::Str(msg.to_string())),
                    ("status", Json::Int(status as i64)),
                ])),
            )
        };
        if method == "GET" && path == "/approvals" {
            let items: Vec<Json> = gw
                .list()
                .into_iter()
                .map(|s| {
                    obj(vec![
                        ("id", Json::Str(s.id)),
                        ("message", Json::Str(s.message)),
                        ("type", Json::Str(s.ty)),
                        ("expires_at", Json::Int(s.expires_at)),
                    ])
                })
                .collect();
            return resp(200, ResponseBody::Json(obj(vec![("pending", Json::Array(items))])));
        }
        if method == "GET" {
            // Link de decisión (A1.v3): /approvals/{id}/{token}?d=yes|no. Respuestas
            // en HTML (el humano viene de un SMS/chat); sí/no solamente — `ask` con
            // `value` sigue siendo POST-only.
            let rest = path.strip_prefix("/approvals/").unwrap_or_default();
            let (id, token) = rest.split_once('/').unwrap_or((rest, ""));
            let approve = match query.get("d").map(String::as_str) {
                Some("yes") => true,
                Some("no") => false,
                _ => {
                    return Self::approval_link_page(
                        400,
                        "Missing decision",
                        "This approval link needs a decision parameter: append ?d=yes to \
                         approve or ?d=no to deny.",
                    )
                }
            };
            return match gw.respond(id, token, Some(approve), None) {
                ApprovalOutcome::Accepted => {
                    let (title, verb) =
                        if approve { ("Approved", "approved") } else { ("Denied", "denied") };
                    Self::approval_link_page(
                        200,
                        title,
                        &format!(
                            "The pending step was {}. This decision was recorded from a \
                             HUMAN following an approval link. You can close this tab.",
                            verb
                        ),
                    )
                }
                ApprovalOutcome::NotFound => Self::approval_link_page(
                    404,
                    "Not found",
                    "This approval link is no longer valid — the request may have expired, \
                     or a HUMAN already answered it.",
                ),
                ApprovalOutcome::BadToken => Self::approval_link_page(
                    403,
                    "Invalid link",
                    "The token in this link is not valid for this approval. The gate is \
                     still waiting for a HUMAN with the correct link.",
                ),
            };
        }
        let id = path.strip_prefix("/approvals/").unwrap_or_default();
        let parsed: serde_json::Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(_) => {
                return err(
                    400,
                    "malformed body — expected JSON {\"token\": \"...\", \"decision\": true|false} \
                     or {\"token\": \"...\", \"value\": \"text\"}",
                )
            }
        };
        let token = match parsed.get("token").and_then(|t| t.as_str()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => return err(400, "missing \"token\" — the one-time token was printed on the server console when the approval was queued"),
        };
        let decision = parsed.get("decision").and_then(|d| d.as_bool());
        let value = parsed.get("value").and_then(|v| v.as_str());
        if decision.is_none() && value.is_none() {
            return err(
                400,
                "missing \"decision\" (true|false, for approve/confirm) or \"value\" (text, for ask)",
            );
        }
        match gw.respond(id, &token, decision, value) {
            ApprovalOutcome::Accepted => {
                resp(200, ResponseBody::Json(obj(vec![("ok", Json::Bool(true))])))
            }
            ApprovalOutcome::NotFound => err(
                404,
                "no pending approval with that id — it may have expired, or a HUMAN already answered it",
            ),
            ApprovalOutcome::BadToken => err(
                403,
                "invalid token for this approval — the gate is still waiting for a HUMAN with the correct token",
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        method: &str,
        path: &str,
        query: IndexMap<String, String>,
        headers: Vec<(String, String)>,
        body_str: &str,
        body_raw: &[u8],
        body_file: Option<&str>,
        client_ip: &str,
        cancel: CancelToken,
    ) -> Dispatched {
        let resp = |status, body| Dispatched::Response { status, body, headers: vec![] };

        // Rutas reservadas `/approvals` (A1.v2/v3): interceptadas ANTES de las rutas
        // de usuario (como `/llms.txt`); sólo existen si el runtime cableó la cola.
        if self.is_approvals_route(method, path) {
            return self.approvals_response(method, path, &query, body_str);
        }

        // vhost (Lote 1): elegir la tabla del host según el header `Host`. Sin vhosts
        // declarados, `host` es siempre el default → comportamiento idéntico al previo.
        let host = self.select_host(&header_value(&headers, "host"));

        let (mut route_idx, mut params) = match host.match_route(method, path) {
            Some((i, p)) => (Some(i), p),
            None => (None, IndexMap::new()),
        };

        // Negociación por sufijo de URL (.md/.json/.html): sólo si un :param se
        // tragó el sufijo. Un estático real en el path exacto gana primero.
        let mut explicit_fmt: Option<String> = None;
        let (logical_path, sfx) = split_format_suffix(path);
        if let (Some(s), Some(idx)) = (sfx, route_idx) {
            if param_last_segment(&host.routes[idx].path) {
                if method == "GET" && !host.static_mounts.is_empty() {
                    if let Some(sr) = host.serve_static_full(path, &headers) {
                        return Dispatched::Response {
                            status: sr.status,
                            body: ResponseBody::Raw(RawResponse {
                                body: sr.body,
                                content_type: sr.content_type,
                                status: sr.status,
                            }),
                            headers: sr.extra,
                        };
                    }
                }
                if let Some((lidx, lparams)) = host.match_route(method, &logical_path) {
                    route_idx = Some(lidx);
                    params = lparams;
                    explicit_fmt = Some(s);
                }
            }
        }

        let idx = match route_idx {
            Some(i) => i,
            None => {
                let allowed = host.methods_for_path(path);
                if !allowed.is_empty() {
                    // 405 — `errors with` puede darle forma; el header Allow se conserva.
                    if self.error_handler.is_some() {
                        let ectx = min_ctx(method, path, &query, &headers, body_str, body_raw, body_file, client_ip);
                        if let Some((st, body, mut hdrs)) = self.custom_error(405, "method not allowed", &ectx) {
                            hdrs.push(("Allow".to_string(), allowed.join(", ")));
                            return Dispatched::Response { status: st, body, headers: hdrs };
                        }
                    }
                    return Dispatched::Response {
                        status: 405,
                        body: ResponseBody::Json(obj(vec![
                            ("error", Json::Str("method not allowed".into())),
                            ("status", Json::Int(405)),
                        ])),
                        headers: vec![("Allow".to_string(), allowed.join(", "))],
                    };
                }
                if method == "GET" {
                    if !host.static_mounts.is_empty() {
                        if let Some(sr) = host.serve_static_full(path, &headers) {
                            return Dispatched::Response {
                                status: sr.status,
                                body: ResponseBody::Raw(RawResponse {
                                    body: sr.body,
                                    content_type: sr.content_type,
                                    status: sr.status,
                                }),
                                headers: sr.extra,
                            };
                        }
                    }
                    if let Some(disc) = self.discovery_response(path, &headers, host) {
                        return resp(disc.status, ResponseBody::Raw(disc));
                    }
                }
                let msg = format!("no route for {} {}", method, path);
                if self.error_handler.is_some() {
                    let ectx = min_ctx(method, path, &query, &headers, body_str, body_raw, body_file, client_ip);
                    if let Some((st, body, hdrs)) = self.custom_error(404, &msg, &ectx) {
                        return Dispatched::Response { status: st, body, headers: hdrs };
                    }
                }
                return resp(
                    404,
                    ResponseBody::Json(obj(vec![
                        ("error", Json::Str(msg)),
                        ("status", Json::Int(404)),
                    ])),
                );
            }
        };

        // Rate limit (tras matchear la ruta, antes de auth/handler).
        let mut rate_headers: Vec<(String, String)> = Vec::new();
        if let Some((capacity, window)) = host.routes[idx].rate_limit {
            let zone = host.routes[idx].rate_zone.clone().unwrap_or_else(|| "None".to_string());
            let key = format!("{}|{}", zone, client_ip);
            let (ok, remaining, retry_after, reset) = self.rate_limiter.check(&key, capacity, window);
            rate_headers = vec![
                ("RateLimit-Limit".to_string(), capacity.to_string()),
                ("RateLimit-Remaining".to_string(), remaining.to_string()),
                ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
            ];
            if !ok {
                let headers_429 = vec![
                    ("RateLimit-Limit".to_string(), capacity.to_string()),
                    ("RateLimit-Remaining".to_string(), "0".to_string()),
                    ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
                    ("Retry-After".to_string(), (retry_after as i64 + 1).to_string()),
                ];
                return Dispatched::Response {
                    status: 429,
                    body: ResponseBody::Json(obj(vec![
                        ("error", Json::Str("rate limit exceeded".into())),
                        ("status", Json::Int(429)),
                    ])),
                    headers: headers_429,
                };
            }
        }

        // Parse del body JSON (sólo error si el cliente declaró JSON).
        let mut json_obj: Option<serde_json::Value> = None;
        if !body_str.is_empty() {
            let ctype = header_value(&headers, "content-type").to_lowercase();
            match serde_json::from_str::<serde_json::Value>(body_str) {
                Ok(v) => json_obj = Some(v),
                Err(_) => {
                    if ctype.contains("json") {
                        return Dispatched::Response {
                            status: 400,
                            body: ResponseBody::Json(obj(vec![
                                ("error", Json::Str("malformed JSON body".into())),
                                ("status", Json::Int(400)),
                            ])),
                            headers: vec![],
                        };
                    }
                }
            }
        }

        let mut ctx = Ctx {
            method: method.to_string(),
            path: path.to_string(),
            query,
            params,
            headers: headers.clone(),
            body: body_str.to_string(),
            body_raw: body_raw.to_vec(),
            body_file: body_file.map(|s| s.to_string()),
            json: json_obj,
            client_ip: client_ip.to_string(),
            user: None,
            cancel,
        };

        // Auth. El `ctx` ya existe (user aún nothing) — el hook lo recibe entero
        // para tasks de 2 parámetros (sesiones por cookie, ítem C).
        if host.routes[idx].requires_auth {
            let token = bearer_token(&headers);
            let user = host.auth_handler.as_ref().and_then(|ah| ah(&token, &ctx));
            match &user {
                None | Some(SynValue::Nothing) => {
                    // 401 — `errors with` puede redirigir al login o dar una página.
                    if let Some((st, body, mut hdrs)) = self.custom_error(401, "unauthorized", &ctx) {
                        hdrs.extend(rate_headers);
                        return Dispatched::Response { status: st, body, headers: hdrs };
                    }
                    return Dispatched::Response {
                        status: 401,
                        body: ResponseBody::Json(obj(vec![
                            ("error", Json::Str("unauthorized".into())),
                            ("status", Json::Int(401)),
                        ])),
                        headers: rate_headers,
                    };
                }
                Some(_) => ctx.user = user,
            }
            // T6.4 — SEGUNDA etapa del rate limit: por IDENTIDAD del sujeto ya
            // autenticado, en su propio namespace de buckets.
            //
            // Por qué DOS etapas y no mover la primera acá: el chequeo por IP corre
            // antes del auth a propósito, porque el auth task ejecuta el intérprete
            // (un worker del pool por request). Si el único límite fuera por
            // identidad, un atacante sin credenciales válidas quemaría workers
            // gratis — el limitador dejaría de frenar justo el ataque que hoy sí
            // frena. Con las dos, el presupuesto efectivo es el mínimo de ambos:
            // la IP acota al anónimo, la identidad evita que agentes distintos
            // detrás del mismo NAT se roben la cuota entre sí.
            if let Some((capacity, window)) = host.routes[idx].rate_limit {
                if let Some(id) = ctx.user.as_ref().and_then(identity_of) {
                    let zone = host.routes[idx].rate_zone.as_deref().unwrap_or("None");
                    let key = format!("user:{}|{}", zone, id);
                    let (ok, remaining, retry_after, reset) =
                        self.rate_limiter.check(&key, capacity, window);
                    // Los headers reflejan el cupo de la identidad (el más
                    // informativo para un cliente autenticado).
                    rate_headers = vec![
                        ("RateLimit-Limit".to_string(), capacity.to_string()),
                        ("RateLimit-Remaining".to_string(), remaining.to_string()),
                        ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
                    ];
                    if !ok {
                        let mut headers_429 = rate_headers.clone();
                        headers_429[1] = ("RateLimit-Remaining".to_string(), "0".to_string());
                        headers_429.push((
                            "Retry-After".to_string(),
                            (retry_after as i64 + 1).to_string(),
                        ));
                        return Dispatched::Response {
                            status: 429,
                            body: ResponseBody::Json(obj(vec![
                                ("error", Json::Str("rate limit exceeded".into())),
                                ("status", Json::Int(429)),
                            ])),
                            headers: headers_429,
                        };
                    }
                }
            }
        }

        // Reverse proxy: auth/rate-limit/vhost ya se resolvieron acá (sync). El forward
        // en sí lo hace el lado async (`proxy_request`) en streaming: SSE, upgrade
        // WebSocket (túnel) y bodies grandes pasan a medida que llegan.
        if let Some(target) = &host.routes[idx].proxy_target {
            return Dispatched::Proxy { target: target.clone(), headers: rate_headers };
        }

        // Socket entrante (ruta `socket`): ocupa un slot de stream (conexión larga con
        // hilo propio) y delega al camino de socket. El upgrade HTTP lo hace el lado
        // async (que ya validó los headers de RFC 6455 antes de llegar acá).
        if host.routes[idx].socket {
            if !self.try_acquire_stream() {
                return Dispatched::Response {
                    status: 503,
                    body: ResponseBody::Json(obj(vec![
                        ("error", Json::Str("too many concurrent streams".into())),
                        ("status", Json::Int(503)),
                    ])),
                    headers: vec![("Retry-After".to_string(), "5".to_string())],
                };
            }
            return Dispatched::Socket {
                socket_handler: host.routes[idx].socket_handler.clone(),
                ctx: Box::new(ctx),
            };
        }

        // Streaming SSE: adquirir slot y delegar al camino de stream.
        if host.routes[idx].streaming {
            if !self.try_acquire_stream() {
                return Dispatched::Response {
                    status: 503,
                    body: ResponseBody::Json(obj(vec![
                        ("error", Json::Str("too many concurrent streams".into())),
                        ("status", Json::Int(503)),
                    ])),
                    headers: vec![("Retry-After".to_string(), "5".to_string())],
                };
            }
            return Dispatched::Stream {
                stream_handler: host.routes[idx].stream_handler.clone(),
                ctx: Box::new(ctx),
            };
        }

        // Correr el handler.
        let mut custom_headers: Vec<(String, String)> = Vec::new();
        let (status, body) = match (host.routes[idx].handler)(&ctx) {
            GiveOutcome::Give(v) => {
                // with_header()/set_cookie(): desenvolver el wrapper — `inner` se
                // procesa exactamente como cualquier give-value y los headers
                // acumulados se emiten al final (después de los de rate-limit).
                // Cubre TODOS los caminos de salida: respuesta directa, negociación
                // de contenido, envelope JSON y redirect.
                let v = match v {
                    Some(SynValue::Server(s)) => match &*s {
                        ServerValue::WithHeaders { inner, headers } => {
                            custom_headers = headers.clone();
                            Some((**inner).clone())
                        }
                        _ => Some(SynValue::Server(s)),
                    },
                    other => other,
                };
                let is_content = matches!(
                    v.as_ref(),
                    Some(SynValue::Server(s)) if matches!(&**s, ServerValue::Content(_))
                );
                if is_content {
                    // content() se negocia: sufijo explícito (.md/.json/.html) gana,
                    // si no el header Accept (default HTML).
                    let fmt = explicit_fmt
                        .clone()
                        .unwrap_or_else(|| negotiate_format(&header_value(&ctx.headers, "accept")));
                    let raw = render_content(v.as_ref().unwrap(), &fmt);
                    (raw.status, ResponseBody::Raw(raw))
                } else {
                    match build_response(v.as_ref(), &ctx.query) {
                        Ok(sb) => sb,
                        Err(e) => self.shape_500(&e, &ctx, &mut custom_headers),
                    }
                }
            }
            GiveOutcome::Validation { message, field } => (
                400,
                ResponseBody::Json(obj(vec![
                    ("error", Json::Str(message)),
                    ("status", Json::Int(400)),
                    ("field", field.map(Json::Str).unwrap_or(Json::Null)),
                ])),
            ),
            GiveOutcome::Error(msg) => self.shape_500(&msg, &ctx, &mut custom_headers),
        };
        let mut headers = rate_headers;
        headers.append(&mut custom_headers);
        Dispatched::Response { status, body, headers }
    }
}

// -- helpers de matching/estáticos (libres) --

fn norm_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return "/".to_string();
    }
    format!("/{}/", prefix.trim_matches('/'))
}

fn within(base: &Path, target: &Path) -> bool {
    target == base || target.starts_with(base)
}

/// Resuelve `rel` a un archivo real dentro de `base` (anti-traversal), o None.
fn resolve_in(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel = unquote(rel);
    let rel = rel.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // Path absoluto o con drive-letter (C:) no puede estar dentro de uno relativo.
    if Path::new(rel).is_absolute() || (rel.len() > 1 && rel.as_bytes()[1] == b':') {
        return None;
    }
    let mut target = base.join(rel).canonicalize().ok()?;
    if !within(base, &target) {
        return None;
    }
    if target.is_dir() {
        target = target.join("index.html").canonicalize().ok()?;
        if !within(base, &target) {
            return None;
        }
    }
    if !target.is_file() {
        return None;
    }
    Some(target)
}

fn static_content_type(path: &Path) -> String {
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    // Web types pinneadas (el contrato, deterministas entre hosts).
    if let Some(t) = web_content_type(&ext) {
        return t.to_string();
    }
    // Fallback: mimetypes.guess_type (tabla incorporada + registro de Windows).
    match crate::mimetypes::guess(&ext) {
        None => "application/octet-stream".to_string(),
        Some(ct) => {
            if ct.starts_with("text/") && !ct.contains("charset") {
                format!("{}; charset=utf-8", ct)
            } else {
                ct
            }
        }
    }
}

// Builtins de respuesta + vocabulario de contenido: EXTRAIDOS a respond.rs (modulo
// puro, compartido con el perfil wasm). Re-export para runtime/tests; parse_cookies
// (lado request) y los renderers HTML/MD del arbol siguen aca.
pub use crate::respond::register_serve_builtins;

// =========================================================
// Servidor HTTP (thread-per-connection, std::net)
// =========================================================

/// A2 batch 2 — Mapa compartido token→key-authorization que el listener HTTP sirve
/// para los challenges ACME HTTP-01.
pub type ChallengeStore = std::sync::Arc<std::sync::Mutex<HashMap<String, String>>>;

/// A2 batch 2 — Config TLS compartida y mutable (renovación ACME hace hot-swap).
pub type SharedServerConfig = std::sync::Arc<std::sync::RwLock<Arc<rustls::ServerConfig>>>;

// =========================================================
// Lote 2 — Servidor async (tokio/hyper/rustls)
// =========================================================
//
// Cáscara async: tokio acepta, hyper hace el framing HTTP/1.1+HTTP/2 (ALPN), y el
// intérprete corre SYNC por request en `spawn_blocking` (igual modelo snapshot-globales
// que antes). El `dispatch` se reusa intacto → mismas respuestas (byte-paridad sobre
// HTTP/1.1; el harness compara status+headers+body parseados).

/// Cuerpo de respuesta unificado (Full para sized, canal para SSE).
type RespBody = BoxBody<Bytes, std::convert::Infallible>;

/// Stack grande para los hilos que corren el intérprete: el tree-walker tiene guard de
/// recursión, pero le damos holgura como el viejo thread-per-conn (fib, tasks recursivas
/// profundas). Vive SOLO en el pool del intérprete y en los hilos de stream — NO en los
/// workers async de I/O de tokio (esos usan stack default).
const SERVE_STACK_SIZE: usize = 64 * 1024 * 1024;

/// Pool dedicado y ACOTADO para correr el intérprete sync por request.
///
/// Reemplaza el `spawn_blocking` por-request, que crecía contra el blocking pool de tokio
/// (hasta 512 hilos) heredando el stack de 64 MB → bajo keep-alive, N requests en vuelo =
/// N × 64 MB → OOM. Acá el tope es fijo: `#workers × 64 MB`, sin importar la concurrencia.
/// El exceso de requests **espera en la cola** (no se rechaza). El intérprete sigue sync.
///
/// Streams (SSE) NO usan este pool: corren en un hilo dedicado (acotado por `max_streams`)
/// para no agotar los workers — si no, unos pocos streams taparían el pool entero.
type InterpJob = Box<dyn FnOnce() + Send + 'static>;

struct InterpreterPool {
    tx: std::sync::mpsc::Sender<InterpJob>,
}

impl InterpreterPool {
    fn new(workers: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<InterpJob>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..workers {
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("synsema-interp-{}", i))
                .stack_size(SERVE_STACK_SIZE)
                .spawn(move || loop {
                    // El lock se sostiene solo durante el `recv` (handoff instantáneo);
                    // el job corre fuera del lock → los workers ejecutan en paralelo.
                    let job = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(_) => return,
                        };
                        guard.recv()
                    };
                    match job {
                        // Un panic del handler NO debe matar al worker: se traga acá; los
                        // canales del job se dropean y el lado async responde 500. Seguimos.
                        Ok(job) => {
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                        }
                        Err(_) => return, // canal cerrado: el proceso termina
                    }
                });
        }
        InterpreterPool { tx }
    }

    fn submit(&self, job: InterpJob) {
        let _ = self.tx.send(job);
    }
}

static INTERP_POOL: std::sync::OnceLock<InterpreterPool> = std::sync::OnceLock::new();

/// El pool del intérprete, inicializado una vez. Tamaño: `SYNSEMA_SERVE_WORKERS` si está
/// seteado (>=1), si no `#cores` (mín. 2). El env es el escape hatch para deploys con
/// handlers I/O-bound (más workers = más concurrencia de I/O, a costa de más RAM); el
/// default acota la memoria. La concurrencia real de I/O sin tope la dará el intérprete
/// async (diferido), no subir esto sin límite.
fn interp_pool() -> &'static InterpreterPool {
    INTERP_POOL.get_or_init(|| {
        let workers = std::env::var("SYNSEMA_SERVE_WORKERS")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .max(2)
            });
        InterpreterPool::new(workers)
    })
}

#[derive(Clone)]
enum TlsMode {
    Plain,
    Fixed(Arc<rustls::ServerConfig>),
    Swap(SharedServerConfig),
}

/// Loop de accept async. Bloquea para siempre (arma su propio runtime tokio).
pub fn serve_forever(rt: Arc<ServeRuntime>, listener: TcpListener) {
    run_async(rt, listener, TlsMode::Plain);
}

/// HTTPS con cert fijo (TLS manual). Bind/handshake fallido cierra esa conexión.
pub fn serve_forever_tls(rt: Arc<ServeRuntime>, listener: TcpListener, config: Arc<rustls::ServerConfig>) {
    run_async(rt, listener, TlsMode::Fixed(config));
}

/// HTTPS con cert hot-swappable (renovación ACME): lee la config por accept.
pub fn serve_forever_tls_auto(rt: Arc<ServeRuntime>, listener: TcpListener, config: SharedServerConfig) {
    run_async(rt, listener, TlsMode::Swap(config));
}

/// Knobs del servidor que el runtime reconoce — del ENTORNO DEL PROCESO (export /
/// systemd / Docker), no del `.env` (que alimenta `env()`/`secret()` y la config de
/// LLM/humanos). Lista CANÓNICA (espejo de `LLM_ENV_VARS`/`HUMAN_ENV_VARS`/
/// `CEILING_ENV_VARS`): el test anti-rot del CLI (`env_example_in_sync_with_engine_knobs`)
/// la cruza con el `.env.example` de `init` — sumar un knob acá sin documentarlo en el
/// template rompe el build a propósito.
pub const SERVE_ENV_VARS: &[&str] = &[
    "SYNSEMA_SERVE_WORKERS",
    "SYNSEMA_SHUTDOWN_GRACE",
    "SYNSEMA_SSE_KEEPALIVE",
    "SYNSEMA_WS_SERVER_PING",
    "SYNSEMA_WS_SUBPROTOCOLS",
    "SYNSEMA_WS_MAX_MESSAGE",
    "SYNSEMA_WS_MAX_CONNS",
    "SYNSEMA_PROC_MAX",
    "SYNSEMA_WATCH_MAX",
];

/// Servidores (`run_async`) vivos en el proceso: con varios `serve on` en un programa,
/// el shutdown ordenado sale del proceso cuando el ÚLTIMO terminó de drenar — no
/// cuando el primero (que cortaría el drain de los demás).
static LIVE_SERVERS: AtomicUsize = AtomicUsize::new(0);

/// Gracia del shutdown ordenado (segundos): `SYNSEMA_SHUTDOWN_GRACE`, default 10, `0` =
/// inmediato.
fn shutdown_grace() -> Duration {
    let secs = std::env::var("SYNSEMA_SHUTDOWN_GRACE")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|f| f.is_finite() && *f >= 0.0)
        .unwrap_or(10.0);
    Duration::from_secs_f64(secs)
}

/// Resuelve al recibir SIGINT (Ctrl-C) o, en Unix, SIGTERM (lo que manda Docker/systemd).
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

fn run_async(rt: Arc<ServeRuntime>, listener: TcpListener, tls: TlsMode) {
    LIVE_SERVERS.fetch_add(1, AtomicOrd::SeqCst);
    let _ = listener.set_nonblocking(true);
    // Arranca el pool del intérprete (stack grande, acotado) ANTES de aceptar conexiones.
    let _ = interp_pool();
    // NO seteamos `thread_stack_size` acá: los workers async de I/O usan stack default
    // (~MBs), no 64 MB. El stack grande vive solo en el pool del intérprete. Además cap
    // explícito del blocking pool (ya casi no se usa: el intérprete migró a su pool) y
    // keep-alive corto de hilos ociosos, como pidió el reporte de la arena.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(4)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(r) => r,
        Err(_) => return,
    };
    runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(l) => l,
            Err(_) => return,
        };
        // Shutdown ordenado (SIGINT/SIGTERM): dejar de aceptar, drenar lo que está en
        // vuelo hasta la gracia, cancelar lo que quede, salir con 0 (fue pedido).
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown_signal());
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, peer) = match accepted {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let _ = tcp.set_nodelay(true);
                    let client_ip = peer.ip().to_string();
                    let rt = rt.clone();
                    let tls = tls.clone();
                    let watcher = graceful.watcher();
                    tokio::spawn(async move {
                        serve_conn(rt, tcp, client_ip, tls, watcher).await;
                    });
                }
                _ = &mut shutdown => break,
            }
        }
        drop(listener);
        let grace = shutdown_grace();
        let inflight = rt.begin_shutdown();
        eprintln!(
            "[serve] shutting down: draining {} in-flight request(s), grace {:.0}s (SYNSEMA_SHUTDOWN_GRACE)",
            inflight,
            grace.as_secs_f64()
        );
        // Un segundo SIGINT durante el drain = salida inmediata (130, como un shell).
        tokio::spawn(async {
            shutdown_signal().await;
            eprintln!("[serve] second signal: exiting now");
            std::process::exit(130);
        });
        let deadline = Instant::now() + grace;
        tokio::select! {
            _ = graceful.shutdown() => {}
            _ = tokio::time::sleep(grace) => {}
        }
        // Un `socket` ya upgradeado no es una conexión de hyper (el graceful no lo
        // espera): la contabilidad propia (`inflight`) cubre streams, sockets y jobs
        // encolados por igual — se espera hasta la gracia.
        while rt.inflight() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if rt.inflight() > 0 {
            let n = rt.cancel_all_requests();
            eprintln!("[serve] grace period elapsed: cancelled {} request(s)", n);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        eprintln!("[serve] stopped");
        if LIVE_SERVERS.fetch_sub(1, AtomicOrd::SeqCst) == 1 {
            std::process::exit(0);
        }
    });
}

async fn serve_conn(
    rt: Arc<ServeRuntime>,
    tcp: tokio::net::TcpStream,
    client_ip: String,
    tls: TlsMode,
    watcher: hyper_util::server::graceful::Watcher,
) {
    let svc = {
        let rt = rt.clone();
        let ip = client_ip.clone();
        service_fn(move |req: Request<Incoming>| {
            let rt = rt.clone();
            let ip = ip.clone();
            async move { handle_request(rt, req, ip).await }
        })
    };
    // auto::Builder negocia HTTP/1.1 o HTTP/2 (ALPN h2 sobre TLS; h2c o 1.1 en claro).
    // `with_upgrades`: sin esto el `hyper::upgrade::on` de las rutas `socket` jamás
    // resuelve. `watcher.watch`: la conexión participa del shutdown ordenado.
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    match tls {
        TlsMode::Plain => {
            let io = TokioIo::new(tcp);
            let _ = watcher.watch(builder.serve_connection_with_upgrades(io, svc)).await;
        }
        TlsMode::Fixed(cfg) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            if let Ok(stream) = acceptor.accept(tcp).await {
                let io = TokioIo::new(stream);
                let _ = watcher.watch(builder.serve_connection_with_upgrades(io, svc)).await;
            }
        }
        TlsMode::Swap(cell) => {
            let cfg = match cell.read() {
                Ok(g) => g.clone(),
                Err(_) => return,
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            if let Ok(stream) = acceptor.accept(tcp).await {
                let io = TokioIo::new(stream);
                let _ = watcher.watch(builder.serve_connection_with_upgrades(io, svc)).await;
            }
        }
    }
}

/// Cabecera resuelta por el `spawn_blocking` (status + headers); el body llega aparte.
struct HeadInfo {
    status: u16,
    content_type: Option<String>,
    extra: Vec<(String, String)>,
    streaming: bool,
    close: bool,
    cors: Option<String>,
    hsts: bool,
    /// `101 Switching Protocols` de un socket entrante: `(Sec-WebSocket-Accept, protocolo)`.
    upgrade: Option<(String, Option<String>)>,
    /// Ruta `proxy to`: el lado async forwardea (streaming) en vez de emitir `body_rx`.
    proxy: Option<ProxyPlan>,
}

/// Lo que el dispatch resolvió para una ruta `proxy to`: upstream + headers (rate-limit).
struct ProxyPlan {
    target: String,
    headers: Vec<(String, String)>,
}

/// Slot donde el hub deja su `mio::Waker` para el pump de un socket entrante.
type WakerSlot = Arc<Mutex<Option<Arc<mio::Waker>>>>;

/// Cierra la contabilidad de una request al terminar su job (o al paniquear).
struct RequestGuard {
    rt: Arc<ServeRuntime>,
    cancel: CancelToken,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.rt.end_request(&self.cancel);
    }
}

/// Intervalo del heartbeat SSE (`: keepalive` como comentario, invisible para
/// `EventSource`): `SYNSEMA_SSE_KEEPALIVE` segundos, default 15, `0` lo apaga.
fn sse_keepalive() -> Option<Duration> {
    let secs = std::env::var("SYNSEMA_SSE_KEEPALIVE")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|f| f.is_finite() && *f >= 0.0)
        .unwrap_or(15.0);
    if secs > 0.0 {
        Some(Duration::from_secs_f64(secs))
    } else {
        None
    }
}

/// Body respaldado por un canal mpsc (SSE: frames a medida que el handler emite).
/// Emite un comentario `: keepalive` si el handler lleva `keepalive` sin emitir —
/// proxies y browsers dejan de cortar streams ociosos, sin tocar el protocolo. El
/// `_done` avisa (al dropearse) que el body terminó: apaga el timer de timeout.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    keepalive: Option<Duration>,
    idle: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    _done: Option<tokio::sync::oneshot::Sender<()>>,
}
impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::convert::Infallible>>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(b)) => {
                self.idle = None; // hubo un frame real: el timer de idle arranca de nuevo
                std::task::Poll::Ready(Some(Ok(Frame::data(b))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => {
                let Some(ka) = self.keepalive else { return std::task::Poll::Pending };
                if self.idle.is_none() {
                    self.idle = Some(Box::pin(tokio::time::sleep(ka)));
                }
                let fired = match self.idle.as_mut() {
                    Some(s) => std::future::Future::poll(s.as_mut(), cx).is_ready(),
                    None => false,
                };
                if fired {
                    self.idle = Some(Box::pin(tokio::time::sleep(ka)));
                    std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b": keepalive\n\n")))))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

/// `Sec-WebSocket-Accept` (RFC 6455 §4.2.2): base64(SHA-1(key + GUID)).
fn ws_accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    synsema_core::bytesutil::b64_encode(&h.finalize())
}

/// ¿La request pide un upgrade a WebSocket válido (RFC 6455)? Devuelve la key.
fn websocket_upgrade_key(headers: &[(String, String)]) -> Option<String> {
    let connection = header_value(headers, "connection").to_ascii_lowercase();
    let upgrade = header_value(headers, "upgrade").to_ascii_lowercase();
    let version = header_value(headers, "sec-websocket-version");
    let key = header_value(headers, "sec-websocket-key");
    let conn_ok = connection.split(',').any(|t| t.trim() == "upgrade");
    if conn_ok && upgrade == "websocket" && version.trim() == "13" && !key.trim().is_empty() {
        Some(key.trim().to_string())
    } else {
        None
    }
}

/// Subprotocolo a acordar: el primero ofrecido por el cliente que figure en
/// `SYNSEMA_WS_SUBPROTOCOLS` (lista separada por comas); sin la env no se acuerda
/// ninguno (se omite el header, como manda la RFC).
fn negotiate_subprotocol(headers: &[(String, String)]) -> Option<String> {
    let offered = header_value(headers, "sec-websocket-protocol");
    if offered.trim().is_empty() {
        return None;
    }
    let allowed = std::env::var("SYNSEMA_WS_SUBPROTOCOLS").ok()?;
    let allowed: Vec<String> = allowed.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    offered.split(',').map(|s| s.trim().to_string()).find(|o| allowed.iter().any(|a| a == o))
}

/// Bombea bytes entre el socket upgradeado (hyper) y el hilo del handler (canales del
/// `ServerSocketLink`). Backpressure real en las dos direcciones: canales acotados —
/// un handler lento frena la lectura del TCP (la ventana frena al cliente); un cliente
/// lento frena las escrituras del handler (WouldBlock en el canal). Cada movimiento
/// despierta al hub por el Waker que el hub dejó en `waker_slot`.
async fn pump_upgraded_socket(
    upgraded: hyper::upgrade::Upgraded,
    in_tx: tokio::sync::mpsc::Sender<Bytes>,
    mut out_rx: tokio::sync::mpsc::Receiver<Bytes>,
    waker_slot: Arc<Mutex<Option<Arc<mio::Waker>>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let io = TokioIo::new(upgraded);
    let (mut rd, mut wr) = tokio::io::split(io);
    let wake = move || {
        if let Ok(g) = waker_slot.lock() {
            if let Some(w) = g.as_ref() {
                let _ = w.wake();
            }
        }
    };
    let wake_r = wake.clone();
    let reader = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break; // el handler cerró
                    }
                    wake_r();
                }
            }
        }
        drop(in_tx); // EOF hacia el handler → `close` en su próximo recv
        wake_r();
    };
    let wake_w = wake.clone();
    let writer = async move {
        while let Some(b) = out_rx.recv().await {
            wake_w(); // hay lugar en el canal: un write pendiente puede reintentar
            if wr.write_all(&b).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
        let _ = wr.shutdown().await;
    };
    tokio::join!(reader, writer);
}

// -- reverse proxy en streaming (`proxy to`) --

/// `http://host[:port][/base]` → (addr para conectar, authority para `Host`, base sin `/` final).
pub fn parse_proxy_target(target: &str) -> Result<(String, String, String), String> {
    let t = target.trim();
    let rest = match t.strip_prefix("http://") {
        Some(r) => r,
        None => {
            return Err(format!(
                "the target must be an http:// URL (got \"{}\"); TLS terminates at the edge — point it at the backend's plain http port",
                t
            ))
        }
    };
    let (authority, base) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.starts_with(':') {
        return Err(format!("the target needs a host (got \"{}\")", t));
    }
    let addr = if authority.rsplit(':').next().map(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty()).unwrap_or(false)
        && authority.contains(':')
    {
        authority.to_string()
    } else {
        format!("{}:80", authority)
    };
    Ok((addr, authority.to_string(), base.trim_end_matches('/').to_string()))
}

/// Hop-by-hop (RFC 7230 §6.1): no cruzan el proxy en ninguna dirección.
fn is_hop_by_hop(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailer"
            | "transfer-encoding" | "upgrade"
    )
}

fn proxy_error_response(
    status: u16,
    msg: String,
    extra: &[(String, String)],
    cors: Option<&str>,
    hsts: bool,
) -> Response<RespBody> {
    let body = obj(vec![("error", Json::Str(msg)), ("status", Json::Int(status as i64))]);
    json_full(status, dumps(&body), extra, cors, hsts, false)
}

/// Forward de una request `proxy to` al upstream, en streaming. El cliente hyper
/// (http1) maneja chunked/length/close/upgrade; el edge NO parsea HTTP a mano.
/// - respuesta normal: los frames del body se reenvían a medida que llegan
///   (`ProxyBody`); `Content-Length` se preserva si el upstream lo dio.
/// - `101` a un upgrade WebSocket del cliente: túnel bidireccional de bytes.
/// - `timeout` (route/serve) acota connect + head del upstream; el body/túnel no
///   tiene techo (como `stream`/`socket`) — lo corta el shutdown o cualquier extremo.
#[allow(clippy::too_many_arguments)]
async fn proxy_request(
    rt: Arc<ServeRuntime>,
    plan: ProxyPlan,
    method: String,
    target_pq: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    client_ip: String,
    upgrade: Option<hyper::upgrade::OnUpgrade>,
    timeout: Option<f64>,
    cors: Option<String>,
    hsts: bool,
) -> Response<RespBody> {
    use hyper::body::Body as _;
    use hyper::http::header::{HeaderName, HeaderValue};

    let extra = plan.headers;
    let (addr, authority, base) = match parse_proxy_target(&plan.target) {
        Ok(x) => x,
        Err(e) => return proxy_error_response(502, format!("proxy error: {}", e), &extra, cors.as_deref(), hsts),
    };
    let wait = Duration::from_secs_f64(timeout.filter(|t| t.is_finite() && *t > 0.0).unwrap_or(30.0));
    let tcp = match tokio::time::timeout(wait, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return proxy_error_response(502, format!("proxy error: connect {}: {}", addr, e), &extra, cors.as_deref(), hsts)
        }
        Err(_) => {
            return proxy_error_response(
                504,
                format!("gateway timeout: the upstream {} did not accept the connection within {}s", addr, wait.as_secs_f64()),
                &extra,
                cors.as_deref(),
                hsts,
            )
        }
    };
    let _ = tcp.set_nodelay(true);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await {
        Ok(x) => x,
        Err(e) => return proxy_error_response(502, format!("proxy error: {}", e), &extra, cors.as_deref(), hsts),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let is_ws = upgrade.is_some();
    let pq = if target_pq.starts_with('/') { target_pq } else { format!("/{}", target_pq) };
    let uri = format!("{}{}", base, pq);
    let mut rb = Request::builder().method(method.as_str()).uri(uri.as_str());
    rb = rb.header("Host", authority.as_str());
    let mut fwd_for: Option<String> = None;
    let mut orig_host: Option<String> = None;
    for (k, v) in &headers {
        let lk = k.to_ascii_lowercase();
        match lk.as_str() {
            "host" => {
                orig_host = Some(v.clone());
                continue;
            }
            "content-length" | "x-forwarded-proto" | "x-forwarded-host" => continue,
            "x-forwarded-for" => {
                fwd_for = Some(v.clone());
                continue;
            }
            // En un upgrade WebSocket, `Upgrade` y `Sec-WebSocket-*` cruzan tal cual.
            "upgrade" if is_ws => {}
            _ if is_hop_by_hop(&lk) => continue,
            _ => {}
        }
        if let (Ok(n), Ok(val)) = (HeaderName::try_from(k.as_str()), HeaderValue::try_from(v.as_str())) {
            rb = rb.header(n, val);
        }
    }
    if is_ws {
        rb = rb.header("Connection", "Upgrade");
    }
    let xff = match fwd_for {
        Some(prev) if !prev.trim().is_empty() => format!("{}, {}", prev.trim(), client_ip),
        _ => client_ip.clone(),
    };
    rb = rb.header("X-Forwarded-For", xff.as_str());
    rb = rb.header("X-Forwarded-Proto", if rt.tls_enabled { "https" } else { "http" });
    if let Some(h) = orig_host {
        if let Ok(val) = HeaderValue::try_from(h.as_str()) {
            rb = rb.header("X-Forwarded-Host", val);
        }
    }
    let req = match rb.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => return proxy_error_response(502, format!("proxy error: bad request for upstream: {}", e), &extra, cors.as_deref(), hsts),
    };
    let resp = match tokio::time::timeout(wait, sender.send_request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return proxy_error_response(502, format!("proxy error: {}", e), &extra, cors.as_deref(), hsts),
        Err(_) => {
            return proxy_error_response(
                504,
                format!("gateway timeout: the upstream did not answer within {}s", wait.as_secs_f64()),
                &extra,
                cors.as_deref(),
                hsts,
            )
        }
    };
    let status = resp.status().as_u16();

    // 101 al upgrade del cliente → túnel de bytes en ambas direcciones.
    if status == 101 {
        let down = match upgrade {
            Some(d) => d,
            None => {
                return proxy_error_response(
                    502,
                    "proxy error: the upstream switched protocols without an upgrade request".to_string(),
                    &extra,
                    cors.as_deref(),
                    hsts,
                )
            }
        };
        if !rt.try_acquire_stream() {
            return proxy_error_response(
                503,
                "too many concurrent streams".to_string(),
                &[("Retry-After".to_string(), "5".to_string())],
                cors.as_deref(),
                hsts,
            );
        }
        let mut builder = Response::builder().status(101).header("Upgrade", "websocket").header("Connection", "Upgrade");
        for (k, v) in resp.headers() {
            if k.as_str().starts_with("sec-websocket-") {
                builder = builder.header(k.clone(), v.clone());
            }
        }
        let cancel = CancelToken::new();
        rt.begin_request(&cancel, true);
        let guard = RequestGuard { rt: rt.clone(), cancel: cancel.clone() };
        let rt2 = rt.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let mut resp = resp;
            let up = hyper::upgrade::on(&mut resp).await;
            let down = down.await;
            if let (Ok(up), Ok(down)) = (up, down) {
                let mut a = TokioIo::new(up);
                let mut b = TokioIo::new(down);
                let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
                tokio::pin!(copy);
                loop {
                    tokio::select! {
                        _ = &mut copy => break,
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {
                            if cancel.is_cancelled() {
                                break;
                            }
                        }
                    }
                }
            }
            rt2.release_stream();
        });
        return builder.body(Full::new(Bytes::new()).boxed()).unwrap_or_else(|_| {
            proxy_error_response(502, "proxy error: invalid upgrade response".to_string(), &[], None, false)
        });
    }

    // Respuesta normal: status + headers end-to-end + body en streaming.
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k.clone(), v.clone());
    }
    if let Some(o) = &cors {
        builder = builder.header("Access-Control-Allow-Origin", o);
    }
    if hsts {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    for (k, v) in &extra {
        if let (Ok(n), Ok(val)) = (HeaderName::try_from(k.as_str()), HeaderValue::try_from(v.as_str())) {
            builder = builder.header(n, val);
        }
    }
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let sized = resp.body().size_hint().exact().is_some() || resp.body().is_end_stream();
    // Un body sin tamaño conocido (SSE, chunked, close-delimited) es long-lived:
    // ocupa un slot de stream y se cancela en el shutdown, como `stream` nativo.
    let slot = !sized && !is_head;
    if slot && !rt.try_acquire_stream() {
        return proxy_error_response(
            503,
            "too many concurrent streams".to_string(),
            &[("Retry-After".to_string(), "5".to_string())],
            cors.as_deref(),
            hsts,
        );
    }
    let cancel = CancelToken::new();
    rt.begin_request(&cancel, slot);
    let guard = RequestGuard { rt: rt.clone(), cancel: cancel.clone() };
    let body = ProxyBody { inner: resp.into_body(), cancel, tick: None, slot, rt: rt.clone(), _guard: guard };
    match builder.body(body.boxed()) {
        Ok(r) => r,
        Err(e) => proxy_error_response(502, format!("proxy error: invalid upstream response: {}", e), &extra, cors.as_deref(), hsts),
    }
}

/// Body de una respuesta proxied: delega en el `Incoming` del cliente hyper frame a
/// frame; termina si la request se cancela (shutdown); libera el slot de stream al
/// dropearse. `size_hint` delegado → hyper emite `Content-Length` exacto cuando el
/// upstream lo dio, chunked (h1) / DATA (h2) si no.
struct ProxyBody {
    inner: Incoming,
    cancel: CancelToken,
    tick: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    slot: bool,
    rt: Arc<ServeRuntime>,
    _guard: RequestGuard,
}

impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::convert::Infallible>>> {
        use std::task::Poll;
        if self.cancel.is_cancelled() {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(f))) => {
                self.tick = None;
                Poll::Ready(Some(Ok(f)))
            }
            // El upstream cortó a mitad: el cliente ve el fin (con Content-Length,
            // hyper cierra la conexión por body corto — visible, no silencioso).
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if !self.slot {
                    return Poll::Pending;
                }
                // Long-lived: vigilar la cancelación aunque el upstream esté callado.
                if self.tick.is_none() {
                    self.tick = Some(Box::pin(tokio::time::sleep(Duration::from_millis(250))));
                }
                let fired = match self.tick.as_mut() {
                    Some(s) => std::future::Future::poll(s.as_mut(), cx).is_ready(),
                    None => false,
                };
                if fired {
                    if self.cancel.is_cancelled() {
                        return Poll::Ready(None);
                    }
                    self.tick = Some(Box::pin(tokio::time::sleep(Duration::from_millis(250))));
                    // Registrar el waker del timer nuevo.
                    if let Some(s) = self.tick.as_mut() {
                        let _ = std::future::Future::poll(s.as_mut(), cx);
                    }
                }
                Poll::Pending
            }
        }
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

impl Drop for ProxyBody {
    fn drop(&mut self) {
        if self.slot {
            self.rt.release_stream();
        }
    }
}

fn response_body_bytes(body: ResponseBody) -> (String, Bytes) {
    match body {
        ResponseBody::Json(j) => ("application/json".to_string(), Bytes::from(dumps(&j))),
        ResponseBody::Raw(r) => (r.content_type, Bytes::from(r.body)),
        // El destino va como header `Location` (inyectado en el dispatch); sin body.
        ResponseBody::Redirect { .. } => ("text/plain; charset=utf-8".to_string(), Bytes::new()),
    }
}

/// Emisor SSE respaldado por el canal: formatea `[event:..\n]data:<json>\n\n`.
fn channel_emitter(tx: tokio::sync::mpsc::Sender<Bytes>) -> Emitter {
    Box::new(move |value: &SynValue, event: Option<&str>| -> Result<(), StreamGone> {
        let mut payload = String::new();
        if let Some(e) = event {
            payload.push_str("event: ");
            payload.push_str(e);
            payload.push('\n');
        }
        payload.push_str("data: ");
        payload.push_str(&dumps(&syn_to_json(value)));
        payload.push_str("\n\n");
        tx.blocking_send(Bytes::from(payload)).map_err(|_| StreamGone)
    })
}

/// Construye un `Response` JSON sized (errores 4xx/5xx fuera del dispatch).
fn json_full(
    status: u16,
    body: String,
    extra: &[(String, String)],
    cors: Option<&str>,
    hsts: bool,
    close: bool,
) -> Response<RespBody> {
    let mut builder = Response::builder().status(status).header("Content-Type", "application/json");
    if close {
        builder = builder.header("Connection", "close");
    }
    if let Some(o) = cors {
        builder = builder.header("Access-Control-Allow-Origin", o);
    }
    if hsts {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    for (k, v) in extra {
        builder = builder.header(k, v);
    }
    builder.body(Full::new(Bytes::from(body)).boxed()).unwrap()
}

/// OPTIONS: 204 + Allow (+ CORS si está). Espeja `handle_options` del path viejo.
fn build_options_response(rt: &ServeRuntime, path: &str) -> Response<RespBody> {
    let allowed = rt.methods_for_path(path);
    if allowed.is_empty() {
        let body = obj(vec![
            ("error", Json::Str(format!("no route for {}", path))),
            ("status", Json::Int(404)),
        ]);
        return json_full(404, dumps(&body), &[], rt.cors_origin(), rt.tls_enabled, false);
    }
    let mut set = allowed;
    set.push("OPTIONS".to_string());
    set.push("HEAD".to_string());
    set.sort();
    set.dedup();
    let allow = set.join(", ");
    let mut builder = Response::builder()
        .status(204)
        .header("Allow", &allow)
        .header("Content-Length", "0");
    if let Some(o) = rt.cors_origin() {
        builder = builder
            .header("Access-Control-Allow-Origin", o)
            .header("Access-Control-Allow-Methods", &allow)
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            .header("Access-Control-Max-Age", "86400");
    }
    if rt.tls_enabled {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    builder.body(Full::new(Bytes::new()).boxed()).unwrap()
}

/// Lee el body respetando `max_body` (excedido → Err → 413).
async fn read_req_body(body: Incoming, max: Option<i64>) -> Result<Bytes, ()> {
    match max {
        Some(m) => {
            let lim = m.max(0) as usize;
            match Limited::new(body, lim).collect().await {
                Ok(c) => Ok(c.to_bytes()),
                Err(_) => Err(()),
            }
        }
        None => match body.collect().await {
            Ok(c) => Ok(c.to_bytes()),
            Err(_) => Err(()),
        },
    }
}

/// Path único para un body spilled a disco (como tempfile del oráculo).
fn spill_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("syn_body_{}_{}", std::process::id(), n))
}

async fn handle_request(
    rt: Arc<ServeRuntime>,
    req: Request<Incoming>,
    client_ip: String,
) -> Result<Response<RespBody>, std::convert::Infallible> {
    let method = req.method().as_str().to_string();
    let target = match req.uri().path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => req.uri().path().to_string(),
    };
    let (path, query) = parse_path_query(&target);
    let mut req = req;
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    // HTTP/2: el Host viaja en el pseudo-header `:authority` (vía `req.uri().authority()`),
    // no en `headers()`. Sin esto, la selección de vhost y `host of (headers of request)`
    // caen al host default para todo cliente h2 (los navegadores negocian h2 sobre TLS).
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        if let Some(auth) = req.uri().authority() {
            headers.push(("host".to_string(), auth.host().to_string()));
        }
    }

    if method == "OPTIONS" {
        return Ok(build_options_response(&rt, &path));
    }
    let is_head = method == "HEAD";
    let eff_method = if is_head { "GET".to_string() } else { method.clone() };

    let cors = rt.cors_origin().map(|s| s.to_string());
    let hsts = rt.tls_enabled;

    // Shutdown ordenado en curso: no se aceptan requests nuevas (las que están en
    // vuelo se drenan). 503 explícito + `Connection: close` (el balanceador reintenta
    // en otra instancia).
    if rt.is_shutting_down() {
        let body = obj(vec![
            ("error", Json::Str("server shutting down".into())),
            ("status", Json::Int(503)),
        ]);
        return Ok(json_full(503, dumps(&body), &[("Retry-After".to_string(), "2".to_string())], cors.as_deref(), hsts, true));
    }

    // Plan de atención (vhost + match, sin auth ni handler): hilo, socket, timeout.
    let plan = rt.route_plan(&eff_method, &path, &headers);

    // Ruta `proxy to` con `Upgrade: websocket`: tomar el upgrade de hyper ANTES de
    // consumir el body (como en `socket`); si el upstream responde 101 se tuneliza.
    let mut proxy_upgrade: Option<hyper::upgrade::OnUpgrade> = None;
    if plan.proxy && !is_head && websocket_upgrade_key(&headers).is_some() {
        proxy_upgrade = Some(hyper::upgrade::on(&mut req));
    }

    // Ruta `socket`: validar el upgrade RFC 6455 ANTES de consumir el body (el
    // `hyper::upgrade::on` necesita la request entera). Sin upgrade → 426.
    let mut on_upgrade: Option<(hyper::upgrade::OnUpgrade, String)> = None;
    if plan.socket {
        match websocket_upgrade_key(&headers) {
            Some(key) if !is_head => {
                on_upgrade = Some((hyper::upgrade::on(&mut req), key));
            }
            _ => {
                let body = obj(vec![
                    ("error", Json::Str("upgrade required: this route is a WebSocket endpoint (send Connection: Upgrade, Upgrade: websocket, Sec-WebSocket-Version: 13, Sec-WebSocket-Key)".into())),
                    ("status", Json::Int(426)),
                ]);
                let extra = vec![
                    ("Upgrade".to_string(), "websocket".to_string()),
                    ("Connection".to_string(), "Upgrade".to_string()),
                ];
                return Ok(json_full(426, dumps(&body), &extra, cors.as_deref(), hsts, false));
            }
        }
    }

    // Body con tope; excedido → 413 + cerrar.
    let body_bytes = match read_req_body(req.into_body(), rt.max_body).await {
        Ok(b) => b,
        Err(()) => {
            let body = obj(vec![
                ("error", Json::Str("payload too large".into())),
                ("status", Json::Int(413)),
            ]);
            return Ok(json_full(413, dumps(&body), &[], cors.as_deref(), hsts, true));
        }
    };
    // Spill a disco igual que el oráculo: bodies > MEM_SPILL no van en memoria (el
    // `body` string queda vacío; el handler lo lee del file vía body_file). El `body_raw`
    // conserva los bytes exactos en memoria (para `read_body_bytes` byte-exacto sin la
    // decodificación lossy de `body`); vacío cuando spilleó (el file es la fuente cruda).
    let (body_str, body_raw, body_file): (String, Vec<u8>, Option<PathBuf>) =
        if body_bytes.len() > MEM_SPILL {
            let p = spill_path();
            let _ = std::fs::write(&p, &body_bytes);
            (String::new(), Vec::new(), Some(p))
        } else {
            (String::from_utf8_lossy(&body_bytes).into_owned(), body_bytes.to_vec(), None)
        };
    // Lo que el forward de un `proxy to` necesita (el job sync consume el resto).
    let proxy_req = if plan.proxy {
        Some((method.clone(), target.clone(), headers.clone(), body_bytes.clone(), client_ip.clone()))
    } else {
        None
    };

    // ¿La ruta que matchearía es un `stream`? Resolución barata (vhost + match de ruta,
    // sin auth ni handler) para decidir el hilo: los streams (long-lived, Ctx !Send) corren
    // en un hilo dedicado; los sized (caso común) van al pool acotado.
    // Las rutas `/approvals` (A1.v2) también van a hilo dedicado: un gate humano
    // bloqueado OCUPA un worker del pool esperando su respuesta — si la respuesta
    // (POST /approvals/{id}) tuviera que esperar un worker libre, con el pool lleno de
    // gates nadie podría aprobar nada hasta los timeouts.
    let streaming_route = plan.dedicated || rt.is_approvals_route(&eff_method, &path);

    // dispatch + (si stream) correr el handler; head por oneshot, body por mpsc (1 frame
    // para sized, N frames para SSE).
    let (head_tx, head_rx) = tokio::sync::oneshot::channel::<HeadInfo>();
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let rt2 = rt.clone();
    let cors_b = cors.clone();

    // Token de cancelación de ESTA request: el handler lo adopta; el lado async lo
    // cancela por timeout o shutdown. Se crea acá (antes del head) para poder cortar
    // un handler que todavía no respondió nada.
    let cancel = CancelToken::new();
    rt.begin_request(&cancel, streaming_route);
    let cancel_job = cancel.clone();

    // Canales del socket entrante (sólo rutas `socket`): bytes del cliente → handler
    // (`in`), bytes del handler → cliente (`out`); 64 slots por dirección = backpressure.
    let socket_link: Option<(ServerSocketLink, tokio::sync::mpsc::Sender<Bytes>, tokio::sync::mpsc::Receiver<Bytes>, WakerSlot)> =
        if on_upgrade.is_some() {
            let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
            let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
            let slot: Arc<Mutex<Option<Arc<mio::Waker>>>> = Arc::new(Mutex::new(None));
            let max_message = std::env::var("SYNSEMA_WS_MAX_MESSAGE")
                .ok()
                .and_then(|s| parse_body_size_str(&s))
                .map(|n| n.max(1) as usize)
                .unwrap_or(16 * 1024 * 1024);
            let link = ServerSocketLink {
                inbound: in_rx,
                outbound: out_tx,
                waker_slot: slot.clone(),
                subprotocol: negotiate_subprotocol(&headers),
                max_message,
            };
            Some((link, in_tx, out_rx, slot))
        } else {
            None
        };
    let (link_for_job, pump_parts) = match socket_link {
        Some((link, in_tx, out_rx, slot)) => (Some(link), Some((in_tx, out_rx, slot))),
        None => (None, None),
    };
    let accept_key = on_upgrade.as_ref().map(|(_, k)| ws_accept_key(k));
    let subprotocol_ack = link_for_job.as_ref().and_then(|l| l.subprotocol.clone());

    // Un SOLO closure: corre el intérprete sync (dispatch + handler). El `Ctx` es !Send
    // pero queda LOCAL al job (nunca se captura) → el closure captura sólo inputs Send, así
    // sirve igual para el pool (sized) que para un hilo dedicado (stream).
    let job = move || {
        // Contabilidad de la request (inflight + token activo): se cierra al terminar
        // el job INCLUSO si el handler paniquea (el pool atrapa el panic; el Drop corre
        // durante el desenrollado).
        let _guard = RequestGuard { rt: rt2.clone(), cancel: cancel_job.clone() };
        let bf = body_file.as_ref().map(|p| p.to_string_lossy().into_owned());
        let accept_gzip =
            header_value(&headers, "accept-encoding").to_ascii_lowercase().contains("gzip");
        let dispatched = rt2.dispatch(
            &eff_method,
            &path,
            query,
            headers,
            &body_str,
            &body_raw,
            bf.as_deref(),
            &client_ip,
            cancel_job.clone(),
        );
        match dispatched {
            Dispatched::Response { status, body, headers: extra } => {
                let mut extra = extra;
                // redirect(): el destino se emite como header `Location`.
                if let ResponseBody::Redirect { location, .. } = &body {
                    extra.push(("Location".to_string(), location.clone()));
                }
                let (ct, bytes) = response_body_bytes(body);
                // gzip DINÁMICO (render()/html()/content()/JSON): los estáticos ya
                // vienen comprimidos desde serve_static_full (traen Content-Encoding
                // en `extra`, así que acá se saltean); 204/206/304 no llevan body
                // comprimible y un body chico no amortiza el overhead.
                let mut bytes = bytes;
                if accept_gzip
                    && bytes.len() >= 1024
                    && !matches!(status, 204 | 206 | 304)
                    && is_compressible(&ct)
                    && !extra.iter().any(|(k, _)| {
                        k.eq_ignore_ascii_case("content-encoding")
                            || k.eq_ignore_ascii_case("content-range")
                    })
                {
                    if let Some(gz) = gzip_bytes(&bytes) {
                        if gz.len() < bytes.len() {
                            bytes = Bytes::from(gz);
                            extra.push(("Content-Encoding".to_string(), "gzip".to_string()));
                            extra.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                        }
                    }
                }
                let _ = head_tx.send(HeadInfo {
                    status,
                    content_type: Some(ct),
                    extra,
                    streaming: false,
                    close: false,
                    cors: cors_b,
                    hsts,
                    upgrade: None,
                    proxy: None,
                });
                let _ = body_tx.blocking_send(bytes);
            }
            Dispatched::Socket { socket_handler, ctx } => {
                match (link_for_job, accept_key) {
                    (Some(link), Some(accept)) => {
                        let _ = head_tx.send(HeadInfo {
                            status: 101,
                            content_type: None,
                            extra: Vec::new(),
                            streaming: false,
                            close: false,
                            cors: cors_b,
                            hsts,
                            upgrade: Some((accept, subprotocol_ack)),
                            proxy: None,
                        });
                        if let Some(sh) = socket_handler {
                            // El error del handler ya viajó al cliente como Close 1011
                            // (lo hace el runtime); acá sólo se libera el slot.
                            let _ = sh(&ctx, Box::new(link));
                        }
                    }
                    _ => {
                        // No debería pasar: dispatch sólo devuelve Socket para rutas
                        // `socket`, y esas llegan acá con upgrade validado. Fail-loud.
                        let _ = head_tx.send(HeadInfo {
                            status: 500,
                            content_type: Some("application/json".to_string()),
                            extra: Vec::new(),
                            streaming: false,
                            close: true,
                            cors: cors_b,
                            hsts,
                            upgrade: None,
                            proxy: None,
                        });
                        let body = obj(vec![
                            ("error", Json::Str("socket route reached without an upgrade".into())),
                            ("status", Json::Int(500)),
                        ]);
                        let _ = body_tx.blocking_send(Bytes::from(dumps(&body)));
                    }
                }
                rt2.release_stream();
            }
            Dispatched::Proxy { target, headers } => {
                // El forward corre del lado async; acá sólo se entrega el plan y el
                // worker del pool queda libre.
                let _ = head_tx.send(HeadInfo {
                    status: 0,
                    content_type: None,
                    extra: Vec::new(),
                    streaming: false,
                    close: false,
                    cors: cors_b,
                    hsts,
                    upgrade: None,
                    proxy: Some(ProxyPlan { target, headers }),
                });
            }
            Dispatched::Stream { stream_handler, ctx } => {
                let _ = head_tx.send(HeadInfo {
                    status: 200,
                    content_type: Some("text/event-stream".to_string()),
                    extra: vec![
                        ("Cache-Control".to_string(), "no-cache".to_string()),
                        ("X-Accel-Buffering".to_string(), "no".to_string()),
                    ],
                    streaming: true,
                    close: true,
                    cors: cors_b,
                    hsts,
                    upgrade: None,
                    proxy: None,
                });
                if let Some(sh) = stream_handler {
                    let emit = channel_emitter(body_tx.clone());
                    if let StreamEnd::Error(msg) = sh(&ctx, emit) {
                        let err = format!(
                            "event: error\ndata: {}\n\n",
                            dumps(&obj(vec![("error", Json::Str(msg))]))
                        );
                        let _ = body_tx.blocking_send(Bytes::from(err));
                    }
                }
                rt2.release_stream();
            }
        }
        // Limpia el body spilled a disco (si lo hubo).
        if let Some(p) = &body_file {
            let _ = std::fs::remove_file(p);
        }
    };

    if streaming_route {
        // Stream: hilo dedicado de stack grande (dispatch + handler juntos; el Ctx no cruza
        // hilos). Acotado por `max_streams` (el slot se adquiere/libera dentro del job).
        // NO ocupa un worker del pool → unas pocas conexiones SSE no lo agotan.
        if std::thread::Builder::new()
            .name("synsema-stream".to_string())
            .stack_size(SERVE_STACK_SIZE)
            .spawn(job)
            .is_err()
        {
            // Falló crear el hilo (sistema sin recursos): el job se dropeó → head_rx da Err
            // → el lado async responde 500. dispatch no corrió: no hay slot que liberar.
        }
    } else {
        // Sized (caso común): pool dedicado y ACOTADO (no el blocking pool de tokio). La
        // memoria es `#workers × 64 MB` pase lo que pase con la concurrencia → adiós OOM:
        // ya no hay N hilos × 64 MB por N requests en vuelo bajo keep-alive.
        interp_pool().submit(Box::new(job));
    }

    // Timeout del handler (`timeout` de la route o del serve). Sized: se responde 504
    // al vencer (aunque el handler siga — se lo cancela y termina al próximo statement
    // o espera). Stream/socket: un timer cancela el token al vencer; se apaga cuando
    // el body termina (`done`).
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    if let Some(secs) = plan.timeout {
        if streaming_route {
            let c = cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs_f64(secs)) => {
                        c.cancel(&format!("request timed out after {}s", secs));
                    }
                    _ = done_rx => {}
                }
            });
        }
    }
    let head = if let (Some(secs), false) = (plan.timeout, streaming_route) {
        match tokio::time::timeout(Duration::from_secs_f64(secs), head_rx).await {
            Ok(Ok(h)) => h,
            Ok(Err(_)) => {
                let body = obj(vec![
                    ("error", Json::Str("internal server error".into())),
                    ("status", Json::Int(500)),
                ]);
                return Ok(json_full(500, dumps(&body), &[], cors.as_deref(), hsts, false));
            }
            Err(_) => {
                cancel.cancel(&format!("request timed out after {}s", secs));
                let body = obj(vec![
                    ("error", Json::Str(format!("gateway timeout: the handler exceeded {}s", secs))),
                    ("status", Json::Int(504)),
                ]);
                return Ok(json_full(504, dumps(&body), &[], cors.as_deref(), hsts, true));
            }
        }
    } else {
        match head_rx.await {
            Ok(h) => h,
            Err(_) => {
                let body = obj(vec![
                    ("error", Json::Str("internal server error".into())),
                    ("status", Json::Int(500)),
                ]);
                return Ok(json_full(500, dumps(&body), &[], cors.as_deref(), hsts, false));
            }
        }
    };

    // Ruta `proxy to`: forward en streaming (SSE / túnel WebSocket / bodies grandes).
    if let Some(pp) = head.proxy {
        let (m, pq, hs, body, ip) =
            proxy_req.unwrap_or_else(|| (method.clone(), target.clone(), Vec::new(), Bytes::new(), String::new()));
        return Ok(proxy_request(rt.clone(), pp, m, pq, hs, body, ip, proxy_upgrade, plan.timeout, cors, hsts).await);
    }

    // 101 Switching Protocols: responder y, cuando hyper entregue el socket crudo,
    // arrancar el pump hacia el hilo del handler.
    if let Some((accept, protocol)) = head.upgrade {
        if let (Some((on_up, _)), Some((in_tx, out_rx, slot))) = (on_upgrade, pump_parts) {
            tokio::spawn(async move {
                // El `done` del timeout vive lo que viva el socket (no lo que viva el 101).
                let _done = done_tx;
                match on_up.await {
                    Ok(upgraded) => pump_upgraded_socket(upgraded, in_tx, out_rx, slot).await,
                    Err(_) => {
                        // El cliente se fue entre el 101 y el upgrade: dropear los canales
                        // → el handler ve EOF (close) en su próximo recv.
                    }
                }
            });
        }
        let mut builder = Response::builder()
            .status(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", accept);
        if let Some(p) = protocol {
            builder = builder.header("Sec-WebSocket-Protocol", p);
        }
        return Ok(builder.body(Full::new(Bytes::new()).boxed()).unwrap());
    }

    let mut builder = Response::builder().status(head.status);
    if let Some(ct) = &head.content_type {
        builder = builder.header("Content-Type", ct);
    }
    if head.close {
        builder = builder.header("Connection", "close");
    }
    if let Some(o) = &head.cors {
        builder = builder.header("Access-Control-Allow-Origin", o);
    }
    if head.hsts {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    // Validar cada header extra y saltear los inválidos: al reenviar headers
    // arbitrarios del upstream (reverse proxy), un valor malformado (p. ej. con un
    // byte de control) envenenaría el builder y haría panic en `.body(...).unwrap()`.
    // Un reverse proxy no debe caerse por datos del upstream → se descarta (como nginx).
    for (k, v) in &head.extra {
        if let (Ok(name), Ok(val)) = (
            hyper::http::header::HeaderName::try_from(k.as_str()),
            hyper::http::header::HeaderValue::try_from(v.as_str()),
        ) {
            builder = builder.header(name, val);
        }
    }

    let mut body_rx = body_rx;
    if head.streaming {
        let body = ChannelBody { rx: body_rx, keepalive: sse_keepalive(), idle: None, _done: Some(done_tx) }.boxed();
        Ok(builder.body(body).unwrap())
    } else {
        // sized: 1 frame con el body completo → Full (hyper pone Content-Length).
        let bytes = body_rx.recv().await.unwrap_or_default();
        if is_head {
            // HEAD: mismo Content-Length, sin cuerpo.
            builder = builder.header("Content-Length", bytes.len().to_string());
            Ok(builder.body(Full::new(Bytes::new()).boxed()).unwrap())
        } else {
            Ok(builder.body(Full::new(bytes).boxed()).unwrap())
        }
    }
}

/// A2 batch 2 — Listener HTTP (típico :80) para auto-HTTPS: sirve el challenge
/// ACME HTTP-01 (`/.well-known/acme-challenge/<token>` → key-authorization desde
/// `store`) y redirige todo lo demás a https. Reúsa el rol del listener de redirect.
pub fn serve_acme_http(listener: TcpListener, https_port: u16, store: ChallengeStore) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let store = store.clone();
        let _ = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _ = acme_http_one(stream, https_port, store);
            });
    }
}

fn acme_http_one(stream: TcpStream, https_port: u16, store: ChallengeStore) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let (_, target, _, headers) = match read_request_head(&mut reader) {
        Some(x) => x,
        None => return Ok(()),
    };
    let (path, _q) = parse_path_query(&target);
    const PFX: &str = "/.well-known/acme-challenge/";
    if let Some(token) = path.strip_prefix(PFX) {
        let body = store.lock().unwrap().get(token).cloned();
        let stream = reader.get_mut();
        match body {
            Some(key_auth) => {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    key_auth.len(),
                    key_auth
                );
                stream.write_all(resp.as_bytes())?;
            }
            None => {
                stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
            }
        }
        return stream.flush();
    }
    // No es un challenge → 301 a https.
    let host_hdr = header_value(&headers, "host");
    let host = host_hdr.split(':').next().unwrap_or("").to_string();
    let authority = if https_port == 443 || host.is_empty() {
        host
    } else {
        format!("{}:{}", host, https_port)
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        authority, target
    );
    let stream = reader.get_mut();
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// A2 — Construye una `ServerConfig` de rustls (ring) desde cert+key PEM. Defaults
/// seguros: TLS 1.2+ (versiones por defecto de rustls), sin auth de cliente.
pub fn build_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    let cert_file =
        File::open(cert_path).map_err(|e| format!("could not read TLS cert {}: {}", cert_path, e))?;
    let mut cert_rd = BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid TLS cert {}: {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path));
    }
    let key_file =
        File::open(key_path).map_err(|e| format!("could not read TLS key {}: {}", key_path, e))?;
    let mut key_rd = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_rd)
        .map_err(|e| format!("invalid TLS key {}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {}", key_path))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS cert/key mismatch: {}", e))?;
    // Lote 2 — HTTP/2: anunciar h2 (y http/1.1 fallback) por ALPN. El auto::Builder
    // sirve HTTP/2 cuando el cliente negocia h2; si no, HTTP/1.1.
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Carga un par cert(cadena)+key PEM en un `CertifiedKey` de rustls (para SNI por-host).
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<rustls::sign::CertifiedKey, String> {
    let cert_file =
        File::open(cert_path).map_err(|e| format!("could not read TLS cert {}: {}", cert_path, e))?;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid TLS cert {}: {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path));
    }
    let key_file =
        File::open(key_path).map_err(|e| format!("could not read TLS key {}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("invalid TLS key {}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {}", key_path))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported TLS key in {}: {}", key_path, e))?;
    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
}

/// Resolver SNI (vhost): elige el cert por server name del handshake; cae al default.
#[derive(Debug)]
struct SniResolver {
    default: std::sync::Arc<rustls::sign::CertifiedKey>,
    by_name: HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>>,
    wildcards: Vec<(String, std::sync::Arc<rustls::sign::CertifiedKey>)>,
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            let name = name.to_ascii_lowercase();
            if let Some(ck) = self.by_name.get(&name) {
                return Some(ck.clone());
            }
            for (suffix, ck) in &self.wildcards {
                if name.ends_with(suffix) {
                    return Some(ck.clone());
                }
            }
        }
        Some(self.default.clone())
    }
}

/// A2 — Config TLS con SNI por-host (vhost): `default_*` es el fallback; cada host
/// (exacto o `*.dominio`) presenta su propio cert. Defaults seguros (TLS 1.2+).
pub fn build_tls_config_sni(
    default_cert: &str,
    default_key: &str,
    hosts: Vec<(String, String, String)>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let default = std::sync::Arc::new(load_certified_key(default_cert, default_key)?);
    let mut by_name: HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>> = HashMap::new();
    let mut wildcards: Vec<(String, std::sync::Arc<rustls::sign::CertifiedKey>)> = Vec::new();
    for (pattern, cert, key) in hosts {
        let ck = std::sync::Arc::new(load_certified_key(&cert, &key)?);
        if let Some(suffix) = pattern.strip_prefix("*.") {
            wildcards.push((format!(".{}", suffix.to_ascii_lowercase()), ck));
        } else {
            by_name.insert(pattern.to_ascii_lowercase(), ck);
        }
    }
    let resolver = std::sync::Arc::new(SniResolver { default, by_name, wildcards });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {}", e))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A2 — Loop de redirección: escucha (típico :80) y responde 301 a https://host[:port].
/// Lee sólo la request line + headers; un hilo liviano por request.
pub fn serve_redirect(listener: TcpListener, https_port: u16) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _ = redirect_one(stream, https_port);
            });
    }
}

fn redirect_one(stream: TcpStream, https_port: u16) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let (_, target, _, headers) = match read_request_head(&mut reader) {
        Some(x) => x,
        None => return Ok(()),
    };
    let host_hdr = header_value(&headers, "host");
    let host = host_hdr.split(':').next().unwrap_or("").to_string();
    let authority = if https_port == 443 || host.is_empty() {
        host
    } else {
        format!("{}:{}", host, https_port)
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        authority, target
    );
    let stream = reader.get_mut();
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// Head parseado de una request: (método, target, versión, headers).
type RequestHead = (String, String, String, Vec<(String, String)>);

fn read_request_head<R: BufRead>(reader: &mut R) -> Option<RequestHead> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None; // EOF / conexión cerrada
    }
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return None;
    }
    let mut it = line.splitn(3, ' ');
    let method = it.next()?.to_string();
    let target = it.next()?.to_string();
    let version = it.next().unwrap_or("HTTP/1.1").to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::respond::{
        append_header_val, build_set_cookie, make_raw_val, parse_cookie_opts, validate_header,
    };
    use synsema_core::interpreter::Control;
    use synsema_core::types::{syn_bool, syn_int, syn_map, syn_text};
    use std::io::Read; // GzDecoder::read_to_end en los tests de gzip

    #[test]
    fn specificity_ordering() {
        // estático < :param < catchall, por segmento.
        assert_eq!(specificity("/products"), vec![0]);
        assert_eq!(specificity("/products/:id"), vec![0, 1]);
        assert_eq!(specificity("/files/*path"), vec![0, 2]);
        assert_eq!(specificity("/"), Vec::<i32>::new());
        // El más específico ordena primero (lista ascendente).
        let mut routes = vec!["/a/*x", "/a/:id", "/a/b"];
        routes.sort_by_key(|p| specificity(p));
        assert_eq!(routes, vec!["/a/b", "/a/:id", "/a/*x"]);
    }

    #[test]
    fn path_match_exact_and_params() {
        assert!(path_match("/health", "/health").is_some());
        assert!(path_match("/health", "/other").is_none());

        let p = path_match("/products/:id", "/products/42").unwrap();
        assert_eq!(p.get("id").map(String::as_str), Some("42"));

        // longitudes distintas → no matchea
        assert!(path_match("/products/:id", "/products/42/extra").is_none());
        assert!(path_match("/products/:id", "/products").is_none());
    }

    #[test]
    fn path_match_catchall() {
        let p = path_match("/files/*path", "/files/a/b/c.txt").unwrap();
        assert_eq!(p.get("path").map(String::as_str), Some("a/b/c.txt"));
        // catchall necesita al menos un segmento
        assert!(path_match("/files/*path", "/files").is_none());
    }

    #[test]
    fn path_match_url_decodes_params() {
        let p = path_match("/u/:name", "/u/jos%C3%A9").unwrap();
        assert_eq!(p.get("name").map(String::as_str), Some("josé"));
    }

    #[test]
    fn param_last_segment_detection() {
        assert!(param_last_segment("/blog/:slug"));
        assert!(!param_last_segment("/blog/post"));
        assert!(!param_last_segment("/files/*path"));
    }

    // A1.v2/v3: formas de las rutas reservadas de aprobaciones. Sin gateway cableado
    // no existen; con él: GET lista, POST {id}, GET {id}/{token} (link) — y NUNCA
    // 3+ segmentos.
    #[test]
    fn approvals_route_shapes() {
        struct NoQueue;
        impl ApprovalsGateway for NoQueue {
            fn list(&self) -> Vec<ApprovalSummary> {
                Vec::new()
            }
            fn respond(
                &self,
                _id: &str,
                _token: &str,
                _decision: Option<bool>,
                _value: Option<&str>,
            ) -> ApprovalOutcome {
                ApprovalOutcome::NotFound
            }
        }
        let mut rt = ServeRuntime::new(
            0,
            "127.0.0.1".to_string(),
            Vec::new(),
            None,
            None,
            8,
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        assert!(!rt.is_approvals_route("GET", "/approvals"), "sin gateway no hay rutas");
        rt.approvals = Some(Arc::new(NoQueue));
        assert!(rt.is_approvals_route("GET", "/approvals"));
        assert!(rt.is_approvals_route("POST", "/approvals/interact_1"));
        assert!(rt.is_approvals_route("GET", "/approvals/interact_1/abc123"));
        assert!(!rt.is_approvals_route("GET", "/approvals/interact_1"), "GET de 1 segmento no es link");
        assert!(!rt.is_approvals_route("POST", "/approvals/interact_1/abc123"), "el link es GET-only");
        assert!(!rt.is_approvals_route("GET", "/approvals/x/y/z"), "3+ segmentos no matchean");
        assert!(!rt.is_approvals_route("GET", "/approvals/x/"), "token vacío no matchea");
        assert!(!rt.is_approvals_route("POST", "/approvals/"), "id vacío no matchea");
    }

    #[test]
    fn split_format_suffix_works() {
        assert_eq!(split_format_suffix("/blog/hola.json"), ("/blog/hola".into(), Some("json".into())));
        assert_eq!(split_format_suffix("/a.md"), ("/a".into(), Some("md".into())));
        assert_eq!(split_format_suffix("/plain"), ("/plain".into(), None));
        // un sufijo solo (".json") sin nombre no cuenta
        assert_eq!(split_format_suffix("/.json"), ("/.json".into(), None));
        // un sufijo tras '/' no cuenta
        assert_eq!(split_format_suffix("/dir/.md"), ("/dir/.md".into(), None));
    }

    #[test]
    fn negotiate_format_defaults_html() {
        assert_eq!(negotiate_format(""), "html");
        assert_eq!(negotiate_format("*/*"), "html");
        assert_eq!(negotiate_format("text/html"), "html");
        assert_eq!(negotiate_format("application/json"), "json");
        assert_eq!(negotiate_format("text/markdown"), "md");
        // html gana si está presente junto a otro
        assert_eq!(negotiate_format("application/json, text/html"), "html");
    }

    #[test]
    fn parse_body_size_units() {
        assert_eq!(parse_body_size_str("512kb"), Some(512 * 1024));
        assert_eq!(parse_body_size_str("10mb"), Some(10 * 1024 * 1024));
        assert_eq!(parse_body_size_str("1gb"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_body_size_str("2048"), Some(2048));
        assert_eq!(parse_body_size_str("unlimited"), None);
        assert_eq!(parse_body_size_str("none"), None);
        assert_eq!(parse_body_size_str("garbage"), Some(MAX_BODY));
    }

    #[test]
    fn parse_path_query_basic() {
        let (p, q) = parse_path_query("/search?q=hello+world&limit=10");
        assert_eq!(p, "/search");
        assert_eq!(q.get("q").map(String::as_str), Some("hello world"));
        assert_eq!(q.get("limit").map(String::as_str), Some("10"));
        let (p2, q2) = parse_path_query("/plain");
        assert_eq!(p2, "/plain");
        assert!(q2.is_empty());
    }

    // ===================== A2: estáticos de producción =====================

    #[test]
    fn parse_range_forms() {
        // bytes=START-END inclusivos
        assert_eq!(parse_range("bytes=0-3", 10), Some((0, 3)));
        // bytes=START- → hasta el final
        assert_eq!(parse_range("bytes=5-", 10), Some((5, 9)));
        // bytes=-N → últimos N
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        // END recortado a size-1
        assert_eq!(parse_range("bytes=2-999", 10), Some((2, 9)));
        // start fuera de rango → None (416)
        assert_eq!(parse_range("bytes=10-12", 10), None);
        assert_eq!(parse_range("bytes=20-", 10), None);
        // start > end → None
        assert_eq!(parse_range("bytes=5-2", 10), None);
        // size 0 → None
        assert_eq!(parse_range("bytes=0-0", 0), None);
        // sin prefijo bytes= → None
        assert_eq!(parse_range("0-3", 10), None);
    }

    #[test]
    fn compressible_types() {
        assert!(is_compressible("text/html"));
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("text/css"));
        assert!(is_compressible("application/json"));
        assert!(is_compressible("image/svg+xml"));
        assert!(is_compressible("text/plain"));
        assert!(!is_compressible("image/png"));
        assert!(!is_compressible("application/octet-stream"));
        assert!(!is_compressible("font/woff2"));
    }

    #[test]
    fn cache_control_specs() {
        assert_eq!(cache_control_value("immutable").unwrap(), "public, max-age=31536000, immutable");
        assert_eq!(cache_control_value("no-store").unwrap(), "no-store");
        assert_eq!(cache_control_value("30s").unwrap(), "public, max-age=30");
        assert_eq!(cache_control_value("5m").unwrap(), "public, max-age=300");
        assert_eq!(cache_control_value("1h").unwrap(), "public, max-age=3600");
        assert_eq!(cache_control_value("7d").unwrap(), "public, max-age=604800");
        assert_eq!(cache_control_value("120").unwrap(), "public, max-age=120");
        assert_eq!(cache_control_value(" 1H ").unwrap(), "public, max-age=3600");
        assert!(cache_control_value("rapido").is_err());
        assert!(cache_control_value("1w").is_err());
        assert!(cache_control_value("").is_err());
    }

    #[test]
    fn form_urlencoded_parses() {
        let m = parse_form_urlencoded("nombre=Jo%C3%ABl&email=a%40b.com&x=1+2&vacio=&=sin");
        assert_eq!(m.get("nombre").unwrap(), "Joël");
        assert_eq!(m.get("email").unwrap(), "a@b.com");
        assert_eq!(m.get("x").unwrap(), "1 2");
        assert_eq!(m.get("vacio").unwrap(), "");
        assert!(!m.contains_key("")); // clave vacía ignorada, como el query string
        // último valor gana
        let m2 = parse_form_urlencoded("a=1&a=2");
        assert_eq!(m2.get("a").unwrap(), "2");
    }

    #[test]
    fn multipart_boundary_and_parts() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=----abc123").as_deref(),
            Some("----abc123")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"quoted\"").as_deref(),
            Some("quoted")
        );
        assert!(multipart_boundary("application/json").is_none());

        let body = b"--B\r\nContent-Disposition: form-data; name=\"campo\"\r\n\r\nvalor\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01BIN\r\n--B--\r\n";
        let parts = parse_multipart("B", body);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "campo");
        assert!(parts[0].filename.is_none());
        assert_eq!(parts[0].data, b"valor");
        assert_eq!(parts[1].name, "f");
        assert_eq!(parts[1].filename.as_deref(), Some("a.bin"));
        assert_eq!(parts[1].content_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(parts[1].data, b"\x00\x01BIN"); // bytes exactos, sin decodificar
    }

    #[test]
    fn static_fallback_serves_index_on_miss() {
        let dir = std::env::temp_dir().join("syn_static_fallback_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("index.html"), b"SHELL").unwrap();
        let rt = ServeRuntime::new(
            0,
            "0.0.0.0".to_string(),
            Vec::new(),
            None,
            None,
            64,
            vec![StaticMountSpec {
                prefix: "/".to_string(),
                dir: dir.to_string_lossy().into_owned(),
                cache: Some("public, max-age=60".to_string()),
                fallback: Some("index.html".to_string()),
            }],
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        // Miss → fallback con 200 + Cache-Control del mount.
        let r = rt.default_host.serve_static_full("/ruta/spa/interna", &[]).expect("fallback");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"SHELL");
        assert!(r.extra.iter().any(|(k, v)| k == "Cache-Control" && v == "public, max-age=60"));
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"hola mundo, esto se comprime bien bien bien bien bien".repeat(10);
        let gz = gzip_bytes(&data).expect("gzip");
        // El header gzip arranca con 0x1f 0x8b.
        assert_eq!(&gz[..2], &[0x1f, 0x8b]);
        let mut dec = flate2::read::GzDecoder::new(&gz[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    /// Construye un ServeRuntime mínimo con un único static mount sobre `dir`.
    fn static_rt(dir: &str) -> ServeRuntime {
        ServeRuntime::new(
            0,
            "0.0.0.0".to_string(),
            Vec::new(),
            None,
            None,
            64,
            vec![StaticMountSpec {
                prefix: "/".to_string(),
                dir: dir.to_string(),
                cache: None,
                fallback: None,
            }],
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        )
    }

    #[test]
    fn serve_static_etag_range_gzip() {
        // dir temporal único para este test
        let dir = std::env::temp_dir().join("syn_static_a2_test");
        let _ = std::fs::create_dir_all(&dir);
        let body = b"<!doctype html><h1>hola</h1> contenido suficiente para comprimir".to_vec();
        std::fs::write(dir.join("index.html"), &body).unwrap();
        let rt = static_rt(&dir.to_string_lossy());

        // (1) GET normal → 200 + ETag + body completo.
        let r = rt.default_host.serve_static_full("/index.html", &[]).expect("estático");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, body);
        let etag = r
            .extra
            .iter()
            .find(|(k, _)| k == "ETag")
            .map(|(_, v)| v.clone())
            .expect("ETag");
        assert!(etag.starts_with('"') && etag.ends_with('"'));

        // (2) If-None-Match con ese etag → 304 sin body.
        let h304 = vec![("If-None-Match".to_string(), etag.clone())];
        let r = rt.default_host.serve_static_full("/index.html", &h304).expect("estático");
        assert_eq!(r.status, 304);
        assert!(r.body.is_empty());

        // (3) Range bytes=0-3 → 206 + Content-Range + 4 bytes.
        let hr = vec![("Range".to_string(), "bytes=0-3".to_string())];
        let r = rt.default_host.serve_static_full("/index.html", &hr).expect("estático");
        assert_eq!(r.status, 206);
        assert_eq!(r.body, &body[0..=3]);
        let cr = r.extra.iter().find(|(k, _)| k == "Content-Range").map(|(_, v)| v.clone());
        assert_eq!(cr, Some(format!("bytes 0-3/{}", body.len())));

        // (4) Accept-Encoding: gzip sobre text/html → Content-Encoding gzip + Vary.
        let hg = vec![("Accept-Encoding".to_string(), "gzip, deflate".to_string())];
        let r = rt.default_host.serve_static_full("/index.html", &hg).expect("estático");
        assert_eq!(r.status, 200);
        assert!(r
            .extra
            .iter()
            .any(|(k, v)| k == "Content-Encoding" && v == "gzip"));
        assert!(r.extra.iter().any(|(k, v)| k == "Vary" && v == "Accept-Encoding"));
        let mut dec = flate2::read::GzDecoder::new(&r.body[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // (5) path inexistente → None.
        assert!(rt.default_host.serve_static_full("/nope.html", &[]).is_none());
    }

    // ---- Tanda web-auth, ítems A/B: with_header + cookies ----

    #[test]
    fn validate_header_rules() {
        assert!(validate_header("with_header", "X-Request-Id", "abc").is_ok());
        assert!(validate_header("with_header", "Cache-Control", "no-store").is_ok());
        // Nombre vacío, char inválido, prohibidos.
        assert!(validate_header("with_header", "", "v").is_err());
        assert!(validate_header("with_header", "X Header", "v").is_err(), "espacio");
        assert!(validate_header("with_header", "X:Y", "v").is_err());
        for banned in [
            "Content-Length",
            "transfer-encoding",
            "Connection",
            "keep-alive",
            "Upgrade",
            "TE",
            "Trailer",
            "Content-Type",
        ] {
            assert!(validate_header("with_header", banned, "v").is_err(), "{}", banned);
        }
        // CR/LF y controles en el valor → header injection, error.
        assert!(validate_header("with_header", "X-A", "a\r\nSet-Cookie: pwn=1").is_err());
        assert!(validate_header("with_header", "X-A", "a\nb").is_err());
        assert!(validate_header("with_header", "X-A", "a\x01b").is_err());
    }

    #[test]
    fn with_header_wraps_and_accumulates() {
        let inner = make_raw_val("hola".to_string(), "text/plain", 200);
        let w1 = append_header_val(&inner, "X-A".to_string(), "1".to_string());
        let w2 = append_header_val(&w1, "X-B".to_string(), "2".to_string());
        // Acumula en el MISMO wrapper (no anida) y preserva el orden.
        match &w2 {
            SynValue::Server(s) => match &**s {
                ServerValue::WithHeaders { inner, headers } => {
                    assert_eq!(
                        headers,
                        &vec![
                            ("X-A".to_string(), "1".to_string()),
                            ("X-B".to_string(), "2".to_string())
                        ]
                    );
                    assert!(
                        matches!(&**inner, SynValue::Server(i) if matches!(&**i, ServerValue::Raw { .. })),
                        "inner es el Raw original, sin anidar"
                    );
                }
                _ => panic!("expected WithHeaders"),
            },
            _ => panic!("expected Server value"),
        }
    }

    #[test]
    fn set_cookie_defaults_and_options() {
        let o = parse_cookie_opts("set_cookie", None, true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "abc123", &o).ok().unwrap();
        // Defaults seguros: Path=/; Secure; HttpOnly; SameSite=Lax.
        assert_eq!(c, "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
        // max_age + overrides.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(86400));
        m.insert("path".to_string(), syn_text("/app"));
        m.insert("same_site".to_string(), syn_text("Strict"));
        m.insert("http_only".to_string(), syn_bool(false));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "v", &o).ok().unwrap();
        assert_eq!(c, "sid=v; Max-Age=86400; Path=/app; Secure; SameSite=Strict");
    }

    #[test]
    fn set_cookie_fail_strong() {
        let o = parse_cookie_opts("set_cookie", None, true).ok().unwrap();
        // Nombre/valor inválidos (RFC 6265): el error sugiere base64url.
        assert!(build_set_cookie("set_cookie", "s id", "v", &o).is_err());
        assert!(build_set_cookie("set_cookie", "", "v", &o).is_err());
        match build_set_cookie("set_cookie", "sid", "a b", &o) {
            Err(Control::Error(e)) => assert!(
                e.to_string().contains("base64url"),
                "el error sugiere el fix: {}",
                e
            ),
            _ => panic!("valor con espacio debe fallar"),
        }
        assert!(build_set_cookie("set_cookie", "sid", "a;b", &o).is_err());
        assert!(build_set_cookie("set_cookie", "sid", "a\"b", &o).is_err());
        // same_site None sin Secure → error (el browser la rechazaría).
        let mut m = IndexMap::new();
        m.insert("same_site".to_string(), syn_text("None"));
        m.insert("secure".to_string(), syn_bool(false));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        assert!(build_set_cookie("set_cookie", "sid", "v", &o).is_err());
        // …con Secure sí vale.
        let mut m = IndexMap::new();
        m.insert("same_site".to_string(), syn_text("None"));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "v", &o).ok().unwrap();
        assert!(c.ends_with("SameSite=None") && c.contains("Secure"));
        // Opt desconocida → error con las válidas.
        let mut m = IndexMap::new();
        m.insert("httponly".to_string(), syn_bool(true));
        assert!(parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).is_err());
        // max_age negativo o no-entero → error.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(-1));
        assert!(parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).is_err());
        // clear_cookie sólo acepta path/domain.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(5));
        assert!(parse_cookie_opts("clear_cookie", Some(&syn_map(m)), false).is_err());
    }

    #[test]
    fn parse_cookies_rfc6265() {
        let h = |v: &str| vec![("Cookie".to_string(), v.to_string())];
        // split por `;`, trim, primer `=` separa, SIN decodificar.
        assert_eq!(
            parse_cookies(&h("sid=abc; theme=dark")),
            vec![
                ("sid".to_string(), "abc".to_string()),
                ("theme".to_string(), "dark".to_string())
            ]
        );
        // El valor conserva `=` internos (primer `=` separa).
        assert_eq!(
            parse_cookies(&h("tok=a=b=c")),
            vec![("tok".to_string(), "a=b=c".to_string())]
        );
        // Duplicado: gana la PRIMERA aparición (orden RFC).
        assert_eq!(
            parse_cookies(&h("sid=first; sid=second")),
            vec![("sid".to_string(), "first".to_string())]
        );
        // Sin header → vacío; segmentos malformados se saltean.
        assert_eq!(parse_cookies(&[]), Vec::<(String, String)>::new());
        assert_eq!(
            parse_cookies(&h("junk; =nada; sid=ok")),
            vec![("sid".to_string(), "ok".to_string())]
        );
        // No se URL-decodea (los %XX quedan tal cual).
        assert_eq!(
            parse_cookies(&h("v=a%20b")),
            vec![("v".to_string(), "a%20b".to_string())]
        );
    }

    #[test]
    fn build_response_unwraps_nothing_for_with_headers() {
        // El dispatch pela el wrapper ANTES de build_response; este test fija que
        // el valor envuelto (inner) responde idéntico a como respondería solo.
        let inner = make_raw_val("hola".to_string(), "text/plain", 201);
        let q = IndexMap::new();
        let (st_direct, _) = build_response(Some(&inner), &q).unwrap();
        assert_eq!(st_direct, 201);
    }
}
