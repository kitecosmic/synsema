//! Cliente WebSocket — primitiva GENERAL del lenguaje (suscripciones RPC, exchanges,
//! Discord/Slack, cualquier feed en vivo). Batch 13 lo trajo bloqueante-por-conexión;
//! **Batch 15 lo termina como transporte de primera clase**: multiplexado a escala,
//! reconexión, keepalive/half-open, backpressure — sobre un core NO-bloqueante con un
//! poller de readiness (`mio`: epoll/kqueue/IOCP).
//!
//! - **G21 — no evade el modelo de red.** `ws_connect(url)` (y CADA reconexión) exige
//!   la capability `net(host)` EXISTENTE (misma que `http_*`/`fetch`, scope por
//!   hostname); dentro de `sandbox` → denegado. La reconexión JAMÁS escala el scope
//!   (mismo host) y `wss` re-valida el cert en cada (re)connect. WS es transporte.
//! - **G25 — nunca busy-spin, nunca cuelga.** `ws_select`/keepalive son readiness-
//!   driven: mientras está ocioso, el hilo DUERME en `mio::Poll` (CPU ~0, una sola
//!   iteración de poll por tick idle — `POLL_ITERS` lo mide). Todo op tiene deadline;
//!   un peer que murió en silencio se detecta por keepalive y no cuelga al agente.
//! - **G26 — memoria acotada bajo entrada hostil.** Cola inbound por conexión acotada
//!   (`max_queue`) + `max_message_size` (batch 13) + tope de conexiones. La política
//!   por default es **backpressure TCP real**: con la cola llena se DEJA de leer el
//!   socket (se despausa al drenar) — la ventana TCP frena al peer, sin pérdida de
//!   datos ni OOM. `drop_oldest`/`error` son opt-in.
//! - **G27 — reconexión honesta.** Backoff exponencial ACOTADO y no-bloqueante (no
//!   frena a las demás conexiones); `on_reconnect` corre con las MISMAS caps para
//!   resubscribir; sin `reconnect` no hay reconexión silenciosa (opt-in explícito).
//!   `ws_status`/`ws_stats` no mienten.
//!
//! **Motor síncrono (la frontera honesta).** No hay hilo de fondo por conexión (eso
//! rompería el aislamiento CSP y la promesa "sin thread-per-conn"). El keepalive y la
//! reconexión AVANZAN mientras el programa está dentro de `ws_select`/`ws_recv`/
//! `ws_status` — el agente arma su event-loop con un `while` + `ws_select`, y ahí el
//! pump tickea. Un `on_reconnect` necesita el intérprete (para correr la task de
//! resubscribe), así que corre al volver de esas llamadas.
//!
//! **`parallel_map` (fan-out horizontal).** Cada worker recibe su propio intérprete
//! sync que hereda las caps y wirea SUS PROPIOS builtins WS (registro por-worker). Un
//! worker puede `ws_connect` su feed, procesarlo y devolver — miles de feeds repartidos
//! en el pool. Los handles NO cruzan workers (aislamiento CSP): cada worker es dueño de
//! los suyos.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpStream as StdTcp, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::net::TcpStream as MioTcp;
use mio::{Events, Interest, Poll, Token};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};
use tungstenite::Bytes;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_bytes, syn_int, syn_map, syn_number, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Techo duro del tamaño de mensaje (el configurable no lo puede superar).
const MAX_MESSAGE_CEILING: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Timeout default de connect/handshake y de `ws_recv` (mismo criterio que `wait_for`).
const DEFAULT_TIMEOUT_SECS: f64 = 30.0;
/// Cola inbound por conexión (backpressure): tope de mensajes DECODIFICADOS en espera.
const DEFAULT_MAX_QUEUE: usize = 1024;
/// Tope en BYTES de la cola inbound (G26): la cota por cantidad no alcanza sola —
/// 1024 mensajes de 16 MiB serían 16 GiB. Se acota en las DOS dimensiones.
const DEFAULT_MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUEUE_BYTES_CEILING: usize = 1024 * 1024 * 1024;
/// Tope blando de conexiones simultáneas por intérprete (anti-footgun de loop).
const DEFAULT_MAX_CONNS: usize = 4096;
const MAX_CONNS_CEILING: usize = 65536;
/// Backoff de reconexión: base y techo (exponencial acotado).
const DEFAULT_BACKOFF_BASE: Duration = Duration::from_millis(500);
const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 10;

thread_local! {
    /// Iteraciones del loop de `mio::Poll` (test de "no busy-spin": una espera ociosa
    /// hace UNA sola iteración). Contador por-hilo → cada worker de parallel_map cuenta
    /// el suyo. Sólo lo lee la suite; el runtime no depende de él.
    pub static POLL_ITERS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

// =========================================================
// Stream: TCP (std durante el handshake, mio en régimen) plano o TLS.
// Se promueve std→mio EN SITIO tras el handshake (sin mover el WebSocket).
// =========================================================

type TlsStd = rustls::StreamOwned<rustls::ClientConnection, StdTcp>;
type TlsMio = rustls::StreamOwned<rustls::ClientConnection, MioTcp>;

enum StreamKind {
    PlainStd(StdTcp),
    PlainMio(MioTcp),
    TlsStd(Box<TlsStd>),
    TlsMio(Box<TlsMio>),
    /// Placeholder transitorio durante la promoción (Read/Write erroran).
    Void,
}

struct WsStream {
    inner: StreamKind,
}

impl WsStream {
    fn plain_std(t: StdTcp) -> Self {
        WsStream { inner: StreamKind::PlainStd(t) }
    }
    fn tls_std(s: TlsStd) -> Self {
        WsStream { inner: StreamKind::TlsStd(Box::new(s)) }
    }

    /// Convierte el socket subyacente std (bloqueante, usado para el handshake) a mio
    /// (no-bloqueante, para el poller) EN SITIO — preserva la sesión TLS (el
    /// `ClientConnection` viaja intacto). Idempotente si ya es mio.
    fn promote_to_mio(&mut self) -> Result<(), Control> {
        let kind = std::mem::replace(&mut self.inner, StreamKind::Void);
        let promoted = match kind {
            StreamKind::PlainStd(t) => {
                t.set_nonblocking(true).map_err(|e| err(format!("ws: cannot set nonblocking: {}", e)))?;
                StreamKind::PlainMio(MioTcp::from_std(t))
            }
            StreamKind::TlsStd(b) => {
                let TlsStd { conn, sock } = *b;
                sock.set_nonblocking(true)
                    .map_err(|e| err(format!("ws: cannot set nonblocking: {}", e)))?;
                let mio = MioTcp::from_std(sock);
                StreamKind::TlsMio(Box::new(rustls::StreamOwned::new(conn, mio)))
            }
            other => other, // ya mio (o Void) — no-op
        };
        self.inner = promoted;
        Ok(())
    }

    /// El `mio::net::TcpStream` subyacente (para registrar/reregistrar en el Poll).
    /// Sólo válido tras `promote_to_mio` (invariante interno).
    fn source(&mut self) -> &mut MioTcp {
        match &mut self.inner {
            StreamKind::PlainMio(t) => t,
            StreamKind::TlsMio(s) => &mut s.sock,
            _ => unreachable!("source() antes de promote_to_mio"),
        }
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            StreamKind::PlainStd(t) => t.read(buf),
            StreamKind::PlainMio(t) => t.read(buf),
            StreamKind::TlsStd(s) => s.read(buf),
            StreamKind::TlsMio(s) => s.read(buf),
            StreamKind::Void => Err(std::io::Error::other("ws stream in transit")),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            StreamKind::PlainStd(t) => t.write(buf),
            StreamKind::PlainMio(t) => t.write(buf),
            StreamKind::TlsStd(s) => s.write(buf),
            StreamKind::TlsMio(s) => s.write(buf),
            StreamKind::Void => Err(std::io::Error::other("ws stream in transit")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            StreamKind::PlainStd(t) => t.flush(),
            StreamKind::PlainMio(t) => t.flush(),
            StreamKind::TlsStd(s) => s.flush(),
            StreamKind::TlsMio(s) => s.flush(),
            StreamKind::Void => Ok(()),
        }
    }
}

// =========================================================
// Configuración por conexión (opt-in vía opts de ws_connect)
// =========================================================

#[derive(Clone)]
struct ReconnectCfg {
    max_retries: u32,
    backoff_base: Duration,
    backoff_max: Duration,
    on_reconnect: Option<SynValue>, // task a correr tras reconectar (resubscribe)
}

#[derive(Clone)]
struct KeepaliveCfg {
    interval: Duration,
    timeout: Duration,
}

#[derive(Clone, Copy, PartialEq)]
enum OnFull {
    /// Backpressure TCP real: se deja de leer el socket (default). Sin pérdida.
    Block,
    /// Se descarta el más viejo para hacer lugar.
    DropOldest,
    /// La conexión se cierra con error atrapable.
    Error,
}

/// Parámetros para (re)establecer la conexión — se guardan para poder reconectar.
#[derive(Clone)]
struct DialParams {
    url: String,
    host: String,
    port: u16,
    tls: bool,
    headers: Vec<(String, String)>,
    subprotocols: Vec<String>,
    max_msg: usize,
    connect_timeout: Duration,
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Open,
    Reconnecting,
    Closed,
}

#[derive(Default, Clone)]
struct Stats {
    sent: u64,
    received: u64,
    reconnects: u64,
    last_pong: Option<Instant>,
}

struct Conn {
    ws: WebSocket<WsStream>,
    token: Token,
    dial: DialParams,
    negotiated_subprotocol: Option<String>,
    inbound: VecDeque<SynValue>,
    /// Bytes de payload encolados (la cota G26 tiene DOS dimensiones: cantidad Y bytes).
    queued_bytes: usize,
    max_queue: usize,
    max_queue_bytes: usize,
    on_full: OnFull,
    read_paused: bool, // cola llena (política Block) → sin interés READABLE
    pending_flush: bool,
    reconnect: Option<ReconnectCfg>,
    keepalive: Option<KeepaliveCfg>,
    status: Status,
    stats: Stats,
    // keepalive/actividad
    last_activity: Instant,
    awaiting_pong_since: Option<Instant>,
    // reconexión no-bloqueante
    retries_left: u32,
    reconnect_at: Option<Instant>,
    current_interest: Option<Interest>,
    /// Cuando la conexión se cierra definitivamente, se encola UN `close` sintético
    /// para que el próximo recv/select lo entregue y retire el handle.
    closed_emitted: bool,
    /// Un error FATAL de protocolo (frame sobre el límite, frame inválido) sin
    /// reconexión: lo entrega el próximo recv/select como error atrapable (NO un
    /// `close` silencioso — el agente debe saber que el peer violó el protocolo).
    last_error: Option<String>,
}

impl Conn {
    /// Interés deseado en el poller según el estado (READABLE salvo pausa de
    /// backpressure; +WRITABLE si hay flush pendiente). None = no registrar (reconnecting).
    fn desired_interest(&self) -> Option<Interest> {
        if self.status != Status::Open {
            return None;
        }
        let mut i = if self.read_paused { None } else { Some(Interest::READABLE) };
        if self.pending_flush {
            i = Some(i.map_or(Interest::WRITABLE, |x| x.add(Interest::WRITABLE)));
        }
        i
    }
}

// =========================================================
// Registro por-intérprete
// =========================================================

struct WsRegistry {
    poll: Poll,
    events: Events,
    conns: HashMap<i64, Conn>,
    token_to_handle: HashMap<usize, i64>,
    next_id: i64,
    next_token: usize,
    max_conns: usize,
    /// Cursor round-robin de `first_ready` (equidad de `ws_select`).
    rr: std::cell::Cell<usize>,
    caps: Rc<RefCell<CapabilitySet>>,
}

/// Un `on_reconnect` que quedó pendiente de correr FUERA del borrow del registro
/// (la task puede re-entrar a ws_send/ws_status → no puede correr con el registro
/// prestado). El wrapper del builtin la ejecuta tras soltar el borrow.
struct PendingReconnect {
    handle: i64,
    task: SynValue,
}

type Registry = Rc<RefCell<WsRegistry>>;

// =========================================================
// Helpers de argumentos
// =========================================================

fn require_net(caps: &Rc<RefCell<CapabilitySet>>, url: &str) -> Result<(), Control> {
    let host = match url_hostname(url) {
        Some(h) if !h.is_empty() => h,
        _ => url.to_string(),
    };
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(host)), "ws_connect()")
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

fn parse_ws_url(url: &str, fname: &str) -> Result<(String, u16, bool), Control> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| err(format!("{}: invalid URL (no scheme): use ws:// or wss://", fname)))?;
    let tls = match scheme.to_lowercase().as_str() {
        "ws" => false,
        "wss" => true,
        "http" | "https" => {
            return Err(err(format!(
                "{}: use the WebSocket scheme (ws:// or wss://), not {}://",
                fname, scheme
            )))
        }
        other => {
            return Err(err(format!("{}: unsupported scheme {:?}; use ws:// or wss://", fname, other)))
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            let port: u16 = p.parse().map_err(|_| err(format!("{}: invalid port in URL", fname)))?;
            (h.to_string(), port)
        }
        _ => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(err(format!("{}: the URL has no host", fname)));
    }
    Ok((host, port, tls))
}

fn timeout_arg(v: Option<&SynValue>, fname: &str) -> Result<Duration, Control> {
    let secs = match v {
        None | Some(SynValue::Nothing) => DEFAULT_TIMEOUT_SECS,
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f < 0.0 {
                return Err(err(format!("{}: the timeout must be a non-negative number of seconds", fname)));
            }
            f
        }
        Some(other) => {
            return Err(err(format!(
                "{}: the timeout must be a number of seconds, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    Ok(Duration::from_secs_f64(secs.min(24.0 * 3600.0)))
}

fn conn_handle(v: &SynValue, fname: &str) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) => n
            .to_i64_trunc()
            .ok_or_else(|| err(format!("{}: the connection handle must be an integer", fname))),
        other => Err(err(format!(
            "{}: expected a connection handle from ws_connect(), got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn ws_error(e: tungstenite::Error, fname: &str) -> Control {
    err(format!("{}: {}", fname, ws_error_detail(&e)))
}

/// Bytes de payload de un mensaje encolado (`{type, data}`) — la unidad de la
/// cota `max_queue_bytes`. Un `close` u otro frame sin payload cuenta 0.
fn msg_payload_size(v: &SynValue) -> usize {
    match v {
        SynValue::Map(m) => match m.borrow().get("data") {
            Some(SynValue::Text(t)) => t.as_ref().len(),
            Some(SynValue::Bytes(b)) => b.len(),
            _ => 0,
        },
        _ => 0,
    }
}

/// Detalle (sin fname) de un error de tungstenite — se guarda en `last_error` y el
/// recv/select que lo entrega le antepone su propio fname.
fn ws_error_detail(e: &tungstenite::Error) -> String {
    use tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed => "the connection is closed".to_string(),
        E::Capacity(c) => format!("message over the size limit: {}", c),
        other => other.to_string(),
    }
}

/// ¿Es un error de "no listo todavía" (no-bloqueante)? tungstenite lo envuelve en Io.
fn is_would_block(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock)
}

// =========================================================
// Establecer la conexión (handshake bloqueante → promoción a mio)
// =========================================================

/// Conecta, hace el handshake TLS+WS en modo BLOQUEANTE (acotado por timeout) y
/// promueve el socket a mio. Re-chequea `net(host)` (G21) — lo llama tanto el
/// connect inicial como cada reconexión. Devuelve el WebSocket listo + el
/// subprotocolo negociado.
fn establish(
    dial: &DialParams,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<(WebSocket<WsStream>, Option<String>), Control> {
    // G21: la MISMA capability net(host) en CADA (re)connect — nunca escala scope.
    require_net(caps, &dial.url)?;

    let addr = format!("{}:{}", dial.host, dial.port);
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| err(format!("ws_connect: cannot resolve {}: {}", dial.host, e)))?
        .next()
        .ok_or_else(|| err(format!("ws_connect: cannot resolve host {}", dial.host)))?;
    let tcp = StdTcp::connect_timeout(&sa, dial.connect_timeout)
        .map_err(|e| err(format!("ws_connect: cannot connect to {}: {}", addr, e)))?;
    let _ = tcp.set_read_timeout(Some(dial.connect_timeout));
    let _ = tcp.set_write_timeout(Some(dial.connect_timeout));
    let _ = tcp.set_nodelay(true);

    let stream = if dial.tls {
        let roots = crate::http::root_cert_store().map_err(|e| err(format!("ws_connect: {}", e)))?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name: rustls::pki_types::ServerName<'static> = dial
            .host
            .as_str()
            .try_into()
            .map(|n: rustls::pki_types::ServerName| n.to_owned())
            .map_err(|_| err(format!("ws_connect: invalid server name: {}", dial.host)))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| err(format!("ws_connect: TLS setup failed: {}", e)))?;
        WsStream::tls_std(rustls::StreamOwned::new(conn, tcp))
    } else {
        WsStream::plain_std(tcp)
    };

    let mut request = dial
        .url
        .as_str()
        .into_client_request()
        .map_err(|e| err(format!("ws_connect: invalid WebSocket URL: {}", e)))?;
    for (k, v) in &dial.headers {
        let name = tungstenite::http::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| err(format!("ws_connect: invalid header name {:?}", k)))?;
        let value = tungstenite::http::header::HeaderValue::from_str(v)
            .map_err(|_| err(format!("ws_connect: invalid value for header {:?}", k)))?;
        request.headers_mut().insert(name, value);
    }
    if !dial.subprotocols.is_empty() {
        let joined = dial.subprotocols.join(", ");
        let value = tungstenite::http::header::HeaderValue::from_str(&joined)
            .map_err(|_| err("ws_connect: invalid subprotocol list"))?;
        request
            .headers_mut()
            .insert(tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL, value);
    }

    let config = WebSocketConfig::default()
        .max_message_size(Some(dial.max_msg))
        .max_frame_size(Some(dial.max_msg));

    let (mut socket, response) =
        tungstenite::client::client_with_config(request, stream, Some(config)).map_err(|e| match e {
            tungstenite::HandshakeError::Interrupted(_) => {
                err(format!("ws_connect: the WebSocket handshake timed out after {:?}", dial.connect_timeout))
            }
            tungstenite::HandshakeError::Failure(e) => {
                err(format!("ws_connect: the WebSocket handshake failed: {}", e))
            }
        })?;

    // Subprotocolo acordado por el server (si pedimos alguno).
    let negotiated = response
        .headers()
        .get(tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Handshake completo sobre el socket bloqueante → ahora a mio (no-bloqueante).
    socket.get_mut().promote_to_mio()?;
    Ok((socket, negotiated))
}

// =========================================================
// El pump: motor readiness-driven (lecturas, keepalive, reconexión, flush)
// =========================================================

impl WsRegistry {
    /// Reregistra el socket de una conexión según su interés deseado. Idempotente.
    fn sync_interest(&mut self, handle: i64) {
        let (want, had) = {
            let Some(c) = self.conns.get(&handle) else { return };
            (c.desired_interest(), c.current_interest)
        };
        if want == had {
            return;
        }
        let Some(c) = self.conns.get_mut(&handle) else { return };
        let source = c.ws.get_mut().source();
        match (had, want) {
            (None, Some(i)) => {
                let _ = self.poll.registry().register(source, c.token, i);
            }
            (Some(_), Some(i)) => {
                let _ = self.poll.registry().reregister(source, c.token, i);
            }
            (Some(_), None) => {
                let _ = self.poll.registry().deregister(source);
            }
            (None, None) => {}
        }
        c.current_interest = want;
    }

    /// Encola un mensaje decodificado respetando la política de backpressure. La
    /// cota vale en DOS dimensiones (cantidad Y bytes — G26: 1024 frames de 16 MiB
    /// serían 16 GiB con cota sólo por cantidad). Devuelve `false` si (política
    /// Error) hay que cerrar la conexión con error atrapable.
    fn enqueue(&mut self, handle: i64, msg: SynValue) -> bool {
        let size = msg_payload_size(&msg);
        let Some(c) = self.conns.get_mut(&handle) else { return true };
        c.stats.received += 1;
        c.last_activity = Instant::now();
        // Tráfico inbound = el peer está VIVO: un pong atrasado detrás de un feed
        // ocupado no debe matar la conexión (falso half-open).
        c.awaiting_pong_since = None;
        let full = c.inbound.len() >= c.max_queue || c.queued_bytes >= c.max_queue_bytes;
        if !full {
            c.inbound.push_back(msg);
            c.queued_bytes += size;
            // Backpressure TCP: al ALCANZAR cualquiera de los topes, pausar la
            // lectura del socket (la ventana TCP frena al peer). Sin pérdida,
            // memoria acotada a max_queue mensajes / ~max_queue_bytes.
            if c.on_full == OnFull::Block
                && (c.inbound.len() >= c.max_queue || c.queued_bytes >= c.max_queue_bytes)
            {
                c.read_paused = true;
            }
            return true;
        }
        // Cola ya llena (DropOldest/Error no pausan la lectura; Block acá es carrera
        // benigna: pausar y descartar nada).
        match c.on_full {
            OnFull::DropOldest => {
                // Sacar los más viejos hasta que el nuevo QUEPA en ambas cotas.
                while !c.inbound.is_empty()
                    && (c.inbound.len() >= c.max_queue || c.queued_bytes + size > c.max_queue_bytes)
                {
                    if let Some(old) = c.inbound.pop_front() {
                        c.queued_bytes = c.queued_bytes.saturating_sub(msg_payload_size(&old));
                    }
                }
                c.inbound.push_back(msg);
                c.queued_bytes += size;
                true
            }
            OnFull::Block => {
                c.read_paused = true;
                true
            }
            OnFull::Error => false,
        }
    }

    /// Overflow con política Error: cierre TERMINAL con error atrapable — jamás un
    /// descarte silencioso. NO se reconecta (la condición es local: el agente lee
    /// más lento que el peer; reconectar con la cola llena repetiría el overflow).
    fn overflow_fail(&mut self, handle: i64) {
        let detail = {
            let Some(c) = self.conns.get(&handle) else { return };
            format!(
                "the inbound queue overflowed ({} messages / {} bytes queued; the program reads slower than the peer sends) — drain with ws_recv/ws_select more often, raise max_queue/max_queue_bytes, or use on_full \"block\" (TCP backpressure) or \"drop_oldest\"",
                c.inbound.len(),
                c.queued_bytes
            )
        };
        {
            let Some(c) = self.conns.get_mut(&handle) else { return };
            let source = c.ws.get_mut().source();
            let _ = self.poll.registry().deregister(source);
        }
        let Some(c) = self.conns.get_mut(&handle) else { return };
        c.current_interest = None;
        c.awaiting_pong_since = None;
        c.last_error = Some(detail);
        c.status = Status::Closed;
    }

    /// Drena TODOS los frames disponibles de una conexión (hasta WouldBlock, cola
    /// llena con Block, o cierre). Traduce cada frame a un SynValue en la cola.
    /// Devuelve `true` si la conexión sigue viva.
    fn drain_reads(&mut self, handle: i64) -> bool {
        loop {
            // Pausa de backpressure: no leer más.
            if self.conns.get(&handle).map(|c| c.read_paused).unwrap_or(true) {
                return true;
            }
            let read = {
                let Some(c) = self.conns.get_mut(&handle) else { return false };
                c.ws.read()
            };
            match read {
                Ok(Message::Text(t)) => {
                    let mut m = indexmap::IndexMap::new();
                    m.insert("type".to_string(), syn_text("text"));
                    m.insert("data".to_string(), syn_text(t.as_str()));
                    if !self.enqueue(handle, syn_map(m)) {
                        self.overflow_fail(handle);
                        return false;
                    }
                }
                Ok(Message::Binary(b)) => {
                    let mut m = indexmap::IndexMap::new();
                    m.insert("type".to_string(), syn_text("binary"));
                    m.insert("data".to_string(), syn_bytes(b.to_vec()));
                    if !self.enqueue(handle, syn_map(m)) {
                        self.overflow_fail(handle);
                        return false;
                    }
                }
                Ok(Message::Ping(_)) => {
                    // tungstenite encola el pong solo; cuenta como actividad y como
                    // prueba de vida (un ping del peer = el peer NO está half-open).
                    if let Some(c) = self.conns.get_mut(&handle) {
                        c.last_activity = Instant::now();
                        c.awaiting_pong_since = None;
                        c.pending_flush = true; // el pong sale en el próximo flush
                    }
                }
                Ok(Message::Pong(_)) => {
                    if let Some(c) = self.conns.get_mut(&handle) {
                        c.awaiting_pong_since = None;
                        c.last_activity = Instant::now();
                        c.stats.last_pong = Some(Instant::now());
                    }
                }
                Ok(Message::Close(frame)) => {
                    let reason = match frame {
                        Some(f) if !f.reason.is_empty() => syn_text(f.reason.to_string()),
                        _ => SynValue::Nothing,
                    };
                    self.mark_gone(handle, reason);
                    return false;
                }
                Ok(Message::Frame(_)) => {} // sólo en modo raw; ignorar
                Err(e) if is_would_block(&e) => return true, // no hay más por ahora
                Err(tungstenite::Error::ConnectionClosed) => {
                    // Cierre limpio del transporte → close (o reconexión).
                    self.mark_gone(handle, SynValue::Nothing);
                    return false;
                }
                Err(e) => {
                    // Violación de protocolo (Capacity, frame inválido): error FATAL
                    // atrapable, no un close silencioso.
                    let detail = ws_error_detail(&e);
                    self.fail_conn(handle, detail);
                    return false;
                }
            }
        }
    }

    /// Una conexión murió: si hay reconexión configurada con reintentos, la agenda;
    /// si no, encola un `close` sintético y la deja lista para retirar.
    fn mark_gone(&mut self, handle: i64, reason: SynValue) {
        let Some(c) = self.conns.get_mut(&handle) else { return };
        // Deregistrar el socket muerto del poller.
        {
            let source = c.ws.get_mut().source();
            let _ = self.poll.registry().deregister(source);
        }
        let Some(c) = self.conns.get_mut(&handle) else { return };
        c.current_interest = None;
        c.awaiting_pong_since = None;
        if let Some(rc) = &c.reconnect {
            if c.retries_left > 0 && rc.max_retries > 0 {
                // Agendar reconexión con backoff exponencial acotado (NO bloquea el
                // pump: se intenta cuando now >= reconnect_at, las demás conns siguen).
                let attempt = rc.max_retries.saturating_sub(c.retries_left);
                let backoff = backoff_delay(rc, attempt);
                c.retries_left -= 1;
                c.status = Status::Reconnecting;
                c.reconnect_at = Some(Instant::now() + backoff);
                return;
            }
        }
        // Sin reconexión (o agotada): cierre definitivo.
        if !c.closed_emitted {
            let mut m = indexmap::IndexMap::new();
            m.insert("type".to_string(), syn_text("close"));
            m.insert("data".to_string(), reason);
            c.inbound.push_back(syn_map(m));
            c.closed_emitted = true;
        }
        c.status = Status::Closed;
    }

    /// Una conexión falló por protocolo (frame sobre el límite, frame inválido). Si
    /// hay reconexión, la agenda (un peer intermitente puede recuperarse); si no,
    /// registra el error para que el próximo recv/select lo entregue atrapable.
    fn fail_conn(&mut self, handle: i64, detail: String) {
        {
            let Some(c) = self.conns.get_mut(&handle) else { return };
            let source = c.ws.get_mut().source();
            let _ = self.poll.registry().deregister(source);
        }
        let Some(c) = self.conns.get_mut(&handle) else { return };
        c.current_interest = None;
        c.awaiting_pong_since = None;
        if let Some(rc) = c.reconnect.clone() {
            if c.retries_left > 0 && rc.max_retries > 0 {
                let attempt = rc.max_retries.saturating_sub(c.retries_left);
                c.retries_left -= 1;
                c.status = Status::Reconnecting;
                c.reconnect_at = Some(Instant::now() + backoff_delay(&rc, attempt));
                return;
            }
        }
        c.last_error = Some(detail);
        c.status = Status::Closed;
    }

    /// Intenta reconectar las conexiones cuyo `reconnect_at` ya venció. Devuelve las
    /// `on_reconnect` a correr fuera del borrow. El connect es bloqueante (acotado);
    /// reconectar es raro.
    fn try_reconnects(&mut self, pending: &mut Vec<PendingReconnect>) {
        let now = Instant::now();
        let due: Vec<i64> = self
            .conns
            .iter()
            .filter(|(_, c)| c.status == Status::Reconnecting && c.reconnect_at.map(|t| now >= t).unwrap_or(false))
            .map(|(h, _)| *h)
            .collect();
        for handle in due {
            let dial = self.conns.get(&handle).map(|c| c.dial.clone());
            let Some(dial) = dial else { continue };
            match establish(&dial, &self.caps) {
                Ok((ws, sub)) => {
                    let task = {
                        let Some(c) = self.conns.get_mut(&handle) else { continue };
                        c.ws = ws;
                        c.negotiated_subprotocol = sub;
                        c.status = Status::Open;
                        c.reconnect_at = None;
                        c.read_paused = false;
                        c.pending_flush = false;
                        c.awaiting_pong_since = None;
                        c.last_activity = Instant::now();
                        c.current_interest = None;
                        c.stats.reconnects += 1;
                        c.reconnect.as_ref().and_then(|r| r.on_reconnect.clone())
                    };
                    self.sync_interest(handle);
                    // Misma cosecha inicial que ws_connect: el handshake de la
                    // reconexión también puede dejar frames en el buffer.
                    self.drain_reads(handle);
                    self.sync_interest(handle);
                    if let Some(task) = task {
                        pending.push(PendingReconnect { handle, task });
                    }
                }
                Err(_) => {
                    // Falló este intento: reagendar si quedan reintentos, si no cerrar.
                    let closed_reason = SynValue::Nothing;
                    let reschedule = {
                        let Some(c) = self.conns.get_mut(&handle) else { continue };
                        if c.retries_left > 0 {
                            if let Some(rc) = c.reconnect.clone() {
                                let attempt = rc.max_retries.saturating_sub(c.retries_left);
                                c.retries_left -= 1;
                                c.reconnect_at = Some(Instant::now() + backoff_delay(&rc, attempt));
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };
                    if !reschedule {
                        if let Some(c) = self.conns.get_mut(&handle) {
                            if !c.closed_emitted {
                                let mut m = indexmap::IndexMap::new();
                                m.insert("type".to_string(), syn_text("close"));
                                m.insert("data".to_string(), closed_reason);
                                c.inbound.push_back(syn_map(m));
                                c.closed_emitted = true;
                            }
                            c.status = Status::Closed;
                        }
                    }
                }
            }
        }
    }

    /// Keepalive: manda ping si toca, y detecta half-open (pong vencido → muerta).
    fn service_keepalive(&mut self) {
        let now = Instant::now();
        let handles: Vec<i64> = self.conns.keys().copied().collect();
        for handle in handles {
            let (send_ping, dead) = {
                let Some(c) = self.conns.get(&handle) else { continue };
                let Some(ka) = &c.keepalive else { continue };
                if c.status != Status::Open {
                    (false, false)
                } else if let Some(since) = c.awaiting_pong_since {
                    (false, now.duration_since(since) >= ka.timeout)
                } else if now.duration_since(c.last_activity) >= ka.interval {
                    (true, false)
                } else {
                    (false, false)
                }
            };
            if dead {
                self.mark_gone(handle, SynValue::Nothing);
                continue;
            }
            if send_ping {
                let ok = {
                    let Some(c) = self.conns.get_mut(&handle) else { continue };
                    c.awaiting_pong_since = Some(now);
                    match c.ws.send(Message::Ping(Bytes::new())) {
                        Ok(()) => true,
                        Err(e) if is_would_block(&e) => {
                            c.pending_flush = true;
                            true
                        }
                        Err(_) => false,
                    }
                };
                if ok {
                    self.sync_interest(handle);
                } else {
                    self.mark_gone(handle, SynValue::Nothing);
                }
            }
        }
    }

    /// Flush del buffer de salida de una conexión (tras un send que quedó a medias).
    fn try_flush(&mut self, handle: i64) {
        let done = {
            let Some(c) = self.conns.get_mut(&handle) else { return };
            if !c.pending_flush {
                return;
            }
            match c.ws.flush() {
                Ok(()) => {
                    c.pending_flush = false;
                    true
                }
                Err(e) if is_would_block(&e) => false,
                Err(_) => {
                    // el peer se fue mientras escribíamos
                    true
                }
            }
        };
        if done {
            let gone = self
                .conns
                .get(&handle)
                .map(|c| c.status != Status::Open)
                .unwrap_or(true);
            if !gone {
                self.sync_interest(handle);
            }
        }
    }

    /// ¿Alguno de los handles objetivo tiene ya un mensaje en cola? Rotación
    /// round-robin (arranca donde terminó la última entrega): un feed parlanchín
    /// al principio de la lista no puede HAMBREAR a los demás — equidad real.
    fn first_ready(&self, targets: &[i64]) -> Option<i64> {
        if targets.is_empty() {
            return None;
        }
        let start = self.rr.get() % targets.len();
        for off in 0..targets.len() {
            let idx = (start + off) % targets.len();
            let h = targets[idx];
            if self.conns.get(&h).map(|c| !c.inbound.is_empty()).unwrap_or(false) {
                self.rr.set(idx + 1);
                return Some(h);
            }
        }
        None
    }

    /// ¿Algún target quedó "accionable" (mensaje en cola o error fatal pendiente)?
    /// Es la condición para que el pump deje de dormir y el caller reaccione.
    fn any_actionable(&self, targets: &[i64]) -> bool {
        targets.iter().any(|h| {
            self.conns
                .get(h)
                .map(|c| !c.inbound.is_empty() || c.last_error.is_some())
                .unwrap_or(false)
        })
    }

    /// Tickea los timers (keepalive/reconexión) y re-sincroniza el interés de cada
    /// conexión en el poller. No bloquea. Devuelve las `on_reconnect` pendientes.
    fn service_timers(&mut self, pending: &mut Vec<PendingReconnect>) {
        self.service_keepalive();
        self.try_reconnects(pending);
        let handles: Vec<i64> = self.conns.keys().copied().collect();
        for h in &handles {
            self.sync_interest(*h);
        }
    }

    /// Una pasada del poller: espera readiness hasta `wait` (ZERO = no-bloqueante) y
    /// procesa los sockets listos (flush pendiente + drenar lecturas). Cuenta una
    /// iteración en `POLL_ITERS` (el test de "no busy-spin").
    fn poll_process(&mut self, wait: Duration) {
        self.events.clear();
        POLL_ITERS.with(|c| c.set(c.get() + 1));
        if self.poll.poll(&mut self.events, Some(wait)).is_err() {
            // Un poll que falla en loop (p.ej. EINTR repetido) no debe convertir el
            // pump en un busy-spin: ceder un instante antes de reintentar.
            std::thread::sleep(Duration::from_millis(1));
            return;
        }
        let ready: Vec<(i64, bool, bool)> = self
            .events
            .iter()
            .filter_map(|ev| {
                let tok = ev.token().0;
                self.token_to_handle.get(&tok).map(|h| (*h, ev.is_readable(), ev.is_writable()))
            })
            .collect();
        for (handle, readable, writable) in ready {
            if writable {
                self.try_flush(handle);
            }
            if readable {
                self.drain_reads(handle);
            }
        }
    }

    /// El corazón: espera readiness hasta que alguno de `targets` tenga un mensaje/
    /// error o venza `deadline`. Tickea keepalive y reconexión. NO corre
    /// `on_reconnect` (los devuelve en `pending`). CPU ~0 mientras está ocioso.
    fn pump(&mut self, targets: &[i64], deadline: Instant, pending: &mut Vec<PendingReconnect>) {
        loop {
            self.service_timers(pending);
            if self.any_actionable(targets) {
                return;
            }
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            // Timeout del poll = min(lo que resta al deadline, el próximo tick de
            // keepalive/reconexión) — así los timers avanzan sin busy-spin.
            let wait = deadline.saturating_duration_since(now).min(self.next_timer(now));
            self.poll_process(wait);
        }
    }

    /// Un tick NO-bloqueante (para `ws_status`): avanza timers y procesa lo que ya
    /// esté listo sin dormir, así el estado refleja la realidad sin colgar.
    fn tick(&mut self, pending: &mut Vec<PendingReconnect>) {
        self.service_timers(pending);
        self.poll_process(Duration::ZERO);
    }

    /// Tiempo hasta el próximo evento temporal (keepalive/reconexión) desde `now`.
    /// Acota el sleep del poll para que los timers no se pasen. `MAX` si no hay.
    fn next_timer(&self, now: Instant) -> Duration {
        let mut soonest = Duration::from_secs(3600);
        for c in self.conns.values() {
            if let Some(at) = c.reconnect_at {
                soonest = soonest.min(at.saturating_duration_since(now));
            }
            if let Some(ka) = &c.keepalive {
                if c.status == Status::Open {
                    if let Some(since) = c.awaiting_pong_since {
                        soonest = soonest.min((since + ka.timeout).saturating_duration_since(now));
                    } else {
                        soonest = soonest.min((c.last_activity + ka.interval).saturating_duration_since(now));
                    }
                }
            }
        }
        soonest
    }

    /// Saca el próximo mensaje en cola de un handle (y retira el handle si era el
    /// `close` final).
    fn take_message(&mut self, handle: i64) -> Option<SynValue> {
        let (msg, retire) = {
            let c = self.conns.get_mut(&handle)?;
            let msg = c.inbound.pop_front()?;
            c.queued_bytes = c.queued_bytes.saturating_sub(msg_payload_size(&msg));
            // Despausar si drenamos por debajo de AMBOS topes (backpressure Block).
            let is_close = matches!(&msg, SynValue::Map(m) if
                matches!(m.borrow().get("type"), Some(SynValue::Text(t)) if t.as_ref() == "close"));
            let retire = is_close && c.status == Status::Closed;
            if c.read_paused && c.inbound.len() < c.max_queue && c.queued_bytes < c.max_queue_bytes {
                c.read_paused = false;
            }
            (msg, retire)
        };
        if retire {
            self.remove(handle);
        } else {
            self.sync_interest(handle);
        }
        Some(msg)
    }

    /// Si un handle tiene un error fatal pendiente Y su cola está vacía, lo toma y
    /// retira el handle (el error es terminal, no hay más que recibir).
    fn take_error(&mut self, handle: i64) -> Option<String> {
        let has = {
            let c = self.conns.get(&handle)?;
            c.inbound.is_empty() && c.last_error.is_some()
        };
        if !has {
            return None;
        }
        let detail = self.conns.get_mut(&handle).and_then(|c| c.last_error.take());
        self.remove(handle);
        detail
    }

    fn remove(&mut self, handle: i64) {
        if let Some(mut c) = self.conns.remove(&handle) {
            self.token_to_handle.remove(&c.token.0);
            if c.current_interest.is_some() {
                let source = c.ws.get_mut().source();
                let _ = self.poll.registry().deregister(source);
            }
        }
    }
}

fn backoff_delay(rc: &ReconnectCfg, attempt: u32) -> Duration {
    let shifted = rc.backoff_base.saturating_mul(1u32.checked_shl(attempt.min(20)).unwrap_or(u32::MAX));
    shifted.min(rc.backoff_max)
}

// =========================================================
// Parsing de opts de ws_connect
// =========================================================

struct ConnectOpts {
    max_msg: usize,
    timeout: Duration,
    subprotocols: Vec<String>,
    max_queue: usize,
    max_queue_bytes: usize,
    on_full: OnFull,
    reconnect: Option<ReconnectCfg>,
    keepalive: Option<KeepaliveCfg>,
}

fn opt_duration(m: &indexmap::IndexMap<String, SynValue>, key: &str, fname: &str) -> Result<Option<Duration>, Control> {
    match m.get(key) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f <= 0.0 {
                return Err(err(format!("{}: {} must be a positive number of seconds", fname, key)));
            }
            Ok(Some(Duration::from_secs_f64(f.min(24.0 * 3600.0))))
        }
        Some(other) => Err(err(format!("{}: {} must be a number, got {}", fname, key, other.type_name()))),
    }
}

fn parse_connect_opts(v: Option<&SynValue>, fname: &str) -> Result<ConnectOpts, Control> {
    let opts = match v {
        None | Some(SynValue::Nothing) => indexmap::IndexMap::new(),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", fname, other.type_name()))),
    };
    const ALLOWED: &[&str] = &[
        "max_message_size", "timeout", "subprotocols", "max_queue", "max_queue_bytes", "on_full",
        "reconnect", "keepalive",
    ];
    for k in opts.keys() {
        if !ALLOWED.contains(&k.as_str()) {
            return Err(err(format!(
                "{}: unknown option {:?} (allowed: {})",
                fname, k, ALLOWED.join(", ")
            )));
        }
    }

    let timeout = timeout_arg(opts.get("timeout"), fname)?;
    let max_msg = match opts.get("max_message_size") {
        None | Some(SynValue::Nothing) => DEFAULT_MAX_MESSAGE,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(x) if x > 0 && (x as usize) <= MAX_MESSAGE_CEILING => x as usize,
            _ => {
                return Err(err(format!(
                    "{}: max_message_size must be a positive number of bytes up to {}",
                    fname, MAX_MESSAGE_CEILING
                )))
            }
        },
        Some(other) => return Err(err(format!("{}: max_message_size must be a number, got {}", fname, other.type_name()))),
    };
    let max_queue = match opts.get("max_queue") {
        None | Some(SynValue::Nothing) => DEFAULT_MAX_QUEUE,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(x) if x > 0 => x as usize,
            _ => return Err(err(format!("{}: max_queue must be a positive integer", fname))),
        },
        Some(other) => return Err(err(format!("{}: max_queue must be a number, got {}", fname, other.type_name()))),
    };
    let max_queue_bytes = match opts.get("max_queue_bytes") {
        None | Some(SynValue::Nothing) => DEFAULT_MAX_QUEUE_BYTES,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(x) if x > 0 && (x as usize) <= MAX_QUEUE_BYTES_CEILING => x as usize,
            _ => {
                return Err(err(format!(
                    "{}: max_queue_bytes must be a positive number of bytes up to {}",
                    fname, MAX_QUEUE_BYTES_CEILING
                )))
            }
        },
        Some(other) => return Err(err(format!("{}: max_queue_bytes must be a number, got {}", fname, other.type_name()))),
    };
    let on_full = match opts.get("on_full") {
        None | Some(SynValue::Nothing) => OnFull::Block,
        Some(SynValue::Text(s)) => match s.as_ref() {
            "block" => OnFull::Block,
            "drop_oldest" => OnFull::DropOldest,
            "error" => OnFull::Error,
            other => return Err(err(format!("{}: on_full must be \"block\", \"drop_oldest\" or \"error\", got {:?}", fname, other))),
        },
        Some(other) => return Err(err(format!("{}: on_full must be text, got {}", fname, other.type_name()))),
    };
    let subprotocols = match opts.get("subprotocols") {
        None | Some(SynValue::Nothing) => Vec::new(),
        Some(SynValue::List(l)) => {
            let items = l.borrow().clone();
            let mut out = Vec::with_capacity(items.len());
            for it in &items {
                match it {
                    SynValue::Text(s) => out.push(s.to_string()),
                    other => return Err(err(format!("{}: each subprotocol must be text, got {}", fname, other.type_name()))),
                }
            }
            out
        }
        Some(other) => return Err(err(format!("{}: subprotocols must be a list of text, got {}", fname, other.type_name()))),
    };

    let reconnect = match opts.get("reconnect") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Map(m)) => {
            let rm = m.borrow().clone();
            for k in rm.keys() {
                if !matches!(k.as_str(), "max_retries" | "backoff" | "backoff_max" | "on_reconnect") {
                    return Err(err(format!("{}: unknown reconnect option {:?} (allowed: max_retries, backoff, backoff_max, on_reconnect)", fname, k)));
                }
            }
            let max_retries = match rm.get("max_retries") {
                None | Some(SynValue::Nothing) => DEFAULT_MAX_RETRIES,
                Some(SynValue::Number(n)) => match n.to_i64_trunc() {
                    Some(x) if x >= 0 => x as u32,
                    _ => return Err(err(format!("{}: reconnect.max_retries must be a non-negative integer", fname))),
                },
                Some(other) => return Err(err(format!("{}: reconnect.max_retries must be a number, got {}", fname, other.type_name()))),
            };
            let backoff_base = opt_duration(&rm, "backoff", fname)?.unwrap_or(DEFAULT_BACKOFF_BASE);
            let backoff_max = opt_duration(&rm, "backoff_max", fname)?.unwrap_or(DEFAULT_BACKOFF_MAX);
            let on_reconnect = match rm.get("on_reconnect") {
                None | Some(SynValue::Nothing) => None,
                Some(v @ SynValue::Task(_)) => Some(v.clone()),
                Some(v @ SynValue::Builtin(_)) => Some(v.clone()),
                Some(other) => return Err(err(format!("{}: reconnect.on_reconnect must be a task, got {}", fname, other.type_name()))),
            };
            Some(ReconnectCfg { max_retries, backoff_base, backoff_max, on_reconnect })
        }
        Some(other) => return Err(err(format!("{}: reconnect must be a map, got {}", fname, other.type_name()))),
    };

    let keepalive = match opts.get("keepalive") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Map(m)) => {
            let km = m.borrow().clone();
            for k in km.keys() {
                if !matches!(k.as_str(), "interval" | "timeout") {
                    return Err(err(format!("{}: unknown keepalive option {:?} (allowed: interval, timeout)", fname, k)));
                }
            }
            let interval = opt_duration(&km, "interval", fname)?
                .ok_or_else(|| err(format!("{}: keepalive needs an \"interval\"", fname)))?;
            let timeout = opt_duration(&km, "timeout", fname)?.unwrap_or(interval);
            Some(KeepaliveCfg { interval, timeout })
        }
        Some(other) => return Err(err(format!("{}: keepalive must be a map, got {}", fname, other.type_name()))),
    };

    Ok(ConnectOpts {
        max_msg,
        timeout,
        subprotocols,
        max_queue,
        max_queue_bytes,
        on_full,
        reconnect,
        keepalive,
    })
}

// =========================================================
// Builtins
// =========================================================

fn parse_headers(v: Option<&SynValue>, fname: &str) -> Result<Vec<(String, String)>, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(Vec::new()),
        Some(SynValue::Map(m)) => Ok(m
            .borrow()
            .iter()
            .map(|(k, v)| {
                let vs = match v {
                    SynValue::Text(s) => s.to_string(),
                    // Un secret (p.ej. bearer()) se materializa SÓLO en el borde del socket.
                    SynValue::Secret(s) => s.expose().into_owned(),
                    other => other.to_string(),
                };
                (k.clone(), vs)
            })
            .collect()),
        Some(other) => Err(err(format!("{}: headers must be a map, got {}", fname, other.type_name()))),
    }
}

fn ws_connect(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_connect";
    let url = match args.first() {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => return Err(err(format!("{}: the URL must be text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the URL", F))),
    };
    // Tope de conexiones ANTES de resolver/conectar (anti-footgun de loop).
    {
        let r = reg.borrow();
        if r.conns.len() >= r.max_conns {
            return Err(err(format!(
                "{}: connection budget reached ({} open, max {}); close some or raise the cap",
                F,
                r.conns.len(),
                r.max_conns
            )));
        }
    }
    let (host, port, tls) = parse_ws_url(&url, F)?;
    let headers = parse_headers(args.get(1), F)?;
    let opts = parse_connect_opts(args.get(2), F)?;

    let dial = DialParams {
        url: url.clone(),
        host,
        port,
        tls,
        headers,
        subprotocols: opts.subprotocols,
        max_msg: opts.max_msg,
        connect_timeout: opts.timeout,
    };
    // establish() re-chequea net(host) (G21) y hace el handshake.
    let caps = reg.borrow().caps.clone();
    let (ws, negotiated) = establish(&dial, &caps)?;

    let mut r = reg.borrow_mut();
    r.next_id += 1;
    let handle = r.next_id;
    r.next_token += 1;
    let token = Token(r.next_token);
    let retries_left = opts.reconnect.as_ref().map(|rc| rc.max_retries).unwrap_or(0);
    let conn = Conn {
        ws,
        token,
        dial,
        negotiated_subprotocol: negotiated,
        inbound: VecDeque::new(),
        queued_bytes: 0,
        max_queue: opts.max_queue,
        max_queue_bytes: opts.max_queue_bytes,
        on_full: opts.on_full,
        read_paused: false,
        pending_flush: false,
        reconnect: opts.reconnect,
        keepalive: opts.keepalive,
        status: Status::Open,
        stats: Stats::default(),
        last_activity: Instant::now(),
        awaiting_pong_since: None,
        retries_left,
        reconnect_at: None,
        current_interest: None,
        closed_emitted: false,
        last_error: None,
    };
    r.conns.insert(handle, conn);
    r.token_to_handle.insert(token.0, handle);
    drop(r);
    {
        // Cosecha INICIAL: el handshake bloqueante puede haber sobre-leído y dejado
        // frames enteros en el buffer de tungstenite (un server que pushea apenas
        // conecta, coalescido con la respuesta 101). Esos bytes NO están en el
        // kernel → epoll/kqueue/IOCP jamás los reportan: sin esta pasada, una
        // conexión "con datos" dormiría hasta el timeout.
        let mut r = reg.borrow_mut();
        r.sync_interest(handle);
        r.drain_reads(handle);
        r.sync_interest(handle);
    }
    Ok(syn_int(handle))
}

fn ws_send(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_send";
    let handle = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the connection handle", F)))?, F)?;
    let msg = match args.get(1) {
        Some(SynValue::Text(s)) => Message::text(s.to_string()),
        Some(SynValue::Bytes(b)) => Message::binary(b[..].to_vec()),
        Some(SynValue::Secret(_)) => {
            return Err(err(format!("{}: cannot send a secret over a WebSocket (reveal() it first if you truly must)", F)))
        }
        Some(other) => return Err(err(format!("{}: the message must be text or bytes, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the message", F))),
    };
    let mut r = reg.borrow_mut();
    let c = r.conns.get_mut(&handle).ok_or_else(|| err(format!("{}: unknown or closed connection handle {}", F, handle)))?;
    if c.status != Status::Open {
        return Err(err(format!("{}: the connection is {} (not open)", F, status_str(c.status))));
    }
    match c.ws.send(msg) {
        Ok(()) => {
            // Enviado y flusheado. (El contador sólo cuenta sends que salieron o
            // quedaron encolados — un send fallido NO suma: ws_stats no miente, G27.)
            c.stats.sent += 1;
        }
        Err(e) if is_would_block(&e) => {
            // Quedó en el buffer de salida: el pump lo flushea al haber writability.
            c.stats.sent += 1;
            c.pending_flush = true;
        }
        Err(e) => {
            let closed = matches!(e, tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed);
            if closed {
                drop(r);
                reg.borrow_mut().mark_gone(handle, SynValue::Nothing);
            }
            return Err(ws_error(e, F));
        }
    }
    drop(r);
    reg.borrow_mut().sync_interest(handle);
    Ok(syn_bool(true))
}

/// Corre las `on_reconnect` pendientes FUERA del borrow (pueden re-entrar a ws_*).
fn run_pending(interp: &mut Interpreter, reg: &Registry, pending: Vec<PendingReconnect>) -> Result<(), Control> {
    for p in pending {
        // Sólo si la conexión sigue existiendo (no la cerró el usuario en el ínterin).
        if reg.borrow().conns.contains_key(&p.handle) {
            interp.call_task(p.task, vec![syn_int(p.handle)])?;
        }
    }
    Ok(())
}

fn ws_recv(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_recv";
    let handle = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the connection handle", F)))?, F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    if !reg.borrow().conns.contains_key(&handle) {
        return Err(err(format!("{}: unknown or closed connection handle {}", F, handle)));
    }
    let deadline = Instant::now() + timeout;
    loop {
        // ¿Ya hay algo? entregarlo.
        if reg.borrow().conns.get(&handle).map(|c| !c.inbound.is_empty()).unwrap_or(false) {
            return Ok(reg.borrow_mut().take_message(handle).unwrap_or(SynValue::Nothing));
        }
        // ¿Un error fatal de protocolo pendiente? entregarlo atrapable.
        if let Some(detail) = reg.borrow_mut().take_error(handle) {
            return Err(err(format!("{}: {}", F, detail)));
        }
        if !reg.borrow().conns.contains_key(&handle) {
            return Ok(SynValue::Nothing); // se retiró (cerrada)
        }
        if Instant::now() >= deadline {
            return Ok(SynValue::Nothing);
        }
        let mut pending = Vec::new();
        reg.borrow_mut().pump(&[handle], deadline, &mut pending);
        run_pending(interp, reg, pending)?;
    }
}

/// Nombres opcionales handle→nombre (cuando `ws_select` recibe un map, no una lista).
type TargetNames = Option<HashMap<i64, String>>;

/// Resuelve la lista de handles objetivo desde una lista de números o un map
/// nombre→handle. Devuelve (handles, Option<map handle→nombre>).
fn resolve_targets(v: &SynValue, fname: &str) -> Result<(Vec<i64>, TargetNames), Control> {
    match v {
        SynValue::List(l) => {
            let items = l.borrow().clone();
            let mut handles = Vec::with_capacity(items.len());
            for it in &items {
                handles.push(conn_handle(it, fname)?);
            }
            Ok((handles, None))
        }
        SynValue::Map(m) => {
            let mm = m.borrow().clone();
            let mut handles = Vec::with_capacity(mm.len());
            let mut names = HashMap::new();
            for (name, hv) in &mm {
                let h = conn_handle(hv, fname)?;
                handles.push(h);
                names.insert(h, name.clone());
            }
            Ok((handles, Some(names)))
        }
        other => Err(err(format!(
            "{}: expected a list of connection handles or a name→handle map, got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// Empaqueta un mensaje (ya `{type, data}`) agregando `conn` (y `name` si venía de un map).
fn tag_message(msg: SynValue, handle: i64, names: &TargetNames) -> SynValue {
    let mut m = match msg {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            let mut mm = indexmap::IndexMap::new();
            mm.insert("data".to_string(), other);
            mm
        }
    };
    m.insert("conn".to_string(), syn_int(handle));
    if let Some(names) = names {
        if let Some(name) = names.get(&handle) {
            m.insert("name".to_string(), syn_text(name.clone()));
        }
    }
    syn_map(m)
}

fn ws_select(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_select";
    let (targets, names) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the connections", F)))?, F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    if targets.is_empty() {
        return Ok(SynValue::Nothing);
    }
    let deadline = Instant::now() + timeout;
    loop {
        // Equidad: buscar el primero listo en orden de la lista. (Extraer el handle
        // ANTES de borrow_mut: el temporario de un scrutinee if-let vive todo el
        // bloque en la edición actual → doble borrow si no se materializa antes.)
        let ready = reg.borrow().first_ready(&targets);
        if let Some(h) = ready {
            let msg = reg.borrow_mut().take_message(h).unwrap_or(SynValue::Nothing);
            return Ok(tag_message(msg, h, &names));
        }
        // Fail-fast: un error fatal en cualquier target sale como error (con `conn`).
        let errored = targets.iter().copied().find(|h| {
            reg.borrow().conns.get(h).map(|c| c.inbound.is_empty() && c.last_error.is_some()).unwrap_or(false)
        });
        if let Some(h) = errored {
            let detail = reg.borrow_mut().take_error(h).unwrap_or_default();
            return Err(err(format!("{}: connection {}: {}", F, h, detail)));
        }
        // Si TODAS las conexiones objetivo desaparecieron, no hay nada que esperar.
        let all_gone = {
            let r = reg.borrow();
            targets.iter().all(|h| !r.conns.contains_key(h))
        };
        if all_gone || Instant::now() >= deadline {
            return Ok(SynValue::Nothing);
        }
        let mut pending = Vec::new();
        reg.borrow_mut().pump(&targets, deadline, &mut pending);
        run_pending(interp, reg, pending)?;
    }
}

fn ws_select_all(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_select_all";
    let (targets, names) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the connections", F)))?, F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    if targets.is_empty() {
        return Ok(SynValue::List(Rc::new(RefCell::new(Vec::new()))));
    }
    let deadline = Instant::now() + timeout;
    // Esperar a que haya AL MENOS uno, después drenar todos los listos de un tick.
    loop {
        let any = reg.borrow().first_ready(&targets).is_some();
        let all_gone = {
            let r = reg.borrow();
            targets.iter().all(|h| !r.conns.contains_key(h))
        };
        if any || all_gone || Instant::now() >= deadline {
            break;
        }
        let mut pending = Vec::new();
        reg.borrow_mut().pump(&targets, deadline, &mut pending);
        run_pending(interp, reg, pending)?;
    }
    // Drenar: un mensaje por conexión lista (evita que un feed hambree a los demás).
    let mut out = Vec::new();
    let mut r = reg.borrow_mut();
    for h in &targets {
        if r.conns.get(h).map(|c| !c.inbound.is_empty()).unwrap_or(false) {
            if let Some(msg) = r.take_message(*h) {
                out.push(tag_message(msg, *h, &names));
            }
        }
    }
    Ok(SynValue::List(Rc::new(RefCell::new(out))))
}

fn ws_broadcast(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_broadcast";
    let (targets, _) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the connections", F)))?, F)?;
    let template = args.get(1).ok_or_else(|| err(format!("{}: missing the message", F)))?;
    let mut sent = 0i64;
    for h in targets {
        // Reutiliza ws_send (mismo manejo de estado/flush); un handle muerto se saltea.
        // El estado se materializa ANTES de ws_send (que hace borrow_mut) — si no, el
        // temporario del borrow en el `&&` viviría hasta el fin de la condición.
        let open = reg.borrow().conns.get(&h).map(|c| c.status == Status::Open).unwrap_or(false);
        if open && ws_send(&[syn_int(h), template.clone()], reg).is_ok() {
            sent += 1;
        }
    }
    Ok(syn_int(sent))
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Open => "open",
        Status::Reconnecting => "reconnecting",
        Status::Closed => "closed",
    }
}

fn ws_status(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_status";
    let handle = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the connection handle", F)))?, F)?;
    // Tick no-bloqueante para que el estado refleje la realidad (lecturas listas,
    // keepalive, reconexión) sin colgar.
    let mut pending = Vec::new();
    reg.borrow_mut().tick(&mut pending);
    run_pending(interp, reg, pending)?;
    let s = match reg.borrow().conns.get(&handle) {
        Some(c) => status_str(c.status),
        None => "closed", // desconocido/retirado
    };
    Ok(syn_text(s))
}

fn ws_stats(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_stats";
    let handle = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the connection handle", F)))?, F)?;
    let r = reg.borrow();
    let c = r.conns.get(&handle).ok_or_else(|| err(format!("{}: unknown or closed connection handle {}", F, handle)))?;
    let mut m = indexmap::IndexMap::new();
    m.insert("sent".to_string(), syn_int(c.stats.sent as i64));
    m.insert("received".to_string(), syn_int(c.stats.received as i64));
    m.insert("reconnects".to_string(), syn_int(c.stats.reconnects as i64));
    m.insert("queued".to_string(), syn_int(c.inbound.len() as i64));
    m.insert("queued_bytes".to_string(), syn_int(c.queued_bytes as i64));
    // Segundos desde el último pong (nothing si nunca llegó uno) — el vital sign
    // del keepalive, visible para un keeper de miles de feeds.
    m.insert(
        "last_pong_ago".to_string(),
        c.stats
            .last_pong
            .map(|t| syn_number(synsema_core::number::Number::Float(t.elapsed().as_secs_f64())))
            .unwrap_or(SynValue::Nothing),
    );
    m.insert("status".to_string(), syn_text(status_str(c.status)));
    m.insert(
        "subprotocol".to_string(),
        c.negotiated_subprotocol.clone().map(syn_text).unwrap_or(SynValue::Nothing),
    );
    Ok(syn_map(m))
}

fn ws_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_close";
    let handle = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the connection handle", F)))?, F)?;
    // Cerrar un handle ya cerrado/desconocido es un no-op (idempotente).
    let mut ws = {
        let mut r = reg.borrow_mut();
        match r.conns.remove(&handle) {
            Some(mut c) => {
                r.token_to_handle.remove(&c.token.0);
                if c.current_interest.is_some() {
                    let source = c.ws.get_mut().source();
                    let _ = r.poll.registry().deregister(source);
                }
                c.ws
            }
            None => return Ok(syn_bool(true)),
        }
    };
    // Close frame limpio + drenar un ratito acotado (los errores acá no importan).
    let _ = ws.close(None);
    let _ = ws.flush();
    for _ in 0..8 {
        match ws.read() {
            Ok(_) => continue,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(syn_bool(true))
}

// =========================================================
// Registro
// =========================================================

pub fn register_ws_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    let poll = Poll::new().expect("mio::Poll::new");
    // Tope de conexiones por intérprete: default DEFAULT_MAX_CONNS, ajustable con
    // `SYNSEMA_WS_MAX_CONNS` (acotado al techo duro; un valor inválido cae al default).
    let max_conns = std::env::var("SYNSEMA_WS_MAX_CONNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_CONNS_CEILING))
        .unwrap_or(DEFAULT_MAX_CONNS);
    let reg: Registry = Rc::new(RefCell::new(WsRegistry {
        poll,
        events: Events::with_capacity(1024),
        conns: HashMap::new(),
        token_to_handle: HashMap::new(),
        next_id: 0,
        next_token: 0,
        max_conns,
        rr: std::cell::Cell::new(0),
        caps,
    }));

    macro_rules! reg_fn {
        ($name:literal, $arity:expr, $f:ident) => {{
            let reg = reg.clone();
            interp.register_builtin($name, $arity, Rc::new(move |_i, a, _l| $f(a, &reg)));
        }};
    }
    macro_rules! reg_fn_interp {
        ($name:literal, $arity:expr, $f:ident) => {{
            let reg = reg.clone();
            interp.register_builtin($name, $arity, Rc::new(move |i, a, _l| $f(i, a, &reg)));
        }};
    }

    reg_fn!("ws_connect", -1, ws_connect);
    reg_fn!("ws_send", 2, ws_send);
    reg_fn_interp!("ws_recv", -1, ws_recv);
    reg_fn_interp!("ws_select", -1, ws_select);
    reg_fn_interp!("ws_select_all", -1, ws_select_all);
    reg_fn!("ws_broadcast", 2, ws_broadcast);
    reg_fn_interp!("ws_status", 1, ws_status);
    reg_fn!("ws_stats", 1, ws_stats);
    reg_fn!("ws_close", 1, ws_close);
}
