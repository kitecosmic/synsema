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
use mio::{Events, Interest, Poll, Token, Waker};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::{Message, Role, WebSocket, WebSocketConfig};
use tungstenite::Bytes;

use synsema_agents::bus::{Bus, OnFull as BusOnFull, SubscribeOpts, Subscriber};
use synsema_capabilities::model::{normalize_path, Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{from_send, syn_bool, syn_bytes, syn_int, syn_map, syn_number, syn_text, SendValue, SynValue};

use crate::proc::{LiveProc, OnFull as ProcOnFull, ProcEvent, ProcStatus, SpawnOpts};
use crate::term::{Term, TermError, TermEvent, TermOpts};
use crate::watch::{Watch, WatchOpts};

/// Token reservado del `mio::Waker` del hub (los sockets arrancan en 1).
const WAKER_TOKEN: Token = Token(0);
/// Ping del servidor a un `socket` entrante (segundos); `SYNSEMA_WS_SERVER_PING` lo
/// ajusta (0 = sin keepalive del lado servidor).
const DEFAULT_SERVER_PING_SECS: f64 = 30.0;
/// Tope de procesos vivos por intérprete (`SYNSEMA_PROC_MAX`, techo 1024).
const DEFAULT_MAX_PROCS: usize = 64;
const MAX_PROCS_CEILING: usize = 1024;
/// Tope de watches vivos por intérprete (cada uno es un hilo scanner).
const DEFAULT_MAX_WATCHES: usize = 64;
const MAX_WATCHES_CEILING: usize = 1024;
/// Plazo de gracia para que los lectores de un proceso que YA salió lleguen a EOF
/// (un nieto que retiene el pipe no puede colgar al `select` para siempre).
const PROC_READER_GRACE: Duration = Duration::from_secs(1);

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
    /// Socket ENTRANTE de `serve` (ruta `socket`): los bytes viajan por dos canales
    /// acotados hacia/desde el pump async de hyper (el TCP/TLS lo tiene tokio). No se
    /// registra en el `Poll`: el pump despierta al hub por el `Waker`.
    Channel(ChannelStream),
    /// Placeholder transitorio durante la promoción (Read/Write erroran).
    Void,
}

/// Transporte por canales de un socket entrante. `read` es no-bloqueante (WouldBlock
/// sin datos; 0 = el pump cerró → EOF), `write` encola (WouldBlock con el canal lleno:
/// tungstenite deja el frame pendiente y el pump lo flushea cuando hay lugar — la
/// ventana TCP del cliente frena al handler, no al revés).
pub struct ChannelStream {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    leftover: Bytes,
}

impl Read for ChannelStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.leftover.is_empty() {
                let n = buf.len().min(self.leftover.len());
                buf[..n].copy_from_slice(&self.leftover[..n]);
                self.leftover = self.leftover.slice(n..);
                return Ok(n);
            }
            match self.rx.try_recv() {
                Ok(b) => self.leftover = b,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return Ok(0),
            }
        }
    }
}

impl Write for ChannelStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Ok(buf.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
    fn channel(c: ChannelStream) -> Self {
        WsStream { inner: StreamKind::Channel(c) }
    }
    /// ¿Transporte por canal (socket entrante)? No tiene `source()` para el Poll.
    fn is_channel(&self) -> bool {
        matches!(self.inner, StreamKind::Channel(_))
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
            StreamKind::Channel(c) => c.read(buf),
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
            StreamKind::Channel(c) => c.write(buf),
            StreamKind::Void => Err(std::io::Error::other("ws stream in transit")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            StreamKind::PlainStd(t) => t.flush(),
            StreamKind::PlainMio(t) => t.flush(),
            StreamKind::TlsStd(s) => s.flush(),
            StreamKind::TlsMio(s) => s.flush(),
            StreamKind::Channel(c) => c.flush(),
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
    /// Socket ENTRANTE (ruta `socket` de serve): sin reconexión posible (el peer es
    /// quien reconecta), `ws_stats.role = "server"`.
    server_side: bool,
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

/// El HUB de I/O del intérprete: sockets (salientes y entrantes), procesos vivos y
/// suscripciones al bus comparten UN contador de handles (jamás colisionan), UN
/// `mio::Poll` (readiness de sockets) y UN `Waker` (procesos/bus/pump async/cancel
/// despiertan la misma espera) → `select` es uno solo. Nació como registro ws
/// (Batch 13/15); el nombre del struct se conserva por continuidad del código.
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
    /// Despertador del Poll (procesos, bus, pump de sockets entrantes, cancelación).
    waker: Arc<Waker>,
    /// Procesos vivos (`proc_*`).
    procs: HashMap<i64, LiveProc>,
    max_procs: usize,
    /// File-watches vivos (`watch`).
    watches: HashMap<i64, Watch>,
    max_watches: usize,
    /// La terminal propia (`term_open`): a lo sumo una por intérprete (y por proceso).
    term: Option<(i64, Term)>,
    /// Suscripciones al bus (`bus_subscribe`).
    subs: HashMap<i64, Arc<Subscriber>>,
    /// El bus del proceso (lo adjunta el motor con `attach_bus` al cablear el swarm).
    bus: Option<Arc<Bus>>,
    /// Último token de cancelación al que registramos nuestro waker (uno por token).
    cancel_seen: usize,
    /// Flag del token vigente: el `pump` sale apenas se enciende (el waker lo despierta).
    cancel_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl Drop for WsRegistry {
    fn drop(&mut self) {
        // Fin del intérprete = fin de sus procesos (LiveProc::drop mata + cosecha), de
        // sus watches (Watch::drop apaga el scanner) y de sus suscripciones (el bus no
        // acumula en colas huérfanas).
        self.procs.clear();
        self.watches.clear();
        self.term = None;
        if let Some(bus) = &self.bus {
            for (_, s) in self.subs.drain() {
                bus.unsubscribe(s.id);
            }
        }
    }
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
            if c.ws.get_ref().is_channel() {
                // Sin socket del kernel: el pump async despierta por el Waker.
                return;
            }
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
            if c.current_interest.is_some() {
                let source = c.ws.get_mut().source();
                let _ = self.poll.registry().deregister(source);
            }
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
                Err(tungstenite::Error::Protocol(
                    tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                )) => {
                    // El peer desapareció sin handshake de cierre (red caída, pestaña
                    // matada, proceso muerto): es una DESCONEXIÓN, no una violación de
                    // protocolo del programa → `close` con motivo (y reconexión si la hay).
                    self.mark_gone(handle, syn_text("connection reset without closing handshake"));
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
        // Deregistrar el socket muerto del poller (los de canal nunca se registraron).
        if c.current_interest.is_some() {
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
            if c.current_interest.is_some() {
                let source = c.ws.get_mut().source();
                let _ = self.poll.registry().deregister(source);
            }
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
    /// Es la condición para que el pump deje de dormir y el caller reaccione. Cubre
    /// las TRES familias de handles (socket, proceso, suscripción).
    fn any_actionable(&self, targets: &[i64]) -> bool {
        targets.iter().any(|h| self.handle_actionable(*h))
    }

    /// Tickea los timers (keepalive/reconexión) y re-sincroniza el interés de cada
    /// conexión en el poller. No bloquea. Devuelve las `on_reconnect` pendientes.
    fn service_timers(&mut self, pending: &mut Vec<PendingReconnect>) {
        self.service_keepalive();
        self.try_reconnects(pending);
        self.service_procs();
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
        // Sockets entrantes (canal): sin readiness del kernel — tras cada pasada del
        // Poll (despertada por el Waker del pump, o por timeout) se flushea lo
        // pendiente y se drena lo que el pump haya encolado (hasta WouldBlock).
        let channel_conns: Vec<i64> = self
            .conns
            .iter()
            .filter(|(_, c)| c.ws.get_ref().is_channel() && c.status == Status::Open)
            .map(|(h, _)| *h)
            .collect();
        for h in channel_conns {
            self.try_flush(h);
            self.drain_reads(h);
        }
    }

    /// El corazón: espera readiness hasta que alguno de `targets` tenga un mensaje/
    /// error o venza `deadline`. Tickea keepalive y reconexión. NO corre
    /// `on_reconnect` (los devuelve en `pending`). CPU ~0 mientras está ocioso.
    fn pump(&mut self, targets: &[i64], deadline: Instant, pending: &mut Vec<PendingReconnect>) {
        loop {
            self.service_timers(pending);
            if self.any_actionable(targets) || self.cancelled() {
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

    /// ¿Cancelación cooperativa pendiente? (el caller la convierte en error).
    fn cancelled(&self) -> bool {
        self.cancel_flag
            .as_ref()
            .map(|f| f.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
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
        // Procesos: sólo hay que hacer polling en dos ventanas cortas — lectores en EOF
        // pero exit aún no cosechado (carrera pipe-close/exit), o exit cosechado pero
        // lectores vivos (nieto reteniendo el pipe → plazo de gracia). Un proceso
        // silencioso en régimen NO despierta a nadie (los lectores avisan por el Waker).
        for p in self.procs.values() {
            if p.exit_code.is_none() && p.shared.readers_done() {
                soonest = soonest.min(Duration::from_millis(20));
            } else if let Some(at) = p.exited_at {
                if !p.shared.readers_done() {
                    soonest = soonest.min((at + PROC_READER_GRACE).saturating_duration_since(now).max(Duration::from_millis(20)));
                }
            } else if p.pty && p.status == ProcStatus::Running {
                // Pty: el EOF del master no es puntual (ConPTY cierra su pipe tarde o
                // nunca hasta ClosePseudoConsole), así que el exit no despierta a
                // nadie por sí solo → try_wait barato cada 50 ms sólo mientras corre.
                soonest = soonest.min(Duration::from_millis(50));
            }
        }
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
            // La respuesta al Close del peer (que tungstenite encola al leerlo) debe
            // SALIR antes de soltar el transporte: si no, el cierre termina en RST y el
            // cliente ve "connection reset without closing handshake" en vez de un
            // handshake de cierre limpio. Best-effort (WouldBlock/closed se ignoran).
            let _ = c.ws.flush();
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
    let server_side = false;
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
        server_side,
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
    watch_cancel(reg, interp);
    loop {
        interp.check_cancel()?;
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
    // Desde el hub unificado, `ws_select` ES `select` (acepta cualquier handle) con
    // el etiquetado histórico (`conn` + `name`) preservado.
    select_impl(interp, args, reg, "ws_select")
}

fn ws_select_all(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_select_all";
    let (targets, names) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the connections", F)))?, F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    if targets.is_empty() {
        return Ok(SynValue::List(Rc::new(RefCell::new(Vec::new()))));
    }
    let deadline = Instant::now() + timeout;
    watch_cancel(reg, interp);
    // Esperar a que haya AL MENOS uno, después drenar todos los listos de un tick.
    loop {
        interp.check_cancel()?;
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
    m.insert("role".to_string(), syn_text(if c.server_side { "server" } else { "client" }));
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
// Hub unificado: procesos + bus + sockets entrantes + `select`
// =========================================================

/// Clave del hub en `Interpreter::ext`.
pub const IO_HUB_KEY: &str = "synsema.io_hub";

/// El hub de un intérprete (si el stdlib ya cableó `register_ws_builtins`).
fn hub_of(interp: &Interpreter) -> Option<Registry> {
    interp.ext.borrow().get(IO_HUB_KEY).and_then(|a| a.downcast_ref::<Registry>().cloned())
}

/// Adjunta el bus del proceso al hub del intérprete (lo llama el motor al cablear el
/// swarm: `bus_*` publican/suscriben contra el MISMO bus que agentes, cron y handlers).
pub fn attach_bus(interp: &Interpreter, bus: Arc<Bus>) {
    if let Some(reg) = hub_of(interp) {
        reg.borrow_mut().bus = Some(bus);
    }
}

/// Fin del trabajo de un intérprete REUSADO (`serve` cachea uno por worker y se lo
/// presta a cada request/tick/stream): el hub vuelve a cero — los sockets se cierran
/// con `Close` limpio (un handle NO cruza requests), los procesos vivos se matan y
/// cosechan (nunca huérfanos), y las suscripciones se retiran del bus (un handler que
/// terminó no sigue acumulando eventos en una cola que nadie lee). Sin esto, el
/// `bus_subscribe` de un SSE cuyo cliente se fue viviría hasta que el worker muera.
pub fn reset_hub(interp: &Interpreter) {
    let Some(reg) = hub_of(interp) else { return };
    let mut r = reg.borrow_mut();
    let handles: Vec<i64> = r.conns.keys().copied().collect();
    for h in handles {
        if let Some(mut c) = r.conns.remove(&h) {
            r.token_to_handle.remove(&c.token.0);
            if c.current_interest.is_some() {
                let source = c.ws.get_mut().source();
                let _ = r.poll.registry().deregister(source);
            }
            let _ = c.ws.close(None);
            let _ = c.ws.flush();
        }
    }
    // `LiveProc::drop` → TERM, KILL a los 2 s, wait: ninguno sobrevive al request.
    r.procs.clear();
    r.watches.clear();
    r.term = None;
    let subs: Vec<Arc<Subscriber>> = r.subs.drain().map(|(_, s)| s).collect();
    if let Some(bus) = r.bus.clone() {
        for s in subs {
            bus.unsubscribe(s.id);
        }
    }
    r.cancel_seen = 0;
    r.cancel_flag = None;
    r.rr.set(0);
}

/// El bus adjunto al hub de este intérprete (para que workers de `parallel_map` y
/// ticks de cron en modo `run` hereden el MISMO bus que su intérprete padre).
pub fn bus_of_interp(interp: &Interpreter) -> Option<Arc<Bus>> {
    hub_of(interp).and_then(|reg| reg.borrow().bus.clone())
}

/// Registra (una vez por token) el waker del hub en el token de cancelación del
/// intérprete: una cancelación (timeout de handler, shutdown, `agent_stop`) despierta
/// la espera del `Poll` de inmediato en vez de esperar su timeout.
fn watch_cancel(reg: &Registry, interp: &Interpreter) {
    let tok = interp.cancel_token();
    let id = tok.id();
    let mut r = reg.borrow_mut();
    if r.cancel_seen == id {
        return;
    }
    r.cancel_seen = id;
    r.cancel_flag = Some(tok.flag.clone());
    let w = r.waker.clone();
    tok.add_waker(Arc::new(move || {
        let _ = w.wake();
    }));
}

/// Enlace de un socket ENTRANTE (ruta `socket` de serve): los dos canales acotados con
/// el pump async de hyper + el slot donde el hub deja su `Waker` para que el pump lo
/// despierte al encolar bytes / liberar lugar.
pub struct ServerSocketLink {
    pub inbound: tokio::sync::mpsc::Receiver<Bytes>,
    pub outbound: tokio::sync::mpsc::Sender<Bytes>,
    pub waker_slot: Arc<std::sync::Mutex<Option<Arc<Waker>>>>,
    pub subprotocol: Option<String>,
    pub max_message: usize,
}

/// Adopta un socket entrante en el hub del intérprete y devuelve su handle (el binding
/// `socket` de la ruta). La familia `ws_*` entera opera sobre él como sobre un
/// `ws_connect`, y `select` lo mezcla con procesos y bus.
pub fn adopt_server_socket(interp: &Interpreter, link: ServerSocketLink) -> Result<i64, Control> {
    let reg = hub_of(interp).ok_or_else(|| err("socket: the I/O hub is not wired in this interpreter"))?;
    {
        let r = reg.borrow();
        if r.conns.len() >= r.max_conns {
            return Err(err(format!(
                "socket: connection budget reached ({} open, max {}); close some or raise SYNSEMA_WS_MAX_CONNS",
                r.conns.len(),
                r.max_conns
            )));
        }
    }
    let ServerSocketLink { inbound, outbound, waker_slot, subprotocol, max_message } = link;
    let max_msg = max_message.clamp(1, MAX_MESSAGE_CEILING);
    let stream = WsStream::channel(ChannelStream { rx: inbound, tx: outbound, leftover: Bytes::new() });
    let config = WebSocketConfig::default().max_message_size(Some(max_msg)).max_frame_size(Some(max_msg));
    let ws = WebSocket::from_raw_socket(stream, Role::Server, Some(config));
    let ping_secs = std::env::var("SYNSEMA_WS_SERVER_PING")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|f| f.is_finite() && *f >= 0.0)
        .unwrap_or(DEFAULT_SERVER_PING_SECS);
    let keepalive = if ping_secs > 0.0 {
        Some(KeepaliveCfg { interval: Duration::from_secs_f64(ping_secs), timeout: Duration::from_secs_f64(ping_secs * 2.0) })
    } else {
        None
    };
    let mut r = reg.borrow_mut();
    if let Ok(mut slot) = waker_slot.lock() {
        *slot = Some(r.waker.clone());
    }
    r.next_id += 1;
    let handle = r.next_id;
    r.next_token += 1;
    let token = Token(r.next_token);
    let conn = Conn {
        ws,
        token,
        dial: DialParams {
            url: "socket://incoming".to_string(),
            host: String::new(),
            port: 0,
            tls: false,
            headers: Vec::new(),
            subprotocols: Vec::new(),
            max_msg,
            connect_timeout: Duration::from_secs(0),
        },
        negotiated_subprotocol: subprotocol,
        inbound: VecDeque::new(),
        queued_bytes: 0,
        max_queue: DEFAULT_MAX_QUEUE,
        max_queue_bytes: DEFAULT_MAX_QUEUE_BYTES,
        on_full: OnFull::Block,
        read_paused: false,
        pending_flush: false,
        reconnect: None,
        keepalive,
        status: Status::Open,
        stats: Stats::default(),
        last_activity: Instant::now(),
        awaiting_pong_since: None,
        retries_left: 0,
        reconnect_at: None,
        current_interest: None,
        closed_emitted: false,
        last_error: None,
        server_side: true,
    };
    r.conns.insert(handle, conn);
    r.token_to_handle.insert(token.0, handle);
    // Cosecha inicial: el pump pudo encolar bytes antes de la adopción.
    r.drain_reads(handle);
    Ok(handle)
}

/// Cierra un socket entrante al terminar el cuerpo de la ruta: `Close 1000` si terminó
/// bien, `Close 1011` + motivo (truncado a 123 bytes, el límite del frame) si el
/// cuerpo falló, `Close 1001` (going away) + motivo si el server lo CANCELÓ (timeout de
/// la ruta, shutdown ordenado) — el cliente distingue "el handler se rompió" de "el
/// server me despidió". Idempotente (un `ws_close(socket)` previo lo dejó retirado).
pub fn close_server_socket(interp: &Interpreter, handle: i64, error: Option<&str>, going_away: bool) {
    let Some(reg) = hub_of(interp) else { return };
    let removed = {
        let mut r = reg.borrow_mut();
        match r.conns.remove(&handle) {
            Some(mut c) => {
                r.token_to_handle.remove(&c.token.0);
                if c.current_interest.is_some() {
                    let source = c.ws.get_mut().source();
                    let _ = r.poll.registry().deregister(source);
                }
                Some(c.ws)
            }
            None => None,
        }
    };
    let Some(mut ws) = removed else { return };
    use tungstenite::protocol::frame::coding::CloseCode;
    use tungstenite::protocol::CloseFrame;
    let frame = match error {
        Some(msg) => {
            let mut reason = msg.to_string();
            while reason.len() > 123 {
                reason.pop();
            }
            let code = if going_away { CloseCode::Away } else { CloseCode::Error };
            CloseFrame { code, reason: reason.into() }
        }
        None => CloseFrame { code: CloseCode::Normal, reason: "".into() },
    };
    let _ = ws.close(Some(frame));
    let _ = ws.flush();
    // Dropear `ws` cierra el canal de salida → el pump termina la escritura y cierra el TCP.
}

/// Familia de un handle (para etiquetar eventos y validar builtins).
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Ws,
    Proc,
    Sub,
    Watch,
    Term,
}

impl WsRegistry {
    fn kind_of(&self, h: i64) -> Option<HandleKind> {
        if self.conns.contains_key(&h) {
            Some(HandleKind::Ws)
        } else if self.procs.contains_key(&h) {
            Some(HandleKind::Proc)
        } else if self.subs.contains_key(&h) {
            Some(HandleKind::Sub)
        } else if self.watches.contains_key(&h) {
            Some(HandleKind::Watch)
        } else if matches!(&self.term, Some((th, _)) if *th == h) {
            Some(HandleKind::Term)
        } else {
            None
        }
    }

    /// ¿El proceso tiene algo que entregar (salida, error de cola, o el exit)?
    fn proc_ready(p: &LiveProc) -> bool {
        if p.shared.is_ready() {
            return true;
        }
        p.exit_code.is_some() && !p.exit_emitted && p.shared.readers_done()
    }

    /// ¿Un handle (de cualquier familia) tiene algo que entregar?
    fn handle_actionable(&self, h: i64) -> bool {
        if let Some(c) = self.conns.get(&h) {
            return !c.inbound.is_empty() || c.last_error.is_some();
        }
        if let Some(p) = self.procs.get(&h) {
            return Self::proc_ready(p);
        }
        if let Some(s) = self.subs.get(&h) {
            return s.is_ready();
        }
        if let Some(w) = self.watches.get(&h) {
            return w.shared.is_ready();
        }
        if let Some((th, t)) = &self.term {
            if *th == h {
                return t.shared.is_ready();
            }
        }
        false
    }

    /// Primer handle listo (cualquier familia), round-robin desde el último entregado.
    fn first_actionable(&self, targets: &[i64]) -> Option<i64> {
        if targets.is_empty() {
            return None;
        }
        let start = self.rr.get() % targets.len();
        for off in 0..targets.len() {
            let idx = (start + off) % targets.len();
            let h = targets[idx];
            if self.handle_actionable(h) {
                self.rr.set(idx + 1);
                return Some(h);
            }
        }
        None
    }

    /// Tick de procesos: cosecha exits (try_wait, no bloquea) y aplica el plazo de
    /// gracia a lectores que no llegan a EOF tras el exit (nieto con el pipe).
    fn service_procs(&mut self) {
        let now = Instant::now();
        for p in self.procs.values_mut() {
            if p.exit_code.is_none() && p.shared.readers_done() {
                p.poll_exit();
            } else if let Some(at) = p.exited_at {
                if !p.shared.readers_done() && now.duration_since(at) >= PROC_READER_GRACE {
                    p.shared.force_readers_done();
                }
            } else if p.status == ProcStatus::Running {
                // Cosecha oportunista (barata): un try_wait por pasada mantiene
                // `proc_status` honesto aunque nadie lea la salida.
                p.poll_exit();
            }
        }
    }

    /// Toma el próximo evento de un handle de cualquier familia, ya etiquetado
    /// (`source`, `handle`, y `conn` en sockets por compatibilidad). `Err` = error
    /// terminal atrapable del handle.
    fn take_event(&mut self, h: i64, names: &TargetNames) -> Option<Result<SynValue, String>> {
        let kind = self.kind_of(h)?;
        let tagged = |mut m: indexmap::IndexMap<String, SynValue>, source: &str| {
            m.insert("source".to_string(), syn_text(source));
            m.insert("handle".to_string(), syn_int(h));
            if let Some(names) = names {
                if let Some(name) = names.get(&h) {
                    m.insert("name".to_string(), syn_text(name.clone()));
                }
            }
            syn_map(m)
        };
        match kind {
            HandleKind::Ws => {
                if self.conns.get(&h).map(|c| !c.inbound.is_empty()).unwrap_or(false) {
                    let msg = self.take_message(h)?;
                    let mut m = match msg {
                        SynValue::Map(m) => m.borrow().clone(),
                        other => {
                            let mut mm = indexmap::IndexMap::new();
                            mm.insert("data".to_string(), other);
                            mm
                        }
                    };
                    m.insert("conn".to_string(), syn_int(h));
                    return Some(Ok(tagged(m, "ws")));
                }
                self.take_error(h).map(|e| Err(format!("connection {}: {}", h, e)))
            }
            HandleKind::Proc => {
                let p = self.procs.get_mut(&h)?;
                match p.shared.try_recv() {
                    Ok(Some(ev)) => {
                        let mut m = indexmap::IndexMap::new();
                        match ev {
                            ProcEvent::Stdout(b) => {
                                m.insert("type".to_string(), syn_text("stdout"));
                                m.insert("data".to_string(), syn_text(String::from_utf8_lossy(&b).into_owned()));
                            }
                            ProcEvent::Stderr(b) => {
                                m.insert("type".to_string(), syn_text("stderr"));
                                m.insert("data".to_string(), syn_text(String::from_utf8_lossy(&b).into_owned()));
                            }
                            ProcEvent::Exit(code, sig) => {
                                m.insert("type".to_string(), syn_text("exit"));
                                m.insert("data".to_string(), exit_map(code, sig));
                            }
                        }
                        Some(Ok(tagged(m, "proc")))
                    }
                    Ok(None) => {
                        if p.exit_code.is_some() && !p.exit_emitted && p.shared.readers_done() {
                            p.exit_emitted = true;
                            let mut m = indexmap::IndexMap::new();
                            m.insert("type".to_string(), syn_text("exit"));
                            m.insert("data".to_string(), exit_map(p.exit_code.unwrap_or(-1), p.exit_signal));
                            Some(Ok(tagged(m, "proc")))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        // Overflow con política Error: terminal → matar y retirar.
                        if let Some(mut p) = self.procs.remove(&h) {
                            p.shutdown();
                        }
                        Some(Err(format!("process {}: {}", h, e)))
                    }
                }
            }
            HandleKind::Sub => {
                let s = self.subs.get(&h)?.clone();
                match s.try_recv() {
                    Ok(Some(ev)) => {
                        let mut m = indexmap::IndexMap::new();
                        m.insert("type".to_string(), syn_text("event"));
                        m.insert("topic".to_string(), syn_text(ev.topic));
                        m.insert("data".to_string(), from_send(&ev.data));
                        m.insert(
                            "timestamp".to_string(),
                            syn_number(synsema_core::number::Number::Float(ev.timestamp)),
                        );
                        Some(Ok(tagged(m, "bus")))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        self.subs.remove(&h);
                        if let Some(bus) = &self.bus {
                            bus.unsubscribe(s.id);
                        }
                        Some(Err(format!("subscription {}: {}", h, e)))
                    }
                }
            }
            HandleKind::Watch => {
                let w = self.watches.get(&h)?;
                match w.shared.try_recv() {
                    Ok(Some(ev)) => {
                        let mut m = indexmap::IndexMap::new();
                        m.insert("type".to_string(), syn_text(ev.kind.as_str()));
                        m.insert("path".to_string(), syn_text(ev.path));
                        m.insert("is_dir".to_string(), syn_bool(ev.is_dir));
                        Some(Ok(tagged(m, "watch")))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        // Terminal (tope de entradas superado): retirar el handle.
                        self.watches.remove(&h);
                        Some(Err(format!("watch {}: {}", h, e)))
                    }
                }
            }
            HandleKind::Term => {
                let ev = self.term.as_ref()?.1.shared.try_recv()?;
                let mut m = indexmap::IndexMap::new();
                match ev {
                    TermEvent::Key { key, text, ctrl, alt, shift } => {
                        m.insert("type".to_string(), syn_text("key"));
                        m.insert("key".to_string(), syn_text(key));
                        m.insert("text".to_string(), syn_text(text));
                        m.insert("ctrl".to_string(), syn_bool(ctrl));
                        m.insert("alt".to_string(), syn_bool(alt));
                        m.insert("shift".to_string(), syn_bool(shift));
                    }
                    TermEvent::Paste(t) => {
                        m.insert("type".to_string(), syn_text("paste"));
                        m.insert("text".to_string(), syn_text(t));
                    }
                    TermEvent::Resize { cols, rows } => {
                        m.insert("type".to_string(), syn_text("resize"));
                        m.insert("cols".to_string(), syn_int(cols as i64));
                        m.insert("rows".to_string(), syn_int(rows as i64));
                    }
                    TermEvent::Focus(g) => {
                        m.insert("type".to_string(), syn_text("focus"));
                        m.insert("gained".to_string(), syn_bool(g));
                    }
                    TermEvent::Eof => {
                        // Fin de la entrada: no es un error atrapable (como `read_line` →
                        // nothing). Se entrega una vez y el handle se retira (restaura).
                        m.insert("type".to_string(), syn_text("eof"));
                        let tagged_ev = tagged(m, "term");
                        self.term = None;
                        return Some(Ok(tagged_ev));
                    }
                }
                Some(Ok(tagged(m, "term")))
            }
        }
    }

    fn all_gone(&self, targets: &[i64]) -> bool {
        targets.iter().all(|h| self.kind_of(*h).is_none())
    }
}

fn exit_map(code: i64, sig: Option<i32>) -> SynValue {
    let mut m = indexmap::IndexMap::new();
    m.insert("exit_code".to_string(), syn_int(code));
    m.insert("signal".to_string(), sig.map(|s| syn_int(s as i64)).unwrap_or(SynValue::Nothing));
    syn_map(m)
}

/// El corazón de `select`/`ws_select`/`proc_select`/`bus_recv`/`proc_recv`: espera al
/// primer handle listo entre `targets` (readiness del Poll + Waker), con equidad,
/// fail-fast en errores terminales, y cancelación cooperativa.
fn select_impl(interp: &mut Interpreter, args: &[SynValue], reg: &Registry, fname: &str) -> Result<SynValue, Control> {
    let (targets, names) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the handles", fname)))?, fname)?;
    let timeout = timeout_arg(args.get(1), fname)?;
    select_on(interp, reg, &targets, &names, timeout, fname)
}

fn select_on(
    interp: &mut Interpreter,
    reg: &Registry,
    targets: &[i64],
    names: &TargetNames,
    timeout: Duration,
    fname: &str,
) -> Result<SynValue, Control> {
    if targets.is_empty() {
        return Ok(SynValue::Nothing);
    }
    let deadline = Instant::now() + timeout;
    watch_cancel(reg, interp);
    loop {
        interp.check_cancel()?;
        let ready = reg.borrow().first_actionable(targets);
        if let Some(h) = ready {
            let taken = reg.borrow_mut().take_event(h, names);
            match taken {
                Some(Ok(v)) => return Ok(v),
                Some(Err(e)) => return Err(err(format!("{}: {}", fname, e))),
                None => {} // carrera benigna: re-evaluar
            }
        }
        let all_gone = reg.borrow().all_gone(targets);
        if all_gone || Instant::now() >= deadline {
            return Ok(SynValue::Nothing);
        }
        let mut pending = Vec::new();
        reg.borrow_mut().pump(targets, deadline, &mut pending);
        run_pending(interp, reg, pending)?;
    }
}

fn select_builtin(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    select_impl(interp, args, reg, "select")
}

// ---------------------------------------------------------
// Procesos vivos
// ---------------------------------------------------------

fn proc_handle(reg: &Registry, v: Option<&SynValue>, fname: &str) -> Result<i64, Control> {
    let h = conn_handle(v.ok_or_else(|| err(format!("{}: missing the process handle", fname)))?, fname)?;
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Proc) => Ok(h),
        Some(HandleKind::Ws) => Err(err(format!("{}: handle {} is a WebSocket connection, not a process", fname, h))),
        Some(HandleKind::Sub) => Err(err(format!("{}: handle {} is a bus subscription, not a process", fname, h))),
        Some(HandleKind::Watch) => Err(err(format!("{}: handle {} is a file watch, not a process", fname, h))),
        Some(HandleKind::Term) => Err(err(format!("{}: handle {} is the terminal, not a process", fname, h))),
        None => Err(err(format!("{}: unknown or closed process handle {}", fname, h))),
    }
}

fn watch_handle(reg: &Registry, v: Option<&SynValue>, fname: &str) -> Result<i64, Control> {
    let h = conn_handle(v.ok_or_else(|| err(format!("{}: missing the watch handle", fname)))?, fname)?;
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Watch) => Ok(h),
        Some(HandleKind::Ws) => Err(err(format!("{}: handle {} is a WebSocket connection, not a file watch", fname, h))),
        Some(HandleKind::Proc) => Err(err(format!("{}: handle {} is a process, not a file watch", fname, h))),
        Some(HandleKind::Sub) => Err(err(format!("{}: handle {} is a bus subscription, not a file watch", fname, h))),
        Some(HandleKind::Term) => Err(err(format!("{}: handle {} is the terminal, not a file watch", fname, h))),
        None => Err(err(format!("{}: unknown or closed watch handle {}", fname, h))),
    }
}

fn term_handle(reg: &Registry, v: Option<&SynValue>, fname: &str) -> Result<i64, Control> {
    let h = conn_handle(v.ok_or_else(|| err(format!("{}: missing the terminal handle", fname)))?, fname)?;
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Term) => Ok(h),
        Some(_) => Err(err(format!("{}: handle {} is not the terminal", fname, h))),
        None => Err(err(format!("{}: unknown or closed terminal handle {}", fname, h))),
    }
}

fn opt_map<'a>(v: Option<&'a SynValue>, fname: &str) -> Result<Option<std::cell::Ref<'a, indexmap::IndexMap<String, SynValue>>>, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Map(m)) => Ok(Some(m.borrow())),
        Some(other) => Err(err(format!("{}: options must be a map, got {}", fname, other.type_name()))),
    }
}

fn opt_usize(m: &indexmap::IndexMap<String, SynValue>, key: &str, fname: &str) -> Result<Option<usize>, Control> {
    match m.get(key) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f < 1.0 {
                return Err(err(format!("{}: {} must be a positive number", fname, key)));
            }
            Ok(Some(f as usize))
        }
        Some(other) => Err(err(format!("{}: {} must be a number, got {}", fname, key, other.type_name()))),
    }
}

fn proc_spawn(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_spawn";
    let cmd = match args.first() {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => return Err(err(format!("{}: the command must be text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the command", F))),
    };
    let arg_list: Vec<String> = match args.get(1) {
        None | Some(SynValue::Nothing) => Vec::new(),
        Some(SynValue::List(l)) => l
            .borrow()
            .iter()
            .map(|v| match v {
                SynValue::Secret(_) => Err(err(format!("{}: cannot pass a secret as a process argument (reveal() it explicitly if you truly must)", F))),
                SynValue::Text(s) => Ok(s.to_string()),
                other => Ok(other.to_string()),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(err(format!("{}: args must be a list", F))),
    };
    // Gate: exec(cmd) — el MISMO de run(); sandbox lo deniega.
    {
        let caps = reg.borrow().caps.clone();
        caps.borrow_mut()
            .require(&Capability::new(CapabilityType::Exec, Some(cmd.clone())), "proc_spawn()")
            .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
    }
    {
        let r = reg.borrow();
        if r.procs.len() >= r.max_procs {
            return Err(err(format!(
                "{}: process budget reached ({} live, max {}); proc_close some or raise SYNSEMA_PROC_MAX",
                F,
                r.procs.len(),
                r.max_procs
            )));
        }
    }
    let mut opts = SpawnOpts::default();
    if let Some(m) = opt_map(args.get(2), F)? {
        if let Some(SynValue::Text(d)) = m.get("cwd") {
            opts.cwd = Some(d.to_string());
        }
        if let Some(SynValue::Map(em)) = m.get("env") {
            for (k, v) in em.borrow().iter() {
                if matches!(v, SynValue::Secret(_)) {
                    return Err(err(format!(
                        "{}: cannot pass a secret in the process env (key {:?}); reveal() it explicitly if you truly must",
                        F, k
                    )));
                }
                opts.env.push((k.clone(), v.to_string()));
            }
        }
        if let Some(n) = opt_usize(&m, "max_queue", F)? {
            opts.max_queue = n;
        }
        if let Some(n) = opt_usize(&m, "max_queue_bytes", F)? {
            opts.max_queue_bytes = n;
        }
        if let Some(v) = m.get("on_full") {
            opts.on_full = match v {
                SynValue::Text(s) if s.as_ref() == "block" => ProcOnFull::Block,
                SynValue::Text(s) if s.as_ref() == "drop_oldest" => ProcOnFull::DropOldest,
                SynValue::Text(s) if s.as_ref() == "error" => ProcOnFull::Error,
                _ => return Err(err(format!("{}: on_full must be \"block\", \"drop_oldest\" or \"error\"", F))),
            };
        }
        if let Some(SynValue::Bool(b)) = m.get("line_mode") {
            opts.line_mode = *b;
        }
        if let Some(v) = m.get("stderr") {
            opts.merge_stderr = match v {
                SynValue::Text(s) if s.as_ref() == "separate" => false,
                SynValue::Text(s) if s.as_ref() == "merge" => true,
                _ => return Err(err(format!("{}: stderr must be \"separate\" or \"merge\"", F))),
            };
        }
        // Pseudo-terminal: mismos eventos, un solo stream y bytes crudos (ANSI incluido).
        match m.get("pty") {
            None | Some(SynValue::Nothing) | Some(SynValue::Bool(false)) => {}
            Some(SynValue::Bool(true)) => {
                opts.pty = true;
                if !matches!(m.get("line_mode"), Some(SynValue::Bool(true))) {
                    opts.line_mode = false;
                }
                opts.merge_stderr = true;
            }
            Some(other) => return Err(err(format!("{}: pty must be a boolean, got {}", F, other.type_name()))),
        }
        if let Some(n) = opt_usize(&m, "cols", F)? {
            opts.cols = n.min(u16::MAX as usize) as u16;
        }
        if let Some(n) = opt_usize(&m, "rows", F)? {
            opts.rows = n.min(u16::MAX as usize) as u16;
        }
        if let Some(SynValue::Text(t)) = m.get("term") {
            opts.term = Some(t.to_string());
        }
        if !opts.pty && (m.contains_key("cols") || m.contains_key("rows") || m.contains_key("term")) {
            return Err(err(format!("{}: cols/rows/term only apply with pty: true", F)));
        }
        // Tree-kill (default): el hijo en su propio grupo/job → kill/close matan nietos.
        // `false` desprende a propósito (un daemon que debe sobrevivir al handler).
        match m.get("process_group") {
            None | Some(SynValue::Nothing) => {}
            Some(SynValue::Bool(b)) => opts.process_group = *b,
            Some(other) => return Err(err(format!("{}: process_group must be a boolean, got {}", F, other.type_name()))),
        }
    }
    let live = LiveProc::spawn(&cmd, &arg_list, opts).map_err(|e| err(format!("{}: {}", F, e)))?;
    let mut r = reg.borrow_mut();
    let w = r.waker.clone();
    live.shared.set_wake(Some(Arc::new(move || {
        let _ = w.wake();
    })));
    r.next_id += 1;
    let handle = r.next_id;
    r.procs.insert(handle, live);
    Ok(syn_int(handle))
}

fn proc_send(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_send";
    let h = proc_handle(reg, args.first(), F)?;
    let data: Vec<u8> = match args.get(1) {
        Some(SynValue::Text(s)) => s.as_bytes().to_vec(),
        Some(SynValue::Bytes(b)) => b[..].to_vec(),
        Some(SynValue::Secret(_)) => {
            return Err(err(format!("{}: cannot send a secret to a process (reveal() it first if you truly must)", F)))
        }
        Some(other) => return Err(err(format!("{}: the data must be text or bytes, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the data", F))),
    };
    let mut r = reg.borrow_mut();
    let p = r.procs.get_mut(&h).ok_or_else(|| err(format!("{}: unknown process handle {}", F, h)))?;
    p.send_stdin(&data).map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(syn_bool(true))
}

fn proc_close_stdin(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_close_stdin";
    let h = proc_handle(reg, args.first(), F)?;
    if let Some(p) = reg.borrow_mut().procs.get_mut(&h) {
        p.close_stdin().map_err(|e| err(format!("{}: {}", F, e)))?;
    }
    Ok(syn_bool(true))
}

fn proc_resize(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_resize";
    let h = proc_handle(reg, args.first(), F)?;
    let dim = |v: Option<&SynValue>, name: &str| -> Result<u16, Control> {
        match v {
            Some(SynValue::Number(n)) => {
                let f = n.to_f64();
                if !f.is_finite() || f < 1.0 || f > u16::MAX as f64 {
                    return Err(err(format!("{}: {} must be a positive number (1..65535)", F, name)));
                }
                Ok(f as u16)
            }
            Some(other) => Err(err(format!("{}: {} must be a number, got {}", F, name, other.type_name()))),
            None => Err(err(format!("{}: missing {}", F, name))),
        }
    };
    let cols = dim(args.get(1), "cols")?;
    let rows = dim(args.get(2), "rows")?;
    let mut r = reg.borrow_mut();
    let p = r.procs.get_mut(&h).ok_or_else(|| err(format!("{}: unknown process handle {}", F, h)))?;
    p.resize(cols, rows).map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(syn_bool(true))
}

fn proc_recv(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_recv";
    let h = proc_handle(reg, args.first(), F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    select_on(interp, reg, &[h], &None, timeout, F)
}

fn proc_select(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_select";
    let (targets, names) = resolve_targets(args.first().ok_or_else(|| err(format!("{}: missing the process handles", F)))?, F)?;
    for h in &targets {
        proc_handle(reg, Some(&syn_int(*h)), F)?;
    }
    let timeout = timeout_arg(args.get(1), F)?;
    select_on(interp, reg, &targets, &names, timeout, F)
}

fn proc_status(_interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_status";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the process handle", F)))?, F)?;
    let mut r = reg.borrow_mut();
    let Some(p) = r.procs.get_mut(&h) else {
        return Ok(syn_text("closed"));
    };
    p.poll_exit();
    Ok(syn_text(match p.status {
        ProcStatus::Running => "running",
        ProcStatus::Exited => "exited",
        ProcStatus::Killed => "killed",
    }))
}

fn proc_kill(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_kill";
    let h = proc_handle(reg, args.first(), F)?;
    let graceful = match args.get(1) {
        None | Some(SynValue::Nothing) => true,
        Some(SynValue::Text(s)) if s.as_ref().eq_ignore_ascii_case("TERM") || s.as_ref().eq_ignore_ascii_case("SIGTERM") => true,
        Some(SynValue::Text(s)) if s.as_ref().eq_ignore_ascii_case("KILL") || s.as_ref().eq_ignore_ascii_case("SIGKILL") => false,
        Some(_) => return Err(err(format!("{}: the signal must be \"TERM\" (default) or \"KILL\"", F))),
    };
    let mut r = reg.borrow_mut();
    let p = r.procs.get_mut(&h).ok_or_else(|| err(format!("{}: unknown process handle {}", F, h)))?;
    p.kill(graceful).map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(syn_bool(true))
}

fn proc_wait(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_wait";
    let h = proc_handle(reg, args.first(), F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    let deadline = Instant::now() + timeout;
    loop {
        interp.check_cancel()?;
        {
            let mut r = reg.borrow_mut();
            let p = r.procs.get_mut(&h).ok_or_else(|| err(format!("{}: unknown process handle {}", F, h)))?;
            if p.poll_exit() {
                return Ok(exit_map(p.exit_code.unwrap_or(-1), p.exit_signal));
            }
        }
        if Instant::now() >= deadline {
            return Ok(SynValue::Nothing);
        }
        // Dormir en el Poll (el exit despierta por los lectores; si no, 20 ms).
        let slice = deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(20));
        reg.borrow_mut().poll_process(slice);
    }
}

fn proc_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_close";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the process handle", F)))?, F)?;
    // Idempotente: cerrar un handle desconocido es no-op.
    let removed = reg.borrow_mut().procs.remove(&h);
    if let Some(mut p) = removed {
        p.shutdown();
    }
    Ok(syn_bool(true))
}

fn proc_stats(_interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "proc_stats";
    let h = proc_handle(reg, args.first(), F)?;
    let mut r = reg.borrow_mut();
    let p = r.procs.get_mut(&h).ok_or_else(|| err(format!("{}: unknown process handle {}", F, h)))?;
    p.poll_exit();
    let (queued, queued_bytes, dropped) = p.shared.stats();
    let mut m = indexmap::IndexMap::new();
    m.insert("pid".to_string(), syn_int(p.pid as i64));
    m.insert("cmd".to_string(), syn_text(p.cmd.clone()));
    m.insert(
        "status".to_string(),
        syn_text(match p.status {
            ProcStatus::Running => "running",
            ProcStatus::Exited => "exited",
            ProcStatus::Killed => "killed",
        }),
    );
    m.insert("exit_code".to_string(), p.exit_code.map(syn_int).unwrap_or(SynValue::Nothing));
    m.insert("pty".to_string(), syn_bool(p.pty));
    m.insert("tree".to_string(), syn_bool(p.tree));
    m.insert("queued".to_string(), syn_int(queued as i64));
    m.insert("queued_bytes".to_string(), syn_int(queued_bytes as i64));
    m.insert("dropped".to_string(), syn_int(dropped as i64));
    m.insert(
        "uptime".to_string(),
        syn_number(synsema_core::number::Number::Float(p.started_at.elapsed().as_secs_f64())),
    );
    Ok(syn_map(m))
}

// ---------------------------------------------------------
// Bus de eventos
// ---------------------------------------------------------

fn bus_of(reg: &Registry, fname: &str) -> Result<Arc<Bus>, Control> {
    reg.borrow()
        .bus
        .clone()
        .ok_or_else(|| err(format!("{}: the event bus is not available in this context (it lives in the process swarm)", fname)))
}

/// Conversión ESTRICTA a `SendValue` para publicar: una task, un builtin o un secret no
/// cruzan el bus (nunca degradados a texto en silencio — el suscriptor recibiría basura
/// o un secret redactado sin saberlo).
fn to_send_strict(v: &SynValue, fname: &str) -> Result<SendValue, Control> {
    match v {
        SynValue::Task(_) | SynValue::Builtin(_) => {
            Err(err(format!("{}: cannot publish a task on the bus (publish data: text/number/bool/list/map/bytes)", fname)))
        }
        SynValue::Secret(_) => Err(err(format!("{}: cannot publish a secret on the bus", fname))),
        SynValue::List(l) => Ok(SendValue::List(
            l.borrow().iter().map(|x| to_send_strict(x, fname)).collect::<Result<Vec<_>, _>>()?,
        )),
        SynValue::Map(m) => Ok(SendValue::Map(
            m.borrow()
                .iter()
                .map(|(k, x)| to_send_strict(x, fname).map(|sv| (k.clone(), sv)))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        other => Ok(synsema_core::types::to_send(other)),
    }
}

fn topic_arg(v: Option<&SynValue>, fname: &str) -> Result<String, Control> {
    match v {
        Some(SynValue::Text(s)) if !s.trim().is_empty() => Ok(s.to_string()),
        Some(SynValue::Text(_)) => Err(err(format!("{}: the topic cannot be empty", fname))),
        Some(other) => Err(err(format!("{}: the topic must be text, got {}", fname, other.type_name()))),
        None => Err(err(format!("{}: missing the topic", fname))),
    }
}

fn bus_publish(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "bus_publish";
    let topic = topic_arg(args.first(), F)?;
    if topic.contains('*') || topic.contains('?') {
        return Err(err(format!("{}: a published topic is literal (globs belong to bus_subscribe), got {:?}", F, topic)));
    }
    let data = to_send_strict(args.get(1).unwrap_or(&SynValue::Nothing), F)?;
    let bus = bus_of(reg, F)?;
    Ok(syn_int(bus.publish(&topic, data) as i64))
}

fn bus_subscribe(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "bus_subscribe";
    let patterns: Vec<String> = match args.first() {
        Some(SynValue::List(l)) => l
            .borrow()
            .iter()
            .map(|v| topic_arg(Some(v), F))
            .collect::<Result<Vec<_>, _>>()?,
        other => vec![topic_arg(other, F)?],
    };
    if patterns.is_empty() {
        return Err(err(format!("{}: subscribe to at least one topic", F)));
    }
    let mut opts = SubscribeOpts::default();
    if let Some(m) = opt_map(args.get(1), F)? {
        if let Some(n) = opt_usize(&m, "max_queue", F)? {
            opts.max_queue = n;
        }
        if let Some(n) = opt_usize(&m, "max_queue_bytes", F)? {
            opts.max_queue_bytes = n;
        }
        if let Some(v) = m.get("on_full") {
            opts.on_full = match v {
                SynValue::Text(s) if s.as_ref() == "drop_oldest" => BusOnFull::DropOldest,
                SynValue::Text(s) if s.as_ref() == "error" => BusOnFull::Error,
                _ => return Err(err(format!("{}: on_full must be \"drop_oldest\" or \"error\"", F))),
            };
        }
    }
    let bus = bus_of(reg, F)?;
    let sub = bus.subscribe(patterns, opts).map_err(err)?;
    let mut r = reg.borrow_mut();
    let w = r.waker.clone();
    sub.set_wake(Some(Arc::new(move || {
        let _ = w.wake();
    })));
    r.next_id += 1;
    let handle = r.next_id;
    r.subs.insert(handle, sub);
    Ok(syn_int(handle))
}

fn bus_recv(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "bus_recv";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the subscription handle", F)))?, F)?;
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Sub) => {}
        Some(_) => return Err(err(format!("{}: handle {} is not a bus subscription", F, h))),
        None => return Err(err(format!("{}: unknown or closed subscription handle {}", F, h))),
    }
    let timeout = timeout_arg(args.get(1), F)?;
    select_on(interp, reg, &[h], &None, timeout, F)
}

fn bus_unsubscribe(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "bus_unsubscribe";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the subscription handle", F)))?, F)?;
    let mut r = reg.borrow_mut();
    if let Some(s) = r.subs.remove(&h) {
        if let Some(bus) = &r.bus {
            bus.unsubscribe(s.id);
        }
    }
    Ok(syn_bool(true))
}

fn bus_topics(_args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "bus_topics";
    let bus = bus_of(reg, F)?;
    let items: Vec<SynValue> = bus
        .topics()
        .into_iter()
        .map(|(topic, n)| {
            let mut m = indexmap::IndexMap::new();
            m.insert("topic".to_string(), syn_text(topic));
            m.insert("subscribers".to_string(), syn_int(n as i64));
            syn_map(m)
        })
        .collect();
    Ok(SynValue::List(Rc::new(RefCell::new(items))))
}

// ---------------------------------------------------------
// File-watch
// ---------------------------------------------------------

fn opt_f64(m: &indexmap::IndexMap<String, SynValue>, key: &str, fname: &str) -> Result<Option<f64>, Control> {
    match m.get(key) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f <= 0.0 {
                return Err(err(format!("{}: {} must be a positive number", fname, key)));
            }
            Ok(Some(f))
        }
        Some(other) => Err(err(format!("{}: {} must be a number, got {}", fname, key, other.type_name()))),
    }
}

/// `watch(path, opts?)` → handle. Gate `file_read(path)`: observar un árbol es leerlo.
fn watch_open(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "watch";
    let path = match args.first() {
        Some(SynValue::Text(s)) => normalize_path(s),
        Some(SynValue::Secret(_)) => return Err(err(format!("{}: the path cannot be a secret", F))),
        Some(other) => return Err(err(format!("{}: the path must be text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the path", F))),
    };
    if path.is_empty() {
        return Err(err(format!("{}: the path is empty", F)));
    }
    {
        let caps = reg.borrow().caps.clone();
        caps.borrow_mut()
            .require(&Capability::new(CapabilityType::FileRead, Some(path.clone())), "watch()")
            .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
    }
    {
        let r = reg.borrow();
        if r.watches.len() >= r.max_watches {
            return Err(err(format!(
                "{}: watch budget reached ({} live, max {}); watch_close some or raise SYNSEMA_WATCH_MAX",
                F,
                r.watches.len(),
                r.max_watches
            )));
        }
    }
    let mut opts = WatchOpts::default();
    if let Some(m) = opt_map(args.get(1), F)? {
        match m.get("recursive") {
            None | Some(SynValue::Nothing) => {}
            Some(SynValue::Bool(b)) => opts.recursive = *b,
            Some(other) => return Err(err(format!("{}: recursive must be a boolean, got {}", F, other.type_name()))),
        }
        if let Some(secs) = opt_f64(&m, "interval", F)? {
            opts.interval = Duration::from_secs_f64(secs).max(crate::watch::MIN_INTERVAL);
        }
        match m.get("ignore") {
            None | Some(SynValue::Nothing) => {}
            Some(SynValue::List(l)) => {
                let mut pats = Vec::new();
                for it in l.borrow().iter() {
                    match it {
                        SynValue::Text(s) if !s.is_empty() => pats.push(s.to_string()),
                        SynValue::Text(_) => {}
                        other => return Err(err(format!("{}: ignore must be a list of text patterns, got {}", F, other.type_name()))),
                    }
                }
                opts.ignore = pats;
            }
            Some(other) => return Err(err(format!("{}: ignore must be a list, got {}", F, other.type_name()))),
        }
        if let Some(n) = opt_usize(&m, "max_entries", F)? {
            opts.max_entries = n.min(crate::watch::MAX_ENTRIES_CEILING);
        }
        if let Some(n) = opt_usize(&m, "max_queue", F)? {
            opts.max_queue = n;
        }
    }
    let w = Watch::start(&path, opts).map_err(|e| err(format!("{}: {}", F, e)))?;
    let mut r = reg.borrow_mut();
    let wk = r.waker.clone();
    w.shared.set_wake(Some(Arc::new(move || {
        let _ = wk.wake();
    })));
    r.next_id += 1;
    let handle = r.next_id;
    r.watches.insert(handle, w);
    Ok(syn_int(handle))
}

fn watch_recv(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "watch_recv";
    let h = watch_handle(reg, args.first(), F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    select_on(interp, reg, &[h], &None, timeout, F)
}

fn watch_stats(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "watch_stats";
    let h = watch_handle(reg, args.first(), F)?;
    let r = reg.borrow();
    let w = r.watches.get(&h).ok_or_else(|| err(format!("{}: unknown watch handle {}", F, h)))?;
    let (queued, dropped, entries, scans) = w.shared.stats();
    let mut m = indexmap::IndexMap::new();
    m.insert("path".to_string(), syn_text(w.shared.root.clone()));
    m.insert("recursive".to_string(), syn_bool(w.shared.recursive));
    m.insert("interval".to_string(), syn_number(synsema_core::number::Number::Float(w.shared.interval.as_secs_f64())));
    m.insert("entries".to_string(), syn_int(entries as i64));
    m.insert("scans".to_string(), syn_int(scans as i64));
    m.insert("queued".to_string(), syn_int(queued as i64));
    m.insert("dropped".to_string(), syn_int(dropped as i64));
    Ok(syn_map(m))
}

fn watch_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "watch_close";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the watch handle", F)))?, F)?;
    // Idempotente: cerrar un handle desconocido es no-op. Drop apaga el scanner.
    reg.borrow_mut().watches.remove(&h);
    Ok(syn_bool(true))
}

// ---------------------------------------------------------
// Terminal propia (`term_*`)
// ---------------------------------------------------------

/// `term_open(opts?)` → handle, o `nothing` sin TTY / bajo test-conform-serve / WASM.
/// Gate `stdin` (se evalúa ANTES del chequeo de TTY: fail-closed primero).
fn term_open(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_open";
    {
        let caps = reg.borrow().caps.clone();
        caps.borrow_mut()
            .require(&Capability::new(CapabilityType::Stdin, None), "term_open()")
            .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
    }
    let mut opts = TermOpts::default();
    if let Some(m) = opt_map(args.first(), F)? {
        for (key, slot) in [("paste", &mut opts.paste), ("kitty", &mut opts.kitty)] {
            match m.get(key) {
                None | Some(SynValue::Nothing) => {}
                Some(SynValue::Bool(b)) => *slot = *b,
                Some(other) => return Err(err(format!("{}: {} must be a boolean, got {}", F, key, other.type_name()))),
            }
        }
        match m.get("ctrl_c") {
            None | Some(SynValue::Nothing) => {}
            Some(SynValue::Text(t)) if t.as_ref() == "exit" => opts.ctrl_c_exit = true,
            Some(SynValue::Text(t)) if t.as_ref() == "key" => opts.ctrl_c_exit = false,
            Some(other) => return Err(err(format!("{}: ctrl_c must be \"exit\" or \"key\", got {}", F, other))),
        }
        match m.get("mouse") {
            None | Some(SynValue::Nothing) | Some(SynValue::Bool(false)) => {}
            Some(_) => return Err(err(format!("{}: mouse capture is not implemented yet (the option is reserved)", F))),
        }
        if let Some(n) = opt_usize(&m, "max_queue", F)? {
            opts.max_queue = n;
        }
    }
    // Sin salida en vivo (`synsema test`, `conform`, `serve`) no hay terminal interactiva:
    // el programa cae a `read_line` como con un pipe. No es error.
    if !interp.live_output {
        return Ok(SynValue::Nothing);
    }
    if let Some((h, _)) = &reg.borrow().term {
        return Err(err(format!("{}: a terminal is already open (handle {}); term_close it first", F, h)));
    }
    let t = match Term::open(opts) {
        Ok(t) => t,
        Err(TermError::NoTty) => return Ok(SynValue::Nothing),
        Err(TermError::Busy) => return Err(err(format!("{}: the terminal is owned by another agent of this process", F))),
        Err(TermError::Other(e)) => return Err(err(format!("{}: {}", F, e))),
    };
    let mut r = reg.borrow_mut();
    let wk = r.waker.clone();
    t.shared.set_wake(Some(Arc::new(move || {
        let _ = wk.wake();
    })));
    r.next_id += 1;
    let handle = r.next_id;
    r.term = Some((handle, t));
    Ok(syn_int(handle))
}

fn term_recv(interp: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_recv";
    let h = term_handle(reg, args.first(), F)?;
    let timeout = timeout_arg(args.get(1), F)?;
    select_on(interp, reg, &[h], &None, timeout, F)
}

fn term_size(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_size";
    term_handle(reg, args.first(), F)?;
    let (cols, rows) = Term::size().map_err(|e| err(format!("{}: {}", F, e)))?;
    let mut m = indexmap::IndexMap::new();
    m.insert("cols".to_string(), syn_int(cols as i64));
    m.insert("rows".to_string(), syn_int(rows as i64));
    Ok(syn_map(m))
}

/// `term_write(h, text)`: a stdout YA, sin pasar por el buffer de `print`.
fn term_write(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_write";
    term_handle(reg, args.first(), F)?;
    let text = match args.get(1) {
        Some(SynValue::Text(t)) => t.to_string(),
        Some(SynValue::Secret(_)) => return Err(err(format!("{}: refusing to print a secret", F))),
        Some(SynValue::Nothing) | None => String::new(),
        Some(other) => other.to_string(),
    };
    Term::write(&text).map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(SynValue::Nothing)
}

fn term_stats(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_stats";
    let h = term_handle(reg, args.first(), F)?;
    let r = reg.borrow();
    let t = &r.term.as_ref().filter(|(th, _)| *th == h).ok_or_else(|| err(format!("{}: unknown terminal handle {}", F, h)))?.1;
    let (queued, dropped, keys) = t.shared.stats();
    let mut m = indexmap::IndexMap::new();
    m.insert("kitty".to_string(), syn_bool(t.shared.kitty));
    m.insert("paste".to_string(), syn_bool(t.shared.paste));
    m.insert("ansi".to_string(), syn_bool(t.shared.ansi));
    m.insert("keys".to_string(), syn_int(keys as i64));
    m.insert("queued".to_string(), syn_int(queued as i64));
    m.insert("dropped".to_string(), syn_int(dropped as i64));
    Ok(syn_map(m))
}

fn term_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "term_close";
    let h = conn_handle(args.first().ok_or_else(|| err(format!("{}: missing the terminal handle", F)))?, F)?;
    // Idempotente: un handle desconocido es no-op. Drop restaura la consola y apaga el lector.
    let mut r = reg.borrow_mut();
    if matches!(&r.term, Some((th, _)) if *th == h) {
        r.term = None;
    }
    Ok(syn_bool(true))
}

// =========================================================
// Registro
// =========================================================

pub fn register_ws_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    let poll = Poll::new().expect("mio::Poll::new");
    let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN).expect("mio::Waker::new"));
    let max_procs = std::env::var("SYNSEMA_PROC_MAX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_PROCS_CEILING))
        .unwrap_or(DEFAULT_MAX_PROCS);
    let max_watches = std::env::var("SYNSEMA_WATCH_MAX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_WATCHES_CEILING))
        .unwrap_or(DEFAULT_MAX_WATCHES);
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
        waker,
        procs: HashMap::new(),
        max_procs,
        watches: HashMap::new(),
        max_watches,
        term: None,
        subs: HashMap::new(),
        bus: None,
        cancel_seen: 0,
        cancel_flag: None,
    }));
    // El hub queda alcanzable desde el intérprete (slot opaco): el motor adjunta el
    // bus (`attach_bus`) y el serve adopta sockets entrantes (`adopt_server_socket`).
    interp.ext.borrow_mut().insert(IO_HUB_KEY, Rc::new(reg.clone()) as Rc<dyn std::any::Any>);

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

    // -- select unificado (sockets + procesos + bus) --
    reg_fn_interp!("select", -1, select_builtin);

    // -- procesos vivos --
    reg_fn!("proc_spawn", -1, proc_spawn);
    reg_fn!("proc_send", 2, proc_send);
    reg_fn!("proc_close_stdin", 1, proc_close_stdin);
    reg_fn!("proc_resize", 3, proc_resize);
    reg_fn_interp!("proc_recv", -1, proc_recv);
    reg_fn_interp!("proc_select", -1, proc_select);
    reg_fn_interp!("proc_status", 1, proc_status);
    reg_fn!("proc_kill", -1, proc_kill);
    reg_fn_interp!("proc_wait", -1, proc_wait);
    reg_fn!("proc_close", 1, proc_close);
    reg_fn_interp!("proc_stats", 1, proc_stats);

    // -- file-watch (polling con snapshot; entra en `select`) --
    reg_fn!("watch", -1, watch_open);
    reg_fn_interp!("watch_recv", -1, watch_recv);
    reg_fn!("watch_stats", 1, watch_stats);
    reg_fn!("watch_close", 1, watch_close);

    // -- terminal propia (raw mode + teclas como eventos; entra en `select`) --
    reg_fn_interp!("term_open", -1, term_open);
    reg_fn_interp!("term_recv", -1, term_recv);
    reg_fn!("term_size", 1, term_size);
    reg_fn!("term_write", 2, term_write);
    reg_fn!("term_stats", 1, term_stats);
    reg_fn!("term_close", 1, term_close);

    // -- bus de eventos (pub/sub in-process) --
    reg_fn!("bus_publish", 2, bus_publish);
    reg_fn!("bus_subscribe", -1, bus_subscribe);
    reg_fn_interp!("bus_recv", -1, bus_recv);
    reg_fn!("bus_unsubscribe", 1, bus_unsubscribe);
    reg_fn!("bus_topics", 0, bus_topics);
}
