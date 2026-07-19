//! Cliente WebSocket (Batch 13, alcance B) — primitiva GENERAL del lenguaje, NO
//! de blockchain: suscripciones RPC, exchanges, Discord/Slack, cualquier feed en
//! vivo que hoy se emulaba con `cron` + polling.
//!
//! - **G21 — no evade el modelo de red.** `ws_connect(url)` exige la capability
//!   `net(host)` EXISTENTE (misma que `http_*`/`fetch`, mismo scope por hostname);
//!   dentro de `sandbox` (caps vaciadas) → denegado. WS es transporte, no una
//!   puerta nueva.
//! - **Anti-DoS.** Tamaño máximo de mensaje acotado (default 16 MiB, configurable
//!   y con techo duro de 64 MiB) — tungstenite corta el buffering al pasarlo; una
//!   conexión muerta nunca cuelga al agente: timeout en connect/handshake y en
//!   CADA `ws_recv` (vencido → `nothing`, jamás bloqueo eterno).
//! - **Sync real.** `tungstenite` bloqueante sobre `std::net` — calza con el
//!   engine sync (como los drivers de DB). TLS de `wss://` con el MISMO
//!   rustls/ring + root CAs del SO que `http.rs` (cero features TLS del crate,
//!   que arrastrarían un provider `*-sys`).
//! - El handle devuelto es un entero opaco por intérprete (como las conexiones de
//!   DB). Bajo `serve`, cada handler puede abrir un WS saliente y reenviar por
//!   SSE (puente WS→SSE); el WS *servidor* (aceptar entrantes) es otro batch.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_bytes, syn_int, syn_map, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Techo duro del tamaño de mensaje (el configurable no lo puede superar).
const MAX_MESSAGE_CEILING: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Timeout default de connect/handshake y de `ws_recv` (mismo criterio que
/// `wait_for`: 30 s).
const DEFAULT_TIMEOUT_SECS: f64 = 30.0;

// =========================================================
// Stream: TCP plano o TLS (rustls/ring, como http.rs)
// =========================================================

enum WsStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl WsStream {
    fn tcp(&self) -> &TcpStream {
        match self {
            WsStream::Plain(t) => t,
            WsStream::Tls(s) => s.get_ref(),
        }
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(t) => t.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(t) => t.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(t) => t.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

/// Registro de conexiones del intérprete (handle entero → socket).
#[derive(Default)]
struct WsRegistry {
    next_id: i64,
    conns: HashMap<i64, WebSocket<WsStream>>,
}

type Registry = Rc<RefCell<WsRegistry>>;

// =========================================================
// Helpers
// =========================================================

fn require_net(caps: &Rc<RefCell<CapabilitySet>>, url: &str) -> Result<(), Control> {
    let host = match url_hostname(url) {
        Some(h) if !h.is_empty() => h,
        _ => url.to_string(), // fail-closed: sin host extraíble, el scope es el URL crudo
    };
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(host)), "ws_connect()")
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// (host, port, tls) desde un URL `ws://` / `wss://`. Un scheme http/https se
/// corrige con un error dirigido (no se adivina).
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
            return Err(err(format!(
                "{}: unsupported scheme {:?}; use ws:// or wss://",
                fname, other
            )))
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            let port: u16 = p
                .parse()
                .map_err(|_| err(format!("{}: invalid port in URL", fname)))?;
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
                return Err(err(format!(
                    "{}: the timeout must be a non-negative number of seconds",
                    fname
                )));
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
        SynValue::Number(n) => n.to_i64_trunc().ok_or_else(|| {
            err(format!("{}: the connection handle must be an integer", fname))
        }),
        other => Err(err(format!(
            "{}: expected a connection handle from ws_connect(), got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// Error de tungstenite → error del lenguaje (atrapable, sin panics).
fn ws_error(e: tungstenite::Error, fname: &str) -> Control {
    use tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed => {
            err(format!("{}: the connection is closed", fname))
        }
        E::Capacity(c) => err(format!("{}: message over the size limit: {}", fname, c)),
        other => err(format!("{}: {}", fname, other)),
    }
}

// =========================================================
// Builtins
// =========================================================

fn ws_connect(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
    reg: &Registry,
) -> Result<SynValue, Control> {
    const F: &str = "ws_connect";
    let url = match args.first() {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => {
            return Err(err(format!("{}: the URL must be text, got {}", F, other.type_name())))
        }
        None => return Err(err(format!("{}: missing the URL", F))),
    };
    // G21: la MISMA capability net(host) que http_*/fetch, chequeada ANTES de
    // resolver/conectar nada.
    require_net(caps, &url)?;
    let (host, port, tls) = parse_ws_url(&url, F)?;

    // headers? (map texto→texto) y opts? ({"max_message_size", "timeout"}).
    let headers: Vec<(String, String)> = match args.get(1) {
        None | Some(SynValue::Nothing) => Vec::new(),
        Some(SynValue::Map(m)) => m
            .borrow()
            .iter()
            .map(|(k, v)| {
                let vs = match v {
                    SynValue::Text(s) => s.to_string(),
                    // Un secret (p.ej. bearer()) se materializa SÓLO en el borde
                    // del socket, como los headers de http_* — jamás en user-space.
                    SynValue::Secret(s) => s.expose().into_owned(),
                    other => other.to_string(),
                };
                (k.clone(), vs)
            })
            .collect(),
        Some(other) => {
            return Err(err(format!(
                "{}: headers must be a map, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => indexmap::IndexMap::new(),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => {
            return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name())))
        }
    };
    for k in opts.keys() {
        if !matches!(k.as_str(), "max_message_size" | "timeout") {
            return Err(err(format!(
                "{}: unknown option {:?} (allowed: max_message_size, timeout)",
                F, k
            )));
        }
    }
    let timeout = timeout_arg(opts.get("timeout"), F)?;
    let max_msg = match opts.get("max_message_size") {
        None | Some(SynValue::Nothing) => DEFAULT_MAX_MESSAGE,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(v) if v > 0 && (v as usize) <= MAX_MESSAGE_CEILING => v as usize,
            _ => {
                return Err(err(format!(
                    "{}: max_message_size must be a positive number of bytes up to {}",
                    F, MAX_MESSAGE_CEILING
                )))
            }
        },
        Some(other) => {
            return Err(err(format!(
                "{}: max_message_size must be a number, got {}",
                F,
                other.type_name()
            )))
        }
    };

    // TCP con timeout de connect + timeouts de lectura/escritura del handshake.
    let addr = format!("{}:{}", host, port);
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| err(format!("{}: cannot resolve {}: {}", F, host, e)))?
        .next()
        .ok_or_else(|| err(format!("{}: cannot resolve host {}", F, host)))?;
    let tcp = TcpStream::connect_timeout(&sa, timeout)
        .map_err(|e| err(format!("{}: cannot connect to {}: {}", F, addr, e)))?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let _ = tcp.set_nodelay(true);

    let stream = if tls {
        // G21: el certificado del server se valida contra los root CAs del SO
        // para el HOSTNAME del URL (el mismo que pasó el gate `net`) — un peer
        // con cert ajeno no pasa, igual que en https.
        let roots = crate::http::root_cert_store().map_err(|e| err(format!("{}: {}", F, e)))?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name: rustls::pki_types::ServerName<'static> = host
            .as_str()
            .try_into()
            .map(|n: rustls::pki_types::ServerName| n.to_owned())
            .map_err(|_| err(format!("{}: invalid server name: {}", F, host)))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| err(format!("{}: TLS setup failed: {}", F, e)))?;
        WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        WsStream::Plain(tcp)
    };

    // Request del handshake: el URL + headers extra del caller.
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| err(format!("{}: invalid WebSocket URL: {}", F, e)))?;
    for (k, v) in &headers {
        let name = tungstenite::http::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| err(format!("{}: invalid header name {:?}", F, k)))?;
        let value = tungstenite::http::header::HeaderValue::from_str(v)
            .map_err(|_| err(format!("{}: invalid value for header {:?}", F, k)))?;
        request.headers_mut().insert(name, value);
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(max_msg))
        .max_frame_size(Some(max_msg));

    let (socket, _response) = tungstenite::client::client_with_config(request, stream, Some(config))
        .map_err(|e| match e {
            tungstenite::HandshakeError::Interrupted(_) => err(format!(
                "{}: the WebSocket handshake timed out after {:?}",
                F, timeout
            )),
            tungstenite::HandshakeError::Failure(e) => {
                err(format!("{}: the WebSocket handshake failed: {}", F, e))
            }
        })?;

    let mut r = reg.borrow_mut();
    r.next_id += 1;
    let id = r.next_id;
    r.conns.insert(id, socket);
    Ok(syn_int(id))
}

fn ws_send(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_send";
    let id = conn_handle(
        args.first()
            .ok_or_else(|| err(format!("{}: missing the connection handle", F)))?,
        F,
    )?;
    let msg = match args.get(1) {
        Some(SynValue::Text(s)) => Message::text(s.to_string()),
        Some(SynValue::Bytes(b)) => Message::binary(b[..].to_vec()),
        Some(SynValue::Secret(_)) => {
            return Err(err(format!(
                "{}: cannot send a secret over a WebSocket (reveal() it first if you truly must)",
                F
            )))
        }
        Some(other) => {
            return Err(err(format!(
                "{}: the message must be text or bytes, got {}",
                F,
                other.type_name()
            )))
        }
        None => return Err(err(format!("{}: missing the message", F))),
    };
    let mut r = reg.borrow_mut();
    let ws = r
        .conns
        .get_mut(&id)
        .ok_or_else(|| err(format!("{}: unknown or closed connection handle {}", F, id)))?;
    match ws.send(msg) {
        Ok(()) => Ok(syn_bool(true)),
        Err(e) => {
            // Una conexión que ya no escribe se retira del registro (el handle
            // queda inválido; el error lo dice).
            let is_closed = matches!(
                e,
                tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed
            );
            if is_closed {
                r.conns.remove(&id);
            }
            Err(ws_error(e, F))
        }
    }
}

fn ws_recv(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_recv";
    let id = conn_handle(
        args.first()
            .ok_or_else(|| err(format!("{}: missing the connection handle", F)))?,
        F,
    )?;
    let timeout = timeout_arg(args.get(1), F)?;
    let deadline = Instant::now() + timeout;
    let mut r = reg.borrow_mut();
    let ws = r
        .conns
        .get_mut(&id)
        .ok_or_else(|| err(format!("{}: unknown or closed connection handle {}", F, id)))?;
    loop {
        // El read-timeout del socket se acota a lo que RESTA del deadline: ni un
        // ping/pong intermedio ni un peer goteando frames estiran la espera total.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(SynValue::Nothing);
        }
        let _ = ws.get_ref().tcp().set_read_timeout(Some(remaining));
        match ws.read() {
            Ok(Message::Text(t)) => {
                let mut m = indexmap::IndexMap::new();
                m.insert("type".to_string(), syn_text("text"));
                m.insert("data".to_string(), syn_text(t.as_str()));
                return Ok(syn_map(m));
            }
            Ok(Message::Binary(b)) => {
                let mut m = indexmap::IndexMap::new();
                m.insert("type".to_string(), syn_text("binary"));
                m.insert("data".to_string(), syn_bytes(b.to_vec()));
                return Ok(syn_map(m));
            }
            // Ping/Pong: tungstenite encola el pong solo; seguimos esperando datos.
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(frame)) => {
                r.conns.remove(&id);
                let mut m = indexmap::IndexMap::new();
                m.insert("type".to_string(), syn_text("close"));
                m.insert(
                    "data".to_string(),
                    match frame {
                        Some(f) if !f.reason.is_empty() => syn_text(f.reason.to_string()),
                        _ => SynValue::Nothing,
                    },
                );
                return Ok(syn_map(m));
            }
            Ok(Message::Frame(_)) => continue, // sólo aparece en modo raw; ignorar
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(SynValue::Nothing); // timeout: nothing, jamás colgado
            }
            Err(tungstenite::Error::ConnectionClosed) => {
                r.conns.remove(&id);
                let mut m = indexmap::IndexMap::new();
                m.insert("type".to_string(), syn_text("close"));
                m.insert("data".to_string(), SynValue::Nothing);
                return Ok(syn_map(m));
            }
            Err(e) => {
                r.conns.remove(&id);
                return Err(ws_error(e, F));
            }
        }
    }
}

fn ws_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "ws_close";
    let id = conn_handle(
        args.first()
            .ok_or_else(|| err(format!("{}: missing the connection handle", F)))?,
        F,
    )?;
    let mut r = reg.borrow_mut();
    // Cerrar un handle ya cerrado/desconocido es un no-op (idempotente, como
    // db_close), no un error.
    let Some(mut ws) = r.conns.remove(&id) else {
        return Ok(syn_bool(true));
    };
    // Close frame limpio + drenar la respuesta un ratito acotado; los errores acá
    // no importan (el peer pudo cortar antes).
    let _ = ws.get_ref().tcp().set_read_timeout(Some(Duration::from_secs(2)));
    let _ = ws.close(None);
    for _ in 0..8 {
        match ws.read() {
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Ok(syn_bool(true))
}

// =========================================================
// Registro
// =========================================================

/// Registra `ws_connect`/`ws_send`/`ws_recv`/`ws_close`. `ws_connect` cierra
/// sobre el `CapabilitySet` para el gate `net(host)` (G21); el registro de
/// conexiones es por-intérprete (como el DatabaseManager).
pub fn register_ws_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    let reg: Registry = Rc::new(RefCell::new(WsRegistry::default()));
    {
        let reg = reg.clone();
        interp.register_builtin(
            "ws_connect",
            -1,
            Rc::new(move |_i, a, _l| ws_connect(a, &caps, &reg)),
        );
    }
    {
        let reg = reg.clone();
        interp.register_builtin("ws_send", 2, Rc::new(move |_i, a, _l| ws_send(a, &reg)));
    }
    {
        let reg = reg.clone();
        interp.register_builtin("ws_recv", -1, Rc::new(move |_i, a, _l| ws_recv(a, &reg)));
    }
    interp.register_builtin("ws_close", 1, Rc::new(move |_i, a, _l| ws_close(a, &reg)));
}
