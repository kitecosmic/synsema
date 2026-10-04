//! v0.6.42 — TCP saliente (`tcp_*`) y extremos de `pipe` (`pipe_*`) como handles del hub.
//!
//! Los dos entran en `select` junto a WebSockets, procesos, bus, watches y la terminal, con el
//! mismo contrato que `ws_*`: `*_recv(h, timeout?)` devuelve `{type: "data", data: <bytes>}` o
//! `{type: "close"}`, y `nothing` si vence el timeout; nunca bloquea para siempre. Memoria acotada
//! en las dos direcciones: un lado que no lee frena al que escribe (TCP: la ventana del kernel;
//! pipe: el tope del buffer), y el escritor espera de forma cancelable o falla con timeout.
//!
//! Capability de `tcp_connect`: `net("host:puerto")` con el puerto real — un grant con puerto cubre
//! sólo ese puerto (`require net("127.0.0.1:8080")` no alcanza el 8081); uno sin puerto, todos.
//! `pipe()` no pide nada: es memoria del proceso.

use super::*;
use crate::pipe::{self, PipeEnd, ReadOutcome, WriteError};
use mio::{Interest, Token};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;

/// Tope de bytes leídos y no entregados por conexión TCP (lo demás espera en el kernel).
const DEFAULT_TCP_BUFFER: usize = 1024 * 1024;
const TCP_BUFFER_CEILING: usize = 64 * 1024 * 1024;
/// Lectura por pasada (se repite hasta `WouldBlock` o hasta llenar el tope).
const READ_CHUNK: usize = 64 * 1024;

/// Un extremo de pipe adoptado. Como en TCP, entregar el `close` del otro lado NO lo saca del
/// hub: el medio cierre (`pipe_close(x, "write")`) deja escribir la respuesta.
pub(super) struct PipeSlot {
    end: PipeEnd,
    eof_emitted: bool,
}

/// Una conexión TCP saliente en el hub.
pub(super) struct TcpConn {
    stream: mio::net::TcpStream,
    token: Token,
    /// Bytes leídos y no entregados (tope `max_buffer`).
    inbound: VecDeque<Bytes>,
    inbound_len: usize,
    /// Bytes que el programa mandó y el kernel todavía no aceptó (tope `max_buffer`).
    outbound: VecDeque<u8>,
    max_buffer: usize,
    /// El otro lado cerró (lectura en 0). Se entrega UNA vez como `{type: "close"}`.
    eof: bool,
    eof_emitted: bool,
    /// Error de transporte: se entrega una vez como error atrapable y el handle se retira.
    error: Option<String>,
    interest: Option<Interest>,
    sent: u64,
    received: u64,
    peer: String,
}

impl TcpConn {
    fn desired_interest(&self) -> Option<Interest> {
        let read = !self.eof && self.error.is_none() && self.inbound_len < self.max_buffer;
        let write = !self.outbound.is_empty() && self.error.is_none();
        match (read, write) {
            (true, true) => Some(Interest::READABLE | Interest::WRITABLE),
            (true, false) => Some(Interest::READABLE),
            (false, true) => Some(Interest::WRITABLE),
            (false, false) => None,
        }
    }

    fn actionable(&self) -> bool {
        !self.inbound.is_empty() || (self.eof && !self.eof_emitted) || self.error.is_some()
    }
}

impl WsRegistry {
    pub(super) fn tcp_sync_interest(&mut self, h: i64) {
        let Some(c) = self.tcps.get_mut(&h) else { return };
        let want = c.desired_interest();
        if want == c.interest {
            return;
        }
        let token = c.token;
        let r = match (c.interest, want) {
            (None, Some(i)) => self.poll.registry().register(&mut c.stream, token, i),
            (Some(_), Some(i)) => self.poll.registry().reregister(&mut c.stream, token, i),
            (Some(_), None) => self.poll.registry().deregister(&mut c.stream),
            (None, None) => Ok(()),
        };
        if r.is_ok() {
            c.interest = want;
        }
    }

    /// Lee hasta `WouldBlock` (mio avisa por flanco: hay que vaciar) o hasta llenar el tope; con
    /// el tope lleno deja de leer y la ventana TCP frena al otro lado.
    pub(super) fn tcp_drain(&mut self, h: i64) {
        let Some(c) = self.tcps.get_mut(&h) else { return };
        let mut buf = vec![0u8; READ_CHUNK];
        while !c.eof && c.error.is_none() && c.inbound_len < c.max_buffer {
            let want = READ_CHUNK.min(c.max_buffer - c.inbound_len);
            match c.stream.read(&mut buf[..want]) {
                Ok(0) => c.eof = true,
                Ok(n) => {
                    c.inbound.push_back(Bytes::copy_from_slice(&buf[..n]));
                    c.inbound_len += n;
                    c.received += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => c.error = Some(e.to_string()),
            }
        }
        self.tcp_sync_interest(h);
    }

    /// Escribe lo pendiente hasta `WouldBlock`.
    pub(super) fn tcp_flush(&mut self, h: i64) {
        let Some(c) = self.tcps.get_mut(&h) else { return };
        while !c.outbound.is_empty() && c.error.is_none() {
            let (front, _) = c.outbound.as_slices();
            match c.stream.write(front) {
                Ok(0) => {
                    c.error = Some("the connection closed while sending".to_string());
                }
                Ok(n) => {
                    c.outbound.drain(..n);
                    c.sent += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => c.error = Some(e.to_string()),
            }
        }
        self.tcp_sync_interest(h);
    }

    pub(super) fn tcp_on_ready(&mut self, h: i64, readable: bool, writable: bool) {
        if writable {
            self.tcp_flush(h);
        }
        if readable {
            self.tcp_drain(h);
        }
    }

    pub(super) fn tcp_actionable(&self, h: i64) -> bool {
        self.tcps.get(&h).map(|c| c.actionable()).unwrap_or(false)
    }

    /// Próximo evento de una conexión TCP: datos, el cierre (una vez) o el error (terminal).
    pub(super) fn tcp_take(&mut self, h: i64, max: usize) -> Option<Result<SynMap, String>> {
        let c = self.tcps.get_mut(&h)?;
        if !c.inbound.is_empty() {
            let mut out = Vec::with_capacity(max.min(c.inbound_len));
            while out.len() < max {
                let Some(front) = c.inbound.front_mut() else { break };
                let take = (max - out.len()).min(front.len());
                out.extend_from_slice(&front[..take]);
                if take == front.len() {
                    c.inbound.pop_front();
                } else {
                    *front = front.slice(take..);
                }
            }
            c.inbound_len -= out.len();
            let mut m = SynMap::new();
            m.insert("type", syn_text("data"));
            m.insert("data", syn_bytes(out));
            // Se liberó lugar: seguir leyendo lo que el kernel retuvo (por flanco no vuelve a avisar).
            self.tcp_drain(h);
            return Some(Ok(m));
        }
        if let Some(e) = c.error.take() {
            self.tcp_retire(h);
            return Some(Err(e));
        }
        if c.eof && !c.eof_emitted {
            c.eof_emitted = true;
            let done = c.outbound.is_empty();
            let mut m = SynMap::new();
            m.insert("type", syn_text("close"));
            // Cerrado del otro lado y sin nada por mandar: deja de ocupar el hub (y el tope de
            // conexiones). Un `tcp_send` posterior dice que la conexión está cerrada.
            if done {
                self.tcp_retire(h);
            }
            return Some(Ok(m));
        }
        None
    }

    pub(super) fn tcp_retire(&mut self, h: i64) {
        if let Some(mut c) = self.tcps.remove(&h) {
            if c.interest.is_some() {
                let _ = self.poll.registry().deregister(&mut c.stream);
            }
            self.token_to_handle.remove(&c.token.0);
            let _ = c.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    // -- pipes --

    /// Adopta en este hub los extremos de pipe de `targets` que todavía viven en la tabla del
    /// proceso (el primer uso). Un extremo ya adoptado por OTRO hub queda desconocido acá.
    pub(super) fn adopt_pipes(&mut self, targets: &[i64]) {
        for &h in targets {
            if pipe::is_pipe_id(h) && !self.pipes.contains_key(&h) {
                if let Some(end) = pipe::adopt(h) {
                    let w = self.waker.clone();
                    end.set_waker(Some(Arc::new(move || {
                        let _ = w.wake();
                    })));
                    self.pipes.insert(h, PipeSlot { end, eof_emitted: false });
                }
            }
        }
    }

    pub(super) fn pipe_actionable(&self, h: i64) -> bool {
        self.pipes
            .get(&h)
            .map(|p| p.end.readable() && !(p.eof_emitted && p.end.at_eof()))
            .unwrap_or(false)
    }

    pub(super) fn pipe_take(&mut self, h: i64, max: usize) -> Option<SynMap> {
        let p = self.pipes.get_mut(&h)?;
        let mut m = SynMap::new();
        match p.end.try_read(max) {
            ReadOutcome::Data(b) => {
                m.insert("type", syn_text("data"));
                m.insert("data", syn_bytes(b.to_vec()));
            }
            ReadOutcome::Eof if !p.eof_emitted => {
                // El otro lado dejó de escribir: se entrega una vez. El extremo SIGUE (se puede
                // seguir escribiendo la respuesta); se retira con `pipe_close` o al cerrar el hub.
                p.eof_emitted = true;
                m.insert("type", syn_text("close"));
            }
            ReadOutcome::Eof | ReadOutcome::Empty => return None,
        }
        Some(m)
    }

    /// Saca un extremo del hub para que lo use el `proxy to` (lado async). Si este hub no lo
    /// adoptó, se adopta de la tabla del proceso.
    pub(super) fn take_pipe_for_proxy(&mut self, h: i64) -> Option<PipeEnd> {
        match self.pipes.remove(&h) {
            Some(slot) => {
                slot.end.set_waker(None);
                Some(slot.end)
            }
            None => pipe::adopt(h),
        }
    }
}

// =========================================================
// Builtins
// =========================================================

fn bytes_arg(v: Option<&SynValue>, fname: &str) -> Result<Vec<u8>, Control> {
    match v {
        Some(SynValue::Bytes(b)) => Ok(b.to_vec()),
        Some(SynValue::Text(t)) => Ok(t.as_bytes().to_vec()),
        Some(SynValue::Secret(_)) => Err(err(format!(
            "{}: cannot send a secret over a raw connection (reveal() it explicitly if you truly must)",
            fname
        ))),
        Some(other) => Err(err(format!("{}: the data must be bytes or text, got {}", fname, other.type_name()))),
        None => Err(err(format!("{}: missing the data", fname))),
    }
}

fn buffer_opt(opts: Option<&SynValue>, default: usize, ceiling: usize, fname: &str) -> Result<usize, Control> {
    Ok(match opt_map(opts, fname)? {
        Some(m) => opt_usize(&m, "max_buffer", fname)?.map(|n| n.min(ceiling)).unwrap_or(default),
        None => default,
    })
}

fn timeout_opt(opts: Option<&SynValue>, fname: &str) -> Result<Duration, Control> {
    match opt_map(opts, fname)? {
        Some(m) => timeout_arg(m.get("timeout"), fname),
        None => timeout_arg(None, fname),
    }
}

fn tcp_handle(reg: &Registry, v: Option<&SynValue>, fname: &str) -> Result<i64, Control> {
    let h = conn_handle(v.ok_or_else(|| err(format!("{}: missing the connection handle", fname)))?, fname)?;
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Tcp) => Ok(h),
        Some(k) => Err(err(format!("{}: handle {} is {}, not a TCP connection", fname, h, k.noun()))),
        None => Err(err(format!("{}: unknown or closed TCP connection {}", fname, h))),
    }
}

fn pipe_handle(reg: &Registry, v: Option<&SynValue>, fname: &str) -> Result<i64, Control> {
    let h = conn_handle(v.ok_or_else(|| err(format!("{}: missing the pipe end", fname)))?, fname)?;
    reg.borrow_mut().adopt_pipes(&[h]);
    match reg.borrow().kind_of(h) {
        Some(HandleKind::Pipe) => Ok(h),
        Some(k) => Err(err(format!("{}: handle {} is {}, not a pipe end", fname, h, k.noun()))),
        None if pipe::is_pipe_id(h) => Err(err(format!(
            "{}: pipe end {} is closed or belongs to another interpreter (an end is used by the first one that touches it)",
            fname, h
        ))),
        None => Err(err(format!("{}: unknown pipe end {}", fname, h))),
    }
}

/// `tcp_connect(host, port, opts?)` → handle. `opts`: `{"timeout" (connect, s), "max_buffer"}`.
pub(super) fn tcp_connect(i: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "tcp_connect";
    let host = match args.first() {
        Some(SynValue::Text(t)) if !t.is_empty() => t.to_string(),
        Some(other) => return Err(err(format!("{}: the host must be text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the host", F))),
    };
    let port = match args.get(1) {
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(p) if (1..=65535).contains(&p) && n.is_integer() => p as u16,
            _ => return Err(err(format!("{}: the port must be an integer from 1 to 65535", F))),
        },
        Some(other) => return Err(err(format!("{}: the port must be a number, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the port", F))),
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    // El scope lleva SIEMPRE el puerto: un grant con puerto cubre sólo ese puerto.
    let scope = if bare.contains(':') { format!("[{}]:{}", bare, port) } else { format!("{}:{}", bare, port) };
    reg.borrow()
        .caps
        .borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(scope.clone())), "tcp_connect()")
        .map_err(|v| Control::Error(v.into_error()))?;
    let timeout = timeout_opt(args.get(2), F)?;
    let max_buffer = buffer_opt(args.get(2), DEFAULT_TCP_BUFFER, TCP_BUFFER_CEILING, F)?;
    {
        let r = reg.borrow();
        if r.conns.len() + r.tcps.len() >= r.max_conns {
            return Err(err(format!("{}: too many open connections in this interpreter ({})", F, r.max_conns)));
        }
    }
    i.check_cancel()?;
    let std_stream = {
        let _w = synsema_core::waiting::waiting();
        // La resolución de nombres de la std no tiene timeout: corre en un hilo y se espera con
        // el mismo plazo que la conexión (un DNS colgado no cuelga el programa).
        let (tx, rx) = std::sync::mpsc::channel();
        let (b2, p2) = (bare.clone(), port);
        std::thread::spawn(move || {
            let _ = tx.send((b2.as_str(), p2).to_socket_addrs().map(|a| a.collect::<Vec<_>>()));
        });
        let addrs: Vec<std::net::SocketAddr> = match rx.recv_timeout(timeout.max(Duration::from_millis(1))) {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => return Err(err(format!("{}: cannot resolve {}: {}", F, bare, e))),
            Err(_) => return Err(err(format!("{}: resolving {} timed out", F, bare))),
        };
        let mut last = None;
        let mut found = None;
        for a in addrs {
            match std::net::TcpStream::connect_timeout(&a, timeout.max(Duration::from_millis(1))) {
                Ok(s) => {
                    found = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        match found {
            Some(s) => s,
            None => {
                return Err(err(format!(
                    "{}: cannot connect to {}: {}",
                    F,
                    scope,
                    last.map(|e| e.to_string()).unwrap_or_else(|| "no address".to_string())
                )))
            }
        }
    };
    // Un timeout que llega mientras conectaba no deja una conexión viva sin handle.
    i.check_cancel()?;
    let _ = std_stream.set_nodelay(true);
    std_stream
        .set_nonblocking(true)
        .map_err(|e| err(format!("{}: {}", F, e)))?;
    let stream = mio::net::TcpStream::from_std(std_stream);
    let mut r = reg.borrow_mut();
    r.next_id += 1;
    r.next_token += 1;
    let h = r.next_id;
    let token = Token(r.next_token);
    r.token_to_handle.insert(token.0, h);
    r.tcps.insert(
        h,
        TcpConn {
            stream,
            token,
            inbound: VecDeque::new(),
            inbound_len: 0,
            outbound: VecDeque::new(),
            max_buffer,
            eof: false,
            eof_emitted: false,
            error: None,
            interest: None,
            sent: 0,
            received: 0,
            peer: scope,
        },
    );
    r.tcp_sync_interest(h);
    Ok(syn_int(h))
}

/// `tcp_send(h, data, timeout?)`: encola y escribe; con el kernel y el buffer llenos espera (de
/// forma cancelable) a que el otro lado lea, o falla al vencer el timeout. Nunca cola sin tope.
pub(super) fn tcp_send(i: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "tcp_send";
    let h = tcp_handle(reg, args.first(), F)?;
    let data = bytes_arg(args.get(1), F)?;
    let deadline = Instant::now() + timeout_arg(args.get(2), F)?;
    watch_cancel(reg, i);
    let mut off = 0;
    let mut _w = None;
    loop {
        {
            let mut r = reg.borrow_mut();
            let c = r.tcps.get_mut(&h).ok_or_else(|| err(format!("{}: connection {} closed", F, h)))?;
            if let Some(e) = c.error.clone() {
                r.tcp_retire(h);
                return Err(err(format!("{}: connection {}: {}", F, h, e)));
            }
            let room = c.max_buffer.saturating_sub(c.outbound.len());
            let n = room.min(data.len() - off);
            c.outbound.extend(&data[off..off + n]);
            off += n;
            r.tcp_flush(h);
        }
        if off == data.len() {
            return Ok(SynValue::Nothing);
        }
        i.check_cancel()?;
        let now = Instant::now();
        if now >= deadline {
            return Err(err(format!(
                "{}: the peer of connection {} is not reading ({} of {} bytes sent before the timeout)",
                F, h, off, data.len()
            )));
        }
        if _w.is_none() {
            _w = Some(synsema_core::waiting::waiting());
        }
        reg.borrow_mut().poll_process((deadline - now).min(Duration::from_millis(250)));
    }
}

/// Espera un evento de UN handle (`tcp_recv`/`pipe_recv`): el mismo núcleo que `select`.
fn recv_one(i: &mut Interpreter, args: &[SynValue], reg: &Registry, h: i64, fname: &str) -> Result<SynValue, Control> {
    let timeout = timeout_arg(args.get(1), fname)?;
    select_on(i, reg, &[h], &None, timeout, fname)
}

pub(super) fn tcp_recv(i: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    let h = tcp_handle(reg, args.first(), "tcp_recv")?;
    recv_one(i, args, reg, h, "tcp_recv")
}

pub(super) fn tcp_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    let h = conn_handle(args.first().ok_or_else(|| err("tcp_close: missing the connection handle"))?, "tcp_close")?;
    let mut r = reg.borrow_mut();
    if r.tcps.contains_key(&h) {
        // Lo encolado sale si el kernel lo acepta ya; cerrar no espera a un peer que no lee.
        r.tcp_flush(h);
        r.tcp_retire(h);
    }
    Ok(SynValue::Nothing)
}

pub(super) fn tcp_stats(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    let h = tcp_handle(reg, args.first(), "tcp_stats")?;
    let r = reg.borrow();
    let c = r.tcps.get(&h).ok_or_else(|| err("tcp_stats: connection closed"))?;
    let mut m = SynMap::new();
    m.insert("peer", syn_text(c.peer.clone()));
    m.insert("sent", syn_int(c.sent as i64));
    m.insert("received", syn_int(c.received as i64));
    m.insert("queued_in", syn_int(c.inbound_len as i64));
    m.insert("queued_out", syn_int(c.outbound.len() as i64));
    m.insert("status", syn_text(if c.eof { "closing" } else { "open" }));
    Ok(syn_map(m))
}

/// `pipe(opts?)` → `{a, b}`: dos extremos conectados. `opts`: `{"max_buffer"}` por dirección.
pub(super) fn pipe_create(args: &[SynValue], _reg: &Registry) -> Result<SynValue, Control> {
    let cap = buffer_opt(args.first(), pipe::DEFAULT_MAX_BUFFER, pipe::MAX_BUFFER_CEILING, "pipe")?;
    let (a, b) = pipe::create(cap).map_err(|e| err(e))?;
    let mut m = SynMap::new();
    m.insert("a", syn_int(a));
    m.insert("b", syn_int(b));
    Ok(syn_map(m))
}

pub(super) fn pipe_send(i: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    const F: &str = "pipe_send";
    let h = pipe_handle(reg, args.first(), F)?;
    let data = bytes_arg(args.get(1), F)?;
    let deadline = Instant::now() + timeout_arg(args.get(2), F)?;
    watch_cancel(reg, i);
    let mut off = 0;
    let mut _w = None;
    while off < data.len() {
        let res = {
            let r = reg.borrow();
            let p = r.pipes.get(&h).ok_or_else(|| err(format!("{}: pipe end {} closed", F, h)))?;
            p.end.try_write(&data[off..])
        };
        match res {
            Ok(n) => off += n,
            Err(WriteError::Closed) => {
                reg.borrow_mut().pipes.remove(&h);
                return Err(err(format!("{}: the other end of pipe {} is closed", F, h)));
            }
            Err(WriteError::Full) => {
                i.check_cancel()?;
                let now = Instant::now();
                if now >= deadline {
                    return Err(err(format!(
                        "{}: the other end of pipe {} is not reading ({} of {} bytes sent before the timeout)",
                        F, h, off, data.len()
                    )));
                }
                if _w.is_none() {
                    _w = Some(synsema_core::waiting::waiting());
                }
                // Lo despierta el otro extremo al leer (libera lugar).
                reg.borrow_mut().poll_process((deadline - now).min(Duration::from_millis(250)));
            }
        }
    }
    Ok(SynValue::Nothing)
}

pub(super) fn pipe_recv(i: &mut Interpreter, args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    let h = pipe_handle(reg, args.first(), "pipe_recv")?;
    recv_one(i, args, reg, h, "pipe_recv")
}

/// `pipe_close(h)` cierra los dos sentidos; `pipe_close(h, "write")` sólo deja de escribir (el
/// otro lado ve `close` después de lo que ya mandó; se puede seguir leyendo).
pub(super) fn pipe_close(args: &[SynValue], reg: &Registry) -> Result<SynValue, Control> {
    let h = conn_handle(args.first().ok_or_else(|| err("pipe_close: missing the pipe end"))?, "pipe_close")?;
    let write_only = match args.get(1) {
        None | Some(SynValue::Nothing) => false,
        Some(SynValue::Text(t)) if t.as_ref() == "write" => true,
        Some(_) => return Err(err("pipe_close: the second argument can only be \"write\" (close the sending side)")),
    };
    let mut r = reg.borrow_mut();
    r.adopt_pipes(&[h]);
    if write_only {
        if let Some(p) = r.pipes.get(&h) {
            p.end.close_write();
        }
    } else if r.pipes.remove(&h).is_none() {
        pipe::close_unadopted(h);
    }
    Ok(SynValue::Nothing)
}

/// El extremo de un pipe para `proxy to` (lo llama el serve desde el worker que evaluó el destino).
pub fn take_pipe_for_proxy(interp: &Interpreter, h: i64) -> Option<PipeEnd> {
    match hub_of(interp) {
        Some(reg) => reg.borrow_mut().take_pipe_for_proxy(h),
        None => pipe::adopt(h),
    }
}
