//! v0.6.42 — `pipe()`: dos extremos de bytes conectados en memoria, con tope por dirección.
//!
//! Es el `io.Pipe`/`net.Pipe` de Go: lo que se escribe en un extremo se lee en el otro, en orden,
//! y un lector que no lee frena al que escribe (el buffer de cada dirección tiene tope; lleno, el
//! escritor espera). Sirve para tests, para proxys sobre cualquier transporte y, sobre todo, para
//! que `proxy to` hable HTTP con un servicio que está del otro lado de un túnel que el programa
//! maneja (spec v0.6.42 §1 T2/T3).
//!
//! Un extremo tiene que poder CRUZAR de intérprete (en un edge, el `proxy to` corre en un worker y
//! el multiplexado del túnel en la ruta `socket`, que es otro intérprete con otro hub). Por eso un
//! extremo recién creado vive en una tabla del PROCESO y su handle es un número único en todo el
//! proceso: el primer hub que lo usa lo ADOPTA (lo saca de la tabla) y desde ahí es suyo. Un
//! extremo adoptado no se puede usar desde otro hub. Viaja por `bus`/`blackboard` como cualquier
//! número.
//!
//! Cada extremo tiene un despertador: lo instala quien lo usa (el `mio::Waker` del hub, o el
//! `Waker` de la tarea async de hyper) y lo llama el otro extremo cuando escribe, lee (libera
//! lugar) o cierra. Nada hace polling.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;

/// Tope por dirección si el programa no pide otro: 1 MiB.
pub const DEFAULT_MAX_BUFFER: usize = 1024 * 1024;
/// Techo del tope configurable: 64 MiB.
pub const MAX_BUFFER_CEILING: usize = 64 * 1024 * 1024;
/// Extremos sin adoptar que el proceso tolera a la vez (cada uno es memoria acotada, pero un
/// bucle que crea pipes y los tira no puede crecer sin fin).
const MAX_UNADOPTED: usize = 65_536;
/// Los handles de pipe viven en su propio rango, lejos de los ids por-hub (que empiezan en 1).
const FIRST_PIPE_ID: u64 = 1 << 40;

/// Despertador de un extremo (lo llama el otro lado).
pub type WakeFn = Arc<dyn Fn() + Send + Sync>;

struct Dir {
    chunks: VecDeque<Bytes>,
    len: usize,
    /// El que escribe en esta dirección cerró (el lector verá EOF al vaciar).
    writer_closed: bool,
    /// El que lee esta dirección cerró (escribir es BrokenPipe).
    reader_closed: bool,
}

struct Shared {
    cap: usize,
    /// `dirs[0]`: a → b; `dirs[1]`: b → a.
    dirs: [Mutex<Dir>; 2],
    /// Despertador de cada lado (`wakers[0]` = el de a).
    wakers: [Mutex<Option<WakeFn>>; 2],
}

/// Un extremo. `side` 0 = a, 1 = b: escribe en `dirs[side]` y lee de `dirs[1 - side]`.
pub struct PipeEnd {
    shared: Arc<Shared>,
    side: usize,
    closed: bool,
}

/// Lo que dio una lectura no bloqueante.
#[derive(Debug, PartialEq)]
pub enum ReadOutcome {
    Data(Bytes),
    /// Nada todavía (el otro lado sigue abierto).
    Empty,
    /// El otro lado cerró y no queda nada por leer.
    Eof,
}

/// Por qué no se pudo escribir.
#[derive(Debug, PartialEq)]
pub enum WriteError {
    /// El buffer de esta dirección está lleno: esperar a que el otro lado lea.
    Full,
    /// El otro lado cerró: nadie va a leer.
    Closed,
}

impl Shared {
    fn wake(&self, side: usize) {
        let w = self.wakers[side].lock().ok().and_then(|g| g.clone());
        if let Some(f) = w {
            f();
        }
    }
}

/// Crea los dos extremos conectados, con `cap` bytes de tope por dirección.
pub fn pair(cap: usize) -> (PipeEnd, PipeEnd) {
    let dir = || Mutex::new(Dir { chunks: VecDeque::new(), len: 0, writer_closed: false, reader_closed: false });
    let shared = Arc::new(Shared {
        cap: cap.clamp(1, MAX_BUFFER_CEILING),
        dirs: [dir(), dir()],
        wakers: [Mutex::new(None), Mutex::new(None)],
    });
    (
        PipeEnd { shared: shared.clone(), side: 0, closed: false },
        PipeEnd { shared, side: 1, closed: false },
    )
}

impl PipeEnd {
    /// Instala (o quita) el despertador de este extremo.
    pub fn set_waker(&self, w: Option<WakeFn>) {
        if let Ok(mut g) = self.shared.wakers[self.side].lock() {
            *g = w;
        }
    }

    /// Escribe lo que entre (hasta llenar el tope). `Ok(n)` con `n ≥ 1`; `Full` si no entra nada.
    pub fn try_write(&self, data: &[u8]) -> Result<usize, WriteError> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = {
            let mut d = self.shared.dirs[self.side].lock().map_err(|_| WriteError::Closed)?;
            if d.reader_closed || d.writer_closed {
                return Err(WriteError::Closed);
            }
            let room = self.shared.cap.saturating_sub(d.len);
            if room == 0 {
                return Err(WriteError::Full);
            }
            let n = room.min(data.len());
            d.chunks.push_back(Bytes::copy_from_slice(&data[..n]));
            d.len += n;
            n
        };
        self.shared.wake(1 - self.side);
        Ok(n)
    }

    /// Lee hasta `max` bytes sin bloquear.
    pub fn try_read(&self, max: usize) -> ReadOutcome {
        let out = {
            let Ok(mut d) = self.shared.dirs[1 - self.side].lock() else { return ReadOutcome::Eof };
            if d.len == 0 {
                return if d.writer_closed { ReadOutcome::Eof } else { ReadOutcome::Empty };
            }
            let mut out = Vec::with_capacity(max.min(d.len));
            while out.len() < max {
                let Some(front) = d.chunks.front_mut() else { break };
                let take = (max - out.len()).min(front.len());
                out.extend_from_slice(&front[..take]);
                if take == front.len() {
                    d.chunks.pop_front();
                } else {
                    *front = front.slice(take..);
                }
            }
            d.len -= out.len();
            Bytes::from(out)
        };
        // Se liberó lugar: el escritor del otro lado puede seguir.
        self.shared.wake(1 - self.side);
        ReadOutcome::Data(out)
    }

    /// ¿Hay algo para entregar (datos o el EOF)?
    pub fn readable(&self) -> bool {
        match self.shared.dirs[1 - self.side].lock() {
            Ok(d) => d.len > 0 || d.writer_closed,
            Err(_) => true,
        }
    }

    /// Bytes esperando a que este extremo los lea, y bytes que escribió y el otro no leyó.
    pub fn queued(&self) -> (usize, usize) {
        let inbound = self.shared.dirs[1 - self.side].lock().map(|d| d.len).unwrap_or(0);
        let outbound = self.shared.dirs[self.side].lock().map(|d| d.len).unwrap_or(0);
        (inbound, outbound)
    }

    /// Deja de escribir (el otro lado verá EOF después de lo que ya está en el buffer); se puede
    /// seguir leyendo. Es el `shutdown(SHUT_WR)` de un socket.
    pub fn close_write(&self) {
        if let Ok(mut d) = self.shared.dirs[self.side].lock() {
            d.writer_closed = true;
        }
        self.shared.wake(1 - self.side);
    }

    /// Cierra los dos sentidos. Idempotente; también lo hace `Drop`.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.set_waker(None);
        if let Ok(mut d) = self.shared.dirs[self.side].lock() {
            d.writer_closed = true;
        }
        if let Ok(mut d) = self.shared.dirs[1 - self.side].lock() {
            d.reader_closed = true;
            // Lo que nadie va a leer se suelta ya: memoria acotada también al cerrar.
            d.chunks.clear();
            d.len = 0;
        }
        self.shared.wake(1 - self.side);
    }

    /// ¿El otro extremo ya cerró del todo (ni lee ni escribe)?
    fn peer_gone(&self) -> bool {
        let peer_reader = self.shared.dirs[self.side].lock().map(|d| d.reader_closed).unwrap_or(true);
        let peer_writer = self.shared.dirs[1 - self.side].lock().map(|d| d.writer_closed).unwrap_or(true);
        peer_reader && peer_writer
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        self.close();
    }
}

// =========================================================
// La tabla del proceso: extremos sin adoptar
// =========================================================

fn table() -> &'static Mutex<HashMap<u64, PipeEnd>> {
    static T: OnceLock<Mutex<HashMap<u64, PipeEnd>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(FIRST_PIPE_ID);

/// ¿Este número es un handle de pipe (por su rango)?
pub fn is_pipe_id(h: i64) -> bool {
    h >= FIRST_PIPE_ID as i64
}

/// Crea un pipe y deja los dos extremos sin adoptar. Devuelve sus handles.
pub fn create(cap: usize) -> Result<(i64, i64), String> {
    let (a, b) = pair(cap);
    let mut t = table().lock().map_err(|_| "pipe(): internal lock poisoned".to_string())?;
    if t.len() + 2 > MAX_UNADOPTED {
        // Antes de negarse, soltar los extremos cuyo par ya no existe (nadie los va a usar).
        t.retain(|_, e| !e.peer_gone() || e.readable());
        if t.len() + 2 > MAX_UNADOPTED {
            return Err(format!(
                "pipe(): {} pipe ends are waiting to be used; use or close them (pipe_close) before creating more",
                t.len()
            ));
        }
    }
    let ia = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let ib = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    t.insert(ia, a);
    t.insert(ib, b);
    Ok((ia as i64, ib as i64))
}

/// Adopta un extremo: lo saca de la tabla del proceso (`None` si no existe o ya lo adoptó otro).
pub fn adopt(h: i64) -> Option<PipeEnd> {
    if !is_pipe_id(h) {
        return None;
    }
    table().lock().ok()?.remove(&(h as u64))
}

/// Cierra un extremo que nadie adoptó todavía (`pipe_close` sobre un handle que este hub no tiene).
pub fn close_unadopted(h: i64) -> bool {
    match adopt(h) {
        Some(mut e) => {
            e.close();
            true
        }
        None => false,
    }
}

// =========================================================
// Lado async (hyper): `proxy to` sobre un extremo
// =========================================================

/// Un extremo como `AsyncRead + AsyncWrite` de tokio (para `TokioIo` y el cliente de hyper).
pub struct PipeIo {
    end: PipeEnd,
}

impl PipeIo {
    pub fn new(end: PipeEnd) -> Self {
        PipeIo { end }
    }
}

fn task_waker(cx: &std::task::Context<'_>) -> WakeFn {
    let w = cx.waker().clone();
    Arc::new(move || w.wake_by_ref())
}

impl tokio::io::AsyncRead for PipeIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let max = buf.remaining();
        if max == 0 {
            return Poll::Ready(Ok(()));
        }
        for attempt in 0..2 {
            match self.end.try_read(max) {
                ReadOutcome::Data(b) => {
                    buf.put_slice(&b);
                    return Poll::Ready(Ok(()));
                }
                ReadOutcome::Eof => return Poll::Ready(Ok(())),
                ReadOutcome::Empty if attempt == 0 => {
                    // Instalar el despertador y volver a mirar: si el otro lado escribió entre
                    // la lectura y la instalación, el segundo intento lo ve (sin despertares perdidos).
                    self.end.set_waker(Some(task_waker(cx)));
                }
                ReadOutcome::Empty => {}
            }
        }
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for PipeIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        for attempt in 0..2 {
            match self.end.try_write(data) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(WriteError::Closed) => {
                    return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
                }
                Err(WriteError::Full) if attempt == 0 => self.end.set_waker(Some(task_waker(cx))),
                Err(WriteError::Full) => {}
            }
        }
        Poll::Pending
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.end.close_write();
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_flow_in_order_both_ways() {
        let (a, b) = pair(16);
        assert_eq!(a.try_write(b"hola"), Ok(4));
        assert_eq!(a.try_write(b" mundo"), Ok(6));
        assert_eq!(b.try_read(3), ReadOutcome::Data(Bytes::from_static(b"hol")));
        assert_eq!(b.try_read(100), ReadOutcome::Data(Bytes::from_static(b"a mundo")));
        assert_eq!(b.try_read(100), ReadOutcome::Empty);
        assert_eq!(b.try_write(b"ok"), Ok(2));
        assert_eq!(a.try_read(100), ReadOutcome::Data(Bytes::from_static(b"ok")));
    }

    #[test]
    fn a_full_direction_pushes_back_and_reading_makes_room() {
        let (a, b) = pair(4);
        assert_eq!(a.try_write(b"123456"), Ok(4), "sólo entra hasta el tope");
        assert_eq!(a.try_write(b"x"), Err(WriteError::Full));
        assert_eq!(b.try_read(2), ReadOutcome::Data(Bytes::from_static(b"12")));
        assert_eq!(a.try_write(b"xyz"), Ok(2));
        assert_eq!(a.queued(), (0, 4));
    }

    #[test]
    fn closing_gives_eof_after_the_buffer_and_broken_pipe_to_the_writer() {
        let (mut a, b) = pair(16);
        a.try_write(b"fin").unwrap();
        a.close_write();
        assert_eq!(b.try_read(10), ReadOutcome::Data(Bytes::from_static(b"fin")));
        assert_eq!(b.try_read(10), ReadOutcome::Eof);
        a.close();
        assert_eq!(b.try_write(b"x"), Err(WriteError::Closed));
    }

    #[test]
    fn the_peer_waker_fires_on_write_read_and_close() {
        let (a, mut b) = pair(4);
        let hits = Arc::new(AtomicU64::new(0));
        let h = hits.clone();
        a.set_waker(Some(Arc::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        })));
        b.try_write(b"x").unwrap(); // escribe hacia a
        a.try_write(b"yy").unwrap();
        b.try_read(1); // libera lugar de a
        b.close();
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn ends_are_adopted_once_from_the_process_table() {
        let (ha, hb) = create(16).unwrap();
        assert!(is_pipe_id(ha) && is_pipe_id(hb) && ha != hb);
        let a = adopt(ha).expect("primera adopción");
        assert!(adopt(ha).is_none(), "un extremo adoptado no se adopta de nuevo");
        assert!(close_unadopted(hb));
        assert_eq!(a.try_write(b"x"), Err(WriteError::Closed), "el otro extremo cerró");
        assert!(!is_pipe_id(7));
    }
}
