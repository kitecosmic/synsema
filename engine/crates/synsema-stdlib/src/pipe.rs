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
/// Un extremo que nadie adoptó y que lleva este tiempo sin actividad (ni del otro extremo) se
/// cierra (el túnel se cayó, el puente no arrancó): un pipe abandonado no retiene memoria ni un
/// lugar de la tabla para siempre. Cuenta desde la última lectura/escritura del par, no desde la
/// creación: un extremo que espera a su dueño mientras el otro trabaja no se barre.
const UNADOPTED_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Extremos sin adoptar que creó UN intérprete (un hub): un programa (o un ataque a sus rutas)
/// no llena la tabla del proceso por su cuenta.
const MAX_UNADOPTED_PER_HUB: usize = 4096;
/// Cada cuánto se barre la tabla en segundo plano (sin esperar a que alguien cree o adopte).
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

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
    /// Última actividad del par (ms desde `epoch()`): la creación, una lectura, una escritura
    /// o un cierre de cualquiera de los dos extremos.
    last: AtomicU64,
}

fn epoch() -> std::time::Instant {
    static E: OnceLock<std::time::Instant> = OnceLock::new();
    *E.get_or_init(std::time::Instant::now)
}

fn now_ms() -> u64 {
    epoch().elapsed().as_millis() as u64
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
    fn touch(&self) {
        self.last.store(now_ms(), Ordering::Relaxed);
    }

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
        last: AtomicU64::new(now_ms()),
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
        self.shared.touch();
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
        self.shared.touch();
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
        self.shared.touch();
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
        self.shared.touch();
        self.shared.wake(1 - self.side);
    }

    /// ¿Pasó `ttl` sin actividad en el par?
    fn idle_for(&self, ttl: std::time::Duration) -> bool {
        now_ms().saturating_sub(self.shared.last.load(Ordering::Relaxed)) >= ttl.as_millis() as u64
    }

    /// ¿Ya no queda nada por leer y el otro lado dejó de escribir? (EOF).
    pub fn at_eof(&self) -> bool {
        self.shared.dirs[1 - self.side].lock().map(|d| d.len == 0 && d.writer_closed).unwrap_or(true)
    }

    /// ¿Hay bytes esperando a que este extremo los lea?
    fn has_unread(&self) -> bool {
        self.shared.dirs[1 - self.side].lock().map(|d| d.len > 0).unwrap_or(false)
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

/// Los extremos sin adoptar (con el hub que los creó) y cuántos tiene cada hub.
#[derive(Default)]
struct Table {
    ends: HashMap<u64, (PipeEnd, usize)>,
    per_hub: HashMap<usize, usize>,
}

impl Table {
    fn take(&mut self, id: u64) -> Option<PipeEnd> {
        let (end, hub) = self.ends.remove(&id)?;
        if let Some(n) = self.per_hub.get_mut(&hub) {
            *n -= 1;
            if *n == 0 {
                self.per_hub.remove(&hub);
            }
        }
        Some(end)
    }

    /// Saca los extremos que ya no va a usar nadie: los que llevan `ttl` sin actividad en el
    /// par, y los que tienen el par cerrado y nada por leer. Soltarlos los cierra.
    fn sweep(&mut self, ttl: std::time::Duration) {
        let dead: Vec<u64> = self
            .ends
            .iter()
            .filter(|(_, (e, _))| e.idle_for(ttl) || (e.peer_gone() && !e.has_unread()))
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            self.take(id);
        }
    }
}

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(|| {
        // Barrido periódico: sin él, sólo se barría al crear o adoptar, y sin actividad ajena la
        // tabla no soltaba nada.
        let _ = std::thread::Builder::new().name("pipe-sweep".to_string()).spawn(|| loop {
            std::thread::sleep(SWEEP_EVERY);
            if let Some(t) = TABLE_READY.get() {
                if let Ok(mut t) = t.lock() {
                    t.sweep(UNADOPTED_TTL);
                }
            }
        });
        Mutex::new(Table::default())
    })
}

/// La tabla, para el hilo de barrido (que arranca dentro de `get_or_init` y no puede volver a
/// entrar ahí).
static TABLE_READY: OnceLock<&'static Mutex<Table>> = OnceLock::new();

fn the_table() -> &'static Mutex<Table> {
    let t = table();
    let _ = TABLE_READY.set(t);
    t
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Un id nuevo, aleatorio (≥ 2^40, < 2^62): un extremo no se adopta adivinando su número.
fn fresh_id(t: &Table) -> u64 {
    use std::hash::BuildHasher;
    loop {
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let r = std::collections::hash_map::RandomState::new().hash_one(n);
        let id = (r >> 2) | FIRST_PIPE_ID;
        if !t.ends.contains_key(&id) {
            return id;
        }
    }
}

/// ¿Este número es un handle de pipe (por su rango)?
pub fn is_pipe_id(h: i64) -> bool {
    h >= FIRST_PIPE_ID as i64
}

/// Crea un pipe y deja los dos extremos sin adoptar, a cuenta del hub `hub` (un número que
/// identifica al intérprete que lo crea). Devuelve sus handles.
pub fn create(cap: usize, hub: usize) -> Result<(i64, i64), String> {
    let (a, b) = pair(cap);
    let mut t = the_table().lock().map_err(|_| "pipe(): internal lock poisoned".to_string())?;
    t.sweep(UNADOPTED_TTL);
    let mine = t.per_hub.get(&hub).copied().unwrap_or(0);
    if mine + 2 > MAX_UNADOPTED_PER_HUB {
        return Err(format!(
            "pipe(): this program has {} pipe ends waiting to be used; use or close them (pipe_close) before creating more",
            mine
        ));
    }
    if t.ends.len() + 2 > MAX_UNADOPTED {
        return Err(format!(
            "pipe(): {} pipe ends are waiting to be used; use or close them (pipe_close) before creating more",
            t.ends.len()
        ));
    }
    let ia = fresh_id(&t);
    t.ends.insert(ia, (a, hub));
    let ib = fresh_id(&t);
    t.ends.insert(ib, (b, hub));
    *t.per_hub.entry(hub).or_insert(0) += 2;
    Ok((ia as i64, ib as i64))
}

/// Adopta un extremo: lo saca de la tabla del proceso (`None` si no existe o ya lo adoptó otro).
pub fn adopt(h: i64) -> Option<PipeEnd> {
    if !is_pipe_id(h) {
        return None;
    }
    let mut t = the_table().lock().ok()?;
    let end = t.take(h as u64);
    t.sweep(UNADOPTED_TTL);
    end
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
        let (ha, hb) = create(16, 1).unwrap();
        assert!(is_pipe_id(ha) && is_pipe_id(hb) && ha != hb);
        assert!(hb != ha + 1, "ids aleatorios, no consecutivos");
        let a = adopt(ha).expect("primera adopción");
        assert!(adopt(ha).is_none(), "un extremo adoptado no se adopta de nuevo");
        assert!(close_unadopted(hb));
        assert_eq!(a.try_write(b"x"), Err(WriteError::Closed), "el otro extremo cerró");
        assert!(!is_pipe_id(7));
    }

    /// Auditoría B3: un extremo que nadie adoptó y cuyo par ya cerró se suelta al crear otro
    /// pipe (antes el predicado del barrido era siempre verdadero y la tabla sólo crecía).
    #[test]
    fn an_abandoned_end_is_swept() {
        let (ha, hb) = create(16, 1).unwrap();
        let mut a = adopt(ha).unwrap();
        a.close();
        drop(a);
        let _ = create(16, 1).unwrap();
        assert!(adopt(hb).is_none(), "el extremo abandonado quedó en la tabla");
    }

    /// Auditoría ronda 2 (R6): el TTL cuenta desde la última actividad del par. Un extremo sin
    /// adoptar cuyo par sigue escribiendo no se barre; uno quieto, sí. Y uno con datos sin leer
    /// cuyo par ya cerró sobrevive (el dueño puede llegar y leerlos).
    #[test]
    fn the_ttl_counts_from_the_last_activity_and_unread_data_survives() {
        let mut t = Table::default();
        let ttl = std::time::Duration::from_millis(150);
        let (busy_a, busy_b) = pair(64);
        let (idle_a, _idle_b) = pair(64);
        let (mut gone_a, data_b) = pair(64);
        gone_a.try_write(b"para despues").unwrap();
        gone_a.close();
        t.ends.insert(1, (busy_b, 7));
        t.ends.insert(2, (idle_a, 7));
        t.ends.insert(3, (data_b, 7));
        t.per_hub.insert(7, 3);
        for _ in 0..4 {
            std::thread::sleep(std::time::Duration::from_millis(60));
            busy_a.try_write(b"x").unwrap(); // el par trabaja: el extremo sin adoptar sigue vivo
            t.sweep(ttl);
        }
        assert!(t.ends.contains_key(&1), "el par tuvo actividad");
        assert!(!t.ends.contains_key(&2), "sin actividad en el TTL se barre");
        assert!(!t.ends.contains_key(&3), "con datos y sin actividad en el TTL también");
        assert_eq!(t.per_hub.get(&7), Some(&1));
        // Dentro del TTL, el extremo con datos de un par cerrado sigue y se lee entero.
        let (mut w, r) = pair(64);
        w.try_write(b"hola").unwrap();
        w.close();
        t.ends.insert(4, (r, 8));
        t.sweep(ttl);
        let r = t.take(4).expect("los datos sin leer lo mantienen");
        assert_eq!(r.try_read(10), ReadOutcome::Data(Bytes::from_static(b"hola")));
        assert_eq!(r.try_read(10), ReadOutcome::Eof);
    }

    #[test]
    fn one_hub_cannot_fill_the_process_table() {
        let hub = 0xDEAD_0000usize;
        let mut made = Vec::new();
        let e = loop {
            match create(16, hub) {
                Ok(p) => made.push(p),
                Err(e) => break e,
            }
        };
        assert!(e.contains("this program"), "{}", e);
        assert_eq!(made.len() * 2, MAX_UNADOPTED_PER_HUB);
        // Otro hub sigue pudiendo.
        let (x, y) = create(16, hub + 1).unwrap();
        for (a, b) in made {
            close_unadopted(a);
            close_unadopted(b);
        }
        close_unadopted(x);
        close_unadopted(y);
        assert!(create(16, hub).is_ok(), "al usarlos o cerrarlos se libera el lugar");
    }
}
