//! v0.6.46 (E6) — el registro de la corrida para el recibo sellado.
//!
//! Sin auditor no existe: [`active`] es un atómico en cero y nada de esto corre. Con auditor (el host
//! lo instala: `--auditor`, `SYNSEMA_AUDITOR_KEY`, `RunOptions.auditor`), cada entrada que hoy sale
//! en el audit (`public`) y cada una que hoy se descarta o se rechaza porque nació en una rama
//! decidida por un valor privado (`sealed`) queda acá, en orden, con su número de secuencia. El
//! recibo (`synsema-stdlib/src/sealed.rs`) encadena las dos en ese orden y cifra las selladas para el
//! auditor en un sobre de tamaño fijo.
//!
//! Vive en core porque lo escriben tres crates: capabilities (`push_audit`), stdlib (el audit de
//! `sign`/`reveal`/wallet) y core (el linaje, en `record_input`). Las funciones que escriben son
//! `#[cold] #[inline(never)]` (fila "código sólo de serve/attest" de `donde-nace-cada-cosa.md`).
//!
//! **De quién es el registro:** uno por proceso para el CLI y el wasm (una corrida por proceso, y los
//! hilos de los agentes que lanza lo ven igual), y uno por hilo bajo `serve`, donde cada request es su
//! propia corrida: el del hilo gana sobre el del proceso.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Lo que se reserva del texto plano del sobre para el envoltorio (semilla, reloj, `truncated`) antes
/// de cortar las entradas.
pub const ENVELOPE_RESERVE: usize = 1024;

/// El registro de una corrida.
#[derive(Debug, Default)]
pub struct RunLog {
    /// Único en el proceso: el generador de `random()` de un hilo sabe si es de ESTA corrida (un hilo
    /// de `serve` atiende muchas).
    pub id: u64,
    /// Bytes del texto plano del sobre (`SYNSEMA_RECEIPT_SEALED_BYTES`).
    capacity: usize,
    /// Bytes que ya ocupan las entradas selladas.
    used: usize,
    next_seq: u64,
    /// `(secuencia, entrada JSON)` de lo que sale a la vista.
    pub public: Vec<(u64, String)>,
    /// `(secuencia, entrada JSON)` de lo que va al sobre.
    pub sealed: Vec<(u64, String)>,
    /// Entradas selladas que no entraron en el sobre (se cuentan, no se guardan).
    pub truncated: u64,
    /// Cada lectura del reloj que el programa vio (`now()`), en orden.
    pub clock: Vec<f64>,
    /// La semilla de `random()`/`random_int()` sin generador (hex), si la corrida la fijó.
    pub seed: Option<String>,
    /// El reloj cercado (con etiquetas): la última lectura en un momento público.
    fenced: Option<f64>,
    /// `--replay`: las lecturas del reloj de la corrida original, en orden, y cuántas se usaron.
    pub replay_clock: Option<(Vec<f64>, usize)>,
    /// `--replay`: `(fuente, sha256)` de cada entrada que leyó la corrida original, en orden, y
    /// cuántas ya se compararon.
    pub replay_inputs: Option<(Vec<(String, String)>, usize)>,
    /// La primera entrada que no coincidió (el replay para ahí).
    replay_error: Option<String>,
    /// v0.6.46 (ronda 1, E6-M1): bytes del sobre que ya ocupa el reloj (también cuentan en `used`),
    /// y las lecturas que no entraron (se cuentan, no se guardan).
    clock_used: usize,
    pub clock_dropped: u64,
    /// v0.6.46 (ronda 1, E6-M2): el recibo ya se armó. Un agente que lanzó la corrida sigue vivo con
    /// este registro instalado: lo que anotara después no estaría en ningún recibo, y una operación
    /// que sin auditor se niega correría sin rastro. Cerrado, el registro no está (`current`).
    closed: bool,
}

impl RunLog {
    pub fn new(capacity: usize) -> RunLog {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        RunLog { id: NEXT.fetch_add(1, Ordering::Relaxed), capacity, ..RunLog::default() }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Lo llama quien arma el recibo, con el registro tomado: desde acá es como si no hubiera auditor.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// ¿Cerrado? Para quien toma el candado por su cuenta (la semilla de `random()`).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    pub fn push_public(&mut self, entry: String) {
        let s = self.seq();
        self.public.push((s, entry));
    }

    /// Una entrada sellada. Si ya no entra en el sobre, se cuenta en `truncated` y la secuencia
    /// igual avanza: el auditor ve que hubo una entrada en ese lugar.
    pub fn push_sealed(&mut self, entry: String) {
        let s = self.seq();
        // `,` + `[s,` + `]` por entrada en el JSON del sobre.
        let cost = entry.len() + 24;
        if self.used + cost + ENVELOPE_RESERVE > self.capacity {
            self.truncated += 1;
            return;
        }
        self.used += cost;
        self.sealed.push((s, entry));
    }

    /// v0.6.46 (ronda 1, E6-M1) — una lectura del reloj. Cuenta en el tamaño del sobre, con tope en
    /// un cuarto: sin tope, muchas `now()` desalojaban al armar el recibo lo que se firmó en una rama
    /// privada, y el armado era cuadrático. Pasado el tope se cuenta y no se guarda (`--replay` usa
    /// la hora real para esas).
    pub fn push_clock(&mut self, v: f64) {
        // Un f64 en el JSON del sobre, como texto (ryu): a lo sumo 24 caracteres, las comillas y la
        // coma.
        const COST: usize = 28;
        if self.clock_used + COST > self.capacity / 4 || self.used + COST + ENVELOPE_RESERVE > self.capacity {
            self.clock_dropped += 1;
            return;
        }
        self.clock_used += COST;
        self.used += COST;
        self.clock.push(v);
    }
}

pub type SharedLog = Arc<Mutex<RunLog>>;

/// Cuántos registros hay instalados en el proceso (el del proceso más los de los hilos). En cero,
/// `active()` es un atómico y nada más.
static INSTALLED: AtomicUsize = AtomicUsize::new(0);
static PROCESS: Mutex<Option<SharedLog>> = Mutex::new(None);

thread_local! {
    static THREAD: RefCell<Option<SharedLog>> = const { RefCell::new(None) };
    static STREAM: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// v0.6.46 (ronda 1, E6-A2) — corre `f` con `name` como flujo de azar de la corrida (lo que sale de
/// `random()` con un registro). Lo fija `parallel_map` por ítem: sus workers no tienen nombre propio,
/// y derivar del nombre del hilo daba el mismo número en todos los ítems. Por ítem, no por hilo: qué
/// hilo toma qué ítem no es determinista, y `--replay` tiene que reproducir la lista.
pub fn with_stream<T>(name: String, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            STREAM.with(|s| *s.borrow_mut() = prev);
        }
    }
    let _restore = Restore(STREAM.with(|s| s.borrow_mut().replace(name)));
    f()
}

/// El flujo de azar de este hilo: el que fijó `with_stream`, o el nombre del hilo (el de la corrida,
/// el de cada agente).
pub fn stream() -> String {
    STREAM
        .with(|s| s.borrow().clone())
        .unwrap_or_else(|| std::thread::current().name().unwrap_or("").to_string())
}

/// ¿Hay un registro para la corrida de este hilo?
#[inline]
pub fn active() -> bool {
    INSTALLED.load(Ordering::Relaxed) != 0 && current().is_some()
}

/// El registro de la corrida de este hilo: el del hilo, o el del proceso. Uno cerrado (su recibo ya
/// se armó) no está, y el del hilo no cae al del proceso.
pub fn current() -> Option<SharedLog> {
    if INSTALLED.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let log = THREAD.with(|t| t.borrow().clone()).or_else(|| PROCESS.lock().ok().and_then(|g| g.clone()))?;
    let closed = log.lock().unwrap_or_else(|p| p.into_inner()).closed;
    (!closed).then_some(log)
}

/// Instala el registro del proceso (CLI, wasm). Devuelve el anterior.
pub fn install_process(log: Option<SharedLog>) -> Option<SharedLog> {
    let mut g = PROCESS.lock().unwrap_or_else(|p| p.into_inner());
    match (&*g, &log) {
        (None, Some(_)) => {
            INSTALLED.fetch_add(1, Ordering::Relaxed);
        }
        (Some(_), None) => {
            INSTALLED.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {}
    }
    std::mem::replace(&mut *g, log)
}

/// Instala el registro de este hilo (una request de `serve`, el hilo de un agente) mientras viva el
/// guard.
pub fn install_thread(log: SharedLog) -> ThreadGuard {
    INSTALLED.fetch_add(1, Ordering::Relaxed);
    let prev = THREAD.with(|t| t.borrow_mut().replace(log));
    ThreadGuard { prev, _not_send: std::marker::PhantomData }
}

pub struct ThreadGuard {
    prev: Option<SharedLog>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        THREAD.with(|t| *t.borrow_mut() = prev);
        INSTALLED.fetch_sub(1, Ordering::Relaxed);
    }
}

fn with_log(f: impl FnOnce(&mut RunLog)) -> bool {
    match current() {
        Some(log) => {
            #[cfg(test)]
            BETWEEN.with(|b| {
                if let Some(f) = b.borrow_mut().take() {
                    f()
                }
            });
            let mut g = log.lock().unwrap_or_else(|p| p.into_inner());
            // Ronda 2 (R2-B1): `closed` otra vez, con el candado con el que se anota: entre el
            // `current()` y este `lock()` otro hilo pudo cerrar el registro y armar el recibo.
            if g.closed {
                return false;
            }
            f(&mut g);
            true
        }
        None => false,
    }
}

#[cfg(test)]
thread_local! {
    /// Corre una vez entre el `current()` y el `lock()` de `with_log` (el test cierra ahí).
    static BETWEEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

/// Una entrada que sale a la vista. `false` si no hay registro.
#[cold]
#[inline(never)]
pub fn push_public(entry: String) -> bool {
    with_log(|l| l.push_public(entry))
}

/// Una entrada para el sobre. `false` si no hay registro (y entonces quien llama hace lo de siempre:
/// descartarla o rechazar la operación).
#[cold]
#[inline(never)]
pub fn push_sealed(entry: String) -> bool {
    with_log(|l| l.push_sealed(entry))
}

/// `now()` con el registro activo: lo que ve el programa, que queda anotado en orden. Con etiquetas, el
/// reloj está cercado: la lectura del último momento público (la primera vez, la de ahora), así la
/// resta de dos `now()` no mide cuánto tardó una rama privada. Con `--replay`, la lectura grabada.
/// `None` si no hay registro.
#[cold]
#[inline(never)]
pub fn read_clock(real: f64, fenced: bool) -> Option<f64> {
    let mut out = None;
    with_log(|l| {
        let v = if let Some((rec, used)) = l.replay_clock.as_mut() {
            let v = rec.get(*used).copied().unwrap_or(real);
            *used += 1;
            v
        } else if fenced {
            *l.fenced.get_or_insert(real)
        } else {
            real
        };
        l.push_clock(v);
        out = Some(v);
    });
    out
}

/// Una entrada de linaje (pública o sellada). Con `--replay`, además se compara con la de la corrida
/// original: la primera que difiere queda anotada y el intérprete corta ahí ([`replay_error`]).
#[cold]
#[inline(never)]
pub fn note_input(entry: String, sealed: bool, source: &str, sha256: &str) {
    with_log(|l| {
        if let Some((rec, used)) = l.replay_inputs.as_mut() {
            let i = *used;
            *used += 1;
            if l.replay_error.is_none() {
                match rec.get(i) {
                    Some((s, h)) if s == source && h == sha256 => {}
                    Some((s, h)) => {
                        l.replay_error = Some(format!(
                            "replay: input #{} differs from the recorded run — {} returned sha256 {}, the recorded run read {} with sha256 {}",
                            i + 1,
                            source,
                            sha256,
                            s,
                            h
                        ))
                    }
                    None => {
                        l.replay_error = Some(format!(
                            "replay: input #{} ({}) was not read by the recorded run (it read {})",
                            i + 1,
                            source,
                            rec.len()
                        ))
                    }
                }
            }
        }
        if sealed {
            l.push_sealed(entry);
        } else {
            l.push_public(entry);
        }
    });
}

/// La primera diferencia que encontró `--replay`, si hubo. Queda anotada aunque el programa atrape el
/// error: el CLI la mira al terminar.
#[cold]
#[inline(never)]
pub fn replay_error() -> Option<String> {
    let mut out = None;
    with_log(|l| out = l.replay_error.clone());
    out
}

/// `(entradas comparadas, entradas grabadas)` de un `--replay`.
pub fn replay_progress() -> Option<(usize, usize)> {
    let mut out = None;
    with_log(|l| out = l.replay_inputs.as_ref().map(|(rec, used)| (*used, rec.len())));
    out
}

/// v0.6.49 (A7): `(lecturas del reloj que hizo la corrida, lecturas grabadas)` de un `--replay`. Las
/// que pasan de las grabadas salieron del reloj real.
pub fn replay_clock_progress() -> Option<(usize, usize)> {
    let mut out = None;
    with_log(|l| out = l.replay_clock.as_ref().map(|(rec, used)| (*used, rec.len())));
    out
}

/// Un momento público (un sumidero que corre, una lectura de afuera con el PC público): el reloj
/// cercado avanza hasta acá.
#[cold]
#[inline(never)]
pub fn tick_clock(real: f64) {
    with_log(|l| {
        if l.fenced.is_some() {
            l.fenced = Some(real);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_entries_truncate_inside_and_keep_the_sequence() {
        let mut l = RunLog::new(ENVELOPE_RESERVE + 100);
        l.push_public("{}".into());
        l.push_sealed("x".repeat(40));
        l.push_sealed("y".repeat(40));
        l.push_public("{}".into());
        assert_eq!(l.public.iter().map(|e| e.0).collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(l.sealed.len(), 1);
        assert_eq!(l.sealed[0].0, 1);
        assert_eq!(l.truncated, 1);
    }

    /// Ronda 1 (E6-M1): el reloj no pasa de su cuarto del sobre, y lo que entra después sigue
    /// teniendo lugar.
    #[test]
    fn the_clock_keeps_to_its_quarter() {
        let mut l = RunLog::new(64 * 1024);
        for i in 0..100_000 {
            l.push_clock(1_760_000_000.0 + i as f64 / 7.0);
        }
        assert!(l.clock.len() < 64 * 1024 / 4 / 20, "{}", l.clock.len());
        assert_eq!(l.clock.len() as u64 + l.clock_dropped, 100_000);
        l.push_sealed("x".repeat(30_000));
        assert_eq!((l.sealed.len(), l.truncated), (1, 0));
    }

    /// v0.6.49 (A2, fila 3; ronda 1, B2): con lecturas falsas, sin depender del reloj real. El reloj
    /// cercado da la primera lectura hasta el próximo momento público, y después la de ese momento.
    #[test]
    fn the_fenced_clock_moves_only_at_a_public_moment() {
        let a: SharedLog = Arc::new(Mutex::new(RunLog::new(1 << 16)));
        let _g = install_thread(a.clone());
        assert_eq!(read_clock(100.0, true), Some(100.0));
        assert_eq!(read_clock(105.0, true), Some(100.0));
        // `read_file` con el PC público (o un sumidero que corre): el momento queda en 110.
        tick_clock(110.0);
        assert_eq!(read_clock(120.0, true), Some(110.0));
        // Sin etiquetas, el reloj es el real.
        assert_eq!(read_clock(130.0, false), Some(130.0));
        assert_eq!(a.lock().unwrap().clock, vec![100.0, 100.0, 110.0, 130.0]);
    }

    #[test]
    fn the_thread_log_wins_and_is_removed_with_its_guard() {
        assert!(!active());
        let a: SharedLog = Arc::new(Mutex::new(RunLog::new(1 << 16)));
        {
            let _g = install_thread(a.clone());
            assert!(active());
            assert!(push_sealed("{\"k\":1}".into()));
        }
        assert!(!active());
        assert!(!push_sealed("{}".into()));
        assert_eq!(a.lock().unwrap().sealed.len(), 1);
    }

    /// Ronda 1 (E6-M2): cerrado (el recibo ya se armó), el registro no está para nadie que lo tenga
    /// instalado: nada se anota y lo que se niega sin auditor se niega.
    #[test]
    fn a_closed_log_is_not_there() {
        let a: SharedLog = Arc::new(Mutex::new(RunLog::new(1 << 16)));
        let _g = install_thread(a.clone());
        assert!(active());
        a.lock().unwrap().close();
        assert!(!active());
        assert!(current().is_none());
        assert!(!push_sealed("{\"k\":1}".into()));
        assert!(!push_public("{}".into()));
        assert!(a.lock().unwrap().sealed.is_empty());
    }

    /// Ronda 2 (R2-B1): el registro se cierra entre que `with_log` lo encuentra y lo toma (otro hilo
    /// armó el recibo en ese hueco): no se anota, y quien llama recibe `false` (la operación se
    /// niega como sin auditor).
    #[test]
    fn a_log_closed_while_writing_is_not_written() {
        let a: SharedLog = Arc::new(Mutex::new(RunLog::new(1 << 16)));
        let _g = install_thread(a.clone());
        let b = a.clone();
        BETWEEN.with(|h| *h.borrow_mut() = Some(Box::new(move || b.lock().unwrap().close())));
        assert!(!push_sealed("{\"k\":1}".into()));
        assert!(a.lock().unwrap().sealed.is_empty());
    }
}
