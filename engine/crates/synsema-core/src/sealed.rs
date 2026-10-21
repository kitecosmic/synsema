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
}

impl RunLog {
    pub fn new(capacity: usize) -> RunLog {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        RunLog { id: NEXT.fetch_add(1, Ordering::Relaxed), capacity, ..RunLog::default() }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
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
}

pub type SharedLog = Arc<Mutex<RunLog>>;

/// Cuántos registros hay instalados en el proceso (el del proceso más los de los hilos). En cero,
/// `active()` es un atómico y nada más.
static INSTALLED: AtomicUsize = AtomicUsize::new(0);
static PROCESS: Mutex<Option<SharedLog>> = Mutex::new(None);

thread_local! {
    static THREAD: RefCell<Option<SharedLog>> = const { RefCell::new(None) };
}

/// ¿Hay un registro para la corrida de este hilo?
#[inline]
pub fn active() -> bool {
    INSTALLED.load(Ordering::Relaxed) != 0 && current().is_some()
}

/// El registro de la corrida de este hilo: el del hilo, o el del proceso.
pub fn current() -> Option<SharedLog> {
    if INSTALLED.load(Ordering::Relaxed) == 0 {
        return None;
    }
    THREAD.with(|t| t.borrow().clone()).or_else(|| PROCESS.lock().ok().and_then(|g| g.clone()))
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
            let mut g = log.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut g);
            true
        }
        None => false,
    }
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
        l.clock.push(v);
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
}
