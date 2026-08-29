//! Puente mínimo entre la terminal interactiva (`term_open`, en synsema-stdlib) y las
//! piezas que escriben/leen la consola sin conocer el hub: el drenaje de `print`
//! (`Interpreter::drain_output`) y el handler humano de consola (`synsema-llm`).
//!
//! `synsema-llm` y `synsema-stdlib` no se conocen; ambos dependen de `core`, así que el
//! estado "hay una terminal en raw mode" vive acá como un `static` por proceso:
//! - `is_raw()`: ¿stdin está en raw? El drenaje de salida convierte `\n` → `\r\n`.
//! - `suspend()` / `resume()`: el handler humano apaga el raw mode mientras hace su
//!   `read_line` cocinado y lo reenciende al volver. Si no hay terminal abierta son no-op.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// `Fn(true)` = reencender raw (resume); `Fn(false)` = apagar raw (suspend).
pub type SuspendFn = Box<dyn Fn(bool) + Send + Sync>;

static RAW: AtomicBool = AtomicBool::new(false);
static SUSPEND: OnceLock<Mutex<Option<SuspendFn>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<SuspendFn>> {
    SUSPEND.get_or_init(|| Mutex::new(None))
}

/// La terminal está en raw mode (hay un `term_open` vivo y no suspendido).
pub fn is_raw() -> bool {
    RAW.load(Ordering::Relaxed)
}

/// Lo llama el dueño de la terminal al abrir (`Some`) y al cerrar (`None`).
pub fn set_owner(f: Option<SuspendFn>) {
    if let Ok(mut g) = slot().lock() {
        *g = f;
    }
    if f_is_none() {
        RAW.store(false, Ordering::Relaxed);
    }
}

fn f_is_none() -> bool {
    slot().lock().map(|g| g.is_none()).unwrap_or(true)
}

/// El dueño informa el estado real del raw mode (tras enable/disable).
pub fn set_raw(on: bool) {
    RAW.store(on, Ordering::Relaxed);
}

/// Apaga el raw mode (si hay terminal abierta) para que un `read_line` cocinado funcione.
pub fn suspend() {
    if let Ok(g) = slot().lock() {
        if let Some(f) = g.as_ref() {
            f(false);
        }
    }
}

/// Reenciende el raw mode si hay terminal abierta.
pub fn resume() {
    if let Ok(g) = slot().lock() {
        if let Some(f) = g.as_ref() {
            f(true);
        }
    }
}
