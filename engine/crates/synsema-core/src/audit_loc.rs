//! Ubicación del programa para el audit de capabilities (`--audit json`): el intérprete
//! deja acá, por hilo, el `SourceLocation` del builtin que está ejecutando (o del
//! `require` que está concediendo), y el sink de audit lo lee al registrar el chequeo.
//!
//! Es diagnóstico, no seguridad: si falta, la entrada del audit lleva `file: null`;
//! nunca hay un chequeo de menos. Vive en un thread-local porque cada intérprete corre
//! en su propio hilo (main, agentes, workers, requests) y el `CapabilitySet` no conoce al
//! intérprete. Cuesta cero mientras ningún sink lo habilite (`enabled()` es un atómico).

use std::cell::RefCell;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::tokens::SourceLocation;

thread_local! {
    static CURRENT: RefCell<Option<SourceLocation>> = const { RefCell::new(None) };
}

/// Lo que el intérprete hace alrededor de cada builtin, en un solo atómico para que el camino común
/// (nada encendido) siga siendo una carga y un salto: `AUDIT` (esto) y `HOLD` (`op_hold`).
static AROUND: AtomicU8 = AtomicU8::new(0);
pub(crate) const AUDIT: u8 = 1;
pub(crate) const HOLD: u8 = 2;

pub(crate) fn around() -> u8 {
    AROUND.load(Ordering::Acquire)
}

pub(crate) fn enable_bit(bit: u8) {
    AROUND.fetch_or(bit, Ordering::Release);
}

/// Lo llama el sink al instalarse: a partir de acá el intérprete anota ubicaciones.
pub fn enable() {
    enable_bit(AUDIT);
}

pub fn enabled() -> bool {
    around() & AUDIT != 0
}

/// Reemplaza la ubicación actual del hilo y devuelve la anterior (para restaurarla al
/// salir del builtin — los builtins que re-entran al intérprete anidan).
pub fn replace(loc: Option<SourceLocation>) -> Option<SourceLocation> {
    CURRENT.with(|c| std::mem::replace(&mut *c.borrow_mut(), loc))
}

/// La ubicación que el intérprete de ESTE hilo está ejecutando, si la anotó.
pub fn current() -> Option<SourceLocation> {
    CURRENT.with(|c| c.borrow().clone())
}
