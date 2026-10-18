//! v0.6.45 (D2) — límites de una corrida EMBEBIDA (`@synsema/wasm`): pasos y memoria. El caso del
//! embebido es justo el código que no es de confianza (el que escribe un modelo): un `each` anidado
//! de 9 M de vueltas bloqueaba el servidor y duplicar un texto 40 veces tiraba el módulo con un trap.
//!
//! Sólo existe en wasm32: el binario nativo no compila nada de esto (los techos de memoria y CPU de
//! un proceso son del sistema operativo, no del intérprete — ver el descarte de "Límites de
//! recursos" en el faltantes). Acá sí son verdad: `steps()` es determinista y la memoria lineal del
//! módulo se mide exacta (`memory.size`), no a ojo.
//!
//! Cómo se engancha sin costo cuando no se piden: el host arma los límites y prende la bandera de
//! cancelación del intérprete; el chequeo por sentencia que ya existe (`exec_block`, `StepsCancel`
//! de la VM) sólo llama a `check_cancel` con la bandera prendida, y `check_cancel` mira acá. Sin
//! límites la bandera queda apagada y el camino es el de siempre.

use std::cell::Cell;

thread_local! {
    /// `(pasos, bytes)` máximos de la corrida en curso; `None` = sin límites.
    static LIMITS: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
    /// El próximo `steps` en que se mira la memoria: cada `MEM_EVERY` pasos alcanza para cortar un
    /// crecimiento que se va de las manos, y `memory.size` en cada sentencia costaba ~10 %.
    static NEXT_MEM_CHECK: Cell<u64> = const { Cell::new(0) };
}

const MEM_EVERY: u64 = 1024;

/// Arma los límites de la corrida en este hilo (`None` en uno = sin ese límite).
pub fn arm(max_steps: Option<u64>, max_bytes: Option<u64>) {
    LIMITS.set(Some((max_steps.unwrap_or(u64::MAX), max_bytes.unwrap_or(u64::MAX))));
    NEXT_MEM_CHECK.set(0);
}

/// Desarma los límites (al terminar la corrida).
pub fn disarm() {
    LIMITS.set(None);
}

/// `None` = no hay límites armados (la bandera es una cancelación de verdad); `Some(Ok)` = armados y
/// dentro de lo permitido; `Some(Err)` = se pasó, con el mensaje.
pub fn check(steps: u64) -> Option<Result<(), String>> {
    let (max_steps, max_bytes) = LIMITS.get()?;
    if steps > max_steps {
        return Some(Err(format!(
            "step limit reached: the program ran more than {} steps (maxSteps)",
            max_steps
        )));
    }
    if max_bytes == u64::MAX || steps < NEXT_MEM_CHECK.get() {
        return Some(Ok(()));
    }
    NEXT_MEM_CHECK.set(steps.saturating_add(MEM_EVERY));
    let bytes = core::arch::wasm32::memory_size(0) as u64 * 65536;
    if bytes > max_bytes {
        return Some(Err(format!(
            "memory limit reached: the engine's memory grew to {} MB, over maxMemoryMb ({} MB)",
            bytes >> 20,
            max_bytes >> 20
        )));
    }
    Some(Ok(()))
}
