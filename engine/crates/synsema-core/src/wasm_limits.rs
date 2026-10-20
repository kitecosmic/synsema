//! v0.6.45 (D2) — límites de una corrida EMBEBIDA (`@synsema/wasm`): pasos y memoria. El caso del
//! embebido es justo el código que no es de confianza (el que escribe un modelo): un `each` anidado
//! de 9 M de vueltas bloqueaba el servidor y duplicar un texto 40 veces tiraba el módulo con un trap.
//!
//! Sólo existe en wasm32: el binario nativo no compila nada de esto (los techos de memoria y CPU de
//! un proceso son del sistema operativo, no del intérprete — ver el descarte de "Límites de
//! recursos" en el faltantes). Acá sí son verdad: `steps()` es determinista, y la memoria son los
//! bytes VIVOS que reservó la corrida, que cuenta el allocator del módulo.
//!
//! Pasos: el host arma los límites y prende la bandera de cancelación del intérprete; el chequeo
//! por sentencia que ya existe (`exec_block`, `StepsCancel` de la VM) sólo llama a `check_cancel`
//! con la bandera prendida, y `check_cancel` mira acá. Sin límites la bandera queda apagada y el
//! camino es el de siempre. Los pasos se cuentan desde que se armó el límite (en el modo handler,
//! desde el principio de cada request).
//!
//! Memoria: el allocator global del módulo (`synsema-wasm-web`) suma y resta en `LIVE` y, armado el
//! límite, RECHAZA la reserva que pasaría el techo (`LIMIT`, en bytes vivos absolutos: lo vivo al
//! armar + el tope). Rust no sabe seguir sin esa memoria y el módulo hace trap; por eso queda
//! `HIT` prendido, y el paquete JS, al ver el trap, pregunta (`synsema_limit_hit`) y devuelve un
//! error normal en vez de un trap. Antes se medía `memory.size`, que nunca baja (el máximo
//! histórico de la instancia) y se miraba cada 1024 pasos: una sola sentencia que reservaba de
//! golpe pasaba de largo, y una corrida anterior grande cortaba a una chica.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

thread_local! {
    /// `(pasos máximos, pasos al armar)`; `None` = sin límite de pasos armado.
    static STEPS: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
    /// ¿Hay límites armados (de pasos o de memoria)?
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// Se pidió un tope de memoria en un build sin allocator que cuente: la corrida falla al
    /// arrancar en vez de correr sin el límite que se pidió.
    static MEM_UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
}

/// Bytes vivos reservados por el allocator del módulo (lo mantiene `synsema-wasm-web`).
pub static LIVE: AtomicUsize = AtomicUsize::new(0);
/// Techo de bytes vivos; `usize::MAX` = sin límite.
pub static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Se pasó el techo de memoria en la corrida en curso (el allocator lo prende al rechazar).
pub static HIT: AtomicBool = AtomicBool::new(false);
/// Hay un allocator que cuenta (`synsema-wasm-web` lo prende). Sin él, pedir un tope de memoria es
/// un error: un límite que no se puede cumplir no se acepta en silencio.
pub static COUNTING: AtomicBool = AtomicBool::new(false);

/// El allocator: ¿entra una reserva de `n` bytes más? Si entra, ya quedó sumada.
pub fn reserve(n: usize) -> bool {
    let live = LIVE.fetch_add(n, Ordering::Relaxed).saturating_add(n);
    if live > LIMIT.load(Ordering::Relaxed) {
        LIVE.fetch_sub(n, Ordering::Relaxed);
        HIT.store(true, Ordering::Relaxed);
        return false;
    }
    true
}

/// El allocator: se liberaron `n` bytes.
pub fn release(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
}

/// Arma los límites de la corrida en este hilo (`None` en uno = sin ese límite). `steps_now` son
/// los pasos que ya lleva el intérprete: el tope cuenta desde acá.
pub fn arm(max_steps: Option<u64>, max_bytes: Option<u64>, steps_now: u64) {
    HIT.store(false, Ordering::Relaxed);
    STEPS.set(max_steps.map(|m| (m, steps_now)));
    let limit = match max_bytes {
        Some(b) => LIVE.load(Ordering::Relaxed).saturating_add(usize::try_from(b).unwrap_or(usize::MAX)),
        None => usize::MAX,
    };
    LIMIT.store(limit, Ordering::Relaxed);
    MEM_UNSUPPORTED.set(memory_limit_unsupported(max_bytes));
    ARMED.set(max_steps.is_some() || max_bytes.is_some());
}

/// Desarma los límites (al terminar la corrida o el request).
pub fn disarm() {
    STEPS.set(None);
    LIMIT.store(usize::MAX, Ordering::Relaxed);
    ARMED.set(false);
}

/// ¿Se pidió un tope de memoria que este build no puede cumplir?
pub fn memory_limit_unsupported(max_bytes: Option<u64>) -> bool {
    max_bytes.is_some() && !COUNTING.load(Ordering::Relaxed)
}

/// El mensaje del tope de memoria (el mismo en el error del motor y en el que arma el JS tras el
/// trap).
pub fn memory_message() -> String {
    "memory limit reached: the run reserved more than maxMemoryMb".to_string()
}

/// `None` = no hay límites armados (la bandera es una cancelación de verdad); `Some(Ok)` = armados y
/// dentro de lo permitido; `Some(Err)` = se pasó, con el mensaje.
pub fn check(steps: u64) -> Option<Result<(), String>> {
    if !ARMED.get() {
        return None;
    }
    if MEM_UNSUPPORTED.get() {
        return Some(Err(
            "maxMemoryMb is not supported by this build of the engine (it needs the module's counting allocator)".to_string(),
        ));
    }
    if HIT.load(Ordering::Relaxed) {
        return Some(Err(memory_message()));
    }
    if let Some((max, base)) = STEPS.get() {
        if steps.saturating_sub(base) > max {
            return Some(Err(format!(
                "step limit reached: the program ran more than {} steps (maxSteps)",
                max
            )));
        }
    }
    Some(Ok(()))
}
