//! Reloj del intérprete — UNA fuente de "ahora" para todo el motor.
//!
//! Nativo y wasip1 leen `SystemTime` (WASI lo provee). En un host sin sistema
//! operativo (`wasm32-unknown-unknown`: navegador, Node/Bun sin WASI, wazero,
//! wasmtime-py con módulo crudo) `SystemTime::now()` PANICA — el host instala su
//! reloj con [`set_clock`] (JS `Date.now()`, `time.time()`, `time.Now()`…) y todos
//! los call sites (now(), timestamps de memoria/progress, captoken/httpsig/oidc/
//! webauth, audit de secrets) lo consumen sin saberlo. La capability `time` se
//! chequea en los builtins, igual que siempre: el reloj es transporte, no permiso.
//!
//! Sin reloj instalado en un host sin SO, el default devuelve 0.0 (epoch) en vez de
//! panicar: un trap en wasm mata la instancia entera; un timestamp 0 es visible y
//! diagnosticable.

use std::sync::{Mutex, OnceLock};

type ClockFn = Box<dyn Fn() -> f64 + Send + Sync>;

fn slot() -> &'static Mutex<Option<ClockFn>> {
    static CLOCK: OnceLock<Mutex<Option<ClockFn>>> = OnceLock::new();
    CLOCK.get_or_init(|| Mutex::new(None))
}

/// Instala el reloj del host: `f` devuelve segundos unix (float). Reemplaza al
/// anterior; `None` vuelve al default de la plataforma.
pub fn set_clock(f: Option<ClockFn>) {
    if let Ok(mut g) = slot().lock() {
        *g = f;
    }
}

fn platform_now() -> f64 {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        0.0
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
}

/// Segundos unix como float (lo que devuelve `now()`).
pub fn now_secs_f64() -> f64 {
    if let Ok(g) = slot().lock() {
        if let Some(f) = g.as_ref() {
            return f();
        }
    }
    platform_now()
}

/// Segundos unix enteros (truncados).
pub fn now_secs() -> i64 {
    now_secs_f64().floor() as i64
}

/// Segundos unix enteros sin signo (para deadlines/monotónicos aproximados).
pub fn now_secs_u64() -> u64 {
    now_secs_f64().max(0.0).floor() as u64
}

type SleepFn = Box<dyn Fn(f64) + Send + Sync>;

fn sleep_slot() -> &'static Mutex<Option<SleepFn>> {
    static SLEEP: OnceLock<Mutex<Option<SleepFn>>> = OnceLock::new();
    SLEEP.get_or_init(|| Mutex::new(None))
}

/// Instala la pausa del host (`sleep()`, polls de confirmación de tx). En un host
/// sin SO `std::thread::sleep` panica; el host decide cómo bloquear (Atomics.wait
/// en un Worker, `time.sleep` en Python…). `None` vuelve al default.
pub fn set_sleep(f: Option<SleepFn>) {
    if let Ok(mut g) = sleep_slot().lock() {
        *g = f;
    }
}

/// Pausa `secs` segundos con la pausa instalada (o la de la plataforma). En un host
/// sin SO y sin pausa instalada es un no-op: el programa sigue, no trapea.
pub fn sleep_secs(secs: f64) {
    if !(secs > 0.0) || !secs.is_finite() {
        return;
    }
    if let Ok(g) = sleep_slot().lock() {
        if let Some(f) = g.as_ref() {
            f(secs);
            return;
        }
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    std::thread::sleep(std::time::Duration::from_secs_f64(secs));
}
