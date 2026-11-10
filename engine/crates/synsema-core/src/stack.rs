//! v0.6.58 (M-r5-1): la pila que le queda al hilo que corre el intérprete.
//!
//! El guardián de recursión (`MAX_RECURSION` y los pesos de `interpreter.rs`) está calibrado para
//! un hilo de `INTERP_STACK_SIZE` (512 MB): una unidad son 512 MB / 3000. Todo hilo que corre el
//! intérprete avisa su pila al empezar con [`enter_thread`] (los de 512 MB y los de 64 MB de
//! `serve`, `stream`, `cron`, las aprobaciones y ACME), y desde ahí el guardián también da el error
//! cuando lo que queda de pila no alcanza para lo que va a correr (en unidades del guardián): la
//! calibración de un host (x86_64 Windows) no alcanza en otro (aarch64 debug usa más por llamada).
//! Un hilo que no avisa (wasm, el de un embebedor) queda como antes: sólo cuenta.
//!
//! Supuesto (ronda 8, medido): las primeras 64 llamadas no miran la pila (`recursion_cap`), así que
//! el hilo tiene que aguantar 64 llamadas del cuerpo más caro que no pasa por `with_stack_weight`.
//! En debug con etiquetas, una task con 6 `when` cuesta más de ~110 KB por llamada: 8 MB desbordan
//! a las 60; 16 MB ya dan el error. Por eso ningún hilo del intérprete tiene menos de 64 MB.
//!
//! No hace falta preguntarle nada al SO: el hilo lo creamos nosotros con `stack_size(size)` y la
//! dirección de una variable local al empezar es el tope de su pila.

use std::cell::Cell;

thread_local! {
    /// La dirección por debajo de la cual no se baja (0: el hilo no avisó).
    static FLOOR: Cell<usize> = const { Cell::new(0) };
}

/// Lo que se deja abajo: la página de guarda del SO, lo que el hilo usó antes de avisar y lo que
/// corre sin pasar por el guardián (builtins, el render de un error).
const RESERVE: usize = 1024 * 1024;

/// La pila más chica de un hilo que corre el intérprete (`serve`, `stream`, `cron`, aprobaciones,
/// ACME); los demás tienen 512 MB. Ver el supuesto en la doc del módulo.
const MIN_STACK: usize = 64 * 1024 * 1024;

/// Una unidad del guardián en bytes (nativo): 512 MB / 3000, la calibración de `node_weight`.
const UNIT: usize = 512 * 1024 * 1024 / 3000;

#[inline(always)]
fn here() -> usize {
    let x = 0u8;
    std::hint::black_box(&x) as *const u8 as usize
}

/// Al empezar un hilo creado con `stack_size(size)` que va a correr el intérprete.
pub fn enter_thread(size: usize) {
    if cfg!(target_arch = "wasm32") {
        return;
    }
    // Ronda 9: el supuesto de la doc del módulo (64 llamadas sin mirar la pila) pide 64 MB.
    debug_assert!(size >= MIN_STACK, "stack::enter_thread: {size} bytes; a thread that runs the interpreter needs at least 64 MB");
    let top = here();
    FLOOR.with(|f| f.set(top.saturating_sub(size).saturating_add(RESERVE)));
}

/// `true` si este hilo avisó su pila (el intérprete que se crea acá mira la pila en cada llamada
/// pasadas las primeras 64).
pub(crate) fn registered() -> bool {
    FLOOR.with(|f| f.get()) != 0
}

/// `true` si a este hilo no le quedan `units` unidades del guardián (más la de la llamada).
#[inline(never)]
pub(crate) fn short(units: usize) -> bool {
    let floor = FLOOR.with(|f| f.get());
    floor != 0 && here() < floor.saturating_add(units.saturating_add(1).saturating_mul(UNIT))
}
