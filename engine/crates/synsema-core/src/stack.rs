//! v0.6.58 (M-r5-1): la pila que le queda al hilo que corre el intérprete.
//!
//! El guardián de recursión (`MAX_RECURSION` y los pesos de `interpreter.rs`) está calibrado para
//! un hilo de `INTERP_STACK_SIZE` (512 MB): una unidad son 512 MB / 3000. Un hilo con menos pila
//! (los de `serve`, `stream`, las aprobaciones y ACME: 64 MB) avisa al empezar con [`enter_thread`],
//! y desde ahí el guardián también da el error cuando lo que queda de pila no alcanza para lo que
//! va a correr (en unidades del guardián). Un hilo que no avisa (los de 512 MB, wasm) queda como
//! antes: sólo cuenta.
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
