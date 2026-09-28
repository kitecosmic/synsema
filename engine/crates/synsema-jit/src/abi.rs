//! **El único módulo con `unsafe` del nivel nativo** (spec §F4.2). Tres cosas y nada más:
//!
//! 1. `Ctx`: lo que el código generado lee y escribe, con punteros a los contadores del intérprete.
//! 2. `synsema_jit_deopt`: la función que el código generado llama al salir a la VM (copia los
//!    valores que dejó en su pila).
//! 3. `Compiled::call`: convertir la dirección de la entrada compilada en una función y llamarla.
//!
//! Lo que hace falta para que sea seguro lo garantiza `lower`: el código generado sólo toca la
//! memoria del `Ctx`, de los contadores a los que apunta, de los argumentos de la entrada y de sus
//! propias ranuras de pila (`lower::check_memory` lo verifica en cada función antes de compilarla),
//! y sólo llama a funciones de su unidad y a `synsema_jit_deopt`.

use std::mem::offset_of;
use std::sync::atomic::AtomicBool;

use synsema_core::native_tier::{NFrame, NOutcome, NVal, NativeCode, NativeCx};

use crate::lower::{Kind, Point};

#[cfg(not(target_pointer_width = "64"))]
compile_error!("synsema-jit sólo en 64 bits (la profundidad de la VM es un usize que el código nativo lee como i64)");

/// El contexto de una llamada nativa. `#[repr(C)]`: el código generado lo lee a desplazamientos fijos.
#[repr(C)]
pub(crate) struct Ctx {
    steps: *mut u64,
    depth: *mut u64,
    cancel: *const u8,
    max_depth: u64,
    /// 0 mientras todo corre en nativo; 1 cuando algún frame salió a la VM.
    status: u64,
    sink: *mut Vec<Raw>,
}

pub(crate) const OFF_STEPS: i32 = offset_of!(Ctx, steps) as i32;
pub(crate) const OFF_DEPTH: i32 = offset_of!(Ctx, depth) as i32;
pub(crate) const OFF_CANCEL: i32 = offset_of!(Ctx, cancel) as i32;
pub(crate) const OFF_MAX_DEPTH: i32 = offset_of!(Ctx, max_depth) as i32;
pub(crate) const OFF_STATUS: i32 = offset_of!(Ctx, status) as i32;

/// Una salida tal como la deja el código generado (del frame de más adentro al de más afuera).
pub(crate) struct Raw {
    func: u32,
    point: u32,
    vals: Vec<i64>,
}

/// La llama el código generado al salir a la VM: `vals` apunta a `n` valores que guardó en su pila
/// (los `Int`/`Bool` del punto `point` de la función `func`, en orden).
pub(crate) extern "C" fn synsema_jit_deopt(ctx: *mut Ctx, func: i64, point: i64, vals: *const i64, n: i64) {
    // SAFETY: `ctx` es el `Ctx` que `Compiled::call` armó en su pila y pasó a la entrada; el código
    // generado lo pasa sin cambios a sus llamados y a esta función, y la llamada nativa termina antes
    // de que `call` vuelva. `sink` apunta al `Vec` local de `call`, vivo y sin otros préstamos
    // mientras corre el código nativo. `vals` apunta a una ranura de pila del que llama de
    // `8 * max(n, 1)` bytes, con `n` valores escritos (lo emite `lower::build` con el mismo `n`).
    unsafe {
        let c = &mut *ctx;
        c.status = 1;
        let v = std::slice::from_raw_parts(vals, n as usize).to_vec();
        (*c.sink).push(Raw { func: func as u32, point: point as u32, vals: v });
    }
}

/// Una unidad compilada.
pub(crate) struct Compiled {
    /// La entrada `(ctx, *const i64) -> i64` (ya en memoria ejecutable, de sólo lectura).
    pub(crate) entry: *const u8,
    pub(crate) nparams: usize,
    pub(crate) ret: Kind,
    /// Las salidas de cada función.
    pub(crate) points: Vec<Vec<Point>>,
}

fn nval(k: Kind, bits: i64) -> NVal {
    match k {
        Kind::Int => NVal::Int(bits),
        Kind::Bool => NVal::Bool(bits != 0),
        Kind::Callee(f) => NVal::Callee(f),
        _ => NVal::Nothing,
    }
}

impl NativeCode for Compiled {
    fn call(&self, cx: &mut NativeCx<'_>, args: &[i64]) -> NOutcome {
        assert_eq!(args.len(), self.nparams, "aridad de la entrada nativa");
        let mut sink: Vec<Raw> = Vec::new();
        let mut ctx = Ctx {
            steps: std::ptr::from_mut::<u64>(cx.steps),
            depth: std::ptr::from_mut::<usize>(cx.depth).cast::<u64>(),
            // Un `AtomicBool` tiene la representación de un `u8` (documentado en `std`).
            cancel: std::ptr::from_ref::<AtomicBool>(cx.cancel).cast::<u8>(),
            max_depth: cx.max_depth as u64,
            status: 0,
            sink: &mut sink,
        };
        // SAFETY: `entry` es la dirección de una función que compiló este crate con la firma
        // `(i64, i64) -> i64` en la convención por defecto de la plataforma (la de `extern "C"`),
        // en memoria que `cranelift-jit` pasó a lectura+ejecución y que no se libera mientras vive
        // el hilo (el módulo es del hilo, como este valor: `Compiled` no es `Send`). Los punteros de
        // `ctx` apuntan a datos vivos durante toda la llamada: los contadores del intérprete
        // (préstamos exclusivos de `cx`, que no se usan mientras tanto), el flag de cancelación
        // (que otro hilo puede escribir de a un byte: el código lo lee con una carga de un byte,
        // como el `load(Relaxed)` de la VM), `args` (con `nparams` enteros, recién verificado) y
        // `sink`. Qué memoria toca el código generado lo acota `lower::check_memory`.
        let r = unsafe {
            let f: extern "C" fn(*mut Ctx, *const i64) -> i64 = std::mem::transmute(self.entry);
            f(&mut ctx, args.as_ptr())
        };
        if ctx.status == 0 {
            return NOutcome::Done(nval(self.ret, r));
        }
        // Del frame de más afuera al de más adentro.
        let frames = sink
            .into_iter()
            .rev()
            .map(|raw| {
                let p = &self.points[raw.func as usize][raw.point as usize];
                let mut it = raw.vals.into_iter();
                let values = p
                    .values
                    .iter()
                    .map(|&(place, k)| {
                        let bits = if matches!(k, Kind::Int | Kind::Bool) { it.next().expect("valor guardado") } else { 0 };
                        (place, nval(k, bits))
                    })
                    .collect();
                NFrame { func: raw.func, pc: p.pc, values, call: p.call }
            })
            .collect();
        NOutcome::Deopt(frames)
    }
}
