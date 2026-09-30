//! **El único módulo con `unsafe` del nivel nativo** (spec §F4.2). Cuatro cosas y nada más:
//!
//! 1. `Ctx`: lo que el código generado lee y escribe, con punteros a los contadores del intérprete.
//! 2. `synsema_jit_deopt`: la función que el código generado llama al salir a la VM (copia los
//!    valores que dejó en su pila).
//! 3. `Compiled::call`: convertir la dirección de la entrada compilada en una función y llamarla, y
//!    al volver (F4.7b) clonar los valores con caja que quedaron vivos.
//! 4. (F4.7b) Las lecturas de valores con caja (`synsema_jit_index`, `_prop`, `_list_body`,
//!    `_list_elem`, `_truthy`, y `_length` de F4.7c): convierten los punteros que les pasa el código generado en
//!    referencias y llaman a las funciones seguras de `synsema_core::native_tier`.
//!
//! Lo que hace falta para que sea seguro lo garantiza `lower`: el código generado sólo toca la
//! memoria del `Ctx`, de los contadores a los que apunta, de los argumentos de la entrada y de sus
//! propias ranuras de pila (`lower::check_memory` lo verifica en cada función antes de compilarla),
//! sólo llama a funciones de su unidad y a las de acá, y los punteros que les pasa (y que guarda en
//! las salidas) vienen de la entrada o de una lectura, nunca de una cuenta (`lower::check_pointers`).
//!
//! **Por qué los punteros siguen valiendo (F4.7b):** un valor con caja entra al código nativo
//! prestado: la dirección de donde vive en la VM (un registro, un lugar de la ventana, una global,
//! el `Rc` de un iterador) o, después de una lectura, la de un elemento de una lista o un valor de
//! un mapa. Mientras corre una llamada nativa nada escribe la memoria de la VM: el código generado
//! sólo escribe sus variables (vuelven a la VM después de `call`), no corre código de la VM, y las
//! lecturas de acá sólo leen (la caché de un sitio es de la unidad). Así que cada una de esas
//! direcciones sigue siendo la de un valor vivo y en su lugar hasta que `call` vuelve; y `call`
//! clona los que quedaron vivos antes de devolver nada (antes de que la VM escriba algo).

use std::any::Any;
use std::mem::offset_of;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;

use synsema_core::native_tier::{self, NFrame, NOutcome, NPeek, NSeen, NVal, NativeCode, NativeCx, Place, SiteIc, TAG_LIST, TAG_MAP, TAG_MISS, TAG_OTHER};
use synsema_core::types::{ListRef, SynValue};

use crate::lower::{ptr_words, words, Kind, Point, TAG_BOOL, TAG_FLOAT, TAG_HOLE, TAG_INT};

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
    /// F4.7b: lo que deja una lectura además de la etiqueta que devuelve: sus bits y su puntero.
    out_bits: i64,
    out_ptr: u64,
    sink: *mut Vec<Raw>,
    /// F4.7b: los sitios de la unidad (sus cachés).
    sites: *const SiteIc,
    nsites: usize,
    /// F4.7b: un pánico dentro de una lectura (se relanza al volver del código nativo).
    panic: *mut Option<Box<dyn Any + Send>>,
}

pub(crate) const OFF_STEPS: i32 = offset_of!(Ctx, steps) as i32;
pub(crate) const OFF_DEPTH: i32 = offset_of!(Ctx, depth) as i32;
pub(crate) const OFF_CANCEL: i32 = offset_of!(Ctx, cancel) as i32;
pub(crate) const OFF_MAX_DEPTH: i32 = offset_of!(Ctx, max_depth) as i32;
pub(crate) const OFF_STATUS: i32 = offset_of!(Ctx, status) as i32;
pub(crate) const OFF_OUT_BITS: i32 = offset_of!(Ctx, out_bits) as i32;
pub(crate) const OFF_OUT_PTR: i32 = offset_of!(Ctx, out_ptr) as i32;

/// Una salida tal como la deja el código generado (del frame de más adentro al de más afuera).
pub(crate) struct Raw {
    func: u32,
    point: u32,
    vals: Vec<i64>,
    ptrs: Vec<i64>,
}

/// La llama el código generado al salir a la VM: `vals` apunta a `n` palabras que guardó en su pila
/// (las de los valores del punto `point` de la función `func`, en orden: ver `lower::words`) y
/// `ptrs` a sus `np` punteros (`lower::ptr_words`).
pub(crate) extern "C" fn synsema_jit_deopt(ctx: *mut Ctx, func: i64, point: i64, vals: *const i64, n: i64, ptrs: *const i64, np: i64) {
    // SAFETY: `ctx` es el `Ctx` que `Compiled::call` armó en su pila y pasó a la entrada; el código
    // generado lo pasa sin cambios a sus llamados y a esta función, y la llamada nativa termina antes
    // de que `call` vuelva. `sink` apunta al `Vec` local de `call`, vivo y sin otros préstamos
    // mientras corre el código nativo. `vals` apunta a una ranura de pila del que llama de
    // `8 * max(n, 1)` bytes con `n` palabras escritas, y `ptrs` (si `np > 0`) a otra de `8 * np`
    // bytes con `np` punteros (lo emite `lower::build` con los mismos números).
    unsafe {
        let c = &mut *ctx;
        c.status = 1;
        let v = std::slice::from_raw_parts(vals, n as usize).to_vec();
        // Sin punteros la dirección es 0 (no hay ranura).
        let p = if np > 0 { std::slice::from_raw_parts(ptrs, np as usize).to_vec() } else { Vec::new() };
        (*c.sink).push(Raw { func: func as u32, point: point as u32, vals: v, ptrs: p });
    }
}

/// Corre una lectura: deja sus bits y su puntero en el contexto y devuelve su etiqueta. Un pánico
/// no cruza el código generado: queda guardado, la lectura da `MISS` (el código sale a la VM) y
/// `call` lo relanza al volver.
fn read(ctx: *mut Ctx, f: impl FnOnce(&Ctx) -> NPeek) -> i64 {
    // SAFETY: `ctx` es el de `Compiled::call` (ver `synsema_jit_deopt`), vivo durante la llamada; el
    // código generado no lo lee mientras corre esta función (la llama y espera).
    let c = unsafe { &mut *ctx };
    let p = match catch_unwind(AssertUnwindSafe(|| f(c))) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: `panic` apunta al `Option` local de `call`, vivo y sin otros préstamos.
            unsafe { *c.panic = Some(e) };
            NPeek::MISS
        }
    };
    c.out_bits = p.bits;
    c.out_ptr = p.ptr as usize as u64;
    p.tag
}

impl Ctx {
    fn site(&self, k: i64) -> Option<&SiteIc> {
        // SAFETY: `sites`/`nsites` son el `Vec` de sitios de la unidad (`Compiled::sites`), que vive
        // mientras vive `Compiled` y no cambia durante la llamada.
        let sites = unsafe { std::slice::from_raw_parts(self.sites, self.nsites) };
        usize::try_from(k).ok().and_then(|k| sites.get(k))
    }
}

/// `x[i]` (`GetIndex`). `obj` e `idx` son valores con caja prestados (o nulos: un `idx` que no tiene
/// caja va en `tag`/`bits`).
pub(crate) extern "C" fn synsema_jit_index(ctx: *mut Ctx, obj: *const SynValue, tag: i64, bits: i64, idx: *const SynValue, site: i64) -> i64 {
    read(ctx, |c| {
        // SAFETY: `obj` e `idx` son nulos o direcciones de valores vivos que no cambian durante la
        // llamada nativa (ver el comienzo del módulo; `check_pointers` verifica su procedencia).
        let (obj, idx) = unsafe { (obj.as_ref(), idx.as_ref()) };
        match (obj, c.site(site)) {
            (Some(o), Some(s)) => s.index(o, tag, bits, idx),
            _ => NPeek::MISS,
        }
    })
}

/// `m.k` (`GetProp`).
pub(crate) extern "C" fn synsema_jit_prop(ctx: *mut Ctx, obj: *const SynValue, site: i64) -> i64 {
    read(ctx, |c| {
        // SAFETY: como en `synsema_jit_index`.
        let obj = unsafe { obj.as_ref() };
        match (obj, c.site(site)) {
            (Some(o), Some(s)) => s.prop(o),
            _ => NPeek::MISS,
        }
    })
}

/// La lista de un `each`: dónde está su `Rc` (0 si no es una lista), y el largo en `out_bits`.
pub(crate) extern "C" fn synsema_jit_list_body(ctx: *mut Ctx, obj: *const SynValue) -> i64 {
    let mut body = 0i64;
    read(ctx, |_| {
        // SAFETY: como en `synsema_jit_index`.
        match unsafe { obj.as_ref() }.and_then(native_tier::list_body) {
            Some((l, len)) => {
                body = l as usize as i64;
                NPeek { tag: TAG_LIST, bits: len as i64, ptr: std::ptr::null() }
            }
            None => NPeek::MISS,
        }
    });
    body
}

/// El elemento `i` de la lista de un `each` (`body`: lo que dio `synsema_jit_list_body`, o el `Rc`
/// de un iterador de la VM al entrar).
pub(crate) extern "C" fn synsema_jit_list_elem(ctx: *mut Ctx, body: *const ListRef, i: i64) -> i64 {
    read(ctx, |_| {
        // SAFETY: `body` es la dirección de un `Rc` de una lista que vive en su lugar durante la
        // llamada (en un valor de la VM, o en el iterador de la VM al entrar).
        match unsafe { body.as_ref() } {
            Some(l) => native_tier::list_elem(l, i),
            None => NPeek::MISS,
        }
    })
}

/// Si un valor con caja es verdadero (`is_truthy`): 1 o 0.
pub(crate) extern "C" fn synsema_jit_truthy(ctx: *mut Ctx, v: *const SynValue) -> i64 {
    let mut t = 0i64;
    read(ctx, |_| {
        // SAFETY: como en `synsema_jit_index`.
        if let Some(v) = unsafe { v.as_ref() } {
            t = i64::from(native_tier::truthy(v));
        }
        NPeek { tag: TAG_OTHER, bits: 0, ptr: std::ptr::null() }
    });
    t
}

/// `length(v)` (F4.7c): el largo, o -1 si `v` no tiene (el código sale y la VM da el error).
pub(crate) extern "C" fn synsema_jit_length(ctx: *mut Ctx, v: *const SynValue) -> i64 {
    let mut len = -1i64;
    read(ctx, |_| {
        // SAFETY: como en `synsema_jit_index`.
        if let Some(n) = unsafe { v.as_ref() }.and_then(native_tier::length) {
            len = n;
        }
        NPeek { tag: TAG_OTHER, bits: 0, ptr: std::ptr::null() }
    });
    len
}

/// Una unidad compilada.
pub(crate) struct Compiled {
    /// La entrada `(ctx, *const i64) -> i64` (ya en memoria ejecutable, de sólo lectura).
    pub(crate) entry: *const u8,
    pub(crate) nparams: usize,
    pub(crate) ret: Kind,
    /// Un bucle (F4.2): los lugares que recibe la entrada, en orden, y lo que tienen que tener.
    pub(crate) inputs: Vec<(Place, NSeen)>,
    /// Las salidas de cada función.
    pub(crate) points: Vec<Vec<Point>>,
    /// F4.7b: los sitios de lectura (con sus cachés).
    pub(crate) sites: Vec<SiteIc>,
}

/// Un valor de tipo `k` a partir de sus palabras (ver `lower::words`) y su puntero (si tiene).
///
/// Clona lo que tiene caja: se llama al volver del código nativo, antes de que la VM escriba nada,
/// con los punteros que dejó una salida (valores vivos y en su lugar: ver el comienzo del módulo).
fn nval(k: Kind, w: &[i64], p: Option<i64>) -> NVal {
    match k {
        Kind::Int => NVal::Int(w[0]),
        Kind::Bool => NVal::Bool(w[0] != 0),
        Kind::Float => NVal::Float(f64::from_bits(w[0] as u64)),
        // F4.7: la etiqueta dice qué es (etiqueta, bits, `f64`; F4.7b: y el puntero).
        Kind::Any(_) => match w[0] {
            TAG_INT => NVal::Int(w[1]),
            TAG_BOOL => NVal::Bool(w[1] != 0),
            TAG_FLOAT => NVal::Float(f64::from_bits(w[2] as u64)),
            TAG_HOLE => NVal::Hole,
            TAG_LIST | TAG_MAP | TAG_OTHER => {
                let ptr = p.expect("puntero de un valor con caja") as usize as *const SynValue;
                // SAFETY: ver arriba; `check_pointers` verificó que el código generado sólo guarda
                // en la ranura de punteros direcciones que vinieron de la entrada o de una lectura.
                NVal::Value(unsafe { (*ptr).clone() })
            }
            _ => NVal::Nothing,
        },
        Kind::ListBody => {
            let ptr = p.expect("puntero de un iterador") as usize as *const ListRef;
            // SAFETY: como el caso anterior (la dirección de un `Rc` de una lista).
            NVal::List(unsafe { (*ptr).clone() })
        }
        Kind::Callee(f) => NVal::Callee(f),
        Kind::RangeFn => NVal::RangeFn,
        Kind::Builtin(w) => NVal::Builtin(w),
        Kind::Undef => NVal::Hole,
        _ => NVal::Nothing,
    }
}

impl NativeCode for Compiled {
    fn call(&self, cx: &mut NativeCx<'_>, args: &[i64]) -> NOutcome {
        assert_eq!(args.len(), self.nparams, "aridad de la entrada nativa");
        let mut sink: Vec<Raw> = Vec::new();
        let mut panic: Option<Box<dyn Any + Send>> = None;
        let mut ctx = Ctx {
            steps: std::ptr::from_mut::<u64>(cx.steps),
            depth: std::ptr::from_mut::<usize>(cx.depth).cast::<u64>(),
            // Un `AtomicBool` tiene la representación de un `u8` (documentado en `std`).
            cancel: std::ptr::from_ref::<AtomicBool>(cx.cancel).cast::<u8>(),
            max_depth: cx.max_depth as u64,
            status: 0,
            out_bits: 0,
            out_ptr: 0,
            sink: &mut sink,
            sites: self.sites.as_ptr(),
            nsites: self.sites.len(),
            panic: &mut panic,
        };
        // SAFETY: `entry` es la dirección de una función que compiló este crate con la firma
        // `(i64, i64) -> i64` en la convención por defecto de la plataforma (la de `extern "C"`),
        // en memoria que `cranelift-jit` pasó a lectura+ejecución y que no se libera mientras vive
        // el hilo (el módulo es del hilo, como este valor: `Compiled` no es `Send`). Los punteros de
        // `ctx` apuntan a datos vivos durante toda la llamada: los contadores del intérprete
        // (préstamos exclusivos de `cx`, que no se usan mientras tanto), el flag de cancelación
        // (que otro hilo puede escribir de a un byte: el código lo lee con una carga de un byte,
        // como el `load(Relaxed)` de la VM), `args` (con `nparams` palabras, recién verificado),
        // `sink`, los sitios y `panic`. Qué memoria toca el código generado lo acota
        // `lower::check_memory`.
        let r = unsafe {
            let f: extern "C" fn(*mut Ctx, *const i64) -> i64 = std::mem::transmute(self.entry);
            f(&mut ctx, args.as_ptr())
        };
        if let Some(p) = panic {
            resume_unwind(p);
        }
        if ctx.status == 0 {
            return NOutcome::Done(nval(self.ret, &[r], None));
        }
        // Del frame de más afuera al de más adentro.
        let frames = sink
            .into_iter()
            .rev()
            .map(|raw| {
                let p = &self.points[raw.func as usize][raw.point as usize];
                let (mut at, mut ap) = (0, 0);
                let values = p
                    .values
                    .iter()
                    .map(|&(place, k)| {
                        let n = words(k);
                        let w = if n == 0 { &[0i64, 0, 0][..] } else { &raw.vals[at..at + n] };
                        at += n;
                        let q = if ptr_words(k) == 1 {
                            ap += 1;
                            Some(raw.ptrs[ap - 1])
                        } else {
                            None
                        };
                        (place, nval(k, w, q))
                    })
                    .collect();
                NFrame { func: raw.func, pc: p.pc, values, call: p.call, planned: p.planned }
            })
            .collect();
        NOutcome::Deopt(frames)
    }

    fn inputs(&self) -> &[(Place, NSeen)] {
        &self.inputs
    }
}

// La etiqueta que no es ningún valor (una lectura que el camino rápido no hace) no puede coincidir
// con una de valor.
const _: () = assert!(TAG_MISS > TAG_OTHER);
