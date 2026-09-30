//! La vista del bytecode (`NUnit`) → Cranelift. Sin `unsafe`.
//!
//! Dos análisis sobre el código de la VM y después la traducción:
//! - **Tipos** (hacia adelante, punto fijo entre las funciones de la unidad): qué hay en cada
//!   registro y lugar de la ventana antes de cada instrucción. Los parámetros tienen lo que la
//!   entrada verifica (o, en una task llamada desde la unidad, lo que le pasan sus llamadas), el
//!   resto de los registros empieza en `nothing` (como la VM) y los lugares de la ventana, vacíos.
//!   Donde el tipo es estático el código nativo no lleva guardas; donde según el camino es uno u
//!   otro (`Any`, F4.7) lleva la guarda de la instrucción de la VM (la misma que su quickening):
//!   si no pasa, sale a la VM antes de la instrucción. Una instrucción cuyo tipo estático no es el
//!   que especializó la VM sale siempre a la VM.
//! - **Vivos** (hacia atrás, con los sucesores de la VM): qué valores hay que devolverle a la VM en
//!   cada salida. Lo que no está vivo la VM lo tiene vacío (nadie lo vuelve a leer).
//!
//! **Representación (F4.7):** cada lugar de la VM es, en el código nativo, tres variables de
//! Cranelift: su etiqueta (`TAG_*`), sus bits enteros (un `Int`, un `Bool`) y su `f64`. Cada
//! escritura define la etiqueta y la parte de su tipo; lo que nadie lee lo borra Cranelift. Un
//! lugar vacío (hueco) es la etiqueta `TAG_HOLE`: leerlo sale a la VM (que lo busca por nombre).
//!
//! Una unidad con algo que no se puede representar (una llamada que no es a la unidad, algo que
//! según el camino es una task o un número) no se compila: queda en la VM.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::types::{F64, I64, I8};
use cranelift_codegen::ir::{self, AbiParam, Block, BlockArg, InstBuilder, MemFlagsData, Opcode, StackSlot, StackSlotData, StackSlotKind, Value, ValueDef};
use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use synsema_core::native_tier::{NArith, NBuiltin, NCall, NCmp, NConst, NFArith, NFunc, NIns, NOpnd, NSeen, NUnary, NUnit, Place, Reg, DISCARD};
// Las etiquetas (las comparte core: sus lecturas las devuelven).
pub(crate) use synsema_core::native_tier::{TAG_ABSENT, TAG_BOOL, TAG_FLOAT, TAG_HOLE, TAG_INT, TAG_LIST, TAG_MAP, TAG_MISS, TAG_NOTHING, TAG_OTHER};

use crate::abi::{OFF_CANCEL, OFF_DEPTH, OFF_MAX_DEPTH, OFF_OUT_BITS, OFF_OUT_PTR, OFF_STATUS, OFF_STEPS};

/// Las funciones de `abi` que llama el código generado (declaradas en cada función).
#[derive(Clone, Copy)]
pub(crate) struct Helpers {
    /// `(ctx, func, point, vals, n, ptrs, np)`: la salida a la VM.
    pub deopt: ir::FuncRef,
    /// Las lecturas: sólo en una función con valores con caja (`has_boxed`); en una numérica no se
    /// declaran (cada declaración le cuesta a Cranelift al compilar) y un `Any` es sólo un escalar.
    pub reads: Option<Reads>,
    /// F4.8d: las escrituras, sólo en un bucle que escribe (`has_writes`).
    pub writes: Option<Writes>,
    /// F4.8d2: el host, sólo en un bucle con llamadas ajenas (`has_foreign`).
    pub host: Option<HostFns>,
}

/// Lo que el código generado le pide al host (F4.8d2).
#[derive(Clone, Copy)]
pub(crate) struct HostFns {
    /// `(ctx, sitio, etiquetas, bits, punteros) -> 0/1/2`: corre la instrucción del sitio (ver
    /// `ExecSite`); 0 siguió, 1 un `stop` cortó el bucle, 2 un error.
    pub exec: ir::FuncRef,
    /// `(ctx, lugar, v) -> dirección`: un valor prestado pasa a su lugar (por el host: después de una
    /// llamada ajena las direcciones de la entrada ya no valen).
    pub home: ir::FuncRef,
}

/// F4.8d2: una instrucción que corre el host: dónde está, cuántos argumentos le pasa el código (en los
/// búferes, antes de las globales, si las pasa) y qué lugares le devuelve después, en orden.
#[derive(Clone, Debug)]
pub(crate) struct ExecSite {
    pub pc: u32,
    pub nargs: u16,
    pub globals: u16,
    pub reload: Vec<Place>,
}

/// Cómo vuelve un lugar después de una llamada ajena.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reload {
    /// Entero (el resultado, una global: el código ajeno puede haberla cambiado).
    Full,
    /// Sólo su dirección, si tiene caja (un valor en su lugar que no cambió, pero la memoria se movió).
    Ptr,
    /// La lista de un iterador.
    Iter,
}

/// Un lugar como número para el host (`(clase << 32) | índice`: registro 0, ventana 1, global 2).
pub(crate) fn place_code(p: Place) -> i64 {
    match p {
        Place::Reg(r) => i64::from(r),
        Place::Local(k) => (1i64 << 32) | i64::from(k),
        Place::Global(g) => (2i64 << 32) | i64::from(g),
        Place::Iter(it, _) => (3i64 << 32) | i64::from(it),
    }
}

/// La etiqueta de un argumento que ya está en su registro (una función que cargó la VM).
pub(crate) const TAG_KEEP: i64 = -1;

/// Las escrituras de `abi` (F4.8d). Cada una devuelve 0 si no la hace (el código sale a la VM antes
/// de la instrucción).
#[derive(Clone, Copy)]
pub(crate) struct Writes {
    /// `(ctx, lugar, v) -> dirección`: un valor prestado pasa a su lugar (un registro o una global).
    pub home: ir::FuncRef,
    /// `(ctx, lugar, v) -> dirección`: lo mismo en un lugar de la ventana.
    pub home_local: ir::FuncRef,
    /// `(ctx, raíz) -> 0/1`: `PathRoot`.
    pub path_root: ir::FuncRef,
    /// `(ctx, cursor, idx_tag, idx_bits, idx_ptr, site) -> dirección`: `PathStep`.
    pub path_step: ir::FuncRef,
    /// `(ctx, cursor, idx_tag, idx_bits, idx_ptr, site, v_tag, v_bits, v_ptr) -> 0/1`: `PathSet`.
    pub path_set: ir::FuncRef,
    /// `(ctx, raíz, primer argumento, tag, bits, ptr) -> 0/1`: `AppendInPlace`.
    pub append: ir::FuncRef,
}


/// Las lecturas de valores con caja de `abi` (F4.7b).
#[derive(Clone, Copy)]
pub(crate) struct Reads {
    /// `(ctx, obj, idx_tag, idx_bits, idx_ptr, site) -> tag`: `x[i]`.
    pub index: ir::FuncRef,
    /// `(ctx, obj, site) -> tag`: `m.k`.
    pub prop: ir::FuncRef,
    /// `(ctx, obj) -> cuerpo`: la lista de un `each` (0 si no es una lista; el largo en `out_bits`).
    pub list_body: ir::FuncRef,
    /// `(ctx, cuerpo, i) -> tag`: el elemento `i`.
    pub list_elem: ir::FuncRef,
    /// `(ctx, v) -> 0/1`: si un valor con caja es verdadero.
    pub truthy: ir::FuncRef,
    /// `(ctx, v) -> largo` (-1 si no tiene: sale): `length(v)` (F4.7c).
    pub length: ir::FuncRef,
    /// `(ctx, obj, idx_tag, idx_bits, idx_ptr) -> tag`: `get(obj, idx, …)` (F4.8d2; `TAG_ABSENT`: el
    /// default).
    pub get: ir::FuncRef,
}

impl Helpers {
    /// Qué argumentos de cada función son punteros (para `check_pointers`), y si devuelve uno.
    fn pointer_args(&self, f: ir::FuncRef) -> Option<(&'static [usize], bool)> {
        if let Some(hf) = self.host {
            if f == hf.home {
                return Some((&[2], true));
            } else if f == hf.exec {
                // Los búferes son ranuras propias (se verifican aparte: ver `check_pointers`).
                return Some((&[], false));
            }
        }
        if let Some(w) = self.writes {
            if f == w.home || f == w.home_local {
                return Some((&[1, 2], true));
            } else if f == w.path_root {
                return Some((&[1], false));
            } else if f == w.path_step {
                return Some((&[1, 4], true));
            } else if f == w.path_set {
                return Some((&[1, 4, 8], false));
            } else if f == w.append {
                return Some((&[1, 2, 5], false));
            }
        }
        let r = self.reads?;
        if f == r.index {
            Some((&[1, 4], false))
        } else if f == r.prop || f == r.truthy || f == r.length {
            Some((&[1], false))
        } else if f == r.list_body {
            Some((&[1], true))
        } else if f == r.list_elem {
            Some((&[1], false))
        } else {
            None
        }
    }
}

/// Si la función `i` puede tener valores con caja: los lee (`GetIndex`, `GetProp`, `each` sobre una
/// lista) o le entran (un bucle con un lugar con caja). Si no, ningún `Any` tiene caja.
pub(crate) fn has_boxed(unit: &NUnit, i: usize, plan: &Plan) -> bool {
    unit.funcs[i].code.iter().any(|ins| matches!(ins, NIns::GetIndex { .. } | NIns::GetProp { .. } | NIns::EachList { .. }))
        || plan.inputs.iter().any(|(_, s)| boxed_seen(*s))
        || unit.funcs[i].params.iter().any(|s| boxed_seen(*s))
        || unit.funcs[i].globals.iter().any(|s| boxed_seen(*s))
        // F4.8d2: lo que devuelve una llamada ajena puede tener caja.
        || has_foreign(unit, i)
}

/// F4.8d: si la función es un bucle que escribe (un `set` con camino, `append` en el lugar): entonces
/// declara las escrituras y lo prestado que cruza una escritura pasa antes a su lugar.
pub(crate) fn has_writes(unit: &NUnit, i: usize) -> bool {
    unit.funcs[i].code.iter().any(|ins| matches!(ins, NIns::PathRoot { .. } | NIns::PathStep { .. } | NIns::PathSet { .. } | NIns::AppendPush { .. }))
}

/// F4.8d2: si la función es un bucle con llamadas ajenas (entonces corre con un host).
pub(crate) fn has_foreign(unit: &NUnit, i: usize) -> bool {
    unit.funcs[i].code.iter().any(|ins| matches!(ins, NIns::LoadForeign { .. } | NIns::CheckForeign { .. }))
}

/// Un valor con caja que entra prestado (la dirección de donde vive).
fn boxed_seen(s: NSeen) -> bool {
    matches!(s, NSeen::List | NSeen::Map | NSeen::Boxed | NSeen::ListIter)
}

/// El tipo estático de un registro o lugar de la ventana.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Todavía sin información (un resultado de una llamada que no se analizó).
    Bot,
    /// Un lugar de la ventana vacío (hueco).
    Undef,
    Nothing,
    Int,
    Bool,
    /// F4.7.
    Float,
    /// F4.7: según el camino, `nothing`, `Int`, `Bool` o `Float` (la etiqueta dice cuál) o, desde
    /// F4.7b, un valor con caja prestado de la VM (lista, mapa, otro: su dirección en el puntero);
    /// `true` si además puede ser un hueco.
    Any(bool),
    /// F4.7b: la primera parte de un iterador de una lista (dónde está su cuerpo).
    ListBody,
    /// La task de la función de la unidad.
    Callee(u32),
    /// El builtin `range` (F4.2b).
    RangeFn,
    /// F4.7c: un builtin intrínseco.
    Builtin(NBuiltin),
    /// F4.8d: el cursor de un `set` con camino: la dirección del lugar (la variable raíz, o uno de
    /// adentro de un contenedor) que el paso siguiente abre o la hoja escribe. Al salir, se clona (la
    /// VM tiene ahí una copia del contenedor).
    Cursor,
    /// F4.8d2: un valor que tiene la VM en el registro (una función que cargó el host para una
    /// llamada ajena); el código nativo no lo lee.
    Foreign,
    /// Según el camino, distinto: no se puede usar.
    Top,
}

/// Un valor (con su posible hueco) que la representación con etiqueta junta con otro.
fn value_kind(k: Kind) -> Option<bool> {
    match k {
        Kind::Nothing | Kind::Int | Kind::Bool | Kind::Float => Some(false),
        Kind::Any(h) => Some(h),
        Kind::Undef => Some(true),
        _ => None,
    }
}

fn join(a: Kind, b: Kind) -> Kind {
    match (a, b) {
        _ if a == b => a,
        (Kind::Bot, x) | (x, Kind::Bot) => x,
        _ => match (value_kind(a), value_kind(b)) {
            (Some(x), Some(y)) => Kind::Any(x || y),
            _ => Kind::Top,
        },
    }
}

/// Lo que queda después de leerlo con la guarda de hueco: nunca un hueco.
fn read_kind(k: Kind) -> Kind {
    match k {
        Kind::Any(_) => Kind::Any(false),
        k => k,
    }
}

fn const_kind(c: NConst) -> Kind {
    match c {
        NConst::Int(_) => Kind::Int,
        NConst::Bool(_) => Kind::Bool,
        NConst::Nothing => Kind::Nothing,
        NConst::Float(_) => Kind::Float,
    }
}

/// Lo que tenía un lugar al compilar un bucle (F4.2).
fn seen_kind(s: NSeen) -> Kind {
    match s {
        NSeen::Int => Kind::Int,
        NSeen::Bool => Kind::Bool,
        NSeen::Float => Kind::Float,
        NSeen::Nothing => Kind::Nothing,
        NSeen::Hole => Kind::Undef,
        NSeen::List | NSeen::Map | NSeen::Boxed => Kind::Any(false),
        NSeen::ListIter => Kind::ListBody,
        NSeen::Opaque => Kind::Top,
    }
}

/// La etiqueta de lo que tenía un lugar al entrar (un valor con caja: su clase).
fn seen_tag(s: NSeen) -> Option<i64> {
    Some(match s {
        NSeen::List => TAG_LIST,
        NSeen::Map => TAG_MAP,
        NSeen::Boxed => TAG_OTHER,
        _ => return None,
    })
}

/// La etiqueta de un valor de tipo estático (`None`: se lee de su variable).
fn static_tag(k: Kind) -> Option<i64> {
    Some(match k {
        // `Bot` en una instrucción a la que se llega: el resultado de una llamada que nunca vuelve
        // (sale siempre). Como un hueco: la guarda sale.
        Kind::Undef | Kind::Bot => TAG_HOLE,
        Kind::Nothing => TAG_NOTHING,
        Kind::Int => TAG_INT,
        Kind::Float => TAG_FLOAT,
        Kind::Bool => TAG_BOOL,
        Kind::Callee(_) | Kind::RangeFn | Kind::Builtin(_) | Kind::Foreign => TAG_OTHER,
        _ => return None,
    })
}

/// Cuántas palabras guarda una salida para un valor de este tipo (ver `abi::Compiled::call`): un
/// `Int`, un `Bool` o un `Float`, una; un `Any`, tres (etiqueta, bits, `f64`) más su puntero; la
/// lista de un iterador, su puntero; el resto, ninguna (el tipo ya dice cuál es). Los punteros van
/// en una ranura aparte (la que verifica `check_pointers`).
pub(crate) fn words(k: Kind) -> usize {
    match k {
        Kind::Int | Kind::Bool | Kind::Float => 1,
        Kind::Any(_) => 3,
        _ => 0,
    }
}

/// Los punteros que guarda una salida para un valor de este tipo.
pub(crate) fn ptr_words(k: Kind) -> usize {
    match k {
        Kind::Any(_) | Kind::ListBody | Kind::Cursor => 1,
        _ => 0,
    }
}

/// Una salida a la VM: dónde sigue, qué valores le devuelve (con su tipo, en el orden en que el
/// código nativo los guarda) y, si el frame esperaba a su llamado, esa llamada.
#[derive(Clone, Debug)]
pub(crate) struct Point {
    pub pc: u32,
    pub values: Vec<(Place, Kind)>,
    pub call: Option<NCall>,
    /// El fin de un bucle nativo (F4.2), no una desoptimización.
    pub planned: bool,
}

impl Point {
    /// Cuántas palabras guarda el código nativo.
    pub fn stored(&self) -> usize {
        self.values.iter().map(|(_, k)| words(*k)).sum()
    }

    /// Cuántos punteros.
    pub fn ptrs(&self) -> usize {
        self.values.iter().map(|(_, k)| ptr_words(*k)).sum()
    }
}

/// Lo que dejan los análisis de una función.
pub(crate) struct Plan {
    /// Tipos antes de cada instrucción (`None`: no se llega).
    state: Vec<Option<Vec<Kind>>>,
    /// Vivos antes de cada instrucción (sucesores de la VM).
    live: Vec<Vec<bool>>,
    /// El código nativo sale siempre antes de esta instrucción.
    trap: Vec<bool>,
    pub ret: Kind,
    /// Los tipos de los parámetros (F4.7: `Int`, `Float` o `Bool`).
    pub params: Vec<Kind>,
    pub points: Vec<Point>,
    /// Un bucle (F4.2): los lugares que el código toca, en el orden de los parámetros de su
    /// función, con lo que tienen que tener al entrar.
    pub inputs: Vec<(Place, NSeen)>,
    /// F4.7b (para `check_pointers`): los parámetros de la entrada que son punteros (índices entre
    /// los parámetros del bloque de entrada) y las ranuras de punteros de las salidas.
    pub ptr_params: Vec<usize>,
    pub ptr_slots: Vec<StackSlot>,
    /// F4.8d (un bucle que escribe): antes de cada instrucción, lo que pasa a su lugar (lo prestado
    /// que cruza una escritura); los lugares cuya dirección entra (después de `inputs`), y la
    /// procedencia de cada lugar antes de cada instrucción (`Some(q)`: su puntero es el lugar de `q`).
    pub homes_at: Vec<Vec<usize>>,
    pub homes: Vec<Place>,
    pub prov: Vec<Option<Vec<Option<usize>>>>,
    /// F4.8d2: las instrucciones que corre el host (en el orden de los sitios del código).
    pub exec_sites: Vec<ExecSite>,
    /// F4.8d2: los búferes de esos sitios (las ranuras de punteros se verifican en `check_pointers`).
    pub exec_ptr_slots: Vec<StackSlot>,
}

impl Plan {
    /// Cuántos parámetros (además del contexto) tiene la función.
    pub fn nargs(&self, f: &NFunc) -> usize {
        if f.osr.is_some() {
            self.inputs.len() + self.homes.len()
        } else {
            // F4.8b: las globales que lee una task, después de sus parámetros.
            f.nparams as usize + f.globals.len()
        }
    }
}

/// Qué sigue a una instrucción en el código nativo.
enum Next {
    Fall,
    Jump(u32),
    Branch(u32, u32),
    /// `give`, `End` o salida a la VM.
    Stop,
}

/// Una llamada de la unidad vista por el análisis de tipos: a qué función y con qué argumentos.
type Calls = Vec<(usize, Vec<Kind>)>;

struct Func<'u> {
    f: &'u NFunc,
    unit: &'u NUnit,
    nregs: usize,
    nvars: usize,
}

impl<'u> Func<'u> {
    fn new(f: &'u NFunc, unit: &'u NUnit) -> Self {
        let nvars = f.nregs as usize + f.nlocals as usize + f.nglobals as usize + 4 * f.niters as usize;
        Func { f, unit, nregs: f.nregs as usize, nvars }
    }

    /// La parte `k` del iterador `it` (0 `valid`, 1 `next`, 2 `hi`, 3 `step`).
    fn iter_var(&self, it: u16, k: u8) -> usize {
        self.nregs + self.f.nlocals as usize + self.f.nglobals as usize + 4 * it as usize + k as usize
    }

    /// Las variables de los iteradores desde `it` (los que un `each` nuevo o terminado deja vacíos).
    fn iters_from(&self, it: u16) -> std::ops::Range<usize> {
        self.iter_var(it.min(self.f.niters), 0)..self.nvars
    }

    fn locals(&self, first: u16, n: u16) -> std::ops::Range<usize> {
        self.nregs + first as usize..self.nregs + first as usize + n as usize
    }

    fn global_var(&self, g: u16) -> usize {
        self.nregs + self.f.nlocals as usize + g as usize
    }

    fn var_of(&self, p: Place) -> usize {
        match p {
            Place::Reg(r) => r as usize,
            Place::Local(k) => self.nregs + k as usize,
            Place::Global(g) => self.global_var(g),
            Place::Iter(it, k) => self.iter_var(it, k),
        }
    }

    fn place_of(&self, v: usize) -> Place {
        let nl = self.f.nlocals as usize;
        if v < self.nregs {
            Place::Reg(v as Reg)
        } else if v < self.nregs + nl {
            Place::Local((v - self.nregs) as u16)
        } else if v < self.nregs + nl + self.f.nglobals as usize {
            Place::Global((v - self.nregs - nl) as u16)
        } else {
            let k = v - self.nregs - nl - self.f.nglobals as usize;
            Place::Iter((k / 4) as u16, (k % 4) as u8)
        }
    }

    /// Un bucle: los lugares que lee o escribe (lo demás pasa sin tocarse).
    fn touched(&self) -> Vec<bool> {
        let mut t = vec![false; self.nvars];
        for pc in 0..self.f.code.len() {
            if matches!(self.f.code[pc], NIns::Leave { .. }) {
                continue;
            }
            let (uses, defs, _) = self.uses_defs(pc);
            for v in uses.into_iter().chain(defs) {
                t[v] = true;
            }
        }
        t
    }

    fn opnd_kind(&self, st: &[Kind], o: NOpnd) -> Kind {
        match o {
            NOpnd::Reg(r) | NOpnd::Copy(r) => st[r as usize],
            NOpnd::Const(c) => const_kind(c),
            NOpnd::Local(k) => st[self.nregs + k as usize],
            NOpnd::Global(g) => st[self.global_var(g)],
        }
    }

    /// Lo que la VM lee de un operando (para los vivos).
    fn opnd_var(&self, o: NOpnd) -> Option<usize> {
        match o {
            NOpnd::Reg(r) | NOpnd::Copy(r) => Some(r as usize),
            NOpnd::Local(k) => Some(self.nregs + k as usize),
            NOpnd::Global(g) => Some(self.global_var(g)),
            NOpnd::Const(_) => None,
        }
    }

    /// Un `Reg` se consume: queda `nothing`.
    fn consumed(o: NOpnd) -> Option<usize> {
        match o {
            NOpnd::Reg(r) => Some(r as usize),
            _ => None,
        }
    }

    /// Los registros que una llamada deja vacíos en el llamador: la ventana del llamado.
    fn call_window(&self, func: usize, args: Reg, n: u16) -> std::ops::Range<usize> {
        let callee = &self.unit.funcs[func];
        let lo = args as usize;
        let hi = (lo + (callee.nregs as usize).max(n as usize)).min(self.nregs);
        lo..hi.max(lo)
    }

    /// Los tipos después de la instrucción `pc`. `Err` = la unidad no se compila; `trap` = sale
    /// siempre a la VM antes de ella. Las llamadas a la unidad quedan en `calls`.
    fn step(&self, pc: usize, st: &mut [Kind], rets: &[Kind], calls: &mut Calls, trap: &mut bool) -> Result<Next, ()> {
        let set = |st: &mut [Kind], r: Reg, k: Kind| {
            if r != DISCARD {
                st[r as usize] = k;
            }
        };
        // Leer un valor: un hueco lo busca la VM por nombre (sale; si puede serlo o no según el
        // camino, lo decide la guarda); algo que depende del camino entre una task y un valor no
        // se puede representar.
        let read = |k: Kind, trap: &mut bool| -> Result<Kind, ()> {
            match k {
                Kind::Top => Err(()),
                Kind::Undef => {
                    *trap = true;
                    Ok(k)
                }
                _ => Ok(read_kind(k)),
            }
        };
        // Un operando numérico: `Some(true)` si puede serlo (con guarda si es `Any`), `None` si no
        // se sabe todavía (`Bot`), `Some(false)` si nunca (la VM desoptimiza: sale siempre).
        let numeric = |k: Kind, ok: &[Kind]| -> Result<Option<bool>, ()> {
            match k {
                Kind::Top => Err(()),
                Kind::Bot => Ok(None),
                Kind::Any(_) => Ok(Some(true)),
                k => Ok(Some(ok.contains(&k))),
            }
        };
        Ok(match self.f.code[pc] {
            NIns::Steps(_) | NIns::StepsCancel(_) | NIns::CheckCancel | NIns::Nop => Next::Fall,
            NIns::Const { dst, v } => {
                set(st, dst, const_kind(v));
                Next::Fall
            }
            NIns::Move { dst, src } => {
                let k = read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                set(st, dst, k);
                Next::Fall
            }
            NIns::Drop { r } => {
                set(st, r, Kind::Nothing);
                Next::Fall
            }
            NIns::IntArith { dst, a, b, .. } | NIns::IntCmp { dst, a, b, .. } => {
                let (ka, kb) = (numeric(self.opnd_kind(st, a), &[Kind::Int])?, numeric(self.opnd_kind(st, b), &[Kind::Int])?);
                let out = if matches!(self.f.code[pc], NIns::IntArith { .. }) { Kind::Int } else { Kind::Bool };
                match (ka, kb) {
                    (Some(false), _) | (_, Some(false)) => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                    (None, _) | (_, None) => set(st, dst, Kind::Bot),
                    _ => set(st, dst, out),
                }
                Next::Fall
            }
            NIns::IntCmpJump { a, b, to, .. } => {
                let (ka, kb) = (numeric(self.opnd_kind(st, a), &[Kind::Int])?, numeric(self.opnd_kind(st, b), &[Kind::Int])?);
                if ka == Some(false) || kb == Some(false) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                Next::Branch(pc as u32 + 2, to)
            }
            NIns::FloatArith { dst, op, a, b } => {
                let nums = [Kind::Int, Kind::Float];
                let (sa, sb) = (self.opnd_kind(st, a), self.opnd_kind(st, b));
                let (ka, kb) = (numeric(sa, &nums)?, numeric(sb, &nums)?);
                // Dos `Int` con `+ - *`: la guarda de la VM no pasa (es `IntArith`).
                if ka == Some(false) || kb == Some(false) || (op != NFArith::Div && sa == Kind::Int && sb == Kind::Int) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                set(st, dst, if ka.is_none() || kb.is_none() { Kind::Bot } else { Kind::Float });
                Next::Fall
            }
            NIns::NumCmp { dst, a, b, .. } => {
                let nums = [Kind::Int, Kind::Float];
                let (ka, kb) = (numeric(self.opnd_kind(st, a), &nums)?, numeric(self.opnd_kind(st, b), &nums)?);
                if ka == Some(false) || kb == Some(false) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                set(st, dst, if ka.is_none() || kb.is_none() { Kind::Bot } else { Kind::Bool });
                Next::Fall
            }
            NIns::Unary { dst, op, a } => {
                let k = read(self.opnd_kind(st, a), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                let out = match (op, k) {
                    (_, Kind::Bot) => Kind::Bot,
                    (NUnary::Neg, Kind::Int | Kind::Float) => k,
                    (NUnary::Neg, Kind::Any(_)) => Kind::Any(false),
                    // `-` de otra cosa: el error lo arma la VM.
                    (NUnary::Neg, _) => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                    (NUnary::Not, _) => Kind::Bool,
                };
                if let Some(r) = Self::consumed(a) {
                    st[r] = Kind::Nothing;
                }
                set(st, dst, out);
                Next::Fall
            }
            NIns::ToBool { dst, src } => {
                let k = read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                set(st, dst, if k == Kind::Bot { Kind::Bot } else { Kind::Bool });
                Next::Fall
            }
            NIns::JumpIfFalsy { src, to } => {
                read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                Next::Branch(pc as u32 + 1, to)
            }
            NIns::Jump { to } => Next::Jump(to),
            NIns::LoadLocal { dst, slot } => {
                let k = read(st[self.nregs + slot as usize], trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                set(st, dst, k);
                Next::Fall
            }
            NIns::LetLocal { src, slot, dst } | NIns::SetLocal { src, slot, dst } => {
                if matches!(self.f.code[pc], NIns::SetLocal { .. }) {
                    // `set` a un hueco: la VM va por nombre.
                    read(st[self.nregs + slot as usize], trap)?;
                }
                let k = read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                st[self.nregs + slot as usize] = k;
                set(st, dst, k);
                Next::Fall
            }
            NIns::LoadCallee { dst, func } => {
                set(st, dst, Kind::Callee(func));
                Next::Fall
            }
            // F4.7c: un builtin intrínseco (un argumento; si no, el error lo arma la VM).
            // F4.8d2: una llamada ajena (la corre la VM entera, por el host): los argumentos, valores o una
            // función que cargó la VM; después, lo que devuelve es cualquier cosa, los registros desde
            // los argumentos quedan vacíos (la ventana del llamado) y las globales del bucle pueden haber
            // cambiado (el código ajeno las ve): pasan a `Any`.
            NIns::Call { dst, func, args, n } if st[func as usize] == Kind::Foreign => {
                for k in 0..n as usize {
                    let a = st[args as usize + k];
                    if value_kind(a).is_none() && !matches!(a, Kind::Foreign | Kind::Bot) {
                        return Err(());
                    }
                }
                st[func as usize] = Kind::Nothing;
                for r in args as usize..self.nregs {
                    st[r] = Kind::Nothing;
                }
                for g in 0..self.f.nglobals {
                    let v = self.global_var(g);
                    if st[v] != Kind::Bot {
                        st[v] = join(st[v], Kind::Any(false));
                    }
                }
                set(st, dst, Kind::Any(false));
                Next::Fall
            }
            NIns::Call { dst, func, args, n } if st[func as usize] == Kind::Builtin(NBuiltin::Get) => {
                // F4.8d2: `get(c, k)`/`get(c, k, d)`: una colección que puede ser un mapa o una lista y
                // una clave que puede ser un texto o un `Int` (lo demás lo hace la VM: sale siempre).
                // El default es un valor que el código representa.
                let mut ks = Vec::with_capacity(n as usize);
                for k in 0..n as usize {
                    ks.push(read(st[args as usize + k], trap)?);
                }
                if *trap {
                    return Ok(Next::Stop);
                }
                let bad = !(2..=3).contains(&n)
                    || !matches!(ks[0], Kind::Any(_) | Kind::Bot)
                    || !matches!(ks[1], Kind::Any(_) | Kind::Int | Kind::Bot)
                    || ks.get(2).is_some_and(|k| value_kind(*k).is_none() || *k == Kind::Undef);
                if bad {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                st[func as usize] = Kind::Nothing;
                for k in 0..n as usize {
                    st[args as usize + k] = Kind::Nothing;
                }
                set(st, dst, if ks.contains(&Kind::Bot) { Kind::Bot } else { Kind::Any(false) });
                Next::Fall
            }
            NIns::Call { dst, func, args, n } if matches!(st[func as usize], Kind::Builtin(_)) => {
                let Kind::Builtin(w) = st[func as usize] else { unreachable!("intrínseco") };
                let k = if n == 1 { st[args as usize] } else { Kind::Undef };
                if k == Kind::Top {
                    return Err(());
                }
                let out = match (w, k) {
                    (_, Kind::Bot) => Kind::Bot,
                    (NBuiltin::Length, Kind::Any(_)) => Kind::Int,
                    (NBuiltin::Sqrt, Kind::Int | Kind::Float | Kind::Any(_)) => Kind::Float,
                    (NBuiltin::Abs, Kind::Int | Kind::Float) => k,
                    (NBuiltin::Abs, Kind::Any(_)) => Kind::Any(false),
                    (NBuiltin::Float, Kind::Int | Kind::Float | Kind::Bool | Kind::Any(_)) => Kind::Float,
                    // Otra cosa (un texto a `sqrt`, un número a `length`, …): el builtin la resuelve
                    // o da su error, en la VM.
                    _ => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                };
                st[func as usize] = Kind::Nothing;
                st[args as usize] = Kind::Nothing;
                set(st, dst, out);
                Next::Fall
            }
            NIns::Call { dst, func, args, n } => {
                let Kind::Callee(target) = st[func as usize] else {
                    return if st[func as usize] == Kind::Bot { Ok(Next::Stop) } else { Err(()) };
                };
                let callee = &self.unit.funcs[target as usize];
                if callee.nparams != n {
                    return Err(());
                }
                let mut kinds = Vec::with_capacity(n as usize);
                for i in 0..n as usize {
                    let k = st[args as usize + i];
                    if !matches!(k, Kind::Int | Kind::Float | Kind::Bool | Kind::Bot) {
                        return Err(());
                    }
                    kinds.push(k);
                }
                calls.push((target as usize, kinds));
                st[func as usize] = Kind::Nothing;
                for r in self.call_window(target as usize, args, n) {
                    st[r] = Kind::Nothing;
                }
                set(st, dst, rets[target as usize]);
                Next::Fall
            }
            NIns::Give { src } | NIns::End { src } => {
                read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                Next::Stop
            }
            NIns::SetGlobal { src, g, dst } | NIns::LetGlobal { src, g, dst } => {
                let v = self.global_var(g);
                if matches!(self.f.code[pc], NIns::SetGlobal { .. }) {
                    // `set` a una global vacía: la VM la busca afuera.
                    read(st[v], trap)?;
                }
                let k = read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                st[v] = k;
                set(st, dst, k);
                Next::Fall
            }
            NIns::Scalar { src } => {
                match self.opnd_kind(st, src) {
                    Kind::Top => return Err(()),
                    // Una global vacía: la VM la busca afuera (y podría ser una lista). Si puede
                    // estarlo o no según el camino, la guarda de hueco.
                    Kind::Undef if matches!(src, NOpnd::Global(_)) => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                    _ => {}
                }
                Next::Fall
            }
            NIns::RangeFn { dst } => {
                set(st, dst, Kind::RangeFn);
                Next::Fall
            }
            NIns::LoadBuiltin { dst, which } => {
                set(st, dst, Kind::Builtin(which));
                Next::Fall
            }
            // Si no es el builtin `range`, la llamada de siempre (que el nivel nativo no hace).
            NIns::IsRange { src, to } => match st[src as usize] {
                Kind::RangeFn => Next::Fall,
                Kind::Top => return Err(()),
                Kind::Bot => Next::Stop,
                _ => Next::Jump(to),
            },
            NIns::EachRange { first, n, it } => {
                if n == 0 || n > 3 || it >= self.f.niters {
                    return Err(());
                }
                for i in 0..n as usize {
                    match st[first as usize + i] {
                        Kind::Top => return Err(()),
                        // `Any`: con la guarda de `Int`.
                        Kind::Int | Kind::Bot | Kind::Any(_) => {}
                        // Otro tipo: lo resuelve la VM (o es el error de `range`).
                        _ => {
                            *trap = true;
                            return Ok(Next::Stop);
                        }
                    }
                }
                for i in 0..n as usize {
                    st[first as usize + i] = Kind::Nothing;
                }
                for v in self.iters_from(it) {
                    st[v] = Kind::Undef;
                }
                for k in 0..4 {
                    st[self.iter_var(it, k)] = Kind::Int;
                }
                Next::Fall
            }
            NIns::EachNext { it, slot, exit } => {
                // Un `range` (la vuelta es un `Int`) o una lista (F4.7b: un elemento, de cualquier tipo).
                let item = match st[self.iter_var(it, 0)] {
                    Kind::Int => Kind::Int,
                    Kind::ListBody => Kind::Any(false),
                    Kind::Top => return Err(()),
                    _ => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                };
                // (En la salida el lugar no se escribe, pero lo que sigue es el `EachEndV` que lo
                // suelta: el tipo de acá no se ve.)
                st[self.nregs + slot as usize] = item;
                Next::Branch(pc as u32 + 1, exit)
            }
            NIns::GetIndex { dst, obj, idx, .. } => {
                let ko = read(self.opnd_kind(st, obj), trap)?;
                let ki = match idx {
                    Some(i) => read(self.opnd_kind(st, i), trap)?,
                    None => Kind::Nothing,
                };
                if *trap {
                    return Ok(Next::Stop);
                }
                // Un número como colección, o un índice que no es un `Int` ni puede ser una clave:
                // el camino rápido de la VM no lo hace (sale siempre).
                if !matches!(ko, Kind::Any(_) | Kind::Bot) || matches!(ki, Kind::Float | Kind::Bool | Kind::Callee(_) | Kind::RangeFn | Kind::ListBody) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                for o in std::iter::once(obj).chain(idx) {
                    if let Some(r) = Self::consumed(o) {
                        st[r] = Kind::Nothing;
                    }
                }
                set(st, dst, if ko == Kind::Bot || ki == Kind::Bot { Kind::Bot } else { Kind::Any(false) });
                Next::Fall
            }
            NIns::GetProp { dst, obj, .. } => {
                let ko = read(self.opnd_kind(st, obj), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if !matches!(ko, Kind::Any(_) | Kind::Bot) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(obj) {
                    st[r] = Kind::Nothing;
                }
                set(st, dst, if ko == Kind::Bot { Kind::Bot } else { Kind::Any(false) });
                Next::Fall
            }
            NIns::EachList { src, it } => {
                if it >= self.f.niters {
                    return Err(());
                }
                let k = read(self.opnd_kind(st, src), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                if !matches!(k, Kind::Any(_)) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                if let Some(r) = Self::consumed(src) {
                    st[r] = Kind::Nothing;
                }
                for v in self.iters_from(it) {
                    st[v] = Kind::Undef;
                }
                st[self.iter_var(it, 0)] = Kind::ListBody;
                for k in 1..4 {
                    st[self.iter_var(it, k)] = Kind::Int;
                }
                Next::Fall
            }
            NIns::EachStep { head, first, n } => {
                for v in self.locals(first, n) {
                    st[v] = Kind::Undef;
                }
                Next::Jump(head)
            }
            NIns::EachEnd { it, first, n } => {
                for v in self.locals(first, n).chain(self.iters_from(it)) {
                    st[v] = Kind::Undef;
                }
                Next::Fall
            }
            NIns::Trap { .. } | NIns::Leave { .. } => {
                *trap = true;
                Next::Stop
            }
            // F4.8d: las escrituras (en un bucle). Lo que el camino rápido de la VM no hace (una raíz
            // que no es una lista o un mapa, un paso o una hoja de otro tipo) sale a la VM.
            NIns::PathRoot { c, root } => {
                let k = read(self.opnd_kind(st, root), trap)?;
                if *trap {
                    return Ok(Next::Stop);
                }
                match k {
                    Kind::Any(_) => set(st, c, Kind::Cursor),
                    Kind::Bot => set(st, c, Kind::Bot),
                    _ => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                }
                Next::Fall
            }
            NIns::PathStep { c, idx, .. } | NIns::PathSet { c, idx, .. } => {
                match st[c as usize] {
                    Kind::Cursor => {}
                    Kind::Bot => return Ok(Next::Stop),
                    _ => return Err(()),
                }
                if let Some(i) = idx {
                    let ki = read(self.opnd_kind(st, i), trap)?;
                    if *trap {
                        return Ok(Next::Stop);
                    }
                    if !matches!(ki, Kind::Int | Kind::Any(_) | Kind::Nothing | Kind::Bot) {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                    if let Some(r) = Self::consumed(i) {
                        st[r] = Kind::Nothing;
                    }
                }
                if let NIns::PathSet { src, dst, .. } = self.f.code[pc] {
                    let k = read(self.opnd_kind(st, src), trap)?;
                    if *trap {
                        return Ok(Next::Stop);
                    }
                    if value_kind(k).is_none() && k != Kind::Bot {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                    if let Some(r) = Self::consumed(src) {
                        st[r] = Kind::Nothing;
                    }
                    st[c as usize] = Kind::Nothing;
                    set(st, dst, read_kind(k));
                }
                Next::Fall
            }
            NIns::LoadForeign { dst } => {
                set(st, dst, Kind::Foreign);
                Next::Fall
            }
            NIns::CheckForeign { func } => {
                match st[func as usize] {
                    Kind::Foreign => {}
                    Kind::Bot => return Ok(Next::Stop),
                    _ => return Err(()),
                }
                Next::Fall
            }
            NIns::AppendPush { dst, func, args, root } => {
                match st[func as usize] {
                    Kind::Builtin(NBuiltin::Append) => {}
                    Kind::Bot => return Ok(Next::Stop),
                    _ => return Err(()),
                }
                let kr = read(self.opnd_kind(st, root), trap)?;
                let (k0, k1) = (read(st[args as usize], trap)?, read(st[args as usize + 1], trap)?);
                if *trap {
                    return Ok(Next::Stop);
                }
                if !matches!(kr, Kind::Any(_)) || !matches!(k0, Kind::Any(_)) || (value_kind(k1).is_none() && k1 != Kind::Bot) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                st[func as usize] = Kind::Nothing;
                st[args as usize] = Kind::Nothing;
                st[args as usize + 1] = Kind::Nothing;
                set(st, dst, Kind::Any(false));
                Next::Fall
            }
        })
    }

    /// Los tipos antes de cada instrucción, dónde sale siempre, el valor que devuelve y las
    /// llamadas a la unidad (con los tipos de sus argumentos). `params`: los de esta función.
    #[allow(clippy::type_complexity)]
    fn kinds(&self, rets: &[Kind], params: &[Kind]) -> Result<(Vec<Option<Vec<Kind>>>, Vec<bool>, Kind, Calls), ()> {
        let n = self.f.code.len();
        let mut state: Vec<Option<Vec<Kind>>> = vec![None; n];
        let start = match &self.f.osr {
            // Un bucle: lo que tenía cada lugar que toca; lo que no toca, sin información (pasa).
            Some(o) => {
                let touched = self.touched();
                let init = (0..self.nvars).map(|v| if touched[v] { seen_kind(o.init[v]) } else { Kind::Bot }).collect();
                state[o.head as usize] = Some(init);
                o.head as usize
            }
            None => {
                let mut init = vec![Kind::Nothing; self.nvars];
                for (k, p) in init.iter_mut().zip(params) {
                    *k = *p;
                }
                for k in init.iter_mut().skip(self.nregs) {
                    *k = Kind::Undef;
                }
                // F4.8b: las globales que lee la task (leídas al entrar, con lo que tenían al compilar).
                for (g, s) in self.f.globals.iter().enumerate() {
                    init[self.global_var(g as u16)] = seen_kind(*s);
                }
                state[0] = Some(init);
                0
            }
        };
        let mut trap = vec![false; n];
        let mut ret = Kind::Bot;
        let mut calls = Vec::new();
        let mut work = vec![start];
        while let Some(pc) = work.pop() {
            let mut st = state[pc].clone().expect("estado");
            let mut t = false;
            let next = self.step(pc, &mut st, rets, &mut calls, &mut t)?;
            trap[pc] = t;
            let mut flow = |to: usize, st: &Vec<Kind>, work: &mut Vec<usize>| -> Result<(), ()> {
                if to >= n {
                    return Err(());
                }
                let changed = match &mut state[to] {
                    Some(old) => {
                        let mut ch = false;
                        for (o, k) in old.iter_mut().zip(st) {
                            let j = join(*o, *k);
                            if j != *o {
                                *o = j;
                                ch = true;
                            }
                        }
                        ch
                    }
                    slot @ None => {
                        *slot = Some(st.clone());
                        true
                    }
                };
                if changed {
                    work.push(to);
                }
                Ok(())
            };
            match next {
                Next::Fall => flow(pc + 1, &st, &mut work)?,
                Next::Jump(to) => flow(to as usize, &st, &mut work)?,
                Next::Branch(a, b) => {
                    flow(a as usize, &st, &mut work)?;
                    flow(b as usize, &st, &mut work)?;
                }
                Next::Stop => {
                    if !t {
                        if let NIns::Give { src } | NIns::End { src } = self.f.code[pc] {
                            ret = join(ret, read_kind(self.opnd_kind(&st, src)));
                        }
                    }
                }
            }
        }
        Ok((state, trap, ret, calls))
    }

    /// Lecturas y escrituras de la instrucción según la VM, y sus sucesores en la VM.
    fn uses_defs(&self, pc: usize) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
        let mut uses = Vec::new();
        let mut defs = Vec::new();
        let op = |uses: &mut Vec<usize>, defs: &mut Vec<usize>, o: NOpnd| {
            if let Some(v) = self.opnd_var(o) {
                uses.push(v);
            }
            if let Some(r) = Self::consumed(o) {
                defs.push(r);
            }
        };
        let dst = |defs: &mut Vec<usize>, r: Reg| {
            if r != DISCARD {
                defs.push(r as usize);
            }
        };
        let fall = vec![pc + 1];
        let succ = match self.f.code[pc] {
            NIns::Steps(_) | NIns::StepsCancel(_) | NIns::CheckCancel | NIns::Nop => fall,
            NIns::Const { dst: d, .. } | NIns::LoadCallee { dst: d, .. } => {
                dst(&mut defs, d);
                fall
            }
            NIns::Drop { r } => {
                defs.push(r as usize);
                fall
            }
            NIns::Move { dst: d, src } | NIns::Unary { dst: d, a: src, .. } | NIns::ToBool { dst: d, src } | NIns::GetProp { dst: d, obj: src, .. } => {
                op(&mut uses, &mut defs, src);
                dst(&mut defs, d);
                fall
            }
            // La VM consume los dos operandos (`opnd`).
            NIns::GetIndex { dst: d, obj, idx, .. } => {
                op(&mut uses, &mut defs, obj);
                if let Some(i) = idx {
                    op(&mut uses, &mut defs, i);
                }
                dst(&mut defs, d);
                fall
            }
            NIns::EachList { src, it } => {
                op(&mut uses, &mut defs, src);
                defs.extend(self.iters_from(it));
                fall
            }
            // El camino rápido de la VM no consume los operandos (los mira sin moverlos).
            NIns::IntArith { dst: d, a, b, .. }
            | NIns::IntCmp { dst: d, a, b, .. }
            | NIns::FloatArith { dst: d, a, b, .. }
            | NIns::NumCmp { dst: d, a, b, .. } => {
                uses.extend(self.opnd_var(a));
                uses.extend(self.opnd_var(b));
                dst(&mut defs, d);
                fall
            }
            NIns::Trap { dst: d, a, b } => {
                op(&mut uses, &mut defs, a);
                op(&mut uses, &mut defs, b);
                dst(&mut defs, d);
                fall
            }
            NIns::IntCmpJump { a, b, to, .. } => {
                uses.extend(self.opnd_var(a));
                uses.extend(self.opnd_var(b));
                vec![pc + 2, to as usize]
            }
            NIns::JumpIfFalsy { src, to } => {
                op(&mut uses, &mut defs, src);
                vec![pc + 1, to as usize]
            }
            NIns::Jump { to } => vec![to as usize],
            NIns::LoadLocal { dst: d, slot } => {
                uses.push(self.nregs + slot as usize);
                dst(&mut defs, d);
                fall
            }
            NIns::LetLocal { src, slot, dst: d } | NIns::SetLocal { src, slot, dst: d } => {
                if matches!(self.f.code[pc], NIns::SetLocal { .. }) {
                    uses.push(self.nregs + slot as usize);
                }
                op(&mut uses, &mut defs, src);
                defs.push(self.nregs + slot as usize);
                dst(&mut defs, d);
                fall
            }
            NIns::Call { dst: d, func, args, n } => {
                uses.push(func as usize);
                uses.extend((0..n as usize).map(|i| args as usize + i));
                defs.push(func as usize);
                // La ventana del llamado (si no se sabe cuál es, sólo los argumentos).
                let hi = (args as usize + n as usize).min(self.nregs);
                defs.extend(args as usize..hi);
                dst(&mut defs, d);
                fall
            }
            NIns::Give { src } | NIns::End { src } => {
                uses.extend(self.opnd_var(src));
                Vec::new()
            }
            NIns::SetGlobal { src, g, dst: d } | NIns::LetGlobal { src, g, dst: d } => {
                if matches!(self.f.code[pc], NIns::SetGlobal { .. }) {
                    uses.push(self.global_var(g));
                }
                op(&mut uses, &mut defs, src);
                defs.push(self.global_var(g));
                dst(&mut defs, d);
                fall
            }
            NIns::Scalar { src } => {
                uses.extend(self.opnd_var(src));
                fall
            }
            NIns::RangeFn { dst: d } | NIns::LoadBuiltin { dst: d, .. } => {
                dst(&mut defs, d);
                fall
            }
            NIns::IsRange { src, to } => {
                uses.push(src as usize);
                vec![pc + 1, to as usize]
            }
            NIns::EachRange { first, n, it } => {
                let args = first as usize..first as usize + n as usize;
                uses.extend(args.clone());
                defs.extend(args);
                defs.extend(self.iters_from(it));
                fall
            }
            NIns::EachNext { it, slot, exit } => {
                uses.extend((0..4).map(|k| self.iter_var(it, k)));
                defs.push(self.nregs + slot as usize);
                vec![pc + 1, exit as usize]
            }
            NIns::EachStep { head, first, n } => {
                defs.extend(self.locals(first, n));
                vec![head as usize]
            }
            NIns::EachEnd { it, first, n } => {
                defs.extend(self.locals(first, n));
                defs.extend(self.iters_from(it));
                fall
            }
            // La VM sigue desde acá: puede leer cualquier cosa.
            NIns::Leave { .. } => {
                uses.extend(0..self.nvars);
                Vec::new()
            }
            NIns::PathRoot { c, root } => {
                uses.extend(self.opnd_var(root));
                defs.push(c as usize);
                fall
            }
            NIns::PathStep { c, idx, .. } => {
                uses.push(c as usize);
                if let Some(i) = idx {
                    op(&mut uses, &mut defs, i);
                }
                defs.push(c as usize);
                fall
            }
            NIns::PathSet { c, idx, src, dst: d, .. } => {
                uses.push(c as usize);
                if let Some(i) = idx {
                    op(&mut uses, &mut defs, i);
                }
                op(&mut uses, &mut defs, src);
                defs.push(c as usize);
                dst(&mut defs, d);
                fall
            }
            NIns::LoadForeign { dst: d } => {
                dst(&mut defs, d);
                fall
            }
            NIns::CheckForeign { func } => {
                uses.push(func as usize);
                fall
            }
            NIns::AppendPush { dst: d, func, args, root } => {
                uses.extend([func as usize, args as usize, args as usize + 1]);
                uses.extend(self.opnd_var(root));
                defs.extend([func as usize, args as usize, args as usize + 1]);
                dst(&mut defs, d);
                fall
            }
        };
        (uses, defs, succ)
    }

    /// Vivos antes de cada instrucción.
    fn liveness(&self) -> Vec<Vec<bool>> {
        let n = self.f.code.len();
        let info: Vec<_> = (0..n).map(|pc| self.uses_defs(pc)).collect();
        let mut live = vec![vec![false; self.nvars]; n];
        let mut changed = true;
        while changed {
            changed = false;
            for pc in (0..n).rev() {
                let (uses, defs, succ) = &info[pc];
                let mut out = vec![false; self.nvars];
                for &s in succ {
                    if s < n {
                        for (o, l) in out.iter_mut().zip(&live[s]) {
                            *o |= *l;
                        }
                    }
                }
                for &d in defs {
                    out[d] = false;
                }
                for &u in uses {
                    out[u] = true;
                }
                if out != live[pc] {
                    live[pc] = out;
                    changed = true;
                }
            }
        }
        live
    }
}

/// La procedencia de cada lugar (F4.8d): `Some(q)`, su puntero es el lugar de `q` en la VM (`q` mismo:
/// el valor está en su lugar, con su cuenta; otro: prestado de ahí); `None`, otra cosa (prestado de
/// adentro de un contenedor, o un escalar).
type Prov = Vec<Option<usize>>;

impl Func<'_> {
    /// Si la instrucción escribe (F4.8d) o es una llamada ajena (F4.8d2): lo prestado que la cruza tiene
    /// que tener dueño antes.
    fn clobbers(&self, pc: usize, st: &[Kind]) -> bool {
        matches!(self.f.code[pc], NIns::PathRoot { .. } | NIns::PathStep { .. } | NIns::PathSet { .. } | NIns::AppendPush { .. }) || self.foreign_call(pc, st)
    }

    /// F4.8d2: una llamada ajena.
    fn foreign_call(&self, pc: usize, st: &[Kind]) -> bool {
        matches!(self.f.code[pc], NIns::Call { func, .. } if st[func as usize] == Kind::Foreign)
    }

    /// La procedencia después de la instrucción `pc` (sin lo que pasa a su lugar antes de ella).
    fn prov_step(&self, pc: usize, st: &[Kind], cur: &mut Prov) {
        let (_, defs, _) = self.uses_defs(pc);
        // F4.8d2: después de una llamada ajena el resultado está en su registro y las globales en su
        // lugar (el host las devuelve con sus direcciones nuevas).
        if let (true, NIns::Call { dst, args, .. }) = (self.foreign_call(pc, st), self.f.code[pc]) {
            for d in defs {
                cur[d] = None;
            }
            for r in args as usize..self.nregs {
                cur[r] = None;
            }
            for g in 0..self.f.nglobals {
                let v = self.global_var(g);
                cur[v] = Some(v);
            }
            if dst != DISCARD {
                cur[dst as usize] = Some(dst as usize);
            }
            return;
        }
        let of = |cur: &Prov, o: NOpnd| self.opnd_var(o).and_then(|v| cur[v]);
        let (target, p): (Vec<usize>, Option<usize>) = match self.f.code[pc] {
            NIns::Move { dst, src } => (if dst != DISCARD { vec![dst as usize] } else { Vec::new() }, of(cur, src)),
            NIns::LetLocal { src, slot, dst } | NIns::SetLocal { src, slot, dst } => {
                let mut t = vec![self.nregs + slot as usize];
                if dst != DISCARD {
                    t.push(dst as usize);
                }
                (t, of(cur, src))
            }
            NIns::SetGlobal { src, g, dst } | NIns::LetGlobal { src, g, dst } => {
                let mut t = vec![self.global_var(g)];
                if dst != DISCARD {
                    t.push(dst as usize);
                }
                (t, of(cur, src))
            }
            NIns::PathSet { src, dst, .. } => (if dst != DISCARD { vec![dst as usize] } else { Vec::new() }, of(cur, src)),
            // El resultado es la raíz (su lugar).
            NIns::AppendPush { dst, root, .. } => (if dst != DISCARD { vec![dst as usize] } else { Vec::new() }, self.opnd_var(root)),
            _ => (Vec::new(), None),
        };
        for d in defs {
            cur[d] = None;
        }
        for t in target {
            cur[t] = p;
        }
    }

    /// F4.8d: en un bucle que escribe, qué pasa a su lugar antes de cada instrucción (lo prestado que
    /// está vivo al llegar a una escritura) y la procedencia antes de cada una. `None` si no se puede:
    /// un iterador de una lista armado en el bucle (prestado) que cruza una escritura.
    #[allow(clippy::type_complexity)]
    fn provenance(&self, state: &[Option<Vec<Kind>>], trap: &[bool], live: &[Vec<bool>]) -> Option<(Vec<Vec<usize>>, Vec<Option<Prov>>)> {
        let n = self.f.code.len();
        let o = self.f.osr.as_ref()?;
        let touched = self.touched();
        let mut prov: Vec<Option<Prov>> = vec![None; n];
        prov[o.head as usize] = Some(
            (0..self.nvars)
                .map(|v| (touched[v] && matches!(o.init[v], NSeen::List | NSeen::Map | NSeen::Boxed | NSeen::ListIter)).then_some(v))
                .collect(),
        );
        let homed = |pc: usize, cur: &Prov| -> Vec<usize> {
            let Some(st) = &state[pc] else { return Vec::new() };
            if trap[pc] || !self.clobbers(pc, st) {
                return Vec::new();
            }
            // Lo que la escritura misma consume (el primer argumento de `append`, el valor y el índice
            // de la hoja) muere ahí: la VM lo suelta antes de escribir (si no, `append` copiaría la lista
            // en cada vuelta) y lo que se guarda, se clona.
            let (uses, defs, _) = self.uses_defs(pc);
            (0..self.nvars)
                .filter(|&v| live[pc][v] && matches!(st[v], Kind::Any(_)) && cur[v] != Some(v) && !(uses.contains(&v) && defs.contains(&v)))
                .collect()
        };
        let mut work = vec![o.head as usize];
        while let Some(pc) = work.pop() {
            if state[pc].is_none() || trap[pc] {
                continue;
            }
            let mut cur = prov[pc].clone().expect("procedencia");
            for v in homed(pc, &cur) {
                cur[v] = Some(v);
            }
            self.prov_step(pc, state[pc].as_ref().expect("estado"), &mut cur);
            for s in self.uses_defs(pc).2 {
                if s >= n || state[s].is_none() {
                    continue;
                }
                let changed = match &mut prov[s] {
                    Some(old) => {
                        let mut ch = false;
                        for (a, b) in old.iter_mut().zip(&cur) {
                            if *a != *b && a.is_some() {
                                *a = None;
                                ch = true;
                            }
                        }
                        ch
                    }
                    slot @ None => {
                        *slot = Some(cur.clone());
                        true
                    }
                };
                if changed {
                    work.push(s);
                }
            }
        }
        let mut homes_at = vec![Vec::new(); n];
        for pc in 0..n {
            let Some(cur) = &prov[pc] else { continue };
            homes_at[pc] = homed(pc, cur);
            // Un iterador de una lista armado en el bucle, vivo al escribir: no tiene su propia cuenta.
            if let Some(st) = &state[pc] {
                if self.clobbers(pc, st) && !trap[pc] && (0..self.nvars).any(|v| live[pc][v] && st[v] == Kind::ListBody && cur[v] != Some(v)) {
                    return None;
                }
                // F4.8d2: el cursor de un `set` con camino que cruza una llamada ajena (la memoria se
                // puede mover): no.
                if self.foreign_call(pc, st) && !trap[pc] && pc + 1 < n && (0..self.nvars).any(|v| live[pc + 1][v] && st[v] == Kind::Cursor) {
                    return None;
                }
            }
        }
        Some((homes_at, prov))
    }
}

/// Cuántos lugares puede tocar un bucle nativo (son los parámetros de su función).
const MAX_INPUTS: usize = 96;

/// Un parámetro que el código nativo recibe como una palabra.
fn param_ok(k: Kind) -> bool {
    matches!(k, Kind::Int | Kind::Float | Kind::Bool)
}

/// Los análisis de toda la unidad; `None` si no se puede compilar.
pub(crate) fn plan(unit: &NUnit) -> Option<Vec<Plan>> {
    let funcs: Vec<Func> = unit.funcs.iter().map(|f| Func::new(f, unit)).collect();
    for (i, f) in funcs.iter().enumerate() {
        if f.f.code.is_empty() || f.f.nparams as usize > f.nregs || f.f.nparams > 8 || f.f.globals.len() > 8 {
            return None;
        }
        // Las globales de una task: sólo la de la entrada, y tantas como dice `nglobals`.
        if f.f.osr.is_none() && (f.f.globals.len() != f.f.nglobals as usize || (i != 0 && !f.f.globals.is_empty())) {
            return None;
        }
        // Sólo la función 0 puede ser un bucle (las demás son tasks que se llaman).
        if let Some(o) = &f.f.osr {
            if i != 0 || o.init.len() != f.nvars || o.head as usize >= f.f.code.len() {
                return None;
            }
        }
    }
    // Los parámetros: los de la función 0 (una task) los fija la entrada; los de las demás salen de
    // sus llamadas (punto fijo, junto con lo que devuelve cada función).
    let mut params: Vec<Vec<Kind>> = Vec::with_capacity(funcs.len());
    for (i, f) in funcs.iter().enumerate() {
        let np = f.f.nparams as usize;
        if i == 0 && f.f.osr.is_none() {
            if f.f.params.len() != np {
                return None;
            }
            params.push(f.f.params.iter().map(|s| seen_kind(*s)).collect());
        } else {
            params.push(vec![Kind::Bot; np]);
        }
    }
    let fixed0 = funcs[0].f.osr.is_none();
    let mut rets = vec![Kind::Bot; funcs.len()];
    let mut results = None;
    for _ in 0..16 {
        let mut out = Vec::with_capacity(funcs.len());
        for (f, p) in funcs.iter().zip(&params) {
            out.push(f.kinds(&rets, p).ok()?);
        }
        let new_rets: Vec<Kind> = out.iter().map(|(_, _, r, _)| *r).collect();
        let mut new_params = params.clone();
        for (_, _, _, calls) in &out {
            for (target, kinds) in calls {
                for (p, k) in new_params[*target].iter_mut().zip(kinds) {
                    *p = join(*p, *k);
                }
            }
        }
        // La task de la entrada no cambia sus parámetros: una llamada recursiva con otros tipos
        // no se puede compilar.
        if fixed0 && new_params[0] != params[0] {
            return None;
        }
        if new_rets == rets && new_params == params {
            results = Some(out);
            break;
        }
        rets = new_rets;
        params = new_params;
    }
    let results = results?;
    // Un bucle cuyo salto hacia atrás no se alcanza sin pasar por una salida a la VM (en cada vuelta
    // algo que el nivel nativo no hace: una llamada a un builtin, una escritura, un texto que se
    // agrega): una vuelta entera nunca correría en nativo. No se compila (compilarlo, entrar y salir
    // en cada vuelta cuesta más que la VM; medido: nbody y text_concat del arnés).
    if let (Some(o), Some((state, trap, _, _))) = (&funcs[0].f.osr, results.first()) {
        let code = &funcs[0].f.code;
        let jumps_back = |pc: usize| match code[pc] {
            NIns::Jump { to } | NIns::EachStep { head: to, .. } if (to as usize) <= pc => Some(to),
            _ => None,
        };
        let completes = |pc: usize| state[pc].is_some() && !trap[pc];
        let back = (0..code.len()).any(|pc| jumps_back(pc) == Some(o.head) && completes(pc));
        // Lo mismo con un bucle de adentro: si nunca completa una vuelta, cada vuelta de afuera que
        // lo corre sale (salvo que corra cero veces).
        let inner_dead = (0..code.len()).any(|pc| jumps_back(pc).is_some_and(|t| t != o.head && t > o.head) && !completes(pc));
        if !back || inner_dead {
            return None;
        }
    }
    // Lo que devuelve una función (una palabra) tiene que tener un tipo estático.
    if rets.iter().any(|r| matches!(r, Kind::Top | Kind::Any(_))) {
        return None;
    }
    for (i, ps) in params.iter_mut().enumerate() {
        for (k, p) in ps.iter_mut().enumerate() {
            // Una task que no se llama desde ningún lugar al que se llegue: no importa.
            if *p == Kind::Bot {
                *p = Kind::Int;
            }
            // F4.8b: la task de la entrada puede recibir un valor con caja, prestado (la dirección del
            // argumento, que vive en la VM o en el builtin que llama mientras corre el código).
            let boxed = i == 0 && fixed0 && funcs[0].f.params.get(k).is_some_and(|s| boxed_seen(*s));
            if !param_ok(*p) && !boxed {
                return None;
            }
        }
    }
    let mut plans = Vec::with_capacity(funcs.len());
    for ((f, (state, trap, ret, _)), params) in funcs.iter().zip(results).zip(params) {
        let live = f.liveness();
        let mut inputs = Vec::new();
        if let Some(o) = &f.f.osr {
            let touched = f.touched();
            for v in 0..f.nvars {
                if !touched[v] {
                    continue;
                }
                // Un valor con caja entra prestado (F4.7b: el código nativo no toca sus cuentas de
                // referencias; al salir, lo que queda vivo se clona). Lo que no representa, no.
                if o.init[v] == NSeen::Opaque {
                    return None;
                }
                inputs.push((f.place_of(v), o.init[v]));
            }
            if inputs.len() > MAX_INPUTS {
                return None;
            }
        }
        // F4.8d: un bucle que escribe: qué pasa a su lugar antes de cada escritura.
        let (mut homes_at, mut homes, mut prov) = (vec![Vec::new(); f.f.code.len()], Vec::new(), vec![None; f.f.code.len()]);
        if f.f.osr.is_some() && (0..f.f.code.len()).any(|pc| state[pc].as_ref().is_some_and(|st| f.clobbers(pc, st)) && !trap[pc]) {
            let (h, p) = f.provenance(&state, &trap, &live)?;
            let mut hv: Vec<usize> = h.iter().flatten().copied().collect();
            hv.sort_unstable();
            hv.dedup();
            // Un iterador no pasa a su lugar (ver `provenance`).
            if hv.iter().any(|v| matches!(f.place_of(*v), Place::Iter(..))) {
                return None;
            }
            // F4.8d2: con llamadas ajenas, el host pone lo prestado en su lugar (sin direcciones de la
            // entrada, que una llamada invalida).
            if !f.f.code.iter().any(|i| matches!(i, NIns::LoadForeign { .. } | NIns::CheckForeign { .. })) {
                homes = hv.into_iter().map(|v| f.place_of(v)).collect();
            }
            homes_at = h;
            prov = p;
            if inputs.len() + homes.len() > MAX_INPUTS {
                return None;
            }
        }
        plans.push(Plan {
            state,
            live,
            trap,
            ret,
            params,
            points: Vec::new(),
            inputs,
            ptr_params: Vec::new(),
            ptr_slots: Vec::new(),
            homes_at,
            homes,
            prov,
            exec_sites: Vec::new(),
            exec_ptr_slots: Vec::new(),
        });
    }
    Some(plans)
}

// =============================================================================================
// Traducción
// =============================================================================================

/// Los valores de un frame para una salida: los vivos con su tipo (lo que no se sabe qué es no va:
/// la VM lo tiene vacío). `None` si alguno vivo no se puede representar.
fn frame_values(f: &Func, st: &[Kind], live: &[bool], skip: impl Fn(usize) -> bool) -> Option<Vec<(Place, Kind)>> {
    let mut out = Vec::new();
    for v in 0..f.nvars {
        if !live[v] || skip(v) {
            continue;
        }
        let place = f.place_of(v);
        // F4.8b: una global que lee una task no vuelve a la VM (no la escribió; la VM la lee de su
        // entorno).
        if f.f.osr.is_none() && matches!(place, Place::Global(_)) {
            continue;
        }
        match st[v] {
            Kind::Top => return None,
            Kind::Bot => {}
            // Un lugar vacío (un `let` de una vuelta que se soltó, un iterador terminado): la VM
            // también lo tiene que tener vacío.
            k => out.push((place, k)),
        }
    }
    Some(out)
}

/// Dónde está cada cosa del contexto (ver `abi::Ctx`).
fn ctx_load(b: &mut FunctionBuilder, ctx: Value, off: i32) -> Value {
    b.ins().load(I64, MemFlagsData::trusted(), ctx, off)
}

/// La salida pendiente de emitir (su bloque y su punto).
struct Exit {
    block: Block,
    point: u32,
}

/// Las variables de Cranelift de un lugar de la VM: etiqueta, bits, `f64` y (F4.7b) puntero.
#[derive(Clone, Copy)]
struct Parts {
    tag: Variable,
    bits: Variable,
    f: Variable,
    ptr: Variable,
}

/// Qué partes de un lugar se usan en alguna parte de la función: la etiqueta sólo si en algún
/// punto es `Any`; los bits si es un `Int`, un `Bool`, `nothing` o `Any`; el `f64` si es un `Float` o
/// `Any`. Lo que no se usa no se define (menos trabajo para Cranelift al compilar).
#[derive(Clone, Copy, Default)]
struct Need {
    tag: bool,
    bits: bool,
    f: bool,
    ptr: bool,
}

fn needs(nvars: usize, state: &[Option<Vec<Kind>>]) -> Vec<Need> {
    let mut out = vec![Need::default(); nvars];
    for st in state.iter().flatten() {
        for (n, k) in out.iter_mut().zip(st) {
            match k {
                Kind::Any(_) => *n = Need { tag: true, bits: true, f: true, ptr: true },
                Kind::ListBody | Kind::Cursor => n.ptr = true,
                Kind::Float => n.f = true,
                Kind::Int | Kind::Bool | Kind::Nothing => n.bits = true,
                _ => {}
            }
        }
    }
    out
}

/// Leer y escribir lugares y operandos (ver "Representación" arriba).
struct Vars<'a> {
    p: Vec<Parts>,
    need: Vec<Need>,
    f: &'a Func<'a>,
    ctx: Value,
    h: Helpers,
}

impl Vars<'_> {
    fn var(&self, o: NOpnd) -> Option<Parts> {
        self.f.opnd_var(o).map(|v| self.p[v])
    }

    /// La etiqueta de un operando (una constante si su tipo es estático).
    fn tag(&self, b: &mut FunctionBuilder, st: &[Kind], o: NOpnd) -> Value {
        match static_tag(self.f.opnd_kind(st, o)) {
            Some(t) => b.ins().iconst(I64, t),
            None => b.use_var(self.var(o).expect("un Any es una variable").tag),
        }
    }

    /// Sus bits enteros (un `Int`, un `Bool`; `nothing` es 0).
    fn bits(&self, b: &mut FunctionBuilder, o: NOpnd) -> Value {
        match o {
            NOpnd::Const(c) => b.ins().iconst(
                I64,
                match c {
                    NConst::Int(x) => x,
                    NConst::Bool(x) => i64::from(x),
                    NConst::Nothing => 0,
                    NConst::Float(x) => x as i64,
                },
            ),
            _ => b.use_var(self.var(o).expect("variable").bits),
        }
    }

    /// Su puntero (sólo con caja; si no, 0).
    fn ptr(&self, b: &mut FunctionBuilder, st: &[Kind], o: NOpnd) -> Value {
        match self.f.opnd_kind(st, o) {
            Kind::Any(_) | Kind::ListBody | Kind::Cursor => b.use_var(self.var(o).expect("variable").ptr),
            _ => b.ins().iconst(I64, 0),
        }
    }

    /// Un valor que devolvió una lectura (`tag`, y sus bits y puntero en el contexto) a `dst`, que
    /// pasa a ser `Any`.
    fn put_read(&self, b: &mut FunctionBuilder, dst: usize, tag: Value) {
        let bits = ctx_load(b, self.ctx, OFF_OUT_BITS);
        let ptr = ctx_load(b, self.ctx, OFF_OUT_PTR);
        let f = b.ins().bitcast(F64, MemFlagsData::new(), bits);
        b.def_var(self.p[dst].tag, tag);
        b.def_var(self.p[dst].bits, bits);
        b.def_var(self.p[dst].f, f);
        b.def_var(self.p[dst].ptr, ptr);
    }

    /// Su `f64` (sólo si es un `Float`).
    fn float(&self, b: &mut FunctionBuilder, o: NOpnd) -> Value {
        match o {
            NOpnd::Const(NConst::Float(x)) => b.ins().f64const(f64::from_bits(x)),
            NOpnd::Const(_) => b.ins().f64const(0.0),
            _ => b.use_var(self.var(o).expect("variable").f),
        }
    }

    /// Un valor sin caja: si la variable también tiene punteros, el suyo pasa a 0 (las lecturas de un
    /// `Any` —`length`, índices, propiedades— miran el puntero, no la etiqueta: uno viejo sería el de
    /// un valor que quizás ya no existe).
    fn put_tag(&self, b: &mut FunctionBuilder, v: usize, t: i64) {
        if self.need[v].tag {
            let x = b.ins().iconst(I64, t);
            b.def_var(self.p[v].tag, x);
        }
        if self.need[v].ptr {
            let z = b.ins().iconst(I64, 0);
            b.def_var(self.p[v].ptr, z);
        }
    }

    fn put_bits(&self, b: &mut FunctionBuilder, v: usize, x: Value) {
        if self.need[v].bits {
            b.def_var(self.p[v].bits, x);
        }
    }

    fn put_int(&self, b: &mut FunctionBuilder, v: usize, x: Value) {
        self.put_tag(b, v, TAG_INT);
        self.put_bits(b, v, x);
    }

    fn put_bool(&self, b: &mut FunctionBuilder, v: usize, x: Value) {
        self.put_tag(b, v, TAG_BOOL);
        self.put_bits(b, v, x);
    }

    fn put_float(&self, b: &mut FunctionBuilder, v: usize, x: Value) {
        self.put_tag(b, v, TAG_FLOAT);
        if self.need[v].f {
            b.def_var(self.p[v].f, x);
        }
    }

    /// `nothing` (también un registro consumido): los bits en 0, así su veracidad es la de un 0.
    fn put_nothing(&self, b: &mut FunctionBuilder, v: usize) {
        self.put_tag(b, v, TAG_NOTHING);
        if self.need[v].bits {
            let z = b.ins().iconst(I64, 0);
            b.def_var(self.p[v].bits, z);
        }
    }

    /// Un hueco. Los bits también en 0: si no, el valor de la vuelta anterior se arrastraría como
    /// parámetro de bloque por todo el bucle (dos instrucciones por vuelta, medido).
    fn put_hole(&self, b: &mut FunctionBuilder, v: usize) {
        self.put_tag(b, v, TAG_HOLE);
        if self.need[v].bits {
            let z = b.ins().iconst(I64, 0);
            b.def_var(self.p[v].bits, z);
        }
    }

    /// Una task de la unidad o el builtin `range` (el tipo estático dice cuál).
    fn put_other(&self, b: &mut FunctionBuilder, v: usize) {
        self.put_tag(b, v, TAG_OTHER);
    }

    /// Un valor con los bits del ABI (una palabra: un `Float` en sus bits) y tipo estático `k`.
    fn put_word(&self, b: &mut FunctionBuilder, v: usize, k: Kind, x: Value) {
        match k {
            Kind::Int => self.put_int(b, v, x),
            Kind::Bool => self.put_bool(b, v, x),
            Kind::Float => {
                let f = b.ins().bitcast(F64, MemFlagsData::new(), x);
                self.put_float(b, v, f);
            }
            Kind::Nothing => self.put_nothing(b, v),
            Kind::Undef => self.put_hole(b, v),
            _ => self.put_other(b, v),
        }
    }

    /// Un valor de tipo estático `k` como la palabra del ABI.
    fn word(&self, b: &mut FunctionBuilder, st: &[Kind], o: NOpnd) -> Value {
        match self.f.opnd_kind(st, o) {
            Kind::Float => {
                let f = self.float(b, o);
                b.ins().bitcast(I64, MemFlagsData::new(), f)
            }
            Kind::Int | Kind::Bool => self.bits(b, o),
            _ => b.ins().iconst(I64, 0),
        }
    }

    /// `dst = src` con el tipo de `src` (el hueco ya lo descartó la guarda).
    fn copy(&self, b: &mut FunctionBuilder, st: &[Kind], src: NOpnd, dst: usize) {
        match self.f.opnd_kind(st, src) {
            Kind::Int => {
                let x = self.bits(b, src);
                self.put_int(b, dst, x);
            }
            Kind::Bool => {
                let x = self.bits(b, src);
                self.put_bool(b, dst, x);
            }
            Kind::Float => {
                let x = self.float(b, src);
                self.put_float(b, dst, x);
            }
            Kind::Nothing => self.put_nothing(b, dst),
            Kind::Undef => self.put_hole(b, dst),
            Kind::Any(_) => {
                let p = self.var(src).expect("un Any es una variable");
                let (t, x, f, q) = (b.use_var(p.tag), b.use_var(p.bits), b.use_var(p.f), b.use_var(p.ptr));
                // El destino es `Any` después de esto: usa sus cuatro partes.
                b.def_var(self.p[dst].tag, t);
                b.def_var(self.p[dst].bits, x);
                b.def_var(self.p[dst].f, f);
                b.def_var(self.p[dst].ptr, q);
            }
            _ => self.put_other(b, dst),
        }
    }

    /// F4.8d: un valor para una escritura de `abi`: su etiqueta, sus bits (un `Float`, los de su `f64`)
    /// y su puntero (con caja; si no, 0).
    fn value_parts(&self, b: &mut FunctionBuilder, st: &[Kind], o: NOpnd) -> (Value, Value, Value) {
        let k = self.f.opnd_kind(st, o);
        let t = self.tag(b, st, o);
        let bits = match k {
            Kind::Float => {
                let x = self.float(b, o);
                b.ins().bitcast(I64, MemFlagsData::new(), x)
            }
            Kind::Any(_) => {
                let x = self.float(b, o);
                let fb = b.ins().bitcast(I64, MemFlagsData::new(), x);
                let ib = self.bits(b, o);
                let isf = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_FLOAT);
                b.ins().select(isf, fb, ib)
            }
            Kind::Int | Kind::Bool => self.bits(b, o),
            _ => b.ins().iconst(I64, 0),
        };
        let p = self.ptr(b, st, o);
        (t, bits, p)
    }

    /// F4.8d: el índice de un paso o de la hoja (`None`: la clave del sitio).
    fn index_parts(&self, b: &mut FunctionBuilder, st: &[Kind], idx: Option<NOpnd>) -> (Value, Value, Value) {
        match idx {
            Some(o) => (self.tag(b, st, o), self.bits(b, o), self.ptr(b, st, o)),
            None => (b.ins().iconst(I64, TAG_NOTHING), b.ins().iconst(I64, 0), b.ins().iconst(I64, 0)),
        }
    }

    fn consume(&self, b: &mut FunctionBuilder, o: NOpnd) {
        if let NOpnd::Reg(r) = o {
            self.put_nothing(b, r as usize);
        }
    }

    /// Si es verdadero (`is_truthy`), como un `I8`.
    fn truthy(&self, b: &mut FunctionBuilder, st: &[Kind], o: NOpnd) -> Value {
        match self.f.opnd_kind(st, o) {
            Kind::Int | Kind::Bool => {
                let x = self.bits(b, o);
                b.ins().icmp_imm_s(IntCC::NotEqual, x, 0)
            }
            Kind::Float => {
                let x = self.float(b, o);
                let z = b.ins().f64const(0.0);
                // `x != 0.0`: NaN es verdadero, `-0.0` falso.
                b.ins().fcmp(FloatCC::NotEqual, x, z)
            }
            Kind::Nothing | Kind::Undef => b.ins().iconst(I8, 0),
            Kind::Any(_) => {
                let t = self.tag(b, st, o);
                let x = self.bits(b, o);
                let f = self.float(b, o);
                let z = b.ins().f64const(0.0);
                let tf = b.ins().fcmp(FloatCC::NotEqual, f, z);
                let ti = b.ins().icmp_imm_s(IntCC::NotEqual, x, 0);
                let isf = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_FLOAT);
                let scalar = b.ins().select(isf, tf, ti);
                // Sin valores con caja en la función, un `Any` es un escalar.
                let Some(reads) = self.h.reads else { return scalar };
                // Un valor con caja (F4.7b): lo dice `is_truthy` (una lista vacía es falsa, …).
                let boxed = b.ins().icmp_imm_s(IntCC::SignedGreaterThanOrEqual, t, TAG_LIST);
                let q = self.ptr(b, st, o);
                let call = b.create_block();
                let join = b.create_block();
                b.append_block_param(join, I8);
                b.ins().brif(boxed, call, &[], join, &[BlockArg::Value(scalar)]);
                b.seal_block(call);
                b.switch_to_block(call);
                let r = b.ins().call(reads.truthy, &[self.ctx, q]);
                let r = b.inst_results(r)[0];
                let t = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
                b.ins().jump(join, &[BlockArg::Value(t)]);
                b.seal_block(join);
                b.switch_to_block(join);
                b.block_params(join)[0]
            }
            _ => b.ins().iconst(I8, 1),
        }
    }
}

/// Un salto a `ex` si `bad` (un `I8`), y sigue en un bloque nuevo.
fn exit_if(b: &mut FunctionBuilder, bad: Value, ex: Block) {
    let ok = b.create_block();
    b.ins().brif(bad, ex, &[], ok, &[]);
    b.seal_block(ok);
    b.switch_to_block(ok);
}

/// `tag` no es ninguna de `tags`: salida.
fn guard_tags(b: &mut FunctionBuilder, tag: Value, tags: &[i64], ex: Block) {
    let mut ok = b.ins().iconst(I8, 0);
    for t in tags {
        let e = b.ins().icmp_imm_s(IntCC::Equal, tag, *t);
        ok = b.ins().bor(ok, e);
    }
    let bad = b.ins().bxor_imm_u(ok, 1);
    exit_if(b, bad, ex);
}

/// Un operando entero: con la guarda de `Int` si es `Any` (entonces `ex` es la salida).
fn int_opnd(b: &mut FunctionBuilder, vs: &Vars, st: &[Kind], o: NOpnd, ex: Option<Block>) -> Value {
    if vs.f.opnd_kind(st, o) != Kind::Int {
        let t = vs.tag(b, st, o);
        guard_tags(b, t, &[TAG_INT], ex.expect("salida de la guarda"));
    }
    vs.bits(b, o)
}

/// Si algún operando no es un número de tipo estático (`Any`, o `Bot`: el resultado de una llamada
/// que no vuelve): lleva guarda y hace falta la salida.
fn dynamic(f: &Func, st: &[Kind], os: &[NOpnd]) -> bool {
    os.iter().any(|o| !matches!(f.opnd_kind(st, *o), Kind::Int | Kind::Float))
}

/// Un operando numérico (`Int` o `Float`, con la guarda si es `Any`): si es `Float` (un `I8`, o
/// `None` si no se sabe hasta correr: `Some` constante si el tipo es estático), sus bits enteros y
/// su `f64` (el que tenga sentido según eso).
struct Num {
    isf: Value,
    is_float: Option<bool>,
    int: Value,
    f: Value,
}

fn num_opnd(b: &mut FunctionBuilder, vs: &Vars, st: &[Kind], o: NOpnd, ex: Option<Block>) -> Num {
    match vs.f.opnd_kind(st, o) {
        Kind::Int => {
            let int = vs.bits(b, o);
            let isf = b.ins().iconst(I8, 0);
            let f = b.ins().fcvt_from_sint(F64, int);
            Num { isf, is_float: Some(false), int, f }
        }
        Kind::Float => {
            let f = vs.float(b, o);
            let isf = b.ins().iconst(I8, 1);
            let int = b.ins().iconst(I64, 0);
            Num { isf, is_float: Some(true), int, f }
        }
        _ => {
            let t = vs.tag(b, st, o);
            guard_tags(b, t, &[TAG_INT, TAG_FLOAT], ex.expect("salida de la guarda"));
            let int = vs.bits(b, o);
            let fv = vs.float(b, o);
            let isf = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_FLOAT);
            let fi = b.ins().fcvt_from_sint(F64, int);
            let f = b.ins().select(isf, fv, fi);
            Num { isf, is_float: None, int, f }
        }
    }
}

/// `(<, ==, >)` entre un entero y un float, EXACTO como `cmp_i64_float` (sin pasar el entero a
/// f64): NaN no es ninguno; fuera de ±2^63 el float está por encima o por debajo de todo entero; si
/// no, se compara con su parte entera (`t`, exacta) y, si es igual, con su parte fraccionaria. Sin
/// `floor` (que en x86 sin SSE4.1 sería una llamada a la biblioteca) y con la conversión que satura
/// (nunca atrapa).
fn cmp_int_float(b: &mut FunctionBuilder, i: Value, f: Value) -> (Value, Value, Value) {
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    let nan = b.ins().fcmp(FloatCC::Unordered, f, f);
    let hi = b.ins().f64const(TWO_63);
    let lo = b.ins().f64const(-TWO_63);
    let big = b.ins().fcmp(FloatCC::GreaterThanOrEqual, f, hi);
    let small = b.ins().fcmp(FloatCC::LessThan, f, lo);
    let t = b.ins().fcvt_to_sint_sat(I64, f);
    let tf = b.ins().fcvt_from_sint(F64, t);
    let ilt = b.ins().icmp(IntCC::SignedLessThan, i, t);
    let igt = b.ins().icmp(IntCC::SignedGreaterThan, i, t);
    let ieq = b.ins().icmp(IntCC::Equal, i, t);
    let fgt = b.ins().fcmp(FloatCC::GreaterThan, f, tf);
    let flt = b.ins().fcmp(FloatCC::LessThan, f, tf);
    let out = b.ins().bor(nan, big);
    let out = b.ins().bor(out, small);
    let inr = b.ins().bxor_imm_u(out, 1);
    // i < f: f ≥ 2^63, o i < t, o i == t y f tiene parte fraccionaria positiva.
    let a = b.ins().band(ieq, fgt);
    let a = b.ins().bor(ilt, a);
    let a = b.ins().band(inr, a);
    let lt = b.ins().bor(big, a);
    let g = b.ins().band(ieq, flt);
    let g = b.ins().bor(igt, g);
    let g = b.ins().band(inr, g);
    let gt = b.ins().bor(small, g);
    let frac = b.ins().bor(fgt, flt);
    let whole = b.ins().bxor_imm_u(frac, 1);
    let eq = b.ins().band(inr, ieq);
    let eq = b.ins().band(eq, whole);
    (lt, eq, gt)
}

/// `NumCmp`: el resultado (un `I8`) con la regla de la VM (`num_eq`/`partial_cmp_num`).
fn num_cmp(b: &mut FunctionBuilder, op: NCmp, x: &Num, y: &Num) -> Value {
    let ii = |b: &mut FunctionBuilder| {
        (
            b.ins().icmp(IntCC::SignedLessThan, x.int, y.int),
            b.ins().icmp(IntCC::Equal, x.int, y.int),
            b.ins().icmp(IntCC::SignedGreaterThan, x.int, y.int),
        )
    };
    let ff = |b: &mut FunctionBuilder| {
        (
            b.ins().fcmp(FloatCC::LessThan, x.f, y.f),
            b.ins().fcmp(FloatCC::Equal, x.f, y.f),
            b.ins().fcmp(FloatCC::GreaterThan, x.f, y.f),
        )
    };
    let i_f = |b: &mut FunctionBuilder| cmp_int_float(b, x.int, y.f);
    let f_i = |b: &mut FunctionBuilder| {
        let (lt, eq, gt) = cmp_int_float(b, y.int, x.f);
        (gt, eq, lt)
    };
    type Ord3 = (Value, Value, Value);
    let pick = |b: &mut FunctionBuilder, c: Value, yes: Ord3, no: Ord3| -> Ord3 {
        (b.ins().select(c, yes.0, no.0), b.ins().select(c, yes.1, no.1), b.ins().select(c, yes.2, no.2))
    };
    let (lt, eq, gt) = match (x.is_float, y.is_float) {
        (Some(false), Some(false)) => ii(b),
        (Some(true), Some(true)) => ff(b),
        (Some(false), Some(true)) => i_f(b),
        (Some(true), Some(false)) => f_i(b),
        (Some(false), None) => {
            let (a, c) = (i_f(b), ii(b));
            pick(b, y.isf, a, c)
        }
        (Some(true), None) => {
            let (a, c) = (ff(b), f_i(b));
            pick(b, y.isf, a, c)
        }
        (None, Some(false)) => {
            let (a, c) = (f_i(b), ii(b));
            pick(b, x.isf, a, c)
        }
        (None, Some(true)) => {
            let (a, c) = (ff(b), i_f(b));
            pick(b, x.isf, a, c)
        }
        (None, None) => {
            let (a, c) = (ff(b), f_i(b));
            let xf = pick(b, y.isf, a, c);
            let (a, c) = (i_f(b), ii(b));
            let xi = pick(b, y.isf, a, c);
            pick(b, x.isf, xf, xi)
        }
    };
    match op {
        NCmp::Lt => lt,
        NCmp::Gt => gt,
        NCmp::Le => b.ins().bor(lt, eq),
        NCmp::Ge => b.ins().bor(gt, eq),
        NCmp::Eq => eq,
        NCmp::Ne => b.ins().bxor_imm_u(eq, 1),
    }
}

/// Traduce la función `i` (ya planeada) al `ir::Function` de `func`. Llena `plan.points`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build(
    unit: &NUnit,
    i: usize,
    plans: &mut [Plan],
    func: &mut ir::Function,
    fbctx: &mut FunctionBuilderContext,
    callees: &[ir::FuncRef],
    h: Helpers,
    config: TargetFrontendConfig,
) -> Option<()> {
    let f = Func::new(&unit.funcs[i], unit);
    let n = f.f.code.len();
    let np = plans[i].nargs(f.f);

    let mut b = FunctionBuilder::new(func, fbctx);
    let parts: Vec<Parts> = (0..f.nvars)
        .map(|_| Parts { tag: b.declare_var(I64), bits: b.declare_var(I64), f: b.declare_var(F64), ptr: b.declare_var(I64) })
        .collect();
    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let ctx = b.block_params(entry)[0];
    // F4.8a: la profundidad de este frame, en una variable (la entrada la trae del contexto; una
    // llamada de la unidad, como parámetro). Va al contexto sólo al salir a la VM. (`steps` vive en el
    // contexto: una suma en memoria por bloque; ver `emit_steps`.)
    let dv = b.declare_var(I64);
    {
        let d0 = b.block_params(entry)[1];
        b.def_var(dv, d0);
    }
    let params: Vec<Value> = b.block_params(entry)[HEAD_PARAMS..HEAD_PARAMS + np].to_vec();
    let vs = Vars { p: parts, need: needs(f.nvars, &plans[i].state), f: &f, ctx, h };
    let mut ptr_params = Vec::new();
    let mut ptr_slots = Vec::new();
    // Lo que tiene cada lugar al entrar. Un bucle: cada parámetro es un lugar que toca (`inputs`),
    // con lo que tenía al compilar; lo que no toca, sin información. Una task: sus parámetros son
    // `r0..`, el resto de los registros `nothing` y la ventana vacía.
    let mut init: Vec<(Kind, Option<Value>)> = vec![(Kind::Bot, None); f.nvars];
    // F4.7b: los lugares con caja entran como su dirección (y su clase como etiqueta).
    let mut boxed_in: Vec<(usize, NSeen, Value)> = Vec::new();
    let mut home_param: HashMap<usize, Value> = HashMap::new();
    if f.f.osr.is_some() {
        for (k, (place, seen)) in plans[i].inputs.iter().enumerate() {
            let v = f.var_of(*place);
            if boxed_seen(*seen) {
                boxed_in.push((v, *seen, params[k]));
                // El parámetro `k` del bloque de entrada (antes: el contexto y la profundidad).
                ptr_params.push(k + HEAD_PARAMS);
            } else {
                init[f.var_of(*place)] = (seen_kind(*seen), Some(params[k]));
            }
        }
        // F4.8d: las direcciones de los lugares donde el código deja un valor antes de una escritura.
        let nin = plans[i].inputs.len();
        for (hk, place) in plans[i].homes.iter().enumerate() {
            home_param.insert(f.var_of(*place), params[nin + hk]);
            ptr_params.push(nin + hk + HEAD_PARAMS);
        }
    } else {
        let npar = f.f.nparams as usize;
        for (v, x) in init.iter_mut().enumerate() {
            *x = if v < npar && f.f.params.get(v).is_some_and(|s| boxed_seen(*s)) {
                // F4.8b: un parámetro con caja (su dirección).
                boxed_in.push((v, f.f.params[v], params[v]));
                ptr_params.push(v + HEAD_PARAMS);
                (Kind::Bot, None)
            } else if v < npar {
                (plans[i].params[v], Some(params[v]))
            } else if v < f.nregs {
                (Kind::Nothing, None)
            } else {
                (Kind::Undef, None)
            };
        }
        // F4.8b: las globales que lee la task, después de los parámetros.
        for (g, s) in f.f.globals.iter().enumerate() {
            let v = f.global_var(g as u16);
            let x = params[npar + g];
            if boxed_seen(*s) {
                boxed_in.push((v, *s, x));
                ptr_params.push(npar + g + HEAD_PARAMS);
            } else {
                init[v] = (seen_kind(*s), Some(x));
            }
        }
    }
    {
        let z = b.ins().iconst(I64, 0);
        let zf = b.ins().f64const(0.0);
        for (v, (k, x)) in init.iter().enumerate() {
            // Las partes que se usan, definidas desde la entrada (así cada camino tiene una).
            let nd = vs.need[v];
            if nd.tag {
                b.def_var(vs.p[v].tag, z);
            }
            if nd.bits {
                b.def_var(vs.p[v].bits, z);
            }
            if nd.f {
                b.def_var(vs.p[v].f, zf);
            }
            if nd.ptr {
                b.def_var(vs.p[v].ptr, z);
            }
            match (k, x) {
                (Kind::Bot, _) => {}
                (k, Some(x)) => vs.put_word(&mut b, v, *k, *x),
                (k, None) => vs.put_word(&mut b, v, *k, z),
            }
        }
        for (v, seen, x) in &boxed_in {
            if let Some(t) = seen_tag(*seen) {
                vs.put_tag(&mut b, *v, t);
            }
            b.def_var(vs.p[*v].ptr, *x);
        }
    }

    // Un bloque por destino de salto alcanzable (y, en un bucle, su cabecera).
    let mut blocks: HashMap<usize, Block> = HashMap::new();
    let plan = &plans[i];
    if let Some(o) = &f.f.osr {
        let bl = b.create_block();
        blocks.insert(o.head as usize, bl);
    }
    for pc in 0..n {
        if plan.state[pc].is_none() || plan.trap[pc] {
            continue;
        }
        let targets: Vec<usize> = match f.f.code[pc] {
            NIns::Jump { to } => vec![to as usize],
            NIns::JumpIfFalsy { to, .. } => vec![pc + 1, to as usize],
            NIns::IntCmpJump { to, .. } => vec![pc + 2, to as usize],
            NIns::IsRange { src, to } => match plan.state[pc].as_ref().map(|st| st[src as usize]) {
                Some(Kind::RangeFn) => Vec::new(),
                _ => vec![to as usize],
            },
            NIns::EachNext { exit, .. } => vec![pc + 1, exit as usize],
            NIns::EachStep { head, .. } => vec![head as usize],
            _ => Vec::new(),
        };
        for t in targets {
            if t < n && !blocks.contains_key(&t) {
                let bl = b.create_block();
                blocks.insert(t, bl);
            }
        }
    }

    let mut points: Vec<Point> = Vec::new();
    let mut exits: Vec<Exit> = Vec::new();
    // F4.8d2: las instrucciones que corre el host, sus ranuras de punteros y la salida de un error de una
    // llamada ajena (sin valores: el entorno ya tiene lo suyo y el frame se desarma con el error).
    let mut exec_sites: Vec<ExecSite> = Vec::new();
    let mut exec_ptr_slots: Vec<StackSlot> = Vec::new();
    let mut fail_block: Option<Block> = None;
    // Salida "antes de pc" (una por instrucción) y "después de la llamada en pc".
    let mut before: HashMap<usize, Block> = HashMap::new();
    let mut after_call: HashMap<usize, Block> = HashMap::new();

    macro_rules! exit_before {
        ($pc:expr) => {{
            let pc: usize = $pc;
            match before.get(&pc) {
                Some(bl) => *bl,
                None => {
                    let st = plan.state[pc].as_ref()?;
                    let values = frame_values(&f, st, &plan.live[pc], |_| false)?;
                    let planned = matches!(f.f.code[pc], NIns::Leave { planned: true });
                    points.push(Point { pc: pc as u32, values, call: None, planned });
                    let bl = b.create_block();
                    b.set_cold_block(bl);
                    exits.push(Exit { block: bl, point: (points.len() - 1) as u32 });
                    before.insert(pc, bl);
                    bl
                }
            }
        }};
    }

    let flags = MemFlagsData::trusted();
    let mut open = true;
    // Un bucle se entra por su cabecera (el estado de la VM ya está en las variables).
    if let Some(o) = &f.f.osr {
        let h = blocks[&(o.head as usize)];
        b.ins().jump(h, &[]);
        open = false;
    }
    for pc in 0..n {
        if let Some(bl) = blocks.get(&pc) {
            if open {
                b.ins().jump(*bl, &[]);
            }
            b.switch_to_block(*bl);
            open = true;
        }
        if !open {
            continue;
        }
        if plan.state[pc].is_none() {
            // No se llega (el análisis lo sabe); no debería haber código abierto acá.
            return None;
        }
        if plan.trap[pc] {
            let ex = exit_before!(pc);
            b.ins().jump(ex, &[]);
            open = false;
            continue;
        }
        let st = plan.state[pc].clone().expect("estado");
        // La guarda de hueco (F4.7): un lugar que según el camino puede estar vacío y que esta
        // instrucción lee; vacío, lo busca la VM por nombre.
        let holes = st.contains(&Kind::Any(true));
        for v in if holes { f.uses_defs(pc).0 } else { Vec::new() } {
            if st[v] == Kind::Any(true) {
                let ex = exit_before!(pc);
                let t = b.use_var(vs.p[v].tag);
                let hole = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_HOLE);
                exit_if(&mut b, hole, ex);
            }
        }
        // F4.8d: antes de una escritura, lo prestado que la cruza pasa a su lugar en la VM (su propia
        // cuenta, como en la VM): si tiene caja, una copia en su lugar, y su puntero pasa a ser ése.
        if h.writes.is_some() || h.host.is_some() {
            for &v in &plan.homes_at[pc] {
                let t = b.use_var(vs.p[v].tag);
                let boxed = b.ins().icmp_imm_s(IntCC::SignedGreaterThanOrEqual, t, TAG_LIST);
                let call = b.create_block();
                let join = b.create_block();
                b.ins().brif(boxed, call, &[], join, &[]);
                b.seal_block(call);
                b.switch_to_block(call);
                let src = b.use_var(vs.p[v].ptr);
                let r = match h.host {
                    // F4.8d2: con llamadas ajenas, por el host (las direcciones de la entrada no valen
                    // después de una llamada).
                    Some(hf) => {
                        let pc_ = b.ins().iconst(I64, place_code(f.place_of(v)));
                        b.ins().call(hf.home, &[ctx, pc_, src])
                    }
                    None => {
                        let w = h.writes?;
                        let slot = *home_param.get(&v)?;
                        let hf = if matches!(f.place_of(v), Place::Local(_)) { w.home_local } else { w.home };
                        b.ins().call(hf, &[ctx, slot, src])
                    }
                };
                let r = b.inst_results(r)[0];
                b.def_var(vs.p[v].ptr, r);
                b.ins().jump(join, &[]);
                b.seal_block(join);
                b.switch_to_block(join);
            }
        }
        match f.f.code[pc] {
            NIns::Nop => {}
            // La vía en el lugar sólo aplica a listas y mapas: con un escalar no hace nada; si puede
            // ser una lista o un mapa (F4.7b), la hace la VM.
            NIns::Scalar { src } => {
                if matches!(f.opnd_kind(&st, src), Kind::Any(_)) {
                    let ex = exit_before!(pc);
                    let t = vs.tag(&mut b, &st, src);
                    let l = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_LIST);
                    let m = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_MAP);
                    let bad = b.ins().bor(l, m);
                    exit_if(&mut b, bad, ex);
                }
            }
            NIns::GetIndex { dst, obj, idx, site } => {
                // F4.7b: el camino rápido de la VM (una lista con un `Int`, un mapa con una clave de
                // texto) en `abi`; lo que no hace (fuera de rango, otra cosa) sale antes.
                let ex = exit_before!(pc);
                let q = vs.ptr(&mut b, &st, obj);
                let (it, ib, ip) = match idx {
                    Some(o) => (vs.tag(&mut b, &st, o), vs.bits(&mut b, o), vs.ptr(&mut b, &st, o)),
                    None => (b.ins().iconst(I64, TAG_NOTHING), b.ins().iconst(I64, 0), b.ins().iconst(I64, 0)),
                };
                let sv = b.ins().iconst(I64, i64::from(site));
                let call = b.ins().call(h.reads?.index, &[ctx, q, it, ib, ip, sv]);
                let tag = b.inst_results(call)[0];
                let miss = b.ins().icmp_imm_s(IntCC::Equal, tag, TAG_MISS);
                exit_if(&mut b, miss, ex);
                vs.consume(&mut b, obj);
                if let Some(o) = idx {
                    vs.consume(&mut b, o);
                }
                if dst != DISCARD {
                    vs.put_read(&mut b, dst as usize, tag);
                }
            }
            NIns::GetProp { dst, obj, site } => {
                let ex = exit_before!(pc);
                let q = vs.ptr(&mut b, &st, obj);
                let sv = b.ins().iconst(I64, i64::from(site));
                let call = b.ins().call(h.reads?.prop, &[ctx, q, sv]);
                let tag = b.inst_results(call)[0];
                let miss = b.ins().icmp_imm_s(IntCC::Equal, tag, TAG_MISS);
                exit_if(&mut b, miss, ex);
                vs.consume(&mut b, obj);
                if dst != DISCARD {
                    vs.put_read(&mut b, dst as usize, tag);
                }
            }
            NIns::EachList { src, it } => {
                // F4.7b: la lista que había al empezar (la VM también la recorre así: si el cuerpo la
                // cambiara, el copy-on-write copia; el código nativo no escribe listas).
                let ex = exit_before!(pc);
                let q = vs.ptr(&mut b, &st, src);
                let call = b.ins().call(h.reads?.list_body, &[ctx, q]);
                let body = b.inst_results(call)[0];
                let none = b.ins().icmp_imm_s(IntCC::Equal, body, 0);
                exit_if(&mut b, none, ex);
                let len = ctx_load(&mut b, ctx, OFF_OUT_BITS);
                vs.consume(&mut b, src);
                for v in f.iters_from(it) {
                    vs.put_hole(&mut b, v);
                }
                b.def_var(vs.p[f.iter_var(it, 0)].ptr, body);
                let zero = b.ins().iconst(I64, 0);
                vs.put_int(&mut b, f.iter_var(it, 1), zero);
                vs.put_int(&mut b, f.iter_var(it, 2), len);
                vs.put_int(&mut b, f.iter_var(it, 3), zero);
            }
            NIns::EachNext { it, slot, exit } if st[f.iter_var(it, 0)] == Kind::ListBody => {
                // F4.7b: la vuelta de una lista (`EachItems::List`): el elemento `i` (clonado por la
                // VM; acá prestado) y `i + 1`, también al terminar.
                let ex = exit_before!(pc);
                let body = b.use_var(vs.p[f.iter_var(it, 0)].ptr);
                let vi = vs.p[f.iter_var(it, 1)].bits;
                let i = b.use_var(vi);
                let len = b.use_var(vs.p[f.iter_var(it, 2)].bits);
                let (go, out) = (*blocks.get(&(pc + 1))?, *blocks.get(&(exit as usize))?);
                let next = b.ins().iadd_imm_s(i, 1);
                let inside = b.ins().icmp(IntCC::SignedLessThan, i, len);
                let yes = b.create_block();
                let end = b.create_block();
                b.ins().brif(inside, yes, &[], end, &[]);
                b.seal_block(end);
                b.switch_to_block(end);
                b.def_var(vi, next);
                b.ins().jump(out, &[]);
                b.seal_block(yes);
                b.switch_to_block(yes);
                let call = b.ins().call(h.reads?.list_elem, &[ctx, body, i]);
                let tag = b.inst_results(call)[0];
                let miss = b.ins().icmp_imm_s(IntCC::Equal, tag, TAG_MISS);
                exit_if(&mut b, miss, ex);
                b.def_var(vi, next);
                vs.put_read(&mut b, f.nregs + slot as usize, tag);
                b.ins().jump(go, &[]);
                open = false;
            }
            NIns::Steps(w) => emit_steps(&mut b, ctx, w),
            NIns::StepsCancel(w) => {
                let ex = exit_before!(pc);
                emit_cancel(&mut b, ctx, ex);
                emit_steps(&mut b, ctx, w);
            }
            NIns::CheckCancel => {
                let ex = exit_before!(pc);
                emit_cancel(&mut b, ctx, ex);
            }
            NIns::Const { dst, v } => {
                if dst != DISCARD {
                    vs.copy(&mut b, &st, NOpnd::Const(v), dst as usize);
                }
            }
            NIns::Move { dst, src } => {
                move_to(&mut b, &vs, &st, src, dst);
            }
            NIns::Drop { r } => {
                if r != DISCARD {
                    vs.put_nothing(&mut b, r as usize);
                }
            }
            NIns::IntArith { dst, op, a, b: rb } => {
                let ex = exit_before!(pc);
                let x = int_opnd(&mut b, &vs, &st, a, Some(ex));
                let y = int_opnd(&mut b, &vs, &st, rb, Some(ex));
                let r = match op {
                    NArith::Add | NArith::Sub | NArith::Mul => {
                        let (r, of) = match op {
                            NArith::Add => b.ins().sadd_overflow(x, y),
                            NArith::Sub => b.ins().ssub_overflow(x, y),
                            _ => b.ins().smul_overflow(x, y),
                        };
                        // Desborda: la VM repite la cuenta y da el `Big`.
                        exit_if(&mut b, of, ex);
                        r
                    }
                    NArith::Mod => {
                        // `% 0`: el error lo arma la VM.
                        let z = b.ins().icmp_imm_s(IntCC::Equal, y, 0);
                        exit_if(&mut b, z, ex);
                        // Módulo con piso (`Number::modulo`, `mod_floor`); `% -1` es 0 (con 1 como
                        // divisor, `i64::MIN % -1` no desborda y da lo mismo).
                        let m1 = b.ins().icmp_imm_s(IntCC::Equal, y, -1);
                        let one = b.ins().iconst(I64, 1);
                        let d = b.ins().select(m1, one, y);
                        let r0 = b.ins().srem(x, d);
                        let sx = b.ins().bxor(r0, d);
                        let neg = b.ins().icmp_imm_s(IntCC::SignedLessThan, sx, 0);
                        let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r0, 0);
                        let adj = b.ins().band(neg, nz);
                        let r1 = b.ins().iadd(r0, d);
                        b.ins().select(adj, r1, r0)
                    }
                };
                if dst != DISCARD {
                    vs.put_int(&mut b, dst as usize, r);
                }
            }
            NIns::IntCmp { dst, op, a, b: rb } => {
                let ex = if dynamic(&f, &st, &[a, rb]) { Some(exit_before!(pc)) } else { None };
                let x = int_opnd(&mut b, &vs, &st, a, ex);
                let y = int_opnd(&mut b, &vs, &st, rb, ex);
                let c = b.ins().icmp(cc(op), x, y);
                let r = b.ins().uextend(I64, c);
                if dst != DISCARD {
                    vs.put_bool(&mut b, dst as usize, r);
                }
            }
            NIns::IntCmpJump { op, a, b: rb, to } => {
                let ex = if dynamic(&f, &st, &[a, rb]) { Some(exit_before!(pc)) } else { None };
                let x = int_opnd(&mut b, &vs, &st, a, ex);
                let y = int_opnd(&mut b, &vs, &st, rb, ex);
                let c = b.ins().icmp(cc(op), x, y);
                let (yes, no) = (*blocks.get(&(pc + 2))?, *blocks.get(&(to as usize))?);
                b.ins().brif(c, yes, &[], no, &[]);
                open = false;
            }
            NIns::FloatArith { dst, op, a, b: rb } => {
                let (ka, kb) = (f.opnd_kind(&st, a), f.opnd_kind(&st, rb));
                let guarded = op == NFArith::Div || dynamic(&f, &st, &[a, rb]) || (ka != Kind::Float && kb != Kind::Float);
                let ex = if guarded { Some(exit_before!(pc)) } else { None };
                let x = num_opnd(&mut b, &vs, &st, a, ex);
                let y = num_opnd(&mut b, &vs, &st, rb, ex);
                // `+ - *` con dos `Int`: la guarda de la VM no pasa (el análisis ya lo descartó si
                // los dos son `Int` estáticos).
                if op != NFArith::Div && x.is_float != Some(true) && y.is_float != Some(true) {
                    let any = b.ins().bor(x.isf, y.isf);
                    let none = b.ins().bxor_imm_u(any, 1);
                    exit_if(&mut b, none, ex.expect("salida"));
                }
                let r = match op {
                    NFArith::Add => b.ins().fadd(x.f, y.f),
                    NFArith::Sub => b.ins().fsub(x.f, y.f),
                    NFArith::Mul => b.ins().fmul(x.f, y.f),
                    NFArith::Div => {
                        // `/` por cero (también `-0.0`) es error: lo arma la VM.
                        let z = b.ins().f64const(0.0);
                        let is0 = b.ins().fcmp(FloatCC::Equal, y.f, z);
                        exit_if(&mut b, is0, ex.expect("salida"));
                        b.ins().fdiv(x.f, y.f)
                    }
                };
                if dst != DISCARD {
                    vs.put_float(&mut b, dst as usize, r);
                }
            }
            NIns::NumCmp { dst, op, a, b: rb } => {
                let ex = if dynamic(&f, &st, &[a, rb]) { Some(exit_before!(pc)) } else { None };
                let x = num_opnd(&mut b, &vs, &st, a, ex);
                let y = num_opnd(&mut b, &vs, &st, rb, ex);
                let c = num_cmp(&mut b, op, &x, &y);
                let r = b.ins().uextend(I64, c);
                if dst != DISCARD {
                    vs.put_bool(&mut b, dst as usize, r);
                }
            }
            NIns::Unary { dst, op, a } => {
                match op {
                    NUnary::Neg => {
                        let k = f.opnd_kind(&st, a);
                        let ex = if k != Kind::Float { Some(exit_before!(pc)) } else { None };
                        let x = num_opnd(&mut b, &vs, &st, a, ex);
                        // `-i64::MIN` es un `Big`: lo da la VM.
                        if let Some(ex) = ex {
                            let min = b.ins().icmp_imm_s(IntCC::Equal, x.int, i64::MIN);
                            let isi = b.ins().bxor_imm_u(x.isf, 1);
                            let bad = b.ins().band(min, isi);
                            exit_if(&mut b, bad, ex);
                        }
                        let ni = b.ins().ineg(x.int);
                        let nf = if matches!(k, Kind::Int) { x.f } else { b.ins().fneg(x.f) };
                        vs.consume(&mut b, a);
                        if dst != DISCARD {
                            let d = dst as usize;
                            match k {
                                Kind::Int => vs.put_int(&mut b, d, ni),
                                Kind::Float => vs.put_float(&mut b, d, nf),
                                _ => {
                                    let (tf, ti) = (b.ins().iconst(I64, TAG_FLOAT), b.ins().iconst(I64, TAG_INT));
                                    let t = b.ins().select(x.isf, tf, ti);
                                    b.def_var(vs.p[d].tag, t);
                                    b.def_var(vs.p[d].bits, ni);
                                    b.def_var(vs.p[d].f, nf);
                                }
                            }
                        }
                    }
                    NUnary::Not => {
                        let t = vs.truthy(&mut b, &st, a);
                        let r = b.ins().bxor_imm_u(t, 1);
                        let r = b.ins().uextend(I64, r);
                        vs.consume(&mut b, a);
                        if dst != DISCARD {
                            vs.put_bool(&mut b, dst as usize, r);
                        }
                    }
                }
            }
            NIns::ToBool { dst, src } => {
                let t = vs.truthy(&mut b, &st, src);
                let r = b.ins().uextend(I64, t);
                vs.consume(&mut b, src);
                if dst != DISCARD {
                    vs.put_bool(&mut b, dst as usize, r);
                }
            }
            NIns::JumpIfFalsy { src, to } => {
                let t = vs.truthy(&mut b, &st, src);
                vs.consume(&mut b, src);
                let (yes, no) = (*blocks.get(&(pc + 1))?, *blocks.get(&(to as usize))?);
                b.ins().brif(t, yes, &[], no, &[]);
                open = false;
            }
            NIns::Jump { to } => {
                let t = *blocks.get(&(to as usize))?;
                b.ins().jump(t, &[]);
                open = false;
            }
            NIns::LoadLocal { dst, slot } => {
                if dst != DISCARD {
                    vs.copy(&mut b, &st, NOpnd::Local(slot), dst as usize);
                }
            }
            NIns::LetLocal { src, slot, dst } | NIns::SetLocal { src, slot, dst } => {
                let v = f.nregs + slot as usize;
                vs.copy(&mut b, &st, src, v);
                vs.consume(&mut b, src);
                if dst != DISCARD {
                    let mut after = st.clone();
                    after[v] = read_kind(f.opnd_kind(&st, src));
                    vs.copy(&mut b, &after, NOpnd::Local(slot), dst as usize);
                }
            }
            NIns::LoadCallee { dst, .. } | NIns::RangeFn { dst } | NIns::LoadBuiltin { dst, .. } => {
                if dst != DISCARD {
                    vs.put_other(&mut b, dst as usize);
                }
            }
            NIns::LoadForeign { .. } | NIns::CheckForeign { .. } => {
                // F4.8d2: la corre el host (sin argumentos ni globales, no devuelve nada al código).
                let hf = h.host?;
                let si = b.ins().iconst(I64, exec_sites.len() as i64);
                exec_sites.push(ExecSite { pc: pc as u32, nargs: 0, globals: 0, reload: Vec::new() });
                let z = b.ins().iconst(I64, 0);
                let r = b.ins().call(hf.exec, &[ctx, si, z, z, z]);
                let r = b.inst_results(r)[0];
                let fb = fail_exit(&mut b, &mut fail_block, &mut points, &mut exits, pc);
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 2);
                exit_if(&mut b, bad, fb);
            }
            NIns::Call { dst, func: freg, args, n: na } if st[freg as usize] == Kind::Foreign => {
                // F4.8d2: una llamada ajena. Lo prestado vivo ya tiene dueño (arriba); los argumentos y
                // las globales van al host en los búferes; lo corre la VM entera; vuelven el resultado,
                // las globales y las direcciones nuevas de lo que sigue vivo (la memoria se pudo mover).
                let hf = h.host?;
                let ng = f.f.nglobals;
                let after = plan.state.get(pc + 1).and_then(|x| x.as_ref())?;
                let live_after = &plan.live[pc + 1];
                let mut reload: Vec<(usize, Reload)> = Vec::new();
                if dst != DISCARD {
                    reload.push((dst as usize, Reload::Full));
                }
                for g in 0..ng {
                    reload.push((f.global_var(g), Reload::Full));
                }
                for v in 0..f.nvars {
                    if v == dst as usize || (v >= args as usize && v < f.nregs) || matches!(f.place_of(v), Place::Global(_)) || !live_after[v] {
                        continue;
                    }
                    match (st[v], after[v]) {
                        (Kind::Any(_), Kind::Any(_)) => reload.push((v, Reload::Ptr)),
                        (Kind::ListBody, Kind::ListBody) => reload.push((v, Reload::Iter)),
                        _ => {}
                    }
                }
                let nflush = na as usize + ng as usize;
                let size = nflush.max(reload.len()).max(1) as u32;
                let mk = |b: &mut FunctionBuilder| b.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, 8 * size, 3));
                let (ts, bs, ps) = (mk(&mut b), mk(&mut b), mk(&mut b));
                exec_ptr_slots.push(ps);
                let put = |b: &mut FunctionBuilder, k: usize, (t, x, p): (Value, Value, Value)| {
                    b.ins().stack_store(I64, t, ts, 8 * k as i32);
                    b.ins().stack_store(I64, x, bs, 8 * k as i32);
                    b.ins().stack_store(I64, p, ps, 8 * k as i32);
                };
                for k in 0..na as usize {
                    let a = NOpnd::Copy(args + k as u16);
                    let parts = if st[args as usize + k] == Kind::Foreign {
                        let z = b.ins().iconst(I64, 0);
                        (b.ins().iconst(I64, TAG_KEEP), z, z)
                    } else {
                        vs.value_parts(&mut b, &st, a)
                    };
                    put(&mut b, k, parts);
                }
                for g in 0..ng {
                    let o = NOpnd::Global(g);
                    let parts = match f.opnd_kind(&st, o) {
                        // Con caja: ya está en su lugar (dueño, arriba): puntero 0, el host no la toca.
                        Kind::Any(_) => {
                            let (t, x, _) = vs.value_parts(&mut b, &st, o);
                            (t, x, b.ins().iconst(I64, 0))
                        }
                        k if value_kind(k).is_some() && k != Kind::Undef => vs.value_parts(&mut b, &st, o),
                        _ => {
                            let z = b.ins().iconst(I64, 0);
                            (b.ins().iconst(I64, TAG_HOLE), z, z)
                        }
                    };
                    put(&mut b, na as usize + g as usize, parts);
                }
                let si = b.ins().iconst(I64, exec_sites.len() as i64);
                exec_sites.push(ExecSite { pc: pc as u32, nargs: na, globals: ng, reload: reload.iter().map(|(v, _)| f.place_of(*v)).collect() });
                let (ta, ba, pa) = (b.ins().stack_addr(I64, ts, 0), b.ins().stack_addr(I64, bs, 0), b.ins().stack_addr(I64, ps, 0));
                let r = b.ins().call(hf.exec, &[ctx, si, ta, ba, pa]);
                let r = b.inst_results(r)[0];
                let fb = fail_exit(&mut b, &mut fail_block, &mut points, &mut exits, pc);
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 2);
                exit_if(&mut b, bad, fb);
                // Lo que consumió la llamada (la función, la ventana del llamado).
                vs.put_nothing(&mut b, freg as usize);
                for v in args as usize..f.nregs {
                    if v != dst as usize {
                        vs.put_nothing(&mut b, v);
                    }
                }
                let (ta, ba, pa) = (b.ins().stack_addr(I64, ts, 0), b.ins().stack_addr(I64, bs, 0), b.ins().stack_addr(I64, ps, 0));
                for (k, (v, mode)) in reload.iter().enumerate() {
                    let off = 8 * k as i32;
                    let t = b.ins().load(I64, MemFlagsData::trusted(), ta, off);
                    let x = b.ins().load(I64, MemFlagsData::trusted(), ba, off);
                    let p = b.ins().load(I64, MemFlagsData::trusted(), pa, off);
                    let pv = vs.p[*v];
                    match mode {
                        Reload::Full => {
                            b.def_var(pv.tag, t);
                            b.def_var(pv.bits, x);
                            let fl = b.ins().bitcast(F64, MemFlagsData::new(), x);
                            b.def_var(pv.f, fl);
                            b.def_var(pv.ptr, p);
                        }
                        Reload::Ptr => {
                            let old_t = b.use_var(pv.tag);
                            let old_p = b.use_var(pv.ptr);
                            let boxed = b.ins().icmp_imm_s(IntCC::SignedGreaterThanOrEqual, old_t, TAG_LIST);
                            let np = b.ins().select(boxed, p, old_p);
                            b.def_var(pv.ptr, np);
                        }
                        Reload::Iter => b.def_var(pv.ptr, p),
                    }
                }
                // Un `stop` cortó el bucle (el host guardó adónde sigue la VM): sale después de la llamada.
                let stop = b.ins().icmp_imm_s(IntCC::Equal, r, 1);
                let ex = exit_before!(pc + 1);
                exit_if(&mut b, stop, ex);
            }
            NIns::Call { dst, func: freg, args, n } if matches!(st[freg as usize], Kind::Builtin(_)) => {
                // F4.7c: el builtin lo hace el código nativo. Lo observable de la llamada de la VM: la
                // profundidad (un nivel, con el mismo tope: si lo pasaría, la VM da el error), y la
                // función y el argumento salen de sus registros.
                let Kind::Builtin(w) = st[freg as usize] else { unreachable!("intrínseco") };
                let ex = exit_before!(pc);
                let d = b.use_var(dv);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_fixed(&mut b, ctx, OFF_MAX_DEPTH);
                let over = b.ins().icmp(IntCC::UnsignedGreaterThan, d1, mx);
                exit_if(&mut b, over, ex);
                let a = NOpnd::Copy(args);
                let k = f.opnd_kind(&st, a);
                let d = dst as usize;
                match w {
                    NBuiltin::Length => {
                        let q = vs.ptr(&mut b, &st, a);
                        let call = b.ins().call(h.reads?.length, &[ctx, q]);
                        let r = b.inst_results(call)[0];
                        let bad = b.ins().icmp_imm_s(IntCC::SignedLessThan, r, 0);
                        exit_if(&mut b, bad, ex);
                        vs.put_nothing(&mut b, freg as usize);
                        vs.put_nothing(&mut b, args as usize);
                        if dst != DISCARD {
                            vs.put_int(&mut b, d, r);
                        }
                    }
                    NBuiltin::Sqrt => {
                        // `sqrt(x)` es `f64::sqrt(x.to_f64())`: un negativo da NaN, no un error.
                        let x = num_opnd(&mut b, &vs, &st, a, Some(ex));
                        let r = b.ins().sqrt(x.f);
                        vs.put_nothing(&mut b, freg as usize);
                        vs.put_nothing(&mut b, args as usize);
                        if dst != DISCARD {
                            vs.put_float(&mut b, d, r);
                        }
                    }
                    NBuiltin::Abs => {
                        // Preserva el tipo; `abs(i64::MIN)` es un `Big` (lo da la VM).
                        let x = num_opnd(&mut b, &vs, &st, a, Some(ex));
                        let min = b.ins().icmp_imm_s(IntCC::Equal, x.int, i64::MIN);
                        let isi = b.ins().bxor_imm_u(x.isf, 1);
                        let bad = b.ins().band(min, isi);
                        exit_if(&mut b, bad, ex);
                        let ni = b.ins().iabs(x.int);
                        let nf = b.ins().fabs(x.f);
                        vs.put_nothing(&mut b, freg as usize);
                        vs.put_nothing(&mut b, args as usize);
                        if dst != DISCARD {
                            match k {
                                Kind::Int => vs.put_int(&mut b, d, ni),
                                Kind::Float => vs.put_float(&mut b, d, nf),
                                _ => {
                                    let (tf, ti) = (b.ins().iconst(I64, TAG_FLOAT), b.ins().iconst(I64, TAG_INT));
                                    let t = b.ins().select(x.isf, tf, ti);
                                    b.def_var(vs.p[d].tag, t);
                                    b.def_var(vs.p[d].bits, ni);
                                    b.def_var(vs.p[d].f, nf);
                                }
                            }
                        }
                    }
                    // (En una llamada común sale a la VM: el análisis de tipos la marca.)
                    NBuiltin::Append => unreachable!("append fuera de AppendPush"),
                    NBuiltin::Get => {
                        // La lectura da el valor (prestado, como `x[i]`), `ABSENT` (el default, sin
                        // ramas: `select` de sus cuatro partes) o `MISS` (sale antes: la VM lo hace).
                        let (o, i) = (NOpnd::Copy(args), NOpnd::Copy(args + 1));
                        let q = vs.ptr(&mut b, &st, o);
                        let (it, ib, ip) = (vs.tag(&mut b, &st, i), vs.bits(&mut b, i), vs.ptr(&mut b, &st, i));
                        let call = b.ins().call(h.reads?.get, &[ctx, q, it, ib, ip]);
                        let rt = b.inst_results(call)[0];
                        let miss = b.ins().icmp_imm_s(IntCC::Equal, rt, TAG_MISS);
                        exit_if(&mut b, miss, ex);
                        if dst != DISCARD {
                            let (dt, dbits, df, dp) = if n == 3 {
                                let dop = NOpnd::Copy(args + 2);
                                match f.opnd_kind(&st, dop) {
                                    Kind::Any(_) => {
                                        let p = vs.var(dop).expect("un Any es una variable");
                                        (b.use_var(p.tag), b.use_var(p.bits), b.use_var(p.f), b.use_var(p.ptr))
                                    }
                                    Kind::Float => {
                                        let x = vs.float(&mut b, dop);
                                        let t = b.ins().iconst(I64, TAG_FLOAT);
                                        let xb = b.ins().bitcast(I64, MemFlagsData::new(), x);
                                        let z = b.ins().iconst(I64, 0);
                                        (t, xb, x, z)
                                    }
                                    _ => {
                                        let (t, x, p) = vs.value_parts(&mut b, &st, dop);
                                        let fl = b.ins().bitcast(F64, MemFlagsData::new(), x);
                                        (t, x, fl, p)
                                    }
                                }
                            } else {
                                let t = b.ins().iconst(I64, TAG_NOTHING);
                                let z = b.ins().iconst(I64, 0);
                                let fl = b.ins().f64const(0.0);
                                (t, z, fl, z)
                            };
                            let rbits = ctx_load(&mut b, ctx, OFF_OUT_BITS);
                            let rptr = ctx_load(&mut b, ctx, OFF_OUT_PTR);
                            let rf = b.ins().bitcast(F64, MemFlagsData::new(), rbits);
                            let absent = b.ins().icmp_imm_s(IntCC::Equal, rt, TAG_ABSENT);
                            let t = b.ins().select(absent, dt, rt);
                            let x = b.ins().select(absent, dbits, rbits);
                            let fl = b.ins().select(absent, df, rf);
                            let p = b.ins().select(absent, dp, rptr);
                            let d = dst as usize;
                            b.def_var(vs.p[d].tag, t);
                            b.def_var(vs.p[d].bits, x);
                            b.def_var(vs.p[d].f, fl);
                            b.def_var(vs.p[d].ptr, p);
                        }
                        vs.put_nothing(&mut b, freg as usize);
                        for k in 0..n as usize {
                            vs.put_nothing(&mut b, args as usize + k);
                        }
                    }
                    NBuiltin::Float => {
                        // `float(x)`: un número a f64, un `Bool` a 1.0/0.0 (sus bits son 1/0: la
                        // misma conversión que un entero).
                        let fv = match k {
                            Kind::Int | Kind::Bool => {
                                let x = vs.bits(&mut b, a);
                                b.ins().fcvt_from_sint(F64, x)
                            }
                            Kind::Float => vs.float(&mut b, a),
                            _ => {
                                let t = vs.tag(&mut b, &st, a);
                                guard_tags(&mut b, t, &[TAG_INT, TAG_FLOAT, TAG_BOOL], ex);
                                let x = vs.bits(&mut b, a);
                                let fx = vs.float(&mut b, a);
                                let fi = b.ins().fcvt_from_sint(F64, x);
                                let isf = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_FLOAT);
                                b.ins().select(isf, fx, fi)
                            }
                        };
                        vs.put_nothing(&mut b, freg as usize);
                        vs.put_nothing(&mut b, args as usize);
                        if dst != DISCARD {
                            vs.put_float(&mut b, d, fv);
                        }
                    }
                }
            }
            NIns::Call { dst, func: freg, args, n: na } => {
                let Kind::Callee(target) = st[freg as usize] else { return None };
                // La profundidad de la VM, con el mismo tope: si lo pasaría, la VM hace la llamada
                // (y da el error).
                let ex = exit_before!(pc);
                let d = b.use_var(dv);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_fixed(&mut b, ctx, OFF_MAX_DEPTH);
                let over = b.ins().icmp(IntCC::UnsignedGreaterThan, d1, mx);
                exit_if(&mut b, over, ex);
                // F4.8a: la profundidad de adentro como parámetro.
                let mut argv = vec![ctx, d1];
                for k in 0..na as usize {
                    argv.push(vs.word(&mut b, &st, NOpnd::Copy(args + k as u16)));
                }
                let call = b.ins().call(callees[target as usize], &argv);
                let r = b.inst_results(call)[0];
                // El llamado salió a la VM: este frame también, esperando su resultado.
                let status = ctx_load(&mut b, ctx, OFF_STATUS);
                let ex2 = match after_call.get(&pc) {
                    Some(bl) => *bl,
                    None => {
                        let window = f.call_window(target as usize, args, na);
                        let live_after = if pc + 1 < n { plan.live[pc + 1].clone() } else { vec![false; f.nvars] };
                        let mut after = st.clone();
                        after[freg as usize] = Kind::Nothing;
                        let values = frame_values(&f, &after, &live_after, |v| v == dst as usize || window.contains(&v) || v == freg as usize)?;
                        points.push(Point { pc: pc as u32 + 1, values, call: Some(NCall { dst, args, n: na }), planned: false });
                        let bl = b.create_block();
                        b.set_cold_block(bl);
                        exits.push(Exit { block: bl, point: (points.len() - 1) as u32 });
                        after_call.insert(pc, bl);
                        bl
                    }
                };
                exit_if(&mut b, status, ex2);
                vs.put_nothing(&mut b, freg as usize);
                for v in f.call_window(target as usize, args, na) {
                    vs.put_nothing(&mut b, v);
                }
                if dst != DISCARD {
                    vs.put_word(&mut b, dst as usize, plans[target as usize].ret, r);
                }
            }
            NIns::Give { src } | NIns::End { src } => {
                let x = vs.word(&mut b, &st, src);
                b.ins().return_(&[x]);
                open = false;
            }
            NIns::SetGlobal { src, g, dst } | NIns::LetGlobal { src, g, dst } => {
                let v = f.global_var(g);
                vs.copy(&mut b, &st, src, v);
                vs.consume(&mut b, src);
                if dst != DISCARD {
                    let mut after = st.clone();
                    after[v] = read_kind(f.opnd_kind(&st, src));
                    vs.copy(&mut b, &after, NOpnd::Global(g), dst as usize);
                }
            }
            NIns::IsRange { src, to } => {
                if st[src as usize] != Kind::RangeFn {
                    let t = *blocks.get(&(to as usize))?;
                    b.ins().jump(t, &[]);
                    open = false;
                }
            }
            NIns::EachRange { first, n, it } => {
                // Un nivel de profundidad, como la llamada al builtin (si pasaría el tope, la VM da
                // el error); el paso cero también es un error de la VM.
                let ex = exit_before!(pc);
                let d = b.use_var(dv);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_fixed(&mut b, ctx, OFF_MAX_DEPTH);
                let over = b.ins().icmp(IntCC::UnsignedGreaterThan, d1, mx);
                exit_if(&mut b, over, ex);
                let a: Vec<Value> = (0..n).map(|k| int_opnd(&mut b, &vs, &st, NOpnd::Copy(first + k), Some(ex))).collect();
                let zero = b.ins().iconst(I64, 0);
                let one = b.ins().iconst(I64, 1);
                let (lo, hi, step) = match n {
                    1 => (zero, a[0], one),
                    2 => (a[0], a[1], one),
                    _ => {
                        let z = b.ins().icmp_imm_s(IntCC::Equal, a[2], 0);
                        exit_if(&mut b, z, ex);
                        (a[0], a[1], a[2])
                    }
                };
                for k in 0..n as usize {
                    vs.put_nothing(&mut b, first as usize + k);
                }
                for v in f.iters_from(it) {
                    vs.put_hole(&mut b, v);
                }
                for (k, x) in [one, lo, hi, step].into_iter().enumerate() {
                    vs.put_int(&mut b, f.iter_var(it, k as u8), x);
                }
            }
            NIns::EachNext { it, slot, exit } => {
                // `RangeIter::next`: sin siguiente, a `exit`; si `i` quedó afuera, terminó; si no,
                // la vuelta con `i` y el siguiente con `checked_add` (si desborda, terminó después).
                let (vv, vn) = (vs.p[f.iter_var(it, 0)].bits, vs.p[f.iter_var(it, 1)].bits);
                let valid = b.use_var(vv);
                let i = b.use_var(vn);
                let hi = b.use_var(vs.p[f.iter_var(it, 2)].bits);
                let step = b.use_var(vs.p[f.iter_var(it, 3)].bits);
                let (go, out) = (*blocks.get(&(pc + 1))?, *blocks.get(&(exit as usize))?);
                let check = b.create_block();
                let end = b.create_block();
                let body = b.create_block();
                b.ins().brif(valid, check, &[], out, &[]);
                b.seal_block(check);
                b.switch_to_block(check);
                let pos = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, step, 0);
                let lt = b.ins().icmp(IntCC::SignedLessThan, i, hi);
                let gt = b.ins().icmp(IntCC::SignedGreaterThan, i, hi);
                let inside = b.ins().select(pos, lt, gt);
                b.ins().brif(inside, body, &[], end, &[]);
                b.seal_block(end);
                b.switch_to_block(end);
                let zero = b.ins().iconst(I64, 0);
                b.def_var(vv, zero);
                b.ins().jump(out, &[]);
                b.seal_block(body);
                b.switch_to_block(body);
                let (nx, of) = b.ins().sadd_overflow(i, step);
                let zero = b.ins().iconst(I64, 0);
                let one = b.ins().iconst(I64, 1);
                let nv = b.ins().select(of, zero, one);
                b.def_var(vv, nv);
                b.def_var(vn, nx);
                vs.put_int(&mut b, f.nregs + slot as usize, i);
                b.ins().jump(go, &[]);
                open = false;
            }
            NIns::EachStep { head, first, n } => {
                for v in f.locals(first, n) {
                    vs.put_hole(&mut b, v);
                }
                let t = *blocks.get(&(head as usize))?;
                b.ins().jump(t, &[]);
                open = false;
            }
            NIns::EachEnd { it, first, n } => {
                for v in f.locals(first, n).chain(f.iters_from(it)) {
                    vs.put_hole(&mut b, v);
                }
            }
            NIns::Trap { .. } | NIns::Leave { .. } => unreachable!("salida sin trap"),
            // F4.8d: las escrituras, por `abi` (lo que no hacen sale a la VM antes de la instrucción).
            NIns::PathRoot { c, root } => {
                let ex = exit_before!(pc);
                let t = vs.tag(&mut b, &st, root);
                guard_tags(&mut b, t, &[TAG_LIST, TAG_MAP], ex);
                let p = vs.ptr(&mut b, &st, root);
                let r = b.ins().call(h.writes?.path_root, &[ctx, p]);
                let r = b.inst_results(r)[0];
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 0);
                exit_if(&mut b, bad, ex);
                if c != DISCARD {
                    b.def_var(vs.p[c as usize].ptr, p);
                }
            }
            NIns::PathStep { c, idx, site } => {
                let ex = exit_before!(pc);
                let cp = b.use_var(vs.p[c as usize].ptr);
                let (it, ib, ip) = vs.index_parts(&mut b, &st, idx);
                let sv = b.ins().iconst(I64, i64::from(site));
                let r = b.ins().call(h.writes?.path_step, &[ctx, cp, it, ib, ip, sv]);
                let r = b.inst_results(r)[0];
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 0);
                exit_if(&mut b, bad, ex);
                if let Some(o) = idx {
                    vs.consume(&mut b, o);
                }
                b.def_var(vs.p[c as usize].ptr, r);
            }
            NIns::PathSet { c, idx, site, src, dst } => {
                let ex = exit_before!(pc);
                let cp = b.use_var(vs.p[c as usize].ptr);
                let (it, ib, ip) = vs.index_parts(&mut b, &st, idx);
                let sv = b.ins().iconst(I64, i64::from(site));
                let (vt, vb, vp) = vs.value_parts(&mut b, &st, src);
                let r = b.ins().call(h.writes?.path_set, &[ctx, cp, it, ib, ip, sv, vt, vb, vp]);
                let r = b.inst_results(r)[0];
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 0);
                exit_if(&mut b, bad, ex);
                // El valor, a `dst` (como la VM), antes de consumir los operandos.
                if dst != DISCARD {
                    vs.copy(&mut b, &st, src, dst as usize);
                }
                if let Some(o) = idx {
                    vs.consume(&mut b, o);
                }
                if Some(dst as usize) != Func::consumed(src) {
                    vs.consume(&mut b, src);
                }
                vs.put_nothing(&mut b, c as usize);
            }
            NIns::AppendPush { dst, func, args, root } => {
                let ex = exit_before!(pc);
                // Un nivel de profundidad, como la llamada al builtin.
                let d = b.use_var(dv);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_fixed(&mut b, ctx, OFF_MAX_DEPTH);
                let over = b.ins().icmp(IntCC::UnsignedGreaterThan, d1, mx);
                exit_if(&mut b, over, ex);
                let a0 = NOpnd::Copy(args);
                let tr = vs.tag(&mut b, &st, root);
                guard_tags(&mut b, tr, &[TAG_LIST], ex);
                let ta = vs.tag(&mut b, &st, a0);
                guard_tags(&mut b, ta, &[TAG_LIST], ex);
                let rp = vs.ptr(&mut b, &st, root);
                let ap = vs.ptr(&mut b, &st, a0);
                let (it, ib, ip) = vs.value_parts(&mut b, &st, NOpnd::Copy(args + 1));
                let r = b.ins().call(h.writes?.append, &[ctx, rp, ap, it, ib, ip]);
                let r = b.inst_results(r)[0];
                let bad = b.ins().icmp_imm_s(IntCC::Equal, r, 0);
                exit_if(&mut b, bad, ex);
                vs.put_nothing(&mut b, func as usize);
                vs.put_nothing(&mut b, args as usize);
                vs.put_nothing(&mut b, args as usize + 1);
                if dst != DISCARD {
                    // El resultado es la lista de la raíz (en su lugar).
                    let d = dst as usize;
                    vs.put_tag(&mut b, d, TAG_LIST);
                    let z = b.ins().iconst(I64, 0);
                    vs.put_bits(&mut b, d, z);
                    b.def_var(vs.p[d].ptr, rp);
                }
            }
        }
    }
    if open {
        return None;
    }

    // Las salidas: guardan los valores vivos (las palabras de cada tipo, ver `words`, y aparte los
    // punteros, ver `ptr_words`), avisan (`synsema_jit_deopt`) y vuelven.
    for ex in exits {
        b.switch_to_block(ex.block);
        let p = &points[ex.point as usize];
        let (stored, nptr) = (p.stored(), p.ptrs());
        let slot = b.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, (8 * stored.max(1)) as u32, 3));
        // La ranura de punteros, sólo si hay (si no, la dirección es 0 y la cuenta también).
        let pslot = (nptr > 0).then(|| b.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, (8 * nptr) as u32, 3)));
        ptr_slots.extend(pslot);
        let (mut k, mut kp) = (0i32, 0i32);
        for (place, kind) in &p.values {
            let pv = vs.p[f.var_of(*place)];
            let ws: Vec<Value> = match kind {
                Kind::Int | Kind::Bool => vec![b.use_var(pv.bits)],
                Kind::Float => vec![b.use_var(pv.f)],
                Kind::Any(_) => vec![b.use_var(pv.tag), b.use_var(pv.bits), b.use_var(pv.f)],
                _ => Vec::new(),
            };
            for x in ws {
                // (`I64`: el tipo de la dirección, no el del valor.)
                b.ins().stack_store(I64, x, slot, 8 * k);
                k += 1;
            }
            if let (1, Some(ps)) = (ptr_words(*kind), pslot) {
                // F4.8d: un valor con caja que ya está en su lugar de la VM (su procedencia es su propio
                // lugar): 0, y la VM lo deja ahí (`NVal::Keep`).
                let v = f.var_of(*place);
                let keep = matches!(kind, Kind::Any(_)) && plan.prov.get(p.pc as usize).and_then(|x| x.as_ref()).is_some_and(|pv| pv[v] == Some(v));
                let x = if keep { b.ins().iconst(I64, 0) } else { b.use_var(pv.ptr) };
                b.ins().stack_store(I64, x, ps, 8 * kp);
                kp += 1;
            }
        }
        let addr = b.ins().stack_addr(I64, slot, 0);
        let paddr = match pslot {
            Some(ps) => b.ins().stack_addr(I64, ps, 0),
            None => b.ins().iconst(I64, 0),
        };
        let fi = b.ins().iconst(I64, i as i64);
        let pi = b.ins().iconst(I64, ex.point as i64);
        let cnt = b.ins().iconst(I64, stored as i64);
        let pcnt = b.ins().iconst(I64, nptr as i64);
        // F4.8a: la profundidad de este frame, si es el de más adentro (después de una llamada que
        // salió, ya la escribió el llamado).
        if p.call.is_none() {
            let d = b.use_var(dv);
            b.ins().store(flags, d, ctx, OFF_DEPTH);
        }
        b.ins().call(h.deopt, &[ctx, fi, pi, addr, cnt, paddr, pcnt]);
        let z = b.ins().iconst(I64, 0);
        b.ins().return_(&[z]);
    }
    b.seal_all_blocks();
    b.finalize(config);
    plans[i].points = points;
    plans[i].ptr_params = ptr_params;
    plans[i].ptr_slots = ptr_slots;
    plans[i].exec_sites = exec_sites;
    plans[i].exec_ptr_slots = exec_ptr_slots;
    Some(())
}

/// F4.8d2: la salida de un error de una llamada ajena (una por función: sin valores; ver `build`).
fn fail_exit(b: &mut FunctionBuilder, fail_block: &mut Option<Block>, points: &mut Vec<Point>, exits: &mut Vec<Exit>, pc: usize) -> Block {
    if let Some(bl) = fail_block {
        return *bl;
    }
    points.push(Point { pc: pc as u32, values: Vec::new(), call: None, planned: true });
    let bl = b.create_block();
    b.set_cold_block(bl);
    exits.push(Exit { block: bl, point: (points.len() - 1) as u32 });
    *fail_block = Some(bl);
    bl
}

/// `Move`: el valor de `src` a `dst` (leído antes de consumir `src`: pueden ser el mismo registro).
fn move_to(b: &mut FunctionBuilder, vs: &Vars, st: &[Kind], src: NOpnd, dst: Reg) {
    if dst == DISCARD {
        vs.consume(b, src);
        return;
    }
    let d = dst as usize;
    if Some(d) == Func::consumed(src) {
        // Mover un registro a sí mismo: queda igual.
        return;
    }
    vs.copy(b, st, src, d);
    vs.consume(b, src);
}

fn cc(op: NCmp) -> IntCC {
    match op {
        NCmp::Lt => IntCC::SignedLessThan,
        NCmp::Le => IntCC::SignedLessThanOrEqual,
        NCmp::Gt => IntCC::SignedGreaterThan,
        NCmp::Ge => IntCC::SignedGreaterThanOrEqual,
        NCmp::Eq => IntCC::Equal,
        NCmp::Ne => IntCC::NotEqual,
    }
}

/// `steps += w` (como la VM: da la vuelta, no satura), en el contexto mismo (F4.8a: una suma en
/// memoria, `add $w, off(ctx)`, sin cargar un puntero). En una variable salía peor: el asignador de
/// registros agregaba movimientos en cada salto hacia atrás (medido: `each` +6 %, bucle vacío +11 %).
fn emit_steps(b: &mut FunctionBuilder, ctx: Value, w: u32) {
    let s = b.ins().load(I64, MemFlagsData::trusted(), ctx, OFF_STEPS);
    let s2 = b.ins().iadd_imm_s(s, w as i64);
    b.ins().store(MemFlagsData::trusted(), s2, ctx, OFF_STEPS);
}

/// Un campo del contexto que no cambia durante la llamada (el puntero al flag de cancelación, el
/// tope de profundidad): `readonly` + `can_move` hacen que Cranelift la trate como pura (la saca de
/// los bucles y junta las repetidas).
fn ctx_fixed(b: &mut FunctionBuilder, ctx: Value, off: i32) -> Value {
    b.ins().load(I64, MemFlagsData::trusted().with_readonly().with_can_move(), ctx, off)
}

/// El flag de cancelación puesto: sale a la VM (que suma los pasos y arma el error). El flag se lee
/// cada vez con una carga atómica (el `load(Relaxed)` de la VM: lo escribe otro hilo). Con una carga
/// común, un bucle sin escrituras a memoria (F4.8a: `steps` en una variable) dejaba que el análisis de
/// alias de Cranelift juntara todas las lecturas en una y la cancelación nunca cortaba. Sólo la
/// dirección sale del bucle.
fn emit_cancel(b: &mut FunctionBuilder, ctx: Value, ex: Block) {
    let c = ctx_fixed(b, ctx, OFF_CANCEL);
    let flag = b.ins().atomic_load(I8, MemFlagsData::trusted(), c);
    let ok = b.create_block();
    b.ins().brif(flag, ex, &[], ok, &[]);
    b.seal_block(ok);
    b.switch_to_block(ok);
}

/// Los parámetros de una función de la unidad antes de los suyos: el contexto y la profundidad
/// (F4.8a: en un registro; ver `build`).
const HEAD_PARAMS: usize = 2;

/// La firma de una función de la unidad: el contexto, la profundidad y los parámetros; devuelve el
/// valor (cada uno una palabra: un `Float` en sus bits).
pub(crate) fn signature(sig: &mut ir::Signature, nparams: usize) {
    for _ in 0..HEAD_PARAMS + nparams {
        sig.params.push(AbiParam::new(I64));
    }
    sig.returns.push(AbiParam::new(I64));
}

/// La entrada desde Rust: `(ctx, *const i64) -> i64`, carga los argumentos y la profundidad y llama
/// a `f0`.
pub(crate) fn build_entry(func: &mut ir::Function, fbctx: &mut FunctionBuilderContext, f0: ir::FuncRef, nparams: usize, config: TargetFrontendConfig) {
    let mut b = FunctionBuilder::new(func, fbctx);
    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let ctx = b.block_params(entry)[0];
    let argp = b.block_params(entry)[1];
    let depth = ctx_load(&mut b, ctx, OFF_DEPTH);
    let mut argv = vec![ctx, depth];
    for k in 0..nparams {
        argv.push(b.ins().load(I64, MemFlagsData::trusted(), argp, (8 * k) as i32));
    }
    let call = b.ins().call(f0, &argv);
    let r = b.inst_results(call)[0];
    b.ins().return_(&[r]);
    b.seal_all_blocks();
    b.finalize(config);
}

/// **El invariante auditable de F4** (spec §F4.2): el código generado sólo toca memoria en el
/// contexto (a desplazamientos constantes), en los contadores cuyos punteros están en el contexto,
/// en los argumentos de la entrada y en sus propias ranuras de pila; nunca en una dirección armada
/// con un valor del programa. Sólo llama a funciones declaradas (la unidad y la salida a la VM).
/// `entry`: la entrada desde Rust, la única que carga de su segundo parámetro (el puntero a los
/// argumentos); en una función de la unidad los parámetros después del contexto son valores.
pub(crate) fn check_memory(func: &ir::Function, entry_fn: bool) -> bool {
    let Some(entry) = func.layout.entry_block() else { return false };
    let params = func.dfg.block_params(entry);
    let is_param = |v: Value| v == params[0] || (entry_fn && params.get(1) == Some(&v));
    // Un puntero cargado del contexto (el parámetro 0) a un desplazamiento fijo.
    let is_ctx_ptr = |v: Value| match func.dfg.value_def(v) {
        ValueDef::Result(inst, _) => {
            func.dfg.insts[inst].opcode() == Opcode::Load && func.dfg.inst_args(inst).first().is_some_and(|a| *a == params[0])
        }
        _ => false,
    };
    // Una ranura de pila propia (`stack_addr`, lo que arma `stack_store`).
    let is_stack = |v: Value| match func.dfg.value_def(v) {
        ValueDef::Result(inst, _) => func.dfg.insts[inst].opcode() == Opcode::StackAddr,
        _ => false,
    };
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            let op = func.dfg.insts[inst].opcode();
            let args = func.dfg.inst_args(inst);
            let ok = match op {
                // F4.8d2: también de una ranura propia (lo que dejó el host en los búferes de una llamada).
                Opcode::Load | Opcode::Uload8 | Opcode::AtomicLoad => is_param(args[0]) || is_ctx_ptr(args[0]) || is_stack(args[0]),
                // F4.8a: también en el contexto mismo (los contadores, a desplazamientos fijos).
                Opcode::Store => args[1] == params[0] || is_ctx_ptr(args[1]) || is_stack(args[1]),
                // Reinterpretar los bits de un valor (un `Float` en una palabra): no toca memoria.
                Opcode::StackAddr | Opcode::Call | Opcode::Bitcast => true,
                _ => !(op.can_load() || op.can_store() || op.is_call()),
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

/// **La procedencia de los punteros (F4.7b).** El código generado no toca memoria con un valor del
/// programa (`check_memory`), pero sí le pasa punteros a las lecturas de `abi` y los guarda en las
/// salidas, y `abi` los usa. Esto verifica que cada uno venga de donde puede venir un puntero: un
/// parámetro de la entrada que es un lugar con caja (`ptr_params`), lo que dejó una lectura en el
/// contexto (`OFF_OUT_PTR`), lo que devuelve `list_body`, el 0, o la unión de esos por los bloques;
/// nunca de una cuenta con un valor. Si no, la unidad no se compila.
pub(crate) fn check_pointers(func: &ir::Function, h: &Helpers, ptr_params: &[usize], ptr_slots: &[StackSlot], exec_ptr_slots: &[StackSlot]) -> bool {
    let Some(entry) = func.layout.entry_block() else { return false };
    // Sin punteros que verificar (ninguna lectura, ninguna ranura de punteros: lo numérico), nada que
    // hacer.
    let reads = func.layout.blocks().any(|bl| {
        func.layout.block_insts(bl).any(|inst| match &func.dfg.insts[inst] {
            ir::InstructionData::Call { func_ref, .. } => h.pointer_args(*func_ref).is_some(),
            _ => false,
        })
    });
    if !reads && ptr_slots.is_empty() && ptr_params.is_empty() && exec_ptr_slots.is_empty() {
        return true;
    }
    // El frontend deja alias (`v96 -> v19`): se compara lo que resuelven.
    let res = |v: Value| func.dfg.resolve_aliases(v);
    let bparams = func.dfg.block_params(entry);
    let ctx = bparams[0];
    // F4.8d2: la dirección de un búfer de punteros de una llamada ajena.
    let is_exec_ptr_slot = |v: Value| match func.dfg.value_def(v) {
        ValueDef::Result(inst, _) => match &func.dfg.insts[inst] {
            d @ ir::InstructionData::StackAddr { .. } => d.stack_slot().is_some_and(|s| exec_ptr_slots.contains(&s)),
            _ => false,
        },
        _ => false,
    };
    let mut ok_vals: std::collections::HashSet<Value> = ptr_params.iter().filter_map(|k| bparams.get(*k).copied()).collect();
    // Las definiciones que son punteros por sí mismas.
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            let data = &func.dfg.insts[inst];
            match data.opcode() {
                Opcode::Iconst => {
                    if let ir::InstructionData::UnaryImm { imm, .. } = data {
                        if imm.bits() == 0 {
                            ok_vals.insert(func.dfg.first_result(inst));
                        }
                    }
                }
                Opcode::Load => {
                    if let ir::InstructionData::Load { arg, offset, .. } = data {
                        // Lo que dejó una lectura en el contexto, o el host en un búfer de punteros.
                        if (res(*arg) == ctx && i32::from(*offset) == OFF_OUT_PTR) || is_exec_ptr_slot(res(*arg)) {
                            ok_vals.insert(func.dfg.first_result(inst));
                        }
                    }
                }
                Opcode::Call => {
                    if let ir::InstructionData::Call { func_ref, .. } = data {
                        if h.pointer_args(*func_ref).is_some_and(|(_, ret)| ret) {
                            ok_vals.insert(func.dfg.first_result(inst));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Los parámetros de bloque: punteros si todo lo que les llega lo es (punto fijo, desde "todos").
    let mut incoming: HashMap<Value, Vec<Value>> = HashMap::new();
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            for call in func.dfg.insts[inst].branch_destination(&func.dfg.jump_tables, &func.dfg.exception_tables) {
                let target = call.block(&func.dfg.value_lists);
                let tparams = func.dfg.block_params(target);
                for (k, a) in call.args(&func.dfg.value_lists).enumerate() {
                    if let (BlockArg::Value(v), Some(p)) = (a, tparams.get(k)) {
                        incoming.entry(*p).or_default().push(res(v));
                    }
                }
            }
        }
    }
    // F4.8d2: un `select` entre dos punteros (la dirección nueva o la vieja de un valor) es uno.
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            if func.dfg.insts[inst].opcode() == Opcode::Select {
                let a = func.dfg.inst_args(inst);
                incoming.insert(func.dfg.first_result(inst), vec![res(a[1]), res(a[2])]);
            }
        }
    }
    let mut cand: std::collections::HashSet<Value> = incoming.keys().copied().collect();
    loop {
        let keep: std::collections::HashSet<Value> =
            cand.iter().copied().filter(|p| incoming[p].iter().all(|v| ok_vals.contains(v) || cand.contains(v))).collect();
        if keep.len() == cand.len() {
            break;
        }
        cand = keep;
    }
    ok_vals.extend(cand);
    let is_ptr_slot = |v: Value| match func.dfg.value_def(v) {
        ValueDef::Result(inst, _) => match &func.dfg.insts[inst] {
            d @ ir::InstructionData::StackAddr { .. } => d.stack_slot().is_some_and(|s| ptr_slots.contains(&s) || exec_ptr_slots.contains(&s)),
            _ => false,
        },
        _ => false,
    };
    for block in func.layout.blocks() {
        for inst in func.layout.block_insts(block) {
            let data = &func.dfg.insts[inst];
            let args = func.dfg.inst_args(inst);
            match data.opcode() {
                Opcode::Call => {
                    if let ir::InstructionData::Call { func_ref, .. } = data {
                        if let Some((pargs, _)) = h.pointer_args(*func_ref) {
                            if pargs.iter().any(|k| !args.get(*k).is_some_and(|a| ok_vals.contains(&res(*a)))) {
                                return false;
                            }
                        }
                    }
                }
                Opcode::Store if is_ptr_slot(res(args[1])) => {
                    if !ok_vals.contains(&res(args[0])) {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use cranelift_codegen::ir::{Function, Signature, UserFuncName};
    use cranelift_codegen::isa::CallConv;

    fn func(body: impl FnOnce(&mut FunctionBuilder, Value, Value)) -> Function {
        let mut sig = Signature::new(CallConv::SystemV);
        signature(&mut sig, 1);
        let mut f = Function::with_name_signature(UserFuncName::default(), sig);
        let mut fbctx = FunctionBuilderContext::new();
        let mut b = FunctionBuilder::new(&mut f, &mut fbctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        let (ctx, x) = (b.block_params(entry)[0], b.block_params(entry)[HEAD_PARAMS]);
        body(&mut b, ctx, x);
        b.seal_all_blocks();
        f
    }

    #[test]
    fn memory_through_the_context_is_allowed() {
        let f = func(|b, ctx, x| {
            b.ins().store(MemFlagsData::trusted(), x, ctx, OFF_DEPTH);
            let p = ctx_fixed(b, ctx, OFF_CANCEL);
            let c = b.ins().atomic_load(I8, MemFlagsData::trusted(), p);
            let c = b.ins().uextend(I64, c);
            let _ = c;
            b.ins().return_(&[x]);
        });
        assert!(check_memory(&f, false));
    }

    /// Una dirección armada con un valor del programa (acá, el parámetro sumado al contexto): el
    /// verificador la rechaza y la unidad no se compila.
    #[test]
    fn an_address_built_from_a_value_is_rejected() {
        let f = func(|b, ctx, x| {
            let addr = b.ins().iadd(ctx, x);
            b.ins().store(MemFlagsData::trusted(), x, addr, 0);
            b.ins().return_(&[x]);
        });
        assert!(!check_memory(&f, false));
        // Cargar desde un parámetro que es un valor del programa: tampoco (sólo la entrada carga de
        // su segundo parámetro, el puntero a los argumentos).
        let g = func(|b, _ctx, x| {
            let v = b.ins().load(I64, MemFlagsData::trusted(), x, 0);
            b.ins().return_(&[v]);
        });
        assert!(!check_memory(&g, false));
        // (La entrada sí carga de su segundo parámetro, el puntero a los argumentos: lo ejercita cada
        // unidad que se compila, `build_entry` + `check_memory(…, true)`.)
    }

    #[test]
    fn words_per_kind() {
        assert_eq!(words(Kind::Int), 1);
        assert_eq!(words(Kind::Float), 1);
        assert_eq!(words(Kind::Any(true)), 3);
        assert_eq!(words(Kind::Nothing), 0);
    }

    #[test]
    fn joining_values_gives_any() {
        assert_eq!(join(Kind::Int, Kind::Float), Kind::Any(false));
        assert_eq!(join(Kind::Int, Kind::Undef), Kind::Any(true));
        assert_eq!(join(Kind::Any(false), Kind::Undef), Kind::Any(true));
        assert_eq!(join(Kind::Int, Kind::Callee(0)), Kind::Top);
        assert_eq!(join(Kind::Bot, Kind::Float), Kind::Float);
    }
}
