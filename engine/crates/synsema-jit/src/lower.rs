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
use cranelift_codegen::ir::{self, AbiParam, Block, InstBuilder, MemFlagsData, Opcode, StackSlotData, StackSlotKind, Value, ValueDef};
use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use synsema_core::native_tier::{NArith, NCall, NCmp, NConst, NFArith, NFunc, NIns, NOpnd, NSeen, NUnary, NUnit, Place, Reg, DISCARD};

use crate::abi::{OFF_CANCEL, OFF_DEPTH, OFF_MAX_DEPTH, OFF_STATUS, OFF_STEPS};

/// Las etiquetas de un valor en el código nativo (la variable de etiqueta de cada lugar).
pub(crate) const TAG_HOLE: i64 = 0;
pub(crate) const TAG_NOTHING: i64 = 1;
pub(crate) const TAG_INT: i64 = 2;
pub(crate) const TAG_FLOAT: i64 = 3;
pub(crate) const TAG_BOOL: i64 = 4;
/// Una task de la unidad o el builtin `range` (nunca se juntan con un valor: su tipo es estático).
pub(crate) const TAG_OTHER: i64 = 7;

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
    /// F4.7: según el camino, `nothing`, `Int`, `Bool` o `Float` (la etiqueta dice cuál); `true` si
    /// además puede ser un hueco.
    Any(bool),
    /// La task de la función de la unidad.
    Callee(u32),
    /// El builtin `range` (F4.2b).
    RangeFn,
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
        NSeen::Boxed => Kind::Top,
    }
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
        Kind::Callee(_) | Kind::RangeFn => TAG_OTHER,
        _ => return None,
    })
}

/// Cuántas palabras guarda una salida para un valor de este tipo (ver `abi::Compiled::call`): un
/// `Int`, un `Bool` o un `Float`, una; un `Any`, tres (etiqueta, bits, `f64`); el resto, ninguna
/// (el tipo ya dice cuál es).
pub(crate) fn words(k: Kind) -> usize {
    match k {
        Kind::Int | Kind::Bool | Kind::Float => 1,
        Kind::Any(_) => 3,
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
}

impl Plan {
    /// Cuántos parámetros (además del contexto) tiene la función.
    pub fn nargs(&self, f: &NFunc) -> usize {
        if f.osr.is_some() {
            self.inputs.len()
        } else {
            f.nparams as usize
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
                match st[self.iter_var(it, 0)] {
                    Kind::Int => {}
                    Kind::Top => return Err(()),
                    _ => {
                        *trap = true;
                        return Ok(Next::Stop);
                    }
                }
                // (En la salida el lugar no se escribe, pero lo que sigue es el `EachEndV` que lo
                // suelta: el tipo de acá no se ve.)
                st[self.nregs + slot as usize] = Kind::Int;
                Next::Branch(pc as u32 + 1, exit)
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
            NIns::Move { dst: d, src } | NIns::Unary { dst: d, a: src, .. } | NIns::ToBool { dst: d, src } => {
                op(&mut uses, &mut defs, src);
                dst(&mut defs, d);
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
            NIns::RangeFn { dst: d } => {
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
        if f.f.code.is_empty() || f.f.nparams as usize > f.nregs || f.f.nparams > 8 {
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
    // Lo que devuelve una función (una palabra) tiene que tener un tipo estático.
    if rets.iter().any(|r| matches!(r, Kind::Top | Kind::Any(_))) {
        return None;
    }
    for p in params.iter_mut().flatten() {
        // Una task que no se llama desde ningún lugar al que se llegue: no importa.
        if *p == Kind::Bot {
            *p = Kind::Int;
        }
        if !param_ok(*p) {
            return None;
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
                // Nunca con un valor con caja en un lugar que toca el código nativo: sus cuentas de
                // referencias (y con ellas el copy-on-write) quedan como en la VM.
                if o.init[v] == NSeen::Boxed {
                    return None;
                }
                inputs.push((f.place_of(v), o.init[v]));
            }
            if inputs.len() > MAX_INPUTS {
                return None;
            }
        }
        plans.push(Plan { state, live, trap, ret, params, points: Vec::new(), inputs });
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

/// Las tres variables de Cranelift de un lugar de la VM.
#[derive(Clone, Copy)]
struct Parts {
    tag: Variable,
    bits: Variable,
    f: Variable,
}

/// Qué partes de un lugar se usan en alguna parte de la función: la etiqueta sólo si en algún
/// punto es `Any`; los bits si es un `Int`, un `Bool`, `nothing` o `Any`; el `f64` si es un `Float` o
/// `Any`. Lo que no se usa no se define (menos trabajo para Cranelift al compilar).
#[derive(Clone, Copy, Default)]
struct Need {
    tag: bool,
    bits: bool,
    f: bool,
}

fn needs(nvars: usize, state: &[Option<Vec<Kind>>]) -> Vec<Need> {
    let mut out = vec![Need::default(); nvars];
    for st in state.iter().flatten() {
        for (n, k) in out.iter_mut().zip(st) {
            match k {
                Kind::Any(_) => *n = Need { tag: true, bits: true, f: true },
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

    /// Su `f64` (sólo si es un `Float`).
    fn float(&self, b: &mut FunctionBuilder, o: NOpnd) -> Value {
        match o {
            NOpnd::Const(NConst::Float(x)) => b.ins().f64const(f64::from_bits(x)),
            NOpnd::Const(_) => b.ins().f64const(0.0),
            _ => b.use_var(self.var(o).expect("variable").f),
        }
    }

    fn put_tag(&self, b: &mut FunctionBuilder, v: usize, t: i64) {
        if self.need[v].tag {
            let x = b.ins().iconst(I64, t);
            b.def_var(self.p[v].tag, x);
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
                let (t, x, f) = (b.use_var(p.tag), b.use_var(p.bits), b.use_var(p.f));
                // El destino es `Any` después de esto: usa sus tres partes.
                b.def_var(self.p[dst].tag, t);
                b.def_var(self.p[dst].bits, x);
                b.def_var(self.p[dst].f, f);
            }
            _ => self.put_other(b, dst),
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
                b.ins().select(isf, tf, ti)
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
    deopt: ir::FuncRef,
    config: TargetFrontendConfig,
) -> Option<()> {
    let f = Func::new(&unit.funcs[i], unit);
    let n = f.f.code.len();
    let np = plans[i].nargs(f.f);

    let mut b = FunctionBuilder::new(func, fbctx);
    let parts: Vec<Parts> =
        (0..f.nvars).map(|_| Parts { tag: b.declare_var(I64), bits: b.declare_var(I64), f: b.declare_var(F64) }).collect();
    let vs = Vars { p: parts, need: needs(f.nvars, &plans[i].state), f: &f };
    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let ctx = b.block_params(entry)[0];
    let params: Vec<Value> = b.block_params(entry)[1..=np].to_vec();
    // Lo que tiene cada lugar al entrar. Un bucle: cada parámetro es un lugar que toca (`inputs`),
    // con lo que tenía al compilar; lo que no toca, sin información. Una task: sus parámetros son
    // `r0..`, el resto de los registros `nothing` y la ventana vacía.
    let mut init: Vec<(Kind, Option<Value>)> = vec![(Kind::Bot, None); f.nvars];
    if f.f.osr.is_some() {
        for (k, (place, seen)) in plans[i].inputs.iter().enumerate() {
            init[f.var_of(*place)] = (seen_kind(*seen), Some(params[k]));
        }
    } else {
        for (v, x) in init.iter_mut().enumerate() {
            *x = if v < np {
                (plans[i].params[v], Some(params[v]))
            } else if v < f.nregs {
                (Kind::Nothing, None)
            } else {
                (Kind::Undef, None)
            };
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
            match (k, x) {
                (Kind::Bot, _) => {}
                (k, Some(x)) => vs.put_word(&mut b, v, *k, *x),
                (k, None) => vs.put_word(&mut b, v, *k, z),
            }
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
        for v in f.uses_defs(pc).0 {
            if st[v] == Kind::Any(true) {
                let ex = exit_before!(pc);
                let t = b.use_var(vs.p[v].tag);
                let hole = b.ins().icmp_imm_s(IntCC::Equal, t, TAG_HOLE);
                exit_if(&mut b, hole, ex);
            }
        }
        match f.f.code[pc] {
            NIns::Nop | NIns::Scalar { .. } => {}
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
            NIns::LoadCallee { dst, .. } | NIns::RangeFn { dst } => {
                if dst != DISCARD {
                    vs.put_other(&mut b, dst as usize);
                }
            }
            NIns::Call { dst, func: freg, args, n: na } => {
                let Kind::Callee(target) = st[freg as usize] else { return None };
                // La profundidad de la VM, con el mismo tope: si lo pasaría, la VM hace la llamada
                // (y da el error).
                let ex = exit_before!(pc);
                let dp = ctx_load(&mut b, ctx, OFF_DEPTH);
                let d = b.ins().load(I64, flags, dp, 0);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_load(&mut b, ctx, OFF_MAX_DEPTH);
                let over = b.ins().icmp(IntCC::UnsignedGreaterThan, d1, mx);
                exit_if(&mut b, over, ex);
                b.ins().store(flags, d1, dp, 0);
                let mut argv = vec![ctx];
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
                b.ins().store(flags, d, dp, 0);
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
                let dp = ctx_load(&mut b, ctx, OFF_DEPTH);
                let d = b.ins().load(I64, flags, dp, 0);
                let d1 = b.ins().iadd_imm_s(d, 1);
                let mx = ctx_load(&mut b, ctx, OFF_MAX_DEPTH);
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
        }
    }
    if open {
        return None;
    }

    // Las salidas: guardan los valores vivos (las palabras de cada tipo, ver `words`), avisan
    // (`synsema_jit_deopt`) y vuelven.
    for ex in exits {
        b.switch_to_block(ex.block);
        let p = &points[ex.point as usize];
        let stored = p.stored();
        let slot = b.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, (8 * stored.max(1)) as u32, 3));
        let mut k = 0i32;
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
        }
        let addr = b.ins().stack_addr(I64, slot, 0);
        let fi = b.ins().iconst(I64, i as i64);
        let pi = b.ins().iconst(I64, ex.point as i64);
        let cnt = b.ins().iconst(I64, stored as i64);
        b.ins().call(deopt, &[ctx, fi, pi, addr, cnt]);
        let z = b.ins().iconst(I64, 0);
        b.ins().return_(&[z]);
    }
    b.seal_all_blocks();
    b.finalize(config);
    plans[i].points = points;
    Some(())
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

/// `steps += w` (como la VM: da la vuelta, no satura).
fn emit_steps(b: &mut FunctionBuilder, ctx: Value, w: u32) {
    let p = ctx_load(b, ctx, OFF_STEPS);
    let s = b.ins().load(I64, MemFlagsData::trusted(), p, 0);
    let s2 = b.ins().iadd_imm_s(s, w as i64);
    b.ins().store(MemFlagsData::trusted(), s2, p, 0);
}

/// El flag de cancelación puesto: sale a la VM (que suma los pasos y arma el error).
fn emit_cancel(b: &mut FunctionBuilder, ctx: Value, ex: Block) {
    let c = ctx_load(b, ctx, OFF_CANCEL);
    let flag = b.ins().uload8(I64, MemFlagsData::trusted(), c, 0);
    let ok = b.create_block();
    b.ins().brif(flag, ex, &[], ok, &[]);
    b.seal_block(ok);
    b.switch_to_block(ok);
}

/// La firma de una función de la unidad: el contexto y los parámetros, devuelve el valor (cada
/// uno una palabra: un `Float` en sus bits).
pub(crate) fn signature(sig: &mut ir::Signature, nparams: usize) {
    sig.params.push(AbiParam::new(I64));
    for _ in 0..nparams {
        sig.params.push(AbiParam::new(I64));
    }
    sig.returns.push(AbiParam::new(I64));
}

/// La entrada desde Rust: `(ctx, *const i64) -> i64`, carga los argumentos y llama a `f0`.
pub(crate) fn build_entry(func: &mut ir::Function, fbctx: &mut FunctionBuilderContext, f0: ir::FuncRef, nparams: usize, config: TargetFrontendConfig) {
    let mut b = FunctionBuilder::new(func, fbctx);
    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let ctx = b.block_params(entry)[0];
    let argp = b.block_params(entry)[1];
    let mut argv = vec![ctx];
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
                Opcode::Load | Opcode::Uload8 => is_param(args[0]) || is_ctx_ptr(args[0]),
                Opcode::Store => is_ctx_ptr(args[1]) || is_stack(args[1]),
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
        let (ctx, x) = (b.block_params(entry)[0], b.block_params(entry)[1]);
        body(&mut b, ctx, x);
        b.seal_all_blocks();
        f
    }

    #[test]
    fn memory_through_the_context_is_allowed() {
        let f = func(|b, ctx, x| {
            emit_steps(b, ctx, 3);
            let p = ctx_load(b, ctx, OFF_DEPTH);
            b.ins().store(MemFlagsData::trusted(), x, p, 0);
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
        assert!(check_memory(&g, true));
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
