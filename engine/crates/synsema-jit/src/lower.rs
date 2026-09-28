//! La vista del bytecode (`NUnit`) → Cranelift. Sin `unsafe`.
//!
//! Dos análisis sobre el código de la VM y después la traducción:
//! - **Tipos** (hacia adelante, punto fijo entre las funciones de la unidad): qué hay en cada
//!   registro y lugar de la ventana antes de cada instrucción. Los parámetros son enteros (la
//!   entrada lo verifica), el resto de los registros empieza en `nothing` (como la VM) y los
//!   lugares de la ventana, vacíos. Como los tipos son estáticos, el código nativo no lleva guardas
//!   de tipo: una instrucción cuyo tipo no es el que especializó la VM sale siempre a la VM.
//! - **Vivos** (hacia atrás, con los sucesores de la VM): qué valores hay que devolverle a la VM en
//!   cada salida. Lo que no está vivo la VM lo tiene vacío (nadie lo vuelve a leer).
//!
//! Una unidad con algo que no se puede representar (un valor que según el camino es de un tipo o
//! de otro y se usa, una llamada que no es a la unidad) no se compila: queda en la VM.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_codegen::ir::types::I64;
use cranelift_codegen::ir::{self, AbiParam, Block, InstBuilder, MemFlagsData, Opcode, StackSlotData, StackSlotKind, Value, ValueDef};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use synsema_core::native_tier::{NArith, NCall, NCmp, NConst, NFunc, NIns, NOpnd, NSeen, NUnit, Place, Reg, DISCARD};

use crate::abi::{OFF_CANCEL, OFF_DEPTH, OFF_MAX_DEPTH, OFF_STATUS, OFF_STEPS};

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
    /// La task de la función de la unidad.
    Callee(u32),
    /// El builtin `range` (F4.2b).
    RangeFn,
    /// Según el camino, distinto: no se puede usar.
    Top,
}

fn join(a: Kind, b: Kind) -> Kind {
    match (a, b) {
        _ if a == b => a,
        (Kind::Bot, x) | (x, Kind::Bot) => x,
        _ => Kind::Top,
    }
}

fn const_kind(c: NConst) -> Kind {
    match c {
        NConst::Int(_) => Kind::Int,
        NConst::Bool(_) => Kind::Bool,
        NConst::Nothing => Kind::Nothing,
    }
}

/// Lo que tenía un lugar al compilar un bucle (F4.2).
fn seen_kind(s: NSeen) -> Kind {
    match s {
        NSeen::Int => Kind::Int,
        NSeen::Bool => Kind::Bool,
        NSeen::Nothing => Kind::Nothing,
        NSeen::Hole => Kind::Undef,
        NSeen::Boxed => Kind::Top,
    }
}

fn const_bits(c: NConst) -> i64 {
    match c {
        NConst::Int(x) => x,
        NConst::Bool(b) => i64::from(b),
        NConst::Nothing => 0,
    }
}

/// Una salida a la VM: dónde sigue, qué valores le devuelve (los `Int`/`Bool` en el orden en que
/// el código nativo los guarda) y, si el frame esperaba a su llamado, esa llamada.
#[derive(Clone, Debug)]
pub(crate) struct Point {
    pub pc: u32,
    pub values: Vec<(Place, Kind)>,
    pub call: Option<NCall>,
    /// El fin de un bucle nativo (F4.2), no una desoptimización.
    pub planned: bool,
}

impl Point {
    /// Cuántos valores guarda el código nativo.
    pub fn stored(&self) -> usize {
        self.values.iter().filter(|(_, k)| matches!(k, Kind::Int | Kind::Bool)).count()
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
    /// siempre a la VM antes de ella.
    fn step(&self, pc: usize, st: &mut [Kind], rets: &[Kind], trap: &mut bool) -> Result<Next, ()> {
        let set = |st: &mut [Kind], r: Reg, k: Kind| {
            if r != DISCARD {
                st[r as usize] = k;
            }
        };
        // Leer un valor: un hueco lo busca la VM por nombre (sale); algo que depende del camino no
        // se puede representar.
        let read = |k: Kind, trap: &mut bool| -> Result<Kind, ()> {
            match k {
                Kind::Top => Err(()),
                Kind::Undef => {
                    *trap = true;
                    Ok(k)
                }
                _ => Ok(k),
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
                let (ka, kb) = (self.opnd_kind(st, a), self.opnd_kind(st, b));
                if ka == Kind::Top || kb == Kind::Top {
                    return Err(());
                }
                let out = if matches!(self.f.code[pc], NIns::IntArith { .. }) { Kind::Int } else { Kind::Bool };
                if ka == Kind::Bot || kb == Kind::Bot {
                    set(st, dst, Kind::Bot);
                } else if ka == Kind::Int && kb == Kind::Int {
                    set(st, dst, out);
                } else {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                Next::Fall
            }
            NIns::IntCmpJump { a, b, to, .. } => {
                let (ka, kb) = (self.opnd_kind(st, a), self.opnd_kind(st, b));
                if ka == Kind::Top || kb == Kind::Top {
                    return Err(());
                }
                if !(matches!(ka, Kind::Int | Kind::Bot) && matches!(kb, Kind::Int | Kind::Bot)) {
                    *trap = true;
                    return Ok(Next::Stop);
                }
                Next::Branch(pc as u32 + 2, to)
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
                for i in 0..n as usize {
                    if !matches!(st[args as usize + i], Kind::Int | Kind::Bot) {
                        return Err(());
                    }
                }
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
                    // Una global vacía: la VM la busca afuera (y podría ser una lista).
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
                        Kind::Int | Kind::Bot => {}
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

    /// Los tipos antes de cada instrucción, el valor que devuelve y dónde sale siempre.
    #[allow(clippy::type_complexity)]
    fn kinds(&self, rets: &[Kind]) -> Result<(Vec<Option<Vec<Kind>>>, Vec<bool>, Kind), ()> {
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
                for k in init.iter_mut().take(self.f.nparams as usize) {
                    *k = Kind::Int;
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
        let mut work = vec![start];
        while let Some(pc) = work.pop() {
            let mut st = state[pc].clone().expect("estado");
            let mut t = false;
            let next = self.step(pc, &mut st, rets, &mut t)?;
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
                            ret = join(ret, self.opnd_kind(&st, src));
                        }
                    }
                }
            }
        }
        Ok((state, trap, ret))
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
            NIns::Move { dst: d, src } => {
                op(&mut uses, &mut defs, src);
                dst(&mut defs, d);
                fall
            }
            // El camino rápido de la VM no consume los operandos (los mira sin moverlos).
            NIns::IntArith { dst: d, a, b, .. } | NIns::IntCmp { dst: d, a, b, .. } => {
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
    // Punto fijo de lo que devuelve cada función (las llamadas usan el de su destino).
    let mut rets = vec![Kind::Bot; funcs.len()];
    let mut results = None;
    for _ in 0..16 {
        let mut out = Vec::with_capacity(funcs.len());
        for f in &funcs {
            out.push(f.kinds(&rets).ok()?);
        }
        let new: Vec<Kind> = out.iter().map(|(_, _, r)| *r).collect();
        if new == rets {
            results = Some(out);
            break;
        }
        rets = new;
    }
    let results = results?;
    if rets.contains(&Kind::Top) {
        return None;
    }
    let mut plans = Vec::with_capacity(funcs.len());
    for (f, (state, trap, ret)) in funcs.iter().zip(results) {
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
        plans.push(Plan { state, live, trap, ret, points: Vec::new(), inputs });
    }
    Some(plans)
}

// =============================================================================================
// Traducción
// =============================================================================================

/// Los valores de un frame para una salida: los vivos con su tipo (los huecos y lo que no se sabe
/// qué es no van: la VM los tiene vacíos). `None` si alguno vivo no se puede representar.
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
    let vars: Vec<Variable> = (0..f.nvars).map(|_| b.declare_var(I64)).collect();
    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let ctx = b.block_params(entry)[0];
    let params: Vec<Value> = b.block_params(entry)[1..=np].to_vec();
    let zero = b.ins().iconst(I64, 0);
    // Un bucle: cada parámetro es un lugar que toca (`inputs`); una task: sus parámetros son `r0..`.
    let mut arg_of: Vec<Option<usize>> = vec![None; f.nvars];
    if f.f.osr.is_some() {
        for (k, (place, _)) in plans[i].inputs.iter().enumerate() {
            arg_of[f.var_of(*place)] = Some(k);
        }
    } else {
        for (v, a) in arg_of.iter_mut().enumerate().take(np) {
            *a = Some(v);
        }
    }
    for (v, var) in vars.iter().enumerate() {
        let x = arg_of[v].map_or(zero, |k| params[k]);
        b.def_var(*var, x);
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
        let val = |b: &mut FunctionBuilder, o: NOpnd| -> Value {
            match o {
                NOpnd::Reg(r) | NOpnd::Copy(r) => b.use_var(vars[r as usize]),
                NOpnd::Const(c) => b.ins().iconst(I64, const_bits(c)),
                NOpnd::Local(k) => b.use_var(vars[f.nregs + k as usize]),
                NOpnd::Global(g) => b.use_var(vars[f.global_var(g)]),
            }
        };
        let consume = |b: &mut FunctionBuilder, o: NOpnd| {
            if let NOpnd::Reg(r) = o {
                let z = b.ins().iconst(I64, 0);
                b.def_var(vars[r as usize], z);
            }
        };
        let set = |b: &mut FunctionBuilder, r: Reg, v: Value| {
            if r != DISCARD {
                b.def_var(vars[r as usize], v);
            }
        };
        match f.f.code[pc] {
            NIns::Nop => {}
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
                let x = b.ins().iconst(I64, const_bits(v));
                set(&mut b, dst, x);
            }
            NIns::Move { dst, src } => {
                let x = val(&mut b, src);
                consume(&mut b, src);
                set(&mut b, dst, x);
            }
            NIns::Drop { r } => {
                let z = b.ins().iconst(I64, 0);
                set(&mut b, r, z);
            }
            NIns::IntArith { dst, op, a, b: rb } => {
                let x = val(&mut b, a);
                let y = val(&mut b, rb);
                let r = match op {
                    NArith::Add | NArith::Sub | NArith::Mul => {
                        let (r, of) = match op {
                            NArith::Add => b.ins().sadd_overflow(x, y),
                            NArith::Sub => b.ins().ssub_overflow(x, y),
                            _ => b.ins().smul_overflow(x, y),
                        };
                        // Desborda: la VM repite la cuenta y da el `Big`.
                        let ex = exit_before!(pc);
                        let ok = b.create_block();
                        b.ins().brif(of, ex, &[], ok, &[]);
                        b.seal_block(ok);
                        b.switch_to_block(ok);
                        r
                    }
                    NArith::Mod => {
                        // `% 0`: el error lo arma la VM.
                        let ex = exit_before!(pc);
                        let ok = b.create_block();
                        let z = b.ins().icmp_imm_s(IntCC::Equal, y, 0);
                        b.ins().brif(z, ex, &[], ok, &[]);
                        b.seal_block(ok);
                        b.switch_to_block(ok);
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
                set(&mut b, dst, r);
            }
            NIns::IntCmp { dst, op, a, b: rb } => {
                let x = val(&mut b, a);
                let y = val(&mut b, rb);
                let c = b.ins().icmp(cc(op), x, y);
                let r = b.ins().uextend(I64, c);
                set(&mut b, dst, r);
            }
            NIns::IntCmpJump { op, a, b: rb, to } => {
                let x = val(&mut b, a);
                let y = val(&mut b, rb);
                let c = b.ins().icmp(cc(op), x, y);
                let (yes, no) = (*blocks.get(&(pc + 2))?, *blocks.get(&(to as usize))?);
                b.ins().brif(c, yes, &[], no, &[]);
                open = false;
            }
            NIns::JumpIfFalsy { src, to } => {
                let k = f.opnd_kind(&st, src);
                let x = val(&mut b, src);
                consume(&mut b, src);
                let (yes, no) = (*blocks.get(&(pc + 1))?, *blocks.get(&(to as usize))?);
                match k {
                    Kind::Int | Kind::Bool => {
                        b.ins().brif(x, yes, &[], no, &[]);
                    }
                    Kind::Nothing => {
                        b.ins().jump(no, &[]);
                    }
                    Kind::Callee(_) | Kind::RangeFn => {
                        b.ins().jump(yes, &[]);
                    }
                    _ => return None,
                }
                open = false;
            }
            NIns::Jump { to } => {
                let t = *blocks.get(&(to as usize))?;
                b.ins().jump(t, &[]);
                open = false;
            }
            NIns::LoadLocal { dst, slot } => {
                let x = b.use_var(vars[f.nregs + slot as usize]);
                set(&mut b, dst, x);
            }
            NIns::LetLocal { src, slot, dst } | NIns::SetLocal { src, slot, dst } => {
                let x = val(&mut b, src);
                consume(&mut b, src);
                b.def_var(vars[f.nregs + slot as usize], x);
                set(&mut b, dst, x);
            }
            NIns::LoadCallee { dst, .. } => {
                let z = b.ins().iconst(I64, 0);
                set(&mut b, dst, z);
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
                let ok = b.create_block();
                b.ins().brif(over, ex, &[], ok, &[]);
                b.seal_block(ok);
                b.switch_to_block(ok);
                b.ins().store(flags, d1, dp, 0);
                let mut argv = vec![ctx];
                for k in 0..na as usize {
                    argv.push(b.use_var(vars[args as usize + k]));
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
                let ok2 = b.create_block();
                b.ins().brif(status, ex2, &[], ok2, &[]);
                b.seal_block(ok2);
                b.switch_to_block(ok2);
                b.ins().store(flags, d, dp, 0);
                let z = b.ins().iconst(I64, 0);
                b.def_var(vars[freg as usize], z);
                for v in f.call_window(target as usize, args, na) {
                    b.def_var(vars[v], z);
                }
                set(&mut b, dst, r);
            }
            NIns::Give { src } | NIns::End { src } => {
                let x = val(&mut b, src);
                b.ins().return_(&[x]);
                open = false;
            }
            NIns::SetGlobal { src, g, dst } | NIns::LetGlobal { src, g, dst } => {
                let x = val(&mut b, src);
                consume(&mut b, src);
                b.def_var(vars[f.global_var(g)], x);
                set(&mut b, dst, x);
            }
            // El tipo estático ya probó que no es una lista ni un mapa.
            NIns::Scalar { .. } => {}
            NIns::RangeFn { dst } => {
                let z = b.ins().iconst(I64, 0);
                set(&mut b, dst, z);
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
                let ok = b.create_block();
                b.ins().brif(over, ex, &[], ok, &[]);
                b.seal_block(ok);
                b.switch_to_block(ok);
                let a: Vec<Value> = (0..n).map(|i| b.use_var(vars[first as usize + i as usize])).collect();
                let zero = b.ins().iconst(I64, 0);
                let one = b.ins().iconst(I64, 1);
                let (lo, hi, step) = match n {
                    1 => (zero, a[0], one),
                    2 => (a[0], a[1], one),
                    _ => {
                        let z = b.ins().icmp_imm_s(IntCC::Equal, a[2], 0);
                        let ok2 = b.create_block();
                        b.ins().brif(z, ex, &[], ok2, &[]);
                        b.seal_block(ok2);
                        b.switch_to_block(ok2);
                        (a[0], a[1], a[2])
                    }
                };
                for i in 0..n as usize {
                    b.def_var(vars[first as usize + i], zero);
                }
                for v in f.iters_from(it) {
                    b.def_var(vars[v], zero);
                }
                for (k, x) in [one, lo, hi, step].into_iter().enumerate() {
                    b.def_var(vars[f.iter_var(it, k as u8)], x);
                }
            }
            NIns::EachNext { it, slot, exit } => {
                // `RangeIter::next`: sin siguiente, a `exit`; si `i` quedó afuera, terminó; si no,
                // la vuelta con `i` y el siguiente con `checked_add` (si desborda, terminó después).
                let (vv, vn) = (vars[f.iter_var(it, 0)], vars[f.iter_var(it, 1)]);
                let valid = b.use_var(vv);
                let i = b.use_var(vn);
                let hi = b.use_var(vars[f.iter_var(it, 2)]);
                let step = b.use_var(vars[f.iter_var(it, 3)]);
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
                b.def_var(vars[f.nregs + slot as usize], i);
                b.ins().jump(go, &[]);
                open = false;
            }
            NIns::EachStep { head, first, n } => {
                let z = b.ins().iconst(I64, 0);
                for v in f.locals(first, n) {
                    b.def_var(vars[v], z);
                }
                let t = *blocks.get(&(head as usize))?;
                b.ins().jump(t, &[]);
                open = false;
            }
            NIns::EachEnd { it, first, n } => {
                let z = b.ins().iconst(I64, 0);
                for v in f.locals(first, n).chain(f.iters_from(it)) {
                    b.def_var(vars[v], z);
                }
            }
            NIns::Trap { .. } | NIns::Leave { .. } => unreachable!("salida sin trap"),
        }
    }
    if open {
        return None;
    }

    // Las salidas: guardan los valores vivos, avisan (`synsema_jit_deopt`) y vuelven.
    for ex in exits {
        b.switch_to_block(ex.block);
        let p = &points[ex.point as usize];
        let stored = p.stored();
        let slot = b.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, (8 * stored.max(1)) as u32, 3));
        let mut k = 0i32;
        for (place, kind) in &p.values {
            if matches!(kind, Kind::Int | Kind::Bool) {
                let x = b.use_var(vars[f.var_of(*place)]);
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

/// La firma de una función de la unidad: el contexto y los parámetros, devuelve el valor.
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
                Opcode::StackAddr | Opcode::Call => true,
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
}
