//! La VM y el nivel nativo (F4.1 de specs/compute-rendimiento.md). Hijo de `vm`: arma la vista del
//! bytecode que compila el nivel instalado (`crate::native_tier`), decide cuándo subir de nivel y
//! vuelve a la VM con el estado de los frames nativos. Todo seguro: el código de máquina y el
//! `unsafe` viven en `synsema-jit`.
//!
//! **Qué compila F4.1:** tasks con frame en registros (F3.3b/F3.7) cuyo código ya especializado es
//! numérico (`Int`/`Bool`): pasos, cancelación, aritmética y comparaciones enteras, saltos, locales,
//! `give` y llamadas posicionales a tasks de la misma unidad (la recursión incluida). Cualquier otra
//! instrucción deja la unidad en la VM.
//!
//! **Entrada:** una llamada de la VM a una task caliente reescribe su `Call` en `CallNative`; ahí
//! se verifica que los argumentos sean enteros y que las globales que la unidad lee sigan siendo las
//! mismas tasks (lo nativo no puede cambiarlas), y se entra.
//!
//! **Salida:** el código nativo sale antes de la instrucción que no puede hacer; cada frame nativo
//! devuelve su estado (`NFrame`) y acá se arman como frames de la VM, igual que si la VM hubiera
//! hecho esas llamadas (`vm_enter_regframe`): la VM sigue en el de más adentro, sin recursión en
//! Rust. Desde ahí todo es la VM.

use super::*;
use crate::native_tier::{self, NArith, NCmp, NConst, NFrame, NFunc, NIns, NOpnd, NOsr, NOutcome, NSeen, NUnit, NVal, NativeCode, NativeCx, Place};
use std::rc::Weak;

/// Cuántas llamadas a otras tasks puede sumar una unidad.
const MAX_FUNCS: usize = 8;
/// Cuántas veces puede salir a la VM una unidad antes de descartarla (una que sale siempre no paga).
const MAX_NATIVE_DEOPTS: u32 = 32;
/// El nivel nativo de una task (en `TaskCode`).
///
/// El conteo es una cuenta regresiva para que la llamada de la VM pague lo mínimo (una carga, una
/// comparación, una resta: `tick`): `left` = llamadas que faltan (0 = todavía no empezó); al llegar
/// a 1 decide `vm_native_tier_up`, fuera de línea. Una task que no se compila (`never`) queda con
/// la cuenta en `u32::MAX` y vuelve a pasar por ahí recién tras 4.000 millones de llamadas.
#[derive(Default)]
pub(crate) struct NativeState {
    left: Cell<u32>,
    never: Cell<bool>,
    unit: std::cell::OnceCell<NativeUnit>,
}

impl NativeState {
    /// Cuenta una llamada; `true` si hay que decidir (empezar la cuenta, compilar, reescribir el
    /// sitio de la llamada).
    #[inline(always)]
    pub(super) fn tick(&self) -> bool {
        let h = self.left.get();
        if h > 1 {
            self.left.set(h - 1);
            false
        } else {
            true
        }
    }

    fn give_up(&self) {
        self.never.set(true);
        self.left.set(u32::MAX);
    }

    /// La unidad compilada, si se puede usar.
    fn unit(&self) -> Option<&NativeUnit> {
        if self.never.get() {
            return None;
        }
        self.unit.get()
    }
}

/// Una unidad compilada: la task (`tasks[0]`) y las que llama. En un bucle (F4.2) la función 0 es
/// el bucle, que no es una task. El código de la VM de cada task (para volver) es el de la task.
pub(crate) struct NativeUnit {
    code: Box<dyn NativeCode>,
    /// `Weak`: la unidad vive en `tasks[0]` (o en el chunk del bucle).
    tasks: Vec<Option<Weak<SynTaskValue>>>,
    /// Los registros de la función 0 (el epílogo de `CallNative`).
    nregs0: u16,
    deps: Vec<Dep>,
    deopts: Cell<u32>,
    /// El builtin `range`, si el código lo tiene en un registro (para devolvérselo a la VM).
    range_fn: Option<SynValue>,
}

/// La global `name`, leída desde el `closure_env` de la función `from` (o, si es `None`, desde el
/// entorno donde corre el bucle), es la task de `to` (o, si es `None`, el builtin `range`).
struct Dep {
    from: Option<usize>,
    name: Arc<str>,
    to: Option<usize>,
}

impl NativeUnit {
    /// Las globales que el código nativo da por sabidas siguen siendo esas tasks (como `LoadGlobal`:
    /// por nombre desde el `closure_env`, o desde `here` para el bucle).
    fn deps_hold(&self, here: Option<&Rc<RefCell<Environment>>>) -> bool {
        self.deps.iter().all(|d| {
            let to = match d.to {
                Some(t) => match self.task(t) {
                    Some(t) => Some(t),
                    None => return false,
                },
                None => None,
            };
            let found = match d.from {
                Some(f) => match self.task(f) {
                    Some(from) => env_get(&from.closure_env, &d.name),
                    None => return false,
                },
                None => match here {
                    Some(e) => env_get(e, &d.name),
                    None => return false,
                },
            };
            match (found, to) {
                (Some(SynValue::Task(t)), Some(to)) => Rc::ptr_eq(&t, &to),
                (Some(SynValue::Builtin(b)), None) => b.name == "range",
                _ => false,
            }
        })
    }

    fn task(&self, f: usize) -> Option<Rc<SynTaskValue>> {
        self.tasks[f].as_ref().and_then(Weak::upgrade)
    }
}

/// Qué pasó en un `CallNative`.
pub(super) enum NativeStep {
    /// Terminó (el valor ya está en su destino).
    Done,
    /// No se puede entrar (la task, los argumentos o las globales ya no encajan): la instrucción
    /// volvió a ser `Call` y el despacho la repite. Todavía no se tocó nada.
    Retry,
    /// Salió a la VM a mitad de camino.
    Resume(Box<Resume>),
}

/// Los frames nativos convertidos en frames de la VM: `frames` van arriba del que llamó (en orden)
/// y la VM sigue en `enter` desde `pc`. `top0`: el largo de la pila de registros antes de la
/// llamada (el `top` del frame del que llamó).
pub(super) struct Resume {
    pub(super) frames: Vec<VmFrame>,
    pub(super) enter: Enter,
    pub(super) pc: usize,
    pub(super) top0: usize,
    /// Dónde empiezan los iteradores del frame de más adentro.
    pub(super) iter_base: usize,
}

/// Qué pasó en un `LoopBack` que llegó a su cuenta (F4.2).
pub(super) enum OsrStep {
    /// Sigue la VM (no se compiló, no se pudo entrar).
    Stay,
    /// El bucle corrió en nativo y salió: la VM sigue en este `pc` del mismo chunk.
    Exit(usize),
    /// Salió a mitad de una llamada de la unidad: el frame actual espera su resultado (vuelve en
    /// `pc`, lo deja en `dst`) y la VM sigue en los frames de `Resume`.
    Resume { r: Box<Resume>, pc: usize, dst: Reg },
}

// =============================================================================================
// La vista del bytecode
// =============================================================================================

/// Lo que arma la vista: las tasks de la unidad (la 0 puede ser un bucle) y de qué globales dependen.
#[derive(Default)]
struct Build {
    funcs: Vec<NFunc>,
    tasks: Vec<Option<Rc<SynTaskValue>>>,
    deps: Vec<Dep>,
    range_fn: Option<SynValue>,
}

impl Build {
    /// El índice de la task `y` en la unidad (la agrega si no está).
    fn callee(&mut self, y: Rc<SynTaskValue>) -> usize {
        match self.tasks.iter().position(|t| t.as_ref().is_some_and(|t| Rc::ptr_eq(t, &y))) {
            Some(i) => i,
            None => {
                self.tasks.push(Some(y));
                self.tasks.len() - 1
            }
        }
    }

    /// Las tasks desde `from` en adelante (y las que ellas llamen), si todo su código es lo que el
    /// nivel nativo compila.
    fn close(&mut self, from: usize) -> Option<()> {
        let mut i = from;
        while i < self.tasks.len() {
            if self.tasks.len() > MAX_FUNCS {
                return None;
            }
            let x = self.tasks[i].clone().expect("task de la unidad");
            let chunk = x.code.get()?.clone();
            if !chunk.regframe {
                return None;
            }
            let mut code = Vec::with_capacity(chunk.code.len());
            for pc in 0..chunk.code.len() {
                code.push(view_ins(&chunk, pc, &x.closure_env, Some(i), self)?);
            }
            let nparams = u16::try_from(x.parameters.len()).ok()?;
            let niters = chunk_iters(&chunk);
            self.funcs.push(NFunc { code, nregs: chunk.nregs, nlocals: chunk.nlocals, nparams, nglobals: 0, niters, osr: None });
            i += 1;
        }
        Some(())
    }

    fn unit(self, code: Box<dyn NativeCode>, nregs0: u16) -> NativeUnit {
        NativeUnit {
            code,
            tasks: self.tasks.iter().map(|t| t.as_ref().map(Rc::downgrade)).collect(),
            nregs0,
            deps: self.deps,
            deopts: Cell::new(0),
            range_fn: self.range_fn,
        }
    }
}

/// La task y las que llama (por `LoadGlobal`), si todo su código es lo que F4.1 compila.
fn build_unit(t: &Rc<SynTaskValue>) -> Option<Build> {
    let mut b = Build { tasks: vec![Some(t.clone())], ..Default::default() };
    b.close(0)?;
    Some(b)
}

fn nconst(v: &SynValue) -> Option<NConst> {
    Some(match v {
        SynValue::Number(Number::Int(x)) => NConst::Int(*x),
        SynValue::Bool(b) => NConst::Bool(*b),
        SynValue::Nothing => NConst::Nothing,
        _ => return None,
    })
}

fn nopnd(c: &Chunk, o: Opnd) -> Option<NOpnd> {
    Some(match o {
        Opnd::Reg(r) => NOpnd::Reg(r),
        Opnd::Copy(r) => NOpnd::Copy(r),
        Opnd::Const(k) => NOpnd::Const(nconst(&c.consts[k as usize])?),
        Opnd::RLocal(k) => NOpnd::Local(k),
        Opnd::Local(_) => return None,
    })
}

fn narith(op: BinOp) -> Option<NArith> {
    Some(match op {
        BinOp::Add => NArith::Add,
        BinOp::Sub => NArith::Sub,
        BinOp::Mul => NArith::Mul,
        BinOp::Mod => NArith::Mod,
        _ => return None,
    })
}

fn ncmp(op: BinOp) -> Option<NCmp> {
    Some(match op {
        BinOp::Lt => NCmp::Lt,
        BinOp::Le => NCmp::Le,
        BinOp::Gt => NCmp::Gt,
        BinOp::Ge => NCmp::Ge,
        BinOp::Eq => NCmp::Eq,
        BinOp::Ne => NCmp::Ne,
        _ => return None,
    })
}

/// Una instrucción de un chunk como la ve el nivel nativo; `None` si no la compila. `env`: desde
/// dónde lee sus globales el código (el `closure_env` de la task, o el entorno del bucle); `me`:
/// la función que la tiene (`None`: el bucle).
fn view_ins(c: &Chunk, pc: usize, env: &Rc<RefCell<Environment>>, me: Option<usize>, b: &mut Build) -> Option<NIns> {
    Some(match c.code[pc].get() {
        Ins::Steps(w) => NIns::Steps(w),
        Ins::StepsCancel(w) => NIns::StepsCancel(w),
        Ins::CheckCancel => NIns::CheckCancel,
        Ins::Const { dst, k } => NIns::Const { dst, v: nconst(&c.consts[k as usize])? },
        Ins::Move { dst, src } => NIns::Move { dst, src: nopnd(c, src)? },
        Ins::Drop { r } => NIns::Drop { r },
        // Todavía adaptativa: la VM la especializa la primera vez que corre.
        Ins::Binary { dst, a, b: y, .. } => NIns::Trap { dst, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::IntArith { dst, op, a, b: y, .. } => NIns::IntArith { dst, op: narith(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::IntCmp { dst, op, a, b: y, .. } => NIns::IntCmp { dst, op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::IntCmpJump { op, a, b: y, .. } => {
            let Some(Ins::JumpIfFalsy { to, .. }) = c.code.get(pc + 1).map(Cell::get) else { return None };
            NIns::IntCmpJump { op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, y)?, to }
        }
        Ins::JumpIfFalsy { src, to } => NIns::JumpIfFalsy { src: nopnd(c, src)?, to },
        Ins::Jump { to } | Ins::LoopBack { to, n: 0, .. } => NIns::Jump { to },
        // `each` sobre `range` (F4.2b): el iterador perezoso en el código nativo.
        Ins::LoopBack { to, first, n, .. } | Ins::EachStepV { head: to, first, n } => NIns::EachStep { head: to, first, n },
        Ins::IsRange { src, to } => NIns::IsRange { src, to },
        Ins::EachRange { first, n, it } => NIns::EachRange { first, n, it },
        Ins::EachNextV { it, slot, exit } => NIns::EachNext { it, slot, exit },
        Ins::EachEndV { it, first, n } => NIns::EachEnd { it, first, n },
        // El camino general de un `each` (la colección no era el builtin `range`): con `range` no se
        // llega; si se llega, sigue la VM.
        Ins::EachInitV { .. } => NIns::Leave { planned: false },
        Ins::LoadRLocal { dst, slot, .. } => NIns::LoadLocal { dst, slot },
        Ins::LetRLocal { src, slot, dst } => NIns::LetLocal { src: nopnd(c, src)?, slot, dst },
        Ins::SetRLocal { src, slot, dst, .. } => NIns::SetLocal { src: nopnd(c, src)?, slot, dst },
        // Sobre una variable de la ventana o un parámetro, la vía en el lugar sólo aplica a
        // listas y mapas: con un escalar (el tipo estático lo prueba) no hace nada.
        Ins::TryInPlace { name, slot, .. } if name != NONE && slot != u16::MAX => {
            NIns::Scalar { src: if slot >= PARAM { NOpnd::Copy(slot & !PARAM) } else { NOpnd::Local(slot) } }
        }
        // La salida de un bucle: vuelve a los frames de vueltas y brazos abiertos en el cuerpo,
        // y acá no hay (lo que los abre, `each` y `match`, no tiene vista).
        Ins::Unwind { .. } => NIns::Nop,
        Ins::LoadGlobal { dst, name, .. } => {
            let nm = c.names[name as usize].clone();
            match env_get(env, &nm)? {
                SynValue::Task(y) => {
                    let to = b.callee(y);
                    b.deps.push(Dep { from: me, name: nm, to: Some(to) });
                    NIns::LoadCallee { dst, func: to as u32 }
                }
                v @ SynValue::Builtin(_) if matches!(&v, SynValue::Builtin(x) if x.name == "range") => {
                    b.deps.push(Dep { from: me, name: nm, to: None });
                    b.range_fn = Some(v);
                    NIns::RangeFn { dst }
                }
                _ => return None,
            }
        }
        Ins::Call { dst, func, args, n, site } | Ins::CallNative { dst, func, args, n, site } => {
            if c.sites[site as usize].names.is_some() {
                return None;
            }
            NIns::Call { dst, func, args, n }
        }
        Ins::Give { src } => NIns::Give { src: nopnd(c, src)? },
        Ins::End { src } => NIns::End { src: nopnd(c, src)? },
        _ => return None,
    })
}

/// Cuántos iteradores de `each` usa el chunk (el mayor `it` + 1).
fn chunk_iters(c: &Chunk) -> u16 {
    c.code
        .iter()
        .filter_map(|x| match x.get() {
            Ins::EachRange { it, .. }
            | Ins::EachNextV { it, .. }
            | Ins::EachEndV { it, .. }
            | Ins::EachInitV { it, .. }
            | Ins::EachInit { it, .. }
            | Ins::EachNext { it, .. }
            | Ins::EachEnd { it } => Some(it + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// Lo que tiene el lugar `at` de la pila de iteradores, visto por el nivel nativo: las cuatro
/// partes de un `range` (`valid`, `next`, `hi`, `step`), vacío, o algo que no representa.
fn iter_parts(v: Option<&EachItems>) -> Result<Option<[i64; 4]>, ()> {
    match v {
        None => Ok(None),
        Some(EachItems::Range(r)) => Ok(Some([i64::from(r.next.is_some()), r.next.unwrap_or(0), r.hi, r.step])),
        Some(_) => Err(()),
    }
}

fn seen(v: Option<&SynValue>) -> NSeen {
    match v {
        None => NSeen::Hole,
        Some(SynValue::Number(Number::Int(_))) => NSeen::Int,
        Some(SynValue::Bool(_)) => NSeen::Bool,
        Some(SynValue::Nothing) => NSeen::Nothing,
        Some(_) => NSeen::Boxed,
    }
}

/// Un bucle compilado (F4.2): la unidad y los nombres de sus globales.
pub(crate) struct LoopUnit {
    unit: NativeUnit,
    globals: Vec<Arc<str>>,
    /// Si el código escribe alguna global (entonces el entorno no puede ser un módulo, que
    /// sincroniza su mapa de exportaciones).
    writes: bool,
}

/// El estado de un bucle en su chunk (F4.2): la cuenta regresiva de vueltas (como `NativeState`)
/// y su código nativo.
#[derive(Default)]
pub(crate) struct LoopState {
    left: Cell<u32>,
    never: Cell<bool>,
    /// Entradas que no rindieron (salieron del cuerpo antes de `MIN_WORK` pasos).
    bad: Cell<u32>,
    /// Entradas que la guarda no dejó pasar.
    misses: Cell<u32>,
    code: std::cell::OnceCell<LoopUnit>,
}

impl LoopState {
    /// Cuenta una vuelta; `true` si hay que decidir (fuera de línea).
    #[inline(always)]
    pub(super) fn tick(&self) -> bool {
        let h = self.left.get();
        if h > 1 {
            self.left.set(h - 1);
            false
        } else {
            true
        }
    }
}

/// Una entrada a un bucle nativo que sale del cuerpo antes de hacer esta cantidad de pasos no rinde
/// (entrar y salir cuesta más que la VM). Por pasos, no por tiempo: determinista.
const MIN_WORK: u64 = 1000;

/// El bucle `[head, back]` del chunk como lo ve el nivel nativo: lo de afuera (y `give`) es una
/// salida prevista; lo de adentro que todavía no se compila, una salida del cuerpo. `None` si no
/// se puede armar.
#[allow(clippy::type_complexity)]
fn view_loop(c: &Chunk, env: &Rc<RefCell<Environment>>, head: usize, back: usize, b: &mut Build) -> Option<(Vec<NIns>, Vec<Arc<str>>, bool)> {
    let mut globals: Vec<Arc<str>> = Vec::new();
    let mut written: Vec<Arc<str>> = Vec::new();
    // Lo que tiene el entorno del bucle, sin mirar afuera: `Some(None)` = el nombre, con un hueco.
    let own = |nm: &str| -> Option<Option<SynValue>> {
        let e = env.borrow();
        let k = e.bindings.find(nm)?;
        Some(e.bindings.slot(k).cloned())
    };
    let module = env.borrow().name.starts_with("module:");
    let mut out = Vec::with_capacity(c.code.len());
    for pc in 0..c.code.len() {
        if pc < head || pc > back {
            out.push(NIns::Leave { planned: true });
            continue;
        }
        let mut global = |nm: &Arc<str>| -> u16 {
            match globals.iter().position(|g| **g == **nm) {
                Some(i) => i as u16,
                None => {
                    globals.push(nm.clone());
                    (globals.len() - 1) as u16
                }
            }
        };
        let ins = match c.code[pc].get() {
            Ins::Give { .. } | Ins::End { .. } => Some(NIns::Leave { planned: true }),
            Ins::LoadGlobal { dst, name, .. } => {
                let nm = &c.names[name as usize];
                match own(nm) {
                    Some(Some(SynValue::Task(_) | SynValue::Builtin(_))) | None => view_ins(c, pc, env, None, b),
                    Some(v) if seen(v.as_ref()) != NSeen::Boxed => Some(NIns::Move { dst, src: NOpnd::Global(global(nm)) }),
                    Some(_) => None,
                }
            }
            Ins::SetGlobal { src, name, dst, .. } | Ins::LetName { src, name, dst } if !module => {
                let nm = &c.names[name as usize];
                match (own(nm), nopnd(c, src)) {
                    (Some(v), Some(src)) if !matches!(v, Some(SynValue::Task(_))) => {
                        written.push(nm.clone());
                        let g = global(nm);
                        Some(if matches!(c.code[pc].get(), Ins::LetName { .. }) {
                            NIns::LetGlobal { src, g, dst }
                        } else {
                            NIns::SetGlobal { src, g, dst }
                        })
                    }
                    _ => None,
                }
            }
            // La vía en el lugar sobre una global del entorno del bucle: con un escalar no hace nada.
            Ins::TryInPlace { name, ic, .. } if name != NONE && ic != NONE && c.ic_here[ic as usize] => {
                let nm = &c.names[name as usize];
                match own(nm) {
                    Some(v) if !matches!(v, Some(SynValue::Task(_))) => Some(NIns::Scalar { src: NOpnd::Global(global(nm)) }),
                    _ => None,
                }
            }
            _ => view_ins(c, pc, env, None, b),
        };
        out.push(ins.unwrap_or(NIns::Leave { planned: false }));
    }
    // Una global que el bucle escribe no puede ser una task que el código nativo da por sabida.
    if written.iter().any(|w| b.deps.iter().any(|d| *d.name == **w)) {
        return None;
    }
    let writes = !written.is_empty();
    Some((out, globals, writes))
}

// =============================================================================================
// Ejecución
// =============================================================================================

impl Interpreter {
    /// La cuenta de una task llegó a su fin (ver `NativeState`): la primera vez empieza la cuenta;
    /// al pasar el umbral se compila (una vez) y el sitio de esta llamada pasa a ser `CallNative`.
    /// Esta vez sigue en la VM.
    #[inline(never)]
    pub(super) fn vm_native_tier_up(&mut self, chunk: &Chunk, at: usize, t: &Rc<SynTaskValue>) {
        let st = &t.code.native;
        if st.never.get() {
            st.left.set(u32::MAX);
            return;
        }
        if st.left.get() == 0 {
            // La primera llamada sólo empieza la cuenta (el cuerpo todavía no corrió en la VM:
            // nada está especializado); se compila en la llamada número `umbral`.
            st.left.set(native_tier::threshold().saturating_sub(1).max(1));
            return;
        }
        if st.unit.get().is_none() {
            let compiled = native_tier::tier().and_then(|tier| {
                let b = build_unit(t)?;
                let code = tier.compile(&NUnit { funcs: b.funcs.clone() })?;
                let nregs0 = b.funcs[0].nregs;
                Some(b.unit(code, nregs0))
            });
            match compiled {
                Some(u) => {
                    native_tier::count_unit();
                    let _ = st.unit.set(u);
                }
                None => {
                    st.give_up();
                    return;
                }
            }
        }
        if let Ins::Call { dst, func, args, n, site } = chunk.code[at].get() {
            chunk.code[at].set(Ins::CallNative { dst, func, args, n, site });
        }
    }

    fn nval_to_syn(unit: &NativeUnit, v: NVal) -> SynValue {
        match v {
            NVal::Int(x) => SynValue::Number(Number::Int(x)),
            NVal::Bool(b) => syn_bool(b),
            NVal::Nothing => SynValue::Nothing,
            NVal::Callee(f) => SynValue::Task(unit.task(f as usize).expect("task de la unidad viva")),
            NVal::RangeFn => unit.range_fn.clone().expect("el builtin range de la unidad"),
            NVal::Hole => SynValue::Nothing,
        }
    }

    /// `CallNative`: entra al código nativo si la task todavía lo tiene y todo encaja; si no, la
    /// instrucción vuelve a ser `Call` y se repite (la llamada de siempre).
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn vm_call_native(
        &mut self,
        chunk: &Chunk,
        base: usize,
        at: usize,
        dst: Reg,
        func: Reg,
        args: Reg,
        n: u16,
        site: u32,
    ) -> Result<NativeStep, Control> {
        let first = base + args as usize;
        let nn = n as usize;
        let fits = match &self.vm_regs[base + func as usize] {
            SynValue::Task(t) => t.code.native.unit().is_some_and(|u| {
                nn == t.parameters.len()
                    && self.vm_regs[first..first + nn].iter().all(|v| matches!(v, SynValue::Number(Number::Int(_))))
                    && u.deps_hold(None)
            }),
            _ => false,
        };
        if !fits {
            chunk.code[at].set(Ins::Call { dst, func, args, n, site });
            return Ok(NativeStep::Retry);
        }
        // Lo mismo que `vm_call` hasta entrar: la función sale de su registro, la aridad ya encaja
        // (tantos argumentos como parámetros) y la profundidad con el mismo tope y el mismo error.
        let f = std::mem::replace(&mut self.vm_regs[base + func as usize], SynValue::Nothing);
        let SynValue::Task(t) = &f else { unreachable!("CallNative sin task") };
        let unit = t.code.native.unit().expect("unidad nativa");
        self.recursion_depth += 1;
        if self.recursion_depth > MAX_RECURSION {
            self.recursion_depth -= 1;
            return Err(err("maximum recursion depth exceeded"));
        }
        let argv: SmallVec<[i64; 8]> = self.vm_regs[first..first + nn]
            .iter()
            .map(|v| match v {
                SynValue::Number(Number::Int(x)) => *x,
                _ => unreachable!("argumento no entero"),
            })
            .collect();
        native_tier::count_entry();
        let out = {
            let mut cx = NativeCx { steps: &mut self.steps, depth: &mut self.recursion_depth, max_depth: MAX_RECURSION, cancel: &self.cancel.flag };
            unit.code.call(&mut cx, &argv)
        };
        match out {
            NOutcome::Done(v) => {
                // El epílogo de una llamada de la VM: la profundidad y la ventana del llamado.
                self.recursion_depth -= 1;
                let top = self.vm_regs.len();
                self.vm_pop_regs((first, unit.nregs0), top);
                let v = Self::nval_to_syn(unit, v);
                self.put(base, dst, v);
                Ok(NativeStep::Done)
            }
            NOutcome::Deopt(frames) => {
                native_tier::count_deopt();
                let d = unit.deopts.get() + 1;
                unit.deopts.set(d);
                let r = self.vm_native_resume(unit, frames, first, nn);
                if d > MAX_NATIVE_DEOPTS {
                    t.code.native.give_up();
                }
                Ok(NativeStep::Resume(r))
            }
        }
    }

    /// Los frames nativos como frames de la VM: para cada uno, lo que `vm_enter_regframe` habría
    /// hecho al entrar (ventana de registros desde los argumentos, ventana de locales) y sus valores
    /// vivos; los de afuera quedan esperando a su llamado (`VmFrame`, como en `Call`).
    fn vm_native_resume(&mut self, unit: &NativeUnit, frames: Vec<NFrame>, first: usize, n: usize) -> Box<Resume> {
        let top0 = self.vm_regs.len();
        let last = frames.len() - 1;
        let mut out = Vec::with_capacity(last);
        let mut pending: Option<VmFrame> = None;
        let (mut first, mut n) = (first, n);
        for (k, fr) in frames.into_iter().enumerate() {
            let f = fr.func as usize;
            let task = unit.task(f).expect("task de la unidad viva");
            let code = task.code.get().expect("código de la task").clone();
            let top = self.vm_regs.len();
            if let Some(mut p) = pending.take() {
                p.top = top;
                out.push(p);
            }
            let need = first + (code.nregs as usize).max(n);
            if top < need {
                self.vm_regs.resize(need, SynValue::Nothing);
            }
            let lbase = self.vm_locals.len();
            self.vm_locals.resize(lbase + code.nlocals as usize, None);
            let ib = self.vm_iters.len();
            self.vm_put_values(unit, fr.values, first, lbase, ib, None);
            match fr.call {
                Some(c) if k < last => {
                    pending = Some(VmFrame {
                        chunk: code,
                        env: task.closure_env.clone(),
                        base: first,
                        pc: fr.pc as usize,
                        dst: c.dst,
                        depth: 0,
                        iter_base: ib,
                        lbase,
                        top: 0,
                    });
                    first += c.args as usize;
                    n = c.n as usize;
                }
                _ => {
                    return Box::new(Resume {
                        frames: out,
                        enter: Enter { code, env: task.closure_env.clone(), base: first, lbase, top: 0 },
                        pc: fr.pc as usize,
                        top0,
                        iter_base: ib,
                    })
                }
            }
        }
        unreachable!("salida nativa sin frames")
    }

    /// Un `LoopBack` llegó a su cuenta (F4.2, OSR): la primera vez empieza la cuenta; al pasar el
    /// umbral se compila el bucle (una vez) y, desde ahí, cada vuelta que corre en la VM intenta
    /// entrar. Si no se puede compilar o no rinde, la instrucción vuelve a ser `Jump`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn vm_loop_hot(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>, base: usize, iter_base: usize, at: usize, lp: u16) -> OsrStep {
        let st = &chunk.loops[lp as usize];
        let Ins::LoopBack { to, first, n, .. } = chunk.code[at].get() else { unreachable!("vm_loop_hot sin LoopBack") };
        let give_up = || {
            st.never.set(true);
            st.left.set(u32::MAX);
            chunk.code[at].set(if n > 0 { Ins::EachStepV { head: to, first, n } } else { Ins::Jump { to } });
        };
        if st.never.get() {
            give_up();
            return OsrStep::Stay;
        }
        if st.left.get() == 0 {
            st.left.set(native_tier::threshold().saturating_sub(1).max(1));
            return OsrStep::Stay;
        }
        if st.code.get().is_none() {
            match self.vm_build_loop(chunk, env, base, iter_base, to as usize, at) {
                Some(u) => {
                    native_tier::count_unit();
                    let _ = st.code.set(u);
                }
                None => {
                    give_up();
                    return OsrStep::Stay;
                }
            }
        }
        let lu = st.code.get().expect("bucle compilado");
        let Some((args, slots)) = self.vm_osr_args(lu, env, base, iter_base) else {
            // No encaja ahora (otro tipo, una task que cambió): más tarde, y si sigue, nunca.
            st.misses.set(st.misses.get() + 1);
            if st.misses.get() > MAX_NATIVE_DEOPTS {
                give_up();
            } else {
                st.left.set(native_tier::threshold().max(2));
            }
            return OsrStep::Stay;
        };
        // Cada vuelta que llegue acá desde la VM vuelve a intentar entrar.
        st.left.set(1);
        native_tier::count_osr();
        let s0 = self.steps;
        let out = {
            let mut cx = NativeCx { steps: &mut self.steps, depth: &mut self.recursion_depth, max_depth: MAX_RECURSION, cancel: &self.cancel.flag };
            lu.unit.code.call(&mut cx, &args)
        };
        let NOutcome::Deopt(mut frames) = out else { unreachable!("un bucle nativo sólo sale a la VM") };
        let planned = frames.last().is_some_and(|f| f.planned);
        if !planned {
            native_tier::count_deopt();
            if self.steps.wrapping_sub(s0) < MIN_WORK {
                st.bad.set(st.bad.get() + 1);
                if st.bad.get() > MAX_NATIVE_DEOPTS {
                    give_up();
                }
            }
        }
        let rest = frames.split_off(1);
        let f0 = frames.pop().expect("frame del bucle");
        // Lo que el bucle tenía en registros vuelve a la VM (las globales, a su lugar del entorno; los
        // iteradores, a su lugar de la pila).
        let lbase = self.vm_lbase;
        self.vm_put_values(&lu.unit, f0.values, base, lbase, iter_base, Some((env, &slots)));
        match f0.call {
            Some(c) => {
                let r = self.vm_native_resume(&lu.unit, rest, base + c.args as usize, c.n as usize);
                OsrStep::Resume { r, pc: f0.pc as usize, dst: c.dst }
            }
            None => OsrStep::Exit(f0.pc as usize),
        }
    }

    /// Compila el bucle `[head, back]` con los tipos que tiene ahora (los que la entrada va a
    /// exigir).
    #[allow(clippy::too_many_arguments)]
    fn vm_build_loop(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>, base: usize, iter_base: usize, head: usize, back: usize) -> Option<LoopUnit> {
        let tier = native_tier::tier()?;
        let mut b = Build { tasks: vec![None], ..Default::default() };
        let (code, globals, writes) = view_loop(chunk, env, head, back, &mut b)?;
        if writes && env.borrow().name.starts_with("module:") {
            return None;
        }
        let nglobals = u16::try_from(globals.len()).ok()?;
        let mut init = Vec::with_capacity(chunk.nregs as usize + chunk.nlocals as usize + globals.len());
        for r in 0..chunk.nregs as usize {
            init.push(seen(Some(&self.vm_regs[base + r])));
        }
        for k in 0..chunk.nlocals as usize {
            init.push(seen(self.vm_locals[self.vm_lbase + k].as_ref()));
        }
        {
            let e = env.borrow();
            for g in &globals {
                let k = e.bindings.find(g)?;
                init.push(seen(e.bindings.slot(k)));
            }
        }
        let niters = chunk_iters(chunk);
        for it in 0..niters as usize {
            let s = match iter_parts(self.vm_iters.get(iter_base + it)) {
                Ok(Some(_)) => NSeen::Int,
                Ok(None) => NSeen::Hole,
                Err(()) => NSeen::Boxed,
            };
            init.extend([s; 4]);
        }
        b.funcs.push(NFunc {
            code,
            nregs: chunk.nregs,
            nlocals: chunk.nlocals,
            nparams: 0,
            nglobals,
            niters,
            osr: Some(NOsr { head: head as u32, init }),
        });
        b.close(1)?;
        // El código de las tasks que llama no puede ser este chunk (el bucle vive en él: un ciclo).
        if b.tasks.iter().flatten().any(|t| t.code.get().is_some_and(|c| Rc::ptr_eq(c, chunk))) {
            return None;
        }
        let code = tier.compile(&NUnit { funcs: std::mem::take(&mut b.funcs) })?;
        Some(LoopUnit { unit: b.unit(code, chunk.nregs), globals, writes })
    }

    /// La guarda de entrada a un bucle nativo: cada lugar que el código lee o escribe tiene lo que
    /// tenía al compilar (nunca un valor con caja: sus cuentas de referencias no se tocan), las
    /// globales están en el entorno y las tasks siguen siendo esas. Los valores de entrada y el
    /// slot de cada global.
    fn vm_osr_args(&self, lu: &LoopUnit, env: &Rc<RefCell<Environment>>, base: usize, iter_base: usize) -> Option<(SmallVec<[i64; 16]>, SmallVec<[usize; 8]>)> {
        let e = env.borrow();
        if lu.writes && e.name.starts_with("module:") {
            return None;
        }
        let mut slots: SmallVec<[usize; 8]> = SmallVec::new();
        for g in &lu.globals {
            slots.push(e.bindings.find(g)?);
        }
        let mut args: SmallVec<[i64; 16]> = SmallVec::new();
        for &(place, want) in lu.unit.code.inputs() {
            if let Place::Iter(it, k) = place {
                let (s, x) = match iter_parts(self.vm_iters.get(iter_base + it as usize)) {
                    Ok(Some(p)) => (NSeen::Int, p[k as usize]),
                    Ok(None) => (NSeen::Hole, 0),
                    Err(()) => (NSeen::Boxed, 0),
                };
                if s != want {
                    return None;
                }
                args.push(x);
                continue;
            }
            let v = match place {
                Place::Reg(r) => Some(&self.vm_regs[base + r as usize]),
                Place::Local(k) => self.vm_locals[self.vm_lbase + k as usize].as_ref(),
                Place::Global(g) => e.bindings.slot(slots[g as usize]),
                Place::Iter(..) => unreachable!("iterador"),
            };
            if seen(v) != want {
                return None;
            }
            args.push(match v {
                Some(SynValue::Number(Number::Int(x))) => *x,
                Some(SynValue::Bool(b)) => i64::from(*b),
                _ => 0,
            });
        }
        drop(e);
        if !lu.unit.deps_hold(Some(env)) {
            return None;
        }
        Some((args, slots))
    }

    /// Los valores de un frame nativo en la VM: registros desde `rbase`, ventana desde `lbase`,
    /// iteradores desde `ib` (un iterador terminado se suelta de la pila) y, en un bucle, las
    /// globales en sus slots del entorno.
    fn vm_put_values(
        &mut self,
        unit: &NativeUnit,
        values: Vec<(Place, NVal)>,
        rbase: usize,
        lbase: usize,
        ib: usize,
        globals: Option<(&Rc<RefCell<Environment>>, &[usize])>,
    ) {
        let mut iters: SmallVec<[(u16, [i64; 4], bool); 4]> = SmallVec::new();
        for (place, v) in values {
            match place {
                Place::Reg(r) => self.vm_regs[rbase + r as usize] = Self::nval_to_syn(unit, v),
                Place::Local(k) => self.vm_locals[lbase + k as usize] = (v != NVal::Hole).then(|| Self::nval_to_syn(unit, v)),
                Place::Global(g) => {
                    // Una global vacía el código nativo no la escribió (un `set` a un hueco sale antes).
                    if v != NVal::Hole {
                        let (env, slots) = globals.expect("global fuera de un bucle");
                        env.borrow_mut().bindings.slot_set(slots[g as usize], Self::nval_to_syn(unit, v));
                    }
                }
                Place::Iter(it, k) => {
                    let i = match iters.iter().position(|x| x.0 == it) {
                        Some(i) => i,
                        None => {
                            iters.push((it, [0; 4], false));
                            iters.len() - 1
                        }
                    };
                    match v {
                        NVal::Int(x) => iters[i].1[k as usize] = x,
                        _ => iters[i].2 = true,
                    }
                }
            }
        }
        iters.sort_by_key(|x| x.0);
        for (it, p, gone) in iters {
            let at = ib + it as usize;
            if gone {
                self.vm_iters.truncate(at);
                continue;
            }
            let r = EachItems::Range(RangeIter { next: (p[0] != 0).then_some(p[1]), hi: p[2], step: p[3] });
            if at < self.vm_iters.len() {
                self.vm_iters[at] = r;
            } else {
                assert_eq!(at, self.vm_iters.len(), "iterador nativo fuera de orden");
                self.vm_iters.push(r);
            }
        }
    }
}
