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
use crate::native_tier::{self, NArith, NCmp, NConst, NFrame, NIns, NOpnd, NOutcome, NUnit, NVal, NativeCode, NativeCx, Place};
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

/// Una unidad compilada: la task (`tasks[0]`) y las que llama, con su código de la VM (para volver).
pub(crate) struct NativeUnit {
    code: Box<dyn NativeCode>,
    /// `Weak`: la unidad vive en `tasks[0]`.
    tasks: Vec<Weak<SynTaskValue>>,
    chunks: Vec<Rc<Chunk>>,
    deps: Vec<Dep>,
    deopts: Cell<u32>,
}

/// La global `name`, leída desde el `closure_env` de la función `from`, es la task de `to`.
struct Dep {
    from: usize,
    name: Arc<str>,
    to: usize,
}

impl NativeUnit {
    /// Las globales que el código nativo da por sabidas siguen siendo esas tasks (como `LoadGlobal`:
    /// por nombre desde el `closure_env`).
    fn deps_hold(&self) -> bool {
        self.deps.iter().all(|d| {
            let (Some(from), Some(to)) = (self.tasks[d.from].upgrade(), self.tasks[d.to].upgrade()) else {
                return false;
            };
            matches!(env_get(&from.closure_env, &d.name), Some(SynValue::Task(t)) if Rc::ptr_eq(&t, &to))
        })
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
}

// =============================================================================================
// La vista del bytecode
// =============================================================================================

/// La task y las que llama (por `LoadGlobal`), si todo su código es lo que F4.1 compila.
#[allow(clippy::type_complexity)]
fn build_unit(t: &Rc<SynTaskValue>) -> Option<(NUnit, Vec<Rc<SynTaskValue>>, Vec<Rc<Chunk>>, Vec<Dep>)> {
    let mut tasks: Vec<Rc<SynTaskValue>> = vec![t.clone()];
    let mut funcs = Vec::new();
    let mut chunks = Vec::new();
    let mut deps = Vec::new();
    let mut i = 0;
    while i < tasks.len() {
        if tasks.len() > MAX_FUNCS {
            return None;
        }
        let x = tasks[i].clone();
        let chunk = x.code.get()?.clone();
        if !chunk.regframe {
            return None;
        }
        let code = view(&chunk, &x, i, &mut tasks, &mut deps)?;
        funcs.push(native_tier::NFunc { code, nregs: chunk.nregs, nlocals: chunk.nlocals, nparams: u16::try_from(x.parameters.len()).ok()? });
        chunks.push(chunk);
        i += 1;
    }
    Some((NUnit { funcs }, tasks, chunks, deps))
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

/// El código de un chunk como lo ve el nivel nativo; `None` si tiene algo que F4.1 no compila.
fn view(c: &Chunk, x: &Rc<SynTaskValue>, me: usize, tasks: &mut Vec<Rc<SynTaskValue>>, deps: &mut Vec<Dep>) -> Option<Vec<NIns>> {
    let mut out = Vec::with_capacity(c.code.len());
    for (pc, cell) in c.code.iter().enumerate() {
        let ins = match cell.get() {
            Ins::Steps(w) => NIns::Steps(w),
            Ins::StepsCancel(w) => NIns::StepsCancel(w),
            Ins::CheckCancel => NIns::CheckCancel,
            Ins::Const { dst, k } => NIns::Const { dst, v: nconst(&c.consts[k as usize])? },
            Ins::Move { dst, src } => NIns::Move { dst, src: nopnd(c, src)? },
            Ins::Drop { r } => NIns::Drop { r },
            // Todavía adaptativa: la VM la especializa la primera vez que corre.
            Ins::Binary { dst, a, b, .. } => NIns::Trap { dst, a: nopnd(c, a)?, b: nopnd(c, b)? },
            Ins::IntArith { dst, op, a, b, .. } => NIns::IntArith { dst, op: narith(op)?, a: nopnd(c, a)?, b: nopnd(c, b)? },
            Ins::IntCmp { dst, op, a, b, .. } => NIns::IntCmp { dst, op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, b)? },
            Ins::IntCmpJump { op, a, b, .. } => {
                let Some(Ins::JumpIfFalsy { to, .. }) = c.code.get(pc + 1).map(Cell::get) else { return None };
                NIns::IntCmpJump { op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, b)?, to }
            }
            Ins::JumpIfFalsy { src, to } => NIns::JumpIfFalsy { src: nopnd(c, src)?, to },
            Ins::Jump { to } => NIns::Jump { to },
            Ins::LoadRLocal { dst, slot, .. } => NIns::LoadLocal { dst, slot },
            Ins::LetRLocal { src, slot, dst } => NIns::LetLocal { src: nopnd(c, src)?, slot, dst },
            Ins::SetRLocal { src, slot, dst, .. } => NIns::SetLocal { src: nopnd(c, src)?, slot, dst },
            // Sobre una variable de la ventana o un parámetro, la vía en el lugar sólo aplica a
            // listas y mapas: con escalares no hace nada.
            Ins::TryInPlace { name, slot, .. } if name != NONE && slot != u16::MAX => NIns::Nop,
            // La salida de un bucle: vuelve a los frames de vueltas y brazos abiertos en el cuerpo,
            // y acá no hay (lo que los abre, `each` y `match`, no tiene vista).
            Ins::Unwind { .. } => NIns::Nop,
            Ins::LoadGlobal { dst, name, .. } => {
                let nm = c.names[name as usize].clone();
                let SynValue::Task(y) = env_get(&x.closure_env, &nm)? else { return None };
                let to = match tasks.iter().position(|t| Rc::ptr_eq(t, &y)) {
                    Some(i) => i,
                    None => {
                        tasks.push(y);
                        tasks.len() - 1
                    }
                };
                deps.push(Dep { from: me, name: nm, to });
                NIns::LoadCallee { dst, func: to as u32 }
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
        };
        out.push(ins);
    }
    Some(out)
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
                let (unit, tasks, chunks, deps) = build_unit(t)?;
                let code = tier.compile(&unit)?;
                Some(NativeUnit { code, tasks: tasks.iter().map(Rc::downgrade).collect(), chunks, deps, deopts: Cell::new(0) })
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
            NVal::Callee(f) => SynValue::Task(unit.tasks[f as usize].upgrade().expect("task de la unidad viva")),
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
                    && u.deps_hold()
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
                self.vm_pop_regs((first, unit.chunks[0].nregs), top);
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
            let code = unit.chunks[f].clone();
            let task = unit.tasks[f].upgrade().expect("task de la unidad viva");
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
            for (place, v) in fr.values {
                let v = Self::nval_to_syn(unit, v);
                match place {
                    Place::Reg(r) => self.vm_regs[first + r as usize] = v,
                    Place::Local(s) => self.vm_locals[lbase + s as usize] = Some(v),
                }
            }
            match fr.call {
                Some(c) if k < last => {
                    pending = Some(VmFrame {
                        chunk: code,
                        env: task.closure_env.clone(),
                        base: first,
                        pc: fr.pc as usize,
                        dst: c.dst,
                        depth: 0,
                        iter_base: self.vm_iters.len(),
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
                    })
                }
            }
        }
        unreachable!("salida nativa sin frames")
    }
}
