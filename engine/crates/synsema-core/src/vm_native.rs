//! La VM y el nivel nativo (F4.1 de specs/compute-rendimiento.md). Hijo de `vm`: arma la vista del
//! bytecode que compila el nivel instalado (`crate::native_tier`), decide cuándo subir de nivel y
//! vuelve a la VM con el estado de los frames nativos. Todo seguro: el código de máquina y el
//! `unsafe` viven en `synsema-jit`.
//!
//! **Qué compila F4.1:** tasks con frame en registros (F3.3b/F3.7) cuyo código ya especializado es
//! numérico (`Int`/`Bool`): pasos, cancelación, aritmética y comparaciones enteras, saltos, locales,
//! `give` y llamadas posicionales a tasks de la misma unidad (la recursión incluida). Cualquier otra
//! instrucción deja la unidad en la VM.
//! F4.7a suma los floats (`FloatArith`, `NumCmp` exacto, `Unary`, `ToBool`, tasks con parámetros
//! `Float`) y los lugares que según el camino tienen un tipo u otro (con guardas en el código nativo).
//! F4.7b suma las lecturas de datos: los valores con caja entran prestados (la dirección de donde
//! viven en la VM, sin tocar sus cuentas; al salir se clonan los que quedan vivos), `GetIndex`/`GetProp`
//! con la caché por forma de su sitio, `each` sobre listas y globales con caja en los bucles.
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
use crate::native_tier::{self, HostOut, NArith, NCmp, NConst, NBuiltin, NFArith, NFrame, NFunc, NIns, NOpnd, NOsr, NOutcome, NPeek, NSeen, NSite, NUnary, NUnit, NVal, NativeCode, NativeCx, NativeHost, Place};
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

    /// Si la unidad ya está compilada (o no se va a compilar nunca).
    pub(super) fn ready(&self) -> bool {
        self.never.get() || self.unit.get().is_some()
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
    /// F4.7c: los builtins intrínsecos que el código tiene en un registro.
    builtins: Vec<(NBuiltin, SynValue)>,
    /// Lo que tienen que tener los argumentos al entrar (F4.7: `Int`, `Float` o `Bool`; F4.8b: o un
    /// valor con caja, prestado).
    params: Vec<NSeen>,
    /// F4.8b: las globales que lee la task de la entrada: su lugar en el `closure_env` y lo que tienen
    /// que tener al entrar.
    globals: Vec<(usize, NSeen)>,
}

/// La global `name`, leída desde el `closure_env` de la función `from` (o, si es `None`, desde el
/// entorno donde corre el bucle), es la task de `to` (o, si es `None`, el builtin `range`).
struct Dep {
    from: Option<usize>,
    name: Arc<str>,
    to: Option<usize>,
    /// Con `to: None`: el builtin que tiene que ser (`range`, o un intrínseco de F4.7c).
    builtin: &'static str,
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
                (Some(SynValue::Builtin(b)), None) => b.name == d.builtin,
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
    /// F4.8d2: una llamada ajena del bucle falló (su `rest` y su `stop_to` ya los aplicó el host): el
    /// error sigue como el del `LoopBack` (mismo `rest` 0 y mismo `stop_to` que la condición del bucle).
    Fail(Control),
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
    builtins: Vec<(NBuiltin, SynValue)>,
    /// F4.7b: los sitios de `GetIndex`/`GetProp` de la unidad.
    sites: Vec<NSite>,
    /// F4.8b: las globales (no tasks) que lee la función 0 de una task: nombre y lugar en su
    /// `closure_env`.
    tglobals: Vec<(Arc<str>, usize)>,
}

impl Build {
    fn site(&mut self, key: Option<Arc<str>>, prop: bool) -> u32 {
        self.sites.push(NSite { key, prop, text: None });
        (self.sites.len() - 1) as u32
    }

    /// F4.8d2: un sitio que guarda un texto constante.
    fn text_site(&mut self, t: &str) -> u32 {
        self.sites.push(NSite { key: None, prop: false, text: Some(Arc::from(t)) });
        (self.sites.len() - 1) as u32
    }
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
            // F4.8b: las globales que lee la task de la entrada (sólo la 0: `view_ins`).
            let (nglobals, globals) = if i == 0 && from == 0 {
                let e = x.closure_env.borrow();
                let g: Vec<NSeen> = self.tglobals.iter().map(|(_, k)| seen(e.bindings.slot(*k))).collect();
                (u16::try_from(g.len()).ok()?, g)
            } else {
                (0, Vec::new())
            };
            self.funcs.push(NFunc { code, nregs: chunk.nregs, nlocals: chunk.nlocals, nparams, nglobals, niters, osr: None, params: Vec::new(), globals });
            i += 1;
        }
        Some(())
    }

    fn unit(self, code: Box<dyn NativeCode>, nregs0: u16, params: Vec<NSeen>) -> NativeUnit {
        let globals = match self.funcs.first() {
            Some(f) if f.osr.is_none() => self.tglobals.iter().map(|(_, k)| *k).zip(f.globals.iter().copied()).collect(),
            _ => Vec::new(),
        };
        NativeUnit {
            globals,
            params,
            code,
            tasks: self.tasks.iter().map(|t| t.as_ref().map(Rc::downgrade)).collect(),
            nregs0,
            deps: self.deps,
            deopts: Cell::new(0),
            range_fn: self.range_fn,
            builtins: self.builtins,
        }
    }
}

/// La task y las que llama (por `LoadGlobal`), si todo su código es lo que el nivel nativo
/// compila. `params`: lo que tienen los argumentos de esta llamada (la entrada lo va a exigir).
fn build_unit(t: &Rc<SynTaskValue>, params: Vec<NSeen>) -> Option<Build> {
    let mut b = Build { tasks: vec![Some(t.clone())], ..Default::default() };
    b.close(0)?;
    b.funcs[0].params = params;
    Some(b)
}

fn nconst(v: &SynValue) -> Option<NConst> {
    Some(match v {
        SynValue::Number(Number::Int(x)) => NConst::Int(*x),
        SynValue::Bool(b) => NConst::Bool(*b),
        SynValue::Nothing => NConst::Nothing,
        SynValue::Number(Number::Float(x)) => NConst::Float(x.to_bits()),
        _ => return None,
    })
}

fn nfarith(op: BinOp) -> Option<NFArith> {
    Some(match op {
        BinOp::Add => NFArith::Add,
        BinOp::Sub => NFArith::Sub,
        BinOp::Mul => NFArith::Mul,
        BinOp::Div => NFArith::Div,
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
        // F4.8d: un `TryInPlace` de camino que la VM dejó de probar (ver `vm_try_in_place`).
        Ins::Nop => NIns::Nop,
        // F4.8d2: un texto constante (un literal): prestado de un sitio de la unidad.
        Ins::Const { dst, k } | Ins::Move { dst, src: Opnd::Const(k) } if matches!(c.consts[k as usize], SynValue::Text(_)) => {
            let SynValue::Text(t) = &c.consts[k as usize] else { unreachable!("texto") };
            NIns::LoadConst { dst, site: b.text_site(t) }
        }
        Ins::Const { dst, k } => NIns::Const { dst, v: nconst(&c.consts[k as usize])? },
        Ins::Move { dst, src } => NIns::Move { dst, src: nopnd(c, src)? },
        Ins::Drop { r } => NIns::Drop { r },
        // Todavía adaptativa: la VM la especializa la primera vez que corre.
        Ins::Binary { dst, a, b: y, .. } => NIns::Trap { dst, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::IntArith { dst, op, a, b: y, .. } => NIns::IntArith { dst, op: narith(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::IntCmp { dst, op, a, b: y, .. } => NIns::IntCmp { dst, op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::FloatArith { dst, op, a, b: y, .. } => NIns::FloatArith { dst, op: nfarith(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::NumCmp { dst, op, a, b: y, .. } => NIns::NumCmp { dst, op: ncmp(op)?, a: nopnd(c, a)?, b: nopnd(c, y)? },
        Ins::Unary { dst, op, a } => NIns::Unary {
            dst,
            op: match op {
                UnOp::Neg => NUnary::Neg,
                UnOp::Not => NUnary::Not,
            },
            a: nopnd(c, a)?,
        },
        Ins::ToBool { dst, src } => NIns::ToBool { dst, src: nopnd(c, src)? },
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
        // El camino general de un `each` (la colección no era el builtin `range`): una lista la
        // recorre el nivel nativo (F4.7b); otra colección sale.
        Ins::EachInitV { src, it, .. } => NIns::EachList { src: nopnd(c, src)?, it },
        // F4.7b: lecturas, con un sitio propio (su caché por forma).
        Ins::GetProp { dst, obj, name, .. } => NIns::GetProp { dst, obj: nopnd(c, obj)?, site: b.site(Some(c.names[name as usize].clone()), true) },
        Ins::GetIndex { dst, obj, idx, .. } => {
            let obj = nopnd(c, obj)?;
            match idx {
                // Una clave de texto constante: la del sitio.
                Opnd::Const(k) => match &c.consts[k as usize] {
                    SynValue::Text(t) => NIns::GetIndex { dst, obj, idx: None, site: b.site(Some(Arc::from(&**t)), false) },
                    _ => NIns::GetIndex { dst, obj, idx: Some(nopnd(c, idx)?), site: b.site(None, false) },
                },
                _ => NIns::GetIndex { dst, obj, idx: Some(nopnd(c, idx)?), site: b.site(None, false) },
            }
        }
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
                // F4.8d2: en un bucle, una task que no se puede compilar (escribe una global, lee algo que
                // el código nativo no representa, …) es una llamada ajena: la corre la VM.
                SynValue::Task(y) if me.is_none() && !task_closes(&y) => NIns::LoadForeign { dst },
                SynValue::Task(y) => {
                    let to = b.callee(y);
                    b.deps.push(Dep { from: me, name: nm, to: Some(to), builtin: "" });
                    NIns::LoadCallee { dst, func: to as u32 }
                }
                v @ SynValue::Builtin(_) if matches!(&v, SynValue::Builtin(x) if x.name == "range") => {
                    b.deps.push(Dep { from: me, name: nm, to: None, builtin: "range" });
                    b.range_fn = Some(v);
                    NIns::RangeFn { dst }
                }
                // F4.7c: un builtin intrínseco (que la global siga siéndolo se verifica al entrar).
                // (`append` sólo en un bucle: ver `NIns::AppendPush`.)
                SynValue::Builtin(x) if NBuiltin::from_name(&x.name).is_some_and(|w| w != NBuiltin::Append || me.is_none()) => {
                    let which = NBuiltin::from_name(&x.name).expect("intrínseco");
                    b.deps.push(Dep { from: me, name: nm, to: None, builtin: which.name() });
                    if !b.builtins.iter().any(|(w, _)| *w == which) {
                        b.builtins.push((which, SynValue::Builtin(x)));
                    }
                    NIns::LoadBuiltin { dst, which }
                }
                // F4.8d2: en un bucle, otro builtin lo carga la VM (una llamada ajena).
                SynValue::Builtin(_) if me.is_none() => NIns::LoadForeign { dst },
                // F4.8b: otra global (no una task ni un builtin), leída por la task de la entrada: un
                // parámetro oculto, leído al entrar (sólo de su propio `closure_env`).
                SynValue::Builtin(_) => return None,
                _ if me == Some(0) => {
                    let k = env.borrow().bindings.find(&nm)?;
                    let g = match b.tglobals.iter().position(|(n, _)| **n == *nm) {
                        Some(g) => g,
                        None => {
                            b.tglobals.push((nm, k));
                            b.tglobals.len() - 1
                        }
                    };
                    NIns::Move { dst, src: NOpnd::Global(g as u16) }
                }
                _ => return None,
            }
        }
        // F4.7c: también una llamada que la VM ya especializó para un builtin (el nivel nativo la
        // hace si el builtin es un intrínseco; si no, sale).
        Ins::Call { dst, func, args, n, site } | Ins::CallNative { dst, func, args, n, site } | Ins::CallBuiltin { dst, func, args, n, site } => {
            if c.sites[site as usize].names.is_some() {
                return None;
            }
            NIns::Call { dst, func, args, n }
        }
        Ins::Give { src } => NIns::Give { src: nopnd(c, src)? },
        Ins::End { src } => NIns::End { src: nopnd(c, src)? },
        // F4.8d2: en un bucle, el chequeo de un builtin protegido lo corre la VM.
        Ins::CheckProtected { func, .. } if me.is_none() => NIns::CheckForeign { func },
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
/// partes de un `range` (`valid`, `next`, `hi`, `step`) o de una lista (F4.7b: dónde está su
/// `Rc`, la posición, el largo y 0), con lo que es cada parte; vacío (`Hole`), o algo que no
/// representa (`Opaque`).
fn iter_parts(v: Option<&EachItems>) -> ([NSeen; 4], [i64; 4]) {
    match v {
        None => ([NSeen::Hole; 4], [0; 4]),
        Some(EachItems::Range(r)) => ([NSeen::Int; 4], [i64::from(r.next.is_some()), r.next.unwrap_or(0), r.hi, r.step]),
        Some(EachItems::List(l, i)) => (
            [NSeen::ListIter, NSeen::Int, NSeen::Int, NSeen::Int],
            [std::ptr::from_ref(l) as usize as i64, *i as i64, l.borrow().len() as i64, 0],
        ),
        Some(_) => ([NSeen::Opaque; 4], [0; 4]),
    }
}

/// Los argumentos de una entrada nativa a una task (las palabras de cada uno), si la task tiene
/// código nativo y todo encaja (los de `CallNative`: aridad, lo que tiene cada argumento, las
/// globales que el código da por sabidas).
fn native_args(t: &SynTaskValue, args: &[SynValue]) -> Option<NativeArgs> {
    let u = t.code.native.unit()?;
    // (Una task con código nativo tiene a lo sumo 8 parámetros y 8 globales: `lower::plan`.)
    if args.len() != u.params.len() || args.len() != t.parameters.len() || args.len() > 8 || u.globals.len() > 8 || (!u.deps.is_empty() && !u.deps_hold(None)) {
        return None;
    }
    let mut out = NativeArgs { w: [0; 16], n: args.len() + u.globals.len() };
    for (k, (v, p)) in args.iter().zip(&u.params).enumerate() {
        out.w[k] = arg_word(v, *p)?;
    }
    if !u.globals.is_empty() {
        let e = t.closure_env.borrow();
        for (g, (k, p)) in u.globals.iter().enumerate() {
            out.w[args.len() + g] = arg_word(e.bindings.slot(*k)?, *p)?;
        }
    }
    Some(out)
}

/// Un argumento (o una global leída al entrar) como la palabra de una entrada nativa, si tiene lo que
/// pide `p`. F4.8b: un valor con caja entra prestado: dónde vive (el registro de la VM, el lugar del
/// argumento en el builtin, el slot de la global), que no se toca hasta que vuelve el código nativo.
fn arg_word(v: &SynValue, p: NSeen) -> Option<i64> {
    Some(match (v, p) {
        (SynValue::Number(Number::Int(x)), NSeen::Int) => *x,
        (SynValue::Number(Number::Float(x)), NSeen::Float) => x.to_bits() as i64,
        (SynValue::Bool(b), NSeen::Bool) => i64::from(*b),
        (SynValue::Nothing, NSeen::Nothing) => 0,
        (v, NSeen::List | NSeen::Map | NSeen::Boxed) if seen_of(v) == p => std::ptr::from_ref(v) as usize as i64,
        _ => return None,
    })
}

/// Las palabras de los argumentos de una entrada nativa (y de las globales que lee).
struct NativeArgs {
    w: [i64; 16],
    n: usize,
}

impl std::ops::Deref for NativeArgs {
    type Target = [i64];
    fn deref(&self) -> &[i64] {
        &self.w[..self.n]
    }
}

pub(super) fn seen_of(v: &SynValue) -> NSeen {
    seen(Some(v))
}

fn seen(v: Option<&SynValue>) -> NSeen {
    match v {
        None => NSeen::Hole,
        Some(SynValue::Number(Number::Int(_))) => NSeen::Int,
        Some(SynValue::Bool(_)) => NSeen::Bool,
        Some(SynValue::Nothing) => NSeen::Nothing,
        Some(SynValue::Number(Number::Float(_))) => NSeen::Float,
        Some(SynValue::List(_)) => NSeen::List,
        Some(SynValue::Map(_)) => NSeen::Map,
        Some(_) => NSeen::Boxed,
    }
}

/// F4.8d: la variable raíz de una escritura de un bucle: una global del entorno del bucle (`Ok`, su
/// nombre: con valor, que no sea una task ni un builtin; el entorno no puede ser un módulo, que
/// sincroniza sus exportaciones) o un lugar de la ventana (`Err`). `None`: no se baja.
fn loop_root(c: &Chunk, root: Root, own: &impl Fn(&str) -> Option<Option<SynValue>>, module: bool) -> Option<Result<Arc<str>, u16>> {
    match root {
        Root::Win(k) => Some(Err(k)),
        Root::Free { name, .. } if !module => {
            let nm = &c.names[name as usize];
            match own(nm) {
                Some(Some(SynValue::Task(_) | SynValue::Builtin(_))) | Some(None) | None => None,
                Some(Some(_)) => Some(Ok(nm.clone())),
            }
        }
        _ => None,
    }
}

/// F4.8d: el índice de un paso o de la hoja de un `set` con camino: un texto constante va como la
/// clave del sitio; otro índice, como operando.
fn path_index(c: &Chunk, idx: Opnd, b: &mut Build) -> Option<(Option<NOpnd>, u32)> {
    Some(match idx {
        Opnd::Const(k) => match &c.consts[k as usize] {
            SynValue::Text(t) => (None, b.site(Some(Arc::from(&**t)), false)),
            _ => (Some(nopnd(c, idx)?), b.site(None, false)),
        },
        _ => (Some(nopnd(c, idx)?), b.site(None, false)),
    })
}

/// F4.8d2: si una task (y las que llama) se puede compilar como parte de una unidad.
fn task_closes(t: &Rc<SynTaskValue>) -> bool {
    // Como la verá la unidad del bucle: una función llamada (la 0 es el bucle).
    let mut b = Build { tasks: vec![None, Some(t.clone())], ..Default::default() };
    b.close(1).is_some()
}

/// F4.8d2: si el código de un bucle tiene llamadas ajenas (entonces corre con un host).
fn code_has_foreign(code: &[NIns]) -> bool {
    code.iter().any(|i| matches!(i, NIns::LoadForeign { .. } | NIns::CheckForeign { .. }))
}

/// F4.8d2: el host de un bucle con llamadas ajenas: el intérprete y el frame del bucle.
struct LoopHost<'a> {
    interp: &'a mut Interpreter,
    chunk: &'a Rc<Chunk>,
    env: &'a Rc<RefCell<Environment>>,
    base: usize,
    lbase: usize,
    iter_base: usize,
    slots: &'a [usize],
    /// El error de una llamada ajena (el código nativo sale sin valores).
    fail: Option<Control>,
    /// La salida del bucle, si un `stop` la cortó.
    jump: Option<usize>,
}

impl NativeHost for LoopHost<'_> {
    fn exec(&mut self, pc: u32, args: &[Option<SynValue>], globals: &[Option<SynValue>], steps: &mut u64) -> HostOut {
        let at = pc as usize;
        {
            let mut e = self.env.borrow_mut();
            for (g, v) in globals.iter().enumerate() {
                if let (Some(v), Some(k)) = (v, self.slots.get(g)) {
                    e.bindings.slot_set(*k, v.clone());
                }
            }
        }
        if let Ins::Call { args: a, .. } | Ins::CallNative { args: a, .. } | Ins::CallBuiltin { args: a, .. } = self.chunk.code[at].get() {
            for (i, v) in args.iter().enumerate() {
                if let Some(v) = v {
                    self.interp.vm_regs[self.base + a as usize + i] = v.clone();
                }
            }
        }
        self.interp.steps = *steps;
        let saved = std::mem::replace(&mut self.interp.vm_lbase, self.lbase);
        let r = self.interp.vm_exec_one(self.chunk, self.env, self.base, at);
        self.interp.vm_lbase = saved;
        let out = match r {
            Ok(()) => HostOut::Ok,
            Err(c) => {
                // Lo que haría el despacho con el error de esta instrucción: los pasos que su bloque
                // sumó de más y, un `stop` en el cuerpo de un bucle, la salida de ese bucle.
                self.interp.steps = self.interp.steps.wrapping_sub(self.chunk.rest[at] as u64);
                if matches!(c, Control::Stop(_)) && self.chunk.stop_to[at] != NONE {
                    self.jump = Some(self.chunk.stop_to[at] as usize);
                    HostOut::Stop
                } else {
                    self.fail = Some(c);
                    HostOut::Fail
                }
            }
        };
        *steps = self.interp.steps;
        out
    }

    fn peek_place(&mut self, p: Place) -> NPeek {
        match p {
            Place::Reg(r) => native_tier::peek_mut(&mut self.interp.vm_regs[self.base + r as usize]),
            Place::Local(k) => match self.interp.vm_locals[self.lbase + k as usize].as_mut() {
                Some(v) => native_tier::peek_mut(v),
                None => NPeek { tag: native_tier::TAG_HOLE, bits: 0, ptr: std::ptr::null() },
            },
            Place::Global(g) => {
                let mut e = self.env.borrow_mut();
                match self.slots.get(g as usize).and_then(|k| e.bindings.slot_mut(*k)) {
                    Some(v) => native_tier::peek_mut(v),
                    None => NPeek { tag: native_tier::TAG_HOLE, bits: 0, ptr: std::ptr::null() },
                }
            }
            Place::Iter(..) => NPeek::MISS,
        }
    }

    fn iter_body(&mut self, it: u16) -> *const ListRef {
        match self.interp.vm_iters.get(self.iter_base + it as usize) {
            Some(EachItems::List(l, _)) => std::ptr::from_ref(l),
            _ => std::ptr::null(),
        }
    }

    fn home(&mut self, p: Place, v: SynValue) -> *const SynValue {
        match p {
            Place::Reg(r) => {
                let s = &mut self.interp.vm_regs[self.base + r as usize];
                *s = v;
                std::ptr::from_mut(s).cast_const()
            }
            Place::Local(k) => std::ptr::from_mut(self.interp.vm_locals[self.lbase + k as usize].insert(v)).cast_const(),
            Place::Global(g) => {
                let mut e = self.env.borrow_mut();
                let k = self.slots[g as usize];
                e.bindings.slot_set(k, v);
                e.bindings.slot_mut(k).map_or(std::ptr::null(), |s| std::ptr::from_mut(s).cast_const())
            }
            Place::Iter(..) => std::ptr::null(),
        }
    }
}

/// Un bucle compilado (F4.2): la unidad y los nombres de sus globales.
pub(crate) struct LoopUnit {
    unit: NativeUnit,
    globals: Vec<Arc<str>>,
    /// Si el código escribe alguna global (entonces el entorno no puede ser un módulo, que
    /// sincroniza su mapa de exportaciones).
    writes: bool,
    /// F4.8d2: si tiene llamadas ajenas (corre con un host).
    foreign: bool,
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
                    // F4.7b: también una global con caja (prestada: el código nativo no la cambia).
                    Some(_) => Some(NIns::Move { dst, src: NOpnd::Global(global(nm)) }),
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
            // F4.8d: `set <camino> to v` y `set P to append(P, e)` sobre una variable del bucle (una
            // global de su entorno, que no sea de un módulo, o una de la ventana).
            Ins::PathRoot { c: cr, desc } => match loop_root(c, c.paths[desc as usize].root, &own, module) {
                Some(Ok(nm)) => {
                    written.push(nm.clone());
                    Some(NIns::PathRoot { c: cr, root: NOpnd::Global(global(&nm)) })
                }
                Some(Err(k)) => Some(NIns::PathRoot { c: cr, root: NOpnd::Local(k) }),
                None => None,
            },
            Ins::AppendInPlace { dst, func, args, site } => match c.sites[site as usize].append.and_then(|r| loop_root(c, r, &own, module)) {
                Some(Ok(nm)) => {
                    written.push(nm.clone());
                    Some(NIns::AppendPush { dst, func, args, root: NOpnd::Global(global(&nm)) })
                }
                Some(Err(k)) => Some(NIns::AppendPush { dst, func, args, root: NOpnd::Local(k) }),
                None => None,
            },
            Ins::PathStep { c: cr, idx, key, .. } => {
                if key != NONE {
                    Some(NIns::PathStep { c: cr, idx: None, site: b.site(Some(c.names[key as usize].clone()), true) })
                } else {
                    path_index(c, idx, b).map(|(idx, site)| NIns::PathStep { c: cr, idx, site })
                }
            }
            Ins::PathSet { c: cr, idx, desc } => {
                let d = c.paths[desc as usize];
                let leaf = if d.key != NONE { Some((None, b.site(Some(c.names[d.key as usize].clone()), true))) } else { path_index(c, idx, b) };
                match (leaf, nopnd(c, d.src)) {
                    (Some((idx, site)), Some(src)) => Some(NIns::PathSet { c: cr, idx, site, src, dst: d.dst }),
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
    pub(super) fn vm_native_tier_up(&mut self, chunk: &Chunk, at: usize, t: &Rc<SynTaskValue>, first: usize, n: usize) {
        let params = self.vm_regs[first..first + n].iter().map(seen_of).collect();
        if !self.vm_native_prepare(t, params) {
            return;
        }
        if let Ins::Call { dst, func, args, n, site } = chunk.code[at].get() {
            chunk.code[at].set(Ins::CallNative { dst, func, args, n, site });
        }
    }

    /// Lo de `vm_native_tier_up` menos reescribir el sitio (F4.8b: también desde `call_fast`, que no
    /// tiene uno): `true` si la task ya tiene código nativo. `params`: lo que tienen los argumentos de
    /// esta llamada.
    #[inline(never)]
    pub(super) fn vm_native_prepare(&mut self, t: &Rc<SynTaskValue>, params: SmallVec<[NSeen; 8]>) -> bool {
        let st = &t.code.native;
        if st.never.get() {
            st.left.set(u32::MAX);
            return false;
        }
        if st.left.get() == 0 {
            // La primera llamada sólo empieza la cuenta (el cuerpo todavía no corrió en la VM:
            // nada está especializado); se compila en la llamada número `umbral`.
            st.left.set(native_tier::threshold().saturating_sub(1).max(1));
            return false;
        }
        if st.unit.get().is_none() {
            // Se compila con lo que tienen los argumentos de esta llamada (F4.7: `Int`, `Float` o
            // `Bool`); con otra cosa, todavía no (se vuelve a mirar dentro de otro umbral).
            if params.iter().any(|p| !matches!(p, NSeen::Int | NSeen::Float | NSeen::Bool | NSeen::List | NSeen::Map | NSeen::Boxed)) {
                st.left.set(native_tier::threshold().max(2));
                return false;
            }
            let compiled = native_tier::tier().and_then(|tier| {
                let b = build_unit(t, params.to_vec())?;
                let code = tier.compile(&NUnit { funcs: b.funcs.clone(), sites: b.sites.clone() })?;
                let nregs0 = b.funcs[0].nregs;
                Some(b.unit(code, nregs0, params.to_vec()))
            });
            match compiled {
                Some(u) => {
                    native_tier::count_unit();
                    let _ = st.unit.set(u);
                }
                None => {
                    st.give_up();
                    return false;
                }
            }
        }
        true
    }

    fn nval_to_syn(unit: &NativeUnit, v: NVal) -> SynValue {
        match v {
            NVal::Int(x) => SynValue::Number(Number::Int(x)),
            NVal::Bool(b) => syn_bool(b),
            NVal::Nothing => SynValue::Nothing,
            NVal::Float(x) => SynValue::Number(Number::Float(x)),
            NVal::Callee(f) => SynValue::Task(unit.task(f as usize).expect("task de la unidad viva")),
            NVal::RangeFn => unit.range_fn.clone().expect("el builtin range de la unidad"),
            NVal::Builtin(w) => unit.builtins.iter().find(|(x, _)| *x == w).map(|(_, v)| v.clone()).expect("un builtin de la unidad"),
            NVal::Hole => SynValue::Nothing,
            NVal::Value(v) => v,
            NVal::List(l) => SynValue::List(l),
            NVal::Keep => unreachable!("un valor en su lugar no se escribe (`vm_put_values`)"),
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
        let argv = match &self.vm_regs[base + func as usize] {
            SynValue::Task(t) => native_args(t, &self.vm_regs[first..first + nn]),
            _ => None,
        };
        let Some(argv) = argv else {
            chunk.code[at].set(Ins::Call { dst, func, args, n, site });
            return Ok(NativeStep::Retry);
        };
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
        native_tier::count_entry();
        let out = {
            let mut cx = NativeCx { steps: &mut self.steps, depth: &mut self.recursion_depth, max_depth: MAX_RECURSION, cancel: &self.cancel.flag, host: None };
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

    /// F4.8b: `call_fast` a una task con código nativo: con los argumentos ya en `r0..` desde `first`
    /// (la profundidad ya contada, la ventana de locales vacía desde `lbase`), entra al código nativo;
    /// si sale a la VM, sus frames siguen en la VM hasta que la task da su valor. `None` si no se
    /// puede entrar (todavía no se tocó nada). El que llama suelta la ventana y la profundidad.
    pub(super) fn vm_native_from_rust(&mut self, t: &Rc<SynTaskValue>, args: &mut [SynValue]) -> Option<Result<SynValue, Control>> {
        let argv = native_args(t, args)?;
        let unit = t.code.native.unit().expect("unidad nativa");
        // Los argumentos ya están en `argv` (los con caja, prestados: siguen en `args` hasta que vuelve
        // el código nativo); si sale a la VM, los frames se arman desde el tope de la pila de
        // registros (la ventana de la task, sus parámetros incluidos).
        let (first, n) = (self.vm_regs.len(), args.len());
        native_tier::count_entry();
        let out = {
            let mut cx = NativeCx { steps: &mut self.steps, depth: &mut self.recursion_depth, max_depth: MAX_RECURSION, cancel: &self.cancel.flag, host: None };
            unit.code.call(&mut cx, &argv)
        };
        for a in args.iter_mut() {
            *a = SynValue::Nothing;
        }
        Some(match out {
            NOutcome::Done(v) => Ok(Self::nval_to_syn(unit, v)),
            NOutcome::Deopt(frames) => {
                native_tier::count_deopt();
                let d = unit.deopts.get() + 1;
                unit.deopts.set(d);
                let outer_iters = self.vm_iters.len();
                let lb0 = self.vm_locals.len();
                let r = self.vm_native_resume(unit, frames, first, n);
                if d > MAX_NATIVE_DEOPTS {
                    t.code.native.give_up();
                }
                let Resume { frames, enter, pc, iter_base, .. } = *r;
                let saved = std::mem::replace(&mut self.vm_lbase, enter.lbase);
                let out = self.run_chunk_from(&enter.code, &enter.env, enter.base, pc, Some((frames, iter_base, outer_iters)));
                self.vm_lbase = saved;
                self.vm_regs.truncate(first);
                self.vm_locals.truncate(lb0);
                match out {
                    Ok(v) | Err(Control::Give(v)) => Ok(v),
                    Err(c) => Err(c),
                }
            }
        })
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
                grow_regs(&mut self.vm_regs, need);
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
        let (out, fail, jump) = if lu.foreign {
            // F4.8d2: con llamadas ajenas el código nativo corre con un host (el intérprete entero:
            // los contadores y el flag van aparte, copiados).
            native_tier::count_foreign();
            let flag = self.cancel.flag.clone();
            let (mut steps, mut depth) = (self.steps, self.recursion_depth);
            let lbase = self.vm_lbase;
            let (out, fail, jump) = {
                let mut host = LoopHost { interp: self, chunk, env, base, lbase, iter_base, slots: &slots, fail: None, jump: None };
                let out = {
                    let mut cx = NativeCx { steps: &mut steps, depth: &mut depth, max_depth: MAX_RECURSION, cancel: &flag, host: Some(&mut host) };
                    lu.unit.code.call(&mut cx, &args)
                };
                (out, host.fail.take(), host.jump.take())
            };
            self.steps = steps;
            self.recursion_depth = depth;
            (out, fail, jump)
        } else {
            let out = {
                let mut cx = NativeCx { steps: &mut self.steps, depth: &mut self.recursion_depth, max_depth: MAX_RECURSION, cancel: &self.cancel.flag, host: None };
                lu.unit.code.call(&mut cx, &args)
            };
            (out, None, None)
        };
        // Una llamada ajena falló: nada vuelve (las globales ya están en el entorno; el frame se
        // desarma con el error: un `try` es un `Ins::Exec`, así que ningún `recover` del mismo frame
        // ve los locales que el código nativo tenía en registros).
        if let Some(c) = fail {
            return OsrStep::Fail(c);
        }
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
            // F4.8d2: un `stop` de una llamada ajena: la VM sigue en la salida del bucle.
            None => OsrStep::Exit(jump.unwrap_or(f0.pc as usize)),
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
            init.extend(iter_parts(self.vm_iters.get(iter_base + it)).0);
        }
        b.funcs.push(NFunc {
            code,
            nregs: chunk.nregs,
            nlocals: chunk.nlocals,
            nparams: 0,
            nglobals,
            niters,
            osr: Some(NOsr { head: head as u32, init }),
            params: Vec::new(),
            globals: Vec::new(),
        });
        b.close(1)?;
        // El código de las tasks que llama no puede ser este chunk (el bucle vive en él: un ciclo).
        if b.tasks.iter().flatten().any(|t| t.code.get().is_some_and(|c| Rc::ptr_eq(c, chunk))) {
            return None;
        }
        let loop_code = b.funcs[0].code.clone();
        let code = tier.compile(&NUnit { funcs: std::mem::take(&mut b.funcs), sites: std::mem::take(&mut b.sites) })?;
        let foreign = code_has_foreign(&loop_code);
        Some(LoopUnit { unit: b.unit(code, chunk.nregs, Vec::new()), globals, writes, foreign })
    }

    /// La guarda de entrada a un bucle nativo: cada lugar que el código lee o escribe tiene lo que
    /// tenía al compilar (nunca un valor con caja: sus cuentas de referencias no se tocan), las
    /// globales están en el entorno y las tasks siguen siendo esas. Los valores de entrada y el
    /// slot de cada global.
    fn vm_osr_args(&mut self, lu: &LoopUnit, env: &Rc<RefCell<Environment>>, base: usize, iter_base: usize) -> Option<(SmallVec<[i64; 16]>, SmallVec<[usize; 8]>)> {
        let mut e = env.borrow_mut();
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
                let (s, x) = iter_parts(self.vm_iters.get(iter_base + it as usize));
                if s[k as usize] != want {
                    return None;
                }
                args.push(x[k as usize]);
                continue;
            }
            // (Por `&mut`: en un bucle con escrituras (F4.8d) el código escribe por esta dirección.)
            let v = match place {
                Place::Reg(r) => Some(&mut self.vm_regs[base + r as usize]),
                Place::Local(k) => self.vm_locals[self.vm_lbase + k as usize].as_mut(),
                Place::Global(g) => e.bindings.slot_mut(slots[g as usize]),
                Place::Iter(..) => unreachable!("iterador"),
            };
            if seen(v.as_deref()) != want {
                return None;
            }
            args.push(match v {
                Some(SynValue::Number(Number::Int(x))) => *x,
                Some(SynValue::Bool(b)) => i64::from(*b),
                Some(SynValue::Number(Number::Float(x))) => x.to_bits() as i64,
                Some(SynValue::Nothing) | None => 0,
                // F4.7b: un valor con caja entra prestado: dónde vive (su lugar en la VM). Ahí sigue
                // hasta que vuelve el código nativo: nada mueve la memoria de la VM mientras tanto.
                Some(v) => std::ptr::from_mut(v) as usize as i64,
            });
        }
        // F4.8d: los lugares donde el código puede dejar un valor con caja (antes de una escritura).
        for &place in lu.unit.code.homes() {
            let p = match place {
                Place::Reg(r) => std::ptr::from_mut(&mut self.vm_regs[base + r as usize]) as usize as i64,
                Place::Local(k) => std::ptr::from_mut(&mut self.vm_locals[self.vm_lbase + k as usize]) as usize as i64,
                Place::Global(g) => std::ptr::from_mut(e.bindings.slot_mut(slots[g as usize])?) as usize as i64,
                Place::Iter(..) => return None,
            };
            args.push(p);
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
        let mut iters: SmallVec<[(u16, [i64; 4], bool, Option<ListRef>); 4]> = SmallVec::new();
        for (place, v) in values {
            // F4.8d: lo que el código nativo dejó en su lugar ya está ahí.
            if matches!(v, NVal::Keep) {
                continue;
            }
            match place {
                Place::Reg(r) => self.vm_regs[rbase + r as usize] = Self::nval_to_syn(unit, v),
                Place::Local(k) => self.vm_locals[lbase + k as usize] = (!matches!(v, NVal::Hole)).then(|| Self::nval_to_syn(unit, v)),
                Place::Global(g) => {
                    // Una global vacía el código nativo no la escribió (un `set` a un hueco sale antes).
                    if !matches!(v, NVal::Hole) {
                        let (env, slots) = globals.expect("global fuera de un bucle");
                        env.borrow_mut().bindings.slot_set(slots[g as usize], Self::nval_to_syn(unit, v));
                    }
                }
                Place::Iter(it, k) => {
                    let i = match iters.iter().position(|x| x.0 == it) {
                        Some(i) => i,
                        None => {
                            iters.push((it, [0; 4], false, None));
                            iters.len() - 1
                        }
                    };
                    match v {
                        NVal::Int(x) => iters[i].1[k as usize] = x,
                        // F4.7b: un iterador de una lista (su lista, ya clonada; la posición en la parte 1).
                        NVal::List(l) => iters[i].3 = Some(l),
                        _ => iters[i].2 = true,
                    }
                }
            }
        }
        iters.sort_by_key(|x| x.0);
        for (it, p, gone, list) in iters {
            let at = ib + it as usize;
            if gone {
                self.vm_iters.truncate(at);
                continue;
            }
            let r = match list {
                Some(l) => EachItems::List(l, p[1] as usize),
                None => EachItems::Range(RangeIter { next: (p[0] != 0).then_some(p[1]), hi: p[2], step: p[3] }),
            };
            if at < self.vm_iters.len() {
                self.vm_iters[at] = r;
            } else {
                assert_eq!(at, self.vm_iters.len(), "iterador nativo fuera de orden");
                self.vm_iters.push(r);
            }
        }
    }
}
