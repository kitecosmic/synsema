//! La VM de bytecode (F3 de specs/compute-rendimiento.md). Corre al lado del tree-walker, nunca en
//! su lugar: sólo con atajos y con etiquetas apagadas (`shortcuts && !labels`); en modo referencia
//! y con etiquetas corre el tree-walker, y el oráculo diferencial compara los dos caminos.
//!
//! **Formato** (pensado para lo que viene, §6.1 del spec):
//! - VM de **registros** (L4): cada expresión deja su valor en un registro temporal; las variables
//!   locales son los slots del frame de F2a (el mismo `Environment`, con los nombres puestos de
//!   antemano en el orden del resolver), así que las closures y el copy-on-write ven lo mismo.
//! - **Estado explícito**: código, `pc`, ventana de registros y frame; nada escondido en la pila de
//!   Rust entre instrucciones (lo que habilita, más adelante, llamadas sin recursión, OSR y
//!   volver desde código nativo).
//! - **`steps()` por bloque básico** (como el *fuel* de wasmtime): cada nodo que la referencia
//!   evalúa suma 1 a la primera instrucción de su subárbol; un bloque básico suma todo al entrar
//!   (`Steps`) y, si una instrucción falla a mitad de bloque, `rest` dice cuánto sobra. Un bloque
//!   termina en cada instrucción que puede observar el contador (llamar al tree-walker) o saltar,
//!   así que en esos puntos el número es exacto.
//! - Constantes en un pool, ubicaciones en una tabla, un slot de *feedback* por operación
//!   (reservado: lo usa el quickening de F3.4) y los encabezados de bucle (reservados: calor/OSR).
//!
//! **Qué se compila** (F3.1): literales, variables, operadores, `and`/`or`, cadenas de comparación,
//! `let`, `set` a una variable, `when`, `while`, `give`, `stop` y la definición de tasks y lambdas
//! (su cuerpo se compila también). Todo lo demás es `Exec`: el nodo lo corre el tree-walker con el
//! frame de la VM como entorno (§6.0 punto 4), y cuenta sus propios pasos.

use super::*;
use crate::resolve::{self, Resolution, ScopeId, Target};
use std::cell::Cell;

pub(crate) type Reg = u16;
/// Registro destino "no hace falta el valor": se suelta en el acto.
const DISCARD: Reg = Reg::MAX;
const NONE: u32 = u32::MAX;

/// Un operando: un registro que se consume, uno que se copia, una constante o un slot del frame
/// propio que está ligado seguro.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Opnd {
    Reg(Reg),
    Copy(Reg),
    Const(u32),
    Local(u16),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Ins {
    /// Entrada a un bloque básico: los pasos de todos sus nodos.
    Steps(u32),
    /// Sólo existe mientras se compila (lleva pasos); no queda en el código final.
    Nop,
    CheckCancel,
    Const { dst: Reg, k: u32 },
    Move { dst: Reg, src: Opnd },
    Drop { r: Reg },
    /// Slot del frame propio que puede estar vacío: si lo está, por nombre desde el padre.
    LoadLocal { dst: Reg, slot: u16, name: u32 },
    /// Slot de un frame de afuera, con guarda por frame (`at` = de dónde se parte; ver `Hops`).
    LoadOuter { dst: Reg, depth: u16, slot: u16, name: u32, at: u32 },
    /// Por nombre, desde el primer frame que no es del resolver (ver `free_start`), con una caché
    /// del slot donde estaba (el índice de un slot no cambia nunca, F2a).
    LoadName { dst: Reg, name: u32, ic: u32 },
    /// `fb`: su slot de feedback (reservado para el quickening de F3.4).
    Binary { dst: Reg, op: BinOp, a: Opnd, b: Opnd, #[allow(dead_code)] fb: u16 },
    Unary { dst: Reg, op: UnOp, a: Opnd },
    ToBool { dst: Reg, src: Opnd },
    Jump { to: u32 },
    JumpIfFalsy { src: Opnd, to: u32 },
    LetLocal { src: Opnd, slot: u16, dst: Reg },
    LetName { src: Opnd, name: u32, dst: Reg },
    SetLocal { src: Opnd, slot: u16, name: u32, dst: Reg },
    SetOuter { src: Opnd, depth: u16, slot: u16, name: u32, dst: Reg, at: u32 },
    SetName { src: Opnd, name: u32, dst: Reg, ic: u32 },
    /// `set P to append(P, …)` y compañía: la vía en el lugar de la referencia
    /// (`try_update_in_place`) si la variable es una lista o un mapa; si aplica, salta a `done`.
    /// `ic` = `NONE` si la variable es del resolver (se mira por nombre desde el frame propio);
    /// `name` = `NONE` si el destino es un camino (siempre se prueba).
    TryInPlace { dst: Reg, node: u32, name: u32, done: u32, ic: u32 },
    /// El nodo lo corre el tree-walker.
    Exec { dst: Reg, node: u32 },
    /// `[a, b, …]` con los elementos en `n` registros desde `first`.
    MakeList { dst: Reg, first: Reg, n: u16 },
    /// `{k: v, …}` con clave y valor alternados en `2n` registros desde `first`.
    MakeMap { dst: Reg, first: Reg, n: u16 },
    GetProp { dst: Reg, obj: Opnd, name: u32 },
    GetIndex { dst: Reg, obj: Opnd, idx: Opnd },
    /// `set <camino> to v`: el destino lo recorre la referencia (`exec_set`), con el valor ya
    /// evaluado.
    SetPath { src: Opnd, node: u32, dst: Reg },
    /// `private(…)`, `print(…)` y los demás protegidos tienen que resolver al builtin de verdad; la
    /// referencia lo chequea antes de evaluar los argumentos.
    CheckProtected { func: Reg, name: u32 },
    /// Una llamada (F3.2): la función en `func`, los argumentos en `n` registros desde `args`. Si
    /// es una task compilada y todos van por posición, la VM entra al cuerpo sin recursión en
    /// Rust; si no, el camino de siempre (`call_value_named`).
    Call { dst: Reg, func: Reg, args: Reg, n: u16, site: u32 },
    /// Define una task o lambda (el tree-walker) y le cuelga su cuerpo compilado.
    Define { dst: Reg, node: u32, child: u32 },
    /// `each` (F3.2): evalúa la colección (como la referencia, con el atajo de `range`) y deja su
    /// iterador en el lugar `it` de este cuerpo.
    EachInit { node: u32, it: u16 },
    /// La vuelta siguiente: un frame nuevo para la vuelta, con la variable; sin más, a `exit`.
    EachNext { it: u16, var: u32, scope: u32, exit: u32 },
    /// Fin de la vuelta: el frame vuelve a la pila si nadie lo capturó, y a `head`.
    EachStep { head: u32 },
    /// Suelta el iterador de un `each` que terminó.
    EachEnd { it: u16 },
    /// Vuelve a `depth` frames de la VM dentro de este cuerpo (salir de un bucle o de un brazo por
    /// un `stop`, o terminar un brazo de `match`).
    Unwind { depth: u16 },
    /// Un brazo de `match` (F3.2): el patrón lo evalúa la referencia contra el sujeto; si
    /// matchea, un frame nuevo con sus binders; si no, a `fail`.
    MatchArm { subj: Reg, node: u32, scope: u32, fail: u32 },
    Give { src: Opnd },
    /// `stop` fuera de un bucle compilado: sale del cuerpo como `Control::Stop`.
    StopOut { src: Opnd, has: bool },
    End { src: Opnd },
    /// wasm32: el tope de vueltas de un `while` (ahí nadie puede cortar un bucle sin fin).
    WasmTick { ctr: Reg },
}

/// Los nombres de un frame en el orden del resolver (parámetros primero). Un frame que la VM
/// preparó lleva este `Rc`: es la guarda de las lecturas de afuera.
pub struct Layout {
    pub(crate) names: Vec<Arc<str>>,
}

pub(crate) struct Chunk {
    code: Vec<Ins>,
    /// Por instrucción: los pasos que su bloque sumó de más si ésta falla.
    rest: Vec<u32>,
    /// Por instrucción: la salida del bucle compilado cuyo CUERPO la contiene (`NONE` si no hay).
    /// Un `stop` que llega hasta ella (de un nodo del tree-walker, de una task llamada) corta ese
    /// bucle, como en la referencia; en la condición de un `while` o la colección de un `each`
    /// no hay (la referencia tampoco lo atrapa ahí).
    stop_to: Vec<u32>,
    loc: Vec<u32>,
    locs: Vec<SourceLocation>,
    consts: Vec<SynValue>,
    names: Vec<Arc<str>>,
    nodes: Vec<Node>,
    children: Vec<Rc<Chunk>>,
    sites: Vec<CallSite>,
    layouts: Rc<Vec<Rc<Layout>>>,
    parents: Rc<Vec<Option<ScopeId>>>,
    /// El layout del frame propio (tasks y lambdas).
    pub(crate) frame: Option<Rc<Layout>>,
    /// Si el frame lleva su `Layout` como marca: sólo hace falta cuando otro chunk (el de una task
    /// o lambda definida adentro) lo va a recorrer y tiene que verificarlo. Los frames que la VM
    /// preparó para este chunk no se verifican: los armó ella.
    pub(crate) tagged: bool,
    nregs: u16,
    /// Las cachés de `LoadName`/`SetName`/`TryInPlace` (0 = vacía; si no, slot + 1) y, para cada
    /// una, desde dónde se busca (`hops`).
    ics: Vec<Cell<u32>>,
    ic_hops: Vec<u32>,
    /// Los recorridos hacia afuera de este cuerpo (ver `Hops`).
    hops: Vec<Hops>,
    /// Reservado (F3.4): cuántos slots de feedback hay.
    #[allow(dead_code)]
    feedback: u16,
    /// Reservado (calor/OSR): dónde empieza cada bucle.
    #[allow(dead_code)]
    loop_heads: Vec<u32>,
}

/// Desde dónde parte una lectura que sale del frame actual: el scope del resolver donde está la
/// instrucción, cuántos frames de la cadena son de este cuerpo (los preparó la VM: no se
/// verifican) y, para una variable `Free`, cuántos frames del resolver hay hasta la raíz dinámica
/// (no la tienen; 0 si alguno es dinámico: se busca desde el frame actual).
#[derive(Clone, Copy)]
struct Hops {
    from: Option<ScopeId>,
    inner: u16,
    skip: u16,
}

/// Lo que una llamada necesita además de sus registros.
struct CallSite {
    /// Los nombres de los argumentos, si alguno va por nombre (entonces, camino de siempre).
    names: Option<Box<[Option<String>]>>,
    /// Si se chequea la aridad: una llamada escrita sí; el paso de un pipe que no es una llamada
    /// (`xs |> f`) no, como `call_value` en la referencia.
    checked: bool,
}

/// El estado del llamador de una llamada que la VM corre sin recursión (F3.2). El frame de la
/// llamada es el `env` del cuerpo mientras corre.
pub(crate) struct VmFrame {
    chunk: Rc<Chunk>,
    env: Rc<RefCell<Environment>>,
    base: usize,
    /// La instrucción después del `Call`.
    pc: usize,
    dst: Reg,
    /// Cuántos frames de la VM (vueltas, brazos) tenía abiertos el llamador, y dónde empiezan
    /// sus iteradores.
    depth: u16,
    iter_base: usize,
    /// `enter_call`/`leave_call` sólo mueven tinta de etiquetas: con etiquetas apagadas (la VM no
    /// corre con ellas) la tinta está vacía y no cambia, así que no se toca.
    taint: Option<TaintFrame>,
    /// La task llamada: vive hasta el final de la llamada, como en `call_value_named_inner`.
    task: Rc<SynTaskValue>,
}

/// El código compilado de una task, y cuántas veces se llamó antes de compilarla.
#[derive(Default)]
pub struct TaskCode {
    code: std::cell::OnceCell<Rc<Chunk>>,
    calls: Cell<u32>,
}

/// Una task definida por el tree-walker se compila recién en su segunda llamada: una lambda que
/// se arma en cada vuelta y se llama una vez no paga el compilador.
const COMPILE_AT_CALL: u32 = 2;

impl TaskCode {
    #[inline]
    pub(crate) fn get(&self) -> Option<&Rc<Chunk>> {
        self.code.get()
    }
    fn set(&self, c: Rc<Chunk>) {
        let _ = self.code.set(c);
    }
}

// =============================================================================================
// Compilador
// =============================================================================================

/// El programa (las sentencias después del preámbulo `intent`/`require`), con las tasks y lambdas
/// que define compiladas también.
pub(crate) fn compile_program(stmts: &[Node]) -> Rc<Chunk> {
    let res = resolve::resolve_block(stmts);
    let shared = Shared::new(&res);
    let mut c = Compiler::new(&res, &shared, None);
    c.block(stmts, Some(0), false);
    c.finish(Opnd::Reg(0))
}

/// El cuerpo de una task o lambda que definió el tree-walker, resuelto por sí solo.
pub(crate) fn compile_function(params: &[Arc<str>], body: &[Node]) -> Rc<Chunk> {
    let (res, s) = resolve::resolve_function(params, body);
    let shared = Shared::new(&res);
    let mut c = Compiler::new(&res, &shared, Some(s));
    c.block(body, Some(0), true);
    c.finish(Opnd::Reg(0))
}

/// Lo que comparten un chunk y los de sus tasks anidadas: los layouts de todos los scopes.
struct Shared<'r> {
    by_node: HashMap<usize, &'r resolve::Access>,
    layouts: Rc<Vec<Rc<Layout>>>,
    parents: Rc<Vec<Option<ScopeId>>>,
}

impl<'r> Shared<'r> {
    fn new(res: &'r Resolution) -> Self {
        let layouts = res.scopes.iter().map(|s| Rc::new(Layout { names: s.names.clone() })).collect();
        let parents = res.scopes.iter().map(|s| s.parent).collect();
        Shared { by_node: res.by_node(), layouts: Rc::new(layouts), parents: Rc::new(parents) }
    }
}

struct Compiler<'r, 's> {
    res: &'r Resolution,
    shared: &'s Shared<'r>,
    frame_scope: Option<ScopeId>,
    code: Vec<Ins>,
    weight: Vec<u32>,
    loc: Vec<u32>,
    stop_of: Vec<u32>,
    locs: Vec<SourceLocation>,
    consts: Vec<SynValue>,
    names: Vec<Arc<str>>,
    nodes: Vec<Node>,
    children: Vec<Rc<Chunk>>,
    sites: Vec<CallSite>,
    /// Nodos que la referencia ya "entró" y todavía no tienen instrucción.
    pending: u32,
    next_reg: Reg,
    max_reg: Reg,
    /// Label → instrucción (o `NONE` mientras no se ligó).
    labels: Vec<u32>,
    /// Salida de cada bucle compilado abierto.
    loops: Vec<u32>,
    feedback: u16,
    loop_heads: Vec<u32>,
    cur_loc: u32,
    ics: u32,
    ic_hops: Vec<u32>,
    hops: Vec<Hops>,
    /// El scope del resolver donde se compila ahora, cuántos frames de la VM hay abiertos dentro
    /// de este cuerpo (vueltas de `each`, brazos de `match`) y cuántos `each` anidados.
    cur_scope: Option<ScopeId>,
    depth: u16,
    eaches: u16,
}

impl<'r, 's> Compiler<'r, 's> {
    fn new(res: &'r Resolution, shared: &'s Shared<'r>, frame_scope: Option<ScopeId>) -> Self {
        Compiler {
            res,
            shared,
            frame_scope,
            code: Vec::new(),
            weight: Vec::new(),
            loc: Vec::new(),
            stop_of: Vec::new(),
            locs: Vec::new(),
            consts: Vec::new(),
            names: Vec::new(),
            nodes: Vec::new(),
            children: Vec::new(),
            sites: Vec::new(),
            pending: 0,
            // r0: el valor del bloque de más afuera.
            next_reg: 1,
            max_reg: 1,
            labels: Vec::new(),
            loops: Vec::new(),
            feedback: 0,
            loop_heads: Vec::new(),
            cur_loc: 0,
            ics: 0,
            ic_hops: Vec::new(),
            hops: Vec::new(),
            cur_scope: frame_scope,
            depth: 0,
            eaches: 0,
        }
    }

    // -- emisión --------------------------------------------------------------------------------

    fn at(&mut self, loc: &SourceLocation) {
        if self.locs.last() != Some(loc) {
            self.locs.push(loc.clone());
        }
        self.cur_loc = (self.locs.len() - 1) as u32;
    }

    fn emit(&mut self, ins: Ins) {
        self.code.push(ins);
        self.weight.push(std::mem::take(&mut self.pending));
        self.loc.push(self.cur_loc);
        self.stop_of.push(self.loops.last().copied().unwrap_or(NONE));
    }

    /// La referencia entra a un nodo: un paso.
    fn enter(&mut self) {
        self.pending += 1;
    }

    /// Los pasos pendientes no pueden cruzar un label ni el final de una sentencia.
    fn flush(&mut self) {
        if self.pending > 0 {
            self.emit(Ins::Nop);
        }
    }

    fn label(&mut self) -> u32 {
        self.labels.push(NONE);
        (self.labels.len() - 1) as u32
    }

    fn bind(&mut self, l: u32) {
        self.flush();
        self.labels[l as usize] = self.code.len() as u32;
    }

    fn reg(&mut self) -> Reg {
        let r = self.next_reg;
        self.next_reg += 1;
        self.max_reg = self.max_reg.max(self.next_reg);
        r
    }

    fn konst(&mut self, v: SynValue) -> u32 {
        self.consts.push(v);
        (self.consts.len() - 1) as u32
    }

    fn name(&mut self, n: &str) -> u32 {
        if let Some(i) = self.names.iter().position(|x| &**x == n) {
            return i as u32;
        }
        self.names.push(Arc::from(n));
        (self.names.len() - 1) as u32
    }

    fn shared_name(&mut self, n: &Arc<str>) -> u32 {
        if let Some(i) = self.names.iter().position(|x| Arc::ptr_eq(x, n)) {
            return i as u32;
        }
        self.names.push(n.clone());
        (self.names.len() - 1) as u32
    }

    fn ic(&mut self) -> u32 {
        let h = self.hops_here();
        self.ic_hops.push(h);
        self.ics += 1;
        self.ics - 1
    }

    /// El recorrido hacia afuera desde el scope actual (ver `Hops`).
    fn hops_here(&mut self) -> u32 {
        let inner = self.depth + u16::from(self.frame_scope.is_some());
        let mut skip = 0u16;
        let mut s = self.cur_scope;
        while let Some(x) = s {
            if self.res.scopes[x as usize].dynamic {
                skip = 0;
                break;
            }
            skip += 1;
            s = self.shared.parents[x as usize];
        }
        self.hops.push(Hops { from: self.cur_scope, inner, skip });
        (self.hops.len() - 1) as u32
    }

    fn cold(&mut self, n: &Node) -> u32 {
        self.nodes.push(n.clone());
        (self.nodes.len() - 1) as u32
    }

    fn target(&self, n: &Node) -> Target {
        self.shared.by_node.get(&(n as *const Node as usize)).map(|a| a.target).unwrap_or(Target::Free)
    }

    /// Un `Local`/`Outer` sólo vale para scopes de la cadena del scope actual.
    fn in_frame(&self, scope: ScopeId, depth: u16) -> bool {
        let mut s = self.cur_scope;
        for _ in 0..depth {
            s = s.and_then(|x| self.shared.parents[x as usize]);
        }
        s == Some(scope)
    }

    // -- sentencias -----------------------------------------------------------------------------

    /// Un bloque (`exec_block`): cancelación antes de cada sentencia (salvo en el nivel de más
    /// afuera del programa) y el valor de la última en `want`.
    fn block(&mut self, stmts: &[Node], want: Option<Reg>, cancel: bool) {
        let refs: Vec<&Node> = stmts.iter().collect();
        self.block_of(&refs, want, cancel);
    }

    fn block_of(&mut self, stmts: &[&Node], want: Option<Reg>, cancel: bool) {
        if stmts.is_empty() {
            if let Some(d) = want {
                let k = self.konst(SynValue::Nothing);
                self.emit(Ins::Const { dst: d, k });
            }
            return;
        }
        let last = stmts.len() - 1;
        for (i, s) in stmts.iter().enumerate() {
            if cancel {
                self.at(&s.location);
                self.emit(Ins::CheckCancel);
            }
            let mark = self.next_reg;
            self.stmt(s, if i == last { want } else { None });
            self.flush();
            self.next_reg = mark;
        }
    }

    fn stmt(&mut self, n: &Node, want: Option<Reg>) {
        use NodeKind as K;
        let dst = want.unwrap_or(DISCARD);
        self.at(&n.location);
        match &n.kind {
            K::LetBinding { name, value, .. } => {
                self.enter();
                let v = self.expr(value);
                self.at(&n.location);
                match self.target_of_bind(n) {
                    Some(slot) => self.emit(Ins::LetLocal { src: v, slot, dst }),
                    None => {
                        let name = self.shared_name(name);
                        self.emit(Ins::LetName { src: v, name, dst })
                    }
                }
            }
            K::SetMutation { target, value } if matches!(target.kind, K::Identifier { .. }) => {
                let K::Identifier { name } = &target.kind else { unreachable!() };
                self.enter();
                let done = if in_place_shape(target, value) {
                    let node = self.cold(n);
                    let nm = self.name(name);
                    let done = self.label();
                    let ic = if self.target(target) == Target::Free { self.ic() } else { NONE };
                    self.emit(Ins::TryInPlace { dst, node, name: nm, done, ic });
                    Some(done)
                } else {
                    None
                };
                let v = self.expr(value);
                self.at(&n.location);
                let nm = self.name(name);
                match self.target(target) {
                    Target::Slot { depth: 0, scope, slot, .. } if self.in_frame(scope, 0) => {
                        self.emit(Ins::SetLocal { src: v, slot, name: nm, dst })
                    }
                    Target::Slot { depth, scope, slot, .. } if self.in_frame(scope, depth) => {
                        let at = self.hops_here();
                        self.emit(Ins::SetOuter { src: v, depth, slot, name: nm, dst, at })
                    }
                    _ => {
                        let ic = self.ic();
                        self.emit(Ins::SetName { src: v, name: nm, dst, ic })
                    }
                }
                if let Some(d) = done {
                    self.bind(d);
                }
            }
            K::SetMutation { target, value } => {
                // `set m.a[k] to v`: la vía en el lugar si aplica (siempre se prueba: la variable
                // de la raíz no dice si el lugar es una lista), el valor compilado y el destino por
                // la referencia.
                self.enter();
                let done = if in_place_shape(target, value) {
                    let node = self.cold(n);
                    let done = self.label();
                    self.emit(Ins::TryInPlace { dst, node, name: NONE, done, ic: NONE });
                    Some(done)
                } else {
                    None
                };
                let v = self.expr(value);
                let node = self.cold(target);
                self.at(&n.location);
                self.emit(Ins::SetPath { src: v, node, dst });
                if let Some(d) = done {
                    self.bind(d);
                }
            }
            K::WhenStatement { .. } => self.when(n, want),
            K::WhileStatement { condition, body } => {
                self.enter();
                self.flush();
                if let Some(d) = want {
                    let k = self.konst(SynValue::Nothing);
                    self.emit(Ins::Const { dst: d, k });
                }
                let ctr = if cfg!(target_arch = "wasm32") {
                    let r = self.reg();
                    let k = self.konst(syn_int(0));
                    self.emit(Ins::Const { dst: r, k });
                    Some(r)
                } else {
                    None
                };
                let head = self.label();
                let exit = self.label();
                self.bind(head);
                self.loop_heads.push(head);
                if let Some(r) = ctr {
                    self.at(&n.location);
                    self.emit(Ins::WasmTick { ctr: r });
                }
                let c = self.expr(condition);
                self.at(&n.location);
                self.emit(Ins::JumpIfFalsy { src: c, to: exit });
                if let Some(d) = want {
                    let k = self.konst(SynValue::Nothing);
                    self.emit(Ins::Const { dst: d, k });
                }
                self.loops.push(exit);
                self.block(body, want, true);
                self.loops.pop();
                self.emit(Ins::Jump { to: head });
                self.bind(exit);
                self.emit(Ins::Unwind { depth: self.depth });
            }
            K::EachStatement { variable, body, .. } => {
                self.enter();
                let node = self.cold(n);
                let it = self.eaches;
                self.eaches += 1;
                self.emit(Ins::EachInit { node, it });
                if let Some(d) = want {
                    let k = self.konst(SynValue::Nothing);
                    self.emit(Ins::Const { dst: d, k });
                }
                let scope = self.res.scope_opened_by(n).expect("each sin scope");
                let head = self.label();
                let exit = self.label();
                self.bind(head);
                self.loop_heads.push(head);
                let var = self.shared_name(variable);
                self.at(&n.location);
                self.emit(Ins::EachNext { it, var, scope, exit });
                // El valor de la vuelta anterior se suelta antes de correr la siguiente.
                if let Some(d) = want {
                    let k = self.konst(SynValue::Nothing);
                    self.emit(Ins::Const { dst: d, k });
                }
                let (outer_scope, outer_depth) = (self.cur_scope, self.depth);
                self.cur_scope = Some(scope);
                self.depth += 1;
                self.loops.push(exit);
                self.block(body, want, true);
                self.loops.pop();
                self.emit(Ins::EachStep { head });
                self.cur_scope = outer_scope;
                self.depth = outer_depth;
                self.bind(exit);
                self.emit(Ins::Unwind { depth: self.depth });
                self.emit(Ins::EachEnd { it });
                self.eaches -= 1;
            }
            K::MatchStatement { value, arms, otherwise } => {
                self.enter();
                let v = self.expr(value);
                let subj = self.to_reg(v);
                let end = self.label();
                for arm in arms {
                    let NodeKind::MatchArm { guard, body, .. } = &arm.kind else { continue };
                    let fail = self.label();
                    let node = self.cold(arm);
                    let scope = self.res.scope_opened_by(arm).expect("brazo sin scope");
                    self.at(&arm.location);
                    self.emit(Ins::MatchArm { subj, node, scope, fail });
                    let (outer_scope, outer_depth) = (self.cur_scope, self.depth);
                    self.cur_scope = Some(scope);
                    self.depth += 1;
                    let guard_fail = guard.as_ref().map(|g| {
                        let c = self.expr(g);
                        let l = self.label();
                        self.at(&arm.location);
                        self.emit(Ins::JumpIfFalsy { src: c, to: l });
                        l
                    });
                    self.block(body, want, true);
                    self.emit(Ins::Unwind { depth: outer_depth });
                    self.emit(Ins::Jump { to: end });
                    self.cur_scope = outer_scope;
                    self.depth = outer_depth;
                    if let Some(l) = guard_fail {
                        // El guard dio falso: se suelta el frame del brazo y sigue el próximo.
                        self.bind(l);
                        self.emit(Ins::Unwind { depth: outer_depth });
                    }
                    self.bind(fail);
                }
                match otherwise {
                    Some(o) => self.block(o, want, true),
                    None => {
                        if let Some(d) = want {
                            let k = self.konst(SynValue::Nothing);
                            self.emit(Ins::Const { dst: d, k });
                        }
                    }
                }
                self.bind(end);
                self.emit(Ins::Drop { r: subj });
            }
            K::GiveStatement { value } => {
                self.enter();
                let v = match value {
                    Some(v) => self.expr(v),
                    None => Opnd::Const(self.konst(SynValue::Nothing)),
                };
                self.at(&n.location);
                self.emit(Ins::Give { src: v });
            }
            K::StopStatement { value } => {
                self.enter();
                let v = value.as_ref().map(|v| self.expr(v));
                self.at(&n.location);
                match self.loops.last().copied() {
                    Some(exit) => {
                        if let Some(Opnd::Reg(r)) = v {
                            self.emit(Ins::Drop { r });
                        }
                        self.emit(Ins::Jump { to: exit });
                    }
                    None => {
                        let has = v.is_some();
                        let src = v.unwrap_or_else(|| Opnd::Const(self.konst(SynValue::Nothing)));
                        self.emit(Ins::StopOut { src, has });
                    }
                }
            }
            K::TaskDefinition { .. } => self.define(n, dst),
            K::TaskCall { .. } => {
                self.call(n, dst);
            }
            _ if is_expression(&n.kind) => {
                let v = self.expr_in(n, want);
                match (want, v) {
                    (Some(d), v) if v == Opnd::Reg(d) => {}
                    (Some(d), v) => self.emit(Ins::Move { dst: d, src: v }),
                    (None, Opnd::Reg(r)) => self.emit(Ins::Drop { r }),
                    (None, _) => {}
                }
            }
            _ => {
                let node = self.cold(n);
                self.emit(Ins::Exec { dst, node });
            }
        }
    }

    fn target_of_bind(&self, n: &Node) -> Option<u16> {
        let a = self.shared.by_node.get(&(n as *const Node as usize))?;
        match a.target {
            Target::Slot { depth: 0, scope, slot, .. } if self.in_frame(scope, 0) => Some(slot),
            _ => None,
        }
    }

    fn when(&mut self, n: &Node, want: Option<Reg>) {
        let NodeKind::WhenStatement { condition, body, otherwise, otherwise_when } = &n.kind else { unreachable!() };
        self.enter();
        let c = self.expr(condition);
        self.at(&n.location);
        let other = self.label();
        let end = self.label();
        self.emit(Ins::JumpIfFalsy { src: c, to: other });
        self.block(body, want, true);
        self.emit(Ins::Jump { to: end });
        self.bind(other);
        if let Some(ow) = otherwise_when {
            // `exec_when_branches` lo evalúa con `exec`, no como bloque: sin chequeo de cancelación.
            let mark = self.next_reg;
            self.stmt(ow, want);
            self.flush();
            self.next_reg = mark;
        } else if let Some(o) = otherwise {
            self.block(o, want, true);
        } else if let Some(d) = want {
            let k = self.konst(SynValue::Nothing);
            self.emit(Ins::Const { dst: d, k });
        }
        self.bind(end);
    }

    /// Una task o lambda: la define el tree-walker; su cuerpo se compila acá.
    fn define(&mut self, n: &Node, dst: Reg) {
        let child = match (&n.kind, self.res.scope_opened_by(n)) {
            (NodeKind::TaskDefinition { body, .. }, Some(s)) => {
                let body: Vec<&Node> =
                    body.iter().filter(|x| !matches!(x.kind, NodeKind::RequireStatement { .. })).collect();
                Some(self.child(s, &body, false))
            }
            (NodeKind::LambdaExpression { body, .. }, Some(s)) => Some(self.child(s, &[&**body], true)),
            _ => None,
        };
        let node = self.cold(n);
        match child {
            Some(c) => {
                self.children.push(c);
                let child = (self.children.len() - 1) as u32;
                self.emit(Ins::Define { dst, node, child });
            }
            None => {
                self.emit(Ins::Exec { dst, node });
            }
        }
    }

    fn child(&mut self, scope: ScopeId, body: &[&Node], lambda: bool) -> Rc<Chunk> {
        let mut c = Compiler::new(self.res, self.shared, Some(scope));
        if lambda {
            // El cuerpo de una lambda es un bloque de una sentencia, el `give <expr>` que arma el
            // intérprete: el chequeo de cancelación del bloque y un nodo más.
            let e = body[0];
            c.at(&e.location);
            c.emit(Ins::CheckCancel);
            c.enter();
            let v = c.expr(e);
            c.at(&e.location);
            c.emit(Ins::Give { src: v });
            return c.finish(Opnd::Reg(0));
        }
        c.block_of(body, Some(0), true);
        c.finish(Opnd::Reg(0))
    }

    // -- expresiones ----------------------------------------------------------------------------

    fn expr(&mut self, n: &Node) -> Opnd {
        self.expr_in(n, None)
    }

    /// El registro destino: el pedido (el lugar de un argumento o de un elemento) o uno nuevo.
    fn dst(&mut self, want: Option<Reg>) -> Reg {
        want.unwrap_or_else(|| self.reg())
    }

    /// Compila una expresión dejando su valor, si va a un registro, en `want` (si lo hay): una VM
    /// de registros escribe cada resultado donde se lo va a usar, sin un `Move` después (L4).
    /// Constantes y slots ligados seguro siguen siendo operandos.
    fn expr_in(&mut self, n: &Node, want: Option<Reg>) -> Opnd {
        use NodeKind as K;
        self.at(&n.location);
        match &n.kind {
            K::NumberLiteral { value } => {
                self.enter();
                Opnd::Const(self.konst(syn_number(value.clone())))
            }
            K::BoolLiteral { value } => {
                self.enter();
                Opnd::Const(self.konst(syn_bool(*value)))
            }
            K::NothingLiteral => {
                self.enter();
                Opnd::Const(self.konst(SynValue::Nothing))
            }
            K::TextLiteral { value } => {
                // Del pool (L7, ex F1.8): evaluarlo suma una referencia. Un texto nunca se modifica
                // en el lugar, así que compartirlo no se ve.
                self.enter();
                Opnd::Const(self.konst(syn_text(value.as_str())))
            }
            K::ListLiteral { elements } => {
                self.enter();
                let first = self.block_regs(elements.len());
                for (i, e) in elements.iter().enumerate() {
                    self.into_reg(e, first + i as Reg, first + elements.len() as Reg);
                }
                self.at(&n.location);
                let dst = self.dst(want);
                self.emit(Ins::MakeList { dst, first, n: elements.len() as u16 });
                Opnd::Reg(dst)
            }
            K::MapLiteral { pairs } => {
                self.enter();
                let first = self.block_regs(2 * pairs.len());
                let end = first + 2 * pairs.len() as Reg;
                for (i, (k, v)) in pairs.iter().enumerate() {
                    self.into_reg(k, first + 2 * i as Reg, end);
                    self.into_reg(v, first + 2 * i as Reg + 1, end);
                }
                self.at(&n.location);
                let dst = self.dst(want);
                self.emit(Ins::MakeMap { dst, first, n: pairs.len() as u16 });
                Opnd::Reg(dst)
            }
            // `a of b.c`: si leer `b.c` falla con "Map has no key", la referencia agrega una nota
            // sobre la precedencia de `of`. Raro: lo corre ella.
            K::PropertyAccess { object, via_of: true, .. } if matches!(object.kind, K::PropertyAccess { .. }) => {
                self.exec_expr(n, want)
            }
            K::PropertyAccess { property_name, object, .. } => {
                self.enter();
                let o = self.expr(object);
                self.at(&n.location);
                let name = self.name(property_name);
                let dst = self.dst(want);
                self.emit(Ins::GetProp { dst, obj: o, name });
                Opnd::Reg(dst)
            }
            K::IndexAccess { object, index } => {
                self.enter();
                let o = self.expr(object);
                let o = self.keep_until(o, index);
                let i = self.expr(index);
                self.at(&n.location);
                let dst = self.dst(want);
                self.emit(Ins::GetIndex { dst, obj: o, idx: i });
                Opnd::Reg(dst)
            }
            K::PipeExpression { value, transforms } => {
                self.enter();
                let v = self.expr(value);
                let mut cur = self.to_reg(v);
                for (ti, t) in transforms.iter().enumerate() {
                    let dst = if ti + 1 == transforms.len() { self.dst(want) } else { self.reg() };
                    match &t.kind {
                        // `xs |> f(a)` = `f(xs, a)`: la referencia no cuenta el nodo de la llamada
                        // (`exec_call_with_first` evalúa el nombre y los argumentos).
                        K::TaskCall { name, arguments } => self.call_with(t, name, arguments, Some(cur), dst, true),
                        _ => {
                            let f = self.expr(t);
                            let func = self.to_reg(f);
                            let first = self.block_regs(1);
                            self.emit(Ins::Move { dst: first, src: Opnd::Reg(cur) });
                            self.sites.push(CallSite { names: None, checked: false });
                            let site = (self.sites.len() - 1) as u32;
                            self.at(&t.location);
                            self.emit(Ins::Call { dst, func, args: first, n: 1, site });
                        }
                    }
                    cur = dst;
                }
                Opnd::Reg(cur)
            }
            K::Identifier { name } => {
                self.enter();
                let nm = self.name(name);
                match self.target(n) {
                    Target::Slot { depth: 0, scope, slot, definite: true } if self.in_frame(scope, 0) => {
                        Opnd::Local(slot)
                    }
                    Target::Slot { depth: 0, scope, slot, .. } if self.in_frame(scope, 0) => {
                        let dst = self.dst(want);
                        self.emit(Ins::LoadLocal { dst, slot, name: nm });
                        Opnd::Reg(dst)
                    }
                    Target::Slot { depth, scope, slot, .. } if self.in_frame(scope, depth) => {
                        let dst = self.dst(want);
                        let at = self.hops_here();
                        self.emit(Ins::LoadOuter { dst, depth, slot, name: nm, at });
                        Opnd::Reg(dst)
                    }
                    _ => {
                        let dst = self.dst(want);
                        let ic = self.ic();
                        self.emit(Ins::LoadName { dst, name: nm, ic });
                        Opnd::Reg(dst)
                    }
                }
            }
            K::BinaryOp { left, operator, right } if matches!(operator, BinOp::And | BinOp::Or) => {
                self.enter();
                let l = self.expr(left);
                self.at(&n.location);
                let dst = self.dst(want);
                let short = self.label();
                let end = self.label();
                if *operator == BinOp::And {
                    self.emit(Ins::JumpIfFalsy { src: l, to: short });
                } else {
                    // `or`: si el lado izquierdo es verdadero, `true` sin evaluar el derecho.
                    self.emit(Ins::ToBool { dst, src: l });
                    self.emit(Ins::JumpIfFalsy { src: Opnd::Copy(dst), to: short });
                    let k = self.konst(syn_bool(true));
                    self.emit(Ins::Const { dst, k });
                    self.emit(Ins::Jump { to: end });
                    self.bind(short);
                    let r = self.expr(right);
                    self.at(&n.location);
                    self.emit(Ins::ToBool { dst, src: r });
                    self.bind(end);
                    return Opnd::Reg(dst);
                }
                let r = self.expr(right);
                self.at(&n.location);
                self.emit(Ins::ToBool { dst, src: r });
                self.emit(Ins::Jump { to: end });
                self.bind(short);
                let k = self.konst(syn_bool(false));
                self.emit(Ins::Const { dst, k });
                self.bind(end);
                Opnd::Reg(dst)
            }
            K::BinaryOp { operator, right, .. } if *operator == BinOp::FloorDiv && floor_div_hint(n, right) => {
                self.exec_expr(n, want)
            }
            K::BinaryOp { left, operator, right } => {
                self.enter();
                let a = self.expr(left);
                let a = self.keep_until(a, right);
                let b = self.expr(right);
                self.at(&n.location);
                let dst = self.dst(want);
                let fb = self.feedback;
                self.feedback = self.feedback.saturating_add(1);
                self.emit(Ins::Binary { dst, op: *operator, a, b, fb });
                Opnd::Reg(dst)
            }
            K::UnaryOp { operator, operand } => {
                self.enter();
                let a = self.expr(operand);
                self.at(&n.location);
                let dst = self.dst(want);
                self.emit(Ins::Unary { dst, op: *operator, a });
                Opnd::Reg(dst)
            }
            K::CompareChain { operands, operators } => {
                self.enter();
                let dst = self.dst(want);
                let fail = self.label();
                let end = self.label();
                let mut prev = self.expr(&operands[0]);
                for (i, (op, node)) in operators.iter().zip(operands[1..].iter()).enumerate() {
                    prev = self.keep_until(prev, node);
                    let cur = self.expr(node);
                    let cur = self.to_reg(cur);
                    self.at(&n.location);
                    let fb = self.feedback;
                    self.feedback = self.feedback.saturating_add(1);
                    self.emit(Ins::Binary { dst, op: *op, a: prev, b: Opnd::Copy(cur), fb });
                    self.emit(Ins::JumpIfFalsy { src: Opnd::Copy(dst), to: fail });
                    if i + 1 == operators.len() {
                        self.emit(Ins::Drop { r: cur });
                    }
                    prev = Opnd::Reg(cur);
                }
                self.emit(Ins::Jump { to: end });
                self.bind(fail);
                // Cortó en un par falso: el operando que quedó se suelta, como en la referencia.
                if let Opnd::Reg(r) = prev {
                    self.emit(Ins::Drop { r });
                }
                let k = self.konst(syn_bool(false));
                self.emit(Ins::Const { dst, k });
                self.bind(end);
                Opnd::Reg(dst)
            }
            K::LambdaExpression { .. } => {
                let dst = self.dst(want);
                self.define(n, dst);
                Opnd::Reg(dst)
            }
            K::TaskCall { .. } => {
                let dst = self.dst(want);
                self.call(n, dst);
                Opnd::Reg(dst)
            }
            _ => self.exec_expr(n, want),
        }
    }

    /// Una llamada: el nodo, la función, los argumentos en orden (como la referencia) y `Call`.
    fn call(&mut self, n: &Node, dst: Reg) {
        let NodeKind::TaskCall { name, arguments } = &n.kind else { unreachable!() };
        self.enter();
        self.call_with(n, name, arguments, None, dst, true);
    }

    /// La función, el chequeo de los protegidos (antes de los argumentos, como la referencia), un
    /// primer argumento ya evaluado si lo hay (un pipe), los argumentos y `Call`.
    fn call_with(&mut self, n: &Node, name: &Node, arguments: &[crate::ast::Arg], first_arg: Option<Reg>, dst: Reg, checked: bool) {
        let f = self.expr(name);
        let func = self.to_reg(f);
        if let Some(id) = name.as_identifier().filter(|id| PROTECTED_BUILTIN_NAMES.contains(id)) {
            let nm = self.name(id);
            self.at(&n.location);
            self.emit(Ins::CheckProtected { func, name: nm });
        }
        let lead = usize::from(first_arg.is_some());
        let total = lead + arguments.len();
        let first = self.block_regs(total);
        let end = first + total as Reg;
        if let Some(r) = first_arg {
            self.emit(Ins::Move { dst: first, src: Opnd::Reg(r) });
        }
        for (i, a) in arguments.iter().enumerate() {
            self.into_reg(&a.value, first + (lead + i) as Reg, end);
        }
        let names = if arguments.iter().any(|a| a.name.is_some()) {
            let mut v: Vec<Option<String>> = Vec::with_capacity(total);
            if lead == 1 {
                v.push(None);
            }
            v.extend(arguments.iter().map(|a| a.name.clone()));
            Some(v.into_boxed_slice())
        } else {
            None
        };
        self.sites.push(CallSite { names, checked });
        let site = (self.sites.len() - 1) as u32;
        self.at(&n.location);
        self.emit(Ins::Call { dst, func, args: first, n: total as u16, site });
    }

    /// `n` registros seguidos (para argumentos o elementos) y los temporales después.
    fn block_regs(&mut self, n: usize) -> Reg {
        let first = self.next_reg;
        for _ in 0..n {
            self.reg();
        }
        first
    }

    /// Evalúa `e` y deja su valor en el registro `slot`; los temporales se liberan hasta `end`.
    fn into_reg(&mut self, e: &Node, slot: Reg, end: Reg) {
        let v = self.expr_in(e, Some(slot));
        if v != Opnd::Reg(slot) {
            self.emit(Ins::Move { dst: slot, src: v });
        }
        self.next_reg = end;
    }



    fn exec_expr(&mut self, n: &Node, want: Option<Reg>) -> Opnd {
        let dst = self.dst(want);
        let node = self.cold(n);
        self.emit(Ins::Exec { dst, node });
        Opnd::Reg(dst)
    }

    /// Un slot leído como operando se lee cuando lo usa la instrucción. Si entre la lectura (en el
    /// orden de la referencia) y el uso se evalúa algo que puede cambiar variables (una llamada,
    /// un nodo del tree-walker), se copia a un registro en su lugar.
    fn keep_until(&mut self, a: Opnd, later: &Node) -> Opnd {
        match a {
            Opnd::Local(_) if !is_simple(later) => Opnd::Reg(self.to_reg(a)),
            _ => a,
        }
    }

    fn to_reg(&mut self, a: Opnd) -> Reg {
        match a {
            Opnd::Reg(r) => r,
            other => {
                let dst = self.reg();
                self.emit(Ins::Move { dst, src: other });
                dst
            }
        }
    }

    // -- ensamblado -----------------------------------------------------------------------------

    fn finish(mut self, result: Opnd) -> Rc<Chunk> {
        self.flush();
        self.emit(Ins::End { src: result });
        let n = self.code.len();
        let target = |labels: &Vec<u32>, l: u32| labels[l as usize] as usize;
        // Bloques básicos: empiezan en 0, en cada destino de salto y después de cada instrucción
        // que salta, sale o puede mirar el contador.
        let mut leader = vec![false; n + 1];
        leader[0] = true;
        for (i, ins) in self.code.iter().enumerate() {
            match *ins {
                Ins::Jump { to } | Ins::JumpIfFalsy { to, .. } => {
                    leader[target(&self.labels, to)] = true;
                    leader[i + 1] = true;
                }
                Ins::TryInPlace { done, .. } => {
                    leader[target(&self.labels, done)] = true;
                    leader[i + 1] = true;
                }
                Ins::SetPath { .. } => leader[i + 1] = true,
                Ins::EachNext { exit, .. } => {
                    leader[target(&self.labels, exit)] = true;
                    leader[i + 1] = true;
                }
                Ins::MatchArm { fail, .. } => {
                    leader[target(&self.labels, fail)] = true;
                    leader[i + 1] = true;
                }
                Ins::EachStep { head } => {
                    leader[target(&self.labels, head)] = true;
                    leader[i + 1] = true;
                }
                Ins::EachInit { .. } => leader[i + 1] = true,
                Ins::Exec { .. } | Ins::Call { .. } => leader[i + 1] = true,
                Ins::Define { .. } | Ins::Give { .. } | Ins::StopOut { .. } | Ins::End { .. } => leader[i + 1] = true,
                _ => {}
            }
        }
        // Lo que sobra si falla la instrucción i: los pesos de las que siguen en su bloque.
        let mut rest = vec![0u32; n];
        let mut acc = 0u32;
        for i in (0..n).rev() {
            rest[i] = acc;
            acc = if leader[i] { 0 } else { acc + self.weight[i] };
        }
        let mut new_index = vec![0u32; n + 1];
        let mut code = Vec::with_capacity(n);
        let mut new_rest = Vec::with_capacity(n);
        let mut new_loc = Vec::with_capacity(n);
        let mut new_stop = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            // Un bloque: suma sus pesos en su primera instrucción.
            let mut j = i + 1;
            while j < n && !leader[j] {
                j += 1;
            }
            let total: u32 = self.weight[i..j].iter().sum();
            let start = code.len() as u32;
            if total > 0 {
                code.push(Ins::Steps(total));
                new_rest.push(0);
                new_loc.push(self.loc[i]);
                new_stop.push(NONE);
            }
            for k in i..j {
                // Un salto al comienzo del bloque cae en su `Steps`.
                new_index[k] = if k == i { start } else { code.len() as u32 };
                if matches!(self.code[k], Ins::Nop) {
                    continue;
                }
                code.push(self.code[k]);
                new_rest.push(rest[k]);
                new_loc.push(self.loc[k]);
                new_stop.push(self.stop_of[k]);
            }
            i = j;
        }
        new_index[n] = code.len() as u32;
        let map = |l: u32, labels: &Vec<u32>| new_index[labels[l as usize] as usize];
        for ins in code.iter_mut() {
            match ins {
                Ins::Jump { to } | Ins::JumpIfFalsy { to, .. } => *to = map(*to, &self.labels),
                Ins::TryInPlace { done, .. } => *done = map(*done, &self.labels),
                Ins::EachNext { exit, .. } => *exit = map(*exit, &self.labels),
                Ins::MatchArm { fail, .. } => *fail = map(*fail, &self.labels),
                Ins::EachStep { head } => *head = map(*head, &self.labels),
                _ => {}
            }
        }
        for t in new_stop.iter_mut() {
            if *t != NONE {
                *t = map(*t, &self.labels);
            }
        }
        let loop_heads = self.loop_heads.iter().map(|&l| map(l, &self.labels)).collect();
        let frame = self.frame_scope.map(|s| self.shared.layouts[s as usize].clone());
        let tagged = !self.children.is_empty();
        Rc::new(Chunk {
            code,
            rest: new_rest,
            stop_to: new_stop,
            loc: new_loc,
            locs: self.locs,
            consts: self.consts,
            names: self.names,
            nodes: self.nodes,
            children: self.children,
            sites: self.sites,
            layouts: self.shared.layouts.clone(),
            parents: self.shared.parents.clone(),
            tagged,
            frame,
            nregs: self.max_reg,
            ics: (0..self.ics).map(|_| Cell::new(0)).collect(),
            ic_hops: self.ic_hops,
            hops: self.hops,
            feedback: self.feedback,
            loop_heads,
        })
    }
}

/// Sentencias que son expresiones (su valor es el del bloque si van últimas).
fn is_expression(k: &NodeKind) -> bool {
    use NodeKind as K;
    matches!(
        k,
        K::NumberLiteral { .. }
            | K::TextLiteral { .. }
            | K::BoolLiteral { .. }
            | K::NothingLiteral
            | K::Identifier { .. }
            | K::BinaryOp { .. }
            | K::UnaryOp { .. }
            | K::CompareChain { .. }
            | K::LambdaExpression { .. }
            | K::ListLiteral { .. }
            | K::MapLiteral { .. }
            | K::PropertyAccess { .. }
            | K::IndexAccess { .. }
            | K::PipeExpression { .. }
    )
}

/// No llama a nada ni corre nada en el tree-walker: no puede cambiar una variable.
fn is_simple(n: &Node) -> bool {
    use NodeKind as K;
    match &n.kind {
        K::NumberLiteral { .. } | K::TextLiteral { .. } | K::BoolLiteral { .. } | K::NothingLiteral | K::Identifier { .. } => true,
        K::BinaryOp { left, operator, right } => {
            !(*operator == BinOp::FloorDiv && floor_div_hint(n, right)) && is_simple(left) && is_simple(right)
        }
        K::UnaryOp { operand, .. } => is_simple(operand),
        K::CompareChain { operands, .. } => operands.iter().all(is_simple),
        K::ListLiteral { elements } => elements.iter().all(is_simple),
        K::MapLiteral { pairs } => pairs.iter().all(|(k, v)| is_simple(k) && is_simple(v)),
        K::PropertyAccess { object, via_of, .. } => !*via_of && is_simple(object),
        K::IndexAccess { object, index } => is_simple(object) && is_simple(index),
        _ => false,
    }
}

/// `x // nota` con espacio: la referencia agrega un aviso al error de variable indefinida.
fn floor_div_hint(n: &Node, right: &Node) -> bool {
    matches!(right.kind, NodeKind::Identifier { .. })
        && right.location.line == n.location.line
        && right.location.column > n.location.column + 2
}

/// Las formas que `try_update_in_place` puede hacer en el lugar (la función vuelve a chequear
/// todo; esto sólo evita llamarla cuando no puede aplicar).
fn in_place_shape(target: &Node, value: &Node) -> bool {
    match &value.kind {
        NodeKind::TaskCall { name, arguments } => {
            matches!(name.as_identifier(), Some("append" | "insert" | "merge"))
                && !arguments.is_empty()
                && same_place(&arguments[0].value, target)
        }
        NodeKind::BinaryOp { left, operator, .. } => *operator == BinOp::Add && same_place(left, target),
        _ => false,
    }
}

// =============================================================================================
// Ejecución
// =============================================================================================

impl Interpreter {
    /// El código de una task para esta llamada, si la VM la corre: compilado al definirla desde
    /// código compilado, o acá en su segunda llamada.
    #[inline]
    pub(super) fn vm_code_for<'t>(&mut self, task: &'t SynTaskValue) -> Option<&'t Rc<Chunk>> {
        if !self.shortcuts || self.labels {
            return None;
        }
        if let Some(c) = task.code.get() {
            return Some(c);
        }
        self.compile_task(task)
    }

    #[inline(never)]
    fn compile_task<'t>(&mut self, task: &'t SynTaskValue) -> Option<&'t Rc<Chunk>> {
        let n = task.code.calls.get() + 1;
        task.code.calls.set(n);
        if n < COMPILE_AT_CALL {
            return None;
        }
        let params: Vec<Arc<str>> = task.parameters.iter().map(|p| p.name.clone()).collect();
        task.code.set(compile_function(&params, &task.body));
        task.code.get()
    }

    /// El programa por la VM (sentencias después del preámbulo).
    pub(super) fn run_program_chunk(&mut self, stmts: &[Node], env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let chunk = compile_program(stmts);
        self.run_chunk(&chunk, env)
    }

    /// Corre un chunk en `env` (el frame de la llamada, ya preparado, o la raíz del programa).
    /// Devuelve lo mismo que `exec_block` sobre ese cuerpo.
    pub(super) fn run_chunk(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        // Los slots `Local` sólo valen en el frame que la llamada preparó con el layout del chunk.
        debug_assert!(chunk.frame.as_ref().is_none_or(|l| {
            let e = env.borrow();
            e.bindings.len_names() >= l.names.len() && (!chunk.tagged || e.bindings.laid_out_as(l))
        }));
        let base = self.vm_regs.len();
        self.vm_regs.resize(base + chunk.nregs as usize, SynValue::Nothing);
        let r = self.run_chunk_at(chunk, env, base);
        self.vm_regs.truncate(base);
        r
    }

    #[inline]
    fn put(&mut self, base: usize, dst: Reg, v: SynValue) {
        if dst != DISCARD {
            self.vm_regs[base + dst as usize] = v;
        }
    }

    #[inline]
    fn opnd(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, o: Opnd, at: usize) -> Result<SynValue, Control> {
        Ok(match o {
            Opnd::Reg(r) => std::mem::replace(&mut self.vm_regs[base + r as usize], SynValue::Nothing),
            Opnd::Copy(r) => self.vm_regs[base + r as usize].clone(),
            Opnd::Const(k) => chunk.consts[k as usize].clone(),
            Opnd::Local(k) => {
                let v = env.borrow().bindings.slot(k as usize).cloned();
                match v {
                    Some(v) => v,
                    // Ligado seguro según el resolver: no pasa. Si pasara, por nombre.
                    None => {
                        let name = env.borrow().bindings.slot_name(k as usize);
                        return self.load_by_name_from_parent(env, &name, Some(&chunk.locs[chunk.loc[at] as usize]));
                    }
                }
            }
        })
    }

    fn load_by_name_from_parent(
        &mut self,
        frame: &Rc<RefCell<Environment>>,
        name: &str,
        loc: Option<&SourceLocation>,
    ) -> Result<SynValue, Control> {
        let parent = frame.borrow().parent.clone();
        match parent.and_then(|p| env_get(&p, name)) {
            Some(v) => Ok(v),
            None => Err(match loc {
                Some(l) => undefined_variable(name, l),
                None => err(format!("Undefined variable: '{}'", name)),
            }),
        }
    }

    /// Dónde empieza la búsqueda de una variable `Free`: pasando los frames del resolver (que no
    /// la tienen: el oráculo del resolver lo verifica en todo el corpus). Los de este cuerpo los
    /// preparó la VM; los de afuera se verifican por su `Layout`, y si alguno no es el que el
    /// resolver vio, se busca desde el frame actual.
    fn free_start(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, h: Hops) -> Rc<RefCell<Environment>> {
        let Some(mut s) = h.from else { return env.clone() };
        let mut f = env.clone();
        for i in 0..h.skip {
            if i >= h.inner && !f.borrow().bindings.laid_out_as(&chunk.layouts[s as usize]) {
                return env.clone();
            }
            let Some(p) = f.borrow().parent.clone() else { return env.clone() };
            f = p;
            if i + 1 < h.skip {
                match chunk.parents[s as usize] {
                    Some(x) => s = x,
                    None => return env.clone(),
                }
            }
        }
        f
    }

    /// Una variable `Free`: en el primer frame de la búsqueda, por la caché; si no está ahí, por
    /// nombre hacia afuera (lo mismo que `env_get`).
    fn load_free(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, name: u32, ic: u32) -> Option<SynValue> {
        let nm = &chunk.names[name as usize];
        let start = self.free_start(chunk, env, chunk.hops[chunk.ic_hops[ic as usize] as usize]);
        let parent = {
            let e = start.borrow();
            if let Some(v) = e.bindings.get_cached(nm, &chunk.ics[ic as usize]) {
                return Some(v.clone());
            }
            e.parent.clone()
        };
        parent.and_then(|p| env_get(&p, nm))
    }

    /// `set` a una variable `Free`: lo mismo que `env_update` desde el primer frame de la búsqueda.
    fn set_free(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, name: u32, ic: u32, v: SynValue) -> bool {
        let nm = &chunk.names[name as usize];
        let start = self.free_start(chunk, env, chunk.hops[chunk.ic_hops[ic as usize] as usize]);
        // Un módulo sincroniza su mapa de exportaciones: por el camino de siempre.
        if start.borrow().name.starts_with("module:") {
            return env_update(&start, nm, v).is_ok();
        }
        let parent = {
            let mut e = start.borrow_mut();
            if let Some(slot) = e.bindings.get_cached_mut(nm, &chunk.ics[ic as usize]) {
                *slot = v;
                return true;
            }
            e.parent.clone()
        };
        parent.is_some_and(|p| env_update(&p, nm, v).is_ok())
    }

    /// El frame `depth` niveles afuera, si cada frame del camino es el que el resolver vio (los de
    /// este cuerpo los preparó la VM; los de afuera se verifican por su `Layout`).
    fn guarded_frame(
        &self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        depth: u16,
        h: Hops,
    ) -> Option<Rc<RefCell<Environment>>> {
        let mut f = env.clone();
        let mut s = h.from?;
        for i in 0..depth {
            if i >= h.inner && !f.borrow().bindings.laid_out_as(&chunk.layouts[s as usize]) {
                return None;
            }
            let p = f.borrow().parent.clone()?;
            f = p;
            s = chunk.parents[s as usize]?;
        }
        if depth >= h.inner && !f.borrow().bindings.laid_out_as(&chunk.layouts[s as usize]) {
            return None;
        }
        Some(f)
    }

    fn run_chunk_at(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>, base: usize) -> Result<SynValue, Control> {
        // El chunk, el frame y la ventana de registros cambian al entrar a una llamada y al volver
        // (F3.2); `entry` es cuántas llamadas de la VM había al empezar: las de arriba son nuestras.
        let mut chunk = chunk.clone();
        let mut env = env.clone();
        let mut base = base;
        let entry = self.vm_frames.len();
        let mut pc = 0usize;
        // Frames de la VM abiertos dentro de este cuerpo (vueltas de `each`, brazos de `match`) y
        // dónde empiezan sus iteradores.
        let mut depth: u16 = 0;
        let mut iter_base = self.vm_iters.len();
        let entry_iters = iter_base;
        loop {
            let at = pc;
            let ins = chunk.code[at];
            pc += 1;
            let out: Result<(), Control> = match ins {
                Ins::Steps(w) => {
                    self.steps = self.steps.wrapping_add(w as u64);
                    Ok(())
                }
                Ins::Nop => Ok(()),
                Ins::CheckCancel => {
                    if self.cancel.flag.load(std::sync::atomic::Ordering::Relaxed) {
                        self.check_cancel()
                    } else {
                        Ok(())
                    }
                }
                Ins::Const { dst, k } => {
                    let v = chunk.consts[k as usize].clone();
                    self.put(base, dst, v);
                    Ok(())
                }
                Ins::MakeList { dst, first, n } => {
                    let from = base + first as usize;
                    let items: Vec<SynValue> = (0..n as usize)
                        .map(|i| std::mem::replace(&mut self.vm_regs[from + i], SynValue::Nothing))
                        .collect();
                    self.put(base, dst, syn_list(items));
                    Ok(())
                }
                Ins::MakeMap { dst, first, n } => {
                    let from = base + first as usize;
                    let mut m = IndexMap::with_capacity(n as usize);
                    for i in 0..n as usize {
                        let k = std::mem::replace(&mut self.vm_regs[from + 2 * i], SynValue::Nothing);
                        let v = std::mem::replace(&mut self.vm_regs[from + 2 * i + 1], SynValue::Nothing);
                        m.insert(k.to_string(), v);
                    }
                    self.put(base, dst, syn_map(m));
                    Ok(())
                }
                Ins::GetProp { dst, obj, name } => (|| {
                    let o = self.opnd(&chunk, &env, base, obj, at)?;
                    let v = self.property_read(o, &chunk.names[name as usize], &chunk.locs[chunk.loc[at] as usize])?;
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::GetIndex { dst, obj, idx } => (|| {
                    let o = self.opnd(&chunk, &env, base, obj, at)?;
                    let i = self.opnd(&chunk, &env, base, idx, at)?;
                    let v = self.index_read(o, i, &chunk.locs[chunk.loc[at] as usize])?;
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::SetPath { src, node, dst } => self.vm_set_path(&chunk, &env, base, src, node, dst, at),
                Ins::CheckProtected { func, name } => check_protected_callee(
                    &chunk.names[name as usize],
                    &self.vm_regs[base + func as usize],
                    &chunk.locs[chunk.loc[at] as usize],
                ),
                Ins::Move { dst, src } => self.opnd(&chunk, &env, base, src, at).map(|v| self.put(base, dst, v)),
                Ins::Drop { r } => {
                    drop(std::mem::replace(&mut self.vm_regs[base + r as usize], SynValue::Nothing));
                    Ok(())
                }
                Ins::LoadLocal { dst, slot, name } => {
                    let v = env.borrow().bindings.slot(slot as usize).cloned();
                    match v {
                        Some(v) => {
                            self.put(base, dst, v);
                            Ok(())
                        }
                        None => {
                            let loc = &chunk.locs[chunk.loc[at] as usize];
                            self.load_by_name_from_parent(&env, &chunk.names[name as usize], Some(loc))
                                .map(|v| self.put(base, dst, v))
                        }
                    }
                }
                Ins::LoadOuter { dst, depth, slot, name, at: h } => {
                    let nm = &chunk.names[name as usize];
                    let loc = &chunk.locs[chunk.loc[at] as usize];
                    let found = match self.guarded_frame(&chunk, &env, depth, chunk.hops[h as usize]) {
                        Some(f) => {
                            let v = f.borrow().bindings.slot(slot as usize).cloned();
                            match v {
                                Some(v) => Some(v),
                                None => f.borrow().parent.clone().and_then(|p| env_get(&p, nm)),
                            }
                        }
                        None => env_get(&env, nm),
                    };
                    match found {
                        Some(v) => {
                            self.put(base, dst, v);
                            Ok(())
                        }
                        None => Err(undefined_variable(nm, loc)),
                    }
                }
                Ins::LoadName { dst, name, ic } => match self.load_free(&chunk, &env, name, ic) {
                    Some(v) => {
                        self.put(base, dst, v);
                        Ok(())
                    }
                    None => Err(undefined_variable(&chunk.names[name as usize], &chunk.locs[chunk.loc[at] as usize])),
                },
                Ins::Binary { dst, op, a, b, .. } => (|| {
                    let a = self.opnd(&chunk, &env, base, a, at)?;
                    let b = self.opnd(&chunk, &env, base, b, at)?;
                    let v = self.exec_binary(a, op, b, &chunk.locs[chunk.loc[at] as usize])?;
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::Unary { dst, op, a } => (|| {
                    let a = self.opnd(&chunk, &env, base, a, at)?;
                    let v = self.exec_unary(op, a, &chunk.locs[chunk.loc[at] as usize])?;
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::ToBool { dst, src } => self.opnd(&chunk, &env, base, src, at).map(|v| self.put(base, dst, syn_bool(v.is_truthy()))),
                Ins::Jump { to } => {
                    pc = to as usize;
                    Ok(())
                }
                Ins::JumpIfFalsy { src, to } => self.opnd(&chunk, &env, base, src, at).map(|v| {
                    if !v.is_truthy() {
                        pc = to as usize;
                    }
                }),
                Ins::LetLocal { src, slot, dst } => self.opnd(&chunk, &env, base, src, at).map(|v| {
                    if dst == DISCARD {
                        env.borrow_mut().bindings.slot_set(slot as usize, v);
                    } else {
                        env.borrow_mut().bindings.slot_set(slot as usize, v.clone());
                        self.put(base, dst, v);
                    }
                }),
                Ins::LetName { src, name, dst } => self.opnd(&chunk, &env, base, src, at).map(|v| {
                    env_set_shared(&env, &chunk.names[name as usize], v.clone());
                    self.put(base, dst, v);
                }),
                Ins::SetLocal { src, slot, name, dst } => (|| {
                    let v = self.opnd(&chunk, &env, base, src, at)?;
                    let present = env.borrow().bindings.slot(slot as usize).is_some();
                    if present {
                        env.borrow_mut().bindings.slot_set(slot as usize, v.clone());
                    } else {
                        let parent = env.borrow().parent.clone();
                        let nm = &chunk.names[name as usize];
                        if parent.map(|p| env_update(&p, nm, v.clone())).unwrap_or(Err(())).is_err() {
                            return Err(set_undefined(nm));
                        }
                    }
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::SetOuter { src, depth, slot, name, dst, at: h } => (|| {
                    let v = self.opnd(&chunk, &env, base, src, at)?;
                    let nm = &chunk.names[name as usize];
                    let ok = match self.guarded_frame(&chunk, &env, depth, chunk.hops[h as usize]) {
                        Some(f) => {
                            let present = f.borrow().bindings.slot(slot as usize).is_some();
                            if present {
                                f.borrow_mut().bindings.slot_set(slot as usize, v.clone());
                                true
                            } else {
                                let parent = f.borrow().parent.clone();
                                parent.map(|p| env_update(&p, nm, v.clone()).is_ok()).unwrap_or(false)
                            }
                        }
                        None => env_update(&env, nm, v.clone()).is_ok(),
                    };
                    if !ok {
                        return Err(set_undefined(nm));
                    }
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::SetName { src, name, dst, ic } => (|| {
                    let v = self.opnd(&chunk, &env, base, src, at)?;
                    if !self.set_free(&chunk, &env, name, ic, v.clone()) {
                        return Err(set_undefined(&chunk.names[name as usize]));
                    }
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::TryInPlace { dst, node, name, done, ic } => match self.vm_try_in_place(&chunk, &env, base, dst, node, name, ic) {
                    Ok(true) => {
                        pc = done as usize;
                        Ok(())
                    }
                    Ok(false) => Ok(()),
                    Err(c) => Err(c),
                },
                Ins::Exec { dst, node } => self.exec(&chunk.nodes[node as usize], &env).map(|v| self.put(base, dst, v)),
                Ins::Call { dst, func, args, n, site } => {
                    match self.vm_call(&chunk, base, at, dst, func, args, n, site) {
                        Ok(None) => Ok(()),
                        Ok(Some(enter)) => {
                            // Entra al cuerpo: el llamador queda en la pila de la VM.
                            let caller = VmFrame {
                                chunk: std::mem::replace(&mut chunk, enter.code),
                                env: std::mem::replace(&mut env, enter.env),
                                base,
                                pc,
                                dst,
                                depth: std::mem::replace(&mut depth, 0),
                                iter_base: std::mem::replace(&mut iter_base, self.vm_iters.len()),
                                taint: enter.taint,
                                task: enter.task,
                            };
                            self.vm_frames.push(caller);
                            base = enter.base;
                            pc = 0;
                            Ok(())
                        }
                        Err(c) => Err(c),
                    }
                }
                Ins::EachInit { node, it } => self.vm_each_init(&chunk, &env, node, it, iter_base),
                Ins::EachNext { it, var, scope, exit } => {
                    match self.vm_iters[iter_base + it as usize].next_item() {
                        None => pc = exit as usize,
                        Some(item) => {
                            let loop_env = self.acquire_frame(&env, "each");
                            env_set_shared(&loop_env, &chunk.names[var as usize], item);
                            loop_env.borrow_mut().bindings.lay_out(&chunk.layouts[scope as usize], chunk.tagged);
                            env = loop_env;
                            depth += 1;
                        }
                    }
                    Ok(())
                }
                Ins::EachStep { head } => {
                    let parent = env.borrow().parent.clone().expect("vuelta sin padre");
                    let loop_env = std::mem::replace(&mut env, parent);
                    depth -= 1;
                    self.release_frame(loop_env);
                    pc = head as usize;
                    Ok(())
                }
                Ins::EachEnd { it } => {
                    self.vm_iters.truncate(iter_base + it as usize);
                    Ok(())
                }
                Ins::Unwind { depth: to } => {
                    while depth > to {
                        let parent = env.borrow().parent.clone().expect("frame sin padre");
                        env = parent;
                        depth -= 1;
                    }
                    Ok(())
                }
                Ins::MatchArm { subj, node, scope, fail } => match self.vm_match_arm(&chunk, &env, base, subj, node, scope) {
                    Ok(Some(arm_env)) => {
                        env = arm_env;
                        depth += 1;
                        Ok(())
                    }
                    Ok(None) => {
                        pc = fail as usize;
                        Ok(())
                    }
                    Err(c) => Err(c),
                },
                Ins::Define { dst, node, child } => self.vm_define(&chunk, &env, base, dst, node, child),
                Ins::Give { src } => match self.opnd(&chunk, &env, base, src, at) {
                    Ok(v) => Err(Control::Give(v)),
                    Err(c) => Err(c),
                },
                Ins::StopOut { src, has } => match self.opnd(&chunk, &env, base, src, at) {
                    Ok(v) => Err(Control::Stop(if has { Some(v) } else { None })),
                    Err(c) => Err(c),
                },
                Ins::End { src } => match self.opnd(&chunk, &env, base, src, at) {
                    // El valor del cuerpo: el de la última sentencia.
                    Ok(v) => Err(Control::Give(v)),
                    Err(c) => Err(c),
                },
                Ins::WasmTick { ctr } => self.vm_wasm_tick(&chunk, base, ctr, at),
            };
            let Err(mut c) = out else { continue };
            // Los pasos que el bloque sumó por adelantado y la referencia no llegó a contar.
            // `give`, `stop` y el final del cuerpo también salen por acá: terminan su bloque, así
            // que no sobra nada.
            self.steps = self.steps.wrapping_sub(chunk.rest[at] as u64);
            // Un `stop` que llega a una instrucción del cuerpo de un bucle compilado lo corta.
            if matches!(c, Control::Stop(_)) && chunk.stop_to[at] != NONE {
                pc = chunk.stop_to[at] as usize;
                continue;
            }
            // `End` sale como `Give` para compartir este camino; al que llamó a `run_chunk` se le
            // devuelve lo mismo que `exec_block`: `Ok` con el valor de la última sentencia.
            let ended = matches!(ins, Ins::End { .. });
            loop {
                if self.vm_frames.len() == entry {
                    self.vm_iters.truncate(entry_iters);
                    return match c {
                        Control::Give(v) if ended => Ok(v),
                        other => Err(other),
                    };
                }
                // Termina una llamada que corría la VM: el mismo epílogo que
                // `call_value_named_inner` (tinta, frame reciclado) y `call_value_named`
                // (profundidad), por el camino normal y por el de error.
                let caller = self.vm_frames.pop().expect("frame de la VM");
                if let Some(t) = caller.taint {
                    self.leave_call(t);
                }
                // Lo que el cuerpo tenía abierto (una vuelta, un brazo) se suelta sin reciclar,
                // como cuando un `give` o un error salen de un `each` de la referencia.
                while depth > 0 {
                    let parent = env.borrow().parent.clone().expect("frame sin padre");
                    env = parent;
                    depth -= 1;
                }
                self.vm_iters.truncate(iter_base);
                let call_env = std::mem::replace(&mut env, caller.env);
                self.release_frame(call_env);
                drop(caller.task);
                self.recursion_depth -= 1;
                self.vm_regs.truncate(base);
                chunk = caller.chunk;
                base = caller.base;
                pc = caller.pc;
                depth = caller.depth;
                iter_base = caller.iter_base;
                let result = match c {
                    Control::Give(v) => Ok(v),
                    other => Err(other),
                };
                match result {
                    Ok(v) => {
                        self.put(base, caller.dst, v);
                        break;
                    }
                    // Un `stop` que sale de la task corta el bucle compilado del llamador.
                    Err(Control::Stop(x)) => {
                        if chunk.stop_to[pc - 1] != NONE {
                            drop(x);
                            pc = chunk.stop_to[pc - 1] as usize;
                            break;
                        }
                        c = Control::Stop(x);
                    }
                    Err(other) => c = other,
                }
                // Sigue el error hacia arriba (un `Call` termina su bloque: no sobran pasos).
            }
        }
    }

    // Los brazos pesados y poco frecuentes del bucle, fuera de línea (como F1.10 con `exec_node`):
    // así el despacho de las instrucciones calientes queda chico y el compilador no lo reacomoda
    // cada vez que cambia uno de estos.

    /// `TryInPlace`: `Ok(true)` si la vía en el lugar hizo la asignación.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_try_in_place(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        dst: Reg,
        node: u32,
        name: u32,
        ic: u32,
    ) -> Result<bool, Control> {
        // Sólo con una lista o un mapa puede aplicar; con cualquier otra cosa la referencia lee
        // la variable, ve que no encaja y deja todo como estaba.
        if name != NONE {
            let now = if ic == NONE { env_get(env, &chunk.names[name as usize]) } else { self.load_free(chunk, env, name, ic) };
            let fits = matches!(now, Some(SynValue::List(_) | SynValue::Map(_)));
            drop(now);
            if !fits {
                return Ok(false);
            }
        }
        let NodeKind::SetMutation { target, value } = &chunk.nodes[node as usize].kind else {
            unreachable!("TryInPlace sobre otro nodo")
        };
        match self.try_update_in_place(target, value, env)? {
            Some(v) => {
                self.put(base, dst, v);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    #[inline(never)]
    fn vm_each_init(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, node: u32, it: u16, iter_base: usize) -> Result<(), Control> {
        let NodeKind::EachStatement { collection, .. } = &chunk.nodes[node as usize].kind else {
            unreachable!("EachInit sobre otro nodo")
        };
        let loc = &chunk.nodes[node as usize].location;
        // Como la referencia con atajos: `range(…)` sin armar la lista.
        let items = match self.each_over_range(collection, env)? {
            Some(r) => EachItems::Range(r),
            None => {
                let coll = self.exec(collection, env)?;
                self.each_items_of(&coll, loc)?
            }
        };
        self.vm_iters.truncate(iter_base + it as usize);
        self.vm_iters.push(items);
        Ok(())
    }

    /// Un brazo de `match`: `Ok(Some(frame))` si matcheó (el frame del brazo, con sus binders).
    #[inline(never)]
    fn vm_match_arm(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        subj: Reg,
        node: u32,
        scope: u32,
    ) -> Result<Option<Rc<RefCell<Environment>>>, Control> {
        let NodeKind::MatchArm { pattern, .. } = &chunk.nodes[node as usize].kind else {
            unreachable!("MatchArm sobre otro nodo")
        };
        // El sujeto sale del registro mientras se prueba (sin una referencia de más).
        let subject = std::mem::replace(&mut self.vm_regs[base + subj as usize], SynValue::Nothing);
        let binds = self.match_pattern_top(pattern, &subject, env);
        self.vm_regs[base + subj as usize] = subject;
        let Some(binds) = binds? else { return Ok(None) };
        // El frame del brazo nace con todos sus nombres (huecos) y los binders se ligan por nombre:
        // un patrón que liga de menos deja su hueco.
        let arm_env = Environment::child_scope(env, "match-arm");
        arm_env.borrow_mut().bindings.lay_out(&chunk.layouts[scope as usize], chunk.tagged);
        for (name, val) in binds {
            env_set(&arm_env, &name, val);
        }
        Ok(Some(arm_env))
    }

    #[inline(never)]
    fn vm_define(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, dst: Reg, node: u32, child: u32) -> Result<(), Control> {
        let v = self.exec(&chunk.nodes[node as usize], env)?;
        if let SynValue::Task(t) = &v {
            t.code.set(chunk.children[child as usize].clone());
        }
        self.put(base, dst, v);
        Ok(())
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_set_path(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        src: Opnd,
        node: u32,
        dst: Reg,
        at: usize,
    ) -> Result<(), Control> {
        let v = self.opnd(chunk, env, base, src, at)?;
        let out = self.exec_set(&chunk.nodes[node as usize], v, env, &chunk.locs[chunk.loc[at] as usize], false)?;
        self.put(base, dst, out);
        Ok(())
    }

    #[inline(never)]
    fn vm_wasm_tick(&mut self, chunk: &Chunk, base: usize, ctr: Reg, at: usize) -> Result<(), Control> {
        let n = match &self.vm_regs[base + ctr as usize] {
            SynValue::Number(Number::Int(i)) => *i + 1,
            _ => 1,
        };
        self.vm_regs[base + ctr as usize] = syn_int(n);
        if n > 1_000_000 {
            return Err(err_at(
                "Loop exceeded maximum iterations (1,000,000) — in the wasm build a `while` is capped, since the host cannot interrupt a loop that never ends; the native `synsema` has no cap",
                &chunk.locs[chunk.loc[at] as usize],
            ));
        }
        Ok(())
    }

    /// Una llamada desde código compilado. `Ok(Some)` = entrar al cuerpo (task compilada, todo por
    /// posición); `Ok(None)` = ya se hizo por el camino de siempre y el valor está en `dst`.
    #[allow(clippy::too_many_arguments)]
    fn vm_call(
        &mut self,
        chunk: &Chunk,
        base: usize,
        at: usize,
        dst: Reg,
        func: Reg,
        args: Reg,
        n: u16,
        site: u32,
    ) -> Result<Option<Enter>, Control> {
        let loc = &chunk.locs[chunk.loc[at] as usize];
        let f = std::mem::replace(&mut self.vm_regs[base + func as usize], SynValue::Nothing);
        let s = &chunk.sites[site as usize];
        let n = n as usize;
        let first = base + args as usize;
        if s.names.is_none() {
            if let SynValue::Task(t) = &f {
                if let Some(code) = self.vm_code_for(t).cloned() {
                    if s.checked {
                        check_task_arity(t, n, |_| false, loc)?;
                    }
                    self.recursion_depth += 1;
                    if self.recursion_depth > MAX_RECURSION {
                        self.recursion_depth -= 1;
                        return Err(err("maximum recursion depth exceeded"));
                    }
                    let call_env = self.acquire_frame(&t.closure_env, "call");
                    // Aridad permisiva (sin chequeo, un pipe): los de más se sueltan antes de los
                    // defaults, como en `call_value_named_inner`.
                    for i in t.parameters.len()..n {
                        drop(std::mem::replace(&mut self.vm_regs[first + i], SynValue::Nothing));
                    }
                    for (i, param) in t.parameters.iter().enumerate() {
                        let v = if i < n {
                            std::mem::replace(&mut self.vm_regs[first + i], SynValue::Nothing)
                        } else {
                            match &param.default {
                                Some(d) => match self.exec(d, &t.closure_env) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        self.recursion_depth -= 1;
                                        return Err(e);
                                    }
                                },
                                None => SynValue::Nothing,
                            }
                        };
                        env_set_shared(&call_env, &param.name, v);
                    }
                    let laid = code.frame.as_ref().is_some_and(|l| call_env.borrow_mut().bindings.lay_out(l, code.tagged));
                    let taint = if self.labels { Some(self.enter_call()) } else { None };
                    if !laid {
                        // No se pudo preparar el frame: el cuerpo por el tree-walker, como antes.
                        let out = match self.exec_block(&t.body, &call_env) {
                            Ok(v) | Err(Control::Give(v)) => Ok(v),
                            Err(other) => Err(other),
                        };
                        if let Some(t) = taint {
                            self.leave_call(t);
                        }
                        self.release_frame(call_env);
                        self.recursion_depth -= 1;
                        let v = out?;
                        self.put(base, dst, v);
                        return Ok(None);
                    }
                    let new_base = self.vm_regs.len();
                    self.vm_regs.resize(new_base + code.nregs as usize, SynValue::Nothing);
                    let SynValue::Task(task) = f else { unreachable!() };
                    return Ok(Some(Enter { code, env: call_env, base: new_base, taint, task }));
                }
            }
        }
        self.vm_call_generic(chunk, base, at, dst, f, first, n, site)
    }

    /// El camino de siempre (`call_value_named`): builtins, argumentos nombrados, tasks sin
    /// compilar.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_call_generic(
        &mut self,
        chunk: &Chunk,
        base: usize,
        at: usize,
        dst: Reg,
        f: SynValue,
        first: usize,
        n: usize,
        site: u32,
    ) -> Result<Option<Enter>, Control> {
        let loc = &chunk.locs[chunk.loc[at] as usize];
        let s = &chunk.sites[site as usize];
        let mut cargs = self.free_args.pop().unwrap_or_default();
        cargs.reserve(n);
        for i in 0..n {
            let name = s.names.as_ref().and_then(|v| v[i].clone());
            cargs.push((name, std::mem::replace(&mut self.vm_regs[first + i], SynValue::Nothing)));
        }
        if s.checked {
            check_call_arity(&f, &cargs, loc)?;
        }
        let out = self.call_value_named(f, &mut cargs, loc);
        self.release_args(cargs);
        let v = out?;
        self.put(base, dst, v);
        Ok(None)
    }
}

/// Entrar al cuerpo de una llamada (lo arma `vm_call`).
struct Enter {
    code: Rc<Chunk>,
    env: Rc<RefCell<Environment>>,
    base: usize,
    taint: Option<TaintFrame>,
    task: Rc<SynTaskValue>,
}

fn set_undefined(name: &str) -> Control {
    err(format!("Cannot set undefined variable: '{}'. Use 'let' first.", name))
}

// =============================================================================================
// `explain` (L10): las instrucciones de un chunk, para tests y para depurar la VM.
// =============================================================================================

#[doc(hidden)]
pub fn explain_source(source: &str) -> String {
    let program = match crate::parser::parse_source(source, "<explain>") {
        Ok(p) => p,
        Err(e) => return format!("parse error: {}", e),
    };
    let chunk = compile_program(&program.statements);
    let mut out = String::new();
    explain_chunk(&chunk, "program", &mut out);
    out
}

fn explain_chunk(c: &Chunk, title: &str, out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(out, "== {} ({} registros)", title, c.nregs);
    if let Some(f) = &c.frame {
        let names: Vec<&str> = f.names.iter().map(|n| &**n).collect();
        let _ = writeln!(out, "   frame: [{}]", names.join(", "));
    }
    for (i, ins) in c.code.iter().enumerate() {
        let l = &c.locs[c.loc[i] as usize];
        let _ = writeln!(out, "{:04} {:<60} rest={} @{}:{}", i, format!("{:?}", ins), c.rest[i], l.line, l.column);
    }
    for (i, ch) in c.children.iter().enumerate() {
        explain_chunk(ch, &format!("{} / hijo {}", title, i), out);
    }
}
