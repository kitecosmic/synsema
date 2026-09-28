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
//!   (lo usa el quickening de F3.4, ver `Ins::Binary`) y los encabezados de bucle (reservados:
//!   calor/OSR).
//!
//! **Qué se compila** (F3.1): literales, variables, operadores, `and`/`or`, cadenas de comparación,
//! `let`, `set` a una variable, `when`, `while`, `give`, `stop` y la definición de tasks y lambdas
//! (su cuerpo se compila también). Todo lo demás es `Exec`: el nodo lo corre el tree-walker con el
//! frame de la VM como entorno (§6.0 punto 4), y cuenta sus propios pasos.

use super::*;
use crate::resolve::{self, Resolution, ScopeId, Target};
use num_integer::Integer;
use std::cell::Cell;

pub(crate) type Reg = u16;
/// Registro destino "no hace falta el valor": se suelta en el acto.
const DISCARD: Reg = Reg::MAX;
/// F3.7: en `TryInPlace`, un `slot` con este bit es un parámetro (el registro `slot & !PARAM`)
/// de un cuerpo con frame en registros, no un lugar de la ventana.
const PARAM: u16 = 0x8000;
const NONE: u32 = u32::MAX;

/// Un operando: un registro que se consume, uno que se copia, una constante o un slot del frame
/// propio que está ligado seguro.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Opnd {
    Reg(Reg),
    Copy(Reg),
    Const(u32),
    Local(u16),
    /// F3.3b: una variable ligada segura de un cuerpo con frame en registros.
    RLocal(u16),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Ins {
    /// Entrada a un bloque básico: los pasos de todos sus nodos.
    Steps(u32),
    /// F3.5 (superinstrucción): `Steps` + `CheckCancel`, el comienzo de cada sentencia de un
    /// bloque (el par más frecuente del perfil: 10 % de lo que corre). Si el chequeo corta, sobran
    /// los pasos que habría sobrado el `CheckCancel` (su `rest`).
    StepsCancel(u32),
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
    /// F3.5: `LoadName` cuya búsqueda empieza en el entorno actual (el nivel superior, o una task
    /// definida ahí que lee una global): el lugar cacheado, sin armar el recorrido (como
    /// `LOAD_GLOBAL` especializado de CPython). Si la caché falla, el camino de `LoadName`.
    LoadGlobal { dst: Reg, name: u32, ic: u32 },
    /// Un operador binario tal como lo emite el compilador: adaptativo (F3.4, *quickening*). La
    /// primera vez mira los tipos de los operandos y se reescribe en su forma especializada (si
    /// la hay: `AddInt`, …) o en `BinaryAny`; esa vez calcula por el camino genérico. `fb`: su
    /// slot de feedback (cuántas veces se desoptimizó).
    Binary { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    /// La forma genérica, que nunca se pierde: `exec_binary`, como la referencia.
    BinaryAny { dst: Reg, op: BinOp, a: Opnd, b: Opnd },
    /// Formas especializadas para `Int` × `Int` (F3.4). Guarda: los dos operandos son
    /// `Number::Int` (un `Big` no pasa aunque su valor entre en i64); si no, `vm_binary_miss`
    /// (camino genérico + desoptimización). Si la cuenta desborda, el camino genérico da el `Big`.
    /// Nunca dan un error propio: los errores los arma `exec_binary` (`%` por cero cae ahí).
    /// `+ - * %` (el operador en `op`).
    IntArith { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    /// `< <= > >= == !=`.
    IntCmp { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    /// F3.5 (superinstrucción por quickening): un `IntCmp` cuyo resultado sólo lo usa el
    /// `JumpIfFalsy` que le sigue (la condición de un `while` o un `when`) compara y salta sin
    /// armar el Bool. El `JumpIfFalsy` queda en su lugar (su `rest`, su ubicación): si la guarda
    /// falla, esta instrucción vuelve a `Binary` y el salto corre como siempre.
    IntCmpJump { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    /// `+ - *` con al menos un `Float` (el otro `Int` o `Float`) y `/` con dos números `Int` o
    /// `Float` (en Synsema `/` siempre da float): la cuenta en f64, como `Number`. Un divisor cero
    /// cae al camino genérico (el error de la referencia).
    FloatArith { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    /// Comparaciones entre `Int` y `Float` en cualquier mezcla: exactas, con el mismo
    /// `partial_cmp_num`/`num_eq` de la referencia (`2**53 + 1` no es igual a `9007199254740992.0`).
    NumCmp { dst: Reg, op: BinOp, a: Opnd, b: Opnd, fb: u16 },
    Unary { dst: Reg, op: UnOp, a: Opnd },
    ToBool { dst: Reg, src: Opnd },
    Jump { to: u32 },
    JumpIfFalsy { src: Opnd, to: u32 },
    LetLocal { src: Opnd, slot: u16, dst: Reg },
    /// F3.3b: lo mismo sobre la ventana de locales (el compilador sabe el modo: el despacho de
    /// las demás instrucciones no pregunta por él).
    LoadRLocal { dst: Reg, slot: u16, name: u32 },
    LetRLocal { src: Opnd, slot: u16, dst: Reg },
    SetRLocal { src: Opnd, slot: u16, name: u32, dst: Reg },
    LetName { src: Opnd, name: u32, dst: Reg },
    SetLocal { src: Opnd, slot: u16, name: u32, dst: Reg },
    SetOuter { src: Opnd, depth: u16, slot: u16, name: u32, dst: Reg, at: u32 },
    SetName { src: Opnd, name: u32, dst: Reg, ic: u32 },
    /// F3.5: `SetName` desde el entorno actual (ver `LoadGlobal`).
    SetGlobal { src: Opnd, name: u32, dst: Reg, ic: u32 },
    /// `set P to append(P, …)` y compañía: la vía en el lugar de la referencia
    /// (`try_update_in_place`) si la variable es una lista o un mapa; si aplica, salta a `done`.
    /// No termina su bloque (F3.5): el valor y la asignación que siguen son del mismo bloque, y
    /// si llama a la referencia descuenta antes sus pasos (`rest`), así lo que la referencia mire
    /// del contador es exacto y, si aplica, esos pasos no se cuentan.
    /// `ic` = `NONE` si la variable es del resolver (se mira por nombre desde el frame propio);
    /// `name` = `NONE` si el destino es un camino (siempre se prueba); `slot` = la variable local
    /// del destino en un cuerpo con frame en registros (`u16::MAX` si no).
    TryInPlace { dst: Reg, node: u32, name: u32, done: u32, ic: u32, slot: u16 },
    /// El nodo lo corre el tree-walker.
    Exec { dst: Reg, node: u32 },
    /// `[a, b, …]` con los elementos en `n` registros desde `first`.
    MakeList { dst: Reg, first: Reg, n: u16 },
    /// `{k: v, …}` con clave y valor alternados en `2n` registros desde `first`.
    MakeMap { dst: Reg, first: Reg, n: u16 },
    /// `m.k`. F3.6 (L3, *inline cache*): `ic` recuerda en qué posición del mapa estaba la clave la
    /// última vez; si la clave en esa posición es la misma, no se hashea (se compara la clave, no
    /// una "forma": la semántica de valor no cambia). Lo demás (otros tipos, clave que falta,
    /// módulos) por `property_read`, con sus errores.
    GetProp { dst: Reg, obj: Opnd, name: u32, ic: u32 },
    /// `x[i]`. F3.6: una lista con un entero, directo; un mapa con una clave de texto, sin armar la
    /// clave (`to_string`) y con la misma caché que `GetProp`. Lo demás por `index_read`.
    GetIndex { dst: Reg, obj: Opnd, idx: Opnd, ic: u32 },
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
    /// F3.4, `each` sin frame: una vuelta cuyo scope nadie puede ver (el resolver lo prueba: sin
    /// captura, sin escape, sin nodos fríos en el cuerpo) guarda sus variables en la ventana de
    /// locales de la VM, como Lua (`FORLOOP`) o V8 cuando nadie captura el contexto. La colección
    /// ya evaluada (por la VM) en `src`.
    EachInitV { src: Opnd, node: u32, it: u16 },
    /// `each i in range(…)` como el atajo de la referencia (`each_over_range`): si `src` es el
    /// builtin `range`, sigue; si no, salta a `to` (la llamada de siempre).
    IsRange { src: Reg, to: u32 },
    /// Los argumentos de `range` en `n` registros desde `first`: el iterador perezoso.
    EachRange { first: Reg, n: u16, it: u16 },
    /// La vuelta siguiente: la variable en el lugar `slot` de la ventana; sin más, a `exit`.
    EachNextV { it: u16, slot: u16, exit: u32 },
    /// Fin de la vuelta: las variables de la vuelta (`n` lugares desde `first`) se sueltan, como
    /// cuando la referencia suelta el frame de la vuelta, y a `head`.
    EachStepV { head: u32, first: u16, n: u16 },
    /// Fin del bucle (también por `stop`): las variables y el iterador se sueltan.
    EachEndV { it: u16, first: u16, n: u16 },
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
    /// El código. En `Cell`: el quickening (F3.4) reescribe una instrucción en el lugar cuando ve
    /// qué tipos le llegan (`Ins` es `Copy`: el despacho la copia antes de ejecutarla, así que
    /// reescribirla mientras corre una recursión es seguro).
    code: Box<[Cell<Ins>]>,
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
    /// F3.3b: el frame de la llamada no existe como `Environment`: sus variables viven en la
    /// ventana de locales de la VM (`vm_locals`) y el entorno del cuerpo es el `closure_env`. Sólo
    /// para cuerpos que nadie puede ver desde afuera (ver `regframe_eligible`).
    pub(crate) regframe: bool,
    /// En un cuerpo con frame en registros: el slot de cada parámetro (en orden).
    param_slots: Vec<u16>,
    /// El tamaño de la ventana de locales de este cuerpo: el frame en registros (si lo es) y las
    /// vueltas de `each` sin frame (F3.4).
    nlocals: u16,
    /// Para la vía en el lugar y `set` con caminos (que corre la referencia, por nombre): por nodo
    /// frío, qué frames hay que armar con las variables de la ventana (`NONE` si ninguno).
    node_spill: Vec<u32>,
    spills: Vec<Box<[Spill]>>,
    /// Si el frame lleva su `Layout` como marca: sólo hace falta cuando otro chunk (el de una task
    /// o lambda definida adentro) lo va a recorrer y tiene que verificarlo. Los frames que la VM
    /// preparó para este chunk no se verifican: los armó ella.
    pub(crate) tagged: bool,
    nregs: u16,
    /// Las cachés de `LoadName`/`SetName`/`TryInPlace` (0 = vacía; si no, slot + 1) y, para cada
    /// una, desde dónde se busca (`hops`).
    ics: Vec<Cell<u32>>,
    ic_hops: Vec<u32>,
    /// Por caché: si la búsqueda empieza en el entorno actual (sin frames que saltear).
    ic_here: Vec<bool>,
    /// Las cachés de `GetProp`/`GetIndex` (F3.6): posición + 1 de la clave en el mapa (0 = vacía).
    key_ics: Box<[Cell<u32>]>,
    /// Los recorridos hacia afuera de este cuerpo (ver `Hops`).
    hops: Vec<Hops>,
    /// Por slot de feedback (F3.4): cuántas veces se desoptimizó su operación.
    deopts: Box<[Cell<u8>]>,
    /// Reservado (calor/OSR): dónde empieza cada bucle.
    #[allow(dead_code)]
    loop_heads: Vec<u32>,
}

/// Un scope que vive en la ventana de locales: su layout (el del resolver) y dónde empieza.
#[derive(Clone, Copy, Debug)]
struct Spill {
    scope: ScopeId,
    off: u16,
    /// El frame de un cuerpo con frame en registros: sus parámetros están en los registros
    /// `r0..` (F3.7), no en la ventana.
    params: bool,
    /// El nombre del frame que la referencia le daría (`call`, `each`).
    name: &'static str,
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
    /// Dónde empieza la ventana de locales del llamador (F3.3b).
    lbase: usize,
    /// El largo de la pila de registros antes de la llamada: al volver, la pila vuelve a ese
    /// largo (F3.7: la ventana del llamado puede empezar adentro de la de su llamador, y la de
    /// éste adentro de la de más afuera; el final del llamador no es el tope de la pila).
    top: usize,
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
    compile_unit(&res, &shared, 0, None, &[], Body::Program(stmts))
}

/// El cuerpo de una task o lambda que definió el tree-walker, resuelto por sí solo.
pub(crate) fn compile_function(params: &[Arc<str>], body: &[Node]) -> Rc<Chunk> {
    let (res, s) = resolve::resolve_function(params, body);
    let shared = Shared::new(&res);
    let refs: Vec<&Node> = body.iter().collect();
    compile_body(&res, &shared, s, params, &refs, false)
}

enum Body<'a> {
    Program(&'a [Node]),
    Task(&'a [&'a Node]),
    Lambda(&'a Node),
}

/// El cuerpo de una task o lambda. Lo compila una vez por scope (lo comparten los intentos de su
/// padre, ver `compile_unit`).
fn compile_body<'r>(
    res: &'r Resolution,
    shared: &Shared<'r>,
    scope: ScopeId,
    params: &[Arc<str>],
    body: &[&Node],
    lambda: bool,
) -> Rc<Chunk> {
    if let Some(c) = shared.done.borrow().get(&scope) {
        return c.clone();
    }
    let unit = res.scopes[scope as usize].unit;
    let c = if lambda {
        compile_unit(res, shared, unit, Some(scope), params, Body::Lambda(body[0]))
    } else {
        compile_unit(res, shared, unit, Some(scope), params, Body::Task(body))
    };
    shared.done.borrow_mut().insert(scope, c.clone());
    c
}

/// Compila una unidad (el programa o un cuerpo) eligiendo qué vive en la ventana de locales:
/// las vueltas de `each` que el resolver deja (`window_candidates`) y, en un cuerpo, su frame si
/// todos sus otros scopes quedaron en la ventana (F3.3b). Si al compilar aparece algo que lee un
/// frame por nombre (un nodo del tree-walker, una task definida adentro, un brazo de `match`, un
/// `each` con frame), esos scopes vuelven a tener frame y se compila de nuevo: la elección sólo
/// se achica, así que termina.
fn compile_unit<'r>(
    res: &'r Resolution,
    shared: &Shared<'r>,
    unit: UnitIdx,
    frame_scope: Option<ScopeId>,
    params: &[Arc<str>],
    body: Body<'_>,
) -> Rc<Chunk> {
    let mut win = window_candidates(res, unit, frame_scope);
    let mut regframe = frame_scope.is_some_and(|s| regframe_eligible(res, s, &win));
    loop {
        let mut c = Compiler::new(res, shared, frame_scope);
        c.window = win.clone();
        c.regframe = regframe;
        c.lay_window(params);
        let chunk = match &body {
            Body::Program(stmts) => {
                c.block(stmts, Some(0), false);
                c.finish_checked()
            }
            Body::Task(stmts) => {
                let r = c.result_reg;
                c.block_of(stmts, Some(r), true);
                c.finish_checked()
            }
            Body::Lambda(e) => {
                // El cuerpo de una lambda es un bloque de una sentencia, el `give <expr>` que arma
                // el intérprete: el chequeo de cancelación del bloque y un nodo más.
                c.at(&e.location);
                c.emit(Ins::CheckCancel);
                c.enter();
                let v = c.expr(e);
                c.at(&e.location);
                c.emit(Ins::Give { src: v });
                c.finish_checked()
            }
        };
        match chunk {
            Ok(chunk) => return chunk,
            Err((bad, frame_needed)) => {
                win.retain(|s| !bad.contains(s));
                regframe = regframe && !frame_needed && frame_scope.is_some_and(|s| regframe_eligible(res, s, &win));
            }
        }
    }
}

type UnitIdx = resolve::UnitId;

/// Las vueltas de `each` de esta unidad que pueden vivir en la ventana: el resolver prueba que
/// nadie ve su frame (ni una closure, ni un nodo frío, ni un hook) y ningún nombre suyo tapa uno
/// de un scope de afuera en la misma unidad (así un hueco sigue buscando donde la referencia).
fn window_candidates(res: &Resolution, unit: UnitIdx, frame_scope: Option<ScopeId>) -> Vec<ScopeId> {
    let mut out = Vec::new();
    for (i, sc) in res.scopes.iter().enumerate() {
        if sc.unit != unit || sc.kind != resolve::ScopeKind::Each || sc.escapes || sc.opaque || sc.dynamic {
            continue;
        }
        let mut ok = true;
        let mut p = sc.parent;
        while let Some(x) = p {
            let up = &res.scopes[x as usize];
            if up.unit != unit && Some(x) != frame_scope {
                break;
            }
            if sc.names.iter().any(|n| up.names.iter().any(|m| m == n)) {
                ok = false;
                break;
            }
            if Some(x) == frame_scope {
                break;
            }
            p = up.parent;
        }
        if ok {
            out.push(i as ScopeId);
        }
    }
    out
}

/// F3.3b: un frame que nadie puede ver desde afuera — ni una closure (no define tasks ni
/// lambdas), ni un nodo del tree-walker (no tiene nodos fríos: el resolver lo marca `escapes`) —
/// puede vivir en registros, si todos los otros scopes de su unidad son vueltas de `each` que
/// también viven en la ventana (F3.4).
fn regframe_eligible(res: &Resolution, scope: ScopeId, win: &[ScopeId]) -> bool {
    let sc = &res.scopes[scope as usize];
    !sc.escapes
        && !sc.opaque
        && !sc.dynamic
        && res.scopes.iter().enumerate().all(|(i, s)| s.unit != sc.unit || i == scope as usize || win.contains(&(i as ScopeId)))
}

/// Dónde vive una variable resuelta (ver `Compiler::place`).
#[derive(Clone, Copy)]
enum Place {
    /// F3.7: un parámetro de un cuerpo con frame en registros (nunca es hueco).
    Param(Reg),
    Win(u16),
    Local(u16),
    Outer(u16, u16),
    Free,
}

/// Lo que comparten un chunk y los de sus tasks anidadas: los layouts de todos los scopes.
struct Shared<'r> {
    by_node: HashMap<usize, &'r resolve::Access>,
    layouts: Rc<Vec<Rc<Layout>>>,
    parents: Rc<Vec<Option<ScopeId>>>,
    /// Los cuerpos ya compilados, por scope: no dependen de lo que elija su padre (una task
    /// definida adentro de una vuelta le deja frame a esa vuelta).
    done: RefCell<HashMap<ScopeId, Rc<Chunk>>>,
}

impl<'r> Shared<'r> {
    fn new(res: &'r Resolution) -> Self {
        let layouts = res.scopes.iter().map(|s| Rc::new(Layout { names: s.names.clone() })).collect();
        let parents = res.scopes.iter().map(|s| s.parent).collect();
        Shared { by_node: res.by_node(), layouts: Rc::new(layouts), parents: Rc::new(parents), done: RefCell::new(HashMap::new()) }
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
    regframe: bool,
    param_slots: Vec<u16>,
    /// Los scopes de vueltas de `each` que viven en la ventana (F3.4) y dónde empieza cada uno.
    window: Vec<ScopeId>,
    win_off: HashMap<ScopeId, u16>,
    nlocals: u16,
    /// Lo que salió al compilar: vueltas que igual necesitan frame, y si el cuerpo lo necesita.
    bad: Vec<ScopeId>,
    frame_needed: bool,
    node_spill: Vec<u32>,
    spills: Vec<Box<[Spill]>>,
    key_ics: u32,
    /// F3.7: en un cuerpo con frame en registros, el registro de cada slot que es un parámetro
    /// (el último si se repite, como la referencia) y dónde va el valor del bloque (`r0` si no).
    param_reg: HashMap<u16, Reg>,
    result_reg: Reg,
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
            regframe: false,
            param_slots: Vec::new(),
            window: Vec::new(),
            win_off: HashMap::new(),
            nlocals: 0,
            bad: Vec::new(),
            frame_needed: false,
            node_spill: Vec::new(),
            spills: Vec::new(),
            key_ics: 0,
            param_reg: HashMap::new(),
            result_reg: 0,
        }
    }

    /// Una caché de clave nueva (F3.6).
    fn key_ic(&mut self) -> u32 {
        self.key_ics += 1;
        self.key_ics - 1
    }

    /// Los lugares de la ventana: el frame en registros primero (parámetros en su slot) y cada
    /// vuelta de `each` sin frame a continuación.
    fn lay_window(&mut self, params: &[Arc<str>]) {
        let mut n = 0usize;
        if self.regframe {
            let s = self.frame_scope.expect("frame en registros sin scope");
            let names = &self.res.scopes[s as usize].names;
            self.param_slots = params
                .iter()
                .map(|p| names.iter().position(|n| **n == **p).expect("parámetro fuera del layout") as u16)
                .collect();
            // F3.7: los parámetros son `r0..r(n-1)` (la llamada los deja ahí: la ventana del
            // cuerpo empieza en los argumentos del llamador) y el valor del bloque va después.
            for (i, &k) in self.param_slots.iter().enumerate() {
                self.param_reg.insert(k, i as Reg);
            }
            let np = params.len() as Reg;
            self.result_reg = np;
            self.next_reg = np + 1;
            self.max_reg = np + 1;
            self.win_off.insert(s, 0);
            n = names.len();
        }
        for &s in &self.window {
            self.win_off.insert(s, n as u16);
            n += self.res.scopes[s as usize].names.len();
        }
        self.nlocals = u16::try_from(n).expect("ventana de locales de más de 65535 lugares");
    }

    /// Dónde empieza en la ventana un scope que vive en ella.
    fn win(&self, scope: ScopeId) -> Option<u16> {
        self.win_off.get(&scope).copied()
    }

    /// Cuántos frames de `Environment` preparó este cuerpo en la cadena actual.
    fn inner(&self) -> u16 {
        self.depth + u16::from(self.frame_scope.is_some() && !self.regframe)
    }

    /// Cuántos frames de verdad hay entre el scope actual y el que está `depth` scopes afuera
    /// según el resolver: los que viven en la ventana no están en la cadena de entornos.
    fn real_depth(&self, depth: u16) -> u16 {
        let mut s = self.cur_scope;
        let mut n = 0;
        for _ in 0..depth {
            let x = s.expect("profundidad fuera de la cadena");
            if self.win(x).is_none() {
                n += 1;
            }
            s = self.shared.parents[x as usize];
        }
        n
    }

    /// Algo va a leer el frame actual por nombre (el tree-walker, una closure, un frame hijo): los
    /// scopes de la ventana de la cadena tienen que tener frame, y el cuerpo también.
    fn needs_names(&mut self) {
        let mut s = self.cur_scope;
        while let Some(x) = s {
            if self.window.contains(&x) {
                self.bad.push(x);
            }
            if self.regframe && Some(x) == self.frame_scope {
                self.frame_needed = true;
            }
            s = self.shared.parents[x as usize];
        }
    }

    /// Los frames que hay que armar para que la referencia vea las variables de la ventana (de
    /// afuera hacia adentro); `NONE` si no hay.
    fn spill_here(&mut self) -> u32 {
        let mut chain = Vec::new();
        let mut s = self.cur_scope;
        while let Some(x) = s {
            match self.win(x) {
                Some(off) => chain.push(Spill {
                    scope: x,
                    off,
                    params: self.regframe && Some(x) == self.frame_scope,
                    name: self.res.scopes[x as usize].kind.frame_name(),
                }),
                None => break,
            }
            s = self.shared.parents[x as usize];
        }
        if chain.is_empty() {
            return NONE;
        }
        chain.reverse();
        self.spills.push(chain.into_boxed_slice());
        (self.spills.len() - 1) as u32
    }

    // -- emisión --------------------------------------------------------------------------------

    fn at(&mut self, loc: &SourceLocation) {
        if self.locs.last() != Some(loc) {
            self.locs.push(loc.clone());
        }
        self.cur_loc = (self.locs.len() - 1) as u32;
    }

    fn emit(&mut self, ins: Ins) {
        if matches!(ins, Ins::Exec { .. } | Ins::Define { .. } | Ins::MatchArm { .. } | Ins::EachInit { .. }) {
            self.needs_names();
        }
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

    /// Si la búsqueda de la caché `ic` empieza en el entorno actual.
    fn ic_here(&self, ic: u32) -> bool {
        self.hops[self.ic_hops[ic as usize] as usize].from.is_none()
    }

    /// El recorrido hacia afuera desde el scope actual (ver `Hops`). Los scopes de la ventana no
    /// tienen frame: se parte del primero que sí.
    fn hops_here(&mut self) -> u32 {
        let mut from = self.cur_scope;
        while let Some(x) = from {
            if self.win(x).is_none() {
                break;
            }
            from = self.shared.parents[x as usize];
        }
        let mut skip = 0u16;
        let mut s = from;
        while let Some(x) = s {
            if self.res.scopes[x as usize].dynamic {
                skip = 0;
                break;
            }
            skip += 1;
            s = self.shared.parents[x as usize];
        }
        self.hops.push(Hops { from, inner: self.inner(), skip });
        (self.hops.len() - 1) as u32
    }

    fn cold(&mut self, n: &Node) -> u32 {
        self.nodes.push(n.clone());
        self.node_spill.push(NONE);
        (self.nodes.len() - 1) as u32
    }

    /// Un nodo frío que la referencia corre con las variables de la ventana puestas en frames.
    fn cold_spilled(&mut self, n: &Node) -> u32 {
        let k = self.cold(n);
        self.node_spill[k as usize] = self.spill_here();
        k
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
                    Some(Place::Param(r)) => self.write_param(r, v, dst),
                    Some(Place::Win(slot)) => self.emit(Ins::LetRLocal { src: v, slot, dst }),
                    Some(Place::Local(slot)) => self.emit(Ins::LetLocal { src: v, slot, dst }),
                    _ => {
                        let name = self.shared_name(name);
                        self.emit(Ins::LetName { src: v, name, dst })
                    }
                }
            }
            K::SetMutation { target, value } if matches!(target.kind, K::Identifier { .. }) => {
                let K::Identifier { name } = &target.kind else { unreachable!() };
                self.enter();
                let done = if in_place_shape(target, value) {
                    let node = self.cold_spilled(n);
                    let nm = self.name(name);
                    let done = self.label();
                    let (ic, slot) = match self.place(self.target(target)) {
                        Place::Free => (self.ic(), u16::MAX),
                        Place::Param(r) => (NONE, PARAM | r),
                        Place::Win(k) => (NONE, k),
                        _ => (NONE, u16::MAX),
                    };
                    self.emit(Ins::TryInPlace { dst, node, name: nm, done, ic, slot });
                    Some(done)
                } else {
                    None
                };
                let v = self.expr(value);
                self.at(&n.location);
                let nm = self.name(name);
                match self.place(self.target(target)) {
                    Place::Param(r) => self.write_param(r, v, dst),
                    Place::Win(slot) => self.emit(Ins::SetRLocal { src: v, slot, name: nm, dst }),
                    Place::Local(slot) => self.emit(Ins::SetLocal { src: v, slot, name: nm, dst }),
                    Place::Outer(depth, slot) => {
                        let at = self.hops_here();
                        self.emit(Ins::SetOuter { src: v, depth, slot, name: nm, dst, at })
                    }
                    Place::Free => {
                        let ic = self.ic();
                        if self.ic_here(ic) {
                            self.emit(Ins::SetGlobal { src: v, name: nm, dst, ic })
                        } else {
                            self.emit(Ins::SetName { src: v, name: nm, dst, ic })
                        }
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
                    let node = self.cold_spilled(n);
                    let done = self.label();
                    self.emit(Ins::TryInPlace { dst, node, name: NONE, done, ic: NONE, slot: u16::MAX });
                    Some(done)
                } else {
                    None
                };
                let v = self.expr(value);
                let node = self.cold_spilled(target);
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
            K::EachStatement { .. } if self.res.scope_opened_by(n).is_some_and(|sc| self.win(sc).is_some()) => {
                self.each_windowed(n, want);
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

    /// Un `each` sin frame (F3.4): la colección la evalúa la VM (con el atajo de `range` de la
    /// referencia), la variable y los `let` de la vuelta viven en la ventana.
    fn each_windowed(&mut self, n: &Node, want: Option<Reg>) {
        let NodeKind::EachStatement { collection, body, .. } = &n.kind else { unreachable!() };
        let scope = self.res.scope_opened_by(n).expect("each sin scope");
        let first = self.win(scope).expect("each fuera de la ventana");
        let count = self.res.scopes[scope as usize].names.len() as u16;
        self.enter();
        let node = self.cold(n);
        let it = self.eaches;
        self.eaches += 1;
        self.collection(collection, node, it);
        if let Some(d) = want {
            let k = self.konst(SynValue::Nothing);
            self.emit(Ins::Const { dst: d, k });
        }
        let head = self.label();
        let exit = self.label();
        self.bind(head);
        self.loop_heads.push(head);
        self.at(&n.location);
        // La variable del `each` es el primer nombre de su scope.
        self.emit(Ins::EachNextV { it, slot: first, exit });
        if let Some(d) = want {
            let k = self.konst(SynValue::Nothing);
            self.emit(Ins::Const { dst: d, k });
        }
        let outer_scope = self.cur_scope;
        self.cur_scope = Some(scope);
        self.loops.push(exit);
        self.block(body, want, true);
        self.loops.pop();
        self.emit(Ins::EachStepV { head, first, n: count });
        self.cur_scope = outer_scope;
        self.bind(exit);
        self.emit(Ins::EachEndV { it, first, n: count });
        self.eaches -= 1;
    }

    /// La colección de un `each` sin frame. `range(a, b, paso)` escrito así (1 a 3 posicionales):
    /// si `range` es el builtin, el iterador perezoso (`each_over_range`: cuenta el nodo de la
    /// llamada, el nombre y los argumentos, y un nivel de recursión); si no, la llamada de siempre.
    fn collection(&mut self, c: &Node, node: u32, it: u16) {
        if let NodeKind::TaskCall { name, arguments } = &c.kind {
            if name.as_identifier() == Some("range")
                && !arguments.is_empty()
                && arguments.len() <= 3
                && arguments.iter().all(|a| a.name.is_none())
                && !PROTECTED_BUILTIN_NAMES.contains(&"range")
            {
                self.enter();
                let f = self.expr(name);
                let func = self.to_reg(f);
                let general = self.label();
                let done = self.label();
                self.emit(Ins::IsRange { src: func, to: general });
                let first = self.block_regs(arguments.len());
                let end = first + arguments.len() as Reg;
                for (i, a) in arguments.iter().enumerate() {
                    self.into_reg(&a.value, first + i as Reg, end);
                }
                self.at(&c.location);
                self.emit(Ins::Drop { r: func });
                self.emit(Ins::EachRange { first, n: arguments.len() as u16, it });
                self.emit(Ins::Jump { to: done });
                self.bind(general);
                let first = self.block_regs(arguments.len());
                let end = first + arguments.len() as Reg;
                for (i, a) in arguments.iter().enumerate() {
                    self.into_reg(&a.value, first + i as Reg, end);
                }
                self.sites.push(CallSite { names: None, checked: true });
                let site = (self.sites.len() - 1) as u32;
                self.at(&c.location);
                let dst = self.reg();
                self.emit(Ins::Call { dst, func, args: first, n: arguments.len() as u16, site });
                self.emit(Ins::EachInitV { src: Opnd::Reg(dst), node, it });
                self.bind(done);
                return;
            }
        }
        let v = self.expr(c);
        self.emit(Ins::EachInitV { src: v, node, it });
    }

    /// `let`/`set` a un parámetro (F3.7): el valor al registro del parámetro y, si el bloque lo
    /// usa, una copia en `dst`.
    fn write_param(&mut self, r: Reg, v: Opnd, dst: Reg) {
        if v != Opnd::Reg(r) {
            self.emit(Ins::Move { dst: r, src: v });
        }
        if dst != DISCARD {
            self.emit(Ins::Move { dst, src: Opnd::Copy(r) });
        }
    }

    fn target_of_bind(&self, n: &Node) -> Option<Place> {
        let a = self.shared.by_node.get(&(n as *const Node as usize))?;
        match a.target {
            Target::Slot { depth: 0, scope, .. } if self.in_frame(scope, 0) => Some(self.place(a.target)),
            _ => None,
        }
    }

    /// Dónde vive una variable resuelta: en la ventana, en el frame propio, en uno de afuera
    /// (contando sólo frames de verdad) o por nombre.
    fn place(&self, t: Target) -> Place {
        match t {
            Target::Slot { depth, scope, slot, .. } if self.in_frame(scope, depth) => {
                if self.regframe && Some(scope) == self.frame_scope {
                    if let Some(&r) = self.param_reg.get(&slot) {
                        return Place::Param(r);
                    }
                }
                if let Some(off) = self.win(scope) {
                    return Place::Win(off + slot);
                }
                let rd = self.real_depth(depth);
                if rd == 0 && self.inner() > 0 {
                    Place::Local(slot)
                } else {
                    Place::Outer(rd, slot)
                }
            }
            _ => Place::Free,
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
            (NodeKind::TaskDefinition { body, parameters, .. }, Some(s)) => {
                let body: Vec<&Node> =
                    body.iter().filter(|x| !matches!(x.kind, NodeKind::RequireStatement { .. })).collect();
                let params: Vec<Arc<str>> = parameters.iter().map(|p| p.name.clone()).collect();
                Some(self.child(s, &params, &body, false))
            }
            (NodeKind::LambdaExpression { body, parameters }, Some(s)) => Some(self.child(s, parameters, &[&**body], true)),
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

    fn child(&mut self, scope: ScopeId, params: &[Arc<str>], body: &[&Node], lambda: bool) -> Rc<Chunk> {
        compile_body(self.res, self.shared, scope, params, body, lambda)
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
                let ic = self.key_ic();
                self.emit(Ins::GetProp { dst, obj: o, name, ic });
                Opnd::Reg(dst)
            }
            K::IndexAccess { object, index } => {
                self.enter();
                let o = self.expr(object);
                let o = self.keep_until(o, index);
                let i = self.expr(index);
                self.at(&n.location);
                let dst = self.dst(want);
                let ic = self.key_ic();
                self.emit(Ins::GetIndex { dst, obj: o, idx: i, ic });
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
                let t = self.target(n);
                let definite = matches!(t, Target::Slot { definite: true, .. });
                match self.place(t) {
                    Place::Param(r) => Opnd::Copy(r),
                    Place::Win(slot) if definite => Opnd::RLocal(slot),
                    Place::Local(slot) if definite => Opnd::Local(slot),
                    Place::Win(slot) => {
                        let dst = self.dst(want);
                        self.emit(Ins::LoadRLocal { dst, slot, name: nm });
                        Opnd::Reg(dst)
                    }
                    Place::Local(slot) => {
                        let dst = self.dst(want);
                        self.emit(Ins::LoadLocal { dst, slot, name: nm });
                        Opnd::Reg(dst)
                    }
                    Place::Outer(depth, slot) => {
                        let dst = self.dst(want);
                        let at = self.hops_here();
                        self.emit(Ins::LoadOuter { dst, depth, slot, name: nm, at });
                        Opnd::Reg(dst)
                    }
                    Place::Free => {
                        let dst = self.dst(want);
                        let ic = self.ic();
                        if self.ic_here(ic) {
                            self.emit(Ins::LoadGlobal { dst, name: nm, ic });
                        } else {
                            self.emit(Ins::LoadName { dst, name: nm, ic });
                        }
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
            Opnd::Local(_) | Opnd::RLocal(_) if !is_simple(later) => Opnd::Reg(self.to_reg(a)),
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

    /// Termina el chunk, o dice qué vueltas (y si el cuerpo) necesitan frame después de todo.
    fn finish_checked(self) -> Result<Rc<Chunk>, (Vec<ScopeId>, bool)> {
        if !self.bad.is_empty() || self.frame_needed {
            return Err((self.bad, self.frame_needed));
        }
        let r = self.result_reg;
        Ok(self.finish(Opnd::Reg(r)))
    }

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
                // F3.5: no corta el bloque (lo común es que no aplique y siga en línea); cuando llama
                // a la referencia descuenta antes lo que el bloque sumó de más (ver el despacho).
                Ins::TryInPlace { done, .. } => {
                    leader[target(&self.labels, done)] = true;
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
                Ins::EachStep { head } | Ins::EachStepV { head, .. } => {
                    leader[target(&self.labels, head)] = true;
                    leader[i + 1] = true;
                }
                Ins::EachNextV { exit, .. } => {
                    leader[target(&self.labels, exit)] = true;
                    leader[i + 1] = true;
                }
                Ins::IsRange { to, .. } => {
                    leader[target(&self.labels, to)] = true;
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
            // Un bloque que empieza con el chequeo de cancelación (cada sentencia de un bloque):
            // los pasos y el chequeo en una instrucción, con el `rest` y la ubicación del chequeo.
            let first = (i..j).find(|&k| !matches!(self.code[k], Ins::Nop));
            let fused = first.filter(|&k| total > 0 && matches!(self.code[k], Ins::CheckCancel));
            if let Some(k) = fused {
                code.push(Ins::StepsCancel(total));
                new_rest.push(rest[k]);
                new_loc.push(self.loc[k]);
                new_stop.push(self.stop_of[k]);
            } else if total > 0 {
                code.push(Ins::Steps(total));
                new_rest.push(0);
                new_loc.push(self.loc[i]);
                new_stop.push(NONE);
            }
            for k in i..j {
                // Un salto al comienzo del bloque cae en su `Steps`.
                new_index[k] = if k == i { start } else { code.len() as u32 };
                if matches!(self.code[k], Ins::Nop) || fused == Some(k) {
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
                Ins::EachStep { head } | Ins::EachStepV { head, .. } => *head = map(*head, &self.labels),
                Ins::EachNextV { exit, .. } => *exit = map(*exit, &self.labels),
                Ins::IsRange { to, .. } => *to = map(*to, &self.labels),
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
            code: code.into_iter().map(Cell::new).collect(),
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
            regframe: self.regframe,
            param_slots: self.param_slots,
            nlocals: self.nlocals,
            node_spill: self.node_spill,
            spills: self.spills,
            nregs: self.max_reg,
            ics: (0..self.ics).map(|_| Cell::new(0)).collect(),
            ic_here: self.ic_hops.iter().map(|&h| self.hops[h as usize].from.is_none()).collect(),
            key_ics: (0..self.key_ics).map(|_| Cell::new(0)).collect(),
            ic_hops: self.ic_hops,
            hops: self.hops,
            deopts: (0..=self.feedback as usize).map(|_| Cell::new(0)).collect(),
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
        self.vm_last_program = Some(chunk.clone());
        #[cfg(feature = "vm-profile")]
        {
            let r = self.run_chunk(&chunk, env);
            profile::flush();
            r
        }
        #[cfg(not(feature = "vm-profile"))]
        self.run_chunk(&chunk, env)
    }

    /// Corre un chunk en `env` (el frame de la llamada, ya preparado, o la raíz del programa).
    /// Devuelve lo mismo que `exec_block` sobre ese cuerpo.
    pub(super) fn run_chunk(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        if chunk.nlocals == 0 {
            return self.run_chunk_regs(chunk, env);
        }
        // Las vueltas de `each` sin frame (F3.4): su ventana de locales.
        let lbase = self.vm_locals.len();
        self.vm_locals.resize(lbase + chunk.nlocals as usize, None);
        let saved = std::mem::replace(&mut self.vm_lbase, lbase);
        let r = self.run_chunk_regs(chunk, env);
        self.vm_lbase = saved;
        self.vm_locals.truncate(lbase);
        r
    }

    fn run_chunk_regs(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        // Los slots `Local` sólo valen en el frame que la llamada preparó con el layout del chunk.
        debug_assert!(chunk.regframe || chunk.frame.as_ref().is_none_or(|l| {
            let e = env.borrow();
            e.bindings.len_names() >= l.names.len() && (!chunk.tagged || e.bindings.laid_out_as(l))
        }));
        let base = self.vm_regs.len();
        self.vm_regs.resize(base + chunk.nregs as usize, SynValue::Nothing);
        let r = self.run_chunk_at(chunk, env, base);
        self.vm_regs.truncate(base);
        r
    }

    /// Un cuerpo con frame en registros llamado desde el tree-walker: los parámetros que ligó en
    /// `call_env` pasan a la ventana de locales y el cuerpo corre con el `closure_env`.
    pub(super) fn run_chunk_regframe(
        &mut self,
        chunk: &Rc<Chunk>,
        call_env: &Rc<RefCell<Environment>>,
        closure_env: &Rc<RefCell<Environment>>,
    ) -> Result<SynValue, Control> {
        let n = chunk.frame.as_ref().map_or(0, |l| l.names.len());
        let lbase = self.vm_locals.len();
        self.vm_locals.resize(lbase + chunk.nlocals as usize, None);
        let base = self.vm_regs.len();
        self.vm_regs.resize(base + chunk.nregs as usize, SynValue::Nothing);
        {
            // Los parámetros van a sus registros (F3.7); otro nombre ligado, a la ventana.
            let mut e = call_env.borrow_mut();
            for k in 0..e.bindings.len_names().min(n) {
                let v = e.bindings.take_slot(k);
                match chunk.param_slots.iter().rposition(|&s| s as usize == k) {
                    Some(i) => self.vm_regs[base + i] = v.unwrap_or(SynValue::Nothing),
                    None => self.vm_locals[lbase + k] = v,
                }
            }
        }
        let saved = std::mem::replace(&mut self.vm_lbase, lbase);
        let r = self.run_chunk_at(chunk, closure_env, base);
        self.vm_regs.truncate(base);
        self.vm_lbase = saved;
        self.vm_locals.truncate(lbase);
        r
    }

    /// Al volver de una llamada de la VM: los registros del llamado se sueltan (como antes, al
    /// truncar su ventana) y la pila vuelve al largo que tenía antes de la llamada (`top`). Un
    /// cuerpo con frame en registros empezó en los argumentos, dentro de la pila de entonces
    /// (F3.7): esa parte se vacía en el lugar y lo que pasa de `top` se recorta.
    #[inline(always)]
    fn vm_pop_regs(&mut self, (cbase, cregs): (usize, u16), top: usize) {
        if self.vm_regs.len() > top {
            self.vm_regs.truncate(top);
        }
        let cend = (cbase + cregs as usize).min(self.vm_regs.len());
        if cbase < cend {
            for r in &mut self.vm_regs[cbase..cend] {
                *r = SynValue::Nothing;
            }
        }
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
            Opnd::RLocal(k) => match &self.vm_locals[self.vm_lbase + k as usize] {
                Some(v) => v.clone(),
                // Ligado seguro según el resolver: no pasa. Si pasara, por nombre.
                None => return self.vm_rlocal_by_name(chunk, env, k, at),
            },
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

    /// Los dos operandos, si los dos son `Number::Int`, leídos sin moverlos ni clonarlos (la guarda
    /// del quickening). Un registro que se consume queda con su `Int`: no tiene referencias que
    /// soltar y nadie lo vuelve a leer sin escribirlo antes. Un hueco no pasa la guarda: el camino
    /// genérico lo busca por nombre, como siempre.
    #[inline(always)]
    fn int_pair(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, a: Opnd, b: Opnd) -> Option<(i64, i64)> {
        Some((self.peek_int(chunk, env, base, a)?, self.peek_int(chunk, env, base, b)?))
    }

    /// Los dos operandos si los dos son `Int` o `Float` (la guarda de `FloatArith`/`NumCmp`).
    #[inline(always)]
    fn num_pair(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, a: Opnd, b: Opnd) -> Option<(Num, Num)> {
        Some((self.peek_num(chunk, env, base, a)?, self.peek_num(chunk, env, base, b)?))
    }

    #[inline(always)]
    fn peek_num(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, o: Opnd) -> Option<Num> {
        let num = |v: &SynValue| match v {
            SynValue::Number(Number::Int(x)) => Some(Num::I(*x)),
            SynValue::Number(Number::Float(x)) => Some(Num::F(*x)),
            _ => None,
        };
        match o {
            Opnd::Reg(r) | Opnd::Copy(r) => num(&self.vm_regs[base + r as usize]),
            Opnd::Const(k) => num(&chunk.consts[k as usize]),
            Opnd::RLocal(k) => num(self.vm_locals[self.vm_lbase + k as usize].as_ref()?),
            Opnd::Local(k) => num(env.borrow().bindings.slot(k as usize)?),
        }
    }

    #[inline(always)]
    fn peek_int(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, o: Opnd) -> Option<i64> {
        let v = match o {
            Opnd::Reg(r) | Opnd::Copy(r) => &self.vm_regs[base + r as usize],
            Opnd::Const(k) => &chunk.consts[k as usize],
            Opnd::RLocal(k) => self.vm_locals[self.vm_lbase + k as usize].as_ref()?,
            Opnd::Local(k) => {
                return match env.borrow().bindings.slot(k as usize) {
                    Some(SynValue::Number(Number::Int(x))) => Some(*x),
                    _ => None,
                }
            }
        };
        match v {
            SynValue::Number(Number::Int(x)) => Some(*x),
            _ => None,
        }
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
            let ins = chunk.code[at].get();
            pc += 1;
            #[cfg(feature = "vm-profile")]
            profile::hit(&ins);
            let out: Result<(), Control> = match ins {
                Ins::Steps(w) => {
                    self.steps = self.steps.wrapping_add(w as u64);
                    Ok(())
                }
                Ins::StepsCancel(w) => {
                    self.steps = self.steps.wrapping_add(w as u64);
                    if self.cancel.flag.load(std::sync::atomic::Ordering::Relaxed) {
                        self.check_cancel()
                    } else {
                        Ok(())
                    }
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
                Ins::GetProp { dst, obj, name, ic } => (|| {
                    let o = self.opnd(&chunk, &env, base, obj, at)?;
                    let found = match &o {
                        SynValue::Map(m) => map_get_cached(&m.borrow(), &chunk.names[name as usize], &chunk.key_ics[ic as usize]),
                        _ => None,
                    };
                    let v = match found {
                        Some(v) => v,
                        None => self.property_read(o, &chunk.names[name as usize], &chunk.locs[chunk.loc[at] as usize])?,
                    };
                    self.put(base, dst, v);
                    Ok(())
                })(),
                Ins::GetIndex { dst, obj, idx, ic } => (|| {
                    let o = self.opnd(&chunk, &env, base, obj, at)?;
                    let i = self.opnd(&chunk, &env, base, idx, at)?;
                    let found = match (&o, &i) {
                        (SynValue::Map(m), SynValue::Text(k)) => map_get_cached(&m.borrow(), k, &chunk.key_ics[ic as usize]),
                        (SynValue::List(l), SynValue::Number(Number::Int(k))) => {
                            let items = l.borrow();
                            resolve_index(*k, items.len()).map(|j| items[j].clone())
                        }
                        _ => None,
                    };
                    let v = match found {
                        Some(v) => v,
                        None => self.index_read(o, i, &chunk.locs[chunk.loc[at] as usize])?,
                    };
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
                Ins::LoadRLocal { dst, slot, name } => match self.vm_locals[self.vm_lbase + slot as usize].clone() {
                    Some(v) => {
                        self.put(base, dst, v);
                        Ok(())
                    }
                    None => self.vm_rlocal_hole(&chunk, &env, base, dst, name, at),
                },
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
                Ins::LoadGlobal { dst, name, ic } => {
                    let v = env.borrow().bindings.get_cached(&chunk.names[name as usize], &chunk.ics[ic as usize]).cloned();
                    match v {
                        Some(v) => {
                            self.put(base, dst, v);
                            Ok(())
                        }
                        None => self.vm_load_name(&chunk, &env, base, dst, name, ic, at),
                    }
                }
                Ins::LoadName { dst, name, ic } => match self.load_free(&chunk, &env, name, ic) {
                    Some(v) => {
                        self.put(base, dst, v);
                        Ok(())
                    }
                    None => Err(undefined_variable(&chunk.names[name as usize], &chunk.locs[chunk.loc[at] as usize])),
                },
                Ins::Binary { dst, op, a, b, fb } => self.vm_binary_adapt(&chunk, &env, base, at, dst, op, a, b, fb),
                Ins::BinaryAny { dst, op, a, b } => (|| {
                    let a = self.opnd(&chunk, &env, base, a, at)?;
                    let b = self.opnd(&chunk, &env, base, b, at)?;
                    let v = self.exec_binary(a, op, b, &chunk.locs[chunk.loc[at] as usize])?;
                    self.put(base, dst, v);
                    Ok(())
                })(),
                // Quickening (F3.4): las formas especializadas, en brazos propios.
                Ins::IntArith { dst, op, a, b, fb } => match self.int_pair(&chunk, &env, base, a, b) {
                    Some((x, y)) => {
                        let r = match op {
                            BinOp::Add => x.checked_add(y),
                            BinOp::Sub => x.checked_sub(y),
                            BinOp::Mul => x.checked_mul(y),
                            // `Number::modulo` con dos `Int`: floored; `% -1` es 0 (`i64::MIN % -1`
                            // desborda en la CPU); `% 0` es error y lo arma el camino genérico.
                            _ => match y {
                                0 => None,
                                -1 => Some(0),
                                _ => Some(x.mod_floor(&y)),
                            },
                        };
                        match r {
                            Some(r) => {
                                self.put(base, dst, SynValue::Number(Number::Int(r)));
                                Ok(())
                            }
                            None => self.vm_binary_generic(&chunk, &env, base, at, dst, op, a, b),
                        }
                    }
                    None => self.vm_binary_miss(&chunk, &env, base, at, dst, op, a, b, fb),
                },
                Ins::FloatArith { dst, op, a, b, fb } => match self.num_pair(&chunk, &env, base, a, b) {
                    Some((x, y)) if op == BinOp::Div || x.is_float() || y.is_float() => {
                        let (x, y) = (x.f64(), y.f64());
                        let r = match op {
                            BinOp::Add => Some(x + y),
                            BinOp::Sub => Some(x - y),
                            BinOp::Mul => Some(x * y),
                            // `/` por cero (también -0.0) es error: lo arma la referencia.
                            _ if y == 0.0 => None,
                            _ => Some(x / y),
                        };
                        match r {
                            Some(r) => {
                                self.put(base, dst, SynValue::Number(Number::Float(r)));
                                Ok(())
                            }
                            None => self.vm_binary_generic(&chunk, &env, base, at, dst, op, a, b),
                        }
                    }
                    _ => self.vm_binary_miss(&chunk, &env, base, at, dst, op, a, b, fb),
                },
                Ins::NumCmp { dst, op, a, b, fb } => match self.num_pair(&chunk, &env, base, a, b) {
                    Some((x, y)) => {
                        let (x, y) = (x.number(), y.number());
                        let r = match op {
                            BinOp::Eq => x.num_eq(&y),
                            BinOp::Ne => !x.num_eq(&y),
                            _ => ord_op(x.partial_cmp_num(&y), op),
                        };
                        self.put(base, dst, syn_bool(r));
                        Ok(())
                    }
                    None => self.vm_binary_miss(&chunk, &env, base, at, dst, op, a, b, fb),
                },
                Ins::IntCmpJump { dst, op, a, b, fb } => match self.int_pair(&chunk, &env, base, a, b) {
                    Some((x, y)) => {
                        let r = match op {
                            BinOp::Lt => x < y,
                            BinOp::Le => x <= y,
                            BinOp::Gt => x > y,
                            BinOp::Ge => x >= y,
                            BinOp::Eq => x == y,
                            _ => x != y,
                        };
                        match (r, chunk.code[pc].get()) {
                            (true, _) => pc += 1,
                            (false, Ins::JumpIfFalsy { to, .. }) => pc = to as usize,
                            _ => unreachable!("IntCmpJump sin su JumpIfFalsy"),
                        }
                        Ok(())
                    }
                    None => self.vm_binary_miss(&chunk, &env, base, at, dst, op, a, b, fb),
                },
                Ins::IntCmp { dst, op, a, b, fb } => match self.int_pair(&chunk, &env, base, a, b) {
                    Some((x, y)) => {
                        let r = match op {
                            BinOp::Lt => x < y,
                            BinOp::Le => x <= y,
                            BinOp::Gt => x > y,
                            BinOp::Ge => x >= y,
                            BinOp::Eq => x == y,
                            _ => x != y,
                        };
                        self.put(base, dst, syn_bool(r));
                        Ok(())
                    }
                    None => self.vm_binary_miss(&chunk, &env, base, at, dst, op, a, b, fb),
                },
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
                Ins::LetRLocal { src, slot, dst } => self.opnd(&chunk, &env, base, src, at).map(|v| {
                    let k = self.vm_lbase + slot as usize;
                    if dst == DISCARD {
                        self.vm_locals[k] = Some(v);
                    } else {
                        self.vm_locals[k] = Some(v.clone());
                        self.put(base, dst, v);
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
                Ins::SetRLocal { src, slot, name, dst } => (|| {
                    let v = self.opnd(&chunk, &env, base, src, at)?;
                    let k = self.vm_lbase + slot as usize;
                    if self.vm_locals[k].is_some() {
                        self.vm_locals[k] = Some(v.clone());
                        self.put(base, dst, v);
                        Ok(())
                    } else {
                        self.vm_rlocal_set_hole(&chunk, &env, base, v, name, dst)
                    }
                })(),
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
                Ins::SetGlobal { src, name, dst, ic } => (|| {
                    let v = self.opnd(&chunk, &env, base, src, at)?;
                    // Un módulo sincroniza su mapa de exportaciones: por el camino de `SetName`.
                    let done = {
                        let mut e = env.borrow_mut();
                        !e.name.starts_with("module:")
                            && match e.bindings.get_cached_mut(&chunk.names[name as usize], &chunk.ics[ic as usize]) {
                                Some(slot) => {
                                    *slot = v.clone();
                                    true
                                }
                                None => false,
                            }
                    };
                    if !done && !self.set_free(&chunk, &env, name, ic, v.clone()) {
                        return Err(set_undefined(&chunk.names[name as usize]));
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
                // La vía en el lugar sólo puede aplicar a una lista o un mapa: el tipo de la
                // variable se mira acá, sin clonarla, y la referencia sólo se llama si puede.
                Ins::TryInPlace { name, slot, .. }
                    if name != NONE
                        && slot < PARAM
                        && !matches!(self.vm_locals[self.vm_lbase + slot as usize], Some(SynValue::List(_) | SynValue::Map(_))) =>
                {
                    Ok(())
                }
                Ins::TryInPlace { name, slot, .. }
                    if name != NONE
                        && slot != u16::MAX
                        && slot >= PARAM
                        && !matches!(self.vm_regs[base + (slot & !PARAM) as usize], SynValue::List(_) | SynValue::Map(_)) =>
                {
                    Ok(())
                }
                Ins::TryInPlace { name, ic, .. }
                    if name != NONE
                        && ic != NONE
                        && chunk.ic_here[ic as usize]
                        && env
                            .borrow()
                            .bindings
                            .get_cached(&chunk.names[name as usize], &chunk.ics[ic as usize])
                            .is_some_and(|v| !matches!(v, SynValue::List(_) | SynValue::Map(_))) =>
                {
                    Ok(())
                }
                Ins::TryInPlace { dst, node, name, done, ic, slot } => {
                    // Los pasos del resto del bloque (el valor y la asignación) no corrieron todavía.
                    let pending = chunk.rest[at] as u64;
                    self.steps = self.steps.wrapping_sub(pending);
                    match self.vm_try_in_place(&chunk, &env, base, dst, node, name, ic, slot) {
                        Ok(true) => {
                            pc = done as usize;
                            Ok(())
                        }
                        Ok(false) => {
                            self.steps = self.steps.wrapping_add(pending);
                            Ok(())
                        }
                        Err(c) => {
                            // El camino de error vuelve a descontar `rest`.
                            self.steps = self.steps.wrapping_add(pending);
                            Err(c)
                        }
                    }
                }
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
                                lbase: std::mem::replace(&mut self.vm_lbase, enter.lbase),
                                top: enter.top,
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
                Ins::EachInitV { src, node, it } => self.vm_each_init_v(&chunk, &env, base, src, node, it, iter_base, at),
                Ins::IsRange { src, to } => {
                    if !matches!(&self.vm_regs[base + src as usize], SynValue::Builtin(b) if b.name == "range") {
                        pc = to as usize;
                    }
                    Ok(())
                }
                Ins::EachRange { first, n, it } => self.vm_each_range(base, first, n, it, iter_base),
                Ins::EachNextV { it, slot, exit } => {
                    match self.vm_iters[iter_base + it as usize].next_item() {
                        None => pc = exit as usize,
                        Some(item) => self.vm_locals[self.vm_lbase + slot as usize] = Some(item),
                    }
                    Ok(())
                }
                Ins::EachStepV { head, first, n } => {
                    // Lo que la vuelta ligó se suelta ahora, como el frame de la vuelta en la
                    // referencia (y un `let` de una rama que no corre vuelve a ser hueco).
                    let k = self.vm_lbase + first as usize;
                    for x in &mut self.vm_locals[k..k + n as usize] {
                        *x = None;
                    }
                    pc = head as usize;
                    Ok(())
                }
                Ins::EachEndV { it, first, n } => {
                    let k = self.vm_lbase + first as usize;
                    for x in &mut self.vm_locals[k..k + n as usize] {
                        *x = None;
                    }
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
                // Volver de una llamada que corre la VM, sin nada abierto adentro del cuerpo (ni
                // vuelta ni brazo con frame): directo al llamador, con el mismo epílogo que el camino
                // de `Control::Give` de abajo (F3.5). `give` y el final del cuerpo terminan su
                // bloque: no sobran pasos.
                Ins::Give { src } | Ins::End { src } if depth == 0 && self.vm_frames.len() > entry => {
                    match self.opnd(&chunk, &env, base, src, at) {
                        Ok(v) => {
                            let caller = self.vm_frames.pop().expect("frame de la VM");
                            self.vm_iters.truncate(iter_base);
                            let call_env = std::mem::replace(&mut env, caller.env);
                            if chunk.regframe {
                                drop(call_env);
                            } else {
                                self.release_frame(call_env);
                            }
                            self.vm_locals.truncate(self.vm_lbase);
                            self.vm_lbase = caller.lbase;
                            self.recursion_depth -= 1;
                            let callee = (base, chunk.nregs);
                            chunk = caller.chunk;
                            base = caller.base;
                            pc = caller.pc;
                            depth = caller.depth;
                            iter_base = caller.iter_base;
                            self.vm_pop_regs(callee, caller.top);
                            self.put(base, caller.dst, v);
                            Ok(())
                        }
                        Err(c) => Err(c),
                    }
                }
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
                // Lo que el cuerpo tenía abierto (una vuelta, un brazo) se suelta sin reciclar,
                // como cuando un `give` o un error salen de un `each` de la referencia.
                while depth > 0 {
                    let parent = env.borrow().parent.clone().expect("frame sin padre");
                    env = parent;
                    depth -= 1;
                }
                self.vm_iters.truncate(iter_base);
                let call_env = std::mem::replace(&mut env, caller.env);
                if chunk.regframe {
                    // No hay frame: el `env` era el `closure_env`.
                    drop(call_env);
                } else {
                    self.release_frame(call_env);
                }
                // La ventana de locales de la llamada (frame en registros, vueltas sin frame).
                self.vm_locals.truncate(self.vm_lbase);
                self.vm_lbase = caller.lbase;
                self.recursion_depth -= 1;
                let callee = (base, chunk.nregs);
                chunk = caller.chunk;
                base = caller.base;
                pc = caller.pc;
                depth = caller.depth;
                iter_base = caller.iter_base;
                self.vm_pop_regs(callee, caller.top);
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

    /// Un operador binario por el camino genérico (el de `BinaryAny`), fuera del despacho: lo usan
    /// la adaptación, las guardas que fallan y el desborde.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_binary_generic(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        at: usize,
        dst: Reg,
        op: BinOp,
        a: Opnd,
        b: Opnd,
    ) -> Result<(), Control> {
        let a = self.opnd(chunk, env, base, a, at)?;
        let b = self.opnd(chunk, env, base, b, at)?;
        let v = self.exec_binary(a, op, b, &chunk.locs[chunk.loc[at] as usize])?;
        self.put(base, dst, v);
        Ok(())
    }

    /// `Binary` (adaptativo): se reescribe según los tipos que ve ahora y calcula por el camino
    /// genérico. Lo que no tiene forma especializada queda en `BinaryAny`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_binary_adapt(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        at: usize,
        dst: Reg,
        op: BinOp,
        a: Opnd,
        b: Opnd,
        fb: u16,
    ) -> Result<(), Control> {
        let quick = match self.num_pair(chunk, env, base, a, b) {
            Some((Num::I(_), Num::I(_))) if op == BinOp::Div => Some(Ins::FloatArith { dst, op, a, b, fb }),
            // Una comparación que sólo usa el salto que le sigue: compara y salta (F3.5).
            Some((Num::I(_), Num::I(_)))
                if matches!(int_form(op, dst, a, b, fb), Some(Ins::IntCmp { .. }))
                    && matches!(chunk.code.get(at + 1).map(Cell::get), Some(Ins::JumpIfFalsy { src: Opnd::Reg(r), .. }) if r == dst) =>
            {
                Some(Ins::IntCmpJump { dst, op, a, b, fb })
            }
            Some((Num::I(_), Num::I(_))) => int_form(op, dst, a, b, fb),
            Some(_) => float_form(op, dst, a, b, fb),
            None => None,
        };
        chunk.code[at].set(quick.unwrap_or(Ins::BinaryAny { dst, op, a, b }));
        self.vm_binary_generic(chunk, env, base, at, dst, op, a, b)
    }

    /// Una forma especializada vio otros tipos: vuelve a `Binary` (para especializarse con lo que
    /// venga) hasta `MAX_DEOPTS` veces, y después queda en `BinaryAny`; esta vez, camino genérico.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_binary_miss(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        at: usize,
        dst: Reg,
        op: BinOp,
        a: Opnd,
        b: Opnd,
        fb: u16,
    ) -> Result<(), Control> {
        let n = &chunk.deopts[fb as usize];
        n.set(n.get().saturating_add(1));
        chunk.code[at].set(if n.get() <= MAX_DEOPTS {
            Ins::Binary { dst, op, a, b, fb }
        } else {
            Ins::BinaryAny { dst, op, a, b }
        });
        self.vm_binary_generic(chunk, env, base, at, dst, op, a, b)
    }

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
        slot: u16,
    ) -> Result<bool, Control> {
        // Sólo con una lista o un mapa puede aplicar; con cualquier otra cosa la referencia lee
        // la variable, ve que no encaja y deja todo como estaba.
        if name != NONE {
            let now = if slot != u16::MAX && slot >= PARAM {
                Some(self.vm_regs[base + (slot & !PARAM) as usize].clone())
            } else if slot != u16::MAX {
                self.vm_locals[self.vm_lbase + slot as usize].clone()
            } else if ic == NONE {
                env_get(env, &chunk.names[name as usize])
            } else {
                self.load_free(chunk, env, name, ic)
            };
            let fits = matches!(now, Some(SynValue::List(_) | SynValue::Map(_)));
            drop(now);
            if !fits {
                return Ok(false);
            }
        }
        let NodeKind::SetMutation { target, value } = &chunk.nodes[node as usize].kind else {
            unreachable!("TryInPlace sobre otro nodo")
        };
        let spill = chunk.node_spill[node as usize];
        if spill != NONE {
            // La vía en el lugar es de la referencia y busca por nombre: las variables de la
            // ventana van a frames el rato que corre (ver `vm_spill`).
            let frames = self.vm_spill(chunk, env, base, spill);
            let r = self.try_update_in_place(target, value, frames.last().expect("spill vacío"));
            self.vm_unspill(chunk, base, spill, frames);
            return match r? {
                Some(v) => {
                    self.put(base, dst, v);
                    Ok(true)
                }
                None => Ok(false),
            };
        }
        match self.try_update_in_place(target, value, env)? {
            Some(v) => {
                self.put(base, dst, v);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// F3.3b: una variable del frame en registros que resultó hueco (una rama que no corrió): por
    /// nombre desde el `closure_env`, que es lo que sigue al frame.
    #[inline(never)]
    fn vm_rlocal_hole(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, dst: Reg, name: u32, at: usize) -> Result<(), Control> {
        let nm = &chunk.names[name as usize];
        match env_get(env, nm) {
            Some(v) => {
                self.put(base, dst, v);
                Ok(())
            }
            None => Err(undefined_variable(nm, &chunk.locs[chunk.loc[at] as usize])),
        }
    }

    #[inline(never)]
    fn vm_rlocal_by_name(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, k: u16, at: usize) -> Result<SynValue, Control> {
        let name = chunk.frame.as_ref().expect("frame").names[k as usize].clone();
        env_get(env, &name).ok_or_else(|| undefined_variable(&name, &chunk.locs[chunk.loc[at] as usize]))
    }

    /// `set` a una variable del frame en registros que es hueco: la de afuera, como `env_update`.
    #[inline(never)]
    fn vm_rlocal_set_hole(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, v: SynValue, name: u32, dst: Reg) -> Result<(), Control> {
        if env_update(env, &chunk.names[name as usize], v.clone()).is_err() {
            return Err(set_undefined(&chunk.names[name as usize]));
        }
        self.put(base, dst, v);
        Ok(())
    }

    /// La referencia (vía en el lugar, `set` con caminos) busca por nombre: los scopes de la
    /// ventana se arman como frames, de afuera hacia adentro, con las variables MOVIDAS adentro
    /// (las mismas cuentas de referencias que la referencia, y con ellas el copy-on-write).
    fn vm_spill(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, spill: u32) -> SmallVec<[Rc<RefCell<Environment>>; 4]> {
        let mut frames: SmallVec<[Rc<RefCell<Environment>>; 4]> = SmallVec::new();
        for sp in chunk.spills[spill as usize].iter() {
            let parent = frames.last().cloned().unwrap_or_else(|| env.clone());
            let frame = self.acquire_frame(&parent, sp.name);
            drop(parent);
            {
                let mut e = frame.borrow_mut();
                for (k, name) in chunk.layouts[sp.scope as usize].names.iter().enumerate() {
                    let v = match param_reg_of(chunk, sp, k) {
                        Some(r) => Some(std::mem::replace(&mut self.vm_regs[base + r], SynValue::Nothing)),
                        None => self.vm_locals[self.vm_lbase + sp.off as usize + k].take(),
                    };
                    e.bindings.push_slot(name.clone(), v);
                }
            }
            frames.push(frame);
        }
        frames
    }

    /// Las variables vuelven a la ventana y los frames a la pila (de adentro hacia afuera: cada
    /// uno suelta a su padre).
    fn vm_unspill(&mut self, chunk: &Chunk, base: usize, spill: u32, mut frames: SmallVec<[Rc<RefCell<Environment>>; 4]>) {
        let chain = &chunk.spills[spill as usize];
        while let Some(frame) = frames.pop() {
            let sp = chain[frames.len()];
            {
                let mut e = frame.borrow_mut();
                let n = e.bindings.len_names().min(chunk.layouts[sp.scope as usize].names.len());
                for k in 0..n {
                    let v = e.bindings.take_slot(k);
                    match param_reg_of(chunk, &sp, k) {
                        // Un parámetro nunca queda hueco (la referencia no lo puede desligar).
                        Some(r) => self.vm_regs[base + r] = v.unwrap_or(SynValue::Nothing),
                        None => self.vm_locals[self.vm_lbase + sp.off as usize + k] = v,
                    }
                }
            }
            self.release_frame(frame);
        }
    }

    /// `LoadGlobal` que no encontró el lugar en el entorno actual: la búsqueda de `LoadName`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_load_name(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, dst: Reg, name: u32, ic: u32, at: usize) -> Result<(), Control> {
        match self.load_free(chunk, env, name, ic) {
            Some(v) => {
                self.put(base, dst, v);
                Ok(())
            }
            None => Err(undefined_variable(&chunk.names[name as usize], &chunk.locs[chunk.loc[at] as usize])),
        }
    }

    /// `EachInitV`: el iterador de la colección ya evaluada, como la referencia.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_each_init_v(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        src: Opnd,
        node: u32,
        it: u16,
        iter_base: usize,
        at: usize,
    ) -> Result<(), Control> {
        let coll = self.opnd(chunk, env, base, src, at)?;
        let items = self.each_items_of(&coll, &chunk.nodes[node as usize].location)?;
        drop(coll);
        self.vm_iters.truncate(iter_base + it as usize);
        self.vm_iters.push(items);
        Ok(())
    }

    /// `EachRange`: lo de `each_over_range` después de evaluar los argumentos (un nivel de
    /// recursión, como una llamada a builtin, y `range_spec`).
    #[inline(never)]
    fn vm_each_range(&mut self, base: usize, first: Reg, n: u16, it: u16, iter_base: usize) -> Result<(), Control> {
        let from = base + first as usize;
        let vals: SmallVec<[SynValue; 3]> =
            (0..n as usize).map(|i| std::mem::replace(&mut self.vm_regs[from + i], SynValue::Nothing)).collect();
        if self.recursion_depth + 1 > MAX_RECURSION {
            return Err(err("maximum recursion depth exceeded"));
        }
        let (lo, hi, step) = range_spec(&vals)?;
        self.vm_iters.truncate(iter_base + it as usize);
        self.vm_iters.push(EachItems::Range(RangeIter::new(lo, hi, step)));
        Ok(())
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
        let loc = &chunk.locs[chunk.loc[at] as usize];
        let spill = chunk.node_spill[node as usize];
        let out = if spill != NONE {
            let frames = self.vm_spill(chunk, env, base, spill);
            let r = self.exec_set(&chunk.nodes[node as usize], v, frames.last().expect("spill vacío"), loc, false);
            self.vm_unspill(chunk, base, spill, frames);
            r?
        } else {
            self.exec_set(&chunk.nodes[node as usize], v, env, loc, false)?
        };
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
                    // Con tantos posicionales como parámetros no sobra ni falta ninguno: el chequeo
                    // no puede fallar y no se recorren los parámetros en cada llamada (F3.5).
                    if s.checked && n != t.parameters.len() {
                        check_task_arity(t, n, |_| false, loc)?;
                    }
                    self.recursion_depth += 1;
                    if self.recursion_depth > MAX_RECURSION {
                        self.recursion_depth -= 1;
                        return Err(err("maximum recursion depth exceeded"));
                    }
                    if code.regframe {
                        return self.vm_enter_regframe(t, code, first, n).map(Some);
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
                    // La VM no corre con etiquetas (`vm_code_for`): `enter_call`/`leave_call` sólo
                    // mueven tinta de etiquetas, vacía y sin cambios acá.
                    debug_assert!(!self.labels);
                    if !laid {
                        // No se pudo preparar el frame: el cuerpo por el tree-walker, como antes.
                        let out = match self.exec_block(&t.body, &call_env) {
                            Ok(v) | Err(Control::Give(v)) => Ok(v),
                            Err(other) => Err(other),
                        };
                        self.release_frame(call_env);
                        self.recursion_depth -= 1;
                        let v = out?;
                        self.put(base, dst, v);
                        return Ok(None);
                    }
                    let new_base = self.vm_regs.len();
                    self.vm_regs.resize(new_base + code.nregs as usize, SynValue::Nothing);
                    let lbase = self.vm_locals.len();
                    self.vm_locals.resize(lbase + code.nlocals as usize, None);
                    return Ok(Some(Enter { code, env: call_env, base: new_base, lbase, top: new_base }));
                }
            }
        }
        self.vm_call_generic(chunk, base, at, dst, f, first, n, site)
    }

    /// Entrar a un cuerpo con frame en registros (F3.3b): los parámetros van a la ventana de
    /// locales, sin `Environment`; el cuerpo corre con el `closure_env`. Lo demás como la entrada
    /// de siempre (profundidad ya contada, defaults en el `closure_env`).
    fn vm_enter_regframe(&mut self, t: &Rc<SynTaskValue>, code: Rc<Chunk>, first: usize, n: usize) -> Result<Enter, Control> {
        // F3.7: la ventana de registros del cuerpo empieza en los argumentos (como Lua): los
        // parámetros `r0..` ya están en su lugar, sin copiarlos. Lo que hay del primer argumento
        // en adelante es del llamado (los argumentos, que la llamada consume, y temporales
        // muertos del llamador); al volver, el llamador recupera su largo con esos lugares vacíos.
        let np = t.parameters.len();
        let top = self.vm_regs.len();
        let need = first + (code.nregs as usize).max(n);
        if top < need {
            self.vm_regs.resize(need, SynValue::Nothing);
        }
        // Aridad permisiva (sin chequeo, un pipe): los de más se sueltan antes de los defaults.
        for i in np..n {
            drop(std::mem::replace(&mut self.vm_regs[first + i], SynValue::Nothing));
        }
        let lbase = self.vm_locals.len();
        self.vm_locals.resize(lbase + code.nlocals as usize, None);
        for i in n.min(np)..np {
            let v = match &t.parameters[i].default {
                Some(d) => match self.exec(d, &t.closure_env) {
                    Ok(v) => v,
                    Err(e) => {
                        self.vm_locals.truncate(lbase);
                        self.recursion_depth -= 1;
                        return Err(e);
                    }
                },
                None => SynValue::Nothing,
            };
            self.vm_regs[first + i] = v;
        }
        debug_assert!(!self.labels);
        Ok(Enter { env: t.closure_env.clone(), code, base: first, lbase, top })
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
    /// La ventana de locales del cuerpo (F3.3b; la del llamador si el cuerpo tiene frame).
    lbase: usize,
    top: usize,
}

/// La clave `key` de un mapa, por la posición que recuerda `ic` (si la clave en esa posición es
/// la misma, sin hashear); si no, la búsqueda de siempre, y `ic` recuerda dónde estaba. `None` si
/// no está (el que llama arma el error de la referencia).
#[inline(always)]
fn map_get_cached(m: &IndexMap<String, SynValue>, key: &str, ic: &Cell<u32>) -> Option<SynValue> {
    let c = ic.get() as usize;
    if c > 0 {
        if let Some((k, v)) = m.get_index(c - 1) {
            if k.as_str() == key {
                return Some(v.clone());
            }
        }
    }
    let (i, _, v) = m.get_full(key)?;
    ic.set(i as u32 + 1);
    Some(v.clone())
}

/// El registro del parámetro que ocupa el slot `k` del scope de `sp` (F3.7), si `sp` es el frame
/// de un cuerpo con frame en registros; el último si el nombre se repite, como la referencia.
fn param_reg_of(chunk: &Chunk, sp: &Spill, k: usize) -> Option<usize> {
    if !sp.params {
        return None;
    }
    chunk.param_slots.iter().rposition(|&s| s as usize == k)
}

/// Cuántas veces puede desoptimizarse una operación antes de quedar genérica para siempre (una que
/// alterna tipos no paga reescribirse en cada vuelta).
const MAX_DEOPTS: u8 = 2;

/// La forma especializada de `op` para dos `Int`, si la hay.
fn int_form(op: BinOp, dst: Reg, a: Opnd, b: Opnd, fb: u16) -> Option<Ins> {
    Some(match op {
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Mod => Ins::IntArith { dst, op, a, b, fb },
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Ne => Ins::IntCmp { dst, op, a, b, fb },
        _ => return None,
    })
}

/// La forma especializada de `op` cuando hay un `Float` en juego (o `/` entre enteros), si la hay.
fn float_form(op: BinOp, dst: Reg, a: Opnd, b: Opnd, fb: u16) -> Option<Ins> {
    Some(match op {
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div => Ins::FloatArith { dst, op, a, b, fb },
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Ne => Ins::NumCmp { dst, op, a, b, fb },
        _ => return None,
    })
}

/// Un operando numérico visto por una guarda (sin moverlo ni clonarlo).
#[derive(Clone, Copy)]
enum Num {
    I(i64),
    F(f64),
}

impl Num {
    #[inline(always)]
    fn is_float(self) -> bool {
        matches!(self, Num::F(_))
    }
    /// Como `Number::to_f64`.
    #[inline(always)]
    fn f64(self) -> f64 {
        match self {
            Num::I(x) => x as f64,
            Num::F(x) => x,
        }
    }
    #[inline(always)]
    fn number(self) -> Number {
        match self {
            Num::I(x) => Number::Int(x),
            Num::F(x) => Number::Float(x),
        }
    }
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

/// Corre el programa y muestra su código como quedó después (el quickening reescribe
/// instrucciones mientras corre; las tasks definidas por el programa son sus hijos). Oculto: para
/// los tests de la VM y para elegir superinstrucciones por perfil.
#[doc(hidden)]
pub fn explain_after_run(source: &str) -> String {
    let program = match crate::parser::parse_source(source, "<explain>") {
        Ok(p) => p,
        Err(e) => return format!("parse error: {}", e),
    };
    let mut interp = Interpreter::new();
    let _ = interp.execute(&program);
    let mut out = String::new();
    match &interp.vm_last_program {
        Some(c) => explain_chunk(c, "program", &mut out),
        None => out.push_str("(el programa no corrió por la VM)
"),
    }
    out
}

fn explain_chunk(c: &Chunk, title: &str, out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "== {} ({} registros{}{})",
        title,
        c.nregs,
        if c.regframe { ", frame en registros" } else { "" },
        if c.nlocals > 0 { format!(", ventana de {}", c.nlocals) } else { String::new() }
    );
    if let Some(f) = &c.frame {
        let names: Vec<&str> = f.names.iter().map(|n| &**n).collect();
        let _ = writeln!(out, "   frame: [{}]", names.join(", "));
    }
    for (i, ins) in c.code.iter().map(Cell::get).enumerate() {
        let l = &c.locs[c.loc[i] as usize];
        let _ = writeln!(out, "{:04} {:<60} rest={} @{}:{}", i, format!("{:?}", ins), c.rest[i], l.line, l.column);
    }
    for (i, ch) in c.children.iter().enumerate() {
        explain_chunk(ch, &format!("{} / hijo {}", title, i), out);
    }
}

/// El perfil de la VM (feature `vm-profile`, sólo para elegir superinstrucciones): cuántas veces
/// corre cada instrucción y cada par seguido (en el orden en que corren, también a través de una
/// llamada). Se acumula por hilo y se junta al terminar cada programa.
#[cfg(feature = "vm-profile")]
pub mod profile {
    use super::Ins;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::mem::Discriminant;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Local {
        tags: HashMap<Discriminant<Ins>, u16>,
        names: Vec<String>,
        prev: Option<u16>,
        single: HashMap<u16, u64>,
        pairs: HashMap<(u16, u16), u64>,
    }

    thread_local! {
        static LOCAL: RefCell<Local> = RefCell::new(Local::default());
    }

    static TOTAL: Mutex<Option<(HashMap<String, u64>, HashMap<(String, String), u64>)>> = Mutex::new(None);

    pub(crate) fn hit(ins: &Ins) {
        LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let d = std::mem::discriminant(ins);
            let t = match l.tags.get(&d) {
                Some(t) => *t,
                None => {
                    let dbg = format!("{:?}", ins);
                    let name = dbg.split([' ', '(']).next().unwrap_or("?").to_string();
                    let t = l.names.len() as u16;
                    l.names.push(name);
                    l.tags.insert(d, t);
                    t
                }
            };
            *l.single.entry(t).or_default() += 1;
            if let Some(p) = l.prev {
                *l.pairs.entry((p, t)).or_default() += 1;
            }
            l.prev = Some(t);
        });
    }

    pub(crate) fn flush() {
        LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let mut g = TOTAL.lock().unwrap();
            let (single, pairs) = g.get_or_insert_with(Default::default);
            let drained: Vec<_> = l.single.drain().collect();
            for (t, n) in drained {
                *single.entry(l.names[t as usize].clone()).or_default() += n;
            }
            let drained: Vec<_> = l.pairs.drain().collect();
            for ((a, b), n) in drained {
                *pairs.entry((l.names[a as usize].clone(), l.names[b as usize].clone())).or_default() += n;
            }
            l.prev = None;
        });
    }

    /// Lo acumulado hasta ahora, de más a menos frecuente, y lo vacía.
    pub fn take() -> String {
        use std::fmt::Write;
        let (single, pairs) = TOTAL.lock().unwrap().take().unwrap_or_default();
        let total: u64 = single.values().sum();
        let mut out = String::new();
        let _ = writeln!(out, "instrucciones: {}", total);
        let mut s: Vec<_> = single.into_iter().collect();
        s.sort_by(|a, b| b.1.cmp(&a.1));
        for (name, n) in s.iter().take(30) {
            let _ = writeln!(out, "  {:>6.2}%  {:>12}  {}", *n as f64 * 100.0 / total.max(1) as f64, n, name);
        }
        let _ = writeln!(out, "pares:");
        let mut p: Vec<_> = pairs.into_iter().collect();
        p.sort_by(|a, b| b.1.cmp(&a.1));
        for ((a, b), n) in p.iter().take(40) {
            let _ = writeln!(out, "  {:>6.2}%  {:>12}  {} -> {}", *n as f64 * 100.0 / total.max(1) as f64, n, a, b);
        }
        out
    }
}
