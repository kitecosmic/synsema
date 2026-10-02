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

use crate::synlist::list_values_mut;
use crate::synmap::{map_from_pair_slots, Key, MapIc, ShapeRef, MAX_SHAPED};
use crate::types::SynMap;
use super::*;
use crate::resolve::{self, Resolution, ScopeId, Target};
use num_integer::Integer;
use std::cell::Cell;

#[cfg(feature = "native-tier")]
#[path = "vm_native.rs"]
mod native;

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
    /// F4.6c: un `+` de una cadena `set P to P + e1 + … + ek` que vio texto (ver `TextChainDesc`).
    /// El miembro `m` de la tabla; `dst`, `a`, `b` los del `Binary` que reemplaza.
    TextChain { dst: Reg, a: Opnd, b: Opnd, m: u16 },
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
    /// F4.2: el salto hacia atrás de un `while` cuando hay nivel nativo. Cuenta vueltas (la cuenta
    /// regresiva de `chunk.loops[lp]`) y, caliente, entra al bucle compilado a mitad de camino
    /// (OSR). Si el bucle no se compila o no rinde, vuelve a ser `Jump`.
    /// F4.2b: también el fin de la vuelta de un `each` sin frame (`EachStepV`: los lugares
    /// `first..first + n` se sueltan antes); `n = 0` en un `while`.
    #[cfg(feature = "native-tier")]
    LoopBack { to: u32, lp: u16, first: u16, n: u16 },
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
    /// F4.8g: con `site` (no `NONE`), las claves son textos constantes: sólo los valores van en
    /// `first..` y las claves y su forma (calculada al compilar) están en `map_sites[site]`. Sin una
    /// variante aparte: una más en el `enum` movía el despacho entero +1,5 % (medido).
    MakeMap { dst: Reg, first: Reg, n: u16, site: u32 },
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
    /// F4.6a: la raíz de `set <camino> to v` (ver `PathDesc`): el contenedor de la variable, único
    /// como en `with_unique_binding`, a `c`. Si la raíz no es de las que la VM resuelve, corre el
    /// `SetPath` de antes (la referencia, con el valor ya evaluado) y salta al `done` de la
    /// descripción; como `TryInPlace`, no termina su bloque y descuenta antes su `rest`.
    PathRoot { c: Reg, desc: u32 },
    /// Un paso intermedio del camino: `[idx]` (`key == NONE`) o `.campo` (`key` = el nombre): `c`
    /// pasa a ser el lugar de adentro, único (`place_index_step`/`place_prop_step`).
    PathStep { c: Reg, idx: Opnd, key: u32, ic: u32 },
    /// La hoja: escribe el valor de la descripción en `c[idx]` o `c.campo` (`set_leaf_*`).
    PathSet { c: Reg, idx: Opnd, desc: u32 },
    /// `private(…)`, `print(…)` y los demás protegidos tienen que resolver al builtin de verdad; la
    /// referencia lo chequea antes de evaluar los argumentos.
    CheckProtected { func: Reg, name: u32 },
    /// Una llamada (F3.2): la función en `func`, los argumentos en `n` registros desde `args`. Si
    /// es una task compilada y todos van por posición, la VM entra al cuerpo sin recursión en
    /// Rust; si no, el camino de siempre (`call_value_named`).
    Call { dst: Reg, func: Reg, args: Reg, n: u16, site: u32 },
    /// F4.1b (quickening, como `CALL_BUILTIN_FAST` de CPython 3.11): un `Call` sin argumentos con
    /// nombre que vio un builtin sin `param_names`. Los mismos pasos observables que el camino
    /// genérico (aridad máxima, profundidad, `dispatch_builtin`, `pending_kwargs` vacío), sin armar
    /// pares nombre/valor ni copiar los argumentos dos veces. Si ya no encaja, vuelve a ser `Call`.
    CallBuiltin { dst: Reg, func: Reg, args: Reg, n: u16, site: u32 },
    /// F4.8c (quickening, como `CallBuiltin`): el `Call` de `set P to append(P, e)` (P una variable,
    /// la raíz en su `CallSite`) que vio el builtin `append`. Si el primer argumento es la lista que
    /// P sigue teniendo, se agrega en el lugar (`make_unique` de P y `push`: lo que hace la vía en el
    /// lugar de la referencia); si no, el builtin de siempre. Si ya no es `append`, vuelve a ser
    /// `Call`.
    AppendInPlace { dst: Reg, func: Reg, args: Reg, site: u32 },
    /// F4.1: un `Call` a una task que tiene código nativo (lo reescribe la VM cuando la task pasa
    /// el umbral). Si la task, los argumentos o las globales ya no encajan, vuelve a ser `Call`.
    #[cfg(feature = "native-tier")]
    CallNative { dst: Reg, func: Reg, args: Reg, n: u16, site: u32 },
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
    /// F4.6a: los `set` con camino.
    paths: Vec<PathDesc>,
    /// F4.8g: los mapas literales con claves constantes (`MakeMap` con sitio).
    map_sites: Box<[MapSite]>,
    /// F4.6c: las cadenas `set P to P + …` y sus `+`.
    text_chains: Box<[TextChainDesc]>,
    text_members: Box<[TextMember]>,
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
    /// Las cachés de `GetProp`/`GetIndex` (F3.6, por forma desde F4.5).
    key_ics: Box<[MapIc]>,
    /// Los recorridos hacia afuera de este cuerpo (ver `Hops`).
    hops: Vec<Hops>,
    /// Por slot de feedback (F3.4): cuántas veces se desoptimizó su operación.
    deopts: Box<[Cell<u8>]>,
    /// Reservado (calor/OSR): dónde empieza cada bucle.
    #[allow(dead_code)]
    loop_heads: Vec<u32>,
    /// F4.2: el estado de cada `LoopBack` (cuenta de vueltas, código nativo).
    #[cfg(feature = "native-tier")]
    loops: Box<[native::LoopState]>,
}

/// F4.8g: un mapa literal con claves de texto constantes: las claves en orden y su forma (`None` si
/// se repite alguna o una transición es megamórfica: el camino general, como `map_from_pair_slots`).
pub(crate) struct MapSite {
    keys: Box<[Key]>,
    shape: Option<ShapeRef>,
}

impl MapSite {
    /// El mapa con los valores de `vals` (los saca: quedan en `Nothing`).
    fn build(&self, vals: &mut [SynValue]) -> crate::types::MapRef {
        match &self.shape {
            Some(sh) => sh.build(vals.iter_mut().map(|v| std::mem::replace(v, SynValue::Nothing))),
            None => {
                // Con claves repetidas pueden quedar pocas: la capacidad no decide el modo.
                let mut m = SynMap::with_capacity(self.keys.len().min(MAX_SHAPED));
                for (k, v) in self.keys.iter().zip(vals.iter_mut()) {
                    m.insert(k, std::mem::replace(v, SynValue::Nothing));
                }
                m.into_ref()
            }
        }
    }
}

/// F4.6a: un `set` con camino que corre la VM (`PathRoot`/`PathStep`/`PathSet`).
#[derive(Clone, Copy, Debug)]
struct PathDesc {
    root: Root,
    /// El destino como nodo frío (con su spill): lo que corre la referencia si la raíz no es de
    /// las que resuelve la VM.
    node: u32,
    /// El valor, ya evaluado (en un registro o una constante: la referencia lo evalúa antes que
    /// el camino, así que no puede ser una lectura diferida).
    src: Opnd,
    dst: Reg,
    /// Al compilar, un label; en el chunk, la instrucción que sigue al `set`.
    done: u32,
    /// La hoja: `.campo` (el nombre) o `NONE` (`[idx]`), y su caché.
    key: u32,
    ic: u32,
    /// La ubicación del destino (el error de fuera de rango).
    target_loc: u32,
}

/// F4.6c: `set P to P + e1 + … + ek` con P una variable (`Root`, nunca `Slow`). Se compila como
/// siempre (los `+` son `Binary`, cada uno con su registro, vivo hasta el final de la sentencia);
/// la primera vez que la cabeza (`P + e1`) ve un texto con una pieza que se le suma, la cadena pasa
/// a `TextChain` (una vez, para siempre, como `BinaryAny`). Entonces el valor de P queda donde está
/// mientras se evalúan las piezas (una pieza que lo lee ve el viejo), la cabeza guarda un clon en
/// `old` y cada pieza queda en el registro de su `+`; el último agrega todas: en el
/// lugar si P sigue siendo el mismo texto y, soltado el clon, tiene un solo dueño; si no, el viejo
/// más las piezas, nuevo. Una pieza que no se suma a un texto (`text_add_piece`) arma en ese
/// momento el intermedio de la referencia y sigue `exec_binary`.
#[derive(Clone, Copy, Debug)]
struct TextChainDesc {
    root: Root,
    /// Con más de un `+`: el registro del valor viejo de P mientras la cadena corre en modo texto
    /// (vacío si no). Uno por cadena, reservado al comienzo del cuerpo (ninguna otra instrucción lo
    /// usa y ninguna llamada de adentro de una pieza lo pisa). Por eso nunca queda un valor de otra
    /// cadena: si tiene uno viejo (un `stop` cortó la cadena), la cadena ya es `TextChain` y su
    /// cabeza lo reescribe antes que nadie lo mire. `DISCARD` con un solo `+`.
    old: Reg,
    /// Sus miembros en `Chunk::text_members`, de la cabeza al último.
    first: u16,
    n: u16,
}

/// Un `+` de una cadena de texto: dónde está y el `Binary` que era.
#[derive(Clone, Copy, Debug)]
struct TextMember {
    pc: u32,
    chain: u16,
    dst: Reg,
    a: Opnd,
    b: Opnd,
    fb: u16,
}

/// Dónde está la variable raíz de un camino (ver `Place`).
#[derive(Clone, Copy, Debug)]
enum Root {
    Param(Reg),
    Win(u16),
    Local(u16),
    /// Por nombre con la caché del slot (`ic`, la de `LoadName`).
    Free { name: u32, ic: u32 },
    /// La referencia (un frame de afuera: raro en código caliente).
    Slow,
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
    /// F4.8c: la variable P de `set P to append(P, e)` (ver `Ins::AppendInPlace`).
    append: Option<Root>,
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
    /// F4: el nivel nativo de esta task (cuántas llamadas lleva, y su código compilado).
    #[cfg(feature = "native-tier")]
    native: native::NativeState,
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
        // F4.6c: un registro por cadena de texto de más de un `+`, antes que cualquier otro (así
        // ninguna llamada de adentro de una pieza lo pisa: su ventana empieza más arriba).
        let long_chains: usize = match &body {
            Body::Program(stmts) => stmts.iter().map(long_text_chains).sum(),
            Body::Task(stmts) => stmts.iter().map(|s| long_text_chains(s)).sum(),
            Body::Lambda(_) => 0,
        };
        let long_chains = u16::try_from(long_chains).unwrap_or(0);
        c.text_regs = (c.next_reg, long_chains);
        for _ in 0..long_chains {
            c.reg();
        }
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
    /// Cuántos `LoopBack` emitió (F4.2).
    #[cfg_attr(not(feature = "native-tier"), allow(dead_code))]
    nloops: u16,
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
    paths: Vec<PathDesc>,
    map_sites: Vec<MapSite>,
    text_chains: Vec<TextChainDesc>,
    text_members: Vec<TextMember>,
    /// Los registros reservados para las cadenas de más de un `+` (el primero y cuántos quedan).
    text_regs: (Reg, u16),
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
            nloops: 0,
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
            paths: Vec::new(),
            map_sites: Vec::new(),
            text_chains: Vec::new(),
            text_members: Vec::new(),
            text_regs: (0, 0),
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

    /// El salto hacia atrás de un `while`: `LoopBack` si hay nivel nativo (F4.2), si no el `Jump`
    /// de siempre (sin nivel nativo el despacho no paga nada por el OSR).
    fn loop_back(&mut self, head: u32) {
        #[cfg(feature = "native-tier")]
        if crate::native_tier::tier().is_some() {
            let lp = self.nloops;
            self.nloops += 1;
            self.emit(Ins::LoopBack { to: head, lp, first: 0, n: 0 });
            return;
        }
        self.emit(Ins::Jump { to: head });
    }

    /// El fin de la vuelta de un `each` sin frame (F4.2b): `LoopBack` con los lugares que suelta si
    /// hay nivel nativo; si no, el `EachStepV` de siempre.
    fn each_back(&mut self, head: u32, first: u16, n: u16) {
        #[cfg(feature = "native-tier")]
        if crate::native_tier::tier().is_some() {
            let lp = self.nloops;
            self.nloops += 1;
            self.emit(Ins::LoopBack { to: head, lp, first, n });
            return;
        }
        self.emit(Ins::EachStepV { head, first, n });
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
                // F4.8c: `set P to append(P, e)` con P de las que la VM encuentra: el camino normal,
                // y su `Call` agrega en el lugar (`AppendInPlace`). Si no, la vía de la referencia.
                let append = if append_shape(target, value) {
                    match self.place(self.target(target)) {
                        Place::Param(r) => Some(Root::Param(r)),
                        Place::Win(k) => Some(Root::Win(k)),
                        Place::Local(k) => Some(Root::Local(k)),
                        Place::Free => {
                            let nm = self.name(name);
                            Some(Root::Free { name: nm, ic: self.ic() })
                        }
                        Place::Outer(..) => None,
                    }
                } else {
                    None
                };
                let done = if append.is_none() && in_place_shape(target, value) {
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
                let v = self.set_value(target, name, value);
                if let Some(root) = append {
                    // La última instrucción del valor es el `Call` de `append`.
                    if let Some(Ins::Call { site, .. }) = self.code.last() {
                        self.sites[*site as usize].append = Some(root);
                    }
                }
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
                if set_root_identifier(target).is_some() {
                    self.set_path(n, target, v, dst);
                } else {
                    let node = self.cold_spilled(target);
                    self.at(&n.location);
                    self.emit(Ins::SetPath { src: v, node, dst });
                }
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
                self.loop_back(head);
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
        self.each_back(head, first, count);
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
                self.sites.push(CallSite { names: None, checked: true, append: None });
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

    /// El valor de `set P to value` con P una variable: una cadena de texto (F4.6c) si `value` es
    /// `P + e1 + … + ek` y P está donde la VM la escribe; si no, la expresión de siempre.
    fn set_value(&mut self, target: &Node, name: &str, value: &Node) -> Opnd {
        let k = text_chain_len(value, name);
        if k == 0 || (k > 1 && self.text_regs.1 == 0) {
            return self.expr(value);
        }
        let root = match self.place(self.target(target)) {
            Place::Param(r) => Root::Param(r),
            Place::Win(s) => Root::Win(s),
            Place::Local(s) => Root::Local(s),
            Place::Free => {
                let name = self.name(name);
                Root::Free { name, ic: self.ic() }
            }
            Place::Outer(..) => return self.expr(value),
        };
        let old = if k > 1 {
            let (r, left) = self.text_regs;
            self.text_regs = (r + 1, left - 1);
            r
        } else {
            DISCARD
        };
        let chain = u16::try_from(self.text_chains.len()).expect("demasiadas cadenas de texto");
        let first = u16::try_from(self.text_members.len()).expect("demasiadas cadenas de texto");
        self.text_chains.push(TextChainDesc { root, old, first, n: k as u16 });
        self.text_link(value, chain, k)
    }

    /// Un `+` de la cadena (`k` = cuántos quedan hasta P, éste incluido): exactamente lo que
    /// compila `expr_in` para un `BinaryOp` (mismos pasos, registros y orden), anotado.
    fn text_link(&mut self, n: &Node, chain: u16, k: usize) -> Opnd {
        let NodeKind::BinaryOp { left, operator, right } = &n.kind else { unreachable!("cadena sin +") };
        self.at(&n.location);
        self.enter();
        let a = if k > 1 { self.text_link(left, chain, k - 1) } else { self.expr(left) };
        let a = self.keep_until(a, right);
        let b = self.expr(right);
        self.at(&n.location);
        let dst = self.reg();
        let fb = self.feedback;
        self.feedback = self.feedback.saturating_add(1);
        self.text_members.push(TextMember { pc: self.code.len() as u32, chain, dst, a, b, fb });
        self.emit(Ins::Binary { dst, op: *operator, a, b, fb });
        Opnd::Reg(dst)
    }

    /// F4.6a: `set <raíz><pasos> to v` con la raíz una variable, en el orden de la referencia
    /// (`exec_set` → `exec_place`): el valor ya evaluado, la raíz, y por cada paso su índice y el
    /// paso; la hoja escribe. Los nodos del destino no cuentan pasos (la referencia tampoco); los
    /// índices, sí, por su código.
    fn set_path(&mut self, n: &Node, target: &Node, v: Opnd, dst: Reg) {
        // La referencia tiene el valor en la mano antes de recorrer el camino (con él, su cuenta
        // de referencias, que decide los `make_unique`): una lectura de variable se toma ya.
        let src = match v {
            Opnd::Reg(_) | Opnd::Const(_) => v,
            other => Opnd::Reg(self.to_reg(other)),
        };
        // Los pasos, de la raíz a la hoja.
        let mut steps: Vec<&Node> = Vec::new();
        let mut cur = target;
        let root_name = loop {
            match &cur.kind {
                NodeKind::Identifier { name } => break name,
                NodeKind::IndexAccess { object, .. } | NodeKind::PropertyAccess { object, .. } => {
                    steps.push(cur);
                    cur = object;
                }
                _ => unreachable!("raíz sin variable"),
            }
        };
        steps.reverse();
        let root = match self.place(self.target(cur)) {
            Place::Param(r) => Root::Param(r),
            Place::Win(k) => Root::Win(k),
            Place::Local(k) => Root::Local(k),
            Place::Free => {
                let name = self.name(root_name);
                Root::Free { name, ic: self.ic() }
            }
            Place::Outer(..) => Root::Slow,
        };
        let node = self.cold_spilled(target);
        let done = self.label();
        let c = self.reg();
        self.at(&target.location);
        let target_loc = self.cur_loc;
        let desc = self.paths.len() as u32;
        self.paths.push(PathDesc { root, node, src, dst, done, key: NONE, ic: NONE, target_loc });
        self.at(&n.location);
        self.emit(Ins::PathRoot { c, desc });
        let last = steps.len() - 1;
        for (i, st) in steps.iter().enumerate() {
            let (idx, key) = match &st.kind {
                NodeKind::IndexAccess { index, .. } => (self.expr(index), NONE),
                NodeKind::PropertyAccess { property_name, .. } => (Opnd::Const(0), self.name(property_name)),
                _ => unreachable!(),
            };
            let ic = self.key_ic();
            if i == last {
                let d = &mut self.paths[desc as usize];
                d.key = key;
                d.ic = ic;
                self.at(&n.location);
                self.emit(Ins::PathSet { c, idx, desc });
            } else {
                // La ubicación del paso (sus errores, como en `exec_place`).
                self.at(&st.location);
                self.emit(Ins::PathStep { c, idx, key, ic });
            }
        }
        self.bind(done);
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
            // F4.8g: con claves de texto constantes, sólo los valores van a registros; las claves y su
            // forma quedan en el sitio (evaluar un literal no hace nada más que su paso: se cuenta
            // igual, en el mismo orden).
            K::MapLiteral { pairs } if !pairs.is_empty() && pairs.len() <= MAX_SHAPED && pairs.iter().all(|(k, _)| matches!(k.kind, K::TextLiteral { .. })) => {
                self.enter();
                let first = self.block_regs(pairs.len());
                let end = first + pairs.len() as Reg;
                let mut keys = Vec::with_capacity(pairs.len());
                for (i, (k, v)) in pairs.iter().enumerate() {
                    let K::TextLiteral { value } = &k.kind else { unreachable!("clave de texto") };
                    self.enter();
                    keys.push(Key::from(value.as_str()));
                    self.into_reg(v, first + i as Reg, end);
                }
                self.at(&n.location);
                let dst = self.dst(want);
                let site = self.map_sites.len() as u32;
                let keys_len = keys.len() as u16;
                let shape = ShapeRef::of_keys(keys.len(), |i| keys[i].clone());
                self.map_sites.push(MapSite { keys: keys.into_boxed_slice(), shape });
                self.emit(Ins::MakeMap { dst, first, n: keys_len, site });
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
                self.emit(Ins::MakeMap { dst, first, n: pairs.len() as u16, site: NONE });
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
                            self.sites.push(CallSite { names: None, checked: false, append: None });
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
        self.sites.push(CallSite { names, checked, append: None });
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
                #[cfg(feature = "native-tier")]
                Ins::LoopBack { to, .. } => {
                    leader[target(&self.labels, to)] = true;
                    leader[i + 1] = true;
                }
                // F3.5: no corta el bloque (lo común es que no aplique y siga en línea); cuando llama
                // a la referencia descuenta antes lo que el bloque sumó de más (ver el despacho).
                Ins::TryInPlace { done, .. } => {
                    leader[target(&self.labels, done)] = true;
                }
                Ins::SetPath { .. } => leader[i + 1] = true,
                // Como `TryInPlace`: no corta el bloque; su salida (la referencia) va a `done`.
                Ins::PathRoot { desc, .. } => {
                    leader[target(&self.labels, self.paths[desc as usize].done)] = true;
                }
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
                Ins::Exec { .. } | Ins::Call { .. } | Ins::CallBuiltin { .. } => leader[i + 1] = true,
                #[cfg(feature = "native-tier")]
                Ins::CallNative { .. } => leader[i + 1] = true,
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
        // Dónde quedó cada instrucción (no su bloque: un salto al comienzo cae en el `Steps`).
        let mut placed = vec![NONE; n];
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
                placed[k] = code.len() as u32;
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
                #[cfg(feature = "native-tier")]
                Ins::LoopBack { to, .. } => *to = map(*to, &self.labels),
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
        for p in self.paths.iter_mut() {
            p.done = map(p.done, &self.labels);
        }
        for m in self.text_members.iter_mut() {
            m.pc = placed[m.pc as usize];
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
            paths: self.paths,
            map_sites: self.map_sites.into_boxed_slice(),
            text_chains: self.text_chains.into_boxed_slice(),
            text_members: self.text_members.into_boxed_slice(),
            nregs: self.max_reg,
            ics: (0..self.ics).map(|_| Cell::new(0)).collect(),
            ic_here: self.ic_hops.iter().map(|&h| self.hops[h as usize].from.is_none()).collect(),
            key_ics: (0..self.key_ics).map(|_| MapIc::default()).collect(),
            ic_hops: self.ic_hops,
            hops: self.hops,
            deopts: (0..=self.feedback as usize).map(|_| Cell::new(0)).collect(),
            loop_heads,
            #[cfg(feature = "native-tier")]
            loops: (0..self.nloops).map(|_| native::LoopState::default()).collect(),
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

/// F4.8c: `append(P, e)` sobre la variable P (dos argumentos por posición, la función por nombre).
fn append_shape(target: &Node, value: &Node) -> bool {
    match &value.kind {
        NodeKind::TaskCall { name, arguments } => {
            name.as_identifier() == Some("append") && arguments.len() == 2 && arguments.iter().all(|a| a.name.is_none()) && same_place(&arguments[0].value, target)
        }
        _ => false,
    }
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

/// F4.6c: cuántos `+` tiene `value` si es `P + e1 + … + ek` (asociativo a izquierda, P abajo de
/// todo); 0 si no.
fn text_chain_len(value: &Node, p: &str) -> usize {
    let mut k = 0;
    let mut cur = value;
    loop {
        match &cur.kind {
            NodeKind::BinaryOp { left, operator, .. } if *operator == BinOp::Add => {
                k += 1;
                cur = left;
            }
            NodeKind::Identifier { name } if k > 0 && **name == *p => return k,
            _ => return 0,
        }
    }
}

/// Cuántas sentencias de este cuerpo (sin entrar a tasks ni lambdas: son otros chunks) son cadenas
/// de texto de más de un `+` (las que el compilador visita: si contara de menos, esas cadenas quedan
/// como `Binary`).
fn long_text_chains(n: &Node) -> usize {
    use NodeKind as K;
    let block = |b: &[Node]| b.iter().map(long_text_chains).sum::<usize>();
    match &n.kind {
        K::SetMutation { target, value } => match &target.kind {
            K::Identifier { name } => usize::from(text_chain_len(value, name) > 1),
            _ => 0,
        },
        K::WhenStatement { body, otherwise, otherwise_when, .. } => {
            block(body) + otherwise.as_deref().map_or(0, block) + otherwise_when.as_deref().map_or(0, long_text_chains)
        }
        K::WhileStatement { body, .. } | K::EachStatement { body, .. } => block(body),
        K::MatchStatement { arms, otherwise, .. } => {
            arms.iter().map(|a| match &a.kind {
                K::MatchArm { body, .. } => block(body),
                _ => 0,
            }).sum::<usize>()
                + otherwise.as_deref().map_or(0, block)
        }
        _ => 0,
    }
}

// =============================================================================================
// Ejecución
// =============================================================================================


/// F4.8g: las llamadas de un builtin a una función por elemento (`apply`, `where`, `reduce`, …), de a
/// una como `call_fast`. Con código nativo, una sesión (`native::LambdaFast`): el contexto se arma una
/// vez y el elemento entra prestado de la lista. Lo que no encaja va por `call_fast`.
pub(crate) struct LambdaCall<'a> {
    f: &'a SynValue,
    /// La task (si la VM puede correrla: ni la referencia ni etiquetas) y el flag de cancelación.
    #[cfg(feature = "native-tier")]
    task: Option<&'a Rc<SynTaskValue>>,
    #[cfg(feature = "native-tier")]
    flag: &'a std::sync::atomic::AtomicBool,
    /// La sesión: se arma cuando la task ya tiene código nativo (lo compila una de las primeras
    /// llamadas, por `call_fast`); `off` si no se puede o se terminó (no se vuelve a intentar).
    #[cfg(feature = "native-tier")]
    fast: Option<native::LambdaFast<'a>>,
    #[cfg(feature = "native-tier")]
    off: bool,
}

impl<'a> LambdaCall<'a> {
    /// Por la sesión, si la hay (o si ya se puede armar); `None`: por `call_fast`.
    #[cfg(feature = "native-tier")]
    #[inline]
    fn native(&mut self, it: &mut Interpreter, pre: Option<&SynValue>, l: &ListRef, i: usize) -> Option<Result<SynValue, Control>> {
        if self.fast.is_none() {
            if self.off {
                return None;
            }
            let t: &'a Rc<SynTaskValue> = self.task?;
            if !t.code.native.ready() {
                return None;
            }
            self.fast = it.vm_lambda_session(t, self.flag);
            if self.fast.is_none() {
                self.off = true;
                return None;
            }
        }
        let r = native::LambdaFast::call(&mut self.fast, it, pre, l, i);
        if self.fast.is_none() {
            self.off = true;
        }
        r
    }

    /// `f(l[i])`.
    pub(crate) fn item(&mut self, it: &mut Interpreter, l: &ListRef, i: usize, loc: &SourceLocation) -> Result<SynValue, Control> {
        #[cfg(feature = "native-tier")]
        if let Some(r) = self.native(it, None, l, i) {
            return r;
        }
        let item = l.borrow().get(i).expect("dentro del largo");
        it.call_fast(self.f, &mut [item], loc)
    }

    /// `f(l[i])` y el elemento (`where`, `find_first`, `sort_by`). La lista es la que tiene el builtin
    /// (una escritura del cuerpo copia): el elemento es el mismo antes o después de la llamada.
    pub(crate) fn item_keep(&mut self, it: &mut Interpreter, l: &ListRef, i: usize, loc: &SourceLocation) -> Result<(SynValue, SynValue), Control> {
        #[cfg(feature = "native-tier")]
        if let Some(r) = self.native(it, None, l, i) {
            return r.map(|r| (l.borrow().get(i).expect("dentro del largo"), r));
        }
        let item = l.borrow().get(i).expect("dentro del largo");
        let r = it.call_fast(self.f, &mut [item.clone()], loc)?;
        Ok((item, r))
    }

    /// `f(acc, l[i])` (`reduce`).
    pub(crate) fn acc_item(&mut self, it: &mut Interpreter, acc: SynValue, l: &ListRef, i: usize, loc: &SourceLocation) -> Result<SynValue, Control> {
        #[cfg(feature = "native-tier")]
        if let Some(r) = self.native(it, Some(&acc), l, i) {
            return r;
        }
        let item = l.borrow().get(i).expect("dentro del largo");
        it.call_fast(self.f, &mut [acc, item], loc)
    }
}

/// Agranda la ventana de registros a `len` con `Nothing` construidos en el lugar: `resize` clona el
/// relleno (el `match` entero de `SynValue::clone` por registro, en cada llamada de la VM).
#[inline]
fn grow_regs(regs: &mut Vec<SynValue>, len: usize) {
    if let Some(k) = len.checked_sub(regs.len()) {
        regs.extend(std::iter::repeat_with(|| SynValue::Nothing).take(k));
    }
}

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

    /// El cuerpo de una ruta de `serve` por la VM, en el scope de la request (`env`, hijo del
    /// global o del módulo que la montó). Compila como el programa: las variables del cuerpo van a
    /// ese scope, los nombres de afuera se buscan subiendo, `give` sale como `Control::Give` y el
    /// final del cuerpo como `Ok` — lo mismo que `exec_block`, que es lo que `serve` distingue
    /// (respuesta con cuerpo o sin cuerpo).
    pub(super) fn run_request_chunk(&mut self, stmts: &[Node], env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let chunk = self.request_chunk(stmts);
        self.run_chunk(&chunk, env)
    }

    /// El chunk del cuerpo de una ruta, compilado la primera vez que este intérprete lo corre.
    /// La clave es la dirección y el largo del cuerpo; como un cuerpo temporal (el de un socket se
    /// arma en cada conexión) puede dejar otro distinto en la misma dirección, se reusa sólo si el
    /// cuerpo guardado es IGUAL al de ahora. Con muchos cuerpos distintos (temporales), se vacía.
    fn request_chunk(&mut self, stmts: &[Node]) -> Rc<Chunk> {
        const MAX: usize = 512;
        let key = (stmts.as_ptr() as usize, stmts.len());
        if let Some((body, chunk)) = self.vm_request_chunks.get(&key) {
            if body.as_slice() == stmts {
                return chunk.clone();
            }
        }
        let chunk = compile_program(stmts);
        if self.vm_request_chunks.len() >= MAX {
            self.vm_request_chunks.clear();
        }
        self.vm_request_chunks.insert(key, (stmts.to_vec(), chunk.clone()));
        chunk
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
        grow_regs(&mut self.vm_regs, base + chunk.nregs as usize);
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
        grow_regs(&mut self.vm_regs, base + chunk.nregs as usize);
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

    #[inline(always)]
    fn run_chunk_at(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>, base: usize) -> Result<SynValue, Control> {
        self.run_chunk_from(chunk, env, base, 0, None)
    }

    /// Los frames de un cuerpo que vuelve del código nativo (ver `run_chunk_from`), fuera de línea:
    /// el despacho no cambia. Dónde empiezan los iteradores del de más adentro y los del de más afuera.
    #[inline(never)]
    fn vm_resume_frames(&mut self, (frames, ib, outer): (Vec<VmFrame>, usize, usize)) -> (usize, usize) {
        self.vm_frames.extend(frames);
        (ib, outer)
    }

    /// `run_chunk_at` desde la instrucción `pc0` (F4.8b). `resume`: un cuerpo que salió del código
    /// nativo a mitad de camino (ver `vm_call_rust`): los frames que esperan a su llamado, arriba de
    /// los de quien llama, y dónde empiezan los iteradores del de más adentro y los del de más afuera.
    fn run_chunk_from(
        &mut self,
        chunk: &Rc<Chunk>,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        pc0: usize,
        resume: Option<(Vec<VmFrame>, usize, usize)>,
    ) -> Result<SynValue, Control> {
        // El chunk, el frame y la ventana de registros cambian al entrar a una llamada y al volver
        // (F3.2); `entry` es cuántas llamadas de la VM había al empezar: las de arriba son nuestras.
        let mut chunk = chunk.clone();
        let mut env = env.clone();
        let mut base = base;
        let entry = self.vm_frames.len();
        let mut pc = pc0;
        // Frames de la VM abiertos dentro de este cuerpo (vueltas de `each`, brazos de `match`) y
        // dónde empiezan sus iteradores.
        let mut depth: u16 = 0;
        let mut iter_base = self.vm_iters.len();
        let mut entry_iters = iter_base;
        if let Some(r) = resume {
            (iter_base, entry_iters) = self.vm_resume_frames(r);
        }
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
                Ins::MakeMap { dst, first, n, site } => {
                    self.vm_make_map(&chunk, base, dst, first, n, site);
                    Ok(())
                }
                Ins::GetProp { dst, obj, name, ic } => (|| {
                    let o = self.opnd(&chunk, &env, base, obj, at)?;
                    let found = match &o {
                        SynValue::Map(m) => m.borrow().get_cached(&chunk.names[name as usize], &chunk.key_ics[ic as usize]).cloned(),
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
                        (SynValue::Map(m), SynValue::Text(k)) => m.borrow().get_cached_key(k, &chunk.key_ics[ic as usize]).cloned(),
                        (SynValue::List(l), SynValue::Number(Number::Int(k))) => {
                            let items = l.borrow();
                            resolve_index(*k, items.len()).and_then(|j| items.get(j))
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
                Ins::PathRoot { c, desc } => match self.vm_path_root(&chunk, &env, base, c, desc, at) {
                    Ok(Some(j)) => {
                        pc = j;
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(c) => Err(c),
                },
                Ins::PathStep { c, idx, key, ic } => self.vm_path_step(&chunk, &env, base, c, idx, key, ic, at),
                Ins::PathSet { c, idx, desc } => self.vm_path_set(&chunk, &env, base, c, idx, desc, at),
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
                Ins::TextChain { dst, a, b, m } => self.vm_text_chain(&chunk, &env, base, at, dst, a, b, m),
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
                #[cfg(feature = "native-tier")]
                Ins::LoopBack { to, lp, first, n } => {
                    if n > 0 {
                        // El fin de la vuelta de un `each`: como `EachStepV`.
                        let k = self.vm_lbase + first as usize;
                        for x in &mut self.vm_locals[k..k + n as usize] {
                            *x = None;
                        }
                    }
                    pc = to as usize;
                    let mut r = Ok(());
                    if chunk.loops[lp as usize].tick() {
                        match self.vm_loop_hot(&chunk, &env, base, iter_base, at, lp) {
                            native::OsrStep::Stay => {}
                            native::OsrStep::Exit(p) => pc = p,
                            native::OsrStep::Fail(c) => r = Err(c),
                            native::OsrStep::Resume { r, pc: back, dst: rdst } => {
                                // Salió a mitad de una llamada: este frame espera su resultado
                                // (como en `CallNative`) y la VM sigue en el de más adentro.
                                let native::Resume { frames, enter, pc: at_pc, top0, iter_base: ib } = *r;
                                let caller = VmFrame {
                                    chunk: std::mem::replace(&mut chunk, enter.code),
                                    env: std::mem::replace(&mut env, enter.env),
                                    base,
                                    pc: back,
                                    dst: rdst,
                                    depth: std::mem::replace(&mut depth, 0),
                                    iter_base: std::mem::replace(&mut iter_base, ib),
                                    lbase: std::mem::replace(&mut self.vm_lbase, enter.lbase),
                                    top: top0,
                                };
                                self.vm_frames.push(caller);
                                self.vm_frames.extend(frames);
                                base = enter.base;
                                pc = at_pc;
                            }
                        }
                    }
                    r
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
                    match self.vm_try_in_place(&chunk, &env, base, at, dst, node, name, ic, slot) {
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
                #[cfg(feature = "native-tier")]
                Ins::CallNative { dst, func, args, n, site } => match self.vm_call_native(&chunk, base, at, dst, func, args, n, site) {
                    Ok(native::NativeStep::Done) => Ok(()),
                    // No pudo entrar (y no tocó nada): la instrucción ya volvió a ser `Call` y se
                    // repite como tal.
                    Ok(native::NativeStep::Retry) => {
                        pc = at;
                        Ok(())
                    }
                    Ok(native::NativeStep::Resume(r)) => {
                        // Salió a la VM a mitad de camino: el que llamó, los frames nativos de
                        // afuera esperando a su llamado, y la VM sigue en el de más adentro.
                        let native::Resume { frames, enter, pc: at_pc, top0, iter_base: ib } = *r;
                        let caller = VmFrame {
                            chunk: std::mem::replace(&mut chunk, enter.code),
                            env: std::mem::replace(&mut env, enter.env),
                            base,
                            pc,
                            dst,
                            depth: std::mem::replace(&mut depth, 0),
                            iter_base: std::mem::replace(&mut iter_base, ib),
                            lbase: std::mem::replace(&mut self.vm_lbase, enter.lbase),
                            top: top0,
                        };
                        self.vm_frames.push(caller);
                        self.vm_frames.extend(frames);
                        base = enter.base;
                        pc = at_pc;
                        Ok(())
                    }
                    Err(c) => Err(c),
                },
                Ins::CallBuiltin { dst, func, args, n, site } => match self.vm_call_builtin(&chunk, base, at, dst, func, args, n, site) {
                    Ok(true) => Ok(()),
                    // Ya no encaja (y no tocó nada): volvió a ser `Call` y se repite como tal.
                    Ok(false) => {
                        pc = at;
                        Ok(())
                    }
                    Err(c) => Err(c),
                },
                Ins::AppendInPlace { dst, func, args, site } => match self.vm_append_in_place(&chunk, &env, base, at, dst, func, args, site) {
                    Ok(true) => Ok(()),
                    Ok(false) => {
                        pc = at;
                        Ok(())
                    }
                    Err(c) => Err(c),
                },
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
            None if op == BinOp::Add && !chunk.text_members.is_empty() => {
                if self.vm_text_quicken(chunk, env, base, at, a, b, fb) {
                    // Esta vez, el camino genérico (la cadena corre en modo texto desde la próxima).
                    return self.vm_binary_generic(chunk, env, base, at, dst, op, a, b);
                }
                None
            }
            None => None,
        };
        chunk.code[at].set(quick.unwrap_or(Ins::BinaryAny { dst, op, a, b }));
        self.vm_binary_generic(chunk, env, base, at, dst, op, a, b)
    }

    /// F4.6c: si el `+` de `at` es la cabeza de una cadena de texto que ve un texto y una pieza que
    /// se le suma, la cadena entera pasa a `TextChain` (para siempre, como `BinaryAny`).
    #[allow(clippy::too_many_arguments)]
    fn vm_text_quicken(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, at: usize, a: Opnd, b: Opnd, fb: u16) -> bool {
        let Some(m) = chunk.text_members.iter().position(|x| x.pc as usize == at) else { return false };
        let ch = chunk.text_chains[chunk.text_members[m].chain as usize];
        if m != ch.first as usize || chunk.deopts[fb as usize].get() > MAX_DEOPTS {
            return false;
        }
        let fits = self.peek_with(chunk, env, base, a, |v| matches!(v, Some(SynValue::Text(_))))
            && self.peek_with(chunk, env, base, b, |v| v.is_some_and(text_addable));
        if !fits {
            return false;
        }
        for j in ch.first..ch.first + ch.n {
            let x = chunk.text_members[j as usize];
            chunk.code[x.pc as usize].set(Ins::TextChain { dst: x.dst, a: x.a, b: x.b, m: j });
        }
        true
    }

    /// Mira un operando sin moverlo ni clonarlo (`None`: un hueco).
    fn peek_with<R>(&self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, o: Opnd, f: impl FnOnce(Option<&SynValue>) -> R) -> R {
        match o {
            Opnd::Reg(r) | Opnd::Copy(r) => f(Some(&self.vm_regs[base + r as usize])),
            Opnd::Const(k) => f(Some(&chunk.consts[k as usize])),
            Opnd::RLocal(k) => f(self.vm_locals[self.vm_lbase + k as usize].as_ref()),
            Opnd::Local(k) => f(env.borrow().bindings.slot(k as usize)),
        }
    }

    /// `TextChain` (F4.6c, ver `TextChainDesc`).
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_text_chain(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        at: usize,
        dst: Reg,
        a: Opnd,
        b: Opnd,
        m: u16,
    ) -> Result<(), Control> {
        let mem = chunk.text_members[m as usize];
        let ch = chunk.text_chains[mem.chain as usize];
        let i = m - ch.first;
        let last = i + 1 == ch.n;
        let loc = &chunk.locs[chunk.loc[at] as usize];
        if i == 0 {
            // La cabeza: P y la primera pieza, en el orden de la referencia.
            let p = self.opnd(chunk, env, base, a, at)?;
            let x = self.opnd(chunk, env, base, b, at)?;
            if ch.old != DISCARD {
                self.vm_regs[base + ch.old as usize] = SynValue::Nothing;
            }
            let head_fb = mem.fb as usize;
            match p {
                SynValue::Text(old) if text_addable(&x) && chunk.deopts[head_fb].get() <= MAX_DEOPTS => {
                    if last {
                        self.vm_text_finish(chunk, env, base, ch, m, dst, old, x);
                    } else {
                        self.vm_regs[base + ch.old as usize] = SynValue::Text(old);
                        self.put(base, dst, x);
                    }
                    Ok(())
                }
                p => {
                    // P no es texto, o la pieza no se le suma: el `+` de siempre (y la cadena
                    // entera, genérica esta vez). Cuenta como desoptimización.
                    let n = &chunk.deopts[head_fb];
                    n.set(n.get().saturating_add(1));
                    let v = self.exec_binary(p, BinOp::Add, x, loc)?;
                    self.put(base, dst, v);
                    Ok(())
                }
            }
        } else {
            let old_at = base + ch.old as usize;
            if !matches!(self.vm_regs[old_at], SynValue::Text(_)) {
                // La cabeza corrió genérica: éste también.
                return self.vm_binary_generic(chunk, env, base, at, dst, BinOp::Add, a, b);
            }
            let x = self.opnd(chunk, env, base, b, at)?;
            if text_addable(&x) {
                if last {
                    let SynValue::Text(old) = std::mem::replace(&mut self.vm_regs[old_at], SynValue::Nothing) else { unreachable!() };
                    self.vm_text_finish(chunk, env, base, ch, m, dst, old, x);
                } else {
                    self.put(base, dst, x);
                }
                return Ok(());
            }
            // Una pieza que no se suma a un texto: en este momento, el intermedio de la referencia
            // (P vieja + las piezas hasta acá) y su `+`, con su resultado o su error.
            let SynValue::Text(mut t) = std::mem::replace(&mut self.vm_regs[old_at], SynValue::Nothing) else { unreachable!() };
            for j in ch.first..m {
                let r = base + chunk.text_members[j as usize].dst as usize;
                let piece = std::mem::replace(&mut self.vm_regs[r], SynValue::Nothing);
                let added = text_add_piece(&mut t, &piece);
                debug_assert!(added);
            }
            let n = &chunk.deopts[chunk.text_members[ch.first as usize].fb as usize];
            n.set(n.get().saturating_add(1));
            let v = self.exec_binary(SynValue::Text(t), BinOp::Add, x, loc)?;
            self.put(base, dst, v);
            Ok(())
        }
    }

    /// El último `+` de una cadena en modo texto: las piezas (las de los registros de los `+`
    /// anteriores y `x`) se agregan al texto de P si sigue siendo el viejo (en el lugar si, soltado
    /// el clon `old`, tiene un solo dueño: `push_str`); si no, a `old`. El resultado va a `dst` y el
    /// `set` que sigue lo escribe como siempre.
    #[allow(clippy::too_many_arguments)]
    fn vm_text_finish(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, ch: TextChainDesc, m: u16, dst: Reg, old: SynText, x: SynValue) {
        let mut pieces: SmallVec<[SynValue; 4]> = SmallVec::new();
        for j in ch.first..m {
            let r = base + chunk.text_members[j as usize].dst as usize;
            pieces.push(std::mem::replace(&mut self.vm_regs[r], SynValue::Nothing));
        }
        pieces.push(x);
        let mut old = Some(old);
        let add = |t: &mut SynText, pieces: &[SynValue]| {
            for p in pieces {
                let added = text_add_piece(t, p);
                debug_assert!(added);
            }
        };
        let in_place = self.vm_text_slot(chunk, env, base, ch.root, |slot| match slot {
            SynValue::Text(t) if SynText::same(t, old.as_ref().expect("viejo")) => {
                drop(old.take());
                add(t, &pieces);
                Some(slot.clone())
            }
            _ => None,
        });
        let v = match in_place.flatten() {
            Some(v) => v,
            None => {
                let mut t = old.take().expect("viejo");
                add(&mut t, &pieces);
                SynValue::Text(t)
            }
        };
        self.put(base, dst, v);
    }

    /// El lugar de P, si está donde lo escribe la VM (un hueco o una global que no está en el
    /// primer frame de su búsqueda: `None`, y el `set` resuelve como siempre).
    fn vm_text_slot<R>(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, root: Root, f: impl FnOnce(&mut SynValue) -> R) -> Option<R> {
        match root {
            Root::Param(r) => Some(f(&mut self.vm_regs[base + r as usize])),
            Root::Win(k) => self.vm_locals[self.vm_lbase + k as usize].as_mut().map(f),
            Root::Local(k) => env.borrow_mut().bindings.slot_mut(k as usize).map(f),
            Root::Free { name, ic } => {
                let start = self.free_start(chunk, env, chunk.hops[chunk.ic_hops[ic as usize] as usize]);
                let mut e = start.borrow_mut();
                e.bindings.get_cached_mut(&chunk.names[name as usize], &chunk.ics[ic as usize]).map(f)
            }
            Root::Slow => None,
        }
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
        at: usize,
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
        let r = if spill != NONE {
            // La vía en el lugar es de la referencia y busca por nombre: las variables de la
            // ventana van a frames el rato que corre (ver `vm_spill`).
            let frames = self.vm_spill(chunk, env, base, spill);
            let r = self.try_update_in_place(target, value, frames.last().expect("spill vacío"));
            self.vm_unspill(chunk, base, spill, frames);
            r
        } else {
            self.try_update_in_place(target, value, env)
        };
        match r? {
            Some(v) => {
                self.put(base, dst, v);
                Ok(true)
            }
            None => {
                // F4.8d: `set <camino> to <camino> + e` que no aplicó (el valor no era una lista): la
                // vía en el lugar no se vuelve a probar (una vez y para siempre, como `BinaryAny`). Es
                // sólo un atajo (su resultado y sus pasos son los del camino normal, que es lo que
                // corre el modo referencia): si más adelante ese lugar tuviera una lista, se copia en
                // vez de agregar en el lugar. Así un `set p.x to p.x + d` con números no llama al
                // tree-walker en cada vuelta, y el bucle puede pasar al nivel nativo.
                if name == NONE && matches!(value.kind, NodeKind::BinaryOp { .. }) {
                    chunk.code[at].set(Ins::Nop);
                }
                Ok(false)
            }
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

    /// `PathRoot` (F4.6a): la raíz la resuelve la VM (lo común: `Ok(None)`, sigue el camino) o corre
    /// la referencia entera y `Ok(Some(done))`; entonces los pasos que el bloque sumó para el código
    /// del camino no corren (ver `TryInPlace`).
    #[inline(never)]
    fn vm_path_root(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, c: Reg, desc: u32, at: usize) -> Result<Option<usize>, Control> {
        if self.vm_path_root_fast(chunk, env, base, c, desc).is_some() {
            return Ok(None);
        }
        let pending = chunk.rest[at] as u64;
        self.steps = self.steps.wrapping_sub(pending);
        let d = chunk.paths[desc as usize];
        match self.vm_set_path(chunk, env, base, d.src, d.node, d.dst, at) {
            Ok(()) => Ok(Some(d.done as usize)),
            Err(c) => {
                // El camino de error vuelve a descontar `rest`.
                self.steps = self.steps.wrapping_add(pending);
                Err(c)
            }
        }
    }

    /// El contenedor de la variable raíz a `c`, como `exec_place` sobre un identificador: el mapa
    /// de un módulo tal cual; si no, único (`make_unique`) y una copia de la referencia. `None` si
    /// la raíz no está donde la VM la busca (un hueco, un frame de módulo o de afuera).
    #[inline(always)]
    fn vm_path_root_fast(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, c: Reg, desc: u32) -> Option<()> {
        fn take(slot: &mut SynValue) -> SynValue {
            if !matches!(slot, SynValue::Map(m) if module_env_of_map(m).is_some()) {
                make_unique(slot);
            }
            slot.clone()
        }
        let v = match chunk.paths[desc as usize].root {
            Root::Param(r) => take(&mut self.vm_regs[base + r as usize]),
            Root::Win(k) => take(self.vm_locals[self.vm_lbase + k as usize].as_mut()?),
            Root::Local(k) => {
                let mut e = env.borrow_mut();
                if e.name.starts_with("module:") {
                    return None;
                }
                take(e.bindings.slot_mut(k as usize)?)
            }
            Root::Free { name, ic } => {
                let start = self.free_start(chunk, env, chunk.hops[chunk.ic_hops[ic as usize] as usize]);
                let mut e = start.borrow_mut();
                if e.name.starts_with("module:") {
                    return None;
                }
                take(e.bindings.get_cached_mut(&chunk.names[name as usize], &chunk.ics[ic as usize])?)
            }
            Root::Slow => return None,
        };
        self.put(base, c, v);
        Some(())
    }

    /// `PathStep` (F4.6a): `c` pasa a ser el lugar de adentro, único. Una lista con un entero y un
    /// mapa que no es de un módulo, directo (con la caché por forma); lo demás, el paso de la
    /// referencia (`place_index_step`/`place_prop_step`), con sus errores.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_path_step(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        c: Reg,
        idx: Opnd,
        key: u32,
        ic: u32,
        at: usize,
    ) -> Result<(), Control> {
        let parent = std::mem::replace(&mut self.vm_regs[base + c as usize], SynValue::Nothing);
        let loc = &chunk.locs[chunk.loc[at] as usize];
        let next = if key != NONE {
            let name = &chunk.names[key as usize];
            let fast = match &parent {
                SynValue::Map(m) if module_env_of_map(m).is_none() => {
                    m.borrow_mut().get_cached_mut(name, &chunk.key_ics[ic as usize]).map(|slot| {
                        make_unique(slot);
                        slot.clone()
                    })
                }
                _ => None,
            };
            match fast {
                Some(v) => v,
                None => self.place_prop_step(parent, name, loc)?,
            }
        } else {
            let i = self.opnd(chunk, env, base, idx, at)?;
            let fast = match (&parent, &i) {
                // (Un paso a un elemento para escribir adentro: una lista sin caja tiene números, que
                // no tienen adentro; pasa a valores y el camino da el error de siempre.)
                (SynValue::List(l), SynValue::Number(Number::Int(k))) => {
                    let mut items = list_values_mut(l);
                    let n = items.len();
                    resolve_index(*k, n).map(|j| {
                        make_unique(&mut items[j]);
                        items[j].clone()
                    })
                }
                (SynValue::Map(m), SynValue::Text(k)) if module_env_of_map(m).is_none() => {
                    m.borrow_mut().get_cached_key_mut(k, &chunk.key_ics[ic as usize]).map(|slot| {
                        make_unique(slot);
                        slot.clone()
                    })
                }
                _ => None,
            };
            match fast {
                Some(v) => v,
                None => self.place_index_step(parent, i, loc)?,
            }
        };
        self.put(base, c, next);
        Ok(())
    }

    /// `PathSet` (F4.6a): la hoja. Una lista con un entero en rango y un mapa que no es de un
    /// módulo con la clave ya puesta, directo; lo demás, `set_leaf_*` (los mismos errores).
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_path_set(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        c: Reg,
        idx: Opnd,
        desc: u32,
        at: usize,
    ) -> Result<(), Control> {
        let d = chunk.paths[desc as usize];
        let obj = std::mem::replace(&mut self.vm_regs[base + c as usize], SynValue::Nothing);
        let out = if d.key != NONE {
            let v = self.opnd(chunk, env, base, d.src, at)?;
            let name = &chunk.names[d.key as usize];
            let done = match &obj {
                SynValue::Map(m) if module_env_of_map(m).is_none() => {
                    let mut b = m.borrow_mut();
                    match b.get_cached_mut(name, &chunk.key_ics[d.ic as usize]) {
                        Some(slot) => {
                            *slot = v.clone();
                            true
                        }
                        None => false,
                    }
                }
                _ => false,
            };
            if done {
                v
            } else {
                set_leaf_prop(&obj, name, v, &chunk.locs[chunk.loc[at] as usize])?
            }
        } else {
            // El índice, después el valor: en la referencia los dos ya están evaluados (el valor
            // antes que todo el camino), así que leerlos en este orden no se ve.
            let i = self.opnd(chunk, env, base, idx, at)?;
            let v = self.opnd(chunk, env, base, d.src, at)?;
            let done = match (&obj, &i) {
                (SynValue::List(l), SynValue::Number(Number::Int(k))) => {
                    let mut items = l.borrow_mut();
                    let n = items.len();
                    match resolve_index(*k, n) {
                        Some(j) => {
                            items.set(j, v.clone());
                            true
                        }
                        None => false,
                    }
                }
                (SynValue::Map(m), SynValue::Text(k)) if module_env_of_map(m).is_none() => {
                    let mut b = m.borrow_mut();
                    match b.get_cached_key_mut(k, &chunk.key_ics[d.ic as usize]) {
                        Some(slot) => {
                            *slot = v.clone();
                            true
                        }
                        None => false,
                    }
                }
                _ => false,
            };
            if done {
                v
            } else {
                set_leaf_index(&obj, &i, v, &chunk.locs[d.target_loc as usize], &chunk.locs[chunk.loc[at] as usize])?
            }
        };
        self.put(base, d.dst, out);
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
                        // F4.1: una task caliente pasa al nivel nativo (esta llamada, en la VM).
                        #[cfg(feature = "native-tier")]
                        if t.code.native.tick() {
                            self.vm_native_tier_up(chunk, at, t, first, n);
                        }
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
                    grow_regs(&mut self.vm_regs, new_base + code.nregs as usize);
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
            grow_regs(&mut self.vm_regs, need);
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

    /// F4.8b: una llamada por posición desde un builtin (`apply`, `where`, `reduce`, …), como el
    /// vectorcall de CPython. A una task cuyo cuerpo es un frame en registros, los argumentos van
    /// directo a su ventana (lo de `vm_call` + `vm_enter_regframe`, sin `Environment` ni `Vec` por
    /// llamada) y, si tiene código nativo, entra ahí. Si no, `call_value` como siempre. Lo observable
    /// es lo de `call_value_named` (la VM no corre con etiquetas: `vm_code_for`): la profundidad con
    /// el mismo tope, aridad permisiva (los de más se sueltan antes de los defaults, que se evalúan
    /// en el `closure_env`) y el `give` es el valor. Deja `args` vacíos.
    pub(super) fn call_fast(&mut self, f: &SynValue, args: &mut [SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        if let SynValue::Task(t) = f {
            if let Some(code) = self.vm_code_for(t) {
                if code.regframe {
                    return self.vm_call_rust(t, code, args);
                }
            }
        }
        let v: Vec<SynValue> = args.iter_mut().map(|a| std::mem::replace(a, SynValue::Nothing)).collect();
        self.call_value(f.clone(), v, loc)
    }

    /// `MakeMap`, fuera de línea (F4.8g): con sitio, las claves constantes y su forma.
    #[cold]
    #[inline(never)]
    fn vm_make_map(&mut self, chunk: &Chunk, base: usize, dst: Reg, first: Reg, n: u16, site: u32) {
        let from = base + first as usize;
        let m = if site == NONE {
            map_from_pair_slots(&mut self.vm_regs[from..from + 2 * n as usize])
        } else {
            chunk.map_sites[site as usize].build(&mut self.vm_regs[from..from + n as usize])
        };
        self.put(base, dst, SynValue::Map(m));
    }

    /// F4.8g: `body` con las llamadas de un builtin a `f` por elemento (ver `LambdaCall`).
    pub(super) fn with_lambda<R>(&mut self, f: &SynValue, body: impl FnOnce(&mut Self, &mut LambdaCall<'_>) -> R) -> R {
        #[cfg(feature = "native-tier")]
        {
            let flag = self.cancel.flag.clone();
            let task = match f {
                SynValue::Task(t) if self.shortcuts && !self.labels => Some(t.clone()),
                _ => None,
            };
            let mut lc = LambdaCall { f, task: task.as_ref(), flag: &flag, fast: None, off: task.is_none() };
            body(self, &mut lc)
        }
        #[cfg(not(feature = "native-tier"))]
        {
            let mut lc = LambdaCall { f };
            body(self, &mut lc)
        }
    }

    /// `call_fast` a un cuerpo con frame en registros.
    fn vm_call_rust(&mut self, t: &Rc<SynTaskValue>, code: &Rc<Chunk>, args: &mut [SynValue]) -> Result<SynValue, Control> {
        self.recursion_depth += 1;
        if self.recursion_depth > MAX_RECURSION {
            self.recursion_depth -= 1;
            return Err(err("maximum recursion depth exceeded"));
        }
        // Con código nativo, los argumentos van directo de acá al código nativo (la ventana de
        // registros se arma sólo si vuelve a la VM).
        #[cfg(feature = "native-tier")]
        {
            // (Con la unidad ya compilada no hay nada que decidir: sin sitio que reescribir.)
            if t.code.native.tick() && !t.code.native.ready() {
                self.vm_native_prepare(t, args.iter().map(native::seen_of).collect());
            }
            if let Some(r) = self.vm_native_from_rust(t, args) {
                self.recursion_depth -= 1;
                return r;
            }
        }
        let (n, np) = (args.len(), t.parameters.len());
        let base = self.vm_regs.len();
        grow_regs(&mut self.vm_regs, base + (code.nregs as usize).max(np));
        // Los parámetros en `r0..` (F3.7); los de más se sueltan acá, antes de los defaults.
        for (i, a) in args.iter_mut().enumerate() {
            let v = std::mem::replace(a, SynValue::Nothing);
            if i < np {
                self.vm_regs[base + i] = v;
            }
        }
        let lbase = self.vm_locals.len();
        self.vm_locals.resize(lbase + code.nlocals as usize, None);
        for i in n.min(np)..np {
            let v = match &t.parameters[i].default {
                Some(d) => match self.exec(d, &t.closure_env) {
                    Ok(v) => v,
                    Err(e) => {
                        self.vm_regs.truncate(base);
                        self.vm_locals.truncate(lbase);
                        self.recursion_depth -= 1;
                        return Err(e);
                    }
                },
                None => SynValue::Nothing,
            };
            self.vm_regs[base + i] = v;
        }
        debug_assert!(!self.labels);
        let saved = std::mem::replace(&mut self.vm_lbase, lbase);
        let r = self.run_chunk_at(code, &t.closure_env, base);
        self.vm_lbase = saved;
        self.vm_regs.truncate(base);
        self.vm_locals.truncate(lbase);
        self.recursion_depth -= 1;
        match r {
            Ok(v) | Err(Control::Give(v)) => Ok(v),
            Err(c) => Err(c),
        }
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
        // F4.1b: un builtin llamado sólo por posición: la próxima vez, `CallBuiltin` (F4.8c: o, en el
        // `append` de `set P to append(P, e)`, `AppendInPlace`).
        if s.names.is_none() && matches!(&f, SynValue::Builtin(b) if b.param_names.is_none()) {
            if let Ins::Call { dst, func, args, n, site } = chunk.code[at].get() {
                let append = s.append.is_some() && n == 2 && matches!(&f, SynValue::Builtin(b) if b.name == "append");
                chunk.code[at].set(if append { Ins::AppendInPlace { dst, func, args, site } } else { Ins::CallBuiltin { dst, func, args, n, site } });
            }
        }
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

impl Interpreter {
    /// `CallBuiltin`: `Ok(false)` si ya no encaja (la instrucción volvió a ser `Call`: se repite).
    /// Lo mismo que `vm_call_generic` + `call_value_named` para un builtin por posición: la función
    /// sale de su registro, el máximo de argumentos (antes de la profundidad), la profundidad con el
    /// mismo tope y el mismo error, y `dispatch_builtin` con `pending_kwargs` vacío.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_call_builtin(
        &mut self,
        chunk: &Chunk,
        base: usize,
        at: usize,
        dst: Reg,
        func: Reg,
        args: Reg,
        n: u16,
        site: u32,
    ) -> Result<bool, Control> {
        let nn = n as usize;
        let fits = match &self.vm_regs[base + func as usize] {
            SynValue::Builtin(b) => {
                b.param_names.is_none()
                    && self.pending_kwargs.is_empty()
                    // Pasarse del máximo es error: lo arma el camino de siempre.
                    && (!chunk.sites[site as usize].checked || b.meta.constructor || b.meta.arity.1.is_none_or(|max| nn <= max))
            }
            _ => false,
        };
        if !fits {
            chunk.code[at].set(Ins::Call { dst, func, args, n, site });
            return Ok(false);
        }
        let f = std::mem::replace(&mut self.vm_regs[base + func as usize], SynValue::Nothing);
        let first = base + args as usize;
        let argv: SmallVec<[SynValue; 4]> =
            (0..nn).map(|i| std::mem::replace(&mut self.vm_regs[first + i], SynValue::Nothing)).collect();
        self.recursion_depth += 1;
        if self.recursion_depth > MAX_RECURSION {
            self.recursion_depth -= 1;
            return Err(err("maximum recursion depth exceeded"));
        }
        let SynValue::Builtin(bt) = &f else { unreachable!("CallBuiltin sin builtin") };
        let r = self.dispatch_builtin(bt, &argv, &chunk.locs[chunk.loc[at] as usize]);
        // Como el camino genérico, que vuelve a poner el mapa que había (vacío) al terminar.
        if !self.pending_kwargs.is_empty() {
            self.pending_kwargs = SynMap::new();
        }
        drop(argv);
        self.recursion_depth -= 1;
        let v = r?;
        self.put(base, dst, v);
        Ok(true)
    }
}

impl Interpreter {
    /// `AppendInPlace` (F4.8c): `Ok(false)` si ya no es el builtin `append` (volvió a ser `Call`: se
    /// repite). Lo observable es lo de `CallBuiltin` con el builtin: la función sale de su registro,
    /// la profundidad con el mismo tope y el mismo error, y el resultado es la lista de antes más el
    /// elemento; sólo que, si P sigue teniendo esa misma lista, se agrega en ella (copiándola antes si
    /// alguien más la comparte), como la vía en el lugar de la referencia.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn vm_append_in_place(
        &mut self,
        chunk: &Chunk,
        env: &Rc<RefCell<Environment>>,
        base: usize,
        at: usize,
        dst: Reg,
        func: Reg,
        args: Reg,
        site: u32,
    ) -> Result<bool, Control> {
        let first = base + args as usize;
        let root = chunk.sites[site as usize].append;
        let fits = matches!(&self.vm_regs[base + func as usize], SynValue::Builtin(b) if b.name == "append" && b.param_names.is_none())
            && self.pending_kwargs.is_empty()
            && root.is_some()
            && matches!(&self.vm_regs[first], SynValue::List(_));
        if fits {
            // La profundidad, como la llamada al builtin (antes de hacer nada).
            if self.recursion_depth + 1 > MAX_RECURSION {
                drop(std::mem::replace(&mut self.vm_regs[base + func as usize], SynValue::Nothing));
                return Err(err("maximum recursion depth exceeded"));
            }
            let mut a0 = Some(std::mem::replace(&mut self.vm_regs[first], SynValue::Nothing));
            let mut item = Some(std::mem::replace(&mut self.vm_regs[first + 1], SynValue::Nothing));
            let p = match &a0 {
                Some(SynValue::List(l)) => crate::types::ListRef::as_ptr(l),
                _ => unreachable!("lista"),
            };
            // Si P sigue teniendo esa lista: el clon del primer argumento se suelta antes (si P es la
            // única dueña, se agrega sin copiar), `make_unique` y `push`.
            let out = self
                .vm_root_slot_mut(chunk, env, base, root.expect("raíz"), |slot| {
                    if !matches!(slot, SynValue::List(r) if crate::types::ListRef::as_ptr(r) == p) {
                        return None;
                    }
                    drop(a0.take());
                    make_unique(slot);
                    if let SynValue::List(l) = slot {
                        l.borrow_mut().push(item.take().expect("elemento"));
                    }
                    Some(slot.clone())
                })
                .flatten();
            if let Some(v) = out {
                drop(std::mem::replace(&mut self.vm_regs[base + func as usize], SynValue::Nothing));
                self.put(base, dst, v);
                return Ok(true);
            }
            // P ya no la tiene (un argumento la religó): los argumentos vuelven a su lugar y el builtin.
            self.vm_regs[first] = a0.expect("primer argumento");
            self.vm_regs[first + 1] = item.expect("elemento");
        }
        // El builtin de siempre (y si ya no es un builtin, vuelve a ser `Call`).
        let r = self.vm_call_builtin(chunk, base, at, dst, func, args, 2, site);
        if matches!(r, Ok(false)) {
            chunk.code[at].set(Ins::Call { dst, func, args, n: 2, site });
        }
        r
    }

    /// La variable raíz de `root` (como `vm_path_root_fast`: nunca la de un módulo), con `f`; `None` si
    /// no está donde la VM la busca.
    fn vm_root_slot_mut<R>(&mut self, chunk: &Chunk, env: &Rc<RefCell<Environment>>, base: usize, root: Root, f: impl FnOnce(&mut SynValue) -> R) -> Option<R> {
        Some(match root {
            Root::Param(r) => f(&mut self.vm_regs[base + r as usize]),
            Root::Win(k) => f(self.vm_locals[self.vm_lbase + k as usize].as_mut()?),
            Root::Local(k) => {
                let mut e = env.borrow_mut();
                if e.name.starts_with("module:") {
                    return None;
                }
                f(e.bindings.slot_mut(k as usize)?)
            }
            Root::Free { name, ic } => {
                let start = self.free_start(chunk, env, chunk.hops[chunk.ic_hops[ic as usize] as usize]);
                let mut e = start.borrow_mut();
                if e.name.starts_with("module:") {
                    return None;
                }
                f(e.bindings.get_cached_mut(&chunk.names[name as usize], &chunk.ics[ic as usize])?)
            }
            Root::Slow => return None,
        })
    }
}

impl Interpreter {
    /// F4.8d2: una instrucción de un bucle, corrida por el host de su código nativo sobre el frame del
    /// bucle (los argumentos ya en sus registros): una llamada (hasta que vuelve: el cuerpo de una
    /// task corre en un despacho propio, con el mismo epílogo que el `give` de la VM), un `LoadGlobal`
    /// o un `CheckProtected`.
    #[cfg(feature = "native-tier")]
    #[inline(never)]
    pub(super) fn vm_exec_one(&mut self, chunk: &Rc<Chunk>, env: &Rc<RefCell<Environment>>, base: usize, at: usize) -> Result<(), Control> {
        match chunk.code[at].get() {
            Ins::LoadGlobal { dst, name, ic } => {
                let v = env.borrow().bindings.get_cached(&chunk.names[name as usize], &chunk.ics[ic as usize]).cloned();
                match v {
                    Some(v) => {
                        self.put(base, dst, v);
                        Ok(())
                    }
                    None => self.vm_load_name(chunk, env, base, dst, name, ic, at),
                }
            }
            Ins::CheckProtected { func, name } => {
                check_protected_callee(&chunk.names[name as usize], &self.vm_regs[base + func as usize], &chunk.locs[chunk.loc[at] as usize])
            }
            Ins::CallBuiltin { dst, func, args, n, site } => match self.vm_call_builtin(chunk, base, at, dst, func, args, n, site)? {
                true => Ok(()),
                // Ya no es un builtin (volvió a ser `Call`): la llamada de siempre.
                false => self.vm_exec_call(chunk, base, at, dst, func, args, n, site),
            },
            Ins::Call { dst, func, args, n, site } | Ins::CallNative { dst, func, args, n, site } => {
                self.vm_exec_call(chunk, base, at, dst, func, args, n, site)
            }
            other => unreachable!("el host no corre {:?}", other),
        }
    }

    /// Una llamada de la VM hasta que vuelve (ver `vm_exec_one`).
    #[cfg(feature = "native-tier")]
    #[allow(clippy::too_many_arguments)]
    fn vm_exec_call(&mut self, chunk: &Rc<Chunk>, base: usize, at: usize, dst: Reg, func: Reg, args: Reg, n: u16, site: u32) -> Result<(), Control> {
        let Some(enter) = self.vm_call(chunk, base, at, dst, func, args, n, site)? else { return Ok(()) };
        let Enter { code, env: call_env, base: cbase, lbase, top } = enter;
        let saved = std::mem::replace(&mut self.vm_lbase, lbase);
        let r = self.run_chunk_at(&code, &call_env, cbase);
        // El epílogo de una llamada de la VM (el `give` del despacho, también por el camino de error).
        if code.regframe {
            drop(call_env);
        } else {
            self.release_frame(call_env);
        }
        self.vm_locals.truncate(lbase);
        self.vm_lbase = saved;
        self.recursion_depth -= 1;
        self.vm_pop_regs((cbase, code.nregs), top);
        match r {
            Ok(v) | Err(Control::Give(v)) => {
                self.put(base, dst, v);
                Ok(())
            }
            Err(c) => Err(c),
        }
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
