//! El enganche del nivel nativo (F4 de specs/compute-rendimiento.md). Sólo con la feature
//! `native-tier`; oculto: no es API del lenguaje.
//!
//! Core no genera código de máquina ni tiene `unsafe`: arma una **vista** del bytecode ya
//! especializado de una task caliente (y de las que llama), se la pasa al nivel nativo instalado
//! (`synsema-jit`, el único crate con Cranelift y `unsafe`) y, cuando el código nativo vuelve a la
//! VM, recibe el estado de cada frame nativo (`NFrame`) y sigue desde ahí.
//!
//! **La regla** (§F4.4 del spec): el código nativo nunca produce un error ni un resultado raro por
//! su cuenta. Ante cualquier cosa fuera de lo previsto (desborde, divisor cero, cancelación, tope de
//! recursión, una instrucción que la VM todavía no especializó) vuelve a la VM **antes** de esa
//! instrucción, sin haber hecho nada de ella, y la VM la corre como siempre.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::number::Number;
use crate::synmap::MapIc;
use crate::types::{ListRef, SynValue};

/// Un registro de la ventana de la VM (el de `vm.rs`).
pub type Reg = u16;
/// Registro destino "no hace falta el valor".
pub const DISCARD: Reg = Reg::MAX;

/// Una constante escalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NConst {
    Int(i64),
    Bool(bool),
    Nothing,
    /// F4.7: un `Float` (sus bits, para que la constante siga siendo `Eq`).
    Float(u64),
}

/// Las etiquetas de un valor en el código nativo (F4.7): lo que dice qué hay en sus bits, su `f64` o
/// su puntero. Las comparten el nivel nativo y las lecturas de abajo.
pub const TAG_HOLE: i64 = 0;
pub const TAG_NOTHING: i64 = 1;
pub const TAG_INT: i64 = 2;
pub const TAG_FLOAT: i64 = 3;
pub const TAG_BOOL: i64 = 4;
/// F4.7b: un valor con caja, prestado de la VM (el puntero es a donde vive: un registro, un lugar de
/// la ventana, una global, un elemento de una lista o un valor de un mapa).
pub const TAG_LIST: i64 = 5;
pub const TAG_MAP: i64 = 6;
/// Otro valor con caja (texto, `Big`, decimal, …), o una task o el builtin `range` (tipo estático).
pub const TAG_OTHER: i64 = 7;
/// Una lectura que el camino rápido no hace: sale a la VM antes de la instrucción.
pub const TAG_MISS: i64 = 0xff;

/// Un operando: como `Opnd` de la VM. `Reg` se consume (queda `nothing`), `Copy` no; `Local` es un
/// lugar de la ventana de locales ligado seguro; `Global` es una global de un bucle nativo (F4.2:
/// la `g` de la tabla de globales de la región).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NOpnd {
    Reg(Reg),
    Copy(Reg),
    Const(NConst),
    Local(u16),
    Global(u16),
}

/// `IntArith`: `+ - * %`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NArith {
    Add,
    Sub,
    Mul,
    Mod,
}

/// `FloatArith` (F4.7): `+ - * /` en f64 (con al menos un `Float`, o `/` entre dos números).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NFArith {
    Add,
    Sub,
    Mul,
    Div,
}

/// `Unary` (F4.7): `-x` y `not x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NUnary {
    Neg,
    Not,
}

/// F4.7c: los builtins puros que el nivel nativo hace él mismo (intrínsecos), como V8 con
/// `Math.sqrt` o LuaJIT con `math.*`. Mismo resultado y mismos errores que el builtin (lo que no hace,
/// sale a la VM antes de la llamada).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NBuiltin {
    Length,
    Sqrt,
    Abs,
    Float,
}

impl NBuiltin {
    pub const ALL: [NBuiltin; 4] = [NBuiltin::Length, NBuiltin::Sqrt, NBuiltin::Abs, NBuiltin::Float];

    /// El nombre del builtin (el que se verifica al entrar: la global sigue siendo ese builtin).
    pub fn name(self) -> &'static str {
        match self {
            NBuiltin::Length => "length",
            NBuiltin::Sqrt => "sqrt",
            NBuiltin::Abs => "abs",
            NBuiltin::Float => "float",
        }
    }

    pub fn from_name(n: &str) -> Option<NBuiltin> {
        NBuiltin::ALL.into_iter().find(|b| b.name() == n)
    }
}

/// `IntCmp`: `< <= > >= == !=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NCmp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// Una instrucción de la VM tal como la ve el nivel nativo. Mismos índices que el código del chunk
/// (un salto a `to` es a la instrucción `to` de la VM), así un `pc` de acá es un `pc` de la VM.
#[derive(Clone, Copy, Debug)]
pub enum NIns {
    Steps(u32),
    StepsCancel(u32),
    CheckCancel,
    /// Sin efecto acá: `TryInPlace` sobre una variable que no puede ser lista ni mapa.
    Nop,
    Const { dst: Reg, v: NConst },
    Move { dst: Reg, src: NOpnd },
    Drop { r: Reg },
    /// La guarda de la VM (dos `Int`) la da el tipo estático; desborde y `% 0` salen a la VM.
    IntArith { dst: Reg, op: NArith, a: NOpnd, b: NOpnd },
    IntCmp { dst: Reg, op: NCmp, a: NOpnd, b: NOpnd },
    /// F4.7: la guarda de la VM (dos números `Int`/`Float`; con `+ - *`, al menos un `Float`) la
    /// da el tipo estático o se chequea; si no pasa, o el divisor de `/` es cero, sale a la VM.
    FloatArith { dst: Reg, op: NFArith, a: NOpnd, b: NOpnd },
    /// F4.7: comparación entre `Int` y `Float` en cualquier mezcla, EXACTA (`partial_cmp_num`).
    NumCmp { dst: Reg, op: NCmp, a: NOpnd, b: NOpnd },
    /// F4.7: `Unary` (consume su operando como la VM). `-` de un `Int` que desborda, o de algo que
    /// no es un número, sale a la VM.
    Unary { dst: Reg, op: NUnary, a: NOpnd },
    /// F4.7: `ToBool` (si es verdadero, como `is_truthy`).
    ToBool { dst: Reg, src: NOpnd },
    /// F4.7b: `x[i]` (lo que hace el camino rápido de la VM: una lista con un `Int`, un mapa con una
    /// clave de texto; lo demás sale). `idx: None`: la clave es la constante de su sitio.
    GetIndex { dst: Reg, obj: NOpnd, idx: Option<NOpnd>, site: u32 },
    /// F4.7b: `m.k` (un mapa, con la caché por forma de su sitio; lo demás sale).
    GetProp { dst: Reg, obj: NOpnd, site: u32 },
    /// F4.7b: `EachInitV` sobre una lista (el iterador recorre la lista que había al empezar, como la
    /// VM); otra colección sale.
    EachList { src: NOpnd, it: u16 },
    /// Compara y salta (`IntCmpJump` + el `JumpIfFalsy` que le sigue, cuyo destino es `to`): si da
    /// verdadero sigue en `pc + 2`.
    IntCmpJump { op: NCmp, a: NOpnd, b: NOpnd, to: u32 },
    JumpIfFalsy { src: NOpnd, to: u32 },
    Jump { to: u32 },
    LoadLocal { dst: Reg, slot: u16 },
    LetLocal { src: NOpnd, slot: u16, dst: Reg },
    SetLocal { src: NOpnd, slot: u16, dst: Reg },
    /// `LoadGlobal` de una task de esta unidad (la función `func`); que la global siga siendo esa
    /// task se verifica al entrar desde la VM (lo nativo no puede cambiarla).
    LoadCallee { dst: Reg, func: u32 },
    /// Una llamada posicional a la task de `func` (un registro con `LoadCallee`).
    Call { dst: Reg, func: Reg, args: Reg, n: u16 },
    Give { src: NOpnd },
    End { src: NOpnd },
    /// F4.2: `set g to …` sobre una global de la región (un hueco sale: la VM la busca afuera).
    SetGlobal { src: NOpnd, g: u16, dst: Reg },
    /// F4.2: `let g be …` en el nivel del bucle, sobre un nombre que ya está en el entorno.
    LetGlobal { src: NOpnd, g: u16, dst: Reg },
    /// `TryInPlace` sobre una variable: la vía en el lugar sólo aplica a listas y mapas, así que con
    /// un escalar no hace nada. El tipo estático lo prueba (si no se sabe, no se compila); una
    /// global vacía sale (la VM la busca afuera).
    Scalar { src: NOpnd },
    /// F4.2b: `LoadGlobal` del builtin `range` (que siga siéndolo se verifica al entrar).
    RangeFn { dst: Reg },
    /// F4.7c: `LoadGlobal` de un builtin que el nivel nativo hace él mismo (verificado al entrar).
    LoadBuiltin { dst: Reg, which: NBuiltin },
    /// `IsRange`: si `src` no es el builtin `range`, a `to` (la llamada de siempre).
    IsRange { src: Reg, to: u32 },
    /// `each … in range(…)`: los argumentos (`n`, de 1 a 3) en registros desde `first`; el
    /// iterador perezoso en el lugar `it`. La profundidad (un nivel, como la llamada al builtin) y
    /// el paso cero los chequea la VM: salida antes.
    EachRange { first: Reg, n: u16, it: u16 },
    /// La vuelta siguiente del iterador `it` (un `range`): la variable en el lugar `slot`; sin más,
    /// a `exit`.
    EachNext { it: u16, slot: u16, exit: u32 },
    /// Fin de la vuelta: los lugares `first..first + n` vuelven a estar vacíos, y a `head`.
    EachStep { head: u32, first: u16, n: u16 },
    /// Fin del bucle: los lugares vacíos y los iteradores desde `it` terminados.
    EachEnd { it: u16, first: u16, n: u16 },
    /// F4.2: acá termina el código nativo y sigue la VM. `planned`: fuera del bucle (la salida, un
    /// `stop`, un `give`); si no, algo del cuerpo que el nivel nativo todavía no hace.
    Leave { planned: bool },
    /// La VM todavía no especializó esta instrucción (`Binary`: una rama que nunca corrió): se sale
    /// acá. Lleva lo que la VM va a leer y escribir.
    Trap { dst: Reg, a: NOpnd, b: NOpnd },
}

/// Lo que tenía un lugar al compilar un bucle (F4.2): el código nativo se especializa en eso y la
/// entrada lo vuelve a verificar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NSeen {
    Int,
    Bool,
    /// F4.7.
    Float,
    Nothing,
    /// Un lugar de la ventana o una global sin valor.
    Hole,
    /// F4.7b: valores con caja (el código nativo los lee prestados, sin tocar sus cuentas): una
    /// lista, un mapa, otro (texto, `Big`, …).
    List,
    Map,
    Boxed,
    /// F4.7b: la primera parte de un iterador de una lista (las otras: posición y largo, `Int`).
    ListIter,
    /// Lo que el nivel nativo no representa (un iterador de claves o de caracteres).
    Opaque,
}

/// Un bucle que se compila a mitad de camino (OSR, F4.2): se entra en `head` con el estado de la
/// VM. `init`: lo que tenía cada variable (registros, ventana, globales y las cuatro de cada
/// iterador, en ese orden; un iterador que no es un `range` es `Boxed`).
#[derive(Clone, Debug)]
pub struct NOsr {
    pub head: u32,
    pub init: Vec<NSeen>,
}

/// El cuerpo de una task (con frame en registros: parámetros en `r0..`, F3.7), o un bucle (`osr`).
#[derive(Clone, Debug)]
pub struct NFunc {
    pub code: Vec<NIns>,
    pub nregs: u16,
    pub nlocals: u16,
    pub nparams: u16,
    /// Las globales de un bucle, o (F4.8b) las que lee la función 0 de una task (`globals`).
    pub nglobals: u16,
    /// Cuántos iteradores de `each` usa (cada uno, cuatro variables: `valid`, `next`, `hi`, `step`).
    pub niters: u16,
    pub osr: Option<NOsr>,
    /// F4.7: lo que tienen los parámetros al entrar desde la VM (`Int`, `Float` o `Bool`), en la
    /// función 0 de una task. Vacío en las demás (sus tipos salen de las llamadas de la unidad) y
    /// en un bucle.
    pub params: Vec<NSeen>,
    /// F4.8b: en la función 0 de una task, lo que tenían al compilar las globales que lee (que no
    /// son tasks ni builtins): entran como parámetros después de los suyos, leídas al entrar (el
    /// código nativo de una task no escribe globales ni corre código ajeno, así que leerlas al entrar
    /// es leerlas cuando las lee el cuerpo). Vacío en las demás y en un bucle.
    pub globals: Vec<NSeen>,
}

/// Un sitio de `GetIndex`/`GetProp` (F4.7b): la clave, si es fija.
#[derive(Clone, Debug)]
pub struct NSite {
    pub key: Option<Arc<str>>,
}

/// Lo que se compila junto: la task caliente (`funcs[0]`) y las que llama.
#[derive(Clone, Debug)]
pub struct NUnit {
    pub funcs: Vec<NFunc>,
    /// F4.7b: los sitios de lectura de todas sus funciones.
    pub sites: Vec<NSite>,
}

/// Un valor de un frame nativo.
#[derive(Clone, Debug)]
pub enum NVal {
    Int(i64),
    Bool(bool),
    Nothing,
    /// F4.7.
    Float(f64),
    /// La task de la función `func` de la unidad.
    Callee(u32),
    /// Un lugar vacío (un `let` de la vuelta que ya se soltó, un iterador terminado).
    Hole,
    /// El builtin `range`.
    RangeFn,
    /// F4.7c: uno de los builtins intrínsecos.
    Builtin(NBuiltin),
    /// F4.7b: un valor con caja (ya clonado: la cuenta es la de la VM).
    Value(SynValue),
    /// F4.7b: la lista de un iterador (ya clonada).
    List(ListRef),
}

// =============================================================================================
// Lecturas (F4.7b): lo que el nivel nativo lee de los valores con caja, sin `unsafe` (lo que
// devuelve un puntero es su dirección, para que el nivel nativo la guarde; leerlo es de él).
// =============================================================================================

/// Un valor visto por el código nativo: su etiqueta, sus bits (un `Int`, un `Bool`, los de un
/// `Float`) y, si tiene caja, dónde está.
#[derive(Clone, Copy, Debug)]
pub struct NPeek {
    pub tag: i64,
    pub bits: i64,
    pub ptr: *const SynValue,
}

impl NPeek {
    pub const MISS: NPeek = NPeek { tag: TAG_MISS, bits: 0, ptr: std::ptr::null() };
}

/// Cómo ve el código nativo a `v` (que vive donde está: su dirección queda en `ptr`).
pub fn peek(v: &SynValue) -> NPeek {
    let (tag, bits) = match v {
        SynValue::Number(Number::Int(x)) => (TAG_INT, *x),
        SynValue::Number(Number::Float(x)) => (TAG_FLOAT, x.to_bits() as i64),
        SynValue::Bool(b) => (TAG_BOOL, i64::from(*b)),
        SynValue::Nothing => (TAG_NOTHING, 0),
        SynValue::List(_) => (TAG_LIST, 0),
        SynValue::Map(_) => (TAG_MAP, 0),
        _ => (TAG_OTHER, 0),
    };
    let ptr = if tag >= TAG_LIST { std::ptr::from_ref(v) } else { std::ptr::null() };
    NPeek { tag, bits, ptr }
}

/// Un sitio de lectura con su caché por forma (la del nivel nativo, aparte de la de la VM: una
/// caché no cambia qué da una lectura).
pub struct SiteIc {
    key: Option<Arc<str>>,
    ic: MapIc,
}

impl SiteIc {
    pub fn new(s: &NSite) -> SiteIc {
        SiteIc { key: s.key.clone(), ic: MapIc::default() }
    }

    /// `obj[idx]` como el camino rápido de `GetIndex` en la VM: una lista con un `Int` (índices
    /// negativos como siempre), un mapa con una clave de texto (la del sitio, o `idx`). Lo demás
    /// (fuera de rango, clave que falta, otro tipo) no lo hace: `MISS`.
    pub fn index(&self, obj: &SynValue, idx_tag: i64, idx_bits: i64, idx: Option<&SynValue>) -> NPeek {
        match obj {
            SynValue::List(l) if idx_tag == TAG_INT => {
                let items = l.borrow();
                match crate::interpreter::resolve_index(idx_bits, items.len()) {
                    Some(j) => peek(&items[j]),
                    None => NPeek::MISS,
                }
            }
            SynValue::Map(m) => {
                let key: &str = match (&self.key, idx) {
                    (Some(k), _) => k,
                    (None, Some(SynValue::Text(t))) => t,
                    _ => return NPeek::MISS,
                };
                match m.borrow().get_cached_key(key, &self.ic) {
                    Some(v) => peek(v),
                    None => NPeek::MISS,
                }
            }
            _ => NPeek::MISS,
        }
    }

    /// `obj.k` como el camino rápido de `GetProp` en la VM: un mapa con la caché por forma.
    pub fn prop(&self, obj: &SynValue) -> NPeek {
        match (obj, &self.key) {
            (SynValue::Map(m), Some(k)) => match m.borrow().get_cached(k, &self.ic) {
                Some(v) => peek(v),
                None => NPeek::MISS,
            },
            _ => NPeek::MISS,
        }
    }
}

/// La lista de `v` (dónde está su `Rc`: el iterador de un `each` la guarda así, como
/// `EachItems::List`) y su largo; `None` si no es una lista.
pub fn list_body(v: &SynValue) -> Option<(*const ListRef, usize)> {
    match v {
        SynValue::List(l) => Some((std::ptr::from_ref(l), l.borrow().len())),
        _ => None,
    }
}

/// El elemento `i` de una lista (la vuelta de un `each`); `MISS` si ya no está.
pub fn list_elem(l: &ListRef, i: i64) -> NPeek {
    let items = l.borrow();
    match usize::try_from(i).ok().and_then(|j| items.get(j)) {
        Some(v) => peek(v),
        None => NPeek::MISS,
    }
}

/// Si `v` es verdadero (`is_truthy`).
pub fn truthy(v: &SynValue) -> bool {
    v.is_truthy()
}

/// F4.7c: `length(v)` como el builtin (texto en caracteres, lista, mapa, bytes); `None` con lo demás
/// (un `Array`, algo sin largo: lo resuelve la VM, con su error).
pub fn length(v: &SynValue) -> Option<i64> {
    Some(match v {
        SynValue::Text(s) => s.chars().count() as i64,
        SynValue::List(l) => l.borrow().len() as i64,
        SynValue::Map(m) => m.borrow().len() as i64,
        SynValue::Bytes(b) => b.len() as i64,
        _ => return None,
    })
}

/// Dónde vive un valor en el frame de la VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Reg(Reg),
    Local(u16),
    Global(u16),
    /// La parte `k` del iterador `it` (0 `valid`, 1 `next`, 2 `hi`, 3 `step`).
    Iter(u16, u8),
}

/// Una llamada en curso: el frame espera su resultado en `dst`; la ventana del llamado empieza en
/// su registro `args` (F3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NCall {
    pub dst: Reg,
    pub args: Reg,
    pub n: u16,
}

/// El estado de un frame nativo al volver a la VM.
#[derive(Clone, Debug)]
pub struct NFrame {
    pub func: u32,
    /// Dónde sigue la VM en el código de este frame.
    pub pc: u32,
    /// Los valores vivos (lo que no está, la VM lo tiene vacío).
    pub values: Vec<(Place, NVal)>,
    /// Todos menos el de más adentro esperan a su llamado.
    pub call: Option<NCall>,
    /// Una salida prevista (el fin de un bucle nativo), no una desoptimización.
    pub planned: bool,
}

/// Cómo terminó una llamada nativa.
#[derive(Debug)]
pub enum NOutcome {
    Done(NVal),
    /// Salió a la VM: los frames nativos, del de más afuera al de más adentro.
    Deopt(Vec<NFrame>),
}

/// Lo del intérprete que el código nativo lee y escribe (los mismos contadores de la VM).
pub struct NativeCx<'a> {
    pub steps: &'a mut u64,
    pub depth: &'a mut usize,
    pub max_depth: usize,
    pub cancel: &'a AtomicBool,
}

/// Una unidad ya compilada (de este hilo).
pub trait NativeCode {
    /// Corre `funcs[0]` con estos argumentos (los bits de cada uno: un `Float` con `to_bits`; la
    /// entrada verifica que tengan lo que pide `params`). En un bucle (F4.2),
    /// los valores de `inputs` en orden.
    fn call(&self, cx: &mut NativeCx<'_>, args: &[i64]) -> NOutcome;
    /// En un bucle: los lugares que el código nativo lee o escribe, con lo que tienen que tener al
    /// entrar (la guarda). Vacío en una task.
    fn inputs(&self) -> &[(Place, NSeen)] {
        &[]
    }
}

/// El nivel nativo instalado.
pub trait NativeTier: Send + Sync {
    /// `None` si no puede compilar la unidad (se queda en la VM).
    fn compile(&self, unit: &NUnit) -> Option<Box<dyn NativeCode>>;
}

static TIER: OnceLock<&'static dyn NativeTier> = OnceLock::new();

/// Instala el nivel nativo para todo el proceso (lo hace el binario al arrancar).
pub fn install(tier: &'static dyn NativeTier) {
    let _ = TIER.set(tier);
}

pub(crate) fn tier() -> Option<&'static dyn NativeTier> {
    TIER.get().copied()
}

/// Cuántas llamadas de la VM a una task (o vueltas de un bucle) antes de compilarla.
const HOT_CALLS: u32 = 1000;
static THRESHOLD: AtomicU32 = AtomicU32::new(HOT_CALLS);

/// Sólo tests (el oráculo diferencial): compilar en la segunda llamada, para que lo nativo corra
/// en todo el corpus. No cambia qué se evalúa, sólo cuándo se compila; no es un knob de usuario.
#[doc(hidden)]
pub fn set_eager(on: bool) {
    THRESHOLD.store(if on { 2 } else { HOT_CALLS }, Ordering::Relaxed);
}

#[inline]
pub(crate) fn threshold() -> u32 {
    THRESHOLD.load(Ordering::Relaxed)
}

/// Cuánto corrió el nivel nativo en el proceso (para los tests: que el oráculo compare código
/// nativo de verdad y no una VM que nunca subió de nivel).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeStats {
    /// Unidades compiladas.
    pub units: u64,
    /// Entradas desde la VM.
    pub entries: u64,
    /// Salidas a la VM a mitad de camino.
    pub deopts: u64,
    /// Entradas a un bucle a mitad de camino (OSR, F4.2).
    pub osr: u64,
}

static UNITS: AtomicU64 = AtomicU64::new(0);
static ENTRIES: AtomicU64 = AtomicU64::new(0);
static DEOPTS: AtomicU64 = AtomicU64::new(0);
static OSR: AtomicU64 = AtomicU64::new(0);

pub(crate) fn count_unit() {
    UNITS.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn count_entry() {
    ENTRIES.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn count_deopt() {
    DEOPTS.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn count_osr() {
    OSR.fetch_add(1, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn stats() -> NativeStats {
    NativeStats {
        units: UNITS.load(Ordering::Relaxed),
        entries: ENTRIES.load(Ordering::Relaxed),
        deopts: DEOPTS.load(Ordering::Relaxed),
        osr: OSR.load(Ordering::Relaxed),
    }
}
