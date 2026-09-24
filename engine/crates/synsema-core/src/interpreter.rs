//! Intérprete de Synsema — evalúa el AST.
//!
//! Port fiel de `synsema/core/interpreter.py`. El control de flujo `give`/`stop`
//! (que Python implementa con excepciones) se modela acá con `Result<_, Control>`.
//! Los entornos son `Rc<RefCell<Environment>>` (closures + scoping léxico) y
//! list/map son referencias mutables compartidas (ver `types.rs`).
//!
//! Capa 4: el intérprete corre programas puros. Las features que requieren el
//! engine completo (serve/send/expect con request) producen el mismo error que
//! el oráculo. Builtins y intentional_ops están registrados como en Python.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use indexmap::IndexMap;
use num_complex::Complex64;
use regex::Regex;

use crate::ast::{Node, NodeKind, Param, Program};
use crate::labels::{self, label_display_raw, DeclassifyEntry, Label};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::parser::{parse_source, CompileError};
use crate::templates::resolve_module_path;
use crate::tokens::SourceLocation;
use crate::types::*;

// =========================================================
// errores y control de flujo
// =========================================================

/// Error en tiempo de ejecución, con ubicación opcional.
#[derive(Debug, Clone)]
pub struct RuntimeError {
    pub message: String,
    pub location: Option<SourceLocation>,
    /// Error de VALIDACIÓN de cliente (p.ej. una falla de `expect body`): el serve lo
    /// mapea a HTTP 400 (no 500), con `field` = el campo ofensor (o None). Para errores
    /// normales del runtime `is_validation` es false.
    pub is_validation: bool,
    pub field: Option<String>,
    /// Falla de una aserción (`assert*`, Batch 3): sólo se usa para el ÍCONO del reporte
    /// de `synsema test` (distingue una aserción de otro error de runtime). NO cambia el
    /// `Display` ni el manejo del error; una aserción falla igual que cualquier error.
    pub is_assertion: bool,
    /// T5 (regla 1.a): el error se ORIGINÓ con una etiqueta de PC no vacía. Un salto de
    /// control desde un contexto privado no se puede observar, así que este error **no es
    /// atrapable** (`try/recover` y `assert_error` lo re-propagan) y su texto se redacta al
    /// salir hacia el host. Lo pone el intérprete, no los constructores: ver `exec`.
    pub from_private_pc: bool,
    /// Principales con los que este error se REDACTA al salir hacia el host (`"a,b"`;
    /// Vacío = no se redacta). Lo pone el intérprete en el momento exacto del error: el PC de
    /// ese instante UNIDO a lo privado que se desenvolvió evaluando ESE nodo. No es el `seen`
    /// Monótono de toda la corrida (que volvía `private(app)` a cualquier error posterior,
    /// Aunque no tuviera relación). Texto (no `Label`) para no meter `Rc` en un tipo que
    /// cruza hilos en el runtime.
    pub redact_label: String,
    /// T5 (regla 3.c): el error lo produjo el PROPIO sistema de etiquetas (un
    /// `label_violation`, un mal uso de `private`/`declassify`). Se distingue por este flag
    /// Y NUNCA por el texto del mensaje: un `raise "label_violation: " + text(x)` del
    /// programa no puede hacerse pasar por un diagnóstico para esquivar la redacción.
    /// Tampoco es atrapable: el veredicto del enforcement no se recupera.
    pub from_labels: bool,
    /// T1 (identidad): la capability la denegó el TECHO DELEGADO de un captoken — el programa
    /// la declara, el token del caller no la concede. Bajo `serve` es la culpa del caller: la
    /// respuesta es un **403 genérico** (`insufficient permissions`), no un 500, y el detalle
    /// queda sólo en el log y el audit del server. Se distingue por este flag y NUNCA por el
    /// texto (lo pone `CapabilityViolation::into_error`, el único conversor).
    pub denied_by_token: bool,
}

impl RuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false }
    }
    pub fn at(message: impl Into<String>, location: SourceLocation) -> Self {
        Self { message: message.into(), location: Some(location), is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false }
    }
    /// El texto de este error **hacia un cliente REMOTO** (el cuerpo de una respuesta HTTP, el
    /// evento final de un stream): igual que `Display`, pero la ubicación viaja con el NOMBRE del
    /// archivo y no con su ruta absoluta.
    ///
    /// Auditoría ronda 4: `err_labels` ya lo hacía para los diagnósticos de etiquetas, pero ése
    /// era un embudo, no el camino — todo error que no fuera de etiquetas seguía contándole al
    /// cliente dónde vive el programa en la máquina que lo corre (bajo `serve --attested`, dentro
    /// del enclave). La ruta completa sigue saliendo por el CLI y por el log local, que son de
    /// quien opera la máquina.
    ///
    /// Auditoría ronda 7: si el corte lo decidió el sistema de etiquetas, el mensaje sale **sin
    /// ubicación**. El texto ya está redactado, pero *dónde* murió no: si el secreto elige cuál
    /// de N sitios falla, la línea vale log₂(N) bits, y bajo servidor el atacante hace una
    /// petición por consulta. Del lado del CLI local la ubicación se conserva — ahí el host es
    /// quien escribió el `private(…)`, o sea el dueño del dato.
    pub fn to_string_for_client(&self) -> String {
        match &self.location {
            _ if self.is_fatal_for_labels() || self.from_labels => self.message.clone(),
            Some(loc) => format!("{}:{}:{}: {}", basename_of(&loc.file), loc.line, loc.column, self.message),
            None => self.message.clone(),
        }
    }
    /// Error de validación de cliente (input que no cumple `expect`): se mapea a HTTP 400
    /// con el nombre del campo ofensor, en vez de a un 500 genérico.
    pub fn validation(message: impl Into<String>, field: Option<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: true, field, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false }
    }
    /// Falla de aserción (`assert*`): marca `is_assertion` para el reporte de tests.
    pub fn assertion(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: false, field: None, is_assertion: true, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false }
    }
    /// Diagnóstico del sistema de etiquetas (`from_labels`), con ubicación.
    pub fn labels(message: impl Into<String>, location: SourceLocation) -> Self {
        Self { message: message.into(), location: Some(location), is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: true, denied_by_token: false }
    }
    /// ¿Este error NO se puede atrapar con `try/recover` ? Un salto de control desde PC
    /// privado sería un bit observable por iteración, y el veredicto del enforcement no se
    /// recupera: los dos casos se propagan hasta el host.
    #[inline]
    pub fn is_fatal_for_labels(&self) -> bool {
        self.from_private_pc || self.from_labels
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.location {
            Some(loc) => write!(f, "{}: {}", loc, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

/// T5 (ronda 5) — el estado de tinta de continuación de una unidad de ejecución, guardado en un
/// borde (llamada, agente, request, bloque `test`) para restaurarlo al volver. Las tres etiquetas
/// tienen alcances distintos a propósito: ver `taint_branch`.
struct TaintFrame {
    /// Tinta del cuerpo de la task (nace de un `give`/`raise` bajo rama privada).
    control: Label,
    /// Tinta del bucle en curso (nace de un `stop`); muere al salir del bucle.
    loops: Label,
    /// La parte que escapa del cuerpo y corta el bucle del llamador.
    escaping: Label,
    /// Bucles abiertos en este cuerpo.
    depth: usize,
}

/// Flujo no-lineal: error, `give` (return) o `stop` (break). Mapea las
/// excepciones del intérprete Python (RuntimeError/GiveSignal/StopSignal).
pub enum Control {
    Error(RuntimeError),
    Give(SynValue),
    Stop(Option<SynValue>),
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}
/// Error de validación de cliente (falla de `expect`): el serve lo mapea a 400 + `field`.
fn err_validation(msg: impl Into<String>, field: Option<String>) -> Control {
    Control::Error(RuntimeError::validation(msg, field))
}
fn err_at(msg: impl Into<String>, loc: &SourceLocation) -> Control {
    Control::Error(RuntimeError::at(msg, loc.clone()))
}
/// Falla de aserción (`assert*`, Batch 3): error de runtime marcado `is_assertion`.
fn err_assertion(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::assertion(msg))
}
/// Diagnóstico del PROPIO sistema de etiquetas (`label_violation`, mal uso de
/// `private`/`declassify`): se marca con un FLAG al construirlo, nunca por el texto (regla
/// 3.c). No se redacta al salir al host (sólo lleva metadatos públicos: nombres del
/// programa, caminos con claves literales y principales, que son públicos por construcción)
/// y tampoco es atrapable.
fn err_labels(msg: impl Into<String>, loc: &SourceLocation) -> Control {
    // M2 (ronda 3): un diagnóstico de etiquetas NUNCA se redacta, y bajo `serve --attested`
    // (que no implica `--secure`) su texto llega al cliente HTTP remoto. La ubicación viaja con
    // el NOMBRE del archivo, no con la ruta absoluta de la máquina del enclave.
    let mut short = loc.clone();
    short.file = basename_of(&short.file).to_string();
    Control::Error(RuntimeError::labels(msg, short))
}

/// Nombre de archivo de una ruta (sin directorios), para los diagnósticos que salen al cliente.
fn basename_of(path: &str) -> &str {
    match path.rfind(['/', '\\']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}
/// Mensaje legible de un `Control` (para el reporte de tests): el error tal cual, o el
/// mensaje estándar de `give`/`stop` fuera de task/loop.
fn control_message(c: &Control) -> String {
    match c {
        Control::Error(e) => e.to_string(),
        Control::Give(_) | Control::Stop(_) => {
            "'give'/'stop' used outside of a task or loop".to_string()
        }
    }
}

// =========================================================
// builtins
// =========================================================

pub type BuiltinFn =
    Rc<dyn Fn(&mut Interpreter, &[SynValue], &SourceLocation) -> Result<SynValue, Control>>;

/// T5 (ronda 8) — envuelve un builtin que PARSEA entrada externa con su variante **total**: con
/// un argumento de más, el último es el valor de reemplazo y el builtin no lanza.
///
/// Por qué hace falta y por qué se hace acá y no builtin por builtin: bajo etiquetas, un error
/// causado por datos privados **no se atrapa** (poder recuperarse de un fallo es el bit), así que
/// un programa que valida entrada no confiable —lo que un enclave hace con todo lo que recibe— se
/// queda sin ninguna frase que escribir. El caso canónico es el descifrado autenticado: un tag
/// manipulado tiene que ser "rechazo esta petición", no "el proceso muere".
///
/// **No se traga los errores del sistema de etiquetas.** Un `label_violation`, o un error nacido
/// de datos privados, se re-propaga: si el reemplazo los absorbiera sería un `try/recover`
/// encubierto y volvería a abrir el canal que la ronda 6 cerró.
///
/// Detalle del lenguaje, evaluación estricta: el valor de reemplazo **se evalúa siempre**, así
/// que un efecto adentro (`json_decode(x, log_algo())`) dispara también en el camino feliz.
pub fn with_fallback(base: usize, f: BuiltinFn) -> BuiltinFn {
    Rc::new(move |i, args, loc| {
        if args.len() != base + 1 {
            return f(i, args, loc);
        }
        match f(i, &args[..base], loc) {
            Ok(v) => Ok(v),
            Err(Control::Error(e)) if !e.is_fatal_for_labels() => Ok(args[base].clone()),
            Err(other) => Err(other),
        }
    })
}

/// Un task built-in (implementado en Rust). `param_count` es informativo (Python
/// no lo fuerza en `_call_value`).
/// `print` escribe directo a stdout en vez de juntar en `output` (v0.6.29). Lo prende
/// sólo el camino normal de `synsema run`; todo lo demás (tests, serve, informes) junta.
pub static LIVE_STDOUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct BuiltinTask {
    pub name: String,
    pub func: BuiltinFn,
    pub param_count: i32,
    /// Nombres de parámetros, OPT-IN (G-8): sólo los builtins que los declaran
    /// aceptan args nombrados (`recall(..., from = "writer")`), mapeados a
    /// posicionales acá mismo. Los demás conservan el error de siempre.
    pub param_names: Option<Vec<&'static str>>,
}

// =========================================================
// entorno
// =========================================================

pub struct Environment {
    pub parent: Option<Rc<RefCell<Environment>>>,
    pub name: String,
    pub bindings: HashMap<String, SynValue>,
}

impl Environment {
    pub fn root(name: &str) -> Rc<RefCell<Environment>> {
        Rc::new(RefCell::new(Environment {
            parent: None,
            name: name.to_string(),
            bindings: HashMap::new(),
        }))
    }
    pub fn child(parent: &Rc<RefCell<Environment>>, name: &str) -> Rc<RefCell<Environment>> {
        Rc::new(RefCell::new(Environment {
            parent: Some(parent.clone()),
            name: name.to_string(),
            bindings: HashMap::new(),
        }))
    }
}

// =========================================================
// módulos: registro explícito (v0.6.29)
// =========================================================

/// Un módulo cargado es DOS vistas del mismo estado: su entorno (`module:<ruta>`, donde viven
/// sus variables y cierran sus tasks) y el mapa de exportaciones que devuelve `use … as m`. El
/// registro las une por identidad —no por forma— para que (a) `m` se reconozca en O(1) como
/// espacio de nombres (un mapa de datos con un task adentro no es un módulo) y (b) cada
/// escritura a una exportación, desde adentro (`set STATE[k]` en un task) o desde afuera
/// (`set m.STATE[k]`), deje las dos vistas apuntando al mismo valor. Por hilo, como el
/// intérprete; los `Weak` no retienen el módulo y mantienen viva la dirección (no se
/// reutiliza mientras esté registrada).
#[derive(Default)]
struct ModuleRegistry {
    by_map: HashMap<usize, (std::rc::Weak<RefCell<IndexMap<String, SynValue>>>, std::rc::Weak<RefCell<Environment>>)>,
    by_env: HashMap<usize, std::rc::Weak<RefCell<IndexMap<String, SynValue>>>>,
    prune_at: usize,
}

thread_local! {
    static MODULES: RefCell<ModuleRegistry> = RefCell::new(ModuleRegistry::default());
}

/// Registra el mapa de exportaciones `map` como la vista de `env` (lo llaman `load_module`
/// y la reconstrucción de módulos de un worker de `serve`/`parallel_map`).
pub fn register_module(map: &Rc<RefCell<IndexMap<String, SynValue>>>, env: &Rc<RefCell<Environment>>) {
    MODULES.with(|r| {
        let mut r = r.borrow_mut();
        if r.by_map.len() >= r.prune_at.max(64) {
            r.by_map.retain(|_, (m, e)| m.strong_count() > 0 && e.strong_count() > 0);
            r.by_env.retain(|_, m| m.strong_count() > 0);
            r.prune_at = r.by_map.len() * 2;
        }
        r.by_map.insert(Rc::as_ptr(map) as usize, (Rc::downgrade(map), Rc::downgrade(env)));
        r.by_env.insert(Rc::as_ptr(env) as usize, Rc::downgrade(map));
    });
}

/// El entorno del módulo cuyo mapa de exportaciones es `map`, si lo es.
pub fn module_env_of_map(map: &Rc<RefCell<IndexMap<String, SynValue>>>) -> Option<Rc<RefCell<Environment>>> {
    MODULES.with(|r| {
        let r = r.borrow();
        if r.by_map.is_empty() {
            return None;
        }
        let (m, e) = r.by_map.get(&(Rc::as_ptr(map) as usize))?;
        m.upgrade()?;
        e.upgrade()
    })
}

/// El mapa de exportaciones del módulo cuyo entorno es `env`, si lo es.
pub fn module_map_of_env(env: &Rc<RefCell<Environment>>) -> Option<Rc<RefCell<IndexMap<String, SynValue>>>> {
    MODULES.with(|r| r.borrow().by_env.get(&(Rc::as_ptr(env) as usize)).and_then(|m| m.upgrade()))
}

/// `set m.X to v` / `set m["X"] to v` sobre un módulo: religa SU variable (la que leen sus
/// tasks), como `m.X = v` en Python; sus nombres son sus exportaciones y sus tasks no se
/// reemplazan desde afuera.
fn module_rebind(
    m: &Rc<RefCell<IndexMap<String, SynValue>>>,
    menv: &Rc<RefCell<Environment>>,
    name: &str,
    value: SynValue,
    loc: &SourceLocation,
) -> Result<SynValue, Control> {
    let current = m.borrow().get(name).cloned();
    match current {
        None => Err(err_at(
            format!("module has no export '{}' — a module's names are the ones it exports; add `export let {} be …` in the module", name, name),
            loc,
        )),
        Some(SynValue::Task(_)) => Err(err_at(format!("cannot replace the module task '{}' from outside the module", name), loc)),
        Some(_) => {
            let _ = env_update(menv, name, value.clone());
            Ok(value)
        }
    }
}

/// Si `parent` es el mapa de un módulo y `name` una de sus exportaciones: acceso único a la
/// VARIABLE del módulo (sincroniza el mapa). `None` si no es un módulo o no exporta ese nombre.
fn module_var_unique(parent: &SynValue, name: &str) -> Option<SynValue> {
    let SynValue::Map(m) = parent else { return None };
    if !m.borrow().contains_key(name) {
        return None;
    }
    let menv = module_env_of_map(m)?;
    with_unique_binding(&menv, name, |slot| slot.clone())
}

/// Un camino que se puede leer dos veces sin efectos: una variable, `p.campo` o `p[k]` con
/// `k` literal o variable.
fn is_pure_place(n: &Node) -> bool {
    match &n.kind {
        NodeKind::Identifier { .. } => true,
        NodeKind::PropertyAccess { object, .. } => is_pure_place(object),
        NodeKind::IndexAccess { object, index } => {
            is_pure_place(object)
                && matches!(
                    index.kind,
                    NodeKind::Identifier { .. } | NodeKind::NumberLiteral { .. } | NodeKind::TextLiteral { .. }
                )
        }
        _ => false,
    }
}

/// ¿`a` y `b` escriben el mismo camino puro? (misma forma, sin mirar ubicaciones)
fn same_place(a: &Node, b: &Node) -> bool {
    match (&a.kind, &b.kind) {
        (NodeKind::Identifier { name: x }, NodeKind::Identifier { name: y }) => x == y,
        (
            NodeKind::PropertyAccess { object: oa, property_name: pa, .. },
            NodeKind::PropertyAccess { object: ob, property_name: pb, .. },
        ) => pa == pb && same_place(oa, ob),
        (NodeKind::IndexAccess { object: oa, index: ia }, NodeKind::IndexAccess { object: ob, index: ib }) => {
            same_place(oa, ob)
                && match (&ia.kind, &ib.kind) {
                    (NodeKind::Identifier { name: x }, NodeKind::Identifier { name: y }) => x == y,
                    (NodeKind::TextLiteral { value: x }, NodeKind::TextLiteral { value: y }) => x == y,
                    (NodeKind::NumberLiteral { .. }, NodeKind::NumberLiteral { .. }) => ia.kind == ib.kind,
                    _ => false,
                }
        }
        _ => false,
    }
}

/// La posición de `insert(xs, i, v)`: `0..=len` (`len` agrega al final) y negativos desde el
/// final como en `xs[i]` (`-1` inserta antes del último). Fuera de rango es error, no se
/// recorta como en Python: un índice equivocado es un bug, no un "al final".
fn insert_position(i: &SynValue, len: usize) -> Result<usize, String> {
    let i = num_to_i64(i).map_err(|e| match e {
        Control::Error(e) => e.message,
        _ => "insert(): the position must be an integer".to_string(),
    })?;
    let n = len as i64;
    let j = if i < 0 { i + n } else { i };
    if j < 0 || j > n {
        return Err(format!("insert(): position {} out of range for a list of length {} (valid: -{}..{})", i, len, len, len));
    }
    Ok(j as usize)
}

/// ¿`a` y `b` son el MISMO contenedor (misma lista, mapa o valor privado)?
fn same_container(a: &SynValue, b: &SynValue) -> bool {
    match (a, b) {
        (SynValue::List(x), SynValue::List(y)) => Rc::ptr_eq(x, y),
        (SynValue::Map(x), SynValue::Map(y)) => Rc::ptr_eq(x, y),
        (SynValue::Private(x), SynValue::Private(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// Acceso MUTABLE y ÚNICO al binding `name` (el scope más cercano que lo tiene): el
/// contenedor se copia antes si otro lo comparte (`make_unique`), `f` lo modifica, y si el
/// binding es una exportación de un módulo, el mapa de exportaciones queda apuntando al
/// resultado. El mapa del módulo NO cuenta como otro dueño: es la otra vista del mismo
/// nombre, así que un task que escribe su estado no lo copia en cada vuelta, y `let snap be
/// m.STATE` (un tercer dueño) sí queda como foto.
fn with_unique_binding<R>(
    env: &Rc<RefCell<Environment>>,
    name: &str,
    f: impl FnOnce(&mut SynValue) -> R,
) -> Option<R> {
    let mut cur = env.clone();
    loop {
        let next = {
            let mut e = cur.borrow_mut();
            let is_module = e.name.starts_with("module:");
            if let Some(slot) = e.bindings.get_mut(name) {
                let view = if is_module { module_map_of_env(&cur) } else { None };
                let exported = view.as_ref().is_some_and(|m| m.borrow().contains_key(name));
                let shared_with_view = exported
                    && view.as_ref().is_some_and(|m| m.borrow().get(name).is_some_and(|v| same_container(v, slot)));
                make_unique_n(slot, if shared_with_view { 1 } else { 0 });
                let out = f(slot);
                if exported {
                    if let Some(m) = view {
                        m.borrow_mut().insert(name.to_string(), slot.clone());
                    }
                }
                return Some(out);
            }
            e.parent.clone()
        };
        match next {
            Some(p) => cur = p,
            None => return None,
        }
    }
}

/// Búsqueda léxica (el scope actual y sus padres). Pública para el análisis
/// estático de rutas (`route_meta::env_lookup`).
pub fn env_get(env: &Rc<RefCell<Environment>>, name: &str) -> Option<SynValue> {
    let mut cur = env.clone();
    loop {
        let next = {
            let e = cur.borrow();
            if let Some(v) = e.bindings.get(name) {
                return Some(v.clone());
            }
            e.parent.clone()
        };
        match next {
            Some(p) => cur = p,
            None => return None,
        }
    }
}

pub(crate) fn env_set(env: &Rc<RefCell<Environment>>, name: &str, value: SynValue) {
    env.borrow_mut().bindings.insert(name.to_string(), value);
}

/// Actualiza una variable existente en cualquier scope. `Err(())` si no existe.
fn env_update(env: &Rc<RefCell<Environment>>, name: &str, value: SynValue) -> Result<(), ()> {
    let mut cur = env.clone();
    loop {
        let has = cur.borrow().bindings.contains_key(name);
        if has {
            let is_module = cur.borrow().name.starts_with("module:");
            if is_module {
                // Una exportación religada dentro del módulo: el mapa `use … as m` la sigue.
                if let Some(m) = module_map_of_env(&cur) {
                    if m.borrow().contains_key(name) {
                        m.borrow_mut().insert(name.to_string(), value.clone());
                    }
                }
            }
            cur.borrow_mut().bindings.insert(name.to_string(), value);
            return Ok(());
        }
        let next = cur.borrow().parent.clone();
        match next {
            Some(p) => cur = p,
            None => return Err(()),
        }
    }
}

// =========================================================
// intérprete
// =========================================================

/// Límite de profundidad de recursión de llamadas. Evita que una recursión
/// patológica desborde el stack nativo (lo que abortaría el proceso); en su lugar
/// produce un error atrapable. NOTA paridad: Python lanza RecursionError a una
/// profundidad distinta (~100-150 niveles de task por su recursionlimit=1000).
/// El corpus no prueba el límite exacto; divergencia documentada.
#[cfg(not(target_arch = "wasm32"))]
const MAX_RECURSION: usize = 3000;
/// wasm32: el stack es lineal (fijado al linkear, ver `engine/.cargo/config.toml`) y un
/// overflow es un TRAP que descarta la instancia del embebedor — el guard salta antes.
#[cfg(target_arch = "wasm32")]
const MAX_RECURSION: usize = 600;

/// Builtins del core CONSCIENTES de etiquetas (reciben los argumentos envueltos):
/// Los cuatro de la feature y `print` (redacta por Display, y además RECHAZA la llamada bajo
/// PC privado: la cuenta de líneas es un canal que la redacción del valor no tapa — ronda 4).
/// `type_of` NO está: pasa por la regla genérica y por eso reporta el tipo del valor interno,
/// envuelto.
const CORE_LABEL_AWARE: &[&str] = &["private", "declassify", "label_of", "is_private", "print"];

/// Nombres PROTEGIDOS (B8): definir una task, variable, parámetro o alias con uno de
/// estos nombres es error de carga SIEMPRE (con etiquetas apagadas también): sombrear el
/// builtin anularía el etiquetado de las fuentes y engañaría al listado del auditor.
pub const PROTECTED_BUILTIN_NAMES: &[&str] = CORE_LABEL_AWARE;

/// SUMIDEROS del core (B7): builtins del core con efecto fuera del intérprete. Los
/// `llm_*` mandan el prompt al proveedor. Los demás sumideros (fs/http/sql/ws/memory/env/
/// exec/blackboard/webpush/run/proc) viven en el stdlib/agents y los registra el host con
/// `register_label_sink`. Las SENTENCIAS con efecto (`share`/`signal`/`send`/`spawn`/
/// `approve`/`confirm`/`ask`/`reason`/`decide`/`analyze`/`generate`) se comprueban en `exec`.
pub const CORE_SINK_BUILTINS: &[&str] = &["llm_step", "llm_stream"];

/// Hook que el host (motor) cablea para que `require <tipo>(<scope>)` conceda en
/// el `CapabilitySet` real (que vive fuera de core, para evitar el ciclo de deps).
/// Espeja el callback `_grant_capability` del intérprete Python.
pub type GrantHook = Rc<dyn Fn(&str, Option<&str>)>;
/// Hook de aislamiento de `sandbox` (lo cablea el motor, que tiene el CapabilitySet):
/// `true` al entrar (deniega TODAS las capabilities), `false` al salir (restaura).
/// Maneja sandboxes anidados (stack en el closure).
pub type SandboxHook = Rc<dyn Fn(bool)>;
/// Hook de `sandbox under <caps>` (T1 del spec de identidad): `Some(valor)` al entrar —
/// el valor es el map de capabilities (o el map que devolvió `captoken_verify`) y el host
/// lo apila como TECHO delegado sobre el CapabilitySet; `None` al salir (lo desapila).
/// `Err(texto)` si el valor no es un techo válido (nombre de capability desconocido…).
/// Core no conoce `Capability`: el host interpreta el valor.
pub type CeilingHook = Rc<dyn Fn(Option<&SynValue>) -> Result<(), String>>;

// --- FASE 1 tool-calling: el callback de paso del LLM (tipos PLANOS) ---
// core NO depende de `synsema-llm` (la dep va al revés vía runtime). Igual que
// `llm_callback`, el motor cablea este callback con el provider real; core sólo
// conoce estos tipos planos (sin `ToolSpec`/`LlmStep` de llm).

/// Entrada del catálogo que el builtin `llm_step` pasa al callback.
#[derive(Clone, Debug)]
pub struct StepCatalogEntry {
    pub name: String,
    pub description: String,
    pub params: Vec<String>,
}

/// Resultado que el callback de paso devuelve al builtin `llm_step`.
pub enum StepResult {
    Final { text: String, tokens: u64 },
    Tool { name: String, args: Vec<(String, String)>, tokens: u64 },
}

/// Callback de paso del LLM: `(prompt, catalog, context) -> StepResult`. Lo cablea el
/// motor con el provider tool-aware; sin él, `llm_step` devuelve un placeholder.
pub type LlmStepCallback =
    Rc<dyn Fn(&str, &[StepCatalogEntry], &str) -> StepResult>;

/// Callback de texto (reason/decide/analyze/generate): `(op, prompt) -> contenido`. El
/// motor lo cablea con el provider real; sin él, las ops LLM caen a placeholders.
pub type LlmTextCallback = Rc<dyn Fn(&str, &str) -> String>;

/// Callback dedicado de `decide` (DE-039): `(prompt, opciones) -> contenido`. Espejo
/// del de texto, pero con las opciones ESTRUCTURADAS para que el motor pueda forzar la
/// elección por tool/enum + normalizar + reintentar. Sin él, `decide` cae al callback
/// de texto genérico (retrocompat: mocks y wirings viejos intactos).
pub type LlmDecideCallback = Rc<dyn Fn(&str, &[String]) -> String>;

/// Callback del primitivo `judge` (System One): el motor lo cablea con el provider real o
/// el mock. `Ok(None)` = no disponible (offline, presupuesto agotado, red caída): cada
/// respuesta degrada a `available: false` con confianza 0. `Err(msg)` = la API rechazó el
/// pedido por culpa del programa (límites, instrucción vacía): error de runtime con el
/// mensaje del vendor. Sin callback: offline.
pub type JudgeCallback = Rc<
    dyn Fn(&crate::judge::JudgeRequest) -> Result<Option<crate::judge::JudgeResponse>, String>,
>;

/// Callback de streaming (`llm_stream`, F2): `(prompt, context, sink) -> texto completo`.
/// El motor lo cablea con `provider.call_stream`; el `sink` recibe cada fragmento a
/// medida que se genera y devuelve `false` para CORTAR la generación (p.ej. el `send`
/// de un cliente SSE desconectado falló). Sin él, `llm_stream` devuelve un placeholder.
#[allow(clippy::type_complexity)]
pub type LlmStreamCallback = Rc<dyn Fn(&str, &str, &mut dyn FnMut(&str) -> bool) -> String>;

/// Hook de aislamiento por-TOOL (least-privilege). Lo cablea el motor con el
/// `CapabilitySet`. `(true, declared)` al entrar: restringe las caps a las DECLARADAS
/// por la tool que el agente ya tenía (∩ agente, SIN heredar el resto del padre) → el
/// `require` por-tool queda ENFORCED, no metadata. `(false, &[])` al salir (restaura,
/// con stack para tools anidadas). Sin él: las tools corren con las caps ambientes.
pub type ToolScopeHook = Rc<dyn Fn(bool, &[(String, Option<String>)])>;

/// Hook que el host (motor) cablea para ejecutar un bloque `serve on PORT { … }`:
/// construye el `ServeRuntime`, bindea el puerto y lanza el servidor. Vive fuera de
/// core (en el motor + stdlib) para evitar el ciclo de deps. Recibe el `&mut`
/// intérprete (para evaluar puerto/opciones/handlers) y el nodo `ServeBlock`.
#[allow(clippy::type_complexity)]
pub type ServeHook =
    Rc<dyn Fn(&mut Interpreter, &Node, &Rc<RefCell<Environment>>) -> Result<SynValue, Control>>;

/// Callback humano de los gates (approve/confirm/ask): (acción, mensaje,
/// within_secs) → respuesta (bool para approve/confirm, texto para ask).
pub type HumanCallback = Rc<dyn Fn(&str, &str, Option<f64>) -> SynValue>;
/// Sink de `send` en un handler SSE: (valor, event_name) → Ok, o corta el stream.
pub type StreamEmitFn = Rc<dyn Fn(SynValue, Option<&str>) -> Result<(), Control>>;

/// Hook de escritura al blackboard (`share`): (clave, valor).
pub type ShareHook = Rc<dyn Fn(&str, &SynValue)>;
/// Hook de lectura del blackboard (`observe`): (clave) → valor.
pub type ObserveHook = Rc<dyn Fn(&str) -> Option<SynValue>>;
/// Hook de señal (`signal`): (canal, payload opcional).
pub type SignalHook = Rc<dyn Fn(&str, Option<SynValue>)>;
/// Hook de espera de señal (`wait_for`): (canal, timeout_secs) → payload.
/// `(canal, timeout_secs, cancel)` — el hook DEBE vigilar `cancel` mientras bloquea
/// (timeout de handler / shutdown / `agent_stop`): una espera larga no puede ignorar
/// una cancelación cooperativa.
pub type WaitForHook = Rc<dyn Fn(&str, Option<f64>, &Arc<AtomicBool>) -> Option<SynValue>>;

/// Token de cancelación cooperativa de un intérprete (ver `Interpreter::cancel`).
/// `Send + Sync`: el server lo crea por request y lo cancela desde el lado async; el
/// swarm lo guarda por agente para `agent_stop`.
pub type CancelWaker = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub struct CancelToken {
    pub flag: Arc<AtomicBool>,
    pub reason: Arc<std::sync::Mutex<String>>,
    /// Despertadores: una espera bloqueante (select/recv sobre `mio::Poll`, condvar)
    /// registra cómo despertarla; `cancel()` los invoca para que la cancelación sea
    /// inmediata y no espere al timeout de la espera.
    wakers: Arc<std::sync::Mutex<Vec<CancelWaker>>>,
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancelToken(cancelled={})", self.is_cancelled())
    }
}

impl CancelToken {
    pub fn new() -> Self {
        CancelToken {
            flag: Arc::new(AtomicBool::new(false)),
            reason: Arc::new(std::sync::Mutex::new(String::new())),
            wakers: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
    /// Marca la cancelación con un motivo (idempotente; el primer motivo gana) y
    /// despierta a las esperas registradas.
    pub fn cancel(&self, reason: &str) {
        if let Ok(mut g) = self.reason.lock() {
            if g.is_empty() {
                g.push_str(reason);
            }
        }
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let wakers: Vec<CancelWaker> = self.wakers.lock().map(|g| g.clone()).unwrap_or_default();
        for w in wakers {
            w();
        }
    }
    /// Registra un despertador (idempotencia a cargo del caller: acotado por token).
    pub fn add_waker(&self, w: CancelWaker) {
        if let Ok(mut g) = self.wakers.lock() {
            if g.len() < 64 {
                g.push(w);
            }
        }
    }
    /// Identidad del token (para que un hub registre su waker UNA vez por token).
    pub fn id(&self) -> usize {
        Arc::as_ptr(&self.flag) as usize
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}
/// Hook de `spawn`: (agente, body, args, snapshot de globals) → instance_id.
pub type SpawnHook = Rc<
    dyn Fn(&str, Vec<Node>, Vec<(String, SynValue)>, Vec<(String, SynValue)>, SpawnSubject) -> Result<String, Control>,
>;

/// T1 (identidad): lo que el intérprete sabe del SUJETO de la unidad de trabajo en curso y
/// que el agente spawneado hereda — la identidad autenticada y su techo de gasto delegado.
/// (El techo delegado de capabilities y el presupuesto LLM viven fuera de core: el motor
/// los captura del CapabilitySet y del hilo al recibir esto.)
#[derive(Clone, Debug, Default)]
pub struct SpawnSubject {
    pub identity: Option<String>,
    pub spend_limits: Vec<(String, String)>,
}

/// Hooks que el host (motor) cablea para conectar `share`/`observe`/`signal`/
/// `wait_for`/`spawn` al swarm real (blackboard + señales + hilos). Espejan los
/// callbacks `_swarm_*` del intérprete Python. Si no están, share/observe usan el
/// blackboard local (programa de un solo hilo) y signal/wait_for/spawn caen a su
/// comportamiento in-process.
#[derive(Clone)]
pub struct SwarmHooks {
    pub share: ShareHook,
    pub observe: ObserveHook,
    pub signal: SignalHook,
    /// `wait_for(canal, timeout_secs)` — `None` = default (30 s). Batch 7.
    pub wait_for: WaitForHook,
    /// `spawn(name, body, args, globals)` — `globals` es un snapshot de los bindings
    /// globales del intérprete llamador (tareas, valores, módulos) para que el agente
    /// hijo los tenga disponibles sin necesitar HTTP ni wrappers.
    pub spawn: SpawnHook,
}

/// Aviso ÚNICO por proceso cuando una op LLM cae a placeholder por estar OFFLINE.
/// Filosofía (spec DX-1): la degradación NUNCA rompe la cadena del agente — el
/// placeholder se devuelve igual y el programa sigue — pero JAMÁS es silenciosa: la
/// falla se descubre en desarrollo, con el diagnóstico a un comando de distancia.
/// Por stderr (no contamina el stdout del programa) y una sola vez (no spamea un
/// loop de agente con muchos pasos).
static LLM_OFFLINE_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// `true` SOLO la primera vez sobre `flag` (separado de la static para poder testearlo
/// con un flag local, sin depender del orden de los tests del proceso).
fn first_time(flag: &std::sync::atomic::AtomicBool) -> bool {
    !flag.swap(true, std::sync::atomic::Ordering::Relaxed)
}

static JUDGE_OFFLINE_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static JUDGE_PATHS_WARNED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

/// Aviso (una vez por ruta y pregunta en el proceso) de una ruta con backticks que la
/// instrucción menciona y el `state` no tiene. Sobre un campo inexistente el modelo contestó
/// 0,31 — ni cero ni medio — así que vale más avisar antes de gastar la llamada.
fn note_judge_missing_path(qid: &str, path: &str, var_hint: Option<&str>, loc: &SourceLocation) {
    let key = format!("{}\u{0}{}", qid, path);
    let set = JUDGE_PATHS_WARNED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let first = set.lock().map(|mut s| s.insert(key)).unwrap_or(true);
    if first {
        let fix = match var_hint {
            Some(var) => format!(
                "the model sees the value of `{v}`, not its name — pass `judge {{\"{v}\": {v}}}` if the question should say `{v}.…`, or drop the `{v}.` prefix",
                v = var
            ),
            None => "fix the path or add the field to the state".to_string(),
        };
        eprintln!(
            "[synsema] warning: {}:{}: judge '{}' refers to `{}` but the state has no such path — the model will answer about a field it cannot see; {}",
            loc.file, loc.line, qid, path, fix
        );
    }
}

fn note_judge_offline() {
    if first_time(&JUDGE_OFFLINE_NOTICED) {
        // En INGLÉS y auto-contenido, como el aviso LLM: lo leen humanos y agentes.
        eprintln!(
            "[synsema] notice: judge is OFFLINE — every `judge` answer is returning available: false \
             with confidence 0 and its main value (probability/choice/score) as nothing, not a real \
             judgment. The program keeps running; a confidence gate sends these to the human path by \
             itself. To enable it, set TYPESAFE_API_KEY in the process environment or in the .env file \
             (SYNSEMA_JUDGE_PROVIDER=mock serves deterministic answers for tests and demos)."
        );
    }
}

fn note_llm_offline() {
    if first_time(&LLM_OFFLINE_NOTICED) {
        // En INGLÉS y auto-contenido: este aviso lo leen humanos Y agentes LLM de
        // cualquier parte — debe explicar qué pasó y qué hacer sin contexto previo.
        eprintln!(
            "[synsema] notice: LLM is OFFLINE — reason/decide/analyze/generate/llm_step/\
             llm_stream are returning placeholder strings, not real model answers. The \
             program keeps running. To diagnose (which variable is missing and where), run: \
             synsema llm status"
        );
    }
}

pub struct Interpreter {
    pub global_env: Rc<RefCell<Environment>>,
    pub output: Vec<String>,
    /// Salida en vivo (DE-018/019): sólo `true` en el camino de `synsema run` interactivo.
    /// Gatea el drenado de `flush()`/`read_line` a stdout. En `conform`/`test`/`serve`
    /// queda `false` → la salida se COLECTA en `output` (JSON `out`/respuesta), nunca a
    /// stdout crudo (no rompe el contrato del oráculo).
    pub live_output: bool,
    pub blackboard: HashMap<String, SynValue>,
    pub agent_definitions: HashMap<String, (Vec<Node>, Rc<RefCell<Environment>>)>,
    /// Contexto de agente para los namespaces de memoria (DB-M1, decisión #4):
    /// stack de nombres de agente en ejecución. Vacío = top-level (`source = "main"`).
    /// El fallback in-process de `spawn` pushea/popea acá; el camino swarm (hilo
    /// propio) lo fija una vez con `set_agent_context` al construir el intérprete
    /// del agente. `current_agent()` es lo que leen `remember`/`recall`.
    agent_context: Vec<String>,
    /// Identidad del SUJETO de la unidad de trabajo en curso : la identidad de
    /// agente que autenticó esta request del serve. NO es `agent_context` (ese es el
    /// agente del swarm que corre el código); acá va *en nombre de quién* corre. La
    /// consume el ledger de `spend` para contabilizar y limitar por identidad, y el
    /// runtime la fija por request desde `request.user`.
    request_identity: Option<String>,
    /// Techo de gasto DELEGADO a esta identidad (unidad → monto en texto decimal),
    /// típicamente el caveat `spend` de un captoken verificado. Se aplica ADEMÁS del
    /// techo del host (fail-closed: mandan los dos, gana el más chico).
    request_spend_limits: Vec<(String, String)>,
    recursion_depth: usize,
    /// Cancelación COOPERATIVA (timeout de handler, shutdown ordenado, `agent_stop`):
    /// `exec_block` la chequea por statement y las esperas largas (select/recv/sleep/
    /// wait_for/run) en su loop. Al verla → `Control::Error("cancelled: …")`; un
    /// `try/recover` puede observarla pero no curarla (el flag sigue puesto y el próximo
    /// statement vuelve a cortar). El `Arc` cruza hilos: el server/el swarm lo setean.
    cancel: CancelToken,
    /// Extensiones opacas del host (p. ej. el hub de I/O del stdlib): el core no conoce
    /// sus tipos; quien las registra las recupera con `downcast`. Es el único slot
    /// genérico — evita enhebrar tipos del stdlib por todas las firmas del motor.
    pub ext: RefCell<HashMap<&'static str, Rc<dyn std::any::Any>>>,
    /// Concede capabilities declaradas con `require` (lo cablea el motor).
    grant_hook: Option<GrantHook>,
    /// Aislamiento de `sandbox`: profundidad de anidamiento (>0 = dentro de un sandbox)
    /// y un hook que vacía/restaura el CapabilitySet durante el cuerpo. Un `require`
    /// dentro de un sandbox es no-op (no se puede re-grantear para escapar).
    sandbox_depth: u32,
    sandbox_hook: Option<SandboxHook>,
    /// Hook de `sandbox under <caps>`: apila/desapila un techo delegado (lo instala el
    /// motor con el CapabilitySet). Sin él, `sandbox under` es un error claro.
    ceiling_hook: Option<CeilingHook>,
    /// Hook de aislamiento por-tool (least-privilege en `call_tool`). Lo instala el
    /// motor con el CapabilitySet. Sin él: las tools corren con las caps ambientes.
    tool_scope_hook: Option<ToolScopeHook>,
    /// Profundidad de `call_tool` (>0 = ejecutando el cuerpo de una tool con
    /// least-privilege). Un `require` ANIDADO en ese cuerpo (bajo when/if/while, que NO
    /// se extrae a `required_capabilities`) es no-op acá → no puede auto-concederse una
    /// cap para escapar del scope. Espejo de `sandbox_depth`.
    tool_scope_depth: u32,
    /// Intent declarado (descriptivo). El texto no gatea nada.
    intent: Option<String>,
    /// True una vez congelado el intent (tras el preámbulo) — anti prompt-injection.
    intent_frozen: bool,
    /// Conexión al swarm real (lo cablea el motor para agentes en hilos).
    swarm_hooks: Option<SwarmHooks>,
    /// Callback humano (approve/confirm/ask). (action, message, timeout_secs) →
    /// synValue (bool para approve/confirm, texto para ask). `timeout_secs` es el
    /// `within` del gate (None = sin `within`; decide el host). Sin él: auto-aprueba.
    human_callback: Option<HumanCallback>,
    /// Callback LLM (reason/decide/analyze/generate): (operación, prompt) → contenido.
    /// El `prompt` lleva el texto ya renderizado de la op (subject/data/objective/…)
    /// para que el provider real tenga qué mandar; un mock puede ignorarlo y keyear por
    /// la operación. Sin él: placeholders descriptivos.
    llm_callback: Option<LlmTextCallback>,
    /// Callback dedicado de `decide` (DE-039): recibe las opciones estructuradas para
    /// el contrato tool/enum + normalización + reintento. Sin él: `decide` usa el
    /// callback de texto genérico (retrocompat).
    llm_decide_callback: Option<LlmDecideCallback>,
    /// Callback LLM tool-aware de PASO (`llm_step`, FASE 1): el motor lo cablea con el
    /// provider guionable/real. Sin él: `llm_step` devuelve un placeholder seguro.
    llm_step_callback: Option<LlmStepCallback>,
    /// Callback LLM de STREAMING (`llm_stream`, F2): el motor lo cablea con
    /// `provider.call_stream`. Sin él: `llm_stream` devuelve el placeholder
    /// `"[no llm provider]"` sin invocar `on_chunk`.
    llm_stream_callback: Option<LlmStreamCallback>,
    /// Callback de `llm_usage()` (FRAMEWORK F1): devuelve los tokens LLM acumulados
    /// del proceso. Introspección sin gate (como `llm_available`). Sin él (offline /
    /// sin provider): el builtin devuelve 0.
    llm_usage_callback: Option<Rc<dyn Fn() -> u64>>,
    /// Gate de capability para las ops LLM: lo cablea el motor para exigir
    /// `require llm` antes de CUALQUIER op LLM (provider real o placeholder).
    /// `Err(msg)` → la op falla con `Capability not granted: llm`. Sin él: sin gate
    /// (core no depende de capabilities; el motor provee la lógica).
    llm_cap_hook: Option<Rc<dyn Fn() -> Result<(), RuntimeError>>>,
    /// Callback de `judge` (ver [`JudgeCallback`]). Sin él: offline, `available: false`.
    judge_callback: Option<JudgeCallback>,
    /// `judge_usage()`: tokens de entrada acumulados del proceso. Sin él: 0.
    judge_usage_callback: Option<Rc<dyn Fn() -> u64>>,
    /// `judge_model()`: id versionado que contestó la última llamada. Sin él: nothing.
    judge_model_callback: Option<Rc<dyn Fn() -> Option<String>>>,
    /// Gate de la capability `judge` (propia: no la concede `llm`). Lo cablea el motor.
    judge_cap_hook: Option<Rc<dyn Fn() -> Result<(), RuntimeError>>>,
    /// `SYNSEMA_JUDGE_DECIDE=1`: `decide between […] given X` se sirve con el juez (una pregunta
    /// `choose`) en vez del LLM. Opt-in del host; sin provider de judge cae al camino LLM.
    decide_via_judge: bool,
    /// Hook de `serve on PORT` (lo cablea el motor en el camino de serve).
    serve_hook: Option<ServeHook>,
    /// Sink de `send` dentro de un handler de stream SSE (lo cablea el motor por
    /// request de streaming). (value, event_name) → (). Sin él, `send` es error.
    stream_emit: Option<StreamEmitFn>,
    /// Hook de log: si está seteado, cada `log` llama el hook en tiempo real (además
    /// de pushear a `output`). Thread-safe (`Arc+Sync`) para que los hilos de agentes
    /// puedan escribir a stdout del proceso principal sin bufferizado.
    #[allow(clippy::type_complexity)]
    pub log_hook: Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
    /// Módulos locales (use/export): caché por path resuelto, set de módulos en
    /// carga (detección de import circular) y una pila de listas de nombres
    /// exportados (un frame por módulo en carga; el frame base es el del
    /// entrypoint y nunca se cosecha → un `export` top-level del entrypoint se ignora).
    module_cache: HashMap<String, SynValue>,
    loading_modules: HashSet<String>,
    exports_collector: Vec<Vec<String>>,
    /// Argumentos del programa (`args()`): lo que siguió al `--` en `synsema run`, o
    /// todo el argv en un binario `synsema build`. Datos que el invocador escribió para
    /// ESTE programa — sin capability (no es un recurso del host).
    program_args: Vec<String>,
    /// v0.6.20 — contador de pasos: un incremento por nodo que pasa por `exec`. Determinista
    /// por construcción (cuenta trabajo del intérprete, no tiempo). Lo expone `steps()` (sin
    /// capability: introspección, como `llm_usage()`); el runtime y el wasm lo reportan.
    steps: u64,
    /// v0.6.20 — raíz del proyecto: el directorio del archivo de ENTRADA, límite de contención
    /// de `use "../x.syn"`. La fija el host (`set_project_root`) o, si no, se captura del primer
    /// `use` que se ejecuta (siempre el top-level de la entrada). `None` = criterio v0.6.19
    /// (el directorio del importador).
    project_root: Option<std::path::PathBuf>,
    /// Gate de `stdout` (lo cablea el motor con el CapabilitySet): se consulta UNA vez
    /// por intérprete en el primer `print`/`show`/`log` y el veredicto se memoiza —
    /// el techo del host (`--cap-set` sin `stdout`) manda también sobre la salida.
    stdout_hook: Option<Rc<dyn Fn() -> Result<(), String>>>,
    stdout_verdict: Option<Result<(), String>>,
    /// Gate de `file.read` para las lecturas de template a disco (`render`/`include`/
    /// `layout`). Sin él, `render(".env")` leía cualquier archivo del cwd sin capability
    /// —bypass del modelo entero—. Lo cablea el motor con el CapabilitySet; recibe el path
    /// CRUDO (como se escribió en `render`/`{ include }`) para que el scope coincida con
    /// `read_file`. Los assets del bundle NO pasan por acá (son el programa).
    template_read_hook: Option<Rc<dyn Fn(&str) -> Result<(), RuntimeError>>>,
    /// Nombres de variables de entorno que Synsema considera SECRETAS (claves de
    /// proveedor LLM, el webhook humano, y las cargadas del `.env`): `run()`/`proc_spawn`
    /// las QUITAN del entorno del proceso hijo (a menos que el programa las pase explícito
    /// por `opts.env`). Cierra la exfiltración `run("printenv")` con `exec` pero sin
    /// `env`/`secret`. Vacío en usos standalone/wasm (sin proceso) → sin efecto.
    sensitive_env: HashSet<String>,
    /// Etiquetas de flujo por principal (`labels.rs`). Apagadas por default: con
    /// `labels == false` ningún camino nuevo corre más allá de un `if self.labels` (mismos
    /// resultados, mismos `steps`, misma salida que sin la feature).
    labels: bool,
    /// Stack de etiquetas de PC (flujos implícitos). Cada entrada es la etiqueta ACUMULADA
    /// (unión con la de abajo), así `pc.last()` es la etiqueta efectiva del contexto.
    pc: Vec<Label>,
    /// Lo privado que se desenvolvió o gateó control evaluando el NODO en curso (se salva y
    /// Se funde con el del padre en cada `exec`). Etiqueta el mensaje del error que atrapa un
    /// `recover` y decide con qué principales se redacta un error: por eso es por nodo y no
    /// acumulado de toda la corrida — si no, cualquier error posterior a haber tocado un
    /// privado salía `private(app)` aunque no tuviera relación (indepurable).
    seen: Label,
    /// ¿La corrida tocó ALGÚN privado? (monótono; lo lee el host con `private_seen`).
    seen_any: bool,
    /// UNIÓN de todo lo privado que la corrida tocó, monótona (a diferencia de `seen`, que es
    /// por nodo). Es la etiqueta del ESTADO AMBIENTE del intérprete —`steps()` hoy—: un
    /// contador global no viaja por el resultado de una task, así que el borde de llamada no lo
    /// alcanza y salía público después de una corrida privada (auditoría ronda 5).
    touched: Label,
    /// Registro de `declassify` ejecutados (motivo/from/to/ubicación), para el host.
    declassify_log: Vec<DeclassifyEntry>,
    /// Builtins que SABEN de etiquetas: reciben los argumentos tal cual (envueltos) y
    /// deciden ellos (redactan, marcan, comprueban con `labels::check_flow`). Los del core
    /// vienen de fábrica; el host agrega los suyos con `register_label_aware`.
    label_aware: HashSet<String>,
    /// SUMIDEROS (B7): builtins con efecto fuera del intérprete (I/O, red, DB, LLM…). Con
    /// etiquetas encendidas se comprueban ANTES de ejecutarse: ningún argumento puede llevar
    /// etiquetas (profundo, `check_flow` contra público) y el PC tiene que estar vacío.
    /// Los del core (`CORE_SINK_BUILTINS`) vienen de fábrica; el host registra los suyos con
    /// `register_label_sink`.
    label_sinks: HashSet<String>,
    /// Acumulador de etiquetas de los PATRONES evaluados durante un `match` (B3): cada valor
    /// De patrón que se compara con el sujeto suma su etiqueta profunda; el cuerpo del arm
    /// (y los arms siguientes, y el `otherwise`) corren bajo esa unión.
    pattern_label: Label,
    /// Etiqueta de CONTINUACIÓN de un `stop` disparado bajo PC
    /// privado: cuántas vueltas alcanzó a dar el bucle es información privada, y lo que las
    /// vueltas anteriores escribieron en variables públicas se lee DESPUÉS del bucle (caso
    /// 1.c). Se une al PC en `pc_label()` y vale hasta el final del bloque/bucle y del resto
    /// del cuerpo de la task donde saltó: se salva y restaura en el borde de llamada, y se
    /// limpia al terminar un bloque `test`, un request o la unidad de ejecución (también por
    /// El camino de error). Un `give` NO tiñe: su punto de llegada es el sitio de la llamada,
    /// Que es un join point, y lo que transporta la información es el VALOR devuelto, que ya
    /// sale etiquetado (B2).
    control_taint: Label,
    /// T5 (ronda 5) — la tinta de continuación de un `stop`: **muere al salir del bucle** del
    /// que el `stop` sale (`enter_loop`/`exit_loop`). Adentro del bucle vale igual que
    /// `control_taint`, así que un contador público sigue violando en la vuelta 0; al salir los
    /// dos caminos convergen y no puede quedar nada público con la cuenta. Separarla de
    /// `control_taint` es lo que devolvió la escribibilidad después de un bucle de búsqueda.
    loop_taint: Label,
    /// T5 (ronda 5) — la parte de la tinta que ESCAPA del cuerpo de esta task: un `stop` que no
    /// tiene un bucle propio donde caer corta el bucle **del llamador**, así que `leave_call`
    /// se la suma a él. Sin esto, un helper de una línea extraía el secreto entero por un
    /// contador público del llamador (la fuga V1 en el sentido contrario).
    escaping_taint: Label,
    /// Bucles abiertos **en el cuerpo de la task en curso** (`enter_call` lo pone en 0: los
    /// `stop` del callee no caen en un bucle nuestro). Decide adónde va la tinta de un `stop`.
    loop_depth: usize,
    /// Etiqueta vacía compartida (evita alocar un `Rc` por consulta de `pc_label()`).
    no_label: Label,
    /// T5 (M1, ronda 3) — principales que se pueden imprimir VERBATIM en un diagnóstico: los
    /// literales que el propio programa escribió en un `private(…)` y los que el host registre
    /// (`register_label_principal`). Cualquier otro sale como `#<índice>`: el nombre de un
    /// principal viaja por el único canal que no se redacta, así que no se imprime un texto
    /// cuyo origen no se conoce.
    known_principals: RefCell<HashSet<String>>,
    /// T5 (ronda 7) — los principales DECLARADOS por el programa (literales del AST) más los que
    /// registró el host. Constante para la corrida: es lo único que se puede imprimir al
    /// redactar sin que el texto delate qué valor se seleccionó. Ver `refresh_redaction_text`.
    declared_principals: RefCell<HashSet<String>>,
    /// El texto ya armado (`"app"`, `"app,bank"`, o vacío), para no re-ordenar en cada mensaje.
    redaction_text: RefCell<String>,
    /// T5 (ronda 7): ¿el último resultado que salió hacia el host lo cortó el sistema de
    /// etiquetas? Lo lee el serve para reponer lo que el request alcanzó a escribir en el
    /// almacén compartido antes del corte (`finish_state_journal`).
    label_stop: Cell<bool>,
    /// T5 (ronda 8): el conjunto con el que se redacta se SELLA después del recorrido estático
    /// del programa de entrada. `use` es una sentencia ejecutable y puede ir dentro de una rama
    /// privada, así que dejar que un módulo aporte principales al cargarse volvía a hacer variar
    /// el texto con el camino tomado (ocho `use` condicionales = un byte).
    principals_sealed: Cell<bool>,
    /// T5 (regla 3.a) — máscara de qué argumentos de la llamada EN CURSO eran literales
    /// escalares en el fuente. La fija el `TaskCall` justo antes de despachar y sólo la leen
    /// `private`/`declassify` como primera cosa: un principal/motivo escrito como literal es
    /// texto del programa (aunque bajo PC lleve la etiqueta del contexto), y uno computado a
    /// partir de datos privados no puede serlo.
    arg_literals: u32,
    /// Argumentos sólo-por-nombre de la llamada a builtin en curso (`BUILTIN_KWARGS`).
    pending_kwargs: IndexMap<String, SynValue>,
    /// Linaje (v0.6.29, DATOS-17): cada dato que el programa LEYÓ, anotado por el motor.
    lineage: Vec<LineageEntry>,
    /// Bytes canónicos de un valor estructurado para el linaje (el stdlib instala
    /// `canonical_json`, RFC 8785): así cualquiera recalcula el hash de un resultado de SQL.
    pub lineage_canonical: Option<Rc<dyn Fn(&SynValue) -> Option<(Vec<u8>, &'static str)>>>,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Interpreter {
    fn drop(&mut self) {
        // Rompe el ciclo de Rc del entorno global: cada task del global cierra sobre
        // `global_env` (su `closure_env`) y el entorno las contiene en `bindings` →
        // `global_env ⇄ tasks` es un ciclo que `Rc` NUNCA libera (Python tiene GC de
        // ciclos; este port no). En el modelo snapshot-por-request del serve cada request
        // arma un `global_env` fresco con este ciclo, así que al terminar NO se libera:
        // leak de ~decenas de KB/request (la RSS trepa bajo carga y en Linux no baja →
        // segundo OOM). Vaciar las bindings acá corta el ciclo y libera el entorno entero
        // (tasks + AST clonado + valores) cuando el intérprete se dropea.
        // `try_borrow_mut`: en drop no debería haber borrows vivos, pero si los hubiera no
        // paniqueamos (sólo nos saltamos la limpieza de ese intérprete).
        if let Ok(mut env) = self.global_env.try_borrow_mut() {
            env.bindings.clear();
        }
    }
}

impl Interpreter {
    pub fn new() -> Self {
        let interp = Interpreter {
            global_env: Environment::root("global"),
            output: Vec::new(),
            blackboard: HashMap::new(),
            agent_definitions: HashMap::new(),
            agent_context: Vec::new(),
            request_identity: None,
            request_spend_limits: Vec::new(),
            recursion_depth: 0,
            cancel: CancelToken::new(),
            ext: RefCell::new(HashMap::new()),
            grant_hook: None,
            sandbox_depth: 0,
            sandbox_hook: None,
            ceiling_hook: None,
            tool_scope_hook: None,
            tool_scope_depth: 0,
            intent: None,
            intent_frozen: false,
            swarm_hooks: None,
            human_callback: None,
            llm_callback: None,
            llm_decide_callback: None,
            llm_step_callback: None,
            llm_stream_callback: None,
            llm_usage_callback: None,
            llm_cap_hook: None,
            judge_callback: None,
            judge_usage_callback: None,
            judge_model_callback: None,
            judge_cap_hook: None,
            decide_via_judge: false,
            serve_hook: None,
            stream_emit: None,
            log_hook: None,
            module_cache: HashMap::new(),
            loading_modules: HashSet::new(),
            exports_collector: vec![Vec::new()],
            live_output: false,
            program_args: Vec::new(),
            steps: 0,
            project_root: None,
            stdout_hook: None,
            stdout_verdict: None,
            template_read_hook: None,
            sensitive_env: HashSet::new(),
            labels: false,
            pc: Vec::new(),
            seen: labels::empty(),
            seen_any: false,
            touched: labels::empty(),
            declassify_log: Vec::new(),
            label_aware: CORE_LABEL_AWARE.iter().map(|s| s.to_string()).collect(),
            label_sinks: CORE_SINK_BUILTINS.iter().map(|s| s.to_string()).collect(),
            pattern_label: labels::empty(),
            control_taint: labels::empty(),
            loop_taint: labels::empty(),
            escaping_taint: labels::empty(),
            loop_depth: 0,
            no_label: labels::empty(),
            known_principals: RefCell::new(HashSet::new()),
            declared_principals: RefCell::new(HashSet::new()),
            redaction_text: RefCell::new(String::new()),
            label_stop: Cell::new(false),
            principals_sealed: Cell::new(false),
            arg_literals: 0,
            pending_kwargs: IndexMap::new(),
            lineage: Vec::new(),
            lineage_canonical: None,
        };
        interp.register_builtins();
        interp
    }

    /// Declara un builtin como SUMIDERO (B7): con etiquetas encendidas, antes de ejecutarlo
    /// Se exige que ningún argumento lleve etiquetas (profundo) y que el PC esté vacío;
    /// Si no, `label_violation` con el camino (`name(argument i).campo`). Fail-closed: el
    /// builtin no llega a correr. El host registra acá todo lo que tenga efecto fuera del
    /// intérprete (fs/http/sql/ws/memory/env/exec/blackboard/llm/webpush/run/proc).
    pub fn register_label_sink(&mut self, name: &str) {
        self.label_sinks.insert(name.to_string());
    }

    /// T5 (M1): declara un principal como seguro de imprimir en un diagnóstico. Lo llama el
    /// host que etiqueta fuentes con nombres propios (`labels::mark(v, label_from(&["app"]))`)
    /// para que sus mensajes digan `app` en vez de `#0`.
    pub fn register_label_principal(&self, name: &str) {
        self.known_principals.borrow_mut().insert(name.to_string());
        // Lo que fija el HOST antes de correr es constante para la corrida, así que entra al
        // conjunto con el que se redacta (ronda 7).
        self.declared_principals.borrow_mut().insert(name.to_string());
        self.refresh_redaction_text();
    }

/// T5 (ronda 7) — **el texto con el que se redacta no puede depender de la etiqueta del valor.**
    ///
    /// Redactar imprimía `private(<los principales de ESE valor>)`, y esa lista varía con qué valor se
    /// seleccionó, así que el mecanismo que existe para tapar el dato lo publicaba:
    ///
    /// ```text
    /// let xs be [private(10, "p0"), private(20, "p1")]
    /// print(xs[private(N, "app")])      N=0 → private(app,p0)   N=1 → private(app,p1)
    /// ```
    ///
    /// Con una tabla de 256 entradas sale el byte entero en una línea, con salida exitosa y la
    /// revisión estática en verde. Y no hace falta un programa adversario: en un despliegue
    /// multi-inquilino el principal ES el inquilino, así que imprimir un valor redactado le dice al
    /// operador de quién era el dato.
    ///
    /// Lo que se imprime ahora es **el conjunto de principales DECLARADOS en el programa**, que es
    /// constante por construcción: los literales que el fuente escribió en `private(v, "…")` más los
    /// que registró el host antes de correr. Para el caso normal —un programa con un solo principal,
    /// que es el del guest y el de cualquier enclave— el texto no cambia (`private(app)`) y los
    /// diagnósticos siguen sirviendo igual; lo que se pierde es la precisión en los programas con
    /// varios principales, que es exactamente donde estaba el canal.
    ///
    /// Lo fija `set_declared_principals` al cargar el programa (un recorrido del AST, estático), y lo
    /// leen tanto los mensajes del intérprete como el `Display` de un valor privado (por el
    /// thread-local de `labels`, que es como el `Display` llega hasta acá).
    fn refresh_redaction_text(&self) {
        let mut names: Vec<String> = self.declared_principals.borrow().iter().cloned().collect();
        names.sort();
        names.dedup();
        let text = if names.is_empty() { String::new() } else { names.join(",") };
        crate::labels::set_redaction_text(&text);
        *self.redaction_text.borrow_mut() = text;
    }
    
    /// T5 (ronda 7): ¿el último resultado hacia el host lo cortó el sistema de etiquetas? Lo
    /// consume el host (lo pone en `false` al leerlo).
    pub fn take_label_stop(&self) -> bool {
        self.label_stop.replace(false)
    }

    /// Los principales declarados, como lista — para un host que arma su propio informe (el ABI
    /// wasm). Constante para la corrida, a diferencia de la etiqueta de un valor.
    pub fn declared_principals_list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.declared_principals.borrow().iter().cloned().collect();
        v.sort();
        v
    }

    /// El principal que se pega en el REMEDIO de un mensaje. Con uno solo declarado —el caso
    /// normal, y el de cualquier enclave— es exacto y se puede copiar tal cual. Con varios no se
    /// pega la lista: `private(…, "a,b")` no es sintaxis válida, y un remedio que no compila es
    /// peor que un hueco. (Tampoco se pega el principal REAL del valor: ése es el canal que la
    /// ronda 7 cerró.)
    fn principal_hint(&self) -> String {
        let d = self.declared_principals.borrow();
        if d.len() == 1 {
            d.iter().next().cloned().unwrap_or_else(|| "<principal>".to_string())
        } else {
            "<principal>".to_string()
        }
    }

    /// El texto de redacción: constante para el programa. Ver `refresh_redaction_text`.
    fn redaction_names(&self) -> String {
        self.redaction_text.borrow().clone()
    }
    
    /// Los principales que el PROGRAMA declara, recogidos del AST antes de ejecutar nada: los
    /// literales de texto que aparecen como segundo argumento de `private(…)` y como tercer
    /// argumento de `declassify(…)`. Es estático, así que el texto de redacción no puede depender
    /// de qué camino tomó la corrida.
    pub fn set_declared_principals(&self, program: &Program) {
        // Sellado tras el programa de ENTRADA: un módulo cargado más tarde (y un `use` dentro de
        // una rama privada es exactamente eso) ya no mueve el texto. Sus principales siguen
        // entrando a `known_principals`, que es para otra cosa.
        if self.principals_sealed.replace(true) {
            return;
        }
        {
            let mut d = self.declared_principals.borrow_mut();
            for name in principal_literals(program) {
                d.insert(name);
            }
        }
        self.refresh_redaction_text();
    }

    /// T5 (M1): registra como conocidos los principales de un valor que ENTRA al intérprete ya
    /// etiquetado — es decir, una fuente marcada por el HOST en Rust (`input.sources` de la op
    /// `run`, los globales que inyecta un guest, los bindings de una request). Esos nombres los
    /// fija el host, no el programa, así que son tan confiables como un literal del fuente y se
    /// imprimen por nombre: si no, el diagnóstico del camino más usado decía `private(#0)` y el
    /// operador perdía de quién era el dato. Los que el PROGRAMA elige ya están acotados a
    /// literales (`private(v, "app")`), así que no hay texto de origen desconocido.
    fn harvest_principals(&self, v: &SynValue) {
        if !self.labels {
            return;
        }
        let l = labels::label_deep(v);
        if l.is_empty() {
            return;
        }
        let mut changed = false;
        {
            let mut known = self.known_principals.borrow_mut();
            let mut declared = self.declared_principals.borrow_mut();
            for p in l.iter() {
                known.insert(p.to_string());
                // Lo marca el HOST en Rust, no el programa, así que es constante por cableado y
                // puede entrar al conjunto con el que se redacta (ronda 7).
                changed |= declared.insert(p.to_string());
            }
        }
        if changed {
            self.refresh_redaction_text();
        }
    }

    /// T5 (M1): `a,#1` — los principales conocidos verbatim, el resto por índice.
    /// El texto de principales que sale en un DIAGNÓSTICO.
    ///
    /// T5 (ronda 7) — **ignora `_l` a propósito.** Antes imprimía los principales de esa etiqueta
    /// concreta (con `#índice` para los que el programa no había escrito como literal), y esa
    /// lista varía con qué valor se seleccionó: `print(xs[idx_privado])` daba `private(app,p0)` o
    /// `private(app,p1)` según el índice, o sea el mecanismo de redacción publicaba el dato. Se
    /// imprime el conjunto DECLARADO, constante para el programa. Para el caso normal —un solo
    /// principal, que es el del guest y el de cualquier enclave— el mensaje no cambia.
    ///
    /// El parámetro se conserva para que cada sitio siga diciendo QUÉ etiqueta quiso nombrar, y
    /// para que volver a un texto dependiente del valor sea un cambio visible, no un descuido.
    fn safe_label(&self, _l: &Label) -> String {
        let text = self.redaction_names();
        if text.is_empty() {
            "…".to_string()
        } else {
            text
        }
    }

    /// ¿La corrida desenvolvió algún valor privado o gateó control con uno ? El host lo
    /// usa para saber que un error/salida de esta corrida tocó datos privados (M1).
    pub fn private_seen(&self) -> bool {
        self.seen_any
    }

    /// Comprobación de sumidero (B7) sobre valores ya evaluados: PC vacío y ningún valor con
    /// etiquetas a ninguna profundidad. `what` nombra al sumidero en el camino del error.
    fn sink_check(&self, what: &str, values: &[&SynValue], loc: &SourceLocation) -> Result<(), Control> {
        if !self.pc_is_empty() {
            return Err(err_labels(
                format!(
                    // Auditoría ronda 6: era el ÚNICO de la familia sin la forma exacta del
                    // remedio, y es el más frecuente (todo builtin con efecto bajo una rama
                    // privada). Sus dos hermanos —el de valor y el de stdout— ya la dan.
                    "label_violation: {} called under private control flow (pc = [{}]); every builtin with an effect is a public sink, so the call itself cannot depend on private data. Move it out of the private branch, or declassify(<the condition>, \"<why it may be published>\") so the branch is public",
                    what,
                    self.safe_label(&self.pc_label())
                ),
                loc,
            ));
        }
        for (i, v) in values.iter().enumerate() {
            if let Err(viol) = labels::check_flow(v, &[], &format!("{}(argument {})", what, i)) {
                return Err(err_labels(
                    format!(
                        "label_violation: {} is private to {}, the sink accepts (public); declassify(<that value>, \"<why it may be published>\") the scalar you want to publish and build the container outside the private branch",
                        viol.path,
                        self.safe_label(&viol.label)
                    ),
                    loc,
                ));
            }
        }
        Ok(())
    }

    /// M1: mensaje de un `Control` para el host (reporte de tests), redactado como
    /// `redact_for_host`.
    fn host_message(&self, c: &Control) -> String {
        match c {
            Control::Error(e) => self.redacted_message(e).unwrap_or_else(|| e.to_string()),
            other => control_message(other),
        }
    }

    /// M1 : ¿con qué texto sale este error HACIA EL HOST? `Some(redactado)` si el
    /// error se originó bajo PC privado (`from_private_pc`, que el `exec` pone en el momento
    /// exacto del error — no por el `seen` monótono de toda la corrida, que volvía indepurable
    /// cualquier error posterior). Un diagnóstico del propio sistema de etiquetas
    /// (`from_labels`) NO se redacta, y la decisión es por FLAG: un `raise "label_violation:
    /// …"` del programa ya no puede hacerse pasar por uno (caso 1.j).
    ///
    /// Ronda 7: **sin ubicación**. El texto se redactaba y la línea no, así que si el secreto
    /// elige cuál de N sitios falla, `file:line:col` vale log₂(N) bits. Esto es lo que sale al
    /// HOST (el reporte del runner de tests); el CLI local, donde el host es el dueño del dato,
    /// conserva la ubicación por `redact_for_host` + el `Display` de `RuntimeError`.
    fn redacted_message(&self, e: &RuntimeError) -> Option<String> {
        if !self.labels {
            return None;
        }
        // Un diagnóstico del propio sistema de etiquetas no se redacta (su texto es el remedio),
        // pero tampoco lleva ubicación: cuál de los sitios violó también depende del dato.
        if e.from_labels {
            return Some(e.message.clone());
        }
        if e.redact_label.is_empty() {
            return None;
        }
        Some(format!("private({})", e.redact_label))
    }

    /// T5 (ronda 6, B2) — la SALIDA acumulada de una corrida que murió por etiquetas no se
    /// entrega: se reemplaza por una línea fija.
    ///
    /// Es el canal de PROGRESO, y hay que nombrarlo por lo que es. El predicado que enciende la
    /// tinta de rama (`block_exits_early`) sólo ve `give`, `stop` y un `raise` literal; un error
    /// de runtime dentro de una rama privada —o un `raise` indirecto por un helper— no lo
    /// enciende, así que las vueltas previas del bucle alcanzan a imprimir en claro y la
    /// CANTIDAD de líneas deletrea el secreto, que es justo lo que el mensaje de `print`
    /// advierte. Modelarlo estáticamente pedría tratar toda rama privada como salida temprana
    /// (cualquier operación puede fallar), y eso teñiría la continuación de cualquier `when`
    /// privado: rompe las siete apps del guest y no lo hago.
    ///
    /// Lo que sí se puede es no entregar el prefijo. Con el error ya fatal (B1), la corrida se
    /// corta en la vuelta del secreto; vaciando acá el buffer, lo que queda observable es que
    /// murió — un bit de terminación, que es el límite declarado —, no cuántas vueltas dio.
    /// **Residuo, dicho sin maquillaje:** los efectos que el prefijo ya hizo sobre OTROS
    /// sumideros (un `write_file` por vuelta) sí ocurrieron; eso no lo puede deshacer el motor
    /// y está declarado como límite en la spec.
    pub fn redact_output_for_host(&mut self, r: &Result<SynValue, Control>) {
        if !self.labels || self.output.is_empty() {
            return;
        }
        let fatal = matches!(r, Err(Control::Error(e)) if e.is_fatal_for_labels());
        if fatal {
            self.output.clear();
            self.output.push(
                "private(labels): the run was stopped by the flow checker; its output is withheld because the NUMBER of lines before the stop depends on private data"
                    .to_string(),
            );
        }
    }

    /// M1: un error que sale HACIA EL HOST (no atrapado por `try/recover`) se redacta si se
    /// originó bajo PC privado: el texto pasa a `private(<labels>)` (como `pc_redact`) y la
    /// ubicación se conserva. Con etiquetas apagadas es la identidad.
    fn redact_for_host(&mut self, r: Result<SynValue, Control>) -> Result<SynValue, Control> {
        if !self.labels {
            return r;
        }
        // T5 (ronda 6, B2): la salida acumulada tampoco sale si el chequeo de flujo cortó la
        // corrida — acá, en el mismo embudo que el mensaje, para que no dependa de que cada
        // host se acuerde. Idempotente: los hosts lo vuelven a llamar como segunda red.
        self.redact_output_for_host(&r);
        // T5 (ronda 7): y se deja anotado, para que el host pueda deshacer lo que el request
        // escribió en el almacén compartido antes del corte.
        if matches!(&r, Err(Control::Error(e)) if e.is_fatal_for_labels()) {
            self.label_stop.set(true);
        }
        match r {
            Err(Control::Error(mut e)) => {
                if !e.redact_label.is_empty() && !e.from_labels {
                    e.message = format!("private({})", e.redact_label);
                }
                Err(Control::Error(e))
            }
            other => other,
        }
    }

    /// No-sensitive-upgrade ESTRICTO (B1/M4): asignar bajo PC privado a algo cuya etiqueta
    /// efectiva (`have`) no cubre el PC es `label_violation`. Una variable/contenedor ya
    /// privados que cubren el PC siguen funcionando (el ledger `set state["balances"][to]`).
    fn nsu_check(&self, have: &Label, what: &str, loc: &SourceLocation) -> Result<(), Control> {
        /// `what` llega entrecomillado para los identificadores (`'counter'`); el remedio se
        /// escribe sin comillas.
        const QUOTE: char = 0x27 as char;
        let pc = self.pc_label();
        if !pc.is_empty() && !labels::subset(&pc, have) {
            return Err(err_labels(
                format!(
                    // Auditoría ronda 6: el remedio lleva el principal REAL y la forma tal cual
                    // se escribe (con `let`), no un `<principal>` que hay que ir a buscar.
                    "label_violation: cannot assign to {} ({}) under private control flow (pc = [{}]); declare it private first (let {} be private(<its initial value>, \"{}\")) or declassify(<the value>, \"<why it may be published>\") at this site",
                    what,
                    if have.is_empty() { "public".to_string() } else { format!("private to {}", self.safe_label(have)) },
                    self.safe_label(&pc),
                    what.trim_matches(QUOTE),
                    self.principal_hint()
                ),
                loc,
            ));
        }
        Ok(())
    }

    /// Enciende/apaga las etiquetas de flujo (`private`/`declassify`). Apagadas
    /// (default) la variante `Private` no existe en runtime y todo se comporta idéntico a
    /// sin la feature. Lo fijan el host (`serve --attested`, el guest) o `--labels`.
    pub fn set_labels(&mut self, on: bool) {
        self.labels = on;
        if !on {
            self.pc.clear();
            self.control_taint = labels::empty();
            self.loop_taint = labels::empty();
            self.escaping_taint = labels::empty();
            self.touched = labels::empty();
        }
    }

    /// ¿Están encendidas las etiquetas de flujo?
    pub fn labels_enabled(&self) -> bool {
        self.labels
    }

    /// Etiqueta de PC efectiva del contexto en curso: la del bloque en ejecución UNIDA a las dos
    /// de continuación — la de la TASK (`control_taint`: lo que sigue a un `give`/`raise`
    /// disparado desde un contexto privado) y la del BUCLE (`loop_taint`: lo que sigue a un
    /// `stop`). Vacía fuera de todo contexto privado o con las etiquetas apagadas. Para que un
    /// sumidero del host compruebe el flujo implícito además del explícito
    /// (`labels::check_flow` sobre el valor).
    pub fn pc_label(&self) -> Label {
        let top = self.pc.last().unwrap_or(&self.no_label);
        let cont = if self.control_taint.is_empty() {
            self.loop_taint.clone()
        } else if self.loop_taint.is_empty() {
            self.control_taint.clone()
        } else {
            labels::union(&self.control_taint, &self.loop_taint)
        };
        if cont.is_empty() {
            return top.clone();
        }
        labels::union(top, &cont)
    }

    /// ¿El PC efectivo está vacío? (sin alocar).
    #[inline]
    fn pc_is_empty(&self) -> bool {
        self.control_taint.is_empty()
            && self.loop_taint.is_empty()
            && self.pc.last().map_or(true, |l| l.is_empty())
    }

    /// T5 (ronda 3, B1) — **la tinta va en la RAMA, no en el salto**. Al evaluar un
    /// `when`/`match`/bucle con condición privada cuyo cuerpo puede SALIR antes de tiempo
    /// (`give`/`stop`/`raise`, estático: `block_exits_early`), la continuación queda teñida
    /// ahí mismo, **se tome o no la rama**.
    ///
    /// Teñir en el salto llegaba tarde: para cuando el `give` dispara en la vuelta 181, las
    /// 181 vueltas anteriores ya escribieron el contador público con PC vacío y el secreto ya
    /// está en la variable. Teñir en la rama hace que `set counter to counter + 1` viole en la
    /// vuelta 0 y la corrida falle cerrada.
    ///
    /// T5 (ronda 5) — **hasta dónde llega depende de adónde salta**, y los tres casos son
    /// distintos:
    ///
    /// · `give`/`raise` (`escapes_task`): el salto sale de la task. Llegar a la línea siguiente
    ///   ya significa que la rama no disparó, así que tiñe el resto del cuerpo. Al volver, la
    ///   información viaja en el VALOR, que sale etiquetado: no se propaga al llamador.
    ///
    /// · sólo `stop`, con un bucle de esta task donde caer: la tinta muere **al salir de ese
    ///   bucle**. Adentro sigue valiendo, que es lo que hace violar en la vuelta 0 a cualquier
    ///   contador público; al salir los dos caminos convergen y no puede quedar nada público
    ///   que lleve la cuenta (si lo hubiera, habría violado adentro). Seguir tiñendo el resto
    ///   de la task sólo sacaba escribibilidad: una línea de log pública y constante después de
    ///   un bucle de búsqueda no lleva ni un bit, y no compilaba.
    ///
    /// · sólo `stop` y NINGÚN bucle en esta task: el salto sale de la task y corta el bucle
    ///   **del llamador**. Tiñe lo que queda de este cuerpo y además viaja al llamador
    ///   (`escaping_taint`, ver `leave_call`) — si no, un helper `task h(s, i) / when s == i /
    ///   stop` llamado desde el bucle del llamador le extraía el secreto entero a un contador
    ///   público suyo, que es la misma clase de fuga que V1 pero en el sentido contrario.
    fn taint_branch(&mut self, l: &Label, escapes_task: bool) {
        if !self.labels || l.is_empty() {
            return;
        }
        if escapes_task {
            self.control_taint = labels::union(&self.control_taint, l);
        } else if self.loop_depth > 0 {
            self.loop_taint = labels::union(&self.loop_taint, l);
        } else {
            self.control_taint = labels::union(&self.control_taint, l);
            self.escaping_taint = labels::union(&self.escaping_taint, l);
        }
        self.note_seen(l);
    }

    /// T5: un `give` disparado bajo PC privado tiñe lo que sigue DENTRO de la task — el resto
    /// del cuerpo del bucle, el bucle mismo y el resto del bloque donde vive, hasta el borde de
    /// la task (`leave_call` restaura el valor del llamador, que es lo que evita que un retorno
    /// normal deje PC residual sobre código público del llamador).
    fn taint_after_give(&mut self) {
        if !self.labels {
            return;
        }
        let pc = self.pc_label();
        if !pc.is_empty() {
            self.control_taint = labels::union(&self.control_taint, &pc);
            self.note_seen(&pc);
        }
    }

    /// T5: un `stop` disparado bajo PC privado tiñe lo que sigue hasta salir del bucle del que
    /// sale — el número de vueltas que alcanzó a dar es información privada que se lee dentro
    /// del bucle (caso 1.c). Sin bucle propio, el salto corta el del llamador: ver
    /// `taint_branch`, tercer caso.
    fn taint_after_stop(&mut self) {
        if !self.labels {
            return;
        }
        let pc = self.pc_label();
        if pc.is_empty() {
            return;
        }
        if self.loop_depth > 0 {
            self.loop_taint = labels::union(&self.loop_taint, &pc);
        } else {
            self.control_taint = labels::union(&self.control_taint, &pc);
            self.escaping_taint = labels::union(&self.escaping_taint, &pc);
        }
        self.note_seen(&pc);
    }

    /// Entra al cuerpo de un bucle: la tinta que el cuerpo agregue por un `stop` muere al salir.
    /// Devuelve el valor a pasarle a `exit_loop`.
    #[inline]
    fn enter_loop(&mut self) -> Label {
        // Con etiquetas apagadas el camino queda idéntico al de siempre: una comparación.
        if !self.labels {
            return self.no_label.clone();
        }
        self.loop_depth += 1;
        self.loop_taint.clone()
    }

    /// Sale del bucle: descarta la tinta de `stop` que nació adentro y deja la de afuera.
    #[inline]
    fn exit_loop(&mut self, saved: Label) {
        if !self.labels {
            return;
        }
        self.loop_depth = self.loop_depth.saturating_sub(1);
        self.loop_taint = saved;
    }

    /// Guarda la tinta de continuación y la deja limpia. Es el borde de una UNIDAD DE EJECUCIÓN
    /// NUEVA —cuerpo de agente, request del serve, bloque `test`—, no el de una llamada: una
    /// task llamada desde código ya teñido sigue el MISMO flujo de control y hereda la tinta
    /// (`enter_call`). El valor devuelto se restaura con `restore_taint`.
    fn take_taint(&mut self) -> TaintFrame {
        TaintFrame {
            control: std::mem::replace(&mut self.control_taint, self.no_label.clone()),
            loops: std::mem::replace(&mut self.loop_taint, self.no_label.clone()),
            escaping: std::mem::replace(&mut self.escaping_taint, self.no_label.clone()),
            depth: std::mem::replace(&mut self.loop_depth, 0),
        }
    }

    /// Restaura la tinta de la unidad de afuera.
    fn restore_taint(&mut self, saved: TaintFrame) {
        self.control_taint = saved.control;
        self.loop_taint = saved.loops;
        self.escaping_taint = saved.escaping;
        self.loop_depth = saved.depth;
    }

    /// Borde de LLAMADA: la tinta del llamador **queda puesta** para el callee (regla 1.b, V1 de
    /// la ronda 4 — vaciarla acá dejaba que un helper sin argumentos escribiera estado público
    /// sin chequeo). Lo que sí arranca de cero es el frame de bucles del callee: sus `stop` no
    /// caen en un bucle nuestro.
    fn enter_call(&mut self) -> TaintFrame {
        TaintFrame {
            control: self.control_taint.clone(),
            loops: self.loop_taint.clone(),
            escaping: std::mem::replace(&mut self.escaping_taint, self.no_label.clone()),
            depth: std::mem::replace(&mut self.loop_depth, 0),
        }
    }

    /// Vuelta de una llamada, por el camino normal y por el de error. Se restaura la tinta del
    /// llamador —lo que pasó adentro no tiñe su continuación: el `give` llega a un join point y
    /// el valor ya viaja etiquetado— salvo lo que ESCAPA del cuerpo del callee (un `stop` sin
    /// bucle propio), que corta el bucle de acá y por eso se suma a nuestra tinta.
    fn leave_call(&mut self, saved: TaintFrame) {
        let escaped = std::mem::replace(&mut self.escaping_taint, saved.escaping);
        self.loop_depth = saved.depth;
        self.control_taint = saved.control;
        self.loop_taint = saved.loops;
        if !self.labels || escaped.is_empty() {
            return;
        }
        if self.loop_depth > 0 {
            self.loop_taint = labels::union(&self.loop_taint, &escaped);
        } else {
            self.control_taint = labels::union(&self.control_taint, &escaped);
            self.escaping_taint = labels::union(&self.escaping_taint, &escaped);
        }
    }

    /// Registro de los `declassify` ejecutados hasta ahora (en orden).
    pub fn declassify_log(&self) -> &[DeclassifyEntry] {
        &self.declassify_log
    }

    /// Vacía y devuelve el registro de `declassify` (para reportarlo por request/job).
    pub fn take_declassify_log(&mut self) -> Vec<DeclassifyEntry> {
        std::mem::take(&mut self.declassify_log)
    }

    /// Declara un builtin como CONSCIENTE de etiquetas: el despacho etiquetado le pasa los
    /// argumentos envueltos (sin strip ni re-envoltura del resultado) para que él mismo
    /// compruebe (`labels::check_flow`), redacte o marque. Es como el host registra sus
    /// sumideros y fuentes (I/O bajo `serve --attested`).
    pub fn register_label_aware(&mut self, name: &str) {
        self.label_aware.insert(name.to_string());
    }

    /// Marca `v` con la etiqueta de PC (identidad con etiquetas apagadas o PC vacío). Un
    /// `Secret` bajo PC es error (M2): elegir entre secrets por un privado lavaría la
    /// etiqueta (un secret no se etiqueta y `reveal` la perdería).
    ///
    /// Regla 2 : el PC **no asciende contenedores**. Envolver una lista/mapa con el
    /// PC fabricaba un envoltorio privado sobre el MISMO `Rc` — un alias que cubre el PC y por
    /// El que se escribe al objeto público original (caso 1.f), y que además inflaba la
    /// etiqueta del contenedor en el camino de `set` (caso 1.e). Los escalares de adentro ya
    /// llevan el PC (B5) y `label_deep` los ve, así que nada se pierde. Para un contenedor
    /// que SÍ tiene que quedar privado está `private(v, p)`, que copia.
    #[inline]
    fn pc_mark(&self, v: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
        if self.labels && !self.pc_is_empty() {
            if v.is_secret() {
                return Err(err_labels(
                    "a secret is already opaque; use private on the value you compute",
                    loc,
                ));
            }
            if !labels::is_container(&v) {
                return Ok(labels::mark(v, self.pc_label()));
            }
        }
        Ok(v)
    }

    /// Empuja `l` al stack de PC (acumulada con la de abajo). Sólo se llama con etiquetas
    /// encendidas y `l` no vacía. Siempre se aparea con `pc_pop`, también en error.
    fn pc_push(&mut self, l: &Label) {
        let joined = match self.pc.last() {
            Some(top) => labels::union(top, l),
            None => l.clone(),
        };
        self.note_seen(l);
        self.pc.push(joined);
    }

    fn pc_pop(&mut self) {
        self.pc.pop();
    }

    /// Anota que se desenvolvió un valor con etiqueta `l` (para el mensaje de error que
    /// atrape un `recover`, también cuando la operación falla antes de re-envolver).
    #[inline]
    fn note_seen(&mut self, l: &Label) {
        if !l.is_empty() {
            self.seen = labels::union(&self.seen, l);
            self.seen_any = true;
            self.touched = labels::union(&self.touched, l);
        }
    }

    /// La unión de todo lo privado que la corrida tocó hasta ahora (monótona). Con las
    /// etiquetas apagadas siempre está vacía.
    pub fn touched_label(&self) -> Label {
        self.touched.clone()
    }

    /// Re-envuelve el resultado de una operación cuyos operandos eran privados con la
    /// etiqueta `l` (unión si ya era privado). Un `Secret` no se etiqueta (ya es opaco y
    /// La etiqueta se perdería en `reveal`): error explícito.
    fn rewrap(&mut self, r: SynValue, l: Label, loc: &SourceLocation) -> Result<SynValue, Control> {
        if l.is_empty() {
            return Ok(r);
        }
        if r.is_secret() {
            return Err(err_labels(
                "a secret is already opaque; use private on the value you compute",
                loc,
            ));
        }
        self.note_seen(&l);
        Ok(labels::mark(r, l))
    }

    /// Bajo una etiqueta de PC no vacía una línea de salida se redacta entera
    /// (`private(A,B)`): que una rama privada imprima o no es un canal de terminación que
    /// No se cubre; su CONTENIDO sí.
    fn pc_redact(&self, s: String) -> String {
        if self.labels && !self.pc_is_empty() {
            return format!("private({})", self.safe_label(&self.pc_label()));
        }
        s
    }

    /// T5 (ronda 4) — el stdout del proceso es un SUMIDERO PÚBLICO, y `print`/`show`/`log` son
    /// sus tres bocas. Redactar el VALOR era la mitad del trabajo: la CANTIDAD de líneas no se
    /// redacta, así que una línea por vuelta de un bucle sobre datos privados se los deletrea a
    /// quien lea la salida — y bajo el guest de un enclave el log del Executor vive FUERA de él.
    /// Vale entonces la misma regla que el motor ya declara para todo builtin con efecto: la
    /// llamada bajo una rama que dependió de datos privados es `label_violation` ANTES de
    /// escribir. Lo que sigue funcionando igual es imprimir un valor privado con el PC público:
    /// sale `private(A,B)` por Display, como siempre.
    fn stdout_flow_check(&self, what: &str, loc: &SourceLocation) -> Result<(), Control> {
        if !self.labels || self.pc_is_empty() {
            return Ok(());
        }
        Err(err_labels(
            format!(
                "label_violation: {} under private control flow (pc = [{}]); stdout is public and the NUMBER of lines is not redacted, so one line per iteration spells the private data out. Move it out of the private branch, or declassify(<the condition>, \"<why it may be published>\")",
                what,
                self.safe_label(&self.pc_label())
            ),
            loc,
        ))
    }

    /// Fija los argumentos del programa (`args()`).
    pub fn set_program_args(&mut self, args: Vec<String>) {
        self.program_args = args;
    }

    /// v0.6.20 — raíz del proyecto para `use "../"` (el host la conoce: dir de la entrada).
    pub fn set_project_root(&mut self, root: std::path::PathBuf) {
        self.project_root = Some(root);
    }

    /// v0.6.20 — pasos ejecutados hasta ahora (nodos que pasaron por `exec`).
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Instala el gate de `stdout` (el motor lo cablea al CapabilitySet).
    pub fn set_stdout_hook(&mut self, hook: Rc<dyn Fn() -> Result<(), String>>) {
        self.stdout_hook = Some(hook);
        self.stdout_verdict = None;
    }

    /// Instala el gate de lectura de templates a disco (`render`/`include`/`layout`).
    pub fn set_template_read_hook(&mut self, hook: Rc<dyn Fn(&str) -> Result<(), RuntimeError>>) {
        self.template_read_hook = Some(hook);
    }

    /// Fija los nombres de env que Synsema trata como secretos (los quita de los hijos
    /// de `run()`/`proc_spawn`). Lo cablea el motor con las claves de proveedor + `.env`.
    pub fn set_sensitive_env(&mut self, names: HashSet<String>) {
        self.sensitive_env = names;
    }

    /// Los nombres de env sensibles (para que `run()`/`proc_spawn` los saquen del hijo).
    pub fn sensitive_env(&self) -> &HashSet<String> {
        &self.sensitive_env
    }

    /// Chequea `file.read` para un template LEÍDO DE DISCO (`raw_path` = como se escribió).
    /// Un template del bundle NO llama a esto (es parte del programa). Sin hook cableado
    /// (usos standalone/tests del core) es no-op — el motor siempre lo cablea.
    pub fn gate_template_read(&self, raw_path: &str) -> Result<(), Control> {
        if let Some(hook) = &self.template_read_hook {
            hook(raw_path).map_err(Control::Error)?;
        }
        Ok(())
    }

    /// Invoca un builtin anotando su ubicación para el audit (`--audit json` → `file`/
    /// `line`). Sin sink instalado no anota nada (un atómico por llamada).
    fn call_builtin_at(
        &mut self,
        f: &BuiltinFn,
        args: &[SynValue],
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        if !crate::audit_loc::enabled() {
            return f(self, args, loc);
        }
        let prev = crate::audit_loc::replace(Some(loc.clone()));
        let r = f(self, args, loc);
        crate::audit_loc::replace(prev);
        r
    }

    /// Despacho de un builtin: el camino directo de siempre, o el etiquetado  cuando
    /// las etiquetas están encendidas.
    fn dispatch_builtin(
        &mut self,
        bt: &Rc<BuiltinTask>,
        args: &[SynValue],
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let r = if self.labels {
            self.call_builtin_labelled(bt, args, loc)
        } else {
            let f = bt.func.clone();
            self.call_builtin_at(&f, args, loc)
        };
        // Linaje (DATOS-17): lo que entra al programa desde afuera queda anotado por el motor.
        if let Ok(v) = &r {
            if LINEAGE_SOURCES.contains(&bt.name.as_str()) {
                self.record_input(&bt.name, args, v);
            }
        }
        // El "missing argument" genérico de `nth` no decía de qué función ni cuántos
        // argumentos esperaba (v0.6.29, V1-E2): se completa acá, donde se sabe.
        match r {
            Err(Control::Error(mut e)) if e.message == "missing argument" => {
                let (min, _) = builtin_arity(bt);
                e.message = if min > args.len() {
                    format!(
                        "{}() needs {} argument{}, got {}",
                        bt.name,
                        min,
                        if min == 1 { "" } else { "s" },
                        args.len()
                    )
                } else {
                    format!("{}() is missing an argument (got {})", bt.name, args.len())
                };
                if e.location.is_none() {
                    e.location = Some(loc.clone());
                }
                Err(Control::Error(e))
            }
            other => other,
        }
    }

    /// Despacho etiquetado . Regla genérica: si algún argumento lleva etiquetas (a
    /// cualquier profundidad) o hay etiqueta de PC, el builtin recibe los argumentos SIN
    /// etiquetas (copia sólo de los contenedores con algo privado; los builtins no mutan sus
    /// argumentos, así que la copia no rompe aliasing), corre bajo esa etiqueta de PC (sus
    /// callbacks — apply/where/transform… — la heredan) y el resultado sale envuelto con la
    /// unión. Los builtins CONSCIENTES (`label_aware`) reciben todo tal cual y deciden ellos.
    fn call_builtin_labelled(
        &mut self,
        bt: &Rc<BuiltinTask>,
        args: &[SynValue],
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let f = bt.func.clone();
        // Sumideros (B7) primero, fail-closed: sin etiquetas en los argumentos y sin PC, o
        // `label_violation` antes de que el builtin corra.
        if self.label_sinks.contains(bt.name.as_str()) {
            let refs: Vec<&SynValue> = args.iter().collect();
            self.sink_check(&bt.name, &refs, loc)?;
            return self.call_builtin_at(&f, args, loc);
        }
        if self.label_aware.contains(bt.name.as_str()) {
            return self.call_builtin_at(&f, args, loc);
        }
        let mut arg_label = labels::empty();
        for a in args {
            arg_label = labels::union(&arg_label, &labels::label_deep(a));
        }
        let l = labels::union(&arg_label, &self.pc_label());
        // T5 (ronda 8) — **lo que el builtin VE por dentro también etiqueta su resultado.**
        //
        // Hasta acá la etiqueta del resultado se calculaba SÓLO con los argumentos y el PC, y un
        // callback que lee un privado por CAPTURA era invisible: el predicado decide en Rust, así
        // que el contexto privado del lenguaje nunca entra. La misma cuenta escrita a mano falla
        // cerrada y la idiomática publicaba el valor exacto:
        //
        //     let n be 0                                  let n be count_where(range(0,256),
        //     each v in range(0, 256)                         (v) => v < SECRET)
        //         when v < SECRET                         → n = 165, label_of(n) = []
        //             set n to n + 1
        //     → label_violation
        //
        // No es un canal lateral: es flujo EXPLÍCITO con etiqueta vacía, y alcanza a
        // `count_where`/`where`/`find_first`/`index_of`/`every`/`some`/`sort_by`/`group_by` y a
        // cualquiera que el host registre después.
        //
        // El arreglo es el mismo mecanismo que `exec` ya usa para `seen`, aplicado al borde con
        // Rust: se acota `seen` a ESTA llamada, se corre, y lo que el builtin desenvolvió se une
        // a la etiqueta del resultado. Estructural a propósito — parchear builtin por builtin
        // deja el próximo abierto.
        let outer_seen = std::mem::replace(&mut self.seen, self.no_label.clone());
        let r = if l.is_empty() {
            self.call_builtin_at(&f, args, loc)
        } else if arg_label.is_empty() {
            // Sólo PC: los argumentos ya están limpios.
            self.pc_push(&l);
            let r = self.call_builtin_at(&f, args, loc);
            self.pc_pop();
            r
        } else {
            let stripped: Vec<SynValue> = args.iter().map(labels::strip_deep).collect();
            self.pc_push(&l);
            let r = self.call_builtin_at(&f, &stripped, loc);
            self.pc_pop();
            r
        };
        // Lo que vio ESTA llamada, y la fusión con lo de afuera (igual que el scoping por nodo).
        let saw = std::mem::replace(&mut self.seen, self.no_label.clone());
        self.seen = labels::union(&outer_seen, &saw);
        let r = r?;
        let l = labels::union(&l, &saw);
        if l.is_empty() {
            return Ok(r);
        }
        if r.is_secret() {
            return Err(err_labels("a secret is already opaque; use private on the value you compute", loc));
        }
        self.note_seen(&l);
        // `mark_owned`: un builtin puede devolver un contenedor que COMPARTE `Rc` con un
        // argumento público (p. ej. `where` sobre una lista pública bajo PC devuelve los
        // mismos elementos). Envolverlo sin copiar fabricaría un alias privado escribible
        // sobre un objeto público — la misma clase que 1.f.
        Ok(labels::mark_owned(&r, l))
    }

    /// Primer `print`/`show`/`log`: consulta el gate una vez y memoiza el veredicto
    /// (un chequeo por intérprete; el audit lo ve una vez, no por línea).
    fn ensure_stdout(&mut self) -> Result<(), Control> {
        if self.stdout_verdict.is_none() {
            let verdict = match self.stdout_hook.clone() {
                Some(h) => h(),
                None => Ok(()),
            };
            self.stdout_verdict = Some(verdict);
        }
        match self.stdout_verdict.as_ref().unwrap() {
            Ok(()) => Ok(()),
            Err(m) => Err(Control::Error(RuntimeError::new(m.clone()))),
        }
    }

    fn register(&self, name: &str, param_count: i32, func: BuiltinFn) {
        self.global_env.borrow_mut().bindings.insert(
            name.to_string(),
            SynValue::Builtin(Rc::new(BuiltinTask {
                name: name.to_string(),
                func,
                param_count,
                param_names: None,
            })),
        );
    }

    /// Registra un builtin externo (lo usa el motor para los builtins seguros).
    pub fn register_builtin(&self, name: &str, param_count: i32, func: BuiltinFn) {
        self.register(name, param_count, func);
    }

    /// Registra un builtin externo CON nombres de parámetros (G-8): habilita args
    /// nombrados (`recall("x", from = "writer")`) mapeados a posicionales. Sólo
    /// los builtins registrados por esta vía los aceptan; el resto conserva el
    /// error de siempre.
    pub fn register_builtin_named(
        &self,
        name: &str,
        param_names: Vec<&'static str>,
        func: BuiltinFn,
    ) {
        self.global_env.borrow_mut().bindings.insert(
            name.to_string(),
            SynValue::Builtin(Rc::new(BuiltinTask {
                name: name.to_string(),
                func,
                param_count: param_names.len() as i32,
                param_names: Some(param_names),
            })),
        );
    }

    /// Las entradas que el programa leyó hasta ahora (DATOS-17), en orden.
    pub fn lineage(&self) -> &[LineageEntry] {
        &self.lineage
    }

    fn record_input(&mut self, source: &str, args: &[SynValue], result: &SynValue) {
        if self.lineage.len() >= MAX_LINEAGE {
            return;
        }
        // Un recv que venció sin mensaje no trajo nada.
        if matches!(result, SynValue::Nothing)
            && ["ws_", "proc_", "term_", "watch_"].iter().any(|p| source.starts_with(p))
        {
            return;
        }
        let canon = self.lineage_canonical.clone();
        // Qué bytes se hashean, y cómo recalcularlo (`encoding`): el texto (utf-8), los bytes
        // tal cual, o un valor estructurado como `canonical_json(x)` ("jcs"); si trae enteros
        // de más de 2^53 (que JCS no puede llevar), como `json_encode(x)` ("json").
        let enc_cell: std::cell::Cell<&'static str> = std::cell::Cell::new("text");
        let bytes_of = |v: &SynValue| -> Vec<u8> {
            match v {
                SynValue::Text(_) | SynValue::Nothing => {
                    enc_cell.set("text");
                    value_bytes(v)
                }
                SynValue::Bytes(_) => {
                    enc_cell.set("bytes");
                    value_bytes(v)
                }
                other => match canon.as_ref().and_then(|f| f(other)) {
                    Some((b, enc)) => {
                        enc_cell.set(enc);
                        b
                    }
                    None => {
                        enc_cell.set("display");
                        value_bytes(other)
                    }
                },
            }
        };
        // Compromiso con sal de la consulta (ver abajo): la sal y cómo se codificó la consulta.
        let mut salt: Option<(String, &'static str)> = None;
        // `what` se publica en el recibo firmado: sólo una ruta que el programa pasó como texto,
        // un host sin credenciales, un compromiso con sal o un tamaño — nunca datos. Un archivo
        // pasado como bytes (`parquet_read(b)`) es `bytes <n>`, no su contenido; `grep(target,
        // pattern)` publica el target, no el patrón (que puede ser el dato buscado).
        let path_what = |a: Option<&SynValue>| -> String {
            match a {
                Some(SynValue::Text(t)) => t.to_string(),
                Some(SynValue::Bytes(b)) => format!("bytes {}", b.len()),
                Some(other) => other.type_name().to_string(),
                None => String::new(),
            }
        };
        let (what, payload): (String, Vec<u8>) = match source {
            "read_file" | "read_file_bytes" | "list_dir" | "grep" | "parquet_read" | "file_info" => {
                (path_what(args.first()), bytes_of(result))
            }
            "read_line" => ("stdin".to_string(), bytes_of(result)),
            s if s.starts_with("http") || s == "fetch" => {
                // Una lectura que no llegó (sin conexión, DNS, TLS) no es una entrada: el mapa
                // trae `error` y ningún dato.
                if let SynValue::Map(m) = result {
                    if m.borrow().contains_key("error") {
                        return;
                    }
                }
                let mut host = url_host(url_of_connection(source, args));
                // Un 4xx/5xx sí trajo un cuerpo que el programa pudo usar: queda, con su estado.
                if let SynValue::Map(m) = result {
                    if let Some(SynValue::Number(Number::Int(st))) = m.borrow().get("status") {
                        if !(200..300).contains(st) {
                            host.push_str(&format!(" status {}", st));
                        }
                    }
                }
                let body = match result {
                    SynValue::Map(m) => m.borrow().get("body").map(|b| bytes_of(b)).unwrap_or_else(|| bytes_of(result)),
                    other => bytes_of(other),
                };
                (host, body)
            }
            _ => {
                // Consultas (bases de datos, nodos de una cadena, sockets, procesos): el hash de
                // la llamada ENTERA (todos sus argumentos, filtros de Mongo incluidos; puede
                // llevar datos o la clave de un RPC, por eso no va en claro) y el del resultado.
                // Si la fuente tiene una conexión (el nodo de una cadena), su host va adelante,
                // sin credenciales; la clave de redis/mongo/memoria nunca (`url_of_connection`).
                // Un COMPROMISO CON SAL, como SD-JWT: sha256(sal ‖ consulta) con 128 bits de sal
                // nueva por entrada. El recibo publica sólo el compromiso (un sha256 a secas de
                // `run("id", "-u")` se revertía probando un diccionario de consultas); la sal
                // queda en `lineage()`, así el dueño puede probar después qué consulta fue.
                let q = bytes_of(&SynValue::List(Rc::new(RefCell::new(args.to_vec()))));
                let q_enc = enc_cell.get();
                let (sal, commit) = salted_commitment(&q);
                salt = Some((sal, q_enc));
                let host = url_host(url_of_connection(source, args));
                let what = if host.is_empty() {
                    format!("query sha256-salted:{}", commit)
                } else {
                    format!("{} query sha256-salted:{}", host, commit)
                };
                (what, bytes_of(result))
            }
        };
        let encoding = enc_cell.get().to_string();
        self.lineage.push(LineageEntry {
            source: source.to_string(),
            what,
            sha256: sha256_hex(&payload),
            bytes: payload.len(),
            encoding,
            salt,
        });
    }

    /// Linaje de una respuesta de modelo (`reason`, `decide`, `analyze`, `generate`): lo que
    /// dijo el modelo también es una entrada del programa. Va el hash del prompt, no el prompt.
    fn record_llm(&mut self, kind: &str, prompt: &str, out: &str) {
        if self.lineage.len() >= MAX_LINEAGE {
            return;
        }
        let (sal, commit) = salted_commitment(prompt.as_bytes());
        self.lineage.push(LineageEntry {
            source: "llm".to_string(),
            what: format!("{} prompt sha256-salted:{}", kind, commit),
            sha256: sha256_hex(out.as_bytes()),
            bytes: out.len(),
            encoding: "text".to_string(),
            salt: Some((sal, "text")),
        });
    }

    /// Lee (y consume) un argumento sólo-por-nombre de la llamada a builtin en curso.
    pub fn kwarg(&mut self, name: &str) -> Option<SynValue> {
        self.pending_kwargs.shift_remove(name)
    }

    /// Liga cada nombre deprecado (`deprecated::DEPRECATED_NAMES`) al builtin de su nombre
    /// nuevo, salvo que el viejo ya esté registrado por su cuenta (porque conserva su forma
    /// vieja, como `capture`, o porque el nombre se reusó, como `solana_tx`).
    pub fn register_deprecated_aliases(&self) {
        let mut g = self.global_env.borrow_mut();
        for (old, new) in crate::deprecated::DEPRECATED_NAMES {
            if g.bindings.contains_key(*old) {
                continue;
            }
            if let Some(v @ SynValue::Builtin(_)) = g.bindings.get(*new).cloned() {
                g.bindings.insert(old.to_string(), v);
            }
        }
    }

    /// Cablea el hook de concesión de capabilities (lo llama `require`).
    pub fn set_grant_hook(&mut self, hook: GrantHook) {
        self.grant_hook = Some(hook);
    }

    /// Cablea el hook de aislamiento de `sandbox` (lo instala el motor con el caps).
    pub fn set_sandbox_hook(&mut self, hook: SandboxHook) {
        self.sandbox_hook = Some(hook);
    }

    /// Cablea el hook de `sandbox under <caps>` (techo delegado por bloque).
    pub fn set_ceiling_hook(&mut self, hook: CeilingHook) {
        self.ceiling_hook = Some(hook);
    }

    /// Cablea el hook de aislamiento por-tool (least-privilege en `call_tool`).
    pub fn set_tool_scope_hook(&mut self, hook: ToolScopeHook) {
        self.tool_scope_hook = Some(hook);
    }

    /// ¿Estamos dentro de un bloque `sandbox`? (capabilities denegadas).
    pub fn in_sandbox(&self) -> bool {
        self.sandbox_depth > 0
    }

    /// ¿Estamos ejecutando el cuerpo de una tool bajo `call_tool` (least-privilege)? Un
    /// `require` anidado ahí es no-op (no puede auto-concederse caps para escapar).
    pub fn in_tool_scope(&self) -> bool {
        self.tool_scope_depth > 0
    }

    /// Congela el intent: re-declararlo después es error (anti prompt-injection).
    pub fn freeze_intent(&mut self) {
        self.intent_frozen = true;
    }

    /// Cablea los hooks del swarm (lo usa el motor para agentes en hilos).
    pub fn set_swarm_hooks(&mut self, hooks: SwarmHooks) {
        self.swarm_hooks = Some(hooks);
    }

    /// Cablea el callback humano (approve/confirm/ask). El tercer parámetro es el
    /// `within` del gate en segundos (None = sin `within`).
    pub fn set_human_callback(&mut self, cb: HumanCallback) {
        self.human_callback = Some(cb);
    }

    /// Cablea el callback LLM (reason/decide/analyze/generate). La firma es
    /// `(op, prompt) -> contenido`: el motor le pasa el prompt renderizado de la op.
    pub fn set_llm_callback(&mut self, cb: LlmTextCallback) {
        self.llm_callback = Some(cb);
    }

    /// Cablea el callback dedicado de `decide` (DE-039). La firma es
    /// `(prompt, opciones) -> contenido`: el prompt renderizado + las opciones
    /// estructuradas del `between [...]`.
    pub fn set_llm_decide_callback(&mut self, cb: LlmDecideCallback) {
        self.llm_decide_callback = Some(cb);
    }

    /// Cablea el callback LLM tool-aware de paso (`llm_step`, FASE 1).
    pub fn set_llm_step_callback(&mut self, cb: LlmStepCallback) {
        self.llm_step_callback = Some(cb);
    }

    /// Cablea el callback LLM de streaming (`llm_stream`, F2).
    pub fn set_llm_stream_callback(&mut self, cb: LlmStreamCallback) {
        self.llm_stream_callback = Some(cb);
    }

    /// Cablea el callback de `llm_usage()` (tokens LLM acumulados del proceso,
    /// FRAMEWORK F1). Sin él, el builtin devuelve 0.
    pub fn set_llm_usage_callback(&mut self, cb: Rc<dyn Fn() -> u64>) {
        self.llm_usage_callback = Some(cb);
    }

    /// Cablea el gate de capability para las ops LLM (exige `require llm`). El hook
    /// devuelve el `RuntimeError` ya armado (con sus flags: `denied_by_token`…), no un texto:
    /// el status HTTP de una denegación jamás se decide por el mensaje.
    pub fn set_llm_cap_hook(&mut self, hook: Rc<dyn Fn() -> Result<(), RuntimeError>>) {
        self.llm_cap_hook = Some(hook);
    }

    /// Cablea el provider de `judge` (real o mock). Ver [`JudgeCallback`].
    pub fn set_judge_callback(&mut self, cb: JudgeCallback) {
        self.judge_callback = Some(cb);
    }

    pub fn set_judge_usage_callback(&mut self, cb: Rc<dyn Fn() -> u64>) {
        self.judge_usage_callback = Some(cb);
    }

    pub fn set_judge_model_callback(&mut self, cb: Rc<dyn Fn() -> Option<String>>) {
        self.judge_model_callback = Some(cb);
    }

    /// Gate de la capability `judge`: `Err(msg)` → el bloque falla con `Capability not
    /// granted: judge`. Propia, no la concede `require llm`.
    pub fn set_judge_cap_hook(&mut self, hook: Rc<dyn Fn() -> Result<(), RuntimeError>>) {
        self.judge_cap_hook = Some(hook);
    }

    fn check_judge_cap(&self) -> Result<(), Control> {
        if let Some(hook) = &self.judge_cap_hook {
            hook().map_err(Control::Error)?;
        }
        Ok(())
    }

    /// `SYNSEMA_JUDGE_DECIDE`: servir `decide` con el juez. Lo activa el motor sólo con un
    /// provider de judge cableado.
    pub fn set_decide_via_judge(&mut self, on: bool) {
        self.decide_via_judge = on;
    }

    /// `decide between […] given X` como una pregunta `choose` al juez. `Ok(None)` = no aplica
    /// o no disponible (el llamador sigue por el camino LLM); `Ok(Some(t))` = la opción elegida,
    /// una de las del programa byte a byte.
    fn decide_with_judge(
        &self,
        opts: &SynValue,
        giv: &SynValue,
        loc: &SourceLocation,
    ) -> Result<Option<SynValue>, Control> {
        use crate::judge::{syn_to_json, JudgeAnswer, JudgeKind, JudgeOption, JudgeQuestion, JudgeRequest, MAX_OPTIONS};
        let Some(cb) = self.judge_callback.clone() else { return Ok(None) };
        let SynValue::List(l) = opts else { return Ok(None) };
        let ids: Vec<String> = l.borrow().iter().map(|v| v.to_string()).collect();
        if ids.len() < 2 || ids.len() > MAX_OPTIONS {
            return Ok(None);
        }
        if let Some(hook) = &self.judge_cap_hook {
            if let Err(m) = hook() {
                return Err(err_at(
                    format!(
                        "{} — this `decide` is served by the judge because SYNSEMA_JUDGE_DECIDE is set; add `require judge` (or unset the knob)",
                        m
                    ),
                    loc,
                ));
            }
        }
        let q = JudgeQuestion {
            id: "decision".to_string(),
            kind: JudgeKind::Choose,
            instruction: serde_json::json!("Which of the options applies to the state?"),
            options: ids.iter().map(|id| JudgeOption { id: id.clone(), description: None }).collect(),
            escape: false,
            yes_no: None,
        };
        let req = JudgeRequest { state: syn_to_json(giv), questions: vec![q] };
        match cb(&req) {
            Ok(Some(resp)) => match resp.answers.first() {
                Some(JudgeAnswer::Choose { choice: Some(c), .. }) => Ok(Some(syn_text(c.as_str()))),
                _ => Ok(None),
            },
            Ok(None) => Ok(None),
            Err(m) => Err(err_at(m, loc)),
        }
    }

    /// Chequea la capability `llm` (si hay gate). Se llama al inicio de cada op LLM,
    /// con o sin provider real. Sin gate cableado: no-op (no rompe `Interpreter::new`).
    fn check_llm_cap(&self) -> Result<(), Control> {
        if let Some(hook) = &self.llm_cap_hook {
            hook().map_err(Control::Error)?;
        }
        Ok(())
    }

    /// Cablea el hook de `serve on PORT` (lo usa el motor en el camino de serve).
    pub fn set_serve_hook(&mut self, hook: ServeHook) {
        self.serve_hook = Some(hook);
    }

    /// Cablea el sink de `send` (por request de streaming SSE).
    pub fn set_stream_emit(&mut self, emit: StreamEmitFn) {
        self.stream_emit = Some(emit);
    }

    /// Token de cancelación cooperativa de ESTE intérprete (clonable, cruza hilos).
    /// Quien lo setea (server/swarm) usa `CancelToken::cancel(reason)`.
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Adopta un token externo (el server crea uno por request ANTES de correr el
    /// handler, para poder cancelarlo desde el lado async aunque el head no salió).
    pub fn set_cancel_token(&mut self, token: CancelToken) {
        self.cancel = token;
    }

    /// ¿Hay una cancelación pendiente? (para loops de espera en builtins).
    pub fn is_cancelled(&self) -> bool {
        self.cancel.flag.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// El flag crudo (para pasarlo a esperas que no tienen el intérprete a mano).
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.flag.clone()
    }

    /// Corta con error si hay cancelación pendiente. Lo llaman `exec_block` (por
    /// statement) y los builtins bloqueantes al salir de su espera.
    pub fn check_cancel(&self) -> Result<(), Control> {
        if self.cancel.flag.load(std::sync::atomic::Ordering::Relaxed) {
            let reason = self.cancel.reason.lock().map(|g| g.clone()).unwrap_or_default();
            let msg = if reason.is_empty() {
                "cancelled".to_string()
            } else {
                format!("cancelled: {}", reason)
            };
            return Err(Control::Error(RuntimeError::new(msg)));
        }
        Ok(())
    }

    /// Llama a un valor invocable (task/builtin) con argumentos. Para el motor
    /// (p.ej. el verificador de auth de `serve`). Un `give` interno → valor de retorno.
    pub fn call_task(&mut self, func: SynValue, args: Vec<SynValue>) -> Result<SynValue, Control> {
        for a in &args {
            self.harvest_principals(a);
        }
        let loc = SourceLocation { file: "<engine>".to_string(), line: 0, column: 0, offset: 0 };
        let r = self.call_value(func, args, &loc);
        // T5 (M1): es un punto de salida hacia el host.
        self.redact_for_host(r)
    }

    /// Intent declarado (para enriquecer /llms.txt). Texto descriptivo, no gatea nada.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Bindea una variable en el entorno global (para los spawn_args de un agente).
    pub fn set_global(&self, name: &str, value: SynValue) {
        self.harvest_principals(&value);
        env_set(&self.global_env, name, value);
    }

    /// Nombre del agente en ejecución (namespaces de memoria, DB-M1). `None` =
    /// top-level (`source = "main"`).
    pub fn current_agent(&self) -> Option<&str> {
        self.agent_context.last().map(|s| s.as_str())
    }

    /// Fija el contexto de agente de este intérprete (camino swarm: el intérprete
    /// del hilo del agente ES el agente, de punta a punta).
    pub fn set_agent_context(&mut self, name: &str) {
        self.agent_context.push(name.to_string());
    }

    /// La identidad del sujeto autenticado de esta unidad de trabajo , si la
    /// hay. Precede a `current_agent()` para contabilidad: el gasto se le imputa a
    /// QUIÉN pidió, no a qué agente ejecutó.
    pub fn request_identity(&self) -> Option<&str> {
        self.request_identity.as_deref()
    }

    /// El techo de gasto delegado a la identidad en curso (unidad → monto decimal
    /// en texto). Vacío = sin techo delegado (sólo rige el del host).
    pub fn request_spend_limits(&self) -> &[(String, String)] {
        &self.request_spend_limits
    }

    /// Fija identidad + techos delegados para la unidad de trabajo en curso. Lo
    /// llama el runtime de serve por request (desde `request.user`); se limpia en
    /// `reset_for_request` para que NUNCA se filtre al request siguiente del
    /// mismo worker.
    pub fn set_request_identity(&mut self, id: Option<String>, spend_limits: Vec<(String, String)>) {
        self.request_identity = id;
        self.request_spend_limits = spend_limits;
    }

    /// Ejecuta un bloque de statements en el entorno global (cuerpo de un agente).
    /// Sin preámbulo/freeze (eso es sólo para el programa top-level).
    pub fn run_block(&mut self, stmts: &[Node]) -> Result<SynValue, Control> {
        let g = self.global_env.clone();
        let saved = self.take_taint();
        let r = self.exec_block(stmts, &g);
        self.restore_taint(saved);
        self.redact_for_host(r)
    }

    /// Corre el cuerpo de una ruta del serve en un scope HIJO del entorno global,
    /// con las bindings de request (`request`/`query`/`params`/`read_body`) locales
    /// a ese scope. Esto habilita reusar el mismo intérprete (builtins + globales +
    /// tasks, caro de construir) entre requests: lo que define el handler queda en el
    /// hijo y se descarta al terminar → NO se filtra al siguiente request. Los
    /// globales (inmutables por convención) se comparten vía el padre. El reset del
    /// estado transitorio entre requests lo hace `reset_for_request`.
    pub fn run_request_block(
        &mut self,
        stmts: &[Node],
        bindings: Vec<(String, SynValue)>,
    ) -> Result<SynValue, Control> {
        let genv = self.global_env.clone();
        self.run_request_block_in(stmts, bindings, &genv)
    }

    /// Como `run_request_block`, pero el scope del request cuelga de `parent` en vez
    /// del global — el caso de una ruta montada desde un módulo (`mount`): su cuerpo
    /// resuelve los helpers PRIVADOS del módulo por nombre simple, igual que una task
    /// exportada (DE-027).
    pub fn run_request_block_in(
        &mut self,
        stmts: &[Node],
        bindings: Vec<(String, SynValue)>,
        parent: &Rc<RefCell<Environment>>,
    ) -> Result<SynValue, Control> {
        let env = Environment::child(parent, "request");
        {
            for (_, v) in &bindings {
                self.harvest_principals(v);
            }
            let mut e = env.borrow_mut();
            for (k, v) in bindings {
                e.bindings.insert(k, v);
            }
        }
        let saved_taint = self.take_taint();
        let result = self.exec_block(stmts, &env);
        self.restore_taint(saved_taint);
        // Rompe cualquier ciclo Rc creado en el scope del request: si el handler hace
        // `define task` dentro del body, la task cierra sobre `env` (`closure_env`) y el
        // env la contiene en `bindings` → `env ⇄ task`, que Rc no libera (igual razón que
        // el `Drop` del intérprete para el global, fix de OOM #7). Como el intérprete se
        // REUSA entre requests, este `env` no se dropea vía ese `Drop`; vaciarlo acá corta
        // el ciclo → el env del request (bindings + lo que definió el handler) se libera.
        // El give-value (en `result`) es un valor owned, no referencia al env.
        env.borrow_mut().bindings.clear();
        // T5 (M1): el error de un handler sale redactado hacia el host si tocó privados.
        self.redact_for_host(result)
    }

    /// Limpia el estado transitorio entre requests del serve (cuando un worker reusa
    /// el mismo intérprete). Deja `global_env` (builtins + globales + tasks) intacto
    /// pero resetea lo per-request: salida acumulada, blackboard local, definiciones
    /// de agente, sink de stream y profundidad de recursión. Las capabilities se
    /// resetean afuera (las posee el motor, vía el `Rc<RefCell<CapabilitySet>>` que
    /// capturan los builtins). Sin esto, el estado de un request se filtraría al
    /// siguiente.
    pub fn reset_for_request(&mut self) {
        // Token NUEVO por request: el job anterior (si sigue corriendo en otro hilo,
        // p. ej. cancelado por timeout) conserva el suyo; éste arranca limpio.
        self.cancel = CancelToken::new();
        self.output.clear();
        self.blackboard.clear();
        self.agent_definitions.clear();
        self.agent_context.clear();
        // La identidad del sujeto es POR REQUEST: si sobreviviera al reset, el
        // próximo request de este worker gastaría contra la identidad anterior.
        self.request_identity = None;
        self.request_spend_limits.clear();
        self.stream_emit = None;
        self.recursion_depth = 0;
        // T5 (ronda 6, B3) — el contador de pasos es POR REQUEST. El serve reusa el intérprete
        // entre requests, así que sin esto el contador acumulaba el trabajo del request
        // ANTERIOR — incluido el privado — y el siguiente lo leía con `touched` ya limpio, o
        // sea público. Medido con dos secretos: las magnitudes difieren por un factor de quince,
        // y vive justo en el despliegue atestado que motivó la tanda. Además es lo correcto
        // aparte de las etiquetas: cada request es su propia unidad de trabajo, y el costo que
        // `steps()` mide es el suyo, no el del vecino que le tocó el mismo worker.
        self.steps = 0;
        // El gate de stdout se re-consulta por request (el set de capabilities se
        // reconstruye afuera; el veredicto memoizado sería del request anterior).
        self.stdout_verdict = None;
        // El contexto de PC es por request (un handler cortado por timeout dentro de
        // Un `when` privado no debe etiquetar al siguiente). El registro de declassify lo
        // drena el host (`take_declassify_log`).
        if self.labels {
            self.pc.clear();
            self.seen = labels::empty();
            self.seen_any = false;
            self.touched = labels::empty();
            self.control_taint = labels::empty();
            self.loop_taint = labels::empty();
            self.escaping_taint = labels::empty();
            self.loop_depth = 0;
        }
    }

    /// Evalúa un nodo en un entorno dado (templates + motor de serve).
    pub fn eval(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        self.exec(node, env)
    }

    /// Carga un módulo local: resuelve → lee → parsea → corre el body en un env
    /// HIJO del global → cosecha los exports en un map → lo devuelve. Cacheado por
    /// path resuelto; un import circular es error. No agrega tipo de runtime nuevo:
    /// el módulo es un `SynValue::Map`.
    fn load_module(&mut self, raw_path: &str, importer_file: &str) -> Result<SynValue, Control> {
        let base_dir = Path::new(importer_file).parent().unwrap_or_else(|| Path::new("."));
        // v0.6.20 — la raíz del proyecto acota `../`: la fijó el host o se captura acá, en el
        // primer `use` (siempre el top-level de la entrada; los `use` de un módulo corren
        // DENTRO de ese primero). `<stdin>`/`<test>` sin dir → sin raíz → criterio v0.6.19.
        if self.project_root.is_none() && !importer_file.starts_with('<') {
            let root = if base_dir.as_os_str().is_empty() { Path::new(".") } else { base_dir };
            self.project_root = Some(root.to_path_buf());
        }
        let resolved = resolve_module_path(raw_path, base_dir, self.project_root.as_deref()).map_err(err)?;

        if self.loading_modules.contains(&resolved) {
            return Err(err(format!(
                "circular import: module '{}' is already being loaded",
                raw_path
            )));
        }
        if let Some(cached) = self.module_cache.get(&resolved) {
            return Ok(cached.clone());
        }

        self.loading_modules.insert(resolved.clone());
        let res = self.load_module_inner(raw_path, &resolved);
        self.loading_modules.remove(&resolved);
        let module_map = res?;
        self.module_cache.insert(resolved, module_map.clone());
        Ok(module_map)
    }

    fn load_module_inner(&mut self, raw_path: &str, resolved: &str) -> Result<SynValue, Control> {
        // Overlay del bundle (`synsema build`): el módulo puede vivir dentro del
        // ejecutable; si no está ahí, el disco como siempre.
        let source = match crate::bundle::get(resolved) {
            Some(bytes) => String::from_utf8(bytes.to_vec())
                .map_err(|_| err(format!("module is not UTF-8: {}", raw_path)))?,
            None => std::fs::read_to_string(resolved)
                .map_err(|_| err(format!("module not found: {}", raw_path)))?,
        };
        // Un error de compilación del módulo se reporta como runtime (la operación
        // de import falló), igual que en el oráculo Python.
        let program = parse_source(&source, resolved).map_err(|e| err(e.to_string()))?;
        // T5 (B8): un módulo tampoco puede redefinir los nombres protegidos.
        check_protected_names(&program)?;
        // T5 (ronda 7): el conjunto con el que se redacta sale del AST, antes de correr nada.
        self.set_declared_principals(&program);

        // Pre-escaneo antes de cualquier efecto: un módulo no puede arrancar un
        // servidor ni ensanchar capabilities globales (el `require` POR TASK sí va).
        for stmt in &program.statements {
            match &stmt.kind {
                NodeKind::ServeBlock { .. } => {
                    return Err(err(format!(
                        "module '{}' must not contain a 'serve' block",
                        raw_path
                    )))
                }
                NodeKind::RequireStatement { .. } => {
                    return Err(err(format!(
                        "module '{}' must not have a top-level 'require'",
                        raw_path
                    )))
                }
                _ => {}
            }
        }

        let module_env = Environment::child(&self.global_env, &format!("module:{}", resolved));
        self.exports_collector.push(Vec::new());
        let exec_res = self.exec_block(&program.statements, &module_env);
        let names = self.exports_collector.pop().unwrap_or_default();
        exec_res?;

        let mut exports = IndexMap::new();
        for name in names {
            if let Some(v) = env_get(&module_env, &name) {
                exports.insert(name, v);
            }
        }
        let map = Rc::new(RefCell::new(exports));
        register_module(&map, &module_env);
        Ok(SynValue::Map(map))
    }

    fn register_builtins(&self) {
        // Núcleo
        self.register("print", -1, Rc::new(|i, a, l| i.b_print(a, l)));
        // args(): los argumentos del programa (`synsema run prog.syn -- a b`, o el argv
        // de un binario `synsema build`). Sin capability: es input escrito por quien
        // invocó ESTE programa, no un recurso del host.
        self.register(
            "args",
            0,
            Rc::new(|i, _a, _l| Ok(syn_list(i.program_args.iter().map(|s| syn_text(s.as_str())).collect()))),
        );
        // self_path(): la ruta del ejecutable en curso, EXACTAMENTE como la devuelve el
        // SO (es lo que hay que pasarle a `run`/`proc_spawn` — el scope de `exec` se
        // compara byte a byte). Sin capability: identidad, no acceso.
        self.register(
            "self_path",
            0,
            Rc::new(|_i, _a, _l| match std::env::current_exe() {
                Ok(p) => Ok(syn_text(p.to_string_lossy().into_owned())),
                Err(e) => Err(Control::Error(RuntimeError::new(format!(
                    "self_path: not available in the pure profile — this run has no process ({})",
                    e
                )))),
            }),
        );
        self.register("length", 1, Rc::new(|i, a, l| i.b_length(a, l)));
        self.register("text", 1, Rc::new(|i, a, l| i.b_to_text(a, l)));
        self.register("number", -1, Rc::new(|i, a, l| i.b_to_number(a, l)));
        // Tipo Decimal (dinero exacto): constructor + conversión a float + introspección.
        self.register("decimal", -1, with_fallback(1, Rc::new(|i, a, l| i.b_decimal(a, l))));
        self.register("float", -1, with_fallback(1, Rc::new(|i, a, l| i.b_float(a, l))));
        self.register("is_decimal", 1, Rc::new(|i, a, l| i.b_is_decimal(a, l)));
        // v0.6.29: entero exacto (forma total como `number`), `0x…` y predicados de tipo.
        // `int(x, fallback)` es la forma total (como `number`); la BASE va con nombre:
        // `int("ff", base = 16)`. `int("ff", 16)` (la forma de Python) es error y lo dice, en
        // vez de devolver 16 en silencio.
        self.register("int", -1, Rc::new(|i, a, l| {
            let base = i.kwarg("base");
            // `int(text, fallback = 10)`: la forma total con el fallback por nombre (sirve
            // también cuando el fallback es un número que parece una base).
            let named_fb = i.kwarg("fallback");
            let mut owned: Vec<SynValue>;
            let a: &[SynValue] = match named_fb {
                Some(fb) => {
                    if a.len() > 1 {
                        return Err(err("int(x, fallback = f): pass the fallback once (by name or second)"));
                    }
                    owned = a.to_vec();
                    owned.push(fb);
                    if base.is_none() {
                        return with_fallback(1, Rc::new(|i: &mut Interpreter, a: &[SynValue], l: &SourceLocation| i.b_int(a, l)))(i, &owned, l);
                    }
                    &owned
                }
                None => a,
            };
            if base.is_none() {
                // Sea cual sea `x` (texto, `nothing`, un número): que el resultado no dependa del dato.
                if let (Some(_), Some(SynValue::Number(Number::Int(b)))) = (a.first(), a.get(1)) {
                    if (2..=36).contains(b) {
                        return Err(err(format!(
                            "int(x, {b}): the second argument is the fallback value, not the base — for base {b} write int(x, base = {b}); for a fallback of {b}, name it: int(x, fallback = {b})"
                        )));
                    }
                }
                return with_fallback(1, Rc::new(|i: &mut Interpreter, a: &[SynValue], l: &SourceLocation| i.b_int(a, l)))(i, a, l);
            }
            let radix = match &base {
                Some(SynValue::Number(Number::Int(b))) if (2..=36).contains(b) => *b as u32,
                other => return Err(err(format!("int(text, base = b): b must be an integer from 2 to 36, got {}", other.as_ref().map(|v| v.to_string()).unwrap_or_default()))),
            };
            let parse = |v: &SynValue| -> Result<SynValue, Control> {
                let SynValue::Text(t) = v else {
                    return Err(err(format!("int(x, base = {}): x must be text, got {}", radix, v.type_name())));
                };
                parse_int_radix(t, radix).map(|n| syn_number(n.normalized())).ok_or_else(|| {
                    err(format!(
                        "Cannot convert {:?} to an integer in base {}. To validate untrusted input without raising: int(x, nothing, base = {})",
                        t.as_ref(), radix, radix
                    ))
                })
            };
            match (a.first(), a.get(1)) {
                (Some(x), None) => parse(x),
                (Some(x), Some(fallback)) => Ok(parse(x).unwrap_or_else(|_| fallback.clone())),
                _ => Err(err("int(x, fallback?, base = b)")),
            }
        }));
        self.register("hex", 1, Rc::new(|i, a, l| i.b_hex(a, l)));
        self.register("is_integer", 1, Rc::new(|_i, a, _l| {
            Ok(syn_bool(matches!(nth(a, 0)?, SynValue::Number(Number::Int(_) | Number::Big(_)))))
        }));
        self.register("is_text", 1, Rc::new(|_i, a, _l| Ok(syn_bool(matches!(nth(a, 0)?, SynValue::Text(_))))));
        self.register("is_list", 1, Rc::new(|_i, a, _l| Ok(syn_bool(matches!(nth(a, 0)?, SynValue::List(_))))));
        self.register("is_map", 1, Rc::new(|_i, a, _l| Ok(syn_bool(nth(a, 0)?.type_name() == "map"))));
        // Tipo bytes (binario): constructor/conversión + introspección. PUROS (sin
        // capability, como text/number/decimal). El hex/base64 es hand-rolled (bytesutil).
        self.register("bytes", -1, Rc::new(|i, a, l| i.b_bytes(a, l)));
        self.register("decode", -1, Rc::new(|i, a, l| i.b_decode(a, l)));
        self.register("is_bytes", 1, Rc::new(|i, a, l| i.b_is_bytes(a, l)));
        self.register("bytes_to_int", 1, Rc::new(|i, a, l| i.b_bytes_to_int(a, l)));
        self.register("int_to_bytes", -1, Rc::new(|i, a, l| i.b_int_to_bytes(a, l)));
        self.register("int_to_bytes_le", 2, Rc::new(|i, a, l| i.b_int_to_bytes_le(a, l)));
        // Aserciones (test framework, Batch 3). PUROS; al fallar producen un error
        // marcado `is_assertion`. Funcionan en cualquier parte (checks defensivos, G3).
        self.register("assert", -1, Rc::new(|i, a, l| i.b_assert(a, l)));
        self.register("assert_eq", -1, Rc::new(|i, a, l| i.b_assert_eq(a, l)));
        self.register("assert_ne", -1, Rc::new(|i, a, l| i.b_assert_ne(a, l)));
        self.register("assert_error", 1, Rc::new(|i, a, l| i.b_assert_error(a, l)));
        // raise(msg) — re-propaga un error (siempre devuelve Control::Error). Habilita
        // re-lanzar un error capturado en `recover` (`raise(err)`). PURO (Batch 6).
        self.register("raise", -1, Rc::new(|i, a, l| i.b_raise(a, l)));
        // Redondeo a entero (PUROS — sin capability, como text/number). ties-to-even en
        // round() para igualar el `round` de Python.
        self.register("floor", 1, Rc::new(|i, a, l| i.b_round_op(a, l, "floor", f64::floor)));
        self.register("ceil", 1, Rc::new(|i, a, l| i.b_round_op(a, l, "ceil", f64::ceil)));
        self.register("round", 1, Rc::new(|i, a, l| i.b_round_op(a, l, "round", f64::round_ties_even)));
        self.register("trunc", 1, Rc::new(|i, a, l| i.b_round_op(a, l, "trunc", f64::trunc)));
        self.register("append", 2, Rc::new(|i, a, l| i.b_append(a, l)));
        self.register("insert", 3, Rc::new(|i, a, l| i.b_insert(a, l)));
        self.register("keys", 1, Rc::new(|i, a, l| i.b_keys(a, l)));
        // v0.6.29 (V1-C1): mapas. `get` es la forma total del índice (lista o mapa);
        // `remove`/`merge` devuelven un mapa nuevo; `items` → [{key, value}].
        self.register("get", -1, Rc::new(|i, a, l| i.b_get(a, l)));
        self.register("remove", 2, Rc::new(|i, a, l| i.b_remove(a, l)));
        self.register("merge", -1, Rc::new(|i, a, l| i.b_merge(a, l)));
        self.register("items", 1, Rc::new(|i, a, l| i.b_items(a, l)));
        self.register("values", 1, Rc::new(|i, a, l| i.b_values(a, l)));
        // enumerate(list) → [{index, item}, …] — índice en loops (each e in enumerate(xs)),
        // en el lenguaje Y en templates. PURO, sin capability.
        self.register("enumerate", 1, Rc::new(|i, a, l| i.b_enumerate(a, l)));
        self.register("contains", 2, Rc::new(|i, a, l| i.b_contains(a, l)));
        self.register("split", 2, Rc::new(|i, a, l| i.b_split(a, l)));
        // `join(items, sep)` une texto; `join(left, right, on, how?)` une TABLAS (v0.6.29,
        // DATOS-14): la forma de la llamada decide, como `join` en polars.
        self.register("join", -1, Rc::new(|i, a, l| {
            if a.len() >= 3 {
                crate::tabular::join(a)
            } else {
                i.b_join(a, l)
            }
        }));
        self.register("range", -1, Rc::new(|i, a, l| i.b_range(a, l)));
        self.register("type_of", 1, Rc::new(|i, a, l| i.b_type_of(a, l)));
        self.register("slice", -1, Rc::new(|i, a, l| i.b_slice(a, l)));
        self.register("fmt", 1, Rc::new(|i, a, l| i.b_fmt(a, l)));
        self.register("upper", 1, Rc::new(|i, a, l| i.b_upper(a, l)));
        self.register("lower", 1, Rc::new(|i, a, l| i.b_lower(a, l)));
        // fold: minúsculas + sin diacríticos (matching tolerante a acentos).
        self.register("fold_text", 1, Rc::new(|i, a, l| i.b_fold(a, l)));
        self.register("fold", 1, Rc::new(|i, a, l| i.b_fold(a, l))); // deprecado → fold_text
        self.register("trim", 1, Rc::new(|i, a, l| i.b_trim(a, l)));
        self.register("starts_with", 2, Rc::new(|i, a, l| i.b_starts_with(a, l)));
        self.register("ends_with", 2, Rc::new(|i, a, l| i.b_ends_with(a, l)));
        // v0.6.29: `replace` es el nombre (el viejo `replace_text` queda como alias hasta v1.0).
        self.register("replace", 3, Rc::new(|i, a, l| i.b_replace_text(a, l)));
        self.register("replace_text", 3, Rc::new(|i, a, l| i.b_replace_text(a, l)));
        // strip_ansi: texto plano a partir de la salida de una terminal (secuencias
        // ESC CSI/OSC/simples y \r de retorno de carro fuera). Puro; para leer la
        // salida de `proc_spawn(..., {pty: true})` como un humano.
        self.register("strip_ansi", 1, Rc::new(|i, a, l| i.b_strip_ansi(a, l)));
        // Entrada de stdin (CLI): lee una línea; `nothing` en EOF. Funciona con pipe.
        self.register("read_line", -1, Rc::new(|i, a, l| i.b_read_line(a, l)));
        // Vuelca la salida pendiente a stdout en vivo (REPLs/loops largos). Ver b_flush.
        self.register("flush", 0, Rc::new(|i, _a, _l| i.b_flush()));
        // Estado del provider LLM: true si el motor cableó uno real (vs placeholder offline).
        self.register("llm_available", 0, Rc::new(|i, _a, _l| Ok(syn_bool(i.llm_callback.is_some()))));
        // Introspección de `judge`, sin gate (como las de LLM): disponibilidad, tokens de
        // entrada acumulados y el id versionado que contestó la última llamada.
        self.register("judge_available", 0, Rc::new(|i, _a, _l| Ok(syn_bool(i.judge_callback.is_some()))));
        self.register(
            "judge_usage",
            0,
            Rc::new(|i, _a, _l| {
                let total = i.judge_usage_callback.as_ref().map(|cb| cb()).unwrap_or(0);
                Ok(syn_int(total as i64))
            }),
        );
        self.register(
            "judge_model",
            0,
            Rc::new(|i, _a, _l| {
                Ok(i.judge_model_callback
                    .as_ref()
                    .and_then(|cb| cb())
                    .map(|m| syn_text(m.as_str()))
                    .unwrap_or(SynValue::Nothing))
            }),
        );
        // Tokens LLM acumulados del proceso (FRAMEWORK F1). Introspección sin gate,
        // como llm_available; offline/sin provider → 0.
        self.register(
            "llm_usage",
            0,
            Rc::new(|i, _a, _l| {
                let total = i.llm_usage_callback.as_ref().map(|cb| cb()).unwrap_or(0);
                Ok(syn_number(Number::parse_int_literal(&total.to_string())))
            }),
        );
        // Regex (computación pura, sin capability)
        // v0.6.29: la familia `regex_*` (los nombres viejos quedan deprecados hasta v1.0;
        // `capture` conserva su forma vieja de resultado, `regex_capture` devuelve SIEMPRE
        // una lista o `nothing`).
        self.register("matches", 2, Rc::new(|i, a, l| i.b_matches(a, l)));
        self.register("regex_find_all", 2, Rc::new(|i, a, l| i.b_find_all(a, l)));
        self.register("regex_capture", 2, Rc::new(|i, a, l| i.b_regex_capture(a, l)));
        self.register("regex_replace", 3, Rc::new(|i, a, l| i.b_replace_re(a, l)));
        self.register("find_all", 2, Rc::new(|i, a, l| i.b_find_all(a, l)));
        self.register("capture", 2, Rc::new(|i, a, l| i.b_capture(a, l)));
        self.register("replace_re", 3, Rc::new(|i, a, l| i.b_replace_re(a, l)));
        // SSR templates — requiere el engine; error fuera de él
        self.register("render", -1, Rc::new(|i, a, l| i.b_render(a, l)));
        // Operaciones intencionales
        self.register("apply", 2, Rc::new(|i, a, l| i.b_apply(a, l)));
        // call(task, args_map) — despacha una task con args NOMBRADOS desde un map
        // (FASE 1 tool-calling). Reusa el binding por nombre de `call_value_named`.
        // `apply` (map sobre lista) queda intacto.
        self.register("call", 2, Rc::new(|i, a, l| i.b_call(a, l)));
        // call_tool(task, args_map) — despacha una task COMO TOOL: igual que `call`
        // pero con least-privilege (caps restringidas a las DECLARADAS por la tool ∩
        // las del agente). El dispatch del loop de agente usa ESTE, no `call`.
        self.register("call_tool", 2, Rc::new(|i, a, l| i.b_call_tool(a, l)));
        // llm_step(prompt, catalog, context) — un PASO del LLM tool-aware (FASE 1):
        // devuelve un map {kind, …}. Gateado por la capability `llm` (reusa el hook).
        self.register("llm_step", 3, Rc::new(|i, a, l| i.b_llm_step(a, l)));
        // llm_stream(prompt, context, on_chunk) — genera invocando la task/lambda
        // `on_chunk` con cada fragmento (F2); devuelve el texto completo. Mismo gate `llm`.
        self.register("llm_stream", 3, Rc::new(|i, a, l| i.b_llm_stream(a, l)));
        self.register("where", 2, Rc::new(|i, a, l| i.b_where(a, l)));
        self.register("collect", 2, Rc::new(|i, a, l| i.b_collect(a, l)));
        self.register("transform", -1, Rc::new(|i, a, l| i.b_transform(a, l)));
        self.register("reduce", -1, Rc::new(|i, a, l| i.b_reduce(a, l)));
        // v0.6.29: orden TOTAL y estable; `desc = true` invierte sin romper la estabilidad y
        // deja los faltantes (`nothing`, NaN) al final igual.
        self.register_builtin_named("sort_by", vec!["items", "key", "desc"], Rc::new(|i, a, l| i.b_sort_by(a, l)));
        self.register_builtin_named("sort", vec!["items", "desc"], Rc::new(|i, a, l| i.b_sort(a, l)));
        // v0.6.29 (DATOS-3): `[{key, items}]` en orden de aparición, la clave con su tipo.
        self.register("group_by", 2, Rc::new(|i, a, _l| crate::tabular::group_by(i, a)));
        self.register("find_first", 2, Rc::new(|i, a, l| i.b_find_first(a, l)));
        self.register("every", 2, Rc::new(|i, a, l| i.b_every(a, l)));
        self.register("some", 2, Rc::new(|i, a, l| i.b_some(a, l)));
        self.register("count_where", 2, Rc::new(|i, a, l| i.b_count_where(a, l)));
        self.register("flatten", 1, Rc::new(|i, a, l| i.b_flatten(a, l)));
        self.register("zip_with", 3, Rc::new(|i, a, l| i.b_zip_with(a, l)));
        // Mini-stdlib (batch DX). Nacen con UN orden canónico (lista primero, el de la
        // familia): el dual-order existe para honrar un accidente histórico, no para lo
        // nuevo (y evita la ambigüedad real de index_of(lista_de_listas, sublista)).
        self.register("unique", 1, Rc::new(|i, a, l| i.b_unique(a, l)));
        // v0.6.20 — `reverse(lista|texto)`; `steps()` (introspección, sin capability).
        self.register("reverse", 1, Rc::new(|i, a, l| i.b_reverse(a, l)));
        // L1: `steps()` es un CANAL PUBLICO documentado (una rama privada cuenta distinto):
        // Sale con la etiqueta del PC del sitio donde se lo llama (via el despacho generico),
        // No con todo lo que la corrida toco — marcarlo con `seen` envenenaba la
        // instrumentacion de cualquier programa que hubiera visto un privado alguna vez.
        // T5 (ronda 5) — `steps()` es ESTADO AMBIENTE, no un valor que viaje por el resultado.
        // Una corrida privada mueve el contador y el borde de llamada no lo alcanza: volvía con
        // etiqueta vacía y `(steps() - base - 24) / 4` reconstruía el escalar privado entero,
        // exacto, en una línea y sin `declassify`. Sale con la unión de todo lo privado que la
        // corrida tocó, que es lo único que describe de qué depende el número.
        self.register(
            "steps",
            0,
            Rc::new(|i, _a, _l| {
                let n = SynValue::Number(Number::Int(i.steps as i64));
                if !i.labels {
                    return Ok(n);
                }
                let t = i.touched_label();
                if t.is_empty() {
                    return Ok(n);
                }
                Ok(labels::mark(n, t))
            }),
        );
        self.register("index_of", 2, Rc::new(|i, a, l| i.b_index_of(a, l)));
        // Etiquetas de flujo por principal (labels.rs). Siempre registrados: con las
        // etiquetas apagadas `private` es un error claro, `declassify` es la identidad,
        // `label_of` → [] e `is_private` → false. Son "conscientes" (CORE_LABEL_AWARE).
        self.register("private", -1, Rc::new(|i, a, l| i.b_private(a, l)));
        self.register("declassify", -1, Rc::new(|i, a, l| i.b_declassify(a, l)));
        self.register("label_of", 1, Rc::new(|i, a, l| i.b_label_of(a, l)));
        self.register("is_private", 1, Rc::new(|i, a, l| i.b_is_private(a, l)));

        // -- Librería matemática (math.rs) — funciones puras sobre Number.
        // NOTA: NO se registra un builtin `log` (choca con el soft keyword de
        // observabilidad); se usan ln/log10/log2.
        // signo / magnitud / selección (preservan tipo)
        self.register("abs", 1, Rc::new(|_i, a, _l| crate::math::abs(a)));
        self.register("sign", 1, Rc::new(|_i, a, _l| crate::math::sign(a)));
        self.register("min", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Min)));
        self.register("max", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Max)));
        self.register("clamp", 3, Rc::new(|_i, a, _l| crate::math::clamp(a)));
        // raíces / potencias
        self.register("sqrt", 1, Rc::new(|_i, a, _l| crate::math::sqrt(a)));
        self.register("cbrt", 1, Rc::new(|_i, a, _l| crate::math::cbrt(a)));
        self.register("hypot", 2, Rc::new(|_i, a, _l| crate::math::hypot(a)));
        self.register("pow", 2, Rc::new(|_i, a, _l| crate::math::pow(a)));
        // exp / log
        self.register("exp", 1, Rc::new(|_i, a, _l| crate::math::exp(a)));
        self.register("ln", 1, Rc::new(|_i, a, _l| crate::math::ln(a)));
        self.register("log10", 1, Rc::new(|_i, a, _l| crate::math::log10(a)));
        self.register("log2", 1, Rc::new(|_i, a, _l| crate::math::log2(a)));
        self.register("log_base", 2, Rc::new(|_i, a, _l| crate::math::log_base(a)));
        // trigonometría (radianes)
        self.register("sin", 1, Rc::new(|_i, a, _l| crate::math::sin(a)));
        self.register("cos", 1, Rc::new(|_i, a, _l| crate::math::cos(a)));
        self.register("tan", 1, Rc::new(|_i, a, _l| crate::math::tan(a)));
        self.register("asin", 1, Rc::new(|_i, a, _l| crate::math::asin(a)));
        self.register("acos", 1, Rc::new(|_i, a, _l| crate::math::acos(a)));
        self.register("atan", 1, Rc::new(|_i, a, _l| crate::math::atan(a)));
        self.register("atan2", 2, Rc::new(|_i, a, _l| crate::math::atan2(a)));
        self.register("radians", 1, Rc::new(|_i, a, _l| crate::math::radians(a)));
        self.register("degrees", 1, Rc::new(|_i, a, _l| crate::math::degrees(a)));
        // teoría de números (enteros)
        self.register("gcd", 2, Rc::new(|_i, a, _l| crate::math::gcd(a)));
        self.register("lcm", 2, Rc::new(|_i, a, _l| crate::math::lcm(a)));
        self.register("factorial", 1, Rc::new(|_i, a, _l| crate::math::factorial(a)));
        // introspección
        self.register("is_nan", 1, Rc::new(|_i, a, _l| crate::math::is_nan(a)));
        self.register("is_infinite", 1, Rc::new(|_i, a, _l| crate::math::is_infinite(a)));
        self.register("is_finite", 1, Rc::new(|_i, a, _l| crate::math::is_finite(a)));
        self.register("round_to", 2, Rc::new(|_i, a, _l| crate::math::round_to(a)));
        // agregados sobre una lista
        // v0.6.29: UNA implementación (stats.rs) para listas y arrays — `nothing` se saltea,
        // NaN se propaga, `axis =` con nombre, `ddof = 1` por defecto, decimal se conserva.
        self.register("sum", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Sum)));
        self.register("product", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Product)));
        self.register("mean", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Mean)));
        self.register("median", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Median)));
        self.register("percentile", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Percentile)));
        self.register("quantile", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Quantile)));
        self.register("histogram", -1, Rc::new(|_i, a, _l| crate::math::histogram(a)));

        // -- CSV (Batch 8) — transformación PURA texto↔valores (csv.rs), espejo de
        // json_encode/json_decode. El I/O de archivos va por read_file/write_file.
        self.register("csv_parse", -1, Rc::new(|_i, a, _l| crate::csv::csv_parse(a)));
        self.register("csv_encode", -1, Rc::new(|_i, a, _l| crate::csv::csv_encode(a)));

        // -- Completitud matemática (Batch 4) --
        // complejos: constructor + accesores (PUROS). Las transcendentales (sqrt/exp/…/pow)
        // ya registradas arriba se vuelven polimórficas internamente (real O complejo, G1).
        self.register("complex", 2, Rc::new(|_i, a, _l| crate::math::complex(a)));
        self.register("real", 1, Rc::new(|_i, a, _l| crate::math::real(a)));
        self.register("imag", 1, Rc::new(|_i, a, _l| crate::math::imag(a)));
        self.register("conj", 1, Rc::new(|_i, a, _l| crate::math::conj(a)));
        self.register("arg", 1, Rc::new(|_i, a, _l| crate::math::arg_phase(a)));
        self.register("is_complex", 1, Rc::new(|_i, a, _l| crate::math::is_complex(a)));
        // Hiperbólicas (polimórficas: real vía std f64, complejo vía num-complex).
        self.register("sinh", 1, Rc::new(|_i, a, _l| crate::math::sinh(a)));
        self.register("cosh", 1, Rc::new(|_i, a, _l| crate::math::cosh(a)));
        self.register("tanh", 1, Rc::new(|_i, a, _l| crate::math::tanh(a)));
        self.register("asinh", 1, Rc::new(|_i, a, _l| crate::math::asinh(a)));
        self.register("acosh", 1, Rc::new(|_i, a, _l| crate::math::acosh(a)));
        self.register("atanh", 1, Rc::new(|_i, a, _l| crate::math::atanh(a)));
        // Funciones especiales (real-only, vía libm).
        self.register("gamma", 1, Rc::new(|_i, a, _l| crate::math::gamma(a)));
        self.register("lgamma", 1, Rc::new(|_i, a, _l| crate::math::lgamma(a)));
        self.register("erf", 1, Rc::new(|_i, a, _l| crate::math::erf(a)));
        self.register("erfc", 1, Rc::new(|_i, a, _l| crate::math::erfc(a)));
        self.register("beta", 2, Rc::new(|_i, a, _l| crate::math::beta(a)));

        // -- Arrays numéricos n-dimensionales + álgebra lineal (Batch 5). PUROS. --
        // construcción.
        self.register("array", 1, Rc::new(|_i, a, _l| crate::arrays::array(a)));
        self.register("zeros", 1, Rc::new(|_i, a, _l| crate::arrays::zeros(a)));
        self.register("ones", 1, Rc::new(|_i, a, _l| crate::arrays::ones(a)));
        self.register("full", 2, Rc::new(|_i, a, _l| crate::arrays::full(a)));
        self.register("arange", -1, Rc::new(|_i, a, _l| crate::arrays::arange(a)));
        self.register("linspace", 3, Rc::new(|_i, a, _l| crate::arrays::linspace(a)));
        self.register("identity", 1, Rc::new(|_i, a, _l| crate::arrays::identity(a)));
        self.register("eye", 1, Rc::new(|_i, a, _l| crate::arrays::eye(a)));
        // Introspección / conversión / forma.
        self.register("shape", 1, Rc::new(|_i, a, _l| crate::arrays::shape(a)));
        self.register("ndim", 1, Rc::new(|_i, a, _l| crate::arrays::ndim(a)));
        self.register("size", 1, Rc::new(|_i, a, _l| crate::arrays::size(a)));
        self.register("is_array", 1, Rc::new(|_i, a, _l| crate::arrays::is_array(a)));
        self.register("to_list", 1, Rc::new(|_i, a, _l| crate::arrays::to_list(a)));
        self.register("reshape", 2, Rc::new(|_i, a, _l| crate::arrays::reshape(a)));
        self.register("transpose", 1, Rc::new(|_i, a, _l| crate::arrays::transpose(a)));
        // `flatten` NO se re-registra: el `flatten` de listas (arriba) ahora es polimórfico
        // y delega los arrays a `crate::arrays::flatten` (G1: no pisa el de listas).
        self.register("at", 2, Rc::new(|_i, a, _l| crate::arrays::at(a)));
        // Reducciones nuevas (std/var). sum/mean/min/max/product se extienden en math.rs.
        self.register("std", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Std)));
        self.register("var", -1, Rc::new(|i, a, _l| crate::stats::builtin(i, a, crate::stats::Kind::Var)));
        // v0.6.29 (DATOS-11/15): combinar, ubicar, acumular, relacionar, ajustar.
        self.register("concat", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::concat_or_stack(a, ax, false) }));
        self.register("stack", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::concat_or_stack(a, ax, true) }));
        self.register("argmin", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::arg_extreme(a, ax, false) }));
        self.register("argmax", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::arg_extreme(a, ax, true) }));
        self.register("cumsum", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::cumsum(a, ax) }));
        self.register("diff", 1, Rc::new(|i, a, _l| { let ax = i.kwarg("axis"); crate::arrays::diff(a, ax) }));
        self.register("cov", 2, Rc::new(|i, a, _l| { let d = i.kwarg("ddof"); crate::arrays::cov(a, d) }));
        self.register("corr", 2, Rc::new(|_i, a, _l| crate::arrays::corr(a)));
        self.register("lstsq", 2, Rc::new(|_i, a, _l| crate::arrays::lstsq(a)));
        self.register("polyfit", 3, Rc::new(|_i, a, _l| crate::arrays::polyfit(a)));
        self.register("polyval", 2, Rc::new(|_i, a, _l| crate::arrays::polyval(a)));
        self.register("mode", 1, Rc::new(|_i, a, _l| crate::tabular::mode(a)));
        // DATOS-3/6/14: tablas como listas de mapas.
        self.register("summarize", 3, Rc::new(|i, a, _l| crate::tabular::summarize(i, a)));
        self.register("count_by", -1, Rc::new(|i, a, _l| crate::tabular::count_by(i, a)));
        self.register("pivot", -1, Rc::new(|i, a, _l| crate::tabular::pivot(i, a)));
        // `count()` es el agregado de `summarize` (filas del grupo); `count(xs)` cuenta los
        // valores PRESENTES (el `count` de pandas/SQL: `nothing` no cuenta) y
        // `count_missing(xs)` los que faltan.
        self.register("count", -1, Rc::new(|_i, a, _l| match a.first() {
            None => crate::tabular::aggregator("count", a),
            Some(SynValue::List(l)) => Ok(syn_int(l.borrow().iter().filter(|v| !matches!(v, SynValue::Nothing)).count() as i64)),
            Some(other) => Err(err(format!("count(values) counts the present values of a list, got {}; count() alone is the summarize aggregate", other.type_name()))),
        }));
        self.register("count_missing", 1, Rc::new(|_i, a, _l| match nth(a, 0)? {
            SynValue::List(l) => Ok(syn_int(l.borrow().iter().filter(|v| matches!(v, SynValue::Nothing)).count() as i64)),
            other => Err(err(format!("count_missing(values) needs a list, got {}", other.type_name()))),
        }));
        for kind in ["sum", "mean", "min", "max", "median", "first", "n_unique"] {
            let name = format!("{}_of", kind);
            self.register(&name, 1, Rc::new(move |_i, a, _l| crate::tabular::aggregator(kind, a)));
        }
        self.register("quantile_of", 2, Rc::new(|_i, a, _l| crate::tabular::aggregator("quantile", a)));
        self.register("is_missing", 1, Rc::new(|_i, a, _l| crate::tabular::is_missing(a)));
        self.register("fill_missing", 2, Rc::new(|_i, a, _l| crate::tabular::fill_missing(a)));
        self.register("drop_missing", -1, Rc::new(|_i, a, _l| crate::tabular::drop_missing(a)));
        self.register("fill_nan", 2, Rc::new(|_i, a, _l| crate::tabular::fill_nan(a)));
        // DATOS-17: el linaje que el motor anotó (lo mismo que `receipt()` publica en `inputs`).
        self.register("lineage", 0, Rc::new(|i, _a, _l| {
            let items = i
                .lineage()
                .iter()
                .map(|e| {
                    let mut m = IndexMap::new();
                    m.insert("source".to_string(), syn_text(e.source.as_str()));
                    m.insert("what".to_string(), syn_text(e.what.as_str()));
                    m.insert("sha256".to_string(), syn_text(e.sha256.as_str()));
                    m.insert("bytes".to_string(), syn_int(e.bytes as i64));
                    m.insert("encoding".to_string(), syn_text(e.encoding.as_str()));
                    // Local, nunca en el recibo: con la sal el dueño revela una consulta.
                    if let Some((salt, qenc)) = &e.salt {
                        m.insert("salt".to_string(), syn_text(salt.as_str()));
                        m.insert("committed_encoding".to_string(), syn_text(*qenc));
                    }
                    syn_map(m)
                })
                .collect();
            Ok(syn_list(items))
        }));
        // DATOS-13: fechas, instantes y duraciones como tipos (puros; sólo `now()` pide time).
        self.register("date", -1, Rc::new(|_i, a, _l| crate::temporal::date(a)));
        self.register("datetime", -1, Rc::new(|_i, a, _l| crate::temporal::datetime(a)));
        self.register_builtin_named(
            "duration",
            vec!["days", "hours", "minutes", "seconds", "milliseconds", "weeks"],
            Rc::new(|_i, a, _l| crate::temporal::duration(a)),
        );
        self.register("parse_date", -1, Rc::new(|_i, a, _l| crate::temporal::parse_date(a)));
        self.register("parse_datetime", -1, Rc::new(|_i, a, _l| crate::temporal::parse_datetime(a)));
        self.register("truncate", 2, Rc::new(|_i, a, _l| crate::temporal::truncate(a)));
        self.register("add_months", 2, Rc::new(|_i, a, _l| crate::temporal::add_months(a)));
        self.register("add_days", 2, Rc::new(|_i, a, _l| crate::temporal::add_days(a)));
        self.register("date_range", -1, Rc::new(|_i, a, _l| crate::temporal::date_range(a)));
        self.register("timestamp", 1, Rc::new(|_i, a, _l| crate::temporal::timestamp(a)));
        self.register("to_timezone", 2, Rc::new(|_i, a, _l| crate::temporal::to_timezone(a)));
        self.register("in_units", 2, Rc::new(|_i, a, _l| crate::temporal::in_units(a)));
        // DATOS-12: generadores con semilla (puros).
        self.register("rng", 1, Rc::new(|_i, a, _l| crate::rng::make_rng(a)));
        self.register("rng_spawn", 2, Rc::new(|_i, a, _l| crate::rng::b_spawn(a)));
        self.register("random_normal", 1, Rc::new(|i, a, l| crate::rng::b_normal(i, a, l)));
        self.register("shuffle", 2, Rc::new(|i, a, l| crate::rng::b_shuffle(i, a, l)));
        self.register("sample", 3, Rc::new(|i, a, l| crate::rng::b_sample(i, a, l)));
        self.register("choice", 2, Rc::new(|i, a, l| crate::rng::b_choice(i, a, l)));
        // Álgebra lineal (faer, sobre 2D).
        self.register("matmul", 2, Rc::new(|_i, a, _l| crate::arrays::matmul(a)));
        self.register("dot", 2, Rc::new(|_i, a, _l| crate::arrays::dot(a)));
        self.register("solve", 2, Rc::new(|_i, a, _l| crate::arrays::solve(a)));
        self.register("det", 1, Rc::new(|_i, a, _l| crate::arrays::det(a)));
        self.register("inv", 1, Rc::new(|_i, a, _l| crate::arrays::inv(a)));
        self.register("norm", -1, Rc::new(|_i, a, _l| crate::arrays::norm(a)));
        self.register("trace", 1, Rc::new(|_i, a, _l| crate::arrays::trace(a)));
        self.register("eig", 1, Rc::new(|_i, a, _l| crate::arrays::eig(a)));
        self.register("svd", 1, Rc::new(|_i, a, _l| crate::arrays::svd(a)));

        // Constantes matemáticas — VALORES globales (se usan sin llamar): pi/tau/e/inf/nan.
        {
            let mut g = self.global_env.borrow_mut();
            g.bindings.insert("pi".to_string(), syn_float(std::f64::consts::PI));
            g.bindings.insert("tau".to_string(), syn_float(std::f64::consts::TAU));
            g.bindings.insert("e".to_string(), syn_float(std::f64::consts::E));
            g.bindings.insert("inf".to_string(), syn_float(f64::INFINITY));
            g.bindings.insert("nan".to_string(), syn_float(f64::NAN));
        }
    }

    /// Si `Enum.variant` (un `property_name` accedido sobre un objeto que evalúa a
    /// un map namespace de enum con "__enum"), devuelve el id calificado
    /// ("Enum.variant"); si no, None.
    fn enum_variant_id(
        &mut self,
        property_name: &str,
        object: &Node,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<String>, Control> {
        let obj = self.exec(object, env)?;
        if let SynValue::Map(m) = &obj {
            if let Some(SynValue::Text(enum_name)) = m.borrow().get("__enum") {
                return Ok(Some(format!("{}.{}", enum_name, property_name)));
            }
        }
        Ok(None)
    }

    /// Matcher de patrones a nivel TOP de un arm `match` (G2). Aplica el matcher
    /// recursivo SÓLO para patrones estructurales (wildcard/list/map) o variantes de
    /// enum; para un identificador suelto u otra expresión a nivel top usa la
    /// **comparación por valor** de siempre (evaluar + `syn_equals`). Así `is x` (top)
    /// sigue comparando con la variable `x`, NUNCA liga.
    fn match_pattern_top(
        &mut self,
        pattern: &Node,
        value: &SynValue,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<Vec<(String, SynValue)>>, Control> {
        match &pattern.kind {
            // Estructurales y variantes de enum → matcher recursivo.
            NodeKind::WildcardPattern
            | NodeKind::ListPattern { .. }
            | NodeKind::MapPattern { .. }
            | NodeKind::PropertyAccess { .. }
            | NodeKind::TaskCall { .. } => self.match_pattern(pattern, value, env),
            // Identificador suelto / literal / cualquier otra expresión → valor (G2).
            _ => {
                let p = self.exec(pattern, env)?;
                self.note_pattern(&p);
                Ok(if pattern_eq(value, &p)? { Some(Vec::new()) } else { None })
            }
        }
    }

    /// Matcher recursivo de patrones (Batch 2). Devuelve `Some(bindings)` si matchea
    /// (acumulando `(nombre, valor)` de los binders), `None` si no. Acá un `Identifier`
    /// SÍ liga: sólo se llega vía sub-patrón de un patrón estructural / variante (a nivel
    /// top G2 lo desvía `match_pattern_top`). El `_` ya se canonizó a `WildcardPattern`.
    fn match_pattern(
        &mut self,
        pattern: &Node,
        value: &SynValue,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<Vec<(String, SynValue)>>, Control> {
        match &pattern.kind {
            NodeKind::WildcardPattern => Ok(Some(Vec::new())),
            NodeKind::Identifier { name } => Ok(Some(vec![(name.clone(), value.clone())])),
            NodeKind::ListPattern { prefix, rest, suffix } => {
                self.match_list_pattern(prefix, rest, suffix, value, env)
            }
            NodeKind::MapPattern { fields } => self.match_map_pattern(fields, value, env),
            // Variante de enum sin payload: `is Enum.variant`.
            NodeKind::PropertyAccess { property_name, object, .. } => {
                if let Some(id) = self.enum_variant_id(property_name, object, env)? {
                    return self.match_variant(value, &id, None, env);
                }
                let p = self.exec(pattern, env)?;
                self.note_pattern(&p);
                Ok(if pattern_eq(value, &p)? { Some(Vec::new()) } else { None })
            }
            // Variante de enum con payload: `is Enum.variant(p1, …)` — sub-patrones.
            NodeKind::TaskCall { name, arguments } => {
                if let NodeKind::PropertyAccess { property_name, object, .. } = &name.kind {
                    // Sólo es patrón de variante si todos los args son posicionales.
                    if arguments.iter().all(|a| a.name.is_none()) {
                        if let Some(id) = self.enum_variant_id(property_name, object, env)? {
                            let subs: Vec<&Node> = arguments.iter().map(|a| &a.value).collect();
                            return self.match_variant(value, &id, Some(&subs), env);
                        }
                    }
                }
                // No es variante → patrón de valor (evaluar + comparar).
                let p = self.exec(pattern, env)?;
                self.note_pattern(&p);
                Ok(if pattern_eq(value, &p)? { Some(Vec::new()) } else { None })
            }
            // Literal / cualquier otra expresión → patrón de valor.
            _ => {
                let p = self.exec(pattern, env)?;
                self.note_pattern(&p);
                Ok(if pattern_eq(value, &p)? { Some(Vec::new()) } else { None })
            }
        }
    }

    /// Matchea un valor contra una variante de enum (`__variant == id`) y, si hay
    /// sub-patrones, los liga recursivamente al payload posicional (orden declarado).
    fn match_variant(
        &mut self,
        value: &SynValue,
        variant_id: &str,
        subs: Option<&[&Node]>,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<Vec<(String, SynValue)>>, Control> {
        let is_match = match value {
            SynValue::Map(m) => matches!(
                m.borrow().get("__variant"),
                Some(SynValue::Text(t)) if t.as_ref() == variant_id
            ),
            _ => false,
        };
        if !is_match {
            return Ok(None);
        }
        match subs {
            // `is Enum.variant` sin paréntesis: matchea la variante, sin ligar.
            None => Ok(Some(Vec::new())),
            Some(subpats) => {
                // Payload = valores del map salvo "__variant", en orden de inserción.
                let payload: Vec<SynValue> = match value {
                    SynValue::Map(m) => m
                        .borrow()
                        .iter()
                        .filter(|(k, _)| k.as_str() != "__variant")
                        .map(|(_, v)| v.clone())
                        .collect(),
                    _ => Vec::new(),
                };
                if subpats.len() != payload.len() {
                    return Err(err(format!(
                        "variant {} binds {} fields, got {}",
                        variant_id,
                        payload.len(),
                        subpats.len()
                    )));
                }
                let mut binds = Vec::new();
                for (sp, pv) in subpats.iter().zip(payload.iter()) {
                    match self.match_pattern(sp, pv, env)? {
                        Some(b) => binds.extend(b),
                        None => return Ok(None),
                    }
                }
                Ok(Some(binds))
            }
        }
    }

    /// Matchea un `ListPattern` contra un valor (sólo `SynValue::List`). Sin spread:
    /// longitud exacta. Con spread: `len >= prefix+suffix`; liga prefix desde el frente,
    /// suffix desde atrás, y (si el spread tiene nombre) el medio como sub-lista.
    fn match_list_pattern(
        &mut self,
        prefix: &[Node],
        rest: &Option<Option<String>>,
        suffix: &[Node],
        value: &SynValue,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<Vec<(String, SynValue)>>, Control> {
        // Clonamos los items (Rc-clones baratos) para no sostener el borrow del RefCell
        // mientras recursamos (match_pattern toma &mut self).
        let items: Vec<SynValue> = match value {
            SynValue::List(l) => l.borrow().clone(),
            _ => return Ok(None),
        };
        let n = items.len();
        let mut binds = Vec::new();
        match rest {
            None => {
                if n != prefix.len() {
                    return Ok(None);
                }
                for (p, v) in prefix.iter().zip(items.iter()) {
                    match self.match_pattern(p, v, env)? {
                        Some(b) => binds.extend(b),
                        None => return Ok(None),
                    }
                }
            }
            Some(rest_name) => {
                if n < prefix.len() + suffix.len() {
                    return Ok(None);
                }
                for (p, v) in prefix.iter().zip(items[..prefix.len()].iter()) {
                    match self.match_pattern(p, v, env)? {
                        Some(b) => binds.extend(b),
                        None => return Ok(None),
                    }
                }
                let suffix_start = n - suffix.len();
                for (p, v) in suffix.iter().zip(items[suffix_start..].iter()) {
                    match self.match_pattern(p, v, env)? {
                        Some(b) => binds.extend(b),
                        None => return Ok(None),
                    }
                }
                if let Some(name) = rest_name {
                    let mid: Vec<SynValue> = items[prefix.len()..suffix_start].to_vec();
                    binds.push((name.clone(), syn_list(mid)));
                }
            }
        }
        Ok(Some(binds))
    }

    /// Matchea un `MapPattern` contra un valor (sólo `SynValue::Map`). **Subset**: cada
    /// clave del patrón debe existir; claves extra del map se ignoran. `None` → bindea la
    /// clave a una var del mismo nombre; `Some(subpat)` → recursa. Server NO se matchea
    /// (sus campos no son un map plano); documentado.
    fn match_map_pattern(
        &mut self,
        fields: &[(String, Option<Node>)],
        value: &SynValue,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<Vec<(String, SynValue)>>, Control> {
        let map = match value {
            SynValue::Map(m) => m.borrow().clone(),
            _ => return Ok(None),
        };
        let mut binds = Vec::new();
        for (k, subpat) in fields {
            let fv = match map.get(k) {
                Some(v) => v.clone(),
                None => return Ok(None),
            };
            match subpat {
                None => binds.push((k.clone(), fv)),
                Some(p) => match self.match_pattern(p, &fv, env)? {
                    Some(b) => binds.extend(b),
                    None => return Ok(None),
                },
            }
        }
        Ok(Some(binds))
    }

    // =========================================================
    // ejecución
    // =========================================================

    pub fn execute(&mut self, program: &Program) -> Result<SynValue, Control> {
        // T5 (B8): nombres protegidos → error de carga, antes de correr nada.
        check_protected_names(program)?;
        // v0.6.29: nombres que cambiaron antes de v1.0 → un aviso por stderr, una vez.
        if let Some(first) = program.statements.first() {
            crate::deprecated::warn_once_at_load(program, &first.location.file);
        }
        // T5 (ronda 7): el conjunto con el que se redacta sale del AST, antes de correr nada.
        self.set_declared_principals(program);
        let r = self.execute_inner(program);
        // T5 (M1): un error no atrapado sale redactado si la corrida tocó privados.
        self.redact_for_host(r)
    }

    fn execute_inner(&mut self, program: &Program) -> Result<SynValue, Control> {
        let g = self.global_env.clone();
        self.control_taint = self.no_label.clone();
        self.loop_taint = self.no_label.clone();
        self.escaping_taint = self.no_label.clone();
        self.loop_depth = 0;
        // Preámbulo: las declaraciones `intent`/`require` al inicio se ejecutan
        // primero; luego, si se declaró un intent, se congela (anti prompt-injection);
        // luego el cuerpo (engine.py:785-809).
        let mut split = 0;
        for stmt in &program.statements {
            if matches!(
                stmt.kind,
                NodeKind::IntentDeclaration { .. } | NodeKind::RequireStatement { .. }
            ) {
                split += 1;
            } else {
                break;
            }
        }
        let mut last = SynValue::Nothing;
        for stmt in &program.statements[..split] {
            last = self.exec(stmt, &g)?;
        }
        if self.intent.is_some() {
            self.intent_frozen = true;
        }
        for stmt in &program.statements[split..] {
            last = self.exec(stmt, &g)?;
        }
        Ok(last)
    }

    /// Runner del test framework (Batch 3). Corre el SETUP top-level (todo lo que no es
    /// `TestBlock`, respetando el preámbulo intent/require como `execute`) en el global, y
    /// luego cada `TestBlock` en un Environment HIJO aislado (G5). Captura el resultado de
    /// cada test SIN abortar a los demás. Si el setup falla, devuelve un único outcome de
    /// error de setup. Las defs top-level quedan visibles dentro de cada test.
    pub fn run_test_blocks(&mut self, program: &Program) -> Vec<TestOutcome> {
        self.run_test_blocks_with(program, &mut |_| None)
    }

    /// Como `run_test_blocks`, con un hook `after_each(nombre)` que corre al terminar
    /// cada bloque `test` (cuerpo incluido) y puede devolver un mensaje de fallo —
    /// el motor lo usa para joinear los agentes que el test spawneó y reflejar sus
    /// errores como fallo de ESE test (`synsema test` cablea el swarm real).
    pub fn run_test_blocks_with(
        &mut self,
        program: &Program,
        after_each: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Vec<TestOutcome> {
        let g = self.global_env.clone();
        // Preámbulo: intent/require al inicio, luego congelar intent (igual que execute).
        let mut split = 0;
        for stmt in &program.statements {
            if matches!(
                stmt.kind,
                NodeKind::IntentDeclaration { .. } | NodeKind::RequireStatement { .. }
            ) {
                split += 1;
            } else {
                break;
            }
        }
        // Setup: preámbulo + todas las sentencias no-`TestBlock`. Un fallo → outcome único.
        let setup: Result<(), Control> = (|| {
            // T5 (B8): nombres protegidos → error de carga.
            check_protected_names(program)?;
            // T5 (ronda 7): idem, antes del setup de los bloques `test`.
            self.set_declared_principals(program);
            for stmt in &program.statements[..split] {
                self.exec(stmt, &g)?;
            }
            if self.intent.is_some() {
                self.intent_frozen = true;
            }
            for stmt in &program.statements[split..] {
                if matches!(stmt.kind, NodeKind::TestBlock { .. }) {
                    continue;
                }
                self.exec(stmt, &g)?;
            }
            Ok(())
        })();
        if let Err(c) = setup {
            return vec![TestOutcome {
                name: "<setup>".to_string(),
                passed: false,
                message: Some(self.host_message(&c)),
                assertion: matches!(&c, Control::Error(e) if e.is_assertion),
            }];
        }
        // Cada test en orden, aislado, con captura (no-abort, G5).
        let mut outcomes = Vec::new();
        for stmt in &program.statements {
            if let NodeKind::TestBlock { name, body } = &stmt.kind {
                let test_env = Environment::child(&g, &format!("test:{}", name));
                // Cada bloque `test` es su propia unidad — la tinta de continuación de uno
                // No puede llegarle al siguiente (ni al setup).
                let saved_taint = self.take_taint();
                let mut outcome = match self.exec_block(body, &test_env) {
                    Ok(_) => {
                        TestOutcome { name: name.clone(), passed: true, message: None, assertion: false }
                    }
                    // T5 (regla 1.a, ronda 5) — el veredicto del enforcement NO es atrapable, y
                    // un runner que lo convierte en un ✗ por bloque lo atrapa igual que un
                    // `try/recover`: con ocho bloques que prueban un bit cada uno, la columna de
                    // ✓/✗ deletrea el byte (✗✓✗✓✗✗✓✗ = 181), y sirve incluso usando la propia
                    // violación como bit. La corrida entera se corta acá, con UN outcome —el
                    // límite que declara la spec es un bit por corrida, no uno por bloque.
                    Err(Control::Error(e)) if self.labels && e.is_fatal_for_labels() => {
                        let msg = self.host_message(&Control::Error(e));
                        outcomes.clear();
                        outcomes.push(TestOutcome {
                            // Ronda 7: el nombre del bloque lo pone el ATACANTE, así que nombrar
                            // en cuál murió es tantos bits como bloques haya — el mismo mensaje
                            // que dice "un veredicto por bloque sería un bit por bloque" los
                            // entregaba en su propio título.
                            name: "labels: the run was stopped".to_string(),
                            passed: false,
                            assertion: false,
                            message: Some(format!(
                                "{} — a label violation stops the whole run: a per-block verdict would \
                                 be one bit of private data per block. Fix it and run the suite again",
                                msg
                            )),
                        });
                        self.restore_taint(saved_taint);
                        return outcomes;
                    }
                    Err(Control::Error(e)) => TestOutcome {
                        name: name.clone(),
                        passed: false,
                        assertion: e.is_assertion,
                        // T5 (M1): el mensaje sale redactado si el test tocó privados.
                        message: Some(self.host_message(&Control::Error(e))),
                    },
                    Err(c @ (Control::Give(_) | Control::Stop(_))) => TestOutcome {
                        name: name.clone(),
                        passed: false,
                        message: Some(control_message(&c)),
                        assertion: false,
                    },
                };
                self.restore_taint(saved_taint);
                // Agentes del test: se esperan y sus errores cuentan como fallo del test.
                if let Some(msg) = after_each(name) {
                    outcome.passed = false;
                    outcome.message = Some(match outcome.message.take() {
                        Some(prev) => format!("{}; {}", prev, msg),
                        None => msg,
                    });
                }
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    fn exec_block(
        &mut self,
        stmts: &[Node],
        env: &Rc<RefCell<Environment>>,
    ) -> Result<SynValue, Control> {
        let mut result = SynValue::Nothing;
        for (idx, s) in stmts.iter().enumerate() {
            // Cancelación cooperativa: un `load` relajado por statement (despreciable
            // frente al tree-walker) — un handler en `while true` deja de ser inmortal.
            if self.cancel.flag.load(std::sync::atomic::Ordering::Relaxed) {
                self.check_cancel()?;
            }
            let _ = idx;
            // Soltar el valor de la sentencia anterior ANTES de ejecutar la siguiente: si
            // no, esa copia viva hace parecer compartida la lista que la sentencia va a
            // modificar y el copy-on-write copiaría de más (v0.6.29).
            drop(std::mem::replace(&mut result, SynValue::Nothing));
            result = self.exec(s, env)?;
        }
        Ok(result)
    }

    /// Todo error que **nace** con una etiqueta de PC no vacía queda
    /// marcado ahí mismo (`from_private_pc` + los principales del momento). Con esa marca
    /// deja de ser atrapable (`try/recover`, `assert_error` lo re-propagan) y sale redactado
    /// Al host: que un salto de control desde un contexto privado se pueda observar —o peor,
    /// Recuperar— es un bit por iteración, que es la extracción completa (casos 1.a–1.d).
    /// Marcar acá, en el único embudo de evaluación, cubre TODA fuente de error (raise,
    /// Índice, clave, aritmética, builtins) sin tocar cada sitio.
    fn exec(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        if !self.labels {
            return self.exec_node(node, env);
        }
        // `seen` se scopea al nodo: lo de afuera se guarda, el nodo arranca limpio, y al
        // salir se funden. Así se sabe exactamente qué privados tocó ESTE nodo.
        let outer = std::mem::replace(&mut self.seen, self.no_label.clone());
        let mut r = self.exec_node(node, env);
        let inner = std::mem::replace(&mut self.seen, self.no_label.clone());
        self.seen = labels::union(&outer, &inner);
        if let Err(Control::Error(e)) = &mut r {
            // T5 (ronda 6, B1) — **la misma unión decide las dos cosas**. Hasta acá la
            // atrapabilidad miraba SÓLO el PC y la redacción miraba el PC ∪ lo que el nodo
            // tocó, y esa asimetría era el agujero: un error CAUSADO por un privado pero
            // nacido sin rama (`1 / (secret - i)` dentro de un bucle público) salía redactado
            // pero atrapable, así que un `recover` lo absorbía, la corrida terminaba bien y el
            // prefijo del bucle ya había dejado el secreto entero en un contador público —
            // medido: 42 y 181 exactos, `label_of` vacío, exit 0 y `code check` en verde.
            //
            // Con la unión, un error que depende de un dato privado es tan poco atrapable como
            // uno nacido bajo rama privada: que se pueda observar —o peor, recuperar— si la
            // operación falló es exactamente el bit que la regla 1.a prohíbe. De paso cierra el
            // veredicto por bloque del runner de tests, que sólo cortaba con `is_fatal_for_labels`.
            let pc_empty = self.pc_is_empty();
            if !pc_empty || !inner.is_empty() {
                let l = labels::union(&self.pc_label(), &inner);
                if !l.is_empty() {
                    e.from_private_pc = true;
                    // Redacción: el PC de este instante ∪ lo privado que tocó ESTE nodo (no el
                    // acumulado de la corrida). Así un `raise "saldo " + text(x)` con `x`
                    // privado sale redactado aunque el PC esté vacío, y un `5 % 0` posterior
                    // conserva su mensaje real. El error más interno gana (el conjunto más
                    // chico): sólo se escribe si está vacío.
                    if e.redact_label.is_empty() && !e.from_labels {
                        e.redact_label = self.safe_label(&l);
                    }
                }
            }
        }
        r
    }

    fn exec_node(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        // V0.6.20 — un paso por nodo; `wrapping_add`: contar jamás puede ser un pánico.
        self.steps = self.steps.wrapping_add(1);
        let loc = &node.location;
        match &node.kind {
            // -- Literales --
            // T5 (B5): un literal ESCALAR evaluado bajo PC privado lleva el PC (QUÉ literal se
            // evaluó depende de la rama). Los literales List/Map NO se envuelven: sus
            // elementos ya llevan lo suyo (un escalar marcado, un `declassify(...)` inline
            // público, un identificador con su etiqueta). `pc_mark` es la identidad sin PC.
            NodeKind::NumberLiteral { value } => self.pc_mark(syn_number(value.clone()), loc),
            NodeKind::TextLiteral { value } => self.pc_mark(syn_text(value.as_str()), loc),
            NodeKind::BoolLiteral { value } => self.pc_mark(syn_bool(*value), loc),
            NodeKind::NothingLiteral => self.pc_mark(SynValue::Nothing, loc),
            NodeKind::ListLiteral { elements } => {
                let mut items = Vec::with_capacity(elements.len());
                for e in elements {
                    items.push(self.exec(e, env)?);
                }
                Ok(syn_list(items))
            }
            NodeKind::MapLiteral { pairs } => {
                let mut m = IndexMap::new();
                // Una clave privada etiqueta el mapa entero (la clave es texto visible).
                let mut key_label: Option<Label> = None;
                for (k, v) in pairs {
                    let key = self.exec(k, env)?;
                    let val = self.exec(v, env)?;
                    if self.labels && key.is_private() {
                        // Una clave LITERAL bajo PC sólo lleva el PC (B5): es texto del
                        // programa, no etiqueta el mapa (el `let`/`give` ya llevan el PC).
                        // Una clave computada privada sí: su etiqueta es de datos.
                        if !is_scalar_literal(k) {
                            let kl = labels::label(&key);
                            key_label = Some(match key_label {
                                Some(l) => labels::union(&l, &kl),
                                None => kl,
                            });
                        }
                        m.insert(labels::unwrap(&key).to_string(), val);
                        continue;
                    }
                    m.insert(key.to_string(), val);
                }
                match key_label {
                    Some(l) => self.rewrap(syn_map(m), l, loc),
                    None => Ok(syn_map(m)),
                }
            }

            // -- Identificadores y acceso --
            NodeKind::Identifier { name } => match env_get(env, name) {
                Some(v) => Ok(v),
                None => {
                    // Batch DX (decisión #6): los bindings que serve inyecta SOLO en el
                    // scope de un route handler (`request`/`query`/`params`/`read_body`/
                    // `read_body_bytes`, ver request_bindings) son el tropiezo #1 de las
                    // tasks auxiliares — el hint dice el fix exacto. Cualquier otro
                    // nombre conserva el mensaje de siempre.
                    let mut msg = format!("Undefined variable: '{}'", name);
                    // v0.6.29 (V1-E1): reflejos de otros lenguajes → la forma de Synsema.
                    if let Some(h) = crate::reflexes::name_hint(name) {
                        msg.push_str(&format!(" — in Synsema: {}", h));
                    } else if let Some(h) = crate::reflexes::statement_hint(name) {
                        msg.push_str(&format!(" — `{}` is not a Synsema statement: {}", name, h));
                    }
                    if matches!(
                        name.as_str(),
                        "request" | "query" | "params" | "read_body" | "read_body_bytes"
                    ) {
                        msg.push_str(&format!(
                            ". '{}' is only available inside route handlers (serve) — pass it as a parameter: task handle({})",
                            name, name
                        ));
                    }
                    Err(err_at(msg, loc))
                }
            },
            NodeKind::PropertyAccess { property_name, object, via_of } => {
                // Hint de precedencia de `of` (batch DX, decisión #7): `a of b.c` parsea
                // como `a of (b.c)` — si ESTE nodo nació de `of` y su operando derecho es
                // un property-access que falla con "Map has no key", el error gana el fix
                // exacto. Cero costo en el camino feliz; cualquier otro error queda igual.
                let obj = match self.exec(object, env) {
                    Ok(v) => v,
                    Err(Control::Error(mut e))
                        if *via_of
                            && matches!(object.kind, NodeKind::PropertyAccess { .. })
                            && e.message.starts_with("Map has no key") =>
                    {
                        e.message.push_str(
                            ". note: 'a of b.c' reads as 'a of (b.c)' — to get '(a of b).c', bind first: let x be a of b, then x.c",
                        );
                        return Err(Control::Error(e));
                    }
                    Err(other) => return Err(other),
                };
                self.property_read(obj, property_name, loc)
            }
            NodeKind::IndexAccess { object, index } => {
                let obj = self.exec(object, env)?;
                let idx = self.exec(index, env)?;
                self.index_read(obj, idx, loc)
            }

            // -- Operadores --
            NodeKind::BinaryOp { left, operator, right } => {
                let l = self.exec(left, env)?;
                // `and`/`or` cortocircuitan (v0.6.10+): el lado derecho sólo se evalúa
                // si hace falta, así `contains(m, "k") and m["k"] == 1` es un guard
                // válido. Resultado siempre booleano (no devuelve el operando, como
                // Python): `x or default` NO es un idioma de Synsema.
                // El booleano sale con la unión de las etiquetas de lo evaluado.
                if operator == "and" {
                    if !l.is_truthy() {
                        let res = syn_bool(false);
                        return if self.labels { self.join_operands(res, &l, None, loc) } else { Ok(res) };
                    }
                    let r = self.exec(right, env)?;
                    let res = syn_bool(r.is_truthy());
                    return if self.labels { self.join_operands(res, &l, Some(&r), loc) } else { Ok(res) };
                }
                if operator == "or" {
                    if l.is_truthy() {
                        let res = syn_bool(true);
                        return if self.labels { self.join_operands(res, &l, None, loc) } else { Ok(res) };
                    }
                    let r = self.exec(right, env)?;
                    let res = syn_bool(r.is_truthy());
                    return if self.labels { self.join_operands(res, &l, Some(&r), loc) } else { Ok(res) };
                }
                let r = self.exec(right, env)?;
                self.exec_binary(l, operator, r, loc)
            }
            NodeKind::UnaryOp { operator, operand } => {
                let v = self.exec(operand, env)?;
                // Operando privado (a cualquier profundidad, B4) → desenvolver la
                // superficie, operar, re-envolver con la etiqueta profunda.
                if self.labels {
                    let l = labels::label_deep(&v);
                    if !l.is_empty() {
                        self.note_seen(&l);
                        let inner = labels::unwrap(&v).clone();
                        let r = self.exec_unary(operator, inner, loc)?;
                        return self.rewrap(r, l, loc);
                    }
                }
                self.exec_unary(operator, v, loc)
            }
            NodeKind::CompareChain { operands, operators } => {
                // `a < b < c`: cada operando una vez, corte en el primer par falso. Bajo
                // etiquetas el booleano une las etiquetas de lo evaluado, como `and`.
                let mut prev = self.exec(&operands[0], env)?;
                let mut acc: Option<SynValue> = None;
                for (op, node) in operators.iter().zip(operands[1..].iter()) {
                    let cur = self.exec(node, env)?;
                    let c = self.exec_binary(prev, op, cur.clone(), loc)?;
                    let joined = match acc {
                        Some(a) if self.labels => {
                            self.join_operands(syn_bool(c.is_truthy()), &a, Some(&c), loc)?
                        }
                        _ => c,
                    };
                    if !joined.is_truthy() {
                        return if self.labels {
                            self.join_operands(syn_bool(false), &joined, None, loc)
                        } else {
                            Ok(syn_bool(false))
                        };
                    }
                    acc = Some(joined);
                    prev = cur;
                }
                Ok(acc.unwrap_or_else(|| syn_bool(true)))
            }
            NodeKind::PipeExpression { value, transforms } => {
                let mut v = self.exec(value, env)?;
                for t in transforms {
                    // Un paso que es una llamada recibe el valor como PRIMER argumento
                    // (v0.6.29): `xs |> sort_by(f)` = `sort_by(xs, f)`.
                    if let NodeKind::TaskCall { name, arguments } = &t.kind {
                        v = self.exec_call_with_first(name, arguments, v, env, loc)?;
                    } else {
                        let func = self.exec(t, env)?;
                        v = self.call_value(func, vec![v], loc)?;
                    }
                }
                Ok(v)
            }

            // -- Bindings --
            // bajo una etiqueta de PC toda asignación etiqueta el valor
            // ("no-sensitive-upgrade": asignar desde un contexto privado convierte la variable).
            // No-sensitive-upgrade ESTRICTO (B1): re-ligar bajo PC un nombre ya existente en
            // ESTE scope cuya etiqueta no cubre el PC es `label_violation` (un `let` nuevo o
            // que sombrea un scope exterior no revela nada: nace privado).
            // Excepción: si el lado derecho es SINTÁCTICAMENTE `declassify(...)` (resuelto
            // Al builtin), el valor queda con la etiqueta que `declassify` devolvió (su `to`)
            // Y NO se le une el PC: el programador declara en ese sitio auditado que ese valor
            // sale de ese contexto con esa etiqueta (`codeintel::declassify_sites` lo lista y
            // `declassify` registra el PC real en `from`).
            NodeKind::LetBinding { name, value, .. } => {
                let v = self.exec(value, env)?;
                let v = if self.labels && !self.is_declassify_call(value, env) {
                    self.let_nsu_check(env, name, loc)?;
                    self.pc_mark(v, loc)?
                } else {
                    v
                };
                env_set(env, name, v.clone());
                Ok(v)
            }
            NodeKind::SetMutation { target, value } => {
                // `set P to append(P, v)`, `P + [...]`, `insert(P, i, v)` y `merge(P, m)` en el
                // lugar (v0.6.29), con P una variable o un camino `x.campo[k]`: con semántica de
                // valor el resultado es el mismo, pero si nadie más comparte el contenedor no
                // hace falta copiarlo: el idioma documentado pasa a ser O(1) por vuelta.
                if !self.labels || self.pc_is_empty() {
                    if let Some(v) = self.try_update_in_place(target, value, env)? {
                        return Ok(v);
                    }
                }
                let v = self.exec(value, env)?;
                let escape_pc = self.labels && self.is_declassify_call(value, env);
                let v = if self.labels && !escape_pc { self.pc_mark(v, loc)? } else { v };
                self.exec_set(target, v, env, loc, escape_pc)
            }

            // -- Control de flujo --
            NodeKind::WhenStatement { condition, body, otherwise, otherwise_when } => {
                let cond = self.exec(condition, env)?;
                // Condición privada (a cualquier profundidad, B3) → toda la cadena
                // when/otherwise corre bajo su etiqueta de PC (flujo implícito); se saca al
                // salir, también en error. El valor IMPLÍCITO de la cadena sale con el PC (B2).
                if self.labels {
                    let l = labels::label_deep(&cond);
                    if !l.is_empty() {
                        // B1 (ronda 3): si alguna rama puede salir antes de tiempo, la
                        // continuación queda teñida ACÁ, se tome o no la rama.
                        if when_exits_early(body, otherwise, otherwise_when) {
                            let escapes = when_exits_task(body, otherwise, otherwise_when);
                            self.taint_branch(&l, escapes);
                        }
                        self.pc_push(&l);
                    }
                    let r = self.exec_when_branches(cond.is_truthy(), body, otherwise_when, otherwise, env);
                    let r = r.and_then(|v| self.pc_mark(v, loc));
                    if !l.is_empty() {
                        self.pc_pop();
                    }
                    return r;
                }
                self.exec_when_branches(cond.is_truthy(), body, otherwise_when, otherwise, env)
            }
            NodeKind::EachStatement { variable, collection, body } => {
                let coll = self.exec(collection, env)?;
                // Colección con etiquetas (a cualquier profundidad, B3) → cada item sale
                // con esa etiqueta y el cuerpo corre bajo ese PC; el valor implícito también.
                let mut each_label: Option<Label> = None;
                let coll = if self.labels {
                    let l = labels::label_deep(&coll);
                    if !l.is_empty() {
                        each_label = Some(l);
                    }
                    labels::unwrap(&coll).clone()
                } else {
                    coll
                };
                // v0.6.29: un mapa se recorre por sus claves y un texto por sus caracteres
                // (como Python); bytes, por sus valores 0..=255.
                let items = match &coll {
                    SynValue::List(l) => l.borrow().clone(),
                    SynValue::Map(m) => m.borrow().keys().map(|k| syn_text(k.as_str())).collect(),
                    SynValue::Text(t) => t.chars().map(|c| syn_text(c.to_string())).collect(),
                    SynValue::Bytes(b) => b.iter().map(|x| syn_int(*x as i64)).collect(),
                    _ => {
                        return Err(err_at(
                            format!(
                                "Cannot iterate over {} — each walks a list, the keys of a map, the characters of a text or the values of bytes",
                                coll.type_name()
                            ),
                            loc,
                        ))
                    }
                };
                // T5 (ronda 5): el frame de bucle se abre ANTES de teñir, porque un `stop` del
                // cuerpo cae en ESTE bucle y su tinta tiene que morir con él.
                let saved_loop = self.enter_loop();
                if let Some(l) = &each_label {
                    if block_exits_early(body) {
                        let escapes = block_exits_task(body);
                        let l = l.clone();
                        self.taint_branch(&l, escapes);
                    }
                    self.pc_push(l);
                }
                let mut result = SynValue::Nothing;
                let mut outcome: Result<(), Control> = Ok(());
                for item in items {
                    let loop_env = Environment::child(env, &format!("each:{}", variable));
                    // El item lleva la etiqueta de DATOS de la colección (no la de PC, que
                    // desde la regla 2 no envuelve contenedores): un mapa dentro de una lista
                    // privada tiene que salir privado, y compartir el `Rc` es correcto acá —
                    // El elemento vive DENTRO del contenedor privado, no hay alias público.
                    let item = match &each_label {
                        Some(l) => labels::mark(item, l.clone()),
                        None => item,
                    };
                    let item = match self.pc_mark(item, loc) {
                        Ok(v) => v,
                        Err(e) => {
                            outcome = Err(e);
                            break;
                        }
                    };
                    env_set(&loop_env, variable, item);
                    // Ver `exec_block`: el valor de la vuelta anterior no debe seguir vivo.
                    drop(std::mem::replace(&mut result, SynValue::Nothing));
                    match self.exec_block(body, &loop_env).and_then(|v| self.pc_mark(v, loc)) {
                        Ok(v) => result = v,
                        Err(Control::Stop(_)) => break,
                        Err(other) => {
                            outcome = Err(other);
                            break;
                        }
                    }
                }
                if each_label.is_some() {
                    self.pc_pop();
                }
                self.exit_loop(saved_loop);
                outcome?;
                Ok(result)
            }
            NodeKind::WhileStatement { condition, body } => {
                // Sin tope de iteraciones (v0.6.29): un bucle de eventos `while true` vive lo
                // que viva el programa. Para acotarlo están `stop`, `timeout` y `agent_stop`.
                let mut result = SynValue::Nothing;
                // T5 (ronda 5): igual que `each` — la tinta de un `stop` del cuerpo muere acá.
                // Por eso el cuerpo ya no puede salir con `return`: el frame quedaría abierto.
                let saved_loop = self.enter_loop();
                let mut outcome: Result<(), Control> = Ok(());
                loop {
                    let cond = match self.exec(condition, env) {
                        Ok(v) => v,
                        Err(e) => {
                            outcome = Err(e);
                            break;
                        }
                    };
                    if !cond.is_truthy() {
                        break;
                    }
                    // Condición con etiquetas (profundo, B3) → el cuerpo de ESTA
                    // iteración y su valor implícito (B2) van bajo PC.
                    let pushed = if self.labels {
                        let l = labels::label_deep(&cond);
                        if l.is_empty() {
                            false
                        } else {
                            if block_exits_early(body) {
                                let escapes = block_exits_task(body);
                                self.taint_branch(&l, escapes);
                            }
                            self.pc_push(&l);
                            true
                        }
                    } else {
                        false
                    };
                    drop(std::mem::replace(&mut result, SynValue::Nothing));
                    let r = self.exec_block(body, env);
                    let r = if self.labels { r.and_then(|v| self.pc_mark(v, loc)) } else { r };
                    if pushed {
                        self.pc_pop();
                    }
                    match r {
                        Ok(v) => result = v,
                        Err(Control::Stop(_)) => break,
                        Err(other) => {
                            outcome = Err(other);
                            break;
                        }
                    }
                }
                self.exit_loop(saved_loop);
                outcome?;
                Ok(result)
            }
            NodeKind::MatchStatement { value, arms, otherwise } => {
                let v = self.exec(value, env)?;
                // T5 (B3): sujeto con etiquetas a cualquier profundidad → se matchea la
                // superficie desenvuelta bajo PC = label_deep(sujeto); los patrones y guards
                // privados suman lo suyo dentro de `exec_match_arms`; binders y valor
                // implícito salen etiquetados.
                if self.labels {
                    let l = labels::label_deep(&v);
                    let inner = labels::unwrap(&v).clone();
                    if !l.is_empty() {
                        if match_exits_early(arms, otherwise) {
                            let escapes = match_exits_task(arms, otherwise);
                            self.taint_branch(&l, escapes);
                        }
                        self.pc_push(&l);
                    }
                    let r = self.exec_match_arms(inner, arms, otherwise, env, loc, &l);
                    if !l.is_empty() {
                        self.pc_pop();
                    }
                    return r;
                }
                let no_label = self.no_label.clone();
                self.exec_match_arms(v, arms, otherwise, env, loc, &no_label)
            }
            NodeKind::StopStatement { value } => {
                let v = match value {
                    Some(n) => Some(self.exec(n, env)?),
                    None => None,
                };
                // T5 (regla 1.b): cortar el bucle desde un contexto privado tiñe lo que sigue
                // — el número de vueltas que alcanzó a dar (y lo que las vueltas previas
                // escribieron en variables públicas) es información privada que se lee después
                // del bucle (caso 1.c). El alcance llega hasta el borde de la task.
                self.taint_after_stop();
                Err(Control::Stop(v))
            }

            // -- Tasks --
            NodeKind::TaskDefinition { name, parameters, body, .. } => {
                let mut required_caps = Vec::new();
                let mut clean_body = Vec::new();
                for stmt in body {
                    if let NodeKind::RequireStatement { capability, scope } = &stmt.kind {
                        let scope_val = match scope {
                            Some(s) => Some(self.exec(s, env)?.to_string()),
                            None => None,
                        };
                        required_caps.push((capability.clone(), scope_val));
                    } else {
                        clean_body.push(stmt.clone());
                    }
                }
                let task = Rc::new(SynTaskValue {
                    name: name.clone(),
                    parameters: parameters.clone(),
                    body: clean_body,
                    closure_env: env.clone(),
                    origin: Some(loc.clone()),
                    required_capabilities: required_caps,
                });
                let value = SynValue::Task(task);
                // Definir una task bajo PC es una asignación más (NSU estricto + el
                // callable sale etiquetado: QUÉ task quedó definida depende de la rama).
                let value = if self.labels {
                    self.let_nsu_check(env, name, loc)?;
                    self.pc_mark(value, loc)?
                } else {
                    value
                };
                env_set(env, name, value.clone());
                Ok(value)
            }
            NodeKind::TaskCall { name, arguments } => {
                let func = self.exec(name, env)?;
                // T5 (B8): `private(…)`/`declassify(…)`/`label_of(…)`/`is_private(…)`/`print(…)`
                // tienen que resolver al builtin de verdad. Cubre los caminos dinámicos que el
                // chequeo estático no ve (un parámetro con ese nombre, un alias de módulo).
                if let Some(id) = name.as_identifier() {
                    if PROTECTED_BUILTIN_NAMES.contains(&id) {
                        check_protected_callee(id, &func, loc)?;
                    }
                }
                // Evaluá cada arg preservando su `name` (named vs posicional).
                let mut args = Vec::with_capacity(arguments.len());
                for arg in arguments {
                    let val = self.exec(&arg.value, env)?;
                    args.push((arg.name.clone(), val));
                }
                // T5 (regla 3.a): que argumentos de ESTA llamada son literales escalares del
                // fuente. Lo leen `private`/`declassify` como primera linea de su cuerpo para
                // distinguir un principal/motivo escrito en el programa (texto fijo, aunque
                // bajo PC lleve la etiqueta del contexto) de uno computado con datos privados.
                // Se fija justo antes de despachar: los argumentos ya estan evaluados, asi que
                // nada puede pisarla en el medio.
                if self.labels {
                    let mut mask = 0u32;
                    for (i, arg) in arguments.iter().enumerate().take(32) {
                        if is_literal_expr(&arg.value) {
                            mask |= 1 << i;
                        }
                    }
                    self.arg_literals = mask;
                }
                check_call_arity(&func, &args, loc)?;
                self.call_value_named(func, args, loc)
            }
            NodeKind::LambdaExpression { parameters, body } => {
                // Una lambda es un task anónimo cuyo cuerpo es un `give <expr>`
                // implícito, que cierra sobre el entorno actual. Se reusa el
                // camino de llamada existente (entorno hijo → bind params →
                // exec body → catch Give). No se hace env_set: es anónima.
                // Las lambdas no tienen sintaxis de default (bounded): cada nombre de
                // param se mapea a `Param { default: None }`. SÍ aceptan llamadas con args
                // nombrados (tienen nombres de param).
                let lambda_params: Vec<Param> = parameters
                    .iter()
                    .map(|n| Param { name: n.clone(), default: None })
                    .collect();
                let task = Rc::new(SynTaskValue {
                    name: "<lambda>".to_string(),
                    parameters: lambda_params,
                    body: vec![Node::new(
                        loc.clone(),
                        NodeKind::GiveStatement { value: Some(body.clone()) },
                    )],
                    closure_env: env.clone(),
                    origin: Some(loc.clone()),
                    required_capabilities: Vec::new(),
                });
                Ok(SynValue::Task(task))
            }
            NodeKind::GiveStatement { value } => {
                let v = match value {
                    Some(n) => self.exec(n, env)?,
                    None => SynValue::Nothing,
                };
                // Un `give` desde un contexto privado devuelve un valor privado — salvo
                // `give declassify(...)` (misma excepción que `let`/`set`: la etiqueta la
                // fija ese sitio auditado).
                let escapes = self.labels && value.as_deref().is_some_and(|n| self.is_declassify_call(n, env));
                let out = if escapes { v } else { self.pc_mark(v, loc)? };
                // Un `give` bajo PC privado corta el bloque (y el bucle donde viva), así que
                // tiñe lo que sigue DENTRO de la task; el borde de llamada restaura la tinta
                // del llamador, que es lo que evita el PC residual sobre su código público.
                self.taint_after_give();
                Err(Control::Give(out))
            }

            // -- Módulos locales (use / export) --
            NodeKind::UseImport { path, alias } => {
                let module_map = self.load_module(path, &loc.file)?;
                env_set(env, alias, module_map.clone());
                Ok(module_map)
            }
            // `routes <name>`: grupo de rutas montable. Se ejecuta a un MAP PLANO
            // {"_routes_meta": [<method/path/params/requires_auth>...],
            //  "_route_handler_<i>": task} — cada handler-task cierra sobre ESTE env
            // (el module_env cuando el grupo vive en un módulo), así el snapshot de
            // serve lo trata como cualquier map de módulo (DE-032) y los cuerpos de
            // ruta llaman helpers privados del módulo por nombre simple.
            NodeKind::RoutesDeclaration { name, routes } => {
                let mut map = IndexMap::new();
                let mut meta: Vec<SynValue> = Vec::new();
                for (i, r) in routes.iter().enumerate() {
                    if let NodeKind::RouteDefinition {
                        method,
                        path,
                        param_names,
                        requires_auth,
                        streaming,
                        socket,
                        rate_limit,
                        timeout,
                        private,
                        body,
                    } = &r.kind
                    {
                        // v0.6.20 — `stream`/`socket` ya viajan por el grupo (clase en la meta);
                        // serve los monta como rutas directas.
                        // `rate_limit` y `timeout` por ruta viajan en la meta: se evalúan acá, una
                        // vez, con el env del módulo (misma regla que una ruta directa: la
                        // expresión se evalúa al arrancar), y serve los aplica al montar.
                        let mut route_limit: Option<SynValue> = None;
                        if let Some(rl) = rate_limit {
                            if let NodeKind::RateLimitClause { count, window, unlimited } = &rl.kind {
                                let cap: i64 = match count {
                                    Some(c) => match self.eval(c, env)? {
                                        SynValue::Number(Number::Int(i)) => i,
                                        SynValue::Number(Number::Float(f)) => f as i64,
                                        other => {
                                            return Err(err_at(
                                                format!("rate_limit count must be a number, got {}", other.type_name()),
                                                &r.location,
                                            ))
                                        }
                                    },
                                    None => 0,
                                };
                                let mut lm = IndexMap::new();
                                lm.insert("unlimited".to_string(), syn_bool(*unlimited));
                                lm.insert("count".to_string(), SynValue::Number(Number::Int(cap)));
                                lm.insert("window".to_string(), syn_text(window.as_str()));
                                route_limit = Some(syn_map(lm));
                            }
                        }
                        let mut route_timeout: Option<SynValue> = None;
                        if let Some(t) = timeout {
                            if let NodeKind::TimeoutClause { secs } = &t.kind {
                                route_timeout = Some(match secs {
                                    None => syn_text("none"),
                                    Some(e) => {
                                        let v = self.eval(e, env)?;
                                        let f = match &v {
                                            SynValue::Number(Number::Int(i)) => *i as f64,
                                            SynValue::Number(Number::Float(f)) => *f,
                                            _ => f64::NAN,
                                        };
                                        if !(f.is_finite() && f > 0.0) {
                                            return Err(err_at(
                                                format!("timeout must be a positive number of seconds (or `none`), got {}", v),
                                                &r.location,
                                            ));
                                        }
                                        SynValue::Number(Number::Float(f))
                                    }
                                });
                            }
                        }
                        let task = SynValue::Task(Rc::new(SynTaskValue {
                            name: format!("route {} {}", method, path),
                            parameters: Vec::new(),
                            body: body.clone(),
                            closure_env: env.clone(),
                            origin: Some(r.location.clone()),
                            required_capabilities: Vec::new(),
                        }));
                        map.insert(format!("_route_handler_{}", i), task);
                        let mut mm = IndexMap::new();
                        mm.insert("method".to_string(), syn_text(method.as_str()));
                        mm.insert("path".to_string(), syn_text(path.as_str()));
                        mm.insert("requires_auth".to_string(), syn_bool(*requires_auth));
                        // v0.6.20 — `private` (fuera de los documentos generados) y la clase de
                        // ruta (`stream`/`socket`) viajan en la meta para que serve las monte
                        // exactamente como una ruta directa.
                        mm.insert("private".to_string(), syn_bool(*private));
                        mm.insert("streaming".to_string(), syn_bool(*streaming));
                        mm.insert("socket".to_string(), syn_bool(*socket));
                        mm.insert(
                            "params".to_string(),
                            syn_list(param_names.iter().map(|p| syn_text(p.as_str())).collect()),
                        );
                        if let Some(l) = route_limit {
                            mm.insert("rate_limit".to_string(), l);
                        }
                        if let Some(t) = route_timeout {
                            mm.insert("timeout".to_string(), t);
                        }
                        meta.push(syn_map(mm));
                    }
                }
                map.insert("_routes_meta".to_string(), syn_list(meta));
                let value = syn_map(map);
                env_set(env, name, value.clone());
                Ok(value)
            }

            // Una cláusula `mount` suelta jamás se ejecuta sola: la consume el serve hook.
            NodeKind::MountClause { .. } => {
                Err(err_at("'mount' is only valid inside a serve block", loc))
            }

            NodeKind::ExportDeclaration { declaration } => {
                let value = self.exec(declaration, env)?;
                let name = match &declaration.kind {
                    NodeKind::TaskDefinition { name, .. }
                    | NodeKind::TypeDefinition { name, .. }
                    | NodeKind::LetBinding { name, .. }
                    | NodeKind::EnumDefinition { name, .. }
                    | NodeKind::RoutesDeclaration { name, .. } => name.clone(),
                    _ => {
                        return Err(err_at(
                            "export must wrap a task, type, let, enum, or routes",
                            loc,
                        ))
                    }
                };
                // Registra el nombre en la superficie pública del módulo actual. El
                // frame base (entrypoint) nunca se cosecha → allí es un no-op.
                if let Some(frame) = self.exports_collector.last_mut() {
                    frame.push(name);
                }
                Ok(value)
            }

            // -- Tipos --
            NodeKind::TypeDefinition { name, fields } => {
                let field_names: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();
                let count = field_names.len() as i32;
                let type_name = name.clone();
                let def_loc = loc.clone();
                let func: BuiltinFn = Rc::new(move |_i, args, _l| {
                    if args.len() != field_names.len() {
                        return Err(err_at(
                            format!(
                                "Type {} expects {} fields, got {}",
                                type_name,
                                field_names.len(),
                                args.len()
                            ),
                            &def_loc,
                        ));
                    }
                    let mut m = IndexMap::new();
                    for (n, v) in field_names.iter().zip(args.iter()) {
                        m.insert(n.clone(), v.clone());
                    }
                    Ok(syn_map(m))
                });
                env_set(
                    env,
                    name,
                    SynValue::Builtin(Rc::new(BuiltinTask {
                        name: name.clone(),
                        func,
                        param_count: count,
                        param_names: None,
                    })),
                );
                Ok(SynValue::Nothing)
            }

            NodeKind::EnumDefinition { name, variants } => {
                // Valor de variante = map etiquetado {"__variant": "Enum.var", <campos>};
                // tipo enum = map namespace {"__enum": "Enum", <var>: valor|ctor}. Sin
                // tipo de runtime nuevo: construcción = property-access + call.
                let mut namespace = IndexMap::new();
                namespace.insert("__enum".to_string(), syn_text(name.as_str()));
                for (variant_name, fields) in variants {
                    let qualified = format!("{}.{}", name, variant_name);
                    if fields.is_empty() {
                        // Variante nullary → un map etiquetado constante.
                        let mut m = IndexMap::new();
                        m.insert("__variant".to_string(), syn_text(qualified.as_str()));
                        namespace.insert(variant_name.clone(), syn_map(m));
                    } else {
                        // Variante con payload → constructor builtin de aridad EXACTA.
                        let field_names = fields.clone();
                        let count = field_names.len() as i32;
                        let q = qualified.clone();
                        let def_loc = loc.clone();
                        let func: BuiltinFn = Rc::new(move |_i, args, _l| {
                            if args.len() != field_names.len() {
                                return Err(err_at(
                                    format!(
                                        "variant {} expects {} fields, got {}",
                                        q,
                                        field_names.len(),
                                        args.len()
                                    ),
                                    &def_loc,
                                ));
                            }
                            let mut m = IndexMap::new();
                            m.insert("__variant".to_string(), syn_text(q.as_str()));
                            for (n, val) in field_names.iter().zip(args.iter()) {
                                m.insert(n.clone(), val.clone());
                            }
                            Ok(syn_map(m))
                        });
                        namespace.insert(
                            variant_name.clone(),
                            SynValue::Builtin(Rc::new(BuiltinTask {
                                name: qualified.clone(),
                                func,
                                param_count: count,
                                param_names: None,
                            })),
                        );
                    }
                }
                let value = syn_map(namespace);
                env_set(env, name, value.clone());
                Ok(value)
            }

            // -- Agentes (fallback in-process; sin swarm en capa 4) --
            NodeKind::AgentDefinition { name, body, .. } => {
                self.agent_definitions.insert(name.clone(), (body.clone(), env.clone()));
                let mut m = IndexMap::new();
                m.insert("name".to_string(), syn_text(name.as_str()));
                m.insert("state".to_string(), syn_text("defined"));
                let agent_data = syn_map(m);
                env_set(env, name, agent_data.clone());
                Ok(agent_data)
            }
            NodeKind::SpawnStatement { agent_name, arguments } => {
                let def = match self.agent_definitions.get(agent_name) {
                    Some(d) => (d.0.clone(), d.1.clone()),
                    None => {
                        // Error auto-diagnóstico (LLM-safe): decir qué agentes SÍ conoce este
                        // contexto. Lista con nombres → typo del usuario. Lista VACÍA con el
                        // agente definido en el programa → contexto de ejecución sin agentes
                        // (p.ej. un intérprete reusado que no los restauró) — señal de runtime,
                        // no del programa; ahorra ciclos de diagnóstico persiguiendo typos.
                        let known: Vec<&str> =
                            self.agent_definitions.keys().map(|s| s.as_str()).collect();
                        let detail = if known.is_empty() {
                            "no agents are defined in this execution context; if this agent IS \
                             defined at the top level of the program, this is a runtime context \
                             issue, not a problem in your code"
                                .to_string()
                        } else {
                            format!("agents defined in this context: {}", known.join(", "))
                        };
                        return Err(err_at(
                            format!("No agent defined with name '{}' ({})", agent_name, detail),
                            loc,
                        ));
                    }
                };
                let mut spawn_args = Vec::with_capacity(arguments.len());
                for (k, vn) in arguments {
                    spawn_args.push((k.clone(), self.exec(vn, env)?));
                }
                // T5 (B7): el agente corre en otro hilo/intérprete — sumidero.
                if self.labels {
                    let refs: Vec<&SynValue> = spawn_args.iter().map(|(_, v)| v).collect();
                    self.sink_check("spawn", &refs, loc)?;
                }
                match self.swarm_hooks.as_ref().map(|s| s.spawn.clone()) {
                    // Con swarm: el agente corre en su propio hilo (motor).
                    Some(spawn) => {
                        // Snapshot de globales del intérprete llamador: tareas, valores
                        // y módulos (excluye builtins). Viajan al intérprete del agente
                        // para que pueda llamar tasks del top-level sin HTTP.
                        let global_vals: Vec<(String, SynValue)> = {
                            let env = self.global_env.borrow();
                            env.bindings.iter()
                                .filter(|(_, v)| !matches!(v, SynValue::Builtin(_)))
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect()
                        };
                        // T1: el agente corre EN NOMBRE de quien pidió (la identidad viaja
                        // con el techo), no "como el agente".
                        let subject = SpawnSubject {
                            identity: self.request_identity.clone(),
                            spend_limits: self.request_spend_limits.clone(),
                        };
                        let id = spawn(agent_name, def.0, spawn_args, global_vals, subject)?;
                        Ok(syn_text(id))
                    }
                    // Sin swarm: ejecución in-process (bloqueante), fallback.
                    None => {
                        let agent_env = Environment::child(&def.1, &format!("agent:{}", agent_name));
                        for (k, v) in spawn_args {
                            env_set(&agent_env, &k, v);
                        }
                        // Namespace de memoria (DB-M1): dentro del cuerpo, el agente ES
                        // el contexto (remember → source = agent_name). Pop garantizado
                        // aunque el cuerpo falle.
                        self.agent_context.push(agent_name.clone());
                        let r = self.exec_block(&def.0, &agent_env);
                        self.agent_context.pop();
                        r?;
                        Ok(syn_text(format!("agent:{}", agent_name)))
                    }
                }
            }

            // -- Blackboard --
            NodeKind::ShareStatement { value, key } => {
                let v = self.exec(value, env)?;
                let kv = self.exec(key, env)?;
                // T5 (B7): el blackboard es un sumidero (otros agentes lo leen).
                if self.labels {
                    self.sink_check("share", &[&v, &kv], loc)?;
                }
                let k = kv.to_string();
                match self.swarm_hooks.as_ref().map(|s| s.share.clone()) {
                    Some(h) => h(&k, &v),
                    None => {
                        self.blackboard.insert(k, v.clone());
                    }
                }
                Ok(v)
            }
            NodeKind::ObserveStatement { key, variable } => {
                let k = self.exec(key, env)?.to_string();
                let val = match self.swarm_hooks.as_ref().map(|s| s.observe.clone()) {
                    Some(h) => h(&k),
                    None => self.blackboard.get(&k).cloned(),
                };
                match val {
                    Some(v) => {
                        env_set(env, variable, v.clone());
                        Ok(v)
                    }
                    None => {
                        env_set(env, variable, SynValue::Nothing);
                        Ok(SynValue::Nothing)
                    }
                }
            }
            NodeKind::SignalStatement { name, data } => {
                // El nombre del canal es una expresión (Batch 6): evaluar a texto.
                let nv = self.exec(name, env)?;
                let d = match data {
                    Some(d) => Some(self.exec(d, env)?),
                    None => None,
                };
                // T5 (B7): la señal sale a otros agentes — sumidero.
                if self.labels {
                    let mut refs: Vec<&SynValue> = vec![&nv];
                    if let Some(dv) = &d {
                        refs.push(dv);
                    }
                    self.sink_check("signal", &refs, loc)?;
                }
                let n = raw_str(&nv);
                if let Some(h) = self.swarm_hooks.as_ref().map(|s| s.signal.clone()) {
                    h(&n, d);
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::WaitForStatement { signal_name, variable, timeout } => {
                let n = raw_str(&self.exec(signal_name, env)?);
                // Timeout opcional (Batch 7): segundos como número (no-número → error claro);
                // clamp a [0, 3600] como `sleep`. `None` = default (30 s) en el hook.
                let secs: Option<f64> = match timeout {
                    Some(t) => match self.exec(t, env)? {
                        SynValue::Number(num) => Some(num.to_f64().clamp(0.0, 3600.0)),
                        _ => {
                            return Err(err_at(
                                "wait_for timeout must be a number of seconds",
                                loc,
                            ))
                        }
                    },
                    None => None,
                };
                let cancel = self.cancel.flag.clone();
                let result = match self.swarm_hooks.as_ref().map(|s| s.wait_for.clone()) {
                    Some(h) => h(&n, secs, &cancel),
                    None => None,
                };
                self.check_cancel()?;
                match result {
                    Some(v) => {
                        if let Some(var) = variable {
                            env_set(env, var, v.clone());
                        }
                        Ok(v)
                    }
                    None => {
                        if let Some(var) = variable {
                            env_set(env, var, SynValue::Nothing);
                        }
                        Ok(SynValue::Nothing)
                    }
                }
            }

            // -- Capacidades --
            NodeKind::RequireStatement { capability, scope } => {
                // El scope se evalúa a su str (igual que el oráculo: str(eval(scope))).
                let scope_val = match scope {
                    Some(s) => Some(self.exec(s, env)?.to_string()),
                    None => None,
                };
                // Dentro de un `sandbox` o del cuerpo de una tool (`call_tool`) NO se
                // conceden capabilities: un `require` ahí es no-op. Si no, se podría
                // re-grantear para escapar del aislamiento / del least-privilege por-tool
                // (un `require` anidado bajo when/if no se extrae a required_capabilities,
                // así que llega acá en runtime).
                if !self.in_sandbox() && !self.in_tool_scope() {
                    if let Some(hook) = self.grant_hook.clone() {
                        // Ubicación del `require` para el audit (`file`/`line` de un
                        // grant rechazado por el techo). Sólo si hay sink instalado.
                        let prev = if crate::audit_loc::enabled() {
                            Some(crate::audit_loc::replace(Some(loc.clone())))
                        } else {
                            None
                        };
                        hook(capability, scope_val.as_deref());
                        if let Some(p) = prev {
                            crate::audit_loc::replace(p);
                        }
                    }
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::SandboxBlock { body, under: None } => {
                // Aislamiento real: durante el cuerpo, todas las capabilities quedan
                // DENEGADAS (el hook vacía el CapabilitySet; `require` es no-op). Se
                // restaura al salir, también en el camino de error. El `print` no está
                // gateado, así que el sandbox puede computar y devolver un valor.
                let sandbox_env = Environment::child(env, "sandbox");
                self.sandbox_depth += 1;
                if let Some(hook) = self.sandbox_hook.clone() {
                    hook(true);
                }
                let result = self.exec_block(body, &sandbox_env);
                if let Some(hook) = self.sandbox_hook.clone() {
                    hook(false);
                }
                self.sandbox_depth -= 1;
                result
            }
            NodeKind::SandboxBlock { body, under: Some(caps_expr) } => {
                // `sandbox under <caps>` (T1 del spec de identidad): el cuerpo corre bajo un
                // TECHO delegado = caps ∩ lo vigente. No vacía nada: lo que el bloque no lista
                // se deniega, lo que lista sigue gateado por los grants del programa y por los
                // techos de arriba (host, token de la request). `caps` es el map que devolvió
                // `captoken_verify` (el bloque queda bajo ESE token) o un map literal de mínimo
                // privilegio. `require` adentro sigue siendo no-op (mismo `sandbox_depth`).
                let caps_val = self.exec(caps_expr, env)?;
                let Some(hook) = self.ceiling_hook.clone() else {
                    return Err(Control::Error(RuntimeError::at(
                        "`sandbox under` needs a host that installs capability ceilings; this host does not (run the program with the synsema binary or a wasm host with capabilities)",
                        loc.clone(),
                    )));
                };
                hook(Some(&caps_val)).map_err(|m| Control::Error(RuntimeError::at(m, loc.clone())))?;
                let sandbox_env = Environment::child(env, "sandbox");
                self.sandbox_depth += 1;
                let result = self.exec_block(body, &sandbox_env);
                // Se desapila también en el camino de error: un techo de bloque jamás
                // sobrevive al bloque.
                let _ = hook(None);
                self.sandbox_depth -= 1;
                result
            }
            NodeKind::InvariantDeclaration { condition, description } => {
                let result = self.exec(condition, env)?;
                // T5 (M1): el veredicto de un invariante sobre datos privados es un uso de
                // privados: el error que produzca sale redactado hacia el host.
                if self.labels {
                    let l = labels::label_deep(&result);
                    if !l.is_empty() {
                        self.note_seen(&l);
                    }
                }
                if !result.is_truthy() {
                    let desc = description.clone().unwrap_or_else(|| "unnamed invariant".to_string());
                    return Err(err_at(format!("Invariant violation: {}", desc), loc));
                }
                Ok(syn_bool(true))
            }
            NodeKind::IntentDeclaration { description } => {
                if self.intent_frozen {
                    return Err(err_at(
                        "Cannot declare a new intent after execution has started. \
Intent is frozen to prevent prompt injection from expanding the mandate.",
                        loc,
                    ));
                }
                self.intent = Some(description.clone());
                Ok(SynValue::Nothing)
            }

            // -- Interacción humana (no-interactiva → auto) --
            // T5 (B7): el mensaje a un humano sale del intérprete — sumidero.
            NodeKind::ApproveStatement { message, timeout, .. } => {
                let m = self.exec(message, env)?;
                if self.labels {
                    self.sink_check("approve", &[&m], loc)?;
                }
                match self.human_callback.clone() {
                    Some(cb) => Ok(cb("approve", &m.to_string(), *timeout)),
                    None => Ok(syn_bool(true)),
                }
            }
            NodeKind::ConfirmStatement { message, timeout } => {
                let m = self.exec(message, env)?;
                if self.labels {
                    self.sink_check("confirm", &[&m], loc)?;
                }
                match self.human_callback.clone() {
                    Some(cb) => Ok(cb("confirm", &m.to_string(), *timeout)),
                    None => Ok(syn_bool(true)),
                }
            }
            NodeKind::ShowStatement { value, label } => {
                let v = self.exec(value, env)?;
                self.ensure_stdout()?;
                // T5 (ronda 4): la misma boca pública que `print` — ver `stdout_flow_check`.
                self.stdout_flow_check("show", loc)?;
                let label_str = match label {
                    Some(l) => format!("[{}] ", l),
                    None => String::new(),
                };
                // Un valor privado se redacta por Display; bajo PC se redacta la línea.
                let line = format!("{}{}", label_str, self.pc_redact(v.to_string()));
                // DE-034: espejo de `log`/`print` — si hay log_hook (p.ej. bajo serve),
                // emitir en vivo además de bufferizar a `output`. Bajo `run` el hook es
                // none, así que el comportamiento no cambia.
                self.emit_line(line);
                Ok(v)
            }
            NodeKind::AskExpression { prompt, options, timeout } => {
                let p = self.exec(prompt, env)?;
                if self.labels {
                    self.sink_check("ask", &[&p], loc)?;
                }
                if let Some(cb) = self.human_callback.clone() {
                    let r = cb("ask", &p.to_string(), *timeout);
                    if r.is_truthy() {
                        return Ok(syn_text(r.to_string()));
                    }
                }
                // Fallback no-interactivo: primera opción si hay lista.
                if let Some(opts) = options {
                    let o = self.exec(opts, env)?;
                    if let SynValue::List(l) = &o {
                        if let Some(first) = l.borrow().first() {
                            return Ok(first.clone());
                        }
                    }
                }
                Ok(syn_text(""))
            }

            // -- LLM (sin callback → placeholders) --
            NodeKind::ReasonExpression { subject, context, .. } => {
                self.check_llm_cap()?;
                let subj = match subject {
                    Some(s) => self.exec(s, env)?,
                    None => SynValue::Nothing,
                };
                // Evaluá el contexto (`with k=v`/`given …`) y armalo para el prompt — el
                // LLM necesita ver ese contexto, no sólo el subject.
                let mut ctx_vals = Vec::with_capacity(context.len());
                for (name, v) in context {
                    ctx_vals.push((name, self.exec(v, env)?));
                }
                // T5 (B7): el prompt va al proveedor LLM — sumidero.
                if self.labels {
                    let mut refs: Vec<&SynValue> = vec![&subj];
                    refs.extend(ctx_vals.iter().map(|(_, v)| v));
                    self.sink_check("reason", &refs, loc)?;
                }
                let ctx_parts: Vec<String> =
                    ctx_vals.iter().map(|(name, v)| format!("{}={}", name, v)).collect();
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let prompt = if ctx_parts.is_empty() {
                            subj.to_string()
                        } else {
                            format!("Reason about: {} (context: {})", subj, ctx_parts.join(", "))
                        };
                        { let out = cb("reason", &prompt); self.record_llm("reason", &prompt, &out); Ok(syn_text(out)) }
                    }
                    None => {
                        note_llm_offline();
                        Ok(syn_text(format!("[reasoning about: {}]", subj)))
                    }
                }
            }
            NodeKind::DecideExpression { options, given, .. } => {
                self.check_llm_cap()?;
                let opts = match options {
                    Some(o) => self.exec(o, env)?,
                    None => SynValue::Nothing,
                };
                let giv = match given {
                    Some(g) => self.exec(g, env)?,
                    None => SynValue::Nothing,
                };
                // T5 (B7): el prompt va al proveedor LLM — sumidero.
                if self.labels {
                    self.sink_check("decide", &[&opts, &giv], loc)?;
                }
                // v0.6.26 — `SYNSEMA_JUDGE_DECIDE`: el juez contesta con una de TUS opciones,
                // calibrado y sin normalización ni reintento. Si no aplica o no está disponible,
                // sigue el camino LLM de siempre.
                if self.decide_via_judge {
                    if let Some(chosen) = self.decide_with_judge(&opts, &giv, loc)? {
                        return Ok(chosen);
                    }
                }
                let prompt = format!("Decide between {} given {}", opts, giv);
                // Camino dedicado (DE-039): las opciones viajan ESTRUCTURADAS al motor,
                // que fuerza la elección por tool/enum + normaliza + reintenta. Sólo si
                // el motor lo cableó; si no, el callback de texto genérico de siempre.
                if let Some(cb) = self.llm_decide_callback.clone() {
                    let opt_list: Vec<String> = match &opts {
                        SynValue::List(l) => l.borrow().iter().map(|v| v.to_string()).collect(),
                        _ => Vec::new(),
                    };
                    return Ok(syn_text(cb(&prompt, &opt_list)));
                }
                match self.llm_callback.clone() {
                    Some(cb) => { let out = cb("decide", &prompt); self.record_llm("decide", &prompt, &out); Ok(syn_text(out)) },
                    None => {
                        note_llm_offline();
                        Ok(syn_text("[decision pending]"))
                    }
                }
            }
            NodeKind::JudgeExpression { state, questions } => {
                use crate::judge::{
                    answer_to_value, is_valid_state, options_from_value, syn_to_json,
                    validate_question, JudgeQuestion, JudgeRequest,
                };
                self.check_judge_cap()?;
                let st = self.exec(state, env)?;
                if !is_valid_state(&st) {
                    return Err(err_at(
                        format!(
                            "judge: the state must be a text, a map or a list (got {}); the model reads \
                             text, so wrap it with text() if you mean its rendering",
                            st.type_name()
                        ),
                        loc,
                    ));
                }
                let mut qs: Vec<JudgeQuestion> = Vec::with_capacity(questions.len());
                let mut crossing: Vec<SynValue> = vec![st.clone()];
                for qn in questions {
                    let instr = self.exec(&qn.instruction, env)?;
                    let options = match &qn.criteria {
                        Some(c) => {
                            let cv = self.exec(c, env)?;
                            options_from_value(&cv)
                                .map_err(|m| err_at(format!("judge '{}': {}", qn.id, m), &qn.loc))?
                        }
                        None => Vec::new(),
                    };
                    let q = JudgeQuestion {
                        id: qn.id.clone(),
                        kind: qn.kind,
                        instruction: syn_to_json(&instr),
                        options,
                        escape: qn.escape,
                        yes_no: None,
                    };
                    validate_question(&q).map_err(|m| err_at(m, &qn.loc))?;
                    // Rutas con backticks que no existen en el state (ni en la instrucción):
                    // aviso una vez por ruta antes de gastar la llamada. Un SDK no puede; el
                    // runtime tiene el valor en la mano.
                    for path in crate::judge::missing_paths(&st, &instr) {
                        // La trampa más común: `judge ticket` con `` `ticket.x` `` en la
                        // pregunta. El modelo ve el VALOR, no el nombre de la variable.
                        let var_hint = match &state.kind {
                            NodeKind::Identifier { name }
                                if path == *name || path.starts_with(&format!("{}.", name)) || path.starts_with(&format!("{}[", name)) =>
                            {
                                Some(name.as_str())
                            }
                            _ => None,
                        };
                        note_judge_missing_path(&qn.id, &path, var_hint, &qn.loc);
                    }
                    crossing.push(instr);
                    qs.push(q);
                }
                // T5: el `state` y las instrucciones cruzan a un tercero — sumidero declarado,
                // igual que `decide`. La respuesta al borde filoso nº 6 del vendor: el contenido
                // adversario entra como dato y el motor sabe que ese dato salió del proceso.
                if self.labels {
                    let refs: Vec<&SynValue> = crossing.iter().collect();
                    self.sink_check("judge", &refs, loc)?;
                }
                let req = JudgeRequest {
                    state: syn_to_json(&st),
                    questions: qs,
                };
                let response = match self.judge_callback.clone() {
                    Some(cb) => cb(&req).map_err(|m| err_at(m, loc))?,
                    None => {
                        note_judge_offline();
                        None
                    }
                };
                // Map plano id → respuesta, en el orden del bloque. Sin metadatos mezclados:
                // una pregunta llamada `usage` no colisiona con nada.
                let mut out: IndexMap<String, SynValue> = IndexMap::new();
                for (i, q) in req.questions.iter().enumerate() {
                    let a = response.as_ref().and_then(|r| r.answers.get(i));
                    out.insert(q.id.clone(), answer_to_value(q, a));
                }
                Ok(syn_map(out))
            }
            NodeKind::AnalyzeExpression { data, objective } => {
                self.check_llm_cap()?;
                let d = self.exec(data, env)?;
                // T5 (B7): el prompt va al proveedor LLM — sumidero.
                if self.labels {
                    self.sink_check("analyze", &[&d], loc)?;
                }
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let prompt = format!("Analyze for {}: {}", objective, d);
                        { let out = cb("analyze", &prompt); self.record_llm("analyze", &prompt, &out); Ok(syn_text(out)) }
                    }
                    None => {
                        note_llm_offline();
                        Ok(syn_text(format!("[analysis of: {}]", objective)))
                    }
                }
            }
            NodeKind::GenerateExpression { target, given, parameters } => {
                self.check_llm_cap()?;
                // Evaluá given/parameters y armalos para el prompt (el LLM los necesita,
                // no sólo el target).
                let giv = match given {
                    Some(g) => Some(self.exec(g, env)?),
                    None => None,
                };
                let mut param_vals = Vec::with_capacity(parameters.len());
                for (name, v) in parameters {
                    param_vals.push((name, self.exec(v, env)?));
                }
                // T5 (B7): el prompt va al proveedor LLM — sumidero.
                if self.labels {
                    let mut refs: Vec<&SynValue> = Vec::new();
                    if let Some(g) = &giv {
                        refs.push(g);
                    }
                    refs.extend(param_vals.iter().map(|(_, v)| v));
                    self.sink_check("generate", &refs, loc)?;
                }
                let param_parts: Vec<String> =
                    param_vals.iter().map(|(name, v)| format!("{}={}", name, v)).collect();
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let mut prompt = format!("Generate {}", target);
                        if let Some(g) = &giv {
                            prompt.push_str(&format!(" given {}", g));
                        }
                        if !param_parts.is_empty() {
                            prompt.push_str(&format!(" with {}", param_parts.join(", ")));
                        }
                        { let out = cb("generate", &prompt); self.record_llm("generate", &prompt, &out); Ok(syn_text(out)) }
                    }
                    None => {
                        note_llm_offline();
                        Ok(syn_text(format!("[generated: {}]", target)))
                    }
                }
            }

            // -- Observabilidad --
            NodeKind::TraceBlock { body, .. } => self.exec_block(body, env),
            NodeKind::LogStatement { message, .. } => {
                let m = self.exec(message, env)?;
                self.ensure_stdout()?;
                // T5 (ronda 4): la misma boca pública que `print` — ver `stdout_flow_check`.
                self.stdout_flow_check("log", loc)?;
                let line = format!("[LOG] {}", self.pc_redact(m.to_string()));
                self.emit_line(line);
                Ok(SynValue::Nothing)
            }
            NodeKind::MeasureBlock { body, .. } => self.exec_block(body, env),
            NodeKind::CheckpointStatement { name } => {
                self.exec(name, env)?; // evalúa la expresión (resuelve variables), descarta el valor
                Ok(SynValue::Nothing)
            }
            // G2: los bloques `test` NO corren en `synsema run` — no-op. Sólo
            // `Interpreter::run_test_blocks` (vía `synsema test`) ejecuta su cuerpo.
            NodeKind::TestBlock { .. } => Ok(SynValue::Nothing),

            // -- Errores --
            NodeKind::TryRecover { try_body, error_variable, recover_body } => {
                // El mensaje del error atrapado sale etiquetado con todo lo privado que
                // Se desenvolvió o gateó control DENTRO del `try` (aproximación conservadora:
                // Un "Index 9 out of bounds" con un índice privado no llega público a `e`).
                let r = self.exec_block(try_body, env);
                // `self.seen` está scopeado a ESTE nodo (lo limpia `exec`), así que acá tiene
                // exactamente lo privado que tocó el cuerpo del `try`.
                let try_seen = if self.labels { Some(self.seen.clone()) } else { None };
                match r {
                    Ok(v) => Ok(v),
                    Err(Control::Give(v)) => Err(Control::Give(v)),
                    Err(Control::Stop(v)) => Err(Control::Stop(v)),
                    // T5 (regla 1.a): un error nacido bajo PC privado, y el veredicto del
                    // propio enforcement, NO se atrapan — se propagan hasta el host (en el
                    // guest: request fallida con código uniforme, que T1 cubre). Atraparlos
                    // convertía el enforcement en el canal (1.a) y un `raise` dentro de la
                    // rama privada en un bit por iteración (1.b, 1.d).
                    Err(Control::Error(e)) if self.labels && e.is_fatal_for_labels() => {
                        Err(Control::Error(e))
                    }
                    Err(Control::Error(e)) => {
                        let msg = strip_loc_prefix(&e.to_string());
                        let recover_env = Environment::child(env, "recover");
                        let mut ev = syn_text(msg);
                        if let Some(l) = &try_seen {
                            ev = labels::mark(ev, l.clone());
                        }
                        let ev = self.pc_mark(ev, loc)?;
                        env_set(&recover_env, error_variable, ev);
                        // T5 (regla 1.c): que el cuerpo del `recover` CORRA es en sí mismo
                        // información sobre lo que pasó adentro del `try` — corre bajo
                        // PC ∪ etiqueta de lo privado que se tocó ahí dentro.
                        let pushed = match &try_seen {
                            Some(l) if self.labels && !l.is_empty() => {
                                self.pc_push(l);
                                true
                            }
                            _ => false,
                        };
                        let out = self.exec_block(recover_body, &recover_env);
                        let out = if self.labels { out.and_then(|v| self.pc_mark(v, loc)) } else { out };
                        if pushed {
                            self.pc_pop();
                        }
                        out
                    }
                }
            }

            // -- HTTP server (lo provee el motor vía serve_hook en capa 8) --
            NodeKind::ServeBlock { .. } => match self.serve_hook.clone() {
                Some(hook) => hook(self, node, env),
                None => Err(err_at("serve is only available through the Synsema engine runtime", loc)),
            },
            NodeKind::RateLimitClause { .. } => Ok(SynValue::Nothing),
            // El parser saca la cláusula del cuerpo de la route y del serve block;
            // ejecutarla es haberla escrito en otro lado (dentro de un `when`, de una
            // task, del top-level) — se dice, no se ignora en silencio.
            NodeKind::TimeoutClause { .. } => Err(err_at(
                "'timeout' is a clause of the serve block or of a route body (top level: `timeout 30` | `timeout none`), not a statement",
                loc,
            )),
            NodeKind::PrivateClause => Err(err_at(
                "'private' is a clause of the serve block, of a route body or of a 'routes' group (a line with just `private`), not a statement",
                loc,
            )),
            NodeKind::ProxyStatement { .. } => {
                Err(err_at("proxy is only available inside a serve route", loc))
            }
            NodeKind::StreamBlock { body } => self.exec_block(body, env),
            // El cuerpo de un `socket` lo corre el runtime de serve con el binding `socket`
            // ya adoptado; llegar acá es ejecutarlo fuera de una ruta.
            NodeKind::SocketBlock { .. } => Err(err_at(
                "socket is only available inside a serve route (route \"GET /path\" + socket block)",
                loc,
            )),
            NodeKind::SendStatement { value, event_name } => match self.stream_emit.clone() {
                Some(emit) => {
                    let v = self.exec(value, env)?;
                    // T5 (B7): el stream va al cliente — sumidero.
                    if self.labels {
                        self.sink_check("send", &[&v], loc)?;
                    }
                    emit(v, event_name.as_deref())?;
                    Ok(SynValue::Nothing)
                }
                None => Err(err_at("send can only be used inside a stream route handler", loc)),
            },
            NodeKind::ExpectStatement { shape, .. } => self.exec_expect(shape, env),

            // -- Sin executor en el oráculo (no alcanzables en programas válidos) --
            NodeKind::MatchArm { .. } => Err(err_at("No executor for node type: MatchArm", loc)),
            // Nodos de patrón: sólo válidos en posición de patrón (los consume
            // `match_pattern`), nunca se evalúan como expresión.
            NodeKind::WildcardPattern => {
                Err(err_at("No executor for node type: WildcardPattern", loc))
            }
            NodeKind::ListPattern { .. } => {
                Err(err_at("No executor for node type: ListPattern", loc))
            }
            NodeKind::MapPattern { .. } => {
                Err(err_at("No executor for node type: MapPattern", loc))
            }
            NodeKind::RouteDefinition { .. } => {
                Err(err_at("No executor for node type: RouteDefinition", loc))
            }
            NodeKind::StaticMount { .. } => {
                Err(err_at("No executor for node type: StaticMount", loc))
            }
            NodeKind::DescribeClause { .. } => {
                Err(err_at("No executor for node type: DescribeClause", loc))
            }
            NodeKind::HostBlock { .. } => {
                Err(err_at("No executor for node type: HostBlock", loc))
            }
            NodeKind::StateTransition { .. } => {
                Err(err_at("No executor for node type: StateTransition", loc))
            }
        }
    }

    /// Selección de rama de un `when` (cuerpo / `otherwise when` / `otherwise`).
    fn exec_when_branches(
        &mut self,
        truthy: bool,
        body: &[Node],
        otherwise_when: &Option<Box<Node>>,
        otherwise: &Option<Vec<Node>>,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<SynValue, Control> {
        if truthy {
            self.exec_block(body, env)
        } else if let Some(ow) = otherwise_when {
            self.exec(ow, env)
        } else if let Some(ob) = otherwise {
            self.exec_block(ob, env)
        } else {
            Ok(SynValue::Nothing)
        }
    }

    /// Los arms de un `match` sobre el valor ya evaluado (y desenvuelto en la superficie, T5).
    ///
    /// T5 (B3): la DECISIÓN de qué arm corre depende del sujeto (ya en PC, lo empuja el
    /// caller), de los valores de los patrones probados hasta acá (`pattern_label`, que suma
    /// `match_pattern*` al evaluar cada patrón de valor) y de los guards evaluados. Esa unión
    /// (`extra`) va al PC durante los binders, el guard y el cuerpo del arm tomado — y en el
    /// `otherwise` (no haber matcheado también es información). Binders y valor implícito
    /// salen etiquetados.
    #[allow(clippy::too_many_arguments)]
    fn exec_match_arms(
        &mut self,
        v: SynValue,
        arms: &[Node],
        otherwise: &Option<Vec<Node>>,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
        subject_label: &Label,
    ) -> Result<SynValue, Control> {
        let mut extra = labels::empty();
        for arm in arms {
            if let NodeKind::MatchArm { pattern, guard, body } = &arm.kind {
                // El patrón liga (en patrones estructurales/variantes) o compara
                // por valor (a nivel top, G2). `None` → no matchea, próximo arm.
                if self.labels {
                    self.pattern_label = labels::empty();
                }
                let binds = self.match_pattern_top(pattern, &v, env)?;
                if self.labels {
                    extra = labels::union(&extra, &self.pattern_label);
                }
                let binds = match binds {
                    Some(b) => b,
                    None => continue,
                };
                // Los binders viven en un Environment HIJO scopeado al arm; el
                // guard se evalúa con ellos en scope. bajo PC salen etiquetados.
                let arm_env = Environment::child(env, "match-arm");
                let pushed = self.labels && !extra.is_empty();
                if pushed {
                    self.pc_push(&extra);
                }
                let prep: Result<Option<SynValue>, Control> = (|| {
                    for (name, val) in binds {
                        // El binder sale con la etiqueta de DATOS del sujeto (el PC no
                        // envuelve contenedores: un submapa ligado por el patrón tiene que
                        // salir privado igual).
                        let val = labels::mark(val, subject_label.clone());
                        let val = self.pc_mark(val, loc)?;
                        env_set(&arm_env, &name, val);
                    }
                    match guard {
                        Some(g) => self.exec(g, &arm_env).map(Some),
                        None => Ok(None),
                    }
                })();
                if pushed {
                    self.pc_pop();
                }
                let guard_val = prep?;
                if let Some(gv) = &guard_val {
                    if self.labels {
                        extra = labels::union(&extra, &labels::label_deep(gv));
                    }
                    if !gv.is_truthy() {
                        continue; // guard falso → próximo arm
                    }
                }
                let pushed = self.labels && !extra.is_empty();
                if pushed {
                    self.pc_push(&extra);
                }
                let r = self.exec_block(body, &arm_env);
                let r = if self.labels { r.and_then(|x| self.pc_mark(x, loc)) } else { r };
                if pushed {
                    self.pc_pop();
                }
                return r;
            }
        }
        // Ningún arm `is` matcheó: corré el bloque `otherwise` si existe.
        let pushed = self.labels && !extra.is_empty();
        if pushed {
            self.pc_push(&extra);
        }
        let r = match otherwise {
            Some(body) => self.exec_block(body, env),
            None => Ok(SynValue::Nothing),
        };
        let r = if self.labels { r.and_then(|x| self.pc_mark(x, loc)) } else { r };
        if pushed {
            self.pc_pop();
        }
        r
    }

    /// T5 (B3): anota la etiqueta profunda de un valor de PATRÓN que se comparó con el sujeto.
    #[inline]
    fn note_pattern(&mut self, p: &SynValue) {
        if self.labels {
            let l = labels::label_deep(p);
            if !l.is_empty() {
                self.pattern_label = labels::union(&self.pattern_label, &l);
                self.seen = labels::union(&self.seen, &l);
            }
        }
    }

    /// T5 (B1): `let`/`task` bajo PC sobre un nombre que YA existe en este scope: su etiqueta
    /// tiene que cubrir el PC (NSU estricto). Un nombre nuevo o de un scope exterior no revela
    /// nada (nace privado / se sombrea).
    fn let_nsu_check(&self, env: &Rc<RefCell<Environment>>, name: &str, loc: &SourceLocation) -> Result<(), Control> {
        if self.pc_is_empty() {
            return Ok(());
        }
        let existing = env.borrow().bindings.get(name).map(labels::label);
        match existing {
            Some(have) => self.nsu_check(&have, &format!("'{}'", name), loc),
            None => Ok(()),
        }
    }

    /// T5 (B8): ¿el nodo es SINTÁCTICAMENTE una llamada a `declassify(...)` Y el callee
    /// RESUELTO en este entorno es el builtin (no una task/lambda del programa)?
    fn is_declassify_call(&self, node: &Node, env: &Rc<RefCell<Environment>>) -> bool {
        match &node.kind {
            NodeKind::TaskCall { name, .. } if name.as_identifier() == Some("declassify") => {
                matches!(env_get(env, "declassify"), Some(SynValue::Builtin(bt)) if bt.name == "declassify")
            }
            _ => false,
        }
    }

    /// Operadores unarios sobre un valor ya evaluado (y desenvuelto, T5).
    fn exec_unary(&mut self, operator: &str, v: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
        match operator {
            "-" => match &v {
                SynValue::Number(n) => Ok(syn_number(n.neg())),
                SynValue::Complex(z) => Ok(SynValue::Complex(-z)),
                SynValue::Array(a) => Ok(crate::arrays::negate(a)),
                _ => Err(err_at(format!("Cannot negate {}", v.type_name()), loc)),
            },
            "not" => Ok(syn_bool(!v.is_truthy())),
            other => Err(err_at(format!("Unknown unary operator: {}", other), loc)),
        }
    }

    /// Re-envuelve `res` con la unión de las etiquetas PROFUNDAS de los operandos de un
    /// `and`/`or` (identidad si ninguno lleva etiquetas). Sólo con etiquetas encendidas.
    fn join_operands(
        &mut self,
        res: SynValue,
        a: &SynValue,
        b: Option<&SynValue>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let mut l = labels::label_deep(a);
        if let Some(b) = b {
            l = labels::union(&l, &labels::label_deep(b));
        }
        self.rewrap(res, l, loc)
    }

    /// Algún operando con etiquetas (a cualquier profundidad, B4: `{"k": private(1)} ==
    /// {"k": 1}` sale privado) → desenvolver la superficie, operar y re-envolver con la unión
    /// profunda. Vale para TODOS los operadores (aritmética, comparación, concat, bytes,
    /// Listas). Sin etiquetas → `exec_binary_plain` directo.
    fn exec_binary(
        &mut self,
        left: SynValue,
        op: &str,
        right: SynValue,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        if self.labels {
            let l = labels::union(&labels::label_deep(&left), &labels::label_deep(&right));
            if !l.is_empty() {
                self.note_seen(&l);
                let (li, ri) = (labels::unwrap(&left).clone(), labels::unwrap(&right).clone());
                let r = self.exec_binary_plain(li, op, ri, loc)?;
                return self.rewrap(r, l, loc);
            }
        }
        self.exec_binary_plain(left, op, right, loc)
    }

    fn exec_binary_plain(
        &mut self,
        left: SynValue,
        op: &str,
        right: SynValue,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        // Lógicos: el cortocircuito vive en `exec` (BinaryOp); acá sólo llega un
        // `and`/`or` ya evaluado por ambos lados (callers internos).
        if op == "and" {
            return Ok(syn_bool(left.is_truthy() && right.is_truthy()));
        }
        if op == "or" {
            return Ok(syn_bool(left.is_truthy() || right.is_truthy()));
        }
        // `x in xs` / `x not in xs` (v0.6.29): pertenencia en lista, clave de mapa,
        // subtexto o subsecuencia de bytes — la misma igualdad que `contains`.
        if op == "in" || op == "not in" {
            if let (SynValue::Text(_), other) = (&right, &left) {
                if !matches!(other, SynValue::Text(_)) {
                    return Err(err_at(
                        format!(
                            "`in` on text looks for a piece of text, got {} — convert it first: text(x) in s",
                            other.type_name()
                        ),
                        loc,
                    ));
                }
            }
            if !matches!(right, SynValue::List(_) | SynValue::Map(_) | SynValue::Text(_) | SynValue::Bytes(_)) {
                return Err(err_at(
                    format!("`in` needs a list, map, text or bytes on its right, got {}", right.type_name()),
                    loc,
                ));
            }
            // `1.5d in [1.5]` sería `false` en silencio: se compara elemento por elemento y, como
            // en `==`, comparar un decimal con un float es error. Sólo el par que se compara: en
            // `"a" in ["a", 1.5, 1d]` nunca se junta un decimal con un float.
            if let SynValue::List(items) = &right {
                let mut found = false;
                for x in items.borrow().iter() {
                    let eq = crate::tabular::strict_equals(&left, x)
                        .map_err(|_| err_at(format!("`{}`: {}", op, crate::number::MIX_DECIMAL_FLOAT), loc))?;
                    if eq {
                        found = true;
                        break;
                    }
                }
                return Ok(syn_bool(if op == "in" { found } else { !found }));
            }
            let found = self.b_contains(&[right, left], loc)?.is_truthy();
            return Ok(syn_bool(if op == "in" { found } else { !found }));
        }
        // Hueco de un template con backticks: el texto de cualquier valor, como el f-string de
        // Python (`xs={xs}` → "xs=[1, 2]"). Un secret sigue por `+` (queda secret y redactado).
        let op = if op == crate::ast::INTERP_CONCAT {
            if let SynValue::Text(l) = &left {
                if !matches!(right, SynValue::Text(_) | SynValue::Secret(_)) {
                    return Ok(syn_text(format!("{}{}", l, right)));
                }
            }
            "+"
        } else {
            op
        };
        // Concatenación de texto: un operando texto coerciona al otro si es un escalar
        // (número, bool). `nothing`, listas, mapas y bytes son error (v0.6.29): pegarlos
        // en silencio daba "xnothing" o un repr que nadie quería.
        if op == "+" {
            if matches!(left, SynValue::Text(_)) != matches!(right, SynValue::Text(_)) {
                let other = if matches!(left, SynValue::Text(_)) { &right } else { &left };
                if matches!(
                    other,
                    SynValue::Nothing
                        | SynValue::List(_)
                        | SynValue::Map(_)
                        | SynValue::Bytes(_)
                        | SynValue::Task(_)
                        | SynValue::Builtin(_)
                ) {
                    return Err(err_at(
                        format!(
                            "Cannot add text and {} — convert it on purpose: text(x), or interpolate it: `...{{x}}`{}",
                            other.type_name(),
                            if matches!(other, SynValue::Bytes(_)) { " (for bytes: hex(b) or decode(b, \"utf8\"))" } else { "" }
                        ),
                        loc,
                    ));
                }
            }
            // Propagación de taint (#10): si algún operando es `secret`, el resultado
            // es `secret` (sigue redactado). Esta es UNA comprobación de discriminante
            // que en código sin secretos es siempre falsa → rama no-tomada, coste
            // efectivo cero (§8: no es un taint pervasivo, es un check local en `+`).
            if left.is_secret() || right.is_secret() {
                return Ok(secret_concat(&left, &right));
            }
            if let SynValue::Text(l) = &left {
                return Ok(syn_text(format!("{}{}", l, right)));
            }
            if let SynValue::Text(r) = &right {
                return Ok(syn_text(format!("{}{}", left, r)));
            }
            // `bytes + bytes` → bytes nuevos (concat). Va DESPUÉS del check de secret y
            // de las ramas de Text (`bytes + text`/`text + bytes` coercionan vía Display,
            // produciendo texto con el repr `bytes(...)`) y ANTES del fallback aritmético.
            if let (SynValue::Bytes(l), SynValue::Bytes(r)) = (&left, &right) {
                let mut v = Vec::with_capacity(l.len() + r.len());
                v.extend_from_slice(l);
                v.extend_from_slice(r);
                return Ok(syn_bytes(v));
            }
            if let (SynValue::List(l), SynValue::List(r)) = (&left, &right) {
                let mut v = l.borrow().clone();
                v.extend(r.borrow().iter().cloned());
                return Ok(syn_list(v));
            }
        }
        // Aritmética complex (Batch 4): si alguno es Complex y ambos coercionan a
        // complex64 (Number→real, promoción). Va DESPUÉS de los concats de Text/List/Bytes
        // (un `Complex + Text` sigue siendo concat de texto vía Display) y ANTES del camino
        // de Number (G2: el tower no se perturba). Sólo +,-,*,/,**; otros ops caen al error.
        if matches!(op, "+" | "-" | "*" | "/" | "**")
            && (matches!(left, SynValue::Complex(_)) || matches!(right, SynValue::Complex(_)))
        {
            if let (Some(a), Some(b)) = (as_complex(&left), as_complex(&right)) {
                let z = match op {
                    "+" => a + b,
                    "-" => a - b,
                    "*" => a * b,
                    "/" => {
                        if b.re == 0.0 && b.im == 0.0 {
                            return Err(err_at("Division by zero", loc));
                        }
                        a / b
                    }
                    // Exponente entero → potencia EXACTA (powi), como Python; si no, powc.
                    "**" => crate::math::complex_pow(a, &right, b),
                    _ => unreachable!(),
                };
                return Ok(SynValue::Complex(z));
            }
        }
        // Aritmética vectorizada de arrays (Batch 5): elementwise + broadcasting, y
        // array⊕scalar. `*` es ELEMENTWISE (Hadamard), NO producto matricial (eso es
        // matmul/dot). Va DESPUÉS de los concats de Text/List/Bytes y de la rama Complex,
        // y ANTES del camino Number (G2: el tower no se perturba). `array_binop` devuelve
        // none si ningún operando es array → sigue al camino normal.
        if matches!(op, "+" | "-" | "*" | "/" | "**" | "//" | "%") {
            if let Some(res) = crate::arrays::array_binop(&left, &right, op) {
                return res;
            }
        }
        // Fechas, instantes y duraciones (v0.6.29).
        if matches!(op, "+" | "-" | "*" | "/") {
            if let Some(r) = crate::temporal::binop(&left, op, &right) {
                return r;
            }
        }
        // Aritmética — por el camino FALIBLE: mezclar Decimal con Float es un error
        // claro. Int/Big mezclan libremente con ambos.
        if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
            match op {
                "+" => return a.checked_add(b).map(syn_number).map_err(|e| err_at(e, loc)),
                "-" => return a.checked_sub(b).map(syn_number).map_err(|e| err_at(e, loc)),
                "*" => return a.checked_mul(b).map(syn_number).map_err(|e| err_at(e, loc)),
                "/" => {
                    if Number::mixes_decimal_float(a, b) {
                        return Err(err_at(MIX_DECIMAL_FLOAT, loc));
                    }
                    if b.is_zero() {
                        return Err(err_at("Division by zero", loc));
                    }
                    return Ok(syn_number(a.div(b)));
                }
                "%" => {
                    return match a.checked_modulo(b) {
                        Err(e) => Err(err_at(e, loc)),
                        Ok(Some(n)) => Ok(syn_number(n)),
                        Ok(None) => Err(err_at("Modulo by zero", loc)),
                    }
                }
                "//" => {
                    return match a.checked_floor_div(b) {
                        Err(e) => Err(err_at(e, loc)),
                        Ok(Some(n)) => Ok(syn_number(n)),
                        Ok(None) => Err(err_at("Division by zero", loc)),
                    }
                }
                "**" => {
                    if a.is_zero() && b.is_negative() {
                        return Err(err_at("Zero cannot be raised to a negative power", loc));
                    }
                    return a.checked_pow(b).map(syn_number).map_err(|e| err_at(e, loc));
                }
                _ => {}
            }
        }
        // Comparación de igualdad. `==`/`!=` dan error al comparar un decimal con un float,
        // también dentro de listas y mapas (en la posición o clave que se compara: `[1d] ==
        // [1.0]`); lo mismo `in`, `match`, `contains` e `index_of` (`strict_equals`, una sola
        // pasada que corta en la primera diferencia). Las claves internas de hash
        // (`group_by`, `unique`, …) siguen usando la igualdad total de `probe_key`.
        if matches!(op, "==" | "!=") {
            let eq = crate::tabular::strict_equals(&left, &right).map_err(|_| err_at(MIX_DECIMAL_FLOAT, loc))?;
            return Ok(syn_bool(if op == "==" { eq } else { !eq }));
        }
        // Orden
        if matches!(op, "<" | ">" | "<=" | ">=") {
            // Los complejos NO son ordenables (G3): error claro, como Python.
            if matches!(left, SynValue::Complex(_)) || matches!(right, SynValue::Complex(_)) {
                return Err(err_at("complex numbers are not ordered", loc));
            }
            // Comparación elementwise de arrays = futuro (§12). Por ahora, error claro (G3).
            if matches!(left, SynValue::Array(_)) || matches!(right, SynValue::Array(_)) {
                return Err(err_at(
                    "arrays do not support ordering comparisons (use elementwise functions)",
                    loc,
                ));
            }
            if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
                if Number::mixes_decimal_float(a, b) {
                    return Err(err_at(MIX_DECIMAL_FLOAT, loc));
                }
                return Ok(syn_bool(ord_op(a.partial_cmp_num(b), op)));
            }
            if let (SynValue::Text(a), SynValue::Text(b)) = (&left, &right) {
                return Ok(syn_bool(ord_op(Some(a.as_ref().cmp(b.as_ref())), op)));
            }
            if let (SynValue::Time(a), SynValue::Time(b)) = (&left, &right) {
                return match crate::temporal::cmp(a, b) {
                    Some(o) => Ok(syn_bool(ord_op(Some(o), op))),
                    None => Err(err_at(format!("cannot order a {} and a {}", a.type_name(), b.type_name()), loc)),
                };
            }
        }
        let hint = if op == "%" && matches!(left, SynValue::Text(_)) {
            " — there is no %-formatting: use a template `…{x}…` or fmt(template, {name: value})"
        } else {
            ""
        };
        Err(err_at(
            format!("Unsupported operation: {} {} {}{}", left.type_name(), op, right.type_name(), hint),
            loc,
        ))
    }

    /// `escape_pc` : el lado derecho era `declassify(...)` — la escritura no une el PC
    /// Ni al valor ni al contenedor destino (la etiqueta de una clave privada sí cuenta).
    fn exec_set(
        &mut self,
        target: &Node,
        value: SynValue,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
        escape_pc: bool,
    ) -> Result<SynValue, Control> {
        match &target.kind {
            NodeKind::Identifier { name } => {
                // T5 (B1): NSU estricto — la variable tiene que cubrir el PC (salvo que el
                // lado derecho sea `declassify(...)`, el escape auditado).
                if self.labels && !escape_pc && !self.pc_is_empty() {
                    match env_get(env, name) {
                        Some(cur) => self.nsu_check(&labels::label(&cur), &format!("'{}'", name), loc)?,
                        None => {
                            return Err(err(format!(
                                "Cannot set undefined variable: '{}'. Use 'let' first.",
                                name
                            )))
                        }
                    }
                }
                if env_update(env, name, value.clone()).is_err() {
                    return Err(err(format!(
                        "Cannot set undefined variable: '{}'. Use 'let' first.",
                        name
                    )));
                }
                Ok(value)
            }
            NodeKind::PropertyAccess { .. } | NodeKind::IndexAccess { .. } if set_root_identifier(target).is_none() => {
                // `set get(m, "a")["b"] to v`: el destino nace de un VALOR (el resultado de una
                // llamada), no de una variable. Con semántica de valor esa escritura o se
                // pierde (en una copia) o toca un dato compartido; ninguna es lo que se quiso.
                Err(err_at(
                    "Invalid set target: it must start from a variable — write the path from the variable, e.g. set m[\"a\"][\"b\"] to v (not set get(m, \"a\")[\"b\"] to v)",
                    loc,
                ))
            }
            NodeKind::PropertyAccess { property_name, object, .. } => {
                let obj = self.exec_place(object, env)?;
                // Escritura a través de un contenedor privado o bajo PC (ver
                // `set_through_labels`): la etiqueta vive en la variable raíz del camino.
                let (obj, value) = if self.labels && (obj.is_private() || !self.pc_is_empty()) {
                    self.set_through_labels(target, obj, labels::empty(), value, env, loc, escape_pc)?
                } else {
                    (obj, value)
                };
                match &obj {
                    SynValue::Map(m) => {
                        // `set m.X to v` sobre un módulo religa SU variable (la que leen sus
                        // tasks), como `m.X = v` en Python; sus nombres son sus exportaciones y
                        // sus tasks no se reemplazan desde afuera.
                        if let Some(menv) = module_env_of_map(m) {
                            return module_rebind(m, &menv, property_name, value, loc);
                        }
                        m.borrow_mut().insert(property_name.clone(), value.clone());
                        Ok(value)
                    }
                    _ => Err(err_at(format!("Cannot set property on {}", obj.type_name()), loc)),
                }
            }
            NodeKind::IndexAccess { object, index } => {
                let obj = self.exec_place(object, env)?;
                let idx = self.exec(index, env)?;
                // Índice/clave privado, contenedor privado o PC → `set_through_labels`
                // Decide (el caso central: `set state["balances"][to] to x` con `state` y
                // `to` privados {app} no revela nada nuevo y procede sin más).
                let (obj, idx, value) =
                    if self.labels && (obj.is_private() || labels::has_label_deep(&idx) || !self.pc_is_empty()) {
                        // Una clave LITERAL sólo puede llevar el PC (B5): es texto del programa,
                        // No una clave privada (el PC se suma aparte, salvo `escape_pc`).
                        let key_label = if is_scalar_literal(index) { labels::empty() } else { labels::label_deep(&idx) };
                        let (obj, value) =
                            self.set_through_labels(target, obj, key_label, value, env, loc, escape_pc)?;
                        (obj, labels::unwrap(&idx).clone(), value)
                    } else {
                        (obj, idx, value)
                    };
                match &obj {
                    SynValue::List(l) => {
                        let mut b = l.borrow_mut();
                        let len = b.len() as i64;
                        let mut i = num_to_i64(&idx)?;
                        if i < 0 {
                            i += len;
                        }
                        if i < 0 || i >= len {
                            return Err(err("list assignment index out of range"));
                        }
                        b[i as usize] = value.clone();
                        Ok(value)
                    }
                    SynValue::Map(m) => {
                        // `set lib["X"] to v`: las mismas reglas que `set lib.X to v`.
                        if let Some(menv) = module_env_of_map(m) {
                            return module_rebind(m, &menv, &idx.to_string(), value, loc);
                        }
                        m.borrow_mut().insert(idx.to_string(), value.clone());
                        Ok(value)
                    }
                    _ => Err(err_at(format!("Cannot set index on {}", obj.type_name()), loc)),
                }
            }
            _ => Err(err_at("Invalid set target", loc)),
        }
    }

    /// Escritura `set <raíz>[…][k] to v` / `set <raíz>.campo to v` con etiquetas.
    ///
    /// La etiqueta EFECTIVA del contenedor destino es la de `obj` tal como la evaluó `exec`
    /// Por el camino desde la variable raíz (la del binding raíz ∪ cada envoltorio Private
    /// atravesado ∪ los índices intermedios). NSU ESTRICTO (B1/M4): si `etiqueta(clave) ∪ PC
    /// ⊆ efectiva` la escritura no revela nada nuevo (la posición ya era al menos tan privada:
    /// El ledger `set state["balances"][to] to x` con `state` y `to` en {app}) y procede tal
    /// cual; si no → `label_violation`. No hay "conversión" del contenedor: religar la raíz
    /// dejaría públicos los alias del mismo Rc (`let n be m`, el parámetro de una task).
    /// Con `escape_pc` (el lado derecho era `declassify(...)`) el PC no cuenta: sólo la
    /// etiqueta de la clave. Devuelve el contenedor desenvuelto y el valor a escribir.
    fn set_through_labels(
        &mut self,
        target: &Node,
        obj: SynValue,
        key_label: Label,
        value: SynValue,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
        escape_pc: bool,
    ) -> Result<(SynValue, SynValue), Control> {
        let needed = if escape_pc { key_label } else { labels::union(&key_label, &self.pc_label()) };
        // 1.e: la etiqueta que manda es la del BINDING RAIZ del camino, no la del objeto
        // intermedio recien evaluado. Un indice literal bajo PC salia marcado con el PC, el
        // `rewrap` del `IndexAccess` devolvia el contenedor envuelto con ese mismo PC, y la
        // comparacion se cumplia sola: `set m["a"]["b"]` pasaba y `set m.a.b` fallaba, con la
        // proteccion dependiendo de que sintaxis eligio el programador.
        let root = set_root_identifier(target);
        let have = match root.and_then(|n| env_get(env, n)) {
            Some(v) => labels::label(&v),
            // Sin raiz religable (el destino no nace de una variable): no hay etiqueta que
            // sostenga la escritura.
            None => labels::empty(),
        };
        if labels::subset(&needed, &have) {
            return Ok((labels::unwrap(&obj).clone(), value));
        }
        let what = match root {
            Some(name) => format!("a position of '{}'", name),
            None => "a position of a container that is not a variable".to_string(),
        };
        Err(err_labels(
            format!(
                "label_violation: cannot write {} ({}) with a key/context private to {}: the container is not at least as private (the written position would leak); bind it as private(…, \"<principal>\") first, or declassify the scalar you want to publish and build the container outside the private branch",
                what,
                if have.is_empty() { "public".to_string() } else { format!("private to {}", self.safe_label(&have)) },
                self.safe_label(&needed)
            ),
            loc,
        ))
    }

    /// Lectura de un campo (`m.k`, `k of m`): la misma para una expresión y para el
    /// camino de un `set` (`exec_place`).
    fn property_read(&mut self, obj: SynValue, property_name: &str, loc: &SourceLocation) -> Result<SynValue, Control> {
        // Leer un campo de un mapa privado da un valor privado (la etiqueta del
        // contenedor se une a la del campo).
        let mut plabel: Option<Label> = None;
        let obj = if self.labels && obj.is_private() {
            let l = labels::label(&obj);
            self.note_seen(&l);
            plabel = Some(l);
            labels::unwrap(&obj).clone()
        } else {
            obj
        };
        let r = match &obj {
            SynValue::Map(m) => match m.borrow().get(property_name) {
                Some(v) => Ok(v.clone()),
                // `a.nx` donde `nx` existe en el módulo pero no se exporta (un `use` interno, un
                // `let` sin `export`): decirlo en vez de "no key".
                None if module_env_of_map(m).is_some_and(|e| e.borrow().bindings.contains_key(property_name)) => Err(err_at(
                    format!(
                        "the module has no export '{}' — it is defined inside the module but not exported (write `export let`/`export task` there; an import of that module is not re-exported: `use` its file directly)",
                        property_name
                    ),
                    loc,
                )),
                // `d.get("a")`, `d.keys()`: un reflejo de método, no una clave que falta.
                None => Err(err_at(
                    match crate::reflexes::method_hint(property_name) {
                        Some(h) => format!("Map has no key '{}' — if you meant a method, Synsema has no methods: {}", property_name, h),
                        None => format!("Map has no key '{}'", property_name),
                    },
                    loc,
                )),
            },
            // Valores del servidor: acceso a su dict subyacente (body/status/…).
            SynValue::Server(s) => match s.get_field(property_name) {
                Some(v) => Ok(v),
                None => Err(err_at(format!("Map has no key '{}'", property_name), loc)),
            },
            _ => {
                let mut msg = format!("Cannot access property '{}' of {}", property_name, obj.type_name());
                // `xs.append(y)`: Synsema no tiene métodos, tiene funciones.
                if let Some(h) = crate::reflexes::method_hint(property_name) {
                    msg.push_str(&format!(" — Synsema has no methods: {}", h));
                }
                Err(err_at(msg, loc))
            }
        };
        match plabel {
            Some(l) => self.rewrap(r?, l, loc),
            None => r,
        }
    }

    /// Lectura de un índice (`xs[i]`, `m[k]`, `s[i]`, `b[i]`, `a[i]`): la misma para una
    /// expresión y para el camino de un `set` (`exec_place`).
    fn index_read(&mut self, obj: SynValue, idx: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
        // Contenedor o índice privados → el elemento sale con la unión.
        let mut plabel: Option<Label> = None;
        let (obj, idx) = if self.labels && (obj.is_private() || labels::has_label_deep(&idx)) {
            let l = labels::union(&labels::label(&obj), &labels::label_deep(&idx));
            self.note_seen(&l);
            plabel = Some(l);
            (labels::unwrap(&obj).clone(), labels::unwrap(&idx).clone())
        } else {
            (obj, idx)
        };
        let r = match &obj {
            // Índices negativos cuentan desde el final (v0.6.29): `xs[-1]`.
            SynValue::List(l) => {
                let items = l.borrow();
                let i = num_to_i64(&idx)?;
                match resolve_index(i, items.len()) {
                    Some(j) => Ok(items[j].clone()),
                    None => Err(err_at(
                        format!("Index {} out of bounds (list length {})", i, items.len()),
                        loc,
                    )),
                }
            }
            // `s[i]` → un carácter (scalar Unicode, lo mismo que cuenta `length`).
            SynValue::Text(t) => {
                let i = num_to_i64(&idx)?;
                let n = t.chars().count();
                match resolve_index(i, n) {
                    Some(j) => Ok(syn_text(t.chars().nth(j).unwrap().to_string())),
                    None => Err(err_at(
                        format!("Index {} out of bounds (text length {})", i, n),
                        loc,
                    )),
                }
            }
            SynValue::Map(m) => {
                let key = idx.to_string();
                match m.borrow().get(&key) {
                    Some(v) => Ok(v.clone()),
                    None => Err(err_at(format!("Map has no key '{}'", key), loc)),
                }
            }
            // `b[i]` → entero (valor del byte 0..=255); negativos desde el final.
            SynValue::Bytes(b) => {
                let i = num_to_i64(&idx)?;
                match resolve_index(i, b.len()) {
                    Some(j) => Ok(syn_int(b[j] as i64)),
                    None => Err(err_at(
                        format!("Index {} out of bounds (bytes length {})", i, b.len()),
                        loc,
                    )),
                }
            }
            // `a[i]` → fila (nD) o escalar (1D). Negativo/fuera de rango → error.
            SynValue::Array(a) => crate::arrays::index_row(a, num_to_i64(&idx)?),
            _ => Err(err_at(format!("Cannot index into {}", obj.type_name()), loc)),
        };
        match plabel {
            Some(l) => self.rewrap(r?, l, loc),
            None => r,
        }
    }

    /// Evalúa el CAMINO de un `set x[i].k to v` haciendo único cada contenedor que
    /// atraviesa (v0.6.29, semántica de valor con copy-on-write): si otra variable, un
    /// parámetro o un elemento comparte la lista o el mapa, se copia ese nivel —y sólo
    /// ése— antes de escribir. Así `let ys be xs` + `set ys[0] to 9` no toca `xs`, y un
    /// task que escribe en el mapa que recibió no cambia el del que llamó. Sin otro dueño
    /// no se copia nada. Devuelve lo mismo que `exec` sobre ese nodo.
    fn exec_place(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        match &node.kind {
            NodeKind::Identifier { name } => {
                // Un módulo (`use … as d`) es un ESPACIO DE NOMBRES, no un dato: `set d.STATE[k]`
                // escribe el estado del módulo, que ven sus tasks. El mapa del módulo no se copia.
                if let Some(v) = env_get(env, name) {
                    if self.is_module_map(&v) {
                        return Ok(v);
                    }
                }
                if let Some(v) = with_unique_binding(env, name, |slot| slot.clone()) {
                    return Ok(v);
                }
                self.exec(node, env)
            }
            NodeKind::IndexAccess { object, index } => {
                let parent = self.exec_place(object, env)?;
                let idx = self.exec(index, env)?;
                // `set d["STATE"][k]`, `set h.l.STATE[k]`: la VARIABLE del módulo, como `d.STATE`.
                if let Some(v) = module_var_unique(&parent, &labels::unwrap(&idx).to_string()) {
                    return Ok(v);
                }
                match labels::unwrap(&parent) {
                    SynValue::List(l) => {
                        if let Ok(i) = num_to_i64(labels::unwrap(&idx)) {
                            let mut items = l.borrow_mut();
                            let n = items.len();
                            if let Some(j) = resolve_index(i, n) {
                                make_unique(&mut items[j]);
                            }
                        }
                    }
                    SynValue::Map(m) => {
                        let key = labels::unwrap(&idx).to_string();
                        if let Some(slot) = m.borrow_mut().get_mut(&key) {
                            make_unique(slot);
                        }
                    }
                    _ => {}
                }
                self.index_read(parent, idx, loc)
            }
            NodeKind::PropertyAccess { property_name, object, .. } => {
                let parent = self.exec_place(object, env)?;
                // `set d.STATE[k] to v`: se escribe la VARIABLE del módulo (la misma que ven sus
                // tasks), copiándola antes sólo si alguien más guardó una foto (`let s be d.STATE`),
                // venga el mapa del módulo de una variable, de un re-export o de un campo.
                if let Some(v) = module_var_unique(&parent, property_name) {
                    return Ok(v);
                }
                if let SynValue::Map(m) = labels::unwrap(&parent) {
                    if let Some(slot) = m.borrow_mut().get_mut(property_name) {
                        make_unique(slot);
                    }
                }
                self.property_read(parent, property_name, loc)
            }
            _ => self.exec(node, env),
        }
    }

    /// ¿Es `v` el mapa de exportaciones de un módulo cargado?
    /// Bajo `run` es un valor de `module_cache`; en un worker (`parallel_map`, `serve`) el
    /// alias se reconstruye, y se reconoce como allá (`serve::module_env_of`): tiene tasks que
    /// cierran sobre un `module_env` y TODAS sus claves son nombres de ese módulo.
    fn is_module_map(&self, v: &SynValue) -> bool {
        let SynValue::Map(m) = v else { return false };
        module_env_of_map(m).is_some()
    }


    /// Camino rápido de `set P to append(P, v)`, `set P to P + <lista>`, `set P to
    /// insert(P, i, v)` y `set P to merge(P, m, …)`, con P una variable o un camino puro
    /// (`x.campo`, `x[k]` con `k` literal o variable): modifica el contenedor de P (copiándolo
    /// antes sólo si otro lo comparte) en vez de construir uno nuevo. El orden es el del camino
    /// normal: se lee P, después se evalúan los argumentos; si eso religó P, el resultado sale
    /// de la P leída y se asigna como siempre. `None` si la sentencia no tiene esa forma.
    fn try_update_in_place(
        &mut self,
        target: &Node,
        value: &Node,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<SynValue>, Control> {
        if !is_pure_place(target) {
            return Ok(None);
        }
        #[derive(Clone, Copy, PartialEq)]
        enum Op { Append, Concat, Insert, Merge }
        let builtin_is = |this: &Self, name: &str| {
            let _ = this;
            matches!(env_get(env, name), Some(SynValue::Builtin(b)) if b.name == name)
        };
        let (op, rest): (Op, Vec<&Node>) = match &value.kind {
            NodeKind::TaskCall { name, arguments }
                if !arguments.is_empty()
                    && arguments.iter().all(|a| a.name.is_none())
                    && same_place(&arguments[0].value, target) =>
            {
                let op = match (name.as_identifier(), arguments.len()) {
                    (Some("append"), 2) => Op::Append,
                    (Some("insert"), 3) => Op::Insert,
                    (Some("merge"), n) if n >= 2 => Op::Merge,
                    _ => return Ok(None),
                };
                // Tiene que ser EL builtin (un task del usuario puede llamarse igual).
                if !builtin_is(self, name.as_identifier().unwrap_or("")) {
                    return Ok(None);
                }
                (op, arguments[1..].iter().map(|a| &a.value).collect())
            }
            NodeKind::BinaryOp { left, operator, right } if operator == "+" && same_place(left, target) => {
                (Op::Concat, vec![right.as_ref()])
            }
            _ => return Ok(None),
        };
        // Leer P. Si no se puede (clave que falta) o no es del tipo, camino normal.
        let before = match self.exec(target, env) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let fits = match (&before, op) {
            (SynValue::List(_), Op::Append | Op::Concat | Op::Insert) => true,
            (SynValue::Map(_), Op::Merge) => true,
            _ => false,
        };
        if !fits {
            return Ok(None);
        }
        let mut args = Vec::with_capacity(rest.len());
        for n in &rest {
            args.push(self.exec(n, env)?);
        }
        // Con etiquetas encendidas (y PC vacío, lo chequeó el llamador) sólo si nada de lo
        // que entra está etiquetado: entonces el camino normal tampoco etiqueta nada.
        if self.labels && args.iter().any(labels::has_label_deep) {
            let mut all = vec![before];
            all.extend(args);
            let v = self.call_update_builtin(op as u8, all, env, &value.location)?;
            return self.exec_set(target, v, env, &target.location, false).map(Some);
        }
        if op == Op::Concat && !matches!(args[0], SynValue::List(_)) {
            let v = self.exec_binary(before, "+", args.pop().unwrap(), &value.location)?;
            return self.exec_set(target, v, env, &target.location, false).map(Some);
        }
        // ¿Sigue ahí el MISMO contenedor? Si los argumentos religaron P, el resultado es el
        // de la P leída.
        let same = match self.exec(target, env) {
            Ok(now) => same_container(&now, &before),
            Err(_) => false,
        };
        if !same {
            let mut all = vec![before];
            all.extend(args);
            let v = self.call_update_builtin(op as u8, all, env, &value.location)?;
            return self.exec_set(target, v, env, &target.location, false).map(Some);
        }
        drop(before);
        let loc = value.location.clone();
        let apply = move |slot: &mut SynValue| -> Result<SynValue, Control> {
            match (slot as &SynValue, op) {
                (SynValue::List(rc), Op::Append) => rc.borrow_mut().push(args.into_iter().next().unwrap()),
                (SynValue::List(rc), Op::Concat) => {
                    if let Some(SynValue::List(r)) = args.first() {
                        let extra = r.borrow().clone();
                        rc.borrow_mut().extend(extra);
                    }
                }
                (SynValue::List(rc), Op::Insert) => {
                    let mut it = args.into_iter();
                    let (i, v) = (it.next().unwrap(), it.next().unwrap());
                    let mut items = rc.borrow_mut();
                    let j = insert_position(&i, items.len()).map_err(|e| err_at(e, &loc))?;
                    items.insert(j, v);
                }
                (SynValue::Map(rc), Op::Merge) => {
                    for (n, a) in args.iter().enumerate() {
                        if !matches!(a, SynValue::Map(_)) {
                            return Err(err_at(
                                format!("merge(): argument {} is {}, not a map", n + 2, a.type_name()),
                                &loc,
                            ));
                        }
                    }
                    let mut out = rc.borrow_mut();
                    for a in &args {
                        if let SynValue::Map(m) = a {
                            for (k, v) in m.borrow().iter() {
                                out.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                _ => return Err(err_at("the value changed type while computing the update", &loc)),
            }
            Ok(slot.clone())
        };
        self.with_unique_place(target, env, apply).map(Some)
    }

    /// El builtin del camino rápido, por el camino normal (una copia nueva, con el mismo
    /// manejo de etiquetas que una llamada escrita).
    fn call_update_builtin(
        &mut self,
        op: u8,
        mut all: Vec<SynValue>,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let name = match op {
            0 => "append",
            1 => {
                let r = all.pop().unwrap_or(SynValue::Nothing);
                let l = all.pop().unwrap_or(SynValue::Nothing);
                return self.exec_binary(l, "+", r, loc);
            }
            2 => "insert",
            _ => "merge",
        };
        let func = env_get(env, name).ok_or_else(|| err_at(format!("Undefined variable: '{}'", name), loc))?;
        self.call_value(func, all, loc)
    }

    /// Acceso único al contenedor de un camino puro: los niveles de arriba se hacen únicos
    /// (`exec_place`), el último también, y `f` lo modifica. Una variable de un módulo sigue
    /// al env del módulo (`with_unique_binding`).
    fn with_unique_place(
        &mut self,
        target: &Node,
        env: &Rc<RefCell<Environment>>,
        f: impl FnOnce(&mut SynValue) -> Result<SynValue, Control>,
    ) -> Result<SynValue, Control> {
        let loc = &target.location;
        let lost = || err_at("the place changed while computing the update", loc);
        match &target.kind {
            NodeKind::Identifier { name } => with_unique_binding(env, name, f).unwrap_or_else(|| Err(lost())),
            NodeKind::PropertyAccess { property_name, object, .. } => {
                let parent = self.exec_place(object, env)?;
                let SynValue::Map(m) = &parent else { return Err(lost()) };
                if let Some(menv) = module_env_of_map(m) {
                    return with_unique_binding(&menv, property_name, f).unwrap_or_else(|| Err(lost()));
                }
                let mut map = m.borrow_mut();
                let slot = map.get_mut(property_name.as_str()).ok_or_else(lost)?;
                make_unique(slot);
                f(slot)
            }
            NodeKind::IndexAccess { object, index } => {
                let parent = self.exec_place(object, env)?;
                let idx = self.exec(index, env)?;
                match &parent {
                    SynValue::List(l) => {
                        let i = num_to_i64(&idx)?;
                        let mut items = l.borrow_mut();
                        let n = items.len();
                        let j = resolve_index(i, n).ok_or_else(lost)?;
                        make_unique(&mut items[j]);
                        f(&mut items[j])
                    }
                    SynValue::Map(m) => {
                        let mut map = m.borrow_mut();
                        let slot = map.get_mut(&idx.to_string()).ok_or_else(lost)?;
                        make_unique(slot);
                        f(slot)
                    }
                    _ => Err(lost()),
                }
            }
            _ => Err(lost()),
        }
    }

    /// Paso de un pipe que es una llamada: `v |> f(a, b = c)` = `f(v, a, b = c)`
    /// (v0.6.29). Mismo camino que `TaskCall`, con el valor entubado como primer
    /// posicional (nunca un literal del fuente para la regla 3.a de etiquetas).
    fn exec_call_with_first(
        &mut self,
        name: &Node,
        arguments: &[crate::ast::Arg],
        first: SynValue,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let func = self.exec(name, env)?;
        if let Some(id) = name.as_identifier() {
            if PROTECTED_BUILTIN_NAMES.contains(&id) {
                check_protected_callee(id, &func, loc)?;
            }
        }
        let mut args = Vec::with_capacity(arguments.len() + 1);
        args.push((None, first));
        for arg in arguments {
            let val = self.exec(&arg.value, env)?;
            args.push((arg.name.clone(), val));
        }
        if self.labels {
            let mut mask = 0u32;
            for (i, arg) in arguments.iter().enumerate().take(31) {
                if is_literal_expr(&arg.value) {
                    mask |= 1 << (i + 1);
                }
            }
            self.arg_literals = mask;
        }
        check_call_arity(&func, &args, loc)?;
        self.call_value_named(func, args, loc)
    }

    /// Llamada con args sólo posicionales (camino de siempre: pipes, apply/where,
    /// callbacks internos, etc.). Envuelve cada uno como `(None, v)` y delega en
    /// `call_value_named`.
    fn call_value(
        &mut self,
        func: SynValue,
        args: Vec<SynValue>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        let named = args.into_iter().map(|v| (None, v)).collect();
        self.call_value_named(func, named, loc)
    }

    /// Llamada con args posicionales y/o nombrados (Batch 2). Lleva el tracking de
    /// recursión; el binding lo hace `call_value_named_inner`.
    fn call_value_named(
        &mut self,
        func: SynValue,
        args: Vec<(Option<String>, SynValue)>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        self.recursion_depth += 1;
        if self.recursion_depth > MAX_RECURSION {
            self.recursion_depth -= 1;
            return Err(err("maximum recursion depth exceeded"));
        }
        let result = self.call_value_named_inner(func, args, loc);
        self.recursion_depth -= 1;
        result
    }

    fn call_value_named_inner(
        &mut self,
        func: SynValue,
        args: Vec<(Option<String>, SynValue)>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        match func {
            SynValue::Builtin(bt) => {
                // Builtins con `param_names` (opt-in, G-8): los args nombrados se mapean
                // a posicionales, con las mismas reglas que las tasks (posicional tras
                // nombrado = error, duplicado = error, nombre desconocido = error, slot
                // vacío = `nothing`). Sin `param_names`: un arg nombrado es error claro
                // (sintaxis nueva, G3) y el camino posicional queda intacto.
                match &bt.param_names {
                    Some(names) => {
                        let mut slots: Vec<Option<SynValue>> = vec![None; names.len()];
                        let mut seen_named = false;
                        let mut pos_idx = 0usize;
                        for (name, value) in args {
                            match name {
                                None => {
                                    if seen_named {
                                        return Err(err_at(
                                            "positional argument after named argument",
                                            loc,
                                        ));
                                    }
                                    if pos_idx < slots.len() {
                                        slots[pos_idx] = Some(value);
                                    }
                                    pos_idx += 1;
                                }
                                Some(n) => {
                                    seen_named = true;
                                    match names.iter().position(|p| *p == n) {
                                        Some(idx) => {
                                            if slots[idx].is_some() {
                                                return Err(err_at(
                                                    format!("duplicate argument '{}'", n),
                                                    loc,
                                                ));
                                            }
                                            slots[idx] = Some(value);
                                        }
                                        None => {
                                            return Err(err_at(
                                                format!("unknown parameter '{}'", n),
                                                loc,
                                            ))
                                        }
                                    }
                                }
                            }
                        }
                        let pos: Vec<SynValue> = slots
                            .into_iter()
                            .map(|s| s.unwrap_or(SynValue::Nothing))
                            .collect();
                        self.dispatch_builtin(&bt, &pos, loc)
                    }
                    None => {
                        let mut pos = Vec::with_capacity(args.len());
                        let allowed = crate::builtin_arity::kwargs_of(&bt.name);
                        let mut kw: IndexMap<String, SynValue> = IndexMap::new();
                        for (name, v) in args {
                            if let Some(n) = name {
                                if allowed.contains(&n.as_str()) {
                                    if kw.insert(n.clone(), v).is_some() {
                                        return Err(err_at(format!("duplicate argument '{}'", n), loc));
                                    }
                                    continue;
                                }
                                if !allowed.is_empty() {
                                    return Err(err_at(
                                        format!(
                                            "{}() has no argument named '{}' (named arguments it takes: {})",
                                            bt.name,
                                            n,
                                            allowed.join(", ")
                                        ),
                                        loc,
                                    ));
                                }
                                return Err(err_at(
                                    format!(
                                        "{}() does not accept named arguments (got {} = …); pass it by position",
                                        bt.name, n
                                    ),
                                    loc,
                                ));
                            }
                            pos.push(v);
                        }
                        let saved = std::mem::replace(&mut self.pending_kwargs, kw);
                        let r = self.dispatch_builtin(&bt, &pos, loc);
                        self.pending_kwargs = saved;
                        r
                    }
                }
            }
            SynValue::Task(task) => {
                let call_env = Environment::child(&task.closure_env, &format!("call:{}", task.name));
                let nparams = task.parameters.len();
                // Repartición: cada slot de param recibe a lo sumo un valor.
                let mut slots: Vec<Option<SynValue>> = vec![None; nparams];
                let mut seen_named = false;
                let mut pos_idx = 0usize;
                for (name, value) in args {
                    match name {
                        None => {
                            // Posicional tras nombrado → error (sintaxis nueva, G3).
                            if seen_named {
                                return Err(err_at(
                                    "positional argument after named argument",
                                    loc,
                                ));
                            }
                            // Aridad permisiva (G3): un posicional extra se descarta,
                            // igual que antes (no es error).
                            if pos_idx < nparams {
                                slots[pos_idx] = Some(value);
                            }
                            pos_idx += 1;
                        }
                        Some(n) => {
                            seen_named = true;
                            match task.parameters.iter().position(|p| p.name == n) {
                                Some(idx) => {
                                    if slots[idx].is_some() {
                                        return Err(err_at(
                                            format!("duplicate argument '{}'", n),
                                            loc,
                                        ));
                                    }
                                    slots[idx] = Some(value);
                                }
                                None => {
                                    return Err(err_at(format!("unknown parameter '{}'", n), loc))
                                }
                            }
                        }
                    }
                }
                // Llená cada param: valor recibido, o default (eval en call time en el
                // closure_env, G5), o `nothing` (aridad permisiva, G3).
                for (i, param) in task.parameters.iter().enumerate() {
                    let v = match slots[i].take() {
                        Some(v) => v,
                        None => match &param.default {
                            Some(default_node) => self.exec(default_node, &task.closure_env)?,
                            None => SynValue::Nothing,
                        },
                    };
                    env_set(&call_env, &param.name, v);
                }
                // T5 (regla 1.b) — la tinta de continuación del LLAMADOR VIAJA con la llamada.
                // Vaciarla al entrar (lo que se hacía hasta la ronda 4) era la puerta más grande
                // de la tanda: un helper SIN argumentos llamado desde un bucle ya teñido corría
                // con tinta vacía y escribía estado público sin chequeo, así que
                // `each i in range(0,256) / when secret == i / give` reconstruía el secreto
                // entero en un contador público (medido: 181, y alcanza `write_file`, `remember`
                // y una respuesta HTTP 200). El mismo helper CON argumento fallaba cerrado sólo
                // por accidente: el argumento se evalúa en el llamador, bajo su tinta.
                // Lo que sí es del cuerpo es lo que la task tiñe ADENTRO: al volver se restaura
                // la tinta del llamador —también por el camino de error—, que es lo que evita el
                // PC residual sobre su código público (un `give` llega a un join point y el
                // valor ya viaja etiquetado).
                let saved_taint = self.enter_call();
                let out = match self.exec_block(&task.body, &call_env) {
                    Ok(v) => Ok(v),
                    Err(Control::Give(v)) => Ok(v),
                    Err(other) => Err(other),
                };
                // T5 (ronda 5) — un `stop` que SALE de la task corta el bucle del LLAMADOR, y
                // ahí la tinta no siempre llega a tiempo. Cuando la rama que lo dispara está en
                // el cuerpo del callee (`task h(s, i) / when s == i / stop`), `taint_branch` la
                // pone en la vuelta 0 y todo cierra. Pero si la rama está en el LLAMADOR y el
                // salto es indirecto (`when secret == i / bail()`, con `task bail() / stop`),
                // el predicado estático no puede verlo —saber si una llamada corta el bucle es
                // interprocedural— y para cuando el `stop` dispara en la vuelta 181, las 181
                // vueltas anteriores ya escribieron un contador público en claro. Medido: el
                // secreto entero, con `label_of` vacío.
                //
                // Así que se rechaza el constructo: un `stop` bajo control privado no puede
                // dejar la task donde está escrito. `escaping_taint` no vacío en este punto
                // significa exactamente "un `stop` de este cuerpo salió bajo PC privado".
                let escaping_stop =
                    self.labels && matches!(out, Err(Control::Stop(_))) && !self.escaping_taint.is_empty();
                let escaped_pc = if escaping_stop { self.safe_label(&self.escaping_taint) } else { String::new() };
                self.leave_call(saved_taint);
                if escaping_stop {
                    return Err(err_labels(
                        format!(
                            "label_violation: 'stop' left the task '{}' under private control flow (pc = [{}]); a 'stop' that breaks the CALLER's loop cannot be checked until the loop has already run, so it is refused. Write the 'stop' in the loop it belongs to (give a value and decide there), or declassify(<the condition>, \"<why it may be published>\")",
                            task.name, escaped_pc
                        ),
                        loc,
                    ));
                }
                out
            }
            // Un callable etiquetado (p. ej. una lambda ligada dentro de un `when`
            // Privado) se llama bajo su etiqueta de PC y el resultado sale con ella: QUÉ
            // función corrió es información privada.
            SynValue::Private(p) if self.labels => {
                let l = p.label.clone();
                let inner = p.value.clone();
                self.pc_push(&l);
                let r = self.call_value_named_inner(inner, args, loc);
                self.pc_pop();
                self.rewrap(r?, l, loc)
            }
            other => Err(err_at(format!("Cannot call value of type {}", other.type_name()), loc)),
        }
    }

    fn exec_expect(
        &mut self,
        shape: &[(String, String)],
        env: &Rc<RefCell<Environment>>,
    ) -> Result<SynValue, Control> {
        let request = match env_get(env, "request") {
            Some(r) => r,
            None => return Err(err("expect can only be used inside an HTTP route handler")),
        };
        let data = match &request {
            SynValue::Map(m) => m.borrow().get("json").cloned(),
            _ => None,
        };
        let data_map = match &data {
            // Input del cliente que no es un objeto JSON → error de validación (400).
            Some(SynValue::Map(m)) => m.clone(),
            _ => return Err(err_validation("request body is not a JSON object", None)),
        };
        for (field_name, type_name) in shape {
            if !matches!(type_name.as_str(), "text" | "number" | "bool" | "list" | "map") {
                // Tipo inexistente en el `.syn`: bug del autor, no del cliente → 500.
                return Err(err(format!(
                    "unknown type '{}' for field '{}' (use: text, number, bool, list, map)",
                    type_name, field_name
                )));
            }
            let actual = match data_map.borrow().get(field_name) {
                Some(v) => v.clone(),
                None => {
                    // Falla de validación del cliente → 400 con el campo ofensor.
                    return Err(err_validation(
                        format!("missing required field '{}' (expected {})", field_name, type_name),
                        Some(field_name.clone()),
                    ))
                }
            };
            if actual.type_name() != type_name.as_str() {
                return Err(err_validation(
                    format!(
                        "field '{}' must be {}, got {}",
                        field_name,
                        type_name,
                        actual.type_name()
                    ),
                    Some(field_name.clone()),
                ));
            }
        }
        Ok(SynValue::Nothing)
    }

    // =========================================================
    // builtins (núcleo)
    // =========================================================

    fn b_print(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        self.ensure_stdout()?;
        // T5 (ronda 4): `print` es un sumidero público — ver `stdout_flow_check`.
        self.stdout_flow_check("print called", loc)?;
        let s = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
        // Defensa de fondo: con el PC ya comprobado arriba esto es la identidad, y sigue acá
        // por si algún camino futuro alcanza `b_print` sin pasar por el chequeo.
        let s = self.pc_redact(s);
        self.emit_line(s);
        Ok(SynValue::Nothing)
    }

    /// La salida de `print`, `log` y `show`, en el orden en que ocurre. `synsema run` (camino
    /// normal) escribe cada línea al momento (v0.6.29): un script largo ya no parece colgado.
    /// `test`, `serve`, `conform`, los informes JSON y los agentes (que transmiten por su
    /// `log_hook` con prefijo) siguen juntando en `output`. Con etiquetas encendidas tampoco se
    /// transmite: `redact_output_for_host` tiene que poder retener TODO el prefijo si la corrida
    /// muere por un flujo privado (cuántas líneas salieron depende del dato).
    fn emit_line(&mut self, line: String) {
        if let Some(hook) = &self.log_hook {
            hook(&line);
        } else if !self.labels && LIVE_STDOUT.load(std::sync::atomic::Ordering::Relaxed) {
            use std::io::Write;
            let out = std::io::stdout();
            let mut lock = out.lock();
            let _ = writeln!(lock, "{}", line);
            let _ = lock.flush();
            return;
        }
        self.output.push(line);
    }

    fn b_length(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        match v {
            SynValue::Text(s) => Ok(syn_int(s.chars().count() as i64)),
            SynValue::List(l) => Ok(syn_int(l.borrow().len() as i64)),
            SynValue::Map(m) => Ok(syn_int(m.borrow().len() as i64)),
            SynValue::Bytes(b) => Ok(syn_int(b.len() as i64)),
            // v0.6.29 (DATOS-8): la primera dimensión, como `len` de numpy (`size` es el total).
            SynValue::Array(a) => Ok(syn_int(a.shape().first().copied().unwrap_or(0) as i64)),
            _ => Err(err(format!("Cannot get length of {}", v.type_name()))),
        }
    }

    fn b_to_text(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(nth(args, 0)?.to_string()))
    }

    /// floor/ceil/round/trunc → entero. Los enteros (Int/Big) ya lo son y pasan tal cual;
    /// los floats aplican `op` y vuelven a Int (o Big si desbordan i64). No-número → error.
    fn b_round_op(
        &mut self,
        args: &[SynValue],
        _loc: &SourceLocation,
        name: &str,
        op: fn(f64) -> f64,
    ) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        match v {
            SynValue::Number(Number::Float(x)) => Ok(SynValue::Number(Number::integer_from_f64(op(*x)))),
            // Un decimal, EXACTO (v0.6.29; antes volvía sin cambiar): el entero que corresponde,
            // como `math.floor(Decimal)` de Python. `round` es mitad al par, como con float.
            SynValue::Number(n) if n.is_decimal() => {
                let (m, s) = n.exact_ratio().unwrap();
                let d = crate::number::pow10_big(s);
                use num_integer::Integer;
                let q = match name {
                    "floor" => m.div_floor(&d),
                    "ceil" => -((-&m).div_floor(&d)),
                    "trunc" => &m / &d,
                    _ => crate::number::div_round_half_even(&m, &d),
                };
                Ok(SynValue::Number(Number::from_bigint(q)))
            }
            SynValue::Number(n) => Ok(SynValue::Number(n.clone())), // Int/Big ya son enteros
            // v0.6.29: sobre un array, elemento a elemento (sigue siendo un array de floats).
            SynValue::Array(a) => Ok(crate::types::syn_array(a.mapv(op))),
            _ => Err(err(format!("{} expects a number, got {}", name, v.type_name()))),
        }
    }

    /// `number(x)` → float, o error. **`number(x, default)` → la variante TOTAL**: devuelve
    /// `default` en vez de lanzar.
    ///
    /// T5 (ronda 7) — no es azúcar. Bajo etiquetas, un error causado por datos privados no se
    /// atrapa (regla 1.a: poder recuperarse de un fallo ES el bit), así que un programa que
    /// valida entrada no confiable —el caso de un enclave, que recibe cargas cifradas de
    /// cualquiera— se quedaba **sin ninguna frase que escribir**: ni `try/recover`, ni declarar
    /// privado el destino. Sin error no hay bit, y el programa valida sin excepciones:
    /// `let n be number(campo, nothing)` y después `when n == nothing`.
    fn b_to_number(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() || args.len() > 2 {
            return Err(err("number(value, default?) takes 1 or 2 arguments"));
        }
        let v = nth(args, 0)?;
        let bail = |v: &SynValue| -> Result<SynValue, Control> {
            match args.get(1) {
                Some(d) => Ok(d.clone()),
                None => Err(err(format!(
                    "Cannot convert {} to number. To validate untrusted input without raising, pass a fallback: number(<value>, nothing)",
                    v
                ))),
            }
        };
        let f = match v {
            SynValue::Number(n) => n.to_f64(),
            SynValue::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            SynValue::Text(s) => {
                // Un texto ENTERO fuera de ±2⁵³ no entra exacto en un float: antes se
                // redondeaba sin avisar (`"123456789012345678901"` → …683968). Ahora es
                // un error que nombra a `int` (v0.6.29).
                if let Some(n) = over_digit_limit(s) {
                    return match args.get(1) {
                        Some(d) => Ok(d.clone()),
                        None => Err(err(format!(
                            "number(): text with {} digits; the limit is {} (converting longer ones is quadratic)",
                            n, MAX_INT_TEXT_DIGITS
                        ))),
                    };
                }
                if let Some(n) = parse_int_text(s) {
                    let big = n.as_bigint().unwrap();
                    let limit = num_bigint::BigInt::from(1u64 << 53);
                    if big > limit || big < -limit {
                        return match args.get(1) {
                            Some(d) => Ok(d.clone()),
                            None => Err(err(format!(
                                "number({:?}) would lose digits: a float is exact only up to 2^53. Use int(x) for an exact integer",
                                s.trim()
                            ))),
                        };
                    }
                }
                // `_` entre dígitos, como en `int` y en los literales (`1_000.5`).
                let t = s.trim();
                let cleaned: String;
                let t = if t.contains('_') {
                    let b = t.as_bytes();
                    let ok = b.iter().enumerate().all(|(i, c)| {
                        *c != b'_' || (i > 0 && i + 1 < b.len() && b[i - 1].is_ascii_digit() && b[i + 1].is_ascii_digit())
                    });
                    if !ok {
                        return bail(v);
                    }
                    cleaned = t.replace('_', "");
                    cleaned.as_str()
                } else {
                    t
                };
                match t.parse::<f64>() {
                    Ok(x) => x,
                    Err(_) => return bail(v),
                }
            }
            _ => return bail(v),
        };
        Ok(syn_float(f))
    }

    /// `int(x)` → entero EXACTO, o error; `int(x, default)` es la forma total (v0.6.29).
    /// Acepta un entero, un float/decimal con valor entero y texto: decimal con signo
    /// (`"-42"`, `"1_000"`) o `0x…`/`0b…` (ceros a la izquierda permitidos: un topic viene
    /// rellenado a 32 bytes). No trunca nunca: `int(1.5)` y `int("1.5")` son error.
    fn b_int(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        let n = match v {
            SynValue::Number(n @ (Number::Int(_) | Number::Big(_))) => n.clone(),
            SynValue::Number(Number::Float(x)) => {
                if !x.is_finite() || x.fract() != 0.0 {
                    return Err(err(format!(
                        "int({}): not a whole number — round it on purpose first: floor(x), round(x) or trunc(x)",
                        crate::number::py_float_str(*x)
                    )));
                }
                Number::integer_from_f64(*x)
            }
            SynValue::Number(d @ (Number::Decimal(_) | Number::BigDec(_))) => match d.as_bigint() {
                Some(b) => Number::from_bigint(b),
                None => {
                    return Err(err(format!(
                        "int({}): not a whole number — round it on purpose first: floor(x), round(x) or trunc(x)",
                        d
                    )))
                }
            },
            SynValue::Text(s) => parse_int_text(s).ok_or_else(|| {
                if let Some(n) = over_digit_limit(s) {
                    return err(format!(
                        "int(): text with {} digits; the limit is {} (converting longer ones is quadratic). To validate untrusted input without raising: int(x, nothing)",
                        n, MAX_INT_TEXT_DIGITS
                    ));
                }
                err(format!(
                    "Cannot convert {:?} to an integer: expected digits with an optional sign, or 0x…/0b…. To validate untrusted input without raising: int(x, nothing)",
                    s.as_ref()
                ))
            })?,
            SynValue::Bytes(_) => {
                return Err(err("int() does not read bytes; use bytes_to_int(b) (big-endian, unsigned)"))
            }
            other => return Err(err(format!("Cannot convert {} to an integer", other.type_name()))),
        };
        Ok(syn_number(n.normalized()))
    }

    /// `hex(x)` → texto `0x…` (v0.6.29). Un entero ≥ 0 da una **cantidad** (dígitos
    /// mínimos, `hex(0)` = `"0x0"`, la forma del JSON-RPC); bytes dan un **dato** (dos
    /// dígitos por byte, con los ceros). `int(hex(n)) == n` y `bytes(hex(b), "hex") == b`.
    fn b_hex(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Number(n @ (Number::Int(_) | Number::Big(_))) => {
                let b = n.as_bigint().unwrap();
                if b.sign() == num_bigint::Sign::Minus {
                    return Err(err(format!("hex({}): negative numbers have no hex quantity form", n)));
                }
                Ok(syn_text(format!("0x{}", b.to_str_radix(16))))
            }
            SynValue::Number(n) => Err(err(format!(
                "hex() takes an integer or bytes, got {} — convert on purpose first: hex(int(x))",
                n
            ))),
            SynValue::Bytes(b) => Ok(syn_text(format!("0x{}", crate::bytesutil::hex_encode(b)))),
            SynValue::Secret(_) => Err(err("hex(): a secret is never shown")),
            other => Err(err(format!("hex() takes an integer or bytes, got {}", other.type_name()))),
        }
    }

    /// `decimal(x)` → Decimal exacto. `decimal("1234.56")`/`decimal(int)` exactos;
    /// `decimal(float)` → ERROR (usar string para evitar la imprecisión del float).
    fn b_decimal(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        let d = match v {
            SynValue::Number(n) if n.is_decimal() => n.clone(),
            SynValue::Number(Number::Float(_)) => {
                return Err(err(
                    "decimal(float) is not exact; use a string, e.g. decimal(\"1.50\"), \
                     to avoid float imprecision",
                ))
            }
            // Un entero de cualquier tamaño es un decimal exacto (v0.6.29).
            SynValue::Number(n) => {
                let (m, s) = n.exact_ratio().ok_or_else(|| err("decimal(): not an exact number"))?;
                Number::decimal_from_parts(m, s)
            }
            SynValue::Text(s) => Number::parse_decimal(s).ok_or_else(|| {
                err(format!(
                    "Cannot parse {} as a decimal (digits with an optional sign and point, up to {} digits)",
                    v,
                    crate::number::MAX_DEC_TEXT_DIGITS
                ))
            })?,
            _ => return Err(err(format!("Cannot convert {} to a decimal", v.type_name()))),
        };
        Ok(syn_number(d))
    }

    /// `float(x)` → Float (lossy a propósito): convierte Decimal→Float, o parsea texto.
    fn b_float(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        let f = match v {
            SynValue::Number(n) => n.to_f64(),
            SynValue::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            SynValue::Text(s) => s
                .trim()
                .parse::<f64>()
                .map_err(|_| err(format!("Cannot convert {} to float", v)))?,
            _ => return Err(err(format!("Cannot convert {} to float", v.type_name()))),
        };
        Ok(syn_float(f))
    }

    /// `is_decimal(x)` → true sólo si `x` es un Decimal.
    fn b_is_decimal(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_bool(matches!(nth(args, 0)?, SynValue::Number(n) if n.is_decimal())))
    }

    /// `bytes(value, encoding?)` → bytes. PURO (sin capability). Conversión hacia
    /// binario; el `encoding` (2º arg) sólo aplica a un primer arg de texto.
    /// - `bytes(text)` / `bytes(text, "utf8")` → UTF-8 del texto.
    /// - `bytes(text, "hex")` → decodifica hex (error si longitud impar o char no-hex).
    /// - `bytes(text, "base64")` → decodifica base64 RFC-4648 con padding (error si inválido).
    /// - `bytes(text, "base64url")` → decodifica base64url (URL-safe `-_`, padding opcional).
    /// - `bytes(text, "base58")` → decodifica base58 (Bitcoin/Solana; error si char inválido).
    /// - `bytes(text, "base32")` → decodifica base32 RFC-4648 (Algorand; error si inválido).
    /// - `bytes(list)` → de una lista de enteros (error si algún elemento no es int 0..=255).
    /// - `bytes(bytes)` → identidad (clona el `Rc`).
    /// - `bytes(secret)` → ERROR (G6: el plaintext no se extrae a bytes).
    fn b_bytes(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() || args.len() > 2 {
            return Err(err("bytes() takes 1 or 2 arguments"));
        }
        match nth(args, 0)? {
            // Identidad: clona el Rc (inmutable, sin copia de datos).
            SynValue::Bytes(b) => Ok(SynValue::Bytes(b.clone())),
            // G6: nunca materializar el plaintext de un secret en bytes user-space.
            SynValue::Secret(_) => Err(err("Cannot convert secret to bytes")),
            SynValue::Text(s) => {
                let enc = bytes_encoding_arg(args)?;
                match enc.as_deref().unwrap_or("utf8") {
                    "utf8" => Ok(syn_bytes(s.as_bytes().to_vec())),
                    // `0x`/`0X` opcional (v0.6.29): es como lo devuelve todo RPC.
                    "hex" => {
                        let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                        crate::bytesutil::hex_decode(h).map(syn_bytes).map_err(|e| {
                            if e.contains("odd") {
                                err(format!(
                                    "{} — an odd number of hex digits is a quantity, not bytes: int({:?})",
                                    e,
                                    s.as_ref()
                                ))
                            } else {
                                err(e)
                            }
                        })
                    }
                    "base64" => crate::bytesutil::b64_decode(s).map(syn_bytes).map_err(err),
                    // Web auth: base64url (RFC 4648 §5, URL-safe `-_`); acepta con y
                    // sin padding — la forma de JWT/tokens.
                    "base64url" => crate::bytesutil::b64url_decode(s).map(syn_bytes).map_err(err),
                    // Batch 11 (blockchain): base58 de Bitcoin/Solana; base32 RFC 4648
                    // (mayúsculas sin padding — convención Algorand).
                    "base58" => crate::bytesutil::base58_decode(s).map(syn_bytes).map_err(err),
                    "base32" => crate::bytesutil::base32_decode(s).map(syn_bytes).map_err(err),
                    other => Err(err(format!(
                        "unsupported encoding {:?} for bytes(); use one of: utf8, hex, base64, base64url, base58, base32",
                        other
                    ))),
                }
            }
            SynValue::List(l) => {
                let items = l.borrow();
                let mut out = Vec::with_capacity(items.len());
                for (i, e) in items.iter().enumerate() {
                    match e {
                        SynValue::Number(Number::Int(n)) if (0..=255).contains(n) => {
                            out.push(*n as u8)
                        }
                        _ => {
                            return Err(err(format!(
                                "bytes(list): element {} is not an integer in 0..=255",
                                i
                            )))
                        }
                    }
                }
                Ok(syn_bytes(out))
            }
            other => Err(err(format!("Cannot convert {} to bytes", other.type_name()))),
        }
    }

    /// `decode(value, encoding?)` → texto. Inverso simétrico de `bytes`. El primer arg
    /// DEBE ser bytes. UTF-8 por defecto es **estricto** (error en inválidos, G4); la
    /// variante lossy (`U+FFFD`) es opt-in explícito con `"utf8_lossy"`.
    /// - `decode(bytes)` / `decode(bytes, "utf8")` → texto (UTF-8 estricto).
    /// - `decode(bytes, "utf8_lossy")` → texto con `U+FFFD` en inválidos.
    /// - `decode(bytes, "hex")` → texto hex en minúsculas.
    /// - `decode(bytes, "base64")` → texto base64 con padding.
    /// - `decode(bytes, "base64url")` → texto base64url (URL-safe `-_`), SIN padding.
    /// - `decode(bytes, "base58")` → texto base58 (Bitcoin/Solana).
    /// - `decode(bytes, "base32")` → texto base32 RFC-4648 mayúsculas sin padding (Algorand).
    /// - `decode(secret)` → ERROR (G6; cae al error de tipo: un secret no es bytes).
    fn b_decode(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() || args.len() > 2 {
            return Err(err("decode() takes 1 or 2 arguments"));
        }
        let b = match nth(args, 0)? {
            SynValue::Bytes(b) => b,
            other => return Err(err(format!("decode expects bytes, got {}", other.type_name()))),
        };
        match bytes_encoding_arg(args)?.as_deref().unwrap_or("utf8") {
            "utf8" => match std::str::from_utf8(b) {
                Ok(s) => Ok(syn_text(s)),
                Err(e) => Err(err(format!(
                    "decode: invalid UTF-8 at byte offset {} (use \"utf8_lossy\" to replace \
                     invalid bytes)",
                    e.valid_up_to()
                ))),
            },
            "utf8_lossy" => Ok(syn_text(String::from_utf8_lossy(b).into_owned())),
            "hex" => Ok(syn_text(crate::bytesutil::hex_encode(b))),
            "base64" => Ok(syn_text(crate::bytesutil::b64_encode(b))),
            // Web auth: base64url (RFC 4648 §5) SIN padding — la forma de JWT/tokens.
            "base64url" => Ok(syn_text(crate::bytesutil::b64url_encode(b))),
            // Batch 11 (blockchain): base58 (Solana/Bitcoin) y base32 RFC 4648
            // mayúsculas sin padding (Algorand).
            "base58" => Ok(syn_text(crate::bytesutil::base58_encode(b))),
            "base32" => Ok(syn_text(crate::bytesutil::base32_encode(b))),
            other => Err(err(format!(
                "unsupported encoding {:?} for decode(); use one of: utf8, utf8_lossy, hex, base64, base64url, base58, base32",
                other
            ))),
        }
    }

    /// `is_bytes(x)` → true sólo si `x` es bytes.
    fn b_is_bytes(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_bool(matches!(nth(args, 0)?, SynValue::Bytes(_))))
    }

    /// `bytes_to_int(b)` → entero NO-negativo desde bytes big-endian, **exacto**
    /// (bytes vacíos → 0; cae a entero grande si no entra en i64 — un r/s de firma
    /// de 32 bytes es un entero de 256 bits, jamás pasa por float). Inverso:
    /// `int_to_bytes`. `bytes_to_int(secret)` → ERROR (G6).
    fn b_bytes_to_int(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Bytes(b) => Ok(syn_number(Number::from_be_bytes(b))),
            SynValue::Secret(_) => Err(err("bytes_to_int: cannot convert a secret")),
            other => Err(err(format!("bytes_to_int expects bytes, got {}", other.type_name()))),
        }
    }

    /// `int_to_bytes(n, size?)` → bytes big-endian de un entero no-negativo.
    /// Sin `size`: MÍNIMOS (sin ceros a la izquierda; `0` → bytes vacíos — la forma
    /// que piden RLP y los enteros de protocolo). Con `size`: exactamente ese ancho,
    /// con padding de ceros a la izquierda (error si el valor no entra — nunca trunca
    /// en silencio). Float/Decimal/negativo → error (la conversión es exacta o no es).
    fn b_int_to_bytes(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() || args.len() > 2 {
            return Err(err("int_to_bytes() takes 1 or 2 arguments: int_to_bytes(n, size?)"));
        }
        let n = match nth(args, 0)? {
            SynValue::Number(n) => n,
            other => {
                return Err(err(format!(
                    "int_to_bytes expects a non-negative integer, got {}",
                    other.type_name()
                )))
            }
        };
        let min = n.to_be_bytes_min().ok_or_else(|| {
            err("int_to_bytes: the value must be a non-negative integer (no floats/decimals/negatives)")
        })?;
        match args.get(1) {
            None | Some(SynValue::Nothing) => Ok(syn_bytes(min)),
            Some(SynValue::Number(sz)) if sz.is_integer() => {
                let size = sz.to_i64_trunc().filter(|s| *s >= 0).ok_or_else(|| {
                    err("int_to_bytes: size must be a non-negative integer")
                })? as usize;
                if min.len() > size {
                    return Err(err(format!(
                        "int_to_bytes: the value needs {} bytes and does not fit in size {}",
                        min.len(),
                        size
                    )));
                }
                let mut out = vec![0u8; size - min.len()];
                out.extend_from_slice(&min);
                Ok(syn_bytes(out))
            }
            Some(other) => Err(err(format!(
                "int_to_bytes: size must be a non-negative integer, got {}",
                other.type_name()
            ))),
        }
    }

    /// `int_to_bytes_le(n, size)` → bytes **little-endian** de ancho fijo de un
    /// entero no-negativo (error si no entra — nunca trunca en silencio). El `size`
    /// es OBLIGATORIO: LE es formato de structs binarios de ancho fijo (los datos
    /// del System Program de Solana son u32/u64 LE), no de enteros mínimos.
    fn b_int_to_bytes_le(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let n = match nth(args, 0)? {
            SynValue::Number(n) => n,
            other => {
                return Err(err(format!(
                    "int_to_bytes_le expects a non-negative integer, got {}",
                    other.type_name()
                )))
            }
        };
        let min = n.to_be_bytes_min().ok_or_else(|| {
            err("int_to_bytes_le: the value must be a non-negative integer (no floats/decimals/negatives)")
        })?;
        let size = match nth(args, 1)? {
            SynValue::Number(sz) if sz.is_integer() => sz
                .to_i64_trunc()
                .filter(|s| *s >= 0)
                .ok_or_else(|| err("int_to_bytes_le: size must be a non-negative integer"))?
                as usize,
            other => {
                return Err(err(format!(
                    "int_to_bytes_le: size must be a non-negative integer, got {}",
                    other.type_name()
                )))
            }
        };
        if min.len() > size {
            return Err(err(format!(
                "int_to_bytes_le: the value needs {} bytes and does not fit in size {}",
                min.len(),
                size
            )));
        }
        let mut out: Vec<u8> = min.into_iter().rev().collect();
        out.resize(size, 0);
        Ok(syn_bytes(out))
    }

    // -- Aserciones (Batch 3) --

    /// `assert(cond, msg?)` → `nothing` si `cond` es truthy; si no, error de aserción con
    /// `msg` (o `"assertion failed"`).
    fn b_assert(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if nth(args, 0)?.is_truthy() {
            return Ok(SynValue::Nothing);
        }
        let msg = match args.get(1) {
            Some(m) => m.to_string(),
            None => "assertion failed".to_string(),
        };
        Err(err_assertion(msg))
    }

    /// `assert_eq(actual, expected, msg?)` → error si `!actual.syn_equals(expected)`. El
    /// mensaje usa `Display` para ambos valores (bytes muestran su repr hex).
    fn b_assert_eq(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let actual = nth(args, 0)?;
        let expected = nth(args, 1)?;
        if actual.syn_equals(expected) {
            return Ok(SynValue::Nothing);
        }
        let prefix = match args.get(2) {
            Some(m) => format!("{}: ", m),
            None => String::new(),
        };
        Err(err_assertion(format!("{}expected {}, got {}", prefix, expected, actual)))
    }

    /// `assert_ne(a, b, msg?)` → error si `a.syn_equals(b)` (se esperaba que difirieran).
    fn b_assert_ne(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let a = nth(args, 0)?;
        let b = nth(args, 1)?;
        if !a.syn_equals(b) {
            return Ok(SynValue::Nothing);
        }
        let prefix = match args.get(2) {
            Some(m) => format!("{}: ", m),
            None => String::new(),
        };
        Err(err_assertion(format!("{}expected values to differ, both {}", prefix, a)))
    }

    /// `assert_error(fn)` → llama `fn` (0 args) vía `call_value`; **pasa** si lanza
    /// `Control::Error`; **falla** si retorna normal. `Give`/`Stop` se propagan tal cual
    /// (un `give` NO es un error → una lambda que da `give` hace FALLAR la aserción).
    fn b_assert_error(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        if !matches!(func, SynValue::Task(_) | SynValue::Builtin(_)) {
            return Err(err_at(
                format!("assert_error expects a task or lambda, got {}", func.type_name()),
                loc,
            ));
        }
        match self.call_value(func, Vec::new(), loc) {
            // T5 (regla 1.a): un error nacido bajo PC privado / del enforcement tampoco se
            // atrapa aca (si no, `assert_error` seria el `try` del atacante).
            Err(Control::Error(e)) if self.labels && e.is_fatal_for_labels() => {
                Err(Control::Error(e))
            }
            // Lanzó un error → la aserción pasa.
            Err(Control::Error(_)) => Ok(SynValue::Nothing),
            // Retornó normal (incl. un `give`, que `call_value` materializa como Ok) → falla.
            Ok(_) => Err(err_assertion("expected an error, but none was raised")),
            // `give`/`stop` fuera de un task se propagan como hoy (no son "el error esperado").
            Err(other) => Err(other),
        }
    }

    /// `raise(message)` → SIEMPRE devuelve `Control::Error` con `message` coercionado a
    /// texto. Re-propaga un error capturado en `recover` (un agente con try/recover+raise
    /// termina en ERROR, no DONE). Sin argumentos → error claro. `give`/`stop` no se ven
    /// afectados (raise es siempre un error, no un control de flujo).
    fn b_raise(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        match args.first() {
            // La ubicación viaja con el error (sin ella el programa es indepurable:
            // Un `raise` perdía `file:line:col`). `try/recover` la sigue quitando del texto
            // que liga (`strip_loc_prefix`), así que el contrato del lenguaje no cambia.
            Some(v) => Err(err_at(raw_str(v), loc)),
            None => Err(err_at("raise expects a message", loc)),
        }
    }

    fn b_append(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let lst = nth(args, 0)?;
        let item = nth(args, 1)?.clone();
        match lst {
            SynValue::List(l) => {
                let mut v = l.borrow().clone();
                v.push(item);
                Ok(syn_list(v))
            }
            _ => Err(err("First argument to append must be a list")),
        }
    }

    /// `insert(xs, i, v)` → lista nueva con `v` en la posición `i` (v0.6.29). `set xs to
    /// insert(xs, i, v)` es en el lugar.
    fn b_insert(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::List(l) => {
                let mut v = l.borrow().clone();
                let j = insert_position(nth(args, 1)?, v.len()).map_err(|e| err_at(e, loc))?;
                v.insert(j, nth(args, 2)?.clone());
                Ok(syn_list(v))
            }
            other => Err(err_at(format!("insert(list, position, value): the first argument is {}, not a list", other.type_name()), loc)),
        }
    }

    /// `get(m, key)` / `get(m, key, default)` y `get(xs, i, default)`: el índice que no
    /// falla. Sin default, lo que falta es `nothing`.
    fn b_get(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.len() < 2 || args.len() > 3 {
            return Err(err(format!("get(collection, key, default?) takes 2 or 3 arguments, got {}", args.len())));
        }
        let default = args.get(2).cloned().unwrap_or(SynValue::Nothing);
        match &args[0] {
            SynValue::Map(m) => Ok(m.borrow().get(&args[1].to_string()).cloned().unwrap_or(default)),
            SynValue::List(l) => {
                let i = num_to_i64(&args[1])?;
                let items = l.borrow();
                Ok(resolve_index(i, items.len()).map(|j| items[j].clone()).unwrap_or(default))
            }
            SynValue::Server(sv) => Ok(sv.get_field(&args[1].to_string()).unwrap_or(default)),
            other => Err(err(format!("get() reads a map or a list, got {}", other.type_name()))),
        }
    }

    /// `remove(m, key)` → un mapa nuevo sin esa clave (si no estaba, igual al original).
    fn b_remove(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Map(m) => {
                let mut copy = m.borrow().clone();
                copy.shift_remove(&nth(args, 1)?.to_string());
                Ok(SynValue::Map(Rc::new(RefCell::new(copy))))
            }
            other => Err(err(format!("remove() takes a map, got {} — for a list use where(xs, …) or slice", other.type_name()))),
        }
    }

    /// `merge(a, b, …)` → un mapa nuevo; ante la misma clave gana el de más a la derecha.
    fn b_merge(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() {
            return Err(err("merge() needs at least one map"));
        }
        let mut out: IndexMap<String, SynValue> = IndexMap::new();
        for (i, a) in args.iter().enumerate() {
            match a {
                SynValue::Map(m) => {
                    for (k, v) in m.borrow().iter() {
                        out.insert(k.clone(), v.clone());
                    }
                }
                other => {
                    return Err(err(format!("merge(): argument {} is {}, not a map", i + 1, other.type_name())))
                }
            }
        }
        Ok(syn_map(out))
    }

    /// `items(m)` → `[{key, value}, …]` en orden de inserción (la forma de `enumerate`).
    fn b_items(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Map(m) => Ok(syn_list(
                m.borrow()
                    .iter()
                    .map(|(k, v)| {
                        let mut e = IndexMap::new();
                        e.insert("key".to_string(), syn_text(k.as_str()));
                        e.insert("value".to_string(), v.clone());
                        syn_map(e)
                    })
                    .collect(),
            )),
            other => Err(err(format!("items() takes a map, got {}", other.type_name()))),
        }
    }

    fn b_keys(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Map(m) => {
                let keys: Vec<SynValue> = m.borrow().keys().map(|k| syn_text(k.as_str())).collect();
                Ok(syn_list(keys))
            }
            // El resultado de `group_by` (una lista de `{key, items}` desde v0.6.29) es el
            // caso típico: decir cómo se lee.
            SynValue::List(l)
                if l.borrow().first().is_some_and(|g| {
                    matches!(g, SynValue::Map(m) if m.borrow().contains_key("key") && m.borrow().contains_key("items"))
                }) =>
            {
                Err(err(
                    "keys() requires a map — group_by returns a list of {key, items} (v0.6.29): the keys are apply(groups, (g) => g.key), the count is length(groups), or use count_by(rows, key)",
                ))
            }
            other => Err(err(format!("keys() requires a map, got {}", other.type_name()))),
        }
    }

    fn b_enumerate(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::List(l) => {
                let items: Vec<SynValue> = l
                    .borrow()
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let mut m = IndexMap::new();
                        m.insert("index".to_string(), syn_int(i as i64));
                        m.insert("item".to_string(), v.clone());
                        syn_map(m)
                    })
                    .collect();
                Ok(syn_list(items))
            }
            other => Err(err(format!("enumerate() requires a list, got {}", other.type_name()))),
        }
    }

    fn b_values(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Map(m) => {
                let vals: Vec<SynValue> = m.borrow().values().cloned().collect();
                Ok(syn_list(vals))
            }
            _ => Err(err("values() requires a map")),
        }
    }

    fn b_contains(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let collection = nth(args, 0)?;
        let item = nth(args, 1)?;
        match collection {
            SynValue::List(l) => {
                // Como `in`: un decimal contra un float es el error de `==`, no un "distinto".
                for e in l.borrow().iter() {
                    if crate::tabular::strict_equals(e, item).map_err(|_| err(format!("contains: {}", MIX_DECIMAL_FLOAT)))? {
                        return Ok(syn_bool(true));
                    }
                }
                Ok(syn_bool(false))
            }
            SynValue::Text(s) => Ok(syn_bool(s.contains(&raw_str(item)))),
            SynValue::Map(m) => Ok(syn_bool(m.borrow().contains_key(&raw_str(item)))),
            SynValue::Bytes(b) => match item {
                // Subsecuencia contigua de bytes; el vacío siempre está contenido.
                SynValue::Bytes(needle) => {
                    let found = needle.is_empty()
                        || (needle.len() <= b.len()
                            && b.windows(needle.len()).any(|w| w == &needle[..]));
                    Ok(syn_bool(found))
                }
                // Un byte suelto (entero 0..=255) presente en la secuencia.
                SynValue::Number(Number::Int(n)) if (0..=255).contains(n) => {
                    Ok(syn_bool(b.contains(&(*n as u8))))
                }
                other => Err(err(format!(
                    "contains(bytes, ...): expected bytes or an integer 0..=255, got {}",
                    other.type_name()
                ))),
            },
            _ => Err(err(format!("Cannot check containment in {}", collection.type_name()))),
        }
    }

    fn b_split(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let sep = raw_str(nth(args, 1)?);
        if sep.is_empty() {
            // v0.6.20 — separador vacío = los caracteres del texto (scalars Unicode), como
            // JS y como el rodeo `slice(t, i, i + 1)` que todo el mundo escribía.
            let chars: Vec<SynValue> = text.chars().map(|c| syn_text(c.to_string())).collect();
            return Ok(syn_list(chars));
        }
        let parts: Vec<SynValue> = text.split(&sep).map(syn_text).collect();
        Ok(syn_list(parts))
    }

    fn b_join(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let lst = nth(args, 0)?;
        let sep = raw_str(nth(args, 1)?);
        match lst {
            // Las mismas reglas que `+` con texto: texto, números y bools se pegan; `nothing`,
            // listas, mapas y bytes son error (pegarlos daba "a,nothing").
            SynValue::List(l) => {
                let items = l.borrow();
                let mut parts: Vec<String> = Vec::with_capacity(items.len());
                for (i, v) in items.iter().enumerate() {
                    if matches!(
                        v,
                        SynValue::Nothing | SynValue::List(_) | SynValue::Map(_) | SynValue::Bytes(_) | SynValue::Task(_) | SynValue::Builtin(_)
                    ) {
                        return Err(err(format!(
                            "join: item {} is {} — convert it on purpose (text(x)), or drop the missing ones first: where(xs, (x) => x != nothing)",
                            i + 1,
                            v.type_name()
                        )));
                    }
                    parts.push(v.to_string());
                }
                Ok(syn_text(parts.join(&sep)))
            }
            _ => Err(err("First argument to join must be a list")),
        }
    }

    fn b_range(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match args.len() {
            1 => {
                let n = num_to_i64(nth(args, 0)?)?;
                Ok(syn_list((0..n).map(syn_int).collect()))
            }
            2 => {
                let lo = num_to_i64(nth(args, 0)?)?;
                let hi = num_to_i64(nth(args, 1)?)?;
                Ok(syn_list((lo..hi).map(syn_int).collect()))
            }
            3 => {
                let lo = num_to_i64(nth(args, 0)?)?;
                let hi = num_to_i64(nth(args, 1)?)?;
                let step = num_to_i64(nth(args, 2)?)?;
                if step == 0 {
                    return Err(err("range() arg 3 must not be zero"));
                }
                let mut out = Vec::new();
                let mut i = lo;
                if step > 0 {
                    while i < hi {
                        out.push(syn_int(i));
                        i += step;
                    }
                } else {
                    while i > hi {
                        out.push(syn_int(i));
                        i += step;
                    }
                }
                Ok(syn_list(out))
            }
            _ => Err(err("range() takes 1-3 arguments")),
        }
    }

    fn b_type_of(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(nth(args, 0)?.type_name()))
    }

    // -- etiquetas de flujo por principal (labels.rs) --

    /// `private(v, principal | [principales])` → `v` etiquetado (unión si ya lo estaba, y
    /// con la etiqueta de PC del contexto). Un `secret` no se etiqueta (ya es opaco). Con las
    /// etiquetas apagadas es un error claro: el programa está escrito para `--labels`.
    fn b_private(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let literals = self.arg_literals;
        if !self.labels {
            return Err(err_labels("private: labels are off; run with --labels or serve --attested", loc));
        }
        if args.len() != 2 {
            return Err(err_labels(
                format!("private: expects 2 arguments (value, principal), got {}", args.len()),
                loc,
            ));
        }
        let v = &args[0];
        if v.is_secret() {
            return Err(err_labels(
                "private: a secret is already opaque; use private on the value you compute",
                loc,
            ));
        }
        let l = principals_arg(&args[1], "private", false, literals & 0b10 != 0, loc)?;
        // M1: el principal vino de un literal del fuente → es texto del programa.
        //
        // T5 (ronda 7) — **NO alimenta el conjunto con el que se redacta.** Ese conjunto sale del
        // recorrido ESTÁTICO del AST (`set_declared_principals`) justamente porque un `private`
        // que corre o no según un secreto haría variar el texto otra vez:
        // `when s == 0 / let a be private(1, "p0") / otherwise / let a be private(1, "p1")`.
        for p in l.iter() {
            self.known_principals.borrow_mut().insert(p.to_string());
        }
        let l = labels::union(&l, &self.pc_label());
        self.note_seen(&l);
        // Regla 2 (1.f): `mark_owned` COPIA el contenedor antes de envolverlo. Compartiendo el
        // `Rc`, `let priv be private(pub, "app")` fabricaba un alias privado sobre el objeto
        // PUBLICO: escribir por el alias (legal, cubre el PC) mutaba el original publico.
        Ok(labels::mark_owned(&v, l))
    }

    /// `declassify(v, reason, to?)` → `v` con la etiqueta REDUCIDA a `to` (público sin `to`).
    /// Nunca amplía (`to ⊆ etiqueta actual`, si no error). Registra motivo/from/to/ubicación
    /// En `declassify_log` (y en el `log_hook` del host, si hay). Con las etiquetas apagadas
    /// Es la identidad; el motivo se valida igual (es parte del programa, no del modo).
    fn b_declassify(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let literals = self.arg_literals;
        if args.len() < 2 || args.len() > 3 {
            return Err(err_labels(
                format!("declassify: expects 2 or 3 arguments (value, reason, to?), got {}", args.len()),
                loc,
            ));
        }
        // M3 : el motivo es METADATO PUBLICO — va al log del host y al registro
        // que lee el auditor. Tiene que ser un literal de texto EN ESTA llamada o un valor sin
        // etiquetas: permitir `subset(PC)` dejaba meter un dato privado (un numero de tarjeta)
        // Como motivo y verlo en claro en el log.
        let pc = self.pc_label();
        let rl = labels::label_deep(&args[1]);
        if !rl.is_empty() && literals & 0b10 == 0 {
            return Err(err_labels(
                format!(
                    "declassify: reason must be public (a text literal at this call, or a value with no labels), it is private to {}",
                    self.safe_label(&rl)
                ),
                loc,
            ));
        }
        let reason = match labels::unwrap(&args[1]) {
            SynValue::Text(s) if !s.trim().is_empty() => s.to_string(),
            _ => return Err(err_labels("declassify: reason must be a non-empty text", loc)),
        };
        if !self.labels {
            return Ok(args[0].clone());
        }
        let v = &args[0];
        // B6: el origen REAL es la etiqueta profunda del valor ∪ el PC del contexto — un
        // literal declassificado dentro de una rama privada sale de `from [pc]`, y así queda
        // registrado para el auditor.
        let from = labels::union(&labels::label_deep(v), &pc);
        let to = match args.get(2) {
            Some(t) if !matches!(labels::unwrap(t), SynValue::Nothing) => {
                principals_arg(t, "declassify", true, literals & 0b100 != 0, loc)?
            }
            _ => labels::empty(),
        };
        if !labels::subset(&to, &from) {
            return Err(err_labels(
                format!(
                    // T5 (ronda 8): no se imprime la etiqueta del VALOR (varía con cuál es, y
                    // por ahí salía el dato). El `to` sí: es el literal escrito en esta llamada.
                    // Y con el `from` constante el texto viejo quedaba absurdo ("from [a,b] to
                    // [a,b]"), así que el mensaje dice qué pasó y qué escribir en su lugar.
                    "declassify: cannot widen a label — [{}] is not a subset of what this value is private to, and `declassify` may only narrow. Drop the third argument to publish it, or narrow to a subset of its own principals",
                    label_display_raw(&to)
                ),
                loc,
            ));
        }
        // T5 (ronda 7) — el `from` que sale al log NO es la etiqueta de ESTE valor. Varía con
        // cuál se seleccionó, igual que la redacción: `declassify(xs[idx_privado], …)` daba
        // `from [app,p0]` o `from [app,p1]` según el índice, o sea el rastro de auditoría
        // publicaba el dato que el `declassify` estaba documentando. Sale el conjunto DECLARADO,
        // constante. El `to` sí es de la etiqueta real: es el literal escrito en ESTE sitio, que
        // no depende del valor. La revisión de verdad es `code check --json`, que es estática.
        if let Some(hook) = &self.log_hook {
            hook(&format!(
                "[INF] declassify: {} (from [{}] to [{}]) at {}:{}",
                reason,
                self.safe_label(&from),
                label_display_raw(&to),
                loc.file,
                loc.line
            ));
        }
        self.declassify_log.push(DeclassifyEntry { reason, from: from.clone(), to: to.clone(), loc: loc.clone() });
        self.note_seen(&from);
        Ok(labels::mark(labels::strip_deep(v), to))
    }

    /// `label_of(v)` → lista de principales (union PROFUNDA); `[]` si es publico o con las
    /// etiquetas apagadas.
    ///
    /// Regla 3.b (1.g): el RESULTADO sale etiquetado con `label_deep(v)` union PC. Devolverlo
    /// publico lo convertia en un oraculo: escribir en un contenedor ya privado un valor de
    /// OTRO principal es legal, y `length(label_of(m)) == 2` leia ese hecho —que depende de
    /// datos privados— como booleano publico.
    fn b_label_of(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        if !self.labels {
            return Ok(syn_list(Vec::new()));
        }
        let l = labels::label_deep(v);
        let meta = labels::union(&l, &self.pc_label());
        // Los elementos (texto) llevan la etiqueta: `label_deep` de la lista la ve, y la lista
        // En si queda sin envolver (regla 2: el PC no asciende contenedores).
        Ok(syn_list(
            l.iter().map(|p| labels::mark(SynValue::Text(p.clone()), meta.clone())).collect(),
        ))
    }

    /// `is_private(v)` → ¿lleva alguna etiqueta (a cualquier profundidad)? `false` apagado.
    /// Regla 3.b: el booleano sale etiquetado con `label_deep(v)` union PC (mismo oraculo que
    /// `label_of`).
    fn b_is_private(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        if !self.labels {
            return Ok(syn_bool(false));
        }
        let meta = labels::union(&labels::label_deep(v), &self.pc_label());
        Ok(labels::mark(syn_bool(labels::has_label_deep(v)), meta))
    }

    fn b_slice(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let coll = nth(args, 0)?;
        let start = if args.len() > 1 { num_to_i64(&args[1])? } else { 0 };
        let end = if args.len() > 2 { Some(num_to_i64(&args[2])?) } else { None };
        match coll {
            SynValue::List(l) => {
                let items = l.borrow();
                let (s, e) = py_slice_range(items.len(), start, end);
                Ok(syn_list(items[s..e].to_vec()))
            }
            SynValue::Text(t) => {
                let chars: Vec<char> = t.chars().collect();
                let (s, e) = py_slice_range(chars.len(), start, end);
                Ok(syn_text(chars[s..e].iter().collect::<String>()))
            }
            SynValue::Bytes(b) => {
                let (s, e) = py_slice_range(b.len(), start, end);
                Ok(syn_bytes(b[s..e].to_vec()))
            }
            // v0.6.29 (DATOS-11): filas `start..end` (el primer eje), negativos incluidos.
            SynValue::Array(a) => {
                if a.ndim() == 0 {
                    return Err(err("Cannot slice a 0-dimensional array"));
                }
                let (s, e) = py_slice_range(a.shape()[0], start, end);
                Ok(crate::types::syn_array(
                    a.slice_axis(ndarray::Axis(0), ndarray::Slice::from(s..e)).to_owned(),
                ))
            }
            _ => Err(err(format!("Cannot slice {}", coll.type_name()))),
        }
    }

    /// `fmt(template, values)`: reemplaza cada `{nombre}` por su valor. Un `{nombre}` sin
    /// valor es error (v0.6.29: antes quedaba tal cual, en silencio). `{{` y `}}` escriben
    /// una llave literal; una llave que no rodea un nombre queda como está (JSON, CSS).
    fn b_fmt(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let template = raw_str(nth(args, 0)?);
        let values = match args.get(1) {
            None | Some(SynValue::Nothing) => None,
            Some(SynValue::Map(m)) => Some(m.borrow().clone()),
            Some(other) => return Err(err(format!("fmt(template, values): values must be a map, got {}", other.type_name()))),
        };
        let chars: Vec<char> = template.chars().collect();
        let mut out = String::with_capacity(template.len());
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '{' && chars.get(i + 1) == Some(&'{') {
                out.push('{');
                i += 2;
                continue;
            }
            if c == '}' && chars.get(i + 1) == Some(&'}') {
                out.push('}');
                i += 2;
                continue;
            }
            if c == '{' {
                // Lo que está entre llaves, si es EXACTAMENTE una clave del mapa, se sustituye
                // siempre, tenga la forma que tenga (`{0}`, `{a-b}`, `{ x }` si la clave es " x ").
                if let Some(close) = chars[i + 1..].iter().position(|&ch| ch == '}' || ch == '{') {
                    let close = i + 1 + close;
                    if chars[close] == '}' {
                        let inner: String = chars[i + 1..close].iter().collect();
                        if let Some(v) = values.as_ref().and_then(|m| m.get(&inner)) {
                            out.push_str(&v.to_string());
                            i = close + 1;
                            continue;
                        }
                    }
                }
                // `{name}` y `{a.b}`: la clave EXACTA `"a.b"` si está; si no, el campo `b` del mapa
                // `a`. Con espacios (`{ x }`, CSS/JS) queda literal, como siempre.
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_' || chars[j] == '.') {
                    j += 1;
                }
                let end = j;
                // Un hueco es `nombre(.nombre)*` con nombres que empiezan con letra o `_`: `{3}`,
                // `{3,5}` (cuantificadores de regex), `{a..b}` y `{a.}` quedan literales.
                let is_hole = end > start
                    && chars[start..end].split(|c| *c == '.').all(|seg| {
                        seg.first().is_some_and(|c| c.is_alphabetic() || *c == '_')
                    });
                if is_hole && chars.get(j) == Some(&'}') {
                    let name: String = chars[start..end].iter().collect();
                    let mut cur = values.as_ref().and_then(|m| m.get(&name)).cloned();
                    if cur.is_none() && name.contains('.') {
                        let mut parts = name.split('.');
                        let first = parts.next().unwrap_or("");
                        // `{obj.prop}` sin `obj` en el mapa: texto de otro lenguaje, queda literal.
                        if values.as_ref().is_none_or(|m| !m.contains_key(first)) {
                            out.push_str(&chars[i..=j].iter().collect::<String>());
                            i = j + 1;
                            continue;
                        }
                        cur = values.as_ref().and_then(|m| m.get(first)).cloned();
                        for p in parts {
                            cur = match cur {
                                Some(SynValue::Map(m)) => m.borrow().get(p).cloned(),
                                _ => None,
                            };
                        }
                    }
                    match cur {
                        Some(v) => out.push_str(&v.to_string()),
                        None => {
                            return Err(err(format!(
                                "fmt: no value for {{{}}} — pass it in the map, or write {{{{{}}}}} for a literal brace",
                                name, name
                            )))
                        }
                    }
                    i = j + 1;
                    continue;
                }
            }
            out.push(c);
            i += 1;
        }
        Ok(syn_text(out))
    }

    fn b_upper(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(raw_str(nth(args, 0)?).to_uppercase()))
    }
    fn b_lower(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(raw_str(nth(args, 0)?).to_lowercase()))
    }
    /// `fold(text)`: minúsculas + sin diacríticos, para matching tolerante a acentos.
    /// Pliega los acentos latinos comunes (Latin-1 Supplement + Latin Extended-A) a su
    /// base ASCII; cualquier otro carácter pasa igual. Puro, sin capability.
    fn b_fold(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let lowered = raw_str(nth(args, 0)?).to_lowercase();
        let mut out = String::with_capacity(lowered.len());
        for c in lowered.chars() {
            match c {
                'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
                'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => out.push('e'),
                'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ı' => out.push('i'),
                'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => out.push('o'),
                'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => out.push('u'),
                'ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
                'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => out.push('c'),
                'ý' | 'ÿ' => out.push('y'),
                'ś' | 'ŝ' | 'ş' | 'š' => out.push('s'),
                'ź' | 'ż' | 'ž' => out.push('z'),
                'ĝ' | 'ğ' | 'ġ' | 'ģ' => out.push('g'),
                'ð' => out.push('d'),
                'þ' => out.push_str("th"),
                'ß' => out.push_str("ss"),
                'æ' => out.push_str("ae"),
                'œ' => out.push_str("oe"),
                other => out.push(other),
            }
        }
        Ok(syn_text(out))
    }
    /// Vuelca a stdout (en vivo) lo acumulado en `self.output` y limpia el buffer. Lo que
    /// se drena se quita de `output` → `cmd_run` no lo re-imprime al final, y `conform`
    /// sólo ve lo que el programa NO drenó (los tests de conform no llaman flush/read_line).
    fn drain_output(&mut self) {
        use std::io::Write;
        // Con la terminal en raw mode (`term_open`) un `\n` solo no vuelve al margen: la
        // salida "escalera". Se escribe `\r\n` sólo en ese estado.
        let raw = crate::term_guard::is_raw();
        for line in self.output.drain(..) {
            if raw {
                print!("{}\r\n", line.replace('\n', "\r\n"));
            } else {
                println!("{}", line);
            }
        }
        let _ = std::io::stdout().flush();
    }
    /// `flush()`: salida en vivo (REPLs/loops largos). Vuelca `output` pendiente a stdout.
    /// Sólo actúa en `run` interactivo (`live_output`); bajo `conform`/`test`/`serve` es
    /// no-op → la salida queda en `output` y entra al JSON/respuesta (DE-019).
    fn b_flush(&mut self) -> Result<SynValue, Control> {
        if self.live_output {
            self.drain_output();
        }
        Ok(SynValue::Nothing)
    }
    /// `read_line(prompt?)`: lee una línea de stdin (CLI). Si hay prompt, lo imprime sin
    /// newline antes de leer. Devuelve el texto sin el `\n`/`\r\n` final; `nothing` en EOF.
    /// Lee stdin crudo → funciona con TTY y con entrada redirigida/pipe (a diferencia de
    /// `ask`, que es un backend de decisión humana).
    fn b_read_line(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        use std::io::Write;
        // Drena la salida pendiente (respuesta del turno previo) ANTES del prompt, para
        // que un REPL sea interactivo de verdad (DE-018) sin requerir flush() explícito.
        // Sólo en `run` interactivo; bajo conform/test/serve no se drena (DE-019). La
        // LECTURA de stdin se hace igual en cualquier modo.
        if self.live_output {
            self.drain_output();
        }
        if let Some(p) = args.first() {
            if !matches!(p, SynValue::Nothing) {
                // El prompt ES salida: bajo un techo sin `stdout` no debe escaparse por acá
                // (print/show/log ya lo chequean; read_line era el único hueco).
                self.ensure_stdout()?;
                print!("{}", raw_str(p));
                let _ = std::io::stdout().flush();
            }
        }
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => Ok(SynValue::Nothing), // EOF
            Ok(_) => {
                let s = line.strip_suffix('\n').unwrap_or(&line);
                let s = s.strip_suffix('\r').unwrap_or(s);
                Ok(syn_text(s))
            }
            Err(_) => Ok(SynValue::Nothing),
        }
    }
    fn b_trim(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(raw_str(nth(args, 0)?).trim().to_string()))
    }
    fn b_starts_with(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_bool(raw_str(nth(args, 0)?).starts_with(&raw_str(nth(args, 1)?))))
    }
    fn b_ends_with(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_bool(raw_str(nth(args, 0)?).ends_with(&raw_str(nth(args, 1)?))))
    }
    fn b_replace_text(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let s = raw_str(nth(args, 0)?);
        let from = raw_str(nth(args, 1)?);
        let to = raw_str(nth(args, 2)?);
        Ok(syn_text(s.replace(&from, &to)))
    }
    fn b_strip_ansi(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_text(strip_ansi(&raw_str(nth(args, 0)?))))
    }

    // -- Regex --

    fn b_matches(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let pat = raw_str(nth(args, 1)?);
        let re = compile_re_full(&pat)?;
        Ok(syn_bool(re.is_match(&text)))
    }

    fn b_find_all(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let pat = raw_str(nth(args, 1)?);
        let re = compile_re(&pat)?;
        let out: Vec<SynValue> = re.find_iter(&text).map(|m| syn_text(m.as_str())).collect();
        Ok(syn_list(out))
    }

    /// `regex_capture(text, re)` → SIEMPRE una lista (los grupos; sin grupos, `[match]`) o
    /// `nothing` si no hay coincidencia. Un grupo opcional que no participó es `nothing`.
    fn b_regex_capture(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let pat = raw_str(nth(args, 1)?);
        let re = compile_re(&pat)?;
        match re.captures(&text) {
            None => Ok(SynValue::Nothing),
            Some(caps) => {
                let ngroups = re.captures_len() - 1;
                if ngroups == 0 {
                    return Ok(syn_list(vec![syn_text(caps.get(0).unwrap().as_str())]));
                }
                Ok(syn_list(
                    (1..=ngroups)
                        .map(|i| caps.get(i).map(|m| syn_text(m.as_str())).unwrap_or(SynValue::Nothing))
                        .collect(),
                ))
            }
        }
    }

    fn b_capture(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let pat = raw_str(nth(args, 1)?);
        let re = compile_re(&pat)?;
        match re.captures(&text) {
            None => Ok(SynValue::Nothing),
            Some(caps) => {
                let ngroups = re.captures_len() - 1;
                if ngroups > 0 {
                    let mut out = Vec::with_capacity(ngroups);
                    for i in 1..=ngroups {
                        match caps.get(i) {
                            Some(m) => out.push(syn_text(m.as_str())),
                            None => out.push(SynValue::Nothing),
                        }
                    }
                    Ok(syn_list(out))
                } else {
                    Ok(syn_text(caps.get(0).unwrap().as_str()))
                }
            }
        }
    }

    fn b_replace_re(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let text = raw_str(nth(args, 0)?);
        let pat = raw_str(nth(args, 1)?);
        let repl = raw_str(nth(args, 2)?);
        let re = compile_re(&pat)?;
        let rust_repl = translate_replacement(&repl);
        Ok(syn_text(re.replace_all(&text, rust_repl.as_str()).into_owned()))
    }

    fn b_render(&mut self, _args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Err(err("render is only available through the Synsema engine runtime"))
    }

    // =========================================================
    // operaciones intencionales
    // =========================================================

    fn list_arg(&self, v: &SynValue, who: &str) -> Result<Vec<SynValue>, Control> {
        match v {
            SynValue::List(l) => Ok(l.borrow().clone()),
            _ => Err(err(format!("{} expects a list, got {}", who, v.type_name()))),
        }
    }

    /// Dual-order de la familia intencional (batch DX, decisión #16 del diseño madre):
    /// los ops con callable aceptan `(fn, lista, …)` Y `(lista, fn, …)` — task/lambda
    /// y lista son tipos distinguibles en runtime, así que no hay ambigüedad y ambas
    /// lecturas inglesas quedan válidas. UNA regla, cero heurística por-op:
    ///   - primer arg callable → orden clásico `(fn, lista)`;
    ///   - primer arg lista → orden familia `(lista, fn)`;
    ///   - dos callables / dos listas → error explícito con AMBAS firmas (G-2: jamás
    ///     adivinar).
    /// Los args extra (pred de `transform`, init de `reduce`) NO se reordenan: la
    /// detección mira SOLO las posiciones 0-1.
    fn dual_fn_list(
        &self,
        args: &[SynValue],
        op: &str,
    ) -> Result<(SynValue, Vec<SynValue>), Control> {
        let a0 = nth(args, 0)?;
        let a1 = nth(args, 1)?;
        match (is_callable(a0), is_callable(a1)) {
            (true, true) => Err(err(format!(
                "{op}: expected one task and one list (either order: {op}(fn, list, ...) or {op}(list, fn, ...)), got two tasks"
            ))),
            (true, false) => Ok((a0.clone(), self.list_arg(a1, op)?)),
            (false, true) => Ok((a1.clone(), self.list_arg(a0, op)?)),
            (false, false) => {
                let l0 = matches!(a0, SynValue::List(_));
                let l1 = matches!(a1, SynValue::List(_));
                if l0 && l1 {
                    return Err(err(format!(
                        "{op}: expected one task and one list (either order: {op}(fn, list, ...) or {op}(list, fn, ...)), got two lists"
                    )));
                }
                // Uno (a lo sumo) es lista y el otro no es callable: se conserva el
                // camino del orden que corresponde — el error de tipo lo produce
                // `list_arg` o el intento de llamada, como hoy (mensajes ya claros).
                if l0 {
                    Ok((a1.clone(), self.list_arg(a0, op)?))
                } else {
                    Ok((a0.clone(), self.list_arg(a1, op)?))
                }
            }
        }
    }

    /// Variante de tres args para `zip_with` (espera DOS listas y un callable):
    /// callable primero → `(fn, a, b)`; lista primero → `(a, b, fn)` y el tercer arg
    /// DEBE ser callable (si no, error explícito con ambas firmas — G-2).
    fn dual_fn_two_lists(
        &self,
        args: &[SynValue],
        op: &str,
    ) -> Result<(SynValue, Vec<SynValue>, Vec<SynValue>), Control> {
        let a0 = nth(args, 0)?;
        if is_callable(a0) {
            let a = self.list_arg(nth(args, 1)?, op)?;
            let b = self.list_arg(nth(args, 2)?, op)?;
            return Ok((a0.clone(), a, b));
        }
        let a2 = nth(args, 2)?;
        if !is_callable(a2) {
            return Err(err(format!(
                "{op}: expected two lists and one task (either order: {op}(fn, list_a, list_b) or {op}(list_a, list_b, fn)), got {} as the combiner",
                a2.type_name()
            )));
        }
        let a = self.list_arg(a0, op)?;
        let b = self.list_arg(nth(args, 1)?, op)?;
        Ok((a2.clone(), a, b))
    }

    fn b_apply(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // v0.6.29 (DATOS-11): sobre un array, elemento a elemento → array de la misma forma.
        if let Some((func, a)) = fn_and_array(args) {
            let mut out = Vec::with_capacity(a.len());
            for x in a.iter() {
                match self.call_value(func.clone(), vec![syn_float(*x)], loc)? {
                    SynValue::Number(n) => out.push(n.to_f64()),
                    other => {
                        return Err(err(format!(
                            "apply over an array needs numbers back, got {} — use to_list(a) for other results",
                            other.type_name()
                        )))
                    }
                }
            }
            return Ok(crate::types::syn_array(
                ndarray::ArrayD::from_shape_vec(a.raw_dim(), out).map_err(|e| err(e.to_string()))?,
            ));
        }
        let (func, items) = self.dual_fn_list(args, "apply")?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(self.call_value(func.clone(), vec![item], loc)?);
        }
        Ok(syn_list(out))
    }

    /// `call(task, args_map)` — despacha `task` con args nombrados tomados del map
    /// (clave→param). `call(task, nothing)` → sin args. Delega en `call_value_named`
    /// (binding + defaults + give-unwrap ya existentes). NO toca `apply`.
    fn b_call(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        let named: Vec<(Option<String>, SynValue)> = match nth(args, 1)? {
            SynValue::Map(m) => {
                m.borrow().iter().map(|(k, v)| (Some(k.clone()), v.clone())).collect()
            }
            SynValue::Nothing => Vec::new(),
            other => {
                return Err(err_at(
                    format!("call expects a map of named args, got {}", other.type_name()),
                    loc,
                ))
            }
        };
        self.call_value_named(func, named, loc)
    }

    /// `call_tool(task, args_map)` — despacha `task` COMO TOOL: igual que `call`, pero
    /// corre su cuerpo con LEAST-PRIVILEGE. El `CapabilitySet` queda restringido a las
    /// caps que la tool DECLARÓ (su `require` por-tool) ∩ las que el agente ya tenía,
    /// SIN heredar el resto → el `require` por-tool pasa a estar ENFORCED por el
    /// lenguaje (no es metadata). Restaura SIEMPRE (también si la tool falla). Sin
    /// `tool_scope_hook` cableado → corre con las caps ambientes (no-op).
    fn b_call_tool(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        let named: Vec<(Option<String>, SynValue)> = match nth(args, 1)? {
            SynValue::Map(m) => {
                m.borrow().iter().map(|(k, v)| (Some(k.clone()), v.clone())).collect()
            }
            SynValue::Nothing => Vec::new(),
            other => {
                return Err(err_at(
                    format!("call_tool expects a map of named args, got {}", other.type_name()),
                    loc,
                ))
            }
        };
        // Las caps que la tool declaró (vacío si no es una task o no declara ninguna).
        let declared: Vec<(String, Option<String>)> = match &func {
            SynValue::Task(t) => t.required_capabilities.clone(),
            _ => Vec::new(),
        };
        // Entrar al scope restringido y SIEMPRE restaurar (incluido el camino de error,
        // por eso no se usa `?` sobre el resultado del cuerpo).
        if let Some(hook) = self.tool_scope_hook.clone() {
            hook(true, &declared);
        }
        // Marca el scope para que un `require` ANIDADO en el cuerpo (no extraído a
        // required_capabilities) sea no-op y no pueda auto-concederse caps (espejo del
        // sandbox). Decremento garantizado (también si el cuerpo falla).
        self.tool_scope_depth += 1;
        let result = self.call_value_named(func, named, loc);
        self.tool_scope_depth -= 1;
        if let Some(hook) = self.tool_scope_hook.clone() {
            hook(false, &[]);
        }
        result
    }

    /// `llm_step(prompt, catalog, context)` — un paso del LLM tool-aware (FASE 1).
    /// GATEADO por la capability `llm` (reusa `check_llm_cap`). Parsea el catálogo
    /// (lista de maps `{name, describe/description, params}`), llama el callback de
    /// paso (o un placeholder si no hay provider cableado) y devuelve un map
    /// `{kind:"final", text, tokens}` | `{kind:"tool", name, args:{…}, tokens}`.
    fn b_llm_step(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        self.check_llm_cap()?; // GATE por `llm` (mismo hook que reason/decide/…)
        let prompt = raw_str(nth(args, 0)?);
        let catalog = parse_catalog(args.get(1));
        let context = match args.get(2) {
            Some(SynValue::Text(s)) => s.to_string(),
            Some(SynValue::Nothing) | None => String::new(),
            Some(v) => v.to_string(),
        };
        let result = match &self.llm_step_callback {
            Some(cb) => cb(&prompt, &catalog, &context),
            // Sin provider cableado (camino `run` normal): placeholder seguro. El
            // programa decide qué hacer; no inventa tool-calls.
            None => {
                note_llm_offline();
                StepResult::Final { text: "[no llm provider]".to_string(), tokens: 0 }
            }
        };
        Ok(step_result_to_synvalue(result))
    }

    /// `llm_stream(prompt, context, on_chunk)` — genera con el provider configurado
    /// invocando la task/lambda `on_chunk` con cada fragmento de texto a medida que se
    /// produce, y devuelve el texto completo (F2). GATEADO por la capability `llm`
    /// (mismo hook que reason/llm_step). Si `on_chunk` falla (p.ej. el `send` de un
    /// cliente SSE desconectado → CLIENT_GONE), la generación se CORTA (el sink devuelve
    /// `false` al provider) y el error PROPAGA — el stream se desenrolla exactamente
    /// como cualquier `send` fallido de serve. Sin provider cableado: placeholder
    /// `"[no llm provider]"` SIN invocar `on_chunk` (los placeholders no son respuestas).
    fn b_llm_stream(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        self.check_llm_cap()?; // GATE por `llm` (mismo hook que reason/decide/…)
        let prompt = raw_str(nth(args, 0)?);
        let context = match args.get(1) {
            Some(SynValue::Text(s)) => s.to_string(),
            Some(SynValue::Nothing) | None => String::new(),
            Some(v) => v.to_string(),
        };
        let on_chunk = nth(args, 2)?.clone();
        let cb = match &self.llm_stream_callback {
            Some(cb) => cb.clone(),
            None => {
                note_llm_offline();
                return Ok(syn_text("[no llm provider]"));
            }
        };
        // El sink invoca la task/lambda del usuario por chunk. Un error ahí no puede
        // atravesar el provider (la firma del sink es `-> bool`), así que se guarda acá
        // y el sink devuelve `false` → el provider corta; al volver, el error propaga.
        let mut chunk_err: Option<Control> = None;
        let full = cb(&prompt, &context, &mut |chunk: &str| {
            match self.call_value(on_chunk.clone(), vec![syn_text(chunk)], loc) {
                Ok(_) => true,
                Err(e) => {
                    chunk_err = Some(e);
                    false
                }
            }
        });
        if let Some(e) = chunk_err {
            return Err(e);
        }
        Ok(syn_text(full))
    }

    fn b_where(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // v0.6.29 (DATOS-11): la máscara con nombre — los elementos que cumplen, como array 1-D.
        if let Some((pred, a)) = fn_and_array(args) {
            let mut out = Vec::new();
            for x in a.iter() {
                if self.call_value(pred.clone(), vec![syn_float(*x)], loc)?.is_truthy() {
                    out.push(*x);
                }
            }
            let n = out.len();
            return Ok(crate::types::syn_array(
                ndarray::ArrayD::from_shape_vec(ndarray::IxDyn(&[n]), out).map_err(|e| err(e.to_string()))?,
            ));
        }
        let (pred, items) = self.dual_fn_list(args, "where")?;
        let mut out = Vec::new();
        for item in items {
            if self.call_value(pred.clone(), vec![item.clone()], loc)?.is_truthy() {
                out.push(item);
            }
        }
        Ok(syn_list(out))
    }

    fn b_collect(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "collect")?;
        let prop = raw_str(nth(args, 1)?);
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            match &item {
                SynValue::Map(m) => match m.borrow().get(&prop) {
                    Some(v) => out.push(v.clone()),
                    None => out.push(SynValue::Nothing),
                },
                _ => out.push(SynValue::Nothing),
            }
        }
        Ok(syn_list(out))
    }

    fn b_transform(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // Dual-order sólo en las posiciones 0-1; el `pred` opcional queda al final.
        let (func, items) = self.dual_fn_list(args, "transform")?;
        let pred = args.get(2).cloned();
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let should = match &pred {
                Some(p) => self.call_value(p.clone(), vec![item.clone()], loc)?.is_truthy(),
                None => true,
            };
            if should {
                out.push(self.call_value(func.clone(), vec![item], loc)?);
            } else {
                out.push(item);
            }
        }
        Ok(syn_list(out))
    }

    fn b_reduce(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // Dual-order sólo en las posiciones 0-1; `init` (aunque sea callable) queda al
        // final y NO participa de la detección.
        let (func, items) = self.dual_fn_list(args, "reduce")?;
        let mut acc = args.get(2).cloned().unwrap_or_else(|| syn_int(0));
        for item in items {
            acc = self.call_value(func.clone(), vec![acc, item], loc)?;
        }
        Ok(acc)
    }

    fn b_sort_by(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (key_func, items) = self.dual_fn_list(args, "sort_by")?;
        let desc = desc_flag(args.get(2), "sort_by")?;
        let mut keyed: Vec<(SynValue, SynValue)> = Vec::with_capacity(items.len());
        for it in items {
            let k = self.call_value(key_func.clone(), vec![it.clone()], loc)?;
            keyed.push((k, it));
        }
        let keys: Vec<SynValue> = keyed.iter().map(|(k, _)| k.clone()).collect();
        check_orderable(&keys, "sort_by")?;
        sort_checked(&mut keyed, |(k, _)| k, desc, "sort_by")?;
        Ok(syn_list(keyed.into_iter().map(|(_, v)| v).collect()))
    }

    /// `sort(xs)` / `sort(xs, desc = true)`: orden total y estable de los valores mismos.
    fn b_sort(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let mut items = self.list_arg(nth(args, 0)?, "sort")?;
        let desc = desc_flag(args.get(1), "sort")?;
        check_orderable(&items, "sort")?;
        sort_checked(&mut items, |v| v, desc, "sort")?;
        Ok(syn_list(items))
    }

    fn b_find_first(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, items) = self.dual_fn_list(args, "find_first")?;
        for item in items {
            if self.call_value(pred.clone(), vec![item.clone()], loc)?.is_truthy() {
                return Ok(item);
            }
        }
        Ok(SynValue::Nothing)
    }

    fn b_every(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, items) = self.dual_fn_list(args, "every")?;
        for item in items {
            if !self.call_value(pred.clone(), vec![item], loc)?.is_truthy() {
                return Ok(syn_bool(false));
            }
        }
        Ok(syn_bool(true))
    }

    fn b_some(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, items) = self.dual_fn_list(args, "some")?;
        for item in items {
            if self.call_value(pred.clone(), vec![item], loc)?.is_truthy() {
                return Ok(syn_bool(true));
            }
        }
        Ok(syn_bool(false))
    }

    fn b_count_where(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, items) = self.dual_fn_list(args, "count_where")?;
        let mut count: i64 = 0;
        for item in items {
            if self.call_value(pred.clone(), vec![item], loc)?.is_truthy() {
                count += 1;
            }
        }
        Ok(syn_int(count))
    }

    fn b_flatten(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        // Array (Batch 5): aplana a un array 1D (row-major). Listas: comportamiento previo
        // (aplana UN nivel de anidamiento). Polimórfico → no rompe el `flatten` de listas (G1).
        if matches!(nth(args, 0)?, SynValue::Array(_)) {
            return crate::arrays::flatten(args);
        }
        let items = self.list_arg(nth(args, 0)?, "flatten")?;
        let mut out = Vec::new();
        for item in items {
            match &item {
                SynValue::List(l) => out.extend(l.borrow().iter().cloned()),
                _ => out.push(item),
            }
        }
        Ok(syn_list(out))
    }

    fn b_zip_with(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (combiner, a, b) = self.dual_fn_two_lists(args, "zip_with")?;
        let mut out = Vec::new();
        for (x, y) in a.into_iter().zip(b) {
            out.push(self.call_value(combiner.clone(), vec![x, y], loc)?);
        }
        Ok(syn_list(out))
    }

    /// `unique(lista)` — deduplica preservando el orden de PRIMERA aparición. La
    /// igualdad es la estructural del lenguaje (`syn_equals`, la misma de `==`/
    /// `contains`) — NO se reimplementa. O(n²) a propósito: hashear divergiría de la
    /// igualdad estructural (maps/listas anidadas, números cross-repr).
    /// v0.6.20 — `reverse(lista)` → lista al revés; `reverse(texto)` → texto al revés por
    /// scalar Unicode (no grapheme-aware, mismo criterio que `slice`). Valor nuevo, el
    /// original no se toca (como `append` y toda la familia).
    fn b_reverse(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Text(s) => Ok(syn_text(s.chars().rev().collect::<String>())),
            other => {
                let items = self.list_arg(other, "reverse")?;
                Ok(syn_list(items.into_iter().rev().collect()))
            }
        }
    }

    fn b_unique(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        // En orden de primera aparición; lo que `==` iguala es un solo valor (`1` y `1.0`, un
        // mapa con otro orden de claves, el mismo instante en otra zona). Los NaN cuentan como
        // uno, como `numpy.unique` y pandas. Lineal: clave canónica en un hash.
        let items = self.list_arg(nth(args, 0)?, "unique")?;
        let mut out: Vec<SynValue> = Vec::with_capacity(items.len());
        let mut seen: HashSet<String> = HashSet::with_capacity(items.len());
        let mut mix = crate::tabular::NumMix::default();
        for item in items {
            mix.check(&item, "unique")?;
            if seen.insert(crate::tabular::probe_key(&item)) {
                out.push(item);
            }
        }
        Ok(syn_list(out))
    }

    /// `index_of(lista, item_o_pred)` — índice (base 0) de la primera coincidencia.
    /// 2º arg callable → predicado; si no → igualdad estructural con el item.
    /// **No encontrado → `nothing`** (el patrón de ausencia del lenguaje, como
    /// `find_first`/`resume_point`): un `-1` usado como índice sin chequear es un bug
    /// silencioso; `nothing` como índice falla ruidoso.
    fn b_index_of(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // v0.6.29: también texto — la posición (en caracteres, como `length` y `s[i]`) de
        // la primera aparición, o `nothing`.
        if let SynValue::Text(hay) = nth(args, 0)? {
            let needle = match nth(args, 1)? {
                SynValue::Text(t) => t.clone(),
                other => {
                    return Err(err(format!("index_of(text, …) looks for a piece of text, got {}", other.type_name())))
                }
            };
            return Ok(match hay.find(needle.as_ref()) {
                Some(byte_pos) => syn_int(hay[..byte_pos].chars().count() as i64),
                None => SynValue::Nothing,
            });
        }
        let items = self.list_arg(nth(args, 0)?, "index_of")?;
        let needle = nth(args, 1)?.clone();
        if is_callable(&needle) {
            for (i, item) in items.into_iter().enumerate() {
                if self.call_value(needle.clone(), vec![item], loc)?.is_truthy() {
                    return Ok(syn_int(i as i64));
                }
            }
        } else {
            for (i, item) in items.iter().enumerate() {
                if crate::tabular::strict_equals(item, &needle).map_err(|_| err(format!("index_of: {}", MIX_DECIMAL_FLOAT)))? {
                    return Ok(syn_int(i as i64));
                }
            }
        }
        Ok(SynValue::Nothing)
    }
}

// =========================================================
// helpers libres
// =========================================================

fn nth(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

/// T5 (B8): error de CARGA si el programa liga alguno de los nombres protegidos
/// (`PROTECTED_BUILTIN_NAMES`) a un valor **invocable**: `task private(…)`, una lambda, o un
/// tipo/enum/grupo de rutas (todos construyen algo llamable). Estático y SIEMPRE activo (con
/// etiquetas apagadas también), porque el mismo programa puede cargarlo un host que las
/// encienda y porque el chequeo que distingue un `declassify(...)` real depende de que el
/// nombre no se pueda sombrear.
///
/// Lo que NO se prohíbe (ronda 3): ligarlos a un valor **no invocable**. `let private be 5`
/// es la especificación por ejemplo de que `private` es una palabra clave BLANDA
/// (`conformance/core/053`), y no reabre nada: el ataque era interceptar la LLAMADA, y de eso
/// se ocupa además el guard de sitio de llamada (`check_protected_callee`), que exige que
/// `private(…)`/`declassify(…)`/… resuelvan al builtin de verdad — cubriendo también los
/// caminos dinámicos (un parámetro, un alias de módulo, un valor del blackboard).
/// T5 (ronda 7) — los principales que el PROGRAMA declara, recogidos del AST antes de ejecutar
/// nada: los literales de texto en el segundo argumento de `private(…)` y en el tercero de
/// `declassify(…)` (la forma que acota en vez de publicar).
///
/// Estático a propósito. Recogerlos cuando el `private` CORRE haría que el texto de redacción
/// dependiera de qué camino tomó la corrida, que es exactamente el canal que esto cierra:
/// `when s == 0 / private(1, "p0") / otherwise / private(1, "p1")` daría un texto distinto según
/// el secreto.
pub fn principal_literals(program: &Program) -> Vec<String> {
    fn literals_of(n: &Node, out: &mut Vec<String>) {
        match &n.kind {
            NodeKind::TextLiteral { value } => {
                if !value.is_empty() && !out.iter().any(|x| x == value) {
                    out.push(value.clone());
                }
            }
            NodeKind::ListLiteral { elements } => {
                for e in elements {
                    literals_of(e, out);
                }
            }
            _ => {}
        }
    }
    let mut out: Vec<String> = Vec::new();
    for stmt in &program.statements {
        crate::ast_api::walk(stmt, &mut |n| {
            if let NodeKind::TaskCall { name, arguments } = &n.kind {
                let idx = match name.as_identifier() {
                    Some("private") => 1,
                    Some("declassify") => 2,
                    _ => return,
                };
                if let Some(arg) = arguments.get(idx) {
                    literals_of(&arg.value, &mut out);
                }
            }
        });
    }
    out
}

pub fn check_protected_names(program: &Program) -> Result<(), Control> {
    let mut bad: Option<(String, SourceLocation)> = None;
    let mut hit = |name: &str, loc: &SourceLocation| {
        if bad.is_none() && PROTECTED_BUILTIN_NAMES.contains(&name) {
            bad = Some((name.to_string(), loc.clone()));
        }
    };
    for stmt in &program.statements {
        crate::ast_api::walk(stmt, &mut |n| {
            let loc = &n.location;
            match &n.kind {
                NodeKind::TaskDefinition { name, .. } => hit(name, loc),
                NodeKind::TypeDefinition { name, .. }
                | NodeKind::EnumDefinition { name, .. }
                | NodeKind::RoutesDeclaration { name, .. } => hit(name, loc),
                // `let f be (x) => …` / `set f to (x) => …`: liga un invocable.
                NodeKind::LetBinding { name, value, .. } => {
                    if matches!(value.kind, NodeKind::LambdaExpression { .. }) {
                        hit(name, loc);
                    }
                }
                NodeKind::SetMutation { target, value } => {
                    if matches!(value.kind, NodeKind::LambdaExpression { .. }) {
                        if let Some(name) = target.as_identifier() {
                            hit(name, loc);
                        }
                    }
                }
                _ => {}
            }
        });
    }
    match bad {
        Some((name, loc)) => Err(err_labels(
            format!(
                "'{}' is a protected builtin and cannot be bound to something callable: the information-flow labels of the whole program are decided by these five builtins, so a program that redefines one could silently un-label its own sources and mislead the audit listing. Binding the name to a plain value (let {} be 5) is fine — it is a soft keyword. This holds with or without --labels, because the same program can be loaded by a host that turns them on",
                name, name
            ),
            &loc,
        )),
        None => Ok(()),
    }
}

/// T5 (B8): el callee de una llamada a un nombre protegido tiene que ser SU builtin.
fn check_protected_callee(name: &str, func: &SynValue, loc: &SourceLocation) -> Result<(), Control> {
    let ok = matches!(func, SynValue::Builtin(bt) if bt.name == name);
    if ok {
        return Ok(());
    }
    Err(err_labels(
        format!(
            "'{}' is a protected builtin and this call does not resolve to it (it resolves to {}): the information-flow labels of the program depend on these five builtins, so intercepting the call would silently un-label the program's own sources",
            name,
            func.type_name()
        ),
        loc,
    ))
}

/// T5 (ronda 3, B1): ¿alguna sentencia de este bloque puede SALIR antes de tiempo dejando
/// trabajo sin hacer — `give`, `stop` (del bucle que lo contiene) o `raise`? Estático sobre el
/// AST; no entra a cuerpos de task ni de lambda (un `give` de ahí adentro sale de ESA task).
pub fn block_exits_early(stmts: &[Node]) -> bool {
    stmts.iter().any(|n| node_exits_early(n, false))
}

/// Las tres ramas de un `when` (cuerpo, `otherwise`, cadena `otherwise when`).
fn when_exits_early(body: &[Node], otherwise: &Option<Vec<Node>>, otherwise_when: &Option<Box<Node>>) -> bool {
    block_exits_early(body)
        || otherwise.as_ref().is_some_and(|b| block_exits_early(b))
        || otherwise_when.as_ref().is_some_and(|w| node_exits_early(w, false))
}

/// T5 (ronda 5) — ¿el bloque puede salir de la TASK ENTERA (`give`/`raise`), y no sólo de este
/// bloque? Es `node_exits_early` con `in_nested_loop = true`, que es exactamente el predicado
/// "un `stop` no me alcanza". Decide hasta dónde llega la tinta de la rama (ver `taint_branch`).
pub fn block_exits_task(stmts: &[Node]) -> bool {
    stmts.iter().any(|n| node_exits_early(n, true))
}

fn when_exits_task(body: &[Node], otherwise: &Option<Vec<Node>>, otherwise_when: &Option<Box<Node>>) -> bool {
    block_exits_task(body)
        || otherwise.as_ref().is_some_and(|b| block_exits_task(b))
        || otherwise_when.as_ref().is_some_and(|w| node_exits_early(w, true))
}

fn match_exits_task(arms: &[Node], otherwise: &Option<Vec<Node>>) -> bool {
    arms.iter().any(|a| node_exits_early(a, true))
        || otherwise.as_ref().is_some_and(|b| block_exits_task(b))
}

/// Los cuerpos de los arms de un `match` y su `otherwise`.
fn match_exits_early(arms: &[Node], otherwise: &Option<Vec<Node>>) -> bool {
    arms.iter().any(|a| node_exits_early(a, false))
        || otherwise.as_ref().is_some_and(|b| block_exits_early(b))
}

fn node_exits_early(n: &Node, in_nested_loop: bool) -> bool {
    match &n.kind {
        NodeKind::GiveStatement { .. } => true,
        // Un `stop` dentro de un bucle ANIDADO corta ese bucle, no este bloque.
        NodeKind::StopStatement { .. } => !in_nested_loop,
        // `raise <msg>` es una llamada al builtin: corta la corrida entera.
        NodeKind::TaskCall { name, .. } => name.as_identifier() == Some("raise"),
        NodeKind::LetBinding { value, .. } => node_exits_early(value, in_nested_loop),
        NodeKind::SetMutation { value, .. } => node_exits_early(value, in_nested_loop),
        NodeKind::WhenStatement { body, otherwise, otherwise_when, .. } => {
            body.iter().any(|s| node_exits_early(s, in_nested_loop))
                || otherwise.as_ref().is_some_and(|b| b.iter().any(|s| node_exits_early(s, in_nested_loop)))
                || otherwise_when.as_ref().is_some_and(|w| node_exits_early(w, in_nested_loop))
        }
        NodeKind::MatchStatement { arms, otherwise, .. } => {
            arms.iter().any(|a| node_exits_early(a, in_nested_loop))
                || otherwise.as_ref().is_some_and(|b| b.iter().any(|s| node_exits_early(s, in_nested_loop)))
        }
        NodeKind::MatchArm { body, .. } => body.iter().any(|s| node_exits_early(s, in_nested_loop)),
        // Dentro de un bucle anidado, sólo `give`/`raise` salen de NUESTRO bloque.
        NodeKind::EachStatement { body, .. } | NodeKind::WhileStatement { body, .. } => {
            body.iter().any(|s| node_exits_early(s, true))
        }
        NodeKind::TryRecover { try_body, recover_body, .. } => {
            try_body.iter().any(|s| node_exits_early(s, in_nested_loop))
                || recover_body.iter().any(|s| node_exits_early(s, in_nested_loop))
        }
        NodeKind::SandboxBlock { body, .. }
        | NodeKind::TraceBlock { body, .. }
        | NodeKind::MeasureBlock { body, .. }
        | NodeKind::StreamBlock { body } => body.iter().any(|s| node_exits_early(s, in_nested_loop)),
        _ => false,
    }
}

/// T5 (regla 3.a): ¿el nodo es un literal del fuente — escalar, o lista/mapa cuyos elementos
/// Lo son? Un principal/motivo escrito así es texto del PROGRAMA: no varía con los datos
/// (aunque bajo PC lleve la etiqueta del contexto, por B5).
fn is_literal_expr(node: &Node) -> bool {
    match &node.kind {
        NodeKind::ListLiteral { elements } => elements.iter().all(is_literal_expr),
        NodeKind::MapLiteral { pairs } => pairs.iter().all(|(k, v)| is_literal_expr(k) && is_literal_expr(v)),
        _ => is_scalar_literal(node),
    }
}

/// T5 (B5): ¿el nodo es un literal escalar (texto del programa)?
fn is_scalar_literal(node: &Node) -> bool {
    matches!(
        node.kind,
        NodeKind::NumberLiteral { .. } | NodeKind::TextLiteral { .. } | NodeKind::BoolLiteral { .. } | NodeKind::NothingLiteral
    )
}

/// La variable raíz de un destino de `set` (`m` en `set m["a"][k].f to v`), si el camino
/// nace de un identificador; `None` si nace de otra expresión (una llamada, un literal…).
fn set_root_identifier(target: &Node) -> Option<&str> {
    match &target.kind {
        NodeKind::Identifier { name } => Some(name.as_str()),
        NodeKind::IndexAccess { object, .. } | NodeKind::PropertyAccess { object, .. } => {
            set_root_identifier(object)
        }
        _ => None,
    }
}

/// El argumento "principal(es)" de `private`/`declassify`: un texto no vacío o una
/// lista de textos no vacíos (`allow_empty`: la lista vacía vale como "público", sólo para
/// El `to` de `declassify`). Los nombres son metadatos: se leen a través de un `Private`.
fn principals_arg(
    v: &SynValue,
    who: &str,
    allow_empty: bool,
    is_literal: bool,
    loc: &SourceLocation,
) -> Result<Label, Control> {
    let bad = || {
        err_labels(
            format!("{}: principal must be a non-empty text or a list of non-empty texts, got {}", who, v.type_name()),
            loc,
        )
    };
    // M3 : el principal es METADATO PUBLICO — es el NOMBRE de la etiqueta, y
    // `label_of` lo devuelve. Tiene que ser un literal escrito en ESTA llamada (texto del
    // programa: no varia con los datos, aunque bajo PC lleve la etiqueta del contexto) o un
    // valor sin etiquetas. Aceptar `subset(PC)` dejaba pasar un dato privado a {app} dentro de
    // una rama con PC {app}: su texto se volvia nombre de principal y salia en claro por
    // `label_of` (un numero de documento escrito a disco en la repro del auditor).
    // M1 (ronda 3): el principal tiene que ser un LITERAL escrito en esta llamada. Se va el
    // escape "un valor sin etiquetas": una variable pública con texto arbitrario entraba como
    // nombre de principal y salía verbatim por los mensajes `label_violation`, que son el único
    // canal que nunca se redacta (y bajo `serve` llegan al cliente). Encadenado con una fuga de
    // control, eso era exfiltración.
    if !is_literal {
        return Err(err_labels(
            format!(
                "{}: the principal must be a text literal written at this call (a computed value could carry data out through the label name, which is printed verbatim in diagnostics)",
                who
            ),
            loc,
        ));
    }
    match labels::unwrap(v) {
        SynValue::Text(s) if !s.trim().is_empty() => Ok(labels::label_from(&[s.trim()])),
        SynValue::List(l) => {
            let items = l.borrow();
            if items.is_empty() && !allow_empty {
                return Err(bad());
            }

            let mut names: Vec<String> = Vec::with_capacity(items.len());
            for it in items.iter() {
                match labels::unwrap(it) {
                    SynValue::Text(s) if !s.trim().is_empty() => names.push(s.trim().to_string()),
                    _ => return Err(bad()),
                }
            }
            Ok(labels::label_from(&names))
        }
        _ => Err(bad()),
    }
}

/// ¿El valor es invocable? (task de usuario, lambda o builtin). La base de la regla
/// de detección del dual-order (batch DX) y del 2º arg de `index_of`.
/// `(función, array)` en cualquier orden, si la llamada es sobre un array.
fn fn_and_array(args: &[SynValue]) -> Option<(SynValue, Rc<ndarray::ArrayD<f64>>)> {
    match (args.first(), args.get(1)) {
        (Some(SynValue::Array(a)), Some(f)) if is_callable(f) => Some((f.clone(), a.clone())),
        (Some(f), Some(SynValue::Array(a))) if is_callable(f) => Some((f.clone(), a.clone())),
        _ => None,
    }
}

fn is_callable(v: &SynValue) -> bool {
    matches!(v, SynValue::Task(_) | SynValue::Builtin(_))
}

/// Parsea el catálogo de tools que el programa pasa a `llm_step`: una lista de maps
/// `{name, describe|description, params}`. Items mal formados (sin `name` texto) se
/// saltan (robustez ante data del programa; no se inventa una tool sin nombre).
fn parse_catalog(arg: Option<&SynValue>) -> Vec<StepCatalogEntry> {
    let list = match arg {
        Some(SynValue::List(l)) => l,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for item in list.borrow().iter() {
        let m = match item {
            SynValue::Map(m) => m,
            _ => continue,
        };
        let m = m.borrow();
        let name = match m.get("name") {
            Some(SynValue::Text(s)) => s.to_string(),
            _ => continue, // sin `name` texto → item inválido, se salta
        };
        let description = match m.get("describe").or_else(|| m.get("description")) {
            Some(SynValue::Text(s)) => s.to_string(),
            _ => String::new(),
        };
        let params = match m.get("params") {
            Some(SynValue::List(pl)) => pl
                .borrow()
                .iter()
                .filter_map(|p| match p {
                    SynValue::Text(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        out.push(StepCatalogEntry { name, description, params });
    }
    out
}

/// Convierte el `StepResult` del callback al map `{kind, …}` que consume el programa:
/// `{kind:"final", text, tokens}` | `{kind:"tool", name, args:{…}, tokens}`.
fn step_result_to_synvalue(result: StepResult) -> SynValue {
    let mut map = IndexMap::new();
    match result {
        StepResult::Final { text, tokens } => {
            map.insert("kind".to_string(), syn_text("final"));
            map.insert("text".to_string(), syn_text(text));
            map.insert("tokens".to_string(), syn_int(tokens as i64));
        }
        StepResult::Tool { name, args, tokens } => {
            let mut amap = IndexMap::new();
            for (k, v) in args {
                amap.insert(k, syn_text(v));
            }
            map.insert("kind".to_string(), syn_text("tool"));
            map.insert("name".to_string(), syn_text(name));
            map.insert("args".to_string(), syn_map(amap));
            map.insert("tokens".to_string(), syn_int(tokens as i64));
        }
    }
    syn_map(map)
}

/// Coerciona un valor a `Complex64` para la aritmética complex (Batch 4): `Complex(z)→z`;
/// `Number(n)→z(n,0)` (promoción real→complex; promover Decimal/Big a f64 es lossy a
/// propósito — complex es float-based); cualquier otro tipo → `None`.
fn as_complex(v: &SynValue) -> Option<Complex64> {
    match v {
        SynValue::Complex(z) => Some(*z),
        SynValue::Number(n) => Some(Complex64::new(n.to_f64(), 0.0)),
        _ => None,
    }
}

/// Lee el arg opcional de encoding (2º) de `bytes`/`decode`: `None` si no se pasó,
/// `Some(enc)` si es texto, error si está presente pero no es texto.
fn bytes_encoding_arg(args: &[SynValue]) -> Result<Option<String>, Control> {
    match args.get(1) {
        None => Ok(None),
        Some(SynValue::Text(s)) => Ok(Some(s.to_string())),
        Some(other) => Err(err(format!("encoding must be text, got {}", other.type_name()))),
    }
}

/// Concatenación que **propaga el taint** (#10): el resultado es un `secret` cuyo
/// plaintext es la concatenación de los plaintexts (un operando no-secret aporta su
/// display, igual que la concatenación normal). El nombre se hereda del primer
/// operando secret (sólo cosmético para la redacción `secret(NAME)`).
fn secret_concat(left: &SynValue, right: &SynValue) -> SynValue {
    // (texto a concatenar, nombre si el operando es secret).
    fn part(v: &SynValue) -> (String, Option<String>) {
        match v {
            SynValue::Secret(s) => (s.expose().to_string(), Some(s.name().to_string())),
            other => (other.to_string(), None),
        }
    }
    let (lp, ln) = part(left);
    let (rp, rn) = part(right);
    let name = ln.or(rn).unwrap_or_else(|| "derived".to_string());
    syn_secret(name, format!("{}{}", lp, rp))
}

/// `str(value.raw)` estilo Python (texto crudo, no el Display de SynValue).
fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// Un índice, posición o paso: tiene que ser ENTERO (v0.6.29). `2.0` vale; `1.7` es
/// error en vez de truncarse en silencio a 1.
/// Copy-on-write de UN nivel (v0.6.29): si la lista o el mapa de `slot` tiene otro dueño,
/// `slot` pasa a apuntar a una copia propia (los elementos se comparten; cada nivel se
/// copia recién cuando alguien escribe en él). Un valor privado se copia por dentro y
/// conserva su etiqueta.
fn make_unique(slot: &mut SynValue) {
    make_unique_n(slot, 0)
}

/// `make_unique` tolerando `extra` dueños conocidos del nivel de arriba (la vista del mapa de
/// un módulo sobre su propia variable).
fn make_unique_n(slot: &mut SynValue, extra: usize) {
    let owners = 1 + extra;
    match slot {
        SynValue::List(rc) if Rc::strong_count(rc) > owners => {
            let copy = rc.borrow().clone();
            *slot = SynValue::List(Rc::new(RefCell::new(copy)));
        }
        SynValue::Map(rc) if Rc::strong_count(rc) > owners && module_env_of_map(rc).is_none() => {
            let copy = rc.borrow().clone();
            *slot = SynValue::Map(Rc::new(RefCell::new(copy)));
        }
        SynValue::Private(p) => {
            let shared_inner = match &p.value {
                SynValue::List(rc) => Rc::strong_count(rc) > 1,
                SynValue::Map(rc) => Rc::strong_count(rc) > 1,
                _ => false,
            };
            if shared_inner || (Rc::strong_count(p) > owners && matches!(p.value, SynValue::List(_) | SynValue::Map(_))) {
                // Copia del contenedor interno aunque su cuenta sea 1 cuando el envoltorio
                // está compartido: el alias ve el mismo Rc interno.
                let inner = match &p.value {
                    SynValue::List(rc) => SynValue::List(Rc::new(RefCell::new(rc.borrow().clone()))),
                    SynValue::Map(rc) => SynValue::Map(Rc::new(RefCell::new(rc.borrow().clone()))),
                    other => other.clone(),
                };
                *slot = SynValue::Private(Rc::new(labels::Labelled { value: inner, label: p.label.clone() }));
            }
        }
        _ => {}
    }
}

/// Una entrada del linaje: de dónde vino, qué fue (ruta, host, hash de la consulta) y el
/// sha256 de los bytes que recibió el programa (para un archivo de texto, el del archivo).
#[derive(Clone, Debug)]
pub struct LineageEntry {
    pub source: String,
    pub what: String,
    pub sha256: String,
    pub bytes: usize,
    /// Cómo se obtuvieron los bytes hasheados: "text" (utf-8), "bytes", "jcs"
    /// (`canonical_json(x)`) o "json" (`json_encode(x)`, cuando hay enteros > 2^53).
    pub encoding: String,
    /// La sal (hex) del compromiso de una consulta o un prompt y cómo se codificó lo que se
    /// comprometió ("jcs": `canonical_json([args…])`, "json", "text"). Sólo en `lineage()`: el
    /// recibo publica el compromiso, nunca la sal.
    pub salt: Option<(String, &'static str)>,
}

/// Builtins que TRAEN datos de afuera (archivos, red, bases, nodos de una cadena, sockets,
/// procesos, la terminal, stdin). Lo que sólo escribe o manda (`write_file`, `ws_send`,
/// `evm_send`) no es una entrada.
pub const LINEAGE_SOURCES: &[&str] = &[
    // archivos y stdin
    "read_file", "read_file_bytes", "read_line", "list_dir", "file_info", "grep", "parquet_read",
    "term_recv", "watch_recv",
    // HTTP
    "http", "http_get", "http_post", "http_put", "http_delete", "http_bytes", "fetch",
    // bases
    "sql", "sql_batch", "sql_tables", "paged", "mongo_find", "mongo_find_one", "mongo_aggregate",
    "mongo_count", "mongo_collections", "redis_get", "redis_mget", "redis_hget", "redis_hgetall",
    "redis_lrange", "redis_smembers", "redis_sismember", "redis_keys", "redis_exists", "redis_llen",
    "redis_lpop", "redis_rpop", "redis_ttl", "redis_type", "redis_incr", "redis_incrby", "redis_decr",
    "redis_hincrby", "recall",
    // cadenas
    "evm_rpc", "evm_call", "evm_balance", "evm_nonce", "evm_chain_id", "evm_gas_price",
    "evm_estimate_gas", "evm_fee_history", "evm_block_number", "evm_logs", "evm_receipt", "evm_wait",
    "solana_rpc", "solana_balance", "solana_latest_blockhash", "solana_wait", "solana_confirm",
    "algorand_account", "algorand_params", "algorand_wait", "btc_rpc", "btc_balance", "btc_utxos",
    "btc_fee_estimates", "btc_wait",
    // sockets y procesos (lo que devuelve un comando externo también es una entrada)
    "ws_recv", "ws_select", "ws_select_all", "proc_recv", "proc_select", "proc_wait", "run", "run_program",
];

/// Compromiso con sal de `data` (como los "disclosures" de SD-JWT): `(sal, sha256(sal ‖ data))`
/// en hex, con 128 bits de sal nueva por llamada. Sin la sal nadie revierte el compromiso
/// probando valores; con la sal y `data`, cualquiera lo verifica.
pub fn salted_commitment(data: &[u8]) -> (String, String) {
    use sha2::{Digest, Sha256};
    let salt = fresh_salt();
    let commit = Sha256::new().chain_update(salt).chain_update(data).finalize();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    (hex(&salt), hex(&commit))
}

/// 16 bytes impredecibles: sha256(secreto del proceso ‖ contador). El secreto sale de la
/// entropía del sistema (claves de `RandomState`, sembradas por el SO), el reloj y el pid.
fn fresh_salt() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static KEY: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    let key = KEY.get_or_init(|| {
        // Entropía del sistema vía las claves de `RandomState` (SipHash sembrado por el SO),
        // más el reloj y el pid; se condensa con sha256.
        use std::hash::{BuildHasher, Hasher};
        let mut h = Sha256::new();
        for i in 0..8u64 {
            let mut s = std::collections::hash_map::RandomState::new().build_hasher();
            s.write_u64(i);
            h.update(s.finish().to_le_bytes());
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        h.update(now.to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        let a = h.finalize();
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&a);
        k[32..].copy_from_slice(&Sha256::digest(a));
        k
    });
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let h = Sha256::new().chain_update(key).chain_update(n.to_le_bytes()).finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// El host de la URL de una CONEXIÓN, sin credenciales (`user:pass@`), ruta, query ni
/// fragmento: un recibo firmado se publica y la clave de un RPC suele viajar ahí. Sólo cuenta un
/// argumento que ES la conexión (`url_of_connection`) y cuyo esquema es de red (`http`, `https`,
/// `ws`, `wss`): la clave de redis `"session://TOKEN"`, una categoría de `recall` o un `://` en
/// medio de una consulta son datos, no hosts, y nunca salen en claro.
fn url_host(url: Option<&SynValue>) -> String {
    let Some(SynValue::Text(t)) = url else { return String::new() };
    let t = t.trim();
    let Some((scheme, rest)) = t.split_once("://") else { return String::new() };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https" | "ws" | "wss") || t.chars().any(char::is_whitespace) {
        return String::new();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    authority.rsplit('@').next().unwrap_or("").to_string()
}

/// El argumento que es la conexión de una fuente del linaje: la URL de `http_*`/`fetch` (la
/// segunda en `http(method, url, …)`) y la del nodo en los lectores de cadena (el primero).
/// Las bases, la memoria, los sockets y los procesos no tienen uno: sus argumentos son datos.
fn url_of_connection<'a>(source: &str, args: &'a [SynValue]) -> Option<&'a SynValue> {
    match source {
        "http" => args.get(1),
        s if s.starts_with("http") || s == "fetch" => args.first(),
        s if ["evm_", "solana_", "algorand_", "btc_"].iter().any(|p| s.starts_with(p)) => args.first(),
        _ => None,
    }
}

/// Tope de entradas del linaje por corrida (un bucle que lee un millón de archivos no crece
/// sin límite; el recibo lo dice con `inputs_truncated`).
pub const MAX_LINEAGE: usize = 10_000;

fn value_bytes(v: &SynValue) -> Vec<u8> {
    match v {
        SynValue::Text(t) => t.as_bytes().to_vec(),
        SynValue::Bytes(b) => b.to_vec(),
        SynValue::Nothing => Vec::new(),
        other => other.to_string().into_bytes(),
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    crate::bytesutil::hex_encode(&sha2::Sha256::digest(b))
}

/// Aridad ESTRICTA de una llamada escrita en el programa (v0.6.29): un argumento de más
/// o un parámetro sin default que falta es error, en tasks, lambdas y builtins. Antes el
/// extra se descartaba en silencio (`append([1], 2, 3)` perdía el 3, `trim(s, "x")`
/// ignoraba la "x") y el faltante llegaba como `nothing`.
///
/// Sólo para llamadas del fuente: el host (rutas de `serve`, handlers, cron) y los
/// builtins que invocan callbacks (`apply`, `where`, `reduce`, …) siguen pasando lo que
/// tienen y el callback declara lo que usa.
fn check_call_arity(
    func: &SynValue,
    args: &[(Option<String>, SynValue)],
    loc: &SourceLocation,
) -> Result<(), Control> {
    let positional = args.iter().filter(|(n, _)| n.is_none()).count();
    match func {
        SynValue::Task(t) => {
            let np = t.parameters.len();
            let who = if t.name == "<lambda>" { "this lambda".to_string() } else { format!("task '{}'", t.name) };
            if positional > np {
                return Err(err_at(
                    format!(
                        "{} takes {} argument{}, got {}",
                        who,
                        np,
                        if np == 1 { "" } else { "s" },
                        positional
                    ),
                    loc,
                ));
            }
            for (i, p) in t.parameters.iter().enumerate() {
                let given = i < positional || args.iter().any(|(n, _)| n.as_deref() == Some(p.name.as_str()));
                if !given && p.default.is_none() {
                    return Err(err_at(
                        format!(
                            "{} is missing argument '{}' — pass it, or give the parameter a default in the task: {} = …",
                            who, p.name, p.name
                        ),
                        loc,
                    ));
                }
            }
            Ok(())
        }
        // El constructor de un tipo o de una variante (`Point(…)`, `Order.paid(…)`) cuenta
        // sus campos él mismo, con un mensaje que nombra el tipo.
        SynValue::Builtin(b) if b.name.starts_with(|c: char| c.is_ascii_uppercase()) => Ok(()),
        SynValue::Builtin(b) => {
            let (min, max) = builtin_arity(b);
            let n = match &b.param_names {
                // Con nombres: cuenta el slot más alto ocupado.
                Some(names) => {
                    let mut hi = positional;
                    for (nm, _) in args {
                        if let Some(nm) = nm {
                            if let Some(i) = names.iter().position(|p| *p == nm.as_str()) {
                                hi = hi.max(i + 1);
                            }
                        }
                    }
                    hi
                }
                None => positional,
            };
            if let Some(max) = max {
                if n > max {
                    // Reflejos de Python con otra aridad: `round(x, 2)` es `round_to(x, 2)`.
                    let hint = match b.name.as_str() {
                        "round" => " — to round to n decimals: round_to(x, n)",
                        "sort" => " — sort(xs, desc = true) for descending; sort_by(xs, key) for a key",
                        "split" => " — split(text, sep) has no limit argument",
                        _ => "",
                    };
                    return Err(err_at(
                        format!(
                            "{}() takes at most {} argument{}, got {}{}",
                            b.name,
                            max,
                            if max == 1 { "" } else { "s" },
                            n,
                            hint
                        ),
                        loc,
                    ));
                }
            }
            // El MÍNIMO lo valida cada builtin (sus mensajes dicen qué falta y por qué:
            // `declassify` pide un motivo, un constructor cuenta campos); si no lo hace, el
            // "missing argument" genérico sale con el nombre del builtin (`dispatch_builtin`).
            let _ = min;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `(mínimo, máximo)` de argumentos de un builtin: la tabla `BUILTIN_ARITY` manda; si
/// no está, un `param_count` fijo es exacto y -1 no se valida acá (el builtin lo hace).
fn builtin_arity(b: &BuiltinTask) -> (usize, Option<usize>) {
    if let Some((min, max)) = crate::builtin_arity::arity_of(&b.name) {
        return (min, max);
    }
    if b.param_count >= 0 {
        (b.param_count as usize, Some(b.param_count as usize))
    } else {
        (0, None)
    }
}

/// Texto → entero exacto: decimal con signo opcional (`_` sólo entre dígitos) o
/// `0x…`/`0b…` sin signo. Espacios alrededor se recortan. `None` si no es eso.
/// Dígitos decimales máximos que `int(text)`/`number(text)` convierten: el tope de Python
/// (`sys.int_info.default_max_str_digits`). Convertir texto decimal a entero es cuadrático;
/// sin tope, un dato hostil de un megabyte compra minutos de CPU. `0x…`/`0b…` son lineales.
pub const MAX_INT_TEXT_DIGITS: usize = 4300;

/// ¿Es texto decimal (signo, `_`) con más dígitos que el tope? Devuelve cuántos.
fn over_digit_limit(s: &str) -> Option<usize> {
    let t = s.trim();
    let t = t.strip_prefix('-').or_else(|| t.strip_prefix('+')).unwrap_or(t);
    let n = t.bytes().filter(|c| c.is_ascii_digit()).count();
    (n > MAX_INT_TEXT_DIGITS && t.bytes().all(|c| c.is_ascii_digit() || c == b'_')).then_some(n)
}

/// `int(text, base = b)`: signo, `_` entre dígitos y, en base 16/8/2, el prefijo `0x`/`0o`/`0b`
/// opcional (como el `int(s, b)` de Python). Bases que no son potencia de 2 con el tope de
/// dígitos (conversión cuadrática).
fn parse_int_radix(s: &str, radix: u32) -> Option<Number> {
    let t = s.trim();
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let prefix = match radix {
        16 => Some(["0x", "0X"]),
        8 => Some(["0o", "0O"]),
        2 => Some(["0b", "0B"]),
        _ => None,
    };
    let body = prefix
        .and_then(|ps| ps.iter().find_map(|p| body.strip_prefix(p)))
        .unwrap_or(body);
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let d: String = body.chars().filter(|c| *c != '_').collect();
    if !d.chars().all(|c| c.is_digit(radix)) || (!radix.is_power_of_two() && d.len() > MAX_INT_TEXT_DIGITS) {
        return None;
    }
    let b = num_bigint::BigInt::parse_bytes(d.as_bytes(), radix)?;
    Some(Number::from_bigint(if neg { -b } else { b }))
}

fn parse_int_text(s: &str) -> Option<Number> {
    let t = s.trim();
    // Un signo delante de `0x…`/`0b…` también (`-0x10` es -16).
    if let Some((neg, rest)) = t.strip_prefix('-').map(|r| (true, r)).or_else(|| t.strip_prefix('+').map(|r| (false, r))) {
        if ["0x", "0X", "0o", "0O", "0b", "0B"].iter().any(|p| rest.starts_with(p)) {
            let n = parse_int_text(rest)?;
            return Some(if neg { n.neg() } else { n });
        }
    }
    let clean = |d: &str| -> Option<String> {
        if d.is_empty() || d.starts_with('_') || d.ends_with('_') || d.contains("__") {
            return None;
        }
        Some(d.chars().filter(|c| *c != '_').collect())
    };
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(rest) = t.strip_prefix(prefix) {
            // Como el literal (y Python): un `_` justo después del prefijo vale (`0x_ff`).
            let d = clean(rest.strip_prefix('_').unwrap_or(rest))?;
            if !d.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            return num_bigint::BigInt::parse_bytes(d.as_bytes(), radix).map(Number::from_bigint);
        }
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let d = clean(body)?;
    if !d.chars().all(|c| c.is_ascii_digit()) || d.len() > MAX_INT_TEXT_DIGITS {
        return None;
    }
    let b: num_bigint::BigInt = d.parse().ok()?;
    Some(Number::from_bigint(if neg { -b } else { b }))
}

fn num_to_i64(v: &SynValue) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) => {
            let integral = match n {
                Number::Float(x) => x.fract() == 0.0,
                Number::Decimal(_) | Number::BigDec(_) => n.as_bigint().is_some(),
                _ => true,
            };
            if !integral {
                return Err(err(format!(
                    "index must be an integer, got {} — use floor(x), round(x) or trunc(x) on purpose",
                    n
                )));
            }
            n.to_i64_trunc().ok_or_else(|| err("number too large for an index"))
        }
        _ => Err(err(format!("an index must be an integer, got {}", v.type_name()))),
    }
}

/// Posición real de un índice que puede ser negativo (`-1` = el último), o `None` si
/// queda fuera de `0..len`.
fn resolve_index(i: i64, len: usize) -> Option<usize> {
    let len = len as i64;
    let j = if i < 0 { i + len } else { i };
    if (0..len).contains(&j) {
        Some(j as usize)
    } else {
        None
    }
}

/// Rango de slice estilo Python (negativos y clamping; nunca falla).
fn py_slice_range(len: usize, start: i64, end: Option<i64>) -> (usize, usize) {
    let len_i = len as i64;
    let clamp = |mut x: i64| -> i64 {
        if x < 0 {
            x += len_i;
        }
        x.clamp(0, len_i)
    };
    let s = clamp(start);
    let e = clamp(end.unwrap_or(len_i));
    if s >= e {
        (s as usize, s as usize)
    } else {
        (s as usize, e as usize)
    }
}

fn ord_op(ord: Option<Ordering>, op: &str) -> bool {
    match ord {
        None => false, // NaN
        Some(o) => match op {
            "<" => o == Ordering::Less,
            ">" => o == Ordering::Greater,
            "<=" => o != Ordering::Greater,
            ">=" => o != Ordering::Less,
            _ => false,
        },
    }
}

/// Rango de "faltante" en el orden total: 0 = valor, 1 = NaN, 2 = `nothing`. Los
/// faltantes van al FINAL tanto ascendente como descendente (como pandas `na_position`).
fn missing_rank(v: &SynValue) -> u8 {
    match labels::unwrap(v) {
        SynValue::Nothing => 2,
        SynValue::Number(Number::Float(x)) if x.is_nan() => 1,
        _ => 0,
    }
}

/// Clase de tipo para ordenar: sólo se ordenan entre sí valores de la misma clase.
fn order_class(v: &SynValue) -> Option<&'static str> {
    match labels::unwrap(v) {
        SynValue::Number(_) => Some("number"),
        SynValue::Text(_) => Some("text"),
        SynValue::Bool(_) => Some("bool"),
        SynValue::Bytes(_) => Some("bytes"),
        SynValue::List(_) => Some("list"),
        SynValue::Time(t) => Some(t.type_name()),
        _ => None,
    }
}

/// Orden TOTAL del lenguaje (v0.6.29, DATOS-1): números exactos (entero vs float sin pasar
/// por f64), texto por punto de código, `false < true`, bytes y listas lexicográficos.
/// Llamar sólo después de `check_orderable` (clases compatibles).
pub(crate) fn total_cmp(a: &SynValue, b: &SynValue) -> Ordering {
    let (a, b) = (labels::unwrap(a), labels::unwrap(b));
    match (missing_rank(a), missing_rank(b)) {
        (0, 0) => {}
        (x, y) => return x.cmp(&y),
    }
    match (a, b) {
        (SynValue::Number(x), SynValue::Number(y)) => x.partial_cmp_num(y).unwrap_or(Ordering::Equal),
        (SynValue::Text(x), SynValue::Text(y)) => x.as_ref().cmp(y.as_ref()),
        (SynValue::Bool(x), SynValue::Bool(y)) => x.cmp(y),
        (SynValue::Bytes(x), SynValue::Bytes(y)) => x.as_ref().cmp(y.as_ref()),
        (SynValue::Time(x), SynValue::Time(y)) => crate::temporal::cmp(x, y).unwrap_or(Ordering::Equal),
        (SynValue::List(x), SynValue::List(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            for (p, q) in x.iter().zip(y.iter()) {
                let c = total_cmp(p, q);
                if c != Ordering::Equal {
                    return c;
                }
            }
            x.len().cmp(&y.len())
        }
        _ => Ordering::Equal,
    }
}

/// Comparación para ordenar con dirección: los faltantes quedan al final en ambas.
fn order_for(a: &SynValue, b: &SynValue, desc: bool) -> Ordering {
    let (ma, mb) = (missing_rank(a), missing_rank(b));
    if ma != 0 || mb != 0 {
        return ma.cmp(&mb);
    }
    let c = total_cmp(a, b);
    if desc {
        c.reverse()
    } else {
        c
    }
}

/// Error claro si los valores no se pueden ordenar juntos (texto con números, mapas…),
/// en vez de dejar la lista como vino (lo que hacía `sort_by` hasta v0.6.28).
/// La igualdad de un patrón de valor de `match`: la de `==` (`strict_equals`). Un decimal contra
/// un float es error, no un "no matchea" que cae en `otherwise` en silencio.
fn pattern_eq(value: &SynValue, p: &SynValue) -> Result<bool, Control> {
    // `match 1.5d` contra `is 1.5` no cae en silencio en `otherwise`: es el error de `==`.
    crate::tabular::strict_equals(value, p).map_err(|_| err(format!("match: {}", MIX_DECIMAL_FLOAT)))
}

/// ¿Comparar `a` con `b` para ordenar junta un decimal con un float? Como `<`: en listas, sólo
/// las posiciones que la comparación lexicográfica llega a mirar (hasta la primera distinta).
/// `sort([[1d, 1.5], [2d, 2.5]])` nunca compara un decimal con un float; `[[1.5d], [1.0]]` sí.
fn order_clash(a: &SynValue, b: &SynValue) -> bool {
    match (labels::unwrap(a), labels::unwrap(b)) {
        (SynValue::List(x), SynValue::List(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            for (p, q) in x.iter().zip(y.iter()) {
                if order_clash(p, q) {
                    return true;
                }
                if order_for(p, q, false) != Ordering::Equal {
                    return false;
                }
            }
            false
        }
        (a, b) => {
            let is_dec = |v: &SynValue| matches!(v, SynValue::Number(n) if n.is_decimal());
            let is_flt = |v: &SynValue| matches!(v, SynValue::Number(Number::Float(x)) if !x.is_nan());
            (is_dec(a) && is_flt(b)) || (is_flt(a) && is_dec(b))
        }
    }
}

/// Ordena con `order_for`, cortando con el error de `<` si una comparación real junta un decimal
/// con un float.
fn sort_checked<T>(items: &mut [T], key: impl Fn(&T) -> &SynValue, desc: bool, who: &str) -> Result<(), Control> {
    let clash = std::cell::Cell::new(false);
    items.sort_by(|a, b| {
        let (a, b) = (key(a), key(b));
        if !clash.get() && order_clash(a, b) {
            clash.set(true);
        }
        order_for(a, b, desc)
    });
    if clash.get() {
        return Err(err(format!("{}: {}", who, MIX_DECIMAL_FLOAT)));
    }
    Ok(())
}

fn check_orderable(vals: &[SynValue], who: &str) -> Result<(), Control> {
    // Decimal con Float lo decide el comparador (`sort_checked`), sólo en comparaciones reales.
    let mut class: Option<&'static str> = None;
    for v in vals {
        if missing_rank(v) != 0 {
            continue;
        }
        let c = order_class(v).ok_or_else(|| {
            err(format!("{}: a {} has no order — sort by a key that is a number, text, bool, bytes or list", who, labels::unwrap(v).type_name()))
        })?;
        match class {
            None => class = Some(c),
            Some(k) if k != c => {
                return Err(err(format!("{}: cannot order {} and {} together — make the key one type", who, k, c)))
            }
            _ => {}
        }
    }
    Ok(())
}

/// El argumento `desc` de `sort`/`sort_by`: ausente o `nothing` = ascendente.
fn desc_flag(v: Option<&SynValue>, who: &str) -> Result<bool, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(err(format!("{}: desc must be true or false, got {}", who, other.type_name()))),
    }
}

#[allow(dead_code)]
fn sort_cmp(a: &SynValue, b: &SynValue) -> Ordering {
    match (a, b) {
        (SynValue::Number(x), SynValue::Number(y)) => x.partial_cmp_num(y).unwrap_or(Ordering::Equal),
        (SynValue::Text(x), SynValue::Text(y)) => x.as_ref().cmp(y.as_ref()),
        // Claves etiquetadas (un `give` bajo PC) se ordenan por su valor interno.
        (SynValue::Private(_), _) | (_, SynValue::Private(_)) => {
            sort_cmp(labels::unwrap(a), labels::unwrap(b))
        }
        _ => Ordering::Equal,
    }
}

/// Quita el prefijo "file:line:col: " de un mensaje de error (como en try/recover).
fn strip_loc_prefix(msg: &str) -> String {
    if !msg.starts_with(' ') {
        if let Some(idx) = msg.find(": ") {
            let head = &msg[..idx];
            if head.matches(':').count() >= 2 {
                return msg[idx + 2..].to_string();
            }
        }
    }
    msg.to_string()
}

/// `repr()` de Python para un string (comillas simples por defecto).
fn py_repr_str(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn compile_re(pat: &str) -> Result<Regex, Control> {
    Regex::new(pat).map_err(|e| err(format!("invalid regex pattern {}: {}", py_repr_str(pat), e)))
}

/// Compila para semántica `fullmatch` (todo el texto debe coincidir).
fn compile_re_full(pat: &str) -> Result<Regex, Control> {
    let wrapped = format!("^(?:{})$", pat);
    Regex::new(&wrapped)
        .map_err(|e| err(format!("invalid regex pattern {}: {}", py_repr_str(pat), e)))
}

/// Traduce el reemplazo estilo Python (`\1`, `\g<n>`) al de Rust (`${1}`),
/// escapando `$` literal como `$$`.
fn translate_replacement(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '$' => out.push_str("$$"),
            '\\' => match chars.peek().copied() {
                Some(d) if d.is_ascii_digit() => {
                    let mut num = String::new();
                    while let Some(d2) = chars.peek().copied() {
                        if d2.is_ascii_digit() {
                            num.push(d2);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    out.push_str(&format!("${{{}}}", num));
                }
                Some('g') => {
                    chars.next();
                    if chars.peek() == Some(&'<') {
                        chars.next();
                        let mut name = String::new();
                        while let Some(c2) = chars.peek().copied() {
                            if c2 == '>' {
                                chars.next();
                                break;
                            }
                            name.push(c2);
                            chars.next();
                        }
                        out.push_str(&format!("${{{}}}", name));
                    } else {
                        out.push('g');
                    }
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                _ => out.push('\\'),
            },
            c => out.push(c),
        }
    }
    out
}

// =========================================================
// runner mínimo (espejo de engine.run_source para los tests de capa 4)
// =========================================================

/// Resultado observable de un programa. Sólo lleva datos `Send` (el `SynValue`
/// final y el intérprete viven y mueren dentro del hilo de ejecución, porque
/// `SynValue` usa `Rc` y no es `Send`).
pub struct RunResult {
    pub success: bool,
    pub output: Vec<String>,
    pub errors: Vec<String>,
}

/// Resultado de un bloque `test` (Batch 3). `assertion` distingue una falla de aserción
/// de otro error de runtime (sólo para el ícono del reporte).
#[derive(Debug, Clone)]
pub struct TestOutcome {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
    pub assertion: bool,
}

/// Stack del hilo de ejecución del intérprete. Grande porque el intérprete es
/// tree-walking (frames grandes) y los programas pueden recursar; el engine y los
/// agentes (capa 7+) usarán hilos similares.
const INTERP_STACK_SIZE: usize = 512 * 1024 * 1024;

fn run_inner(source: &str, filename: &str) -> RunResult {
    // Las categorías de error ("Lexer error:" / "Parse error:" / "Runtime error:")
    // las antepone el engine sólo al error NO atrapado (engine.py:814-830). Los
    // errores capturados por try/recover usan str(e) sin categoría — eso ocurre
    // dentro del intérprete, no acá. Nunca emitimos "Internal error:".
    match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Lexer error: {}", e)],
        },
        Err(CompileError::Parse(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Parse error: {}", e)],
        },
        Ok(program) => {
            let mut interp = Interpreter::new();
            match interp.execute(&program) {
                Ok(_) => RunResult {
                    success: true,
                    output: std::mem::take(&mut interp.output),
                    errors: Vec::new(),
                },
                Err(Control::Error(e)) => RunResult {
                    success: false,
                    output: std::mem::take(&mut interp.output),
                    errors: vec![format!("Runtime error: {}", e)],
                },
                // `give`/`stop` que escapan al top: error limpio (no "Internal error:").
                Err(Control::Give(_)) | Err(Control::Stop(_)) => RunResult {
                    success: false,
                    output: std::mem::take(&mut interp.output),
                    errors: vec![
                        "Runtime error: 'give'/'stop' used outside of a task or loop".to_string(),
                    ],
                },
            }
        }
    }
}

/// Ejecuta un programa Synsema y devuelve su salida observable. Corre en un
/// hilo dedicado con stack grande.
pub fn run_source(source: &str, filename: &str) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_inner(&src, &fname))
        .expect("no se pudo crear el hilo del intérprete")
        .join()
        .unwrap_or_else(|p| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!(
                "internal error in the interpreter (a bug, not your program — please report it): {}",
                p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default()
            )],
        })
}

#[cfg(test)]
mod lineage_host_tests {
    use super::{url_host, url_of_connection};
    use crate::types::{syn_list, syn_text};

    fn host(source: &str, args: &[crate::types::SynValue]) -> String {
        url_host(url_of_connection(source, args))
    }

    // Un recibo firmado publica el host de la CONEXIÓN y nada más: una clave de redis, una
    // categoría de `recall` o un filtro con forma de URL son datos (antes, `recall("session://TOKEN")`
    // publicaba `TOKEN` como host).
    #[test]
    fn only_the_connection_gives_a_host() {
        assert_eq!(host("recall", &[syn_text("session://TOKEN-SECRETO")]), "");
        assert_eq!(host("redis_get", &[syn_text("session://TOKEN-SECRETO")]), "");
        assert_eq!(host("mongo_find", &[syn_text("db://x"), syn_text("https://a.b/c")]), "");
        assert_eq!(host("sql", &[syn_text("SELECT 'http://x.com'"), syn_list(vec![])]), "");
        assert_eq!(host("http_get", &[syn_text("http://alice:pw@api.x.com:8080/v1?k=K#f")]), "api.x.com:8080");
        assert_eq!(host("http", &[syn_text("GET"), syn_text("HTTPS://api.x.com/v1")]), "api.x.com");
        assert_eq!(host("evm_rpc", &[syn_text("https://rpc.x.org/KEY"), syn_text("eth_chainId")]), "rpc.x.org");
        // Un esquema que no es de red no es un host, aunque venga en el lugar de la conexión.
        assert_eq!(host("evm_rpc", &[syn_text("session://TOKEN")]), "");
        assert_eq!(host("http_get", &[syn_text(" http://x.com")]), "x.com");
    }
}

#[cfg(test)]
mod llm_offline_notice_tests {
    use super::first_time;
    use std::sync::atomic::AtomicBool;

    // El aviso de LLM-offline es único: `first_time` devuelve true SOLO la primera vez.
    // (Se testea sobre un flag LOCAL — la static del proceso puede ya estar consumida
    // por otros tests que ejercitan placeholders; el aviso mismo es solo un eprintln.)
    #[test]
    fn first_time_is_true_exactly_once() {
        let flag = AtomicBool::new(false);
        assert!(first_time(&flag), "la primera vez debe ser true");
        assert!(!first_time(&flag), "la segunda vez debe ser false");
        assert!(!first_time(&flag), "y todas las siguientes también");
    }
}

#[cfg(test)]
mod drop_tests {
    use super::*;
    use crate::types::SynTaskValue;
    use std::rc::Rc;

    /// El intérprete por-request arma un `global_env` fresco con tasks que cierran sobre él
    /// (`closure_env = global_env`) → ciclo Rc `global_env ⇄ task`. Sin romperlo, el entorno
    /// global se filtra en CADA request (segundo OOM del serve, pinned en Linux). El `Drop`
    /// del intérprete debe cortar el ciclo: tras droppearlo, el `global_env` ya no debe vivir.
    #[test]
    fn drop_breaks_global_env_task_cycle() {
        let weak;
        {
            let interp = Interpreter::new();
            let task = SynValue::Task(Rc::new(SynTaskValue {
                name: "f".to_string(),
                parameters: vec![],
                body: vec![],
                closure_env: interp.global_env.clone(), // task → global_env (la mitad del ciclo)
                origin: None,
                required_capabilities: vec![],
            }));
            interp.set_global("f", task); // global_env → task (la otra mitad)
            weak = Rc::downgrade(&interp.global_env);
            assert!(weak.upgrade().is_some(), "global_env vivo mientras el interp vive");
        } // el interp se dropea acá → Drop vacía bindings → corta el ciclo
        assert!(
            weak.upgrade().is_none(),
            "FUGA: global_env sigue vivo tras drop — el ciclo Rc no se rompió"
        );
    }

    /// `run_request_block` corre el handler en un scope HIJO efímero y, como el
    /// intérprete se REUSA entre requests (perf/interp-reuse), no se dropea por request.
    /// Si el handler hace `define task` dentro del body, la task cierra sobre ese scope
    /// → ciclo `scope ⇄ task`. `run_request_block` vacía las bindings del hijo al final
    /// para cortarlo: tras correr, el scope del request NO debe seguir vivo (igual
    /// invariante que el Drop del global, fix de OOM #7, pero para el scope del request).
    #[test]
    fn request_scope_does_not_leak_handler_defined_task() {
        let interp = Interpreter::new(); // se reusa: NO se dropea entre "requests"
        let weak;
        {
            // Replica lo que hace run_request_block: child env + una task que cierra
            // sobre él (lo que produciría un `define task` dentro del handler).
            let env = Environment::child(&interp.global_env, "request");
            let task = SynValue::Task(Rc::new(SynTaskValue {
                name: "t".to_string(),
                parameters: vec![],
                body: vec![],
                closure_env: env.clone(), // task → child (mitad del ciclo)
                origin: None,
                required_capabilities: vec![],
            }));
            env.borrow_mut().bindings.insert("t".to_string(), task); // child → task (otra mitad)
            weak = Rc::downgrade(&env);
            assert!(weak.upgrade().is_some(), "scope del request vivo mientras corre");
            // El cierre que hace run_request_block tras exec_block:
            env.borrow_mut().bindings.clear();
        }
        assert!(
            weak.upgrade().is_none(),
            "FUGA: el scope del request sigue vivo — el ciclo Rc no se rompió (el reuse del \
             intérprete lo filtraría por request)"
        );
    }
}

#[cfg(test)]
mod lambda_tests {
    use super::run_source;

    fn out(src: &str) -> Vec<String> {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        r.output
    }

    #[test]
    fn lambda_is_task_type() {
        assert_eq!(out("print(type_of((x) => x))"), vec!["task"]);
    }

    #[test]
    fn lambda_evaluates_and_calls() {
        assert_eq!(out("let double be (x) => x * 2\nprint(text(double(21)))"), vec!["42"]);
    }

    #[test]
    fn lambda_closes_over_outer_let() {
        let src = "let y be 10\nlet f be (x) => x + y\nprint(text(f(5)))";
        assert_eq!(out(src), vec!["15"]);
    }

    #[test]
    fn lambda_zero_arg_called() {
        assert_eq!(out("let f be () => 7\nprint(text(f()))"), vec!["7"]);
    }

    #[test]
    fn lambda_curried() {
        let src = "let curry be (m) => (n) => m * n\nlet t3 be curry(3)\nprint(text(t3(4)))";
        assert_eq!(out(src), vec!["12"]);
    }

    #[test]
    fn lambda_missing_arg_is_an_error() {
        // v0.6.29: una llamada escrita a una lambda cumple la misma aridad que un task.
        let r = run_source("let f be (a, b) => b\nprint(text(f(5)))", "<test>");
        assert!(!r.success && r.errors.iter().any(|e| e.contains("missing argument 'b'")), "{:?}", r.errors);
    }

    #[test]
    fn lambda_extra_args_are_an_error() {
        let r = run_source("let f be (x) => x\nprint(text(f(1, 2, 3)))", "<test>");
        assert!(!r.success && r.errors.iter().any(|e| e.contains("takes 1 argument, got 3")), "{:?}", r.errors);
    }

    #[test]
    fn apply_with_lambda() {
        assert_eq!(out("print(apply((x) => x * 2, [1, 2, 3]))"), vec!["[2, 4, 6]"]);
    }

    #[test]
    fn reduce_with_lambda() {
        assert_eq!(out("print(text(reduce([1, 2, 3], (a, b) => a + b, 0)))"), vec!["6"]);
    }

    #[test]
    fn where_with_lambda_predicate() {
        assert_eq!(out("print(where([1, 2, 3, 4], (x) => x > 2))"), vec!["[3, 4]"]);
    }

    #[test]
    fn sort_by_with_lambda_key() {
        assert_eq!(out("print(sort_by([3, 1, 2], (x) => x))"), vec!["[1, 2, 3]"]);
    }

    #[test]
    fn call_non_function_fails() {
        let r = run_source("let x be 5\nprint(x(1))", "<test>");
        assert!(!r.success, "llamar a un no-función debería fallar");
    }
}

#[cfg(test)]
mod module_tests {
    use super::run_source;
    use std::fs;

    /// Crea un dir temporal con fixtures `.syn` y devuelve el path del entrypoint
    /// (cuyo dir es contra el que resuelven los `use "./x.syn"`). El entrypoint no
    /// se escribe a disco: run_source parsea el `source` directamente.
    fn setup(tag: &str, fixtures: &[(&str, &str)]) -> String {
        let dir = std::env::temp_dir().join(format!("synsema_modtest_{}", tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for (name, content) in fixtures {
            fs::write(dir.join(name), content).unwrap();
        }
        dir.join("__entry__.syn").to_string_lossy().to_string()
    }

    #[test]
    fn basic_import_and_call() {
        let entry = setup("basic", &[(
            "orders.syn",
            "task _mk(name, amount)\n    give {\"name\": name, \"amount\": amount}\n\
             export task create(name, amount)\n    give _mk(name, amount)\n\
             export task total(o)\n    give amount of o\n",
        )]);
        let r = run_source(
            "use \"./orders.syn\" as orders\nlet o be orders.create(\"Ana\", 500)\n\
             print(text(orders.total(o)))",
            &entry,
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["500"]);
    }

    #[test]
    fn module_private_isolation() {
        let entry = setup("private", &[(
            "orders.syn",
            "task _mk(x)\n    give x\nexport task create(x)\n    give _mk(x)\n",
        )]);
        let r = run_source("use \"./orders.syn\" as orders\nprint(orders._mk(1))", &entry);
        assert!(!r.success, "acceder a un nombre privado del módulo debería fallar");
    }

    #[test]
    fn circular_import_errors() {
        let entry = setup("circular", &[
            ("a.syn", "use \"./b.syn\" as b\nexport task fa()\n    give 1\n"),
            ("b.syn", "use \"./a.syn\" as a\nexport task fb()\n    give 2\n"),
        ]);
        let r = run_source("use \"./a.syn\" as a\nprint(1)", &entry);
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains("circular import")), "{:?}", r.errors);
    }

    #[test]
    fn serve_in_module_errors() {
        let entry = setup("serve", &[(
            "srv.syn",
            "export task f()\n    give 1\nserve on 8080\n    route \"GET /x\"\n        give 1\n",
        )]);
        let r = run_source("use \"./srv.syn\" as s\nprint(1)", &entry);
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains("serve")), "{:?}", r.errors);
    }

    #[test]
    fn toplevel_require_in_module_errors() {
        let entry = setup("require", &[(
            "req.syn",
            "require net(\"x.com\")\nexport task f()\n    give 1\n",
        )]);
        let r = run_source("use \"./req.syn\" as r\nprint(1)", &entry);
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains("require")), "{:?}", r.errors);
    }

    #[test]
    fn caching_runs_module_once() {
        let entry = setup("cache", &[(
            "noisy.syn",
            "print(\"loaded\")\nexport let answer be 42\n",
        )]);
        let r = run_source(
            "use \"./noisy.syn\" as m\nuse \"./noisy.syn\" as m2\nprint(text(m.answer))",
            &entry,
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["loaded", "42"]);
    }

    #[test]
    fn traversal_path_errors() {
        let entry = setup("traversal", &[]);
        let r = run_source("use \"../secret.syn\" as x\nprint(1)", &entry);
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains("escapes")), "{:?}", r.errors);
    }

    #[test]
    fn non_syn_path_errors() {
        let entry = setup("nonsyn", &[]);
        let r = run_source("use \"./x.txt\" as x\nprint(1)", &entry);
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains(".syn")), "{:?}", r.errors);
    }

    #[test]
    fn export_enum_construct_and_match_cross_module() {
        let entry = setup(
            "exportenum",
            &[(
                "ordstatus.syn",
                "export enum OrderStatus\n    pending\n    paid(method)\n    shipped(carrier, tracking)\nenum Hidden\n    secret\n",
            )],
        );
        // construir + leer payload por `of` desde el importador
        let r = run_source(
            "use \"./ordstatus.syn\" as orders\nlet s be orders.OrderStatus.shipped(\"DHL\", \"ABC\")\nprint(carrier of s)",
            &entry,
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["DHL"]);
        // match por variante cross-módulo + otherwise
        let m = "use \"./ordstatus.syn\" as orders\nlet s be orders.OrderStatus.shipped(\"DHL\", \"ABC\")\nmatch s\n    is orders.OrderStatus.pending\n        print(\"p\")\n    is orders.OrderStatus.shipped\n        print(\"enviado por \" + carrier of s)\n    otherwise\n        print(\"otro\")\n";
        let r2 = run_source(m, &entry);
        assert!(r2.success, "{:?}", r2.errors);
        assert_eq!(r2.output, vec!["enviado por DHL"]);
        // un enum NO exportado no es visible
        let r3 = run_source("use \"./ordstatus.syn\" as orders\nprint(orders.Hidden)", &entry);
        assert!(!r3.success, "Hidden no debería ser visible");
    }
}

#[cfg(test)]
mod enum_tests {
    use super::run_source;

    const ENUM: &str = "enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n";

    fn out(src: &str) -> Vec<String> {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        r.output
    }

    #[test]
    fn construct_and_payload_access() {
        let src = format!(
            "{}let o be Order.shipped(\"2026-06-23\", \"DHL\")\nprint(carrier of o)\nprint(date of o)",
            ENUM
        );
        assert_eq!(out(&src), vec!["DHL", "2026-06-23"]);
    }

    #[test]
    fn nullary_value_is_map() {
        assert_eq!(out(&format!("{}let s be Order.pending\nprint(type_of(s))", ENUM)), vec!["map"]);
    }

    #[test]
    fn match_payloaded_variant() {
        let src = format!(
            "{}let o be Order.shipped(\"d\", \"DHL\")\nmatch o\n    is Order.pending\n        print(\"p\")\n    is Order.shipped\n        print(\"enviado por \" + carrier of o)\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["enviado por DHL"]);
    }

    #[test]
    fn match_nullary_variant() {
        let src = format!(
            "{}let o be Order.pending\nmatch o\n    is Order.paid\n        print(\"paid\")\n    is Order.pending\n        print(\"pend\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["pend"]);
    }

    #[test]
    fn match_no_arm_returns_nothing() {
        let src = format!(
            "{}let o be Order.paid(50)\nmatch o\n    is Order.pending\n        print(\"p\")\n",
            ENUM
        );
        assert_eq!(out(&src), Vec::<String>::new());
    }

    #[test]
    fn equality_nullary_and_different() {
        assert_eq!(out(&format!("{}print(text(Order.pending == Order.pending))", ENUM)), vec!["true"]);
        assert_eq!(
            out(&format!("{}print(text(Order.pending == Order.paid(1)))", ENUM)),
            vec!["false"]
        );
    }

    #[test]
    fn wrong_arity_errors() {
        let r = run_source(&format!("{}let o be Order.shipped(\"d\")", ENUM), "<test>");
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains("expects 2 fields, got 1")), "{:?}", r.errors);
    }

    #[test]
    fn nullary_not_callable() {
        let r = run_source(&format!("{}let o be Order.pending()", ENUM), "<test>");
        assert!(!r.success);
    }

    #[test]
    fn non_enum_match_regression() {
        let src = "let x be 9\nmatch x\n    is 5\n        print(\"five\")\n    is 9\n        print(\"nine\")\n";
        assert_eq!(out(src), vec!["nine"]);
    }
}

#[cfg(test)]
mod match_fixes_tests {
    use super::run_source;

    fn out(src: &str) -> Vec<String> {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        r.output
    }

    const ENUM: &str = "enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n";

    // -- Parte A: otherwise --

    #[test]
    fn otherwise_runs_when_no_arm_matches() {
        let src = "let x be 9\nmatch x\n    is 5\n        print(\"five\")\n    otherwise\n        print(\"other\")\n";
        assert_eq!(out(src), vec!["other"]);
    }

    #[test]
    fn otherwise_not_run_when_arm_matches() {
        let src = "let x be 5\nmatch x\n    is 5\n        print(\"five\")\n    otherwise\n        print(\"other\")\n";
        assert_eq!(out(src), vec!["five"]);
    }

    #[test]
    fn no_otherwise_no_match_is_nothing() {
        let src = "let x be 9\nmatch x\n    is 5\n        print(\"five\")\n";
        assert_eq!(out(src), Vec::<String>::new());
    }

    #[test]
    fn enum_match_otherwise_for_unhandled_variant() {
        let src = format!(
            "{}let o be Order.paid(50)\nmatch o\n    is Order.pending\n        print(\"p\")\n    is Order.shipped\n        print(\"s\")\n    otherwise\n        print(\"otro\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["otro"]);
    }

    #[test]
    fn enum_match_otherwise_not_run_for_handled_variant() {
        let src = format!(
            "{}let o be Order.shipped(\"d\", \"DHL\")\nmatch o\n    is Order.shipped\n        print(\"enviado por \" + carrier of o)\n    otherwise\n        print(\"otro\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["enviado por DHL"]);
    }

    // -- Parte B: la igualdad estructural de Rust ya es correcta (regresión) --

    #[test]
    fn structural_map_equality() {
        assert_eq!(out("print(text({\"x\": 1} == {\"x\": 1}))"), vec!["true"]);
        assert_eq!(out("print(text([1, 2] == [1, 2]))"), vec!["true"]);
        assert_eq!(out("print(text({\"x\": 1} == {\"x\": 2}))"), vec!["false"]);
    }

    #[test]
    fn payloaded_enum_equality() {
        let src = format!("{}print(text(Order.shipped(\"a\",\"b\") == Order.shipped(\"a\",\"b\")))", ENUM);
        assert_eq!(out(&src), vec!["true"]);
    }
}

#[cfg(test)]
mod match_binding_tests {
    use super::run_source;

    const ENUM: &str = "enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n";

    fn out(src: &str) -> Vec<String> {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        r.output
    }

    // `is Order.shipped(d, c)` liga el payload POSICIONALMENTE (orden declarado).
    #[test]
    fn binds_payload_positionally() {
        let src = format!(
            "{}let o be Order.shipped(\"2026-06-23\", \"DHL\")\nmatch o\n    is Order.shipped(d, c)\n        print(d)\n        print(c)\n",
            ENUM
        );
        // date=d, carrier=c (orden declarado: shipped(date, carrier))
        assert_eq!(out(&src), vec!["2026-06-23", "DHL"]);
    }

    #[test]
    fn binds_single_field_variant() {
        let src = format!(
            "{}let o be Order.paid(99)\nmatch o\n    is Order.paid(amt)\n        print(text(amt))\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["99"]);
    }

    // El arm de binding se SALTEA si la variante no matchea (sin fuga de binders).
    #[test]
    fn binding_arm_skipped_on_non_matching_variant() {
        let src = format!(
            "{}let o be Order.pending\nmatch o\n    is Order.shipped(d, c)\n        print(c)\n    is Order.pending\n        print(\"pend\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["pend"]);
    }

    // `otherwise` corre si ningún `is` (incluido uno con binding) matchea.
    #[test]
    fn otherwise_runs_when_binding_arm_does_not_match() {
        let src = format!(
            "{}let o be Order.pending\nmatch o\n    is Order.shipped(d, c)\n        print(c)\n    otherwise\n        print(\"otro\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["otro"]);
    }

    // Aridad: `is Order.shipped(d)` contra un shipped (2 campos) → error claro.
    #[test]
    fn arity_mismatch_errors() {
        let src = format!(
            "{}let o be Order.shipped(\"d\", \"c\")\nmatch o\n    is Order.shipped(d)\n        print(d)\n",
            ENUM
        );
        let r = run_source(&src, "<test>");
        assert!(!r.success, "binder-count incorrecto debería fallar");
        assert!(
            r.errors.iter().any(|e| e.contains("binds 2 fields, got 1")),
            "error de aridad esperado, got {:?}",
            r.errors
        );
    }

    // Los binders están scopeados al arm: no son visibles tras el match.
    #[test]
    fn binders_are_arm_scoped() {
        let src = format!(
            "{}let o be Order.shipped(\"d\", \"DHL\")\nmatch o\n    is Order.shipped(d, c)\n        print(c)\nprint(c)\n",
            ENUM
        );
        let r = run_source(&src, "<test>");
        assert!(!r.success, "el binder `c` no debería ser visible tras el match");
        assert!(
            r.errors.iter().any(|e| e.contains("Undefined") || e.contains("c")),
            "se esperaba un error de variable indefinida, got {:?}",
            r.errors
        );
    }

    #[test]
    fn binder_shadows_outer() {
        let src = format!(
            "{}let c be \"outer\"\nlet o be Order.shipped(\"d\", \"DHL\")\nmatch o\n    is Order.shipped(d, c)\n        print(c)\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["DHL"]);
    }

    // -- Regresión: las formas existentes siguen igual --

    #[test]
    fn no_parens_variant_still_matches() {
        let src = format!(
            "{}let o be Order.pending\nmatch o\n    is Order.pending\n        print(\"pend\")\n",
            ENUM
        );
        assert_eq!(out(&src), vec!["pend"]);
    }

    #[test]
    fn literal_payload_is_value_match() {
        // `is Order.paid(100)` (literal, no identificador) → patrón de valor.
        let hit = format!(
            "{}let o be Order.paid(100)\nmatch o\n    is Order.paid(100)\n        print(\"cien\")\n    otherwise\n        print(\"otro\")\n",
            ENUM
        );
        assert_eq!(out(&hit), vec!["cien"]);
        let miss = format!(
            "{}let o be Order.paid(50)\nmatch o\n    is Order.paid(100)\n        print(\"cien\")\n    otherwise\n        print(\"otro\")\n",
            ENUM
        );
        assert_eq!(out(&miss), vec!["otro"]);
    }

    #[test]
    fn non_enum_match_unchanged() {
        let src = "let x be 9\nmatch x\n    is 5\n        print(\"five\")\n    is 9\n        print(\"nine\")\n";
        assert_eq!(out(src), vec!["nine"]);
    }
}

#[cfg(test)]
mod semantic_invariants {
    //! Red de seguridad que reemplaza al oráculo diferencial de Python para la
    //! semántica más riesgosa: igualdad ESTRUCTURAL (donde estuvo el bug real),
    //! orden, coerción, `contains` y la igualdad del `match`. Corre programas
    //! `.syn` reales por run_source. Rust es ahora la fuente de verdad.
    use super::run_source;

    fn line(src: &str) -> String {
        let r = run_source(src, "<inv>");
        assert!(r.success, "programa falló: {:?} | src={}", r.errors, src);
        assert_eq!(r.output.len(), 1, "esperaba 1 línea, got {:?}", r.output);
        r.output.into_iter().next().unwrap()
    }
    fn b(expr: &str) -> String {
        line(&format!("print(text({}))", expr))
    }
    fn t(expr: &str) {
        assert_eq!(b(expr), "true", "esperaba true: {}", expr);
    }
    fn f(expr: &str) {
        assert_eq!(b(expr), "false", "esperaba false: {}", expr);
    }

    // -- Igualdad estructural de maps (el bug que encontramos: separately-built) --
    #[test]
    fn eq_maps_structural() {
        t(r#"{"x": 1} == {"x": 1}"#);
        t(r#"{"a": 1, "b": 2} == {"a": 1, "b": 2}"#);
        f(r#"{"x": 1} == {"x": 2}"#);
        f(r#"{"x": 1} == {"y": 1}"#);
        f(r#"{"x": 1} == {"x": 1, "y": 2}"#); // distinto tamaño
        t(r#"{} == {}"#);
    }

    #[test]
    fn eq_nested_composites() {
        t(r#"{"a": [1, 2], "b": {"c": 3}} == {"a": [1, 2], "b": {"c": 3}}"#);
        f(r#"{"a": [1, 2]} == {"a": [1, 3]}"#);
    }

    #[test]
    fn eq_lists_structural_and_ordered() {
        t("[1, 2, 3] == [1, 2, 3]");
        f("[1, 2, 3] == [1, 2]");
        f("[1, 2] == [2, 1]"); // el orden importa
        t("[] == []");
    }

    #[test]
    fn eq_reflexive_and_separately_built() {
        assert_eq!(line("let m be {\"x\": 1}\nprint(text(m == m))"), "true");
        assert_eq!(
            line("let a be [1, {\"k\": 2}]\nlet z be [1, {\"k\": 2}]\nprint(text(a == z))"),
            "true"
        );
    }

    #[test]
    fn neq_is_negation_of_eq() {
        f(r#"{"x": 1} != {"x": 1}"#);
        t(r#"{"x": 1} != {"x": 2}"#);
        f("5 != 5");
    }

    // -- Escalares + coerción (bool/number = Python `True == 1`) --
    #[test]
    fn eq_scalars_and_coercion() {
        t("5 == 5");
        t("\"a\" == \"a\"");
        t("nothing == nothing");
        t("true == true");
        t("true == 1");
        t("false == 0");
        f("5 == \"5\""); // tipos distintos
        f("true == 2");
        f("\"a\" == \"b\"");
    }

    // -- Orden --
    #[test]
    fn ordering_numbers() {
        t("1 < 2");
        f("2 < 1");
        t("2 <= 2");
        t("3 > 2");
        t("2 >= 2");
        f("2 > 2");
    }

    #[test]
    fn ordering_consistent_with_eq() {
        t("(1 < 2) == (2 > 1)");
        // `not` liga más flojo que `==` en Synsema (not a == b == not (a == b)),
        // por eso se testea aislado en vez de combinarlo con `==`.
        t("not (2 > 2)");
        f("not (2 <= 2)");
    }

    // -- contains usa igualdad estructural --
    #[test]
    fn contains_structural() {
        t(r#"contains([{"x": 1}, {"y": 2}], {"x": 1})"#);
        f(r#"contains([{"x": 1}], {"x": 2})"#);
        t("contains([1, 2, 3], 2)");
        f("contains([1, 2, 3], 9)");
    }

    // -- match (no-variante) usa igualdad estructural --
    #[test]
    fn match_uses_structural_equality() {
        let src = "let m be {\"k\": 1}\nmatch m\n    is {\"k\": 1}\n        print(\"si\")\n    otherwise\n        print(\"no\")\n";
        assert_eq!(line(src), "si");
    }

    // -- Igualdad de variantes de enum con payload (separately-built) --
    #[test]
    fn enum_payload_eq_separately_built() {
        let src = "enum O\n    s(a, b)\nprint(text(O.s(1, 2) == O.s(1, 2)))";
        assert_eq!(line(src), "true");
        let src2 = "enum O\n    s(a, b)\nprint(text(O.s(1, 2) == O.s(1, 9)))";
        assert_eq!(line(src2), "false");
    }
}

#[cfg(test)]
mod soft_dsl_keyword_tests {
    use super::run_source;

    fn out(src: &str) -> Vec<String> {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        r.output
    }

    fn ok(src: &str) {
        let r = run_source(src, "<test>");
        assert!(r.success, "el DSL debería parsear+correr: {:?}", r.errors);
    }

    // ---- Las 14 palabras ahora usables como NOMBRES ----

    #[test]
    fn show_as_task_name_and_call() {
        // `task show(x)` (posición de nombre) + `show(5)` (seguido de `(` → llamada)
        assert_eq!(out("task show(x)\n    give x * 2\nprint(text(show(5)))"), vec!["10"]);
    }

    #[test]
    fn state_as_variable() {
        assert_eq!(out("let state be 1\nprint(text(state))"), vec!["1"]);
    }

    #[test]
    fn measure_as_variable() {
        assert_eq!(out("let measure be 2\nprint(text(measure))"), vec!["2"]);
    }

    #[test]
    fn log_as_task_name_and_call() {
        assert_eq!(out("task log(m)\n    give m\nprint(log(\"x\"))"), vec!["x"]);
    }

    #[test]
    fn soft_word_as_lambda_property() {
        // `(s) => state of s` — `state` es campo/propiedad
        assert_eq!(
            out("let m be {\"state\": 7}\nlet f be (s) => state of s\nprint(text(f(m)))"),
            vec!["7"]
        );
    }

    #[test]
    fn soft_word_as_map_key_and_property() {
        // map key "log" + `log of m` (seguido de `of` → propiedad)
        assert_eq!(out("let m be {\"log\": 1}\nprint(text(log of m))"), vec!["1"]);
    }

    #[test]
    fn statement_soft_words_as_bare_value_names() {
        // Las 10 palabras DSL de statement son identificadores ordinarios en
        // expresión (no son expression-primaries), así que se leen como valor.
        let src = "let agent be 1\nlet share be 2\nlet observe be 3\nlet signal be 4\n\
                   let spawn be 5\nlet state be 6\nlet trace be 7\nlet log be 8\n\
                   let measure be 9\nlet checkpoint be 10\n\
                   print(text(agent + share + observe + signal + spawn + state + trace + log + measure + checkpoint))";
        assert_eq!(out(src), vec!["55"]);
    }

    #[test]
    fn expression_soft_words_as_task_names_and_calls() {
        // ask/show/approve/confirm: usables como nombre de task + llamada `(`.
        assert_eq!(out("task ask(q)\n    give q\nprint(ask(\"hi\"))"), vec!["hi"]);
        assert_eq!(out("task approve(m)\n    give m\nprint(approve(\"ok\"))"), vec!["ok"]);
        assert_eq!(out("task confirm(m)\n    give m\nprint(confirm(\"y\"))"), vec!["y"]);
    }

    // ---- El DSL sigue parseando + corriendo (regresión) ----

    #[test]
    fn dsl_log_still_works() {
        ok("log \"msg\"");
    }

    #[test]
    fn dsl_show_as_label_still_works() {
        ok("show 42 as \"answer\"");
    }

    #[test]
    fn dsl_share_and_observe_still_work() {
        assert_eq!(out("share 5 as \"k\"\nobserve \"k\" as v\nprint(text(v))"), vec!["5"]);
    }

    #[test]
    fn dsl_signal_still_works() {
        ok("signal \"s\"");
    }

    #[test]
    fn dsl_agent_and_spawn_still_work() {
        ok("agent Researcher\n    task search(q)\n        give q\nspawn Researcher");
    }

    #[test]
    fn dsl_approve_confirm_ask_still_work() {
        ok("approve \"deploy?\"");
        ok("confirm \"sure?\"");
        ok("ask \"name?\" with [\"a\", \"b\"]");
    }

    #[test]
    fn dsl_trace_measure_checkpoint_still_work() {
        assert_eq!(out("trace \"t\"\n    print(\"x\")"), vec!["x"]);
        assert_eq!(out("measure \"m\"\n    print(\"y\")"), vec!["y"]);
        ok("checkpoint \"c\"");
    }

    // ---- Seguridad/core siguen reservadas (regresión) ----

    #[test]
    fn security_keywords_stay_reserved() {
        // `require`/`sandbox` son keywords reservadas: no son nombres válidos.
        assert!(!run_source("let require be 1", "<test>").success);
        assert!(!run_source("let sandbox be 1", "<test>").success);
    }
}

#[cfg(test)]
mod math_library_tests {
    use super::run_source;

    fn line(src: &str) -> String {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        assert_eq!(r.output.len(), 1, "se esperaba una línea de salida: {:?}", r.output);
        r.output[0].clone()
    }

    fn fails(src: &str) {
        assert!(!run_source(src, "<test>").success, "se esperaba un error para: {}", src);
    }

    // ---- constantes ----
    #[test]
    fn constants() {
        assert_eq!(line("print(text(pi))"), "3.141592653589793");
        assert_eq!(line("let r be 2\nprint(text(pi * r * r))"), "12.566370614359172");
        assert_eq!(line("print(text(round_to(e, 5)))"), "2.71828");
        assert_eq!(line("print(text(round_to(tau, 5)))"), "6.28319");
        assert_eq!(line("print(text(nan))"), "nan");
        assert_eq!(line("print(text(inf))"), "inf");
        assert_eq!(line("print(text(0 - inf))"), "-inf");
    }

    // ---- raíces / potencias ----
    #[test]
    fn roots_and_powers() {
        assert_eq!(line("print(text(sqrt(16)))"), "4.0");
        assert_eq!(line("print(text(round_to(sqrt(2), 4)))"), "1.4142");
        assert_eq!(line("print(text(is_nan(sqrt(-1))))"), "true");
        assert_eq!(line("print(text(cbrt(27)))"), "3.0");
        assert_eq!(line("print(text(pow(2, 10)))"), "1024"); // int, espeja **
        assert_eq!(line("print(text(hypot(3, 4)))"), "5.0");
    }

    // ---- exp / log ----
    #[test]
    fn exp_and_log() {
        assert_eq!(line("print(text(exp(0)))"), "1.0");
        assert_eq!(line("print(text(round_to(ln(e), 6)))"), "1.0");
        assert_eq!(line("print(text(round_to(log10(1000), 6)))"), "3.0");
        assert_eq!(line("print(text(log2(8)))"), "3.0");
        assert_eq!(line("print(text(is_infinite(ln(0))))"), "true");
        assert_eq!(line("print(text(ln(0)))"), "-inf");
        assert_eq!(line("print(text(is_nan(ln(-1))))"), "true");
        assert_eq!(line("print(text(round_to(log_base(8, 2), 6)))"), "3.0");
    }

    // ---- trig (radianes) ----
    #[test]
    fn trig() {
        assert_eq!(line("print(text(sin(0)))"), "0.0");
        assert_eq!(line("print(text(cos(0)))"), "1.0");
        assert_eq!(line("print(text(round_to(sin(pi / 2), 6)))"), "1.0");
        assert_eq!(line("print(text(round_to(atan2(1, 1), 6)))"), "0.785398");
        assert_eq!(line("print(text(round_to(degrees(pi), 6)))"), "180.0");
        assert_eq!(line("print(text(round_to(radians(180), 6)))"), "3.141593");
    }

    // ---- signo / magnitud / selección (preservan tipo) ----
    #[test]
    fn sign_abs_min_max_clamp() {
        assert_eq!(line("print(text(abs(-5)))"), "5"); // int
        assert_eq!(line("print(text(abs(-5.0)))"), "5.0"); // float (tipo preservado)
        assert_eq!(line("print(text(sign(-3)))"), "-1");
        assert_eq!(line("print(text(sign(0)))"), "0");
        assert_eq!(line("print(text(sign(7)))"), "1");
        assert_eq!(line("print(text(min(3, 5, 1)))"), "1");
        assert_eq!(line("print(text(max([3, 5, 1])))"), "5");
        assert_eq!(line("print(text(min(5)))"), "5");
        assert_eq!(line("print(text(clamp(12, 0, 10)))"), "10");
        assert_eq!(line("print(text(clamp(-3, 0, 10)))"), "0");
        assert_eq!(line("print(text(clamp(5, 0, 10)))"), "5");
    }

    // ---- teoría de números ----
    #[test]
    fn number_theory() {
        assert_eq!(line("print(text(gcd(12, 18)))"), "6");
        assert_eq!(line("print(text(lcm(4, 6)))"), "12");
        assert_eq!(line("print(text(factorial(25)))"), "15511210043330985984000000");
        assert_eq!(line("print(text(factorial(0)))"), "1");
    }

    // ---- introspección ----
    #[test]
    fn introspection() {
        assert_eq!(line("print(text(is_finite(1.0)))"), "true");
        assert_eq!(line("print(text(is_nan(nan)))"), "true");
        assert_eq!(line("print(text(is_infinite(inf)))"), "true");
        assert_eq!(line("print(text(is_finite(inf)))"), "false");
        assert_eq!(line("print(text(is_finite(42)))"), "true"); // los enteros son finitos
        assert_eq!(line("print(text(round_to(3.14159, 2)))"), "3.14");
    }

    // ---- agregados ----
    #[test]
    fn aggregates() {
        assert_eq!(line("print(text(sum([1, 2, 3])))"), "6");
        assert_eq!(line("print(text(product([1, 2, 3, 4])))"), "24");
        assert_eq!(line("print(text(mean([2, 4, 6])))"), "4.0");
        assert_eq!(line("print(text(sum([])))"), "0"); // vacío → 0
        assert_eq!(line("print(text(product([])))"), "1"); // vacío → 1
    }

    // ---- errores ----
    #[test]
    fn errors() {
        fails("print(sqrt(\"x\"))"); // tipo
        fails("print(min())"); // vacío
        fails("print(min([]))"); // lista vacía
        fails("print(mean([]))"); // mean vacío → error
        fails("print(sqrt(1, 2))"); // aridad
        fails("print(gcd(1.5, 2))"); // gcd sobre float
        fails("print(factorial(0 - 3))"); // factorial negativo
    }

    // ---- regresión: redondeo intacto + sin colisión con el soft keyword `log` ----
    #[test]
    fn rounding_builtins_unchanged() {
        assert_eq!(line("print(text(floor(3.7)))"), "3");
        assert_eq!(line("print(text(ceil(3.2)))"), "4");
        assert_eq!(line("print(text(round(2.5)))"), "2"); // ties-to-even
        assert_eq!(line("print(text(trunc(-3.7)))"), "-3");
    }

    #[test]
    fn log_soft_keyword_not_shadowed() {
        // No se registró un builtin `log`: `log "msg"` sigue siendo el DSL.
        assert!(run_source("log \"msg\"", "<test>").success);
    }
}

#[cfg(test)]
mod decimal_tests {
    use super::run_source;

    fn line(src: &str) -> String {
        let r = run_source(src, "<test>");
        assert!(r.success, "el programa falló: {:?}", r.errors);
        assert_eq!(r.output.len(), 1, "se esperaba una línea: {:?}", r.output);
        r.output[0].clone()
    }

    fn fails_with(src: &str, needle: &str) {
        let r = run_source(src, "<test>");
        assert!(!r.success, "se esperaba error para: {}", src);
        assert!(
            r.errors.iter().any(|e| e.contains(needle)),
            "error esperado contiene {:?}, got {:?}",
            needle,
            r.errors
        );
    }

    // ---- literal + exactitud ----
    #[test]
    fn literal_and_exactness() {
        assert_eq!(line("print(text(0.1d + 0.2d == 0.3d))"), "true");
        assert_eq!(line("print(text(19.99d * 3))"), "59.97");
        assert_eq!(line("print(text(1.50d + 1.50d))"), "3.00"); // escala preservada
        assert_eq!(line("print(text(2d ** 3))"), "8"); // ** con exp entero → Decimal
        assert_eq!(line("print(text(2d ** 10))"), "1024");
    }

    // ---- constructor ----
    #[test]
    fn constructor() {
        assert_eq!(line("print(text(decimal(\"1234.56\")))"), "1234.56");
        assert_eq!(line("print(text(decimal(100)))"), "100");
        assert_eq!(line("print(text(decimal(\"0.10\")))"), "0.10"); // escala del string
        fails_with("print(decimal(1.5))", "decimal(float) is not exact");
    }

    // ---- error de mezcla Decimal⊕Float ----
    #[test]
    fn mixing_errors() {
        fails_with("print(1.50d + 1.5)", "cannot mix decimal and float");
        fails_with("print(1.5 - 1.50d)", "cannot mix decimal and float");
        fails_with("print(1.50d * 2.0)", "cannot mix decimal and float");
        fails_with("print(1.50d / 2.0)", "cannot mix decimal and float");
        fails_with("print(text(1.50d < 1.5))", "cannot mix decimal and float");
        fails_with("print(text(1.50d == 1.5))", "cannot mix decimal and float");
        fails_with("print(text(1.50d != 1.5))", "cannot mix decimal and float");
        // Int/Big mezclan libremente:
        assert_eq!(line("print(text(5 + 1.50d))"), "6.50");
        assert_eq!(line("print(text(5 == 5d))"), "true");
        assert_eq!(line("print(text(1.50d < 2))"), "true");
    }

    // ---- división / precisión ----
    #[test]
    fn division_precision() {
        assert_eq!(line("print(text(1d / 4d))"), "0.25"); // exacto
        // precisión por defecto de rust_decimal: 28 dígitos significativos, bancario.
        assert_eq!(line("print(text(1d / 3d))"), "0.3333333333333333333333333333");
    }

    // ---- display / escala ----
    #[test]
    fn display_scale() {
        assert_eq!(line("print(text(1.50d))"), "1.50");
        assert_eq!(line("print(text(100d))"), "100");
        assert_eq!(line("print(text(0.1d))"), "0.1");
    }

    // ---- conversión float() ----
    #[test]
    fn conversion_float() {
        assert_eq!(line("print(text(float(1.50d)))"), "1.5"); // Float (lossy)
        assert_eq!(line("print(text(is_decimal(float(1.50d))))"), "false");
        assert_eq!(line("print(text(float(100d)))"), "100.0");
    }

    // ---- math que preserva Decimal ----
    #[test]
    fn math_preserves_decimal() {
        assert_eq!(line("print(text(abs(0 - 1.50d)))"), "1.50");
        assert_eq!(line("print(text(min(1.5d, 2.5d, 0.5d)))"), "0.5");
        assert_eq!(line("print(text(max([1.5d, 2.5d, 0.5d])))"), "2.5");
        assert_eq!(line("print(text(sum([1.10d, 2.20d])))"), "3.30");
        assert_eq!(line("print(text(product([1.5d, 2d])))"), "3.0");
        assert_eq!(line("print(text(clamp(12.5d, 0d, 10d)))"), "10");
        // trascendentes/raíces coercionan a f64 → Float (irracional, ok):
        assert_eq!(line("print(text(round_to(sqrt(2d), 4)))"), "1.4142");
        // math sobre Decimal⊕Float también erroría:
        fails_with("print(min(1.5d, 2.0))", "cannot mix decimal and float");
    }

    // ---- type_of / is_decimal ----
    #[test]
    fn type_introspection() {
        // DE-021: type_of de un decimal reporta "decimal" (antes colapsaba a "number").
        assert_eq!(line("print(text(type_of(1.5d)))"), "decimal");
        assert_eq!(line("print(text(type_of(decimal(\"1.50\"))))"), "decimal");
        // int/float intactos.
        assert_eq!(line("print(text(type_of(42)))"), "number");
        assert_eq!(line("print(text(type_of(3.14)))"), "number");
        assert_eq!(line("print(text(type_of(complex(1,2))))"), "complex");
        assert_eq!(line("print(text(is_decimal(1.5d)))"), "true");
        assert_eq!(line("print(text(is_decimal(1.5)))"), "false");
        assert_eq!(line("print(text(is_decimal(5)))"), "false");
        assert_eq!(line("print(text(is_decimal(\"x\")))"), "false");
        // dispatch por type_of (el caso de uso que estaba roto para decimal).
        let p = "let x be 1.5d\nwhen type_of(x) == \"decimal\"\n    print(\"ok\")\notherwise\n    print(\"no\")";
        assert_eq!(line(p), "ok");
        // aritmética decimal exacta intacta.
        assert_eq!(line("print(text(0.1d + 0.2d == 0.3d))"), "true");
    }

    // ---- regresión: int/float/bigint intactos; en match/contains Decimal≠Float SIN error ----
    #[test]
    fn regression_other_numbers_unchanged() {
        assert_eq!(line("print(text(2 + 3))"), "5"); // int
        assert_eq!(line("print(text(0.1 + 0.2))"), "0.30000000000000004"); // float drift intacto
        assert_eq!(line("print(text(2 ** 100))"), "1267650600228229401496703205376"); // bigint
        assert_eq!(line("print(text(1.5 < 2.5))"), "true");
    }

    #[test]
    fn match_and_contains_decimal_vs_float_are_the_error_of_eq() {
        // match / contains / index_of usan la igualdad de `==`: un decimal contra un float es
        // error (antes: "distinto" en silencio, y `1.5d == 1.5` ya era error).
        let m = "let d be 1.5d\nmatch d\n    is 1.5\n        print(\"float\")\n    otherwise\n        print(\"otro\")\n";
        fails_with(m, "cannot mix decimal and float");
        fails_with("print(contains([1.5d], 1.5))", "cannot mix decimal and float");
        fails_with("print(index_of([1d, 2.0], 1.0))", "cannot mix decimal and float");
        // Sin mezclar, igual que antes; y con enteros no hay mezcla.
        let ok = "let d be 1.5d\nmatch d\n    is 1.5d\n        print(\"decimal\")\n    otherwise\n        print(\"otro\")\n";
        assert_eq!(line(ok), "decimal");
        assert_eq!(line("print(text(contains([1.5d], 1.5d)))"), "true");
        assert_eq!(line("print(text(contains([1d, 2d], 2)))"), "true");
        // Corta en la primera diferencia: la posición 0 ya decide.
        assert_eq!(line("print(text([\"a\", 1d] == [\"b\", 1.0]))"), "false");
        assert_eq!(line("print(text({\"a\": 1d, \"b\": 1} == {\"a\": 1.0, \"c\": 1}))"), "false");
    }
}

/// Quita las secuencias de escape de terminal (ECMA-48): CSI (`ESC [ ... final`), OSC
/// (`ESC ] ... BEL | ESC \\`), DCS/PM/APC (`ESC P/^/_ ... ESC \\`), escapes de dos
/// bytes (`ESC x`) y los C0 de control salvo `\n`/`\t`. Un `\r` seguido de texto en
/// la misma línea (barra de progreso que se redibuja) conserva sólo el último redibujo.
pub fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut line_start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == 0x1B {
            i += 1;
            match b.get(i) {
                Some(b'[') => {
                    // CSI: parámetros 0x30-0x3F, intermedios 0x20-0x2F, final 0x40-0x7E.
                    i += 1;
                    while i < b.len() && (0x20..=0x3F).contains(&b[i]) {
                        i += 1;
                    }
                    if i < b.len() {
                        i += 1;
                    }
                }
                Some(b']') | Some(b'P') | Some(b'^') | Some(b'_') | Some(b'X') => {
                    // Cadena terminada por BEL o ST (ESC \).
                    i += 1;
                    while i < b.len() {
                        if b[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if b[i] == 0x1B && b.get(i + 1) == Some(&b'\\') {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                Some(&x) if (0x20..=0x2F).contains(&x) => {
                    // nF: intermedios 0x20-0x2F y un final (p. ej. `ESC ( B`, charset).
                    while i < b.len() && (0x20..=0x2F).contains(&b[i]) {
                        i += 1;
                    }
                    if i < b.len() {
                        i += 1;
                    }
                }
                Some(_) => i += 1,
                None => {}
            }
            continue;
        }
        if c == b'\r' {
            // Retorno de carro: si viene texto después en la misma línea, descarta lo
            // ya escrito desde el inicio de la línea (redibujo).
            let next = b.get(i + 1);
            if matches!(next, Some(b'\n')) || next.is_none() {
                i += 1;
                continue;
            }
            out.truncate(line_start);
            i += 1;
            continue;
        }
        if c == b'\n' {
            out.push(c);
            line_start = out.len();
            i += 1;
            continue;
        }
        if c < 0x20 && c != b'\t' {
            i += 1;
            continue;
        }
        if c == 0x7F {
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod strip_ansi_tests {
    use super::strip_ansi;

    #[test]
    fn removes_csi_osc_and_controls() {
        assert_eq!(strip_ansi("\x1b[1;32mok\x1b[0m done"), "ok done");
        assert_eq!(strip_ansi("\x1b]0;title\x07x\x1b]2;t\x1b\\y"), "xy");
        assert_eq!(strip_ansi("a\x1b[2J\x1b[H\x1b[?25lb\x1b(B"), "ab");
        assert_eq!(strip_ansi("tab\tkeep\nline"), "tab\tkeep\nline");
        assert_eq!(strip_ansi("bell\x07\x08x"), "bellx");
    }

    #[test]
    fn carriage_return_keeps_the_last_redraw() {
        assert_eq!(strip_ansi("10%\r50%\r100%\r\nend"), "100%\nend");
        assert_eq!(strip_ansi("line\r\n"), "line\n");
        assert_eq!(strip_ansi("ñandú \x1b[31mé\x1b[0m"), "ñandú é");
    }
}
