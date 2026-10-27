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

use crate::synlist::{list_values, list_values_mut};
use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use smallvec::{smallvec, SmallVec};
use num_complex::Complex64;
use regex::Regex;

use crate::ast::{BinOp, Node, NodeKind, Param, Program, UnOp};
use crate::inline_vec::InlineVec;
use crate::labels::{self, label_display_raw, DeclassifyEntry, Label};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::parser::{parse_source, CompileError};
use crate::templates::resolve_module_path;
use crate::tokens::SourceLocation;
use crate::types::*;

// =========================================================
// errores y control de flujo
// =========================================================

/// Error en tiempo de ejecución, con ubicación opcional. Los datos van en un `Box`: toda
/// evaluación devuelve `Result<SynValue, Control>`, y con el error por valor ese `Result` medía
/// 128 bytes aunque el error no ocurriera nunca (specs/compute-rendimiento.md F1.10). Los campos se
/// leen y escriben como siempre (`e.message`, `e.location = …`) a través de `Deref`.
#[derive(Clone)]
pub struct RuntimeError(Box<RuntimeErrorData>);

impl std::ops::Deref for RuntimeError {
    type Target = RuntimeErrorData;
    fn deref(&self) -> &RuntimeErrorData {
        &self.0
    }
}

impl std::ops::DerefMut for RuntimeError {
    fn deref_mut(&mut self) -> &mut RuntimeErrorData {
        &mut self.0
    }
}

/// La misma salida que daba `#[derive(Debug)]` cuando los campos estaban en `RuntimeError`.
impl fmt::Debug for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeError")
            .field("message", &self.message)
            .field("location", &self.location)
            .field("is_validation", &self.is_validation)
            .field("field", &self.field)
            .field("is_assertion", &self.is_assertion)
            .field("from_private_pc", &self.from_private_pc)
            .field("redact_label", &self.redact_label)
            .field("from_labels", &self.from_labels)
            .field("denied_by_token", &self.denied_by_token)
            .field("operator_detail", &self.operator_detail)
            .finish()
    }
}

/// Los datos de un `RuntimeError`.
#[derive(Debug, Clone)]
pub struct RuntimeErrorData {
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
    /// v0.6.42 — `exit(code)`: no es una falla sino el fin pedido del programa. No se atrapa
    /// (`try/recover`, `assert_error`, los fallbacks lo re-propagan) y el host lo traduce a
    /// código de salida sin imprimir "Runtime error". Va en el `Box`: no agranda nada.
    pub exit_code: Option<i32>,
    /// v0.6.42 — `proxy to <destino>` ejecutado dentro de una ruta: corta el handler (no se
    /// atrapa, como `exit`) y el runtime de `serve` reenvía la request a ese destino.
    pub proxy: Option<ProxyTo>,
    /// v0.6.47 (T1) — el diagnóstico completo de un corte de etiquetas (el mensaje con el sitio y
    /// el remedio, con su ubicación), apartado para el OPERADOR. `Some` quiere decir que `message`
    /// ya es el texto fijo que ve el programa y `location` ya no está: ver
    /// `Interpreter::withhold_labels_detail`. El host lo lleva por su propio canal (stderr del CLI
    /// sin techo, el campo `operator_detail` del wasm, el log de `serve`, el recibo sellado) y
    /// nunca a `errors` ni al log del programa.
    pub operator_detail: Option<String>,
}

/// v0.6.42 — el destino de un `proxy to` evaluado por request.
#[derive(Clone, Debug, PartialEq)]
pub enum ProxyTo {
    /// `http://host[:puerto][/base]`.
    Url(String),
    /// Un extremo de `pipe()`: el motor habla HTTP/1.1 sobre él.
    Handle(i64),
}

impl RuntimeError {
    /// El mensaje, consumiendo el error (los datos van en un `Box`: no se puede mover un campo).
    pub fn into_message(self) -> String {
        self.0.message
    }
    pub fn new(message: impl Into<String>) -> Self {
        RuntimeError(Box::new(RuntimeErrorData { message: message.into(), location: None, is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false, exit_code: None, proxy: None, operator_detail: None }))
    }
    pub fn at(message: impl Into<String>, location: SourceLocation) -> Self {
        RuntimeError(Box::new(RuntimeErrorData { message: message.into(), location: Some(location), is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false, exit_code: None, proxy: None, operator_detail: None }))
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
        RuntimeError(Box::new(RuntimeErrorData { message: message.into(), location: None, is_validation: true, field, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false, exit_code: None, proxy: None, operator_detail: None }))
    }
    /// Falla de aserción (`assert*`): marca `is_assertion` para el reporte de tests.
    pub fn assertion(message: impl Into<String>) -> Self {
        RuntimeError(Box::new(RuntimeErrorData { message: message.into(), location: None, is_validation: false, field: None, is_assertion: true, from_private_pc: false, redact_label: String::new(), from_labels: false, denied_by_token: false, exit_code: None, proxy: None, operator_detail: None }))
    }
    /// Diagnóstico del sistema de etiquetas (`from_labels`), con ubicación.
    pub fn labels(message: impl Into<String>, location: SourceLocation) -> Self {
        RuntimeError(Box::new(RuntimeErrorData { message: message.into(), location: Some(location), is_validation: false, field: None, is_assertion: false, from_private_pc: false, redact_label: String::new(), from_labels: true, denied_by_token: false, exit_code: None, proxy: None, operator_detail: None }))
    }
    /// v0.6.47 (T1, B1): el chequeo de un `stream` (un sumidero del host) es un corte de etiquetas
    /// como cualquier otro: no se atrapa, no lleva ubicación y sale con el texto fijo por el embudo.
    pub fn stream_label_cut(message: impl Into<String>) -> Self {
        Self::label_cut(message)
    }
    /// v0.6.49 (A3): un corte de etiquetas que decide un builtin del stdlib (una operación auditada
    /// o una firma con techo en una rama privada). Sin la marca salía redactado (`private(app)`,
    /// sin texto): se construía bajo el PC privado con `RuntimeError::new`. Sin ubicación, como el de
    /// un `stream`: cuál sitio cortó lo elige el dato.
    pub fn label_cut(message: impl Into<String>) -> Self {
        let mut e = RuntimeError::new(message);
        e.from_labels = true;
        e
    }
    /// v0.6.42 — el fin pedido por `exit(code)` (ver `exit_code`).
    pub fn exit(code: i32) -> Self {
        let mut e = RuntimeError::new(format!("exit({})", code));
        e.exit_code = Some(code);
        e
    }
    /// ¿Es el fin pedido por `exit`? No se atrapa, como los cortes de etiquetas, pero tampoco
    /// redacta la salida: no es un veredicto del enforcement.
    #[inline]
    pub fn is_exit(&self) -> bool {
        self.exit_code.is_some()
    }
    /// ¿Es un corte pedido por el programa (`exit` o `proxy to`)? Ninguno de los dos se atrapa.
    #[inline]
    pub fn is_halt(&self) -> bool {
        self.exit_code.is_some() || self.proxy.is_some()
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
/// v0.6.46 (C6): un argumento con nombre que la task o el builtin no tiene. Dice los que tiene (la
/// firma es dato: es lo que ve un modelo que arma la llamada) y el más cercano si hay uno. Frío:
/// está en el camino de llamada y sólo corre al fallar.
#[cold]
#[inline(never)]
fn unknown_parameter<'a>(name: &str, params: impl Iterator<Item = &'a str>, loc: &SourceLocation) -> Control {
    let params: Vec<&str> = params.collect();
    let mut msg = format!("unknown parameter '{}'", name);
    let close = params
        .iter()
        .map(|p| (crate::capscope::edit_distance(name, p), *p))
        .min()
        .filter(|(d, p)| *d <= 2.max(p.len() / 3));
    if let Some((_, p)) = close {
        msg.push_str(&format!(" — did you mean '{}'?", p));
    }
    if params.is_empty() {
        msg.push_str("; it takes no named arguments");
    } else {
        msg.push_str(&format!("; the parameters are: {}", params.join(", ")));
    }
    err_at(msg, loc)
}

/// El error de leer una variable que no existe (el mismo texto en el tree-walker y en la VM).
/// v0.6.50 (A): ¿hay un `use` de archivo en algún lugar de estas sentencias? (`Program` lo trae
/// del parser como `has_file_use`; esto es para un bloque suelto.)
#[cold]
fn stmts_have_file_use(stmts: &[Node]) -> bool {
    let mut found = false;
    for s in stmts {
        crate::ast_api::walk(s, &mut |n| {
            if let NodeKind::UseImport { path, .. } = &n.kind {
                found |= !path.starts_with("trusted:");
            }
        });
    }
    found
}

/// Las constantes matemáticas del preludio: valores globales que se usan sin llamar.
const PRELUDE_CONSTANTS: [(&str, f64); 5] =
    [("pi", std::f64::consts::PI), ("tau", std::f64::consts::TAU), ("e", std::f64::consts::E), ("inf", f64::INFINITY), ("nan", f64::NAN)];

fn undefined_variable(name: &str, loc: &SourceLocation) -> Control {
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
        name,
        "request" | "query" | "params" | "read_body" | "read_body_bytes"
    ) {
        msg.push_str(&format!(
            ". '{}' is only available inside route handlers (serve) — pass it as a parameter: task handle({})",
            name, name
        ));
    }
    err_at(msg, loc)
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
    short.file = basename_of(&short.file).into();
    Control::Error(RuntimeError::labels(msg, short))
}

/// Nombre de archivo de una ruta (sin directorios), para los diagnósticos que salen al cliente.
/// v0.6.42 — escribe líneas en stderr, sin buffer (un lock, un flush). Con la terminal en raw
/// mode (`term_open`) un `\n` solo no vuelve al margen: `\r\n`, como `drain_output`.
pub fn write_stderr_lines(lines: &[String]) {
    use std::io::Write;
    let raw = crate::term_guard::is_raw();
    let err = std::io::stderr();
    let mut lock = err.lock();
    for line in lines {
        let _ = if raw {
            write!(lock, "{}\r\n", line.replace('\n', "\r\n"))
        } else {
            writeln!(lock, "{}", line)
        };
    }
    let _ = lock.flush();
}

/// v0.6.42 — `exit(code?)`: termina el programa con ese código (0 por defecto, 0–255). Lo hace
/// el host al recibir el error (`engine::finish` → `synsema run`), después de vaciar la salida,
/// el audit y los agentes: nunca un `process::exit` desde acá. Pública para que `serve` la
/// envuelva (bajo un servidor, `exit` remite a `shutdown`).
pub fn exit_builtin(args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
    let code = match args.first() {
        None => 0,
        Some(SynValue::Number(n)) => match n.is_integer().then(|| n.to_i64_trunc()).flatten() {
            Some(c) if (0..=255).contains(&c) => c as i32,
            _ => return Err(err_at(format!("exit: the code must be an integer from 0 to 255, got {}", n), loc)),
        },
        Some(v) => return Err(err_at(format!("exit: the code must be an integer from 0 to 255, got {}", v.type_name()), loc)),
    };
    let mut e = RuntimeError::exit(code);
    e.location = Some(loc.clone());
    Err(Control::Error(e))
}

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

/// Los argumentos de una llamada, cada uno con su nombre si es nombrado. Un `Vec` (24 bytes, sin
/// memoria si no hay argumentos): con un `SmallVec` en línea las llamadas sin argumentos iban 5–8 %
/// más lentas (specs/compute-rendimiento.md F1.7, medido).
pub type CallArgs = Vec<(Option<String>, SynValue)>;

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
            Err(Control::Error(e)) if !e.is_fatal_for_labels() && !e.is_halt() => Ok(args[base].clone()),
            Err(other) => Err(other),
        }
    })
}

/// Un task built-in (implementado en Rust). `param_count` es informativo (Python
/// no lo fuerza en `_call_value`).
/// `print` escribe directo a stdout en vez de juntar en `output` (v0.6.29). Lo prende
/// sólo el camino normal de `synsema run`; todo lo demás (tests, serve, informes) junta.
pub static LIVE_STDOUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Modo REFERENCIA, sólo para tests: los intérpretes creados con él prendido no toman ningún
/// atajo de ejecución (hoy `try_update_in_place`) y corren el camino de referencia. Lo usa el
/// oráculo diferencial, que compara las dos corridas: un atajo tiene que dar exactamente lo mismo
/// (valor, salida, errores, `steps()`). No es un knob: ni variable de entorno ni flag del CLI.
static REFERENCE_MODE: AtomicBool = AtomicBool::new(false);

/// Prende o apaga el modo referencia para los intérpretes que se creen después (ver
/// `REFERENCE_MODE`).
#[doc(hidden)]
pub fn set_reference_mode(on: bool) {
    REFERENCE_MODE.store(on, std::sync::atomic::Ordering::SeqCst);
}

pub struct BuiltinTask {
    pub name: String,
    pub func: BuiltinFn,
    pub param_count: i32,
    /// Nombres de parámetros, OPT-IN (G-8): sólo los builtins que los declaran
    /// aceptan args nombrados (`recall(..., from = "writer")`), mapeados a
    /// posicionales acá mismo. Los demás conservan el error de siempre.
    pub param_names: Option<Vec<&'static str>>,
    /// Lo que cada llamada consulta del builtin, resuelto una vez al crearlo: antes se buscaba
    /// por nombre en tablas en cada llamada (specs/compute-rendimiento.md §3.4). Lo arma
    /// `BuiltinTask::new`, el único constructor.
    pub meta: BuiltinMeta,
    /// v0.6.49 (B9): si es el envoltorio de una task de un módulo de confianza, la task y su scope.
    /// Con eso `tool_spec` lee la firma y una llamada con argumentos nombrados (`call_tool`) entra
    /// al scope igual que una posicional. Antes las tasks de confianza eran sólo posicionales.
    pub trusted: Option<Rc<TrustedTool>>,
}

/// Ver `BuiltinTask::trusted`.
pub struct TrustedTool {
    pub module: String,
    pub label: String,
    pub task: Rc<SynTaskValue>,
    pub hook: TrustedScopeHook,
}

/// Ver `BuiltinTask::meta`. Las tablas (`BUILTIN_ARITY`, `BUILTIN_KWARGS`, `LINEAGE_SOURCES`)
/// siguen siendo la fuente de verdad; esto es su lectura para un builtin concreto.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinMeta {
    /// `(mínimo, máximo)` de argumentos (ver `builtin_arity`).
    pub arity: (usize, Option<usize>),
    /// Argumentos nombrados que acepta sin `param_names` (`BUILTIN_KWARGS`).
    pub kwargs: &'static [&'static str],
    /// Lo que devuelve entra al programa desde afuera y se anota en el linaje (`LINEAGE_SOURCES`).
    pub lineage_source: bool,
    /// Constructor de un tipo o de una variante (`Point(…)`, `Order.paid(…)`): cuenta sus campos él.
    pub constructor: bool,
}

impl BuiltinTask {
    pub fn new(
        name: impl Into<String>,
        param_count: i32,
        param_names: Option<Vec<&'static str>>,
        func: BuiltinFn,
    ) -> Self {
        let name = name.into();
        // La tabla `BUILTIN_ARITY` manda; si no está, un `param_count` fijo es exacto y -1 no se
        // valida acá (el builtin lo hace).
        let arity = match crate::builtin_arity::arity_of(&name) {
            Some(a) => a,
            None if param_count >= 0 => (param_count as usize, Some(param_count as usize)),
            None => (0, None),
        };
        let meta = BuiltinMeta {
            arity,
            kwargs: crate::builtin_arity::kwargs_of(&name),
            lineage_source: LINEAGE_SOURCES.contains(&name.as_str()),
            constructor: name.starts_with(|c: char| c.is_ascii_uppercase()),
        };
        BuiltinTask { name, func, param_count, param_names, meta, trusted: None }
    }
}

// La VM de bytecode (F3): un hijo de este módulo, para usar las mismas funciones que el
// tree-walker (operadores, errores, atajos) en vez de reescribirlas.
#[path = "vm.rs"]
mod vm;
pub use vm::TaskCode;
#[doc(hidden)]
pub use vm::{explain_after_run, explain_source};
#[cfg(feature = "vm-profile")]
pub use vm::profile as vm_profile;

// =========================================================
// entorno
// =========================================================

pub struct Environment {
    pub parent: Option<Rc<RefCell<Environment>>>,
    pub name: EnvName,
    pub bindings: Bindings,
}

impl Environment {
    pub fn root(name: &str) -> Rc<RefCell<Environment>> {
        Rc::new(RefCell::new(Environment {
            parent: None,
            name: EnvName::Owned(Rc::from(name)),
            bindings: Bindings::default(),
        }))
    }
    /// Un scope con identidad (`module:<ruta>`, un test, un template): el nombre se guarda.
    pub fn child(parent: &Rc<RefCell<Environment>>, name: &str) -> Rc<RefCell<Environment>> {
        Rc::new(RefCell::new(Environment {
            parent: Some(parent.clone()),
            name: EnvName::Owned(Rc::from(name)),
            bindings: Bindings::default(),
        }))
    }
    /// Un scope de ejecución que nadie identifica por nombre (una llamada, una vuelta de `each`,
    /// un brazo de `match`, un request): etiqueta fija, sin pedir memoria para el nombre.
    pub fn child_scope(parent: &Rc<RefCell<Environment>>, kind: &'static str) -> Rc<RefCell<Environment>> {
        Rc::new(RefCell::new(Environment {
            parent: Some(parent.clone()),
            name: EnvName::Static(kind),
            bindings: Bindings::default(),
        }))
    }
}

/// El nombre de un scope. Antes era un `String` armado con `format!` en cada llamada y en cada
/// vuelta de `each` (`"call:fib"`, `"each:i"`), que nadie leía (specs/compute-rendimiento.md
/// §3.3). Sólo los módulos se identifican por nombre: `module:<ruta>` es el id estable con el que
/// `serve` y `parallel_map` los reconstruyen en otro hilo.
#[derive(Clone, Debug)]
pub enum EnvName {
    /// Scopes de ejecución: una etiqueta fija (`"call"`, `"each"`, `"match-arm"`, …).
    Static(&'static str),
    /// Scopes con identidad: módulos, tests, templates, forks.
    Owned(Rc<str>),
}

impl EnvName {
    pub fn as_str(&self) -> &str {
        match self {
            EnvName::Static(s) => s,
            EnvName::Owned(s) => s,
        }
    }
}

impl std::ops::Deref for EnvName {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Las variables de un scope. Es un tipo propio y no un `HashMap` a la vista para que la
/// representación pueda cambiar sin tocar a quienes lo usan (specs/compute-rendimiento.md §6.0:
/// esta API es la definitiva; F2a cambió lo de adentro).
///
/// Formato de frame (F2a, el que F2b indexa y la VM de F3 usa como registros): dos arreglos en
/// paralelo, `names[k]` y `slots[k]`. Un binding **nunca cambia de índice**: `remove` deja el hueco
/// (`None`) con su nombre, y volver a ligar ese nombre reusa el mismo slot. Los primeros
/// `INLINE_BINDINGS` viven adentro del entorno (una llamada o una vuelta de `each` no piden memoria
/// para la tabla); la búsqueda es lineal, que en scopes chicos gana al hash. Pasados
/// `INDEX_AT` bindings (el global, un módulo) se arma un índice nombre → slot. El orden de
/// iteración es el de inserción (antes era el orden arbitrario del `HashMap`).
///
/// Los dos arreglos son `InlineVec` (propio, no `SmallVec`): la representación del frame no puede
/// cambiar según las features que otro crate del binario le prenda a una dependencia (ver
/// `inline_vec.rs`). Un nombre en línea es `Option` sólo para tener un lugar vacío: siempre es `Some`.
#[derive(Default)]
pub struct Bindings {
    names: InlineVec<Option<Arc<str>>, INLINE_BINDINGS>,
    slots: InlineVec<Option<SynValue>, INLINE_BINDINGS>,
    index: Option<Box<HashMap<Arc<str>, u32, rustc_hash::FxBuildHasher>>>,
    /// Si la VM preparó este frame (F3): el orden de sus nombres es el del resolver, y el slot `k`
    /// es la variable `k` de ese scope. Se pierde al vaciarlo.
    layout: Option<Rc<vm::Layout>>,
}

const INLINE_BINDINGS: usize = 8;
const INDEX_AT: usize = 16;

impl Bindings {
    #[inline]
    fn find(&self, name: &str) -> Option<usize> {
        match &self.index {
            Some(ix) => ix.get(name).map(|&k| k as usize),
            None => {
                let (inline, heap) = self.names.as_slices();
                let is = |n: &Option<Arc<str>>| matches!(n, Some(s) if **s == *name);
                match inline.iter().position(is) {
                    Some(k) => Some(k),
                    None => heap.iter().position(is).map(|k| inline.len() + k),
                }
            }
        }
    }
    #[inline]
    fn name_at(&self, k: usize) -> &Arc<str> {
        self.names[k].as_ref().expect("nombre del frame")
    }
    fn push(&mut self, name: Arc<str>, value: SynValue) {
        let k = self.names.len();
        if let Some(ix) = &mut self.index {
            ix.insert(name.clone(), k as u32);
        } else if k + 1 > INDEX_AT {
            let mut ix: HashMap<Arc<str>, u32, rustc_hash::FxBuildHasher> = HashMap::with_capacity_and_hasher(k * 2, Default::default());
            for (i, n) in self.names.iter().enumerate() {
                ix.insert(n.clone().expect("nombre del frame"), i as u32);
            }
            ix.insert(name.clone(), k as u32);
            self.index = Some(Box::new(ix));
        }
        self.names.push(Some(name));
        self.slots.push(Some(value));
    }
    pub fn get(&self, name: &str) -> Option<&SynValue> {
        self.find(name).and_then(|k| self.slots[k].as_ref())
    }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut SynValue> {
        self.find(name).and_then(|k| self.slots[k].as_mut())
    }
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    /// Agrega o reemplaza (devuelve el valor anterior). La clave sólo se convierte si es nueva.
    pub fn insert<K: AsRef<str> + Into<Arc<str>>>(&mut self, name: K, value: SynValue) -> Option<SynValue> {
        match self.find(name.as_ref()) {
            Some(k) => self.slots[k].replace(value),
            None => {
                self.push(name.into(), value);
                None
            }
        }
    }
    /// Liga `name`: si ya existe, reemplaza el valor en el lugar sin crear otra clave; si no, la
    /// agrega. Es lo que hace `let` (re-ligar en un bucle no pide memoria).
    pub fn set(&mut self, name: &str, value: SynValue) {
        match self.find(name) {
            Some(k) => self.slots[k] = Some(value),
            None => self.push(Arc::from(name), value),
        }
    }
    /// `set` con el nombre ya compartido (el del AST): si es nuevo, la clave es ese mismo `Arc`
    /// y ligar no pide memoria (F2a.2).
    pub fn set_shared(&mut self, name: &Arc<str>, value: SynValue) {
        match self.find(name) {
            Some(k) => self.slots[k] = Some(value),
            None => self.push(name.clone(), value),
        }
    }
    pub fn remove(&mut self, name: &str) -> Option<SynValue> {
        self.find(name).and_then(|k| self.slots[k].take())
    }
    pub fn clear(&mut self) {
        self.names.clear();
        self.slots.clear();
        self.index = None;
        self.layout = None;
    }
    /// Prepara un frame de llamada para la VM: los parámetros ya ligados tienen que ser los
    /// primeros nombres del layout, en su orden; el resto queda como hueco ("no está acá").
    /// `false` (y el frame sin tocar) si no coinciden.
    pub(crate) fn lay_out(&mut self, layout: &Rc<vm::Layout>, tag: bool) -> bool {
        let n = self.names.len();
        if n > layout.names.len() || self.names.iter().zip(layout.names.iter()).any(|(a, b)| a.as_deref() != Some(&**b)) {
            return false;
        }
        for name in &layout.names[n..] {
            self.push(name.clone(), SynValue::Nothing);
            let k = self.slots.len() - 1;
            self.slots[k] = None;
        }
        if tag {
            self.layout = Some(layout.clone());
        }
        true
    }
    /// F3.3b: agrega un nombre con su slot tal cual (un hueco si es `None`), en orden.
    pub(crate) fn push_slot(&mut self, name: Arc<str>, v: Option<SynValue>) {
        self.push(name, SynValue::Nothing);
        let k = self.slots.len() - 1;
        self.slots[k] = v;
    }
    /// F3.3b: saca el valor del slot `k` (queda un hueco).
    pub(crate) fn take_slot(&mut self, k: usize) -> Option<SynValue> {
        self.slots.get_mut(k).and_then(|s| s.take())
    }
    pub(crate) fn len_names(&self) -> usize {
        self.names.len()
    }
    #[inline]
    pub(crate) fn laid_out_as(&self, layout: &Rc<vm::Layout>) -> bool {
        self.layout.as_ref().is_some_and(|l| Rc::ptr_eq(l, layout))
    }
    #[inline]
    pub(crate) fn slot(&self, k: usize) -> Option<&SynValue> {
        self.slots[k].as_ref()
    }
    #[inline]
    pub(crate) fn slot_mut(&mut self, k: usize) -> Option<&mut SynValue> {
        self.slots[k].as_mut()
    }
    #[inline]
    pub(crate) fn slot_set(&mut self, k: usize, v: SynValue) {
        self.slots[k] = Some(v);
    }
    pub(crate) fn slot_name(&self, k: usize) -> Arc<str> {
        self.name_at(k).clone()
    }
    /// `get` con una caché del índice (el de la última vez; un índice nunca cambia): si en ese
    /// slot está este nombre, no se busca. Un hueco es "no está acá", como en `get`.
    #[inline]
    pub(crate) fn get_cached(&self, name: &Arc<str>, ic: &Cell<u32>) -> Option<&SynValue> {
        let k = self.cached_index(name, ic)?;
        self.slots[k].as_ref()
    }
    #[inline]
    pub(crate) fn get_cached_mut(&mut self, name: &Arc<str>, ic: &Cell<u32>) -> Option<&mut SynValue> {
        let k = self.cached_index(name, ic)?;
        self.slots[k].as_mut()
    }
    #[inline]
    fn cached_index(&self, name: &Arc<str>, ic: &Cell<u32>) -> Option<usize> {
        let c = ic.get() as usize;
        if c > 0 {
            if let Some(Some(n)) = self.names.get(c - 1) {
                if Arc::ptr_eq(n, name) || **n == **name {
                    return Some(c - 1);
                }
            }
        }
        let k = self.find(name)?;
        ic.set(k as u32 + 1);
        Some(k)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &SynValue)> {
        self.names.iter().zip(self.slots.iter()).filter_map(|(n, v)| Some((n.as_ref()?, v.as_ref()?)))
    }
    pub fn keys(&self) -> impl Iterator<Item = &Arc<str>> {
        self.iter().map(|(n, _)| n)
    }
    pub fn values(&self) -> impl Iterator<Item = &SynValue> {
        self.slots.iter().flatten()
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
/// reutiliza mientras esté registrada). Las DOS tablas guardan los dos `Weak`: una clave es una
/// dirección, y sólo es de ese objeto mientras su `Weak` la reserve. Hasta R2.5 `by_env` guardaba
/// sólo el mapa: muerto el entorno, su dirección quedaba libre y un entorno nuevo en la misma
/// dirección heredaba el mapa ajeno (un worker de `serve` escribía las exportaciones en el mapa de
/// otro módulo; con el mapa congelado, era un pánico).
#[derive(Default)]
struct ModuleRegistry {
    by_map: HashMap<usize, (synsema_heap::WeakTail<MapObj>, std::rc::Weak<RefCell<Environment>>)>,
    by_env: HashMap<usize, (synsema_heap::WeakTail<MapObj>, std::rc::Weak<RefCell<Environment>>)>,
    prune_at: usize,
}

thread_local! {
    static MODULES: RefCell<ModuleRegistry> = RefCell::new(ModuleRegistry::default());
}

/// Registra el mapa de exportaciones `map` como la vista de `env` (lo llaman `load_module`
/// y la reconstrucción de módulos de un worker de `serve`/`parallel_map`).
pub fn register_module(map: &crate::types::MapRef, env: &Rc<RefCell<Environment>>) {
    MODULES.with(|r| {
        let mut r = r.borrow_mut();
        if r.by_map.len() >= r.prune_at.max(64) {
            r.by_map.retain(|_, (m, e)| m.strong_count() > 0 && e.strong_count() > 0);
            r.by_env.retain(|_, (m, e)| m.strong_count() > 0 && e.strong_count() > 0);
            r.prune_at = r.by_map.len() * 2;
        }
        r.by_map.insert(crate::types::MapRef::as_ptr(map).cast::<()>() as usize, (crate::types::MapRef::downgrade(map), Rc::downgrade(env)));
        r.by_env.insert(Rc::as_ptr(env) as usize, (crate::types::MapRef::downgrade(map), Rc::downgrade(env)));
    });
}

/// El entorno del módulo cuyo mapa de exportaciones es `map`, si lo es.
pub fn module_env_of_map(map: &crate::types::MapRef) -> Option<Rc<RefCell<Environment>>> {
    MODULES.with(|r| {
        let r = r.borrow();
        if r.by_map.is_empty() {
            return None;
        }
        let (m, e) = r.by_map.get(&(crate::types::MapRef::as_ptr(map).cast::<()>() as usize))?;
        m.upgrade()?;
        e.upgrade()
    })
}

/// El mapa de exportaciones del módulo cuyo entorno es `env`, si lo es.
pub fn module_map_of_env(env: &Rc<RefCell<Environment>>) -> Option<crate::types::MapRef> {
    MODULES.with(|r| {
        let r = r.borrow();
        let (m, e) = r.by_env.get(&(Rc::as_ptr(env) as usize))?;
        // La entrada es de `env` sólo si su entorno sigue vivo (si no, es de uno muerto que ocupaba
        // esta dirección; su `Weak` la reservaba, así que acá no puede pasar, pero no se asume).
        e.upgrade().filter(|x| Rc::ptr_eq(x, env))?;
        m.upgrade()
    })
}

/// `set m.X to v` / `set m["X"] to v` sobre un módulo: religa SU variable (la que leen sus
/// tasks), como `m.X = v` en Python; sus nombres son sus exportaciones y sus tasks no se
/// reemplazan desde afuera.
fn module_rebind(
    m: &crate::types::MapRef,
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
        // Ronda 1 (A2): se mira también el binding del módulo; una exportación envuelta (o
        // cualquier otra envoltura) no dice que detrás hay una task.
        Some(v) if matches!(v, SynValue::Task(_)) || matches!(menv.borrow().bindings.get(name), Some(SynValue::Task(_))) => {
            Err(err_at(format!("cannot replace the module task '{}' from outside the module", name), loc))
        }
        Some(_) => {
            let _ = env_update(menv, name, value.clone());
            Ok(value)
        }
    }
}

thread_local! {
    /// v0.6.49 (B8): las vistas de los módulos de confianza (la copia de sus exportaciones que
    /// recibe cada `use "trusted:…"`), por dirección; el `Weak` reserva la dirección, como en
    /// `ModuleRegistry`. Un mapa de datos, pero con los nombres de un módulo.
    ///
    /// Ronda 1 (B1): la regla vale en el hilo donde se cargó el módulo. La vista que cruza a un
    /// worker (`parallel_map`, `spawn`) es otro mapa en otro hilo y no está registrada: ahí
    /// `set t.NEW to 5` agrega el nombre a esa copia. No hay nada que proteger: en el worker las
    /// tasks de confianza llegan como texto (no se pueden llamar), y la copia muere con el worker.
    static TRUSTED_VIEWS: RefCell<(HashMap<usize, synsema_heap::WeakTail<MapObj>>, usize)> = RefCell::new((HashMap::new(), 0));
}

/// ¿Alguna vista registrada en el proceso? `set` sobre un mapa es camino caliente: sin módulos de
/// confianza no se toca el thread-local.
static ANY_TRUSTED_VIEW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn register_trusted_view(map: &crate::types::MapRef) {
    ANY_TRUSTED_VIEW.store(true, std::sync::atomic::Ordering::Relaxed);
    TRUSTED_VIEWS.with(|r| {
        let (views, prune_at) = &mut *r.borrow_mut();
        if views.len() >= (*prune_at).max(64) {
            views.retain(|_, m| m.strong_count() > 0);
            *prune_at = views.len() * 2;
        }
        views.insert(crate::types::MapRef::as_ptr(map).cast::<()>() as usize, crate::types::MapRef::downgrade(map));
    });
}

/// v0.6.50 (B): la vista de una tool reconstruida en otro intérprete (un worker, un agente) se
/// registra como la original: `set t.X` sigue siendo error.
pub fn register_rebuilt_trusted_view(map: &crate::types::MapRef) {
    register_trusted_view(map);
}

/// v0.6.50 (B): ¿es `map` la vista de una tool de confianza (en este hilo)?
pub fn is_trusted_view_map(map: &crate::types::MapRef) -> bool {
    is_trusted_view(map)
}

/// v0.6.50 (B): envuelve una task de confianza reconstruida en otro intérprete con el hook de ese
/// intérprete, como `load_trusted_module` (el que la recibe la marca con `mark_label_aware`).
pub fn wrap_trusted_task(module: &str, export: &str, task: Rc<SynTaskValue>, hook: TrustedScopeHook) -> SynValue {
    trusted_wrapper(module, export, task, hook)
}

/// v0.6.50 (B): las piezas de una task de confianza envuelta, para llevarla a otro intérprete:
/// (módulo, nombre exportado, la task de la tool).
pub fn trusted_tool_parts(b: &BuiltinTask) -> Option<(&str, &str, &Rc<SynTaskValue>)> {
    let t = b.trusted.as_ref()?;
    let export = t.label.strip_prefix("trusted:")?.strip_prefix(t.module.as_str())?.strip_prefix('.')?;
    Some((t.module.as_str(), export, &t.task))
}

#[inline]
fn is_trusted_view(map: &crate::types::MapRef) -> bool {
    ANY_TRUSTED_VIEW.load(std::sync::atomic::Ordering::Relaxed) && is_trusted_view_slow(map)
}

#[cold]
#[inline(never)]
fn is_trusted_view_slow(map: &crate::types::MapRef) -> bool {
    TRUSTED_VIEWS.with(|r| {
        let r = r.borrow();
        !r.0.is_empty() && r.0.get(&(crate::types::MapRef::as_ptr(map).cast::<()>() as usize)).is_some_and(|m| m.upgrade().is_some())
    })
}

/// `set t.X to v` sobre la vista de un módulo de confianza: las reglas de un módulo de archivo
/// (sus nombres son sus exportaciones, sus tasks no se reemplazan desde afuera); lo demás cambia
/// sólo esta copia, que la tool no ve. Antes `set t.NEW` agregaba un nombre y `set t.task` tapaba
/// la task.
fn trusted_view_set(m: &crate::types::MapRef, name: &str, loc: &SourceLocation) -> Result<(), Control> {
    match m.borrow().get(name) {
        None => Err(err_at(
            format!("trusted module has no export '{}' — its names are the ones it exports, and the program cannot add one", name),
            loc,
        )),
        Some(SynValue::Task(_)) | Some(SynValue::Builtin(_)) => {
            Err(err_at(format!("cannot replace the trusted task '{}' from outside the module", name), loc))
        }
        Some(_) => Ok(()),
    }
}

/// La hoja de `set <camino>.campo to v` (sin etiquetas: ya se resolvieron), con el contenedor ya
/// evaluado: lo mismo para el tree-walker y para la VM (F4.6a). Devuelve el valor escrito.
pub(crate) fn set_leaf_prop(obj: &SynValue, property_name: &str, value: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
    match obj {
        SynValue::Map(m) => {
            // `set m.X to v` sobre un módulo religa SU variable (la que leen sus tasks), como
            // `m.X = v` en Python; sus nombres son sus exportaciones y sus tasks no se reemplazan
            // desde afuera.
            if let Some(menv) = module_env_of_map(m) {
                return module_rebind(m, &menv, property_name, value, loc);
            }
            if is_trusted_view(m) {
                trusted_view_set(m, property_name, loc)?;
            }
            m.borrow_mut().set(property_name, value.clone());
            Ok(value)
        }
        _ => Err(err_at(format!("Cannot set property on {}", obj.type_name()), loc)),
    }
}

/// La hoja de `set <camino>[idx] to v` (ver `set_leaf_prop`). `target_loc`: la del destino (el
/// error de fuera de rango, como la lectura `xs[i]`); `loc`: la de la sentencia.
pub(crate) fn set_leaf_index(
    obj: &SynValue,
    idx: &SynValue,
    value: SynValue,
    target_loc: &SourceLocation,
    loc: &SourceLocation,
) -> Result<SynValue, Control> {
    match obj {
        SynValue::List(l) => {
            let mut b = list_values_mut(&l);
            let len = b.len() as i64;
            let given = num_to_i64(idx)?;
            let mut i = given;
            if i < 0 {
                i += len;
            }
            // El mismo mensaje y lugar que la lectura `xs[i]`.
            if i < 0 || i >= len {
                return Err(err_at(
                    format!("Index {} out of bounds (list length {}) — to add an item: set xs to append(xs, x)", given, len),
                    target_loc,
                ));
            }
            b[i as usize] = value.clone();
            Ok(value)
        }
        SynValue::Map(m) => {
            // `set lib["X"] to v`: las mismas reglas que `set lib.X to v`.
            if let Some(menv) = module_env_of_map(m) {
                return module_rebind(m, &menv, &idx.to_string(), value, loc);
            }
            if is_trusted_view(m) {
                trusted_view_set(m, &idx.to_string(), loc)?;
            }
            m.borrow_mut().set_value_key(idx, value.clone());
            Ok(value)
        }
        _ => Err(err_at(format!("Cannot set index on {}", obj.type_name()), loc)),
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
        Control::Error(e) => e.into_message(),
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
        (SynValue::List(x), SynValue::List(y)) => crate::types::ListRef::ptr_eq(x, y),
        (SynValue::Map(x), SynValue::Map(y)) => crate::types::MapRef::ptr_eq(x, y),
        (SynValue::Private(x), SynValue::Private(y)) => crate::types::Obj::ptr_eq(x, y),
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
    env.borrow_mut().bindings.set(name, value);
}

/// `env_set` con el nombre del AST: no copia el nombre si el binding es nuevo.
fn env_set_shared(env: &Rc<RefCell<Environment>>, name: &Arc<str>, value: SynValue) {
    env.borrow_mut().bindings.set_shared(name, value);
}

/// Actualiza una variable existente en cualquier scope. `Err(())` si no existe. Una búsqueda por
/// scope y la asignación en el lugar: sin crear la clave otra vez ni hashear dos veces.
fn env_update(env: &Rc<RefCell<Environment>>, name: &str, value: SynValue) -> Result<(), ()> {
    let mut cur = env.clone();
    loop {
        let next = {
            let mut e = cur.borrow_mut();
            let Environment { parent, name: env_name, bindings } = &mut *e;
            if let Some(slot) = bindings.get_mut(name) {
                // Una exportación religada dentro del módulo: el mapa `use … as m` la sigue. (Sólo
                // se mira en el scope donde está la variable.)
                if env_name.starts_with("module:") {
                    if let Some(m) = module_map_of_env(&cur) {
                        if m.borrow().contains_key(name) {
                            m.borrow_mut().insert(name.to_string(), value.clone());
                        }
                    }
                }
                *slot = value;
                return Ok(());
            }
            parent.clone()
        };
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
const CORE_LABEL_AWARE: &[&str] = &["private", "declassify", "label_of", "is_private", "print", "eprint"];

/// Nombres PROTEGIDOS (B8): definir una task, variable, parámetro o alias con uno de
/// estos nombres es error de carga SIEMPRE (con etiquetas apagadas también): sombrear el
/// builtin anularía el etiquetado de las fuentes y engañaría al listado del auditor.
pub const PROTECTED_BUILTIN_NAMES: &[&str] = CORE_LABEL_AWARE;

/// SUMIDEROS del core (B7): builtins del core con efecto fuera del intérprete. Los
/// `llm_*` mandan el prompt al proveedor. Los demás sumideros (fs/http/sql/ws/memory/env/
/// exec/blackboard/webpush/run/proc) viven en el stdlib/agents y los registra el host con
/// `register_label_sink`. Las SENTENCIAS con efecto (`share`/`signal`/`send`/`spawn`/
/// `approve`/`confirm`/`ask`/`reason`/`decide`/`analyze`/`generate`) se comprueban en `exec`.
/// v0.6.42 — `exit`: el código de salida es un canal público (8 bits) y la llamada misma también;
/// bajo una rama privada o con un código privado, `label_violation` antes de salir.
pub const CORE_SINK_BUILTINS: &[&str] = &["exit"];

/// v0.6.46 (E5) — `llm_step` y `llm_stream` dejan de ser sumideros: un sumidero vuelve antes de
/// la unión de etiquetas y su respuesta no salía etiquetada nunca. Reciben los argumentos
/// envueltos y hacen su propio chequeo (el PC, el techo `llm=P@<provider>` y la capability), y lo
/// que devuelven (el mapa de `llm_step` entero, cada fragmento de `llm_stream`) lleva la etiqueta
/// de lo que se les dio. No son nombres protegidos: un programa puede seguir llamando así a una
/// task suya.
pub const CORE_LLM_LABEL_AWARE: &[&str] = &["llm_step", "llm_stream"];

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

/// v0.6.46 (E3) — el gate de `declassify` del host: recibe los principales que la llamada quita
/// (`from \ to`) y el conjunto DECLARADO (lo que nombran el mensaje y el audit, nunca la etiqueta
/// real), y dice si la capability `declassify` los cubre a todos.
pub type DeclassifyCapHook = Rc<dyn Fn(&[Rc<str>], &str) -> bool>;

/// v0.6.46 (E3b) — el scope de un módulo de confianza: `Some((módulo, requires))` al entrar (al
/// correr su cuerpo, o una task exportada con sus `require`), `None` al salir. El host cambia el
/// `CapabilitySet` por lo declarado ∩ el techo de confianza, sin nada del llamador, y lo restaura.
pub type TrustedScopeHook = Rc<dyn Fn(Option<(&str, &[(String, Option<String>)])>)>;

/// v0.6.46 (E5) — el permiso de mandarle datos privados a un modelo: `(op, principales, conjunto
/// declarado, judge)` → ¿lo permite el host? El host mira el provider de esta llamada (`judge` = el
/// del juez) y exige, por cada principal P, un techo con `llm=P@<host del provider>` (`judge=` para
/// el juez) y el `require llm("P")` del programa. El audit nombra el conjunto DECLARADO, como el de
/// `declassify` (el real variaría con el valor elegido). Sin hook, nada privado llega al modelo.
pub type LlmDataHook = Rc<dyn Fn(&str, &[Rc<str>], &str, bool) -> bool>;

/// v0.6.46 (E8) — abre un template del disco ya gateado (`raw`, como se escribió) sin ventana entre
/// el gate y la apertura. Abre lo que juzgó el gate (la ruta normalizada de `raw`), NO la ruta ya
/// resuelta con `canonicalize`: ésa se resolvió después del gate y nadie la juzgó (ronda 1, E8-A3).
/// Lo cablea el motor (que tiene con qué abrir sin seguir links); sin él, el template se lee por
/// nombre, como v0.6.45.
pub type TemplateOpenHook = Rc<dyn Fn(&str) -> Result<std::fs::File, RuntimeError>>;

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
    /// v0.6.46 (F1): el tipo de cada parámetro (`"nombre: tipo"` en el catálogo), en el orden de
    /// `params`; `None` = sin tipo (llega como texto, como antes).
    pub types: Vec<Option<crate::ast::ParamType>>,
    /// v0.6.46 (F1): los nombres de `optional` (fuera de `required` en el esquema).
    pub optional: Vec<String>,
}

/// Resultado que el callback de paso devuelve al builtin `llm_step`.
pub enum StepResult {
    Final { text: String, tokens: u64 },
    /// v0.6.46 (F1): los argumentos como valores. El motor decodifica los de un parámetro tipado
    /// del catálogo; los demás llegan como texto, como antes.
    Tool { name: String, args: Vec<(String, SynValue)>, tokens: u64 },
}

/// Callback de paso del LLM: `(prompt, catalog, context) -> StepResult`. Lo cablea el
/// motor con el provider tool-aware; sin él, `llm_step` devuelve un placeholder.
pub type LlmStepCallback =
    Rc<dyn Fn(&str, &[StepCatalogEntry], &str) -> StepResult>;

/// Callback de texto (reason/decide/analyze/generate): `(op, prompt) -> contenido`. El
/// motor lo cablea con el provider real; sin él, las ops LLM caen a placeholders.
///
/// v0.6.46 (E5): recibe también los principales de lo privado que lleva el prompt (vacío con
/// datos públicos), para el host que lo quiera decidir o auditar, y `Err(texto)` es un error de
/// ESA llamada (un hook de wasm que lanzó), no una respuesta vacía.
pub type LlmTextCallback = Rc<dyn Fn(&str, &str, &[Rc<str>]) -> Result<String, String>>;

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
    dyn Fn(&str, std::sync::Arc<[Node]>, Vec<(String, SynValue)>, Vec<(String, SynValue)>, SpawnSubject) -> Result<String, Control>,
>;

/// T1 (identidad): lo que el intérprete sabe del SUJETO de la unidad de trabajo en curso y
/// que el agente spawneado hereda — la identidad autenticada y su techo de gasto delegado.
/// (El techo delegado de capabilities y el presupuesto LLM viven fuera de core: el motor
/// los captura del CapabilitySet y del hilo al recibir esto.)
#[derive(Clone, Debug, Default)]
pub struct SpawnSubject {
    pub identity: Option<String>,
    pub spend_limits: Vec<(String, String)>,
    /// v0.6.47 (T1, A1): el corte de la corrida que lanza al agente; el agente lo comparte.
    pub run_cut: Option<std::sync::Arc<RunCut>>,
    /// v0.6.47 (T1, N3): los principales declarados del que lo lanza, para que el texto fijo de un
    /// corte del agente sea el mismo que el de la corrida.
    pub principals: Vec<String>,
}

/// La única línea de salida de una corrida cortada por el chequeo de flujo (ver
/// `redact_output_for_host`); el motor la usa también cuando el corte es de un agente.
pub const LABELS_WITHHELD_OUTPUT: &str = "private(labels): the run was stopped by the flow checker; its output is withheld because the NUMBER of lines before the stop depends on private data";

/// v0.6.47 (T1, A1) — **el corte de etiquetas de una corrida, compartido con sus agentes.** Un
/// agente corre en su propio hilo; si un corte suyo quedara contenido (DE-011), su estado
/// `error`/`done` sería un bit por agente que el principal lee con `agents()` y sigue corriendo
/// (diez agentes, uno por dígito, deletreaban una tarjeta en una corrida). El agente que se corta
/// anota acá `(texto, detalle)` antes de que su estado cambie, y desde ese momento todo sumidero de
/// la corrida y el embudo del host dan ese corte: la corrida entera termina como un corte, como en
/// wasm (donde `spawn` corre en línea) y como en el runner de tests.
#[derive(Debug, Default)]
pub struct RunCut(std::sync::OnceLock<(String, String)>);

impl RunCut {
    /// Anota el corte; el primero gana.
    pub fn set(&self, message: String, detail: String) {
        let _ = self.0.set((message, detail));
    }
    /// `(texto hacia el programa, detalle para el operador)`, si hubo corte.
    pub fn get(&self) -> Option<&(String, String)> {
        self.0.get()
    }
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
    /// El cuerpo de cada agente, compartido con el AST (R2.5).
    pub agent_definitions: HashMap<String, (std::sync::Arc<[Node]>, Rc<RefCell<Environment>>)>,
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
    /// Los entornos de módulo que el host reconstruyó para este intérprete (`parallel_map`, un
    /// agente, un worker de `serve`: `adopt_module_envs`). Son suyos: el `Drop` los vacía.
    owned_module_envs: Vec<Rc<RefCell<Environment>>>,
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
    /// ¿Se pueden tomar atajos de ejecución? `false` en modo referencia (ver `REFERENCE_MODE`).
    shortcuts: bool,
    /// Frames reciclados (F2a.3 de specs/compute-rendimiento.md): el entorno de una llamada o de
    /// una vuelta de `each` que nadie capturó vuelve acá vacío y con su capacidad, y la próxima
    /// llamada lo reusa en vez de pedir memoria. Ver `acquire_frame` / `release_frame`.
    free_frames: Vec<Rc<RefCell<Environment>>>,
    /// Los `Vec` de argumentos de las llamadas, por la misma razón (F2a.3): vacíos, con su capacidad.
    free_args: Vec<CallArgs>,
    /// Los registros de la VM (F3): cada chunk en ejecución usa una ventana al final.
    vm_regs: Vec<SynValue>,
    /// Las llamadas en curso dentro de la VM (F3.2): el estado del llamador de cada una.
    vm_frames: Vec<vm::VmFrame>,
    /// Los iteradores de los `each` compilados en curso (F3.2).
    vm_iters: Vec<EachItems>,
    /// Las variables de los cuerpos con frame en registros (F3.3b) y dónde empieza la del que
    /// corre ahora.
    vm_locals: Vec<Option<SynValue>>,
    vm_lbase: usize,
    /// El chunk del último programa que corrió la VM (para `explain_after_run`: su código queda
    /// como lo dejó el quickening).
    vm_last_program: Option<Rc<vm::Chunk>>,
    /// Los cuerpos de las rutas de `serve` ya compilados por la VM, en este intérprete (uno por
    /// worker): cada request de una ruta corre el mismo chunk, así que lo especializado y lo
    /// nativo de una request sirve para las siguientes. Clave: dirección y largo del cuerpo; el
    /// valor guarda una copia del cuerpo y sólo se reusa si es igual (ver `vm::request_chunk`).
    vm_request_chunks: HashMap<(usize, usize), (Vec<Node>, Rc<vm::Chunk>)>,
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
    pending_kwargs: SynMap,
    /// Linaje (v0.6.29, DATOS-17): cada dato que el programa LEYÓ, anotado por el motor.
    lineage: Vec<LineageEntry>,
    /// Bytes canónicos de un valor estructurado para el linaje (el stdlib instala
    /// `canonical_json`, RFC 8785): así cualquiera recalcula el hash de un resultado de SQL.
    pub lineage_canonical: Option<Rc<dyn Fn(&SynValue) -> Option<(Vec<u8>, &'static str)>>>,
    /// v0.6.42 (al final del struct a propósito: no corre los offsets de los campos calientes)
    /// — líneas de `eprint`/`log` retenidas para stderr. Sólo se usa con etiquetas
    /// encendidas (el mismo motivo que `output`: si la corrida muere por un flujo privado,
    /// cuántas líneas salieron depende del dato); sin etiquetas van a stderr al momento.
    /// Se sueltan (o se retienen) en `redact_for_host`, el embudo de cada entrada del host.
    err_output: Vec<String>,
    /// v0.6.42 — el `log_hook` sólo observa (el de `run --labels`, que saca los `declassify` a
    /// stderr) y no es un destino de la salida como el de un agente o el de serve: `log` lo trata
    /// como si no hubiera hook y, bajo `synsema run`, va a stderr.
    pub log_hook_observes_only: bool,
    /// v0.6.46 (E4) — la marca de un solo uso de una llamada a `declassify`/`private` POR SU NOMBRE
    /// (el callee literal, ya chequeado por `check_protected_callee`). La arma el `TaskCall` (y el
    /// pipe) con las etiquetas encendidas, después de evaluar los argumentos, justo antes de
    /// despachar; `b_private`/`b_declassify` la consumen. Sin ella (un alias, un contenedor, un
    /// parámetro, un valor devuelto) no corren: así todo sitio que declasifica es una llamada
    /// literal y el inventario de `code check --json` es completo. Al final del struct a propósito.
    label_call_armed: bool,
    /// v0.6.46 (E3) — el gate de `declassify` (ver [`DeclassifyCapHook`]). Sólo se llama con las
    /// etiquetas encendidas. Sin él (un host que no cablea capabilities), sin gate. Al final del
    /// struct a propósito, como `label_call_armed`.
    declassify_cap_hook: Option<DeclassifyCapHook>,
    /// v0.6.46 (E3b) — los módulos de confianza que cargó el HOST (`--trusted nombre=ruta`, o
    /// `trusted` en wasm): nombre → fuente. El programa los importa con `use "trusted:nombre"`;
    /// no ve la ruta ni puede escribirlos.
    trusted_sources: HashMap<String, Rc<str>>,
    /// v0.6.46 (E3b) — ver [`TrustedScopeHook`]. Sin él, `use "trusted:…"` es error.
    trusted_scope_hook: Option<TrustedScopeHook>,
    /// v0.6.46 (E5) — ver [`LlmDataHook`]. Al final del struct a propósito (no es camino caliente).
    llm_data_hook: Option<LlmDataHook>,
    /// v0.6.46 (ronda 1, A1) — el padre del entorno de un módulo de confianza: los builtins y lo que
    /// puso el host, tomados antes de que corra el programa. Colgado de `global_env`, la tool
    /// buscaba `upper` o `length` en los globales del programa y corría lo que éste definiera.
    trusted_base_env: Option<Rc<RefCell<Environment>>>,
    /// v0.6.46 (ronda 1, A1) — cuántos scopes de confianza hay abiertos (el cuerpo de un módulo de
    /// confianza o una tool en curso). Adentro, lo que correría en otro intérprete con los globales
    /// del programa (`spawn`, `parallel_map`, `cron_every`, un módulo de archivo) es error.
    trusted_depth: u32,
    /// v0.6.46 (E8) — ver [`TemplateOpenHook`].
    template_open_hook: Option<TemplateOpenHook>,
    /// v0.6.46 (C3) — lo que la corrida escribió (archivos), en orden: el reverso de `lineage`. Lo
    /// anota el builtin que escribe, con los bytes que escribió (`record_output`), no el despacho.
    outputs: Vec<LineageEntry>,
    /// v0.6.46 (ronda 1 de cf1, N1): si se descartó alguna entrada de `lineage` / de `outputs` por
    /// el tope `MAX_LINEAGE`. El recibo lo marca así, no por el largo: con exactamente el tope no se
    /// perdió nada.
    lineage_dropped: [bool; 2],
    /// v0.6.47 (T1) — el diagnóstico de un corte de etiquetas sale entero HACIA EL PROGRAMA (el
    /// texto de hoy, con sitio, remedio y ubicación). Apagado por defecto: el programa recibe un
    /// texto fijo y el detalle va al operador. Lo enciende sólo el CLI sin techo, donde quien corre
    /// el binario escribió el programa y es el dueño del dato. Al final del struct a propósito.
    labels_detail_to_program: bool,
    /// v0.6.47 (T1, A1): el corte compartido con los agentes de la corrida (ver `RunCut`).
    run_cut: std::sync::Arc<RunCut>,
    /// v0.6.47 (T1): adónde va el stderr retenido al terminar sin corte (`None` = al stderr del
    /// proceso). Con agentes y etiquetas, al swarm: sale al cierre de la corrida, no cuando
    /// termina cada intérprete (cuándo terminó cada uno lo elegía el dato).
    pub err_hook: Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
    /// v0.6.50 (A): el padre del entorno de un módulo de archivo, la foto del preludio (ver
    /// `snapshot_module_base`). Colgado de `global_env`, un módulo leía y escribía los globales de
    /// quien lo importaba. Al final del struct a propósito (no es camino caliente).
    module_base_env: Option<Rc<RefCell<Environment>>>,
    /// v0.6.50 (D): los templates que el host le dio a cada tool de confianza
    /// (`--trusted-templates`). Dentro del scope de una tool, `render` resuelve sólo contra éstos.
    trusted_templates: HashMap<String, Rc<crate::templates::ToolTemplates>>,
    /// v0.6.50 (D): las tools en cuyo scope corre el código (la última es la actual), junto a
    /// `trusted_depth`.
    trusted_stack: Vec<String>,
    /// v0.6.50 (ronda 1, M1): ya corrió un `execute`. Lo que haya en `global_env` desde entonces lo
    /// ligó el programa, no es preludio: una foto tomada después son los builtins.
    executed: bool,
}

/// v0.6.46 (ronda 1 de cf1, B2): el linaje que juntó un intérprete hijo (un worker de
/// `parallel_map`), para sumarlo al del padre con [`Interpreter::absorb_lineage`].
#[derive(Default)]
pub struct LineageTaken {
    inputs: Vec<LineageEntry>,
    outputs: Vec<LineageEntry>,
    dropped: [bool; 2],
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
        // El mismo ciclo en cada entorno de módulo: sus tasks cierran sobre él y él las tiene en
        // sus bindings. Los que cargó `use` (en `module_cache`) y los que el host reconstruyó desde
        // una foto (`adopt_module_envs`): sin esto, cada item de `parallel_map` y cada agente
        // dejaban vivo el programa entero (lampson: ~26 MB por llamada, v0.6.38).
        let mut envs: Vec<Rc<RefCell<Environment>>> = self
            .module_cache
            .values()
            .filter_map(|v| match v {
                SynValue::Map(m) => module_env_of_map(m),
                _ => None,
            })
            .collect();
        envs.append(&mut self.owned_module_envs);
        for env in envs {
            if let Ok(mut e) = env.try_borrow_mut() {
                e.bindings.clear();
            }
        }
    }
}

/// Un argumento nombrado de un builtin sin `param_names`: a `kw` si el builtin lo acepta; si no, el
/// error de siempre. Fuera de línea (F4.4): es el camino raro de `call_value_named_inner`.
#[cold]
#[inline(never)]
fn builtin_named_arg(bt: &BuiltinTask, kw: &mut SynMap, n: String, v: SynValue, loc: &SourceLocation) -> Result<(), Control> {
    let allowed = bt.meta.kwargs;
    if allowed.contains(&n.as_str()) {
        if kw.contains_key(&n) {
            return Err(err_at(format!("duplicate argument '{}'", n), loc));
        }
        kw.insert(n, v);
        return Ok(());
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
    Err(err_at(
        format!("{}() does not accept named arguments (got {} = …); pass it by position", bt.name, n),
        loc,
    ))
}

impl Interpreter {
    /// Un scope de ejecución (`"call"`, `"each"`) hijo de `parent`: un frame reciclado si hay,
    /// o uno nuevo. Sólo con atajos: en modo referencia cada scope es un `Rc` nuevo, y el oráculo
    /// compara los dos caminos.
    #[inline]
    fn acquire_frame(&mut self, parent: &Rc<RefCell<Environment>>, kind: &'static str) -> Rc<RefCell<Environment>> {
        if let Some(frame) = self.free_frames.pop() {
            {
                let mut e = frame.borrow_mut();
                e.parent = Some(parent.clone());
                e.name = EnvName::Static(kind);
            }
            return frame;
        }
        Environment::child_scope(parent, kind)
    }

    /// Fin de una llamada o de una vuelta de `each`. Si nadie más tiene el frame (ni una closure
    /// que lo capturó, ni un agente, ni un `Weak` de nadie), se vacía AHORA —los valores se
    /// sueltan en el mismo momento en que se soltaban al destruir el `Rc`, primero el padre y
    /// después las variables, como el orden de los campos— y queda para la próxima. Si alguien
    /// lo retiene, se suelta como siempre: la closure sigue viendo sus variables.
    #[inline]
    fn release_frame(&mut self, frame: Rc<RefCell<Environment>>) {
        if !self.shortcuts
            || Rc::strong_count(&frame) != 1
            || Rc::weak_count(&frame) != 0
            || self.free_frames.len() >= MAX_FREE_FRAMES
        {
            return;
        }
        {
            let mut e = frame.borrow_mut();
            drop(e.parent.take());
            e.bindings.clear();
        }
        self.free_frames.push(frame);
    }
}

impl Interpreter {
    /// Fin de una llamada: el `Vec` de argumentos se vacía (lo que quede se suelta ahora, como
    /// al salir de su scope) y vuelve a la pila. Sólo con atajos, como los frames.
    #[inline]
    fn release_args(&mut self, mut args: CallArgs) {
        if self.shortcuts && self.free_args.len() < MAX_FREE_FRAMES {
            args.clear();
            self.free_args.push(args);
        }
    }
}

/// Tope de la pila de frames libres: la profundidad de llamadas vivas que se recicla sin pedir
/// memoria. Más allá, el frame se suelta como siempre.
const MAX_FREE_FRAMES: usize = 256;

impl Interpreter {
    pub fn new() -> Self {
        let interp = Interpreter {
            global_env: Environment::root("global"),
            output: Vec::new(),
            err_output: Vec::new(),
            log_hook_observes_only: false,
            label_call_armed: false,
            declassify_cap_hook: None,
            trusted_sources: HashMap::new(),
            trusted_scope_hook: None,
            llm_data_hook: None,
            trusted_base_env: None,
            trusted_depth: 0,
            template_open_hook: None,
            outputs: Vec::new(),
            lineage_dropped: [false; 2],
            labels_detail_to_program: false,
            run_cut: std::sync::Arc::new(RunCut::default()),
            err_hook: None,
            module_base_env: None,
            trusted_templates: HashMap::new(),
            trusted_stack: Vec::new(),
            executed: false,
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
            owned_module_envs: Vec::new(),
            loading_modules: HashSet::new(),
            exports_collector: vec![Vec::new()],
            live_output: false,
            program_args: Vec::new(),
            steps: 0,
            shortcuts: !REFERENCE_MODE.load(std::sync::atomic::Ordering::SeqCst),
            free_frames: Vec::new(),
            free_args: Vec::new(),
            vm_regs: Vec::new(),
            vm_frames: Vec::new(),
            vm_iters: Vec::new(),
            vm_locals: Vec::new(),
            vm_lbase: 0,
            vm_last_program: None,
            vm_request_chunks: HashMap::new(),
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
            label_aware: CORE_LABEL_AWARE.iter().chain(CORE_LLM_LABEL_AWARE).map(|s| s.to_string()).collect(),
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
            pending_kwargs: SynMap::new(),
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

    /// v0.6.47 (T1): el host anota un corte que el chequeo vio fuera del bloque (el valor que un
    /// handler de `serve` devuelve y la respuesta rechaza), para tratarlo como cualquier corte.
    pub fn mark_label_stop(&self) {
        self.label_stop.set(true);
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
            // v0.6.47 (T1): un intérprete que no cargó el programa (el worker de `serve`, un agente)
            // usa el conjunto del proceso, como el `Display` de un valor privado: si no, su corte decía
            // `…` y el rechazo de la respuesta `app`, dos textos para el mismo corte.
            labels::principals_out()
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
        if let Some(c) = self.cut_by_agent() {
            return Err(c);
        }
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
            // v0.6.47 (T1): el reporte de tests no pasa por `redact_for_host`; el texto fijo, igual.
            Control::Error(e) if e.is_fatal_for_labels() && e.operator_detail.is_none() && self.labels && !self.labels_detail_to_program => {
                let mut e = e.clone();
                self.withhold_labels_detail(&mut e);
                e.message.clone()
            }
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
        if !self.labels {
            return;
        }
        let fatal = matches!(r, Err(Control::Error(e)) if e.is_fatal_for_labels());
        // stderr: la misma regla que stdout. Si la corrida se cortó, nada; si no, se escribe.
        if fatal {
            self.err_output.clear();
        } else if !self.err_output.is_empty() {
            let lines = std::mem::take(&mut self.err_output);
            match &self.err_hook {
                Some(hook) => lines.iter().for_each(|l| hook(l)),
                None => write_stderr_lines(&lines),
            }
        }
        // v0.6.47 (T1): con corte, la línea fija SIEMPRE, también sin salida previa: si no, «hubo
        // líneas antes del corte» quedaba a la vista y el sitio del corte lo elige el privado.
        if fatal {
            self.output.clear();
            self.output.push(LABELS_WITHHELD_OUTPUT.to_string());
        }
    }

    /// M1: un error que sale HACIA EL HOST (no atrapado por `try/recover`) se redacta si se
    /// originó bajo PC privado: el texto pasa a `private(<labels>)` (como `pc_redact`) y la
    /// ubicación se conserva. Con etiquetas apagadas es la identidad.
    fn redact_for_host(&mut self, r: Result<SynValue, Control>) -> Result<SynValue, Control> {
        if !self.labels {
            return r;
        }
        // v0.6.47 (T1, A1): si un agente de la corrida se cortó, la corrida termina con ese corte.
        let r = match (r, self.cut_by_agent()) {
            (Err(Control::Error(e)), _) if e.is_fatal_for_labels() => Err(Control::Error(e)),
            (_, Some(c)) => Err(c),
            (r, None) => r,
        };
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
                // v0.6.50 (ronda 4 de v0.6.49, B1): el texto real se toma ANTES de redactar y va al
                // sobre del recibo (sólo lo abre el auditor): era `private(clientes)` en todas partes
                // y quien escribió la tool no sabía que la causa era `render`. El operador sigue
                // viendo el redactado con su ubicación: su log no es un destino de datos privados.
                let real = (!e.redact_label.is_empty() && !e.from_labels && e.operator_detail.is_none())
                    .then(|| e.to_string());
                if real.is_some() {
                    e.message = format!("private({})", e.redact_label);
                }
                self.withhold_labels_detail_sealing(&mut e, real);
                Err(Control::Error(e))
            }
            other => other,
        }
    }

    /// v0.6.47 (T1) — **un corte de etiquetas le llega al programa con un texto fijo.** El mensaje
    /// de un `label_violation` nombra el sitio (la variable, el builtin, la ruta del argumento) y la
    /// ubicación, y cuál de N sitios falla lo elige el dato privado: eran log₂(N) bits por corrida,
    /// y en un loop de agente el error vuelve al modelo (el exploit leía una tarjeta entera, un
    /// dígito por corrida). Hacia el programa sale el mismo texto para cualquier sitio y tipo, con el
    /// conjunto DECLARADO (constante para el programa); el diagnóstico entero queda en
    /// `operator_detail` y, con auditor, en el sobre del recibo. Un error que el programa hizo bajo
    /// una rama privada (`from_private_pc`) sale con el MISMO texto.
    ///
    /// Idempotente (`operator_detail` ya puesto): los hosts pasan por más de un embudo. Con
    /// `labels_detail_to_program` (el CLI sin techo) no hace nada: el texto de hoy, que trae el
    /// remedio exacto, es para quien escribió el programa.
    #[cold]
    #[inline(never)]
    fn withhold_labels_detail(&self, e: &mut RuntimeError) {
        self.withhold_labels_detail_sealing(e, None)
    }

    /// `withhold_labels_detail` con el texto que va al sobre cuando difiere del del operador (B1:
    /// el real de un error redactado; el operador recibe el redactado).
    fn withhold_labels_detail_sealing(&self, e: &mut RuntimeError, sealed: Option<String>) {
        if !self.labels || !e.is_fatal_for_labels() || e.is_halt() || e.operator_detail.is_some() {
            return;
        }
        if self.labels_detail_to_program {
            // Ronda 1 (B3): sin techo el programa ve el detalle de un corte, pero no el texto real
            // de un error redactado; ése va igual al sobre, si hay auditor.
            if let Some(real) = sealed {
                if crate::sealed::active() {
                    crate::sealed::push_sealed(serde_json::json!({"kind": "label_violation", "detail": real}).to_string());
                }
            }
            return;
        }
        let detail = e.to_string();
        // El detalle depende del dato privado, así que va al sobre (sólo lo abre el auditor).
        let sealed = sealed.unwrap_or_else(|| detail.clone());
        crate::sealed::push_sealed(serde_json::json!({"kind": "label_violation", "detail": sealed}).to_string());
        // Un solo texto para los dos tipos de corte: si un `label_violation` y un error bajo la rama
        // privada dijeran cosas distintas, cuál de los dos fue también lo elegiría el dato.
        e.message = labels::cut_text(&self.safe_label(&labels::empty()));
        e.location = None;
        e.operator_detail = Some(detail);
    }

    /// v0.6.47 (T1) — el diagnóstico entero de un corte de etiquetas sale hacia el programa (ver
    /// `withhold_labels_detail`). Sólo para un host donde quien lo corre escribió el programa: el CLI
    /// sin techo.
    pub fn labels_detail_to_program(&self) -> bool {
        self.labels_detail_to_program
    }

    /// v0.6.47 (T1, A1): el corte que comparte esta corrida con sus agentes (ver `RunCut`).
    pub fn run_cut(&self) -> std::sync::Arc<RunCut> {
        self.run_cut.clone()
    }

    /// v0.6.47 (T1, A1): el agente adopta el corte de la corrida que lo lanzó.
    pub fn set_run_cut(&mut self, cut: std::sync::Arc<RunCut>) {
        self.run_cut = cut;
    }

    /// v0.6.47 (T1, A1): `Some` si un agente de la corrida se cortó por etiquetas. El error ya sale
    /// retenido (texto del agente, detalle en `operator_detail`): el agente lo selló al cortarse.
    #[inline]
    fn cut_by_agent(&self) -> Option<Control> {
        if !self.labels {
            return None;
        }
        self.run_cut.get().map(|(m, d)| Self::agent_cut_error(m, d))
    }

    /// v0.6.47 (T1, A1): quien observa el estado de un agente cortado (`agents()`) adopta su corte.
    pub fn adopt_run_cut(&self, message: &str, detail: &str) -> Control {
        self.run_cut.set(message.to_string(), detail.to_string());
        Self::agent_cut_error(message, detail)
    }

    #[cold]
    #[inline(never)]
    fn agent_cut_error(message: &str, detail: &str) -> Control {
        let mut e = RuntimeError::new(message.to_string());
        e.from_labels = true;
        e.operator_detail = Some(detail.to_string());
        Control::Error(e)
    }

    pub fn set_labels_detail_to_program(&mut self, on: bool) {
        self.labels_detail_to_program = on;
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

    /// ¿Hay etiqueta de PC efectiva? Lo mismo que `!pc_label().is_empty()`, sin armar la unión.
    pub fn pc_is_private(&self) -> bool {
        !self.pc.last().unwrap_or(&self.no_label).is_empty() || !self.control_taint.is_empty() || !self.loop_taint.is_empty()
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
                return Err(err_labels(SECRET_UNDER_PRIVATE_PC, loc));
            }
            if !labels::is_container(&v) {
                return Ok(labels::mark(v, self.pc_label()));
            }
        }
        Ok(v)
    }

    /// v0.6.49 (A3): el texto de un secreto que sale de una operación con algo privado. Un secreto no
    /// lleva etiqueta, así que no puede nacer, elegirse ni combinarse con lo privado (sigue prohibido;
    /// sólo cambia el mensaje). Hay dos causas y un texto fijo para cada una: no nombra el sitio, el
    /// builtin ni el secreto, que podrían depender del dato (T1).
    #[cold]
    fn secret_under_labels_text(&self) -> &'static str {
        if self.pc_is_empty() {
            SECRET_FROM_PRIVATE_VALUE
        } else {
            SECRET_UNDER_PRIVATE_PC
        }
    }

    /// v0.6.42 (auditoría, ronda 2) — el lado derecho de `and`/`or` corre SÓLO si el izquierdo lo
    /// permite: es una rama, y con un izquierdo privado corre bajo su PC, igual que el cuerpo de un
    /// `when`. Sin esto `s or exit(1)`, `s and http_post(…)` o `s and print("x")` ejecutaban un
    /// efecto decidido por el secreto con el PC vacío, y el chequeo de sumidero pasaba. Aparte y
    /// sin inline: el camino sin etiquetas no paga nada.
    #[inline(never)]
    fn exec_right_under(&mut self, left: &SynValue, right: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let l = labels::label_deep(left);
        if l.is_empty() {
            return self.exec(right, env);
        }
        self.pc_push(&l);
        let r = self.exec(right, env);
        self.pc_pop();
        r
    }

    /// Empuja `l` al stack de PC (acumulada con la de abajo). Sólo se llama con etiquetas
    /// encendidas y `l` no vacía. Siempre se aparea con `pc_pop`, también en error.
    /// ¿El PC era privado ANTES de la llamada al builtin en curso? (el despacho genérico empuja un
    /// nivel con la etiqueta de los argumentos; el de abajo es el de la rama.)
    #[cold]
    fn outer_pc_private(&self) -> bool {
        !self.control_taint.is_empty()
            || !self.loop_taint.is_empty()
            || (self.pc.len() >= 2 && !self.pc[self.pc.len() - 2].is_empty())
    }

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
    pub(crate) fn note_seen(&mut self, l: &Label) {
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
            return Err(err_labels(self.secret_under_labels_text(), loc));
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
        if let Some(c) = self.cut_by_agent() {
            return Err(c);
        }
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

    /// v0.6.46 (E8): instala la apertura de templates del disco (ver [`TemplateOpenHook`]).
    pub fn set_template_open_hook(&mut self, hook: TemplateOpenHook) {
        self.template_open_hook = Some(hook);
    }

    pub fn template_open_hook(&self) -> Option<TemplateOpenHook> {
        self.template_open_hook.clone()
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
            // M2 (ronda 2): el escritor del audit tiene que saber si la rama es privada. Con un guard
            // (ronda 3, B2): un pánico dentro del builtin no deja el flag prendido en el hilo.
            let _pc = labels::PcPrivateGuard::set(self.pc_is_private());
            self.call_builtin_labelled(bt, args, loc)
        } else {
            let f = bt.func.clone();
            self.call_builtin_at(&f, args, loc)
        };
        // Linaje (DATOS-17): lo que entra al programa desde afuera queda anotado por el motor.
        if let Ok(v) = &r {
            if bt.meta.lineage_source {
                self.record_input(&bt.name, args, v);
                // v0.6.46 (E6): `--replay` corta en la primera entrada que no es la de la corrida
                // grabada.
                if crate::sealed::active() {
                    if let Some(m) = crate::sealed::replay_error() {
                        return Err(Control::Error(RuntimeError::at(m, loc.clone())));
                    }
                }
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
            // v0.6.46 (ronda 3, N1): un error de una task que corrió un builtin (`call_task` no
            // tiene ubicación) dice la línea del builtin, no `<engine>:0:0`.
            Err(Control::Error(mut e)) if e.location.as_ref().is_some_and(|l| l.line == 0 && &*l.file == "<engine>") => {
                e.location = Some(loc.clone());
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
            match self.sink_check(&bt.name, &refs, loc) {
                Ok(()) => {
                    // v0.6.46 (E6.4): un sumidero que corre es un momento público; el reloj cercado
                    // del recibo sellado avanza acá.
                    if crate::sealed::active() {
                        crate::sealed::tick_clock(crate::clock::now_secs_f64());
                    }
                    return self.call_builtin_at(&f, args, loc);
                }
                // v0.6.46 (E6): con el recibo sellado, `reveal` corre en una rama privada (su
                // entrada de audit va al sobre) y sigue por el despacho genérico: el texto revelado
                // sale con la etiqueta del PC. Sólo en el camino del error: el feliz no cambia.
                Err(e) if !sealed_sink_allowed(&bt.name, args) => return Err(e),
                Err(_) => {}
            }
        }
        if self.label_aware.contains(bt.name.as_str()) {
            return self.call_builtin_at(&f, args, loc);
        }
        // v0.6.49 (B9): `call_tool` sobre una task de confianza es la llamada directa con nombres:
        // los argumentos entran con su etiqueta y la política de la tool decide qué publica. Sólo
        // con la tool a la vista: una elegida por un valor privado sigue por el despacho genérico.
        if bt.name == "call_tool" && matches!(args.first(), Some(SynValue::Builtin(t)) if t.trusted.is_some()) {
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
            return Err(err_labels(self.secret_under_labels_text(), loc));
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
            SynValue::Builtin(Rc::new(BuiltinTask::new(name, param_count, None, func))),
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
            SynValue::Builtin(Rc::new(BuiltinTask::new(name, param_names.len() as i32, Some(param_names), func))),
        );
    }

    /// Las entradas que el programa leyó hasta ahora (DATOS-17), en orden.
    pub fn lineage(&self) -> &[LineageEntry] {
        &self.lineage
    }

    /// v0.6.46 (C3): lo que el programa escribió hasta ahora, en orden (`receipt()` lo publica como
    /// `outputs`).
    pub fn outputs(&self) -> &[LineageEntry] {
        &self.outputs
    }

    /// v0.6.46 (C3): un builtin que escribió `data` en `what` (la ruta como la pasó el programa) lo
    /// anota acá, después de escribir bien: el recibo trae el sha256 de lo que quedó, sin que el
    /// programa lo meta a mano. `encoding` dice qué bytes se hashearon ("text": utf-8, "bytes").
    /// Lo llama el builtin y no el despacho: `call_builtin` no paga nada por esto. Una escritura
    /// bajo un PC privado no se anota (ni llega: escribir es un sumidero público).
    /// v0.6.49 (B11): una lectura que hace un builtin que NO es fuente del linaje por lo que
    /// devuelve (`edit_file` lee el archivo y devuelve `{replaced}`): se anota `content` como si lo
    /// hubiera devuelto `source(args…)`, y `--replay` lo compara igual. `Err` = el replay difiere.
    pub fn record_read(&mut self, source: &str, args: &[SynValue], content: &SynValue) -> Result<(), Control> {
        self.record_input(source, args, content);
        if crate::sealed::active() {
            if let Some(m) = crate::sealed::replay_error() {
                return Err(Control::Error(RuntimeError::new(m)));
            }
        }
        Ok(())
    }

    pub fn record_output(&mut self, source: &str, what: &str, data: &[u8], encoding: &'static str) {
        if self.labels && self.pc_is_private() {
            return;
        }
        let entry = LineageEntry {
            source: source.to_string(),
            what: what.to_string(),
            sha256: sha256_hex(data),
            bytes: data.len(),
            encoding: encoding.to_string(),
            salt: None,
            secrets: Vec::new(),
        };
        // v0.6.46 (ronda 1 de cf1, B1): con auditor, lo escrito también va al registro sellado de la
        // corrida, no sólo a `receipt()`.
        if crate::sealed::active() {
            seal_output(&entry);
        }
        if self.outputs.len() >= MAX_LINEAGE {
            self.lineage_dropped[1] = true;
            return;
        }
        self.outputs.push(entry);
    }

    /// v0.6.46 (ronda 1 de cf1, N1): si `lineage()` / `outputs()` perdieron entradas por el tope.
    pub fn lineage_truncated(&self) -> (bool, bool) {
        (self.lineage_dropped[0], self.lineage_dropped[1])
    }

    /// v0.6.46 (ronda 1 de cf1, B2): saca el linaje de este intérprete (un worker que terminó).
    pub fn take_lineage(&mut self) -> LineageTaken {
        LineageTaken {
            inputs: std::mem::take(&mut self.lineage),
            outputs: std::mem::take(&mut self.outputs),
            dropped: self.lineage_dropped,
        }
    }

    /// v0.6.46 (ronda 1 de cf1, B2): suma lo que leyó y escribió un worker, en el orden en que se
    /// llama (el de los items). Bajo un PC privado no se suma: igual que una lectura propia, cuántas
    /// entradas trae `receipt()` diría qué rama se tomó (con auditor, el worker ya lo selló).
    pub fn absorb_lineage(&mut self, t: LineageTaken) {
        if self.labels && self.pc_is_private() {
            return;
        }
        for (i, (mine, theirs)) in [(&mut self.lineage, t.inputs), (&mut self.outputs, t.outputs)].into_iter().enumerate() {
            let room = MAX_LINEAGE.saturating_sub(mine.len());
            if theirs.len() > room || t.dropped[i] {
                self.lineage_dropped[i] = true;
            }
            mine.extend(theirs.into_iter().take(room));
        }
    }

    fn record_input(&mut self, source: &str, args: &[SynValue], result: &SynValue) {
        // v0.6.46 (E6.8): una lectura hecha en una rama decidida por un valor privado no entra en
        // el linaje público: cuántas entradas tenía `inputs` en `receipt()` decía qué rama se tomó.
        // E6: con auditor, va al sobre del recibo sellado; sin auditor, no se registra.
        let sealed = self.labels && self.pc_is_private();
        if sealed && !crate::sealed::active() {
            return;
        }
        if !sealed && self.lineage.len() >= MAX_LINEAGE {
            self.lineage_dropped[0] = true;
            return;
        }
        // v0.6.46 (ronda 1, E6-A1): bajo un PC privado lo leído llega etiquetado (`private`), y el
        // serializador lo redactaba: se sellaba el hash de "[redacted]" (y `--replay` no veía otra
        // entrada) y avisaba en stderr una vez por lectura, que contaba las lecturas de la rama. Se
        // hashea el valor sin etiquetas: sólo va dentro del sobre, que es privado por construcción.
        let (stripped_result, stripped_args);
        let (result, args): (&SynValue, &[SynValue]) = if sealed {
            stripped_result = crate::labels::strip_deep(result);
            stripped_args = args.iter().map(crate::labels::strip_deep).collect::<Vec<_>>();
            (&stripped_result, &stripped_args)
        } else {
            (result, args)
        };
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
            "read_file" | "read_file_bytes" | "list_dir" | "grep" | "parquet_read" | "parquet_scan" | "file_info" | "edit_file" => {
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
                let q = bytes_of(&SynValue::List(crate::types::ListRef::new(args.to_vec().into())));
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
        let secrets = if url_of_connection(source, args).is_some() {
            crate::secret::secret_names_in(args)
        } else {
            Vec::new()
        };
        let entry = LineageEntry {
            source: source.to_string(),
            what,
            sha256: sha256_hex(&payload),
            bytes: payload.len(),
            encoding,
            salt,
            secrets,
        };
        if sealed {
            seal_lineage(&entry, true);
            return;
        }
        // v0.6.46 (E6.4): una lectura de afuera con el PC público también avanza el reloj cercado, y
        // queda en el registro de la corrida (en orden, para que `--replay` la compare).
        if crate::sealed::active() {
            crate::sealed::tick_clock(crate::clock::now_secs_f64());
            seal_lineage(&entry, false);
        }
        self.lineage.push(entry);
    }

    /// Linaje de una respuesta de modelo (`reason`, `decide`, `analyze`, `generate`): lo que
    /// dijo el modelo también es una entrada del programa. Va el hash del prompt, no el prompt.
    ///
    /// v0.6.46 (E5): con datos privados en el prompt (`private`), la respuesta también es privada:
    /// su hash va con la MISMA sal que el del prompt y su largo no se publica (`bytes: 0`). Sin la
    /// sal, el hash de una respuesta corta (un sí/no, una opción) se adivina probando.
    fn record_llm(&mut self, kind: &str, prompt: &str, out: &str, private: bool) {
        use sha2::{Digest, Sha256};
        if self.lineage.len() >= MAX_LINEAGE {
            self.lineage_dropped[0] = true;
            return;
        }
        let salt = fresh_salt();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let commit = hex(&Sha256::new().chain_update(salt).chain_update(prompt.as_bytes()).finalize());
        let (what, sha256, bytes) = if private {
            (
                format!("{} prompt sha256-salted:{} response sha256-salted", kind, commit),
                hex(&Sha256::new().chain_update(salt).chain_update(out.as_bytes()).finalize()),
                0,
            )
        } else {
            (format!("{} prompt sha256-salted:{}", kind, commit), sha256_hex(out.as_bytes()), out.len())
        };
        self.lineage.push(LineageEntry {
            source: "llm".to_string(),
            what,
            sha256,
            bytes,
            encoding: "text".to_string(),
            salt: Some((hex(&salt), "text")),
            secrets: Vec::new(),
        });
    }

    /// v0.6.46 (E5): la respuesta de un modelo lleva la etiqueta de lo que se le dio.
    #[inline]
    fn llm_out(lab: &Label, v: SynValue) -> SynValue {
        if lab.is_empty() {
            v
        } else {
            labels::mark(v, lab.clone())
        }
    }

    /// v0.6.46 (E5): llama al callback de texto con el prompt sin redactar, anota el linaje y
    /// etiqueta la respuesta. Un `Err` del host (un hook de wasm que lanzó) es error de la llamada.
    fn llm_text_call(&mut self, cb: &LlmTextCallback, op: &str, prompt: &str, lab: &Label, loc: &SourceLocation) -> Result<SynValue, Control> {
        let out = cb(op, prompt, &lab[..]).map_err(|m| err_at(format!("{}: {}", op, m), loc))?;
        self.record_llm(op, prompt, &out, !lab.is_empty());
        Ok(Self::llm_out(lab, syn_text(out)))
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

    /// v0.6.46 (E3): cablea el gate de `declassify` (ver [`DeclassifyCapHook`]).
    pub fn set_declassify_cap_hook(&mut self, hook: DeclassifyCapHook) {
        self.declassify_cap_hook = Some(hook);
    }

    /// v0.6.46 (E5): cablea el permiso de datos privados hacia el modelo (ver [`LlmDataHook`]).
    pub fn set_llm_data_hook(&mut self, hook: LlmDataHook) {
        self.llm_data_hook = Some(hook);
    }

    /// v0.6.46 (E3b): registra un módulo de confianza del host y el hook de su scope. Con alguno,
    /// el programa corre en el tree-walker: la envoltura de sus tasks es un builtin, y así la VM
    /// no tiene un caso más que mirar. Ronda 3 (N2): la VM no tiene el chequeo de origen
    /// (`check_trusted_origin`); por eso `shortcuts` queda en `false`, y la envoltura lo afirma.
    pub fn set_trusted_module(&mut self, name: &str, source: &str, hook: TrustedScopeHook) {
        self.trusted_sources.insert(name.to_string(), Rc::from(source));
        self.trusted_scope_hook = Some(hook);
        self.shortcuts = false;
    }

    /// v0.6.50 (D): los templates que el host le da a la tool `name` (`(nombre relativo, texto)`), ya
    /// leídos: el programa no los puede cambiar después.
    pub fn set_trusted_templates(&mut self, name: &str, files: &[(String, String)]) {
        self.trusted_templates.insert(name.to_string(), Rc::new(crate::templates::ToolTemplates::new(files)));
    }

    /// v0.6.50 (D): dentro del scope de una tool, cuál es y sus templates (si el host le dio).
    pub(crate) fn current_tool_templates(&self) -> Option<(&str, Option<Rc<crate::templates::ToolTemplates>>)> {
        let module = self.trusted_stack.last()?;
        Some((module, self.trusted_templates.get(module).cloned()))
    }

    /// v0.6.46 (ronda 1, A1): ¿corre código de una tool de confianza? Lo miran los builtins que
    /// mandan una task a otro intérprete (`parallel_map`, `cron_every`): ahí vería los globales del
    /// programa con las capabilities de la tool.
    pub fn in_trusted_scope(&self) -> bool {
        self.trusted_depth > 0
    }

    /// v0.6.46 (ronda 1, A1): la foto del preludio (builtins, constantes, lo que puso el host) para
    /// los módulos de confianza, antes de la primera sentencia del programa. Sin módulos de
    /// confianza no hace nada.
    fn snapshot_trusted_base(&mut self) {
        if self.trusted_sources.is_empty() || self.trusted_base_env.is_some() {
            return;
        }
        self.trusted_base_env = Some(self.prelude_snapshot("trusted-base"));
    }

    /// v0.6.50 (A): la foto del preludio para los módulos de archivo, antes de la primera sentencia
    /// del programa (o, en un worker o un agente, antes de inyectarle los globales). Una vez por
    /// intérprete. Es otra base que la de confianza: `check_trusted_origin` distingue una task de una
    /// tool porque su cadena llega a ESA base.
    /// Ronda 1 (M1) y ronda 2 (N1): la base de los módulos al entrar por `execute`, `run_block` o
    /// los bloques de test. La primera entrada saca la foto del preludio; una siguiente (cada línea
    /// de la REPL, un embebedor) no: la foto traería lo que ligaron las anteriores, así que sin foto
    /// quedan los builtins.
    fn first_module_base(&mut self) {
        if self.executed {
            self.module_base();
        } else {
            self.snapshot_module_base();
        }
    }

    pub fn snapshot_module_base(&mut self) {
        if self.module_base_env.is_none() {
            self.module_base_env = Some(self.prelude_snapshot("module-base"));
        }
    }

    /// Una copia de lo que hay hoy en `global_env`, en un entorno raíz propio.
    fn prelude_snapshot(&self, name: &str) -> Rc<RefCell<Environment>> {
        let base = Environment::root(name);
        {
            let g = self.global_env.borrow();
            let mut b = base.borrow_mut();
            for (k, v) in g.bindings.iter() {
                b.bindings.insert(k.clone(), v.clone());
            }
        }
        base
    }

    /// El padre de un módulo de archivo. Sin foto (un intérprete que no entró por `execute` ni por
    /// `rebuild_globals`, como la REPL), los builtins con su nombre y las constantes.
    #[cold]
    pub fn module_base(&mut self) -> Rc<RefCell<Environment>> {
        if let Some(b) = &self.module_base_env {
            return b.clone();
        }
        let base = self.builtins_only("module-base");
        self.module_base_env = Some(base.clone());
        base
    }

    /// Los builtins con su propio nombre (o el alias deprecado de uno) y las constantes: lo que el
    /// programa liga a un nombre es una task o un valor, nunca un builtin con ese nombre.
    fn builtins_only(&self, name: &str) -> Rc<RefCell<Environment>> {
        let base = Environment::root(name);
        {
            let g = self.global_env.borrow();
            let mut b = base.borrow_mut();
            for (k, v) in g.bindings.iter() {
                if let SynValue::Builtin(bt) = v {
                    let own = *bt.name == **k
                        || crate::deprecated::DEPRECATED_NAMES.iter().any(|(old, new)| *old == &**k && *new == &*bt.name);
                    if own {
                        b.bindings.insert(k.clone(), v.clone());
                    }
                }
            }
            for (k, v) in PRELUDE_CONSTANTS {
                b.bindings.insert(k, syn_float(v));
            }
        }
        base
    }

    /// v0.6.50 (A): `Undefined variable` y, si el nombre se buscó desde un módulo de archivo y es
    /// del programa, por qué no lo ve. Sólo en el camino del error.
    #[cold]
    #[inline(never)]
    pub(crate) fn undefined_in(&self, name: &str, loc: &SourceLocation, env: &Rc<RefCell<Environment>>) -> Control {
        self.with_module_hint(undefined_variable(name, loc), name, env)
    }

    /// Lo mismo para `set` (`Cannot set undefined variable`).
    #[cold]
    #[inline(never)]
    pub(crate) fn set_undefined_in(&self, name: &str, env: &Rc<RefCell<Environment>>) -> Control {
        self.with_module_hint(err(format!("Cannot set undefined variable: '{}'. Use 'let' first.", name)), name, env)
    }

    fn with_module_hint(&self, mut c: Control, name: &str, env: &Rc<RefCell<Environment>>) -> Control {
        let Some(base) = &self.module_base_env else { return c };
        let mut cur = env.clone();
        let in_module = loop {
            let next = {
                let e = cur.borrow();
                match &e.parent {
                    Some(p) if Rc::ptr_eq(p, base) => break e.name.starts_with("module:"),
                    Some(p) => p.clone(),
                    None => break false,
                }
            };
            cur = next;
        };
        if in_module && self.global_env.borrow().bindings.get(name).is_some() {
            if let Control::Error(e) = &mut c {
                e.message.push_str(&format!(
                    " — '{}' is a name of the program that imports this module, and a module sees only its own names and the builtins: pass it as an argument or define it in the module",
                    name
                ));
            }
        }
        c
    }

    /// v0.6.50 (B): la base de confianza de ESTE intérprete para reconstruir una tool que llegó en
    /// una foto (un worker, un agente): la foto del preludio antes de inyectar los globales. `None`
    /// sin módulos de confianza en el proceso.
    pub fn trusted_base_for_rebuild(&mut self) -> Option<Rc<RefCell<Environment>>> {
        if self.trusted_sources.is_empty() {
            return None;
        }
        self.snapshot_trusted_base();
        Some(self.trusted_base())
    }

    /// v0.6.50 (B): el hook del scope de confianza de ESTE intérprete (para envolver una tool que
    /// llegó en una foto con `wrap_trusted_task`).
    pub fn trusted_scope_hook(&self) -> Option<TrustedScopeHook> {
        self.trusted_scope_hook.clone()
    }

    /// v0.6.50 (B): la task envuelta `name` recibe los argumentos con su etiqueta, como las que
    /// envuelve `load_trusted_module`.
    pub fn mark_label_aware(&mut self, name: &str) {
        self.label_aware.insert(name.to_string());
    }

    /// v0.6.50 (B): la vista reconstruida queda en el caché como la tool `module` de este
    /// intérprete: un `use "trusted:<module>"` posterior (en una ruta) recibe una copia de ésta, sin
    /// volver a correr el nivel superior de la tool.
    pub fn adopt_trusted_view(&mut self, module: &str, view: &crate::types::MapRef) {
        let key = format!("trusted:{}", module);
        if !self.module_cache.contains_key(&key) {
            self.module_cache.insert(key, SynValue::Map(view.borrow().to_ref()));
        }
    }

    /// Ronda 2: ¿la task es de una tool de confianza? Lo es si su entorno, subiendo por los padres,
    /// llega a la base de confianza (un módulo de confianza, sus lambdas, sus templates); lo que
    /// cuelga de `global_env` es del programa. Sin base (no debería pasar con un scope abierto), no.
    #[cold]
    #[inline(never)]
    fn check_trusted_origin(&self, task: &SynTaskValue, loc: &SourceLocation) -> Result<(), Control> {
        let mut cur = task.closure_env.clone();
        loop {
            let next = cur.borrow().parent.clone();
            match next {
                Some(p) => cur = p,
                None => break,
            }
        }
        if self.trusted_base_env.as_ref().is_some_and(|b| Rc::ptr_eq(b, &cur)) {
            return Ok(());
        }
        Err(err_at(
            format!(
                "a trusted tool cannot run the program's task '{}' — it would run with the tool's capabilities (a callback the program registered, or a name resolved in the program's globals); a trusted tool runs only its own code",
                task.name
            ),
            loc,
        ))
    }

    /// v0.6.46 (ronda 2): el padre del entorno de un template. Dentro de una tool de confianza, la
    /// base de confianza (los builtins): un `{upper(x)}` del template de la tool no llama a lo que el
    /// programa definió con ese nombre. Ronda 3: hoy no se alcanza (`render` es error dentro de la
    /// tool, R3-A1); queda para cuando el host le dé a la tool sus templates.
    pub(crate) fn template_parent(&self) -> Rc<RefCell<Environment>> {
        if self.trusted_depth > 0 {
            if let Some(b) = &self.trusted_base_env {
                return b.clone();
            }
        }
        self.global_env.clone()
    }

    /// El padre de un módulo de confianza. Si no hubo foto (un intérprete que no entra por
    /// `execute`, como el de un agente), sólo los builtins con su propio nombre (o el alias
    /// deprecado de uno): lo que el programa liga a un nombre es una task o un valor, nunca un
    /// builtin con ese nombre.
    #[cold]
    fn trusted_base(&mut self) -> Rc<RefCell<Environment>> {
        if let Some(b) = &self.trusted_base_env {
            return b.clone();
        }
        let base = self.builtins_only("trusted-base");
        self.trusted_base_env = Some(base.clone());
        base
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
    ) -> Result<Option<(SynValue, String)>, Control> {
        use crate::judge::{syn_to_json, JudgeAnswer, JudgeKind, JudgeOption, JudgeQuestion, JudgeRequest, MAX_OPTIONS};
        let Some(cb) = self.judge_callback.clone() else { return Ok(None) };
        let SynValue::List(l) = opts else { return Ok(None) };
        let ids: Vec<String> = list_values(&l).iter().map(|v| v.to_string()).collect();
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
                Some(JudgeAnswer::Choose { choice: Some(c), .. }) => {
                    Ok(Some((syn_text(c.as_str()), format!("Decide between {} given {}", opts, giv))))
                }
                _ => Ok(None),
            },
            Ok(None) => Ok(None),
            Err(m) => Err(err_at(m, loc)),
        }
    }

    /// v0.6.46 (E5): el gate de datos de una operación LLM, ANTES de la capability. Con las
    /// etiquetas encendidas: el PC tiene que ser público (como en todo sumidero, y sin dejar
    /// entrada de audit de una rama privada), y si lo que se le da al modelo lleva algo privado,
    /// el host tiene que permitirlo para esos principales y ese provider. Devuelve la etiqueta de
    /// las entradas: la llamada arma el prompt sin redactar y la respuesta sale con ella.
    fn llm_data_gate(&mut self, op: &str, judge: bool, inputs: &[&SynValue], loc: &SourceLocation) -> Result<Label, Control> {
        if !self.labels {
            return Ok(labels::empty());
        }
        if !self.pc_is_empty() {
            self.sink_check(op, &[], loc)?;
        }
        let mut l = labels::empty();
        for v in inputs {
            l = labels::union(&l, &labels::label_deep(v));
        }
        if l.is_empty() {
            return Ok(l);
        }
        self.note_seen(&l);
        let ok = match &self.llm_data_hook {
            Some(h) => h(op, &l[..], &self.safe_label(&l), judge),
            None => false,
        };
        if !ok {
            return Err(llm_data_not_granted(op, judge, &self.safe_label(&l), loc));
        }
        Ok(l)
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
        crate::waiting::set_thread_cancel(Some(token.flag.clone()));
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
        // v0.6.45 (D2): en wasm, la bandera también enruta acá los límites de la corrida embebida.
        #[cfg(target_arch = "wasm32")]
        if let Some(r) = crate::wasm_limits::check(self.steps) {
            return r.map_err(|m| Control::Error(RuntimeError::new(m)));
        }
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
        let loc = SourceLocation { file: "<engine>".into(), line: 0, column: 0, offset: 0 };
        let r = self.call_value(func, args, &loc);
        // T5 (M1): es un punto de salida hacia el host.
        self.redact_for_host(r)
    }

    /// Intent declarado (para enriquecer /llms.txt). Texto descriptivo, no gatea nada.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// El host le entrega a este intérprete los entornos de módulo que reconstruyó para él (desde
    /// la foto de un `parallel_map`, un agente o un worker de `serve`). Quedan a su cargo: al morir
    /// el intérprete se vacían, como el global, para cortar el ciclo entre cada task del módulo y su
    /// entorno. Sólo los que no comparte con nadie que lo sobreviva.
    pub fn adopt_module_envs(&mut self, envs: impl IntoIterator<Item = Rc<RefCell<Environment>>>) {
        for e in envs {
            if !self.owned_module_envs.iter().any(|x| Rc::ptr_eq(x, &e)) {
                self.owned_module_envs.push(e);
            }
        }
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
        // v0.6.50 (A): como `execute`, la foto del preludio antes de que el bloque ligue nada (la
        // REPL, un embebedor). Un agente ya la trae de `rebuild_globals`.
        if self.module_base_env.is_none() && stmts_have_file_use(stmts) {
            self.first_module_base();
        }
        self.executed = true;
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
        let env = Environment::child_scope(parent, "request");
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
        // El cuerpo de la ruta por la VM (y el nivel nativo), con la misma condición que el
        // programa: atajos y sin etiquetas. Con etiquetas (`--labels`, `serve --attested`), el
        // tree-walker. Hasta v0.6.38 los handlers corrían siempre en el tree-walker.
        let result = if self.shortcuts && !self.labels && !stmts.is_empty() {
            self.run_request_chunk(stmts, &env)
        } else {
            self.exec_block(stmts, &env)
        };
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
        // v0.6.46 (ronda 1 de cf1, M1): el linaje es POR REQUEST. El worker nace vacío (no corre
        // el top-level), así que todo lo que hay es de requests anteriores, que pueden ser de otros
        // usuarios: `receipt()` listaba lo que leyeron y escribieron (con su nombre en la ruta).
        self.lineage.clear();
        self.outputs.clear();
        self.lineage_dropped = [false; 2];
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
        if let Some(name) = raw_path.strip_prefix("trusted:") {
            return self.load_trusted_module(name);
        }
        if self.trusted_depth > 0 {
            return Err(err(format!(
                "a trusted module imports only other trusted modules (`use \"trusted:…\"`), not '{}': a file module is read from disk, where the program can write it, and it would run with the tool's capabilities",
                raw_path
            )));
        }
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

    /// v0.6.46 (E3b): `use "trusted:nombre"`. El cuerpo corre bajo el scope de confianza, y cada
    /// task exportada se entrega envuelta: al llamarla corre con SUS `require` ∩ el techo de
    /// confianza, no con lo del llamador. Una task común no paga nada: la diferencia está en el
    /// valor (un builtin), no en una marca que mire cada llamada.
    #[cold]
    #[inline(never)]
    fn load_trusted_module(&mut self, name: &str) -> Result<SynValue, Control> {
        let key = format!("trusted:{}", name);
        // Ronda 1 (A2): cada `use` recibe SU copia de las exportaciones: lo que un importador
        // escribe en ella no lo ve la tool ni otro importador. Ronda 2 (N2): es una segunda defensa
        // sin test propio (hoy el `set` ya copia el mapa antes de escribirlo, porque el caché es
        // otro dueño); no sacarla creyendo que sobra.
        if let Some(SynValue::Map(cached)) = self.module_cache.get(&key) {
            let copy = cached.borrow().to_ref();
            register_trusted_view(&copy);
            return Ok(SynValue::Map(copy));
        }
        let (Some(source), Some(hook)) = (self.trusted_sources.get(name).cloned(), self.trusted_scope_hook.clone()) else {
            return Err(err(format!(
                "no trusted module named '{}': the host loads it (`synsema run --trusted {}=./file.syn`, or `trusted: {{ {}: source }}` in wasm); a program cannot load one itself",
                name, name, name
            )));
        };
        if self.loading_modules.contains(&key) {
            return Err(err(format!("circular import: module '{}' is already being loaded", key)));
        }
        let program = parse_source(&source, &key).map_err(|e| err(e.to_string()))?;
        note_loaded_module(&key, &source, &program);
        check_protected_names(&program)?;
        for stmt in &program.statements {
            match &stmt.kind {
                NodeKind::ServeBlock { .. } => return Err(err(format!("module '{}' must not contain a 'serve' block", key))),
                NodeKind::RequireStatement { .. } => {
                    return Err(err(format!(
                        "module '{}' must not have a top-level 'require': each exported task declares its own",
                        key
                    )))
                }
                _ => {}
            }
        }
        // v0.6.50 (D8): un `render("literal")` de la tool tiene que estar entre sus templates; acá,
        // antes de que llegue ningún dato, el texto se ve aunque los datos sean privados.
        crate::templates::check_tool_renders(&program, name, self.trusted_templates.get(name).map(|t| &**t))
            .map_err(err)?;
        self.loading_modules.insert(key.clone());
        // Ronda 1 (A1): hijo del preludio, no de `global_env`: los nombres libres del módulo son los
        // builtins, no lo que el programa definió antes o después del `use`.
        let base = self.trusted_base();
        let module_env = Environment::child(&base, &format!("module:{}", key));
        self.exports_collector.push(Vec::new());
        self.stdout_verdict = None;
        hook(Some((name, &[])));
        debug_assert!(!self.shortcuts, "a trusted scope opened with the VM on (it has no origin check)");
        self.trusted_depth += 1;
        self.trusted_stack.push(name.to_string());
        let exec_res = self.exec_block(&program.statements, &module_env);
        self.trusted_stack.pop();
        self.trusted_depth -= 1;
        hook(None);
        self.stdout_verdict = None;
        let names = self.exports_collector.pop().unwrap_or_default();
        self.loading_modules.remove(&key);
        exec_res?;
        let mut exports = SynMap::new();
        let mut wrapped: HashSet<usize> = HashSet::new();
        for export in names {
            if let Some(v) = env_get(&module_env, &export) {
                // Consciente de etiquetas: los argumentos entran con la suya (la política del dev
                // decide qué publica) y el PC es el del llamador. El despacho genérico los habría
                // desetiquetado y corrido la task bajo su unión. Ronda 1 de v0.6.50 (B6): también
                // una task que la tool expone dentro de un mapa o una lista (`export let M be
                // {"f": helper}`): sin envolver corría con las capabilities del programa.
                let mut aware = Vec::new();
                let v = wrap_exposed_tasks(name, &export, v, &hook, &mut aware, &mut wrapped);
                self.label_aware.extend(aware);
                exports.insert(export, v);
            }
        }
        // v0.6.50 (E-c): el `require` de una task que el módulo no exporta no concede nada. Ronda 2
        // (B1): cuenta como exportada la task de nivel superior que la carga envolvió, también la que
        // llega a un export por otro nombre (`export let M be BASE`); una que sólo nombra una lambda
        // o una llamada (`export let W be () => helper()`), no.
        let exported: HashSet<String> = module_env
            .borrow()
            .bindings
            .iter()
            .filter(|(_, v)| matches!(v, SynValue::Task(t) if wrapped.contains(&(Rc::as_ptr(t) as usize))))
            .map(|(k, _)| k.to_string())
            .collect();
        crate::deprecated::warn_trusted_unexported_requires(&program, name, &exported);
        // Ronda 1 (A2): sin `register_module`. La vista de un módulo común se escribe desde afuera
        // (`set m.X to v` religa su variable); la de uno de confianza es un mapa de datos.
        let map = exports.into_ref();
        let copy = map.borrow().to_ref();
        register_trusted_view(&copy);
        self.module_cache.insert(key, SynValue::Map(map));
        Ok(SynValue::Map(copy))
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
        // `program_sha` del recibo se calcula con ESTOS bytes, sin releer ni reparsear. Fuera de
        // línea y fría: dentro de esta función movía el acomodo del intérprete (+8 % en Windows sin
        // PGO, con las mismas instrucciones).
        note_loaded_module(resolved, &source, &program);
        // T5 (B8): un módulo tampoco puede redefinir los nombres protegidos.
        check_protected_names(&program)?;
        // Un nombre deprecado en un módulo avisa igual que en el archivo principal (una vez
        // por nombre y por proceso), con el archivo del módulo.
        crate::deprecated::warn_once_at_load(&program, raw_path.trim_start_matches("./"));
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

        #[cfg(feature = "resolver-check")]
        crate::resolve::check::register(&program);
        // v0.6.50 (A): hijo del preludio, no de `global_env`: un módulo no ve los nombres de quien lo
        // importa (ni los que define antes o después del `use`).
        let base = self.module_base();
        let module_env = Environment::child(&base, &format!("module:{}", resolved));
        self.exports_collector.push(Vec::new());
        let exec_res = self.exec_block(&program.statements, &module_env);
        let names = self.exports_collector.pop().unwrap_or_default();
        exec_res?;

        let mut exports = SynMap::new();
        for name in names {
            if let Some(v) = env_get(&module_env, &name) {
                exports.insert(name, v);
            }
        }
        let map = exports.into_ref();
        register_module(&map, &module_env);
        Ok(SynValue::Map(map))
    }

    fn register_builtins(&self) {
        // Núcleo
        self.register("print", -1, Rc::new(|i, a, l| i.b_print(a, l)));
        self.register("eprint", -1, Rc::new(|i, a, l| i.b_eprint(a, l)));
        self.register("exit", -1, Rc::new(|_i, a, l| exit_builtin(a, l)));
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
                // `2.0` (o `2.0d`) se lee igual que `2`: un número con valor entero de 2 a 36.
                if let (Some(_), Some(SynValue::Number(n))) = (a.first(), a.get(1)) {
                    let f = n.to_f64();
                    if f.fract() == 0.0 && (2.0..=36.0).contains(&f) {
                        let (shown, b) = (n.to_string(), f as i64);
                        return Err(err(format!(
                            "int(x, {shown}): the second argument is the fallback value, not the base — for base {b} write int(x, base = {b}); for a fallback of {shown}, name it: int(x, fallback = {shown})"
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
            Some(SynValue::List(l)) => Ok(syn_int(list_values(&l).iter().filter(|v| !matches!(v, SynValue::Nothing)).count() as i64)),
            Some(other) => Err(err(format!("count(values) counts the present values of a list, got {}; count() alone is the summarize aggregate", other.type_name()))),
        }));
        self.register("count_missing", 1, Rc::new(|_i, a, _l| match nth(a, 0)? {
            SynValue::List(l) => Ok(syn_int(list_values(&l).iter().filter(|v| matches!(v, SynValue::Nothing)).count() as i64)),
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
                    let mut m = SynMap::new();
                    m.insert("source", syn_text(e.source.as_str()));
                    m.insert("what", syn_text(e.what.as_str()));
                    m.insert("sha256", syn_text(e.sha256.as_str()));
                    m.insert("bytes", syn_int(e.bytes as i64));
                    m.insert("encoding", syn_text(e.encoding.as_str()));
                    if !e.secrets.is_empty() {
                        m.insert("secrets", syn_list(e.secrets.iter().map(|n| syn_text(n.as_str())).collect()));
                    }
                    // Local, nunca en el recibo: con la sal el dueño revela una consulta.
                    if let Some((salt, qenc)) = &e.salt {
                        m.insert("salt", syn_text(salt.as_str()));
                        m.insert("committed_encoding", syn_text(*qenc));
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
            for (k, v) in PRELUDE_CONSTANTS {
                g.bindings.insert(k, syn_float(v));
            }
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
            SynValue::List(l) => l.borrow().to_vec(),
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
            SynValue::Map(m) => m.borrow().to_map(),
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
        #[cfg(feature = "resolver-check")]
        crate::resolve::check::register(program);
        let r = self.execute_inner(program);
        // T5 (M1): un error no atrapado sale redactado si la corrida tocó privados.
        let r = self.redact_for_host(r);
        // v0.6.47 (T1): el corte del programa también es el de la corrida, y el cierre con agentes
        // (`close_swarm_run`) retiene igual su eco y su stderr. Sólo acá, en la corrida entera: un
        // `call_task`/`run_block` (cron, handlers de serve) no corta a los que vienen después.
        if let Err(Control::Error(e)) = &r {
            if self.labels && e.is_fatal_for_labels() {
                self.run_cut.set(e.to_string(), e.operator_detail.clone().unwrap_or_else(|| e.to_string()));
            }
        }
        r
    }

    fn execute_inner(&mut self, program: &Program) -> Result<SynValue, Control> {
        let g = self.global_env.clone();
        self.snapshot_trusted_base();
        if program.has_file_use {
            self.first_module_base();
        }
        self.executed = true;
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
        let rest = &program.statements[split..];
        // La VM (F3) corre el programa con atajos y sin etiquetas; si no, el tree-walker.
        if self.shortcuts && !self.labels && !rest.is_empty() {
            return self.run_program_chunk(rest, &g);
        }
        for stmt in rest {
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
        self.run_test_blocks_with(program, &mut |_, _| None)
    }

    /// Como `run_test_blocks`, con un hook `after_each(nombre)` que corre al terminar
    /// cada bloque `test` (cuerpo incluido) y puede devolver un mensaje de fallo —
    /// el motor lo usa para joinear los agentes que el test spawneó y reflejar sus
    /// errores como fallo de ESE test (`synsema test` cablea el swarm real).
    pub fn run_test_blocks_with(
        &mut self,
        program: &Program,
        after_each: &mut dyn FnMut(&str, bool) -> Option<String>,
    ) -> Vec<TestOutcome> {
        let g = self.global_env.clone();
        self.snapshot_trusted_base();
        if program.has_file_use {
            self.first_module_base();
        }
        self.executed = true;
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
                // v0.6.47 (T1, A1): un agente del setup o del bloque anterior (ya esperado por
                // `after_each`) se cortó: la corrida entera termina, como con un corte del bloque.
                if let Some(c) = self.cut_by_agent() {
                    return vec![self.labels_stopped_outcome(&c)];
                }
                let test_env = Environment::child(&g, &format!("test:{}", name));
                // Cada bloque `test` es su propia unidad — la tinta de continuación de uno
                // No puede llegarle al siguiente (ni al setup).
                let saved_taint = self.take_taint();
                let result = self.exec_block(body, &test_env);
                // Ronda 1 (M3): un bloque que llamó `exit` le pide al host que detenga sus agentes.
                let exited = matches!(&result, Err(Control::Error(e)) if e.exit_code.is_some());
                let mut outcome = match result {
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
                        self.restore_taint(saved_taint);
                        return vec![self.labels_stopped_outcome(&Control::Error(e))];
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
                if let Some(msg) = after_each(name, exited) {
                    outcome.passed = false;
                    outcome.message = Some(match outcome.message.take() {
                        Some(prev) => format!("{}; {}", prev, msg),
                        None => msg,
                    });
                }
                outcomes.push(outcome);
            }
        }
        if let Some(c) = self.cut_by_agent() {
            return vec![self.labels_stopped_outcome(&c)];
        }
        outcomes
    }

    /// El único outcome de una corrida de tests cortada por etiquetas.
    fn labels_stopped_outcome(&self, c: &Control) -> TestOutcome {
        // v0.6.47 (T1): el corte de la suite es el de la corrida: el cierre retiene el eco y el
        // stderr de los agentes (`run_tests_inner`).
        if let Control::Error(e) = c {
            self.run_cut.set(self.host_message(c), e.operator_detail.clone().unwrap_or_else(|| e.to_string()));
        }
        TestOutcome {
            // Ronda 7: el nombre del bloque lo pone el ATACANTE, así que nombrar en cuál murió es
            // tantos bits como bloques haya — el mismo mensaje que dice "un veredicto por bloque
            // sería un bit por bloque" los entregaba en su propio título.
            name: "labels: the run was stopped".to_string(),
            passed: false,
            assertion: false,
            message: Some(format!(
                "{} — a label violation stops the whole run: a per-block verdict would \
                 be one bit of private data per block. Fix it and run the suite again",
                self.host_message(c)
            )),
        }
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
        self.exec_labelled(node, env)
    }

    /// La rama de `exec` con etiquetas encendidas. Aparte y sin inline a propósito (v0.6.42): así
    /// `exec`, que envuelve a TODO nodo, queda de dos líneas y un cambio en la lógica de etiquetas
    /// no mueve el camino caliente de los programas sin etiquetas.
    #[inline(never)]
    fn exec_labelled(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
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
            // v0.6.42 (auditoría) — `exit`/`proxy to` no son fallas: su llamada ya pasó el chequeo
            // de sumidero (PC vacío, valor público). Marcarlos como corte del flujo retenía stdout.
            if (!pc_empty || !inner.is_empty()) && !e.is_halt() {
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
                let mut m = SynMap::with_capacity(pairs.len());
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
                        m.insert(Key::of_value(labels::unwrap(&key)), val);
                        continue;
                    }
                    m.insert(Key::of_value(&key), val);
                }
                match key_label {
                    Some(l) => self.rewrap(syn_map(m), l, loc),
                    None => Ok(syn_map(m)),
                }
            }

            // -- Identificadores y acceso --
            NodeKind::Identifier { name } => match {
                #[cfg(feature = "resolver-check")]
                crate::resolve::check::at(loc, name, false, env);
                env_get(env, name)
            } {
                Some(v) => Ok(v),
                None => Err(self.undefined_in(name, loc, env)),
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
                if *operator == BinOp::And {
                    if !l.is_truthy() {
                        let res = syn_bool(false);
                        return if self.labels { self.join_operands(res, &l, None, loc) } else { Ok(res) };
                    }
                    let r = if self.labels { self.exec_right_under(&l, right, env)? } else { self.exec(right, env)? };
                    let res = syn_bool(r.is_truthy());
                    return if self.labels { self.join_operands(res, &l, Some(&r), loc) } else { Ok(res) };
                }
                if *operator == BinOp::Or {
                    if l.is_truthy() {
                        let res = syn_bool(true);
                        return if self.labels { self.join_operands(res, &l, None, loc) } else { Ok(res) };
                    }
                    let r = if self.labels { self.exec_right_under(&l, right, env)? } else { self.exec(right, env)? };
                    let res = syn_bool(r.is_truthy());
                    return if self.labels { self.join_operands(res, &l, Some(&r), loc) } else { Ok(res) };
                }
                // `x // nota`: un comentario al estilo C se lee como división entera por la
                // variable `nota`. Si esa palabra no existe, el error lo dice (sólo con espacio
                // después de `//`, como se escribe un comentario; la semántica de `//` no cambia).
                if *operator == BinOp::FloorDiv {
                    if let NodeKind::Identifier { .. } = &right.kind {
                        if right.location.line == loc.line && right.location.column > loc.column + 2 {
                            let r = self.exec(right, env).map_err(|c| match c {
                                Control::Error(mut e) if e.message.starts_with("Undefined variable") => {
                                    e.message.push_str(" — `//` is integer division; comments in Synsema start with `--`");
                                    Control::Error(e)
                                }
                                other => other,
                            })?;
                            return self.exec_binary(l, *operator, r, loc);
                        }
                    }
                }
                let r = self.exec(right, env)?;
                self.exec_binary(l, *operator, r, loc)
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
                        let r = self.exec_unary(*operator, inner, loc)?;
                        return self.rewrap(r, l, loc);
                    }
                }
                self.exec_unary(*operator, v, loc)
            }
            NodeKind::CompareChain { operands, operators } => {
                // `a < b < c`: cada operando una vez, corte en el primer par falso. Bajo
                // etiquetas el booleano une las etiquetas de lo evaluado, como `and`.
                let mut prev = self.exec(&operands[0], env)?;
                let mut acc: Option<SynValue> = None;
                for (op, node) in operators.iter().zip(operands[1..].iter()) {
                    let cur = self.exec(node, env)?;
                    let c = self.exec_binary(prev, *op, cur.clone(), loc)?;
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
                env_set_shared(env, name, v.clone());
                #[cfg(feature = "resolver-check")]
                crate::resolve::check::at(loc, name, true, env);
                Ok(v)
            }
            NodeKind::SetMutation { target, value } => {
                // `set P to append(P, v)`, `P + [...]`, `insert(P, i, v)` y `merge(P, m)` en el
                // lugar (v0.6.29), con P una variable o un camino `x.campo[k]`: con semántica de
                // valor el resultado es el mismo, pero si nadie más comparte el contenedor no
                // hace falta copiarlo: el idioma documentado pasa a ser O(1) por vuelta.
                if self.shortcuts && (!self.labels || self.pc_is_empty()) {
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
                // `each i in range(…)` sin armar la lista (atajo, F1.11; ver `each_over_range`).
                let lazy = if self.shortcuts && !self.labels { self.each_over_range(collection, env)? } else { None };
                let mut each_label: Option<Label> = None;
                let mut items = match lazy {
                    Some(r) => EachItems::Range(r),
                    None => {
                        let coll = self.exec(collection, env)?;
                        // Colección con etiquetas (a cualquier profundidad, B3) → cada item sale
                        // con esa etiqueta y el cuerpo corre bajo ese PC; el valor implícito también.
                        let coll = if self.labels {
                            let l = labels::label_deep(&coll);
                            if !l.is_empty() {
                                each_label = Some(l);
                            }
                            labels::unwrap(&coll).clone()
                        } else {
                            coll
                        };
                        self.each_items_of(&coll, loc)?
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
                while let Some(item) = items.next_item() {
                    let loop_env = self.acquire_frame(env, "each");
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
                    env_set_shared(&loop_env, variable, item);
                    #[cfg(feature = "resolver-check")]
                    crate::resolve::check::at(loc, variable, true, &loop_env);
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
                    self.release_frame(loop_env);
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
                // En wasm el tope de siempre se queda: ahí no hay `timeout`, hilos ni señal
                // que corte un bucle sin fin, y el host (una pestaña, un handler) se colgaría.
                #[cfg(target_arch = "wasm32")]
                let mut wasm_iters: u64 = 0;
                let mut result = SynValue::Nothing;
                // T5 (ronda 5): igual que `each` — la tinta de un `stop` del cuerpo muere acá.
                // Por eso el cuerpo ya no puede salir con `return`: el frame quedaría abierto.
                let saved_loop = self.enter_loop();
                let mut outcome: Result<(), Control> = Ok(());
                loop {
                    #[cfg(target_arch = "wasm32")]
                    {
                        wasm_iters += 1;
                        if wasm_iters > 1_000_000 {
                            outcome = Err(err_at(
                                "Loop exceeded maximum iterations (1,000,000) — in the wasm build a `while` is capped, since the host cannot interrupt a loop that never ends; the native `synsema` has no cap",
                                &node.location,
                            ));
                            break;
                        }
                    }
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
            NodeKind::TaskDefinition { .. } => self.exec_task_definition(node, env),
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
                // Evaluá cada arg preservando su `name` (named vs posicional), en un `Vec`
                // reciclado (F2a.3) si hay uno.
                let mut args = self.free_args.pop().unwrap_or_default();
                args.reserve(arguments.len());
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
                    // v0.6.46 (E4): la llamada literal a `declassify`/`private` arma su marca.
                    if matches!(name.as_identifier(), Some("declassify" | "private")) {
                        let out = self.call_label_builtin_by_name(func, &mut args, loc);
                        self.release_args(args);
                        return out;
                    }
                }
                if let Err(e) = check_call_arity(&func, &args, loc) {
                    return Err(arity_error(e, &func, &args, loc));
                }
                let out = self.call_value_named(func, &mut args, loc);
                self.release_args(args);
                out
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
                    .map(|n| Param { name: n.clone(), default: None, ty: None })
                    .collect();
                let task = Rc::new(SynTaskValue {
                    name: "<lambda>".to_string(),
                    parameters: lambda_params,
                    // `[give <expresión>]`, armado por el parser y compartido (R2.5): crear una
                    // lambda ya no copia su expresión.
                    body: body.clone(),
                    closure_env: env.clone(),
                    origin: Some(loc.clone()),
                    required_capabilities: Vec::new(),
                    code: Default::default(),
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
            NodeKind::UseImport { .. } => self.exec_use_import(node, env),
            // `routes <name>`: grupo de rutas montable. Se ejecuta a un MAP PLANO
            // {"_routes_meta": [<method/path/params/requires_auth>...],
            //  "_route_handler_<i>": task} — cada handler-task cierra sobre ESTE env
            // (el module_env cuando el grupo vive en un módulo), así el snapshot de
            // serve lo trata como cualquier map de módulo (DE-032) y los cuerpos de
            // ruta llaman helpers privados del módulo por nombre simple.
            NodeKind::RoutesDeclaration { .. } => self.exec_routes_declaration(node, env),

            // Una cláusula `mount` suelta jamás se ejecuta sola: la consume el serve hook.
            NodeKind::MountClause { .. } => {
                Err(err_at("'mount' is only valid inside a serve block", loc))
            }

            NodeKind::ExportDeclaration { .. } => self.exec_export_declaration(node, env),

            // -- Tipos --
            NodeKind::TypeDefinition { .. } => self.exec_type_definition(node, env),

            NodeKind::EnumDefinition { .. } => self.exec_enum_definition(node, env),

            // -- Agentes (fallback in-process; sin swarm en capa 4) --
            NodeKind::AgentDefinition { .. } => self.exec_agent_definition(node, env),
            NodeKind::SpawnStatement { .. } => self.exec_spawn_statement(node, env),

            // -- Blackboard --
            NodeKind::ShareStatement { .. } => self.exec_share_statement(node, env),
            NodeKind::ObserveStatement { .. } => self.exec_observe_statement(node, env),
            NodeKind::SignalStatement { .. } => self.exec_signal_statement(node, env),
            NodeKind::WaitForStatement { .. } => self.exec_wait_for_statement(node, env),

            // -- Capacidades --
            NodeKind::RequireStatement { .. } => self.exec_require_statement(node, env),
            NodeKind::SandboxBlock { under: None, .. } => self.exec_sandbox_block(node, env),
            NodeKind::SandboxBlock { under: Some(_), .. } => self.exec_sandbox_block_under(node, env),
            NodeKind::InvariantDeclaration { .. } => self.exec_invariant_declaration(node, env),
            NodeKind::IntentDeclaration { .. } => self.exec_intent_declaration(node, env),

            // -- Interacción humana (no-interactiva → auto) --
            // T5 (B7): el mensaje a un humano sale del intérprete — sumidero.
            NodeKind::ApproveStatement { .. } => self.exec_approve_statement(node, env),
            NodeKind::ConfirmStatement { .. } => self.exec_confirm_statement(node, env),
            NodeKind::ShowStatement { .. } => self.exec_show_statement(node, env),
            NodeKind::AskExpression { .. } => self.exec_ask_expression(node, env),

            // -- LLM (sin callback → placeholders) --
            NodeKind::ReasonExpression { .. } => self.exec_reason_expression(node, env),
            NodeKind::DecideExpression { .. } => self.exec_decide_expression(node, env),
            NodeKind::JudgeExpression { .. } => self.exec_judge_expression(node, env),
            NodeKind::AnalyzeExpression { .. } => self.exec_analyze_expression(node, env),
            NodeKind::GenerateExpression { .. } => self.exec_generate_expression(node, env),

            // -- Observabilidad --
            NodeKind::TraceBlock { body, .. } => self.exec_block(body, env),
            NodeKind::LogStatement { .. } => self.exec_log_statement(node, env),
            NodeKind::MeasureBlock { body, .. } => self.exec_block(body, env),
            NodeKind::CheckpointStatement { name } => {
                self.exec(name, env)?; // evalúa la expresión (resuelve variables), descarta el valor
                Ok(SynValue::Nothing)
            }
            // G2: los bloques `test` NO corren en `synsema run` — no-op. Sólo
            // `Interpreter::run_test_blocks` (vía `synsema test`) ejecuta su cuerpo.
            NodeKind::TestBlock { .. } => Ok(SynValue::Nothing),

            // -- Errores --
            NodeKind::TryRecover { .. } => self.exec_try_recover(node, env),

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
            NodeKind::ProxyStatement { .. } => self.exec_proxy_statement(node, env),
            NodeKind::StreamBlock { body } => self.exec_block(body, env),
            // El cuerpo de un `socket` lo corre el runtime de serve con el binding `socket`
            // ya adoptado; llegar acá es ejecutarlo fuera de una ruta.
            NodeKind::SocketBlock { .. } => Err(err_at(
                "socket is only available inside a serve route (route \"GET /path\" + socket block)",
                loc,
            )),
            NodeKind::SendStatement { .. } => self.exec_send_statement(node, env),
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

    // Brazos poco usados de `exec_node`, cada uno en su función (specs/compute-rendimiento.md
    // F1.10): con todos adentro, el frame de `exec_node` se dimensionaba para el peor de ellos y
    // cada nivel de expresión y de llamada pagaba esa pila. El cuerpo es el del brazo, sin cambios.

    #[inline(never)]
    fn exec_agent_definition(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let NodeKind::AgentDefinition { name, body, .. } = &node.kind else { unreachable!("exec_agent_definition: otro nodo") };
        if self.trusted_depth > 0 {
            return Err(err_at(trusted_no_agents(name), &node.location));
        }
        {
        self.agent_definitions.insert(name.clone(), (body.clone(), env.clone()));
        let mut m = SynMap::new();
        m.insert("name", syn_text(name.as_str()));
        m.insert("state", syn_text("defined"));
        let agent_data = syn_map(m);
        env_set(env, name, agent_data.clone());
        Ok(agent_data)
    }
    }

    #[inline(never)]
    fn exec_analyze_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::AnalyzeExpression { data, objective } = &node.kind else { unreachable!("exec_analyze_expression: otro nodo") };
        {
        let d = self.exec(data, env)?;
        // v0.6.46 (E5): el gate de datos (PC, techo `llm=P@…`) antes que la capability; el prompt
        // lleva el dato sin redactar y la respuesta sale con su etiqueta.
        let lab = self.llm_data_gate("analyze", false, &[&d], loc)?;
        self.check_llm_cap()?;
        let d = if lab.is_empty() { d } else { labels::strip_deep(&d) };
        match self.llm_callback.clone() {
            Some(cb) => {
                let prompt = format!("Analyze for {}: {}", objective, d);
                self.llm_text_call(&cb, "analyze", &prompt, &lab, loc)
            }
            None => {
                note_llm_offline();
                Ok(Self::llm_out(&lab, syn_text(format!("[analysis of: {}]", objective))))
            }
        }
    }
    }

    #[inline(never)]
    fn exec_approve_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ApproveStatement { message, timeout, .. } = &node.kind else { unreachable!("exec_approve_statement: otro nodo") };
        {
        let m = self.exec(message, env)?;
        if self.labels {
            self.sink_check("approve", &[&m], loc)?;
        }
        match self.human_callback.clone() {
            Some(cb) => {
                // v0.6.42 — una persona tarda: bajo `serve` el hilo suelta su permiso mientras espera.
                let _w = crate::waiting::waiting();
                Ok(cb("approve", &m.to_string(), *timeout))
            }
            None => Ok(syn_bool(true)),
        }
    }
    }

    #[inline(never)]
    fn exec_ask_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::AskExpression { prompt, options, timeout } = &node.kind else { unreachable!("exec_ask_expression: otro nodo") };
        {
        let p = self.exec(prompt, env)?;
        if self.labels {
            self.sink_check("ask", &[&p], loc)?;
        }
        if let Some(cb) = self.human_callback.clone() {
            let r = {
                let _w = crate::waiting::waiting();
                cb("ask", &p.to_string(), *timeout)
            };
            if r.is_truthy() {
                return Ok(syn_text(r.to_string()));
            }
        }
        // Fallback no-interactivo: primera opción si hay lista.
        if let Some(opts) = options {
            let o = self.exec(opts, env)?;
            if let SynValue::List(l) = &o {
                if let Some(first) = list_values(&l).first() {
                    return Ok(first.clone());
                }
            }
        }
        Ok(syn_text(""))
    }
    }

    #[inline(never)]
    fn exec_confirm_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ConfirmStatement { message, timeout } = &node.kind else { unreachable!("exec_confirm_statement: otro nodo") };
        {
        let m = self.exec(message, env)?;
        if self.labels {
            self.sink_check("confirm", &[&m], loc)?;
        }
        match self.human_callback.clone() {
            Some(cb) => {
                let _w = crate::waiting::waiting();
                Ok(cb("confirm", &m.to_string(), *timeout))
            }
            None => Ok(syn_bool(true)),
        }
    }
    }

    #[inline(never)]
    fn exec_decide_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::DecideExpression { options, given, .. } = &node.kind else { unreachable!("exec_decide_expression: otro nodo") };
        {
        // v0.6.26 — `SYNSEMA_JUDGE_DECIDE`: el juez contesta con una de TUS opciones,
        // calibrado y sin normalización ni reintento. Si no aplica o no está disponible,
        // sigue el camino LLM de siempre.
        // v0.6.46 (E5): ese camino se chequea contra el techo del JUEZ (`judge=P@…`).
        let via_judge = self.decide_via_judge && self.judge_callback.is_some();
        if via_judge {
            // v0.6.49 (§C): `llm` se pide antes de preguntarle al juez (si el juez no elige,
            // contesta el modelo, y que eso dependa de la respuesta haría depender el permiso del
            // dato). El error salía sin ubicación ni por qué. Ronda 2 (M1): al entrar, antes de
            // evaluar `options` y `given`. Si el nodo ya tocó lo privado (`given c.name`), un
            // error común sale redactado (`private(customers)`), y el texto de este no depende
            // del dato. Ronda 2 (B1): con el PC privado va primero el del sumidero, el de fondo,
            // como en el camino LLM común.
            if self.labels && !self.pc_is_empty() {
                self.sink_check("decide", &[], loc)?;
            }
            if let Err(Control::Error(e)) = self.check_llm_cap() {
                // Ronda 1 (N6): un solo remedio; el de la denegación común sólo nombraba el
                // preámbulo. Ronda 2 (B2): con las dos formas, porque acá no se sabe todavía si
                // el dato es privado.
                let head = e.message.split(" — ").next().unwrap_or(&e.message);
                // Ronda 1 de v0.6.50 (B4): el `require` va donde corre el código, como en
                // `where_to_require` (en un agente, su cuerpo; en una tool, su task exportada).
                let place = match (self.in_trusted_scope(), self.current_agent()) {
                    (true, _) => "to the exported task of the trusted module that runs it".to_string(),
                    (false, Some(a)) => format!("to the body of agent {} (the program's `require` does not reach it)", a),
                    (false, None) => "to the program's preamble".to_string(),
                };
                return Err(err_at(
                    format!(
                        "{} — a `decide` served by the judge (SYNSEMA_JUDGE_DECIDE) falls back to the model when the judge does not choose, so it needs `llm` as well as `judge`: add `require llm` {} (with private data, `require llm(\"<principal>\")`), and the host's ceiling has to allow it too (`llm`, or `llm=<principal>@<provider host>` for private data), or unset the knob",
                        head, place
                    ),
                    loc,
                ));
            }
        }
        let opts = match options {
            Some(o) => self.exec(o, env)?,
            None => SynValue::Nothing,
        };
        let giv = match given {
            Some(g) => self.exec(g, env)?,
            None => SynValue::Nothing,
        };
        if via_judge {
            let lab = self.llm_data_gate("decide", true, &[&opts, &giv], loc)?;
            let (o, g) = if lab.is_empty() { (opts.clone(), giv.clone()) } else { (labels::strip_deep(&opts), labels::strip_deep(&giv)) };
            if let Some((chosen, prompt)) = self.decide_with_judge(&o, &g, loc)? {
                let c = chosen.to_string();
                self.record_llm("decide", &prompt, &c, !lab.is_empty());
                return Ok(Self::llm_out(&lab, chosen));
            }
        }
        let lab = self.llm_data_gate("decide", false, &[&opts, &giv], loc)?;
        if !via_judge {
            self.check_llm_cap()?;
        }
        let (opts, giv) = if lab.is_empty() { (opts, giv) } else { (labels::strip_deep(&opts), labels::strip_deep(&giv)) };
        let prompt = format!("Decide between {} given {}", opts, giv);
        // Camino dedicado (DE-039): las opciones viajan ESTRUCTURADAS al motor,
        // que fuerza la elección por tool/enum + normaliza + reintenta. Sólo si
        // el motor lo cableó; si no, el callback de texto genérico de siempre.
        if let Some(cb) = self.llm_decide_callback.clone() {
            let opt_list: Vec<String> = match &opts {
                SynValue::List(l) => list_values(&l).iter().map(|v| v.to_string()).collect(),
                _ => Vec::new(),
            };
            let out = cb(&prompt, &opt_list);
            self.record_llm("decide", &prompt, &out, !lab.is_empty());
            return Ok(Self::llm_out(&lab, syn_text(out)));
        }
        match self.llm_callback.clone() {
            Some(cb) => self.llm_text_call(&cb, "decide", &prompt, &lab, loc),
            None => {
                note_llm_offline();
                Ok(Self::llm_out(&lab, syn_text("[decision pending]")))
            }
        }
    }
    }

    #[inline(never)]
    fn exec_enum_definition(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::EnumDefinition { name, variants } = &node.kind else { unreachable!("exec_enum_definition: otro nodo") };
        {
        // Valor de variante = map etiquetado {"__variant": "Enum.var", <campos>};
        // tipo enum = map namespace {"__enum": "Enum", <var>: valor|ctor}. Sin
        // tipo de runtime nuevo: construcción = property-access + call.
        let mut namespace = SynMap::new();
        namespace.insert("__enum", syn_text(name.as_str()));
        for (variant_name, fields) in variants {
            let qualified = format!("{}.{}", name, variant_name);
            if fields.is_empty() {
                // Variante nullary → un map etiquetado constante.
                let mut m = SynMap::new();
                m.insert("__variant", syn_text(qualified.as_str()));
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
                    let mut m = SynMap::new();
                    m.insert("__variant", syn_text(q.as_str()));
                    for (n, val) in field_names.iter().zip(args.iter()) {
                        m.insert(n.clone(), val.clone());
                    }
                    Ok(syn_map(m))
                });
                namespace.insert(
                    variant_name.clone(),
                    SynValue::Builtin(Rc::new(BuiltinTask::new(qualified.clone(), count, None, func))),
                );
            }
        }
        let value = syn_map(namespace);
        env_set(env, name, value.clone());
        Ok(value)
    }
    }

    #[inline(never)]
    fn exec_export_declaration(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ExportDeclaration { declaration } = &node.kind else { unreachable!("exec_export_declaration: otro nodo") };
        {
        let value = self.exec(declaration, env)?;
        let name = match &declaration.kind {
            NodeKind::TaskDefinition { name, .. }
            | NodeKind::TypeDefinition { name, .. }
            | NodeKind::EnumDefinition { name, .. }
            | NodeKind::RoutesDeclaration { name, .. } => name.clone(),
            NodeKind::LetBinding { name, .. } => name.to_string(),
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
    }

    #[inline(never)]
    fn exec_generate_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::GenerateExpression { target, given, parameters } = &node.kind else { unreachable!("exec_generate_expression: otro nodo") };
        {
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
        // v0.6.46 (E5): gate de datos, después la capability; el prompt sin redactar.
        let lab = {
            let mut refs: Vec<&SynValue> = Vec::new();
            if let Some(g) = &giv {
                refs.push(g);
            }
            refs.extend(param_vals.iter().map(|(_, v)| v));
            self.llm_data_gate("generate", false, &refs, loc)?
        };
        self.check_llm_cap()?;
        let (giv, param_vals) = if lab.is_empty() {
            (giv, param_vals)
        } else {
            (giv.map(|g| labels::strip_deep(&g)), param_vals.into_iter().map(|(n, v)| (n, labels::strip_deep(&v))).collect())
        };
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
                self.llm_text_call(&cb, "generate", &prompt, &lab, loc)
            }
            None => {
                note_llm_offline();
                Ok(Self::llm_out(&lab, syn_text(format!("[generated: {}]", target))))
            }
        }
    }
    }

    #[inline(never)]
    fn exec_intent_declaration(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let _ = env;
        let NodeKind::IntentDeclaration { description } = &node.kind else { unreachable!("exec_intent_declaration: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_invariant_declaration(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::InvariantDeclaration { condition, description } = &node.kind else { unreachable!("exec_invariant_declaration: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_judge_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::JudgeExpression { state, questions } = &node.kind else { unreachable!("exec_judge_expression: otro nodo") };
        {
        use crate::judge::{
            answer_to_value, is_valid_state, options_from_value, syn_to_json,
            validate_question, JudgeQuestion, JudgeRequest,
        };
        let st = self.exec(state, env)?;
        // v0.6.46 (E5): un estado privado se valida por lo que lleva adentro (llega al juez si el
        // techo lo permite).
        if !is_valid_state(labels::unwrap(&st)) {
            return Err(err_at(
                format!(
                    "judge: the state must be a text, a map or a list (got {}); the model reads \
                     text, so wrap it with text() if you mean its rendering",
                    labels::unwrap(&st).type_name()
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
        // v0.6.46 (E5): con `judge=P@…` en el techo, el dato privado llega al juez sin redactar
        // (gate de datos antes que la capability) y las respuestas salen con su etiqueta.
        let lab = {
            let refs: Vec<&SynValue> = crossing.iter().collect();
            self.llm_data_gate("judge", true, &refs, loc)?
        };
        self.check_judge_cap()?;
        if !lab.is_empty() {
            for (q, v) in qs.iter_mut().zip(crossing.iter().skip(1)) {
                q.instruction = syn_to_json(&labels::strip_deep(v));
            }
        }
        let state_json = if lab.is_empty() { syn_to_json(&st) } else { syn_to_json(&labels::strip_deep(&st)) };
        let req = JudgeRequest {
            state: state_json,
            questions: qs,
        };
        let response = match self.judge_callback.clone() {
            Some(cb) => cb(&req).map_err(|m| err_at(m, loc))?,
            None => {
                note_judge_offline();
                None
            }
        };
        if let Some(r) = &response {
            let prompt = serde_json::json!({"state": &req.state, "questions": req.questions.iter().map(|q| &q.instruction).collect::<Vec<_>>()}).to_string();
            let answers = format!("{:?}", r.answers);
            self.record_llm("judge", &prompt, &answers, !lab.is_empty());
        }
        // Map plano id → respuesta, en el orden del bloque. Sin metadatos mezclados:
        // una pregunta llamada `usage` no colisiona con nada.
        let mut out: SynMap = SynMap::new();
        for (i, q) in req.questions.iter().enumerate() {
            let a = response.as_ref().and_then(|r| r.answers.get(i));
            out.insert(q.id.clone(), answer_to_value(q, a));
        }
        Ok(Self::llm_out(&lab, syn_map(out)))
    }
    }

    /// v0.6.42 — `proxy to <destino>` dentro de una ruta. Fuera de `exec_node` a propósito: ese
    /// `match` es el camino caliente del intérprete y un brazo grande lo engorda para todos.
    #[inline(never)]
    fn exec_proxy_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ProxyStatement { target } = &node.kind else { unreachable!("exec_proxy_statement: otro nodo") };
        // v0.6.42 — dentro de una ruta de `serve`, `proxy to <destino>` corta el handler y
        // el runtime reenvía la request (también desde una task que la ruta llamó). Fuera
        // de una ruta nadie lo convierte: el host lo informa con este mismo mensaje.
        let v = self.exec(target, env)?;
        if self.labels {
            // El destino es una salida a la red: ni elegido bajo una rama privada ni privado.
            self.sink_check("proxy to", &[&v], loc)?;
        }
        let dest = match &v {
            SynValue::Text(t) => ProxyTo::Url(t.to_string()),
            SynValue::Number(n) if n.is_integer() => match n.to_i64_trunc() {
                Some(h) => ProxyTo::Handle(h),
                None => return Err(err_at("proxy to: the handle is out of range", loc)),
            },
            other => {
                return Err(err_at(
                    format!("proxy to: expected an http:// URL or a pipe end, got {}", other.type_name()),
                    loc,
                ))
            }
        };
        let mut e = RuntimeError::at("proxy is only available inside a serve route", loc.clone());
        e.proxy = Some(dest);
        Err(Control::Error(e))
    }

    #[inline(never)]
    fn exec_log_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::LogStatement { message, .. } = &node.kind else { unreachable!("exec_log_statement: otro nodo") };
        {
        let m = self.exec(message, env)?;
        self.ensure_stdout()?;
        // T5 (ronda 4): la misma boca pública que `print` — ver `stdout_flow_check`.
        self.stdout_flow_check("log", loc)?;
        let line = format!("[LOG] {}", self.pc_redact(m.to_string()));
        // v0.6.42 — bajo `synsema run`, `log` es diagnóstico y va a stderr (Go `log`, Python
        // `logging`, Rust `env_logger`, MCP por stdio): stdout queda para el resultado. Bajo
        // `test`/`serve`/`conform`/JSON se sigue colectando con la salida, como siempre.
        // Con un `log_hook` (agentes, el sink de serve) va por el hook: conserva el prefijo del
        // agente y el destino del host. Un hook que sólo observa (`run --labels`) no es un destino.
        let to_hook = self.log_hook.is_some() && !self.log_hook_observes_only;
        if !to_hook && LIVE_STDOUT.load(std::sync::atomic::Ordering::Relaxed) {
            self.emit_err_line(line);
        } else {
            self.emit_line(line);
        }
        Ok(SynValue::Nothing)
    }
    }

    #[inline(never)]
    fn exec_observe_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let NodeKind::ObserveStatement { key, variable } = &node.kind else { unreachable!("exec_observe_statement: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_reason_expression(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ReasonExpression { subject, context, .. } = &node.kind else { unreachable!("exec_reason_expression: otro nodo") };
        {
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
        // v0.6.46 (E5): gate de datos, después la capability; el prompt sin redactar.
        let lab = {
            let mut refs: Vec<&SynValue> = vec![&subj];
            refs.extend(ctx_vals.iter().map(|(_, v)| v));
            self.llm_data_gate("reason", false, &refs, loc)?
        };
        self.check_llm_cap()?;
        let (subj, ctx_vals) = if lab.is_empty() {
            (subj, ctx_vals)
        } else {
            (labels::strip_deep(&subj), ctx_vals.into_iter().map(|(n, v)| (n, labels::strip_deep(&v))).collect())
        };
        let ctx_parts: Vec<String> =
            ctx_vals.iter().map(|(name, v)| format!("{}={}", name, v)).collect();
        match self.llm_callback.clone() {
            Some(cb) => {
                let prompt = if ctx_parts.is_empty() {
                    subj.to_string()
                } else {
                    format!("Reason about: {} (context: {})", subj, ctx_parts.join(", "))
                };
                self.llm_text_call(&cb, "reason", &prompt, &lab, loc)
            }
            None => {
                note_llm_offline();
                Ok(Self::llm_out(&lab, syn_text(format!("[reasoning about: {}]", subj))))
            }
        }
    }
    }

    #[inline(never)]
    fn exec_require_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::RequireStatement { capability, scope, bound_to } = &node.kind else { unreachable!("exec_require_statement: otro nodo") };
        {
        // El scope se evalúa a su str (igual que el oráculo: str(eval(scope))).
        let scope_v = match scope {
            Some(s) => Some(self.exec(s, env)?),
            None => None,
        };
        // v0.6.45 (ronda 4, revisión): con etiquetas, un `require` dentro de una rama privada (o con
        // un scope que sale de un valor privado) no concede nada: lo concedido dependería del dato
        // (un `try random_int(…)` público después lo publicaba) y su entrada de audit — "above host
        // ceiling" — sólo aparecía si la rama se tomaba.
        // Dentro de un `sandbox` o de una tool el `require` no concede nada (más abajo): ahí no hay
        // nada que depender del dato (ronda 4, revisión).
        if self.labels
            && !self.in_sandbox()
            && !self.in_tool_scope()
            && (self.pc_is_private() || scope_v.as_ref().is_some_and(|v| !labels::label_deep(v).is_empty()))
        {
            return Err(Control::Error(RuntimeError::labels(
                format!(
                    "label_violation: `require {}` runs in a branch decided by a private value (or its scope is private); what is granted cannot depend on private data — declare it at the top of the program, or declassify(<the condition>, \"<why it may be published>\")",
                    capability
                ),
                loc.clone(),
            )));
        }
        let mut scope_val = scope_v.map(|v| v.to_string());
        if let (Some(hosts), Some(name)) = (bound_to, scope_val.as_deref()) {
            scope_val = Some(self.bound_secret_scope(name, hosts, env, loc)?);
        }
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
    }

    /// v0.6.46 (E1): el scope de `require secret("K") for net("h1"), net("h2")` como lo lee el
    /// modelo de capabilities: `K@h1|h2` (la misma forma que el techo `--cap-set secret=K@h`).
    /// Cada host se normaliza como un scope de `net` y sigue la gramática de una atadura.
    #[cold]
    #[inline(never)]
    fn bound_secret_scope(
        &mut self,
        name: &str,
        hosts: &[Node],
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
    ) -> Result<String, Control> {
        if name.is_empty() || name.contains('@') || name.contains('|') {
            return Err(err_at(
                format!("require secret({:?}) for net(...): the name of a bound secret cannot be empty or contain '@' or '|'", name),
                loc,
            ));
        }
        let mut out: Vec<String> = Vec::with_capacity(hosts.len());
        for h in hosts {
            let v = self.exec(h, env)?;
            if self.labels && !labels::label_deep(&v).is_empty() {
                return Err(Control::Error(RuntimeError::labels(
                    format!("label_violation: the host of `require secret({:?}) for net(...)` is private; where a secret may go cannot depend on private data", name),
                    loc.clone(),
                )));
            }
            let SynValue::Text(t) = &v else {
                return Err(err_at(
                    format!("require secret({:?}) for net(...): the host must be text, got {}", name, v.type_name()),
                    loc,
                ));
            };
            let host = crate::capscope::net_host_scope(t);
            if let Some(e) = crate::capscope::bound_host_error(&host) {
                return Err(err_at(format!("require secret({:?}) for net(...): {}", name, e), loc));
            }
            if !out.contains(&host) {
                out.push(host);
            }
        }
        Ok(format!("{}@{}", name, out.join("|")))
    }

    #[inline(never)]
    fn exec_routes_declaration(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let NodeKind::RoutesDeclaration { name, routes } = &node.kind else { unreachable!("exec_routes_declaration: otro nodo") };
        {
        let mut map = SynMap::new();
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
                        let mut lm = SynMap::new();
                        lm.insert("unlimited", syn_bool(*unlimited));
                        lm.insert("count", SynValue::Number(Number::Int(cap)));
                        lm.insert("window", syn_text(window.as_str()));
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
                    code: Default::default(),
                }));
                map.insert(format!("_route_handler_{}", i), task);
                let mut mm = SynMap::new();
                mm.insert("method", syn_text(method.as_str()));
                mm.insert("path", syn_text(path.as_str()));
                mm.insert("requires_auth", syn_bool(*requires_auth));
                // v0.6.20 — `private` (fuera de los documentos generados) y la clase de
                // ruta (`stream`/`socket`) viajan en la meta para que serve las monte
                // exactamente como una ruta directa.
                mm.insert("private", syn_bool(*private));
                mm.insert("streaming", syn_bool(*streaming));
                mm.insert("socket", syn_bool(*socket));
                mm.insert(
                    "params".to_string(),
                    syn_list(param_names.iter().map(|p| syn_text(p.as_str())).collect()),
                );
                if let Some(l) = route_limit {
                    mm.insert("rate_limit", l);
                }
                if let Some(t) = route_timeout {
                    mm.insert("timeout", t);
                }
                meta.push(syn_map(mm));
            }
        }
        map.insert("_routes_meta", syn_list(meta));
        let value = syn_map(map);
        env_set(env, name, value.clone());
        Ok(value)
    }
    }

    #[inline(never)]
    fn exec_sandbox_block(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let NodeKind::SandboxBlock { body, under: None } = &node.kind else { unreachable!("exec_sandbox_block: otro nodo") };
        {
        // Aislamiento real: durante el cuerpo, todas las capabilities quedan
        // DENEGADAS (el hook vacía el CapabilitySet; `require` es no-op). Se
        // restaura al salir, también en el camino de error. El `print` no está
        // gateado, así que el sandbox puede computar y devolver un valor.
        let sandbox_env = Environment::child_scope(env, "sandbox");
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
    }

    #[inline(never)]
    fn exec_sandbox_block_under(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::SandboxBlock { body, under: Some(caps_expr) } = &node.kind else { unreachable!("exec_sandbox_block_under: otro nodo") };
        {
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
        let sandbox_env = Environment::child_scope(env, "sandbox");
        self.sandbox_depth += 1;
        let result = self.exec_block(body, &sandbox_env);
        // Se desapila también en el camino de error: un techo de bloque jamás
        // sobrevive al bloque.
        let _ = hook(None);
        self.sandbox_depth -= 1;
        result
    }
    }

    #[inline(never)]
    fn exec_send_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::SendStatement { value, event_name } = &node.kind else { unreachable!("exec_send_statement: otro nodo") };
        match self.stream_emit.clone() {
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
    }
    }

    #[inline(never)]
    fn exec_share_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ShareStatement { value, key } = &node.kind else { unreachable!("exec_share_statement: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_show_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::ShowStatement { value, label } = &node.kind else { unreachable!("exec_show_statement: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_signal_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::SignalStatement { name, data } = &node.kind else { unreachable!("exec_signal_statement: otro nodo") };
        {
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
    }

    #[inline(never)]
    fn exec_spawn_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::SpawnStatement { agent_name, arguments } = &node.kind else { unreachable!("exec_spawn_statement: otro nodo") };
        if self.trusted_depth > 0 {
            return Err(err_at(trusted_no_agents(agent_name), loc));
        }
        {
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
                        .map(|(k, v)| (k.to_string(), v.clone()))
                        .collect()
                };
                // T1: el agente corre EN NOMBRE de quien pidió (la identidad viaja
                // con el techo), no "como el agente".
                let subject = SpawnSubject {
                    identity: self.request_identity.clone(),
                    spend_limits: self.request_spend_limits.clone(),
                    run_cut: Some(self.run_cut.clone()),
                    principals: self.declared_principals_list(),
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
    }

    #[inline(never)]
    fn exec_task_definition(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::TaskDefinition { name, parameters, body, .. } = &node.kind else { unreachable!("exec_task_definition: otro nodo") };
        {
        let mut required_caps = Vec::new();
        let mut clean_body = Vec::new();
        // Sin `require` adentro (casi siempre), el cuerpo de la task ES el del AST, compartido
        // (R2.5); con `require`, el cuerpo limpio se arma acá.
        let has_requires = body.iter().any(|s| matches!(s.kind, NodeKind::RequireStatement { .. }));
        for stmt in body.iter() {
            if let NodeKind::RequireStatement { capability, scope, bound_to } = &stmt.kind {
                let scope_v = match scope {
                    Some(s) => Some(self.exec(s, env)?),
                    None => None,
                };
                // Ronda 5 (B2): el `require` de una task es el techo de la tool en `call_tool`; con
                // etiquetas, el mismo chequeo que `exec_require_statement` (lo concedido no puede
                // depender de un dato privado: una lectura que anda o no según el valor, y un `try`
                // público alrededor, lo publicaba).
                if self.labels
                    && (self.pc_is_private() || scope_v.as_ref().is_some_and(|v| !labels::label_deep(v).is_empty()))
                {
                    return Err(Control::Error(RuntimeError::labels(
                        format!(
                            "label_violation: `require {}` in task {} is defined in a branch decided by a private value (or its scope is private); what a tool is granted cannot depend on private data — define the task at the top of the program with a public scope, or declassify(<the value>, \"<why it may be published>\")",
                            capability, name
                        ),
                        stmt.location.clone(),
                    )));
                }
                let mut scope_s = scope_v.map(|v| v.to_string());
                if let (Some(hosts), Some(n)) = (bound_to, scope_s.as_deref()) {
                    scope_s = Some(self.bound_secret_scope(n, hosts, env, &stmt.location)?);
                }
                required_caps.push((capability.clone(), scope_s));
            } else if has_requires {
                clean_body.push(stmt.clone());
            }
        }
        let task = Rc::new(SynTaskValue {
            name: name.clone(),
            parameters: parameters.clone(),
            body: if has_requires { clean_body.into() } else { body.clone() },
            closure_env: env.clone(),
            origin: Some(loc.clone()),
            required_capabilities: required_caps,
            code: Default::default(),
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
    }

    #[inline(never)]
    fn exec_try_recover(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::TryRecover { try_body, error_variable, recover_body } = &node.kind else { unreachable!("exec_try_recover: otro nodo") };
        {
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
            // v0.6.42 — `exit(code)` termina el programa y `proxy to` el handler: no son errores
            // que se recuperan.
            Err(Control::Error(e)) if e.is_halt() => Err(Control::Error(e)),
            Err(Control::Error(e)) => {
                let msg = strip_loc_prefix(&e.to_string());
                let recover_env = Environment::child_scope(env, "recover");
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
    }

    #[inline(never)]
    fn exec_type_definition(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::TypeDefinition { name, fields } = &node.kind else { unreachable!("exec_type_definition: otro nodo") };
        {
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
            let mut m = SynMap::new();
            for (n, v) in field_names.iter().zip(args.iter()) {
                m.insert(n.clone(), v.clone());
            }
            Ok(syn_map(m))
        });
        env_set(
            env,
            name,
            SynValue::Builtin(Rc::new(BuiltinTask::new(name.clone(), count, None, func))),
        );
        Ok(SynValue::Nothing)
    }
    }

    #[inline(never)]
    fn exec_use_import(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::UseImport { path, alias } = &node.kind else { unreachable!("exec_use_import: otro nodo") };
        {
        let module_map = self.load_module(path, &loc.file)?;
        env_set(env, alias, module_map.clone());
        Ok(module_map)
    }
    }

    #[inline(never)]
    fn exec_wait_for_statement(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        let NodeKind::WaitForStatement { signal_name, variable, timeout } = &node.kind else { unreachable!("exec_wait_for_statement: otro nodo") };
        {
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
            Some(h) => {
                // v0.6.42 — bajo `serve`, el hilo que espera la señal suelta su permiso.
                let _w = crate::waiting::waiting();
                h(&n, secs, &cancel)
            }
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
                let arm_env = Environment::child_scope(env, "match-arm");
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
    fn exec_unary(&mut self, operator: UnOp, v: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
        match operator {
            UnOp::Neg => match &v {
                SynValue::Number(n) => Ok(syn_number(n.neg())),
                SynValue::Complex(z) => Ok(SynValue::Complex(-z)),
                SynValue::Array(a) => Ok(crate::arrays::negate(a)),
                _ => Err(err_at(format!("Cannot negate {}", v.type_name()), loc)),
            },
            UnOp::Not => Ok(syn_bool(!v.is_truthy())),
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
        op: BinOp,
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
        op: BinOp,
        right: SynValue,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        // Lógicos: el cortocircuito vive en `exec` (BinaryOp); acá sólo llega un
        // `and`/`or` ya evaluado por ambos lados (callers internos).
        if op == BinOp::And {
            return Ok(syn_bool(left.is_truthy() && right.is_truthy()));
        }
        if op == BinOp::Or {
            return Ok(syn_bool(left.is_truthy() || right.is_truthy()));
        }
        // `x in xs` / `x not in xs` (v0.6.29): pertenencia en lista, clave de mapa,
        // subtexto o subsecuencia de bytes — la misma igualdad que `contains`.
        if matches!(op, BinOp::In | BinOp::NotIn) {
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
                for x in list_values(&items).iter() {
                    let eq = crate::tabular::strict_equals(&left, x)
                        .map_err(|_| err_at(format!("`{}`: {}", op, crate::number::MIX_DECIMAL_FLOAT), loc))?;
                    if eq {
                        found = true;
                        break;
                    }
                }
                return Ok(syn_bool(if op == BinOp::In { found } else { !found }));
            }
            let found = self.b_contains(&[right, left], loc)?.is_truthy();
            return Ok(syn_bool(if op == BinOp::In { found } else { !found }));
        }
        // Hueco de un template con backticks: el texto de cualquier valor, como el f-string de
        // Python (`xs={xs}` → "xs=[1, 2]"). Un secret sigue por `+` (queda secret y redactado).
        let op = if op == BinOp::InterpConcat {
            if !matches!(right, SynValue::Text(_) | SynValue::Secret(_)) {
                // v0.6.46 (E2): una lista o un mapa con un secret adentro saldría como
                // `{k: secret(K)}`, texto común que puede terminar en un header o una URL. Sólo en
                // contenedores (un hueco escalar no paga nada nuevo), y sin recorrerlos: el `Display`
                // ya los recorre y cuenta cada marcador que escribe. El error se arma aparte (frío).
                // Ronda 1: también un valor de servidor (`ok(xs)` se imprime con lo que lleva).
                if matches!(right, SynValue::List(_) | SynValue::Map(_) | SynValue::Server(_)) {
                    let before = crate::secret::placeholders_written();
                    let hole = match &left {
                        SynValue::Text(l) => Some((true, format!("{}{}", l, right))),
                        SynValue::Secret(_) => Some((false, right.to_string())),
                        _ => None,
                    };
                    if crate::secret::placeholders_written() != before {
                        return Err(secret_in_hole_error(&right, loc));
                    }
                    match hole {
                        Some((true, s)) => return Ok(syn_text(s)),
                        Some((false, h)) => return secret_concat(&left, &syn_text(h), loc),
                        None => {}
                    }
                }
                match &left {
                    SynValue::Text(l) => return Ok(syn_text(format!("{}{}", l, right))),
                    // v0.6.44 (auditoría A2): después de un hueco con un secret lo acumulado es un
                    // secret, y el hueco siguiente es igual de template: su texto, como sin secret.
                    // Lo demás (sellado, bytes no UTF-8) lo decide `secret_concat`.
                    SynValue::Secret(_) => return secret_concat(&left, &syn_text(right.to_string()), loc),
                    _ => {}
                }
            }
            BinOp::Add
        } else {
            op
        };
        // Concatenación de texto: un operando texto coerciona al otro si es un escalar
        // (número, bool). `nothing`, listas, mapas y bytes son error (v0.6.29): pegarlos
        // en silencio daba "xnothing" o un repr que nadie quería.
        if op == BinOp::Add {
            if matches!(left, SynValue::Text(_)) != matches!(right, SynValue::Text(_)) {
                let other = if matches!(left, SynValue::Text(_)) { &right } else { &left };
                // Los tipos que no se suman a un texto (la lista vive en `text_addable`, que usa
                // también la VM); un `secret` sí se suma (sigue abajo).
                if !other.is_secret() && !text_addable(other) {
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
                return secret_concat(&left, &right, loc);
            }
            // F4.6b: el texto de la izquierda se agrega en el lugar si este valor es su único dueño
            // (el intermedio de `a + b + c`, como `s += x` con refcount 1 en CPython); si no, una
            // copia del largo justo. El resultado es el mismo texto en los dos casos.
            if let SynValue::Text(mut l) = left {
                let added = text_add_piece(&mut l, &right);
                debug_assert!(added, "texto + {}: los errores y `secret` ya salieron arriba", right.type_name());
                return Ok(SynValue::Text(l));
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
                let mut v = l.borrow().to_vec();
                v.extend(list_values(&r).iter().cloned());
                return Ok(syn_list(v));
            }
        }
        // Aritmética complex (Batch 4): si alguno es Complex y ambos coercionan a
        // complex64 (Number→real, promoción). Va DESPUÉS de los concats de Text/List/Bytes
        // (un `Complex + Text` sigue siendo concat de texto vía Display) y ANTES del camino
        // de Number (G2: el tower no se perturba). Sólo +,-,*,/,**; otros ops caen al error.
        if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Pow)
            && (matches!(left, SynValue::Complex(_)) || matches!(right, SynValue::Complex(_)))
        {
            if let (Some(a), Some(b)) = (as_complex(&left), as_complex(&right)) {
                let z = match op {
                    BinOp::Add => a + b,
                    BinOp::Sub => a - b,
                    BinOp::Mul => a * b,
                    BinOp::Div => {
                        if b.re == 0.0 && b.im == 0.0 {
                            return Err(err_at("Division by zero", loc));
                        }
                        a / b
                    }
                    // Exponente entero → potencia EXACTA (powi), como Python; si no, powc.
                    BinOp::Pow => crate::math::complex_pow(a, &right, b),
                    _ => unreachable!(),
                };
                return Ok(SynValue::Complex(z));
            }
        }
        // Aritmética vectorizada de arrays (Batch 5): elementwise + broadcasting, y
        // array⊕scalar. `*` es ELEMENTWISE (Hadamard), NO producto matricial (eso es
        // matmul/dot). Va DESPUÉS de los concats de Text/List/Bytes y de la rama Complex,
        // y ANTES del camino Number (G2: el tower no se perturba). `array_binop` devuelve
        // none si ningún operando es array → sigue al camino normal. El chequeo de array va acá y no
        // sólo adentro: si LLVM no inlinea `array_binop` (rustc 1.99), cada suma pagaba la llamada.
        if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Pow | BinOp::FloorDiv | BinOp::Mod)
            && (matches!(left, SynValue::Array(_)) || matches!(right, SynValue::Array(_)))
        {
            if let Some(res) = crate::arrays::array_binop(&left, &right, op.as_str()) {
                return res;
            }
        }
        // Fechas, instantes y duraciones (v0.6.29).
        if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div) {
            if let Some(r) = crate::temporal::binop(&left, op.as_str(), &right) {
                return r;
            }
        }
        // Aritmética — por el camino FALIBLE: mezclar Decimal con Float es un error
        // claro. Int/Big mezclan libremente con ambos.
        if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
            match op {
                BinOp::Add => return a.checked_add(b).map(syn_number).map_err(|e| err_at(e, loc)),
                BinOp::Sub => return a.checked_sub(b).map(syn_number).map_err(|e| err_at(e, loc)),
                BinOp::Mul => return a.checked_mul(b).map(syn_number).map_err(|e| err_at(e, loc)),
                BinOp::Div => {
                    if Number::mixes_decimal_float(a, b) {
                        return Err(err_at(MIX_DECIMAL_FLOAT, loc));
                    }
                    if b.is_zero() {
                        return Err(err_at("Division by zero", loc));
                    }
                    return Ok(syn_number(a.div(b)));
                }
                BinOp::Mod => {
                    return match a.checked_modulo(b) {
                        Err(e) => Err(err_at(e, loc)),
                        Ok(Some(n)) => Ok(syn_number(n)),
                        Ok(None) => Err(err_at("Modulo by zero", loc)),
                    }
                }
                BinOp::FloorDiv => {
                    return match a.checked_floor_div(b) {
                        Err(e) => Err(err_at(e, loc)),
                        Ok(Some(n)) => Ok(syn_number(n)),
                        Ok(None) => Err(err_at("Division by zero", loc)),
                    }
                }
                BinOp::Pow => {
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
        if matches!(op, BinOp::Eq | BinOp::Ne) {
            let eq = crate::tabular::strict_equals(&left, &right).map_err(|_| err_at(MIX_DECIMAL_FLOAT, loc))?;
            return Ok(syn_bool(if op == BinOp::Eq { eq } else { !eq }));
        }
        // Orden
        if matches!(op, BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge) {
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
        let hint = if op == BinOp::Mod && matches!(left, SynValue::Text(_)) {
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
                        None => return Err(self.set_undefined_in(name, env)),
                    }
                }
                #[cfg(feature = "resolver-check")]
                crate::resolve::check::at(&target.location, name, false, env);
                if env_update(env, name, value.clone()).is_err() {
                    return Err(self.set_undefined_in(name, env));
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
                set_leaf_prop(&obj, property_name, value, loc)
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
                set_leaf_index(&obj, &idx, value, &target.location, loc)
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
                None if module_env_of_map(m).is_some_and(|e| e.borrow().bindings.contains_key(property_name)) => {
                    // La pista nombra la forma de lo que está definido: un enum se exporta con
                    // `export enum`, un task con `export task`.
                    let binding = module_env_of_map(m).and_then(|e| e.borrow().bindings.get(property_name).cloned());
                    let how = match &binding {
                        Some(SynValue::Map(b)) if b.borrow().contains_key("__enum") => format!("write `export enum {}` there", property_name),
                        Some(SynValue::Task(_)) => format!("write `export task {}` there", property_name),
                        _ => "write `export let`/`export task`/`export enum`/`export type` there".to_string(),
                    };
                    Err(err_at(
                        format!(
                            "the module has no export '{}' — it is defined inside the module but not exported ({}; an import of that module is not re-exported: `use` its file directly)",
                            property_name, how
                        ),
                        loc,
                    ))
                }
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
                let items = list_values(&l);
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
                self.place_index_step(parent, idx, loc)
            }
            NodeKind::PropertyAccess { property_name, object, .. } => {
                let parent = self.exec_place(object, env)?;
                self.place_prop_step(parent, property_name, loc)
            }
            _ => self.exec(node, env),
        }
    }

    /// Un paso `[idx]` del camino de un `set` (ver `exec_place`), con el lugar de arriba y el
    /// índice ya evaluados: lo mismo para el tree-walker y para la VM (F4.6a).
    pub(crate) fn place_index_step(&mut self, parent: SynValue, idx: SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
        // `set d["STATE"][k]`, `set h.l.STATE[k]`: la VARIABLE del módulo, como `d.STATE`. (Sólo
        // un mapa puede ser un módulo: la clave como texto, sólo entonces.)
        if matches!(parent, SynValue::Map(_)) {
            if let Some(v) = module_var_unique(&parent, &labels::unwrap(&idx).to_string()) {
                return Ok(v);
            }
        }
        match labels::unwrap(&parent) {
            SynValue::List(l) => {
                if let Ok(i) = num_to_i64(labels::unwrap(&idx)) {
                    let mut items = list_values_mut(&l);
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

    /// Un paso `.campo` del camino de un `set` (ver `exec_place`).
    pub(crate) fn place_prop_step(&mut self, parent: SynValue, property_name: &str, loc: &SourceLocation) -> Result<SynValue, Control> {
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
    ///
    /// Es un atajo: lo observable tiene que ser idéntico al camino de referencia, `steps()`
    /// incluido (specs/compute-rendimiento.md §3.6). Si no aplica, no deja rastro (ni pasos ni
    /// asignaciones); si aplica, los pasos quedan como los habría contado la referencia: el nodo
    /// del valor y el identificador de la función, los nodos de P una vez, los argumentos y lo que
    /// `exec_set` evalúa del destino.
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
        /// Los argumentos que siguen a P, sin juntarlos en un `Vec` antes de saber si el atajo
        /// aplica.
        enum Rest<'a> {
            Args(&'a [crate::ast::Arg]),
            One(&'a Node),
        }
        let builtin_is = |this: &Self, name: &str| {
            let _ = this;
            matches!(env_get(env, name), Some(SynValue::Builtin(b)) if b.name == name)
        };
        // `overhead`: los nodos que la referencia evalúa antes de P y el atajo no (la llamada y
        // el identificador de la función, o el `+`).
        let (op, rest, overhead): (Op, Rest, u64) = match &value.kind {
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
                (op, Rest::Args(&arguments[1..]), 2)
            }
            NodeKind::BinaryOp { left, operator, right } if *operator == BinOp::Add && same_place(left, target) => {
                (Op::Concat, Rest::One(right.as_ref()), 1)
            }
            _ => return Ok(None),
        };
        let s0 = self.steps;
        // Leer P. Si no se puede (clave que falta) o no es del tipo, camino normal, y sin rastro:
        // lo que esta lectura contó no lo cuenta la referencia (`set i to i + 1` contaba un paso
        // de más).
        let before = match self.exec(target, env) {
            Ok(v) => v,
            Err(_) => {
                self.steps = s0;
                return Ok(None);
            }
        };
        let place_steps = self.steps.wrapping_sub(s0);
        let fits = match (&before, op) {
            (SynValue::List(_), Op::Append | Op::Concat | Op::Insert) => true,
            (SynValue::Map(_), Op::Merge) => true,
            _ => false,
        };
        if !fits {
            self.steps = s0;
            return Ok(None);
        }
        // Desde acá el atajo corre y los pasos siguen a la referencia, que evalúa el nodo del
        // valor (y el de la función) antes que P.
        self.steps = s0.wrapping_add(overhead).wrapping_add(place_steps);
        let mut args = Vec::new();
        match rest {
            Rest::Args(a) => {
                for x in a {
                    args.push(self.exec(&x.value, env)?);
                }
            }
            Rest::One(n) => args.push(self.exec(n, env)?),
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
            let v = self.exec_binary(before, BinOp::Add, args.pop().unwrap(), &value.location)?;
            return self.exec_set(target, v, env, &target.location, false).map(Some);
        }
        // ¿Sigue ahí el MISMO contenedor? Si los argumentos religaron P, el resultado es el
        // de la P leída. (Esta segunda lectura no existe en la referencia: no cuenta.)
        let before_check = self.steps;
        let same = match self.exec(target, env) {
            Ok(now) => same_container(&now, &before),
            Err(_) => false,
        };
        self.steps = before_check;
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
                        let extra = r.borrow().to_vec();
                        list_values_mut(rc).extend(extra);
                    }
                }
                (SynValue::List(rc), Op::Insert) => {
                    let mut it = args.into_iter();
                    let (i, v) = (it.next().unwrap(), it.next().unwrap());
                    let mut items = list_values_mut(&rc);
                    let j = insert_position(&i, items.len()).map_err(|e| err_at(e, &loc))?;
                    items.insert(j, v);
                }
                (SynValue::Map(rc), Op::Merge) => {
                    for (n, a) in args.iter().enumerate() {
                        if !matches!(a, SynValue::Map(_)) {
                            // El mismo error que el builtin (`b_merge`), con la ubicación de la llamada.
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
        // `with_unique_place` recorre el destino como `exec_set` (mismos pasos). Si la operación
        // falla (posición de `insert` fuera de rango, `merge` con algo que no es mapa), en la
        // referencia el error sale del builtin, antes de asignar: esos pasos no se cuentan.
        let before_set = self.steps;
        let r = self.with_unique_place(target, env, apply);
        if r.is_err() {
            self.steps = before_set;
        }
        r.map(Some)
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
                return self.exec_binary(l, BinOp::Add, r, loc);
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
                        let mut items = list_values_mut(&l);
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
        let mut args = CallArgs::with_capacity(arguments.len() + 1);
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
            // v0.6.46 (E4): como en el `TaskCall`.
            if matches!(name.as_identifier(), Some("declassify" | "private")) {
                return self.call_label_builtin_by_name(func, &mut args, loc);
            }
        }
        if let Err(e) = check_call_arity(&func, &args, loc) {
            return Err(arity_error(e, &func, &args, loc));
        }
        self.call_value_named(func, &mut args, loc)
    }

    /// v0.6.46 (E4): la llamada a `declassify`/`private` por su nombre, con la marca armada sólo
    /// mientras dura el despacho (los argumentos ya están evaluados: una llamada anidada en ellos,
    /// `declassify(g(x), "m")` con `g` alias, no la ve). Frío: no agranda el `TaskCall`.
    #[cold]
    #[inline(never)]
    fn call_label_builtin_by_name(&mut self, func: SynValue, args: &mut CallArgs, loc: &SourceLocation) -> Result<SynValue, Control> {
        if let Err(e) = check_call_arity(&func, args, loc) {
            return Err(arity_error(e, &func, args, loc));
        }
        self.label_call_armed = true;
        let out = self.call_value_named(func, args, loc);
        self.label_call_armed = false;
        out
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
        let mut named: CallArgs = args.into_iter().map(|v| (None, v)).collect();
        self.call_value_named(func, &mut named, loc)
    }

    /// Llamada con args posicionales y/o nombrados (Batch 2). Lleva el tracking de
    /// recursión; el binding lo hace `call_value_named_inner`.
    /// `args` va por referencia y se consume (queda vacía).
    fn call_value_named(
        &mut self,
        func: SynValue,
        args: &mut CallArgs,
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

    #[cold]
    #[inline(never)]
    fn call_trusted_named(&mut self, tool: Rc<TrustedTool>, args: &mut CallArgs, loc: &SourceLocation) -> Result<SynValue, Control> {
        call_trusted(self, &tool, args, loc)
    }

    fn call_value_named_inner(
        &mut self,
        func: SynValue,
        args: &mut CallArgs,
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
                        let mut slots: SmallVec<[Option<SynValue>; 4]> = smallvec![None; names.len()];
                        let mut seen_named = false;
                        let mut pos_idx = 0usize;
                        for (name, value) in args.drain(..) {
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
                                        None => return Err(unknown_parameter(&n, names.iter().copied(), loc)),
                                    }
                                }
                            }
                        }
                        let pos: SmallVec<[SynValue; 4]> = slots
                            .into_iter()
                            .map(|s| s.unwrap_or(SynValue::Nothing))
                            .collect();
                        self.dispatch_builtin(&bt, &pos, loc)
                    }
                    None => {
                        // v0.6.49 (B9): una task de confianza con argumentos nombrados.
                        if let Some(tool) = &bt.trusted {
                            if args.iter().any(|(n, _)| n.is_some()) {
                                return self.call_trusted_named(tool.clone(), args, loc);
                            }
                        }
                        let mut pos: SmallVec<[SynValue; 4]> = SmallVec::with_capacity(args.len());
                        let mut kw: SynMap = SynMap::new();
                        for (name, v) in args.drain(..) {
                            if let Some(n) = name {
                                // Fuera de línea: el camino raro no engorda esta función (F4.4).
                                builtin_named_arg(&bt, &mut kw, n, v, loc)?;
                                continue;
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
                // Ronda 2: dentro de una tool de confianza sólo corre código de la tool. Por acá entra
                // toda llamada a una task (por nombre, desde un builtin, un template o un callback
                // guardado), así que un camino nuevo no reabre el agujero. Sin `--trusted`, una lectura.
                if self.trusted_depth > 0 {
                    self.check_trusted_origin(&task, loc)?;
                }
                let call_env = self.acquire_frame(&task.closure_env, "call");
                let nparams = task.parameters.len();
                if args.iter().all(|(n, _)| n.is_none()) {
                    // Todos posicionales (el caso común): el i-ésimo argumento es el i-ésimo
                    // parámetro, sin repartir en slots (F1.7). Los de más (aridad permisiva, G3)
                    // se sueltan antes de evaluar defaults, igual que en el reparto de abajo.
                    args.truncate(nparams);
                    let mut given = args.drain(..);
                    for param in task.parameters.iter() {
                        let v = match given.next() {
                            Some((_, v)) => v,
                            None => match &param.default {
                                Some(default_node) => self.exec(default_node, &task.closure_env)?,
                                None => SynValue::Nothing,
                            },
                        };
                        env_set_shared(&call_env, &param.name, v);
                    }
                } else {
                    // Repartición: cada slot de param recibe a lo sumo un valor.
                    let mut slots: Vec<Option<SynValue>> = vec![None; nparams];
                    let mut seen_named = false;
                    let mut pos_idx = 0usize;
                    for (name, value) in args.drain(..) {
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
                                match task.parameters.iter().position(|p| *p.name == *n) {
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
                                        return Err(unknown_parameter(&n, task.parameters.iter().map(|p| &*p.name), loc))
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
                        env_set_shared(&call_env, &param.name, v);
                    }
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
                // La VM (F3) corre el cuerpo si lo tiene compilado y el frame se pudo preparar; si
                // no, el tree-walker. Los dos devuelven lo mismo (el oráculo los compara).
                let body = match self.vm_code_for(&task) {
                    Some(code) if code.regframe => self.run_chunk_regframe(code, &call_env, &task.closure_env),
                    Some(code) if code.frame.as_ref().is_some_and(|l| call_env.borrow_mut().bindings.lay_out(l, code.tagged)) => {
                        self.run_chunk(code, &call_env)
                    }
                    _ => self.exec_block(&task.body, &call_env),
                };
                let out = match body {
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
                self.release_frame(call_env);
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

    /// v0.6.42 — la boca de stderr (`eprint`, y `log` bajo `run`). Sin etiquetas, al momento y
    /// sin buffer en cualquier modo: un servidor MCP/LSP por stdio, un filtro de pipes o un
    /// informe `--format json` necesitan su diagnóstico afuera de stdout. Con etiquetas se
    /// retiene hasta el embudo del host (`redact_output_for_host`), igual que stdout.
    fn emit_err_line(&mut self, line: String) {
        if self.labels {
            self.err_output.push(line);
        } else {
            write_stderr_lines(std::slice::from_ref(&line));
        }
    }

    fn b_eprint(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        self.ensure_stdout()?;
        self.stdout_flow_check("eprint", loc)?;
        let s = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
        let s = self.pc_redact(s);
        self.emit_err_line(s);
        Ok(SynValue::Nothing)
    }

    fn b_length(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        match v {
            SynValue::Text(s) => Ok(syn_int(s.chars().count() as i64)),
            SynValue::List(l) => Ok(syn_int(l.borrow().len() as i64)),
            SynValue::Map(m) => Ok(syn_int(m.borrow().len() as i64)),
            SynValue::Bytes(b) => Ok(syn_int(b.len() as i64)),
            // v0.6.29 (DATOS-8): la primera dimensión, como `len` de numpy (`size` es el total).
            // Un array 0-D es un escalar: no tiene largo (numpy da TypeError en `len()`); dar 0
            // lo haría pasar por vacío.
            SynValue::Array(a) if a.ndim() == 0 => Err(err("length: a 0-d array has no length (it is a scalar) — use size(a), which is 1")),
            SynValue::Array(a) => Ok(syn_int(a.shape()[0] as i64)),
            _ => Err(err(format!("Cannot get length of {}", v.type_name()))),
        }
    }

    fn b_to_text(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        // F4.6c: el `Display` directo en un texto (en línea hasta 15 B: sin pedir memoria), sin un
        // `String` en el medio; un texto es él mismo.
        match nth(args, 0)? {
            SynValue::Text(t) => Ok(SynValue::Text(t.clone())),
            // F4.8g: un entero sin la maquinaria de `fmt` (lo mismo que su `Display`).
            SynValue::Number(Number::Int(x)) => {
                let mut t = SynText::new();
                push_int(&mut t, *x);
                Ok(SynValue::Text(t))
            }
            v => {
                use std::fmt::Write;
                let mut t = SynText::new();
                let _ = write!(t, "{}", v);
                Ok(SynValue::Text(t))
            }
        }
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
                    "Cannot parse {} as a decimal (digits with an optional sign, point and exponent — 12.50, 1.5e-3 — up to {} digits)",
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
                let items = list_values(&l);
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
            // Python da `bytes(33)` = 33 ceros; Synsema no adivina qué se quería.
            SynValue::Number(n) => Err(err(format!(
                "Cannot convert number to bytes: bytes({}) does not say how to encode it — for the integer's bytes use int_to_bytes({}, size) (big-endian; int_to_bytes_le for little-endian){}",
                n,
                n,
                match n {
                    Number::Int(b) if (0..=255).contains(b) => format!("; for the single byte {} use bytes([{}])", b, b),
                    _ => String::new(),
                }
            ))),
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
            Err(Control::Error(e)) if e.is_halt() => Err(Control::Error(e)),
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
                // F4.8e: la copia conserva la forma (sin caja si lo es; una vacía toma la del
                // elemento): `set xs to append(xs, n)` arma una lista de enteros sin caja.
                let mut v = l.borrow().clone();
                v.push(item);
                Ok(crate::types::syn_list_of(v))
            }
            _ => Err(err("First argument to append must be a list")),
        }
    }

    /// `insert(xs, i, v)` → lista nueva con `v` en la posición `i` (v0.6.29). `set xs to
    /// insert(xs, i, v)` es en el lugar.
    fn b_insert(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::List(l) => {
                let mut v = l.borrow().to_vec();
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
                let items = list_values(&l);
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
                let mut copy = m.borrow().to_map();
                copy.shift_remove(&nth(args, 1)?.to_string());
                Ok(SynValue::Map(copy.into_ref()))
            }
            other => Err(err(format!("remove() takes a map, got {} — for a list use where(xs, …) or slice", other.type_name()))),
        }
    }

    /// `merge(a, b, …)` → un mapa nuevo; ante la misma clave gana el de más a la derecha.
    fn b_merge(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        if args.is_empty() {
            return Err(err_at("merge() needs at least one map", loc));
        }
        let mut out: SynMap = SynMap::new();
        for (i, a) in args.iter().enumerate() {
            match a {
                SynValue::Map(m) => {
                    for (k, v) in m.borrow().iter() {
                        out.insert(k.clone(), v.clone());
                    }
                }
                other => {
                    return Err(err_at(format!("merge(): argument {} is {}, not a map", i + 1, other.type_name()), loc))
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
                        let mut e = SynMap::new();
                        e.insert("key", syn_text(k.as_str()));
                        e.insert("value", v.clone());
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
                let keys: Vec<SynValue> = m.borrow().keys().map(|k| SynValue::Text(k.text().clone())).collect();
                Ok(syn_list(keys))
            }
            // El resultado de `group_by` (una lista de `{key, items}` desde v0.6.29) es el
            // caso típico: decir cómo se lee.
            SynValue::List(l)
                if list_values(&l).first().is_some_and(|g| {
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
                let items: Vec<SynValue> = list_values(&l)
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let mut m = SynMap::new();
                        m.insert("index", syn_int(i as i64));
                        m.insert("item", v.clone());
                        syn_map(m)
                    })
                    .collect();
                Ok(syn_list(items))
            }
            // v0.6.46 (C1): un array por su primer eje, como `length(a)` y `a[i]` (y `apply`, que ya
            // lo acepta): cada `item` es un número (1-D) o la fila (un array de una dimensión menos).
            SynValue::Array(a) if a.ndim() == 0 => {
                Err(err("enumerate() of a 0-d array: it is a scalar and has no rows — use to_list(a) or the value itself"))
            }
            SynValue::Array(a) => {
                let items = (0..a.shape()[0])
                    .map(|i| {
                        let mut m = SynMap::new();
                        m.insert("index", syn_int(i as i64));
                        m.insert("item", crate::arrays::index_row(&a, i as i64)?);
                        Ok(syn_map(m))
                    })
                    .collect::<Result<Vec<_>, Control>>()?;
                Ok(syn_list(items))
            }
            other => Err(err(format!("enumerate() requires a list or an array, got {}", other.type_name()))),
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
                for e in list_values(&l).iter() {
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
                let items = list_values(&l);
                // F4.8g: primero los errores (en orden: el primero que falla) y el largo de los
                // textos; después un solo `String`, cada parte escrita directo (lo de su `Display`).
                let mut cap = sep.len() * items.len().saturating_sub(1);
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
                    if let SynValue::Text(t) = v {
                        cap += t.as_str().len();
                    }
                }
                let mut out = String::with_capacity(cap);
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(&sep);
                    }
                    match v {
                        SynValue::Text(t) => out.push_str(t.as_str()),
                        SynValue::Number(Number::Int(x)) => out.push_str(int_digits(*x, &mut [0u8; 20])),
                        other => {
                            use std::fmt::Write;
                            let _ = write!(out, "{}", other);
                        }
                    }
                }
                Ok(syn_text(out))
            }
            _ => Err(err("First argument to join must be a list")),
        }
    }

    fn b_range(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let (lo, hi, step) = range_spec(args)?;
        // F4.8e: una lista de enteros sin caja.
        if step == 1 {
            return Ok(crate::types::syn_list_of(SynList::from_ints((lo..hi).collect())));
        }
        Ok(crate::types::syn_list_of(SynList::from_ints(RangeIter::new(lo, hi, step).collect())))
    }

    /// `each x in range(…)` con `range` el builtin de verdad (se mira sin evaluar nada): evalúa el
    /// nombre y los argumentos como la llamada normal —mismos pasos, mismos errores, la misma
    /// validación que `b_range`— y devuelve el iterador, sin armar la lista (F1.11:
    /// `range(0, 900000)` pedía ~36 MB). `None` si la colección no tiene esa forma; entonces no
    /// evaluó nada y sigue el camino de siempre.
    fn each_over_range(
        &mut self,
        collection: &Node,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<RangeIter>, Control> {
        let NodeKind::TaskCall { name, arguments } = &collection.kind else { return Ok(None) };
        if name.as_identifier() != Some("range")
            || arguments.is_empty()
            || arguments.len() > 3
            || arguments.iter().any(|a| a.name.is_some())
        {
            return Ok(None);
        }
        // Tiene que ser EL builtin (un task del usuario puede llamarse igual).
        if !matches!(env_get(env, "range"), Some(SynValue::Builtin(b)) if b.name == "range") {
            return Ok(None);
        }
        // Lo que la referencia evalúa y cuenta: el nodo de la llamada, el nombre y los argumentos.
        // (La aridad no puede fallar: 1 a 3 posicionales es lo que `range` acepta.)
        self.steps = self.steps.wrapping_add(1);
        self.exec(name, env)?;
        let mut vals: SmallVec<[SynValue; 3]> = SmallVec::new();
        for a in arguments {
            vals.push(self.exec(&a.value, env)?);
        }
        // Una llamada a builtin cuenta un nivel de recursión (`call_value_named`).
        if self.recursion_depth + 1 > MAX_RECURSION {
            return Err(err("maximum recursion depth exceeded"));
        }
        let (lo, hi, step) = range_spec(&vals)?;
        Ok(Some(RangeIter::new(lo, hi, step)))
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
        let by_name = std::mem::take(&mut self.label_call_armed);
        if !self.labels {
            return Err(err_labels("private: labels are off; run with --labels or serve --attested", loc));
        }
        if !by_name {
            return Err(not_called_by_name("private", "private(v, \"owner\")", loc));
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
        let by_name = std::mem::take(&mut self.label_call_armed);
        if self.labels && !by_name {
            return Err(not_called_by_name("declassify", "declassify(v, \"why\")", loc));
        }
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
        // v0.6.46 (E3): publicar es una capability. Se chequea lo que la llamada quita, y si no
        // está concedido es `label_violation` fatal: que pase o no depende de la etiqueta real
        // (de qué valor se eligió), así que no se puede atrapar (un bit por corrida, el límite de
        // `labels.md`) y el mensaje nombra el conjunto declarado, nunca el real.
        if let Some(hook) = &self.declassify_cap_hook {
            let removed = labels::difference(&from, &to);
            if !removed.is_empty() && !hook(&removed[..], &self.safe_label(&from)) {
                return Err(declassify_not_granted(&self.safe_label(&from), self.in_trusted_scope(), self.current_agent(), loc));
            }
        }
        // T5 (ronda 7) — el `from` que sale al log NO es la etiqueta de ESTE valor. Varía con
        // cuál se seleccionó, igual que la redacción: `declassify(xs[idx_privado], …)` daba
        // `from [app,p0]` o `from [app,p1]` según el índice, o sea el rastro de auditoría
        // publicaba el dato que el `declassify` estaba documentando. Sale el conjunto DECLARADO,
        // constante. El `to` sí es de la etiqueta real: es el literal escrito en ESTE sitio, que
        // no depende del valor. La revisión de verdad es `code check --json`, que es estática.
        // v0.6.46 (E6.8): dentro de una rama privada la línea no sale. Cuántas líneas hubo decía
        // qué rama se tomó o cuántas vueltas dio un bucle privado, como las entradas de audit
        // (ronda 4, M5). La entrada queda en el registro interno, marcada.
        let under_private_pc = self.pc_is_private();
        if let (Some(hook), false) = (&self.log_hook, under_private_pc) {
            // v0.6.49 (§C): sin principales declarados (los marcó el host) decía `from […]`.
            let declared = self.safe_label(&from);
            let from_text = if declared == "…" { "principals the program does not declare".to_string() } else { format!("[{}]", declared) };
            hook(&format!(
                "[INF] declassify: {} (from {} to [{}]) at {}:{}",
                reason,
                from_text,
                label_display_raw(&to),
                loc.file,
                loc.line
            ));
        }
        self.declassify_log.push(DeclassifyEntry {
            reason,
            from: from.clone(),
            to: to.clone(),
            loc: loc.clone(),
            under_private_pc,
        });
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
            l.iter().map(|p| labels::mark(SynValue::Text(SynText::from(&**p)), meta.clone())).collect(),
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
                let items = list_values(&l);
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
            Some(SynValue::Map(m)) => Some(m.borrow().to_map()),
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
        // v0.6.46: con etiquetas no se vacía (como `emit_line`, que no transmite): `redact_output_for_host`
        // tiene que poder retener todo, y un `flush` en una rama privada diría cuántas líneas salieron.
        if self.live_output && !self.labels {
            self.drain_output();
        }
        Ok(SynValue::Nothing)
    }
    /// `read_line(prompt?)`: lee una línea de stdin (CLI). Si hay prompt, lo imprime sin
    /// newline antes de leer. Devuelve el texto sin el `\n`/`\r\n` final; `nothing` en EOF.
    /// Lee stdin crudo → funciona con TTY y con entrada redirigida/pipe (a diferencia de
    /// `ask`, que es un backend de decisión humana).
    fn b_read_line(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        use std::io::Write;
        // Drena la salida pendiente (respuesta del turno previo) ANTES del prompt, para
        // que un REPL sea interactivo de verdad (DE-018) sin requerir flush() explícito.
        // Sólo en `run` interactivo; bajo conform/test/serve no se drena (DE-019). La
        // LECTURA de stdin se hace igual en cualquier modo. v0.6.46: con etiquetas tampoco (ver
        // `b_flush`): vaciar dentro de una rama privada diría cuántas líneas salieron antes.
        if self.live_output && !self.labels {
            self.drain_output();
        }
        if let Some(p) = args.first() {
            if !matches!(p, SynValue::Nothing) {
                // El prompt ES salida: bajo un techo sin `stdout` no debe escaparse por acá
                // (print/show/log ya lo chequean; read_line era el único hueco).
                self.ensure_stdout()?;
                // v0.6.46: y es un sumidero público como `print`. `read_line` es puro para las
                // etiquetas, así que el despacho genérico ya empujó al PC la etiqueta del prompt:
                // este chequeo cubre un prompt privado y uno dentro de una rama privada. Leer sin
                // prompt en una rama privada sigue permitido.
                // v0.6.49 (B10): si el PC privado lo puso sólo esta llamada (el despacho empuja la
                // etiqueta del prompt), lo privado es el prompt, no una rama: decirlo así.
                if self.labels && !self.pc_is_empty() && !self.outer_pc_private() && self.cut_by_agent().is_none() {
                    return Err(err_labels(
                        format!(
                            "label_violation: the read_line prompt is private (to {}) and the prompt goes to stdout, which is public. Ask with a public prompt, or declassify(<the prompt>, \"<why it may be published>\")",
                            self.safe_label(&self.pc_label())
                        ),
                        loc,
                    ));
                }
                self.stdout_flow_check("read_line prompt", loc)?;
                if self.labels {
                    // v0.6.47 (T1): con etiquetas el prompt se junta como `print`: si saliera en
                    // vivo, cuántos prompts se vieron antes de un corte lo elegiría el dato. Va por
                    // `emit_line` (el eco de un agente lleva su prefijo y también se retiene).
                    self.emit_line(raw_str(p).to_string());
                } else if !self.live_output && crate::sealed::active() {
                    // v0.6.46 (E6): con auditor nada sale antes del recibo; el prompt se junta como
                    // cualquier salida.
                    self.output.push(raw_str(p).to_string());
                } else {
                    print!("{}", raw_str(p));
                    let _ = std::io::stdout().flush();
                }
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
            SynValue::List(l) => Ok(l.borrow().to_vec()),
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
    /// F4.8b: la función y la lista, sin copiarla: su `Rc`, que se recorre por índice (la foto de la
    /// lista al llamar: mientras lo tenemos, una escritura del cuerpo de la función copia, como con
    /// el iterador de un `each`). Mismos errores, en el mismo orden.
    fn dual_fn_rc(&self, args: &[SynValue], op: &str) -> Result<(SynValue, ListRef), Control> {
        let (f, l) = dual_fn_pick(args, op)?;
        match l {
            SynValue::List(l) => Ok((f, l.clone())),
            other => Err(err(format!("{} expects a list, got {}", op, other.type_name()))),
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
        let (func, l) = self.dual_fn_rc(args, "apply")?;
        let n = l.borrow().len();
        self.with_lambda(&func, |it, lc| {
            // F4.8e: los resultados en una lista que toma la forma de lo que llega (sin caja si son
            // todos enteros o todos floats).
            let mut out = SynList::with_capacity(n);
            for i in 0..n {
                out.push(lc.item(it, &l, i, loc)?);
            }
            Ok(crate::types::syn_list_of(out))
        })
    }

    /// `call(task, args_map)` — despacha `task` con args nombrados tomados del map
    /// (clave→param). `call(task, nothing)` → sin args. Delega en `call_value_named`
    /// (binding + defaults + give-unwrap ya existentes). NO toca `apply`.
    fn b_call(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        let mut named: CallArgs = match nth(args, 1)? {
            SynValue::Map(m) => {
                m.borrow().iter().map(|(k, v)| (Some(k.to_string()), v.clone())).collect()
            }
            SynValue::Nothing => CallArgs::new(),
            other => {
                return Err(err_at(
                    format!("call expects a map of named args, got {}", other.type_name()),
                    loc,
                ))
            }
        };
        // v0.6.46 (F1): la frontera valida los tipos declarados.
        if let SynValue::Task(t) = &func {
            if t.parameters.iter().any(|p| p.ty.is_some()) {
                check_typed_args("call", t, &named, loc)?;
            }
        }
        self.call_value_named(func, &mut named, loc)
    }

    /// `call_tool(task, args_map)` — despacha `task` COMO TOOL: igual que `call`, pero
    /// corre su cuerpo con LEAST-PRIVILEGE. El `CapabilitySet` queda restringido a las
    /// caps que la tool DECLARÓ (su `require` por-tool) ∩ las que el agente ya tenía,
    /// SIN heredar el resto → el `require` por-tool pasa a estar ENFORCED por el
    /// lenguaje (no es metadata). Restaura SIEMPRE (también si la tool falla). Sin
    /// `tool_scope_hook` cableado → corre con las caps ambientes (no-op).
    fn b_call_tool(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        let mut named: CallArgs = match nth(args, 1)? {
            SynValue::Map(m) => {
                m.borrow().iter().map(|(k, v)| (Some(k.to_string()), v.clone())).collect()
            }
            SynValue::Nothing => CallArgs::new(),
            other => {
                return Err(err_at(
                    format!("call_tool expects a map of named args, got {}", other.type_name()),
                    loc,
                ))
            }
        };
        // v0.6.46 (F1): la frontera valida los tipos declarados, antes de entrar al scope.
        if let SynValue::Task(t) = &func {
            if t.parameters.iter().any(|p| p.ty.is_some()) {
                check_typed_args("call_tool", t, &named, loc)?;
            }
        }
        if let SynValue::Builtin(b) = &func {
            if let Some(t) = b.trusted.as_ref().map(|tool| &tool.task) {
                if t.parameters.iter().any(|p| p.ty.is_some()) {
                    check_typed_args("call_tool", t, &named, loc)?;
                }
            }
        }
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
        let result = self.call_value_named(func, &mut named, loc);
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
    ///
    /// v0.6.46 (E5): consciente de etiquetas. Con algo privado en los argumentos (y el techo que lo
    /// permite), el mapa sale etiquetado ENTERO: elegir una herramienta con `r.name` exige un
    /// `declassify`, que tiene su propio techo. Es la propiedad de CaMeL.
    fn b_llm_step(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let lab = {
            let refs: Vec<&SynValue> = args.iter().collect();
            self.llm_data_gate("llm_step", false, &refs, loc)?
        };
        self.check_llm_cap()?; // GATE por `llm` (mismo hook que reason/decide/…)
        let stripped: Vec<SynValue>;
        let args = if self.labels && args.iter().any(labels::has_label_deep) {
            stripped = args.iter().map(labels::strip_deep).collect();
            &stripped[..]
        } else {
            args
        };
        let prompt = raw_str(nth(args, 0)?);
        let catalog = parse_catalog(args.get(1))?;
        let context = match args.get(2) {
            Some(SynValue::Text(s)) => s.to_string(),
            Some(SynValue::Nothing) | None => String::new(),
            Some(v) => v.to_string(),
        };
        let result = match &self.llm_step_callback {
            Some(cb) => {
                let r = cb(&prompt, &catalog, &context);
                let out = match &r {
                    StepResult::Final { text, .. } => text.clone(),
                    StepResult::Tool { name, args, .. } => {
                        // La misma vista `(clave, texto)` de antes de F1: el registro no cambia.
                        let view: Vec<(&str, String)> = args.iter().map(|(k, v)| (k.as_str(), raw_str(v))).collect();
                        format!("{}{:?}", name, view)
                    }
                };
                self.record_llm("llm_step", &format!("{}\n{}", prompt, context), &out, !lab.is_empty());
                r
            }
            // Sin provider cableado (camino `run` normal): placeholder seguro. El
            // programa decide qué hacer; no inventa tool-calls.
            None => {
                note_llm_offline();
                StepResult::Final { text: "[no llm provider]".to_string(), tokens: 0 }
            }
        };
        Ok(Self::llm_out(&lab, step_result_to_synvalue(result)))
    }

    /// `llm_stream(prompt, context, on_chunk)` — genera con el provider configurado
    /// invocando la task/lambda `on_chunk` con cada fragmento de texto a medida que se
    /// produce, y devuelve el texto completo (F2). GATEADO por la capability `llm`
    /// (mismo hook que reason/llm_step). Si `on_chunk` falla (p.ej. el `send` de un
    /// cliente SSE desconectado → CLIENT_GONE), la generación se CORTA (el sink devuelve
    /// `false` al provider) y el error PROPAGA — el stream se desenrolla exactamente
    /// como cualquier `send` fallido de serve. Sin provider cableado: placeholder
    /// `"[no llm provider]"` SIN invocar `on_chunk` (los placeholders no son respuestas).
    ///
    /// v0.6.46 (E5): consciente de etiquetas, como `llm_step`: cada fragmento que recibe `on_chunk`
    /// y el texto completo llevan la etiqueta de lo que se le dio.
    fn b_llm_stream(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let lab = {
            let refs: Vec<&SynValue> = args.iter().collect();
            self.llm_data_gate("llm_stream", false, &refs, loc)?
        };
        self.check_llm_cap()?; // GATE por `llm` (mismo hook que reason/decide/…)
        let stripped: Vec<SynValue>;
        let args = if self.labels && args.iter().any(labels::has_label_deep) {
            stripped = args.iter().map(labels::strip_deep).collect();
            &stripped[..]
        } else {
            args
        };
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
                return Ok(Self::llm_out(&lab, syn_text("[no llm provider]")));
            }
        };
        // El sink invoca la task/lambda del usuario por chunk. Un error ahí no puede
        // atravesar el provider (la firma del sink es `-> bool`), así que se guarda acá
        // y el sink devuelve `false` → el provider corta; al volver, el error propaga.
        let mut chunk_err: Option<Control> = None;
        // Ronda 1 (A3): con una respuesta privada el callback corre bajo su PC, como el cuerpo de un
        // `each` sobre una lista privada: CUÁNTOS fragmentos hubo depende de la respuesta, y un
        // efecto público por fragmento (`print("tick")`) deletreaba su largo.
        let under = self.labels && !lab.is_empty();
        if under {
            self.pc_push(&lab);
        }
        let full = cb(&prompt, &context, &mut |chunk: &str| {
            match self.call_value(on_chunk.clone(), vec![Self::llm_out(&lab, syn_text(chunk))], loc) {
                Ok(_) => true,
                Err(e) => {
                    chunk_err = Some(e);
                    false
                }
            }
        });
        if under {
            self.pc_pop();
        }
        if let Some(e) = chunk_err {
            return Err(e);
        }
        self.record_llm("llm_stream", &format!("{}\n{}", prompt, context), &full, !lab.is_empty());
        Ok(Self::llm_out(&lab, syn_text(full)))
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
        let (pred, l) = self.dual_fn_rc(args, "where")?;
        self.with_lambda(&pred, |it, lc| {
            let mut out = SynList::new();
            for i in 0..l.borrow().len() {
                let (item, r) = lc.item_keep(it, &l, i, loc)?;
                if r.is_truthy() {
                    out.push(item);
                }
            }
            Ok(crate::types::syn_list_of(out))
        })
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
        let (func, l) = self.dual_fn_rc(args, "transform")?;
        let pred = args.get(2).cloned();
        let n = l.borrow().len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let item = list_values(&l)[i].clone();
            let should = match &pred {
                Some(p) => self.call_fast(p, &mut [item.clone()], loc)?.is_truthy(),
                None => true,
            };
            if should {
                out.push(self.call_fast(&func, &mut [item], loc)?);
            } else {
                out.push(item);
            }
        }
        Ok(syn_list(out))
    }

    fn b_reduce(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        // Dual-order sólo en las posiciones 0-1; `init` (aunque sea callable) queda al
        // final y NO participa de la detección.
        let (func, l) = self.dual_fn_rc(args, "reduce")?;
        let mut acc = args.get(2).cloned().unwrap_or_else(|| syn_int(0));
        self.with_lambda(&func, |it, lc| {
            for i in 0..l.borrow().len() {
                acc = lc.acc_item(it, std::mem::replace(&mut acc, SynValue::Nothing), &l, i, loc)?;
            }
            Ok(acc)
        })
    }

    fn b_sort_by(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (key_func, l) = self.dual_fn_rc(args, "sort_by")?;
        let desc = desc_flag(args.get(2), "sort_by")?;
        let n = l.borrow().len();
        let mut keyed: Vec<(SynValue, SynValue)> = Vec::with_capacity(n);
        self.with_lambda(&key_func, |me, lc| {
            for i in 0..n {
                let (it, k) = lc.item_keep(me, &l, i, loc)?;
                keyed.push((k, it));
            }
            Ok::<(), Control>(())
        })?;
        let keys: Vec<SynValue> = keyed.iter().map(|(k, _)| k.clone()).collect();
        check_orderable(&keys, "sort_by")?;
        sort_checked(&mut keyed, |(k, _)| k, desc, "sort_by")?;
        Ok(syn_list(keyed.into_iter().map(|(_, v)| v).collect()))
    }

    /// `sort(xs)` / `sort(xs, desc = true)`: orden total y estable de los valores mismos.
    fn b_sort(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        // F4.8e: una lista sin caja se ordena sin pasar a valores, con el mismo orden: enteros
        // iguales no se distinguen; floats en orden estable (−0.0 y 0.0 son iguales) con los NaN al
        // final en los dos sentidos (`order_for`).
        if let SynValue::List(l) = nth(args, 0)? {
            let desc = desc_flag(args.get(1), "sort")?;
            let b = l.borrow();
            if let Some(v) = b.as_ints() {
                let mut v = v.to_vec();
                v.sort_unstable();
                if desc {
                    v.reverse();
                }
                return Ok(crate::types::syn_list_of(SynList::from_ints(v)));
            }
            if let Some(v) = b.as_floats() {
                let mut v = v.to_vec();
                v.sort_by(|x, y| match (x.is_nan(), y.is_nan()) {
                    (false, false) => {
                        let c = x.partial_cmp(y).unwrap_or(Ordering::Equal);
                        if desc {
                            c.reverse()
                        } else {
                            c
                        }
                    }
                    (a, b) => a.cmp(&b),
                });
                return Ok(crate::types::syn_list_of(SynList::from_floats(v)));
            }
        }
        let mut items = self.list_arg(nth(args, 0)?, "sort")?;
        let desc = desc_flag(args.get(1), "sort")?;
        check_orderable(&items, "sort")?;
        sort_checked(&mut items, |v| v, desc, "sort")?;
        Ok(syn_list(items))
    }

    fn b_find_first(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, l) = self.dual_fn_rc(args, "find_first")?;
        self.with_lambda(&pred, |it, lc| {
            for i in 0..l.borrow().len() {
                let (item, r) = lc.item_keep(it, &l, i, loc)?;
                if r.is_truthy() {
                    return Ok(item);
                }
            }
            Ok(SynValue::Nothing)
        })
    }

    fn b_every(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, l) = self.dual_fn_rc(args, "every")?;
        self.with_lambda(&pred, |it, lc| {
            for i in 0..l.borrow().len() {
                if !lc.item(it, &l, i, loc)?.is_truthy() {
                    return Ok(syn_bool(false));
                }
            }
            Ok(syn_bool(true))
        })
    }

    fn b_some(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, l) = self.dual_fn_rc(args, "some")?;
        self.with_lambda(&pred, |it, lc| {
            for i in 0..l.borrow().len() {
                if lc.item(it, &l, i, loc)?.is_truthy() {
                    return Ok(syn_bool(true));
                }
            }
            Ok(syn_bool(false))
        })
    }

    fn b_count_where(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let (pred, l) = self.dual_fn_rc(args, "count_where")?;
        self.with_lambda(&pred, |it, lc| {
            let mut count: i64 = 0;
            for i in 0..l.borrow().len() {
                if lc.item(it, &l, i, loc)?.is_truthy() {
                    count += 1;
                }
            }
            Ok(syn_int(count))
        })
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
                SynValue::List(l) => out.extend(list_values(&l).iter().cloned()),
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
        // Sin copiar la lista (como `in` y `contains`): un acierto temprano es O(1).
        let SynValue::List(list) = nth(args, 0)? else {
            return Err(err(format!("index_of expects a list, got {}", nth(args, 0)?.type_name())));
        };
        let needle = nth(args, 1)?;
        if is_callable(needle) {
            // El predicado corre código: no se retiene el préstamo mientras corre. Este `Rc` es
            // una foto (una escritura del predicado a la lista copia, por copy-on-write), así
            // que el largo no cambia; se relee igual por si acaso.
            let mut i = 0;
            loop {
                let item = match list.borrow().get(i) {
                    Some(x) => x.clone(),
                    None => break,
                };
                if self.call_value(needle.clone(), vec![item], loc)?.is_truthy() {
                    return Ok(syn_int(i as i64));
                }
                i += 1;
            }
        } else {
            for (i, item) in list_values(&list).iter().enumerate() {
                if crate::tabular::strict_equals(item, needle).map_err(|_| err(format!("index_of: {}", MIX_DECIMAL_FLOAT)))? {
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

/// `(desde, hasta, paso)` de `range(…)`: la validación que comparten `b_range` y el `each`
/// perezoso, así los dos caminos dan los mismos errores.
fn range_spec(args: &[SynValue]) -> Result<(i64, i64, i64), Control> {
    match args.len() {
        1 => Ok((0, num_to_i64(nth(args, 0)?)?, 1)),
        2 => Ok((num_to_i64(nth(args, 0)?)?, num_to_i64(nth(args, 1)?)?, 1)),
        3 => {
            let lo = num_to_i64(nth(args, 0)?)?;
            let hi = num_to_i64(nth(args, 1)?)?;
            let step = num_to_i64(nth(args, 2)?)?;
            if step == 0 {
                return Err(err("range() arg 3 must not be zero"));
            }
            Ok((lo, hi, step))
        }
        _ => Err(err("range() takes 1-3 arguments")),
    }
}

/// Los enteros de un `range`, sin armar la lista. Avanza con `checked_add`: si el paso pasa de
/// `i64::MAX` (o de `i64::MIN`), el rango terminó, como en Python. Antes `i += step` daba la
/// vuelta en release y el bucle no terminaba (specs/compute-rendimiento.md §3.10).
pub(crate) struct RangeIter {
    next: Option<i64>,
    hi: i64,
    step: i64,
}

impl RangeIter {
    fn new(lo: i64, hi: i64, step: i64) -> Self {
        RangeIter { next: Some(lo), hi, step }
    }
}

impl Iterator for RangeIter {
    type Item = i64;
    fn next(&mut self) -> Option<i64> {
        let i = self.next?;
        let inside = if self.step > 0 { i < self.hi } else { i > self.hi };
        if !inside {
            self.next = None;
            return None;
        }
        self.next = i.checked_add(self.step);
        Some(i)
    }
}

/// De dónde salen los elementos de un `each`.
enum EachItems {
    /// Ya armados (claves de un mapa, caracteres, bytes; o la copia de la lista en modo referencia).
    Owned(std::vec::IntoIter<SynValue>),
    /// Una lista recorrida por índice, sin copiarla (F1.11).
    List(ListRef, usize),
    /// `range(…)` sin armar la lista (F1.11).
    Range(RangeIter),
}

impl Interpreter {
    /// Qué recorre un `each` sobre un valor ya evaluado (el tree-walker y la VM).
    fn each_items_of(&self, coll: &SynValue, loc: &SourceLocation) -> Result<EachItems, Control> {
        // v0.6.29: un mapa se recorre por sus claves y un texto por sus caracteres
        // (como Python); bytes, por sus valores 0..=255.
        Ok(match coll {
            // Atajo (F1.11): la lista se recorre por índice en vez de copiarla
            // entera. La foto la sigue dando la semántica de valor: si el cuerpo la
            // modifica, el copy-on-write ve este `Rc` compartido y copia (una vez).
            SynValue::List(l) if self.shortcuts => EachItems::List(l.clone(), 0),
            SynValue::List(l) => EachItems::Owned(l.borrow().to_vec().into_iter()),
            SynValue::Map(m) => EachItems::Owned(
                m.borrow().keys().map(|k| syn_text(k.as_str())).collect::<Vec<_>>().into_iter(),
            ),
            SynValue::Text(t) => {
                EachItems::Owned(t.chars().map(|c| syn_text(c.to_string())).collect::<Vec<_>>().into_iter())
            }
            SynValue::Bytes(b) => {
                EachItems::Owned(b.iter().map(|x| syn_int(*x as i64)).collect::<Vec<_>>().into_iter())
            }
            _ => {
                return Err(err_at(
                    format!(
                        "Cannot iterate over {} — each walks a list, the keys of a map, the characters of a text or the values of bytes",
                        coll.type_name()
                    ),
                    loc,
                ))
            }
        })
    }
}

impl EachItems {
    fn next_item(&mut self) -> Option<SynValue> {
        match self {
            EachItems::Owned(it) => it.next(),
            EachItems::List(l, i) => {
                let item = l.borrow().get(*i);
                *i += 1;
                item
            }
            EachItems::Range(r) => r.next().map(syn_int),
        }
    }
}

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
    if bad.is_none() {
        // v0.6.46 (E4): y que `declassify`/`private` no se lean como valor.
        check_label_builtin_values(program)?;
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

/// v0.6.46 (E4): `declassify`/`private` llamados como valor (un alias, un contenedor, un parámetro,
/// un valor devuelto) con las etiquetas encendidas.
#[cold]
#[inline(never)]
fn not_called_by_name(name: &str, form: &str, loc: &SourceLocation) -> Control {
    err_labels(
        format!(
            "{} can only be called by its name: `{}`; passing it as a value hides the call from the review (`synsema code check` lists every call by name)",
            name, form
        ),
        loc,
    )
}

/// v0.6.46 (E4, capa 2): `declassify`/`private` leídos como VALOR (no como el callee de una
/// llamada) en un programa que no liga ese nombre en ningún lado son error de carga: es un alias
/// del builtin (`let d be declassify`, `[declassify][0]`, `f(declassify, t)`). Si el programa liga
/// el nombre (`let private be 5`, un parámetro, una variable de `each`, un patrón), al cargar no se
/// sabe a qué se refiere cada lectura sin un análisis de alcance, y decide la marca en ejecución.
fn check_label_builtin_values(program: &Program) -> Result<(), Control> {
    const NAMES: [&str; 2] = ["declassify", "private"];
    let mut bound = [false; 2];
    let mut bind = |n: &str| {
        if let Some(i) = NAMES.iter().position(|x| *x == n) {
            bound[i] = true;
        }
    };
    let mut callees: std::collections::HashSet<*const Node> = std::collections::HashSet::new();
    let mut patterns: Vec<&Node> = Vec::new();
    for stmt in &program.statements {
        crate::ast_api::walk(stmt, &mut |n| match &n.kind {
            NodeKind::TaskCall { name, .. } => {
                callees.insert(&**name as *const Node);
            }
            NodeKind::LetBinding { name, .. } => bind(name),
            NodeKind::TaskDefinition { parameters, .. } => parameters.iter().for_each(|p| bind(&p.name)),
            NodeKind::LambdaExpression { parameters, .. } => parameters.iter().for_each(|p| bind(p)),
            NodeKind::EachStatement { variable, .. } => bind(variable),
            NodeKind::ObserveStatement { variable, .. } => bind(variable),
            NodeKind::WaitForStatement { variable: Some(v), .. } => bind(v),
            NodeKind::TryRecover { error_variable, .. } => bind(error_variable),
            NodeKind::RouteDefinition { param_names, .. } => param_names.iter().for_each(|p| bind(p)),
            NodeKind::UseImport { alias, .. } => bind(alias),
            NodeKind::ListPattern { rest: Some(Some(r)), .. } => bind(r),
            NodeKind::MapPattern { fields } => fields.iter().filter(|(_, sub)| sub.is_none()).for_each(|(k, _)| bind(k)),
            NodeKind::MatchArm { pattern, .. } => patterns.push(pattern),
            _ => {}
        });
    }
    // Un identificador en un patrón liga (`is private`), no lee.
    let mut in_pattern: std::collections::HashSet<*const Node> = std::collections::HashSet::new();
    for p in patterns {
        crate::ast_api::walk(p, &mut |n| {
            if let NodeKind::Identifier { name } = &n.kind {
                bind(name);
                in_pattern.insert(n as *const Node);
            }
        });
    }
    if bound.iter().all(|b| *b) {
        return Ok(());
    }
    let mut bad: Option<(&str, SourceLocation)> = None;
    for stmt in &program.statements {
        crate::ast_api::walk(stmt, &mut |n| {
            if bad.is_some() {
                return;
            }
            let NodeKind::Identifier { name } = &n.kind else { return };
            let Some(i) = NAMES.iter().position(|x| *x == name.as_str()) else { return };
            let p = n as *const Node;
            if !bound[i] && !callees.contains(&p) && !in_pattern.contains(&p) {
                bad = Some((NAMES[i], n.location.clone()));
            }
        });
    }
    match bad {
        Some((name, loc)) => Err(err_labels(
            format!(
                "'{}' is read as a value here (an alias, a list or map entry, an argument): it can only be called by its name, `{}(…)`, so that every call is in the review (`synsema code check`)",
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
            let items = list_values(&l);
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
fn fn_and_array(args: &[SynValue]) -> Option<(SynValue, crate::types::Obj<ndarray::ArrayD<f64>>)> {
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
/// `{name, describe|description, params, optional}`. Items mal formados (sin `name` texto) se
/// saltan (robustez ante data del programa; no se inventa una tool sin nombre). v0.6.46 (F1): un
/// parámetro puede ser `"nombre: tipo"`; un tipo desconocido es un error (no un parámetro sin tipo).
fn parse_catalog(arg: Option<&SynValue>) -> Result<Vec<StepCatalogEntry>, Control> {
    let list = match arg {
        Some(SynValue::List(l)) => l,
        _ => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for item in list_values(&list).iter() {
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
        let mut params = Vec::new();
        let mut types = Vec::new();
        if let Some(SynValue::List(pl)) = m.get("params") {
            for p in list_values(&pl).iter() {
                let SynValue::Text(s) = p else { continue };
                match s.split_once(':') {
                    Some((n, t)) => match crate::ast::ParamType::parse(t.trim()) {
                        Some(ty) => {
                            params.push(n.trim().to_string());
                            types.push(Some(ty));
                        }
                        None => return Err(catalog_type_error(&name, s)),
                    },
                    None => {
                        params.push(s.to_string());
                        types.push(None);
                    }
                }
            }
        }
        let optional = match m.get("optional") {
            Some(SynValue::List(ol)) => list_values(&ol)
                .iter()
                .filter_map(|o| match o {
                    SynValue::Text(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        out.push(StepCatalogEntry { name, description, params, types, optional });
    }
    Ok(out)
}

#[cold]
#[inline(never)]
fn catalog_type_error(tool: &str, param: &str) -> Control {
    err(format!(
        "llm_step: tool '{}' declares the parameter '{}' with an unknown type: the types are {}",
        tool,
        param,
        crate::ast::ParamType::ALL
    ))
}

/// v0.6.46 (F1): `call`/`call_tool` reciben los argumentos como un mapa de datos (de un modelo, de un
/// JSON): ahí se validan los tipos declarados, estrictos y sin conversiones. Sólo corre si la task
/// declara alguno; una llamada normal no pasa por acá. Un parámetro tipado sin default que no llegó
/// es un error (`call` liga a `nothing` lo que falta: el esquema dice que es obligatorio).
#[cold]
#[inline(never)]
fn check_typed_args(op: &str, t: &SynTaskValue, named: &CallArgs, loc: &SourceLocation) -> Result<(), Control> {
    for p in t.parameters.iter() {
        let Some(ty) = p.ty else { continue };
        let Some((_, v)) = named.iter().find(|(k, _)| k.as_deref() == Some(&*p.name)) else {
            if p.default.is_none() {
                return Err(err_at(format!("{}({}): missing '{}' ({})", op, t.name, p.name, ty.name()), loc));
            }
            continue;
        };
        // v0.6.46 (ronda 1 de cf1, N4): `nothing` vale si es el default declarado (`t: text =
        // nothing`): pasarlo a mano es lo mismo que no pasarlo.
        if ty.accepts(v)
            || (matches!(crate::labels::unwrap(v), SynValue::Nothing)
                && p.default.as_ref().is_some_and(|d| matches!(d.kind, NodeKind::NothingLiteral)))
        {
            continue;
        }
        let got = crate::labels::unwrap(v).type_name();
        let hint = if got == "text" {
            " — a tool call from `llm_step` brings typed arguments only for the parameters the catalog types (`tool_spec(task, describe)` takes them from the signature)"
        } else {
            ""
        };
        return Err(err_at(
            format!("{}({}): '{}' must be {}, got {}{}", op, t.name, p.name, ty.name(), got, hint),
            loc,
        ));
    }
    Ok(())
}

/// Convierte el `StepResult` del callback al map `{kind, …}` que consume el programa:
/// `{kind:"final", text, tokens}` | `{kind:"tool", name, args:{…}, tokens}`.
fn step_result_to_synvalue(result: StepResult) -> SynValue {
    let mut map = SynMap::new();
    match result {
        StepResult::Final { text, tokens } => {
            map.insert("kind", syn_text("final"));
            map.insert("text", syn_text(text));
            map.insert("tokens", syn_int(tokens as i64));
        }
        StepResult::Tool { name, args, tokens } => {
            let mut amap = SynMap::new();
            for (k, v) in args {
                amap.insert(k, v);
            }
            map.insert("kind", syn_text("tool"));
            map.insert("name", syn_text(name));
            map.insert("args", syn_map(amap));
            map.insert("tokens", syn_int(tokens as i64));
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

/// `texto + x` (sin etiquetas): lo que `x` le agrega al texto. La regla vive sólo acá (la usan
/// `exec_binary` y las cadenas `set P to P + …` de la VM, F4.6c): un texto tal cual, cualquier otro
/// valor que se suma a un texto por su `Display`. `false`, sin tocar `t`, si `texto + x` no es
/// agregar: un `secret` (el resultado es secret) o un tipo que no se suma a un texto (el error de
/// `exec_binary`).
pub(crate) fn text_add_piece(t: &mut SynText, x: &SynValue) -> bool {
    if !text_addable(x) {
        return false;
    }
    match x {
        SynValue::Text(r) => t.push_str(r),
        SynValue::Number(Number::Int(n)) => push_int(t, *n),
        other => {
            use std::fmt::Write;
            let _ = write!(t, "{}", other);
        }
    }
    true
}

/// F4.8g: los dígitos de `x` en decimal (con `-` si es negativo), como su `Display`, sin `fmt`.
pub(crate) fn push_int(t: &mut SynText, x: i64) {
    t.push_str(int_digits(x, &mut [0u8; 20]));
}

/// Los dígitos de `x` (ver `push_int`), escritos al final de `buf`.
pub(crate) fn int_digits(x: i64, buf: &mut [u8; 20]) -> &str {
    let mut i = buf.len();
    let mut u = x.unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if x < 0 {
        i -= 1;
        buf[i] = b'-';
    }
    // Sólo dígitos ASCII y `-`.
    std::str::from_utf8(&buf[i..]).unwrap_or_default()
}

#[cfg(test)]
mod push_int_tests {
    use super::*;

    #[test]
    fn push_int_is_display() {
        let mut xs = vec![0, 1, -1, 9, 10, -10, 99, 100, i64::MAX, i64::MIN, i64::MIN + 1, 1_000_000_007, -123_456_789_012];
        let mut r: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..10_000 {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            xs.push(r as i64 >> (r % 60));
        }
        for x in xs {
            let mut t = SynText::from("p");
            push_int(&mut t, x);
            assert_eq!(t.as_str(), format!("p{}", SynValue::Number(Number::Int(x))));
        }
    }
}

/// Si `texto + x` es agregar `x` al texto (ver `text_add_piece`).
#[inline]
pub(crate) fn text_addable(x: &SynValue) -> bool {
    !matches!(
        x,
        SynValue::Secret(_)
            | SynValue::Nothing
            | SynValue::List(_)
            | SynValue::Map(_)
            | SynValue::Bytes(_)
            | SynValue::Task(_)
            | SynValue::Builtin(_)
    )
}

/// Concatenación que **propaga el taint** (#10): el resultado es un `secret` cuyo
/// plaintext es la concatenación de los plaintexts (un operando no-secret aporta su
/// display, igual que la concatenación normal). El nombre se hereda del primer
/// operando secret (sólo cosmético para la redacción `secret(NAME)`).
/// `a + b` con algún operando `secret`: el resultado es un secret (sigue redactado). Las mismas
/// reglas que la suma de texto: números y bools se pegan; `nothing`, bytes, listas y mapas son
/// error (v0.6.44, auditoría M4: con un secret se pegaba su forma impresa, `secret + nothing` daba
/// "…nothing" — el `Bearer None` por otra puerta). Un secret SELLADO es error (daba un secret no
/// sellado con el texto `secret(NAME)`), y uno de bytes que no son UTF-8 también (cambiaba en
/// silencio: la clave de un HMAC encadenado salía otra).
fn secret_concat(left: &SynValue, right: &SynValue, loc: &SourceLocation) -> Result<SynValue, Control> {
    // (texto a concatenar, nombre si el operando es secret).
    let part = |v: &SynValue, other: &SynValue| -> Result<(String, Option<String>), Control> {
        let named = |o: &SynValue| match o {
            SynValue::Secret(s) => format!("secret({})", s.name()),
            _ => "a secret".to_string(),
        };
        match v {
            SynValue::Secret(s) if s.is_sealed() => Err(err_at(
                format!("Cannot add secret({}): it is sealed (the attested identity key never becomes text)", s.name()),
                loc,
            )),
            SynValue::Secret(s) => match std::str::from_utf8(s.expose_bytes()) {
                Ok(t) => Ok((t.to_string(), Some(s.name().to_string()))),
                Err(_) => Err(err_at(
                    format!("Cannot add secret({}): it holds bytes that are not UTF-8 text, and `+` joins text", s.name()),
                    loc,
                )),
            },
            SynValue::Text(t) => Ok((t.to_string(), None)),
            o if text_addable(o) => Ok((o.to_string(), None)),
            o => Err(err_at(
                format!(
                    "Cannot add {} and {} — convert it on purpose: text(x){}",
                    named(other),
                    o.type_name(),
                    if matches!(o, SynValue::Nothing) { " (a missing env var or map key?)" } else { "" }
                ),
                loc,
            )),
        }
    };
    let (lp, ln) = part(left, right)?;
    let (rp, rn) = part(right, left)?;
    let name = ln.or(rn).unwrap_or_else(|| "derived".to_string());
    // v0.6.46 (E1): el resultado sólo puede ir adonde pueden ir los dos (intersección de las
    // ataduras; atado + no atado = la del atado), recuerda el texto público que va antes del primer
    // secret (de ahí sale el host de una URL secret) y de qué secrets se armó (audit y eco).
    let sec = |v: &SynValue| match v {
        SynValue::Secret(s) => Some(s.clone()),
        _ => None,
    };
    let (sl, sr) = (sec(left), sec(right));
    let bound: Option<std::sync::Arc<[String]>> = match (sl.as_ref().and_then(|s| s.bound()), sr.as_ref().and_then(|s| s.bound())) {
        (Some(a), Some(b)) => {
            let i = crate::capscope::intersect_bound(a, b);
            if i.is_empty() {
                let who = |s: &Option<crate::types::Obj<crate::secret::SecretInner>>| s.as_ref().map(|s| s.name().to_string()).unwrap_or_default();
                return Err(err_at(
                    format!(
                        "Cannot add secret({}) and secret({}): the first may only go to [{}], the second only to [{}] — no request can carry both",
                        who(&sl),
                        who(&sr),
                        a.join(", "),
                        b.join(", ")
                    ),
                    loc,
                ));
            }
            Some(i.into())
        }
        (Some(a), None) | (None, Some(a)) => Some(a.clone()),
        (None, None) => None,
    };
    // El prefijo es texto público: se guarda también sin atadura, para que el error de un secret no
    // atado en una URL nombre el host (`for net("api.example.com")`).
    let public_prefix: Option<Box<str>> = match (&sl, &sr) {
        (Some(s), _) => s.public_prefix().map(Box::from),
        (None, Some(s)) => Some(format!("{}{}", lp, s.public_prefix().unwrap_or("")).into_boxed_str()),
        (None, None) => None,
    };
    let mut parts: Vec<(String, String)> = Vec::new();
    for s in [&sl, &sr].into_iter().flatten() {
        parts.extend(s.atoms());
    }
    let from_config = [&sl, &sr].into_iter().flatten().all(|s| s.is_from_config());
    Ok(SynValue::Secret(crate::types::Obj::new(
        crate::secret::SecretInner::new(name, format!("{}{}", lp, rp)).with_binding(bound, public_prefix, parts).from_config(from_config),
    )))
}

/// v0.6.46 (E3b): la envoltura de una task exportada por un módulo de confianza. Entra al scope
/// (lo que la task declaró ∩ el techo de confianza), la llama y sale, también por error. Los
/// argumentos son datos: un callable adentro correría con las capabilities de la tool (el
/// "confused deputy"), así que es error.
/// v0.6.50 (ronda 1, B6): envuelve en el scope de la tool cada task que expone un export, también
/// dentro de mapas y listas (`path` es `M.f`, `L[0]`). Un mapa o una lista sin tasks no se copia.
/// `aware` junta los nombres de los envoltorios (son conscientes de etiquetas); `wrapped`, las tasks
/// envueltas (para E-c, ronda 2).
fn wrap_exposed_tasks(
    module: &str,
    path: &str,
    v: SynValue,
    hook: &TrustedScopeHook,
    aware: &mut Vec<String>,
    wrapped: &mut HashSet<usize>,
) -> SynValue {
    fn has_task(v: &SynValue) -> bool {
        match v {
            SynValue::Task(_) => true,
            SynValue::Map(m) => m.borrow().iter().any(|(_, x)| has_task(x)),
            SynValue::List(l) => l.borrow().as_values().is_some_and(|v| v.iter().any(has_task)),
            _ => false,
        }
    }
    match v {
        SynValue::Task(t) => {
            wrapped.insert(Rc::as_ptr(&t) as usize);
            let w = trusted_wrapper(module, path, t, hook.clone());
            if let SynValue::Builtin(b) = &w {
                aware.push(b.name.to_string());
            }
            w
        }
        SynValue::Map(m) if has_task(&SynValue::Map(m.clone())) => {
            let mut out = SynMap::new();
            for (k, x) in m.borrow().iter() {
                let key = k.to_string();
                let p = format!("{}.{}", path, key);
                out.insert(key, wrap_exposed_tasks(module, &p, x.clone(), hook, aware, wrapped));
            }
            SynValue::Map(out.into_ref())
        }
        SynValue::List(l) if has_task(&SynValue::List(l.clone())) => {
            let items: Vec<SynValue> = l
                .borrow()
                .to_vec()
                .into_iter()
                .enumerate()
                .map(|(i, x)| wrap_exposed_tasks(module, &format!("{}[{}]", path, i), x, hook, aware, wrapped))
                .collect();
            syn_list(items)
        }
        other => other,
    }
}

fn trusted_wrapper(module: &str, export: &str, task: Rc<SynTaskValue>, hook: TrustedScopeHook) -> SynValue {
    let label = format!("trusted:{}.{}", module, export);
    let tool = Rc::new(TrustedTool { module: module.to_string(), label: label.clone(), task, hook });
    let t = tool.clone();
    let func: BuiltinFn = Rc::new(move |i: &mut Interpreter, args: &[SynValue], loc: &SourceLocation| {
        let mut named: CallArgs = args.iter().map(|v| (None, v.clone())).collect();
        call_trusted(i, &t, &mut named, loc)
    });
    let mut b = BuiltinTask::new(label, -1, None, func);
    b.trusted = Some(tool);
    SynValue::Builtin(Rc::new(b))
}

/// Una llamada a una task de confianza, posicional o con nombres: los argumentos son datos, y la
/// task corre en el scope de su módulo.
fn call_trusted(i: &mut Interpreter, tool: &TrustedTool, args: &mut CallArgs, loc: &SourceLocation) -> Result<SynValue, Control> {
    if let Some(kind) = args.iter().find_map(|(_, v)| callable_inside(v)) {
        return Err(err_at(
            format!(
                "{}: a trusted tool takes data, not code — an argument holds a {}, which would run with the tool's capabilities; pass the values it needs instead",
                tool.label, kind
            ),
            loc,
        ));
    }
    i.stdout_verdict = None;
    (tool.hook)(Some((&tool.module, &tool.task.required_capabilities)));
    debug_assert!(!i.shortcuts, "a trusted scope opened with the VM on (it has no origin check)");
    i.trusted_depth += 1;
    i.trusted_stack.push(tool.module.clone());
    let r = i.call_value_named(SynValue::Task(tool.task.clone()), args, loc);
    i.trusted_stack.pop();
    i.trusted_depth -= 1;
    (tool.hook)(None);
    i.stdout_verdict = None;
    r
}

/// v0.6.46 (ronda 1, A1): un agente corre en otro intérprete, con los globales del programa, y la
/// tabla de agentes es una sola por nombre (el programa pisaba el agente de la tool).
#[cold]
fn trusted_no_agents(name: &str) -> String {
    format!(
        "agent '{}': a trusted tool cannot define or spawn agents yet — the agent would run with the tool's capabilities next to the program's names; do the work in the tool's own tasks",
        name
    )
}

/// v0.6.46 (E3b): ¿hay un callable (task, lambda, builtin) en el valor, a cualquier profundidad?
fn callable_inside(v: &SynValue) -> Option<&'static str> {
    match labels::unwrap(v) {
        SynValue::Task(_) => Some("task"),
        SynValue::Builtin(_) => Some("builtin"),
        SynValue::List(l) => list_values(l).iter().find_map(callable_inside),
        SynValue::Map(m) => m.borrow().iter().find_map(|(_, x)| callable_inside(x)),
        // Ronda 1 (B2): `ok(f)`, `content(f)` y `with_header(f, …)` también guardan un valor.
        SynValue::Server(s) => match &**s {
            crate::types::ServerValue::Envelope { value, .. } => callable_inside(value),
            crate::types::ServerValue::Content(v) | crate::types::ServerValue::WithHeaders { inner: v, .. } => callable_inside(v),
            crate::types::ServerValue::Node(m) => m.borrow().iter().find_map(|(_, x)| callable_inside(x)),
            _ => None,
        },
        _ => None,
    }
}

/// v0.6.46 (E5): el host no permite que esta operación le mande al modelo lo privado que lleva.
#[cold]
#[inline(never)]
fn llm_data_not_granted(op: &str, judge: bool, declared: &str, loc: &SourceLocation) -> Control {
    let cap = if judge { "judge" } else { "llm" };
    err_labels(
        format!(
            "label_violation: {op} would send data private to ({declared}) to the model; the host allows that per principal and provider in its ceiling (`--cap-set {cap}=<principal>@<provider host>`, `@local` for a model in the process, `@embedder` in wasm) and the program declares `require {cap}(\"<principal>\")`. Otherwise declassify(<that value>, \"<why the model may see it>\") the part the model may see"
        ),
        loc,
    )
}

/// v0.6.49 (A3): un secreto creado o elegido con el PC privado (`mnemonic_generate`, `hd_derive`,
/// `secret(...)` en una rama privada; un secreto asignado dentro de ella).
const SECRET_UNDER_PRIVATE_PC: &str = "label_violation: a secret cannot be created or chosen under private control flow — a secret carries no label, so the branch would be lost in it; create or pick the secret before the `when` (or the loop) that depends on the private value";
/// v0.6.49 (A3): un secreto hecho de, combinado con o elegido por un valor privado, con el PC público.
const SECRET_FROM_PRIVATE_VALUE: &str = "label_violation: a secret cannot be made from, combined with or chosen by a private value — a secret carries no label, so the private data would be lost in it; keep secrets and private data apart, and choose a secret with a public value";

/// v0.6.46 (E3): el error de un `declassify` que el host no concede (frío, fuera de `b_declassify`).
#[cold]
fn declassify_not_granted(declared: &str, trusted: bool, agent: Option<&str>, loc: &SourceLocation) -> Control {
    // v0.6.49 (ronda 2, B3): una task de confianza tiene su `require` y su techo, aunque la llame un
    // agente (el agente puede tener el suyo; lo que falta es el de la task). Ronda 3 (B2): también
    // corre acá el nivel superior del módulo al cargarlo, donde no se puede declarar nada; el texto
    // cubre los dos casos.
    if trusted {
        return err_labels(
            format!(
                "label_violation: declassify is not granted for what this value is private to ({}). This runs in a trusted module, which declares its capabilities per exported task: add `require declassify(\"<principal>\")` to the exported task that runs it (while the module loads nothing is declared, not even by a task its top level calls: move the declassify into an exported task and call it from the program), and the host's ceiling for trusted modules has to allow it too (`--trusted-cap-set declassify=<principal>`)",
                declared
            ),
            loc,
        );
    }
    // v0.6.49 (ronda 1, M2): un agente declara sus propias capabilities (el `require` del programa
    // no le llega), así que el remedio nombra al agente en vez del preámbulo.
    if let Some(agent) = agent {
        return err_labels(
            format!(
                "label_violation: declassify is not granted for what this value is private to ({}). An agent declares its own capabilities (the program's `require` does not reach it): add `require declassify(\"<principal>\")` to the body of agent {}, and the host's ceiling has to allow it too (`--cap-set declassify=<principal>`)",
                declared, agent
            ),
            loc,
        );
    }
    // Ronda 2 (B3): un worker de `parallel_map` hereda las capabilities de quien lo lanzó, no su
    // nombre de agente, así que acá no se sabe si lo lanzó un agente: se nombran los dos lugares.
    // Ronda 3 (B1): `spawn` lanza un agente, que tiene su contexto y cae en la rama de arriba.
    err_labels(
        format!(
            "label_violation: declassify is not granted for what this value is private to ({}). With a ceiling the program declares what it publishes (`require declassify(\"<principal>\")` in the program's preamble, or in the body of the agent that runs this code: an agent declares its own, also for its `parallel_map`) and the host's ceiling has to allow it too (`--cap-set declassify=<principal>`); inside a `sandbox` only a `sandbox under` that delegates `declassify` allows it",
            declared
        ),
        loc,
    )
}

/// v0.6.46 (E2): el error de una lista o un mapa con un secret en el hueco de un template.
#[cold]
#[inline(never)]
fn secret_in_hole_error(v: &SynValue, loc: &SourceLocation) -> Control {
    let name = crate::secret::contains_secret(v).unwrap_or_default();
    err_at(
        format!(
            "a secret inside a {} cannot go into a text hole (secret({}) would travel as its placeholder): take it out on its own (`creds.k`) or use bearer(...)/basic(...)",
            v.type_name(),
            name
        ),
        loc,
    )
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
pub(crate) fn make_unique(slot: &mut SynValue) {
    make_unique_n(slot, 0)
}

/// `make_unique` tolerando `extra` dueños conocidos del nivel de arriba (la vista del mapa de
/// un módulo sobre su propia variable).
fn make_unique_n(slot: &mut SynValue, extra: usize) {
    let owners = 1 + extra;
    match slot {
        SynValue::List(rc) if crate::types::ListRef::strong_count(rc) > owners => {
            let copy = rc.borrow().clone();
            *slot = SynValue::List(synsema_heap::Shared::new(copy));
        }
        SynValue::Map(rc) if crate::types::MapRef::strong_count(rc) > owners && module_env_of_map(rc).is_none() => {
            let copy = rc.borrow().to_ref();
            // La copia de la vista de un módulo de confianza sigue siendo esa vista (B8).
            if is_trusted_view(rc) {
                register_trusted_view(&copy);
            }
            *slot = SynValue::Map(copy);
        }
        SynValue::Private(p) => {
            let shared_inner = match &p.value {
                SynValue::List(rc) => crate::types::ListRef::strong_count(rc) > 1,
                SynValue::Map(rc) => crate::types::MapRef::strong_count(rc) > 1,
                _ => false,
            };
            if shared_inner || (crate::types::Obj::strong_count(p) > owners && matches!(p.value, SynValue::List(_) | SynValue::Map(_))) {
                // Copia del contenedor interno aunque su cuenta sea 1 cuando el envoltorio
                // está compartido: el alias ve el mismo Rc interno.
                let inner = match &p.value {
                    SynValue::List(rc) => SynValue::List(crate::types::ListRef::new(rc.borrow().clone())),
                    SynValue::Map(rc) => SynValue::Map(rc.borrow().to_ref()),
                    other => other.clone(),
                };
                *slot = labels::labelled(inner, p.label.clone());
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
    /// v0.6.46 (E1.7): los secrets que salieron en esa llamada (sus nombres, nunca su valor ni la
    /// URL). Vacío en lo que no es de red.
    pub secrets: Vec<String>,
}

/// v0.6.46 (E6): ¿un sumidero que falló sólo por el PC privado puede correr igual porque su efecto es
/// una entrada de audit que va al sobre? Sólo `reveal`, sólo con el registro sellado activo y sólo con
/// los argumentos sin etiqueta (si alguno la tiene, el error fue por el dato, no por la rama). `spend`
/// no: gasta un cupo compartido, y después se ve si alcanza (un oráculo de la rama).
#[cold]
#[inline(never)]
fn sealed_sink_allowed(name: &str, args: &[SynValue]) -> bool {
    name == "reveal" && crate::sealed::active() && args.iter().all(|a| labels::label_deep(a).is_empty())
}

/// v0.6.46 (E6): una entrada de linaje en el registro de la corrida del recibo sellado. La hecha bajo
/// un PC privado va al sobre y lleva la sal (el sobre es del auditor, que con ella puede probar qué
/// consulta fue); la pública va sin sal, como en `receipt()`.
#[cold]
#[inline(never)]
fn seal_lineage(e: &LineageEntry, sealed: bool) {
    let mut v = serde_json::json!({
        "kind": "input",
        "source": e.source,
        "what": e.what,
        "sha256": e.sha256,
        "bytes": e.bytes,
        "encoding": e.encoding,
    });
    if let (true, Some((salt, enc))) = (sealed, &e.salt) {
        v["salt"] = serde_json::json!(salt);
        v["salted_encoding"] = serde_json::json!(enc);
    }
    if !e.secrets.is_empty() {
        v["secrets"] = serde_json::json!(e.secrets);
    }
    crate::sealed::note_input(v.to_string(), sealed, &e.source, &e.sha256);
}

/// v0.6.46 (ronda 1 de cf1, B1): una escritura en el registro de la corrida del recibo sellado. Es
/// pública (bajo un PC privado escribir se rechaza antes) y no entra en `--replay`, que compara lo
/// leído.
#[cold]
#[inline(never)]
fn seal_output(e: &LineageEntry) {
    let v = serde_json::json!({
        "kind": "output",
        "source": e.source,
        "what": e.what,
        "sha256": e.sha256,
        "bytes": e.bytes,
        "encoding": e.encoding,
    });
    crate::sealed::push_public(v.to_string());
}

/// Builtins que TRAEN datos de afuera (archivos, red, bases, nodos de una cadena, sockets,
/// procesos, la terminal, stdin). Lo que sólo escribe o manda (`write_file`, `ws_send`,
/// `evm_send`) no es una entrada.
pub const LINEAGE_SOURCES: &[&str] = &[
    // archivos y stdin
    "read_file", "read_file_bytes", "read_line", "list_dir", "file_info", "grep", "parquet_read", "parquet_scan",
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
    "ws_recv", "ws_select", "ws_select_all", "select", "tcp_recv", "pipe_recv", "proc_recv", "proc_select", "proc_wait", "run", "run_program",
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
/// entropía del SO (`getrandom`; en el navegador, la del host), más las claves de `RandomState`
/// y, fuera de wasm32-unknown-unknown, el reloj y el pid.
fn fresh_salt() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static KEY: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    let key = KEY.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = Sha256::new();
        let mut os = [0u8; 32];
        if getrandom::getrandom(&mut os).is_ok() {
            h.update(os);
        }
        for i in 0..8u64 {
            let mut s = std::collections::hash_map::RandomState::new().build_hasher();
            s.write_u64(i);
            h.update(s.finish().to_le_bytes());
        }
        // En wasm32-unknown-unknown no hay reloj ni proceso: `SystemTime::now()` y
        // `process::id()` hacen pánico (un `unreachable` que tira la instancia).
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            h.update(now.to_le_bytes());
            h.update(std::process::id().to_le_bytes());
        }
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
    // v0.6.46 (E1): de una URL que es un secret atado, el host sale de su parte pública.
    let t: &str = match url {
        Some(SynValue::Text(t)) => t,
        Some(SynValue::Secret(s)) => match s.public_prefix() {
            Some(p) => return url_host(Some(&syn_text(p))),
            None => return String::new(),
        },
        _ => return String::new(),
    };
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
/// La aridad de una llamada a una task: `positional` argumentos por posición y `named(p)` dice
/// si el parámetro `p` vino por nombre. La usan el tree-walker y la VM (mismos mensajes).
fn check_task_arity(
    t: &SynTaskValue,
    positional: usize,
    named: impl Fn(&str) -> bool,
    loc: &SourceLocation,
) -> Result<(), Control> {
    let np = t.parameters.len();
    // Sólo para el mensaje: se arma cuando hay error, no en cada llamada.
    let who = || if t.name == "<lambda>" { "this lambda".to_string() } else { format!("task '{}'", t.name) };
    if positional > np {
        return Err(err_at(
            format!(
                "{} takes {} argument{}, got {}",
                who(),
                np,
                if np == 1 { "" } else { "s" },
                positional
            ),
            loc,
        ));
    }
    for (i, p) in t.parameters.iter().enumerate() {
        let given = i < positional || named(&p.name);
        if !given && p.default.is_none() {
            return Err(err_at(
                format!(
                    "{} is missing argument '{}' — pass it, or give the parameter a default in the task: {} = …",
                    who(), p.name, p.name
                ),
                loc,
            ));
        }
    }
    Ok(())
}

/// v0.6.46 (C6): la aridad de una llamada a una task falló; si además vino un nombre que la task no
/// tiene, ése es el error (`page(limt = 1)` decía que faltaba `limit`). Lo llaman los que llaman a
/// `check_call_arity`, que tienen `func` y `args` vivos de todos modos: hacerlo adentro alargaba su
/// vida en el camino feliz y costaba +0,1–0,2 % de instrucciones por llamada en el tree-walker.
#[cold]
#[inline(never)]
fn arity_error(e: Control, func: &SynValue, args: &[(Option<String>, SynValue)], loc: &SourceLocation) -> Control {
    let SynValue::Task(t) = func else { return e };
    match args.iter().filter_map(|(n, _)| n.as_deref()).find(|n| !t.parameters.iter().any(|p| *p.name == **n)) {
        Some(n) => unknown_parameter(n, t.parameters.iter().map(|p| &*p.name), loc),
        None => e,
    }
}

fn check_call_arity(
    func: &SynValue,
    args: &[(Option<String>, SynValue)],
    loc: &SourceLocation,
) -> Result<(), Control> {
    let positional = args.iter().filter(|(n, _)| n.is_none()).count();
    match func {
        SynValue::Task(t) => check_task_arity(t, positional, |name| args.iter().any(|(n, _)| n.as_deref() == Some(name)), loc),
        // El constructor de un tipo o de una variante (`Point(…)`, `Order.paid(…)`) cuenta
        // sus campos él mismo, con un mensaje que nombra el tipo.
        SynValue::Builtin(b) if b.meta.constructor => Ok(()),
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
    b.meta.arity
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
pub(crate) fn resolve_index(i: i64, len: usize) -> Option<usize> {
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

fn ord_op(ord: Option<Ordering>, op: BinOp) -> bool {
    match ord {
        None => false, // NaN
        Some(o) => match op {
            BinOp::Lt => o == Ordering::Less,
            BinOp::Gt => o == Ordering::Greater,
            BinOp::Le => o != Ordering::Greater,
            BinOp::Ge => o != Ordering::Less,
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
            let (x, y) = (crate::synlist::list_read(x), crate::synlist::list_read(y));
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
            let (x, y) = (crate::synlist::list_read(x), crate::synlist::list_read(y));
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
///
/// v0.6.50: el estado de la corrida viaja con ella (antes eran globales del proceso, "la última
/// corrida": un embebedor que corría dos a la vez leía el de la otra).
#[derive(Default)]
pub struct RunResult {
    pub success: bool,
    pub output: Vec<String>,
    pub errors: Vec<String>,
    /// El código que pidió `exit(code)`, si el programa lo llamó (`None` también tras un corte de
    /// etiquetas: el código sería el dato).
    pub exit_code: Option<i32>,
    /// Pasos del intérprete del programa principal (`steps()`; determinista).
    pub steps: u64,
    /// ¿La corrida tocó datos privados? Si sí, el host no publica `steps` (después de una rama
    /// privada el contador es el dato con aritmética encima).
    pub touched_private: bool,
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
            ..Default::default()
        },
        Err(CompileError::Parse(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Parse error: {}", e)],
            ..Default::default()
        },
        Ok(program) => {
            let mut interp = Interpreter::new();
            match interp.execute(&program) {
                Ok(_) => RunResult {
                    success: true,
                    output: std::mem::take(&mut interp.output),
                    errors: Vec::new(),
                    ..Default::default()
                },
                Err(Control::Error(e)) => RunResult {
                    success: false,
                    output: std::mem::take(&mut interp.output),
                    errors: vec![format!("Runtime error: {}", e)],
                    ..Default::default()
                },
                // `give`/`stop` que escapan al top: error limpio (no "Internal error:").
                Err(Control::Give(_)) | Err(Control::Stop(_)) => RunResult {
                    success: false,
                    output: std::mem::take(&mut interp.output),
                    errors: vec![
                        "Runtime error: 'give'/'stop' used outside of a task or loop".to_string(),
                    ],
                    ..Default::default()
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
            ..Default::default()
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
                body: Vec::new().into(),
                closure_env: interp.global_env.clone(), // task → global_env (la mitad del ciclo)
                origin: None,
                required_capabilities: vec![],
                code: Default::default(),
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
            let env = Environment::child_scope(&interp.global_env, "request");
            let task = SynValue::Task(Rc::new(SynTaskValue {
                name: "t".to_string(),
                parameters: vec![],
                body: Vec::new().into(),
                closure_env: env.clone(), // task → child (mitad del ciclo)
                origin: None,
                required_capabilities: vec![],
                code: Default::default(),
            }));
            env.borrow_mut().bindings.insert("t", task); // child → task (otra mitad)
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

/// El orden doble de los builtins con una función y una lista (ver `dual_fn_rc`): cuál es la
/// función y cuál debería ser la lista (todavía sin mirar si lo es).
fn dual_fn_pick<'a>(args: &'a [SynValue], op: &str) -> Result<(SynValue, &'a SynValue), Control> {
    let a0 = nth(args, 0)?;
    let a1 = nth(args, 1)?;
    match (is_callable(a0), is_callable(a1)) {
        (true, true) => Err(err(format!(
            "{op}: expected one task and one list (either order: {op}(fn, list, ...) or {op}(list, fn, ...)), got two tasks"
        ))),
        (true, false) => Ok((a0.clone(), a1)),
        (false, true) => Ok((a1.clone(), a0)),
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
                Ok((a1.clone(), a0))
            } else {
                Ok((a0.clone(), a1))
            }
        }
    }
}

/// Anota un módulo cargado para `program_sha` del recibo (`loaded_modules`). Fría y fuera de línea:
/// llamada desde `load_module_inner`, que no es caliente, pero el código en línea ahí cambiaba el
/// acomodo del binario entero (medido: +8 % de tiempo en Windows sin PGO, mismas instrucciones).
#[cold]
#[inline(never)]
fn note_loaded_module(resolved: &str, source: &str, program: &crate::ast::Program) {
    crate::loaded_modules::record(resolved, source, program);
}

#[cfg(test)]
mod secret_concat_tests {
    //! v0.6.44 (auditoría M4): `+` con un secret sigue las reglas de la suma de texto, y nunca pega
    //! la forma impresa de nada ni el marcador de un sellado.
    use super::*;
    use crate::secret::SecretInner;
    use crate::types::{syn_bytes, syn_int, syn_secret_bytes, syn_text};

    fn loc() -> SourceLocation {
        SourceLocation { file: "t.syn".into(), line: 1, column: 1, offset: 0 }
    }
    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!("expected an error"),
        }
    }

    #[test]
    fn plus_with_a_secret_follows_the_text_rules() {
        let k = syn_secret("K", "abc".to_string());
        let ok = |r: Result<SynValue, Control>| match r {
            Ok(SynValue::Secret(s)) => (s.name().to_string(), s.expose().to_string()),
            _ => panic!("expected a secret"),
        };
        assert_eq!(ok(secret_concat(&syn_text("AWS4"), &k, &loc())), ("K".to_string(), "AWS4abc".to_string()));
        assert_eq!(ok(secret_concat(&k, &syn_int(5), &loc())), ("K".to_string(), "abc5".to_string()), "un número se pega, como en el texto");
        assert_eq!(ok(secret_concat(&syn_secret_bytes("B", b"utf8".to_vec()), &syn_text("!"), &loc())).1, "utf8!");
        assert!(msg(secret_concat(&k, &SynValue::Nothing, &loc())).contains("Cannot add secret(K) and nothing"));
        assert!(msg(secret_concat(&SynValue::Nothing, &k, &loc())).contains("Cannot add secret(K) and nothing"));
        assert!(msg(secret_concat(&k, &syn_bytes(vec![1u8]), &loc())).contains("Cannot add secret(K) and bytes"));
        assert!(msg(secret_concat(&syn_secret_bytes("B", vec![0xff]), &syn_text("x"), &loc())).contains("secret(B): it holds bytes that are not UTF-8"));
        let sealed = SynValue::Secret(crate::types::Obj::new(SecretInner::new_bytes_sealed("attestation_key", vec![7u8; 32])));
        assert!(msg(secret_concat(&syn_text("x"), &sealed, &loc())).contains("secret(attestation_key): it is sealed"));
    }
}

#[cfg(test)]
mod bindings_find_tests {
    use super::*;

    /// `find` recorre dos tramos (en línea y heap) sin `Chain`: cada nombre tiene que caer en su
    /// índice en los dos, antes de que exista el índice por hash (`INDEX_AT`) y después.
    #[test]
    fn every_name_is_found_at_its_slot_inline_heap_and_indexed() {
        let mut b = Bindings::default();
        for i in 0..INDEX_AT + 4 {
            b.set(&format!("v{i}"), SynValue::Bool(i % 2 == 0));
            for j in 0..=i {
                assert_eq!(b.find(&format!("v{j}")), Some(j), "con {} nombres", i + 1);
            }
            assert_eq!(b.find("nadie"), None);
            // un prefijo o un nombre más largo no es el mismo nombre
            assert_eq!(b.find("v"), None);
            assert_eq!(b.find(&format!("v{i}x")), None);
        }
        // el hueco que deja `remove` conserva su nombre y su índice
        assert!(b.remove("v9").is_some());
        assert_eq!(b.find("v9"), Some(9));
        assert!(b.get("v9").is_none());
    }
}
