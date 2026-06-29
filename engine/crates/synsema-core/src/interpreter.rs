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

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::rc::Rc;

use indexmap::IndexMap;
use num_complex::Complex64;
use regex::Regex;

use crate::ast::{Node, NodeKind, Param, Program};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::parser::{parse_source, CompileError};
use crate::templates::resolve_module_path;
use crate::tokens::SourceLocation;
use crate::types::*;

// =========================================================
// Errores y control de flujo
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
}

impl RuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: false, field: None, is_assertion: false }
    }
    pub fn at(message: impl Into<String>, location: SourceLocation) -> Self {
        Self { message: message.into(), location: Some(location), is_validation: false, field: None, is_assertion: false }
    }
    /// Error de validación de cliente (input que no cumple `expect`): se mapea a HTTP 400
    /// con el nombre del campo ofensor, en vez de a un 500 genérico.
    pub fn validation(message: impl Into<String>, field: Option<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: true, field, is_assertion: false }
    }
    /// Falla de aserción (`assert*`): marca `is_assertion` para el reporte de tests.
    pub fn assertion(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: false, field: None, is_assertion: true }
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
// Builtins
// =========================================================

pub type BuiltinFn =
    Rc<dyn Fn(&mut Interpreter, &[SynValue], &SourceLocation) -> Result<SynValue, Control>>;

/// Un task built-in (implementado en Rust). `param_count` es informativo (Python
/// no lo fuerza en `_call_value`).
pub struct BuiltinTask {
    pub name: String,
    pub func: BuiltinFn,
    pub param_count: i32,
}

// =========================================================
// Entorno
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

pub(crate) fn env_get(env: &Rc<RefCell<Environment>>, name: &str) -> Option<SynValue> {
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
// Intérprete
// =========================================================

/// Límite de profundidad de recursión de llamadas. Evita que una recursión
/// patológica desborde el stack nativo (lo que abortaría el proceso); en su lugar
/// produce un error atrapable. NOTA paridad: Python lanza RecursionError a una
/// profundidad distinta (~100-150 niveles de task por su recursionlimit=1000).
/// El corpus no prueba el límite exacto; divergencia documentada.
const MAX_RECURSION: usize = 3000;

/// Hook que el host (motor) cablea para que `require <tipo>(<scope>)` conceda en
/// el `CapabilitySet` real (que vive fuera de core, para evitar el ciclo de deps).
/// Espeja el callback `_grant_capability` del intérprete Python.
pub type GrantHook = Rc<dyn Fn(&str, Option<&str>)>;
/// Hook de aislamiento de `sandbox` (lo cablea el motor, que tiene el CapabilitySet):
/// `true` al entrar (deniega TODAS las capabilities), `false` al salir (restaura).
/// Maneja sandboxes anidados (stack en el closure).
pub type SandboxHook = Rc<dyn Fn(bool)>;

// --- FASE 1 tool-calling: el callback de paso del LLM (tipos PLANOS) ---
// Core NO depende de `synsema-llm` (la dep va al revés vía runtime). Igual que
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

/// Hooks que el host (motor) cablea para conectar `share`/`observe`/`signal`/
/// `wait_for`/`spawn` al swarm real (blackboard + señales + hilos). Espejan los
/// callbacks `_swarm_*` del intérprete Python. Si no están, share/observe usan el
/// blackboard local (programa de un solo hilo) y signal/wait_for/spawn caen a su
/// comportamiento in-process.
#[derive(Clone)]
pub struct SwarmHooks {
    pub share: Rc<dyn Fn(&str, &SynValue)>,
    pub observe: Rc<dyn Fn(&str) -> Option<SynValue>>,
    pub signal: Rc<dyn Fn(&str, Option<SynValue>)>,
    /// `wait_for(canal, timeout_secs)` — `None` = default (30 s). Batch 7.
    pub wait_for: Rc<dyn Fn(&str, Option<f64>) -> Option<SynValue>>,
    #[allow(clippy::type_complexity)]
    /// `spawn(name, body, args, globals)` — `globals` es un snapshot de los bindings
    /// globales del intérprete llamador (tareas, valores, módulos) para que el agente
    /// hijo los tenga disponibles sin necesitar HTTP ni wrappers.
    pub spawn: Rc<dyn Fn(&str, Vec<Node>, Vec<(String, SynValue)>, Vec<(String, SynValue)>) -> Result<String, Control>>,
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
    recursion_depth: usize,
    /// Concede capabilities declaradas con `require` (lo cablea el motor).
    grant_hook: Option<GrantHook>,
    /// Aislamiento de `sandbox`: profundidad de anidamiento (>0 = dentro de un sandbox)
    /// y un hook que vacía/restaura el CapabilitySet durante el cuerpo. Un `require`
    /// dentro de un sandbox es no-op (no se puede re-grantear para escapar).
    sandbox_depth: u32,
    sandbox_hook: Option<SandboxHook>,
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
    /// Callback humano (approve/confirm/ask). (action, message) → SynValue
    /// (bool para approve/confirm, texto para ask). Sin él: auto-aprueba.
    human_callback: Option<Rc<dyn Fn(&str, &str) -> SynValue>>,
    /// Callback LLM (reason/decide/analyze/generate): (operación, prompt) → contenido.
    /// El `prompt` lleva el texto ya renderizado de la op (subject/data/objective/…)
    /// para que el provider real tenga qué mandar; un mock puede ignorarlo y keyear por
    /// la operación. Sin él: placeholders descriptivos.
    llm_callback: Option<LlmTextCallback>,
    /// Callback LLM tool-aware de PASO (`llm_step`, FASE 1): el motor lo cablea con el
    /// provider guionable/real. Sin él: `llm_step` devuelve un placeholder seguro.
    llm_step_callback: Option<LlmStepCallback>,
    /// Gate de capability para las ops LLM: lo cablea el motor para exigir
    /// `require llm` antes de CUALQUIER op LLM (provider real o placeholder).
    /// `Err(msg)` → la op falla con `Capability not granted: llm`. Sin él: sin gate
    /// (core no depende de capabilities; el motor provee la lógica).
    llm_cap_hook: Option<Rc<dyn Fn() -> Result<(), String>>>,
    /// Hook de `serve on PORT` (lo cablea el motor en el camino de serve).
    serve_hook: Option<ServeHook>,
    /// Sink de `send` dentro de un handler de stream SSE (lo cablea el motor por
    /// request de streaming). (value, event_name) → (). Sin él, `send` es error.
    stream_emit: Option<Rc<dyn Fn(SynValue, Option<&str>) -> Result<(), Control>>>,
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
            recursion_depth: 0,
            grant_hook: None,
            sandbox_depth: 0,
            sandbox_hook: None,
            tool_scope_hook: None,
            tool_scope_depth: 0,
            intent: None,
            intent_frozen: false,
            swarm_hooks: None,
            human_callback: None,
            llm_callback: None,
            llm_step_callback: None,
            llm_cap_hook: None,
            serve_hook: None,
            stream_emit: None,
            log_hook: None,
            module_cache: HashMap::new(),
            loading_modules: HashSet::new(),
            exports_collector: vec![Vec::new()],
            live_output: false,
        };
        interp.register_builtins();
        interp
    }

    fn register(&self, name: &str, param_count: i32, func: BuiltinFn) {
        self.global_env.borrow_mut().bindings.insert(
            name.to_string(),
            SynValue::Builtin(Rc::new(BuiltinTask {
                name: name.to_string(),
                func,
                param_count,
            })),
        );
    }

    /// Registra un builtin externo (lo usa el motor para los builtins seguros).
    pub fn register_builtin(&self, name: &str, param_count: i32, func: BuiltinFn) {
        self.register(name, param_count, func);
    }

    /// Cablea el hook de concesión de capabilities (lo llama `require`).
    pub fn set_grant_hook(&mut self, hook: GrantHook) {
        self.grant_hook = Some(hook);
    }

    /// Cablea el hook de aislamiento de `sandbox` (lo instala el motor con el caps).
    pub fn set_sandbox_hook(&mut self, hook: SandboxHook) {
        self.sandbox_hook = Some(hook);
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

    /// Cablea el callback humano (approve/confirm/ask).
    pub fn set_human_callback(&mut self, cb: Rc<dyn Fn(&str, &str) -> SynValue>) {
        self.human_callback = Some(cb);
    }

    /// Cablea el callback LLM (reason/decide/analyze/generate). La firma es
    /// `(op, prompt) -> contenido`: el motor le pasa el prompt renderizado de la op.
    pub fn set_llm_callback(&mut self, cb: LlmTextCallback) {
        self.llm_callback = Some(cb);
    }

    /// Cablea el callback LLM tool-aware de paso (`llm_step`, FASE 1).
    pub fn set_llm_step_callback(&mut self, cb: LlmStepCallback) {
        self.llm_step_callback = Some(cb);
    }

    /// Cablea el gate de capability para las ops LLM (exige `require llm`).
    pub fn set_llm_cap_hook(&mut self, hook: Rc<dyn Fn() -> Result<(), String>>) {
        self.llm_cap_hook = Some(hook);
    }

    /// Chequea la capability `llm` (si hay gate). Se llama al inicio de cada op LLM,
    /// con o sin provider real. Sin gate cableado: no-op (no rompe `Interpreter::new`).
    fn check_llm_cap(&self) -> Result<(), Control> {
        if let Some(hook) = &self.llm_cap_hook {
            hook().map_err(|m| Control::Error(RuntimeError::new(m)))?;
        }
        Ok(())
    }

    /// Cablea el hook de `serve on PORT` (lo usa el motor en el camino de serve).
    pub fn set_serve_hook(&mut self, hook: ServeHook) {
        self.serve_hook = Some(hook);
    }

    /// Cablea el sink de `send` (por request de streaming SSE).
    pub fn set_stream_emit(&mut self, emit: Rc<dyn Fn(SynValue, Option<&str>) -> Result<(), Control>>) {
        self.stream_emit = Some(emit);
    }

    /// Llama a un valor invocable (task/builtin) con argumentos. Para el motor
    /// (p.ej. el verificador de auth de `serve`). Un `give` interno → valor de retorno.
    pub fn call_task(&mut self, func: SynValue, args: Vec<SynValue>) -> Result<SynValue, Control> {
        let loc = SourceLocation { file: "<engine>".to_string(), line: 0, column: 0, offset: 0 };
        self.call_value(func, args, &loc)
    }

    /// Intent declarado (para enriquecer /llms.txt). Texto descriptivo, no gatea nada.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Bindea una variable en el entorno global (para los spawn_args de un agente).
    pub fn set_global(&self, name: &str, value: SynValue) {
        env_set(&self.global_env, name, value);
    }

    /// Ejecuta un bloque de statements en el entorno global (cuerpo de un agente).
    /// Sin preámbulo/freeze (eso es sólo para el programa top-level).
    pub fn run_block(&mut self, stmts: &[Node]) -> Result<SynValue, Control> {
        let g = self.global_env.clone();
        self.exec_block(stmts, &g)
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
        let env = Environment::child(&self.global_env, "request");
        {
            let mut e = env.borrow_mut();
            for (k, v) in bindings {
                e.bindings.insert(k, v);
            }
        }
        let result = self.exec_block(stmts, &env);
        // Rompe cualquier ciclo Rc creado en el scope del request: si el handler hace
        // `define task` dentro del body, la task cierra sobre `env` (`closure_env`) y el
        // env la contiene en `bindings` → `env ⇄ task`, que Rc no libera (igual razón que
        // el `Drop` del intérprete para el global, fix de OOM #7). Como el intérprete se
        // REUSA entre requests, este `env` no se dropea vía ese `Drop`; vaciarlo acá corta
        // el ciclo → el env del request (bindings + lo que definió el handler) se libera.
        // El give-value (en `result`) es un valor owned, no referencia al env.
        env.borrow_mut().bindings.clear();
        result
    }

    /// Limpia el estado transitorio entre requests del serve (cuando un worker reusa
    /// el mismo intérprete). Deja `global_env` (builtins + globales + tasks) intacto
    /// pero resetea lo per-request: salida acumulada, blackboard local, definiciones
    /// de agente, sink de stream y profundidad de recursión. Las capabilities se
    /// resetean afuera (las posee el motor, vía el `Rc<RefCell<CapabilitySet>>` que
    /// capturan los builtins). Sin esto, el estado de un request se filtraría al
    /// siguiente.
    pub fn reset_for_request(&mut self) {
        self.output.clear();
        self.blackboard.clear();
        self.agent_definitions.clear();
        self.stream_emit = None;
        self.recursion_depth = 0;
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
        let resolved = resolve_module_path(raw_path, base_dir).map_err(err)?;

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
        let source = std::fs::read_to_string(resolved)
            .map_err(|_| err(format!("module not found: {}", raw_path)))?;
        // Un error de compilación del módulo se reporta como runtime (la operación
        // de import falló), igual que en el oráculo Python.
        let program = parse_source(&source, resolved).map_err(|e| err(e.to_string()))?;

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
        Ok(syn_map(exports))
    }

    fn register_builtins(&self) {
        // Núcleo
        self.register("print", -1, Rc::new(|i, a, l| i.b_print(a, l)));
        self.register("length", 1, Rc::new(|i, a, l| i.b_length(a, l)));
        self.register("text", 1, Rc::new(|i, a, l| i.b_to_text(a, l)));
        self.register("number", 1, Rc::new(|i, a, l| i.b_to_number(a, l)));
        // Tipo Decimal (dinero exacto): constructor + conversión a float + introspección.
        self.register("decimal", 1, Rc::new(|i, a, l| i.b_decimal(a, l)));
        self.register("float", 1, Rc::new(|i, a, l| i.b_float(a, l)));
        self.register("is_decimal", 1, Rc::new(|i, a, l| i.b_is_decimal(a, l)));
        // Tipo bytes (binario): constructor/conversión + introspección. PUROS (sin
        // capability, como text/number/decimal). El hex/base64 es hand-rolled (bytesutil).
        self.register("bytes", -1, Rc::new(|i, a, l| i.b_bytes(a, l)));
        self.register("decode", -1, Rc::new(|i, a, l| i.b_decode(a, l)));
        self.register("is_bytes", 1, Rc::new(|i, a, l| i.b_is_bytes(a, l)));
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
        self.register("keys", 1, Rc::new(|i, a, l| i.b_keys(a, l)));
        self.register("values", 1, Rc::new(|i, a, l| i.b_values(a, l)));
        self.register("contains", 2, Rc::new(|i, a, l| i.b_contains(a, l)));
        self.register("split", 2, Rc::new(|i, a, l| i.b_split(a, l)));
        self.register("join", 2, Rc::new(|i, a, l| i.b_join(a, l)));
        self.register("range", -1, Rc::new(|i, a, l| i.b_range(a, l)));
        self.register("type_of", 1, Rc::new(|i, a, l| i.b_type_of(a, l)));
        self.register("slice", -1, Rc::new(|i, a, l| i.b_slice(a, l)));
        self.register("fmt", 1, Rc::new(|i, a, l| i.b_fmt(a, l)));
        self.register("upper", 1, Rc::new(|i, a, l| i.b_upper(a, l)));
        self.register("lower", 1, Rc::new(|i, a, l| i.b_lower(a, l)));
        // fold: minúsculas + sin diacríticos (matching tolerante a acentos).
        self.register("fold", 1, Rc::new(|i, a, l| i.b_fold(a, l)));
        self.register("trim", 1, Rc::new(|i, a, l| i.b_trim(a, l)));
        self.register("starts_with", 2, Rc::new(|i, a, l| i.b_starts_with(a, l)));
        self.register("ends_with", 2, Rc::new(|i, a, l| i.b_ends_with(a, l)));
        self.register("replace_text", 3, Rc::new(|i, a, l| i.b_replace_text(a, l)));
        // Entrada de stdin (CLI): lee una línea; `nothing` en EOF. Funciona con pipe.
        self.register("read_line", -1, Rc::new(|i, a, l| i.b_read_line(a, l)));
        // Vuelca la salida pendiente a stdout en vivo (REPLs/loops largos). Ver b_flush.
        self.register("flush", 0, Rc::new(|i, _a, _l| i.b_flush()));
        // Estado del provider LLM: true si el motor cableó uno real (vs placeholder offline).
        self.register("llm_available", 0, Rc::new(|i, _a, _l| Ok(syn_bool(i.llm_callback.is_some()))));
        // Regex (computación pura, sin capability)
        self.register("matches", 2, Rc::new(|i, a, l| i.b_matches(a, l)));
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
        self.register("where", 2, Rc::new(|i, a, l| i.b_where(a, l)));
        self.register("collect", 2, Rc::new(|i, a, l| i.b_collect(a, l)));
        self.register("transform", -1, Rc::new(|i, a, l| i.b_transform(a, l)));
        self.register("reduce", -1, Rc::new(|i, a, l| i.b_reduce(a, l)));
        self.register("sort_by", 2, Rc::new(|i, a, l| i.b_sort_by(a, l)));
        self.register("group_by", 2, Rc::new(|i, a, l| i.b_group_by(a, l)));
        self.register("find_first", 2, Rc::new(|i, a, l| i.b_find_first(a, l)));
        self.register("every", 2, Rc::new(|i, a, l| i.b_every(a, l)));
        self.register("some", 2, Rc::new(|i, a, l| i.b_some(a, l)));
        self.register("count_where", 2, Rc::new(|i, a, l| i.b_count_where(a, l)));
        self.register("flatten", 1, Rc::new(|i, a, l| i.b_flatten(a, l)));
        self.register("zip_with", 3, Rc::new(|i, a, l| i.b_zip_with(a, l)));

        // -- Librería matemática (math.rs) — funciones puras sobre Number.
        // NOTA: NO se registra un builtin `log` (choca con el soft keyword de
        // observabilidad); se usan ln/log10/log2.
        // signo / magnitud / selección (preservan tipo)
        self.register("abs", 1, Rc::new(|_i, a, _l| crate::math::abs(a)));
        self.register("sign", 1, Rc::new(|_i, a, _l| crate::math::sign(a)));
        self.register("min", -1, Rc::new(|_i, a, _l| crate::math::min(a)));
        self.register("max", -1, Rc::new(|_i, a, _l| crate::math::max(a)));
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
        self.register("sum", -1, Rc::new(|_i, a, _l| crate::math::sum(a)));
        self.register("product", -1, Rc::new(|_i, a, _l| crate::math::product(a)));
        self.register("mean", -1, Rc::new(|_i, a, _l| crate::math::mean(a)));

        // -- Completitud matemática (Batch 4) --
        // Complejos: constructor + accesores (PUROS). Las transcendentales (sqrt/exp/…/pow)
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
        // Construcción.
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
        self.register("std", -1, Rc::new(|_i, a, _l| crate::arrays::std(a)));
        self.register("var", -1, Rc::new(|_i, a, _l| crate::arrays::var(a)));
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
                Ok(if value.syn_equals(&p) { Some(Vec::new()) } else { None })
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
            NodeKind::PropertyAccess { property_name, object } => {
                if let Some(id) = self.enum_variant_id(property_name, object, env)? {
                    return self.match_variant(value, &id, None, env);
                }
                let p = self.exec(pattern, env)?;
                Ok(if value.syn_equals(&p) { Some(Vec::new()) } else { None })
            }
            // Variante de enum con payload: `is Enum.variant(p1, …)` — sub-patrones.
            NodeKind::TaskCall { name, arguments } => {
                if let NodeKind::PropertyAccess { property_name, object } = &name.kind {
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
                Ok(if value.syn_equals(&p) { Some(Vec::new()) } else { None })
            }
            // Literal / cualquier otra expresión → patrón de valor.
            _ => {
                let p = self.exec(pattern, env)?;
                Ok(if value.syn_equals(&p) { Some(Vec::new()) } else { None })
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
    // Ejecución
    // =========================================================

    pub fn execute(&mut self, program: &Program) -> Result<SynValue, Control> {
        let g = self.global_env.clone();
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
                message: Some(control_message(&c)),
                assertion: matches!(&c, Control::Error(e) if e.is_assertion),
            }];
        }
        // Cada test en orden, aislado, con captura (no-abort, G5).
        let mut outcomes = Vec::new();
        for stmt in &program.statements {
            if let NodeKind::TestBlock { name, body } = &stmt.kind {
                let test_env = Environment::child(&g, &format!("test:{}", name));
                let outcome = match self.exec_block(body, &test_env) {
                    Ok(_) => {
                        TestOutcome { name: name.clone(), passed: true, message: None, assertion: false }
                    }
                    Err(Control::Error(e)) => TestOutcome {
                        name: name.clone(),
                        passed: false,
                        message: Some(e.to_string()),
                        assertion: e.is_assertion,
                    },
                    Err(c @ (Control::Give(_) | Control::Stop(_))) => TestOutcome {
                        name: name.clone(),
                        passed: false,
                        message: Some(control_message(&c)),
                        assertion: false,
                    },
                };
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
        for s in stmts {
            result = self.exec(s, env)?;
        }
        Ok(result)
    }

    fn exec(&mut self, node: &Node, env: &Rc<RefCell<Environment>>) -> Result<SynValue, Control> {
        let loc = &node.location;
        match &node.kind {
            // -- Literales --
            NodeKind::NumberLiteral { value } => Ok(syn_number(value.clone())),
            NodeKind::TextLiteral { value } => Ok(syn_text(value.as_str())),
            NodeKind::BoolLiteral { value } => Ok(syn_bool(*value)),
            NodeKind::NothingLiteral => Ok(SynValue::Nothing),
            NodeKind::ListLiteral { elements } => {
                let mut items = Vec::with_capacity(elements.len());
                for e in elements {
                    items.push(self.exec(e, env)?);
                }
                Ok(syn_list(items))
            }
            NodeKind::MapLiteral { pairs } => {
                let mut m = IndexMap::new();
                for (k, v) in pairs {
                    let key = self.exec(k, env)?;
                    let val = self.exec(v, env)?;
                    m.insert(key.to_string(), val);
                }
                Ok(syn_map(m))
            }

            // -- Identificadores y acceso --
            NodeKind::Identifier { name } => match env_get(env, name) {
                Some(v) => Ok(v),
                None => Err(err_at(format!("Undefined variable: '{}'", name), loc)),
            },
            NodeKind::PropertyAccess { property_name, object } => {
                let obj = self.exec(object, env)?;
                match &obj {
                    SynValue::Map(m) => match m.borrow().get(property_name) {
                        Some(v) => Ok(v.clone()),
                        None => Err(err_at(format!("Map has no key '{}'", property_name), loc)),
                    },
                    // Valores del servidor: acceso a su dict subyacente (body/status/…).
                    SynValue::Server(s) => match s.get_field(property_name) {
                        Some(v) => Ok(v),
                        None => Err(err_at(format!("Map has no key '{}'", property_name), loc)),
                    },
                    _ => Err(err_at(
                        format!("Cannot access property '{}' of {}", property_name, obj.type_name()),
                        loc,
                    )),
                }
            }
            NodeKind::IndexAccess { object, index } => {
                let obj = self.exec(object, env)?;
                let idx = self.exec(index, env)?;
                match &obj {
                    SynValue::List(l) => {
                        let items = l.borrow();
                        let i = num_to_i64(&idx)?;
                        if i < 0 || i >= items.len() as i64 {
                            return Err(err_at(
                                format!("Index {} out of bounds (list length {})", i, items.len()),
                                loc,
                            ));
                        }
                        Ok(items[i as usize].clone())
                    }
                    SynValue::Map(m) => {
                        let key = idx.to_string();
                        match m.borrow().get(&key) {
                            Some(v) => Ok(v.clone()),
                            None => Err(err_at(format!("Map has no key '{}'", key), loc)),
                        }
                    }
                    // `b[i]` → entero (valor del byte 0..=255). Sin índices negativos
                    // (out-of-bounds igual que la rama List; misma forma de mensaje).
                    SynValue::Bytes(b) => {
                        let i = num_to_i64(&idx)?;
                        if i < 0 || i >= b.len() as i64 {
                            return Err(err_at(
                                format!("Index {} out of bounds (bytes length {})", i, b.len()),
                                loc,
                            ));
                        }
                        Ok(syn_int(b[i as usize] as i64))
                    }
                    // `a[i]` → fila (nD) o escalar (1D). Negativo/fuera de rango → error.
                    SynValue::Array(a) => crate::arrays::index_row(a, num_to_i64(&idx)?),
                    _ => Err(err_at(format!("Cannot index into {}", obj.type_name()), loc)),
                }
            }

            // -- Operadores --
            NodeKind::BinaryOp { left, operator, right } => {
                let l = self.exec(left, env)?;
                let r = self.exec(right, env)?;
                self.exec_binary(l, operator, r, loc)
            }
            NodeKind::UnaryOp { operator, operand } => {
                let v = self.exec(operand, env)?;
                match operator.as_str() {
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
            NodeKind::PipeExpression { value, transforms } => {
                let mut v = self.exec(value, env)?;
                for t in transforms {
                    let func = self.exec(t, env)?;
                    v = self.call_value(func, vec![v], loc)?;
                }
                Ok(v)
            }

            // -- Bindings --
            NodeKind::LetBinding { name, value, .. } => {
                let v = self.exec(value, env)?;
                env_set(env, name, v.clone());
                Ok(v)
            }
            NodeKind::SetMutation { target, value } => {
                let v = self.exec(value, env)?;
                self.exec_set(target, v, env, loc)
            }

            // -- Control de flujo --
            NodeKind::WhenStatement { condition, body, otherwise, otherwise_when } => {
                let cond = self.exec(condition, env)?;
                if cond.is_truthy() {
                    self.exec_block(body, env)
                } else if let Some(ow) = otherwise_when {
                    self.exec(ow, env)
                } else if let Some(ob) = otherwise {
                    self.exec_block(ob, env)
                } else {
                    Ok(SynValue::Nothing)
                }
            }
            NodeKind::EachStatement { variable, collection, body } => {
                let coll = self.exec(collection, env)?;
                let items = match &coll {
                    SynValue::List(l) => l.borrow().clone(),
                    _ => return Err(err_at(format!("Cannot iterate over {}", coll.type_name()), loc)),
                };
                let mut result = SynValue::Nothing;
                for item in items {
                    let loop_env = Environment::child(env, &format!("each:{}", variable));
                    env_set(&loop_env, variable, item);
                    match self.exec_block(body, &loop_env) {
                        Ok(v) => result = v,
                        Err(Control::Stop(_)) => break,
                        Err(other) => return Err(other),
                    }
                }
                Ok(result)
            }
            NodeKind::WhileStatement { condition, body } => {
                let mut result = SynValue::Nothing;
                let max_iter = 1_000_000;
                let mut i = 0;
                while i < max_iter {
                    let cond = self.exec(condition, env)?;
                    if !cond.is_truthy() {
                        break;
                    }
                    match self.exec_block(body, env) {
                        Ok(v) => result = v,
                        Err(Control::Stop(_)) => break,
                        Err(other) => return Err(other),
                    }
                    i += 1;
                }
                if i >= max_iter {
                    return Err(err_at("Loop exceeded maximum iterations (1,000,000)", loc));
                }
                Ok(result)
            }
            NodeKind::MatchStatement { value, arms, otherwise } => {
                let v = self.exec(value, env)?;
                for arm in arms {
                    if let NodeKind::MatchArm { pattern, guard, body } = &arm.kind {
                        // El patrón liga (en patrones estructurales/variantes) o compara
                        // por valor (a nivel top, G2). `None` → no matchea, próximo arm.
                        let binds = match self.match_pattern_top(pattern, &v, env)? {
                            Some(b) => b,
                            None => continue,
                        };
                        // Los binders viven en un Environment HIJO scopeado al arm; el
                        // guard se evalúa con ellos en scope.
                        let arm_env = Environment::child(env, "match-arm");
                        for (name, val) in binds {
                            env_set(&arm_env, &name, val);
                        }
                        if let Some(g) = guard {
                            if !self.exec(g, &arm_env)?.is_truthy() {
                                continue; // guard falso → próximo arm
                            }
                        }
                        return self.exec_block(body, &arm_env);
                    }
                }
                // Ningún arm `is` matcheó: corré el bloque `otherwise` si existe.
                if let Some(body) = otherwise {
                    return self.exec_block(body, env);
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::StopStatement { value } => {
                let v = match value {
                    Some(n) => Some(self.exec(n, env)?),
                    None => None,
                };
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
                env_set(env, name, value.clone());
                Ok(value)
            }
            NodeKind::TaskCall { name, arguments } => {
                let func = self.exec(name, env)?;
                // Evaluá cada arg preservando su `name` (named vs posicional).
                let mut args = Vec::with_capacity(arguments.len());
                for arg in arguments {
                    let val = self.exec(&arg.value, env)?;
                    args.push((arg.name.clone(), val));
                }
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
                Err(Control::Give(v))
            }

            // -- Módulos locales (use / export) --
            NodeKind::UseImport { path, alias } => {
                let module_map = self.load_module(path, &loc.file)?;
                env_set(env, alias, module_map.clone());
                Ok(module_map)
            }
            NodeKind::ExportDeclaration { declaration } => {
                let value = self.exec(declaration, env)?;
                let name = match &declaration.kind {
                    NodeKind::TaskDefinition { name, .. }
                    | NodeKind::TypeDefinition { name, .. }
                    | NodeKind::LetBinding { name, .. }
                    | NodeKind::EnumDefinition { name, .. } => name.clone(),
                    _ => return Err(err_at("export must wrap a task, type, let, or enum", loc)),
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
                        return Err(err_at(format!("No agent defined with name '{}'", agent_name), loc))
                    }
                };
                let mut spawn_args = Vec::with_capacity(arguments.len());
                for (k, vn) in arguments {
                    spawn_args.push((k.clone(), self.exec(vn, env)?));
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
                        let id = spawn(agent_name, def.0, spawn_args, global_vals)?;
                        Ok(syn_text(id))
                    }
                    // Sin swarm: ejecución in-process (bloqueante), fallback.
                    None => {
                        let agent_env = Environment::child(&def.1, &format!("agent:{}", agent_name));
                        for (k, v) in spawn_args {
                            env_set(&agent_env, &k, v);
                        }
                        self.exec_block(&def.0, &agent_env)?;
                        Ok(syn_text(format!("agent:{}", agent_name)))
                    }
                }
            }

            // -- Blackboard --
            NodeKind::ShareStatement { value, key } => {
                let v = self.exec(value, env)?;
                let k = self.exec(key, env)?.to_string();
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
                let n = raw_str(&self.exec(name, env)?);
                let d = match data {
                    Some(d) => Some(self.exec(d, env)?),
                    None => None,
                };
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
                let result = match self.swarm_hooks.as_ref().map(|s| s.wait_for.clone()) {
                    Some(h) => h(&n, secs),
                    None => None,
                };
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
                        hook(capability, scope_val.as_deref());
                    }
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::SandboxBlock { body, .. } => {
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
            NodeKind::InvariantDeclaration { condition, description } => {
                let result = self.exec(condition, env)?;
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
            NodeKind::ApproveStatement { message, .. } => {
                let m = self.exec(message, env)?;
                match self.human_callback.clone() {
                    Some(cb) => Ok(cb("approve", &m.to_string())),
                    None => Ok(syn_bool(true)),
                }
            }
            NodeKind::ConfirmStatement { message } => {
                let m = self.exec(message, env)?;
                match self.human_callback.clone() {
                    Some(cb) => Ok(cb("confirm", &m.to_string())),
                    None => Ok(syn_bool(true)),
                }
            }
            NodeKind::ShowStatement { value, label } => {
                let v = self.exec(value, env)?;
                let label_str = match label {
                    Some(l) => format!("[{}] ", l),
                    None => String::new(),
                };
                let line = format!("{}{}", label_str, v);
                // DE-034: espejo de `log`/`print` — si hay log_hook (p.ej. bajo serve),
                // emitir en vivo además de bufferizar a `output`. Bajo `run` el hook es
                // None, así que el comportamiento no cambia.
                if let Some(hook) = &self.log_hook {
                    hook(&line);
                }
                self.output.push(line);
                Ok(v)
            }
            NodeKind::AskExpression { prompt, options } => {
                let p = self.exec(prompt, env)?;
                if let Some(cb) = self.human_callback.clone() {
                    let r = cb("ask", &p.to_string());
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
                let mut ctx_parts = Vec::new();
                for (name, v) in context {
                    ctx_parts.push(format!("{}={}", name, self.exec(v, env)?));
                }
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let prompt = if ctx_parts.is_empty() {
                            subj.to_string()
                        } else {
                            format!("Reason about: {} (context: {})", subj, ctx_parts.join(", "))
                        };
                        Ok(syn_text(cb("reason", &prompt)))
                    }
                    None => Ok(syn_text(format!("[reasoning about: {}]", subj))),
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
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let prompt = format!("Decide between {} given {}", opts, giv);
                        Ok(syn_text(cb("decide", &prompt)))
                    }
                    None => Ok(syn_text("[decision pending]")),
                }
            }
            NodeKind::AnalyzeExpression { data, objective } => {
                self.check_llm_cap()?;
                let d = self.exec(data, env)?;
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let prompt = format!("Analyze for {}: {}", objective, d);
                        Ok(syn_text(cb("analyze", &prompt)))
                    }
                    None => Ok(syn_text(format!("[analysis of: {}]", objective))),
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
                let mut param_parts = Vec::new();
                for (name, v) in parameters {
                    param_parts.push(format!("{}={}", name, self.exec(v, env)?));
                }
                match self.llm_callback.clone() {
                    Some(cb) => {
                        let mut prompt = format!("Generate {}", target);
                        if let Some(g) = &giv {
                            prompt.push_str(&format!(" given {}", g));
                        }
                        if !param_parts.is_empty() {
                            prompt.push_str(&format!(" with {}", param_parts.join(", ")));
                        }
                        Ok(syn_text(cb("generate", &prompt)))
                    }
                    None => Ok(syn_text(format!("[generated: {}]", target))),
                }
            }

            // -- Observabilidad --
            NodeKind::TraceBlock { body, .. } => self.exec_block(body, env),
            NodeKind::LogStatement { message, .. } => {
                let m = self.exec(message, env)?;
                let line = format!("[LOG] {}", m);
                if let Some(hook) = &self.log_hook {
                    hook(&line);
                }
                self.output.push(line);
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
                match self.exec_block(try_body, env) {
                    Ok(v) => Ok(v),
                    Err(Control::Give(v)) => Err(Control::Give(v)),
                    Err(Control::Stop(v)) => Err(Control::Stop(v)),
                    Err(Control::Error(e)) => {
                        let msg = strip_loc_prefix(&e.to_string());
                        let recover_env = Environment::child(env, "recover");
                        env_set(&recover_env, error_variable, syn_text(msg));
                        self.exec_block(recover_body, &recover_env)
                    }
                }
            }

            // -- HTTP server (lo provee el motor vía serve_hook en capa 8) --
            NodeKind::ServeBlock { .. } => match self.serve_hook.clone() {
                Some(hook) => hook(self, node, env),
                None => Err(err_at("serve is only available through the Synsema engine runtime", loc)),
            },
            NodeKind::RateLimitClause { .. } => Ok(SynValue::Nothing),
            NodeKind::ProxyStatement { .. } => {
                Err(err_at("proxy is only available inside a serve route", loc))
            }
            NodeKind::StreamBlock { body } => self.exec_block(body, env),
            NodeKind::SendStatement { value, event_name } => match self.stream_emit.clone() {
                Some(emit) => {
                    let v = self.exec(value, env)?;
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

    fn exec_binary(
        &mut self,
        left: SynValue,
        op: &str,
        right: SynValue,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        // Lógicos (Python evalúa AMBOS lados antes; no hay short-circuit acá).
        if op == "and" {
            return Ok(syn_bool(left.is_truthy() && right.is_truthy()));
        }
        if op == "or" {
            return Ok(syn_bool(left.is_truthy() || right.is_truthy()));
        }
        // Concatenación de texto (un operando texto coerciona el otro vía str()).
        if op == "+" {
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
        // Complex64 (Number→real, promoción). Va DESPUÉS de los concats de Text/List/Bytes
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
        // None si ningún operando es array → sigue al camino normal.
        if matches!(op, "+" | "-" | "*" | "/") {
            if let Some(res) = crate::arrays::array_binop(&left, &right, op) {
                return res;
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
                "**" => {
                    if a.is_zero() && b.is_negative() {
                        return Err(err_at("Zero cannot be raised to a negative power", loc));
                    }
                    return a.checked_pow(b).map(syn_number).map_err(|e| err_at(e, loc));
                }
                _ => {}
            }
        }
        // Comparación de igualdad. El OPERADOR `==`/`!=` erroría al mezclar Decimal y
        // Float (a diferencia de match/contains, que los consideran simplemente
        // distintos para mantener total esa comparación).
        if matches!(op, "==" | "!=") {
            if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
                if Number::mixes_decimal_float(a, b) {
                    return Err(err_at(MIX_DECIMAL_FLOAT, loc));
                }
            }
            let eq = left.syn_equals(&right);
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
        }
        Err(err_at(
            format!("Unsupported operation: {} {} {}", left.type_name(), op, right.type_name()),
            loc,
        ))
    }

    fn exec_set(
        &mut self,
        target: &Node,
        value: SynValue,
        env: &Rc<RefCell<Environment>>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        match &target.kind {
            NodeKind::Identifier { name } => {
                if env_update(env, name, value.clone()).is_err() {
                    return Err(err(format!(
                        "Cannot set undefined variable: '{}'. Use 'let' first.",
                        name
                    )));
                }
                Ok(value)
            }
            NodeKind::PropertyAccess { property_name, object } => {
                let obj = self.exec(object, env)?;
                match &obj {
                    SynValue::Map(m) => {
                        m.borrow_mut().insert(property_name.clone(), value.clone());
                        Ok(value)
                    }
                    _ => Err(err_at(format!("Cannot set property on {}", obj.type_name()), loc)),
                }
            }
            NodeKind::IndexAccess { object, index } => {
                let obj = self.exec(object, env)?;
                let idx = self.exec(index, env)?;
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
                        m.borrow_mut().insert(idx.to_string(), value.clone());
                        Ok(value)
                    }
                    _ => Err(err_at(format!("Cannot set index on {}", obj.type_name()), loc)),
                }
            }
            _ => Err(err_at("Invalid set target", loc)),
        }
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
                // Los builtins no declaran nombres de param: un arg nombrado es error
                // claro (sintaxis nueva, G3). El camino posicional queda intacto.
                let mut pos = Vec::with_capacity(args.len());
                for (name, v) in args {
                    if let Some(n) = name {
                        return Err(err_at(
                            format!("builtin '{}' does not accept named arguments", n),
                            loc,
                        ));
                    }
                    pos.push(v);
                }
                let f = bt.func.clone();
                f(self, &pos, loc)
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
                match self.exec_block(&task.body, &call_env) {
                    Ok(v) => Ok(v),
                    Err(Control::Give(v)) => Ok(v),
                    Err(other) => Err(other),
                }
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
    // Builtins (núcleo)
    // =========================================================

    fn b_print(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let s = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
        if let Some(hook) = &self.log_hook {
            hook(&s);
        }
        self.output.push(s);
        Ok(SynValue::Nothing)
    }

    fn b_length(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        match v {
            SynValue::Text(s) => Ok(syn_int(s.chars().count() as i64)),
            SynValue::List(l) => Ok(syn_int(l.borrow().len() as i64)),
            SynValue::Map(m) => Ok(syn_int(m.borrow().len() as i64)),
            SynValue::Bytes(b) => Ok(syn_int(b.len() as i64)),
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
            SynValue::Number(n) => Ok(SynValue::Number(n.clone())), // Int/Big ya son enteros
            _ => Err(err(format!("{} expects a number, got {}", name, v.type_name()))),
        }
    }

    fn b_to_number(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
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
            SynValue::Text(s) => match s.trim().parse::<f64>() {
                Ok(x) => x,
                Err(_) => return Err(err(format!("Cannot convert {} to number", v))),
            },
            _ => return Err(err(format!("Cannot convert {} to number", v))),
        };
        Ok(syn_float(f))
    }

    /// `decimal(x)` → Decimal exacto. `decimal("1234.56")`/`decimal(int)` exactos;
    /// `decimal(float)` → ERROR (usar string para evitar la imprecisión del float).
    fn b_decimal(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        let d = match v {
            SynValue::Number(Number::Decimal(d)) => *d,
            SynValue::Number(Number::Float(_)) => {
                return Err(err(
                    "decimal(float) is not exact; use a string, e.g. decimal(\"1.50\"), \
                     to avoid float imprecision",
                ))
            }
            SynValue::Number(n) => n
                .to_decimal()
                .ok_or_else(|| err("number too large for an exact decimal"))?,
            SynValue::Text(s) => rust_decimal::Decimal::from_str_exact(s.trim())
                .map_err(|_| err(format!("Cannot parse {} as a decimal", v)))?,
            _ => return Err(err(format!("Cannot convert {} to a decimal", v.type_name()))),
        };
        Ok(syn_number(Number::Decimal(d)))
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
        Ok(syn_bool(matches!(nth(args, 0)?, SynValue::Number(Number::Decimal(_)))))
    }

    /// `bytes(value, encoding?)` → bytes. PURO (sin capability). Conversión hacia
    /// binario; el `encoding` (2º arg) sólo aplica a un primer arg de texto.
    /// - `bytes(text)` / `bytes(text, "utf8")` → UTF-8 del texto.
    /// - `bytes(text, "hex")` → decodifica hex (error si longitud impar o char no-hex).
    /// - `bytes(text, "base64")` → decodifica base64 RFC-4648 con padding (error si inválido).
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
                    "hex" => crate::bytesutil::hex_decode(s).map(syn_bytes).map_err(err),
                    "base64" => crate::bytesutil::b64_decode(s).map(syn_bytes).map_err(err),
                    other => Err(err(format!(
                        "unsupported encoding {:?} for bytes(); use one of: utf8, hex, base64",
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
            other => Err(err(format!(
                "unsupported encoding {:?} for decode(); use one of: utf8, utf8_lossy, hex, base64",
                other
            ))),
        }
    }

    /// `is_bytes(x)` → true sólo si `x` es bytes.
    fn b_is_bytes(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        Ok(syn_bool(matches!(nth(args, 0)?, SynValue::Bytes(_))))
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
    fn b_raise(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match args.first() {
            Some(v) => Err(err(raw_str(v))),
            None => Err(err("raise expects a message")),
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

    fn b_keys(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        match nth(args, 0)? {
            SynValue::Map(m) => {
                let keys: Vec<SynValue> = m.borrow().keys().map(|k| syn_text(k.as_str())).collect();
                Ok(syn_list(keys))
            }
            _ => Err(err("keys() requires a map")),
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
                for e in l.borrow().iter() {
                    if e.syn_equals(item) {
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
            return Err(err("empty separator"));
        }
        let parts: Vec<SynValue> = text.split(&sep).map(syn_text).collect();
        Ok(syn_list(parts))
    }

    fn b_join(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let lst = nth(args, 0)?;
        let sep = raw_str(nth(args, 1)?);
        match lst {
            SynValue::List(l) => {
                let parts: Vec<String> = l.borrow().iter().map(|v| v.to_string()).collect();
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
            _ => Err(err(format!("Cannot slice {}", coll.type_name()))),
        }
    }

    fn b_fmt(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let mut template = raw_str(nth(args, 0)?);
        if args.len() > 1 {
            if let SynValue::Map(m) = &args[1] {
                for (k, v) in m.borrow().iter() {
                    template = template.replace(&format!("{{{}}}", k), &v.to_string());
                }
            }
        }
        Ok(syn_text(template))
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
        for line in self.output.drain(..) {
            println!("{}", line);
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
    // Operaciones intencionales
    // =========================================================

    fn list_arg(&self, v: &SynValue, who: &str) -> Result<Vec<SynValue>, Control> {
        match v {
            SynValue::List(l) => Ok(l.borrow().clone()),
            _ => Err(err(format!("{} expects a list, got {}", who, v.type_name()))),
        }
    }

    fn b_apply(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let func = nth(args, 0)?.clone();
        let items = self.list_arg(nth(args, 1)?, "apply")?;
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
            None => StepResult::Final { text: "[no llm provider]".to_string(), tokens: 0 },
        };
        Ok(step_result_to_synvalue(result))
    }

    fn b_where(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "where")?;
        let pred = nth(args, 1)?.clone();
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
        let items = self.list_arg(nth(args, 0)?, "transform")?;
        let func = nth(args, 1)?.clone();
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
        let items = self.list_arg(nth(args, 0)?, "reduce")?;
        let func = nth(args, 1)?.clone();
        let mut acc = args.get(2).cloned().unwrap_or_else(|| syn_int(0));
        for item in items {
            acc = self.call_value(func.clone(), vec![acc, item], loc)?;
        }
        Ok(acc)
    }

    fn b_sort_by(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "sort_by")?;
        let key_func = nth(args, 1)?.clone();
        let mut keyed: Vec<(SynValue, SynValue)> = Vec::with_capacity(items.len());
        for it in items {
            let k = self.call_value(key_func.clone(), vec![it.clone()], loc)?;
            keyed.push((k, it));
        }
        keyed.sort_by(|(ka, _), (kb, _)| sort_cmp(ka, kb));
        Ok(syn_list(keyed.into_iter().map(|(_, v)| v).collect()))
    }

    fn b_group_by(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "group_by")?;
        let key_func = nth(args, 1)?.clone();
        let mut groups: IndexMap<String, Vec<SynValue>> = IndexMap::new();
        for item in items {
            let key = self.call_value(key_func.clone(), vec![item.clone()], loc)?.to_string();
            groups.entry(key).or_default().push(item);
        }
        let mut result = IndexMap::new();
        for (k, v) in groups {
            result.insert(k, syn_list(v));
        }
        Ok(syn_map(result))
    }

    fn b_find_first(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "find_first")?;
        let pred = nth(args, 1)?.clone();
        for item in items {
            if self.call_value(pred.clone(), vec![item.clone()], loc)?.is_truthy() {
                return Ok(item);
            }
        }
        Ok(SynValue::Nothing)
    }

    fn b_every(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "every")?;
        let pred = nth(args, 1)?.clone();
        for item in items {
            if !self.call_value(pred.clone(), vec![item], loc)?.is_truthy() {
                return Ok(syn_bool(false));
            }
        }
        Ok(syn_bool(true))
    }

    fn b_some(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "some")?;
        let pred = nth(args, 1)?.clone();
        for item in items {
            if self.call_value(pred.clone(), vec![item], loc)?.is_truthy() {
                return Ok(syn_bool(true));
            }
        }
        Ok(syn_bool(false))
    }

    fn b_count_where(&mut self, args: &[SynValue], loc: &SourceLocation) -> Result<SynValue, Control> {
        let items = self.list_arg(nth(args, 0)?, "count_where")?;
        let pred = nth(args, 1)?.clone();
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
        let a = self.list_arg(nth(args, 0)?, "zip_with")?;
        let b = self.list_arg(nth(args, 1)?, "zip_with")?;
        let combiner = nth(args, 2)?.clone();
        let mut out = Vec::new();
        for (x, y) in a.into_iter().zip(b.into_iter()) {
            out.push(self.call_value(combiner.clone(), vec![x, y], loc)?);
        }
        Ok(syn_list(out))
    }
}

// =========================================================
// Helpers libres
// =========================================================

fn nth(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
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
/// Display, igual que la concatenación normal). El nombre se hereda del primer
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

fn num_to_i64(v: &SynValue) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) => n.to_i64_trunc().ok_or_else(|| err("number too large for index")),
        _ => Err(err(format!("expected a number, got {}", v.type_name()))),
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

fn sort_cmp(a: &SynValue, b: &SynValue) -> Ordering {
    match (a, b) {
        (SynValue::Number(x), SynValue::Number(y)) => x.partial_cmp_num(y).unwrap_or(Ordering::Equal),
        (SynValue::Text(x), SynValue::Text(y)) => x.as_ref().cmp(y.as_ref()),
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
// Runner mínimo (espejo de engine.run_source para los tests de capa 4)
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
        .unwrap_or_else(|_| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec!["el intérprete abortó (probable desborde de stack nativo)".to_string()],
        })
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
    fn lambda_missing_arg_binds_nothing() {
        assert_eq!(out("let f be (a, b) => b\nprint(text(f(5)))"), vec!["nothing"]);
    }

    #[test]
    fn lambda_extra_args_ignored() {
        assert_eq!(out("let f be (x) => x\nprint(text(f(1, 2, 3)))"), vec!["1"]);
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
    fn match_and_contains_decimal_vs_float_unequal_no_error() {
        // match: un Decimal contra un patrón Float NO matchea (y NO erroría).
        let m = "let d be 1.5d\nmatch d\n    is 1.5\n        print(\"float\")\n    is 1.5d\n        print(\"decimal\")\n    otherwise\n        print(\"otro\")\n";
        assert_eq!(line(m), "decimal");
        // contains: Decimal vs Float → false (sin error); Decimal vs Decimal → true.
        assert_eq!(line("print(text(contains([1.5d], 1.5)))"), "false");
        assert_eq!(line("print(text(contains([1.5d], 1.5d)))"), "true");
        assert_eq!(line("print(text(contains([1.5], 1.5d)))"), "false");
    }
}
