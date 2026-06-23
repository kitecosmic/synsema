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
use regex::Regex;

use crate::ast::{Node, NodeKind, Program};
use crate::number::Number;
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
}

impl RuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: false, field: None }
    }
    pub fn at(message: impl Into<String>, location: SourceLocation) -> Self {
        Self { message: message.into(), location: Some(location), is_validation: false, field: None }
    }
    /// Error de validación de cliente (input que no cumple `expect`): se mapea a HTTP 400
    /// con el nombre del campo ofensor, en vez de a un 500 genérico.
    pub fn validation(message: impl Into<String>, field: Option<String>) -> Self {
        Self { message: message.into(), location: None, is_validation: true, field }
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
    pub wait_for: Rc<dyn Fn(&str) -> Option<SynValue>>,
    #[allow(clippy::type_complexity)]
    pub spawn: Rc<dyn Fn(&str, Vec<Node>, Vec<(String, SynValue)>) -> Result<String, Control>>,
}

pub struct Interpreter {
    pub global_env: Rc<RefCell<Environment>>,
    pub output: Vec<String>,
    pub blackboard: HashMap<String, SynValue>,
    pub agent_definitions: HashMap<String, (Vec<Node>, Rc<RefCell<Environment>>)>,
    recursion_depth: usize,
    /// Concede capabilities declaradas con `require` (lo cablea el motor).
    grant_hook: Option<GrantHook>,
    /// Intent declarado (descriptivo). El texto no gatea nada.
    intent: Option<String>,
    /// True una vez congelado el intent (tras el preámbulo) — anti prompt-injection.
    intent_frozen: bool,
    /// Conexión al swarm real (lo cablea el motor para agentes en hilos).
    swarm_hooks: Option<SwarmHooks>,
    /// Callback humano (approve/confirm/ask). (action, message) → SynValue
    /// (bool para approve/confirm, texto para ask). Sin él: auto-aprueba.
    human_callback: Option<Rc<dyn Fn(&str, &str) -> SynValue>>,
    /// Callback LLM (reason/decide/analyze/generate): operación → contenido.
    /// Sin él: placeholders descriptivos.
    llm_callback: Option<Rc<dyn Fn(&str) -> String>>,
    /// Hook de `serve on PORT` (lo cablea el motor en el camino de serve).
    serve_hook: Option<ServeHook>,
    /// Sink de `send` dentro de un handler de stream SSE (lo cablea el motor por
    /// request de streaming). (value, event_name) → (). Sin él, `send` es error.
    stream_emit: Option<Rc<dyn Fn(SynValue, Option<&str>) -> Result<(), Control>>>,
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
            intent: None,
            intent_frozen: false,
            swarm_hooks: None,
            human_callback: None,
            llm_callback: None,
            serve_hook: None,
            stream_emit: None,
            module_cache: HashMap::new(),
            loading_modules: HashSet::new(),
            exports_collector: vec![Vec::new()],
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

    /// Cablea el callback LLM (reason/decide/analyze/generate).
    pub fn set_llm_callback(&mut self, cb: Rc<dyn Fn(&str) -> String>) {
        self.llm_callback = Some(cb);
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
        self.register("trim", 1, Rc::new(|i, a, l| i.b_trim(a, l)));
        self.register("starts_with", 2, Rc::new(|i, a, l| i.b_starts_with(a, l)));
        self.register("ends_with", 2, Rc::new(|i, a, l| i.b_ends_with(a, l)));
        self.register("replace_text", 3, Rc::new(|i, a, l| i.b_replace_text(a, l)));
        // Regex (computación pura, sin capability)
        self.register("matches", 2, Rc::new(|i, a, l| i.b_matches(a, l)));
        self.register("find_all", 2, Rc::new(|i, a, l| i.b_find_all(a, l)));
        self.register("capture", 2, Rc::new(|i, a, l| i.b_capture(a, l)));
        self.register("replace_re", 3, Rc::new(|i, a, l| i.b_replace_re(a, l)));
        // SSR templates — requiere el engine; error fuera de él
        self.register("render", -1, Rc::new(|i, a, l| i.b_render(a, l)));
        // Operaciones intencionales
        self.register("apply", 2, Rc::new(|i, a, l| i.b_apply(a, l)));
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
    }

    /// Si `pattern` es un acceso `Enum.variant` cuyo objeto evalúa a un map
    /// namespace de enum (tiene "__enum"), devuelve el id calificado
    /// ("Enum.variant"); si no, None (→ el caller usa igualdad de valor).
    fn variant_pattern_id(
        &mut self,
        pattern: &Node,
        env: &Rc<RefCell<Environment>>,
    ) -> Result<Option<String>, Control> {
        if let NodeKind::PropertyAccess { property_name, object } = &pattern.kind {
            let obj = self.exec(object, env)?;
            if let SynValue::Map(m) = &obj {
                if let Some(SynValue::Text(enum_name)) = m.borrow().get("__enum") {
                    return Ok(Some(format!("{}.{}", enum_name, property_name)));
                }
            }
        }
        Ok(None)
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
                    if let NodeKind::MatchArm { pattern, body } = &arm.kind {
                        // Patrón de variante `Enum.variant`: match por discriminante
                        // ("__variant"), payload ignorado.
                        if let Some(variant_id) = self.variant_pattern_id(pattern, env)? {
                            let is_match = if let SynValue::Map(m) = &v {
                                matches!(
                                    m.borrow().get("__variant"),
                                    Some(SynValue::Text(t)) if t.as_ref() == variant_id.as_str()
                                )
                            } else {
                                false
                            };
                            if is_match {
                                return self.exec_block(body, env);
                            }
                            continue;
                        }
                        // Cualquier otro patrón: la igualdad de valor de SIEMPRE.
                        let p = self.exec(pattern, env)?;
                        if v.syn_equals(&p) {
                            return self.exec_block(body, env);
                        }
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
                let mut args = Vec::with_capacity(arguments.len());
                for arg in arguments {
                    args.push(self.exec(arg, env)?);
                }
                self.call_value(func, args, loc)
            }
            NodeKind::LambdaExpression { parameters, body } => {
                // Una lambda es un task anónimo cuyo cuerpo es un `give <expr>`
                // implícito, que cierra sobre el entorno actual. Se reusa el
                // camino de llamada existente (entorno hijo → bind params →
                // exec body → catch Give). No se hace env_set: es anónima.
                let task = Rc::new(SynTaskValue {
                    name: "<lambda>".to_string(),
                    parameters: parameters.clone(),
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
                        let id = spawn(agent_name, def.0, spawn_args)?;
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
                let d = match data {
                    Some(d) => Some(self.exec(d, env)?),
                    None => None,
                };
                if let Some(h) = self.swarm_hooks.as_ref().map(|s| s.signal.clone()) {
                    h(name, d);
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::WaitForStatement { signal_name, variable, .. } => {
                let result = match self.swarm_hooks.as_ref().map(|s| s.wait_for.clone()) {
                    Some(h) => h(signal_name),
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
                if let Some(hook) = self.grant_hook.clone() {
                    hook(capability, scope_val.as_deref());
                }
                Ok(SynValue::Nothing)
            }
            NodeKind::SandboxBlock { body, .. } => {
                let sandbox_env = Environment::child(env, "sandbox");
                self.exec_block(body, &sandbox_env)
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
                self.output.push(format!("{}{}", label_str, v));
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
                let subj = match subject {
                    Some(s) => self.exec(s, env)?,
                    None => SynValue::Nothing,
                };
                for (_, v) in context {
                    self.exec(v, env)?;
                }
                match self.llm_callback.clone() {
                    Some(cb) => Ok(syn_text(cb("reason"))),
                    None => Ok(syn_text(format!("[reasoning about: {}]", subj))),
                }
            }
            NodeKind::DecideExpression { options, given, .. } => {
                if let Some(o) = options {
                    self.exec(o, env)?;
                }
                if let Some(g) = given {
                    self.exec(g, env)?;
                }
                match self.llm_callback.clone() {
                    Some(cb) => Ok(syn_text(cb("decide"))),
                    None => Ok(syn_text("[decision pending]")),
                }
            }
            NodeKind::AnalyzeExpression { data, objective } => {
                self.exec(data, env)?;
                match self.llm_callback.clone() {
                    Some(cb) => Ok(syn_text(cb("analyze"))),
                    None => Ok(syn_text(format!("[analysis of: {}]", objective))),
                }
            }
            NodeKind::GenerateExpression { target, given, parameters } => {
                if let Some(g) = given {
                    self.exec(g, env)?;
                }
                for (_, v) in parameters {
                    self.exec(v, env)?;
                }
                match self.llm_callback.clone() {
                    Some(cb) => Ok(syn_text(cb("generate"))),
                    None => Ok(syn_text(format!("[generated: {}]", target))),
                }
            }

            // -- Observabilidad --
            NodeKind::TraceBlock { body, .. } => self.exec_block(body, env),
            NodeKind::LogStatement { message, .. } => {
                let m = self.exec(message, env)?;
                self.output.push(format!("[LOG] {}", m));
                Ok(SynValue::Nothing)
            }
            NodeKind::MeasureBlock { body, .. } => self.exec_block(body, env),
            NodeKind::CheckpointStatement { .. } => Ok(SynValue::Nothing),

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
            if let (SynValue::List(l), SynValue::List(r)) = (&left, &right) {
                let mut v = l.borrow().clone();
                v.extend(r.borrow().iter().cloned());
                return Ok(syn_list(v));
            }
        }
        // Aritmética
        if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
            match op {
                "+" => return Ok(syn_number(a.add(b))),
                "-" => return Ok(syn_number(a.sub(b))),
                "*" => return Ok(syn_number(a.mul(b))),
                "/" => {
                    if b.is_zero() {
                        return Err(err_at("Division by zero", loc));
                    }
                    return Ok(syn_number(a.div(b)));
                }
                "%" => {
                    return match a.modulo(b) {
                        Some(n) => Ok(syn_number(n)),
                        None => Err(err_at("Modulo by zero", loc)),
                    }
                }
                "**" => {
                    if a.is_zero() && b.is_negative() {
                        return Err(err_at("Zero cannot be raised to a negative power", loc));
                    }
                    return Ok(syn_number(a.pow(b)));
                }
                _ => {}
            }
        }
        // Comparación de igualdad
        if op == "==" {
            return Ok(syn_bool(left.syn_equals(&right)));
        }
        if op == "!=" {
            return Ok(syn_bool(!left.syn_equals(&right)));
        }
        // Orden
        if matches!(op, "<" | ">" | "<=" | ">=") {
            if let (SynValue::Number(a), SynValue::Number(b)) = (&left, &right) {
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

    fn call_value(
        &mut self,
        func: SynValue,
        args: Vec<SynValue>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        self.recursion_depth += 1;
        if self.recursion_depth > MAX_RECURSION {
            self.recursion_depth -= 1;
            return Err(err("maximum recursion depth exceeded"));
        }
        let result = self.call_value_inner(func, args, loc);
        self.recursion_depth -= 1;
        result
    }

    fn call_value_inner(
        &mut self,
        func: SynValue,
        args: Vec<SynValue>,
        loc: &SourceLocation,
    ) -> Result<SynValue, Control> {
        match func {
            SynValue::Builtin(bt) => {
                let f = bt.func.clone();
                f(self, &args, loc)
            }
            SynValue::Task(task) => {
                let call_env = Environment::child(&task.closure_env, &format!("call:{}", task.name));
                for (i, param) in task.parameters.iter().enumerate() {
                    let v = args.get(i).cloned().unwrap_or(SynValue::Nothing);
                    env_set(&call_env, param, v);
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
        self.output.push(s);
        Ok(SynValue::Nothing)
    }

    fn b_length(&mut self, args: &[SynValue], _loc: &SourceLocation) -> Result<SynValue, Control> {
        let v = nth(args, 0)?;
        match v {
            SynValue::Text(s) => Ok(syn_int(s.chars().count() as i64)),
            SynValue::List(l) => Ok(syn_int(l.borrow().len() as i64)),
            SynValue::Map(m) => Ok(syn_int(m.borrow().len() as i64)),
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
