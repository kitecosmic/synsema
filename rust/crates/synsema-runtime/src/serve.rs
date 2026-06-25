//! Puente del motor para `serve on PORT { … }`. Análogo de `engine._run_serve`.
//!
//! Modelo de aislamiento (paridad con el oráculo + restricción `!Send` del intérprete):
//! el top-level corre UNA vez en el hilo del motor; al ejecutar el bloque serve se
//! toma un **snapshot `Send`** de los globales (valores + definiciones de tasks) y se
//! arma el `ServeRuntime`. Cada request corre en su hilo de conexión (`std::thread`)
//! con un intérprete fresco reconstruido desde ese snapshot, compartiendo el swarm
//! (blackboard) vía `Arc`. Es exactamente el aislamiento documentado: "lo único
//! compartido es el blackboard y la base de datos".

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

/// Callback de persistencia que se llama tras cada mutación de memoria desde
/// un route handler. Encapsula el `StatePersistence` protegido por mutex.
type OnWriteFn = Arc<dyn Fn(&AgentMemory) + Send + Sync>;

/// Memoria compartida entre todos los handlers de un serve: el `AgentMemory`
/// vive en un `Arc<Mutex>` para ser accesible desde múltiples hilos del pool.
type SharedMemoryStore = Arc<Mutex<AgentMemory>>;
use std::thread::JoinHandle;

use indexmap::IndexMap;

use synsema_agents::builtins::register_serve_memory_builtins;
use synsema_agents::memory::{AgentMemory, OwnerRule};
use synsema_agents::progress::ProgressManager;
use synsema_agents::swarm::Swarm;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::ast::{Node, NodeKind, Param};
use synsema_core::interpreter::{
    BuiltinTask, Control, Environment, Interpreter, RunResult, RuntimeError, ServeHook,
};
use synsema_core::number::Number;
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{
    from_send, syn_bool, syn_bytes, syn_map, syn_nothing, syn_text, to_send, SendValue,
    SynTaskValue, SynValue,
};
use synsema_stdlib::acme;
use synsema_stdlib::database::{register_database_builtins, DatabaseManager};
use synsema_stdlib::server::{
    self, json_to_syn, serve_forever, AuthHandler, Ctx, Emitter, GiveOutcome, Handler, RouteSpec,
    ServeRuntime, StreamEnd, StreamGone, StreamHandler,
};

/// Manager de base de datos compartido entre el top-level y los hilos de conexión.
type SharedDb = Arc<Mutex<DatabaseManager>>;

/// Estado mutable compartido entre todos los route handlers de un serve.
/// Respaldo de `state_set`/`state_get`/`state_incr` — alternativa explícita
/// a mutar globales (que no se propagan entre requests por diseño).
type SharedState = Arc<Mutex<HashMap<String, SendValue>>>;

use crate::engine::{wire_common_with_state, wire_swarm_hooks, INTERP_STACK_SIZE};

// =========================================================
// Overrides de despliegue por CLI (Pieza A)
// =========================================================

/// Config de despliegue inyectada por flags de `synsema serve` (capa de lanzamiento).
/// NO toca la gramática del `serve` (sigue declarativo). Precedencia: **flag > cláusula
/// del archivo > default**. Todos los campos son `Send` (cruzan al hilo del motor).
#[derive(Clone, Default)]
pub struct ServeOverrides {
    /// `--port N`: sobreescribe `serve on N` y **concede** la capability `serve(N)`.
    pub port: Option<u16>,
    /// `--domain d1,d2,…`: dominios del cert SAN de ACME (pisa `domain` del archivo).
    pub domains: Option<Vec<String>>,
    /// `--tls-auto <email>`: prende auto-HTTPS (ACME). Su presencia es el toggle dev↔prod.
    pub tls_auto_email: Option<String>,
    /// `--tls-cert <path>`: TLS manual (excluyente con `--tls-auto`).
    pub tls_cert: Option<String>,
    /// `--tls-key <path>`: par de `--tls-cert`.
    pub tls_key: Option<String>,
    /// `--bind <addr>`: dirección de bind (default `0.0.0.0`).
    pub bind: Option<String>,
}

impl ServeOverrides {
    /// True si no se pasó ningún flag de despliegue.
    pub fn is_empty(&self) -> bool {
        self.port.is_none()
            && self.domains.is_none()
            && self.tls_auto_email.is_none()
            && self.tls_cert.is_none()
            && self.tls_key.is_none()
            && self.bind.is_none()
    }

    /// Validación fail-loud de combinaciones inválidas (independiente del archivo).
    /// La ausencia de dominio para `--tls-auto` se valida en el hook (puede venir del
    /// archivo). El rango de puerto ya queda validado al parsear (`u16`, > 0).
    pub fn validate(&self) -> Result<(), String> {
        if self.tls_auto_email.is_some() && (self.tls_cert.is_some() || self.tls_key.is_some()) {
            return Err(
                "--tls-auto and --tls-cert/--tls-key are mutually exclusive (choose one)".to_string(),
            );
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err("--tls-cert and --tls-key must be provided together".to_string());
        }
        Ok(())
    }
}

// =========================================================
// Snapshot de globales (Send) → reconstrucción por request
// =========================================================

pub(crate) enum GlobalVal {
    Value(SendValue),
    Task {
        name: String,
        parameters: Vec<Param>,
        body: Vec<Node>,
        required_capabilities: Vec<(String, Option<String>)>,
    },
    /// Definición de agente (Batch 6): las defs de agentes viven en
    /// `Interpreter.agent_definitions` (fuera de `global_env.bindings`), así que se
    /// snapshotean/restauran aparte para que un `spawn` desde una route las encuentre. El
    /// nombre va en la clave de la tupla; el `body` (Vec<Node>) es `Send` y clonable.
    Agent {
        body: Vec<Node>,
    },
    /// Un módulo importado (`use "…" as name`) — map cuyas entradas pueden ser Tasks
    /// u otros GlobalVal. Se snapshotea recursivamente para que las tasks del módulo
    /// sobrevivan al cruce de hilos (parallel_map) y al snapshot de serve, en lugar de
    /// degradarse a texto a través de to_send/from_send.
    Module(Vec<(String, GlobalVal)>),
}

/// Convierte un `SynValue` a `GlobalVal` de forma recursiva. Los Maps que contienen
/// Tasks (patrón módulo importado) se convierten en `GlobalVal::Module` para que las
/// tasks sobrevivan el cruce de hilos y el snapshot de serve sin degradarse a texto.
pub(crate) fn val_to_global(v: &SynValue) -> GlobalVal {
    match v {
        SynValue::Task(t) => GlobalVal::Task {
            name: t.name.clone(),
            parameters: t.parameters.clone(),
            body: t.body.clone(),
            required_capabilities: t.required_capabilities.clone(),
        },
        SynValue::Builtin(_) => GlobalVal::Value(to_send(v)),
        SynValue::Map(m) => {
            let entries: Vec<(String, GlobalVal)> = m
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), val_to_global(v)))
                .collect();
            // Si alguna entrada es Task o Module anidado, usar Module para conservarlas.
            // Maps puramente de valores primitivos siguen viajando como SendValue (barato).
            if entries.iter().any(|(_, gv)| !matches!(gv, GlobalVal::Value(_))) {
                GlobalVal::Module(entries)
            } else {
                GlobalVal::Value(to_send(&SynValue::Map(m.clone())))
            }
        }
        other => GlobalVal::Value(to_send(other)),
    }
}

/// Reconstruye un `SynValue` desde un `GlobalVal`, apuntando las tasks al `global_env`
/// del intérprete nuevo para que puedan llamar a otros globales (recursión mutua, etc.).
fn rebuild_global_val(gv: &GlobalVal, global_env: &Rc<RefCell<Environment>>) -> SynValue {
    match gv {
        GlobalVal::Value(sv) => from_send(sv),
        GlobalVal::Task { name, parameters, body, required_capabilities } => {
            SynValue::Task(Rc::new(SynTaskValue {
                name: name.clone(),
                parameters: parameters.clone(),
                body: body.clone(),
                closure_env: global_env.clone(),
                origin: None,
                required_capabilities: required_capabilities.clone(),
            }))
        }
        GlobalVal::Module(entries) => {
            let mut m = IndexMap::new();
            for (k, gv) in entries {
                m.insert(k.clone(), rebuild_global_val(gv, global_env));
            }
            SynValue::Map(Rc::new(RefCell::new(m)))
        }
        GlobalVal::Agent { .. } => {
            // Los agentes van a `agent_definitions`, nunca a bindings — no debería llegar aquí.
            SynValue::Nothing
        }
    }
}

/// Snapshot de las bindings globales (tras correr el top-level). Los builtins se
/// re-registran por intérprete (no se copian); las tasks se copian con su AST;
/// los módulos importados (maps con tasks) se snapshotean recursivamente.
pub(crate) fn snapshot_globals(interp: &Interpreter) -> Arc<Vec<(String, GlobalVal)>> {
    let env = interp.global_env.borrow();
    let mut out: Vec<(String, GlobalVal)> = Vec::new();
    for (k, v) in env.bindings.iter() {
        if matches!(v, SynValue::Builtin(_)) {
            continue; // re-registrados por wire_common
        }
        out.push((k.clone(), val_to_global(v)));
    }
    // Agentes (Batch 6): viven en `agent_definitions`, no en `bindings` → se snapshotean
    // aparte (sólo el body; el closure_env se re-apunta al global del nuevo intérprete).
    for (name, (body, _env)) in interp.agent_definitions.iter() {
        out.push((name.clone(), GlobalVal::Agent { body: body.clone() }));
    }
    Arc::new(out)
}

/// Reconstruye los globales en un intérprete fresco. Las tasks (top-level y dentro de
/// módulos) se recrean con su closure apuntando al global del nuevo intérprete para que
/// la recursión mutua y el acceso a otros globales sigan funcionando.
pub(crate) fn rebuild_globals(interp: &mut Interpreter, snapshot: &[(String, GlobalVal)]) {
    for (k, gv) in snapshot {
        match gv {
            // Agentes (Batch 6): van al mapa separado `agent_definitions` (NO a bindings),
            // con el closure apuntando al global del intérprete nuevo (como las tasks). Sin
            // esto, un `spawn Worker` desde una route daría "No agent defined".
            GlobalVal::Agent { body } => {
                let genv = interp.global_env.clone();
                interp.agent_definitions.insert(k.clone(), (body.clone(), genv));
            }
            other => {
                let v = rebuild_global_val(other, &interp.global_env.clone());
                interp.set_global(k, v);
            }
        }
    }
}

/// Intérprete base de un serve: wiring común + hooks del swarm + db compartida +
/// globales (tasks+valores). La db compartida (Arc<Mutex>) sobrescribe la db fresca
/// de wire_common para que los handlers vean las tablas/datos abiertos en el top-level.
///
/// Registra los builtins de estado compartido (`state_set`/`state_get`/`state_incr`)
/// para un serve. El `SharedState` es un `HashMap<String, SendValue>` bajo `Arc<Mutex>`
/// — compartido entre todos los route handlers y entre requests, con la misma vida que
/// el servidor. No persiste a disco (para persistencia usar SQL o `remember`).
fn register_serve_state_builtins(interp: &Interpreter, state: SharedState) {
    {
        let s = state.clone();
        interp.register_builtin("state_set", 2, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_set: missing key"))),
            };
            let val = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            s.lock().unwrap().insert(key, to_send(&val));
            Ok(val)
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_get", -1, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_get: missing key"))),
            };
            let guard = s.lock().unwrap();
            match guard.get(&key) {
                Some(sv) => Ok(from_send(sv)),
                None => Ok(args.get(1).cloned().unwrap_or(SynValue::Nothing)),
            }
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_incr", -1, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_incr: missing key"))),
            };
            let delta = match args.get(1) {
                Some(SynValue::Number(n)) => n.to_f64(),
                _ => 1.0,
            };
            let mut guard = s.lock().unwrap();
            let current = match guard.get(&key) {
                Some(SendValue::Number(n)) => n.to_f64(),
                _ => 0.0,
            };
            let new_val = current + delta;
            guard.insert(key, to_send(&SynValue::Number(synsema_core::number::Number::Float(new_val))));
            Ok(SynValue::Number(synsema_core::number::Number::Float(new_val)))
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_delete", 1, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_delete: missing key"))),
            };
            s.lock().unwrap().remove(&key);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_all", 0, Rc::new(move |_i, _args, _l| {
            let guard = s.lock().unwrap();
            let mut map = IndexMap::new();
            for (k, sv) in guard.iter() {
                map.insert(k.clone(), from_send(sv));
            }
            Ok(SynValue::Map(Rc::new(RefCell::new(map))))
        }));
    }
}

/// Construir esto es CARO (registrar ~100 builtins + recargar `.env` + clonar el AST
/// de cada task) y era el ~46% del CPU por request (medido en la VPS: profile-first).
/// Ahora se construye UNA vez por worker y se reusa entre requests (ver
/// `with_serve_interp`), no por request. Devuelve el `CapabilitySet` para poder
/// resetearlo entre requests (los grants del preámbulo, vía el `Rc` que capturan los
/// builtins gateados: secret/env/reveal/fetch/…).
fn build_base_interp(
    swarm: Arc<Swarm>,
    snapshot: &[(String, GlobalVal)],
    caps_snap: &[Capability],
    shared_db: SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_state: &SharedState,
    secure: bool,
) -> (Interpreter, Rc<RefCell<CapabilitySet>>) {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("request")));
    // Pre-populamos el AgentMemory con las reglas del top-level para que
    // add_rule/check_rules/get_rules funcionen desde los route handlers.
    let mut mem = AgentMemory::new();
    for rule in rules_snap.iter() {
        mem.rules.insert(rule.name.clone(), rule.clone());
    }
    wire_common_with_state(
        &mut interp,
        &caps,
        secure,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(mem)),
    );
    // Sobrescribir los builtins de memoria (remember/recall/forget_memory/memory_summary)
    // con versiones que usan el AgentMemory compartido entre hilos.
    register_serve_memory_builtins(&interp, shared_memory.clone(), on_write.clone());
    // Registrar los builtins de estado compartido (state_set/state_get/state_incr/…).
    register_serve_state_builtins(&interp, shared_state.clone());
    {
        let mut c = caps.borrow_mut();
        for cap in caps_snap {
            c.grant(cap.clone());
        }
    }
    wire_swarm_hooks(&mut interp, swarm, "request");
    register_database_builtins(&interp, shared_db);
    rebuild_globals(&mut interp, snapshot);
    (interp, caps)
}

/// Intérprete base + sus capabilities, cacheado por-worker y reusado entre requests.
struct BaseInterp {
    interp: Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
}

thread_local! {
    /// Cache por-thread (cada worker del pool del intérprete) de un `BaseInterp` por
    /// serve, keyed por el puntero del `snapshot` (estable y único mientras viva el
    /// serve; los handlers lo mantienen vivo vía `Arc`). Reusar el intérprete entre
    /// requests es lo que elimina el hotspot. El intérprete es `!Send` (Rc/RefCell) →
    /// no puede compartirse entre hilos; por eso el cache es thread-local (uno por
    /// worker). Acotado: `#workers × #serves` (no por request) → no reintroduce el OOM.
    static SERVE_INTERPS: RefCell<HashMap<usize, BaseInterp>> = RefCell::new(HashMap::new());
}

/// Corre `f` sobre el intérprete base de este serve (construyéndolo la primera vez en
/// este worker, reusándolo después). Tras `f`, restaura el estado por-request del
/// intérprete y las capabilities al snapshot del preámbulo → el próximo request
/// arranca aislado (un `require`/print/share dentro de un handler no se filtra).
fn with_serve_interp<R>(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_state: &SharedState,
    secure: bool,
    f: impl FnOnce(&mut Interpreter) -> R,
) -> R {
    let key = Arc::as_ptr(snapshot) as *const () as usize;
    // Sacá el base del cache (o construilo la primera vez). Sacarlo (en vez de tomar
    // prestado) evita sostener el borrow del thread-local mientras corre `f`.
    let mut base = SERVE_INTERPS.with(|c| c.borrow_mut().remove(&key)).unwrap_or_else(|| {
        let (interp, caps) = build_base_interp(
            swarm.clone(),
            snapshot,
            caps_snap,
            shared_db.clone(),
            rules_snap,
            shared_memory,
            on_write,
            shared_state,
            secure,
        );
        BaseInterp { interp, caps }
    });

    let out = f(&mut base.interp);

    // Limpieza por-request: estado transitorio del intérprete + capabilities al
    // snapshot del preámbulo (aislamiento entre requests reusando el mismo intérprete).
    base.interp.reset_for_request();
    {
        let mut c = base.caps.borrow_mut();
        *c = CapabilitySet::new("request");
        for cap in caps_snap.iter() {
            c.grant(cap.clone());
        }
    }
    // Devolvelo al cache para el próximo request de este worker. (Si `f` paniquea, el
    // base se dropea acá sin re-insertarse → se evita reusar un intérprete corrupto; su
    // `Drop` corta el ciclo Rc del global_env. El pool atrapa el panic.)
    SERVE_INTERPS.with(|c| c.borrow_mut().insert(key, base));
    out
}

// =========================================================
// Construcción del contexto de request (SynValue)
// =========================================================

fn str_map(m: &IndexMap<String, String>) -> SynValue {
    let mut out = IndexMap::new();
    for (k, v) in m {
        out.insert(k.clone(), syn_text(v.as_str()));
    }
    syn_map(out)
}

fn headers_map(headers: &[(String, String)]) -> SynValue {
    let mut out = IndexMap::new();
    for (k, v) in headers {
        out.insert(k.clone(), syn_text(v.as_str())); // último gana (como dict de Python)
    }
    syn_map(out)
}

/// El map `request` que ve el handler (paridad con `_build_request`).
fn build_request_syn(ctx: &Ctx) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("method".to_string(), syn_text(ctx.method.as_str()));
    m.insert("path".to_string(), syn_text(ctx.path.as_str()));
    m.insert("body".to_string(), syn_text(ctx.body.as_str()));
    m.insert(
        "body_file".to_string(),
        match &ctx.body_file {
            Some(p) => syn_text(p.as_str()),
            None => syn_nothing(),
        },
    );
    m.insert(
        "json".to_string(),
        match &ctx.json {
            Some(v) => json_to_syn(v),
            None => syn_nothing(),
        },
    );
    m.insert("headers".to_string(), headers_map(&ctx.headers));
    m.insert("query".to_string(), str_map(&ctx.query));
    m.insert("params".to_string(), str_map(&ctx.params));
    m.insert("ip".to_string(), syn_text(ctx.client_ip.as_str()));
    m.insert("user".to_string(), ctx.user.clone().unwrap_or_else(syn_nothing));
    syn_map(m)
}

/// Las bindings que ve un handler, LOCALES al scope hijo del request (no globales →
/// no se filtran al siguiente request al reusar el intérprete): `request`, `query`,
/// `params` y el builtin `read_body` (lee el cuerpo, en memoria o del temp file spilled).
fn request_bindings(ctx: &Ctx) -> Vec<(String, SynValue)> {
    let body_text = ctx.body.clone();
    let body_file = ctx.body_file.clone();
    let read_body = SynValue::Builtin(Rc::new(BuiltinTask {
        name: "read_body".to_string(),
        param_count: 0,
        func: Rc::new(move |_i, _a, _l| match &body_file {
            Some(bf) => Ok(syn_text(std::fs::read_to_string(bf).unwrap_or_default())),
            None => Ok(syn_text(body_text.as_str())),
        }),
    }));
    // read_body_bytes() → bytes crudos (NO lossy). Prefiere el temp file spilled
    // (`std::fs::read`, no `read_to_string`); para bodies en memoria usa `body_raw` (los
    // bytes exactos), no `body` (que pasó por from_utf8_lossy aguas arriba). Cierra el
    // punto lossy de read_body para binario; exactitud byte-a-byte (A4).
    let body_raw = ctx.body_raw.clone();
    let body_file_b = ctx.body_file.clone();
    let read_body_bytes = SynValue::Builtin(Rc::new(BuiltinTask {
        name: "read_body_bytes".to_string(),
        param_count: 0,
        func: Rc::new(move |_i, _a, _l| match &body_file_b {
            Some(bf) => Ok(syn_bytes(std::fs::read(bf).unwrap_or_default())),
            None => Ok(syn_bytes(body_raw.clone())),
        }),
    }));
    vec![
        ("request".to_string(), build_request_syn(ctx)),
        ("query".to_string(), str_map(&ctx.query)),
        ("params".to_string(), str_map(&ctx.params)),
        ("read_body".to_string(), read_body),
        ("read_body_bytes".to_string(), read_body_bytes),
    ]
}

/// Corre el cuerpo de una ruta normal; captura el `give`-value.
fn run_route(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_state: &SharedState,
    body: &[Node],
    ctx: &Ctx,
    secure: bool,
) -> GiveOutcome {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_state, secure, |interp| {
        match interp.run_request_block(body, request_bindings(ctx)) {
            Ok(_) => GiveOutcome::Give(None),
            Err(Control::Give(v)) => GiveOutcome::Give(Some(v)),
            // Falla de validación (`expect`) → 400 + `field`; cualquier otro error → 500.
            Err(Control::Error(e)) if e.is_validation => {
                GiveOutcome::Validation { message: e.message.clone(), field: e.field.clone() }
            }
            Err(Control::Error(e)) => GiveOutcome::Error(e.to_string()),
            Err(Control::Stop(_)) => {
                GiveOutcome::Error("'give'/'stop' used outside of a task or loop".to_string())
            }
        }
    })
}

/// Marcador (en el mensaje del error) de desconexión del cliente SSE.
const CLIENT_GONE: &str = "__client_gone__";

/// Corre el cuerpo de una ruta de streaming SSE: `send` emite vía el `Emitter`. Un
/// `give` (o el fin del cuerpo) termina el stream limpio; un fallo de escritura
/// (cliente desconectado) lo desenrolla.
fn run_stream(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_state: &SharedState,
    body: &[Node],
    ctx: &Ctx,
    secure: bool,
    emit: Emitter,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_state, secure, move |interp| {
        let cell = Rc::new(RefCell::new(emit));
        let ec = cell.clone();
        interp.set_stream_emit(Rc::new(move |val: SynValue, event: Option<&str>| {
            match (*ec.borrow_mut())(&val, event) {
                Ok(()) => Ok(()),
                Err(StreamGone) => Err(Control::Error(RuntimeError::new(CLIENT_GONE))),
            }
        }));
        match interp.run_request_block(body, request_bindings(ctx)) {
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => StreamEnd::Done,
            Err(Control::Error(e)) => {
                let m = e.to_string();
                if m == CLIENT_GONE {
                    StreamEnd::ClientGone
                } else {
                    StreamEnd::Error(m)
                }
            }
        }
    })
}

// =========================================================
// Resolución de opciones del bloque serve
// =========================================================

fn val_to_f64(v: &SynValue) -> Option<f64> {
    match v {
        SynValue::Number(Number::Int(i)) => Some(*i as f64),
        SynValue::Number(Number::Float(f)) => Some(*f),
        SynValue::Number(Number::Big(b)) => b.to_string().parse().ok(),
        SynValue::Text(s) => s.trim().parse().ok(),
        SynValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum RateKind {
    Unlimited,
    Limit(i64, f64),
}

fn window_seconds(window: &str) -> f64 {
    match window {
        "second" => 1.0,
        "minute" => 60.0,
        "hour" => 3600.0,
        _ => 60.0,
    }
}

fn resolve_rate(
    interp: &mut Interpreter,
    env: &Rc<RefCell<synsema_core::interpreter::Environment>>,
    clause: Option<&Node>,
) -> Result<Option<RateKind>, Control> {
    let clause = match clause {
        Some(c) => c,
        None => return Ok(None),
    };
    if let NodeKind::RateLimitClause { count, window, unlimited } = &clause.kind {
        if *unlimited {
            return Ok(Some(RateKind::Unlimited));
        }
        let cap = match count {
            Some(c) => val_to_f64(&interp.eval(c, env)?).unwrap_or(0.0) as i64,
            None => 0,
        };
        return Ok(Some(RateKind::Limit(cap, window_seconds(window))));
    }
    Ok(None)
}

// =========================================================
// serve_hook + camino de ejecución de serve
// =========================================================

type Servers = Arc<Mutex<Vec<JoinHandle<()>>>>;

/// Construye la tabla (rutas + estáticos + auth) de un host (default o vhost) desde
/// sus nodos AST. Reusado por el host default y por cada bloque `host "..."`.
#[allow(clippy::too_many_arguments)]
fn build_host_table(
    interp: &mut Interpreter,
    env: &Rc<RefCell<synsema_core::interpreter::Environment>>,
    routes_n: &[Node],
    static_mounts_n: &[Node],
    auth_handler_n: Option<&Node>,
    block_limit: Option<(i64, f64)>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_state: &SharedState,
    swarm: &Arc<Swarm>,
    shared_db: &SharedDb,
    secure: bool,
) -> Result<(Vec<RouteSpec>, Vec<(String, String)>, Option<AuthHandler>), Control> {
    // -- static mounts (dedup por prefijo) --
    let mut static_mounts: Vec<(String, String)> = Vec::new();
    let mut seen_prefixes: Vec<String> = Vec::new();
    for mount in static_mounts_n {
        if let NodeKind::StaticMount { directory, prefix } = &mount.kind {
            let dir = interp.eval(directory, env)?.to_string();
            let prefix_str = match prefix {
                Some(p) => interp.eval(p, env)?.to_string(),
                None => "/".to_string(),
            };
            let key = format!("/{}", prefix_str.trim_matches('/'));
            if seen_prefixes.contains(&key) {
                return Err(Control::Error(RuntimeError::new(format!(
                    "two static mounts at the same prefix '{}'; mount each at a distinct prefix (e.g. static \"/assets\" from \"./assets\")",
                    prefix_str
                ))));
            }
            seen_prefixes.push(key);
            static_mounts.push((prefix_str, dir));
        }
    }

    // -- auth handler: corre la task de `auth with <task>` con el bearer token --
    let auth_handler: Option<AuthHandler> = auth_handler_n.map(|an| {
        let auth_node = an.clone();
        let swarm_a = swarm.clone();
        let snap_a = snapshot.clone();
        let caps_a = caps_snap.clone();
        let rules_a = rules_snap.clone();
        let mem_a = shared_memory.clone();
        let ow_a = on_write.clone();
        let st_a = shared_state.clone();
        let db_a = shared_db.clone();
        let h: AuthHandler = Arc::new(move |token: &str| -> Option<SynValue> {
            with_serve_interp(&swarm_a, &snap_a, &caps_a, &db_a, &rules_a, &mem_a, &ow_a, &st_a, secure, |interp| {
                let genv = interp.global_env.clone();
                let task = match interp.eval(&auth_node, &genv) {
                    Ok(t) => t,
                    Err(_) => return None,
                };
                match interp.call_task(task, vec![syn_text(token)]) {
                    Ok(user) => Some(user),
                    Err(_) => None,
                }
            })
        });
        h
    });

    // -- rutas --
    let mut routes: Vec<RouteSpec> = Vec::new();
    for r in routes_n {
        if let NodeKind::RouteDefinition {
            method,
            path,
            param_names,
            requires_auth,
            streaming,
            rate_limit,
            body,
        } = &r.kind
        {
            let rc = resolve_rate(interp, env, rate_limit.as_deref())?;
            let (eff_rate, zone) = match rc {
                None => match block_limit {
                    Some(bl) => (Some(bl), Some("__default__".to_string())),
                    None => (None, None),
                },
                Some(RateKind::Unlimited) => (None, None),
                Some(RateKind::Limit(c, s)) => {
                    (Some((c, s)), Some(format!("route:{} {}", method, path)))
                }
            };

            // Reverse proxy (Lote 2): body == `proxy to <url>` → forwardea al upstream.
            let proxy_target: Option<String> = if body.len() == 1 {
                if let NodeKind::ProxyStatement { target } = &body[0].kind {
                    Some(interp.eval(target, env)?.to_string())
                } else {
                    None
                }
            } else {
                None
            };

            let body_c = body.clone();
            let swarm_c = swarm.clone();
            let snap_c = snapshot.clone();
            let caps_c = caps_snap.clone();
            let rules_c = rules_snap.clone();
            let mem_c = shared_memory.clone();
            let ow_c = on_write.clone();
            let st_c = shared_state.clone();
            let db_c = shared_db.clone();
            let handler: Handler = Arc::new(move |ctx: &Ctx| {
                run_route(&swarm_c, &snap_c, &caps_c, &db_c, &rules_c, &mem_c, &ow_c, &st_c, &body_c, ctx, secure)
            });

            let stream_handler: Option<StreamHandler> = if *streaming {
                let body_s = body.clone();
                let swarm_s = swarm.clone();
                let snap_s = snapshot.clone();
                let caps_s = caps_snap.clone();
                let rules_s = rules_snap.clone();
                let mem_s = shared_memory.clone();
                let ow_s = on_write.clone();
                let st_s = shared_state.clone();
                let db_s = shared_db.clone();
                Some(Arc::new(move |ctx: &Ctx, emit: Emitter| {
                    run_stream(
                        &swarm_s, &snap_s, &caps_s, &db_s, &rules_s, &mem_s, &ow_s, &st_s, &body_s, ctx, secure, emit,
                    )
                }))
            } else {
                None
            };

            routes.push(RouteSpec {
                method: method.clone(),
                path: path.clone(),
                param_names: param_names.clone(),
                requires_auth: *requires_auth,
                streaming: *streaming,
                rate_limit: eff_rate,
                rate_zone: zone,
                handler,
                stream_handler,
                proxy_target,
            });
        }
    }
    Ok((routes, static_mounts, auth_handler))
}

#[allow(clippy::too_many_lines)]
fn make_serve_hook(
    caps: Rc<RefCell<CapabilitySet>>,
    swarm: Arc<Swarm>,
    shared_db: SharedDb,
    servers: Servers,
    secure: bool,
    overrides: ServeOverrides,
    top_level_memory: Rc<RefCell<AgentMemory>>,
    shared_memory: SharedMemoryStore,
    on_write: OnWriteFn,
    shared_state: SharedState,
) -> ServeHook {
    Rc::new(move |interp, node, env| {
        let (
            port_n,
            auth_handler_n,
            max_body_n,
            max_streams_n,
            block_rate_n,
            static_mounts_n,
            cors_n,
            describe_n,
            private,
            routes_n,
            tls_cert_n,
            tls_key_n,
            redirect_https,
            tls_auto,
            tls_auto_email_n,
            domain_n,
            hosts_n,
        ) = match &node.kind {
            NodeKind::ServeBlock {
                port,
                auth_handler,
                max_body,
                max_streams,
                rate_limit,
                static_mounts,
                cors,
                describe,
                private,
                routes,
                tls_cert,
                tls_key,
                redirect_https,
                tls_auto,
                tls_auto_email,
                domain,
                hosts,
            } => (
                port.as_ref(),
                auth_handler.as_deref(),
                max_body.as_deref(),
                max_streams.as_deref(),
                rate_limit.as_deref(),
                static_mounts,
                cors.as_deref(),
                describe.as_deref(),
                *private,
                routes,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                *redirect_https,
                *tls_auto,
                tls_auto_email.as_deref(),
                domain.as_deref(),
                hosts,
            ),
            _ => return Err(Control::Error(RuntimeError::new("internal: serve_hook on non-serve node"))),
        };
        // -- puerto + capability (precedencia: --port > `serve on N`) --
        let port_num = match overrides.port {
            // El operador que pasa `--port` es la autoridad: se concede `serve(N)`, así
            // que el `require serve(...)` del archivo no necesita coincidir.
            Some(p) => {
                caps.borrow_mut().grant(Capability::new(CapabilityType::Serve, Some(p.to_string())));
                p as i64
            }
            None => {
                let port_val = interp.eval(port_n, env)?;
                match val_to_f64(&port_val) {
                    Some(f) => f as i64,
                    None => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "serve port must be a number, got {}",
                            port_val
                        ))))
                    }
                }
            }
        };
        let port_str = port_num.to_string();
        let cap = Capability::new(CapabilityType::Serve, Some(port_str.clone()));
        if !caps.borrow_mut().check(&cap, &format!("serve on {}", port_str)) {
            return Err(Control::Error(RuntimeError::new(format!(
                "serve on {0} is not permitted: missing capability serve({0}). Add `require serve({0})` at the top of your program.",
                port_str
            ))));
        }
        // Dirección de bind (precedencia: --bind > default 0.0.0.0).
        let bind_addr: String = overrides.bind.clone().unwrap_or_else(|| "0.0.0.0".to_string());

        // -- max_body / max_streams --
        let max_body = match max_body_n {
            Some(n) => {
                let v = interp.eval(n, env)?;
                match &v {
                    SynValue::Number(_) => {
                        let i = val_to_f64(&v).unwrap_or(0.0) as i64;
                        if i > 0 {
                            Some(i)
                        } else {
                            None
                        }
                    }
                    _ => server::parse_body_size_str(&v.to_string()),
                }
            }
            None => Some(server::MAX_BODY),
        };
        let max_streams = match max_streams_n {
            Some(n) => {
                let i = val_to_f64(&interp.eval(n, env)?).map(|f| f as i64).unwrap_or(server::DEFAULT_MAX_STREAMS);
                if i <= 0 {
                    server::DEFAULT_MAX_STREAMS
                } else {
                    i
                }
            }
            None => server::DEFAULT_MAX_STREAMS,
        };

        // -- rate limits --
        let block_rate = resolve_rate(interp, env, block_rate_n)?;
        let block_limit = match block_rate {
            Some(RateKind::Limit(c, s)) => Some((c, s)),
            _ => None,
        };

        // -- cors / describe --
        let cors_origin = match cors_n {
            Some(c) => Some(interp.eval(c, env)?.to_string()),
            None => None,
        };
        let (describe_about, describe_api) = match describe_n {
            Some(d) => {
                if let NodeKind::DescribeClause { about, api } = &d.kind {
                    let about_s = match about {
                        Some(a) => Some(interp.eval(a, env)?.to_string()),
                        None => None,
                    };
                    let api_v = match api {
                        Some(a) => match interp.eval(a, env)? {
                            SynValue::List(l) => l.borrow().iter().map(|x| x.to_string()).collect(),
                            _ => Vec::new(),
                        },
                        None => Vec::new(),
                    };
                    (about_s, api_v)
                } else {
                    (None, Vec::new())
                }
            }
            None => (None, Vec::new()),
        };

        // Snapshot de globales (una vez, ya corrió el top-level): cada request lo
        // reconstruye en su intérprete fresco. Intent enriquece /llms.txt.
        let snapshot = snapshot_globals(interp);
        // Snapshot `Send` de las capabilities concedidas por el preámbulo `require`
        // (ya corrió, porque `serve on` viene después). Cada request las re-aplica en
        // su intérprete fresco (los grants no cruzan hilos vía `Rc`).
        let caps_snap: Arc<Vec<Capability>> =
            Arc::new(caps.borrow().granted.iter().cloned().collect());
        // Snapshot de las reglas declaradas en el top-level con `add_rule`. Se clona
        // una vez aquí (el top-level ya corrió completo) y se pre-popula en el
        // AgentMemory de cada intérprete de request, para que check_rules/get_rules
        // encuentren las reglas sin que el programador tenga que re-declararlas.
        let rules_snap: Arc<Vec<OwnerRule>> = Arc::new(
            top_level_memory.borrow().rules.values().cloned().collect(),
        );
        let intent = interp.intent().map(|s| s.to_string());

        // -- host default (rutas/estáticos/auth a nivel de `serve`) --
        let (routes, static_mounts, auth_handler) = build_host_table(
            interp,
            env,
            routes_n,
            static_mounts_n,
            auth_handler_n,
            block_limit,
            &snapshot,
            &caps_snap,
            &rules_snap,
            &shared_memory,
            &on_write,
            &shared_state,
            &swarm,
            &shared_db,
            secure,
        )?;

        // -- vhosts (Lote 1): cada `host "..."` con su propia tabla + cert opcional (SNI) --
        struct VHostBuilt {
            pattern: String,
            routes: Vec<RouteSpec>,
            static_mounts: Vec<(String, String)>,
            auth_handler: Option<AuthHandler>,
            tls_cert: Option<String>,
            tls_key: Option<String>,
        }
        let mut built_vhosts: Vec<VHostBuilt> = Vec::new();
        for h in hosts_n {
            if let NodeKind::HostBlock {
                pattern,
                auth_handler,
                static_mounts,
                routes,
                tls_cert,
                tls_key,
            } = &h.kind
            {
                let pat = interp.eval(pattern, env)?.to_string();
                let (vroutes, vstatic, vauth) = build_host_table(
                    interp,
                    env,
                    routes,
                    static_mounts,
                    auth_handler.as_deref(),
                    block_limit,
                    &snapshot,
                    &caps_snap,
                    &rules_snap,
                    &shared_memory,
                    &on_write,
                    &shared_state,
                    &swarm,
                    &shared_db,
                    secure,
                )?;
                let cert_path = match tls_cert {
                    Some(c) => Some(interp.eval(c, env)?.to_string()),
                    None => None,
                };
                let key_path = match tls_key {
                    Some(k) => Some(interp.eval(k, env)?.to_string()),
                    None => None,
                };
                built_vhosts.push(VHostBuilt {
                    pattern: pat,
                    routes: vroutes,
                    static_mounts: vstatic,
                    auth_handler: vauth,
                    tls_cert: cert_path,
                    tls_key: key_path,
                });
            }
        }

        // -- TLS resolution (precedencia: flag CLI > cláusula del archivo > default) --
        // Si la CLI fuerza un modo TLS (--tls-auto o --tls-cert), ESE flag es la autoridad
        // y define TLS por completo: se ignoran las cláusulas `tls` del archivo, incluidos
        // los certs por-host (SNI). Así es predecible para CUALQUIER programa (no sólo el
        // caso de un único cert por defecto): "si overrideás TLS por CLI, la CLI manda".
        let cli_forces_auto = overrides.tls_auto_email.is_some();
        let cli_overrides_tls = cli_forces_auto || overrides.tls_cert.is_some();

        // Certs por-host (vhost) para SNI — sólo cuando la CLI no sobreescribe TLS.
        let host_certs: Vec<(String, String, String)> = if cli_overrides_tls {
            Vec::new()
        } else {
            built_vhosts
                .iter()
                .filter_map(|v| match (&v.tls_cert, &v.tls_key) {
                    (Some(c), Some(k)) => Some((v.pattern.clone(), c.clone(), k.clone())),
                    _ => None,
                })
                .collect()
        };

        // Modo TLS efectivo:
        //   --tls-cert/--tls-key → TLS manual (pisa el archivo).
        //   --tls-auto           → ACME (pisa el archivo) y desactiva el `tls cert` del archivo.
        //   sin flags TLS        → lo que declare el archivo.
        let (manual_cert, manual_key): (Option<String>, Option<String>) =
            match (&overrides.tls_cert, &overrides.tls_key) {
                (Some(c), Some(k)) => (Some(c.clone()), Some(k.clone())),
                _ if cli_forces_auto => (None, None),
                _ => match (tls_cert_n, tls_key_n) {
                    (Some(c), Some(k)) => {
                        (Some(interp.eval(c, env)?.to_string()), Some(interp.eval(k, env)?.to_string()))
                    }
                    _ => (None, None),
                },
            };
        let tls_config = match (&manual_cert, &manual_key) {
            (Some(c), Some(k)) => {
                let cfg = if host_certs.is_empty() {
                    server::build_tls_config(c, k)
                } else {
                    // Default + per-host vía resolver SNI.
                    server::build_tls_config_sni(c, k, host_certs)
                };
                match cfg {
                    Ok(cfg) => Some(cfg),
                    Err(e) => return Err(Control::Error(RuntimeError::new(format!("TLS error: {}", e)))),
                }
            }
            _ => {
                if !host_certs.is_empty() {
                    return Err(Control::Error(RuntimeError::new(
                        "per-host `tls cert ... key ...` (SNI) requires a default `tls cert ... key ...` at the serve level".to_string(),
                    )));
                }
                None
            }
        };

        // -- auto-HTTPS / ACME: `tls auto [<email>]` + `domain <expr>`, o los flags
        // `--tls-auto <email>` + `--domain`. `domain` acepta un string (un dominio) o
        // lista (cert SAN multi-dominio); el primero es el primario.
        let acme_domains: Vec<String> = match &overrides.domains {
            Some(ds) => ds.clone(),
            None => match domain_n {
                Some(d) => match interp.eval(d, env)? {
                    SynValue::List(l) => l.borrow().iter().map(|x| x.to_string()).collect(),
                    other => vec![other.to_string()],
                },
                None => Vec::new(),
            },
        };
        let tls_auto_eff = if overrides.tls_cert.is_some() {
            false // un cert manual por flag desactiva el auto
        } else {
            cli_forces_auto || tls_auto
        };
        let acme_email = match &overrides.tls_auto_email {
            Some(e) => Some(e.clone()),
            None => match tls_auto_email_n {
                Some(e) => Some(interp.eval(e, env)?.to_string()),
                None => None,
            },
        };
        if tls_auto_eff && acme_domains.is_empty() {
            return Err(Control::Error(RuntimeError::new(
                "tls auto (auto-HTTPS) requires a domain — pass `--domain example.com` or add `domain \"example.com\"` to the serve block".to_string(),
            )));
        }
        let use_tls = tls_config.is_some() || tls_auto_eff;

        let n_routes = routes.len();
        let mut runtime = ServeRuntime::new(
            port_num as u16,
            bind_addr.clone(),
            routes,
            auth_handler,
            max_body,
            max_streams,
            static_mounts,
            cors_origin,
            intent,
            describe_about,
            describe_api,
            private,
            secure,
        );
        runtime.tls_enabled = use_tls;
        // Registrar los vhosts (Lote 1): el dispatch elige por header `Host`.
        for vh in built_vhosts {
            runtime.add_vhost(vh.pattern, vh.routes, vh.static_mounts, vh.auth_handler);
        }

        // Bind síncrono: si el puerto ya acepta, la readiness está garantizada.
        let listener = match TcpListener::bind((bind_addr.as_str(), port_num as u16)) {
            Ok(l) => l,
            Err(e) => {
                return Err(Control::Error(RuntimeError::new(format!(
                    "could not start server on {}:{}: {}",
                    bind_addr, port_str, e
                ))))
            }
        };
        let scheme = if use_tls { "HTTPS" } else { "HTTP" };
        println!("Serving {} on port {} ({} route(s))", scheme, port_str, n_routes);
        let rt = Arc::new(runtime);

        // auto-HTTPS: levanta el listener de challenge (HTTP-01 + 301), obtiene/carga
        // el cert (bloquea hasta tenerlo) y sirve HTTPS con hot-swap en renovación.
        if tls_auto_eff {
            let http_port: u16 = std::env::var("SYNSEMA_ACME_HTTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80);
            let store: server::ChallengeStore =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            let chal = match TcpListener::bind((bind_addr.as_str(), http_port)) {
                Ok(l) => l,
                Err(e) => {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "could not start ACME HTTP-01 challenge listener on port {}: {}",
                        http_port, e
                    ))))
                }
            };
            let https_port = port_num as u16;
            {
                let store2 = store.clone();
                let h = std::thread::Builder::new()
                    .name(format!("acme-http:{}", http_port))
                    .spawn(move || server::serve_acme_http(chal, https_port, store2))
                    .expect("hilo de challenge ACME");
                servers.lock().unwrap().push(h);
            }
            // Obtiene (o reusa) el cert SAN (cubre todos los `acme_domains`).
            // Bloqueante: no se puede servir HTTPS sin él.
            let cfg = match acme::load_or_obtain_config(&acme_domains, acme_email.as_deref(), store.clone())
            {
                Ok(c) => c,
                Err(e) => {
                    return Err(Control::Error(RuntimeError::new(format!("ACME error: {}", e))))
                }
            };
            println!("ACME: certificate ready for {}", acme_domains.join(", "));
            let cell: server::SharedServerConfig = Arc::new(std::sync::RwLock::new(cfg));
            acme::spawn_renewal_thread(acme_domains, acme_email, store, cell.clone());
            let rt2 = rt.clone();
            let h = std::thread::Builder::new()
                .name(format!("serve:{}", port_str))
                .spawn(move || server::serve_forever_tls_auto(rt2, listener, cell))
                .expect("hilo de accept del server");
            servers.lock().unwrap().push(h);
            return Ok(syn_text(format!("serving:{}", port_str)));
        }

        // `redirect https`: además escucha :80 y responde 301 → https://host[:port].
        if redirect_https && tls_config.is_some() {
            match TcpListener::bind((bind_addr.as_str(), 80u16)) {
                Ok(rl) => {
                    let https_port = port_num as u16;
                    let h = std::thread::Builder::new()
                        .name("serve:redirect:80".to_string())
                        .spawn(move || server::serve_redirect(rl, https_port))
                        .expect("hilo de redirección :80");
                    servers.lock().unwrap().push(h);
                }
                Err(e) => {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "could not start http→https redirect on port 80: {}",
                        e
                    ))))
                }
            }
        }

        let handle = match tls_config {
            Some(cfg) => {
                let rt2 = rt.clone();
                std::thread::Builder::new()
                    .name(format!("serve:{}", port_str))
                    .spawn(move || server::serve_forever_tls(rt2, listener, cfg))
                    .expect("hilo de accept del server")
            }
            None => {
                let rt2 = rt.clone();
                std::thread::Builder::new()
                    .name(format!("serve:{}", port_str))
                    .spawn(move || serve_forever(rt2, listener))
                    .expect("hilo de accept del server")
            }
        };
        servers.lock().unwrap().push(handle);

        Ok(syn_text(format!("serving:{}", port_str)))
    })
}

fn serve_inner(source: &str, filename: &str, secure: bool, overrides: ServeOverrides) -> RunResult {
    let program = match parse_source(source, filename) {
        Ok(p) => p,
        Err(CompileError::Lex(e)) => {
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Lexer error: {}", e)] }
        }
        Err(CompileError::Parse(e)) => {
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Parse error: {}", e)] }
        }
    };

    // Validación de los flags de despliegue (fail-loud) y política de múltiples serve.
    if !overrides.is_empty() {
        if let Err(e) = overrides.validate() {
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Runtime error: {}", e)] };
        }
        // Los flags configuran UN despliegue: con varios bloques `serve` no hay forma
        // coherente de aplicar --port/--tls-* (cada uno bindea su propio puerto), así
        // que se rechaza con un error claro (el caso común es un solo `serve`).
        let n_serve = program
            .statements
            .iter()
            .filter(|s| matches!(s.kind, NodeKind::ServeBlock { .. }))
            .count();
        if n_serve != 1 {
            return RunResult {
                success: false,
                output: Vec::new(),
                errors: vec![format!(
                    "Runtime error: CLI serve flags (--port/--domain/--tls-*/--bind) require exactly one `serve` block, but found {}",
                    n_serve
                )],
            };
        }
    }

    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));

    // ── Memoria compartida entre el top-level y todos los route handlers ──────
    // `shared_memory` es la fuente de verdad para remember/recall. Se inicializa
    // desde el SQLite del programa (mismo .db que usa `synsema run`) para que la
    // memoria persista entre reinicios y sea coherente entre ambos modos.
    let shared_memory: SharedMemoryStore = Arc::new(Mutex::new(AgentMemory::new()));
    {
        let persistence = crate::engine::state_persistence_for(filename);
        if let Some(ref p) = persistence {
            let mut pm = ProgressManager::new();
            p.load_into(&mut shared_memory.lock().unwrap(), &mut pm);
        }
    }
    // Callback de persistencia: cada vez que remember/forget_memory muten la
    // memoria, se guarda al SQLite inmediatamente para sobrevivir reinicios.
    let persist_for_serve = {
        let persistence = crate::engine::state_persistence_for(filename);
        let shared_persistence: Option<Arc<Mutex<crate::persistence::StatePersistence>>> =
            persistence.map(|p| Arc::new(Mutex::new(p)));
        let sp = shared_persistence;
        let on_write: OnWriteFn = Arc::new(move |mem: &AgentMemory| {
            if let Some(ref p) = sp {
                if let Ok(guard) = p.lock() {
                    guard.save_from(mem, &ProgressManager::new());
                }
            }
        });
        on_write
    };

    // `top_level_memory` sigue siendo el AgentMemory per-intérprete del top-level.
    // Gestiona add_rule/check_rules (gap-15). Para remember/recall usamos shared_memory.
    let top_level_memory = Rc::new(RefCell::new(AgentMemory::new()));
    wire_common_with_state(
        &mut interp,
        &caps,
        secure,
        Rc::new(RefCell::new(ProgressManager::new())),
        top_level_memory.clone(),
    );
    // Sobrescribir los builtins de memoria en el top-level con los compartidos,
    // para que `remember` en el top-level también persista a disco.
    register_serve_memory_builtins(&interp, shared_memory.clone(), persist_for_serve.clone());

    let swarm = Arc::new(Swarm::new());
    wire_swarm_hooks(&mut interp, swarm.clone(), "main");
    // db compartida: el top-level abre/crea tablas; los handlers (en sus hilos) la
    // comparten vía Arc<Mutex>. Sobrescribe la db fresca que dejó wire_common.
    let shared_db: SharedDb = Arc::new(Mutex::new(DatabaseManager::new()));
    register_database_builtins(&interp, shared_db.clone());
    // Estado mutable compartido entre todos los route handlers: respaldo de
    // state_set/state_get/state_incr. Vive mientras el servidor esté activo.
    let shared_state: SharedState = Arc::new(Mutex::new(HashMap::new()));
    // Registrar los builtins de estado también en el top-level (para que puedan
    // inicializar valores antes del `serve on PORT`).
    register_serve_state_builtins(&interp, shared_state.clone());

    let servers: Servers = Arc::new(Mutex::new(Vec::new()));
    interp.set_serve_hook(make_serve_hook(
        caps.clone(),
        swarm.clone(),
        shared_db.clone(),
        servers.clone(),
        secure,
        overrides,
        top_level_memory,
        shared_memory,
        persist_for_serve,
        shared_state,
    ));

    let r = interp.execute(&program);
    for line in &interp.output {
        println!("{}", line);
    }
    if let Err(Control::Error(e)) = &r {
        return RunResult {
            success: false,
            output: interp.output.clone(),
            errors: vec![format!("Runtime error: {}", e)],
        };
    }

    let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *servers.lock().unwrap());
    if handles.is_empty() {
        // Sin server: resultado normal (un programa serve sin bloque serve válido).
        return match r {
            Ok(_) => RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new() },
            Err(_) => RunResult {
                success: false,
                output: std::mem::take(&mut interp.output),
                errors: vec!["Runtime error: 'give'/'stop' used outside of a task or loop".to_string()],
            },
        };
    }
    println!("\n{} HTTP server(s) running. Press Ctrl+C to stop.", handles.len());
    for h in handles {
        let _ = h.join(); // bloquea para siempre (el accept loop nunca termina)
    }
    RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new() }
}

/// Corre un programa que contiene `serve on PORT`. Bindea (síncrono), imprime la
/// línea de readiness y bloquea hasta que maten el proceso. Default no-secure
/// (como `synsema run`); `secure=true` para el path seguro (body 500 genérico).
pub fn run_serve_program(source: &str, filename: &str, secure: bool) -> RunResult {
    run_serve_program_with_overrides(source, filename, secure, ServeOverrides::default())
}

/// Como `run_serve_program` pero con los flags de despliegue de la CLI (Pieza A):
/// `--port`/`--domain`/`--tls-auto`/`--tls-cert`/`--tls-key`/`--bind`. Sobreescriben
/// las cláusulas del bloque `serve` (precedencia flag > archivo > default).
pub fn run_serve_program_with_overrides(
    source: &str,
    filename: &str,
    secure: bool,
    overrides: ServeOverrides,
) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || serve_inner(&src, &fname, secure, overrides))
        .expect("no se pudo crear el hilo del motor serve")
        .join()
        .unwrap_or_else(|_| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec!["el motor abortó (probable desborde de stack nativo)".to_string()],
        })
}
