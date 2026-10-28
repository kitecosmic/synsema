//! Puente del motor para `serve on PORT { … }`. Análogo de `engine._run_serve`.
//!
//! Modelo de aislamiento (paridad con el oráculo + restricción `!Send` del intérprete):
//! el top-level corre UNA vez en el hilo del motor; al ejecutar el bloque serve se
//! toma un **snapshot `Send`** de los globales (valores + definiciones de tasks) y se
//! arma el `ServeRuntime`. Cada request corre en su hilo de conexión (`std::thread`)
//! con un intérprete fresco reconstruido desde ese snapshot, compartiendo el swarm
//! (blackboard) vía `Arc`. Es exactamente el aislamiento documentado: "lo único
//! compartido es el blackboard y la base de datos".

use synsema_core::synlist::{list_values};
use synsema_core::types::{MapObj, SynMap};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};

/// Callback de persistencia que se llama tras cada mutación de memoria desde
/// un route handler. Encapsula el `StatePersistence` protegido por mutex.
type OnWriteFn = Arc<dyn Fn(&AgentMemory) + Send + Sync>;

/// Callback de persistencia análogo para el progress (DE-028): se llama tras cada
/// mutación de progress desde un handler. Escribe SOLO la tabla de progress (no pisa
/// memoria), de ahí que sea un callback separado del de memoria.
type OnWriteProgressFn = Arc<dyn Fn(&ProgressManager) + Send + Sync>;

/// Memoria compartida entre todos los handlers de un serve: el `AgentMemory`
/// vive en un `Arc<Mutex>` para ser accesible desde múltiples hilos del pool.
type SharedMemoryStore = Arc<Mutex<AgentMemory>>;

/// Progress compartido entre todos los handlers de un serve (DE-028): gemelo de
/// `SharedMemoryStore`. Sin esto, los planes (`create_progress`/`resume_point`/…) no
/// sobrevivían entre requests y el ciclo PLAN→ADVANCE crasheaba.
type SharedProgressStore = Arc<Mutex<ProgressManager>>;
use std::thread::JoinHandle;


use synsema_agents::builtins::{register_serve_memory_builtins, register_serve_progress_builtins};
use synsema_agents::memory::{AgentMemory, OwnerRule};
use synsema_agents::progress::ProgressManager;
use synsema_agents::swarm::Swarm;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::ast::{Node, NodeKind, Param};
use synsema_core::interpreter::{
    Control, Environment, Interpreter, RunResult, RuntimeError, ServeHook,
};
use synsema_core::number::Number;
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{
    from_send, syn_bool, syn_int, syn_text, to_send, SendValue,
    ServerValue, SynTaskValue, SynValue,
};
use synsema_stdlib::cron::{
    register_cron_builtins, CronScheduler, ExecutorFactory as CronExecutorFactory, SchedRef,
    Task as CronTask,
};
use synsema_stdlib::database::{register_database_builtins, DatabaseManager};
use synsema_stdlib::server::{
    self, serve_forever, AuthHandler, Ctx, Emitter, ErrorHandler, GiveOutcome,
    Handler, RouteSpec, ServeRuntime, StaticMountSpec, StreamEnd, StreamGone, StreamHandler,
};
use synsema_stdlib::routing::SocketHandler;
use synsema_stdlib::ws::{adopt_server_socket, close_server_socket, ServerSocketLink};

/// Techo del host para `serve` (`synsema serve --sandbox | --cap-set`): política del
/// PROCESO (viene de la CLI), por eso vive en un slot global y no se enhebra por las
/// firmas del motor. Lo leen los intérpretes de request, los ticks de cron y los
/// agentes spawneados bajo serve — ninguno puede exceder lo que el operador fijó.
static SERVE_CEILING: std::sync::OnceLock<Option<Arc<Vec<Capability>>>> = std::sync::OnceLock::new();

fn set_serve_ceiling(ceiling: Option<Vec<Capability>>) {
    let _ = SERVE_CEILING.set(ceiling.map(Arc::new));
}

fn serve_ceiling() -> Option<Arc<Vec<Capability>>> {
    SERVE_CEILING.get().cloned().flatten()
}
#[allow(unused_imports)]
use synsema_stdlib::routing::{build_form_syn, build_request_syn, headers_map, request_bindings, str_map};

/// Manager de base de datos compartido entre el top-level y los hilos de conexión.
type SharedDb = Arc<Mutex<DatabaseManager>>;

/// Tabla de un host (default o vhost): rutas + static mounts (prefijo, dir) + auth.
type HostTable = (Vec<RouteSpec>, Vec<StaticMountSpec>, Option<AuthHandler>);

/// Estado mutable compartido entre todos los route handlers de un serve.
/// Respaldo de `state_set`/`state_get`/`state_incr` — alternativa explícita
/// a mutar globales (que no se propagan entre requests por diseño).
type SharedState = Arc<Mutex<HashMap<String, SendValue>>>;

/// Cola de aprobaciones humanas de UN serve (A1.v2): compartida entre todos los
/// workers/handlers del server, más la espera default del knob del host.
struct ApprovalsShared {
    queue: Arc<synsema_llm::human::QueueHandler>,
    /// `SYNSEMA_HUMAN_TIMEOUT` resuelto (environ > `.env`); `None` → la cola aplica
    /// su default de 300 s. El `within` de cada gate le gana a esto.
    default_timeout: Option<f64>,
}
type ServeApprovals = Arc<ApprovalsShared>;

/// Adapter cola → contrato de stdlib: sirve las rutas reservadas `/approvals` del
/// server (stdlib no conoce `QueueHandler`; sólo este trait).
struct QueueGateway(Arc<synsema_llm::human::QueueHandler>);

impl server::ApprovalsGateway for QueueGateway {
    fn list(&self) -> Vec<server::ApprovalSummary> {
        self.0
            .pending_summaries()
            .into_iter()
            .map(|s| server::ApprovalSummary {
                id: s.id,
                message: s.message,
                ty: s.ty,
                expires_at: s.expires_at,
            })
            .collect()
    }
    fn respond(
        &self,
        id: &str,
        token: &str,
        decision: Option<bool>,
        value: Option<&str>,
    ) -> server::ApprovalOutcome {
        use synsema_llm::human::RespondOutcome as R;
        match self.0.respond_with_token(id, token, decision, value) {
            R::Accepted => server::ApprovalOutcome::Accepted,
            R::NotFound => server::ApprovalOutcome::NotFound,
            R::BadToken => server::ApprovalOutcome::BadToken,
        }
    }
}

/// Espera default del host para los gates humanos (D1): knob `SYNSEMA_HUMAN_TIMEOUT`
/// en segundos, con la MISMA precedencia que los knobs LLM (environ > `.env` — reusa
/// `resolve_knob`, única implementación). Inválido/ausente/no-positivo → `None` (la
/// cola aplica su default de 300 s).
fn resolve_human_timeout(store: &synsema_stdlib::secrets::EnvStore) -> Option<f64> {
    crate::llm_providers::resolve_knob("SYNSEMA_HUMAN_TIMEOUT", store)
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|t| *t > 0.0)
}

/// Cola de aprobaciones "de fábrica" (aviso por el sink de logs, timeout del knob).
/// La usan el camino serve (una por bloque) y los entornos de cron de run/serve-solo-jobs.
fn default_approvals() -> ServeApprovals {
    let store = synsema_stdlib::secrets::EnvStore::load_default();
    Arc::new(ApprovalsShared {
        queue: Arc::new(synsema_llm::human::QueueHandler::with_notice(serve_log_sink())),
        default_timeout: resolve_human_timeout(&store),
    })
}

// =========================================================
// cron real (ejecución de tasks Synsema desde el hilo del job)
// =========================================================
//
// El problema de fondo: un task vive en un `Interpreter` (`Rc`, !Send) y no puede
// cruzar al hilo del timer. La solución es la MISMA que serve usa para los requests:
// el hilo de cada job construye (una vez, cacheado en su thread-local — espejo de
// `SERVE_INTERPS`) su intérprete desde el snapshot `Send` del programa y ejecuta el
// task POR NOMBRE en cada tick, con la limpieza por-ejecución y las caps del
// preámbulo de `with_serve_interp`. Rendimiento: el hilo espera PARKED (cero CPU),
// el intérprete se construye UNA vez por hilo de job (no por tick), y el lock del
// scheduler jamás se sostiene durante un tick.

/// Todo lo que el hilo de un job necesita para ejecutar su task como un request:
/// snapshot del programa + estado compartido del proceso. Puros `Arc` (Send+Sync).
#[derive(Clone)]
pub(crate) struct CronExecEnv {
    swarm: Arc<Swarm>,
    snapshot: Arc<Vec<(String, GlobalVal)>>,
    caps_snap: Arc<Vec<Capability>>,
    shared_db: SharedDb,
    rules_snap: Arc<Vec<OwnerRule>>,
    shared_memory: SharedMemoryStore,
    on_write: OnWriteFn,
    shared_progress: SharedProgressStore,
    on_write_progress: OnWriteProgressFn,
    shared_state: SharedState,
    approvals: ServeApprovals,
    secure: bool,
    /// Nombre de la memoria DECLARADA del programa (DB-M1) — `None` si no declara.
    /// Define el gate de los builtins de estado persistente en el intérprete del tick.
    mem_name: Option<crate::engine::MemName>,
}

/// Slot del entorno de ejecución: bajo serve se llena UNA vez (con el bind listo);
/// bajo run se refresca en cada registración (snapshot del momento). Los hilos de
/// job lo leen por tick (lectura de RwLock + clones de Arc — barato).
pub(crate) type CronEnvSlot = Arc<RwLock<Option<CronExecEnv>>>;

/// Wiring de cron de UN proceso: scheduler compartido (decisión: todos los workers
/// ven los mismos jobs) + slot del entorno. La copia STRONG vive en el dueño del
/// ciclo de vida (serve_inner / el intérprete principal de run); todo lo que quede
/// dentro del scheduler o de los intérpretes de tick usa [`CronTickCtx`] (weak).
#[derive(Clone)]
pub(crate) struct CronWiring {
    pub(crate) sched: Arc<CronScheduler>,
    pub(crate) slot: CronEnvSlot,
}

impl CronWiring {
    pub(crate) fn new_deferred() -> Self {
        Self { sched: Arc::new(CronScheduler::deferred()), slot: Arc::new(RwLock::new(None)) }
    }

    fn tick_ctx(&self) -> CronTickCtx {
        CronTickCtx { sched: Arc::downgrade(&self.sched), slot: self.slot.clone() }
    }
}

/// Lo que captura el closure de un tick: `Weak` al scheduler — un task que retiene
/// fuerte a su PROPIO scheduler sería un ciclo Arc (scheduler → job → task →
/// scheduler): el Drop (y su `cancel_all`) jamás correría y los hilos de los jobs
/// quedarían zombies al terminar un `run`.
#[derive(Clone)]
pub(crate) struct CronTickCtx {
    sched: std::sync::Weak<CronScheduler>,
    slot: CronEnvSlot,
}

/// Publica el entorno (si aún no hay uno — el primer `serve on` gana) y arranca los
/// jobs pendientes. Orden obligatorio: primero el env, después `start()` — ningún
/// tick corre sin entorno.
fn arm_cron(cron: &CronWiring, env: CronExecEnv) {
    {
        let mut w = cron.slot.write().unwrap();
        if w.is_none() {
            *w = Some(env);
        }
    }
    cron.sched.start();
}

/// Parámetros OBLIGATORIOS de un task (los que tienen default son opcionales).
fn required_params(params: &[Param]) -> usize {
    params.iter().filter(|p| p.default.is_none()).count()
}

/// Resuelve el argumento task de `cron_every`/`cron_after` contra el intérprete que
/// registra. Errores EN LA REGISTRACIÓN (no en el tick — G5): debe ser un task (o su
/// nombre), existir en el top-level (el tick lo ejecuta POR NOMBRE contra el snapshot
/// del programa) y no exigir parámetros.
fn resolve_cron_task(interp: &Interpreter, v: &SynValue, builtin: &str) -> Result<String, String> {
    let name = match v {
        SynValue::Task(t) => t.name.clone(),
        SynValue::Builtin(b) => b.name.clone(),
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(format!(
                "{}: the task argument must be a task or a task name, got {}",
                builtin,
                other.type_name()
            ))
        }
    };
    let global = interp.global_env.borrow().bindings.get(&name).cloned();
    match global {
        Some(SynValue::Task(t)) => {
            let required = required_params(&t.parameters);
            if required > 0 {
                return Err(format!(
                    "{}: cron task '{}' takes {} parameter(s); cron tasks take none — wrap it in a zero-argument task",
                    builtin, name, required
                ));
            }
            Ok(name)
        }
        Some(SynValue::Builtin(b)) => {
            if b.param_count > 0 {
                return Err(format!(
                    "{}: cron task '{}' takes {} parameter(s); cron tasks take none — wrap it in a zero-argument task",
                    builtin, name, b.param_count
                ));
            }
            Ok(name)
        }
        Some(other) => Err(format!(
            "{}: '{}' is not a task (it is a {}); cron runs a zero-argument task by name",
            builtin,
            name,
            other.type_name()
        )),
        // Un task local (definido dentro de otra task/handler) no sobrevive al tick:
        // el job lo ejecuta por nombre contra el snapshot del programa.
        None => Err(format!(
            "{}: task '{}' is not defined at the top level; cron runs the task by name, so define it before scheduling it",
            builtin, name
        )),
    }
}

/// Un tick: intérprete por hilo de job (cacheado en `SERVE_INTERPS` — misma
/// maquinaria y limpieza que un request) + ejecución del task por nombre con 0
/// argumentos. `Err(())` = terminó en error (ya logueado; el scheduler sólo cuenta).
/// El intérprete del tick lleva los builtins de cron cableados al MISMO scheduler —
/// un task puede registrar/cancelar otros jobs (visibles globalmente, sin deadlock:
/// el lock de jobs no se sostiene durante la ejecución).
fn run_cron_tick(
    name: &str,
    ctx: &CronTickCtx,
    log: &Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<(), ()> {
    // El scheduler se está dropeando (fin del programa) → la cancelación de este
    // hilo es inminente; no hay nada que ejecutar ni nadie que observe el conteo.
    let Some(sched) = ctx.sched.upgrade() else {
        return Err(());
    };
    let cron = CronWiring { sched, slot: ctx.slot.clone() };
    // Clonar el env FUERA del guard: un task largo no retiene el RwLock.
    let env = match cron.slot.read() {
        Ok(g) => g.clone(),
        Err(_) => None,
    };
    let Some(env) = env else {
        // No debería pasar (los hilos arrancan después de publicar el env). Si pasa,
        // es un tick perdido VISIBLE — jamás un run_count fantasma (G3).
        log(&format!("[cron] job '{}' ticked before the runtime was ready; tick skipped", name));
        return Err(());
    };
    // Un panic dentro del tick NO puede matar el hilo del job en silencio (el job
    // quedaría listado activo con los contadores congelados): se atrapa, se loguea y
    // cuenta como error; el intérprete posiblemente corrupto ya quedó descartado
    // (with_serve_interp no reinserta el base si `f` paniquea).
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_cron_tick_inner(name, &env, &cron)
    }));
    match guarded {
        Ok(outcome) => match outcome {
            // Un `give`/`stop` al tope del task es un fin normal del tick.
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => Ok(()),
            Err(Control::Error(e)) => {
                // Una línea por tick fallido; el intervalo del job acota la tasa. El
                // mensaje de runtime jamás trae plaintext de secrets (redacción del core).
                log(&format!("[cron] job '{}' failed: {}", name, e.message));
                Err(())
            }
        },
        Err(_) => {
            log(&format!(
                "[cron] job '{}' panicked; the tick was aborted and the job stays scheduled",
                name
            ));
            Err(())
        }
    }
}

/// El cuerpo del tick propiamente dicho (separado para poder envolverlo en
/// `catch_unwind` sin anidar el logging).
fn run_cron_tick_inner(
    name: &str,
    env: &CronExecEnv,
    cron: &CronWiring,
) -> Result<SynValue, Control> {
    with_serve_interp(
        &env.swarm,
        &env.snapshot,
        &env.caps_snap,
        &env.shared_db,
        &env.rules_snap,
        &env.shared_memory,
        &env.on_write,
        &env.shared_progress,
        &env.on_write_progress,
        &env.shared_state,
        &env.approvals,
        cron,
        env.secure,
        &env.mem_name,
        |interp, caps| {
            // T1: un tick de cron corre EN NOMBRE de `cron:<job>` — el ledger de `spend`, el
            // techo LLM por identidad y el audit dicen qué job fue, nunca "nadie".
            let _cron_subject = crate::subject::Subject::cron(name).apply(interp, caps);
            let task = interp.global_env.borrow().bindings.get(name).cloned();
            match task {
                Some(t @ (SynValue::Task(_) | SynValue::Builtin(_))) => {
                    interp.call_task(t, Vec::new())
                }
                Some(other) => Err(Control::Error(RuntimeError::new(format!(
                    "cron job '{}' no longer resolves to a task (it is a {})",
                    name,
                    other.type_name()
                )))),
                None => Err(Control::Error(RuntimeError::new(format!(
                    "cron job '{}' is not defined in the program snapshot",
                    name
                )))),
            }
        },
    )
}

/// Factory del ejecutor sobre un wiring COMPARTIDO (el mismo para el top-level de
/// serve, los workers y los intérpretes de tick): valida en la registración y arma
/// el closure del tick. Captura sólo el contexto weak — jamás retiene fuerte al
/// scheduler dentro de un intérprete de tick.
pub(crate) fn shared_cron_executor(ctx: CronTickCtx, log: Arc<dyn Fn(&str) + Send + Sync>) -> CronExecutorFactory {
    Rc::new(move |interp, v, builtin| {
        let name = resolve_cron_task(interp, v, builtin)?;
        let ctx = ctx.clone();
        let log = log.clone();
        let n = name.clone();
        let task: CronTask = Box::new(move || run_cron_tick(&n, &ctx, &log));
        Ok((name, task))
    })
}

/// Factory del ejecutor bajo run/test/conform: mismo esquema que serve (snapshot
/// `Send` → intérprete propio en el hilo del job), con el snapshot tomado en la
/// REGISTRACIÓN y estado compartido fresco del modo (los jobs de un mismo programa
/// comparten stores entre sí; el estado del intérprete principal no cruza — la
/// frontera documentada son archivos/db/blackboard).
pub(crate) fn run_mode_cron_executor(
    caps: Rc<RefCell<CapabilitySet>>,
    secure: bool,
    sched: &Arc<CronScheduler>,
    mem: Option<crate::engine::MemoryCtx>,
) -> CronExecutorFactory {
    // Compartidos entre TODOS los jobs registrados por este intérprete. El contexto
    // lleva (weak) el MISMO scheduler que registró el intérprete principal: un task
    // de cron que registra otro cron es visible en cron_list() y ejecuta.
    let ctx = CronTickCtx { sched: Arc::downgrade(sched), slot: Arc::new(RwLock::new(None)) };
    // El swarm de los ticks es propio, pero se crea en la PRIMERA registración para
    // compartir el bus del intérprete que registra: un `bus_publish` de un tick lo ven
    // los suscriptores del programa principal (y viceversa).
    let swarm_cell: Arc<std::sync::OnceLock<Arc<Swarm>>> = Arc::new(std::sync::OnceLock::new());
    let shared_db: SharedDb = Arc::new(Mutex::new(DatabaseManager::new()));
    // Memoria DECLARADA (DB-M1): los ticks comparten los stores (y la persistencia
    // on-write) del programa. Sin declaración: stores descartables + gate cerrado
    // (los builtins fallan; los stores quedan inalcanzables — G-1).
    let mem_name = mem.as_ref().map(|m| crate::engine::MemName { name: m.name.clone(), child: m.child.clone() });
    let (shared_memory, on_write_mem): (SharedMemoryStore, OnWriteFn) = match &mem {
        Some(m) => (m.memory.clone(), m.on_write_mem.clone()),
        None => (Arc::new(Mutex::new(AgentMemory::new())), Arc::new(|_| {})),
    };
    let (shared_progress, on_write_prog): (SharedProgressStore, OnWriteProgressFn) = match &mem {
        Some(m) => (m.progress.clone(), m.on_write_prog.clone()),
        None => (Arc::new(Mutex::new(ProgressManager::new())), Arc::new(|_| {})),
    };
    let shared_state: SharedState = Arc::new(Mutex::new(HashMap::new()));
    let log: Arc<dyn Fn(&str) + Send + Sync> =
        Arc::new(|line: &str| eprintln!("[synsema] {line}"));
    // Sin leer `.env` acá: este factory se construye por CADA intérprete (wire_common)
    // y la I/O sería un costo fijo por worker. La cola aplica su default (300 s).
    let approvals: ServeApprovals = Arc::new(ApprovalsShared {
        queue: Arc::new(synsema_llm::human::QueueHandler::with_notice(log.clone())),
        default_timeout: None,
    });
    Rc::new(move |interp, v, builtin| {
        let name = resolve_cron_task(interp, v, builtin)?;
        // Refrescar el snapshot en cada registración: los jobs ven el mundo del
        // momento en que el ÚLTIMO fue registrado (los stores compartidos son los
        // mismos Arc — el cache por-hilo se renueva solo al cambiar el snapshot).
        let swarm = swarm_cell
            .get_or_init(|| {
                Arc::new(labels_swarm(match synsema_stdlib::ws::bus_of_interp(interp) {
                    Some(b) => Swarm::with_bus(b),
                    None => Swarm::new(),
                }))
            })
            .clone();
        let env = CronExecEnv {
            swarm: swarm.clone(),
            // Lo ya congelado para siempre (las globales de `serve`) se comparte; lo demás se copia:
            // esta foto se repite en cada registración (R2.4).
            snapshot: snapshot_globals_shared(interp),
            caps_snap: Arc::new(caps.borrow().granted.iter().cloned().collect()),
            shared_db: shared_db.clone(),
            rules_snap: Arc::new(Vec::new()),
            shared_memory: shared_memory.clone(),
            on_write: on_write_mem.clone(),
            shared_progress: shared_progress.clone(),
            on_write_progress: on_write_prog.clone(),
            shared_state: shared_state.clone(),
            approvals: approvals.clone(),
            secure,
            mem_name: mem_name.clone(),
        };
        *ctx.slot.write().unwrap() = Some(env);
        let ctx = ctx.clone();
        let log = log.clone();
        let n = name.clone();
        let task: CronTask = Box::new(move || run_cron_tick(&n, &ctx, &log));
        Ok((name, task))
    })
}

// =========================================================
// webhook saliente de aprobaciones (A1.v3)
// =========================================================

/// Config del webhook saliente de aprobaciones, resuelta de los knobs al armar el
/// serve. El engine NO conoce canales (SMS/Telegram/…): dispara ESTE protocolo y el
/// canal (userland, p.ej. otro `.syn` bajo serve) se lo hace llegar al humano.
struct ApprovalWebhook {
    /// `SYNSEMA_HUMAN_WEBHOOK`: URL destino del POST.
    url: String,
    /// `SYNSEMA_HUMAN_WEBHOOK_SECRET`: clave HMAC del header `X-Synsema-Signature`.
    /// Ausente → se envía SIN firmar (dev local; producción DEBE setearla).
    secret: Option<String>,
    /// `SYNSEMA_HUMAN_PUBLIC_URL`: base pública del server — habilita `respond_url` y
    /// los `respond_link_*` absolutos del payload.
    public_url: Option<String>,
}

/// Valor del header `X-Synsema-Signature`: `sha256=<hmac-sha256 hex del body>` (pura).
fn webhook_signature(secret: &str, body: &str) -> String {
    format!(
        "sha256={}",
        synsema_stdlib::secrets::hmac_sha256_hex(secret.as_bytes(), body.as_bytes())
    )
}

/// Body JSON del webhook (pura, D2). Con `public_url` incluye `respond_url` y los
/// `respond_link_yes`/`respond_link_no` listos para reenviar por SMS/chat; sin ella,
/// sólo `respond_path` (el receptor sabe dónde vive el server que configuró).
fn approval_webhook_payload(
    e: &synsema_llm::human::EnqueuedApproval,
    public_url: Option<&str>,
) -> String {
    let mut body = serde_json::json!({
        "id": e.id,
        "type": e.ty,
        "message": e.message,
        "expires_at": e.expires_at,
        "token": e.token,
        "respond_path": format!("/approvals/{}", e.id),
    });
    if let Some(base) = public_url {
        let base = base.trim_end_matches('/');
        body["respond_url"] = serde_json::json!(format!("{}/approvals/{}", base, e.id));
        body["respond_link_yes"] =
            serde_json::json!(format!("{}/approvals/{}/{}?d=yes", base, e.id, e.token));
        body["respond_link_no"] =
            serde_json::json!(format!("{}/approvals/{}/{}?d=no", base, e.id, e.token));
    }
    body.to_string()
}

/// Aviso ÚNICO por proceso si el webhook no se pudo entregar. El gate NO se rompe:
/// quedan la consola y `GET /approvals` como fallback (por eso un intento y listo).
static WEBHOOK_FAILED_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn note_webhook_failed(err: &str) {
    if !WEBHOOK_FAILED_NOTICED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "[synsema] notice: the approval webhook could not be delivered ({}). The \
             approval is still pending — a HUMAN can find it on the server console or \
             GET /approvals.",
            err
        );
    }
}

/// Dispara el webhook en un hilo aparte: UN intento, timeout 10 s, sin reintentos —
/// fire-and-forget, jamás bloquea ni rompe el gate (D3).
fn fire_approval_webhook(cfg: Arc<ApprovalWebhook>, e: synsema_llm::human::EnqueuedApproval) {
    let spawned = std::thread::Builder::new()
        .name("synsema-approval-webhook".to_string())
        .spawn(move || {
            let body = approval_webhook_payload(&e, cfg.public_url.as_deref());
            let mut headers =
                vec![("content-type".to_string(), "application/json".to_string())];
            if let Some(s) = &cfg.secret {
                headers.push(("X-Synsema-Signature".to_string(), webhook_signature(s, &body)));
            }
            // v0.6.46 (E7): el webhook lo configura el host.
            let r = synsema_stdlib::http::host::http_request(
                "POST",
                &cfg.url,
                Some(&headers),
                None,
                Some(&body),
                10,
            );
            if let Some(err) = r.error {
                note_webhook_failed(&err);
            } else if !r.ok {
                note_webhook_failed(&format!("HTTP {}", r.status));
            }
        });
    if spawned.is_err() {
        note_webhook_failed("could not spawn the webhook thread");
    }
}

use crate::engine::{wire_common_with_state, wire_swarm_hooks, INTERP_STACK_SIZE};

// =========================================================
// overrides de despliegue por CLI (Pieza A)
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
    /// v0.6.42 — `--trust-proxy ip,cidr,…`: proxys de confianza (pisa `trust proxy` del archivo).
    pub trust_proxy: Option<Vec<String>>,
    /// `--sandbox` | `--cap-set <list>`: techo de capabilities del host para TODO el
    /// serve (requests, cron, agentes). `None` = sin techo (comportamiento histórico).
    pub ceiling: Option<Vec<Capability>>,
    /// `--attested`: al arrancar se genera un par P-256, se pide a la
    /// plataforma un documento que ata `sha256(spki ‖ program_sha)` y se publica en
    /// `GET /.well-known/attestation`. Sin `--tls-cert`/`--tls-auto`, TLS va con un cert
    /// autofirmado emitido con ESA clave (el cliente la pinea). Si la plataforma no responde,
    /// el servidor NO arranca.
    pub attested: bool,
    /// v0.6.46 (E6-h) — `--auditor` (o `SYNSEMA_AUDITOR_KEY`): la pública X25519 del auditor. Cada
    /// request que corre código del programa deja un recibo sellado, escrito antes de la respuesta.
    pub auditor: Option<[u8; 32]>,
    /// v0.6.46 (E6-h) — `--receipt <ruta|fd:N>`: adónde van los recibos (una línea por request;
    /// la ruta se abre para agregar). Sin esto, stderr.
    pub receipt: Option<String>,
    /// v0.6.46 (E6-h) — `SYNSEMA_RECEIPT_SEALED_BYTES`: el tamaño del texto plano del sobre.
    pub sealed_bytes: Option<usize>,
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
            && self.trust_proxy.is_none()
            && !self.attested
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
// snapshot de globales (Send) → reconstrucción por request
// =========================================================

pub(crate) enum GlobalVal {
    Value(SendValue),
    /// Un dato congelado en el lugar (R2 de specs/modelo-memoria-regiones.md): todos los workers
    /// leen EL MISMO, sin copiarlo (`Value` es una copia que cada worker vuelve a armar). Sólo en
    /// las fotos que viven lo que el proceso (`snapshot_globals_frozen`): congelar es para siempre.
    Frozen(synsema_core::frozen::FrozenValue),
    /// Un dato congelado sólo mientras corren los hilos de un `ScopedFreeze` (R2.3, `parallel_map`):
    /// el índice del valor en su `ScopeCtx`, que el rebuild recibe (`scope`).
    Scoped(usize),
    /// Un generador de `rng()` que vive en un global: del otro lado (cada request de `serve`,
    /// cada worker) sería una copia que REPITE la misma secuencia, así que llega como un valor
    /// que al usarse explica qué hacer. El `String` es su nombre (`rng(42)`).
    SharedRng(String),
    /// Ronda 3 (R3): un generador que es un local de quien armó la task (un frame): lo mismo, con
    /// el texto de un local.
    CapturedRng(String),
    /// Ronda 3 (R3): un builtin del lenguaje ligado a otro nombre (`let up be upper`) o guardado en
    /// un dato: cruza por su nombre propio y del otro lado es el builtin de ese intérprete.
    Builtin(String),
    /// Ronda 3 (R3): el constructor de un `type` o de una variante: cruza su definición.
    Constructor(synsema_core::interpreter::CtorSpec),
    /// Ronda 3 (R3): un cierre del motor (`read_body`, un agregado de tabla) que no tiene cómo
    /// cruzar: del otro lado falla con texto al llamarlo, nunca se lee otro valor en su lugar.
    Uncrossable(String),
    Task {
        name: String,
        parameters: Vec<Param>,
        body: std::sync::Arc<[Node]>,
        required_capabilities: Vec<(String, Option<String>)>,
        /// v0.6.50 (ronda 1, A1): de qué raíz léxica cuelga la task. Del otro lado cierra ahí, no
        /// donde está guardada: una lambda del programa que un módulo guarda sigue viendo el programa.
        root: TaskRoot,
        /// Ronda 2 (R2): los envs entre la task y su raíz (los locales de quien la armó), del más
        /// externo al más interno. Viajan copiados, como cualquier dato que cruza.
        frames: Vec<FrameVal>,
        /// Ronda 6 (N1): los nombres libres, si el original ya los calculó. La copia los hereda y no
        /// vuelve a recorrer el cuerpo (un `parallel_map` dentro de cada item de otro).
        free_names: Option<std::sync::Arc<HashSet<String>>>,
    },
    /// v0.6.50 (B): una task exportada por una tool de confianza (el builtin que la envuelve). Viaja
    /// la task y el entorno de la tool (por id, una vez por foto, como un `Module`); del otro lado
    /// el entorno cuelga de la base de confianza de ESE intérprete y la task se envuelve con SU hook.
    TrustedTask {
        module: String,
        export: String,
        task: Box<GlobalVal>,
        env_id: String,
        env: Option<Vec<(String, GlobalVal)>>,
    },
    /// v0.6.50 (B): la vista de una tool (`use "trusted:t" as t`): del otro lado se registra como
    /// vista (`set t.X` es error) y queda en el caché de módulos.
    TrustedView(Vec<(String, GlobalVal)>),
    /// Definición de agente (Batch 6): las defs de agentes viven en
    /// `Interpreter.agent_definitions` (fuera de `global_env.bindings`), así que se
    /// snapshotean/restauran aparte para que un `spawn` desde una route las encuentre. El
    /// nombre va en la clave de la tupla; el `body` (Vec<Node>) es `Send` y clonable.
    Agent {
        body: std::sync::Arc<[Node]>,
    },
    /// Un map que cierra sobre un `module_env` (el alias de un `use "…" as name`, o un
    /// map interno estilo `TOOL_ALLOW` — DE-032). El módulo se identifica por su **ID
    /// estable** (`id` = el `name` del `module_env` original, `"module:<resolved>"`), y
    /// su env viaja **UNA sola vez** por árbol de snapshot: el primer encuentro lo lleva
    /// inline (`env: Some(…)`); los demás encuentros — el segundo brazo de un diamante
    /// B→D←C (DE-033), un map auto-referencial, o cualquier ciclo hipotético — llevan
    /// solo el `id` (`env: None`). En rebuild, un `ModuleRegistry` (`id → env`, vivo
    /// durante ESE rebuild) garantiza que toda referencia al mismo módulo resuelva al
    /// MISMO `module_env` compartido — igual que `module_cache` bajo `run` (DE-027/030).
    Module {
        /// ID estable: el `name` del `module_env` original (`"module:<resolved>"`).
        id: String,
        /// `true` si el map ERA el mapa de exportaciones del módulo (`use … as m`), no un map
        /// de datos que guarda tasks del módulo (`{"f": m.f}`): el rebuild lo registra como
        /// vista del módulo (`register_module`) y las escrituras `set m.X[k]` siguen al env.
        is_alias: bool,
        /// Entradas del map (alias de módulo o map interno). `is_export = true` ⇔ en el
        /// snapshot la entry `(k, v)` era EL MISMO objeto (`Rc::ptr_eq`) que el binding
        /// `k` del `module_env` → en rebuild se cosecha del env reconstruido (identidad
        /// compartida alias↔env, como los exports de `load_module_inner`). `false` → se
        /// materializa desde el `GlobalVal` (primitivas inmutables, claves renombradas).
        alias: Vec<(String, GlobalVal, bool /* is_export */)>,
        /// `Some(bindings)` SOLO en el primer encuentro del módulo en el árbol de
        /// snapshot (TODAS las bindings: exportadas + internas + `let`s); `None` en los
        /// siguientes (referencia por `id` al registro del rebuild).
        env: Option<Vec<(String, GlobalVal)>>,
    },
    /// Un map de DATOS cuyas entradas incluyen tasks/closures (p.ej. un callback en un
    /// map de config) pero que NO es un módulo importado. Se conserva como variante aparte
    /// (en vez de degradar las tasks a texto vía to_send/from_send) y, en rebuild, sus
    /// tasks cierran sobre el global del request como cualquier task top-level — sin el
    /// `module_env` compartido del caso módulo.
    MapWithTasks(Vec<(String, GlobalVal)>),
    /// Ronda 2 (R2, B3): una lista con tasks. Cada task cruza por su cadena, como en `MapWithTasks`;
    /// antes la lista viajaba como dato y sus tasks llegaban como texto.
    ListWithTasks(Vec<GlobalVal>),
}

/// Ronda 2 (R2): un env intermedio de la cadena de una task. Se identifica por id (la identidad del
/// env en la foto), como un módulo: la primera vez viaja con sus nombres; las siguientes, por id. Dos
/// lambdas del mismo frame comparten la copia del otro lado, y una task local que se nombra a sí
/// misma desde su frame se resuelve sin ciclo.
pub(crate) struct FrameVal {
    id: String,
    name: String,
    env: Option<Vec<(String, GlobalVal)>>,
}

/// Estado del ÁRBOL COMPLETO de un snapshot. Se comparte entre TODOS los bindings de
/// `snapshot_globals_*` para que el diamante entre bindings top-level (b y c importan d)
/// también dedupee: d viaja UNA vez, las demás apariciones son referencias por id.
#[derive(Default)]
struct SnapState<'a> {
    /// `module_env`s EN CURSO de snapshot (stack, por identidad de `Rc`): corta la
    /// recursión de un map interno auto-referencial (TOOL_ALLOW — DE-032) y de
    /// cualquier ciclo hipotético.
    in_progress: Vec<usize>,
    /// `module_env`s YA snapshoteados en este árbol: una segunda aparición (el otro
    /// brazo del diamante B→D←C — DE-033) viaja como referencia por id, no como copia.
    done: HashSet<usize>,
    /// Los datos se congelan en el lugar (`GlobalVal::Frozen`) en vez de copiarse: sólo para una
    /// foto que vive lo que el proceso (las globales del preámbulo de `serve`).
    freeze: bool,
    /// Los datos se congelan sólo mientras corren los hilos de este alcance (`GlobalVal::Scoped`).
    scoped: Option<&'a mut synsema_core::frozen::ScopedFreeze>,
    /// Lo que YA está congelado para siempre se comparte (`GlobalVal::Frozen`) sin congelar nada
    /// nuevo; lo demás se copia (agentes y `cron`, R2.4).
    share: bool,
    /// Ronda 3 (R3): por frame (identidad del `Rc`), los nombres que ya viajan en esta foto. Una
    /// segunda task del mismo frame agrega sólo lo que le falta.
    frame_names: HashMap<usize, HashSet<String>>,
    /// Ronda 3 (R3): se está copiando un local de un frame (un generador ahí es un local).
    in_frame: bool,
}

/// Un dato (sin tareas): congelado si la foto congela y se puede; si no, la copia de siempre (un
/// generador adentro cruza como stub).
fn data_global(v: &SynValue, state: &mut SnapState) -> GlobalVal {
    frozen_global(v, state).unwrap_or_else(|| GlobalVal::Value(synsema_core::rng::with_stubbed_globals(|| to_send(v))))
}

/// El dato congelado (para siempre, compartido o con alcance), si la foto congela y se puede. Lo
/// que se congela no tiene tasks: el congelado las rechaza.
fn frozen_global(v: &SynValue, state: &mut SnapState) -> Option<GlobalVal> {
    if state.freeze {
        if let Ok(f) = synsema_core::frozen::FrozenValue::new(v.clone()) {
            return Some(GlobalVal::Frozen(f));
        }
    }
    if state.share {
        if let Ok(f) = synsema_core::frozen::FrozenValue::share(v.clone()) {
            return Some(GlobalVal::Frozen(f));
        }
    }
    if let Some(scope) = state.scoped.as_deref_mut() {
        if let Ok(i) = scope.add(v.clone()) {
            return Some(GlobalVal::Scoped(i));
        }
    }
    None
}

/// Convierte un `SynValue` a `GlobalVal` de forma recursiva, con un árbol de snapshot
/// propio (para snapshots de UN valor suelto: los globales que viajan a un agente
/// spawneado). Un Map que cierra sobre un `module_env` se snapshotea como
/// `GlobalVal::Module` (env inline la primera vez, referencia por id después); un Map
/// de datos con tasks se preserva como `MapWithTasks`. Los datos: lo que ya está congelado
/// para siempre se comparte (sin congelar nada nuevo) y el resto se copia como SendValue — el
/// agente vive libre (R2.4). Bajo `serve`, las globales del preámbulo llegan sin copia.
pub(crate) fn val_to_global_shared(v: &SynValue) -> GlobalVal {
    val_to_global_inner(v, &mut SnapState { share: true, ..SnapState::default() })
}

/// ¿La entry `(k, v)` del map alias es EL MISMO objeto que el binding `k` del
/// `module_env`? Solo valores por-referencia (Task/Map/List vía `Rc::ptr_eq`);
/// primitivas → `false` (inmutables: la copia es indistinguible del original).
fn is_export_of(module_env: &Rc<RefCell<Environment>>, k: &str, v: &SynValue) -> bool {
    let env = module_env.borrow();
    match (env.bindings.get(k), v) {
        (Some(SynValue::Task(a)), SynValue::Task(b)) => Rc::ptr_eq(a, b),
        (Some(SynValue::Map(a)), SynValue::Map(b)) => synsema_core::types::MapRef::ptr_eq(a, b),
        (Some(SynValue::List(a)), SynValue::List(b)) => synsema_core::types::ListRef::ptr_eq(a, b),
        _ => false,
    }
}

/// Snapshotea las entradas de un map que cierra sobre `module_env`, marcando con
/// `is_export` las que son el mismo objeto que el binding homónimo del env (en rebuild
/// se cosechan del env reconstruido → identidad compartida alias↔env).
fn snapshot_alias_entries(
    m: &synsema_core::types::MapRef,
    module_env: &Rc<RefCell<Environment>>,
    state: &mut SnapState,
) -> Vec<(String, GlobalVal, bool)> {
    m.borrow()
        .iter()
        .map(|(k, v)| {
            let is_export = is_export_of(module_env, k, v);
            (k.to_string(), val_to_global_inner(v, state), is_export)
        })
        .collect()
}

/// v0.6.50 (ronda 1, A1): la raíz léxica de una task (ver `GlobalVal::Task`).
pub(crate) enum TaskRoot {
    /// Cuelga del global del programa (una task o lambda del programa).
    Global,
    /// Cuelga del env de un módulo (`module:<id>`). Ronda 2 (R2, M1): el env viaja con la task si
    /// todavía no viajó en esta foto, así que no depende del orden de los `use`.
    Module { id: String, env: Option<Vec<(String, GlobalVal)>> },
    /// Otra raíz (un fork, un template): cierra donde se reconstruye, como antes.
    Here,
}

/// Ronda 3 (R3, B1): de un frame, las bindings que la task nombra (`names`) y que todavía no viajan
/// en esta foto. Se anotan antes de copiar los valores: una task local recursiva que vuelve a este
/// frame no las repite. `None` si no hay nada nuevo.
fn frame_bindings(f: &Rc<RefCell<Environment>>, names: &HashSet<String>, state: &mut SnapState) -> Option<Vec<(String, GlobalVal)>> {
    let key = Rc::as_ptr(f) as usize;
    let picked: Vec<(String, SynValue)> = {
        let sent = state.frame_names.entry(key).or_default();
        let e = f.borrow();
        let mut out = Vec::new();
        for n in names {
            if !sent.contains(n) {
                if let Some(v) = e.bindings.get(n) {
                    sent.insert(n.clone());
                    out.push((n.clone(), v.clone()));
                }
            }
        }
        out
    };
    if picked.is_empty() {
        return None;
    }
    let in_frame = std::mem::replace(&mut state.in_frame, true);
    let entries = picked.into_iter().map(|(k, v)| (k, val_to_global_inner(&v, state))).collect();
    state.in_frame = in_frame;
    Some(entries)
}

/// Las bindings de un env para la foto (sin los builtins, que cada intérprete tiene), marcado en
/// curso mientras se recorren; `None` si ya viaja (o viajó) en este árbol.
fn env_bindings(env: &Rc<RefCell<Environment>>, state: &mut SnapState) -> Option<Vec<(String, GlobalVal)>> {
    let key = Rc::as_ptr(env) as usize;
    if state.in_progress.contains(&key) || state.done.contains(&key) {
        return None;
    }
    state.in_progress.push(key);
    let in_frame = std::mem::replace(&mut state.in_frame, false);
    let entries: Vec<(String, GlobalVal)> = env
        .borrow()
        .bindings
        .iter()
        .filter(|(k, v)| !matches!(v, SynValue::Builtin(b) if synsema_core::interpreter::is_own_builtin(k, b)))
        .map(|(k, v)| (k.to_string(), val_to_global_inner(v, state)))
        .collect();
    state.in_frame = in_frame;
    state.in_progress.pop();
    state.done.insert(key);
    Some(entries)
}

/// Ronda 2 (R2): la foto de una task con su cadena léxica: la raíz (el global, su módulo u otra) y
/// los envs intermedios.
fn task_global(t: &Rc<SynTaskValue>, state: &mut SnapState) -> GlobalVal {
    let mut chain: Vec<Rc<RefCell<Environment>>> = Vec::new();
    let mut cur = t.closure_env.clone();
    let root = loop {
        let (is_module, parent) = {
            let e = cur.borrow();
            (e.name.starts_with("module:"), e.parent.clone())
        };
        if is_module {
            let id = cur.borrow().name.to_string();
            break TaskRoot::Module { id, env: env_bindings(&cur, state) };
        }
        match parent {
            Some(p) => {
                chain.push(cur.clone());
                cur = p;
            }
            None => break if &*cur.borrow().name == "global" { TaskRoot::Global } else { TaskRoot::Here },
        }
    };
    let names = if chain.is_empty() { std::sync::Arc::new(HashSet::new()) } else { synsema_core::interpreter::task_free_names(t) };
    let frames = chain
        .iter()
        .rev()
        .map(|f| FrameVal {
            id: format!("frame:{:x}", Rc::as_ptr(f) as usize),
            name: f.borrow().name.to_string(),
            env: frame_bindings(f, &names, state),
        })
        .collect();
    GlobalVal::Task {
        name: t.name.clone(),
        parameters: t.parameters.clone(),
        body: t.body.clone(),
        required_capabilities: t.required_capabilities.clone(),
        root,
        frames,
        free_names: t.free_names.get().cloned(),
    }
}

/// Ronda 2 (R2): la foto de la task que `parallel_map` aplica, con su cadena (los datos, congelados
/// con el alcance del `parallel_map`).
pub(crate) fn snapshot_task(t: &Rc<SynTaskValue>, scoped: Option<&mut synsema_core::frozen::ScopedFreeze>) -> GlobalVal {
    task_global(t, &mut SnapState { scoped, ..SnapState::default() })
}

/// ¿Hay una task (o una task de confianza) en el valor? Sólo una lista de valores puede tenerla.
fn has_callable(v: &SynValue) -> bool {
    match v {
        SynValue::Task(_) => true,
        // Ronda 3 (R3): todo builtin; uno que no es de confianza cruza por su nombre o falla.
        SynValue::Builtin(_) => true,
        SynValue::Map(m) => m.borrow().iter().any(|(_, x)| has_callable(x)),
        SynValue::List(l) => l.borrow().as_values().is_some_and(|xs| xs.iter().any(has_callable)),
        _ => false,
    }
}

/// Núcleo recursivo de `val_to_global_shared`/`snapshot_globals_*`/`snapshot_task`.
fn val_to_global_inner(v: &SynValue, state: &mut SnapState) -> GlobalVal {
    match v {
        SynValue::Task(t) => task_global(t, state),
        // Un generador dentro de un global (`{"g": rng(1)}`) tampoco se copia en silencio.
        SynValue::Builtin(b) if synsema_core::rng::snapshot(b).is_some() => {
            if state.in_frame {
                GlobalVal::CapturedRng(b.name.clone())
            } else {
                GlobalVal::SharedRng(b.name.clone())
            }
        }
        SynValue::Builtin(b) if synsema_core::interpreter::trusted_tool_parts(b).is_some() => trusted_task_global(b, state),
        // Ronda 3 (R3): un constructor cruza su definición; un builtin del lenguaje, su nombre; un
        // cierre del motor no cruza (falla con texto del otro lado).
        SynValue::Builtin(b) => match (&b.ctor, b.meta.registered) {
            (Some(c), _) => GlobalVal::Constructor((**c).clone()),
            (None, true) => GlobalVal::Builtin(b.name.clone()),
            (None, false) => GlobalVal::Uncrossable(b.name.clone()),
        },
        SynValue::Map(m) if synsema_core::interpreter::is_trusted_view_map(m) => {
            GlobalVal::TrustedView(m.borrow().iter().map(|(k, v)| (k.to_string(), val_to_global_inner(v, state))).collect())
        }
        SynValue::Map(m) => {
            // ¿El map cierra sobre un `module_env`? (alias de `use`, o map interno cuyas
            // tasks cierran sobre el módulo — heurística por el nombre "module:…").
            // v0.6.50 (A): primero el registro (`use` lo anota): un módulo que exporta sólo datos —un
            // mapa de callbacks que armó una de sus tasks— no tiene ninguna task que cierre sobre él, y
            // viajaba como un mapa común, con sus lambdas colgadas del global del request.
            let module_env = synsema_core::interpreter::module_env_of_map(m).or_else(|| module_env_of(&m.borrow()));
            if let Some(module_env) = module_env {
                let id = module_env.borrow().name.to_string();
                let is_alias = synsema_core::interpreter::module_env_of_map(m).is_some();
                // Primer encuentro: el env viaja inline (TODAS las bindings, DE-027). Si ya viaja (o
                // viajó) en este árbol, referencia por id: un solo camino cubre el map
                // auto-referencial (DE-032), el diamante B→D←C (DE-033) y cualquier ciclo
                // hipotético. En rebuild resuelve al MISMO env vía el registro.
                let env = env_bindings(&module_env, state);
                let alias = snapshot_alias_entries(m, &module_env, state);
                return GlobalVal::Module { id, is_alias, alias, env };
            }
            let entries: Vec<(String, GlobalVal)> = m
                .borrow()
                .iter()
                .map(|(k, v)| (k.to_string(), val_to_global_inner(v, state)))
                .collect();
            // Map puramente de datos → un solo dato (congelado, o la copia de siempre).
            if entries.iter().all(|(_, gv)| matches!(gv, GlobalVal::Value(_) | GlobalVal::Frozen(_))) {
                return data_global(v, state);
            }
            // Map de datos con callbacks (tasks que NO cierran sobre un módulo).
            GlobalVal::MapWithTasks(entries)
        }
        // Ronda 2 (R2, B3): una lista con tasks cruza como un mapa con tasks. Primero el congelado
        // (lo que congela no tiene tasks): una lista grande de datos no se recorre dos veces.
        SynValue::List(l) => match frozen_global(v, state) {
            Some(g) => g,
            None if has_callable(v) => {
                GlobalVal::ListWithTasks(l.borrow().to_vec().iter().map(|x| val_to_global_inner(x, state)).collect())
            }
            None => GlobalVal::Value(synsema_core::rng::with_stubbed_globals(|| to_send(v))),
        },
        // Una lista (o lo que sea) con un generador adentro: el generador cruza como stub.
        other => data_global(other, state),
    }
}

/// v0.6.50 (B): la foto de una task de confianza: la task y el entorno de su tool (inline la primera
/// vez en este árbol de foto, por id después, como la rama `Module`).
fn trusted_task_global(b: &synsema_core::interpreter::BuiltinTask, state: &mut SnapState) -> GlobalVal {
    let (module, export, t) = synsema_core::interpreter::trusted_tool_parts(b).expect("una task de confianza");
    let module_env = t.closure_env.clone();
    let env_id = module_env.borrow().name.to_string();
    let env = env_bindings(&module_env, state);
    GlobalVal::TrustedTask {
        module: module.to_string(),
        export: export.to_string(),
        task: Box::new(val_to_global_inner(&SynValue::Task(t.clone()), state)),
        env_id,
        env,
    }
}

/// Devuelve el `module_env` de un map que es alias de módulo: el `closure_env` de
/// cualquiera de sus tasks cuyo env se llame `module:…`. `None` si el map no es un alias
/// de módulo (sus tasks cierran sobre el global u otro scope → map de datos con callbacks).
pub(crate) fn module_env_of(map: &MapObj) -> Option<Rc<RefCell<Environment>>> {
    for v in map.values() {
        if let SynValue::Task(t) = v {
            if t.closure_env.borrow().name.starts_with("module:") {
                return Some(t.closure_env.clone());
            }
        }
    }
    None
}

/// Registro `id → module_env` de UN rebuild (per-request/per-worker): toda referencia
/// al mismo módulo (diamante, alias, task aplicada) resuelve al MISMO env, igual que
/// `module_cache` bajo `run`. Vive lo que dura ese rebuild — NUNCA se comparte entre
/// requests o workers (el aislamiento CSP no cambia; el estado entre requests es
/// `state_set`/SQL/`remember`).
pub(crate) type ModuleRegistry = HashMap<String, Rc<RefCell<Environment>>>;

/// v0.6.50: de qué cuelga lo que reconstruye un rebuild en ESTE intérprete. Un módulo de archivo, de
/// la foto de su preludio (A); una tool de confianza, de su base de confianza, con su hook (B). Lo
/// que el intérprete tiene que anotar al terminar (las tasks envueltas, las vistas) se junta acá y
/// lo aplica `finish`.
pub(crate) struct Bases {
    /// El global del intérprete: donde cierra una task de raíz `Global` (ronda 1, A1).
    global: Rc<RefCell<Environment>>,
    module: Rc<RefCell<Environment>>,
    trusted: Option<Rc<RefCell<Environment>>>,
    hook: Option<synsema_core::interpreter::TrustedScopeHook>,
    wrapped: RefCell<Vec<String>>,
    views: RefCell<Vec<(String, synsema_core::types::MapRef)>>,
}

impl Bases {
    /// Las bases de `interp`. Antes de inyectarle globales: la foto es su preludio.
    pub(crate) fn of(interp: &mut Interpreter) -> Bases {
        interp.snapshot_module_base();
        Bases {
            global: interp.global_env.clone(),
            module: interp.module_base(),
            trusted: interp.trusted_base_for_rebuild(),
            hook: interp.trusted_scope_hook(),
            wrapped: RefCell::new(Vec::new()),
            views: RefCell::new(Vec::new()),
        }
    }

    fn for_id(&self, id: &str) -> &Rc<RefCell<Environment>> {
        match &self.trusted {
            Some(t) if id.starts_with("module:trusted:") => t,
            _ => &self.module,
        }
    }

    pub(crate) fn finish(self, interp: &mut Interpreter) {
        for name in self.wrapped.into_inner() {
            interp.mark_label_aware(&name);
        }
        for (module, view) in self.views.into_inner() {
            interp.adopt_trusted_view(&module, &view);
        }
    }
}

/// Reconstruye (o reusa del registro) el `module_env` compartido de un módulo, hijo de
/// `base`, con cada task cerrando sobre ESE env → las hermanas (exportadas o no) se
/// resuelven por nombre simple. Reproduce la estructura de `load_module_inner` de core.
/// Compartido por la rama Module de `rebuild_global_val` (globales, DE-027) y por
/// `reconstruct_task` de `parallel_map` (task aplicada, DE-030).
pub(crate) fn rebuild_module_env(
    id: &str,
    env: &[(String, GlobalVal)],
    base: &Bases,
    registry: &mut ModuleRegistry,
    scope: Option<&synsema_core::frozen::ScopeCtx>,
) -> Rc<RefCell<Environment>> {
    // Identidad primero: si ESTE rebuild ya reconstruyó el módulo (p.ej. llegó por otro
    // brazo del diamante, o la task aplicada es de un módulo también global), reusar ese
    // env — un solo D compartido, como `module_cache` bajo `run`.
    if let Some(e) = registry.get(id) {
        return e.clone();
    }
    // El env reconstruido conserva el nombre ORIGINAL ("module:<resolved>"), no un
    // placeholder: `module_env_of` y el check de `parallel_map` dependen del prefijo
    // "module:", y el dedup de un re-snapshot anidado (parallel_map dentro de un route
    // handler bajo serve) depende del nombre COMPLETO.
    let module_env = Environment::child(base.for_id(id), id);
    // Registrar ANTES de poblar: un map interno auto-referencial (TOOL_ALLOW — DE-032)
    // que aparezca durante la población resuelve a ESTE env en construcción.
    registry.insert(id.to_string(), module_env.clone());
    for (k, gv) in env {
        let v = rebuild_global_val(gv, &module_env, base, registry, scope);
        module_env.borrow_mut().bindings.insert(k.clone(), v);
    }
    module_env
}

/// Ronda 3 (R3): lo que un worker recibe en lugar de un builtin que no tiene: falla al llamarlo.
fn uncrossable_stub(name: &str, why: &str) -> SynValue {
    let msg = format!("'{}' {}", name, why);
    SynValue::Builtin(Rc::new(synsema_core::interpreter::BuiltinTask::new(
        name,
        -1,
        None,
        Rc::new(move |_i, _a, _l| Err(synsema_core::interpreter::Control::Error(synsema_core::interpreter::RuntimeError::new(msg.clone())))),
    )))
}

/// Reconstruye un `SynValue` desde un `GlobalVal`. `closure_target` es el env que
/// capturan las tasks (para top-level es el global; para una task de módulo es el
/// `module_env` compartido). `base` es el padre para nuevos `module_env`: la foto del preludio
/// del intérprete (`Interpreter::module_base`), igual que `load_module_inner` — v0.6.50 (A): un
/// módulo no ve los globales del request. Las tasks cierran sobre `closure_target` para que la recursión mutua entre
/// globales y la llamada a hermanas dentro de un módulo (DE-027) sigan funcionando.
/// `registry` dedupea los `module_env` de este rebuild por id (DE-033).
pub(crate) fn rebuild_global_val(
    gv: &GlobalVal,
    closure_target: &Rc<RefCell<Environment>>,
    base: &Bases,
    registry: &mut ModuleRegistry,
    scope: Option<&synsema_core::frozen::ScopeCtx>,
) -> SynValue {
    match gv {
        GlobalVal::Value(sv) => from_send(sv),
        GlobalVal::Frozen(f) => f.get(),
        GlobalVal::Scoped(i) => scope.expect("un valor con alcance se reconstruye dentro de su alcance").get(*i),
        GlobalVal::Task { name, parameters, body, required_capabilities, root, frames, free_names } => {
            // Ronda 1 (A1) y ronda 2 (R2): cierra en su cadena, no donde está guardada. El módulo de
            // la raíz viene inline la primera vez en la foto o ya está en el registro; si no está en
            // ningún lado, un env vacío de ese módulo (el nombre falta; nunca el de otro módulo).
            let mut closure_env = match root {
                TaskRoot::Global => base.global.clone(),
                TaskRoot::Module { id, env: Some(entries) } => rebuild_module_env(id, entries, base, registry, scope),
                TaskRoot::Module { id, env: None } => {
                    registry.get(id).cloned().unwrap_or_else(|| Environment::child(base.for_id(id), id))
                }
                TaskRoot::Here => closure_target.clone(),
            };
            for f in frames {
                let e = match registry.get(&f.id) {
                    Some(e) => e.clone(),
                    None => {
                        let e = Environment::child(&closure_env, &f.name);
                        // Registrar ANTES de poblar: una task del frame que lo nombra resuelve acá.
                        registry.insert(f.id.clone(), e.clone());
                        e
                    }
                };
                // Ronda 3 (R3): lo que esta task nombra y todavía no estaba en la copia del frame.
                for (k, gv) in f.env.iter().flatten() {
                    let v = rebuild_global_val(gv, &e, base, registry, scope);
                    e.borrow_mut().bindings.insert(k.clone(), v);
                }
                closure_env = e;
            }
            SynValue::Task(Rc::new(SynTaskValue {
                name: name.clone(),
                parameters: parameters.clone(),
                body: body.clone(),
                closure_env,
                origin: None,
                required_capabilities: required_capabilities.clone(),
                code: Default::default(),
                free_names: free_names.clone().map(std::cell::OnceCell::from).unwrap_or_default(),
            }))
        }
        GlobalVal::Module { id, is_alias, alias, env } => {
            // Resolver el `module_env` compartido: el primer encuentro (env inline) lo
            // construye y registra; una referencia (env: None) lo toma del registro.
            let module_env = match env {
                Some(entries) => rebuild_module_env(id, entries, base, registry, scope),
                None => match registry.get(id) {
                    Some(e) => e.clone(),
                    None => {
                        // Fallback defensivo (jamás panic): inalcanzable por construcción
                        // para imports (`use`) — el primer encuentro siempre viaja con el
                        // env inline y el rebuild recorre en el mismo orden. Solo llegaría
                        // acá una mutación exótica post-load (inyectar en un map de módulo
                        // tasks de OTRO módulo no alcanzado por el snapshot). Se registra
                        // el env vacío para que al menos todas las referencias compartan.
                        let e = Environment::child(base.for_id(id), id);
                        registry.insert(id.clone(), e.clone());
                        e
                    }
                },
            };
            // Materializar el map: las entries que eran EL MISMO objeto que el binding
            // homónimo del env (`is_export`) se COSECHAN del env reconstruido — misma
            // identidad alias↔env que los exports de `load_module_inner` bajo `run`
            // (mutar `d.STATE` y leer vía una task del módulo ven el mismo objeto). Las
            // demás se materializan cerrando sobre el module_env (donde viven las
            // hermanas), igual que antes.
            // Un módulo tiene UN mapa de exportaciones: si este rebuild ya armó el del módulo (otro
            // alias, un re-export `export let L be lib`, `{"l": lib}`), es ése — con sus entradas
            // al día desde el env —, no una copia que después quedaría desconectada.
            if *is_alias {
                if let Some(existing) = synsema_core::interpreter::module_map_of_env(&module_env) {
                    for (k, _, is_export) in alias {
                        if *is_export {
                            if let Some(v) = module_env.borrow().bindings.get(k.as_str()).cloned() {
                                existing.borrow_mut().insert(k.clone(), v);
                            }
                        }
                    }
                    return SynValue::Map(existing);
                }
            }
            let mut m = SynMap::new();
            for (k, gv, is_export) in alias {
                let harvested = if *is_export {
                    module_env.borrow().bindings.get(k.as_str()).cloned()
                } else {
                    None
                };
                let v = match harvested {
                    Some(v) => v,
                    // `is_export` sin binding aún: referencia dentro de un env en plena
                    // población (orden arbitrario del HashMap de bindings) → materializar
                    // desde el GlobalVal como fallback.
                    None => rebuild_global_val(gv, &module_env, base, registry, scope),
                };
                m.insert(k.clone(), v);
            }
            let map = m.into_ref();
            if *is_alias {
                synsema_core::interpreter::register_module(&map, &module_env);
            }
            SynValue::Map(map)
        }
        GlobalVal::SharedRng(name) => synsema_core::rng::top_level_stub(name),
        GlobalVal::CapturedRng(name) => synsema_core::rng::captured_stub(name),
        GlobalVal::Builtin(name) => match base.module.borrow().bindings.get(name) {
            Some(v @ SynValue::Builtin(b)) if b.name == *name => v.clone(),
            _ => uncrossable_stub(
                name,
                "is a builtin this worker does not have (it exists only where the program runs: a `serve` request, an agent, or the host's interpreter): call it there and pass its result",
            ),
        },
        GlobalVal::Constructor(c) => synsema_core::interpreter::constructor_value(c.clone()),
        GlobalVal::Uncrossable(name) => uncrossable_stub(
            name,
            "is a closure of the engine that does not cross into a worker: call it before and pass its result",
        ),
        GlobalVal::TrustedTask { module, export, task, env_id, env } => {
            let module_env = match env {
                Some(entries) => rebuild_module_env(env_id, entries, base, registry, scope),
                None => match registry.get(env_id) {
                    Some(e) => e.clone(),
                    None => {
                        let e = Environment::child(base.for_id(env_id), env_id);
                        registry.insert(env_id.clone(), e.clone());
                        e
                    }
                },
            };
            match (rebuild_global_val(task, &module_env, base, registry, scope), &base.hook) {
                (SynValue::Task(t), Some(hook)) => {
                    let w = synsema_core::interpreter::wrap_trusted_task(module, export, t, hook.clone());
                    if let SynValue::Builtin(b) = &w {
                        base.wrapped.borrow_mut().push(b.name.clone());
                    }
                    w
                }
                // Sin hook este proceso no cargó tools (no puede pasar: la foto es del mismo proceso).
                _ => SynValue::Nothing,
            }
        }
        GlobalVal::TrustedView(entries) => {
            let mut m = SynMap::new();
            let mut module = None;
            for (k, gv) in entries {
                let v = rebuild_global_val(gv, closure_target, base, registry, scope);
                if let SynValue::Builtin(b) = &v {
                    if let Some((md, _, _)) = synsema_core::interpreter::trusted_tool_parts(b) {
                        module.get_or_insert_with(|| md.to_string());
                    }
                }
                m.insert(k.clone(), v);
            }
            let map = m.into_ref();
            synsema_core::interpreter::register_rebuilt_trusted_view(&map);
            if let Some(md) = module {
                base.views.borrow_mut().push((md, map.clone()));
            }
            SynValue::Map(map)
        }
        GlobalVal::MapWithTasks(entries) => {
            // Map de datos con callbacks: cada task cierra en su raíz (ronda 1, A1: una lambda del
            // programa guardada en un módulo sigue viendo el programa; una del módulo, el módulo).
            let mut m = SynMap::new();
            for (k, gv) in entries {
                m.insert(k.clone(), rebuild_global_val(gv, closure_target, base, registry, scope));
            }
            SynValue::Map(m.into_ref())
        }
        GlobalVal::ListWithTasks(items) => synsema_core::types::syn_list(
            items.iter().map(|gv| rebuild_global_val(gv, closure_target, base, registry, scope)).collect(),
        ),
        GlobalVal::Agent { .. } => {
            // Los agentes van a `agent_definitions`, nunca a bindings — no debería llegar aquí.
            SynValue::Nothing
        }
    }
}

/// Snapshot de las bindings globales (tras correr el top-level). Los builtins se
/// re-registran por intérprete (no se copian); las tasks se copian con su AST;
/// los módulos importados (maps con tasks) se snapshotean recursivamente. Los datos según
/// cuánto vive la foto (R2): congelados para siempre (`snapshot_globals_frozen`), compartiendo lo
/// ya permanente y copiando el resto (`snapshot_globals_shared`), o congelados mientras corre un
/// alcance (`snapshot_globals_scoped`).
///
/// Congelando los datos en el lugar (R2): todos los workers leen las mismas
/// globales, sin una copia por worker. **Sólo para una foto que vive lo que el proceso** (las
/// globales del preámbulo de `serve`, el proceso de sólo `cron`): un inmortal no se libera nunca, así
/// que congelar en una foto que se repite (`parallel_map`, `cron_every` desde una ruta) sería una
/// fuga. Después de esto el programa sigue andando igual: escribir una global congelada copia.
pub(crate) fn snapshot_globals_frozen(interp: &Interpreter) -> Arc<Vec<(String, GlobalVal)>> {
    snapshot_globals_with(interp, true, None)
}

/// Las globales compartiendo lo que ya está congelado para siempre y copiando el resto (R2.4):
/// para una foto que se puede repetir y cuyos hilos viven libres (`cron_every`, también desde una
/// ruta). Congelar ahí sería una fuga por foto; compartir lo permanente, no.
pub(crate) fn snapshot_globals_shared(interp: &Interpreter) -> Arc<Vec<(String, GlobalVal)>> {
    snapshot_globals_mode(interp, false, None, true)
}

/// Las globales congelando los datos SÓLO mientras corren los hilos de `scope` (R2.3,
/// `parallel_map`): los hilos los leen sin una copia por item, y al terminar vuelven a ser objetos
/// comunes (`ScopedFreeze::run`). Reconstruir esta foto pide el `ScopeCtx` (`rebuild_globals`).
pub(crate) fn snapshot_globals_scoped(
    interp: &Interpreter,
    scope: &mut synsema_core::frozen::ScopedFreeze,
) -> Arc<Vec<(String, GlobalVal)>> {
    snapshot_globals_with(interp, false, Some(scope))
}

fn snapshot_globals_with(
    interp: &Interpreter,
    freeze: bool,
    scoped: Option<&mut synsema_core::frozen::ScopedFreeze>,
) -> Arc<Vec<(String, GlobalVal)>> {
    snapshot_globals_mode(interp, freeze, scoped, false)
}

fn snapshot_globals_mode(
    interp: &Interpreter,
    freeze: bool,
    scoped: Option<&mut synsema_core::frozen::ScopedFreeze>,
    share: bool,
) -> Arc<Vec<(String, GlobalVal)>> {
    let env = interp.global_env.borrow();
    let mut out: Vec<(String, GlobalVal)> = Vec::new();
    // UN SnapState para TODOS los bindings: el diamante entre bindings top-level (b y c
    // importan d) dedupea — el env de d viaja UNA vez y la otra aparición es referencia
    // por id. El orden del Vec se conserva → en rebuild el primer encuentro (que lleva
    // el env inline) siempre se procesa antes que sus referencias.
    let mut state = SnapState { freeze, scoped, share, ..SnapState::default() };
    for (k, v) in env.bindings.iter() {
        // Ronda 3 (R3): sólo el builtin del lenguaje con su propio nombre lo vuelve a registrar
        // `wire_common`; un alias, un constructor o una task de confianza cruzan.
        if matches!(v, SynValue::Builtin(b) if synsema_core::interpreter::is_own_builtin(k, b)) {
            continue;
        }
        out.push((k.to_string(), val_to_global_inner(v, &mut state)));
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
/// la recursión mutua y el acceso a otros globales sigan funcionando. Devuelve el
/// `ModuleRegistry` de este rebuild — `parallel_map` lo necesita para que la task
/// aplicada de un módulo TAMBIÉN global reuse el mismo `module_env` (DE-033); los demás
/// call sites pueden ignorarlo.
pub(crate) fn rebuild_globals(
    interp: &mut Interpreter,
    snapshot: &[(String, GlobalVal)],
    scope: Option<&synsema_core::frozen::ScopeCtx>,
) -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    // Agentes (Batch 6): van al mapa separado `agent_definitions` (NO a bindings). Se
    // insertan vía `restore_agents` — el MISMO camino que la restauración post-request
    // de `with_serve_interp` — para que build fresco y reset no puedan divergir (si
    // divergieran, el bug pocos-cores volvería sólo en uno de los dos caminos).
    restore_agents(interp, snapshot);
    // v0.6.50 (A): la foto del preludio ANTES de inyectar los globales (ahora el global del
    // intérprete es sólo el preludio). Una vez por intérprete: un worker que se reusa ya la tiene.
    let bases = Bases::of(interp);
    for (k, gv) in snapshot {
        match gv {
            GlobalVal::Agent { .. } => {}
            other => {
                // Top-level: las tasks cierran sobre el global (closure_target); los nuevos
                // module_env cuelgan de la foto del preludio (base).
                let genv = interp.global_env.clone();
                let v = rebuild_global_val(other, &genv, &bases, &mut registry, scope);
                interp.set_global(k, v);
            }
        }
    }
    bases.finish(interp);
    registry
}

/// Re-inserta SOLO los agentes del snapshot en `agent_definitions`. `reset_for_request`
/// los borra (aislamiento: un `agent` definido dentro de un handler no se filtra al
/// siguiente request), pero el intérprete base se REUSA entre requests del mismo worker
/// — sin esta restauración, el segundo request del worker daría "No agent defined".
/// Sólo se manifiesta con pocos workers (una VPS de 1-2 cores dimensiona el pool chico
/// y los requests reusan siempre el mismo worker); con muchos cores cada request suele
/// caer en un worker virgen y el bug queda latente.
pub(crate) fn restore_agents(interp: &mut Interpreter, snapshot: &[(String, GlobalVal)]) {
    for (k, gv) in snapshot {
        if let GlobalVal::Agent { body } = gv {
            let genv = interp.global_env.clone();
            interp.agent_definitions.insert(k.clone(), (body.clone(), genv));
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
/// T5 (ronda 7/8) — **lo que un request escribió en el almacén compartido no puede sobrevivirle
/// si el chequeo de flujo lo cortó, y deshacerlo no puede pisar lo que otros confirmaron.**
///
/// El canal (ronda 7): el prefijo de un bucle incrementa `state_incr("n")` con PC público —legal
/// en ese momento—, el request muere en la vuelta del secreto, y OTRA ruta lee ese contador como
/// un número público.
///
/// El fallo de INTEGRIDAD que introdujo el primer arreglo (ronda 8): guardaba el valor ABSOLUTO
/// previo y lo reponía, así que con concurrencia real el request que moría deshacía en silencio
/// lo que otros tres habían recibido confirmado (medido: `visits` llega a 6 y vuelve a 2). Un
/// arreglo de confidencialidad no puede pagarse con corrupción de datos.
///
/// Así que el diario deshace **sólo lo que se puede atribuir a este request**:
///
/// · `state_incr` anota el **delta acumulado** y el rollback resta. La suma conmuta, así que es
///   correcto con cualquier intercalado: lo de los demás queda.
/// · `state_set`/`state_delete` anotan el valor previo **y el que dejó este request**, y el
///   rollback repone sólo si el valor actual sigue siendo el suyo (comparar-y-cambiar). Si otro
///   escribió en el medio, no se toca: pisarlo sería el mismo fallo de integridad.
/// · Una clave que recibió las dos formas se trata como absoluta, que es la conservadora.
#[derive(Clone)]
enum StateUndo {
    /// Sólo incrementos: el delta acumulado por este request.
    Delta(Number),
    /// Hubo `set`/`delete`: el valor previo y el último que dejó este request.
    Absolute { prev: Option<SendValue>, mine: Option<SendValue> },
}

thread_local! {
    /// El diario del request en curso de ESTE worker (uno por vez). `None` = sin etiquetas.
    static STATE_JOURNAL: RefCell<Option<Vec<(String, StateUndo)>>> = const { RefCell::new(None) };
}

/// Arranca el diario del request (sólo con etiquetas encendidas).
fn arm_state_journal() {
    if !crate::host::labels() {
        return;
    }
    STATE_JOURNAL.with(|j| *j.borrow_mut() = Some(Vec::new()));
}

fn with_journal(f: impl FnOnce(&mut Vec<(String, StateUndo)>)) {
    STATE_JOURNAL.with(|j| {
        let mut j = j.borrow_mut();
        if let Some(undo) = j.as_mut() {
            f(undo);
        }
    });
}

/// Anota un incremento de `key` por `delta`.
fn journal_state_incr(key: &str, delta: &Number) {
    with_journal(|undo| {
        if let Some((_, e)) = undo.iter_mut().find(|(k, _)| k == key) {
            if let StateUndo::Delta(acc) = e {
                *acc = match (&acc, delta) {
                    (Number::Int(a), Number::Int(b)) => Number::Int(a + b),
                    _ => Number::Float(acc.to_f64() + delta.to_f64()),
                };
            }
            // Si ya es Absolute, la clave queda en el camino conservador: el `mine` lo
            // actualiza `journal_state_write` en cada escritura posterior.
            return;
        }
        undo.push((key.to_string(), StateUndo::Delta(delta.clone())));
    });
}

/// Anota una escritura absoluta de `key`: el valor previo (la primera vez) y el que queda.
fn journal_state_write(store: &HashMap<String, SendValue>, key: &str, mine: Option<SendValue>) {
    with_journal(|undo| {
        if let Some((_, e)) = undo.iter_mut().find(|(k, _)| k == key) {
            match e {
                StateUndo::Absolute { mine: m, .. } => *m = mine,
                // Venía por incrementos: pasa a absoluta y se renuncia a deshacerlos (no se sabe
                // el valor previo real). Conservador: sólo repone si nadie más tocó la clave.
                StateUndo::Delta(_) => {
                    *e = StateUndo::Absolute { prev: store.get(key).cloned(), mine };
                }
            }
            return;
        }
        undo.push((key.to_string(), StateUndo::Absolute { prev: store.get(key).cloned(), mine }));
    });
}

/// Cierra el diario. Con `rollback`, deshace lo atribuible a este request.
fn finish_state_journal(state: &SharedState, rollback: bool) {
    let undo = STATE_JOURNAL.with(|j| j.borrow_mut().take());
    let Some(undo) = undo else { return };
    if !rollback || undo.is_empty() {
        return;
    }
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for (key, u) in undo.into_iter().rev() {
        match u {
            StateUndo::Delta(d) => {
                let current = match guard.get(&key) {
                    Some(SendValue::Number(n)) => n.clone(),
                    _ => continue, // ya no es un número: no es nuestro, no se toca
                };
                let back = match (&current, &d) {
                    (Number::Int(a), Number::Int(b)) => Number::Int(a - b),
                    _ => Number::Float(current.to_f64() - d.to_f64()),
                };
                guard.insert(key, to_send(&SynValue::Number(back)));
            }
            StateUndo::Absolute { prev, mine } => {
                // Comparar-y-cambiar: sólo si el valor actual sigue siendo el que dejamos.
                let current = guard.get(&key).cloned();
                if send_eq(current.as_ref(), mine.as_ref()) {
                    match prev {
                        Some(v) => {
                            guard.insert(key, v);
                        }
                        None => {
                            guard.remove(&key);
                        }
                    }
                }
            }
        }
    }
}

/// Igualdad suficiente para el comparar-y-cambiar del diario (por su forma serializada).
fn send_eq(a: Option<&SendValue>, b: Option<&SendValue>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => from_send(x).to_string() == from_send(y).to_string(),
        _ => false,
    }
}

fn register_serve_state_builtins(interp: &Interpreter, state: SharedState) {
    // v0.6.42 — todo intérprete de serve (handlers, cron, agentes) pasa por acá: `exit` es de
    // `run`; bajo serve remite a `shutdown`.
    synsema_stdlib::server::register_serve_exit_builtin(interp);
    {
        let s = state.clone();
        interp.register_builtin("state_set", 2, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_set: missing key"))),
            };
            let val = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            let mut guard = s.lock().unwrap();
            let sent = to_send(&val);
            journal_state_write(&guard, &key, Some(sent.clone()));
            guard.insert(key, sent);
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
                Some(SynValue::Number(n)) => n.clone(),
                _ => Number::Int(1), // default entero
            };
            let mut guard = s.lock().unwrap();
            journal_state_incr(&key, &delta);
            let current = match guard.get(&key) {
                Some(SendValue::Number(n)) => n.clone(),
                _ => Number::Int(0),
            };
            // Aritmética entera cuando AMBOS son Int (contadores → JSON `1`, no `1.0`);
            // Float si alguno es Float/Big (DE-009). `SendValue::Number` preserva la
            // variante Int/Float en el round-trip al state compartido.
            let new_val = match (&current, &delta) {
                (Number::Int(a), Number::Int(b)) => Number::Int(a + b),
                _ => Number::Float(current.to_f64() + delta.to_f64()),
            };
            guard.insert(key, to_send(&SynValue::Number(new_val.clone())));
            Ok(SynValue::Number(new_val))
        }));
    }
    // v0.6.45 (A8) — leer-modificar-guardar de un mapa desde varios requests a la vez perdía
    // escrituras (13 webhooks simultáneos: llegaron 7). Las dos operaciones corren enteras bajo el
    // mismo candado. No hay `state_update(k, fn)` a propósito: una lambda que corra bajo el candado
    // global y llame a `state_*` se traba.
    {
        let s = state.clone();
        interp.register_builtin("state_merge", 2, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_merge: missing key"))),
            };
            let patch = match args.get(1) {
                Some(SynValue::Map(m)) => m.clone(),
                Some(other) => {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "state_merge: the second argument must be a map, got {}",
                        other.type_name()
                    ))))
                }
                None => return Err(Control::Error(RuntimeError::new("state_merge: missing the map to merge"))),
            };
            let mut guard = s.lock().unwrap();
            let mut merged = SynMap::new();
            match guard.get(&key).map(from_send) {
                None | Some(SynValue::Nothing) => {}
                Some(SynValue::Map(m)) => {
                    for (k, v) in m.borrow().iter() {
                        merged.insert(k.clone(), v.clone());
                    }
                }
                Some(other) => {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "state_merge: the value of '{}' is {}, not a map — use state_set to replace it",
                        key,
                        other.type_name()
                    ))))
                }
            }
            for (k, v) in patch.borrow().iter() {
                merged.insert(k.clone(), v.clone());
            }
            let val = SynValue::Map(merged.into_ref());
            let sent = to_send(&val);
            journal_state_write(&guard, &key, Some(sent.clone()));
            guard.insert(key, sent);
            Ok(val)
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_cas", 3, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_cas: missing key"))),
            };
            let expected = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            let new = args.get(2).cloned().unwrap_or(SynValue::Nothing);
            let mut guard = s.lock().unwrap();
            // Una clave ausente vale `nothing`, como en `state_get`.
            let current = guard.get(&key).map(from_send).unwrap_or(SynValue::Nothing);
            if !current.syn_equals(&expected) {
                return Ok(syn_bool(false));
            }
            let sent = to_send(&new);
            journal_state_write(&guard, &key, Some(sent.clone()));
            guard.insert(key, sent);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_delete", 1, Rc::new(move |_i, args, _l| {
            let key = match args.first() {
                Some(v) => v.to_string(),
                None => return Err(Control::Error(RuntimeError::new("state_delete: missing key"))),
            };
            let mut guard = s.lock().unwrap();
            journal_state_write(&guard, &key, None);
            guard.remove(&key);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = state.clone();
        interp.register_builtin("state_all", 0, Rc::new(move |_i, _args, _l| {
            let guard = s.lock().unwrap();
            let mut map = SynMap::new();
            for (k, sv) in guard.iter() {
                map.insert(k.clone(), from_send(sv));
            }
            Ok(SynValue::Map(map.into_ref()))
        }));
    }
}

/// Tanda TEE (T5, auditoría ronda 3, M3) — los builtins que ve un WORKER de `serve`: el wiring
/// común más lo que el runtime registra por worker (estado compartido, memoria/progreso
/// compartidos, cron y db del proceso) y los del swarm (`agents`/`agent_stop`). El anti-rot
/// `every_effectful_family_is_a_label_sink` lo cruza con las listas de clasificación igual que al
/// wiring de `run`: sin esto la garantía no cubría justo el modo que usa `--attested`, y por ese
/// hueco `state_all` era el único de su familia sin declarar.
pub fn registered_serve_builtin_names() -> Vec<String> {
    use std::collections::HashMap as StdHashMap;
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("probe")));
    crate::engine::wire_common(&mut interp, &caps, false, None, "probe");
    let shared_state: SharedState = Arc::new(Mutex::new(StdHashMap::new()));
    register_serve_state_builtins(&interp, shared_state);
    let shared_memory: SharedMemoryStore = Arc::new(Mutex::new(AgentMemory::new()));
    let shared_progress: SharedProgressStore = Arc::new(Mutex::new(ProgressManager::new()));
    let gate = crate::engine::undeclared_memory_gate("probe".to_string());
    let on_write: OnWriteFn = Arc::new(|_: &AgentMemory| {});
    let on_write_progress: OnWriteProgressFn = Arc::new(|_: &ProgressManager| {});
    register_serve_memory_builtins(&interp, shared_memory, on_write, gate.clone());
    register_serve_progress_builtins(&interp, shared_progress, on_write_progress, gate);
    register_database_builtins(&interp, Arc::new(Mutex::new(DatabaseManager::new())), caps.clone());
    // Swarm: `agents`/`agent_stop` (sólo existen con el swarm cableado, como bajo `serve`).
    wire_swarm_hooks(&mut interp, Arc::new(Swarm::new()), "main", None, None, None, &caps);
    let env = interp.global_env.borrow();
    let mut names: Vec<String> = env
        .bindings
        .iter()
        .filter(|(_, v)| matches!(v, SynValue::Builtin(_)))
        .map(|(k, _)| k.to_string())
        .collect();
    names.sort();
    names
}

/// Sink global de las líneas de log de los handlers de `serve` (DE-034). Por defecto
/// (`None`) cada línea va a stdout con prefijo `[serve]`. Un embedder —o un test— puede
/// instalar el suyo con [`set_serve_log_sink`] (p.ej. para enrutar a un logger o
/// capturarlas). Se resuelve UNA vez por worker al construir el intérprete base, así que
/// instalalo ANTES de arrancar el server.
static SERVE_LOG_SINK: Mutex<Option<ServeLogSink>> = Mutex::new(None);

/// Sink de una línea de log de serve (thread-safe: lo comparten workers y jobs).
pub type ServeLogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Instala el sink global de logs de `serve`. Pasá `None` para volver al default (stdout).
pub fn set_serve_log_sink(sink: Option<ServeLogSink>) {
    *SERVE_LOG_SINK.lock().unwrap() = sink;
}

/// v0.6.47 (T1): bajo `serve` con etiquetas no hay modo dueño (quien llama a un server es otro; el
/// detalle de un corte ya va sólo al recibo). Lo que imprime un request o un tick del cron se retiene
/// y se escribe al terminar, sólo si no lo cortaron las etiquetas: si saliera en vivo, cuántas líneas
/// salieron antes del corte lo elegiría el dato, y bajo `--attested` el log está fuera del enclave.
/// La salida de los agentes no se escribe (ver `Swarm::dropping_output`).
const SERVE_LABELS_LOG_NOTICE: &str = "labels: request and cron output is logged when each one ends, and not at all if a label cut stopped it; agent output is not logged (which agent stopped would be the private data)";

/// Tope de lo retenido por request (líneas): lo que pasa del tope se descarta y se cuenta.
const SERVE_LABELS_LOG_CAP: usize = 10_000;

fn labels_swarm(s: Swarm) -> Swarm {
    if crate::host::labels() {
        s.dropping_output().journaling_runs()
    } else {
        s
    }
}

/// Lo retenido de un request: `(es_stderr, línea)` y cuántas quedaron afuera del tope.
#[derive(Default)]
struct HeldServeLog {
    lines: Vec<(bool, String)>,
    dropped: usize,
}

impl HeldServeLog {
    fn push(&mut self, err: bool, line: &str) {
        if self.lines.len() < SERVE_LABELS_LOG_CAP {
            self.lines.push((err, line.to_string()));
        } else {
            self.dropped += 1;
        }
    }
}

/// Engancha la salida del intérprete a un buffer por request (con etiquetas).
fn hold_serve_log(interp: &mut Interpreter) -> Arc<Mutex<HeldServeLog>> {
    let held: Arc<Mutex<HeldServeLog>> = Arc::default();
    let (out, err) = (held.clone(), held.clone());
    interp.log_hook = Some(Arc::new(move |line: &str| out.lock().unwrap().push(false, line)));
    interp.err_hook = Some(Arc::new(move |line: &str| err.lock().unwrap().push(true, line)));
    held
}

/// Suelta lo retenido: entero si no hubo corte; si lo hubo, la línea fija y nada más.
fn release_serve_log(interp: &mut Interpreter, held: Arc<Mutex<HeldServeLog>>, stopped: bool) {
    interp.log_hook = Some(serve_log_sink());
    interp.err_hook = None;
    let held = std::mem::take(&mut *held.lock().unwrap());
    let sink = serve_log_sink();
    if stopped {
        sink(synsema_core::interpreter::LABELS_WITHHELD_OUTPUT);
        return;
    }
    for (err, line) in &held.lines {
        if *err {
            synsema_core::interpreter::write_stderr_lines(std::slice::from_ref(line));
        } else {
            sink(line);
        }
    }
    if held.dropped > 0 {
        sink(&format!("labels: {} line(s) over the cap of {} were not logged", held.dropped, SERVE_LABELS_LOG_CAP));
    }
}

/// v0.6.47 (T1): una línea de stderr del server sobre una entrada (la task de `auth with` o de
/// `errors with` que falló) va con el resto del log de esa entrada: con etiquetas se retiene y, si la
/// entrada se cortó, no sale.
fn entry_eprintln(interp: &Interpreter, line: &str) {
    match &interp.err_hook {
        Some(hook) => hook(line),
        None => eprintln!("{}", line),
    }
}

/// v0.6.47 (T1): el valor que devuelve un handler y la respuesta va a rechazar (un privado sin
/// `declassify`) es un corte como cualquier otro: lo retenido del request no se escribe.
fn mark_if_response_refused(interp: &Interpreter, v: &SynValue) {
    if interp.labels_enabled() && synsema_core::labels::check_flow(v, &[], "response").is_err() {
        interp.mark_label_stop();
    }
}

/// Resuelve el sink de log de serve: el instalado o, por defecto, stdout `[serve] …`.
fn serve_log_sink() -> ServeLogSink {
    SERVE_LOG_SINK
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| Arc::new(|line: &str| println!("[serve] {line}")))
}

/// Construir esto es CARO (registrar ~100 builtins + recargar `.env` + clonar el AST
/// de cada task) y era el ~46% del CPU por request (medido en la VPS: profile-first).
/// Ahora se construye UNA vez por worker y se reusa entre requests (ver
/// `with_serve_interp`), no por request. Devuelve el `CapabilitySet` para poder
/// resetearlo entre requests (los grants del preámbulo, vía el `Rc` que capturan los
/// builtins gateados: secret/env/reveal/fetch/…).
#[allow(clippy::too_many_arguments)]
fn build_base_interp(
    swarm: Arc<Swarm>,
    snapshot: &[(String, GlobalVal)],
    caps_snap: &[Capability],
    shared_db: SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    agent_builder: Option<crate::engine::InterpBuilder>,
) -> (Interpreter, Rc<RefCell<CapabilitySet>>, Originals) {
    let mut interp = Interpreter::new();
    // DE-034: bajo `serve`, los `log`/`print`/`show` de DENTRO de un handler se
    // descartaban (el buffer `output` se limpia por request sin volcarse). Cableamos el
    // `log_hook` — espejo de los agentes del swarm (`setup_swarm_interpreter`) — para que
    // cada línea salga en tiempo real (a stdout por defecto; útil para SSE/handlers
    // largos). El `run` NO se toca: este wiring es exclusivo de la ruta serve.
    interp.log_hook = Some(serve_log_sink());
    let caps = Rc::new(RefCell::new(CapabilitySet::new("request")));
    // Techo del host (`serve --sandbox/--cap-set`): ANTES de wire_common para que los
    // auto-grants ambientales también se filtren; se propaga a los agentes spawneados.
    let host_ceiling = serve_ceiling();
    if let Some(cl) = &host_ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new((**cl).clone()));
    }
    // Gate de memoria declarada (DB-M1): mismo gate para la familia entera (memoria +
    // reglas + progress) contra las caps del WORKER — el snapshot del preámbulo trae
    // el grant de `memory("<nombre>")` si el programa lo declaró; un `sandbox` dentro
    // del handler lo vacía como al resto (G-2/G-9).
    let mem_gate = match mem_name {
        Some(n) => crate::engine::declared_memory_gate(caps.clone(), n.name.clone()),
        None => crate::engine::undeclared_memory_gate("my-agent".to_string()),
    };
    // Ctx compartido para lo que este worker propague (cron registrado desde rutas,
    // workers de parallel_map dentro de un handler): mismos stores + on_write.
    let mem_ctx: Option<crate::engine::MemoryCtx> = mem_name.as_ref().map(|n| crate::engine::MemoryCtx {
        name: n.name.clone(),
        memory: shared_memory.clone(),
        progress: shared_progress.clone(),
        on_write_mem: on_write.clone(),
        on_write_prog: on_write_progress.clone(),
        child: n.child.clone(),
    });
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
        mem_gate.clone(),
        mem_ctx.clone(),
    );
    // DE-029: cablear el provider LLM real (texto + paso tool-aware) también bajo serve,
    // para que reason/decide/generate/llm_step de los handlers no caigan a placeholders.
    // Por-worker (no por-request): el provider se resuelve una vez al construir la base.
    crate::engine::wire_real_llm_provider(&mut interp);
    crate::engine::wire_real_judge_provider(&mut interp);
    // Gates humanos (DX-3 etapa 1, A1.v2): bajo serve, `approve`/`confirm`/`ask` van a
    // la COLA compartida del server — el hilo del request BLOQUEA hasta la respuesta
    // humana (POST /approvals/{id} con el token de la consola) o el deadline (`within`
    // del gate > SYNSEMA_HUMAN_TIMEOUT > 300 s); al vencer DENIEGA fail-closed con
    // aviso único. OJO: un `within` largo retiene el hilo del request toda la espera —
    // v2 es para minutos, no días (la persistencia para esperas largas es v3).
    {
        let mgr = synsema_llm::human::InteractionManager::new(approvals.queue.clone())
            .with_default_timeout(approvals.default_timeout);
        interp.set_human_callback(mgr.get_callback());
    }
    // Sobrescribir los builtins de memoria (remember/recall/forget_memory/memory_summary)
    // con versiones que usan el AgentMemory compartido entre hilos.
    register_serve_memory_builtins(&interp, shared_memory.clone(), on_write.clone(), mem_gate.clone());
    // DE-028: ídem para el progress (create_progress/start_step/…/resume_point) → el
    // progressManager compartido entre hilos/requests, no el fresco per-intérprete.
    register_serve_progress_builtins(&interp, shared_progress.clone(), on_write_progress.clone(), mem_gate);
    // Registrar los builtins de estado compartido (state_set/state_get/state_incr/…).
    register_serve_state_builtins(&interp, shared_state.clone());
    // Cron del PROCESO (ejecución real): sobrescribe el scheduler fresco de
    // wire_common con el compartido del serve — un `cron_every` desde una ruta es
    // visible (y ejecuta) globalmente, no en una isla por-worker. WEAK: este
    // intérprete puede vivir en el thread-local de un hilo de tick; una referencia
    // fuerte acá sería el ciclo scheduler → job → interp → scheduler.
    register_cron_builtins(
        &interp,
        SchedRef::Weak(Arc::downgrade(&cron.sched)),
        shared_cron_executor(cron.tick_ctx(), serve_log_sink()),
    );
    {
        let mut c = caps.borrow_mut();
        for cap in caps_snap {
            c.grant(cap.clone());
        }
    }
    // Hooks del swarm con el techo del host y el CONSTRUCTOR de intérpretes de serve:
    // un agente spawneado desde un handler nace con el mismo wiring que un tick de cron
    // (state_*, DB compartida, approvals, cron, bus, memoria) — no en una isla.
    wire_swarm_hooks(&mut interp, swarm, "request", host_ceiling, mem_ctx, agent_builder, &caps);
    register_database_builtins(&interp, shared_db, caps.clone());
    let registry = rebuild_globals(&mut interp, snapshot, None);
    let originals = Originals::capture(&interp, snapshot, &registry);
    // A cargo del intérprete (un worker que se descarta tras un pánico, un agente de un handler):
    // se vacían cuando muere (ver `adopt_module_envs`).
    interp.adopt_module_envs(registry.into_values());
    (interp, caps, originals)
}

/// Los valores con que arrancan las globales del programa (y las variables de los módulos que
/// importa) en este worker. Cada request empieza con ellos: como el worker los sigue teniendo,
/// toda lista o mapa global tiene un dueño más, así que una escritura durante la request copia
/// primero (`make_unique`) y los originales no cambian. Al terminar, `restore` vuelve a atar cada
/// nombre a su original. Es lo que promete `serve.md`: un `set` de una global dentro de un handler
/// no llega a la request siguiente (hasta v0.6.37 quedaba en el worker que la atendió).
/// Clones de `Rc`: ningún dato se copia para guardarlos.
pub(crate) struct Originals {
    globals: Vec<(String, SynValue)>,
    modules: Vec<(Rc<RefCell<Environment>>, Vec<(Arc<str>, SynValue)>)>,
}

impl Originals {
    fn capture(interp: &Interpreter, snapshot: &[(String, GlobalVal)], registry: &ModuleRegistry) -> Originals {
        let genv = interp.global_env.borrow();
        let globals = snapshot
            .iter()
            .filter(|(_, gv)| !matches!(gv, GlobalVal::Agent { .. }))
            .filter_map(|(k, _)| genv.bindings.get(k).map(|v| (k.clone(), v.clone())))
            .collect();
        let modules = registry
            .values()
            .map(|env| {
                let vals = env.borrow().bindings.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                (env.clone(), vals)
            })
            .collect();
        Originals { globals, modules }
    }

    /// Vuelve a atar cada nombre a su original. Directo en los bindings, sin `set_global`: los
    /// principales de las etiquetas ya se cosecharon al construir el worker, y cosecharlos de nuevo
    /// recorrería todos los datos en cada request.
    fn restore(&self, interp: &Interpreter) {
        {
            let mut genv = interp.global_env.borrow_mut();
            for (k, v) in &self.globals {
                genv.bindings.set(k, v.clone());
            }
        }
        for (env, vals) in &self.modules {
            let mut e = env.borrow_mut();
            for (k, v) in vals {
                e.bindings.set_shared(k, v.clone());
            }
        }
    }
}

/// Intérprete base + sus capabilities, cacheado por-worker y reusado entre requests.
struct BaseInterp {
    interp: Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    /// Ver `Originals`: con qué valores empieza cada request.
    originals: Originals,
    /// Pinnea el snapshot mientras la entrada viva en el cache: la clave del cache es
    /// la DIRECCIÓN del Arc — si el snapshot se liberara, otro Arc podría alocarse en
    /// la misma dirección y colisionar con este intérprete (construido de otro mundo).
    _snapshot: Arc<Vec<(String, GlobalVal)>>,
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
#[allow(clippy::too_many_arguments)]
/// v0.6.47 (T1): el dueño de la corrida de una entrada de serve. Si el hilo se desenrolla antes de
/// cerrarla, la cierra con corte (`specs/t1-diario-modelo.md`).
struct RunOwner<'a> {
    swarm: &'a Arc<Swarm>,
    scope: Option<Arc<synsema_core::interpreter::RunCut>>,
}

impl Drop for RunOwner<'_> {
    fn drop(&mut self) {
        if let Some(s) = self.scope.take() {
            self.swarm.close_run(&s, true);
            synsema_agents::blackboard::set_thread_scope(None);
        }
    }
}

fn with_serve_interp<R>(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    f: impl FnOnce(&mut Interpreter, &Rc<RefCell<CapabilitySet>>) -> R,
) -> R {
    let key = Arc::as_ptr(snapshot) as *const () as usize;
    // Sacá el base del cache (o construilo la primera vez). Sacarlo (en vez de tomar
    // prestado) evita sostener el borrow del thread-local mientras corre `f`.
    let mut base = SERVE_INTERPS.with(|c| c.borrow_mut().remove(&key)).unwrap_or_else(|| {
        // Constructor `Send` de intérpretes de ESTE serve (para agentes spawneados desde
        // handlers/cron): captura los Arcs compartidos y se pasa a sí mismo (los agentes
        // de agentes heredan el mismo wiring).
        let builder: crate::engine::InterpBuilder = {
            let cell: Arc<std::sync::OnceLock<crate::engine::InterpBuilder>> = Arc::new(std::sync::OnceLock::new());
            let cell2 = cell.clone();
            let (sw, sn, cs, db, rs, sm, ow, sp, owp, st, ap, cr, mn) = (
                swarm.clone(),
                snapshot.clone(),
                caps_snap.clone(),
                shared_db.clone(),
                rules_snap.clone(),
                shared_memory.clone(),
                on_write.clone(),
                shared_progress.clone(),
                on_write_progress.clone(),
                shared_state.clone(),
                approvals.clone(),
                cron.clone(),
                mem_name.clone(),
            );
            let b: crate::engine::InterpBuilder = Arc::new(move || {
                let (interp, caps, _) = build_base_interp(
                    sw.clone(),
                    &sn,
                    &cs,
                    db.clone(),
                    &rs,
                    &sm,
                    &ow,
                    &sp,
                    &owp,
                    &st,
                    &ap,
                    &cr,
                    secure,
                    &mn,
                    cell2.get().cloned(),
                );
                (interp, caps)
            });
            let _ = cell.set(b.clone());
            b
        };
        let (interp, caps, originals) = build_base_interp(
            swarm.clone(),
            snapshot,
            caps_snap,
            shared_db.clone(),
            rules_snap,
            shared_memory,
            on_write,
            shared_progress,
            on_write_progress,
            shared_state,
            approvals,
            cron,
            secure,
            mem_name,
            Some(builder),
        );
        BaseInterp { interp, caps, originals, _snapshot: snapshot.clone() }
    });

    // v0.6.46 (E6-h): con `serve --auditor`, si este hilo atiende una request, su registro sellado
    // queda instalado desde acá (auth, handler y handler de error van al mismo recibo).
    if synsema_stdlib::sealed::serve_receipts_on() {
        synsema_stdlib::sealed::request_touch();
    }
    // T5 (ronda 7): el diario del almacén compartido cubre exactamente este request.
    arm_state_journal();
    // v0.6.47 (T1): cada entrada (request, tick del cron, handler de socket) es su propia corrida,
    // con su propio corte y sus propios agentes: el intérprete del worker no arrastra los de la
    // anterior.
    base.interp.set_run_cut(Arc::new(synsema_core::interpreter::RunCut::default()));
    let held = if crate::host::labels() { Some(hold_serve_log(&mut base.interp)) } else { None };
    // v0.6.47 (T1): lo que esta entrada escribe en el blackboard va al diario de su corrida, como
    // `state_*` (abajo): se deshace si la cortan.
    let scope = swarm.journals_runs().then(|| base.interp.run_cut());
    synsema_agents::blackboard::set_thread_scope(scope.clone());
    // Si `f` entra en pánico (un bug del motor), la corrida se cierra igual, con corte: si no, quedaba
    // abierta para siempre, con lo que escribió a la vista y sin confirmar ni deshacer.
    let mut owner = RunOwner { swarm, scope };
    let out = f(&mut base.interp, &base.caps);
    let stopped = base.interp.take_label_stop();
    finish_state_journal(shared_state, stopped);
    if let Some(s) = owner.scope.take() {
        // El request y sus agentes son una sola corrida (el `RunCut` de arriba, que heredan).
        swarm.close_run(&s, stopped || s.get().is_some());
        synsema_agents::blackboard::set_thread_scope(None);
    }
    if let Some(h) = held {
        release_serve_log(&mut base.interp, h, stopped);
    }

    // Limpieza por-request: estado transitorio del intérprete + capabilities al
    // snapshot del preámbulo (aislamiento entre requests reusando el mismo intérprete).
    // El hub de I/O también: sockets cerrados, procesos matados, suscripciones al bus
    // retiradas — nada de lo que abrió este request sobrevive al siguiente.
    synsema_stdlib::ws::reset_hub(&base.interp);
    base.interp.reset_for_request();
    // Las globales (y las variables de los módulos) vuelven a sus originales: lo que la request
    // escribió en ellas no llega a la siguiente.
    base.originals.restore(&base.interp);
    // El reset borra `agent_definitions`; los agentes top-level vuelven del snapshot —
    // si no, el próximo request de este worker vería "No agent defined" (bug pocos-cores).
    restore_agents(&mut base.interp, snapshot);
    {
        // CONSERVANDO el techo del host: `CapabilitySet::new` lo perdería y, del segundo
        // request de este worker en adelante, un `require exec(...)` en un handler
        // pasaría (bypass de `--sandbox`/`--cap-set`, v0.6.13).
        let mut c = base.caps.borrow_mut();
        c.reset_keeping_ceiling("request");
        for cap in caps_snap.iter() {
            c.grant(cap.clone());
        }
    }
    // Devolvelo al cache para el próximo request de este worker. (Si `f` paniquea, el
    // base se dropea acá sin re-insertarse → se evita reusar un intérprete corrupto; su
    // `Drop` corta el ciclo Rc del global_env. El pool atrapa el panic.)
    // v0.6.42 (auditoría B7) — un hilo EXTRA del pool es efímero: su intérprete se va con él (no
    // se cachea; si no, 256 hilos extra serían ~5 GB de intérpretes guardados).
    if !synsema_stdlib::server::on_extra_pool_thread() {
        SERVE_INTERPS.with(|c| c.borrow_mut().insert(key, base));
    }
    out
}

/// Corre el cuerpo de una ruta `socket` (WebSocket entrante): adopta el enlace en el
/// hub de I/O del intérprete (el binding `socket` es el handle, misma familia `ws_*`),
/// corre el bloque, y cierra limpio (1000) o con 1011 + motivo si el cuerpo falló.
#[allow(clippy::too_many_arguments)]
fn run_socket(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    body: &[Node],
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    link: Box<dyn std::any::Any + Send>,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp, caps| {
        interp.set_cancel_token(ctx.cancel.clone());
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        let link = match link.downcast::<ServerSocketLink>() {
            Ok(l) => *l,
            Err(_) => return StreamEnd::Error("socket: internal transport link type mismatch".to_string()),
        };
        let handle = match adopt_server_socket(interp, link) {
            Ok(h) => h,
            Err(Control::Error(e)) => return StreamEnd::Error(e.to_string_for_client()),
            Err(_) => return StreamEnd::Error("socket: could not adopt the connection".to_string()),
        };
        let mut bindings = request_bindings(ctx);
        bindings.push(("socket".to_string(), syn_int(handle)));
        // El cuerpo de la ruta trae el nodo `SocketBlock`: se corre SU cuerpo (aplanado),
        // igual que `stream` corre el suyo — el resto de statements de la ruta (antes
        // del bloque) se ejecutan en orden.
        let flat: Vec<Node> = body
            .iter()
            .flat_map(|s| match &s.kind {
                NodeKind::SocketBlock { body } => body.clone(),
                _ => vec![s.clone()],
            })
            .collect();
        let end = match interp.run_request_block(&flat, bindings) {
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => StreamEnd::Done,
            Err(Control::Error(e)) => StreamEnd::Error(e.to_string_for_client()),
        };
        // Cierre honesto: 1000 al terminar bien; 1011 + motivo si el cuerpo falló (el
        // cliente sabe que el server se rompió, nunca un corte mudo); 1001 + motivo si
        // fue el server quien cortó (timeout de la ruta / shutdown). Log del server.
        let cancelled = interp.is_cancelled();
        let reason = match &end {
            StreamEnd::Error(m) => {
                let what = if cancelled { "cancelled" } else { "handler failed" };
                (serve_log_sink())(&format!("[socket] {} {}: {}: {}", ctx.method, ctx.path, what, m));
                Some(m.as_str())
            }
            _ => None,
        };
        close_server_socket(interp, handle, reason, cancelled);
        end
    })
}

// =========================================================
// construcción del contexto de request (SynValue)
// =========================================================

// `str_map`/`headers_map`/`build_request_syn`/`build_form_syn`/`request_bindings`:
// MOVIDOS a synsema_stdlib::routing (puros; el handler-mode wasm arma el mismo
// `request`). Importados arriba.

/// v0.6.42 — el destino de un `proxy to` como única sentencia de la ruta, si no depende de la
/// request: no nombra `request`/`params`/`query`/`read_body*` ni un parámetro del path, y no
/// llama a una task del programa (un builtin como `env(...)` sí vale, como hasta ahora).
fn static_proxy_target<'a>(stmt: &'a Node, param_names: &[String], env: &Rc<RefCell<Environment>>) -> Option<&'a Node> {
    use synsema_stdlib::routing::REQUEST_NAMES;
    let NodeKind::ProxyStatement { target } = &stmt.kind else { return None };
    let mut dynamic = false;
    synsema_core::ast_api::walk(target, &mut |n| match &n.kind {
        NodeKind::Identifier { name } => {
            if REQUEST_NAMES.contains(&name.as_str()) || param_names.iter().any(|p| p == name) {
                dynamic = true;
            }
        }
        NodeKind::TaskCall { name, .. } => match &name.kind {
            NodeKind::Identifier { name } => {
                if matches!(synsema_core::interpreter::env_get(env, name), Some(SynValue::Task(_))) {
                    dynamic = true;
                }
            }
            _ => dynamic = true,
        },
        _ => {}
    });
    (!dynamic).then_some(target.as_ref())
}

/// ¿El cuerpo de la ruta ejecuta `proxy to` en algún punto (no como única sentencia estática)?
fn body_has_proxy(body: &[Node]) -> bool {
    let mut found = false;
    for st in body {
        synsema_core::ast_api::walk(st, &mut |n| {
            if matches!(n.kind, NodeKind::ProxyStatement { .. }) {
                found = true;
            }
        });
    }
    found
}

/// v0.6.42 (auditoría) — ¿el cuerpo de la ruta lee el body de la request? `read_body`,
/// `read_body_bytes`, o `body`/`form`/`json` del request (`body of request`, `request.form`,
/// `request["json"]`), o `expect` (valida `request.json`). Lo que se le escapa (una task que lee
/// `r.body`, `get(request, "body")`, `request[k]`) falla en runtime: el `request` de una ruta en
/// streaming no tiene esas claves (ver `Ctx::body_streamed`).
fn body_reads_request_body(body: &[Node]) -> bool {
    const FIELDS: [&str; 4] = ["body", "form", "json", "body_file"];
    let mut reads = false;
    for st in body {
        synsema_core::ast_api::walk(st, &mut |n| match &n.kind {
            NodeKind::Identifier { name } if name == "read_body" || name == "read_body_bytes" => reads = true,
            NodeKind::ExpectStatement { .. } => reads = true,
            NodeKind::PropertyAccess { property_name, .. } if FIELDS.contains(&property_name.as_str()) => reads = true,
            NodeKind::IndexAccess { index, .. } => {
                if let NodeKind::TextLiteral { value } = &index.kind {
                    if FIELDS.contains(&value.as_str()) {
                        reads = true;
                    }
                }
            }
            _ => {}
        });
    }
    reads
}

/// v0.6.42 — la ruta ejecutó `proxy to <destino>`: una URL pasa por el mismo gate `net` que al
/// arrancar, pero ahora por request y con las capabilities del worker; un extremo de `pipe` se
/// saca del hub del worker (el lado async habla HTTP sobre él).
fn proxy_outcome(
    interp: &mut Interpreter,
    caps: &Rc<RefCell<CapabilitySet>>,
    dest: synsema_core::interpreter::ProxyTo,
) -> GiveOutcome {
    use synsema_core::interpreter::ProxyTo;
    match dest {
        ProxyTo::Url(url) => {
            // El permiso se pide sobre el MISMO host[:puerto] al que se va a conectar (auditoría
            // B2: dos parsers distintos dejaban chequear un host y conectar a otro).
            let scope = match synsema_stdlib::server::parse_proxy_target(&url) {
                Ok((_, authority, _)) => authority.to_ascii_lowercase(),
                Err(m) => return GiveOutcome::Error(format!("proxy to: {}", m)),
            };
            if let Err(v) = caps
                .borrow_mut()
                .require(&Capability::new(CapabilityType::Net, Some(scope)), &format!("proxy to \"{}\"", url))
            {
                let e = v.into_error();
                return if e.denied_by_token {
                    GiveOutcome::Forbidden(e.to_string_for_client())
                } else {
                    GiveOutcome::Error(e.to_string_for_client())
                };
            }
            // v0.6.46 (E7): con las capas de `net` del worker, para chequear la IP al conectar.
            let net = Some(std::sync::Arc::new(caps.borrow().net_layers()));
            GiveOutcome::Proxy(synsema_stdlib::routing::ProxyDest::Url(url, net))
        }
        ProxyTo::Handle(h) => match synsema_stdlib::ws::take_pipe_for_proxy(interp, h) {
            Some(end) => GiveOutcome::Proxy(synsema_stdlib::routing::ProxyDest::Conn(Box::new(end))),
            None => GiveOutcome::Error(format!(
                "proxy to: {} is not a pipe end this request can use (closed, or already taken by another interpreter)",
                h
            )),
        },
    }
}

/// v0.6.42 — corre una task del programa FUERA de una request (las de `domain ask` y `tls dns`),
/// en un intérprete de serve con las capabilities del programa, como `auth with`. Devuelve si
/// el resultado es exactamente `true` (para `ask`), o el error de la task.
#[allow(clippy::too_many_arguments)]
fn serve_task_runner(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    node: Node,
) -> Arc<dyn Fn(&[&str]) -> Result<bool, String> + Send + Sync> {
    let (swarm, snapshot, caps_snap, shared_db, rules_snap) =
        (swarm.clone(), snapshot.clone(), caps_snap.clone(), shared_db.clone(), rules_snap.clone());
    let (shared_memory, on_write, shared_progress, on_write_progress) =
        (shared_memory.clone(), on_write.clone(), shared_progress.clone(), on_write_progress.clone());
    let (shared_state, approvals, cron, mem_name) = (shared_state.clone(), approvals.clone(), cron.clone(), mem_name.clone());
    Arc::new(move |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        with_serve_interp(&swarm, &snapshot, &caps_snap, &shared_db, &rules_snap, &shared_memory, &on_write, &shared_progress, &on_write_progress, &shared_state, &approvals, &cron, secure, &mem_name, |interp, _caps| {
            let genv = interp.global_env.clone();
            let task = interp.eval(&node, &genv).map_err(|e| match e {
                Control::Error(e) => e.message.clone(),
                _ => "the task did not evaluate".to_string(),
            })?;
            match interp.call_task(task, args.iter().map(|a| syn_text(a.as_str())).collect()) {
                Ok(SynValue::Bool(b)) => Ok(b),
                Ok(_) => Ok(false),
                Err(Control::Error(e)) => Err(e.message.clone()),
                Err(_) => Ok(false),
            }
        })
    })
}

/// Corre el cuerpo de una ruta normal; captura el `give`-value.
#[allow(clippy::too_many_arguments)]
fn run_route(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    body: &[Node],
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
) -> GiveOutcome {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, |interp, caps| {
        // T6.4 — identidad del sujeto de ESTA request (y su techo de gasto
        // delegado, si el token lo trae): lo consume el ledger de `spend` para
        // contabilizar y limitar por identidad. `reset_for_request` lo limpia al
        // devolver el intérprete al pool, así no se filtra al request siguiente.
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        // Token de cancelación de la request (timeout de handler / shutdown).
        interp.set_cancel_token(ctx.cancel.clone());
        match interp.run_request_block(body, request_bindings(ctx)) {
            Ok(_) => GiveOutcome::Give(None),
            Err(Control::Give(v)) => {
                mark_if_response_refused(interp, &v);
                GiveOutcome::Give(Some(v))
            }
            Err(Control::Error(e)) if e.proxy.is_some() => proxy_outcome(interp, caps, e.proxy.clone().unwrap()),
            // Falla de validación (`expect`) → 400 + `field`; cualquier otro error → 500.
            // v0.6.47 (T1): un corte de etiquetas es siempre el 500 fijo, aunque haya nacido en un
            // `expect` o en una denegación del token bajo una rama privada (si no, el status y el
            // `field` dirían qué sitio cortó).
            Err(Control::Error(e)) if e.is_validation && !e.is_fatal_for_labels() => {
                GiveOutcome::Validation { message: e.message.clone(), field: e.field.clone() }
            }
            // T1: denegada por el token del CALLER → 403 genérico, no 500 (la culpa no es del
            // server). Se decide por el flag, jamás por el texto.
            Err(Control::Error(e)) if e.denied_by_token && !e.is_fatal_for_labels() => GiveOutcome::Forbidden(e.to_string_for_client()),
            Err(Control::Error(e)) => GiveOutcome::Error(e.to_string_for_client()),
            Err(Control::Stop(_)) => {
                GiveOutcome::Error("'give'/'stop' used outside of a task or loop".to_string())
            }
        }
    })
}

/// Marcador (en el mensaje del error) de desconexión del cliente SSE.
const CLIENT_GONE: &str = "__client_gone__";

/// `SYNSEMA_IDENTITY_KEY` (environ o `.env`): la semilla ed25519 (64 hex) de la identidad del
/// server. Inválida → aviso por stderr y sin identidad (nunca una clave adivinada).
fn identity_key_from_env() -> Option<[u8; 32]> {
    let store = synsema_stdlib::secrets::EnvStore::load_default();
    let raw = crate::llm_providers::resolve_knob("SYNSEMA_IDENTITY_KEY", &store)?;
    let raw = raw.trim().trim_start_matches("0x");
    match synsema_core::bytesutil::hex_decode(raw) {
        Ok(b) if b.len() == 32 => Some(b.try_into().expect("32")),
        _ => {
            eprintln!("synsema: warning: SYNSEMA_IDENTITY_KEY must be the ed25519 seed as 64 hex chars — ignored; the agent card is served unsigned");
            None
        }
    }
}

/// Corre el cuerpo de una ruta de streaming SSE: `send` emite vía el `Emitter`. Un
/// `give` (o el fin del cuerpo) termina el stream limpio; un fallo de escritura
/// (cliente desconectado) lo desenrolla.
#[allow(clippy::too_many_arguments)]
fn run_stream(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    body: &[Node],
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    emit: Emitter,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp, caps| {
        // Identidad del sujeto de ESTA request: la misma que fija `run_route`. Sin esto una
        // ruta `stream` directa quedaba fuera de los techos por identidad (LLM, spend, sign):
        // venía así desde v0.6.19 y la auditoría de v0.6.20 lo destapó con el techo LLM nuevo.
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        interp.set_cancel_token(ctx.cancel.clone());
        let cell = Rc::new(RefCell::new(emit));
        let ec = cell.clone();
        interp.set_stream_emit(Rc::new(move |val: SynValue, event: Option<&str>| {
            // Un stream es un sumidero PÚBLICO como la respuesta: un valor
            // `private` no sale sin `declassify` (el error nombra el camino, nunca el valor).
            if let Err(e) = synsema_core::labels::check_flow(&val, &[], "stream") {
                return Err(Control::Error(RuntimeError::stream_label_cut(e.to_string())));
            }
            match (*ec.borrow_mut())(&val, event) {
                Ok(()) => Ok(()),
                Err(StreamGone) => Err(Control::Error(RuntimeError::new(CLIENT_GONE))),
            }
        }));
        match interp.run_request_block(body, request_bindings(ctx)) {
            // Un `give with_header(...)` en una ruta de streaming NO puede aplicar
            // headers (el head SSE ya se escribió al socket) — error claro, jamás
            // ignorar en silencio (G2).
            Err(Control::Give(SynValue::Server(s)))
                if matches!(&*s, ServerValue::WithHeaders { .. }) =>
            {
                StreamEnd::Error(
                    "streaming responses do not accept with_header/set_cookie yet \
                     (the SSE response head is already written); set headers on a \
                     non-streaming route"
                        .to_string(),
                )
            }
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => StreamEnd::Done,
            Err(Control::Error(e)) => {
                // `CLIENT_GONE` es un centinela sin ubicación, así que se reconoce igual por el
                // `Display`; lo que sale al cliente es la forma sin ruta absoluta.
                if e.to_string() == CLIENT_GONE {
                    StreamEnd::ClientGone
                } else {
                    StreamEnd::Error(e.to_string_for_client())
                }
            }
        }
    })
}

// =========================================================
// resolución de opciones del bloque serve
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

/// Validación al arranque de templates literales: cada `render("literal.html", ...)`
/// en un cuerpo de ruta se resuelve y parsea (recursivo: incluye sus `include`/`layout`
/// literales) ANTES de aceptar tráfico. Un typo o un template roto falla acá — no como
/// un 500 en el primer request. Los `render(<expr>)` dinámicos no se pueden validar
/// estáticamente y quedan para runtime, como siempre.
/// `timeout <expr>` | `timeout none` → `Some(segundos)`; `none` → `Some(0.0)` (sin
/// límite explícito, distinto de "no declarado" = `None` → hereda el del serve).
fn resolve_timeout(interp: &mut Interpreter, env: &Rc<RefCell<Environment>>, clause: Option<&Node>) -> Result<Option<f64>, Control> {
    let Some(node) = clause else { return Ok(None) };
    let NodeKind::TimeoutClause { secs } = &node.kind else { return Ok(None) };
    match secs {
        None => Ok(Some(0.0)),
        Some(e) => {
            let v = interp.eval(e, env)?;
            match val_to_f64(&v) {
                Some(f) if f.is_finite() && f > 0.0 => Ok(Some(f)),
                _ => Err(Control::Error(RuntimeError::new(format!(
                    "timeout must be a positive number of seconds (or `none`), got {}",
                    v
                )))),
            }
        }
    }
}

fn validate_route_templates(interp: &Interpreter, routes_n: &[Node]) -> Result<(), Control> {
    use synsema_core::ast::NodeKind as NK;
    for r in routes_n {
        let mut err: Option<String> = None;
        synsema_core::ast_api::walk(r, &mut |n: &Node| {
            if err.is_some() {
                return;
            }
            if let NK::TaskCall { name, arguments } = &n.kind {
                if matches!(&name.kind, NK::Identifier { name } if name == "render") {
                    if let Some(first) = arguments.first() {
                        if first.name.is_none() {
                            if let NK::TextLiteral { value } = &first.value.kind {
                                match synsema_core::templates::validate_template_gated(value, interp) {
                                    Err(e) => {
                                        err = Some(format!(
                                            "template validation failed for render(\"{}\"): {}",
                                            value, e
                                        ))
                                    }
                                    // v0.6.46 (ronda 1 de cf1, M3): lo que esta corrida todavía no
                                    // puede leer (un `require` dentro de la ruta) se chequea al
                                    // renderizar; se avisa una vez, sin leerlo.
                                    Ok(skipped) => {
                                        for (tpl, why) in skipped {
                                            eprintln!(
                                                "note: render(\"{}\"): \"{}\" is not checked at startup ({}); render() checks it when the route runs",
                                                value, tpl, why
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        if let Some(e) = err {
            return Err(Control::Error(RuntimeError::new(e)));
        }
    }
    Ok(())
}

/// Construye la tabla (rutas + estáticos + auth) de un host (default o vhost) desde
/// sus nodos AST. Reusado por el host default y por cada bloque `host "..."`.
#[allow(clippy::too_many_arguments)]
/// v0.6.45 (ronda 2, M6): el `tls cert "<c>" key "<k>"` de un bloque `serve` es código del
/// programa: lee esos PEM bajo `file.read`, como `mtls_identity`, y se abre la ruta normalizada que
/// se chequeó. Los `--tls-cert`/`--tls-key` de la línea de comandos son del operador y no pasan por
/// acá.
fn gate_tls_pem(caps: &Rc<RefCell<CapabilitySet>>, raw: &str) -> Result<String, Control> {
    let path = synsema_capabilities::model::normalize_path(raw);
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::FileRead, Some(path.clone())), "serve tls")
        .map_err(|v| Control::Error(v.into_error()))?;
    Ok(path)
}

/// v0.6.46: el `deny` que alcanza la carpeta entera de un `static` (la carpeta, o `<dir>/**`).
/// `<dir>/**` se mira sólo por nombre: como ruta tiene un glob, en disco no se resuelve.
fn static_root_denied<'a>(dir: &str, denied: &'a [Capability]) -> Option<&'a Capability> {
    let dir = dir.trim_end_matches(['/', '\\']);
    let root = Capability::new(CapabilityType::FileRead, Some(dir.to_string()));
    let tree = Capability::new(CapabilityType::FileRead, Some(format!("{}/**", dir)));
    denied.iter().find(|d| d.covers_by_name(&root) || d.reaches_physically(&root) || d.covers_by_name(&tree))
}

fn build_host_table(
    interp: &mut Interpreter,
    env: &Rc<RefCell<synsema_core::interpreter::Environment>>,
    routes_n: &[Node],
    mounts_n: &[Node],
    static_mounts_n: &[Node],
    auth_handler_n: Option<&Node>,
    block_limit: Option<(i64, f64)>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    denied_snap: &[Capability],
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    swarm: &Arc<Swarm>,
    shared_db: &SharedDb,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
) -> Result<HostTable, Control> {
    // Templates literales de las rutas: validados al construir el serve (fail-fast).
    validate_route_templates(interp, routes_n)?;

    // -- static mounts (dedup por prefijo; cache/fallback validados fail-fast) --
    let mut static_mounts: Vec<StaticMountSpec> = Vec::new();
    let mut seen_prefixes: Vec<String> = Vec::new();
    for mount in static_mounts_n {
        if let NodeKind::StaticMount { directory, prefix, cache, fallback } = &mount.kind {
            // v0.6.45 (ronda 2, M5): la carpeta NORMALIZADA, la misma que chequea el gate de abajo
            // (con la cruda, en Unix `./public/link/..` pasaba como `./public` y servía otro lado).
            let dir = synsema_capabilities::model::normalize_path(&interp.eval(directory, env)?.to_string());
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
            // v0.6.45 — servir una carpeta es leerla, y el archivo lo elige un cliente remoto: hace
            // falta `file.read("<dir>/**")` declarado (antes no se pedía nada, y `static "/" from "/"`
            // servía el disco sin que el preámbulo lo dijera). Una carpeta que viaja dentro del
            // binario de `synsema build` es parte del programa y no lo pide, como `read_file`.
            let bundled = synsema_core::bundle::mounted()
                .and_then(|b| synsema_core::bundle::normalize_name(&dir).map(|k| b.has_prefix(&k)))
                .unwrap_or(false);
            if !bundled {
                let scope = format!("{}/**", dir.trim_end_matches(['/', '\\']));
                let need = Capability::new(CapabilityType::FileRead, Some(scope.clone()));
                if !caps_snap.iter().any(|c| c.covers(&need)) {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "Capability not granted: static \"{}\" from \"{}\" serves the files of that folder — this is a permission, not a bug: add `require file.read(\"{}\")` to the program's preamble",
                        prefix_str, dir, scope
                    ))));
                }
                // v0.6.46: un `deny` que alcanza la carpeta entera deja el mount sin nada que servir:
                // se dice al arrancar. Uno de adentro se mira por request (`server::static_denied`).
                if let Some(d) = static_root_denied(&dir, denied_snap) {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "static \"{}\" from \"{}\": this run denies reading that folder (deny {}, set by the host); serve another folder",
                        prefix_str, dir, d
                    ))));
                }
            }
            // `cache "<spec>"` → valor Cache-Control, validado ACÁ (arranque), nunca
            // en un request.
            let cache_val = match cache {
                Some(c) => {
                    let spec = interp.eval(c, env)?.to_string();
                    match server::cache_control_value(&spec) {
                        Ok(v) => Some(v),
                        Err(e) => return Err(Control::Error(RuntimeError::new(e))),
                    }
                }
                None => None,
            };
            // `fallback "<file>"` → debe existir dentro del mount al arrancar.
            let fallback_val = match fallback {
                Some(f) => {
                    let fb = interp.eval(f, env)?.to_string();
                    let candidate = std::path::Path::new(&dir).join(&fb);
                    if !candidate.is_file() {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "static fallback '{}' not found in '{}' — the fallback file must exist when the server starts",
                            fb, dir
                        ))));
                    }
                    Some(fb)
                }
                None => None,
            };
            static_mounts.push(StaticMountSpec {
                prefix: prefix_str,
                dir,
                cache: cache_val,
                fallback: fallback_val,
                deny: if bundled { Vec::new() } else { denied_snap.to_vec() },
            });
        }
    }

    // -- auth handler: corre la task de `auth with <task>` con el bearer token —
    // y, si el task declara 2 parámetros, también con el map `request` completo
    // (sesiones por cookie, ítem C). La aridad se valida ACÁ, al construir el
    // serve (fail-fast), no en runtime. 1 parámetro = comportamiento idéntico al
    // histórico, byte a byte.
    let auth_handler: Option<AuthHandler> = match auth_handler_n {
        None => None,
        Some(an) => {
            // Aridad declarada del task. Si el nodo no evalúa acá (task aún no
            // definido), se mantiene el comportamiento histórico: resolución lazy
            // por request con 1 parámetro (y 401 si sigue sin resolver).
            let arity: usize = match interp.eval(an, env) {
                Ok(SynValue::Task(t)) => t.parameters.len(),
                _ => 1,
            };
            if arity != 1 && arity != 2 {
                return Err(Control::Error(RuntimeError::new(format!(
                    "auth task must take 1 (token) or 2 (token, request) parameters, got {}",
                    arity
                ))));
            }
            let auth_node = an.clone();
            let swarm_a = swarm.clone();
            let snap_a = snapshot.clone();
            let caps_a = caps_snap.clone();
            let rules_a = rules_snap.clone();
            let mem_a = shared_memory.clone();
            let ow_a = on_write.clone();
            let prog_a = shared_progress.clone();
            let owp_a = on_write_progress.clone();
            let st_a = shared_state.clone();
            let ap_a = approvals.clone();
            let cron_a = cron.clone();
            let db_a = shared_db.clone();
            let mn_a = mem_name.clone();
            let h: AuthHandler = Arc::new(move |token: &str, ctx: &Ctx| -> Option<SynValue> {
                with_serve_interp(&swarm_a, &snap_a, &caps_a, &db_a, &rules_a, &mem_a, &ow_a, &prog_a, &owp_a, &st_a, &ap_a, &cron_a, secure, &mn_a, |interp, _caps| {
                    let genv = interp.global_env.clone();
                    let task = match interp.eval(&auth_node, &genv) {
                        Ok(t) => t,
                        Err(_) => return None,
                    };
                    let args = if arity == 2 {
                        // El MISMO map `request` que ve el handler de ruta
                        // (incluye `cookies`; `user` aún nothing).
                        vec![syn_text(token), build_request_syn(ctx)]
                    } else {
                        vec![syn_text(token)]
                    };
                    // Auditoría ronda 5: un fallo DENTRO de la task de auth se convertía en
                    // "sin usuario" sin dejar rastro: el operador veía a todos sus usuarios
                    // afuera y ni una línea de por qué. El caso real es `jwt_verify` bajo
                    // `--secure` sin `require time` (la capability no está concedida), que en
                    // una ruta normal SÍ se loguea. Degradar con aviso: el veredicto no cambia
                    // (no hay usuario), pero el motivo queda escrito.
                    match interp.call_task(task, args) {
                        Ok(v) => Some(v),
                        Err(Control::Error(e)) => {
                            entry_eprintln(interp, &format!("[serve] auth task failed, so the request has no user: {}", e.message));
                            None
                        }
                        Err(_) => None,
                    }
                })
            });
            Some(h)
        }
    };

    // -- rutas --
    let mut routes: Vec<RouteSpec> = Vec::new();
    for r in routes_n {
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
            let rc = resolve_rate(interp, env, rate_limit.as_deref())?;
            let route_timeout = resolve_timeout(interp, env, timeout.as_deref())?;
            let rate_unlimited = matches!(rc, Some(RateKind::Unlimited));
            // Metadatos estáticos para /openapi.json y /docs (expect, respuesta,
            // capabilities transitivas): del AST + el entorno ya evaluado.
            let meta = synsema_core::route_meta::route_meta(body, *streaming, &synsema_core::route_meta::env_lookup(env));
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
            // v0.6.42 — un `proxy to` cuyo destino no depende de la request (un literal, una
            // constante, `env(...)`) se evalúa y se chequea UNA vez al arrancar, como siempre; si
            // depende de la request o hay sentencias antes, corre como handler (`proxy_dynamic`).
            let mut proxy_net = None;
            let proxy_target: Option<String> = if body.len() == 1 {
                if let Some(target) = static_proxy_target(&body[0], param_names, env) {
                    let url = interp.eval(target, env)?.to_string();
                    // Validar al arrancar (la URL se evalúa una vez): un target https://
                    // o sin host no puede ser un 502 por request.
                    let (_, authority, _) = match synsema_stdlib::server::parse_proxy_target(&url) {
                        Ok(t) => t,
                        Err(m) => {
                            return Err(Control::Error(RuntimeError::new(format!(
                                "proxy to: {} (route \"{} {}\")",
                                m, method, path
                            ))))
                        }
                    };
                    // El upstream es una conexión SALIENTE: mismo gate `net(host)` que
                    // http_get/fetch/ws_connect (deny-by-default). Se chequea acá, al
                    // arrancar, contra las capabilities del programa — nunca por request.
                    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(&authority).to_ascii_lowercase();
                    let mut check = CapabilitySet::new("proxy");
                    // El set descartable lleva el techo del host: sin él, un grant del
                    // snapshot que el techo rechazó entraría acá igual.
                    if let Some(cl) = serve_ceiling() {
                        check.ceiling = Some(Rc::new((*cl).clone()));
                    }
                    for cap in caps_snap.iter() {
                        check.grant(cap.clone());
                    }
                    let scope = synsema_capabilities::model::net_request_scope(&url).unwrap_or_else(|| host.clone());
                    if let Err(v) = check.require(
                        &Capability::new(CapabilityType::Net, Some(scope)),
                        &format!("proxy to \"{}\" (route \"{} {}\")", url, method, path),
                    ) {
                        return Err(Control::Error(v.into_error()));
                    }
                    // v0.6.46 (E7): las mismas capas, para chequear la IP en cada conexión.
                    proxy_net = Some(std::sync::Arc::new(check.net_layers()));
                    Some(url)
                } else {
                    None
                }
            } else {
                None
            };
            let proxy_dynamic = proxy_target.is_none() && body_has_proxy(body);
            let proxy_reads_body = proxy_dynamic && body_reads_request_body(body);

            let body_c = body.clone();
            let swarm_c = swarm.clone();
            let snap_c = snapshot.clone();
            let caps_c = caps_snap.clone();
            let rules_c = rules_snap.clone();
            let mem_c = shared_memory.clone();
            let ow_c = on_write.clone();
            let prog_c = shared_progress.clone();
            let owp_c = on_write_progress.clone();
            let st_c = shared_state.clone();
            let ap_c = approvals.clone();
            let cron_c = cron.clone();
            let db_c = shared_db.clone();
            let mn_c = mem_name.clone();
            let handler: Handler = Arc::new(move |ctx: &Ctx| {
                run_route(&swarm_c, &snap_c, &caps_c, &db_c, &rules_c, &mem_c, &ow_c, &prog_c, &owp_c, &st_c, &ap_c, &cron_c, &body_c, ctx, secure, &mn_c)
            });

            let socket_handler: Option<SocketHandler> = if *socket {
                let body_s = body.clone();
                let swarm_s = swarm.clone();
                let snap_s = snapshot.clone();
                let caps_s = caps_snap.clone();
                let rules_s = rules_snap.clone();
                let mem_s = shared_memory.clone();
                let ow_s = on_write.clone();
                let prog_s = shared_progress.clone();
                let owp_s = on_write_progress.clone();
                let st_s = shared_state.clone();
                let ap_s = approvals.clone();
                let cron_s = cron.clone();
                let db_s = shared_db.clone();
                let mn_s = mem_name.clone();
                Some(Arc::new(move |ctx: &Ctx, link: Box<dyn std::any::Any + Send>| {
                    run_socket(
                        &swarm_s, &snap_s, &caps_s, &db_s, &rules_s, &mem_s, &ow_s, &prog_s, &owp_s, &st_s, &ap_s, &cron_s, &body_s, ctx, secure, &mn_s, link,
                    )
                }))
            } else {
                None
            };

            let stream_handler: Option<StreamHandler> = if *streaming {
                let body_s = body.clone();
                let swarm_s = swarm.clone();
                let snap_s = snapshot.clone();
                let caps_s = caps_snap.clone();
                let rules_s = rules_snap.clone();
                let mem_s = shared_memory.clone();
                let ow_s = on_write.clone();
                let prog_s = shared_progress.clone();
                let owp_s = on_write_progress.clone();
                let st_s = shared_state.clone();
                let ap_s = approvals.clone();
                let cron_s = cron.clone();
                let db_s = shared_db.clone();
                let mn_s = mem_name.clone();
                Some(Arc::new(move |ctx: &Ctx, emit: Emitter| {
                    run_stream(
                        &swarm_s, &snap_s, &caps_s, &db_s, &rules_s, &mem_s, &ow_s, &prog_s, &owp_s, &st_s, &ap_s, &cron_s, &body_s, ctx, secure, &mn_s, emit,
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
                socket: *socket,
                private: *private,
                rate_limit: eff_rate,
                rate_zone: zone,
                handler,
                stream_handler,
                socket_handler,
                timeout: route_timeout,
                proxy_target,
                proxy_net,
                proxy_dynamic,
                proxy_reads_body,
                rate_unlimited,
                meta,
            });
        }
    }

    // -- rutas montadas: `mount <expr> [at "/prefix"]` sobre un grupo `export routes` --
    // El grupo se evalúa AHORA (fail-fast: forma inválida = error de arranque); el
    // handler re-evalúa la expresión por request (igual que el auth handler) para
    // obtener la task REBUILDEADA que cierra sobre el module_env del request.
    for mnode in mounts_n {
        if let NodeKind::MountClause { source, prefix } = &mnode.kind {
            let group = interp.eval(source, env)?;
            let metas: Vec<SynValue> = match &group {
                SynValue::Map(m) => match m.borrow().get("_routes_meta") {
                    Some(SynValue::List(l)) => l.borrow().to_vec(),
                    _ => {
                        return Err(Control::Error(RuntimeError::new(
                            "mount expects a routes group (a module's `export routes ...`) — the value has no routes"
                                .to_string(),
                        )))
                    }
                },
                other => {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "mount expects a routes group (a module's `export routes ...`), got {}",
                        other.type_name()
                    ))))
                }
            };
            // Los templates literales de las rutas MONTADAS también se validan al
            // arranque (los cuerpos viven en las handler-tasks del grupo).
            if let SynValue::Map(m) = &group {
                for (k, v) in m.borrow().iter() {
                    if k.starts_with("_route_handler_") {
                        if let SynValue::Task(t) = v {
                            validate_route_templates(interp, &t.body)?;
                        }
                    }
                }
            }
            let prefix_str = match prefix {
                Some(p) => {
                    let s = interp.eval(p, env)?.to_string();
                    if !s.starts_with('/') {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "mount prefix must start with '/', got '{}'",
                            s
                        ))));
                    }
                    s.trim_end_matches('/').to_string()
                }
                None => String::new(),
            };
            for (i, meta) in metas.iter().enumerate() {
                let mm = match meta {
                    SynValue::Map(m) => m.borrow().to_map(),
                    _ => continue,
                };
                let method = mm.get("method").map(|v| v.to_string()).unwrap_or_default();
                let rpath = mm.get("path").map(|v| v.to_string()).unwrap_or_default();
                let requires_auth = matches!(mm.get("requires_auth"), Some(SynValue::Bool(true)));
                // v0.6.20 — clase de ruta y publicación, tal como viajan en la meta del grupo.
                let streaming = matches!(mm.get("streaming"), Some(SynValue::Bool(true)));
                let socket = matches!(mm.get("socket"), Some(SynValue::Bool(true)));
                let private = matches!(mm.get("private"), Some(SynValue::Bool(true)));
                let params: Vec<String> = match mm.get("params") {
                    Some(SynValue::List(l)) => list_values(&l).iter().map(|x| x.to_string()).collect(),
                    _ => Vec::new(),
                };
                if requires_auth && auth_handler.is_none() {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "mounted route \"{} {}\" uses 'requires auth' but the 'serve' block declares no 'auth with <task>'",
                        method, rpath
                    ))));
                }
                let full_path = if prefix_str.is_empty() {
                    rpath.clone()
                } else if rpath == "/" {
                    prefix_str.clone()
                } else {
                    format!("{}{}", prefix_str, rpath)
                };
                // `rate_limit` / `timeout` declarados en la ruta del grupo viajan en la meta
                // (evaluados al ejecutar el grupo) y se aplican igual que en una ruta directa:
                // zona propia por ruta montada (el prefijo la hace distinta), o el default del bloque.
                let rc: Option<RateKind> = match mm.get("rate_limit") {
                    Some(SynValue::Map(r)) => {
                        let r = r.borrow();
                        if matches!(r.get("unlimited"), Some(SynValue::Bool(true))) {
                            Some(RateKind::Unlimited)
                        } else {
                            let cap = r.get("count").and_then(val_to_f64).unwrap_or(0.0) as i64;
                            let w = r.get("window").map(|v| v.to_string()).unwrap_or_default();
                            Some(RateKind::Limit(cap, window_seconds(&w)))
                        }
                    }
                    _ => None,
                };
                let rate_unlimited = matches!(rc, Some(RateKind::Unlimited));
                let route_timeout: Option<f64> = match mm.get("timeout") {
                    Some(SynValue::Text(t)) if t.to_string() == "none" => Some(0.0),
                    Some(v) => val_to_f64(v),
                    None => None,
                };
                let (eff_rate, zone) = match rc {
                    None => match block_limit {
                        Some(bl) => (Some(bl), Some("__default__".to_string())),
                        None => (None, None),
                    },
                    Some(RateKind::Unlimited) => (None, None),
                    Some(RateKind::Limit(c, s)) => (Some((c, s)), Some(format!("route:{} {}", method, full_path))),
                };
                let source_c = source.as_ref().clone();
                let key = format!("_route_handler_{}", i);
                // v0.6.42 — ¿el cuerpo (en la task del grupo) ejecuta `proxy to`? Entonces el
                // transporte prepara el reenvío (headers, body, upgrade) como en una ruta directa.
                let (mounted_proxy, mounted_reads_body) = match &group {
                    SynValue::Map(m) => match m.borrow().get(&key) {
                        Some(SynValue::Task(t)) => (body_has_proxy(&t.body), body_reads_request_body(&t.body)),
                        _ => (false, false),
                    },
                    _ => (false, false),
                };
                // El cuerpo de una ruta montada vive en su handler-task (cierra sobre el
                // env del módulo): de ahí salen expect/respuesta/capabilities.
                let meta = match &group {
                    SynValue::Map(m) => match m.borrow().get(&key) {
                        Some(SynValue::Task(t)) => synsema_core::route_meta::route_meta(
                            &t.body,
                            streaming,
                            &synsema_core::route_meta::env_lookup(&t.closure_env),
                        ),
                        _ => Default::default(),
                    },
                    _ => Default::default(),
                };
                let swarm_c = swarm.clone();
                let snap_c = snapshot.clone();
                let caps_c = caps_snap.clone();
                let rules_c = rules_snap.clone();
                let mem_c = shared_memory.clone();
                let ow_c = on_write.clone();
                let prog_c = shared_progress.clone();
                let owp_c = on_write_progress.clone();
                let st_c = shared_state.clone();
                let ap_c = approvals.clone();
                let cron_c = cron.clone();
                let db_c = shared_db.clone();
                let mn_c = mem_name.clone();
                // v0.6.20 — `stream`/`socket` montados: las mismas variantes que una ruta
                // directa, resolviendo el cuerpo en la task del grupo (`_route_handler_i`).
                let (source_s, key_s) = (source_c.clone(), key.clone());
                let handler: Handler = Arc::new(move |ctx: &Ctx| {
                    run_mounted_route(
                        &swarm_c, &snap_c, &caps_c, &db_c, &rules_c, &mem_c, &ow_c, &prog_c,
                        &owp_c, &st_c, &ap_c, &cron_c, &source_c, &key, ctx, secure, &mn_c,
                    )
                });
                let stream_handler: Option<StreamHandler> = if streaming {
                    let (source_s, key_s) = (source_s.clone(), key_s.clone());
                    let swarm_s = swarm.clone();
                    let snap_s = snapshot.clone();
                    let caps_s = caps_snap.clone();
                    let rules_s = rules_snap.clone();
                    let mem_s = shared_memory.clone();
                    let ow_s = on_write.clone();
                    let prog_s = shared_progress.clone();
                    let owp_s = on_write_progress.clone();
                    let st_s = shared_state.clone();
                    let ap_s = approvals.clone();
                    let cron_s = cron.clone();
                    let db_s = shared_db.clone();
                    let mn_s = mem_name.clone();
                    Some(Arc::new(move |ctx: &Ctx, emit: Emitter| {
                        run_mounted_stream(
                            &swarm_s, &snap_s, &caps_s, &db_s, &rules_s, &mem_s, &ow_s, &prog_s,
                            &owp_s, &st_s, &ap_s, &cron_s, &source_s, &key_s, ctx, secure, &mn_s, emit,
                        )
                    }))
                } else {
                    None
                };
                let socket_handler: Option<SocketHandler> = if socket {
                    let (source_s, key_s) = (source_s.clone(), key_s.clone());
                    let swarm_s = swarm.clone();
                    let snap_s = snapshot.clone();
                    let caps_s = caps_snap.clone();
                    let rules_s = rules_snap.clone();
                    let mem_s = shared_memory.clone();
                    let ow_s = on_write.clone();
                    let prog_s = shared_progress.clone();
                    let owp_s = on_write_progress.clone();
                    let st_s = shared_state.clone();
                    let ap_s = approvals.clone();
                    let cron_s = cron.clone();
                    let db_s = shared_db.clone();
                    let mn_s = mem_name.clone();
                    Some(Arc::new(move |ctx: &Ctx, link: Box<dyn std::any::Any + Send>| {
                        run_mounted_socket(
                            &swarm_s, &snap_s, &caps_s, &db_s, &rules_s, &mem_s, &ow_s, &prog_s,
                            &owp_s, &st_s, &ap_s, &cron_s, &source_s, &key_s, ctx, secure, &mn_s, link,
                        )
                    }))
                } else {
                    None
                };
                routes.push(RouteSpec {
                    method,
                    path: full_path,
                    param_names: params,
                    requires_auth,
                    streaming,
                    socket,
                    private,
                    rate_limit: eff_rate,
                    rate_zone: zone,
                    handler,
                    stream_handler,
                    socket_handler,
                    timeout: route_timeout,
                    proxy_target: None,
                    proxy_net: None,
                    proxy_dynamic: mounted_proxy,
                    proxy_reads_body: mounted_proxy && mounted_reads_body,
                    rate_unlimited,
                    meta,
                });
            }
        }
    }
    Ok((routes, static_mounts, auth_handler))
}

/// Corre el cuerpo de una ruta MONTADA desde un grupo `export routes`: re-evalúa la
/// expresión del mount en el intérprete del request (los globals rebuildeados ya
/// contienen el alias del módulo con su module_env compartido — DE-027/033), toma la
/// handler-task y ejecuta su cuerpo con los bindings de request colgando del
/// module_env → los helpers privados del módulo resuelven por nombre simple.
#[allow(clippy::too_many_arguments)]
fn run_mounted_route(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    source: &Node,
    handler_key: &str,
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
) -> GiveOutcome {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, |interp, caps| {
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        let genv = interp.global_env.clone();
        let group = match interp.eval(source, &genv) {
            Ok(v) => v,
            Err(Control::Error(e)) => {
                return GiveOutcome::Error(format!(
                    "mounted routes group is not available: {}",
                    e.message
                ))
            }
            Err(_) => return GiveOutcome::Error("mounted routes group is not available".to_string()),
        };
        let task = match &group {
            SynValue::Map(m) => m.borrow().get(handler_key).cloned(),
            _ => None,
        };
        let task = match task {
            Some(SynValue::Task(t)) => t,
            _ => {
                return GiveOutcome::Error(format!(
                    "mounted route handler '{}' not found in the routes group",
                    handler_key
                ))
            }
        };
        let parent = task.closure_env.clone();
        interp.set_cancel_token(ctx.cancel.clone());
        match interp.run_request_block_in(&task.body, request_bindings(ctx), &parent) {
            Ok(_) => GiveOutcome::Give(None),
            Err(Control::Give(v)) => {
                mark_if_response_refused(interp, &v);
                GiveOutcome::Give(Some(v))
            }
            Err(Control::Error(e)) if e.proxy.is_some() => proxy_outcome(interp, caps, e.proxy.clone().unwrap()),
            // v0.6.47 (T1): un corte de etiquetas es siempre el 500 fijo, aunque haya nacido en un
            // `expect` o en una denegación del token bajo una rama privada (si no, el status y el
            // `field` dirían qué sitio cortó).
            Err(Control::Error(e)) if e.is_validation && !e.is_fatal_for_labels() => {
                GiveOutcome::Validation { message: e.message.clone(), field: e.field.clone() }
            }
            // T1: denegada por el token del CALLER → 403 genérico, no 500 (la culpa no es del
            // server). Se decide por el flag, jamás por el texto.
            Err(Control::Error(e)) if e.denied_by_token && !e.is_fatal_for_labels() => GiveOutcome::Forbidden(e.to_string_for_client()),
            Err(Control::Error(e)) => GiveOutcome::Error(e.to_string_for_client()),
            Err(Control::Stop(_)) => {
                GiveOutcome::Error("'give'/'stop' used outside of a task or loop".to_string())
            }
        }
    })
}

/// v0.6.20 — resuelve la task `_route_handler_i` del grupo montado (con su env de módulo).
fn mounted_task(
    interp: &mut Interpreter,
    source: &Node,
    handler_key: &str,
) -> Result<Rc<synsema_core::types::SynTaskValue>, String> {
    let genv = interp.global_env.clone();
    let group = match interp.eval(source, &genv) {
        Ok(v) => v,
        Err(Control::Error(e)) => return Err(format!("mounted routes group is not available: {}", e.message)),
        Err(_) => return Err("mounted routes group is not available".to_string()),
    };
    let task = match &group {
        SynValue::Map(m) => m.borrow().get(handler_key).cloned(),
        _ => None,
    };
    match task {
        Some(SynValue::Task(t)) => Ok(t),
        _ => Err(format!("mounted route handler '{}' not found in the routes group", handler_key)),
    }
}

/// v0.6.20 — ruta `stream` montada desde un grupo `export routes`: igual que `run_stream`,
/// con el cuerpo y el env de la task del grupo.
#[allow(clippy::too_many_arguments)]
fn run_mounted_stream(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    source: &Node,
    handler_key: &str,
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    emit: Emitter,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp, caps| {
        interp.set_cancel_token(ctx.cancel.clone());
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        let task = match mounted_task(interp, source, handler_key) {
            Ok(t) => t,
            Err(m) => return StreamEnd::Error(m),
        };
        let cell = Rc::new(RefCell::new(emit));
        let ec = cell.clone();
        interp.set_stream_emit(Rc::new(move |val: SynValue, event: Option<&str>| {
            // Un stream es un sumidero PÚBLICO como la respuesta: un valor
            // `private` no sale sin `declassify` (el error nombra el camino, nunca el valor).
            if let Err(e) = synsema_core::labels::check_flow(&val, &[], "stream") {
                return Err(Control::Error(RuntimeError::stream_label_cut(e.to_string())));
            }
            match (*ec.borrow_mut())(&val, event) {
                Ok(()) => Ok(()),
                Err(StreamGone) => Err(Control::Error(RuntimeError::new(CLIENT_GONE))),
            }
        }));
        let parent = task.closure_env.clone();
        match interp.run_request_block_in(&task.body, request_bindings(ctx), &parent) {
            Err(Control::Give(SynValue::Server(s))) if matches!(&*s, ServerValue::WithHeaders { .. }) => {
                StreamEnd::Error(
                    "streaming responses do not accept with_header/set_cookie yet \
                     (the SSE response head is already written); set headers on a \
                     non-streaming route"
                        .to_string(),
                )
            }
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => StreamEnd::Done,
            Err(Control::Error(e)) => {
                // `CLIENT_GONE` es un centinela sin ubicación, así que se reconoce igual por el
                // `Display`; lo que sale al cliente es la forma sin ruta absoluta.
                if e.to_string() == CLIENT_GONE {
                    StreamEnd::ClientGone
                } else {
                    StreamEnd::Error(e.to_string_for_client())
                }
            }
        }
    })
}

/// v0.6.20 — ruta `socket` montada desde un grupo `export routes`: igual que `run_socket`,
/// con el cuerpo y el env de la task del grupo.
#[allow(clippy::too_many_arguments)]
fn run_mounted_socket(
    swarm: &Arc<Swarm>,
    snapshot: &Arc<Vec<(String, GlobalVal)>>,
    caps_snap: &Arc<Vec<Capability>>,
    shared_db: &SharedDb,
    rules_snap: &Arc<Vec<OwnerRule>>,
    shared_memory: &SharedMemoryStore,
    on_write: &OnWriteFn,
    shared_progress: &SharedProgressStore,
    on_write_progress: &OnWriteProgressFn,
    shared_state: &SharedState,
    approvals: &ServeApprovals,
    cron: &CronWiring,
    source: &Node,
    handler_key: &str,
    ctx: &Ctx,
    secure: bool,
    mem_name: &Option<crate::engine::MemName>,
    link: Box<dyn std::any::Any + Send>,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp, caps| {
        interp.set_cancel_token(ctx.cancel.clone());
        // T1 — el SUJETO de esta request (identidad, techo de gasto y techo delegado del
        // token, presupuesto LLM delegado) sobre el intérprete y su CapabilitySet. Lo limpia
        // `reset_for_request` / `reset_keeping_ceiling` al devolver el worker al pool.
        let _llm_identity = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
        let task = match mounted_task(interp, source, handler_key) {
            Ok(t) => t,
            Err(m) => return StreamEnd::Error(m),
        };
        let link = match link.downcast::<ServerSocketLink>() {
            Ok(l) => *l,
            Err(_) => return StreamEnd::Error("socket: internal transport link type mismatch".to_string()),
        };
        let handle = match adopt_server_socket(interp, link) {
            Ok(h) => h,
            Err(Control::Error(e)) => return StreamEnd::Error(e.to_string_for_client()),
            Err(_) => return StreamEnd::Error("socket: could not adopt the connection".to_string()),
        };
        let mut bindings = request_bindings(ctx);
        bindings.push(("socket".to_string(), syn_int(handle)));
        let flat: Vec<Node> = task
            .body
            .iter()
            .flat_map(|s| match &s.kind {
                NodeKind::SocketBlock { body } => body.clone(),
                _ => vec![s.clone()],
            })
            .collect();
        let parent = task.closure_env.clone();
        let end = match interp.run_request_block_in(&flat, bindings, &parent) {
            Ok(_) | Err(Control::Give(_)) | Err(Control::Stop(_)) => StreamEnd::Done,
            Err(Control::Error(e)) => StreamEnd::Error(e.to_string_for_client()),
        };
        let cancelled = interp.is_cancelled();
        let reason = match &end {
            StreamEnd::Error(m) => {
                let what = if cancelled { "cancelled" } else { "handler failed" };
                (serve_log_sink())(&format!("[socket] {} {}: {}: {}", ctx.method, ctx.path, what, m));
                Some(m.as_str())
            }
            _ => None,
        };
        close_server_socket(interp, handle, reason, cancelled);
        end
    })
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
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
    shared_progress: SharedProgressStore,
    on_write_progress: OnWriteProgressFn,
    shared_state: SharedState,
    cron: CronWiring,
    mem_name: Option<crate::engine::MemName>,
) -> ServeHook {
    Rc::new(move |interp, node, env| {
        let (
            port_n,
            auth_handler_n,
            error_handler_n,
            max_body_n,
            max_streams_n,
            block_rate_n,
            timeout_n,
            static_mounts_n,
            cors_n,
            describe_n,
            private,
            docs_off,
            discovery_off,
            routes_n,
            tls_cert_n,
            tls_key_n,
            redirect_https,
            acme_n,
            trust_proxy_n,
            bind_n,
            hosts_n,
            mounts_n,
        ) = match &node.kind {
            NodeKind::ServeBlock {
                port,
                auth_handler,
                error_handler,
                max_body,
                max_streams,
                rate_limit,
                timeout,
                static_mounts,
                cors,
                describe,
                private,
                docs_off,
                discovery_off,
                routes,
                tls_cert,
                tls_key,
                redirect_https,
                acme,
                trust_proxy,
                bind,
                hosts,
                mounts,
            } => (
                port.as_ref(),
                auth_handler.as_deref(),
                error_handler.as_deref(),
                max_body.as_deref(),
                max_streams.as_deref(),
                rate_limit.as_deref(),
                timeout.as_deref(),
                static_mounts,
                cors.as_deref(),
                describe.as_deref(),
                *private,
                *docs_off,
                *discovery_off,
                routes,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                *redirect_https,
                acme.as_deref(),
                trust_proxy.as_deref(),
                bind.as_deref(),
                hosts,
                mounts,
            ),
            _ => return Err(Control::Error(RuntimeError::new("internal: serve_hook on non-serve node"))),
        };
        // v0.6.42 — la config ACME vive en `ServeAcme` (fuera del nodo); `domain ask`, `tls dns`
        // y `trust proxy` los consume la tanda de stdlib/runtime.
        let tls_auto = acme_n.map_or(false, |a| a.tls_auto);
        let tls_auto_email_n = acme_n.and_then(|a| a.email.as_deref());
        let domain_n = acme_n.and_then(|a| a.domain.as_deref());
        // -- puerto + capability (precedencia: --port > `serve on N`) --
        let port_num = match overrides.port {
            // El operador que pasa `--port` es la autoridad: se concede `serve(N)`, así
            // que el `require serve(...)` del archivo no necesita coincidir.
            Some(p) => {
                caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Serve, Some(p.to_string())));
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
        // Dirección de bind (precedencia: --bind > cláusula `bind "…"` del archivo > 0.0.0.0).
        let bind_addr: String = match (&overrides.bind, bind_n) {
            (Some(b), _) => b.clone(),
            (None, Some(n)) => {
                let v = interp.eval(n, env)?;
                match &v {
                    SynValue::Text(t) if !t.trim().is_empty() => t.trim().to_string(),
                    other => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "serve `bind` must be a non-empty text (an IP or a host name), got {}",
                            other
                        ))))
                    }
                }
            }
            (None, None) => "0.0.0.0".to_string(),
        };

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

        // -- timeout por defecto de los handlers (`timeout N` | `timeout none`) --
        let default_timeout = resolve_timeout(interp, env, timeout_n)?;

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
        let (describe_about, describe_api, describe_version) = match describe_n {
            Some(d) => {
                if let NodeKind::DescribeClause { about, api, version } = &d.kind {
                    let about_s = match about {
                        Some(a) => Some(interp.eval(a, env)?.to_string()),
                        None => None,
                    };
                    let version_s = match version {
                        Some(v) => Some(interp.eval(v, env)?.to_string()),
                        None => None,
                    };
                    let api_v = match api {
                        Some(a) => match interp.eval(a, env)? {
                            SynValue::List(l) => list_values(&l).iter().map(|x| x.to_string()).collect(),
                            _ => Vec::new(),
                        },
                        None => Vec::new(),
                    };
                    (about_s, api_v, version_s)
                } else {
                    (None, Vec::new(), None)
                }
            }
            None => (None, Vec::new(), None),
        };

        // Snapshot de globales (una vez, ya corrió el top-level): cada request lo
        // reconstruye en su intérprete fresco. Intent enriquece /llms.txt. Los datos se
        // congelan en el lugar (R2): todos los workers leen los mismos, sin copiarlos.
        let snapshot = snapshot_globals_frozen(interp);
        // Snapshot `Send` de las capabilities concedidas por el preámbulo `require`
        // (ya corrió, porque `serve on` viene después). Cada request las re-aplica en
        // su intérprete fresco (los grants no cruzan hilos vía `Rc`).
        let caps_snap: Arc<Vec<Capability>> =
            Arc::new(caps.borrow().granted.iter().cloned().collect());
        // v0.6.46: los `deny` también, para los mounts de `static` (el archivo lo elige el cliente).
        let denied_snap: Vec<Capability> = caps.borrow().denied_snapshot();
        // Snapshot de las reglas declaradas en el top-level con `add_rule`. Se clona
        // una vez aquí (el top-level ya corrió completo) y se pre-popula en el
        // agentMemory de cada intérprete de request, para que check_rules/get_rules
        // encuentren las reglas sin que el programador tenga que re-declararlas.
        let rules_snap: Arc<Vec<OwnerRule>> = Arc::new(
            top_level_memory.borrow().rules.values().cloned().collect(),
        );
        let intent = interp.intent().map(|s| s.to_string());

        // Cola de aprobaciones humanas de ESTE serve (A1.v2): una por server,
        // compartida entre todos los workers/handlers. El OTT de cada pendiente sale
        // por la consola del server (mismo sink que los logs de serve); el default de
        // espera viene del knob `SYNSEMA_HUMAN_TIMEOUT` (`within` por gate le gana;
        // sin nada, 300 s). Con `SYNSEMA_HUMAN_WEBHOOK` (A1.v3), cada encolado dispara
        // además el webhook saliente firmado — el canal concreto es userland.
        let approvals: ServeApprovals = {
            let store = synsema_stdlib::secrets::EnvStore::load_default();
            let mut queue = synsema_llm::human::QueueHandler::with_notice(serve_log_sink());
            if let Some(url) = crate::llm_providers::resolve_knob("SYNSEMA_HUMAN_WEBHOOK", &store)
            {
                let cfg = Arc::new(ApprovalWebhook {
                    url,
                    secret: crate::llm_providers::resolve_knob(
                        "SYNSEMA_HUMAN_WEBHOOK_SECRET",
                        &store,
                    ),
                    public_url: crate::llm_providers::resolve_knob(
                        "SYNSEMA_HUMAN_PUBLIC_URL",
                        &store,
                    ),
                });
                queue = queue.with_enqueue_hook(Arc::new(move |e| {
                    fire_approval_webhook(cfg.clone(), e.clone())
                }));
            }
            Arc::new(ApprovalsShared {
                queue: Arc::new(queue),
                default_timeout: resolve_human_timeout(&store),
            })
        };

        // -- host default (rutas/estáticos/auth a nivel de `serve`) --
        let (routes, static_mounts, auth_handler) = build_host_table(
            interp,
            env,
            routes_n,
            mounts_n,
            static_mounts_n,
            auth_handler_n,
            block_limit,
            &snapshot,
            &caps_snap,
            &denied_snap,
            &rules_snap,
            &shared_memory,
            &on_write,
            &shared_progress,
            &on_write_progress,
            &shared_state,
            &approvals,
            &cron,
            &swarm,
            &shared_db,
            secure,
            &mem_name,
        )?;

        // -- errors with <task> (serve-level): páginas de error propias para
        // 401/404/405/500. Misma mecánica que el auth handler: la task corre en un
        // intérprete de request con el snapshot de globals. Aridad fija (3) validada
        // al construir el serve (fail-fast).
        let error_handler: Option<ErrorHandler> = match error_handler_n {
            None => None,
            Some(en) => {
                let arity: usize = match interp.eval(en, env) {
                    Ok(SynValue::Task(t)) => t.parameters.len(),
                    _ => 3,
                };
                if arity != 3 {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "errors task must take 3 parameters (status, message, request), got {}",
                        arity
                    ))));
                }
                let err_node = en.clone();
                let swarm_e = swarm.clone();
                let snap_e = snapshot.clone();
                let caps_e = caps_snap.clone();
                let rules_e = rules_snap.clone();
                let mem_e = shared_memory.clone();
                let ow_e = on_write.clone();
                let prog_e = shared_progress.clone();
                let owp_e = on_write_progress.clone();
                let st_e = shared_state.clone();
                let ap_e = approvals.clone();
                let cron_e = cron.clone();
                let db_e = shared_db.clone();
                let mn_e = mem_name.clone();
                let h: ErrorHandler = Arc::new(
                    move |status: i64, message: &str, ctx: &Ctx| -> Option<SynValue> {
                        with_serve_interp(&swarm_e, &snap_e, &caps_e, &db_e, &rules_e, &mem_e, &ow_e, &prog_e, &owp_e, &st_e, &ap_e, &cron_e, secure, &mn_e, |interp, caps| {
                            // T1 — la página de error corre bajo el MISMO sujeto que la ruta
                            // (identidad, techo delegado del token, presupuestos): el caller
                            // dispara el error a voluntad, así que sin esto era una escalada
                            // (auditoría ronda 1: el 403 de la ruta leía el archivo en el
                            // cuerpo de su propia página de error).
                            let _subject = crate::subject::Subject::of_user(ctx.user.as_ref()).apply(interp, caps);
                            let genv = interp.global_env.clone();
                            let task = match interp.eval(&err_node, &genv) {
                                Ok(t) => t,
                                Err(_) => return None,
                            };
                            let args =
                                vec![syn_int(status), syn_text(message), build_request_syn(ctx)];
                            match interp.call_task(task, args) {
                                Ok(SynValue::Nothing) => None,
                                // v0.6.47 (T1): si la página no puede salir por etiquetas, es un corte
                                // como el de una ruta (el log de esta entrada queda en la línea fija).
                                Ok(v) => {
                                    mark_if_response_refused(interp, &v);
                                    Some(v)
                                }
                                Err(e) => {
                                    // La task de errores falló: se loggea y el default
                                    // JSON responde — un bug acá jamás tumba el error path.
                                    if let Control::Error(re) = e {
                                        entry_eprintln(interp, &format!("[serve] errors task failed: {}", re.message));
                                    }
                                    None
                                }
                            }
                        })
                    },
                );
                Some(h)
            }
        };

        // -- vhosts (Lote 1): cada `host "..."` con su propia tabla + cert opcional (SNI) --
        struct VHostBuilt {
            pattern: String,
            routes: Vec<RouteSpec>,
            static_mounts: Vec<StaticMountSpec>,
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
                    &[],
                    static_mounts,
                    auth_handler.as_deref(),
                    block_limit,
                    &snapshot,
                    &caps_snap,
                    &denied_snap,
                    &rules_snap,
                    &shared_memory,
                    &on_write,
                    &shared_progress,
                    &on_write_progress,
                    &shared_state,
                    &approvals,
                    &cron,
                    &swarm,
                    &shared_db,
                    secure,
                    &mem_name,
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
            // Los PEM por host se gatean recién acá, cuando de verdad se usan (con `--tls-auto` o
            // `--tls-cert` la CLI manda y no se leen).
            let mut out = Vec::new();
            for v in &built_vhosts {
                if let (Some(c), Some(k)) = (&v.tls_cert, &v.tls_key) {
                    out.push((v.pattern.clone(), gate_tls_pem(&caps, c)?, gate_tls_pem(&caps, k)?));
                }
            }
            out
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
                    (Some(c), Some(k)) => (
                        Some(gate_tls_pem(&caps, &interp.eval(c, env)?.to_string())?),
                        Some(gate_tls_pem(&caps, &interp.eval(k, env)?.to_string())?),
                    ),
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
                    SynValue::List(l) => list_values(&l).iter().map(|x| x.to_string()).collect(),
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
        let domain_ask_n = acme_n.and_then(|a| a.domain_ask.as_deref());
        let tls_dns_n = acme_n.and_then(|a| a.tls_dns.as_deref());
        if tls_auto_eff && acme_domains.is_empty() && domain_ask_n.is_none() {
            return Err(Control::Error(RuntimeError::new(
                "tls auto (auto-HTTPS) requires a domain — pass `--domain example.com` or add `domain \"example.com\"` to the serve block".to_string(),
            )));
        }
        // Bajo `--attested` sin TLS propio, un cert autofirmado emitido con la
        // clave P-256 de la identidad (la que `/.well-known/attestation` anuncia): el cliente
        // verifica el documento y pinea el SPKI del cert a `public_key_hex`. Con `--tls-cert` o
        // `--tls-auto` se respeta lo del operador; el pin sigue siendo la clave anunciada (sirve
        // para cifrar bodies con `ecdh_*`), no la del cert.
        let mut tls_config = tls_config;
        let attested_identity = if overrides.attested {
            let id = synsema_stdlib::attest::attested_identity().ok_or_else(|| {
                Control::Error(RuntimeError::new("internal: serve --attested without an installed identity"))
            })?;
            // El modo TLS que se ató en `report_data` (decidido estáticamente en `serve_inner`)
            // Tiene que ser EXACTAMENTE el que se va a servir; si no, fallar cerrado.
            let operator_now = tls_config.is_some() || tls_auto_eff;
            if (id.config.tls_key == "operator") != operator_now {
                return Err(Control::Error(RuntimeError::new(format!(
                    "serve --attested: TLS mode mismatch (attested as {:?}, resolved as {:?}); refusing to serve an identity that does not describe this server",
                    id.config.tls_key,
                    if operator_now { "operator" } else { "attested" }
                ))));
            }
            // Auditoría externa: ninguna ruta del programa (host default ni vhosts) puede caer en
            // una URL reservada del runtime — `/.well-known/attestation` incluida, con o sin
            // barra final. Es error de CARGA, no un 404 tardío.
            for (label, rs) in std::iter::once(("", &routes)).chain(built_vhosts.iter().map(|v| (v.pattern.as_str(), &v.routes))) {
                if let Some(hit) = server::reserved_route_collision(rs) {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "serve --attested: route `{}`{} collides with a reserved path ({}); the program cannot declare reserved URLs under --attested",
                        hit,
                        if label.is_empty() { String::new() } else { format!(" (host {})", label) },
                        server::RESERVED_PATHS.join(", ")
                    ))));
                }
            }
            if tls_config.is_none() && !tls_auto_eff {
                let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
                if !matches!(bind_addr.as_str(), "0.0.0.0" | "::" | "[::]" | "localhost" | "127.0.0.1") {
                    sans.push(bind_addr.clone());
                }
                let cert_der = synsema_stdlib::attest::self_signed_cert_der(&id, &sans)
                    .map_err(|e| Control::Error(RuntimeError::new(e)))?;
                let cfg = server::build_tls_config_from_der(cert_der, id.pkcs8_der.clone())
                    .map_err(|e| Control::Error(RuntimeError::new(format!("serve --attested: TLS error: {}", e))))?;
                tls_config = Some(cfg);
            }
            Some(id)
        } else {
            None
        };
        let use_tls = tls_config.is_some() || tls_auto_eff;

        // v0.6.46 (E6-h): `serve --auditor`. El recibo de cada request se escribe antes de su
        // respuesta; una ruta `stream`/`socket` manda su body mientras corre, antes de que el recibo
        // exista: con auditor se rechaza al cargar. Firma la clave atestada bajo `--attested`, la de
        // `SYNSEMA_IDENTITY_KEY` si la hay, o una efímera del proceso (el header dice cuál).
        if let Some(auditor) = overrides.auditor {
            for (label, rs) in std::iter::once(("", &routes)).chain(built_vhosts.iter().map(|v| (v.pattern.as_str(), &v.routes))) {
                if let Some(r) = rs.iter().find(|r| r.streaming || r.socket) {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "serve --auditor: route `{} {}`{} is a {} route: its body leaves while it runs, before the request's sealed receipt exists",
                        r.method,
                        r.path,
                        if label.is_empty() { String::new() } else { format!(" (host {})", label) },
                        if r.socket { "socket" } else { "stream" }
                    ))));
                }
            }
            if !synsema_stdlib::sealed::serve_receipts_on() {
                let key = match &attested_identity {
                    Some(id) => synsema_stdlib::sealed::RunKey::from_attested_scalar(&id.private_scalar)
                        .map_err(|e| Control::Error(RuntimeError::new(format!("serve --auditor: {}", e))))?,
                    None => match identity_key_from_env() {
                        Some(seed) => synsema_stdlib::sealed::RunKey::from_identity_seed(&seed),
                        None => synsema_stdlib::sealed::RunKey::ephemeral(),
                    },
                };
                let program_sha = synsema_stdlib::attest::current_program_sha().map(|s| synsema_core::bytesutil::hex_encode(&s));
                let config_sha = attested_identity.as_ref().map(|id| synsema_core::bytesutil::hex_encode(&id.config_sha));
                synsema_stdlib::sealed::install_serve_receipts(
                    auditor,
                    overrides.sealed_bytes.unwrap_or(synsema_stdlib::sealed::DEFAULT_SEALED_BYTES),
                    key,
                    program_sha,
                    config_sha,
                    overrides.receipt.as_deref(),
                )
                .map_err(|e| Control::Error(RuntimeError::new(format!("serve --auditor: {}", e))))?;
            }
        }

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
        if let Some(id) = &attested_identity {
            runtime.attestation_json = Some(id.json().to_string());
            // T10: los documentos se renuevan antes de vencer (misma clave); si al vencer no se
            // pudo, el servidor se cierra con error en vez de servir un documento vencido.
            synsema_stdlib::attest::spawn_renewal().map_err(|e| Control::Error(RuntimeError::new(format!("serve --attested: {}", e))))?;
        }
        // T3: la identidad que firma la Agent Card. Bajo `--attested` ES la clave atestada
        // (la tarjeta y el documento de attestation hablan de la misma clave); si no,
        // `SYNSEMA_IDENTITY_KEY` (semilla ed25519 en hex). Sin ninguna, la tarjeta va sin firma.
        runtime.card_signer = match &attested_identity {
            Some(id) => synsema_stdlib::discovery::CardSigner::p256_from_scalar(&id.private_scalar).ok(),
            None => identity_key_from_env().map(synsema_stdlib::discovery::CardSigner::ed25519_from_seed),
        };
        // `timeout N` del serve block (Some(0) = `none` explícito = sin límite).
        runtime.set_default_timeout(default_timeout.filter(|t| *t > 0.0));
        // Shutdown ordenado: al iniciar el drain se paran los jobs de cron y se cancelan
        // cooperativamente los agentes vivos (junto con los handlers long-lived).
        {
            let sched = cron.sched.clone();
            let sw = swarm.clone();
            runtime.set_on_shutdown(Box::new(move || {
                sched.cancel_all();
                let n = sw.stop_all_agents("server shutting down");
                if n > 0 {
                    (serve_log_sink())(&format!("[serve] shutdown: cancelling {} live agent(s)", n));
                }
            }));
        }
        // Discovery: base URL absoluta (sitemap/openapi/robots), versión del API y
        // si la página /docs está encendida.
        runtime.domain = acme_domains.iter().find(|d| !d.starts_with("*.")).cloned();
        // v0.6.42 — `trust proxy` (o `--trust-proxy`): texto o lista de IPs/CIDRs. Un valor que
        // no es una IP ni un CIDR no arranca el servidor (fail-loud, como un puerto inválido).
        let trust_specs: Vec<String> = match &overrides.trust_proxy {
            Some(v) => v.clone(),
            None => match trust_proxy_n {
                Some(n) => match interp.eval(n, env)? {
                    SynValue::List(l) => list_values(&l).iter().map(|x| x.to_string()).collect(),
                    SynValue::Nothing => Vec::new(),
                    other => vec![other.to_string()],
                },
                None => Vec::new(),
            },
        };
        let mut trusted = Vec::with_capacity(trust_specs.len());
        for spec in &trust_specs {
            trusted.push(
                synsema_stdlib::server::TrustedNet::parse(spec).map_err(|m| Control::Error(RuntimeError::new(m)))?,
            );
        }
        runtime.trusted_proxies = trusted;
        runtime.describe_version = describe_version;
        runtime.docs_enabled = !docs_off;
        runtime.discovery_enabled = !discovery_off;
        // `errors with <task>`: páginas de error propias (401/404/405/500).
        if let Some(h) = error_handler {
            runtime.set_error_handler(h);
        }
        // Rutas reservadas /approvals (A1.v2): el server responde la cola de gates
        // humanos vía el gateway (GET lista sin tokens; POST con OTT responde).
        runtime.approvals = Some(Arc::new(QueueGateway(approvals.queue.clone())));
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
        // v0.6.45 (A5): desde acá el proceso escucha; `exit()` deja de ser válido.
        server::mark_serve_bound();
        let scheme = if use_tls { "HTTPS" } else { "HTTP" };
        println!("Serving {} on port {} ({} route(s))", scheme, port_str, n_routes);
        if let Some(id) = &attested_identity {
            println!("{}", synsema_stdlib::attest::attested_notice(id));
        }
        let rt = Arc::new(runtime);

        // Cron real: con el bind YA listo, publicar el entorno de ejecución (snapshot
        // + estado compartido del proceso — el mismo que ve un worker) y arrancar los
        // jobs del top-level que quedaron diferidos. Ningún tick corre contra un
        // server a medio levantar; los jobs registrados desde rutas arrancan solos.
        let cron_env = CronExecEnv {
            swarm: swarm.clone(),
            snapshot: snapshot.clone(),
            caps_snap: caps_snap.clone(),
            shared_db: shared_db.clone(),
            rules_snap: rules_snap.clone(),
            shared_memory: shared_memory.clone(),
            on_write: on_write.clone(),
            shared_progress: shared_progress.clone(),
            on_write_progress: on_write_progress.clone(),
            shared_state: shared_state.clone(),
            approvals: approvals.clone(),
            secure,
            mem_name: mem_name.clone(),
        };
        arm_cron(&cron, cron_env);

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
            // v0.6.42 — certificados administrados: la cuenta se reusa, uno por nombre (los
            // `*.` por DNS-01 con `tls dns`), y bajo demanda con `domain ask`. Los fijos se
            // obtienen (o se cargan del disco) antes de servir: sin ellos no hay HTTPS.
            let runner = |n: &Node| {
                serve_task_runner(&swarm, &snapshot, &caps_snap, &shared_db, &rules_snap, &shared_memory, &on_write, &shared_progress, &on_write_progress, &shared_state, &approvals, &cron, secure, &mem_name, n.clone())
            };
            let ask: Option<synsema_stdlib::acme_manager::AskFn> = domain_ask_n.map(|n| {
                let run = runner(n);
                Arc::new(move |host: &str| {
                    match run(&[host]) {
                        Ok(v) => v,
                        Err(e) => {
                            // Un error de la task cuenta como NO (y queda en el log).
                            eprintln!("[serve] domain ask failed for {}: {}", host, e);
                            false
                        }
                    }
                }) as synsema_stdlib::acme_manager::AskFn
            });
            let dns: Option<synsema_stdlib::acme_manager::DnsFn> = tls_dns_n.map(|n| {
                let run = runner(n);
                Arc::new(move |name: &str, value: &str, action: &str| run(&[name, value, action]).map(|_| ()))
                    as synsema_stdlib::acme_manager::DnsFn
            });
            let mgr = synsema_stdlib::acme_manager::CertManager::new(synsema_stdlib::acme_manager::AcmeOptions {
                email: acme_email.clone(),
                domains: acme_domains.clone(),
                ask,
                dns,
                http_store: Some(store.clone()),
            });
            // Un nombre que falla va al log y NO aborta el arranque (auditoría B6): sus handshakes
            // fallan hasta que la renovación en segundo plano lo consiga.
            match mgr.bootstrap() {
                Ok(missing) if !missing.is_empty() => {
                    eprintln!("ACME: serving without a certificate for {} (retrying in the background)", missing.join(", "));
                }
                Ok(_) => {}
                Err(e) => return Err(Control::Error(RuntimeError::new(format!("ACME error: {}", e)))),
            }
            mgr.spawn_renewal();
            let rt2 = rt.clone();
            let h = std::thread::Builder::new()
                .name(format!("serve:{}", port_str))
                .spawn(move || server::serve_forever_tls_managed(rt2, listener, mgr))
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
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Lexer error: {}", e)], ..Default::default() }
        }
        Err(CompileError::Parse(e)) => {
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Parse error: {}", e)], ..Default::default() }
        }
    };

    // Validación de los flags de despliegue (fail-loud) y política de múltiples serve.
    if !overrides.is_empty() {
        if let Err(e) = overrides.validate() {
            return RunResult { success: false, output: Vec::new(), errors: vec![format!("Runtime error: {}", e)], ..Default::default() };
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
                    "Runtime error: CLI serve flags (--port/--domain/--tls-*/--bind/--attested) require exactly one `serve` block, but found {}",
                    n_serve
                )],
                ..Default::default()
            };
        }
    }

    // `--attested`: la identidad se genera ANTES de correr una línea del
    // programa (par P-256 efímero + documento de la plataforma que ata sha256(spki ‖
    // program_sha)). Si la plataforma no responde, el servidor no arranca: error claro, nunca
    // Un serve "atestado" sin documento.
    if overrides.attested {
        // T5 — un `serve --attested` corre SIEMPRE con etiquetas de flujo. Hasta la ronda 3 eso lo
        // hacía sólo `cmd_serve` al parsear la flag, así que cualquier OTRO front-end que use esta
        // API pública (`run_serve_program_with_overrides` con `attested: true`: un embebedor, un
        // test, el daemon) levantaba un servidor atestado SIN etiquetas — el mismo agujero de "un
        // techo que se acepta en un front-end y se ignora en otro". Se fija acá, en el único
        // camino por el que pasan todos.
        crate::host::set_labels(true);
        // Auditoría externa (chequeo ESTÁTICO, antes de generar la identidad): ninguna ruta literal
        // del programa — host default o vhost — puede caer en una URL reservada del runtime
        // (`/.well-known/attestation` incluida, con o sin barra final). Las rutas que llegan por
        // grupos montados (`mount … at "/prefijo"`) las cubre el mismo chequeo sobre la tabla ya
        // construida, en el hook.
        for st in &program.statements {
            let NodeKind::ServeBlock { routes, hosts, .. } = &st.kind else { continue };
            let host_routes = hosts.iter().filter_map(|h| match &h.kind {
                NodeKind::HostBlock { routes, pattern, .. } => Some((Some(pattern), routes)),
                _ => None,
            });
            for (host, rs) in std::iter::once((None, routes)).chain(host_routes) {
                for r in rs {
                    let NodeKind::RouteDefinition { method, path, .. } = &r.kind else { continue };
                    let norm = server::normalize_route_path(path);
                    if server::RESERVED_PATHS.contains(&norm.as_str()) {
                        return RunResult {
                            success: false,
                            output: Vec::new(),
                            errors: vec![format!(
                                "Runtime error: serve --attested: route `{} {}`{} collides with a reserved path ({}); the program cannot declare reserved URLs under --attested",
                                method,
                                path,
                                host.map(|_| " (in a host block)".to_string()).unwrap_or_default(),
                                server::RESERVED_PATHS.join(", ")
                            )],
                            ..Default::default()
                        };
                    }
                }
            }
        }
        // Auditoría externa: `report_data` ata también un digest de CONFIGURACIÓN (etiquetas,
        // Techo, modo TLS, motor, perfil). El modo TLS se decide acá, ESTÁTICAMENTE, con lo
        // mismo que el hook aplicará después: `--tls-cert`/`--tls-auto` de la CLI o las
        // cláusulas `tls cert`/`tls auto` del único bloque `serve` → "operator" (la clave
        // anunciada NO es la del cert TLS; sirve para cifrar bodies); si no, "attested" (el cert
        // autofirmado se emite con la clave anunciada). El hook re-verifica la coherencia.
        let file_tls = program.statements.iter().any(|st| {
            matches!(&st.kind, NodeKind::ServeBlock { tls_cert, acme, .. } if tls_cert.is_some() || acme.as_ref().map_or(false, |a| a.tls_auto))
        });
        let operator_tls = overrides.tls_cert.is_some() || overrides.tls_auto_email.is_some() || file_tls;
        let config = synsema_stdlib::attest::AttestConfig {
            labels: crate::host::labels(),
            ceiling: overrides.ceiling.clone(),
            tls_key: if operator_tls { "operator" } else { "attested" },
            profile: match crate::host::profile() {
                crate::host::Profile::Pure => "pure",
                crate::host::Profile::Native => "native",
            },
            // Los llena `build_attested_identity` con los drivers elegidos (T4).
            drivers: Vec::new(),
        };
        match synsema_stdlib::attest::build_attested_identity(source, filename, config)
            .and_then(synsema_stdlib::attest::install_attested_identity)
        {
            Ok(()) => {}
            Err(e) => {
                return RunResult { success: false, output: Vec::new(), errors: vec![format!("Runtime error: {}", e)], ..Default::default() };
            }
        }
    }

    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));

    // ── Memoria + progress compartidos entre el top-level y todos los handlers ──
    // `shared_memory`/`shared_progress` son la fuente de verdad para remember/recall y
    // create_progress/resume_point. Se inicializan desde el SQLite del programa (mismo
    // .db que usa `synsema run`) para que sobrevivan reinicios y sean coherentes entre
    // ambos modos. (Antes el progress del boot se cargaba en un `pm` descartado → DE-028.)
    let shared_memory: SharedMemoryStore = Arc::new(Mutex::new(AgentMemory::new()));
    let shared_progress: SharedProgressStore = Arc::new(Mutex::new(ProgressManager::new()));
    // Identidad DECLARADA (DB-M1): una sola resolución para todo el serve (un solo
    // warning G-4, un solo `.db`). Sin declaración → cero archivos y gate cerrado en
    // top-level, workers, cron y agentes (G-1); los stores quedan inalcanzables.
    let host_ceiling = serve_ceiling();
    // Techo del host TAMBIÉN en el top-level: sin esto, el PREÁMBULO del programa (los
    // statements antes de `serve on`) corría sin techo — un `run("cmd")`/`fetch(...)`
    // ahí escapaba `serve --sandbox`/`--cap-set`. Se setea ANTES de `wire_common` para
    // que filtre los auto-grants y los `require` del preámbulo (mismo patrón que `run`).
    if let Some(cl) = &host_ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new((**cl).clone()));
    }
    let declared = match crate::engine::resolve_declared_state(
        &program.statements,
        filename,
        host_ceiling.as_ref().map(|a| a.as_slice()),
    ) {
        Ok(d) => d,
        Err(msg) => {
            return RunResult {
                success: false,
                output: Vec::new(),
                errors: vec![format!("Runtime error: {}", msg)],
                ..Default::default()
            }
        }
    };
    let mem_name: Option<String> = declared.as_ref().map(|d| d.name.clone());
    // Callbacks de persistencia: cada mutación se guarda al SQLite inmediatamente para
    // sobrevivir reinicios. Memoria y progress escriben tablas DISTINTAS y tienen
    // callbacks separados (`save_memory_only`/`save_progress_only`) para no pisarse —
    // antes el on_write de memoria hacía `save_from(mem, &ProgressManager::new())`, que
    // borraba el progress persistido en cada `remember` (DE-028). Comparten UNA
    // `StatePersistence` (mismo .db), y ningún callback toma el lock del OTRO store, así
    // que no hay inversión de orden de locks.
    let (declared_persistence, declared_dir) = match declared {
        Some(d) => (d.persistence, d.dir),
        None => (None, None),
    };
    let shared_persistence: Option<Arc<Mutex<crate::persistence::StatePersistence>>> =
        declared_persistence.map(|p| Arc::new(Mutex::new(p)));
    if let Some(ref p) = shared_persistence {
        p.lock().unwrap().load_into(
            &mut shared_memory.lock().unwrap(),
            &mut shared_progress.lock().unwrap(),
        );
    }
    let persist_memory: OnWriteFn = {
        let sp = shared_persistence.clone();
        Arc::new(move |mem: &AgentMemory| {
            if let Some(ref p) = sp {
                if let Ok(guard) = p.lock() {
                    guard.save_memory_only(mem);
                }
            }
        })
    };
    let persist_progress: OnWriteProgressFn = {
        let sp = shared_persistence.clone();
        Arc::new(move |prog: &ProgressManager| {
            if let Some(ref p) = sp {
                if let Ok(guard) = p.lock() {
                    guard.save_progress_only(prog);
                }
            }
        })
    };

    // Gate del top-level (DB-M1) + ctx para lo que el preámbulo propague (cron/parallel).
    let top_gate = match &mem_name {
        Some(n) => crate::engine::declared_memory_gate(caps.clone(), n.clone()),
        None => crate::engine::undeclared_memory_gate(crate::engine::suggested_memory_name(filename)),
    };
    // Ronda 5 (M1/B1): lo que `run_program` necesita de esta memoria (carpeta + recarga). Viaja con
    // el nombre (`MemName`) a los workers y a los ticks de cron.
    let serve_child: Option<crate::engine::ChildState> = match (&shared_persistence, declared_dir) {
        (Some(p), Some(dir)) => Some(crate::engine::child_state_for(
            dir,
            p.clone(),
            shared_memory.clone(),
            shared_progress.clone(),
        )),
        _ => None,
    };
    let top_mem_ctx: Option<crate::engine::MemoryCtx> = mem_name.as_ref().map(|n| crate::engine::MemoryCtx {
        name: n.clone(),
        memory: shared_memory.clone(),
        progress: shared_progress.clone(),
        on_write_mem: persist_memory.clone(),
        on_write_prog: persist_progress.clone(),
        child: serve_child.clone(),
    });
    let mem_name: Option<crate::engine::MemName> =
        mem_name.map(|name| crate::engine::MemName { name, child: serve_child.clone() });
    // `top_level_memory` sigue siendo el AgentMemory per-intérprete del top-level.
    // Gestiona add_rule/check_rules (gap-15). Para remember/recall usamos shared_memory.
    let top_level_memory = Rc::new(RefCell::new(AgentMemory::new()));
    wire_common_with_state(
        &mut interp,
        &caps,
        secure,
        Rc::new(RefCell::new(ProgressManager::new())),
        top_level_memory.clone(),
        top_gate.clone(),
        top_mem_ctx.clone(),
    );
    // DE-029: el provider LLM real también en el intérprete del preámbulo, para que el
    // código top-level (antes del `serve on PORT`) pueda usar reason/decide/generate.
    crate::engine::wire_real_llm_provider(&mut interp);
    crate::engine::wire_real_judge_provider(&mut interp);
    // Sobrescribir los builtins de memoria/progress en el top-level con los compartidos,
    // para que `remember`/`create_progress` en el top-level también persistan a disco y
    // sean coherentes con lo que ven los handlers.
    register_serve_memory_builtins(&interp, shared_memory.clone(), persist_memory.clone(), top_gate.clone());
    register_serve_progress_builtins(&interp, shared_progress.clone(), persist_progress.clone(), top_gate);

    let swarm = Arc::new(labels_swarm(Swarm::new()));
    if crate::host::labels() {
        (serve_log_sink())(SERVE_LABELS_LOG_NOTICE);
    }
    // Techo del host (--sandbox/--cap-set) aún no se extiende a `serve` (extensión posterior).
    wire_swarm_hooks(&mut interp, swarm.clone(), "main", serve_ceiling(), top_mem_ctx, None, &caps);
    // db compartida: el top-level abre/crea tablas; los handlers (en sus hilos) la
    // comparten vía Arc<Mutex>. Sobrescribe la db fresca que dejó wire_common.
    let shared_db: SharedDb = Arc::new(Mutex::new(DatabaseManager::new()));
    register_database_builtins(&interp, shared_db.clone(), caps.clone());
    // Estado mutable compartido entre todos los route handlers: respaldo de
    // state_set/state_get/state_incr. Vive mientras el servidor esté activo.
    let shared_state: SharedState = Arc::new(Mutex::new(HashMap::new()));
    // Registrar los builtins de estado también en el top-level (para que puedan
    // inicializar valores antes del `serve on PORT`).
    register_serve_state_builtins(&interp, shared_state.clone());
    // Cron del PROCESO (ejecución real): UN scheduler compartido por todos los
    // intérpretes (top-level + workers) — decisión "un solo scheduler". Nace
    // DIFERIDO: los jobs del top-level arrancan recién con el bind listo (o al
    // final del top-level si el programa no tiene `serve on` — camino solo-jobs).
    let cron = CronWiring::new_deferred();
    register_cron_builtins(
        &interp,
        SchedRef::Strong(cron.sched.clone()),
        shared_cron_executor(cron.tick_ctx(), serve_log_sink()),
    );

    let servers: Servers = Arc::new(Mutex::new(Vec::new()));
    interp.set_serve_hook(make_serve_hook(
        caps.clone(),
        swarm.clone(),
        shared_db.clone(),
        servers.clone(),
        secure,
        overrides,
        top_level_memory.clone(),
        shared_memory.clone(),
        persist_memory.clone(),
        shared_progress.clone(),
        persist_progress.clone(),
        shared_state.clone(),
        cron.clone(),
        mem_name.clone(),
    ));

    let r = interp.execute(&program);
    for line in &interp.output {
        println!("{}", line);
    }
    // v0.6.45 (A5): un `exit(code)` del preámbulo (antes de escuchar) es el fin pedido, no una
    // falla: sin "Runtime error" y con su código, como en `run`.
    let exit = match &r {
        Err(Control::Error(e)) => e.exit_code,
        _ => None,
    };
    if let Some(code) = exit {
        return RunResult {
            success: code == 0,
            output: std::mem::take(&mut interp.output),
            exit_code: Some(code),
            ..Default::default()
        };
    }
    if let Err(Control::Error(e)) = &r {
        return RunResult {
            success: false,
            output: interp.output.clone(),
            errors: vec![format!("Runtime error: {}", e)],
            ..Default::default()
        };
    }

    // v0.6.47 (T1, ronda 7): el preámbulo es una corrida más (la del swarm, que heredan los agentes que
    // lanzó) y terminó: su dueño la cierra. Si le quedan agentes vivos, la corrida sigue abierta hasta
    // que terminen (ronda 8, N1; caso 14 de `specs/t1-diario-modelo.md`): recién ahí se confirma, y si
    // uno se corta ya sirviendo, se deshace todo lo del preámbulo. Un worker que no termina nunca deja
    // la corrida abierta para siempre (cadena acotada: una versión por corrida con algo vivo).
    swarm.close_run(&swarm.run_cut, swarm.run_cut.get().is_some());
    let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *servers.lock().unwrap());
    if handles.is_empty() {
        // Sin rutas pero CON jobs de cron → proceso vivo con los jobs ejecutando
        // (la promesa documentada de `synsema serve` para programas solo-cron).
        let n_jobs = cron.sched.job_count();
        if n_jobs > 0 && r.is_ok() {
            let rules_snap: Arc<Vec<OwnerRule>> =
                Arc::new(top_level_memory.borrow().rules.values().cloned().collect());
            let env = CronExecEnv {
                swarm,
                // Una sola foto para lo que dura el proceso: congelada (R2).
                snapshot: snapshot_globals_frozen(&interp),
                caps_snap: Arc::new(caps.borrow().granted.iter().cloned().collect()),
                shared_db,
                rules_snap,
                shared_memory,
                on_write: persist_memory,
                shared_progress,
                on_write_progress: persist_progress,
                shared_state,
                approvals: default_approvals(),
                secure,
                mem_name,
            };
            arm_cron(&cron, env);
            println!("Serving {} cron job(s). Press Ctrl+C to stop.", n_jobs);
            // Bloquea (cero CPU) mientras los hilos de los jobs trabajan, hasta que maten el
            // proceso (Ctrl+C) o el programa pida `shutdown()` desde un job: entonces se
            // cancelan los jobs y se sale con 0, como el drain de un server.
            synsema_stdlib::server::park_cron_only();
            cron.sched.cancel_all();
            eprintln!("[serve] stopped");
            return RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new(), ..Default::default() };
        }
        // Sin server ni jobs: resultado normal (un programa serve sin bloque serve válido).
        return match r {
            Ok(_) => RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new(), ..Default::default() },
            Err(_) => RunResult {
                success: false,
                output: std::mem::take(&mut interp.output),
                errors: vec!["Runtime error: 'give'/'stop' used outside of a task or loop".to_string()],
                ..Default::default()
            },
        };
    }
    println!("\n{} HTTP server(s) running. Press Ctrl+C to stop.", handles.len());
    for h in handles {
        let _ = h.join(); // bloquea para siempre (el accept loop nunca termina)
    }
    // T10: un `serve --attested` que se cerró porque sus documentos vencieron sin renovación
    // termina con error, no con un apagado normal.
    if let Some(reason) = synsema_stdlib::attest::renewal_failure() {
        return RunResult { success: false, output: std::mem::take(&mut interp.output), errors: vec![format!("Runtime error: {}", reason)], ..Default::default() };
    }
    RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new(), ..Default::default() }
}

/// Corre un programa que contiene `serve on PORT`. Bindea (síncrono), imprime la
/// línea de readiness y bloquea hasta que maten el proceso. Default no-secure
/// (como `synsema run`); `secure=true` para el path seguro (body 500 genérico).
/// v0.6.20 — SIGHUP recarga el `.env`: sube la generación global y cada intérprete relee el
/// archivo en su próxima resolución de `secret()`/`env()` (`synsema_stdlib::secrets`). Un
/// `secret` ya guardado en un `let` de arranque no se renueva (es un valor). Sólo Unix: en
/// Windows no existe la señal y el camino sigue siendo reiniciar con drenado, dicho así.
fn install_env_reload_on_sighup() {
    #[cfg(unix)]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = std::thread::Builder::new().name("synsema-sighup".into()).spawn(|| {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                    return;
                };
                rt.block_on(async {
                    let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else {
                        return;
                    };
                    while sig.recv().await.is_some() {
                        let g = synsema_stdlib::secrets::request_env_reload();
                        (serve_log_sink())(&format!(
                            "[serve] SIGHUP: .env reload requested (generation {}); secret()/env() re-read the file on their next call",
                            g
                        ));
                    }
                });
            });
        });
    }
}

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
    // T4: la medida del programa que sirve, para el recibo (`receipt()`) de cada request.
    synsema_stdlib::attest::note_program_sha(source, filename);
    set_serve_ceiling(overrides.ceiling.clone());
    // Desde acá `shutdown()` tiene sentido (bajo `run` es un error claro).
    synsema_stdlib::server::mark_under_serve();
    install_env_reload_on_sighup();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || serve_inner(&src, &fname, secure, overrides))
        .expect("no se pudo crear el hilo del motor serve")
        .join()
        .unwrap_or_else(|p| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![crate::engine::abort_message(&p)],
            ..Default::default()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_stdlib::secrets::EnvStore;

    /// v0.6.47 (T1): una entrada de serve que entra en pánico cierra su corrida con corte (lo que
    /// escribió se deshace y la corrida no queda abierta para siempre).
    #[test]
    fn a_panicking_entry_closes_its_run_with_a_cut() {
        let swarm = Arc::new(Swarm::new().journaling_runs());
        let run = Arc::new(synsema_core::interpreter::RunCut::default());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            synsema_agents::blackboard::set_thread_scope(Some(run.clone()));
            let _owner = RunOwner { swarm: &swarm, scope: Some(run.clone()) };
            swarm.blackboard.write("k", synsema_core::types::SendValue::Text("x".into()), "");
            panic!("bug del motor");
        }));
        assert!(r.is_err());
        assert_eq!(swarm.blackboard.read("k", ""), None);
        assert!(synsema_agents::blackboard::thread_scope().is_none());
    }

    /// v0.6.46 (backlog §10): un `deny` del host en la raíz de un `static` (o en todo su árbol)
    /// arrancaba igual y servía la carpeta; uno de adentro no frena el arranque.
    #[test]
    fn a_deny_on_the_static_root_stops_the_start() {
        let fr = |p: &str| Capability::new(CapabilityType::FileRead, Some(p.to_string()));
        assert!(static_root_denied("./www/", &[fr("./www")]).is_some());
        assert!(static_root_denied("./www", &[fr("./www/**")]).is_some());
        assert!(static_root_denied("./www", &[fr("./www/private/**")]).is_none());
        assert!(static_root_denied("./www", &[]).is_none());
    }

    /// R2.5: el código no se copia por worker. Una task (y una lambda guardada en una global)
    /// reconstruida desde la foto usa EL MISMO cuerpo que la del proceso que la definió.
    #[test]
    fn a_rebuilt_task_shares_its_body() {
        let mut interp = Interpreter::new();
        let program = synsema_core::parser::parse_source(
            "task doble(x)
    let y be x * 2
    give y
let f be (x) => x + 1
",
            "<r25>",
        )
        .expect("parse");
        assert!(interp.execute(&program).is_ok());
        let body_of = |i: &Interpreter, name: &str| match synsema_core::interpreter::env_get(&i.global_env, name) {
            Some(SynValue::Task(t)) => t.body.clone(),
            other => panic!("{}: {:?}", name, other.map(|v| v.type_name())),
        };
        let snap = snapshot_globals_frozen(&interp);
        let mut worker = Interpreter::new();
        let _reg = rebuild_globals(&mut worker, &snap, None);
        for name in ["doble", "f"] {
            assert!(std::sync::Arc::ptr_eq(&body_of(&interp, name), &body_of(&worker, name)), "{} se copió", name);
        }
        // Y la task del AST es la misma que la definida: definir no copia.
        let synsema_core::ast::NodeKind::TaskDefinition { body, .. } = &program.statements[0].kind else { panic!("task") };
        assert!(std::sync::Arc::ptr_eq(body, &body_of(&interp, "doble")));
    }

    /// Ronda 3 (R3, B1): de un frame cruzan sólo los nombres que la task menciona. Un local grande
    /// que la lambda no nombra no viaja; una segunda task del mismo frame agrega lo suyo.
    #[test]
    fn a_frame_carries_only_the_names_the_task_mentions() {
        let mut interp = Interpreter::new();
        let program = synsema_core::parser::parse_source(
            "task mk(n)
    let big be [1, 2, 3]
    let k be 2
    give [(x) => x * n + k, () => big]
let fs be mk(3)
",
            "<r3b1>",
        )
        .expect("parse");
        assert!(interp.execute(&program).is_ok());
        let Some(SynValue::List(l)) = synsema_core::interpreter::env_get(&interp.global_env, "fs") else { panic!("fs") };
        let fs = l.borrow().to_vec();
        let names = |gv: &GlobalVal| -> Vec<String> {
            let GlobalVal::Task { frames, .. } = gv else { panic!("una task") };
            let mut v: Vec<String> = frames.iter().flat_map(|f| f.env.iter().flatten().map(|(k, _)| k.clone())).collect();
            v.sort();
            v
        };
        let mut state = SnapState::default();
        let SynValue::Task(t0) = &fs[0] else { panic!("lambda") };
        let SynValue::Task(t1) = &fs[1] else { panic!("lambda") };
        assert_eq!(names(&task_global(t0, &mut state)), vec!["k".to_string(), "n".to_string()]);
        // La segunda, en la misma foto, agrega sólo `big`; sola, lleva sólo `big`. Ronda 4 (N1): los
        // nombres de un cuerpo se calculan una vez.
        assert_eq!(names(&task_global(t1, &mut state)), vec!["big".to_string()]);
        assert_eq!(names(&task_global(t1, &mut SnapState::default())), vec!["big".to_string()]);
        let a = synsema_core::interpreter::task_free_names(t0);
        assert!(std::sync::Arc::ptr_eq(&a, &synsema_core::interpreter::task_free_names(t0)), "se recorrió dos veces");
        // Ronda 6 (N1): la copia de la foto hereda los nombres y no recorre (un `parallel_map`
        // dentro de cada item de otro).
        let mut base_interp = Interpreter::new();
        let base = Bases::of(&mut base_interp);
        let gv = task_global(t0, &mut SnapState::default());
        let SynValue::Task(copy) = rebuild_global_val(&gv, &base.global.clone(), &base, &mut ModuleRegistry::default(), None) else {
            panic!("una task")
        };
        assert!(copy.free_names.get().is_some_and(|n| std::sync::Arc::ptr_eq(n, &a)), "la copia vuelve a recorrer");
        // Ronda 5 (M1): viven con la task, no en una caché que la sobrevive.
        let program = synsema_core::parser::parse_source("task inner(x)\n    require time\n    give x + k\n", "<r5m1>").expect("parse");
        let synsema_core::ast::NodeKind::TaskDefinition { parameters, body, .. } = &program.statements[0].kind else { panic!("task") };
        let t = Rc::new(SynTaskValue {
            name: "inner".into(),
            parameters: parameters.clone(),
            body: body.iter().cloned().collect::<Vec<_>>().into(),
            closure_env: Environment::root("t"),
            origin: None,
            required_capabilities: Vec::new(),
            code: Default::default(),
            free_names: Default::default(),
        });
        let n = synsema_core::interpreter::task_free_names(&t);
        assert!(n.contains("k"));
        let weak = std::sync::Arc::downgrade(&n);
        drop(n);
        drop(t);
        assert!(weak.upgrade().is_none(), "los nombres sobreviven a la task");
    }

    /// R2.4: la foto de un agente o de `cron` comparte lo que ya está congelado para siempre (las
    /// globales de `serve`) y copia el resto, sin congelar nada nuevo.
    #[test]
    fn a_shared_snapshot_shares_only_what_is_already_permanent() {
        let mut interp = Interpreter::new();
        let program = synsema_core::parser::parse_source(
            "let fijo be [\"un texto largo que no entra en línea\", {\"a\": 1}]
let nuevo be {\"b\": [2, 3]}
",
            "<r24>",
        )
        .expect("parse");
        assert!(interp.execute(&program).is_ok());
        let fijo = synsema_core::interpreter::env_get(&interp.global_env, "fijo").expect("fijo");
        let nuevo = synsema_core::interpreter::env_get(&interp.global_env, "nuevo").expect("nuevo");
        // `fijo` como las globales de `serve`: congelado para siempre.
        let _f = synsema_core::frozen::FrozenValue::new(fijo.clone()).ok().expect("se congela");
        let snap = snapshot_globals_shared(&interp);
        let kind = |name: &str| match snap.iter().find(|(k, _)| k == name).map(|(_, g)| g) {
            Some(GlobalVal::Frozen(_)) => "compartido",
            Some(GlobalVal::Value(_)) => "copia",
            _ => "otro",
        };
        assert_eq!(kind("fijo"), "compartido");
        assert_eq!(kind("nuevo"), "copia");
        // Y no congeló lo que no lo estaba.
        match &nuevo {
            SynValue::Map(m) => assert!(!synsema_core::types::MapRef::is_immortal(m)),
            other => panic!("{}", other.type_name()),
        }
        assert!(matches!(val_to_global_shared(&fijo), GlobalVal::Frozen(_)));
        assert!(matches!(val_to_global_shared(&nuevo), GlobalVal::Value(_)));
    }

    fn enqueued(id: &str, token: &str) -> synsema_llm::human::EnqueuedApproval {
        synsema_llm::human::EnqueuedApproval {
            id: id.to_string(),
            ty: "approve".to_string(),
            message: "Delete the production table?".to_string(),
            token: token.to_string(),
            expires_at: 1786500000,
            timeout_secs: 300.0,
        }
    }

    // A1.v3: la firma del webhook es HMAC-SHA256 hex con prefijo `sha256=` — vector
    // conocido (RFC 2202-style, key="key").
    #[test]
    fn webhook_signature_known_vector() {
        assert_eq!(
            webhook_signature("key", "The quick brown fox jumps over the lazy dog"),
            "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    // A1.v3 (D2): payload SIN public_url → sólo respond_path; CON public_url → además
    // respond_url y los links yes/no absolutos con el token.
    #[test]
    fn webhook_payload_with_and_without_public_url() {
        let e = enqueued("interact_7", "abc123");
        let bare: serde_json::Value =
            serde_json::from_str(&approval_webhook_payload(&e, None)).unwrap();
        assert_eq!(bare["id"], "interact_7");
        assert_eq!(bare["type"], "approve");
        assert_eq!(bare["message"], "Delete the production table?");
        assert_eq!(bare["expires_at"], 1786500000);
        assert_eq!(bare["token"], "abc123");
        assert_eq!(bare["respond_path"], "/approvals/interact_7");
        assert!(bare.get("respond_url").is_none(), "sin public_url no hay URL absoluta");
        assert!(bare.get("respond_link_yes").is_none());

        // El trailing slash de la base no debe duplicar la barra.
        let full: serde_json::Value = serde_json::from_str(&approval_webhook_payload(
            &e,
            Some("https://mi-app.com/"),
        ))
        .unwrap();
        assert_eq!(full["respond_url"], "https://mi-app.com/approvals/interact_7");
        assert_eq!(
            full["respond_link_yes"],
            "https://mi-app.com/approvals/interact_7/abc123?d=yes"
        );
        assert_eq!(
            full["respond_link_no"],
            "https://mi-app.com/approvals/interact_7/abc123?d=no"
        );
    }

    // D1: precedencia del default del host para gates humanos — environ > `.env` >
    // ausente (`None` → la cola aplica 300 s). Un valor no-numérico o no-positivo NO
    // produce un default roto: cae a `None`. (El `within` por-gate se resuelve en el
    // callback y le gana a todo esto — testeado en human.rs.)
    #[test]
    fn human_timeout_knob_precedence() {
        std::env::remove_var("SYNSEMA_HUMAN_TIMEOUT");
        let store = EnvStore::parse("SYNSEMA_HUMAN_TIMEOUT=45\n");
        assert_eq!(resolve_human_timeout(&store), Some(45.0), "el `.env` alcanza solo");
        std::env::set_var("SYNSEMA_HUMAN_TIMEOUT", "90");
        assert_eq!(resolve_human_timeout(&store), Some(90.0), "el environ gana sobre el .env");
        std::env::set_var("SYNSEMA_HUMAN_TIMEOUT", "no-numerico");
        assert_eq!(resolve_human_timeout(&store), None, "valor inválido → default (300)");
        std::env::set_var("SYNSEMA_HUMAN_TIMEOUT", "-5");
        assert_eq!(resolve_human_timeout(&store), None, "no-positivo → default (300)");
        std::env::remove_var("SYNSEMA_HUMAN_TIMEOUT");
        assert_eq!(resolve_human_timeout(&EnvStore::empty()), None);
    }
}
