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

use indexmap::IndexMap;

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
use synsema_stdlib::acme;
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
// Cron real (ejecución de tasks Synsema desde el hilo del job)
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
    mem_name: Option<String>,
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
        |interp| {
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
    let mem_name = mem.as_ref().map(|m| m.name.clone());
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
                Arc::new(match synsema_stdlib::ws::bus_of_interp(interp) {
                    Some(b) => Swarm::with_bus(b),
                    None => Swarm::new(),
                })
            })
            .clone();
        let env = CronExecEnv {
            swarm: swarm.clone(),
            snapshot: snapshot_globals(interp),
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
// Webhook saliente de aprobaciones (A1.v3)
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
            let r = synsema_stdlib::http::http_request(
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
    /// `--sandbox` | `--cap-set <list>`: techo de capabilities del host para TODO el
    /// serve (requests, cron, agentes). `None` = sin techo (comportamiento histórico).
    pub ceiling: Option<Vec<Capability>>,
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
}

/// Estado del ÁRBOL COMPLETO de un snapshot. Se comparte entre TODOS los bindings de
/// `snapshot_globals` para que el diamante entre bindings top-level (b y c importan d)
/// también dedupee: d viaja UNA vez, las demás apariciones son referencias por id.
#[derive(Default)]
struct SnapState {
    /// `module_env`s EN CURSO de snapshot (stack, por identidad de `Rc`): corta la
    /// recursión de un map interno auto-referencial (TOOL_ALLOW — DE-032) y de
    /// cualquier ciclo hipotético.
    in_progress: Vec<usize>,
    /// `module_env`s YA snapshoteados en este árbol: una segunda aparición (el otro
    /// brazo del diamante B→D←C — DE-033) viaja como referencia por id, no como copia.
    done: HashSet<usize>,
}

/// Convierte un `SynValue` a `GlobalVal` de forma recursiva, con un árbol de snapshot
/// propio (para snapshots de UN valor suelto, p.ej. los globales que viajan a un agente
/// spawneado). Un Map que cierra sobre un `module_env` se snapshotea como
/// `GlobalVal::Module` (env inline la primera vez, referencia por id después); un Map
/// de datos con tasks se preserva como `MapWithTasks`; un Map puramente de valores viaja
/// barato como SendValue.
pub(crate) fn val_to_global(v: &SynValue) -> GlobalVal {
    val_to_global_inner(v, &mut SnapState::default())
}

/// ¿La entry `(k, v)` del map alias es EL MISMO objeto que el binding `k` del
/// `module_env`? Solo valores por-referencia (Task/Map/List vía `Rc::ptr_eq`);
/// primitivas → `false` (inmutables: la copia es indistinguible del original).
fn is_export_of(module_env: &Rc<RefCell<Environment>>, k: &str, v: &SynValue) -> bool {
    let env = module_env.borrow();
    match (env.bindings.get(k), v) {
        (Some(SynValue::Task(a)), SynValue::Task(b)) => Rc::ptr_eq(a, b),
        (Some(SynValue::Map(a)), SynValue::Map(b)) => Rc::ptr_eq(a, b),
        (Some(SynValue::List(a)), SynValue::List(b)) => Rc::ptr_eq(a, b),
        _ => false,
    }
}

/// Snapshotea las entradas de un map que cierra sobre `module_env`, marcando con
/// `is_export` las que son el mismo objeto que el binding homónimo del env (en rebuild
/// se cosechan del env reconstruido → identidad compartida alias↔env).
fn snapshot_alias_entries(
    m: &Rc<RefCell<IndexMap<String, SynValue>>>,
    module_env: &Rc<RefCell<Environment>>,
    state: &mut SnapState,
) -> Vec<(String, GlobalVal, bool)> {
    m.borrow()
        .iter()
        .map(|(k, v)| {
            let is_export = is_export_of(module_env, k, v);
            (k.clone(), val_to_global_inner(v, state), is_export)
        })
        .collect()
}

/// Núcleo recursivo de `val_to_global`/`snapshot_globals`/`snapshot_module_env`.
fn val_to_global_inner(v: &SynValue, state: &mut SnapState) -> GlobalVal {
    match v {
        SynValue::Task(t) => GlobalVal::Task {
            name: t.name.clone(),
            parameters: t.parameters.clone(),
            body: t.body.clone(),
            required_capabilities: t.required_capabilities.clone(),
        },
        SynValue::Builtin(_) => GlobalVal::Value(to_send(v)),
        SynValue::Map(m) => {
            // ¿El map cierra sobre un `module_env`? (alias de `use`, o map interno cuyas
            // tasks cierran sobre el módulo — heurística por el nombre "module:…").
            if let Some(module_env) = module_env_of(&m.borrow()) {
                let key = Rc::as_ptr(&module_env) as usize;
                let id = module_env.borrow().name.clone();
                if state.in_progress.contains(&key) || state.done.contains(&key) {
                    // El env ya viaja (o viajó) en este árbol: referencia por id. Un solo
                    // camino cubre el map auto-referencial (DE-032), el diamante B→D←C
                    // (DE-033) y cualquier ciclo hipotético. En rebuild resuelve al MISMO
                    // env vía el registro.
                    let alias = snapshot_alias_entries(m, &module_env, state);
                    return GlobalVal::Module { id, alias, env: None };
                }
                // Primer encuentro: el env viaja inline (TODAS las bindings, DE-027).
                state.in_progress.push(key);
                let env: Vec<(String, GlobalVal)> = module_env
                    .borrow()
                    .bindings
                    .iter()
                    .filter(|(_, v)| !matches!(v, SynValue::Builtin(_)))
                    .map(|(k, v)| (k.clone(), val_to_global_inner(v, state)))
                    .collect();
                state.in_progress.pop();
                state.done.insert(key);
                let alias = snapshot_alias_entries(m, &module_env, state);
                return GlobalVal::Module { id, alias, env: Some(env) };
            }
            let entries: Vec<(String, GlobalVal)> = m
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), val_to_global_inner(v, state)))
                .collect();
            // Map puramente de valores primitivos → viaja barato como SendValue.
            if entries.iter().all(|(_, gv)| matches!(gv, GlobalVal::Value(_))) {
                return GlobalVal::Value(to_send(&SynValue::Map(m.clone())));
            }
            // Map de datos con callbacks (tasks que NO cierran sobre un módulo).
            GlobalVal::MapWithTasks(entries)
        }
        other => GlobalVal::Value(to_send(other)),
    }
}

/// Devuelve el `module_env` de un map que es alias de módulo: el `closure_env` de
/// cualquiera de sus tasks cuyo env se llame `module:…`. `None` si el map no es un alias
/// de módulo (sus tasks cierran sobre el global u otro scope → map de datos con callbacks).
pub(crate) fn module_env_of(map: &IndexMap<String, SynValue>) -> Option<Rc<RefCell<Environment>>> {
    for v in map.values() {
        if let SynValue::Task(t) = v {
            if t.closure_env.borrow().name.starts_with("module:") {
                return Some(t.closure_env.clone());
            }
        }
    }
    None
}

/// Snapshotea TODAS las bindings de un `module_env` (saltando builtins) a `GlobalVal`,
/// para que viajen `Send` a otro hilo/intérprete, con el env raíz marcado en curso (una
/// referencia interna a él — map auto-referencial — viaja por id, no re-snapshotea).
/// Reusa el mismo camino que la rama Module de `val_to_global_inner` — usado por
/// `parallel_map` para capturar el módulo de la task aplicada (DE-030).
pub(crate) fn snapshot_module_env(module_env: &Rc<RefCell<Environment>>) -> Vec<(String, GlobalVal)> {
    let mut state = SnapState {
        in_progress: vec![Rc::as_ptr(module_env) as usize],
        done: HashSet::new(),
    };
    module_env
        .borrow()
        .bindings
        .iter()
        .filter(|(_, v)| !matches!(v, SynValue::Builtin(_)))
        .map(|(k, v)| (k.clone(), val_to_global_inner(v, &mut state)))
        .collect()
}

/// Registro `id → module_env` de UN rebuild (per-request/per-worker): toda referencia
/// al mismo módulo (diamante, alias, task aplicada) resuelve al MISMO env, igual que
/// `module_cache` bajo `run`. Vive lo que dura ese rebuild — NUNCA se comparte entre
/// requests o workers (el aislamiento CSP no cambia; el estado entre requests es
/// `state_set`/SQL/`remember`).
pub(crate) type ModuleRegistry = HashMap<String, Rc<RefCell<Environment>>>;

/// Reconstruye (o reusa del registro) el `module_env` compartido de un módulo, hijo de
/// `base`, con cada task cerrando sobre ESE env → las hermanas (exportadas o no) se
/// resuelven por nombre simple. Reproduce la estructura de `load_module_inner` de core.
/// Compartido por la rama Module de `rebuild_global_val` (globales, DE-027) y por
/// `reconstruct_task` de `parallel_map` (task aplicada, DE-030).
pub(crate) fn rebuild_module_env(
    id: &str,
    env: &[(String, GlobalVal)],
    base: &Rc<RefCell<Environment>>,
    registry: &mut ModuleRegistry,
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
    let module_env = Environment::child(base, id);
    // Registrar ANTES de poblar: un map interno auto-referencial (TOOL_ALLOW — DE-032)
    // que aparezca durante la población resuelve a ESTE env en construcción.
    registry.insert(id.to_string(), module_env.clone());
    for (k, gv) in env {
        let v = rebuild_global_val(gv, &module_env, base, registry);
        module_env.borrow_mut().bindings.insert(k.clone(), v);
    }
    module_env
}

/// Reconstruye un `SynValue` desde un `GlobalVal`. `closure_target` es el env que
/// capturan las tasks (para top-level es el global; para una task de módulo es el
/// `module_env` compartido). `base` es el padre para nuevos `module_env` (siempre el
/// global del request, igual que `load_module_inner`, que cuelga todo module_env del
/// global). Las tasks cierran sobre `closure_target` para que la recursión mutua entre
/// globales y la llamada a hermanas dentro de un módulo (DE-027) sigan funcionando.
/// `registry` dedupea los `module_env` de este rebuild por id (DE-033).
fn rebuild_global_val(
    gv: &GlobalVal,
    closure_target: &Rc<RefCell<Environment>>,
    base: &Rc<RefCell<Environment>>,
    registry: &mut ModuleRegistry,
) -> SynValue {
    match gv {
        GlobalVal::Value(sv) => from_send(sv),
        GlobalVal::Task { name, parameters, body, required_capabilities } => {
            SynValue::Task(Rc::new(SynTaskValue {
                name: name.clone(),
                parameters: parameters.clone(),
                body: body.clone(),
                closure_env: closure_target.clone(),
                origin: None,
                required_capabilities: required_capabilities.clone(),
            }))
        }
        GlobalVal::Module { id, alias, env } => {
            // Resolver el `module_env` compartido: el primer encuentro (env inline) lo
            // construye y registra; una referencia (env: None) lo toma del registro.
            let module_env = match env {
                Some(entries) => rebuild_module_env(id, entries, base, registry),
                None => match registry.get(id) {
                    Some(e) => e.clone(),
                    None => {
                        // Fallback defensivo (jamás panic): inalcanzable por construcción
                        // para imports (`use`) — el primer encuentro siempre viaja con el
                        // env inline y el rebuild recorre en el mismo orden. Solo llegaría
                        // acá una mutación exótica post-load (inyectar en un map de módulo
                        // tasks de OTRO módulo no alcanzado por el snapshot). Se registra
                        // el env vacío para que al menos todas las referencias compartan.
                        let e = Environment::child(base, id);
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
            let mut m = IndexMap::new();
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
                    None => rebuild_global_val(gv, &module_env, base, registry),
                };
                m.insert(k.clone(), v);
            }
            SynValue::Map(Rc::new(RefCell::new(m)))
        }
        GlobalVal::MapWithTasks(entries) => {
            // Map de datos con callbacks: las tasks cierran sobre el global (como cualquier
            // task top-level), NO sobre un module_env compartido.
            let mut m = IndexMap::new();
            for (k, gv) in entries {
                m.insert(k.clone(), rebuild_global_val(gv, base, base, registry));
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
    // UN SnapState para TODOS los bindings: el diamante entre bindings top-level (b y c
    // importan d) dedupea — el env de d viaja UNA vez y la otra aparición es referencia
    // por id. El orden del Vec se conserva → en rebuild el primer encuentro (que lleva
    // el env inline) siempre se procesa antes que sus referencias.
    let mut state = SnapState::default();
    for (k, v) in env.bindings.iter() {
        if matches!(v, SynValue::Builtin(_)) {
            continue; // re-registrados por wire_common
        }
        out.push((k.clone(), val_to_global_inner(v, &mut state)));
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
) -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    // Agentes (Batch 6): van al mapa separado `agent_definitions` (NO a bindings). Se
    // insertan vía `restore_agents` — el MISMO camino que la restauración post-request
    // de `with_serve_interp` — para que build fresco y reset no puedan divergir (si
    // divergieran, el bug pocos-cores volvería sólo en uno de los dos caminos).
    restore_agents(interp, snapshot);
    for (k, gv) in snapshot {
        match gv {
            GlobalVal::Agent { .. } => {}
            other => {
                // Top-level: las tasks cierran sobre el global (closure_target) y los
                // nuevos module_env también cuelgan del global (base).
                let genv = interp.global_env.clone();
                let v = rebuild_global_val(other, &genv, &genv, &mut registry);
                interp.set_global(k, v);
            }
        }
    }
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
                Some(SynValue::Number(n)) => n.clone(),
                _ => Number::Int(1), // default entero
            };
            let mut guard = s.lock().unwrap();
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
    mem_name: &Option<String>,
    agent_builder: Option<crate::engine::InterpBuilder>,
) -> (Interpreter, Rc<RefCell<CapabilitySet>>) {
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
        Some(n) => crate::engine::declared_memory_gate(caps.clone(), n.clone()),
        None => crate::engine::undeclared_memory_gate("my-agent".to_string()),
    };
    // Ctx compartido para lo que este worker propague (cron registrado desde rutas,
    // workers de parallel_map dentro de un handler): mismos stores + on_write.
    let mem_ctx: Option<crate::engine::MemoryCtx> = mem_name.as_ref().map(|n| crate::engine::MemoryCtx {
        name: n.clone(),
        memory: shared_memory.clone(),
        progress: shared_progress.clone(),
        on_write_mem: on_write.clone(),
        on_write_prog: on_write_progress.clone(),
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
    // ProgressManager compartido entre hilos/requests, no el fresco per-intérprete.
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
    wire_swarm_hooks(&mut interp, swarm, "request", host_ceiling, mem_ctx, agent_builder);
    register_database_builtins(&interp, shared_db, caps.clone());
    rebuild_globals(&mut interp, snapshot);
    (interp, caps)
}

/// Intérprete base + sus capabilities, cacheado por-worker y reusado entre requests.
struct BaseInterp {
    interp: Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
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
    mem_name: &Option<String>,
    f: impl FnOnce(&mut Interpreter) -> R,
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
                build_base_interp(
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
                )
            });
            let _ = cell.set(b.clone());
            b
        };
        let (interp, caps) = build_base_interp(
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
        BaseInterp { interp, caps, _snapshot: snapshot.clone() }
    });

    let out = f(&mut base.interp);

    // Limpieza por-request: estado transitorio del intérprete + capabilities al
    // snapshot del preámbulo (aislamiento entre requests reusando el mismo intérprete).
    // El hub de I/O también: sockets cerrados, procesos matados, suscripciones al bus
    // retiradas — nada de lo que abrió este request sobrevive al siguiente.
    synsema_stdlib::ws::reset_hub(&base.interp);
    base.interp.reset_for_request();
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
    SERVE_INTERPS.with(|c| c.borrow_mut().insert(key, base));
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
    mem_name: &Option<String>,
    link: Box<dyn std::any::Any + Send>,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp| {
        interp.set_cancel_token(ctx.cancel.clone());
        let (identity, limits) = match &ctx.user {
            Some(u) => (server::identity_of(u), server::delegated_spend_of(u)),
            None => (None, Vec::new()),
        };
        interp.set_request_identity(identity, limits);
        let link = match link.downcast::<ServerSocketLink>() {
            Ok(l) => *l,
            Err(_) => return StreamEnd::Error("socket: internal transport link type mismatch".to_string()),
        };
        let handle = match adopt_server_socket(interp, link) {
            Ok(h) => h,
            Err(Control::Error(e)) => return StreamEnd::Error(e.to_string()),
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
            Err(Control::Error(e)) => StreamEnd::Error(e.to_string()),
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
// Construcción del contexto de request (SynValue)
// =========================================================

// `str_map`/`headers_map`/`build_request_syn`/`build_form_syn`/`request_bindings`:
// MOVIDOS a synsema_stdlib::routing (puros; el handler-mode wasm arma el mismo
// `request`). Importados arriba.

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
    mem_name: &Option<String>,
) -> GiveOutcome {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, |interp| {
        // T6.4 — identidad del sujeto de ESTA request (y su techo de gasto
        // delegado, si el token lo trae): lo consume el ledger de `spend` para
        // contabilizar y limitar por identidad. `reset_for_request` lo limpia al
        // devolver el intérprete al pool, así no se filtra al request siguiente.
        let (identity, limits) = match &ctx.user {
            Some(u) => (server::identity_of(u), server::delegated_spend_of(u)),
            None => (None, Vec::new()),
        };
        interp.set_request_identity(identity, limits);
        // Token de cancelación de la request (timeout de handler / shutdown).
        interp.set_cancel_token(ctx.cancel.clone());
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
    mem_name: &Option<String>,
    emit: Emitter,
) -> StreamEnd {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, move |interp| {
        interp.set_cancel_token(ctx.cancel.clone());
        let cell = Rc::new(RefCell::new(emit));
        let ec = cell.clone();
        interp.set_stream_emit(Rc::new(move |val: SynValue, event: Option<&str>| {
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

fn validate_route_templates(routes_n: &[Node]) -> Result<(), Control> {
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
                                if let Err(e) =
                                    synsema_core::templates::validate_template(value)
                                {
                                    err = Some(format!(
                                        "template validation failed for render(\"{}\"): {}",
                                        value, e
                                    ));
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
    mem_name: &Option<String>,
) -> Result<HostTable, Control> {
    // Templates literales de las rutas: validados al construir el serve (fail-fast).
    validate_route_templates(routes_n)?;

    // -- static mounts (dedup por prefijo; cache/fallback validados fail-fast) --
    let mut static_mounts: Vec<StaticMountSpec> = Vec::new();
    let mut seen_prefixes: Vec<String> = Vec::new();
    for mount in static_mounts_n {
        if let NodeKind::StaticMount { directory, prefix, cache, fallback } = &mount.kind {
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
                with_serve_interp(&swarm_a, &snap_a, &caps_a, &db_a, &rules_a, &mem_a, &ow_a, &prog_a, &owp_a, &st_a, &ap_a, &cron_a, secure, &mn_a, |interp| {
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
                    interp.call_task(task, args).ok()
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
            let proxy_target: Option<String> = if body.len() == 1 {
                if let NodeKind::ProxyStatement { target } = &body[0].kind {
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
                    if let Err(v) = check.require(
                        &Capability::new(CapabilityType::Net, Some(host.clone())),
                        &format!("proxy to \"{}\" (route \"{} {}\")", url, method, path),
                    ) {
                        return Err(Control::Error(RuntimeError::new(v.message)));
                    }
                    Some(url)
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
                rate_limit: eff_rate,
                rate_zone: zone,
                handler,
                stream_handler,
                socket_handler,
                timeout: route_timeout,
                proxy_target,
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
                    Some(SynValue::List(l)) => l.borrow().clone(),
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
                            validate_route_templates(&t.body)?;
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
                    SynValue::Map(m) => m.borrow().clone(),
                    _ => continue,
                };
                let method = mm.get("method").map(|v| v.to_string()).unwrap_or_default();
                let rpath = mm.get("path").map(|v| v.to_string()).unwrap_or_default();
                let requires_auth = matches!(mm.get("requires_auth"), Some(SynValue::Bool(true)));
                let params: Vec<String> = match mm.get("params") {
                    Some(SynValue::List(l)) => l.borrow().iter().map(|x| x.to_string()).collect(),
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
                let (eff_rate, zone) = match block_limit {
                    Some(bl) => (Some(bl), Some("__default__".to_string())),
                    None => (None, None),
                };
                let source_c = source.as_ref().clone();
                let key = format!("_route_handler_{}", i);
                // El cuerpo de una ruta montada vive en su handler-task (cierra sobre el
                // env del módulo): de ahí salen expect/respuesta/capabilities.
                let meta = match &group {
                    SynValue::Map(m) => match m.borrow().get(&key) {
                        Some(SynValue::Task(t)) => synsema_core::route_meta::route_meta(
                            &t.body,
                            false,
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
                let handler: Handler = Arc::new(move |ctx: &Ctx| {
                    run_mounted_route(
                        &swarm_c, &snap_c, &caps_c, &db_c, &rules_c, &mem_c, &ow_c, &prog_c,
                        &owp_c, &st_c, &ap_c, &cron_c, &source_c, &key, ctx, secure, &mn_c,
                    )
                });
                routes.push(RouteSpec {
                    method,
                    path: full_path,
                    param_names: params,
                    requires_auth,
                    streaming: false,
                    socket: false,
                    rate_limit: eff_rate,
                    rate_zone: zone,
                    handler,
                    stream_handler: None,
                    socket_handler: None,
                    timeout: None,
                    proxy_target: None,
                    rate_unlimited: false,
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
    mem_name: &Option<String>,
) -> GiveOutcome {
    with_serve_interp(swarm, snapshot, caps_snap, shared_db, rules_snap, shared_memory, on_write, shared_progress, on_write_progress, shared_state, approvals, cron, secure, mem_name, |interp| {
        let (identity, limits) = match &ctx.user {
            Some(u) => (server::identity_of(u), server::delegated_spend_of(u)),
            None => (None, Vec::new()),
        };
        interp.set_request_identity(identity, limits);
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
            Err(Control::Give(v)) => GiveOutcome::Give(Some(v)),
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
    mem_name: Option<String>,
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
            routes_n,
            tls_cert_n,
            tls_key_n,
            redirect_https,
            tls_auto,
            tls_auto_email_n,
            domain_n,
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
                routes,
                tls_cert,
                tls_key,
                redirect_https,
                tls_auto,
                tls_auto_email,
                domain,
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
                routes,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                *redirect_https,
                *tls_auto,
                tls_auto_email.as_deref(),
                domain.as_deref(),
                bind.as_deref(),
                hosts,
                mounts,
            ),
            _ => return Err(Control::Error(RuntimeError::new("internal: serve_hook on non-serve node"))),
        };
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
                            SynValue::List(l) => l.borrow().iter().map(|x| x.to_string()).collect(),
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
                        with_serve_interp(&swarm_e, &snap_e, &caps_e, &db_e, &rules_e, &mem_e, &ow_e, &prog_e, &owp_e, &st_e, &ap_e, &cron_e, secure, &mn_e, |interp| {
                            let genv = interp.global_env.clone();
                            let task = match interp.eval(&err_node, &genv) {
                                Ok(t) => t,
                                Err(_) => return None,
                            };
                            let args =
                                vec![syn_int(status), syn_text(message), build_request_syn(ctx)];
                            match interp.call_task(task, args) {
                                Ok(SynValue::Nothing) => None,
                                Ok(v) => Some(v),
                                Err(e) => {
                                    // La task de errores falló: se loggea y el default
                                    // JSON responde — un bug acá jamás tumba el error path.
                                    if let Control::Error(re) = e {
                                        eprintln!("[serve] errors task failed: {}", re.message);
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
        runtime.domain = acme_domains.first().cloned();
        runtime.describe_version = describe_version;
        runtime.docs_enabled = !docs_off;
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
        let scheme = if use_tls { "HTTPS" } else { "HTTP" };
        println!("Serving {} on port {} ({} route(s))", scheme, port_str, n_routes);
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
    let shared_persistence: Option<Arc<Mutex<crate::persistence::StatePersistence>>> =
        declared.and_then(|d| d.persistence).map(|p| Arc::new(Mutex::new(p)));
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
    let top_mem_ctx: Option<crate::engine::MemoryCtx> = mem_name.as_ref().map(|n| crate::engine::MemoryCtx {
        name: n.clone(),
        memory: shared_memory.clone(),
        progress: shared_progress.clone(),
        on_write_mem: persist_memory.clone(),
        on_write_prog: persist_progress.clone(),
    });
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
    // Sobrescribir los builtins de memoria/progress en el top-level con los compartidos,
    // para que `remember`/`create_progress` en el top-level también persistan a disco y
    // sean coherentes con lo que ven los handlers.
    register_serve_memory_builtins(&interp, shared_memory.clone(), persist_memory.clone(), top_gate.clone());
    register_serve_progress_builtins(&interp, shared_progress.clone(), persist_progress.clone(), top_gate);

    let swarm = Arc::new(Swarm::new());
    // Techo del host (--sandbox/--cap-set) aún no se extiende a `serve` (extensión posterior).
    wire_swarm_hooks(&mut interp, swarm.clone(), "main", serve_ceiling(), top_mem_ctx, None);
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
    if let Err(Control::Error(e)) = &r {
        return RunResult {
            success: false,
            output: interp.output.clone(),
            errors: vec![format!("Runtime error: {}", e)],
        };
    }

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
                snapshot: snapshot_globals(&interp),
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
            return RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new() };
        }
        // Sin server ni jobs: resultado normal (un programa serve sin bloque serve válido).
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
    set_serve_ceiling(overrides.ceiling.clone());
    // Desde acá `shutdown()` tiene sentido (bajo `run` es un error claro).
    synsema_stdlib::server::mark_under_serve();
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

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_stdlib::secrets::EnvStore;

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
