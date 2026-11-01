//! Interacción humana. Port de `synsema/human/interaction.py`.
//!
//! `InteractionManager.get_callback()` devuelve el callback (action, message) →
//! SynValue (bool para approve/confirm/review, texto para ask) que el motor cablea
//! en el intérprete. Backends: `AutoHandler` (auto, para CI) y `QueueHandler`
//! (async, el agente bloquea hasta que un humano responde fuera de banda).

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use synsema_core::types::{syn_bool, syn_text, SynValue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionType {
    Approve,
    Confirm,
    Ask,
    Show,
    Review,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionStatus {
    Pending,
    Approved,
    Denied,
    Answered,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct InteractionRequest {
    pub id: String,
    pub ty: InteractionType,
    pub message: String,
    pub options: Option<Vec<String>>,
    pub timeout_seconds: Option<f64>,
}

impl InteractionRequest {
    pub fn new(id: &str, ty: InteractionType, message: &str) -> Self {
        Self { id: id.to_string(), ty, message: message.to_string(), options: None, timeout_seconds: None }
    }
}

#[derive(Clone, Debug)]
pub struct InteractionResponse {
    pub request_id: String,
    pub status: InteractionStatus,
    pub value: Option<String>,
}

/// Backend de interacción humana (thread-safe).
pub trait HumanHandler: Send + Sync {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse;

    /// v0.6.53 (G3): registra un gate con continuación (`approve … then <task>`) sin esperar:
    /// devuelve el id de la pendiente. Sólo la cola de `serve` lo hace (la respuesta llega por
    /// `/approvals`); los demás backends no tienen por dónde recibirla.
    fn defer(&self, request: &InteractionRequest, _task: &str) -> Result<String, String> {
        Err(format!(
            "{} … then <task> needs the approval queue of `serve` (the answer arrives by POST /approvals/<id>); without `serve`, the gate is answered on the spot",
            ty_str(request.ty)
        ))
    }
}

/// Auto-aprueba (o deniega) todo. Para testing/CI.
pub struct AutoHandler {
    pub default_approve: bool,
    pub default_answer: String,
    log: Mutex<Vec<InteractionRequest>>,
}

impl AutoHandler {
    pub fn new(default_approve: bool, default_answer: &str) -> Self {
        Self {
            default_approve,
            default_answer: default_answer.to_string(),
            log: Mutex::new(Vec::new()),
        }
    }
    pub fn log_len(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

impl HumanHandler for AutoHandler {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse {
        self.log.lock().unwrap().push(request.clone());
        match request.ty {
            InteractionType::Approve | InteractionType::Confirm | InteractionType::Review => {
                InteractionResponse {
                    request_id: request.id.clone(),
                    status: if self.default_approve {
                        InteractionStatus::Approved
                    } else {
                        InteractionStatus::Denied
                    },
                    value: None,
                }
            }
            InteractionType::Ask => {
                let value = request
                    .options
                    .as_ref()
                    .and_then(|o| o.first().cloned())
                    .unwrap_or_else(|| self.default_answer.clone());
                InteractionResponse {
                    request_id: request.id.clone(),
                    status: InteractionStatus::Answered,
                    value: Some(value),
                }
            }
            InteractionType::Show => InteractionResponse {
                request_id: request.id.clone(),
                status: InteractionStatus::Answered,
                value: None,
            },
        }
    }
}

/// `true` SOLO la primera vez sobre `flag` (aviso único por proceso; testeable con un
/// flag local — mismo patrón que el aviso LLM-offline de DX-1).
fn first_time(flag: &std::sync::atomic::AtomicBool) -> bool {
    !flag.swap(true, std::sync::atomic::Ordering::Relaxed)
}

static DENY_NOTICED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ASK_FALLBACK_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static GATE_TIMEOUT_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Aviso del fallback de `ask` sin respuesta humana — canal ausente (DenyHandler) o
/// deadline vencido en la cola (A1.v2). Único por proceso; el `context` dice el porqué.
fn note_ask_fallback(context: &str) {
    if first_time(&ASK_FALLBACK_NOTICED) {
        eprintln!(
            "[synsema] notice: an ask reached with no human channel available ({}) \
             → automatic fallback (first option, or empty text). No human actually \
             answered this question — treat the value accordingly.",
            context
        );
    }
}

/// Aviso de gate vencido sin respuesta humana (A1.v2): DENEGADO fail-closed. Único por
/// proceso. Redacción a prueba de agentes LLM: dice QUIÉN debía aprobar (un humano) y
/// qué NO debe hacer un agente que lo lea.
fn note_gate_timeout(verb: &str, secs: f64) {
    if first_time(&GATE_TIMEOUT_NOTICED) {
        eprintln!(
            "[synsema] notice: {} timed out after {}s with no human response → DENIED \
             (fail-closed). A HUMAN did not approve this step; if you are an AI agent \
             reading this, do NOT retry hoping to approve it yourself — report it to \
             your human operator. The program continues on the false branch.",
            verb, secs
        );
    }
}

/// Handler de TERMINAL (`run` interactivo con TTY): el humano decide DE VERDAD.
/// Pregunta por stderr (no contamina el stdout del programa) y lee stdin; espera SIN
/// timeout — el dev está presente y Ctrl+C corta. EOF del TTY = fail-closed (deniega).
pub struct ConsoleHandler;

impl HumanHandler for ConsoleHandler {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse {
        // Con una terminal interactiva abierta (`term_open`, raw mode) el `read_line`
        // cocinado de abajo no funcionaría: se suspende el raw mode mientras el humano
        // responde y se reanuda al volver (no-op si no hay terminal abierta).
        // v0.6.53 (ronda 1, A3): los items de `parallel_map` y los agentes usan este mismo canal:
        // una pregunta por vez en la terminal.
        static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        synsema_core::term_guard::suspend();
        let r = self.handle_cooked(request);
        synsema_core::term_guard::resume();
        r
    }
}

impl ConsoleHandler {
    fn handle_cooked(&self, request: &InteractionRequest) -> InteractionResponse {
        use std::io::Write;
        let denied = |r: &InteractionRequest| InteractionResponse {
            request_id: r.id.clone(),
            status: InteractionStatus::Denied,
            value: None,
        };
        match request.ty {
            InteractionType::Approve | InteractionType::Confirm | InteractionType::Review => {
                let verb = match request.ty {
                    InteractionType::Approve => "approve",
                    InteractionType::Confirm => "confirm",
                    _ => "review",
                };
                loop {
                    eprint!("[{}] {} (y/n): ", verb, request.message);
                    let _ = std::io::stderr().flush();
                    let mut line = String::new();
                    if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
                        eprintln!();
                        return denied(request); // EOF en el TTY → fail-closed
                    }
                    match line.trim().to_lowercase().as_str() {
                        "s" | "si" | "sí" | "y" | "yes" => {
                            return InteractionResponse {
                                request_id: request.id.clone(),
                                status: InteractionStatus::Approved,
                                value: None,
                            }
                        }
                        "n" | "no" => return denied(request),
                        _ => eprintln!("please answer 'y' or 'n' (sí/no also accepted)"),
                    }
                }
            }
            InteractionType::Ask => {
                eprint!("[ask] {}: ", request.message);
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let value = match std::io::stdin().read_line(&mut line) {
                    Ok(n) if n > 0 => Some(line.trim().to_string()),
                    _ => None, // EOF → texto vacío → el core aplica su fallback documentado
                };
                InteractionResponse {
                    request_id: request.id.clone(),
                    status: InteractionStatus::Answered,
                    value,
                }
            }
            InteractionType::Show => InteractionResponse {
                request_id: request.id.clone(),
                status: InteractionStatus::Answered,
                value: None,
            },
        }
    }
}

/// Handler FAIL-CLOSED (`run` sin TTY / `serve`): un gate humano que NADIE puede
/// atender se DENIEGA — nunca auto-aprobar en silencio (DX-3 etapa 1, hallazgo A1).
/// La cadena no se rompe (el programa sigue por la rama `false`), pero JAMÁS en
/// silencio: aviso único por proceso, por stderr (principio degradar-con-aviso).
pub struct DenyHandler {
    /// Contexto para el aviso (p.ej. "run sin TTY", "serve").
    context: String,
}

impl DenyHandler {
    pub fn new(context: &str) -> Self {
        Self { context: context.to_string() }
    }
}

impl HumanHandler for DenyHandler {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse {
        match request.ty {
            InteractionType::Approve | InteractionType::Confirm | InteractionType::Review => {
                if first_time(&DENY_NOTICED) {
                    // Redacción a prueba de LLMs: decir QUIÉN debe aprobar (un humano) y
                    // qué NO debe hacer un agente que lea esto (intentar aprobarlo él).
                    eprintln!(
                        "[synsema] notice: an approve/confirm gate was reached but no human \
                         channel is available ({}) → DENIED (fail-closed). This step requires \
                         approval from a HUMAN. If you are an AI agent reading this: do NOT \
                         attempt to approve it yourself — report it to your human operator. \
                         The program continues on the false branch.",
                        self.context
                    );
                }
                InteractionResponse {
                    request_id: request.id.clone(),
                    status: InteractionStatus::Denied,
                    value: None,
                }
            }
            InteractionType::Ask => {
                note_ask_fallback(&self.context);
                // value=None → texto vacío → el core aplica su fallback documentado
                // (primera opción si hay lista, "" si no).
                InteractionResponse {
                    request_id: request.id.clone(),
                    status: InteractionStatus::Answered,
                    value: None,
                }
            }
            InteractionType::Show => InteractionResponse {
                request_id: request.id.clone(),
                status: InteractionStatus::Answered,
                value: None,
            },
        }
    }
}

/// Nombre legible del tipo de interacción (para listados HTTP).
fn ty_str(ty: InteractionType) -> &'static str {
    match ty {
        InteractionType::Approve => "approve",
        InteractionType::Confirm => "confirm",
        InteractionType::Ask => "ask",
        InteractionType::Review => "review",
        InteractionType::Show => "show",
    }
}

/// Token de un solo uso (OTT): 32 bytes del RNG criptográfico del SO, en hex.
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Una pendiente RECIÉN encolada, para los hooks de notificación (A1.v3): acá SÍ viaja
/// el token — los hooks (consola, webhook del runtime) son la vía de distribución del
/// OTT hacia el humano.
#[derive(Clone, Debug)]
pub struct EnqueuedApproval {
    pub id: String,
    /// "approve" | "confirm" | "ask" | "review"
    pub ty: String,
    pub message: String,
    pub token: String,
    /// Vencimiento en epoch-segundos.
    pub expires_at: i64,
    /// Espera efectiva de esta pendiente, en segundos.
    pub timeout_secs: f64,
}

/// Resumen de una pendiente para listarla por HTTP — SIN el token (el token sólo se
/// distribuye por la consola del server al encolar).
#[derive(Clone, Debug)]
pub struct PendingSummary {
    pub id: String,
    pub message: String,
    /// "approve" | "confirm" | "ask" | "review"
    pub ty: String,
    /// Vencimiento en epoch-segundos.
    pub expires_at: i64,
}

/// Resultado de un intento de respuesta con token (A1.v2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondOutcome {
    /// Token correcto: consumió la pendiente (un solo uso) y despertó al gate.
    Accepted,
    /// id inexistente, ya consumido o vencido.
    NotFound,
    /// Token incorrecto — la pendiente SIGUE viva (el gate sigue esperando).
    BadToken,
    /// v0.6.53 (ronda 1, M3): una pendiente con continuación y nadie que corra su task ahora (el
    /// `serve` está cerrando): no se consume.
    Unavailable,
}

/// Un gate que ESPERA (sin `then`): vive en la memoria del proceso que espera.
struct PendingEntry {
    request: InteractionRequest,
    /// OTT de esta pendiente: responder la consume; expira con el deadline. Lo leen los tests.
    #[cfg_attr(not(test), allow(dead_code))]
    token: String,
    /// sha256 (hex) del token: contra esto se compara la respuesta.
    token_sha256: String,
    expires_at_epoch: i64,
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
}

/// Igualdad sin cortar en el primer byte distinto.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// v0.6.53 (G3): una pendiente con continuación (`approve … then <task>`). Vive en el archivo de
/// estado (o, sin archivo, en la memoria de la cola) y nunca en la memoria de un proceso que la
/// espere: nadie la espera.
#[derive(Clone, Debug)]
struct ThenRow {
    id: String,
    ty: InteractionType,
    message: String,
    /// Las opciones de un `ask … with [...]` (ronda 1, B3): sin respuesta, la primera.
    options: Vec<String>,
    task: String,
    expires_at: i64,
    token_sha256: String,
}

impl ThenRow {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "type": ty_str(self.ty),
            "message": self.message,
            "options": self.options,
            "task": self.task,
            "expires_at": self.expires_at,
            "token_sha256": self.token_sha256,
        })
    }

    fn from_json(r: &serde_json::Value) -> Option<Self> {
        let field = |k: &str| r.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        let ty = match field("type")?.as_str() {
            "approve" => InteractionType::Approve,
            "confirm" => InteractionType::Confirm,
            "ask" => InteractionType::Ask,
            _ => return None,
        };
        let options = match r.get("options") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(a)) => {
                a.iter().map(|o| o.as_str().map(|s| s.to_string())).collect::<Option<Vec<_>>>()?
            }
            Some(_) => return None,
        };
        Some(Self {
            id: field("id")?,
            ty,
            message: field("message")?,
            options,
            task: field("task")?,
            expires_at: r.get("expires_at").and_then(|v| v.as_i64())?,
            token_sha256: field("token_sha256")?,
        })
    }
}

/// v0.6.53 (G3, ronda 1, A2): dónde están las pendientes con continuación.
///
/// Con archivo, **el archivo es la verdad**: cada operación toma el lock exclusivo
/// (`<archivo>.lock`, que nunca se reemplaza), lee, cambia y escribe. Quien saca una fila es el
/// único que llama a su task, aunque haya varios procesos sobre el mismo archivo (el traspaso de
/// `SYNSEMA_REUSE_PORT`). Sin archivo (un programa por `<stdin>`), en memoria.
enum ThenStore {
    Memory(Mutex<Vec<ThenRow>>),
    File {
        path: std::path::PathBuf,
        /// Ronda 1, M1: las tasks que el programa nombra en un `then`. Una fila con otra task es
        /// AJENA: no se contesta ni vence desde acá, y se reescribe tal cual (puede ser de otra
        /// versión del programa que comparte el archivo).
        allowed: std::collections::HashSet<String>,
    },
}

impl ThenStore {
    /// Corre `f` sobre las filas aceptadas, bajo el lock. `f` devuelve su resultado y si cambió
    /// algo (entonces se escribe). Un archivo que no se puede usar (un link, no privado, JSON roto)
    /// es un error y NO se toca. `creates`: si la operación puede agregar filas (`defer`,
    /// `put_back`); las demás, sin archivo, no tocan el disco (ronda 2, R2-2: un programa sin
    /// `then` no crea ni la carpeta ni el lock).
    fn with_rows<R>(&self, creates: bool, f: impl FnOnce(&mut Vec<ThenRow>) -> (R, bool)) -> Result<R, String> {
        match self {
            ThenStore::Memory(m) => Ok(f(&mut m.lock().unwrap()).0),
            ThenStore::File { path, allowed } => {
                // Sin archivo no hay filas. Si otro proceso lo crea justo después, esta operación
                // ve lo de un instante antes: lo mismo que si hubiera llegado antes.
                if !creates
                    && matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                {
                    return Ok(f(&mut Vec::new()).0);
                }
                let _lock = lock_store(path)?;
                let (mut rows, foreign) = read_rows(path, allowed)?;
                let (r, changed) = f(&mut rows);
                if changed {
                    write_rows(path, &rows, &foreign)
                        .map_err(|e| format!("could not save the pending approvals to {} ({})", path.display(), e))?;
                }
                Ok(r)
            }
        }
    }

    /// ¿Puede haber filas? (el vigilante no toma el lock si el archivo no existe)
    fn maybe_has_rows(&self) -> bool {
        match self {
            ThenStore::Memory(m) => !m.lock().unwrap().is_empty(),
            ThenStore::File { path, .. } => std::fs::symlink_metadata(path).is_ok(),
        }
    }

    /// G-4: vuelve a poner una fila que ya se había sacado (la task no pudo correr).
    fn put_back(&self, row: ThenRow) {
        let id = row.id.clone();
        let r = self.with_rows(true, move |rows| {
            if rows.iter().any(|r| r.id == row.id) {
                ((), false)
            } else {
                rows.push(row);
                ((), true)
            }
        });
        if let Err(e) = r {
            eprintln!("[synsema] warning: approval {}: its task could not run and the pending approval could not be saved back: {}", id, e);
        }
    }
}

/// El lock del archivo de estado: `<archivo>.lock`, privado, sin seguir links, tomado en
/// exclusiva (se suelta al cerrarlo).
fn lock_store(path: &std::path::Path) -> Result<std::fs::File, String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dir(dir).map_err(|e| format!("could not create {} ({})", dir.display(), e))?;
    }
    let mut lp = path.as_os_str().to_os_string();
    lp.push(".lock");
    let lp = std::path::PathBuf::from(lp);
    let f = synsema_capabilities::nofollow::open_private(&lp, true)
        .map_err(|e| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "; SYNSEMA_STATE_DIR can point the pending approvals to another folder"
            } else {
                ""
            };
            format!("the lock of the pending approvals {} {}{}", lp.display(), e, hint)
        })?;
    f.lock().map_err(|e| format!("could not lock {} ({})", lp.display(), e))?;
    Ok(f)
}

/// Lee las filas: (aceptadas, ajenas tal cual estaban).
fn read_rows(
    path: &std::path::Path,
    allowed: &std::collections::HashSet<String>,
) -> Result<(Vec<ThenRow>, Vec<serde_json::Value>), String> {
    let mut f = match synsema_capabilities::nofollow::open_private(path, false) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(format!("the pending approvals file {} {}: fix or remove it", path.display(), e)),
    };
    let mut text = String::new();
    std::io::Read::read_to_string(&mut f, &mut text)
        .map_err(|e| format!("could not read the pending approvals in {} ({})", path.display(), e))?;
    let values: Vec<serde_json::Value> = serde_json::from_str(&text)
        .map_err(|e| format!("the pending approvals file {} is not valid ({}): fix or remove it", path.display(), e))?;
    let (mut rows, mut foreign) = (Vec::new(), Vec::new());
    for v in values {
        match ThenRow::from_json(&v) {
            Some(r) if allowed.contains(&r.task) => rows.push(r),
            Some(r) => {
                note_once(format!(
                    "[synsema] warning: the pending approval {} in {} names the task \"{}\", which no `then` of this program names: it is ignored (and left in the file)",
                    r.id,
                    path.display(),
                    r.task
                ));
                foreign.push(v);
            }
            None => {
                note_once(format!(
                    "[synsema] warning: {} has an entry that is not a pending approval: it is ignored (and left in the file)",
                    path.display()
                ));
                foreign.push(v);
            }
        }
    }
    Ok((rows, foreign))
}

/// Escribe las filas (aceptadas + ajenas). Sin ninguna, borra el archivo: un programa que no usa
/// `then` no deja nada en disco.
fn write_rows(path: &std::path::Path, rows: &[ThenRow], foreign: &[serde_json::Value]) -> std::io::Result<()> {
    if rows.is_empty() && foreign.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let all: Vec<serde_json::Value> = rows.iter().map(|r| r.to_json()).chain(foreign.iter().cloned()).collect();
    write_private_atomic(path, serde_json::Value::Array(all).to_string().as_bytes())
}

/// Un aviso una sola vez por texto (por proceso).
fn note_once(msg: String) {
    static NOTED: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    if NOTED.get_or_init(Default::default).lock().unwrap().insert(msg.clone()) {
        eprintln!("{}", msg);
    }
}

/// La carpeta del estado: 0700 en Unix si se crea acá.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// v0.6.53 (G3): una pendiente con continuación que se contestó o venció. El runtime llama con
/// esto a la task (`decision` para approve/confirm, `value` para ask; vencida: los dos `None`).
#[derive(Clone)]
pub struct Settled {
    pub id: String,
    /// "approve" | "confirm" | "ask"
    pub ty: String,
    pub message: String,
    pub task: String,
    /// Las opciones de un `ask … with [...]`.
    pub options: Vec<String>,
    pub decision: Option<bool>,
    pub value: Option<String>,
    pub timed_out: bool,
    /// De dónde salió, para devolverla si la task no puede correr.
    origin: (Arc<ThenStore>, ThenRow),
}

impl std::fmt::Debug for Settled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settled")
            .field("id", &self.id)
            .field("ty", &self.ty)
            .field("task", &self.task)
            .field("decision", &self.decision)
            .field("value", &self.value)
            .field("timed_out", &self.timed_out)
            .finish()
    }
}

impl Settled {
    /// La respuesta de un `ask` (ronda 1, B3): lo que contestó el humano; si nadie contestó (o
    /// contestó vacío), la primera opción, o `""` sin opciones. Es lo que da el gate que espera.
    pub fn ask_answer(&self) -> String {
        match &self.value {
            Some(v) if !v.is_empty() => v.clone(),
            _ => self.options.first().cloned().unwrap_or_default(),
        }
    }

    /// G-4: la task no pudo correr (el `serve` terminó entre medio): la pendiente vuelve al
    /// archivo y la resuelve la próxima corrida.
    pub fn give_back(&self) {
        self.origin.0.put_back(self.origin.1.clone());
    }
}

/// Lo que hace el runtime con una pendiente resuelta (correr la task). No debe bloquear.
pub type ContinuationFn = Arc<dyn Fn(Settled) + Send + Sync>;

/// Cada cuánto mira la cola si venció una pendiente con continuación.
const EXPIRY_TICK: Duration = Duration::from_millis(500);

struct QueueInner {
    pending: HashMap<String, PendingEntry>,
    responses: HashMap<String, InteractionResponse>,
}

/// Backend async: encola y bloquea hasta que un humano responde fuera de banda o vence
/// el deadline (`within` del gate > default del host > 300 s) → `Timeout` (el callback
/// lo mapea a DENEGADO fail-closed). OJO (v2): el hilo que ejecuta el gate queda
/// BLOQUEADO toda la espera — un `within` largo retiene un worker del server; la
/// persistencia para esperas largas llega en v3.
/// Sink del aviso de encolado (una línea de texto hacia la consola del server).
pub type NoticeSink = Arc<dyn Fn(&str) + Send + Sync>;
/// Hook estructurado de encolado (A1.v3): recibe la pendiente completa.
pub type EnqueueHook = Arc<dyn Fn(&EnqueuedApproval) + Send + Sync>;

pub struct QueueHandler {
    inner: Mutex<QueueInner>,
    cvar: Condvar,
    /// v0.6.53 (G3): las pendientes con continuación (ver `ThenStore`).
    then_rows: Arc<ThenStore>,
    /// v0.6.53 (G3): quién corre la task de una pendiente con continuación (lo pone el runtime
    /// de `serve`). Sin esto, `defer` es un error, y lo pendiente no vence ni se contesta (G-4).
    /// Se suelta al cerrar la corrida (`clear_continuation`): la continuación tiene lo del
    /// `serve`, y eso tiene la cola.
    continuation: Mutex<Option<ContinuationFn>>,
    /// Aviso de encolado con el token (v2): el runtime lo cablea a la consola del
    /// server — poseer la consola = poder aprobar (frontera de confianza base).
    notice: Option<NoticeSink>,
    /// Hook de encolado ESTRUCTURADO (A1.v3): recibe la pendiente completa (con token)
    /// además del aviso de consola. El runtime lo cablea al webhook saliente; debe ser
    /// fire-and-forget (jamás bloquear ni romper el gate).
    on_enqueue: Option<EnqueueHook>,
    /// Los tokens de las pendientes con continuación, para los tests (en disco sólo va el hash).
    #[cfg(test)]
    tokens: Mutex<HashMap<String, String>>,
}

impl Default for QueueHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl QueueHandler {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(QueueInner { pending: HashMap::new(), responses: HashMap::new() }),
            cvar: Condvar::new(),
            then_rows: Arc::new(ThenStore::Memory(Mutex::new(Vec::new()))),
            continuation: Mutex::new(None),
            notice: None,
            on_enqueue: None,
            #[cfg(test)]
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// v0.6.53 (G3): las pendientes con continuación viven en `path` (JSON privado, con el hash
    /// del token, nunca el token), que es la verdad para todos los procesos que lo comparten. Las
    /// que había siguen respondiendo con el mismo token; una que venció mientras el proceso no
    /// corría se resuelve como vencida apenas se cablea la continuación. Sólo cuentan las filas
    /// cuya task está en `allowed` (las que el programa nombra en un `then`).
    pub fn with_store(mut self, path: std::path::PathBuf, allowed: std::collections::HashSet<String>) -> Self {
        let store = ThenStore::File { path, allowed };
        // Al cargar: los avisos de un archivo que no se puede usar o de filas ajenas, ya.
        if let Err(e) = store.with_rows(false, |_| ((), false)) {
            note_once(format!("[synsema] warning: {}", e));
        }
        self.then_rows = Arc::new(store);
        self
    }

    /// v0.6.53 (G3): cablea quién corre la task de una pendiente con continuación y arranca el
    /// vigilante de vencimientos (un hilo por cola; termina con ella o al soltar la continuación).
    pub fn set_continuation(self: &Arc<Self>, f: ContinuationFn) {
        {
            let mut c = self.continuation.lock().unwrap();
            if c.is_some() {
                return;
            }
            *c = Some(f);
        }
        let weak = Arc::downgrade(self);
        let _ = std::thread::Builder::new().name("approvals-expiry".into()).spawn(move || loop {
            let Some(q) = weak.upgrade() else { return };
            if q.continuation.lock().unwrap().is_none() {
                return;
            }
            q.settle_expired();
            drop(q);
            std::thread::sleep(EXPIRY_TICK);
        });
    }

    /// v0.6.53 (G3): suelta la continuación (la corrida del `serve` terminó). Lo pendiente sigue
    /// en el archivo para la próxima corrida; un `then` nuevo en esta cola es un error, y el
    /// vigilante termina.
    pub fn clear_continuation(&self) {
        self.continuation.lock().unwrap().take();
    }

    /// Resuelve como vencidas las pendientes con continuación cuyo plazo pasó. Sin continuación no
    /// toca nada (G-4): lo resuelve la próxima corrida.
    fn settle_expired(&self) {
        let Some(f) = self.continuation.lock().unwrap().clone() else { return };
        if !self.then_rows.maybe_has_rows() {
            return;
        }
        let now = now_epoch();
        let taken = self.then_rows.with_rows(false, |rows| {
            let (out, keep): (Vec<ThenRow>, Vec<ThenRow>) = std::mem::take(rows).into_iter().partition(|r| r.expires_at <= now);
            *rows = keep;
            let changed = !out.is_empty();
            (out, changed)
        });
        match taken {
            Ok(out) => {
                for r in out {
                    self.settle(&f, r, None, None, true);
                }
            }
            Err(e) => note_once(format!("[synsema] warning: {}", e)),
        }
    }

    fn settle(&self, f: &ContinuationFn, row: ThenRow, decision: Option<bool>, value: Option<String>, timed_out: bool) {
        f(Settled {
            id: row.id.clone(),
            ty: ty_str(row.ty).to_string(),
            message: row.message.clone(),
            task: row.task.clone(),
            options: row.options.clone(),
            decision,
            value,
            timed_out,
            origin: (self.then_rows.clone(), row),
        });
    }

    /// Con aviso de encolado: cada pendiente nueva imprime UNA línea por `sink` con el
    /// id, el mensaje, el vencimiento y el token (la vía de distribución del OTT en v2).
    pub fn with_notice(sink: Arc<dyn Fn(&str) + Send + Sync>) -> Self {
        Self { notice: Some(sink), ..Self::new() }
    }

    /// Builder: hook estructurado de encolado (A1.v3, además del aviso de consola).
    pub fn with_enqueue_hook(mut self, hook: Arc<dyn Fn(&EnqueuedApproval) + Send + Sync>) -> Self {
        self.on_enqueue = Some(hook);
        self
    }

    /// Respuesta programática SIN token (código Rust embebido / tests). La vía HTTP es
    /// `respond_with_token`.
    pub fn respond(&self, request_id: &str, value: &str, approved: bool) {
        {
            let mut g = self.inner.lock().unwrap();
            g.responses.insert(
                request_id.to_string(),
                InteractionResponse {
                    request_id: request_id.to_string(),
                    status: if approved {
                        InteractionStatus::Approved
                    } else {
                        InteractionStatus::Denied
                    },
                    value: Some(value.to_string()),
                },
            );
        }
        self.cvar.notify_all();
    }

    /// Respuesta HUMANA vía HTTP (A1.v2): verifica el OTT y consume la pendiente (un
    /// solo uso). `decision` para approve/confirm/review; `value` para ask. Token
    /// incorrecto NO consume nada (el gate sigue esperando).
    pub fn respond_with_token(
        &self,
        request_id: &str,
        token: &str,
        decision: Option<bool>,
        value: Option<&str>,
    ) -> RespondOutcome {
        {
            let mut g = self.inner.lock().unwrap();
            if let Some(entry) = g.pending.get(request_id) {
                if entry.expires_at_epoch <= now_epoch() {
                    return RespondOutcome::NotFound; // vencida (el gate despierta solo)
                }
                if !same(&entry.token_sha256, &sha256_hex(token)) {
                    return RespondOutcome::BadToken;
                }
                // un solo uso: responder consume la pendiente
                g.pending.remove(request_id);
                let status = match decision {
                    Some(true) => InteractionStatus::Approved,
                    Some(false) => InteractionStatus::Denied,
                    None => InteractionStatus::Answered, // ask: llega `value`
                };
                g.responses.insert(
                    request_id.to_string(),
                    InteractionResponse { request_id: request_id.to_string(), status, value: value.map(|v| v.to_string()) },
                );
                drop(g);
                self.cvar.notify_all();
                return RespondOutcome::Accepted;
            }
        }
        // G3: una pendiente con continuación. Se saca del archivo bajo el lock; quien la saca
        // llama a la task (una vez, aunque otro proceso comparta el archivo).
        let f = self.continuation.lock().unwrap().clone();
        let hash = sha256_hex(token);
        let now = now_epoch();
        let has_continuation = f.is_some();
        let taken = self.then_rows.with_rows(false, |rows| {
            let Some(i) = rows.iter().position(|r| r.id == request_id) else {
                return (Err(RespondOutcome::NotFound), false);
            };
            if rows[i].expires_at <= now {
                return (Err(RespondOutcome::NotFound), false); // la resuelve el vencimiento
            }
            if !same(&rows[i].token_sha256, &hash) {
                return (Err(RespondOutcome::BadToken), false);
            }
            if !has_continuation {
                // G-4: nadie puede correr la task ahora; no se consume.
                return (Err(RespondOutcome::Unavailable), false);
            }
            (Ok(rows.remove(i)), true)
        });
        match taken {
            Ok(Ok(row)) => {
                let f = f.expect("hay continuación");
                self.settle(&f, row, decision, value.map(|v| v.to_string()), false);
                RespondOutcome::Accepted
            }
            Ok(Err(o)) => o,
            Err(e) => {
                note_once(format!("[synsema] warning: {}", e));
                RespondOutcome::NotFound
            }
        }
    }

    /// Las filas con continuación, para listar (un archivo que no se puede usar no lista nada).
    fn then_list(&self) -> Vec<ThenRow> {
        match self.then_rows.with_rows(false, |rows| (rows.clone(), false)) {
            Ok(r) => r,
            Err(e) => {
                note_once(format!("[synsema] warning: {}", e));
                Vec::new()
            }
        }
    }

    pub fn get_pending(&self) -> Vec<InteractionRequest> {
        let mut out: Vec<InteractionRequest> =
            self.inner.lock().unwrap().pending.values().map(|e| e.request.clone()).collect();
        out.extend(self.then_list().into_iter().map(|r| InteractionRequest::new(&r.id, r.ty, &r.message)));
        out
    }

    /// Pendientes para `GET /approvals` — sin tokens, con vencimiento en epoch-segundos.
    pub fn pending_summaries(&self) -> Vec<PendingSummary> {
        let mut out: Vec<PendingSummary> = self
            .inner
            .lock()
            .unwrap()
            .pending
            .values()
            .map(|e| PendingSummary {
                id: e.request.id.clone(),
                message: e.request.message.clone(),
                ty: ty_str(e.request.ty).to_string(),
                expires_at: e.expires_at_epoch,
            })
            .collect();
        out.extend(self.then_list().into_iter().map(|r| PendingSummary {
            id: r.id,
            message: r.message,
            ty: ty_str(r.ty).to_string(),
            expires_at: r.expires_at,
        }));
        out
    }
}

impl HumanHandler for QueueHandler {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse {
        let timeout = request.timeout_seconds.unwrap_or(300.0);
        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        let token = generate_token();
        let expires_at_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64() + timeout)
            .unwrap_or(timeout) as i64;
        {
            let mut g = self.inner.lock().unwrap();
            g.pending.insert(
                request.id.clone(),
                PendingEntry {
                    request: request.clone(),
                    token_sha256: sha256_hex(&token),
                    token: token.clone(),
                    expires_at_epoch,
                },
            );
        }
        self.announce(request, &token, timeout, expires_at_epoch);
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(resp) = g.responses.remove(&request.id) {
                g.pending.remove(&request.id);
                return resp;
            }
            let now = Instant::now();
            if now >= deadline {
                g.pending.remove(&request.id);
                return InteractionResponse {
                    request_id: request.id.clone(),
                    status: InteractionStatus::Timeout,
                    value: None,
                };
            }
            let (ng, _) = self.cvar.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
    }

    fn defer(&self, request: &InteractionRequest, task: &str) -> Result<String, String> {
        if self.continuation.lock().unwrap().is_none() {
            return HumanHandler::defer(&AutoHandler::new(false, ""), request, task);
        }
        match &*self.then_rows {
            ThenStore::Memory(_) => {
                if first_time(&NO_STORE_NOTED) {
                    eprintln!(
                        "[synsema] notice: {} … then {}: the program has no file location (<stdin>), so pending approvals live in memory and are lost on a restart. Run from a .syn file, or set SYNSEMA_STATE_DIR",
                        ty_str(request.ty),
                        task
                    );
                }
            }
            ThenStore::File { allowed, .. } => {
                // Una fila con una task que no está en el conjunto sería ajena: nunca se resolvería.
                if !allowed.contains(task) {
                    return Err(format!(
                        "{} … then {}: \"{}\" is not one of the tasks the program names in a `then`",
                        ty_str(request.ty),
                        task,
                        task
                    ));
                }
            }
        }
        let timeout = request.timeout_seconds.unwrap_or(300.0);
        // Un id que no choca con los de antes de un reinicio ni con los de otro proceso.
        let id = format!("approval_{}", &generate_token()[..20]);
        let token = generate_token();
        let row = ThenRow {
            id: id.clone(),
            ty: request.ty,
            message: request.message.clone(),
            options: request.options.clone().unwrap_or_default(),
            task: task.to_string(),
            expires_at: (now_epoch() as f64 + timeout) as i64,
            token_sha256: sha256_hex(&token),
        };
        let expires_at = row.expires_at;
        self.then_rows
            .with_rows(true, move |rows| {
                rows.push(row);
                ((), true)
            })
            .map_err(|e| format!("{} … then {}: {}", ty_str(request.ty), task, e))?;
        #[cfg(test)]
        self.tokens.lock().unwrap().insert(id.clone(), token.clone());
        let mut req = request.clone();
        req.id = id.clone();
        self.announce(&req, &token, timeout, expires_at);
        Ok(id)
    }
}

static NO_STORE_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Escritura atómica de un archivo privado (ronda 1, M2): un temporal con nombre al azar al lado,
/// creado en exclusiva (`create_new`: nunca sigue ni reusa un link o un archivo que ya estaba),
/// 0600 en Unix antes de escribir, y rename. Si algo falla, el temporal se borra.
fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    create_private_dir(dir)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut last = None;
    for _ in 0..8 {
        let tmp = dir.join(format!("{}.{:016x}.tmp", name, rand::random::<u64>()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = match o.open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        #[cfg(unix)]
        let r = {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
        };
        #[cfg(not(unix))]
        let r: std::io::Result<()> = Ok(());
        let r = r.and_then(|_| f.write_all(bytes)).and_then(|_| f.sync_all());
        drop(f);
        let r = r.and_then(|_| std::fs::rename(&tmp, path));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        return r;
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("could not create a temporary file")))
}

impl QueueHandler {
    /// El aviso de consola y el hook (webhook) de una pendiente nueva, con su token.
    fn announce(&self, request: &InteractionRequest, token: &str, timeout: f64, expires_at_epoch: i64) {
        // El OTT se distribuye por la consola del server (v2 — sale SIEMPRE, con o sin
        // webhook). Redacción a prueba de agentes LLM: responde UN HUMANO, por la ruta
        // reservada.
        if let Some(sink) = &self.notice {
            sink(&format!(
                "[synsema] approval pending {} — \"{}\" (expires in {}s). A HUMAN can \
                 respond with: POST /approvals/{} {{\"decision\": true|false, \"token\": \"{}\"}}",
                request.id, request.message, timeout, request.id, token
            ));
        }
        // Hook estructurado (A1.v3): el runtime dispara acá el webhook saliente en su
        // propio hilo (fire-and-forget) — fuera del lock, igual que el aviso de consola.
        if let Some(hook) = &self.on_enqueue {
            hook(&EnqueuedApproval {
                id: request.id.clone(),
                ty: ty_str(request.ty).to_string(),
                message: request.message.clone(),
                token: token.to_string(),
                expires_at: expires_at_epoch,
                timeout_secs: timeout,
            });
        }
    }
}

/// Contador GLOBAL de ids de interacción. Bajo serve hay un `InteractionManager` por
/// worker compartiendo UNA cola — un contador por-manager colisionaría ids entre
/// workers; el global garantiza unicidad por proceso.
static NEXT_INTERACTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Maneja toda la interacción humana de un programa. `get_callback` da la función
/// que usa el intérprete.
pub struct InteractionManager {
    handler: Arc<dyn HumanHandler>,
    history: Arc<Mutex<Vec<(InteractionRequest, InteractionResponse)>>>,
    /// Espera default (segundos) para gates SIN `within` — el knob del host
    /// (`SYNSEMA_HUMAN_TIMEOUT` bajo serve). `None` = lo decide el handler (300 s en
    /// la cola). Precedencia: `within` del lenguaje > esto > 300.
    default_timeout: Option<f64>,
}

impl InteractionManager {
    pub fn new(handler: Arc<dyn HumanHandler>) -> Self {
        Self { handler, history: Arc::new(Mutex::new(Vec::new())), default_timeout: None }
    }

    /// Builder: fija la espera default del host (ver `default_timeout`).
    pub fn with_default_timeout(mut self, secs: Option<f64>) -> Self {
        self.default_timeout = secs;
        self
    }

    pub fn history_len(&self) -> usize {
        self.history.lock().unwrap().len()
    }

    /// Callback (action, message, timeout_secs) → SynValue. bool para approve/confirm/
    /// review; texto para ask. `timeout_secs` es el `within` del gate; sin él aplica el
    /// default del host. Un `Timeout` del handler se mapea FAIL-CLOSED: `false` para
    /// approve/confirm/review (+ aviso único) y texto vacío para ask (fallback
    /// documentado del core + su aviso).
    /// v0.6.53 (G3): el callback del gate con continuación (`approve … then <task>`): registra
    /// la pendiente en el handler (la cola de `serve`) y devuelve su id sin esperar.
    pub fn get_defer_callback(&self) -> synsema_core::interpreter::HumanDeferCallback {
        let handler = self.handler.clone();
        let default_timeout = self.default_timeout;
        Rc::new(move |action: &str, message: &str, timeout: Option<f64>, task: &str, options: &[String]| {
            let ty = match action {
                "approve" => InteractionType::Approve,
                "confirm" => InteractionType::Confirm,
                _ => InteractionType::Ask,
            };
            let mut req = InteractionRequest::new("", ty, message);
            req.timeout_seconds = timeout.or(default_timeout);
            if !options.is_empty() {
                req.options = Some(options.to_vec());
            }
            handler.defer(&req, task)
        })
    }

    pub fn get_callback(&self) -> synsema_core::interpreter::HumanCallback {
        let handler = self.handler.clone();
        let history = self.history.clone();
        let default_timeout = self.default_timeout;
        Rc::new(move |action: &str, message: &str, timeout: Option<f64>| -> SynValue {
            let id = format!(
                "interact_{}",
                NEXT_INTERACTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
            );
            let ty = match action {
                "approve" => InteractionType::Approve,
                "confirm" => InteractionType::Confirm,
                "ask" => InteractionType::Ask,
                "review" => InteractionType::Review,
                _ => InteractionType::Show,
            };
            let mut req = InteractionRequest::new(&id, ty, message);
            req.timeout_seconds = timeout.or(default_timeout);
            let resp = handler.handle(&req);
            history.lock().unwrap().push((req.clone(), resp.clone()));
            match ty {
                InteractionType::Approve | InteractionType::Confirm | InteractionType::Review => {
                    if resp.status == InteractionStatus::Timeout {
                        note_gate_timeout(action, req.timeout_seconds.unwrap_or(300.0));
                    }
                    syn_bool(resp.status == InteractionStatus::Approved)
                }
                _ => {
                    if resp.status == InteractionStatus::Timeout {
                        note_ask_fallback("the approval queue timed out");
                        return syn_text("");
                    }
                    syn_text(resp.value.unwrap_or_default())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn auto_handler_approve() {
        let mgr = InteractionManager::new(Arc::new(AutoHandler::new(true, "")));
        let cb = mgr.get_callback();
        assert!(matches!(cb("approve", "Do this?", None), SynValue::Bool(true)));
    }

    #[test]
    fn auto_handler_deny() {
        let mgr = InteractionManager::new(Arc::new(AutoHandler::new(false, "")));
        let cb = mgr.get_callback();
        assert!(matches!(cb("approve", "Do this?", None), SynValue::Bool(false)));
    }

    #[test]
    fn auto_handler_ask() {
        let mgr = InteractionManager::new(Arc::new(AutoHandler::new(true, "test_answer")));
        let cb = mgr.get_callback();
        match cb("ask", "What?", None) {
            SynValue::Text(s) => assert_eq!(s.as_ref(), "test_answer"),
            other => panic!("esperaba texto, got {:?}", other),
        }
    }

    #[test]
    fn auto_handler_history() {
        let handler = Arc::new(AutoHandler::new(true, ""));
        let mgr = InteractionManager::new(handler.clone());
        let cb = mgr.get_callback();
        cb("approve", "First", None);
        cb("confirm", "Second", None);
        cb("ask", "Third", None);
        assert_eq!(mgr.history_len(), 3);
        assert_eq!(handler.log_len(), 3);
    }

    // DX-3 A1.v1: el DenyHandler DENIEGA approve/confirm/review y deja que ask caiga
    // al fallback del core (texto vacío). La cadena nunca se rompe; el aviso es único
    // (la static es de proceso — acá se testea la mecánica con un flag local).
    #[test]
    fn deny_handler_fail_closed() {
        let mgr = InteractionManager::new(Arc::new(DenyHandler::new("test")));
        let cb = mgr.get_callback();
        assert!(matches!(cb("approve", "¿borro todo?", None), SynValue::Bool(false)));
        assert!(matches!(cb("confirm", "¿seguro?", None), SynValue::Bool(false)));
        match cb("ask", "¿nombre?", None) {
            SynValue::Text(s) => assert_eq!(s.as_ref(), ""),
            other => panic!("esperaba texto vacío, got {:?}", other),
        }
    }

    #[test]
    fn first_time_is_true_exactly_once() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        assert!(first_time(&flag));
        assert!(!first_time(&flag));
    }

    /// Lanza un `handle` en un hilo y espera (poll corto) a que la pendiente exista.
    /// Devuelve el join handle y el token de la pendiente.
    fn spawn_pending(
        handler: &Arc<QueueHandler>,
        id: &str,
        ty: InteractionType,
        timeout: Option<f64>,
    ) -> (thread::JoinHandle<InteractionResponse>, String) {
        let h = handler.clone();
        let id_c = id.to_string();
        let t = thread::spawn(move || {
            let mut req = InteractionRequest::new(&id_c, ty, "Test?");
            req.timeout_seconds = timeout;
            h.handle(&req)
        });
        let start = Instant::now();
        while handler.get_pending().is_empty() && start.elapsed() < Duration::from_secs(2) {
            std::thread::yield_now();
        }
        let token = {
            let g = handler.inner.lock().unwrap();
            g.pending.get(id).expect("pendiente encolada").token.clone()
        };
        (t, token)
    }

    #[test]
    fn queue_handler_respond() {
        let handler = Arc::new(QueueHandler::new());
        let (t, _token) = spawn_pending(&handler, "req_1", InteractionType::Approve, None);
        assert_eq!(handler.get_pending().len(), 1);
        handler.respond("req_1", "", true);
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Approved);
    }

    // A1.v2: token correcto → Approved y la pendiente se consume (un solo uso).
    #[test]
    fn queue_respond_with_token_approves_and_consumes() {
        let handler = Arc::new(QueueHandler::new());
        let (t, token) = spawn_pending(&handler, "req_t1", InteractionType::Approve, None);
        assert_eq!(
            handler.respond_with_token("req_t1", &token, Some(true), None),
            RespondOutcome::Accepted
        );
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Approved);
        // Un solo uso: el mismo id ya no existe.
        assert_eq!(
            handler.respond_with_token("req_t1", &token, Some(true), None),
            RespondOutcome::NotFound
        );
    }

    // A1.v2: token inválido NO consume la pendiente — el gate sigue esperando y una
    // respuesta posterior con el token correcto llega igual.
    #[test]
    fn queue_bad_token_keeps_pending_alive() {
        let handler = Arc::new(QueueHandler::new());
        let (t, token) = spawn_pending(&handler, "req_t2", InteractionType::Confirm, None);
        assert_eq!(
            handler.respond_with_token("req_t2", "token-falso", Some(true), None),
            RespondOutcome::BadToken
        );
        assert_eq!(handler.get_pending().len(), 1, "la pendiente debe seguir viva");
        assert_eq!(
            handler.respond_with_token("req_t2", &token, Some(false), None),
            RespondOutcome::Accepted
        );
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Denied);
    }

    // A1.v2: ask responde con `value` → Answered con ese texto.
    #[test]
    fn queue_ask_answered_with_value() {
        let handler = Arc::new(QueueHandler::new());
        let (t, token) = spawn_pending(&handler, "req_t3", InteractionType::Ask, None);
        assert_eq!(
            handler.respond_with_token("req_t3", &token, None, Some("azul")),
            RespondOutcome::Accepted
        );
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Answered);
        assert_eq!(resp.value.as_deref(), Some("azul"));
    }

    // A1.v2: sin respuesta → al deadline `Timeout` y la pendiente desaparece.
    #[test]
    fn queue_timeout_expires_pending() {
        let handler = Arc::new(QueueHandler::new());
        let (t, _token) = spawn_pending(&handler, "req_t4", InteractionType::Approve, Some(0.05));
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Timeout);
        assert!(handler.get_pending().is_empty(), "la pendiente vencida no debe listarse");
    }

    // A1.v2: los summaries no exponen el token y llevan tipo + vencimiento.
    #[test]
    fn queue_summaries_have_no_token() {
        let handler = Arc::new(QueueHandler::new());
        let (t, token) = spawn_pending(&handler, "req_t5", InteractionType::Approve, Some(60.0));
        let sums = handler.pending_summaries();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].id, "req_t5");
        assert_eq!(sums[0].ty, "approve");
        assert!(sums[0].expires_at > 0);
        // El resumen es lo que sale por GET /approvals: no contiene el token.
        assert!(!format!("{:?}", sums[0]).contains(&token));
        handler.respond_with_token("req_t5", &token, Some(true), None);
        let _ = t.join().unwrap();
    }

    // A1.v2 (D1): el mapeo de Timeout en el callback es fail-closed: false para
    // approve, texto vacío para ask (fallback documentado del core).
    #[test]
    fn callback_maps_timeout_to_false_and_empty() {
        let mgr = InteractionManager::new(Arc::new(QueueHandler::new()));
        let cb = mgr.get_callback();
        assert!(matches!(cb("approve", "¿seguro?", Some(0.05)), SynValue::Bool(false)));
        match cb("ask", "¿nombre?", Some(0.05)) {
            SynValue::Text(s) => assert_eq!(s.as_ref(), ""),
            other => panic!("esperaba texto vacío, got {:?}", other),
        }
    }

    // Precedencia del timeout (D1): `within` del gate > default del host (knob). El
    // request que llega al handler lleva el timeout ya resuelto.
    #[test]
    fn callback_timeout_precedence_within_over_default() {
        let handler = Arc::new(AutoHandler::new(true, ""));
        let mgr = InteractionManager::new(handler.clone()).with_default_timeout(Some(7.0));
        let cb = mgr.get_callback();
        cb("approve", "con within", Some(2.0));
        cb("approve", "sin within", None);
        let log = handler.log.lock().unwrap();
        assert_eq!(log[0].timeout_seconds, Some(2.0), "`within` le gana al default");
        assert_eq!(log[1].timeout_seconds, Some(7.0), "sin `within` aplica el knob");
    }

    /// Una cola con continuación que anota lo que le llega.
    fn deferred_queue(store: Option<std::path::PathBuf>) -> (Arc<QueueHandler>, Arc<Mutex<Vec<Settled>>>) {
        let q = match store {
            Some(p) => QueueHandler::new().with_store(p, allowed(&["decide_payment", "pick", "on_delete", "t", "settle"])),
            None => QueueHandler::new(),
        };
        let q = Arc::new(q);
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        q.set_continuation(Arc::new(move |s| g.lock().unwrap().push(s)));
        (q, got)
    }

    fn token_of(q: &QueueHandler, id: &str) -> String {
        q.tokens.lock().unwrap().get(id).expect("pendiente").clone()
    }

    fn allowed(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Un archivo de estado escrito a mano, privado (0600 en Unix) como lo exige la cola.
    fn write_private(path: &std::path::Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("syn_g3_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wait_until(mut ok: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !ok() && t0.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// v0.6.53 (G3): `defer` no espera; la respuesta con el token llama a la continuación (una
    /// vez) con la decisión, el mensaje, la task y el id.
    #[test]
    fn a_deferred_gate_does_not_wait_and_its_answer_reaches_the_task() {
        let (q, got) = deferred_queue(None);
        let mut req = InteractionRequest::new("", InteractionType::Approve, "¿Pagar 800?");
        req.timeout_seconds = Some(60.0);
        let t0 = Instant::now();
        let id = q.defer(&req, "decide_payment").unwrap();
        assert!(t0.elapsed() < Duration::from_millis(500), "no bloquea");
        assert!(id.starts_with("approval_"), "{}", id);
        assert_eq!(q.pending_summaries().len(), 1, "se lista en GET /approvals");
        let token = token_of(&q, &id);
        assert_eq!(q.respond_with_token(&id, "mal", Some(true), None), RespondOutcome::BadToken);
        assert!(got.lock().unwrap().is_empty());
        assert_eq!(q.respond_with_token(&id, &token, Some(true), None), RespondOutcome::Accepted);
        assert_eq!(q.respond_with_token(&id, &token, Some(true), None), RespondOutcome::NotFound, "un solo uso");
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 1);
        let s = &got[0];
        assert_eq!((s.id.as_str(), s.ty.as_str(), s.message.as_str(), s.task.as_str()), (id.as_str(), "approve", "¿Pagar 800?", "decide_payment"));
        assert_eq!((s.decision, s.timed_out), (Some(true), false));
    }

    /// v0.6.53 (G3): una pendiente con continuación que vence llama a la task como vencida.
    #[test]
    fn a_deferred_gate_that_times_out_reaches_the_task_as_timed_out() {
        let (q, got) = deferred_queue(None);
        let mut req = InteractionRequest::new("", InteractionType::Ask, "¿Color?");
        req.timeout_seconds = Some(0.0);
        let id = q.defer(&req, "pick").unwrap();
        let t0 = Instant::now();
        while got.lock().unwrap().is_empty() && t0.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(50));
        }
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 1, "venció");
        assert_eq!((got[0].id.as_str(), got[0].timed_out, got[0].value.clone()), (id.as_str(), true, None));
        assert!(q.pending_summaries().is_empty());
    }

    /// v0.6.53 (G3): sin continuación cableada (fuera de `serve`) `defer` es un error claro.
    #[test]
    fn defer_without_a_continuation_is_an_error() {
        let q = QueueHandler::new();
        let e = q.defer(&InteractionRequest::new("", InteractionType::Approve, "x"), "t").unwrap_err();
        assert!(e.contains("serve"), "{}", e);
    }

    /// v0.6.53 (G3): lo pendiente se guarda con el hash del token (nunca el token) y una cola
    /// nueva sobre el mismo archivo (un reinicio) lo recupera: el token de antes sigue valiendo.
    /// Sin pendientes, el archivo se borra.
    #[test]
    fn deferred_approvals_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("syn_g3_store_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("approvals-8080.json");
        let (q, _) = deferred_queue(Some(path.clone()));
        let mut req = InteractionRequest::new("", InteractionType::Confirm, "¿Borrar?");
        req.timeout_seconds = Some(3600.0);
        let id = q.defer(&req, "on_delete").unwrap();
        let token = token_of(&q, &id);
        let text = std::fs::read_to_string(&path).expect("guardado");
        assert!(text.contains(&id) && text.contains("on_delete") && text.contains(&sha256_hex(&token)), "{}", text);
        assert!(!text.contains(&token), "el token no va al disco");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(q);
        let (q2, got) = deferred_queue(Some(path.clone()));
        assert_eq!(q2.pending_summaries().len(), 1, "recuperada");
        assert_eq!(q2.respond_with_token(&id, "otro", Some(false), None), RespondOutcome::BadToken);
        assert_eq!(q2.respond_with_token(&id, &token, Some(false), None), RespondOutcome::Accepted);
        let got = got.lock().unwrap();
        assert_eq!((got[0].task.as_str(), got[0].ty.as_str(), got[0].decision), ("on_delete", "confirm", Some(false)));
        assert!(!path.exists(), "sin pendientes no queda archivo");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v0.6.53 (G3): una pendiente que venció con el proceso apagado se resuelve como vencida al
    /// volver.
    #[test]
    fn a_deferred_approval_that_expired_while_down_is_settled_on_start() {
        let dir = fresh_dir("down");
        let path = dir.join("approvals-1.json");
        write_private(
            &path,
            r#"[{"id":"approval_x","type":"approve","message":"m","task":"t","expires_at":1,"token_sha256":"00"}]"#,
        );
        let (_q, got) = deferred_queue(Some(path.clone()));
        let t0 = Instant::now();
        while got.lock().unwrap().is_empty() && t0.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(50));
        }
        let got = got.lock().unwrap();
        assert_eq!((got.len(), got[0].id.as_str(), got[0].timed_out), (1, "approval_x", true));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn deferred(q: &QueueHandler, ty: InteractionType, msg: &str, secs: f64, task: &str) -> String {
        let mut req = InteractionRequest::new("", ty, msg);
        req.timeout_seconds = Some(secs);
        q.defer(&req, task).unwrap()
    }

    /// Una fila vigente escrita a mano, con el hash de `token`.
    fn row_json(id: &str, task: &str, token: &str) -> String {
        format!(
            r#"[{{"id":"{}","type":"approve","message":"m","task":"{}","expires_at":99999999999,"token_sha256":"{}"}}]"#,
            id,
            task,
            sha256_hex(token)
        )
    }

    /// Ronda 1, A2: dos colas sobre el mismo archivo (dos procesos en el traspaso de G1). Una
    /// pendiente que vence corre la task UNA vez, contando las dos.
    #[test]
    fn two_queues_on_one_file_settle_an_expired_approval_once() {
        let dir = fresh_dir("two_expire");
        let path = dir.join("approvals-9.json");
        let (a, got_a) = deferred_queue(Some(path.clone()));
        let (_b, got_b) = deferred_queue(Some(path.clone()));
        deferred(&a, InteractionType::Approve, "Pay?", 1.0, "settle");
        wait_until(|| got_a.lock().unwrap().len() + got_b.lock().unwrap().len() >= 1);
        thread::sleep(Duration::from_millis(1200)); // los dos vigilantes pasaron varias veces
        assert_eq!(got_a.lock().unwrap().len() + got_b.lock().unwrap().len(), 1, "una sola vez");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, A2: lo que crea una cola lo ve la otra (el archivo es la verdad), y una respuesta
    /// en una deja a la otra sin nada que contestar con el mismo token.
    #[test]
    fn two_queues_on_one_file_share_pending_approvals_and_answer_once() {
        let dir = fresh_dir("two_answer");
        let path = dir.join("approvals-9.json");
        let (a, got_a) = deferred_queue(Some(path.clone()));
        let (b, got_b) = deferred_queue(Some(path.clone()));
        let id_a = deferred(&a, InteractionType::Approve, "A?", 3600.0, "settle");
        let id_b = deferred(&b, InteractionType::Confirm, "B?", 3600.0, "settle");
        let ids = |q: &QueueHandler| {
            let mut v: Vec<String> = q.pending_summaries().into_iter().map(|s| s.id).collect();
            v.sort();
            v
        };
        let mut both = vec![id_a.clone(), id_b.clone()];
        both.sort();
        assert_eq!(ids(&a), both, "la cola A ve la de B");
        assert_eq!(ids(&b), both, "la cola B ve la de A");
        let token = token_of(&a, &id_a);
        assert_eq!(b.respond_with_token(&id_a, &token, Some(true), None), RespondOutcome::Accepted);
        assert_eq!(a.respond_with_token(&id_a, &token, Some(true), None), RespondOutcome::NotFound);
        assert_eq!((got_a.lock().unwrap().len(), got_b.lock().unwrap().len()), (0, 1));
        assert_eq!(ids(&a), vec![id_b.clone()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M1: una fila con una task que ningún `then` del programa nombra no se lista, no
    /// se contesta y no vence desde acá, y queda en el archivo tal cual.
    #[test]
    fn a_planted_row_with_a_task_the_program_does_not_name_is_ignored_and_kept() {
        let dir = fresh_dir("planted");
        let path = dir.join("approvals-9.json");
        let planted = format!(
            r#"[{{"id":"approval_plantado","type":"approve","message":"m","task":"danger","expires_at":1,"token_sha256":"{}"}}]"#,
            sha256_hex("conocido")
        );
        write_private(&path, &planted);
        let (q, got) = deferred_queue(Some(path.clone()));
        assert!(q.pending_summaries().is_empty());
        assert_eq!(q.respond_with_token("approval_plantado", "conocido", Some(true), None), RespondOutcome::NotFound);
        thread::sleep(Duration::from_millis(1200)); // venció hace rato: tampoco corre por ahí
        assert!(got.lock().unwrap().is_empty());
        // Una pendiente de verdad no la borra al escribir.
        let id = deferred(&q, InteractionType::Approve, "x", 3600.0, "settle");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("approval_plantado") && text.contains(&id), "{}", text);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M1: un archivo de estado que es un link no se lee ni se pisa, y `defer` da error.
    #[cfg(unix)]
    #[test]
    fn a_state_file_that_is_a_link_is_not_followed() {
        let dir = fresh_dir("link");
        let path = dir.join("approvals-9.json");
        let target = dir.join("otro.json");
        let row = row_json("approval_l", "settle", "tk");
        write_private(&target, &row);
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let (q, got) = deferred_queue(Some(path.clone()));
        assert!(q.pending_summaries().is_empty());
        assert_eq!(q.respond_with_token("approval_l", "tk", Some(true), None), RespondOutcome::NotFound);
        let mut req = InteractionRequest::new("", InteractionType::Approve, "x");
        req.timeout_seconds = Some(60.0);
        let e = q.defer(&req, "settle").unwrap_err();
        assert!(e.contains("is a link"), "{}", e);
        assert!(got.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), row, "el destino intacto");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M1: un archivo de estado que otros pueden leer o escribir no se usa.
    #[cfg(unix)]
    #[test]
    fn a_state_file_that_is_not_private_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("mode");
        let path = dir.join("approvals-9.json");
        write_private(&path, &row_json("approval_m", "settle", "tk"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (q, got) = deferred_queue(Some(path.clone()));
        assert!(q.pending_summaries().is_empty());
        assert_eq!(q.respond_with_token("approval_m", "tk", Some(true), None), RespondOutcome::NotFound);
        assert!(got.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 2, R2-2: una cola con archivo pero sin pendientes no crea nada: ni al cargar, ni al
    /// listar, ni al contestar un id que no existe, ni con el vigilante andando.
    #[test]
    fn a_store_without_pending_approvals_creates_nothing() {
        let dir = fresh_dir("nothing");
        let state = dir.join("state");
        let (q, _got) = deferred_queue(Some(state.join("approvals-9.json")));
        assert!(q.pending_summaries().is_empty());
        assert_eq!(q.respond_with_token("approval_x", "t", Some(true), None), RespondOutcome::NotFound);
        thread::sleep(Duration::from_millis(600));
        assert!(!state.exists(), "sin pendientes no se crea nada");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un lock que no es privado (el caso de un disco de Windows montado en la WSL, donde `chmod`
    /// no hace nada) es un error del gate que nombra la salida: `SYNSEMA_STATE_DIR`.
    #[cfg(unix)]
    #[test]
    fn a_lock_that_is_not_private_names_the_way_out() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("lockmode");
        let path = dir.join("approvals-9.json");
        let lock = dir.join("approvals-9.json.lock");
        std::fs::write(&lock, "").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (q, _got) = deferred_queue(Some(path));
        let mut req = InteractionRequest::new("", InteractionType::Approve, "x");
        req.timeout_seconds = Some(60.0);
        let e = q.defer(&req, "settle").unwrap_err();
        assert!(e.contains("mode 666") && e.contains("SYNSEMA_STATE_DIR"), "{}", e);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M2: un link plantado con el nombre del temporal viejo (`.tmp<pid>`) no se toca: el
    /// temporal es nuevo, con nombre al azar y creado en exclusiva.
    #[cfg(unix)]
    #[test]
    fn the_temporary_file_never_follows_a_planted_link() {
        let dir = fresh_dir("tmp");
        let path = dir.join("approvals-9.json");
        let victim = dir.join("victima.txt");
        std::fs::write(&victim, "contenido de la víctima").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(format!("approvals-9.tmp{}", std::process::id()))).unwrap();
        let (q, _) = deferred_queue(Some(path.clone()));
        deferred(&q, InteractionType::Approve, "x", 3600.0, "settle");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "contenido de la víctima");
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M2: la escritura no deja temporales y el archivo queda con lo escrito.
    #[test]
    fn write_private_atomic_leaves_no_temporary() {
        let dir = fresh_dir("tmp_left");
        let path = dir.join("a.json");
        write_private_atomic(&path, b"[1]").unwrap();
        write_private_atomic(&path, b"[2]").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[2]");
        let others: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).filter(|n| n != "a.json").collect();
        assert!(others.is_empty(), "{:?}", others);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, M3: sin continuación (la corrida terminó) una pendiente no vence ni se contesta:
    /// queda en el archivo y la respuesta da `Unavailable` sin consumirla.
    #[test]
    fn without_a_continuation_nothing_pending_is_consumed() {
        let dir = fresh_dir("noc");
        let path = dir.join("approvals-9.json");
        let (q, got) = deferred_queue(Some(path.clone()));
        let id = deferred(&q, InteractionType::Approve, "x", 1.0, "settle");
        q.clear_continuation();
        thread::sleep(Duration::from_millis(2000)); // venció
        assert!(got.lock().unwrap().is_empty());
        assert!(std::fs::read_to_string(&path).unwrap().contains(&id), "sigue en el archivo");
        write_private(&path, &row_json("approval_v", "settle", "tk"));
        assert_eq!(q.respond_with_token("approval_v", "tk", Some(true), None), RespondOutcome::Unavailable);
        assert!(std::fs::read_to_string(&path).unwrap().contains("approval_v"), "no se consumió");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// G-4: una fila que salió y cuya task no pudo correr vuelve al archivo.
    #[test]
    fn give_back_puts_the_row_back() {
        let dir = fresh_dir("giveback");
        let path = dir.join("approvals-9.json");
        let (q, got) = deferred_queue(Some(path.clone()));
        let id = deferred(&q, InteractionType::Ask, "Color?", 3600.0, "pick");
        let token = token_of(&q, &id);
        assert_eq!(q.respond_with_token(&id, &token, None, Some("azul")), RespondOutcome::Accepted);
        assert!(!path.exists());
        let s = got.lock().unwrap()[0].clone();
        s.give_back();
        assert!(std::fs::read_to_string(&path).unwrap().contains(&id));
        assert_eq!(q.pending_summaries().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 1, B3: «nadie contestó» en un `ask … with [...]` es la primera opción, como el gate
    /// que espera; con respuesta, la respuesta.
    #[test]
    fn an_unanswered_ask_settles_with_its_first_option() {
        let (q, got) = deferred_queue(None);
        let mut req = InteractionRequest::new("", InteractionType::Ask, "Color?");
        req.timeout_seconds = Some(0.0);
        req.options = Some(vec!["rojo".into(), "azul".into()]);
        q.defer(&req, "pick").unwrap();
        wait_until(|| !got.lock().unwrap().is_empty());
        let s = got.lock().unwrap()[0].clone();
        assert!(s.timed_out);
        assert_eq!(s.ask_answer(), "rojo");
        let answered = Settled { value: Some("azul".into()), ..s.clone() };
        assert_eq!(answered.ask_answer(), "azul");
        let bare = Settled { options: Vec::new(), ..s };
        assert_eq!(bare.ask_answer(), "");
    }
}
