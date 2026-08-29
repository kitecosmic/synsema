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
}

struct PendingEntry {
    request: InteractionRequest,
    /// OTT de esta pendiente: responder la consume; expira con el deadline.
    token: String,
    expires_at_epoch: i64,
}

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
    /// Aviso de encolado con el token (v2): el runtime lo cablea a la consola del
    /// server — poseer la consola = poder aprobar (frontera de confianza base).
    notice: Option<NoticeSink>,
    /// Hook de encolado ESTRUCTURADO (A1.v3): recibe la pendiente completa (con token)
    /// además del aviso de consola. El runtime lo cablea al webhook saliente; debe ser
    /// fire-and-forget (jamás bloquear ni romper el gate).
    on_enqueue: Option<EnqueueHook>,
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
            notice: None,
            on_enqueue: None,
        }
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
            let entry = match g.pending.get(request_id) {
                Some(e) => e,
                None => return RespondOutcome::NotFound,
            };
            let now_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if entry.expires_at_epoch <= now_epoch {
                return RespondOutcome::NotFound; // vencida (el gate despierta solo)
            }
            if entry.token != token {
                return RespondOutcome::BadToken;
            }
            g.pending.remove(request_id); // un solo uso: responder consume la pendiente
            let status = match decision {
                Some(true) => InteractionStatus::Approved,
                Some(false) => InteractionStatus::Denied,
                None => InteractionStatus::Answered, // ask: llega `value`
            };
            g.responses.insert(
                request_id.to_string(),
                InteractionResponse {
                    request_id: request_id.to_string(),
                    status,
                    value: value.map(|v| v.to_string()),
                },
            );
        }
        self.cvar.notify_all();
        RespondOutcome::Accepted
    }

    pub fn get_pending(&self) -> Vec<InteractionRequest> {
        self.inner.lock().unwrap().pending.values().map(|e| e.request.clone()).collect()
    }

    /// Pendientes para `GET /approvals` — sin tokens, con vencimiento en epoch-segundos.
    pub fn pending_summaries(&self) -> Vec<PendingSummary> {
        self.inner
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
            .collect()
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
                PendingEntry { request: request.clone(), token: token.clone(), expires_at_epoch },
            );
        }
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
                token: token.clone(),
                expires_at: expires_at_epoch,
                timeout_secs: timeout,
            });
        }
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
}
