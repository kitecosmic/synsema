//! Interacción humana. Port de `synsema/human/interaction.py`.
//!
//! `InteractionManager.get_callback()` devuelve el callback (action, message) →
//! SynValue (bool para approve/confirm/review, texto para ask) que el motor cablea
//! en el intérprete. Backends: `AutoHandler` (auto, para CI) y `QueueHandler`
//! (async, el agente bloquea hasta que un humano responde fuera de banda).

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

struct QueueInner {
    pending: HashMap<String, InteractionRequest>,
    responses: HashMap<String, InteractionResponse>,
}

/// Backend async: encola y bloquea hasta que `respond` entrega la respuesta.
pub struct QueueHandler {
    inner: Mutex<QueueInner>,
    cvar: Condvar,
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
        }
    }

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

    pub fn get_pending(&self) -> Vec<InteractionRequest> {
        self.inner.lock().unwrap().pending.values().cloned().collect()
    }
}

impl HumanHandler for QueueHandler {
    fn handle(&self, request: &InteractionRequest) -> InteractionResponse {
        let timeout = request.timeout_seconds.unwrap_or(300.0);
        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        let mut g = self.inner.lock().unwrap();
        g.pending.insert(request.id.clone(), request.clone());
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

/// Maneja toda la interacción humana de un programa. `get_callback` da la función
/// que usa el intérprete.
pub struct InteractionManager {
    handler: Arc<dyn HumanHandler>,
    history: Arc<Mutex<Vec<(InteractionRequest, InteractionResponse)>>>,
    counter: Arc<Mutex<u64>>,
}

impl InteractionManager {
    pub fn new(handler: Arc<dyn HumanHandler>) -> Self {
        Self {
            handler,
            history: Arc::new(Mutex::new(Vec::new())),
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub fn history_len(&self) -> usize {
        self.history.lock().unwrap().len()
    }

    /// Callback (action, message) → SynValue. bool para approve/confirm/review;
    /// texto para ask.
    pub fn get_callback(&self) -> Rc<dyn Fn(&str, &str) -> SynValue> {
        let handler = self.handler.clone();
        let history = self.history.clone();
        let counter = self.counter.clone();
        Rc::new(move |action: &str, message: &str| -> SynValue {
            let id = {
                let mut c = counter.lock().unwrap();
                *c += 1;
                format!("interact_{}", *c)
            };
            let ty = match action {
                "approve" => InteractionType::Approve,
                "confirm" => InteractionType::Confirm,
                "ask" => InteractionType::Ask,
                "review" => InteractionType::Review,
                _ => InteractionType::Show,
            };
            let req = InteractionRequest::new(&id, ty, message);
            let resp = handler.handle(&req);
            history.lock().unwrap().push((req, resp.clone()));
            match ty {
                InteractionType::Approve | InteractionType::Confirm | InteractionType::Review => {
                    syn_bool(resp.status == InteractionStatus::Approved)
                }
                _ => syn_text(resp.value.unwrap_or_default()),
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
        assert!(matches!(cb("approve", "Do this?"), SynValue::Bool(true)));
    }

    #[test]
    fn auto_handler_deny() {
        let mgr = InteractionManager::new(Arc::new(AutoHandler::new(false, "")));
        let cb = mgr.get_callback();
        assert!(matches!(cb("approve", "Do this?"), SynValue::Bool(false)));
    }

    #[test]
    fn auto_handler_ask() {
        let mgr = InteractionManager::new(Arc::new(AutoHandler::new(true, "test_answer")));
        let cb = mgr.get_callback();
        match cb("ask", "What?") {
            SynValue::Text(s) => assert_eq!(s.as_ref(), "test_answer"),
            other => panic!("esperaba texto, got {:?}", other),
        }
    }

    #[test]
    fn auto_handler_history() {
        let handler = Arc::new(AutoHandler::new(true, ""));
        let mgr = InteractionManager::new(handler.clone());
        let cb = mgr.get_callback();
        cb("approve", "First");
        cb("confirm", "Second");
        cb("ask", "Third");
        assert_eq!(mgr.history_len(), 3);
        assert_eq!(handler.log_len(), 3);
    }

    #[test]
    fn queue_handler_respond() {
        let handler = Arc::new(QueueHandler::new());
        let h = handler.clone();
        let t = thread::spawn(move || {
            let req = InteractionRequest::new("req_1", InteractionType::Approve, "Test?");
            h.handle(&req)
        });
        // Esperar a que el request esté pendiente (sin sleep fijo: poll corto).
        let mut pending = handler.get_pending();
        let start = Instant::now();
        while pending.is_empty() && start.elapsed() < Duration::from_secs(2) {
            std::thread::yield_now();
            pending = handler.get_pending();
        }
        assert_eq!(pending.len(), 1);
        handler.respond("req_1", "", true);
        let resp = t.join().unwrap();
        assert_eq!(resp.status, InteractionStatus::Approved);
    }
}
