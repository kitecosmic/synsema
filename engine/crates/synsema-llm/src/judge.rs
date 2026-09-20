//! Provider del primitivo `judge`: el contrato que implementa cada backend (TypeSafe directo,
//! gateways compatibles, el adaptador `llm` marcado, el mock determinista) y el mock.
//!
//! Los tipos del pedido y la respuesta viven en `synsema_core::judge`: el intérprete los
//! arma, el provider los sirve. Acá no hay red: la capa HTTP está en el runtime.

use std::collections::VecDeque;
use std::sync::Mutex;

pub use synsema_core::judge::{
    JudgeAnswer, JudgeKind, JudgeOption, JudgeQuestion, JudgeRequest, JudgeResponse,
};
use synsema_core::judge::{argmax_id, confidence_from, ESCAPE_ID};

/// Resultado de una llamada al provider. Tres desenlaces, y ninguno inventa números:
/// - `Answered`: la respuesta normalizada (ids del programa, orden de declaración).
/// - `Unavailable`: offline, presupuesto agotado, red caída, 429/529 tras reintentos. El
///   intérprete degrada cada respuesta a `available: false` con confianza 0.
/// - `Rejected`: la API rechazó el pedido por culpa del programa (400/422: límites,
///   instrucción vacía, `state` inválido). Es un error de runtime con el mensaje del vendor.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum JudgeCall {
    Answered(JudgeResponse),
    Unavailable(String),
    Rejected(String),
}

/// Un backend de `judge`. Un `impl` sólo transporta: armar el cable, postear, parsear.
pub trait JudgeProvider: Send + Sync {
    fn judge(&self, request: &JudgeRequest) -> JudgeCall;
    fn name(&self) -> String;
    /// `true` si las probabilidades vienen de un modelo entrenado para calibrarlas. El
    /// adaptador `llm` devuelve `false` y el runtime lo dice en letra grande.
    fn calibrated(&self) -> bool {
        true
    }
}

/// Mock determinista, sin red: para el corpus de conformance y los tests de CI sin clave.
///
/// Sin guion, contesta con una regla fija y legible: `whether` → 0,5; `choose` → la primera
/// opción con toda la masa (o la de escape si la pregunta lo permite y la instrucción
/// contiene "nothing"); `rate` → el nivel del medio. Con guion (`push`), sirve las
/// respuestas en orden, una llamada por entrada, y cae a la regla fija cuando se acaba.
pub struct MockJudgeProvider {
    scripted: Mutex<VecDeque<JudgeCall>>,
    calls: Mutex<u64>,
}

impl Default for MockJudgeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockJudgeProvider {
    pub fn new() -> Self {
        Self {
            scripted: Mutex::new(VecDeque::new()),
            calls: Mutex::new(0),
        }
    }

    /// Encola una respuesta completa para la próxima llamada.
    pub fn push(&self, call: JudgeCall) {
        self.scripted.lock().unwrap().push_back(call);
    }

    /// Cantidad de llamadas recibidas (para afirmar que un bloque = una llamada).
    pub fn calls(&self) -> u64 {
        *self.calls.lock().unwrap()
    }

    /// La respuesta fija para un pedido: determinista y explicable.
    pub fn fixed_answer(q: &JudgeQuestion) -> JudgeAnswer {
        match q.kind {
            JudgeKind::Whether => JudgeAnswer::Whether { probability: 0.5 },
            JudgeKind::Choose => {
                let wants_escape = q.escape
                    && q.instruction
                        .to_string()
                        .to_ascii_lowercase()
                        .contains("nothing");
                let mut probabilities: Vec<(String, f64)> =
                    q.options.iter().map(|o| (o.id.clone(), 0.0)).collect();
                if q.escape {
                    probabilities.push((ESCAPE_ID.to_string(), 0.0));
                }
                let winner = if wants_escape { probabilities.len() - 1 } else { 0 };
                if let Some(w) = probabilities.get_mut(winner) {
                    w.1 = 1.0;
                }
                let probs: Vec<f64> = probabilities.iter().map(|p| p.1).collect();
                let choice = if wants_escape {
                    None
                } else {
                    q.options.first().map(|o| o.id.clone())
                };
                JudgeAnswer::Choose {
                    choice,
                    confidence: confidence_from(&probs),
                    probabilities,
                }
            }
            JudgeKind::Rate => {
                let n = q.options.len().max(1);
                let mid = (n - 1) / 2;
                let probabilities: Vec<(String, f64)> = q
                    .options
                    .iter()
                    .enumerate()
                    .map(|(i, o)| (o.id.clone(), if i == mid { 1.0 } else { 0.0 }))
                    .collect();
                let probs: Vec<f64> = probabilities.iter().map(|p| p.1).collect();
                JudgeAnswer::Rate {
                    score: mid as f64,
                    level: argmax_id(&probabilities).unwrap_or_default(),
                    confidence: confidence_from(&probs),
                    probabilities,
                }
            }
        }
    }
}

impl JudgeProvider for MockJudgeProvider {
    fn judge(&self, request: &JudgeRequest) -> JudgeCall {
        *self.calls.lock().unwrap() += 1;
        if let Some(scripted) = self.scripted.lock().unwrap().pop_front() {
            return scripted;
        }
        let answers = request.questions.iter().map(Self::fixed_answer).collect();
        JudgeCall::Answered(JudgeResponse {
            answers,
            model: "mock-judge".to_string(),
            input_tokens: 0,
            output_tokens: 0,
        })
    }

    fn name(&self) -> String {
        "mock".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn q(kind: JudgeKind, ids: &[&str], escape: bool, instr: &str) -> JudgeQuestion {
        JudgeQuestion {
            id: "q".into(),
            kind,
            instruction: json!(instr),
            options: ids.iter().map(|s| JudgeOption { id: s.to_string(), description: None }).collect(),
            escape,
            yes_no: None,
        }
    }

    #[test]
    fn fixed_answers_are_deterministic_and_shaped() {
        let m = MockJudgeProvider::new();
        let req = JudgeRequest {
            state: json!("x"),
            questions: vec![
                q(JudgeKind::Whether, &[], false, "Is it?"),
                q(JudgeKind::Choose, &["a", "b"], true, "Which?"),
                q(JudgeKind::Rate, &["low", "mid", "high"], false, "How much?"),
            ],
        };
        let JudgeCall::Answered(r) = m.judge(&req) else { panic!("expected answered") };
        assert_eq!(r.answers[0], JudgeAnswer::Whether { probability: 0.5 });
        match &r.answers[1] {
            JudgeAnswer::Choose { choice, probabilities, confidence } => {
                assert_eq!(choice.as_deref(), Some("a"));
                assert_eq!(probabilities.len(), 3, "escape option is in the distribution");
                assert_eq!(probabilities[2].0, "none");
                assert_eq!(*confidence, 1.0);
            }
            other => panic!("{:?}", other),
        }
        match &r.answers[2] {
            JudgeAnswer::Rate { score, level, .. } => {
                assert_eq!(*score, 1.0);
                assert_eq!(level, "mid");
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(m.calls(), 1, "one block, one call");
    }

    #[test]
    fn escape_wins_when_asked_for_nothing() {
        let m = MockJudgeProvider::new();
        let req = JudgeRequest {
            state: json!("x"),
            questions: vec![q(JudgeKind::Choose, &["a", "b"], true, "Pick nothing here")],
        };
        let JudgeCall::Answered(r) = m.judge(&req) else { panic!() };
        match &r.answers[0] {
            JudgeAnswer::Choose { choice, probabilities, .. } => {
                assert!(choice.is_none());
                assert_eq!(probabilities[2], ("none".to_string(), 1.0));
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn scripted_calls_come_first_then_fixed() {
        let m = MockJudgeProvider::new();
        m.push(JudgeCall::Unavailable("scripted offline".into()));
        let req = JudgeRequest { state: json!("x"), questions: vec![q(JudgeKind::Whether, &[], false, "?")] };
        assert!(matches!(m.judge(&req), JudgeCall::Unavailable(_)));
        assert!(matches!(m.judge(&req), JudgeCall::Answered(_)));
        assert_eq!(m.calls(), 2);
    }
}
