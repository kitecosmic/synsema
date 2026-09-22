//! Provider `laya` de `judge`: decisiones calibradas **sin red, sin secreto y sin costo**.
//!
//! El tercer backend del primitivo, junto a `typesafe` y `mock`. La spec del judge ya lo
//! anticipaba: *"eso deja de ser el API de un proveedor y pasa a ser un protocolo: razón de peso
//! para que nuestro lado sea genérico y el vendor sea sólo el primer backend"*
//! (`specs/system-one-judge.md` §1). Acá se cobra esa decisión.
//!
//! ## Qué cambia para un programa `.syn`
//!
//! Nada. El mismo bloque `judge` corre igual, con el mismo resultado, pero el programa ya no
//! necesita `require net(…)` ni un secreto, y **la degradación offline deja de ser el caso
//! común**: si el checkpoint está en disco, hay respuesta.
//!
//! ## El mapeo con el modelo
//!
//! | Verbo de Synsema | Pregunta de Laya |
//! |---|---|
//! | `whether` | `noul` — P(verdadero) |
//! | `choose` | `choice` — distribución sobre las opciones |
//! | `rate` | `score` — posición ponderada sobre los niveles |
//!
//! `choose … or nothing` agrega la opción de escape como una etiqueta más: el modelo la puntúa
//! igual que a las otras, y si gana, el programa ve `nothing`. No hay umbral inventado.
//!
//! ## Lo que este provider NO hace
//!
//! No descarga el checkpoint. Son ~843 MB y bajarlos es una decisión del operador, igual que con
//! los GGUF. Si no está, el error dice cómo conseguirlo en vez de hacerlo por su cuenta.

use std::sync::OnceLock;

use synsema_core::judge::{ESCAPE_DESCRIPTION, ESCAPE_ID};
use synsema_infer::laya::{Criteria, QType, Question};
use synsema_llm::judge::{
    JudgeAnswer, JudgeCall, JudgeKind, JudgeProvider, JudgeQuestion, JudgeRequest, JudgeResponse,
};

/// El modelo que se reporta en el resultado y en el audit. Lleva el nombre del checkpoint para
/// que dos corridas con pesos distintos no se confundan al leer un log.
fn model_id(spec: &str) -> String {
    format!("laya:{}", spec)
}

fn store_config() -> &'static synsema_infer::StoreConfig {
    static CFG: OnceLock<synsema_infer::StoreConfig> = OnceLock::new();
    CFG.get_or_init(synsema_infer::StoreConfig::from_env)
}

/// Provider local de `judge`. Sólo guarda el spec del checkpoint: los pesos viven en el cache
/// memoizado de `synsema-infer`, compartidos por todo el proceso.
pub struct LayaJudgeProvider {
    spec: String,
}

impl LayaJudgeProvider {
    pub fn new(spec: String) -> Self {
        LayaJudgeProvider { spec }
    }
}

impl JudgeProvider for LayaJudgeProvider {
    fn judge(&self, request: &JudgeRequest) -> JudgeCall {
        // El orden de las opciones es el de declaración del programa y **se conserva**: es el
        // orden en que vuelven las probabilidades, y el que el programa espera leer.
        let mut converted: Vec<(String, Question)> = Vec::with_capacity(request.questions.len());
        for q in &request.questions {
            match to_laya_question(q) {
                Ok(question) => converted.push((q.id.clone(), question)),
                // Una pregunta mal formada es culpa del programa, no del backend: se rechaza
                // con el mismo tipo de error que usaría el vendor.
                Err(e) => return JudgeCall::Rejected(e),
            }
        }

        let session = synsema_infer::decide::load(&self.spec, store_config());
        let session = match session.as_ref() {
            Ok(s) => s,
            Err(e) => {
                return JudgeCall::Unavailable(format!(
                    "no se pudo cargar el checkpoint de Laya '{}': {}",
                    self.spec, e
                ))
            }
        };

        let decision = match session.decide(&request.state, &converted) {
            Ok(d) => d,
            Err(e) => return JudgeCall::Rejected(e),
        };

        let mut answers = Vec::with_capacity(decision.answers.len());
        for (q, (_, answer)) in request.questions.iter().zip(decision.answers.iter()) {
            answers.push(to_judge_answer(q, answer));
        }

        JudgeCall::Answered(JudgeResponse {
            answers,
            model: model_id(&self.spec),
            input_tokens: decision.input_tokens,
            // No genera texto: ése es el punto de un modelo System One.
            output_tokens: 0,
        })
    }

    fn name(&self) -> String {
        model_id(&self.spec)
    }

    /// Laya se entrenó con RLCD contra reglas de scoring estrictamente propias: reportar
    /// probabilidades honestas es la única forma de maximizar la recompensa. Las probabilidades
    /// **son** calibradas, así que el runtime no tiene que advertir nada.
    fn calibrated(&self) -> bool {
        true
    }
}

/// Traduce una pregunta del bloque `judge` a la forma que entiende el modelo.
fn to_laya_question(q: &JudgeQuestion) -> Result<Question, String> {
    let instructions = json_as_text(&q.instruction);
    if instructions.trim().is_empty() {
        return Err(format!("la pregunta '{}' no tiene instrucción", q.id));
    }
    let criteria = match q.kind {
        JudgeKind::Whether => {
            let (no, yes) = match &q.yes_no {
                Some((n, y)) => (Some(n.clone()), Some(y.clone())),
                None => (None, None),
            };
            Criteria::Truth { when_false: no, when_true: yes }
        }
        JudgeKind::Choose => {
            let mut labels: Vec<(String, Option<serde_json::Value>)> =
                q.options.iter().map(|o| (o.id.clone(), o.description.clone())).collect();
            if q.escape {
                // La opción de escape entra como una más: el modelo la puntúa, no se infiere de
                // un umbral sobre la confianza.
                labels.push((
                    ESCAPE_ID.to_string(),
                    Some(serde_json::Value::String(ESCAPE_DESCRIPTION.to_string())),
                ));
            }
            if labels.is_empty() {
                return Err(format!("la pregunta '{}' no tiene opciones", q.id));
            }
            Criteria::Labels(labels)
        }
        JudgeKind::Rate => {
            if q.options.is_empty() {
                return Err(format!("la pregunta '{}' no tiene niveles", q.id));
            }
            // Un nivel se describe por su descripción si la tiene, y si no por su id: lo que el
            // modelo lee tiene que ser el texto más informativo disponible.
            let levels = q
                .options
                .iter()
                .map(|o| match &o.description {
                    Some(d) => d.clone(),
                    None => serde_json::Value::String(o.id.clone()),
                })
                .collect();
            Criteria::Levels(levels)
        }
    };
    let kind = match q.kind {
        JudgeKind::Whether => QType::Noul,
        JudgeKind::Choose => QType::Choice,
        JudgeKind::Rate => QType::Score,
    };
    Ok(Question { kind, instructions, criteria })
}

/// Traduce la respuesta del modelo al resultado que ve el programa.
fn to_judge_answer(q: &JudgeQuestion, a: &synsema_infer::Answer) -> JudgeAnswer {
    let probabilities: Vec<(String, f64)> =
        a.probabilities.iter().map(|(l, p)| (l.clone(), *p as f64)).collect();
    match q.kind {
        JudgeKind::Whether => JudgeAnswer::Whether { probability: a.truth.unwrap_or(0.0) as f64 },
        JudgeKind::Choose => {
            let winner = a.choice.clone();
            // Ganó el escape: el programa ve `nothing`, que es una respuesta legítima y no un fallo.
            let choice = match winner {
                Some(id) if q.escape && id == ESCAPE_ID => None,
                other => other,
            };
            JudgeAnswer::Choose { choice, probabilities, confidence: a.confidence as f64 }
        }
        JudgeKind::Rate => {
            // Las etiquetas del modelo para `score` son índices ("0", "1", …); el programa espera
            // el id del nivel que declaró.
            let level_ids: Vec<String> = q.options.iter().map(|o| o.id.clone()).collect();
            let best = a
                .probabilities
                .iter()
                .enumerate()
                .max_by(|x, y| x.1 .1.partial_cmp(&y.1 .1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);
            let named: Vec<(String, f64)> = level_ids
                .iter()
                .zip(a.probabilities.iter())
                .map(|(id, (_, p))| (id.clone(), *p as f64))
                .collect();
            JudgeAnswer::Rate {
                score: a.score.unwrap_or(0.0) as f64,
                level: level_ids.get(best).cloned().unwrap_or_default(),
                probabilities: named,
                confidence: a.confidence as f64,
            }
        }
    }
}

/// Una instrucción puede ser texto o estructura. El modelo lee texto, así que lo estructurado se
/// serializa en vez de descartarse: la API del vendor también aprovecha la estructura.
fn json_as_text(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::judge::JudgeOption;

    fn question(kind: JudgeKind, options: Vec<(&str, Option<&str>)>, escape: bool) -> JudgeQuestion {
        JudgeQuestion {
            id: "q".to_string(),
            kind,
            instruction: serde_json::Value::String("¿qué corresponde?".to_string()),
            options: options
                .into_iter()
                .map(|(id, d)| JudgeOption {
                    id: id.to_string(),
                    description: d.map(|s| serde_json::Value::String(s.to_string())),
                })
                .collect(),
            escape,
            yes_no: None,
        }
    }

    #[test]
    fn choose_keeps_declaration_order() {
        let q = question(JudgeKind::Choose, vec![("billing", None), ("technical", None)], false);
        let laya = to_laya_question(&q).unwrap();
        assert_eq!(laya.kind, QType::Choice);
        assert_eq!(laya.labels(), vec!["billing", "technical"]);
    }

    #[test]
    fn escape_becomes_one_more_option_the_model_scores() {
        let q = question(JudgeKind::Choose, vec![("a", None)], true);
        let laya = to_laya_question(&q).unwrap();
        assert_eq!(laya.labels(), vec!["a", ESCAPE_ID]);
        assert_eq!(laya.option_count(), 2);
    }

    #[test]
    fn whether_is_always_two_options() {
        let q = question(JudgeKind::Whether, vec![], false);
        let laya = to_laya_question(&q).unwrap();
        assert_eq!(laya.kind, QType::Noul);
        assert_eq!(laya.option_count(), 2);
    }

    #[test]
    fn rate_uses_the_description_when_there_is_one() {
        let q = question(
            JudgeKind::Rate,
            vec![("low", Some("nada urgente")), ("high", None)],
            false,
        );
        let laya = to_laya_question(&q).unwrap();
        assert_eq!(laya.kind, QType::Score);
        let opts = laya.render_options();
        assert!(opts[0].contains("nada urgente"), "{:?}", opts);
        // Sin descripción, el id es lo más informativo que hay.
        assert!(opts[1].contains("high"), "{:?}", opts);
    }

    #[test]
    fn empty_instruction_is_rejected_not_guessed() {
        let mut q = question(JudgeKind::Whether, vec![], false);
        q.instruction = serde_json::Value::String("   ".to_string());
        assert!(to_laya_question(&q).is_err());
    }

    #[test]
    fn choose_without_options_is_rejected() {
        let q = question(JudgeKind::Choose, vec![], false);
        assert!(to_laya_question(&q).is_err());
    }

    // -- traducción de respuestas --

    fn answer(kind: QType, probs: &[(&str, f32)]) -> synsema_infer::Answer {
        synsema_infer::Answer {
            kind,
            confidence: 0.8,
            probabilities: probs.iter().map(|(l, p)| (l.to_string(), *p)).collect(),
            choice: probs
                .iter()
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .map(|(l, _)| l.to_string()),
            score: Some(0.25),
            truth: Some(0.75),
        }
    }

    #[test]
    fn escape_winning_reads_as_nothing() {
        let q = question(JudgeKind::Choose, vec![("a", None)], true);
        let a = answer(QType::Choice, &[("a", 0.3), (ESCAPE_ID, 0.7)]);
        match to_judge_answer(&q, &a) {
            JudgeAnswer::Choose { choice, .. } => assert!(choice.is_none(), "debía ser nothing"),
            other => panic!("esperaba Choose, got {:?}", other),
        }
    }

    #[test]
    fn rate_reports_the_declared_level_id_not_the_index() {
        let q = question(JudgeKind::Rate, vec![("low", None), ("high", None)], false);
        let a = answer(QType::Score, &[("0", 0.1), ("1", 0.9)]);
        match to_judge_answer(&q, &a) {
            JudgeAnswer::Rate { level, probabilities, .. } => {
                assert_eq!(level, "high", "el nivel es el id del programa");
                assert_eq!(probabilities[0].0, "low", "las claves también");
            }
            other => panic!("esperaba Rate, got {:?}", other),
        }
    }

    #[test]
    fn whether_carries_the_probability_through() {
        let q = question(JudgeKind::Whether, vec![], false);
        let a = answer(QType::Noul, &[("false", 0.25), ("true", 0.75)]);
        match to_judge_answer(&q, &a) {
            JudgeAnswer::Whether { probability } => assert!((probability - 0.75).abs() < 1e-6),
            other => panic!("esperaba Whether, got {:?}", other),
        }
    }
}
