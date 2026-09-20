//! `judge` — el primitivo de juicio calibrado (System One). Tipos del pedido y de la
//! respuesta, validación de límites y la forma del valor que ve el programa.
//!
//! Los tres verbos nombran las tres distribuciones discretas básicas, no los campos de un
//! vendor: `whether` es una Bernoulli (una proposición, una probabilidad), `choose` una
//! categórica (opciones sin orden, una distribución) y `rate` una ordinal (niveles con
//! orden, una distribución y una posición ponderada). Cualquier modelo System One produce
//! estas tres formas; el cable de cada proveedor vive en el runtime, nunca acá.
//!
//! Core no habla con la red: el intérprete arma un [`JudgeRequest`], lo entrega al callback
//! que cablea el motor y convierte la [`JudgeResponse`] en maps comunes del lenguaje. Sin
//! callback (offline, sin presupuesto, error de red) cada respuesta degrada a
//! `available: false` con confianza 0 — nunca a una probabilidad inventada.

use indexmap::IndexMap;
use serde_json::Value as Json;

use crate::number::Number;
use crate::types::{syn_bool, syn_list, syn_map, syn_number, syn_text, SynValue};

/// Los tres verbos del bloque `judge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JudgeKind {
    /// `whether "…"` → probabilidad de que la proposición sea cierta.
    Whether,
    /// `choose "…" between {…} [or nothing]` → una opción + distribución + confianza.
    Choose,
    /// `rate "…" across […]` → posición ponderada + nivel ganador + distribución + confianza.
    Rate,
}

impl JudgeKind {
    /// El verbo tal como se escribe en el programa; también es el `type` del resultado.
    pub fn verb(&self) -> &'static str {
        match self {
            JudgeKind::Whether => "whether",
            JudgeKind::Choose => "choose",
            JudgeKind::Rate => "rate",
        }
    }
}

/// Una opción de `choose` o un nivel de `rate`. `id` es lo que el programa ve en `choice`,
/// `level`, `levels` y como clave de `probabilities`; `description` es lo que ve el modelo
/// además del id (forma map). En la forma lista el id ES la descripción y `description` va
/// vacío.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeOption {
    pub id: String,
    pub description: Option<Json>,
}

/// Una pregunta del bloque, ya evaluada (instrucción y criteria son valores, no AST).
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeQuestion {
    pub id: String,
    pub kind: JudgeKind,
    /// Texto u objeto: la API lee estructura y la aprovecha (verificado en vivo).
    pub instruction: Json,
    /// `choose`: opciones (sin la de escape); `rate`: niveles en orden; `whether`: vacío.
    pub options: Vec<JudgeOption>,
    /// `choose … or nothing`: el runtime agrega la opción [`ESCAPE_ID`] al cable.
    pub escape: bool,
    /// `whether`: descripciones opcionales de qué significa sí y qué significa no. Sin
    /// sintaxis en esta tanda; el tipo la lleva para que el cable no cambie cuando llegue.
    pub yes_no: Option<(Json, Json)>,
}

/// Lo que el intérprete entrega al provider: un `state` y sus preguntas, en una llamada.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeRequest {
    pub state: Json,
    pub questions: Vec<JudgeQuestion>,
}

/// Una respuesta, ya normalizada por el provider: ids del programa (no del cable),
/// `probabilities` en el orden de declaración, `level` calculado por argmax.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum JudgeAnswer {
    Whether {
        probability: f64,
    },
    Choose {
        /// `None` = ganó la opción de escape (`or nothing`).
        choice: Option<String>,
        probabilities: Vec<(String, f64)>,
        confidence: f64,
    },
    Rate {
        /// Posición ponderada sobre los niveles (0 = primero); puede caer entre dos.
        score: f64,
        /// Id del nivel con mayor probabilidad (argmax: aritmética, no invención).
        level: String,
        probabilities: Vec<(String, f64)>,
        confidence: f64,
    },
}

/// Respuesta completa de una llamada. `answers` va alineada con `questions` del pedido.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeResponse {
    pub answers: Vec<JudgeAnswer>,
    /// Id versionado que contestó (la doc del vendor recomienda loguearlo y pinearlo).
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Id de la opción de escape de `choose … or nothing` en la distribución y en el cable, y
/// su descripción fija. Es `none` y no `nothing` porque `nothing` es palabra reservada del
/// lenguaje: `v.team.probabilities.none` parsea, `.nothing` no. El VALOR de `choice` cuando
/// gana el escape sí es `nothing`, el null del lenguaje.
pub const ESCAPE_ID: &str = "none";
pub const ESCAPE_DESCRIPTION: &str = "None of the options fits the state";

/// Límites que la API cobra (verificados: 256 opciones → 400, 11 niveles → 400) y los
/// mínimos que cobramos nosotros (la API acepta una sola opción y contesta con confianza
/// 1,0: una respuesta vacía disfrazada de certeza).
pub const MAX_OPTIONS: usize = 255;
pub const MAX_LEVELS: usize = 10;
pub const MIN_OPTIONS: usize = 2;

/// Valida una pregunta antes de gastar la llamada. Los mismos mensajes los usa `check`
/// cuando las criteria son literales.
pub fn validate_question(q: &JudgeQuestion) -> Result<(), String> {
    let empty_instruction = match &q.instruction {
        Json::String(s) => s.trim().is_empty(),
        Json::Null => true,
        Json::Object(m) => m.is_empty(),
        Json::Array(a) => a.is_empty(),
        _ => false,
    };
    if empty_instruction && q.yes_no.is_none() {
        return Err(format!("judge '{}': the instruction is empty", q.id));
    }
    match q.kind {
        JudgeKind::Whether => Ok(()),
        JudgeKind::Choose => {
            if q.options.len() < MIN_OPTIONS {
                return Err(format!(
                    "judge '{}': choose needs at least {} options (got {}); with one option the model can only agree",
                    q.id, MIN_OPTIONS, q.options.len()
                ));
            }
            if q.options.len() > MAX_OPTIONS {
                return Err(format!(
                    "judge '{}': choose accepts at most {} options (got {})",
                    q.id, MAX_OPTIONS, q.options.len()
                ));
            }
            if q.escape && q.options.iter().any(|o| o.id == ESCAPE_ID) {
                return Err(format!(
                    "judge '{}': an option is named '{}' and the question also says 'or nothing'; rename the option",
                    q.id, ESCAPE_ID
                ));
            }
            check_duplicates(&q.id, "option", &q.options)
        }
        JudgeKind::Rate => {
            if q.options.len() < MIN_OPTIONS {
                return Err(format!(
                    "judge '{}': rate needs at least {} levels (got {})",
                    q.id, MIN_OPTIONS, q.options.len()
                ));
            }
            if q.options.len() > MAX_LEVELS {
                return Err(format!(
                    "judge '{}': rate accepts at most {} levels (got {}); merge levels you cannot describe distinctly",
                    q.id, MAX_LEVELS, q.options.len()
                ));
            }
            check_duplicates(&q.id, "level", &q.options)
        }
    }
}

fn check_duplicates(qid: &str, what: &str, opts: &[JudgeOption]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for o in opts {
        if o.id.trim().is_empty() {
            return Err(format!("judge '{}': an {} has an empty name", qid, what));
        }
        if !seen.insert(o.id.as_str()) {
            return Err(format!(
                "judge '{}': the {} '{}' is declared twice; each {} must be distinct",
                qid, what, o.id, what
            ));
        }
    }
    Ok(())
}

/// Convierte un valor del lenguaje al JSON que viaja como `state` o instrucción. Los
/// secretos se redactan por el `Display` del valor; los tipos sin forma JSON natural van
/// como texto.
pub fn syn_to_json(v: &SynValue) -> Json {
    match v {
        SynValue::Nothing => Json::Null,
        SynValue::Bool(b) => Json::Bool(*b),
        SynValue::Text(t) => Json::String(t.to_string()),
        SynValue::Number(n) => number_to_json(n),
        SynValue::List(l) => Json::Array(l.borrow().iter().map(syn_to_json).collect()),
        SynValue::Map(m) => Json::Object(
            m.borrow()
                .iter()
                .map(|(k, v)| (k.clone(), syn_to_json(v)))
                .collect(),
        ),
        other => Json::String(other.to_string()),
    }
}

fn number_to_json(n: &Number) -> Json {
    match n {
        Number::Int(i) => Json::from(*i),
        Number::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or_else(|| Json::String(f.to_string())),
        other => {
            let s = other.to_string();
            s.parse::<i64>()
                .map(Json::from)
                .or_else(|_| s.parse::<f64>().map(Json::from))
                .unwrap_or(Json::String(s))
        }
    }
}

/// `true` si el valor sirve como `state`: texto, map o list. Un número o un bool lo
/// rechaza la API (422), así que es un error del programa, no del servicio.
pub fn is_valid_state(v: &SynValue) -> bool {
    matches!(v, SynValue::Text(_) | SynValue::Map(_) | SynValue::List(_))
}

/// Convierte las criteria evaluadas (`between {…}` / `across […]`) a opciones. Una sola
/// regla para los dos verbos: lista → el ítem es id y descripción a la vez; map → la clave
/// es el id y el valor la descripción que ve el modelo.
pub fn options_from_value(v: &SynValue) -> Result<Vec<JudgeOption>, String> {
    match v {
        SynValue::List(l) => l
            .borrow()
            .iter()
            .map(|item| match item {
                SynValue::Text(t) => Ok(JudgeOption { id: t.to_string(), description: None }),
                SynValue::Number(n) => Ok(JudgeOption { id: n.to_string(), description: None }),
                other => Err(format!(
                    "options must be texts (got {}); use a map {{\"id\": \"description\"}} for structured descriptions",
                    other.type_name()
                )),
            })
            .collect(),
        SynValue::Map(m) => Ok(m
            .borrow()
            .iter()
            .map(|(k, v)| JudgeOption {
                id: k.clone(),
                description: match v {
                    SynValue::Nothing => None,
                    other => Some(syn_to_json(other)),
                },
            })
            .collect()),
        other => Err(format!(
            "options must be a list or a map (got {})",
            other.type_name()
        )),
    }
}

/// Confianza derivada de una distribución, `(n·max − 1)/(n − 1)`: es la estadística del
/// vendor y sirve **sólo** para el mock y para el adaptador `llm`. Con un provider real
/// se pasa la confianza que mandó la API; recalcularla sobre probabilidades redondeadas
/// difiere en la segunda cifra (verificado).
pub fn confidence_from(probs: &[f64]) -> f64 {
    let n = probs.len();
    if n < 2 {
        return if n == 1 { 1.0 } else { 0.0 };
    }
    let max = probs.iter().cloned().fold(f64::MIN, f64::max);
    ((n as f64 * max - 1.0) / (n as f64 - 1.0)).clamp(0.0, 1.0)
}

/// Id del nivel u opción con mayor probabilidad (el primero en caso de empate exacto).
pub fn argmax_id(probs: &[(String, f64)]) -> Option<String> {
    let mut best: Option<(&str, f64)> = None;
    for (id, p) in probs {
        match best {
            Some((_, bp)) if *p <= bp => {}
            _ => best = Some((id.as_str(), *p)),
        }
    }
    best.map(|(id, _)| id.to_string())
}

/// El valor que ve el programa para una pregunta. `answer == None` es la forma offline:
/// `available: false`, `confidence: 0`, y el valor principal en `nothing`, para que una
/// compuerta de confianza mande al humano sola y una comparación directa falle fuerte en
/// vez de tomar la rama equivocada en silencio.
pub fn answer_to_value(q: &JudgeQuestion, answer: Option<&JudgeAnswer>) -> SynValue {
    let mut m: IndexMap<String, SynValue> = IndexMap::new();
    // `kind` y no `type`: `type` es palabra reservada y `v.refund.type` no parsea.
    m.insert("kind".into(), syn_text(q.kind.verb()));
    let available = answer.is_some();
    match (q.kind, answer) {
        (JudgeKind::Whether, Some(JudgeAnswer::Whether { probability })) => {
            m.insert("probability".into(), float(*probability));
        }
        (JudgeKind::Whether, _) => {
            m.insert("probability".into(), SynValue::Nothing);
        }
        (JudgeKind::Choose, Some(JudgeAnswer::Choose { choice, probabilities, confidence })) => {
            m.insert(
                "choice".into(),
                choice.as_ref().map(|c| syn_text(c.as_str())).unwrap_or(SynValue::Nothing),
            );
            m.insert("probabilities".into(), probs_map(probabilities));
            m.insert("confidence".into(), float(*confidence));
        }
        (JudgeKind::Choose, _) => {
            m.insert("choice".into(), SynValue::Nothing);
            m.insert("probabilities".into(), syn_map(IndexMap::new()));
            m.insert("confidence".into(), float(0.0));
        }
        (JudgeKind::Rate, Some(JudgeAnswer::Rate { score, level, probabilities, confidence })) => {
            m.insert("score".into(), float(*score));
            m.insert("level".into(), syn_text(level.as_str()));
            m.insert("levels".into(), levels_list(q));
            m.insert("probabilities".into(), probs_map(probabilities));
            m.insert("confidence".into(), float(*confidence));
        }
        (JudgeKind::Rate, _) => {
            m.insert("score".into(), SynValue::Nothing);
            m.insert("level".into(), SynValue::Nothing);
            m.insert("levels".into(), levels_list(q));
            m.insert("probabilities".into(), syn_map(IndexMap::new()));
            m.insert("confidence".into(), float(0.0));
        }
    }
    m.insert("available".into(), syn_bool(available));
    syn_map(m)
}

fn float(f: f64) -> SynValue {
    syn_number(Number::Float(f))
}

fn probs_map(probs: &[(String, f64)]) -> SynValue {
    let mut pm: IndexMap<String, SynValue> = IndexMap::new();
    for (id, p) in probs {
        pm.insert(id.clone(), float(*p));
    }
    syn_map(pm)
}

fn levels_list(q: &JudgeQuestion) -> SynValue {
    syn_list(q.options.iter().map(|o| syn_text(o.id.as_str())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(kind: JudgeKind, ids: &[&str]) -> JudgeQuestion {
        JudgeQuestion {
            id: "q".into(),
            kind,
            instruction: Json::String("Is it?".into()),
            options: ids.iter().map(|s| JudgeOption { id: s.to_string(), description: None }).collect(),
            escape: false,
            yes_no: None,
        }
    }

    #[test]
    fn limits_are_ours_and_theirs() {
        assert!(validate_question(&q(JudgeKind::Choose, &["a"])).unwrap_err().contains("at least 2"));
        let many: Vec<String> = (0..256).map(|i| format!("o{}", i)).collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        assert!(validate_question(&q(JudgeKind::Choose, &refs)).unwrap_err().contains("at most 255"));
        let eleven: Vec<String> = (0..11).map(|i| format!("l{}", i)).collect();
        let refs: Vec<&str> = eleven.iter().map(|s| s.as_str()).collect();
        assert!(validate_question(&q(JudgeKind::Rate, &refs)).unwrap_err().contains("at most 10"));
        assert!(validate_question(&q(JudgeKind::Rate, &["a", "a"])).unwrap_err().contains("declared twice"));
        assert!(validate_question(&q(JudgeKind::Choose, &["a", "b"])).is_ok());
        assert!(validate_question(&q(JudgeKind::Whether, &[])).is_ok());
    }

    #[test]
    fn empty_instruction_is_an_error_unless_yes_no() {
        let mut w = q(JudgeKind::Whether, &[]);
        w.instruction = Json::String("   ".into());
        assert!(validate_question(&w).unwrap_err().contains("instruction is empty"));
        w.yes_no = Some((Json::String("yes".into()), Json::String("no".into())));
        assert!(validate_question(&w).is_ok());
    }

    #[test]
    fn escape_collides_with_an_option_named_nothing() {
        let mut c = q(JudgeKind::Choose, &["none", "b"]);
        c.escape = true;
        assert!(validate_question(&c).unwrap_err().contains("or nothing"));
    }

    #[test]
    fn confidence_formula_matches_vendor_demo() {
        assert!((confidence_from(&[0.97, 0.03]) - 0.94).abs() < 1e-9);
        assert_eq!(confidence_from(&[1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]).round(), 0.0);
        assert_eq!(confidence_from(&[1.0, 0.0, 0.0]), 1.0);
    }

    #[test]
    fn argmax_takes_first_on_tie() {
        let p = vec![("a".to_string(), 0.4), ("b".to_string(), 0.4), ("c".to_string(), 0.2)];
        assert_eq!(argmax_id(&p).as_deref(), Some("a"));
    }

    #[test]
    fn offline_shape_has_nothing_and_zero_confidence() {
        let c = q(JudgeKind::Choose, &["a", "b"]);
        let v = answer_to_value(&c, None);
        let s = v.to_string();
        assert!(s.contains("\"available\": false") || s.contains("available"), "{}", s);
        if let SynValue::Map(m) = v {
            let m = m.borrow();
            assert!(matches!(m.get("choice"), Some(SynValue::Nothing)));
            assert!(matches!(m.get("available"), Some(SynValue::Bool(false))));
            assert!(matches!(m.get("kind"), Some(SynValue::Text(t)) if &**t == "choose"));
        } else {
            panic!("not a map");
        }
    }

    #[test]
    fn options_from_list_and_map_follow_one_rule() {
        let list = syn_list(vec![syn_text("Calm"), syn_text("Angry")]);
        let o = options_from_value(&list).unwrap();
        assert_eq!(o[0].id, "Calm");
        assert!(o[0].description.is_none());
        let mut m = IndexMap::new();
        m.insert("calm".to_string(), syn_text("Polite, no complaint"));
        m.insert("angry".to_string(), SynValue::Nothing);
        let o = options_from_value(&syn_map(m)).unwrap();
        assert_eq!(o[0].id, "calm");
        assert_eq!(o[0].description, Some(Json::String("Polite, no complaint".into())));
        assert!(o[1].description.is_none());
        assert!(options_from_value(&syn_text("x")).is_err());
    }
}
