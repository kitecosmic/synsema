//! Provider HTTP del primitivo `judge` (System One) y su configuración por knobs.
//!
//! Slot PARALELO al de LLM (`SYNSEMA_JUDGE_*`, independiente de `SYNSEMA_LLM_*`): los dos
//! pueden estar cableados a la vez y es lo normal. La clave nunca entra al programa: la
//! resuelve el runtime del environ o del `.env` protegido, y el host lo fija el knob
//! `SYNSEMA_JUDGE_BASE_URL`, no el `.syn`.
//!
//! Forma del código, casa: el **armado del body** y el **parseo de la respuesta** son
//! funciones puras con fixtures; el `impl` sólo postea. Verificado en vivo (spec §1.2):
//! - el cable no preserva el orden de `probabilities` → acá se reordena a la declaración;
//! - `score` teclea `probabilities` por índice `"0".."n"` → acá se mapea a los ids;
//! - `confidence` y `noul` se pasan tal cual, nunca se recalculan;
//! - el cuerpo de error trae `detail` en tres formas (string, objeto, lista) → las tres.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value as Json};
use synsema_core::judge::{
    argmax_id, JudgeAnswer, JudgeKind, JudgeRequest, JudgeResponse, ESCAPE_DESCRIPTION, ESCAPE_ID,
};
use synsema_llm::judge::{JudgeCall, JudgeProvider, MockJudgeProvider};
use synsema_stdlib::http::http_request;
use synsema_stdlib::secrets::EnvStore;

use crate::llm_providers::resolve_knob;

/// Knobs del slot `judge`. Lista canónica: va también al template de `init` (con el sha LF
/// previo en `ENV_EXAMPLE_PAST`) y a la lista de nombres sensibles del proceso.
pub const JUDGE_ENV_VARS: &[&str] = &[
    "SYNSEMA_JUDGE_PROVIDER",
    "SYNSEMA_JUDGE_MODEL",
    "SYNSEMA_JUDGE_BASE_URL",
    "SYNSEMA_JUDGE_TIMEOUT",
    "SYNSEMA_JUDGE_BUDGET",
    "TYPESAFE_API_KEY",
];

pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";
pub const DEFAULT_MODEL: &str = "jev-latest";
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Intentos totales ante 429/529 (el primero + tres reintentos), con backoff exponencial
/// desde medio segundo, tope ocho, honrando `retry-after` si viene.
const MAX_ATTEMPTS: u32 = 4;

// ---- Metering del proceso -------------------------------------------------------------

static JUDGE_INPUT_TOKENS: AtomicU64 = AtomicU64::new(0);
static JUDGE_OUTPUT_TOKENS: AtomicU64 = AtomicU64::new(0);
static JUDGE_BUDGET_NOTICED: AtomicBool = AtomicBool::new(false);
static JUDGE_LAST_MODEL: Mutex<Option<String>> = Mutex::new(None);

/// Tokens de ENTRADA acumulados del proceso (la salida es gratis en el vendor; se cuenta
/// aparte para el audit pero no entra al presupuesto). Lo expone `judge_usage()`.
pub fn judge_tokens_total() -> u64 {
    JUDGE_INPUT_TOKENS.load(Ordering::Relaxed)
}

pub fn judge_output_tokens_total() -> u64 {
    JUDGE_OUTPUT_TOKENS.load(Ordering::Relaxed)
}

/// Id versionado que contestó la última llamada (`jev-1.13.0`, no el alias). Lo expone
/// `judge_model()`; la doc del vendor recomienda loguearlo y pinear umbrales a él.
pub fn judge_last_model() -> Option<String> {
    JUDGE_LAST_MODEL.lock().ok().and_then(|m| m.clone())
}

fn record_usage(resp: &JudgeResponse) {
    JUDGE_INPUT_TOKENS.fetch_add(resp.input_tokens, Ordering::Relaxed);
    JUDGE_OUTPUT_TOKENS.fetch_add(resp.output_tokens, Ordering::Relaxed);
    if let Ok(mut m) = JUDGE_LAST_MODEL.lock() {
        *m = Some(resp.model.clone());
    }
}

// ---- Configuración --------------------------------------------------------------------

/// Config resuelta del slot. Resolución environ del proceso > `.env` protegido > default,
/// idéntica a la de LLM.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeConfig {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub timeout_secs: u64,
    pub budget: Option<u64>,
    pub has_key: bool,
}

pub fn config_from_store(store: &EnvStore) -> JudgeConfig {
    let key = resolve_knob("TYPESAFE_API_KEY", store).filter(|k| !k.trim().is_empty());
    let provider = resolve_knob("SYNSEMA_JUDGE_PROVIDER", store)
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| if key.is_some() { "typesafe".to_string() } else { "none".to_string() });
    let timeout_secs = resolve_knob("SYNSEMA_JUDGE_TIMEOUT", store)
        .and_then(|t| t.trim().parse::<u64>().ok())
        .filter(|t| *t > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let budget = resolve_knob("SYNSEMA_JUDGE_BUDGET", store)
        .and_then(|b| b.trim().parse::<u64>().ok())
        .filter(|b| *b > 0);
    JudgeConfig {
        provider,
        model: resolve_knob("SYNSEMA_JUDGE_MODEL", store)
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string()),
        base_url: resolve_knob("SYNSEMA_JUDGE_BASE_URL", store)
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        timeout_secs,
        budget,
        has_key: key.is_some(),
    }
}

/// El provider cableable, o `None` si el slot está offline. `mock` sirve el determinista de
/// `synsema-llm` (tests y demos sin clave). Un provider desconocido avisa y queda offline:
/// mejor `available: false` que una llamada a un host que no es.
pub fn provider_from_config(store: &EnvStore) -> Option<Arc<WiredJudgeProvider>> {
    let cfg = config_from_store(store);
    let inner: Arc<dyn JudgeProvider> = match cfg.provider.as_str() {
        "typesafe" => {
            let key = resolve_knob("TYPESAFE_API_KEY", store)?;
            Arc::new(TypeSafeJudgeProvider {
                api_key: key,
                model: cfg.model.clone(),
                base_url: cfg.base_url.clone(),
                timeout_secs: cfg.timeout_secs,
            })
        }
        "mock" => Arc::new(MockJudgeProvider::new()),
        "none" => return None,
        other => {
            eprintln!(
                "[synsema] notice: SYNSEMA_JUDGE_PROVIDER='{}' is not a judge provider (typesafe | mock); \
                 judge stays OFFLINE",
                other
            );
            return None;
        }
    };
    Some(Arc::new(WiredJudgeProvider { inner, budget: cfg.budget }))
}

/// Envoltura que aplica el presupuesto y el metering a cualquier backend, y traduce
/// [`JudgeCall`] al contrato del intérprete (`Ok(None)` = no disponible, `Err` = rechazo).
pub struct WiredJudgeProvider {
    inner: Arc<dyn JudgeProvider>,
    budget: Option<u64>,
}

impl WiredJudgeProvider {
    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn calibrated(&self) -> bool {
        self.inner.calibrated()
    }

    pub fn judge_for_interpreter(&self, req: &JudgeRequest) -> Result<Option<JudgeResponse>, String> {
        if let Some(cap) = self.budget {
            if judge_tokens_total() >= cap {
                if !JUDGE_BUDGET_NOTICED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "[synsema] notice: SYNSEMA_JUDGE_BUDGET={} reached ({} input tokens used): judge answers \
                         degrade to available: false, no network call is made. judge_usage() reports the total.",
                        cap,
                        judge_tokens_total()
                    );
                }
                return Ok(None);
            }
        }
        match self.inner.judge(req) {
            JudgeCall::Answered(resp) => {
                record_usage(&resp);
                Ok(Some(resp))
            }
            JudgeCall::Unavailable(why) => {
                eprintln!("[synsema] notice: judge unavailable ({}); answers degrade to available: false", why);
                Ok(None)
            }
            JudgeCall::Rejected(msg) => Err(msg),
            #[allow(unreachable_patterns)]
            _ => Ok(None),
        }
    }
}

// ---- El backend TypeSafe (y todo host que sirva el mismo cable) --------------------------

pub struct TypeSafeJudgeProvider {
    api_key: String,
    model: String,
    base_url: String,
    timeout_secs: u64,
}

impl TypeSafeJudgeProvider {
    fn endpoint(&self) -> String {
        format!("{}/v1/systemone", self.base_url)
    }

    fn headers(&self) -> [(String, String); 2] {
        [
            ("authorization".to_string(), format!("Bearer {}", self.api_key)),
            ("content-type".to_string(), "application/json".to_string()),
        ]
    }
}

impl JudgeProvider for TypeSafeJudgeProvider {
    fn judge(&self, request: &JudgeRequest) -> JudgeCall {
        let body = build_body(request, &self.model).to_string();
        let url = self.endpoint();
        let headers = self.headers();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let r = http_request("POST", &url, Some(&headers), None, Some(&body), self.timeout_secs);
            if let Some(e) = r.error {
                return JudgeCall::Unavailable(format!("network error calling {}: {}", url, e));
            }
            match r.status {
                200 => {
                    return match parse_response(&r.body, request) {
                        Ok(resp) => JudgeCall::Answered(resp),
                        Err(e) => JudgeCall::Unavailable(format!("malformed judge response: {}", e)),
                    };
                }
                429 | 529 if attempt < MAX_ATTEMPTS => {
                    let wait = retry_delay(attempt, &r.headers);
                    std::thread::sleep(wait);
                    continue;
                }
                429 | 529 => {
                    return JudgeCall::Unavailable(format!(
                        "judge API answered {} after {} attempts",
                        r.status, attempt
                    ));
                }
                400 | 422 => return JudgeCall::Rejected(error_message(r.status, &r.body)),
                401 => {
                    return JudgeCall::Unavailable(format!(
                        "judge API rejected the key (401): {}",
                        error_message(401, &r.body)
                    ));
                }
                other => {
                    return JudgeCall::Unavailable(format!(
                        "judge API answered {}: {}",
                        other,
                        error_message(other, &r.body)
                    ));
                }
            }
        }
    }

    fn name(&self) -> String {
        "typesafe".to_string()
    }
}

/// Backoff exponencial desde medio segundo, tope ocho, o lo que diga `retry-after`
/// (segundos) si el header viene y es razonable.
fn retry_delay(attempt: u32, headers: &[(String, String)]) -> Duration {
    let from_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0 && *s <= 30);
    match from_header {
        Some(secs) => Duration::from_secs(secs),
        None => Duration::from_millis((500u64 << (attempt - 1).min(4)).min(8_000)),
    }
}

// ---- Funciones puras: cable ↔ tipos ---------------------------------------------------

/// El body exacto que espera `POST /v1/systemone`. Manda sólo los campos documentados: un
/// campo desconocido a nivel raíz es 400 (verificado).
pub fn build_body(req: &JudgeRequest, model: &str) -> Json {
    let mut questions = serde_json::Map::new();
    for q in &req.questions {
        let mut body = serde_json::Map::new();
        match q.kind {
            JudgeKind::Whether => {
                body.insert("type".into(), json!("noul"));
                body.insert("instructions".into(), q.instruction.clone());
                if let Some((yes, no)) = &q.yes_no {
                    body.insert("criteria".into(), json!({ "true": yes, "false": no }));
                }
            }
            JudgeKind::Choose => {
                body.insert("type".into(), json!("choice"));
                body.insert("instructions".into(), q.instruction.clone());
                let mut criteria = serde_json::Map::new();
                for o in &q.options {
                    criteria.insert(o.id.clone(), o.description.clone().unwrap_or(Json::Null));
                }
                if q.escape {
                    criteria.insert(ESCAPE_ID.to_string(), json!(ESCAPE_DESCRIPTION));
                }
                body.insert("criteria".into(), Json::Object(criteria));
            }
            JudgeKind::Rate => {
                body.insert("type".into(), json!("score"));
                body.insert("instructions".into(), q.instruction.clone());
                // Forma lista: el id es la descripción. Forma map: el nivel viaja como
                // `{"<id>": "<descripción>"}` para que el id lo vea el modelo, igual que las
                // claves de `choose` (verificado: funciona igual que texto plano).
                let levels: Vec<Json> = q
                    .options
                    .iter()
                    .map(|o| match &o.description {
                        None => json!(o.id),
                        Some(d) => json!({ o.id.clone(): d }),
                    })
                    .collect();
                body.insert("criteria".into(), Json::Array(levels));
            }
        }
        questions.insert(q.id.clone(), Json::Object(body));
    }
    json!({ "state": req.state, "model": model, "questions": Json::Object(questions) })
}

/// Normaliza la respuesta del cable a [`JudgeResponse`], alineada con las preguntas del
/// pedido. Cualquier campo faltante o de tipo raro es `Err` (→ `available: false` con
/// aviso, nunca un número inventado).
pub fn parse_response(body: &str, req: &JudgeRequest) -> Result<JudgeResponse, String> {
    let v: Json = serde_json::from_str(body).map_err(|e| format!("not JSON: {}", e))?;
    let model = v
        .get("model")
        .and_then(Json::as_str)
        .ok_or("missing 'model'")?
        .to_string();
    let answers_obj = v
        .get("answers")
        .and_then(Json::as_object)
        .ok_or("missing 'answers'")?;
    let usage = v.get("usage").cloned().unwrap_or(Json::Null);
    let input_tokens = usage.get("input_tokens").and_then(Json::as_u64).unwrap_or(0);
    let output_tokens = usage.get("output_tokens").and_then(Json::as_u64).unwrap_or(0);

    let mut answers = Vec::with_capacity(req.questions.len());
    for q in &req.questions {
        let a = answers_obj
            .get(&q.id)
            .ok_or_else(|| format!("no answer for question '{}'", q.id))?;
        let ans = match q.kind {
            JudgeKind::Whether => JudgeAnswer::Whether {
                probability: num(a, "noul", &q.id)?,
            },
            JudgeKind::Choose => {
                let wire_probs = a
                    .get("probabilities")
                    .and_then(Json::as_object)
                    .ok_or_else(|| format!("'{}': missing probabilities", q.id))?;
                let mut probabilities: Vec<(String, f64)> = Vec::with_capacity(q.options.len() + 1);
                for o in &q.options {
                    probabilities.push((o.id.clone(), prob_of(wire_probs, &o.id, &q.id)?));
                }
                if q.escape {
                    probabilities.push((ESCAPE_ID.to_string(), prob_of(wire_probs, ESCAPE_ID, &q.id)?));
                }
                let wire_choice = a
                    .get("choice")
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("'{}': missing choice", q.id))?;
                let choice = if q.escape && wire_choice == ESCAPE_ID {
                    None
                } else if q.options.iter().any(|o| o.id == wire_choice) {
                    Some(wire_choice.to_string())
                } else {
                    return Err(format!(
                        "'{}': the API chose '{}', which is not one of the declared options",
                        q.id, wire_choice
                    ));
                };
                JudgeAnswer::Choose {
                    choice,
                    probabilities,
                    confidence: num(a, "confidence", &q.id)?,
                }
            }
            JudgeKind::Rate => {
                let wire_probs = a
                    .get("probabilities")
                    .and_then(Json::as_object)
                    .ok_or_else(|| format!("'{}': missing probabilities", q.id))?;
                let mut probabilities: Vec<(String, f64)> = Vec::with_capacity(q.options.len());
                for (i, o) in q.options.iter().enumerate() {
                    probabilities.push((o.id.clone(), prob_of(wire_probs, &i.to_string(), &q.id)?));
                }
                let level = argmax_id(&probabilities).ok_or_else(|| format!("'{}': no levels", q.id))?;
                JudgeAnswer::Rate {
                    score: num(a, "score", &q.id)?,
                    level,
                    probabilities,
                    confidence: num(a, "confidence", &q.id)?,
                }
            }
        };
        answers.push(ans);
    }
    Ok(JudgeResponse { answers, model, input_tokens, output_tokens })
}

fn num(a: &Json, field: &str, qid: &str) -> Result<f64, String> {
    a.get(field)
        .and_then(Json::as_f64)
        .ok_or_else(|| format!("'{}': missing or non-numeric '{}'", qid, field))
}

fn prob_of(probs: &serde_json::Map<String, Json>, key: &str, qid: &str) -> Result<f64, String> {
    probs
        .get(key)
        .and_then(Json::as_f64)
        .ok_or_else(|| format!("'{}': no probability for '{}'", qid, key))
}

/// El mensaje legible de un cuerpo de error. `detail` viene en tres formas (verificado):
/// string (400 semántico), objeto `{error_type, message}` (400 de uso / 401) o lista
/// pydantic `[{loc, msg, …}]` (422 de esquema). Sin `detail`, el crudo recortado.
pub fn error_message(status: i64, body: &str) -> String {
    let parsed: Option<Json> = serde_json::from_str(body).ok();
    let detail = parsed.as_ref().and_then(|v| v.get("detail"));
    let msg = match detail {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Object(o)) => {
            let m = o.get("message").and_then(Json::as_str).unwrap_or("");
            let t = o.get("error_type").and_then(Json::as_str).unwrap_or("");
            match (t.is_empty(), m.is_empty()) {
                (false, false) => format!("{}: {}", t, m),
                (true, false) => m.to_string(),
                (false, true) => t.to_string(),
                (true, true) => Json::Object(o.clone()).to_string(),
            }
        }
        Some(Json::Array(items)) => items
            .iter()
            .map(|it| {
                let loc = it
                    .get("loc")
                    .and_then(Json::as_array)
                    .map(|l| l.iter().map(|p| p.to_string().trim_matches('"').to_string()).collect::<Vec<_>>().join("."))
                    .unwrap_or_default();
                let m = it.get("msg").and_then(Json::as_str).unwrap_or("invalid");
                if loc.is_empty() { m.to_string() } else { format!("{}: {}", loc, m) }
            })
            .collect::<Vec<_>>()
            .join("; "),
        _ => body.chars().take(300).collect(),
    };
    format!("judge API rejected the request ({}): {}", status, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::judge::{JudgeOption, JudgeQuestion};

    fn opt(id: &str, desc: Option<&str>) -> JudgeOption {
        JudgeOption { id: id.into(), description: desc.map(|d| json!(d)) }
    }

    fn ticket_request() -> JudgeRequest {
        JudgeRequest {
            state: json!({"ticket": "Help! I want my money back."}),
            questions: vec![
                JudgeQuestion {
                    id: "refund".into(),
                    kind: JudgeKind::Whether,
                    instruction: json!("The customer is asking for money back"),
                    options: vec![],
                    escape: false,
                    yes_no: None,
                },
                JudgeQuestion {
                    id: "team".into(),
                    kind: JudgeKind::Choose,
                    instruction: json!("Which team should handle this?"),
                    options: vec![opt("billing", Some("Payments")), opt("technical", Some("Bugs"))],
                    escape: true,
                    yes_no: None,
                },
                JudgeQuestion {
                    id: "anger".into(),
                    kind: JudgeKind::Rate,
                    instruction: json!("How frustrated is the customer?"),
                    options: vec![opt("calm", Some("Polite")), opt("angry", Some("Caps or threats"))],
                    escape: false,
                    yes_no: None,
                },
            ],
        }
    }

    #[test]
    fn body_uses_the_wire_names_and_adds_the_escape_option() {
        let b = build_body(&ticket_request(), "jev-latest");
        assert_eq!(b["model"], "jev-latest");
        assert_eq!(b["questions"]["refund"]["type"], "noul");
        assert_eq!(b["questions"]["team"]["type"], "choice");
        assert_eq!(b["questions"]["team"]["criteria"]["none"], ESCAPE_DESCRIPTION);
        assert_eq!(b["questions"]["team"]["criteria"]["billing"], "Payments");
        assert_eq!(b["questions"]["anger"]["type"], "score");
        // nivel con id visible: {"calm": "Polite"}
        assert_eq!(b["questions"]["anger"]["criteria"][0]["calm"], "Polite");
        assert!(b.get("foo").is_none());
    }

    #[test]
    fn list_form_levels_travel_as_plain_text() {
        let mut req = ticket_request();
        req.questions[2].options = vec![opt("Calm", None), opt("Angry", None)];
        let b = build_body(&req, "m");
        assert_eq!(b["questions"]["anger"]["criteria"], json!(["Calm", "Angry"]));
        req.questions[1].options = vec![opt("a", None), opt("b", None)];
        let b = build_body(&req, "m");
        assert_eq!(b["questions"]["team"]["criteria"]["a"], Json::Null);
    }

    #[test]
    fn response_is_reordered_mapped_and_escape_aware() {
        // Cable real (2026-09-20): probabilities de choice fuera de orden; score por índice.
        let wire = r#"{"model":"jev-1.13.0","answers":{
            "refund":{"type":"noul","noul":0.97},
            "team":{"type":"choice","choice":"none","confidence":0.93,"probabilities":{"technical":0.02,"none":0.97,"billing":0.01}},
            "anger":{"type":"score","score":0.94,"confidence":0.3,"legend":{"0":"calm","1":"angry"},"probabilities":{"1":0.6,"0":0.4}}},
            "usage":{"input_tokens":438,"output_tokens":61}}"#;
        let r = parse_response(wire, &ticket_request()).unwrap();
        assert_eq!(r.model, "jev-1.13.0");
        assert_eq!((r.input_tokens, r.output_tokens), (438, 61));
        assert_eq!(r.answers[0], JudgeAnswer::Whether { probability: 0.97 });
        match &r.answers[1] {
            JudgeAnswer::Choose { choice, probabilities, confidence } => {
                assert!(choice.is_none(), "escape wins → nothing");
                let ids: Vec<&str> = probabilities.iter().map(|p| p.0.as_str()).collect();
                assert_eq!(ids, ["billing", "technical", "none"], "declaration order, escape last");
                assert_eq!(*confidence, 0.93, "confidence is passed through, never recomputed");
            }
            other => panic!("{:?}", other),
        }
        match &r.answers[2] {
            JudgeAnswer::Rate { score, level, probabilities, .. } => {
                assert_eq!(*score, 0.94);
                assert_eq!(level, "angry", "argmax over the mapped ids");
                assert_eq!(probabilities[0], ("calm".to_string(), 0.4));
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn response_missing_pieces_is_an_error_not_a_guess() {
        let req = ticket_request();
        assert!(parse_response("not json", &req).is_err());
        assert!(parse_response(r#"{"model":"m","answers":{}}"#, &req).unwrap_err().contains("no answer for question 'refund'"));
        let bad_choice = r#"{"model":"m","answers":{"refund":{"noul":0.5},"team":{"choice":"sales","confidence":1,"probabilities":{"billing":0,"technical":0,"none":0}},"anger":{"score":0,"confidence":1,"probabilities":{"0":1,"1":0}}}}"#;
        assert!(parse_response(bad_choice, &req).unwrap_err().contains("not one of the declared options"));
    }

    #[test]
    fn error_detail_in_its_three_shapes() {
        assert_eq!(
            error_message(400, r#"{"detail":"Too many score levels. Must have at most 10 levels."}"#),
            "judge API rejected the request (400): Too many score levels. Must have at most 10 levels."
        );
        assert!(error_message(401, r#"{"detail":{"error_type":"authentication_error","message":"Cannot authenticate"}}"#)
            .contains("authentication_error: Cannot authenticate"));
        let pyd = r#"{"detail":[{"type":"missing","loc":["body","model"],"msg":"Field required"}]}"#;
        assert!(error_message(422, pyd).contains("body.model: Field required"));
        assert!(error_message(500, "<html>oops</html>").contains("<html>oops</html>"));
    }

    #[test]
    fn retry_delay_honours_header_and_backs_off() {
        assert_eq!(retry_delay(1, &[]), Duration::from_millis(500));
        assert_eq!(retry_delay(2, &[]), Duration::from_millis(1000));
        assert_eq!(retry_delay(3, &[]), Duration::from_millis(2000));
        assert_eq!(retry_delay(1, &[("Retry-After".into(), "3".into())]), Duration::from_secs(3));
        assert_eq!(retry_delay(1, &[("retry-after".into(), "9999".into())]), Duration::from_millis(500));
    }
}
