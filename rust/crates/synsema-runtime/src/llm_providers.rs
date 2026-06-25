//! Providers LLM reales (HTTP). Conectividad de las ops `reason`/`decide`/`analyze`/
//! `generate` y del primitivo `llm_step` con un modelo real (Anthropic primero,
//! OpenAI/compatible segundo).
//!
//! Diseño:
//! - El trait/contrato (`LLMProvider` + tipos + `MockProvider`) vive en `synsema-llm`,
//!   sin red. ACÁ (en `synsema-runtime`) está la capa de red, que sólo orquesta
//!   `synsema_stdlib::http::http_request` y usa `serde_json` para armar/parsear el JSON.
//! - La construcción del body y el parseo de la respuesta son **funciones puras**
//!   (testeables con fixtures, sin tocar la red). El `impl LLMProvider` sólo hace el
//!   POST y delega en ellas.
//! - Un error de red o de parseo NUNCA panica ni corta el loop en-lenguaje: se devuelve
//!   un `Final` con texto `"[<provider> error: <detalle>]"` y 0 tokens.
//!
//! Conectividad LIBRE (los knobs los elige el usuario por env; el runtime no impone
//! límites): `SYNSEMA_LLM_MODEL` (modelo), `SYNSEMA_LLM_MAX_TOKENS` (tope de salida),
//! `SYNSEMA_LLM_BASE_URL` (endpoint → modelos LOCALES OpenAI-compatibles: Ollama/LM
//! Studio/vLLM/llama.cpp). Gating: lo controla `require llm` (en core/runtime);
//! `http_request` de stdlib NO chequea `net` — el host lo fija el runtime por env.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use synsema_llm::provider::{
    LLMProvider, LLMRequest, LLMResponse, LlmStep, LlmStepResponse, ToolSpec,
};
use synsema_stdlib::http::http_request;

const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Default de tokens de salida por request. La API de Anthropic OBLIGA a mandar el
/// parámetro; el VALOR lo elige el usuario por `SYNSEMA_LLM_MAX_TOKENS`. 1024 cortaba
/// respuestas de agente — 4096 es un default más razonable.
const DEFAULT_MAX_TOKENS: u64 = 4096;
/// Timeout de la llamada HTTP, en segundos.
const TIMEOUT_SECS: u64 = 60;

/// Base-URL oficial de Anthropic (override por `SYNSEMA_LLM_BASE_URL`).
const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
/// Base-URL oficial de OpenAI (override por `SYNSEMA_LLM_BASE_URL` → modelos LOCALES
/// OpenAI-compatibles, ej. `http://localhost:11434/v1` para Ollama).
const OPENAI_DEFAULT_BASE: &str = "https://api.openai.com/v1";

/// Default de Anthropic: **Sonnet** (más barato) por seguridad de costo. Opus es
/// opt-in vía `SYNSEMA_LLM_MODEL=claude-opus-4-8` — así nadie quema plata sin querer.
pub const ANTHROPIC_DEFAULT_MODEL: &str = "claude-sonnet-4-6";
/// Default de OpenAI (configurable por `SYNSEMA_LLM_MODEL`; para local poné el tuyo).
pub const OPENAI_DEFAULT_MODEL: &str = "gpt-4o";

// =========================================================
// Helpers puros compartidos
// =========================================================

/// Endpoint de Anthropic Messages: `{base}/v1/messages`. El base oficial NO incluye `/v1`.
pub fn anthropic_endpoint(base: &str) -> String {
    format!("{}/v1/messages", base.trim_end_matches('/'))
}

/// Endpoint OpenAI-compatible: `{base}/chat/completions`. El base SÍ incluye `/v1`
/// (ej. Ollama `http://localhost:11434/v1` → `…/v1/chat/completions`).
pub fn openai_endpoint(base: &str) -> String {
    format!("{}/chat/completions", base.trim_end_matches('/'))
}

/// Combina prompt + contexto en el `content` del mensaje user (contexto opcional).
fn user_content(user_prompt: &str, context: &str) -> String {
    if context.is_empty() {
        user_prompt.to_string()
    } else {
        format!("{}\n{}", user_prompt, context)
    }
}

/// Stringifica un valor JSON para un arg de tool: los strings pierden las comillas;
/// el resto se serializa canónico (números, bools, objetos anidados, …).
fn stringify_json(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `properties` de un input-schema: cada param → `{"type":"string"}`.
fn string_properties(params: &[String]) -> Value {
    let mut props = Map::new();
    for p in params {
        props.insert(p.clone(), json!({ "type": "string" }));
    }
    Value::Object(props)
}

/// Mensaje de error de la API (clave `error.message`), o el JSON crudo si no está.
fn api_error_message(err: &Value) -> String {
    err.get("message")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| err.to_string())
}

// =========================================================
// Anthropic
// =========================================================

/// Arma el body JSON para `POST /v1/messages`. Si `tools` está vacío, OMITE la clave
/// `tools`. NO manda `temperature`/`top_p`/`top_k`/`thinking` (dan 400 en modelos
/// actuales).
pub fn build_anthropic_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    tools: &[ToolSpec],
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
    });
    if !tools.is_empty() {
        let arr: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": {
                        "type": "object",
                        "properties": string_properties(&t.params),
                        "required": t.params,
                    }
                })
            })
            .collect();
        body["tools"] = Value::Array(arr);
    }
    body.to_string()
}

/// tokens = `usage.input_tokens + usage.output_tokens`.
fn anthropic_tokens(v: &Value) -> u64 {
    let usage = v.get("usage");
    let inp = usage.and_then(|u| u.get("input_tokens")).and_then(Value::as_u64).unwrap_or(0);
    let out = usage.and_then(|u| u.get("output_tokens")).and_then(Value::as_u64).unwrap_or(0);
    inp + out
}

/// Concatena el texto de los bloques `{"type":"text","text":..}`.
fn anthropic_concat_text(content: &[Value]) -> String {
    let mut out = String::new();
    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(t) = block.get("text").and_then(Value::as_str) {
                out.push_str(t);
            }
        }
    }
    out
}

/// Parsea la respuesta de Anthropic como un PASO tool-aware: un bloque `tool_use` →
/// `ToolCall`; si no, concatena los `text` → `Final`. tokens de `usage`.
pub fn parse_anthropic_step(json_str: &str) -> Result<(LlmStep, u64), String> {
    let v: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(api_error_message(err));
    }
    let tokens = anthropic_tokens(&v);
    let content = v
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| "anthropic: respuesta sin array `content`".to_string())?;
    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("tool_use") {
            let name = block.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let args = match block.get("input") {
                Some(Value::Object(m)) => {
                    m.iter().map(|(k, val)| (k.clone(), stringify_json(val))).collect()
                }
                _ => Vec::new(),
            };
            return Ok((LlmStep::ToolCall { name, args }, tokens));
        }
    }
    Ok((LlmStep::Final(anthropic_concat_text(content)), tokens))
}

/// Parsea la respuesta de Anthropic como TEXTO (concatena los bloques `text`).
pub fn parse_anthropic_text(json_str: &str) -> Result<(String, u64), String> {
    let v: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(api_error_message(err));
    }
    let tokens = anthropic_tokens(&v);
    let content = v
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| "anthropic: respuesta sin array `content`".to_string())?;
    Ok((anthropic_concat_text(content), tokens))
}

/// Provider real de Anthropic (`{base}/v1/messages`).
pub struct AnthropicProvider {
    pub api_key: String,
    pub model: String,
    /// Tope de tokens de salida (configurable por `SYNSEMA_LLM_MAX_TOKENS`).
    pub max_tokens: u64,
    /// Base-URL (configurable por `SYNSEMA_LLM_BASE_URL`).
    pub base_url: String,
}

impl AnthropicProvider {
    /// POST del body al endpoint. Devuelve el body de respuesta o un error legible.
    fn post(&self, body: String) -> Result<String, String> {
        let headers = [
            ("x-api-key".to_string(), self.api_key.clone()),
            ("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let url = anthropic_endpoint(&self.base_url);
        let r = http_request("POST", &url, Some(&headers), None, Some(&body), TIMEOUT_SECS);
        if let Some(e) = r.error {
            return Err(e);
        }
        // Aun con !ok, el body trae el JSON de error de la API → dejá que el parser
        // extraiga `error.message`; sólo si el parser falla mostramos el crudo.
        Ok(r.body)
    }
}

impl LLMProvider for AnthropicProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body = build_anthropic_body(&self.model, self.max_tokens, &prompt, &context, &[]);
        let content = match self.post(body).and_then(|j| parse_anthropic_text(&j)) {
            Ok((text, _)) => text,
            Err(e) => format!("[anthropic error: {}]", e),
        };
        LLMResponse { content, model: self.model.clone() }
    }

    fn name(&self) -> String {
        format!("anthropic:{}", self.model)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body =
            build_anthropic_body(&self.model, self.max_tokens, &prompt, &context, &request.tools);
        match self.post(body).and_then(|j| parse_anthropic_step(&j)) {
            Ok((step, tokens)) => LlmStepResponse { step, tokens_used: tokens },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[anthropic error: {}]", e)),
                tokens_used: 0,
            },
        }
    }
}

// =========================================================
// OpenAI (y compatibles: Ollama / LM Studio / vLLM / llama.cpp)
// =========================================================

/// Arma el body JSON para `POST /chat/completions`. Tools al estilo function-calling.
/// Manda `max_tokens` (importante para locales como Ollama, cuyo default es chico).
pub fn build_openai_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    tools: &[ToolSpec],
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
    });
    if !tools.is_empty() {
        let arr: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": {
                            "type": "object",
                            "properties": string_properties(&t.params),
                            "required": t.params,
                        }
                    }
                })
            })
            .collect();
        body["tools"] = Value::Array(arr);
    }
    body.to_string()
}

/// tokens = `usage.prompt_tokens + usage.completion_tokens`.
fn openai_tokens(v: &Value) -> u64 {
    let usage = v.get("usage");
    let p = usage.and_then(|u| u.get("prompt_tokens")).and_then(Value::as_u64).unwrap_or(0);
    let c = usage.and_then(|u| u.get("completion_tokens")).and_then(Value::as_u64).unwrap_or(0);
    p + c
}

/// Parsea el string JSON de `arguments` de una function-call a pares (k, str(v)).
fn openai_parse_args(args_str: &str) -> Vec<(String, String)> {
    match serde_json::from_str::<Value>(args_str) {
        Ok(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), stringify_json(v))).collect(),
        _ => Vec::new(),
    }
}

/// `choices[0].message` (objeto), o error si falta.
fn openai_message(v: &Value) -> Result<&Value, String> {
    v.get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .ok_or_else(|| "openai: respuesta sin `choices[0].message`".to_string())
}

/// Parsea la respuesta de OpenAI como un PASO tool-aware.
pub fn parse_openai_step(json_str: &str) -> Result<(LlmStep, u64), String> {
    let v: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(api_error_message(err));
    }
    let tokens = openai_tokens(&v);
    let message = openai_message(&v)?;
    if let Some(call) =
        message.get("tool_calls").and_then(Value::as_array).and_then(|a| a.first())
    {
        if let Some(func) = call.get("function") {
            let name = func.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let args_str = func.get("arguments").and_then(Value::as_str).unwrap_or("{}");
            return Ok((LlmStep::ToolCall { name, args: openai_parse_args(args_str) }, tokens));
        }
    }
    let text = message.get("content").and_then(Value::as_str).unwrap_or("").to_string();
    Ok((LlmStep::Final(text), tokens))
}

/// Parsea la respuesta de OpenAI como TEXTO (`choices[0].message.content`).
pub fn parse_openai_text(json_str: &str) -> Result<(String, u64), String> {
    let v: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(api_error_message(err));
    }
    let tokens = openai_tokens(&v);
    let message = openai_message(&v)?;
    let text = message.get("content").and_then(Value::as_str).unwrap_or("").to_string();
    Ok((text, tokens))
}

/// Provider real OpenAI-compatible (`{base}/chat/completions`).
pub struct OpenAIProvider {
    pub api_key: String,
    pub model: String,
    pub max_tokens: u64,
    pub base_url: String,
}

impl OpenAIProvider {
    fn post(&self, body: String) -> Result<String, String> {
        let headers = [
            ("Authorization".to_string(), format!("Bearer {}", self.api_key)),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let url = openai_endpoint(&self.base_url);
        let r = http_request("POST", &url, Some(&headers), None, Some(&body), TIMEOUT_SECS);
        if let Some(e) = r.error {
            return Err(e);
        }
        Ok(r.body)
    }
}

impl LLMProvider for OpenAIProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body = build_openai_body(&self.model, self.max_tokens, &prompt, &context, &[]);
        let content = match self.post(body).and_then(|j| parse_openai_text(&j)) {
            Ok((text, _)) => text,
            Err(e) => format!("[openai error: {}]", e),
        };
        LLMResponse { content, model: self.model.clone() }
    }

    fn name(&self) -> String {
        format!("openai:{}", self.model)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body = build_openai_body(&self.model, self.max_tokens, &prompt, &context, &request.tools);
        match self.post(body).and_then(|j| parse_openai_step(&j)) {
            Ok((step, tokens)) => LlmStepResponse { step, tokens_used: tokens },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[openai error: {}]", e)),
                tokens_used: 0,
            },
        }
    }
}

// =========================================================
// Factory + selección por env
// =========================================================

/// Construye un provider real por nombre (puro, testeable). `base_url=None` → el base
/// oficial del provider. `None` si el nombre no es un provider soportado.
pub fn build_provider(
    provider: &str,
    api_key: String,
    model: String,
    max_tokens: u64,
    base_url: Option<String>,
) -> Option<Arc<dyn LLMProvider>> {
    match provider.to_lowercase().as_str() {
        "anthropic" | "claude" => Some(Arc::new(AnthropicProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| ANTHROPIC_DEFAULT_BASE.to_string()),
        })),
        "openai" | "gpt" => Some(Arc::new(OpenAIProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| OPENAI_DEFAULT_BASE.to_string()),
        })),
        _ => None,
    }
}

/// Selecciona el provider a partir del environ del proceso. Todos los knobs son del
/// usuario (conectividad libre; el runtime no impone límites):
/// - `SYNSEMA_LLM_PROVIDER` si está; si no, `ANTHROPIC_API_KEY`→anthropic,
///   `OPENAI_API_KEY`→openai; si ninguno, `None` (offline → placeholders).
/// - key del env correspondiente (`None` si falta).
/// - `SYNSEMA_LLM_MODEL` (override gana sobre el default), `SYNSEMA_LLM_MAX_TOKENS`
///   (default 4096), `SYNSEMA_LLM_BASE_URL` (override → modelos locales OpenAI-compat).
pub fn provider_from_env() -> Option<Arc<dyn LLMProvider>> {
    let provider = match std::env::var("SYNSEMA_LLM_PROVIDER") {
        Ok(p) if !p.trim().is_empty() => p.trim().to_lowercase(),
        _ => {
            if std::env::var("ANTHROPIC_API_KEY").is_ok() {
                "anthropic".to_string()
            } else if std::env::var("OPENAI_API_KEY").is_ok() {
                "openai".to_string()
            } else {
                return None;
            }
        }
    };
    let (key_var, default_model) = match provider.as_str() {
        "anthropic" | "claude" => ("ANTHROPIC_API_KEY", ANTHROPIC_DEFAULT_MODEL),
        "openai" | "gpt" => ("OPENAI_API_KEY", OPENAI_DEFAULT_MODEL),
        _ => return None,
    };
    let api_key = std::env::var(key_var).ok()?;
    // El override de modelo GANA sobre el default.
    let model = std::env::var("SYNSEMA_LLM_MODEL")
        .ok()
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| default_model.to_string());
    let max_tokens = std::env::var("SYNSEMA_LLM_MAX_TOKENS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_TOKENS);
    let base_url = std::env::var("SYNSEMA_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    build_provider(&provider, api_key, model, max_tokens, base_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Endpoints (base-URL configurable) --

    #[test]
    fn endpoints_default_and_override() {
        assert_eq!(
            anthropic_endpoint(ANTHROPIC_DEFAULT_BASE),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            openai_endpoint(OPENAI_DEFAULT_BASE),
            "https://api.openai.com/v1/chat/completions"
        );
        // Modelo LOCAL (Ollama): base con `/v1` → endpoint OpenAI-compatible.
        assert_eq!(
            openai_endpoint("http://localhost:11434/v1"),
            "http://localhost:11434/v1/chat/completions"
        );
        // Tolera trailing slash.
        assert_eq!(
            openai_endpoint("http://localhost:11434/v1/"),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    // -- Anthropic: build_body --

    #[test]
    fn build_anthropic_body_with_tool() {
        let tools = vec![ToolSpec {
            name: "get_weather".to_string(),
            description: "get the weather".to_string(),
            params: vec!["city".to_string()],
        }];
        let body = build_anthropic_body("claude-opus-4-8", 512, "What's the weather?", "", &tools);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["model"], "claude-opus-4-8");
        assert_eq!(v["max_tokens"], 512);
        assert!(v["messages"][0]["content"].as_str().unwrap().contains("What's the weather?"));
        assert_eq!(v["tools"][0]["name"], "get_weather");
        assert_eq!(v["tools"][0]["input_schema"]["properties"]["city"]["type"], "string");
        let required = v["tools"][0]["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|x| x == "city"));
    }

    #[test]
    fn build_anthropic_body_no_tools_omits_key() {
        let body = build_anthropic_body("m", 16, "hi", "", &[]);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("tools").is_none(), "no debería tener clave `tools`: {}", body);
    }

    #[test]
    fn build_anthropic_body_appends_context() {
        let body = build_anthropic_body("m", 16, "prompt-here", "context-here", &[]);
        let v: Value = serde_json::from_str(&body).unwrap();
        let content = v["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("prompt-here") && content.contains("context-here"));
    }

    // -- Anthropic: parse_step / parse_text --

    const ANTHROPIC_TOOL_USE: &str = r#"{
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Let me check the weather."},
            {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Madrid"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 12, "output_tokens": 7}
    }"#;

    const ANTHROPIC_TEXT_ONLY: &str = r#"{
        "id": "msg_2",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "hola"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 5, "output_tokens": 3}
    }"#;

    #[test]
    fn parse_anthropic_step_tool_use() {
        let (step, tokens) = parse_anthropic_step(ANTHROPIC_TOOL_USE).unwrap();
        assert_eq!(tokens, 19);
        match step {
            LlmStep::ToolCall { name, args } => {
                assert_eq!(name, "get_weather");
                assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
            }
            _ => panic!("esperaba ToolCall, got {:?}", step),
        }
    }

    #[test]
    fn parse_anthropic_step_text_only() {
        let (step, tokens) = parse_anthropic_step(ANTHROPIC_TEXT_ONLY).unwrap();
        assert_eq!(tokens, 8);
        match step {
            LlmStep::Final(t) => assert_eq!(t, "hola"),
            _ => panic!("esperaba Final, got {:?}", step),
        }
    }

    #[test]
    fn parse_anthropic_text_concats() {
        let (text, tokens) = parse_anthropic_text(ANTHROPIC_TEXT_ONLY).unwrap();
        assert_eq!(text, "hola");
        assert_eq!(tokens, 8);
    }

    #[test]
    fn parse_anthropic_error_surfaces_message() {
        let err = r#"{"type":"error","error":{"type":"invalid_request_error","message":"bad model"}}"#;
        let e = parse_anthropic_text(err).unwrap_err();
        assert!(e.contains("bad model"), "got {}", e);
    }

    // -- OpenAI: build_body --

    #[test]
    fn build_openai_body_with_tool_and_max_tokens() {
        let tools = vec![ToolSpec {
            name: "get_weather".to_string(),
            description: "get the weather".to_string(),
            params: vec!["city".to_string()],
        }];
        let body = build_openai_body("gpt-4o", 256, "What's the weather?", "", &tools);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["model"], "gpt-4o");
        assert_eq!(v["max_tokens"], 256);
        assert!(v["messages"][0]["content"].as_str().unwrap().contains("What's the weather?"));
        assert_eq!(v["tools"][0]["type"], "function");
        assert_eq!(v["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(
            v["tools"][0]["function"]["parameters"]["properties"]["city"]["type"],
            "string"
        );
        let required =
            v["tools"][0]["function"]["parameters"]["required"].as_array().unwrap();
        assert!(required.iter().any(|x| x == "city"));
    }

    #[test]
    fn build_openai_body_no_tools_omits_key() {
        let body = build_openai_body("m", 16, "hi", "", &[]);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("tools").is_none(), "no debería tener clave `tools`: {}", body);
        assert_eq!(v["max_tokens"], 16);
    }

    // -- OpenAI: parse_step / parse_text --

    const OPENAI_TOOL_CALL: &str = r#"{
        "id": "chatcmpl-1",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\": \"Madrid\"}"}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
    }"#;

    const OPENAI_CONTENT: &str = r#"{
        "id": "chatcmpl-2",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hola"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 4, "completion_tokens": 3}
    }"#;

    #[test]
    fn parse_openai_step_tool_call() {
        let (step, tokens) = parse_openai_step(OPENAI_TOOL_CALL).unwrap();
        assert_eq!(tokens, 15);
        match step {
            LlmStep::ToolCall { name, args } => {
                assert_eq!(name, "get_weather");
                assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
            }
            _ => panic!("esperaba ToolCall, got {:?}", step),
        }
    }

    #[test]
    fn parse_openai_step_content() {
        let (step, tokens) = parse_openai_step(OPENAI_CONTENT).unwrap();
        assert_eq!(tokens, 7);
        match step {
            LlmStep::Final(t) => assert_eq!(t, "hola"),
            _ => panic!("esperaba Final, got {:?}", step),
        }
    }

    #[test]
    fn parse_openai_text_content() {
        let (text, tokens) = parse_openai_text(OPENAI_CONTENT).unwrap();
        assert_eq!(text, "hola");
        assert_eq!(tokens, 7);
    }

    #[test]
    fn parse_openai_error_surfaces_message() {
        let err = r#"{"error":{"message":"invalid api key","type":"invalid_request_error"}}"#;
        let e = parse_openai_text(err).unwrap_err();
        assert!(e.contains("invalid api key"), "got {}", e);
    }

    // -- Factory --

    #[test]
    fn build_provider_anthropic_some() {
        let p = build_provider("anthropic", "k".to_string(), "m".to_string(), 4096, None).unwrap();
        assert!(p.name().contains("anthropic"), "name: {}", p.name());
    }

    #[test]
    fn build_provider_openai_some() {
        let p = build_provider("openai", "k".to_string(), "m".to_string(), 4096, None).unwrap();
        assert!(p.name().contains("openai"), "name: {}", p.name());
    }

    #[test]
    fn build_provider_unknown_none() {
        assert!(build_provider("nope", "k".to_string(), "m".to_string(), 4096, None).is_none());
    }

    // -- Live (red real). Corre a mano:
    //    ANTHROPIC_API_KEY=... cargo test -p synsema-runtime anthropic_live -- --ignored --nocapture
    #[test]
    #[ignore = "necesita ANTHROPIC_API_KEY viva + red; corre con -- --ignored"]
    fn anthropic_live() {
        let key = std::env::var("ANTHROPIC_API_KEY")
            .expect("seteá ANTHROPIC_API_KEY para el test live");
        let model = std::env::var("SYNSEMA_LLM_MODEL")
            .unwrap_or_else(|_| ANTHROPIC_DEFAULT_MODEL.to_string());
        let p = AnthropicProvider {
            api_key: key,
            model,
            max_tokens: DEFAULT_MAX_TOKENS,
            base_url: ANTHROPIC_DEFAULT_BASE.to_string(),
        };
        let mut req = LLMRequest::new("reason");
        req.data.insert(
            "prompt".to_string(),
            "Reply with exactly one word: pong".to_string(),
        );
        let resp = p.call(&req);
        println!("[anthropic_live] respuesta: {}", resp.content);
        assert!(!resp.content.is_empty(), "respuesta vacía");
        assert!(
            !resp.content.starts_with("[anthropic error"),
            "error del provider: {}",
            resp.content
        );
    }
}
