//! Providers LLM reales. Conectividad de las ops `reason`/`decide`/`analyze`/
//! `generate` y del primitivo `llm_step` con un modelo real: Anthropic, OpenAI/compatible,
//! MiniMax, DeepSeek (HTTP) y — con `--features llm-local` — el provider `local`
//! (GGUF cuantizado embebido, CPU, sin red ni API key; ver `llm_local.rs`).
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
//! Studio/vLLM/llama.cpp), `SYNSEMA_LLM_TIMEOUT` (timeout HTTP en segundos, default 60 —
//! con el transporte streaming mide SILENCIO entre bytes, no duración total),
//! `SYNSEMA_LLM_HTTP_STREAM` (default `1`: los providers de red piden SSE y rearman la
//! respuesta internamente; `0`/`false` → camino no-stream clásico, para proxies raros).
//! Gating: lo controla `require llm` (en core/runtime);
//! `http_request` de stdlib NO chequea `net` — el host lo fija el runtime por env.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use synsema_llm::provider::{
    LLMProvider, LLMRequest, LLMResponse, LlmStep, LlmStepResponse, ToolSpec,
};
use synsema_stdlib::http::{http_request, http_request_stream};
use synsema_stdlib::secrets::EnvStore;

const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Default de tokens de salida por request. La API de Anthropic OBLIGA a mandar el
/// parámetro; el VALOR lo elige el usuario por `SYNSEMA_LLM_MAX_TOKENS`. 1024 cortaba
/// respuestas de agente — 4096 es un default más razonable.
const DEFAULT_MAX_TOKENS: u64 = 4096;
/// Default del timeout HTTP, en segundos (configurable por `SYNSEMA_LLM_TIMEOUT`).
/// Con el transporte streaming (default) mide silencio entre bytes — cada chunk
/// recibido lo renueva — así que 60s es un buen default incluso para generaciones
/// largas; en el camino no-stream limita la llamada completa, como siempre.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Base-URL oficial de Anthropic (override por `SYNSEMA_LLM_BASE_URL`).
const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
/// Base-URL oficial de OpenAI (override por `SYNSEMA_LLM_BASE_URL` → modelos LOCALES
/// OpenAI-compatibles, ej. `http://localhost:11434/v1` para Ollama).
const OPENAI_DEFAULT_BASE: &str = "https://api.openai.com/v1";
/// Base de MiniMax: su API **Anthropic-compatible** (mismo formato `/v1/messages` +
/// `x-api-key`), por eso reusa el `AnthropicProvider`. Override por `SYNSEMA_LLM_BASE_URL`.
const MINIMAX_DEFAULT_BASE: &str = "https://api.minimax.io/anthropic";
/// Base de DeepSeek: su API es **OpenAI-compatible** (Bearer, `{base}/chat/completions`,
/// `usage.prompt/completion_tokens`), por eso reusa el `OpenAIProvider`. Override por
/// `SYNSEMA_LLM_BASE_URL`.
const DEEPSEEK_DEFAULT_BASE: &str = "https://api.deepseek.com";

/// Default de Anthropic: **Sonnet** (más barato) por seguridad de costo. Opus es
/// opt-in vía `SYNSEMA_LLM_MODEL=claude-opus-4-8` — así nadie quema plata sin querer.
pub const ANTHROPIC_DEFAULT_MODEL: &str = "claude-sonnet-4-6";
/// Default de OpenAI (configurable por `SYNSEMA_LLM_MODEL`; para local poné el tuyo).
pub const OPENAI_DEFAULT_MODEL: &str = "gpt-4o";
/// Default de MiniMax (configurable por `SYNSEMA_LLM_MODEL`): la serie M para razonamiento
/// agéntico + tool use + long-context.
pub const MINIMAX_DEFAULT_MODEL: &str = "MiniMax-M3";
/// Default de DeepSeek (configurable por `SYNSEMA_LLM_MODEL`): el modelo de chat general
/// (soporta tool-calls); los modelos nuevos se setean por env.
pub const DEEPSEEK_DEFAULT_MODEL: &str = "deepseek-chat";

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
// Transporte streaming (SSE) — infraestructura compartida
// =========================================================

/// Un evento SSE rearmado: `event:` opcional + las líneas `data:` concatenadas.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Acumulador SSE con estado: `feed` recibe texto fragmentado en CUALQUIER punto
/// (los reads del socket no respetan límites de línea ni de evento) y devuelve los
/// eventos que se COMPLETARON (un evento termina en línea en blanco). Tolera `\r\n`
/// y `\n`; ignora comentarios (`:`) y campos desconocidos (`id:`, `retry:`).
pub struct SseAccumulator {
    buf: String,
    cur_event: Option<String>,
    cur_data: Vec<String>,
}

impl Default for SseAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl SseAccumulator {
    pub fn new() -> Self {
        Self { buf: String::new(), cur_event: None, cur_data: Vec::new() }
    }

    pub fn feed(&mut self, chunk: &str) -> Vec<SseEvent> {
        self.buf.push_str(chunk);
        let mut out = Vec::new();
        while let Some(nl) = self.buf.find('\n') {
            let line = self.buf[..nl].trim_end_matches('\r').to_string();
            self.buf.drain(..nl + 1);
            if line.is_empty() {
                // Línea en blanco = fin de evento (si había algo acumulado).
                if self.cur_event.is_some() || !self.cur_data.is_empty() {
                    out.push(SseEvent {
                        event: self.cur_event.take(),
                        data: self.cur_data.join("\n"),
                    });
                    self.cur_data.clear();
                }
            } else if let Some(rest) = line.strip_prefix("event:") {
                self.cur_event = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.cur_data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
        }
        out
    }
}

/// Decodificación UTF-8 incremental: agrega `bytes` a `carry`, devuelve el prefijo
/// válido y deja en `carry` los bytes de un char multi-byte cortado entre reads.
/// UTF-8 inválido de verdad (no truncado) sale lossy para no trabar el stream.
fn utf8_drain(carry: &mut Vec<u8>, bytes: &[u8]) -> String {
    carry.extend_from_slice(bytes);
    match std::str::from_utf8(carry) {
        Ok(s) => {
            let out = s.to_string();
            carry.clear();
            out
        }
        // error_len() == None → char truncado AL FINAL: emitir el prefijo válido y
        // retener la cola para el próximo read.
        Err(e) if e.error_len().is_none() => {
            let valid = e.valid_up_to();
            let out = String::from_utf8_lossy(&carry[..valid]).into_owned();
            carry.drain(..valid);
            out
        }
        Err(_) => {
            let out = String::from_utf8_lossy(carry).into_owned();
            carry.clear();
            out
        }
    }
}

/// Resultado de un POST con transporte streaming: o la respuesta FUE SSE (y el estado
/// del rearmado quedó en `S`), o el peer respondió JSON plano (típicamente un error de
/// API, o un compatible que ignoró `stream: true`) → el body completo va al parser
/// no-stream de siempre.
enum SsePost<S> {
    Stream(S),
    Plain(String),
}

/// ¿El Content-Type de la respuesta es `text/event-stream`?
fn is_event_stream(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type")
            && v.to_ascii_lowercase().contains("text/event-stream")
    })
}

// =========================================================
// Anthropic
// =========================================================

/// Arma el body JSON para `POST /v1/messages`. Si `tools` está vacío, OMITE la clave
/// `tools`. NO manda `temperature`/`top_p`/`top_k`/`thinking` (dan 400 en modelos
/// actuales). Con `stream` agrega `"stream": true` (transporte SSE; sin él, el body
/// es byte a byte el de siempre).
pub fn build_anthropic_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    tools: &[ToolSpec],
    stream: bool,
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
    });
    if stream {
        body["stream"] = Value::Bool(true);
    }
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

/// Arma el body de `decide` con opciones (DE-039): tool `elegir` cuyo schema restringe
/// la respuesta al set (`enum` = opciones) + `tool_choice` FORZADO — el modelo no puede
/// responder texto libre. Variante de `build_anthropic_body` (que queda intacta para
/// el resto de las ops).
pub fn build_anthropic_decide_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    options: &[String],
    stream: bool,
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
        "tools": [{
            "name": "elegir",
            "description": "Elegí exactamente una opción.",
            "input_schema": {
                "type": "object",
                "properties": { "opcion": { "type": "string", "enum": options } },
                "required": ["opcion"],
            }
        }],
        "tool_choice": { "type": "tool", "name": "elegir" },
    });
    if stream {
        body["stream"] = Value::Bool(true);
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

/// Estado del rearmado de un stream SSE Anthropic-compatible (Anthropic canónico y
/// MiniMax). `feed` procesa cada evento y devuelve el text-delta si lo hubo (para
/// `on_chunk`); `finish_*` cierra y devuelve lo mismo que los parsers no-stream.
///
/// Usage — regla que cubre AMBOS dialectos sin caso especial: Anthropic canónico manda
/// `input_tokens` en `message_start` y `output_tokens` en `message_delta`; MiniMax manda
/// ceros en `message_start` y los REALES (input + output) recién en `message_delta`
/// (verificado en vivo 2026-07-09). Por eso: se actualiza input/output desde CUALQUIER
/// evento que traiga `usage`, last-write-wins por campo, y un campo ausente NO pisa el
/// valor previo. Campos extra desconocidos en `usage` se ignoran.
#[derive(Default)]
struct AnthropicStreamState {
    text: String,
    /// `(name, json de args acumulado, index del bloque)` del PRIMER bloque `tool_use`
    /// (los parsers no-stream también toman el primero). El `index` distingue sus
    /// `input_json_delta` de los de OTROS bloques `tool_use` (parallel tool use): sin
    /// el filtro, los args del segundo tool contaminan el JSON del primero y el parse
    /// termina en args vacíos — divergencia con el no-stream.
    tool: Option<(String, String, Option<u64>)>,
    input_tokens: u64,
    output_tokens: u64,
    error: Option<String>,
}

impl AnthropicStreamState {
    fn update_usage(&mut self, usage: &Value) {
        if let Some(n) = usage.get("input_tokens").and_then(Value::as_u64) {
            self.input_tokens = n;
        }
        if let Some(n) = usage.get("output_tokens").and_then(Value::as_u64) {
            self.output_tokens = n;
        }
    }

    /// Procesa un evento; devuelve el text-delta si el evento traía texto nuevo.
    /// Eventos desconocidos (`ping`, …) se ignoran — de paso renuevan el read-timeout.
    fn feed(&mut self, ev: &SseEvent) -> Option<String> {
        let v: Value = serde_json::from_str(&ev.data).ok()?;
        if ev.event.as_deref() == Some("error")
            || v.get("type").and_then(Value::as_str) == Some("error")
        {
            self.error = Some(
                v.get("error").map(api_error_message).unwrap_or_else(|| v.to_string()),
            );
            return None;
        }
        // usage puede venir en message_start (`message.usage`) o message_delta (`usage`).
        if let Some(u) = v.get("usage") {
            self.update_usage(u);
        }
        if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
            self.update_usage(u);
        }
        match v.get("type").and_then(Value::as_str) {
            Some("content_block_start") => {
                if self.tool.is_none() {
                    if let Some(cb) = v.get("content_block") {
                        if cb.get("type").and_then(Value::as_str) == Some("tool_use") {
                            let name =
                                cb.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                            let index = v.get("index").and_then(Value::as_u64);
                            self.tool = Some((name, String::new(), index));
                        }
                    }
                }
                None
            }
            Some("content_block_delta") => {
                let delta = v.get("delta")?;
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        let t = delta.get("text").and_then(Value::as_str).unwrap_or("");
                        self.text.push_str(t);
                        if t.is_empty() { None } else { Some(t.to_string()) }
                    }
                    Some("input_json_delta") => {
                        // Solo los deltas del MISMO bloque que el tool registrado
                        // (`index` == `index`; ambos `None` = fixtures sin index).
                        let ev_index = v.get("index").and_then(Value::as_u64);
                        if let Some((_, args, tool_index)) = self.tool.as_mut() {
                            if *tool_index == ev_index {
                                args.push_str(
                                    delta.get("partial_json").and_then(Value::as_str).unwrap_or(""),
                                );
                            }
                        }
                        None
                    }
                    _ => None,
                }
            }
            _ => None, // message_start/stop, content_block_stop, ping, …
        }
    }

    fn tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }

    /// Cierre como PASO tool-aware (equivale a `parse_anthropic_step`).
    fn finish_step(self) -> Result<(LlmStep, u64), String> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let tokens = self.tokens();
        if let Some((name, args_json, _)) = self.tool {
            // Mismo mapeo de args que el camino no-stream: objeto JSON → (k, str(v)).
            let args = match serde_json::from_str::<Value>(&args_json) {
                Ok(Value::Object(m)) => {
                    m.iter().map(|(k, val)| (k.clone(), stringify_json(val))).collect()
                }
                _ => Vec::new(),
            };
            return Ok((LlmStep::ToolCall { name, args }, tokens));
        }
        Ok((LlmStep::Final(self.text), tokens))
    }

    /// Cierre como TEXTO (equivale a `parse_anthropic_text`).
    fn finish_text(self) -> Result<(String, u64), String> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let tokens = self.tokens();
        Ok((self.text, tokens))
    }
}

/// Provider real de Anthropic (`{base}/v1/messages`).
pub struct AnthropicProvider {
    pub api_key: String,
    pub model: String,
    /// Tope de tokens de salida (configurable por `SYNSEMA_LLM_MAX_TOKENS`).
    pub max_tokens: u64,
    /// Base-URL (configurable por `SYNSEMA_LLM_BASE_URL`).
    pub base_url: String,
    /// Timeout HTTP en segundos (configurable por `SYNSEMA_LLM_TIMEOUT`). Con el
    /// transporte streaming mide silencio entre bytes; sin él, la llamada completa.
    pub timeout_secs: u64,
    /// Transporte streaming SSE (default; `SYNSEMA_LLM_HTTP_STREAM=0` → no-stream).
    pub stream_transport: bool,
}

impl AnthropicProvider {
    fn headers(&self) -> [(String, String); 3] {
        [
            ("x-api-key".to_string(), self.api_key.clone()),
            ("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ]
    }

    /// POST del body al endpoint. Devuelve el body de respuesta o un error legible.
    fn post(&self, body: String) -> Result<String, String> {
        let url = anthropic_endpoint(&self.base_url);
        let r = http_request(
            "POST",
            &url,
            Some(&self.headers()),
            None,
            Some(&body),
            self.timeout_secs,
        );
        if let Some(e) = r.error {
            return Err(e);
        }
        // Aun con !ok, el body trae el JSON de error de la API → dejá que el parser
        // extraiga `error.message`; sólo si el parser falla mostramos el crudo.
        Ok(r.body)
    }

    /// POST con transporte streaming: rearma la respuesta SSE al vuelo. `on_chunk`
    /// recibe cada text-delta; si devuelve `false` se corta la lectura y el estado
    /// conserva lo acumulado (los callers sin streaming visible pasan `|_| true`).
    /// Si la respuesta NO fue SSE (JSON plano de error, o un compatible que ignoró
    /// `stream: true`), devuelve el body completo para el parser no-stream de siempre.
    fn post_sse(
        &self,
        body: &str,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> Result<SsePost<AnthropicStreamState>, String> {
        let url = anthropic_endpoint(&self.base_url);
        let headers = self.headers();
        let mut state = AnthropicStreamState::default();
        let mut raw: Vec<u8> = Vec::new(); // copia cruda por si NO es SSE
        let mut sse = SseAccumulator::new();
        let mut carry: Vec<u8> = Vec::new();
        let (_status, resp_headers) = http_request_stream(
            "POST",
            &url,
            Some(&headers),
            Some(body),
            self.timeout_secs,
            &mut |bytes| {
                raw.extend_from_slice(bytes);
                let text = utf8_drain(&mut carry, bytes);
                for ev in sse.feed(&text) {
                    if let Some(delta) = state.feed(&ev) {
                        if !on_chunk(&delta) {
                            return false; // el caller cortó: cerrar el socket
                        }
                    }
                    if state.error.is_some() {
                        return false; // error de la API en el stream: no hay más que leer
                    }
                }
                true
            },
        )?;
        if is_event_stream(&resp_headers) {
            Ok(SsePost::Stream(state))
        } else {
            Ok(SsePost::Plain(String::from_utf8_lossy(&raw).to_string()))
        }
    }
}

impl LLMProvider for AnthropicProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        // `decide` con opciones (DE-039): body con tool `elegir` + tool_choice forzado.
        // La respuesta llega como ToolCall (el rearmado SSE de tools ya existe) y el
        // content es `args["opcion"]`. Si el modelo igual respondió texto, se devuelve
        // crudo — la normalización/reintento viven en `decide_with_contract`.
        if request.operation == "decide" && !request.options.is_empty() {
            let result = if self.stream_transport {
                let body = build_anthropic_decide_body(
                    &self.model,
                    self.max_tokens,
                    &prompt,
                    &context,
                    &request.options,
                    true,
                );
                self.post_sse(&body, &mut |_| true).and_then(|r| match r {
                    SsePost::Stream(st) => st.finish_step(),
                    SsePost::Plain(j) => parse_anthropic_step(&j),
                })
            } else {
                let body = build_anthropic_decide_body(
                    &self.model,
                    self.max_tokens,
                    &prompt,
                    &context,
                    &request.options,
                    false,
                );
                self.post(body).and_then(|j| parse_anthropic_step(&j))
            };
            let (content, tokens) = match result {
                Ok((step, t)) => (decide_step_to_text(step), t),
                Err(e) => (format!("[anthropic error: {}]", e), 0),
            };
            return LLMResponse { content, model: self.model.clone(), tokens_used: tokens };
        }
        let result = if self.stream_transport {
            let body = build_anthropic_body(&self.model, self.max_tokens, &prompt, &context, &[], true);
            self.post_sse(&body, &mut |_| true).and_then(|r| match r {
                SsePost::Stream(st) => st.finish_text(),
                SsePost::Plain(j) => parse_anthropic_text(&j),
            })
        } else {
            let body =
                build_anthropic_body(&self.model, self.max_tokens, &prompt, &context, &[], false);
            self.post(body).and_then(|j| parse_anthropic_text(&j))
        };
        let (content, tokens) = match result {
            Ok((text, t)) => (text, t),
            Err(e) => (format!("[anthropic error: {}]", e), 0),
        };
        LLMResponse { content, model: self.model.clone(), tokens_used: tokens }
    }

    fn name(&self) -> String {
        format!("anthropic:{}", self.model)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let result = if self.stream_transport {
            let body = build_anthropic_body(
                &self.model,
                self.max_tokens,
                &prompt,
                &context,
                &request.tools,
                true,
            );
            self.post_sse(&body, &mut |_| true).and_then(|r| match r {
                SsePost::Stream(st) => st.finish_step(),
                SsePost::Plain(j) => parse_anthropic_step(&j),
            })
        } else {
            let body = build_anthropic_body(
                &self.model,
                self.max_tokens,
                &prompt,
                &context,
                &request.tools,
                false,
            );
            self.post(body).and_then(|j| parse_anthropic_step(&j))
        };
        match result {
            Ok((step, tokens)) => LlmStepResponse { step, tokens_used: tokens },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[anthropic error: {}]", e)),
                tokens_used: 0,
            },
        }
    }

    /// Streaming real (F2) para el provider de red: `on_chunk` recibe cada text-delta
    /// a medida que llega del socket; si devuelve `false`, se corta y se devuelve lo
    /// acumulado. Errores como RETORNO `"[anthropic error: …]"` (patrón de la casa),
    /// nunca por chunks. Sin `stream_transport`, cae al contrato default (emite el
    /// contenido completo una vez).
    fn call_stream(
        &self,
        request: &LLMRequest,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> LLMResponse {
        if !self.stream_transport {
            let resp = self.call(request);
            on_chunk(&resp.content);
            return resp;
        }
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body = build_anthropic_body(&self.model, self.max_tokens, &prompt, &context, &[], true);
        let (content, tokens) = match self.post_sse(&body, on_chunk).and_then(|r| match r {
            SsePost::Stream(st) => st.finish_text(),
            SsePost::Plain(j) => parse_anthropic_text(&j),
        }) {
            Ok((text, t)) => (text, t),
            Err(e) => (format!("[anthropic error: {}]", e), 0),
        };
        LLMResponse { content, model: self.model.clone(), tokens_used: tokens }
    }
}

// =========================================================
// OpenAI (y compatibles: Ollama / LM Studio / vLLM / llama.cpp)
// =========================================================

/// Arma el body JSON para `POST /chat/completions`. Tools al estilo function-calling.
/// Manda `max_tokens` (importante para locales como Ollama, cuyo default es chico).
/// Con `stream` agrega `"stream": true` + `"stream_options": {"include_usage": true}`
/// (sin eso el usage no llega en stream; compatibles viejos que rechacen
/// `stream_options` tienen reintento sin el campo en el provider).
pub fn build_openai_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    tools: &[ToolSpec],
    stream: bool,
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
    });
    if stream {
        body["stream"] = Value::Bool(true);
        body["stream_options"] = json!({ "include_usage": true });
    }
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

/// Arma el body de `decide` con opciones (DE-039), dialecto function-calling: function
/// `elegir` con `enum` = opciones + `tool_choice` FORZADO. Variante de
/// `build_openai_body` (que queda intacta para el resto de las ops).
pub fn build_openai_decide_body(
    model: &str,
    max_tokens: u64,
    user_prompt: &str,
    context: &str,
    options: &[String],
    stream: bool,
) -> String {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [ { "role": "user", "content": user_content(user_prompt, context) } ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "elegir",
                "description": "Elegí exactamente una opción.",
                "parameters": {
                    "type": "object",
                    "properties": { "opcion": { "type": "string", "enum": options } },
                    "required": ["opcion"],
                }
            }
        }],
        "tool_choice": { "type": "function", "function": { "name": "elegir" } },
    });
    if stream {
        body["stream"] = Value::Bool(true);
        body["stream_options"] = json!({ "include_usage": true });
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

/// Estado del rearmado de un stream SSE OpenAI-compatible (`data: {json}` … `data:
/// [DONE]`). Acumula SOLO la primera tool-call (consistente con `parse_openai_step`,
/// que hace `a.first()`); el usage llega en el último chunk (con `stream_options`).
#[derive(Default)]
struct OpenAiStreamState {
    text: String,
    tool_name: Option<String>,
    tool_args: String,
    prompt_tokens: u64,
    completion_tokens: u64,
    error: Option<String>,
}

impl OpenAiStreamState {
    /// Procesa un evento; devuelve el text-delta si el evento traía texto nuevo.
    fn feed(&mut self, ev: &SseEvent) -> Option<String> {
        let data = ev.data.trim();
        if data == "[DONE]" {
            return None;
        }
        let v: Value = serde_json::from_str(data).ok()?;
        if let Some(err) = v.get("error") {
            self.error = Some(api_error_message(err));
            return None;
        }
        if let Some(u) = v.get("usage") {
            if let Some(n) = u.get("prompt_tokens").and_then(Value::as_u64) {
                self.prompt_tokens = n;
            }
            if let Some(n) = u.get("completion_tokens").and_then(Value::as_u64) {
                self.completion_tokens = n;
            }
        }
        let delta = v
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("delta"))?;
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                // SOLO la primera tool-call (index 0), como el camino no-stream.
                if call.get("index").and_then(Value::as_u64).unwrap_or(0) != 0 {
                    continue;
                }
                if let Some(func) = call.get("function") {
                    if let Some(name) = func.get("name").and_then(Value::as_str) {
                        if self.tool_name.is_none() {
                            self.tool_name = Some(name.to_string());
                        }
                    }
                    if let Some(frag) = func.get("arguments").and_then(Value::as_str) {
                        self.tool_args.push_str(frag);
                    }
                }
            }
        }
        let t = delta.get("content").and_then(Value::as_str).unwrap_or("");
        if t.is_empty() {
            None
        } else {
            self.text.push_str(t);
            Some(t.to_string())
        }
    }

    fn tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    /// Cierre como PASO tool-aware (equivale a `parse_openai_step`).
    fn finish_step(self) -> Result<(LlmStep, u64), String> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let tokens = self.tokens();
        if let Some(name) = self.tool_name {
            return Ok((
                LlmStep::ToolCall { name, args: openai_parse_args(&self.tool_args) },
                tokens,
            ));
        }
        Ok((LlmStep::Final(self.text), tokens))
    }

    /// Cierre como TEXTO (equivale a `parse_openai_text`).
    fn finish_text(self) -> Result<(String, u64), String> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let tokens = self.tokens();
        Ok((self.text, tokens))
    }
}

/// Quita `stream_options` de un body ya armado (reintento para compatibles viejos
/// que rechazan el campo; el usage no llega → tokens=0, contrato degradado existente).
fn strip_stream_options(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(mut v) => {
            if let Some(o) = v.as_object_mut() {
                o.remove("stream_options");
            }
            v.to_string()
        }
        Err(_) => body.to_string(),
    }
}

/// Provider real OpenAI-compatible (`{base}/chat/completions`).
pub struct OpenAIProvider {
    pub api_key: String,
    pub model: String,
    pub max_tokens: u64,
    pub base_url: String,
    /// Timeout HTTP en segundos (configurable por `SYNSEMA_LLM_TIMEOUT`). Con el
    /// transporte streaming mide silencio entre bytes; sin él, la llamada completa.
    pub timeout_secs: u64,
    /// Transporte streaming SSE (default; `SYNSEMA_LLM_HTTP_STREAM=0` → no-stream).
    pub stream_transport: bool,
}

impl OpenAIProvider {
    fn headers(&self) -> [(String, String); 2] {
        [
            ("Authorization".to_string(), format!("Bearer {}", self.api_key)),
            ("content-type".to_string(), "application/json".to_string()),
        ]
    }

    fn post(&self, body: String) -> Result<String, String> {
        let url = openai_endpoint(&self.base_url);
        let r = http_request(
            "POST",
            &url,
            Some(&self.headers()),
            None,
            Some(&body),
            self.timeout_secs,
        );
        if let Some(e) = r.error {
            return Err(e);
        }
        Ok(r.body)
    }

    /// POST con transporte streaming (ver `AnthropicProvider::post_sse` — mismo diseño,
    /// formato SSE OpenAI; callers sin streaming visible pasan `|_| true`).
    fn post_sse(
        &self,
        body: &str,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> Result<SsePost<OpenAiStreamState>, String> {
        let url = openai_endpoint(&self.base_url);
        let headers = self.headers();
        let mut state = OpenAiStreamState::default();
        let mut raw: Vec<u8> = Vec::new();
        let mut sse = SseAccumulator::new();
        let mut carry: Vec<u8> = Vec::new();
        let (_status, resp_headers) = http_request_stream(
            "POST",
            &url,
            Some(&headers),
            Some(body),
            self.timeout_secs,
            &mut |bytes| {
                raw.extend_from_slice(bytes);
                let text = utf8_drain(&mut carry, bytes);
                for ev in sse.feed(&text) {
                    if let Some(delta) = state.feed(&ev) {
                        if !on_chunk(&delta) {
                            return false;
                        }
                    }
                    if state.error.is_some() {
                        return false;
                    }
                }
                true
            },
        )?;
        if is_event_stream(&resp_headers) {
            Ok(SsePost::Stream(state))
        } else {
            Ok(SsePost::Plain(String::from_utf8_lossy(&raw).to_string()))
        }
    }

    /// `post_sse` + reintento: si el compatible rechazó `stream_options` (error que
    /// menciona el campo), reintenta UNA vez sin él. Un error de red NO se reintenta.
    /// (Un error no emite text-deltas, así que el reintento no duplica chunks.)
    fn post_sse_with_retry(
        &self,
        body: &str,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> Result<SsePost<OpenAiStreamState>, String> {
        let first = self.post_sse(body, &mut *on_chunk)?;
        let rejected_stream_options = match &first {
            SsePost::Plain(j) => {
                matches!(parse_openai_text(j), Err(m) if m.contains("stream_options"))
            }
            SsePost::Stream(st) => {
                st.error.as_deref().is_some_and(|m| m.contains("stream_options"))
            }
        };
        if rejected_stream_options {
            return self.post_sse(&strip_stream_options(body), on_chunk);
        }
        Ok(first)
    }
}

impl LLMProvider for OpenAIProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        // `decide` con opciones (DE-039): function `elegir` + tool_choice forzado.
        // Espejo del camino de AnthropicProvider (ver el comentario ahí).
        if request.operation == "decide" && !request.options.is_empty() {
            let result = if self.stream_transport {
                let body = build_openai_decide_body(
                    &self.model,
                    self.max_tokens,
                    &prompt,
                    &context,
                    &request.options,
                    true,
                );
                self.post_sse_with_retry(&body, &mut |_| true).and_then(|r| match r {
                    SsePost::Stream(st) => st.finish_step(),
                    SsePost::Plain(j) => parse_openai_step(&j),
                })
            } else {
                let body = build_openai_decide_body(
                    &self.model,
                    self.max_tokens,
                    &prompt,
                    &context,
                    &request.options,
                    false,
                );
                self.post(body).and_then(|j| parse_openai_step(&j))
            };
            let (content, tokens) = match result {
                Ok((step, t)) => (decide_step_to_text(step), t),
                Err(e) => (format!("[openai error: {}]", e), 0),
            };
            return LLMResponse { content, model: self.model.clone(), tokens_used: tokens };
        }
        let result = if self.stream_transport {
            let body = build_openai_body(&self.model, self.max_tokens, &prompt, &context, &[], true);
            self.post_sse_with_retry(&body, &mut |_| true).and_then(|r| match r {
                SsePost::Stream(st) => st.finish_text(),
                SsePost::Plain(j) => parse_openai_text(&j),
            })
        } else {
            let body =
                build_openai_body(&self.model, self.max_tokens, &prompt, &context, &[], false);
            self.post(body).and_then(|j| parse_openai_text(&j))
        };
        let (content, tokens) = match result {
            Ok((text, t)) => (text, t),
            Err(e) => (format!("[openai error: {}]", e), 0),
        };
        LLMResponse { content, model: self.model.clone(), tokens_used: tokens }
    }

    fn name(&self) -> String {
        format!("openai:{}", self.model)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let result = if self.stream_transport {
            let body = build_openai_body(
                &self.model,
                self.max_tokens,
                &prompt,
                &context,
                &request.tools,
                true,
            );
            self.post_sse_with_retry(&body, &mut |_| true).and_then(|r| match r {
                SsePost::Stream(st) => st.finish_step(),
                SsePost::Plain(j) => parse_openai_step(&j),
            })
        } else {
            let body = build_openai_body(
                &self.model,
                self.max_tokens,
                &prompt,
                &context,
                &request.tools,
                false,
            );
            self.post(body).and_then(|j| parse_openai_step(&j))
        };
        match result {
            Ok((step, tokens)) => LlmStepResponse { step, tokens_used: tokens },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[openai error: {}]", e)),
                tokens_used: 0,
            },
        }
    }

    /// Streaming real (F2) — mismo contrato que `AnthropicProvider::call_stream`:
    /// errores como retorno, nunca por chunks; `on_chunk` `false` corta y devuelve lo
    /// acumulado. Sin `stream_transport`, contrato default (emite una vez).
    fn call_stream(
        &self,
        request: &LLMRequest,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> LLMResponse {
        if !self.stream_transport {
            let resp = self.call(request);
            on_chunk(&resp.content);
            return resp;
        }
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let body = build_openai_body(&self.model, self.max_tokens, &prompt, &context, &[], true);
        let (content, tokens) = match self.post_sse_with_retry(&body, on_chunk).and_then(|r| match r {
            SsePost::Stream(st) => st.finish_text(),
            SsePost::Plain(j) => parse_openai_text(&j),
        }) {
            Ok((text, t)) => (text, t),
            Err(e) => (format!("[openai error: {}]", e), 0),
        };
        LLMResponse { content, model: self.model.clone(), tokens_used: tokens }
    }
}

// =========================================================
// Contrato de `decide` (DE-039)
// =========================================================

/// Content de un paso de `decide` forzado por tool: la ToolCall `elegir` → su arg
/// `opcion`; un `Final` (modelo que igual respondió texto, o compatible que ignoró el
/// `tool_choice`) → el texto tal cual. La normalización/reintento viven en
/// `decide_with_contract`, que recibe esto como "crudo".
fn decide_step_to_text(step: LlmStep) -> String {
    match step {
        LlmStep::ToolCall { args, .. } => args
            .into_iter()
            .find(|(k, _)| k == "opcion")
            .map(|(_, v)| v)
            .unwrap_or_default(),
        LlmStep::Final(t) => t,
    }
}

/// Forma canónica para comparar una respuesta contra las opciones: trim, sacar
/// puntuación/comillas ENVOLVENTES (no internas) y case-fold.
fn normalize_decide_token(s: &str) -> String {
    s.trim()
        .trim_matches(|c: char| c.is_ascii_punctuation() || c == '¿' || c == '¡' || c == '«' || c == '»' || c == '“' || c == '”' || c == '‘' || c == '’')
        .trim()
        .to_lowercase()
}

/// Normalización tolerante de la respuesta de `decide` (pura, DE-039 peldaño 2):
/// - tras normalizar, la respuesta ES una opción → esa (`"ROJO."` → `ROJO`);
/// - la respuesta CONTIENE exactamente UNA opción normalizada → esa
///   (`"La respuesta es AZUL"` → `AZUL`);
/// - cero o varias → `None` (ambigua: que decida el reintento/fallback).
///
/// Devuelve siempre la opción ORIGINAL (casing/formato intactos), nunca la forma
/// normalizada — el contrato es "una de las opciones", byte a byte.
pub fn normalize_decide(raw: &str, options: &[String]) -> Option<String> {
    let raw_norm = normalize_decide_token(raw);
    if raw_norm.is_empty() {
        return None;
    }
    // Match exacto primero (gana aunque otra opción esté CONTENIDA en esta,
    // p.ej. opciones "azul" y "azul oscuro" con respuesta "azul oscuro").
    for opt in options {
        if normalize_decide_token(opt) == raw_norm {
            return Some(opt.clone());
        }
    }
    // Contención: exactamente UNA opción normalizada dentro de la respuesta, como
    // PALABRA(S) COMPLETA(S) — substring a secas inventa decisiones ("si" dentro de
    // "nece*si*to"); ver el test adversario `normalize_decide_containment_is_word_boundary`.
    let contained: Vec<&String> = options
        .iter()
        .filter(|opt| {
            let o = normalize_decide_token(opt);
            !o.is_empty() && contains_whole(&raw_norm, &o)
        })
        .collect();
    match contained.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

/// ¿`needle` aparece en `haystack` con LÍMITE DE PALABRA a ambos lados (el char
/// adyacente, si existe, no es alfanumérico)? Los índices de `find` son byte-offsets de
/// substrings válidos → los slices caen siempre en límites de char (UTF-8 seguro).
fn contains_whole(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let end = abs + needle.len();
        let before_ok =
            haystack[..abs].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack[end..].chars().next().is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        start = end;
    }
    false
}

/// Aviso ÚNICO por proceso cuando `decide` entrega crudo pese al reintento (peldaño 4).
/// Mismo patrón `first_time` que los avisos de LLM-offline (DX-1) y de human-gates.
static DECIDE_FALLBACK_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// `true` SOLO la primera vez sobre `flag` (testeable con un flag local).
fn first_time(flag: &std::sync::atomic::AtomicBool) -> bool {
    !flag.swap(true, std::sync::atomic::Ordering::Relaxed)
}

fn note_decide_fallback() {
    if first_time(&DECIDE_FALLBACK_NOTICED) {
        eprintln!(
            "[synsema] notice: decide returned a value outside the given options even after \
             one retry — returning the raw model response. Code branching on this decide \
             should handle a value that is not one of the options."
        );
    }
}

/// La escalera completa de `decide` con opciones (DE-039): tool/enum forzado (lo hace
/// el provider al ver `options` en la request) → normalización tolerante → UN reintento
/// con feedback → fallback crudo CON aviso único. Agnóstica del transporte: cualquier
/// `LLMProvider` sirve (los que no miran `options` — local GGUF, mock — responden texto
/// y entran directo por la normalización).
pub fn decide_with_contract(
    provider: &dyn LLMProvider,
    prompt: &str,
    options: &[String],
) -> String {
    let mut req = LLMRequest::new("decide");
    req.data.insert("prompt".to_string(), prompt.to_string());
    req.options = options.to_vec();
    let raw = provider.call(&req).content;
    if options.is_empty() {
        return raw; // sin `between [...]`: no hay contrato que hacer cumplir
    }
    if let Some(choice) = normalize_decide(&raw, options) {
        return choice;
    }
    // UN reintento con feedback (peldaño 3) — costo solo cuando hace falta.
    let mut retry = LLMRequest::new("decide");
    retry.data.insert(
        "prompt".to_string(),
        format!(
            "{}\nTu respuesta '{}' no es válida. Respondé ÚNICAMENTE con una de: {}",
            prompt,
            raw,
            options.join(", ")
        ),
    );
    retry.options = options.to_vec();
    let raw2 = provider.call(&retry).content;
    if let Some(choice) = normalize_decide(&raw2, options) {
        return choice;
    }
    note_decide_fallback();
    raw2
}

// =========================================================
// Metering LLM + backstop de budget (FRAMEWORK F1 / F-A)
// =========================================================

/// Tokens LLM acumulados del PROCESO (input + output de cada llamada real). Lo
/// alimenta `MeteredProvider` (envuelve al provider elegido en
/// `provider_from_config`, con o sin budget) y lo lee el builtin `llm_usage()`.
/// Monotónico por proceso: las ventanas de tiempo son política del framework, no
/// del runtime.
static LLM_TOKENS_USED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Total de tokens LLM consumidos por este proceso (para cablear `llm_usage()`).
pub fn llm_tokens_total() -> u64 {
    LLM_TOKENS_USED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Aviso ÚNICO por proceso al cortar por budget (mismo patrón que LLM-offline).
static BUDGET_CUT_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Marker de degradación al superar `SYNSEMA_LLM_BUDGET`. MISMO patrón que offline:
/// las ops LLM degradan con un texto descriptivo, NUNCA rompen la cadena del agente.
/// Autocontenido y LLM-safe: dice qué pasó, quién lo fija y qué no hacer.
fn budget_marker(used: u64, budget: u64) -> String {
    format!("[llm budget exceeded: used {} of {} tokens]", used, budget)
}

fn note_budget_cut(used: u64, budget: u64) {
    if first_time(&BUDGET_CUT_NOTICED) {
        eprintln!(
            "[synsema] notice: the LLM token budget is exhausted (used {} of {} tokens, set by \
             the host via SYNSEMA_LLM_BUDGET). LLM operations now return the marker text \
             \"[llm budget exceeded: …]\" instead of calling the model. An agent should not \
             retry LLM operations in this process; raise the budget or start a new process.",
            used, budget
        );
    }
}

/// Envuelve al provider real y METRA cada llamada: acumula `tokens_used` en el
/// contador del proceso y, si hay `SYNSEMA_LLM_BUDGET`, corta ANTES de delegar cuando
/// ya se alcanzó (degrada con marker + aviso único; jamás error — asimetría deliberada
/// con `spend`, que sí es error duro). Cubre `call`/`call_step`/`call_stream` → las 6
/// ops del lenguaje pasan por acá. `provider_from_config` lo aplica SIEMPRE (sin
/// budget igual metra: `llm_usage()` funciona sin config).
pub struct MeteredProvider {
    pub inner: Arc<dyn LLMProvider>,
    /// `None` = sin techo (solo metering). `Some(n)`: al llegar a `n` tokens usados,
    /// las llamadas siguientes degradan sin tocar la red.
    pub budget: Option<u64>,
}

impl MeteredProvider {
    /// `Some(used)` si el budget ya está agotado (la llamada NO debe delegar).
    fn over_budget(&self) -> Option<(u64, u64)> {
        let budget = self.budget?;
        let used = LLM_TOKENS_USED.load(std::sync::atomic::Ordering::Relaxed);
        if used >= budget {
            Some((used, budget))
        } else {
            None
        }
    }

    fn meter(&self, tokens: u64) {
        if tokens > 0 {
            LLM_TOKENS_USED.fetch_add(tokens, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl LLMProvider for MeteredProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        if let Some((used, budget)) = self.over_budget() {
            note_budget_cut(used, budget);
            return LLMResponse {
                content: budget_marker(used, budget),
                model: self.inner.name(),
                tokens_used: 0,
            };
        }
        let resp = self.inner.call(request);
        self.meter(resp.tokens_used);
        resp
    }

    /// Transparente: reporta el nombre del provider envuelto (así `llm_available` y
    /// los logs no cambian por el metering).
    fn name(&self) -> String {
        self.inner.name()
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        if let Some((used, budget)) = self.over_budget() {
            note_budget_cut(used, budget);
            return LlmStepResponse {
                step: LlmStep::Final(budget_marker(used, budget)),
                tokens_used: 0,
            };
        }
        let resp = self.inner.call_step(request);
        self.meter(resp.tokens_used);
        resp
    }

    fn call_stream(
        &self,
        request: &LLMRequest,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> LLMResponse {
        if let Some((used, budget)) = self.over_budget() {
            note_budget_cut(used, budget);
            let marker = budget_marker(used, budget);
            // Contrato de stream degradado (mismo que el default del trait): el marker
            // se emite como UN chunk y como contenido final.
            on_chunk(&marker);
            return LLMResponse { content: marker, model: self.inner.name(), tokens_used: 0 };
        }
        let resp = self.inner.call_stream(request, on_chunk);
        self.meter(resp.tokens_used);
        resp
    }
}

/// `SYNSEMA_LLM_BUDGET` → tope de tokens del proceso. Inválido o 0 → SIN budget, con
/// warn (un techo silenciosamente ignorado sería peor que no tenerlo).
fn resolve_llm_budget(store: &EnvStore) -> Option<u64> {
    let raw = resolve_knob("SYNSEMA_LLM_BUDGET", store)?;
    match raw.trim().parse::<u64>() {
        Ok(n) if n > 0 => Some(n),
        _ => {
            eprintln!(
                "synsema: warning: SYNSEMA_LLM_BUDGET='{}' is not a positive integer — \
                 running WITHOUT an LLM token budget",
                raw
            );
            None
        }
    }
}

// =========================================================
// Factory + selección por env
// =========================================================

/// Construye un provider real por nombre (puro, testeable). `base_url=None` → el base
/// oficial del provider. `None` si el nombre no es un provider soportado.
/// `timeout_secs`/`stream_transport` sólo aplican a los providers de RED; el provider
/// `local` los ignora (no tiene socket y ya streamea por diseño propio).
pub fn build_provider(
    provider: &str,
    api_key: String,
    model: String,
    max_tokens: u64,
    base_url: Option<String>,
    timeout_secs: u64,
    stream_transport: bool,
) -> Option<Arc<dyn LLMProvider>> {
    match provider.to_lowercase().as_str() {
        "anthropic" | "claude" => Some(Arc::new(AnthropicProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| ANTHROPIC_DEFAULT_BASE.to_string()),
            timeout_secs,
            stream_transport,
        })),
        "openai" | "gpt" => Some(Arc::new(OpenAIProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| OPENAI_DEFAULT_BASE.to_string()),
            timeout_secs,
            stream_transport,
        })),
        // MiniMax expone una API Anthropic-compatible → reusa el AnthropicProvider
        // (mismo `/v1/messages`, `x-api-key`, content blocks y `usage`), sólo cambia
        // la base + el modelo + la key (`MINIMAX_API_KEY`).
        "minimax" => Some(Arc::new(AnthropicProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| MINIMAX_DEFAULT_BASE.to_string()),
            timeout_secs,
            stream_transport,
        })),
        // DeepSeek expone una API OpenAI-compatible → reusa el OpenAIProvider (Bearer,
        // chat/completions), sólo cambia la base + el modelo + la key (`DEEPSEEK_API_KEY`).
        "deepseek" => Some(Arc::new(OpenAIProvider {
            api_key,
            model,
            max_tokens,
            base_url: base_url.unwrap_or_else(|| DEEPSEEK_DEFAULT_BASE.to_string()),
            timeout_secs,
            stream_transport,
        })),
        // Provider `local`: GGUF embebido (candle, CPU). SIN api_key ni base_url —
        // `model` es el PATH al `.gguf`. Los knobs finos (ctx/threads/temperature/
        // max_concurrent) los resuelve `provider_from_config`; este camino (factory puro)
        // usa los defaults. Sin la feature: aviso por stderr y offline — JAMÁS degradar
        // en silencio a otro provider.
        #[cfg(feature = "llm-local")]
        "local" | "gguf" => Some(Arc::new(crate::llm_local::LocalGgufProvider::new(
            model,
            max_tokens,
            crate::llm_local::LocalKnobs::default(),
        ))),
        #[cfg(not(feature = "llm-local"))]
        "local" | "gguf" => {
            eprintln!(
                "[synsema] SYNSEMA_LLM_PROVIDER=local requiere un binario compilado con \
                 --features llm-local (o usá SYNSEMA_LLM_PROVIDER=openai + SYNSEMA_LLM_BASE_URL \
                 contra un server local)"
            );
            None
        }
        _ => None,
    }
}

/// Resuelve un knob de configuración del provider con la MISMA precedencia que
/// `env()`/`secret()` (§2.1): **environ del proceso > `.env` (EnvStore protegido)**.
/// Vacío/espacios cuenta como ausente en ambas fuentes. Devuelve `None` si no está en
/// ninguna → el caller aplica el default. Así la clave puede vivir SOLO en el `.env`
/// (gitignoreado) sin exportarse al environ del proceso ni a los hijos (DE-007).
/// `pub(crate)`: también resuelve knobs no-LLM del runtime (p.ej.
/// `SYNSEMA_HUMAN_TIMEOUT` en serve) — única implementación de la precedencia.
pub(crate) fn resolve_knob(name: &str, store: &EnvStore) -> Option<String> {
    resolve_knob_src(name, store).map(|(v, _)| v)
}

/// Como [`resolve_knob`] pero además dice DE DÓNDE salió el valor (para el reporte de
/// `synsema llm status`). Única implementación de la precedencia — `resolve_knob`
/// delega acá, así el reporte no puede divergir de la resolución real.
fn resolve_knob_src(name: &str, store: &EnvStore) -> Option<(String, KnobSource)> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some((v, KnobSource::Environ)),
        _ => store
            .get(name)
            .filter(|v| !v.trim().is_empty())
            .map(|v| (v, KnobSource::DotEnv)),
    }
}

/// `SYNSEMA_LLM_TIMEOUT` → segundos (MISMO patrón que `SYNSEMA_LLM_MAX_TOKENS`:
/// inválido o ≤0 cae al default en silencio).
fn resolve_timeout_secs(store: &EnvStore) -> u64 {
    resolve_knob("SYNSEMA_LLM_TIMEOUT", store)
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

/// `SYNSEMA_LLM_HTTP_STREAM` → transporte streaming (default ON). Sólo `0`/`false`
/// (case-insensitive) lo apagan; cualquier otra cosa (incluido inválido) queda en ON.
fn resolve_stream_transport(store: &EnvStore) -> bool {
    resolve_knob("SYNSEMA_LLM_HTTP_STREAM", store)
        .map(|s| {
            let t = s.trim().to_lowercase();
            t != "0" && t != "false"
        })
        .unwrap_or(true)
}

/// Knobs del provider `local` (ignorados por los providers de red), resueltos con la
/// MISMA precedencia `environ > .env > default` que el resto (`resolve_knob`):
/// `SYNSEMA_LLM_CTX` (default 4096, capado al ctx del GGUF), `SYNSEMA_LLM_THREADS`
/// (default: el del pool de rayon), `SYNSEMA_LLM_TEMPERATURE` (default 0 = greedy),
/// `SYNSEMA_LLM_MAX_CONCURRENT` (default 1 = serializa bajo serve).
#[cfg(feature = "llm-local")]
fn local_knobs_from_config(store: &EnvStore) -> crate::llm_local::LocalKnobs {
    let defaults = crate::llm_local::LocalKnobs::default();
    crate::llm_local::LocalKnobs {
        ctx: resolve_knob("SYNSEMA_LLM_CTX", store)
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(defaults.ctx),
        threads: resolve_knob("SYNSEMA_LLM_THREADS", store)
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0),
        temperature: resolve_knob("SYNSEMA_LLM_TEMPERATURE", store)
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&t| t >= 0.0)
            .unwrap_or(defaults.temperature),
        max_concurrent: resolve_knob("SYNSEMA_LLM_MAX_CONCURRENT", store)
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(defaults.max_concurrent),
        stream_buffer: resolve_knob("SYNSEMA_LLM_STREAM_BUFFER", store)
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(defaults.stream_buffer),
    }
}

/// Selecciona el provider resolviendo cada knob con precedencia `environ > .env (store) >
/// default` (vía [`resolve_knob`]). Todos los knobs son del usuario (conectividad libre;
/// el runtime no impone límites):
/// - `SYNSEMA_LLM_PROVIDER` si está; si no, auto-selección por presencia de
///   `ANTHROPIC_API_KEY`→anthropic, `OPENAI_API_KEY`→openai, `MINIMAX_API_KEY`→minimax,
///   `DEEPSEEK_API_KEY`→deepseek (en ese orden); si ninguno, `None` (offline → placeholders).
///   El provider `local` (GGUF embebido) es SIEMPRE explícito — jamás auto-seleccionado —
///   y no lleva API key; su `SYNSEMA_LLM_MODEL` es el path al `.gguf` (obligatorio).
/// - key del provider correspondiente (`None` si falta → offline).
/// - `SYNSEMA_LLM_MODEL` (override gana sobre el default), `SYNSEMA_LLM_MAX_TOKENS`
///   (default 4096), `SYNSEMA_LLM_BASE_URL` (override → modelos locales OpenAI-compat).
/// - `SYNSEMA_LLM_TIMEOUT` (default 60): timeout HTTP en segundos de los providers de
///   red. Con el transporte streaming mide SILENCIO entre bytes (cada chunk lo renueva);
///   inválido o ≤0 cae al default en silencio, como los demás knobs.
/// - `SYNSEMA_LLM_HTTP_STREAM` (default `1`): transporte streaming SSE interno de los
///   providers de red (el lenguaje no cambia: las ops devuelven texto completo).
///   `0`/`false` → camino no-stream clásico (proxies/compatibles que se atragantan
///   con SSE).
///
/// La clave resuelta sólo se usa para armar el header HTTP en el socket: NO se inyecta al
/// environ ni queda accesible al programa `.syn` (que sigue necesitando `require env/secret`
/// para tocar el `.env`, y aun así lo vería redactado).
pub fn provider_from_config(store: &EnvStore) -> Option<Arc<dyn LLMProvider>> {
    inner_provider_from_config(store).map(|inner| {
        // Metering SIEMPRE (F-A): sin `SYNSEMA_LLM_BUDGET` igual se acumula, así
        // `llm_usage()` funciona sin config; con budget, el wrapper corta al llegar.
        Arc::new(MeteredProvider { inner, budget: resolve_llm_budget(store) })
            as Arc<dyn LLMProvider>
    })
}

/// Selección del provider CRUDO (sin el wrapper de metering). Separada para que el
/// wrap de `provider_from_config` sea incondicional y no se pueda olvidar en una rama.
fn inner_provider_from_config(store: &EnvStore) -> Option<Arc<dyn LLMProvider>> {
    let provider = match resolve_knob("SYNSEMA_LLM_PROVIDER", store) {
        Some(p) => p.trim().to_lowercase(),
        None => {
            if resolve_knob("ANTHROPIC_API_KEY", store).is_some() {
                "anthropic".to_string()
            } else if resolve_knob("OPENAI_API_KEY", store).is_some() {
                "openai".to_string()
            } else if resolve_knob("MINIMAX_API_KEY", store).is_some() {
                "minimax".to_string()
            } else if resolve_knob("DEEPSEEK_API_KEY", store).is_some() {
                "deepseek".to_string()
            } else {
                return None;
            }
        }
    };
    // Provider `local`: SIEMPRE explícito (jamás auto-seleccionado), sin API key (el
    // path del GGUF es config del runtime por env, como el endpoint de los de red —
    // mismo precedente: tampoco exige cap `net`/`file`). `SYNSEMA_LLM_MODEL` acá es el
    // PATH al `.gguf` y es obligatorio.
    if provider == "local" || provider == "gguf" {
        let model = match resolve_knob("SYNSEMA_LLM_MODEL", store) {
            Some(m) => m,
            None => {
                eprintln!(
                    "[synsema] SYNSEMA_LLM_PROVIDER=local necesita SYNSEMA_LLM_MODEL=<ruta al .gguf>"
                );
                return None;
            }
        };
        #[cfg(feature = "llm-local")]
        {
            let max_tokens = resolve_knob("SYNSEMA_LLM_MAX_TOKENS", store)
                .and_then(|s| s.trim().parse::<u64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(DEFAULT_MAX_TOKENS);
            return Some(Arc::new(crate::llm_local::LocalGgufProvider::new(
                model,
                max_tokens,
                local_knobs_from_config(store),
            )));
        }
        #[cfg(not(feature = "llm-local"))]
        {
            let _ = model;
            eprintln!(
                "[synsema] SYNSEMA_LLM_PROVIDER=local requiere un binario compilado con \
                 --features llm-local (o usá SYNSEMA_LLM_PROVIDER=openai + SYNSEMA_LLM_BASE_URL \
                 contra un server local)"
            );
            return None;
        }
    }
    let (key_var, default_model) = match provider.as_str() {
        "anthropic" | "claude" => ("ANTHROPIC_API_KEY", ANTHROPIC_DEFAULT_MODEL),
        "openai" | "gpt" => ("OPENAI_API_KEY", OPENAI_DEFAULT_MODEL),
        "minimax" => ("MINIMAX_API_KEY", MINIMAX_DEFAULT_MODEL),
        "deepseek" => ("DEEPSEEK_API_KEY", DEEPSEEK_DEFAULT_MODEL),
        _ => return None,
    };
    let api_key = resolve_knob(key_var, store)?;
    // El override de modelo GANA sobre el default (resolve_knob ya descarta vacíos).
    let model = resolve_knob("SYNSEMA_LLM_MODEL", store)
        .unwrap_or_else(|| default_model.to_string());
    let max_tokens = resolve_knob("SYNSEMA_LLM_MAX_TOKENS", store)
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_TOKENS);
    let base_url = resolve_knob("SYNSEMA_LLM_BASE_URL", store);
    let timeout_secs = resolve_timeout_secs(store);
    let stream_transport = resolve_stream_transport(store);
    build_provider(&provider, api_key, model, max_tokens, base_url, timeout_secs, stream_transport)
}

/// Compat: selecciona el provider SÓLO desde el environ del proceso (sin `.env`).
/// Equivale a `provider_from_config(&EnvStore::empty())`. El camino real de `run`/`conform`
/// usa `provider_from_config` con el `.env` cargado (DE-007).
pub fn provider_from_env() -> Option<Arc<dyn LLMProvider>> {
    provider_from_config(&EnvStore::empty())
}

// =========================================================
// Reporte de configuración (`synsema llm status`) — datos puros
// =========================================================

/// De dónde salió un valor resuelto. La 4ª "fuente" (flag `--provider`) llega como
/// `Environ` porque el CLI setea la env-var antes de resolver — es fiel a lo que pasa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnobSource {
    Environ,
    DotEnv,
    Default,
}

impl KnobSource {
    pub fn label(&self) -> &'static str {
        match self {
            KnobSource::Environ => "environ",
            KnobSource::DotEnv => ".env",
            KnobSource::Default => "default",
        }
    }
}

/// Un knob NO-secreto resuelto: valor efectivo + fuente. REGLA DE SEGURIDAD: este tipo
/// jamás transporta material de keys — las keys se reportan SOLO como presencia.
#[derive(Debug, Clone)]
pub struct KnobReport {
    pub value: String,
    pub source: KnobSource,
}

/// Cómo se eligió el provider.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderSelection {
    /// `SYNSEMA_LLM_PROVIDER` presente (la fuente dice si environ/.env).
    Forced(KnobSource),
    /// Auto-seleccionado por presencia de una API key.
    Auto,
    /// Nada configurado.
    None,
}

/// Por qué el runtime va a quedar OFFLINE (las ops devuelven placeholders).
#[derive(Debug, Clone, PartialEq)]
pub enum OfflineReason {
    /// Provider (forzado o auto) sin SU key. `expected_var` = la variable que falta;
    /// `misplaced` = OTRAS `*_API_KEY` que SÍ están (heurística de clave-equivocada).
    KeyMissing { expected_var: String, misplaced: Vec<String> },
    /// Ni `SYNSEMA_LLM_PROVIDER` ni ninguna API key.
    NoProviderNoKeys,
    /// `provider=local` sin `SYNSEMA_LLM_MODEL` (path al `.gguf`, obligatorio).
    LocalModelMissing,
    /// `provider=local` en un binario compilado sin la feature `llm-local`.
    LocalFeatureMissing,
    /// Nombre de provider no soportado.
    UnknownProvider { name: String },
}

/// Reporte PURO de la config LLM que [`provider_from_config`] va a resolver — para
/// `synsema llm status`. Espeja la MISMA lógica (mismos `resolve_knob_src`, mismo orden
/// de auto-selección); si esto miente, el test `report_matches_provider_from_config`
/// debe fallar. SEGURIDAD: no contiene NINGÚN valor de key (ni prefijo ni longitud) —
/// solo presencia y en qué fuente está; `base_url` sale con el userinfo redactado.
#[derive(Debug)]
pub struct LlmConfigReport {
    pub provider: String,
    pub selection: ProviderSelection,
    /// Variable de key que el provider elegido espera (None para `local`).
    pub key_var: Option<String>,
    /// Presencia de esa key (None = FALTA). Nunca el valor.
    pub key_present: Option<KnobSource>,
    pub model: KnobReport,
    pub max_tokens: KnobReport,
    pub timeout_secs: KnobReport,
    /// `"streaming"` o `"no-stream"`.
    pub transport: KnobReport,
    pub base_url: KnobReport,
    /// ¿El binario tiene compilada la feature `llm-local`?
    pub local_feature: bool,
    /// None = VIVO; Some = OFFLINE con el porqué.
    pub offline: Option<OfflineReason>,
}

const KEY_VARS: [(&str, &str); 4] = [
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("OPENAI_API_KEY", "openai"),
    ("MINIMAX_API_KEY", "minimax"),
    ("DEEPSEEK_API_KEY", "deepseek"),
];

/// Lista CANÓNICA de todas las env-vars que el runtime LLM reconoce (knobs + keys).
/// La consumen `synsema init` (test de sincronía del template — Spec DX-2) y sirve de
/// referencia única. ⚠️ Al agregar un knob nuevo: sumalo ACÁ — si el template de `init`
/// no se actualiza a la par, el test `env_example_in_sync_with_engine_knobs` del CLI
/// rompe el build a propósito (anti-rot del template).
pub const LLM_ENV_VARS: &[&str] = &[
    "SYNSEMA_LLM_PROVIDER",
    "SYNSEMA_LLM_MODEL",
    "SYNSEMA_LLM_MAX_TOKENS",
    "SYNSEMA_LLM_TIMEOUT",
    "SYNSEMA_LLM_HTTP_STREAM",
    "SYNSEMA_LLM_BASE_URL",
    "SYNSEMA_LLM_BUDGET",
    "SYNSEMA_LLM_CTX",
    "SYNSEMA_LLM_THREADS",
    "SYNSEMA_LLM_TEMPERATURE",
    "SYNSEMA_LLM_MAX_CONCURRENT",
    "SYNSEMA_LLM_STREAM_BUFFER",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "MINIMAX_API_KEY",
    "DEEPSEEK_API_KEY",
];

/// Knobs de interacción HUMANA que el runtime reconoce (espejo de [`LLM_ENV_VARS`]).
/// ⚠️ Sumar un knob acá sin actualizar el template de `init` rompe el build a
/// propósito (test `env_example_in_sync_with_engine_knobs` del CLI — anti-rot).
pub const HUMAN_ENV_VARS: &[&str] = &[
    "SYNSEMA_HUMAN_TIMEOUT",
    "SYNSEMA_HUMAN_WEBHOOK",
    "SYNSEMA_HUMAN_WEBHOOK_SECRET",
    "SYNSEMA_HUMAN_PUBLIC_URL",
];

/// Redacta el userinfo de una URL (`https://user:pass@host/...` → `https://***@host/...`)
/// para que un `base_url` con credenciales embebidas no las imprima.
fn redact_url_userinfo(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        let authority_end = rest.find('/').unwrap_or(rest.len());
        if let Some(at) = rest[..authority_end].rfind('@') {
            return format!("{}***@{}", &url[..scheme_end + 3], &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Arma el reporte. Puro sobre `store` + environ del proceso; NO toca la red.
pub fn llm_config_report(store: &EnvStore) -> LlmConfigReport {
    let forced = resolve_knob_src("SYNSEMA_LLM_PROVIDER", store);
    let (provider, selection) = match &forced {
        Some((p, src)) => (p.trim().to_lowercase(), ProviderSelection::Forced(*src)),
        None => match KEY_VARS.iter().find(|(var, _)| resolve_knob(var, store).is_some()) {
            Some((_, prov)) => (prov.to_string(), ProviderSelection::Auto),
            None => (String::new(), ProviderSelection::None),
        },
    };

    // Knobs comunes (mismos defaults y parseo que provider_from_config).
    let model_default = match provider.as_str() {
        "anthropic" | "claude" => ANTHROPIC_DEFAULT_MODEL,
        "openai" | "gpt" => OPENAI_DEFAULT_MODEL,
        "minimax" => MINIMAX_DEFAULT_MODEL,
        "deepseek" => DEEPSEEK_DEFAULT_MODEL,
        _ => "",
    };
    let knob = |name: &str, default: String, valid: &dyn Fn(&str) -> bool| -> KnobReport {
        match resolve_knob_src(name, store) {
            Some((v, src)) if valid(v.trim()) => KnobReport { value: v.trim().to_string(), source: src },
            _ => KnobReport { value: default, source: KnobSource::Default },
        }
    };
    let model = knob("SYNSEMA_LLM_MODEL", model_default.to_string(), &|_| true);
    let max_tokens = knob("SYNSEMA_LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS.to_string(), &|v| {
        v.parse::<u64>().map(|n| n > 0).unwrap_or(false)
    });
    let timeout_secs = knob("SYNSEMA_LLM_TIMEOUT", DEFAULT_TIMEOUT_SECS.to_string(), &|v| {
        v.parse::<u64>().map(|n| n > 0).unwrap_or(false)
    });
    let transport = match resolve_knob_src("SYNSEMA_LLM_HTTP_STREAM", store) {
        Some((v, src)) => {
            let t = v.trim().to_lowercase();
            let on = t != "0" && t != "false";
            KnobReport { value: if on { "streaming" } else { "no-stream" }.to_string(), source: src }
        }
        None => KnobReport { value: "streaming".to_string(), source: KnobSource::Default },
    };
    let base_default = match provider.as_str() {
        "anthropic" | "claude" => ANTHROPIC_DEFAULT_BASE,
        "openai" | "gpt" => OPENAI_DEFAULT_BASE,
        "minimax" => MINIMAX_DEFAULT_BASE,
        "deepseek" => DEEPSEEK_DEFAULT_BASE,
        _ => "",
    };
    let base_url = match resolve_knob_src("SYNSEMA_LLM_BASE_URL", store) {
        Some((v, src)) => KnobReport { value: redact_url_userinfo(v.trim()), source: src },
        None => KnobReport { value: base_default.to_string(), source: KnobSource::Default },
    };

    let local_feature = cfg!(feature = "llm-local");
    let misplaced = || -> Vec<String> {
        KEY_VARS
            .iter()
            .filter(|(var, _)| resolve_knob(var, store).is_some())
            .map(|(var, _)| var.to_string())
            .collect()
    };

    // Diagnóstico — mismo árbol de decisión que provider_from_config.
    let (key_var, key_present, offline) = match provider.as_str() {
        "" => (None, None, Some(OfflineReason::NoProviderNoKeys)),
        "local" | "gguf" => {
            let has_model = resolve_knob_src("SYNSEMA_LLM_MODEL", store).is_some();
            let offline = if !has_model {
                Some(OfflineReason::LocalModelMissing)
            } else if !local_feature {
                Some(OfflineReason::LocalFeatureMissing)
            } else {
                None
            };
            (None, None, offline)
        }
        p => {
            let expected = match p {
                "anthropic" | "claude" => Some("ANTHROPIC_API_KEY"),
                "openai" | "gpt" => Some("OPENAI_API_KEY"),
                "minimax" => Some("MINIMAX_API_KEY"),
                "deepseek" => Some("DEEPSEEK_API_KEY"),
                _ => None,
            };
            match expected {
                None => (None, None, Some(OfflineReason::UnknownProvider { name: p.to_string() })),
                Some(var) => {
                    let present = resolve_knob_src(var, store).map(|(_, src)| src);
                    let offline = if present.is_none() {
                        Some(OfflineReason::KeyMissing {
                            expected_var: var.to_string(),
                            misplaced: misplaced(),
                        })
                    } else {
                        None
                    };
                    (Some(var.to_string()), present, offline)
                }
            }
        }
    };

    LlmConfigReport {
        provider,
        selection,
        key_var,
        key_present,
        model,
        max_tokens,
        timeout_secs,
        transport,
        base_url,
        local_feature,
        offline,
    }
}

impl LlmConfigReport {
    /// JSON estable para `--json` (a mano con serde_json: sin claves de secreto posibles
    /// por construcción — el tipo no las contiene).
    pub fn to_json(&self) -> String {
        let sel = match &self.selection {
            ProviderSelection::Forced(src) => json!({"mode": "forced", "source": src.label()}),
            ProviderSelection::Auto => json!({"mode": "auto"}),
            ProviderSelection::None => json!({"mode": "none"}),
        };
        let knob = |k: &KnobReport| json!({"value": k.value, "source": k.source.label()});
        let offline = self.offline.as_ref().map(|r| match r {
            OfflineReason::KeyMissing { expected_var, misplaced } => {
                json!({"reason": "key_missing", "expected_var": expected_var, "other_keys_present": misplaced})
            }
            OfflineReason::NoProviderNoKeys => json!({"reason": "no_provider_no_keys"}),
            OfflineReason::LocalModelMissing => json!({"reason": "local_model_missing"}),
            OfflineReason::LocalFeatureMissing => json!({"reason": "local_feature_missing"}),
            OfflineReason::UnknownProvider { name } => {
                json!({"reason": "unknown_provider", "name": name})
            }
        });
        json!({
            "alive": self.offline.is_none(),
            "provider": self.provider,
            "selection": sel,
            "key_var": self.key_var,
            "key_present": self.key_present.map(|s| s.label()),
            "model": knob(&self.model),
            "max_tokens": knob(&self.max_tokens),
            "timeout_secs": knob(&self.timeout_secs),
            "transport": knob(&self.transport),
            "base_url": knob(&self.base_url),
            "local_feature": self.local_feature,
            "offline": offline,
        })
        .to_string()
    }
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
        let body =
            build_anthropic_body("claude-opus-4-8", 512, "What's the weather?", "", &tools, false);
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
        let body = build_anthropic_body("m", 16, "hi", "", &[], false);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("tools").is_none(), "no debería tener clave `tools`: {}", body);
        // Sin stream, el body NO lleva la clave (byte a byte el de siempre).
        assert!(v.get("stream").is_none(), "sin stream no va la clave: {}", body);
    }

    #[test]
    fn build_bodies_with_stream_flag() {
        let a = build_anthropic_body("m", 16, "hi", "", &[], true);
        let va: Value = serde_json::from_str(&a).unwrap();
        assert_eq!(va["stream"], true);
        let o = build_openai_body("m", 16, "hi", "", &[], true);
        let vo: Value = serde_json::from_str(&o).unwrap();
        assert_eq!(vo["stream"], true);
        assert_eq!(vo["stream_options"]["include_usage"], true);
        // strip_stream_options: el reintento manda el mismo body sin ese campo.
        let stripped: Value = serde_json::from_str(&strip_stream_options(&o)).unwrap();
        assert!(stripped.get("stream_options").is_none());
        assert_eq!(stripped["stream"], true);
    }

    #[test]
    fn build_anthropic_body_appends_context() {
        let body = build_anthropic_body("m", 16, "prompt-here", "context-here", &[], false);
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
        let body = build_openai_body("gpt-4o", 256, "What's the weather?", "", &tools, false);
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
        let body = build_openai_body("m", 16, "hi", "", &[], false);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("tools").is_none(), "no debería tener clave `tools`: {}", body);
        assert_eq!(v["max_tokens"], 16);
        assert!(v.get("stream").is_none() && v.get("stream_options").is_none());
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
        let p = build_provider(
            "anthropic",
            "k".to_string(),
            "m".to_string(),
            4096,
            None,
            DEFAULT_TIMEOUT_SECS,
            true,
        )
        .unwrap();
        assert!(p.name().contains("anthropic"), "name: {}", p.name());
    }

    #[test]
    fn build_provider_openai_some() {
        let p = build_provider(
            "openai",
            "k".to_string(),
            "m".to_string(),
            4096,
            None,
            DEFAULT_TIMEOUT_SECS,
            true,
        )
        .unwrap();
        assert!(p.name().contains("openai"), "name: {}", p.name());
    }

    #[test]
    fn build_provider_minimax_some() {
        // MiniMax reusa el AnthropicProvider (API Anthropic-compatible); el modelo
        // queda en el name → identificable.
        let p = build_provider(
            "minimax",
            "k".to_string(),
            "MiniMax-M3".to_string(),
            4096,
            None,
            DEFAULT_TIMEOUT_SECS,
            true,
        )
        .unwrap();
        assert!(p.name().contains("MiniMax-M3"), "name: {}", p.name());
    }

    #[test]
    fn minimax_anthropic_compatible_endpoint() {
        assert_eq!(
            anthropic_endpoint(MINIMAX_DEFAULT_BASE),
            "https://api.minimax.io/anthropic/v1/messages"
        );
    }

    #[test]
    fn build_provider_deepseek_some() {
        // DeepSeek reusa el OpenAIProvider (API OpenAI-compatible).
        let p = build_provider(
            "deepseek",
            "k".to_string(),
            "deepseek-chat".to_string(),
            4096,
            None,
            DEFAULT_TIMEOUT_SECS,
            true,
        )
        .unwrap();
        assert!(p.name().contains("openai"), "name: {}", p.name());
    }

    #[test]
    fn deepseek_openai_compatible_endpoint() {
        assert_eq!(
            openai_endpoint(DEEPSEEK_DEFAULT_BASE),
            "https://api.deepseek.com/chat/completions"
        );
    }

    #[test]
    fn build_provider_unknown_none() {
        assert!(build_provider(
            "nope",
            "k".to_string(),
            "m".to_string(),
            4096,
            None,
            DEFAULT_TIMEOUT_SECS,
            true
        )
        .is_none());
    }

    // Lock de los tests que manipulan env-vars globales del proceso (cargo test corre en
    // threads): todo test que toque `std::env::set_var`/`remove_var` de knobs LLM debe
    // tomar este guard primero.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -- DE-007: resolución desde el `.env` protegido (precedencia environ > store) --
    // Serializado vía ENV_LOCK para no carrear con los tests del provider local.
    #[test]
    fn provider_from_config_dotenv_and_precedence() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let keys = [
            "SYNSEMA_LLM_PROVIDER",
            "SYNSEMA_LLM_MODEL",
            "SYNSEMA_LLM_BASE_URL",
            "SYNSEMA_LLM_MAX_TOKENS",
            "SYNSEMA_LLM_TIMEOUT",
            "SYNSEMA_LLM_HTTP_STREAM",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "MINIMAX_API_KEY",
            "DEEPSEEK_API_KEY",
        ];
        let clear = || {
            for k in keys {
                std::env::remove_var(k);
            }
        };
        let store = EnvStore::parse("DEEPSEEK_API_KEY=sk-store\nSYNSEMA_LLM_PROVIDER=deepseek\n");

        // (1) La clave SOLO en el `.env` (store) basta — sin exportar nada al environ.
        //     DeepSeek reusa el OpenAIProvider con su modelo default.
        clear();
        let p = provider_from_config(&store).expect("deepseek desde el .env");
        assert!(p.name().contains(DEEPSEEK_DEFAULT_MODEL), "name: {}", p.name());

        // (2) El environ GANA sobre el `.env`: aunque el store diga deepseek, un provider
        //     explícito en el environ (openai) se impone.
        clear();
        std::env::set_var("SYNSEMA_LLM_PROVIDER", "openai");
        std::env::set_var("OPENAI_API_KEY", "sk-environ");
        let p2 = provider_from_config(&store).expect("openai desde el environ");
        assert!(p2.name().contains(OPENAI_DEFAULT_MODEL), "el environ debe ganar: {}", p2.name());

        // (3) Sin nada (ni environ ni store) → offline.
        clear();
        assert!(provider_from_config(&EnvStore::empty()).is_none());

        // (4) `provider_from_env()` (compat) ignora el `.env`: misma ausencia → offline.
        clear();
        assert!(provider_from_env().is_none());

        clear();
    }

    // -- Provider `local` (spec LLM-LOCAL F1) --

    /// Limpia los knobs LLM del environ (los tests locales asumen environ limpio, como
    /// el test DE-007). Llamar SOLO con ENV_LOCK tomado.
    fn clear_llm_env() {
        for k in [
            "SYNSEMA_LLM_PROVIDER",
            "SYNSEMA_LLM_MODEL",
            "SYNSEMA_LLM_BASE_URL",
            "SYNSEMA_LLM_MAX_TOKENS",
            "SYNSEMA_LLM_TIMEOUT",
            "SYNSEMA_LLM_HTTP_STREAM",
            "SYNSEMA_LLM_CTX",
            "SYNSEMA_LLM_THREADS",
            "SYNSEMA_LLM_TEMPERATURE",
            "SYNSEMA_LLM_MAX_CONCURRENT",
            "SYNSEMA_LLM_STREAM_BUFFER",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "MINIMAX_API_KEY",
            "DEEPSEEK_API_KEY",
        ] {
            std::env::remove_var(k);
        }
    }

    // Sin `SYNSEMA_LLM_MODEL`, provider=local → None (falta el path del GGUF), en AMBOS
    // modos de feature — nunca un provider roto.
    #[test]
    fn provider_local_without_model_is_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store = EnvStore::parse("SYNSEMA_LLM_PROVIDER=local\n");
        assert!(provider_from_config(&store).is_none());
        clear_llm_env();
    }

    // Feature ON: provider=local + model (SOLO desde el `.env`, sin API key) → Some, y
    // el name identifica el archivo. Alias `gguf` equivalente. NUNCA auto-seleccionado
    // sin `SYNSEMA_LLM_PROVIDER` explícito.
    #[cfg(feature = "llm-local")]
    #[test]
    fn provider_local_from_store_without_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store =
            EnvStore::parse("SYNSEMA_LLM_PROVIDER=local\nSYNSEMA_LLM_MODEL=modelo.gguf\n");
        let p = provider_from_config(&store).expect("local desde el .env, sin key");
        assert_eq!(p.name(), "local:modelo.gguf");

        let store2 = EnvStore::parse("SYNSEMA_LLM_PROVIDER=gguf\nSYNSEMA_LLM_MODEL=m.gguf\n");
        assert!(provider_from_config(&store2).is_some(), "alias gguf");

        // Sin provider explícito NO hay auto-selección hacia local (aunque haya modelo).
        let store3 = EnvStore::parse("SYNSEMA_LLM_MODEL=m.gguf\n");
        assert!(provider_from_config(&store3).is_none());
        clear_llm_env();
    }

    // Feature ON: precedencia environ > `.env` > default para los knobs nuevos (calca
    // el test DE-007).
    #[cfg(feature = "llm-local")]
    #[test]
    fn local_knobs_precedence() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store = EnvStore::parse(
            "SYNSEMA_LLM_CTX=2048\nSYNSEMA_LLM_TEMPERATURE=0.7\nSYNSEMA_LLM_MAX_CONCURRENT=2\nSYNSEMA_LLM_STREAM_BUFFER=8\n",
        );

        // (1) Sólo el `.env`: gana el store.
        let k = local_knobs_from_config(&store);
        assert_eq!(k.ctx, 2048);
        assert_eq!(k.temperature, 0.7);
        assert_eq!(k.max_concurrent, 2);
        assert_eq!(k.stream_buffer, 8);
        assert_eq!(k.threads, None);

        // (2) El environ GANA sobre el `.env`.
        std::env::set_var("SYNSEMA_LLM_CTX", "8192");
        std::env::set_var("SYNSEMA_LLM_THREADS", "4");
        let k2 = local_knobs_from_config(&store);
        assert_eq!(k2.ctx, 8192);
        assert_eq!(k2.threads, Some(4));

        // (3) Sin nada → defaults (4096 / greedy / 1 instancia).
        clear_llm_env();
        let k3 = local_knobs_from_config(&EnvStore::empty());
        assert_eq!(k3, crate::llm_local::LocalKnobs::default());

        // (4) Valores inválidos caen al default, no rompen.
        let bad = EnvStore::parse("SYNSEMA_LLM_CTX=cero\nSYNSEMA_LLM_MAX_CONCURRENT=0\n");
        let k4 = local_knobs_from_config(&bad);
        assert_eq!(k4.ctx, 4096);
        assert_eq!(k4.max_concurrent, 1);
        clear_llm_env();
    }

    // Feature OFF: provider=local configurado → None (aviso por stderr) y JAMÁS otro
    // provider en silencio — aunque haya una key de red disponible en el store.
    #[cfg(not(feature = "llm-local"))]
    #[test]
    fn provider_local_without_feature_is_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store = EnvStore::parse(
            "SYNSEMA_LLM_PROVIDER=local\nSYNSEMA_LLM_MODEL=m.gguf\nOPENAI_API_KEY=sk-x\n",
        );
        assert!(provider_from_config(&store).is_none());
        clear_llm_env();
    }

    // -- MF-011: resolución de los knobs nuevos (mismo patrón que MAX_TOKENS) --

    #[test]
    fn timeout_and_stream_knobs_resolution() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        // SYNSEMA_LLM_TIMEOUT: válido → ese valor; 0/inválido/ausente → default 60.
        assert_eq!(resolve_timeout_secs(&EnvStore::parse("SYNSEMA_LLM_TIMEOUT=120\n")), 120);
        assert_eq!(
            resolve_timeout_secs(&EnvStore::parse("SYNSEMA_LLM_TIMEOUT=0\n")),
            DEFAULT_TIMEOUT_SECS
        );
        assert_eq!(
            resolve_timeout_secs(&EnvStore::parse("SYNSEMA_LLM_TIMEOUT=abc\n")),
            DEFAULT_TIMEOUT_SECS
        );
        assert_eq!(resolve_timeout_secs(&EnvStore::empty()), DEFAULT_TIMEOUT_SECS);
        // El environ GANA sobre el `.env` (precedencia de resolve_knob).
        std::env::set_var("SYNSEMA_LLM_TIMEOUT", "300");
        assert_eq!(resolve_timeout_secs(&EnvStore::parse("SYNSEMA_LLM_TIMEOUT=120\n")), 300);
        clear_llm_env();

        // SYNSEMA_LLM_HTTP_STREAM: default ON; sólo 0/false lo apagan.
        assert!(resolve_stream_transport(&EnvStore::empty()));
        assert!(!resolve_stream_transport(&EnvStore::parse("SYNSEMA_LLM_HTTP_STREAM=0\n")));
        assert!(!resolve_stream_transport(&EnvStore::parse("SYNSEMA_LLM_HTTP_STREAM=false\n")));
        assert!(!resolve_stream_transport(&EnvStore::parse("SYNSEMA_LLM_HTTP_STREAM=FALSE\n")));
        assert!(resolve_stream_transport(&EnvStore::parse("SYNSEMA_LLM_HTTP_STREAM=1\n")));
        assert!(resolve_stream_transport(&EnvStore::parse("SYNSEMA_LLM_HTTP_STREAM=si\n")));
        clear_llm_env();
    }

    // -- llm status: reporte de configuración --

    #[test]
    fn report_alive_with_forced_provider_and_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store = EnvStore::parse(
            "SYNSEMA_LLM_PROVIDER=minimax\nMINIMAX_API_KEY=sk-cp-xyz\nSYNSEMA_LLM_MODEL=MiniMax-M3\n",
        );
        let r = llm_config_report(&store);
        assert!(r.offline.is_none(), "debe estar VIVO: {:?}", r.offline);
        assert_eq!(r.provider, "minimax");
        assert_eq!(r.selection, ProviderSelection::Forced(KnobSource::DotEnv));
        assert_eq!(r.key_var.as_deref(), Some("MINIMAX_API_KEY"));
        assert_eq!(r.key_present, Some(KnobSource::DotEnv));
        assert_eq!(r.model.value, "MiniMax-M3");
        assert_eq!(r.timeout_secs.value, "60");
        assert_eq!(r.timeout_secs.source, KnobSource::Default);
        clear_llm_env();
    }

    // El incidente real: provider=minimax con la clave bajo DEEPSEEK_API_KEY.
    #[test]
    fn report_offline_key_missing_with_misplaced_hint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let store =
            EnvStore::parse("SYNSEMA_LLM_PROVIDER=minimax\nDEEPSEEK_API_KEY=sk-equivocada\n");
        let r = llm_config_report(&store);
        match r.offline {
            Some(OfflineReason::KeyMissing { ref expected_var, ref misplaced }) => {
                assert_eq!(expected_var, "MINIMAX_API_KEY");
                assert_eq!(misplaced, &["DEEPSEEK_API_KEY".to_string()]);
            }
            other => panic!("esperaba KeyMissing con hint, got {:?}", other),
        }
        clear_llm_env();
    }

    #[test]
    fn report_offline_and_auto_variants() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        // Nada configurado.
        let r = llm_config_report(&EnvStore::empty());
        assert_eq!(r.offline, Some(OfflineReason::NoProviderNoKeys));
        // Auto-selección por key (sin PROVIDER).
        let r = llm_config_report(&EnvStore::parse("ANTHROPIC_API_KEY=sk-a\n"));
        assert!(r.offline.is_none());
        assert_eq!(r.provider, "anthropic");
        assert_eq!(r.selection, ProviderSelection::Auto);
        // Provider desconocido.
        let r = llm_config_report(&EnvStore::parse("SYNSEMA_LLM_PROVIDER=nope\n"));
        assert_eq!(r.offline, Some(OfflineReason::UnknownProvider { name: "nope".to_string() }));
        // local sin MODEL.
        let r = llm_config_report(&EnvStore::parse("SYNSEMA_LLM_PROVIDER=local\n"));
        assert_eq!(r.offline, Some(OfflineReason::LocalModelMissing));
        clear_llm_env();
    }

    // SEGURIDAD: el reporte (y su JSON) JAMÁS contiene material de la key — ni el valor,
    // ni un prefijo. Coherencia: alive == provider_from_config().is_some().
    #[test]
    fn report_never_leaks_key_material_and_matches_resolution() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_llm_env();
        let secret = "sk-SUPERSECRETO-NO-IMPRIMIR-9f3a";
        for env in [
            format!("SYNSEMA_LLM_PROVIDER=minimax\nMINIMAX_API_KEY={}\n", secret),
            format!("SYNSEMA_LLM_PROVIDER=minimax\nDEEPSEEK_API_KEY={}\n", secret),
            format!("DEEPSEEK_API_KEY={}\n", secret),
            "SYNSEMA_LLM_PROVIDER=deepseek\n".to_string(),
        ] {
            let store = EnvStore::parse(&env);
            let r = llm_config_report(&store);
            let dump = format!("{:?} {}", r, r.to_json());
            assert!(!dump.contains(secret), "el reporte filtró la key: {}", dump);
            assert!(!dump.contains("SUPERSECRETO"), "el reporte filtró parte de la key");
            assert_eq!(
                r.offline.is_none(),
                provider_from_config(&store).is_some(),
                "el reporte miente vs la resolución real para: {}",
                env
            );
        }
        // base_url con credenciales embebidas → userinfo redactado.
        let store = EnvStore::parse(
            "SYNSEMA_LLM_PROVIDER=openai\nOPENAI_API_KEY=k\nSYNSEMA_LLM_BASE_URL=http://user:clave@interno:8080/v1\n",
        );
        let r = llm_config_report(&store);
        assert_eq!(r.base_url.value, "http://***@interno:8080/v1");
        assert!(!r.to_json().contains("clave"));
        clear_llm_env();
    }

    // -- B.2: SseAccumulator + utf8_drain (fragmentación arbitraria) --

    #[test]
    fn sse_accumulator_reassembles_any_fragmentation() {
        let transcript = "event: ping\ndata: {}\n\nevent: x\ndata: hola\ndata: chau\n\ndata: solo\n\n";
        let expect = vec![
            SseEvent { event: Some("ping".to_string()), data: "{}".to_string() },
            SseEvent { event: Some("x".to_string()), data: "hola\nchau".to_string() },
            SseEvent { event: None, data: "solo".to_string() },
        ];
        for step in [1usize, 7, transcript.len()] {
            let mut acc = SseAccumulator::new();
            let mut got = Vec::new();
            let chars = transcript.chars().collect::<Vec<_>>();
            for piece in chars.chunks(step) {
                got.extend(acc.feed(&piece.iter().collect::<String>()));
            }
            assert_eq!(got, expect, "split de {} chars", step);
        }
        // \r\n también vale como fin de línea.
        let mut acc = SseAccumulator::new();
        let got = acc.feed("data: crlf\r\n\r\n");
        assert_eq!(got, vec![SseEvent { event: None, data: "crlf".to_string() }]);
    }

    #[test]
    fn utf8_drain_splits_multibyte_chars() {
        // "ñ" = [0xC3, 0xB1] cortado entre reads: el primer byte queda en carry.
        let mut carry = Vec::new();
        assert_eq!(utf8_drain(&mut carry, &[b'a', 0xC3]), "a");
        assert_eq!(carry, vec![0xC3]);
        assert_eq!(utf8_drain(&mut carry, &[0xB1, b'b']), "ñb");
        assert!(carry.is_empty());
    }

    // -- B.2: rearmado Anthropic (texto, dialecto MiniMax, tool_use, error) --

    /// Alimenta un transcript SSE Anthropic completo en cortes de `step` bytes
    /// (valida SseAccumulator + utf8_drain + AnthropicStreamState juntos).
    fn run_anthropic_transcript(transcript: &str, step: usize) -> AnthropicStreamState {
        let mut sse = SseAccumulator::new();
        let mut st = AnthropicStreamState::default();
        let mut carry = Vec::new();
        for piece in transcript.as_bytes().chunks(step) {
            let text = utf8_drain(&mut carry, piece);
            for ev in sse.feed(&text) {
                let _ = st.feed(&ev);
            }
        }
        st
    }

    const ANTHROPIC_SSE_TEXT: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hola \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"mundo\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    #[test]
    fn anthropic_stream_text_any_fragmentation() {
        for step in [1usize, 7, ANTHROPIC_SSE_TEXT.len()] {
            let st = run_anthropic_transcript(ANTHROPIC_SSE_TEXT, step);
            let (text, tokens) = st.finish_text().unwrap();
            assert_eq!(text, "Hola mundo", "split de {} bytes", step);
            // input de message_start + output de message_delta (canónico Anthropic).
            assert_eq!(tokens, 19, "split de {} bytes", step);
        }
    }

    // Quirk MiniMax (capturado en vivo 2026-07-09): ceros en message_start, tokens
    // reales recién en message_delta (input Y output), con `ping` intercalado.
    // Last-write-wins por campo → 38+13=51; el ping se ignora.
    #[test]
    fn anthropic_stream_minimax_usage_dialect_and_ping() {
        let transcript = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}}\n\n",
            "event: ping\n",
            "data: {\"type\":\"ping\"}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":38,\"output_tokens\":13,\"cache_read_input_tokens\":5,\"service_tier\":\"standard\"}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        for step in [1usize, 7, transcript.len()] {
            let st = run_anthropic_transcript(transcript, step);
            let (text, tokens) = st.finish_text().unwrap();
            assert_eq!(text, "ok");
            assert_eq!(tokens, 51, "split de {} bytes", step);
        }
    }

    #[test]
    fn anthropic_stream_tool_use_fragmented_json() {
        // input_json_delta fragmentado en pedazos arbitrarios, incluso a mitad de un
        // escape (`\"`) dentro del JSON de args.
        let transcript = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"get_weather\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ci\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ty\\\": \\\"Ma\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"drid\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\"}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        for step in [1usize, 7, transcript.len()] {
            let st = run_anthropic_transcript(transcript, step);
            let (step_out, tokens) = st.finish_step().unwrap();
            assert_eq!(tokens, 15, "split de {} bytes", step);
            match step_out {
                LlmStep::ToolCall { name, args } => {
                    assert_eq!(name, "get_weather");
                    assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
                }
                other => panic!("esperaba ToolCall, got {:?}", other),
            }
        }
    }

    // PARALLEL TOOL USE (adversario, auditoría 2026-07-09): Anthropic emite VARIOS
    // bloques `tool_use` en una misma respuesta de rutina. El no-stream toma el PRIMERO
    // con sus `input` completos (`parse_anthropic_step` corta en el primer bloque). El
    // stream debe dar EXACTAMENTE lo mismo: los `input_json_delta` del segundo bloque
    // (otro `index`) NO pueden contaminar los args del primero.
    #[test]
    fn anthropic_stream_parallel_tool_use_matches_nonstream() {
        let transcript = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"get_weather\"}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"get_news\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\": \\\"Ma\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"topic\\\": \\\"clima\\\"}\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"drid\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        for step in [1usize, 7, transcript.len()] {
            let st = run_anthropic_transcript(transcript, step);
            let (step_out, tokens) = st.finish_step().unwrap();
            assert_eq!(tokens, 19, "split de {} bytes", step);
            match step_out {
                LlmStep::ToolCall { name, args } => {
                    assert_eq!(name, "get_weather", "split de {} bytes", step);
                    assert_eq!(
                        args,
                        vec![("city".to_string(), "Madrid".to_string())],
                        "los deltas del bloque 1 NO deben contaminar los args del bloque 0 (split {})",
                        step
                    );
                }
                other => panic!("esperaba ToolCall, got {:?}", other),
            }
        }
    }

    #[test]
    fn anthropic_stream_error_event_surfaces_message() {
        let transcript = concat!(
            "event: error\n",
            "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}\n\n",
        );
        let st = run_anthropic_transcript(transcript, 7);
        let e = st.finish_text().unwrap_err();
        assert!(e.contains("overloaded"), "got {}", e);
    }

    // -- B.2: rearmado OpenAI-compatible --

    fn run_openai_transcript(transcript: &str, step: usize) -> OpenAiStreamState {
        let mut sse = SseAccumulator::new();
        let mut st = OpenAiStreamState::default();
        let mut carry = Vec::new();
        for piece in transcript.as_bytes().chunks(step) {
            let text = utf8_drain(&mut carry, piece);
            for ev in sse.feed(&text) {
                let _ = st.feed(&ev);
            }
        }
        st
    }

    const OPENAI_SSE_TEXT: &str = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"Ho\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"la\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3}}\n\n",
        "data: [DONE]\n\n",
    );

    #[test]
    fn openai_stream_text_any_fragmentation() {
        for step in [1usize, 7, OPENAI_SSE_TEXT.len()] {
            let st = run_openai_transcript(OPENAI_SSE_TEXT, step);
            let (text, tokens) = st.finish_text().unwrap();
            assert_eq!(text, "Hola", "split de {} bytes", step);
            assert_eq!(tokens, 7, "split de {} bytes", step);
        }
    }

    #[test]
    fn openai_stream_tool_call_fragmented() {
        let transcript = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"ci\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ty\\\": \\\"Madrid\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        );
        for step in [1usize, 7, transcript.len()] {
            let st = run_openai_transcript(transcript, step);
            let (step_out, tokens) = st.finish_step().unwrap();
            assert_eq!(tokens, 15, "split de {} bytes", step);
            match step_out {
                LlmStep::ToolCall { name, args } => {
                    assert_eq!(name, "get_weather");
                    assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
                }
                other => panic!("esperaba ToolCall, got {:?}", other),
            }
        }
    }

    #[test]
    fn openai_stream_error_surfaces_message() {
        let transcript =
            "data: {\"error\":{\"message\":\"invalid api key\",\"type\":\"invalid_request_error\"}}\n\n";
        let st = run_openai_transcript(transcript, 7);
        let e = st.finish_text().unwrap_err();
        assert!(e.contains("invalid api key"), "got {}", e);
    }

    // -- B.3: provider end-to-end contra un server fake local --

    use std::io::{Read as IoRead, Write as IoWrite};
    use std::net::TcpListener;
    use std::thread;

    /// Server fake: atiende `responses.len()` conexiones en orden; en cada una drena
    /// el head del request y escribe la respuesta tal cual (después cierra → EOF).
    fn spawn_fake_server(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for resp in responses {
                let Ok((mut sock, _)) = listener.accept() else { return };
                let mut buf = [0u8; 4096];
                let mut acc: Vec<u8> = Vec::new();
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = sock.write_all(&resp);
            }
        });
        (format!("http://127.0.0.1:{}", port), handle)
    }

    fn sse_response(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n{}", body).into_bytes()
    }

    fn fake_anthropic(base_url: String, timeout_secs: u64) -> AnthropicProvider {
        AnthropicProvider {
            api_key: "k".to_string(),
            model: "m".to_string(),
            max_tokens: 64,
            base_url,
            timeout_secs,
            stream_transport: true,
        }
    }

    #[test]
    fn anthropic_provider_sse_call_and_call_stream() {
        let (url, handle) = spawn_fake_server(vec![
            sse_response(ANTHROPIC_SSE_TEXT),
            sse_response(ANTHROPIC_SSE_TEXT),
        ]);
        let p = fake_anthropic(url, 5);
        let mut req = LLMRequest::new("reason");
        req.data.insert("prompt".to_string(), "hola".to_string());

        // call(): rearmado interno — mismo contrato de siempre (texto completo).
        let resp = p.call(&req);
        assert_eq!(resp.content, "Hola mundo");

        // call_stream(): emite MÁS de una vez (un chunk por text_delta) y el
        // concatenado == el content devuelto.
        let mut chunks: Vec<String> = Vec::new();
        let resp2 = p.call_stream(&req, &mut |c| {
            chunks.push(c.to_string());
            true
        });
        handle.join().unwrap();
        assert!(chunks.len() > 1, "esperaba >1 chunk, llegaron {:?}", chunks);
        assert_eq!(chunks.concat(), "Hola mundo");
        assert_eq!(resp2.content, "Hola mundo");
    }

    #[test]
    fn anthropic_provider_sse_call_step_tokens() {
        let (url, handle) = spawn_fake_server(vec![sse_response(ANTHROPIC_SSE_TEXT)]);
        let p = fake_anthropic(url, 5);
        let mut req = LLMRequest::new("step");
        req.data.insert("prompt".to_string(), "hola".to_string());
        let r = p.call_step(&req);
        handle.join().unwrap();
        match r.step {
            LlmStep::Final(t) => assert_eq!(t, "Hola mundo"),
            other => panic!("esperaba Final, got {:?}", other),
        }
        assert_eq!(r.tokens_used, 19);
    }

    // Respuesta JSON plano (Content-Type application/json — así devuelven los errores
    // de API con stream=true, y también un compatible que ignore el stream) → va al
    // parser no-stream y extrae `error.message`.
    #[test]
    fn anthropic_provider_plain_json_error_via_stream_transport() {
        let err_body = r#"{"type":"error","error":{"type":"invalid_request_error","message":"bad model"}}"#;
        let resp = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            err_body.len(),
            err_body
        );
        let (url, handle) = spawn_fake_server(vec![resp.into_bytes()]);
        let p = fake_anthropic(url, 5);
        let mut req = LLMRequest::new("reason");
        req.data.insert("prompt".to_string(), "hola".to_string());
        let r = p.call(&req);
        handle.join().unwrap();
        assert_eq!(r.content, "[anthropic error: bad model]");
    }

    // MF-011 e2e: el timeout construido vía build_provider LLEGA al socket — un server
    // mudo por 3s con timeout de 1s falla rápido (y no panica: error como texto).
    #[test]
    fn build_provider_timeout_reaches_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                thread::sleep(std::time::Duration::from_secs(3));
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let p = build_provider(
            "anthropic",
            "k".to_string(),
            "m".to_string(),
            64,
            Some(format!("http://127.0.0.1:{}", port)),
            1,
            true,
        )
        .unwrap();
        let mut req = LLMRequest::new("reason");
        req.data.insert("prompt".to_string(), "hola".to_string());
        let start = std::time::Instant::now();
        let r = p.call(&req);
        assert!(
            r.content.starts_with("[anthropic error:"),
            "esperaba error de timeout, got {}",
            r.content
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "el timeout de 1s debe cortar antes de los 3s del server"
        );
        handle.join().unwrap();
    }

    #[test]
    fn openai_provider_sse_call_and_call_stream() {
        let (url, handle) = spawn_fake_server(vec![
            sse_response(OPENAI_SSE_TEXT),
            sse_response(OPENAI_SSE_TEXT),
        ]);
        let p = OpenAIProvider {
            api_key: "k".to_string(),
            model: "m".to_string(),
            max_tokens: 64,
            // openai_endpoint agrega /chat/completions al base tal cual.
            base_url: url,
            timeout_secs: 5,
            stream_transport: true,
        };
        let mut req = LLMRequest::new("reason");
        req.data.insert("prompt".to_string(), "hola".to_string());
        let resp = p.call(&req);
        assert_eq!(resp.content, "Hola");
        let mut chunks: Vec<String> = Vec::new();
        let resp2 = p.call_stream(&req, &mut |c| {
            chunks.push(c.to_string());
            true
        });
        handle.join().unwrap();
        assert!(chunks.len() > 1, "esperaba >1 chunk, llegaron {:?}", chunks);
        assert_eq!(resp2.content, "Hola");
    }

    // -- DE-039: contrato de `decide` (normalización + tool forzado + escalera) --

    use synsema_llm::provider::MockProvider;

    #[test]
    fn normalize_decide_table() {
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        // exacto y variantes de formato (trim, case, puntuación/comillas envolventes)
        assert_eq!(normalize_decide("ROJO", &opts), Some("ROJO".to_string()));
        assert_eq!(normalize_decide("  rojo.  ", &opts), Some("ROJO".to_string()));
        assert_eq!(normalize_decide("\"AZUL\"", &opts), Some("AZUL".to_string()));
        assert_eq!(normalize_decide("'azul!'", &opts), Some("AZUL".to_string()));
        // contención única
        assert_eq!(normalize_decide("La respuesta es AZUL", &opts), Some("AZUL".to_string()));
        // ambigua (contiene ambas) o ninguna o vacía → None
        assert_eq!(normalize_decide("rojo o azul", &opts), None);
        assert_eq!(normalize_decide("verde", &opts), None);
        assert_eq!(normalize_decide("", &opts), None);
        // los underscores son puntuación envolvente: `__yes__` y `yes` normalizan igual
        let yn = vec!["__yes__".to_string(), "__no__".to_string()];
        assert_eq!(normalize_decide("__yes__", &yn), Some("__yes__".to_string()));
        assert_eq!(normalize_decide("yes", &yn), Some("__yes__".to_string()));
        // el match exacto gana sobre la contención (opciones que se contienen entre sí)
        let sub = vec!["azul".to_string(), "azul oscuro".to_string()];
        assert_eq!(normalize_decide("azul oscuro", &sub), Some("azul oscuro".to_string()));
    }

    // ADVERSARIO (auditoría Orden 1): la contención debe ser por PALABRA COMPLETA, no
    // substring — con opciones cortas tipo si/no, "nece*si*to" NO es una elección.
    // Devolver "si" acá sería inventar una decisión que el modelo no tomó (peor que el
    // bug DE-039 original, porque encima viene "validada" por el contrato).
    #[test]
    fn normalize_decide_containment_is_word_boundary() {
        let yn = vec!["si".to_string(), "no".to_string()];
        // "si" está DENTRO de "necesito" → NO cuenta como contención.
        assert_eq!(normalize_decide("necesito más información", &yn), None);
        // "no" dentro de "noviembre" tampoco.
        assert_eq!(normalize_decide("noviembre", &yn), None);
        // Como palabra completa SÍ cuenta.
        assert_eq!(normalize_decide("creo que si", &yn), Some("si".to_string()));
        assert_eq!(normalize_decide("por ahora no, gracias", &yn), Some("no".to_string()));
        // Palabra completa en el borde del texto.
        assert_eq!(normalize_decide("si claro", &yn), Some("si".to_string()));
        // Multi-palabra con límites correctos.
        let sub = vec!["azul oscuro".to_string(), "rojo".to_string()];
        assert_eq!(
            normalize_decide("prefiero el azul oscuro para el fondo", &sub),
            Some("azul oscuro".to_string())
        );
        assert_eq!(normalize_decide("azuloscuro", &sub), None);
    }

    #[test]
    fn build_anthropic_decide_body_forces_tool() {
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        let body = build_anthropic_decide_body("m", 64, "elegí", "", &opts, false);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["tool_choice"], json!({ "type": "tool", "name": "elegir" }));
        assert_eq!(v["tools"][0]["name"], "elegir");
        assert_eq!(
            v["tools"][0]["input_schema"]["properties"]["opcion"]["enum"],
            json!(["ROJO", "AZUL"])
        );
        assert_eq!(v["tools"][0]["input_schema"]["required"], json!(["opcion"]));
        assert!(v.get("stream").is_none());
        let vs: Value =
            serde_json::from_str(&build_anthropic_decide_body("m", 64, "elegí", "", &opts, true))
                .unwrap();
        assert_eq!(vs["stream"], json!(true));
    }

    #[test]
    fn build_openai_decide_body_forces_function() {
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        let body = build_openai_decide_body("m", 64, "elegí", "", &opts, false);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["tool_choice"],
            json!({ "type": "function", "function": { "name": "elegir" } })
        );
        assert_eq!(v["tools"][0]["type"], "function");
        assert_eq!(v["tools"][0]["function"]["name"], "elegir");
        assert_eq!(
            v["tools"][0]["function"]["parameters"]["properties"]["opcion"]["enum"],
            json!(["ROJO", "AZUL"])
        );
        // con stream: el flag + stream_options (usage), como el body de texto
        let vs: Value =
            serde_json::from_str(&build_openai_decide_body("m", 64, "elegí", "", &opts, true))
                .unwrap();
        assert_eq!(vs["stream"], json!(true));
        assert_eq!(vs["stream_options"], json!({ "include_usage": true }));
    }

    /// Request de `decide` con opciones estructuradas (como la arma el wiring).
    fn decide_request(prompt: &str, options: &[&str]) -> LLMRequest {
        let mut req = LLMRequest::new("decide");
        req.data.insert("prompt".to_string(), prompt.to_string());
        req.options = options.iter().map(|s| s.to_string()).collect();
        req
    }

    const ANTHROPIC_SSE_ELEGIR: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"elegir\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"opcion\\\": \\\"ROJO\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\"}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    // El parser SSE rearma la ToolCall `elegir` y `call()` devuelve el valor ∈ set.
    #[test]
    fn anthropic_decide_sse_toolcall_returns_option() {
        let (url, handle) = spawn_fake_server(vec![sse_response(ANTHROPIC_SSE_ELEGIR)]);
        let p = fake_anthropic(url, 5);
        let r = p.call(&decide_request("elegí", &["ROJO", "AZUL"]));
        handle.join().unwrap();
        assert_eq!(r.content, "ROJO");
    }

    const OPENAI_SSE_ELEGIR: &str = concat!(
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"elegir\",\"arguments\":\"{\\\"opcion\\\": \\\"AZUL\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":4}}\n\n",
        "data: [DONE]\n\n",
    );

    #[test]
    fn openai_decide_sse_toolcall_returns_option() {
        let (url, handle) = spawn_fake_server(vec![sse_response(OPENAI_SSE_ELEGIR)]);
        let p = OpenAIProvider {
            api_key: "k".to_string(),
            model: "m".to_string(),
            max_tokens: 64,
            base_url: url,
            timeout_secs: 5,
            stream_transport: true,
        };
        let r = p.call(&decide_request("elegí", &["ROJO", "AZUL"]));
        handle.join().unwrap();
        assert_eq!(r.content, "AZUL");
    }

    /// Server fake que además CAPTURA cada request completo (head + body por
    /// Content-Length) — para aseverar el feedback del reintento de decide.
    fn spawn_capture_server(
        responses: Vec<Vec<u8>>,
    ) -> (String, thread::JoinHandle<()>, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = captured.clone();
        let handle = thread::spawn(move || {
            for resp in responses {
                let Ok((mut sock, _)) = listener.accept() else { return };
                let mut acc: Vec<u8> = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&acc[..pos]).to_lowercase();
                        let clen: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if acc.len() >= pos + 4 + clen {
                            break;
                        }
                    }
                    match sock.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                cap.lock().unwrap().push(String::from_utf8_lossy(&acc).to_string());
                let _ = sock.write_all(&resp);
            }
        });
        (format!("http://127.0.0.1:{}", port), handle, captured)
    }

    /// Transcript SSE Anthropic de texto plano con el `text` dado (para simular un
    /// modelo que respondió fuera del set pese al tool forzado).
    fn sse_anthropic_text(text: &str) -> Vec<u8> {
        sse_response(&format!(
            concat!(
                "event: message_start\n",
                "data: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":1,\"output_tokens\":0}}}}}}\n\n",
                "event: content_block_delta\n",
                "data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{}\"}}}}\n\n",
                "event: message_stop\n",
                "data: {{\"type\":\"message_stop\"}}\n\n",
            ),
            text
        ))
    }

    // Caso común: la ToolCall ya viene en el set → CERO reintentos.
    #[test]
    fn decide_contract_toolcall_needs_no_retry() {
        let (url, handle, reqs) = spawn_capture_server(vec![sse_response(ANTHROPIC_SSE_ELEGIR)]);
        let p = fake_anthropic(url, 5);
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        let out = decide_with_contract(&p, "elegí", &opts);
        handle.join().unwrap();
        assert_eq!(out, "ROJO");
        assert_eq!(reqs.lock().unwrap().len(), 1, "cero reintentos en el caso común");
    }

    // Fuera de set → UN reintento con el feedback en el body → la opción normalizada.
    #[test]
    fn decide_contract_retry_with_feedback_then_ok() {
        let (url, handle, reqs) = spawn_capture_server(vec![
            sse_anthropic_text("verde"),
            sse_anthropic_text("AZUL."),
        ]);
        let p = fake_anthropic(url, 5);
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        let out = decide_with_contract(&p, "elegí un color", &opts);
        handle.join().unwrap();
        assert_eq!(out, "AZUL");
        let reqs = reqs.lock().unwrap();
        assert_eq!(reqs.len(), 2, "exactamente UN reintento");
        // ambos requests fuerzan la tool `elegir`
        assert!(reqs[0].contains("tool_choice"), "1er request sin tool forzada: {}", reqs[0]);
        assert!(reqs[1].contains("tool_choice"), "reintento sin tool forzada: {}", reqs[1]);
        // el reintento lleva el feedback con la respuesta inválida citada
        assert!(reqs[1].contains("no es válida"), "reintento sin feedback: {}", reqs[1]);
        assert!(reqs[1].contains("verde"), "el feedback debe citar la respuesta inválida");
        assert!(reqs[1].contains("ROJO, AZUL"), "el feedback debe listar las opciones");
    }

    // Reintento también fuera de set → fallback: el crudo (degradar-con-aviso, nunca romper).
    #[test]
    fn decide_contract_fallback_returns_raw_after_retry() {
        let (url, handle, reqs) = spawn_capture_server(vec![
            sse_anthropic_text("verde"),
            sse_anthropic_text("verde"),
        ]);
        let p = fake_anthropic(url, 5);
        let opts = vec!["ROJO".to_string(), "AZUL".to_string()];
        let out = decide_with_contract(&p, "elegí un color", &opts);
        handle.join().unwrap();
        assert_eq!(out, "verde", "el fallback entrega el crudo, no rompe");
        assert_eq!(reqs.lock().unwrap().len(), 2, "un solo reintento, no un loop");
    }

    // Provider sin camino de tools (mock ≈ local GGUF): entra directo por la
    // normalización — peldaño 2 de la escalera.
    #[test]
    fn decide_contract_mock_normalizes_without_tools() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("decide".to_string(), "La respuesta es AZUL".to_string());
        let p = MockProvider::new(responses);
        let out =
            decide_with_contract(&p, "elegí", &["ROJO".to_string(), "AZUL".to_string()]);
        assert_eq!(out, "AZUL");
    }

    // Sin opciones (decide sin `between [...]`): passthrough del crudo, sin contrato.
    #[test]
    fn decide_contract_without_options_returns_raw() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("decide".to_string(), "lo que sea".to_string());
        let p = MockProvider::new(responses);
        assert_eq!(decide_with_contract(&p, "x", &[]), "lo que sea");
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
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            stream_transport: true,
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
        // F-A live: una respuesta real trae usage → el metering tiene qué acumular.
        assert!(resp.tokens_used > 0, "usage real esperado, got 0");
    }

    // =========================================================
    // Metering + budget (FRAMEWORK F1 / F-A)
    // =========================================================

    /// El contador de tokens es GLOBAL del proceso (así es el contrato de
    /// `llm_usage()`): estos tests se serializan entre sí y miden DELTAS, nunca
    /// valores absolutos — otros tests del binario no tocan el contador.
    static METER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn meter_lock() -> std::sync::MutexGuard<'static, ()> {
        METER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn step_req() -> LLMRequest {
        let mut r = LLMRequest::new("reason");
        r.data.insert("prompt".to_string(), "hola".to_string());
        r
    }

    #[test]
    fn metered_provider_accumulates() {
        let _g = meter_lock();
        // Mock guionado: call/call_stream reportan 5 tokens; el paso guionado, 7.
        let mock = MockProvider::scripted(vec![LlmStepResponse {
            step: LlmStep::Final("done".to_string()),
            tokens_used: 7,
        }])
        .with_call_tokens(5);
        let p = MeteredProvider { inner: Arc::new(mock), budget: None };
        let before = llm_tokens_total();
        let r1 = p.call(&step_req());
        assert_eq!(r1.tokens_used, 5, "los tokens del mock fluyen a la LLMResponse");
        let _ = p.call_stream(&step_req(), &mut |_| true);
        let r3 = p.call_step(&step_req());
        assert_eq!(r3.tokens_used, 7);
        assert_eq!(
            llm_tokens_total() - before,
            5 + 5 + 7,
            "call + call_stream + call_step acumulan en el contador del proceso"
        );
    }

    #[test]
    fn metered_provider_budget_cuts() {
        let _g = meter_lock();
        let mock =
            Arc::new(MockProvider::new(std::collections::HashMap::new()).with_call_tokens(8));
        let base = llm_tokens_total();
        // Budget = base + 5: la primera llamada pasa (base < base+5) y suma 8; la
        // segunda encuentra el contador ≥ budget → marker SIN delegar.
        let p = MeteredProvider { inner: mock.clone(), budget: Some(base + 5) };
        let r1 = p.call(&step_req());
        assert!(!r1.content.contains("llm budget exceeded"), "la primera pasa: {}", r1.content);
        assert_eq!(mock.call_log_len(), 1);
        assert_eq!(llm_tokens_total(), base + 8);

        let r2 = p.call(&step_req());
        assert!(
            r2.content.starts_with("[llm budget exceeded: used"),
            "marker de degradación, no error: {}",
            r2.content
        );
        assert_eq!(r2.tokens_used, 0);
        assert_eq!(mock.call_log_len(), 1, "cortó ANTES de delegar (el mock no vio la 2ª)");
        assert_eq!(llm_tokens_total(), base + 8, "el corte no acumula");

        // Las 3 superficies cortan: call_step → Final(marker); call_stream → marker
        // como único chunk y como content.
        let s = p.call_step(&step_req());
        match s.step {
            LlmStep::Final(t) => assert!(t.starts_with("[llm budget exceeded"), "{}", t),
            other => panic!("esperaba Final(marker), got {:?}", other),
        }
        let mut chunks: Vec<String> = Vec::new();
        let st = p.call_stream(&step_req(), &mut |c| {
            chunks.push(c.to_string());
            true
        });
        assert!(st.content.starts_with("[llm budget exceeded"), "{}", st.content);
        assert_eq!(chunks.len(), 1, "el marker sale como UN chunk (contrato degradado)");
        assert_eq!(mock.call_log_len(), 1, "ninguna superficie delegó tras el corte");
    }

    #[test]
    fn llm_budget_knob_parses_and_warns_on_invalid() {
        // Válido → Some; inválido o 0 → None (con warn a stderr, no verificable acá).
        let store = EnvStore::parse("SYNSEMA_LLM_BUDGET=1000");
        // El environ del proceso podría tener la var en un entorno raro de CI; este
        // test sólo usa el .env → no la seteamos ni la tocamos.
        if std::env::var("SYNSEMA_LLM_BUDGET").is_err() {
            assert_eq!(resolve_llm_budget(&store), Some(1000));
            let bad = EnvStore::parse("SYNSEMA_LLM_BUDGET=abc");
            assert_eq!(resolve_llm_budget(&bad), None);
            let zero = EnvStore::parse("SYNSEMA_LLM_BUDGET=0");
            assert_eq!(resolve_llm_budget(&zero), None);
        }
    }
}
