//! Provider LLM `local`: el adaptador entre el protocolo LLM y `synsema-infer`.
//!
//! Inferencia GGUF cuantizada embebida en el binario, CPU-only. Cero red, cero server aparte,
//! cero API key: un `.syn` con `require llm` + `SYNSEMA_LLM_PROVIDER=local` +
//! `SYNSEMA_LLM_MODEL=…` razona offline. Es el único provider que funciona con `deny net` total.
//!
//! Desde la tanda I2, `SYNSEMA_LLM_MODEL` acepta tres formas y **ninguna descarga nada**:
//! una ruta a un `.gguf`, un `modelo:tag` que ya esté en el cache de Ollama, o un `org/repo` que
//! ya esté en el cache de Hugging Face. Un dev que ya tiene Ollama corre su primer `.syn` con LLM
//! local sin bajar un byte.
//!
//! ## Qué quedó acá y qué se fue (spec `synsema-infer.md`, tanda I1)
//!
//! El cálculo —GGUF, tokenizer, pool de instancias, KV cache, generación, sampling— vive ahora
//! en el crate `synsema-infer`. Este archivo se quedó con **lo que es del protocolo LLM y no de
//! la inferencia**:
//!
//! - `LocalGgufProvider`: el `impl LLMProvider`, que traduce `LLMRequest` → texto → `LLMResponse`.
//! - El **tool-calling prompteado** (`build_local_step_prompt` / `parse_local_step`): los GGUF no
//!   tienen API de tools, así que se pide un JSON por prompt y se parsea la respuesta. Ambas
//!   funciones son PURAS y se testean sin modelo — patrón de la casa.
//! - El **puente de streaming** (`pump_chunks`): buffer acotado entre la generación y la emisión.
//!
//! La dirección de la dependencia es a propósito: **`synsema-infer` no conoce `synsema-llm`**.
//! Invertirlo haría que la capa de cálculo dependiera del protocolo, y entonces el día que la
//! misma inferencia sirva al `judge` local o a los embeddings de la DB (I3) arrastraría tipos que
//! no tienen nada que ver.
//!
//! ## Lo que NO cambió
//!
//! La carga sigue siendo lazy y memoizada (ahora por spec) para todo el proceso; el aislamiento de KV
//! sigue garantizado (y ahora lo exige el trait `Model`, así que una arquitectura no puede
//! entrar sin cumplirlo); los errores siguen saliendo como `Final("[local error: …]")` con 0
//! tokens, igual que los providers de red, y nunca por panic.

use std::path::Path;
use std::sync::OnceLock;

use serde_json::Value;

use synsema_llm::provider::{
    LLMProvider, LLMRequest, LLMResponse, LlmStep, LlmStepResponse, ToolSpec,
};

/// Los knobs viven en `synsema-infer` (quien los usa es el motor de inferencia), pero se
/// reexportan acá para que `llm_providers.rs` los siga nombrando como siempre.
pub use synsema_infer::LocalKnobs;

/// Dónde buscar modelos: se resuelve UNA vez por proceso. Mira `OLLAMA_MODELS` y `HF_HOME` (o
/// los directorios por convención) para poder reusar lo que el dev ya tiene bajado — cero
/// descarga. Ver `synsema_infer::store`.
fn store_config() -> &'static synsema_infer::StoreConfig {
    static CFG: OnceLock<synsema_infer::StoreConfig> = OnceLock::new();
    CFG.get_or_init(synsema_infer::StoreConfig::from_env)
}

/// Lo que `synsema llm status` dice sobre las arquitecturas que este binario sabe correr.
///
/// Son líneas ya armadas, no los tipos del crate de inferencia: el CLI no tiene por qué conocer
/// `ArchDef`, y así sumarle un campo a una definición no toca dos crates.
pub struct ArchReport {
    /// El backend que va a correr, que es de quien depende la lista.
    pub backend: &'static str,
    /// El directorio de definiciones del operador, si configuró uno.
    pub dir: Option<String>,
    /// Una línea por arquitectura: nombre, pasos, origen y sha.
    pub lines: Vec<String>,
    /// Lo mismo en campos, para `--json`. Un agente no tiene que parsear una frase para saber
    /// con qué sha corrió: la procedencia sirve si se puede comparar, y comparar prosa no es
    /// comparar. Los dos salen de la MISMA definición, así que no pueden discrepar.
    pub archs: Vec<ArchEntry>,
    /// Las definiciones del directorio que no cargaron, con su error.
    pub problems: Vec<String>,
}

/// Una arquitectura del registro, en campos.
pub struct ArchEntry {
    pub name: String,
    /// `decoder` o `encoder`.
    pub kind: &'static str,
    /// Cuántos pasos corre por capa. Es el tamaño de la DEFINICIÓN, así que una arquitectura
    /// compilada no tiene: ahí es `None`, no `0`.
    pub steps_per_block: Option<usize>,
    /// `en el binario`, `compilada en el binario` o la ruta del archivo del operador.
    pub origin: String,
    /// SHA-256 del texto de la definición, completo. `None` cuando no hay texto que hashear.
    pub sha256: Option<String>,
}

/// Qué arquitecturas conoce este binario y de dónde salieron (tanda I5).
///
/// **La lista es la del backend que va a correr, no la unión de los dos.** Las definiciones sólo
/// las ejecuta el backend propio: con candle activo, listarlas diría que este binario corre
/// gemma3 —que candle no corre— y que un archivo del operador está en juego cuando no lo está.
/// Un `llm status` que adorna es peor que uno que no existe, porque se le cree.
///
/// Para el backend propio la lista **no está fija en el ejecutable**: incluye lo que el operador
/// puso en `SYNSEMA_INFER_ARCHDEF`, y por eso va con el sha de cada definición.
pub fn architecture_report() -> ArchReport {
    if !synsema_infer::want_rust_backend() {
        // candle: la lista está compilada, no hay definiciones ni sha que mostrar.
        return ArchReport {
            backend: "candle",
            dir: None,
            lines: synsema_infer::candle_architectures()
                .iter()
                .map(|n| format!("{} (compilada en el binario)", n))
                .collect(),
            archs: synsema_infer::candle_architectures()
                .iter()
                .map(|n| ArchEntry {
                    name: (*n).to_string(),
                    kind: "decoder",
                    steps_per_block: None,
                    origin: "compilada en el binario".to_string(),
                    sha256: None,
                })
                .collect(),
            problems: Vec::new(),
        };
    }
    let reg = synsema_infer::arch_registry::Registry::shared();
    ArchReport {
        backend: "rust",
        dir: synsema_infer::arch_registry::configured_dir().map(|p| p.display().to_string()),
        lines: reg.all().iter().map(|d| d.summary()).collect(),
        archs: reg
            .all()
            .iter()
            .map(|d| ArchEntry {
                name: d.name.clone(),
                kind: d.kind.label(),
                steps_per_block: Some(d.block.len()),
                origin: d.origin.describe(),
                sha256: Some(d.sha256.clone()),
            })
            .collect(),
        problems: reg.problems().iter().map(|p| p.to_string()).collect(),
    }
}

/// Los modelos locales que este sistema podría usar, con su origen y su sha cuando se conoce.
/// Lo consume `synsema llm status` para poder decir "tenés esto, usá este nombre".
pub fn discovered_models() -> Vec<synsema_infer::DiscoveredModel> {
    synsema_infer::discover(store_config())
}

// =========================================================
// Tool-calling prompteado (funciones PURAS, testeables sin modelo)
// =========================================================

/// Igual que `user_content` de los providers de red: prompt + contexto opcional.
fn local_user_content(user_prompt: &str, context: &str) -> String {
    if context.is_empty() {
        user_prompt.to_string()
    } else {
        format!("{}\n{}", user_prompt, context)
    }
}

/// Igual que `stringify_json` de los providers de red: strings sin comillas, el resto
/// serializado canónico.
fn local_stringify_json(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Arma el prompt del paso tool-aware: contenido del user + catálogo (name/description/params)
/// + formato exigido. En inglés: los GGUF chicos siguen instrucciones en inglés mucho mejor que
/// en otros idiomas.
pub fn build_local_step_prompt(prompt: &str, context: &str, tools: &[ToolSpec]) -> String {
    let user = local_user_content(prompt, context);
    if tools.is_empty() {
        return user;
    }
    let mut out = String::with_capacity(user.len() + 256);
    out.push_str(&user);
    out.push_str("\n\nYou have access to the following tools:\n");
    for t in tools {
        out.push_str("- ");
        out.push_str(&t.name);
        out.push_str(": ");
        out.push_str(&t.description);
        if !t.params.is_empty() {
            out.push_str(" (parameters: ");
            out.push_str(&t.params.join(", "));
            out.push(')');
        }
        out.push('\n');
    }
    out.push_str(
        "\nTo call a tool, reply with EXACTLY one JSON object on a single line and nothing else:\n\
         {\"tool\": \"<tool name>\", \"args\": {\"<parameter>\": \"<value>\"}}\n\
         If no tool is needed, reply directly with your final answer as plain text (no JSON).",
    );
    out
}

/// Quita las líneas de code fence (```…) — los modelos chicos envuelven el JSON en fences
/// aunque se les pida que no.
fn strip_code_fences(text: &str) -> String {
    if !text.contains("```") {
        return text.to_string();
    }
    text.lines()
        .filter(|l| !l.trim_start().starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Fin (inclusive) del objeto `{…}` balanceado que empieza en `start`, respetando strings JSON
/// con escapes. Los delimitadores son ASCII → los índices caen en límites de char y el slicing
/// es seguro.
fn find_balanced_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parsea la salida del modelo como un paso tool-aware: el PRIMER objeto JSON válido (pelando
/// code fences) cuyo `"tool"` matchee el catálogo → `ToolCall` (args stringificados); cualquier
/// otra cosa (texto plano, JSON malformado, tool inexistente) → `Final` con el texto limpio.
pub fn parse_local_step(output: &str, tools: &[ToolSpec]) -> LlmStep {
    let clean = strip_code_fences(output);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = find_balanced_end(bytes, i) {
                if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&clean[i..=end]) {
                    if let Some(Value::String(name)) = m.get("tool") {
                        if tools.iter().any(|t| &t.name == name) {
                            let args = match m.get("args") {
                                Some(Value::Object(a)) => a
                                    .iter()
                                    .map(|(k, v)| (k.clone(), local_stringify_json(v)))
                                    .collect(),
                                _ => Vec::new(),
                            };
                            return LlmStep::ToolCall { name: name.clone(), args };
                        }
                    }
                }
            }
        }
        i += 1;
    }
    LlmStep::Final(clean.trim().to_string())
}

// =========================================================
// Puente generación→emisión con buffer acotado (F3-A)
// =========================================================

/// Corre `producer` en un hilo scoped y puentea sus chunks hacia `on_chunk` (invocado en el hilo
/// LLAMADOR) por un canal ACOTADO de `buffer` chunks. Semántica:
/// - El productor termina y suelta sus recursos (el préstamo del pool) aunque el consumidor siga
///   drenando el buffer — esa es la ganancia con `max_concurrent = 1`.
/// - Consumidor lento → el productor se bloquea recién con el buffer LLENO (backpressure
///   acotada, no cola infinita).
/// - `on_chunk` → `false` (o error del sink) → se dropea el receiver → el próximo `send` del
///   productor falla → su sink devuelve `false` → early-stop intacto, ahora vía canal.
/// - `thread::scope` garantiza el join: ningún hilo sobrevive a la llamada.
/// - Orden y byte-exactitud: el canal es FIFO y no parte ni funde chunks.
fn pump_chunks<T: Send>(
    buffer: usize,
    producer: impl FnOnce(&mut dyn FnMut(&str) -> bool) -> T + Send,
    on_chunk: &mut dyn FnMut(&str) -> bool,
) -> Result<T, String> {
    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(buffer.max(1));
        // `tx` se mueve ENTERO al hilo productor (no queda copia acá): cuando el productor
        // termina, el canal se cierra y el drenaje de abajo corta solo.
        let gen = s.spawn(move || producer(&mut |chunk: &str| tx.send(chunk.to_string()).is_ok()));
        for chunk in rx {
            if !on_chunk(&chunk) {
                break; // dropea `rx` → el productor ve el canal cerrado y corta
            }
        }
        gen.join().map_err(|_| "el hilo de generación abortó".to_string())
    })
}

// =========================================================
// El provider
// =========================================================

/// Provider LLM `local`. `Send + Sync`: el estado mutable (instancias del modelo con su KV) vive
/// en el pool que administra `synsema-infer`; el provider en sí sólo guarda configuración
/// inmutable.
pub struct LocalGgufProvider {
    /// Lo que el operador escribió: una ruta a un `.gguf`, un `modelo:tag` de Ollama o un
    /// `org/repo` de Hugging Face. La resolución a un archivo la hace `synsema-infer`.
    model_spec: String,
    /// Nombre corto para `name()` y el campo `model` de las respuestas.
    display_name: String,
    max_tokens: u64,
    knobs: LocalKnobs,
}

impl LocalGgufProvider {
    pub fn new(model_spec: String, max_tokens: u64, knobs: LocalKnobs) -> Self {
        // Una ruta se muestra por su archivo; un `qwen3:8b` se muestra tal cual. Mostrar el
        // basename de un blob de Ollama daría `sha256-a1b2c3…`, que no le dice nada a nadie.
        let display_name = if model_spec.contains('/')
            || model_spec.contains('\\')
            || model_spec.ends_with(".gguf")
        {
            Path::new(&model_spec)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| model_spec.clone())
        } else {
            model_spec.clone()
        };
        Self { model_spec, display_name, max_tokens, knobs }
    }

    /// Camino común de generación. El knob de threads se aplica ANTES de la primera operación
    /// del backend (después, el pool global de rayon ya quedó fijado) — por eso vive acá y no
    /// en `synsema-infer`, que a propósito no lee variables de entorno.
    fn generate_text(
        &self,
        user_text: &str,
        sink: Option<&mut dyn FnMut(&str) -> bool>,
    ) -> Result<(String, u64), String> {
        if let Some(n) = self.knobs.threads {
            if std::env::var_os("RAYON_NUM_THREADS").is_none() {
                std::env::set_var("RAYON_NUM_THREADS", n.to_string());
            }
        }
        synsema_infer::generate(
            &self.model_spec,
            store_config(),
            user_text,
            &self.knobs,
            self.max_tokens,
            sink,
        )
    }
}

impl LLMProvider for LocalGgufProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let user = local_user_content(&prompt, &context);
        let (content, tokens) = match self.generate_text(&user, None) {
            Ok((text, t)) => (text, t),
            Err(e) => (format!("[local error: {}]", e), 0),
        };
        LLMResponse { content, model: self.display_name.clone(), tokens_used: tokens }
    }

    /// Streaming real: el único provider que emite token a token. Los errores van como RETORNO
    /// `"[local error: …]"` (patrón de la casa), nunca por chunks.
    ///
    /// La generación corre en un hilo scoped y los chunks pasan por un canal acotado
    /// (`stream_buffer`) — ver `pump_chunks`. El camino sin sink (`call`/`call_step`) no cambia
    /// ni un byte.
    fn call_stream(
        &self,
        request: &LLMRequest,
        on_chunk: &mut dyn FnMut(&str) -> bool,
    ) -> LLMResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let user = local_user_content(&prompt, &context);
        let result = pump_chunks(
            self.knobs.stream_buffer,
            |sink| self.generate_text(&user, Some(sink)),
            on_chunk,
        );
        let (content, tokens) = match result {
            Ok(Ok((text, t))) => (text, t),
            Ok(Err(e)) | Err(e) => (format!("[local error: {}]", e), 0),
        };
        LLMResponse { content, model: self.display_name.clone(), tokens_used: tokens }
    }

    fn name(&self) -> String {
        format!("local:{}", self.display_name)
    }

    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        let prompt = request.data.get("prompt").cloned().unwrap_or_default();
        let context = request.data.get("context").cloned().unwrap_or_default();
        let step_prompt = build_local_step_prompt(&prompt, &context, &request.tools);
        match self.generate_text(&step_prompt, None) {
            Ok((text, tokens)) => LlmStepResponse {
                step: parse_local_step(&text, &request.tools),
                tokens_used: tokens,
            },
            Err(e) => LlmStepResponse {
                step: LlmStep::Final(format!("[local error: {}]", e)),
                tokens_used: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn tool(name: &str, desc: &str, params: &[&str]) -> ToolSpec {
        ToolSpec {
            name: name.to_string(),
            description: desc.to_string(),
            params: params.iter().map(|s| s.to_string()).collect(),
        }
    }

    // -- build_local_step_prompt --

    #[test]
    fn step_prompt_includes_catalog_and_format() {
        let tools = [
            tool("get_weather", "get the weather", &["city"]),
            tool("send_mail", "send an email", &["to", "body"]),
        ];
        let p = build_local_step_prompt("What's the weather?", "ctx-here", &tools);
        assert!(p.contains("What's the weather?"));
        assert!(p.contains("ctx-here"));
        assert!(p.contains("get_weather") && p.contains("get the weather") && p.contains("city"));
        assert!(p.contains("send_mail") && p.contains("to, body"));
        assert!(p.contains("{\"tool\""), "debe exigir el formato JSON: {}", p);
    }

    #[test]
    fn step_prompt_without_tools_is_plain() {
        let p = build_local_step_prompt("hola", "", &[]);
        assert_eq!(p, "hola");
        let p2 = build_local_step_prompt("hola", "ctx", &[]);
        assert_eq!(p2, "hola\nctx");
    }

    // -- parse_local_step --

    #[test]
    fn parse_clean_json_tool_call() {
        let tools = [tool("get_weather", "d", &["city"])];
        let step =
            parse_local_step(r#"{"tool": "get_weather", "args": {"city": "Madrid"}}"#, &tools);
        match step {
            LlmStep::ToolCall { name, args } => {
                assert_eq!(name, "get_weather");
                assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
            }
            _ => panic!("esperaba ToolCall, got {:?}", step),
        }
    }

    #[test]
    fn parse_json_in_code_fence() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out = "```json\n{\"tool\": \"get_weather\", \"args\": {\"city\": \"Madrid\"}}\n```";
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_json_embedded_in_prose() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out =
            "Sure, let me check.\n{\"tool\": \"get_weather\", \"args\": {\"city\": \"Madrid\"}}\nDone.";
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_tool_falls_to_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        let out = r#"{"tool": "rm_rf", "args": {}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::Final(t) => assert!(t.contains("rm_rf")),
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_plain_text_is_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        match parse_local_step("The weather is sunny.", &tools) {
            LlmStep::Final(t) => assert_eq!(t, "The weather is sunny."),
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_malformed_json_is_final() {
        let tools = [tool("get_weather", "d", &["city"])];
        match parse_local_step(r#"{"tool": "get_weather", "args": {"#, &tools) {
            LlmStep::Final(_) => {}
            other => panic!("esperaba Final, got {:?}", other),
        }
    }

    #[test]
    fn parse_non_string_args_stringified() {
        let tools = [tool("calc", "d", &["n", "flag"])];
        let out = r#"{"tool": "calc", "args": {"n": 42, "flag": true, "obj": {"a": 1}}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { args, .. } => {
                let get = |k: &str| args.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
                assert_eq!(get("n").as_deref(), Some("42"));
                assert_eq!(get("flag").as_deref(), Some("true"));
                assert_eq!(get("obj").as_deref(), Some(r#"{"a":1}"#));
            }
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_braces_inside_strings_dont_break_balance() {
        let tools = [tool("echo", "d", &["msg"])];
        let out = r#"{"tool": "echo", "args": {"msg": "a { b } c \" d"}}"#;
        match parse_local_step(out, &tools) {
            LlmStep::ToolCall { args, .. } => {
                assert_eq!(args[0].1, "a { b } c \" d");
            }
            other => panic!("esperaba ToolCall, got {:?}", other),
        }
    }

    // -- F3-A: pump_chunks (deterministas, sin modelo) --

    // Orden FIFO intacto y byte-exactitud: lo que el productor emite es lo que el consumidor ve,
    // chunk a chunk, y el retorno del productor llega entero.
    #[test]
    fn pump_chunks_order_and_exactness() {
        let chunks_in = ["Ho", "la", " mundo"];
        let mut got: Vec<String> = Vec::new();
        let r = pump_chunks(
            4,
            |sink| {
                let mut full = String::new();
                for c in chunks_in {
                    if !sink(c) {
                        break;
                    }
                    full.push_str(c);
                }
                full
            },
            &mut |c| {
                got.push(c.to_string());
                true
            },
        );
        assert_eq!(r.unwrap(), "Hola mundo");
        assert_eq!(got, vec!["Ho".to_string(), "la".to_string(), " mundo".to_string()]);
    }

    // Early-stop vía receiver dropeado: `on_chunk` → false al PRIMER chunk → el productor ve el
    // canal cerrado en su próximo send y corta (no produce los 5).
    #[test]
    fn pump_chunks_early_stop_via_receiver_drop() {
        let mut n = 0;
        let r = pump_chunks(
            1,
            |sink| {
                let mut sent = 0;
                for c in ["a", "b", "c", "d", "e"] {
                    if !sink(c) {
                        break;
                    }
                    sent += 1;
                }
                sent
            },
            &mut |_| {
                n += 1;
                false
            },
        );
        assert_eq!(n, 1, "el consumidor debía ver exactamente un chunk");
        // Con buffer 1 el productor puede colar a lo sumo un chunk extra antes de ver el canal
        // cerrado — pero jamás los cinco.
        assert!(r.unwrap() <= 2, "el productor debía cortar temprano");
    }

    // La ganancia F3-A: el productor TERMINA (y soltaría el préstamo del pool) mientras el
    // consumidor lento sigue drenando el buffer.
    #[test]
    fn pump_chunks_producer_finishes_before_slow_drain() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let done = AtomicBool::new(false);
        let mut last_saw_done = false;
        pump_chunks(
            32,
            |sink| {
                for c in ["a", "b", "c", "d"] {
                    sink(c);
                }
                done.store(true, Ordering::SeqCst);
            },
            &mut |_| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                last_saw_done = done.load(Ordering::SeqCst);
                true
            },
        )
        .unwrap();
        assert!(
            last_saw_done,
            "el productor debía terminar antes de que el consumidor lento drenara todo"
        );
    }

    // -- Tests en vivo (gated por SYNSEMA_TEST_GGUF; skip limpio si falta — patrón dev-db).
    //    El GGUF JAMÁS va al repo: bajalo a mano y exportá el path. --

    fn test_gguf_path() -> Option<String> {
        match std::env::var("SYNSEMA_TEST_GGUF") {
            Ok(p) if !p.trim().is_empty() => Some(p),
            _ => {
                eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/path/a/modelo.gguf para el test live");
                None
            }
        }
    }

    // call() genera texto y dos llamadas consecutivas no se contaminan (KV aislado).
    #[test]
    fn live_call_generates_and_isolates_kv() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut r1 = LLMRequest::new("reason");
        r1.data.insert("prompt".to_string(), "Reply with exactly one word: apple".to_string());
        let a = p.call(&r1);
        let mut r2 = LLMRequest::new("reason");
        r2.data.insert("prompt".to_string(), "Reply with exactly one word: banana".to_string());
        let b = p.call(&r2);
        assert!(!a.content.is_empty(), "primera respuesta vacía");
        assert!(!b.content.is_empty(), "segunda respuesta vacía");
        assert!(!a.content.starts_with("[local error"), "error: {}", a.content);
        assert!(!b.content.starts_with("[local error"), "error: {}", b.content);
        // Aislamiento: la segunda respuesta responde a SU prompt, no arrastra el primero.
        assert!(
            b.content.to_lowercase().contains("banana"),
            "la 2ª llamada no respondió a su prompt (¿KV contaminado?): {}",
            b.content
        );
    }

    // Streaming real — ≥2 chunks para una respuesta multi-token, y la concatenación de los
    // chunks == el retorno, BYTE-exacto (la garantía de la detokenización incremental).
    #[test]
    fn live_call_stream_chunks_concat_exact() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut req = LLMRequest::new("stream");
        req.data.insert("prompt".to_string(), "Count from one to ten in words.".to_string());
        let mut chunks: Vec<String> = Vec::new();
        let resp = p.call_stream(&req, &mut |c| {
            chunks.push(c.to_string());
            true
        });
        assert!(!resp.content.starts_with("[local error"), "error: {}", resp.content);
        assert!(chunks.len() >= 2, "esperaba ≥2 chunks, got {}: {:?}", chunks.len(), chunks);
        assert_eq!(chunks.concat(), resp.content, "concat de chunks != retorno");
    }

    // Early-stop — `on_chunk` → false tras el PRIMER chunk corta la generación (sin panic), y la
    // llamada SIGUIENTE no ve contaminación (KV aislado).
    #[test]
    fn live_call_stream_early_stop_and_isolation() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 64, LocalKnobs::default());
        let mut req = LLMRequest::new("stream");
        req.data.insert("prompt".to_string(), "Write a long story about the sea.".to_string());
        let mut n = 0;
        let resp = p.call_stream(&req, &mut |_| {
            n += 1;
            false
        });
        assert_eq!(n, 1, "debía cortar tras el primer chunk");
        assert!(
            resp.content.len() < 200,
            "cortó tarde ({} chars): {}",
            resp.content.len(),
            resp.content
        );
        let mut r2 = LLMRequest::new("reason");
        r2.data.insert("prompt".to_string(), "Reply with exactly one word: banana".to_string());
        let b = p.call(&r2);
        assert!(
            b.content.to_lowercase().contains("banana"),
            "la llamada post-corte no respondió a su prompt (¿KV contaminado?): {}",
            b.content
        );
    }

    // Con max_concurrent=1, una SEGUNDA llamada NO espera a que el consumidor lento del primer
    // stream termine de drenar — el préstamo del pool se libera al terminar la GENERACIÓN.
    #[test]
    fn live_stream_slow_drain_releases_pool() {
        let Some(path) = test_gguf_path() else { return };
        let p = Arc::new(LocalGgufProvider::new(path, 16, LocalKnobs::default()));
        // Warmup: paga la carga para que los tiempos de abajo midan sólo generación.
        let mut warm = LLMRequest::new("reason");
        warm.data.insert("prompt".to_string(), "hi".to_string());
        let _ = p.call(&warm);

        let p1 = p.clone();
        let h = std::thread::spawn(move || {
            let mut req = LLMRequest::new("stream");
            req.data.insert("prompt".to_string(), "Count from one to ten in words.".to_string());
            let t0 = std::time::Instant::now();
            let _ = p1.call_stream(&req, &mut |_| {
                std::thread::sleep(std::time::Duration::from_millis(300)); // cliente lento
                true
            });
            t0.elapsed()
        });
        // Dar tiempo a que el stream 1 esté en curso, luego competir por la instancia.
        std::thread::sleep(std::time::Duration::from_millis(700));
        let mut req2 = LLMRequest::new("reason");
        req2.data.insert("prompt".to_string(), "Reply with exactly one word: pong".to_string());
        let t0 = std::time::Instant::now();
        let r2 = p.call(&req2);
        let fast = t0.elapsed();
        let slow_total = h.join().expect("hilo del stream lento");
        assert!(!r2.content.starts_with("[local error"), "error: {}", r2.content);
        assert!(
            fast.as_secs_f64() < slow_total.as_secs_f64() * 0.8,
            "la 2ª llamada no debía esperar el drenaje completo (fast {:?} vs slow {:?})",
            fast,
            slow_total
        );
    }

    // call_step() con catálogo → ToolCall bien parseada; prompt trivial → Final.
    #[test]
    fn live_call_step_tool_and_final() {
        let Some(path) = test_gguf_path() else { return };
        let p = LocalGgufProvider::new(path, 128, LocalKnobs::default());
        let tools = vec![
            tool("get_weather", "Get the current weather for a city", &["city"]),
            tool("send_mail", "Send an email", &["to", "body"]),
        ];
        let mut req = LLMRequest::new("step").with_tools(tools.clone());
        req.data.insert(
            "prompt".to_string(),
            "Use the get_weather tool to find the weather in Madrid. You MUST call the tool."
                .to_string(),
        );
        let r = p.call_step(&req);
        assert!(r.tokens_used > 0, "tokens_used debe contar prompt + generados");
        match r.step {
            LlmStep::ToolCall { name, .. } => assert_eq!(name, "get_weather"),
            LlmStep::Final(t) => panic!("esperaba ToolCall, el modelo respondió: {}", t),
        }

        // Prompt trivial SIN relación con el catálogo (un 0.5B se distrae si el prompt menciona
        // cualquier cosa cercana a una tool).
        let mut req2 = LLMRequest::new("step").with_tools(tools);
        req2.data
            .insert("prompt".to_string(), "What is 2 plus 2? Reply with just the number.".to_string());
        let r2 = p.call_step(&req2);
        match r2.step {
            LlmStep::Final(t) => assert!(!t.is_empty()),
            LlmStep::ToolCall { name, .. } => panic!("no debía llamar tool, llamó: {}", name),
        }
    }
}
