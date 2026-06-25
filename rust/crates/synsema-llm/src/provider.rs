//! Proveedores LLM. Port de `synsema/llm/provider.py`.
//!
//! El motor de razonamiento es swappable. `MockProvider` da respuestas predecibles
//! para testing; los proveedores de red (anthropic/openai/…) se identifican por
//! `name()` (las llamadas reales son capa posterior — necesitan red/keys y no son
//! deterministas, fuera del corpus).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct LLMRequest {
    pub operation: String,
    pub data: HashMap<String, String>,
    /// Catálogo de tools ofrecidas al LLM en este paso (FASE 1 tool-calling). Lo arma
    /// el programa como dato (ver el loop seguro en-lenguaje). Vacío para las ops de
    /// texto (reason/decide/analyze/generate) → retrocompat total.
    pub tools: Vec<ToolSpec>,
}

impl LLMRequest {
    pub fn new(operation: &str) -> Self {
        Self { operation: operation.to_string(), data: HashMap::new(), tools: Vec::new() }
    }
    /// Builder: adjunta el catálogo de tools a la request.
    pub fn with_tools(mut self, t: Vec<ToolSpec>) -> Self {
        self.tools = t;
        self
    }
}

#[derive(Clone, Debug)]
pub struct LLMResponse {
    pub content: String,
    pub model: String,
}

/// Una tool ofrecida al LLM (la arma el programa como dato; ver el loop seguro).
#[derive(Clone, Debug)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub params: Vec<String>,
}

/// El paso que decide el LLM: respuesta final O una tool-call estructurada.
/// `args` es nombre→valor STRINGIFICADO (zero-dep: sin serde; valores tipados =
/// FASE futura cuando los providers de red parseen JSON con el parser propio).
#[derive(Clone, Debug)]
pub enum LlmStep {
    Final(String),
    ToolCall { name: String, args: Vec<(String, String)> },
}

/// Un paso del LLM + los tokens que consumió (para el budget en-lenguaje).
#[derive(Clone, Debug)]
pub struct LlmStepResponse {
    pub step: LlmStep,
    pub tokens_used: u64,
}

pub trait LLMProvider: Send + Sync {
    fn call(&self, request: &LLMRequest) -> LLMResponse;
    fn name(&self) -> String;
    /// Paso estructurado (tool-aware). Default: envuelve `call()` como `Final` con 0
    /// tokens, así `NetworkProvider` y cualquier provider viejo siguen andando sin
    /// cambios (no rompe los providers existentes).
    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        LlmStepResponse { step: LlmStep::Final(self.call(request).content), tokens_used: 0 }
    }
}

/// Proveedor mock: respuestas predecibles + log de llamadas. Para tool-calling, una
/// cola GUIONADA de pasos deterministas (`scripted`) que `call_step` consume en orden.
pub struct MockProvider {
    pub responses: HashMap<String, String>,
    call_log: Mutex<Vec<LLMRequest>>,
    /// Cola de pasos guionados que `call_step` consume (FIFO). Cuando se vacía,
    /// `call_step` cae a `Final` desde `responses` → un Mock SIN `Final` nunca termina
    /// (habilita el test de `max_steps`).
    scripted: Mutex<VecDeque<LlmStepResponse>>,
}

impl MockProvider {
    pub fn new(responses: HashMap<String, String>) -> Self {
        Self { responses, call_log: Mutex::new(Vec::new()), scripted: Mutex::new(VecDeque::new()) }
    }
    /// Constructor guionado: una secuencia determinista de pasos (sin red). `responses`
    /// queda vacío; la cola se consume en orden por `call_step`.
    pub fn scripted(steps: Vec<LlmStepResponse>) -> Self {
        Self {
            responses: HashMap::new(),
            call_log: Mutex::new(Vec::new()),
            scripted: Mutex::new(steps.into_iter().collect()),
        }
    }
    /// Encola un paso guionado más.
    pub fn push_step(&self, s: LlmStepResponse) {
        self.scripted.lock().unwrap().push_back(s);
    }
    pub fn call_log_len(&self) -> usize {
        self.call_log.lock().unwrap().len()
    }
}

impl LLMProvider for MockProvider {
    fn call(&self, request: &LLMRequest) -> LLMResponse {
        self.call_log.lock().unwrap().push(request.clone());
        let content = self
            .responses
            .get(&request.operation)
            .cloned()
            .unwrap_or_else(|| format!("[mock:{}]", request.operation));
        LLMResponse { content, model: "mock".to_string() }
    }
    fn name(&self) -> String {
        "mock".to_string()
    }
    /// Devuelve el siguiente paso guionado (registrando la request en `call_log`, igual
    /// que `call`). Si la cola está vacía, cae a `Final` desde `responses[operation]`
    /// (o `[mock:op]`) con 0 tokens → así un Mock sin `Final` nunca termina.
    fn call_step(&self, request: &LLMRequest) -> LlmStepResponse {
        self.call_log.lock().unwrap().push(request.clone());
        if let Some(step) = self.scripted.lock().unwrap().pop_front() {
            return step;
        }
        let content = self
            .responses
            .get(&request.operation)
            .cloned()
            .unwrap_or_else(|| format!("[mock:{}]", request.operation));
        LlmStepResponse { step: LlmStep::Final(content), tokens_used: 0 }
    }
}

/// Proveedor de red (sólo identidad por ahora; la llamada real es capa posterior).
pub struct NetworkProvider {
    pub prefix: String,
    pub model: String,
}

impl LLMProvider for NetworkProvider {
    fn call(&self, _request: &LLMRequest) -> LLMResponse {
        LLMResponse {
            content: format!("[{} provider: real calls not implemented yet]", self.prefix),
            model: self.model.clone(),
        }
    }
    fn name(&self) -> String {
        format!("{}:{}", self.prefix, self.model)
    }
}

/// Factory: crea un proveedor por nombre (espeja `create_provider`).
pub fn create_provider(name: &str) -> Option<Box<dyn LLMProvider>> {
    let net = |prefix: &str, model: &str| -> Option<Box<dyn LLMProvider>> {
        Some(Box::new(NetworkProvider { prefix: prefix.to_string(), model: model.to_string() }))
    };
    match name.to_lowercase().as_str() {
        "mock" => Some(Box::new(MockProvider::new(HashMap::new()))),
        "anthropic" | "claude" => net("anthropic", "claude-sonnet-4-20250514"),
        "openai" | "gpt" => net("openai", "gpt-4o"),
        "minimax" | "minimax-m1" => net("minimax", "MiniMax-M3"),
        "ollama" | "local" => net("ollama", "llama3"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider() {
        let mut responses = HashMap::new();
        responses.insert("reason".to_string(), "This is a mock reasoning result".to_string());
        responses.insert("decide".to_string(), "option_a".to_string());
        let p = MockProvider::new(responses);
        let resp = p.call(&LLMRequest::new("reason"));
        assert_eq!(resp.content, "This is a mock reasoning result");
        assert_eq!(p.call_log_len(), 1);
    }

    #[test]
    fn create_provider_factory() {
        assert_eq!(create_provider("mock").unwrap().name(), "mock");
        assert!(create_provider("anthropic").unwrap().name().contains("anthropic"));
    }

    // Helpers de tests (FASE 1 tool-calling).
    fn tool(name: &str, args: &[(&str, &str)], tok: u64) -> LlmStepResponse {
        LlmStepResponse {
            step: LlmStep::ToolCall {
                name: name.to_string(),
                args: args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            },
            tokens_used: tok,
        }
    }
    fn final_(text: &str, tok: u64) -> LlmStepResponse {
        LlmStepResponse { step: LlmStep::Final(text.to_string()), tokens_used: tok }
    }

    // F1: la cola guionada se consume en orden; ToolCall/Final correctos; tokens se propagan.
    #[test]
    fn scripted_steps_in_order_with_tokens() {
        let p = MockProvider::scripted(vec![
            tool("get_weather", &[("city", "Madrid")], 12),
            final_("done", 7),
        ]);
        let r1 = p.call_step(&LLMRequest::new("step"));
        match r1.step {
            LlmStep::ToolCall { name, args } => {
                assert_eq!(name, "get_weather");
                assert_eq!(args, vec![("city".to_string(), "Madrid".to_string())]);
            }
            _ => panic!("esperaba ToolCall"),
        }
        assert_eq!(r1.tokens_used, 12);

        let r2 = p.call_step(&LLMRequest::new("step"));
        match r2.step {
            LlmStep::Final(t) => assert_eq!(t, "done"),
            _ => panic!("esperaba Final"),
        }
        assert_eq!(r2.tokens_used, 7);
        // Las dos llamadas quedaron registradas en el call_log.
        assert_eq!(p.call_log_len(), 2);
    }

    // F2: cola vacía → cae a Final (habilita max_steps). Tras agotar la cola, siempre Final.
    #[test]
    fn empty_queue_falls_to_final() {
        let p = MockProvider::scripted(vec![tool("noop", &[], 1)]);
        let _ = p.call_step(&LLMRequest::new("step")); // consume el único paso
        let r = p.call_step(&LLMRequest::new("step")); // cola vacía → Final
        match r.step {
            LlmStep::Final(_) => {}
            _ => panic!("esperaba Final tras vaciar la cola"),
        }
        assert_eq!(r.tokens_used, 0);
    }

    // Default del trait: un provider que sólo implementa `call` obtiene `call_step`
    // como Final (0 tokens) → NetworkProvider y providers viejos siguen andando.
    #[test]
    fn default_call_step_wraps_call() {
        let np = NetworkProvider { prefix: "anthropic".to_string(), model: "m".to_string() };
        let r = np.call_step(&LLMRequest::new("reason"));
        match r.step {
            LlmStep::Final(t) => assert!(t.contains("not implemented")),
            _ => panic!("esperaba Final del default"),
        }
        assert_eq!(r.tokens_used, 0);
    }

    // push_step encola incrementalmente.
    #[test]
    fn push_step_enqueues() {
        let p = MockProvider::scripted(vec![]);
        p.push_step(final_("hola", 3));
        let r = p.call_step(&LLMRequest::new("step"));
        assert_eq!(r.tokens_used, 3);
    }
}
