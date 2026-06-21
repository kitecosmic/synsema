//! Proveedores LLM. Port de `synsema/llm/provider.py`.
//!
//! El motor de razonamiento es swappable. `MockProvider` da respuestas predecibles
//! para testing; los proveedores de red (anthropic/openai/…) se identifican por
//! `name()` (las llamadas reales son capa posterior — necesitan red/keys y no son
//! deterministas, fuera del corpus).

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct LLMRequest {
    pub operation: String,
    pub data: HashMap<String, String>,
}

impl LLMRequest {
    pub fn new(operation: &str) -> Self {
        Self { operation: operation.to_string(), data: HashMap::new() }
    }
}

#[derive(Clone, Debug)]
pub struct LLMResponse {
    pub content: String,
    pub model: String,
}

pub trait LLMProvider: Send + Sync {
    fn call(&self, request: &LLMRequest) -> LLMResponse;
    fn name(&self) -> String;
}

/// Proveedor mock: respuestas predecibles + log de llamadas.
pub struct MockProvider {
    pub responses: HashMap<String, String>,
    call_log: Mutex<Vec<LLMRequest>>,
}

impl MockProvider {
    pub fn new(responses: HashMap<String, String>) -> Self {
        Self { responses, call_log: Mutex::new(Vec::new()) }
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
}
