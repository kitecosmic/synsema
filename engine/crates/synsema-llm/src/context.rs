//! Constructor de contexto para llamadas al LLM. Port de `synsema/llm/context.py`.
//!
//! Cuando el lenguaje llama al LLM (reason/decide/analyze/generate) envía el contexto
//! COMPLETO: intent, variables en scope, reglas del owner, memoria, paso de progreso,
//! capabilities, trace. Convierte una llamada genérica en una decisión INFORMADA.
//! (Módulo de capa 10; no lo ejercita el corpus de conformidad.)

use std::collections::HashMap;

use indexmap::IndexMap;

#[derive(Default)]
pub struct LLMContext {
    pub intent: Option<String>,
    pub active_trace: Option<String>,
    pub current_step: Option<String>,
    pub progress_summary: Option<String>,
    pub rules: Vec<(String, String)>,        // (level, description)
    pub recent_memory: Vec<(String, String)>, // (category, content)
    pub variables: IndexMap<String, String>,
    pub capabilities: Vec<String>,
    pub agent_name: Option<String>,
}

impl LLMContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_intent(&mut self, intent: &str) {
        self.intent = Some(intent.to_string());
    }
    pub fn set_progress(&mut self, step: &str, summary: &str) {
        self.current_step = Some(step.to_string());
        self.progress_summary = Some(summary.to_string());
    }

    /// Prompt de sistema con todo el contexto disponible.
    pub fn build_system_prompt(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push("You are the reasoning engine for a Synsema agent.".to_string());
        if let Some(a) = &self.agent_name {
            parts.push(format!("Agent name: {}", a));
        }
        if let Some(i) = &self.intent {
            parts.push(format!("Program intent: {}", i));
        }
        if let Some(step) = &self.current_step {
            let mut s = format!("Current task step: {}", step);
            if let Some(sum) = &self.progress_summary {
                s += &format!(" ({})", sum);
            }
            parts.push(s);
        }
        if let Some(t) = &self.active_trace {
            parts.push(format!("Inside trace block: {}", t));
        }
        if !self.rules.is_empty() {
            let mut text = String::from("Owner rules in effect:\n");
            for (level, desc) in &self.rules {
                text += &format!("  [{}] {}\n", level, desc);
            }
            parts.push(text.trim_end().to_string());
        }
        if !self.recent_memory.is_empty() {
            let mut text = String::from("Relevant agent memory:\n");
            for (cat, content) in self.recent_memory.iter().take(5) {
                text += &format!("  [{}] {}\n", cat, content);
            }
            parts.push(text.trim_end().to_string());
        }
        if !self.variables.is_empty() {
            let user_vars: Vec<(&String, &String)> = self
                .variables
                .iter()
                .filter(|(_, v)| {
                    !v.starts_with("SynValue(task:")
                        && !v.starts_with("builtin:")
                        && !v.starts_with("task ")
                })
                .collect();
            if !user_vars.is_empty() {
                let mut text = String::from("Visible variables:\n");
                for (k, v) in user_vars.iter().take(15) {
                    text += &format!("  {} = {}\n", k, v);
                }
                parts.push(text.trim_end().to_string());
            }
        }
        if !self.capabilities.is_empty() {
            parts.push(format!("Available capabilities: {}", self.capabilities.join(", ")));
        }
        parts.push(
            "Respond concisely and directly. When choosing between options, respond with ONLY \
             the chosen option. When analyzing, be structured and actionable. Respect all owner \
             rules."
                .to_string(),
        );
        parts.join("\n\n")
    }
}

/// Construye un prompt completo con contexto para una operación del LLM.
pub fn build_contextual_prompt(
    operation: &str,
    data: &HashMap<String, String>,
    context: Option<&LLMContext>,
) -> String {
    let system = context.map(|c| c.build_system_prompt()).unwrap_or_default();
    let g = |k: &str| data.get(k).cloned().unwrap_or_default();

    let prompt = match operation {
        "reason" => {
            let mut p = format!("Reason about: {}\n", g("subject"));
            p += "\nProvide a clear, structured analysis.";
            p
        }
        "decide" => {
            let mut p = format!("Given: {}\n\n", g("given"));
            p += &format!("Choose the best option from: {}\n", g("options"));
            p += "Respond with ONLY the chosen option, nothing else.";
            p
        }
        "analyze" => {
            let mut p = format!("Data to analyze:\n{}\n\n", g("data"));
            p += &format!("Objective: {}\n", g("objective"));
            p += "Provide a concise, actionable analysis.";
            p
        }
        "generate" => {
            let mut p = format!("Generate: {}\n", g("target"));
            let given = g("given");
            if !given.is_empty() {
                p += &format!("\nBased on: {}\n", given);
            }
            p
        }
        _ => format!("{:?}", data),
    };

    if !system.is_empty() {
        format!("{}\n\n---\n\n{}", system, prompt)
    } else {
        prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_includes_context() {
        let mut c = LLMContext::new();
        c.set_intent("Handle support tickets");
        c.rules.push(("hard".to_string(), "max_refund <= 200".to_string()));
        c.variables.insert("customer".to_string(), "Alice".to_string());
        let p = c.build_system_prompt();
        assert!(p.contains("reasoning engine"));
        assert!(p.contains("Handle support tickets"));
        assert!(p.contains("max_refund <= 200"));
        assert!(p.contains("customer = Alice"));
    }

    #[test]
    fn system_prompt_filters_builtins() {
        let mut c = LLMContext::new();
        c.variables.insert("print".to_string(), "builtin:print".to_string());
        c.variables.insert("x".to_string(), "42".to_string());
        let p = c.build_system_prompt();
        assert!(p.contains("x = 42"));
        assert!(!p.contains("builtin:print"));
    }

    #[test]
    fn contextual_prompt_decide() {
        let mut d = HashMap::new();
        d.insert("options".to_string(), "[refund, replace]".to_string());
        d.insert("given".to_string(), "broken item".to_string());
        let p = build_contextual_prompt("decide", &d, None);
        assert!(p.contains("Choose the best option from: [refund, replace]"));
        assert!(p.contains("ONLY the chosen option"));
    }

    #[test]
    fn contextual_prompt_analyze_with_system() {
        let mut c = LLMContext::new();
        c.set_intent("Audit logs");
        let mut d = HashMap::new();
        d.insert("data".to_string(), "logs".to_string());
        d.insert("objective".to_string(), "find anomalies".to_string());
        let p = build_contextual_prompt("analyze", &d, Some(&c));
        assert!(p.contains("Audit logs")); // del system prompt
        assert!(p.contains("Objective: find anomalies"));
        assert!(p.contains("---")); // separador system/prompt
    }
}
