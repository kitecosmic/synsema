//! Declaración de intent de Synsema.
//!
//! Port fiel de `synsema/capabilities/intent.py`. El intent es DESCRIPTIVO:
//! da contexto de auditoría y de LLM, pero NO autoriza ni bloquea acciones — eso
//! lo hacen exclusivamente las capabilities. `check_action` registra y SIEMPRE
//! permite. Se congela al empezar la ejecución (anti prompt-injection); el freeze
//! lo aplica el intérprete (redeclarar un intent congelado es error).

/// Etiquetas de operaciones con efecto, sólo para el audit log (informativas).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionCategory {
    DataRead,
    DataWrite,
    NetRead,
    NetWrite,
    FileRead,
    FileWrite,
    Exec,
    Communicate,
    Compute,
    HumanInteract,
    LlmReason,
    AgentSpawn,
    AgentSignal,
}

impl ActionCategory {
    pub fn name(&self) -> &'static str {
        use ActionCategory::*;
        match self {
            DataRead => "DATA_READ",
            DataWrite => "DATA_WRITE",
            NetRead => "NET_READ",
            NetWrite => "NET_WRITE",
            FileRead => "FILE_READ",
            FileWrite => "FILE_WRITE",
            Exec => "EXEC",
            Communicate => "COMMUNICATE",
            Compute => "COMPUTE",
            HumanInteract => "HUMAN_INTERACT",
            LlmReason => "LLM_REASON",
            AgentSpawn => "AGENT_SPAWN",
            AgentSignal => "AGENT_SIGNAL",
        }
    }
}

/// Intent declarado: descripción legible + flag de congelado.
#[derive(Clone, Debug)]
pub struct IntentScope {
    pub description: String,
    pub frozen: bool,
}

/// Compat: el intent ya no bloquea, así que nunca se producen violaciones acá.
#[derive(Clone, Debug, Default)]
pub struct IntentViolation {
    pub action: String,
    pub detail: String,
    pub intent_description: String,
}

/// Registro de una acción (audit log). Informativo: nunca gatea ejecución.
#[derive(Clone, Debug)]
pub struct CheckRecord {
    pub category: String,
    pub detail: String,
    pub result: String,
    pub reason: String,
}

/// Sostiene el intent declarado (una descripción). Descriptivo, no de seguridad.
pub struct IntentEnforcer {
    pub intent: Option<IntentScope>,
    pub checks: Vec<CheckRecord>,
    /// Siempre vacío: el intent nunca bloquea. Compat.
    pub violations: Vec<IntentViolation>,
    /// Retenido por compatibilidad de API; sin efecto.
    pub strict: bool,
}

impl Default for IntentEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentEnforcer {
    pub fn new() -> Self {
        Self {
            intent: None,
            checks: Vec::new(),
            violations: Vec::new(),
            strict: true,
        }
    }

    pub fn set_intent(&mut self, description: &str) {
        self.intent = Some(IntentScope {
            description: description.to_string(),
            frozen: false,
        });
    }

    pub fn freeze_intent(&mut self) {
        if let Some(intent) = &mut self.intent {
            intent.frozen = true;
        }
    }

    /// Registra una acción y SIEMPRE permite (el intent es descriptivo).
    pub fn check_action(&mut self, category: Option<ActionCategory>, detail: &str) -> bool {
        self.checks.push(CheckRecord {
            category: category.map(|c| c.name().to_string()).unwrap_or_else(|| "?".to_string()),
            detail: detail.to_string(),
            result: "allowed".to_string(),
            reason: "intent_is_descriptive".to_string(),
        });
        true
    }

    pub fn get_report(&self) -> String {
        let mut lines = vec!["Intent Report".to_string()];
        match &self.intent {
            Some(intent) => {
                lines.push(format!("  Intent: {}", intent.description));
                lines.push(format!("  Frozen: {}", if intent.frozen { "True" } else { "False" }));
                lines.push(
                    "  Security: enforced by capabilities (require), not by the intent text."
                        .to_string(),
                );
            }
            None => lines.push("  No intent declared.".to_string()),
        }
        lines.push(format!("\n  Actions recorded: {}", self.checks.len()));
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_intent_stores_description() {
        let mut e = IntentEnforcer::new();
        e.set_intent("Process customer orders");
        assert_eq!(e.intent.unwrap().description, "Process customer orders");
    }

    #[test]
    fn no_intent_allows_all() {
        let mut e = IntentEnforcer::new();
        assert!(e.check_action(Some(ActionCategory::NetWrite), "send"));
        assert!(e.check_action(Some(ActionCategory::Exec), "run"));
    }

    #[test]
    fn intent_does_not_block_any_category() {
        let mut e = IntentEnforcer::new();
        e.set_intent("Read and analyze data");
        assert!(e.check_action(Some(ActionCategory::Exec), "run rm -rf"));
        assert!(e.check_action(Some(ActionCategory::NetWrite), "post"));
        assert!(e.check_action(Some(ActionCategory::FileWrite), "write"));
        assert_eq!(e.violations.len(), 0);
    }

    #[test]
    fn intent_is_language_agnostic() {
        for desc in ["Generar reportes", "Read files", "Faire un rapport", "report data"] {
            let mut e = IntentEnforcer::new();
            e.set_intent(desc);
            assert!(e.check_action(Some(ActionCategory::FileWrite), "write"));
            assert_eq!(e.intent.as_ref().unwrap().description, desc);
        }
    }

    #[test]
    fn freeze_sets_flag() {
        let mut e = IntentEnforcer::new();
        e.set_intent("Read data");
        assert!(!e.intent.as_ref().unwrap().frozen);
        e.freeze_intent();
        assert!(e.intent.as_ref().unwrap().frozen);
    }

    #[test]
    fn get_report_shows_description() {
        let mut e = IntentEnforcer::new();
        e.set_intent("Process orders");
        assert!(e.get_report().contains("Process orders"));
    }
}
