//! Protocolo de recuperación de errores + escalación a humano. Port de
//! `syntecnia/runtime/recovery.py`.
//!
//! Ante un error: 1) DIAGNOSE (diagnóstico rico), 2) RECOVER (retry/fallback/partial/
//! speculate), 3) ESCALATE (opciones estructuradas al humano), 4) RECORD (log de
//! decisiones para precedentes). Es maquinaria standalone (no expuesta al lenguaje).

use std::time::{SystemTime, UNIX_EPOCH};

use syntecnia_core::types::SynValue;

use crate::error_reporter::{ErrorDiagnostic, ErrorReporter};

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Closure de estrategia: produce un SynValue o falla con mensaje.
pub type StrategyFn = Box<dyn FnMut() -> Result<SynValue, String>>;

#[derive(Clone, Debug)]
pub struct RecoveryAttempt {
    pub strategy: String,
    pub description: String,
    pub success: bool,
    pub result: Option<SynValue>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EscalationOption {
    pub key: String,
    pub label: String,
    pub description: String,
    pub impact: String,
}

#[derive(Clone, Debug)]
pub struct HumanDecision {
    pub timestamp: f64,
    pub error_type: String,
    pub error_message: String,
    pub context: String,
    pub options_presented: Vec<String>,
    pub chosen_option: String,
    pub chosen_label: String,
    pub outcome: String,
    pub agent_name: String,
}

#[derive(Default)]
pub struct RecoveryResult {
    pub recovered: bool,
    pub value: Option<SynValue>,
    pub strategy_used: String,
    pub attempts: Vec<RecoveryAttempt>,
    pub escalated: bool,
    pub human_decision: Option<HumanDecision>,
    pub diagnostic: Option<ErrorDiagnostic>,
}

/// Estrategias provistas por el caller (todas opcionales).
#[derive(Default)]
pub struct RecoveryOptions {
    pub retry_fn: Option<StrategyFn>,
    pub fallback_value: Option<SynValue>,
    pub partial_fn: Option<StrategyFn>,
    pub speculate_fns: Vec<StrategyFn>,
    pub context: String,
}

#[allow(clippy::type_complexity)]
pub struct RecoveryProtocol {
    pub error_reporter: ErrorReporter,
    pub human_callback: Option<Box<dyn FnMut(&str, &str) -> String>>,
    pub output_callback: Option<Box<dyn FnMut(&str)>>,
    pub decision_log: Vec<HumanDecision>,
    pub max_retry_attempts: usize,
    pub retry_backoff_ms: Vec<u64>,
}

impl Default for RecoveryProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryProtocol {
    pub fn new() -> Self {
        RecoveryProtocol {
            error_reporter: ErrorReporter::new(),
            human_callback: None,
            output_callback: None,
            decision_log: Vec::new(),
            max_retry_attempts: 3,
            retry_backoff_ms: vec![100, 500, 2000],
        }
    }

    fn output(&mut self, text: &str) {
        if let Some(cb) = self.output_callback.as_mut() {
            cb(text);
        }
    }

    /// Protocolo completo: diagnostica, intenta estrategias, escala al humano.
    pub fn handle_error(
        &mut self,
        error_type: &str,
        message: &str,
        mut opts: RecoveryOptions,
    ) -> RecoveryResult {
        let mut result = RecoveryResult::default();
        let diag = self.error_reporter.build_diagnostic(error_type, message, None, None);

        self.output(&format!("[RECOVERY] Error detected: {}", diag.message));
        self.output(&format!(
            "[RECOVERY] Category: {}, Recoverable: {}",
            diag.error_category, diag.recoverable
        ));

        let has_strategies = opts.retry_fn.is_some()
            || opts.fallback_value.is_some()
            || opts.partial_fn.is_some()
            || !opts.speculate_fns.is_empty();

        if diag.recoverable || has_strategies {
            // Retry (errores IO/transitorios o retry provisto por el caller).
            if opts.retry_fn.is_some() && (diag.retry_makes_sense || has_strategies) {
                let mut f = opts.retry_fn.take().unwrap();
                let attempt = self.try_retry(&mut f);
                let ok = attempt.success;
                let val = attempt.result.clone();
                result.attempts.push(attempt);
                if ok {
                    result.recovered = true;
                    result.value = val;
                    result.strategy_used = "retry".to_string();
                    self.output("[RECOVERY] Recovered via retry");
                    result.diagnostic = Some(diag);
                    return result;
                }
            }
            // Fallback.
            if let Some(fb) = opts.fallback_value.take() {
                result.attempts.push(RecoveryAttempt {
                    strategy: "fallback".to_string(),
                    description: "Using fallback value".to_string(),
                    success: true,
                    result: Some(fb.clone()),
                    error: None,
                });
                result.recovered = true;
                result.value = Some(fb);
                result.strategy_used = "fallback".to_string();
                self.output("[RECOVERY] Recovered via fallback value");
                result.diagnostic = Some(diag);
                return result;
            }
            // Partial.
            if let Some(mut pf) = opts.partial_fn.take() {
                let attempt = self.try_partial(&mut pf);
                let ok = attempt.success;
                let val = attempt.result.clone();
                result.attempts.push(attempt);
                if ok {
                    result.recovered = true;
                    result.value = val;
                    result.strategy_used = "partial".to_string();
                    self.output("[RECOVERY] Recovered via partial results");
                    result.diagnostic = Some(diag);
                    return result;
                }
            }
            // Speculate (alternativas).
            let specs = std::mem::take(&mut opts.speculate_fns);
            for (i, mut sf) in specs.into_iter().enumerate() {
                let attempt = self.try_speculate(&mut sf, i);
                let ok = attempt.success;
                let val = attempt.result.clone();
                result.attempts.push(attempt);
                if ok {
                    result.recovered = true;
                    result.value = val;
                    result.strategy_used = format!("speculate:{}", i);
                    self.output(&format!("[RECOVERY] Recovered via alternative approach {}", i));
                    result.diagnostic = Some(diag);
                    return result;
                }
            }
        }

        // Todas las estrategias automáticas fallaron → escalar.
        self.output("[RECOVERY] Automatic recovery failed. Escalating to human.");
        result.escalated = true;
        if self.human_callback.is_some() {
            let decision = self.escalate_to_human(&diag, &opts.context);
            if let Some(d) = decision {
                self.decision_log.push(d.clone());
                result.human_decision = Some(d);
            }
        } else {
            self.output("[RECOVERY] No human handler configured. Error is unrecoverable.");
        }
        result.diagnostic = Some(diag);
        result
    }

    fn try_retry(&mut self, retry_fn: &mut StrategyFn) -> RecoveryAttempt {
        for i in 0..self.max_retry_attempts {
            let attempt_num = i + 1;
            let backoff = self.retry_backoff_ms[i.min(self.retry_backoff_ms.len() - 1)];
            self.output(&format!(
                "[RECOVERY] Retry attempt {}/{} (backoff: {}ms)",
                attempt_num, self.max_retry_attempts, backoff
            ));
            if backoff > 0 {
                std::thread::sleep(std::time::Duration::from_millis(backoff));
            }
            match retry_fn() {
                Ok(v) => {
                    return RecoveryAttempt {
                        strategy: "retry".to_string(),
                        description: format!("Retry attempt {} succeeded", attempt_num),
                        success: true,
                        result: Some(v),
                        error: None,
                    }
                }
                Err(e) => {
                    if attempt_num == self.max_retry_attempts {
                        return RecoveryAttempt {
                            strategy: "retry".to_string(),
                            description: format!("All {} retry attempts failed", self.max_retry_attempts),
                            success: false,
                            result: None,
                            error: Some(e),
                        };
                    }
                }
            }
        }
        RecoveryAttempt {
            strategy: "retry".to_string(),
            description: "Retry exhausted".to_string(),
            success: false,
            result: None,
            error: None,
        }
    }

    fn try_partial(&mut self, partial_fn: &mut StrategyFn) -> RecoveryAttempt {
        self.output("[RECOVERY] Trying partial results strategy");
        match partial_fn() {
            Ok(v) => RecoveryAttempt {
                strategy: "partial".to_string(),
                description: "Partial results obtained".to_string(),
                success: true,
                result: Some(v),
                error: None,
            },
            Err(e) => RecoveryAttempt {
                strategy: "partial".to_string(),
                description: "Partial results failed".to_string(),
                success: false,
                result: None,
                error: Some(e),
            },
        }
    }

    fn try_speculate(&mut self, spec_fn: &mut StrategyFn, index: usize) -> RecoveryAttempt {
        self.output(&format!("[RECOVERY] Trying alternative approach {}", index));
        match spec_fn() {
            Ok(v) => RecoveryAttempt {
                strategy: format!("speculate:{}", index),
                description: format!("Alternative approach {} succeeded", index),
                success: true,
                result: Some(v),
                error: None,
            },
            Err(e) => RecoveryAttempt {
                strategy: format!("speculate:{}", index),
                description: format!("Alternative approach {} failed", index),
                success: false,
                result: None,
                error: Some(e),
            },
        }
    }

    fn escalate_to_human(&mut self, diag: &ErrorDiagnostic, context: &str) -> Option<HumanDecision> {
        let options = generate_default_options(diag);
        // (mensaje de escalación → output; omitido el detalle para brevedad)
        self.output("ESCALATION REQUIRED");
        let keys: Vec<String> = options.iter().map(|o| o.key.clone()).collect();
        let prompt = format!("Choose option ({})", keys.join(", "));
        let cb = self.human_callback.as_mut().unwrap();
        let response = cb("ask", &prompt);
        let mut chosen = response.trim().to_uppercase();
        let labels: std::collections::HashMap<String, String> =
            options.iter().map(|o| (o.key.clone(), o.label.clone())).collect();
        if !labels.contains_key(&chosen) {
            for o in &options {
                let prefix: String = o.label.chars().take(chosen.len()).collect();
                if chosen == o.key || chosen == prefix.to_uppercase() {
                    chosen = o.key.clone();
                    break;
                }
            }
        }
        let chosen_label = labels.get(&chosen).cloned().unwrap_or_else(|| chosen.clone());
        let decision = HumanDecision {
            timestamp: now_secs(),
            error_type: diag.error_type.clone(),
            error_message: diag.message.clone(),
            context: if context.is_empty() {
                diag.active_intent.clone().unwrap_or_default()
            } else {
                context.to_string()
            },
            options_presented: options.iter().map(|o| format!("{}: {}", o.key, o.label)).collect(),
            chosen_option: chosen.clone(),
            chosen_label: chosen_label.clone(),
            outcome: String::new(),
            agent_name: String::new(),
        };
        self.output(&format!("[DECISION] Human chose: {} — {}", chosen, chosen_label));
        Some(decision)
    }

    /// Busca una decisión pasada para un error similar (precedente).
    pub fn find_precedent(&self, error_type: &str, context: &str) -> Option<&HumanDecision> {
        self.decision_log.iter().rev().find(|d| {
            d.error_type == error_type && (context.is_empty() || d.context.contains(context))
        })
    }

    pub fn save_decisions(&self, filepath: &str) -> std::io::Result<()> {
        let arr: Vec<serde_json::Value> = self
            .decision_log
            .iter()
            .map(|d| {
                serde_json::json!({
                    "timestamp": d.timestamp,
                    "error_type": d.error_type,
                    "error_message": d.error_message,
                    "context": d.context,
                    "options": d.options_presented,
                    "chosen": d.chosen_option,
                    "chosen_label": d.chosen_label,
                    "outcome": d.outcome,
                })
            })
            .collect();
        std::fs::write(filepath, serde_json::to_string_pretty(&arr).unwrap_or_default())
    }

    pub fn load_decisions(&mut self, filepath: &str) {
        let text = match std::fs::read_to_string(filepath) {
            Ok(t) => t,
            Err(_) => return,
        };
        let arr: Vec<serde_json::Value> = match serde_json::from_str(&text) {
            Ok(a) => a,
            Err(_) => return,
        };
        for d in arr {
            self.decision_log.push(HumanDecision {
                timestamp: d.get("timestamp").and_then(|v| v.as_f64()).unwrap_or(0.0),
                error_type: d.get("error_type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                error_message: d.get("error_message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                context: d.get("context").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                options_presented: d
                    .get("options")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                chosen_option: d.get("chosen").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                chosen_label: d.get("chosen_label").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                outcome: d.get("outcome").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                agent_name: String::new(),
            });
        }
    }
}

/// Opciones de escalación por defecto según el tipo de error.
fn generate_default_options(diag: &ErrorDiagnostic) -> Vec<EscalationOption> {
    let mut options: Vec<EscalationOption> = Vec::new();
    if diag.retry_makes_sense {
        options.push(EscalationOption {
            key: "A".into(),
            label: "Retry later".into(),
            description: "Pause and retry after a delay".into(),
            impact: "Operation will be delayed but may succeed".into(),
        });
    }
    if diag.error_category == "io" {
        options.push(EscalationOption {
            key: "B".into(),
            label: "Use fallback".into(),
            description: "Continue with default/cached data".into(),
            impact: "Results may be incomplete or outdated".into(),
        });
    }
    if diag.error_category == "data" {
        options.push(EscalationOption {
            key: "C".into(),
            label: "Skip this item".into(),
            description: "Skip the problematic data and continue".into(),
            impact: "Some items will be missing from results".into(),
        });
    }
    options.push(EscalationOption {
        key: "D".into(),
        label: "Abort".into(),
        description: "Stop the entire operation".into(),
        impact: "Nothing will be processed".into(),
    });
    if options.len() == 1 {
        options.insert(
            0,
            EscalationOption {
                key: "A".into(),
                label: "Retry once".into(),
                description: "Try the operation one more time".into(),
                impact: "May succeed if the issue was transient".into(),
            },
        );
    }
    // Re-key secuencialmente A, B, C, ...
    for (i, opt) in options.iter_mut().enumerate() {
        opt.key = ((b'A' + i as u8) as char).to_string();
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use syntecnia_core::types::syn_text;

    #[test]
    fn retry_succeeds() {
        let mut p = RecoveryProtocol::new();
        p.max_retry_attempts = 2;
        p.retry_backoff_ms = vec![0, 0];
        let count = Rc::new(RefCell::new(0));
        let c = count.clone();
        let opts = RecoveryOptions {
            retry_fn: Some(Box::new(move || {
                *c.borrow_mut() += 1;
                if *c.borrow() < 2 {
                    Err("Temporary failure".to_string())
                } else {
                    Ok(syn_text("success!"))
                }
            })),
            ..Default::default()
        };
        let r = p.handle_error("Exception", "Temporary failure", opts);
        assert!(r.recovered);
        assert_eq!(r.strategy_used, "retry");
        assert_eq!(r.value.unwrap().to_string(), "success!");
    }

    #[test]
    fn fallback() {
        let mut p = RecoveryProtocol::new();
        let opts = RecoveryOptions { fallback_value: Some(syn_text("default_data")), ..Default::default() };
        let r = p.handle_error("Exception", "Service unavailable", opts);
        assert!(r.recovered);
        assert_eq!(r.strategy_used, "fallback");
        assert_eq!(r.value.unwrap().to_string(), "default_data");
    }

    #[test]
    fn partial() {
        let mut p = RecoveryProtocol::new();
        let opts = RecoveryOptions {
            partial_fn: Some(Box::new(|| Ok(syn_text("partial_result")))),
            ..Default::default()
        };
        let r = p.handle_error("Exception", "Full data unavailable", opts);
        assert!(r.recovered);
        assert_eq!(r.strategy_used, "partial");
    }

    #[test]
    fn speculate() {
        let mut p = RecoveryProtocol::new();
        let opts = RecoveryOptions {
            speculate_fns: vec![
                Box::new(|| Err("A also fails".to_string())),
                Box::new(|| Ok(syn_text("B worked!"))),
            ],
            ..Default::default()
        };
        let r = p.handle_error("Exception", "Primary approach failed", opts);
        assert!(r.recovered);
        assert_eq!(r.strategy_used, "speculate:1");
        assert_eq!(r.value.unwrap().to_string(), "B worked!");
    }

    #[test]
    fn all_fail_escalates() {
        let mut p = RecoveryProtocol::new();
        p.max_retry_attempts = 1;
        p.retry_backoff_ms = vec![0];
        p.human_callback = Some(Box::new(|_action, _msg| "A".to_string()));
        let opts = RecoveryOptions {
            retry_fn: Some(Box::new(|| Err("still broken".to_string()))),
            speculate_fns: vec![Box::new(|| Err("still broken".to_string()))],
            context: "processing orders".to_string(),
            ..Default::default()
        };
        let r = p.handle_error("Exception", "Persistent failure", opts);
        assert!(r.escalated);
        assert!(r.human_decision.is_some());
        assert_eq!(r.human_decision.unwrap().chosen_option, "A");
    }

    #[test]
    fn precedent_lookup() {
        let mut p = RecoveryProtocol::new();
        p.decision_log.push(HumanDecision {
            timestamp: 0.0,
            error_type: "RuntimeError".into(),
            error_message: "API timeout".into(),
            context: "sync_inventory".into(),
            options_presented: vec!["A: Retry".into(), "B: Skip".into()],
            chosen_option: "B".into(),
            chosen_label: "Skip".into(),
            outcome: "worked fine".into(),
            agent_name: String::new(),
        });
        let precedent = p.find_precedent("RuntimeError", "inventory");
        assert!(precedent.is_some());
        assert_eq!(precedent.unwrap().chosen_option, "B");
    }

    #[test]
    fn no_precedent() {
        let p = RecoveryProtocol::new();
        assert!(p.find_precedent("UnknownError", "").is_none());
    }

    #[test]
    fn decision_persistence() {
        let path = std::env::temp_dir().join(format!("syn_dec_{}.json", std::process::id()));
        let path = path.to_string_lossy().to_string();
        let mut p = RecoveryProtocol::new();
        p.decision_log.push(HumanDecision {
            timestamp: 0.0,
            error_type: "TestError".into(),
            error_message: "test msg".into(),
            context: "test".into(),
            options_presented: vec!["A: Do it".into()],
            chosen_option: "A".into(),
            chosen_label: "Do it".into(),
            outcome: String::new(),
            agent_name: String::new(),
        });
        p.save_decisions(&path).unwrap();
        let mut p2 = RecoveryProtocol::new();
        p2.load_decisions(&path);
        assert_eq!(p2.decision_log.len(), 1);
        assert_eq!(p2.decision_log[0].error_type, "TestError");
        let _ = std::fs::remove_file(&path);
    }
}
