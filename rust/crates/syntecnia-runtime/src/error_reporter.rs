//! Diagnósticos ricos de error. Port de `syntecnia/runtime/error_reporter.py`.
//!
//! Cuando algo falla, Syntecnia da: qué falló y dónde, el call stack, las variables
//! visibles, el código fuente alrededor, el intent/trace, y sugerencias por tipo de
//! error. Pensado para que un AGENTE lo consuma (estructurado, accionable).

use indexmap::IndexMap;
use regex::RegexBuilder;

use syntecnia_core::tokens::SourceLocation;

/// Clasificación de un mensaje de error.
#[derive(Clone, Debug)]
pub struct Classification {
    pub category: String,
    pub recoverable: bool,
    pub retry_makes_sense: bool,
    pub suggestions: Vec<String>,
}

/// Patrones de error (en orden; el primero que matchea gana). Espeja ERROR_PATTERNS.
/// (regex case-insensitive, categoría, recoverable, retry_makes_sense, sugerencias)
fn error_patterns() -> Vec<(&'static str, &'static str, bool, bool, Vec<&'static str>)> {
    vec![
        ("Division by zero", "data", true, false, vec![
            "Add a guard: when divisor != 0 before dividing",
            "Add invariant: divisor > 0 before the division",
            "Provide a default: when divisor == 0, give 0 otherwise give x / divisor",
        ]),
        ("Undefined variable", "logic", false, false, vec![
            "Check spelling of the variable name",
            "Ensure the variable is defined with 'let' before use",
            "If inside a task, check the variable is passed as parameter",
        ]),
        ("Cannot iterate over", "type", false, false, vec![
            "Ensure the value is a list before using 'each'",
            "Use type_of() to check the type at runtime",
            "Wrap single values in a list: [value]",
        ]),
        ("Index .* out of bounds", "data", true, false, vec![
            "Check length() before accessing by index",
            "Use find_first() instead of direct indexing",
            "Add invariant: index < length(list)",
        ]),
        ("Cannot call value of type", "type", false, false, vec![
            "Check that the name refers to a task, not a variable",
            "Ensure the task is defined before it's called",
            "Use type_of() to inspect the value",
        ]),
        ("Capability not granted", "capability", false, false, vec![
            "Add the matching 'require' at the top of the program",
            "Run with the --grant flag, e.g. --grant file:/path/*",
            "Check if this operation matches the declared intent",
        ]),
        ("Intent violation", "capability", false, false, vec![
            "The operation falls outside the declared intent",
            "Update the intent declaration to include this operation",
            "Run with --no-strict-intent to allow (not recommended)",
        ]),
        ("Invariant violation", "logic", true, false, vec![
            "The program state violates a declared guarantee",
            "Check the data that led to this state",
            "Add validation before the invariant point",
        ]),
        ("HTTP", "io", true, true, vec![
            "The external service may be temporarily unavailable",
            "Retry with exponential backoff",
            "Check if the URL and credentials are correct",
            "Use a fallback data source",
        ]),
        ("Timed out", "io", true, true, vec![
            "The operation took too long",
            "Increase the timeout parameter",
            "Retry — it may be a temporary slowdown",
            "Consider an async approach",
        ]),
        ("File not found", "io", true, false, vec![
            "Check that the file path is correct",
            "Use file_exists() before reading",
            "Provide a default value if the file is optional",
        ]),
        ("Loop exceeded maximum iterations", "logic", false, false, vec![
            "The loop condition never becomes false",
            "Add a counter limit or stop condition",
            "Check the loop variable is actually changing",
        ]),
        ("Cannot set undefined variable", "logic", false, false, vec![
            "Use 'let' to define the variable first, then 'set' to change it",
            "'set' only works on already-defined variables",
        ]),
        ("Map has no key", "data", true, false, vec![
            "Check if the key exists with contains()",
            "Use a default value pattern",
            "Verify the data structure with show or log",
        ]),
    ]
}

/// Clasifica un mensaje de error y devuelve sugerencias (re.search case-insensitive).
pub fn classify_error(message: &str) -> Classification {
    for (pat, category, recoverable, retry, suggestions) in error_patterns() {
        let re = RegexBuilder::new(pat).case_insensitive(true).build();
        if let Ok(re) = re {
            if re.is_match(message) {
                return Classification {
                    category: category.to_string(),
                    recoverable,
                    retry_makes_sense: retry,
                    suggestions: suggestions.iter().map(|s| s.to_string()).collect(),
                };
            }
        }
    }
    Classification {
        category: "unknown".to_string(),
        recoverable: false,
        retry_makes_sense: false,
        suggestions: vec!["Check the error message for details".to_string()],
    }
}

/// Un frame del call stack.
#[derive(Clone, Debug)]
pub struct CallFrame {
    pub task_name: String,
    pub location: Option<SourceLocation>,
    pub arguments: Vec<(String, String)>,
}

impl std::fmt::Display for CallFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let loc = self.location.as_ref().map(|l| format!(" at {}", l)).unwrap_or_default();
        if self.arguments.is_empty() {
            write!(f, "{}{}", self.task_name, loc)
        } else {
            let args =
                self.arguments.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", ");
            write!(f, "{}({}){}", self.task_name, args, loc)
        }
    }
}

/// Diagnóstico completo de un error de runtime (lo consume un agente o humano).
#[derive(Clone, Debug, Default)]
pub struct ErrorDiagnostic {
    pub error_type: String,
    pub message: String,
    pub location: Option<SourceLocation>,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub source_context: Vec<String>,
    pub error_line_content: String,
    pub call_stack: Vec<CallFrame>,
    pub visible_variables: IndexMap<String, String>,
    pub active_trace: Option<String>,
    pub active_intent: Option<String>,
    pub suggestions: Vec<String>,
    pub error_category: String,
    pub recoverable: bool,
    pub retry_makes_sense: bool,
}

impl ErrorDiagnostic {
    /// Formato para humano (terminal).
    pub fn format_human(&self) -> String {
        let bar = "=".repeat(60);
        let mut lines = vec![bar.clone(), format!("ERROR: {}", self.message), bar.clone()];
        if !self.file.is_empty() && self.line > 0 {
            lines.push(format!("\n  Location: {}:{}:{}", self.file, self.line, self.column));
        }
        if let Some(intent) = &self.active_intent {
            lines.push(format!("  Intent: {}", intent));
        }
        if let Some(trace) = &self.active_trace {
            lines.push(format!("  Inside trace: {}", trace));
        }
        if !self.source_context.is_empty() {
            lines.push("\n  Source:".to_string());
            for (i, src_line) in self.source_context.iter().enumerate() {
                let line_num = self.line as i64 - (self.source_context.len() / 2) as i64 + i as i64;
                let marker = if line_num == self.line as i64 { " >> " } else { "    " };
                lines.push(format!("  {}{:>4} | {}", marker, line_num, src_line));
            }
        }
        if !self.call_stack.is_empty() {
            lines.push("\n  Call stack:".to_string());
            for (i, frame) in self.call_stack.iter().enumerate() {
                let prefix = if i == 0 { "  → " } else { "    " };
                lines.push(format!("  {}{}", prefix, frame));
            }
        }
        if !self.visible_variables.is_empty() {
            lines.push("\n  Variables at failure:".to_string());
            for (name, value) in &self.visible_variables {
                if value.starts_with("SynValue(task:") || value.starts_with("builtin:") {
                    continue;
                }
                lines.push(format!("    {} = {}", name, value));
            }
        }
        if !self.suggestions.is_empty() {
            lines.push("\n  Suggestions:".to_string());
            for (i, sug) in self.suggestions.iter().enumerate() {
                lines.push(format!("    {}. {}", i + 1, sug));
            }
        }
        lines.push(format!("\n  Category: {}", self.error_category));
        lines.push(format!("  Recoverable: {}", if self.recoverable { "yes" } else { "no" }));
        if self.retry_makes_sense {
            lines.push("  Retry may help: yes".to_string());
        }
        lines.push(bar);
        lines.join("\n")
    }

    /// Formato para agente (data estructurada).
    pub fn format_agent(&self) -> serde_json::Value {
        let variables: serde_json::Map<String, serde_json::Value> = self
            .visible_variables
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        serde_json::json!({
            "error_type": self.error_type,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "error_category": self.error_category,
            "recoverable": self.recoverable,
            "retry_makes_sense": self.retry_makes_sense,
            "call_stack": self.call_stack.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
            "variables": serde_json::Value::Object(variables),
            "suggestions": self.suggestions,
            "active_intent": self.active_intent,
            "active_trace": self.active_trace,
        })
    }
}

/// Construye diagnósticos ricos a partir de fallos de runtime.
#[derive(Default)]
pub struct ErrorReporter {
    source_lines: IndexMap<String, Vec<String>>,
    pub call_stack: Vec<CallFrame>,
    active_intent: Option<String>,
    active_traces: Vec<String>,
}

impl ErrorReporter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_source(&mut self, filename: &str, source: &str) {
        self.source_lines
            .insert(filename.to_string(), source.split('\n').map(|s| s.to_string()).collect());
    }

    pub fn set_intent(&mut self, intent: &str) {
        self.active_intent = Some(intent.to_string());
    }

    pub fn push_trace(&mut self, name: &str) {
        self.active_traces.push(name.to_string());
    }
    pub fn pop_trace(&mut self) {
        self.active_traces.pop();
    }

    /// Construye un ErrorDiagnostic. `env_vars` = (nombre, str(valor)) visibles al fallar.
    pub fn build_diagnostic(
        &self,
        error_type: &str,
        message: &str,
        location: Option<&SourceLocation>,
        env_vars: Option<&[(String, String)]>,
    ) -> ErrorDiagnostic {
        let mut diag = ErrorDiagnostic {
            error_type: error_type.to_string(),
            message: message.to_string(),
            ..Default::default()
        };
        if let Some(loc) = location {
            diag.location = Some(loc.clone());
            diag.file = loc.file.clone();
            diag.line = loc.line;
            diag.column = loc.column;
            // Contexto: 3 líneas antes y después.
            if let Some(lines) = self.source_lines.get(&loc.file) {
                let start = loc.line.saturating_sub(4);
                let end = (loc.line + 3).min(lines.len());
                diag.source_context = lines[start..end].to_vec();
                if loc.line > 0 && loc.line <= lines.len() {
                    diag.error_line_content = lines[loc.line - 1].clone();
                }
            }
        }
        diag.call_stack = self.call_stack.clone();
        if let Some(vars) = env_vars {
            for (name, value) in vars {
                diag.visible_variables.insert(name.clone(), value.clone());
            }
        }
        diag.active_intent = self.active_intent.clone();
        diag.active_trace = self.active_traces.last().cloned();
        let c = classify_error(message);
        diag.error_category = c.category;
        diag.recoverable = c.recoverable;
        diag.retry_makes_sense = c.retry_makes_sense;
        diag.suggestions = c.suggestions;
        diag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_division_by_zero() {
        let r = classify_error("Division by zero");
        assert_eq!(r.category, "data");
        assert!(r.recoverable);
        assert!(!r.suggestions.is_empty());
    }
    #[test]
    fn classify_undefined_variable() {
        let r = classify_error("Undefined variable: 'foo'");
        assert_eq!(r.category, "logic");
        assert!(!r.recoverable);
    }
    #[test]
    fn classify_capability() {
        assert_eq!(classify_error("Capability not granted: net(evil.com)").category, "capability");
    }
    #[test]
    fn classify_http_error() {
        let r = classify_error("HTTP 500 from api.example.com");
        assert_eq!(r.category, "io");
        assert!(r.retry_makes_sense);
    }
    #[test]
    fn classify_timeout() {
        let r = classify_error("Timed out after 30s");
        assert_eq!(r.category, "io");
        assert!(r.retry_makes_sense);
    }
    #[test]
    fn classify_file_not_found() {
        let r = classify_error("File not found: /data/report.csv");
        assert_eq!(r.category, "io");
        assert!(r.recoverable);
    }
    #[test]
    fn classify_invariant() {
        assert_eq!(classify_error("Invariant violation: x > 0").category, "logic");
    }
    #[test]
    fn classify_map_key() {
        assert_eq!(classify_error("Map has no key 'email'").category, "data");
    }
    #[test]
    fn classify_index_out_of_bounds_regex() {
        assert_eq!(classify_error("Index 5 out of bounds (list length 3)").category, "data");
    }

    #[test]
    fn build_diagnostic_captures_context_and_vars() {
        let mut r = ErrorReporter::new();
        r.load_source("test.syn", "let x be 0\nlet y be 10 / x\nprint(y)");
        let loc = SourceLocation { file: "test.syn".into(), line: 2, column: 15, offset: 20 };
        let vars = vec![("x".to_string(), "0".to_string()), ("y".to_string(), "undefined".to_string())];
        let diag = r.build_diagnostic("FakeError", "Division by zero", Some(&loc), Some(&vars));
        assert_eq!(diag.file, "test.syn");
        assert_eq!(diag.line, 2);
        assert!(!diag.source_context.is_empty());
        assert!(diag.visible_variables.contains_key("x"));
        assert!(diag.visible_variables["x"].contains("0"));
    }

    #[test]
    fn human_format_has_message_intent_suggestions() {
        let mut r = ErrorReporter::new();
        r.load_source("test.syn", "line1\nline2\nline3\nline4\nline5");
        r.set_intent("Process orders");
        let loc = SourceLocation { file: "test.syn".into(), line: 3, column: 5, offset: 0 };
        let diag = r.build_diagnostic("Exception", "Division by zero", Some(&loc), None);
        let text = diag.format_human();
        assert!(text.contains("Division by zero"));
        assert!(text.contains("Process orders"));
        assert!(text.contains("Suggestions:"));
    }

    #[test]
    fn agent_format_has_category_and_retry() {
        let r = ErrorReporter::new();
        let diag = r.build_diagnostic("Exception", "HTTP 500 error", None, None);
        let data = diag.format_agent();
        assert_eq!(data["error_type"], "Exception");
        assert_eq!(data["error_category"], "io");
        assert_eq!(data["retry_makes_sense"], true);
    }
}
