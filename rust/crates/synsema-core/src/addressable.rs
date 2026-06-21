//! Memoria direccionable — acceso a código eficiente en tokens. Port de
//! `synsema/core/addressable.py`.
//!
//! En vez de cargar archivos enteros, un agente direcciona partes concretas:
//!   `file.syn:task:process_order`, `file.syn:line:42-50`, `file.syn:type:Customer`.
//! Devuelve sólo la porción relevante. Construido sobre [`crate::ast_api`].

use indexmap::IndexMap;

use crate::ast::{NodeKind, Program};
use crate::ast_api::{find_task_by_name, find_types, get_task_dependencies, summarize, Summary};
use crate::parser::parse_source;

#[derive(Debug, Default)]
pub struct AddressResult {
    pub found: bool,
    pub source_lines: Vec<String>,
    pub summary: String,
    pub location: Option<String>,
    pub params: Vec<String>,
    pub deps: Vec<String>,
    pub fields: Vec<(String, String)>,
}

#[derive(Default)]
pub struct AddressableCode {
    programs: IndexMap<String, Program>,
    source_lines: IndexMap<String, Vec<String>>,
}

impl AddressableCode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parsea e indexa un archivo fuente.
    pub fn load(&mut self, filename: &str, source: &str) {
        self.source_lines
            .insert(filename.to_string(), source.split('\n').map(|s| s.to_string()).collect());
        if let Ok(program) = parse_source(source, filename) {
            self.programs.insert(filename.to_string(), program);
        }
    }

    /// Resuelve una dirección `<file>:<selector>:<id>`.
    pub fn address(&self, addr: &str) -> AddressResult {
        let mut result = AddressResult::default();
        let parts: Vec<&str> = addr.splitn(3, ':').collect();
        if parts.len() < 2 {
            result.summary = format!("Invalid address: {}", addr);
            return result;
        }
        let filename = parts[0];
        let selector = parts[1];
        let identifier = if parts.len() > 2 { parts[2] } else { "" };

        let program = match self.programs.get(filename) {
            Some(p) => p,
            None => {
                result.summary = format!("File not loaded: {}", filename);
                return result;
            }
        };
        let lines = self.source_lines.get(filename).cloned().unwrap_or_default();

        match selector {
            "summary" => {
                result.found = true;
                result.summary = format_summary(&summarize(program));
            }
            "task" => {
                if let Some(task) = find_task_by_name(program, identifier) {
                    if let NodeKind::TaskDefinition { name, parameters, .. } = &task.kind {
                        result.found = true;
                        result.location = Some(format!("{}:{}", filename, task.location.line));
                        result.source_lines = extract_lines(&lines, task.location.line, 30);
                        result.summary = format!("task {}({})", name, parameters.join(", "));
                        result.params = parameters.clone();
                        result.deps = get_task_dependencies(program, name);
                    }
                }
            }
            "signature" => {
                if let Some(task) = find_task_by_name(program, identifier) {
                    if let NodeKind::TaskDefinition { name, parameters, .. } = &task.kind {
                        result.found = true;
                        result.summary = format!("task {}({})", name, parameters.join(", "));
                    }
                }
            }
            "deps" => {
                let deps = get_task_dependencies(program, identifier);
                result.found = true;
                let listed = if deps.is_empty() { "none".to_string() } else { deps.join(", ") };
                result.summary = format!("Dependencies of {}: {}", identifier, listed);
                result.deps = deps;
            }
            "type" => {
                for t in find_types(program) {
                    if let NodeKind::TypeDefinition { name, fields } = &t.kind {
                        if name == identifier {
                            result.found = true;
                            result.location = Some(format!("{}:{}", filename, t.location.line));
                            let f =
                                fields.iter().map(|(n, ty)| format!("{}: {}", n, ty)).collect::<Vec<_>>().join(", ");
                            result.summary = format!("type {} ({})", name, f);
                            result.fields = fields.clone();
                            return result;
                        }
                    }
                }
            }
            "line" => {
                let parsed = if let Some((s, e)) = identifier.split_once('-') {
                    s.parse::<usize>().ok().zip(e.parse::<usize>().ok()).map(|(s, e)| (s - 1, e))
                } else {
                    identifier.parse::<usize>().ok().map(|s| (s - 1, s))
                };
                match parsed {
                    Some((start, end)) => {
                        result.found = true;
                        let start = start.min(lines.len());
                        let end = end.min(lines.len());
                        result.source_lines = lines[start..end.max(start)].to_vec();
                        result.location = Some(format!("{}:{}-{}", filename, start + 1, end));
                    }
                    None => result.summary = format!("Invalid line range: {}", identifier),
                }
            }
            other => {
                result.summary = format!("Unknown selector: {}", other);
            }
        }
        result
    }
}

/// Extrae las líneas de un nodo siguiendo la indentación.
fn extract_lines(lines: &[String], start_line: usize, max_lines: usize) -> Vec<String> {
    if start_line == 0 || start_line > lines.len() {
        return Vec::new();
    }
    let idx = start_line - 1;
    let mut extracted = vec![lines[idx].clone()];
    let base_indent = lines[idx].len() - lines[idx].trim_start().len();
    let end = (idx + max_lines).min(lines.len());
    for line in &lines[idx + 1..end] {
        if line.trim().is_empty() {
            extracted.push(line.clone());
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= base_indent {
            break;
        }
        extracted.push(line.clone());
    }
    extracted
}

/// Resumen del programa en formato compacto (mínimos tokens).
fn format_summary(s: &Summary) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !s.tasks.is_empty() {
        let t = s
            .tasks
            .iter()
            .map(|t| format!("{}({} params)", t.name, t.params.len()))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("Tasks: {}", t));
    }
    if !s.types.is_empty() {
        let t = s.types.iter().map(|t| t.name.clone()).collect::<Vec<_>>().join(", ");
        parts.push(format!("Types: {}", t));
    }
    if !s.agents.is_empty() {
        parts.push(format!("Agents: {}", s.agents.join(", ")));
    }
    if !s.variables.is_empty() {
        let v = s.variables.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
        parts.push(format!("Variables: {}", v));
    }
    if !s.intents.is_empty() {
        parts.push(format!("Intent: {}", s.intents[0]));
    }
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\ntask add(a, b)\n    give a + b\n\ntask multiply(a, b)\n    give a * b\n\ntask compute(x)\n    let doubled be add(x, x)\n    give multiply(doubled, 3)\n\ntype Point\n    x: number\n    y: number\n\nlet result be compute(5)\n";

    fn loaded() -> AddressableCode {
        let mut ac = AddressableCode::new();
        ac.load("test.syn", SAMPLE);
        ac
    }

    #[test]
    fn summary_sel() {
        let r = loaded().address("test.syn:summary");
        assert!(r.found);
        assert!(r.summary.contains("add"));
        assert!(r.summary.contains("Point"));
    }

    #[test]
    fn task_sel() {
        let r = loaded().address("test.syn:task:add");
        assert!(r.found);
        assert!(r.summary.contains("add"));
        assert_eq!(r.params, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn signature_sel() {
        let r = loaded().address("test.syn:signature:compute");
        assert!(r.found);
        assert!(r.summary.contains("compute"));
        assert!(r.source_lines.is_empty());
    }

    #[test]
    fn deps_sel() {
        let r = loaded().address("test.syn:deps:compute");
        assert!(r.found);
        assert!(r.deps.contains(&"add".to_string()));
    }

    #[test]
    fn type_sel() {
        let r = loaded().address("test.syn:type:Point");
        assert!(r.found);
        assert!(r.summary.contains("Point"));
    }

    #[test]
    fn line_sel() {
        let r = loaded().address("test.syn:line:1-3");
        assert!(r.found);
        assert_eq!(r.source_lines.len(), 3);
    }
}
