//! Sintaxis flat (estilo documento). Port de `syntecnia/core/flat_syntax.py`.
//!
//! En vez de bloques por indentación, se escribe estilo documento:
//!     task process_order(order):
//!         When amount of order > 1000, approve "Large order".
//!         Otherwise, log "Small order".
//! Reglas: cada paso una línea terminada en punto; condiciones con coma
//! ("When X, do Y."); "Then ..." secuencial; "Otherwise, ..."; bloques cierran con
//! "end" o línea en blanco. Es un pre-procesador: flat → estándar → lexer → parser.

use regex::Regex;

struct FlatTranslator {
    re_task: Regex,
    re_agent: Regex,
    re_type: Regex,
    re_when: Regex,
    re_otherwise_when: Regex,
    re_otherwise: Regex,
    re_then: Regex,
    re_each: Regex,
}

impl FlatTranslator {
    fn new() -> Self {
        FlatTranslator {
            re_task: Regex::new(r"^(task\s+\w+\([^)]*\))\s*:").unwrap(),
            re_agent: Regex::new(r"^(agent\s+\w+)\s*:").unwrap(),
            re_type: Regex::new(r"^(type\s+\w+)\s*:").unwrap(),
            re_when: Regex::new(r"^[Ww]hen\s+(.+?),\s*(.+)$").unwrap(),
            re_otherwise_when: Regex::new(r"^[Oo]therwise\s+when\s+(.+?),\s*(.+)$").unwrap(),
            re_otherwise: Regex::new(r"^[Oo]therwise,?\s*(.+)$").unwrap(),
            re_then: Regex::new(r"^[Tt]hen\s+(.+)$").unwrap(),
            re_each: Regex::new(r"^[Ff]or each\s+(\w+)\s+in\s+(.+?),\s*(.+)$").unwrap(),
        }
    }

    fn translate(&self, source: &str) -> String {
        let lines: Vec<&str> = source.split('\n').collect();
        let mut out: Vec<String> = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let stripped = line.trim();
            if stripped.is_empty() || stripped.starts_with("--") {
                out.push(line.to_string());
                i += 1;
                continue;
            }
            // Definiciones con dos puntos (task/agent/type): cuerpo indentado.
            if let Some(header) = self
                .re_task
                .captures(stripped)
                .or_else(|| self.re_agent.captures(stripped))
                .map(|c| c.get(1).unwrap().as_str().to_string())
            {
                out.push(header);
                i += 1;
                let body = self.collect_body(&lines, i);
                for bl in &body {
                    let translated = self.translate_statement(bl.trim());
                    for tl in translated.split('\n') {
                        out.push(format!("    {}", tl));
                    }
                }
                i += body.len();
                if i < lines.len() && lines[i].trim().eq_ignore_ascii_case("end") {
                    i += 1;
                }
                continue;
            }
            if let Some(c) = self.re_type.captures(stripped) {
                out.push(c.get(1).unwrap().as_str().to_string());
                i += 1;
                let body = self.collect_body(&lines, i);
                for bl in &body {
                    out.push(format!("    {}", bl.trim().trim_end_matches('.')));
                }
                i += body.len();
                if i < lines.len() && lines[i].trim().eq_ignore_ascii_case("end") {
                    i += 1;
                }
                continue;
            }
            // Statement regular.
            out.push(self.translate_statement(stripped));
            i += 1;
        }
        out.join("\n")
    }

    fn collect_body(&self, lines: &[&str], start: usize) -> Vec<String> {
        let mut body = Vec::new();
        let mut i = start;
        while i < lines.len() {
            let stripped = lines[i].trim();
            if stripped.eq_ignore_ascii_case("end") {
                break;
            }
            if stripped.is_empty() && !body.is_empty() {
                break;
            }
            if !stripped.is_empty() {
                body.push(stripped.to_string());
            }
            i += 1;
        }
        body
    }

    fn translate_statement(&self, line: &str) -> String {
        let line = line.trim_end_matches('.');
        let stripped = line.trim();
        if stripped.is_empty() {
            return String::new();
        }
        // "When X, do Y." → when X\n    Y
        if let Some(c) = self.re_when.captures(stripped) {
            let cond = c.get(1).unwrap().as_str();
            let action = self.translate_statement(c.get(2).unwrap().as_str());
            return format!("when {}\n    {}", cond, action);
        }
        // "Otherwise when X, do Y." → otherwise when X\n    Y
        if let Some(c) = self.re_otherwise_when.captures(stripped) {
            let cond = c.get(1).unwrap().as_str();
            let action = self.translate_statement(c.get(2).unwrap().as_str());
            return format!("otherwise when {}\n    {}", cond, action);
        }
        // "Otherwise, do Y." → otherwise\n    Y
        if let Some(c) = self.re_otherwise.captures(stripped) {
            let action = self.translate_statement(c.get(1).unwrap().as_str());
            return format!("otherwise\n    {}", action);
        }
        // "Then X" → X
        if let Some(c) = self.re_then.captures(stripped) {
            return self.translate_statement(c.get(1).unwrap().as_str());
        }
        // "For each X in Y, do Z." → each X in Y\n    Z
        if let Some(c) = self.re_each.captures(stripped) {
            let var = c.get(1).unwrap().as_str();
            let coll = c.get(2).unwrap().as_str();
            let action = self.translate_statement(c.get(3).unwrap().as_str());
            return format!("each {} in {}\n    {}", var, coll, action);
        }
        // Normalizar keywords capitalizados a minúscula (primer match gana).
        const KEYWORDS: &[(&str, &str)] = &[
            ("Let ", "let "),
            ("Set ", "set "),
            ("Give ", "give "),
            ("Show ", "show "),
            ("Log ", "log "),
            ("Stop", "stop"),
            ("Approve ", "approve "),
            ("Confirm ", "confirm "),
            ("Share ", "share "),
            ("Observe ", "observe "),
            ("Require ", "require "),
            ("Spawn ", "spawn "),
        ];
        for (cap, low) in KEYWORDS {
            if let Some(rest) = stripped.strip_prefix(cap) {
                return format!("{}{}", low, rest);
            }
        }
        stripped.to_string()
    }
}

/// Traduce sintaxis flat a Syntecnia estándar.
pub fn translate_flat(source: &str) -> String {
    FlatTranslator::new().translate(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_comma() {
        let std = translate_flat("When x > 5, print(\"big\").");
        assert!(std.contains("when x > 5"));
        assert!(std.contains("print(\"big\")"));
    }

    #[test]
    fn otherwise() {
        let std = translate_flat("Otherwise, print(\"small\").");
        assert!(std.contains("otherwise"));
        assert!(std.contains("print(\"small\")"));
    }

    #[test]
    fn task_block() {
        let flat = "task greet(name):\n    Let msg be \"Hello \" + name.\n    Give msg.\nend";
        let std = translate_flat(flat);
        assert!(std.contains("task greet(name)"));
        assert!(std.contains("let msg be"));
        assert!(std.contains("give msg"));
    }

    #[test]
    fn for_each() {
        let std = translate_flat("For each item in list, print(item).");
        assert!(std.contains("each item in list"));
    }
}
