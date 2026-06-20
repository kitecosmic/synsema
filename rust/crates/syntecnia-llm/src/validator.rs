//! Validador de respuestas del LLM. Port de `syntecnia/llm/validator.py`.
//!
//! Toda respuesta del LLM debe matchear lo que el lenguaje espera; si no, se
//! reintenta con feedback. `decide` → exactamente una de las opciones (tolerando
//! texto extra, numeración, comillas, mayúsculas); analyze/generate/reason → texto
//! no vacío. (Módulo de capa 10; no lo ejercita el corpus de conformidad.)

use std::collections::HashMap;

use regex::RegexBuilder;

#[derive(Clone, Debug, Default)]
pub struct ValidationResult {
    pub valid: bool,
    pub value: String,
    pub raw_response: String,
    pub error: String,
    pub attempts: usize,
}

/// Parsea opciones de varios formatos string (`[a, b, c]`, `a, b, c`, `a`).
pub fn parse_options(options_str: &str) -> Vec<String> {
    let cleaned = options_str.trim();
    let strip = |p: &str| p.trim().trim_matches(['"', '\'']).trim().to_string();
    if cleaned.starts_with('[') && cleaned.ends_with(']') {
        let inner = &cleaned[1..cleaned.len() - 1];
        return inner.split(',').map(strip).filter(|p| !p.is_empty()).collect();
    }
    if cleaned.contains(',') {
        return cleaned.split(',').map(strip).collect();
    }
    if !cleaned.is_empty() {
        return vec![cleaned.to_string()];
    }
    Vec::new()
}

/// Valida un `decide` — debe ser exactamente una de las opciones.
pub fn validate_decide(response: &str, data: &HashMap<String, String>) -> ValidationResult {
    let options = parse_options(data.get("options").map(|s| s.as_str()).unwrap_or(""));
    if options.is_empty() {
        return ValidationResult {
            valid: true,
            value: response.trim().to_string(),
            raw_response: response.to_string(),
            ..Default::default()
        };
    }
    let cleaned = response.trim().trim_matches(['"', '\'']).trim().to_string();

    // Match exacto (case-insensitive).
    for opt in &options {
        if cleaned.eq_ignore_ascii_case(opt) {
            return ok(opt, response);
        }
    }
    // Número: "1" → primera opción.
    if let Ok(n) = cleaned.parse::<usize>() {
        if n >= 1 && n <= options.len() {
            return ok(&options[n - 1], response);
        }
    }
    // "Option X" / "Choice X".
    if let Ok(re) = RegexBuilder::new(r"(?:option|choice)\s*(\d+)").case_insensitive(true).build() {
        if let Some(c) = re.captures(&cleaned) {
            if let Ok(n) = c[1].parse::<usize>() {
                if n >= 1 && n <= options.len() {
                    return ok(&options[n - 1], response);
                }
            }
        }
    }
    // Alguna opción aparece en la respuesta (exactamente una).
    let found: Vec<&String> =
        options.iter().filter(|o| cleaned.to_lowercase().contains(&o.to_lowercase())).collect();
    if found.len() == 1 {
        return ok(found[0], response);
    }
    ValidationResult {
        valid: false,
        raw_response: response.to_string(),
        error: format!("Response '{}' is not one of the valid options: {:?}", cleaned, options),
        ..Default::default()
    }
}

/// Valida analyze/generate/reason — texto no vacío.
pub fn validate_text_response(response: &str, _data: &HashMap<String, String>) -> ValidationResult {
    let cleaned = response.trim();
    if cleaned.is_empty() {
        return ValidationResult {
            valid: false,
            raw_response: response.to_string(),
            error: "Response is empty".to_string(),
            ..Default::default()
        };
    }
    if cleaned.starts_with('[') && cleaned.to_lowercase().contains("error") {
        return ValidationResult {
            valid: false,
            raw_response: response.to_string(),
            error: format!("LLM returned an error: {}", cleaned),
            ..Default::default()
        };
    }
    ValidationResult {
        valid: true,
        value: cleaned.to_string(),
        raw_response: response.to_string(),
        ..Default::default()
    }
}

fn ok(value: &str, response: &str) -> ValidationResult {
    ValidationResult {
        valid: true,
        value: value.to_string(),
        raw_response: response.to_string(),
        ..Default::default()
    }
}

fn validator_for(operation: &str) -> fn(&str, &HashMap<String, String>) -> ValidationResult {
    match operation {
        "decide" => validate_decide,
        _ => validate_text_response, // analyze/generate/reason + default
    }
}

/// Valida respuestas del LLM y reintenta con feedback ante fallo.
pub struct ResponseValidator {
    llm_call: Box<dyn FnMut(&str, &HashMap<String, String>) -> String>,
    pub max_retries: usize,
}

impl ResponseValidator {
    pub fn new(llm_call: Box<dyn FnMut(&str, &HashMap<String, String>) -> String>, max_retries: usize) -> Self {
        ResponseValidator { llm_call, max_retries }
    }

    pub fn call_validated(&mut self, operation: &str, data: &HashMap<String, String>) -> ValidationResult {
        let validator = validator_for(operation);
        let mut last_error = String::new();
        let mut response = String::new();
        for attempt in 1..=self.max_retries {
            let mut call_data = data.clone();
            if !last_error.is_empty() && attempt > 1 {
                let mut fb = format!(
                    "Your previous response was invalid: {}. Please try again following the format instructions exactly.",
                    last_error
                );
                if attempt == self.max_retries {
                    fb.push_str(" This is the final attempt. Respond with ONLY the required value, nothing else.");
                }
                call_data.insert("_retry_feedback".to_string(), fb);
            }
            response = (self.llm_call)(operation, &call_data);
            let mut result = validator(&response, data);
            result.attempts = attempt;
            if result.valid {
                return result;
            }
            last_error = result.error;
        }
        ValidationResult {
            valid: false,
            raw_response: response,
            error: format!("Failed after {} attempts. Last error: {}", self.max_retries, last_error),
            attempts: self.max_retries,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(options: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("options".to_string(), options.to_string());
        m
    }

    #[test]
    fn decide_exact_and_cleaning() {
        let d = data("[refund, replace, escalate]");
        assert_eq!(validate_decide("refund", &d).value, "refund");
        assert_eq!(validate_decide("\"Refund\"", &d).value, "refund"); // comillas + case
        assert_eq!(validate_decide("I would choose refund", &d).value, "refund"); // substring única
        assert_eq!(validate_decide("1", &d).value, "refund"); // número
        assert_eq!(validate_decide("Option 2", &d).value, "replace"); // "Option X"
        assert!(!validate_decide("maybe banana", &d).valid); // nada matchea
    }

    #[test]
    fn text_response() {
        let d = HashMap::new();
        assert!(validate_text_response("hello", &d).valid);
        assert!(!validate_text_response("   ", &d).valid);
        assert!(!validate_text_response("[error: boom]", &d).valid);
    }

    #[test]
    fn parse_options_formats() {
        assert_eq!(parse_options("[a, b, c]"), vec!["a", "b", "c"]);
        assert_eq!(parse_options("a, b"), vec!["a", "b"]);
        assert_eq!(parse_options("solo"), vec!["solo"]);
        assert!(parse_options("").is_empty());
    }

    #[test]
    fn validator_retries_then_succeeds() {
        let calls = std::rc::Rc::new(std::cell::RefCell::new(0));
        let c = calls.clone();
        let llm: Box<dyn FnMut(&str, &HashMap<String, String>) -> String> = Box::new(move |_op, _d| {
            *c.borrow_mut() += 1;
            if *c.borrow() < 2 {
                "I think refund".to_string() // inválido (substring 'refund' está... )
            } else {
                "refund".to_string()
            }
        });
        // Para forzar invalidez en el intento 1, usamos opciones donde 'I think refund'
        // contiene 2 opciones → ambiguo → inválido.
        let mut v = ResponseValidator::new(llm, 3);
        let mut d = HashMap::new();
        d.insert("options".to_string(), "[refund, think]".to_string());
        let r = v.call_validated("decide", &d);
        assert!(r.valid);
        assert_eq!(r.value, "refund");
        assert_eq!(r.attempts, 2);
    }
}
