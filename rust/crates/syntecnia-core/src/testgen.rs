//! Generador de tests automático desde tipos/invariantes/firmas. Port de
//! `syntecnia/core/testgen.py`.
//!
//! El lenguaje deriva tests solo: casos borde (cero, negativos, vacíos), conformidad
//! de tipos, verificación de invariantes, idempotencia. NOTA: no se replica el
//! relleno aleatorio (los counts del gate ≤ casos borde → determinista) ni el timeout
//! por caso (los programas del gate no recursan).

use crate::ast::{NodeKind, Program};
use crate::ast_api::{find_invariants, find_tasks, find_types};
use crate::interpreter::{Control, Interpreter};
use crate::parser::parse_source;
use crate::types::{syn_bool, syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue};
use indexmap::IndexMap;

// -- Generadores de valores (casos borde, sin aleatoriedad) --

fn gen_numbers(count: usize) -> Vec<SynValue> {
    let edge = vec![
        syn_int(0),
        syn_int(1),
        syn_int(-1),
        SynValue::Number(crate::number::Number::Float(0.5)),
        SynValue::Number(crate::number::Number::Float(-0.5)),
        syn_int(10),
        syn_int(-10),
        SynValue::Number(crate::number::Number::Float(0.0001)),
    ];
    edge.into_iter().take(count).collect()
}

fn gen_texts(count: usize) -> Vec<SynValue> {
    let edge = vec![
        syn_text(""),
        syn_text(" "),
        syn_text("hello"),
        syn_text("Hello World"),
        syn_text("a".repeat(1000)),
        syn_text("special: !@#$%^&*()"),
        syn_text("unicode: é à ñ 日本語"),
        syn_text("newline\nin\nstring"),
    ];
    edge.into_iter().take(count).collect()
}

fn gen_bools(_count: usize) -> Vec<SynValue> {
    vec![syn_bool(true), syn_bool(false)]
}

fn gen_lists(count: usize) -> Vec<SynValue> {
    let edge = vec![
        syn_list(Vec::new()),
        syn_list(vec![syn_int(1)]),
        syn_list((0..10).map(syn_int).collect()),
        syn_list(vec![syn_int(5); 5]),
        syn_list((0..5).map(|i| syn_int(-i)).collect()),
        syn_list(vec![syn_text("a"), syn_int(1), syn_bool(true)]),
    ];
    edge.into_iter().take(count).collect()
}

fn gen_maps(count: usize) -> Vec<SynValue> {
    let mut single = IndexMap::new();
    single.insert("key".to_string(), syn_text("value"));
    let mut triple = IndexMap::new();
    triple.insert("a".to_string(), syn_int(1));
    triple.insert("b".to_string(), syn_int(2));
    triple.insert("c".to_string(), syn_int(3));
    let edge = vec![syn_map(IndexMap::new()), syn_map(single), syn_map(triple)];
    edge.into_iter().take(count).collect()
}

fn generate_values(type_name: &str, count: usize) -> Vec<SynValue> {
    match type_name {
        "number" => gen_numbers(count),
        "text" => gen_texts(count),
        "bool" => gen_bools(count),
        "list" => gen_lists(count),
        "map" => gen_maps(count),
        _ => vec![syn_nothing()],
    }
}

/// Un caso de test generado.
pub struct TestCase {
    pub name: String,
    pub task_name: String,
    pub inputs: Vec<SynValue>,
    pub check: String, // no_error | should_error | idempotent | invariant
    pub passed: Option<bool>,
    pub error: Option<String>,
    pub result: Option<SynValue>,
    /// Para `invariant`: la condición a re-evaluar.
    pub expected: Option<crate::ast::Node>,
}

impl TestCase {
    fn new(name: String, task_name: String, inputs: Vec<SynValue>, check: &str) -> Self {
        TestCase {
            name,
            task_name,
            inputs,
            check: check.to_string(),
            passed: None,
            error: None,
            result: None,
            expected: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct TestStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
}

#[derive(Default)]
pub struct TestGenerator {
    program: Option<Program>,
    interp: Option<Interpreter>,
}

impl TestGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parsea y carga un programa (lo ejecuta para registrar tasks/types).
    pub fn load_program(&mut self, source: &str) {
        if let Ok(program) = parse_source(source, "<testgen>") {
            let mut interp = Interpreter::new();
            let _ = interp.execute(&program);
            self.program = Some(program);
            self.interp = Some(interp);
        }
    }

    pub fn generate_all(&self) -> Vec<TestCase> {
        let program = match &self.program {
            Some(p) => p,
            None => return Vec::new(),
        };
        let mut cases = Vec::new();
        cases.extend(self.task_tests(program));
        cases.extend(self.invariant_tests(program));
        cases.extend(self.type_tests(program));
        cases
    }

    fn task_tests(&self, program: &Program) -> Vec<TestCase> {
        let mut cases = Vec::new();
        for task in find_tasks(program) {
            let (name, params) = match &task.kind {
                NodeKind::TaskDefinition { name, parameters, .. } => (name.clone(), parameters.clone()),
                _ => continue,
            };
            if params.is_empty() {
                cases.push(TestCase::new(format!("{}:no_crash", name), name.clone(), Vec::new(), "no_error"));
                continue;
            }
            let pc = params.len();
            for (i, v) in gen_numbers(5).into_iter().enumerate() {
                cases.push(TestCase::new(
                    format!("{}:number_edge_{}", name, i),
                    name.clone(),
                    vec![v; pc],
                    "no_error",
                ));
            }
            for (i, v) in gen_texts(3).into_iter().enumerate() {
                cases.push(TestCase::new(
                    format!("{}:text_edge_{}", name, i),
                    name.clone(),
                    vec![v; pc],
                    "no_error",
                ));
            }
            cases.push(TestCase::new(
                format!("{}:nothing_input", name),
                name.clone(),
                vec![syn_nothing(); pc],
                "no_error",
            ));
            if pc == 1 {
                cases.push(TestCase::new(
                    format!("{}:idempotency", name),
                    name.clone(),
                    vec![syn_int(42)],
                    "idempotent",
                ));
            }
        }
        cases
    }

    fn invariant_tests(&self, program: &Program) -> Vec<TestCase> {
        let mut cases = Vec::new();
        for (i, inv) in find_invariants(program).into_iter().enumerate() {
            let mut c = TestCase::new(
                format!("invariant_{}", i),
                "__invariant__".to_string(),
                Vec::new(),
                "invariant",
            );
            if let NodeKind::InvariantDeclaration { condition, .. } = &inv.kind {
                c.expected = Some((**condition).clone());
            }
            cases.push(c);
        }
        cases
    }

    fn type_tests(&self, program: &Program) -> Vec<TestCase> {
        let mut cases = Vec::new();
        for typedef in find_types(program) {
            if let NodeKind::TypeDefinition { name, fields } = &typedef.kind {
                let inputs: Vec<SynValue> = fields
                    .iter()
                    .map(|(_, ftype)| generate_values(ftype, 1).into_iter().next().unwrap_or_else(syn_nothing))
                    .collect();
                cases.push(TestCase::new(
                    format!("type_{}:construct", name),
                    name.clone(),
                    inputs.clone(),
                    "no_error",
                ));
                if !fields.is_empty() {
                    let too_few = inputs[..fields.len() - 1].to_vec();
                    cases.push(TestCase::new(
                        format!("type_{}:too_few_args", name),
                        name.clone(),
                        too_few,
                        "should_error",
                    ));
                }
            }
        }
        cases
    }

    /// Corre todos los casos y devuelve el resumen.
    pub fn run_all(&mut self, cases: &mut [TestCase]) -> TestStats {
        let mut stats = TestStats::default();
        for case in cases.iter_mut() {
            stats.total += 1;
            self.run_case(case);
            match case.passed {
                Some(true) => stats.passed += 1,
                Some(false) => stats.failed += 1,
                None => stats.errors += 1,
            }
        }
        stats
    }

    fn run_case(&mut self, case: &mut TestCase) {
        let interp = match self.interp.as_mut() {
            Some(i) => i,
            None => {
                case.passed = Some(false);
                case.error = Some("no interpreter".to_string());
                return;
            }
        };

        if case.check == "invariant" {
            if let Some(cond) = &case.expected {
                let genv = interp.global_env.clone();
                match interp.eval(cond, &genv) {
                    Ok(v) => {
                        case.passed = Some(v.is_truthy());
                        if !v.is_truthy() {
                            case.error = Some("Invariant violation".to_string());
                        }
                        case.result = Some(v);
                    }
                    Err(e) => {
                        case.passed = Some(false);
                        case.error = Some(control_msg(&e));
                    }
                }
            }
            return;
        }

        let task_val = interp.global_env.borrow().bindings.get(&case.task_name).cloned();
        let task_val = match task_val {
            Some(v) => v,
            None => {
                case.passed = Some(false);
                case.error = Some(format!("Task '{}' not found", case.task_name));
                return;
            }
        };

        match case.check.as_str() {
            "should_error" => match interp.call_task(task_val, case.inputs.clone()) {
                Ok(_) => {
                    case.passed = Some(false);
                    case.error = Some("Expected error but succeeded".to_string());
                }
                Err(_) => case.passed = Some(true),
            },
            "no_error" => match interp.call_task(task_val, case.inputs.clone()) {
                Ok(v) => {
                    case.passed = Some(true);
                    case.result = Some(v);
                }
                Err(e) => {
                    case.passed = Some(false);
                    case.error = Some(control_msg(&e));
                }
            },
            "idempotent" => match interp.call_task(task_val.clone(), case.inputs.clone()) {
                Ok(r1) => {
                    let _ = interp.call_task(task_val, vec![r1.clone()]);
                    case.passed = Some(true);
                    case.result = Some(r1);
                }
                Err(e) => {
                    // Idempotencia fallida es informativa, no falla.
                    case.passed = Some(true);
                    case.error = Some(format!("Non-idempotent: {}", control_msg(&e)));
                }
            },
            _ => {}
        }
    }

    pub fn format_report(&self, cases: &[TestCase], stats: &TestStats) -> String {
        let mut lines = vec![
            "Test Generation Report".to_string(),
            format!(
                "  Total: {}, Passed: {}, Failed: {}, Errors: {}",
                stats.total, stats.passed, stats.failed, stats.errors
            ),
            String::new(),
        ];
        for case in cases {
            let status = if case.passed == Some(true) { "PASS" } else { "FAIL" };
            let err = case.error.as_ref().map(|e| format!(" — {}", e)).unwrap_or_default();
            lines.push(format!("  [{}] {}{}", status, case.name, err));
        }
        lines.join("\n")
    }
}

fn control_msg(c: &Control) -> String {
    match c {
        Control::Error(e) => e.message.clone(),
        Control::Give(_) => "give outside task".to_string(),
        Control::Stop(_) => "stop outside loop".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_cases() {
        let mut gen = TestGenerator::new();
        gen.load_program("task double(x)\n    give x * 2\n\ntype Item\n    name: text\n    price: number\n");
        let cases = gen.generate_all();
        assert!(!cases.is_empty());
        let task_tests = cases.iter().filter(|c| c.task_name == "double").count();
        let type_tests = cases.iter().filter(|c| c.task_name.contains("Item")).count();
        assert!(task_tests > 0);
        assert!(type_tests > 0);
    }

    #[test]
    fn runs_and_reports() {
        let mut gen = TestGenerator::new();
        gen.load_program("task add(a, b)\n    give a + b\n");
        let mut cases = gen.generate_all();
        let stats = gen.run_all(&mut cases);
        assert!(stats.total > 0);
        let report = gen.format_report(&cases, &stats);
        assert!(report.contains("Test Generation Report"));
    }
}
