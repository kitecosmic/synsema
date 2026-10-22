//! Conformidad de `invariant`: la forma con
//! descripción `invariant "texto": expr` además de `invariant: expr`. El mensaje del fallo sigue
//! siendo `Invariant violation: <descripción>` ("unnamed invariant" sin ella), y la descripción
//! llega al AST (`ast_api::summarize`, `codeintel`), donde antes era siempre `None`.

use synsema_core::ast::NodeKind;
use synsema_core::ast_api::{find_invariants, summarize};
use synsema_core::interpreter::run_source;
use synsema_core::parser::parse_source;

fn assert_ok(source: &str) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
}

fn assert_error_eq(source: &str, expected: &str) {
    let r = run_source(source, "<archivo>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    assert_eq!(r.errors, vec![expected.to_string()], "fuente:\n{}", source);
}

fn descriptions(source: &str) -> Vec<Option<String>> {
    let program = parse_source(source, "<test>").expect("parsea");
    summarize(&program).invariants
}

// -- La forma sin descripción sigue igual --

#[test]
fn bare_invariant_still_parses_and_runs() {
    assert_ok("let x be 10\ninvariant: x > 0\nprint(\"ok\")");
    assert_error_eq(
        "let x be -1\ninvariant: x > 0",
        "Runtime error: <archivo>:2:1: Invariant violation: unnamed invariant",
    );
    assert_eq!(descriptions("let x be 1\ninvariant: x > 0"), vec![None]);
}

// -- La forma con descripción --

#[test]
fn described_invariant_passes_when_true() {
    assert_ok("let balance be 10\ninvariant \"balance never negative\": balance >= 0\nprint(\"ok\")");
}

#[test]
fn described_invariant_names_itself_in_the_violation() {
    assert_error_eq(
        "let balance be -1\ninvariant \"balance never negative\": balance >= 0",
        "Runtime error: <archivo>:2:1: Invariant violation: balance never negative",
    );
}

#[test]
fn description_reaches_the_ast() {
    let src = "let a be 1\nlet b be 2\ninvariant \"a below b\": a < b\ninvariant: b > 0\n";
    assert_eq!(descriptions(src), vec![Some("a below b".to_string()), None]);
    let program = parse_source(src, "<test>").unwrap();
    let invs = find_invariants(&program);
    assert_eq!(invs.len(), 2);
    match &invs[0].kind {
        NodeKind::InvariantDeclaration { description, .. } => assert_eq!(description.as_deref(), Some("a below b")),
        other => panic!("esperaba InvariantDeclaration, got {:?}", other),
    }
}

#[test]
fn description_is_catchable_text_under_try_recover() {
    // Atrapado con try/recover, el mensaje ligado no lleva categoría ni ubicación.
    let r = run_source(
        "let x be 0\ntry\n    invariant \"x is positive\": x > 0\nrecover e\n    print(e)\n",
        "<test>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["Invariant violation: x is positive".to_string()]);
}

#[test]
fn description_inside_a_task_runs_per_call() {
    let src = "task debit(balance, amount)\n    let after be balance - amount\n    invariant \"no overdraft\": after >= 0\n    give after\nprint(text(debit(10, 3)))\ndebit(1, 5)\n";
    let r = run_source(src, "<archivo>");
    assert!(!r.success);
    assert_eq!(r.output, vec!["7".to_string()]);
    assert!(
        r.errors.iter().any(|e| e.ends_with("Invariant violation: no overdraft")),
        "{:?}",
        r.errors
    );
}

// -- Errores de sintaxis: la descripción es un Text y va ANTES de los dos puntos --

// -- L19: la descripción también puede ser un template con backticks (texto estático) --

#[test]
fn described_invariant_accepts_a_backtick_template() {
    assert_ok("let x be 10\ninvariant `balance {x} stays positive`: x > 0\nprint(\"ok\")");
    assert_error_eq(
        "let x be -1\ninvariant `balance {x} stays positive`: x > 0",
        "Runtime error: <archivo>:2:1: Invariant violation: balance {x} stays positive",
    );
    assert_eq!(
        descriptions("let x be 1\ninvariant `plain template`: x > 0"),
        vec![Some("plain template".to_string())]
    );
}

#[test]
fn description_must_be_a_text_literal() {
    // Un identificador no es una descripción (sólo un literal Text), y tras ella van los dos puntos.
    assert!(parse_source("let d be \"x\"\ninvariant d: 1 > 0", "<test>").is_err());
    assert!(parse_source("invariant \"desc\" 1 > 0", "<test>").is_err());
    assert!(parse_source("invariant \"desc\"", "<test>").is_err());
}
