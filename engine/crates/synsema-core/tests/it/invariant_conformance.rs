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
