//! Conformidad de la capa 4 (intérprete) — espeja `tests/test_core.py` del oráculo.
//!
//! Estos son tests propios del agente de desarrollo (smoke). El contrato real es
//! el corpus de conformidad que entrega el agente de testing.

use synsema_core::interpreter::run_source;

fn assert_output(source: &str, expected: &[&str]) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.output, exp, "fuente:\n{}", source);
}

fn assert_error_contains(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "Se esperaba un error con '{}', got {:?}",
        needle,
        r.errors
    );
}

#[test]
fn trace_and_log() {
    let src = "trace \"test_op\"\n    log \"inside trace\"\n    print(\"traced\")\n";
    assert_output(src, &["[LOG] inside trace", "traced"]);
}

#[test]
fn sandbox() {
    assert_output("sandbox\n    print(\"sandboxed\")\n", &["sandboxed"]);
}

#[test]
fn reserved_word_as_variable() {
    assert_error_contains("let task be 1", "reserved word");
}

#[test]
fn reserved_word_as_task_name() {
    assert_error_contains("task while(x)\n    give x", "reserved word");
}

#[test]
fn zero_errors_located_and_catchable() {
    // El error no atrapado lleva categoría + prefijo de ubicación.
    let r = run_source("print(text(5 % 0))", "<test>");
    assert!(
        r.errors[0].starts_with("Runtime error: <test>:"),
        "esperaba 'Runtime error: <test>:...', got {:?}",
        r.errors
    );
    // Atrapable por try/recover: el mensaje ligado NO lleva categoría ni ubicación.
    assert_output("try\n    let x be 5 % 0\nrecover e\n    print(e)\n", &["Modulo by zero"]);
    assert_output(
        "try\n    let y be 0 ** -1\nrecover e\n    print(e)\n",
        &["Zero cannot be raised to a negative power"],
    );
}

fn assert_error_eq(source: &str, expected: &[&str]) {
    let r = run_source(source, "<archivo>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.errors, exp, "fuente:\n{}", source);
}

#[test]
fn error_category_vectors() {
    assert_error_eq(
        "print(text(1 / 0))",
        &["Runtime error: <archivo>:1:14: Division by zero"],
    );
    assert_error_eq(
        "let x be -1\ninvariant: x > 0",
        &["Runtime error: <archivo>:2:1: Invariant violation: unnamed invariant"],
    );
    assert_error_eq(
        "print(undefined_var)",
        &["Runtime error: <archivo>:1:7: Undefined variable: 'undefined_var'"],
    );
    // Parse error lleva su categoría.
    assert_error_eq(
        "let task be 1",
        &["Parse error: <archivo>:1:5: 'task' is a reserved word in Synsema; choose another name for the variable after 'let'"],
    );
    // Lexer error lleva su categoría.
    assert_error_eq(
        "let x be @",
        &["Lexer error: <archivo>:1:10: Unexpected character: '@'"],
    );
}

#[test]
fn llm_available_false_offline() {
    assert_output("print(text(llm_available()))", &["false"]);
}

#[test]
fn flush_noop_when_not_live() {
    // DE-019: el runner mínimo de core COLECTA la salida (como conform/test), con
    // live_output=false → flush() NO drena a stdout; "X" e "Y" quedan en `output`.
    // (El drenado en vivo del camino `run` se verifica end-to-end contra el binario.)
    assert_output("print(\"X\")\nflush()\nprint(\"Y\")", &["X", "Y"]);
}

// -- raise como SENTENCIA (DX F1 follow-up): `raise "x"` lanza de verdad --
// Antes parseaba como dos expresiones inertes → no-op silencioso.
