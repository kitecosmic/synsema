//! Conformidad del Batch 6 (fixes): `raise(msg)` y el parseo de `signal`/`wait_for` con
//! nombre dinámico (las cláusulas `with`/`as` no se tragan la expresión). La ruta real de
//! `spawn`-desde-route y los canales por job_id viven en los tests del runtime (swarm/serve).

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

fn fails_with(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba error con '{}', got {:?}",
        needle,
        r.errors
    );
}

// =========================================================
// Fix 3 — raise(msg)
// =========================================================

#[test]
fn raise_propagates_message() {
    fails_with("raise(\"boom\")", "boom");
    fails_with("raise(\"custom error \" + text(42))", "custom error 42");
}

#[test]
fn raise_coerces_to_text() {
    fails_with("raise(42)", "42");
}

#[test]
fn raise_without_arg_errors() {
    fails_with("raise()", "raise expects a message");
}

#[test]
fn raise_reraises_captured_error() {
    // try/recover SIN raise → el error se traga (programa OK).
    let swallowed = "let ok be \"swallowed\"\ntry\n    let x be (1 / 0)\nrecover err\n    set ok to \"caught\"\nprint(ok)";
    assert_eq!(out(swallowed), vec!["caught"]);
    // try/recover CON raise(err) → el error se re-propaga (programa falla).
    let reraised = "try\n    let x be (1 / 0)\nrecover err\n    raise(err)";
    let r = run_source(reraised, "<test>");
    assert!(!r.success, "raise(err) debería re-propagar el error");
    assert!(
        r.errors.iter().any(|e| e.contains("Division by zero")),
        "el error re-propagado debe contener el original: {:?}",
        r.errors
    );
}

#[test]
fn raise_inside_task_propagates() {
    let src = "task check(n)\n    when n < 0\n        raise(\"negative not allowed\")\n    give n\ncheck(-1)";
    fails_with(src, "negative not allowed");
}

// =========================================================
// Fix 2 — signal/wait_for con nombre dinámico (parseo + ejecución no-swarm)
// =========================================================
// Fuera de un swarm, los hooks de signal/wait_for son no-op: estos tests verifican que el
// nombre como EXPRESIÓN parsea/corre y que `with`/`as` no se tragan la expresión.

#[test]
fn signal_literal_still_parses() {
    // Regresión: literal sigue funcionando (ahora es un TextLiteral evaluado).
    assert_eq!(out("signal \"x\"\nprint(\"done\")"), vec!["done"]);
}

#[test]
fn signal_dynamic_name_and_with_clause() {
    // `signal <expr> with <data>` — el `with` NO se traga la expresión del nombre.
    let src = "let id be 7\nsignal \"cancel:\" + text(id) with {\"reason\": \"timeout\"}\nprint(\"sent\")";
    assert_eq!(out(src), vec!["sent"]);
}

#[test]
fn wait_for_literal_and_dynamic_with_as() {
    // literal con `as`
    assert_eq!(
        out("wait_for \"x\" as r\nprint(text(r == nothing))"),
        vec!["true"] // no-op fuera de swarm → nothing
    );
    // `wait_for <expr> as <var>` — el `as` NO se traga la expresión del nombre.
    let src = "let job be 3\nwait_for \"done:\" + text(job) as result\nprint(text(result == nothing))";
    assert_eq!(out(src), vec!["true"]);
}
