//! Conformidad del Batch 7 (`timeout` en `wait_for`): parseo de la cláusula, `timeout`
//! como soft keyword (sigue usable de identificador), y validación del valor. Fuera de un
//! swarm los hooks son no-op → estos tests cubren parseo/validación; el TIMING real (que el
//! timeout se respeta) vive en los tests E2E del runtime.

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
// Parseo de la cláusula timeout (no-op fuera de swarm)
// =========================================================

#[test]
fn wait_for_without_timeout_still_parses() {
    // Regresión G1: sin `timeout` sigue funcionando (no-op fuera de swarm → nothing).
    assert_eq!(out("wait_for \"x\"\nprint(\"done\")"), vec!["done"]);
    assert_eq!(out("wait_for \"x\" as r\nprint(text(r == nothing))"), vec!["true"]);
}

#[test]
fn wait_for_with_timeout_parses() {
    assert_eq!(out("wait_for \"x\" timeout 1\nprint(\"ok\")"), vec!["ok"]);
    // `timeout` antes de `as`: el `as` no se traga la expresión del timeout.
    assert_eq!(out("wait_for \"x\" timeout 2 as r\nprint(text(r == nothing))"), vec!["true"]);
    // expresión agrupada como timeout.
    assert_eq!(out("wait_for \"x\" timeout (1 + 1) as r\nprint(\"ok\")"), vec!["ok"]);
    // canal dinámico (Batch 6) + timeout (Batch 7).
    let src = "let id be 7\nwait_for \"c:\" + text(id) timeout 0.5 as r\nprint(text(r == nothing))";
    assert_eq!(out(src), vec!["true"]);
}

// =========================================================
// G2 — `timeout` es SOFT keyword (sigue usable como identificador)
// =========================================================

#[test]
fn timeout_is_usable_as_identifier() {
    assert_eq!(out("let timeout be 5\nprint(text(timeout))"), vec!["5"]);
    // un timeout como param de task / en expresiones.
    assert_eq!(out("task f(timeout)\n    give timeout * 2\nprint(text(f(10)))"), vec!["20"]);
}

#[test]
fn channel_var_named_timeout_parses_unambiguously() {
    // `wait_for timeout timeout 1`: canal = la var `timeout` (= "ch"), timeout = 1.
    let src = "let timeout be \"ch\"\nwait_for timeout timeout 1\nprint(\"parsed\")";
    assert_eq!(out(src), vec!["parsed"]);
    // sin la cláusula: `wait_for timeout` (canal = la var) sigue OK.
    let src2 = "let timeout be \"ch\"\nwait_for timeout as r\nprint(text(r == nothing))";
    assert_eq!(out(src2), vec!["true"]);
}

// =========================================================
// G3 — validación del valor (no-número → error; clamp en runtime)
// =========================================================

#[test]
fn non_numeric_timeout_errors() {
    fails_with("wait_for \"x\" timeout \"abc\"", "wait_for timeout must be a number of seconds");
    fails_with("wait_for \"x\" timeout [1, 2]", "wait_for timeout must be a number of seconds");
}

#[test]
fn timeout_zero_and_negative_parse() {
    // timeout 0 (chequeo inmediato) y valores fuera de rango parsean; el clamp es en runtime.
    assert_eq!(out("wait_for \"x\" timeout 0\nprint(\"ok\")"), vec!["ok"]);
    assert_eq!(out("wait_for \"x\" timeout 99999 as r\nprint(\"ok\")"), vec!["ok"]);
}
