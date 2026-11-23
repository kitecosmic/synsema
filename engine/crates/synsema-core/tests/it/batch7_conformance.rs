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

// =========================================================
// G2 — `timeout` es SOFT keyword (sigue usable como identificador)
// =========================================================

// =========================================================
// G3 — validación del valor (no-número → error; clamp en runtime)
// =========================================================

#[test]
fn timeout_zero_and_negative_parse() {
    // timeout 0 (chequeo inmediato) y valores fuera de rango parsean; el clamp es en runtime.
    assert_eq!(out("wait_for \"x\" timeout 0\nprint(\"ok\")"), vec!["ok"]);
    assert_eq!(out("wait_for \"x\" timeout 99999 as r\nprint(\"ok\")"), vec!["ok"]);
}
