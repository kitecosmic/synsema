//! Conformidad de las aserciones del test framework (Batch 3), parte que corre por el
//! intérprete de core (`run_source`): los builtins `assert*` y el no-op de `test` en `run`
//! (G2). El runner `synsema test` (aislamiento, captura, reporte) se prueba en el crate
//! runtime (`test_framework.rs`).

use synsema_core::interpreter::run_source;

fn ok(source: &str) {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
}

fn fails_with(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba un error con '{}', got {:?}\nfuente:\n{}",
        needle,
        r.errors,
        source
    );
}

fn output(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

// -- assert --

// -- assert_eq --

// -- assert_ne --

// -- assert_error --

// -- G3: las aserciones funcionan fuera de test (checks defensivos) --

// -- G2: `test` es no-op en `run` --

#[test]
fn test_block_is_noop_in_run() {
    // El test tiene assert(false), pero NO corre en `run` → el programa tiene éxito y
    // el print posterior se ejecuta.
    let src = "test \"nunca corre en run\"\n    assert(false)\nprint(\"after\")";
    assert_eq!(output(src), vec!["after".to_string()]);
}

// -- G1: `test` sigue usable como identificador (3 posiciones) --

// -- assert dentro de un task llamado desde código normal: el fallo se propaga --

