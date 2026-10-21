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

#[test]
fn assert_basic() {
    ok("assert(true)");
    ok("assert(1)");
    ok("assert(\"x\")");
    fails_with("assert(false)", "assertion failed");
    fails_with("assert(false, \"custom message\")", "custom message");
    // falsy: 0, "", [], nothing
    fails_with("assert(0)", "assertion failed");
    fails_with("assert([])", "assertion failed");
}

// -- assert_eq --

#[test]
fn assert_eq_basic() {
    ok("assert_eq(2 + 3, 5)");
    ok("assert_eq(\"hi\", \"hi\")");
    ok("assert_eq([1, 2], [1, 2])"); // igualdad estructural
    fails_with("assert_eq(\"a\", \"b\")", "expected b, got a");
    fails_with("assert_eq(1, 2, \"nums\")", "nums: expected 2, got 1");
}

#[test]
fn assert_eq_bytes_uses_hex_repr() {
    // Batch 1: bytes igualan byte-a-byte; el mensaje usa el repr hex (Display).
    ok("assert_eq(bytes(\"Hello\"), bytes(\"48656c6c6f\", \"hex\"))");
    fails_with("assert_eq(bytes(\"Hi\"), bytes(\"Ho\"))", "expected bytes(486f), got bytes(4869)");
}

// -- assert_ne --

#[test]
fn assert_ne_basic() {
    ok("assert_ne(1, 2)");
    ok("assert_ne(bytes(\"Hi\"), bytes(\"Ho\"))");
    fails_with("assert_ne(1, 1)", "expected values to differ, both 1");
    fails_with("assert_ne(\"x\", \"x\", \"dup\")", "dup: expected values to differ, both x");
}

// -- assert_error --

#[test]
fn assert_error_passes_when_fn_raises() {
    // lambda que indexa fuera de rango (con x = nothing por aridad permisiva) → error.
    ok("assert_error((x) => x[100])");
    // error explícito de tipo
    ok("assert_error(() => bytes(true))");
}

#[test]
fn assert_error_fails_when_no_error() {
    fails_with("assert_error(() => 1)", "expected an error, but none was raised");
}

#[test]
fn assert_error_give_is_not_an_error() {
    // Una lambda hace `give` (su cuerpo SIEMPRE es un give implícito); eso NO es un error
    // → assert_error DEBE fallar, no pasar por accidente.
    fails_with("let f be (x) => 42\nassert_error(f)", "expected an error, but none was raised");
}

#[test]
fn assert_error_non_invocable() {
    fails_with("assert_error(5)", "assert_error expects a task or lambda");
}

// -- G3: las aserciones funcionan fuera de test (checks defensivos) --

#[test]
fn assert_works_outside_test_blocks() {
    ok("let x be 10\nassert(x > 5)\nprint(text(x))");
    fails_with("let x be 1\nassert(x > 5, \"x too small\")", "x too small");
}

// -- G2: `test` es no-op en `run` --

#[test]
fn test_block_is_noop_in_run() {
    // El test tiene assert(false), pero NO corre en `run` → el programa tiene éxito y
    // el print posterior se ejecuta.
    let src = "test \"nunca corre en run\"\n    assert(false)\nprint(\"after\")";
    assert_eq!(output(src), vec!["after".to_string()]);
}

// -- G1: `test` sigue usable como identificador (3 posiciones) --

#[test]
fn test_as_identifier_three_positions() {
    // variable
    assert_eq!(output("let test be 5\nprint(text(test))"), vec!["5"]);
    // parámetro
    assert_eq!(output("task f(test)\n    give test\nprint(text(f(7)))"), vec!["7"]);
    // clave/propiedad de map
    assert_eq!(output("let m be {\"test\": 1}\nprint(text(m.test))"), vec!["1"]);
}

// -- assert dentro de un task llamado desde código normal: el fallo se propaga --

#[test]
fn assert_inside_task_propagates() {
    let src = "task check(n)\n    assert(n > 0, \"must be positive\")\n    give n\ncheck(-1)";
    fails_with(src, "must be positive");
}
