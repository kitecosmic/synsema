//! Conformidad FASE 1 (tool-calling): el builtin `call(task, args_map)` despacha una
//! task con args NOMBRADOS tomados de un map. `apply` (map sobre lista) queda intacto.
//! Estos tests son puros (no usan LLM) → corren por el intérprete de core.

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
        "Se esperaba un error con '{}', got {:?}\nfuente:\n{}",
        needle,
        r.errors,
        source
    );
}

const GREET: &str = "task greet(name, greeting)\n    give greeting + \", \" + name\n";

// F5a — bindea named args desde el map (por nombre, no por orden de inserción).
#[test]
fn call_binds_named_args_from_map() {
    // El map lista `greeting` ANTES que `name`; si bindeara por posición daría
    // "World, Hello". Por nombre da "Hello, World".
    assert_output(
        &format!("{}print(call(greet, {{\"greeting\": \"Hello\", \"name\": \"World\"}}))", GREET),
        &["Hello, World"],
    );
}

// F5b — param desconocido en el map → error claro (reusa el binding nombrado).
#[test]
fn call_unknown_param_errors() {
    assert_error_contains(
        &format!("{}print(call(greet, {{\"bogus\": 1}}))", GREET),
        "unknown parameter 'bogus'",
    );
}

// F5c — param faltante usa el DEFAULT del task (eval en call time).
#[test]
fn call_missing_param_uses_default() {
    let src = "task connect(host, port = 5432)\n    give host + \":\" + text(port)\n\
               print(call(connect, {\"host\": \"db\"}))";
    assert_output(src, &["db:5432"]);
}

// F5d — param faltante SIN default → `nothing` (aridad permisiva).
#[test]
fn call_missing_param_is_nothing() {
    let src = "task pick(a, b)\n    give b\n\
               print(text(call(pick, {\"a\": 1}) == nothing))";
    assert_output(src, &["true"]);
}

// F5e — `call(task, nothing)` → sin args (todos default/nothing).
#[test]
fn call_with_nothing_passes_no_args() {
    let src = "task hi()\n    give \"hi\"\nprint(call(hi, nothing))";
    assert_output(src, &["hi"]);
    // Un map vacío también significa "sin args".
    let src2 = "task hi()\n    give \"hi\"\nprint(call(hi, {}))";
    assert_output(src2, &["hi"]);
}

// F5f — `call` con un segundo arg que no es map/nothing → error claro.
#[test]
fn call_non_map_args_errors() {
    assert_error_contains(
        &format!("{}print(call(greet, [1, 2]))", GREET),
        "call expects a map of named args",
    );
}

// F5g — `call` a un builtin con args nombrados → el error existente aplica.
#[test]
fn call_builtin_with_named_errors() {
    assert_error_contains(
        "print(call(length, {\"x\": [1, 2]}))",
        "does not accept named arguments",
    );
}
