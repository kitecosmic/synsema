//! Batch DX (db-nativa-ai): dual-order de la familia intencional + `unique`/`index_of`
//! + mensajes con hint (`request` fuera de handler, precedencia de `of`).
//!
//! Programas `.syn` reales por el
//! intérprete — el REPL y `run --explain` ven exactamente estos builtins (G-4: un solo
//! punto de registro, `Interpreter::register`).

use synsema_core::interpreter::{env_get, run_source, Control, Interpreter};
use synsema_core::parser::parse_source;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_int, SynValue};

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

fn fails_with(source: &str, needle: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba error con '{}', got {:?}",
        needle,
        r.errors
    );
    r.errors
}

/// §4.1 — ambos órdenes producen el MISMO resultado (mismos datos fijos).
fn both_orders(classic: &str, family: &str, expected: &str) {
    shows(classic, expected);
    shows(family, expected);
}

// =========================================================
// §4.1 dual-order — los 11 ops
// =========================================================

#[test]
fn dual_order_apply() {
    both_orders(
        "text(apply((x) => x * 2, [1, 2, 3]))",
        "text(apply([1, 2, 3], (x) => x * 2))",
        "[2, 4, 6]",
    );
}

#[test]
fn internal_callbacks_reject_missing_required_arguments_only_when_invoked() {
    fails_with("print(apply((a, b) => b, [1, 2]))", "missing argument 'b'");
    fails_with("print(where([1], (a, b) => true))", "missing argument 'b'");
    fails_with("print(reduce([1, 2], (acc, x, extra) => extra, 0))", "missing argument 'extra'");
    fails_with("print(sort_by([2, 1], (a, b) => a))", "missing argument 'b'");
    shows("text(apply(() => 7, [1, 2]))", "[7, 7]");
    assert_eq!(out("task plus_default(a, b = 9)\n    give a + b\nprint(text(apply(plus_default, [1, 2])))\n"), vec!["[10, 11]"]);
    shows("text(apply((a, b) => b, []))", "[]");
}

#[test]
fn host_callback_arity_fails_before_body_and_recovers_on_next_call() {
    let program = parse_source("let hit be 0\ntask f(a, b)\n    set hit to hit + 1\n    give a + b\n", "<host>").expect("source");
    let mut interp = Interpreter::new();
    assert!(interp.execute(&program).is_ok());
    let func = env_get(&interp.global_env, "f").expect("task");
    let loc = SourceLocation { file: "<host>".into(), line: 0, column: 0, offset: 0 };
    let error = interp.call_callback(func.clone(), vec![syn_int(2)], &loc);
    let Err(Control::Error(error)) = error else { panic!("required argument was omitted") };
    assert!(error.to_string().contains("missing argument 'b'"));
    assert_eq!(env_get(&interp.global_env, "hit").unwrap().to_string(), "0");
    let result = interp.call_task(func, vec![syn_int(2), syn_int(3)]);
    assert!(matches!(result, Ok(SynValue::Number(_))));
    assert_eq!(env_get(&interp.global_env, "hit").unwrap().to_string(), "1");
}

#[test]
fn dual_order_where() {
    both_orders(
        "text(where((x) => x > 1, [1, 2, 3]))",
        "text(where([1, 2, 3], (x) => x > 1))",
        "[2, 3]",
    );
}

#[test]
fn dual_order_transform_with_and_without_pred() {
    both_orders(
        "text(transform((x) => x + 10, [1, 2]))",
        "text(transform([1, 2], (x) => x + 10))",
        "[11, 12]",
    );
    // El `pred` opcional queda al FINAL en ambos órdenes (no se reordena).
    both_orders(
        "text(transform((x) => x + 10, [1, 2, 3], (x) => x > 1))",
        "text(transform([1, 2, 3], (x) => x + 10, (x) => x > 1))",
        "[1, 12, 13]",
    );
}

#[test]
fn dual_order_reduce_with_and_without_init() {
    both_orders(
        "text(reduce((acc, x) => acc + x, [1, 2, 3]))",
        "text(reduce([1, 2, 3], (acc, x) => acc + x))",
        "6",
    );
    both_orders(
        "text(reduce((acc, x) => acc + x, [1, 2, 3], 100))",
        "text(reduce([1, 2, 3], (acc, x) => acc + x, 100))",
        "106",
    );
}

#[test]
fn dual_order_sort_by() {
    both_orders(
        "sort_by((x) => 0 - x, [1, 3, 2])[0]",
        "sort_by([1, 3, 2], (x) => 0 - x)[0]",
        "3",
    );
}

#[test]
fn dual_order_group_by() {
    both_orders(
        "text(length(group_by((x) => x > 2, [1, 2, 3, 4])[1].items))",
        "text(length(group_by([1, 2, 3, 4], (x) => x > 2)[1].items))",
        "2",
    );
}

#[test]
fn dual_order_find_first() {
    both_orders(
        "find_first((x) => x > 1, [1, 2, 3])",
        "find_first([1, 2, 3], (x) => x > 1)",
        "2",
    );
}

#[test]
fn dual_order_every_and_some() {
    both_orders(
        "text(every((x) => x > 0, [1, 2]))",
        "text(every([1, 2], (x) => x > 0))",
        "true",
    );
    both_orders(
        "text(some((x) => x > 1, [1, 2]))",
        "text(some([1, 2], (x) => x > 1))",
        "true",
    );
}

#[test]
fn dual_order_count_where() {
    both_orders(
        "text(count_where((x) => x > 1, [1, 2, 3]))",
        "text(count_where([1, 2, 3], (x) => x > 1))",
        "2",
    );
}

#[test]
fn dual_order_zip_with() {
    both_orders(
        "text(zip_with((a, b) => a + b, [1, 2], [10, 20]))",
        "text(zip_with([1, 2], [10, 20], (a, b) => a + b))",
        "[11, 22]",
    );
}

// =========================================================
// §4.2 no-breaking — los llamados EXACTOS de hoy, byte-idénticos
// =========================================================

#[test]
fn no_breaking_todays_exact_calls() {
    shows("text(apply((x) => x * 2, [1, 2]))", "[2, 4]");
    shows("text(where([1, 2, 3], (x) => x != 2))", "[1, 3]");
    shows("text(reduce([1, 2, 3], (acc, x) => acc + x))", "6");
    shows("text(reduce([1, 2, 3], (acc, x) => acc + x, 10))", "16");
    shows("text(transform([1, 2], (x) => x * 3))", "[3, 6]");
    shows("text(transform([1, 2], (x) => x * 3, (x) => x > 1))", "[1, 6]");
    shows("text(zip_with([1, 2], [3, 4], (a, b) => a * b))", "[3, 8]");
    shows("text(sort_by([3, 1, 2], (x) => x))", "[1, 2, 3]");
    shows("find_first([1, 2], (x) => x > 5)", "nothing");
    shows("text(every([1, 2], (x) => x > 1))", "false");
    shows("text(some([1, 2], (x) => x > 5))", "false");
    shows("text(count_where([1, 2, 3], (x) => x > 0))", "3");
}

// =========================================================
// §4.3 ambigüedad — jamás adivinar (G-2), con ambas firmas en el mensaje
// =========================================================

#[test]
fn ambiguity_two_tasks_and_two_lists_error() {
    let e = fails_with("where((x) => x, (y) => y)", "got two tasks");
    assert!(
        e.iter().any(|m| m.contains("where(fn, list, ...)") && m.contains("where(list, fn, ...)")),
        "el mensaje debe traer AMBAS firmas: {:?}",
        e
    );
    let e2 = fails_with("apply([1], [2])", "got two lists");
    assert!(
        e2.iter().any(|m| m.contains("apply(fn, list, ...)") && m.contains("apply(list, fn, ...)")),
        "el mensaje debe traer AMBAS firmas: {:?}",
        e2
    );
    let e3 = fails_with("zip_with([1], [2], 5)", "as the combiner");
    assert!(
        e3.iter().any(|m| m.contains("zip_with(fn, list_a, list_b)") && m.contains("zip_with(list_a, list_b, fn)")),
        "el mensaje debe traer AMBAS firmas: {:?}",
        e3
    );
}

/// §4.4 — `reduce(fn, lista, init)` con `init` CALLABLE es válido: la detección mira
/// SOLO las posiciones 0-1 (el init nunca participa).
#[test]
fn reduce_with_callable_init_is_valid() {
    shows("text(reduce((acc, x) => 1, [9], (y) => y))", "1");
}

// =========================================================
// §4.5 unique
// =========================================================

#[test]
fn unique_first_appearance_order_and_structural_equality() {
    shows("text(unique([3, 1, 3, 2, 1]))", "[3, 1, 2]");
    shows("text(unique([]))", "[]");
    shows("text(unique([\"a\", \"b\", \"a\"]))", "[\"a\", \"b\"]");
    // Tipos mezclados conviven (la igualdad estructural no cruza tipos no comparables).
    shows("text(length(unique([1, \"x\", 1, \"x\"])))", "2");
    // Igualdad estructural: maps y listas anidadas deduplican por VALOR.
    shows("text(length(unique([{\"a\": 1}, {\"a\": 1}, {\"a\": 2}])))", "2");
    shows("text(length(unique([[1, 2], [1, 2], [3]])))", "2");
}

// =========================================================
// §4.6 index_of
// =========================================================

#[test]
fn index_of_item_predicate_and_nothing() {
    shows("text(index_of([10, 20, 30], 20))", "1");
    shows("text(index_of([1, 2, 3], (x) => x > 1))", "1");
    // No encontrado → `nothing` (patrón de ausencia del lenguaje), NO -1.
    shows("index_of([1, 2], 9)", "nothing");
    shows("text(index_of([1, 2], 9) == nothing)", "true");
    // El idiom documentado por el ejemplo: chequear contra nothing antes de indexar.
    let o = out(
        "let idx be index_of([\"a\", \"b\"], \"b\")\n\
         when idx != nothing\n    print([\"a\", \"b\"][idx])\n",
    );
    assert_eq!(o, vec!["b"]);
    // Igualdad estructural también para el item (maps por valor).
    shows("text(index_of([{\"k\": 1}, {\"k\": 2}], {\"k\": 2}))", "1");
}

// =========================================================
// §4.7 hint de `request` fuera de handler
// =========================================================

#[test]
fn request_outside_handler_gets_actionable_hint() {
    let e = fails_with("print(request)", "route handlers");
    assert!(
        e.iter().any(|m| m.contains("pass it as a parameter")),
        "el hint debe traer el fix: {:?}",
        e
    );
    // También dentro de una task auxiliar (el tropiezo real de la sonda).
    fails_with("task t()\n    give request\nprint(t())", "route handlers");
    // Un nombre cualquiera conserva el mensaje de siempre, sin ruido.
    let e2 = fails_with("print(no_existe)", "Undefined variable: 'no_existe'");
    assert!(
        !e2.iter().any(|m| m.contains("route handlers")),
        "sin hint para nombres ajenos al contexto de handler: {:?}",
        e2
    );
}

// =========================================================
// §4.8 hint de precedencia de `of`
// =========================================================

#[test]
fn of_precedence_hint_only_when_of_is_involved() {
    // `user of request.role` = `user of (request.role)` → el error gana el hint.
    let e = fails_with(
        "let request be {\"user\": \"ada\"}\nlet u be user of request.role\nprint(u)",
        "bind first",
    );
    assert!(
        e.iter().any(|m| m.contains("Map has no key 'role'")),
        "el error original se conserva (el hint se ANEXA): {:?}",
        e
    );
    // Un "Map has no key" SIN `of` involucrado → sin hint (cero ruido).
    let e2 = fails_with("let m be {\"a\": {\"b\": 1}}\nprint(m.a.c)", "Map has no key 'c'");
    assert!(
        !e2.iter().any(|m| m.contains("bind first")),
        "sin hint en un dot-access normal: {:?}",
        e2
    );
    // `a of b` con la key presente sigue funcionando idéntico (cero cambio semántico).
    shows("user of {\"user\": \"ada\"}", "ada");
}
