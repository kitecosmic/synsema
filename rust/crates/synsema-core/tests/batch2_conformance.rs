//! Conformidad del Batch 2: pattern matching enriquecido + default/named params.
//!
//! Corre programas `.syn` reales por el intérprete de core (`run_source`). Cubre §6.2/§6.3
//! del spec + los desafíos adversariales §6.4 (G2/G3, `=` vs `==`, patrones profundos,
//! dos spreads → error de parseo).

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

// =========================================================
// G2 — `is <ident>` a nivel TOP compara por valor (NO liga)
// =========================================================

#[test]
fn g2_top_identifier_compares_by_value() {
    // Si `target` se ligara, SIEMPRE matchearía. Como compara por valor: 5 == 5 → hit.
    let hit = "let target be 5\nmatch 5\n    is target\n        print(\"hit\")\n    otherwise\n        print(\"miss\")\n";
    assert_output(hit, &["hit"]);
    // 5 != 99 → miss (prueba que NO se ligó: un binder daría siempre "hit").
    let miss = "let target be 99\nmatch 5\n    is target\n        print(\"hit\")\n    otherwise\n        print(\"miss\")\n";
    assert_output(miss, &["miss"]);
}

// =========================================================
// G3 — aridad permisiva para params SIN default
// =========================================================

#[test]
fn g3_permissive_arity_preserved() {
    // f(1) a task f(a, b): no error; b = nothing.
    assert_output("task f(a, b)\n    give a\nprint(text(f(1)))", &["1"]);
    assert_output(
        "task showb(a, b)\n    give b\nlet r be showb(1)\nprint(text(r == nothing))",
        &["true"],
    );
    // Posicional extra se descarta (sin error), como antes.
    assert_output("task g(a)\n    give a\nprint(text(g(7, 8, 9)))", &["7"]);
}

// =========================================================
// Default / named params
// =========================================================

const CONNECT: &str = "task connect(host, port = 5432, timeout = 30)\n    give host + \":\" + text(port) + \":\" + text(timeout)\n";

#[test]
fn defaults_used_positional_named() {
    assert_output(&format!("{}print(connect(\"db\"))", CONNECT), &["db:5432:30"]);
    assert_output(&format!("{}print(connect(\"db\", 6000))", CONNECT), &["db:6000:30"]);
    assert_output(&format!("{}print(connect(\"db\", timeout = 60))", CONNECT), &["db:5432:60"]);
    assert_output(
        &format!("{}print(connect(\"db\", port = 6000, timeout = 60))", CONNECT),
        &["db:6000:60"],
    );
    // named en orden distinto.
    assert_output(
        &format!("{}print(connect(\"db\", timeout = 60, port = 7000))", CONNECT),
        &["db:7000:60"],
    );
}

#[test]
fn default_reevaluated_each_call_and_overridable() {
    // Default = llamada a un builtin puro (length): se evalúa fresco en cada llamada.
    let src = "task f(n = length([1, 2, 3]))\n    give n\nprint(text(f()))\nprint(text(f(99)))";
    assert_output(src, &["3", "99"]);
}

#[test]
fn default_sees_global_not_other_params() {
    // Default que referencia un GLOBAL: OK (closure_env, G5).
    assert_output("let base be 100\ntask g(x = base)\n    give x\nprint(text(g()))", &["100"]);
    // Default que referencia OTRO param: NO lo ve (closure_env del task, G5) → Undefined.
    assert_error_contains(
        "task h(a, b = a)\n    give b\nprint(text(h(5)))",
        "Undefined variable",
    );
}

#[test]
fn named_arg_errors_only_new_syntax() {
    // named desconocido.
    assert_error_contains(&format!("{}print(connect(\"db\", bogus = 1))", CONNECT), "unknown parameter 'bogus'");
    // posicional tras named.
    assert_error_contains(
        &format!("{}print(connect(\"db\", port = 6000, 30))", CONNECT),
        "positional argument after named argument",
    );
    // duplicado: posicional + named del mismo param.
    assert_error_contains(
        &format!("{}print(connect(\"db\", 6000, port = 7000))", CONNECT),
        "duplicate argument 'port'",
    );
    // duplicado: named repetido.
    assert_error_contains(
        &format!("{}print(connect(\"db\", port = 1, port = 2))", CONNECT),
        "duplicate argument 'port'",
    );
    // named a un builtin.
    assert_error_contains("print(length(x = [1, 2]))", "does not accept named arguments");
}

#[test]
fn equal_vs_assign_in_call() {
    // f(v == 1) = arg posicional booleano; f(v = 1) = named. Token Equal vs Assign.
    let t = "task ident(v)\n    give v\n";
    assert_output(&format!("{}print(text(ident(2 == 2)))", t), &["true"]);
    assert_output(&format!("{}print(text(ident(v = 5)))", t), &["5"]);
}

#[test]
fn lambda_accepts_named_args() {
    // Las lambdas no tienen sintaxis de default, pero aceptan llamadas con args nombrados.
    assert_output("let f be (a, b) => a + b\nprint(text(f(b = 3, a = 10)))", &["13"]);
}

// =========================================================
// Pattern matching — listas
// =========================================================

#[test]
fn list_patterns() {
    assert_output("match [1, 2, 3]\n    is [a, b, c]\n        print(text(a + b + c))", &["6"]);
    assert_output("match []\n    is []\n        print(\"empty\")\n    otherwise\n        print(\"no\")", &["empty"]);
    assert_output(
        "match [1, 2, 3]\n    is [first, ...rest]\n        print(text(first) + \"/\" + text(length(rest)))",
        &["1/2"],
    );
    assert_output(
        "match [1, 2, 3]\n    is [...init, last]\n        print(text(last) + \"/\" + text(length(init)))",
        &["3/2"],
    );
    assert_output(
        "match [1, 2, 3, 4]\n    is [a, ...mid, z]\n        print(text(a) + \",\" + text(z) + \",\" + text(length(mid)))",
        &["1,4,2"],
    );
    // anidado
    assert_output("match [[1], 2]\n    is [[a], b]\n        print(text(a + b))", &["3"]);
    // elemento literal + binder: 200 no matchea 10 → cae al siguiente arm
    assert_output(
        "match [10, 20]\n    is [200, x]\n        print(\"lit\")\n    is [a, x]\n        print(text(a))",
        &["10"],
    );
    // wildcard como elemento
    assert_output("match [1, 2]\n    is [_, x]\n        print(text(x))", &["2"]);
    // spread anónimo
    assert_output("match [1, 2, 3]\n    is [first, ...]\n        print(text(first))", &["1"]);
}

#[test]
fn list_patterns_no_match_cases() {
    // longitud no coincide (sin spread)
    assert_output(
        "match [1, 2, 3]\n    is [a, b]\n        print(\"two\")\n    otherwise\n        print(\"other\")",
        &["other"],
    );
    // más corta que los fijos (con spread)
    assert_output(
        "match [1]\n    is [a, b, ...rest]\n        print(\"ge2\")\n    otherwise\n        print(\"short\")",
        &["short"],
    );
    // matchear un no-lista
    assert_output(
        "match 5\n    is [a]\n        print(\"list\")\n    otherwise\n        print(\"notlist\")",
        &["notlist"],
    );
}

#[test]
fn two_spreads_is_parse_error() {
    assert_error_contains(
        "match [1, 2, 3]\n    is [...a, ...b]\n        print(\"x\")\n",
        "at most one",
    );
}

// =========================================================
// Pattern matching — maps
// =========================================================

#[test]
fn map_patterns() {
    // subset, bindea claves (claves extra ignoradas)
    assert_output(
        "match {\"name\": \"Ada\", \"age\": 36}\n    is {name, age}\n        print(name + \" \" + text(age))",
        &["Ada 36"],
    );
    // clave faltante → no matchea
    assert_output(
        "match {\"name\": \"Ada\"}\n    is {name, age}\n        print(\"both\")\n    otherwise\n        print(\"missing\")",
        &["missing"],
    );
    // valor + bind
    assert_output(
        "match {\"status\": 200, \"body\": \"ok\"}\n    is {status: 200, body}\n        print(\"200 \" + body)\n    otherwise\n        print(\"other\")",
        &["200 ok"],
    );
    // anidado
    assert_output(
        "match {\"items\": [1, 2, 3]}\n    is {items: [h, ...t]}\n        print(text(h) + \" tail \" + text(length(t)))",
        &["1 tail 2"],
    );
    // {} matchea cualquier map
    assert_output(
        "match {\"a\": 1}\n    is {}\n        print(\"any\")\n    otherwise\n        print(\"no\")",
        &["any"],
    );
    // no-map → no matchea
    assert_output(
        "match 5\n    is {x}\n        print(\"map\")\n    otherwise\n        print(\"notmap\")",
        &["notmap"],
    );
}

#[test]
fn map_literal_value_pattern_preserved_g1() {
    // `is {"k": 1}` (clave string) sigue siendo igualdad estructural de map literal.
    assert_output(
        "let m be {\"k\": 1}\nmatch m\n    is {\"k\": 1}\n        print(\"si\")\n    otherwise\n        print(\"no\")",
        &["si"],
    );
    assert_output(
        "let m be {\"k\": 2}\nmatch m\n    is {\"k\": 1}\n        print(\"si\")\n    otherwise\n        print(\"no\")",
        &["no"],
    );
}

// =========================================================
// Wildcard + guards
// =========================================================

#[test]
fn wildcard_top() {
    assert_output("match 42\n    is _\n        print(\"any\")", &["any"]);
    assert_output("match \"x\"\n    is _\n        print(\"any\")", &["any"]);
}

#[test]
fn guards() {
    assert_output(
        "match [18]\n    is [age] when age >= 18\n        print(\"adult\")\n    otherwise\n        print(\"minor\")",
        &["adult"],
    );
    // guard falso → otherwise
    assert_output(
        "match [15]\n    is [age] when age >= 18\n        print(\"adult\")\n    otherwise\n        print(\"minor\")",
        &["minor"],
    );
    // guard con == sobre nombre ligado de un map
    assert_output(
        "match {\"carrier\": \"DHL\"}\n    is {carrier} when carrier == \"DHL\"\n        print(\"dhl\")\n    otherwise\n        print(\"other\")",
        &["dhl"],
    );
    // guard falso cae al SIGUIENTE arm (no sólo a otherwise)
    assert_output(
        "match [5]\n    is [n] when n > 10\n        print(\"big\")\n    is [n]\n        print(\"small \" + text(n))",
        &["small 5"],
    );
}

// =========================================================
// Enum variant binding (G1) + guard + patrón profundo
// =========================================================

const ENUM: &str = "enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n";

#[test]
fn enum_payload_binding_still_works() {
    let src = format!(
        "{}let o be Order.shipped(\"today\", \"DHL\")\nmatch o\n    is Order.shipped(d, c)\n        print(d + \"/\" + c)\n    otherwise\n        print(\"other\")",
        ENUM
    );
    assert_output(&src, &["today/DHL"]);
}

#[test]
fn enum_variant_guard() {
    let dhl = format!(
        "{}let o be Order.shipped(\"today\", \"DHL\")\nmatch o\n    is Order.shipped(d, c) when c == \"DHL\"\n        print(\"dhl \" + d)\n    otherwise\n        print(\"other\")",
        ENUM
    );
    assert_output(&dhl, &["dhl today"]);
    let ups = format!(
        "{}let o be Order.shipped(\"today\", \"UPS\")\nmatch o\n    is Order.shipped(d, c) when c == \"DHL\"\n        print(\"dhl\")\n    otherwise\n        print(\"other\")",
        ENUM
    );
    assert_output(&ups, &["other"]);
}

#[test]
fn enum_literal_subpattern_value_match() {
    // `is Order.paid(100)` ahora destructura con subpatrón literal (equivalente al match
    // de valor previo): matchea variante + payload == 100.
    let hit = format!(
        "{}let o be Order.paid(100)\nmatch o\n    is Order.paid(100)\n        print(\"cien\")\n    otherwise\n        print(\"otro\")",
        ENUM
    );
    assert_output(&hit, &["cien"]);
    let miss = format!(
        "{}let o be Order.paid(50)\nmatch o\n    is Order.paid(100)\n        print(\"cien\")\n    otherwise\n        print(\"otro\")",
        ENUM
    );
    assert_output(&miss, &["otro"]);
}

#[test]
fn deep_pattern_with_guard() {
    // Patrón profundo del desafío adversarial: {status: 200, items: [first, ...rest]} when …
    let src = "let resp be {\"status\": 200, \"items\": [10, 20, 30]}\nmatch resp\n    is {status: 200, items: [first, ...rest]} when length(rest) > 0\n        print(text(first) + \" rest \" + text(length(rest)))\n    otherwise\n        print(\"no\")";
    assert_output(src, &["10 rest 2"]);
    // mismo patrón, guard falso (rest vacío) → otherwise
    let src2 = "let resp be {\"status\": 200, \"items\": [10]}\nmatch resp\n    is {status: 200, items: [first, ...rest]} when length(rest) > 0\n        print(\"hit\")\n    otherwise\n        print(\"no\")";
    assert_output(src2, &["no"]);
}

// =========================================================
// Dogfood recursivo + property chain intacto (G6)
// =========================================================

#[test]
fn recursive_sum_with_list_patterns() {
    let src = "task sum(xs)\n    match xs\n        is []\n            give 0\n        is [h, ...t]\n            give h + sum(t)\nprint(text(sum([1, 2, 3, 4, 5])))";
    assert_output(src, &["15"]);
}

#[test]
fn property_chain_not_broken_by_spread_token() {
    // `a.b.c` sigue siendo Dot/Dot (G6); el token `...` no lo altera.
    let src = "let a be {\"b\": {\"c\": 42}}\nprint(text(a.b.c))";
    assert_output(src, &["42"]);
}
