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

fn assert_fails(source: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo pero tuvo éxito.\nfuente:\n{}", source);
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

// -- Aritmética y expresiones --

#[test]
fn arithmetic() {
    assert_output("print(text(2 + 3))", &["5"]);
    assert_output("print(text(10 - 4))", &["6"]);
    assert_output("print(text(3 * 7))", &["21"]);
    assert_output("print(text(15 / 3))", &["5.0"]);
    assert_output("print(text(2 ** 10))", &["1024"]);
    assert_output("print(text(17 % 5))", &["2"]);
}

#[test]
fn string_concatenation() {
    assert_output("print(\"hello\" + \" \" + \"world\")", &["hello world"]);
}

#[test]
fn comparison() {
    assert_output("print(text(5 > 3))", &["true"]);
    assert_output("print(text(5 < 3))", &["false"]);
    assert_output("print(text(5 == 5))", &["true"]);
    assert_output("print(text(5 != 3))", &["true"]);
}

// -- Variables --

#[test]
fn let_binding() {
    assert_output("let x be 42\nprint(text(x))", &["42"]);
}

#[test]
fn set_mutation() {
    assert_output("let x be 1\nset x to 2\nprint(text(x))", &["2"]);
}

// -- Control de flujo --

#[test]
fn when_otherwise() {
    let src = "let x be 10\nwhen x > 5\n    print(\"big\")\notherwise\n    print(\"small\")\n";
    assert_output(src, &["big"]);
}

#[test]
fn when_otherwise_when() {
    let src = "let x be 5\nwhen x > 10\n    print(\"big\")\notherwise when x > 3\n    print(\"medium\")\notherwise\n    print(\"small\")\n";
    assert_output(src, &["medium"]);
}

#[test]
fn each_loop() {
    assert_output("each i in [1, 2, 3]\n    print(text(i))\n", &["1", "2", "3"]);
}

#[test]
fn while_loop() {
    let src = "let i be 0\nwhile i < 3\n    print(text(i))\n    set i to i + 1\n";
    assert_output(src, &["0", "1", "2"]);
}

#[test]
fn match_statement() {
    let src = "let x be \"b\"\nmatch x\n    is \"a\"\n        print(\"alpha\")\n    is \"b\"\n        print(\"beta\")\n    is \"c\"\n        print(\"gamma\")\n";
    assert_output(src, &["beta"]);
}

// -- Tasks --

#[test]
fn task_definition_and_call() {
    assert_output("task add(a, b)\n    give a + b\nprint(text(add(3, 4)))\n", &["7"]);
}

#[test]
fn task_recursion() {
    let src = "task factorial(n)\n    when n <= 1\n        give 1\n    otherwise\n        give n * factorial(n - 1)\nprint(text(factorial(5)))\n";
    assert_output(src, &["120"]);
}

#[test]
fn task_closure() {
    let src = "task make_adder(n)\n    task adder(x)\n        give x + n\n    give adder\n\nlet add5 be make_adder(5)\nprint(text(add5(10)))\n";
    assert_output(src, &["15"]);
}

// -- Estructuras de datos --

#[test]
fn list_operations() {
    let src = "let lst be [1, 2, 3]\nprint(text(length(lst)))\nlet lst2 be append(lst, 4)\nprint(text(length(lst2)))\n";
    assert_output(src, &["3", "4"]);
}

#[test]
fn map_operations() {
    let src = "let m be {\"name\": \"Alice\", \"age\": 30}\nprint(name of m)\nprint(text(age of m))\n";
    assert_output(src, &["Alice", "30"]);
}

#[test]
fn pipe_operator() {
    let src = "task double(x)\n    give x * 2\ntask inc(x)\n    give x + 1\nprint(text(5 |> double |> inc))\n";
    assert_output(src, &["11"]);
}

// -- Definición de tipos --

#[test]
fn type_definition() {
    let src = "type Point\n    x: number\n    y: number\nlet p be Point(3, 4)\nprint(text(x of p))\nprint(text(y of p))\n";
    assert_output(src, &["3", "4"]);
}

// -- Observabilidad --

#[test]
fn trace_and_log() {
    let src = "trace \"test_op\"\n    log \"inside trace\"\n    print(\"traced\")\n";
    assert_output(src, &["[LOG] inside trace", "traced"]);
}

// -- Blackboard --

#[test]
fn share_observe() {
    let src = "let data be \"shared_value\"\nshare data as \"my_key\"\nobserve \"my_key\" as retrieved\nprint(retrieved)\n";
    assert_output(src, &["shared_value"]);
}

// -- Sandbox --

#[test]
fn sandbox() {
    assert_output("sandbox\n    print(\"sandboxed\")\n", &["sandboxed"]);
}

// -- Manejo de errores --

#[test]
fn undefined_variable() {
    assert_fails("print(undefined_var)");
}

#[test]
fn division_by_zero() {
    assert_fails("print(text(1 / 0))");
}

#[test]
fn invariant_violation() {
    assert_fails("let x be -1\ninvariant: x > 0");
}

#[test]
fn invariant_pass() {
    let r = run_source("let x be 10\ninvariant: x > 0", "<test>");
    assert!(r.success);
}

// -- Builtins --

#[test]
fn builtin_range() {
    assert_output("each i in range(3)\n    print(text(i))", &["0", "1", "2"]);
}

#[test]
fn builtin_contains() {
    assert_output("print(text(contains([1, 2, 3], 2)))", &["true"]);
    assert_output("print(text(contains(\"hello\", \"ell\")))", &["true"]);
}

#[test]
fn builtin_split_join() {
    assert_output("print(text(length(split(\"a,b,c\", \",\"))))", &["3"]);
    assert_output("print(join([\"a\", \"b\", \"c\"], \"-\"))", &["a-b-c"]);
}

#[test]
fn builtin_type_of() {
    assert_output("print(type_of(42))", &["number"]);
    assert_output("print(type_of(\"hi\"))", &["text"]);
    assert_output("print(type_of([1]))", &["list"]);
}

// -- Regex --

#[test]
fn regex_matches() {
    assert_output("print(text(matches(\"12345\", \"[0-9]+\")))", &["true"]);
    assert_output("print(text(matches(\"hello 5 world\", \"[0-9]+\")))", &["false"]);
    assert_output(
        "print(text(matches(\"a@b.com\", \"[^@ ]+@[^@ ]+\\.[^@ ]+\")))",
        &["true"],
    );
    assert_output(
        "print(text(matches(\"junk a@b.com junk\", \"[^@ ]+@[^@ ]+\\.[^@ ]+\")))",
        &["false"],
    );
    assert_output(
        "print(text(matches(\"a@b.com\", \"^[^@]+@[^@]+\\.[^@]+$\")))",
        &["true"],
    );
    assert_output(
        "print(text(matches(\"not-an-email\", \"^[^@]+@[^@]+\\.[^@]+$\")))",
        &["false"],
    );
}

#[test]
fn regex_find_all() {
    assert_output("print(find_all(\"a1b2\", \"[0-9]\"))", &["[1, 2]"]);
    assert_output("print(text(length(find_all(\"a1b2c3\", \"[0-9]\"))))", &["3"]);
    assert_output("print(find_all(\"ab12cd34\", \"[a-z]+[0-9]+\"))", &["[ab12, cd34]"]);
}

#[test]
fn regex_capture() {
    assert_output("print(capture(\"hello world\", \"w[a-z]+\"))", &["world"]);
    assert_output(
        "print(capture(\"2026-06-19\", \"([0-9]+)-([0-9]+)-([0-9]+)\"))",
        &["[2026, 06, 19]"],
    );
    assert_output("print(text(capture(\"zzz\", \"q+\")))", &["nothing"]);
}

#[test]
fn regex_replace_re() {
    assert_output("print(replace_re(\"foo123bar\", \"[0-9]+\", \"#\"))", &["foo#bar"]);
    assert_output(
        "print(replace_re(\"John Smith\", \"(\\w+) (\\w+)\", \"\\2 \\1\"))",
        &["Smith John"],
    );
}

#[test]
fn regex_invalid_pattern_errors() {
    assert_error_contains("print(matches(\"x\", \"[unterminated\"))", "invalid regex");
}

// -- Soft keywords --

#[test]
fn soft_keywords_as_variables() {
    assert_output("let route be \"/x\"\nprint(route)", &["/x"]);
    assert_output("let auth be \"tok\"\nprint(auth)", &["tok"]);
    assert_output("let on be true\nprint(on)", &["true"]);
    assert_output("let expect be 5\nprint(expect)", &["5"]);
    assert_output("let serve be 9\nprint(serve)", &["9"]);
    assert_output("let requires be \"yes\"\nprint(requires)", &["yes"]);
    assert_output("let send be 1\nprint(send)", &["1"]);
    assert_output("let stream be 2\nprint(stream)", &["2"]);
    assert_output("let static be 1\nprint(static)", &["1"]);
    assert_output("let from be 3\nprint(from)", &["3"]);
}

#[test]
fn soft_keyword_auth_as_task_name() {
    assert_output("task auth(x)\n    give x\nprint(auth(7))", &["7"]);
}

#[test]
fn soft_keyword_as_property_key() {
    assert_output(
        "let m be {\"auth\": 1, \"route\": 2}\nprint(m.auth)\nprint(m.route)",
        &["1", "2"],
    );
}

// -- Palabras reservadas dan error claro --

#[test]
fn reserved_word_as_variable() {
    assert_error_contains("let task be 1", "reserved word");
}

#[test]
fn reserved_word_as_task_name() {
    assert_error_contains("task while(x)\n    give x", "reserved word");
}

// -- Promoción a BigInt (paridad con enteros de precisión arbitraria) --

#[test]
fn bigint_factorial() {
    let src = "task fact(n)\n    when n <= 1\n        give 1\n    otherwise\n        give n * fact(n - 1)\nprint(text(fact(25)))\n";
    // 25! = 15511210043330985984000000 (desborda i64 → promueve a BigInt)
    assert_output(src, &["15511210043330985984000000"]);
}

#[test]
fn bigint_power() {
    assert_output("print(text(2 ** 100))", &["1267650600228229401496703205376"]);
}

// -- FIX 1: formato de floats = repr(float) de Python (vectores del corpus) --

#[test]
fn float_repr_vectors() {
    assert_output("print(text(15 / 3))", &["5.0"]);
    assert_output("print(text(0.1 + 0.2))", &["0.30000000000000004"]);
    assert_output("print(text(1 / 3))", &["0.3333333333333333"]);
    assert_output("print(text(2.0 ** 100))", &["1.2676506002282294e+30"]);
    assert_output("print(text(1.0))", &["1.0"]);
    assert_output("print(text(100.0))", &["100.0"]);
    assert_output("print(text(0.0001))", &["0.0001"]);
    assert_output("print(text(0.00001))", &["1e-05"]);
    assert_output("print(text(10000000000000000.0))", &["1e+16"]);
    assert_output("print(text(100000000000000000.0))", &["1e+17"]);
    assert_output("print(text(0.0000001))", &["1e-07"]);
    assert_output("print(text(2 ** -1))", &["0.5"]);
}

// -- FIX 2: igualdad por valor (vectores del corpus) --

#[test]
fn equality_scalars() {
    assert_output("print(text(1 == 1))", &["true"]);
    assert_output("print(text(1 == 1.0))", &["true"]);
    assert_output("print(text(1 == 2))", &["false"]);
    assert_output("print(text(\"a\" == \"a\"))", &["true"]);
    assert_output("print(text(true == true))", &["true"]);
    assert_output("print(text(true == 1))", &["true"]);
    assert_output("print(text(1 == \"1\"))", &["false"]);
    assert_output("print(text(nothing == nothing))", &["true"]);
}

#[test]
fn equality_collections() {
    assert_output("print(text([1, 2] == [1, 2]))", &["true"]);
    assert_output("print(text([1, 2] == [1, 2, 3]))", &["false"]);
    assert_output("print(text([[1], [2]] == [[1], [2]]))", &["true"]);
    assert_output("print(text({\"a\": 1, \"b\": 2} == {\"a\": 1, \"b\": 2}))", &["true"]);
    assert_output("print(text({\"a\": 1, \"b\": 2} == {\"b\": 2, \"a\": 1}))", &["true"]);
    assert_output("print(text({\"a\": 1} == {\"a\": 2}))", &["false"]);
}

// -- FIX 3: división / módulo / potencia por cero → error limpio atrapable --

#[test]
fn zero_errors() {
    assert_error_contains("print(text(1 / 0))", "Division by zero");
    assert_error_contains("print(text(5 % 0))", "Modulo by zero");
    assert_error_contains("print(text(0 ** -1))", "Zero cannot be raised to a negative power");
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

// -- Categoría de error en errores NO atrapados (engine.run_source) --

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

// -- floor / ceil / round / trunc (builtins PUROS de redondeo, sin capability) --

#[test]
fn math_rounding_builtins() {
    // floor: hacia abajo (-inf)
    assert_output("print(text(floor(3.7)))", &["3"]);
    assert_output("print(text(floor(-3.7)))", &["-4"]);
    assert_output("print(text(floor(3.0)))", &["3"]);
    // ceil: hacia arriba (+inf)
    assert_output("print(text(ceil(3.2)))", &["4"]);
    assert_output("print(text(ceil(-3.2)))", &["-3"]);
    assert_output("print(text(ceil(0.1)))", &["1"]);
    // trunc: hacia cero
    assert_output("print(text(trunc(3.7)))", &["3"]);
    assert_output("print(text(trunc(-3.7)))", &["-3"]);
    assert_output("print(text(trunc(-0.9)))", &["0"]);
    // round: al más cercano, EMPATES al par (round-half-to-even, como el `round` de Python)
    assert_output("print(text(round(0.5)))", &["0"]);
    assert_output("print(text(round(1.5)))", &["2"]);
    assert_output("print(text(round(2.5)))", &["2"]);
    assert_output("print(text(round(3.5)))", &["4"]);
    assert_output("print(text(round(-2.5)))", &["-2"]);
    assert_output("print(text(round(2.4)))", &["2"]);
    assert_output("print(text(round(2.6)))", &["3"]);
    // devuelven ENTERO (text sin decimal)
    assert_output("print(text(floor(9.99)))", &["9"]);
    // un entero pasa tal cual (Int/Big)
    assert_output("print(text(floor(42)))", &["42"]);
    assert_output("print(text(round(-7)))", &["-7"]);
    assert_output("print(text(ceil(1000000000000)))", &["1000000000000"]);
    // no-número → error claro
    assert_error_contains("print(floor(\"x\"))", "expects a number");
    assert_error_contains("print(round(true))", "expects a number");
}

// -- fold (MF-006): minúsculas + sin diacríticos --

#[test]
fn fold_strips_accents_and_lowercases() {
    assert_output("print(fold(\"Continúa\"))", &["continua"]);
    assert_output("print(fold(\"ÁÉÍÓÚñ\"))", &["aeioun"]);
    assert_output("print(text(contains(fold(\"Está aquí\"), \"esta\")))", &["true"]);
    // sin acentos = lower normal; otros caracteres pasan igual
    assert_output("print(fold(\"Hello World 123\"))", &["hello world 123"]);
}

// -- llm_available (MF-002): false sin provider cableado (runner mínimo de core) --

#[test]
fn llm_available_false_offline() {
    assert_output("print(text(llm_available()))", &["false"]);
}
