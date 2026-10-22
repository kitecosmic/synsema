//! v0.6.29 — lo que se fijó antes de v1.0 (specs/lenguaje: evm.md, v1-compatibilidad.md):
//! números exactos (`int`, `//`, `hex`, literales `0x`/`1e`, `int == float`), sintaxis
//! (`**` y unario, `|>`, `in`, comparaciones encadenadas, `--`), semántica de valor con
//! copy-on-write, aridad estricta y el anti-rot de la tabla de aridades.

use synsema_runtime::engine::run_program;

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "v0629.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let r = run_program(src, "v0629.syn");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

#[test]
fn every_variadic_builtin_declares_its_arity() {
    let table: std::collections::HashSet<&str> =
        synsema_core::builtin_arity::BUILTIN_ARITY.iter().map(|(n, _, _)| *n).collect();
    let missing: Vec<String> = synsema_runtime::engine::registered_builtin_arities()
        .into_iter()
        .filter(|(n, pc)| *pc < 0 && !table.contains(n.as_str()))
        .map(|(n, _)| n)
        .collect();
    assert!(
        missing.is_empty(),
        "builtins variádicos sin aridad en synsema-core/src/builtin_arity.rs: {:?}",
        missing
    );
}

#[test]
fn exact_integers() {
    assert_eq!(
        out(r#"print(int("123456789012345678901"), int("0x1f18"), int("-42"), int("1_000"), int(3.0), int("x", nothing))"#),
        vec!["123456789012345678901 7960 -42 1000 3 nothing"]
    );
    assert_eq!(
        out(r#"print(int("0x0000000000000000000000000000000000000000000000000000000000001f18"))"#),
        vec!["7960"]
    );
    assert!(fails("print(int(1.5))").contains("not a whole number"));
    assert!(fails(r#"print(int("1.5"))"#).contains("Cannot convert"));
    assert!(fails(r#"print(number("123456789012345678901"))"#).contains("int(x)"));
    assert_eq!(out(r#"print(number("123456789012345678901", nothing))"#), vec!["nothing"]);
}

#[test]
fn floor_division_and_hex() {
    assert_eq!(
        out("print((10**30) // 3, -7 // 2, 7 // -2, 7.5 // 2)"),
        vec!["333333333333333333333333333333 -4 -4 3.0"]
    );
    // a == b * (a // b) + a % b en toda la tabla de signos.
    assert_eq!(
        out("let ok be true\neach a in [7, -7, 10**30, -(10**30)]\n    each b in [2, -2, 3, -3]\n        when a != b * (a // b) + a % b\n            set ok to false\nprint(ok)"),
        vec!["true"]
    );
    assert!(fails("print(1 // 0)").contains("Division by zero"));
    assert_eq!(out("print(hex(7960), hex(0), hex(bytes([0, 255])))"), vec!["0x1f18 0x0 0x00ff"]);
    assert_eq!(
        out(r#"print(int(hex(2**255)) == 2**255, bytes(hex(bytes([1,2])), "hex") == bytes([1,2]))"#),
        vec!["true true"]
    );
    assert!(fails("print(hex(-1))").contains("negative"));
    assert_eq!(out(r#"print(bytes("0x00ff", "hex") == bytes("00ff", "hex"))"#), vec!["true"]);
    assert!(fails(r#"print(bytes("0x9", "hex"))"#).contains("int("));
}

#[test]
fn literals_and_exact_comparison() {
    assert_eq!(out("print(0x1f18, 0b101, 1e3, 1.5e-3, 0xFF_FF)"), vec!["7960 5 1000.0 0.0015 65535"]);
    assert_eq!(
        out("print(2**53 + 1 == 9007199254740992.0, 2**53 == 9007199254740992.0, 2**53 + 1 > 9007199254740992.0)"),
        vec!["false true true"]
    );
    assert_eq!(out("print(1 < 1.5, 2 > 1.5, 1 == 1.0)"), vec!["true true true"]);
}

#[test]
fn syntax_fixes() {
    assert_eq!(out("print(-2 ** 2, (-2) ** 2, 2 ** -1, 2 ** 3 ** 2)"), vec!["-4 4 0.5 512"]);
    assert_eq!(
        out("task double(x)\n    give x * 2\nprint(1 + 2 |> double)\nprint([3, 1, 2] |> sort_by((x) => x))"),
        vec!["6", "[1, 2, 3]"]
    );
    assert_eq!(
        out(r#"print(2 in [1, 2], "a" in "cat", "k" in {"k": 1}, 5 not in [1])"#),
        vec!["true true true true"]
    );
    assert_eq!(out("print(1 < 2 < 3, 3 > 2 > 5, 1 < 2 <= 2)"), vec!["true false true"]);
    // cada operando se evalúa una sola vez
    assert_eq!(
        out("let n be 0\ntask mid()\n    set n to n + 1\n    give 2\nprint(1 < mid() < 3, n)"),
        vec!["true 1"]
    );
    assert!(fails("let y be 5--1").contains("`--`"));
    assert_eq!(out("let y be 5 - -1 -- comentario\nprint(y)"), vec!["6"]);
    assert_eq!(out(r#"let ev be {"type": "x", "to": "y"}
print(ev.type, ev.to)"#), vec!["x y"]);
}

#[test]
fn indexing() {
    assert_eq!(out(r#"let xs be [1, 2, 3]
print(xs[-1], "héllo"[1], "abc"[-1])"#), vec!["3 é c"]);
    assert!(fails("print([1, 2][1.7])").contains("integer"));
    assert!(fails("print(range(0, 1, 0.25))").contains("integer"));
    assert_eq!(out("print([1, 2][1.0])"), vec!["2"]);
}

#[test]
fn text_concat_and_display() {
    assert!(fails(r#"print("x" + nothing)"#).contains("Cannot add text and nothing"));
    assert!(fails(r#"print("x" + [1])"#).contains("Cannot add text and list"));
    assert_eq!(out(r#"print("n=" + 1, "b=" + true)"#), vec!["n=1 b=true"]);
    assert_eq!(out(r#"print(["1", 1, {"a": "b"}])"#), vec![r#"["1", 1, {a: "b"}]"#]);
    assert_eq!(out(r#"print("plain")"#), vec!["plain"]);
}

#[test]
fn value_semantics() {
    assert_eq!(out("let xs be [1, 2]\nlet ys be xs\nset ys[0] to 9\nprint(xs, ys)"), vec!["[1, 2] [9, 2]"]);
    assert_eq!(
        out("let m be {\"a\": {\"b\": 1}}\ntask poke(state)\n    set state[\"a\"][\"b\"] to 2\n    give state\nlet m2 be poke(m)\nprint(m, m2)"),
        vec!["{a: {b: 1}} {a: {b: 2}}"]
    );
    assert_eq!(
        out("let n be [[1], [2]]\nlet n2 be n\nset n2[0][0] to 7\nprint(n, n2)"),
        vec!["[[1], [2]] [[7], [2]]"]
    );
    assert_eq!(
        out("let a be [1]\nlet keep be a\nset a to append(a, 2)\nset a to a + [3]\nprint(keep, a)"),
        vec!["[1] [1, 2, 3]"]
    );
    assert_eq!(out("let p be {\"x\": 1}\nlet q be p\nset q.x to 5\nprint(p.x, q.x)"), vec!["1 5"]);
}

#[test]
fn append_in_a_loop_is_linear() {
    let t = std::time::Instant::now();
    assert_eq!(
        out("let acc be []\neach i in range(0, 200000)\n    set acc to append(acc, i)\nprint(length(acc))"),
        vec!["200000"]
    );
    // Cuadrático eran minutos; lineal son segundos incluso en debug.
    assert!(t.elapsed().as_secs() < 30, "200k append tardó {:?}", t.elapsed());
}

#[test]
fn strict_arity() {
    assert!(fails("task f(a, b)\n    give a\nprint(f(1))").contains("missing argument 'b'"));
    assert!(fails("task f(a)\n    give a\nprint(f(1, 2))").contains("takes 1 argument, got 2"));
    assert!(fails("print(append([1], 2, 3))").contains("at most 2"));
    assert!(fails(r#"print(upper("a", "b"))"#).contains("at most 1"));
    assert_eq!(out("task f(a, b = 2)\n    give a + b\nprint(f(1), f(1, b = 5))"), vec!["3 6"]);
    // Los callbacks que invoca un builtin siguen declarando lo que usan.
    assert_eq!(out("print(apply([1, 2], (x) => x + 1))"), vec!["[2, 3]"]);
}

#[test]
fn json_big_integers_are_exact() {
    assert_eq!(out(r#"print(json_decode("{\"id\": 12345678901234567890}"))"#), vec!["{id: 12345678901234567890}"]);
    assert_eq!(out(r#"print(json_decode(json_encode(2**255)) == 2**255, json_decode("1.5"))"#), vec!["true 1.5"]);
}

#[test]
fn while_has_no_iteration_cap() {
    assert_eq!(out("let i be 0\nwhile i < 1500000\n    set i to i + 1\nprint(i)"), vec!["1500000"]);
}

#[test]
fn maps_api() {
    assert_eq!(
        out(r#"let m be {"a": 1, "b": 2}
print(get(m, "a"), get(m, "z"), get(m, "z", 0), get([1, 2], -1), get([1], 5, "no"))
print(remove(m, "a"), m)
print(merge(m, {"b": 3, "c": 4}))
print(items({"x": 1}))"#),
        vec!["1 nothing 0 2 no", "{b: 2} {a: 1, b: 2}", "{a: 1, b: 3, c: 4}", "[{key: \"x\", value: 1}]"]
    );
}

#[test]
fn total_order_and_sort() {
    assert_eq!(
        out(r#"print(sort([3, 1, 2]), sort([3, 1, 2], desc = true))
print(sort([3, nothing, 1, nan, 2]))
print(sort(["b", "a", "C"]))
let rows be [{"n": "a", "k": 2}, {"n": "b", "k": 1}, {"n": "c", "k": 2}]
print(apply(sort_by(rows, (r) => r.k, desc = true), (r) => r.n))
print(sort([[1, 2], [1], [0, 9]]))"#),
        vec!["[1, 2, 3] [3, 2, 1]", "[1, 2, 3, nan, nothing]", r#"["C", "a", "b"]"#, r#"["a", "c", "b"]"#, "[[0, 9], [1], [1, 2]]"]
    );
    assert!(fails(r#"print(sort([1, "a"]))"#).contains("cannot order number and text"));
    assert!(fails(r#"print(sort_by([{"a": 1}], (x) => x))"#).contains("has no order"));
}

#[test]
fn each_over_maps_text_and_bytes() {
    assert_eq!(
        out("let ks be []\neach k in {\"a\": 1, \"b\": 2}\n    set ks to append(ks, k)\nlet cs be []\neach c in \"hé\"\n    set cs to append(cs, c)\nlet bs be 0\neach b in bytes([1, 2])\n    set bs to bs + b\nprint(ks, cs, bs)"),
        vec![r#"["a", "b"] ["h", "é"] 3"#]
    );
}

#[test]
fn text_and_regex_names() {
    assert_eq!(
        out(r##"print(regex_find_all("a1b2", "[0-9]"), regex_capture("2026-09", "([0-9]+)-([0-9]+)"), regex_capture("x", "y"))
print(regex_replace("a1b2", "[0-9]", "#"), fold_text("Ñandú"), index_of("héllo", "llo"), index_of("abc", "z"))
print(min(["b", "a"]), max("b", "c"), min([3, nothing, 1]), max([1, nan, 2]))"##),
        vec![r#"["1", "2"] ["2026", "09"] nothing"#, "a#b# nandu 2 nothing", "a c 1 nan"]
    );
}

#[test]
fn fmt_is_strict() {
    assert_eq!(out(r#"print(fmt("{a}-{b} {{a}} {\"k\": 1}", {"a": 1, "b": "x"}))"#), vec![r#"1-x {a} {"k": 1}"#]);
    assert!(fails(r#"print(fmt("{a}", {}))"#).contains("no value for {a}"));
}

#[test]
fn reflex_hints() {
    assert!(fails("task f(x)\n    return x\n").contains("give"));
    assert!(fails("x = 6\n").contains("let x be"));
    assert!(fails("print(len([1]))").contains("length(x)"));
    assert!(fails("let xs be [1]\nxs.append(2)").contains("append(xs, item)"));
    assert!(fails("let x be 1\nwhen x > 0:\n    print(x)").contains("no colon"));
    assert!(fails("print(None)").contains("nothing"));
}

#[test]
fn type_predicates() {
    assert_eq!(
        out(r#"print(is_integer(1), is_integer(1.0), is_text("a"), is_list([]), is_map({}))"#),
        vec!["true false true true true"]
    );
}
