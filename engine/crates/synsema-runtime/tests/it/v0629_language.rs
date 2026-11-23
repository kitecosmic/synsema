//! v0.6.29: pruebas que permanecen en Rust por tabla interna de aridades, parseo del
//! programa completo y tiempo de pared. Los casos de valores están en
//! `tests/v0629_language.test.syn`.

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
fn reflex_hints() {
    assert!(fails("task f(x)\n    return x\n").contains("give"));
    assert!(fails("x = 6\n").contains("let x be"));
    assert!(fails("print(len([1]))").contains("length(x)"));
    assert!(fails("let xs be [1]\nxs.append(2)").contains("append(xs, item)"));
    assert!(fails("let x be 1\nwhen x > 0:\n    print(x)").contains("no colon"));
    assert!(fails("print(None)").contains("nothing"));
}
