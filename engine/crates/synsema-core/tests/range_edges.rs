//! `range(a, b, paso)` cerca de los extremos de `i64` termina, como en Python. Antes `i += paso`
//! daba la vuelta en release (sin `overflow-checks`) y el bucle no terminaba, llenando la memoria
//! (specs/compute-rendimiento.md §3.10). Se prueban los dos caminos: la lista armada
//! (`let r be range(…)`) y el `each` que la recorre sin armarla (F1.11).

use synsema_core::interpreter::run_source;

fn out(src: &str) -> Vec<String> {
    let r = run_source(src, "<range>");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

#[test]
fn range_near_the_i64_edges_ends() {
    // Subiendo hasta cerca de i64::MAX con un paso que pasaría del máximo.
    let up = "range(9223372036854775800, 9223372036854775807, 5)";
    // Bajando hasta cerca de i64::MIN.
    let down = "range(-9223372036854775800, -9223372036854775808, -5)";
    for (r, expected) in [
        (up, "[9223372036854775800, 9223372036854775805]"),
        (down, "[-9223372036854775800, -9223372036854775805]"),
    ] {
        // La lista armada.
        assert_eq!(out(&format!("print({})\n", r)), vec![expected.to_string()], "{}", r);
        // El `each`, que no la arma.
        let src = format!("let seen be []\neach i in {}\n    set seen to append(seen, i)\nprint(seen)\n", r);
        assert_eq!(out(&src), vec![expected.to_string()], "each en {}", r);
    }
}

#[test]
fn range_forms_are_the_same_in_a_list_and_in_each() {
    for r in [
        "range(5)",
        "range(0)",
        "range(-3)",
        "range(2, 7)",
        "range(7, 2)",
        "range(0, 10, 3)",
        "range(10, 0, -3)",
        "range(0, 10, -1)",
        "range(5, 5, 1)",
    ] {
        let listed = out(&format!("print({})\n", r));
        let walked = out(&format!("let seen be []\neach i in {}\n    set seen to append(seen, i)\nprint(seen)\n", r));
        assert_eq!(listed, walked, "{}", r);
    }
}
