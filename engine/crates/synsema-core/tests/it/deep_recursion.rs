//! Una recursión cerca del tope (`MAX_RECURSION = 3000`) tiene que funcionar, y pasarlo tiene que
//! dar el error atrapable, no tumbar el proceso por desborde de pila. En builds de debug (como
//! corren los tests) el frame de `exec_node` sin optimizar llegó a ~300 KB y el proceso se caía a
//! los ~1.750 niveles (specs/compute-rendimiento.md F1.10). Este test es la guardia.

use synsema_core::interpreter::run_source;

fn depth(n: u32) -> synsema_core::interpreter::RunResult {
    let src = format!(
        "task f(n)\n    when n == 0\n        give 0\n    give f(n - 1) + 1\nprint(f({}))\n",
        n
    );
    run_source(&src, "<deep>")
}

#[test]
fn recursion_near_the_cap_works_and_past_it_is_an_error() {
    let r = depth(2900);
    assert!(r.success, "2900 niveles fallaron: {:?}", r.errors);
    assert_eq!(r.output, vec!["2900".to_string()]);

    let r = depth(3500);
    assert!(!r.success, "3500 niveles tendrían que pasar el tope");
    assert!(
        r.errors.iter().any(|e| e.contains("maximum recursion depth exceeded")),
        "se esperaba el error del tope, no otro: {:?}",
        r.errors
    );
}
