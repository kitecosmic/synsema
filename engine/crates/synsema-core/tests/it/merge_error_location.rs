//! Los errores de `merge` dicen en qué línea está la llamada, sea cual sea la forma de la
//! sentencia. Antes `set m to merge(m, 5)` (el camino en el lugar) la daba y `set n to merge(m, 5)`
//! (el builtin) no: el oráculo diferencial encontró la diferencia.

use synsema_core::interpreter::run_source;

fn error_of(src: &str) -> String {
    let r = run_source(src, "<merge>");
    assert!(!r.success, "se esperaba un error:\n{}", src);
    r.errors.join("\n")
}

#[test]
fn merge_errors_carry_the_call_location() {
    let cases = [
        // (programa, línea:columna de la llamada, mensaje)
        ("let m be {\"a\": 1}\nset m to merge(m, 5)\n", "<merge>:2:", "merge(): argument 2 is number, not a map"),
        ("let m be {\"a\": 1}\nlet n be merge(m, 5)\n", "<merge>:2:", "merge(): argument 2 is number, not a map"),
        ("let m be {\"a\": 1}\nset m to merge(m, {\"b\": 1}, [1])\n", "<merge>:2:", "merge(): argument 3 is list, not a map"),
        ("let n be merge()\n", "<merge>:1:", "merge() needs at least one map"),
    ];
    for (src, at, msg) in cases {
        let e = error_of(src);
        assert!(e.contains(msg), "falta el mensaje {:?} en {:?}", msg, e);
        assert!(e.contains(at), "falta la ubicación {:?} en {:?}", at, e);
    }
}
