//! Frames reciclados (F2a.3 de specs/compute-rendimiento.md): el entorno de una llamada o de una
//! vuelta de `each` que nadie capturó se reusa. Lo que una closure capturó sigue intacto, una
//! llamada nunca ve las variables de la anterior y el padre de cada frame es el de ahora. Cada
//! programa corre en modo referencia (sin reciclar) y con atajos, y los dos dan lo mismo.
//!
//! Un solo `#[test]`: prende y apaga el modo referencia, que es del proceso.

use synsema_core::interpreter::{run_source, set_reference_mode};

const CAPTURES: &str = include_str!("../../synsema-runtime/tests/oracle_cases/frame_reuse.syn");

const EXPECTED: &[&str] = &[
    "2", "11", "0", "100", "200", "a", "b", "14", "16", "3628800", "hola ana", "chau beto", "hola carla",
];

/// La segunda llamada puede recibir el frame de la primera: no puede ver su `secret`.
const NO_LEAK: &str = "task f()\n    let secret be 42\n    give 0\ntask g()\n    give secret\nprint(f())\nprint(g())\n";

/// Lo mismo en una vuelta de `each`: la variable de la vuelta anterior no existe en la siguiente.
const NO_LEAK_EACH: &str = "each i in [1, 2]\n    when i == 2\n        print(seen)\n    let seen be i\n";

#[test]
fn recycled_frames_keep_captures_and_leak_nothing() {
    for reference in [true, false] {
        set_reference_mode(reference);
        let r = run_source(CAPTURES, "<frames>");
        let leak = run_source(NO_LEAK, "<leak>");
        let leak_each = run_source(NO_LEAK_EACH, "<leak-each>");
        set_reference_mode(false);

        assert!(r.success, "referencia={}: {:?}", reference, r.errors);
        assert_eq!(r.output, EXPECTED, "referencia={}", reference);

        assert!(!leak.success, "referencia={}: g() vio el `secret` de f(): {:?}", reference, leak.output);
        assert_eq!(leak.output, ["0"], "referencia={}", reference);
        assert!(format!("{:?}", leak.errors).contains("secret"), "referencia={}: {:?}", reference, leak.errors);

        assert!(!leak_each.success, "referencia={}: la vuelta 2 vio `seen` de la 1", reference);
        assert!(format!("{:?}", leak_each.errors).contains("seen"), "referencia={}: {:?}", reference, leak_each.errors);
    }
}
