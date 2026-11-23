//! v0.6.46, Tanda C: lo que queda en Rust (v0.6.68, migas §1) — el linaje y sus salidas vistos
//! desde el `Interpreter` de Rust. c1/c2/c6 viven en `tests/v0646_tanda_c.test.syn` (c5 es error
//! de parseo y también quedó en Rust).

use synsema_core::interpreter::run_source;

fn assert_output(source: &str, expected: &[&str]) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.output, exp, "fuente:\n{}", source);
}

fn error_of(source: &str) -> String {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    r.errors.join("\n")
}

/// C5: `discovery off` es una cláusula del `serve`; otra palabra después de `discovery` es un error
/// que dice la forma, y el mensaje de cláusula desconocida la lista.
#[test]
fn c5_discovery_takes_only_off() {
    let e = error_of("require serve(8080)\nserve on 8080\n    discovery on\n");
    assert!(e.contains("Expected 'off' after 'discovery' (discovery off)"), "{}", e);
    let e = error_of("require serve(8080)\nserve on 8080\n    discovry off\n");
    assert!(e.contains("'discovery off'"), "{}", e);
}

/// Un intérprete con un `read_file` de mentira: una fuente del linaje que siempre trae "x".
fn with_fake_reads() -> synsema_core::interpreter::Interpreter {
    let i = synsema_core::interpreter::Interpreter::new();
    i.register_builtin("read_file", 1, std::rc::Rc::new(|_, _, _| Ok(synsema_core::types::syn_text("x"))));
    i
}

fn exec(i: &mut synsema_core::interpreter::Interpreter, src: &str) {
    let p = synsema_core::parser::parse_source(src, "<t>").unwrap();
    assert!(i.execute(&p).is_ok());
}

/// Ronda 1 de cf1 (M1): `serve` reusa el intérprete entre requests y el linaje no se vaciaba: el
/// `receipt()` de un request listaba lo que leyeron y escribieron los anteriores (de otros usuarios).
#[test]
fn c3_lineage_and_outputs_are_per_request() {
    let mut i = with_fake_reads();
    exec(&mut i, "read_file(\"a\")\n");
    i.record_output("write_file", "uploads/ana.json", b"{}", "text");
    assert_eq!((i.lineage().len(), i.outputs().len()), (1, 1));
    i.reset_for_request();
    assert_eq!((i.lineage().len(), i.outputs().len()), (0, 0), "el request siguiente arranca vacío");
}

/// Ronda 1 de cf1 (N1): `*_truncated` dice que se perdió algo, no que se llegó al tope.
#[test]
fn c3_truncated_means_something_was_dropped() {
    use synsema_core::interpreter::MAX_LINEAGE;
    let mut i = with_fake_reads();
    for _ in 0..MAX_LINEAGE {
        i.record_output("write_file", "a", b"x", "text");
    }
    exec(&mut i, &format!("each k in range(0, {})\n    read_file(\"a\")\n", MAX_LINEAGE));
    assert_eq!(i.lineage_truncated(), (false, false), "con el tope justo no se perdió nada");
    i.record_output("write_file", "a", b"x", "text");
    exec(&mut i, "read_file(\"a\")\n");
    assert_eq!(i.lineage_truncated(), (true, true));
    assert_eq!((i.lineage().len(), i.outputs().len()), (MAX_LINEAGE, MAX_LINEAGE));
    i.reset_for_request();
    assert_eq!(i.lineage_truncated(), (false, false));
}
