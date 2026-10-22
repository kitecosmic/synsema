//! v0.6.46, Tanda C (C1, C2, C5 y C6): `enumerate` sobre un array, las pistas del camino de error y
//! la cláusula `discovery off`.

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

/// C1: un array se enumera por su primer eje, como `length(a)` y `a[i]`.
#[test]
fn c1_enumerate_walks_an_array_by_its_first_axis() {
    assert_output(
        "let e be enumerate(array([10, 20, 30]))\n\
         print(length(e))\n\
         print(e[2][\"index\"])\n\
         print(e[2][\"item\"] == 30)\n",
        &["3", "2", "true"],
    );
    // 2-D: cada `item` es la fila, igual que `m[i]`.
    assert_output(
        "let m be array([[1, 2], [3, 4]])\n\
         let e be enumerate(m)\n\
         print(length(e))\n\
         print(to_list(e[1][\"item\"]) == to_list(m[1]))\n",
        &["2", "true"],
    );
    let e = error_of("print(enumerate(array(5)))\n");
    assert!(e.contains("0-d array"), "{}", e);
    let e = error_of("print(enumerate(5))\n");
    assert!(e.contains("requires a list or an array, got number"), "{}", e);
}

/// C2: `log(x)` dice cuál logaritmo, y `in_units` con un número dice cómo armar la duración.
#[test]
fn c2_hints_for_log_and_in_units() {
    let e = error_of("print(log(10))\n");
    assert!(e.contains("ln(x)") && e.contains("log10(x)") && e.contains("log \"message\""), "{}", e);
    let e = error_of("print(in_units(90, \"minutes\"))\n");
    assert!(e.contains("got number") && e.contains("duration(seconds = 90)"), "{}", e);
    // La pista arma una llamada que anda.
    assert_output("print(in_units(duration(seconds = 90), \"minutes\"))\n", &["1.5"]);
}

/// C6: un nombre que no existe dice los parámetros que hay y el más cercano.
#[test]
fn c6_unknown_parameter_names_the_valid_ones() {
    let e = error_of("task page(limit, offset)\n    give limit + offset\nprint(page(limt = 1, offset = 0))\n");
    assert!(e.contains("unknown parameter 'limt'") && e.contains("did you mean 'limit'?"), "{}", e);
    assert!(e.contains("the parameters are: limit, offset"), "{}", e);
    // Un builtin con nombres (`duration`) dice los suyos.
    let e = error_of("print(duration(hour = 1))\n");
    assert!(e.contains("did you mean 'hours'?") && e.contains("days, hours, minutes"), "{}", e);
    // Sin nada cercano, sólo la lista.
    let e = error_of("task f(a)\n    give a\nprint(f(zzzzzz = 1))\n");
    assert!(!e.contains("did you mean") && e.contains("the parameters are: a"), "{}", e);
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
