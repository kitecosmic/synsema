//! v0.6.55 (ítem 1): los builtins elemento a elemento de `synsema-stdlib/src/ndarray_ops.rs`
//! (`dtype`, `equal`, `not_equal`, `logical_*`, `if_else`, `maximum`, `minimum`) desde un programa.
//! Los valores esperados salen de numpy 2.2.1: `specs/v0.6.55-numpy/item1.py`.

fn run(src: &str) -> synsema_core::interpreter::RunResult {
    synsema_runtime::engine::run_source(src, "v0655.syn")
}

const A: &str = "let a be array([1, 5, 2, 8])\nlet m be a > 2\nlet b be array([3, 3, 9, 1])\nlet M be array([[1, 2], [3, 4]])\n";

/// Lo impreso por `rest` (después de `A`), o `ERR: <error>`.
fn with_a(rest: &str) -> String {
    let r = run(&format!("{}{}", A, rest));
    if r.success {
        r.output.join("\n")
    } else {
        format!("ERR: {}", r.errors.join("\n"))
    }
}

fn err_has(rest: &str, want: &str) {
    let out = with_a(rest);
    assert!(out.starts_with("ERR: ") && out.contains(want), "{}\n→ {}", rest, out);
}











/// Diseño §4: el resultado lleva la etiqueta del array privado, sin corte (`equal(p, 3)`,
/// `if_else` y compañía son flujo de datos).
#[test]
fn elementwise_builtins_keep_the_label() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let p = "let p be private(array([1, 5, 2, 8]), \"x\")\n";
    for (expr, want) in [
        ("equal(p, 5)", "[false, true, false, false]"),
        ("not_equal(p, 5)", "[true, false, true, true]"),
        ("if_else(p > 2, p, 0)", "[0, 5, 0, 8]"),
        ("if_else(array([1, 5, 2, 8]) > 2, 0, p)", "[1, 0, 2, 0]"),
        ("maximum(p, 3)", "[3, 5, 3, 8]"),
        ("logical_not(p > 2)", "[true, false, true, false]"),
        ("dtype(p > 2)", "bool"),
        ("transpose(p, [0])", "[1, 5, 2, 8]"),
        ("array_from_bytes(array_to_bytes(p), \"f64\")", "[1, 5, 2, 8]"),
    ] {
        let src = format!("{}let r be {}\n", p, expr);
        let program = synsema_core::parser::parse_source(&src, "<v0655>").unwrap();
        let mut interp = Interpreter::new();
        synsema_stdlib::ndarray_ops::register_ndarray_builtins(&interp);
        interp.set_labels(true);
        interp.set_labels_detail_to_program(true);
        if let Err(Control::Error(e)) = interp.execute(&program) {
            panic!("{}: {}", expr, e);
        }
        let v = env_get(&interp.global_env, "r").expect("sin r");
        assert_eq!(
            (label_display_raw(&label_deep(&v)).as_str(), strip_deep(&v).to_string().as_str()),
            ("x", want),
            "{}",
            expr
        );
    }
}

/// R4 en las plantillas: `{ when m }` con un array da el error del `when`.
#[test]
fn a_template_when_on_an_array_is_an_error() {
    // Una plantilla se lee relativa al directorio de trabajo (el del crate al correr los tests).
    let dir = std::path::PathBuf::from(format!("tmp_v0655_tpl_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Se borra también si el test falla.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    std::fs::write(dir.join("t.html"), "{ when m }yes{ otherwise }no{ end }").unwrap();
    let p = format!("{}/t.html", dir.display());
    let run_with = |m: &str| {
        let r = run(&format!("require file(\"{p}\")\nprint(render(\"{p}\", {{\"m\": {m}}}).body)\n"));
        if r.success { r.output.join("\n") } else { format!("ERR: {}", r.errors.join("\n")) }
    };
    assert_eq!(run_with("some(array([1, 5]) > 2)"), "yes");
    let out = run_with("array([1, 5]) > 2");
    assert!(out.contains("an array is not true or false"), "{}", out);
    // Ítem 9: `{ each }` recorre un array como `each`.
    std::fs::write(dir.join("t.html"), "{ each x in m }[{ x }]{ end }").unwrap();
    assert_eq!(run_with("array([1, 5]) > 2"), "[false][true]");
    assert_eq!(run_with("array([[1, 2], [3, 4]])"), "[[1, 2]][[3, 4]]");
}

/// R6 con `set`: un array privado recibe valores tan privados como él; uno público no guarda un
/// elemento privado, y una rama privada no escribe en él.
#[test]
fn set_into_an_array_respects_labels() {
    use synsema_core::interpreter::{env_get, Control, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let run = |src: &str| {
        let program = synsema_core::parser::parse_source(src, "<v0655>").unwrap();
        let mut interp = Interpreter::new();
        synsema_stdlib::ndarray_ops::register_ndarray_builtins(&interp);
        interp.set_labels(true);
        interp.set_labels_detail_to_program(true);
        let r = interp.execute(&program);
        (interp, r)
    };
    let (interp, r) = run("let p be private(array([1, 5, 2, 8]), \"x\")\nset p[0] to p[1] * 2\nset p[[2, 3]] to 0\n");
    assert!(r.is_ok(), "{:?}", r.err().map(|c| match c { Control::Error(e) => e.message.clone(), _ => String::new() }));
    let v = env_get(&interp.global_env, "p").unwrap();
    assert_eq!((label_display_raw(&label_deep(&v)), strip_deep(&v).to_string()), ("x".to_string(), "[10, 5, 0, 0]".to_string()));
    // R5 con un array privado: el alias no cambia.
    let (interp, r) = run("let p be private(array([1, 2]), \"x\")\nlet q be p\nset p[0] to 9\n");
    assert!(r.is_ok());
    let q = env_get(&interp.global_env, "q").unwrap();
    let p = env_get(&interp.global_env, "p").unwrap();
    assert_eq!((strip_deep(&q).to_string(), strip_deep(&p).to_string()), ("[1, 2]".to_string(), "[9, 2]".to_string()));
    let err_of = |src: &str| match run(src).1 {
        Err(Control::Error(e)) => e.message.clone(),
        other => panic!("se esperaba un error: {:?}", other.is_ok()),
    };
    let e = err_of("let a be array([1, 5])\nlet s be private(3, \"x\")\nset a[0] to s\n");
    assert!(e.contains("into the array 'a' (public): an array is private as a whole"), "{}", e);
    let e = err_of("let a be array([1, 5])\nlet s be private(3, \"x\")\nwhen s > 2\n    set a[0] to 1\n");
    assert!(e.contains("a position of the array 'a'"), "{}", e);
}

// =========================================================
// Auditoría v0.6.55, ronda 1
// =========================================================

/// N3: `matmul` y `dot` con una matriz y un vector dicen la forma Synsema (antes se mandaban uno al
/// otro), con el largo del vector; y la forma que dicen anda.
#[test]
fn matmul_and_dot_with_a_vector_name_the_shape() {
    let v = "let v be array([1, 1])\n";
    let t = |rest: &str| with_a(&format!("{}{}", v, rest));
    assert_eq!(
        t("print(matmul(M, v))"),
        "ERR: Runtime error: matmul: expected a 2D array (matrix), got 1-D — for a matrix times a vector: matmul(M, reshape(v, [2, 1])); for two vectors: dot(a, b)"
    );
    assert_eq!(
        t("print(matmul(v, M))"),
        "ERR: Runtime error: matmul: expected a 2D array (matrix), got 1-D — for a vector times a matrix: matmul(reshape(v, [1, 2]), M); for two vectors: dot(a, b)"
    );
    assert_eq!(t("print(matmul(v, v))"), "ERR: Runtime error: matmul: expected a 2D array (matrix), got 1-D — for two vectors: dot(a, b)");
    assert_eq!(
        t("print(dot(M, v))"),
        "ERR: Runtime error: dot is the inner product of two 1-D vectors (got 2-D and 1-D) — for a matrix times a vector: matmul(M, reshape(v, [2, 1]))"
    );
    assert_eq!(
        t("print(dot(v, M))"),
        "ERR: Runtime error: dot is the inner product of two 1-D vectors (got 1-D and 2-D) — for a vector times a matrix: matmul(reshape(v, [1, 2]), M)"
    );
    assert_eq!(
        t("print(dot(M, M))"),
        "ERR: Runtime error: dot is the inner product of two 1-D vectors (got 2-D and 2-D) — for matrices use matmul(a, b)"
    );
    // Lo que el mensaje propone (numpy: M @ v = [3, 7], v @ M = [4, 6]).
    assert_eq!(t("print(matmul(M, reshape(v, [2, 1])))\nprint(matmul(reshape(v, [1, 2]), M))"), "[[3], [7]]\n[[4, 6]]");
}

/// M28 (ronda 6): el REPL atrapa el error de cada línea y sigue en el mismo hilo; un `set` que falló a
/// mitad de camino no le deja a la línea siguiente una copia del array retenida.
#[test]
fn the_repl_does_not_keep_copies_of_failed_sets() {
    use synsema_core::interpreter::{env_get, Interpreter};
    use synsema_core::types::SynValue;
    use synsema_runtime::engine::repl_eval;
    let ptr = |interp: &Interpreter| match env_get(&interp.global_env, "A") {
        Some(SynValue::Array(o)) => synsema_core::types::Obj::as_ptr(&o) as usize,
        other => panic!("{:?}", other.map(|v| v.type_name())),
    };
    let mut interp = Interpreter::new();
    assert_eq!(repl_eval(&mut interp, "let A be zeros([2, 3])"), None);
    let before = ptr(&interp);
    for _ in 0..3 {
        let e = repl_eval(&mut interp, "set A[0][nope] to 1").expect("la línea falla");
        assert!(e.starts_with("Runtime error:"), "{}", e);
    }
    assert_eq!(repl_eval(&mut interp, "set A[0][1] to 5"), None);
    assert_eq!(ptr(&interp), before);
    assert_eq!(repl_eval(&mut interp, "print(A[0][1])"), None);
    assert_eq!(interp.output.last().map(String::as_str), Some("5.0"));
}
