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

#[test]
fn dtype_names_the_element_type() {
    assert_eq!(with_a("print(dtype(a))\nprint(dtype(m))"), "f64\nbool");
    err_has("print(dtype([1, 2]))", "dtype expects an array, got list");
}

#[test]
fn equal_and_not_equal_give_masks() {
    assert_eq!(with_a("print(equal(a, 5))"), "[false, true, false, false]");
    assert_eq!(with_a("print(not_equal(a, b))"), "[true, true, true, true]");
    // Dos números dan un bool, no un array 0-d (que se imprimiría igual).
    assert_eq!(with_a("print(equal(nan, nan))\nprint(type_of(equal(1, 1)))"), "false\nbool");
    assert_eq!(with_a("print(equal(array([nan, 1]), array([nan, 1])))"), "[false, true]");
    err_has("print(equal(a, [1, 5]))", "equal: make the list an array first: array(xs)");
}

#[test]
fn logical_functions_combine_masks() {
    assert_eq!(with_a("print(logical_and(m, a < 8))"), "[false, true, false, false]");
    assert_eq!(with_a("print(logical_or(m, a < 2))"), "[true, true, false, true]");
    assert_eq!(with_a("print(logical_not(m))"), "[true, false, true, false]");
    assert_eq!(with_a("print(sum(logical_and(m, a < 8)))"), "1");
    err_has(
        "print(logical_and(a, m))",
        "logical_and expects masks (bool arrays), got a f64 array — compare first: a > 0",
    );
    err_has("print(logical_not(true))", "logical_not expects masks (bool arrays), got bool");
}

#[test]
fn if_else_is_numpys_three_argument_where() {
    assert_eq!(with_a("print(if_else(m, a, 0))"), "[0, 5, 0, 8]");
    assert_eq!(with_a("print(dtype(if_else(m, a, 0)))"), "f64");
    assert_eq!(with_a("print(if_else(M > 2, M, array([[10], [20]])))"), "[[10, 10], [3, 4]]");
    // Los dos lados máscaras: una máscara.
    assert_eq!(with_a("print(if_else(m, a > 4, a < 2))"), "[true, true, false, true]");
    err_has("print(if_else(a, a, 0))", "if_else expects masks (bool arrays), got a f64 array");
    err_has("print(if_else(m, [1, 2, 3, 4], 0))", "if_else: make the list an array first: array(xs)");
}

#[test]
fn maximum_and_minimum_broadcast_and_propagate_nan() {
    assert_eq!(with_a("print(maximum(a, 3))"), "[3, 5, 3, 8]");
    assert_eq!(with_a("print(minimum(a, b))"), "[1, 3, 2, 1]");
    assert_eq!(with_a("print(maximum(a, array([nan, 0, 0, 0])))"), "[nan, 5, 2, 8]");
    assert_eq!(with_a("print(minimum(M, array([2, 2])))"), "[[1, 2], [2, 2]]");
    err_has("print(maximum(a, array([1, 2])))", "maximum: arrays of shape [4] and [2] are not broadcastable");
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
