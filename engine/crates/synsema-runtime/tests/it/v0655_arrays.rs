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

// Ítems 4, 7 y 8 (`synsema-stdlib/src/ndarray_ops.rs`). Valores: `specs/v0.6.55-numpy/item478.py`.

const T: &str = "let T be reshape(arange(0, 24), [2, 3, 4])\n";

#[test]
fn transpose_reorders_the_axes() {
    let t = |rest: &str| with_a(&format!("{}{}", T, rest));
    assert_eq!(
        t("let r be transpose(T, [0, 2, 1])\nprint(shape(r))\nprint(r[1])"),
        "[2, 4, 3]\n[[12, 16, 20], [13, 17, 21], [14, 18, 22], [15, 19, 23]]"
    );
    assert_eq!(t("let r be transpose(T, [-1, 0, 1])\nprint(shape(r))\nprint(r[3])"), "[4, 2, 3]\n[[3, 7, 11], [15, 19, 23]]");
    assert_eq!(with_a("print(transpose(M))\nprint(transpose(M, [1, 0]))"), "[[1, 3], [2, 4]]\n[[1, 3], [2, 4]]");
    assert_eq!(with_a("print(dtype(transpose(M > 2, [1, 0])))\nprint(transpose(M > 2, [1, 0]))"), "bool\n[[false, true], [false, true]]");
    for bad in ["[0, 0, 1]", "[0, 1]", "[0, 1, 3]", "[0, 1, 2.5]", "[0, 1, -4]"] {
        let out = t(&format!("print(transpose(T, {}))", bad));
        assert_eq!(out, format!("ERR: Runtime error: transpose: axes must be a permutation of 0..2, got {}", bad), "{}", bad);
    }
    err_has("print(transpose(M, \"10\"))", "transpose: axes must be a list of integers, got text");
}

#[test]
fn matmul_over_batches_broadcasts_like_numpy() {
    let src = "let A be reshape(arange(0, 24), [2, 3, 4])\nlet B be reshape(arange(0, 40), [2, 4, 5])\n";
    let t = |rest: &str| with_a(&format!("{}{}", src, rest));
    assert_eq!(
        t("let r be matmul(A, B)\nprint(shape(r))\nprint(r[1])"),
        "[2, 3, 5]\n[[1510, 1564, 1618, 1672, 1726], [1950, 2020, 2090, 2160, 2230], [2390, 2476, 2562, 2648, 2734]]"
    );
    assert_eq!(
        t("let r be matmul(reshape(arange(0, 12), [1, 3, 4]), reshape(arange(0, 140), [7, 4, 5]))\nprint(shape(r))\nprint(r[6][2])"),
        "[7, 3, 5]\n[4870, 4908, 4946, 4984, 5022]"
    );
    assert_eq!(
        t("let r be matmul(reshape(arange(0, 12), [3, 4]), B)\nprint(shape(r))\nprint(r[1][0])"),
        "[2, 3, 5]\n[190, 196, 202, 208, 214]"
    );
    assert_eq!(t("print(shape(matmul(ones([2, 1, 3, 4]), ones([5, 4, 2]))))"), "[2, 5, 3, 2]");
    assert_eq!(
        t("let r be matmul(A, reshape(arange(0, 20), [4, 5]))\nprint(shape(r))\nprint(r[1][0])"),
        "[2, 3, 5]\n[430, 484, 538, 592, 646]"
    );
    // El 2-D sigue siendo el del núcleo.
    assert_eq!(with_a("print(matmul(M, M))"), "[[7, 10], [15, 22]]");
    err_has(
        "print(matmul(ones([2, 3, 4]), ones([2, 5, 5])))",
        "matmul: incompatible shapes [2, 3, 4] and [2, 5, 5] (cols of A must equal rows of B)",
    );
    err_has(
        "print(matmul(ones([2, 3, 4]), ones([3, 4, 5])))",
        "matmul: the batch axes of [2, 3, 4] and [3, 4, 5] are not broadcastable",
    );
    err_has("print(matmul(ones([4]), ones([2, 4, 5])))", "matmul: expected a 2D array (matrix), got 1-D");
}

#[test]
fn arrays_to_bytes_and_back() {
    let x = "let x be array([1.5, -2, 0.1])\n";
    let t = |rest: &str| with_a(&format!("{}{}", x, rest));
    assert_eq!(t("print(hex(array_to_bytes(x)))"), "0x000000000000f83f00000000000000c09a9999999999b93f");
    assert_eq!(t("print(hex(array_to_bytes(x, \"f64\")))"), "0x000000000000f83f00000000000000c09a9999999999b93f");
    assert_eq!(t("print(hex(array_to_bytes(x, \"f32\")))"), "0x0000c03f000000c0cdcccc3d");
    assert_eq!(t("print(hex(array_to_bytes(array([1, 0, 1]) > 0)))"), "0x010001");
    // Una máscara como número es 0/1 (R2).
    assert_eq!(t("print(hex(array_to_bytes(array([1, 0]) > 0, \"f32\")))"), "0x0000803f00000000");
    assert_eq!(t("print(array_from_bytes(array_to_bytes(x, \"f32\"), \"f32\"))"), "[1.5, -2, 0.10000000149011612]");
    assert_eq!(t("print(array_from_bytes(array_to_bytes(x), \"f64\") == x)"), "true");
    assert_eq!(
        t("print(array_from_bytes(array_to_bytes(arange(0, 6), \"f32\"), \"f32\", shape = [2, 3]))"),
        "[[0, 1, 2], [3, 4, 5]]"
    );
    assert_eq!(t("let m be array_from_bytes(array_to_bytes(x > 0), \"bool\")\nprint(dtype(m))\nprint(m)"), "bool\n[true, false, true]");
    assert_eq!(t("print(shape(array_from_bytes(bytes(\"\"), \"f64\")))"), "[0]");
    err_has(
        "print(array_from_bytes(bytes(\"0123456789\"), \"f32\"))",
        "array_from_bytes: 10 bytes is not a whole number of f32 values (4 bytes each)",
    );
    err_has(
        "print(array_from_bytes(bytes(\"0123456789abcdef\"), \"f32\", shape = [2, 3]))",
        "array_from_bytes: shape [2, 3] needs 24 bytes, got 16",
    );
    err_has("print(array_from_bytes(bytes(\"a\"), \"bool\"))", "array_from_bytes: byte 97 at position 0 is not a bool (0 or 1)");
    err_has("print(array_to_bytes(a, \"i8\"))", "array_to_bytes: unknown element type \"i8\" — \"f64\", \"f32\" or \"bool\"");
    err_has("print(array_to_bytes(a, \"bool\"))", "array_to_bytes: \"bool\" is for masks and this array is f64 — compare first: a != 0");
    err_has("print(array_from_bytes(\"abc\", \"f64\"))", "array_from_bytes expects bytes, got text");
    err_has("print(array_to_bytes([1, 2]))", "array_to_bytes expects an array, got list");
}
