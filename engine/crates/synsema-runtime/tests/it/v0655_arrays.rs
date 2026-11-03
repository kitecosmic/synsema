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
    err_has("print(array_to_bytes(a, \"f16\"))", "array_to_bytes: dtype must be \"f64\", \"f32\" or \"bool\", got \"f16\"");
    err_has("print(array_from_bytes(bytes(\"\"), 4))", "array_from_bytes: dtype must be \"f64\", \"f32\" or \"bool\", got number");
    err_has("print(array_to_bytes(a, \"bool\"))", "array_to_bytes: \"bool\" is for masks and this array is f64 — compare first: a != 0");
    err_has("print(array_from_bytes(\"abc\", \"f64\"))", "array_from_bytes expects bytes, got text");
    err_has("print(array_to_bytes([1, 2]))", "array_to_bytes expects an array, got list");
}

// Ítems 2 y 3: `take` e `index_add` (stdlib), y `set a[i]` con etiquetas.
// Valores: `specs/v0.6.55-numpy/item23.py`.

#[test]
fn take_picks_positions_along_an_axis() {
    assert_eq!(with_a("print(take(M, [1, 0], axis = 1))\nprint(take(M, [1, 0], axis = -1))"), "[[2, 1], [4, 3]]\n[[2, 1], [4, 3]]");
    assert_eq!(with_a("print(take(M, [1, 1], axis = 0))\nprint(take(a, [3, 0]))"), "[[3, 4], [3, 4]]\n[8, 1]");
    assert_eq!(with_a("print(dtype(take(m, [0, 1])))"), "bool");
    err_has("print(take(M, [0], axis = 2))", "take: axis 2 out of range for a 2-D array");
    err_has(
        "print(take(M, [0]))",
        "take: say which axis of the 2-D array — axis = 0 for rows, axis = 1 for columns (numpy's take without an axis flattens: take(flatten(a), …))",
    );
    err_has("print(take(M, [0, 2], axis = 1))", "take: Index 2 out of bounds (array axis 1 has length 2)");
    err_has("print(take(a, m))", "take takes positions, not a mask — for the elements where a mask is true: where(a, m)");
    err_has("print(take([1, 2], [0]))", "take expects an array, got list");
}

#[test]
fn index_add_accumulates_repeated_positions() {
    assert_eq!(with_a("print(index_add(a, [0, 0, 2], array([1, 1, 1])))\nprint(a)"), "[3, 5, 3, 8]\n[1, 5, 2, 8]");
    assert_eq!(with_a("print(index_add(a, [0, 0, 2], 1))"), "[3, 5, 3, 8]");
    // El gradiente de un embedding: filas sumadas en sus posiciones.
    assert_eq!(
        with_a("print(index_add(zeros([4, 2]), [0, 2, 0], array([[1, 1], [2, 2], [3, 3]])))"),
        "[[4, 4], [0, 0], [2, 2], [0, 0]]"
    );
    assert_eq!(
        with_a("print(index_add(zeros([2, 3]), [2, 2], array([[1, 2], [3, 4]]), axis = 1))"),
        "[[0, 0, 3], [0, 0, 7]]"
    );
    err_has("print(index_add(a, [0, 1], array([1, 2, 3])))", "index_add: the values have shape [3] and the selection [2]");
    err_has("print(index_add(a, [0, 1], [1, 2]))", "index_add: make the list an array first: array(xs)");
    err_has("print(index_add(a, [9], 1))", "index_add: Index 9 out of bounds (array axis 0 has length 4)");
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

/// Diseño §3.3: un array congelado (el global que leen los workers de `parallel_map`) siempre se
/// copia al escribir; el de los demás workers y el del programa no cambian.
#[test]
fn set_on_a_frozen_array_copies() {
    let src = "let G be array([1, 2, 3])\n\
        task f(i)\n    let c be G\n    set c[0] to i\n    give sum(c)\n\
        print(parallel_map(f, [10, 20, 30]))\nprint(G)";
    assert_eq!(with_a(src), "[15.0, 25.0, 35.0]\n[1, 2, 3]");
}

/// `set z[i]` en un bucle caliente por el motor entero (el que compila a nativo): el mismo
/// resultado, sin el error de un array tomado por otro.
#[test]
fn set_in_a_hot_loop_through_the_engine() {
    let src = "let n be 20000\nlet z be zeros(n)\nlet Q be zeros([200, 3])\nlet i be 0\n\
        while i < n\n    set z[i] to i % 7\n    set Q[i % 200][i % 3] to Q[i % 200][i % 3] + 1\n    set i to i + 1\n\
        print(sum(z))\nprint(sum(Q))\nprint(Q[0])";
    assert_eq!(with_a(src), "59997.0\n20000.0\n[34, 33, 33]");
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

/// M4: con dos números, `equal`/`maximum` siguen los números del lenguaje (como `==` y `max`).
#[test]
fn elementwise_builtins_on_two_numbers_follow_the_language() {
    assert_eq!(with_a("print(maximum(2, 3))\nprint(minimum(2.5, 3))\nprint(maximum(2.0, 3.0))"), "3\n2.5\n3.0");
    assert_eq!(
        with_a("print(equal(9007199254740993, 9007199254740992))\nprint(9007199254740993 == 9007199254740992)"),
        "false\nfalse"
    );
    assert_eq!(with_a("print(not_equal(2, 2.0))\nprint(equal(nan, nan))\nprint(maximum(nan, 1))"), "false\nfalse\nnan");
    err_has("print(equal(\"a\", \"a\"))", "equal works on arrays (got text and text) — for two values use a == b");
    err_has("print(maximum(true, 1))", "maximum works on arrays (got bool and number) — for two numbers use max(a, b)");
}

/// M5: `sum` de una máscara cuenta también por eje: 0-d es un entero (numpy: `int64`).
#[test]
fn sum_of_a_mask_by_axis_counts() {
    assert_eq!(with_a("print(sum(array([1, 0]) > 0, axis = 0))\nprint(sum(m, axis = 0) + 0.5)"), "1\n2.5");
    assert_eq!(with_a("print(sum(M > 1, axis = 0))\nprint(sum(M > 1, axis = 1))"), "[1, 2]\n[1, 2]");
}
