//! v0.6.55 — arrays sin bucles por elemento (specs/v0.6.55-diseno.md).
//!
//! Paso 2 de las migas: el tipo de elemento vive dentro del `Obj` (`NdArray::F64`/`NdArray::Bool`).
//! Todavía ningún builtin produce una máscara, así que estos tests la construyen desde Rust y
//! verifican cada sitio que mira el tipo (§2 del diseño): repr, `to_list`, snapshots, igualdad,
//! operaciones de forma (que lo conservan) y aritmética (que la pasa a 0/1, R2). El tamaño de
//! `SynValue` lo cuida `type_sizes`.

use ndarray::{ArrayD, IxDyn};
use synsema_core::arrays;
use synsema_core::interpreter::Control;
use synsema_core::types::{from_send, syn_array, syn_float, syn_int, syn_list, syn_mask, to_send, NdArray, SendArray, SendValue, SynValue};

fn mask(shape: &[usize], v: &[bool]) -> SynValue {
    syn_mask(ArrayD::from_shape_vec(IxDyn(shape), v.to_vec()).unwrap())
}

fn f64s(shape: &[usize], v: &[f64]) -> SynValue {
    syn_array(ArrayD::from_shape_vec(IxDyn(shape), v.to_vec()).unwrap())
}

fn ok(r: Result<SynValue, Control>) -> SynValue {
    match r {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn dtype(v: &SynValue) -> &'static str {
    match v {
        SynValue::Array(a) => a.dtype(),
        other => panic!("esperaba un array, got {}", other.type_name()),
    }
}

#[test]
fn a_mask_prints_as_true_false() {
    let m = mask(&[4], &[false, true, false, true]);
    assert_eq!(m.to_string(), "[false, true, false, true]");
    assert_eq!(m.type_name(), "array");
    assert_eq!(dtype(&m), "bool");
    assert_eq!(mask(&[2, 2], &[true, false, false, true]).to_string(), "[[true, false], [false, true]]");
    // Más de 100 elementos: el mismo resumen que un array `f64`.
    assert_eq!(mask(&[101], &[true; 101]).to_string(), "array(shape=[101], 101 elements)");
    assert_eq!(dtype(&f64s(&[2], &[1.0, 2.0])), "f64");
}

#[test]
fn to_list_of_a_mask_gives_bools() {
    let l = ok(arrays::to_list(&[mask(&[2, 2], &[true, false, false, true])]));
    assert_eq!(l.to_string(), "[[true, false], [false, true]]");
    match &l {
        SynValue::List(rows) => match &rows.borrow().to_vec()[0] {
            SynValue::List(r) => assert!(matches!(r.borrow().to_vec()[0], SynValue::Bool(true))),
            other => panic!("fila: {}", other.type_name()),
        },
        other => panic!("{}", other.type_name()),
    }
    // Un array `f64` sigue dando números.
    assert_eq!(ok(arrays::to_list(&[f64s(&[2], &[1.0, 2.5])])).to_string(), "[1.0, 2.5]");
}

/// Un snapshot (`parallel_map`, globales de `serve`, agentes) lleva el tipo de elemento.
#[test]
fn a_mask_crosses_a_snapshot_with_its_dtype() {
    let m = mask(&[2, 2], &[true, false, false, true]);
    let s = to_send(&m);
    assert_eq!(s, SendValue::Array(vec![2, 2], SendArray::Bool(vec![true, false, false, true])));
    assert_eq!(s.to_string(), "[[true, false], [false, true]]");
    let back = from_send(&s);
    assert_eq!(dtype(&back), "bool");
    assert!(back.syn_equals(&m));
    let f = f64s(&[3], &[1.0, -0.0, f64::INFINITY]);
    let back = from_send(&to_send(&f));
    assert_eq!(dtype(&back), "f64");
    assert!(back.syn_equals(&f));
    if let SendValue::Array(_, d) = to_send(&m) {
        assert_eq!((d.len(), d.byte_len()), (4, 4));
    }
    if let SendValue::Array(_, d) = to_send(&f) {
        assert_eq!((d.len(), d.byte_len()), (3, 24));
    }
}

/// R3: igualdad del valor entero; una máscara nunca es igual a un `f64` con los mismos 0/1.
#[test]
fn whole_value_equality_looks_at_the_dtype() {
    let m = mask(&[2], &[false, true]);
    assert!(m.syn_equals(&mask(&[2], &[false, true])));
    assert!(!m.syn_equals(&mask(&[2], &[true, true])));
    assert!(!m.syn_equals(&mask(&[1, 2], &[false, true])));
    assert!(!m.syn_equals(&f64s(&[2], &[0.0, 1.0])));
    assert!(!f64s(&[2], &[0.0, 1.0]).syn_equals(&m));
    assert!(!f64s(&[1], &[f64::NAN]).syn_equals(&f64s(&[1], &[f64::NAN])));
}

/// Forma y orden no dependen del tipo: `reshape`, `transpose`, `flatten`, `slice`, `a[i]` y `at`
/// devuelven una máscara (o un `bool` suelto).
#[test]
fn shape_operations_keep_the_mask() {
    let m = mask(&[2, 3], &[true, false, false, false, true, true]);
    let r = ok(arrays::reshape(&[m.clone(), syn_list(vec![syn_int(3), syn_int(2)])]));
    assert_eq!((dtype(&r), r.to_string().as_str()), ("bool", "[[true, false], [false, false], [true, true]]"));
    let t = ok(arrays::transpose(&[m.clone()]));
    assert_eq!((dtype(&t), t.to_string().as_str()), ("bool", "[[true, false], [false, true], [false, true]]"));
    let f = ok(arrays::flatten(&[m.clone()]));
    assert_eq!((dtype(&f), f.to_string().as_str()), ("bool", "[true, false, false, false, true, true]"));
    let SynValue::Array(a) = &m else { unreachable!() };
    let row = ok(arrays::index_row(a, -1));
    assert_eq!((dtype(&row), row.to_string().as_str()), ("bool", "[false, true, true]"));
    let s = arrays::slice_rows(a, 1, 2);
    assert_eq!((dtype(&s), s.to_string().as_str()), ("bool", "[[false, true, true]]"));
    let SynValue::Array(f1) = &f else { unreachable!() };
    assert!(matches!(ok(arrays::index_row(f1, 0)), SynValue::Bool(true)));
    let at = ok(arrays::at(&[m.clone(), syn_list(vec![syn_int(1), syn_int(2)])]));
    assert!(matches!(at, SynValue::Bool(true)));
    // Las de introspección no convierten.
    assert_eq!(ok(arrays::shape(&[m.clone()])).to_string(), "[2, 3]");
    assert_eq!(ok(arrays::size(&[m.clone()])).to_string(), "6");
    assert_eq!(ok(arrays::ndim(&[m])).to_string(), "2");
}

/// R2: en una cuenta, una máscara es 0/1 en `f64`.
#[test]
fn a_mask_in_arithmetic_is_zero_one() {
    let m = mask(&[3], &[true, false, true]);
    let g = f64s(&[3], &[2.0, 3.0, 4.0]);
    let r = arrays::array_binop(&m, &g, "*").unwrap();
    let r = ok(r);
    assert_eq!((dtype(&r), r.to_string().as_str()), ("f64", "[2, 0, 4]"));
    let r = ok(arrays::array_binop(&m, &m, "+").unwrap());
    assert_eq!((dtype(&r), r.to_string().as_str()), ("f64", "[2, 0, 2]"));
    let r = ok(arrays::array_binop(&syn_float(1.5), &m, "*").unwrap());
    assert_eq!(r.to_string(), "[1.5, 0, 1.5]");
    let SynValue::Array(a) = &m else { unreachable!() };
    assert_eq!(arrays::negate(a).to_string(), "[-1, -0, -1]");
    let d = ok(arrays::dot(&[m.clone(), g]));
    assert_eq!(d.to_string(), "6.0");
}

#[test]
fn ndarray_helpers() {
    let b = NdArray::from(ArrayD::from_shape_vec(IxDyn(&[0]), Vec::<bool>::new()).unwrap());
    assert!(b.is_empty() && b.ndim() == 1 && b.dtype() == "bool" && b.as_f64().is_none());
    let f = NdArray::from(ArrayD::from_elem(IxDyn(&[2, 2]), 1.5));
    assert_eq!((f.len(), f.shape()), (4, &[2usize, 2][..]));
    assert!(matches!(f.to_f64(), std::borrow::Cow::Borrowed(_)), "un f64 no se copia");
    let m = NdArray::from(ArrayD::from_shape_vec(IxDyn(&[2]), vec![true, false]).unwrap());
    assert_eq!(m.to_f64().iter().copied().collect::<Vec<_>>(), vec![1.0, 0.0]);
}

/// `fill_nan` sobre una máscara: no tiene NaN, queda igual (y sigue siendo máscara).
#[test]
fn fill_nan_leaves_a_mask_alone() {
    let m = mask(&[2], &[true, false]);
    let r = ok(synsema_core::tabular::fill_nan(&[m.clone(), syn_int(7)]));
    assert_eq!((dtype(&r), r.to_string().as_str()), ("bool", "[true, false]"));
    let r = ok(synsema_core::tabular::fill_nan(&[f64s(&[2], &[f64::NAN, 1.0]), syn_int(7)]));
    assert_eq!((dtype(&r), r.to_string().as_str()), ("f64", "[7, 1]"));
}

// =========================================================
// 1b — `apply` sobre un array con etiquetas (diseño §4, R6)
// =========================================================

/// Corre con etiquetas encendidas y devuelve (etiqueta profunda, valor sin etiquetas) de `r`.
fn labelled_r(source: &str) -> (String, String) {
    use synsema_core::interpreter::{env_get, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("el programa falló: {}\nfuente:\n{}", e, source);
    }
    let v = env_get(&interp.global_env, "r").expect("sin r");
    let stripped = strip_deep(&v);
    assert_eq!(stripped.type_name(), "array", "fuente:\n{}", source);
    (label_display_raw(&label_deep(&v)), stripped.to_string())
}

/// v0.6.54: `apply(private(a), f)` cortaba con `Runtime error: private(x)`: la lambda devuelve un
/// `Private` (el PC del despacho etiquetado) y `apply` sobre arrays sólo aceptaba números.
#[test]
fn apply_over_a_private_array_gives_a_private_array() {
    let (l, v) = labelled_r("let r be apply(private(array([1, 5, 2, 8]), \"x\"), (x) => x * 2)\n");
    assert_eq!((l.as_str(), v.as_str()), ("x", "[2, 10, 4, 16]"));
}

#[test]
fn apply_with_a_captured_private_labels_the_whole_array() {
    let (l, v) = labelled_r("let k be private(3, \"x\")\nlet r be apply(array([1, 5]), (x) => x * k)\n");
    assert_eq!((l.as_str(), v.as_str()), ("x", "[3, 15]"));
    let (l, v) = labelled_r("let r be apply(array([1, 5]), (x) => x * 3)\n");
    assert_eq!((l.as_str(), v.as_str()), ("", "[3, 15]"));
}

/// Lo que ya andaba sigue igual: `where` con predicado, aritmética y `sum` sobre el array privado.
#[test]
fn where_and_arithmetic_over_a_private_array_still_work() {
    let (l, v) = labelled_r("let p be private(array([1, 5, 2, 8]), \"x\")\nlet r be where(p, (x) => x > 2)\n");
    assert_eq!((l.as_str(), v.as_str()), ("x", "[5, 8]"));
    let (l, v) = labelled_r("let p be private(array([1, 5]), \"x\")\nlet r be p * 2 + apply(p, (x) => x)\n");
    assert_eq!((l.as_str(), v.as_str()), ("x", "[3, 15]"));
}

// =========================================================
// Ítem 1 — comparaciones, máscaras, `==` y condiciones (diseño §3.1, §3.2)
// =========================================================

/// Corre `source` con la VM (sin etiquetas) y con el intérprete de árbol (`--labels`, sin datos
/// privados) y exige lo mismo de los dos: lo impreso, o `ERR: <mensaje>`.
fn both(source: &str) -> String {
    fn one(source: &str, labels: bool) -> String {
        use synsema_core::interpreter::Interpreter;
        let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
        let mut interp = Interpreter::new();
        interp.set_labels(labels);
        match interp.execute(&program) {
            Ok(_) => interp.output.join("\n"),
            Err(Control::Error(e)) => format!("ERR: {}", e.message),
            Err(_) => "otro control".to_string(),
        }
    }
    let (vm, tree) = (one(source, false), one(source, true));
    assert_eq!(vm, tree, "la VM y el árbol no coinciden en:\n{}", source);
    vm
}

const A: &str = "let a be array([1, 5, 2, 8])\nlet m be a > 2\n";

fn with_a(rest: &str) -> String {
    both(&format!("{}{}", A, rest))
}

#[test]
fn ordering_comparisons_give_masks() {
    assert_eq!(with_a("print(m)"), "[false, true, false, true]");
    assert_eq!(with_a("print(2 < a)"), "[false, true, false, true]");
    assert_eq!(with_a("print(a >= 5)"), "[false, true, false, true]");
    assert_eq!(with_a("print(a <= array([1, 1, 1, 9]))"), "[true, false, false, true]");
    // Broadcasting: una columna contra una fila.
    assert_eq!(both("print(array([[1], [3]]) > array([0, 2, 4]))"), "[[true, false, false], [true, true, false]]");
    assert_eq!(with_a("print(type_of(m))"), "array");
}

#[test]
fn a_comparison_with_nan_is_false() {
    assert_eq!(with_a("print(a > nan)\nprint(a <= nan)"), "[false, false, false, false]\n[false, false, false, false]");
}

#[test]
fn comparison_errors_name_the_synsema_way() {
    assert_eq!(with_a("print(m > m)"), "ERR: masks are not ordered — compare the numbers they came from");
    assert_eq!(
        with_a("print(a > [1, 2, 3, 4])"),
        "ERR: cannot compare an array with a list — make it an array first: array(xs)"
    );
    assert_eq!(with_a("print(a > array([1, 2]))"), "ERR: arrays of shape [4] and [2] are not broadcastable");
}

#[test]
fn a_mask_in_a_sum_is_a_count() {
    assert_eq!(with_a("print(sum(m))\nprint(is_integer(sum(m)))"), "2\ntrue");
    assert_eq!(with_a("print(mean(m))"), "0.5");
    assert_eq!(with_a("print(m * 1.0)"), "[0, 1, 0, 1]");
    assert_eq!(with_a("print(m + m)"), "[0, 2, 0, 2]");
    assert_eq!(with_a("print(sum(m * 1.0))"), "2.0");
}

#[test]
fn where_with_a_mask_keeps_the_true_elements() {
    assert_eq!(with_a("print(where(a, m))"), "[5, 8]");
    assert_eq!(with_a("print(where(a, (x) => x > 2))"), "[5, 8]");
    assert_eq!(both("let M be array([[1, 5], [7, 2]])\nprint(where(M, M > 2))"), "[5, 7]");
    // Una máscara filtrada por otra sigue siendo máscara.
    assert_eq!(with_a("print(where(m, m))"), "[true, true]");
    assert_eq!(with_a("print(where(a, slice(m, 0, 2)))"), "ERR: where: the mask has shape [2] and the array [4]");
    // Mismo largo, otra forma: también es un error (no se aplana en silencio).
    assert_eq!(
        with_a("print(where(array([[1, 5], [2, 8]]), m))"),
        "ERR: where: the mask has shape [4] and the array [2, 2]"
    );
    assert_eq!(
        with_a("print(where(a, a * 1.0))"),
        "ERR: where expects a mask (a > 0) or a predicate ((x) => …), got a f64 array"
    );
    assert_eq!(
        with_a("print(where(m, a, 0))"),
        "ERR: where takes a list or array and a predicate or mask; numpy's where(cond, x, y) is if_else(cond, x, y)"
    );
}

#[test]
fn some_every_count_where_over_arrays_and_masks() {
    assert_eq!(with_a("print(some(m))\nprint(every(m))\nprint(count_where(m))"), "true\nfalse\n2");
    assert_eq!(
        with_a("print(some(a, (x) => x > 7))\nprint(every(a, (x) => x > 0))\nprint(count_where(a, (x) => x > 1))"),
        "true\ntrue\n3"
    );
    assert_eq!(with_a("print(every(a > 0))"), "true");
    assert_eq!(with_a("print(count_where(m, (b) => not b))"), "2");
    assert_eq!(
        with_a("print(some(a))"),
        "ERR: some expects a mask (bool array) or a predicate, got a f64 array — compare first: a > 0"
    );
    // Las listas siguen igual.
    assert_eq!(both("print(some([1, 5], (x) => x > 2))"), "true");
}

#[test]
fn apply_returning_bools_gives_a_mask() {
    assert_eq!(with_a("let r be apply(a, (x) => x > 2)\nprint(r)\nprint(sum(r))"), "[false, true, false, true]\n2");
    let mixed = with_a("task f(x)\n    when x > 2\n        give true\n    give 1\nprint(apply(a, f))");
    assert_eq!(mixed, "ERR: apply over an array needs numbers back, got bool — use to_list(a) for other results");
}

#[test]
fn clamp_and_max_on_arrays() {
    assert_eq!(with_a("print(clamp(a, 0, 4))"), "[1, 4, 2, 4]");
    assert_eq!(with_a("print(clamp(a, array([2, 2, 2, 2]), 6))"), "[2, 5, 2, 6]");
    assert_eq!(with_a("print(clamp(3, 0, 1))"), "1");
    assert_eq!(
        with_a("print(max(a, a))"),
        "ERR: max: axis must be an integer, got [1, 5, 2, 8] — for the elementwise max of two arrays: maximum(a, b)"
    );
}

#[test]
fn numpy_names_point_to_synsema() {
    for (name, hint) in [
        ("any", "some(m) / every(m)"),
        ("all", "some(m) / every(m)"),
        ("clip", "clamp(a, lo, hi)"),
        ("scatter_add", "index_add(a, indices, values)"),
    ] {
        let out = with_a(&format!("print({}(m))", name));
        assert!(out.starts_with(&format!("ERR: Undefined variable: '{}'", name)), "{}", out);
        assert!(out.ends_with(&format!("— in Synsema: {}", hint)), "{}", out);
    }
}

#[test]
fn whole_value_equality_of_arrays() {
    assert_eq!(with_a("print(a == array([1, 5, 2, 8]))\nprint(a != array([1, 5, 2, 8]))"), "true\nfalse");
    assert_eq!(with_a("print(a == array([1, 5]))"), "false");
    assert_eq!(with_a("print(a == nothing)\nprint(a != nothing)"), "false\ntrue");
    assert_eq!(both("print(array([nan]) == array([nan]))"), "false");
    assert_eq!(with_a("print(array([1, 2]) in [array([1, 2])])"), "true");
    assert_eq!(with_a("print(contains([array([1, 2])], array([1, 2])))"), "true");
}

#[test]
fn equality_that_would_be_silently_false_is_an_error() {
    assert_eq!(
        with_a("print(m == array([0, 1, 0, 1]))"),
        "ERR: a mask and a f64 array are never equal — compare like with like (m * 1.0 gives 0/1 floats)"
    );
    assert_eq!(with_a("print(a == 3)"), "ERR: == compares whole values; for elementwise: equal(a, 3)");
    assert_eq!(with_a("print(a != 3)"), "ERR: != compares whole values; for elementwise: not_equal(a, 3)");
    assert_eq!(
        with_a("print(a == [1, 5, 2, 8])"),
        "ERR: == between an array and a list is never true — compare array(xs), or to_list(a) == xs"
    );
    assert_eq!(with_a("print(a == \"x\")"), "ERR: == between an array and text is never true");
    assert_eq!(with_a("print(3 == a)"), "ERR: == compares whole values; for elementwise: equal(a, 3)");
}

const NOT_A_CONDITION: &str =
    "an array is not true or false — some(m) / every(m) for a mask, length(a) > 0 for \"not empty\"";

fn not_a_condition() -> String {
    format!("ERR: {}", NOT_A_CONDITION)
}

#[test]
fn an_array_is_not_a_condition() {
    assert_eq!(with_a("when m\n    print(1)"), not_a_condition());
    assert_eq!(with_a("when a\n    print(1)"), not_a_condition());
    assert_eq!(with_a("when 1 > 2\n    print(1)\notherwise when m\n    print(2)"), not_a_condition());
    // Acotado: si `while m` pasara, el test falla en vez de colgarse.
    assert_eq!(with_a("let n be 0\nwhile m\n    set n to n + 1\n    when n > 2\n        stop"), not_a_condition());
    assert_eq!(
        with_a("match 1\n    is 1 when m\n        print(1)\n    otherwise\n        print(2)"),
        not_a_condition()
    );
    assert_eq!(with_a("assert(m)"), not_a_condition());
    // Un array vacío tampoco: no hay excepción por el tamaño.
    assert_eq!(both("when array([])\n    print(1)"), not_a_condition());
    // Lo que sí es una condición sigue igual.
    assert_eq!(with_a("when some(m)\n    print(1)\nwhen length(a) > 0\n    print(2)"), "1\n2");
}

#[test]
fn and_or_not_need_true_or_false() {
    let and = "ERR: and needs true or false, got a mask — combine masks with logical_and(m1, m2)";
    let or = "ERR: or needs true or false, got a mask — combine masks with logical_or(m1, m2)";
    assert_eq!(with_a("print(m and true)"), and);
    assert_eq!(with_a("print(true and m)"), and);
    assert_eq!(with_a("print(false or m)"), or);
    assert_eq!(with_a("print(m or true)"), or);
    assert_eq!(with_a("print(not m)"), "ERR: not needs true or false, got a mask — negate a mask with logical_not(m)");
    assert_eq!(with_a("print(not a)"), "ERR: not needs true or false, got an array — negate a mask with logical_not(m)");
    // Como condición de un `when`, lo mismo.
    assert_eq!(with_a("when m and true\n    print(1)"), and);
    // El cortocircuito no mira lo que no evalúa.
    assert_eq!(with_a("print(false and m)\nprint(true or m)"), "false\ntrue");
    // Una cadena de comparaciones de arrays es un `and`.
    assert_eq!(with_a("print(0 < a < 9)"), and);
}

#[test]
fn a_predicate_returning_an_array_names_the_function() {
    for f in ["where", "some", "every", "count_where", "find_first", "index_of"] {
        assert_eq!(
            with_a(&format!("print({}([1, 2], (x) => a))", f)),
            format!("ERR: {}: the function returned an array — {}", f, NOT_A_CONDITION)
        );
    }
}

/// Como `labelled_r`, sin exigir que `r` sea un array.
fn labelled_any(source: &str) -> (String, String) {
    use synsema_core::interpreter::{env_get, Interpreter};
    use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
    let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("el programa falló: {}\nfuente:\n{}", e, source);
    }
    let v = env_get(&interp.global_env, "r").expect("sin r");
    (label_display_raw(&label_deep(&v)), strip_deep(&v).to_string())
}

/// Diseño §4: una comparación sobre un array privado da una máscara privada, y la cuenta sobre ella
/// es flujo de datos (sin corte), con el resultado privado.
#[test]
fn a_private_array_gives_a_private_mask_and_counts_without_a_cut() {
    let p = "let p be private(array([1, 5, 2, 8]), \"x\")\n";
    for (expr, want) in [
        ("p > 2", "[false, true, false, true]"),
        ("sum(p > 2)", "2"),
        ("some(p > 2)", "true"),
        ("every(p > 2)", "false"),
        ("count_where(p > 2)", "2"),
        ("where(p, p > 2)", "[5, 8]"),
        ("where(array([1, 5, 2, 8]), p > 2)", "[5, 8]"),
        ("count_where(p, (x) => x > 2)", "2"),
        ("some(p, (x) => x > 7)", "true"),
        ("apply(p, (x) => x > 2)", "[false, true, false, true]"),
        ("p == array([1, 5, 2, 8])", "true"),
        ("clamp(p, 0, 4)", "[1, 4, 2, 4]"),
    ] {
        let (l, v) = labelled_any(&format!("{}let r be {}\n", p, expr));
        assert_eq!((l.as_str(), v.as_str()), ("x", want), "{}", expr);
    }
}

#[test]
fn an_invariant_on_an_array_is_an_error() {
    assert_eq!(with_a("invariant \"positive\": a > 0\nprint(1)"), not_a_condition());
    assert_eq!(with_a("invariant \"positive\": every(a > 0)\nprint(1)"), "1");
}

/// R4 con un array privado: también es un error bajo etiquetas. El error depende de un dato privado,
/// así que sale redactado (T5): `private(x)`, nunca un `when` que pasa en silencio.
#[test]
fn a_private_mask_is_not_a_condition_either() {
    use synsema_core::interpreter::Interpreter;
    let src = "let p be private(array([1, 5]), \"x\")\nwhen p > 2\n    print(1)\n";
    let program = synsema_core::parser::parse_source(src, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_labels_detail_to_program(true);
    match interp.execute(&program) {
        Err(Control::Error(e)) => assert_eq!(e.message, "private(x)"),
        Ok(_) => panic!("una máscara privada pasó como condición"),
        Err(_) => panic!("otro control"),
    }
}
