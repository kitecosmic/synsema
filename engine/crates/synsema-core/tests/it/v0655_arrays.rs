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

// =========================================================
// Ítem 9 — `each` sobre un array (diseño §3.2)
// =========================================================

#[test]
fn each_walks_the_first_axis_of_an_array() {
    assert_eq!(with_a("each x in a\n    print(x)"), "1.0\n5.0\n2.0\n8.0");
    assert_eq!(with_a("each b in m\n    print(b)"), "false\ntrue\nfalse\ntrue");
    assert_eq!(both("each r in array([[1, 2], [3, 4]])\n    print(r)"), "[1, 2]\n[3, 4]");
    // Lo mismo que `enumerate(a)` da como `item`.
    assert_eq!(
        both("let M be array([[1, 2], [3, 4]])\nlet n be 0\neach e in enumerate(M)\n    each r in M\n        when r == e.item\n            set n to n + 1\nprint(n)"),
        "2"
    );
    assert_eq!(both("each x in array([])\n    print(x)\nprint(\"fin\")"), "fin");
    assert_eq!(
        both("each x in array(5)\n    print(x)"),
        "ERR: each over a 0-d array: it is a scalar and has no rows — use the value itself"
    );
}

/// Un array privado se recorre como una lista privada (R6): cada elemento sale con la etiqueta y
/// una rama sobre él corta igual.
#[test]
fn each_over_a_private_array_behaves_like_a_private_list() {
    fn outcome(coll: &str, body: &str) -> String {
        use synsema_core::interpreter::{env_get, Interpreter};
        use synsema_core::labels::{label_deep, label_display_raw, strip_deep};
        let src = format!("let p be private({}, \"x\")\nlet n be 0\nlet out be []\neach x in p\n{}\n", coll, body);
        let program = synsema_core::parser::parse_source(&src, "<v0655>").unwrap();
        let mut interp = Interpreter::new();
        interp.set_labels(true);
        interp.set_labels_detail_to_program(true);
        match interp.execute(&program) {
            Ok(_) => {
                let v = env_get(&interp.global_env, "out").expect("sin out");
                format!("ok {} {}", label_display_raw(&label_deep(&v)), strip_deep(&v))
            }
            Err(Control::Error(e)) => e.message.clone(),
            Err(_) => "otro control".to_string(),
        }
    }
    for body in [
        "    when x > 2\n        set n to n + 1",
        "    set out to append(out, x * 2)",
    ] {
        let list = outcome("[1.0, 5.0, 2.0, 8.0]", body);
        assert_eq!(outcome("array([1, 5, 2, 8])", body), list, "{}", body);
    }
}

// =========================================================
// Ítem 5 — funciones numéricas sobre arrays (diseño §3.4)
// Valores de `specs/v0.6.55-numpy/item5.py` (numpy 2.2.1 y `math` de Python).
// =========================================================

/// `true` si `expr` (un array) está a menos de 1e-12 de `want` en cada elemento.
fn close(expr: &str, want: &str) -> String {
    both(&format!("let got be {}\nprint(shape(got) == shape(array({w})) and every(abs(got - array({w})) < 1e-12))", expr, w = want))
}

#[test]
fn unary_numeric_functions_work_elementwise() {
    assert_eq!(both("print(sign(array([-2, 0, 3, nan])))"), "[-1, 0, 1, nan]");
    let g = "array([0.5, 1, 4.5])";
    assert_eq!(close(&format!("gamma({})", g), "[1.7724538509055159, 1.0, 11.631728396567446]"), "true");
    assert_eq!(close(&format!("lgamma({})", g), "[0.5723649429247004, 0.0, 2.453736570842443]"), "true");
    assert_eq!(close(&format!("erf({})", g), "[0.5204998778130465, 0.8427007929497149, 0.9999999998033839]"), "true");
    assert_eq!(close(&format!("erfc({})", g), "[0.4795001221869534, 0.1572992070502851, 1.9661604415428876e-10]"), "true");
    // Una máscara entra como 0/1 (R2).
    assert_eq!(with_a("print(gamma(m + 2.0))"), "[1, 2, 1, 2]");
}

#[test]
fn predicates_over_an_array_give_masks() {
    let v = "array([1, nan, exp(1000)])";
    assert_eq!(both(&format!("print(is_nan({v}))\nprint(is_finite({v}))")), "[false, true, false]\n[true, false, false]");
    assert_eq!(both("print(is_infinite(array([1, nan, -exp(1000)])))"), "[false, false, true]");
}

#[test]
fn binary_numeric_functions_broadcast() {
    assert_eq!(with_a("print(pow(a, 2))\nprint(pow(2, a))"), "[1, 25, 4, 64]\n[2, 32, 4, 256]");
    let b = "array([3, 3, 9, 1])";
    assert_eq!(
        close(&format!("atan2(array([1, 5, 2, 8]), {b})"), "[0.3217505543966422, 1.0303768265243125, 0.21866894587394195, 1.446441332248135]"),
        "true"
    );
    assert_eq!(
        close(&format!("hypot(array([1, 5, 2, 8]), {b})"), "[3.1622776601683795, 5.830951894845301, 9.219544457292887, 8.06225774829855]"),
        "true"
    );
    assert_eq!(close("log_base(array([1, 5, 2, 8]), 2)", "[0.0, 2.321928094887362, 1.0, 3.0]"), "true");
    assert_eq!(close("beta(array([1, 0.5]), array([2, 0.5]))", "[0.5000000000000002, 3.1415926535897953]"), "true");
    assert_eq!(both("print(pow(array([[1], [2]]), array([1, 2])))"), "[[1, 1], [2, 4]]");
    assert_eq!(with_a("print(pow(a, [1, 2]))"), "ERR: pow: make the list an array first: array(xs)");
    assert_eq!(with_a("print(hypot(a, array([1, 2])))"), "ERR: hypot: arrays of shape [4] and [2] are not broadcastable");
}

#[test]
fn round_to_over_an_array() {
    assert_eq!(both("print(round_to(array([2.675, 1.005, -0.125, 3.14159]), 2))"), "[2.67, 1, -0.12, 3.14]");
    assert_eq!(
        with_a("print(round_to(a, array([1])))"),
        "ERR: round_to expects a number, got array"
    );
    assert_eq!(
        with_a("print(round_to(a, -1))"),
        "ERR: round_to expects a non-negative integer number of decimals"
    );
}

/// Los que cerraron la lista del test de abajo: enteros y complejos sobre arrays.
#[test]
fn integer_and_complex_functions_over_arrays() {
    let (x, y) = ("array([12, 18, 0, -4])", "array([8, 27, 5, 6])");
    assert_eq!(both(&format!("print(gcd({x}, {y}))
print(lcm({x}, {y}))")), "[4, 9, 5, 2]
[24, 54, 0, 12]");
    assert_eq!(both(&format!("print(gcd({x}, 6))")), "[6, 6, 6, 2]");
    // numpy: `lcm(0, 0)` = 0 (no 0/0).
    assert_eq!(both("print(lcm(array([0, 3]), 0))"), "[0, 0]");
    assert_eq!(both("print(gcd(array([2.5]), 5))"), "ERR: gcd expects whole numbers, the array has 2.5");
    assert_eq!(both("print(lcm(array([1, nan]), 5))"), "ERR: lcm expects whole numbers, the array has NaN");
    assert_eq!(both("print(factorial(array([0, 1, 5, 20, 171])))"), "[1, 1, 120, 2.43290200817664e+18, inf]");
    assert_eq!(both("print(factorial(array([3, -1])))"), "ERR: factorial expects a non-negative integer");
    let z = "array([-1, 0, 2, nan])";
    assert_eq!(
        both(&format!("print(real({z}))
print(imag({z}))
print(conj({z}))")),
        "[-1, 0, 2, nan]
[0, 0, 0, 0]
[-1, 0, 2, nan]"
    );
    assert_eq!(close(&format!("arg(array([-1, 0, 2]))"), "[3.141592653589793, 0.0, 0.0]"), "true");
    assert_eq!(both(&format!("print(is_nan(arg({z})))")), "[false, false, false, true]");
    assert_eq!(
        both("print(complex(array([1]), 2))"),
        "ERR: complex: arrays hold f64 or bool, not complex numbers — keep the real and imaginary parts as two arrays"
    );
}

/// El cierre de la lista (diseño §3.4): ningún builtin numérico de `math.rs` responde
/// `expects a number` a un array. Recorre los builtins registrados que llaman a `crate::math::`.
#[test]
fn no_numeric_builtin_rejects_an_array() {
    let src = include_str!("../../src/interpreter.rs");
    let mut names: Vec<(String, usize)> = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        if !line.starts_with("self.register(\"") || !line.contains("crate::math::") {
            continue;
        }
        let name = line["self.register(\"".len()..].split('"').next().unwrap().to_string();
        let arity: i64 = line.split(", ").nth(1).and_then(|n| n.trim().parse().ok()).unwrap_or(1);
        names.push((name, arity.max(1) as usize));
    }
    assert!(names.len() > 40, "se esperaban los builtins de math.rs, hubo {}", names.len());
    let mut bad = Vec::new();
    for (name, n) in &names {
        // `round_to`: los decimales son un número, no un array (diseño §3.4).
        let args = if name == "round_to" {
            "array([0.5, 2]), 1".to_string()
        } else {
            vec!["array([0.5, 2])"; *n].join(", ")
        };
        let out = both(&format!("print({}({}))", name, args));
        if out.contains("expects a number") {
            bad.push(format!("{}: {}", name, out));
        }
    }
    assert!(bad.is_empty(), "no aceptan arrays:\n{}", bad.join("\n"));
}

// =========================================================
// Ítem 6 — `random_normal`/`random_uniform` con forma (diseño §3.5)
// Valores de `specs/v0.6.55-numpy/item6.py` (numpy 2.2.1, `default_rng`). `==` compara bit a bit.
// =========================================================

#[test]
fn random_with_a_shape_repeats_numpy() {
    let src = "let g be rng(42)\n\
        let n be random_normal(g, [2, 3], mean = 1, std = 2)\n\
        let u be random_uniform(g, [2, 2], low = -1, high = 3)\n\
        print(shape(n))\n\
        print(n == array([[1.6094341595088628, -1.079968212480991, 2.5009023916129145], [2.8811294327824277, -2.902070377307673, -1.6043590137246362]]))\n\
        print(u == array([[2.044558807961412, 2.1442572211078152], [-0.4875454692978165, 0.8015437515822685]]))\n\
        print(g() == 0.37079802423258124)\n";
    assert_eq!(both(src), "[2, 3]\ntrue\ntrue\ntrue");
    let src = "let g be rng(7)\n\
        print(random_normal(g, 4) == array([0.0012301533574825742, 0.2987455375084699, -0.2741378553622176, -0.8905918387572742]))\n\
        print(random_uniform(g) == 0.30016628491122543)\n";
    assert_eq!(both(src), "true\ntrue");
    // Sin forma, el número de siempre; `random_uniform(g)` es `g()`.
    assert_eq!(both("print(random_uniform(rng(1)) == rng(1)())\nprint(is_array(random_normal(rng(1))))"), "true\nfalse");
    assert_eq!(both("print(shape(random_uniform(rng(1), [0, 3])))"), "[0, 3]");
}

/// Un generador que no es de `rng()` (Box–Muller): con forma, las mismas muestras y en el mismo
/// orden que llamada por llamada.
#[test]
fn random_with_a_shape_from_any_generator() {
    let src = "let g1 be rng(3)\nlet g2 be rng(3)\n\
        let h1 be () => g1()\nlet h2 be () => g2()\n\
        let a be random_normal(h1, [3], std = 2)\n\
        let b be [random_normal(h2, std = 2), random_normal(h2, std = 2), random_normal(h2, std = 2)]\n\
        print(a == array(b))\n\
        print(random_uniform(h1, [2], low = 5, high = 6) == array([5 + g2(), 5 + g2()]))\n";
    assert_eq!(both(src), "true\ntrue");
}

#[test]
fn random_with_a_shape_errors() {
    assert_eq!(both("print(random_normal(rng(1), [2], std = -1))"), "ERR: random_normal: std must be ≥ 0, got -1");
    assert_eq!(both("print(random_uniform(rng(1), [2], low = \"a\"))"), "ERR: random_uniform: low must be a number, got text");
    assert_eq!(
        both("print(random_uniform(rng(1), [2], low = 0, high = inf))"),
        "ERR: random_uniform: high - low must be finite, got low = 0 and high = inf"
    );
    assert_eq!(both("print(random_normal(rng(1), \"x\"))"), "ERR: random_normal: shape must be an int or a list of ints, got text");
    assert_eq!(both("print(random_uniform(rng(1), [-1]))"), "ERR: random_uniform: dimensions must be non-negative");
}

// =========================================================
// Ítems 2 y 3 — indexar con posiciones y escribir (diseño §3.3, R5)
// Valores de `specs/v0.6.55-numpy/item23.py`.
// =========================================================

const M: &str = "let M be array([[1, 2], [3, 4]])\n";

#[test]
fn an_index_list_takes_rows_in_order() {
    let t = |rest: &str| with_a(&format!("{}{}", M, rest));
    assert_eq!(t("print(M[[1, 0]])\nprint(a[[0, 0, 3]])\nprint(a[array([0, 3])])"), "[[3, 4], [1, 2]]\n[1, 1, 8]\n[1, 8]");
    assert_eq!(t("print(a[[-1]])\nprint(m[[1, 3]])\nprint(shape(M[[]]))"), "[8]\n[true, true]\n[0, 2]");
    assert_eq!(t("print(a[[0, 9]])"), "ERR: Index 9 out of bounds (array axis 0 has length 4)");
    assert_eq!(t("print(a[m])"), "ERR: an array is indexed by positions — for the elements where a mask is true: where(a, m)");
    assert_eq!(t("print(a[array([1.5])])"), "ERR: an array index must hold whole numbers, got 1.5 — round first");
    assert_eq!(t("print(a[[\"x\"]])"), "ERR: an index must be an integer, got text");
    assert_eq!(t("print(a[[0.5]])"), "ERR: index must be an integer, got 0.5 — use floor(x), round(x) or trunc(x) on purpose");
    // Un número sigue como siempre.
    assert_eq!(t("print(M[1])\nprint(a[-1])"), "[3, 4]\n8.0");
}

#[test]
fn set_writes_into_an_array() {
    let t = |rest: &str| with_a(&format!("{}{}", M, rest));
    assert_eq!(t("set a[1] to 9\nprint(a)"), "[1, 9, 2, 8]");
    assert_eq!(t("set a[-1] to 0\nprint(a)"), "[1, 5, 2, 0]");
    assert_eq!(t("set M[0] to array([7, 7])\nprint(M)"), "[[7, 7], [3, 4]]");
    assert_eq!(t("set M[0] to 0\nprint(M)"), "[[0, 0], [3, 4]]");
    assert_eq!(t("set M[0][1] to 9\nprint(M)"), "[[1, 9], [3, 4]]");
    assert_eq!(t("set M[-1][-2] to 9\nprint(M)"), "[[1, 2], [9, 4]]");
    assert_eq!(t("set a[[0, 2]] to array([4, 4])\nprint(a)"), "[4, 5, 4, 8]");
    assert_eq!(t("set a[[0, 2]] to 4\nprint(a)"), "[4, 5, 4, 8]");
    // Un índice repetido: gana el último (numpy).
    assert_eq!(t("set a[[0, 0]] to array([1, 2])\nprint(a)"), "[2, 5, 2, 8]");
    assert_eq!(t("set M[[1, 0]] to array([[5, 6], [7, 8]])\nprint(M)"), "[[7, 8], [5, 6]]");
    assert_eq!(t("set m[0] to true\nprint(m)"), "[true, true, false, true]");
    assert_eq!(
        both("let T be reshape(arange(0, 24), [2, 3, 4])\nset T[1][2][3] to -1\nprint(T[1])\nprint(T[0][0])"),
        "[[12, 13, 14, 15], [16, 17, 18, 19], [20, 21, 22, -1]]\n[0, 1, 2, 3]"
    );
    // En un bucle, con el índice de una variable.
    assert_eq!(both("let z be zeros(5)\nlet i be 0\nwhile i < 5\n    set z[i] to i * i\n    set i to i + 1\nprint(z)"), "[0, 1, 4, 9, 16]");
    // El valor de un `set` dentro de una lista o un mapa.
    assert_eq!(both("let xs be [array([1, 2]), array([3, 4])]\nset xs[1][0] to 9\nprint(xs)"), "[[1, 2], [9, 4]]");
    assert_eq!(both("let p be {\"w\": array([[1, 2], [3, 4]])}\nset p[\"w\"][1][1] to 0\nset p.w[0] to 5\nprint(p.w)"), "[[5, 5], [3, 0]]");
}

#[test]
fn set_errors_name_the_rule() {
    let t = |rest: &str| with_a(&format!("{}{}", M, rest));
    assert_eq!(t("set M[0] to array([1, 2, 3])"), "ERR: set M[0]: the row has shape [2], got [3]");
    assert_eq!(t("set a[0] to array([1, 2])"), "ERR: set a[0]: the element is a number, got [2]");
    assert_eq!(t("set a[[0, 1]] to array([1, 2, 3])"), "ERR: set a[[0, 1]]: the positions have shape [2], got [3]");
    assert_eq!(t("set m[0] to 1"), "ERR: a mask holds true or false, got 1");
    assert_eq!(t("set m[0] to array([1, 2])"), "ERR: a mask holds true or false, got an f64 array");
    assert_eq!(t("set a[0] to true"), "ERR: an f64 array holds numbers, got bool — use 1.0");
    assert_eq!(t("set M[0] to array([1, 0]) > 0"), "ERR: an f64 array holds numbers, got a mask — use m * 1.0");
    assert_eq!(t("set a[0] to \"x\""), "ERR: an f64 array holds numbers, got text");
    assert_eq!(t("set a[m] to 0"), "ERR: set takes positions, not a mask — if_else(m, 0, a) builds the new array");
    assert_eq!(t("set a[9] to 1"), "ERR: Index 9 out of bounds (array axis 0 has length 4)");
    assert_eq!(t("set M[0] to [1, 2]"), "ERR: set: make the list an array first: array(xs)");
    assert_eq!(
        t("set M[[0, 1]][0] to 1"),
        "ERR: set: a list of positions only goes in the last index — set M[[0, 2]] to rows, or M[i][j] one by one"
    );
    assert_eq!(t("set a[0][0] to 1"), "ERR: Cannot set index on number");
    // Un error no deja nada escrito ni afecta al siguiente `set`.
    assert_eq!(t("let r be 0\nset M[0][\"x\"] to 1\nprint(M)"), "ERR: an index must be an integer, got text");
}

/// R5: escribir en un array no cambia a nadie más (un alias, el argumento de una task, el array
/// que recorre un `each`).
#[test]
fn set_has_value_semantics() {
    assert_eq!(with_a("let b be a\nset a[0] to 9\nprint(a)\nprint(b)"), "[9, 5, 2, 8]\n[1, 5, 2, 8]");
    assert_eq!(with_a("let b be a\nset b[0] to 9\nprint(a)\nprint(b)"), "[1, 5, 2, 8]\n[9, 5, 2, 8]");
    assert_eq!(
        with_a("task zero(c)\n    set c[0] to 0\n    give c\nlet z be zero(a)\nprint(a)\nprint(z)"),
        "[1, 5, 2, 8]\n[0, 5, 2, 8]"
    );
    assert_eq!(both(&format!("{}let R be M[0]\nset M[0][0] to 9\nprint(R)\nprint(M)", M)), "[1, 2]\n[[9, 2], [3, 4]]");
    assert_eq!(both(&format!("{}let R be M\nset M[0][0] to 9\nprint(R)", M)), "[[1, 2], [3, 4]]");
    assert_eq!(
        with_a("let seen be []\neach x in a\n    set a[0] to 100\n    set seen to append(seen, x)\nprint(seen)\nprint(a)"),
        "[1.0, 5.0, 2.0, 8.0]\n[100, 5, 2, 8]"
    );
    assert_eq!(
        both("let xs be [array([1, 2])]\nlet ys be xs\nset xs[0][0] to 9\nprint(xs)\nprint(ys)"),
        "[[9, 2]]\n[[1, 2]]"
    );
}

/// R5 y §5: sin otro dueño, `set a[i]` escribe en el mismo array (no lo copia en cada vuelta).
#[test]
fn set_writes_in_place_when_nobody_shares() {
    use synsema_core::interpreter::{env_get, Interpreter};
    for labels in [false, true] {
        let mut interp = Interpreter::new();
        interp.set_labels(labels);
        let run = |interp: &mut Interpreter, src: &str| {
            let program = synsema_core::parser::parse_source(src, "<v0655>").unwrap();
            if let Err(Control::Error(e)) = interp.execute(&program) {
                panic!("{}", e);
            }
        };
        let ptr = |interp: &Interpreter| match env_get(&interp.global_env, "z") {
            Some(synsema_core::types::SynValue::Array(o)) => synsema_core::types::Obj::as_ptr(&o) as usize,
            other => panic!("{:?}", other.map(|v| v.to_string())),
        };
        run(&mut interp, "let z be zeros([300, 4])\n");
        let before = ptr(&interp);
        run(&mut interp, "let i be 0\nwhile i < 300\n    set z[i] to i\n    set z[i][1] to -1\n    set i to i + 1\n");
        assert_eq!(ptr(&interp), before, "labels = {}", labels);
        run(&mut interp, "let w be z\nset z[0][0] to 7\n");
        assert_ne!(ptr(&interp), before, "con un alias se copia (labels = {})", labels);
    }
}

// =========================================================
// Auditoría v0.6.55, ronda 1
// =========================================================

/// N2: `set T[i][j][k]` escribe el elemento en `T`, sin copiar la fila (antes, una losa de 8 MB por
/// escritura: 3000 escrituras tardaban decenas de segundos en debug).
#[test]
fn set_of_an_element_does_not_copy_its_row() {
    let src = "let T be zeros([2, 1000, 1000])\nlet i be 0\nwhile i < 3000\n    set T[i % 2][i % 1000][7] to i\n    set i to i + 1\nprint(T[1][999][7])\nprint(sum(T))";
    let t0 = std::time::Instant::now();
    assert_eq!(both(src), "2999.0\n2499500.0");
    let took = t0.elapsed();
    assert!(took < std::time::Duration::from_secs(10), "tardó {:?}: ¿se copia la fila?", took);
}

/// N4 (p6_stale): un `set` de fila que falló a mitad de camino no afecta a los siguientes, ni a un
/// alias tomado después; un `set` de otro array dentro de un índice no le borra el camino al de
/// afuera, y uno del mismo array sí lo corta.
#[test]
fn a_failed_row_set_leaves_the_next_ones_alone() {
    let src = format!(
        "{}try\n    set M[0][nope] to 1\nrecover e\n    print(\"err\")\nset M[1][1] to 40\nlet K be M\nset M[0][0] to 5\nprint(M)\nprint(K)",
        M
    );
    assert_eq!(both(&src), "err\n[[5, 2], [3, 40]]\n[[1, 2], [3, 40]]");
    let other = "let M be zeros([2, 2])\nlet z be zeros(3)\ntask f()\n    set z[1] to 7\n    give 1\nset M[0][f()] to 9\nprint(M)\nprint(z)";
    assert_eq!(both(other), "[[0, 9], [0, 0]]\n[0, 7, 0]");
    let same = "let M be zeros([2, 2])\ntask f()\n    set M[1][0] to 7\n    give 1\nset M[0][f()] to 9";
    assert_eq!(both(same), REBOUND_M);
}

/// §3.2: `match` compara el valor entero, como `in` (sin cambio).
#[test]
fn match_compares_whole_arrays() {
    assert_eq!(
        both("let a be array([1, 2])\nlet b be array([1, 2])\nmatch a\n    is b\n        print(\"same\")\n    otherwise\n        print(\"other\")"),
        "same"
    );
    assert_eq!(
        both("let a be array([1, 2])\nlet b be array([1, 3])\nmatch a\n    is b\n        print(\"same\")\n    otherwise\n        print(\"other\")"),
        "other"
    );
}

/// Corre con etiquetas y devuelve cada variable sin etiquetas.
fn labelled_vars(source: &str, names: &[&str]) -> Vec<String> {
    use synsema_core::interpreter::{env_get, Interpreter};
    let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    if let Err(Control::Error(e)) = interp.execute(&program) {
        panic!("el programa falló: {}\nfuente:\n{}", e, source);
    }
    names
        .iter()
        .map(|n| synsema_core::labels::strip_deep(&env_get(&interp.global_env, n).expect("sin la variable")).to_string())
        .collect()
}

/// N4 (A-private-inner): un valor privado que comparte su array con otro lo copia antes de escribir.
#[test]
fn writing_a_private_copy_leaves_the_original() {
    // Lo que se prueba: el brazo `Private` de `make_unique_n` mira la cuenta del ARRAY de adentro.
    // `private(b)` envuelve el mismo array de `b`, así que el envoltorio tiene un dueño (`p`) y el
    // array dos (`b` y el envoltorio): sólo esa cuenta obliga a copiar. El `let k` en el medio hace
    // falta porque el valor de la sentencia anterior (el envoltorio que dio `let p`) vive hasta que
    // termina la siguiente: sin él el envoltorio tendría dos dueños y se copiaría por esa cuenta, sin
    // pasar por la del array.
    assert_eq!(
        labelled_vars("let b be array([1, 2])\nlet p be private(b, \"x\")\nlet k be 0\nset p[0] to 9\n", &["b", "p"]),
        ["[1, 2]", "[9, 2]"]
    );
    assert_eq!(
        labelled_vars("let B be array([[1, 2], [3, 4]])\nlet P be private(B, \"x\")\nlet k be 0\nset P[1][0] to 9\n", &["B", "P"]),
        ["[[1, 2], [3, 4]]", "[[1, 2], [9, 4]]"]
    );
    // Lo que se lee de un contenedor privado, `L[0]`, también es otro envoltorio sobre el mismo array.
    assert_eq!(
        labelled_vars("let L be private([array([1, 2])], \"x\")\nlet p be L[0]\nlet k be 0\nset p[0] to 9\nlet r be L[0]\n", &["p", "r"]),
        ["[9, 2]", "[1, 2]"]
    );
}

/// Corre en la VM y en el árbol y devuelve `línea:columna: mensaje` del error (los dos iguales).
fn both_at(source: &str) -> String {
    fn one(source: &str, labels: bool) -> String {
        use synsema_core::interpreter::Interpreter;
        let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
        let mut interp = Interpreter::new();
        interp.set_labels(labels);
        match interp.execute(&program) {
            Err(Control::Error(e)) => match &e.location {
                Some(l) => format!("{}:{}: {}", l.line, l.column, e.message),
                None => format!("sin ubicación: {}", e.message),
            },
            _ => "sin error".to_string(),
        }
    }
    let (vm, tree) = (one(source, false), one(source, true));
    assert_eq!(vm, tree, "la VM y el árbol no coinciden en:\n{}", source);
    vm
}

/// N1: los errores de R1, R3, R4 y R5 dicen la línea (el de orden de v0.6.54 la decía).
#[test]
fn array_errors_say_the_line() {
    let at = |rest: &str| both_at(&format!("{}let n be 0\n{}", A, rest));
    let starts = |rest: &str, want: &str| {
        let got = at(rest);
        assert!(got.starts_with(want), "{}\n  dio: {}\n  esperaba: {}…", rest, got, want);
    };
    assert_eq!(at("when a\n    print(1)"), format!("4:1: {}", NOT_A_CONDITION));
    assert_eq!(at("print(when m then 1 otherwise 0)"), format!("4:7: {}", NOT_A_CONDITION));
    assert_eq!(at("while m\n    stop"), format!("4:1: {}", NOT_A_CONDITION));
    starts("print(a == 3)", "4:9: == compares whole values");
    starts("print(m > m)", "4:9: masks are not ordered");
    starts("print(a > [1, 2, 3, 4])", "4:9: cannot compare an array with a list");
    starts("print(not m)", "4:7: not needs true or false");
    starts("print(m and true)", "4:9: and needs true or false");
    starts("print(1 < a < 9)", "4:9: and needs true or false");
    starts("print(where([1, 2], (x) => a))", "4:12: where: the function returned an array");
    starts("assert(m)", "4:7: an array is not true or false");
    starts("set a[0] to true", "4:6: an f64 array holds numbers");
    starts("print(a + array([1, 2]))", "4:9: arrays of shape [4] and [2] are not broadcastable");
    starts("print(a[[0, 9]])", "4:8: Index 9 out of bounds");
    starts("each x in array(5)\n    print(x)", "4:1: each over a 0-d array");
    starts("print(-m)", "4:7: Cannot negate a mask");
}

fn module_dir(tag: &str, lib: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("synsema-v0655-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("lib.syn"), lib).unwrap();
    d
}

/// B1: un array exportado por un módulo se escribe desde sus tasks y desde afuera, en el lugar (la
/// vista del mapa del módulo no cuenta como otro dueño), y una foto tomada antes no cambia.
#[test]
fn an_exported_array_is_written_in_place() {
    use synsema_core::interpreter::{env_get, Interpreter};
    let lib = "export let STATE be zeros(3000)\nexport let G be zeros([3, 3])\n\
        export task bump(n)\n    let i be 0\n    while i < n\n        set STATE[i] to STATE[i] + i\n        set i to i + 1\n    give STATE[n - 1]\n\
        export task show()\n    give STATE[1]\n\
        export task put(i, j, v)\n    set G[i][j] to v\n    give G\n\
        export task fail(n)\n    let Q be zeros([2, 2])\n    let k be 0\n    while k < n\n        try\n            set Q[0][nope] to 1\n        recover e\n            set k to k + 1\n    give 1\n";
    for labels in [false, true] {
        let d = module_dir(&format!("export-{}", labels), lib);
        let main = d.join("main.syn").to_string_lossy().to_string();
        let mut interp = Interpreter::new();
        interp.set_labels(labels);
        let run = |interp: &mut Interpreter, src: &str| {
            let program = synsema_core::parser::parse_source(src, &main).unwrap();
            interp.output.clear();
            if let Err(Control::Error(e)) = interp.execute(&program) {
                panic!("labels = {}: {}", labels, e);
            }
            interp.output.join("\n")
        };
        let ptr = |interp: &Interpreter| match env_get(&interp.global_env, "m") {
            Some(SynValue::Map(m)) => match m.borrow().get("STATE") {
                Some(SynValue::Array(o)) => synsema_core::types::Obj::as_ptr(&o) as usize,
                other => panic!("{:?}", other.map(|v| v.type_name())),
            },
            other => panic!("{:?}", other.map(|v| v.type_name())),
        };
        assert_eq!(run(&mut interp, "use \"./lib.syn\" as m\nprint(m.bump(3000))"), "2999.0");
        let before = ptr(&interp);
        assert_eq!(run(&mut interp, "print(m.bump(3000))"), "5998.0");
        assert_eq!(ptr(&interp), before, "una task que escribe su array exportado no lo copia (labels = {})", labels);
        assert_eq!(run(&mut interp, "set m.STATE[1] to 70\nprint(m.show())"), "70.0");
        assert_eq!(ptr(&interp), before, "desde afuera, tampoco (labels = {})", labels);
        assert_eq!(
            run(&mut interp, "let snap be m.STATE\nset m.STATE[1] to 71\nprint(snap[1])\nprint(m.show())\nprint(m.STATE[1])"),
            "70.0\n71.0\n71.0"
        );
        assert_eq!(
            run(&mut interp, "print(m.put(1, 2, 5))\nset m.G[0][0] to 4\nprint(m.G)"),
            "[[0, 0, 0], [0, 0, 5], [0, 0, 0]]\n[[4, 0, 0], [0, 0, 5], [0, 0, 0]]"
        );
        // La vista del módulo sigue viva aunque el índice llene el tope de entradas (M17 de la ronda 3).
        // Con `--labels`, un índice que corre código por el mapa del módulo es un error (B3).
        let deep = run_result(&mut interp, &main, "set m.G[2][m.fail(70)] to 6\nprint(m.G[2])");
        if labels {
            assert!(deep.contains("an index that runs code writes into an array inside a list or map"), "{}", deep);
        } else {
            assert_eq!(deep, "[0, 6, 0]");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// M7: `each` sobre un array toma una foto del array, no de sus elementos: la vuelta lee el que le
/// toca, y un `set` del cuerpo no lo cambia.
#[test]
fn each_over_an_array_reads_as_it_goes() {
    assert_eq!(
        both("let M be array([[1, 2], [3, 4]])\neach r in M\n    set M[1][0] to 9\n    print(r)\nprint(M)"),
        "[1, 2]\n[3, 4]\n[[1, 2], [9, 4]]"
    );
    assert_eq!(both("let n be 0\neach x in zeros(100000) > -1\n    when x\n        set n to n + 1\nprint(n)"), "100000");
    assert_eq!(both("each x in array([])\n    print(x)\nprint(\"done\")"), "done");
}

// =========================================================
// Auditoría v0.6.55, ronda 2
// =========================================================

const REBOUND_A: &str = "ERR: set: the index changed 'a' while it was being written (it now holds another value) — compute the index into a variable first";
const REBOUND_M: &str = "ERR: set: the index changed 'M' while it was being written (it now holds another value) — compute the index into a variable first";

/// Corre con etiquetas y devuelve lo impreso, o `ERR: <mensaje>`.
fn labelled_out(source: &str) -> String {
    use synsema_core::interpreter::Interpreter;
    let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    match interp.execute(&program) {
        Ok(_) => interp.output.join("\n"),
        // El programa ve un texto fijo; el diagnóstico va al operador.
        Err(Control::Error(e)) => format!("ERR: {}", e.operator_detail.clone().unwrap_or_else(|| e.message.clone())),
        Err(_) => "otro control".to_string(),
    }
}

/// B2: un índice que religa la variable y deja el array viejo en otra no hace caer la escritura en
/// ese alias: con `--labels` era un secreto en un array público sin `declassify`. Sin etiquetas, el
/// alias tampoco cambia (M1 para arrays). La VM y el árbol dan lo mismo.
#[test]
fn an_index_that_rebinds_the_array_stops_the_write() {
    let leak = "let a be private(array([1, 2, 3]), \"x\")\nlet secret be private(42, \"x\")\nlet keep be nothing\n\
        task f()\n    set keep to declassify(a, \"x\")\n    set a to private(zeros(3), \"x\")\n    give 0\n\
        try\n    set a[f()] to secret\nrecover e\n    print(e)\nprint(keep)\nprint(label_of(keep))";
    // Con etiquetas es un diagnóstico del sistema (M16 de la ronda 3): no se atrapa, el programa ve el
    // texto fijo de corte y el operador el motivo, que sólo nombra la variable. La corrida se corta en
    // el `set`, sin que el secreto llegue a `keep`.
    assert_eq!(labelled_out(leak), format!("ERR: <v0655>:9:10: {}", &REBOUND_A[5..]));
    let plain = "let a be array([1, 2, 3])\nlet keep be nothing\ntask f()\n    set keep to a\n    set a to zeros(3)\n    give 0\n";
    assert_eq!(both(&format!("{}set a[f()] to 42", plain)), REBOUND_A);
    assert_eq!(both(&format!("{}try\n    set a[f()] to 42\nrecover e\n    print(\"err\")\nprint(keep)\nprint(a)", plain)), "err\n[1, 2, 3]\n[0, 0, 0]");
    // Por una fila: la raíz de la cadena es el array viejo de `M`.
    let row = "let M be zeros([2, 2])\nlet keep be nothing\ntask f()\n    set keep to M\n    set M to zeros([2, 2])\n    give 1\nset M[0][f()] to 9";
    assert_eq!(both(row), REBOUND_M);
    // Un parámetro de una task (la raíz en un registro de la VM).
    assert_eq!(
        both("let keep be nothing\ntask g(c)\n    task f()\n        set c to zeros(2)\n        give 0\n    set c[f()] to 5\n    give c\nprint(g(array([1, 2])))"),
        "ERR: set: the index changed 'c' while it was being written (it now holds another value) — compute the index into a variable first"
    );
    // Lo que no religa sigue escribiendo.
    assert_eq!(both("let a be array([1, 2, 3])\nlet n be 0\ntask f()\n    set n to n + 1\n    give n\nset a[f()] to 9\nprint(a)"), "[1, 9, 3]");
}

const THROUGH_A_LIST: &str = "label_violation: an index that runs code writes into an array inside a list or map — compute the index into a variable first";

/// Sin etiquetas, sólo la VM: lo impreso, o `ERR: <mensaje>`.
fn plain_out(source: &str) -> String {
    use synsema_core::interpreter::Interpreter;
    let program = synsema_core::parser::parse_source(source, "<v0655>").unwrap();
    let mut interp = Interpreter::new();
    match interp.execute(&program) {
        Ok(_) => interp.output.join("\n"),
        Err(Control::Error(e)) => format!("ERR: {}", e.message),
        Err(_) => "otro control".to_string(),
    }
}

/// B2 y B3, a través de una lista o un mapa: la identidad del array no se puede verificar, así que con
/// `--labels` un índice que corre código es un error por la forma del camino, sea privado el valor
/// (B2), el índice (B3: elegiría la posición en el alias público) o un índice del medio. Con índices
/// que no corren código se escribe; sin etiquetas, también.
#[test]
fn with_labels_an_index_that_runs_code_cannot_write_through_a_list() {
    let pre = "let L be private([array([1, 2, 3])], \"x\")\nlet secret be private(42, \"x\")\nlet keep be nothing\n\
        task f()\n    set keep to declassify(L, \"x\")\n    set L to private([zeros(3)], \"x\")\n    give 0\n";
    assert_eq!(labelled_out(&format!("{}set L[0][f()] to secret\nprint(keep)", pre)), format!("ERR: <v0655>:8:9: {}", THROUGH_A_LIST));
    assert_eq!(labelled_out(&format!("{}let i be 1\nset L[0][i] to secret\nprint(declassify(L, \"x\"))", pre)), "[[1, 42, 3]]");
    // B3: el valor es público y el índice, privado (la sonda `lp_idx_try` de la ronda 3).
    let idx = "let secret be private(1, \"x\")\nlet L be private([array([0, 0, 0])], \"x\")\nlet keep be nothing\n\
        task f()\n    set keep to declassify(L, \"x\")[0]\n    set L to private([zeros(3)], \"x\")\n    give secret\n\
        set L[0][f()] to 1\nprint(keep)";
    assert_eq!(labelled_out(idx), format!("ERR: <v0655>:8:9: {}", THROUGH_A_LIST));
    // Por un mapa (`lp_map_idx`) y religando el elemento (`lp_elem_idx`).
    let map = "let m be private({\"x\": array([0, 0, 0])}, \"x\")\nlet keep be nothing\n\
        task f()\n    set keep to declassify(m, \"x\").x\n    set m to private({\"x\": zeros(3)}, \"x\")\n    give private(2, \"x\")\n\
        set m.x[f()] to 1\nprint(keep)";
    assert_eq!(labelled_out(map), format!("ERR: <v0655>:7:8: {}", THROUGH_A_LIST));
    let elem = "let L be private([array([0, 0, 0])], \"x\")\nlet keep be nothing\n\
        task f()\n    set keep to declassify(L[0], \"x\")\n    set L[0] to zeros(3)\n    give private(2, \"x\")\n\
        set L[0][f()] to 1\nprint(keep)";
    assert_eq!(labelled_out(elem), format!("ERR: <v0655>:7:9: {}", THROUGH_A_LIST));
    // Un índice del medio que corre código, y una llamada adentro de una cuenta (`f() + 0`).
    let mid = "let L be [array([1, 2]), array([3, 4])]\ntask f()\n    give 1\n";
    assert_eq!(labelled_out(&format!("{}set L[f()][0] to 9\nprint(L)", mid)), format!("ERR: <v0655>:4:11: {}", THROUGH_A_LIST));
    assert_eq!(labelled_out(&format!("{}set L[0][f() + 0] to 9\nprint(L)", mid)), format!("ERR: <v0655>:4:9: {}", THROUGH_A_LIST));
    // Sin etiquetas, lo mismo escribe; con etiquetas, sin código en los índices, también.
    assert_eq!(plain_out(&format!("{}set L[f()][0] to 9\nset L[0][f() + 0] to 8\nprint(L)", mid)), "[[1, 8], [9, 4]]");
    assert_eq!(labelled_out(&format!("{}let i be f()\nset L[i][0] to 9\nset L[0][i + 0] to 8\nprint(L)", mid)), "[[1, 8], [9, 4]]");
    // Un array directo (sin lista en el medio) no pasa por esta guarda: ahí decide `rebound`.
    assert_eq!(labelled_out("let a be zeros(3)\ntask f()\n    give 1\nset a[f()] to 5\nprint(a)"), "[0, 5, 0]");
}

/// M11: el tope de las entradas descarta sólo las muertas; la de la sentencia en curso sigue.
#[test]
fn many_failed_sets_inside_an_index_leave_the_outer_one_alone() {
    for n in [10, 70, 200] {
        let src = format!(
            "let M be array([[1, 2], [3, 4]])\nlet Q be array([[1, 2], [3, 4]])\ntask g()\n    let k be 0\n    while k < {}\n        try\n            set Q[0][nope] to 1\n        recover e\n            set k to k + 1\n    give 1\nset M[0][g()] to 9\nprint(M)",
            n
        );
        assert_eq!(both(&src), "[[1, 9], [3, 4]]", "{} fallas", n);
    }
    // Tres fichas vivas a la vez (un `set` 4-d): ninguna se descarta.
    assert_eq!(
        both("let Z be zeros([2, 2, 2, 2])\nset Z[1][0][1][0] to 7\nprint(sum(Z))\nprint(Z[1][0][1])"),
        "7.0\n[7, 0]"
    );
}

/// M12: el error de forma de `set T[0][1]` nombra el camino entero.
#[test]
fn a_shape_error_names_the_whole_path() {
    assert_eq!(
        both("let T be zeros([2, 2, 2])\nset T[0][1] to array([9, 9, 9])"),
        "ERR: set T[0][1]: the row has shape [2], got [3]"
    );
    assert_eq!(
        both("let T be zeros([2, 2, 2])\nset T[1][-1][0] to array([1, 2])"),
        "ERR: set T[1][1][0]: the element is a number, got [2]"
    );
    // La hoja también resuelta (M18 de la ronda 3), con una lista de posiciones.
    assert_eq!(
        both("let T be zeros([2, 2, 3])\nset T[-1][0][[0, -1]] to array([1, 2, 3])"),
        "ERR: set T[1][0][[0, 2]]: the positions have shape [2], got [3]"
    );
    assert_eq!(
        both("let T be zeros([2, 2])\nset T[1][-1] to array([1, 2])"),
        "ERR: set T[1][1]: the element is a number, got [2]"
    );
}

/// M13: `-m` es un error, como `-true` (numpy también lo rechaza); un array `f64` se niega.
#[test]
fn negating_a_mask_is_an_error() {
    assert_eq!(with_a("print(-m)"), "ERR: Cannot negate a mask — logical_not(m) flips it; 0 - m gives the 0/-1 floats");
    // La pista da los floats sin `-0` (M19 de la ronda 3).
    assert_eq!(with_a("print(0 - m)\nprint(-a)"), "[0, -1, 0, -1]\n[-1, -5, -2, -8]");
}


// =========================================================
// Auditoría v0.6.55, ronda 3
// =========================================================

/// N5: las cuatro raíces de la VM (un parámetro, una variable local de una task, un local que captura
/// un cierre y el nivel de arriba) escriben con un índice que corre código, igual que el árbol (las
/// sondas `roots` y `roots2` de la ronda 3).
#[test]
fn every_vm_root_writes_through_an_index_that_runs_code() {
    let roots = r#"let top be zeros(3)
set top[abs(1)] to 1
print(top)
task t()
    let loc be zeros([2, 2])
    set loc[1][abs(0)] to 2
    let i be 0
    while i < 2
        let inner be zeros(2)
        set inner[abs(i)] to 3
        set loc[0][i] to 4
        set i to i + 1
    each j in [0, 1]
        let e be zeros(2)
        set e[abs(j)] to 5
        set loc[j][j] to 6
    give loc
print(t())
task p(c)
    set c[abs(0)] to 7
    give c
print(p(zeros(2)))"#;
    assert_eq!(both(roots), "[0, 1, 0]\n[[6, 4], [2, 6]]\n[7, 0]");
    let captured = r#"task t()
    let a be zeros(3)
    let g be () => a
    set a[abs(1)] to 1
    give [a, g()]
print(t())
task u()
    let M be zeros([2, 2])
    task h()
        give M
    set M[1][abs(1)] to 2
    give h()
print(u())"#;
    assert_eq!(both(captured), "[[0, 1, 0], [0, 1, 0]]\n[[0, 0], [0, 2]]");
}

/// M17: con muchas sentencias en curso a la vez (la llamada en el índice, recursiva) el tope no
/// descarta las vivas: crece (la sonda `m11_deep` de la ronda 3).
#[test]
fn deep_recursion_in_the_index_keeps_every_row_alive() {
    let src = "task g(n)\n    when n == 0\n        give 0\n    let A be zeros([2, 2])\n    set A[0][g(n - 1)] to n\n    give 1\n\
        print(g(30))\nprint(g(70))\nprint(g(150))";
    // La recursión de 150 niveles pide más pila que la del hilo de test en debug.
    let got = std::thread::Builder::new().stack_size(64 << 20).spawn(move || both(src)).unwrap().join().unwrap();
    assert_eq!(got, "1\n1\n1");
}

/// Corre en un intérprete ya armado y devuelve lo impreso, o `ERR: <diagnóstico del operador o mensaje>`.
fn run_result(interp: &mut synsema_core::interpreter::Interpreter, file: &str, src: &str) -> String {
    let program = synsema_core::parser::parse_source(src, file).unwrap();
    interp.output.clear();
    match interp.execute(&program) {
        Ok(_) => interp.output.join("\n"),
        Err(Control::Error(e)) => format!("ERR: {}", e.operator_detail.clone().unwrap_or_else(|| e.message.clone())),
        Err(_) => "otro control".to_string(),
    }
}
