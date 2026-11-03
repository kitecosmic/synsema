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
