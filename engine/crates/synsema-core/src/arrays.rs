//! Arrays numéricos n-dimensionales + álgebra lineal (Batch 5).
//!
//! Tipo `SynValue::Array(Rc<ArrayD<f64>>)` (dtype f64, inmutable). `ndarray` da el modelo
//! n-dimensional + vectorización/broadcasting/reducciones; `faer` (puro-Rust, SIMD) el
//! álgebra lineal densa 2D (matmul/solve/det/inv/eig/svd). **`*` es ELEMENTWISE**; el
//! producto matricial es `matmul`/`dot`.
//!
//! Builtins puros (sin capability). Errores claros, nunca NaN/panic silencioso por shapes
//! incompatibles, no-2D en LA, o matriz singular (G3).

use ndarray::{ArrayD, Axis, IxDyn};

use faer::linalg::matmul::matmul as faer_matmul_into;
use faer::linalg::solvers::{DenseSolveCore, Solve};
use faer::{Accum, Mat, Par};

use indexmap::IndexMap;

use crate::interpreter::{Control, RuntimeError};
use crate::number::Number;
use crate::types::{
    syn_array, syn_bool, syn_complex, syn_float, syn_int, syn_list, syn_map, SynValue,
};

// =========================================================
// Helpers básicos
// =========================================================

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

fn arity(args: &[SynValue], n: usize, name: &str) -> Result<(), Control> {
    if args.len() != n {
        return Err(err(format!("{} expects {} argument(s), got {}", name, n, args.len())));
    }
    Ok(())
}

/// El i-ésimo argumento como número real (f64); error claro si no es número.
fn num_f64(args: &[SynValue], i: usize, name: &str) -> Result<f64, Control> {
    match arg(args, i)? {
        SynValue::Number(n) => Ok(n.to_f64()),
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

/// El i-ésimo argumento como `array`; error si no lo es.
fn array_arg<'a>(args: &'a [SynValue], i: usize, name: &str) -> Result<&'a ArrayD<f64>, Control> {
    match arg(args, i)? {
        SynValue::Array(a) => Ok(a),
        other => Err(err(format!("{} expects an array, got {}", name, other.type_name()))),
    }
}

/// `shape` desde un arg: un entero `n` → `[n]` (1D); una lista de enteros `[2,3]` → nD.
fn shape_from(v: &SynValue, name: &str) -> Result<Vec<usize>, Control> {
    let dim = |n: &Number| -> Result<usize, Control> {
        let i = n.to_i64_trunc().ok_or_else(|| err(format!("{}: dimension too large", name)))?;
        if i < 0 {
            return Err(err(format!("{}: dimensions must be non-negative", name)));
        }
        Ok(i as usize)
    };
    match v {
        SynValue::Number(n) => Ok(vec![dim(n)?]),
        SynValue::List(l) => {
            let mut out = Vec::new();
            for it in l.borrow().iter() {
                match it {
                    SynValue::Number(n) => out.push(dim(n)?),
                    other => {
                        return Err(err(format!(
                            "{}: shape must be ints, got {}",
                            name,
                            other.type_name()
                        )))
                    }
                }
            }
            Ok(out)
        }
        other => Err(err(format!("{}: shape must be an int or a list of ints, got {}", name, other.type_name()))),
    }
}

/// Un array 0-dimensional se devuelve como escalar `Number`; cualquier otro como `array`.
fn nd_result(a: ArrayD<f64>) -> SynValue {
    if a.ndim() == 0 {
        syn_float(*a.first().unwrap())
    } else {
        syn_array(a)
    }
}

// =========================================================
// Construcción
// =========================================================

/// Recorre listas anidadas Synsema infiriendo la shape (rectangular) y aplanando los datos
/// row-major. Filas de distinta forma → error (ragged); elemento no-numérico → error.
fn build_nested(v: &SynValue) -> Result<(Vec<usize>, Vec<f64>), Control> {
    match v {
        SynValue::Number(n) => Ok((vec![], vec![n.to_f64()])),
        SynValue::List(l) => {
            let items = l.borrow();
            if items.is_empty() {
                return Ok((vec![0], vec![]));
            }
            let mut child_shape: Option<Vec<usize>> = None;
            let mut data = Vec::new();
            for it in items.iter() {
                let (sh, d) = build_nested(it)?;
                match &child_shape {
                    None => child_shape = Some(sh),
                    Some(s0) => {
                        if *s0 != sh {
                            return Err(err(
                                "array: ragged nested lists (sub-lists of different shape)",
                            ));
                        }
                    }
                }
                data.extend(d);
            }
            let mut shape = vec![items.len()];
            shape.extend(child_shape.unwrap());
            Ok((shape, data))
        }
        other => Err(err(format!(
            "array expects numbers or nested lists of numbers, got {}",
            other.type_name()
        ))),
    }
}

/// `array(nested_list)` — array desde listas anidadas (1D/2D/nD). Infiere shape.
pub fn array(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "array")?;
    let (shape, data) = build_nested(arg(args, 0)?)?;
    let a = ArrayD::from_shape_vec(IxDyn(&shape), data)
        .map_err(|e| err(format!("array: {}", e)))?;
    Ok(syn_array(a))
}

pub fn zeros(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "zeros")?;
    let shape = shape_from(arg(args, 0)?, "zeros")?;
    Ok(syn_array(ArrayD::zeros(IxDyn(&shape))))
}

pub fn ones(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "ones")?;
    let shape = shape_from(arg(args, 0)?, "ones")?;
    Ok(syn_array(ArrayD::from_elem(IxDyn(&shape), 1.0)))
}

pub fn full(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "full")?;
    let shape = shape_from(arg(args, 0)?, "full")?;
    let v = num_f64(args, 1, "full")?;
    Ok(syn_array(ArrayD::from_elem(IxDyn(&shape), v)))
}

/// `arange(start, stop, step?)` — 1D `[start, start+step, …)` (excluye `stop`).
pub fn arange(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.len() < 2 || args.len() > 3 {
        return Err(err("arange expects 2 or 3 arguments (start, stop, step?)"));
    }
    let start = num_f64(args, 0, "arange")?;
    let stop = num_f64(args, 1, "arange")?;
    let step = if args.len() == 3 { num_f64(args, 2, "arange")? } else { 1.0 };
    if step == 0.0 {
        return Err(err("arange: step must not be zero"));
    }
    let mut data = Vec::new();
    let mut x = start;
    if step > 0.0 {
        while x < stop {
            data.push(x);
            x += step;
        }
    } else {
        while x > stop {
            data.push(x);
            x += step;
        }
    }
    let n = data.len();
    Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&[n]), data).unwrap()))
}

/// `linspace(start, stop, n)` — 1D de `n` puntos equiespaciados (incluye ambos extremos).
pub fn linspace(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 3, "linspace")?;
    let start = num_f64(args, 0, "linspace")?;
    let stop = num_f64(args, 1, "linspace")?;
    let n_i = num_f64(args, 2, "linspace")?;
    if n_i < 0.0 || n_i.fract() != 0.0 {
        return Err(err("linspace: n must be a non-negative integer"));
    }
    let n = n_i as usize;
    let data: Vec<f64> = if n == 0 {
        Vec::new()
    } else if n == 1 {
        vec![start]
    } else {
        let step = (stop - start) / (n as f64 - 1.0);
        (0..n).map(|i| start + step * i as f64).collect()
    };
    Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&[n]), data).unwrap()))
}

fn identity_n(n_arg: f64, name: &str) -> Result<SynValue, Control> {
    if n_arg < 0.0 || n_arg.fract() != 0.0 {
        return Err(err(format!("{}: n must be a non-negative integer", name)));
    }
    let n = n_arg as usize;
    let mut a = ArrayD::<f64>::zeros(IxDyn(&[n, n]));
    for i in 0..n {
        a[[i, i]] = 1.0;
    }
    Ok(syn_array(a))
}

pub fn identity(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "identity")?;
    identity_n(num_f64(args, 0, "identity")?, "identity")
}

pub fn eye(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "eye")?;
    identity_n(num_f64(args, 0, "eye")?, "eye")
}

// =========================================================
// Introspección / conversión
// =========================================================

pub fn shape(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "shape")?;
    let a = array_arg(args, 0, "shape")?;
    Ok(syn_list(a.shape().iter().map(|&d| syn_int(d as i64)).collect()))
}

pub fn ndim(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "ndim")?;
    Ok(syn_int(array_arg(args, 0, "ndim")?.ndim() as i64))
}

pub fn size(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "size")?;
    Ok(syn_int(array_arg(args, 0, "size")?.len() as i64))
}

pub fn is_array(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "is_array")?;
    Ok(syn_bool(matches!(arg(args, 0)?, SynValue::Array(_))))
}

/// `array` → lista anidada Synsema (vuelve a valores `number`).
fn view_to_value(a: &ndarray::ArrayViewD<f64>) -> SynValue {
    if a.ndim() == 0 {
        syn_float(*a.first().unwrap())
    } else {
        syn_list(a.outer_iter().map(|s| view_to_value(&s)).collect())
    }
}

pub fn to_list(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "to_list")?;
    Ok(view_to_value(&array_arg(args, 0, "to_list")?.view()))
}

pub fn reshape(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "reshape")?;
    let a = array_arg(args, 0, "reshape")?;
    let shape = shape_from(arg(args, 1)?, "reshape")?;
    let total: usize = shape.iter().product();
    if total != a.len() {
        return Err(err(format!(
            "reshape: cannot reshape array of {} elements into shape {:?}",
            a.len(),
            shape
        )));
    }
    // row-major (C order), consistente con `flatten` y `array`.
    let flat: Vec<f64> = a.iter().copied().collect();
    Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&shape), flat).unwrap()))
}

pub fn transpose(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "transpose")?;
    let a = array_arg(args, 0, "transpose")?;
    // reverso de ejes (2D = la transpuesta usual). `.t()` invierte los ejes.
    Ok(syn_array(a.t().to_owned()))
}

pub fn flatten(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "flatten")?;
    let a = array_arg(args, 0, "flatten")?;
    let flat: Vec<f64> = a.iter().copied().collect();
    let n = flat.len();
    Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&[n]), flat).unwrap()))
}

/// `at(a, [i, j, …])` → el escalar en el multi-índice. Nº de índices ≠ ndim → error; fuera
/// de rango → error.
pub fn at(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "at")?;
    let a = array_arg(args, 0, "at")?;
    let idx_list = match arg(args, 1)? {
        SynValue::List(l) => l.borrow().clone(),
        other => return Err(err(format!("at expects a list of indices, got {}", other.type_name()))),
    };
    if idx_list.len() != a.ndim() {
        return Err(err(format!(
            "at: expected {} indices for a {}-D array, got {}",
            a.ndim(),
            a.ndim(),
            idx_list.len()
        )));
    }
    let mut idx = Vec::with_capacity(idx_list.len());
    for (axis, iv) in idx_list.iter().enumerate() {
        let i = match iv {
            SynValue::Number(n) => n.to_i64_trunc().unwrap_or(-1),
            other => return Err(err(format!("at: indices must be integers, got {}", other.type_name()))),
        };
        let dim = a.shape()[axis] as i64;
        if i < 0 || i >= dim {
            return Err(err(format!("at: index {} out of bounds for axis {} with size {}", i, axis, dim)));
        }
        idx.push(i as usize);
    }
    Ok(syn_float(a[IxDyn(&idx)]))
}

// =========================================================
// Indexación por fila (llamado desde interpreter::IndexAccess)
// =========================================================

/// `a[i]`: 1D → escalar (Number); nD → la fila `i` (sub-array de un eje menos). Índice
/// negativo o fuera de rango → error.
pub fn index_row(a: &ArrayD<f64>, i: i64) -> Result<SynValue, Control> {
    if a.ndim() == 0 {
        return Err(err("cannot index a 0-dimensional array"));
    }
    let len0 = a.shape()[0] as i64;
    if i < 0 || i >= len0 {
        return Err(err(format!("Index {} out of bounds (array axis 0 has length {})", i, len0)));
    }
    let sub = a.index_axis(Axis(0), i as usize);
    if sub.ndim() == 0 {
        Ok(syn_float(*sub.first().unwrap()))
    } else {
        Ok(syn_array(sub.to_owned()))
    }
}

// =========================================================
// Aritmética vectorizada (llamado desde interpreter::exec_binary)
// =========================================================

/// Shape de broadcast estilo NumPy (alinea desde la derecha; cada dim igual o uno = 1).
/// `None` si no son broadcasteables.
fn broadcast_shape(a: &[usize], b: &[usize]) -> Option<Vec<usize>> {
    let n = a.len().max(b.len());
    let mut out = vec![0usize; n];
    for i in 0..n {
        let da = if i + a.len() < n { 1 } else { a[i + a.len() - n] };
        let db = if i + b.len() < n { 1 } else { b[i + b.len() - n] };
        out[i] = if da == db {
            da
        } else if da == 1 {
            db
        } else if db == 1 {
            da
        } else {
            return None;
        };
    }
    Some(out)
}

fn scalar_op(l: f64, r: f64, op: &str) -> f64 {
    match op {
        "+" => l + r,
        "-" => l - r,
        "*" => l * r,
        "/" => l / r, // IEEE: /0 → ±Inf/NaN (es float elementwise, NO error)
        _ => f64::NAN,
    }
}

/// Aritmética vectorizada para `exec_binary`. Devuelve `None` si NINGÚN operando es array
/// (deja seguir al camino Number); `Some(res)` si lo maneja (array⊕array con broadcasting,
/// array⊕scalar). Sólo `+ - * /` (`*` es ELEMENTWISE, no matmul).
pub fn array_binop(left: &SynValue, right: &SynValue, op: &str) -> Option<Result<SynValue, Control>> {
    let la = matches!(left, SynValue::Array(_));
    let ra = matches!(right, SynValue::Array(_));
    if !la && !ra {
        return None;
    }
    let res = match (left, right) {
        (SynValue::Array(a), SynValue::Array(b)) => {
            match broadcast_shape(a.shape(), b.shape()) {
                None => Err(err(format!(
                    "arrays of shape {:?} and {:?} are not broadcastable",
                    a.shape(),
                    b.shape()
                ))),
                Some(shape) => {
                    let va = a.broadcast(IxDyn(&shape)).unwrap().to_owned();
                    let vb = b.broadcast(IxDyn(&shape)).unwrap().to_owned();
                    let out = match op {
                        "+" => va + vb,
                        "-" => va - vb,
                        "*" => va * vb,
                        "/" => va / vb,
                        _ => unreachable!(),
                    };
                    Ok(syn_array(out))
                }
            }
        }
        (SynValue::Array(a), SynValue::Number(n)) => {
            let s = n.to_f64();
            Ok(syn_array(a.mapv(|x| scalar_op(x, s, op))))
        }
        (SynValue::Number(n), SynValue::Array(b)) => {
            let s = n.to_f64();
            Ok(syn_array(b.mapv(|x| scalar_op(s, x, op))))
        }
        _ => {
            let other = if la { right } else { left };
            Err(err(format!("cannot apply '{}' between array and {}", op, other.type_name())))
        }
    };
    Some(res)
}

/// Unario `-` sobre un array (elementwise).
pub fn negate(a: &ArrayD<f64>) -> SynValue {
    syn_array(a.mapv(|x| -x))
}

// =========================================================
// Reducciones (sum/mean/min/max/product/std/var) con eje opcional
// =========================================================

/// Eje opcional (2º arg): `None` = reduce todo; `Some(k)` = a lo largo del eje k (validado).
fn axis_arg(args: &[SynValue], ndim: usize, name: &str) -> Result<Option<usize>, Control> {
    match args.get(1) {
        None => Ok(None),
        Some(SynValue::Number(n)) => {
            let k = n.to_i64_trunc().unwrap_or(-1);
            if k < 0 || k as usize >= ndim {
                return Err(err(format!("{}: axis {} out of range for a {}-D array", name, k, ndim)));
            }
            Ok(Some(k as usize))
        }
        Some(other) => Err(err(format!("{}: axis must be an integer, got {}", name, other.type_name()))),
    }
}

fn min_all(a: &ArrayD<f64>) -> f64 {
    a.iter().copied().fold(f64::INFINITY, f64::min)
}
fn max_all(a: &ArrayD<f64>) -> f64 {
    a.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}

/// Reducción de un array (con eje opcional). `kind ∈ {sum,mean,min,max,product,var,std}`.
/// La invoca `math.rs` cuando el primer arg es `Array` (las listas siguen su camino, G1).
pub fn reduce(args: &[SynValue], kind: &str) -> Result<SynValue, Control> {
    let a = array_arg(args, 0, kind)?;
    if a.is_empty() {
        return Err(err(format!("{} of an empty array", kind)));
    }
    let axis = axis_arg(args, a.ndim(), kind)?;
    let result = match (kind, axis) {
        ("sum", None) => return Ok(syn_float(a.sum())),
        ("sum", Some(k)) => a.sum_axis(Axis(k)),
        ("product", None) => return Ok(syn_float(a.iter().product())),
        ("product", Some(k)) => a.map_axis(Axis(k), |v| v.iter().product()),
        ("mean", None) => return Ok(syn_float(a.mean().unwrap())),
        ("mean", Some(k)) => a.mean_axis(Axis(k)).unwrap(),
        ("min", None) => return Ok(syn_float(min_all(a))),
        ("min", Some(k)) => a.map_axis(Axis(k), |v| v.iter().copied().fold(f64::INFINITY, f64::min)),
        ("max", None) => return Ok(syn_float(max_all(a))),
        ("max", Some(k)) => a.map_axis(Axis(k), |v| v.iter().copied().fold(f64::NEG_INFINITY, f64::max)),
        ("var", None) => return Ok(syn_float(variance(a.iter().copied()))),
        ("var", Some(k)) => a.map_axis(Axis(k), |v| variance(v.iter().copied())),
        ("std", None) => return Ok(syn_float(variance(a.iter().copied()).sqrt())),
        ("std", Some(k)) => a.map_axis(Axis(k), |v| variance(v.iter().copied()).sqrt()),
        _ => return Err(err(format!("unknown reduction '{}'", kind))),
    };
    Ok(nd_result(result))
}

/// Varianza poblacional (ddof = 0, como NumPy por defecto).
fn variance(it: impl Iterator<Item = f64> + Clone) -> f64 {
    let vals: Vec<f64> = it.collect();
    let n = vals.len() as f64;
    let mean = vals.iter().sum::<f64>() / n;
    vals.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n
}

/// `std`/`var` sobre una LISTA de números (ergonomía; complementa el camino array).
fn list_variance(args: &[SynValue], name: &str) -> Result<f64, Control> {
    let items = match arg(args, 0)? {
        SynValue::List(l) => l.borrow().clone(),
        other => return Err(err(format!("{} expects an array or list, got {}", name, other.type_name()))),
    };
    if items.is_empty() {
        return Err(err(format!("{} of an empty list", name)));
    }
    let mut vals = Vec::with_capacity(items.len());
    for it in &items {
        match it {
            SynValue::Number(n) => vals.push(n.to_f64()),
            other => return Err(err(format!("{} expects numbers, got {}", name, other.type_name()))),
        }
    }
    Ok(variance(vals.into_iter()))
}

pub fn var(args: &[SynValue]) -> Result<SynValue, Control> {
    if matches!(arg(args, 0)?, SynValue::Array(_)) {
        return reduce(args, "var");
    }
    Ok(syn_float(list_variance(args, "var")?))
}

pub fn std(args: &[SynValue]) -> Result<SynValue, Control> {
    if matches!(arg(args, 0)?, SynValue::Array(_)) {
        return reduce(args, "std");
    }
    Ok(syn_float(list_variance(args, "std")?.sqrt()))
}

// =========================================================
// Álgebra lineal (faer) — sobre matrices 2D
// =========================================================

/// `ArrayD<f64>` 2D → `faer::Mat<f64>` (copia). No-2D → error.
fn nd_to_faer(a: &ArrayD<f64>, name: &str) -> Result<Mat<f64>, Control> {
    if a.ndim() != 2 {
        return Err(err(format!("{}: expected a 2D array (matrix), got {}-D", name, a.ndim())));
    }
    let (r, c) = (a.shape()[0], a.shape()[1]);
    Ok(Mat::from_fn(r, c, |i, j| a[[i, j]]))
}

/// `faer::Mat<f64>` → `ArrayD<f64>` 2D.
fn faer_to_nd(m: &Mat<f64>) -> ArrayD<f64> {
    let (r, c) = (m.nrows(), m.ncols());
    ArrayD::from_shape_fn(IxDyn(&[r, c]), |idx| m[(idx[0], idx[1])])
}

fn faer_mul(a: &Mat<f64>, b: &Mat<f64>) -> Mat<f64> {
    let mut c = Mat::<f64>::zeros(a.nrows(), b.ncols());
    faer_matmul_into(c.as_mut(), Accum::Replace, a.as_ref(), b.as_ref(), 1.0, Par::Seq);
    c
}

fn all_finite(m: &Mat<f64>) -> bool {
    (0..m.nrows()).all(|i| (0..m.ncols()).all(|j| m[(i, j)].is_finite()))
}

/// `matmul(a, b)` — producto matricial 2D×2D. Dims internas no compatibles → error.
pub fn matmul(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "matmul")?;
    let a = array_arg(args, 0, "matmul")?;
    let b = array_arg(args, 1, "matmul")?;
    let fa = nd_to_faer(a, "matmul")?;
    let fb = nd_to_faer(b, "matmul")?;
    if fa.ncols() != fb.nrows() {
        return Err(err(format!(
            "matmul: incompatible shapes {:?} and {:?} (cols of A must equal rows of B)",
            a.shape(),
            b.shape()
        )));
    }
    Ok(syn_array(faer_to_nd(&faer_mul(&fa, &fb))))
}

/// `dot(a, b)`: 1D·1D → escalar (Number); 2D×2D → matmul.
pub fn dot(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "dot")?;
    let a = array_arg(args, 0, "dot")?;
    let b = array_arg(args, 1, "dot")?;
    if a.ndim() == 1 && b.ndim() == 1 {
        if a.len() != b.len() {
            return Err(err(format!(
                "dot: vectors of different length ({} and {})",
                a.len(),
                b.len()
            )));
        }
        let s: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        return Ok(syn_float(s));
    }
    matmul(args)
}

/// `solve(A, b)` — resuelve `A x = b` (A cuadrada n×n; b vector 1D o matriz 2D). Singular → error.
pub fn solve(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "solve")?;
    let a = array_arg(args, 0, "solve")?;
    let fa = nd_to_faer(a, "solve")?;
    if fa.nrows() != fa.ncols() {
        return Err(err("solve: A must be a square matrix"));
    }
    let n = fa.nrows();
    let b = array_arg(args, 1, "solve")?;
    let b_is_vec = b.ndim() == 1;
    // b como matriz n×k (vector → n×1).
    let (bk, fb) = match b.ndim() {
        1 => {
            if b.len() != n {
                return Err(err(format!("solve: b length {} != A size {}", b.len(), n)));
            }
            (1usize, Mat::from_fn(n, 1, |i, _| b[[i]]))
        }
        2 => {
            if b.shape()[0] != n {
                return Err(err(format!("solve: b rows {} != A size {}", b.shape()[0], n)));
            }
            (b.shape()[1], Mat::from_fn(n, b.shape()[1], |i, j| b[[i, j]]))
        }
        _ => return Err(err("solve: b must be a 1D vector or 2D matrix")),
    };
    let lu = fa.as_ref().partial_piv_lu();
    let x = lu.solve(fb.as_ref());
    if !all_finite(&x) {
        return Err(err("solve: matrix A is singular (no unique solution)"));
    }
    if b_is_vec {
        Ok(syn_array(ArrayD::from_shape_fn(IxDyn(&[n]), |idx| x[(idx[0], 0)])))
    } else {
        Ok(syn_array(ArrayD::from_shape_fn(IxDyn(&[n, bk]), |idx| x[(idx[0], idx[1])])))
    }
}

/// `det(A)` — determinante (Number). A cuadrada 2D.
pub fn det(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "det")?;
    let a = array_arg(args, 0, "det")?;
    let fa = nd_to_faer(a, "det")?;
    if fa.nrows() != fa.ncols() {
        return Err(err("det: matrix must be square"));
    }
    Ok(syn_float(fa.as_ref().determinant()))
}

/// `inv(A)` — inversa de A cuadrada. Singular → error.
pub fn inv(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "inv")?;
    let a = array_arg(args, 0, "inv")?;
    let fa = nd_to_faer(a, "inv")?;
    if fa.nrows() != fa.ncols() {
        return Err(err("inv: matrix must be square"));
    }
    let inverse = fa.as_ref().partial_piv_lu().inverse();
    if !all_finite(&inverse) {
        return Err(err("inv: matrix is singular (not invertible)"));
    }
    Ok(syn_array(faer_to_nd(&inverse)))
}

/// `norm(a, kind?)` — L2 (vector) / Frobenius (matriz) por defecto; `"l1"`/`"inf"` opcionales.
pub fn norm(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.is_empty() || args.len() > 2 {
        return Err(err("norm expects 1 or 2 arguments (array, kind?)"));
    }
    let a = array_arg(args, 0, "norm")?;
    let kind = match args.get(1) {
        None => "l2".to_string(),
        Some(SynValue::Text(s)) => s.to_lowercase(),
        Some(other) => return Err(err(format!("norm: kind must be text, got {}", other.type_name()))),
    };
    let val = match kind.as_str() {
        "l2" | "fro" | "frobenius" => a.iter().map(|x| x * x).sum::<f64>().sqrt(),
        "l1" => a.iter().map(|x| x.abs()).sum::<f64>(),
        "inf" => a.iter().map(|x| x.abs()).fold(0.0, f64::max),
        other => {
            return Err(err(format!(
                "norm: unknown kind '{}'; use one of: l2, l1, inf",
                other
            )))
        }
    };
    Ok(syn_float(val))
}

/// `trace(A)` — suma de la diagonal (matriz cuadrada 2D).
pub fn trace(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "trace")?;
    let a = array_arg(args, 0, "trace")?;
    if a.ndim() != 2 {
        return Err(err(format!("trace: expected a 2D array, got {}-D", a.ndim())));
    }
    let (r, c) = (a.shape()[0], a.shape()[1]);
    if r != c {
        return Err(err("trace: matrix must be square"));
    }
    Ok(syn_float((0..r).map(|i| a[[i, i]]).sum()))
}

/// `eig(A)` — autovalores/autovectores de A cuadrada → `{values, vectors}`.
/// `values` = lista de `complex` (no se pierde la parte imaginaria); `vectors` = lista de
/// autovectores (uno por autovalor, column j), cada uno una lista de `complex`.
pub fn eig(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "eig")?;
    let a = array_arg(args, 0, "eig")?;
    let fa = nd_to_faer(a, "eig")?;
    if fa.nrows() != fa.ncols() {
        return Err(err("eig: matrix must be square"));
    }
    let n = fa.nrows();
    let e = fa
        .as_ref()
        .eigen()
        .map_err(|_| err("eig: eigendecomposition failed to converge"))?;
    let s = e.S();
    let u = e.U();
    let values: Vec<SynValue> = (0..n)
        .map(|i| {
            let z = s[i];
            syn_complex(z.re, z.im)
        })
        .collect();
    let vectors: Vec<SynValue> = (0..n)
        .map(|j| {
            let col: Vec<SynValue> = (0..n)
                .map(|i| {
                    let z = u[(i, j)];
                    syn_complex(z.re, z.im)
                })
                .collect();
            syn_list(col)
        })
        .collect();
    let mut m = IndexMap::new();
    m.insert("values".to_string(), syn_list(values));
    m.insert("vectors".to_string(), syn_list(vectors));
    Ok(syn_map(m))
}

/// `svd(A)` — descomposición A = U·diag(S)·Vt → `{u, s, vt}`. `s` = valores singulares (1D);
/// `u`/`vt` = matrices 2D (`vt` = V transpuesta, para que `matmul(u, matmul(diag(s), vt)) ≈ A`).
pub fn svd(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "svd")?;
    let a = array_arg(args, 0, "svd")?;
    let fa = nd_to_faer(a, "svd")?;
    let decomp = fa.as_ref().svd().map_err(|_| err("svd: decomposition failed"))?;
    let u = faer_to_nd(&decomp.U().to_owned());
    // V → Vt (transpuesta; para real V^H = V^T).
    let vt = faer_to_nd(&decomp.V().to_owned());
    let vt = vt.t().to_owned();
    let s_diag = decomp.S();
    let k = s_diag.dim();
    let s: Vec<f64> = (0..k).map(|i| s_diag[i]).collect();
    let mut m = IndexMap::new();
    m.insert("u".to_string(), syn_array(u));
    m.insert("s".to_string(), syn_array(ArrayD::from_shape_vec(IxDyn(&[k]), s).unwrap()));
    m.insert("vt".to_string(), syn_array(vt));
    Ok(syn_map(m))
}
