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
    syn_array, syn_bool, syn_complex, syn_float, syn_int, syn_list, syn_map, syn_number, SynValue,
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
    // Negativos desde el final (v0.6.29), como listas y texto.
    let j = if i < 0 { i + len0 } else { i };
    if j < 0 || j >= len0 {
        return Err(err(format!("Index {} out of bounds (array axis 0 has length {})", i, len0)));
    }
    let sub = a.index_axis(Axis(0), j as usize);
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
        "**" => l.powf(r),
        // El divmod de CPython/numpy (`np.floor_divide(7, 0.1)` es 69.0); con divisor 0, lo
        // de numpy: ±inf / NaN.
        "//" if r != 0.0 => crate::number::py_float_divmod(l, r).0,
        "%" if r != 0.0 => crate::number::py_float_divmod(l, r).1,
        "//" => (l / r).floor(),
        "%" => f64::NAN,
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
                        _ => {
                            let mut o = va.clone();
                            ndarray::Zip::from(&mut o).and(&vb).for_each(|x, &y| *x = scalar_op(*x, y, op));
                            o
                        }
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
    // v0.6.29 (DATOS-10): un nombre por concepto — `dot` es el producto interno de VECTORES;
    // el producto de matrices es `matmul` (en numpy `dot` hace las dos cosas y confunde).
    Err(err(format!(
        "dot is the inner product of two 1-D vectors (got {}-D and {}-D) — for matrices use matmul(a, b)",
        a.ndim(),
        b.ndim()
    )))
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

// =========================================================
// v0.6.29 — datos (DATOS-10/11/15): combinar, ubicar, acumular, relacionar, ajustar
// =========================================================

/// `nd_result` público: 0-D → número, n-D → array.
pub fn nd_value(a: ArrayD<f64>) -> SynValue {
    nd_result(a)
}

/// Datos 1-D de una lista de números o un array 1-D (para corr/cov/polyfit/…).
/// Un vector de floats. Un `nothing` (dato faltante) es un error: pasarlo a NaN (resultado
/// inválido) confundiría las dos cosas en silencio. Quien sabe saltear faltantes usa
/// `vector_with_gaps` y los mira en la lista original.
fn vector(v: &SynValue, name: &str) -> Result<Vec<f64>, Control> {
    if let SynValue::List(l) = v {
        if let Some(i) = l.borrow().iter().position(|x| matches!(x, SynValue::Nothing)) {
            return Err(err(format!(
                "{}: position {} is nothing (a missing value), and there is no number to compute with — drop the missing values first: drop_missing(xs)",
                name, i
            )));
        }
    }
    vector_with_gaps(v, name)
}

/// Como `vector`, con NaN en el lugar de cada `nothing`: sólo para quien después saltea esas
/// posiciones mirando la lista original (`pairs`).
fn vector_with_gaps(v: &SynValue, name: &str) -> Result<Vec<f64>, Control> {
    match v {
        SynValue::Array(a) => {
            if a.ndim() != 1 {
                return Err(err(format!("{}: expected a 1-D array or a list, got a {}-D array", name, a.ndim())));
            }
            Ok(a.iter().copied().collect())
        }
        SynValue::List(l) => l
            .borrow()
            .iter()
            .map(|x| match x {
                SynValue::Number(n) => Ok(n.to_f64()),
                SynValue::Nothing => Ok(f64::NAN),
                other => Err(err(format!("{}: expected numbers, got {}", name, other.type_name()))),
            })
            .collect(),
        other => Err(err(format!("{}: expected a list of numbers or an array, got {}", name, other.type_name()))),
    }
}

fn axis_norm(k: i64, ndim: usize, name: &str) -> Result<usize, Control> {
    let nd = ndim as i64;
    let k2 = if k < 0 { k + nd } else { k };
    if k2 < 0 || k2 >= nd {
        return Err(err(format!("{}: axis {} out of range for a {}-D array", name, k, nd)));
    }
    Ok(k2 as usize)
}

fn int_value(v: &SynValue, what: &str, name: &str) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) if n.is_integer() => n.to_i64_trunc().ok_or_else(|| err(format!("{}: {} out of range", name, what))),
        other => Err(err(format!("{}: {} must be an integer, got {}", name, what, other))),
    }
}

/// `concat([a, b, …], axis = 0)`: une arrays a lo largo de un eje existente.
/// `stack([a, b, …], axis = 0)`: los apila en un eje NUEVO.
pub fn concat_or_stack(args: &[SynValue], axis: Option<SynValue>, stack: bool) -> Result<SynValue, Control> {
    let name = if stack { "stack" } else { "concat" };
    let items = match arg(args, 0)? {
        SynValue::List(l) => l.borrow().clone(),
        other => return Err(err(format!("{}: expected a list of arrays, got {}", name, other.type_name()))),
    };
    if items.is_empty() {
        return Err(err(format!("{}: the list of arrays is empty", name)));
    }
    let mut arrs: Vec<ArrayD<f64>> = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        match it {
            SynValue::Array(a) => arrs.push((**a).clone()),
            other => return Err(err(format!("{}: item {} is {}, not an array", name, i, other.type_name()))),
        }
    }
    let k = match axis {
        None | Some(SynValue::Nothing) => 0,
        Some(v) => int_value(&v, "axis", name)?,
    };
    let ndim = if stack { arrs[0].ndim() + 1 } else { arrs[0].ndim() };
    let ax = Axis(axis_norm(k, ndim, name)?);
    let views: Vec<_> = arrs.iter().map(|a| a.view()).collect();
    let r = if stack { ndarray::stack(ax, &views) } else { ndarray::concatenate(ax, &views) };
    r.map(syn_array).map_err(|e| err(format!("{}: the shapes do not line up ({})", name, e)))
}

/// `argmin`/`argmax`: la posición del extremo (la primera si hay empate; la del primer NaN
/// si hay alguno, como numpy). Lista o array (con `axis` → array de posiciones).
pub fn arg_extreme(args: &[SynValue], axis: Option<SynValue>, max: bool) -> Result<SynValue, Control> {
    let name = if max { "argmax" } else { "argmin" };
    let lane = |v: &[f64]| -> f64 {
        if let Some(i) = v.iter().position(|x| x.is_nan()) {
            return i as f64;
        }
        let mut best = 0usize;
        for (i, x) in v.iter().enumerate() {
            if (max && *x > v[best]) || (!max && *x < v[best]) {
                best = i;
            }
        }
        best as f64
    };
    match (arg(args, 0)?, axis) {
        (SynValue::Array(a), Some(k)) if !matches!(k, SynValue::Nothing) => {
            let ax = axis_norm(int_value(&k, "axis", name)?, a.ndim(), name)?;
            let out = a.map_axis(Axis(ax), |l| lane(&l.iter().copied().collect::<Vec<_>>()));
            Ok(nd_result(out))
        }
        // Una lista: `nothing` es un dato faltante y se saltea (como `min`/`max` y el
        // `idxmin` de pandas); NaN sí cuenta y gana (como numpy: "el mínimo no está definido").
        (SynValue::List(l), _) => {
            let items = l.borrow();
            let mut idx: Vec<usize> = Vec::with_capacity(items.len());
            let mut data: Vec<f64> = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                match x {
                    SynValue::Nothing => {}
                    SynValue::Number(n) => {
                        idx.push(i);
                        data.push(n.to_f64());
                    }
                    other => return Err(err(format!("{}: expected numbers, got {} at position {}", name, other.type_name(), i))),
                }
            }
            if data.is_empty() {
                return Err(err(format!(
                    "{} of {}",
                    name,
                    if items.is_empty() { "an empty sequence" } else { "a list where every value is missing" }
                )));
            }
            Ok(syn_int(idx[lane(&data) as usize] as i64))
        }
        (v, _) => {
            let data = match v {
                SynValue::Array(a) => a.iter().copied().collect(),
                other => vector(other, name)?,
            };
            if data.is_empty() {
                return Err(err(format!("{} of an empty sequence", name)));
            }
            Ok(syn_int(lane(&data) as i64))
        }
    }
}

/// `cumsum(xs)`: sumas acumuladas. Lista → lista exacta (enteros/decimal sin pasar por
/// float); array → array (aplanado sin `axis`, como numpy).
pub fn cumsum(args: &[SynValue], axis: Option<SynValue>) -> Result<SynValue, Control> {
    match arg(args, 0)? {
        SynValue::List(l) => {
            let mut acc = Number::Int(0);
            let mut out = Vec::new();
            for x in l.borrow().iter() {
                match x {
                    SynValue::Number(n) => {
                        acc = acc.checked_add(n).map_err(err)?;
                        out.push(syn_number(acc.clone()));
                    }
                    SynValue::Nothing => out.push(SynValue::Nothing),
                    other => return Err(err(format!("cumsum: expected numbers, got {}", other.type_name()))),
                }
            }
            Ok(crate::types::syn_list(out))
        }
        SynValue::Array(a) => match axis {
            None | Some(SynValue::Nothing) => {
                let mut acc = 0.0;
                let flat: Vec<f64> = a.iter().map(|x| {
                    acc += x;
                    acc
                }).collect();
                Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&[flat.len()]), flat).unwrap()))
            }
            Some(k) => {
                let ax = axis_norm(int_value(&k, "axis", "cumsum")?, a.ndim(), "cumsum")?;
                let mut out = (**a).clone();
                out.accumulate_axis_inplace(Axis(ax), |&prev, cur| *cur += prev);
                Ok(syn_array(out))
            }
        },
        other => Err(err(format!("cumsum: expected a list or an array, got {}", other.type_name()))),
    }
}

/// `diff(xs)`: diferencias consecutivas (`x[i+1] - x[i]`). Lista → lista exacta; array → a lo
/// largo del ÚLTIMO eje por defecto (numpy) o de `axis`.
pub fn diff(args: &[SynValue], axis: Option<SynValue>) -> Result<SynValue, Control> {
    match arg(args, 0)? {
        SynValue::List(l) => {
            let items = l.borrow();
            let mut out = Vec::new();
            for w in items.windows(2) {
                match (&w[0], &w[1]) {
                    (SynValue::Number(a), SynValue::Number(b)) => out.push(syn_number(b.checked_sub(a).map_err(err)?)),
                    (SynValue::Nothing, _) | (_, SynValue::Nothing) => out.push(SynValue::Nothing),
                    (a, b) => return Err(err(format!("diff: expected numbers, got {} and {}", a.type_name(), b.type_name()))),
                }
            }
            Ok(crate::types::syn_list(out))
        }
        SynValue::Array(a) => {
            let k = match axis {
                None | Some(SynValue::Nothing) => -1,
                Some(v) => int_value(&v, "axis", "diff")?,
            };
            let ax = Axis(axis_norm(k, a.ndim(), "diff")?);
            let n = a.len_of(ax);
            if n == 0 {
                return Ok(syn_array((**a).clone()));
            }
            let hi = a.slice_axis(ax, ndarray::Slice::from(1..));
            let lo = a.slice_axis(ax, ndarray::Slice::from(..n - 1));
            Ok(syn_array(&hi - &lo))
        }
        other => Err(err(format!("diff: expected a list or an array, got {}", other.type_name()))),
    }
}

/// Pares presentes de dos vectores (se saltean los pares con un faltante; NaN propaga).
fn pairs(x: &SynValue, y: &SynValue, name: &str) -> Result<(Vec<f64>, Vec<f64>), Control> {
    let (xs, ys) = (vector_with_gaps(x, name)?, vector_with_gaps(y, name)?);
    if xs.len() != ys.len() {
        return Err(err(format!("{}: the two series have different lengths ({} and {})", name, xs.len(), ys.len())));
    }
    let missing = |v: &SynValue, i: usize| matches!(v, SynValue::List(l) if matches!(l.borrow().get(i), Some(SynValue::Nothing)));
    let mut a = Vec::new();
    let mut b = Vec::new();
    for i in 0..xs.len() {
        if missing(x, i) || missing(y, i) {
            continue;
        }
        a.push(xs[i]);
        b.push(ys[i]);
    }
    Ok((a, b))
}

/// `cov(xs, ys, ddof = 1)`: covarianza (muestral por defecto, como `std`).
pub fn cov(args: &[SynValue], ddof: Option<SynValue>) -> Result<SynValue, Control> {
    let (a, b) = pairs(arg(args, 0)?, arg(args, 1)?, "cov")?;
    let d = match ddof {
        None => 1.0,
        Some(v) => int_value(&v, "ddof", "cov")? as f64,
    };
    let n = a.len() as f64;
    if n - d <= 0.0 {
        return Ok(syn_float(f64::NAN));
    }
    let (ma, mb) = (a.iter().sum::<f64>() / n, b.iter().sum::<f64>() / n);
    Ok(syn_float(a.iter().zip(&b).map(|(x, y)| (x - ma) * (y - mb)).sum::<f64>() / (n - d)))
}

/// `corr(xs, ys)`: correlación de Pearson.
pub fn corr(args: &[SynValue]) -> Result<SynValue, Control> {
    let (a, b) = pairs(arg(args, 0)?, arg(args, 1)?, "corr")?;
    let n = a.len() as f64;
    if n < 2.0 {
        return Ok(syn_float(f64::NAN));
    }
    let (ma, mb) = (a.iter().sum::<f64>() / n, b.iter().sum::<f64>() / n);
    let sxy: f64 = a.iter().zip(&b).map(|(x, y)| (x - ma) * (y - mb)).sum();
    let sxx: f64 = a.iter().map(|x| (x - ma) * (x - ma)).sum();
    let syy: f64 = b.iter().map(|y| (y - mb) * (y - mb)).sum();
    Ok(syn_float(sxy / (sxx * syy).sqrt()))
}

/// Mínimos cuadrados por SVD, como `numpy.linalg.lstsq` (LAPACK gelsd): `x` que minimiza
/// `‖A·x − b‖` y, entre las que empatan, la de norma mínima. Los valores singulares por
/// debajo de `eps · max(m, n) · s_max` (el `rcond` por defecto de numpy) cuentan como cero,
/// así que un sistema con columnas dependientes o con menos filas que columnas tiene
/// respuesta —la misma que numpy— en vez de números enormes. Devuelve también el rango.
fn least_squares(a: &Mat<f64>, b: &Mat<f64>, name: &str) -> Result<(Mat<f64>, usize), Control> {
    let (m, n) = (a.nrows(), a.ncols());
    if m == 0 || n == 0 {
        return Err(err(format!("{}: A is empty", name)));
    }
    if !all_finite(a) || !all_finite(b) {
        return Err(err(format!("{}: A and b must be finite (found NaN or infinity)", name)));
    }
    let dec = a.as_ref().thin_svd().map_err(|_| err(format!("{}: the SVD did not converge", name)))?;
    let (u, v, sd) = (dec.U(), dec.V(), dec.S());
    let k = sd.dim();
    let smax = (0..k).map(|i| sd[i]).fold(0.0_f64, f64::max);
    let tol = f64::EPSILON * (m.max(n) as f64) * smax;
    let mut x = Mat::<f64>::zeros(n, b.ncols());
    let mut rank = 0;
    for i in 0..k {
        let si = sd[i];
        if si <= tol {
            continue;
        }
        rank += 1;
        for c in 0..b.ncols() {
            let mut dot = 0.0;
            for r in 0..m {
                dot += u[(r, i)] * b[(r, c)];
            }
            let coef = dot / si;
            for j in 0..n {
                x[(j, c)] += v[(j, i)] * coef;
            }
        }
    }
    Ok((x, rank))
}

/// `lstsq(A, b)`: la solución de mínimos cuadrados (1-D si `b` es 1-D).
pub fn lstsq(args: &[SynValue]) -> Result<SynValue, Control> {
    let a = array_arg(args, 0, "lstsq")?;
    let fa = nd_to_faer(a, "lstsq")?;
    let (fb, one_d) = match arg(args, 1)? {
        SynValue::Array(b) if b.ndim() == 1 => (Mat::from_fn(b.len(), 1, |i, _| b[[i]]), true),
        SynValue::Array(b) => (nd_to_faer(b, "lstsq")?, false),
        other => {
            let v = vector(other, "lstsq")?;
            (Mat::from_fn(v.len(), 1, |i, _| v[i]), true)
        }
    };
    if fb.nrows() != fa.nrows() {
        return Err(err(format!("lstsq: A has {} rows but b has {}", fa.nrows(), fb.nrows())));
    }
    let (x, _rank) = least_squares(&fa, &fb, "lstsq")?;
    if one_d {
        Ok(syn_array(ArrayD::from_shape_fn(IxDyn(&[x.nrows()]), |i| x[(i[0], 0)])))
    } else {
        Ok(syn_array(faer_to_nd(&x)))
    }
}

/// `polyfit(xs, ys, degree)` → coeficientes del polinomio de mínimos cuadrados, del grado más
/// ALTO al término independiente (el orden de numpy): `polyfit(x, y, 1)` = `[pendiente, ordenada]`.
pub fn polyfit(args: &[SynValue]) -> Result<SynValue, Control> {
    let (xs, ys) = pairs(arg(args, 0)?, arg(args, 1)?, "polyfit")?;
    let deg = int_value(arg(args, 2)?, "the degree", "polyfit")?;
    if deg < 0 {
        return Err(err("polyfit: the degree must be 0 or more"));
    }
    let d = deg as usize;
    if xs.len() <= d {
        return Err(err(format!("polyfit: degree {} needs at least {} points, got {}", d, d + 1, xs.len())));
    }
    // Vandermonde con las columnas escaladas a norma 1, como numpy (mejor condicionado).
    let mut a = Mat::from_fn(xs.len(), d + 1, |i, j| xs[i].powi((d - j) as i32));
    let scale: Vec<f64> = (0..=d)
        .map(|j| {
            let n = (0..xs.len()).map(|i| a[(i, j)] * a[(i, j)]).sum::<f64>().sqrt();
            if n == 0.0 { 1.0 } else { n }
        })
        .collect();
    for j in 0..=d {
        for i in 0..xs.len() {
            a[(i, j)] /= scale[j];
        }
    }
    let b = Mat::from_fn(ys.len(), 1, |i, _| ys[i]);
    let (c, rank) = least_squares(&a, &b, "polyfit")?;
    // numpy avisa (`RankWarning`) y devuelve igual; acá es error: un ajuste que no queda
    // determinado por los datos no es un resultado.
    if rank < d + 1 {
        return Err(err(format!(
            "polyfit: the fit is not determined by the data (rank {} of {}): there are fewer distinct x values than degree + 1, or they are too close for this degree — lower the degree or rescale x",
            rank,
            d + 1
        )));
    }
    Ok(crate::types::syn_list((0..=d).map(|j| syn_float(c[(j, 0)] / scale[j])).collect()))
}

/// `polyval(coefs, x)`: evalúa el polinomio (grado más alto primero) en un número, lista o array.
/// Un coeficiente faltante es un error (no hay polinomio); un `x` faltante en una lista queda
/// `nothing` en su lugar, como en `cumsum`.
pub fn polyval(args: &[SynValue]) -> Result<SynValue, Control> {
    let coefs = vector(arg(args, 0)?, "polyval")?;
    let eval = |x: f64| coefs.iter().fold(0.0, |acc, c| acc * x + c);
    match arg(args, 1)? {
        SynValue::Number(n) => Ok(syn_float(eval(n.to_f64()))),
        SynValue::Array(a) => Ok(syn_array(a.mapv(eval))),
        SynValue::Nothing => Ok(SynValue::Nothing),
        other => {
            let xs = vector_with_gaps(other, "polyval")?;
            let gap = |i: usize| matches!(other, SynValue::List(l) if matches!(l.borrow().get(i), Some(SynValue::Nothing)));
            Ok(crate::types::syn_list(
                xs.into_iter().enumerate().map(|(i, x)| if gap(i) { SynValue::Nothing } else { syn_float(eval(x)) }).collect(),
            ))
        }
    }
}
