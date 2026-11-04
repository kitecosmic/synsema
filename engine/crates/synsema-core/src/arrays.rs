//! Arrays numéricos n-dimensionales + álgebra lineal (Batch 5).
//!
//! Tipo `SynValue::Array(Obj<NdArray>)` (dtype `f64` o `bool`, inmutable; ver `types::NdArray`). `ndarray` da el modelo
//! n-dimensional + vectorización/broadcasting/reducciones; `faer` (puro-Rust, SIMD) el
//! álgebra lineal densa 2D (matmul/solve/det/inv/eig/svd). **`*` es ELEMENTWISE**; el
//! producto matricial es `matmul`/`dot`.
//!
//! Builtins puros (sin capability). Errores claros, nunca NaN/panic silencioso por shapes
//! incompatibles, no-2D en LA, o matriz singular (G3).

use crate::synlist::{list_values};
use crate::types::SynMap;
use ndarray::{ArrayD, Axis, IxDyn};

use faer::linalg::matmul::matmul as faer_matmul_into;
use faer::linalg::solvers::{DenseSolveCore, Solve};
use faer::{Accum, Mat, Par};


use crate::interpreter::{Control, RuntimeError};
use crate::number::Number;
use crate::types::{
    syn_array, syn_bool, syn_complex, syn_float, syn_int, syn_list, syn_map, syn_number, NdArray, SynValue,
};
use std::borrow::Cow;

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

/// El i-ésimo argumento como `array`, con su tipo de elemento; error si no lo es.
fn nd_arg<'a>(args: &'a [SynValue], i: usize, name: &str) -> Result<&'a NdArray, Control> {
    match arg(args, i)? {
        SynValue::Array(a) => Ok(a),
        other => Err(err(format!("{} expects an array, got {}", name, other.type_name()))),
    }
}

/// El i-ésimo argumento como números `f64`: prestado si el array es `f64`, convertido a 0/1 si
/// es una máscara (R2). Es el único punto de conversión de las operaciones que no miran el tipo.
fn array_arg<'a>(args: &'a [SynValue], i: usize, name: &str) -> Result<Cow<'a, ArrayD<f64>>, Control> {
    nd_arg(args, i, name).map(NdArray::to_f64)
}

/// Aplica una transformación que no depende del tipo de elemento (forma, orden) a cada variante.
macro_rules! nd_map {
    ($a:expr, |$x:ident| $body:expr) => {
        match $a {
            NdArray::F64($x) => NdArray::F64($body),
            NdArray::Bool($x) => NdArray::Bool($body),
        }
    };
}

/// `shape` desde un arg: un entero `n` → `[n]` (1D); una lista de enteros `[2,3]` → nD.
pub fn shape_from(v: &SynValue, name: &str) -> Result<Vec<usize>, Control> {
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
            for it in list_values(&l).iter() {
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
            let items = list_values(&l);
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
    let a = nd_arg(args, 0, "shape")?;
    Ok(syn_list(a.shape().iter().map(|&d| syn_int(d as i64)).collect()))
}

pub fn ndim(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "ndim")?;
    Ok(syn_int(nd_arg(args, 0, "ndim")?.ndim() as i64))
}

pub fn size(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "size")?;
    Ok(syn_int(nd_arg(args, 0, "size")?.len() as i64))
}

pub fn is_array(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "is_array")?;
    Ok(syn_bool(matches!(arg(args, 0)?, SynValue::Array(_))))
}

/// `array` → lista anidada Synsema (vuelve a valores `number`, o `bool` si es una máscara).
fn view_to_value<T: Copy>(a: &ndarray::ArrayViewD<T>, elem: fn(T) -> SynValue) -> SynValue {
    if a.ndim() == 0 {
        elem(*a.first().unwrap())
    } else {
        syn_list(a.outer_iter().map(|s| view_to_value(&s, elem)).collect())
    }
}

/// Un elemento suelto del array como valor del lenguaje: número o `bool`.
pub fn nd_to_list(a: &NdArray) -> SynValue {
    match a {
        NdArray::F64(x) => view_to_value(&x.view(), syn_float),
        NdArray::Bool(x) => view_to_value(&x.view(), syn_bool),
    }
}

pub fn to_list(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "to_list")?;
    Ok(nd_to_list(nd_arg(args, 0, "to_list")?))
}

pub fn reshape(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "reshape")?;
    let a = nd_arg(args, 0, "reshape")?;
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
    Ok(nd_value_of(nd_map!(a, |x| ArrayD::from_shape_vec(IxDyn(&shape), x.iter().copied().collect()).unwrap())))
}

/// `slice(a, i, j)`: las filas `s..e` del primer eje (ya normalizadas), con el mismo tipo.
pub fn slice_rows(a: &NdArray, s: usize, e: usize) -> SynValue {
    nd_value_of(nd_map!(a, |x| x.slice_axis(Axis(0), ndarray::Slice::from(s..e)).to_owned()))
}

/// Envuelve un `NdArray` como valor `array`.
fn nd_value_of(a: NdArray) -> SynValue {
    SynValue::Array(crate::types::Obj::new(a))
}

pub fn transpose(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "transpose")?;
    let a = nd_arg(args, 0, "transpose")?;
    // reverso de ejes (2D = la transpuesta usual). `.t()` invierte los ejes.
    Ok(nd_value_of(nd_map!(a, |x| x.t().to_owned())))
}

pub fn flatten(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "flatten")?;
    let a = nd_arg(args, 0, "flatten")?;
    let n = a.len();
    Ok(nd_value_of(nd_map!(a, |x| ArrayD::from_shape_vec(IxDyn(&[n]), x.iter().copied().collect()).unwrap())))
}

/// `at(a, [i, j, …])` → el escalar en el multi-índice. Nº de índices ≠ ndim → error; fuera
/// de rango → error.
pub fn at(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "at")?;
    let a = nd_arg(args, 0, "at")?;
    let idx_list = match arg(args, 1)? {
        SynValue::List(l) => l.borrow().to_vec(),
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
    Ok(match a {
        NdArray::F64(x) => syn_float(x[IxDyn(&idx)]),
        NdArray::Bool(x) => syn_bool(x[IxDyn(&idx)]),
    })
}

// =========================================================
// Indexación por fila (llamado desde interpreter::IndexAccess)
// =========================================================

/// `a[i]`: 1D → escalar (Number); nD → la fila `i` (sub-array de un eje menos). Índice
/// negativo o fuera de rango → error.
pub fn index_row(a: &NdArray, i: i64) -> Result<SynValue, Control> {
    if a.ndim() == 0 {
        return Err(err("cannot index a 0-dimensional array"));
    }
    let len0 = a.shape()[0] as i64;
    // Negativos desde el final (v0.6.29), como listas y texto.
    let j = if i < 0 { i + len0 } else { i };
    if j < 0 || j >= len0 {
        return Err(err(format!("Index {} out of bounds (array axis 0 has length {})", i, len0)));
    }
    let j = j as usize;
    if a.ndim() == 1 {
        return Ok(match a {
            NdArray::F64(x) => syn_float(x[[j]]),
            NdArray::Bool(x) => syn_bool(x[[j]]),
        });
    }
    Ok(nd_value_of(nd_map!(a, |x| x.index_axis(Axis(0), j).to_owned())))
}

// =========================================================
// Aritmética vectorizada (llamado desde interpreter::exec_binary)
// =========================================================

/// Shape de broadcast estilo NumPy (alinea desde la derecha; cada dim igual o uno = 1).
/// `None` si no son broadcasteables.
pub fn broadcast_shape(a: &[usize], b: &[usize]) -> Option<Vec<usize>> {
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
            let (a, b) = (a.to_f64(), b.to_f64());
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
            Ok(syn_array(a.to_f64().mapv(|x| scalar_op(x, s, op))))
        }
        (SynValue::Number(n), SynValue::Array(b)) => {
            let s = n.to_f64();
            Ok(syn_array(b.to_f64().mapv(|x| scalar_op(s, x, op))))
        }
        _ => {
            let other = if la { right } else { left };
            Err(err(format!("cannot apply '{}' between array and {}", op, other.type_name())))
        }
    };
    Some(res)
}

// =========================================================
// Elemento a elemento con broadcasting (v0.6.55): comparaciones, `==`, `maximum`, …
// =========================================================

/// Un operando elemento a elemento como `f64`: un array (una máscara da 0/1, R2) o un número
/// (un array 0-d, que el broadcasting estira). `None` si no es ninguno de los dos.
pub fn elem_operand(v: &SynValue) -> Option<Cow<'_, ArrayD<f64>>> {
    match v {
        SynValue::Array(a) => Some(a.to_f64()),
        SynValue::Number(n) => Some(Cow::Owned(ArrayD::from_elem(IxDyn(&[]), n.to_f64()))),
        _ => None,
    }
}

/// `f(a, b)` elemento a elemento con el broadcasting de numpy, sin copiar los operandos.
pub fn zip_broadcast<A: Copy, B: Copy, T>(a: &ArrayD<A>, b: &ArrayD<B>, f: impl Fn(A, B) -> T) -> Result<ArrayD<T>, Control> {
    let shape = broadcast_shape(a.shape(), b.shape())
        .ok_or_else(|| err(format!("arrays of shape {:?} and {:?} are not broadcastable", a.shape(), b.shape())))?;
    let (va, vb) = (a.broadcast(IxDyn(&shape)).unwrap(), b.broadcast(IxDyn(&shape)).unwrap());
    Ok(ndarray::Zip::from(va).and(vb).map_collect(|&x, &y| f(x, y)))
}

fn is_mask(v: &SynValue) -> bool {
    matches!(v, SynValue::Array(a) if a.as_f64().is_none())
}

/// `<`, `>`, `<=`, `>=` con un array de un lado (R1): una máscara de la forma del broadcast. Un
/// `NaN` da `false` (numpy). Una máscara no tiene orden (R2) y una lista no se convierte sola.
/// Fría: `exec_binary` llega acá sólo si un operando es un array.
#[inline(never)]
pub fn array_compare(left: &SynValue, right: &SynValue, op: &str) -> Result<SynValue, Control> {
    if is_mask(left) || is_mask(right) {
        return Err(err("masks are not ordered — compare the numbers they came from"));
    }
    let (a, b) = match (elem_operand(left), elem_operand(right)) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            let other = if matches!(left, SynValue::Array(_)) { right } else { left };
            return Err(match other {
                SynValue::List(_) => err("cannot compare an array with a list — make it an array first: array(xs)"),
                o => err(format!("cannot compare an array with {}", o.type_name())),
            });
        }
    };
    let f: fn(f64, f64) -> bool = match op {
        "<" => |x, y| x < y,
        ">" => |x, y| x > y,
        "<=" => |x, y| x <= y,
        _ => |x, y| x >= y,
    };
    Ok(crate::types::syn_mask(zip_broadcast(&a, &b, f)?))
}

/// `==`/`!=` con un array de un lado, cuando la igualdad del valor entero dio `false` (R3): si
/// eso es la respuesta (otra forma, otros valores, `nothing`) devuelve `Ok`; si `false` en
/// silencio sería un error (un número, una lista, otro tipo, una máscara contra un `f64`), el
/// error nombra la forma Synsema.
#[inline(never)]
pub fn array_eq_mismatch(left: &SynValue, right: &SynValue, op: &str) -> Result<(), Control> {
    let (arr, other) = if matches!(left, SynValue::Array(_)) { (left, right) } else { (right, left) };
    match (arr, other) {
        (SynValue::Array(a), SynValue::Array(b)) => {
            if a.dtype() == b.dtype() {
                Ok(())
            } else {
                Err(err("a mask and a f64 array are never equal — compare like with like (m * 1.0 gives 0/1 floats)"))
            }
        }
        (_, SynValue::Nothing) => Ok(()),
        (_, SynValue::Number(n)) => {
            let f = if op == "==" { "equal" } else { "not_equal" };
            Err(err(format!("{} compares whole values; for elementwise: {}(a, {})", op, f, n)))
        }
        (_, SynValue::List(_)) => Err(err(if op == "==" {
            "== between an array and a list is never true — compare array(xs), or to_list(a) == xs"
        } else {
            "!= between an array and a list is always true — compare array(xs), or to_list(a) != xs"
        })),
        (_, o) => Err(err(format!(
            "{} between an array and {} is {}",
            op,
            o.type_name(),
            if op == "==" { "never true" } else { "always true" }
        ))),
    }
}

/// `where(a, m)` (v0.6.55): los elementos de `a` donde la máscara es verdadera, aplanados en 1-D,
/// como `a[m]` de numpy. La máscara tiene la forma de `a`. Una máscara de máscara da una máscara.
#[inline(never)]
pub fn where_mask(a: &NdArray, m: &SynValue) -> Result<SynValue, Control> {
    let m = match m {
        SynValue::Array(x) => match &**x {
            NdArray::Bool(m) => m,
            NdArray::F64(_) => {
                return Err(err("where expects a mask (a > 0) or a predicate ((x) => …), got a f64 array"))
            }
        },
        other => {
            return Err(err(format!(
                "where expects a mask (a > 0) or a predicate ((x) => …), got {}",
                other.type_name()
            )))
        }
    };
    if m.shape() != a.shape() {
        return Err(err(format!("where: the mask has shape {:?} and the array {:?}", m.shape(), a.shape())));
    }
    fn pick<T: Copy>(x: &ArrayD<T>, m: &ArrayD<bool>) -> ArrayD<T> {
        let v: Vec<T> = x.iter().zip(m.iter()).filter(|(_, k)| **k).map(|(v, _)| *v).collect();
        let n = v.len();
        ArrayD::from_shape_vec(IxDyn(&[n]), v).expect("1-D")
    }
    Ok(nd_value_of(nd_map!(a, |x| pick(x, m))))
}

/// `clamp(a, lo, hi)` con un array en alguno de los tres (v0.6.55): `min(max(x, lo), hi)` elemento a
/// elemento, con broadcasting; un `NaN` se propaga (el `np.clip` de numpy).
#[inline(never)]
pub fn clamp_array(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 3, "clamp")?;
    let one = |i: usize| -> Result<Cow<'_, ArrayD<f64>>, Control> {
        elem_operand(&args[i]).ok_or_else(|| match &args[i] {
            SynValue::List(_) => err("clamp: make the list an array first: array(xs)"),
            o => err(format!("clamp expects arrays or numbers, got {}", o.type_name())),
        })
    };
    let (x, lo, hi) = (one(0)?, one(1)?, one(2)?);
    let up = zip_broadcast(&x, &lo, |v, l| if v.is_nan() || l.is_nan() { f64::NAN } else { v.max(l) })?;
    Ok(syn_array(zip_broadcast(&up, &hi, |v, h| if v.is_nan() || h.is_nan() { f64::NAN } else { v.min(h) })?))
}

/// Lo que recorre `each x in a` (v0.6.55, ítem 9): el primer eje, como `enumerate(a)` y `a[i]`. Un
/// array 1-D da sus elementos (números, o bool si es una máscara); uno de más ejes, sus filas.
#[inline(never)]
pub fn each_items(a: &NdArray) -> Result<Vec<SynValue>, Control> {
    each_check(a)?;
    Ok((0..a.shape()[0]).filter_map(|i| each_item(a, i)).collect())
}

/// `each` sobre un array 0-d es un error (no tiene filas).
pub fn each_check(a: &NdArray) -> Result<(), Control> {
    if a.ndim() == 0 {
        return Err(err("each over a 0-d array: it is a scalar and has no rows — use the value itself"));
    }
    Ok(())
}

/// El elemento (1-D) o la fila `i` de `each`, recién cuando le toca la vuelta; `None` al terminar.
#[inline(never)]
pub fn each_item(a: &NdArray, i: usize) -> Option<SynValue> {
    if i >= a.shape()[0] {
        return None;
    }
    if a.ndim() == 1 {
        return Some(match a {
            NdArray::F64(x) => syn_float(x[[i]]),
            NdArray::Bool(x) => syn_bool(x[[i]]),
        });
    }
    index_row(a, i as i64).ok()
}

/// Un error sin ubicación con la de `loc` (la de la sentencia que lo pidió).
pub fn located(e: Control, loc: &crate::tokens::SourceLocation) -> Control {
    match e {
        Control::Error(mut r) if r.location.is_none() => {
            r.location = Some(loc.clone());
            Control::Error(r)
        }
        other => other,
    }
}

/// Una función numérica de un argumento sobre un array (v0.6.55, ítem 5): elemento a elemento, `f64`
/// (una máscara entra como 0/1, R2).
#[inline(never)]
pub fn map_f64(a: &NdArray, f: impl Fn(f64) -> f64) -> SynValue {
    syn_array(a.to_f64().mapv(f))
}

/// Un predicado numérico sobre un array (`is_nan`, `is_finite`, …): una máscara.
#[inline(never)]
pub fn map_pred(a: &NdArray, f: fn(f64) -> bool) -> SynValue {
    crate::types::syn_mask(a.to_f64().mapv(f))
}

/// Una función numérica de dos argumentos con un array en alguno (`pow`, `atan2`, `hypot`,
/// `log_base`, `beta`): elemento a elemento con broadcasting, `f64`.
#[inline(never)]
pub fn binary_elem(args: &[SynValue], name: &str, f: impl Fn(f64, f64) -> f64) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    let one = |i: usize| -> Result<Cow<'_, ArrayD<f64>>, Control> {
        elem_operand(&args[i]).ok_or_else(|| match &args[i] {
            SynValue::List(_) => err(format!("{}: make the list an array first: array(xs)", name)),
            o => err(format!("{} expects arrays or numbers, got {}", name, o.type_name())),
        })
    };
    let (a, b) = (one(0)?, one(1)?);
    let r = zip_broadcast(&a, &b, f).map_err(|e| match e {
        Control::Error(mut r) => {
            r.message = format!("{}: {}", name, r.message);
            Control::Error(r)
        }
        other => other,
    })?;
    Ok(syn_array(r))
}

/// `Err` si algún elemento de un array de `args` no es un entero (`gcd`, `lcm`, `factorial`
/// sobre arrays: el array es `f64`, los enteros van como floats exactos hasta 2^53).
#[inline(never)]
pub fn require_whole(args: &[SynValue], name: &str) -> Result<(), Control> {
    for v in args {
        if let SynValue::Array(a) = v {
            if let Some(x) = a.to_f64().iter().find(|x| !(x.is_finite() && x.fract() == 0.0)) {
                return Err(err(format!("{} expects whole numbers, the array has {}", name, x)));
            }
        }
    }
    Ok(())
}

/// `gcd` de dos floats enteros (Euclides; exacto mientras quepan en 2^53).
pub fn gcd_f64(a: f64, b: f64) -> f64 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0.0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Unario `-` sobre un array (elementwise).
pub fn negate(a: &NdArray) -> SynValue {
    syn_array(a.to_f64().mapv(|x| -x))
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
        ("min", None) => return Ok(syn_float(min_all(&a))),
        ("min", Some(k)) => a.map_axis(Axis(k), |v| v.iter().copied().fold(f64::INFINITY, f64::min)),
        ("max", None) => return Ok(syn_float(max_all(&a))),
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
        SynValue::List(l) => l.borrow().to_vec(),
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
    let fa = nd_to_faer(&a, "matmul")?;
    let fb = nd_to_faer(&b, "matmul")?;
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
    // Una matriz con un vector (`np.dot(M, v)`): la forma Synsema, con el largo del vector.
    let hint = match (a.ndim(), b.ndim()) {
        (2, 1) => format!("for a matrix times a vector: matmul(M, reshape(v, [{}, 1]))", b.len()),
        (1, 2) => format!("for a vector times a matrix: matmul(reshape(v, [1, {}]), M)", a.len()),
        _ => "for matrices use matmul(a, b)".to_string(),
    };
    Err(err(format!(
        "dot is the inner product of two 1-D vectors (got {}-D and {}-D) — {}",
        a.ndim(),
        b.ndim(),
        hint
    )))
}

/// `solve(A, b)` — resuelve `A x = b` (A cuadrada n×n; b vector 1D o matriz 2D). Singular → error.
pub fn solve(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "solve")?;
    let a = array_arg(args, 0, "solve")?;
    let fa = nd_to_faer(&a, "solve")?;
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
    let fa = nd_to_faer(&a, "det")?;
    if fa.nrows() != fa.ncols() {
        return Err(err("det: matrix must be square"));
    }
    Ok(syn_float(fa.as_ref().determinant()))
}

/// `inv(A)` — inversa de A cuadrada. Singular → error.
pub fn inv(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "inv")?;
    let a = array_arg(args, 0, "inv")?;
    let fa = nd_to_faer(&a, "inv")?;
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
    let fa = nd_to_faer(&a, "eig")?;
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
    let mut m = SynMap::new();
    m.insert("values", syn_list(values));
    m.insert("vectors", syn_list(vectors));
    Ok(syn_map(m))
}

/// `svd(A)` — descomposición A = U·diag(S)·Vt → `{u, s, vt}`. `s` = valores singulares (1D);
/// `u`/`vt` = matrices 2D (`vt` = V transpuesta, para que `matmul(u, matmul(diag(s), vt)) ≈ A`).
pub fn svd(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "svd")?;
    let a = array_arg(args, 0, "svd")?;
    let fa = nd_to_faer(&a, "svd")?;
    let decomp = fa.as_ref().svd().map_err(|_| err("svd: decomposition failed"))?;
    let u = faer_to_nd(&decomp.U().to_owned());
    // V → Vt (transpuesta; para real V^H = V^T).
    let vt = faer_to_nd(&decomp.V().to_owned());
    let vt = vt.t().to_owned();
    let s_diag = decomp.S();
    let k = s_diag.dim();
    let s: Vec<f64> = (0..k).map(|i| s_diag[i]).collect();
    let mut m = SynMap::new();
    m.insert("u", syn_array(u));
    m.insert("s", syn_array(ArrayD::from_shape_vec(IxDyn(&[k]), s).unwrap()));
    m.insert("vt", syn_array(vt));
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
        if let Some(i) = list_values(&l).iter().position(|x| matches!(x, SynValue::Nothing)) {
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
            Ok(a.to_f64().iter().copied().collect())
        }
        SynValue::List(l) => list_values(&l)
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
        SynValue::List(l) => l.borrow().to_vec(),
        other => return Err(err(format!("{}: expected a list of arrays, got {}", name, other.type_name()))),
    };
    if items.is_empty() {
        return Err(err(format!("{}: the list of arrays is empty", name)));
    }
    let mut arrs: Vec<ArrayD<f64>> = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        match it {
            SynValue::Array(a) => arrs.push(a.to_f64().into_owned()),
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
            let a = a.to_f64();
            let ax = axis_norm(int_value(&k, "axis", name)?, a.ndim(), name)?;
            let out = a.map_axis(Axis(ax), |l| lane(&l.iter().copied().collect::<Vec<_>>()));
            Ok(nd_result(out))
        }
        // Una lista: `nothing` es un dato faltante y se saltea (como `min`/`max` y el
        // `idxmin` de pandas); NaN sí cuenta y gana (como numpy: "el mínimo no está definido").
        (SynValue::List(l), _) => {
            let items = list_values(&l);
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
                SynValue::Array(a) => a.to_f64().iter().copied().collect(),
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
            for x in list_values(&l).iter() {
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
        SynValue::Array(a) => match (a.to_f64(), axis) {
            (a, None | Some(SynValue::Nothing)) => {
                let mut acc = 0.0;
                let flat: Vec<f64> = a.iter().map(|x| {
                    acc += x;
                    acc
                }).collect();
                Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&[flat.len()]), flat).unwrap()))
            }
            (a, Some(k)) => {
                let ax = axis_norm(int_value(&k, "axis", "cumsum")?, a.ndim(), "cumsum")?;
                let mut out = a.into_owned();
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
            let items = list_values(&l);
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
            let a = a.to_f64();
            let k = match axis {
                None | Some(SynValue::Nothing) => -1,
                Some(v) => int_value(&v, "axis", "diff")?,
            };
            let ax = Axis(axis_norm(k, a.ndim(), "diff")?);
            let n = a.len_of(ax);
            if n == 0 {
                return Ok(syn_array(a.into_owned()));
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
    let fa = nd_to_faer(&a, "lstsq")?;
    let (fb, one_d) = match arg(args, 1)? {
        SynValue::Array(b) if b.ndim() == 1 => {
            let b = b.to_f64();
            (Mat::from_fn(b.len(), 1, |i, _| b[[i]]), true)
        }
        SynValue::Array(b) => (nd_to_faer(&b.to_f64(), "lstsq")?, false),
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
        SynValue::Array(a) => Ok(syn_array(a.to_f64().mapv(eval))),
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

// =========================================================
// v0.6.55, ítems 2 y 3: indexar con posiciones y escribir (R5)
// =========================================================

/// Para qué se piden las posiciones: cambia sólo el texto del error de una máscara.
#[derive(Clone, Copy)]
pub enum PosFor<'a> {
    /// `a[[0, 3]]`.
    Read,
    /// `set a[[0, 3]] to …`.
    Set,
    /// Un builtin (`take`, `index_add`): su nombre va adelante.
    Builtin(&'a str),
}

/// Las posiciones de `idx` sobre un eje de largo `len`: un número (una), una lista o un array de
/// enteros (en ese orden, repetir vale). Negativos desde el final; fuera de rango, el error de
/// `a[i]`. Una máscara no es una lista de posiciones.
#[inline(never)]
pub fn positions(idx: &SynValue, len: usize, axis: usize, why: PosFor) -> Result<Vec<usize>, Control> {
    let pre = match why {
        PosFor::Builtin(n) => format!("{}: ", n),
        _ => String::new(),
    };
    let one = |x: f64, shown: &dyn std::fmt::Display| -> Result<usize, Control> {
        let k = x as i64;
        let j = if k < 0 { k + len as i64 } else { k };
        if j < 0 || j >= len as i64 {
            return Err(err(format!("{}Index {} out of bounds (array axis {} has length {})", pre, shown, axis, len)));
        }
        Ok(j as usize)
    };
    let number = |n: &Number| -> Result<usize, Control> {
        let x = n.to_f64();
        if !(x.is_finite() && x.fract() == 0.0) {
            return Err(err(format!(
                "{}index must be an integer, got {} — use floor(x), round(x) or trunc(x) on purpose",
                pre, n
            )));
        }
        one(x, n)
    };
    match idx {
        SynValue::Number(n) => Ok(vec![number(n)?]),
        SynValue::List(l) => list_values(l)
            .iter()
            .map(|v| match v {
                SynValue::Number(n) => number(n),
                other => Err(err(format!("{}an index must be an integer, got {}", pre, other.type_name()))),
            })
            .collect(),
        SynValue::Array(a) => match &**a {
            NdArray::Bool(_) => Err(err(match why {
                PosFor::Read => "an array is indexed by positions — for the elements where a mask is true: where(a, m)".to_string(),
                PosFor::Set => "set takes positions, not a mask — if_else(m, 0, a) builds the new array".to_string(),
                PosFor::Builtin(n) => {
                    format!("{} takes positions, not a mask — for the elements where a mask is true: where(a, m)", n)
                }
            })),
            NdArray::F64(x) => {
                if x.ndim() != 1 {
                    return Err(err(format!("{}an array index must be 1-D, got shape {:?}", pre, x.shape())));
                }
                x.iter()
                    .map(|&v| {
                        if !(v.is_finite() && v.fract() == 0.0) {
                            return Err(err(format!("{}an array index must hold whole numbers, got {} — round first", pre, v)));
                        }
                        one(v, &v)
                    })
                    .collect()
            }
        },
        other => Err(err(format!("{}an index must be an integer, got {}", pre, other.type_name()))),
    }
}

/// `a[[1, 0]]`, `a[array([0, 3])]`: las filas en esas posiciones (como `take(a, …, axis = 0)`).
/// Un índice que no es número llega acá; el número sigue por `index_row`.
#[inline(never)]
pub fn index_by(a: &NdArray, idx: &SynValue) -> Result<SynValue, Control> {
    if a.ndim() == 0 {
        return Err(err("cannot index a 0-dimensional array"));
    }
    let pos = positions(idx, a.shape()[0], 0, PosFor::Read)?;
    Ok(take_axis(a, &pos, 0))
}

/// Las posiciones `pos` del eje `axis`, en orden, con el tipo de elemento.
pub fn take_axis(a: &NdArray, pos: &[usize], axis: usize) -> SynValue {
    nd_value_of(nd_map!(a, |x| x.select(Axis(axis), pos)))
}

/// Un paso de fila del camino de un `set` (`set M[i][j]`, R5): por el camino no viaja la fila (una
/// copia por escritura) sino una FICHA, un array vacío propio que la hoja reconoce; la entrada dice
/// de qué array (o de qué ficha de más arriba) y en qué posición. La hoja escribe el elemento
/// directo en el array de la variable. La entrada guarda la ficha viva, así que su dirección no se
/// reusa: una que quedó de un `set` que falló no se confunde con otra.
struct RowPlace {
    token: crate::types::Obj<NdArray>,
    parent: crate::types::Obj<NdArray>,
    at: usize,
}

/// Lo que el camino de un `set` sobre arrays deja para la hoja: las fichas de las filas y los arrays
/// exportados por un módulo, cuya vista en el mapa del módulo es un dueño más que el lugar (B1 de la
/// auditoría de v0.6.55). Cada entrada guarda una referencia, que la hoja descuenta al sacarla.
struct Places {
    rows: Vec<RowPlace>,
    views: Vec<crate::types::Obj<NdArray>>,
    /// Cuántas entradas disparan la limpieza (`prune`): `PLACES_CAP`, o el doble de las vivas.
    limit: usize,
}

thread_local! {
    static PLACES: std::cell::RefCell<Places> =
        const { std::cell::RefCell::new(Places { rows: Vec::new(), views: Vec::new(), limit: PLACES_CAP }) };
}

/// Al llegar a este tope se descartan las entradas muertas: las de `set` que fallaron a mitad de
/// camino (una entrada vieja sólo cuesta una copia del array en el próximo `set`, porque suma un
/// dueño). Las de una sentencia en curso no se tocan nunca (M11 de la ronda 2, M17 de la ronda 3):
/// están acotadas por la profundidad de las sentencias en curso, y el tope sólo dispara la limpieza.
const PLACES_CAP: usize = 64;

/// Una ficha viva tiene otro dueño además de la entrada (el valor que recorre el camino); una muerta,
/// no. Una vista muerta es la de un array que ya no tiene nadie más. Las vivas quedan; si son muchas
/// (una recursión con la llamada en el índice), el próximo disparo espera al doble, para que limpiar
/// no cueste en cada `set`.
#[cold]
#[inline(never)]
fn prune(s: &mut Places) {
    s.rows.retain(|e| crate::types::Obj::strong_count(&e.token) > 1);
    s.views.retain(|v| crate::types::Obj::strong_count(v) > 1);
    s.limit = PLACES_CAP.max(2 * s.rows.len().max(s.views.len()));
}

/// Después de un error que el programa atrapa (`recover`, `assert_error`) o que termina una unidad de
/// trabajo de un hilo que sigue vivo (`serve`): las entradas de los `set` que fallaron a mitad de camino
/// ya están muertas (sus fichas cayeron al propagarse el error) y cada una retiene una copia entera
/// del array como dueña (N6 de la ronda 4). Las de las sentencias en curso de más afuera siguen vivas
/// y quedan. De paso el tope vuelve a bajar (M24). Frío: sólo corre después de un error.
#[cold]
#[inline(never)]
pub fn drop_dead_places() {
    PLACES.with(|s| {
        let mut s = s.borrow_mut();
        if !s.rows.is_empty() || !s.views.is_empty() || s.limit != PLACES_CAP {
            prune(&mut s);
        }
    });
}

/// La raíz y las posiciones de una ficha (de afuera hacia adentro); `None` si `a` no es una ficha.
fn row_chain(rows: &[RowPlace], a: &crate::types::Obj<NdArray>) -> Option<(crate::types::Obj<NdArray>, Vec<usize>)> {
    let mut cur = a;
    let mut prefix = Vec::new();
    while let Some(e) = rows.iter().find(|e| crate::types::Obj::ptr_eq(&e.token, cur)) {
        prefix.push(e.at);
        cur = &e.parent;
    }
    if prefix.is_empty() {
        return None;
    }
    prefix.reverse();
    Some((cur.clone(), prefix))
}

/// La sub-vista en `prefix` (una posición por eje, desde el primero).
fn sub_view<'a, T>(x: &'a ArrayD<T>, prefix: &[usize]) -> ndarray::ArrayViewD<'a, T> {
    let mut v = x.view();
    for &i in prefix {
        v = v.index_axis_move(Axis(0), i);
    }
    v
}

fn sub_view_mut<'a, T>(x: &'a mut ArrayD<T>, prefix: &[usize]) -> ndarray::ArrayViewMutD<'a, T> {
    let mut v = x.view_mut();
    for &i in prefix {
        v = v.index_axis_move(Axis(0), i);
    }
    v
}

/// `with_unique_binding` (intérprete): el array de una exportación de un módulo, al que la vista del
/// mapa también apunta. La hoja cuenta esa vista como dueña (B1).
#[inline(never)]
pub fn note_module_view(a: &crate::types::Obj<NdArray>) {
    PLACES.with(|s| {
        let mut s = s.borrow_mut();
        if s.views.len() >= s.limit {
            prune(&mut s);
        }
        s.views.push(a.clone());
    });
}

/// Un paso `[i]` del camino de un `set` sobre un array (`place_index_step`): la ficha de la fila
/// `i`, o el elemento si la fila es un número (la hoja dará entonces el error de siempre).
#[inline(never)]
pub fn place_row(parent: &SynValue, idx: &SynValue) -> Result<SynValue, Control> {
    let SynValue::Array(p) = parent else {
        return Err(err(format!("Cannot index into {}", parent.type_name())));
    };
    let (root, prefix) = PLACES.with(|s| row_chain(&s.borrow().rows, p)).unwrap_or_else(|| (p.clone(), Vec::new()));
    let shape = &root.shape()[prefix.len()..];
    if shape.is_empty() {
        return Err(err("cannot index a 0-dimensional array"));
    }
    if !matches!(idx, SynValue::Number(_)) {
        return Err(err(
            "set: a list of positions only goes in the last index — set M[[0, 2]] to rows, or M[i][j] one by one",
        ));
    }
    let at = positions(idx, shape[0], 0, PosFor::Set)?[0];
    if shape.len() == 1 {
        return Ok(match &*root {
            NdArray::F64(x) => syn_float(sub_view(x, &prefix)[[at]]),
            NdArray::Bool(x) => syn_bool(sub_view(x, &prefix)[[at]]),
        });
    }
    let token = crate::types::Obj::new(NdArray::F64(ArrayD::zeros(IxDyn(&[0]))));
    PLACES.with(|s| {
        let mut s = s.borrow_mut();
        if s.rows.len() >= s.limit {
            prune(&mut s);
        }
        s.rows.push(RowPlace { token: token.clone(), parent: p.clone(), at });
    });
    Ok(SynValue::Array(token))
}

/// Lo que se escribe, ya convertido al tipo del array.
enum Payload {
    F64(f64),
    Bool(bool),
    F64s(ArrayD<f64>),
    Bools(ArrayD<bool>),
}

impl Payload {
    fn of(value: &SynValue, mask: bool) -> Result<Payload, Control> {
        let value = crate::labels::unwrap(value);
        let shown = |v: &SynValue| match v {
            SynValue::Number(n) => n.to_string(),
            SynValue::Bool(b) => b.to_string(),
            SynValue::Array(a) if a.dtype() == "bool" => "a mask".to_string(),
            SynValue::Array(_) => "an f64 array".to_string(),
            o => o.type_name().to_string(),
        };
        Ok(match (mask, value) {
            (_, SynValue::List(_)) => return Err(err("set: make the list an array first: array(xs)")),
            (false, SynValue::Number(n)) => Payload::F64(n.to_f64()),
            (false, SynValue::Array(a)) if a.dtype() == "f64" => Payload::F64s(a.to_f64().into_owned()),
            (false, SynValue::Bool(_)) => return Err(err("an f64 array holds numbers, got bool — use 1.0")),
            (false, SynValue::Array(_)) => return Err(err("an f64 array holds numbers, got a mask — use m * 1.0")),
            (false, o) => return Err(err(format!("an f64 array holds numbers, got {}", shown(o)))),
            (true, SynValue::Bool(b)) => Payload::Bool(*b),
            (true, SynValue::Array(a)) => match &**a {
                NdArray::Bool(m) => Payload::Bools(m.clone()),
                NdArray::F64(_) => return Err(err("a mask holds true or false, got an f64 array")),
            },
            (true, o) => return Err(err(format!("a mask holds true or false, got {}", shown(o)))),
        })
    }

    fn shape(&self) -> Option<&[usize]> {
        match self {
            Payload::F64s(a) => Some(a.shape()),
            Payload::Bools(a) => Some(a.shape()),
            _ => None,
        }
    }
}

/// Escribe `p` en las posiciones `pos` del primer eje de `x` (la región es `[k] ++ shape[1..]`, o
/// `shape[1..]` con un índice solo). Las formas ya están verificadas.
fn write_region<T: Copy>(mut x: ndarray::ArrayViewMutD<T>, pos: &[usize], single: bool, scalar: Option<T>, arr: Option<&ArrayD<T>>) {
    let region: Vec<usize> = if single {
        x.shape()[1..].to_vec()
    } else {
        std::iter::once(pos.len()).chain(x.shape()[1..].iter().copied()).collect()
    };
    let src = arr.map(|a| a.broadcast(IxDyn(&region)).expect("forma verificada"));
    for (n, &p) in pos.iter().enumerate() {
        let mut dst = x.index_axis_mut(Axis(0), p);
        match (&scalar, &src) {
            (Some(v), _) => dst.fill(*v),
            (None, Some(s)) if single => dst.assign(s),
            (None, Some(s)) => dst.assign(&s.index_axis(Axis(0), n)),
            (None, None) => {}
        }
    }
}

/// Lo que la hoja sabe de la variable raíz (ver `set_index`).
pub struct Rooted {
    /// Cuántos índices van de la variable a la hoja; `None` si el camino pasa por un campo.
    pub depth: Option<usize>,
    /// El array que tiene ahora la variable (su dirección), si tiene uno.
    pub now: Option<usize>,
    /// Con `--labels`: `rebound` e `in_use` salen como diagnóstico del sistema de etiquetas (el
    /// programa ve el texto fijo de corte, el operador el motivo; M16 de la ronda 3). Su texto sólo
    /// nombra la variable.
    pub labels: bool,
    /// La variable tiene el array dentro de un envoltorio `Private` que alguien más comparte (un
    /// alias tomado a mitad de la sentencia, M21 de la ronda 4): `in_use`, como sin etiquetas.
    pub shared: bool,
}

/// Cuántas filas recorrió el camino hasta la ficha `obj` (0 si no es una ficha).
pub fn chain_len(obj: &SynValue) -> usize {
    let SynValue::Array(a) = obj else { return 0 };
    PLACES.with(|s| row_chain(&s.borrow().rows, a).map_or(0, |(_, p)| p.len()))
}

/// `set a[idx] to value` (la hoja; `set_leaf_index`): escribe en el lugar el array que el camino
/// dejó único. Si `a` es la ficha de una fila (`set M[i][j]`), escribe en el array de la variable,
/// en esa fila. `root`: el nombre de la variable, para los errores. `rooted`: lo que se sabe de la
/// variable raíz ahora (B2 de la ronda 2).
#[inline(never)]
pub fn set_index(
    obj: &SynValue,
    idx: &SynValue,
    value: SynValue,
    root: Option<&str>,
    rooted: Rooted,
) -> Result<SynValue, Control> {
    let SynValue::Array(a) = obj else {
        return Err(err(format!("Cannot set index on {}", obj.type_name())));
    };
    // Las entradas de ESTA escritura salen (y sus referencias con ellas); las de otra, no: un `set`
    // dentro de un índice (`set M[0][f()]` con `f` que escribe otro array) no le borra el camino.
    let (chain, view) = PLACES.with(|s| {
        let mut s = s.borrow_mut();
        let chain = row_chain(&s.rows, a);
        if let Some((r, _)) = &chain {
            // Las fichas de esta cadena: de `a` hacia arriba hasta la raíz.
            let mut cur = a.clone();
            while let Some(k) = s.rows.iter().position(|e| crate::types::Obj::ptr_eq(&e.token, &cur)) {
                let e = s.rows.swap_remove(k);
                if crate::types::Obj::ptr_eq(&e.parent, r) {
                    break;
                }
                cur = e.parent;
            }
        }
        let target = chain.as_ref().map_or(a, |(r, _)| r);
        let view = match s.views.iter().position(|v| crate::types::Obj::ptr_eq(v, target)) {
            Some(k) => {
                s.views.swap_remove(k);
                true
            }
            None => false,
        };
        (chain, view)
    });
    let (target, prefix): (&crate::types::Obj<NdArray>, &[usize]) = match &chain {
        Some((r, p)) => (r, p),
        None => (a, &[]),
    };
    // B2 (ronda 2): si la raíz de la cadena es el array de la variable al empezar el camino, la
    // variable tiene que seguir teniéndolo. Un índice que la religó (y guardó el array viejo en otra)
    // haría caer la escritura en ese alias, y con `--labels` un valor privado en un array público.
    let direct = rooted.depth == Some(prefix.len() + 1);
    if direct && rooted.now != Some(crate::types::Obj::as_ptr(target) as usize) {
        return Err(sys(rebound(root), rooted.labels));
    }
    // Con `--labels` la variable tiene un envoltorio `Private`, y un alias tomado en el índice comparte
    // el envoltorio, no el array: la cuenta del array no lo ve.
    if direct && rooted.shared {
        return Err(sys(in_use(), rooted.labels));
    }

    // Los dueños del array de la variable: su lugar y la referencia de esta escritura (la del camino,
    // o la raíz de la cadena), más la vista del módulo si es una exportación. Si hay otro (un alias
    // tomado a mitad de la sentencia, la reentrada), no se escribe.
    let owners = if view { 3 } else { 2 };
    if crate::types::Obj::strong_count(target) != owners {
        return Err(sys(in_use(), rooted.labels));
    }
    let shape = &target.shape()[prefix.len()..];
    if shape.is_empty() {
        return Err(err("cannot index a 0-dimensional array"));
    }
    let single = matches!(idx, SynValue::Number(_));
    let pos = positions(idx, shape[0], 0, PosFor::Set)?;
    let payload = Payload::of(&value, target.dtype() == "bool")?;
    let sub = &shape[1..];
    let region: Vec<usize> =
        if single { sub.to_vec() } else { std::iter::once(pos.len()).chain(sub.iter().copied()).collect() };
    if let Some(vs) = payload.shape() {
        if broadcast_shape(vs, &region).as_deref() != Some(region.as_slice()) {
            let what = if single { if sub.is_empty() { "the element is a number" } else { "the row has shape" } } else { "the positions have shape" };
            let shape = if single && sub.is_empty() { String::new() } else { format!(" {:?}", region) };
            // Las posiciones resueltas, todas (M18 de la ronda 3): `T[-1][0]` sale `T[1][0]`.
            let path: String = prefix.iter().map(|i| format!("[{}]", i)).collect();
            let leaf = if single { pos[0].to_string() } else { format!("{:?}", pos) };
            return Err(err(format!(
                "set {}{}[{}]: {}{}, got {:?}",
                root.unwrap_or("a"),
                path,
                leaf,
                what,
                shape,
                vs
            )));
        }
    }
    // SAFETY: la cuenta es exacta (arriba) y ninguna de esas referencias se lee mientras se escribe:
    // el lugar está quieto hasta que termine la sentencia, el valor ya se copió a `payload` y las
    // posiciones ya están calculadas. Que el otro dueño sea el lugar lo dice `rooted` (arriba) cuando
    // el camino va de la variable al array sólo por índices; a través de una lista o un mapa
    // (`set L[0][f()]`) la cuenta no lo distingue, como con listas (faltantes: evaluar los índices
    // antes del camino); con `--labels`, ahí un valor privado sólo pasa con índices que no corren
    // código (`set_leaf_index`).
    let t = unsafe { crate::types::Obj::get_mut_with_owners(target, owners) }.ok_or_else(|| sys(in_use(), rooted.labels))?;
    match (t, payload) {
        (NdArray::F64(x), Payload::F64(v)) => write_region(sub_view_mut(x, prefix), &pos, single, Some(v), None),
        (NdArray::F64(x), Payload::F64s(s)) => write_region(sub_view_mut(x, prefix), &pos, single, None, Some(&s)),
        (NdArray::Bool(x), Payload::Bool(v)) => write_region(sub_view_mut(x, prefix), &pos, single, Some(v), None),
        (NdArray::Bool(x), Payload::Bools(s)) => write_region(sub_view_mut(x, prefix), &pos, single, None, Some(&s)),
        _ => unreachable!("Payload::of sigue el tipo del array"),
    }
    Ok(value)
}

#[cold]
fn rebound(root: Option<&str>) -> Control {
    err(format!(
        "set: the index changed '{}' while it was being written (it now holds another value) — compute the index into a variable first",
        root.unwrap_or("a")
    ))
}

/// Con `--labels`, un error de la escritura que es un diagnóstico del sistema (`from_labels`): no se
/// redacta ni se atrapa, y su texto va al operador.
#[cold]
fn sys(e: Control, labels: bool) -> Control {
    match e {
        Control::Error(mut r) if labels => {
            r.from_labels = true;
            Control::Error(r)
        }
        other => other,
    }
}

#[cold]
fn in_use() -> Control {
    err("set: the array is in use elsewhere in this statement and cannot be written in place — an index or value that reads or writes the same array: compute it into a variable first")
}

#[cfg(test)]
mod tests {
    /// El único `unsafe` de este archivo (`get_mut_with_owners` en `set_index`) con los casos que lo
    /// cuidan: escritura en el lugar, un alias que tiene que copiarse, el alias tomado en el índice
    /// (`in_use`), una fila y la religadura en el índice; con y sin `--labels`. Pensado para Miri
    /// (`cargo +nightly miri test -p synsema-core --lib arrays::tests`): ningún acceso inválido.
    #[test]
    fn writing_in_place_with_the_shared_reference() {
        let src = "let A be zeros([2, 3])
set A[0][1] to 5
let B be A
set A[1][2] to 7
print(B[1][2])
print(A[1][2])
let keep be nothing
task grab()
    set keep to A
    give 0
try
    set A[grab()][0] to 1
recover e
    print(\"in use\")
task rebind()
    set A to zeros([2, 3])
    give 1
try
    set A[rebind()][1] to 9
recover e
    print(\"rebound\")
set A[1][1] to 9
print(A)
set A[0] to array([1, 2, 3])
print(A[0])";
        let want = ["0.0", "7.0", "in use", "rebound", "[[0, 0, 0], [0, 9, 0]]", "[1, 2, 3]"];
        let r = crate::interpreter::run_source(src, "<arrays>");
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, want);
        let program = crate::parser::parse_source(src, "<arrays>").unwrap();
        let mut interp = crate::interpreter::Interpreter::new();
        interp.set_labels(true);
        assert!(interp.execute(&program).is_ok());
        assert_eq!(interp.output, want);
    }
}
