//! Arrays elemento a elemento (v0.6.55, ítem 1): `dtype`, `equal`, `not_equal`, `logical_and`,
//! `logical_or`, `logical_not`, `if_else`, `maximum`, `minimum`. Puros, sin capability; compilan
//! para wasm.
//!
//! Viven en stdlib y no en `synsema-core/src/arrays.rs` por lo mismo que `bits.rs`: código nuevo en
//! el núcleo mueve el inlining del intérprete caliente (`specs/donde-nace-cada-cosa.md`). Lo que
//! comparten con el núcleo (el broadcasting, el operando como `f64`) es `synsema_core::arrays`.
//!
//! Las reglas son las de `specs/v0.6.55-diseno.md`: una máscara en una cuenta es 0/1 (R2), las
//! funciones `logical_*` y la condición de `if_else` piden máscaras, y una lista nunca se convierte
//! sola en array (el error dice `array(xs)`).

use std::rc::Rc;

use ndarray::{ArrayD, Dimension, IxDyn, Zip};
use synsema_core::arrays::{broadcast_shape, elem_operand, zip_broadcast};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_array, syn_bool, syn_float, syn_mask, syn_text, NdArray, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn arity(args: &[SynValue], n: usize, name: &str) -> Result<(), Control> {
    if args.len() != n {
        return Err(err(format!("{} expects {} argument(s), got {}", name, n, args.len())));
    }
    Ok(())
}

/// Registra los builtins (lo llaman `engine.rs` y `synsema-wasm`).
pub fn register_ndarray_builtins(interp: &Interpreter) {
    interp.register_builtin("dtype", 1, Rc::new(|_i, a, _l| dtype(a)));
    interp.register_builtin("equal", 2, Rc::new(|_i, a, _l| equal(a, "equal", |x, y| x == y)));
    interp.register_builtin("not_equal", 2, Rc::new(|_i, a, _l| equal(a, "not_equal", |x, y| x != y)));
    interp.register_builtin("logical_and", 2, Rc::new(|_i, a, _l| logical2(a, "logical_and", |x, y| x && y)));
    interp.register_builtin("logical_or", 2, Rc::new(|_i, a, _l| logical2(a, "logical_or", |x, y| x || y)));
    interp.register_builtin("logical_not", 1, Rc::new(|_i, a, _l| logical_not(a)));
    interp.register_builtin("if_else", 3, Rc::new(|_i, a, _l| if_else(a)));
    interp.register_builtin("maximum", 2, Rc::new(|_i, a, _l| extreme(a, "maximum", f64::max)));
    interp.register_builtin("minimum", 2, Rc::new(|_i, a, _l| extreme(a, "minimum", f64::min)));
    // Ítems 4, 7 y 8: reemplazan el `transpose` y el `matmul` del núcleo (que siguen siendo el caso
    // de un argumento y el 2-D) y suman los bytes.
    interp.register_builtin("transpose", -1, Rc::new(|_i, a, _l| transpose(a)));
    interp.register_builtin("matmul", 2, Rc::new(|_i, a, _l| matmul(a)));
    interp.register_builtin("array_to_bytes", -1, Rc::new(|_i, a, _l| array_to_bytes(a)));
    interp.register_builtin("array_from_bytes", 2, Rc::new(|i, a, _l| array_from_bytes(i, a)));
}

/// `dtype(a)`: `"f64"` o `"bool"` (R1).
pub fn dtype(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "dtype")?;
    match &args[0] {
        SynValue::Array(a) => Ok(syn_text(a.dtype())),
        other => Err(err(format!("dtype expects an array, got {}", other.type_name()))),
    }
}

/// Los dos operandos como `f64` (array o número; una máscara es 0/1). Al menos uno tiene que ser
/// array, salvo en `equal`/`maximum` de dos números, que da un escalar.
fn operands<'a>(
    args: &'a [SynValue],
    name: &str,
) -> Result<(std::borrow::Cow<'a, ArrayD<f64>>, std::borrow::Cow<'a, ArrayD<f64>>), Control> {
    let one = |v: &'a SynValue| match elem_operand(v) {
        Some(a) => Ok(a),
        None => Err(match v {
            SynValue::List(_) => err(format!("{}: make the list an array first: array(xs)", name)),
            o => err(format!("{} expects arrays or numbers, got {}", name, o.type_name())),
        }),
    };
    Ok((one(&args[0])?, one(&args[1])?))
}

fn both_numbers(args: &[SynValue]) -> bool {
    matches!((&args[0], &args[1]), (SynValue::Number(_), SynValue::Number(_)))
}

/// `equal`/`not_equal`: la máscara de la igualdad elemento a elemento (un `NaN` nunca es igual).
fn equal(args: &[SynValue], name: &str, f: fn(f64, f64) -> bool) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    let (a, b) = operands(args, name)?;
    let m = zip_broadcast(&a, &b, f).map_err(|e| prefixed(e, name))?;
    if both_numbers(args) {
        return Ok(syn_bool(m.iter().next().copied().unwrap_or(false)));
    }
    Ok(syn_mask(m))
}

/// `maximum`/`minimum`: elemento a elemento; un `NaN` se propaga (numpy).
fn extreme(args: &[SynValue], name: &str, f: fn(f64, f64) -> f64) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    let (a, b) = operands(args, name)?;
    let r = zip_broadcast(&a, &b, |x, y| if x.is_nan() || y.is_nan() { f64::NAN } else { f(x, y) })
        .map_err(|e| prefixed(e, name))?;
    if both_numbers(args) {
        return Ok(syn_float(r.iter().next().copied().unwrap_or(f64::NAN)));
    }
    Ok(syn_array(r))
}

/// El error de forma del broadcasting, con el nombre de la función adelante.
fn prefixed(e: Control, name: &str) -> Control {
    match e {
        Control::Error(mut r) => {
            r.message = format!("{}: {}", name, r.message);
            Control::Error(r)
        }
        other => other,
    }
}

/// Un argumento que tiene que ser máscara: con un `f64`, el error sugiere comparar primero.
fn mask_arg<'a>(v: &'a SynValue, name: &str) -> Result<&'a ArrayD<bool>, Control> {
    match v {
        SynValue::Array(a) => match &**a {
            NdArray::Bool(m) => Ok(m),
            NdArray::F64(_) => Err(err(format!(
                "{} expects masks (bool arrays), got a f64 array — compare first: a > 0",
                name
            ))),
        },
        o => Err(err(format!("{} expects masks (bool arrays), got {}", name, o.type_name()))),
    }
}

fn logical2(args: &[SynValue], name: &str, f: fn(bool, bool) -> bool) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    let (a, b) = (mask_arg(&args[0], name)?, mask_arg(&args[1], name)?);
    Ok(syn_mask(zip_broadcast(a, b, f).map_err(|e| prefixed(e, name))?))
}

fn logical_not(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "logical_not")?;
    Ok(syn_mask(mask_arg(&args[0], "logical_not")?.mapv(|x| !x)))
}

/// `if_else(m, x, y)`: el `np.where(c, x, y)` de numpy (R7: `where` ya es de Synsema). Toma `x`
/// donde `m` es verdadero y `y` donde no, con broadcasting entre los tres. Da `f64`, salvo que los
/// dos lados sean máscaras: entonces una máscara.
pub fn if_else(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 3, "if_else")?;
    let m = mask_arg(&args[0], "if_else")?;
    fn side_masks(v: &SynValue) -> Option<&ArrayD<bool>> {
        match v {
            SynValue::Array(a) => match &**a {
                NdArray::Bool(b) => Some(b),
                NdArray::F64(_) => None,
            },
            _ => None,
        }
    }
    let shape3 = |x: &[usize], y: &[usize]| -> Result<Vec<usize>, Control> {
        broadcast_shape(m.shape(), x)
            .and_then(|s| broadcast_shape(&s, y))
            .ok_or_else(|| {
                err(format!(
                    "if_else: the mask has shape {:?} and the values {:?} and {:?} — they are not broadcastable",
                    m.shape(),
                    x,
                    y
                ))
            })
    };
    if let (Some(x), Some(y)) = (side_masks(&args[1]), side_masks(&args[2])) {
        let shape = shape3(x.shape(), y.shape())?;
        let (vm, vx, vy) = (bview(m, &shape), bview(x, &shape), bview(y, &shape));
        return Ok(syn_mask(Zip::from(vm).and(vx).and(vy).map_collect(|&c, &p, &q| if c { p } else { q })));
    }
    fn one(v: &SynValue) -> Result<std::borrow::Cow<'_, ArrayD<f64>>, Control> {
        elem_operand(v).ok_or_else(|| match v {
            SynValue::List(_) => err("if_else: make the list an array first: array(xs)"),
            o => err(format!("if_else expects arrays or numbers for the values, got {}", o.type_name())),
        })
    }
    let (x, y) = (one(&args[1])?, one(&args[2])?);
    let shape = shape3(x.shape(), y.shape())?;
    let (vm, vx, vy) = (bview(m, &shape), bview(&x, &shape), bview(&y, &shape));
    Ok(syn_array(Zip::from(vm).and(vx).and(vy).map_collect(|&c, &p, &q| if c { p } else { q })))
}

fn bview<'a, T>(a: &'a ArrayD<T>, shape: &[usize]) -> ndarray::ArrayViewD<'a, T> {
    a.broadcast(IxDyn(shape)).expect("forma ya verificada")
}

// =========================================================
// Ítem 4: `transpose(a, ejes)` (np.transpose)
// =========================================================

/// `transpose(a)` invierte los ejes (núcleo); `transpose(a, [0, 2, 1])` los reordena. Un eje
/// negativo cuenta desde el final. Conserva el tipo de elemento.
pub fn transpose(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.len() != 2 {
        return synsema_core::arrays::transpose(args);
    }
    let a = match &args[0] {
        SynValue::Array(a) => a,
        other => return Err(err(format!("transpose expects an array, got {}", other.type_name()))),
    };
    let axes = permutation(&args[1], a.ndim())?;
    Ok(match &**a {
        NdArray::F64(x) => syn_array(x.view().permuted_axes(IxDyn(&axes)).to_owned()),
        NdArray::Bool(x) => syn_mask(x.view().permuted_axes(IxDyn(&axes)).to_owned()),
    })
}

/// Los ejes de `transpose` como una permutación de `0..n`.
fn permutation(v: &SynValue, n: usize) -> Result<Vec<usize>, Control> {
    let SynValue::List(l) = v else {
        return Err(err(format!("transpose: axes must be a list of integers, got {}", v.type_name())));
    };
    let bad = || err(format!("transpose: axes must be a permutation of 0..{}, got {}", n.saturating_sub(1), v));
    let mut out = Vec::new();
    for it in synsema_core::synlist::list_values(l).iter() {
        let SynValue::Number(k) = it else { return Err(bad()) };
        let k = k.to_i64_trunc().filter(|_| k.is_integer()).ok_or_else(bad)?;
        let k = if k < 0 { k + n as i64 } else { k };
        if k < 0 || k >= n as i64 {
            return Err(bad());
        }
        out.push(k as usize);
    }
    let mut seen = vec![false; n];
    if out.len() != n || out.iter().any(|&k| std::mem::replace(&mut seen[k], true)) {
        return Err(bad());
    }
    Ok(out)
}

// =========================================================
// Ítem 7: `matmul` por lotes (np.matmul con 3-D o más)
// =========================================================

/// `matmul(a, b)`: el 2-D es el del núcleo; con más ejes, un producto por lote, y los ejes de lote
/// hacen broadcasting como numpy (`[1, 3, 4]` con `[7, 4, 5]` da `[7, 3, 5]`). `Par::Seq` (el
/// paralelismo es de 0.6.56).
pub fn matmul(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "matmul")?;
    let (SynValue::Array(a), SynValue::Array(b)) = (&args[0], &args[1]) else {
        return synsema_core::arrays::matmul(args);
    };
    if a.ndim() < 2 || b.ndim() < 2 || (a.ndim() == 2 && b.ndim() == 2) {
        return synsema_core::arrays::matmul(args);
    }
    let (a, b) = (a.to_f64(), b.to_f64());
    batched_matmul(&a, &b)
}

#[inline(never)]
fn batched_matmul(a: &ArrayD<f64>, b: &ArrayD<f64>) -> Result<SynValue, Control> {
    let (na, nb) = (a.ndim(), b.ndim());
    let (m, k) = (a.shape()[na - 2], a.shape()[na - 1]);
    let (k2, p) = (b.shape()[nb - 2], b.shape()[nb - 1]);
    if k != k2 {
        return Err(err(format!(
            "matmul: incompatible shapes {:?} and {:?} (cols of A must equal rows of B)",
            a.shape(),
            b.shape()
        )));
    }
    let batch = broadcast_shape(&a.shape()[..na - 2], &b.shape()[..nb - 2]).ok_or_else(|| {
        err(format!(
            "matmul: the batch axes of {:?} and {:?} are not broadcastable",
            a.shape(),
            b.shape()
        ))
    })?;
    let with = |x: usize, y: usize| batch.iter().copied().chain([x, y]).collect::<Vec<_>>();
    let av = bview(a, &with(m, k));
    let bv = bview(b, &with(k, p));
    let mut out: Vec<f64> = Vec::with_capacity(batch.iter().product::<usize>() * m * p);
    for idx in ndarray::indices(IxDyn(&batch)) {
        let (mut sa, mut sb) = (av.view(), bv.view());
        for &i in idx.slice() {
            sa = sa.index_axis_move(ndarray::Axis(0), i);
            sb = sb.index_axis_move(ndarray::Axis(0), i);
        }
        let fa = faer::Mat::<f64>::from_fn(m, k, |i, j| sa[[i, j]]);
        let fb = faer::Mat::<f64>::from_fn(k, p, |i, j| sb[[i, j]]);
        let mut c = faer::Mat::<f64>::zeros(m, p);
        faer::linalg::matmul::matmul(c.as_mut(), faer::Accum::Replace, fa.as_ref(), fb.as_ref(), 1.0, faer::Par::Seq);
        for i in 0..m {
            for j in 0..p {
                out.push(c[(i, j)]);
            }
        }
    }
    Ok(syn_array(ArrayD::from_shape_vec(IxDyn(&with(m, p)), out).expect("forma del lote")))
}

// =========================================================
// Ítem 8: arrays <-> bytes (little-endian, orden C)
// =========================================================

/// Nombre y bytes por elemento de `"f64"`, `"f32"` o `"bool"`.
fn elem_size(name: &str, t: &SynValue) -> Result<(&'static str, usize), Control> {
    match t {
        SynValue::Text(s) => match s.as_ref() {
            "f64" => Ok(("f64", 8)),
            "f32" => Ok(("f32", 4)),
            "bool" => Ok(("bool", 1)),
            other => Err(err(format!(
                "{}: unknown element type \"{}\" — \"f64\", \"f32\" or \"bool\"",
                name, other
            ))),
        },
        other => Err(err(format!(
            "{}: the element type is a text (\"f64\", \"f32\" or \"bool\"), got {}",
            name,
            other.type_name()
        ))),
    }
}

/// `array_to_bytes(a)` / `array_to_bytes(a, "f32")`: los elementos en orden C, little-endian. Sin
/// tipo, el del array (`f64` o `bool`). Una máscara como número es 0/1 (R2); `"bool"` pide una
/// máscara. A `f32` se redondea al más cercano.
pub fn array_to_bytes(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!("array_to_bytes expects 1 or 2 argument(s), got {}", args.len())));
    }
    let a = match &args[0] {
        SynValue::Array(a) => a,
        other => return Err(err(format!("array_to_bytes expects an array, got {}", other.type_name()))),
    };
    let t = match args.get(1) {
        Some(t) => elem_size("array_to_bytes", t)?.0,
        None => a.dtype(),
    };
    let out: Vec<u8> = match (t, &**a) {
        ("bool", NdArray::Bool(m)) => m.iter().map(|&x| x as u8).collect(),
        ("bool", NdArray::F64(_)) => {
            return Err(err(
                "array_to_bytes: \"bool\" is for masks and this array is f64 — compare first: a != 0",
            ))
        }
        ("f32", _) => a.to_f64().iter().flat_map(|&x| (x as f32).to_le_bytes()).collect(),
        _ => a.to_f64().iter().flat_map(|&x| x.to_le_bytes()).collect(),
    };
    Ok(synsema_core::types::syn_bytes(out))
}

/// `array_from_bytes(b, "f32", shape = [2, 3])`: el array de esos bytes (little-endian, orden C).
/// Sin `shape`, 1-D. `"f32"` es el formato de los bytes: el array es `f64` (hasta 0.6.56).
/// `"bool"` da una máscara y cada byte es 0 o 1.
pub fn array_from_bytes(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    let shape = interp.kwarg("shape");
    arity(args, 2, "array_from_bytes")?;
    let b = match &args[0] {
        SynValue::Bytes(b) => b,
        other => return Err(err(format!("array_from_bytes expects bytes, got {}", other.type_name()))),
    };
    let (t, size) = elem_size("array_from_bytes", &args[1])?;
    let shape = match &shape {
        Some(s) => {
            let shape = synsema_core::arrays::shape_from(s, "array_from_bytes")?;
            let need = shape.iter().try_fold(size, |acc, &d| acc.checked_mul(d));
            if need != Some(b.len()) {
                return Err(err(match need {
                    Some(n) => format!("array_from_bytes: shape {:?} needs {} bytes, got {}", shape, n, b.len()),
                    None => format!("array_from_bytes: shape {:?} is too large", shape),
                }));
            }
            shape
        }
        None => {
            if b.len() % size != 0 {
                return Err(err(format!(
                    "array_from_bytes: {} bytes is not a whole number of {} values ({} bytes each)",
                    b.len(),
                    t,
                    size
                )));
            }
            vec![b.len() / size]
        }
    };
    let dims = IxDyn(&shape);
    Ok(match t {
        "bool" => {
            if let Some((i, x)) = b.iter().enumerate().find(|(_, x)| **x > 1) {
                return Err(err(format!(
                    "array_from_bytes: byte {} at position {} is not a bool (0 or 1)",
                    x, i
                )));
            }
            syn_mask(ArrayD::from_shape_vec(dims, b.iter().map(|&x| x == 1).collect()).expect("forma verificada"))
        }
        "f32" => syn_array(
            ArrayD::from_shape_vec(
                dims,
                b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f64).collect(),
            )
            .expect("forma verificada"),
        ),
        _ => syn_array(
            ArrayD::from_shape_vec(
                dims,
                b.chunks_exact(8).map(|c| f64::from_le_bytes(c.try_into().expect("8 bytes"))).collect(),
            )
            .expect("forma verificada"),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_list;

    fn arr(xs: &[f64]) -> SynValue {
        syn_array(ArrayD::from_shape_vec(IxDyn(&[xs.len()]), xs.to_vec()).unwrap())
    }
    fn mask(xs: &[bool]) -> SynValue {
        syn_mask(ArrayD::from_shape_vec(IxDyn(&[xs.len()]), xs.to_vec()).unwrap())
    }
    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.message.clone(),
            Ok(v) => panic!("se esperaba un error, dio {}", v),
            Err(_) => panic!("otro control"),
        }
    }

    #[test]
    fn v0655_logical_on_a_f64_array_suggests_comparing() {
        let a = arr(&[1.0, 5.0]);
        assert_eq!(
            msg(logical2(&[a.clone(), a], "logical_and", |x, y| x && y)),
            "logical_and expects masks (bool arrays), got a f64 array — compare first: a > 0"
        );
    }

    #[test]
    fn v0655_equal_with_a_list_says_array() {
        let r = equal(&[arr(&[1.0, 5.0]), syn_list(vec![syn_float(1.0)])], "equal", |x, y| x == y);
        assert_eq!(msg(r), "equal: make the list an array first: array(xs)");
    }

    #[test]
    fn v0655_if_else_of_two_masks_is_a_mask() {
        let r = if_else(&[mask(&[true, false]), mask(&[true, true]), mask(&[false, false])]).ok().unwrap();
        assert_eq!(r.to_string(), "[true, false]");
    }
}
