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

use ndarray::{ArrayD, IxDyn, Zip};
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

/// Registra los nueve builtins (lo llaman `engine.rs` y `synsema-wasm`).
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
