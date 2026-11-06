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
use synsema_core::arrays::{broadcast_shape, out_num, positions, take_axis, zip_broadcast, zip_real, Num, PosFor, Real};
use synsema_core::by_num;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_array, syn_array32, syn_bool, syn_float, syn_mask, syn_text, NdArray, SynValue};

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
    interp.register_builtin("take", 2, Rc::new(|i, a, _l| take(i, a)));
    interp.register_builtin("index_add", 3, Rc::new(|i, a, _l| index_add(i, a)));
}

/// `dtype(a)`: `"f64"`, `"f32"` o `"bool"` (R1; `f32` desde 0.6.56).
pub fn dtype(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "dtype")?;
    match &args[0] {
        SynValue::Array(a) => Ok(syn_text(a.dtype())),
        other => Err(err(format!("dtype expects an array, got {}", other.type_name()))),
    }
}

/// Los dos operandos en el tipo `T` (array o número; una máscara es 0/1; el número ya en `T`: F3).
/// Al menos uno tiene que ser array (dos números los resuelven `equal`/`extreme` con los números del
/// lenguaje); el tipo lo eligió `out_num` (un `f32` con un `f64` es E1).
#[allow(clippy::type_complexity)]
fn operands<'a, T: Real>(
    args: &'a [SynValue],
    name: &str,
) -> Result<(std::borrow::Cow<'a, ArrayD<T>>, std::borrow::Cow<'a, ArrayD<T>>), Control> {
    let one = |v: &'a SynValue| match T::operand(v) {
        Some(a) => Ok(a),
        None => Err(match v {
            SynValue::List(_) => err(format!("{}: make the list an array first: array(xs)", name)),
            o => err(format!("{} expects arrays or numbers, got {}", name, o.type_name())),
        }),
    };
    Ok((one(&args[0])?, one(&args[1])?))
}

/// El tipo de salida de `equal`/`maximum`/…: error si no hay ningún array, o si mezclan `f32` y `f64`.
fn kind_of(args: &[SynValue], name: &str) -> Result<Num, Control> {
    if !matches!(args[0], SynValue::Array(_)) && !matches!(args[1], SynValue::Array(_)) {
        return Err(two_scalars(&args[0], &args[1], name));
    }
    out_num(name, &[&args[0], &args[1]])
}

/// Dos números (M4 de la auditoría de v0.6.55): su orden con los números del lenguaje, no por `f64`
/// (`equal(2**53 + 1, 2**53)` es `false`, como `==`; `maximum(2, 3)` es el entero `3`, como `max`).
/// `None` adentro: un `NaN`. `Ok(None)`: no son dos números.
fn two_numbers(args: &[SynValue], name: &str) -> Result<Option<Option<std::cmp::Ordering>>, Control> {
    let (SynValue::Number(a), SynValue::Number(b)) = (&args[0], &args[1]) else { return Ok(None) };
    if synsema_core::number::Number::mixes_decimal_float(a, b) {
        return Err(err(format!("{}: cannot mix a decimal and a float — convert one first", name)));
    }
    Ok(Some(a.partial_cmp_num(b)))
}

#[cold]
#[inline(never)]
fn two_scalars(a: &SynValue, b: &SynValue, name: &str) -> Control {
    let instead = match name {
        "equal" => "for two values use a == b",
        "not_equal" => "for two values use a != b",
        "maximum" => "for two numbers use max(a, b)",
        _ => "for two numbers use min(a, b)",
    };
    match (a, b) {
        (SynValue::List(_), _) | (_, SynValue::List(_)) => err(format!("{}: make the list an array first: array(xs)", name)),
        _ => err(format!("{} works on arrays (got {} and {}) — {}", name, a.type_name(), b.type_name(), instead)),
    }
}

/// `equal`/`not_equal`: la máscara de la igualdad elemento a elemento (un `NaN` nunca es igual).
fn equal(args: &[SynValue], name: &str, f: fn(f64, f64) -> bool) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    if let Some(o) = two_numbers(args, name)? {
        // `equal(nan, nan)` es `false` (diseño §3.1), como `f(nan, nan)`.
        let eq = o == Some(std::cmp::Ordering::Equal);
        return Ok(syn_bool(if name == "equal" { eq } else { !eq }));
    }
    // v0.6.56: en `f32` se compara en `f32` (`equal(w, 0.1)` sobre un `f32` 0.1 es verdadero).
    let k = kind_of(args, name)?;
    by_num!(k, T => {
        let (a, b) = operands::<T>(args, name)?;
        let m = zip_broadcast(&a, &b, |x: T, y: T| f(x.f(), y.f())).map_err(|e| prefixed(e, name))?;
        Ok(syn_mask(m))
    })
}

/// `maximum`/`minimum`: elemento a elemento; un `NaN` se propaga (numpy).
fn extreme(args: &[SynValue], name: &str, f: fn(f64, f64) -> f64) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    if let Some(o) = two_numbers(args, name)? {
        let (x, y) = (&args[0], &args[1]);
        return Ok(match o {
            None => syn_float(f64::NAN),
            Some(o) => {
                let first = if name == "maximum" { o != std::cmp::Ordering::Less } else { o != std::cmp::Ordering::Greater };
                if first { x.clone() } else { y.clone() }
            }
        });
    }
    let k = kind_of(args, name)?;
    by_num!(k, T => {
        let (a, b) = operands::<T>(args, name)?;
        let r = zip_real(&a, &b, |x, y| if x.is_nan() || y.is_nan() { f64::NAN } else { f(x, y) })
            .map_err(|e| prefixed(e, name))?;
        Ok(T::wrap(r))
    })
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
            other => Err(err(format!(
                "{} expects masks (bool arrays), got a {} array — compare first: a > 0",
                name,
                other.dtype()
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
                _ => None,
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
    fn one<T: Real>(v: &SynValue) -> Result<std::borrow::Cow<'_, ArrayD<T>>, Control> {
        T::operand(v).ok_or_else(|| match v {
            SynValue::List(_) => err("if_else: make the list an array first: array(xs)"),
            o => err(format!("if_else expects arrays or numbers for the values, got {}", o.type_name())),
        })
    }
    // v0.6.56: `if_else(m, w, 0)` es `f32`; con un `f32` y un `f64`, E1.
    let k = out_num("if_else", &[&args[1], &args[2]])?;
    by_num!(k, T => {
        let (x, y) = (one::<T>(&args[1])?, one::<T>(&args[2])?);
        let shape = shape3(x.shape(), y.shape())?;
        let (vm, vx, vy) = (bview(m, &shape), bview(&x, &shape), bview(&y, &shape));
        Ok(T::wrap(Zip::from(vm).and(vx).and(vy).map_collect(|&c, &p, &q| if c { p } else { q })))
    })
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
        NdArray::F32(x) => syn_array32(x.view().permuted_axes(IxDyn(&axes)).to_owned()),
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
/// hacen broadcasting como numpy (`[1, 3, 4]` con `[7, 4, 5]` da `[7, 3, 5]`). v0.6.57: cada producto en
/// el orden escrito de `synsema_core::matkernel`; con varios lotes, los lotes se reparten entre hilos
/// (cada producto en un hilo), así que los bits no dependen de cuántos hilos haya.
pub fn matmul(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "matmul")?;
    let (SynValue::Array(a), SynValue::Array(b)) = (&args[0], &args[1]) else {
        return synsema_core::arrays::matmul(args);
    };
    if a.ndim() == 1 || b.ndim() == 1 {
        return Err(matmul_vector_error(a.shape(), b.shape()));
    }
    if a.ndim() < 2 || b.ndim() < 2 || (a.ndim() == 2 && b.ndim() == 2) {
        return synsema_core::arrays::matmul(args);
    }
    // v0.6.56 (F7): `f32` en `f32` de punta a punta; con un `f64`, E1.
    by_num!(out_num("matmul", &[&args[0], &args[1]])?, T => {
        let (a, b) = (T::of_nd(a), T::of_nd(b));
        batched_matmul::<T>(&a, &b)
    })
}

/// `matmul` con un vector (N3 de la auditoría de v0.6.55): numpy lo acepta y quita el eje; acá la
/// forma es explícita, y el error dice cuál (`M @ v` es la línea más común de una red).
#[cold]
#[inline(never)]
fn matmul_vector_error(a: &[usize], b: &[usize]) -> Control {
    let hint = match (a.len(), b.len()) {
        (1, 1) => "for two vectors: dot(a, b)".to_string(),
        (_, 1) => format!(
            "for a matrix times a vector: matmul(M, reshape(v, [{}, 1])); for two vectors: dot(a, b)",
            b[0]
        ),
        _ => format!(
            "for a vector times a matrix: matmul(reshape(v, [1, {}]), M); for two vectors: dot(a, b)",
            a[0]
        ),
    };
    err(format!("matmul: expected a 2D array (matrix), got 1-D — {}", hint))
}

#[inline(never)]
fn batched_matmul<T: Real + synsema_core::matkernel::Elem>(a: &ArrayD<T>, b: &ArrayD<T>) -> Result<SynValue, Control> {
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
    let mut pairs = Vec::with_capacity(batch.iter().product::<usize>());
    for idx in ndarray::indices(IxDyn(&batch)) {
        let (mut sa, mut sb) = (av.view(), bv.view());
        for &i in idx.slice() {
            sa = sa.index_axis_move(ndarray::Axis(0), i);
            sb = sb.index_axis_move(ndarray::Axis(0), i);
        }
        let (sa, sb) = (sa.into_dimensionality::<ndarray::Ix2>(), sb.into_dimensionality::<ndarray::Ix2>());
        pairs.push((sa.expect("2-D del lote"), sb.expect("2-D del lote")));
    }
    let per = m * p;
    let mut out: Vec<T> = vec![<T as synsema_core::matkernel::Elem>::ZERO; pairs.len() * per];
    let cap = synsema_core::matkernel::thread_cap();
    let t = synsema_core::matkernel::batch_threads::<T>(pairs.len(), m * k * p, cap);
    // En wasm el `else` no tiene cuerpo (no hay hilos): el camino de un hilo se elige acá mismo y no
    // depende de que `batch_threads` devuelva 1 (si no, el lote saldría en ceros sin error).
    if t <= 1 || cfg!(target_family = "wasm") {
        for ((sa, sb), o) in pairs.iter().zip(out.chunks_mut(per.max(1))) {
            o.copy_from_slice(synsema_core::arrays::matmul_2d(sa.view(), sb.view(), cap).as_slice().expect("layout C"));
        }
    } else {
        #[cfg(not(target_family = "wasm"))]
        {
            let chunk = pairs.len().div_ceil(t);
            std::thread::scope(|s| {
                for (ps, os) in pairs.chunks(chunk).zip(out.chunks_mut(chunk * per)) {
                    s.spawn(move || {
                        for ((sa, sb), o) in ps.iter().zip(os.chunks_mut(per)) {
                            let c = synsema_core::arrays::matmul_2d(sa.view(), sb.view(), 1);
                            o.copy_from_slice(c.as_slice().expect("layout C"));
                        }
                    });
                }
            });
        }
    }
    Ok(T::wrap(ArrayD::from_shape_vec(IxDyn(&with(m, p)), out).expect("forma del lote")))
}

// =========================================================
// Ítem 8: arrays <-> bytes (little-endian, orden C)
// =========================================================

/// Nombre y bytes por elemento de `"f64"`, `"f32"`, `"bool"` y (v0.6.56, formatos de bytes:
/// diseño §3.7) `"f16"`, `"bf16"`.
fn elem_size(name: &str, t: &SynValue) -> Result<(&'static str, usize), Control> {
    match t {
        SynValue::Text(s) => match s.as_ref() {
            "f64" => Ok(("f64", 8)),
            "f32" => Ok(("f32", 4)),
            "bool" => Ok(("bool", 1)),
            "f16" => Ok(("f16", 2)),
            "bf16" => Ok(("bf16", 2)),
            other => Err(err(format!(
                "{}: dtype must be \"f64\", \"f32\", \"f16\", \"bf16\" or \"bool\", got \"{}\"",
                name, other
            ))),
        },
        other => Err(err(format!(
            "{}: dtype must be \"f64\", \"f32\", \"f16\", \"bf16\" or \"bool\", got {}",
            name,
            other.type_name()
        ))),
    }
}

/// Un elemento a 2 bytes, redondeado al más cercano desde su valor (sin pasar por otro tipo: un
/// `f64` va directo, sin doble redondeo); fuera de rango, ±inf.
fn half_bytes(a: &NdArray, bf: bool) -> Vec<u8> {
    fn put<T: Copy>(x: &ArrayD<T>, f: impl Fn(T) -> [u8; 2]) -> Vec<u8> {
        x.iter().flat_map(|&v| f(v)).collect()
    }
    match (a, bf) {
        (NdArray::F64(x), false) => put(x, |v| half::f16::from_f64(v).to_le_bytes()),
        (NdArray::F64(x), true) => put(x, |v| half::bf16::from_f64(v).to_le_bytes()),
        (NdArray::F32(x), false) => put(x, |v| half::f16::from_f32(v).to_le_bytes()),
        (NdArray::F32(x), true) => put(x, |v| half::bf16::from_f32(v).to_le_bytes()),
        (NdArray::Bool(m), false) => put(m, |v| half::f16::from_f32(v as u8 as f32).to_le_bytes()),
        (NdArray::Bool(m), true) => put(m, |v| half::bf16::from_f32(v as u8 as f32).to_le_bytes()),
    }
}

/// `array_to_bytes(a)` / `array_to_bytes(a, "f32")`: los elementos en orden C, little-endian. Sin
/// tipo, el del array (`f64`, `f32` o `bool`). Una máscara como número es 0/1 (R2); `"bool"` pide
/// una máscara. A `f32`, `f16` y `bf16` se redondea al más cercano.
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
        ("bool", other) => {
            return Err(err(format!(
                "array_to_bytes: \"bool\" is for masks and this array is {} — compare first: a != 0",
                other.dtype()
            )))
        }
        ("f32", _) => f32::of_nd(a).iter().flat_map(|&x| x.to_le_bytes()).collect(),
        ("f16", _) => half_bytes(a, false),
        ("bf16", _) => half_bytes(a, true),
        _ => a.numbers_f64().iter().flat_map(|&x| x.to_le_bytes()).collect(),
    };
    Ok(synsema_core::types::syn_bytes(out))
}

/// `array_from_bytes(b, "f32", shape = [2, 3])`: el array de esos bytes (little-endian, orden C).
/// Sin `shape`, 1-D. `"f32"` da un array `f32` (desde 0.6.56; antes, `f64`); `"f16"` y `"bf16"`
/// también dan `f32` (ensanchar es exacto). `"bool"` da una máscara y cada byte es 0 o 1.
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
        "f32" => syn_array32(
            ArrayD::from_shape_vec(dims, b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
                .expect("forma verificada"),
        ),
        "f16" => syn_array32(
            ArrayD::from_shape_vec(dims, b.chunks_exact(2).map(|c| half::f16::from_le_bytes([c[0], c[1]]).to_f32()).collect())
                .expect("forma verificada"),
        ),
        "bf16" => syn_array32(
            ArrayD::from_shape_vec(dims, b.chunks_exact(2).map(|c| half::bf16::from_le_bytes([c[0], c[1]]).to_f32()).collect())
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

// =========================================================
// Ítems 2 y 3: `take` e `index_add`
// =========================================================

/// El eje de `take`/`index_add` (`axis = k`, negativo desde el final), o el de siempre.
fn axis_kw(interp: &mut Interpreter, name: &str, ndim: usize, default: Option<usize>) -> Result<Option<usize>, Control> {
    match interp.kwarg("axis") {
        None | Some(SynValue::Nothing) => Ok(default),
        Some(SynValue::Number(n)) if n.is_integer() => {
            let k = n.to_i64_trunc().unwrap_or(i64::MAX);
            let j = if k < 0 { k + ndim as i64 } else { k };
            if j < 0 || j >= ndim as i64 {
                return Err(err(format!("{}: axis {} out of range for a {}-D array", name, k, ndim)));
            }
            Ok(Some(j as usize))
        }
        Some(other) => Err(err(format!("{}: axis must be an integer, got {}", name, other))),
    }
}

/// `take(a, [1, 0], axis = 1)`: las posiciones de ese eje, en orden (np.take). Sobre un 1-D el eje
/// es el único; con más ejes hay que decirlo (el `take` de numpy sin eje aplana: eso es
/// `take(flatten(a), …)`).
pub fn take(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    let a = match args.first() {
        Some(SynValue::Array(a)) => a,
        Some(other) => {
            let _ = interp.kwarg("axis");
            return Err(err(format!("take expects an array, got {}", other.type_name())));
        }
        None => return Err(err("take expects 2 argument(s), got 0")),
    };
    let nd = a.ndim();
    let axis = axis_kw(interp, "take", nd, if nd == 1 { Some(0) } else { None })?;
    arity(args, 2, "take")?;
    if nd == 0 {
        return Err(err("take: a 0-dimensional array has no axis"));
    }
    let Some(axis) = axis else {
        return Err(err(format!(
            "take: say which axis of the {}-D array — axis = 0 for rows, axis = 1 for columns (numpy's take without an axis flattens: take(flatten(a), …))",
            nd
        )));
    };
    let pos = positions(&args[1], a.shape()[axis], axis, PosFor::Builtin("take"))?;
    Ok(take_axis(a, &pos, axis))
}

/// `index_add(a, [0, 0, 2], values, axis = 0)`: un array nuevo con `values` sumados en esas
/// posiciones del eje; las repetidas acumulan, en el orden de las posiciones. Con `axis = 0` sobre
/// una matriz suma filas (el gradiente de un embedding). `values` tiene la forma de la selección
/// (o se le hace broadcasting); una máscara cuenta como 0/1 (R2).
pub fn index_add(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    let a = match args.first() {
        Some(SynValue::Array(a)) => a,
        Some(other) => {
            let _ = interp.kwarg("axis");
            return Err(err(format!("index_add expects an array, got {}", other.type_name())));
        }
        None => return Err(err("index_add expects 3 argument(s), got 0")),
    };
    let nd = a.ndim();
    let axis = axis_kw(interp, "index_add", nd, Some(0))?.unwrap_or(0);
    arity(args, 3, "index_add")?;
    if nd == 0 {
        return Err(err("index_add: a 0-dimensional array has no axis"));
    }
    let pos = positions(&args[1], a.shape()[axis], axis, PosFor::Builtin("index_add"))?;
    // v0.6.56: un `f32` suma en `f32`, en el orden de las posiciones (`np.add.at`); con un `f64`, E1.
    let k = out_num("index_add", &[&args[0], &args[2]])?;
    fn go<T: Real + std::ops::AddAssign>(a: &NdArray, values: &SynValue, axis: usize, pos: &[usize]) -> Result<SynValue, Control> {
        let values = T::operand(values).ok_or_else(|| match values {
            SynValue::List(_) => err("index_add: make the list an array first: array(xs)"),
            o => err(format!("index_add expects an array or a number for the values, got {}", o.type_name())),
        })?;
        let mut region = a.shape().to_vec();
        region[axis] = pos.len();
        let Some(vb) = values.broadcast(IxDyn(&region)) else {
            return Err(err(format!(
                "index_add: the values have shape {:?} and the selection {:?}",
                values.shape(),
                region
            )));
        };
        let mut out = T::of_nd(a).into_owned();
        for (n, &p) in pos.iter().enumerate() {
            let src = vb.index_axis(ndarray::Axis(axis), n);
            let mut dst = out.index_axis_mut(ndarray::Axis(axis), p);
            dst.zip_mut_with(&src, |d, &s| *d += s);
        }
        Ok(T::wrap(out))
    }
    by_num!(k, T => go::<T>(a, &args[2], axis, &pos))
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
