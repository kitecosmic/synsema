//! Librería matemática de Synsema: builtins puros sobre [`Number`].
//!
//! Semántica (spec math-library §2):
//! - **Preservación de tipo:** las funciones con sentido entero conservan
//!   `Int`/`Big` (`abs`, `sign`, `min`, `max`, `clamp`, `gcd`, `lcm`, `factorial`,
//!   `sum`/`product` sobre enteros). Las trascendentes/raíces devuelven `Float`.
//!   `pow` espeja el operador `**`.
//! - **Casos de dominio → NaN/±Inf** (IEEE, como f64/JS/numpy): `sqrt(-1)`→NaN,
//!   `ln(0)`→-Inf, `ln(-1)`→NaN. Se chequean con `is_nan/is_infinite/is_finite`.
//! - **Trig en RADIANES** + `radians()`/`degrees()`.
//! - **Tipo/aridad incorrectos → error claro**, como los builtins existentes.
//!
//! Funciones puras: no tocan el intérprete ni el entorno (se registran como
//! builtins en `interpreter.rs::register_builtins`). Las constantes `pi/tau/e/
//! inf/nan` se registran allí como VALORES globales (no funciones).

use std::cmp::Ordering;

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::ToPrimitive;

use crate::interpreter::{Control, RuntimeError};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::types::{syn_bool, syn_float, syn_int, syn_number, SynValue};

// -- helpers --

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

/// Exige exactamente `n` argumentos (aridad estricta, error claro en cualquier desvío).
fn arity(args: &[SynValue], n: usize, name: &str) -> Result<(), Control> {
    if args.len() != n {
        return Err(err(format!(
            "{} expects {} argument(s), got {}",
            name,
            n,
            args.len()
        )));
    }
    Ok(())
}

/// Lee el i-ésimo argumento como `Number`, o error de tipo claro.
fn num<'a>(args: &'a [SynValue], i: usize, name: &str) -> Result<&'a Number, Control> {
    match arg(args, i)? {
        SynValue::Number(n) => Ok(n),
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

/// Lee el i-ésimo argumento como entero (`Int`/`Big`); error si es float.
fn int_arg(args: &[SynValue], i: usize, name: &str) -> Result<BigInt, Control> {
    let n = num(args, i, name)?;
    n.as_bigint()
        .ok_or_else(|| err(format!("{} expects an integer, got float", name)))
}

/// `name(x)` → `Float(f(x))` (raíces/exp/log/trig — siempre Float).
fn unary_float(args: &[SynValue], name: &str, f: impl Fn(f64) -> f64) -> Result<SynValue, Control> {
    arity(args, 1, name)?;
    Ok(syn_float(f(num(args, 0, name)?.to_f64())))
}

/// `name(a, b)` → `Float(f(a, b))`.
fn binary_float(
    args: &[SynValue],
    name: &str,
    f: impl Fn(f64, f64) -> f64,
) -> Result<SynValue, Control> {
    arity(args, 2, name)?;
    let a = num(args, 0, name)?.to_f64();
    let b = num(args, 1, name)?.to_f64();
    Ok(syn_float(f(a, b)))
}

// =========================================================
// Signo / magnitud / selección (preservan tipo)
// =========================================================

pub fn abs(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "abs")?;
    let n = num(args, 0, "abs")?;
    Ok(syn_number(match n {
        Number::Float(x) => Number::Float(x.abs()),
        _ if n.is_negative() => n.neg(), // neg() promueve i64::MIN a Big
        _ => n.clone(),
    }))
}

pub fn sign(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "sign")?;
    let n = num(args, 0, "sign")?;
    if let Number::Float(x) = n {
        if x.is_nan() {
            return Ok(syn_int(0)); // NaN: sin signo definido
        }
    }
    let s = if n.is_zero() {
        0
    } else if n.is_negative() {
        -1
    } else {
        1
    };
    Ok(syn_int(s))
}

/// Reúne los números de un `min`/`max`: variádico `min(3, 5, 1)` o una sola lista
/// `min([3, 5, 1])`. Lista vacía / sin args → error.
fn select_numbers(args: &[SynValue], name: &str) -> Result<Vec<Number>, Control> {
    let items: Vec<SynValue> = match args {
        [SynValue::List(l)] => l.borrow().clone(),
        _ => args.to_vec(),
    };
    if items.is_empty() {
        return Err(err(format!("{} of an empty sequence", name)));
    }
    let mut nums = Vec::with_capacity(items.len());
    for it in &items {
        match it {
            SynValue::Number(n) => nums.push(n.clone()),
            other => {
                return Err(err(format!("{} expects numbers, got {}", name, other.type_name())))
            }
        }
    }
    // Coherente con el orden del lenguaje: no mezclar Decimal y Float.
    if nums.iter().any(|n| n.is_decimal()) && nums.iter().any(|n| matches!(n, Number::Float(_))) {
        return Err(err(MIX_DECIMAL_FLOAT.to_string()));
    }
    Ok(nums)
}

pub fn min(args: &[SynValue]) -> Result<SynValue, Control> {
    let nums = select_numbers(args, "min")?;
    let mut best = nums[0].clone();
    for n in &nums[1..] {
        if n.partial_cmp_num(&best) == Some(Ordering::Less) {
            best = n.clone();
        }
    }
    Ok(syn_number(best))
}

pub fn max(args: &[SynValue]) -> Result<SynValue, Control> {
    let nums = select_numbers(args, "max")?;
    let mut best = nums[0].clone();
    for n in &nums[1..] {
        if n.partial_cmp_num(&best) == Some(Ordering::Greater) {
            best = n.clone();
        }
    }
    Ok(syn_number(best))
}

pub fn clamp(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 3, "clamp")?;
    let x = num(args, 0, "clamp")?;
    let lo = num(args, 1, "clamp")?;
    let hi = num(args, 2, "clamp")?;
    if Number::mixes_decimal_float(x, lo) || Number::mixes_decimal_float(x, hi) {
        return Err(err(MIX_DECIMAL_FLOAT.to_string()));
    }
    if x.partial_cmp_num(lo) == Some(Ordering::Less) {
        Ok(syn_number(lo.clone()))
    } else if x.partial_cmp_num(hi) == Some(Ordering::Greater) {
        Ok(syn_number(hi.clone()))
    } else {
        Ok(syn_number(x.clone()))
    }
}

// =========================================================
// Raíces / potencias
// =========================================================

pub fn sqrt(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "sqrt", f64::sqrt)
}
pub fn cbrt(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "cbrt", f64::cbrt)
}
pub fn hypot(args: &[SynValue]) -> Result<SynValue, Control> {
    binary_float(args, "hypot", f64::hypot)
}

/// `pow(base, exp)` espeja el operador `**`: entero^entero≥0 → entero; Decimal base
/// + exp entero → Decimal; mezclar Decimal y Float → error; si no → float.
pub fn pow(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "pow")?;
    let base = num(args, 0, "pow")?;
    let exp = num(args, 1, "pow")?;
    base.checked_pow(exp).map(syn_number).map_err(err)
}

// =========================================================
// Exp / log  (sin `log` pelado: choca con el soft keyword de observabilidad)
// =========================================================

pub fn exp(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "exp", f64::exp)
}
pub fn ln(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "ln", f64::ln)
}
pub fn log10(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "log10", f64::log10)
}
pub fn log2(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "log2", f64::log2)
}
pub fn log_base(args: &[SynValue]) -> Result<SynValue, Control> {
    binary_float(args, "log_base", |x, base| x.log(base))
}

// =========================================================
// Trigonometría (radianes)
// =========================================================

pub fn sin(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "sin", f64::sin)
}
pub fn cos(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "cos", f64::cos)
}
pub fn tan(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "tan", f64::tan)
}
pub fn asin(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "asin", f64::asin)
}
pub fn acos(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "acos", f64::acos)
}
pub fn atan(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "atan", f64::atan)
}
pub fn atan2(args: &[SynValue]) -> Result<SynValue, Control> {
    binary_float(args, "atan2", f64::atan2)
}
pub fn radians(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "radians", |d| d * std::f64::consts::PI / 180.0)
}
pub fn degrees(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "degrees", |r| r * 180.0 / std::f64::consts::PI)
}

// =========================================================
// Teoría de números (enteros)
// =========================================================

pub fn gcd(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "gcd")?;
    let a = int_arg(args, 0, "gcd")?;
    let b = int_arg(args, 1, "gcd")?;
    Ok(syn_number(Number::from_bigint(a.gcd(&b))))
}

pub fn lcm(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "lcm")?;
    let a = int_arg(args, 0, "lcm")?;
    let b = int_arg(args, 1, "lcm")?;
    Ok(syn_number(Number::from_bigint(a.lcm(&b))))
}

/// `factorial(n)` exacto (usa `Big`). `n` debe ser un entero no-negativo.
pub fn factorial(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "factorial")?;
    let bi = int_arg(args, 0, "factorial")?;
    if bi.sign() == Sign::Minus {
        return Err(err("factorial expects a non-negative integer"));
    }
    let count = bi
        .to_u64()
        .ok_or_else(|| err("factorial argument too large"))?;
    let mut acc = BigInt::from(1u32);
    let mut k: u64 = 2;
    while k <= count {
        acc *= BigInt::from(k);
        k += 1;
    }
    Ok(syn_number(Number::from_bigint(acc)))
}

// =========================================================
// Introspección
// =========================================================

fn float_pred(
    args: &[SynValue],
    name: &str,
    f: fn(f64) -> bool,
    int_default: bool,
) -> Result<SynValue, Control> {
    arity(args, 1, name)?;
    let b = match num(args, 0, name)? {
        Number::Float(x) => f(*x),
        _ => int_default, // los enteros son siempre finitos
    };
    Ok(syn_bool(b))
}

pub fn is_nan(args: &[SynValue]) -> Result<SynValue, Control> {
    float_pred(args, "is_nan", f64::is_nan, false)
}
pub fn is_infinite(args: &[SynValue]) -> Result<SynValue, Control> {
    float_pred(args, "is_infinite", f64::is_infinite, false)
}
pub fn is_finite(args: &[SynValue]) -> Result<SynValue, Control> {
    float_pred(args, "is_finite", f64::is_finite, true)
}

/// `round_to(x, decimals)` → `Float` redondeado a N decimales (ties-to-even, como el
/// builtin `round`). Es un helper de DISPLAY/precisión, NO dinero exacto (eso será
/// el futuro tipo `Decimal`).
pub fn round_to(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "round_to")?;
    let x = num(args, 0, "round_to")?.to_f64();
    let d = num(args, 1, "round_to")?;
    if !d.is_integer() {
        return Err(err("round_to expects an integer number of decimals"));
    }
    let decimals = d
        .to_i64_trunc()
        .ok_or_else(|| err("round_to decimals out of range"))?;
    if decimals < 0 {
        return Err(err("round_to expects a non-negative number of decimals"));
    }
    let factor = 10f64.powi(decimals as i32);
    Ok(syn_float((x * factor).round_ties_even() / factor))
}

// =========================================================
// Agregados sobre una lista
// =========================================================

/// Extrae los números de una lista (único argumento), o error de tipo claro.
fn list_numbers(args: &[SynValue], name: &str) -> Result<Vec<Number>, Control> {
    arity(args, 1, name)?;
    let items = match &args[0] {
        SynValue::List(l) => l.borrow().clone(),
        other => return Err(err(format!("{} expects a list, got {}", name, other.type_name()))),
    };
    let mut nums = Vec::with_capacity(items.len());
    for it in &items {
        match it {
            SynValue::Number(n) => nums.push(n.clone()),
            other => {
                return Err(err(format!(
                    "{} expects a list of numbers, got {}",
                    name,
                    other.type_name()
                )))
            }
        }
    }
    Ok(nums)
}

pub fn sum(args: &[SynValue]) -> Result<SynValue, Control> {
    let nums = list_numbers(args, "sum")?;
    let mut acc = Number::Int(0);
    for n in &nums {
        // preserva Int/Big/Decimal; promueve a Float si hay floats; mezclar
        // Decimal y Float → error (camino falible).
        acc = acc.checked_add(n).map_err(err)?;
    }
    Ok(syn_number(acc))
}

pub fn product(args: &[SynValue]) -> Result<SynValue, Control> {
    let nums = list_numbers(args, "product")?;
    let mut acc = Number::Int(1);
    for n in &nums {
        acc = acc.checked_mul(n).map_err(err)?;
    }
    Ok(syn_number(acc))
}

pub fn mean(args: &[SynValue]) -> Result<SynValue, Control> {
    let nums = list_numbers(args, "mean")?;
    if nums.is_empty() {
        return Err(err("mean of an empty list"));
    }
    let mut acc = Number::Int(0);
    for n in &nums {
        acc = acc.checked_add(n).map_err(err)?;
    }
    Ok(syn_float(acc.to_f64() / nums.len() as f64))
}
