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
use num_complex::Complex64;
use num_integer::Integer;
use num_traits::ToPrimitive;

use crate::interpreter::{Control, RuntimeError};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::types::{syn_bool, syn_complex, syn_float, syn_int, syn_number, SynValue};

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
// Polimorfismo real/complex (Batch 4)
// =========================================================

/// Función unaria POLIMÓRFICA: arg real → `Float(real(x))` (idéntico a hoy, G1); arg
/// complejo → `Complex(cplx(z))`. Cualquier otro tipo → error de tipo claro.
fn unary_poly(
    args: &[SynValue],
    name: &str,
    real: impl Fn(f64) -> f64,
    cplx: impl Fn(Complex64) -> Complex64,
) -> Result<SynValue, Control> {
    arity(args, 1, name)?;
    match arg(args, 0)? {
        SynValue::Number(n) => Ok(syn_float(real(n.to_f64()))),
        SynValue::Complex(z) => Ok(SynValue::Complex(cplx(*z))),
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

/// Potencia compleja `a ** exp` con **exponente entero exacto** (Python-like): si `exp`
/// es un entero que entra en `i32` → `a.powi` (cuadrados repetidos, sin el drift de
/// `powc`: `complex(0,1)**2 == -1+0i` exacto); si no → `a.powc(b)`. `b` es `exp` ya
/// coercionado a `Complex64`.
pub fn complex_pow(a: Complex64, exp: &SynValue, b: Complex64) -> Complex64 {
    if let SynValue::Number(n) = exp {
        if n.is_integer() {
            if let Some(i) = n.to_i64_trunc().and_then(|v| i32::try_from(v).ok()) {
                return a.powi(i);
            }
        }
    }
    a.powc(b)
}

/// Coerciona el i-ésimo argumento a `Complex64` (real → parte imaginaria 0).
fn complex_arg(args: &[SynValue], i: usize, name: &str) -> Result<Complex64, Control> {
    match arg(args, i)? {
        SynValue::Number(n) => Ok(Complex64::new(n.to_f64(), 0.0)),
        SynValue::Complex(z) => Ok(*z),
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

/// Lee un argumento REAL para una función real-only (gamma/erf/…). Un complejo da un
/// error específico ("X is not defined for complex numbers"); otro tipo, error de tipo.
fn real_only(args: &[SynValue], i: usize, name: &str) -> Result<f64, Control> {
    match arg(args, i)? {
        SynValue::Number(n) => Ok(n.to_f64()),
        SynValue::Complex(_) => {
            Err(err(format!("{} is not defined for complex numbers", name)))
        }
        other => Err(err(format!("{} expects a number, got {}", name, other.type_name()))),
    }
}

// =========================================================
// Signo / magnitud / selección (preservan tipo)
// =========================================================

pub fn abs(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "abs")?;
    // Complex (Batch 4): módulo (Float). El resto preserva tipo (G1).
    if let SynValue::Complex(z) = arg(args, 0)? {
        return Ok(syn_float(z.norm()));
    }
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
    // Array (Batch 5): reducción total o por eje (las listas/variádicos siguen igual, G1).
    if matches!(args.first(), Some(SynValue::Array(_))) {
        return crate::arrays::reduce(args, "min");
    }
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
    if matches!(args.first(), Some(SynValue::Array(_))) {
        return crate::arrays::reduce(args, "max");
    }
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

/// `sqrt` POLIMÓRFICA: real → `f64::sqrt` (G1: `sqrt(-1)`→NaN); complejo → raíz
/// principal (`sqrt(complex(-1,0))`→`complex(0,1)`).
pub fn sqrt(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "sqrt", f64::sqrt, |z| z.sqrt())
}
pub fn cbrt(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_float(args, "cbrt", f64::cbrt)
}
pub fn hypot(args: &[SynValue]) -> Result<SynValue, Control> {
    binary_float(args, "hypot", f64::hypot)
}

/// `pow(base, exp)` espeja el operador `**`: si alguno es complejo → `a.powc(b)`
/// (complex); si no, entero^entero≥0 → entero; Decimal base + exp entero → Decimal;
/// mezclar Decimal y Float → error; si no → float (idéntico a hoy para reales, G1).
pub fn pow(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "pow")?;
    if matches!(arg(args, 0)?, SynValue::Complex(_)) || matches!(arg(args, 1)?, SynValue::Complex(_))
    {
        let a = complex_arg(args, 0, "pow")?;
        let b = complex_arg(args, 1, "pow")?;
        return Ok(SynValue::Complex(complex_pow(a, arg(args, 1)?, b)));
    }
    let base = num(args, 0, "pow")?;
    let exp = num(args, 1, "pow")?;
    base.checked_pow(exp).map(syn_number).map_err(err)
}

// =========================================================
// Exp / log  (sin `log` pelado: choca con el soft keyword de observabilidad)
// =========================================================

pub fn exp(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "exp", f64::exp, |z| z.exp())
}
pub fn ln(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "ln", f64::ln, |z| z.ln())
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
    unary_poly(args, "sin", f64::sin, |z| z.sin())
}
pub fn cos(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "cos", f64::cos, |z| z.cos())
}
pub fn tan(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "tan", f64::tan, |z| z.tan())
}
pub fn asin(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "asin", f64::asin, |z| z.asin())
}
pub fn acos(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "acos", f64::acos, |z| z.acos())
}
pub fn atan(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "atan", f64::atan, |z| z.atan())
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
    if matches!(args.first(), Some(SynValue::Array(_))) {
        return crate::arrays::reduce(args, "sum");
    }
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
    if matches!(args.first(), Some(SynValue::Array(_))) {
        return crate::arrays::reduce(args, "product");
    }
    let nums = list_numbers(args, "product")?;
    let mut acc = Number::Int(1);
    for n in &nums {
        acc = acc.checked_mul(n).map_err(err)?;
    }
    Ok(syn_number(acc))
}

pub fn mean(args: &[SynValue]) -> Result<SynValue, Control> {
    if matches!(args.first(), Some(SynValue::Array(_))) {
        return crate::arrays::reduce(args, "mean");
    }
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

// =========================================================
// Hiperbólicas (Batch 4) — polimórficas (real vía std f64, complejo vía num-complex)
// =========================================================

pub fn sinh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "sinh", f64::sinh, |z| z.sinh())
}
pub fn cosh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "cosh", f64::cosh, |z| z.cosh())
}
pub fn tanh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "tanh", f64::tanh, |z| z.tanh())
}
pub fn asinh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "asinh", f64::asinh, |z| z.asinh())
}
pub fn acosh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "acosh", f64::acosh, |z| z.acosh())
}
pub fn atanh(args: &[SynValue]) -> Result<SynValue, Control> {
    unary_poly(args, "atanh", f64::atanh, |z| z.atanh())
}

// =========================================================
// Funciones especiales (Batch 4) — REAL-ONLY, vía libm (puro-Rust)
// =========================================================

/// `gamma(x)` = Γ(x) (= `(x-1)!` para enteros). `gamma(5)`=24, `gamma(0.5)`=√π.
pub fn gamma(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "gamma")?;
    Ok(syn_float(libm::tgamma(real_only(args, 0, "gamma")?)))
}
/// `lgamma(x)` = ln|Γ(x)| (estable para argumentos grandes).
pub fn lgamma(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "lgamma")?;
    Ok(syn_float(libm::lgamma(real_only(args, 0, "lgamma")?)))
}
/// `erf(x)` = función error.
pub fn erf(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "erf")?;
    Ok(syn_float(libm::erf(real_only(args, 0, "erf")?)))
}
/// `erfc(x)` = error complementaria (`1 - erf(x)`, estable en la cola).
pub fn erfc(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "erfc")?;
    Ok(syn_float(libm::erfc(real_only(args, 0, "erfc")?)))
}
/// `beta(a, b)` = B(a,b) = Γ(a)Γ(b)/Γ(a+b). Forma numéricamente estable vía lgamma con
/// signo (`lgamma_r`): `signo · exp(lgΓ(a)+lgΓ(b)−lgΓ(a+b))`. Para `a,b>0` es positivo.
pub fn beta(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "beta")?;
    let a = real_only(args, 0, "beta")?;
    let b = real_only(args, 1, "beta")?;
    let (la, sa) = libm::lgamma_r(a);
    let (lb, sb) = libm::lgamma_r(b);
    let (lab, sab) = libm::lgamma_r(a + b);
    // signo(Γ(a))·signo(Γ(b))/signo(Γ(a+b)); como sab=±1, dividir = multiplicar.
    let sign = (sa * sb * sab) as f64;
    Ok(syn_float(sign * (la + lb - lab).exp()))
}

// =========================================================
// Constructores / accesores complex (Batch 4)
// =========================================================

/// `complex(re, im)` → número complejo (re/im numéricos reales).
pub fn complex(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 2, "complex")?;
    let re = num(args, 0, "complex")?.to_f64();
    let im = num(args, 1, "complex")?.to_f64();
    Ok(syn_complex(re, im))
}

/// `real(z)` → parte real (`Float`). Acepta un real (`real(5)`→5.0) por ergonomía.
pub fn real(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "real")?;
    match arg(args, 0)? {
        SynValue::Complex(z) => Ok(syn_float(z.re)),
        SynValue::Number(n) => Ok(syn_float(n.to_f64())),
        other => Err(err(format!("real expects a number or complex, got {}", other.type_name()))),
    }
}

/// `imag(z)` → parte imaginaria (`Float`). Un real tiene parte imaginaria 0 (`imag(5)`→0.0).
pub fn imag(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "imag")?;
    match arg(args, 0)? {
        SynValue::Complex(z) => Ok(syn_float(z.im)),
        SynValue::Number(_) => Ok(syn_float(0.0)),
        other => Err(err(format!("imag expects a number or complex, got {}", other.type_name()))),
    }
}

/// `conj(z)` → conjugado. El conjugado de un real es él mismo (devuelve el real).
pub fn conj(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "conj")?;
    match arg(args, 0)? {
        SynValue::Complex(z) => Ok(SynValue::Complex(z.conj())),
        SynValue::Number(n) => Ok(syn_number(n.clone())),
        other => Err(err(format!("conj expects a number or complex, got {}", other.type_name()))),
    }
}

/// `arg(z)` → fase/argumento en radianes (`Float`). `arg` del real positivo = 0, del
/// negativo = π. (Builtin `arg`; el nombre Rust es `arg_phase` por la colisión con el
/// helper interno `arg`.)
pub fn arg_phase(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "arg")?;
    match arg(args, 0)? {
        SynValue::Complex(z) => Ok(syn_float(z.arg())),
        SynValue::Number(n) => Ok(syn_float(Complex64::new(n.to_f64(), 0.0).arg())),
        other => Err(err(format!("arg expects a number or complex, got {}", other.type_name()))),
    }
}

/// `is_complex(x)` → `true` sólo si `x` es complex (espeja `is_decimal`/`is_bytes`).
pub fn is_complex(args: &[SynValue]) -> Result<SynValue, Control> {
    arity(args, 1, "is_complex")?;
    Ok(syn_bool(matches!(arg(args, 0)?, SynValue::Complex(_))))
}
