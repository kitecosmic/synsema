//! Modelo numérico de Synsema.
//!
//! Python usa enteros de **precisión arbitraria** + `float`. Para igualar al
//! oráculo sin sacrificar velocidad, el entero tiene fast-path `i64` y **promueve
//! a `BigInt`** sólo cuando desborda i64. Nunca hay wrap silencioso (coincide con
//! el principio del lenguaje: "predecible, nunca degradar en silencio").
//!
//! La aritmética reproduce la semántica exacta del intérprete Python:
//! `+ - *` enteros con promoción; `/` SIEMPRE float; `%` floored (signo del
//! divisor, como Python); `**` entero con exponente ≥0 → entero, si no float.

use std::cmp::Ordering;
use std::fmt;

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};
use rust_decimal::Decimal;

/// Mensaje único para el error de mezclar Decimal con Float (camino falible).
pub const MIX_DECIMAL_FLOAT: &str =
    "cannot mix decimal and float; convert with float(x) or decimal(...)";

#[derive(Clone, Debug)]
pub enum Number {
    /// Entero que entra en i64 (caso común).
    Int(i64),
    /// Entero de precisión arbitraria (al desbordar i64).
    Big(BigInt),
    /// Punto flotante.
    Float(f64),
    /// Decimal exacto base-10 (dinero/finanzas): 96-bit, preserva escala.
    Decimal(Decimal),
}

impl Number {
    /// Parsea un literal entero ya limpio de `_`: `i64` si entra, si no `BigInt`.
    pub fn parse_int_literal(digits: &str) -> Number {
        match digits.parse::<i64>() {
            Ok(n) => Number::Int(n),
            Err(_) => match digits.parse::<BigInt>() {
                Ok(b) => Number::from_bigint(b),
                Err(_) => Number::Int(0), // inalcanzable para dígitos válidos
            },
        }
    }

    /// Construye desde BigInt manteniendo el invariante: si entra en i64, es `Int`.
    pub fn from_bigint(b: BigInt) -> Number {
        match b.to_i64() {
            Some(n) => Number::Int(n),
            None => Number::Big(b),
        }
    }

    /// Un f64 **entero** (ya sin parte fraccionaria, p.ej. de floor/ceil/round/trunc) a
    /// `Number` entero: `Int` si entra en i64, si no `Big` (preserva el valor exacto del
    /// float). NaN/inf → `Int(0)` (no deberían llegar con input finito).
    pub fn integer_from_f64(v: f64) -> Number {
        if !v.is_finite() {
            return Number::Int(0);
        }
        // < 2^63 entra holgado en i64 (y el cast `as i64` satura en el borde, sin UB).
        if v.abs() < 9.223_372_036_854_776e18 {
            Number::Int(v as i64)
        } else {
            match BigInt::from_f64(v) {
                Some(b) => Number::from_bigint(b),
                None => Number::Int(0),
            }
        }
    }

    /// Demueve `Big` a `Int` si entra en i64.
    pub fn normalized(self) -> Number {
        match self {
            Number::Big(b) => Number::from_bigint(b),
            other => other,
        }
    }

    /// True si es entero (`Int` o `Big`), no `Float`/`Decimal`.
    pub fn is_integer(&self) -> bool {
        matches!(self, Number::Int(_) | Number::Big(_))
    }

    /// True si es un `Decimal` (tipo dinero exacto).
    pub fn is_decimal(&self) -> bool {
        matches!(self, Number::Decimal(_))
    }

    /// True si el valor es cero (entero, float o decimal).
    pub fn is_zero(&self) -> bool {
        match self {
            Number::Int(n) => *n == 0,
            Number::Big(b) => b.is_zero(),
            Number::Float(x) => *x == 0.0,
            Number::Decimal(d) => d.is_zero(),
        }
    }

    /// True si es estrictamente negativo (`-0.0` no lo es).
    pub fn is_negative(&self) -> bool {
        match self {
            Number::Int(n) => *n < 0,
            Number::Big(b) => b.sign() == Sign::Minus,
            Number::Float(x) => *x < 0.0,
            Number::Decimal(d) => d.is_sign_negative() && !d.is_zero(),
        }
    }

    pub fn to_f64(&self) -> f64 {
        match self {
            Number::Int(n) => *n as f64,
            Number::Big(b) => b.to_f64().unwrap_or(f64::INFINITY),
            Number::Float(x) => *x,
            Number::Decimal(d) => d.to_f64().unwrap_or(f64::NAN),
        }
    }

    /// Vista como BigInt si es entero (incl. un `Decimal` con parte fraccionaria
    /// cero); `None` si es float o un decimal no entero.
    pub fn as_bigint(&self) -> Option<BigInt> {
        match self {
            Number::Int(n) => Some(BigInt::from(*n)),
            Number::Big(b) => Some(b.clone()),
            Number::Float(_) => None,
            Number::Decimal(d) => {
                if d.fract().is_zero() {
                    // Un Decimal entero siempre entra en i128 (máx ~7.9e28).
                    d.to_i128().map(BigInt::from)
                } else {
                    None
                }
            }
        }
    }

    /// Vista como `Decimal` exacto si es representable (Int/Big/Decimal); `None`
    /// para Float (lossy a propósito) o Big fuera del rango de Decimal.
    pub fn to_decimal(&self) -> Option<Decimal> {
        match self {
            Number::Int(n) => Some(Decimal::from(*n)),
            Number::Big(b) => Decimal::from_str_exact(&b.to_string()).ok(),
            Number::Decimal(d) => Some(*d),
            Number::Float(_) => None,
        }
    }

    /// Entero a i64 truncando (para índices/longitudes).
    pub fn to_i64_trunc(&self) -> Option<i64> {
        match self {
            Number::Int(n) => Some(*n),
            Number::Big(b) => b.to_i64(),
            Number::Float(x) => Some(x.trunc() as i64),
            Number::Decimal(d) => d.to_i64(),
        }
    }

    fn any_float(a: &Number, b: &Number) -> bool {
        matches!(a, Number::Float(_)) || matches!(b, Number::Float(_))
    }

    fn any_decimal(a: &Number, b: &Number) -> bool {
        a.is_decimal() || b.is_decimal()
    }

    /// True si un operando es Decimal y el otro Float (mezcla prohibida).
    pub fn mixes_decimal_float(a: &Number, b: &Number) -> bool {
        (a.is_decimal() && matches!(b, Number::Float(_)))
            || (matches!(a, Number::Float(_)) && b.is_decimal())
    }

    /// Operación binaria entre números donde al menos uno es Decimal. Decimal⊕
    /// Decimal/Int/Big → Decimal exacto. La mezcla con Float NO debería llegar acá
    /// (el intérprete usa los `checked_*` y erroría antes); por totalidad cae a
    /// Float. Un overflow de Decimal o un Big fuera de rango también cae a Float.
    fn decimal_binop(
        a: &Number,
        b: &Number,
        dec: impl Fn(Decimal, Decimal) -> Option<Decimal>,
        flt: impl Fn(f64, f64) -> f64,
    ) -> Number {
        if Number::any_float(a, b) {
            return Number::Float(flt(a.to_f64(), b.to_f64()));
        }
        match (a.to_decimal(), b.to_decimal()) {
            (Some(x), Some(y)) => match dec(x, y) {
                Some(r) => Number::Decimal(r),
                None => Number::Float(flt(a.to_f64(), b.to_f64())),
            },
            _ => Number::Float(flt(a.to_f64(), b.to_f64())),
        }
    }

    pub fn add(&self, other: &Number) -> Number {
        if Number::any_decimal(self, other) {
            return Number::decimal_binop(self, other, |x, y| x.checked_add(y), |x, y| x + y);
        }
        match (self, other) {
            _ if Number::any_float(self, other) => Number::Float(self.to_f64() + other.to_f64()),
            (Number::Int(a), Number::Int(b)) => match a.checked_add(*b) {
                Some(r) => Number::Int(r),
                None => Number::from_bigint(BigInt::from(*a) + BigInt::from(*b)),
            },
            _ => Number::from_bigint(self.as_bigint().unwrap() + other.as_bigint().unwrap()),
        }
    }

    pub fn sub(&self, other: &Number) -> Number {
        if Number::any_decimal(self, other) {
            return Number::decimal_binop(self, other, |x, y| x.checked_sub(y), |x, y| x - y);
        }
        match (self, other) {
            _ if Number::any_float(self, other) => Number::Float(self.to_f64() - other.to_f64()),
            (Number::Int(a), Number::Int(b)) => match a.checked_sub(*b) {
                Some(r) => Number::Int(r),
                None => Number::from_bigint(BigInt::from(*a) - BigInt::from(*b)),
            },
            _ => Number::from_bigint(self.as_bigint().unwrap() - other.as_bigint().unwrap()),
        }
    }

    pub fn mul(&self, other: &Number) -> Number {
        if Number::any_decimal(self, other) {
            return Number::decimal_binop(self, other, |x, y| x.checked_mul(y), |x, y| x * y);
        }
        match (self, other) {
            _ if Number::any_float(self, other) => Number::Float(self.to_f64() * other.to_f64()),
            (Number::Int(a), Number::Int(b)) => match a.checked_mul(*b) {
                Some(r) => Number::Int(r),
                None => Number::from_bigint(BigInt::from(*a) * BigInt::from(*b)),
            },
            _ => Number::from_bigint(self.as_bigint().unwrap() * other.as_bigint().unwrap()),
        }
    }

    /// División: con Decimal (sin Float) → Decimal exacto/redondeado (precisión por
    /// defecto de rust_decimal: ~28 dígitos significativos, redondeo bancario). Si no,
    /// en Synsema (como Python `/`) SIEMPRE devuelve float. El divisor-cero lo chequea
    /// el intérprete antes de llamar.
    pub fn div(&self, other: &Number) -> Number {
        if Number::any_decimal(self, other) && !Number::any_float(self, other) {
            if let (Some(x), Some(y)) = (self.to_decimal(), other.to_decimal()) {
                if let Some(r) = x.checked_div(y) {
                    return Number::Decimal(r);
                }
            }
        }
        Number::Float(self.to_f64() / other.to_f64())
    }

    /// Módulo floored (signo del divisor, como Python). `None` si divisor es cero.
    pub fn modulo(&self, other: &Number) -> Option<Number> {
        if Number::any_decimal(self, other) && !Number::any_float(self, other) {
            let (x, y) = (self.to_decimal()?, other.to_decimal()?);
            if y.is_zero() {
                return None;
            }
            let r = x.checked_rem(y)?;
            // Truncado → floored: ajustar al signo del divisor (como Python).
            let r = if !r.is_zero() && (r.is_sign_negative() != y.is_sign_negative()) {
                r.checked_add(y).unwrap_or(r)
            } else {
                r
            };
            return Some(Number::Decimal(r));
        }
        if Number::any_float(self, other) {
            let (a, b) = (self.to_f64(), other.to_f64());
            if b == 0.0 {
                return None;
            }
            // Python: a % b == a - floor(a/b)*b (signo del divisor).
            return Some(Number::Float(a - (a / b).floor() * b));
        }
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => {
                if *b == 0 {
                    None
                } else {
                    Some(Number::Int(a.mod_floor(b)))
                }
            }
            _ => {
                let b = other.as_bigint().unwrap();
                if b.is_zero() {
                    None
                } else {
                    Some(Number::from_bigint(self.as_bigint().unwrap().mod_floor(&b)))
                }
            }
        }
    }

    /// Potencia: entero^entero≥0 → entero (con BigInt); si no → float.
    pub fn pow(&self, other: &Number) -> Number {
        if self.is_integer() && other.is_integer() {
            if let Some(exp) = other.as_bigint() {
                if exp.sign() != Sign::Minus {
                    let base = self.as_bigint().unwrap();
                    if let Some(e) = exp.to_u32() {
                        return Number::from_bigint(base.pow(e));
                    }
                    // Exponente gigantesco: Python colgaría; aproximamos con float.
                    return Number::Float(self.to_f64().powf(other.to_f64()));
                }
            }
        }
        Number::Float(self.to_f64().powf(other.to_f64()))
    }

    pub fn neg(&self) -> Number {
        match self {
            Number::Int(n) => match n.checked_neg() {
                Some(r) => Number::Int(r),
                None => Number::from_bigint(-BigInt::from(*n)),
            },
            Number::Big(b) => Number::from_bigint(-b),
            Number::Float(x) => Number::Float(-x),
            Number::Decimal(d) => Number::Decimal(-*d),
        }
    }

    // -- Camino falible: la mezcla Decimal⊕Float es un ERROR del lenguaje --
    // El intérprete (y math.rs) rutean la aritmética por estos `checked_*` para
    // que `1.50d + 1.5` falle claro. Int/Big mezclan libremente con ambos.

    pub fn checked_add(&self, other: &Number) -> Result<Number, String> {
        Self::guard_mix(self, other)?;
        Ok(self.add(other))
    }
    pub fn checked_sub(&self, other: &Number) -> Result<Number, String> {
        Self::guard_mix(self, other)?;
        Ok(self.sub(other))
    }
    pub fn checked_mul(&self, other: &Number) -> Result<Number, String> {
        Self::guard_mix(self, other)?;
        Ok(self.mul(other))
    }
    pub fn checked_div(&self, other: &Number) -> Result<Number, String> {
        Self::guard_mix(self, other)?;
        Ok(self.div(other))
    }
    pub fn checked_modulo(&self, other: &Number) -> Result<Option<Number>, String> {
        Self::guard_mix(self, other)?;
        Ok(self.modulo(other))
    }

    /// `**` falible: mezcla con Float → error; con base/exp Decimal el exponente
    /// debe ser ENTERO (exactitud), si no → error (recomendación del spec §6).
    pub fn checked_pow(&self, other: &Number) -> Result<Number, String> {
        Self::guard_mix(self, other)?;
        if Number::any_decimal(self, other) {
            let exp = other.as_bigint().ok_or_else(|| {
                "decimal ** non-integer exponent is not supported (it would lose \
                 exactness); use float(x) for an approximate power"
                    .to_string()
            })?;
            let base = self
                .to_decimal()
                .ok_or_else(|| "number too large for an exact decimal power".to_string())?;
            return decimal_powi(base, &exp);
        }
        Ok(self.pow(other))
    }

    fn guard_mix(a: &Number, b: &Number) -> Result<(), String> {
        if Number::mixes_decimal_float(a, b) {
            Err(MIX_DECIMAL_FLOAT.to_string())
        } else {
            Ok(())
        }
    }

    /// Orden numérico (para `< > <= >=`). `None` sólo con NaN.
    pub fn partial_cmp_num(&self, other: &Number) -> Option<Ordering> {
        // Decimal⊕Float: incomparable acá (el operador de orden erroría antes vía el
        // chequeo de mezcla; en sort cae a Equal con unwrap_or). Decimal con Int/Big/
        // Decimal: comparación de valor exacta.
        if Number::mixes_decimal_float(self, other) {
            return None;
        }
        if Number::any_decimal(self, other) {
            return match (self.to_decimal(), other.to_decimal()) {
                (Some(a), Some(b)) => a.partial_cmp(&b),
                _ => None,
            };
        }
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(b),
            (Number::Float(a), _) => a.partial_cmp(&other.to_f64()),
            (_, Number::Float(b)) => self.to_f64().partial_cmp(b),
            _ => self.as_bigint().unwrap().partial_cmp(&other.as_bigint().unwrap()),
        }
    }

    /// Igualdad numérica con semántica Python (`5 == 5.0` es true).
    pub fn num_eq(&self, other: &Number) -> bool {
        // Decimal⊕Float: simplemente distintos (sin error — mantiene total el `==`
        // de match/contains). Decimal con Int/Big/Decimal: igualdad de valor exacta
        // (`5 == 5d` → true; `1.50d == 1.5d` → true).
        if Number::mixes_decimal_float(self, other) {
            return false;
        }
        if Number::any_decimal(self, other) {
            return matches!(
                (self.to_decimal(), other.to_decimal()),
                (Some(a), Some(b)) if a == b
            );
        }
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Float(a), _) => *a == other.to_f64(),
            (_, Number::Float(b)) => self.to_f64() == *b,
            _ => self.as_bigint() == other.as_bigint(),
        }
    }
}

/// `base^exp` exacto con `exp` ENTERO (BigInt). Exp negativo → división con la
/// precisión por defecto de rust_decimal. Overflow / exp gigante → error.
fn decimal_powi(base: Decimal, exp: &BigInt) -> Result<Number, String> {
    let neg = exp.sign() == Sign::Minus;
    let e = exp
        .abs()
        .to_u32()
        .ok_or_else(|| "decimal exponent too large".to_string())?;
    let mut acc = Decimal::ONE;
    for _ in 0..e {
        acc = acc
            .checked_mul(base)
            .ok_or_else(|| "decimal power overflow".to_string())?;
    }
    if neg {
        Decimal::ONE
            .checked_div(acc)
            .map(Number::Decimal)
            .ok_or_else(|| "decimal power division failed".to_string())
    } else {
        Ok(Number::Decimal(acc))
    }
}

/// `str(float)`/`repr(float)` de Python (idénticos desde 3.1).
///
/// Algoritmo: dígitos shortest round-trip (los de `{:e}` de Rust). Con
/// `value = 0.<dígitos> × 10^decpt`, usa científica sii `decpt <= -4 || decpt > 16`,
/// si no fija (los enteros muestran `.0`). En científica el exponente lleva signo
/// y mínimo 2 dígitos. nan/inf/-inf y el signo se preservan.
pub fn py_float_str(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x < 0.0 { "-inf".to_string() } else { "inf".to_string() };
    }

    // `{:e}` de Rust da la mantisa shortest en forma `d.ddd` y el exponente decimal.
    let e = format!("{:e}", x); // p.ej. "3.0000000000000004e-1", "1e2", "-5e-1", "0e0"
    let (mant, exp_str) = e.split_once('e').expect("{:e} siempre incluye 'e'");
    let exp10: i32 = exp_str.parse().expect("exponente decimal válido");
    let negative = mant.starts_with('-');
    let digits: String = mant.trim_start_matches('-').chars().filter(|c| *c != '.').collect();
    let n = digits.len() as i32;
    let decpt = exp10 + 1;

    let body = if decpt <= -4 || decpt > 16 {
        // Científica: <mantisa>e<signo><exp>, exp con signo y ≥2 dígitos.
        let mantissa = if n == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let exp = decpt - 1;
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{}e{}{:02}", mantissa, sign, exp.abs())
    } else if decpt <= 0 {
        // 0.000ddd
        format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
    } else if decpt >= n {
        // Entero (ceros de relleno) + ".0"
        format!("{}{}.0", digits, "0".repeat((decpt - n) as usize))
    } else {
        // Punto intercalado entre los dígitos
        format!("{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
    };

    if negative {
        format!("-{}", body)
    } else {
        body
    }
}

/// Igualdad estructural robusta a la representación (Int vs Big por valor; float
/// sólo iguala a float; decimal sólo iguala a decimal por VALOR — escala-insensible).
/// La igualdad `==` del lenguaje Synsema usa `num_eq` (que sí mezcla Int con Decimal).
impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Float(_), _) | (_, Number::Float(_)) => false,
            (Number::Decimal(a), Number::Decimal(b)) => a == b,
            (Number::Decimal(_), _) | (_, Number::Decimal(_)) => false,
            _ => self.as_bigint() == other.as_bigint(),
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::Int(n) => write!(f, "{}", n),
            Number::Big(b) => write!(f, "{}", b),
            Number::Float(x) => write!(f, "{}", py_float_str(*x)),
            // rust_decimal preserva la escala: 1.50d → "1.50", 100d → "100".
            Number::Decimal(d) => write!(f, "{}", d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_int_is_int() {
        assert!(matches!(Number::parse_int_literal("42"), Number::Int(42)));
    }

    #[test]
    fn overflow_promotes_to_big() {
        let n = Number::parse_int_literal("9223372036854775808"); // 2^63
        assert!(matches!(n, Number::Big(_)));
    }

    #[test]
    fn add_overflow_promotes() {
        let r = Number::Int(i64::MAX).add(&Number::Int(1));
        assert!(matches!(r, Number::Big(_)));
        assert_eq!(r.to_string(), "9223372036854775808");
    }

    #[test]
    fn pow_big() {
        // 2 ** 100 no entra en i64.
        let r = Number::Int(2).pow(&Number::Int(100));
        assert_eq!(r.to_string(), "1267650600228229401496703205376");
    }

    #[test]
    fn div_is_float() {
        assert_eq!(Number::Int(15).div(&Number::Int(3)).to_string(), "5.0");
    }

    #[test]
    fn modulo_floored() {
        // Python: -7 % 3 == 2
        assert_eq!(Number::Int(-7).modulo(&Number::Int(3)).unwrap(), Number::Int(2));
        assert_eq!(Number::Int(17).modulo(&Number::Int(5)).unwrap(), Number::Int(2));
    }

    #[test]
    fn int_eq_big_by_value() {
        assert_eq!(Number::Int(100), Number::Big("100".parse().unwrap()));
    }
}
