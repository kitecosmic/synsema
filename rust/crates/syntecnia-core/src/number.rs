//! Modelo numérico de Syntecnia.
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
use num_traits::{ToPrimitive, Zero};

#[derive(Clone, Debug)]
pub enum Number {
    /// Entero que entra en i64 (caso común).
    Int(i64),
    /// Entero de precisión arbitraria (al desbordar i64).
    Big(BigInt),
    /// Punto flotante.
    Float(f64),
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

    /// Demueve `Big` a `Int` si entra en i64.
    pub fn normalized(self) -> Number {
        match self {
            Number::Big(b) => Number::from_bigint(b),
            other => other,
        }
    }

    /// True si es entero (`Int` o `Big`), no `Float`.
    pub fn is_integer(&self) -> bool {
        matches!(self, Number::Int(_) | Number::Big(_))
    }

    /// True si el valor es cero (entero o float).
    pub fn is_zero(&self) -> bool {
        match self {
            Number::Int(n) => *n == 0,
            Number::Big(b) => b.is_zero(),
            Number::Float(x) => *x == 0.0,
        }
    }

    /// True si es estrictamente negativo (`-0.0` no lo es).
    pub fn is_negative(&self) -> bool {
        match self {
            Number::Int(n) => *n < 0,
            Number::Big(b) => b.sign() == Sign::Minus,
            Number::Float(x) => *x < 0.0,
        }
    }

    pub fn to_f64(&self) -> f64 {
        match self {
            Number::Int(n) => *n as f64,
            Number::Big(b) => b.to_f64().unwrap_or(f64::INFINITY),
            Number::Float(x) => *x,
        }
    }

    /// Vista como BigInt si es entero; `None` si es float.
    pub fn as_bigint(&self) -> Option<BigInt> {
        match self {
            Number::Int(n) => Some(BigInt::from(*n)),
            Number::Big(b) => Some(b.clone()),
            Number::Float(_) => None,
        }
    }

    /// Entero a usize si es no-negativo y entra (para índices/longitudes).
    pub fn to_i64_trunc(&self) -> Option<i64> {
        match self {
            Number::Int(n) => Some(*n),
            Number::Big(b) => b.to_i64(),
            Number::Float(x) => Some(x.trunc() as i64),
        }
    }

    fn any_float(a: &Number, b: &Number) -> bool {
        matches!(a, Number::Float(_)) || matches!(b, Number::Float(_))
    }

    pub fn add(&self, other: &Number) -> Number {
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
        match (self, other) {
            _ if Number::any_float(self, other) => Number::Float(self.to_f64() * other.to_f64()),
            (Number::Int(a), Number::Int(b)) => match a.checked_mul(*b) {
                Some(r) => Number::Int(r),
                None => Number::from_bigint(BigInt::from(*a) * BigInt::from(*b)),
            },
            _ => Number::from_bigint(self.as_bigint().unwrap() * other.as_bigint().unwrap()),
        }
    }

    /// División: en Syntecnia (como Python `/`) SIEMPRE devuelve float.
    /// El divisor-cero lo chequea el intérprete antes de llamar.
    pub fn div(&self, other: &Number) -> Number {
        Number::Float(self.to_f64() / other.to_f64())
    }

    /// Módulo floored (signo del divisor, como Python). `None` si divisor es cero.
    pub fn modulo(&self, other: &Number) -> Option<Number> {
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
        }
    }

    /// Orden numérico (para `< > <= >=`). `None` sólo con NaN.
    pub fn partial_cmp_num(&self, other: &Number) -> Option<Ordering> {
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(b),
            (Number::Float(a), _) => a.partial_cmp(&other.to_f64()),
            (_, Number::Float(b)) => self.to_f64().partial_cmp(b),
            _ => self.as_bigint().unwrap().partial_cmp(&other.as_bigint().unwrap()),
        }
    }

    /// Igualdad numérica con semántica Python (`5 == 5.0` es true).
    pub fn num_eq(&self, other: &Number) -> bool {
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Float(a), _) => *a == other.to_f64(),
            (_, Number::Float(b)) => self.to_f64() == *b,
            _ => self.as_bigint() == other.as_bigint(),
        }
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
/// sólo iguala a float; entero ≠ float). La igualdad `==` de Syntecnia usa `num_eq`.
impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Float(_), _) | (_, Number::Float(_)) => false,
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
