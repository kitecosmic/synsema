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
    /// Entero de precisión arbitraria (al desbordar i64). En `Box`, como `BigDec`: es el caso raro
    /// y en línea dimensionaba `Number` (y `SynValue`) a 32 bytes (specs/compute-rendimiento.md F1.10).
    Big(Box<BigInt>),
    /// Punto flotante.
    Float(f64),
    /// Decimal exacto base-10 (dinero/finanzas): 96-bit, preserva escala. El caso común.
    Decimal(Decimal),
    /// Decimal que NO entra en `Decimal` (más de 28-29 dígitos o más de 28 decimales), v0.6.29:
    /// el mismo tipo `decimal` para el programa (como `Int`/`Big` son el mismo entero). Nunca
    /// guarda un valor que entra en `Decimal` (lo garantiza `Number::decimal_from_parts`).
    BigDec(Box<BigDec>),
}

/// Un decimal grande: valor = `m / 10^s`, exacto.
#[derive(Clone, Debug)]
pub struct BigDec {
    pub m: BigInt,
    pub s: u32,
}

/// Cifras significativas de una división o raíz decimal inexacta (el contexto por defecto de
/// Python `decimal`); la parte entera nunca se trunca (como `numeric` de Postgres).
pub const DEC_SIG_DIGITS: u32 = 28;

/// Dígitos máximos de un decimal leído de texto (el tope de Python para enteros: convertir
/// uno enorme es cuadrático).
pub const MAX_DEC_TEXT_DIGITS: usize = 4300;

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
            None => Number::Big(Box::new(b)),
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

    /// Entero NO-negativo desde bytes big-endian (vacío → 0). Exacto: cae a `Big`
    /// cuando no entra en i64 — un r/s de firma secp256k1 es un entero de 256 bits.
    pub fn from_be_bytes(b: &[u8]) -> Number {
        Number::from_bigint(BigInt::from_bytes_be(Sign::Plus, b))
    }

    /// Bytes big-endian MÍNIMOS (sin ceros a la izquierda; 0 → vacío — la forma que
    /// piden RLP y los enteros de protocolo) de un entero no-negativo. `None` si el
    /// número es negativo o no es entero (`Float`/`Decimal`).
    pub fn to_be_bytes_min(&self) -> Option<Vec<u8>> {
        match self {
            Number::Int(i) if *i >= 0 => {
                let b = (*i as u64).to_be_bytes();
                let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
                Some(b[first..].to_vec())
            }
            Number::Big(b) if b.sign() != Sign::Minus => {
                let (_, mag) = b.to_bytes_be();
                Some(if mag == [0] { Vec::new() } else { mag })
            }
            _ => None,
        }
    }

    /// Demueve `Big` a `Int` si entra en i64.
    pub fn normalized(self) -> Number {
        match self {
            Number::Big(b) => Number::from_bigint(*b),
            other => other,
        }
    }

    /// True si es entero (`Int` o `Big`), no `Float`/`Decimal`.
    pub fn is_integer(&self) -> bool {
        matches!(self, Number::Int(_) | Number::Big(_))
    }

    /// True si es un `Decimal` (tipo dinero exacto), chico o grande.
    pub fn is_decimal(&self) -> bool {
        matches!(self, Number::Decimal(_) | Number::BigDec(_))
    }

    /// Un decimal exacto `m / 10^s`: `Decimal` si entra, si no `BigDec`. Con escala de más de
    /// 28, los ceros de la derecha no son información y se quitan antes de decidir.
    pub fn decimal_from_parts(mut m: BigInt, mut s: u32) -> Number {
        if s > 28 {
            let ten = BigInt::from(10);
            while s > 28 && (&m % &ten).is_zero() {
                m /= &ten;
                s -= 1;
            }
        }
        if s <= 28 {
            if let Some(v) = m.to_i128() {
                if v.unsigned_abs() < (1u128 << 96) {
                    return Number::Decimal(Decimal::from_i128_with_scale(v, s));
                }
            }
        }
        Number::BigDec(Box::new(BigDec { m, s }))
    }

    /// Un decimal desde texto (`"1234.5678"`, `"-0.001"`, con cualquier cantidad de dígitos
    /// hasta 4300), también con exponente (`"1e5"`, `"1.5E-3"`): el valor exacto, mantisa ×
    /// 10^exp, como `numeric` de Postgres y `Decimal` de Python (`"1.50e1"` es `15.0`: la escala
    /// es la de la mantisa menos el exponente, nunca negativa). `None` si no es un decimal o si
    /// el resultado pasaría de 4300 dígitos (`"1e999999999"` no puede pedir memoria sin tope).
    pub fn parse_decimal(text: &str) -> Option<Number> {
        let t = text.trim();
        if let Some(i) = t.find(['e', 'E']) {
            let (mant, exp) = (&t[..i], &t[i + 1..]);
            let digits = exp.strip_prefix(['+', '-']).unwrap_or(exp);
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let exp: i64 = exp.parse().ok()?;
            if mant.contains(['e', 'E']) {
                return None;
            }
            let (m, s) = Number::parse_decimal(mant)?.exact_ratio()?;
            let scale = s as i64 - exp;
            let int_digits = m.abs().to_string().len() as i64 - s as i64;
            if scale > MAX_DEC_TEXT_DIGITS as i64 || int_digits + exp.max(0) > MAX_DEC_TEXT_DIGITS as i64 {
                return None;
            }
            return Some(if scale >= 0 {
                Number::decimal_from_parts(m, scale as u32)
            } else {
                Number::decimal_from_parts(m * pow10_big((-scale) as u32), 0)
            });
        }
        if let Ok(d) = Decimal::from_str_exact(t) {
            return Some(Number::Decimal(d));
        }
        let (neg, body) = match t.as_bytes().first()? {
            b'-' => (true, &t[1..]),
            b'+' => (false, &t[1..]),
            _ => (false, t),
        };
        let (int_part, frac) = match body.split_once('.') {
            Some((a, b)) => (a, b),
            None => (body, ""),
        };
        if int_part.is_empty() && frac.is_empty() {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if int_part.len() + frac.len() > MAX_DEC_TEXT_DIGITS {
            return None;
        }
        let digits = format!("{}{}", int_part, frac);
        let m: BigInt = if digits.is_empty() { BigInt::zero() } else { digits.parse().ok()? };
        Some(Number::decimal_from_parts(if neg { -m } else { m }, frac.len() as u32))
    }

    /// `num / den` como decimal (`den != 0`): exacto si termina (recortando ceros hasta la escala
    /// `ideal`, como Python); si no, redondeado mitad al par con 28 cifras significativas y nunca
    /// menos de `min_scale` decimales; la parte entera siempre completa.
    pub fn decimal_from_ratio(num: &BigInt, den: &BigInt, min_scale: u32, ideal: u32) -> Number {
        let (num, den) = if den.is_negative() { (-num, -den) } else { (num.clone(), den.clone()) };
        if num.is_zero() {
            return Number::decimal_from_parts(BigInt::zero(), ideal.min(min_scale.max(ideal)));
        }
        let int_digits = magnitude_digits(&num, &den);
        let scale = (min_scale as i64).max(DEC_SIG_DIGITS as i64 - int_digits).max(0) as u32;
        let scaled = &num * pow10_big(scale);
        let mut q = div_round_half_even(&scaled, &den);
        let mut s = scale;
        if &q * &den == scaled {
            let ten = BigInt::from(10);
            while s > ideal && (&q % &ten).is_zero() {
                q /= &ten;
                s -= 1;
            }
        }
        Number::decimal_from_parts(q, s)
    }

    /// `sqrt(num / den)` como decimal (num ≥ 0, den > 0): exacta si lo es, si no 28 cifras.
    pub fn decimal_sqrt_ratio(num: &BigInt, den: &BigInt) -> Number {
        if num.is_zero() {
            return Number::Decimal(Decimal::ZERO);
        }
        // Dígitos de la parte entera de la raíz: la mitad (hacia arriba) de los del radicando.
        let e = magnitude_digits(num, den) - 1; // floor(log10(valor))
        let int_digits = e.div_euclid(2) + 1;
        let scale = (DEC_SIG_DIGITS as i64 - int_digits).max(0) as u32;
        // floor(sqrt(valor · 10^(2·scale+2))) y el dígito de más para redondear.
        let x = (num * pow10_big(2 * scale + 2)) / den;
        let r = x.sqrt();
        let mut q = div_round_half_even(&r, &BigInt::from(10));
        let mut s = scale;
        if &q * &q * den == num * pow10_big(2 * scale) {
            let ten = BigInt::from(10);
            while s > 0 && (&q % &ten).is_zero() {
                q /= &ten;
                s -= 1;
            }
        }
        Number::decimal_from_parts(q, s)
    }

    /// True si el valor es cero (entero, float o decimal).
    pub fn is_zero(&self) -> bool {
        match self {
            Number::Int(n) => *n == 0,
            Number::Big(b) => b.is_zero(),
            Number::Float(x) => *x == 0.0,
            Number::Decimal(d) => d.is_zero(),
            Number::BigDec(_) => false,
        }
    }

    /// True si es estrictamente negativo (`-0.0` no lo es).
    pub fn is_negative(&self) -> bool {
        match self {
            Number::Int(n) => *n < 0,
            Number::Big(b) => b.sign() == Sign::Minus,
            Number::Float(x) => *x < 0.0,
            Number::Decimal(d) => d.is_sign_negative() && !d.is_zero(),
            Number::BigDec(b) => b.m.is_negative(),
        }
    }

    pub fn to_f64(&self) -> f64 {
        match self {
            Number::Int(n) => *n as f64,
            Number::Big(b) => b.to_f64().unwrap_or(f64::INFINITY),
            Number::Float(x) => *x,
            Number::Decimal(d) => d.to_f64().unwrap_or(f64::NAN),
            Number::BigDec(b) => ratio_f64(&b.m, &pow10_big(b.s)),
        }
    }

    /// Vista como BigInt si es entero (incl. un `Decimal` con parte fraccionaria
    /// cero); `None` si es float o un decimal no entero.
    pub fn as_bigint(&self) -> Option<BigInt> {
        match self {
            Number::Int(n) => Some(BigInt::from(*n)),
            Number::Big(b) => Some((**b).clone()),
            Number::Float(_) => None,
            Number::Decimal(d) => {
                if d.fract().is_zero() {
                    // Un Decimal entero siempre entra en i128 (máx ~7.9e28).
                    d.to_i128().map(BigInt::from)
                } else {
                    None
                }
            }
            Number::BigDec(b) => {
                let (q, r) = b.m.div_rem(&pow10_big(b.s));
                if r.is_zero() {
                    Some(q)
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
            Number::Float(_) | Number::BigDec(_) => None,
        }
    }

    /// El valor exacto como `(m, s)` = m / 10^s (Int/Big/Decimal); `None` para Float.
    pub fn exact_ratio(&self) -> Option<(BigInt, u32)> {
        match self {
            Number::Int(n) => Some((BigInt::from(*n), 0)),
            Number::Big(b) => Some(((**b).clone(), 0)),
            Number::Decimal(d) => Some((BigInt::from(d.mantissa()), d.scale())),
            Number::BigDec(b) => Some((b.m.clone(), b.s)),
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
            Number::BigDec(b) => (&b.m / pow10_big(b.s)).to_i64(),
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

    /// Operación binaria entre números donde al menos uno es decimal. Decimal⊕
    /// Decimal/Int/Big → decimal EXACTO de cualquier tamaño (como `BigDecimal` de Java y
    /// `numeric` de Postgres): si no entra en `Decimal`, `BigDec`. La mezcla con Float NO
    /// debería llegar acá (el intérprete usa los `checked_*` y erroría antes); por totalidad
    /// cae a Float.
    fn decimal_binop(
        a: &Number,
        b: &Number,
        dec: impl Fn(Decimal, Decimal) -> Option<Decimal>,
        flt: impl Fn(f64, f64) -> f64,
        op: char,
    ) -> Number {
        if Number::any_float(a, b) {
            return Number::Float(flt(a.to_f64(), b.to_f64()));
        }
        let exact = || Number::exact_op(a, b, op).unwrap_or_else(|| Number::Float(flt(a.to_f64(), b.to_f64())));
        if matches!(a, Number::BigDec(_)) || matches!(b, Number::BigDec(_)) {
            return exact();
        }
        match (a.to_decimal(), b.to_decimal()) {
            (Some(x), Some(y)) => match dec(x, y) {
                Some(r) => Number::Decimal(r),
                None => exact(),
            },
            _ => exact(),
        }
    }

    /// `a op b` exacto (`+`, `-`, `*`) sobre `m / 10^s`: siempre un decimal (`1d + 10**30` es
    /// el decimal 1000000000000000000000000000001). `None` sólo con un float.
    fn exact_op(a: &Number, b: &Number, op: char) -> Option<Number> {
        let ((ma, sa), (mb, sb)) = (a.exact_ratio()?, b.exact_ratio()?);
        let (m, s) = match op {
            '*' => (ma * mb, sa + sb),
            '+' | '-' => {
                let s = sa.max(sb);
                let (x, y) = (ma * pow10_big(s - sa), mb * pow10_big(s - sb));
                (if op == '+' { x + y } else { x - y }, s)
            }
            _ => return None,
        };
        Some(Number::decimal_from_parts(m, s))
    }

    /// `a / b` decimal (b ≠ 0). Si los dos entran en `Decimal` y su cociente conserva 28
    /// cifras (o es exacto), el de `rust_decimal`; si no (`1e-20d / 1e10d`, que daba 0), el
    /// cociente exacto redondeado a 28 cifras significativas, sin truncar la parte entera.
    fn decimal_div(a: &Number, b: &Number) -> Option<Number> {
        if let (Number::Decimal(_) | Number::Int(_), Number::Decimal(_) | Number::Int(_)) = (a, b) {
            if let (Some(x), Some(y)) = (a.to_decimal(), b.to_decimal()) {
                if let Some(q) = x.checked_div(y) {
                    let digits = q.mantissa().unsigned_abs().checked_ilog10().map(|d| d + 1).unwrap_or(1);
                    if digits >= DEC_SIG_DIGITS || q.checked_mul(y) == Some(x) {
                        return Some(Number::Decimal(q));
                    }
                }
            }
        }
        let ((ma, sa), (mb, sb)) = (a.exact_ratio()?, b.exact_ratio()?);
        if mb.is_zero() {
            return None;
        }
        let num = ma * pow10_big(sb);
        let den = mb * pow10_big(sa);
        Some(Number::decimal_from_ratio(&num, &den, sa.max(sb), sa.saturating_sub(sb)))
    }

    /// Los dos decimales (o enteros) llevados a una escala común: `(A, B, s)` con a = A/10^s.
    fn common_scale(a: &Number, b: &Number) -> Option<(BigInt, BigInt, u32)> {
        let ((ma, sa), (mb, sb)) = (a.exact_ratio()?, b.exact_ratio()?);
        let s = sa.max(sb);
        Some((ma * pow10_big(s - sa), mb * pow10_big(s - sb), s))
    }

    pub fn add(&self, other: &Number) -> Number {
        if Number::any_decimal(self, other) {
            return Number::decimal_binop(self, other, |x, y| x.checked_add(y), |x, y| x + y, '+');
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
            return Number::decimal_binop(self, other, |x, y| x.checked_sub(y), |x, y| x - y, '-');
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
            return Number::decimal_binop(self, other, |x, y| x.checked_mul(y), |x, y| x * y, '*');
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
            if let Some(r) = Number::decimal_div(self, other) {
                return r;
            }
        }
        Number::Float(self.to_f64() / other.to_f64())
    }

    /// Módulo floored (signo del divisor, como Python). `None` si divisor es cero.
    pub fn modulo(&self, other: &Number) -> Option<Number> {
        if Number::any_decimal(self, other) && !Number::any_float(self, other) {
            // Exacto a cualquier tamaño, floored (el signo del divisor, como Python con `%`).
            let (x, y, s) = Number::common_scale(self, other)?;
            if y.is_zero() {
                return None;
            }
            return Some(Number::decimal_from_parts(x.mod_floor(&y), s));
        }
        if Number::any_float(self, other) {
            let (a, b) = (self.to_f64(), other.to_f64());
            if b == 0.0 {
                return None;
            }
            // El `float_divmod` de CPython (fmod + ajuste de signo): `7 % 0.1` es
            // 0.09999999999999962, no 0.0.
            return Some(Number::Float(py_float_divmod(a, b).1));
        }
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => {
                if *b == 0 {
                    None
                } else if *b == -1 {
                    // `i64::MIN % -1` desborda en la CPU (y en num-integer); el resto es 0.
                    Some(Number::Int(0))
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
            Number::Big(b) => Number::from_bigint(-&**b),
            Number::Float(x) => Number::Float(-x),
            Number::Decimal(d) => Number::Decimal(-*d),
            Number::BigDec(b) => Number::BigDec(Box::new(BigDec { m: -&b.m, s: b.s })),
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
            return decimal_powi(self, &exp);
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
        // Int×Int primero: es la condición de todo bucle y de todo `when` sobre enteros, y no
        // hay decimal ni float en juego. Sin BigInt (antes: dos asignaciones por comparación).
        if let (Number::Int(a), Number::Int(b)) = (self, other) {
            return Some(a.cmp(b));
        }
        // Decimal⊕Float: incomparable acá (el operador de orden erroría antes vía el
        // chequeo de mezcla; en sort cae a Equal con unwrap_or). Decimal con Int/Big/
        // Decimal: comparación de valor exacta.
        if Number::mixes_decimal_float(self, other) {
            return None;
        }
        if Number::any_decimal(self, other) {
            return match (self.to_decimal(), other.to_decimal()) {
                (Some(a), Some(b)) => a.partial_cmp(&b),
                // Un decimal o un entero grandes (`10**30` contra `1d`): exacto como racional.
                _ => Some(cmp_ratio(&self.exact_ratio()?, &other.exact_ratio()?)),
            };
        }
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(b),
            // Entero vs float: EXACTO, como Python (v0.6.29). Pasar el entero a f64
            // hacía `2**53 + 1 == 9007199254740992.0` verdadero.
            (Number::Float(a), Number::Int(i)) => cmp_i64_float(*i, *a).map(Ordering::reverse),
            (Number::Int(i), Number::Float(b)) => cmp_i64_float(*i, *b),
            (Number::Float(a), _) => cmp_int_float(&other.as_bigint().unwrap(), *a).map(Ordering::reverse),
            (_, Number::Float(b)) => cmp_int_float(&self.as_bigint().unwrap(), *b),
            _ => Some(cmp_int_big(self, other)),
        }
    }

    /// `a // b`: división entera con piso (v0.6.29), exacta en enteros de cualquier
    /// tamaño y coherente con `%`: `a == b * (a // b) + a % b`. Con float, `floor(a / b)`
    /// como float (Python); con decimal, decimal. `None` si el divisor es cero.
    pub fn floor_div(&self, other: &Number) -> Option<Number> {
        if other.is_zero() {
            return None;
        }
        if Number::any_decimal(self, other) && !Number::any_float(self, other) {
            // Exacto (el cociente redondeado de `/` podía caer del otro lado de un entero).
            let (x, y, _) = Number::common_scale(self, other)?;
            return Some(Number::decimal_from_parts(x.div_floor(&y), 0));
        }
        if Number::any_float(self, other) {
            let (a, b) = (self.to_f64(), other.to_f64());
            // El `float_divmod` de CPython: `7 // 0.1` es 69.0 (0.1 es un poco más que un décimo).
            return Some(Number::Float(py_float_divmod(a, b).0));
        }
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => match a.checked_div_euclid(*b) {
                // div_floor de num-integer maneja los signos como Python; i64::MIN / -1
                // desborda y cae a BigInt.
                Some(_) => Some(Number::Int(a.div_floor(b))),
                None => Some(Number::from_bigint(BigInt::from(*a).div_floor(&BigInt::from(*b)))),
            },
            _ => Some(Number::from_bigint(self.as_bigint()?.div_floor(&other.as_bigint()?))),
        }
    }

    pub fn checked_floor_div(&self, other: &Number) -> Result<Option<Number>, String> {
        Self::guard_mix(self, other)?;
        Ok(self.floor_div(other))
    }

    /// Igualdad numérica con semántica Python (`5 == 5.0` es true).
    pub fn num_eq(&self, other: &Number) -> bool {
        // Int×Int primero, sin BigInt (ver `partial_cmp_num`).
        if let (Number::Int(a), Number::Int(b)) = (self, other) {
            return a == b;
        }
        // Decimal⊕Float: simplemente distintos (sin error — mantiene total el `==`
        // de match/contains). Decimal con Int/Big/Decimal: igualdad de valor exacta
        // (`5 == 5d` → true; `1.50d == 1.5d` → true).
        if Number::mixes_decimal_float(self, other) {
            return false;
        }
        if Number::any_decimal(self, other) {
            return match (self.to_decimal(), other.to_decimal()) {
                (Some(a), Some(b)) => a == b,
                _ => match (self.exact_ratio(), other.exact_ratio()) {
                    (Some(a), Some(b)) => cmp_ratio(&a, &b) == Ordering::Equal,
                    _ => false,
                },
            };
        }
        match (self, other) {
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Float(a), Number::Int(i)) | (Number::Int(i), Number::Float(a)) => {
                cmp_i64_float(*i, *a) == Some(Ordering::Equal)
            }
            (Number::Float(a), _) => cmp_int_float(&other.as_bigint().unwrap(), *a) == Some(Ordering::Equal),
            (_, Number::Float(b)) => cmp_int_float(&self.as_bigint().unwrap(), *b) == Some(Ordering::Equal),
            _ => cmp_int_big(self, other) == Ordering::Equal,
        }
    }
}

/// Orden entre dos enteros exactos (`Int`/`Big`) sin asignar: un `Big` se compara por valor
/// contra un `Int` (no se asume que un `Big` nunca entra en `i64`: puede venir construido así).
/// Sólo para enteros; lo que no es entero no llega acá.
fn cmp_int_big(a: &Number, b: &Number) -> Ordering {
    match (a, b) {
        (Number::Int(x), Number::Int(y)) => x.cmp(y),
        (Number::Big(x), Number::Big(y)) => x.cmp(y),
        (Number::Int(x), Number::Big(y)) => match y.to_i64() {
            Some(y) => x.cmp(&y),
            None if y.sign() == Sign::Minus => Ordering::Greater,
            None => Ordering::Less,
        },
        (Number::Big(_), Number::Int(_)) => cmp_int_big(b, a).reverse(),
        // Inalcanzable desde los llamadores (decimal y float se resuelven antes); el camino
        // general de siempre, por las dudas.
        _ => a.as_bigint().cmp(&b.as_bigint()),
    }
}

/// Orden EXACTO entre un `i64` y un float, sin `BigInt`: la misma cuenta que `cmp_int_float`.
/// 2^63 es exacto en f64; todo float ≥ 2^63 queda por encima de cualquier `i64` y todo float
/// < −2^63 por debajo (los infinitos incluidos). En el medio, el piso del float entra exacto en
/// `i64`. NaN → `None`.
fn cmp_i64_float(i: i64, f: f64) -> Option<Ordering> {
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    if f.is_nan() {
        return None;
    }
    if f >= TWO_63 {
        return Some(Ordering::Less);
    }
    if f < -TWO_63 {
        return Some(Ordering::Greater);
    }
    let fl = f.floor();
    match i.cmp(&(fl as i64)) {
        Ordering::Less => Some(Ordering::Less),
        Ordering::Greater => Some(Ordering::Greater),
        // i == floor(f): igual si f es entero, menor si f tiene parte fraccionaria.
        Ordering::Equal => Some(if fl == f { Ordering::Equal } else { Ordering::Less }),
    }
}

/// 10^k como entero.
pub fn pow10_big(k: u32) -> BigInt {
    num_traits::pow(BigInt::from(10), k as usize)
}

/// Cantidad de dígitos de la parte entera de `|num / den|` (den > 0): `floor(log10) + 1`,
/// que es ≤ 0 para un valor menor que 1 (0.05 → -1).
fn magnitude_digits(num: &BigInt, den: &BigInt) -> i64 {
    let n = num.abs();
    let digits = |x: &BigInt| x.to_string().len() as i64;
    let mut e = digits(&n) - digits(den); // floor(log10) es e o e − 1
    let ge = |e: i64| -> bool {
        if e >= 0 {
            n >= den * pow10_big(e as u32)
        } else {
            &n * pow10_big((-e) as u32) >= *den
        }
    };
    if !ge(e) {
        e -= 1;
    }
    e + 1
}

/// `num / den` (den > 0) al entero más cercano, mitades al par.
pub fn div_round_half_even(num: &BigInt, den: &BigInt) -> BigInt {
    let (q, r) = num.div_mod_floor(den);
    match (&r * 2u32).cmp(den) {
        Ordering::Less => q,
        Ordering::Greater => q + 1,
        Ordering::Equal => {
            if q.is_even() {
                q
            } else {
                q + 1
            }
        }
    }
}

/// `num / den` como f64 sin desbordar en el camino.
pub fn ratio_f64(num: &BigInt, den: &BigInt) -> f64 {
    let bits = num.bits().max(den.bits());
    let shift = bits.saturating_sub(1000);
    let (n, d) = (num >> shift, den >> shift);
    n.to_f64().unwrap_or(f64::NAN) / d.to_f64().unwrap_or(f64::NAN)
}

/// Orden de dos `(m, s)` = m / 10^s, exacto.
pub fn cmp_ratio(a: &(BigInt, u32), b: &(BigInt, u32)) -> Ordering {
    let s = a.1.max(b.1);
    (&a.0 * pow10_big(s - a.1)).cmp(&(&b.0 * pow10_big(s - b.1)))
}

/// `divmod(a, b)` de floats exactamente como CPython (`Objects/floatobject.c: _float_div_mod`),
/// `b != 0`.
pub fn py_float_divmod(vx: f64, wx: f64) -> (f64, f64) {
    let mut m = vx % wx; // fmod
    let mut div = (vx - m) / wx;
    if m != 0.0 {
        if (wx < 0.0) != (m < 0.0) {
            m += wx;
            div -= 1.0;
        }
    } else {
        m = 0.0_f64.copysign(wx);
    }
    let floordiv = if div != 0.0 {
        let mut f = div.floor();
        if div - f > 0.5 {
            f += 1.0;
        }
        f
    } else {
        0.0_f64.copysign(vx / wx)
    };
    (floordiv, m)
}

/// Orden EXACTO entre un entero y un float (v0.6.29), como Python: sin pasar el
/// entero a f64. NaN → `None`; ±inf quedan por encima/debajo de todo entero.
fn cmp_int_float(i: &BigInt, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    if f.is_infinite() {
        return Some(if f > 0.0 { Ordering::Less } else { Ordering::Greater });
    }
    let fl = f.floor();
    // Un f64 finito es un racional exacto: su piso es un entero exacto.
    let floor = BigInt::from_f64(fl)?;
    match i.cmp(&floor) {
        Ordering::Less => Some(Ordering::Less),
        Ordering::Greater => Some(Ordering::Greater),
        // i == floor(f): igual si f es entero, menor si f tiene parte fraccionaria.
        Ordering::Equal => Some(if fl == f { Ordering::Equal } else { Ordering::Less }),
    }
}

/// `base^exp` EXACTO con `exp` entero, a cualquier tamaño (como `BigDecimal.pow` de Java).
/// Exponente negativo → `1 / base^|exp|` con la regla de la división decimal. Un resultado de
/// más de un millón de dígitos es error (usar float).
fn decimal_powi(base: &Number, exp: &BigInt) -> Result<Number, String> {
    let (m, s) = base.exact_ratio().ok_or_else(|| MIX_DECIMAL_FLOAT.to_string())?;
    let neg = exp.sign() == Sign::Minus;
    let e = exp.abs().to_u32().filter(|e| *e <= 1_000_000).ok_or_else(|| "decimal exponent too large".to_string())?;
    let digits = (m.bits().max(1) as f64 * std::f64::consts::LOG10_2).ceil() * e as f64;
    if digits > 1_000_000.0 {
        return Err("decimal power too large for an exact result (more than a million digits); use float(x) for an approximate one".to_string());
    }
    let scale = s.checked_mul(e).ok_or_else(|| "decimal exponent too large".to_string())?;
    let pm = num_traits::pow(m, e as usize);
    if neg {
        if pm.is_zero() {
            return Err("decimal power: zero to a negative power".to_string());
        }
        Ok(Number::decimal_from_ratio(&pow10_big(scale), &pm, 0, 0))
    } else {
        Ok(Number::decimal_from_parts(pm, scale))
    }
}

/// `m / 10^s` en texto, con la escala completa (`1.50`), sin notación científica.
fn fmt_scaled(m: &BigInt, s: u32) -> String {
    if s == 0 {
        return m.to_string();
    }
    let digits = m.abs().to_string();
    let s = s as usize;
    let padded = if digits.len() <= s { format!("{}{}", "0".repeat(s - digits.len() + 1), digits) } else { digits };
    let (i, f) = padded.split_at(padded.len() - s);
    format!("{}{}.{}", if m.is_negative() { "-" } else { "" }, i, f)
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
            (Number::Decimal(_) | Number::BigDec(_), Number::Decimal(_) | Number::BigDec(_)) => {
                cmp_ratio(&self.exact_ratio().unwrap(), &other.exact_ratio().unwrap()) == Ordering::Equal
            }
            (Number::Decimal(_) | Number::BigDec(_), _) | (_, Number::Decimal(_) | Number::BigDec(_)) => false,
            _ => cmp_int_big(self, other) == Ordering::Equal,
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
            Number::BigDec(b) => write!(f, "{}", fmt_scaled(&b.m, b.s)),
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
        assert_eq!(Number::Int(100), Number::Big(Box::new("100".parse().unwrap())));
    }

    /// El orden i64×float sin BigInt da exactamente lo mismo que el camino exacto con BigInt, en
    /// los bordes: ±2^53 (donde f64 deja de representar todo entero), ±2^63, i64::MIN/MAX,
    /// fracciones, ±0.0, infinitos y NaN.
    #[test]
    fn i64_float_order_matches_the_bigint_path() {
        let p53 = 9_007_199_254_740_992_i64;
        let ints = [
            0, 1, -1, 2, -2, 5, -5, 7, p53 - 1, p53, p53 + 1, -p53 - 1, -p53, -p53 + 1,
            i64::MAX, i64::MAX - 1, i64::MIN, i64::MIN + 1, 1 << 62, -(1 << 62),
        ];
        let mut floats = vec![
            0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 1.5, -1.5, 4.999999999999999, 5.0, 5.000000000000001,
            -5.0, 9_007_199_254_740_992.0, 9_007_199_254_740_994.0, -9_007_199_254_740_992.0,
            9_223_372_036_854_775_808.0, -9_223_372_036_854_775_808.0, 9_223_372_036_854_774_784.0,
            -9_223_372_036_854_774_784.0, 1e300, -1e300, f64::MIN_POSITIVE, -f64::MIN_POSITIVE,
            f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
        ];
        floats.extend(ints.iter().map(|i| *i as f64));
        for &i in &ints {
            for &f in &floats {
                let slow = cmp_int_float(&BigInt::from(i), f);
                assert_eq!(cmp_i64_float(i, f), slow, "i = {}, f = {:?}", i, f);
                let (n, x) = (Number::Int(i), Number::Float(f));
                assert_eq!(n.partial_cmp_num(&x), slow, "partial_cmp_num({}, {:?})", i, f);
                assert_eq!(x.partial_cmp_num(&n), slow.map(Ordering::reverse), "partial_cmp_num({:?}, {})", f, i);
                assert_eq!(n.num_eq(&x), slow == Some(Ordering::Equal), "num_eq({}, {:?})", i, f);
            }
        }
        // El caso que motivó el camino exacto (v0.6.29).
        assert!(!Number::Int(p53 + 1).num_eq(&Number::Float(9_007_199_254_740_992.0)));
    }

    /// El orden entre enteros exactos sin asignar da lo mismo que comparar como BigInt, incluido
    /// un `Big` construido con un valor que entra en `i64`.
    #[test]
    fn int_big_order_matches_the_bigint_path() {
        let big = |s: &str| Number::Big(Box::new(s.parse().unwrap()));
        let vals = [
            Number::Int(0),
            Number::Int(-3),
            Number::Int(i64::MAX),
            Number::Int(i64::MIN),
            big("100"),
            big("-100"),
            big("9223372036854775808"),
            big("-9223372036854775809"),
            big("123456789012345678901234567890"),
        ];
        for a in &vals {
            for b in &vals {
                let slow = a.as_bigint().unwrap().cmp(&b.as_bigint().unwrap());
                assert_eq!(a.partial_cmp_num(b), Some(slow), "{} vs {}", a, b);
                assert_eq!(a.num_eq(b), slow == Ordering::Equal, "{} == {}", a, b);
                assert_eq!(a == b, slow == Ordering::Equal, "PartialEq {} {}", a, b);
            }
        }
    }
}
