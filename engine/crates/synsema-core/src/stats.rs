//! Reducciones estadísticas (v0.6.29, DATOS-2/4/5/7/10): UNA implementación para listas y
//! arrays, con las mismas reglas en todas:
//!
//! - `nothing` es un dato FALTANTE: se saltea (como los null de polars/SQL).
//! - NaN es un resultado inválido: se PROPAGA (un NaN escondido es un bug que no se tapa).
//! - El eje es un argumento con nombre: `sum(m, axis = 0)` (en arrays también posicional,
//!   `sum(m, 0)`, como siempre). Un eje negativo cuenta desde el final.
//! - `std`/`var` son MUESTRALES por defecto (`ddof = 1`, como pandas, polars, R y
//!   `statistics`); la poblacional es `ddof = 0`.
//! - `decimal` se conserva en `sum`, `product`, `mean` y `median` (un monto no se degrada).
//! - `percentile(x, p)` con p en 0..100 y `quantile(x, q)` con q en 0..1, interpolación lineal
//!   (el default de numpy).

use std::cmp::Ordering;
use std::rc::Rc;

use ndarray::{ArrayD, Axis};

use crate::interpreter::{Control, Interpreter, RuntimeError};
use crate::number::{Number, MIX_DECIMAL_FLOAT};
use crate::types::{syn_float, syn_number, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Sum,
    Product,
    Mean,
    Min,
    Max,
    Median,
    Percentile,
    Quantile,
    Var,
    Std,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Sum => "sum",
            Kind::Product => "product",
            Kind::Mean => "mean",
            Kind::Min => "min",
            Kind::Max => "max",
            Kind::Median => "median",
            Kind::Percentile => "percentile",
            Kind::Quantile => "quantile",
            Kind::Var => "var",
            Kind::Std => "std",
        }
    }
    /// ¿Lleva un segundo argumento posicional que NO es el eje (p / q)?
    fn takes_level(self) -> bool {
        matches!(self, Kind::Percentile | Kind::Quantile)
    }
}

fn int_kw(v: SynValue, what: &str, who: &str) -> Result<i64, Control> {
    match &v {
        SynValue::Number(n) if n.is_integer() => n.to_i64_trunc().ok_or_else(|| err(format!("{}: {} out of range", who, what))),
        other => Err(err(format!("{}: {} must be an integer, got {}", who, what, other))),
    }
}

thread_local! {
    /// El nivel EXACTO (como decimal) del `quantile`/`percentile` en curso, para el camino
    /// decimal: `percentile(d, 90)` interpola con 0.9 exacto, no con 90.0/100 en f64.
    static EXACT_LEVEL: std::cell::Cell<Option<rust_decimal::Decimal>> = const { std::cell::Cell::new(None) };
}

fn exact_level(kind: Kind, v: Option<&SynValue>) -> Option<rust_decimal::Decimal> {
    use rust_decimal::prelude::*;
    let d = match v? {
        SynValue::Number(Number::Float(x)) => Decimal::from_str(&crate::number::py_float_str(*x)).ok()?,
        SynValue::Number(n) => n.to_decimal()?,
        _ => return None,
    };
    if kind == Kind::Percentile {
        d.checked_div(Decimal::ONE_HUNDRED)
    } else {
        Some(d)
    }
}

/// Nivel de percentil/cuantil como fracción en [0, 1].
fn level(kind: Kind, v: Option<&SynValue>) -> Result<f64, Control> {
    let who = kind.name();
    let x = match v {
        Some(SynValue::Number(n)) => n.to_f64(),
        Some(other) => return Err(err(format!("{}: the level must be a number, got {}", who, other.type_name()))),
        None => {
            return Err(err(match kind {
                Kind::Percentile => "percentile(values, p): p from 0 to 100".to_string(),
                _ => "quantile(values, q): q from 0 to 1".to_string(),
            }))
        }
    };
    match kind {
        Kind::Percentile => {
            if !(0.0..=100.0).contains(&x) {
                return Err(err(format!("percentile expects p between 0 and 100, got {} (quantile takes 0..1)", crate::number::py_float_str(x))));
            }
            Ok(x / 100.0)
        }
        _ => {
            if !(0.0..=1.0).contains(&x) {
                return Err(err(format!("quantile expects q between 0 and 1, got {} (percentile takes 0..100)", crate::number::py_float_str(x))));
            }
            Ok(x)
        }
    }
}

/// Interpolación lineal sobre datos YA ordenados (sin NaN), `q` ∈ [0, 1].
fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = q * (n - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo as f64)
}

/// Una reducción sobre números f64 (una lane de array, o una lista sin exactitud que cuidar).
fn reduce_f64(kind: Kind, vals: &[f64], lvl: f64, ddof: f64) -> f64 {
    if vals.is_empty() {
        return match kind {
            Kind::Sum => 0.0,
            Kind::Product => 1.0,
            _ => f64::NAN,
        };
    }
    if vals.iter().any(|v| v.is_nan()) {
        return f64::NAN;
    }
    let n = vals.len() as f64;
    match kind {
        Kind::Sum => vals.iter().sum(),
        Kind::Product => vals.iter().product(),
        Kind::Mean => vals.iter().sum::<f64>() / n,
        Kind::Min => vals.iter().copied().fold(f64::INFINITY, f64::min),
        Kind::Max => vals.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        Kind::Median | Kind::Percentile | Kind::Quantile => {
            let mut s = vals.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
            quantile_sorted(&s, if kind == Kind::Median { 0.5 } else { lvl })
        }
        Kind::Var | Kind::Std => {
            if n - ddof <= 0.0 {
                return f64::NAN;
            }
            let mean = vals.iter().sum::<f64>() / n;
            let v = vals.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (n - ddof);
            if kind == Kind::Std {
                v.sqrt()
            } else {
                v
            }
        }
    }
}

/// Punto de entrada de los builtins: lee `axis`/`ddof` con nombre y despacha.
pub fn builtin(interp: &mut Interpreter, args: &[SynValue], kind: Kind) -> Result<SynValue, Control> {
    let who = kind.name();
    let kw_axis = interp.kwarg("axis");
    let ddof = match interp.kwarg("ddof") {
        Some(v) => {
            let d = int_kw(v, "ddof", who)?;
            if d < 0 {
                return Err(err(format!("{}: ddof must be 0 or more", who)));
            }
            d as f64
        }
        None => 1.0,
    };
    let first = args.first().ok_or_else(|| err(format!("{}() needs the values", who)))?;
    let lvl = if kind.takes_level() { level(kind, args.get(1))? } else { 0.0 };
    let exact = if kind.takes_level() { exact_level(kind, args.get(1)) } else { None };
    EXACT_LEVEL.with(|c| c.set(exact));
    struct ClearLevel;
    impl Drop for ClearLevel {
        fn drop(&mut self) {
            EXACT_LEVEL.with(|c| c.set(None));
        }
    }
    let _clear = ClearLevel;
    match first {
        SynValue::Array(a) => {
            // Eje: con nombre, o (compatibilidad) posicional después de los valores.
            let pos_axis = if kind.takes_level() { args.get(2) } else { args.get(1) };
            let axis = match (kw_axis, pos_axis) {
                (Some(_), Some(_)) => return Err(err(format!("{}: pass the axis once (axis = k)", who))),
                (Some(v), None) => Some(int_kw(v, "axis", who)?),
                (None, Some(v)) => Some(int_kw(v.clone(), "axis", who)?),
                (None, None) => None,
            };
            reduce_array(a, kind, axis, lvl, ddof)
        }
        _ => {
            if kw_axis.is_some() {
                return Err(err(format!("{}: axis applies to arrays; a list has a single axis", who)));
            }
            match kind {
                Kind::Min => crate::math::min(args),
                Kind::Max => crate::math::max(args),
                _ => {
                    let extra = if kind.takes_level() { 2 } else { 1 };
                    if args.len() > extra {
                        let hint = match kind {
                            Kind::Std | Kind::Var => format!(" — pass ddof by name: {}(xs, ddof = 0)", who),
                            _ => String::new(),
                        };
                        return Err(err(format!(
                            "{}() takes a list (or an array){}{}",
                            who,
                            if kind.takes_level() { " and the level" } else { "" },
                            hint
                        )));
                    }
                    reduce_list(first, kind, lvl, ddof)
                }
            }
        }
    }
}

fn reduce_array(a: &Rc<ArrayD<f64>>, kind: Kind, axis: Option<i64>, lvl: f64, ddof: f64) -> Result<SynValue, Control> {
    let who = kind.name();
    if a.is_empty() && !matches!(kind, Kind::Sum | Kind::Product) {
        return Err(err(format!("{} of an empty array", who)));
    }
    match axis {
        None => {
            let vals: Vec<f64> = a.iter().copied().collect();
            Ok(syn_float(reduce_f64(kind, &vals, lvl, ddof)))
        }
        Some(k) => {
            let nd = a.ndim() as i64;
            let k2 = if k < 0 { k + nd } else { k };
            if k2 < 0 || k2 >= nd {
                return Err(err(format!("{}: axis {} out of range for a {}-D array", who, k, nd)));
            }
            let out = a.map_axis(Axis(k2 as usize), |lane| {
                let v: Vec<f64> = lane.iter().copied().collect();
                reduce_f64(kind, &v, lvl, ddof)
            });
            Ok(crate::arrays::nd_value(out))
        }
    }
}

/// Lista (o valores de una columna): `nothing` se saltea; lo demás tiene que ser número.
fn present_numbers(v: &SynValue, who: &str) -> Result<(Vec<Number>, usize), Control> {
    let items = match v {
        SynValue::List(l) => l.borrow().clone(),
        other => return Err(err(format!("{} expects a list of numbers or an array, got {}", who, other.type_name()))),
    };
    let total = items.len();
    let mut out = Vec::with_capacity(total);
    for (i, it) in items.iter().enumerate() {
        match it {
            SynValue::Nothing => {}
            SynValue::Number(n) => out.push(n.clone()),
            other => {
                return Err(err(format!(
                    "{} expects numbers, got {} at index {} (missing values are `nothing`)",
                    who,
                    other.type_name(),
                    i
                )))
            }
        }
    }
    if out.iter().any(|n| n.is_decimal()) && out.iter().any(|n| matches!(n, Number::Float(_))) {
        return Err(err(MIX_DECIMAL_FLOAT));
    }
    Ok((out, total))
}

/// Reducción de una lista con las reglas de este módulo (para los agregados de `tabular`).
pub fn reduce_values(v: &SynValue, kind: Kind, lvl: f64) -> Result<SynValue, Control> {
    reduce_list(v, kind, lvl, 1.0)
}

fn reduce_list(v: &SynValue, kind: Kind, lvl: f64, ddof: f64) -> Result<SynValue, Control> {
    let who = kind.name();
    let (nums, total) = present_numbers(v, who)?;
    let nan = nums.iter().any(|n| matches!(n, Number::Float(x) if x.is_nan()));
    match kind {
        Kind::Sum | Kind::Product => {
            let mut acc = Number::Int(if kind == Kind::Sum { 0 } else { 1 });
            for n in &nums {
                acc = if kind == Kind::Sum { acc.checked_add(n) } else { acc.checked_mul(n) }.map_err(err)?;
            }
            return Ok(syn_number(acc));
        }
        _ => {}
    }
    if nums.is_empty() {
        return Err(err(if total == 0 {
            format!("{} of an empty list", who)
        } else {
            format!("{}: every value is missing (nothing)", who)
        }));
    }
    if nan {
        return Ok(syn_float(f64::NAN));
    }
    let all_exact_decimal = nums.iter().any(|n| n.is_decimal()) && nums.iter().all(|n| !matches!(n, Number::Float(_)));
    match kind {
        Kind::Mean if all_exact_decimal => {
            // La suma es exacta a cualquier tamaño; la división sigue la regla de `/` decimal.
            let mut acc = Number::Int(0);
            for n in &nums {
                acc = acc.checked_add(n).map_err(err)?;
            }
            Ok(syn_number(as_decimal(&acc).div(&Number::Int(nums.len() as i64))))
        }
        // Mediana, varianza, desviación y cuantiles de decimales (con o sin enteros de cualquier
        // tamaño): EXACTOS sobre racionales m / 10^s y SIEMPRE decimales (ver `exact_stat`).
        Kind::Median | Kind::Var | Kind::Std | Kind::Percentile | Kind::Quantile if all_exact_decimal => {
            Ok(match exact_stat(kind, &nums, lvl, ddof) {
                Some(n) => syn_number(n),
                None => syn_float(f64::NAN),
            })
        }
        _ => {
            let vals: Vec<f64> = nums.iter().map(|n| n.to_f64()).collect();
            Ok(syn_float(reduce_f64(kind, &vals, lvl, ddof)))
        }
    }
}

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use crate::number::{cmp_ratio, pow10_big};

/// Los valores exactos llevados a una escala común `s`: cada uno es `x / 10^s`.
fn common_scale(nums: &[Number]) -> (Vec<BigInt>, u32) {
    let rs: Vec<(BigInt, u32)> = nums.iter().filter_map(|n| n.exact_ratio()).collect();
    debug_assert_eq!(rs.len(), nums.len(), "exact_stat sin floats");
    let s = rs.iter().map(|r| r.1).max().unwrap_or(0);
    (rs.into_iter().map(|(m, k)| m * pow10_big(s - k)).collect(), s)
}

/// Un valor exacto como decimal (un entero de la lista también: el resultado es decimal).
fn as_decimal(n: &Number) -> Number {
    match n.exact_ratio() {
        Some((m, s)) if !n.is_decimal() => Number::decimal_from_parts(m, s),
        _ => n.clone(),
    }
}

/// Un decimal sin los ceros de la derecha (`2.50` → `2.5`), como `normalize` de Python.
fn trimmed(n: Number) -> Number {
    match n.exact_ratio() {
        Some((mut m, mut s)) => {
            let ten = BigInt::from(10);
            while s > 0 && (&m % &ten).is_zero() {
                m /= &ten;
                s -= 1;
            }
            Number::decimal_from_parts(m, s)
        }
        None => n,
    }
}

/// Mediana / cuantil / varianza / desviación EXACTAS de valores exactos (decimales y enteros de
/// cualquier tamaño), como `statistics` de Python con `Decimal`: el resultado es SIEMPRE un
/// decimal — exacto si termina, si no con 28 cifras significativas. `None` = NaN (menos valores
/// que `ddof`).
fn exact_stat(kind: Kind, nums: &[Number], lvl: f64, ddof: f64) -> Option<Number> {
    use rust_decimal::prelude::*;
    let n = nums.len();
    match kind {
        Kind::Var | Kind::Std => {
            let dd = ddof as u64;
            if (n as u64) <= dd {
                return None;
            }
            // var = (n·Σx² − (Σx)²) / (n·(n−ddof)·10^(2s)), todo entero.
            let (xs, s) = common_scale(nums);
            let s1: BigInt = xs.iter().sum();
            let s2: BigInt = xs.iter().map(|x| x * x).sum();
            let nb = BigInt::from(n);
            let num = &nb * s2 - &s1 * &s1;
            let den = &nb * BigInt::from(n as u64 - dd) * pow10_big(2 * s);
            let num = if num < BigInt::zero() { BigInt::zero() } else { num };
            Some(trimmed(if kind == Kind::Var {
                Number::decimal_from_ratio(&num, &den, 0, 0)
            } else {
                Number::decimal_sqrt_ratio(&num, &den)
            }))
        }
        _ => {
            let mut sorted: Vec<&Number> = nums.iter().collect();
            sorted.sort_by(|a, b| cmp_ratio(&a.exact_ratio().unwrap(), &b.exact_ratio().unwrap()));
            if kind == Kind::Median {
                if n % 2 == 1 {
                    return Some(as_decimal(sorted[n / 2]));
                }
                // (a + b) / 2 exacto: la suma par se divide en su escala; impar, un decimal más.
                let pair = [sorted[n / 2 - 1].clone(), sorted[n / 2].clone()];
                let (xs, s) = common_scale(&pair);
                let sum = &xs[0] + &xs[1];
                let (q, k) = if sum.is_even() { (sum / 2, s) } else { (sum * 5, s + 1) };
                return Some(Number::decimal_from_parts(q, k));
            }
            // La interpolación lineal de numpy con el nivel exacto: pos = q·(n−1).
            let q = match EXACT_LEVEL.with(|c| c.get()) {
                Some(q) => q,
                None => Decimal::from_str(&crate::number::py_float_str(lvl)).ok()?,
            };
            let (qm, qs) = (BigInt::from(q.mantissa()), q.scale());
            let pos = qm * BigInt::from(n - 1);
            let (lo, frac) = pos.div_mod_floor(&pow10_big(qs));
            let i = lo.to_usize()?;
            if frac.is_zero() || i + 1 >= n {
                return Some(as_decimal(sorted[i.min(n - 1)]));
            }
            let pair = [sorted[i].clone(), sorted[i + 1].clone()];
            let (xs, s) = common_scale(&pair);
            // a + (b − a)·frac/10^qs, exacto sobre 10^(s+qs).
            let num = &xs[0] * pow10_big(qs) + (&xs[1] - &xs[0]) * frac;
            Some(trimmed(Number::decimal_from_parts(num, s + qs)))
        }
    }
}
