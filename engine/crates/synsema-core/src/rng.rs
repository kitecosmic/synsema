//! Generadores aleatorios con semilla (v0.6.29, DATOS-12).
//!
//! El generador es un VALOR, no un estado global (el modelo de `numpy.random.default_rng` y
//! JAX): `let g be rng(42)` devuelve una función; cada `g()` es el siguiente uniforme en
//! [0, 1). Dos partes del programa no se pisan la secuencia, cada test o agente fija la suya,
//! y es PURO: bajo `--deterministic` está permitido (sólo `random()` sin generador pide la
//! capability `random`).
//!
//! Algoritmo fijo y documentado, para que la misma semilla dé la misma secuencia en toda
//! plataforma y versión: PCG64 (XSL-RR 128/64, el de numpy), con el estado inicial derivado
//! de la semilla por SplitMix64. Uniformes de 53 bits; normal por Box–Muller (dos uniformes
//! por valor).

use std::cell::RefCell;
use std::rc::Rc;

use crate::interpreter::{BuiltinTask, Control, RuntimeError};
use crate::number::Number;
use crate::types::{syn_float, syn_list, SynValue};

const PCG_MULT: u128 = 0x2360_ED05_1FC6_5DA4_4385_DF64_9FCC_F645;

#[derive(Clone, Debug)]
pub struct Pcg64 {
    state: u128,
    inc: u128,
}

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Pcg64 {
    pub fn from_seed(seed: u64) -> Pcg64 {
        let mut sm = seed;
        let s = ((splitmix64(&mut sm) as u128) << 64) | splitmix64(&mut sm) as u128;
        let i = ((splitmix64(&mut sm) as u128) << 64) | splitmix64(&mut sm) as u128;
        let mut g = Pcg64 { state: 0, inc: (i << 1) | 1 };
        g.step();
        g.state = g.state.wrapping_add(s);
        g.step();
        g
    }

    fn step(&mut self) {
        self.state = self.state.wrapping_mul(PCG_MULT).wrapping_add(self.inc);
    }

    pub fn next_u64(&mut self) -> u64 {
        self.step();
        let rot = (self.state >> 122) as u32;
        let xored = ((self.state >> 64) as u64) ^ (self.state as u64);
        xored.rotate_right(rot)
    }

    /// Uniforme en [0, 1) con 53 bits.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// `rng(seed)` → un generador: una función sin argumentos que devuelve el siguiente
/// uniforme en [0, 1).
pub fn make_rng(args: &[SynValue]) -> Result<SynValue, Control> {
    let seed = match args.first() {
        Some(SynValue::Number(n @ (Number::Int(_) | Number::Big(_)))) => {
            let b = n.as_bigint().unwrap();
            use num_traits::ToPrimitive;
            b.to_u64().ok_or_else(|| err("rng(seed): the seed must be an integer from 0 to 2^64-1"))?
        }
        Some(other) => return Err(err(format!("rng(seed): the seed must be an integer, got {}", other.type_name()))),
        None => return Err(err("rng(seed): pass a seed — the same seed gives the same sequence everywhere")),
    };
    let state = Rc::new(RefCell::new(Pcg64::from_seed(seed)));
    Ok(SynValue::Builtin(Rc::new(BuiltinTask {
        name: format!("rng({})", seed),
        func: Rc::new(move |_i, _a, _l| Ok(syn_float(state.borrow_mut().next_f64()))),
        param_count: 0,
        param_names: None,
    })))
}

/// Un uniforme [0, 1) del generador `g` (cualquier función sin argumentos que los dé).
pub fn uniform(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    who: &str,
    loc: &crate::tokens::SourceLocation,
) -> Result<f64, Control> {
    let _ = loc;
    match interp.call_task(g.clone(), Vec::new())? {
        SynValue::Number(n) => {
            let x = n.to_f64();
            if (0.0..1.0).contains(&x) {
                Ok(x)
            } else {
                Err(err(format!("{}: the generator returned {}, expected a number in [0, 1)", who, x)))
            }
        }
        other => Err(err(format!("{}: the generator must return a number in [0, 1), got {}", who, other.type_name()))),
    }
}

/// Entero uniforme en [lo, hi] (inclusivo) con `g`. Rango ≤ 2^53 (exacto con 53 bits).
pub fn int_in(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    lo: i64,
    hi: i64,
    who: &str,
    loc: &crate::tokens::SourceLocation,
) -> Result<i64, Control> {
    if lo > hi {
        return Err(err(format!("{}: min ({}) is greater than max ({})", who, lo, hi)));
    }
    let span = (hi as i128 - lo as i128 + 1) as f64;
    if span > (1u64 << 53) as f64 {
        return Err(err(format!("{}: the range is wider than 2^53; split it", who)));
    }
    let u = uniform(interp, g, who, loc)?;
    Ok(lo + (u * span).floor() as i64)
}

/// Normal(mean, std) por Box–Muller.
pub fn normal(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    mean: f64,
    std: f64,
    loc: &crate::tokens::SourceLocation,
) -> Result<f64, Control> {
    let u1 = 1.0 - uniform(interp, g, "random_normal", loc)?; // (0, 1]
    let u2 = uniform(interp, g, "random_normal", loc)?;
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    Ok(mean + std * z)
}

/// Fisher–Yates con `g` → lista nueva.
pub fn shuffle(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    items: Vec<SynValue>,
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let mut v = items;
    for i in (1..v.len()).rev() {
        let j = int_in(interp, g, 0, i as i64, "shuffle", loc)? as usize;
        v.swap(i, j);
    }
    Ok(syn_list(v))
}

fn list_items(v: &SynValue, who: &str) -> Result<Vec<SynValue>, Control> {
    match v {
        SynValue::List(l) => Ok(l.borrow().clone()),
        other => Err(err(format!("{}: expected a list, got {}", who, other.type_name()))),
    }
}

fn num_kw(v: Option<SynValue>, default: f64, what: &str) -> Result<f64, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(default),
        Some(SynValue::Number(n)) => Ok(n.to_f64()),
        Some(other) => Err(err(format!("random_normal: {} must be a number, got {}", what, other.type_name()))),
    }
}

/// `random_normal(g, mean = 0, std = 1)` → un valor normal con el generador `g`.
pub fn b_normal(
    interp: &mut crate::interpreter::Interpreter,
    args: &[SynValue],
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let mean = num_kw(interp.kwarg("mean"), 0.0, "mean")?;
    let std = num_kw(interp.kwarg("std"), 1.0, "std")?;
    let g = args.first().ok_or_else(|| err("random_normal(g, mean = 0, std = 1): pass a generator from rng(seed)"))?;
    Ok(syn_float(normal(interp, g, mean, std, loc)?))
}

/// `shuffle(g, xs)` → una lista nueva, mezclada con `g`.
pub fn b_shuffle(
    interp: &mut crate::interpreter::Interpreter,
    args: &[SynValue],
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let items = list_items(args.get(1).unwrap_or(&SynValue::Nothing), "shuffle")?;
    shuffle(interp, &args[0], items, loc)
}

/// `sample(g, xs, n)` → `n` elementos distintos (sin reemplazo), en orden de extracción.
pub fn b_sample(
    interp: &mut crate::interpreter::Interpreter,
    args: &[SynValue],
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let mut items = list_items(args.get(1).unwrap_or(&SynValue::Nothing), "sample")?;
    let n = match args.get(2) {
        Some(SynValue::Number(n)) if n.is_integer() && !n.is_negative() => n.to_i64_trunc().unwrap_or(0) as usize,
        _ => return Err(err("sample(g, items, n): n must be a non-negative integer")),
    };
    if n > items.len() {
        return Err(err(format!("sample: asked for {} of {} items (without replacement)", n, items.len())));
    }
    // Fisher–Yates parcial: los primeros n.
    let len = items.len();
    for i in 0..n {
        let j = int_in(interp, &args[0], i as i64, (len - 1) as i64, "sample", loc)? as usize;
        items.swap(i, j);
    }
    items.truncate(n);
    Ok(syn_list(items))
}

/// `choice(g, xs)` → un elemento al azar.
pub fn b_choice(
    interp: &mut crate::interpreter::Interpreter,
    args: &[SynValue],
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let items = list_items(args.get(1).unwrap_or(&SynValue::Nothing), "choice")?;
    if items.is_empty() {
        return Err(err("choice: the list is empty"));
    }
    let j = int_in(interp, &args[0], 0, items.len() as i64 - 1, "choice", loc)? as usize;
    Ok(items[j].clone())
}
