//! Generadores aleatorios con semilla (v0.6.29, DATOS-12).
//!
//! El generador es un VALOR, no un estado global (el modelo de `numpy.random.default_rng` y
//! JAX): `let g be rng(42)` devuelve una función; cada `g()` es el siguiente uniforme en
//! [0, 1). Dos partes del programa no se pisan la secuencia, cada test o agente fija la suya,
//! y es PURO: bajo `--deterministic` está permitido (sólo `random()` sin generador pide la
//! capability `random`).
//!
//! **La misma secuencia que numpy, bit a bit**: `rng(s)` es `numpy.random.default_rng(s)`
//! (SeedSequence → PCG64 XSL-RR 128/64) y cada operación usa el algoritmo de su equivalente
//! en `numpy.random.Generator` (numpy ≥ 1.17, verificado contra 2.2):
//!
//! | Synsema                      | numpy                                   |
//! |------------------------------|-----------------------------------------|
//! | `g()`, `random(g)`           | `g.random()`                            |
//! | `random_int(g, lo, hi)`      | `g.integers(lo, hi + 1)` (Lemire)       |
//! | `random_normal(g, mean, std)`| `g.normal(mean, std)` (zigurat)         |
//! | `shuffle(g, xs)`             | `g.permutation(xs)`                     |
//! | `choice(g, xs)`              | `g.choice(xs)`                          |
//! | `sample(g, xs, n)`           | `g.choice(xs, n, replace=False)`        |
//! | `rng_spawn(g, n)`            | `g.spawn(n)`                            |
//!
//! Un generador es un PROCESO, no un dato (como en numpy): `let h be g` es el mismo
//! generador, y sacar de `h` avanza `g`. Para flujos independientes, `rng_spawn`.
//! Cualquier función sin argumentos que devuelva un uniforme en [0, 1) también sirve de
//! generador (entonces las operaciones usan ese uniforme, sin la compatibilidad con numpy).

#![allow(clippy::excessive_precision)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};

use crate::interpreter::{BuiltinTask, Control, RuntimeError};
use crate::number::Number;
use crate::rng_ziggurat::{FI_DOUBLE, KI_DOUBLE, WI_DOUBLE, ZIGGURAT_NOR_INV_R, ZIGGURAT_NOR_R};
use crate::types::{syn_float, syn_list, SynValue};

const PCG_MULT: u128 = 0x2360_ED05_1FC6_5DA4_4385_DF64_9FCC_F645;

// ---------------------------------------------------------------------------------------
// SeedSequence (numpy/random/bit_generator.pyx)
// ---------------------------------------------------------------------------------------

const POOL_SIZE: usize = 4;
const INIT_A: u32 = 0x43b0_d7e5;
const MULT_A: u32 = 0x931e_8875;
const INIT_B: u32 = 0x8b51_f9dd;
const MULT_B: u32 = 0x58f3_8ded;
const MIX_MULT_L: u32 = 0xca01_f9dd;
const MIX_MULT_R: u32 = 0x4973_f715;
const XSHIFT: u32 = 16;

/// Un entero no negativo en palabras de 32 bits, las bajas primero (`_int_to_uint32_array`).
fn int_to_u32_words(n: &num_bigint::BigUint) -> Vec<u32> {
    let d = n.to_u32_digits();
    if d.is_empty() {
        vec![0]
    } else {
        d
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SeedSeq {
    entropy: Vec<u32>,
    spawn_key: Vec<u64>,
    n_children_spawned: u64,
    pool: [u32; POOL_SIZE],
}

fn hashmix(value: u32, hash_const: &mut u32) -> u32 {
    let mut v = value ^ *hash_const;
    *hash_const = hash_const.wrapping_mul(MULT_A);
    v = v.wrapping_mul(*hash_const);
    v ^ (v >> XSHIFT)
}

fn mix(x: u32, y: u32) -> u32 {
    let r = MIX_MULT_L.wrapping_mul(x).wrapping_sub(MIX_MULT_R.wrapping_mul(y));
    r ^ (r >> XSHIFT)
}

impl SeedSeq {
    fn new(entropy: Vec<u32>, spawn_key: Vec<u64>) -> SeedSeq {
        // get_assembled_entropy
        let mut run = entropy.clone();
        let spawn: Vec<u32> = spawn_key
            .iter()
            .flat_map(|k| int_to_u32_words(&num_bigint::BigUint::from(*k)))
            .collect();
        if !spawn.is_empty() && run.len() < POOL_SIZE {
            run.resize(POOL_SIZE, 0);
        }
        let mut ent = run;
        ent.extend(spawn);
        // mix_entropy
        let mut pool = [0u32; POOL_SIZE];
        let mut hc = INIT_A;
        for (i, slot) in pool.iter_mut().enumerate() {
            *slot = hashmix(ent.get(i).copied().unwrap_or(0), &mut hc);
        }
        for i_src in 0..POOL_SIZE {
            for i_dst in 0..POOL_SIZE {
                if i_src != i_dst {
                    let h = hashmix(pool[i_src], &mut hc);
                    pool[i_dst] = mix(pool[i_dst], h);
                }
            }
        }
        for &e in ent.iter().skip(POOL_SIZE) {
            for slot in pool.iter_mut() {
                let h = hashmix(e, &mut hc);
                *slot = mix(*slot, h);
            }
        }
        SeedSeq { entropy, spawn_key, n_children_spawned: 0, pool }
    }

    /// `generate_state(n_words, uint64)`.
    fn generate_state_u64(&self, n_words: usize) -> Vec<u64> {
        let mut hc = INIT_B;
        let mut words = Vec::with_capacity(n_words * 2);
        for i in 0..n_words * 2 {
            let mut v = self.pool[i % POOL_SIZE];
            v ^= hc;
            hc = hc.wrapping_mul(MULT_B);
            v = v.wrapping_mul(hc);
            v ^= v >> XSHIFT;
            words.push(v);
        }
        words.chunks(2).map(|c| (c[0] as u64) | ((c[1] as u64) << 32)).collect()
    }

    fn spawn(&mut self, n: u64) -> Vec<SeedSeq> {
        let out = (self.n_children_spawned..self.n_children_spawned + n)
            .map(|i| {
                let mut key = self.spawn_key.clone();
                key.push(i);
                SeedSeq::new(self.entropy.clone(), key)
            })
            .collect();
        self.n_children_spawned += n;
        out
    }
}

// ---------------------------------------------------------------------------------------
// PCG64 (numpy/random/src/pcg64) + Generator
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Generator {
    state: u128,
    inc: u128,
    has_uint32: bool,
    uinteger: u32,
    seed_seq: SeedSeq,
}

impl Generator {
    fn from_seed_seq(seed_seq: SeedSeq) -> Generator {
        let v = seed_seq.generate_state_u64(4);
        let s = ((v[0] as u128) << 64) | v[1] as u128;
        let i = ((v[2] as u128) << 64) | v[3] as u128;
        let mut g = Generator { state: 0, inc: (i << 1) | 1, has_uint32: false, uinteger: 0, seed_seq };
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

    /// `pcg64_next32`: la mitad baja, y la alta queda guardada para la próxima.
    fn next_u32(&mut self) -> u32 {
        if self.has_uint32 {
            self.has_uint32 = false;
            return self.uinteger;
        }
        let n = self.next_u64();
        self.has_uint32 = true;
        self.uinteger = (n >> 32) as u32;
        n as u32
    }

    /// Uniforme en [0, 1) con 53 bits (`next_double`).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / 9007199254740992.0)
    }

    /// Entero en [0, rng] (`random_bounded_uint64` sin máscara: Lemire).
    fn bounded(&mut self, rng: u64) -> u64 {
        if rng == 0 {
            0
        } else if rng <= 0xFFFF_FFFF {
            if rng == 0xFFFF_FFFF {
                return self.next_u32() as u64;
            }
            let rng = rng as u32;
            let excl = rng + 1;
            let mut m = (self.next_u32() as u64) * excl as u64;
            let mut left = m as u32;
            if left < excl {
                let threshold = (u32::MAX - rng) % excl;
                while left < threshold {
                    m = (self.next_u32() as u64) * excl as u64;
                    left = m as u32;
                }
            }
            m >> 32
        } else if rng == u64::MAX {
            self.next_u64()
        } else {
            let excl = rng + 1;
            let mut m = (self.next_u64() as u128) * excl as u128;
            let mut left = m as u64;
            if left < excl {
                let threshold = (u64::MAX - rng) % excl;
                while left < threshold {
                    m = (self.next_u64() as u128) * excl as u128;
                    left = m as u64;
                }
            }
            (m >> 64) as u64
        }
    }

    /// Entero en [0, max] por máscara y rechazo (`random_interval`, el de `shuffle`).
    fn interval(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        let mut mask = max;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        mask |= mask >> 32;
        if max <= 0xFFFF_FFFF {
            loop {
                let v = self.next_u32() as u64 & mask;
                if v <= max {
                    return v;
                }
            }
        } else {
            loop {
                let v = self.next_u64() & mask;
                if v <= max {
                    return v;
                }
            }
        }
    }

    /// `random_standard_normal`: el zigurat de numpy con sus tablas.
    fn standard_normal(&mut self) -> f64 {
        loop {
            let mut r = self.next_u64();
            let idx = (r & 0xff) as usize;
            r >>= 8;
            let sign = r & 1;
            let rabs = (r >> 1) & 0x000f_ffff_ffff_ffff;
            let mut x = rabs as f64 * WI_DOUBLE[idx];
            if sign & 1 == 1 {
                x = -x;
            }
            if rabs < KI_DOUBLE[idx] {
                return x;
            }
            if idx == 0 {
                loop {
                    let xx = -ZIGGURAT_NOR_INV_R * (-self.next_f64()).ln_1p();
                    let yy = -(-self.next_f64()).ln_1p();
                    if yy + yy > xx * xx {
                        return if (rabs >> 8) & 1 == 1 { -(ZIGGURAT_NOR_R + xx) } else { ZIGGURAT_NOR_R + xx };
                    }
                }
            } else if (FI_DOUBLE[idx - 1] - FI_DOUBLE[idx]) * self.next_f64() + FI_DOUBLE[idx] < (-0.5 * x * x).exp() {
                return x;
            }
        }
    }

    /// `Generator.choice(n, size, replace=False)` sobre índices: Floyd con conjunto hash, o
    /// mezcla de la cola cuando se pide mucho de una población grande; después se mezcla.
    fn sample_indices(&mut self, pop: u64, size: u64) -> Vec<u64> {
        if pop > 10000 && size > pop / 50 {
            let mut idx: Vec<u64> = (0..pop).collect();
            let first = (pop - size).max(1);
            for i in (first..pop).rev() {
                let j = self.bounded(i) as usize;
                idx.swap(i as usize, j);
            }
            return idx[(pop - size) as usize..].to_vec();
        }
        let mut out = vec![0u64; size as usize];
        let set_size = (1.2 * size as f64) as u64;
        let mut mask = set_size;
        for s in [1, 2, 4, 8, 16, 32] {
            mask |= mask >> s;
        }
        let empty = u64::MAX;
        let mut set = vec![empty; (mask + 1) as usize];
        for j in (pop - size)..pop {
            let val = self.bounded(j);
            let mut loc = val & mask;
            while set[loc as usize] != empty && set[loc as usize] != val {
                loc = (loc + 1) & mask;
            }
            let k = (j + size - pop) as usize;
            if set[loc as usize] == empty {
                set[loc as usize] = val;
                out[k] = val;
            } else {
                let mut loc = j & mask;
                while set[loc as usize] != empty {
                    loc = (loc + 1) & mask;
                }
                set[loc as usize] = j;
                out[k] = j;
            }
        }
        for i in (1..size as usize).rev() {
            let j = self.bounded(i as u64) as usize;
            out.swap(i, j);
        }
        out
    }
}

// ---------------------------------------------------------------------------------------
// El generador como valor
// ---------------------------------------------------------------------------------------

type GenCell = Rc<RefCell<Generator>>;

thread_local! {
    /// El estado de cada generador de `rng()`, por la identidad de la función que lo
    /// representa (un `Builtin`): así `random_int(g, …)` usa los algoritmos de numpy sobre el
    /// mismo estado que `g()`. `Weak` a ambos: no retiene nada.
    static GENERATORS: RefCell<HashMap<usize, (Weak<BuiltinTask>, Weak<RefCell<Generator>>)>> =
        RefCell::new(HashMap::new());
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn wrap(gen: Generator, name: String) -> SynValue {
    let cell: GenCell = Rc::new(RefCell::new(gen));
    let st = cell.clone();
    let task = Rc::new(BuiltinTask {
        name,
        func: Rc::new(move |_i, _a, _l| Ok(syn_float(st.borrow_mut().next_f64()))),
        param_count: 0,
        param_names: None,
    });
    GENERATORS.with(|r| {
        let mut r = r.borrow_mut();
        // Poda amortizada (al duplicar el tamaño): podar en cada alta era cuadrático.
        if r.len() >= 256 && r.len().is_power_of_two() {
            r.retain(|_, (t, g)| t.strong_count() > 0 && g.strong_count() > 0);
        }
        r.insert(Rc::as_ptr(&task) as usize, (Rc::downgrade(&task), Rc::downgrade(&cell)));
    });
    SynValue::Builtin(task)
}

/// Copia del estado de un generador (para cruzar a otro hilo: `parallel_map`, `serve`).
pub fn snapshot(b: &Rc<BuiltinTask>) -> Option<Generator> {
    generator_of(&SynValue::Builtin(b.clone())).map(|c| c.borrow().clone())
}

/// Un generador reconstruido del otro lado de un snapshot.
pub fn restore(g: Generator, name: String) -> SynValue {
    wrap(g, name)
}

/// Pone el estado de `b` (un generador) en `g`: el padre de un `parallel_map` recibe así lo que
/// el worker avanzó, como con `apply`. `false` si `b` no es un generador.
pub fn set_state(b: &Rc<BuiltinTask>, g: Generator) -> bool {
    match generator_of(&SynValue::Builtin(b.clone())) {
        Some(cell) => {
            *cell.borrow_mut() = g;
            true
        }
        None => false,
    }
}

thread_local! {
    static STUB_GLOBALS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// ¿Se está sacando un snapshot de globales? (`to_send` convierte los generadores en stubs).
pub fn stubbing_globals() -> bool {
    STUB_GLOBALS.with(|c| c.get())
}

/// Corre `f` con los generadores convertidos en stubs por `to_send` (snapshot de globales).
pub fn with_stubbed_globals<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            STUB_GLOBALS.with(|c| c.set(self.0));
        }
    }
    let _reset = Reset(STUB_GLOBALS.with(|c| c.replace(true)));
    f()
}

/// El valor que ocupa el lugar de un generador de nivel superior en un request de `serve` o en
/// un worker: usarlo es un error que dice qué hacer (una copia repetiría la misma secuencia).
pub fn top_level_stub(name: &str) -> SynValue {
    let msg = format!(
        "the generator {} was created at the top level; here it would restart the same sequence in every request/worker — create it where you use it (rng(seed) from something per request), or give each parallel_map item its own with rng_spawn(g, n)",
        name
    );
    SynValue::Builtin(Rc::new(BuiltinTask {
        name: name.to_string(),
        func: Rc::new(move |_i, _a, _l| Err(crate::interpreter::Control::Error(crate::interpreter::RuntimeError::new(msg.clone())))),
        param_count: 0,
        param_names: None,
    }))
}

/// ¿`v` es un generador de `rng()`/`rng_spawn()`? (Para nombrarlo bien en un error: por
/// fuera es un builtin, pero no es una función cualquiera.)
pub fn is_generator(v: &SynValue) -> bool {
    generator_of(v).is_some()
}

/// Cómo nombrar un valor que es código en un mensaje: `a generator` o `a task`.
pub fn code_noun(v: &SynValue) -> &'static str {
    if is_generator(v) { "a generator (from rng)" } else { "a task" }
}

/// El estado numpy de `g`, si `g` salió de `rng()`/`rng_spawn()`.
fn generator_of(g: &SynValue) -> Option<GenCell> {
    let SynValue::Builtin(b) = g else { return None };
    GENERATORS.with(|r| {
        let r = r.borrow();
        let (t, cell) = r.get(&(Rc::as_ptr(b) as usize))?;
        let t = t.upgrade()?;
        if !Rc::ptr_eq(&t, b) {
            return None;
        }
        cell.upgrade()
    })
}

/// `rng(seed)` → un generador: una función sin argumentos que devuelve el siguiente
/// uniforme en [0, 1). La semilla es un entero ≥ 0 de cualquier tamaño (como numpy).
pub fn make_rng(args: &[SynValue]) -> Result<SynValue, Control> {
    let seed = match args.first() {
        Some(SynValue::Number(n @ (Number::Int(_) | Number::Big(_)))) => {
            let b = n.as_bigint().unwrap();
            b.to_biguint().ok_or_else(|| err("rng(seed): the seed must be an integer ≥ 0"))?
        }
        Some(other) => return Err(err(format!("rng(seed): the seed must be an integer, got {}", other.type_name()))),
        None => return Err(err("rng(seed): pass a seed — the same seed gives the same sequence everywhere")),
    };
    let gen = Generator::from_seed_seq(SeedSeq::new(int_to_u32_words(&seed), Vec::new()));
    Ok(wrap(gen, format!("rng({})", seed)))
}

/// `rng_spawn(g, n)` → `n` generadores independientes derivados de `g` (numpy
/// `Generator.spawn`): cada llamada da hijos nuevos, distintos de los anteriores.
pub fn b_spawn(args: &[SynValue]) -> Result<SynValue, Control> {
    let g = args.first().ok_or_else(|| err("rng_spawn(g, n)"))?;
    let cell = generator_of(g).ok_or_else(|| err("rng_spawn(g, n): g must be a generator from rng(seed)"))?;
    let n = match args.get(1) {
        Some(SynValue::Number(Number::Int(n))) if *n >= 0 => *n as u64,
        _ => return Err(err("rng_spawn(g, n): n must be an integer ≥ 0")),
    };
    let base = match g {
        SynValue::Builtin(b) => b.name.clone(),
        _ => "rng".to_string(),
    };
    let first = cell.borrow().seed_seq.n_children_spawned;
    let kids = cell.borrow_mut().seed_seq.spawn(n);
    Ok(syn_list(
        kids.into_iter()
            .enumerate()
            .map(|(i, ss)| wrap(Generator::from_seed_seq(ss), format!("{}.spawn({})", base, first + i as u64)))
            .collect(),
    ))
}

/// Un uniforme [0, 1) del generador `g` (cualquier función sin argumentos que los dé).
pub fn uniform(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    who: &str,
    loc: &crate::tokens::SourceLocation,
) -> Result<f64, Control> {
    let _ = loc;
    if let Some(cell) = generator_of(g) {
        return Ok(cell.borrow_mut().next_f64());
    }
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

/// Entero uniforme en [lo, hi] (inclusivo) con `g`: con un generador de `rng()`, el de
/// `numpy.Generator.integers(lo, hi + 1)`; con otra función, a partir de su uniforme (rango
/// ≤ 2^53).
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
    if let Some(cell) = generator_of(g) {
        let rng = (hi as i128 - lo as i128) as u64;
        let v = cell.borrow_mut().bounded(rng);
        return Ok((lo as u64).wrapping_add(v) as i64);
    }
    let span = (hi as i128 - lo as i128 + 1) as f64;
    if span > (1u64 << 53) as f64 {
        return Err(err(format!("{}: the range is wider than 2^53; split it", who)));
    }
    let u = uniform(interp, g, who, loc)?;
    Ok(lo + (u * span).floor() as i64)
}

/// Normal(mean, std): el zigurat de numpy con un generador de `rng()`; Box–Muller con otra
/// función.
pub fn normal(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    mean: f64,
    std: f64,
    loc: &crate::tokens::SourceLocation,
) -> Result<f64, Control> {
    if let Some(cell) = generator_of(g) {
        return Ok(mean + std * cell.borrow_mut().standard_normal());
    }
    let u1 = 1.0 - uniform(interp, g, "random_normal", loc)?; // (0, 1]
    let u2 = uniform(interp, g, "random_normal", loc)?;
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    Ok(mean + std * z)
}

/// Fisher–Yates con `g` → lista nueva (numpy `permutation`).
pub fn shuffle(
    interp: &mut crate::interpreter::Interpreter,
    g: &SynValue,
    items: Vec<SynValue>,
    loc: &crate::tokens::SourceLocation,
) -> Result<SynValue, Control> {
    let mut v = items;
    if let Some(cell) = generator_of(g) {
        let mut gen = cell.borrow_mut();
        for i in (1..v.len()).rev() {
            let j = gen.interval(i as u64) as usize;
            v.swap(i, j);
        }
        return Ok(syn_list(v));
    }
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
    if std < 0.0 {
        return Err(err(format!("random_normal: std must be ≥ 0, got {}", std)));
    }
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
    if let Some(cell) = generator_of(&args[0]) {
        let idx = cell.borrow_mut().sample_indices(items.len() as u64, n as u64);
        return Ok(syn_list(idx.into_iter().map(|i| items[i as usize].clone()).collect()));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gen(seed: u64) -> Generator {
        Generator::from_seed_seq(SeedSeq::new(int_to_u32_words(&num_bigint::BigUint::from(seed)), Vec::new()))
    }

    /// `np.random.default_rng(42).random(3)` y `.integers(0, 10, 5)` (numpy 2.2.1).
    #[test]
    fn matches_numpy_seed_42() {
        let mut g = gen(42);
        let r: Vec<f64> = (0..3).map(|_| g.next_f64()).collect();
        assert_eq!(r, vec![0.7739560485559633, 0.4388784397520523, 0.8585979199113825]);
    }
}
