//! Elección del próximo token, y la razón por la que el default es determinista.
//!
//! Diseño:
//! - **Greedy por default** (`temperature = 0`): un agente que decide dos veces lo mismo sobre la
//!   misma entrada tiene que decidir igual. Es el camino que el spec promete determinista bit a
//!   bit (§5) y el que los goldens vigilan.
//! - **Con temperatura, seed fija**: el muestreo sigue siendo reproducible entre corridas (mismo
//!   binario + mismo prompt → misma salida). Dejar la seed al azar haría imposible atestiguar una
//!   decisión, que es justamente lo que este crate viene a arreglar.
//!
//! Trabaja sobre `&[f32]`, no sobre un tensor: así sirve a los dos backends sin que ninguno tenga
//! que convertir al tipo del otro.

/// Seed del sampler. Es la velocidad de la luz en m/s: una constante que nadie va a confundir con
/// un valor calculado, para que quede claro que es arbitraria y fija a propósito.
pub const SAMPLER_SEED: u64 = 299_792_458;

/// Elige el próximo token sobre logits crudos.
///
/// El estado (el generador) vive en la instancia, así que una secuencia de llamadas con
/// temperatura es reproducible de punta a punta y no depende del reloj ni del sistema.
pub struct Sampler {
    temperature: f64,
    rng: Xorshift64,
}

impl Sampler {
    pub fn new(temperature: f64) -> Self {
        Sampler { temperature, rng: Xorshift64::new(SAMPLER_SEED) }
    }

    /// `temperature <= 0` → argmax. `> 0` → muestreo de la distribución escalada.
    pub fn sample(&mut self, logits: &[f32]) -> Result<u32, String> {
        if logits.is_empty() {
            return Err("no hay logits para elegir".to_string());
        }
        if self.temperature <= 0.0 {
            return Ok(argmax(logits));
        }
        // Softmax estable sobre los logits escalados.
        let scale = self.temperature.max(1e-3);
        let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        if !max.is_finite() {
            return Err("los logits no son finitos".to_string());
        }
        let mut probs = Vec::with_capacity(logits.len());
        let mut total = 0f64;
        for &l in logits {
            let p = (((l - max) as f64) / scale).exp();
            probs.push(p);
            total += p;
        }
        if total <= 0.0 {
            return Ok(argmax(logits));
        }
        // Muestreo por acumulación. El corte se compara contra la suma parcial en `f64` para que
        // un vocabulario de 150 000 entradas no pierda la cola por redondeo.
        let cut = self.rng.next_f64() * total;
        let mut acc = 0f64;
        for (i, p) in probs.iter().enumerate() {
            acc += p;
            if acc >= cut {
                return Ok(i as u32);
            }
        }
        Ok((probs.len() - 1) as u32)
    }
}

/// El índice del mayor. Ante empate gana el primero, que es lo que hace que sea determinista.
pub fn argmax(logits: &[f32]) -> u32 {
    let mut best = 0usize;
    let mut best_v = f32::NEG_INFINITY;
    for (i, &v) in logits.iter().enumerate() {
        if v > best_v {
            best_v = v;
            best = i;
        }
    }
    best as u32
}

/// Generador xorshift64*: determinista, sin dependencias y más que suficiente para muestrear un
/// token. **No sirve para nada criptográfico**, y acá no hace falta que sirva.
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        // El estado nunca puede ser cero: xorshift se queda pegado ahí.
        Xorshift64 { state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Un uniforme en `[0, 1)`, usando los 53 bits de mantisa de un `f64`.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greedy_picks_the_maximum() {
        let mut s = Sampler::new(0.0);
        assert_eq!(s.sample(&[1.0, 5.0, 2.0]).unwrap(), 1);
        assert_eq!(s.sample(&[-1.0, -5.0, -0.5]).unwrap(), 2);
    }

    #[test]
    fn greedy_is_stable_on_ties() {
        // Ante empate gana el primero: si no, dos corridas podrían diferir.
        let mut s = Sampler::new(0.0);
        assert_eq!(s.sample(&[3.0, 3.0, 3.0]).unwrap(), 0);
    }

    #[test]
    fn greedy_is_deterministic_across_samplers() {
        let logits = [0.1, 0.9, 0.4, 0.9];
        let a = Sampler::new(0.0).sample(&logits).unwrap();
        let b = Sampler::new(0.0).sample(&logits).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sampling_with_temperature_is_reproducible() {
        // La misma seed y la misma secuencia de llamadas dan la misma secuencia de tokens.
        let logits = [1.0, 2.0, 3.0, 0.5];
        let run = || {
            let mut s = Sampler::new(0.8);
            (0..10).map(|_| s.sample(&logits).unwrap()).collect::<Vec<_>>()
        };
        assert_eq!(run(), run(), "el muestreo con seed fija debe repetirse");
    }

    #[test]
    fn temperature_actually_samples_more_than_one_token() {
        let logits = [1.0, 1.1, 0.9];
        let mut s = Sampler::new(2.0);
        let seen: std::collections::HashSet<u32> =
            (0..200).map(|_| s.sample(&logits).unwrap()).collect();
        assert!(seen.len() > 1, "con temperatura alta no puede salir siempre el mismo");
    }

    #[test]
    fn higher_temperature_is_less_concentrated() {
        let logits = [5.0, 0.0, 0.0, 0.0];
        let count = |t: f64| {
            let mut s = Sampler::new(t);
            (0..500).filter(|_| s.sample(&logits).unwrap() == 0).count()
        };
        assert!(count(0.5) > count(5.0), "menos temperatura concentra más en el máximo");
    }

    #[test]
    fn empty_and_non_finite_logits_are_errors() {
        assert!(Sampler::new(0.0).sample(&[]).is_err());
        assert!(Sampler::new(1.0).sample(&[f32::NAN, f32::NAN]).is_err());
    }

    #[test]
    fn rng_never_gets_stuck_at_zero() {
        let mut r = Xorshift64::new(0);
        let a = r.next_u64();
        let b = r.next_u64();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn rng_uniform_stays_in_range() {
        let mut r = Xorshift64::new(SAMPLER_SEED);
        for _ in 0..1000 {
            let v = r.next_f64();
            assert!((0.0..1.0).contains(&v), "valor fuera de [0,1): {}", v);
        }
    }
}
