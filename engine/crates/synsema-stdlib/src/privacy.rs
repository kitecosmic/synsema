//! T6.1 — Privacidad de salida: ruido **determinista** para privacidad diferencial.
//!
//! Dos builtins puros (sin capability, compilan al perfil wasm):
//!
//! - `laplace_noise(seed: bytes|text, scale: number) → number`
//! - `gaussian_noise(seed: bytes|text, sigma: number) → number`
//!
//! La aleatoriedad NO sale de `random()`: sale de la semilla. Un uniforme en `(0, 1)` se deriva de
//! `sha256(seed)` (los primeros 8 bytes como `u64` big-endian, `((v >> 11) | 1) / 2^53`: 53 bits
//! forzados a impar, jamás `0.0` ni `1.0` exactos, así `ln` nunca ve un cero) y se pasa por la inversa de
//! la CDF (Laplace) o por Box–Muller (Gauss, con dos uniformes de `sha256(seed ‖ 0x00)` y
//! `sha256(seed ‖ 0x01)`).
//!
//! **Misma semilla → mismo ruido.** Es una propiedad buscada, no una limitación: en un enclave sin
//! reloj ni entropía confiable la semilla es el diseño (`hmac_sha256(keccak256(state), report_id)`):
//! un observador sin el estado no la predice,
//! y **repetir la misma consulta sobre el mismo estado devuelve el mismo ruido**, con lo que
//! repetir no promedia el ruido hacia el valor real (el ataque de promediado contra el ruido
//! fresco). Quien quiera ruido fresco por consulta mete un contador o un `report_id` nuevo en la
//! semilla; el presupuesto ε lo lleva el programa en su estado (patrón, no motor).
//!
//! `scale` y `sigma` deben ser números finitos `> 0`; cualquier otra cosa es error claro. La
//! salida es siempre `float` (aunque la escala sea entera): el ruido es real por definición.
//!
//! ## Límites conocidos (L16 de la auditoría TEE)
//!
//! - **Gauss es Box–Muller**, no la inversa de la CDF: la normal no
//!   tiene inversa cerrada y Box–Muller con dos uniformes independientes es exacto en distribución.
//!   Los vectores pineados abajo fijan esa elección.
//! - **`ln`/`cos` vienen de la libm de la plataforma** (`sqrt` es IEEE-exacto; `ln` y `cos` no lo
//!   garantizan al último bit). El resultado es determinista dentro de un mismo binario o `.wasm`
//!   (lo que importa para "misma consulta, mismo ruido" y para reproducir un veredicto), pero NO se
//!   promete igualdad bit a bit entre nativo y wasm ni entre plataformas: diferencias de 1 ulp son
//!   posibles. Por eso los tests comparan con tolerancia `1e-12` y no por igualdad exacta.
//! - **Mironov 2012** ("On significance of the least significant bits for differential privacy"):
//!   los bits bajos de un float con ruido revelan información del valor real, porque el conjunto de
//!   `f(D) + ruido` alcanzable no es el mismo para `D` y `D'`. La mitigación estándar (*snapping*)
//!   redondea la SUMA publicada `f(D) + ruido` a un múltiplo de `Λ ≥ scale` y la recorta a un rango
//!   `[-B, B]`; NO se puede hacer sobre el ruido solo, que es lo único que este builtin devuelve
//!   (redondear acá daría una falsa sensación de mitigación y no cambia el conjunto alcanzable de
//!   la suma). Decisión: no se redondea; el programa que publica un agregado aplica el snapping al
//!   resultado — `round((valor + ruido) / lambda) * lambda` con `lambda` una potencia de dos
//!   `≥ scale`, y clamp — y lo documenta en el motivo de su `declassify`. Los kits llevan el patrón.

use std::rc::Rc;

use sha2::{Digest, Sha256};

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_float, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// La semilla: bytes crudos, el UTF-8 de un texto, o el plaintext de un `secret` (es material de
/// clave: se hashea y sale un real; el plaintext no se materializa hacia el programa, mismo
/// criterio que la clave de `hmac_sha256`).
///
/// Un secret **sellado** (`attestation_key()`) se RECHAZA (auditoría ronda 3, bloqueante 4): no es
/// extracción —la salida es un float derivado por SHA-256— pero la semilla del ruido no tiene por
/// qué ser la clave de identidad del enclave, y dejar acá el único borde crudo invita a que el
/// próximo builtin lo copie. La semilla del patrón es `hmac_sha256(keccak256(state), report_id)`,
/// que ya sale de una clave del programa.
fn seed_bytes(v: &SynValue, who: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Bytes(b) => Ok(b.to_vec()),
        SynValue::Text(s) => Ok(s.as_bytes().to_vec()),
        SynValue::Secret(s) => Ok(s.expose_bytes_checked(who).map_err(err)?.to_vec()),
        other => Err(err(format!(
            "{}: the seed must be bytes or text (e.g. hmac_sha256(keccak256(state), report_id)), got {}",
            who,
            other.type_name()
        ))),
    }
}

/// `scale`/`sigma`: número finito estrictamente positivo.
fn positive_param(v: &SynValue, who: &str, name: &str) -> Result<f64, Control> {
    match v {
        SynValue::Number(n) => {
            let x = n.to_f64();
            if !x.is_finite() || x <= 0.0 {
                return Err(err(format!("{}: {} must be a finite number > 0, got {}", who, name, v)));
            }
            Ok(x)
        }
        other => Err(err(format!("{}: {} must be a number > 0, got {}", who, name, other.type_name()))),
    }
}

/// Uniforme determinista en el abierto `(0, 1)` desde un digest: los 53 bits altos del `u64`
/// forzados a impar, sobre `2^53`. Mínimo `2^-53`, máximo `1 - 2^-53`: nunca `0.0` ni `1.0`.
fn unit_uniform(digest: &[u8]) -> f64 {
    let v = u64::from_be_bytes(digest[..8].try_into().expect("digest has at least 8 bytes"));
    // `| 1` fuerza un impar: nunca 0, nunca 2^53 (= 1.0), y todo impar < 2^53 es exacto en f64
    // (sumar 0.5 NO sirve: (2^53 - 1) + 0.5 redondea a 2^53 y da 1.0 exacto).
    ((v >> 11) | 1) as f64 / 9_007_199_254_740_992.0 // 2^53
}

fn sha256_of(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Laplace(0, scale) por inversa de la CDF: `x = -scale · sign(u - ½) · ln(1 - 2|u - ½|)`.
pub fn laplace_noise(seed: &[u8], scale: f64) -> f64 {
    let u = unit_uniform(&sha256_of(&[seed]));
    let d = u - 0.5;
    let sign = if d < 0.0 { -1.0 } else { 1.0 };
    -scale * sign * (1.0 - 2.0 * d.abs()).ln()
}

/// N(0, sigma²) por Box–Muller con dos uniformes independientes (dominios `seed‖00` y `seed‖01`).
pub fn gaussian_noise(seed: &[u8], sigma: f64) -> f64 {
    let u1 = unit_uniform(&sha256_of(&[seed, &[0x00]]));
    let u2 = unit_uniform(&sha256_of(&[seed, &[0x01]]));
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    sigma * z
}

fn b_laplace_noise(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "laplace_noise";
    if args.len() != 2 {
        return Err(err(format!("{}(seed, scale) takes 2 arguments", F)));
    }
    let seed = seed_bytes(&args[0], F)?;
    let scale = positive_param(&args[1], F, "scale")?;
    Ok(syn_float(laplace_noise(&seed, scale)))
}

fn b_gaussian_noise(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "gaussian_noise";
    if args.len() != 2 {
        return Err(err(format!("{}(seed, sigma) takes 2 arguments", F)));
    }
    let seed = seed_bytes(&args[0], F)?;
    let sigma = positive_param(&args[1], F, "sigma")?;
    Ok(syn_float(gaussian_noise(&seed, sigma)))
}

/// Registra `laplace_noise` y `gaussian_noise`. Puros: sin `CapabilitySet`.
pub fn register_privacy_builtins(interp: &Interpreter) {
    interp.register_builtin("laplace_noise", 2, Rc::new(|_i, a, _l| b_laplace_noise(a)));
    interp.register_builtin("gaussian_noise", 2, Rc::new(|_i, a, _l| b_gaussian_noise(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::{syn_bytes, syn_int, syn_text};

    fn ok(r: Result<SynValue, Control>) -> f64 {
        match r {
            Ok(SynValue::Number(n)) => n.to_f64(),
            Ok(other) => panic!("esperaba number, got {}", other),
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn err_of(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.to_string(),
            Ok(v) => panic!("esperaba error, got {}", v),
            Err(_) => panic!("control"),
        }
    }

    #[test]
    fn unit_uniform_is_open_interval_and_deterministic() {
        assert_eq!(unit_uniform(&[0u8; 32]), 1.0 / 9_007_199_254_740_992.0);
        let top = unit_uniform(&[0xffu8; 32]);
        assert_eq!(top, 1.0 - 1.0 / 9_007_199_254_740_992.0);
        assert!(top < 1.0);
        // El caso que rompía la variante "+ 0.5": el mayor impar sigue siendo < 1.0.
        let mut almost = [0xffu8; 32];
        almost[6] = 0xf7; // v = 0xfffffffffffff7ff → v >> 11 = 2^53 - 2 → | 1 = 2^53 - 1
        assert!(unit_uniform(&almost) < 1.0);
        assert_eq!(unit_uniform(&sha256_of(&[b"x"])), unit_uniform(&sha256_of(&[b"x"])));
    }

    /// Vectores fijos (calculados una vez con la misma fórmula fuera de Rust; ver el reporte de la
    /// tanda). Si alguien cambia la derivación del uniforme, esto lo delata.
    #[test]
    fn pinned_vectors() {
        let cases: &[(&[u8], f64, f64, f64)] = &[
            // (seed, scale/sigma, laplace, gaussian)
            (b"seed-1", 1.0, LAPLACE_SEED_1, GAUSS_SEED_1),
            (b"seed-2", 2.5, LAPLACE_SEED_2, GAUSS_SEED_2),
            (b"", 1.0, LAPLACE_EMPTY, GAUSS_EMPTY),
            (&[0u8, 1, 2, 3], 0.1, LAPLACE_BYTES, GAUSS_BYTES),
        ];
        for (seed, s, l, g) in cases {
            let lap = laplace_noise(seed, *s);
            let gau = gaussian_noise(seed, *s);
            assert!((lap - l).abs() < 1e-12, "laplace({:?}, {}) = {} ≠ {}", seed, s, lap, l);
            assert!((gau - g).abs() < 1e-12, "gaussian({:?}, {}) = {} ≠ {}", seed, s, gau, g);
        }
    }

    // Valores pineados: sha256 → u64 BE >> 11, | 1, / 2^53; Laplace inversa; Box–Muller (cos).
    const LAPLACE_SEED_1: f64 = -2.16499352759329;
    const GAUSS_SEED_1: f64 = 1.123095419229882;
    const LAPLACE_SEED_2: f64 = -1.0779049600440997;
    const GAUSS_SEED_2: f64 = 1.9057115534532507;
    const LAPLACE_EMPTY: f64 = 1.508832639063013;
    const GAUSS_EMPTY: f64 = -0.3755877822603734;
    const LAPLACE_BYTES: f64 = -0.31827988507988775;
    const GAUSS_BYTES: f64 = -0.03540449661849892;

    #[test]
    fn same_seed_same_noise_and_scale_is_linear() {
        assert_eq!(laplace_noise(b"k", 1.0), laplace_noise(b"k", 1.0));
        assert_eq!(gaussian_noise(b"k", 1.0), gaussian_noise(b"k", 1.0));
        assert!((laplace_noise(b"k", 3.0) - 3.0 * laplace_noise(b"k", 1.0)).abs() < 1e-12);
        assert!((gaussian_noise(b"k", 3.0) - 3.0 * gaussian_noise(b"k", 1.0)).abs() < 1e-12);
        assert_ne!(laplace_noise(b"k", 1.0), laplace_noise(b"K", 1.0));
        // Texto y bytes con el mismo contenido son la misma semilla.
        assert_eq!(ok(b_laplace_noise(&[syn_text("k"), syn_int(1)])), ok(b_laplace_noise(&[syn_bytes(b"k".to_vec()), syn_int(1)])));
    }

    /// Simetría estadística sobre 10k semillas: media ≈ 0, varianza ≈ 2·scale² (Laplace) y
    /// ≈ sigma² (Gauss). Tolerancias amplias: es un smoke test de la distribución, no un test de
    /// hipótesis.
    #[test]
    fn statistical_moments_over_10k_seeds() {
        let n = 10_000;
        let (scale, sigma) = (1.5f64, 0.7f64);
        let (mut sl, mut sl2, mut sg, mut sg2) = (0.0, 0.0, 0.0, 0.0);
        let (mut pos_l, mut pos_g) = (0usize, 0usize);
        for i in 0..n {
            let seed = format!("seed-{}", i);
            let l = laplace_noise(seed.as_bytes(), scale);
            let g = gaussian_noise(seed.as_bytes(), sigma);
            sl += l;
            sl2 += l * l;
            sg += g;
            sg2 += g * g;
            pos_l += (l > 0.0) as usize;
            pos_g += (g > 0.0) as usize;
        }
        let nf = n as f64;
        let (mean_l, var_l) = (sl / nf, sl2 / nf - (sl / nf).powi(2));
        let (mean_g, var_g) = (sg / nf, sg2 / nf - (sg / nf).powi(2));
        assert!(mean_l.abs() < 0.1, "laplace mean {}", mean_l);
        assert!((var_l - 2.0 * scale * scale).abs() < 0.5, "laplace var {} (expected {})", var_l, 2.0 * scale * scale);
        assert!(mean_g.abs() < 0.05, "gauss mean {}", mean_g);
        assert!((var_g - sigma * sigma).abs() < 0.1, "gauss var {} (expected {})", var_g, sigma * sigma);
        // Signo balanceado (≈ 50 %).
        assert!((pos_l as f64 / nf - 0.5).abs() < 0.03, "laplace positives {}", pos_l);
        assert!((pos_g as f64 / nf - 0.5).abs() < 0.03, "gauss positives {}", pos_g);
    }

    /// Ronda 3 (bloqueante 4): la semilla acepta un `secret` normal (es material de clave) pero
    /// NO el sellado de la identidad atestada.
    #[test]
    fn sealed_secret_is_not_a_valid_seed() {
        use synsema_core::secret::SecretInner;
        use std::rc::Rc;
        let normal = SynValue::Secret(Rc::new(SecretInner::new_bytes("REPORT_KEY", b"seed-1".to_vec())));
        // Un secret normal da EXACTAMENTE el mismo ruido que sus bytes: es la semilla del patrón.
        assert_eq!(ok(b_laplace_noise(&[normal.clone(), syn_int(1)])), LAPLACE_SEED_1);
        assert_eq!(ok(b_gaussian_noise(&[normal, syn_int(1)])), GAUSS_SEED_1);
        let sealed = SynValue::Secret(Rc::new(SecretInner::new_bytes_sealed("attestation_key", b"seed-1".to_vec())));
        for (r, who) in [
            (b_laplace_noise(&[sealed.clone(), syn_int(1)]), "laplace_noise"),
            (b_gaussian_noise(&[sealed, syn_int(1)]), "gaussian_noise"),
        ] {
            let e = err_of(r);
            assert!(e.starts_with(&format!("{}: secret(attestation_key) is sealed", who)), "{}", e);
            assert!(e.contains("stays inside the process"), "{}", e);
        }
    }

    #[test]
    fn rejects_bad_params_with_clear_errors() {
        assert!(err_of(b_laplace_noise(&[syn_text("s"), syn_int(0)])).contains("scale must be a finite number > 0"));
        assert!(err_of(b_laplace_noise(&[syn_text("s"), syn_int(-3)])).contains("scale must be"));
        assert!(err_of(b_gaussian_noise(&[syn_text("s"), syn_float(f64::NAN)])).contains("sigma must be a finite number > 0"));
        assert!(err_of(b_gaussian_noise(&[syn_text("s"), syn_float(f64::INFINITY)])).contains("sigma must be"));
        assert!(err_of(b_gaussian_noise(&[syn_text("s"), syn_text("1")])).contains("sigma must be a number"));
        assert!(err_of(b_laplace_noise(&[syn_int(1), syn_int(1)])).contains("the seed must be bytes or text"));
        assert!(err_of(b_laplace_noise(&[syn_text("s")])).contains("takes 2 arguments"));
        // La salida es siempre float, aunque la escala sea entera.
        assert!(matches!(b_laplace_noise(&[syn_text("s"), syn_int(2)]), Ok(SynValue::Number(synsema_core::number::Number::Float(_)))));
    }
}
