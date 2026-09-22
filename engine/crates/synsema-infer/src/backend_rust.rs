//! El backend propio: tensores `f32` en Rust puro, sin candle.
//!
//! Éste es el archivo que I4 viene a escribir (spec `synsema-infer.md` §7). No es un framework de
//! tensores: es **exactamente el conjunto de operaciones que nuestras arquitecturas necesitan**, y
//! nada más. Esa restricción es el proyecto entero — un framework general son años, esto es una
//! lista acotada que cabe en un archivo.
//!
//! ## Dos decisiones que lo hacen tratable
//!
//! 1. **Sin dimensión de batch.** Todo es `[seq, dim]`, nunca `[batch, seq, dim]`. Laya corre de a
//!    una secuencia y el `judge` trae pocas preguntas, así que el batch sólo agregaría padding,
//!    índices y bugs. Quitarlo borra la mitad del código y toda una clase de errores de forma.
//! 2. **El matmul no se escribe: se usa `matrixmultiply`.** Es puro Rust, de otro autor, con
//!    kernels SIMD, y ya estaba en el árbol. Escribir un matmul competitivo es un proyecto en sí
//!    mismo, y el nuestro sería peor. Lo que sí es nuestro es todo lo demás.
//!
//! ## Precisión
//!
//! Todo en `f32`. Los acumuladores de `layer_norm` y `softmax` van en `f64` porque una suma de
//! miles de términos en `f32` pierde dígitos donde más duele: la varianza de una norma y el
//! denominador de una softmax.

use crate::tensor_rust::RTensor;

/// `x @ w^T + b`, la operación que domina el tiempo de un transformer.
///
/// `w` viene en el layout de PyTorch —`[out, in]`, o sea ya transpuesta— así que se recorre por
/// filas y no hace falta transponerla en memoria: se lo decimos a `matrixmultiply` con los strides.
pub fn linear(x: &RTensor, w: &RTensor, b: Option<&RTensor>) -> Result<RTensor, String> {
    let (n, k) = x.dims2()?;
    let (out, k_w) = w.dims2()?;
    if k != k_w {
        return Err(format!("linear: x es [{}, {}] y w es [{}, {}]", n, k, out, k_w));
    }
    let mut y = vec![0f32; n * out];
    // C[n, out] = A[n, k] * B[k, out], con B = w^T expresada por strides: w es [out, k] en
    // row-major, así que su transpuesta tiene rsb = 1 y csb = k.
    unsafe {
        matrixmultiply::sgemm(
            n, k, out, 1.0, x.data().as_ptr(), k as isize, 1, // A: row-major [n, k]
            w.data().as_ptr(), 1, k as isize, // B = w^T sin copiar
            0.0, y.as_mut_ptr(), out as isize, 1,
        );
    }
    if let Some(bias) = b {
        let bias = bias.data();
        if bias.len() != out {
            return Err(format!("linear: bias de {} para salida de {}", bias.len(), out));
        }
        for row in y.chunks_mut(out) {
            for (v, bb) in row.iter_mut().zip(bias) {
                *v += bb;
            }
        }
    }
    RTensor::new(y, vec![n, out])
}

/// `a @ b` sin transponer: `[n, k] × [k, m] → [n, m]`. La usan los scores de atención.
pub fn matmul(a: &RTensor, b: &RTensor) -> Result<RTensor, String> {
    let (n, k) = a.dims2()?;
    let (k_b, m) = b.dims2()?;
    if k != k_b {
        return Err(format!("matmul: [{}, {}] × [{}, {}]", n, k, k_b, m));
    }
    let mut y = vec![0f32; n * m];
    unsafe {
        matrixmultiply::sgemm(
            n, k, m, 1.0, a.data().as_ptr(), k as isize, 1, b.data().as_ptr(), m as isize, 1, 0.0,
            y.as_mut_ptr(), m as isize, 1,
        );
    }
    RTensor::new(y, vec![n, m])
}

/// LayerNorm por fila. `bias` es opcional: las normas del encoder de ModernBERT no lo llevan y las
/// de las cabezas de Laya sí — cargar una por la otra no falla, da números mal.
pub fn layer_norm(
    x: &RTensor,
    weight: &[f32],
    bias: Option<&[f32]>,
    eps: f32,
) -> Result<RTensor, String> {
    let (n, d) = x.dims2()?;
    if weight.len() != d {
        return Err(format!("layer_norm: peso de {} para dimensión {}", weight.len(), d));
    }
    let mut out = vec![0f32; n * d];
    for (row_in, row_out) in x.data().chunks(d).zip(out.chunks_mut(d)) {
        // Acumuladores en f64: sumar miles de f32 pierde exactamente donde importa.
        let mean = row_in.iter().map(|&v| v as f64).sum::<f64>() / d as f64;
        let var =
            row_in.iter().map(|&v| { let c = v as f64 - mean; c * c }).sum::<f64>() / d as f64;
        let inv = 1.0 / (var + eps as f64).sqrt();
        for (i, (&v, o)) in row_in.iter().zip(row_out.iter_mut()).enumerate() {
            let normed = ((v as f64 - mean) * inv) as f32;
            *o = normed * weight[i] + bias.map(|b| b[i]).unwrap_or(0.0);
        }
    }
    RTensor::new(out, vec![n, d])
}

/// Softmax por fila, estable (resta el máximo antes de exponenciar).
pub fn softmax_rows(x: &mut RTensor) -> Result<(), String> {
    let (_, d) = x.dims2()?;
    for row in x.data_mut().chunks_mut(d) {
        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        // Una fila entera en -inf daría 0/0. No debería pasar con nuestras máscaras, pero si
        // pasara, devolver uniforme es mejor que propagar NaN a toda la red.
        if !max.is_finite() {
            let u = 1.0 / d as f32;
            row.iter_mut().for_each(|v| *v = u);
            continue;
        }
        let mut sum = 0f64;
        for v in row.iter_mut() {
            let e = ((*v - max) as f64).exp();
            *v = e as f32;
            sum += e;
        }
        if sum > 0.0 {
            let inv = (1.0 / sum) as f32;
            row.iter_mut().for_each(|v| *v *= inv);
        }
    }
    Ok(())
}

/// GELU exacta (con `erf`), que es la que usan ModernBERT y el scorer de Laya.
///
/// **No es la aproximación con `tanh`.** Difieren en ~1e-3, que suena poco y es suficiente para
/// mover un argmax cuando dos opciones están parejas.
pub fn gelu(x: &mut RTensor) {
    for v in x.data_mut() {
        let t = *v as f64;
        *v = (0.5 * t * (1.0 + erf(t / std::f64::consts::SQRT_2))) as f32;
    }
}

/// ReLU. La usa el MLP de las cabezas de decisión: el `TransformerEncoderLayer` de PyTorch la
/// tiene por defecto, aunque el encoder use GELU.
/// GELU con la aproximación **tanh**, que es la que usa Gemma (`gelu_pytorch_tanh`) y la que
/// implementa ggml.
///
/// No es la misma función que [`gelu`]: aquélla usa `erf` y es la definición exacta. Se parecen
/// hasta unos `1e-3`, y por eso tener las dos importa — un modelo entrenado con una y corrido con
/// la otra no explota, **deriva**, que es la forma de estar mal que más cuesta descubrir.
pub fn gelu_tanh(x: &mut RTensor) {
    // sqrt(2/π)
    const C: f32 = 0.797_884_56;
    for v in x.data_mut() {
        let t = *v;
        *v = 0.5 * t * (1.0 + (C * (t + 0.044_715 * t * t * t)).tanh());
    }
}

pub fn relu(x: &mut RTensor) {
    for v in x.data_mut() {
        if *v < 0.0 {
            *v = 0.0;
        }
    }
}

/// `erf` por la aproximación de Abramowitz y Stegun 7.1.26, con error < 1,5e-7.
///
/// Rust no trae `erf` en `std`, y traer una crate entera por una función de doce líneas no se
/// justifica. **Error máximo medido: 1,394e-07** (y 2,111e-07 al propagarse a GELU), contra
/// pesos que son `f16` convertidos a `f32` — sobra por tres órdenes de magnitud.
fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-x * x).exp();
    sign * y
}

/// Suma elemento a elemento, en el lugar. Es la conexión residual.
pub fn add_inplace(x: &mut RTensor, other: &RTensor) -> Result<(), String> {
    if x.shape() != other.shape() {
        return Err(format!("add: {:?} contra {:?}", x.shape(), other.shape()));
    }
    for (a, b) in x.data_mut().iter_mut().zip(other.data()) {
        *a += b;
    }
    Ok(())
}

/// Suma un vector a cada fila (broadcast). Lo usa el sesgo de tipo de pregunta de Laya.
pub fn add_row_broadcast(x: &mut RTensor, row: &[f32]) -> Result<(), String> {
    let (_, d) = x.dims2()?;
    if row.len() != d {
        return Err(format!("broadcast: vector de {} para dimensión {}", row.len(), d));
    }
    for chunk in x.data_mut().chunks_mut(d) {
        for (v, r) in chunk.iter_mut().zip(row) {
            *v += r;
        }
    }
    Ok(())
}

/// Multiplicación elemento a elemento. La usa la compuerta del MLP de ModernBERT.
pub fn mul_inplace(x: &mut RTensor, other: &RTensor) -> Result<(), String> {
    if x.shape() != other.shape() {
        return Err(format!("mul: {:?} contra {:?}", x.shape(), other.shape()));
    }
    for (a, b) in x.data_mut().iter_mut().zip(other.data()) {
        *a *= b;
    }
    Ok(())
}

/// RoPE **no tradicional** (el estilo "rotate half" de Hugging Face y candle), aplicada en el lugar
/// sobre `[seq, num_heads * head_dim]`.
///
/// `pos_offset` es cuántos tokens ya pasaron: con KV cache, el token nuevo no está en la
/// posición 0. Olvidarlo hace que cada continuación vuelva a empezar desde el principio.
///
/// La variante importa: la "tradicional" rota pares contiguos `(x0,x1), (x2,x3)…`, y ésta parte el
/// vector al medio y rota `(x_i, x_{i+d/2})`. Con los mismos pesos, elegir mal no falla — produce
/// otra respuesta. ModernBERT usa ésta, con **dos bases distintas** según la capa sea de atención
/// global o local.
pub fn rope_inplace(
    x: &mut RTensor,
    num_heads: usize,
    head_dim: usize,
    base: f32,
    pos_offset: usize,
) -> Result<(), String> {
    let (seq, width) = x.dims2()?;
    if width != num_heads * head_dim || head_dim % 2 != 0 {
        return Err(format!(
            "rope: ancho {} no es {} cabezas × {} (par)",
            width, num_heads, head_dim
        ));
    }
    let half = head_dim / 2;
    // cos/sin por posición y frecuencia: se calculan una vez para toda la secuencia.
    let mut cos = vec![0f32; seq * half];
    let mut sin = vec![0f32; seq * half];
    for pos in 0..seq {
        for i in 0..half {
            let inv_freq = 1.0 / (base as f64).powf(2.0 * i as f64 / head_dim as f64);
            // La posición ABSOLUTA en la secuencia: con KV cache, el token que llega no está en
            // la posición 0 sino después de todo lo que ya se generó.
            let angle = (pos_offset + pos) as f64 * inv_freq;
            cos[pos * half + i] = angle.cos() as f32;
            sin[pos * half + i] = angle.sin() as f32;
        }
    }
    let data = x.data_mut();
    for pos in 0..seq {
        for h in 0..num_heads {
            let off = pos * width + h * head_dim;
            for i in 0..half {
                let (c, s) = (cos[pos * half + i], sin[pos * half + i]);
                let a = data[off + i];
                let b = data[off + half + i];
                data[off + i] = a * c - b * s;
                data[off + half + i] = a * s + b * c;
            }
        }
    }
    Ok(())
}

/// Multiplica todo por un escalar, en el lugar. Es el `1/sqrt(head_dim)` de la atención.
pub fn scale_inplace(x: &mut RTensor, factor: f32) {
    for v in x.data_mut() {
        *v *= factor;
    }
}

/// Máscara de atención local sobre una matriz de scores `[seq, seq]`.
///
/// ModernBERT alterna capas de atención **global** (cada token ve a todos) y **local** (sólo a los
/// que están a distancia `<= window/2`). El `<=` importa: con `<` la ventana queda un token más
/// corta y los números divergen sin que nada falle.
pub fn mask_local_inplace(scores: &mut RTensor, window: usize) -> Result<(), String> {
    let (n, m) = scores.dims2()?;
    if n != m {
        return Err(format!("la máscara local espera una matriz cuadrada, es [{}, {}]", n, m));
    }
    let max_distance = window / 2;
    let data = scores.data_mut();
    for i in 0..n {
        for j in 0..n {
            if i.abs_diff(j) > max_distance {
                data[i * n + j] = f32::NEG_INFINITY;
            }
        }
    }
    Ok(())
}

/// RMSNorm: `x / sqrt(mean(x²) + eps) · weight`.
///
/// **No es LayerNorm**: no resta la media. Los decoders modernos (llama, qwen, gemma) usan ésta
/// porque sale más barata y funciona igual; los encoders tipo BERT usan la otra. Confundirlas no
/// falla, da números mal.
pub fn rms_norm(x: &RTensor, weight: &[f32], eps: f32) -> Result<RTensor, String> {
    let (n, d) = x.dims2()?;
    if weight.len() != d {
        return Err(format!("rms_norm: peso de {} para dimensión {}", weight.len(), d));
    }
    let mut out = vec![0f32; n * d];
    for (row_in, row_out) in x.data().chunks(d).zip(out.chunks_mut(d)) {
        // Acumulador en f64 por la misma razón que en layer_norm.
        let sum_sq: f64 = row_in.iter().map(|&v| (v as f64) * (v as f64)).sum();
        let inv = 1.0 / ((sum_sq / d as f64) + eps as f64).sqrt();
        for (i, (&v, o)) in row_in.iter().zip(row_out.iter_mut()).enumerate() {
            *o = ((v as f64 * inv) as f32) * weight[i];
        }
    }
    RTensor::new(out, vec![n, d])
}

/// RMSNorm aplicada **por cabeza**, sobre `[seq, heads · head_dim]`.
///
/// Es lo que hace qwen3 con `attn_q_norm` y `attn_k_norm`: normaliza cada cabeza por separado con
/// el mismo vector de pesos de `head_dim`. Aplicarla sobre la fila entera daría otro resultado.
pub fn rms_norm_per_head_inplace(
    x: &mut RTensor,
    heads: usize,
    head_dim: usize,
    weight: &[f32],
    eps: f32,
) -> Result<(), String> {
    let (_, width) = x.dims2()?;
    if width != heads * head_dim || weight.len() != head_dim {
        return Err(format!(
            "rms_norm por cabeza: ancho {} con {} cabezas de {} y peso de {}",
            width,
            heads,
            head_dim,
            weight.len()
        ));
    }
    for row in x.data_mut().chunks_mut(width) {
        for h in 0..heads {
            let seg = &mut row[h * head_dim..(h + 1) * head_dim];
            let sum_sq: f64 = seg.iter().map(|&v| (v as f64) * (v as f64)).sum();
            let inv = 1.0 / ((sum_sq / head_dim as f64) + eps as f64).sqrt();
            for (i, v) in seg.iter_mut().enumerate() {
                *v = ((*v as f64 * inv) as f32) * weight[i];
            }
        }
    }
    Ok(())
}

/// SiLU (también llamada swish): `x · sigmoid(x)`. Es la activación de la compuerta en SwiGLU.
pub fn silu(x: &mut RTensor) {
    for v in x.data_mut() {
        let t = *v as f64;
        *v = (t / (1.0 + (-t).exp())) as f32;
    }
}

/// Máscara causal: la posición `i` de la consulta sólo ve claves hasta `offset + i`.
///
/// `offset` es cuántos tokens ya estaban en el cache. Sin él, el primer token de una continuación
/// vería el futuro de su propio bloque.
pub fn mask_causal_inplace(scores: &mut RTensor, offset: usize) -> Result<(), String> {
    let (q_len, k_len) = scores.dims2()?;
    let data = scores.data_mut();
    for i in 0..q_len {
        for j in 0..k_len {
            if j > offset + i {
                data[i * k_len + j] = f32::NEG_INFINITY;
            }
        }
    }
    Ok(())
}

/// Máscara causal **con ventana deslizante**: la posición `i` ve las claves `j` que cumplen
/// `j <= offset+i` y `offset+i - j <= window`.
///
/// Es lo que usa gemma3 en cinco de cada seis capas: mirar hacia atrás, pero sólo hasta cierta
/// distancia. Combina las dos restricciones — quitar cualquiera de las dos da otro modelo.
pub fn mask_causal_window_inplace(
    scores: &mut RTensor,
    offset: usize,
    window: usize,
) -> Result<(), String> {
    let (q_len, k_len) = scores.dims2()?;
    let data = scores.data_mut();
    for i in 0..q_len {
        let pos = offset + i;
        for j in 0..k_len {
            if j > pos || pos - j > window {
                data[i * k_len + j] = f32::NEG_INFINITY;
            }
        }
    }
    Ok(())
}

/// Filas de una tabla de embeddings: `[n] → [n, dim]`.
pub fn embedding(ids: &[u32], table: &RTensor) -> Result<RTensor, String> {
    let (vocab, dim) = table.dims2()?;
    let mut out = Vec::with_capacity(ids.len() * dim);
    for &id in ids {
        let id = id as usize;
        if id >= vocab {
            return Err(format!("embedding: token {} fuera del vocabulario de {}", id, vocab));
        }
        out.extend_from_slice(&table.data()[id * dim..(id + 1) * dim]);
    }
    RTensor::new(out, vec![ids.len(), dim])
}

/// Toma filas por índice. La usan los marcadores de Laya sobre la salida del encoder.
pub fn index_select(x: &RTensor, rows: &[usize]) -> Result<RTensor, String> {
    let (n, d) = x.dims2()?;
    let mut out = Vec::with_capacity(rows.len() * d);
    for &r in rows {
        if r >= n {
            return Err(format!("index_select: fila {} de {}", r, n));
        }
        out.extend_from_slice(&x.data()[r * d..(r + 1) * d]);
    }
    RTensor::new(out, vec![rows.len(), d])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(data: &[f32], shape: &[usize]) -> RTensor {
        RTensor::new(data.to_vec(), shape.to_vec()).unwrap()
    }

    #[test]
    fn linear_matches_hand_computation() {
        // x [2,3] × w^T [3,2] + b
        let x = t(&[1., 2., 3., 4., 5., 6.], &[2, 3]);
        let w = t(&[1., 0., 0., 0., 1., 0.], &[2, 3]); // selecciona col0 y col1
        let b = t(&[10., 20.], &[2]);
        let y = linear(&x, &w, Some(&b)).unwrap();
        assert_eq!(y.shape(), &[2, 2]);
        assert_eq!(y.data(), &[11., 22., 14., 25.]);
    }

    #[test]
    fn matmul_is_plain_row_by_column() {
        let a = t(&[1., 2., 3., 4.], &[2, 2]);
        let b = t(&[5., 6., 7., 8.], &[2, 2]);
        let c = matmul(&a, &b).unwrap();
        assert_eq!(c.data(), &[19., 22., 43., 50.]);
    }

    #[test]
    fn layer_norm_centers_and_scales() {
        let x = t(&[1., 2., 3., 4.], &[1, 4]);
        let y = layer_norm(&x, &[1., 1., 1., 1.], None, 1e-5).unwrap();
        let mean: f32 = y.data().iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-5, "media {}", mean);
        let var: f32 = y.data().iter().map(|v| v * v).sum::<f32>() / 4.0;
        assert!((var - 1.0).abs() < 1e-3, "varianza {}", var);
    }

    #[test]
    fn layer_norm_bias_is_applied_when_present() {
        let x = t(&[1., 2.], &[1, 2]);
        let sin_bias = layer_norm(&x, &[1., 1.], None, 1e-5).unwrap();
        let con_bias = layer_norm(&x, &[1., 1.], Some(&[5., 5.]), 1e-5).unwrap();
        for (a, b) in sin_bias.data().iter().zip(con_bias.data()) {
            assert!((b - a - 5.0).abs() < 1e-5);
        }
    }

    #[test]
    fn softmax_rows_sum_to_one_and_are_stable() {
        let mut x = t(&[1., 2., 3., 1000., 1000., 1000.], &[2, 3]);
        softmax_rows(&mut x).unwrap();
        for row in x.data().chunks(3) {
            let s: f32 = row.iter().sum();
            assert!((s - 1.0).abs() < 1e-5, "suma {}", s);
            assert!(row.iter().all(|v| v.is_finite()), "valores no finitos: {:?}", row);
        }
    }

    #[test]
    fn softmax_of_a_fully_masked_row_is_uniform_not_nan() {
        let mut x = t(&[f32::NEG_INFINITY, f32::NEG_INFINITY], &[1, 2]);
        softmax_rows(&mut x).unwrap();
        assert!(x.data().iter().all(|v| v.is_finite()), "{:?}", x.data());
        assert!((x.data()[0] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn gelu_matches_known_values() {
        let mut x = t(&[0.0, 1.0, -1.0, 2.0], &[1, 4]);
        gelu(&mut x);
        // Valores de la GELU exacta (erf), no de la aproximación con tanh.
        let expected = [0.0, 0.841_345, -0.158_655, 1.954_5];
        for (got, want) in x.data().iter().zip(expected) {
            assert!((got - want).abs() < 1e-4, "got {} want {}", got, want);
        }
    }

    /// Tolerancias **medidas**, no supuestas: barriendo x en [0, 6] el error máximo de esta
    /// aproximación es 1,394e-07, y el que hereda GELU es 2,111e-07. En x = 0 no da cero exacto
    /// sino ~1e-9, porque el polinomio evaluado en t = 1 suma 0,999999999 en vez de 1.
    #[test]
    fn erf_is_accurate_enough() {
        assert!((erf(1.0) - 0.842_700_793).abs() < 2e-7);
        assert!((erf(0.5) - 0.520_499_878).abs() < 2e-7);
        assert!((erf(-1.0) + 0.842_700_793).abs() < 2e-7);
        assert!(erf(0.0).abs() < 1e-8, "erf(0) = {}", erf(0.0));
        // Y monótona creciente, que es lo que la hace usable como CDF.
        assert!(erf(0.1) < erf(0.2) && erf(0.2) < erf(1.0));
    }

    #[test]
    fn rope_leaves_position_zero_untouched() {
        // En pos 0 el ángulo es 0: cos=1, sin=0, así que el vector no cambia.
        let mut x = t(&[1., 2., 3., 4.], &[1, 4]);
        rope_inplace(&mut x, 1, 4, 10000.0, 0).unwrap();
        for (got, want) in x.data().iter().zip([1., 2., 3., 4.]) {
            assert!((got - want).abs() < 1e-6, "{:?}", x.data());
        }
    }

    #[test]
    fn rope_rotates_halves_not_adjacent_pairs() {
        // La variante "no tradicional" empareja i con i+d/2. Con d=4, el par es (0,2) y (1,3).
        let mut x = t(&[1., 0., 0., 0.], &[1, 4]);
        // Dos posiciones para que la segunda tenga ángulo != 0.
        let mut two = t(&[1., 0., 0., 0., 1., 0., 0., 0.], &[2, 4]);
        rope_inplace(&mut x, 1, 4, 10000.0, 0).unwrap();
        rope_inplace(&mut two, 1, 4, 10000.0, 0).unwrap();
        let second = &two.data()[4..];
        // x0 rota hacia x2 (índice 0 y 0+2), nunca hacia x1.
        assert!(second[0] != 1.0, "x0 debía rotar");
        assert!(second[1].abs() < 1e-9, "x1 no participa del par de x0: {:?}", second);
        assert!(second[2] != 0.0, "x2 debía recibir la componente de x0: {:?}", second);
    }

    #[test]
    fn rope_preserves_the_norm_of_each_pair() {
        let mut x = t(&[3., 0., 4., 0.], &[1, 4]);
        let before: f32 = x.data().iter().map(|v| v * v).sum();
        rope_inplace(&mut x, 1, 4, 10000.0, 0).unwrap();
        let after: f32 = x.data().iter().map(|v| v * v).sum();
        assert!((before - after).abs() < 1e-4, "una rotación no cambia la norma");
    }

    #[test]
    fn embedding_and_index_select_pick_the_right_rows() {
        let table = t(&[0., 0., 1., 1., 2., 2.], &[3, 2]);
        let e = embedding(&[2, 0], &table).unwrap();
        assert_eq!(e.data(), &[2., 2., 0., 0.]);
        let s = index_select(&table, &[1]).unwrap();
        assert_eq!(s.data(), &[1., 1.]);
    }

    #[test]
    fn out_of_range_ids_are_errors_not_panics() {
        let table = t(&[0., 0.], &[1, 2]);
        assert!(embedding(&[5], &table).is_err());
        assert!(index_select(&table, &[9]).is_err());
    }

    #[test]
    fn shape_mismatches_are_reported() {
        let a = t(&[1., 2.], &[1, 2]);
        let b = t(&[1., 2., 3.], &[1, 3]);
        assert!(matmul(&a, &b).is_err());
        let mut c = a.clone();
        assert!(add_inplace(&mut c, &b).is_err());
    }
    #[test]
    fn local_mask_keeps_the_inclusive_window() {
        // window = 4 -> max_distance = 2: se ven los vecinos a distancia 0, 1 y 2.
        let mut s = RTensor::new(vec![0.0; 25], vec![5, 5]).unwrap();
        mask_local_inplace(&mut s, 4).unwrap();
        let d = s.data();
        assert_eq!(d[0 * 5 + 2], 0.0, "distancia 2 debe verse (<=)");
        assert!(d[0 * 5 + 3].is_infinite(), "distancia 3 debe estar enmascarada");
        assert_eq!(d[2 * 5 + 2], 0.0, "la diagonal siempre se ve");
        assert_eq!(d[4 * 5 + 2], 0.0, "la máscara es simétrica");
    }

    #[test]
    fn local_mask_rejects_non_square() {
        let mut s = RTensor::new(vec![0.0; 6], vec![2, 3]).unwrap();
        assert!(mask_local_inplace(&mut s, 4).is_err());
    }

    #[test]
    fn scale_multiplies_everything() {
        let mut x = t(&[1., 2., -3.], &[1, 3]);
        scale_inplace(&mut x, 2.0);
        assert_eq!(x.data(), &[2., 4., -6.]);
    }
    #[test]
    fn rms_norm_does_not_subtract_the_mean() {
        // Con todos iguales, LayerNorm daría 0 y RMSNorm da 1 (por el peso).
        let x = t(&[2., 2., 2., 2.], &[1, 4]);
        let r = rms_norm(&x, &[1., 1., 1., 1.], 1e-6).unwrap();
        for v in r.data() {
            assert!((v - 1.0).abs() < 1e-4, "rms_norm de constantes debe dar 1, dio {}", v);
        }
        let l = layer_norm(&x, &[1., 1., 1., 1.], None, 1e-6).unwrap();
        assert!(l.data().iter().all(|v| v.abs() < 1e-3), "layer_norm sí centra");
    }

    #[test]
    fn rms_norm_per_head_normalises_each_head_separately() {
        // Dos cabezas de 2: la primera con magnitud 1, la segunda con 100.
        let mut x = t(&[1., 1., 100., 100.], &[1, 4]);
        rms_norm_per_head_inplace(&mut x, 2, 2, &[1., 1.], 1e-6).unwrap();
        // Cada cabeza queda normalizada a 1 por su cuenta.
        for v in x.data() {
            assert!((v - 1.0).abs() < 1e-3, "cada cabeza se normaliza sola: {:?}", x.data());
        }
    }

    #[test]
    fn silu_matches_known_values() {
        let mut x = t(&[0.0, 1.0, -1.0], &[1, 3]);
        silu(&mut x);
        assert!((x.data()[0] - 0.0).abs() < 1e-6);
        assert!((x.data()[1] - 0.731_058_6).abs() < 1e-5, "{}", x.data()[1]);
        assert!((x.data()[2] + 0.268_941_4).abs() < 1e-5, "{}", x.data()[2]);
    }

    #[test]
    fn causal_mask_hides_the_future_and_respects_the_offset() {
        // Una consulta nueva con 2 tokens ya en cache: ve las claves 0, 1 y 2, no la 3.
        let mut s = RTensor::new(vec![0.0; 2 * 4], vec![2, 4]).unwrap();
        mask_causal_inplace(&mut s, 2).unwrap();
        let d = s.data();
        assert_eq!(d[0 * 4 + 2], 0.0, "la posición 0 ve hasta la clave offset+0 = 2");
        assert!(d[0 * 4 + 3].is_infinite(), "y no la 3");
        assert_eq!(d[1 * 4 + 3], 0.0, "la posición 1 ve hasta la 3");
    }
    #[test]
    fn rope_offset_shifts_the_position() {
        // El token en posición 0 con offset 1 debe rotar igual que el token 1 sin offset.
        let mut a = t(&[1., 0., 0., 0.], &[1, 4]);
        rope_inplace(&mut a, 1, 4, 10000.0, 1).unwrap();
        let mut b = t(&[1., 0., 0., 0., 1., 0., 0., 0.], &[2, 4]);
        rope_inplace(&mut b, 1, 4, 10000.0, 0).unwrap();
        for (x, y) in a.data().iter().zip(&b.data()[4..]) {
            assert!((x - y).abs() < 1e-6, "offset 1 debe igualar a la posición 1");
        }
    }
    #[test]
    fn sliding_window_mask_is_causal_and_bounded() {
        // window = 2: la posicion 4 ve 2, 3 y 4; no ve 1 (muy atras) ni 5 (futuro).
        let mut m = RTensor::new(vec![0.0; 36], vec![6, 6]).unwrap();
        mask_causal_window_inplace(&mut m, 0, 2).unwrap();
        let d = m.data();
        assert_eq!(d[4 * 6 + 2], 0.0, "distancia 2 se ve");
        assert!(d[4 * 6 + 1].is_infinite(), "distancia 3 queda fuera de la ventana");
        assert_eq!(d[4 * 6 + 4], 0.0, "la diagonal siempre");
        assert!(d[4 * 6 + 5].is_infinite(), "el futuro nunca");
    }
}
