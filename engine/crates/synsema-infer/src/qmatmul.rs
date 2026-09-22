//! Matmul **cuantizado**: multiplicar sin dequantizar los pesos.
//!
//! Es la tanda I4-e, y la que decide si el backend propio sirve para modelos de verdad. Hasta acá
//! dequantizábamos todo a `f32` al cargar: simple y preciso, pero medido contra candle daba
//! **2,14× más RAM y 3,6× más lento generando**, y hacía imposible correr un modelo mediano.
//!
//! ## La idea
//!
//! En vez de convertir los pesos a `f32`, se **cuantiza la activación** —una sola vez por
//! producto— y se multiplica en aritmética entera, bloque contra bloque:
//!
//! ```text
//! activación f32  ──quantize_q8k──►  Q8_K
//!                                     │
//! pesos Q4_K/Q6_K (sin tocar)  ──vec_dot──►  f32
//! ```
//!
//! Los pesos se quedan comprimidos en memoria, que es de donde sale el ahorro. Y como el producto
//! punto recorre enteros de 8 bits en vez de flotantes de 32, mueve cuatro veces menos memoria,
//! que es lo que domina cuando se genera token a token.
//!
//! ## Qué se pierde
//!
//! Precisión: cuantizar la activación introduce un error que el camino `f32` no tiene. Es
//! exactamente lo que hacen ggml, llama.cpp y candle, así que **este camino se parece más a lo que
//! corre el resto del mundo** — y de hecho es lo que permite comparar contra candle valor a valor.

use crate::mapped::Slice;
use crate::quant::{self, QuantType};
use crate::tensor_rust::RTensor;

/// Valores por super-bloque de los esquemas K. Es el mismo para Q4_K, Q6_K y Q8_K.
const QK_K: usize = 256;

/// Una activación cuantizada a `Q8_K`: enteros de 8 bits más una escala y las sumas parciales.
///
/// `bsums` guarda la suma de cada grupo de 16 valores. No es una optimización: `Q4_K` guarda un
/// **mínimo** por sub-bloque que hay que restar, y hacerlo con las sumas ya calculadas evita
/// recorrer los 256 valores otra vez por cada columna de la matriz.
#[derive(Clone, Debug)]
pub struct BlockQ8K {
    d: f32,
    qs: [i8; QK_K],
    bsums: [i16; QK_K / 16],
}

impl Default for BlockQ8K {
    fn default() -> Self {
        BlockQ8K { d: 0.0, qs: [0; QK_K], bsums: [0; QK_K / 16] }
    }
}

/// Cuantiza una fila de activaciones a `Q8_K`.
///
/// La escala sale del valor de **mayor magnitud** (conservando su signo, como ggml), de modo que
/// ese valor caiga en −127. Un bloque entero de ceros da escala cero y se salta.
pub fn quantize_row_q8k(xs: &[f32], out: &mut Vec<BlockQ8K>) -> Result<(), String> {
    if !xs.len().is_multiple_of(QK_K) {
        return Err(format!("una fila de {} valores no es múltiplo de {}", xs.len(), QK_K));
    }
    out.clear();
    out.reserve(xs.len() / QK_K);
    for chunk in xs.chunks_exact(QK_K) {
        let mut block = BlockQ8K::default();
        // `max` conserva el signo del de mayor magnitud: es lo que hace ggml, y cambiarlo mueve
        // todos los cuantos medio paso.
        let mut amax = 0f32;
        let mut max = 0f32;
        for &x in chunk {
            if x.abs() > amax {
                amax = x.abs();
                max = x;
            }
        }
        if amax == 0.0 {
            out.push(block);
            continue;
        }
        let iscale = -127.0 / max;
        for (j, q) in block.qs.iter_mut().enumerate() {
            *q = (iscale * chunk[j]).round().clamp(-128.0, 127.0) as i8;
        }
        for j in 0..QK_K / 16 {
            let sum: i32 = block.qs[j * 16..(j + 1) * 16].iter().map(|&v| v as i32).sum();
            block.bsums[j] = sum as i16;
        }
        block.d = 1.0 / iscale;
        out.push(block);
    }
    Ok(())
}

/// Una activación cuantizada a `Q8_0`: bloques de 32 con una escala.
///
/// Es el compañero de los pesos `Q8_0`, igual que `Q8_K` lo es de `Q4_K` y `Q6_K`. Más simple:
/// sin sumas parciales, porque `Q8_0` no guarda mínimos que corregir.
#[derive(Clone, Debug)]
pub struct BlockQ80 {
    d: f32,
    qs: [i8; 32],
}

impl Default for BlockQ80 {
    fn default() -> Self {
        BlockQ80 { d: 0.0, qs: [0; 32] }
    }
}

/// Cuantiza una fila de activaciones a `Q8_0`.
///
/// A diferencia de `Q8_K`, la escala sale del valor **absoluto** máximo y va a `+127`: es la
/// convención de ggml para este esquema, y mezclarlas produce todos los signos invertidos.
pub fn quantize_row_q8_0(xs: &[f32], out: &mut Vec<BlockQ80>) -> Result<(), String> {
    if !xs.len().is_multiple_of(32) {
        return Err(format!("una fila de {} valores no es multiplo de 32", xs.len()));
    }
    out.clear();
    out.reserve(xs.len() / 32);
    for chunk in xs.chunks_exact(32) {
        let mut block = BlockQ80::default();
        let amax = chunk.iter().fold(0f32, |a, b| a.max(b.abs()));
        if amax == 0.0 {
            out.push(block);
            continue;
        }
        let d = amax / 127.0;
        let id = 1.0 / d;
        for (j, q) in block.qs.iter_mut().enumerate() {
            *q = (chunk[j] * id).round().clamp(-128.0, 127.0) as i8;
        }
        block.d = d;
        out.push(block);
    }
    Ok(())
}

/// Producto punto entre una fila `Q8_0` y una activación `Q8_0`.
///
/// El más simple de los tres: sin mínimos ni escalas por sub-bloque, sólo el producto de las dos
/// escalas por la suma de los productos enteros.
fn vec_dot_q8_0_q8_0(w: &[u8], lhs: &[BlockQ80]) -> f32 {
    let mut sumf = 0f32;
    for (bi, y) in lhs.iter().enumerate() {
        let block = &w[bi * 34..(bi + 1) * 34];
        let d = f16_at(block, 0);
        let mut acc = 0i32;
        for l in 0..32 {
            acc += (block[2 + l] as i8) as i32 * y.qs[l] as i32;
        }
        sumf += d * y.d * acc as f32;
    }
    sumf
}

/// Una matriz de pesos que se queda **cuantizada** en memoria.
///
/// Guarda los bytes tal como vinieron del GGUF. Ahí está el ahorro: un tensor `Q4_K` ocupa lo
/// mismo que en disco, contra las cuatro veces que costaría en `f32`.
#[derive(Clone)]
pub struct QTensor {
    kind: QuantType,
    /// `[filas, columnas]`, al estilo PyTorch: cada fila es una salida.
    shape: (usize, usize),
    data: QBytes,
}

/// De dónde salen los bytes del tensor.
///
/// `Shared` es el caso real: una porción del modelo mapeado, **sin copiar**. `Owned` existe para
/// los tests, que arman tensores a mano.
#[derive(Clone)]
enum QBytes {
    Owned(Vec<u8>),
    Shared(Slice),
}

impl QBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            QBytes::Owned(v) => v,
            QBytes::Shared(s) => s.as_slice(),
        }
    }

    fn len(&self) -> usize {
        match self {
            QBytes::Owned(v) => v.len(),
            QBytes::Shared(s) => s.len(),
        }
    }
}

impl QTensor {
    /// Desde bytes propios. Para tests.
    pub fn new(kind: QuantType, rows: usize, cols: usize, data: Vec<u8>) -> Result<Self, String> {
        Self::build(kind, rows, cols, QBytes::Owned(data))
    }

    /// Desde una porción del modelo mapeado: **no copia nada**.
    pub fn from_slice(
        kind: QuantType,
        rows: usize,
        cols: usize,
        data: Slice,
    ) -> Result<Self, String> {
        Self::build(kind, rows, cols, QBytes::Shared(data))
    }

    fn build(kind: QuantType, rows: usize, cols: usize, data: QBytes) -> Result<Self, String> {
        let expected = kind.bytes_for(rows * cols)?;
        if data.len() != expected {
            return Err(format!(
                "{:?}: {} bytes para [{}, {}] (se esperaban {})",
                kind,
                data.len(),
                rows,
                cols,
                expected
            ));
        }
        if !cols.is_multiple_of(kind.block_elements()) {
            return Err(format!(
                "{:?}: {} columnas no es múltiplo del bloque de {}",
                kind,
                cols,
                kind.block_elements()
            ));
        }
        Ok(QTensor { kind, shape: (rows, cols), data })
    }

    pub fn shape(&self) -> (usize, usize) {
        self.shape
    }

    pub fn kind(&self) -> QuantType {
        self.kind
    }

    /// Cuántos bytes ocupa. Es el número que hace que esto valga la pena.
    pub fn bytes(&self) -> usize {
        self.data.len()
    }

    fn raw(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Convierte a `f32`. Se usa para los tensores chicos —normas, sesgos— donde el ahorro no
    /// compensa la complejidad, y como escape si algún esquema no tiene producto punto.
    pub fn to_dense(&self) -> Result<RTensor, String> {
        let (rows, cols) = self.shape;
        let values = quant::dequantize(self.kind, self.raw(), rows * cols)?;
        RTensor::new(values, vec![rows, cols])
    }

/// Una fila del tensor, dequantizada sola.
///
/// Es lo que necesita una tabla de embeddings: de 151 936 filas se usan las pocas del prompt, así
/// que dequantizar la tabla entera sería convertir 124 MB para leer unos kilobytes.
    pub fn row_dense(&self, row: usize) -> Result<Vec<f32>, String> {
        let (rows, cols) = self.shape;
        if row >= rows {
            return Err(format!("fila {} de {}", row, rows));
        }
        let row_bytes = self.kind.bytes_for(cols)?;
        let start = row * row_bytes;
        quant::dequantize(self.kind, &self.raw()[start..start + row_bytes], cols)
    }
    /// `true` si este esquema tiene producto punto cuantizado. Los que no, pasan por `to_dense`.
    pub fn has_vec_dot(&self) -> bool {
        matches!(self.kind, QuantType::Q4K | QuantType::Q6K | QuantType::Q8_0)
    }
}

/// Un peso del modelo: denso o cuantizado, con la misma interfaz.
///
/// Los tensores chicos —normas, sesgos— se quedan densos: ocupan kilobytes y cuantizarlos sólo
/// agregaría casos. Los grandes se quedan comprimidos, que es de donde sale el ahorro.
pub enum Weight {
    Dense(RTensor),
    Quantized(QTensor),
}

impl Weight {
    /// Envuelve un tensor cuantizado, dejándolo denso si su esquema no tiene producto punto o si
    /// es tan chico que no vale la pena.
    pub fn from_qtensor(q: QTensor) -> Result<Self, String> {
        // **Sin umbral de tamaño, y es a propósito.** Un corte por bytes dejaba unos tensores
        // cuantizados y otros densos, mezclando dos caminos numéricos distintos dentro del mismo
        // modelo — y eso daba MÁS diferencia contra candle que ser consistentemente uno u otro.
        // Si el esquema tiene producto punto, se usa siempre.
        if !q.has_vec_dot() {
            return Ok(Weight::Dense(q.to_dense()?));
        }
        Ok(Weight::Quantized(q))
    }

    /// `x @ w^T`, por el camino que corresponda.
    pub fn matmul(&self, x: &RTensor) -> Result<RTensor, String> {
        match self {
            Weight::Dense(w) => crate::backend_rust::linear(x, w, None),
            Weight::Quantized(w) => qmatmul(x, w),
        }
    }

    /// Filas por índice: la tabla de embeddings.
    pub fn embedding(&self, ids: &[u32]) -> Result<RTensor, String> {
        match self {
            Weight::Dense(w) => crate::backend_rust::embedding(ids, w),
            Weight::Quantized(w) => {
                let (rows, cols) = w.shape();
                let mut out = Vec::with_capacity(ids.len() * cols);
                for &id in ids {
                    let id = id as usize;
                    if id >= rows {
                        return Err(format!("token {} fuera del vocabulario de {}", id, rows));
                    }
                    out.extend(w.row_dense(id)?);
                }
                RTensor::new(out, vec![ids.len(), cols])
            }
        }
    }

    /// Cuántos bytes ocupa. Sirve para reportar cuánto se ahorró.
    pub fn bytes(&self) -> usize {
        match self {
            Weight::Dense(w) => w.data().len() * 4,
            Weight::Quantized(w) => w.bytes(),
        }
    }
}

/// `x @ w^T`: activaciones densas por pesos cuantizados.
///
/// La activación se cuantiza **una vez** y se reutiliza para todas las filas de `w`, que es lo que
/// amortiza su costo: con una matriz de 2048 columnas, se paga una cuantización y se cobran 2048
/// productos punto.
pub fn qmatmul(x: &RTensor, w: &QTensor) -> Result<RTensor, String> {
    let (n, k) = x.dims2()?;
    let (out, k_w) = w.shape();
    if k != k_w {
        return Err(format!("qmatmul: x es [{}, {}] y w es [{}, {}]", n, k, out, k_w));
    }
    let block = w.kind.block_elements();
    if !k.is_multiple_of(block) {
        return Err(format!("qmatmul: {} columnas no es multiplo de {}", k, block));
    }
    let row_bytes = w.kind.bytes_for(k)?;
    let mut result = vec![0f32; n * out];

    // Cada esquema se multiplica contra la activacion cuantizada que le corresponde: los K
    // contra `Q8_K`, y `Q8_0` contra `Q8_0`. Es el `VecDotType` de ggml.
    let mut lhs_k: Vec<BlockQ8K> = Vec::new();
    let mut lhs_0: Vec<BlockQ80> = Vec::new();

    for row in 0..n {
        let activation = &x.data()[row * k..(row + 1) * k];
        match w.kind {
            QuantType::Q4K | QuantType::Q6K => quantize_row_q8k(activation, &mut lhs_k)?,
            QuantType::Q8_0 => quantize_row_q8_0(activation, &mut lhs_0)?,
            other => return Err(format!("{:?} no tiene producto punto cuantizado", other)),
        }
        for col in 0..out {
            let w_row = &w.raw()[col * row_bytes..(col + 1) * row_bytes];
            result[row * out + col] = match w.kind {
                QuantType::Q4K => vec_dot_q4k_q8k(w_row, &lhs_k),
                QuantType::Q6K => vec_dot_q6k_q8k(w_row, &lhs_k),
                QuantType::Q8_0 => vec_dot_q8_0_q8_0(w_row, &lhs_0),
                other => return Err(format!("{:?} no tiene producto punto cuantizado", other)),
            };
        }
    }
    RTensor::new(result, vec![n, out])
}

/// Las escalas y mínimos de 6 bits de `Q4_K`. Es la misma extracción que usa `quant::dequantize`,
/// ya verificada con diferencia cero contra candle.
fn scale_min_k4(j: usize, q: &[u8]) -> (u8, u8) {
    if j < 4 {
        (q[j] & 63, q[j + 4] & 63)
    } else {
        ((q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4), (q[j + 4] >> 4) | ((q[j] >> 6) << 4))
    }
}

fn f16_at(raw: &[u8], at: usize) -> f32 {
    half::f16::from_le_bytes([raw[at], raw[at + 1]]).to_f32()
}

/// Producto punto entre una fila `Q4_K` y una activación `Q8_K`.
///
/// El orden de las operaciones sigue al de ggml: se expanden los nibbles a enteros, se acumula por
/// sub-bloque con su escala, y **al final** se resta la corrección de mínimos usando las sumas
/// parciales. Hacerlo en otro orden cambia los últimos dígitos.
fn vec_dot_q4k_q8k(w: &[u8], lhs: &[BlockQ8K]) -> f32 {
    let mut sumf = 0f32;
    for (bi, y) in lhs.iter().enumerate() {
        let block = &w[bi * 144..(bi + 1) * 144];
        let d = f16_at(block, 0);
        let dmin = f16_at(block, 2);
        let scales_raw = &block[4..16];
        let qs = &block[16..144];

        // Los 256 nibbles, expandidos: primero los bajos de cada grupo de 32, después los altos.
        let mut aux = [0i8; QK_K];
        for g in 0..4 {
            let q = &qs[g * 32..(g + 1) * 32];
            for l in 0..32 {
                aux[g * 64 + l] = (q[l] & 0x0F) as i8;
                aux[g * 64 + 32 + l] = (q[l] >> 4) as i8;
            }
        }

        // La corrección de mínimos, con las sumas por grupos de 16 ya calculadas.
        let mut sumi = 0i32;
        for j in 0..QK_K / 16 {
            let (_, m) = scale_min_k4(j / 2, scales_raw);
            sumi += y.bsums[j] as i32 * m as i32;
        }

        // El producto punto, sub-bloque por sub-bloque con su escala.
        let mut acc = 0i32;
        for sb in 0..8 {
            let (sc, _) = scale_min_k4(sb, scales_raw);
            let mut part = 0i32;
            for l in 0..32 {
                let idx = sb * 32 + l;
                part += y.qs[idx] as i32 * aux[idx] as i32;
            }
            acc += sc as i32 * part;
        }
        sumf += d * y.d * acc as f32 - dmin * y.d * sumi as f32;
    }
    sumf
}

/// Producto punto entre una fila `Q6_K` y una activación `Q8_K`.
///
/// `Q6_K` no tiene mínimos: los valores ya vienen centrados restando 32, así que no hay corrección
/// que aplicar — sólo la escala de cada grupo de 16.
fn vec_dot_q6k_q8k(w: &[u8], lhs: &[BlockQ8K]) -> f32 {
    let mut sumf = 0f32;
    for (bi, y) in lhs.iter().enumerate() {
        let block = &w[bi * 210..(bi + 1) * 210];
        let ql = &block[0..128];
        let qh = &block[128..192];
        let scales = &block[192..208];
        let d = f16_at(block, 208);

        // Los 256 valores de 6 bits, con el mismo desempaquetado que `quant::dequantize`.
        let mut aux = [0i8; QK_K];
        for half in 0..2 {
            let ql = &ql[half * 64..];
            let qh = &qh[half * 32..];
            let base = half * 128;
            for l in 0..32 {
                aux[base + l] = ((ql[l] & 0x0F) | (((qh[l] >> 0) & 3) << 4)) as i8 - 32;
                aux[base + l + 32] = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) as i8 - 32;
                aux[base + l + 64] = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) as i8 - 32;
                aux[base + l + 96] = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) as i8 - 32;
            }
        }

        // Una escala cada 16 valores.
        let mut acc = 0i32;
        for g in 0..16 {
            let sc = scales[g] as i8 as i32;
            let mut part = 0i32;
            for l in 0..16 {
                let idx = g * 16 + l;
                part += y.qs[idx] as i32 * aux[idx] as i32;
            }
            acc += sc * part;
        }
        sumf += d * y.d * acc as f32;
    }
    sumf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantizing_zeros_gives_a_zero_block() {
        let mut out = Vec::new();
        quantize_row_q8k(&vec![0f32; QK_K], &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].d, 0.0);
        assert!(out[0].qs.iter().all(|&q| q == 0));
    }

    #[test]
    fn quantization_puts_the_extreme_at_minus_127() {
        let mut xs = vec![0f32; QK_K];
        xs[5] = 3.5; // el de mayor magnitud, positivo
        let mut out = Vec::new();
        quantize_row_q8k(&xs, &mut out).unwrap();
        // iscale = -127/3.5 → el máximo cae en -127.
        assert_eq!(out[0].qs[5], -127);
        // Y la escala reconstruye el valor: d · q ≈ x
        assert!((out[0].d * out[0].qs[5] as f32 - 3.5).abs() < 0.05);
    }

    #[test]
    fn bsums_are_the_partial_sums_of_sixteen() {
        let xs: Vec<f32> = (0..QK_K).map(|i| if i < 16 { 1.0 } else { 0.0 }).collect();
        let mut out = Vec::new();
        quantize_row_q8k(&xs, &mut out).unwrap();
        let expect: i32 = out[0].qs[..16].iter().map(|&v| v as i32).sum();
        assert_eq!(out[0].bsums[0] as i32, expect);
        assert_eq!(out[0].bsums[1], 0, "el segundo grupo es todo ceros");
    }

    #[test]
    fn non_multiple_rows_are_rejected() {
        let mut out = Vec::new();
        assert!(quantize_row_q8k(&vec![0f32; 100], &mut out).is_err());
    }

    #[test]
    fn qtensor_checks_its_own_size() {
        let good = QTensor::new(QuantType::Q4K, 2, 256, vec![0u8; 288]);
        assert!(good.is_ok());
        assert_eq!(good.unwrap().bytes(), 288);
        assert!(QTensor::new(QuantType::Q4K, 2, 256, vec![0u8; 100]).is_err());
        // Columnas que no son múltiplo del bloque.
        assert!(QTensor::new(QuantType::Q4K, 1, 100, vec![0u8; 144]).is_err());
    }

    #[test]
    fn qtensor_knows_which_schemes_have_a_dot_product() {
        let q4 = QTensor::new(QuantType::Q4K, 1, 256, vec![0u8; 144]).unwrap();
        assert!(q4.has_vec_dot());
        let q8 = QTensor::new(QuantType::Q8_0, 1, 256, vec![0u8; 272]).unwrap();
        assert!(q8.has_vec_dot(), "Q8_0 tiene el suyo desde I4-d");
        // Los densos no: no hay nada que multiplicar cuantizado.
        let f32t = QTensor::new(QuantType::F32, 1, 4, vec![0u8; 16]).unwrap();
        assert!(!f32t.has_vec_dot());
    }

    #[test]
    fn q8_0_quantization_uses_the_absolute_max() {
        let mut xs = vec![0f32; 32];
        xs[3] = -4.0; // el de mayor magnitud, negativo
        let mut out = Vec::new();
        quantize_row_q8_0(&xs, &mut out).unwrap();
        // A diferencia de Q8_K, aca el extremo va a -127 por el signo del valor, no por la escala.
        assert_eq!(out[0].qs[3], -127);
        assert!(out[0].d > 0.0, "la escala de Q8_0 es positiva");
        assert!((out[0].d * out[0].qs[3] as f32 + 4.0).abs() < 0.05);
    }

    #[test]
    fn q8_0_zero_block_is_zero() {
        let mut out = Vec::new();
        quantize_row_q8_0(&vec![0f32; 64], &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|b| b.d == 0.0 && b.qs.iter().all(|&q| q == 0)));
    }

    #[test]
    fn q8_0_rejects_non_multiples_of_32() {
        let mut out = Vec::new();
        assert!(quantize_row_q8_0(&vec![0f32; 40], &mut out).is_err());
    }

    #[test]
    fn q8_0_now_has_a_dot_product() {
        let q8 = QTensor::new(QuantType::Q8_0, 1, 256, vec![0u8; 272]).unwrap();
        assert!(q8.has_vec_dot(), "Q8_0 ya no pasa por to_dense");
    }

    #[test]
    fn shape_mismatch_is_reported() {
        let x = RTensor::new(vec![0f32; 256], vec![1, 256]).unwrap();
        let w = QTensor::new(QuantType::Q4K, 1, 512, vec![0u8; 288]).unwrap();
        assert!(qmatmul(&x, &w).is_err());
    }
}

/// **El oráculo de I4-e.** El producto cuantizado contra el denso, sobre pesos reales.
///
/// El denso —dequantizar y multiplicar en `f32`— ya está verificado con diferencia **cero** contra
/// candle. Así que si el cuantizado se le acerca, el producto punto está bien; y la distancia que
/// quede **es** el error de cuantizar la activación, que es lo que este camino cambia a propósito.
#[cfg(all(test, feature = "rust-backend"))]
mod oracle {
    use super::*;
    use crate::gguf_rust;

    /// Toma el primer tensor del tipo pedido y compara los dos caminos sobre una activación real.
    fn compare(kind: QuantType, label: &str) {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let bytes = std::fs::read(&path).expect("GGUF legible");
        let header = gguf_rust::parse_header(&bytes).expect("header");

        // Un tensor chico de ese tipo, para que el test sea rápido.
        let Some(info) = header
            .tensors
            .iter()
            .filter(|t| QuantType::from_ggml(t.kind) == Ok(kind))
            .min_by_key(|t| t.element_count())
        else {
            eprintln!("[skip] el GGUF no trae tensores {}", label);
            return;
        };
        let rows = info.dims[1];
        let cols = info.dims[0];
        let start = header.data_offset + info.offset as usize;
        let len = kind.bytes_for(rows * cols).unwrap();
        let w = QTensor::new(kind, rows, cols, bytes[start..start + len].to_vec()).unwrap();

        // Una activación con estructura, no ruido: valores de distinta magnitud ejercitan la
        // escala de la cuantización.
        let x: Vec<f32> = (0..cols)
            .map(|i| ((i as f32) * 0.017).sin() * (1.0 + (i % 7) as f32 * 0.3))
            .collect();
        let x = RTensor::new(x, vec![1, cols]).unwrap();

        let quantized = qmatmul(&x, &w).expect("producto cuantizado");
        let dense = crate::backend_rust::linear(&x, &w.to_dense().unwrap(), None)
            .expect("producto denso");

        let range = dense.data().iter().fold(0f32, |a, b| a.max(b.abs())).max(1e-6);
        let mut worst = 0f32;
        for (a, b) in quantized.data().iter().zip(dense.data()) {
            worst = worst.max((a - b).abs());
        }
        eprintln!(
            "[oráculo I4-e] {} en '{}': [{}x{}], peor diferencia {:.3e} sobre un rango de {:.3} ({:.3}%)",
            label,
            info.name,
            rows,
            cols,
            worst,
            range,
            100.0 * worst / range
        );
        // 2% del rango: es el error de cuantizar la activación a 8 bits, no un bug. Si el producto
        // punto estuviera mal, la diferencia sería del orden del propio rango.
        assert!(
            worst <= 0.02 * range,
            "{}: diferencia {} sobre un rango de {} — demasiado para ser sólo la cuantización",
            label,
            worst,
            range
        );
    }

    #[test]
    fn q4k_dot_product_matches_the_dense_path() {
        compare(QuantType::Q4K, "Q4_K");
    }

    #[test]
    fn q6k_dot_product_matches_the_dense_path() {
        compare(QuantType::Q6K, "Q6_K");
    }
}

/// Aísla el producto punto: **el nuestro contra el de candle**, sobre el mismo tensor y la misma
/// activación.
///
/// El test contra el camino denso sólo dice que nos parecemos a nosotros mismos. Éste dice si el
/// `vec_dot` es el de ggml o uno distinto, que es lo que de verdad importa cuando el resultado
/// tiene que coincidir con el resto del mundo.
#[cfg(all(test, feature = "rust-backend", feature = "candle-backend"))]
mod oracle_candle {
    use super::*;
    use crate::gguf_rust;

    #[test]
    fn our_dot_product_matches_candles() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let bytes = std::fs::read(&path).expect("GGUF legible");
        let header = gguf_rust::parse_header(&bytes).expect("header");

        for kind in [QuantType::Q4K, QuantType::Q6K, QuantType::Q8_0] {
            let Some(info) = header
                .tensors
                .iter()
                .filter(|t| QuantType::from_ggml(t.kind) == Ok(kind))
                .min_by_key(|t| t.element_count())
            else {
                continue;
            };
            let rows = info.dims[1];
            let cols = info.dims[0];
            let start = header.data_offset + info.offset as usize;
            let len = kind.bytes_for(rows * cols).unwrap();
            let w = QTensor::new(kind, rows, cols, bytes[start..start + len].to_vec()).unwrap();

            let xs: Vec<f32> = (0..cols)
                .map(|i| ((i as f32) * 0.017).sin() * (1.0 + (i % 7) as f32 * 0.3))
                .collect();
            let x = RTensor::new(xs.clone(), vec![1, cols]).unwrap();
            let ours = qmatmul(&x, &w).expect("nuestro producto");

            // El mismo tensor, leído y multiplicado por candle.
            let mut file = std::fs::File::open(&path).unwrap();
            let content =
                candle_core::quantized::gguf_file::Content::read(&mut file).expect("header candle");
            let device = candle_core::Device::Cpu;
            let qt = content.tensor(&mut file, &info.name, &device).expect("tensor candle");
            let mm = candle_core::quantized::QMatMul::from_qtensor(qt).expect("qmatmul candle");
            let xc = candle_core::Tensor::new(xs.as_slice(), &device)
                .unwrap()
                .reshape((1, cols))
                .unwrap();
            let theirs: Vec<f32> = candle_core::Module::forward(&mm, &xc)
                .expect("forward candle")
                .flatten_all()
                .unwrap()
                .to_vec1::<f32>()
                .unwrap();

            let range = theirs.iter().fold(0f32, |a, b| a.max(b.abs())).max(1e-6);
            let mut worst = 0f32;
            for (a, b) in ours.data().iter().zip(theirs.iter()) {
                worst = worst.max((a - b).abs());
            }
            eprintln!(
                "[vec_dot] {:?} en '{}': peor diferencia {:.3e} sobre un rango de {:.3} ({:.4}%)",
                kind,
                info.name,
                worst,
                range,
                100.0 * worst / range
            );
            // Si los dos hacen el MISMO producto punto, la diferencia es de redondeo en f32.
            assert!(
                worst <= 1e-3 * range,
                "{:?}: {} sobre {} — no estamos haciendo el mismo producto punto",
                kind,
                worst,
                range
            );
        }
    }
}
