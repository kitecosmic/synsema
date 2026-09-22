//! Dequantización de los esquemas de ggml.
//!
//! Un GGUF cuantizado guarda los pesos en bloques: un puñado de valores enteros chicos más una o
//! dos escalas en `f16` que los devuelven a su rango. Es de donde sale que un modelo de 8 000
//! millones de parámetros entre en 4 GB.
//!
//! Se implementan los que aparecen de verdad en los modelos que corremos:
//!
//! | Esquema | Bloque | Bytes | Dónde aparece |
//! |---|---|---|---|
//! | `F32` / `F16` | — | 4 / 2 | tensores chicos: normas, sesgos |
//! | `Q8_0` | 32 valores | 34 | cuantización suave |
//! | `Q4_K` | 256 valores | 144 | el grueso de un `Q4_K_M` |
//! | `Q6_K` | 256 valores | 210 | las capas sensibles de un `Q4_K_M` |
//!
//! ## Por qué esto se escribe con el formato al lado
//!
//! El empaquetado de bits de los K-quants no es adivinable: las escalas de `Q4_K` van en **6
//! bits** repartidos en doce bytes con un esquema distinto para los primeros cuatro sub-bloques
//! que para los últimos, y `Q6_K` parte cada valor entre un nibble en `ql` y dos bits en `qh`.
//! Equivocarse en un corrimiento no falla: devuelve pesos que son ruido, y el modelo responde
//! cualquier cosa con total aplomo. Por eso cada bloque lleva su estructura documentada y el
//! oráculo compara contra candle sobre tensores reales.

/// Los `ggml_type` que sabemos leer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuantType {
    F32,
    F16,
    Q8_0,
    Q4K,
    Q6K,
}

impl QuantType {
    /// Traduce el número crudo del GGUF. Los que no están se rechazan por nombre, para que el
    /// error diga qué encontró y no sólo que falló.
    pub fn from_ggml(kind: u32) -> Result<Self, String> {
        Ok(match kind {
            0 => QuantType::F32,
            1 => QuantType::F16,
            8 => QuantType::Q8_0,
            12 => QuantType::Q4K,
            14 => QuantType::Q6K,
            other => {
                return Err(format!(
                    "cuantización ggml tipo {} ({}) no soportada; se leen F32, F16, Q8_0, Q4_K y Q6_K",
                    other,
                    ggml_type_name(other)
                ))
            }
        })
    }

    /// Cuántos valores trae cada bloque.
    pub fn block_elements(self) -> usize {
        match self {
            QuantType::F32 | QuantType::F16 => 1,
            QuantType::Q8_0 => 32,
            QuantType::Q4K | QuantType::Q6K => 256,
        }
    }

    /// Cuántos bytes ocupa cada bloque.
    pub fn block_bytes(self) -> usize {
        match self {
            QuantType::F32 => 4,
            QuantType::F16 => 2,
            QuantType::Q8_0 => 34,
            QuantType::Q4K => 144,
            QuantType::Q6K => 210,
        }
    }

    /// Cuántos bytes ocupa un tensor de `n` valores.
    pub fn bytes_for(self, n: usize) -> Result<usize, String> {
        let per = self.block_elements();
        if n % per != 0 {
            return Err(format!(
                "un tensor de {} valores no es múltiplo del bloque de {} de {:?}",
                n, per, self
            ));
        }
        Ok(n / per * self.block_bytes())
    }
}

/// Nombres de los tipos de ggml, sólo para que un error sea legible.
fn ggml_type_name(kind: u32) -> &'static str {
    match kind {
        2 => "Q4_0",
        3 => "Q4_1",
        6 => "Q5_0",
        7 => "Q5_1",
        9 => "Q8_1",
        10 => "Q2_K",
        11 => "Q3_K",
        13 => "Q5_K",
        15 => "Q8_K",
        _ => "desconocido",
    }
}

/// Convierte un tensor entero a `f32`.
pub fn dequantize(kind: QuantType, raw: &[u8], n: usize) -> Result<Vec<f32>, String> {
    let expected = kind.bytes_for(n)?;
    if raw.len() < expected {
        return Err(format!(
            "{:?}: {} bytes para {} valores (se necesitan {})",
            kind,
            raw.len(),
            n,
            expected
        ));
    }
    let raw = &raw[..expected];
    Ok(match kind {
        QuantType::F32 => raw
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
        QuantType::F16 => raw
            .chunks_exact(2)
            .map(|c| half::f16::from_le_bytes([c[0], c[1]]).to_f32())
            .collect(),
        QuantType::Q8_0 => dequantize_q8_0(raw, n),
        QuantType::Q4K => dequantize_q4_k(raw, n),
        QuantType::Q6K => dequantize_q6_k(raw, n),
    })
}

fn f16_at(raw: &[u8], at: usize) -> f32 {
    half::f16::from_le_bytes([raw[at], raw[at + 1]]).to_f32()
}

/// `Q8_0`: bloques de 32 con una escala.
///
/// ```text
/// d: f16 | qs: 32 × int8      → 34 bytes
/// valor = d · qs[i]
/// ```
fn dequantize_q8_0(raw: &[u8], n: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(n);
    for block in raw.chunks_exact(34) {
        let d = f16_at(block, 0);
        for &q in &block[2..34] {
            out.push(d * (q as i8) as f32);
        }
    }
    out
}

/// Las escalas y los mínimos de `Q4_K` van en **6 bits**, empaquetados en doce bytes con dos
/// esquemas distintos: uno para los sub-bloques 0–3 y otro para los 4–7, que reusan los bits altos
/// de los primeros. Es la parte del formato donde es más fácil equivocarse.
fn get_scale_min_k4(j: usize, q: &[u8]) -> (u8, u8) {
    if j < 4 {
        (q[j] & 63, q[j + 4] & 63)
    } else {
        (
            (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4),
            (q[j + 4] >> 4) | ((q[j] >> 6) << 4),
        )
    }
}

/// `Q4_K`: super-bloques de 256, con ocho sub-bloques de 32.
///
/// ```text
/// d: f16 | dmin: f16 | scales: 12 bytes (6 bits c/u) | qs: 128 bytes (4 bits c/u)  → 144
/// valor = d·sc · q − dmin·m
/// ```
///
/// Los nibbles **no** van en orden: los 32 primeros valores de cada par de sub-bloques salen de
/// los nibbles bajos y los 32 siguientes de los altos, del mismo grupo de 32 bytes.
fn dequantize_q4_k(raw: &[u8], n: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(n);
    for block in raw.chunks_exact(144) {
        let d = f16_at(block, 0);
        let dmin = f16_at(block, 2);
        let scales = &block[4..16];
        let qs = &block[16..144];

        let mut is = 0usize;
        for group in 0..4 {
            let q = &qs[group * 32..(group + 1) * 32];
            let (sc1, m1) = get_scale_min_k4(is, scales);
            let (sc2, m2) = get_scale_min_k4(is + 1, scales);
            let (d1, min1) = (d * sc1 as f32, dmin * m1 as f32);
            let (d2, min2) = (d * sc2 as f32, dmin * m2 as f32);
            for &b in q {
                out.push(d1 * (b & 0x0F) as f32 - min1);
            }
            for &b in q {
                out.push(d2 * (b >> 4) as f32 - min2);
            }
            is += 2;
        }
    }
    out
}

/// `Q6_K`: super-bloques de 256 con seis bits por valor, partidos entre dos arreglos.
///
/// ```text
/// ql: 128 bytes (4 bits bajos) | qh: 64 bytes (2 bits altos) | scales: 16 × int8 | d: f16  → 210
/// valor = d · scale · (q − 32)
/// ```
///
/// Cada mitad de 128 valores se arma leyendo cuatro posiciones a la vez, con los bits altos
/// tomados de `qh` en corrimientos de 0, 2, 4 y 6.
fn dequantize_q6_k(raw: &[u8], n: usize) -> Vec<f32> {
    let mut out = vec![0f32; n];
    let mut written = 0usize;
    for block in raw.chunks_exact(210) {
        let ql = &block[0..128];
        let qh = &block[128..192];
        let scales = &block[192..208];
        let d = f16_at(block, 208);

        // Dos mitades de 128 valores cada una.
        for half in 0..2 {
            let ql = &ql[half * 64..];
            let qh = &qh[half * 32..];
            let sc = &scales[half * 8..];
            let base = written + half * 128;
            for l in 0..32 {
                let is = l / 16;
                let q1 = ((ql[l] & 0x0F) | (((qh[l] >> 0) & 3) << 4)) as i8 as i32 - 32;
                let q2 = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) as i8 as i32 - 32;
                let q3 = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) as i8 as i32 - 32;
                let q4 = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) as i8 as i32 - 32;
                out[base + l] = d * (sc[is] as i8) as f32 * q1 as f32;
                out[base + l + 32] = d * (sc[is + 2] as i8) as f32 * q2 as f32;
                out[base + l + 64] = d * (sc[is + 4] as i8) as f32 * q3 as f32;
                out[base + l + 96] = d * (sc[is + 6] as i8) as f32 * q4 as f32;
            }
        }
        written += 256;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_sizes_match_the_format() {
        assert_eq!(QuantType::Q8_0.block_bytes(), 34);
        assert_eq!(QuantType::Q8_0.block_elements(), 32);
        assert_eq!(QuantType::Q4K.block_bytes(), 144);
        assert_eq!(QuantType::Q4K.block_elements(), 256);
        assert_eq!(QuantType::Q6K.block_bytes(), 210);
        assert_eq!(QuantType::Q6K.block_elements(), 256);
    }

    #[test]
    fn bytes_for_rejects_non_multiples_of_the_block() {
        assert!(QuantType::Q4K.bytes_for(100).is_err());
        assert_eq!(QuantType::Q4K.bytes_for(512).unwrap(), 288);
        assert_eq!(QuantType::Q8_0.bytes_for(64).unwrap(), 68);
    }

    #[test]
    fn unsupported_type_names_what_it_found() {
        let err = QuantType::from_ggml(10).unwrap_err();
        assert!(err.contains("Q2_K"), "{}", err);
        assert!(err.contains("Q4_K"), "debe listar lo que sí se lee: {}", err);
    }

    #[test]
    fn q8_0_scales_the_integers() {
        // d = 2.0, qs = [1, -1, 127, -128, 0…]
        let mut block = half::f16::from_f32(2.0).to_le_bytes().to_vec();
        block.extend_from_slice(&[1u8, 0xFF, 127, 0x80]);
        block.extend(vec![0u8; 28]);
        let out = dequantize(QuantType::Q8_0, &block, 32).unwrap();
        assert_eq!(out[0], 2.0);
        assert_eq!(out[1], -2.0);
        assert_eq!(out[2], 254.0);
        assert_eq!(out[3], -256.0);
        assert_eq!(out[4], 0.0);
    }

    /// Los sub-bloques 0–3 leen la escala directo; los 4–7 la arman con bits de dos bytes. Si se
    /// confunde el esquema, los últimos 128 valores de cada super-bloque salen mal y los primeros
    /// bien — un error que pasa desapercibido si sólo se mira el principio de un tensor.
    #[test]
    fn q4_k_scale_extraction_follows_both_schemes() {
        let mut scales = [0u8; 12];
        scales[0] = 63; // sub-bloque 0: escala 63
        scales[4] = 12; // sub-bloque 0: mínimo 12
        let (sc, m) = get_scale_min_k4(0, &scales);
        assert_eq!((sc, m), (63, 12));

        // Sub-bloque 4: los 4 bits bajos salen de scales[8], los 2 altos de scales[0] >> 6.
        let mut s2 = [0u8; 12];
        s2[8] = 0x0A; // nibble bajo = 10
        s2[0] = 0b1100_0000; // bits altos = 3
        let (sc, _) = get_scale_min_k4(4, &s2);
        assert_eq!(sc, 10 | (3 << 4), "escala del sub-bloque 4 mal armada");
    }

    #[test]
    fn q4_k_dequantizes_a_known_block() {
        // d = 1.0, dmin = 0.0 → valor = sc · nibble
        let mut block = Vec::new();
        block.extend(half::f16::from_f32(1.0).to_le_bytes()); // d
        block.extend(half::f16::from_f32(0.0).to_le_bytes()); // dmin
        let mut scales = [0u8; 12];
        scales[0] = 1; // escala 1 para el sub-bloque 0
        scales[1] = 2; // escala 2 para el sub-bloque 1
        block.extend_from_slice(&scales);
        let mut qs = [0u8; 128];
        qs[0] = 0x35; // nibble bajo 5, nibble alto 3
        block.extend_from_slice(&qs);

        let out = dequantize(QuantType::Q4K, &block, 256).unwrap();
        assert_eq!(out.len(), 256);
        assert_eq!(out[0], 5.0, "el nibble bajo va al sub-bloque 0 con escala 1");
        assert_eq!(out[32], 6.0, "el nibble alto va al sub-bloque 1 con escala 2");
    }

    #[test]
    fn q6_k_centres_values_around_zero() {
        // Todo en cero: q = 0 → (0 - 32) = -32, por la escala y d.
        let mut block = vec![0u8; 210];
        block[192] = 1; // scales[0] = 1
        block[193] = 1;
        block[194] = 1;
        block[195] = 1;
        block[196] = 1;
        block[197] = 1;
        block[198] = 1;
        block[199] = 1;
        let d = half::f16::from_f32(1.0).to_le_bytes();
        block[208] = d[0];
        block[209] = d[1];
        let out = dequantize(QuantType::Q6K, &block, 256).unwrap();
        assert_eq!(out.len(), 256);
        assert_eq!(out[0], -32.0, "Q6_K resta 32 para centrar");
    }

    #[test]
    fn short_buffer_is_an_error() {
        assert!(dequantize(QuantType::Q4K, &[0u8; 10], 256).is_err());
        assert!(dequantize(QuantType::Q8_0, &[0u8; 4], 32).is_err());
    }

    #[test]
    fn f16_and_f32_pass_through() {
        let f32s: Vec<u8> = [1.5f32, -2.5].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(dequantize(QuantType::F32, &f32s, 2).unwrap(), vec![1.5, -2.5]);
        let f16s: Vec<u8> =
            [1.5f32, -2.5].iter().flat_map(|v| half::f16::from_f32(*v).to_le_bytes()).collect();
        assert_eq!(dequantize(QuantType::F16, &f16s, 2).unwrap(), vec![1.5, -2.5]);
    }
}

/// **El oráculo de la dequantización.** Compara nuestros esquemas contra los de candle sobre un
/// GGUF real.
///
/// Es la única prueba que sirve para los K-quants: el empaquetado de bits no se puede verificar
/// "a ojo", y un corrimiento mal puesto produce pesos que son ruido plausible. Gateado por
/// `SYNSEMA_TEST_GGUF`.
#[cfg(all(test, feature = "rust-backend", feature = "candle-backend"))]
mod oracle {
    use super::*;
    use crate::gguf_rust;

    /// Tolerancia relativa al rango del tensor. No es cero porque candle dequantiza con SIMD y
    /// nosotros escalar, y el orden de las operaciones mueve el último bit.
    const TOLERANCE: f32 = 1e-4;

    #[test]
    fn our_dequantization_matches_candle_on_a_real_gguf() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let bytes = std::fs::read(&path).expect("el GGUF debe ser legible");
        let header = gguf_rust::parse_header(&bytes).expect("header legible por nosotros");
        eprintln!(
            "[oráculo] {} tensores, arch {:?}, datos en {}",
            header.tensors.len(),
            header.arch(),
            header.data_offset
        );

        // El mismo archivo, leído por candle.
        let mut file = std::fs::File::open(&path).unwrap();
        let content = candle_core::quantized::gguf_file::Content::read(&mut file)
            .expect("header legible por candle");

        // El tensor MÁS CHICO de cada tipo: así se ejercita cada esquema sin dequantizar el
        // embedding de 311 millones de valores, que son 1,2 GB y varios minutos por nada.
        let mut smallest: std::collections::HashMap<u32, &gguf_rust::TensorInfo> =
            std::collections::HashMap::new();
        for info in &header.tensors {
            if QuantType::from_ggml(info.kind).is_err() {
                continue;
            }
            smallest
                .entry(info.kind)
                .and_modify(|best| {
                    if info.element_count() < best.element_count() {
                        *best = info;
                    }
                })
                .or_insert(info);
        }
        let mut picked: Vec<_> = smallest.values().copied().collect();
        picked.sort_by_key(|t| t.kind);

        let mut checked = 0usize;
        for info in picked {
            let kind = QuantType::from_ggml(info.kind).unwrap();
            let n = info.element_count();
            let start = header.data_offset + info.offset as usize;
            let len = kind.bytes_for(n).expect("tamaño calculable");
            let ours = dequantize(kind, &bytes[start..start + len], n).expect("dequantización");

            let qt = content
                .tensor(&mut file, &info.name, &candle_core::Device::Cpu)
                .expect("candle lee el tensor");
            let theirs = qt
                .dequantize(&candle_core::Device::Cpu)
                .expect("candle dequantiza")
                .flatten_all()
                .unwrap()
                .to_vec1::<f32>()
                .unwrap();

            assert_eq!(ours.len(), theirs.len(), "{}: distinta cantidad de valores", info.name);
            let range = theirs.iter().fold(0f32, |a, b| a.max(b.abs())).max(1e-6);
            let mut worst = 0f32;
            for (i, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
                let d = (a - b).abs();
                if d > worst {
                    worst = d;
                }
                assert!(
                    d <= TOLERANCE * range,
                    "{} ({:?}) valor {}: propio {} vs candle {}",
                    info.name,
                    kind,
                    i,
                    a,
                    b
                );
            }
            eprintln!(
                "[oráculo] {:?} en '{}': {} valores, peor diferencia {:.3e} (rango {:.3})",
                kind, info.name, n, worst, range
            );
            checked += 1;
        }
        assert!(checked > 0, "no se verificó ningún tensor: ¿el GGUF usa esquemas que no leemos?");
    }
}
