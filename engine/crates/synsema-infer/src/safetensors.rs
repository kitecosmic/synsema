//! Lector de `.safetensors`, propio y sin dependencias de terceros.
//!
//! El formato es deliberadamente simple, y ésa es la razón por la que existe: **no ejecuta código
//! al cargar**, a diferencia de un pickle de PyTorch. Son tres partes:
//!
//! ```text
//! [8 bytes: largo del header, u64 little-endian]
//! [header JSON: { "nombre": {"dtype","shape","data_offsets":[ini,fin]}, … }]
//! [los datos, crudos y contiguos]
//! ```
//!
//! Escribirlo nosotros son ~150 líneas y nos saca la última dependencia de candle en el camino de
//! Laya. Soporta los dtypes que aparecen en checkpoints reales de inferencia: `F32`, `F16` y
//! `BF16`, todos convertidos a `f32` al leer (ver `backend_rust` para por qué `f32`).
//!
//! ## Qué se valida, y por qué
//!
//! Un `.safetensors` es un archivo ajeno. Cada offset se verifica contra el tamaño real del
//! archivo y contra la forma declarada **antes** de leer: un header manipulado no puede hacer que
//! leamos fuera de rango ni que interpretemos basura como pesos. Es dato, no código, y se trata
//! como tal.

use std::collections::HashMap;
use std::path::Path;

use crate::tensor_rust::RTensor;

/// Lee todos los tensores de un `.safetensors`, convertidos a `f32`.
pub fn load(path: &Path) -> Result<HashMap<String, RTensor>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("no se pudo leer {}: {}", path.display(), e))?;
    parse(&bytes).map_err(|e| format!("{}: {}", path.display(), e))
}

/// Parsea el contenido. Separado de la lectura del archivo para poder testearlo con bytes armados
/// a mano, sin tocar el disco.
pub fn parse(bytes: &[u8]) -> Result<HashMap<String, RTensor>, String> {
    if bytes.len() < 8 {
        return Err("archivo demasiado corto para ser un safetensors".to_string());
    }
    let header_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
    let header_end = 8usize
        .checked_add(header_len)
        .ok_or_else(|| "largo de header inverosímil".to_string())?;
    if header_end > bytes.len() {
        return Err(format!(
            "el header declara {} bytes pero el archivo tiene {}",
            header_len,
            bytes.len()
        ));
    }
    let header: serde_json::Value = serde_json::from_slice(&bytes[8..header_end])
        .map_err(|e| format!("header no es JSON válido: {}", e))?;
    let obj = header.as_object().ok_or_else(|| "el header no es un objeto".to_string())?;

    let data = &bytes[header_end..];
    let mut out = HashMap::with_capacity(obj.len());
    for (name, meta) in obj {
        // `__metadata__` es texto libre del productor del archivo, no un tensor.
        if name == "__metadata__" {
            continue;
        }
        out.insert(name.clone(), read_tensor(name, meta, data)?);
    }
    Ok(out)
}

fn read_tensor(name: &str, meta: &serde_json::Value, data: &[u8]) -> Result<RTensor, String> {
    let dtype = meta
        .get("dtype")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("'{}' no declara dtype", name))?;
    let shape: Vec<usize> = meta
        .get("shape")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("'{}' no declara shape", name))?
        .iter()
        .map(|v| v.as_u64().map(|n| n as usize).ok_or_else(|| format!("'{}': shape inválida", name)))
        .collect::<Result<_, _>>()?;
    let offsets = meta
        .get("data_offsets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("'{}' no declara data_offsets", name))?;
    if offsets.len() != 2 {
        return Err(format!("'{}': data_offsets debe traer dos valores", name));
    }
    let start = offsets[0].as_u64().ok_or_else(|| format!("'{}': offset inválido", name))? as usize;
    let end = offsets[1].as_u64().ok_or_else(|| format!("'{}': offset inválido", name))? as usize;

    // Todo se valida ANTES de indexar: el archivo es ajeno.
    if end < start || end > data.len() {
        return Err(format!(
            "'{}': rango [{}, {}) fuera de los {} bytes de datos",
            name,
            start,
            end,
            data.len()
        ));
    }
    let raw = &data[start..end];
    let count: usize = shape.iter().product();
    let width = match dtype {
        "F32" => 4,
        "F16" | "BF16" => 2,
        other => {
            return Err(format!(
                "'{}': dtype '{}' no soportado (se leen F32, F16 y BF16)",
                name, other
            ))
        }
    };
    if raw.len() != count * width {
        return Err(format!(
            "'{}': {} bytes para {} valores de {} ({} esperados)",
            name,
            raw.len(),
            count,
            dtype,
            count * width
        ));
    }

    let values: Vec<f32> = match dtype {
        "F32" => raw
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
        "F16" => raw
            .chunks_exact(2)
            .map(|c| half::f16::from_le_bytes([c[0], c[1]]).to_f32())
            .collect(),
        // BF16 son los 16 bits ALTOS de un f32: se completa con ceros y listo.
        "BF16" => raw
            .chunks_exact(2)
            .map(|c| f32::from_le_bytes([0, 0, c[0], c[1]]))
            .collect(),
        _ => unreachable!("dtype ya validado arriba"),
    };
    RTensor::new(values, shape).map_err(|e| format!("'{}': {}", name, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arma un safetensors en memoria, como lo haría un productor real.
    fn build(header: &str, data: &[u8]) -> Vec<u8> {
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn reads_f32_tensors() {
        let data: Vec<u8> =
            [1.0f32, 2.0, 3.0, 4.0].iter().flat_map(|v| v.to_le_bytes()).collect();
        let header = r#"{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}"#;
        let t = parse(&build(header, &data)).unwrap();
        assert_eq!(t["w"].shape(), &[2, 2]);
        assert_eq!(t["w"].data(), &[1.0, 2.0, 3.0, 4.0]);
    }

    #[test]
    fn reads_f16_and_converts_to_f32() {
        let data: Vec<u8> = [1.0f32, -2.5]
            .iter()
            .flat_map(|v| half::f16::from_f32(*v).to_le_bytes())
            .collect();
        let header = r#"{"w":{"dtype":"F16","shape":[2],"data_offsets":[0,4]}}"#;
        let t = parse(&build(header, &data)).unwrap();
        assert_eq!(t["w"].data(), &[1.0, -2.5]);
    }

    #[test]
    fn reads_bf16_as_the_high_half_of_an_f32() {
        // BF16 de 1.0 son los 16 bits altos de 1.0f32 = 0x3F800000 → 0x3F80.
        let data = vec![0x80u8, 0x3F];
        let header = r#"{"w":{"dtype":"BF16","shape":[1],"data_offsets":[0,2]}}"#;
        let t = parse(&build(header, &data)).unwrap();
        assert_eq!(t["w"].data(), &[1.0]);
    }

    #[test]
    fn metadata_is_skipped_not_treated_as_a_tensor() {
        let data: Vec<u8> = 1.0f32.to_le_bytes().to_vec();
        let header =
            r#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let t = parse(&build(header, &data)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.contains_key("w"));
    }

    // -- el archivo es ajeno: nada de esto puede leer fuera de rango --

    #[test]
    fn offsets_past_the_end_are_rejected() {
        let header = r#"{"w":{"dtype":"F32","shape":[100],"data_offsets":[0,400]}}"#;
        let err = parse(&build(header, &[0u8; 4])).unwrap_err();
        assert!(err.contains("fuera de los"), "{}", err);
    }

    #[test]
    fn shape_that_disagrees_with_the_bytes_is_rejected() {
        let data: Vec<u8> = [1.0f32, 2.0].iter().flat_map(|v| v.to_le_bytes()).collect();
        // Declara 4 valores pero el rango sólo cubre 2.
        let header = r#"{"w":{"dtype":"F32","shape":[4],"data_offsets":[0,8]}}"#;
        let err = parse(&build(header, &data)).unwrap_err();
        assert!(err.contains("esperados"), "{}", err);
    }

    #[test]
    fn inverted_range_is_rejected() {
        let header = r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[8,4]}}"#;
        assert!(parse(&build(header, &[0u8; 16])).is_err());
    }

    #[test]
    fn oversized_header_length_is_rejected() {
        let mut bytes = u64::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn truncated_file_is_rejected() {
        assert!(parse(&[0u8; 4]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn unsupported_dtype_says_which_ones_work() {
        let header = r#"{"w":{"dtype":"I64","shape":[1],"data_offsets":[0,8]}}"#;
        let err = parse(&build(header, &[0u8; 8])).unwrap_err();
        assert!(err.contains("F32") && err.contains("F16"), "{}", err);
    }

    #[test]
    fn garbage_header_is_an_error_not_a_panic() {
        let mut bytes = 4u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"nope");
        assert!(parse(&bytes).is_err());
    }
}
