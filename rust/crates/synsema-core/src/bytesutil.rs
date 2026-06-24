//! Codificación hex y base64 hand-rolled (zero-dep) para el tipo `bytes`.
//!
//! RFC-4648 estándar: hex en minúsculas, base64 con alfabeto `A-Za-z0-9+/` y
//! padding `=`. No se suma ninguna dependencia (el spec del Batch 1 prohíbe crates
//! nuevos; `secrets.rs` tiene helpers análogos pero viven en otro crate y son
//! privados, así que se re-implementan acá — son pocas líneas y evitan acoplar
//! core↔stdlib). Los decodificadores son **estrictos**: cualquier entrada inválida
//! es un error (nunca decodifican basura en silencio).

// =========================================================
// Hex
// =========================================================

/// Codifica bytes a hex en **minúsculas** (2 chars por byte).
pub fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Valor de un dígito hex (acepta mayúsculas y minúsculas), o None si no es hex.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodifica hex → bytes. Error si la longitud es impar o hay un char no-hex.
/// La cadena vacía decodifica a `[]` (longitud 0, par).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("invalid hex: odd-length string".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])
            .ok_or_else(|| format!("invalid hex character: {:?}", bytes[i] as char))?;
        let lo = hex_val(bytes[i + 1])
            .ok_or_else(|| format!("invalid hex character: {:?}", bytes[i + 1] as char))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

// =========================================================
// Base64 (RFC-4648 estándar, con padding)
// =========================================================

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Codifica bytes a base64 estándar **con padding** (`=`).
pub fn b64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let b0 = chunk[0] as u32;
        let b1 = if n > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if n > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if n > 1 { B64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if n > 2 { B64_ALPHABET[(triple & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Valor de un char base64 estándar, o None si no pertenece al alfabeto.
fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodifica base64 estándar **con padding** → bytes. Estricto: la longitud debe
/// ser múltiplo de 4, el padding `=` sólo en las últimas posiciones, y cualquier
/// char fuera del alfabeto es error. La cadena vacía decodifica a `[]`.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err("invalid base64: length is not a multiple of 4".to_string());
    }
    // Padding sólo permitido en las últimas 1 o 2 posiciones.
    let mut pad = 0;
    if bytes[bytes.len() - 1] == b'=' {
        pad += 1;
        if bytes[bytes.len() - 2] == b'=' {
            pad += 1;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let content_len = bytes.len() - pad;
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'=' {
            // Un `=` antes de la zona de padding final es inválido.
            if i < content_len {
                return Err("invalid base64: misplaced padding".to_string());
            }
            continue;
        }
        let v = b64_val(c)
            .ok_or_else(|| format!("invalid base64 character: {:?}", c as char))?;
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_all_bytes() {
        let all: Vec<u8> = (0..=255u8).collect();
        let enc = hex_encode(&all);
        assert_eq!(enc.len(), 512);
        assert_eq!(hex_decode(&enc).unwrap(), all);
    }

    #[test]
    fn hex_known_vectors() {
        assert_eq!(hex_encode(b"Hi"), "4869");
        assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_errors() {
        assert!(hex_decode("abc").is_err()); // impar
        assert!(hex_decode("xy").is_err()); // no-hex
        assert!(hex_decode("ff").is_ok());
    }

    #[test]
    fn b64_round_trip_all_bytes() {
        let all: Vec<u8> = (0..=255u8).collect();
        let enc = b64_encode(&all);
        assert_eq!(b64_decode(&enc).unwrap(), all);
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
    }

    #[test]
    fn b64_errors() {
        assert!(b64_decode("Zg=").is_err()); // largo no múltiplo de 4
        assert!(b64_decode("Z===").is_err()); // padding mal ubicado
        assert!(b64_decode("Zm9v!mFy").is_err()); // char inválido
    }
}
