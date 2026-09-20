//! CBOR mínimo (RFC 8949) + COSE_Sign1 (RFC 9052): lo justo para los documentos de attestation
//! (Nitro/NSM firma un `COSE_Sign1` cuyo payload es un mapa CBOR) y para el driver `mock` de
//! `attest`, que produce el mismo formato. Compartido por `attestation.rs` (verificar) y
//! `attest.rs` (producir): un solo codec, un solo `Sig_structure`.
//!
//! Alcance deliberado: enteros (mayores 0/1), bytes (2), texto (3), arrays (4), mapas (5), tags
//! (6), `false`/`true`/`null`/`undefined` y floats (7). Sólo longitudes DEFINIDAS: NSM, COSE y
//! los quotes de plataforma usan codificación determinista; un `0x?f` (indefinido) se rechaza
//! con error claro en vez de adivinar. Profundidad acotada (64) y toda longitud se valida
//! contra lo que queda del buffer antes de reservar memoria (un documento hostil no puede pedir
//! 4 GB). Sin dependencias: es un módulo de ~300 líneas, puro, compila a wasm.

use std::fmt;

/// Un ítem CBOR ya decodificado.
#[derive(Clone, Debug, PartialEq)]
pub enum Cbor {
    /// Mayor 0 (≥ 0) y mayor 1 (< 0). `i128` cubre `-2^64 ..= 2^64-1`.
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    /// Pares en el orden del documento (COSE y NSM no exigen orden canónico al leer).
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
    Undefined,
    Float(f64),
}

/// Profundidad máxima de anidamiento aceptada al decodificar.
const MAX_DEPTH: usize = 64;

impl Cbor {
    pub fn text(s: &str) -> Cbor {
        Cbor::Text(s.to_string())
    }

    pub fn bytes(b: &[u8]) -> Cbor {
        Cbor::Bytes(b.to_vec())
    }

    /// Un mapa con claves de texto, desde pares `(&str, Cbor)`.
    pub fn map_text(pairs: Vec<(&str, Cbor)>) -> Cbor {
        Cbor::Map(pairs.into_iter().map(|(k, v)| (Cbor::text(k), v)).collect())
    }

    /// El valor bajo una clave de TEXTO en un mapa (`None` si no es mapa o no está).
    pub fn get(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(pairs) => pairs.iter().find(|(k, _)| matches!(k, Cbor::Text(t) if t == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// El valor bajo una clave ENTERA en un mapa (las cabeceras COSE usan enteros: 1 = alg).
    pub fn get_int(&self, key: i128) -> Option<&Cbor> {
        match self {
            Cbor::Map(pairs) => pairs.iter().find(|(k, _)| matches!(k, Cbor::Int(i) if *i == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Cbor, Cbor)]> {
        match self {
            Cbor::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Cbor::Null)
    }

    /// Quita un tag exterior si lo hay (`Tag(18, x)` → `x`); lo demás pasa tal cual.
    pub fn untagged(&self) -> &Cbor {
        match self {
            Cbor::Tag(_, inner) => inner.untagged(),
            other => other,
        }
    }

    /// Codificación (shortest-form para enteros y longitudes; el orden de los mapas es el dado).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Int(i) => {
                if *i >= 0 {
                    head(out, 0, *i as u128 as u64);
                } else {
                    // -1 - n  →  n = -1 - i  (cabe en u64 para i ≥ -2^64)
                    let n = (-1i128 - *i) as u128;
                    head(out, 1, n as u64);
                }
            }
            Cbor::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Cbor::Array(items) => {
                head(out, 4, items.len() as u64);
                for it in items {
                    it.encode_into(out);
                }
            }
            Cbor::Map(pairs) => {
                head(out, 5, pairs.len() as u64);
                for (k, v) in pairs {
                    k.encode_into(out);
                    v.encode_into(out);
                }
            }
            Cbor::Tag(t, inner) => {
                head(out, 6, *t);
                inner.encode_into(out);
            }
            Cbor::Bool(false) => out.push(0xf4),
            Cbor::Bool(true) => out.push(0xf5),
            Cbor::Null => out.push(0xf6),
            Cbor::Undefined => out.push(0xf7),
            Cbor::Float(f) => {
                // Siempre f64: no reducimos a f16/f32 (los documentos que leemos no traen
                // floats; al escribir, la forma ancha es correcta y simple).
                out.push(0xfb);
                out.extend_from_slice(&f.to_bits().to_be_bytes());
            }
        }
    }
}

/// Cabecera: mayor (3 bits) + argumento en la forma más corta.
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Error de decodificación, con la posición del byte que falló.
#[derive(Debug, Clone, PartialEq)]
pub struct CborError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cbor: {} (at byte {})", self.message, self.offset)
    }
}

/// Decodifica UN ítem que debe ocupar exactamente todo el buffer.
pub fn decode(bytes: &[u8]) -> Result<Cbor, CborError> {
    let (item, used) = decode_prefix(bytes)?;
    if used != bytes.len() {
        return Err(CborError { offset: used, message: format!("{} trailing byte(s) after the item", bytes.len() - used) });
    }
    Ok(item)
}

/// Decodifica UN ítem al inicio del buffer; devuelve (ítem, bytes consumidos).
pub fn decode_prefix(bytes: &[u8]) -> Result<(Cbor, usize), CborError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let item = d.item(0)?;
    Ok((item, d.pos))
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn err(&self, message: impl Into<String>) -> CborError {
        CborError { offset: self.pos, message: message.into() }
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or_else(|| self.err("unexpected end of input"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if self.buf.len() - self.pos < n {
            return Err(self.err(format!("length {} exceeds the {} remaining byte(s)", n, self.buf.len() - self.pos)));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// El argumento de la cabecera (`ai` = additional info 0..=27). `None` = indefinido (31).
    fn arg(&mut self, ai: u8) -> Result<Option<u64>, CborError> {
        Ok(Some(match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.byte()?),
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            31 => return Ok(None),
            _ => return Err(self.err(format!("reserved additional info {}", ai))),
        }))
    }

    fn len(&mut self, ai: u8, what: &str) -> Result<usize, CborError> {
        match self.arg(ai)? {
            Some(n) => {
                let n = usize::try_from(n).map_err(|_| self.err(format!("{} length does not fit in memory", what)))?;
                // Cada ítem ocupa al menos un byte: una cuenta mayor que lo que queda es hostil.
                if n > self.buf.len() - self.pos {
                    return Err(self.err(format!("{} length {} exceeds the {} remaining byte(s)", what, n, self.buf.len() - self.pos)));
                }
                Ok(n)
            }
            None => Err(self.err(format!("indefinite-length {} is not supported (definite encoding only)", what))),
        }
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > MAX_DEPTH {
            return Err(self.err(format!("nesting deeper than {}", MAX_DEPTH)));
        }
        let initial = self.byte()?;
        let (major, ai) = (initial >> 5, initial & 0x1f);
        match major {
            0 => {
                let n = self.arg(ai)?.ok_or_else(|| self.err("indefinite integer"))?;
                Ok(Cbor::Int(n as i128))
            }
            1 => {
                let n = self.arg(ai)?.ok_or_else(|| self.err("indefinite integer"))?;
                Ok(Cbor::Int(-1i128 - n as i128))
            }
            2 => {
                let n = self.len(ai, "byte string")?;
                Ok(Cbor::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.len(ai, "text string")?;
                let raw = self.take(n)?;
                let s = std::str::from_utf8(raw).map_err(|_| self.err("text string is not UTF-8"))?;
                Ok(Cbor::Text(s.to_string()))
            }
            4 => {
                let n = self.len(ai, "array")?;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let n = self.len(ai, "map")?;
                let mut pairs = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    let v = self.item(depth + 1)?;
                    pairs.push((k, v));
                }
                Ok(Cbor::Map(pairs))
            }
            6 => {
                let t = self.arg(ai)?.ok_or_else(|| self.err("indefinite tag"))?;
                let inner = self.item(depth + 1)?;
                Ok(Cbor::Tag(t, Box::new(inner)))
            }
            7 => match ai {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                23 => Ok(Cbor::Undefined),
                24 => {
                    let v = self.byte()?;
                    if v < 32 {
                        return Err(self.err("invalid simple value"));
                    }
                    Ok(Cbor::Undefined)
                }
                25 => Ok(Cbor::Float(f16_to_f64(u16::from_be_bytes(self.take(2)?.try_into().unwrap())))),
                26 => Ok(Cbor::Float(f64::from(f32::from_bits(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))))),
                27 => Ok(Cbor::Float(f64::from_bits(u64::from_be_bytes(self.take(8)?.try_into().unwrap())))),
                31 => Err(self.err("unexpected break (indefinite-length items are not supported)")),
                _ => Ok(Cbor::Undefined),
            },
            _ => unreachable!("major type is 3 bits"),
        }
    }
}

/// IEEE 754 binary16 → f64 (RFC 8949 Appendix D).
fn f16_to_f64(h: u16) -> f64 {
    let exp = ((h >> 10) & 0x1f) as i32;
    let mant = (h & 0x3ff) as f64;
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let v = if exp == 0 {
        mant * 2f64.powi(-24)
    } else if exp != 31 {
        (mant + 1024.0) * 2f64.powi(exp - 25)
    } else if mant == 0.0 {
        f64::INFINITY
    } else {
        f64::NAN
    };
    sign * v
}

// =========================================================
// COSE_Sign1 (RFC 9052 §4.2)
// =========================================================

/// Tag CBOR de un `COSE_Sign1`.
pub const COSE_SIGN1_TAG: u64 = 18;
/// Cabecera COSE `alg` (clave 1).
pub const COSE_HEADER_ALG: i128 = 1;
/// `alg` = ES384 (ECDSA w/ SHA-384), RFC 9053 §2.1.
pub const COSE_ALG_ES384: i128 = -35;
/// `alg` = ES256.
pub const COSE_ALG_ES256: i128 = -7;

/// Un `COSE_Sign1` desarmado: `[protected: bstr, unprotected: map, payload: bstr | nil, signature: bstr]`.
#[derive(Clone, Debug, PartialEq)]
pub struct CoseSign1 {
    /// Los bytes CRUDOS del header protegido (un mapa CBOR serializado; se firma tal cual).
    pub protected: Vec<u8>,
    pub unprotected: Cbor,
    /// `None` = payload detached (nil).
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parsea un `COSE_Sign1`, con o sin el tag 18 exterior.
    pub fn parse(bytes: &[u8]) -> Result<CoseSign1, String> {
        let item = decode(bytes).map_err(|e| e.to_string())?;
        let inner = match &item {
            Cbor::Tag(t, inner) if *t == COSE_SIGN1_TAG => inner.as_ref(),
            Cbor::Tag(t, _) => return Err(format!("COSE_Sign1: unexpected tag {} (expected 18)", t)),
            other => other,
        };
        let parts = inner.as_array().ok_or("COSE_Sign1: not an array")?;
        if parts.len() != 4 {
            return Err(format!("COSE_Sign1: expected 4 elements, got {}", parts.len()));
        }
        let protected = parts[0].as_bytes().ok_or("COSE_Sign1: protected header must be a byte string")?.to_vec();
        if !matches!(parts[1], Cbor::Map(_)) {
            return Err("COSE_Sign1: unprotected header must be a map".to_string());
        }
        let payload = match &parts[2] {
            Cbor::Null => None,
            Cbor::Bytes(b) => Some(b.clone()),
            _ => return Err("COSE_Sign1: payload must be a byte string or nil".to_string()),
        };
        let signature = parts[3].as_bytes().ok_or("COSE_Sign1: signature must be a byte string")?.to_vec();
        Ok(CoseSign1 { protected, unprotected: parts[1].clone(), payload, signature })
    }

    /// El header protegido decodificado (un mapa; vacío si los bytes están vacíos).
    pub fn protected_map(&self) -> Result<Cbor, String> {
        if self.protected.is_empty() {
            return Ok(Cbor::Map(Vec::new()));
        }
        decode(&self.protected).map_err(|e| format!("COSE_Sign1: protected header: {}", e))
    }

    /// `alg` del header protegido (COSE exige que `alg` vaya protegido).
    pub fn alg(&self) -> Result<i128, String> {
        self.protected_map()?
            .get_int(COSE_HEADER_ALG)
            .and_then(Cbor::as_int)
            .ok_or_else(|| "COSE_Sign1: protected header has no integer `alg` (label 1)".to_string())
    }

    /// Los bytes que se firman: `Sig_structure = ["Signature1", protected, external_aad, payload]`
    /// con `external_aad` vacío (RFC 9052 §4.4).
    pub fn sig_structure(&self) -> Vec<u8> {
        cose_sign1_sig_structure(&self.protected, self.payload.as_deref().unwrap_or(&[]))
    }

    /// Serializa con el tag 18 exterior.
    pub fn encode_tagged(&self) -> Vec<u8> {
        Cbor::Tag(COSE_SIGN1_TAG, Box::new(self.encode_untagged_item())).encode()
    }

    /// Serializa SIN tag (la forma que NSM devuelve en `document`).
    pub fn encode_untagged(&self) -> Vec<u8> {
        self.encode_untagged_item().encode()
    }

    fn encode_untagged_item(&self) -> Cbor {
        Cbor::Array(vec![
            Cbor::Bytes(self.protected.clone()),
            self.unprotected.clone(),
            match &self.payload {
                Some(p) => Cbor::Bytes(p.clone()),
                None => Cbor::Null,
            },
            Cbor::Bytes(self.signature.clone()),
        ])
    }
}

/// `Sig_structure` de un `COSE_Sign1` con `external_aad` vacío.
pub fn cose_sign1_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    Cbor::Array(vec![Cbor::text("Signature1"), Cbor::bytes(protected), Cbor::bytes(&[]), Cbor::bytes(payload)]).encode()
}

/// El header protegido mínimo `{1: alg}` serializado.
pub fn cose_protected_alg(alg: i128) -> Vec<u8> {
    Cbor::Map(vec![(Cbor::Int(COSE_HEADER_ALG), Cbor::Int(alg))]).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn round(item: Cbor, expect_hex: &str) {
        let enc = item.encode();
        assert_eq!(enc, hex(expect_hex), "encode {:?}", item);
        assert_eq!(decode(&enc).unwrap(), item, "decode {}", expect_hex);
    }

    #[test]
    fn rfc8949_appendix_a_vectors() {
        round(Cbor::Int(0), "00");
        round(Cbor::Int(1), "01");
        round(Cbor::Int(10), "0a");
        round(Cbor::Int(23), "17");
        round(Cbor::Int(24), "1818");
        round(Cbor::Int(25), "1819");
        round(Cbor::Int(100), "1864");
        round(Cbor::Int(1000), "1903e8");
        round(Cbor::Int(1_000_000), "1a000f4240");
        round(Cbor::Int(1_000_000_000_000), "1b000000e8d4a51000");
        round(Cbor::Int(18_446_744_073_709_551_615), "1bffffffffffffffff");
        round(Cbor::Int(-1), "20");
        round(Cbor::Int(-10), "29");
        round(Cbor::Int(-100), "3863");
        round(Cbor::Int(-1000), "3903e7");
        round(Cbor::Int(-18_446_744_073_709_551_616), "3bffffffffffffffff");
        round(Cbor::Bool(false), "f4");
        round(Cbor::Bool(true), "f5");
        round(Cbor::Null, "f6");
        round(Cbor::Undefined, "f7");
        round(Cbor::Bytes(vec![]), "40");
        round(Cbor::Bytes(vec![1, 2, 3, 4]), "4401020304");
        round(Cbor::text(""), "60");
        round(Cbor::text("IETF"), "6449455446");
        round(Cbor::text("\u{00fc}"), "62c3bc");
        round(Cbor::Array(vec![]), "80");
        round(Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)]), "83010203");
        round(
            Cbor::Array(vec![Cbor::Int(1), Cbor::Array(vec![Cbor::Int(2), Cbor::Int(3)]), Cbor::Array(vec![Cbor::Int(4), Cbor::Int(5)])]),
            "8301820203820405",
        );
        round(Cbor::Map(vec![]), "a0");
        round(Cbor::Map(vec![(Cbor::Int(1), Cbor::Int(2)), (Cbor::Int(3), Cbor::Int(4))]), "a201020304");
        round(
            Cbor::map_text(vec![("a", Cbor::Int(1)), ("b", Cbor::Array(vec![Cbor::Int(2), Cbor::Int(3)]))]),
            "a26161016162820203",
        );
        round(Cbor::Tag(1, Box::new(Cbor::Int(1_363_896_240))), "c11a514b67b0");
        round(Cbor::Tag(23, Box::new(Cbor::Bytes(vec![1, 2, 3, 4]))), "d74401020304");
        // 25 ítems: la longitud pasa a un byte extra.
        let big: Vec<Cbor> = (1..=25).map(Cbor::Int).collect();
        round(Cbor::Array(big), "98190102030405060708090a0b0c0d0e0f101112131415161718181819");
        // Floats: decodifican las tres anchuras; codificamos siempre f64.
        assert_eq!(decode(&hex("f93c00")).unwrap(), Cbor::Float(1.0));
        assert_eq!(decode(&hex("f93e00")).unwrap(), Cbor::Float(1.5));
        assert_eq!(decode(&hex("f97bff")).unwrap(), Cbor::Float(65504.0));
        assert_eq!(decode(&hex("fa47c35000")).unwrap(), Cbor::Float(100000.0));
        assert_eq!(decode(&hex("fb3ff199999999999a")).unwrap(), Cbor::Float(1.1));
        assert_eq!(decode(&hex("f90001")).unwrap(), Cbor::Float(5.960464477539063e-8));
        assert_eq!(decode(&hex("f9c400")).unwrap(), Cbor::Float(-4.0));
        assert!(matches!(decode(&hex("f97c00")).unwrap(), Cbor::Float(f) if f.is_infinite()));
        assert_eq!(Cbor::Float(1.1).encode(), hex("fb3ff199999999999a"));
    }

    #[test]
    fn hostile_input_is_a_clean_error() {
        // Longitud mayor que lo que queda: error, sin reservar.
        let e = decode(&hex("5bffffffffffffffff00")).unwrap_err();
        assert!(e.message.contains("exceeds"), "{}", e);
        // Array que anuncia 2^32 ítems con dos bytes detrás.
        assert!(decode(&hex("9affffffff0102")).is_err());
        // Indefinidos: rechazo explícito.
        assert!(decode(&hex("5f42010243030405ff")).unwrap_err().message.contains("indefinite"));
        assert!(decode(&hex("9f018202039f0405ffff")).unwrap_err().message.contains("indefinite"));
        // Trailing bytes.
        assert!(decode(&hex("0100")).unwrap_err().message.contains("trailing"));
        // Truncado.
        assert!(decode(&hex("1a0000")).is_err());
        // UTF-8 inválido en texto.
        assert!(decode(&hex("61ff")).unwrap_err().message.contains("UTF-8"));
        // Anidamiento excesivo: 100 arrays de un elemento.
        let deep: Vec<u8> = std::iter::repeat(0x81u8).take(100).chain([0x00]).collect();
        assert!(decode(&deep).unwrap_err().message.contains("nesting"));
        // Vacío.
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn map_lookups() {
        let m = Cbor::map_text(vec![("pcrs", Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![0; 48]))])), ("nonce", Cbor::Null)]);
        assert_eq!(m.get("pcrs").unwrap().get_int(0).unwrap().as_bytes().unwrap().len(), 48);
        assert!(m.get("nonce").unwrap().is_null());
        assert!(m.get("missing").is_none());
        assert!(Cbor::Int(1).get("x").is_none());
    }

    #[test]
    fn cose_sign1_round_trip_and_sig_structure() {
        let protected = cose_protected_alg(COSE_ALG_ES384);
        assert_eq!(protected, hex("a1013822"));
        let s = CoseSign1 { protected: protected.clone(), unprotected: Cbor::Map(vec![]), payload: Some(b"hello".to_vec()), signature: vec![9; 96] };
        let tagged = s.encode_tagged();
        assert_eq!(tagged[0], 0xd2, "tag 18");
        let back = CoseSign1::parse(&tagged).unwrap();
        assert_eq!(back, s);
        // Sin tag también parsea (NSM devuelve el array pelado).
        let untagged = s.encode_untagged();
        assert_eq!(CoseSign1::parse(&untagged).unwrap(), s);
        assert_eq!(back.alg().unwrap(), COSE_ALG_ES384);
        // Sig_structure = ["Signature1", protected, h'', payload]
        let expect = Cbor::Array(vec![Cbor::text("Signature1"), Cbor::Bytes(protected), Cbor::Bytes(vec![]), Cbor::Bytes(b"hello".to_vec())]).encode();
        assert_eq!(back.sig_structure(), expect);
        // Un tag ajeno o una aridad distinta se rechazan con mensaje.
        assert!(CoseSign1::parse(&Cbor::Tag(17, Box::new(Cbor::Array(vec![]))).encode()).unwrap_err().contains("tag 17"));
        assert!(CoseSign1::parse(&Cbor::Array(vec![Cbor::Int(1)]).encode()).unwrap_err().contains("4 elements"));
        // Payload detached.
        let d = CoseSign1 { protected: vec![], unprotected: Cbor::Map(vec![]), payload: None, signature: vec![] };
        assert_eq!(CoseSign1::parse(&d.encode_untagged()).unwrap(), d);
        assert_eq!(d.protected_map().unwrap(), Cbor::Map(vec![]));
        assert!(d.alg().is_err());
    }
}
