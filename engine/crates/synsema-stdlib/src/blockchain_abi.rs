//! EVM completo (Batch 12, alcance A): ABI encode/decode + EIP-191 + EIP-712.
//!
//! TODO PURO (G13): acá no hay ninguna puerta de firma nueva — estos builtins
//! producen digests y encodings; firmar sigue pasando EXCLUSIVAMENTE por
//! `secp256k1_sign`/`ed25519_sign` (gate `sign(NAME)` + audit del batch 11).
//!
//! Doctrina:
//! - **G14 (anti blind-signing):** `eip712_digest` toma domain/types/message como
//!   maps Synsema LEGIBLES — el programa puede mostrarlos en un `confirm`/`show`
//!   antes de firmar. Un typed-data malformado produce un error que nombra el
//!   tipo/campo, jamás valores.
//! - **G15 (canónico estricto):** `abi_decode` rechaza offsets no-canónicos u
//!   hostiles, padding con basura y data corta/larga — dos byte-strings distintos
//!   jamás decodifican al mismo valor en silencio.
//! - La firma ABI es CANÓNICA: sin espacios ni nombres de parámetro
//!   (`"transfer(address,uint256)"`). Los alias `uint`/`int` se normalizan a
//!   `uint256`/`int256` (una sola forma de selector).

use num_bigint::{BigInt, Sign};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::number::Number;
use synsema_core::types::{syn_bool, syn_bytes, syn_list, syn_number, syn_text, SynValue};

use crate::blockchain::{arg, arg_bytes, eip55, err};

/// Cota de recursión para TODO descenso estructural del batch 12 (tipos ABI,
/// cadena de structs EIP-712). Espeja `RLP_MAX_DEPTH` del batch 11: input hostil
/// (una firma o un typed-data de un contraparte) NUNCA debe reventar el stack —
/// eso sería un abort no atrapable = DoS bajo `serve` (G10). 64 niveles es 10x
/// cualquier ABI/typed-data real; el máximo legítimo on-chain es de un puñado.
const MAX_DEPTH: usize = 64;

// =========================================================
// Modelo de tipos ABI (compartido con EIP-712)
// =========================================================

#[derive(Clone, Debug, PartialEq)]
enum AbiType {
    Uint(u16),
    Int(u16),
    Address,
    Bool,
    FixedBytes(usize),
    Bytes,
    String,
    Array(Box<AbiType>),
    FixedArray(Box<AbiType>, usize),
    Tuple(Vec<AbiType>),
    /// Referencia a un struct definido por el usuario — SÓLO en EIP-712.
    Struct(String),
}

impl fmt::Display for AbiType {
    /// Forma canónica (la que entra al selector: `uint256`, no `uint`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiType::Uint(n) => write!(f, "uint{}", n),
            AbiType::Int(n) => write!(f, "int{}", n),
            AbiType::Address => write!(f, "address"),
            AbiType::Bool => write!(f, "bool"),
            AbiType::FixedBytes(n) => write!(f, "bytes{}", n),
            AbiType::Bytes => write!(f, "bytes"),
            AbiType::String => write!(f, "string"),
            AbiType::Array(t) => write!(f, "{}[]", t),
            AbiType::FixedArray(t, k) => write!(f, "{}[{}]", t, k),
            AbiType::Tuple(ts) => {
                write!(f, "(")?;
                for (i, t) in ts.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", t)?;
                }
                write!(f, ")")
            }
            AbiType::Struct(name) => write!(f, "{}", name),
        }
    }
}

impl AbiType {
    fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::String | AbiType::Array(_) => true,
            AbiType::FixedArray(t, _) => t.is_dynamic(),
            AbiType::Tuple(ts) => ts.iter().any(|t| t.is_dynamic()),
            _ => false,
        }
    }

    /// Tamaño en bytes del head de este tipo dentro de un scope.
    fn head_size(&self) -> usize {
        if self.is_dynamic() {
            32
        } else {
            self.static_size()
        }
    }

    /// Tamaño codificado de un tipo ESTÁTICO (los dinámicos no tienen tamaño fijo).
    fn static_size(&self) -> usize {
        match self {
            AbiType::FixedArray(t, k) => t.static_size() * k,
            AbiType::Tuple(ts) => ts.iter().map(|t| t.static_size()).sum(),
            _ => 32,
        }
    }
}

// =========================================================
// Parser de tipos y firmas
// =========================================================

struct TypeParser<'a> {
    s: &'a [u8],
    pos: usize,
    /// EIP-712 permite referenciar structs por nombre; una firma ABI no.
    structs_ok: bool,
    fname: &'a str,
}

impl<'a> TypeParser<'a> {
    fn new(s: &'a str, structs_ok: bool, fname: &'a str) -> Self {
        TypeParser { s: s.as_bytes(), pos: 0, structs_ok, fname }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn full(&self) -> &str {
        std::str::from_utf8(self.s).unwrap_or("<non-utf8>")
    }

    fn parse_type(&mut self, depth: usize) -> Result<AbiType, Control> {
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "{}: the type is nested too deeply (max {} levels)",
                self.fname, MAX_DEPTH
            )));
        }
        let base = if self.peek() == Some(b'(') {
            self.pos += 1;
            let mut ts = Vec::new();
            if self.peek() == Some(b')') {
                return Err(err(format!(
                    "{}: empty tuple \"()\" is not a valid ABI type (in {:?})",
                    self.fname,
                    self.full()
                )));
            }
            loop {
                ts.push(self.parse_type(depth + 1)?);
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b')') => {
                        self.pos += 1;
                        break;
                    }
                    _ => {
                        return Err(err(format!(
                            "{}: expected \",\" or \")\" in tuple type (in {:?})",
                            self.fname,
                            self.full()
                        )))
                    }
                }
            }
            AbiType::Tuple(ts)
        } else {
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == start {
                return Err(err(format!(
                    "{}: expected a type name (in {:?})",
                    self.fname,
                    self.full()
                )));
            }
            let ident = std::str::from_utf8(&self.s[start..self.pos]).unwrap_or("");
            self.base_type(ident)?
        };
        // Sufijos de array: T[] / T[k], repetibles (uint256[3][] etc.).
        let mut t = base;
        while self.peek() == Some(b'[') {
            self.pos += 1;
            let dstart = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            let digits = std::str::from_utf8(&self.s[dstart..self.pos]).unwrap_or("");
            if self.peek() != Some(b']') {
                return Err(err(format!(
                    "{}: unclosed \"[\" in type (in {:?})",
                    self.fname,
                    self.full()
                )));
            }
            self.pos += 1;
            if digits.is_empty() {
                t = AbiType::Array(Box::new(t));
            } else {
                let k: usize = digits.parse().map_err(|_| {
                    err(format!("{}: invalid array size {:?}", self.fname, digits))
                })?;
                if k == 0 {
                    return Err(err(format!(
                        "{}: zero-length fixed array \"{}[0]\" is not a valid ABI type",
                        self.fname, t
                    )));
                }
                t = AbiType::FixedArray(Box::new(t), k);
            }
        }
        Ok(t)
    }

    fn base_type(&self, ident: &str) -> Result<AbiType, Control> {
        match ident {
            "address" => return Ok(AbiType::Address),
            "bool" => return Ok(AbiType::Bool),
            "string" => return Ok(AbiType::String),
            "bytes" => return Ok(AbiType::Bytes),
            "uint" => return Ok(AbiType::Uint(256)),
            "int" => return Ok(AbiType::Int(256)),
            "tuple" => {
                return Err(err(format!(
                    "{}: write tuples with parentheses — \"(address,uint256)\" — not \"tuple\"",
                    self.fname
                )))
            }
            "fixed" | "ufixed" => {
                return Err(err(format!(
                    "{}: fixed-point ABI types are not supported (no mainstream contract uses them)",
                    self.fname
                )))
            }
            _ => {}
        }
        if let Some(n) = ident.strip_prefix("uint").and_then(|d| d.parse::<u16>().ok()) {
            if (8..=256).contains(&n) && n % 8 == 0 {
                return Ok(AbiType::Uint(n));
            }
            return Err(err(format!(
                "{}: invalid type \"{}\" (uint width must be 8..256 in steps of 8)",
                self.fname, ident
            )));
        }
        if let Some(n) = ident.strip_prefix("int").and_then(|d| d.parse::<u16>().ok()) {
            if (8..=256).contains(&n) && n % 8 == 0 {
                return Ok(AbiType::Int(n));
            }
            return Err(err(format!(
                "{}: invalid type \"{}\" (int width must be 8..256 in steps of 8)",
                self.fname, ident
            )));
        }
        if let Some(n) = ident.strip_prefix("bytes").and_then(|d| d.parse::<usize>().ok()) {
            if (1..=32).contains(&n) {
                return Ok(AbiType::FixedBytes(n));
            }
            return Err(err(format!(
                "{}: invalid type \"{}\" (bytesN width must be 1..32)",
                self.fname, ident
            )));
        }
        if self.structs_ok {
            // Un ident que no es primitivo referencia un struct del typed-data.
            if ident.as_bytes()[0].is_ascii_digit() {
                return Err(err(format!(
                    "{}: invalid type name {:?}",
                    self.fname, ident
                )));
            }
            return Ok(AbiType::Struct(ident.to_string()));
        }
        Err(err(format!("{}: unknown ABI type {:?}", self.fname, ident)))
    }

    fn expect_end(&self, what: &str) -> Result<(), Control> {
        if self.pos != self.s.len() {
            return Err(err(format!(
                "{}: unexpected trailing characters in {} {:?}",
                self.fname,
                what,
                self.full()
            )));
        }
        Ok(())
    }
}

/// Parsea UN tipo desde texto (p.ej. `"uint256"` o `"(address,uint256)"`).
fn parse_single_type(s: &str, structs_ok: bool, fname: &str) -> Result<AbiType, Control> {
    check_no_spaces(s, fname)?;
    let mut p = TypeParser::new(s, structs_ok, fname);
    let t = p.parse_type(0)?;
    p.expect_end("type")?;
    Ok(t)
}

fn check_no_spaces(s: &str, fname: &str) -> Result<(), Control> {
    if s.chars().any(|c| c.is_whitespace()) {
        return Err(err(format!(
            "{}: the signature/type must be canonical — no spaces or parameter names, e.g. \"transfer(address,uint256)\" (got {:?})",
            fname, s
        )));
    }
    Ok(())
}

/// Parsea una firma `name(type,type,…)` canónica. Devuelve (canónica, tipos).
fn parse_signature(sig: &str, fname: &str) -> Result<(String, Vec<AbiType>), Control> {
    check_no_spaces(sig, fname)?;
    let open = sig.find('(').ok_or_else(|| {
        err(format!(
            "{}: the signature must look like \"transfer(address,uint256)\" (got {:?})",
            fname, sig
        ))
    })?;
    let name = &sig[..open];
    if name.is_empty()
        || name.as_bytes()[0].is_ascii_digit()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return Err(err(format!(
            "{}: invalid function name {:?} in the signature",
            fname, name
        )));
    }
    if !sig.ends_with(')') {
        return Err(err(format!(
            "{}: the signature must end with \")\" (got {:?})",
            fname, sig
        )));
    }
    let inner = &sig[open + 1..sig.len() - 1];
    let types = if inner.is_empty() {
        Vec::new()
    } else {
        let mut p = TypeParser::new(inner, false, fname);
        let mut ts = Vec::new();
        loop {
            ts.push(p.parse_type(0)?);
            match p.peek() {
                Some(b',') => p.pos += 1,
                None => break,
                _ => {
                    return Err(err(format!(
                        "{}: expected \",\" between parameter types in {:?}",
                        fname, sig
                    )))
                }
            }
        }
        ts
    };
    let canonical = format!(
        "{}({})",
        name,
        types.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",")
    );
    Ok((canonical, types))
}

// =========================================================
// Encode
// =========================================================

fn u256_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

/// Entero EXACTO del valor (Int/Big; un Decimal entero también es exacto). Float →
/// error dirigido: un uint256 de wei NO cabe exacto en un float.
fn int_value(v: &SynValue, path: &str, fname: &str) -> Result<BigInt, Control> {
    match v {
        SynValue::Number(n) => n.as_bigint().ok_or_else(|| {
            err(format!(
                "{}: {} must be an exact integer (floats lose precision — a uint256 amount needs exact integers)",
                fname, path
            ))
        }),
        SynValue::Secret(_) => Err(err(format!("{}: {} cannot be a secret", fname, path))),
        other => Err(err(format!(
            "{}: {} must be an integer, got {}",
            fname,
            path,
            other.type_name()
        ))),
    }
}

/// 20 bytes de dirección desde text `0x…` (EIP-55 validado si viene mixed-case;
/// todo-minúsculas o todo-mayúsculas se acepta sin checksum) o bytes(20).
/// `pub(crate)`: blockchain_rpc.rs valida direcciones con la MISMA regla.
pub(crate) fn addr20(v: &SynValue, path: &str, fname: &str) -> Result<[u8; 20], Control> {
    match v {
        SynValue::Bytes(b) => {
            if b.len() != 20 {
                return Err(err(format!(
                    "{}: {} must be a 20-byte address, got {} bytes",
                    fname,
                    path,
                    b.len()
                )));
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(b);
            Ok(a)
        }
        SynValue::Text(s) => {
            let hexs = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .ok_or_else(|| {
                    err(format!(
                        "{}: {} must be a \"0x…\" address (40 hex chars) or 20 bytes",
                        fname, path
                    ))
                })?;
            if hexs.len() != 40 || !hexs.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(format!(
                    "{}: {} is not a valid address (need exactly 40 hex chars after 0x)",
                    fname, path
                )));
            }
            let raw = synsema_core::bytesutil::hex_decode(hexs)
                .map_err(|e| err(format!("{}: {}: {}", fname, path, e)))?;
            // EIP-55: mixed-case declara checksum → se VALIDA. Todo-minúsculas o
            // todo-mayúsculas = sin checksum → se acepta.
            let has_lower = hexs.bytes().any(|c| c.is_ascii_lowercase());
            let has_upper = hexs.bytes().any(|c| c.is_ascii_uppercase());
            if has_lower && has_upper {
                let want = eip55(&raw);
                if want[2..] != *hexs {
                    return Err(err(format!(
                        "{}: {} has an invalid EIP-55 checksum (did you paste it wrong?); expected {}",
                        fname, path, want
                    )));
                }
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(&raw);
            Ok(a)
        }
        SynValue::Secret(_) => Err(err(format!("{}: {} cannot be a secret", fname, path))),
        other => Err(err(format!(
            "{}: {} must be an address (\"0x…\" text or 20 bytes), got {}",
            fname,
            path,
            other.type_name()
        ))),
    }
}

/// Palabra de 32 bytes de un valor ATÓMICO (uint/int/address/bool/bytesN).
/// Compartida entre el encoder ABI y encodeData de EIP-712.
fn encode_atomic(t: &AbiType, v: &SynValue, path: &str, fname: &str) -> Result<[u8; 32], Control> {
    match t {
        AbiType::Uint(n) => {
            let i = int_value(v, path, fname)?;
            if i.sign() == Sign::Minus {
                return Err(err(format!(
                    "{}: {} is negative — a {} cannot hold a negative value",
                    fname, path, t
                )));
            }
            if i.bits() > u64::from(*n) {
                return Err(err(format!(
                    "{}: {} does not fit in {} (needs {} bits)",
                    fname,
                    path,
                    t,
                    i.bits()
                )));
            }
            let (_, mag) = i.to_bytes_be();
            let mut w = [0u8; 32];
            let mag = if mag == [0] { &[][..] } else { &mag[..] };
            w[32 - mag.len()..].copy_from_slice(mag);
            Ok(w)
        }
        AbiType::Int(n) => {
            let i = int_value(v, path, fname)?;
            let bound = BigInt::from(1u8) << (n - 1);
            if i >= bound || i < -&bound {
                return Err(err(format!(
                    "{}: {} does not fit in {} (range is -2^{} .. 2^{}-1)",
                    fname,
                    path,
                    t,
                    n - 1,
                    n - 1
                )));
            }
            // Complemento a dos de 256 bits: v mod 2^256.
            let m = if i.sign() == Sign::Minus { i + (BigInt::from(1u8) << 256) } else { i };
            let (_, mag) = m.to_bytes_be();
            let mut w = [0u8; 32];
            let mag = if mag == [0] { &[][..] } else { &mag[..] };
            w[32 - mag.len()..].copy_from_slice(mag);
            Ok(w)
        }
        AbiType::Address => {
            let a = addr20(v, path, fname)?;
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&a);
            Ok(w)
        }
        AbiType::Bool => match v {
            SynValue::Bool(b) => {
                let mut w = [0u8; 32];
                w[31] = u8::from(*b);
                Ok(w)
            }
            other => Err(err(format!(
                "{}: {} must be true or false, got {}",
                fname,
                path,
                other.type_name()
            ))),
        },
        AbiType::FixedBytes(k) => match v {
            SynValue::Bytes(b) => {
                if b.len() != *k {
                    return Err(err(format!(
                        "{}: {} must be exactly {} bytes for {}, got {}",
                        fname,
                        path,
                        k,
                        t,
                        b.len()
                    )));
                }
                let mut w = [0u8; 32];
                w[..*k].copy_from_slice(b);
                Ok(w)
            }
            other => Err(err(format!(
                "{}: {} must be bytes for {}, got {}",
                fname,
                path,
                t,
                other.type_name()
            ))),
        },
        _ => unreachable!("encode_atomic sólo recibe tipos atómicos"),
    }
}

/// Lista Synsema del valor (para arrays/tuples), con chequeo de tipo.
fn list_items(v: &SynValue, path: &str, fname: &str) -> Result<Vec<SynValue>, Control> {
    match v {
        SynValue::List(l) => Ok(l.borrow().clone()),
        other => Err(err(format!(
            "{}: {} must be a list, got {}",
            fname,
            path,
            other.type_name()
        ))),
    }
}

fn pad32_len(n: usize) -> usize {
    n.div_ceil(32) * 32
}

fn encode_value(t: &AbiType, v: &SynValue, path: &str, fname: &str) -> Result<Vec<u8>, Control> {
    match t {
        AbiType::Uint(_) | AbiType::Int(_) | AbiType::Address | AbiType::Bool
        | AbiType::FixedBytes(_) => Ok(encode_atomic(t, v, path, fname)?.to_vec()),
        AbiType::Bytes => match v {
            SynValue::Bytes(b) => {
                let mut out = u256_word(b.len()).to_vec();
                out.extend_from_slice(b);
                out.resize(32 + pad32_len(b.len()), 0);
                Ok(out)
            }
            other => Err(err(format!(
                "{}: {} must be bytes, got {}",
                fname,
                path,
                other.type_name()
            ))),
        },
        AbiType::String => match v {
            SynValue::Text(s) => {
                let b = s.as_bytes();
                let mut out = u256_word(b.len()).to_vec();
                out.extend_from_slice(b);
                out.resize(32 + pad32_len(b.len()), 0);
                Ok(out)
            }
            SynValue::Secret(_) => Err(err(format!("{}: {} cannot be a secret", fname, path))),
            other => Err(err(format!(
                "{}: {} must be text for string, got {}",
                fname,
                path,
                other.type_name()
            ))),
        },
        AbiType::Array(inner) => {
            let items = list_items(v, path, fname)?;
            let mut out = u256_word(items.len()).to_vec();
            let types: Vec<AbiType> = vec![(**inner).clone(); items.len()];
            out.extend(encode_scope(&types, &items, path, fname)?);
            Ok(out)
        }
        AbiType::FixedArray(inner, k) => {
            let items = list_items(v, path, fname)?;
            if items.len() != *k {
                return Err(err(format!(
                    "{}: {} must have exactly {} elements for {}, got {}",
                    fname,
                    path,
                    k,
                    t,
                    items.len()
                )));
            }
            let types: Vec<AbiType> = vec![(**inner).clone(); *k];
            encode_scope(&types, &items, path, fname)
        }
        AbiType::Tuple(ts) => {
            let items = list_items(v, path, fname)?;
            if items.len() != ts.len() {
                return Err(err(format!(
                    "{}: {} must have {} elements for {}, got {}",
                    fname,
                    path,
                    ts.len(),
                    t,
                    items.len()
                )));
            }
            encode_scope(ts, &items, path, fname)
        }
        AbiType::Struct(_) => Err(err(format!(
            "{}: struct types only exist in eip712_digest",
            fname
        ))),
    }
}

/// Codifica un scope head/tail (tuple, cuerpo de array). Los elementos dinámicos
/// van con offset relativo al inicio del scope, según la spec de Solidity.
fn encode_scope(
    types: &[AbiType],
    vals: &[SynValue],
    path: &str,
    fname: &str,
) -> Result<Vec<u8>, Control> {
    let head_size: usize = types.iter().map(|t| t.head_size()).sum();
    let mut head = Vec::with_capacity(head_size);
    let mut tail: Vec<u8> = Vec::new();
    for (i, (t, v)) in types.iter().zip(vals).enumerate() {
        let p = format!("{}[{}]", path, i);
        if t.is_dynamic() {
            head.extend_from_slice(&u256_word(head_size + tail.len()));
            tail.extend(encode_value(t, v, &p, fname)?);
        } else {
            head.extend(encode_value(t, v, &p, fname)?);
        }
    }
    head.extend(tail);
    Ok(head)
}

fn abi_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    let sig = match arg(args, 0, "abi_encode")? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "abi_encode: the first argument must be the function signature as text, got {}",
                other.type_name()
            )))
        }
    };
    let (canonical, types) = parse_signature(&sig, "abi_encode")?;
    let vals = match arg(args, 1, "abi_encode")? {
        SynValue::List(l) => l.borrow().clone(),
        other => {
            return Err(err(format!(
                "abi_encode: the second argument must be a list of values, got {}",
                other.type_name()
            )))
        }
    };
    if vals.len() != types.len() {
        return Err(err(format!(
            "abi_encode: {} expects {} argument(s), got {}",
            canonical,
            types.len(),
            vals.len()
        )));
    }
    let mut out = Keccak256::digest(canonical.as_bytes())[..4].to_vec();
    // El error nombra el argumento 1-based y su tipo (posición humana, G4-style).
    let head_size: usize = types.iter().map(|t| t.head_size()).sum();
    let mut head = Vec::new();
    let mut tail: Vec<u8> = Vec::new();
    for (i, (t, v)) in types.iter().zip(&vals).enumerate() {
        let p = format!("argument {} ({})", i + 1, t);
        if t.is_dynamic() {
            head.extend_from_slice(&u256_word(head_size + tail.len()));
            tail.extend(encode_value(t, v, &p, "abi_encode")?);
        } else {
            head.extend(encode_value(t, v, &p, "abi_encode")?);
        }
    }
    out.extend(head);
    out.extend(tail);
    Ok(syn_bytes(out))
}

fn abi_selector(args: &[SynValue]) -> Result<SynValue, Control> {
    let sig = match arg(args, 0, "abi_selector")? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "abi_selector: expected the function signature as text, got {}",
                other.type_name()
            )))
        }
    };
    let (canonical, _types) = parse_signature(&sig, "abi_selector")?;
    Ok(syn_bytes(Keccak256::digest(canonical.as_bytes())[..4].to_vec()))
}

// =========================================================
// Decode (ESTRICTO — G15)
// =========================================================

struct Dec<'a> {
    data: &'a [u8],
    fname: &'a str,
}

impl<'a> Dec<'a> {
    fn word(&self, pos: usize) -> Result<&'a [u8], Control> {
        if pos + 32 > self.data.len() {
            return Err(err(format!(
                "{}: the data is truncated (needed a 32-byte word at offset {}, data is {} bytes)",
                self.fname,
                pos,
                self.data.len()
            )));
        }
        Ok(&self.data[pos..pos + 32])
    }

    /// Palabra interpretada como offset/longitud. Hostil-safe: los 24 bytes altos
    /// deben ser cero y el valor no puede exceder el tamaño de la data.
    fn usize_word(&self, pos: usize, what: &str) -> Result<usize, Control> {
        let w = self.word(pos)?;
        if w[..24].iter().any(|&b| b != 0) {
            return Err(err(format!(
                "{}: {} at offset {} is out of range",
                self.fname, what, pos
            )));
        }
        let v = u64::from_be_bytes(w[24..].try_into().expect("8 bytes"));
        if v > self.data.len() as u64 {
            return Err(err(format!(
                "{}: {} {} exceeds the data length ({} bytes)",
                self.fname,
                what,
                v,
                self.data.len()
            )));
        }
        Ok(v as usize)
    }

    /// Decodifica un scope (tuple / cuerpo de array) en `base`. Devuelve los
    /// valores y el TAMAÑO total del scope. Estricto: cada offset dinámico debe
    /// ser EXACTAMENTE la posición canónica secuencial — sin huecos, solapes ni
    /// punteros hostiles (G15).
    fn scope(&self, types: &[AbiType], base: usize) -> Result<(Vec<SynValue>, usize), Control> {
        let head_size: usize = types.iter().map(|t| t.head_size()).sum();
        if base + head_size > self.data.len() {
            return Err(err(format!(
                "{}: the data is truncated (scope at offset {} needs {} head bytes, data is {} bytes)",
                self.fname,
                base,
                head_size,
                self.data.len()
            )));
        }
        let mut vals = Vec::with_capacity(types.len());
        let mut hp = 0usize;
        let mut tail_pos = head_size;
        for t in types {
            if t.is_dynamic() {
                let off = self.usize_word(base + hp, "a dynamic-data offset")?;
                if off != tail_pos {
                    return Err(err(format!(
                        "{}: non-canonical encoding (dynamic offset {} where {} was expected — gaps, overlaps and hostile pointers are rejected)",
                        self.fname, off, tail_pos
                    )));
                }
                let (v, sz) = self.elem(t, base + off)?;
                vals.push(v);
                tail_pos += sz;
                hp += 32;
            } else {
                let (v, sz) = self.elem(t, base + hp)?;
                vals.push(v);
                hp += sz;
            }
        }
        Ok((vals, tail_pos))
    }

    /// Decodifica UN elemento en `pos`. Devuelve (valor, tamaño codificado).
    fn elem(&self, t: &AbiType, pos: usize) -> Result<(SynValue, usize), Control> {
        match t {
            AbiType::Uint(n) => {
                let w = self.word(pos)?;
                let nb = usize::from(*n) / 8;
                if w[..32 - nb].iter().any(|&b| b != 0) {
                    return Err(err(format!(
                        "{}: dirty padding for {} at offset {} (the value exceeds the type width — strict decode rejects it)",
                        self.fname, t, pos
                    )));
                }
                Ok((syn_number(Number::from_be_bytes(w)), 32))
            }
            AbiType::Int(n) => {
                let w = self.word(pos)?;
                let nb = usize::from(*n) / 8;
                if nb < 32 {
                    let fill = if w[32 - nb] & 0x80 != 0 { 0xff } else { 0x00 };
                    if w[..32 - nb].iter().any(|&b| b != fill) {
                        return Err(err(format!(
                            "{}: dirty sign-extension padding for {} at offset {}",
                            self.fname, t, pos
                        )));
                    }
                }
                let v = BigInt::from_signed_bytes_be(w);
                Ok((syn_number(Number::from_bigint(v)), 32))
            }
            AbiType::Address => {
                let w = self.word(pos)?;
                if w[..12].iter().any(|&b| b != 0) {
                    return Err(err(format!(
                        "{}: dirty padding for address at offset {} (top 12 bytes must be zero)",
                        self.fname, pos
                    )));
                }
                Ok((syn_text(eip55(&w[12..])), 32))
            }
            AbiType::Bool => {
                let w = self.word(pos)?;
                if w[..31].iter().any(|&b| b != 0) || w[31] > 1 {
                    return Err(err(format!(
                        "{}: invalid bool encoding at offset {} (must be exactly 0 or 1)",
                        self.fname, pos
                    )));
                }
                Ok((syn_bool(w[31] == 1), 32))
            }
            AbiType::FixedBytes(k) => {
                let w = self.word(pos)?;
                if w[*k..].iter().any(|&b| b != 0) {
                    return Err(err(format!(
                        "{}: dirty padding for {} at offset {} (trailing bytes must be zero)",
                        self.fname, t, pos
                    )));
                }
                Ok((syn_bytes(w[..*k].to_vec()), 32))
            }
            AbiType::Bytes | AbiType::String => {
                let len = self.usize_word(pos, "a length")?;
                let start = pos + 32;
                if start + len > self.data.len() {
                    return Err(err(format!(
                        "{}: the data is truncated ({} bytes of content at offset {} exceed the data)",
                        self.fname, len, start
                    )));
                }
                let padded = pad32_len(len);
                if start + padded > self.data.len() {
                    return Err(err(format!(
                        "{}: the data is truncated (missing padding after the content at offset {})",
                        self.fname, start
                    )));
                }
                if self.data[start + len..start + padded].iter().any(|&b| b != 0) {
                    return Err(err(format!(
                        "{}: dirty padding after {} content at offset {} (must be zero)",
                        self.fname, t, start
                    )));
                }
                let content = &self.data[start..start + len];
                let v = if matches!(t, AbiType::String) {
                    match std::str::from_utf8(content) {
                        Ok(s) => syn_text(s),
                        Err(_) => {
                            return Err(err(format!(
                                "{}: string content at offset {} is not valid UTF-8",
                                self.fname, start
                            )))
                        }
                    }
                } else {
                    syn_bytes(content.to_vec())
                };
                Ok((v, 32 + padded))
            }
            AbiType::Array(inner) => {
                let k = self.usize_word(pos, "an array length")?;
                // Cada elemento consume ≥32 bytes de head: cota ANTES de alocar
                // nada proporcional a un largo hostil (no se lee "de más" ni se
                // reserva memoria por un length inventado — G15).
                if k.saturating_mul(32) > self.data.len().saturating_sub(pos + 32) {
                    return Err(err(format!(
                        "{}: array length {} at offset {} exceeds the data (truncated input or hostile length)",
                        self.fname, k, pos
                    )));
                }
                let types: Vec<AbiType> = vec![(**inner).clone(); k];
                let (vals, sz) = self.scope(&types, pos + 32)?;
                Ok((syn_list(vals), 32 + sz))
            }
            AbiType::FixedArray(inner, k) => {
                let types: Vec<AbiType> = vec![(**inner).clone(); *k];
                let (vals, sz) = self.scope(&types, pos)?;
                Ok((syn_list(vals), sz))
            }
            AbiType::Tuple(ts) => {
                let (vals, sz) = self.scope(ts, pos)?;
                Ok((syn_list(vals), sz))
            }
            AbiType::Struct(_) => Err(err(format!(
                "{}: struct types only exist in eip712_digest",
                self.fname
            ))),
        }
    }
}

fn abi_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    let types: Vec<AbiType> = match arg(args, 0, "abi_decode")? {
        SynValue::Text(s) => {
            let t = parse_single_type(s, false, "abi_decode")?;
            match t {
                AbiType::Tuple(ts) => ts,
                single => vec![single],
            }
        }
        SynValue::List(l) => {
            let items = l.borrow().clone();
            let mut ts = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                match it {
                    SynValue::Text(s) => ts.push(parse_single_type(s, false, "abi_decode")?),
                    other => {
                        return Err(err(format!(
                            "abi_decode: type {} in the list must be text, got {}",
                            i + 1,
                            other.type_name()
                        )))
                    }
                }
            }
            ts
        }
        other => {
            return Err(err(format!(
                "abi_decode: the first argument must be the types — text \"(address,uint256)\" or a list of texts — got {}",
                other.type_name()
            )))
        }
    };
    let data = arg_bytes(arg(args, 1, "abi_decode")?, "abi_decode", "the data")?;
    let dec = Dec { data, fname: "abi_decode" };
    let (vals, size) = dec.scope(&types, 0)?;
    if size != data.len() {
        return Err(err(format!(
            "abi_decode: {} trailing byte(s) after the encoded data (strict decode rejects extra data)",
            data.len() - size
        )));
    }
    Ok(syn_list(vals))
}

// =========================================================
// EIP-191 (personal_sign / SIWE)
// =========================================================

fn eip191_digest(args: &[SynValue]) -> Result<SynValue, Control> {
    let message: Vec<u8> = match arg(args, 0, "eip191_digest")? {
        SynValue::Text(s) => s.as_bytes().to_vec(),
        SynValue::Bytes(b) => b[..].to_vec(),
        SynValue::Secret(_) => {
            return Err(err("eip191_digest: the message cannot be a secret"))
        }
        other => {
            return Err(err(format!(
                "eip191_digest: the message must be text or bytes, got {}",
                other.type_name()
            )))
        }
    };
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    h.update(&message);
    Ok(syn_bytes(h.finalize().to_vec()))
}

// =========================================================
// EIP-712 (typed data)
// =========================================================

/// Campos del domain en el ORDEN FIJO del EIP; sólo los presentes entran.
const DOMAIN_FIELDS: [(&str, AbiType); 5] = [
    ("name", AbiType::String),
    ("version", AbiType::String),
    ("chainId", AbiType::Uint(256)),
    ("verifyingContract", AbiType::Address),
    ("salt", AbiType::FixedBytes(32)),
];

type StructDefs = indexmap::IndexMap<String, Vec<(String, AbiType)>>;

/// Parsea el map `types` con la forma del JSON estándar:
/// `{"Person": [{"name": "name", "type": "string"}, …]}`.
fn parse_types(v: &SynValue) -> Result<StructDefs, Control> {
    const F: &str = "eip712_digest";
    let m = match v {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: types must be a map of struct definitions, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let mut defs = StructDefs::new();
    for (tname, fields) in m.iter() {
        if tname != "EIP712Domain" {
            // El nombre del struct no puede pisar un primitivo ni ser inválido.
            let mut p = TypeParser::new(tname, true, F);
            match p.parse_type(0) {
                Ok(AbiType::Struct(_)) if p.pos == tname.len() => {}
                _ => {
                    return Err(err(format!(
                        "{}: invalid struct name {:?} (it must be an identifier and cannot shadow a builtin ABI type)",
                        F, tname
                    )))
                }
            }
        }
        let list = match fields {
            SynValue::List(l) => l.borrow().clone(),
            other => {
                return Err(err(format!(
                    "{}: type {:?} must map to a list of fields, got {}",
                    F,
                    tname,
                    other.type_name()
                )))
            }
        };
        let mut parsed = Vec::with_capacity(list.len());
        for (i, f) in list.iter().enumerate() {
            let fm = match f {
                SynValue::Map(fm) => fm.borrow().clone(),
                other => {
                    return Err(err(format!(
                        "{}: field {} of type {:?} must be a map with \"name\" and \"type\", got {}",
                        F,
                        i + 1,
                        tname,
                        other.type_name()
                    )))
                }
            };
            let fname_v = fm.get("name").ok_or_else(|| {
                err(format!(
                    "{}: field {} of type {:?} is missing \"name\"",
                    F,
                    i + 1,
                    tname
                ))
            })?;
            let ftype_v = fm.get("type").ok_or_else(|| {
                err(format!(
                    "{}: field {} of type {:?} is missing \"type\"",
                    F,
                    i + 1,
                    tname
                ))
            })?;
            let (fname_s, ftype_s) = match (fname_v, ftype_v) {
                (SynValue::Text(a), SynValue::Text(b)) => (a.to_string(), b.to_string()),
                _ => {
                    return Err(err(format!(
                        "{}: field {} of type {:?}: \"name\" and \"type\" must be text",
                        F,
                        i + 1,
                        tname
                    )))
                }
            };
            let ft = parse_single_type(&ftype_s, true, F)?;
            if contains_tuple(&ft) {
                return Err(err(format!(
                    "{}: field {:?} of type {:?}: tuple types are not part of EIP-712 (define a named struct instead)",
                    F, fname_s, tname
                )));
            }
            parsed.push((fname_s, ft));
        }
        defs.insert(tname.clone(), parsed);
    }
    Ok(defs)
}

fn contains_tuple(t: &AbiType) -> bool {
    match t {
        AbiType::Tuple(_) => true,
        AbiType::Array(inner) | AbiType::FixedArray(inner, _) => contains_tuple(inner),
        _ => false,
    }
}

/// Struct base referenciado por un tipo de campo (desarma arrays), si lo hay.
fn struct_ref(t: &AbiType) -> Option<&str> {
    match t {
        AbiType::Struct(n) => Some(n),
        AbiType::Array(inner) | AbiType::FixedArray(inner, _) => struct_ref(inner),
        _ => None,
    }
}

/// `encodeType` del EIP: el primary primero, luego los referenciados en orden
/// alfabético, transitivos. Detecta tipos no definidos y ciclos con DFS.
fn encode_type(primary: &str, defs: &StructDefs) -> Result<String, Control> {
    const F: &str = "eip712_digest";
    fn collect<'a>(
        name: &'a str,
        defs: &'a StructDefs,
        seen: &mut Vec<&'a str>,
        stack: &mut Vec<&'a str>,
        depth: usize,
    ) -> Result<(), Control> {
        // Un ciclo lo corta `stack.contains`; una CADENA acíclica larguísima
        // (A→B→…→Z de miles de structs, atacante-controlada en un typed-data)
        // reventaría el stack sin esta cota — abort no atrapable = DoS (G10).
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "{}: the type reference chain is too deep (max {} levels)",
                F, MAX_DEPTH
            )));
        }
        if stack.contains(&name) {
            return Err(err(format!(
                "{}: type cycle detected involving {:?} (a struct cannot reference itself, directly or indirectly)",
                F, name
            )));
        }
        if seen.contains(&name) {
            return Ok(());
        }
        seen.push(name);
        stack.push(name);
        let fields = defs.get(name).expect("caller validated");
        for (_, ft) in fields {
            if let Some(r) = struct_ref(ft) {
                let (rname, _) = defs.get_key_value(r).ok_or_else(|| {
                    err(format!(
                        "{}: type {:?} references undefined type {:?}",
                        F, name, r
                    ))
                })?;
                collect(rname, defs, seen, stack, depth + 1)?;
            }
        }
        stack.pop();
        Ok(())
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut stack: Vec<&str> = Vec::new();
    collect(primary, defs, &mut seen, &mut stack, 0)?;
    let mut deps: Vec<&str> = seen.iter().copied().filter(|n| *n != primary).collect();
    deps.sort_unstable();
    let mut out = String::new();
    for name in std::iter::once(primary).chain(deps) {
        out.push_str(name);
        out.push('(');
        for (i, (fname, ftype)) in defs[name].iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&ftype.to_string());
            out.push(' ');
            out.push_str(fname);
        }
        out.push(')');
    }
    Ok(out)
}

/// Palabra de 32 bytes de un VALOR de campo EIP-712 (encodeData del EIP).
fn encode_712_value(
    t: &AbiType,
    v: &SynValue,
    path: &str,
    defs: &StructDefs,
) -> Result<[u8; 32], Control> {
    const F: &str = "eip712_digest";
    match t {
        AbiType::Struct(name) => hash_struct(name, v, path, defs),
        AbiType::String => match v {
            SynValue::Text(s) => Ok(Keccak256::digest(s.as_bytes()).into()),
            SynValue::Secret(_) => Err(err(format!("{}: {} cannot be a secret", F, path))),
            other => Err(err(format!(
                "{}: {} must be text for string, got {}",
                F,
                path,
                other.type_name()
            ))),
        },
        AbiType::Bytes => match v {
            SynValue::Bytes(b) => Ok(Keccak256::digest(&b[..]).into()),
            other => Err(err(format!(
                "{}: {} must be bytes, got {}",
                F,
                path,
                other.type_name()
            ))),
        },
        AbiType::Array(inner) => {
            let items = list_items(v, path, F)?;
            let mut concat = Vec::with_capacity(items.len() * 32);
            for (i, it) in items.iter().enumerate() {
                let p = format!("{}[{}]", path, i);
                concat.extend_from_slice(&encode_712_value(inner, it, &p, defs)?);
            }
            Ok(Keccak256::digest(&concat).into())
        }
        AbiType::FixedArray(inner, k) => {
            let items = list_items(v, path, F)?;
            if items.len() != *k {
                return Err(err(format!(
                    "{}: {} must have exactly {} elements for {}, got {}",
                    F,
                    path,
                    k,
                    t,
                    items.len()
                )));
            }
            let mut concat = Vec::with_capacity(items.len() * 32);
            for (i, it) in items.iter().enumerate() {
                let p = format!("{}[{}]", path, i);
                concat.extend_from_slice(&encode_712_value(inner, it, &p, defs)?);
            }
            Ok(Keccak256::digest(&concat).into())
        }
        _ => encode_atomic(t, v, path, F),
    }
}

/// `hashStruct` = keccak256(typeHash ‖ encodeData). Estricto anti blind-signing:
/// un campo faltante O un campo extra en el message es error (nombrando el campo).
fn hash_struct(
    name: &str,
    v: &SynValue,
    path: &str,
    defs: &StructDefs,
) -> Result<[u8; 32], Control> {
    const F: &str = "eip712_digest";
    let fields = defs.get(name).ok_or_else(|| {
        err(format!("{}: undefined type {:?}", F, name))
    })?;
    let m = match v {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: {} must be a map for type {:?}, got {}",
                F,
                path,
                name,
                other.type_name()
            )))
        }
    };
    for k in m.keys() {
        if !fields.iter().any(|(f, _)| f == k) {
            return Err(err(format!(
                "{}: unexpected field {:?} in {} (type {:?} does not define it — you should not sign data you cannot read)",
                F, k, path, name
            )));
        }
    }
    let type_hash: [u8; 32] = Keccak256::digest(encode_type(name, defs)?.as_bytes()).into();
    let mut data = type_hash.to_vec();
    for (fname, ftype) in fields {
        let fv = m.get(fname).ok_or_else(|| {
            err(format!(
                "{}: field {:?} of {:?} is missing in {}",
                F, fname, name, path
            ))
        })?;
        let p = format!("{}.{}", path, fname);
        data.extend_from_slice(&encode_712_value(ftype, fv, &p, defs)?);
    }
    Ok(Keccak256::digest(&data).into())
}

/// domainSeparator: hashStruct del `EIP712Domain` sintetizado desde los campos
/// PRESENTES del domain, en el orden fijo del EIP.
fn domain_separator(domain: &SynValue, defs: &StructDefs) -> Result<[u8; 32], Control> {
    const F: &str = "eip712_digest";
    let m = match domain {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: domain must be a map, got {}",
                F,
                other.type_name()
            )))
        }
    };
    for k in m.keys() {
        if !DOMAIN_FIELDS.iter().any(|(f, _)| f == k) {
            return Err(err(format!(
                "{}: unknown domain field {:?} (the EIP-712 domain allows: name, version, chainId, verifyingContract, salt)",
                F, k
            )));
        }
    }
    let present: Vec<(&str, &AbiType)> = DOMAIN_FIELDS
        .iter()
        .filter(|(f, _)| m.contains_key(*f))
        .map(|(f, t)| (*f, t))
        .collect();
    // Si el usuario declaró "EIP712Domain" en types, debe coincidir EXACTO con el
    // derivado del domain (mismos campos, mismo orden, mismos tipos) — dos fuentes
    // de verdad que difieren en un digest de firma son un bug, no una opción.
    if let Some(user_def) = defs.get("EIP712Domain") {
        let matches = user_def.len() == present.len()
            && user_def
                .iter()
                .zip(&present)
                .all(|((un, ut), (dn, dt))| un == dn && ut == *dt);
        if !matches {
            return Err(err(format!(
                "{}: the \"EIP712Domain\" entry in types does not match the domain map (expected fields, in order: {})",
                F,
                present.iter().map(|(f, _)| *f).collect::<Vec<_>>().join(", ")
            )));
        }
    }
    let mut enc_type = String::from("EIP712Domain(");
    for (i, (f, t)) in present.iter().enumerate() {
        if i > 0 {
            enc_type.push(',');
        }
        enc_type.push_str(&t.to_string());
        enc_type.push(' ');
        enc_type.push_str(f);
    }
    enc_type.push(')');
    let mut data: Vec<u8> = Keccak256::digest(enc_type.as_bytes()).to_vec();
    for (f, t) in &present {
        let v = m.get(*f).expect("filtered by presence");
        let p = format!("domain.{}", f);
        let word = match t {
            AbiType::String => match v {
                SynValue::Text(s) => Keccak256::digest(s.as_bytes()).into(),
                other => {
                    return Err(err(format!(
                        "{}: {} must be text, got {}",
                        F,
                        p,
                        other.type_name()
                    )))
                }
            },
            _ => encode_atomic(t, v, &p, F)?,
        };
        data.extend_from_slice(&word);
    }
    Ok(Keccak256::digest(&data).into())
}

fn eip712_digest(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "eip712_digest";
    let domain = arg(args, 0, F)?.clone();
    let defs = parse_types(arg(args, 1, F)?)?;
    let primary = match arg(args, 2, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the primary type must be text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    if primary == "EIP712Domain" {
        return Err(err(format!(
            "{}: the primary type cannot be \"EIP712Domain\" (that is the domain, not the message)",
            F
        )));
    }
    if !defs.contains_key(&primary) {
        return Err(err(format!(
            "{}: primary type {:?} is not defined in types",
            F, primary
        )));
    }
    let message = arg(args, 3, F)?.clone();

    let dsep = domain_separator(&domain, &defs)?;
    let mhash = hash_struct(&primary, &message, "message", &defs)?;
    let mut h = Keccak256::new();
    h.update([0x19, 0x01]);
    h.update(dsep);
    h.update(mhash);
    Ok(syn_bytes(h.finalize().to_vec()))
}

// =========================================================
// Registro (todos PUROS — G13: ninguna capability)
// =========================================================

pub(crate) fn register(interp: &Interpreter) {
    interp.register_builtin("abi_encode", 2, Rc::new(|_i, a, _l| abi_encode(a)));
    interp.register_builtin("abi_decode", 2, Rc::new(|_i, a, _l| abi_decode(a)));
    interp.register_builtin("abi_selector", 1, Rc::new(|_i, a, _l| abi_selector(a)));
    interp.register_builtin("eip191_digest", 1, Rc::new(|_i, a, _l| eip191_digest(a)));
    interp.register_builtin("eip712_digest", 4, Rc::new(|_i, a, _l| eip712_digest(a)));
}

// =========================================================
// Unit tests de los INTERMEDIOS del EIP-712 (domainSeparator y hashStruct por
// separado — el builtin sólo expone el digest final; los intermedios se anclan
// acá al ejemplo del apéndice del EIP-712, que publica los tres valores).
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use synsema_core::bytesutil::hex_encode;
    use synsema_core::types::{syn_int, syn_map};

    fn ok<T>(r: Result<T, Control>) -> T {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn m(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut im = IndexMap::new();
        for (k, v) in pairs {
            im.insert(k.to_string(), v.clone());
        }
        syn_map(im)
    }

    fn field(name: &str, ty: &str) -> SynValue {
        m(&[("name", syn_text(name)), ("type", syn_text(ty))])
    }

    /// Vectores del apéndice del EIP-712 (ejemplo "Ether Mail", generados también
    /// con eth_account.messages.encode_typed_data — scratchpad gen_vectors.py):
    /// domainSeparator f2cee375…, hashStruct(Mail) c52c0ee5…, digest be609aee….
    #[test]
    fn eip712_appendix_intermediates_are_exact() {
        let types = m(&[
            ("Person", syn_list(vec![field("name", "string"), field("wallet", "address")])),
            (
                "Mail",
                syn_list(vec![
                    field("from", "Person"),
                    field("to", "Person"),
                    field("contents", "string"),
                ]),
            ),
        ]);
        let defs = ok(parse_types(&types));
        let domain = m(&[
            ("name", syn_text("Ether Mail")),
            ("version", syn_text("1")),
            ("chainId", syn_int(1)),
            ("verifyingContract", syn_text("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")),
        ]);
        let dsep = ok(domain_separator(&domain, &defs));
        assert_eq!(
            hex_encode(&dsep),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
            "domainSeparator exacto del apéndice del EIP-712"
        );
        let message = m(&[
            (
                "from",
                m(&[
                    ("name", syn_text("Cow")),
                    ("wallet", syn_text("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
                ]),
            ),
            (
                "to",
                m(&[
                    ("name", syn_text("Bob")),
                    ("wallet", syn_text("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")),
                ]),
            ),
            ("contents", syn_text("Hello, Bob!")),
        ]);
        let hs = ok(hash_struct("Mail", &message, "message", &defs));
        assert_eq!(
            hex_encode(&hs),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
            "hashStruct(Mail) exacto del apéndice del EIP-712"
        );
        // encodeType exacto (la string que entra al typeHash, del apéndice).
        assert_eq!(
            ok(encode_type("Mail", &defs)),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
    }
}
