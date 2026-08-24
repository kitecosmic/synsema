//! Criptografía de blockchain (Batch 11) — firmar/verificar/derivar/codificar para
//! operar on-chain (Ethereum, Avalanche, Solana, Algorand) desde un agente, con la
//! clave privada sellada como `secret` que **jamás** se materializa en user-space.
//!
//! Doctrina (spec batch-11 §0/§2):
//! - **La clave NUNCA cruza al lenguaje (G2).** No hay builtin que devuelva una clave
//!   privada. La firma la CONSUME vía `SecretInner::expose_bytes()` (Rust-side); el
//!   plaintext se decodifica, se usa y se **zeroiza**, sin volverse un valor Synsema.
//! - **Firmar es GATEADO + AUDITADO (G3).** `secp256k1_sign`/`ed25519_sign` exigen
//!   `require sign("KEY_NAME")` (scope al name del secret) y escriben un audit
//!   fail-loud (sin auditoría no hay firma, como `reveal`). Dentro de `sandbox` (caps
//!   vaciadas) → denegado. Todo lo demás (hash, encoding, verify, recover, derivación
//!   de pubkey/dirección) es **PURO** — la pubkey y la dirección son públicas.
//! - **Errores sin fuga (G4).** Ningún mensaje ecoa material de clave/firma; describe
//!   tamaño/forma. Atrapables con `try`/`recover` (G10).
//! - **Determinismo (G5).** secp256k1 firma con nonce RFC 6979 (default de `k256`);
//!   ed25519 es determinista por RFC 8032. Misma `(clave, digest)` → misma firma.
//! - **Malleabilidad controlada (G6).** Las firmas secp256k1 se emiten low-s
//!   normalizadas (lo hace `sign_prehash_recoverable` de k256).
//! - **Puro-Rust, sin C (G8).** k256 / ed25519-dalek / sha3 / bech32, cero `*-sys`.
//! - **Solo defensivo (G12):** firmar/verificar/derivar/codificar. Nada ataca ni evade.

use std::rc::Rc;

use bech32::{Bech32, Bech32m, Hrp};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey as EdVerifyingKey};
use indexmap::IndexMap;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature as EcSignature, SigningKey as EcSigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_bool, syn_bytes, syn_map, syn_text, SynValue};
use std::cell::RefCell;

use crate::secrets::write_sign_audit;

pub(crate) fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Lectura de argumentos (sin unwrap sobre input — G10)
// =========================================================

pub(crate) fn arg<'a>(args: &'a [SynValue], i: usize, fname: &str) -> Result<&'a SynValue, Control> {
    args.get(i)
        .ok_or_else(|| err(format!("{}: missing argument {}", fname, i + 1)))
}

/// Bytes de un argumento: sólo `bytes` (no text — la ambigüedad hex/ascii es peligrosa
/// en cripto). Un `secret` → error de forma (usá el argumento de clave, no acá).
pub(crate) fn arg_bytes<'a>(v: &'a SynValue, fname: &str, what: &str) -> Result<&'a [u8], Control> {
    match v {
        SynValue::Bytes(b) => Ok(&b[..]),
        SynValue::Secret(_) => Err(err(format!(
            "{}: {} must be bytes, got a secret; only the private key is a secret here",
            fname, what
        ))),
        other => Err(err(format!("{}: {} must be bytes, got {}", fname, what, other.type_name()))),
    }
}

/// Bytes de largo EXACTO (para digests/firmas/pubkeys de tamaño fijo). El error nombra
/// el tamaño esperado y el recibido (la longitud NO es material sensible — G4).
pub(crate) fn arg_bytes_len<'a>(
    v: &'a SynValue,
    fname: &str,
    what: &str,
    want: usize,
) -> Result<&'a [u8], Control> {
    let b = arg_bytes(v, fname, what)?;
    if b.len() != want {
        return Err(err(format!(
            "{}: {} must be exactly {} bytes, got {}",
            fname, what, want, b.len()
        )));
    }
    Ok(b)
}

// =========================================================
// Extracción de la clave desde un `secret` (Rust-side, nunca al lenguaje — G2)
// =========================================================

/// Devuelve `(name_del_secret, bytes_de_clave)`. El `name` NO es sensible (se usa para
/// gate + audit). Los bytes vienen de `expose_bytes` (Rust-only): un secret de **texto**
/// = hex (con o sin `0x`); un secret de **bytes** = crudos. El caller DEBE zeroizarlos.
/// Errores sin fuga (G4): jamás incluyen el valor, sólo la forma esperada.
pub(crate) fn key_material(v: &SynValue, fname: &str) -> Result<(String, Vec<u8>), Control> {
    match v {
        SynValue::Secret(inner) => {
            let name = inner.name().to_string();
            if inner.is_bytes() {
                Ok((name, inner.expose_bytes().to_vec()))
            } else {
                // Secret de texto → hex. `expose_bytes` de un secret de texto son sus
                // bytes UTF-8; su forma de texto es válida por construcción.
                let s = String::from_utf8_lossy(inner.expose_bytes());
                let t = s.trim();
                let hexs = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
                let key = synsema_core::bytesutil::hex_decode(hexs).map_err(|_| {
                    err(format!(
                        "{}: the key secret is not valid hex (a text key must be hex, with or without 0x). The key value is never shown.",
                        fname
                    ))
                })?;
                Ok((name, key))
            }
        }
        other => Err(err(format!(
            "{}: the key must be a secret — declare it with `require secret(\"NAME\")` and pass secret(\"NAME\"), got {}. Never pass a private key as a plain string.",
            fname,
            other.type_name()
        ))),
    }
}

// =========================================================
// Gate + audit de la firma (decisión #2 / G3)
// =========================================================

fn sign_denied(name: &str) -> Control {
    err(format!(
        "sign not permitted: Capability not granted: sign(\"{name}\") — \
         add `require sign(\"{name}\")` (signing moves value: it is deny-by-default and writes a persistent audit entry)"
    ))
}

/// Chequea `sign("NAME")` (scope al name del secret — anti-swap: redirigir la variable
/// a otro secret re-evalúa contra SU name) y escribe el audit. Fail-loud: si no se puede
/// auditar en el camino concedido, NO se firma. `pub(crate)`: blockchain_btc.rs
/// (schnorr_sign) usa la MISMA puerta (G30 — cero capability nueva).
pub(crate) fn gate_and_audit(
    caps: &Rc<RefCell<CapabilitySet>>,
    name: &str,
    curve: &str,
    loc: &SourceLocation,
) -> Result<(), Control> {
    let granted = caps
        .borrow_mut()
        .check(&Capability::new(CapabilityType::Sign, Some(name.to_string())), "sign-builtin");
    if !granted {
        // Auditar el intento DENEGADO (best-effort: ya se rechaza igual).
        let _ = write_sign_audit(name, curve, loc, false);
        return Err(sign_denied(name));
    }
    // Techo de CANTIDAD de firmas del host (`SYNSEMA_SIGN_CEILING`, FRAMEWORK F1/F-C):
    // chequea y reserva el cupo ANTES del audit concedido. Sin config → no-op
    // byte-idéntico. Denegado por techo → audit `denied_by=ceiling` + error catchable.
    crate::spend::sign_ceiling_reserve(name, curve, loc)?;
    write_sign_audit(name, curve, loc, true).map_err(|e| {
        err(format!(
            "sign(\"{name}\") failed: cannot write the audit log ({e}). Refusing to sign without an audit trail."
        ))
    })
}

// =========================================================
// secp256k1 (Ethereum, Avalanche C-Chain)
// =========================================================

fn secp256k1_sign(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    let digest = arg_bytes_len(arg(args, 0, "secp256k1_sign")?, "secp256k1_sign", "the digest", 32)?
        .to_vec();
    let (name, mut key) = key_material(arg(args, 1, "secp256k1_sign")?, "secp256k1_sign")?;
    // Gate + audit ANTES de construir la clave de firma.
    if let Err(e) = gate_and_audit(caps, &name, "secp256k1", loc) {
        key.zeroize();
        return Err(e);
    }
    let signing = EcSigningKey::from_slice(&key);
    key.zeroize(); // el material se consumió; borrar la copia temporal
    let signing = signing.map_err(|_| {
        err("secp256k1_sign: the private key must be 32 bytes of valid secp256k1 scalar; check the key's length/format (the key value is never shown)")
    })?;
    // RFC 6979 (determinista, G5) + low-s normalizado + recovery id (G6).
    let (sig, recid): (EcSignature, RecoveryId) = signing
        .sign_prehash_recoverable(&digest)
        .map_err(|_| err("secp256k1_sign: failed to sign the digest"))?;
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&sig.to_bytes()); // r(32) || s(32)
    out.push(recid.to_byte()); // v = recovery id (0/1); el caller ajusta a EIP-155
    Ok(syn_bytes(out))
}

fn secp256k1_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    let digest = arg_bytes_len(arg(args, 0, "secp256k1_verify")?, "secp256k1_verify", "the digest", 32)?;
    let sig_raw = arg_bytes(arg(args, 1, "secp256k1_verify")?, "secp256k1_verify", "the signature")?;
    // 64 (r||s) o 65 (r||s||v — se ignora el recovery id para verificar).
    let sig64 = match sig_raw.len() {
        64 | 65 => &sig_raw[..64],
        n => {
            return Err(err(format!(
                "secp256k1_verify: the signature must be 64 or 65 bytes, got {}",
                n
            )))
        }
    };
    let pubkey = arg_bytes(arg(args, 2, "secp256k1_verify")?, "secp256k1_verify", "the public key")?;
    if !matches!(pubkey.len(), 33 | 65) {
        return Err(err(format!(
            "secp256k1_verify: the public key must be 33 (compressed) or 65 (uncompressed) bytes, got {}",
            pubkey.len()
        )));
    }
    let vk = VerifyingKey::from_sec1_bytes(pubkey)
        .map_err(|_| err("secp256k1_verify: the public key is not a valid secp256k1 point"))?;
    let sig = EcSignature::from_slice(sig64)
        .map_err(|_| err("secp256k1_verify: the signature is not a valid (r, s) pair"))?;
    Ok(syn_bool(vk.verify_prehash(digest, &sig).is_ok()))
}

fn secp256k1_recover(args: &[SynValue]) -> Result<SynValue, Control> {
    let digest = arg_bytes_len(arg(args, 0, "secp256k1_recover")?, "secp256k1_recover", "the digest", 32)?;
    let sig65 = arg_bytes_len(arg(args, 1, "secp256k1_recover")?, "secp256k1_recover", "the signature", 65)?;
    let sig = EcSignature::from_slice(&sig65[..64])
        .map_err(|_| err("secp256k1_recover: the signature is not a valid (r, s) pair"))?;
    let recid = RecoveryId::from_byte(sig65[64]).ok_or_else(|| {
        err("secp256k1_recover: the recovery id (byte 65) must be 0..=3; got an out-of-range value")
    })?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| err("secp256k1_recover: could not recover a public key from this (digest, signature)"))?;
    Ok(syn_bytes(vk.to_encoded_point(false).as_bytes().to_vec())) // uncompressed 65
}

fn secp256k1_pubkey(args: &[SynValue]) -> Result<SynValue, Control> {
    let (_name, mut key) = key_material(arg(args, 0, "secp256k1_pubkey")?, "secp256k1_pubkey")?;
    let signing = EcSigningKey::from_slice(&key);
    key.zeroize();
    let signing = signing.map_err(|_| {
        err("secp256k1_pubkey: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)")
    })?;
    // compressed? default true (33 bytes).
    let compressed = match args.get(1) {
        None | Some(SynValue::Nothing) => true,
        Some(SynValue::Bool(b)) => *b,
        Some(other) => {
            return Err(err(format!(
                "secp256k1_pubkey: the second argument (compressed) must be true or false, got {}",
                other.type_name()
            )))
        }
    };
    Ok(syn_bytes(signing.verifying_key().to_encoded_point(compressed).as_bytes().to_vec()))
}

// =========================================================
// ed25519 (Solana, Algorand)
// =========================================================

/// Seed de 32 bytes desde el material de clave. Acepta la forma Solana de 64 bytes
/// `[seed(32) || pubkey(32)]`, validando que la pubkey coincida con la derivada del
/// seed (mismatch → error claro, sin exponer material). `key` se zeroiza acá.
pub(crate) fn ed25519_seed(mut key: Vec<u8>, fname: &str) -> Result<SigningKey, Control> {
    let result = (|| {
        let seed: [u8; 32] = match key.len() {
            32 => key[..32].try_into().expect("32 bytes"),
            64 => {
                let seed: [u8; 32] = key[..32].try_into().expect("32 bytes");
                let claimed = &key[32..64];
                let sk = SigningKey::from_bytes(&seed);
                if sk.verifying_key().to_bytes() != claimed {
                    return Err(err(format!(
                        "{}: the 64-byte key's embedded public key does not match the one derived from the seed (the key value is never shown)",
                        fname
                    )));
                }
                return Ok(sk);
            }
            n => {
                return Err(err(format!(
                    "{}: the ed25519 key must be a 32-byte seed (or 64-byte seed||pubkey), got {} bytes",
                    fname, n
                )))
            }
        };
        Ok(SigningKey::from_bytes(&seed))
    })();
    key.zeroize();
    result
}

fn ed25519_sign(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    // ⚠️ ed25519 firma el MENSAJE CRUDO (hashea internamente por RFC 8032) — NO un
    // pre-hash. Aceptamos bytes o text (a diferencia de secp256k1, acá no hay
    // ambigüedad: el mensaje se firma tal cual, no se interpreta como número).
    let message: Vec<u8> = match arg(args, 0, "ed25519_sign")? {
        SynValue::Bytes(b) => b[..].to_vec(),
        SynValue::Text(s) => s.as_bytes().to_vec(),
        SynValue::Secret(_) => {
            return Err(err(
                "ed25519_sign: the message must be bytes or text, got a secret; only the key is a secret",
            ))
        }
        other => {
            return Err(err(format!(
                "ed25519_sign: the message must be bytes or text, got {}. ed25519 signs the raw message (do NOT pre-hash it).",
                other.type_name()
            )))
        }
    };
    let (name, key) = key_material(arg(args, 1, "ed25519_sign")?, "ed25519_sign")?;
    if let Err(e) = gate_and_audit(caps, &name, "ed25519", loc) {
        let mut k = key;
        k.zeroize();
        return Err(e);
    }
    let sk = ed25519_seed(key, "ed25519_sign")?;
    let sig = sk.sign(&message);
    Ok(syn_bytes(sig.to_bytes().to_vec())) // 64 bytes
}

fn ed25519_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    let message: Vec<u8> = match arg(args, 0, "ed25519_verify")? {
        SynValue::Bytes(b) => b[..].to_vec(),
        SynValue::Text(s) => s.as_bytes().to_vec(),
        other => {
            return Err(err(format!(
                "ed25519_verify: the message must be bytes or text, got {}",
                other.type_name()
            )))
        }
    };
    let sig = arg_bytes_len(arg(args, 1, "ed25519_verify")?, "ed25519_verify", "the signature", 64)?;
    let pubkey = arg_bytes_len(arg(args, 2, "ed25519_verify")?, "ed25519_verify", "the public key", 32)?;
    let pk_arr: [u8; 32] = pubkey.try_into().expect("32 bytes");
    let vk = match EdVerifyingKey::from_bytes(&pk_arr) {
        Ok(vk) => vk,
        Err(_) => return Err(err("ed25519_verify: the public key is not a valid ed25519 point")),
    };
    let sig_arr: [u8; 64] = sig.try_into().expect("64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    // verify_STRICT (no `verify`): rechaza pubkeys/R de orden pequeño — bajo el verify
    // laxo una pubkey de orden pequeño "valida" CUALQUIER mensaje (forja trivial), y
    // las cadenas (Solana/Algorand) rechazan lo que strict rechaza. Money code: el
    // verificador local jamás debe aceptar lo que la cadena rechazaría.
    Ok(syn_bool(vk.verify_strict(&message, &signature).is_ok()))
}

fn ed25519_pubkey(args: &[SynValue]) -> Result<SynValue, Control> {
    let (_name, key) = key_material(arg(args, 0, "ed25519_pubkey")?, "ed25519_pubkey")?;
    let sk = ed25519_seed(key, "ed25519_pubkey")?;
    Ok(syn_bytes(sk.verifying_key().to_bytes().to_vec())) // 32 bytes
}

// =========================================================
// bech32 (Avalanche X/P; direcciones segwit) — PURO
// =========================================================

fn bech32_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    let hrp_s = match arg(args, 0, "bech32_encode")? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "bech32_encode: the HRP (human-readable part) must be text, got {}",
                other.type_name()
            )))
        }
    };
    let data = arg_bytes(arg(args, 1, "bech32_encode")?, "bech32_encode", "the data")?;
    let variant = match args.get(2) {
        None | Some(SynValue::Nothing) => "bech32".to_string(),
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => {
            return Err(err(format!(
                "bech32_encode: the variant must be \"bech32\" or \"bech32m\", got {}",
                other.type_name()
            )))
        }
    };
    let hrp = Hrp::parse(&hrp_s)
        .map_err(|e| err(format!("bech32_encode: invalid HRP: {}", e)))?;
    let s = match variant.as_str() {
        "bech32" => bech32::encode::<Bech32>(hrp, data),
        "bech32m" => bech32::encode::<Bech32m>(hrp, data),
        other => {
            return Err(err(format!(
                "bech32_encode: unknown variant {:?}; use \"bech32\" or \"bech32m\"",
                other
            )))
        }
    };
    s.map(syn_text).map_err(|e| err(format!("bech32_encode: {}", e)))
}

fn bech32_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    let text = match arg(args, 0, "bech32_decode")? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "bech32_decode: expected a bech32 string, got {}",
                other.type_name()
            )))
        }
    };
    // Detectar la variante por el CHECKSUM (bech32::decode es agnóstico): probar
    // Bech32 (BIP-173) y, si su checksum no valida, Bech32m (BIP-350). Un string sólo
    // valida contra UNA de las dos (los checksums difieren por diseño).
    use bech32::primitives::decode::CheckedHrpstring;
    let (hrp, data, variant) =
        if let Ok(cs) = CheckedHrpstring::new::<Bech32>(&text) {
            (cs.hrp(), cs.byte_iter().collect::<Vec<u8>>(), "bech32")
        } else if let Ok(cs) = CheckedHrpstring::new::<Bech32m>(&text) {
            (cs.hrp(), cs.byte_iter().collect::<Vec<u8>>(), "bech32m")
        } else {
            return Err(err(
                "bech32_decode: invalid checksum (the string is neither valid bech32 nor bech32m)",
            ));
        };
    let mut m = IndexMap::new();
    m.insert("hrp".to_string(), syn_text(hrp.as_str()));
    m.insert("data".to_string(), syn_bytes(data));
    m.insert("variant".to_string(), syn_text(variant));
    Ok(syn_map(m))
}

// =========================================================
// EVM: dirección EIP-55 + RLP — PURO
// =========================================================

/// Pubkey secp256k1 SIN comprimir (65 bytes con prefijo 0x04) desde una pubkey
/// (33/65) o un `secret` (deriva Rust-side). El error nunca expone material.
fn uncompressed_pubkey(v: &SynValue, fname: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Secret(_) => {
            let (_name, mut key) = key_material(v, fname)?;
            let signing = EcSigningKey::from_slice(&key);
            key.zeroize();
            let signing = signing.map_err(|_| {
                err(format!("{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)", fname))
            })?;
            Ok(signing.verifying_key().to_encoded_point(false).as_bytes().to_vec())
        }
        SynValue::Bytes(b) => {
            if !matches!(b.len(), 33 | 65) {
                return Err(err(format!(
                    "{}: expected a secp256k1 public key of 33 or 65 bytes (or a key secret), got {} bytes",
                    fname,
                    b.len()
                )));
            }
            let vk = VerifyingKey::from_sec1_bytes(b)
                .map_err(|_| err(format!("{}: the public key is not a valid secp256k1 point", fname)))?;
            Ok(vk.to_encoded_point(false).as_bytes().to_vec())
        }
        other => Err(err(format!(
            "{}: expected a secp256k1 public key (bytes) or a key secret, got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// Checksum EIP-55: hex mixed-case de los 20 bytes de dirección (con `0x`).
pub(crate) fn eip55(addr20: &[u8]) -> String {
    let hexs = synsema_core::bytesutil::hex_encode(addr20); // 40 chars lowercase
    let hash = Keccak256::digest(hexs.as_bytes());
    let hash_hex = synsema_core::bytesutil::hex_encode(&hash); // 64 chars
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hexs.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            // Nibble i del hash: uppercase si >= 8.
            let hn = hash_hex.as_bytes()[i];
            if hn >= b'8' {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    out
}

fn eth_address(args: &[SynValue]) -> Result<SynValue, Control> {
    let uncompressed = uncompressed_pubkey(arg(args, 0, "eth_address")?, "eth_address")?;
    // keccak256(pubkey_sin_comprimir[1..])[12..] → 20 bytes.
    let hash = Keccak256::digest(&uncompressed[1..]);
    Ok(syn_text(eip55(&hash[12..])))
}

// -- RLP --

const RLP_MAX_DEPTH: usize = 64;

/// Bytes big-endian MÍNIMOS de un entero no-negativo (0 → vacío). Float/Decimal/negativo
/// → error (RLP no los codifica). El error no expone valor sensible (los enteros de una
/// tx no son secretos, pero mantenemos el estilo).
fn int_be_minimal(n: &Number, fname: &str) -> Result<Vec<u8>, Control> {
    match n {
        Number::Int(i) => {
            if *i < 0 {
                return Err(err(format!("{}: cannot RLP-encode a negative integer", fname)));
            }
            let bytes = (*i as u64).to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
            Ok(bytes[first..].to_vec())
        }
        Number::Big(b) => {
            use num_bigint::Sign;
            let (sign, mag) = b.to_bytes_be();
            if sign == Sign::Minus {
                return Err(err(format!("{}: cannot RLP-encode a negative integer", fname)));
            }
            // to_bytes_be de cero → [0]; RLP quiere vacío.
            if mag == [0] {
                Ok(Vec::new())
            } else {
                Ok(mag)
            }
        }
        Number::Float(_) => {
            Err(err(format!("{}: cannot RLP-encode a float; RLP takes bytes, non-negative integers, and lists", fname)))
        }
        Number::Decimal(_) => {
            Err(err(format!("{}: cannot RLP-encode a decimal; RLP takes bytes, non-negative integers, and lists", fname)))
        }
    }
}

fn rlp_string(s: &[u8], out: &mut Vec<u8>) {
    if s.len() == 1 && s[0] <= 0x7f {
        out.push(s[0]);
    } else if s.len() <= 55 {
        out.push(0x80 + s.len() as u8);
        out.extend_from_slice(s);
    } else {
        let len_bytes = (s.len() as u64).to_be_bytes();
        let first = len_bytes.iter().position(|&b| b != 0).unwrap_or(len_bytes.len());
        let len_be = &len_bytes[first..];
        out.push(0xb7 + len_be.len() as u8);
        out.extend_from_slice(len_be);
        out.extend_from_slice(s);
    }
}

fn rlp_list_frame(payload: &[u8], out: &mut Vec<u8>) {
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
        out.extend_from_slice(payload);
    } else {
        let len_bytes = (payload.len() as u64).to_be_bytes();
        let first = len_bytes.iter().position(|&b| b != 0).unwrap_or(len_bytes.len());
        let len_be = &len_bytes[first..];
        out.push(0xf7 + len_be.len() as u8);
        out.extend_from_slice(len_be);
        out.extend_from_slice(payload);
    }
}

/// `pub(crate)`: blockchain_rpc.rs (tx_eip1559/tx_eip1559_raw) serializa la lista
/// de fields con el MISMO encoder RLP (una sola implementación de money-encoding).
pub(crate) fn rlp_encode_val(v: &SynValue, depth: usize, out: &mut Vec<u8>) -> Result<(), Control> {
    if depth > RLP_MAX_DEPTH {
        return Err(err("rlp_encode: the list is nested too deeply (max 64 levels)"));
    }
    match v {
        SynValue::Bytes(b) => {
            rlp_string(&b[..], out);
            Ok(())
        }
        SynValue::Number(n) => {
            let be = int_be_minimal(n, "rlp_encode")?;
            rlp_string(&be, out);
            Ok(())
        }
        SynValue::List(l) => {
            let mut payload = Vec::new();
            for item in l.borrow().iter() {
                rlp_encode_val(item, depth + 1, &mut payload)?;
            }
            rlp_list_frame(&payload, out);
            Ok(())
        }
        // text/secret/map/decimal → error dirigido (no adivinar la codificación — money code).
        SynValue::Text(_) => Err(err(
            "rlp_encode: cannot encode text directly (ambiguous); convert with bytes(x) for UTF-8 or bytes(x, \"hex\") for a hex value",
        )),
        SynValue::Secret(_) => Err(err("rlp_encode: cannot encode a secret")),
        other => Err(err(format!(
            "rlp_encode: cannot encode {}; RLP takes bytes, non-negative integers, and lists",
            other.type_name()
        ))),
    }
}

fn rlp_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    let mut out = Vec::new();
    rlp_encode_val(arg(args, 0, "rlp_encode")?, 0, &mut out)?;
    Ok(syn_bytes(out))
}

/// Decodifica un item RLP en `data[pos..]`. Devuelve (valor, nuevo_pos). Bounds-checked
/// en cada paso (sin panic — G10); profundidad acotada.
fn rlp_decode_at(data: &[u8], pos: usize, depth: usize) -> Result<(SynValue, usize), Control> {
    if depth > RLP_MAX_DEPTH {
        return Err(err("rlp_decode: the input is nested too deeply (max 64 levels)"));
    }
    if pos >= data.len() {
        return Err(err("rlp_decode: unexpected end of input"));
    }
    let prefix = data[pos];
    // Helper: leer un largo de `nbytes` big-endian desde `start`. ESTRICTO (es código
    // de dinero, como los decoders canónicos de Ethereum): un byte de largo con cero
    // a la izquierda, o la forma larga para un payload < 56 bytes, se RECHAZAN — dos
    // byte-strings distintos jamás decodifican a la misma estructura en silencio.
    let read_len = |start: usize, nbytes: usize| -> Result<usize, Control> {
        if nbytes == 0 || nbytes > 8 || start + nbytes > data.len() {
            return Err(err("rlp_decode: truncated length header"));
        }
        if data[start] == 0 {
            return Err(err(
                "rlp_decode: non-canonical encoding (length header has a leading zero byte)",
            ));
        }
        let mut n: u64 = 0;
        for &b in &data[start..start + nbytes] {
            n = (n << 8) | b as u64;
        }
        let len = usize::try_from(n).map_err(|_| err("rlp_decode: length is too large"))?;
        if len <= 55 {
            return Err(err(
                "rlp_decode: non-canonical encoding (long-form length used for a payload under 56 bytes)",
            ));
        }
        Ok(len)
    };
    if prefix <= 0x7f {
        // Byte único, es su propio valor.
        Ok((syn_bytes(vec![prefix]), pos + 1))
    } else if prefix <= 0xb7 {
        // String corto (0..55 bytes).
        let len = (prefix - 0x80) as usize;
        let start = pos + 1;
        if start + len > data.len() {
            return Err(err("rlp_decode: string body exceeds input length"));
        }
        // Canonicidad: un byte único <= 0x7f DEBE codificarse como sí mismo, no 0x81 xx.
        if len == 1 && data[start] <= 0x7f {
            return Err(err(
                "rlp_decode: non-canonical encoding (a single byte <= 0x7f must be encoded as itself)",
            ));
        }
        Ok((syn_bytes(data[start..start + len].to_vec()), start + len))
    } else if prefix <= 0xbf {
        // String largo: 0xb7 + nbytes de largo (read_len exige largo >= 56, canónico).
        let nbytes = (prefix - 0xb7) as usize;
        let len = read_len(pos + 1, nbytes)?;
        let start = pos + 1 + nbytes;
        if start + len > data.len() {
            return Err(err("rlp_decode: string body exceeds input length"));
        }
        Ok((syn_bytes(data[start..start + len].to_vec()), start + len))
    } else if prefix <= 0xf7 {
        // Lista corta.
        let len = (prefix - 0xc0) as usize;
        let start = pos + 1;
        rlp_decode_list(data, start, len, depth)
    } else {
        // Lista larga (read_len exige largo >= 56, canónico).
        let nbytes = (prefix - 0xf7) as usize;
        let len = read_len(pos + 1, nbytes)?;
        let start = pos + 1 + nbytes;
        rlp_decode_list(data, start, len, depth)
    }
}

fn rlp_decode_list(
    data: &[u8],
    start: usize,
    len: usize,
    depth: usize,
) -> Result<(SynValue, usize), Control> {
    let end = start + len;
    if end > data.len() {
        return Err(err("rlp_decode: list body exceeds input length"));
    }
    let mut items = Vec::new();
    let mut p = start;
    while p < end {
        let (v, np) = rlp_decode_at(data, p, depth + 1)?;
        if np > end {
            return Err(err("rlp_decode: a list item overruns the list body"));
        }
        items.push(v);
        p = np;
    }
    Ok((SynValue::List(Rc::new(RefCell::new(items))), end))
}

fn rlp_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    let data = arg_bytes(arg(args, 0, "rlp_decode")?, "rlp_decode", "the input")?;
    if data.is_empty() {
        return Err(err("rlp_decode: empty input"));
    }
    let (v, consumed) = rlp_decode_at(data, 0, 0)?;
    if consumed != data.len() {
        return Err(err(format!(
            "rlp_decode: {} trailing byte(s) after the first RLP item",
            data.len() - consumed
        )));
    }
    Ok(v)
}

// =========================================================
// Registro
// =========================================================

/// Registra los builtins de blockchain. Los PUROS no tocan `caps`; los de FIRMA
/// (`secp256k1_sign`/`ed25519_sign`) cierran sobre el `CapabilitySet` para gatear
/// `sign("NAME")` + audit (G3). Wired en `engine.rs` y en el intérprete base de serve.
pub fn register_blockchain_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // -- hashes/encoding viven en hashing.rs y core (bytes/decode) --

    // -- secp256k1 --
    {
        let caps = caps.clone();
        interp.register_builtin(
            "secp256k1_sign",
            2,
            Rc::new(move |_i, a, l| secp256k1_sign(a, l, &caps)),
        );
    }
    interp.register_builtin("secp256k1_verify", 3, Rc::new(|_i, a, _l| secp256k1_verify(a)));
    interp.register_builtin("secp256k1_recover", 2, Rc::new(|_i, a, _l| secp256k1_recover(a)));
    interp.register_builtin("secp256k1_pubkey", -1, Rc::new(|_i, a, _l| secp256k1_pubkey(a)));

    // -- ed25519 --
    {
        let caps = caps.clone();
        interp.register_builtin(
            "ed25519_sign",
            2,
            Rc::new(move |_i, a, l| ed25519_sign(a, l, &caps)),
        );
    }
    interp.register_builtin("ed25519_verify", 3, Rc::new(|_i, a, _l| ed25519_verify(a)));
    interp.register_builtin("ed25519_pubkey", 1, Rc::new(|_i, a, _l| ed25519_pubkey(a)));

    // -- bech32 --
    interp.register_builtin("bech32_encode", -1, Rc::new(|_i, a, _l| bech32_encode(a)));
    interp.register_builtin("bech32_decode", 1, Rc::new(|_i, a, _l| bech32_decode(a)));

    // -- EVM --
    interp.register_builtin("eth_address", 1, Rc::new(|_i, a, _l| eth_address(a)));
    interp.register_builtin("rlp_encode", 1, Rc::new(|_i, a, _l| rlp_encode(a)));
    interp.register_builtin("rlp_decode", 1, Rc::new(|_i, a, _l| rlp_decode(a)));

    // -- Batch 12 (todo PURO — G13: ninguna puerta de firma nueva) --
    crate::blockchain_abi::register(interp); // ABI + EIP-191 + EIP-712
    crate::blockchain_solana::register(interp); // message/tx de Solana + PDA/SPL (Batch 13)
    crate::blockchain_algorand::register(interp); // msgpack canónico de Algorand

    // -- Batch 13 (custodia): HD wallets + keystore V3, TODO gateado por `wallet`
    //    (G20) y TODO devuelve `secret` (G19). Cierra sobre el mismo CapabilitySet
    //    → sandbox lo vacía, deny-by-default.
    crate::blockchain_hd::register(interp, caps.clone());

    // -- Batch 14 (read-side): JSON-RPC EVM/Solana + REST algod, TODO gateado por
    //    `net(host)` (G22 — cero capability nueva; `sign` sigue siendo la única
    //    puerta de valor) + los builders EIP-1559 puros. Sin `native` el transporte
    //    es el stub de http (falla con "no sockets in this build") → los builders
    //    puros (tx_eip1559/…) siguen completos en el perfil wasm.
    crate::blockchain_rpc::register(interp, caps.clone());

    // -- Batch 16 (Bitcoin): direcciones/txid/builder UTXO/PSBT puros;
    //    `schnorr_sign` con la MISMA puerta `sign`, `wif_import` con `wallet`,
    //    read-side Esplora/Core con `net(host)` (G30 — cero puerta nueva).
    crate::blockchain_btc::register(interp, caps.clone());
    crate::blockchain_btc_rpc::register(interp, caps);
}
