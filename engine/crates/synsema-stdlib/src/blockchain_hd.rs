//! HD wallets / mnemónicos + keystore V3 (Batch 13, alcances A y C) — CUSTODIA.
//! Un agente genera una wallet desde cero (mnemónico → seed → claves derivadas),
//! la respalda como frase, e importa/exporta keystores de Ethereum — como
//! Metamask/Phantom/Pera, con la paranoia máxima de la serie:
//!
//! - **G19 — la derivación NUNCA materializa material.** TODO lo que produce un
//!   mnemónico/seed/clave devuelve un **`secret`** sellado (`syn_secret*`); el
//!   mnemónico y la passphrase ENTRAN como `secret`. No existe camino desde el
//!   lenguaje al plaintext (sólo `reveal`, gateado + auditado, para respaldar la
//!   frase a propósito).
//! - **G20 — crear custodia es gateado + auditado.** Cada builtin de este módulo
//!   exige la capability `wallet` (deny-by-default, nunca ambiente; `sandbox` la
//!   vacía) con scope al name del secret de ORIGEN (o al label del secret nuevo
//!   al generar), y escribe un audit fail-loud en `wallet.log` (sin auditoría no
//!   se crea custodia — mismo criterio que `sign`/`reveal`).
//! - **G18 — descenso acotado.** El parser del path BIP-32 acota largo y número
//!   de segmentos; todo error es atrapable (`try`/`recover`), jamás un panic.
//! - **G4 — errores sin fuga.** Ningún mensaje ecoa mnemónico/seed/clave/
//!   passphrase; describen forma (conteo de palabras, índice, tamaño).
//! - **Estándares:** BIP-39 (crate `bip39` de rust-bitcoin; wordlist inglesa
//!   embebida), BIP-32 (secp256k1, hand-rolled sobre hmac/sha2/k256), SLIP-0010
//!   (ed25519, hardened-only, hand-rolled), mnemónico de 25 palabras de Algorand
//!   (NO es BIP-39: checksum sha512_256 y empaquetado 11-bit little-endian propio,
//!   pero la MISMA wordlist inglesa), keystore V3 de Ethereum (scrypt/pbkdf2 +
//!   AES-128-CTR + MAC keccak256 — Geth/MyEtherWallet).

use std::cell::RefCell;
use std::rc::Rc;

use aes::Aes128;
use bip39::{Language, Mnemonic};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256, Sha512, Sha512_256};
use sha3::Keccak256;
use zeroize::Zeroize;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::secret::constant_time_eq;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_secret, syn_secret_bytes, syn_text, SynValue};

use crate::blockchain::{arg, err, key_material};
use crate::secrets::write_wallet_audit;

type HmacSha512 = Hmac<Sha512>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

// =========================================================
// Gate + audit de custodia (G20)
// =========================================================

fn wallet_denied(name: &str) -> Control {
    err(format!(
        "wallet not permitted: Capability not granted: wallet(\"{name}\") — \
         add `require wallet(\"{name}\")` or a bare `require wallet` (creating key \
         custody is deny-by-default and writes a persistent audit entry)"
    ))
}

/// Chequea `wallet("NAME")` (scope al name del secret de origen, o al label del
/// secret nuevo al generar) y escribe el audit en `wallet.log`. Fail-loud: si no
/// se puede auditar en el camino concedido, NO se crea custodia. `pub(crate)`:
/// blockchain_btc.rs (wif_import) es custodia con la MISMA puerta (G30).
pub(crate) fn gate_wallet(
    caps: &Rc<RefCell<CapabilitySet>>,
    name: &str,
    op: &str,
    loc: &SourceLocation,
) -> Result<(), Control> {
    let granted = caps
        .borrow_mut()
        .check(&Capability::new(CapabilityType::Wallet, Some(name.to_string())), "wallet-builtin");
    if !granted {
        // Auditar el intento DENEGADO (best-effort: ya se rechaza igual).
        let _ = write_wallet_audit(name, op, loc, false);
        return Err(wallet_denied(name));
    }
    write_wallet_audit(name, op, loc, true).map_err(|e| {
        err(format!(
            "wallet(\"{name}\") failed: cannot write the audit log ({e}). \
             Refusing to create custody without an audit trail."
        ))
    })
}

// =========================================================
// Lectura de argumentos específica de custodia
// =========================================================

/// Texto plano de un `secret` de TEXTO (mnemónico/passphrase). El plaintext queda
/// Rust-side; jamás se vuelve un valor Synsema. Un no-secret → error dirigido (G19:
/// el material sensible ENTRA como secret; `as_secret(...)` sella un valor en mano).
fn text_secret_material(v: &SynValue, fname: &str, what: &str) -> Result<(String, String), Control> {
    match v {
        SynValue::Secret(inner) => {
            Ok((inner.name().to_string(), inner.expose().into_owned()))
        }
        other => Err(err(format!(
            "{}: {} must be a secret (it is custody material) — load it with secret(\"NAME\") \
             or seal it with as_secret(x, \"LABEL\"), got {}. Never pass it as a plain string.",
            fname,
            what,
            other.type_name()
        ))),
    }
}

pub(crate) fn opt_label(v: Option<&SynValue>, fname: &str, default: &str) -> Result<String, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(default.to_string()),
        Some(SynValue::Text(s)) => Ok(s.to_string()),
        Some(other) => Err(err(format!(
            "{}: the label must be text, got {}",
            fname,
            other.type_name()
        ))),
    }
}

// =========================================================
// BIP-39 (mnemónico ↔ entropy ↔ seed)
// =========================================================

/// Error de validación BIP-39 SIN fuga (G4): describe la forma (conteo, índice),
/// jamás la palabra ni la frase.
fn bip39_error(e: bip39::Error, fname: &str) -> Control {
    use bip39::Error as E;
    let detail = match e {
        E::BadWordCount(n) => format!("bad word count {} (must be 12, 15, 18, 21 or 24)", n),
        E::UnknownWord(i) => format!("word {} is not in the BIP-39 English word list", i + 1),
        E::InvalidChecksum => "the checksum does not verify (a mistyped or reordered word)".to_string(),
        E::BadEntropyBitCount(n) => format!("bad entropy size ({} bits)", n),
        E::AmbiguousLanguages(_) => "ambiguous language".to_string(),
    };
    err(format!(
        "{}: the mnemonic does not pass BIP-39 validation: {}. The mnemonic value is never shown.",
        fname, detail
    ))
}

/// Parsea + valida (checksum incluido) un mnemónico BIP-39 inglés desde el
/// plaintext de un secret. El plaintext se zeroiza acá.
fn parse_bip39(mut phrase: String, fname: &str) -> Result<Mnemonic, Control> {
    let r = Mnemonic::parse_in(Language::English, phrase.trim());
    phrase.zeroize();
    r.map_err(|e| bip39_error(e, fname))
}

fn mnemonic_generate(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "mnemonic_generate";
    let words = match args.first() {
        None | Some(SynValue::Nothing) => 12usize,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(w @ (12 | 15 | 18 | 21 | 24)) => w as usize,
            _ => {
                return Err(err(format!(
                    "{}: the word count must be 12, 15, 18, 21 or 24, got {}",
                    F, n
                )))
            }
        },
        Some(other) => {
            return Err(err(format!(
                "{}: the word count must be a number, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let label = opt_label(args.get(1), F, "mnemonic")?;
    gate_wallet(caps, &label, "generate", loc)?;
    // Entropía del CSPRNG del SO (OsRng, del `rand` que el engine ya usa) — jamás
    // un RNG hand-rolled ni sembrable: es la semilla de una wallet real.
    let mut entropy = vec![0u8; words * 4 / 3]; // 12→16, 15→20, 18→24, 21→28, 24→32
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut entropy)
        .map_err(|_| err(format!("{}: the OS random source is unavailable", F)))?;
    let m = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| bip39_error(e, F));
    entropy.zeroize();
    let m = m?;
    Ok(syn_secret(label, m.to_string()))
}

fn mnemonic_to_seed(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "mnemonic_to_seed";
    let (mname, mut phrase) = text_secret_material(arg(args, 0, F)?, F, "the mnemonic")?;
    let mut passphrase = match args.get(1) {
        None | Some(SynValue::Nothing) => String::new(),
        Some(v) => match text_secret_material(v, F, "the passphrase") {
            Ok((_, p)) => p,
            Err(e) => {
                phrase.zeroize();
                return Err(e);
            }
        },
    };
    if let Err(e) = gate_wallet(caps, &mname, "seed", loc) {
        phrase.zeroize();
        passphrase.zeroize();
        return Err(e);
    }
    let m = match parse_bip39(phrase, F) {
        Ok(m) => m,
        Err(e) => {
            passphrase.zeroize();
            return Err(e);
        }
    };
    // `to_seed` normaliza el passphrase a NFKD (BIP-39) — feature unicode-normalization.
    let mut seed = m.to_seed(passphrase.as_str());
    passphrase.zeroize();
    let out = syn_secret_bytes(format!("{}.seed", mname), seed.to_vec());
    seed.zeroize();
    Ok(out)
}

fn mnemonic_from_entropy(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "mnemonic_from_entropy";
    // La entropía ES material de clave → entra como secret (bytes crudos o hex).
    let (ename, mut entropy) = key_material(arg(args, 0, F)?, F)?;
    let label = opt_label(args.get(1), F, &format!("{}.mnemonic", ename))?;
    if let Err(e) = gate_wallet(caps, &label, "generate", loc) {
        entropy.zeroize();
        return Err(e);
    }
    if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
        let n = entropy.len();
        entropy.zeroize();
        return Err(err(format!(
            "{}: the entropy must be 16, 20, 24, 28 or 32 bytes, got {}",
            F, n
        )));
    }
    let m = Mnemonic::from_entropy_in(Language::English, &entropy).map_err(|e| bip39_error(e, F));
    entropy.zeroize();
    Ok(syn_secret(label, m?.to_string()))
}

fn mnemonic_to_entropy(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "mnemonic_to_entropy";
    let (mname, mut phrase) = text_secret_material(arg(args, 0, F)?, F, "the mnemonic")?;
    if let Err(e) = gate_wallet(caps, &mname, "entropy", loc) {
        phrase.zeroize();
        return Err(e);
    }
    let m = parse_bip39(phrase, F)?;
    Ok(syn_secret_bytes(format!("{}.entropy", mname), m.to_entropy()))
}

// =========================================================
// BIP-32 (secp256k1) + SLIP-0010 (ed25519)
// =========================================================

/// Cotas del parser de paths (G18): un path hostil larguísimo o con miles de
/// segmentos errora atrapable — jamás consume memoria/stack sin límite.
const PATH_MAX_LEN: usize = 256;
const PATH_MAX_SEGMENTS: usize = 32;
const HARDENED: u32 = 0x8000_0000;

/// Parsea un path BIP-32 (`m/44'/60'/0'/0/0`; `h`/`H` también marcan hardened).
/// Devuelve los índices YA con el bit hardened aplicado.
fn parse_path(path: &str, fname: &str) -> Result<Vec<u32>, Control> {
    if path.len() > PATH_MAX_LEN {
        return Err(err(format!(
            "{}: the derivation path is too long ({} characters, max {})",
            fname,
            path.len(),
            PATH_MAX_LEN
        )));
    }
    let mut parts = path.split('/');
    match parts.next() {
        Some("m") | Some("M") => {}
        _ => {
            return Err(err(format!(
                "{}: the derivation path must start with \"m\" (e.g. \"m/44'/60'/0'/0/0\")",
                fname
            )))
        }
    }
    let mut out = Vec::new();
    for (i, seg) in parts.enumerate() {
        if i >= PATH_MAX_SEGMENTS {
            return Err(err(format!(
                "{}: the derivation path has too many segments (max {})",
                fname, PATH_MAX_SEGMENTS
            )));
        }
        let (digits, hardened) = match seg.strip_suffix(['\'', 'h', 'H']) {
            Some(d) => (d, true),
            None => (seg, false),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err(format!(
                "{}: invalid path segment {:?} (expected a number, optionally followed by ' for hardened)",
                fname, seg
            )));
        }
        let n: u32 = digits.parse().map_err(|_| {
            err(format!(
                "{}: path segment {:?} is out of range (each index must be below 2^31)",
                fname, seg
            ))
        })?;
        if n >= HARDENED {
            return Err(err(format!(
                "{}: path segment {:?} is out of range (each index must be below 2^31)",
                fname, seg
            )));
        }
        out.push(if hardened { n | HARDENED } else { n });
    }
    Ok(out)
}

/// HMAC-SHA512 (el primitivo de BIP-32/SLIP-0010).
fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut m = HmacSha512::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Deriva BIP-32 secp256k1: seed → master ("Bitcoin seed") → hijos por el path.
/// Los inválidos-por-probabilidad (IL ≥ n, k = 0; ~2^-127) erroran claro en vez
/// de re-intentar en silencio (money code: nada de fallbacks mudos).
fn derive_secp256k1(seed: &[u8], path: &[u32], fname: &str) -> Result<Vec<u8>, Control> {
    let invalid = |what: &str| {
        err(format!(
            "{}: {} (an astronomically unlikely seed/path; use a different one). No material is shown.",
            fname, what
        ))
    };
    let mut i = hmac512(b"Bitcoin seed", seed);
    let (kb, cb) = i.split_at(32);
    let key_ct = Option::<Scalar>::from(Scalar::from_repr(*k256::FieldBytes::from_slice(kb)));
    let mut chain: [u8; 32] = cb.try_into().expect("32 bytes");
    i.zeroize();
    let mut key: Scalar = match key_ct {
        Some(k) if k != Scalar::ZERO => k,
        _ => return Err(invalid("the master key derived from this seed is invalid")),
    };
    for &idx in path {
        let mut data = Vec::with_capacity(37);
        if idx & HARDENED != 0 {
            data.push(0);
            data.extend_from_slice(&key.to_bytes());
        } else {
            let point = (ProjectivePoint::GENERATOR * key).to_affine();
            data.extend_from_slice(point.to_encoded_point(true).as_bytes());
        }
        data.extend_from_slice(&idx.to_be_bytes());
        let mut i = hmac512(&chain, &data);
        data.zeroize();
        let (ilb, irb) = i.split_at(32);
        let il = Option::<Scalar>::from(Scalar::from_repr(*k256::FieldBytes::from_slice(ilb)));
        chain = irb.try_into().expect("32 bytes");
        i.zeroize();
        let il = match il {
            Some(v) => v,
            None => return Err(invalid("a child key along this path is invalid")),
        };
        key += il;
        if key == Scalar::ZERO {
            return Err(invalid("a child key along this path is invalid"));
        }
    }
    chain.zeroize();
    Ok(key.to_bytes().to_vec())
}

/// Deriva SLIP-0010 ed25519: seed → master ("ed25519 seed") → hijos (SÓLO
/// hardened; la curva no soporta derivación normal — error claro, no silencio).
fn derive_ed25519(seed: &[u8], path: &[u32], fname: &str) -> Result<Vec<u8>, Control> {
    for &idx in path {
        if idx & HARDENED == 0 {
            return Err(err(format!(
                "{}: SLIP-0010 ed25519 only supports HARDENED indices — write {}' instead of {} \
                 (e.g. Solana uses \"m/44'/501'/0'/0'\")",
                fname,
                idx,
                idx
            )));
        }
    }
    let mut i = hmac512(b"ed25519 seed", seed);
    let mut key: [u8; 32] = i[..32].try_into().expect("32 bytes");
    let mut chain: [u8; 32] = i[32..].try_into().expect("32 bytes");
    i.zeroize();
    for &idx in path {
        let mut data = Vec::with_capacity(37);
        data.push(0);
        data.extend_from_slice(&key);
        data.extend_from_slice(&idx.to_be_bytes());
        let mut i = hmac512(&chain, &data);
        data.zeroize();
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        i.zeroize();
    }
    chain.zeroize();
    Ok(key.to_vec())
}

fn hd_derive(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "hd_derive";
    let (sname, mut seed) = key_material(arg(args, 0, F)?, F)?;
    let cleanup = |mut s: Vec<u8>| {
        s.zeroize();
    };
    let path_s = match args.get(1) {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => {
            cleanup(seed);
            return Err(err(format!(
                "{}: the path must be text like \"m/44'/60'/0'/0/0\", got {}",
                F,
                other.type_name()
            )));
        }
        None => {
            cleanup(seed);
            return Err(err(format!("{}: missing argument 2 (the derivation path)", F)));
        }
    };
    let curve = match args.get(2) {
        None | Some(SynValue::Nothing) => "secp256k1".to_string(),
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => {
            cleanup(seed);
            return Err(err(format!(
                "{}: the curve must be \"secp256k1\" or \"ed25519\", got {}",
                F,
                other.type_name()
            )));
        }
    };
    let label = match opt_label(args.get(3), F, &format!("{}/{}", sname, path_s)) {
        Ok(l) => l,
        Err(e) => {
            cleanup(seed);
            return Err(e);
        }
    };
    if let Err(e) = gate_wallet(caps, &sname, &format!("derive curve={}", curve), loc) {
        cleanup(seed);
        return Err(e);
    }
    let result = (|| {
        if !(16..=64).contains(&seed.len()) {
            return Err(err(format!(
                "{}: the seed must be 16..=64 bytes (BIP-39 seeds are 64), got {}",
                F,
                seed.len()
            )));
        }
        let path = parse_path(&path_s, F)?;
        match curve.as_str() {
            "secp256k1" => derive_secp256k1(&seed, &path, F),
            "ed25519" => derive_ed25519(&seed, &path, F),
            other => Err(err(format!(
                "{}: unknown curve {:?}; use \"secp256k1\" (EVM, default) or \"ed25519\" (Solana)",
                F, other
            ))),
        }
    })();
    seed.zeroize();
    let mut key = result?;
    let out = syn_secret_bytes(label, key.to_vec());
    key.zeroize();
    Ok(out)
}

// =========================================================
// Mnemónico de 25 palabras de Algorand (NO es BIP-39)
// =========================================================

/// Bytes → índices de 11 bits, little-endian por bits (el empaquetado de algosdk).
fn to_u11_le(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len() * 8 / 11 + 1);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buf |= (b as u32) << bits;
        bits += 8;
        while bits >= 11 {
            out.push((buf & 0x7ff) as u16);
            buf >>= 11;
            bits -= 11;
        }
    }
    if bits > 0 {
        out.push((buf & 0x7ff) as u16);
    }
    out
}

/// Índices de 11 bits → bytes, inverso exacto de `to_u11_le` (algosdk `_to_key`).
fn u11_le_to_bytes(nums: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nums.len() * 11 / 8 + 1);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &n in nums {
        buf |= (n as u32) << bits;
        bits += 11;
        while bits >= 8 {
            out.push((buf & 0xff) as u8);
            buf >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        out.push((buf & 0xff) as u8);
    }
    out
}

/// Palabra de checksum: los primeros 11 bits (LE) de sha512_256(key)[0..2].
fn algorand_checksum_word(key: &[u8]) -> u16 {
    let h = Sha512_256::digest(key);
    to_u11_le(&h[..2])[0]
}

fn algorand_mnemonic(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "algorand_mnemonic";
    let (kname, mut key) = key_material(arg(args, 0, F)?, F)?;
    if let Err(e) = gate_wallet(caps, &kname, "mnemonic", loc) {
        key.zeroize();
        return Err(e);
    }
    if key.len() != 32 {
        let n = key.len();
        key.zeroize();
        return Err(err(format!(
            "{}: the key must be the 32-byte ed25519 private key seed, got {} bytes",
            F, n
        )));
    }
    let words = Language::English.word_list();
    let mut indices = to_u11_le(&key); // 24 palabras (256 bits → 24×11)
    indices.push(algorand_checksum_word(&key));
    key.zeroize();
    let phrase = indices
        .iter()
        .map(|&i| words[i as usize])
        .collect::<Vec<_>>()
        .join(" ");
    indices.zeroize();
    Ok(syn_secret(format!("{}.mnemonic", kname), phrase))
}

fn algorand_mnemonic_to_key(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "algorand_mnemonic_to_key";
    let (mname, mut phrase) = text_secret_material(arg(args, 0, F)?, F, "the mnemonic")?;
    let label = match opt_label(args.get(1), F, &format!("{}.key", mname)) {
        Ok(l) => l,
        Err(e) => {
            phrase.zeroize();
            return Err(e);
        }
    };
    if let Err(e) = gate_wallet(caps, &mname, "from_mnemonic", loc) {
        phrase.zeroize();
        return Err(e);
    }
    let result = (|| {
        let word_vec: Vec<&str> = phrase.split_whitespace().collect();
        if word_vec.len() != 25 {
            return Err(err(format!(
                "{}: an Algorand mnemonic has exactly 25 words, got {} (it is NOT a BIP-39 phrase)",
                F,
                word_vec.len()
            )));
        }
        let mut indices = Vec::with_capacity(25);
        for (i, w) in word_vec.iter().enumerate() {
            match Language::English.find_word(&w.to_lowercase()) {
                Some(idx) => indices.push(idx),
                None => {
                    return Err(err(format!(
                        "{}: word {} is not in the word list. The mnemonic value is never shown.",
                        F,
                        i + 1
                    )))
                }
            }
        }
        let checksum_word = indices.pop().expect("25 palabras");
        let mut raw = u11_le_to_bytes(&indices); // 24×11 = 264 bits → 33 bytes
        indices.zeroize();
        if raw.len() != 33 || raw[32] != 0 {
            raw.zeroize();
            return Err(err(format!(
                "{}: the mnemonic does not decode to a 32-byte key (corrupted phrase)",
                F
            )));
        }
        raw.truncate(32);
        // Checksum en comparación constant-time (misma higiene que verify_hmac).
        let want = algorand_checksum_word(&raw).to_le_bytes();
        if !constant_time_eq(&want, &checksum_word.to_le_bytes()) {
            raw.zeroize();
            return Err(err(format!(
                "{}: the checksum word does not verify (a mistyped or reordered word). \
                 The mnemonic value is never shown.",
                F
            )));
        }
        Ok(raw)
    })();
    phrase.zeroize();
    let mut key = result?;
    let out = syn_secret_bytes(label, key.to_vec());
    key.zeroize();
    Ok(out)
}

// =========================================================
// Keystore V3 de Ethereum (alcance C)
// =========================================================

/// Cotas anti-DoS de los parámetros KDF de un keystore ENTRANTE (no confiable):
/// un JSON hostil con `n` gigante colgaría/OOMearía al agente (G18 aplicado a
/// trabajo, no sólo a profundidad). Los defaults de Geth (n=262144, r=8, p=1)
/// entran holgados.
const SCRYPT_MAX_NR: u64 = 1 << 23; // memoria = 128·n·r ≤ 1 GiB
const SCRYPT_MAX_P: u64 = 16;
const PBKDF2_MAX_C: u64 = 20_000_000;

fn json_u64(v: Option<&serde_json::Value>, what: &str, fname: &str) -> Result<u64, Control> {
    v.and_then(|x| x.as_u64())
        .ok_or_else(|| err(format!("{}: the keystore is missing a numeric {:?}", fname, what)))
}

fn json_hex(v: Option<&serde_json::Value>, what: &str, fname: &str) -> Result<Vec<u8>, Control> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| err(format!("{}: the keystore is missing {:?}", fname, what)))?;
    synsema_core::bytesutil::hex_decode(s.trim_start_matches("0x"))
        .map_err(|_| err(format!("{}: the keystore field {:?} is not valid hex", fname, what)))
}

/// Deriva la KEK del keystore según su bloque `kdf`/`kdfparams`. Valida cotas
/// anti-DoS y `dklen == 32` (el V3 estándar; el MAC usa dk[16..32]).
fn keystore_kdf(
    crypto: &serde_json::Value,
    passphrase: &[u8],
    fname: &str,
) -> Result<[u8; 32], Control> {
    let kdf = crypto
        .get("kdf")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(format!("{}: the keystore is missing \"kdf\"", fname)))?;
    let params = crypto
        .get("kdfparams")
        .ok_or_else(|| err(format!("{}: the keystore is missing \"kdfparams\"", fname)))?;
    let dklen = json_u64(params.get("dklen"), "dklen", fname)?;
    if dklen != 32 {
        return Err(err(format!(
            "{}: unsupported dklen {} (the V3 standard uses 32)",
            fname, dklen
        )));
    }
    let salt = json_hex(params.get("salt"), "salt", fname)?;
    let mut dk = [0u8; 32];
    match kdf {
        "scrypt" => {
            let n = json_u64(params.get("n"), "n", fname)?;
            let r = json_u64(params.get("r"), "r", fname)?;
            let p = json_u64(params.get("p"), "p", fname)?;
            if n < 2 || !n.is_power_of_two() {
                return Err(err(format!(
                    "{}: scrypt n must be a power of two >= 2, got {}",
                    fname, n
                )));
            }
            if r == 0 || p == 0 || n.saturating_mul(r) > SCRYPT_MAX_NR || p > SCRYPT_MAX_P {
                return Err(err(format!(
                    "{}: scrypt parameters out of the accepted range (n*r <= {}, 0 < p <= {}) — \
                     refusing a keystore that would exhaust memory/CPU",
                    fname, SCRYPT_MAX_NR, SCRYPT_MAX_P
                )));
            }
            let log_n = n.trailing_zeros() as u8;
            let sp = scrypt::Params::new(log_n, r as u32, p as u32, 32)
                .map_err(|_| err(format!("{}: invalid scrypt parameters", fname)))?;
            scrypt::scrypt(passphrase, &salt, &sp, &mut dk)
                .map_err(|_| err(format!("{}: scrypt failed", fname)))?;
        }
        "pbkdf2" => {
            let c = json_u64(params.get("c"), "c", fname)?;
            if c == 0 || c > PBKDF2_MAX_C {
                return Err(err(format!(
                    "{}: pbkdf2 iteration count out of the accepted range (0 < c <= {})",
                    fname, PBKDF2_MAX_C
                )));
            }
            let prf = params.get("prf").and_then(|v| v.as_str()).unwrap_or("hmac-sha256");
            if prf != "hmac-sha256" {
                return Err(err(format!(
                    "{}: unsupported pbkdf2 prf {:?} (only hmac-sha256)",
                    fname, prf
                )));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, c as u32, &mut dk);
        }
        other => {
            return Err(err(format!(
                "{}: unsupported kdf {:?} (only scrypt and pbkdf2)",
                fname, other
            )))
        }
    }
    Ok(dk)
}

fn keystore_import(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "keystore_import";
    let json_s = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the keystore must be its JSON text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let (_pname, mut passphrase) = text_secret_material(arg(args, 1, F)?, F, "the passphrase")?;
    // IIFE: TODO camino (gate denegado, JSON/campos inválidos, KDF) pasa por el
    // zeroize de la passphrase de abajo — jamás queda viva en un early-return.
    let parsed = (|| {
        let label = opt_label(args.get(2), F, "keystore")?;
        gate_wallet(caps, &label, "keystore_import", loc)?;

        let doc: serde_json::Value = serde_json::from_str(&json_s)
            .map_err(|e| err(format!("{}: the keystore is not valid JSON: {}", F, e)))?;
        if doc.get("version").and_then(|v| v.as_u64()) != Some(3) {
            return Err(err(format!(
                "{}: only keystore version 3 is supported (Geth/MyEtherWallet V3)",
                F
            )));
        }
        // Geth escribe "crypto"; algunos wallets viejos "Crypto".
        let crypto = doc
            .get("crypto")
            .or_else(|| doc.get("Crypto"))
            .ok_or_else(|| err(format!("{}: the keystore is missing \"crypto\"", F)))?;
        let cipher = crypto.get("cipher").and_then(|v| v.as_str()).unwrap_or("");
        if cipher != "aes-128-ctr" {
            return Err(err(format!(
                "{}: unsupported cipher {:?} (only aes-128-ctr)",
                F, cipher
            )));
        }
        let ciphertext = json_hex(crypto.get("ciphertext"), "ciphertext", F)?;
        let iv = json_hex(
            crypto.get("cipherparams").and_then(|p| p.get("iv")),
            "cipherparams.iv",
            F,
        )?;
        if iv.len() != 16 {
            return Err(err(format!(
                "{}: the AES-CTR iv must be 16 bytes, got {}",
                F,
                iv.len()
            )));
        }
        let mac = json_hex(crypto.get("mac"), "mac", F)?;
        let dk = keystore_kdf(crypto, passphrase.as_bytes(), F)?;
        Ok((label, dk, ciphertext, iv, mac))
    })();
    passphrase.zeroize();
    let (label, mut dk, ciphertext, iv, mac) = parsed?;
    // MAC = keccak256(dk[16..32] ‖ ciphertext), comparado constant-time. Un MAC
    // inválido = passphrase incorrecta O keystore corrupto — SIN producir material.
    let mut h = Keccak256::new();
    h.update(&dk[16..32]);
    h.update(&ciphertext);
    let want = h.finalize();
    if !constant_time_eq(&want, &mac) {
        dk.zeroize();
        return Err(err(format!(
            "{}: wrong passphrase (or corrupted keystore) — the MAC does not verify. \
             No key material was produced.",
            F
        )));
    }
    let mut key = ciphertext.clone();
    let mut cipher = Aes128Ctr::new_from_slices(&dk[..16], &iv)
        .expect("key de 16 y iv de 16, validados arriba");
    cipher.apply_keystream(&mut key);
    dk.zeroize();
    if key.len() != 32 {
        let n = key.len();
        key.zeroize();
        return Err(err(format!(
            "{}: the keystore does not hold a 32-byte private key (got {} bytes)",
            F, n
        )));
    }
    let out = syn_secret_bytes(label, key.to_vec());
    key.zeroize();
    Ok(out)
}

/// UUID v4 formateado desde 16 bytes aleatorios (sin dep nueva: la forma es sólo
/// hex con guiones + bits de versión/variante).
fn uuid_v4(bytes: &mut [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = synsema_core::bytesutil::hex_encode(bytes);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn keystore_export(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "keystore_export";
    let (kname, mut key) = key_material(arg(args, 0, F)?, F)?;
    // La passphrase vive FUERA del closure: todo camino (opts inválidas, gate
    // denegado, clave inválida, KDF) pasa por el zeroize de abajo.
    let mut passphrase = match arg(args, 1, F).and_then(|v| {
        text_secret_material(v, F, "the passphrase").map(|(_, p)| p)
    }) {
        Ok(p) => p,
        Err(e) => {
            key.zeroize();
            return Err(e);
        }
    };
    let result = (|| {
        let opts = match args.get(2) {
            None | Some(SynValue::Nothing) => indexmap::IndexMap::new(),
            Some(SynValue::Map(m)) => m.borrow().clone(),
            Some(other) => {
                return Err(err(format!(
                    "{}: opts must be a map, got {}",
                    F,
                    other.type_name()
                )))
            }
        };
        for k in opts.keys() {
            if !matches!(k.as_str(), "kdf" | "n" | "r" | "p" | "c") {
                return Err(err(format!(
                    "{}: unknown option {:?} (allowed: kdf, n, r, p, c)",
                    F, k
                )));
            }
        }
        let get_int = |key: &str, default: u64| -> Result<u64, Control> {
            match opts.get(key) {
                None | Some(SynValue::Nothing) => Ok(default),
                Some(SynValue::Number(n)) => n.to_i64_trunc().filter(|v| *v > 0).map(|v| v as u64).ok_or_else(|| {
                    err(format!("{}: option {:?} must be a positive integer", F, key))
                }),
                Some(other) => Err(err(format!(
                    "{}: option {:?} must be a number, got {}",
                    F,
                    key,
                    other.type_name()
                ))),
            }
        };
        let kdf = match opts.get("kdf") {
            None | Some(SynValue::Nothing) => "scrypt".to_string(),
            Some(SynValue::Text(s)) => s.to_string(),
            Some(other) => {
                return Err(err(format!(
                    "{}: option \"kdf\" must be \"scrypt\" or \"pbkdf2\", got {}",
                    F,
                    other.type_name()
                )))
            }
        };
        gate_wallet(caps, &kname, "keystore_export", loc)?;
        if key.len() != 32 {
            return Err(err(format!(
                "{}: the key must be a 32-byte private key, got {} bytes",
                F,
                key.len()
            )));
        }
        // Dirección (pública) para el campo `address` — la convención V3 de Geth
        // (hex minúscula sin 0x).
        let signing = k256::ecdsa::SigningKey::from_slice(&key).map_err(|_| {
            err(format!(
                "{}: the key is not a valid secp256k1 scalar (the key value is never shown)",
                F
            ))
        })?;
        let uncompressed = signing.verifying_key().to_encoded_point(false);
        let addr20 = &Keccak256::digest(&uncompressed.as_bytes()[1..])[12..];

        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut idb = [0u8; 16];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::try_fill_bytes(&mut rng, &mut salt)
            .and_then(|_| rand::RngCore::try_fill_bytes(&mut rng, &mut iv))
            .and_then(|_| rand::RngCore::try_fill_bytes(&mut rng, &mut idb))
            .map_err(|_| err(format!("{}: the OS random source is unavailable", F)))?;

        let mut dk = [0u8; 32];
        let kdfparams = match kdf.as_str() {
            "scrypt" => {
                let n = get_int("n", 262_144)?; // el default de Geth (2^18)
                let r = get_int("r", 8)?;
                let p = get_int("p", 1)?;
                if n < 2 || !n.is_power_of_two() {
                    return Err(err(format!(
                        "{}: scrypt n must be a power of two >= 2, got {}",
                        F, n
                    )));
                }
                if n.saturating_mul(r) > SCRYPT_MAX_NR || p > SCRYPT_MAX_P {
                    return Err(err(format!(
                        "{}: scrypt parameters out of the accepted range (n*r <= {}, p <= {})",
                        F, SCRYPT_MAX_NR, SCRYPT_MAX_P
                    )));
                }
                let sp = scrypt::Params::new(n.trailing_zeros() as u8, r as u32, p as u32, 32)
                    .map_err(|_| err(format!("{}: invalid scrypt parameters", F)))?;
                scrypt::scrypt(passphrase.as_bytes(), &salt, &sp, &mut dk)
                    .map_err(|_| err(format!("{}: scrypt failed", F)))?;
                serde_json::json!({
                    "dklen": 32, "n": n, "r": r, "p": p,
                    "salt": synsema_core::bytesutil::hex_encode(&salt),
                })
            }
            "pbkdf2" => {
                let c = get_int("c", 262_144)?;
                if c > PBKDF2_MAX_C {
                    return Err(err(format!(
                        "{}: pbkdf2 iteration count out of the accepted range (c <= {})",
                        F, PBKDF2_MAX_C
                    )));
                }
                pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, c as u32, &mut dk);
                serde_json::json!({
                    "dklen": 32, "c": c, "prf": "hmac-sha256",
                    "salt": synsema_core::bytesutil::hex_encode(&salt),
                })
            }
            other => {
                return Err(err(format!(
                    "{}: unknown kdf {:?}; use \"scrypt\" (default) or \"pbkdf2\"",
                    F, other
                )))
            }
        };
        let mut ciphertext = key.clone();
        let mut cipher = Aes128Ctr::new_from_slices(&dk[..16], &iv)
            .expect("key de 16 y iv de 16 por construcción");
        cipher.apply_keystream(&mut ciphertext);
        let mut h = Keccak256::new();
        h.update(&dk[16..32]);
        h.update(&ciphertext);
        let mac = h.finalize();
        dk.zeroize();
        let doc = serde_json::json!({
            "version": 3,
            "id": uuid_v4(&mut idb),
            "address": synsema_core::bytesutil::hex_encode(addr20),
            "crypto": {
                "ciphertext": synsema_core::bytesutil::hex_encode(&ciphertext),
                "cipherparams": { "iv": synsema_core::bytesutil::hex_encode(&iv) },
                "cipher": "aes-128-ctr",
                "kdf": kdf,
                "kdfparams": kdfparams,
                "mac": synsema_core::bytesutil::hex_encode(&mac),
            },
        });
        Ok(syn_text(doc.to_string()))
    })();
    passphrase.zeroize();
    key.zeroize();
    result
}

// =========================================================
// Registro
// =========================================================

/// Registra los builtins de custodia (TODOS gateados por `wallet` + audit, G20;
/// TODOS devuelven `secret`, G19). Wired desde `register_blockchain_builtins`.
pub(crate) fn register(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    macro_rules! gated {
        ($name:literal, $f:ident) => {{
            let caps = caps.clone();
            interp.register_builtin($name, -1, Rc::new(move |_i, a, l| $f(a, l, &caps)));
        }};
    }
    gated!("mnemonic_generate", mnemonic_generate);
    gated!("mnemonic_to_seed", mnemonic_to_seed);
    gated!("mnemonic_from_entropy", mnemonic_from_entropy);
    gated!("mnemonic_to_entropy", mnemonic_to_entropy);
    gated!("hd_derive", hd_derive);
    gated!("algorand_mnemonic", algorand_mnemonic);
    gated!("algorand_mnemonic_to_key", algorand_mnemonic_to_key);
    gated!("keystore_import", keystore_import);
    gated!("keystore_export", keystore_export);
}
