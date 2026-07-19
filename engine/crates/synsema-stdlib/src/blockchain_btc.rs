//! Bitcoin (Batch 16) — la matriz UTXO: direcciones/scripts/txid, firma Schnorr
//! BIP-340 (taproot), el builder `btc_tx`/`btc_tx_raw` y PSBT (BIP-174). El agente
//! LEE (blockchain_btc_rpc), CONSTRUYE (acá, puro), FIRMA (gate `sign`) y DIFUNDE —
//! o PREPARA un PSBT para que un humano firme en su hardware wallet (custodia fría).
//!
//! Doctrina (spec batch-16 §9, hereda G1–G27):
//! - **G28 — cada satoshi contabilizado.** En UTXO el fee es IMPLÍCITO
//!   (inputs − outputs): olvidar el vuelto DONA el remanente a los mineros (pasó
//!   con cientos de BTC reales). Acá el fee se DECLARA y el invariante
//!   `sum(inputs) == sum(outputs) + fee` se verifica; si no cierra, el error
//!   nombra la diferencia exacta. Dust y fee-absurdo tienen guardas explícitas
//!   (override opt-in, jamás silencioso). El builder ecoa fee y amounts ANTES de
//!   firmar (para el `confirm`).
//! - **G29 — matriz de direcciones estricta.** Decode con checksum + la variante
//!   bech32/bech32m CORRECTA (BIP-350: v0⇒bech32, v1⇒bech32m; la cruzada se
//!   rechaza), longitudes exactas, red identificada; una dirección de otra red en
//!   una tx → error que nombra las DOS redes. Amounts SIEMPRE sats enteros
//!   exactos (float → error dirigido con la conversión).
//! - **G30 — sin puertas nuevas.** `schnorr_sign` usa la MISMA capability `sign`
//!   (+ audit) que secp256k1/ed25519; `wif_import` usa `wallet`; el read-side usa
//!   `net(host)`. PSBT es puro. `sign` sigue siendo la única puerta que autoriza
//!   gastar.
//! - **Sighash acotado:** SIGHASH_ALL para P2WPKH (BIP-143) y SIGHASH_DEFAULT
//!   para P2TR key-path (BIP-341) — los defaults universales de las wallets.
//!   NONE/SINGLE/ANYONECANPAY → error dirigido (footguns de nicho, fuera de
//!   alcance). Se gasta DESDE P2WPKH y P2TR key-path; se envía HACIA cualquier
//!   tipo estándar (P2PKH/P2SH/P2WPKH/P2WSH/P2TR).
//! - **Determinismo:** ECDSA con RFC 6979 (k256); Schnorr BIP-340 con aux-rand
//!   FIJO en 32 bytes cero — la misma (clave, digest) produce la misma firma, y
//!   coincide byte a byte con los vectores oficiales de BIP-340/341 (que usan
//!   aux = 0). El tweak de taproot (BIP-341 key-path, merkle vacío) vive DENTRO
//!   de `btc_address`/`schnorr_sign(…, "taproot")` — el usuario jamás tweakea.

use std::cell::RefCell;
use std::rc::Rc;

use bech32::{segwit, Hrp};
use indexmap::IndexMap;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as EcSignature, SigningKey as EcSigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::schnorr;
use k256::{ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use synsema_capabilities::model::CapabilitySet;
use synsema_core::bytesutil::{b64_decode, b64_encode, base58_decode, base58_encode, hex_decode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::number::Number;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{
    syn_bool, syn_bytes, syn_int, syn_list, syn_map, syn_number, syn_secret_bytes, syn_text,
    SynValue,
};

use crate::blockchain::{arg, arg_bytes, arg_bytes_len, err, gate_and_audit, key_material};
use crate::blockchain_hd::{gate_wallet, opt_label};

/// Techo de sats de CUALQUIER amount: los 21 M de BTC. Más = basura u hostil.
/// `pub(crate)`: blockchain_btc_rpc.rs valida con el mismo techo lo que el nodo dice.
pub(crate) const MAX_SATS: i64 = 2_100_000_000_000_000;
/// Techo anti-DoS de una tx / un PSBT entrante (el peso máximo de un bloque).
const MAX_TX_BYTES: usize = 4_000_000;
/// n/2 de secp256k1 — una firma ECDSA con s por encima es malleada/no estándar.
const SECP_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
    0x20, 0xa0,
];

// =========================================================
// Hashes (hash160, dSHA256) y base58check
// =========================================================

pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// SHA-256 con tag BIP-340 (`sha256(sha256(tag) ‖ sha256(tag) ‖ data…)`).
fn tagged_hasher(tag: &str) -> Sha256 {
    let th = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(th);
    h.update(th);
    h
}

/// base58check: base58(payload ‖ dSHA256(payload)[..4]).
fn base58check_encode(payload: &[u8]) -> String {
    let check = dsha256(payload);
    let mut full = Vec::with_capacity(payload.len() + 4);
    full.extend_from_slice(payload);
    full.extend_from_slice(&check[..4]);
    base58_encode(&full)
}

/// Decode ESTRICTO de base58check. El error jamás ecoa el string (puede ser una
/// clave WIF — G4); describe la causa.
fn base58check_decode(s: &str) -> Result<Vec<u8>, String> {
    let full = base58_decode(s).map_err(|_| "not valid base58".to_string())?;
    if full.len() < 5 {
        return Err("too short for base58check (needs payload + 4 checksum bytes)".to_string());
    }
    let (payload, check) = full.split_at(full.len() - 4);
    let want = dsha256(payload);
    if want[..4] != *check {
        return Err("the checksum does not verify (a mistyped character?)".to_string());
    }
    Ok(payload.to_vec())
}

// =========================================================
// Redes y tipos de dirección (G29)
// =========================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    fn parse(v: Option<&SynValue>, fname: &str) -> Result<Network, Control> {
        match v {
            None | Some(SynValue::Nothing) => Ok(Network::Mainnet),
            Some(SynValue::Text(s)) => match s.to_string().as_str() {
                "mainnet" => Ok(Network::Mainnet),
                "testnet" => Ok(Network::Testnet),
                "signet" => Ok(Network::Signet),
                "regtest" => Ok(Network::Regtest),
                other => Err(err(format!(
                    "{}: unknown network {:?}; use \"mainnet\", \"testnet\", \"signet\" or \"regtest\"",
                    fname, other
                ))),
            },
            Some(other) => Err(err(format!(
                "{}: the network must be text, got {}",
                fname,
                other.type_name()
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// HRP bech32 (BIP-173): signet COMPARTE `tb` con testnet.
    fn hrp(self) -> Hrp {
        let s = match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Signet => "tb",
            Network::Regtest => "bcrt",
        };
        Hrp::parse(s).expect("hrp estático válido")
    }

    fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            _ => 0x6f, // testnet/signet/regtest comparten versiones base58
        }
    }

    fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            _ => 0xc4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AddrKind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
}

impl AddrKind {
    fn as_str(self) -> &'static str {
        match self {
            AddrKind::P2pkh => "p2pkh",
            AddrKind::P2sh => "p2sh",
            AddrKind::P2wpkh => "p2wpkh",
            AddrKind::P2wsh => "p2wsh",
            AddrKind::P2tr => "p2tr",
        }
    }

    /// Dust limit estándar por tipo de OUTPUT (la política de Core: un output que
    /// cuesta más gastarlo de lo que vale). 546/540 para legacy, 294/330 segwit.
    fn dust_limit(self) -> u64 {
        match self {
            AddrKind::P2pkh => 546,
            AddrKind::P2sh => 540,
            AddrKind::P2wpkh => 294,
            AddrKind::P2wsh | AddrKind::P2tr => 330,
        }
    }
}

/// Una dirección decodificada ESTRICTAMENTE (G29). `net_label` es la red que la
/// codificación DECLARA: bech32 distingue mainnet/testnet(=signet)/regtest;
/// base58 sólo mainnet/testnet-family (regtest comparte las versiones de testnet).
pub(crate) struct DecodedAddr {
    pub(crate) kind: AddrKind,
    pub(crate) program: Vec<u8>,
    pub(crate) net_label: &'static str,
    pub(crate) base58: bool,
}

/// Decodifica una dirección de Bitcoin, checksum y variante BIP-350 verificados.
/// Decode laxo = fondos quemados: todo error acá es definitivo y descriptivo.
pub(crate) fn decode_address(s: &str, fname: &str) -> Result<DecodedAddr, Control> {
    let lower = s.to_lowercase();
    let looks_bech32 = ["bc1", "tb1", "bcrt1"].iter().any(|p| lower.starts_with(p));
    if looks_bech32 {
        let (hrp, version, program) = segwit::decode(s).map_err(|e| {
            err(format!(
                "{}: invalid segwit address: {} (BIP-350: witness v0 uses bech32, v1+ uses bech32m — the wrong checksum variant is rejected). The address was not accepted.",
                fname, e
            ))
        })?;
        let net_label = match hrp.to_lowercase().as_str() {
            "bc" => "mainnet",
            "tb" => "testnet",
            "bcrt" => "regtest",
            other => {
                return Err(err(format!(
                    "{}: unknown address prefix {:?} (expected bc, tb or bcrt)",
                    fname, other
                )))
            }
        };
        let v = version.to_u8();
        let kind = match (v, program.len()) {
            (0, 20) => AddrKind::P2wpkh,
            (0, 32) => AddrKind::P2wsh,
            (0, n) => {
                return Err(err(format!(
                    "{}: a witness v0 program must be 20 or 32 bytes (BIP-141), got {}",
                    fname, n
                )))
            }
            (1, 32) => AddrKind::P2tr,
            (1, n) => {
                return Err(err(format!(
                    "{}: a witness v1 (taproot) program must be 32 bytes, got {}",
                    fname, n
                )))
            }
            (v, _) => {
                return Err(err(format!(
                    "{}: witness version {} is not a standard address type yet — refusing to build an output no wallet can spend",
                    fname, v
                )))
            }
        };
        return Ok(DecodedAddr { kind, program, net_label, base58: false });
    }
    // base58check (P2PKH / P2SH)
    let payload = base58check_decode(s).map_err(|e| {
        err(format!("{}: invalid base58 address: {}", fname, e))
    })?;
    if payload.len() != 21 {
        return Err(err(format!(
            "{}: a base58 address payload must be 21 bytes (version + hash160), got {}",
            fname,
            payload.len()
        )));
    }
    let (kind, net_label) = match payload[0] {
        0x00 => (AddrKind::P2pkh, "mainnet"),
        0x05 => (AddrKind::P2sh, "mainnet"),
        0x6f => (AddrKind::P2pkh, "testnet"),
        0xc4 => (AddrKind::P2sh, "testnet"),
        v => {
            return Err(err(format!(
                "{}: unknown base58 address version 0x{:02x} (not a standard Bitcoin address)",
                fname, v
            )))
        }
    };
    Ok(DecodedAddr { kind, program: payload[1..].to_vec(), net_label, base58: true })
}

/// Cross-check estructural de red (G29): una dirección de testnet en una tx de
/// mainnet → error que nombra las DOS redes. Base58 no distingue
/// testnet/signet/regtest (comparten versiones), bech32 sí (tb vs bcrt).
fn check_network(dec: &DecodedAddr, tx_net: Network, what: &str, fname: &str) -> Result<(), Control> {
    let ok = match tx_net {
        Network::Mainnet => dec.net_label == "mainnet",
        Network::Testnet | Network::Signet => dec.net_label == "testnet",
        Network::Regtest => dec.net_label == "regtest" || (dec.base58 && dec.net_label == "testnet"),
    };
    if !ok {
        return Err(err(format!(
            "{}: {} is a {} address but the transaction is for {} — a cross-network send burns funds; nothing was built",
            fname,
            what,
            dec.net_label,
            tx_net.as_str()
        )));
    }
    Ok(())
}

/// scriptPubKey de un (kind, program) estándar.
pub(crate) fn script_pubkey_of(kind: AddrKind, program: &[u8]) -> Vec<u8> {
    match kind {
        AddrKind::P2pkh => {
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(program);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        AddrKind::P2sh => {
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(program);
            s.push(0x87);
            s
        }
        AddrKind::P2wpkh | AddrKind::P2wsh => {
            let mut s = Vec::with_capacity(2 + program.len());
            s.push(0x00);
            s.push(program.len() as u8);
            s.extend_from_slice(program);
            s
        }
        AddrKind::P2tr => {
            let mut s = Vec::with_capacity(34);
            s.push(0x51);
            s.push(0x20);
            s.extend_from_slice(program);
            s
        }
    }
}

// =========================================================
// Taproot: tweak BIP-341 de key-path (interno — el usuario jamás tweakea)
// =========================================================

/// `t = int(tagged_hash("TapTweak", xonly ‖ merkle?))`, verificado `t < n`
/// (BIP-341: si no, la clave es inválida — probabilidad ~2^-128).
fn tap_tweak_scalar(xonly: &[u8; 32], merkle: Option<&[u8]>, fname: &str) -> Result<Scalar, Control> {
    let mut h = tagged_hasher("TapTweak");
    h.update(xonly);
    if let Some(m) = merkle {
        h.update(m);
    }
    let t = h.finalize();
    Option::<Scalar>::from(Scalar::from_repr(t)).ok_or_else(|| {
        err(format!(
            "{}: the taproot tweak for this key is invalid (an astronomically unlikely key); use a different key",
            fname
        ))
    })
}

/// Clave de SALIDA de taproot: `Q = lift_x(P) + t·G` → (x(Q), paridad). La
/// dirección P2TR codifica la clave TWEAKED, no la interna — el error clásico.
fn tap_output_key(
    xonly: &[u8; 32],
    merkle: Option<&[u8]>,
    fname: &str,
) -> Result<([u8; 32], bool), Control> {
    let vk = schnorr::VerifyingKey::from_bytes(xonly).map_err(|_| {
        err(format!(
            "{}: the 32-byte x-only public key is not a valid secp256k1 x coordinate",
            fname
        ))
    })?;
    let t = tap_tweak_scalar(xonly, merkle, fname)?;
    let q = (ProjectivePoint::from(*vk.as_affine()) + ProjectivePoint::GENERATOR * t).to_affine();
    let enc = q.to_encoded_point(true);
    let bytes = enc.as_bytes();
    if bytes.len() != 33 {
        // Punto en el infinito: t == -int(P)·… — imposible salvo clave hostil.
        return Err(err(format!(
            "{}: the tweaked taproot key is the point at infinity (invalid key)",
            fname
        )));
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[1..]);
    Ok((x, bytes[0] == 0x03))
}

/// Escalar tweakeado de BIP-341: `d_even + t` (la interna normalizada a Y par,
/// más el tweak) — el `tweakedPrivkey` de los vectores oficiales, sin la
/// re-normalización de salida (esa la hace BIP-340 al firmar).
fn tap_tweaked_scalar(key: &[u8], merkle: Option<&[u8]>, fname: &str) -> Result<Scalar, Control> {
    let sk = schnorr::SigningKey::from_bytes(key).map_err(|_| {
        err(format!(
            "{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)",
            fname
        ))
    })?;
    let xonly: [u8; 32] = sk.verifying_key().to_bytes().into();
    let t = tap_tweak_scalar(&xonly, merkle, fname)?;
    let d: Scalar = *sk.as_nonzero_scalar().as_ref();
    Ok(d + t)
}

/// SigningKey de BIP-340 para el gasto key-path: el escalar tweakeado, con la
/// re-normalización de paridad de salida a cargo de k256 — exactamente el
/// algoritmo de firma de BIP-341.
fn tap_tweaked_signing_key(
    key: &[u8],
    merkle: Option<&[u8]>,
    fname: &str,
) -> Result<schnorr::SigningKey, Control> {
    let d2 = tap_tweaked_scalar(key, merkle, fname)?;
    let mut d2_bytes = d2.to_bytes();
    let out = schnorr::SigningKey::from_bytes(&d2_bytes).map_err(|_| {
        err(format!(
            "{}: the tweaked taproot key is zero (an astronomically unlikely key)",
            fname
        ))
    });
    d2_bytes.zeroize();
    out
}

// =========================================================
// Schnorr BIP-340 (misma puerta `sign` — G30)
// =========================================================

/// aux-rand FIJO (32 bytes cero): determinista (G5) y byte-exacto contra los
/// vectores oficiales de BIP-340/341, que usan aux = 0.
const SCHNORR_AUX: [u8; 32] = [0u8; 32];

fn schnorr_mode(v: Option<&SynValue>, fname: &str) -> Result<bool, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Text(s)) if s.to_string() == "taproot" => Ok(true),
        Some(SynValue::Text(s)) => Err(err(format!(
            "{}: unknown mode {:?}; omit it for plain BIP-340 or use \"taproot\" for a key-path spend (applies the BIP-341 tweak internally)",
            fname,
            s.to_string()
        ))),
        Some(other) => Err(err(format!(
            "{}: the mode must be text, got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn schnorr_sign(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "schnorr_sign";
    let digest = arg_bytes_len(arg(args, 0, F)?, F, "the digest", 32)?.to_vec();
    let (name, mut key) = key_material(arg(args, 1, F)?, F)?;
    let taproot = match schnorr_mode(args.get(2), F) {
        Ok(t) => t,
        Err(e) => {
            key.zeroize();
            return Err(e);
        }
    };
    let curve = if taproot { "schnorr(taproot)" } else { "schnorr" };
    if let Err(e) = gate_and_audit(caps, &name, curve, loc) {
        key.zeroize();
        return Err(e);
    }
    let sk = if taproot {
        tap_tweaked_signing_key(&key, None, F)
    } else {
        schnorr::SigningKey::from_bytes(&key).map_err(|_| {
            err(format!(
                "{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)",
                F
            ))
        })
    };
    key.zeroize();
    let sig = sk?
        .sign_raw(&digest, &SCHNORR_AUX)
        .map_err(|_| err(format!("{}: failed to sign the digest", F)))?;
    Ok(syn_bytes(sig.to_bytes().to_vec())) // 64 bytes
}

fn schnorr_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "schnorr_verify";
    let digest = arg_bytes_len(arg(args, 0, F)?, F, "the digest", 32)?;
    let sig = arg_bytes_len(arg(args, 1, F)?, F, "the signature", 64)?;
    let pubkey = arg_bytes_len(arg(args, 2, F)?, F, "the x-only public key", 32)?;
    let vk = match schnorr::VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return Ok(syn_bool(false)), // x fuera de la curva: no verifica
    };
    let sig = match schnorr::Signature::try_from(sig) {
        Ok(s) => s,
        Err(_) => return Ok(syn_bool(false)), // r/s fuera de rango: no verifica
    };
    Ok(syn_bool(vk.verify_prehash(digest, &sig).is_ok()))
}

fn schnorr_pubkey(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "schnorr_pubkey";
    let (_name, mut key) = key_material(arg(args, 0, F)?, F)?;
    let sk = schnorr::SigningKey::from_bytes(&key);
    key.zeroize();
    let sk = sk.map_err(|_| {
        err(format!(
            "{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)",
            F
        ))
    })?;
    Ok(syn_bytes(sk.verifying_key().to_bytes().to_vec())) // 32 bytes x-only
}

// =========================================================
// Direcciones y scripts (Alcance A)
// =========================================================

/// Pubkey COMPRIMIDA (33) desde un `secret` o bytes. Una pubkey sin comprimir es
/// otra dirección (hash distinto) y en segwit es no-estándar → error dirigido.
fn compressed_pubkey(v: &SynValue, fname: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Secret(_) => {
            let (_name, mut key) = key_material(v, fname)?;
            let signing = EcSigningKey::from_slice(&key);
            key.zeroize();
            let signing = signing.map_err(|_| {
                err(format!(
                    "{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)",
                    fname
                ))
            })?;
            Ok(signing.verifying_key().to_encoded_point(true).as_bytes().to_vec())
        }
        SynValue::Bytes(b) => match b.len() {
            33 => {
                VerifyingKey::from_sec1_bytes(b).map_err(|_| {
                    err(format!("{}: the public key is not a valid secp256k1 point", fname))
                })?;
                Ok(b[..].to_vec())
            }
            65 => Err(err(format!(
                "{}: got an uncompressed (65-byte) public key — Bitcoin segwit addresses require the compressed 33-byte form (an uncompressed key hashes to a DIFFERENT address)",
                fname
            ))),
            n => Err(err(format!(
                "{}: the public key must be 33 bytes compressed (or a key secret), got {}",
                fname, n
            ))),
        },
        other => Err(err(format!(
            "{}: expected a public key (bytes) or a key secret, got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// x-only (32) para taproot desde secret / pubkey 33 / x-only 32.
fn xonly_pubkey(v: &SynValue, fname: &str) -> Result<[u8; 32], Control> {
    let x: [u8; 32] = match v {
        SynValue::Bytes(b) if b.len() == 32 => b[..].try_into().expect("32 bytes"),
        SynValue::Secret(_) => {
            let (_name, mut key) = key_material(v, fname)?;
            let sk = schnorr::SigningKey::from_bytes(&key);
            key.zeroize();
            let sk = sk.map_err(|_| {
                err(format!(
                    "{}: the private key must be 32 bytes of valid secp256k1 scalar (the key value is never shown)",
                    fname
                ))
            })?;
            sk.verifying_key().to_bytes().into()
        }
        _ => {
            let pk = compressed_pubkey(v, fname)?;
            pk[1..].try_into().expect("32 bytes")
        }
    };
    Ok(x)
}

fn btc_address(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_address";
    let kind = match args.get(1) {
        None | Some(SynValue::Nothing) => "p2wpkh".to_string(),
        Some(SynValue::Text(s)) => s.to_string(),
        Some(other) => {
            return Err(err(format!(
                "{}: the kind must be text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let network = Network::parse(args.get(2), F)?;
    let key = arg(args, 0, F)?;
    let addr = match kind.as_str() {
        "p2wpkh" => {
            let pk = compressed_pubkey(key, F)?;
            segwit::encode_v0(network.hrp(), &hash160(&pk))
                .map_err(|e| err(format!("{}: {}", F, e)))?
        }
        "p2tr" => {
            let x = xonly_pubkey(key, F)?;
            // La dirección codifica la clave TWEAKED (BIP-341 key-path, merkle
            // vacío) — jamás la interna (el error clásico de implementación).
            let (out, _parity) = tap_output_key(&x, None, F)?;
            segwit::encode_v1(network.hrp(), &out)
                .map_err(|e| err(format!("{}: {}", F, e)))?
        }
        "p2pkh" => {
            let pk = compressed_pubkey(key, F)?;
            let mut payload = Vec::with_capacity(21);
            payload.push(network.p2pkh_version());
            payload.extend_from_slice(&hash160(&pk));
            base58check_encode(&payload)
        }
        other => {
            return Err(err(format!(
                "{}: unknown kind {:?}; use \"p2wpkh\" (default), \"p2tr\" or \"p2pkh\"",
                F, other
            )))
        }
    };
    Ok(syn_text(addr))
}

fn btc_address_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_address_decode";
    let s = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the address must be text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let dec = decode_address(&s, F)?;
    let mut m = IndexMap::new();
    m.insert("kind".to_string(), syn_text(dec.kind.as_str()));
    m.insert("network".to_string(), syn_text(dec.net_label));
    m.insert("program".to_string(), syn_bytes(dec.program));
    m.insert(
        "encoding".to_string(),
        syn_text(if dec.base58 {
            "base58check"
        } else if dec.kind == AddrKind::P2tr {
            "bech32m"
        } else {
            "bech32"
        }),
    );
    Ok(syn_map(m))
}

fn btc_script(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_script";
    let s = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the address must be text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let dec = decode_address(&s, F)?;
    Ok(syn_bytes(script_pubkey_of(dec.kind, &dec.program)))
}

// =========================================================
// CompactSize + parser/serializador de transacciones
// =========================================================

fn write_varint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// CompactSize CANÓNICO (money decode): la forma larga para un valor que entra
/// en la corta se RECHAZA — dos byte-strings jamás decodifican igual en silencio.
fn read_varint(data: &[u8], pos: &mut usize, fname: &str) -> Result<u64, Control> {
    let trunc = || err(format!("{}: truncated transaction (unexpected end of input)", fname));
    let b = *data.get(*pos).ok_or_else(trunc)?;
    *pos += 1;
    let (n, min): (u64, u64) = match b {
        0..=0xfc => return Ok(b as u64),
        0xfd => {
            let raw: [u8; 2] = data.get(*pos..*pos + 2).ok_or_else(trunc)?.try_into().unwrap();
            *pos += 2;
            (u16::from_le_bytes(raw) as u64, 0xfd)
        }
        0xfe => {
            let raw: [u8; 4] = data.get(*pos..*pos + 4).ok_or_else(trunc)?.try_into().unwrap();
            *pos += 4;
            (u32::from_le_bytes(raw) as u64, 0x10000)
        }
        _ => {
            let raw: [u8; 8] = data.get(*pos..*pos + 8).ok_or_else(trunc)?.try_into().unwrap();
            *pos += 8;
            (u64::from_le_bytes(raw), 0x1_0000_0000)
        }
    };
    if n < min {
        return Err(err(format!(
            "{}: non-canonical CompactSize encoding (a longer form than the value needs)",
            fname
        )));
    }
    Ok(n)
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, n: usize, fname: &str) -> Result<&'a [u8], Control> {
    let end = pos.checked_add(n).filter(|&e| e <= data.len()).ok_or_else(|| {
        err(format!("{}: truncated transaction (unexpected end of input)", fname))
    })?;
    let out = &data[*pos..end];
    *pos = end;
    Ok(out)
}

fn read_u32le(data: &[u8], pos: &mut usize, fname: &str) -> Result<u32, Control> {
    Ok(u32::from_le_bytes(read_bytes(data, pos, 4, fname)?.try_into().unwrap()))
}

fn read_u64le(data: &[u8], pos: &mut usize, fname: &str) -> Result<u64, Control> {
    Ok(u64::from_le_bytes(read_bytes(data, pos, 8, fname)?.try_into().unwrap()))
}

pub(crate) struct RawInput {
    pub(crate) prev_le: [u8; 32], // txid en orden de WIRE (little-endian del display)
    pub(crate) vout: u32,
    pub(crate) script_sig: Vec<u8>,
    pub(crate) sequence: u32,
    pub(crate) witness: Vec<Vec<u8>>,
}

pub(crate) struct RawOutput {
    pub(crate) amount: u64,
    pub(crate) script: Vec<u8>,
}

pub(crate) struct RawTx {
    pub(crate) version: u32,
    pub(crate) inputs: Vec<RawInput>,
    pub(crate) outputs: Vec<RawOutput>,
    pub(crate) locktime: u32,
}

/// Parser ESTRICTO de una transacción (legacy o segwit). Bounds-checked en cada
/// paso; varints canónicos; trailing bytes → error. Un blob hostil jamás panica.
pub(crate) fn parse_tx(data: &[u8], fname: &str) -> Result<RawTx, Control> {
    if data.len() > MAX_TX_BYTES {
        return Err(err(format!(
            "{}: the transaction is over the {} MB consensus limit — refusing to parse it",
            fname,
            MAX_TX_BYTES / 1_000_000
        )));
    }
    let mut pos = 0usize;
    let version = read_u32le(data, &mut pos, fname)?;
    // Marker segwit: 0x00 0x01 tras la versión (un tx legacy jamás tiene 0
    // inputs, así que el 0x00 es inequívoco).
    let segwit_flag = data.get(pos) == Some(&0x00);
    if segwit_flag {
        if data.get(pos + 1) != Some(&0x01) {
            return Err(err(format!(
                "{}: invalid segwit marker (flag must be 0x01)",
                fname
            )));
        }
        pos += 2;
    }
    let n_in = read_varint(data, &mut pos, fname)?;
    if n_in == 0 {
        return Err(err(format!("{}: the transaction has no inputs", fname)));
    }
    // Cota estructural: cada input pesa al menos 41 bytes — un count hostil
    // gigante no aloca nada antes de fallar por truncamiento.
    if n_in > (data.len() / 41 + 1) as u64 {
        return Err(err(format!("{}: input count exceeds what the data can hold", fname)));
    }
    let mut inputs = Vec::with_capacity(n_in as usize);
    for _ in 0..n_in {
        let prev_le: [u8; 32] = read_bytes(data, &mut pos, 32, fname)?.try_into().unwrap();
        let vout = read_u32le(data, &mut pos, fname)?;
        let slen = read_varint(data, &mut pos, fname)? as usize;
        let script_sig = read_bytes(data, &mut pos, slen, fname)?.to_vec();
        let sequence = read_u32le(data, &mut pos, fname)?;
        inputs.push(RawInput { prev_le, vout, script_sig, sequence, witness: Vec::new() });
    }
    let n_out = read_varint(data, &mut pos, fname)?;
    if n_out > (data.len() / 9 + 1) as u64 {
        return Err(err(format!("{}: output count exceeds what the data can hold", fname)));
    }
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        let amount = read_u64le(data, &mut pos, fname)?;
        let slen = read_varint(data, &mut pos, fname)? as usize;
        let script = read_bytes(data, &mut pos, slen, fname)?.to_vec();
        outputs.push(RawOutput { amount, script });
    }
    if segwit_flag {
        for input in &mut inputs {
            let n_items = read_varint(data, &mut pos, fname)?;
            if n_items > (data.len() + 1) as u64 {
                return Err(err(format!("{}: witness item count exceeds what the data can hold", fname)));
            }
            let mut items = Vec::with_capacity(n_items as usize);
            for _ in 0..n_items {
                let ilen = read_varint(data, &mut pos, fname)? as usize;
                items.push(read_bytes(data, &mut pos, ilen, fname)?.to_vec());
            }
            input.witness = items;
        }
    }
    let locktime = read_u32le(data, &mut pos, fname)?;
    if pos != data.len() {
        return Err(err(format!(
            "{}: {} trailing byte(s) after the transaction",
            fname,
            data.len() - pos
        )));
    }
    Ok(RawTx { version, inputs, outputs, locktime })
}

/// Serializa. `with_witness = false` = la forma del TXID (BIP-141: el txid es el
/// dSHA256 del serializado SIN witness).
pub(crate) fn serialize_tx(tx: &RawTx, with_witness: bool) -> Vec<u8> {
    let has_witness = with_witness && tx.inputs.iter().any(|i| !i.witness.is_empty());
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    if has_witness {
        out.push(0x00);
        out.push(0x01);
    }
    write_varint(tx.inputs.len() as u64, &mut out);
    for i in &tx.inputs {
        out.extend_from_slice(&i.prev_le);
        out.extend_from_slice(&i.vout.to_le_bytes());
        write_varint(i.script_sig.len() as u64, &mut out);
        out.extend_from_slice(&i.script_sig);
        out.extend_from_slice(&i.sequence.to_le_bytes());
    }
    write_varint(tx.outputs.len() as u64, &mut out);
    for o in &tx.outputs {
        out.extend_from_slice(&o.amount.to_le_bytes());
        write_varint(o.script.len() as u64, &mut out);
        out.extend_from_slice(&o.script);
    }
    if has_witness {
        for i in &tx.inputs {
            write_varint(i.witness.len() as u64, &mut out);
            for item in &i.witness {
                write_varint(item.len() as u64, &mut out);
                out.extend_from_slice(item);
            }
        }
    }
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out
}

/// TXID en la forma que muestran exploradores y RPC: dSHA256 del serializado sin
/// witness, **byte-reversed**. Evita el clásico "mi txid está al revés".
pub(crate) fn txid_of(tx: &RawTx) -> String {
    let mut h = dsha256(&serialize_tx(tx, false));
    h.reverse();
    hex_encode(&h)
}

fn btc_txid(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_txid";
    let raw = arg_bytes(arg(args, 0, F)?, F, "the raw transaction")?;
    let tx = parse_tx(raw, F)?;
    Ok(syn_text(txid_of(&tx)))
}

// =========================================================
// Sighash BIP-143 (P2WPKH) y BIP-341 (P2TR key-path)
// =========================================================

/// La vista de una tx para FIRMAR: cada input con su amount y scriptPubKey
/// (BIP-143/341 firman los amounts — la protección anti-firma-ciega).
pub(crate) struct SigInput {
    pub(crate) prev_le: [u8; 32],
    pub(crate) vout: u32,
    pub(crate) sequence: u32,
    pub(crate) amount: u64,
    pub(crate) script_pubkey: Vec<u8>,
}

pub(crate) struct SigTxCtx {
    pub(crate) version: u32,
    pub(crate) locktime: u32,
    pub(crate) inputs: Vec<SigInput>,
    pub(crate) outputs: Vec<RawOutput>,
}

fn outputs_blob(outputs: &[RawOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    for o in outputs {
        b.extend_from_slice(&o.amount.to_le_bytes());
        write_varint(o.script.len() as u64, &mut b);
        b.extend_from_slice(&o.script);
    }
    b
}

/// Sighash BIP-143 de un input P2WPKH con SIGHASH_ALL (el único en alcance).
pub(crate) fn sighash_bip143(ctx: &SigTxCtx, index: usize, fname: &str) -> Result<[u8; 32], Control> {
    let input = &ctx.inputs[index];
    if input.script_pubkey.len() != 22 || input.script_pubkey[0] != 0x00 || input.script_pubkey[1] != 0x14 {
        return Err(err(format!(
            "{}: input {} is not P2WPKH (internal kind mismatch)",
            fname, index
        )));
    }
    let mut prevouts = Vec::with_capacity(36 * ctx.inputs.len());
    let mut sequences = Vec::with_capacity(4 * ctx.inputs.len());
    for i in &ctx.inputs {
        prevouts.extend_from_slice(&i.prev_le);
        prevouts.extend_from_slice(&i.vout.to_le_bytes());
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
    }
    // scriptCode de P2WPKH: el P2PKH implícito del program (BIP-143).
    let mut script_code = Vec::with_capacity(26);
    script_code.extend_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
    script_code.extend_from_slice(&input.script_pubkey[2..22]);
    script_code.extend_from_slice(&[0x88, 0xac]);

    let mut pre = Vec::new();
    pre.extend_from_slice(&ctx.version.to_le_bytes());
    pre.extend_from_slice(&dsha256(&prevouts));
    pre.extend_from_slice(&dsha256(&sequences));
    pre.extend_from_slice(&input.prev_le);
    pre.extend_from_slice(&input.vout.to_le_bytes());
    pre.extend_from_slice(&script_code);
    pre.extend_from_slice(&input.amount.to_le_bytes());
    pre.extend_from_slice(&input.sequence.to_le_bytes());
    pre.extend_from_slice(&dsha256(&outputs_blob(&ctx.outputs)));
    pre.extend_from_slice(&ctx.locktime.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
    Ok(dsha256(&pre))
}

/// Sighash BIP-341 key-path. `hash_type` completo a nivel interno (los vectores
/// oficiales cubren la matriz); el BUILDER sólo pasa 0x00 (SIGHASH_DEFAULT).
pub(crate) fn sighash_bip341(
    ctx: &SigTxCtx,
    index: usize,
    hash_type: u8,
    fname: &str,
) -> Result<[u8; 32], Control> {
    if !matches!(hash_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83) {
        return Err(err(format!("{}: invalid taproot hash type 0x{:02x}", fname, hash_type)));
    }
    let anyonecanpay = hash_type & 0x80 != 0;
    let out_kind = hash_type & 0x03;
    let input = &ctx.inputs[index];

    let mut msg = Vec::new();
    msg.push(0x00); // epoch
    msg.push(hash_type);
    msg.extend_from_slice(&ctx.version.to_le_bytes());
    msg.extend_from_slice(&ctx.locktime.to_le_bytes());
    if !anyonecanpay {
        // BIP-341 usa SHA256 SIMPLE (no doble) para los precomputados.
        let mut prevouts = Vec::new();
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        let mut sequences = Vec::new();
        for i in &ctx.inputs {
            prevouts.extend_from_slice(&i.prev_le);
            prevouts.extend_from_slice(&i.vout.to_le_bytes());
            amounts.extend_from_slice(&i.amount.to_le_bytes());
            write_varint(i.script_pubkey.len() as u64, &mut scripts);
            scripts.extend_from_slice(&i.script_pubkey);
            sequences.extend_from_slice(&i.sequence.to_le_bytes());
        }
        msg.extend_from_slice(&Sha256::digest(&prevouts));
        msg.extend_from_slice(&Sha256::digest(&amounts));
        msg.extend_from_slice(&Sha256::digest(&scripts));
        msg.extend_from_slice(&Sha256::digest(&sequences));
    }
    if out_kind != 0x02 && out_kind != 0x03 {
        // ALL / DEFAULT: todos los outputs.
        msg.extend_from_slice(&Sha256::digest(outputs_blob(&ctx.outputs)));
    }
    msg.push(0x00); // spend_type: key-path, sin annex
    if anyonecanpay {
        msg.extend_from_slice(&input.prev_le);
        msg.extend_from_slice(&input.vout.to_le_bytes());
        msg.extend_from_slice(&input.amount.to_le_bytes());
        let mut spk = Vec::new();
        write_varint(input.script_pubkey.len() as u64, &mut spk);
        spk.extend_from_slice(&input.script_pubkey);
        msg.extend_from_slice(&spk);
        msg.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if out_kind == 0x03 {
        // SINGLE: el output correspondiente (debe existir).
        let o = ctx.outputs.get(index).ok_or_else(|| {
            err(format!(
                "{}: SIGHASH_SINGLE has no corresponding output for input {}",
                fname, index
            ))
        })?;
        let mut blob = Vec::new();
        blob.extend_from_slice(&o.amount.to_le_bytes());
        write_varint(o.script.len() as u64, &mut blob);
        blob.extend_from_slice(&o.script);
        msg.extend_from_slice(&Sha256::digest(&blob));
    }
    let mut h = tagged_hasher("TapSighash");
    h.update(&msg);
    Ok(h.finalize().into())
}

// =========================================================
// El builder (Alcance C, G28): cada satoshi contabilizado
// =========================================================

const SEQ_RBF: u32 = 0xFFFF_FFFD;
const SEQ_FINAL_NO_RBF: u32 = 0xFFFF_FFFE;

struct PlanInput {
    txid_display: [u8; 32],
    vout: u32,
    amount: u64,
    address: String,
    kind: AddrKind,
    program: Vec<u8>,
    pubkey: Option<Vec<u8>>,
}

struct PlanOutput {
    amount: u64,
    address: String,
    kind: AddrKind,
    script: Vec<u8>,
}

struct Plan {
    network: Network,
    rbf: bool,
    locktime: u32,
    inputs: Vec<PlanInput>,
    outputs: Vec<PlanOutput>,
    fee: u64,
    allow_absurd_fee: bool,
}

const TX_VERSION: u32 = 2;

/// Amount en SATS: entero EXACTO y positivo. Un float o un decimal → error
/// dirigido con la conversión (G29: "0.1 BTC" jamás se adivina).
fn sats_field(v: Option<&SynValue>, what: &str, fname: &str, min: i64) -> Result<u64, Control> {
    let n = match v {
        Some(SynValue::Number(n)) => n,
        Some(other) => {
            return Err(err(format!(
                "{}: {} must be an integer amount in SATS, got {}",
                fname,
                what,
                other.type_name()
            )))
        }
        None => {
            return Err(err(format!(
                "{}: missing {} — amounts are explicit, in sats",
                fname, what
            )))
        }
    };
    if !n.is_integer() {
        return Err(err(format!(
            "{}: {} must be an EXACT integer number of sats — never a float or a decimal BTC amount (1 BTC = 100_000_000 sats; convert explicitly)",
            fname, what
        )));
    }
    let i = n.to_i64_trunc().ok_or_else(|| {
        err(format!("{}: {} is out of range (max {} sats = 21M BTC)", fname, what, MAX_SATS))
    })?;
    if i < min || i > MAX_SATS {
        return Err(err(format!(
            "{}: {} must be between {} and {} sats (21M BTC), got {}",
            fname, what, min, MAX_SATS, i
        )));
    }
    Ok(i as u64)
}

/// TXID de un input: text de 64 hex (la forma de exploradores/RPC) o bytes(32),
/// SIEMPRE en orden de display — el reverse al orden de wire es interno.
fn txid_field(v: Option<&SynValue>, what: &str, fname: &str) -> Result<[u8; 32], Control> {
    match v {
        Some(SynValue::Text(s)) => {
            let s = s.to_string();
            if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(format!(
                    "{}: {} must be 64 hex characters (the txid as explorers show it)",
                    fname, what
                )));
            }
            let b = hex_decode(&s).expect("validado hex");
            Ok(b.try_into().expect("32 bytes"))
        }
        Some(SynValue::Bytes(b)) if b.len() == 32 => Ok(b[..].try_into().expect("32 bytes")),
        Some(SynValue::Bytes(b)) => Err(err(format!(
            "{}: {} must be 32 bytes, got {}",
            fname,
            what,
            b.len()
        ))),
        Some(other) => Err(err(format!(
            "{}: {} must be a 64-hex text or 32 bytes, got {}",
            fname,
            what,
            other.type_name()
        ))),
        None => Err(err(format!("{}: missing {}", fname, what))),
    }
}

fn map_of(v: &SynValue, what: &str, fname: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!(
            "{}: {} must be a map, got {}",
            fname,
            what,
            other.type_name()
        ))),
    }
}

fn list_of(v: Option<&SynValue>, what: &str, fname: &str) -> Result<Vec<SynValue>, Control> {
    match v {
        Some(SynValue::List(l)) => Ok(l.borrow().clone()),
        Some(other) => Err(err(format!(
            "{}: {} must be a list, got {}",
            fname,
            what,
            other.type_name()
        ))),
        None => Err(err(format!("{}: missing {}", fname, what))),
    }
}

/// Construye y VALIDA el plan completo (G28 + G29). Compartido por `btc_tx`,
/// `btc_tx_raw` y `psbt_encode` — una única implementación de las guardas.
fn build_plan(params: &IndexMap<String, SynValue>, fname: &str) -> Result<Plan, Control> {
    for k in params.keys() {
        match k.as_str() {
            "inputs" | "outputs" | "fee" | "network" | "rbf" | "locktime" | "allow_absurd_fee" => {}
            "sighash" => {
                return Err(err(format!(
                    "{}: custom sighash types are not supported — the builder always uses SIGHASH_ALL (P2WPKH) / SIGHASH_DEFAULT (P2TR); NONE/SINGLE/ANYONECANPAY are out of scope",
                    fname
                )))
            }
            other => {
                return Err(err(format!(
                    "{}: unknown key {:?} in params (allowed: inputs, outputs, fee, network, rbf, locktime, allow_absurd_fee)",
                    fname, other
                )))
            }
        }
    }
    let network = Network::parse(params.get("network"), fname)?;
    let rbf = match params.get("rbf") {
        None | Some(SynValue::Nothing) => true, // el default moderno de Core
        Some(SynValue::Bool(b)) => *b,
        Some(other) => {
            return Err(err(format!(
                "{}: \"rbf\" must be true or false, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    let locktime = match params.get("locktime") {
        None | Some(SynValue::Nothing) => 0u32,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(l) if n.is_integer() && (0..=u32::MAX as i64).contains(&l) => l as u32,
            _ => {
                return Err(err(format!(
                    "{}: \"locktime\" must be an integer 0..=4294967295",
                    fname
                )))
            }
        },
        Some(other) => {
            return Err(err(format!(
                "{}: \"locktime\" must be a number, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    let allow_absurd_fee = match params.get("allow_absurd_fee") {
        None | Some(SynValue::Nothing) => false,
        Some(SynValue::Bool(b)) => *b,
        Some(other) => {
            return Err(err(format!(
                "{}: \"allow_absurd_fee\" must be true or false, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    // El fee se DECLARA (G28): el error de campo faltante explica el footgun.
    let fee = match params.get("fee") {
        Some(v) => sats_field(Some(v), "\"fee\"", fname, 0)?,
        None => {
            return Err(err(format!(
                "{}: missing \"fee\" — in UTXO the fee is IMPLICIT (inputs − outputs) and forgetting the change output donates the remainder to miners; here the fee is DECLARED and every satoshi must be accounted for (G28). Read rates with btc_fee_estimates(url) and state the fee",
                fname
            )))
        }
    };

    // -- inputs --
    let in_list = list_of(params.get("inputs"), "\"inputs\"", fname)?;
    if in_list.is_empty() {
        return Err(err(format!("{}: \"inputs\" cannot be empty", fname)));
    }
    let mut inputs = Vec::with_capacity(in_list.len());
    let mut seen = std::collections::HashSet::new();
    for (i, item) in in_list.iter().enumerate() {
        let what = format!("inputs[{}]", i);
        let m = map_of(item, &what, fname)?;
        for k in m.keys() {
            if !matches!(k.as_str(), "txid" | "vout" | "amount" | "address" | "pubkey") {
                return Err(err(format!(
                    "{}: unknown key {:?} in {} (allowed: txid, vout, amount, address, pubkey)",
                    fname, k, what
                )));
            }
        }
        let txid_display = txid_field(m.get("txid"), &format!("{}.txid", what), fname)?;
        let vout = match m.get("vout") {
            Some(SynValue::Number(n)) => match n.to_i64_trunc() {
                Some(v) if n.is_integer() && (0..=u32::MAX as i64).contains(&v) => v as u32,
                _ => {
                    return Err(err(format!(
                        "{}: {}.vout must be an integer 0..=4294967295",
                        fname, what
                    )))
                }
            },
            Some(other) => {
                return Err(err(format!(
                    "{}: {}.vout must be a number, got {}",
                    fname,
                    what,
                    other.type_name()
                )))
            }
            None => return Err(err(format!("{}: {} is missing \"vout\"", fname, what))),
        };
        if !seen.insert((txid_display, vout)) {
            return Err(err(format!(
                "{}: {} spends the same UTXO as an earlier input (duplicate txid:vout) — a transaction cannot spend one output twice",
                fname, what
            )));
        }
        // amount + address OBLIGATORIOS: BIP-143/341 firman los amounts (la
        // protección anti-firma-ciega). El error nombra el lector (patrón G24).
        let amount = match m.get("amount") {
            Some(v) => sats_field(Some(v), &format!("{}.amount", what), fname, 1)?,
            None => {
                return Err(err(format!(
                    "{}: {} is missing \"amount\" — BIP-143/341 SIGN the input amounts (the anti-blind-signing protection); read your UTXOs with btc_utxos(url, address)",
                    fname, what
                )))
            }
        };
        let addr_s = match m.get("address") {
            Some(SynValue::Text(s)) => s.to_string(),
            Some(other) => {
                return Err(err(format!(
                    "{}: {}.address must be text, got {}",
                    fname,
                    what,
                    other.type_name()
                )))
            }
            None => {
                return Err(err(format!(
                    "{}: {} is missing \"address\" — the UTXO's own address decides HOW it is signed (P2WPKH vs P2TR); read your UTXOs with btc_utxos(url, address)",
                    fname, what
                )))
            }
        };
        let dec = decode_address(&addr_s, fname)?;
        check_network(&dec, network, &format!("{}.address", what), fname)?;
        let pubkey = match (dec.kind, m.get("pubkey")) {
            (AddrKind::P2wpkh, Some(v)) => {
                let pk = compressed_pubkey(v, fname)?;
                if hash160(&pk) != dec.program[..] {
                    return Err(err(format!(
                        "{}: {}.pubkey does not hash to the address {} — signing with the wrong key would produce an invalid spend; nothing was built",
                        fname, what, addr_s
                    )));
                }
                Some(pk)
            }
            (AddrKind::P2wpkh, None) => {
                return Err(err(format!(
                    "{}: {} is missing \"pubkey\" — a P2WPKH witness reveals the full public key (the address only holds its hash); pass secp256k1_pubkey(secret(\"KEY\")) or the 33-byte pubkey",
                    fname, what
                )))
            }
            (AddrKind::P2tr, Some(v)) => {
                // Cross-check opcional: la INTERNA tweakeada debe dar el program.
                let x = xonly_pubkey(v, fname)?;
                let (out, _parity) = tap_output_key(&x, None, fname)?;
                if out != dec.program[..] {
                    return Err(err(format!(
                        "{}: {}.pubkey (internal key) does not tweak to the address {} — signing with the wrong key would produce an invalid spend; nothing was built",
                        fname, what, addr_s
                    )));
                }
                None // el witness key-path no lleva pubkey
            }
            (AddrKind::P2tr, None) => None,
            (kind, _) => {
                return Err(err(format!(
                    "{}: {} is a {} UTXO — this batch spends FROM p2wpkh and p2tr (key-path) only; sending TO {} works, spending from it is out of scope",
                    fname, what, kind.as_str(), kind.as_str()
                )))
            }
        };
        inputs.push(PlanInput {
            txid_display,
            vout,
            amount,
            address: addr_s,
            kind: dec.kind,
            program: dec.program,
            pubkey,
        });
    }

    // -- outputs --
    let out_list = list_of(params.get("outputs"), "\"outputs\"", fname)?;
    if out_list.is_empty() {
        return Err(err(format!("{}: \"outputs\" cannot be empty", fname)));
    }
    let mut outputs = Vec::with_capacity(out_list.len());
    for (i, item) in out_list.iter().enumerate() {
        let what = format!("outputs[{}]", i);
        let m = map_of(item, &what, fname)?;
        for k in m.keys() {
            if !matches!(k.as_str(), "address" | "amount") {
                return Err(err(format!(
                    "{}: unknown key {:?} in {} (allowed: address, amount)",
                    fname, k, what
                )));
            }
        }
        let addr_s = match m.get("address") {
            Some(SynValue::Text(s)) => s.to_string(),
            Some(other) => {
                return Err(err(format!(
                    "{}: {}.address must be text, got {}",
                    fname,
                    what,
                    other.type_name()
                )))
            }
            None => return Err(err(format!("{}: {} is missing \"address\"", fname, what))),
        };
        let dec = decode_address(&addr_s, fname)?;
        check_network(&dec, network, &format!("{}.address", what), fname)?;
        let amount = sats_field(m.get("amount"), &format!("{}.amount", what), fname, 1)?;
        // Guarda de dust: un output bajo el límite no relaya (sats quemados).
        if amount < dec.kind.dust_limit() {
            return Err(err(format!(
                "{}: {} pays {} sats to a {} address — below its dust limit of {} sats (the network would not relay it); merge it into another output or raise it",
                fname,
                what,
                amount,
                dec.kind.as_str(),
                dec.kind.dust_limit()
            )));
        }
        outputs.push(PlanOutput {
            amount,
            address: addr_s,
            kind: dec.kind,
            script: script_pubkey_of(dec.kind, &dec.program),
        });
    }

    // -- G28: el invariante central --
    let total_in: u64 = inputs.iter().map(|i| i.amount).sum();
    let total_out: u64 = outputs.iter().map(|o| o.amount).sum();
    let spend = total_out
        .checked_add(fee)
        .ok_or_else(|| err(format!("{}: outputs + fee overflow", fname)))?;
    if total_in != spend {
        return Err(if total_in > spend {
            let diff = total_in - spend;
            err(format!(
                "{}: G28 violated — inputs ({} sats) exceed outputs + fee ({} sats) by {} sats. Did you forget the change output? In UTXO the remainder is silently DONATED to miners; here every satoshi must be accounted for: add a change output back to your own address (or raise the fee explicitly)",
                fname, total_in, spend, diff
            ))
        } else {
            let diff = spend - total_in;
            err(format!(
                "{}: G28 violated — outputs + fee ({} sats) exceed inputs ({} sats) by {} sats; the transaction cannot be funded. Add inputs (btc_utxos) or lower the amounts/fee",
                fname, spend, total_in, diff
            ))
        });
    }
    // Fee absurdo: mayor que TODO lo enviado es casi siempre un bug de amounts.
    if fee > total_out && !allow_absurd_fee {
        return Err(err(format!(
            "{}: the fee ({} sats) is larger than everything the transaction sends ({} sats) — almost always a bug in the amounts. If this is deliberate, pass \"allow_absurd_fee\": true",
            fname, fee, total_out
        )));
    }
    Ok(Plan { network, rbf, locktime, inputs, outputs, fee, allow_absurd_fee })
}

impl Plan {
    fn sequence(&self) -> u32 {
        if self.rbf {
            SEQ_RBF
        } else {
            SEQ_FINAL_NO_RBF
        }
    }

    /// Vista de firma: prev en orden de wire, amounts y scriptPubKeys.
    fn sig_ctx(&self) -> SigTxCtx {
        let sequence = self.sequence();
        SigTxCtx {
            version: TX_VERSION,
            locktime: self.locktime,
            inputs: self
                .inputs
                .iter()
                .map(|i| {
                    let mut prev_le = i.txid_display;
                    prev_le.reverse();
                    SigInput {
                        prev_le,
                        vout: i.vout,
                        sequence,
                        amount: i.amount,
                        script_pubkey: script_pubkey_of(i.kind, &i.program),
                    }
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|o| RawOutput { amount: o.amount, script: o.script.clone() })
                .collect(),
        }
    }

    /// Un digest por input (BIP-143 o BIP-341 según el tipo del UTXO).
    fn digests(&self, fname: &str) -> Result<Vec<[u8; 32]>, Control> {
        let ctx = self.sig_ctx();
        let mut out = Vec::with_capacity(self.inputs.len());
        for (i, input) in self.inputs.iter().enumerate() {
            out.push(match input.kind {
                AddrKind::P2wpkh => sighash_bip143(&ctx, i, fname)?,
                AddrKind::P2tr => sighash_bip341(&ctx, i, 0x00, fname)?,
                _ => unreachable!("build_plan sólo admite p2wpkh/p2tr como inputs"),
            });
        }
        Ok(out)
    }

    /// vsize ESTIMADO (las firmas aún no existen): DER máximo 72 bytes por input
    /// P2WPKH, 64 por P2TR. Sirve para elegir el fee (`fee = vsize × sat/vB`).
    fn estimate_vsize(&self) -> u64 {
        let mut base: u64 = 4 + 4; // version + locktime
        let mut count = Vec::new();
        write_varint(self.inputs.len() as u64, &mut count);
        write_varint(self.outputs.len() as u64, &mut count);
        base += count.len() as u64;
        base += self.inputs.len() as u64 * (32 + 4 + 1 + 4); // outpoint + scriptSig vacío + sequence
        for o in &self.outputs {
            let mut lp = Vec::new();
            write_varint(o.script.len() as u64, &mut lp);
            base += 8 + lp.len() as u64 + o.script.len() as u64;
        }
        let wit: u64 = self
            .inputs
            .iter()
            .map(|i| match i.kind {
                AddrKind::P2wpkh => 108u64, // count + (72+len) + (33+len)
                AddrKind::P2tr => 66,       // count + (64+len)
                _ => 0,
            })
            .sum();
        let weight = base * 4 + 2 + wit; // marker+flag pesan 2
        weight.div_ceil(4)
    }

    /// El eco completo (G28): fee, amounts, direcciones y digests A LA VISTA
    /// para el `confirm` PREVIO a firmar. `btc_tx_raw`/`psbt_encode` reconstruyen
    /// el plan desde este mismo map (y re-validan todo).
    fn to_map(&self, fname: &str) -> Result<SynValue, Control> {
        let digests = self.digests(fname)?;
        let vsize = self.estimate_vsize();
        let mut m = IndexMap::new();
        m.insert(
            "digests".to_string(),
            syn_list(digests.into_iter().map(|d| syn_bytes(d.to_vec())).collect()),
        );
        m.insert("fee".to_string(), syn_int(self.fee as i64));
        m.insert("vsize".to_string(), syn_int(vsize as i64));
        m.insert(
            "fee_rate".to_string(),
            syn_number(Number::Float(self.fee as f64 / vsize as f64)),
        );
        m.insert(
            "total_in".to_string(),
            syn_int(self.inputs.iter().map(|i| i.amount).sum::<u64>() as i64),
        );
        m.insert(
            "total_out".to_string(),
            syn_int(self.outputs.iter().map(|o| o.amount).sum::<u64>() as i64),
        );
        m.insert("network".to_string(), syn_text(self.network.as_str()));
        m.insert("rbf".to_string(), syn_bool(self.rbf));
        m.insert("locktime".to_string(), syn_int(self.locktime as i64));
        m.insert("version".to_string(), syn_int(TX_VERSION as i64));
        if self.allow_absurd_fee {
            m.insert("allow_absurd_fee".to_string(), syn_bool(true));
        }
        let inputs = self
            .inputs
            .iter()
            .map(|i| {
                let mut im = IndexMap::new();
                im.insert("txid".to_string(), syn_text(hex_encode(&i.txid_display)));
                im.insert("vout".to_string(), syn_int(i.vout as i64));
                im.insert("amount".to_string(), syn_int(i.amount as i64));
                im.insert("address".to_string(), syn_text(i.address.clone()));
                im.insert("kind".to_string(), syn_text(i.kind.as_str()));
                if let Some(pk) = &i.pubkey {
                    im.insert("pubkey".to_string(), syn_bytes(pk.clone()));
                }
                syn_map(im)
            })
            .collect();
        m.insert("inputs".to_string(), syn_list(inputs));
        let outputs = self
            .outputs
            .iter()
            .map(|o| {
                let mut om = IndexMap::new();
                om.insert("address".to_string(), syn_text(o.address.clone()));
                om.insert("amount".to_string(), syn_int(o.amount as i64));
                om.insert("kind".to_string(), syn_text(o.kind.as_str()));
                syn_map(om)
            })
            .collect();
        m.insert("outputs".to_string(), syn_list(outputs));
        Ok(syn_map(m))
    }
}

/// Reconstruye los params del eco de `btc_tx` (misma forma) y RE-VALIDA con
/// `build_plan` — un map manipulado entre `btc_tx` y `btc_tx_raw` vuelve a pasar
/// por TODAS las guardas (G28 no se puede sortear editando el eco).
fn plan_from_map(m: &IndexMap<String, SynValue>, fname: &str) -> Result<Plan, Control> {
    let mut params = IndexMap::new();
    for key in ["inputs", "outputs", "fee", "network", "rbf", "locktime", "allow_absurd_fee"] {
        if let Some(v) = m.get(key) {
            params.insert(key.to_string(), v.clone());
        }
    }
    if !params.contains_key("inputs") || !params.contains_key("outputs") {
        return Err(err(format!(
            "{}: expected the map returned by btc_tx (it carries inputs/outputs/fee)",
            fname
        )));
    }
    // El eco de inputs/outputs lleva "kind" (informativo) — se filtra acá.
    let strip = |v: &SynValue, extra: &[&str]| -> SynValue {
        if let SynValue::List(l) = v {
            let items = l
                .borrow()
                .iter()
                .map(|item| {
                    if let SynValue::Map(im) = item {
                        let mut c = im.borrow().clone();
                        for e in extra {
                            c.shift_remove(*e);
                        }
                        syn_map(c)
                    } else {
                        item.clone()
                    }
                })
                .collect();
            syn_list(items)
        } else {
            v.clone()
        }
    };
    if let Some(v) = params.get("inputs").cloned() {
        params.insert("inputs".to_string(), strip(&v, &["kind"]));
    }
    if let Some(v) = params.get("outputs").cloned() {
        params.insert("outputs".to_string(), strip(&v, &["kind"]));
    }
    build_plan(&params, fname)
}

fn btc_tx(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_tx";
    let params = map_of(arg(args, 0, F)?, "params", F)?;
    let plan = build_plan(&params, F)?;
    plan.to_map(F)
}

// -- Ensamblado de la firmada (btc_tx_raw) --

/// DER de un entero de 32 bytes (mínimo, con 0x00 si el high bit está seteado).
fn der_int(x: &[u8]) -> Vec<u8> {
    let first = x.iter().position(|&b| b != 0).unwrap_or(x.len() - 1);
    let body = &x[first..];
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x02);
    if body[0] & 0x80 != 0 {
        out.push(body.len() as u8 + 1);
        out.push(0x00);
    } else {
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
    out
}

/// (r ‖ s) de 64 bytes → DER ‖ 0x01 (SIGHASH_ALL). Exige low-s (una firma
/// high-s es malleada y no estándar — el nodo la rechazaría).
fn ecdsa_der_with_hashtype(sig64: &[u8], index: usize, fname: &str) -> Result<Vec<u8>, Control> {
    let (r, s) = sig64.split_at(32);
    if s > &SECP_N_HALF[..] {
        return Err(err(format!(
            "{}: the signature for input {} is not low-s (malleable, non-standard) — sign with secp256k1_sign, which normalizes it",
            fname, index
        )));
    }
    let ri = der_int(r);
    let si = der_int(s);
    let mut out = Vec::with_capacity(ri.len() + si.len() + 3);
    out.push(0x30);
    out.push((ri.len() + si.len()) as u8);
    out.extend_from_slice(&ri);
    out.extend_from_slice(&si);
    out.push(0x01); // SIGHASH_ALL
    Ok(out)
}

/// La tx firmada, lista para `btc_send`. Reconstruye el plan (re-valida G28),
/// recomputa los digests y **VERIFICA cada firma contra la clave del UTXO** antes
/// de ensamblar — una firma con la clave equivocada jamás sale al aire.
fn btc_tx_raw(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "btc_tx_raw";
    let m = map_of(arg(args, 0, F)?, "the tx map", F)?;
    let plan = plan_from_map(&m, F)?;
    let sigs = list_of(args.get(1), "the signatures", F)?;
    if sigs.len() != plan.inputs.len() {
        return Err(err(format!(
            "{}: got {} signature(s) for {} input(s) — one signature PER INPUT, in the same order",
            F,
            sigs.len(),
            plan.inputs.len()
        )));
    }
    let digests = plan.digests(F)?;
    let ctx = plan.sig_ctx();
    let mut raw_inputs = Vec::with_capacity(plan.inputs.len());
    for (i, (input, sig_ctx)) in plan.inputs.iter().zip(&ctx.inputs).enumerate() {
        let what = format!("signatures[{}]", i);
        let sig_raw = arg_bytes(&sigs[i], F, &what)?;
        let witness = match input.kind {
            AddrKind::P2wpkh => {
                // 65 = r‖s‖recid de secp256k1_sign (el recid sobra acá); 64 = r‖s.
                let sig64 = match sig_raw.len() {
                    64 => sig_raw,
                    65 => &sig_raw[..64],
                    n => {
                        return Err(err(format!(
                            "{}: {} must be the 64/65-byte output of secp256k1_sign, got {} bytes",
                            F, what, n
                        )))
                    }
                };
                let pubkey = input.pubkey.as_ref().expect("build_plan lo exige para p2wpkh");
                let vk = VerifyingKey::from_sec1_bytes(pubkey)
                    .map_err(|_| err(format!("{}: input {} has an invalid public key", F, i)))?;
                let sig = EcSignature::from_slice(sig64)
                    .map_err(|_| err(format!("{}: {} is not a valid (r, s) pair", F, what)))?;
                if vk.verify_prehash(&digests[i], &sig).is_err() {
                    return Err(err(format!(
                        "{}: {} does not verify against input {}'s key — did you sign THIS tx's digest (tx[\"digests\"][{}]) with the key of {}? Nothing was assembled",
                        F, what, i, i, input.address
                    )));
                }
                vec![ecdsa_der_with_hashtype(sig64, i, F)?, pubkey.clone()]
            }
            AddrKind::P2tr => {
                if sig_raw.len() != 64 {
                    return Err(err(format!(
                        "{}: {} must be a 64-byte Schnorr signature, got {} bytes",
                        F,
                        what,
                        sig_raw.len()
                    )));
                }
                let out_key: [u8; 32] =
                    input.program[..].try_into().expect("program p2tr de 32");
                let vk = schnorr::VerifyingKey::from_bytes(&out_key)
                    .map_err(|_| err(format!("{}: input {} has an invalid taproot key", F, i)))?;
                let sig = schnorr::Signature::try_from(sig_raw)
                    .map_err(|_| err(format!("{}: {} is not a valid Schnorr signature", F, what)))?;
                if vk.verify_prehash(&digests[i], &sig).is_err() {
                    return Err(err(format!(
                        "{}: {} does not verify against input {}'s taproot OUTPUT key — a key-path spend signs with the TWEAKED key: schnorr_sign(tx[\"digests\"][{}], secret, \"taproot\"). Nothing was assembled",
                        F, what, i, i
                    )));
                }
                vec![sig_raw.to_vec()]
            }
            _ => unreachable!("build_plan sólo admite p2wpkh/p2tr como inputs"),
        };
        raw_inputs.push(RawInput {
            prev_le: sig_ctx.prev_le,
            vout: sig_ctx.vout,
            script_sig: Vec::new(),
            sequence: sig_ctx.sequence,
            witness,
        });
    }
    let tx = RawTx {
        version: TX_VERSION,
        inputs: raw_inputs,
        outputs: ctx.outputs,
        locktime: plan.locktime,
    };
    Ok(syn_bytes(serialize_tx(&tx, true)))
}

// =========================================================
// PSBT — BIP-174 (Alcance E): el agente prepara, el humano firma en frío
// =========================================================

const PSBT_MAGIC: &[u8; 5] = b"psbt\xff";
// Tipos de campo (BIP-174).
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_VERSION: u8 = 0xfb;
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;

/// `psbt_encode(tx)` → base64 del PSBT unsigned (creator + witness_utxo por
/// input — los amounts/scripts que una hardware wallet EXIGE para firmar sin
/// firma ciega). Importable directo en Sparrow/Electrum/Ledger/Trezor/Coldcard.
fn psbt_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "psbt_encode";
    let m = map_of(arg(args, 0, F)?, "the tx map", F)?;
    let plan = plan_from_map(&m, F)?;
    let ctx = plan.sig_ctx();
    let unsigned = RawTx {
        version: TX_VERSION,
        inputs: ctx
            .inputs
            .iter()
            .map(|i| RawInput {
                prev_le: i.prev_le,
                vout: i.vout,
                script_sig: Vec::new(),
                sequence: i.sequence,
                witness: Vec::new(),
            })
            .collect(),
        outputs: ctx
            .outputs
            .iter()
            .map(|o| RawOutput { amount: o.amount, script: o.script.clone() })
            .collect(),
        locktime: plan.locktime,
    };
    let mut out = Vec::new();
    out.extend_from_slice(PSBT_MAGIC);
    // global: unsigned tx
    let tx_bytes = serialize_tx(&unsigned, false);
    out.push(1);
    out.push(PSBT_GLOBAL_UNSIGNED_TX);
    write_varint(tx_bytes.len() as u64, &mut out);
    out.extend_from_slice(&tx_bytes);
    out.push(0x00);
    // por input: witness_utxo (amount + scriptPubKey del UTXO)
    for i in &ctx.inputs {
        out.push(1);
        out.push(PSBT_IN_WITNESS_UTXO);
        let mut utxo = Vec::with_capacity(8 + 1 + i.script_pubkey.len());
        utxo.extend_from_slice(&i.amount.to_le_bytes());
        write_varint(i.script_pubkey.len() as u64, &mut utxo);
        utxo.extend_from_slice(&i.script_pubkey);
        write_varint(utxo.len() as u64, &mut out);
        out.extend_from_slice(&utxo);
        out.push(0x00);
    }
    // por output: mapas vacíos (un separador 0x00 por output)
    out.extend(std::iter::repeat_n(0x00u8, ctx.outputs.len()));
    Ok(syn_text(b64_encode(&out)))
}

/// Un campo key→value de un mapa PSBT.
type PsbtField = (Vec<u8>, Vec<u8>);

/// Un mapa key→value de PSBT. Claves DUPLICADAS → error (BIP-174 lo prohíbe; un
/// firmante que tolere duplicados puede ser engañado con dos witness_utxo).
fn read_psbt_map(data: &[u8], pos: &mut usize, fname: &str) -> Result<Vec<PsbtField>, Control> {
    let mut out: Vec<PsbtField> = Vec::new();
    loop {
        let klen = read_varint(data, pos, fname)? as usize;
        if klen == 0 {
            return Ok(out); // separador de mapa
        }
        if klen > data.len() {
            return Err(err(format!("{}: PSBT key length exceeds the input", fname)));
        }
        let key = read_bytes(data, pos, klen, fname)?.to_vec();
        let vlen = read_varint(data, pos, fname)? as usize;
        let value = read_bytes(data, pos, vlen, fname)?.to_vec();
        if out.iter().any(|(k, _)| *k == key) {
            return Err(err(format!(
                "{}: the PSBT has a duplicate key in a map (forbidden by BIP-174)",
                fname
            )));
        }
        out.push((key, value));
    }
}

struct PsbtInput {
    utxo: Option<(u64, Vec<u8>)>, // (amount, scriptPubKey)
    partial_sigs: Vec<(Vec<u8>, Vec<u8>)>,
    sighash_type: Option<u32>,
    final_scriptsig: Option<Vec<u8>>,
    final_witness: Option<Vec<Vec<u8>>>,
    tap_key_sig: Option<Vec<u8>>,
}

struct Psbt {
    tx: RawTx,
    inputs: Vec<PsbtInput>,
}

fn parse_psbt(text: &str, fname: &str) -> Result<Psbt, Control> {
    let data = b64_decode(text.trim())
        .map_err(|e| err(format!("{}: not valid base64: {}", fname, e)))?;
    if data.len() > MAX_TX_BYTES {
        return Err(err(format!(
            "{}: the PSBT is over the {} MB limit — refusing to parse it",
            fname,
            MAX_TX_BYTES / 1_000_000
        )));
    }
    if data.len() < 5 || &data[..5] != PSBT_MAGIC {
        return Err(err(format!(
            "{}: not a PSBT (missing the \"psbt\\xff\" magic); pass the base64 text of a BIP-174 PSBT",
            fname
        )));
    }
    let mut pos = 5usize;
    let global = read_psbt_map(&data, &mut pos, fname)?;
    let mut unsigned: Option<RawTx> = None;
    for (key, value) in &global {
        match key[0] {
            PSBT_GLOBAL_UNSIGNED_TX if key.len() == 1 => {
                let tx = parse_tx(value, fname)?;
                if tx.inputs.iter().any(|i| !i.script_sig.is_empty() || !i.witness.is_empty()) {
                    return Err(err(format!(
                        "{}: the PSBT's unsigned tx already carries signatures (invalid per BIP-174)",
                        fname
                    )));
                }
                unsigned = Some(tx);
            }
            PSBT_GLOBAL_VERSION => {
                return Err(err(format!(
                    "{}: this is a PSBT v2 — only PSBT v0 (BIP-174, the hardware-wallet interchange format) is supported",
                    fname
                )))
            }
            _ => {} // otros globales (xpubs, propietarios) pasan de largo
        }
    }
    let tx = unsigned.ok_or_else(|| {
        err(format!("{}: the PSBT has no unsigned transaction (global key 0x00)", fname))
    })?;
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for i in 0..tx.inputs.len() {
        let map = read_psbt_map(&data, &mut pos, fname)?;
        let mut pin = PsbtInput {
            utxo: None,
            partial_sigs: Vec::new(),
            sighash_type: None,
            final_scriptsig: None,
            final_witness: None,
            tap_key_sig: None,
        };
        for (key, value) in map {
            match key[0] {
                PSBT_IN_WITNESS_UTXO if key.len() == 1 => {
                    let mut p = 0usize;
                    let amount = read_u64le(&value, &mut p, fname)?;
                    let slen = read_varint(&value, &mut p, fname)? as usize;
                    let script = read_bytes(&value, &mut p, slen, fname)?.to_vec();
                    if p != value.len() {
                        return Err(err(format!(
                            "{}: input {} has a malformed witness_utxo",
                            fname, i
                        )));
                    }
                    pin.utxo = Some((amount, script));
                }
                PSBT_IN_NON_WITNESS_UTXO if key.len() == 1 => {
                    // La tx COMPLETA que creó el UTXO → el output que gastamos.
                    let prev = parse_tx(&value, fname)?;
                    let vout = tx.inputs[i].vout as usize;
                    let o = prev.outputs.get(vout).ok_or_else(|| {
                        err(format!(
                            "{}: input {}'s non_witness_utxo has no output {}",
                            fname, i, vout
                        ))
                    })?;
                    if pin.utxo.is_none() {
                        pin.utxo = Some((o.amount, o.script.clone()));
                    }
                }
                PSBT_IN_PARTIAL_SIG => {
                    pin.partial_sigs.push((key[1..].to_vec(), value));
                }
                PSBT_IN_SIGHASH_TYPE if key.len() == 1 && value.len() == 4 => {
                    pin.sighash_type = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                }
                PSBT_IN_FINAL_SCRIPTSIG if key.len() == 1 => {
                    pin.final_scriptsig = Some(value);
                }
                PSBT_IN_FINAL_SCRIPTWITNESS if key.len() == 1 => {
                    let mut p = 0usize;
                    let n = read_varint(&value, &mut p, fname)?;
                    let mut items = Vec::new();
                    for _ in 0..n {
                        let ilen = read_varint(&value, &mut p, fname)? as usize;
                        items.push(read_bytes(&value, &mut p, ilen, fname)?.to_vec());
                    }
                    if p != value.len() {
                        return Err(err(format!(
                            "{}: input {} has a malformed final witness",
                            fname, i
                        )));
                    }
                    pin.final_witness = Some(items);
                }
                PSBT_IN_TAP_KEY_SIG if key.len() == 1 => {
                    if !matches!(value.len(), 64 | 65) {
                        return Err(err(format!(
                            "{}: input {} has a taproot key signature of {} bytes (expected 64 or 65)",
                            fname,
                            i,
                            value.len()
                        )));
                    }
                    pin.tap_key_sig = Some(value);
                }
                _ => {} // campos desconocidos pasan de largo (forward-compat)
            }
        }
        inputs.push(pin);
    }
    for _ in 0..tx.outputs.len() {
        read_psbt_map(&data, &mut pos, fname)?; // mapas de output (se toleran campos)
    }
    if pos != data.len() {
        return Err(err(format!(
            "{}: {} trailing byte(s) after the PSBT",
            fname,
            data.len() - pos
        )));
    }
    Ok(Psbt { tx, inputs })
}

/// scriptPubKey estándar → (kind, program) si es reconocible.
fn classify_script(script: &[u8]) -> Option<(AddrKind, Vec<u8>)> {
    match script {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => {
            Some((AddrKind::P2pkh, h.to_vec()))
        }
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => Some((AddrKind::P2sh, h.to_vec())),
        [0x00, 0x14, p @ ..] if p.len() == 20 => Some((AddrKind::P2wpkh, p.to_vec())),
        [0x00, 0x20, p @ ..] if p.len() == 32 => Some((AddrKind::P2wsh, p.to_vec())),
        [0x51, 0x20, p @ ..] if p.len() == 32 => Some((AddrKind::P2tr, p.to_vec())),
        _ => None,
    }
}

/// (kind, program) → dirección en la red dada.
fn address_of(kind: AddrKind, program: &[u8], network: Network) -> Result<String, Control> {
    Ok(match kind {
        AddrKind::P2pkh | AddrKind::P2sh => {
            let mut payload = Vec::with_capacity(21);
            payload.push(if kind == AddrKind::P2pkh {
                network.p2pkh_version()
            } else {
                network.p2sh_version()
            });
            payload.extend_from_slice(program);
            base58check_encode(&payload)
        }
        AddrKind::P2wpkh | AddrKind::P2wsh => segwit::encode_v0(network.hrp(), program)
            .map_err(|e| err(format!("address encode: {}", e)))?,
        AddrKind::P2tr => segwit::encode_v1(network.hrp(), program)
            .map_err(|e| err(format!("address encode: {}", e)))?,
    })
}

/// `psbt_decode(text, network?)` → map legible (inputs/outputs/amounts/fee) para
/// AUDITAR un PSBT ajeno con `show`/`confirm` ANTES de firmarlo o difundirlo.
fn psbt_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "psbt_decode";
    let text = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the PSBT must be base64 text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let network = Network::parse(args.get(1), F)?;
    let psbt = parse_psbt(&text, F)?;
    let mut m = IndexMap::new();
    m.insert("txid".to_string(), syn_text(txid_of(&psbt.tx)));
    m.insert("version".to_string(), syn_int(psbt.tx.version as i64));
    m.insert("locktime".to_string(), syn_int(psbt.tx.locktime as i64));
    let mut total_in: Option<u64> = Some(0);
    let mut complete = true;
    let inputs: Vec<SynValue> = psbt
        .tx
        .inputs
        .iter()
        .zip(&psbt.inputs)
        .map(|(raw, pin)| {
            let mut im = IndexMap::new();
            let mut display = raw.prev_le;
            display.reverse();
            im.insert("txid".to_string(), syn_text(hex_encode(&display)));
            im.insert("vout".to_string(), syn_int(raw.vout as i64));
            im.insert("sequence".to_string(), syn_int(raw.sequence as i64));
            match &pin.utxo {
                Some((amount, script)) => {
                    im.insert("amount".to_string(), syn_int(*amount as i64));
                    total_in = total_in.map(|t| t + amount);
                    if let Some((kind, program)) = classify_script(script) {
                        im.insert("kind".to_string(), syn_text(kind.as_str()));
                        if let Ok(a) = address_of(kind, &program, network) {
                            im.insert("address".to_string(), syn_text(a));
                        }
                    }
                }
                None => {
                    total_in = None; // sin el UTXO no hay cálculo de fee honesto
                }
            }
            let signed = pin.final_witness.is_some()
                || pin.final_scriptsig.is_some()
                || pin.tap_key_sig.is_some()
                || !pin.partial_sigs.is_empty();
            if !signed {
                complete = false;
            }
            im.insert("signed".to_string(), syn_bool(signed));
            if let Some(sh) = pin.sighash_type {
                im.insert("sighash".to_string(), syn_int(sh as i64));
            }
            syn_map(im)
        })
        .collect();
    m.insert("inputs".to_string(), syn_list(inputs));
    let total_out: u64 = psbt.tx.outputs.iter().map(|o| o.amount).sum();
    let outputs: Vec<SynValue> = psbt
        .tx
        .outputs
        .iter()
        .map(|o| {
            let mut om = IndexMap::new();
            om.insert("amount".to_string(), syn_int(o.amount as i64));
            match classify_script(&o.script) {
                Some((kind, program)) => {
                    om.insert("kind".to_string(), syn_text(kind.as_str()));
                    if let Ok(a) = address_of(kind, &program, network) {
                        om.insert("address".to_string(), syn_text(a));
                    }
                }
                None => {
                    om.insert("script".to_string(), syn_bytes(o.script.clone()));
                }
            }
            syn_map(om)
        })
        .collect();
    m.insert("outputs".to_string(), syn_list(outputs));
    m.insert("total_out".to_string(), syn_int(total_out as i64));
    match total_in {
        Some(tin) => {
            m.insert("total_in".to_string(), syn_int(tin as i64));
            // El fee IMPLÍCITO del PSBT — el número que se AUDITA antes de firmar.
            match tin.checked_sub(total_out) {
                Some(fee) => {
                    m.insert("fee".to_string(), syn_int(fee as i64));
                }
                None => {
                    return Err(err(format!(
                        "{}: the PSBT's outputs exceed its inputs — not a fundable transaction",
                        F
                    )))
                }
            }
        }
        None => {
            m.insert("total_in".to_string(), SynValue::Nothing);
            m.insert("fee".to_string(), SynValue::Nothing);
        }
    }
    m.insert("complete".to_string(), syn_bool(complete));
    Ok(syn_map(m))
}

/// `psbt_finalize(text)` → bytes de la tx lista para `btc_send`, si el PSBT trae
/// las firmas (de una hardware wallet). Cubre P2WPKH (partial_sig) y P2TR
/// key-path (tap_key_sig); un input sin firma → error que lo nombra.
fn psbt_finalize(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "psbt_finalize";
    let text = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the PSBT must be base64 text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let psbt = parse_psbt(&text, F)?;
    let mut tx = psbt.tx;
    for (i, pin) in psbt.inputs.iter().enumerate() {
        if let Some(w) = &pin.final_witness {
            tx.inputs[i].witness = w.clone();
            if let Some(ss) = &pin.final_scriptsig {
                tx.inputs[i].script_sig = ss.clone();
            }
            continue;
        }
        if let Some(sig) = &pin.tap_key_sig {
            tx.inputs[i].witness = vec![sig.clone()];
            continue;
        }
        if !pin.partial_sigs.is_empty() {
            let kind = pin
                .utxo
                .as_ref()
                .and_then(|(_, s)| classify_script(s))
                .map(|(k, _)| k);
            if kind != Some(AddrKind::P2wpkh) {
                return Err(err(format!(
                    "{}: input {} has a partial signature but is not a P2WPKH input — only P2WPKH and taproot key-path finalize here; finalize other types in the signing wallet",
                    F, i
                )));
            }
            if pin.partial_sigs.len() != 1 {
                return Err(err(format!(
                    "{}: input {} has {} partial signatures — multisig does not finalize here",
                    F,
                    i,
                    pin.partial_sigs.len()
                )));
            }
            let (pubkey, sig) = &pin.partial_sigs[0];
            if pubkey.len() != 33 {
                return Err(err(format!(
                    "{}: input {}'s signature is for a {}-byte pubkey (P2WPKH uses compressed 33-byte keys)",
                    F,
                    i,
                    pubkey.len()
                )));
            }
            tx.inputs[i].witness = vec![sig.clone(), pubkey.clone()];
            continue;
        }
        return Err(err(format!(
            "{}: input {} has no signature (no final witness, taproot key sig, or partial sig) — the PSBT is not fully signed yet",
            F, i
        )));
    }
    Ok(syn_bytes(serialize_tx(&tx, true)))
}

// =========================================================
// WIF (Alcance 8) — importar custodia, gateado por `wallet`
// =========================================================

/// `wif_import(text, label?)` → `secret`. G2: no existe el export inverso (el
/// respaldo deliberado es `reveal()` del mnemónico); el error jamás ecoa el WIF.
fn wif_import(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "wif_import";
    let wif = match arg(args, 0, F)? {
        SynValue::Text(s) => s.to_string(),
        SynValue::Secret(inner) => String::from_utf8_lossy(inner.expose_bytes()).into_owned(),
        other => {
            return Err(err(format!(
                "{}: the WIF must be text (or a sealed secret), got {}",
                F,
                other.type_name()
            )))
        }
    };
    let label = opt_label(args.get(1), F, "wif")?;
    gate_wallet(caps, &label, "wif_import", loc)?;
    let mut payload = base58check_decode(wif.trim()).map_err(|e| {
        err(format!(
            "{}: invalid WIF: {}. The WIF value is never shown.",
            F, e
        ))
    })?;
    let result = (|| {
        if payload.is_empty() {
            return Err(err(format!("{}: invalid WIF (empty payload)", F)));
        }
        match payload[0] {
            0x80 | 0xef => {} // mainnet | testnet/signet/regtest
            v => {
                return Err(err(format!(
                    "{}: unknown WIF version byte 0x{:02x} (0x80 mainnet, 0xef testnet). The WIF value is never shown.",
                    F, v
                )))
            }
        }
        let key: Vec<u8> = match payload.len() {
            34 if payload[33] == 0x01 => payload[1..33].to_vec(), // comprimida (la moderna)
            33 => payload[1..33].to_vec(),                        // sin comprimir (legacy)
            34 => {
                return Err(err(format!(
                    "{}: invalid WIF (the compression flag byte must be 0x01). The WIF value is never shown.",
                    F
                )))
            }
            n => {
                return Err(err(format!(
                    "{}: invalid WIF payload length {} (expected 33 or 34 bytes). The WIF value is never shown.",
                    F, n
                )))
            }
        };
        // Validar que sea un escalar secp256k1 real ANTES de sellarlo.
        EcSigningKey::from_slice(&key).map_err(|_| {
            err(format!(
                "{}: the WIF does not hold a valid secp256k1 key. The WIF value is never shown.",
                F
            ))
        })?;
        Ok(key)
    })();
    payload.zeroize();
    let mut key = result?;
    let out = syn_secret_bytes(label, key.to_vec());
    key.zeroize();
    Ok(out)
}

// =========================================================
// Registro
// =========================================================

/// Registra los builtins de Bitcoin. PUROS salvo `schnorr_sign` (capability
/// `sign` + audit — G30, la misma puerta que secp256k1/ed25519) y `wif_import`
/// (capability `wallet` + audit). Wired desde `register_blockchain_builtins`.
pub(crate) fn register(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // -- hash --
    interp.register_builtin(
        "hash160",
        1,
        Rc::new(|_i, a, _l| {
            const F: &str = "hash160";
            let data: &[u8] = match arg(a, 0, F)? {
                SynValue::Bytes(b) => &b[..],
                SynValue::Text(s) => s.as_bytes(),
                SynValue::Secret(_) => {
                    return Err(err(
                        "hash160: cannot hash a secret (use hmac_sha256 for secret-keyed MACs)",
                    ))
                }
                other => {
                    return Err(err(format!(
                        "hash160: expected bytes or text, got {}",
                        other.type_name()
                    )))
                }
            };
            Ok(syn_bytes(hash160(data).to_vec()))
        }),
    );
    // -- direcciones / scripts / txid (puros) --
    interp.register_builtin("btc_address", -1, Rc::new(|_i, a, _l| btc_address(a)));
    interp.register_builtin("btc_address_decode", 1, Rc::new(|_i, a, _l| btc_address_decode(a)));
    interp.register_builtin("btc_script", 1, Rc::new(|_i, a, _l| btc_script(a)));
    interp.register_builtin("btc_txid", 1, Rc::new(|_i, a, _l| btc_txid(a)));
    // -- Schnorr BIP-340 --
    {
        let caps = caps.clone();
        interp.register_builtin(
            "schnorr_sign",
            -1,
            Rc::new(move |_i, a, l| schnorr_sign(a, l, &caps)),
        );
    }
    interp.register_builtin("schnorr_verify", 3, Rc::new(|_i, a, _l| schnorr_verify(a)));
    interp.register_builtin("schnorr_pubkey", 1, Rc::new(|_i, a, _l| schnorr_pubkey(a)));
    // -- builder (puro: G13/G30 — firmar sigue siendo la única puerta) --
    interp.register_builtin("btc_tx", 1, Rc::new(|_i, a, _l| btc_tx(a)));
    interp.register_builtin("btc_tx_raw", 2, Rc::new(|_i, a, _l| btc_tx_raw(a)));
    // -- PSBT (puro) --
    interp.register_builtin("psbt_encode", 1, Rc::new(|_i, a, _l| psbt_encode(a)));
    interp.register_builtin("psbt_decode", -1, Rc::new(|_i, a, _l| psbt_decode(a)));
    interp.register_builtin("psbt_finalize", 1, Rc::new(|_i, a, _l| psbt_finalize(a)));
    // -- WIF (custodia: `wallet` + audit) --
    interp.register_builtin(
        "wif_import",
        -1,
        Rc::new(move |_i, a, l| wif_import(a, l, &caps)),
    );
}

// =========================================================
// Tests — vectores OFICIALES (BIP-143/341/350/84/86) + compuestos (embit 0.8.0)
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_secret_bytes;

    /// `Control` no implementa Debug — unwrap con el mensaje del error.
    fn ok<T>(r: Result<T, Control>) -> T {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control-flow inesperado"),
        }
    }

    fn errmsg<T>(r: Result<T, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.message,
            Ok(_) => panic!("esperaba error, vino Ok"),
            Err(_) => panic!("control-flow inesperado"),
        }
    }

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn get(m: &SynValue, key: &str) -> SynValue {
        match m {
            SynValue::Map(mm) => mm
                .borrow()
                .get(key)
                .cloned()
                .unwrap_or_else(|| panic!("sin clave {}", key)),
            _ => panic!("no es un map"),
        }
    }

    fn get_list(m: &SynValue, key: &str) -> Vec<SynValue> {
        match get(m, key) {
            SynValue::List(l) => l.borrow().clone(),
            _ => panic!("{} no es lista", key),
        }
    }

    fn as_bytes(v: &SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b[..].to_vec(),
            _ => panic!("no es bytes"),
        }
    }

    fn hx(s: &str) -> Vec<u8> {
        hex_decode(s).expect("hex de test")
    }

    // -- BIP-143: el vector Native P2WPKH OFICIAL (bip-0143.mediawiki) --

    #[test]
    fn bip143_official_native_p2wpkh_vector() {
        // La tx sin firmar del BIP; el input 1 es el P2WPKH (value 6 BTC).
        let unsigned = hx("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000");
        let parsed = ok(parse_tx(&unsigned, "t"));
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.locktime, 0x11);
        assert_eq!(parsed.inputs[0].sequence, 0xffffffee);
        // ctx de firma: el amount/script del input 0 (P2PK legacy) no participa
        // del sighash del input 1 — sólo su outpoint y sequence.
        let ctx = SigTxCtx {
            version: parsed.version,
            locktime: parsed.locktime,
            inputs: parsed
                .inputs
                .iter()
                .enumerate()
                .map(|(i, inp)| SigInput {
                    prev_le: inp.prev_le,
                    vout: inp.vout,
                    sequence: inp.sequence,
                    amount: if i == 1 { 600_000_000 } else { 0 },
                    script_pubkey: if i == 1 {
                        hx("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
                    } else {
                        hx("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac")
                    },
                })
                .collect(),
            outputs: parsed
                .outputs
                .iter()
                .map(|o| RawOutput { amount: o.amount, script: o.script.clone() })
                .collect(),
        };
        let sighash = ok(sighash_bip143(&ctx, 1, "t"));
        assert_eq!(
            hex_encode(&sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
            "sigHash != vector oficial BIP-143"
        );
    }

    // -- BIP-341: los vectores keyPathSpending OFICIALES (wallet-test-vectors.json) --

    const KP_RAW: &str = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";

    const KP_UTXOS: [(&str, u64); 9] = [
        ("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000),
        ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000),
        ("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000),
        ("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000),
        ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000),
        ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000),
        ("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000),
        ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000),
        ("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000),
    ];

    /// (txinIndex, hashType, internalPrivkey, merkleRoot, tweakedPrivkey, sigHash, witness).
    const KP_ROWS: [(usize, u8, &str, &str, &str, &str, &str); 7] = [
        (0, 0x03, "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa", "", "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9", "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555", "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03"),
        (1, 0x83, "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f", "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080", "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d", "052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83"),
        (3, 0x01, "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64", "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b", "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d", "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669", "ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a01"),
        (4, 0x00, "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e", "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2", "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501", "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef", "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"),
        (6, 0x02, "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8", "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def", "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901", "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85", "a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee002"),
        (7, 0x82, "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103", "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef", "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b", "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10", "ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c482"),
        (8, 0x81, "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa", "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc", "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5", "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2", "bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd981"),
    ];

    #[test]
    fn bip341_official_key_path_spending_vectors() {
        let parsed = ok(parse_tx(&hx(KP_RAW), "t"));
        assert_eq!(parsed.inputs.len(), 9);
        let ctx = SigTxCtx {
            version: parsed.version,
            locktime: parsed.locktime,
            inputs: parsed
                .inputs
                .iter()
                .zip(KP_UTXOS.iter())
                .map(|(inp, (spk, amount))| SigInput {
                    prev_le: inp.prev_le,
                    vout: inp.vout,
                    sequence: inp.sequence,
                    amount: *amount,
                    script_pubkey: hx(spk),
                })
                .collect(),
            outputs: parsed
                .outputs
                .iter()
                .map(|o| RawOutput { amount: o.amount, script: o.script.clone() })
                .collect(),
        };
        for (idx, hash_type, privkey, merkle, tweaked, sighash, witness) in KP_ROWS {
            let sh = ok(sighash_bip341(&ctx, idx, hash_type, "t"));
            assert_eq!(hex_encode(&sh), sighash, "sigHash input {} != vector", idx);
            let merkle_bytes = if merkle.is_empty() { None } else { Some(hx(merkle)) };
            let d2 = ok(tap_tweaked_scalar(&hx(privkey), merkle_bytes.as_deref(), "t"));
            assert_eq!(
                hex_encode(&d2.to_bytes()),
                tweaked,
                "tweakedPrivkey input {} != vector",
                idx
            );
            // La firma esperada del vector usa aux = 0 — el MISMO determinismo
            // de schnorr_sign. Byte-exacta o falla.
            let sk = ok(tap_tweaked_signing_key(&hx(privkey), merkle_bytes.as_deref(), "t"));
            let sig = sk.sign_raw(&sh, &SCHNORR_AUX).expect("firma");
            let want = hx(witness);
            assert_eq!(&want[..64], &sig.to_bytes()[..], "firma input {} != vector", idx);
            if hash_type != 0 {
                assert_eq!(want[64], hash_type, "hashtype byte input {}", idx);
            } else {
                assert_eq!(want.len(), 64, "SIGHASH_DEFAULT no lleva byte extra");
            }
        }
    }

    /// (internalPubkey, merkleRoot, tweakedPubkey, address) — sección scriptPubKey.
    const SPK_ROWS: [(&str, &str, &str, &str); 7] = [
        ("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", "", "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"),
        ("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586"),
        ("93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820", "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b", "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5"),
        ("ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592", "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef", "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm"),
        ("f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8", "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc", "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq"),
        ("e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f", "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2", "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e"),
        ("55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d", "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def", "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe"),
    ];

    #[test]
    fn bip341_official_tweak_and_address_vectors() {
        for (internal, merkle, tweaked, address) in SPK_ROWS {
            let x: [u8; 32] = hx(internal).try_into().unwrap();
            let merkle_bytes = if merkle.is_empty() { None } else { Some(hx(merkle)) };
            let (out, _parity) = ok(tap_output_key(&x, merkle_bytes.as_deref(), "t"));
            assert_eq!(hex_encode(&out), tweaked, "tweakedPubkey != vector");
            if merkle.is_empty() {
                // La dirección key-path (merkle vacío) es la que emite btc_address.
                let a = ok(btc_address(&[syn_bytes(x.to_vec()), syn_text("p2tr")]));
                assert_eq!(a.to_string(), address);
            }
        }
    }

    #[test]
    fn schnorr_aux_is_pinned_to_bip340_vector_zero() {
        // El determinismo documentado: aux = 32 bytes cero ⇒ el vector 0 de
        // BIP-340 byte a byte. Si el aux cambia, esto rompe.
        let sk = schnorr::SigningKey::from_bytes(&hx(
            "0000000000000000000000000000000000000000000000000000000000000003",
        ))
        .unwrap();
        let sig = sk.sign_raw(&[0u8; 32], &SCHNORR_AUX).unwrap();
        assert_eq!(
            hex_encode(&sig.to_bytes()).to_uppercase(),
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        );
    }

    // -- BIP-84 / BIP-86: las direcciones OFICIALES del mnemónico estándar --

    #[test]
    fn bip84_official_addresses() {
        // (pubkey, address) de bip-0084.mediawiki.
        let rows = [
            ("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            ("03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
            ("03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
        ];
        for (pk, addr) in rows {
            let a = ok(btc_address(&[syn_bytes(hx(pk))]));
            assert_eq!(a.to_string(), addr);
        }
        // Desde el SECRET (la clave del path 0, generada con embit del mismo
        // mnemónico): deriva la pubkey sin materializar nada.
        let k = syn_secret_bytes(
            "K",
            hx("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"),
        );
        let a = ok(btc_address(&[k]));
        assert_eq!(a.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn bip86_official_addresses() {
        // (internal_key x-only, address) de bip-0086.mediawiki.
        let rows = [
            ("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            ("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
            ("399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"),
        ];
        for (xk, addr) in rows {
            let a = ok(btc_address(&[syn_bytes(hx(xk)), syn_text("p2tr")]));
            assert_eq!(a.to_string(), addr);
        }
        // Desde el secret del path 0 (embit, mismo mnemónico).
        let k = syn_secret_bytes(
            "K",
            hx("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"),
        );
        let a = ok(btc_address(&[k, syn_text("p2tr")]));
        assert_eq!(a.to_string(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    }

    // -- BIP-350: direcciones válidas e inválidas OFICIALES --

    #[test]
    fn bip350_official_valid_v0_v1_addresses() {
        // Las filas v0/v1 estándar decodifican y su scriptPubKey coincide.
        let rows = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6", "p2wpkh", "mainnet"),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", "p2wsh", "testnet"),
            ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", "p2wsh", "testnet"),
            ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", "p2tr", "testnet"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "p2tr", "mainnet"),
        ];
        for (addr, script, kind, network) in rows {
            let d = ok(btc_address_decode(&[syn_text(addr)]));
            assert_eq!(get(&d, "kind").to_string(), kind, "{}", addr);
            assert_eq!(get(&d, "network").to_string(), network, "{}", addr);
            let s = ok(btc_script(&[syn_text(addr)]));
            assert_eq!(hex_encode(&as_bytes(&s)), script, "{}", addr);
        }
        // Válidas por BIP-350 pero NO estándar (v1 de 40 bytes, v16, v2): se
        // rechazan con error dirigido — nadie puede gastarlas hoy.
        for addr in [
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "BC1SW50QGDZ25J",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        ] {
            let e = errmsg(btc_address_decode(&[syn_text(addr)]));
            assert!(e.contains("witness") || e.contains("program"), "{}: {}", addr, e);
        }
    }

    #[test]
    fn bip350_official_invalid_addresses_all_rejected() {
        // La lista COMPLETA de inválidas de bip-0350.mediawiki.
        let invalid = [
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            "bc1pw5dgrnzv",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            "bc1gmk9yu",
        ];
        for addr in invalid {
            assert!(btc_address_decode(&[syn_text(addr)]).is_err(), "debió rechazar {:?}", addr);
        }
    }

    #[test]
    fn base58check_and_wif_structure() {
        // Roundtrip + un carácter cambiado rompe el checksum.
        let payload = hx("00c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2");
        let s = base58check_encode(&payload);
        assert_eq!(base58check_decode(&s).unwrap(), payload);
        let mut corrupted = s.clone();
        corrupted.replace_range(3..4, if &s[3..4] == "x" { "y" } else { "x" });
        assert!(base58check_decode(&corrupted).is_err());
        // El WIF OFICIAL de BIP-84 (m/84'/0'/0'/0/0): versión 0x80, clave
        // conocida, flag comprimido 0x01.
        let p = base58check_decode("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d").unwrap();
        assert_eq!(p[0], 0x80);
        assert_eq!(
            hex_encode(&p[1..33]),
            "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"
        );
        assert_eq!(p[33], 0x01);
    }

    #[test]
    fn compact_size_canonical_enforced() {
        let mut out = Vec::new();
        for n in [0u64, 0xfc, 0xfd, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000] {
            out.clear();
            write_varint(n, &mut out);
            let mut pos = 0;
            assert_eq!(ok(read_varint(&out, &mut pos, "t")), n);
            assert_eq!(pos, out.len());
        }
        // 16 codificado con la forma 0xfd → no canónico → error.
        let bad = [0xfdu8, 0x10, 0x00];
        let mut pos = 0;
        assert!(read_varint(&bad, &mut pos, "t").is_err());
    }

    // -- Vectores COMPUESTOS (embit 0.8.0, mnemónico estándar, schnorr aux=0) --

    const VEC_W_RAW: &str = "02000000000102cdb19716824445f00f6aafa3e750a6bca5c7165afff5614ef75000a395a7e20b0000000000fdffffff845cd043bdbe1a6de3586cdfd9f17586cf1d0bd222231bb99ed57ca5d91e78fd0100000000fdffffff0270110100000000001976a914c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e288ac3c730000000000001600143e34985dca6fddc9fb369940e4c7d8e2873f529c02473044022026790f43a716975857a55620caf6ca646389dd3fed3563e87826173529184e3002206fac336ad92eaec43299931321fd491f3e78ecb1ffc1155a06fd5a638c98e85901210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c02473044022006f42a574075a32f6e2b8263d04f9f16768d5b10f3d9dec0d06dde1f654fe3ad02203f513b5569af26f216810fa94d4e81763a6409f15b30b4b1020959e03f3bc062012103e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea7700000000";
    const VEC_W_TXID: &str = "6aa99c206cc4c51bc1f64fe11fb70833bc43d4bced76bab7e9bf53022da55695";
    const VEC_T_RAW: &str = "02000000000101a7a00bf2ed15f21c107126686d7662e9eef23c295b8bb746146277e5ced6f4f00000000000fdffffff023075000000000000225120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbbf44c000000000000225120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc0140e077ce8461ab91733cf7249e79e7e47ee198205eb0b53366e2646973b6f9f84cc1c12732d02264d3d06c1e04091e2a3312432914b2f46b73251e80ec59db222c00000000";
    const VEC_T_TXID: &str = "d98a84d0e281fd79a1b290a87ba19e8f434f392b5b2c47e60c7ea4556bedc3eb";
    const VEC_M_RAW: &str = "0200000000010269b5864e028ad77207a65b8d1dda0355e0f67666b5fda21557d9b164fbec2ebe0300000000fdffffff40552d4e072d0254d82af774e887f7fa18d23d2638e03a7c6cab53da79c9f8c80000000000fdffffff01f8c00000000000001600149c90f934ea51fa0f6504177043e0908da69299830247304402203657d8c554568a92e414f2a2b48ee0a1b01c966a90eadd3de8138d1178bdd49002206a3fa53f8356af34f880cb2c4d992c0f3905075f742c2bd17bec2d418c74634301210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c0140f4c2f828519496f4f69585cca6206cc989a4e34d33b9a8cdad7dee5f5d9f7c50bb194a0d5cc5478403a979c5656312abc4e70981967be5b1bf60a08bb469833b00000000";
    const VEC_M_TXID: &str = "f5542775bbbfbbc7d2e920c348cb464fc2cd2f836c72d09e388bc050622a81b6";

    const KEY_84_0: &str = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";
    const KEY_84_1: &str = "2fd0affa51529f940a358ec0c50de81267d0bf5158ca61887347676946362c5b";
    const KEY_86_0: &str = "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361";
    const PUB_84_0: &str = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
    const PUB_84_1: &str = "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77";

    fn vec_w_params() -> SynValue {
        map(vec![
            ("inputs", syn_list(vec![
                map(vec![
                    ("txid", syn_text("0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd")),
                    ("vout", syn_int(0)),
                    ("amount", syn_int(60000)),
                    ("address", syn_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")),
                    ("pubkey", syn_bytes(hx(PUB_84_0))),
                ]),
                map(vec![
                    ("txid", syn_text("fd781ed9a57cd59eb91b2322d20b1dcf8675f1d9df6c58e36d1abebd43d05c84")),
                    ("vout", syn_int(1)),
                    ("amount", syn_int(40000)),
                    ("address", syn_text("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")),
                    ("pubkey", syn_bytes(hx(PUB_84_1))),
                ]),
            ])),
            ("outputs", syn_list(vec![
                map(vec![
                    ("address", syn_text("1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso")),
                    ("amount", syn_int(70000)),
                ]),
                map(vec![
                    ("address", syn_text("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")),
                    ("amount", syn_int(29500)),
                ]),
            ])),
            ("fee", syn_int(500)),
        ])
    }

    fn vec_t_params() -> SynValue {
        map(vec![
            ("inputs", syn_list(vec![map(vec![
                ("txid", syn_text("f0f4d6cee577621446b78b5b293cf2eee962766d682671101cf215edf20ba0a7")),
                ("vout", syn_int(0)),
                ("amount", syn_int(50000)),
                ("address", syn_text("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")),
            ])])),
            ("outputs", syn_list(vec![
                map(vec![
                    ("address", syn_text("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh")),
                    ("amount", syn_int(30000)),
                ]),
                map(vec![
                    ("address", syn_text("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")),
                    ("amount", syn_int(19700)),
                ]),
            ])),
            ("fee", syn_int(300)),
        ])
    }

    /// Firma ECDSA como lo haría `secp256k1_sign` (RFC 6979, r‖s‖recid).
    fn ecdsa_sign65(key_hex: &str, digest: &[u8]) -> Vec<u8> {
        let sk = EcSigningKey::from_slice(&hx(key_hex)).unwrap();
        let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(recid.to_byte());
        out
    }

    /// Firma Schnorr key-path como `schnorr_sign(d, k, "taproot")`.
    fn taproot_sign64(key_hex: &str, digest: &[u8]) -> Vec<u8> {
        let sk = ok(tap_tweaked_signing_key(&hx(key_hex), None, "t"));
        sk.sign_raw(digest, &SCHNORR_AUX).unwrap().to_bytes().to_vec()
    }

    #[test]
    fn builder_p2wpkh_matches_embit_vector_byte_for_byte() {
        let tx = ok(btc_tx(&[vec_w_params()]));
        // Eco G28: los números a la vista para el confirm.
        assert_eq!(get(&tx, "fee").to_string(), "500");
        assert_eq!(get(&tx, "total_in").to_string(), "100000");
        assert_eq!(get(&tx, "total_out").to_string(), "99500");
        let digests = get_list(&tx, "digests");
        assert_eq!(
            hex_encode(&as_bytes(&digests[0])),
            "73aec89898beb3b9c365e221f5701b46b8452d56f6f18b290f8c0325e4d9c09e"
        );
        assert_eq!(
            hex_encode(&as_bytes(&digests[1])),
            "14a26540a49a228626d4aff98add5ad901b3c0771b837714354e6a954123b125"
        );
        let sigs = syn_list(vec![
            syn_bytes(ecdsa_sign65(KEY_84_0, &as_bytes(&digests[0]))),
            syn_bytes(ecdsa_sign65(KEY_84_1, &as_bytes(&digests[1]))),
        ]);
        let raw = ok(btc_tx_raw(&[tx, sigs]));
        assert_eq!(hex_encode(&as_bytes(&raw)), VEC_W_RAW, "raw != vector embit");
        let txid = ok(btc_txid(&[raw]));
        assert_eq!(txid.to_string(), VEC_W_TXID);
    }

    #[test]
    fn builder_p2tr_matches_embit_vector_byte_for_byte() {
        let tx = ok(btc_tx(&[vec_t_params()]));
        let digests = get_list(&tx, "digests");
        assert_eq!(
            hex_encode(&as_bytes(&digests[0])),
            "8638bb5b0890bb9a7afb7ea23fb668c60084f064c60a3646a566fce8cfc89b3f"
        );
        let sigs = syn_list(vec![syn_bytes(taproot_sign64(KEY_86_0, &as_bytes(&digests[0])))]);
        let raw = ok(btc_tx_raw(&[tx, sigs]));
        assert_eq!(hex_encode(&as_bytes(&raw)), VEC_T_RAW, "raw != vector embit");
        assert_eq!(ok(btc_txid(&[raw])).to_string(), VEC_T_TXID);
    }

    #[test]
    fn builder_mixed_p2wpkh_p2tr_matches_embit_vector() {
        let params = map(vec![
            ("inputs", syn_list(vec![
                map(vec![
                    ("txid", syn_text("be2eecfb64b1d95715a2fdb56676f6e05503da1d8d5ba60772d78a024e86b569")),
                    ("vout", syn_int(3)),
                    ("amount", syn_int(25000)),
                    ("address", syn_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")),
                    ("pubkey", syn_bytes(hx(PUB_84_0))),
                ]),
                map(vec![
                    ("txid", syn_text("c8f8c979da53ab6c7c3ae038263dd218faf787e874f72ad854022d074e2d5540")),
                    ("vout", syn_int(0)),
                    ("amount", syn_int(25000)),
                    ("address", syn_text("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")),
                    // El cross-check p2tr: la interna (33 bytes sec) tweakea al program.
                    ("pubkey", syn_bytes(hx("03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"))),
                ]),
            ])),
            ("outputs", syn_list(vec![map(vec![
                ("address", syn_text("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")),
                ("amount", syn_int(49400)),
            ])])),
            ("fee", syn_int(600)),
        ]);
        let tx = ok(btc_tx(&[params]));
        let digests = get_list(&tx, "digests");
        // Los digests (la parte DETERMINISTA, definida por el consenso) coinciden
        // con embit byte a byte.
        assert_eq!(
            hex_encode(&as_bytes(&digests[0])),
            "355b330e7835ac2225f71d3d395b7a5726691fc3216f4049b691105defdf5e7c"
        );
        assert_eq!(
            hex_encode(&as_bytes(&digests[1])),
            "22ac05766e0c51c2b7517ecae744e9c72b7c436b8fa2a94bd15e292a242ff00d"
        );
        let sigs = syn_list(vec![
            syn_bytes(ecdsa_sign65(KEY_84_0, &as_bytes(&digests[0]))),
            syn_bytes(taproot_sign64(KEY_86_0, &as_bytes(&digests[1]))),
        ]);
        let raw = ok(btc_tx_raw(&[tx, sigs]));
        // El TXID excluye el witness (BIP-141) → es independiente de la política
        // de nonce del firmante y coincide con embit exacto.
        assert_eq!(ok(btc_txid(std::slice::from_ref(&raw))).to_string(), VEC_M_TXID);
        // La estructura no-witness es byte-exacta contra embit; sólo las firmas
        // ECDSA difieren porque embit hace low-R grinding (BIP-62) y k256 usa
        // RFC-6979 puro — ambas VÁLIDAS. Se confirma re-parseando y verificando
        // cada witness contra su digest (btc_tx_raw ya lo hizo internamente).
        let parsed = ok(parse_tx(&as_bytes(&raw), "t"));
        assert_eq!(hex_encode(&serialize_tx(&parsed, false)), {
            let embit = ok(parse_tx(&hx(VEC_M_RAW), "t"));
            hex_encode(&serialize_tx(&embit, false))
        });
        // El input taproot (Schnorr determinista, sin grinding) SÍ es byte-exacto.
        let embit = ok(parse_tx(&hx(VEC_M_RAW), "t"));
        assert_eq!(parsed.inputs[1].witness, embit.inputs[1].witness);
    }

    /// La firma ECDSA byte-exacta AUTORITATIVA: k256 (RFC-6979 puro, low-s)
    /// reproduce la firma OFICIAL del vector Native P2WPKH de BIP-143. Esto ancla
    /// el camino de firma a la fuente BIP, no a lo que produce embit (que además
    /// hace low-R grinding).
    #[test]
    fn bip143_official_signature_is_byte_exact() {
        let key = hx("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        let digest = hx("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        let sig = ecdsa_sign65(&hex_encode(&key), &digest);
        let der = ok(ecdsa_der_with_hashtype(&sig[..64], 0, "t"));
        assert_eq!(
            hex_encode(&der),
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
            "la firma ECDSA no coincide con el vector oficial BIP-143"
        );
    }

    #[test]
    fn vsize_estimate_brackets_actual_size() {
        // El estimado (DER de 72) acota por ARRIBA el real (DER de 71/72) y no
        // se aleja más de unos bytes — sirve para fee = vsize × rate.
        let tx = ok(btc_tx(&[vec_w_params()]));
        let est = match get(&tx, "vsize") {
            SynValue::Number(n) => n.to_i64_trunc().unwrap() as u64,
            _ => panic!("vsize"),
        };
        let raw = hx(VEC_W_RAW);
        let parsed = ok(parse_tx(&raw, "t"));
        let base = serialize_tx(&parsed, false).len() as u64;
        let actual = (3 * base + raw.len() as u64).div_ceil(4);
        assert!(est >= actual && est <= actual + 4, "est {} vs actual {}", est, actual);
    }

    #[test]
    fn rbf_and_locktime_are_honored() {
        // rbf default true → sequence 0xFFFFFFFD (ya cubierto por el vector);
        // rbf false → 0xFFFFFFFE; locktime viaja al serializado.
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            m.borrow_mut().insert("rbf".to_string(), syn_bool(false));
            m.borrow_mut().insert("locktime".to_string(), syn_int(850_000));
        }
        let tx = ok(btc_tx(&[params]));
        let digests = get_list(&tx, "digests");
        let sigs = syn_list(vec![
            syn_bytes(ecdsa_sign65(KEY_84_0, &as_bytes(&digests[0]))),
            syn_bytes(ecdsa_sign65(KEY_84_1, &as_bytes(&digests[1]))),
        ]);
        let raw = ok(btc_tx_raw(&[tx, sigs]));
        let parsed = ok(parse_tx(&as_bytes(&raw), "t"));
        assert_eq!(parsed.inputs[0].sequence, 0xFFFF_FFFE);
        assert_eq!(parsed.locktime, 850_000);
    }

    // -- G28 hostil: cada guarda con su error dirigido --

    #[test]
    fn g28_missing_fee_names_the_footgun() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            m.borrow_mut().shift_remove("fee");
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("G28") && e.contains("fee"), "{}", e);
    }

    #[test]
    fn g28_forgotten_change_names_exact_difference() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            // Sin el output de vuelto: 100000 != 70000 + 500 → sobran 29500.
            let outs = syn_list(vec![map(vec![
                ("address", syn_text("1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso")),
                ("amount", syn_int(70000)),
            ])]);
            m.borrow_mut().insert("outputs".to_string(), outs);
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("29500") && e.contains("change output") && e.contains("G28"), "{}", e);
    }

    #[test]
    fn g28_unfunded_names_exact_difference() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            m.borrow_mut().insert("fee".to_string(), syn_int(600));
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("100") && e.contains("cannot be funded"), "{}", e);
    }

    #[test]
    fn g28_dust_output_names_the_limit() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            let outs = syn_list(vec![
                map(vec![
                    ("address", syn_text("1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso")),
                    ("amount", syn_int(99300)),
                ]),
                map(vec![
                    ("address", syn_text("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")),
                    ("amount", syn_int(200)), // bajo el dust de p2wpkh (294)
                ]),
            ]);
            m.borrow_mut().insert("outputs".to_string(), outs);
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("dust") && e.contains("294"), "{}", e);
    }

    #[test]
    fn g28_absurd_fee_requires_explicit_override() {
        let params = |absurd: bool| {
            let mut pairs = vec![
                ("inputs", syn_list(vec![map(vec![
                    ("txid", syn_text("0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd")),
                    ("vout", syn_int(0)),
                    ("amount", syn_int(60000)),
                    ("address", syn_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")),
                    ("pubkey", syn_bytes(hx(PUB_84_0))),
                ])])),
                ("outputs", syn_list(vec![map(vec![
                    ("address", syn_text("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")),
                    ("amount", syn_int(1000)),
                ])])),
                ("fee", syn_int(59000)), // fee ≫ lo enviado
            ];
            if absurd {
                pairs.push(("allow_absurd_fee", syn_bool(true)));
            }
            map(pairs)
        };
        let e = errmsg(btc_tx(&[params(false)]));
        assert!(e.contains("allow_absurd_fee"), "{}", e);
        assert!(btc_tx(&[params(true)]).is_ok(), "el override explícito debe pasar");
    }

    #[test]
    fn g29_float_amount_rejected_with_conversion_hint() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            let outs = syn_list(vec![map(vec![
                ("address", syn_text("1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso")),
                ("amount", syn_number(Number::Float(0.1))),
            ])]);
            m.borrow_mut().insert("outputs".to_string(), outs);
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("100_000_000") && e.contains("sats"), "{}", e);
    }

    #[test]
    fn g29_cross_network_send_rejected_naming_both() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            let outs = syn_list(vec![map(vec![
                // p2wpkh de TESTNET dentro de una tx de mainnet.
                ("address", syn_text("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")),
                ("amount", syn_int(99500)),
            ])]);
            m.borrow_mut().insert("outputs".to_string(), outs);
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("testnet") && e.contains("mainnet"), "{}", e);
    }

    #[test]
    fn sighash_param_gets_directed_error() {
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            m.borrow_mut().insert("sighash".to_string(), syn_int(2));
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("SIGHASH_ALL") && e.contains("out of scope"), "{}", e);
    }

    #[test]
    fn duplicate_outpoint_rejected() {
        let dup = map(vec![
            ("txid", syn_text("0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd")),
            ("vout", syn_int(0)),
            ("amount", syn_int(100000)),
            ("address", syn_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")),
            ("pubkey", syn_bytes(hx(PUB_84_0))),
        ]);
        let params = map(vec![
            ("inputs", syn_list(vec![dup.clone(), dup])),
            ("outputs", syn_list(vec![map(vec![
                ("address", syn_text("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")),
                ("amount", syn_int(199500)),
            ])])),
            ("fee", syn_int(500)),
        ]);
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("duplicate"), "{}", e);
    }

    #[test]
    fn spending_from_legacy_or_wrong_key_rejected() {
        // Gastar DESDE p2pkh: fuera de alcance con error dirigido.
        let params = map(vec![
            ("inputs", syn_list(vec![map(vec![
                ("txid", syn_text("0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd")),
                ("vout", syn_int(0)),
                ("amount", syn_int(60000)),
                ("address", syn_text("1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso")),
            ])])),
            ("outputs", syn_list(vec![map(vec![
                ("address", syn_text("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")),
                ("amount", syn_int(59500)),
            ])])),
            ("fee", syn_int(500)),
        ]);
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("out of scope"), "{}", e);
        // Sin pubkey en un input p2wpkh → error que explica el porqué.
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            let mut in0 = match &get_list(&params, "inputs")[0] {
                SynValue::Map(im) => im.borrow().clone(),
                _ => panic!(),
            };
            in0.shift_remove("pubkey");
            let in1 = get_list(&params, "inputs")[1].clone();
            m.borrow_mut().insert("inputs".to_string(), syn_list(vec![syn_map(in0), in1]));
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("pubkey"), "{}", e);
        // Pubkey que NO hashea a la dirección → rechazo.
        let params = vec_w_params();
        if let SynValue::Map(m) = &params {
            let mut in0 = match &get_list(&params, "inputs")[0] {
                SynValue::Map(im) => im.borrow().clone(),
                _ => panic!(),
            };
            in0.insert("pubkey".to_string(), syn_bytes(hx(PUB_84_1)));
            let in1 = get_list(&params, "inputs")[1].clone();
            m.borrow_mut().insert("inputs".to_string(), syn_list(vec![syn_map(in0), in1]));
        }
        let e = errmsg(btc_tx(&[params]));
        assert!(e.contains("does not hash"), "{}", e);
    }

    #[test]
    fn tx_raw_verifies_signatures_before_assembly() {
        let tx = ok(btc_tx(&[vec_w_params()]));
        let digests = get_list(&tx, "digests");
        // Cantidad equivocada.
        let one = syn_list(vec![syn_bytes(ecdsa_sign65(KEY_84_0, &as_bytes(&digests[0])))]);
        let e = errmsg(btc_tx_raw(&[tx.clone(), one]));
        assert!(e.contains("PER INPUT"), "{}", e);
        // Firma con la CLAVE equivocada → se detecta ANTES de difundir.
        let bad = syn_list(vec![
            syn_bytes(ecdsa_sign65(KEY_84_1, &as_bytes(&digests[0]))), // clave cruzada
            syn_bytes(ecdsa_sign65(KEY_84_1, &as_bytes(&digests[1]))),
        ]);
        let e = errmsg(btc_tx_raw(&[tx.clone(), bad]));
        assert!(e.contains("does not verify"), "{}", e);
        // Firma taproot SIN tweak sobre un input p2tr → error con la pista.
        let tx_t = ok(btc_tx(&[vec_t_params()]));
        let d = get_list(&tx_t, "digests");
        let untweaked = schnorr::SigningKey::from_bytes(&hx(KEY_86_0))
            .unwrap()
            .sign_raw(&as_bytes(&d[0]), &SCHNORR_AUX)
            .unwrap();
        let e = errmsg(btc_tx_raw(&[
            tx_t,
            syn_list(vec![syn_bytes(untweaked.to_bytes().to_vec())]),
        ]));
        assert!(e.contains("TWEAKED") && e.contains("taproot"), "{}", e);
    }

    // -- PSBT: byte-exacto contra embit + decode/finalize --

    const PSBT_W_UNSIGNED: &str = "cHNidP8BAJ0CAAAAAs2xlxaCREXwD2qvo+dQprylxxZa//VhTvdQAKOVp+ILAAAAAAD9////hFzQQ72+Gm3jWGzf2fF1hs8dC9IiIxu5ntV8pdkeeP0BAAAAAP3///8CcBEBAAAAAAAZdqkUwM681sPTyox13F7GLr5VMw75EOKIrDxzAAAAAAAAFgAUPjSYXcpv3cn7NplA5MfY4oc/UpwAAAAAAAEBH2DqAAAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAQEfQJwAAAAAAAAWABSckPk06lH6D2UEF3BD4JCNppKZgwAAAA==";
    const PSBT_W_SIGNED: &str = "cHNidP8BAJ0CAAAAAs2xlxaCREXwD2qvo+dQprylxxZa//VhTvdQAKOVp+ILAAAAAAD9////hFzQQ72+Gm3jWGzf2fF1hs8dC9IiIxu5ntV8pdkeeP0BAAAAAP3///8CcBEBAAAAAAAZdqkUwM681sPTyox13F7GLr5VMw75EOKIrDxzAAAAAAAAFgAUPjSYXcpv3cn7NplA5MfY4oc/UpwAAAAAAAEBH2DqAAAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIiAgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPEcwRAIgJnkPQ6cWl1hXpVYgyvbKZGOJ3T/tNWPoeCYXNSkYTjACIG+sM2rZLq7EMpmTEyH9SR8+eOyx/8EVWgb9WmOMmOhZAQABAR9AnAAAAAAAABYAFJyQ+TTqUfoPZQQXcEPgkI2mkpmDIgID53X9UfDfuM2GXZ/xzKKhWM9lH+mX/cn+6cHTtemV6ndHMEQCIAb0KldAdaMvbiuCY9BPnxZ2jVsQ89newNBt3h9lT+OtAiA/UTtVaa8m8haBD6lNToF2OmQJ8VswtLECCVngPzvAYgEAAAA=";
    const PSBT_T_UNSIGNED: &str = "cHNidP8BAIkCAAAAAaegC/LtFfIcEHEmaG12Yunu8jwpW4u3RhRid+XO1vTwAAAAAAD9////AjB1AAAAAAAAIlEgqC8plE1luGrmteXMdeKU6tbFk5Gh7cXgFuNJjGf8e7v0TAAAAAAAACJRIIgtdOXQVy1agWzvAEGpa2wd6DL2+WdtlgXETV6al9PcAAAAAAABAStQwwAAAAAAACJRIKYIafDbzx3GWcnOy6+AUBNeqejNxIcFPx3GiAlJ3GhMAAAA";
    const PSBT_T_SIGNED: &str = "cHNidP8BAIkCAAAAAaegC/LtFfIcEHEmaG12Yunu8jwpW4u3RhRid+XO1vTwAAAAAAD9////AjB1AAAAAAAAIlEgqC8plE1luGrmteXMdeKU6tbFk5Gh7cXgFuNJjGf8e7v0TAAAAAAAACJRIIgtdOXQVy1agWzvAEGpa2wd6DL2+WdtlgXETV6al9PcAAAAAAABAStQwwAAAAAAACJRIKYIafDbzx3GWcnOy6+AUBNeqejNxIcFPx3GiAlJ3GhMAQhCAUDgd86EYauRczz3JJ555+R+4ZggXrC1M2biZGlztvn4TMHBJzLQImTT0GweBAkeKjMSQykUsvRrcyUegOxZ2yIsAAAA";

    #[test]
    fn psbt_encode_matches_embit_byte_for_byte() {
        let tx = ok(btc_tx(&[vec_w_params()]));
        let psbt = ok(psbt_encode(&[tx]));
        assert_eq!(psbt.to_string(), PSBT_W_UNSIGNED, "PSBT != embit");
        let tx_t = ok(btc_tx(&[vec_t_params()]));
        let psbt_t = ok(psbt_encode(&[tx_t]));
        assert_eq!(psbt_t.to_string(), PSBT_T_UNSIGNED, "PSBT taproot != embit");
    }

    #[test]
    fn psbt_decode_audits_amounts_fee_and_signed_state() {
        // El PSBT sin firmar: fee implícito 500, nada firmado.
        let d = ok(psbt_decode(&[syn_text(PSBT_W_UNSIGNED)]));
        assert_eq!(get(&d, "fee").to_string(), "500");
        assert_eq!(get(&d, "total_in").to_string(), "100000");
        assert_eq!(get(&d, "total_out").to_string(), "99500");
        assert_eq!(get(&d, "txid").to_string(), VEC_W_TXID);
        assert!(matches!(get(&d, "complete"), SynValue::Bool(false)));
        let ins = get_list(&d, "inputs");
        assert!(matches!(get(&ins[0], "signed"), SynValue::Bool(false)));
        assert_eq!(get(&ins[0], "amount").to_string(), "60000");
        assert_eq!(
            get(&ins[0], "address").to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let outs = get_list(&d, "outputs");
        assert_eq!(get(&outs[0], "kind").to_string(), "p2pkh");
        assert_eq!(
            get(&outs[1], "address").to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
        // El firmado: signed true y complete true.
        let d = ok(psbt_decode(&[syn_text(PSBT_W_SIGNED)]));
        assert!(matches!(get(&d, "complete"), SynValue::Bool(true)));
        let ins = get_list(&d, "inputs");
        assert!(matches!(get(&ins[0], "signed"), SynValue::Bool(true)));
    }

    #[test]
    fn psbt_finalize_reproduces_the_signed_raw() {
        // P2WPKH: partial_sigs de embit → la MISMA raw del vector.
        let raw = ok(psbt_finalize(&[syn_text(PSBT_W_SIGNED)]));
        assert_eq!(hex_encode(&as_bytes(&raw)), VEC_W_RAW);
        // Taproot: final_scriptwitness → la raw del vector T.
        let raw = ok(psbt_finalize(&[syn_text(PSBT_T_SIGNED)]));
        assert_eq!(hex_encode(&as_bytes(&raw)), VEC_T_RAW);
        // Sin firmas → error que nombra el input.
        let e = errmsg(psbt_finalize(&[syn_text(PSBT_W_UNSIGNED)]));
        assert!(e.contains("input 0") && e.contains("no signature"), "{}", e);
    }

    #[test]
    fn psbt_hostile_inputs_rejected() {
        // No-base64 y magic ausente.
        assert!(psbt_decode(&[syn_text("no es un psbt!!")]).is_err());
        let e = errmsg(psbt_decode(&[syn_text(b64_encode(b"hola mundo hola mundo"))]));
        assert!(e.contains("psbt"), "{}", e);
        // PSBT v2 → error dirigido.
        let mut v2 = Vec::new();
        v2.extend_from_slice(PSBT_MAGIC);
        v2.extend_from_slice(&[0x01, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00]);
        let e = errmsg(psbt_decode(&[syn_text(b64_encode(&v2))]));
        assert!(e.contains("v2"), "{}", e);
        // Truncado.
        let cut = b64_decode(PSBT_W_UNSIGNED).unwrap();
        let e = errmsg(psbt_decode(&[syn_text(b64_encode(&cut[..cut.len() - 10]))]));
        assert!(
            e.contains("truncated") || e.contains("trailing") || e.contains("end of input"),
            "{}",
            e
        );
        // Clave global duplicada.
        let mut dup = Vec::new();
        dup.extend_from_slice(PSBT_MAGIC);
        dup.extend_from_slice(&[0x01, 0x77, 0x01, 0x00, 0x01, 0x77, 0x01, 0x00, 0x00]);
        let e = errmsg(psbt_decode(&[syn_text(b64_encode(&dup))]));
        assert!(e.contains("duplicate"), "{}", e);
    }

    #[test]
    fn schnorr_verify_builtin_accepts_and_rejects() {
        // La firma del vector T contra la clave de SALIDA (el program p2tr).
        let d = ok(btc_address_decode(&[syn_text(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        )]));
        let out_key = as_bytes(&get(&d, "program"));
        let digest = hx("8638bb5b0890bb9a7afb7ea23fb668c60084f064c60a3646a566fce8cfc89b3f");
        let sig = taproot_sign64(KEY_86_0, &digest);
        let v = ok(schnorr_verify(&[
            syn_bytes(digest.clone()),
            syn_bytes(sig.clone()),
            syn_bytes(out_key.clone()),
        ]));
        assert!(matches!(v, SynValue::Bool(true)));
        let mut bad = sig;
        bad[0] ^= 1;
        let v = ok(schnorr_verify(&[syn_bytes(digest), syn_bytes(bad), syn_bytes(out_key)]));
        assert!(matches!(v, SynValue::Bool(false)));
    }

    #[test]
    fn txid_handles_legacy_and_segwit_forms() {
        // El txid de la firmada == el de la sin firmar (el witness no cuenta).
        let signed = hx(VEC_W_RAW);
        assert_eq!(ok(btc_txid(&[syn_bytes(signed)])).to_string(), VEC_W_TXID);
        // Basura → error atrapable, jamás panic.
        assert!(btc_txid(&[syn_bytes(vec![0u8; 3])]).is_err());
        let mut trailing = hx(VEC_W_RAW);
        trailing.push(0);
        assert!(btc_txid(&[syn_bytes(trailing)]).is_err());
    }

    #[test]
    fn hash160_matches_known_program() {
        // hash160(pubkey BIP-84) == el program de su dirección.
        let h = hash160(&hx(PUB_84_0));
        let d = ok(btc_address_decode(&[syn_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")]));
        assert_eq!(h.to_vec(), as_bytes(&get(&d, "program")));
    }
}
