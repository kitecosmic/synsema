//! Algorand transaccionable (Batch 12, alcance C): msgpack CANÓNICO + prefijo de
//! dominio `TX` + ensamblado del SignedTxn + helper de dirección. TODO PURO (G13).
//!
//! - **Canónico estricto (G15):** Algorand exige msgpack canónico — claves de map
//!   ordenadas bytewise, enteros en su representación mínima, y campos cero/vacíos/
//!   false OMITIDOS (si no, la red rechaza o el TXID difiere). El encoder lo emite
//!   así por construcción; no hay modo laxo.
//! - Las claves del `txn` son las CORTAS del protocolo (`snd`, `rcv`, `amt`, `fee`,
//!   `fv`, `lv`, `gen`, `gh`, `note`, …) — sin alias inventados, así el JSON de la
//!   API de algod mapea directo.
//! - Direcciones: text base32 de 58 chars se acepta y se VALIDA el checksum
//!   (sha512_256(pk)[28..32]) → bytes(32) internos; bytes(32) crudos también.
//! - El msgpack hand-rolled cubre el subset del protocolo (uint/bytes/str/bool/
//!   map/list) — cero deps nuevas (G16), mismo molde que RLP.
//!
//! Se firma con `ed25519_sign(algorand_tx_encode(txn), key)` (gate del batch 11) y
//! se difunde con `http_post` a `/v2/transactions` (`application/x-binary`).
//! El TXID (= base32(sha512_256("TX" ‖ msgpack))) queda componible en userland.

use std::rc::Rc;

use sha2::{Digest, Sha512_256};

use synsema_core::bytesutil::{base32_decode, base32_encode};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_bytes, syn_text, SynValue};

use crate::blockchain::{arg, arg_bytes_len, ed25519_seed, err, key_material};

/// Cota de recursión del descenso msgpack (espeja `RLP_MAX_DEPTH` del batch 11 y
/// el `MAX_DEPTH` de ABI): un `txn` con maps/listas anidadas sin fondo reventaría
/// el stack en `to_mp` — abort no atrapable = DoS bajo `serve` (G10). Ninguna
/// transacción real anida cerca de esto.
const MAX_DEPTH: usize = 64;

// =========================================================
// Direcciones
// =========================================================

/// Dirección Algorand desde la pubkey: base32(pk ‖ sha512_256(pk)[28..32]).
fn address_from_pubkey(pk: &[u8; 32]) -> String {
    let check = Sha512_256::digest(pk);
    let mut full = pk.to_vec();
    full.extend_from_slice(&check[28..32]);
    base32_encode(&full)
}

/// Decodifica y VALIDA una dirección text (58 chars base32 con checksum) → pubkey.
/// `pub(crate)`: blockchain_rpc.rs (algorand_account) valida con la MISMA regla.
pub(crate) fn address_to_pubkey(s: &str, what: &str, fname: &str) -> Result<[u8; 32], Control> {
    if s.len() != 58 {
        return Err(err(format!(
            "{}: {} must be a 58-character Algorand address, got {} characters",
            fname,
            what,
            s.len()
        )));
    }
    let raw = base32_decode(s)
        .map_err(|e| err(format!("{}: {} is not valid base32: {}", fname, what, e)))?;
    if raw.len() != 36 {
        return Err(err(format!(
            "{}: {} did not decode to pubkey+checksum (36 bytes), got {}",
            fname,
            what,
            raw.len()
        )));
    }
    let pk: [u8; 32] = raw[..32].try_into().expect("32 bytes");
    let check = Sha512_256::digest(pk);
    if raw[32..36] != check[28..32] {
        return Err(err(format!(
            "{}: {} has an invalid address checksum (a mistyped or truncated address — refusing to send money to it)",
            fname, what
        )));
    }
    Ok(pk)
}

// =========================================================
// msgpack canónico (subset de Algorand)
// =========================================================

/// Valor msgpack ya canónico: convertido, con las claves ordenadas y SIN
/// zero-values (se podan al construir).
enum Mp {
    Uint(u64),
    Bytes(Vec<u8>),
    Str(String),
    Bool(bool),
    Map(Vec<(String, Mp)>),
    List(Vec<Mp>),
}

/// Campos de dirección del protocolo en el nivel dado: se aceptan como text
/// (validando checksum) y viajan como bytes(32).
const TXN_ADDR_KEYS: &[&str] = &["snd", "rcv", "close", "asnd", "arcv", "rekey"];
const APAR_ADDR_KEYS: &[&str] = &["m", "r", "f", "c"];

/// Convierte un SynValue a Mp canónico. Devuelve `None` para los zero-values
/// (0, bytes/str/map/list vacíos, false): en un map de Algorand se OMITEN.
fn to_mp(
    v: &SynValue,
    path: &str,
    addr_keys: &'static [&'static str],
    fname: &str,
    depth: usize,
) -> Result<Option<Mp>, Control> {
    if depth > MAX_DEPTH {
        return Err(err(format!(
            "{}: {} is nested too deeply (max {} levels)",
            fname, path, MAX_DEPTH
        )));
    }
    match v {
        SynValue::Number(n) => {
            let big = n.as_bigint().ok_or_else(|| {
                err(format!(
                    "{}: {} must be an exact integer (protocol amounts are exact — no floats)",
                    fname, path
                ))
            })?;
            if big.sign() == num_bigint::Sign::Minus {
                return Err(err(format!(
                    "{}: {} is negative — Algorand protocol fields are unsigned",
                    fname, path
                )));
            }
            let u = u64::try_from(&big).map_err(|_| {
                err(format!(
                    "{}: {} does not fit in 64 bits (Algorand protocol integers are uint64)",
                    fname, path
                ))
            })?;
            Ok(if u == 0 { None } else { Some(Mp::Uint(u)) })
        }
        SynValue::Bool(b) => Ok(if *b { Some(Mp::Bool(true)) } else { None }),
        SynValue::Bytes(b) => {
            Ok(if b.is_empty() { None } else { Some(Mp::Bytes(b[..].to_vec())) })
        }
        SynValue::Text(s) => {
            Ok(if s.is_empty() { None } else { Some(Mp::Str(s.to_string())) })
        }
        SynValue::Map(m) => {
            let m = m.borrow().clone();
            let mut entries: Vec<(String, Mp)> = Vec::with_capacity(m.len());
            for (k, val) in m.iter() {
                let child_path = format!("{}.{}", path, k);
                // ¿Este campo es una dirección? → text se decodifica y valida.
                let converted: Option<SynValue> = if addr_keys.contains(&k.as_str()) {
                    match val {
                        SynValue::Text(s) => {
                            let pk = address_to_pubkey(s, &child_path, fname)?;
                            Some(SynValue::Bytes(pk.to_vec().into()))
                        }
                        SynValue::Bytes(b) if b.len() == 32 => None,
                        SynValue::Bytes(b) => {
                            return Err(err(format!(
                                "{}: {} must be a 32-byte pubkey or a 58-char address, got {} bytes",
                                fname,
                                child_path,
                                b.len()
                            )))
                        }
                        other => {
                            return Err(err(format!(
                                "{}: {} must be an address (58-char text or 32 bytes), got {}",
                                fname,
                                child_path,
                                other.type_name()
                            )))
                        }
                    }
                } else {
                    None
                };
                let val = converted.as_ref().unwrap_or(val);
                // "apar" (params de asset) tiene sus propios campos de dirección.
                let child_addr: &'static [&'static str] =
                    if k == "apar" { APAR_ADDR_KEYS } else { &[] };
                if let Some(mp) = to_mp(val, &child_path, child_addr, fname, depth + 1)? {
                    entries.push((k.clone(), mp));
                }
            }
            if entries.is_empty() {
                return Ok(None);
            }
            // Canónico: claves ordenadas BYTEWISE.
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            Ok(Some(Mp::Map(entries)))
        }
        SynValue::List(l) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                let child_path = format!("{}[{}]", path, i);
                // Dentro de una lista NO se omiten zero-values (cambiaría el
                // índice de los demás elementos); se codifican tal cual.
                out.push(to_mp_in_list(it, &child_path, fname, depth + 1)?);
            }
            Ok(Some(Mp::List(out)))
        }
        SynValue::Secret(_) => Err(err(format!(
            "{}: {} cannot be a secret (only the signing key is a secret, and it never enters the transaction)",
            fname, path
        ))),
        other => Err(err(format!(
            "{}: {} has unsupported type {} (the protocol subset is: integers, bytes, text, booleans, maps, lists)",
            fname,
            path,
            other.type_name()
        ))),
    }
}

/// Elemento de lista: mismo subset, pero un zero-value se CODIFICA (omitirlo
/// correría los índices). Un map vacío dentro de una lista se emite como {}.
fn to_mp_in_list(v: &SynValue, path: &str, fname: &str, depth: usize) -> Result<Mp, Control> {
    match to_mp(v, path, &[], fname, depth)? {
        Some(mp) => Ok(mp),
        None => Ok(match v {
            SynValue::Number(_) => Mp::Uint(0),
            SynValue::Bool(_) => Mp::Bool(false),
            SynValue::Bytes(_) => Mp::Bytes(Vec::new()),
            SynValue::Text(_) => Mp::Str(String::new()),
            SynValue::Map(_) => Mp::Map(Vec::new()),
            SynValue::List(_) => Mp::List(Vec::new()),
            _ => unreachable!("to_mp ya filtró los tipos"),
        }),
    }
}

/// Emisión msgpack canónica: representación MÍNIMA para cada valor.
fn mp_write(v: &Mp, out: &mut Vec<u8>) {
    match v {
        Mp::Uint(n) => {
            let n = *n;
            if n <= 0x7f {
                out.push(n as u8);
            } else if n <= 0xff {
                out.push(0xcc);
                out.push(n as u8);
            } else if n <= 0xffff {
                out.push(0xcd);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else if n <= 0xffff_ffff {
                out.push(0xce);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            } else {
                out.push(0xcf);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        Mp::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
        Mp::Bytes(b) => {
            let len = b.len();
            if len <= 0xff {
                out.push(0xc4);
                out.push(len as u8);
            } else if len <= 0xffff {
                out.push(0xc5);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                out.push(0xc6);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
            out.extend_from_slice(b);
        }
        Mp::Str(s) => {
            let b = s.as_bytes();
            let len = b.len();
            if len <= 31 {
                out.push(0xa0 | len as u8);
            } else if len <= 0xff {
                out.push(0xd9);
                out.push(len as u8);
            } else if len <= 0xffff {
                out.push(0xda);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                out.push(0xdb);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
            out.extend_from_slice(b);
        }
        Mp::Map(entries) => {
            let len = entries.len();
            if len <= 15 {
                out.push(0x80 | len as u8);
            } else if len <= 0xffff {
                out.push(0xde);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                out.push(0xdf);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
            for (k, val) in entries {
                mp_write(&Mp::Str(k.clone()), out);
                mp_write(val, out);
            }
        }
        Mp::List(items) => {
            let len = items.len();
            if len <= 15 {
                out.push(0x90 | len as u8);
            } else if len <= 0xffff {
                out.push(0xdc);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                out.push(0xdd);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
            for it in items {
                mp_write(it, out);
            }
        }
    }
}

/// txn (map Synsema) → Mp canónico podado, validando forma.
fn txn_to_mp(v: &SynValue, fname: &str) -> Result<Mp, Control> {
    match v {
        SynValue::Map(_) => {}
        other => {
            return Err(err(format!(
                "{}: the transaction must be a map with the protocol's short field names (type, snd, rcv, amt, fee, fv, lv, gh, …), got {}",
                fname,
                other.type_name()
            )))
        }
    }
    match to_mp(v, "txn", TXN_ADDR_KEYS, fname, 0)? {
        Some(mp) => Ok(mp),
        None => Err(err(format!(
            "{}: the transaction has no non-zero fields (canonical encoding omits zero values — an empty transaction is a bug, not a payload)",
            fname
        ))),
    }
}

// =========================================================
// Builtins
// =========================================================

/// `algorand_tx_encode(txn)` → bytes `"TX" ‖ msgpack_canónico(txn)`, LISTOS para
/// `ed25519_sign` (Algorand firma el msgpack con prefijo de dominio).
fn algorand_tx_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "algorand_tx_encode";
    let mp = txn_to_mp(arg(args, 0, F)?, F)?;
    let mut out = b"TX".to_vec();
    mp_write(&mp, &mut out);
    Ok(syn_bytes(out))
}

/// `algorand_tx(txn, signature)` → bytes del SignedTxn (`{"sig": …, "txn": {…}}`)
/// listos para POST a `/v2/transactions` (`Content-Type: application/x-binary`).
fn algorand_tx(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "algorand_tx";
    let txn = txn_to_mp(arg(args, 0, F)?, F)?;
    let sig = arg_bytes_len(arg(args, 1, F)?, F, "the signature", 64)?;
    // "sig" < "txn" bytewise: el orden canónico ya viene dado.
    let signed = Mp::Map(vec![
        ("sig".to_string(), Mp::Bytes(sig.to_vec())),
        ("txn".to_string(), txn),
    ]);
    let mut out = Vec::new();
    mp_write(&signed, &mut out);
    Ok(syn_bytes(out))
}

/// `algo_address(pubkey_or_secret)` → text base32 con checksum. Espeja
/// `eth_address`: con un secret deriva la pubkey Rust-side (G2) — la clave
/// jamás se materializa en user-space.
fn algo_address(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "algo_address";
    let v = arg(args, 0, F)?;
    let pk: [u8; 32] = match v {
        SynValue::Secret(_) => {
            let (_name, key) = key_material(v, F)?;
            let sk = ed25519_seed(key, F)?;
            sk.verifying_key().to_bytes()
        }
        SynValue::Bytes(b) => b[..].try_into().map_err(|_| {
            err(format!(
                "{}: the public key must be exactly 32 bytes, got {}",
                F,
                b.len()
            ))
        })?,
        other => {
            return Err(err(format!(
                "{}: expected a 32-byte ed25519 public key (bytes) or a key secret, got {}",
                F,
                other.type_name()
            )))
        }
    };
    Ok(syn_text(address_from_pubkey(&pk)))
}

// =========================================================
// Registro (todos PUROS — G13)
// =========================================================

pub(crate) fn register(interp: &Interpreter) {
    interp.register_builtin("algorand_tx_encode", 1, Rc::new(|_i, a, _l| algorand_tx_encode(a)));
    interp.register_builtin("algorand_tx", 2, Rc::new(|_i, a, _l| algorand_tx(a)));
    interp.register_builtin("algo_address", 1, Rc::new(|_i, a, _l| algo_address(a)));
}
