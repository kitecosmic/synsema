//! `did:key` (T3 del spec de identidad): la identidad que es una función pura de la clave.
//! `did:key:z` + base58btc(multicodec ‖ clave). Sin registro, sin red, sin resolver: cualquier
//! consumidor DID/VC resuelve nuestra identidad offline, y nosotros no dependemos de nadie —
//! es el único método DID que cuesta cero dependencia, y por eso es EL método del motor
//! (`did:web` ata la identidad a DNS+TLS y queda afuera; un registro propio, ni hablar).
//!
//! Por qué builtin: el prefijo multicodec va en **varint** (`0xed 0x01` ed25519, `0x80 0x24`
//! P-256, `0xec 0x01` X25519, `0xe7 0x01` secp256k1) — escribir `0xed` en vez de `0xed01`
//! produce un DID que parece válido y no resuelve en ningún lado. Footgun de canonicalización
//! de manual, y la tarjeta del server lo deriva sola de todos modos.
//!
//! - `did_key_encode(public_key, alg?)` → `did:key:z…` (`alg` = "ed25519" por defecto,
//!   "p256", "x25519", "secp256k1"; P-256 y secp256k1 se COMPRIMEN a 33 bytes como manda el
//!   spec, aceptando los 65 crudos).
//! - `did_key_decode(did)` → `{alg, public_key, multibase}`, ESTRICTO: multicodec desconocido,
//!   longitud incorrecta, multibase que no sea `z` → error (un DID es dato del programa; roto
//!   es bug, no credencial inválida). Acepta el fragmento `did:key:z…#z…` de un
//!   `verificationMethod`.
//! - `did_key_document(did)` → el DID Document derivado (verificationMethod `Multikey`, las
//!   cuatro relaciones, y para ed25519 el `keyAgreement` X25519 derivado, multicodec `0xec`).
//!
//! Vectores: el spec del W3C CCG (did:key Method v0.9, ejemplo
//! `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`).

use indexmap::IndexMap;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use synsema_core::bytesutil::{base58_decode, base58_encode, hex_decode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_list, syn_map, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn syn_bytes(b: Vec<u8>) -> SynValue {
    SynValue::Bytes(std::rc::Rc::from(b.into_boxed_slice()))
}

/// Prefijos multicodec (varint) de las claves públicas que el motor conoce.
pub const MC_ED25519: &[u8] = &[0xed, 0x01];
pub const MC_X25519: &[u8] = &[0xec, 0x01];
pub const MC_P256: &[u8] = &[0x80, 0x24];
pub const MC_SECP256K1: &[u8] = &[0xe7, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Ed25519,
    X25519,
    P256,
    Secp256k1,
}

impl KeyAlg {
    pub fn name(self) -> &'static str {
        match self {
            KeyAlg::Ed25519 => "ed25519",
            KeyAlg::X25519 => "x25519",
            KeyAlg::P256 => "p256",
            KeyAlg::Secp256k1 => "secp256k1",
        }
    }

    fn parse(s: &str) -> Option<KeyAlg> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ed25519" => Some(KeyAlg::Ed25519),
            "x25519" => Some(KeyAlg::X25519),
            "p256" | "p-256" | "secp256r1" | "es256" => Some(KeyAlg::P256),
            "secp256k1" | "k256" => Some(KeyAlg::Secp256k1),
            _ => None,
        }
    }

    fn multicodec(self) -> &'static [u8] {
        match self {
            KeyAlg::Ed25519 => MC_ED25519,
            KeyAlg::X25519 => MC_X25519,
            KeyAlg::P256 => MC_P256,
            KeyAlg::Secp256k1 => MC_SECP256K1,
        }
    }
}

/// Valida (y comprime, si hace falta) la clave pública para su algoritmo.
fn normalize_key(alg: KeyAlg, key: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        KeyAlg::Ed25519 => {
            if key.len() != 32 {
                return Err(format!("an ed25519 public key is 32 bytes, got {}", key.len()));
            }
            // Tiene que ser un punto válido (un DID de 32 bytes al azar no es una identidad).
            let arr: [u8; 32] = key.try_into().expect("32");
            ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| "not a valid ed25519 point".to_string())?;
            Ok(key.to_vec())
        }
        KeyAlg::X25519 => {
            if key.len() != 32 {
                return Err(format!("an X25519 public key is 32 bytes, got {}", key.len()));
            }
            Ok(key.to_vec())
        }
        KeyAlg::P256 => {
            let pk = p256::PublicKey::from_sec1_bytes(key)
                .map_err(|_| "not a valid P-256 point (SEC1: 33 bytes compressed or 65 uncompressed)".to_string())?;
            Ok(pk.to_encoded_point(true).as_bytes().to_vec())
        }
        KeyAlg::Secp256k1 => {
            let pk = k256::PublicKey::from_sec1_bytes(key)
                .map_err(|_| "not a valid secp256k1 point (SEC1: 33 bytes compressed or 65 uncompressed)".to_string())?;
            Ok(pk.to_encoded_point(true).as_bytes().to_vec())
        }
    }
}

/// `did:key:z…` de una clave pública.
pub fn encode(alg: KeyAlg, key: &[u8]) -> Result<String, String> {
    let key = normalize_key(alg, key)?;
    let mut raw = alg.multicodec().to_vec();
    raw.extend_from_slice(&key);
    Ok(format!("did:key:z{}", base58_encode(&raw)))
}

/// La parte multibase (`z…`) de un `did:key`, sin el fragmento.
fn multibase_of(did: &str) -> Result<&str, String> {
    let did = did.trim();
    let body = did.split('#').next().unwrap_or("");
    let Some(mb) = body.strip_prefix("did:key:") else {
        return Err(format!("not a did:key ({:?}); expected \"did:key:z…\"", did));
    };
    if !mb.starts_with('z') {
        return Err(format!(
            "unsupported multibase prefix {:?} in {:?}; did:key uses base58btc (\"z\")",
            mb.chars().next().map(|c| c.to_string()).unwrap_or_default(),
            did
        ));
    }
    Ok(mb)
}

/// Decodifica ESTRICTO: (algoritmo, clave pública, multibase).
pub fn decode(did: &str) -> Result<(KeyAlg, Vec<u8>, String), String> {
    let mb = multibase_of(did)?;
    let raw = base58_decode(&mb[1..]).map_err(|_| format!("the did:key body is not base58btc: {:?}", did))?;
    let (alg, key) = if let Some(k) = raw.strip_prefix(MC_ED25519) {
        (KeyAlg::Ed25519, k)
    } else if let Some(k) = raw.strip_prefix(MC_X25519) {
        (KeyAlg::X25519, k)
    } else if let Some(k) = raw.strip_prefix(MC_P256) {
        (KeyAlg::P256, k)
    } else if let Some(k) = raw.strip_prefix(MC_SECP256K1) {
        (KeyAlg::Secp256k1, k)
    } else {
        return Err(format!(
            "unknown multicodec prefix in {:?} (supported: ed25519 0xed, x25519 0xec, p256 0x1200, secp256k1 0xe7)",
            did
        ));
    };
    let expected = match alg {
        KeyAlg::Ed25519 | KeyAlg::X25519 => 32,
        KeyAlg::P256 | KeyAlg::Secp256k1 => 33,
    };
    if key.len() != expected {
        return Err(format!(
            "a {} did:key carries {} key bytes, this one has {}",
            alg.name(),
            expected,
            key.len()
        ));
    }
    let key = normalize_key(alg, key)?;
    Ok((alg, key, mb.to_string()))
}

/// El DID Document derivado (did:key Method v0.9 §3.1): `Multikey`, las cuatro relaciones,
/// y `keyAgreement` X25519 derivado de una clave ed25519.
pub fn document(did: &str) -> Result<SynValue, String> {
    let (alg, key, mb) = decode(did)?;
    let did = format!("did:key:{}", mb);
    let vm_id = format!("{}#{}", did, mb);
    let mut vm = IndexMap::new();
    vm.insert("id".to_string(), syn_text(vm_id.clone()));
    vm.insert("type".to_string(), syn_text("Multikey"));
    vm.insert("controller".to_string(), syn_text(did.clone()));
    vm.insert("publicKeyMultibase".to_string(), syn_text(mb.clone()));

    let mut doc = IndexMap::new();
    doc.insert(
        "@context".to_string(),
        syn_list(vec![
            syn_text("https://www.w3.org/ns/did/v1"),
            syn_text("https://w3id.org/security/multikey/v1"),
        ]),
    );
    doc.insert("id".to_string(), syn_text(did.clone()));
    let refs = || syn_list(vec![syn_text(vm_id.clone())]);
    match alg {
        KeyAlg::X25519 => {
            // Una clave de acuerdo sola: sólo `keyAgreement`.
            doc.insert("verificationMethod".to_string(), syn_list(vec![syn_map(vm)]));
            doc.insert("keyAgreement".to_string(), refs());
        }
        _ => {
            let mut methods = vec![syn_map(vm)];
            doc.insert("authentication".to_string(), refs());
            doc.insert("assertionMethod".to_string(), refs());
            doc.insert("capabilityInvocation".to_string(), refs());
            doc.insert("capabilityDelegation".to_string(), refs());
            if alg == KeyAlg::Ed25519 {
                // X25519 derivada (§3.1.2): la clave de acuerdo de la misma identidad.
                let arr: [u8; 32] = key.as_slice().try_into().expect("32");
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).expect("validada en decode");
                let x = vk.to_montgomery().to_bytes();
                let mut raw = MC_X25519.to_vec();
                raw.extend_from_slice(&x);
                let xmb = format!("z{}", base58_encode(&raw));
                let xid = format!("{}#{}", did, xmb);
                let mut ka = IndexMap::new();
                ka.insert("id".to_string(), syn_text(xid.clone()));
                ka.insert("type".to_string(), syn_text("Multikey"));
                ka.insert("controller".to_string(), syn_text(did.clone()));
                ka.insert("publicKeyMultibase".to_string(), syn_text(xmb));
                methods.push(syn_map(ka));
                doc.insert("keyAgreement".to_string(), syn_list(vec![syn_text(xid)]));
            }
            doc.insert("verificationMethod".to_string(), syn_list(methods));
        }
    }
    Ok(syn_map(doc))
}

fn key_arg(v: &SynValue, who: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Bytes(b) => Ok(b[..].to_vec()),
        SynValue::Text(s) => hex_decode(s.trim().trim_start_matches("0x"))
            .map_err(|_| err(format!("{}: public_key must be bytes (or hex text), got text that is not hex", who))),
        SynValue::Secret(_) => Err(err(format!(
            "{}: public_key must be the PUBLIC key (bytes), got a secret — derive it first (ed25519_pubkey(secret))",
            who
        ))),
        other => Err(err(format!("{}: public_key must be bytes, got {}", who, other.type_name()))),
    }
}

fn b_did_key_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "did_key_encode";
    if !(1..=2).contains(&args.len()) {
        return Err(err(format!("{}(public_key, alg?) takes 1 or 2 arguments", F)));
    }
    let key = key_arg(&args[0], F)?;
    let alg = match args.get(1) {
        None | Some(SynValue::Nothing) => KeyAlg::Ed25519,
        Some(SynValue::Text(s)) => KeyAlg::parse(s).ok_or_else(|| {
            err(format!(
                "{}: alg must be \"ed25519\", \"p256\", \"x25519\" or \"secp256k1\", got {:?}",
                F, s
            ))
        })?,
        Some(other) => return Err(err(format!("{}: alg must be text, got {}", F, other.type_name()))),
    };
    encode(alg, &key).map(syn_text).map_err(|e| err(format!("{}: {}", F, e)))
}

fn did_arg(v: &SynValue, who: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        other => Err(err(format!("{}: did must be text (\"did:key:z…\"), got {}", who, other.type_name()))),
    }
}

fn b_did_key_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "did_key_decode";
    if args.len() != 1 {
        return Err(err(format!("{}(did) takes exactly 1 argument", F)));
    }
    let did = did_arg(&args[0], F)?;
    let (alg, key, mb) = decode(&did).map_err(|e| err(format!("{}: {}", F, e)))?;
    let mut m = IndexMap::new();
    m.insert("alg".to_string(), syn_text(alg.name()));
    m.insert("public_key".to_string(), syn_bytes(key));
    m.insert("multibase".to_string(), syn_text(mb.clone()));
    m.insert("did".to_string(), syn_text(format!("did:key:{}", mb)));
    Ok(syn_map(m))
}

fn b_did_key_document(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "did_key_document";
    if args.len() != 1 {
        return Err(err(format!("{}(did) takes exactly 1 argument", F)));
    }
    let did = did_arg(&args[0], F)?;
    document(&did).map_err(|e| err(format!("{}: {}", F, e)))
}

/// Registra `did_key_encode`, `did_key_decode`, `did_key_document`. PUROS.
pub fn register_didkey_builtins(interp: &Interpreter) {
    interp.register_builtin("did_key_encode", -1, std::rc::Rc::new(|_i, a, _l| b_did_key_encode(a)));
    interp.register_builtin("did_key_decode", 1, std::rc::Rc::new(|_i, a, _l| b_did_key_decode(a)));
    interp.register_builtin("did_key_document", 1, std::rc::Rc::new(|_i, a, _l| b_did_key_document(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El vector del spec: la clave ed25519 de ejemplo y su DID.
    const SPEC_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn spec_vector_roundtrips() {
        let (alg, key, mb) = decode(SPEC_DID).expect("decode");
        assert_eq!(alg, KeyAlg::Ed25519);
        assert_eq!(key.len(), 32);
        assert_eq!(format!("did:key:{}", mb), SPEC_DID);
        assert_eq!(encode(KeyAlg::Ed25519, &key).unwrap(), SPEC_DID);
        // el fragmento de un verificationMethod se ignora
        let (_, key2, _) = decode(&format!("{}#{}", SPEC_DID, mb)).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn p256_is_compressed_and_wrong_prefixes_are_errors() {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let uncompressed = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
        let did = encode(KeyAlg::P256, &uncompressed).unwrap();
        let (alg, key, _) = decode(&did).unwrap();
        assert_eq!(alg, KeyAlg::P256);
        assert_eq!(key.len(), 33);
        assert_eq!(encode(KeyAlg::P256, &key).unwrap(), did);
        // 0xed sin el 0x01 del varint: NO es un did:key de ed25519
        let mut raw = vec![0xed];
        raw.extend_from_slice(&[9u8; 32]);
        let bad = format!("did:key:z{}", base58_encode(&raw));
        assert!(decode(&bad).unwrap_err().contains("unknown multicodec"));
        assert!(decode("did:web:example.com").unwrap_err().contains("not a did:key"));
        assert!(decode("did:key:u6Mk").unwrap_err().contains("multibase"));
        // 32 bytes que no son un punto ed25519: y = 0x0202…02 no tiene raíz (x² no es cuadrado).
        // ([0xff; 32] SÍ decodifica: dalek reduce la y no canónica módulo p y la raíz existe.)
        assert!(encode(KeyAlg::Ed25519, &[0x02u8; 32]).unwrap_err().contains("not a valid ed25519 point"));
        assert!(encode(KeyAlg::Ed25519, &[0x02u8; 31]).unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn did_document_has_the_relationships_and_the_derived_x25519() {
        let doc = document(SPEC_DID).unwrap();
        let SynValue::Map(m) = doc else { panic!("map") };
        let m = m.borrow();
        assert_eq!(m.get("id").unwrap().to_string(), SPEC_DID);
        for rel in ["authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation", "keyAgreement"] {
            assert!(m.contains_key(rel), "{}", rel);
        }
        let SynValue::List(vms) = m.get("verificationMethod").unwrap() else { panic!("list") };
        assert_eq!(vms.borrow().len(), 2);
        // el keyAgreement es una clave x25519 (multicodec 0xec) derivada de la ed25519
        let SynValue::List(ka) = m.get("keyAgreement").unwrap() else { panic!("list") };
        let ka_id = ka.borrow()[0].to_string();
        // `did:key:<ed25519>#<x25519>`: el fragmento es la clave X25519 (el DID sigue siendo el ed25519).
        let (did_part, frag) = ka_id.split_once('#').expect("fragmento");
        assert_eq!(did_part, SPEC_DID);
        let (alg, _, _) = decode(&format!("did:key:{}", frag)).unwrap();
        assert_eq!(alg, KeyAlg::X25519);
        // Oráculo independiente: u = (1 + y) / (1 - y) mod p calculado a mano (Python) sobre la y
        // de la clave ed25519 de z6MkhaXg… (2e6fcce3…) da 6e5ff792…, que con el multicodec 0xec01
        // es z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p. (La misma conversión que
        // crypto_sign_ed25519_pk_to_curve25519 de libsodium.)
        assert!(ka_id.ends_with("#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"), "{}", ka_id);
    }
}
