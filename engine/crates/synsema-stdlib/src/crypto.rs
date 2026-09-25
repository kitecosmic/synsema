//! v0.6.20 — criptografía genérica con nombres y firmas de WebCrypto: ECDH (P-256 y P-521),
//! HKDF-SHA256 y AES-GCM (128 y 256). Lo pidió un TEE (Vela); le sirve a cualquiera que cifre
//! extremo a extremo. Nada de un proveedor en los nombres: es el eje CLIENTE de la regla de
//! dos ejes (spec de faltantes, sección "WASM, Vela y otras integraciones").
//!
//! Contrato:
//! - `ecdh_keypair(curve)` → `{private: secret, public: bytes}`; `curve` = `"P-256"` | `"P-521"`.
//!   Público SEC1 sin comprimir (`04‖X‖Y`). **Requiere `random`** (genera clave; la misma
//!   puerta que `random_bytes`). La clave sale de OsRng, jamás del `random()` no-cripto.
//! - `ecdh_shared_secret(private, peer_public, curve)` → `secret` (bytes crudos de la X
//!   compartida, como `deriveBits` de WebCrypto). Puro.
//! - `hkdf_sha256(ikm, salt, info, length)` → `bytes` (o `secret` si `ikm` lo es). RFC 5869.
//! - `aes_gcm_encrypt(key, nonce, plaintext, aad?)` → `bytes` = ciphertext ‖ tag (16);
//!   `aes_gcm_decrypt(key, nonce, ciphertext, aad?)` → `bytes`. La clave de 16 bytes elige
//!   AES-128-GCM y la de 32 AES-256-GCM; el nonce son 12 bytes. Un fallo de autenticación es
//!   error, nunca bytes parciales.
//!
//! Todo RustCrypto puro-Rust, ya en el árbol salvo `p521` (0.13, misma pila que `p256`).

use std::cell::RefCell;
use std::rc::Rc;

use hkdf::Hkdf;
use indexmap::IndexMap;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use zeroize::Zeroize;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bytes, syn_map, syn_secret_bytes, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P521,
}

impl Curve {
    fn parse(v: Option<&SynValue>, who: &str) -> Result<Curve, Control> {
        match v {
            Some(SynValue::Text(s)) => match s.to_ascii_uppercase().as_str() {
                "P-256" | "P256" | "SECP256R1" | "PRIME256V1" => Ok(Curve::P256),
                "P-521" | "P521" | "SECP521R1" => Ok(Curve::P521),
                other => Err(err(format!(
                    "{}: unknown curve {:?} (supported: \"P-256\", \"P-521\")",
                    who, other
                ))),
            },
            Some(other) => Err(err(format!(
                "{}: curve must be text (\"P-256\" | \"P-521\"), got {}",
                who,
                other.type_name()
            ))),
            None => Err(err(format!("{}: the curve is required (\"P-256\" | \"P-521\")", who))),
        }
    }
    fn scalar_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P521 => 66,
        }
    }
}

/// Bytes de un argumento: `bytes`, `secret` (expuesto sólo acá) o texto (UTF-8). Devuelve
/// también si venía sellado, para que la salida herede el sello.
///
/// Un secret **sellado** (`attestation_key`) se RECHAZA acá —
/// Era el camino por el que se extraía el escalar P-256 de la identidad atestada cifrándolo
/// con `aes_gcm_encrypt` bajo una clave elegida por el programa y descifrándolo afuera. El
/// único uso legítimo de ese material en este módulo es `ecdh_shared_secret` con la clave
/// PROPIA, que pide los bytes por `private_key_arg`.
fn bytes_arg(v: Option<&SynValue>, who: &str, what: &str) -> Result<(Vec<u8>, bool), Control> {
    match v {
        Some(SynValue::Bytes(b)) => Ok((b.to_vec(), false)),
        Some(SynValue::Secret(s)) => Ok((s.expose_bytes_checked(who).map_err(err)?.to_vec(), true)),
        Some(SynValue::Text(s)) => Ok((s.as_bytes().to_vec(), false)),
        Some(other) => Err(err(format!(
            "{}: {} must be bytes, a secret or text, got {}",
            who,
            what,
            other.type_name()
        ))),
        None => Err(err(format!("{}: {} is required", who, what))),
    }
}

fn require_random(caps: &Rc<RefCell<CapabilitySet>>, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Random, None), source)
        .map_err(|v| Control::Error(v.into_error()))
}

/// Escalar privado válido desde OsRng: `from_slice` rechaza 0 y ≥ n; se reintenta (la
/// probabilidad es despreciable, el bucle existe para no devolver jamás una clave inválida).
fn random_scalar(curve: Curve, who: &str) -> Result<Vec<u8>, Control> {
    for _ in 0..16 {
        let mut bytes = crate::webauth::os_random(curve.scalar_len(), who)?;
        // P-521: el orden n tiene 521 bits en 66 bytes; sin enmascarar el byte alto a 1 bit,
        // un escalar al azar es ≥ n el 99 % de las veces (FIPS 186-4 B.4.2, mismo recorte).
        if curve == Curve::P521 {
            bytes[0] &= 0x01;
        }
        let valid = match curve {
            Curve::P256 => p256::SecretKey::from_slice(&bytes).is_ok(),
            Curve::P521 => p521::SecretKey::from_slice(&bytes).is_ok(),
        };
        if valid {
            return Ok(bytes);
        }
    }
    Err(err(format!("{}: could not draw a valid private scalar (OsRng failure?)", who)))
}

fn public_of(curve: Curve, private: &[u8], who: &str) -> Result<Vec<u8>, Control> {
    Ok(match curve {
        Curve::P256 => {
            let sk = p256::SecretKey::from_slice(private)
                .map_err(|_| err(format!("{}: the private key is not a valid P-256 scalar (32 bytes)", who)))?;
            sk.public_key().to_encoded_point(false).as_bytes().to_vec()
        }
        Curve::P521 => {
            let sk = p521::SecretKey::from_slice(private)
                .map_err(|_| err(format!("{}: the private key is not a valid P-521 scalar (66 bytes)", who)))?;
            sk.public_key().to_encoded_point(false).as_bytes().to_vec()
        }
    })
}

fn shared_secret(curve: Curve, private: &[u8], peer: &[u8], who: &str) -> Result<Vec<u8>, Control> {
    Ok(match curve {
        Curve::P256 => {
            let sk = p256::SecretKey::from_slice(private)
                .map_err(|_| err(format!("{}: the private key is not a valid P-256 scalar (32 bytes)", who)))?;
            let pk = p256::PublicKey::from_sec1_bytes(peer)
                .map_err(|_| err(format!("{}: the peer public key is not a valid SEC1 P-256 point", who)))?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            shared.raw_secret_bytes().to_vec()
        }
        Curve::P521 => {
            let sk = p521::SecretKey::from_slice(private)
                .map_err(|_| err(format!("{}: the private key is not a valid P-521 scalar (66 bytes)", who)))?;
            let pk = p521::PublicKey::from_sec1_bytes(peer)
                .map_err(|_| err(format!("{}: the peer public key is not a valid SEC1 P-521 point", who)))?;
            let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            shared.raw_secret_bytes().to_vec()
        }
    })
}

fn b_ecdh_keypair(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "ecdh_keypair";
    if args.len() != 1 {
        return Err(err(format!("{}(curve) takes exactly 1 argument (\"P-256\" | \"P-521\")", F)));
    }
    let curve = Curve::parse(args.first(), F)?;
    require_random(caps, "ecdh_keypair()")?;
    let mut private = random_scalar(curve, F)?;
    let public = public_of(curve, &private, F)?;
    let mut out = IndexMap::new();
    out.insert("private".to_string(), syn_secret_bytes("ecdh_keypair.private", private.clone()));
    out.insert("public".to_string(), syn_bytes(public));
    private.zeroize();
    Ok(syn_map(out))
}

/// La CLAVE PRIVADA de `ecdh_shared_secret`: igual que `bytes_arg` pero acepta un secret
/// SELLADO — es el uso legítimo del material de la identidad atestada (MEDIO 0). El resultado
/// del ECDH es un secret nuevo (no sellado): es un valor derivado, no la clave.
fn private_key_arg(v: Option<&SynValue>, who: &str) -> Result<Vec<u8>, Control> {
    match v {
        Some(SynValue::Secret(s)) => Ok(s.expose_bytes().to_vec()),
        other => bytes_arg(other, who, "the private key").map(|(b, _)| b),
    }
}

fn b_ecdh_shared_secret(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "ecdh_shared_secret";
    if args.len() != 3 {
        return Err(err(format!("{}(private, peer_public, curve) takes exactly 3 arguments", F)));
    }
    let mut private = private_key_arg(args.first(), F)?;
    let (peer, _) = bytes_arg(args.get(1), F, "the peer public key")?;
    let curve = Curve::parse(args.get(2), F)?;
    let r = shared_secret(curve, &private, &peer, F);
    private.zeroize();
    Ok(syn_secret_bytes("ecdh_shared_secret", r?))
}

fn b_hkdf_sha256(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "hkdf_sha256";
    if args.len() != 4 {
        return Err(err(format!("{}(ikm, salt, info, length) takes exactly 4 arguments", F)));
    }
    let (mut ikm, sealed) = bytes_arg(args.first(), F, "ikm")?;
    let (salt, _) = bytes_arg(args.get(1), F, "salt")?;
    let (info, _) = bytes_arg(args.get(2), F, "info")?;
    let length = match args.get(3) {
        Some(SynValue::Number(n)) => n.to_f64(),
        Some(other) => {
            return Err(err(format!("{}: length must be a number of bytes, got {}", F, other.type_name())))
        }
        None => return Err(err(format!("{}: length is required", F))),
    };
    if !(length >= 1.0 && length <= 8160.0 && length.fract() == 0.0) {
        return Err(err(format!(
            "{}: length must be a whole number between 1 and 8160 bytes (255 × 32), got {}",
            F, length
        )));
    }
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; length as usize];
    let r = hk.expand(&info, &mut okm);
    ikm.zeroize();
    r.map_err(|_| err(format!("{}: invalid length", F)))?;
    Ok(if sealed { syn_secret_bytes("hkdf_sha256", okm) } else { syn_bytes(okm) })
}

enum Gcm {
    A128(aes_gcm::Aes128Gcm),
    A256(aes_gcm::Aes256Gcm),
}

fn gcm_cipher(key: &[u8], who: &str) -> Result<Gcm, Control> {
    use aes_gcm::aead::KeyInit;
    match key.len() {
        16 => Ok(Gcm::A128(aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| err(format!("{}: bad key", who)))?)),
        32 => Ok(Gcm::A256(aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| err(format!("{}: bad key", who)))?)),
        n => Err(err(format!(
            "{}: the key must be 16 bytes (AES-128-GCM) or 32 bytes (AES-256-GCM), got {}",
            who, n
        ))),
    }
}

fn gcm_args(args: &[SynValue], who: &str, third: &str) -> Result<(Gcm, Vec<u8>, Vec<u8>, Vec<u8>), Control> {
    if !(3..=4).contains(&args.len()) {
        return Err(err(format!("{}(key, nonce, {}, aad?) takes 3 or 4 arguments", who, third)));
    }
    let (mut key, _) = bytes_arg(args.first(), who, "the key")?;
    let cipher = gcm_cipher(&key, who);
    key.zeroize();
    let cipher = cipher?;
    let (nonce, _) = bytes_arg(args.get(1), who, "the nonce")?;
    if nonce.len() != 12 {
        return Err(err(format!("{}: the nonce must be 12 bytes (96 bits), got {}", who, nonce.len())));
    }
    let (data, _) = bytes_arg(args.get(2), who, third)?;
    let aad = match args.get(3) {
        None | Some(SynValue::Nothing) => Vec::new(),
        v => bytes_arg(v, who, "aad")?.0,
    };
    Ok((cipher, nonce, data, aad))
}

fn b_aes_gcm_encrypt(args: &[SynValue]) -> Result<SynValue, Control> {
    use aes_gcm::aead::{Aead, Payload};
    const F: &str = "aes_gcm_encrypt";
    let (cipher, nonce, plaintext, aad) = gcm_args(args, F, "plaintext")?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let payload = Payload { msg: &plaintext, aad: &aad };
    let out = match cipher {
        Gcm::A128(c) => c.encrypt(nonce, payload),
        Gcm::A256(c) => c.encrypt(nonce, payload),
    }
    .map_err(|_| err(format!("{}: encryption failed", F)))?;
    Ok(syn_bytes(out))
}

fn b_aes_gcm_decrypt(args: &[SynValue]) -> Result<SynValue, Control> {
    use aes_gcm::aead::{Aead, Payload};
    const F: &str = "aes_gcm_decrypt";
    let (cipher, nonce, ciphertext, aad) = gcm_args(args, F, "ciphertext")?;
    if ciphertext.len() < 16 {
        return Err(err(format!("{}: the ciphertext is shorter than the 16-byte tag", F)));
    }
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let payload = Payload { msg: &ciphertext, aad: &aad };
    let out = match cipher {
        Gcm::A128(c) => c.decrypt(nonce, payload),
        Gcm::A256(c) => c.decrypt(nonce, payload),
    }
    .map_err(|_| err(format!("{}: authentication failed (wrong key, nonce, aad, or tampered data)", F)))?;
    Ok(syn_bytes(out))
}

pub fn register_crypto_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    {
        let caps = caps.clone();
        interp.register_builtin("ecdh_keypair", -1, Rc::new(move |_i, a, _l| b_ecdh_keypair(&caps, a)));
    }
    interp.register_builtin("ecdh_shared_secret", -1, Rc::new(|_i, a, _l| b_ecdh_shared_secret(a)));
    interp.register_builtin("hkdf_sha256", -1, Rc::new(|_i, a, _l| b_hkdf_sha256(a)));
    interp.register_builtin("aes_gcm_encrypt", -1, Rc::new(|_i, a, _l| b_aes_gcm_encrypt(a)));
    // `aes_gcm_decrypt(key, nonce, ct, aad, default)` — la variante TOTAL de la operación
    // canónica de un enclave: un tag manipulado es "rechazo esta petición", no "el proceso muere".
    // El `aad` va explícito (puede ser `nothing`) para que el reemplazo quede en un lugar fijo.
    interp.register_builtin("aes_gcm_decrypt", -1, synsema_core::interpreter::with_fallback(4, Rc::new(|_i, a, _l| b_aes_gcm_decrypt(a))));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_text;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Un secret SELLADO (`attestation_key`) no entra a ningún
    /// borde criptográfico genérico — era el camino por el que se extraía el escalar P-256 de la
    /// identidad atestada cifrándolo con `aes_gcm_encrypt` bajo una clave del programa. El único
    /// uso legítimo, ECDH con la clave PROPIA, sigue funcionando; y el borde de TEXTO devuelve la
    /// forma redactada, así que SQL, headers y concatenación tampoco lo materializan.
    #[test]
    fn a_sealed_secret_is_rejected_by_every_generic_crypto_border() {
        use synsema_core::secret::SecretInner;
        let scalar = vec![7u8; 32];
        let sealed = SynValue::Secret(std::rc::Rc::new(SecretInner::new_bytes_sealed("attestation_key", scalar.clone())));
        let msg = |r: Result<SynValue, Control>| -> String {
            match r {
                Err(Control::Error(e)) => e.into_message(),
                Ok(v) => panic!("esperaba error, devolvió {}", v),
                Err(_) => panic!("esperaba error, hubo control flow"),
            }
        };
        let nonce = syn_bytes(vec![0u8; 12]);
        // AES-GCM: como clave y como plaintext (la extracción del auditor era la segunda).
        let e = msg(b_aes_gcm_encrypt(&[sealed.clone(), nonce.clone(), syn_text("x")]));
        assert!(e.contains("sealed") && e.contains("aes_gcm_encrypt"), "{}", e);
        let e = msg(b_aes_gcm_encrypt(&[syn_bytes(vec![1u8; 32]), nonce.clone(), sealed.clone()]));
        assert!(e.contains("sealed"), "{}", e);
        let e = msg(b_aes_gcm_decrypt(&[sealed.clone(), nonce, syn_bytes(vec![0u8; 32])]));
        assert!(e.contains("sealed"), "{}", e);
        // HKDF: como IKM, como salt y como info.
        for args in [
            vec![sealed.clone(), syn_text(""), syn_text(""), SynValue::Number(synsema_core::number::Number::Int(32))],
            vec![syn_bytes(vec![1u8; 32]), sealed.clone(), syn_text(""), SynValue::Number(synsema_core::number::Number::Int(32))],
            vec![syn_bytes(vec![1u8; 32]), syn_text(""), sealed.clone(), SynValue::Number(synsema_core::number::Number::Int(32))],
        ] {
            let e = msg(b_hkdf_sha256(&args));
            assert!(e.contains("sealed") && e.contains("hkdf_sha256"), "{}", e);
        }
        // ECDH con la clave PROPIA: es el uso legítimo y tiene que seguir andando.
        let peer = {
            let sk = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
            sk.public_key().to_encoded_point(false).as_bytes().to_vec()
        };
        let own = p256::SecretKey::from_slice(&scalar).unwrap();
        let out = match b_ecdh_shared_secret(&[sealed.clone(), syn_bytes(peer.clone()), syn_text("P-256")]) {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("ECDH con la clave propia falló: {}", e.message),
            Err(_) => panic!("ECDH con la clave propia: control flow"),
        };
        let SynValue::Secret(shared) = &out else { panic!("el shared secret es un secret") };
        assert!(!shared.is_sealed(), "el derivado NO hereda el sello (es un valor, no la clave)");
        let expect = p256::ecdh::diffie_hellman(own.to_nonzero_scalar(), p256::PublicKey::from_sec1_bytes(&peer).unwrap().as_affine());
        assert_eq!(shared.expose_bytes(), expect.raw_secret_bytes().as_slice());
        // …pero el PEER público sellado no (ahí no hay uso legítimo).
        let e = msg(b_ecdh_shared_secret(&[syn_bytes(scalar.clone()), sealed.clone(), syn_text("P-256")]));
        assert!(e.contains("sealed"), "{}", e);
        // Borde de TEXTO (SQL, header, concat, nombre de archivo): forma redactada, nunca el material.
        let SynValue::Secret(inner) = &sealed else { unreachable!() };
        assert_eq!(inner.expose(), "secret(attestation_key)");
        assert!(inner.expose_bytes_checked("x").is_err());
        // Un secret común no cambia en nada.
        let plain = SecretInner::new_bytes("k", vec![1, 2, 3]);
        assert_eq!(plain.expose_bytes_checked("x").unwrap(), &[1, 2, 3]);
    }

    fn bytes_of(v: SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b.to_vec(),
            SynValue::Secret(s) => s.expose_bytes().to_vec(),
            other => panic!("esperaba bytes, got {}", other),
        }
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn num(n: i64) -> SynValue {
        SynValue::Number(synsema_core::number::Number::Int(n))
    }

    /// RFC 5869, test case 1 (SHA-256).
    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = bytes_of(ok(b_hkdf_sha256(&[syn_bytes(ikm), syn_bytes(salt), syn_bytes(info), num(42)])));
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// NIST GCM test vectors: AES-128 (caso 1) y AES-256 (caso 13): clave y nonce cero,
    /// plaintext vacío → sólo el tag.
    #[test]
    fn aes_gcm_nist_empty_plaintext_tags() {
        let tag128 = bytes_of(ok(b_aes_gcm_encrypt(&[syn_bytes(vec![0u8; 16]), syn_bytes(vec![0u8; 12]), syn_bytes(vec![])])));
        assert_eq!(to_hex(&tag128), "58e2fccefa7e3061367f1d57a4e7455a");
        let tag256 = bytes_of(ok(b_aes_gcm_encrypt(&[syn_bytes(vec![0u8; 32]), syn_bytes(vec![0u8; 12]), syn_bytes(vec![])])));
        assert_eq!(to_hex(&tag256), "530f8afbc74536b9a963b4f1c4cb738b");
    }

    #[test]
    fn aes_gcm_round_trip_and_tamper_detection() {
        let key = syn_bytes(hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"));
        let nonce = syn_bytes(hex("cafebabefacedbaddecaf888"));
        let ct = bytes_of(ok(b_aes_gcm_encrypt(&[key.clone(), nonce.clone(), syn_text("hola mundo"), syn_text("aad")])));
        assert_eq!(ct.len(), 10 + 16);
        let pt = bytes_of(ok(b_aes_gcm_decrypt(&[key.clone(), nonce.clone(), syn_bytes(ct.clone()), syn_text("aad")])));
        assert_eq!(pt, b"hola mundo");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(matches!(b_aes_gcm_decrypt(&[key.clone(), nonce.clone(), syn_bytes(bad), syn_text("aad")]), Err(_)));
        // AAD distinto también falla.
        assert!(matches!(b_aes_gcm_decrypt(&[key, nonce, syn_bytes(ct), syn_text("otro")]), Err(_)));
    }

    /// P-256: el escalar 1 da el generador G (SEC 2 / FIPS 186-4), en SEC1 sin comprimir.
    #[test]
    fn p256_public_of_scalar_one_is_the_generator() {
        let mut one = vec![0u8; 32];
        one[31] = 1;
        let pk = public_of(Curve::P256, &one, "t").map_err(|_| ()).unwrap();
        assert_eq!(
            to_hex(&pk),
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
    }

    #[test]
    fn ecdh_round_trip_both_curves() {
        for (curve, name, plen) in [(Curve::P256, "P-256", 32usize), (Curve::P521, "P-521", 66usize)] {
            let a = random_scalar(curve, "t").map_err(|_| ()).unwrap();
            let b = random_scalar(curve, "t").map_err(|_| ()).unwrap();
            let pa = public_of(curve, &a, "t").map_err(|_| ()).unwrap();
            let pb = public_of(curve, &b, "t").map_err(|_| ()).unwrap();
            assert_eq!(pa[0], 4, "SEC1 sin comprimir");
            assert_eq!(pa.len(), 1 + 2 * plen);
            let s1 = bytes_of(ok(b_ecdh_shared_secret(&[syn_bytes(a.clone()), syn_bytes(pb), syn_text(name)])));
            let s2 = bytes_of(ok(b_ecdh_shared_secret(&[syn_bytes(b), syn_bytes(pa), syn_text(name)])));
            assert_eq!(s1, s2, "{}", name);
            assert_eq!(s1.len(), plen);
        }
    }

    #[test]
    fn keypair_requires_random() {
        let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
        let e = match b_ecdh_keypair(&caps, &[syn_text("P-521")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba denegación"),
        };
        assert!(e.contains("Capability not granted"), "{}", e);
        caps.borrow_mut().grant(Capability::new(CapabilityType::Random, None));
        let kp = ok(b_ecdh_keypair(&caps, &[syn_text("P-521")]));
        if let SynValue::Map(m) = &kp {
            assert!(matches!(m.borrow().get("private"), Some(SynValue::Secret(_))), "la privada sale sellada");
            assert!(matches!(m.borrow().get("public"), Some(SynValue::Bytes(_))));
        } else {
            panic!("esperaba map");
        }
    }
}
