//! Web auth (tanda web-auth, ítems E–H): CSPRNG expuesto (`random_bytes`/`token`),
//! password hashing argon2id (`password_hash`/`password_verify`), JWT HS256
//! (`jwt_sign`/`jwt_verify`) y TOTP RFC 6238 (`totp`/`totp_verify`).
//!
//! Doctrina de la tanda:
//! - G4: NINGUNA primitiva hand-rolled — argon2/hmac/sha vienen de RustCrypto; lo
//!   único armado a mano es *formato* (split del JWT, string base64url).
//! - G5: toda comparación de credenciales es constant-time (`constant_time_eq` de
//!   core; `password_verify` lo trae el propio argon2).
//! - G6: toda clave/contraseña acepta secret sellado, text o bytes; el valor jamás
//!   se loguea ni viaja en mensajes de error.
//! - Capabilities: los builtins cuyo PROPÓSITO es producir aleatoriedad
//!   (`random_bytes`/`token`) están gateados por `random` — la MISMA puerta
//!   deny-by-default de `random()`/`random_int()`; dejarlos libres la volvería
//!   decorativa. Los transforms puros (password/jwt/totp) no llevan gate (mismo
//!   criterio que `hmac_sha256`/`sha256`); la salt interna de `password_hash` no
//!   cuenta como "producir aleatoriedad" (mismo precedente que el token interno
//!   de `redis_lock`).

use std::cell::RefCell;
use std::rc::Rc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use indexmap::IndexMap;
use zeroize::Zeroize;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use sha2::Sha256;
use synsema_core::bytesutil::{b64_decode, b64url_decode, b64url_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::constant_time_eq;
use synsema_core::types::{syn_int, syn_map, syn_nothing, syn_text, SynValue};

use crate::secrets::{hmac_compute, Algo};
use crate::json::{dumps, json_to_syn, syn_to_json};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn syn_bool(b: bool) -> SynValue {
    SynValue::Bool(b)
}

fn syn_bytes(b: Vec<u8>) -> SynValue {
    SynValue::Bytes(Rc::from(b.into_boxed_slice()))
}

// =========================================================
// Helpers comunes
// =========================================================

/// Material de clave/contraseña (G6): un secret aporta su plaintext (uso interno,
/// la salida es un hash/MAC/bool — no filtra), text sus bytes UTF-8 crudos
/// (explícito > magia: un secret TOTP en base32 se pasa `bytes(x, "base32")`),
/// bytes tal cual. Cualquier otro tipo es error claro — jamás una coerción por
/// Display que meta un repr como material criptográfico.
fn key_material(v: &SynValue, who: &str, what: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Secret(s) => Ok(s.expose_bytes().to_vec()),
        SynValue::Text(s) => Ok(s.as_bytes().to_vec()),
        SynValue::Bytes(b) => Ok(b.to_vec()),
        other => Err(err(format!(
            "{}: {} must be a secret, text or bytes, got {}",
            who,
            what,
            other.type_name()
        ))),
    }
}

/// Gate `random` (deny-by-default, la misma puerta de `random()`/`random_int()`).
/// El mensaje de la violación ya trae el fix (`add \`require random\``).
fn require_random(caps: &Rc<RefCell<CapabilitySet>>, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Random, None), source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// n bytes del CSPRNG del SO (OsRng — jamás el `rand` no-cripto de `random()`).
pub(crate) fn os_random(n: usize, who: &str) -> Result<Vec<u8>, Control> {
    let mut out = vec![0u8; n];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut out)
        .map_err(|_| err(format!("{}: the OS random source is unavailable", who)))?;
    Ok(out)
}

/// Unix timestamp actual (segundos). std::time — chrono va sin feature `clock`.
fn unix_now() -> i64 {
    synsema_core::clock::now_secs()
}

/// Entero i64 de un opt, con validación de tipo y rango inferior.
fn opt_int(v: &SynValue, who: &str, name: &str, min: i64) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) => match n.to_i64_trunc() {
            Some(i) if i >= min => Ok(i),
            _ => Err(err(format!(
                "{}: {} must be an integer >= {}, got {}",
                who, name, min, v
            ))),
        },
        other => Err(err(format!(
            "{}: {} must be an integer, got {}",
            who,
            name,
            other.type_name()
        ))),
    }
}

/// El map de opts (o nothing/ausente → vacío). Otro tipo → error claro.
fn opts_map(v: Option<&SynValue>, who: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(IndexMap::new()),
        Some(SynValue::Map(m)) => Ok(m.borrow().clone()),
        Some(other) => Err(err(format!(
            "{}: opts must be a map, got {}",
            who,
            other.type_name()
        ))),
    }
}

// =========================================================
// Ítem E — CSPRNG expuesto
// =========================================================

fn b_random_bytes(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "random_bytes";
    let n = match args.first() {
        Some(v) => opt_int(v, F, "n", 1)?,
        None => return Err(err(format!("{}(n) requires the number of bytes", F))),
    };
    if !(1..=65536).contains(&n) {
        return Err(err(format!(
            "{}: n must be between 1 and 65536 bytes, got {}",
            F, n
        )));
    }
    Ok(syn_bytes(os_random(n as usize, F)?))
}

fn b_token(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "token";
    let n = match args.first() {
        None | Some(SynValue::Nothing) => 32,
        Some(v) => opt_int(v, F, "n", 1)?,
    };
    // Menos de 16 bytes de entropía en un token de sesión/CSRF es un footgun.
    if !(16..=256).contains(&n) {
        return Err(err(format!(
            "{}: n must be between 16 and 256 bytes (fewer than 16 bytes of entropy \
             is guessable; the default 32 is fine for sessions), got {}",
            F, n
        )));
    }
    Ok(syn_text(b64url_encode(&os_random(n as usize, F)?)))
}

// =========================================================
// Ítem F — Password hashing (argon2id, parámetros OWASP)
// =========================================================

/// Instancia argon2id v19 con los parámetros OWASP pineados: m=19456 KiB, t=2,
/// p=1. SIN opts en v1: el string PHC lleva los parámetros, así que subirlos en
/// el futuro no rompe la verificación de hashes viejos.
fn argon2id_owasp() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("static OWASP argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn b_password_hash(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "password_hash";
    let pw_arg = args
        .first()
        .ok_or_else(|| err(format!("{}(password) requires the password", F)))?;
    let mut pw = key_material(pw_arg, F, "the password")?;
    // Salt de 16 bytes de OsRng (el default PHC).
    let salt_bytes = os_random(16, F)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| err(format!("{}: could not encode the salt: {}", F, e)))?;
    let hashed = argon2id_owasp().hash_password(&pw, &salt);
    pw.zeroize();
    match hashed {
        Ok(h) => Ok(syn_text(h.to_string())),
        // Sin detalle del password en el error (G6) — argon2 no lo incluye.
        Err(e) => Err(err(format!("{}: hashing failed: {}", F, e))),
    }
}

fn b_password_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "password_verify";
    if args.len() != 2 {
        return Err(err(format!("{}(password, phc_hash) takes 2 arguments", F)));
    }
    let mut pw = key_material(&args[0], F, "the password")?;
    let phc = match &args[1] {
        SynValue::Text(s) => s.to_string(),
        other => {
            pw.zeroize();
            return Err(err(format!(
                "{}: the stored hash must be text (the PHC string from password_hash), got {}",
                F,
                other.type_name()
            )));
        }
    };
    // PHC malformado o de esquema desconocido → ERROR, no false: "contraseña
    // incorrecta" y "hash corrupto en la DB" no deben confundirse jamás.
    let parsed = match PasswordHash::new(&phc) {
        Ok(p) => p,
        Err(e) => {
            pw.zeroize();
            return Err(err(format!(
                "{}: the stored hash is not a valid PHC string (expected the \
                 \"$argon2id$...\" produced by password_hash): {}",
                F, e
            )));
        }
    };
    // Verificación con los parámetros del PHC; la comparación interna del crate
    // es constant-time (G5).
    let out = match argon2id_owasp().verify_password(&pw, &parsed) {
        Ok(()) => Ok(syn_bool(true)),
        Err(argon2::password_hash::Error::Password) => Ok(syn_bool(false)),
        Err(e) => Err(err(format!(
            "{}: the stored hash could not be verified (unsupported scheme or \
             corrupt hash): {}",
            F, e
        ))),
    };
    pw.zeroize();
    out
}

// =========================================================
// Ítem G — JWT (HS256, pineado)
// =========================================================

/// Header fijo. El algoritmo lo fija el EMISOR y lo exige el VERIFICADOR; jamás
/// se lee del token (ver `b_jwt_verify`).
const JWT_HEADER: &str = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

fn b_jwt_sign(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "jwt_sign";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(claims, key, opts?) takes 2 or 3 arguments", F)));
    }
    let claims = match &args[0] {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: claims must be a map, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let mut key = key_material(&args[1], F, "the key")?;
    let opts = opts_map(args.get(2), F)?;
    let mut expires_in: Option<i64> = None;
    // v0.6.20 — `alg`: HS256 (default, como siempre) | RS256 | ES256. Lo fija el FIRMANTE por
    // opción, jamás el contenido de la clave (misma doctrina que el verificador). `kid` viaja
    // en el header: GitHub Apps, las service accounts de Google y Apple lo esperan.
    let mut alg = JwtAlg::Hs256;
    let mut kid: Option<String> = None;
    for (k, v) in &opts {
        match k.as_str() {
            "expires_in" => expires_in = Some(opt_int(v, F, "expires_in", 1)?),
            "alg" => {
                alg = match v {
                    SynValue::Text(s) => match JwtAlg::parse(s) {
                        Some(a) => a,
                        None => {
                            key.zeroize();
                            return Err(err(format!(
                                "{}: unknown alg {:?} (supported: HS256, RS256, ES256)",
                                F, s
                            )));
                        }
                    },
                    other => {
                        key.zeroize();
                        return Err(err(format!("{}: alg must be text, got {}", F, other.type_name())));
                    }
                }
            }
            "kid" => {
                kid = match v {
                    SynValue::Text(s) if !s.is_empty() => Some(s.to_string()),
                    _ => {
                        key.zeroize();
                        return Err(err(format!("{}: kid must be a non-empty text", F)));
                    }
                }
            }
            other => {
                key.zeroize();
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: expires_in, alg, kid)",
                    F, other
                )));
            }
        }
    }
    let mut payload = claims;
    // `iat` siempre; el explícito del caller gana (explícito > magia).
    let now = unix_now();
    if !payload.contains_key("iat") {
        payload.insert("iat".to_string(), syn_int(now));
    }
    if let Some(ttl) = expires_in {
        // Un `exp` explícito Y `expires_in` a la vez es ambiguo → error claro.
        if payload.contains_key("exp") {
            key.zeroize();
            return Err(err(format!(
                "{}: the claims already contain \"exp\" — pass either an explicit \
                 exp claim or opts.expires_in, not both",
                F
            )));
        }
        payload.insert("exp".to_string(), syn_int(now + ttl));
    }
    let payload_json = dumps(&syn_to_json(&syn_map(payload)));
    let header = jwt_header(alg, kid.as_deref());
    let signing_input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload_json.as_bytes())
    );
    let signature = match alg {
        JwtAlg::Hs256 => hmac_compute(Algo::Sha256, &key, signing_input.as_bytes()),
        JwtAlg::Rs256 | JwtAlg::Es256 => {
            let pem = match String::from_utf8(key.clone()) {
                Ok(s) => s,
                Err(_) => {
                    key.zeroize();
                    return Err(err(format!(
                        "{}: for {} the key must be a PEM (text, or a secret holding the PEM text)",
                        F,
                        alg.name()
                    )));
                }
            };
            let r = match (alg, private_key_from_pem(&pem, F)) {
                (JwtAlg::Rs256, Ok(AsymPrivate::Rsa(k))) => Ok(rs256_sign(&k, signing_input.as_bytes())),
                (JwtAlg::Es256, Ok(AsymPrivate::P256(k))) => Ok(es256_sign(&k, signing_input.as_bytes())),
                (JwtAlg::Rs256, Ok(AsymPrivate::P256(_))) => {
                    Err(err(format!("{}: alg RS256 needs an RSA private key, got an EC (P-256) key", F)))
                }
                (JwtAlg::Es256, Ok(AsymPrivate::Rsa(_))) => {
                    Err(err(format!("{}: alg ES256 needs a P-256 private key, got an RSA key", F)))
                }
                (_, Err(e)) => Err(e),
                (JwtAlg::Hs256, Ok(_)) => unreachable!("HS256 no pasa por acá"),
            };
            match r {
                Ok(s) => s,
                Err(e) => {
                    key.zeroize();
                    return Err(e);
                }
            }
        }
    };
    key.zeroize();
    Ok(syn_text(format!("{}.{}", signing_input, b64url_encode(&signature))))
}

// =========================================================
// v0.6.20 — firma asimétrica: RS256 / ES256 (JWT), rsa_* / ecdsa_p256_* (crudos)
// =========================================================
//
// Las claves llegan como PEM (lo que entrega GitHub para una App, Google para una service
// account, `openssl`), como texto o como `secret` con ese texto. El PEM se decodifica acá
// (base64 estándar → DER) y el DER de PKCS#8 / SEC1 / SPKI se desarma con un lector mínimo:
// así `rsa` y `p256` se usan con las MISMAS features que ya tenían para `oidc_verify` y no
// entra ningún crate ni feature nuevos por esta tanda. Nada de esto requiere `sign`: esa
// capability gatea mover valor on-chain; acá la clave ya es un `secret` del programa.

#[derive(Clone, Copy, PartialEq, Eq)]
enum JwtAlg {
    Hs256,
    Rs256,
    Es256,
}

impl JwtAlg {
    fn parse(s: &str) -> Option<JwtAlg> {
        match s.to_ascii_uppercase().as_str() {
            "HS256" => Some(JwtAlg::Hs256),
            "RS256" => Some(JwtAlg::Rs256),
            "ES256" => Some(JwtAlg::Es256),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            JwtAlg::Hs256 => "HS256",
            JwtAlg::Rs256 => "RS256",
            JwtAlg::Es256 => "ES256",
        }
    }
}

/// Header JOSE. Sin `kid` y con HS256 es byte a byte el histórico (`JWT_HEADER`).
fn jwt_header(alg: JwtAlg, kid: Option<&str>) -> String {
    match (alg, kid) {
        (JwtAlg::Hs256, None) => JWT_HEADER.to_string(),
        (alg, None) => format!("{{\"alg\":\"{}\",\"typ\":\"JWT\"}}", alg.name()),
        (alg, Some(k)) => format!(
            "{{\"alg\":\"{}\",\"kid\":{},\"typ\":\"JWT\"}}",
            alg.name(),
            dumps(&syn_to_json(&syn_text(k)))
        ),
    }
}

/// PEM → (etiqueta, DER). Acepta `\\n` literales (un PEM metido en una línea de `.env`).
fn pem_decode(text: &str) -> Result<(String, Vec<u8>), String> {
    let t = text.replace("\\n", "\n");
    let begin = t.find("-----BEGIN ").ok_or("not a PEM: missing '-----BEGIN'")?;
    let after = &t[begin + 11..];
    let label_end = after.find("-----").ok_or("malformed PEM header")?;
    let label = after[..label_end].trim().to_string();
    let body_start = begin + 11 + label_end + 5;
    let end_marker = format!("-----END {}-----", label);
    let end = t[body_start..].find(&end_marker).ok_or("malformed PEM: missing the END line")? + body_start;
    let b64: String = t[body_start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = b64_decode(&b64).map_err(|e| format!("PEM body is not base64: {}", e))?;
    Ok((label, der))
}

/// Lector DER mínimo (TLV, longitudes cortas y largas). Suficiente para PKCS#8, SEC1 y SPKI.
struct DerReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> DerReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        DerReader { b, i: 0 }
    }
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), String> {
        let tag = *self.b.get(self.i).ok_or("DER: truncated")?;
        let first = *self.b.get(self.i + 1).ok_or("DER: truncated")? as usize;
        let (len, hdr) = if first & 0x80 == 0 {
            (first, 2)
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 {
                return Err("DER: unsupported length".to_string());
            }
            let mut len = 0usize;
            for k in 0..n {
                len = (len << 8) | *self.b.get(self.i + 2 + k).ok_or("DER: truncated")? as usize;
            }
            (len, 2 + n)
        };
        let start = self.i + hdr;
        let end = start.checked_add(len).filter(|e| *e <= self.b.len()).ok_or("DER: truncated")?;
        self.i = end;
        Ok((tag, &self.b[start..end]))
    }
}

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// SEC1 `ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, … }` → el escalar.
fn ec_scalar_from_sec1(der: &[u8]) -> Result<Vec<u8>, String> {
    let (tag, seq) = DerReader::new(der).tlv()?;
    if tag != 0x30 {
        return Err("SEC1: expected SEQUENCE".to_string());
    }
    let mut r = DerReader::new(seq);
    let (t1, _version) = r.tlv()?;
    let (t2, key) = r.tlv()?;
    if t1 != 0x02 || t2 != 0x04 {
        return Err("SEC1: expected INTEGER version and OCTET STRING privateKey".to_string());
    }
    Ok(key.to_vec())
}

/// PKCS#8 `PrivateKeyInfo` → (OID del algoritmo, DER interno de la clave).
fn pkcs8_unwrap(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (tag, seq) = DerReader::new(der).tlv()?;
    if tag != 0x30 {
        return Err("PKCS#8: expected SEQUENCE".to_string());
    }
    let mut r = DerReader::new(seq);
    let (_t0, _version) = r.tlv()?;
    let (t1, alg) = r.tlv()?;
    let (t2, inner) = r.tlv()?;
    if t1 != 0x30 || t2 != 0x04 {
        return Err("PKCS#8: expected AlgorithmIdentifier and OCTET STRING".to_string());
    }
    let (t3, oid) = DerReader::new(alg).tlv()?;
    if t3 != 0x06 {
        return Err("PKCS#8: expected an OID".to_string());
    }
    Ok((oid.to_vec(), inner.to_vec()))
}

/// SPKI `SubjectPublicKeyInfo` → (OID del algoritmo, contenido del BIT STRING sin el byte de
/// bits sin usar).
fn spki_unwrap(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (tag, seq) = DerReader::new(der).tlv()?;
    if tag != 0x30 {
        return Err("SPKI: expected SEQUENCE".to_string());
    }
    let mut r = DerReader::new(seq);
    let (t1, alg) = r.tlv()?;
    let (t2, bits) = r.tlv()?;
    if t1 != 0x30 || t2 != 0x03 || bits.is_empty() {
        return Err("SPKI: expected AlgorithmIdentifier and BIT STRING".to_string());
    }
    let (t3, oid) = DerReader::new(alg).tlv()?;
    if t3 != 0x06 {
        return Err("SPKI: expected an OID".to_string());
    }
    Ok((oid.to_vec(), bits[1..].to_vec()))
}

enum AsymPrivate {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::SecretKey),
}

enum AsymPublic {
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

fn private_key_from_pem(text: &str, who: &str) -> Result<AsymPrivate, Control> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    let (label, der) = pem_decode(text).map_err(|e| err(format!("{}: {}", who, e)))?;
    let bad = |what: &str| err(format!("{}: the PEM is not a valid {} ({})", who, label, what));
    match label.as_str() {
        "RSA PRIVATE KEY" => rsa::RsaPrivateKey::from_pkcs1_der(&der)
            .map(AsymPrivate::Rsa)
            .map_err(|_| bad("PKCS#1 RSAPrivateKey")),
        "EC PRIVATE KEY" => {
            let scalar = ec_scalar_from_sec1(&der).map_err(|e| bad(&e))?;
            p256::SecretKey::from_slice(&scalar)
                .map(AsymPrivate::P256)
                .map_err(|_| bad("P-256 scalar; only P-256 (prime256v1) is supported"))
        }
        "PRIVATE KEY" => {
            let (oid, inner) = pkcs8_unwrap(&der).map_err(|e| bad(&e))?;
            if oid == OID_RSA_ENCRYPTION {
                rsa::RsaPrivateKey::from_pkcs1_der(&inner)
                    .map(AsymPrivate::Rsa)
                    .map_err(|_| bad("PKCS#8 RSA key"))
            } else if oid == OID_EC_PUBLIC_KEY {
                let scalar = ec_scalar_from_sec1(&inner).map_err(|e| bad(&e))?;
                p256::SecretKey::from_slice(&scalar)
                    .map(AsymPrivate::P256)
                    .map_err(|_| bad("P-256 scalar; only P-256 (prime256v1) is supported"))
            } else {
                Err(bad("unsupported algorithm OID; RSA and P-256 are supported"))
            }
        }
        other => Err(err(format!(
            "{}: unsupported PEM label {:?} (expected PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY)",
            who, other
        ))),
    }
}

fn public_key_from_pem(text: &str, who: &str) -> Result<AsymPublic, Control> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let (label, der) = pem_decode(text).map_err(|e| err(format!("{}: {}", who, e)))?;
    let bad = |what: &str| err(format!("{}: the PEM is not a valid {} ({})", who, label, what));
    match label.as_str() {
        "RSA PUBLIC KEY" => rsa::RsaPublicKey::from_pkcs1_der(&der)
            .map(AsymPublic::Rsa)
            .map_err(|_| bad("PKCS#1 RSAPublicKey")),
        "PUBLIC KEY" => {
            let (oid, bits) = spki_unwrap(&der).map_err(|e| bad(&e))?;
            if oid == OID_RSA_ENCRYPTION {
                rsa::RsaPublicKey::from_pkcs1_der(&bits)
                    .map(AsymPublic::Rsa)
                    .map_err(|_| bad("SPKI RSA key"))
            } else if oid == OID_EC_PUBLIC_KEY {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&bits)
                    .map(AsymPublic::P256)
                    .map_err(|_| bad("SEC1 P-256 point; only P-256 (prime256v1) is supported"))
            } else {
                Err(bad("unsupported algorithm OID; RSA and P-256 are supported"))
            }
        }
        other => Err(err(format!(
            "{}: unsupported PEM label {:?} (expected PUBLIC KEY or RSA PUBLIC KEY)",
            who, other
        ))),
    }
}

/// RSASSA-PKCS1-v1_5 con SHA-256 (RS256). Determinista.
fn rs256_sign(key: &rsa::RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    let sk = SigningKey::<Sha256>::new(key.clone());
    sk.sign(msg).to_bytes().to_vec()
}

fn rs256_verify(key: &rsa::RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let vk = VerifyingKey::<Sha256>::new(key.clone());
    match Signature::try_from(sig) {
        Ok(s) => vk.verify(msg, &s).is_ok(),
        Err(_) => false,
    }
}

/// ECDSA P-256 con SHA-256 (ES256): firma CRUDA r‖s de 64 bytes (JWS), nonce RFC 6979
/// (determinista, sin depender de la entropía del host).
fn es256_sign(key: &p256::SecretKey, msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from(key.clone());
    let sig: Signature = sk.sign(msg);
    sig.to_bytes().to_vec()
}

fn es256_verify(vk: &p256::ecdsa::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::Signature;
    if sig.len() != 64 {
        return false;
    }
    match Signature::from_slice(sig) {
        Ok(s) => vk.verify(msg, &s).is_ok(),
        Err(_) => false,
    }
}

fn msg_bytes(v: &SynValue, who: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Text(s) => Ok(s.as_bytes().to_vec()),
        SynValue::Bytes(b) => Ok(b.to_vec()),
        SynValue::Secret(_) => Err(err(format!("{}: the message cannot be a secret (sign its plaintext form explicitly)", who))),
        other => Err(err(format!("{}: the message must be text or bytes, got {}", who, other.type_name()))),
    }
}

fn pem_text(v: &SynValue, who: &str, what: &str) -> Result<String, Control> {
    let mut raw = key_material(v, who, what)?;
    let s = String::from_utf8(raw.clone());
    raw.zeroize();
    s.map_err(|_| err(format!("{}: {} must be a PEM (text, or a secret holding the PEM text)", who, what)))
}

fn b_rsa_sign_sha256(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "rsa_sign_sha256";
    if args.len() != 2 {
        return Err(err(format!("{}(message, private_key_pem) takes exactly 2 arguments", F)));
    }
    let msg = msg_bytes(&args[0], F)?;
    let pem = pem_text(&args[1], F, "the private key")?;
    match private_key_from_pem(&pem, F)? {
        AsymPrivate::Rsa(k) => Ok(syn_bytes(rs256_sign(&k, &msg))),
        AsymPrivate::P256(_) => Err(err(format!("{}: needs an RSA private key, got an EC key (use ecdsa_p256_sign)", F))),
    }
}

fn b_rsa_verify_sha256(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "rsa_verify_sha256";
    if args.len() != 3 {
        return Err(err(format!("{}(message, signature, public_key_pem) takes exactly 3 arguments", F)));
    }
    let msg = msg_bytes(&args[0], F)?;
    let sig = match &args[1] {
        SynValue::Bytes(b) => b.to_vec(),
        other => return Err(err(format!("{}: the signature must be bytes, got {}", F, other.type_name()))),
    };
    let pem = pem_text(&args[2], F, "the public key")?;
    match public_key_from_pem(&pem, F)? {
        AsymPublic::Rsa(k) => Ok(syn_bool(rs256_verify(&k, &msg, &sig))),
        AsymPublic::P256(_) => Err(err(format!("{}: needs an RSA public key, got an EC key (use ecdsa_p256_verify)", F))),
    }
}

fn b_ecdsa_p256_sign(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "ecdsa_p256_sign";
    if args.len() != 2 {
        return Err(err(format!("{}(message, private_key_pem) takes exactly 2 arguments", F)));
    }
    let msg = msg_bytes(&args[0], F)?;
    let pem = pem_text(&args[1], F, "the private key")?;
    match private_key_from_pem(&pem, F)? {
        AsymPrivate::P256(k) => Ok(syn_bytes(es256_sign(&k, &msg))),
        AsymPrivate::Rsa(_) => Err(err(format!("{}: needs a P-256 private key, got an RSA key (use rsa_sign_sha256)", F))),
    }
}

fn b_ecdsa_p256_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "ecdsa_p256_verify";
    if args.len() != 3 {
        return Err(err(format!("{}(message, signature, public_key_pem) takes exactly 3 arguments", F)));
    }
    let msg = msg_bytes(&args[0], F)?;
    let sig = match &args[1] {
        SynValue::Bytes(b) => b.to_vec(),
        other => return Err(err(format!("{}: the signature must be bytes (64 bytes r‖s), got {}", F, other.type_name()))),
    };
    let pem = pem_text(&args[2], F, "the public key")?;
    match public_key_from_pem(&pem, F)? {
        AsymPublic::P256(k) => Ok(syn_bool(es256_verify(&k, &msg, &sig))),
        AsymPublic::Rsa(_) => Err(err(format!("{}: needs a P-256 public key, got an RSA key (use rsa_verify_sha256)", F))),
    }
}

fn b_jwt_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "jwt_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(token, key, opts?) takes 2 or 3 arguments", F)));
    }
    let token = match &args[0] {
        SynValue::Text(s) => s.to_string(),
        // Un no-texto no puede ser un JWT válido → nothing (mismo contrato que
        // cualquier otra malformación; los errores de opts sí son del caller).
        _ => return Ok(syn_nothing()),
    };
    let mut key = key_material(&args[1], F, "the key")?;
    let opts = opts_map(args.get(2), F)?;
    let mut leeway: i64 = 60;
    for (k, v) in &opts {
        match k.as_str() {
            "leeway" => leeway = opt_int(v, F, "leeway", 0)?,
            other => {
                key.zeroize();
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: leeway)",
                    F, other
                )));
            }
        }
    }
    // Toda falla del token → nothing, sin detalle: un endpoint no debe poder
    // distinguirse por QUÉ rechazó (firma vs exp vs malformado).
    let out = jwt_verify_inner(&token, &key, leeway);
    key.zeroize();
    Ok(out.unwrap_or_else(syn_nothing))
}

/// El pipeline de verificación. `None` = rechazo (por cualquier causa).
fn jwt_verify_inner(token: &str, key: &[u8], leeway: i64) -> Option<SynValue> {
    // 1. split estricto en 3 partes + base64url decode + JSON parse.
    let mut parts = token.split('.');
    let (h_b64, p_b64, s_b64) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header_bytes = b64url_decode(h_b64).ok()?;
    let payload_bytes = b64url_decode(p_b64).ok()?;
    let sig = b64url_decode(s_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    // 2. El algoritmo lo fija el VERIFICADOR, jamás el token. `"none"`, `"RS256"`
    //    o cualquier otro valor → rechazo. Aceptar el alg del header es LA
    //    vulnerabilidad clásica de JWT (CVE-2015-9235 y familia).
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return None;
    }
    // 3. Firma sobre los bytes RECIBIDOS (no re-serializados), constant-time (G5).
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let expected = hmac_compute(Algo::Sha256, key, signing_input.as_bytes());
    if !constant_time_eq(&expected, &sig) {
        return None;
    }
    // 4. Ventana temporal: exp/nbf si presentes, con leeway. Un exp/nbf presente
    //    pero no-numérico es un token malformado → rechazo.
    let claims_obj = payload.as_object()?;
    let now = unix_now();
    if let Some(exp) = claims_obj.get("exp") {
        let exp = exp.as_i64()?;
        if now > exp + leeway {
            return None;
        }
    }
    if let Some(nbf) = claims_obj.get("nbf") {
        let nbf = nbf.as_i64()?;
        if now < nbf - leeway {
            return None;
        }
    }
    Some(json_to_syn(&payload))
}

// =========================================================
// Ítem H — TOTP (RFC 6238)
// =========================================================

/// Algoritmo del HMAC de TOTP. SHA-1 SOLO entra acá (es el default del RFC y de
/// Google Authenticator) — NO se expone como builtin de hash general.
#[derive(Clone, Copy)]
enum TotpAlgo {
    Sha1,
    Sha256,
}

struct TotpOpts {
    algo: TotpAlgo,
    digits: u32,
    period: i64,
    at: i64,
    window: i64,
}

fn parse_totp_opts(v: Option<&SynValue>, who: &str, allow_window: bool) -> Result<TotpOpts, Control> {
    let mut out = TotpOpts {
        algo: TotpAlgo::Sha1,
        digits: 6,
        period: 30,
        at: unix_now(),
        window: 1,
    };
    for (k, val) in &opts_map(v, who)? {
        match (k.as_str(), allow_window) {
            ("algo", _) => match val.to_string().to_ascii_lowercase().as_str() {
                "sha1" => out.algo = TotpAlgo::Sha1,
                "sha256" => out.algo = TotpAlgo::Sha256,
                other => {
                    return Err(err(format!(
                        "{}: algo must be \"sha1\" (the RFC/Google Authenticator \
                         default) or \"sha256\", got {:?}",
                        who, other
                    )))
                }
            },
            ("digits", _) => {
                let d = opt_int(val, who, "digits", 6)?;
                if !(6..=8).contains(&d) {
                    return Err(err(format!(
                        "{}: digits must be between 6 and 8 (RFC 6238), got {}",
                        who, d
                    )));
                }
                out.digits = d as u32;
            }
            ("period", _) => {
                let p = opt_int(val, who, "period", 1)?;
                if p > 3600 {
                    return Err(err(format!(
                        "{}: period must be at most 3600 seconds, got {}",
                        who, p
                    )));
                }
                out.period = p;
            }
            ("at", _) => out.at = opt_int(val, who, "at", 0)?,
            ("window", true) => {
                let w = opt_int(val, who, "window", 0)?;
                if w > 10 {
                    return Err(err(format!(
                        "{}: window must be at most 10 periods (a wide window \
                         defeats the point of TOTP), got {}",
                        who, w
                    )));
                }
                out.window = w;
            }
            (other, _) => {
                let valid = if allow_window {
                    "algo, digits, period, at, window"
                } else {
                    "algo, digits, period, at"
                };
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: {})",
                    who, other, valid
                )));
            }
        }
    }
    Ok(out)
}

/// El código TOTP de un contador concreto (RFC 6238 sobre el HOTP de RFC 4226).
fn totp_code(key: &[u8], counter: i64, o: &TotpOpts) -> String {
    let mac = match o.algo {
        TotpAlgo::Sha1 => {
            use hmac::Mac;
            let mut m = <hmac::Hmac<sha1::Sha1>>::new_from_slice(key)
                .expect("HMAC takes any key length");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha256 => hmac_compute(Algo::Sha256, key, &counter.to_be_bytes()),
    };
    // Truncado dinámico (RFC 4226 §5.3): offset = nibble bajo del último byte,
    // 31 bits big-endian desde ahí, módulo 10^digits, con ceros a la izquierda.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let code = bin % 10u32.pow(o.digits);
    format!("{:0width$}", code, width = o.digits as usize)
}

fn b_totp(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "totp";
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!("{}(key, opts?) takes 1 or 2 arguments", F)));
    }
    // Text se toma como UTF-8 CRUDO (explícito > magia): el secret típico en
    // base32 se pasa `totp(bytes(seed_b32, "base32"))`.
    let mut key = key_material(&args[0], F, "the key")?;
    let o = parse_totp_opts(args.get(1), F, false)?;
    let code = totp_code(&key, o.at.div_euclid(o.period), &o);
    key.zeroize();
    Ok(syn_text(code))
}

fn b_totp_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "totp_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(key, code, opts?) takes 2 or 3 arguments", F)));
    }
    let mut key = key_material(&args[0], F, "the key")?;
    let submitted = match &args[1] {
        SynValue::Text(s) => s.trim().to_string(),
        other => {
            key.zeroize();
            // Un código como número perdería los ceros a la izquierda — text.
            return Err(err(format!(
                "{}: the code must be text (leading zeros matter — quote it), got {}",
                F,
                other.type_name()
            )));
        }
    };
    let o = parse_totp_opts(args.get(2), F, true)?;
    let t = o.at.div_euclid(o.period);
    // Ventana ±window períodos; comparación constant-time (G5) y SIN cortocircuito
    // temprano por match (se recorren todos los contadores igual).
    let mut ok = false;
    for c in (t - o.window)..=(t + o.window) {
        if constant_time_eq(totp_code(&key, c, &o).as_bytes(), submitted.as_bytes()) {
            ok = true;
        }
    }
    key.zeroize();
    Ok(syn_bool(ok))
}

// =========================================================
// Registro
// =========================================================

/// Registra los builtins de web auth. Wired en `wire_common_with_state`
/// (engine.rs) junto a `register_hash_builtins` → existe en el intérprete
/// principal Y en los de serve/parallel/cron. `random_bytes`/`token` cierran
/// sobre el `CapabilitySet` para gatear `random` (deny-by-default; `sandbox`
/// los vacía); el resto es puro y no toca `caps`.
pub fn register_webauth_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random_bytes",
            1,
            Rc::new(move |_i, a, _l| {
                require_random(&caps, "random_bytes()")?;
                b_random_bytes(a)
            }),
        );
    }
    {
        let caps = caps.clone();
        interp.register_builtin(
            "token",
            -1,
            Rc::new(move |_i, a, _l| {
                require_random(&caps, "token()")?;
                b_token(a)
            }),
        );
    }
    interp.register_builtin("password_hash", 1, Rc::new(|_i, a, _l| b_password_hash(a)));
    interp.register_builtin("password_verify", 2, Rc::new(|_i, a, _l| b_password_verify(a)));
    interp.register_builtin("jwt_sign", -1, Rc::new(|_i, a, _l| b_jwt_sign(a)));
    // v0.6.20 — firma asimétrica cruda (RS256 / ES256 sin el envoltorio JWT).
    interp.register_builtin("rsa_sign_sha256", -1, Rc::new(|_i, a, _l| b_rsa_sign_sha256(a)));
    interp.register_builtin("rsa_verify_sha256", -1, Rc::new(|_i, a, _l| b_rsa_verify_sha256(a)));
    interp.register_builtin("ecdsa_p256_sign", -1, Rc::new(|_i, a, _l| b_ecdsa_p256_sign(a)));
    interp.register_builtin("ecdsa_p256_verify", -1, Rc::new(|_i, a, _l| b_ecdsa_p256_verify(a)));
    interp.register_builtin("jwt_verify", -1, Rc::new(|_i, a, _l| b_jwt_verify(a)));
    interp.register_builtin("totp", -1, Rc::new(|_i, a, _l| b_totp(a)));
    interp.register_builtin("totp_verify", -1, Rc::new(|_i, a, _l| b_totp_verify(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> SynValue {
        syn_text(s)
    }

    /// unwrap sin exigir Debug en Control (que no lo implementa).
    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("unexpected error: {}", e),
            Err(_) => panic!("unexpected control flow"),
        }
    }

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn bytes_val(b: &[u8]) -> SynValue {
        syn_bytes(b.to_vec())
    }

    // ---- Ítem E ----

    #[test]
    fn random_bytes_length_and_range() {
        let v = ok(b_random_bytes(&[syn_int(16)]));
        match v {
            SynValue::Bytes(b) => assert_eq!(b.len(), 16),
            _ => panic!("expected bytes"),
        }
        // Dos tiradas no coinciden (probabilidad 2^-128).
        let a = ok(b_random_bytes(&[syn_int(16)]));
        let b = ok(b_random_bytes(&[syn_int(16)]));
        assert!(!a.syn_equals(&b));
        assert!(b_random_bytes(&[syn_int(0)]).is_err());
        assert!(b_random_bytes(&[syn_int(65537)]).is_err());
        assert!(b_random_bytes(&[text("x")]).is_err());
    }

    #[test]
    fn token_shape_and_range() {
        // 32 bytes → 43 chars base64url sin padding.
        let t = ok(b_token(&[])).to_string();
        assert_eq!(t.len(), 43);
        assert!(!t.contains('=') && !t.contains('+') && !t.contains('/'));
        let t16 = ok(b_token(&[syn_int(16)])).to_string();
        assert_eq!(t16.len(), 22);
        assert!(b_token(&[syn_int(8)]).is_err(), "menos de 16 bytes es footgun");
        assert!(b_token(&[syn_int(257)]).is_err());
    }

    // ---- Ítem F ----

    #[test]
    fn password_hash_and_verify_roundtrip() {
        let phc = ok(b_password_hash(&[text("hunter2")])).to_string();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "PHC OWASP: {}", phc);
        let good = ok(b_password_verify(&[text("hunter2"), text(&phc)]));
        assert!(matches!(good, SynValue::Bool(true)));
        let bad = ok(b_password_verify(&[text("wrong"), text(&phc)]));
        assert!(matches!(bad, SynValue::Bool(false)));
        // Dos hashes del mismo password difieren (salt aleatoria).
        let phc2 = ok(b_password_hash(&[text("hunter2")])).to_string();
        assert_ne!(phc, phc2);
    }

    #[test]
    fn password_verify_corrupt_hash_is_error_not_false() {
        // "hash corrupto en la DB" y "contraseña incorrecta" no se confunden.
        assert!(b_password_verify(&[text("pw"), text("not-a-phc")]).is_err());
        assert!(b_password_verify(&[text("pw"), text("$unknown$x$y")]).is_err());
    }

    // ---- Ítem G ----

    /// Vector conocido (el clásico de jwt.io): HS256, key "your-256-bit-secret".
    const JWT_IO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const JWT_IO_KEY: &str = "your-256-bit-secret";

    #[test]
    fn jwt_verify_known_vector() {
        let v = ok(b_jwt_verify(&[text(JWT_IO), text(JWT_IO_KEY)]));
        match v {
            SynValue::Map(m) => {
                let m = m.borrow();
                assert_eq!(m.get("sub").unwrap().to_string(), "1234567890");
                assert_eq!(m.get("name").unwrap().to_string(), "John Doe");
                assert_eq!(m.get("iat").unwrap().to_string(), "1516239022");
            }
            other => panic!("expected claims map, got {}", other),
        }
        // Clave equivocada → nothing.
        let bad = ok(b_jwt_verify(&[text(JWT_IO), text("other-key")]));
        assert!(matches!(bad, SynValue::Nothing));
    }

    #[test]
    fn jwt_sign_verify_roundtrip() {
        let claims = map(vec![("sub", text("u1")), ("role", text("admin"))]);
        let opts = map(vec![("expires_in", syn_int(3600))]);
        let tok = ok(b_jwt_sign(&[claims, text("k"), opts])).to_string();
        assert_eq!(tok.split('.').count(), 3);
        let v = ok(b_jwt_verify(&[text(&tok), text("k")]));
        match v {
            SynValue::Map(m) => {
                let m = m.borrow();
                assert_eq!(m.get("sub").unwrap().to_string(), "u1");
                assert!(m.contains_key("iat"), "iat siempre presente");
                assert!(m.contains_key("exp"), "exp desde expires_in");
            }
            other => panic!("expected claims map, got {}", other),
        }
        // La clave acepta bytes y secret (G6) — mismo token, mismas claims.
        let v2 = ok(b_jwt_verify(&[text(&tok), bytes_val(b"k")]));
        assert!(matches!(v2, SynValue::Map(_)));
    }

    #[test]
    fn jwt_verify_adversarial() {
        // alg "none": firmar con header adulterado y firma vacía.
        let payload = b64url_encode(b"{\"sub\":\"x\"}");
        let none_header = b64url_encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let forged = format!("{}.{}.", none_header, payload);
        assert!(matches!(
            ok(b_jwt_verify(&[text(&forged), text("k")])),
            SynValue::Nothing
        ));
        // alg cambiado a RS256 (firma HMAC válida sobre ese header NO alcanza:
        // el verificador exige HS256 antes de mirar la firma).
        let rs_header = b64url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let si = format!("{}.{}", rs_header, payload);
        let mac = hmac_compute(Algo::Sha256, b"k", si.as_bytes());
        let forged2 = format!("{}.{}", si, b64url_encode(&mac));
        assert!(matches!(
            ok(b_jwt_verify(&[text(&forged2), text("k")])),
            SynValue::Nothing
        ));
        // Firma truncada.
        let good = ok(b_jwt_sign(&[map(vec![("a", syn_int(1))]), text("k")])).to_string();
        let truncated = &good[..good.len() - 4];
        assert!(matches!(
            ok(b_jwt_verify(&[text(truncated), text("k")])),
            SynValue::Nothing
        ));
        // exp vencido (fuera del leeway).
        let expired = map(vec![("exp", syn_int(unix_now() - 3600))]);
        let tok = ok(b_jwt_sign(&[expired, text("k")])).to_string();
        assert!(matches!(
            ok(b_jwt_verify(&[text(&tok), text("k")])),
            SynValue::Nothing
        ));
        // ...pero un leeway generoso lo acepta (opts.leeway).
        let lenient = map(vec![("leeway", syn_int(7200))]);
        assert!(matches!(
            ok(b_jwt_verify(&[text(&tok), text("k"), lenient])),
            SynValue::Map(_)
        ));
        // nbf futuro.
        let future = map(vec![("nbf", syn_int(unix_now() + 3600))]);
        let tok = ok(b_jwt_sign(&[future, text("k")])).to_string();
        assert!(matches!(
            ok(b_jwt_verify(&[text(&tok), text("k")])),
            SynValue::Nothing
        ));
        // Payload re-encodeado con padding: los bytes firmados cambian → rechazo.
        let good = ok(b_jwt_sign(&[map(vec![("a", syn_int(1))]), text("k")])).to_string();
        let parts: Vec<&str> = good.split('.').collect();
        let repadded = format!("{}.{}==.{}", parts[0], parts[1], parts[2]);
        assert!(matches!(
            ok(b_jwt_verify(&[text(&repadded), text("k")])),
            SynValue::Nothing
        ));
        // Basura y dos partes → nothing, jamás error.
        assert!(matches!(ok(b_jwt_verify(&[text("a.b"), text("k")])), SynValue::Nothing));
        assert!(matches!(ok(b_jwt_verify(&[text("no"), text("k")])), SynValue::Nothing));
    }

    #[test]
    fn jwt_sign_opts_fail_strong() {
        let claims = map(vec![("sub", text("u"))]);
        // Opt desconocida → error (typo, no silencio).
        assert!(b_jwt_sign(&[claims.clone(), text("k"), map(vec![("ttl", syn_int(1))])]).is_err());
        // exp explícito + expires_in → ambiguo → error.
        let both = map(vec![("exp", syn_int(1))]);
        assert!(b_jwt_sign(&[both, text("k"), map(vec![("expires_in", syn_int(1))])]).is_err());
        // claims no-map → error.
        assert!(b_jwt_sign(&[text("x"), text("k")]).is_err());
    }

    // ---- Ítem H ----

    /// Vectores oficiales RFC 6238 Apéndice B. Seeds: ASCII "12345678901234567890"
    /// (sha1) y "12345678901234567890123456789012" (sha256); 8 dígitos.
    #[test]
    fn totp_rfc6238_vectors() {
        let seed1 = bytes_val(b"12345678901234567890");
        let seed256 = bytes_val(b"12345678901234567890123456789012");
        let cases_sha1: &[(i64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (at, want) in cases_sha1 {
            let opts = map(vec![("digits", syn_int(8)), ("at", syn_int(*at))]);
            let got = ok(b_totp(&[seed1.clone(), opts])).to_string();
            assert_eq!(&got, want, "sha1 at={}", at);
        }
        let cases_sha256: &[(i64, &str)] = &[
            (59, "46119246"),
            (1111111109, "68084774"),
            (20000000000, "77737706"),
        ];
        for (at, want) in cases_sha256 {
            let opts = map(vec![
                ("algo", text("sha256")),
                ("digits", syn_int(8)),
                ("at", syn_int(*at)),
            ]);
            let got = ok(b_totp(&[seed256.clone(), opts])).to_string();
            assert_eq!(&got, want, "sha256 at={}", at);
        }
    }

    #[test]
    fn totp_verify_window() {
        let seed = bytes_val(b"12345678901234567890");
        let at = 1111111109i64;
        let code = ok(b_totp(&[seed.clone(), map(vec![("at", syn_int(at))])])).to_string();
        // El código de t vale en t, t+29 (mismo período) y t±1 período (window 1).
        for delta in [0i64, 29, 30, -30] {
            let opts = map(vec![("at", syn_int(at + delta))]);
            let got = ok(b_totp_verify(&[seed.clone(), text(&code), opts]));
            assert!(matches!(got, SynValue::Bool(true)), "delta={}", delta);
        }
        // Fuera de la ventana → false.
        let far = map(vec![("at", syn_int(at + 90))]);
        let got = ok(b_totp_verify(&[seed.clone(), text(&code), far]));
        assert!(matches!(got, SynValue::Bool(false)));
        // window: 0 → sólo el período exacto.
        let w0 = map(vec![("at", syn_int(at + 30)), ("window", syn_int(0))]);
        let got = ok(b_totp_verify(&[seed.clone(), text(&code), w0]));
        assert!(matches!(got, SynValue::Bool(false)));
        // Código no-texto → error claro (los ceros a la izquierda importan).
        assert!(b_totp_verify(&[seed, syn_int(94287082)]).is_err());
    }

    #[test]
    fn totp_opts_fail_strong() {
        let seed = bytes_val(b"12345678901234567890");
        assert!(b_totp(&[seed.clone(), map(vec![("digits", syn_int(9))])]).is_err());
        assert!(b_totp(&[seed.clone(), map(vec![("algo", text("md5"))])]).is_err());
        assert!(b_totp(&[seed.clone(), map(vec![("period", syn_int(0))])]).is_err());
        assert!(b_totp(&[seed.clone(), map(vec![("window", syn_int(1))])]).is_err(), "window es de verify");
        assert!(b_totp_verify(&[seed, text("123456"), map(vec![("window", syn_int(11))])]).is_err());
    }
}

#[cfg(test)]
mod v0620_tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use synsema_core::bytesutil::b64_encode;

    fn pem(label: &str, der: &[u8]) -> String {
        format!("-----BEGIN {l}-----\n{}\n-----END {l}-----\n", b64_encode(der), l = label)
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn bytes_of(v: SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b.to_vec(),
            other => panic!("esperaba bytes, got {}", other),
        }
    }

    fn map(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.clone());
        }
        syn_map(m)
    }

    /// Clave RSA real: PKCS#1 y PKCS#8 privada, SPKI pública, todas por nuestro PEM→DER.
    fn rsa_pems() -> (String, String, String) {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let mut rng = rand::rngs::OsRng;
        let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let pk = rsa::RsaPublicKey::from(&sk);
        let pkcs1 = pem("RSA PRIVATE KEY", sk.to_pkcs1_der().unwrap().as_bytes());
        let pkcs8 = pem("PRIVATE KEY", sk.to_pkcs8_der().unwrap().as_bytes());
        let spki = pem("PUBLIC KEY", pk.to_public_key_der().unwrap().as_bytes());
        (pkcs1, pkcs8, spki)
    }

    /// Clave P-256 con escalar fijo: SEC1 DER y SPKI armados a mano (formatos estándar).
    fn p256_pems() -> (String, String, String) {
        let mut scalar = vec![0u8; 32];
        scalar[31] = 7;
        let sk = p256::SecretKey::from_slice(&scalar).unwrap();
        let pt = sk.public_key().to_encoded_point(false);
        // SEC1: SEQUENCE { INTEGER 1, OCTET STRING(32) }
        let mut sec1 = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&scalar);
        // PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID prime256v1 }, OCTET STRING(sec1) }
        let alg: Vec<u8> = vec![
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        let mut pkcs8 = vec![0x30, (3 + alg.len() + 2 + sec1.len()) as u8, 0x02, 0x01, 0x00];
        pkcs8.extend_from_slice(&alg);
        pkcs8.push(0x04);
        pkcs8.push(sec1.len() as u8);
        pkcs8.extend_from_slice(&sec1);
        // SPKI: SEQUENCE { alg, BIT STRING 00 || 04 X Y }
        let mut spki = vec![0x30, (alg.len() + 2 + 1 + 65) as u8];
        spki.extend_from_slice(&alg);
        spki.push(0x03);
        spki.push(66);
        spki.push(0x00);
        spki.extend_from_slice(pt.as_bytes());
        (pem("EC PRIVATE KEY", &sec1), pem("PRIVATE KEY", &pkcs8), pem("PUBLIC KEY", &spki))
    }

    fn split_jwt(t: &str) -> (String, String, Vec<u8>) {
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3, "{}", t);
        let header = String::from_utf8(b64url_decode(parts[0]).unwrap()).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        (header, signing_input, b64url_decode(parts[2]).unwrap())
    }

    #[test]
    fn jwt_sign_rs256_with_kid_from_pkcs1_and_pkcs8_verifies_with_the_public_key() {
        let (pkcs1, pkcs8, spki) = rsa_pems();
        let claims = map(&[("iss", syn_text("app-123")), ("iat", syn_int(1_700_000_000))]);
        for key in [pkcs1, pkcs8] {
            let tok = ok(b_jwt_sign(&[claims.clone(), syn_text(key.as_str()), map(&[("alg", syn_text("RS256")), ("kid", syn_text("k1"))])])).to_string();
            let (header, si, sig) = split_jwt(&tok);
            assert_eq!(header, "{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}");
            assert_eq!(sig.len(), 256);
            assert_eq!(ok(b_rsa_verify_sha256(&[syn_text(si.as_str()), syn_bytes(sig.clone()), syn_text(spki.as_str())])).to_string(), "true");
            let mut bad = sig.clone();
            bad[10] ^= 1;
            assert_eq!(ok(b_rsa_verify_sha256(&[syn_text(si.as_str()), syn_bytes(bad), syn_text(spki.as_str())])).to_string(), "false");
        }
        // HS256 sin kid sigue byte a byte igual que antes en el header.
        let tok = ok(b_jwt_sign(&[claims.clone(), syn_text("secret-key")])).to_string();
        let (header, _, _) = split_jwt(&tok);
        assert_eq!(header, JWT_HEADER);
        // El alg lo fija el firmante: una clave EC con RS256 es error claro.
        let (_, ec_pkcs8, _) = p256_pems();
        let e = match b_jwt_sign(&[claims, syn_text(ec_pkcs8.as_str()), map(&[("alg", syn_text("RS256"))])]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("needs an RSA private key"), "{}", e);
    }

    #[test]
    fn jwt_sign_es256_and_raw_ecdsa_round_trip() {
        let (sec1, pkcs8, spki) = p256_pems();
        let claims = map(&[("sub", syn_text("u1")), ("iat", syn_int(1_700_000_000))]);
        for key in [sec1.clone(), pkcs8] {
            let tok = ok(b_jwt_sign(&[claims.clone(), syn_text(key.as_str()), map(&[("alg", syn_text("ES256"))])])).to_string();
            let (header, si, sig) = split_jwt(&tok);
            assert_eq!(header, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
            assert_eq!(sig.len(), 64, "JWS ES256 es r‖s crudo");
            assert_eq!(ok(b_ecdsa_p256_verify(&[syn_text(si.as_str()), syn_bytes(sig), syn_text(spki.as_str())])).to_string(), "true");
        }
        let sig = bytes_of(ok(b_ecdsa_p256_sign(&[syn_text("hola"), syn_text(sec1.as_str())])));
        let sig2 = bytes_of(ok(b_ecdsa_p256_sign(&[syn_text("hola"), syn_text(sec1.as_str())])));
        assert_eq!(sig, sig2, "RFC 6979: determinista");
        assert_eq!(ok(b_ecdsa_p256_verify(&[syn_text("hola"), syn_bytes(sig.clone()), syn_text(spki.as_str())])).to_string(), "true");
        assert_eq!(ok(b_ecdsa_p256_verify(&[syn_text("holA"), syn_bytes(sig), syn_text(spki.as_str())])).to_string(), "false");
        // Un PEM en una sola línea con `\n` literales (como en un .env) también sirve.
        let one_line = sec1.replace('\n', "\\n");
        assert!(b_ecdsa_p256_sign(&[syn_text("x"), syn_text(one_line.as_str())]).is_ok());
        // Etiqueta desconocida y basura: errores claros, nunca pánico.
        let e = match b_ecdsa_p256_sign(&[syn_text("x"), syn_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!(),
        };
        assert!(e.contains("unsupported PEM label"), "{}", e);
        assert!(b_ecdsa_p256_sign(&[syn_text("x"), syn_text("not a pem")]).is_err());
    }

    #[test]
    fn rsa_raw_sign_verify_round_trip() {
        let (pkcs1, _, spki) = rsa_pems();
        let sig = bytes_of(ok(b_rsa_sign_sha256(&[syn_bytes(b"payload".to_vec()), syn_text(pkcs1.as_str())])));
        assert_eq!(sig.len(), 256);
        assert_eq!(ok(b_rsa_verify_sha256(&[syn_bytes(b"payload".to_vec()), syn_bytes(sig.clone()), syn_text(spki.as_str())])).to_string(), "true");
        assert_eq!(ok(b_rsa_verify_sha256(&[syn_bytes(b"payloaD".to_vec()), syn_bytes(sig), syn_text(spki.as_str())])).to_string(), "false");
    }
}
