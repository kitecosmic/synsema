//! WebAuthn / passkeys (T2 del spec de identidad): verificar en el server lo que el
//! navegador devuelve — el REGISTRO (`navigator.credentials.create` → `attestationObject` +
//! `clientDataJSON`) y la AUTENTICACIÓN (`navigator.credentials.get` → `authenticatorData` +
//! `clientDataJSON` + `signature`). Es el lado humano del mismo paradigma que `http_sign`:
//! proof-of-possession de una clave (P-256, RSA o ed25519) en vez de un bearer.
//!
//! Por qué builtin y no userland: verificar exige re-armar EXACTAMENTE el mensaje firmado
//! (`authenticatorData ‖ sha256(clientDataJSON)`), parsear el CBOR/COSE del authenticator y
//! comparar challenge / origin / rpIdHash / flags en el orden correcto — el footgun clásico
//! de canonicalización, el mismo por el que `http_signature_verify` es builtin.
//!
//! Doctrina:
//! - **Puros** (sin capability): CPU sobre bytes. El challenge lo genera el programa con
//!   `random_bytes` (gate `random`) y lo guarda en la sesión.
//! - **`nothing` en TODA falla de verificación** (challenge, origin, rpId, flags, firma,
//!   contador): un endpoint no se distingue por el motivo del rechazo — misma doctrina que
//!   `jwt_verify`/`captoken_verify`. Error sólo por opciones o forma MAL ARMADAS (falta
//!   `rp_id`, falta `clientDataJSON`): eso es un bug del programa, con el fix en el mensaje.
//! - **La attestation del registro se IGNORA a propósito**: `fmt` se reporta, `attStmt` no se
//!   verifica. Verificar de qué marca es la llave mete trust lists de fabricantes y la
//!   dependencia salta de "baja" a "alta" (§5 del spec). Si algún día entra, será opt-in.
//! - **Sin estado**: `sign_count` se devuelve y el programa lo guarda; si pasa el guardado en
//!   `opts.sign_count`, un contador que no avanza (posible llave clonada) es rechazo.
//! - **Salida con la convención de `identity_of`**: `id` = credential id → un `auth with` que
//!   devuelva el map ya da identidad, cuotas y `spend` por identidad, sin adaptadores.
//! - Algoritmos: ES256 (COSE -7, el obligatorio de WebAuthn), RS256 (-257, Windows Hello con
//!   TPM viejo) y EdDSA (-8). **El alg lo fija la CLAVE registrada, jamás el mensaje** (mismo
//!   principio que `http_signature_verify` con `opts.alg`).
//! - Las formas de entrada son las que el navegador ya produce: el JSON de
//!   `PublicKeyCredential.toJSON()` (`{id, rawId, response: {clientDataJSON, …}}`, base64url)
//!   tal cual, o un map plano con esas claves en camelCase o snake_case. Los binarios se aceptan
//!   como `bytes` o como texto base64url.

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use synsema_core::bytesutil::{b64url_decode, b64url_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::constant_time_eq;
use synsema_core::types::{syn_int, syn_map, syn_nothing, syn_text, SynValue};

use crate::cbor::{self, Cbor};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// =========================================================
// entrada: el JSON del navegador o un map plano
// =========================================================

/// Un binario de la credencial: `bytes` tal cual, o texto base64url (con o sin `=`).
fn bin(v: &SynValue) -> Option<Vec<u8>> {
    match v {
        SynValue::Bytes(b) => Some(b[..].to_vec()),
        SynValue::Text(s) => b64url_decode(s.trim()).ok(),
        _ => None,
    }
}

/// Busca la primera clave presente entre `keys` en el map, y si no, en su sub-map `response`
/// (la forma de `PublicKeyCredential.toJSON()`).
fn field(m: &IndexMap<String, SynValue>, keys: &[&str]) -> Option<SynValue> {
    for k in keys {
        if let Some(v) = m.get(*k) {
            if !matches!(v, SynValue::Nothing) {
                return Some(v.clone());
            }
        }
    }
    if let Some(SynValue::Map(r)) = m.get("response") {
        let r = r.borrow();
        for k in keys {
            if let Some(v) = r.get(*k) {
                if !matches!(v, SynValue::Nothing) {
                    return Some(v.clone());
                }
            }
        }
    }
    None
}

fn as_map(v: &SynValue, who: &str, what: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!("{}: {} must be a map, got {}", who, what, other.type_name()))),
    }
}

/// Un campo binario OBLIGATORIO de la credencial: faltar es error de forma (bug del programa,
/// con las claves aceptadas en el mensaje); no decodificar es `None` (credencial inválida).
fn required_bin(
    m: &IndexMap<String, SynValue>,
    keys: &[&str],
    who: &str,
) -> Result<Option<Vec<u8>>, Control> {
    match field(m, keys) {
        Some(v) => Ok(bin(&v)),
        None => Err(err(format!(
            "{}: the credential has no {:?} (accepted keys: {}); pass the JSON of PublicKeyCredential.toJSON() or a map with that field as bytes / base64url text",
            who,
            keys[0],
            keys.join(", ")
        ))),
    }
}

// =========================================================
// opciones
// =========================================================

struct Opts {
    rp_id: String,
    origins: Vec<String>,
    challenge: Vec<u8>,
    uv_required: bool,
    /// Sólo en `webauthn_verify`: el contador guardado de la credencial.
    stored_count: Option<u64>,
}

fn parse_opts(v: Option<&SynValue>, who: &str, verifying: bool) -> Result<Opts, Control> {
    let m = match v {
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(SynValue::Nothing) | None => IndexMap::new(),
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", who, other.type_name()))),
    };
    let rp_id = match m.get("rp_id") {
        Some(SynValue::Text(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(err(format!(
                "{}: opts.rp_id is required — the relying party id (your domain, e.g. \"app.example.com\"); the authenticator bound the credential to its hash",
                who
            )))
        }
    };
    let origins: Vec<String> = match m.get("origin") {
        Some(SynValue::Text(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        Some(SynValue::List(l)) => {
            let out: Vec<String> = l.borrow().iter().map(|x| x.to_string().trim().to_string()).collect();
            if out.is_empty() || out.iter().any(|s| s.is_empty()) {
                return Err(err(format!("{}: opts.origin must be a non-empty text or a list of texts", who)));
            }
            out
        }
        _ => {
            return Err(err(format!(
                "{}: opts.origin is required — the exact origin the browser signed for (e.g. \"https://app.example.com\"), or a list of accepted origins",
                who
            )))
        }
    };
    let challenge = match m.get("challenge") {
        Some(v) => match bin(v) {
            Some(b) if !b.is_empty() => b,
            _ => {
                return Err(err(format!(
                    "{}: opts.challenge must be the challenge you issued for this ceremony, as bytes or base64url text",
                    who
                )))
            }
        },
        None => {
            return Err(err(format!(
                "{}: opts.challenge is required — the random challenge you issued for this ceremony (random_bytes(32)) and kept in the session",
                who
            )))
        }
    };
    let uv_required = match m.get("user_verification") {
        None | Some(SynValue::Nothing) => false,
        Some(SynValue::Text(s)) => match s.as_ref() {
            "required" => true,
            "preferred" | "discouraged" => false,
            other => {
                return Err(err(format!(
                    "{}: opts.user_verification must be \"required\", \"preferred\" or \"discouraged\", got {:?}",
                    who, other
                )))
            }
        },
        Some(other) => {
            return Err(err(format!(
                "{}: opts.user_verification must be text, got {}",
                who,
                other.type_name()
            )))
        }
    };
    let stored_count = match m.get("sign_count") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Number(n)) if verifying => match n.to_i64_trunc() {
            Some(c) if c >= 0 => Some(c as u64),
            _ => return Err(err(format!("{}: opts.sign_count must be a non-negative integer", who))),
        },
        Some(_) if !verifying => {
            return Err(err(format!("{}: opts.sign_count only applies to webauthn_verify", who)))
        }
        Some(other) => {
            return Err(err(format!(
                "{}: opts.sign_count must be an integer, got {}",
                who,
                other.type_name()
            )))
        }
    };
    for k in m.keys() {
        if !matches!(k.as_str(), "rp_id" | "origin" | "challenge" | "user_verification" | "sign_count") {
            return Err(err(format!(
                "{}: unknown option {:?} (valid options: rp_id, origin, challenge, user_verification, sign_count)",
                who, k
            )));
        }
    }
    Ok(Opts { rp_id, origins, challenge, uv_required, stored_count })
}

// =========================================================
// clientDataJSON
// =========================================================

/// Verifica `type`, `challenge` y `origin` del clientDataJSON. `None` = rechazo.
fn check_client_data(cdj: &[u8], expected_type: &str, o: &Opts) -> Option<()> {
    let v: serde_json::Value = serde_json::from_slice(cdj).ok()?;
    if v.get("type").and_then(|t| t.as_str()) != Some(expected_type) {
        return None;
    }
    let chal = b64url_decode(v.get("challenge").and_then(|c| c.as_str())?).ok()?;
    if !constant_time_eq(&chal, &o.challenge) {
        return None;
    }
    let origin = v.get("origin").and_then(|s| s.as_str())?;
    if !o.origins.iter().any(|a| a == origin) {
        return None;
    }
    // Level 3: `crossOrigin: true` = la ceremonia corrió en un iframe de otro origen. Se
    // rechaza: aceptarlo exige una política que el programa no declaró.
    if v.get("crossOrigin").and_then(|c| c.as_bool()) == Some(true) {
        return None;
    }
    Some(())
}

// =========================================================
// authenticatorData
// =========================================================

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    /// `attestedCredentialData` (sólo en el registro): (aaguid, credentialId, COSE_Key).
    cred: Option<([u8; 16], Vec<u8>, Cbor)>,
}

fn parse_auth_data(b: &[u8]) -> Option<AuthData> {
    if b.len() < 37 {
        return None;
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&b[..32]);
    let flags = b[32];
    let sign_count = u32::from_be_bytes([b[33], b[34], b[35], b[36]]);
    let mut rest = &b[37..];
    let mut cred = None;
    if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return None;
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[..16]);
        let len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        rest = &rest[18..];
        if rest.len() < len || len == 0 {
            return None;
        }
        let cred_id = rest[..len].to_vec();
        rest = &rest[len..];
        let (key, used) = cbor::decode_prefix(rest).ok()?;
        rest = &rest[used..];
        cred = Some((aaguid, cred_id, key));
    }
    // Lo que sigue son las extensiones: sólo con el flag ED, y el flag ED sólo con
    // extensiones (bytes de extensión sin ED, o ED sin bytes, es un authenticatorData mal
    // armado). No se interpretan; sólo se exige que sean CBOR completo, para que basura al
    // final no pase.
    if (flags & FLAG_ED != 0) != !rest.is_empty() {
        return None;
    }
    if !rest.is_empty() {
        let (_ext, used) = cbor::decode_prefix(rest).ok()?;
        if used != rest.len() {
            return None;
        }
    }
    Some(AuthData { rp_id_hash, flags, sign_count, cred })
}

/// rpIdHash + UP (+ UV si se exige). `None` = rechazo.
fn check_auth_data(a: &AuthData, o: &Opts) -> Option<()> {
    let expected = Sha256::digest(o.rp_id.as_bytes());
    if !constant_time_eq(&a.rp_id_hash, &expected) {
        return None;
    }
    if a.flags & FLAG_UP == 0 {
        return None;
    }
    if o.uv_required && a.flags & FLAG_UV == 0 {
        return None;
    }
    Some(())
}

// =========================================================
// la clave pública (COSE_Key ↔ JWK)
// =========================================================

enum PubKey {
    P256 { x: Vec<u8>, y: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ed25519(Vec<u8>),
}

impl PubKey {
    fn alg_name(&self) -> &'static str {
        match self {
            PubKey::P256 { .. } => "ES256",
            PubKey::Rsa { .. } => "RS256",
            PubKey::Ed25519(_) => "EdDSA",
        }
    }

    /// Desde el COSE_Key del authenticator (RFC 9052 / RFC 9053): `kty` 1, `alg` 3, y por
    /// tipo: EC2 `crv` -1 / `x` -2 / `y` -3, RSA `n` -1 / `e` -2, OKP `crv` -1 / `x` -2.
    fn from_cose(k: &Cbor) -> Option<PubKey> {
        let kty = k.get_int(1)?.as_int()?;
        let alg = k.get_int(3)?.as_int()?;
        match (kty, alg) {
            // EC2 + ES256, crv P-256 (1)
            (2, -7) => {
                if k.get_int(-1)?.as_int()? != 1 {
                    return None;
                }
                let x = k.get_int(-2)?.as_bytes()?.to_vec();
                let y = k.get_int(-3)?.as_bytes()?.to_vec();
                if x.len() != 32 || y.len() != 32 {
                    return None;
                }
                Some(PubKey::P256 { x, y })
            }
            // RSA + RS256
            (3, -257) => {
                let n = k.get_int(-1)?.as_bytes()?.to_vec();
                let e = k.get_int(-2)?.as_bytes()?.to_vec();
                if n.is_empty() || e.is_empty() {
                    return None;
                }
                Some(PubKey::Rsa { n, e })
            }
            // OKP + EdDSA, crv Ed25519 (6)
            (1, -8) => {
                if k.get_int(-1)?.as_int()? != 6 {
                    return None;
                }
                let x = k.get_int(-2)?.as_bytes()?.to_vec();
                if x.len() != 32 {
                    return None;
                }
                Some(PubKey::Ed25519(x))
            }
            _ => None,
        }
    }

    /// El JWK que devuelve `webauthn_register` y acepta `webauthn_verify`: portable, JSON,
    /// la misma forma que `oidc_verify` lee de un JWKS.
    fn to_syn(&self) -> SynValue {
        let mut m = IndexMap::new();
        match self {
            PubKey::P256 { x, y } => {
                m.insert("kty".to_string(), syn_text("EC"));
                m.insert("crv".to_string(), syn_text("P-256"));
                m.insert("alg".to_string(), syn_text("ES256"));
                m.insert("x".to_string(), syn_text(b64url_encode(x)));
                m.insert("y".to_string(), syn_text(b64url_encode(y)));
            }
            PubKey::Rsa { n, e } => {
                m.insert("kty".to_string(), syn_text("RSA"));
                m.insert("alg".to_string(), syn_text("RS256"));
                m.insert("n".to_string(), syn_text(b64url_encode(n)));
                m.insert("e".to_string(), syn_text(b64url_encode(e)));
            }
            PubKey::Ed25519(x) => {
                m.insert("kty".to_string(), syn_text("OKP"));
                m.insert("crv".to_string(), syn_text("Ed25519"));
                m.insert("alg".to_string(), syn_text("EdDSA"));
                m.insert("x".to_string(), syn_text(b64url_encode(x)));
            }
        }
        syn_map(m)
    }

    /// Desde el JWK (map, o su JSON como texto). Error de FORMA si no es un JWK que este
    /// builtin entienda: la clave la guardó el programa al registrar, así que un JWK roto es
    /// un bug del programa, no una credencial inválida.
    fn from_syn(v: &SynValue, who: &str) -> Result<PubKey, Control> {
        let m: IndexMap<String, SynValue> = match v {
            SynValue::Map(m) => m.borrow().clone(),
            SynValue::Text(s) => {
                let j: serde_json::Value = serde_json::from_str(s).map_err(|_| {
                    err(format!("{}: public_key must be the JWK map returned by webauthn_register (or its JSON)", who))
                })?;
                let mut m = IndexMap::new();
                if let Some(o) = j.as_object() {
                    for (k, x) in o {
                        if let Some(s) = x.as_str() {
                            m.insert(k.clone(), syn_text(s));
                        }
                    }
                }
                m
            }
            other => {
                return Err(err(format!(
                    "{}: public_key must be the JWK map returned by webauthn_register (or its JSON), got {}",
                    who,
                    other.type_name()
                )))
            }
        };
        let text = |k: &str| -> Option<String> {
            match m.get(k) {
                Some(SynValue::Text(s)) => Some(s.to_string()),
                _ => None,
            }
        };
        let dec = |k: &str| -> Result<Vec<u8>, Control> {
            let s = text(k).ok_or_else(|| err(format!("{}: public_key.{} is missing", who, k)))?;
            b64url_decode(&s).map_err(|_| err(format!("{}: public_key.{} is not base64url", who, k)))
        };
        match text("kty").as_deref() {
            Some("EC") => {
                if text("crv").as_deref() != Some("P-256") {
                    return Err(err(format!("{}: public_key.crv must be \"P-256\" (the only EC curve WebAuthn's ES256 uses)", who)));
                }
                let (x, y) = (dec("x")?, dec("y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(err(format!("{}: public_key.x/y must be 32 bytes each", who)));
                }
                Ok(PubKey::P256 { x, y })
            }
            Some("RSA") => Ok(PubKey::Rsa { n: dec("n")?, e: dec("e")? }),
            Some("OKP") => {
                if text("crv").as_deref() != Some("Ed25519") {
                    return Err(err(format!("{}: public_key.crv must be \"Ed25519\" for an OKP key", who)));
                }
                let x = dec("x")?;
                if x.len() != 32 {
                    return Err(err(format!("{}: public_key.x must be 32 bytes", who)));
                }
                Ok(PubKey::Ed25519(x))
            }
            other => Err(err(format!(
                "{}: public_key.kty must be \"EC\", \"RSA\" or \"OKP\" (got {:?}); use the map webauthn_register returned",
                who, other
            ))),
        }
    }

    /// Verifica `sig` sobre `msg` con el algoritmo QUE FIJA LA CLAVE. WebAuthn manda la firma
    /// ES256 en DER (no r‖s como JWS), RS256 PKCS#1 v1.5 y EdDSA cruda de 64 bytes.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PubKey::P256 { x, y } => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                use p256::elliptic_curve::generic_array::GenericArray;
                use p256::EncodedPoint;
                let pt = EncodedPoint::from_affine_coordinates(
                    GenericArray::from_slice(x),
                    GenericArray::from_slice(y),
                    false,
                );
                let Ok(vk) = VerifyingKey::from_encoded_point(&pt) else { return false };
                let Ok(s) = Signature::from_der(sig) else { return false };
                vk.verify(msg, &s).is_ok()
            }
            PubKey::Rsa { n, e } => {
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                use rsa::signature::Verifier;
                use rsa::{BigUint, RsaPublicKey};
                let n = BigUint::from_bytes_be(n);
                // Un módulo débil no valida nada (mismo criterio que `oidc_verify`).
                if n.bits() < 2048 {
                    return false;
                }
                let Ok(pk) = RsaPublicKey::new(n, BigUint::from_bytes_be(e)) else { return false };
                let vk = VerifyingKey::<Sha256>::new(pk);
                let Ok(s) = Signature::try_from(sig) else { return false };
                vk.verify(msg, &s).is_ok()
            }
            PubKey::Ed25519(x) => {
                let Ok(pk): Result<[u8; 32], _> = x.as_slice().try_into() else { return false };
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
                let Ok(sa): Result<[u8; 64], _> = sig.try_into() else { return false };
                let s = ed25519_dalek::Signature::from_bytes(&sa);
                // strict: mismo criterio que `ed25519_verify` (rechaza puntos de orden chico).
                vk.verify_strict(msg, &s).is_ok()
            }
        }
    }
}

fn flags_into(m: &mut IndexMap<String, SynValue>, flags: u8) {
    m.insert("user_present".to_string(), SynValue::Bool(flags & FLAG_UP != 0));
    m.insert("user_verified".to_string(), SynValue::Bool(flags & FLAG_UV != 0));
    m.insert("backup_eligible".to_string(), SynValue::Bool(flags & FLAG_BE != 0));
    m.insert("backup_state".to_string(), SynValue::Bool(flags & FLAG_BS != 0));
}

// =========================================================
// webauthn_register
// =========================================================

/// `webauthn_register(credential, opts) → {id, public_key, alg, sign_count, aaguid, fmt,
/// user_present, user_verified, backup_eligible, backup_state, transports} | nothing`.
fn b_webauthn_register(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "webauthn_register";
    if args.len() != 2 {
        return Err(err(format!("{}(credential, opts) takes exactly 2 arguments", F)));
    }
    let cred = as_map(&args[0], F, "credential")?;
    let o = parse_opts(args.get(1), F, false)?;
    let Some(cdj) = required_bin(&cred, &["clientDataJSON", "client_data_json"], F)? else {
        return Ok(syn_nothing());
    };
    let Some(att) = required_bin(&cred, &["attestationObject", "attestation_object"], F)? else {
        return Ok(syn_nothing());
    };
    if check_client_data(&cdj, "webauthn.create", &o).is_none() {
        return Ok(syn_nothing());
    }
    let Ok(obj) = cbor::decode(&att) else { return Ok(syn_nothing()) };
    let fmt = match obj.get("fmt").and_then(|f| f.as_text()) {
        Some(f) => f.to_string(),
        None => return Ok(syn_nothing()),
    };
    // `attStmt` se exige presente (es parte del formato) pero NO se verifica: attestation
    // de fabricante ignorada por diseño (ver el doc del módulo).
    if obj.get("attStmt").and_then(|s| s.as_map()).is_none() {
        return Ok(syn_nothing());
    }
    let Some(auth_bytes) = obj.get("authData").and_then(|a| a.as_bytes()) else {
        return Ok(syn_nothing());
    };
    let Some(a) = parse_auth_data(auth_bytes) else { return Ok(syn_nothing()) };
    if check_auth_data(&a, &o).is_none() {
        return Ok(syn_nothing());
    }
    let Some((aaguid, cred_id, cose)) = a.cred else { return Ok(syn_nothing()) };
    let Some(key) = PubKey::from_cose(&cose) else { return Ok(syn_nothing()) };
    // El `id` del navegador (si vino) tiene que ser el mismo credentialId que firma el
    // authenticator: un cliente que dice ser otra credencial no pasa.
    if let Some(v) = field(&cred, &["rawId", "raw_id", "id"]) {
        match bin(&v) {
            Some(b) if constant_time_eq(&b, &cred_id) => {}
            _ => return Ok(syn_nothing()),
        }
    }
    let mut out = IndexMap::new();
    out.insert("id".to_string(), syn_text(b64url_encode(&cred_id)));
    out.insert("public_key".to_string(), key.to_syn());
    out.insert("alg".to_string(), syn_text(key.alg_name()));
    out.insert("sign_count".to_string(), syn_int(a.sign_count as i64));
    out.insert("aaguid".to_string(), syn_text(hex(&aaguid)));
    out.insert("fmt".to_string(), syn_text(fmt));
    flags_into(&mut out, a.flags);
    let transports = match field(&cred, &["transports"]) {
        Some(SynValue::List(l)) => SynValue::List(l.clone()),
        _ => syn_nothing(),
    };
    out.insert("transports".to_string(), transports);
    Ok(syn_map(out))
}

// =========================================================
// webauthn_verify
// =========================================================

/// La credencial GUARDADA: lo que devolvió `webauthn_register` (o su JSON) — `id` +
/// `public_key`, y opcionalmente `sign_count` y `user_handle`. El id ATA la clave a la
/// credencial: `rawId` y `userHandle` NO van firmados (la firma cubre authenticatorData ‖
/// sha256(clientDataJSON)), así que sin esto un assertion firmado con la clave del atacante
/// que declara el id de la víctima salía con la identidad de la víctima (auditoría T1–T4,
/// ronda 1; WebAuthn §7.2 pasos 5–6).
struct StoredCredential {
    id: Vec<u8>,
    key: PubKey,
    sign_count: Option<u64>,
    user_handle: Option<String>,
}

fn stored_credential(v: &SynValue, who: &str) -> Result<StoredCredential, Control> {
    let m: IndexMap<String, SynValue> = match v {
        SynValue::Map(m) => m.borrow().clone(),
        SynValue::Text(s) => {
            let j: serde_json::Value = serde_json::from_str(s).map_err(|_| {
                err(format!("{}: credential must be the map returned by webauthn_register (or its JSON)", who))
            })?;
            match crate::json::json_to_syn(&j) {
                SynValue::Map(m) => m.borrow().clone(),
                _ => return Err(err(format!("{}: the credential JSON must be an object", who))),
            }
        }
        other => {
            return Err(err(format!(
                "{}: credential must be the map returned by webauthn_register ({{id, public_key, …}}), got {}",
                who,
                other.type_name()
            )))
        }
    };
    if m.contains_key("kty") && !m.contains_key("public_key") {
        return Err(err(format!(
            "{}: pass the credential map returned by webauthn_register ({{id, public_key, …}}), not the key alone — the credential id must be bound to the key it was registered with",
            who
        )));
    }
    let id = match m.get("id") {
        Some(SynValue::Text(s)) => b64url_decode(s).map_err(|_| err(format!("{}: credential.id is not base64url", who)))?,
        Some(SynValue::Bytes(b)) => b.to_vec(),
        _ => {
            return Err(err(format!(
                "{}: credential.id is missing — store the `id` webauthn_register returned next to its public_key",
                who
            )))
        }
    };
    if id.is_empty() {
        return Err(err(format!("{}: credential.id is empty", who)));
    }
    let key = match m.get("public_key") {
        Some(k) => PubKey::from_syn(k, who)?,
        None => return Err(err(format!("{}: credential.public_key is missing", who))),
    };
    let sign_count = match m.get("sign_count") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Number(n)) => Some(
            n.to_i64_trunc()
                .filter(|v| *v >= 0)
                .map(|v| v as u64)
                .ok_or_else(|| err(format!("{}: credential.sign_count must be a non-negative integer", who)))?,
        ),
        Some(other) => {
            return Err(err(format!("{}: credential.sign_count must be an integer, got {}", who, other.type_name())))
        }
    };
    let user_handle = match m.get("user_handle") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(s)) => Some(s.to_string()),
        Some(other) => return Err(err(format!("{}: credential.user_handle must be text, got {}", who, other.type_name()))),
    };
    Ok(StoredCredential { id, key, sign_count, user_handle })
}

/// `webauthn_verify(assertion, credential, opts) → {id, user_handle, alg, sign_count,
/// user_present, user_verified, backup_eligible, backup_state} | nothing`. `credential` es
/// el map que devolvió `webauthn_register` (con `sign_count` y `user_handle` guardados si
/// los hay): el `id` que sale es el GUARDADO, nunca el que declara el assertion.
fn b_webauthn_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "webauthn_verify";
    if args.len() != 3 {
        return Err(err(format!("{}(assertion, credential, opts) takes exactly 3 arguments", F)));
    }
    let asr = as_map(&args[0], F, "assertion")?;
    let stored = stored_credential(&args[1], F)?;
    let key = &stored.key;
    let o = parse_opts(args.get(2), F, true)?;
    let Some(cdj) = required_bin(&asr, &["clientDataJSON", "client_data_json"], F)? else {
        return Ok(syn_nothing());
    };
    let Some(auth_bytes) = required_bin(&asr, &["authenticatorData", "authenticator_data"], F)? else {
        return Ok(syn_nothing());
    };
    let Some(sig) = required_bin(&asr, &["signature"], F)? else {
        return Ok(syn_nothing());
    };
    // El assertion tiene que ser DE la credencial guardada (rawId no va firmado). Sin
    // `rawId` es un assertion mal armado (el browser siempre lo manda): error de forma.
    match field(&asr, &["rawId", "raw_id", "id"]).and_then(|v| bin(&v)) {
        Some(b) if b.len() == stored.id.len() && constant_time_eq(&b, &stored.id) => {}
        Some(_) => return Ok(syn_nothing()),
        None => {
            return Err(err(format!(
                "{}: assertion has no \"rawId\" (the credential id the browser reports in PublicKeyCredential.toJSON())",
                F
            )))
        }
    }
    if check_client_data(&cdj, "webauthn.get", &o).is_none() {
        return Ok(syn_nothing());
    }
    let Some(a) = parse_auth_data(&auth_bytes) else { return Ok(syn_nothing()) };
    // Un assertion no lleva attestedCredentialData (flag AT): eso es un registro.
    if a.cred.is_some() {
        return Ok(syn_nothing());
    }
    if check_auth_data(&a, &o).is_none() {
        return Ok(syn_nothing());
    }
    // El mensaje firmado: authenticatorData ‖ sha256(clientDataJSON).
    let mut msg = auth_bytes.clone();
    msg.extend_from_slice(&Sha256::digest(&cdj));
    if !key.verify(&msg, &sig) {
        return Ok(syn_nothing());
    }
    // Contador: si el authenticator lo lleva (≠ 0) o el programa guardó uno (en opts o en la
    // credencial), tiene que AVANZAR. Un contador que no avanza es la señal de una llave
    // clonada: rechazo.
    if let Some(stored_count) = o.stored_count.or(stored.sign_count) {
        if (a.sign_count != 0 || stored_count != 0) && (a.sign_count as u64) <= stored_count {
            return Ok(syn_nothing());
        }
    }
    // `userHandle` tampoco va firmado: sólo sale el GUARDADO, y si el assertion trae uno tiene
    // que coincidir (puede no traerlo: con allowCredentials el usuario ya está identificado
    // por la credencial).
    let asserted_handle = field(&asr, &["userHandle", "user_handle"])
        .and_then(|v| bin(&v))
        .filter(|b| !b.is_empty())
        .map(|b| match String::from_utf8(b.clone()) {
            Ok(s) => s,
            Err(_) => b64url_encode(&b),
        });
    let user_handle = match &stored.user_handle {
        Some(s) => {
            if let Some(h) = &asserted_handle {
                if h != s {
                    return Ok(syn_nothing());
                }
            }
            Some(s.clone())
        }
        None => None,
    };
    let mut out = IndexMap::new();
    out.insert("id".to_string(), syn_text(b64url_encode(&stored.id)));
    out.insert("user_handle".to_string(), user_handle.map(syn_text).unwrap_or_else(syn_nothing));
    out.insert("alg".to_string(), syn_text(key.alg_name()));
    out.insert("sign_count".to_string(), syn_int(a.sign_count as i64));
    flags_into(&mut out, a.flags);
    Ok(syn_map(out))
}

// =========================================================
// registro
// =========================================================

/// Registra `webauthn_register` y `webauthn_verify`. PUROS (sin capability): verificar es
/// CPU sobre bytes; el challenge lo genera el programa con `random_bytes` (gate `random`).
pub fn register_webauthn_builtins(interp: &Interpreter) {
    interp.register_builtin("webauthn_register", 2, std::rc::Rc::new(|_i, a, _l| b_webauthn_register(a)));
    interp.register_builtin("webauthn_verify", 3, std::rc::Rc::new(|_i, a, _l| b_webauthn_verify(a)));
}

// =========================================================
// tests: vectores sintéticos (un authenticator P-256/RSA/ed25519 emulado byte a byte)
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    const RP: &str = "app.example";
    const ORIGIN: &str = "https://app.example";
    const CHAL: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn text(s: &str) -> SynValue {
        syn_text(s)
    }

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn opts(extra: Vec<(&str, SynValue)>) -> SynValue {
        let mut v = vec![("rp_id", text(RP)), ("origin", text(ORIGIN)), ("challenge", text(&b64url_encode(CHAL)))];
        v.extend(extra);
        map(v)
    }

    fn client_data(ty: &str, chal: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            ty,
            b64url_encode(chal),
            origin
        )
        .into_bytes()
    }

    fn auth_data(rp: &str, flags: u8, count: u32, cred: Option<(&[u8], Cbor)>) -> Vec<u8> {
        let mut b = Sha256::digest(rp.as_bytes()).to_vec();
        b.push(flags);
        b.extend_from_slice(&count.to_be_bytes());
        if let Some((id, key)) = cred {
            b.extend_from_slice(&[0u8; 16]);
            b.extend_from_slice(&(id.len() as u16).to_be_bytes());
            b.extend_from_slice(id);
            b.extend_from_slice(&key.encode());
        }
        b
    }

    fn attestation_object(auth: &[u8]) -> Vec<u8> {
        Cbor::map_text(vec![
            ("fmt", Cbor::text("none")),
            ("attStmt", Cbor::Map(Vec::new())),
            ("authData", Cbor::bytes(auth)),
        ])
        .encode()
    }

    /// Un authenticator P-256 emulado: clave, COSE_Key y firma DER.
    struct P256Auth {
        sk: p256::ecdsa::SigningKey,
    }

    impl P256Auth {
        fn new() -> Self {
            let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
            P256Auth { sk: p256::ecdsa::SigningKey::from(secret) }
        }
        fn cose(&self) -> Cbor {
            let pt = self.sk.verifying_key().to_encoded_point(false);
            Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(2)),
                (Cbor::Int(3), Cbor::Int(-7)),
                (Cbor::Int(-1), Cbor::Int(1)),
                (Cbor::Int(-2), Cbor::bytes(pt.x().unwrap())),
                (Cbor::Int(-3), Cbor::bytes(pt.y().unwrap())),
            ])
        }
        fn sign(&self, auth: &[u8], cdj: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::Signer;
            let mut msg = auth.to_vec();
            msg.extend_from_slice(&Sha256::digest(cdj));
            let sig: p256::ecdsa::Signature = self.sk.sign(&msg);
            sig.to_der().as_bytes().to_vec()
        }
    }

    fn register(a: &P256Auth, cred_id: &[u8]) -> SynValue {
        let auth = auth_data(RP, FLAG_UP | FLAG_UV | FLAG_AT, 0, Some((cred_id, a.cose())));
        let cred = map(vec![
            ("id", text(&b64url_encode(cred_id))),
            ("rawId", text(&b64url_encode(cred_id))),
            ("type", text("public-key")),
            (
                "response",
                map(vec![
                    ("clientDataJSON", text(&b64url_encode(&client_data("webauthn.create", CHAL, ORIGIN)))),
                    ("attestationObject", text(&b64url_encode(&attestation_object(&auth)))),
                ]),
            ),
        ]);
        b_webauthn_register(&[cred, opts(vec![])]).unwrap_or_else(|_| panic!("register"))
    }

    fn assertion(a: &P256Auth, cred_id: &[u8], flags: u8, count: u32, cdj: Vec<u8>, rp: &str) -> SynValue {
        let auth = auth_data(rp, flags, count, None);
        let sig = a.sign(&auth, &cdj);
        map(vec![
            ("id", text(&b64url_encode(cred_id))),
            ("rawId", text(&b64url_encode(cred_id))),
            (
                "response",
                map(vec![
                    ("clientDataJSON", text(&b64url_encode(&cdj))),
                    ("authenticatorData", text(&b64url_encode(&auth))),
                    ("signature", text(&b64url_encode(&sig))),
                    ("userHandle", text(&b64url_encode(b"user-42"))),
                ]),
            ),
        ])
    }

    fn entries(v: &SynValue) -> IndexMap<String, SynValue> {
        match v {
            SynValue::Map(m) => m.borrow().clone(),
            _ => panic!("map"),
        }
    }

    fn get(v: &SynValue, k: &str) -> SynValue {
        match v {
            SynValue::Map(m) => m.borrow().get(k).cloned().unwrap_or(SynValue::Nothing),
            _ => SynValue::Nothing,
        }
    }

    fn verify(asr: SynValue, cred: SynValue, o: SynValue) -> SynValue {
        b_webauthn_verify(&[asr, cred, o]).unwrap_or_else(|_| panic!("verify"))
    }

    /// Una credencial guardada armada a mano (para claves que no pasaron por `register`).
    fn stored(cred_id: &[u8], jwk: SynValue) -> SynValue {
        map(vec![("id", text(&b64url_encode(cred_id))), ("public_key", jwk)])
    }

    #[test]
    fn register_then_authenticate_es256_roundtrip() {
        let a = P256Auth::new();
        let cred_id = b"credential-one";
        let reg = register(&a, cred_id);
        assert_eq!(get(&reg, "id").to_string(), b64url_encode(cred_id));
        assert_eq!(get(&reg, "alg").to_string(), "ES256");
        assert_eq!(get(&reg, "fmt").to_string(), "none");
        assert!(matches!(get(&reg, "user_verified"), SynValue::Bool(true)));
        let pk = get(&reg, "public_key");
        assert_eq!(get(&pk, "kty").to_string(), "EC");

        let asr = assertion(&a, cred_id, FLAG_UP | FLAG_UV, 7, client_data("webauthn.get", CHAL, ORIGIN), RP);
        let v = verify(asr, reg.clone(), opts(vec![("sign_count", syn_int(3))]));
        assert!(!matches!(v, SynValue::Nothing), "esperaba éxito");
        assert_eq!(get(&v, "id").to_string(), b64url_encode(cred_id));
        // El userHandle del assertion NO es identidad: sólo sale el guardado (acá no hay).
        assert!(matches!(get(&v, "user_handle"), SynValue::Nothing));
        assert_eq!(get(&v, "sign_count").to_string(), "7");
        assert_eq!(get(&v, "alg").to_string(), "ES256");
        // La credencial también entra como JSON (guardada en la DB como texto), con el
        // user_handle y el contador guardados: el handle sale, el contador se exige.
        let cred_json = format!(
            r#"{{"id":"{}","public_key":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{}","y":"{}"}},"sign_count":7,"user_handle":"user-42"}}"#,
            b64url_encode(cred_id),
            get(&pk, "x"),
            get(&pk, "y")
        );
        let asr2 = assertion(&a, cred_id, FLAG_UP, 8, client_data("webauthn.get", CHAL, ORIGIN), RP);
        let v2 = verify(asr2, text(&cred_json), opts(vec![]));
        assert_eq!(get(&v2, "user_handle").to_string(), "user-42");
        // …y un contador guardado (7) que el assertion no supera → nothing.
        let asr3 = assertion(&a, cred_id, FLAG_UP, 7, client_data("webauthn.get", CHAL, ORIGIN), RP);
        assert!(matches!(verify(asr3, text(&cred_json), opts(vec![])), SynValue::Nothing));
    }

    #[test]
    fn the_identity_is_the_stored_credential_never_what_the_assertion_declares() {
        let victim = P256Auth::new();
        let attacker = P256Auth::new();
        let victim_id = b"credential-victim";
        let attacker_id = b"credential-attacker";
        let victim_cred = register(&victim, victim_id);
        let attacker_cred = register(&attacker, attacker_id);
        // El atacante firma con SU clave y declara el id (y el userHandle) de la víctima.
        let forged = assertion(&attacker, victim_id, FLAG_UP, 1, client_data("webauthn.get", CHAL, ORIGIN), RP);
        // Contra la credencial de la víctima: la firma no es de esa clave → nothing.
        assert!(matches!(verify(forged.clone(), victim_cred.clone(), opts(vec![])), SynValue::Nothing));
        // Contra la credencial del atacante (la que un lookup por sesión podría elegir): el id
        // declarado no es el de esa credencial → nothing. Antes salía {id: víctima, …}.
        assert!(matches!(verify(forged, attacker_cred.clone(), opts(vec![])), SynValue::Nothing));
        // Un userHandle guardado que el assertion contradice → nothing; ausente en el
        // assertion → vale (identificado por la credencial) y sale el guardado.
        let mut with_handle = entries(&attacker_cred);
        with_handle.insert("user_handle".to_string(), text("alice"));
        let ok_asr = assertion(&attacker, attacker_id, FLAG_UP, 1, client_data("webauthn.get", CHAL, ORIGIN), RP);
        assert!(matches!(verify(ok_asr, syn_map(with_handle.clone()), opts(vec![])), SynValue::Nothing), "user-42 ≠ alice");
        with_handle.insert("user_handle".to_string(), text("user-42"));
        let v = verify(
            assertion(&attacker, attacker_id, FLAG_UP, 2, client_data("webauthn.get", CHAL, ORIGIN), RP),
            syn_map(with_handle),
            opts(vec![]),
        );
        assert_eq!(get(&v, "user_handle").to_string(), "user-42");
        assert_eq!(get(&v, "id").to_string(), b64url_encode(attacker_id));
        // La clave sola (sin id) no alcanza: error con el arreglo, no un veredicto.
        let e = match b_webauthn_verify(&[
            assertion(&attacker, attacker_id, FLAG_UP, 3, client_data("webauthn.get", CHAL, ORIGIN), RP),
            get(&attacker_cred, "public_key"),
            opts(vec![]),
        ]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("not the key alone"), "{}", e);
    }

    #[test]
    fn an_assertion_with_attested_data_or_malformed_extensions_is_nothing() {
        let a = P256Auth::new();
        let cred_id = b"credential-flags";
        let cred = register(&a, cred_id);
        let cdj = client_data("webauthn.get", CHAL, ORIGIN);
        let sign = |auth: &[u8]| a.sign(auth, &cdj);
        let asr_of = |auth: Vec<u8>| {
            map(vec![
                ("rawId", text(&b64url_encode(cred_id))),
                ("response", map(vec![
                    ("clientDataJSON", text(&b64url_encode(&cdj))),
                    ("authenticatorData", text(&b64url_encode(&auth))),
                    ("signature", text(&b64url_encode(&sign(&auth)))),
                ])),
            ])
        };
        // Flag AT en un assertion (attestedCredentialData): eso es un registro → nothing.
        let with_at = auth_data(RP, FLAG_UP | FLAG_AT, 1, Some((cred_id, a.cose())));
        assert!(matches!(verify(asr_of(with_at), cred.clone(), opts(vec![])), SynValue::Nothing));
        // Flag ED sin extensiones → nothing; extensiones sin flag ED → nothing.
        let ed_no_ext = auth_data(RP, FLAG_UP | FLAG_ED, 1, None);
        assert!(matches!(verify(asr_of(ed_no_ext), cred.clone(), opts(vec![])), SynValue::Nothing));
        let mut ext_no_ed = auth_data(RP, FLAG_UP, 1, None);
        ext_no_ed.extend_from_slice(&Cbor::Map(Vec::new()).encode());
        assert!(matches!(verify(asr_of(ext_no_ed), cred.clone(), opts(vec![])), SynValue::Nothing));
        // Y el bien formado con extensiones (ED + CBOR) sí verifica.
        let mut ed_ext = auth_data(RP, FLAG_UP | FLAG_ED, 1, None);
        ed_ext.extend_from_slice(&Cbor::Map(Vec::new()).encode());
        assert!(!matches!(verify(asr_of(ed_ext), cred, opts(vec![])), SynValue::Nothing));
    }

    #[test]
    fn every_verification_failure_is_nothing() {
        let a = P256Auth::new();
        let cred_id = b"credential-two";
        let pk = register(&a, cred_id);
        let good = || assertion(&a, cred_id, FLAG_UP | FLAG_UV, 5, client_data("webauthn.get", CHAL, ORIGIN), RP);
        // challenge equivocado
        let wrong_chal = assertion(&a, cred_id, FLAG_UP, 5, client_data("webauthn.get", b"other-challenge-bytes-32-long!!!", ORIGIN), RP);
        assert!(matches!(verify(wrong_chal, pk.clone(), opts(vec![])), SynValue::Nothing));
        // origin equivocado
        let wrong_origin = assertion(&a, cred_id, FLAG_UP, 5, client_data("webauthn.get", CHAL, "https://evil.example"), RP);
        assert!(matches!(verify(wrong_origin, pk.clone(), opts(vec![])), SynValue::Nothing));
        // tipo de ceremonia equivocado (un registro no autentica)
        let wrong_type = assertion(&a, cred_id, FLAG_UP, 5, client_data("webauthn.create", CHAL, ORIGIN), RP);
        assert!(matches!(verify(wrong_type, pk.clone(), opts(vec![])), SynValue::Nothing));
        // rpId equivocado (el hash del authenticator es de otro dominio)
        let wrong_rp = assertion(&a, cred_id, FLAG_UP, 5, client_data("webauthn.get", CHAL, ORIGIN), "other.example");
        assert!(matches!(verify(wrong_rp, pk.clone(), opts(vec![])), SynValue::Nothing));
        // sin UP
        let no_up = assertion(&a, cred_id, 0, 5, client_data("webauthn.get", CHAL, ORIGIN), RP);
        assert!(matches!(verify(no_up, pk.clone(), opts(vec![])), SynValue::Nothing));
        // UV exigida y ausente
        let no_uv = assertion(&a, cred_id, FLAG_UP, 5, client_data("webauthn.get", CHAL, ORIGIN), RP);
        assert!(matches!(verify(no_uv, pk.clone(), opts(vec![("user_verification", text("required"))])), SynValue::Nothing));
        // contador que no avanza (llave clonada)
        assert!(matches!(verify(good(), pk.clone(), opts(vec![("sign_count", syn_int(5))])), SynValue::Nothing));
        assert!(matches!(verify(good(), pk.clone(), opts(vec![("sign_count", syn_int(9))])), SynValue::Nothing));
        // firma de OTRA clave
        let other = P256Auth::new();
        let forged = assertion(&other, cred_id, FLAG_UP, 5, client_data("webauthn.get", CHAL, ORIGIN), RP);
        assert!(matches!(verify(forged, pk.clone(), opts(vec![])), SynValue::Nothing));
        // authenticatorData manipulado después de firmar
        let mut tampered = match good() {
            SynValue::Map(m) => m.borrow().clone(),
            _ => unreachable!(),
        };
        if let Some(SynValue::Map(r)) = tampered.get("response").cloned() {
            let mut r = r.borrow().clone();
            let mut auth = bin(r.get("authenticatorData").unwrap()).unwrap();
            auth[33] |= FLAG_UV;
            r.insert("authenticatorData".to_string(), text(&b64url_encode(&auth)));
            tampered.insert("response".to_string(), syn_map(r));
        }
        assert!(matches!(verify(syn_map(tampered), pk.clone(), opts(vec![])), SynValue::Nothing));
        // el bueno sigue pasando (los rechazos de arriba no fueron por otra cosa)
        assert!(!matches!(verify(good(), pk, opts(vec![("sign_count", syn_int(4))])), SynValue::Nothing));
    }

    #[test]
    fn register_rejects_the_wrong_ceremony_and_a_lying_id() {
        let a = P256Auth::new();
        let cred_id = b"credential-three";
        let auth = auth_data(RP, FLAG_UP | FLAG_AT, 0, Some((cred_id, a.cose())));
        let mk = |cdj: Vec<u8>, id: &[u8]| {
            map(vec![
                ("rawId", text(&b64url_encode(id))),
                (
                    "response",
                    map(vec![
                        ("clientDataJSON", text(&b64url_encode(&cdj))),
                        ("attestationObject", text(&b64url_encode(&attestation_object(&auth)))),
                    ]),
                ),
            ])
        };
        // una assertion (`webauthn.get`) no registra
        let r = b_webauthn_register(&[mk(client_data("webauthn.get", CHAL, ORIGIN), cred_id), opts(vec![])]).map_err(|_| ()).unwrap();
        assert!(matches!(r, SynValue::Nothing));
        // un `rawId` que no es el credentialId firmado por el authenticator
        let r = b_webauthn_register(&[mk(client_data("webauthn.create", CHAL, ORIGIN), b"someone-else"), opts(vec![])]).map_err(|_| ()).unwrap();
        assert!(matches!(r, SynValue::Nothing));
        // UV exigida en el registro y ausente
        let r = b_webauthn_register(&[mk(client_data("webauthn.create", CHAL, ORIGIN), cred_id), opts(vec![("user_verification", text("required"))])]).map_err(|_| ()).unwrap();
        assert!(matches!(r, SynValue::Nothing));
        // el bueno
        let r = b_webauthn_register(&[mk(client_data("webauthn.create", CHAL, ORIGIN), cred_id), opts(vec![])]).map_err(|_| ()).unwrap();
        assert!(!matches!(r, SynValue::Nothing));
    }

    #[test]
    fn eddsa_and_rs256_credentials_verify_by_the_key_alg() {
        // EdDSA (OKP / Ed25519)
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let cose = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(1)),
            (Cbor::Int(3), Cbor::Int(-8)),
            (Cbor::Int(-1), Cbor::Int(6)),
            (Cbor::Int(-2), Cbor::bytes(&pk_bytes)),
        ]);
        let key = PubKey::from_cose(&cose).expect("cose okp");
        let jwk = key.to_syn();
        assert_eq!(get(&jwk, "kty").to_string(), "OKP");
        let auth = auth_data(RP, FLAG_UP, 1, None);
        let cdj = client_data("webauthn.get", CHAL, ORIGIN);
        let mut msg = auth.clone();
        msg.extend_from_slice(&Sha256::digest(&cdj));
        use ed25519_dalek::Signer;
        let sig = sk.sign(&msg).to_bytes().to_vec();
        let asr = map(vec![
            ("rawId", text(&b64url_encode(b"okp-cred"))),
            ("clientDataJSON", text(&b64url_encode(&cdj))),
            ("authenticatorData", text(&b64url_encode(&auth))),
            ("signature", text(&b64url_encode(&sig))),
        ]);
        let v = verify(asr, stored(b"okp-cred", jwk.clone()), opts(vec![]));
        assert_eq!(get(&v, "alg").to_string(), "EdDSA");
        // la misma assertion con una firma ES256 "de otro alg" no confunde al verificador:
        // el alg lo fija la clave registrada
        let asr_bad = map(vec![
            ("rawId", text(&b64url_encode(b"okp-cred"))),
            ("clientDataJSON", text(&b64url_encode(&cdj))),
            ("authenticatorData", text(&b64url_encode(&auth))),
            ("signature", text(&b64url_encode(&[1u8; 64]))),
        ]);
        assert!(matches!(verify(asr_bad, stored(b"okp-cred", jwk), opts(vec![])), SynValue::Nothing));

        // RS256 (RSA 2048, PKCS#1 v1.5)
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::SignatureEncoding;
        use rsa::traits::PublicKeyParts;
        let rsa_sk = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("keygen");
        let rsa_pk = rsa_sk.to_public_key();
        let cose = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(3)),
            (Cbor::Int(3), Cbor::Int(-257)),
            (Cbor::Int(-1), Cbor::bytes(&rsa_pk.n().to_bytes_be())),
            (Cbor::Int(-2), Cbor::bytes(&rsa_pk.e().to_bytes_be())),
        ]);
        let key = PubKey::from_cose(&cose).expect("cose rsa");
        let jwk = key.to_syn();
        assert_eq!(get(&jwk, "kty").to_string(), "RSA");
        let signer = SigningKey::<Sha256>::new(rsa_sk);
        let sig = signer.sign(&msg).to_bytes().to_vec();
        let asr = map(vec![
            ("rawId", text(&b64url_encode(b"rsa-cred"))),
            ("clientDataJSON", text(&b64url_encode(&cdj))),
            ("authenticatorData", text(&b64url_encode(&auth))),
            ("signature", text(&b64url_encode(&sig))),
        ]);
        let v = verify(asr, stored(b"rsa-cred", jwk), opts(vec![]));
        assert_eq!(get(&v, "alg").to_string(), "RS256");
    }

    #[test]
    fn shape_and_option_mistakes_are_errors_with_the_fix() {
        let e = |r: Result<SynValue, Control>| match r {
            Err(Control::Error(e)) => e.to_string(),
            Ok(v) => panic!("esperaba error, got {}", v),
            Err(_) => panic!("control"),
        };
        let a = P256Auth::new();
        let pk = register(&a, b"c");
        // opciones incompletas
        let asr = assertion(&a, b"c", FLAG_UP, 1, client_data("webauthn.get", CHAL, ORIGIN), RP);
        let m = e(b_webauthn_verify(&[asr.clone(), pk.clone(), map(vec![("origin", text(ORIGIN)), ("challenge", text("AAAA"))])]));
        assert!(m.contains("opts.rp_id is required"), "{}", m);
        let m = e(b_webauthn_verify(&[asr.clone(), pk.clone(), map(vec![("rp_id", text(RP)), ("challenge", text("AAAA"))])]));
        assert!(m.contains("opts.origin is required"), "{}", m);
        let m = e(b_webauthn_verify(&[asr.clone(), pk.clone(), map(vec![("rp_id", text(RP)), ("origin", text(ORIGIN))])]));
        assert!(m.contains("opts.challenge is required"), "{}", m);
        let m = e(b_webauthn_verify(&[asr.clone(), pk.clone(), opts(vec![("user_verification", text("maybe"))])]));
        assert!(m.contains("user_verification"), "{}", m);
        // forma incompleta: falta la firma
        let m = e(b_webauthn_verify(&[map(vec![("clientDataJSON", text("AAAA")), ("authenticatorData", text("AAAA"))]), pk.clone(), opts(vec![])]));
        assert!(m.contains("has no \"signature\""), "{}", m);
        // clave que no es un JWK entendible (dentro de la credencial)
        let m = e(b_webauthn_verify(&[asr.clone(), stored(b"c", map(vec![("kty", text("oct"))])), opts(vec![])]));
        assert!(m.contains("public_key.kty"), "{}", m);
        // la clave sola, sin el id de la credencial: error con el arreglo
        let m = e(b_webauthn_verify(&[asr.clone(), map(vec![("kty", text("oct"))]), opts(vec![])]));
        assert!(m.contains("not the key alone"), "{}", m);
        // una credencial sin id
        let m = e(b_webauthn_verify(&[asr, map(vec![("public_key", get(&pk, "public_key"))]), opts(vec![])]));
        assert!(m.contains("credential.id is missing"), "{}", m);
        // sign_count no aplica al registro
        let m = e(b_webauthn_register(&[map(vec![("clientDataJSON", text("AAAA")), ("attestationObject", text("AAAA"))]), opts(vec![("sign_count", syn_int(1))])]));
        assert!(m.contains("only applies to webauthn_verify"), "{}", m);
    }
}
