//! Web Push nativo (tanda PWA): `push_send(subscription, payload, opts)` y
//! `push_vapid_keys()`.
//!
//! Lo que hace un push service (Apple, Google, Mozilla) es entregar al navegador del
//! usuario un mensaje que SÓLO ese navegador puede leer. Tres RFCs, implementadas acá
//! tal cual, sin atajos:
//! - **RFC 8030** (protocolo): `POST <endpoint>` con `TTL`, `Urgency`, `Topic`;
//!   201 = aceptado; 404/410 = la suscripción ya no existe (la app debe borrarla).
//! - **RFC 8291 + RFC 8188** (cifrado `aes128gcm`): ECDH P-256 entre una clave EFÍMERA
//!   del servidor y la `p256dh` del navegador, HKDF-SHA256 con el `auth` secret, y
//!   AES-128-GCM sobre un único registro de 4096 bytes. Sal y clave efímera nuevas por
//!   mensaje (reusarlas rompe la seguridad): salen de OsRng, jamás de `random()`.
//! - **RFC 8292** (VAPID): un JWT ES256 firmado con la clave P-256 del servidor,
//!   `aud` = origen del endpoint, `exp` ≤ 24 h (acá 12 h), `sub` = `mailto:` del
//!   operador; `Authorization: vapid t=<jwt>, k=<clave pública>`.
//!
//! Doctrina:
//! - **Capabilities:** `push_send` gatea `net(<host del endpoint>)` — la MISMA puerta y
//!   scope que `http_*`/`fetch` (un push service es un host más; sandbox lo deniega
//!   igual). `push_vapid_keys` gatea `random` (crea material secreto, como `token()`).
//!   La entropía INTERNA del cifrado (sal, clave efímera) no se gatea: es del protocolo,
//!   como el handshake TLS de `http_get` — el programa no la ve.
//! - **La clave privada VAPID es un secret.** Se acepta como `secret` (texto base64url o
//!   hex, o bytes crudos) o como texto; jamás aparece en un error ni en un log. La
//!   pública se valida contra la privada: una config cruzada falla al instante, no en
//!   silencio en el push service.
//! - **Puro donde se puede:** cifrado, HKDF y VAPID no tocan red ni disco (tests con los
//!   vectores oficiales de RFC 8291). La red va por `http` y por eso, sin la feature
//!   `native` (wasm), `push_send` falla con el error claro del build (como `oidc_verify`).
//! - **Proveedor externo:** quien ya tiene OneSignal/FCM/Pusher los llama con `http_post`
//!   bajo `require net(...)`; nada de esto lo obliga a cambiar.

use std::cell::RefCell;
use std::rc::Rc;

use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::bytesutil::{b64url_decode, b64url_encode, hex_decode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
// `syn_bool`/`syn_int` arman el resultado del POST: sólo existen con red (`native`).
#[cfg(feature = "native")]
use synsema_core::types::{syn_bool, syn_int};
use synsema_core::types::{syn_map, syn_secret, syn_text, SynValue};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Tamaño de registro de RFC 8188 que Web Push fija (RFC 8291 §4): un solo registro.
pub const RECORD_SIZE: u32 = 4096;
/// Header `aes128gcm`: sal(16) + rs(4) + idlen(1) + clave efímera sin comprimir (65).
const HEADER_LEN: usize = 16 + 4 + 1 + 65;
/// El cuerpo entero no puede superar 4096 bytes (los push services rechazan más):
/// header 86 + plaintext + delimitador 1 + tag 16.
pub const MAX_PLAINTEXT: usize = RECORD_SIZE as usize - HEADER_LEN - 1 - 16;
/// Vida del JWT VAPID: 12 h (Apple exige ≤ 24 h; Mozilla/Google aceptan hasta 24 h).
const VAPID_EXP_SECS: i64 = 12 * 3600;
const DEFAULT_TTL: i64 = 86_400;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

// =========================================================
// HKDF-SHA256 (RFC 5869) — 20 líneas sobre el hmac/sha2 ya presentes
// =========================================================

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(salt).expect("HMAC takes any key length");
    m.update(ikm);
    let out = m.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    prk
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut m = HmacSha256::new_from_slice(prk).expect("HMAC takes any key length");
        m.update(&prev);
        m.update(info);
        m.update(&[counter]);
        prev = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

// =========================================================
// RFC 8291 — derivación de claves + cifrado aes128gcm (RFC 8188)
// =========================================================

/// Los valores intermedios de RFC 8291 §3 (los mismos que lista su Appendix A) — los
/// tests los comparan uno a uno contra los vectores oficiales.
#[derive(Debug)]
pub struct Derived {
    pub ecdh_secret: [u8; 32],
    pub prk_key: [u8; 32],
    pub ikm: Vec<u8>,
    pub prk: [u8; 32],
    pub cek: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Deriva CEK y NONCE. `local`/`remote` son las claves de ESTE lado y del otro;
/// `ua_public`/`as_public` son las formas sin comprimir (65 bytes) del navegador y del
/// servidor, en ese orden fijo (RFC 8291 §3.3: `key_info = "WebPush: info" || 0x00 ||
/// ua_public || as_public`, sea quien sea el que deriva).
fn derive(
    local: &p256::SecretKey,
    remote: &p256::PublicKey,
    ua_public: &[u8],
    as_public: &[u8],
    auth_secret: &[u8],
    salt: &[u8],
) -> Derived {
    let shared = p256::ecdh::diffie_hellman(local.to_nonzero_scalar(), remote.as_affine());
    let mut ecdh_secret = [0u8; 32];
    ecdh_secret.copy_from_slice(shared.raw_secret_bytes());
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let prk_key = hkdf_extract(auth_secret, &ecdh_secret);
    let ikm = hkdf_expand(&prk_key, &key_info, 32);
    let prk = hkdf_extract(salt, &ikm);
    let cek = hkdf_expand(&prk, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = hkdf_expand(&prk, b"Content-Encoding: nonce\0", 12);
    Derived { ecdh_secret, prk_key, ikm, prk, cek, nonce }
}

fn uncompressed(pk: &p256::PublicKey) -> Vec<u8> {
    pk.to_encoded_point(false).as_bytes().to_vec()
}

/// Cifra `plaintext` para el navegador (`ua_public` = `keys.p256dh`, `auth_secret` =
/// `keys.auth`) con la clave efímera `as_secret` y la `salt` dadas. Devuelve el cuerpo
/// `aes128gcm` COMPLETO (header + ciphertext). Determinista dados sus argumentos: así
/// los vectores de RFC 8291 lo prueban byte a byte; `push_send` le pasa sal y clave
/// frescas de OsRng.
pub fn encrypt_with(
    plaintext: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
    as_secret: &p256::SecretKey,
    salt: &[u8; 16],
) -> Result<(Vec<u8>, Derived), String> {
    if auth_secret.len() != 16 {
        return Err(format!(
            "subscription keys.auth must decode to 16 bytes, got {}",
            auth_secret.len()
        ));
    }
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(format!(
            "payload is {} bytes; Web Push allows at most {} (the encrypted body must stay under {})",
            plaintext.len(),
            MAX_PLAINTEXT,
            RECORD_SIZE
        ));
    }
    let ua_pk = p256::PublicKey::from_sec1_bytes(ua_public)
        .map_err(|_| "subscription keys.p256dh is not a valid P-256 public key".to_string())?;
    let ua_unc = uncompressed(&ua_pk);
    let as_unc = uncompressed(&as_secret.public_key());
    let d = derive(as_secret, &ua_pk, &ua_unc, &as_unc, auth_secret, salt);

    use aes_gcm::aead::{Aead, KeyInit};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&d.cek)
        .map_err(|_| "internal: AES key length".to_string())?;
    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(0x02); // delimitador del ÚLTIMO registro (RFC 8188 §2)
    let ct = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&d.nonce), record.as_ref())
        .map_err(|_| "encryption failed".to_string())?;

    let mut body = Vec::with_capacity(HEADER_LEN + ct.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_unc.len() as u8);
    body.extend_from_slice(&as_unc);
    body.extend_from_slice(&ct);
    Ok((body, d))
}

/// El lado RECEPTOR (lo que hace el navegador): descifra un cuerpo `aes128gcm` con la
/// clave privada de la suscripción. No es un builtin — existe para que los tests cierren
/// el círculo (cifrar con `push_send`, descifrar como lo haría el navegador) y como
/// referencia de la simetría del protocolo.
pub fn decrypt_with(
    body: &[u8],
    ua_secret: &p256::SecretKey,
    auth_secret: &[u8],
) -> Result<Vec<u8>, String> {
    if body.len() < HEADER_LEN + 16 {
        return Err("body too short for an aes128gcm record".to_string());
    }
    let salt = &body[..16];
    let rs = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
    let idlen = body[20] as usize;
    if idlen != 65 || rs < 18 {
        return Err(format!("unexpected aes128gcm header (idlen {}, rs {})", idlen, rs));
    }
    let as_unc = &body[21..21 + idlen];
    let as_pk = p256::PublicKey::from_sec1_bytes(as_unc)
        .map_err(|_| "sender key in header is not a valid P-256 point".to_string())?;
    let ct = &body[HEADER_LEN..];
    let ua_unc = uncompressed(&ua_secret.public_key());
    let d = derive(ua_secret, &as_pk, &ua_unc, as_unc, auth_secret, salt);
    use aes_gcm::aead::{Aead, KeyInit};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&d.cek)
        .map_err(|_| "internal: AES key length".to_string())?;
    let mut record = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&d.nonce), ct)
        .map_err(|_| "decryption failed (wrong keys or tampered body)".to_string())?;
    // Quitar padding (ceros) y el delimitador (0x02 último / 0x01 intermedio).
    while record.last() == Some(&0) {
        record.pop();
    }
    match record.pop() {
        Some(0x02) | Some(0x01) => Ok(record),
        _ => Err("record delimiter missing".to_string()),
    }
}

// =========================================================
// RFC 8292 — VAPID
// =========================================================

/// Origen (`scheme://host[:port]`) de un endpoint — el `aud` del JWT VAPID.
pub fn origin_of(endpoint: &str) -> Result<String, String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| format!("endpoint {:?} is not an absolute URL", endpoint))?;
    if scheme != "https" && scheme != "http" {
        return Err(format!("endpoint scheme must be https (got {:?})", scheme));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("endpoint {:?} has no host", endpoint));
    }
    Ok(format!("{}://{}", scheme, authority))
}

/// `Authorization: vapid t=<jwt>, k=<pública>` (RFC 8292 §3). `exp` absoluto (unix).
pub fn vapid_authorization(
    endpoint: &str,
    subject: &str,
    exp: i64,
    private: &p256::SecretKey,
) -> Result<String, String> {
    let aud = origin_of(endpoint)?;
    let header = b64url_encode(b"{\"typ\":\"JWT\",\"alg\":\"ES256\"}");
    let claims = serde_json::json!({ "aud": aud, "exp": exp, "sub": subject }).to_string();
    let signing_input = format!("{}.{}", header, b64url_encode(claims.as_bytes()));
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::from(private);
    let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
    let jwt = format!("{}.{}", signing_input, b64url_encode(&sig.to_bytes()));
    let k = b64url_encode(&uncompressed(&private.public_key()));
    Ok(format!("vapid t={}, k={}", jwt, k))
}

// =========================================================
// Lectura de argumentos
// =========================================================

fn text_of<'a>(v: Option<&'a SynValue>, what: &str) -> Result<&'a str, Control> {
    match v {
        Some(SynValue::Text(s)) => Ok(s),
        Some(SynValue::Secret(_)) => Err(err(format!("push_send: {} cannot be a secret", what))),
        Some(other) => Err(err(format!(
            "push_send: {} must be text, got {}",
            what,
            other.type_name()
        ))),
        None => Err(err(format!("push_send: {} is required", what))),
    }
}

fn map_field(m: &IndexMap<String, SynValue>, k: &str) -> Option<SynValue> {
    m.get(k).cloned()
}

fn as_map(v: Option<&SynValue>, what: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        Some(SynValue::Map(m)) => Ok(m.borrow().clone()),
        Some(other) => Err(err(format!(
            "push_send: {} must be a map, got {}",
            what,
            other.type_name()
        ))),
        None => Err(err(format!("push_send: {} is required", what))),
    }
}

fn int_of(v: Option<&SynValue>, what: &str, default: i64, min: i64) -> Result<i64, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(default),
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f.fract() != 0.0 || f < min as f64 {
                return Err(err(format!(
                    "push_send: {} must be an integer ≥ {}, got {}",
                    what, min, f
                )));
            }
            Ok(f as i64)
        }
        Some(other) => Err(err(format!(
            "push_send: {} must be a number, got {}",
            what,
            other.type_name()
        ))),
    }
}

/// Clave privada VAPID: SÓLO un `secret` (texto base64url/hex, o bytes crudos sellados con
/// `as_secret`). Es una clave de firma asimétrica de larga vida — quien la tiene manda
/// push a TODOS tus usuarios — así que rige la misma doctrina que la clave privada de
/// `sign` (blockchain.rs `key_material`): jamás como texto plano en el lenguaje. Lo que
/// `push_vapid_keys()` devuelve ya viene sellado; de `.env` se carga con `secret()`.
/// Los errores jamás incluyen el valor.
fn vapid_private_key(v: Option<&SynValue>) -> Result<p256::SecretKey, Control> {
    let mut raw: Vec<u8> = match v {
        Some(SynValue::Secret(inner)) => {
            if inner.is_bytes() {
                inner.expose_bytes().to_vec()
            } else {
                decode_key_text(&String::from_utf8_lossy(inner.expose_bytes()))?
            }
        }
        Some(other) => {
            return Err(err(format!(
                "push_send: opts.vapid.private must be a secret — declare it with `require secret(\"VAPID_PRIVATE_KEY\")` and pass secret(\"VAPID_PRIVATE_KEY\") (or seal a runtime value with as_secret), got {}. Never pass a private key as a plain string.",
                other.type_name()
            )))
        }
        None => return Err(err("push_send: opts.vapid.private is required (the VAPID private key, as a secret)")),
    };
    let key = if raw.len() == 32 {
        p256::SecretKey::from_slice(&raw)
            .map_err(|_| err("push_send: opts.vapid.private is not a valid P-256 private key. The key value is never shown."))
    } else {
        Err(err(format!(
            "push_send: opts.vapid.private must decode to 32 bytes, got {}. The key value is never shown.",
            raw.len()
        )))
    };
    raw.zeroize();
    key
}

/// base64url (43/44 chars, lo que dan `push_vapid_keys` y `web-push generate-vapid-keys`)
/// o hex (64 chars, con o sin 0x).
fn decode_key_text(s: &str) -> Result<Vec<u8>, Control> {
    let t = s.trim();
    let hexs = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if hexs.len() == 64 && hexs.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex_decode(hexs).map_err(|_| err("push_send: opts.vapid.private is not valid hex. The key value is never shown."));
    }
    b64url_decode(t).map_err(|_| {
        err("push_send: opts.vapid.private must be base64url (or hex) text. The key value is never shown.")
    })
}

/// La pública VAPID (texto base64url de 65 bytes sin comprimir) — validada contra la
/// privada: una config cruzada (dos apps, dos pares) se dice acá, no la rechaza el push
/// service con un 401 opaco.
fn vapid_public_matches(public: &str, private: &p256::SecretKey) -> Result<(), Control> {
    let bytes = b64url_decode(public.trim())
        .map_err(|_| err("push_send: opts.vapid.public must be base64url text"))?;
    let pk = p256::PublicKey::from_sec1_bytes(&bytes)
        .map_err(|_| err("push_send: opts.vapid.public is not a valid P-256 public key"))?;
    if pk != private.public_key() {
        return Err(err(
            "push_send: opts.vapid.public does not match opts.vapid.private (are they from the same push_vapid_keys() pair?)",
        ));
    }
    Ok(())
}

/// El payload: texto tal cual; map/list → JSON; bytes crudos; `nothing` → sin cuerpo.
fn payload_bytes(v: Option<&SynValue>) -> Result<Option<Vec<u8>>, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Text(s)) => Ok(Some(s.as_bytes().to_vec())),
        Some(SynValue::Bytes(b)) => Ok(Some(b.to_vec())),
        Some(v @ SynValue::Map(_)) | Some(v @ SynValue::List(_)) => {
            Ok(Some(crate::json::dumps(&crate::json::syn_to_json(v)).into_bytes()))
        }
        Some(SynValue::Secret(_)) => Err(err("push_send: the payload cannot be a secret (it would leave the process)")),
        Some(other) => Err(err(format!(
            "push_send: payload must be text, a map/list (sent as JSON), bytes or nothing, got {}",
            other.type_name()
        ))),
    }
}

fn os_random(n: usize) -> Result<Vec<u8>, Control> {
    let mut out = vec![0u8; n];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut out)
        .map_err(|_| err("push_send: the OS random source is unavailable"))?;
    Ok(out)
}

// =========================================================
// Builtins
// =========================================================

/// Lo que `push_send` manda: se construye entero antes de tocar la red (así los tests lo
/// inspeccionan y la parte pura queda separada del transporte).
pub struct PushRequest {
    pub endpoint: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout_secs: u64,
}

/// Arma la request (validación + cifrado + VAPID) sin red. `now` = unix segundos.
pub fn build_push_request(args: &[SynValue], now: i64) -> Result<PushRequest, Control> {
    if args.len() < 2 || args.len() > 3 {
        return Err(err(format!(
            "push_send expects (subscription, payload, opts) — 2 or 3 argument(s), got {}",
            args.len()
        )));
    }
    let sub = as_map(args.first(), "subscription")?;
    let endpoint = text_of(sub.get("endpoint"), "subscription.endpoint")?.to_string();
    let keys = as_map(sub.get("keys").as_ref().map(|v| v as &SynValue), "subscription.keys")
        .map_err(|_| err("push_send: subscription.keys must be a map with p256dh and auth (pass PushSubscription.toJSON() from the browser)"))?;
    let p256dh = b64url_decode(text_of(keys.get("p256dh"), "subscription.keys.p256dh")?.trim())
        .map_err(|_| err("push_send: subscription.keys.p256dh must be base64url"))?;
    let auth = b64url_decode(text_of(keys.get("auth"), "subscription.keys.auth")?.trim())
        .map_err(|_| err("push_send: subscription.keys.auth must be base64url"))?;

    let opts = as_map(args.get(2), "opts")?;
    let vapid = as_map(map_field(&opts, "vapid").as_ref(), "opts.vapid")
        .map_err(|_| err("push_send: opts.vapid is required: {\"public\": ..., \"private\": secret(...), \"subject\": \"mailto:you@example.com\"} (push_vapid_keys() makes the pair)"))?;
    let private = vapid_private_key(vapid.get("private"))?;
    let public = text_of(vapid.get("public"), "opts.vapid.public")?;
    vapid_public_matches(public, &private)?;
    let subject = text_of(vapid.get("subject"), "opts.vapid.subject")?;
    if !(subject.starts_with("mailto:") || subject.starts_with("https://")) {
        return Err(err(format!(
            "push_send: opts.vapid.subject must be a mailto: address or an https:// URL (got {:?})",
            subject
        )));
    }
    for k in opts.keys() {
        if !["vapid", "ttl", "urgency", "topic", "timeout"].contains(&k.as_str()) {
            return Err(err(format!(
                "push_send: unknown option {:?}; valid options are: vapid, ttl, urgency, topic, timeout",
                k
            )));
        }
    }
    let ttl = int_of(opts.get("ttl"), "opts.ttl", DEFAULT_TTL, 0)?;
    let timeout = int_of(opts.get("timeout"), "opts.timeout", DEFAULT_TIMEOUT_SECS as i64, 1)? as u64;
    let urgency = match opts.get("urgency") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(u)) => {
            if !["very-low", "low", "normal", "high"].contains(&u.as_ref()) {
                return Err(err(format!(
                    "push_send: opts.urgency must be one of very-low, low, normal, high (got {:?})",
                    u
                )));
            }
            Some(u.to_string())
        }
        Some(other) => return Err(err(format!("push_send: opts.urgency must be text, got {}", other.type_name()))),
    };
    let topic = match opts.get("topic") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(t)) => {
            let ok = !t.is_empty()
                && t.len() <= 32
                && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !ok {
                return Err(err(format!(
                    "push_send: opts.topic must be 1-32 URL-safe characters [A-Za-z0-9-_] (got {:?})",
                    t
                )));
            }
            Some(t.to_string())
        }
        Some(other) => return Err(err(format!("push_send: opts.topic must be text, got {}", other.type_name()))),
    };

    let authorization = vapid_authorization(&endpoint, subject, now + VAPID_EXP_SECS, &private)
        .map_err(|e| err(format!("push_send: {}", e)))?;

    let mut headers: Vec<(String, String)> = vec![
        ("TTL".to_string(), ttl.to_string()),
        ("Authorization".to_string(), authorization),
    ];
    if let Some(u) = urgency {
        headers.push(("Urgency".to_string(), u));
    }
    if let Some(t) = topic {
        headers.push(("Topic".to_string(), t));
    }
    let body = match payload_bytes(args.get(1))? {
        None => None,
        Some(plain) => {
            let as_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let salt_v = os_random(16)?;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_v);
            let (body, _) = encrypt_with(&plain, &p256dh, &auth, &as_secret, &salt)
                .map_err(|e| err(format!("push_send: {}", e)))?;
            headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
            headers.push(("Content-Encoding".to_string(), "aes128gcm".to_string()));
            Some(body)
        }
    };
    Ok(PushRequest { endpoint, headers, body, timeout_secs: timeout })
}

fn push_send(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    let req = build_push_request(args, synsema_core::clock::now_secs())?;
    // Red = capability `net`, con el MISMO scope de host que `http_post` (el error ya
    // sugiere el `require net("host")` exacto).
    crate::http_common::require_net(caps, &req.endpoint, "push_send()")?;
    // Un push service real es SIEMPRE https. La única excepción es loopback (un mock
    // local en desarrollo/tests): ahí no hay red que interceptar.
    let loopback = synsema_capabilities::secure::url_hostname(&req.endpoint)
        .map(|h| h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]")
        .unwrap_or(false);
    if !req.endpoint.starts_with("https://") && !loopback {
        return Err(err(format!(
            "push_send: the endpoint must be https:// (got {:?}) — a push subscription only travels over TLS",
            req.endpoint
        )));
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = &req;
        Err(err(
            "push_send: delivering to the push service needs the network, and this build has no sockets — run the program with the native `synsema` binary",
        ))
    }
    #[cfg(feature = "native")]
    {
        let res = crate::http::http_request_with_bytes(
            "POST",
            &req.endpoint,
            Some(&req.headers),
            req.body.as_deref(),
            req.timeout_secs,
        );
        if res.status == 0 {
            return Err(err(format!(
                "push_send: could not reach the push service at {}: {}",
                origin_of(&req.endpoint).unwrap_or_default(),
                res.error.unwrap_or_else(|| "request failed".to_string())
            )));
        }
        let mut m = IndexMap::new();
        m.insert("status".to_string(), syn_int(res.status));
        m.insert("ok".to_string(), syn_bool(res.ok));
        // 404/410: la suscripción ya no existe (RFC 8030 §7.2) — la app debe borrarla.
        m.insert("gone".to_string(), syn_bool(res.status == 404 || res.status == 410));
        let retry_after = res
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
            .map(|(_, v)| v.clone());
        m.insert(
            "retry_after".to_string(),
            match retry_after {
                Some(v) => syn_text(v),
                None => SynValue::Nothing,
            },
        );
        m.insert("body".to_string(), syn_text(res.body));
        Ok(syn_map(m))
    }
}

/// Un par P-256 nuevo (OsRng). Sirve para VAPID y, en tests, para simular la
/// suscripción del navegador (`keys.p256dh` = `public_b64`).
pub fn keygen() -> p256::SecretKey {
    p256::SecretKey::random(&mut rand::rngs::OsRng)
}

/// La pública en el formato de Web Push: base64url del punto sin comprimir (65 bytes).
pub fn public_b64(sk: &p256::SecretKey) -> String {
    b64url_encode(&uncompressed(&sk.public_key()))
}

/// La privada en el formato de las herramientas VAPID: base64url del escalar (32 bytes).
pub fn private_b64(sk: &p256::SecretKey) -> String {
    let mut raw = sk.to_bytes();
    let s = b64url_encode(&raw);
    raw.zeroize();
    s
}

fn push_vapid_keys(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    if !args.is_empty() {
        return Err(err(format!("push_vapid_keys expects no arguments, got {}", args.len())));
    }
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Random, None), "push_vapid_keys()")
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
    let sk = keygen();
    let public = public_b64(&sk);
    let private = private_b64(&sk);
    let mut m = IndexMap::new();
    m.insert("public".to_string(), syn_text(public));
    // La privada nace SELLADA: se persiste con reveal() una vez (a .env) y se carga con
    // secret(); jamás viaja por print/log/JSON sin decirlo.
    m.insert("private".to_string(), syn_secret("vapid_private", private));
    Ok(syn_map(m))
}

pub fn register_webpush_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    {
        let caps = caps.clone();
        interp.register_builtin("push_send", -1, Rc::new(move |_i, a, _l| push_send(&caps, a)));
    }
    {
        let caps = caps.clone();
        interp.register_builtin("push_vapid_keys", -1, Rc::new(move |_i, a, _l| push_vapid_keys(&caps, a)));
    }
}

// =========================================================
// Tests: vectores oficiales
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> Vec<u8> {
        b64url_decode(s).unwrap()
    }

    /// `Control` no es Debug/Display a propósito (transporta valores del lenguaje):
    /// desempaquetar con el mensaje del error, no con `unwrap`.
    fn ok<T>(r: Result<T, Control>) -> T {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("unexpected non-error control flow"),
        }
    }

    fn errmsg<T>(r: Result<T, Control>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(Control::Error(e)) => e.to_string(),
            Err(_) => panic!("unexpected non-error control flow"),
        }
    }

    /// RFC 5869 Appendix A, test case 1.
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex_decode("000102030405060708090a0b0c").unwrap();
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            synsema_core::bytesutil::hex_encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(
            synsema_core::bytesutil::hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// RFC 8291 Appendix A — cada valor intermedio y el cuerpo final, byte a byte.
    #[test]
    fn rfc8291_appendix_a_vector() {
        let plaintext = b64("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
        assert_eq!(plaintext, b"When I grow up, I want to be a watermelon");
        let auth = b64("BTBZMqHH6r4Tts7J_aSIgg");
        let ua_private = p256::SecretKey::from_slice(&b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")).unwrap();
        let ua_public = b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        assert_eq!(uncompressed(&ua_private.public_key()), ua_public);
        let as_private = p256::SecretKey::from_slice(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let as_public = b64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
        assert_eq!(uncompressed(&as_private.public_key()), as_public);
        let salt_v = b64("DGv6ra1nlYgDCS1FRnbzlw");
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_v);

        let (body, d) = encrypt_with(&plaintext, &ua_public, &auth, &as_private, &salt).unwrap();
        assert_eq!(b64url_encode(&d.ecdh_secret), "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
        assert_eq!(b64url_encode(&d.prk_key), "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k");
        assert_eq!(b64url_encode(&d.ikm), "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
        assert_eq!(b64url_encode(&d.prk), "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc");
        assert_eq!(b64url_encode(&d.cek), "oIhVW04MRdy2XN9CiKLxTg");
        assert_eq!(b64url_encode(&d.nonce), "4h_95klXJ5E_qnoN");

        // Header: sal | rs=4096 | 65 | as_public; ciphertext = el de la RFC.
        assert_eq!(&body[..16], &salt);
        assert_eq!(&body[16..20], &4096u32.to_be_bytes());
        assert_eq!(body[20], 65);
        assert_eq!(&body[21..86], &as_public[..]);
        assert_eq!(
            b64url_encode(&body[86..]),
            "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"
        );
        // El cuerpo completo de la RFC ("the encrypted message").
        assert_eq!(
            b64url_encode(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
        // Y el navegador lo lee.
        assert_eq!(decrypt_with(&body, &ua_private, &auth).unwrap(), plaintext);
    }

    #[test]
    fn encrypt_decrypt_round_trip_with_fresh_keys() {
        let ua = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let ua_pub = uncompressed(&ua.public_key());
        let auth = ok(os_random(16));
        let as_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&ok(os_random(16)));
        let msg = b"{\"title\":\"hola\",\"body\":\"desde synsema\"}";
        let (body, _) = encrypt_with(msg, &ua_pub, &auth, &as_secret, &salt).unwrap();
        assert_eq!(decrypt_with(&body, &ua, &auth).unwrap(), msg);
        // Un byte tocado → falla la autenticación, nunca un plaintext basura.
        let mut bad = body.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt_with(&bad, &ua, &auth).is_err());
        // Clave equivocada → falla.
        let other = p256::SecretKey::random(&mut rand::rngs::OsRng);
        assert!(decrypt_with(&body, &other, &auth).is_err());
    }

    #[test]
    fn payload_size_limit_is_the_documented_one() {
        let ua = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let ua_pub = uncompressed(&ua.public_key());
        let auth = [7u8; 16];
        let as_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let salt = [1u8; 16];
        let ok = vec![b'x'; MAX_PLAINTEXT];
        let (body, _) = encrypt_with(&ok, &ua_pub, &auth, &as_secret, &salt).unwrap();
        assert_eq!(body.len(), RECORD_SIZE as usize);
        let too_big = vec![b'x'; MAX_PLAINTEXT + 1];
        let e = encrypt_with(&too_big, &ua_pub, &auth, &as_secret, &salt).unwrap_err();
        assert!(e.contains("at most"), "{}", e);
        assert!(encrypt_with(b"x", &ua_pub, &[1u8; 15], &as_secret, &salt).is_err());
    }

    #[test]
    fn vapid_header_verifies_with_the_public_key() {
        use p256::ecdsa::signature::Verifier;
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let h = vapid_authorization("https://web.push.apple.com/QAbc/def?x=1", "mailto:ops@example.com", 1_900_000_000, &sk).unwrap();
        let rest = h.strip_prefix("vapid t=").unwrap();
        let (jwt, k) = rest.split_once(", k=").unwrap();
        assert_eq!(b64(k), uncompressed(&sk.public_key()));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&b64(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        let claims: serde_json::Value = serde_json::from_slice(&b64(parts[1])).unwrap();
        assert_eq!(claims["aud"], "https://web.push.apple.com");
        assert_eq!(claims["sub"], "mailto:ops@example.com");
        assert_eq!(claims["exp"], 1_900_000_000);
        let vk = p256::ecdsa::VerifyingKey::from(&p256::ecdsa::SigningKey::from(&sk));
        let sig = p256::ecdsa::Signature::from_slice(&b64(parts[2])).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
    }

    #[test]
    fn origin_of_endpoints() {
        assert_eq!(origin_of("https://fcm.googleapis.com/fcm/send/abc:def").unwrap(), "https://fcm.googleapis.com");
        assert_eq!(origin_of("https://updates.push.services.mozilla.com/wpush/v2/x").unwrap(), "https://updates.push.services.mozilla.com");
        assert_eq!(origin_of("https://host:8443/a?b#c").unwrap(), "https://host:8443");
        assert!(origin_of("ftp://x/y").is_err());
        assert!(origin_of("no-url").is_err());
    }

    #[test]
    fn build_push_request_shape_and_errors() {
        use synsema_core::types::syn_list;
        let ua = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let vapid = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let sub = || {
            let mut keys = IndexMap::new();
            keys.insert("p256dh".to_string(), syn_text(b64url_encode(&uncompressed(&ua.public_key()))));
            keys.insert("auth".to_string(), syn_text(b64url_encode(&[9u8; 16])));
            let mut m = IndexMap::new();
            m.insert("endpoint".to_string(), syn_text("https://push.example.com/v1/abc"));
            m.insert("keys".to_string(), syn_map(keys));
            syn_map(m)
        };
        let opts = |extra: Vec<(&str, SynValue)>| {
            let mut v = IndexMap::new();
            v.insert("public".to_string(), syn_text(b64url_encode(&uncompressed(&vapid.public_key()))));
            v.insert("private".to_string(), syn_secret("k", b64url_encode(&vapid.to_bytes())));
            v.insert("subject".to_string(), syn_text("mailto:a@b.c"));
            let mut m = IndexMap::new();
            m.insert("vapid".to_string(), syn_map(v));
            for (k, val) in extra {
                m.insert(k.to_string(), val);
            }
            syn_map(m)
        };
        let mut payload = IndexMap::new();
        payload.insert("title".to_string(), syn_text("hi"));
        let req = ok(build_push_request(
            &[sub(), syn_map(payload), opts(vec![("ttl", syn_int(60)), ("urgency", syn_text("high")), ("topic", syn_text("news"))])],
            1_800_000_000,
        ));
        assert_eq!(req.endpoint, "https://push.example.com/v1/abc");
        let h = |n: &str| req.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        assert_eq!(h("TTL").as_deref(), Some("60"));
        assert_eq!(h("Urgency").as_deref(), Some("high"));
        assert_eq!(h("Topic").as_deref(), Some("news"));
        assert_eq!(h("Content-Encoding").as_deref(), Some("aes128gcm"));
        assert_eq!(h("Content-Type").as_deref(), Some("application/octet-stream"));
        assert!(h("Authorization").unwrap().starts_with("vapid t="));
        let body = req.body.unwrap();
        // El map viaja como el JSON del lenguaje (mismo formato que json_encode).
        assert_eq!(decrypt_with(&body, &ua, &[9u8; 16]).unwrap(), b"{\"title\": \"hi\"}");

        // Sin payload: sin cuerpo ni Content-Encoding.
        let req = ok(build_push_request(&[sub(), SynValue::Nothing, opts(vec![])], 0));
        assert!(req.body.is_none());
        assert!(h("TTL").is_some());
        assert!(req.headers.iter().all(|(k, _)| k != "Content-Encoding"));

        // Errores claros: pública cruzada, urgency inválida, opción desconocida, sin vapid.
        let other = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let mut bad_vapid = IndexMap::new();
        bad_vapid.insert("public".to_string(), syn_text(b64url_encode(&uncompressed(&other.public_key()))));
        bad_vapid.insert("private".to_string(), syn_secret("k", b64url_encode(&vapid.to_bytes())));
        bad_vapid.insert("subject".to_string(), syn_text("mailto:a@b.c"));
        let mut o = IndexMap::new();
        o.insert("vapid".to_string(), syn_map(bad_vapid));
        let e = errmsg(build_push_request(&[sub(), syn_text("x"), syn_map(o)], 0));
        assert!(e.contains("does not match"), "{}", e);
        let e = errmsg(build_push_request(&[sub(), syn_text("x"), opts(vec![("urgency", syn_text("asap"))])], 0));
        assert!(e.contains("urgency"), "{}", e);
        let e = errmsg(build_push_request(&[sub(), syn_text("x"), opts(vec![("colour", syn_text("red"))])], 0));
        assert!(e.contains("unknown option"), "{}", e);
        let e = errmsg(build_push_request(&[sub(), syn_text("x"), syn_map(IndexMap::new())], 0));
        assert!(e.contains("opts.vapid is required"), "{}", e);
        let e = errmsg(build_push_request(&[sub(), syn_list(vec![]), opts(vec![("topic", syn_text("has space"))])], 0));
        assert!(e.contains("topic"), "{}", e);
        // Un secret como payload jamás sale del proceso.
        let e = errmsg(build_push_request(&[sub(), syn_secret("s", "x"), opts(vec![])], 0));
        assert!(e.contains("cannot be a secret"), "{}", e);
    }

    #[test]
    fn private_key_formats() {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let raw = sk.to_bytes();
        let b64s = b64url_encode(&raw);
        let hexs = synsema_core::bytesutil::hex_encode(&raw);
        // Sellada: texto base64url o hex, o bytes crudos.
        for v in [
            syn_secret("k", b64s.clone()),
            syn_secret("k", format!("0x{}", hexs)),
            syn_secret("k", hexs.clone()),
            synsema_core::types::syn_secret_bytes("k", raw.to_vec()),
        ] {
            assert_eq!(ok(vapid_private_key(Some(&v))).to_bytes(), raw);
        }
        // Texto o bytes SIN sellar → error (doctrina de clave privada = secret), aunque el
        // valor sea válido.
        for v in [syn_text(b64s.clone()), synsema_core::types::syn_bytes(raw.to_vec())] {
            let e = errmsg(vapid_private_key(Some(&v)));
            assert!(e.contains("must be a secret"), "{}", e);
            assert!(!e.contains(&b64s), "el valor no se filtra: {}", e);
        }
        let e = errmsg(vapid_private_key(Some(&syn_secret("k", "nope"))));
        assert!(e.contains("never shown"), "{}", e);
        assert!(!e.contains("nope"), "el valor no se filtra: {}", e);
    }
}
