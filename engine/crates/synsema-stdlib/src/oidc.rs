//! T3 — Verificación de tokens OIDC de TERCEROS (RS256/ES256) con JWKS.
//!
//! Destraba dos mundos con una sola pieza: "login with Google/GitHub/Auth0" en el
//! mundo web, y **workload identity** en la nube (el agente corriendo en AWS/GCP/
//! Azure/GitHub Actions ya tiene una identidad que le da la plataforma — no hay
//! secreto sembrado que robar, P0 del diseño).
//!
//! **Por qué es una función PROPIA y no `jwt_verify` con `{"alg": "RS256"}`:**
//! - `iss` y `aud` son **obligatorios** acá. Verificar la firma sin validar la
//!   audiencia es el confused-deputy clásico de OIDC: un token legítimo emitido
//!   para OTRA aplicación del mismo IdP verificaría perfecto. `jwt_verify` (HS256,
//!   clave propia) no tiene ese problema y no debe cargar con esa obligación.
//! - Acá hay RED (el fetch del JWKS) y por lo tanto capability `net`; `jwt_verify`
//!   es puro. Mezclarlos habría hecho que un builtin puro dejara de serlo según
//!   los argumentos.
//!
//! **Contrato de fallas:** toda falla del TOKEN → `nothing`, sin decir cuál (mismo
//! contrato que `jwt_verify`/`captoken_verify`). Los errores del PROGRAMA (falta
//! `iss`, falta `aud`, JWKS inalcanzable) sí son errores catchables: no es lo
//! mismo "el token no vale" que "no pude comprobarlo".

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use indexmap::IndexMap;
use rsa::signature::Verifier as _;
use sha2::Sha256;

use synsema_capabilities::model::CapabilitySet;
use synsema_core::bytesutil::b64url_decode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_nothing, SynValue};

use crate::server::json_to_syn;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// TTL del cache de JWKS. Las claves de un IdP rotan en días/semanas; 10 minutos
/// mantiene el costo bajo sin quedarse pegado a un set viejo. Un `kid` desconocido
/// fuerza un re-fetch inmediato igual (ver `jwks_for`).
const JWKS_TTL_SECS: u64 = 600;

/// Tope del cuerpo del JWKS que se acepta (un IdP real está muy por debajo; esto
/// acota un endpoint hostil o mal configurado).
const JWKS_MAX_BYTES: usize = 512 * 1024;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// =========================================================
// Cache de JWKS (por URL, con TTL)
// =========================================================

struct CachedJwks {
    fetched_at: u64,
    body: String,
}

fn jwks_cache() -> &'static Mutex<HashMap<String, CachedJwks>> {
    static C: OnceLock<Mutex<HashMap<String, CachedJwks>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn monotonic_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Trae el JWKS de `url` (cacheado). `force` ignora el cache — lo usa el camino de
/// `kid` desconocido (rotación de claves del IdP).
fn fetch_jwks(
    caps: &Rc<RefCell<CapabilitySet>>,
    url: &str,
    force: bool,
) -> Result<String, Control> {
    if !force {
        if let Ok(cache) = jwks_cache().lock() {
            if let Some(c) = cache.get(url) {
                if monotonic_secs().saturating_sub(c.fetched_at) < JWKS_TTL_SECS {
                    return Ok(c.body.clone());
                }
            }
        }
    }
    // Red = capability `net`, con el MISMO scope de host que `http_get` (el error
    // ya sugiere el `require net("host")` exacto).
    crate::http::require_net(caps, url, "oidc_verify() fetching the JWKS")?;
    if !url.starts_with("https://") {
        return Err(err(format!(
            "oidc_verify: the JWKS URL must be https:// (got {:?}) — the signing keys of an \
             identity provider cannot travel over plaintext",
            url
        )));
    }
    let res = crate::http::http_request("GET", url, None, None, None, 10);
    if !res.ok {
        return Err(err(format!(
            "oidc_verify: could not fetch the JWKS from {} (status {}). The token was NOT verified.",
            url, res.status
        )));
    }
    if res.body.len() > JWKS_MAX_BYTES {
        return Err(err(format!(
            "oidc_verify: the JWKS from {} is larger than {} bytes; refusing to parse it",
            url, JWKS_MAX_BYTES
        )));
    }
    if let Ok(mut cache) = jwks_cache().lock() {
        cache.insert(
            url.to_string(),
            CachedJwks { fetched_at: monotonic_secs(), body: res.body.clone() },
        );
    }
    Ok(res.body)
}

// =========================================================
// Claves JWK
// =========================================================

/// Una clave pública del JWKS, ya en su forma verificable.
enum Jwk {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256 { x: Vec<u8>, y: Vec<u8> },
}

struct KeyEntry {
    kid: Option<String>,
    alg: Option<String>,
    key: Jwk,
}

/// Parsea un documento JWKS. Las entradas que no se entienden se SALTEAN (un IdP
/// puede publicar claves de tipos que no soportamos); si no queda ninguna útil, el
/// verify falla por falta de clave, no por un parseo a medias.
fn parse_jwks(body: &str) -> Vec<KeyEntry> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys {
        let kid = k.get("kid").and_then(|v| v.as_str()).map(str::to_string);
        let alg = k.get("alg").and_then(|v| v.as_str()).map(str::to_string);
        // `use` (si viene) debe ser de firma: una clave de cifrado no valida nada.
        if let Some(u) = k.get("use").and_then(|v| v.as_str()) {
            if u != "sig" {
                continue;
            }
        }
        let key = match k.get("kty").and_then(|v| v.as_str()) {
            Some("RSA") => {
                let (Some(n), Some(e)) = (
                    k.get("n").and_then(|v| v.as_str()),
                    k.get("e").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let (Ok(n), Ok(e)) = (b64url_decode(n), b64url_decode(e)) else {
                    continue;
                };
                Jwk::Rsa { n, e }
            }
            Some("EC") => {
                if k.get("crv").and_then(|v| v.as_str()) != Some("P-256") {
                    continue; // P-384/P-521 no soportadas (nadie las usa en OIDC)
                }
                let (Some(x), Some(y)) = (
                    k.get("x").and_then(|v| v.as_str()),
                    k.get("y").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let (Ok(x), Ok(y)) = (b64url_decode(x), b64url_decode(y)) else {
                    continue;
                };
                if x.len() != 32 || y.len() != 32 {
                    continue;
                }
                Jwk::P256 { x, y }
            }
            _ => continue,
        };
        out.push(KeyEntry { kid, alg, key });
    }
    out
}

/// Verifica la firma de `signing_input` con la clave dada, para el alg declarado.
fn verify_with(key: &Jwk, alg: &str, signing_input: &[u8], sig: &[u8]) -> bool {
    match (key, alg) {
        (Jwk::Rsa { n, e }, "RS256") => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::{BigUint, RsaPublicKey};
            // Módulo de menos de 2048 bits = clave débil: se rechaza en vez de
            // verificar contra ella (un IdP legítimo no publica claves así; si una
            // aparece, es señal de configuración rota o de un JWKS suplantado).
            if n.len() * 8 < 2040 {
                return false;
            }
            let Ok(pk) = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
            else {
                return false;
            };
            let vk = VerifyingKey::<Sha256>::new(pk);
            let Ok(signature) = Signature::try_from(sig) else {
                return false;
            };
            vk.verify(signing_input, &signature).is_ok()
        }
        (Jwk::P256 { x, y }, "ES256") => {
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::EncodedPoint;
            // JWS ES256 es la firma CRUDA r‖s de 64 bytes (no DER).
            if sig.len() != 64 {
                return false;
            }
            let point = EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
            let Ok(vk) = VerifyingKey::from_encoded_point(&point) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            // `Signature::from_slice` acepta high-s; ECDSA es maleable en s, pero
            // para VERIFICAR un token eso no habilita nada (el par (r,s) sigue
            // atado a la clave y al mensaje).
            vk.verify(signing_input, &signature).is_ok()
        }
        // Cualquier otra combinación (incluido `alg: "none"`, HS*, o una clave RSA
        // con alg ES256) → falso. El algoritmo se elige del PAR (clave, alg
        // declarado) y ambos tienen que ser coherentes.
        _ => false,
    }
}

// =========================================================
// oidc_verify
// =========================================================

fn opts_map(v: Option<&SynValue>, who: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        Some(SynValue::Map(m)) => Ok(m.borrow().clone()),
        Some(other) => Err(err(format!(
            "{}: opts must be a map, got {}",
            who,
            other.type_name()
        ))),
        None => Err(err(format!("{}: opts is required (iss and aud are mandatory)", who))),
    }
}

struct Expect {
    iss: String,
    aud: Vec<String>,
    leeway: i64,
    algs: Vec<String>,
}

fn b_oidc_verify(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "oidc_verify";
    if args.len() != 2 {
        return Err(err(format!(
            "{}(token, opts) takes 2 arguments — opts must carry at least iss, aud and the keys \
             (jwks_url or jwks)",
            F
        )));
    }
    let opts = opts_map(args.get(1), F)?;

    let mut iss: Option<String> = None;
    let mut aud: Vec<String> = Vec::new();
    let mut jwks_url: Option<String> = None;
    let mut jwks_inline: Option<String> = None;
    let mut leeway: i64 = 60;
    let mut algs: Vec<String> = vec!["RS256".to_string(), "ES256".to_string()];
    for (k, v) in &opts {
        match k.as_str() {
            "iss" => iss = Some(v.to_string()),
            "aud" => match v {
                SynValue::List(l) => aud = l.borrow().iter().map(|x| x.to_string()).collect(),
                other => aud = vec![other.to_string()],
            },
            "jwks_url" => jwks_url = Some(v.to_string()),
            // `jwks` inline: el documento JSON (text) o un map ya parseado. Para
            // tests, entornos sin red y claves pineadas.
            "jwks" => {
                jwks_inline = Some(match v {
                    SynValue::Text(s) => s.to_string(),
                    SynValue::Map(_) => crate::server::dumps(&crate::server::syn_to_json(v)),
                    other => {
                        return Err(err(format!(
                            "{}: jwks must be the JWKS document as text or a map, got {}",
                            F,
                            other.type_name()
                        )))
                    }
                })
            }
            "leeway" => match v {
                SynValue::Number(n) => {
                    leeway = n.to_i64_trunc().filter(|l| *l >= 0).ok_or_else(|| {
                        err(format!("{}: leeway must be an integer >= 0 (seconds)", F))
                    })?
                }
                other => {
                    return Err(err(format!(
                        "{}: leeway must be an integer (seconds), got {}",
                        F,
                        other.type_name()
                    )))
                }
            },
            "alg" => {
                let list: Vec<String> = match v {
                    SynValue::List(l) => l.borrow().iter().map(|x| x.to_string()).collect(),
                    other => vec![other.to_string()],
                };
                for a in &list {
                    if a != "RS256" && a != "ES256" {
                        return Err(err(format!(
                            "{}: alg must be \"RS256\" and/or \"ES256\", got {:?}. HS256 belongs to \
                             jwt_verify (a shared secret you own), not to a third-party IdP.",
                            F, a
                        )));
                    }
                }
                algs = list;
            }
            other => {
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: iss, aud, jwks_url, jwks, leeway, alg)",
                    F, other
                )))
            }
        }
    }

    // iss y aud son OBLIGATORIOS: sin audiencia, un token legítimo emitido para
    // otra app del mismo IdP verificaría bien (confused deputy).
    let iss = iss.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        err(format!(
            "{}: opts.iss is REQUIRED — the expected issuer (e.g. \"https://accounts.google.com\")",
            F
        ))
    })?;
    if aud.is_empty() || aud.iter().all(|a| a.trim().is_empty()) {
        return Err(err(format!(
            "{}: opts.aud is REQUIRED — the audience this token must be for (your client id). \
             Verifying the signature without checking the audience accepts tokens minted for \
             ANOTHER application of the same provider.",
            F
        )));
    }
    if jwks_url.is_none() && jwks_inline.is_none() {
        return Err(err(format!(
            "{}: give the signing keys with jwks_url (fetched and cached, needs `require net(host)`) \
             or jwks (the document inline)",
            F
        )));
    }

    let token = match &args[0] {
        SynValue::Text(s) => s.to_string(),
        _ => return Ok(syn_nothing()),
    };
    let expect = Expect { iss, aud, leeway, algs };

    // Partido en dos pasos porque el `kid` desconocido fuerza un re-fetch (rotación
    // de claves del IdP) — y ese re-fetch es red, o sea que puede fallar con error.
    let Some((header, signing_input, sig)) = split_token(&token) else {
        return Ok(syn_nothing());
    };
    let kid = header.get("kid").and_then(|v| v.as_str());
    let alg = match header.get("alg").and_then(|v| v.as_str()) {
        Some(a) if expect.algs.iter().any(|x| x == a) => a.to_string(),
        // `alg: "none"`, HS256 (el ataque de confusión) o un alg fuera de la lista
        // permitida → rechazo, sin tocar la red siquiera.
        _ => return Ok(syn_nothing()),
    };

    let body = match (&jwks_inline, &jwks_url) {
        (Some(inline), _) => inline.clone(),
        (None, Some(url)) => fetch_jwks(caps, url, false)?,
        _ => unreachable!("validado arriba"),
    };
    let mut keys = parse_jwks(&body);
    // `kid` que no está en el set cacheado → re-fetch forzado (el IdP rotó).
    if let (Some(kid), Some(url)) = (kid, &jwks_url) {
        if !keys.iter().any(|k| k.kid.as_deref() == Some(kid)) {
            let fresh = fetch_jwks(caps, url, true)?;
            keys = parse_jwks(&fresh);
        }
    }

    Ok(verify_claims(&keys, kid, &alg, &signing_input, &sig, &expect).unwrap_or_else(syn_nothing))
}

/// Split del JWT + parse del header. `None` = malformado.
fn split_token(token: &str) -> Option<(serde_json::Value, Vec<u8>, Vec<u8>)> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: serde_json::Value = serde_json::from_slice(&b64url_decode(h).ok()?).ok()?;
    let signing_input = format!("{}.{}", h, p).into_bytes();
    let sig = b64url_decode(s).ok()?;
    Some((header, signing_input, sig))
}

fn verify_claims(
    keys: &[KeyEntry],
    kid: Option<&str>,
    alg: &str,
    signing_input: &[u8],
    sig: &[u8],
    expect: &Expect,
) -> Option<SynValue> {
    // Candidatas: la del `kid` si el token lo trae; si no, todas las que declaren
    // este alg (o ninguno). Un IdP serio siempre manda kid.
    let candidates: Vec<&KeyEntry> = match kid {
        Some(k) => keys.iter().filter(|e| e.kid.as_deref() == Some(k)).collect(),
        None => keys
            .iter()
            .filter(|e| e.alg.is_none() || e.alg.as_deref() == Some(alg))
            .collect(),
    };
    if candidates.is_empty() {
        return None;
    }
    // Si la clave declara su propio alg, tiene que coincidir con el del token.
    if !candidates.iter().any(|e| {
        e.alg.as_deref().map(|a| a == alg).unwrap_or(true)
            && verify_with(&e.key, alg, signing_input, sig)
    }) {
        return None;
    }

    // Firma OK → recién ahora los claims.
    let payload_b64 = std::str::from_utf8(signing_input).ok()?.split('.').nth(1)?;
    let payload: serde_json::Value = serde_json::from_slice(&b64url_decode(payload_b64).ok()?).ok()?;
    let claims = payload.as_object()?;

    // `iss` exacto (nunca un prefijo/substring: `evil.com/accounts.google.com`).
    if claims.get("iss").and_then(|v| v.as_str())? != expect.iss {
        return None;
    }
    // `aud` puede ser string o lista; alcanza con que UNA de las esperadas esté.
    let aud_ok = match claims.get("aud")? {
        serde_json::Value::String(s) => expect.aud.iter().any(|a| a == s),
        serde_json::Value::Array(list) => list
            .iter()
            .filter_map(|v| v.as_str())
            .any(|s| expect.aud.iter().any(|a| a == s)),
        _ => false,
    };
    if !aud_ok {
        return None;
    }
    // Cuando el token trae `azp` (Google multi-cliente), la parte autorizada debe
    // ser una de las audiencias esperadas.
    if let Some(azp) = claims.get("azp").and_then(|v| v.as_str()) {
        if !expect.aud.iter().any(|a| a == azp) {
            return None;
        }
    }
    // Ventana temporal: `exp` es obligatorio en OIDC; `nbf`/`iat` si vienen.
    let now = unix_now();
    let exp = claims.get("exp")?.as_i64()?;
    if now > exp + expect.leeway {
        return None;
    }
    if let Some(nbf) = claims.get("nbf") {
        if now < nbf.as_i64()? - expect.leeway {
            return None;
        }
    }
    if let Some(iat) = claims.get("iat") {
        // Un `iat` en el futuro (fuera del leeway) es un token de un emisor con el
        // reloj roto o fabricado: rechazo.
        if now < iat.as_i64()? - expect.leeway {
            return None;
        }
    }
    Some(json_to_syn(&payload))
}

// =========================================================
// Registro
// =========================================================

/// Registra `oidc_verify`. Cierra sobre el `CapabilitySet` porque el fetch del
/// JWKS es RED (gateada por `net(host)`, igual que `http_get`).
pub fn register_oidc_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    interp.register_builtin(
        "oidc_verify",
        -1,
        Rc::new(move |_i, a, _l| b_oidc_verify(a, &caps)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::bytesutil::b64url_encode;
    use synsema_core::types::{syn_list, syn_map, syn_text};

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

    fn caps() -> Rc<RefCell<CapabilitySet>> {
        Rc::new(RefCell::new(CapabilitySet::new("test")))
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("unexpected error: {}", e),
            Err(_) => panic!("unexpected control flow"),
        }
    }

    /// Un IdP de prueba: par ES256 fijo + emisión de tokens firmados de verdad.
    struct FakeIdp {
        signing: p256::ecdsa::SigningKey,
    }

    impl FakeIdp {
        fn new() -> Self {
            // Escalar fijo → test determinista (no es una clave real de nadie).
            let bytes = [
                0x4c, 0x0d, 0xa1, 0x67, 0xb1, 0x2f, 0x33, 0x9b, 0x67, 0x88, 0x30, 0x14, 0x5e, 0x1a,
                0x9c, 0x77, 0x25, 0xd1, 0x4b, 0x2e, 0x08, 0x6a, 0x71, 0x03, 0x9c, 0xf5, 0x62, 0x11,
                0x88, 0x33, 0x1d, 0x0a,
            ];
            FakeIdp {
                signing: p256::ecdsa::SigningKey::from_slice(&bytes).expect("scalar válido"),
            }
        }

        fn jwks(&self, kid: &str) -> String {
            let point = self.signing.verifying_key().to_encoded_point(false);
            format!(
                r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{}","alg":"ES256","use":"sig","x":"{}","y":"{}"}}]}}"#,
                kid,
                b64url_encode(point.x().expect("x")),
                b64url_encode(point.y().expect("y"))
            )
        }

        fn token(&self, kid: &str, claims: &str) -> String {
            use p256::ecdsa::signature::Signer;
            let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{}"}}"#, kid);
            let si = format!("{}.{}", b64url_encode(header.as_bytes()), b64url_encode(claims.as_bytes()));
            let sig: p256::ecdsa::Signature = self.signing.sign(si.as_bytes());
            format!("{}.{}", si, b64url_encode(&sig.to_bytes()))
        }
    }

    fn base_claims(extra: &str) -> String {
        let now = unix_now();
        format!(
            r#"{{"iss":"https://idp.example.com","aud":"my-client-id","sub":"user-1","exp":{},"iat":{}{}}}"#,
            now + 600,
            now,
            extra
        )
    }

    fn verify(token: &str, opts: Vec<(&str, SynValue)>, jwks: &str) -> SynValue {
        let mut o = opts;
        o.push(("jwks", text(jwks)));
        ok(b_oidc_verify(&[text(token), map(o)], &caps()))
    }

    #[test]
    fn verifies_a_real_es256_token() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let token = idp.token("k1", &base_claims(""));
        let out = verify(
            &token,
            vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
            &jwks,
        );
        match out {
            SynValue::Map(m) => {
                assert_eq!(m.borrow().get("sub").unwrap().to_string(), "user-1");
            }
            other => panic!("expected claims map, got {}", other),
        }
    }

    #[test]
    fn rejects_wrong_audience_and_issuer() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let token = idp.token("k1", &base_claims(""));
        // Token legítimo del MISMO IdP pero emitido para otra app → rechazo.
        // (Es el confused deputy que motiva que `aud` sea obligatorio.)
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("otra-app"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // Issuer distinto → rechazo.
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://evil.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // Un `iss` que CONTIENE al esperado no vale (comparación exacta).
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com/extra")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
    }

    #[test]
    fn accepts_audience_list_and_array_claim() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let now = unix_now();
        let claims = format!(
            r#"{{"iss":"https://idp.example.com","aud":["other","my-client-id"],"sub":"u","exp":{}}}"#,
            now + 600
        );
        let token = idp.token("k1", &claims);
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Map(_)
        ));
        // Y la lista del lado del verificador también.
        let token = idp.token("k1", &base_claims(""));
        assert!(matches!(
            verify(
                &token,
                vec![
                    ("iss", text("https://idp.example.com")),
                    ("aud", syn_list(vec![text("a"), text("my-client-id")]))
                ],
                &jwks
            ),
            SynValue::Map(_)
        ));
    }

    #[test]
    fn rejects_alg_confusion_and_none() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let claims = base_claims("");
        // alg: "none" con firma vacía.
        let header = br#"{"alg":"none","typ":"JWT","kid":"k1"}"#;
        let forged = format!(
            "{}.{}.",
            b64url_encode(header),
            b64url_encode(claims.as_bytes())
        );
        assert!(matches!(
            verify(
                &forged,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // HS256 firmado con la clave PÚBLICA del JWKS como secreto HMAC (el ataque
        // clásico de confusión): rechazado porque HS256 no está en los algs.
        let header = br#"{"alg":"HS256","typ":"JWT","kid":"k1"}"#;
        let si = format!(
            "{}.{}",
            b64url_encode(header),
            b64url_encode(claims.as_bytes())
        );
        let mac = crate::secrets::hmac_compute(crate::secrets::Algo::Sha256, jwks.as_bytes(), si.as_bytes());
        let forged = format!("{}.{}", si, b64url_encode(&mac));
        assert!(matches!(
            verify(
                &forged,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
    }

    #[test]
    fn rejects_tampered_payload_and_unknown_kid() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let token = idp.token("k1", &base_claims(""));
        // Payload cambiado (mismo header y firma).
        let parts: Vec<&str> = token.split('.').collect();
        let evil = b64url_encode(base_claims(r#","role":"admin""#).as_bytes());
        let tampered = format!("{}.{}.{}", parts[0], evil, parts[2]);
        assert!(matches!(
            verify(
                &tampered,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // kid que no está en el JWKS (y sin jwks_url no hay re-fetch) → rechazo.
        let token = idp.token("k-desconocido", &base_claims(""));
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // Basura.
        assert!(matches!(
            verify(
                "no.es.jwt",
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
    }

    #[test]
    fn rejects_expired_and_future_tokens() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let now = unix_now();
        let expired = format!(
            r#"{{"iss":"https://idp.example.com","aud":"my-client-id","sub":"u","exp":{}}}"#,
            now - 3600
        );
        let token = idp.token("k1", &expired);
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // `nbf` futuro.
        let nbf = format!(
            r#"{{"iss":"https://idp.example.com","aud":"my-client-id","sub":"u","exp":{},"nbf":{}}}"#,
            now + 7200,
            now + 3600
        );
        let token = idp.token("k1", &nbf);
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        // Sin `exp` → rechazo (OIDC lo exige).
        let no_exp = r#"{"iss":"https://idp.example.com","aud":"my-client-id","sub":"u"}"#;
        let token = idp.token("k1", no_exp);
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
    }

    #[test]
    fn azp_must_match_when_present() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let token = idp.token("k1", &base_claims(r#","azp":"otra-app""#));
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Nothing
        ));
        let token = idp.token("k1", &base_claims(r#","azp":"my-client-id""#));
        assert!(matches!(
            verify(
                &token,
                vec![("iss", text("https://idp.example.com")), ("aud", text("my-client-id"))],
                &jwks
            ),
            SynValue::Map(_)
        ));
    }

    #[test]
    fn required_options_fail_loud() {
        let idp = FakeIdp::new();
        let jwks = idp.jwks("k1");
        let token = idp.token("k1", &base_claims(""));
        let c = caps();
        // Falta iss.
        let o = map(vec![("aud", text("x")), ("jwks", text(&jwks))]);
        assert!(b_oidc_verify(&[text(&token), o], &c).is_err());
        // Falta aud → el error explica el confused deputy.
        let o = map(vec![("iss", text("https://idp.example.com")), ("jwks", text(&jwks))]);
        match b_oidc_verify(&[text(&token), o], &c) {
            Err(Control::Error(e)) => assert!(
                e.to_string().contains("ANOTHER application"),
                "el error explica por qué: {}",
                e
            ),
            _ => panic!("sin aud debe fallar"),
        }
        // Faltan las claves.
        let o = map(vec![("iss", text("https://i")), ("aud", text("x"))]);
        assert!(b_oidc_verify(&[text(&token), o], &c).is_err());
        // HS256 no se acepta acá (es de jwt_verify).
        let o = map(vec![
            ("iss", text("https://i")),
            ("aud", text("x")),
            ("jwks", text(&jwks)),
            ("alg", text("HS256")),
        ]);
        assert!(b_oidc_verify(&[text(&token), o], &c).is_err());
        // Opt desconocida.
        let o = map(vec![
            ("iss", text("https://i")),
            ("aud", text("x")),
            ("jwks", text(&jwks)),
            ("issuer", text("x")),
        ]);
        assert!(b_oidc_verify(&[text(&token), o], &c).is_err());
    }

    #[test]
    fn jwks_fetch_needs_net_capability() {
        let idp = FakeIdp::new();
        let token = idp.token("k1", &base_claims(""));
        let o = map(vec![
            ("iss", text("https://idp.example.com")),
            ("aud", text("my-client-id")),
            ("jwks_url", text("https://idp.example.com/.well-known/jwks.json")),
        ]);
        // Sin `require net(...)` el fetch se deniega con el mensaje de capability
        // (y NO devuelve nothing: "no pude comprobarlo" ≠ "el token no vale").
        match b_oidc_verify(&[text(&token), o], &caps()) {
            Err(Control::Error(e)) => {
                let m = e.to_string();
                assert!(m.contains("net"), "menciona la capability: {}", m);
            }
            _ => panic!("el fetch sin capability debe fallar"),
        }
    }

    /// RS256 de punta a punta: clave RSA generada, JWKS publicado, token firmado y
    /// verificado — más el rechazo de una clave por debajo del mínimo de 2048 bits.
    #[test]
    fn verifies_a_real_rs256_token_and_rejects_weak_keys() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::rngs::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 2048).expect("keygen 2048");
        let pk = RsaPublicKey::from(&sk);
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"r1","alg":"RS256","use":"sig","n":"{}","e":"{}"}}]}}"#,
            b64url_encode(&pk.n().to_bytes_be()),
            b64url_encode(&pk.e().to_bytes_be())
        );
        let claims = base_claims("");
        let header = br#"{"alg":"RS256","typ":"JWT","kid":"r1"}"#;
        let si = format!(
            "{}.{}",
            b64url_encode(header),
            b64url_encode(claims.as_bytes())
        );
        let signing: SigningKey<Sha256> = SigningKey::new(sk);
        let sig = signing.sign(si.as_bytes());
        let token = format!("{}.{}", si, b64url_encode(&sig.to_bytes()));

        let opts = vec![
            ("iss", text("https://idp.example.com")),
            ("aud", text("my-client-id")),
        ];
        assert!(matches!(verify(&token, opts.clone(), &jwks), SynValue::Map(_)));

        // Payload alterado → rechazo (la firma ya no cierra).
        let parts: Vec<&str> = token.split('.').collect();
        let evil = b64url_encode(base_claims(r#","role":"admin""#).as_bytes());
        let tampered = format!("{}.{}.{}", parts[0], evil, parts[2]);
        assert!(matches!(verify(&tampered, opts.clone(), &jwks), SynValue::Nothing));

        // Clave de 1024 bits (débil) → rechazo aunque la firma sea correcta.
        let weak_sk = RsaPrivateKey::new(&mut rng, 1024).expect("keygen 1024");
        let weak_pk = RsaPublicKey::from(&weak_sk);
        let weak_jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"w1","alg":"RS256","use":"sig","n":"{}","e":"{}"}}]}}"#,
            b64url_encode(&weak_pk.n().to_bytes_be()),
            b64url_encode(&weak_pk.e().to_bytes_be())
        );
        let header = br#"{"alg":"RS256","typ":"JWT","kid":"w1"}"#;
        let si = format!(
            "{}.{}",
            b64url_encode(header),
            b64url_encode(claims.as_bytes())
        );
        let weak_signing: SigningKey<Sha256> = SigningKey::new(weak_sk);
        let weak_sig = weak_signing.sign(si.as_bytes());
        let weak_token = format!("{}.{}", si, b64url_encode(&weak_sig.to_bytes()));
        assert!(matches!(verify(&weak_token, opts, &weak_jwks), SynValue::Nothing));
    }

    #[test]
    fn jwks_parsing_skips_unusable_keys() {
        // Claves de cifrado, curvas no soportadas y entradas rotas se saltean.
        let doc = r#"{"keys":[
            {"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB","kid":"enc"},
            {"kty":"EC","crv":"P-521","x":"AA","y":"AA","kid":"p521"},
            {"kty":"oct","k":"AA","kid":"sym"},
            {"kty":"EC","crv":"P-256","kid":"bad","x":"short","y":"short"}
        ]}"#;
        assert!(parse_jwks(doc).is_empty());
        // Un JSON que no es JWKS no explota.
        assert!(parse_jwks("{}").is_empty());
        assert!(parse_jwks("no json").is_empty());
    }
}
