//! T2 — Firmas de request HTTP (proof-of-possession), perfil PINEADO de RFC 9421.
//!
//! El paradigma (P1 del diseño de auth de agentes): un bearer token robado del
//! contexto de un LLM lo usa cualquiera; una request FIRMADA exige poseer la clave
//! —que vive sellada como `secret` bajo el gate `sign`—, así que el robo del token
//! deja de alcanzar. Es el modelo AWS SigV4 generalizado.
//!
//! **Perfil fijo (v1), no configurable:**
//! - Componentes firmados, en este orden: `@method`, `@target-uri`, `content-digest`.
//!   El `content-digest` va SIEMPRE (también con body vacío: si fuera opcional, un
//!   atacante podría agregarle body a una request firmada sin romper la firma).
//! - Parámetros firmados: `created`, `keyid`, `alg` y `nonce` (si se pide).
//! - Algoritmos: `ed25519` (asimétrico, el default) y `hmac-sha256` (simétrico).
//! - NADA de canonicalización general de RFC 9421 (structured fields, component
//!   identifiers arbitrarios): superficie enorme y fácil de errar. Este perfil es
//!   un subconjunto interoperable y verificable byte a byte.
//!
//! **Por qué los dos builtins son simétricos:** verificar exige re-canonicalizar
//! exactamente igual que al firmar — que es justamente el footgun por el que la
//! firma es builtin. Un `http_sign` sin su `http_signature_verify` obligaría a
//! reimplementar la canonicalización en userland: no se hace.
//!
//! **Confusión de algoritmo (la vulnerabilidad clásica):** `http_signature_verify`
//! exige `opts.alg` — el algoritmo lo fija el VERIFICADOR, jamás el mensaje. Sin
//! esto, un atacante cambia `alg="hmac-sha256"` en `Signature-Input` y firma con la
//! CLAVE PÚBLICA ed25519 (que es pública) como clave HMAC: falsificación total. Es
//! el mismo ataque que RS256→HS256 en JWT.

use std::cell::RefCell;
use std::rc::Rc;

use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use synsema_capabilities::model::CapabilitySet;
use synsema_core::bytesutil::b64_encode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::constant_time_eq;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_int, syn_map, syn_nothing, syn_text, SynValue};

use crate::blockchain::{ed25519_seed, gate_and_audit, key_material as curve_key_material};
use crate::secrets::{hmac_compute, Algo};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// Los componentes cubiertos, en orden. Fijo por perfil (v1).
const COVERED: [&str; 3] = ["@method", "@target-uri", "content-digest"];

/// Ventana de aceptación por defecto de `created`, en segundos (anti-replay).
const DEFAULT_MAX_AGE: i64 = 300;

/// Label del bloque de firma cuando no se pide otro (RFC 9421 permite varios).
const DEFAULT_LABEL: &str = "sig1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum SigAlg {
    Ed25519,
    HmacSha256,
}

impl SigAlg {
    fn name(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ed25519",
            SigAlg::HmacSha256 => "hmac-sha256",
        }
    }

    fn parse(s: &str, who: &str) -> Result<Self, Control> {
        match s {
            "ed25519" => Ok(SigAlg::Ed25519),
            "hmac-sha256" => Ok(SigAlg::HmacSha256),
            other => Err(err(format!(
                "{}: alg must be \"ed25519\" or \"hmac-sha256\", got {:?}",
                who, other
            ))),
        }
    }
}

fn unix_now() -> i64 {
    synsema_core::clock::now_secs()
}

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

fn req_map(v: &SynValue, who: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!(
            "{}: the request must be a map with method, url and (optionally) body/headers, got {}",
            who,
            other.type_name()
        ))),
    }
}

/// Campo de texto requerido del map de request.
fn req_text(m: &IndexMap<String, SynValue>, key: &str, who: &str) -> Result<String, Control> {
    match m.get(key) {
        Some(SynValue::Text(s)) => {
            let s = s.trim().to_string();
            if s.is_empty() {
                return Err(err(format!("{}: request.{} cannot be empty", who, key)));
            }
            Ok(s)
        }
        Some(other) => Err(err(format!(
            "{}: request.{} must be text, got {}",
            who,
            key,
            other.type_name()
        ))),
        None => Err(err(format!(
            "{}: the request map needs a {:?} field",
            who, key
        ))),
    }
}

/// Bytes del body (ausente/nothing → vacío). Text o bytes; otro tipo → error claro
/// (un map NO se serializa solo: el body firmado tiene que ser byte a byte el que
/// viaja, y la serialización la elige el programa con `json_encode`).
fn body_bytes(m: &IndexMap<String, SynValue>, who: &str) -> Result<Vec<u8>, Control> {
    match m.get("body") {
        None | Some(SynValue::Nothing) => Ok(Vec::new()),
        Some(SynValue::Text(s)) => Ok(s.as_bytes().to_vec()),
        Some(SynValue::Bytes(b)) => Ok(b.to_vec()),
        Some(other) => Err(err(format!(
            "{}: request.body must be text or bytes, got {} — serialize it first (e.g. json_encode(value)) so the signed bytes are exactly the ones sent",
            who,
            other.type_name()
        ))),
    }
}

/// `Content-Digest` (RFC 9530): `sha-256=:BASE64:` sobre los bytes exactos del body.
fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", b64_encode(&Sha256::digest(body)))
}

/// El valor de `@signature-params`: la lista de componentes + los parámetros. Es la
/// última línea de la base Y el valor del header `Signature-Input` (mismo string —
/// por eso el verificador puede reconstruirlo sin ambigüedad).
fn signature_params(alg: SigAlg, created: i64, keyid: &str, nonce: Option<&str>) -> String {
    let components: Vec<String> = COVERED.iter().map(|c| format!("\"{}\"", c)).collect();
    let mut s = format!(
        "({});created={};keyid=\"{}\";alg=\"{}\"",
        components.join(" "),
        created,
        keyid,
        alg.name()
    );
    if let Some(n) = nonce {
        s.push_str(&format!(";nonce=\"{}\"", n));
    }
    s
}

/// La base de firma: una línea por componente cubierto y `@signature-params` al
/// final (RFC 9421 §2.5). El método va en MAYÚSCULAS y la URI tal cual la envía el
/// cliente — el verificador la reconstruye igual o la firma no valida.
fn signature_base(method: &str, target_uri: &str, digest: &str, params: &str) -> String {
    format!(
        "\"@method\": {}\n\"@target-uri\": {}\n\"content-digest\": {}\n\"@signature-params\": {}",
        method.to_ascii_uppercase(),
        target_uri,
        digest,
        params
    )
}

/// Valida que un valor de parámetro no rompa el header ni la base (comillas, CR/LF,
/// controles). Fallar fuerte: nunca sanear en silencio (misma doctrina que
/// `with_header`/`redirect`).
fn check_param(who: &str, name: &str, value: &str) -> Result<(), Control> {
    if value.is_empty() {
        return Err(err(format!("{}: {} cannot be empty", who, name)));
    }
    if value.contains('"') || value.contains('\\') || value.chars().any(|c| c.is_ascii_control()) {
        return Err(err(format!(
            "{}: {} must not contain quotes, backslashes or control characters",
            who, name
        )));
    }
    Ok(())
}

// =========================================================
// http_sign
// =========================================================

fn b_http_sign(
    args: &[SynValue],
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "http_sign";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(request, key, opts?) takes 2 or 3 arguments", F)));
    }
    let req = req_map(&args[0], F)?;
    let method = req_text(&req, "method", F)?;
    let url = req_text(&req, "url", F)?;
    let body = body_bytes(&req, F)?;

    let opts = opts_map(args.get(2), F)?;
    let mut alg = SigAlg::Ed25519;
    let mut created = unix_now();
    let mut keyid: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut label = DEFAULT_LABEL.to_string();
    for (k, v) in &opts {
        match k.as_str() {
            "alg" => alg = SigAlg::parse(&v.to_string(), F)?,
            "created" => match v {
                SynValue::Number(n) => {
                    created = n.to_i64_trunc().ok_or_else(|| {
                        err(format!("{}: created must be a unix timestamp (integer)", F))
                    })?
                }
                other => {
                    return Err(err(format!(
                        "{}: created must be a unix timestamp (integer), got {}",
                        F,
                        other.type_name()
                    )))
                }
            },
            "keyid" => keyid = Some(v.to_string()),
            "nonce" => nonce = Some(v.to_string()),
            "label" => label = v.to_string(),
            other => {
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: alg, created, keyid, nonce, label)",
                    F, other
                )))
            }
        }
    }

    // La clave SIEMPRE es un secret sellado: su name da el scope del gate `sign` y
    // el default de `keyid` (P1 — la clave nunca es un string pelado en el programa).
    //
    // El MATERIAL se lee distinto según el algoritmo, y eso no es un capricho:
    // - ed25519: es material de curva (32/64 bytes), así que un secret de texto se
    //   interpreta como HEX — la misma regla que `ed25519_sign` y el resto del
    //   engine, para que la MISMA clave sirva en los dos lugares.
    // - hmac-sha256: la clave es una cadena compartida arbitraria (lo que el otro
    //   lado configuró); sus bytes van CRUDOS, como en `hmac_sha256`. Pedir hex acá
    //   rompería toda clave compartida que no lo sea.
    let (name, key) = match alg {
        SigAlg::Ed25519 => curve_key_material(&args[1], F)?,
        SigAlg::HmacSha256 => match &args[1] {
            SynValue::Secret(s) => (s.name().to_string(), s.expose_bytes().to_vec()),
            other => {
                return Err(err(format!(
                    "{}: the key must be a secret — declare it with `require secret(\"NAME\")` and \
                     pass secret(\"NAME\"), got {}. The secret's name is what scopes `require sign(...)`.",
                    F,
                    other.type_name()
                )))
            }
        },
    };
    let keyid = keyid.unwrap_or_else(|| name.clone());
    check_param(F, "keyid", &keyid)?;
    check_param(F, "label", &label)?;
    if let Some(n) = &nonce {
        check_param(F, "nonce", n)?;
    }

    // Gate + audit ANTES de tocar el material de clave (misma puerta que firmar una
    // transacción on-chain: `require sign("NAME")` + entrada en sign.log).
    if let Err(e) = gate_and_audit(caps, &name, alg.name(), loc) {
        let mut k = key;
        k.zeroize();
        return Err(e);
    }

    let digest = content_digest(&body);
    let params = signature_params(alg, created, &keyid, nonce.as_deref());
    let base = signature_base(&method, &url, &digest, &params);

    let signature = match alg {
        SigAlg::Ed25519 => {
            let sk = ed25519_seed(key, F)?;
            use ed25519_dalek::Signer;
            sk.sign(base.as_bytes()).to_bytes().to_vec()
        }
        SigAlg::HmacSha256 => {
            let mut k = key;
            let mac = hmac_compute(Algo::Sha256, &k, base.as_bytes());
            k.zeroize();
            mac
        }
    };

    // Los headers listos para mandar (`http_post(url, body, {"headers": h})`).
    let mut out = IndexMap::new();
    out.insert("Content-Digest".to_string(), syn_text(digest.as_str()));
    out.insert(
        "Signature-Input".to_string(),
        syn_text(format!("{}={}", label, params)),
    );
    out.insert(
        "Signature".to_string(),
        syn_text(format!("{}=:{}:", label, b64_encode(&signature))),
    );
    Ok(syn_map(out))
}

// =========================================================
// http_signature_verify
// =========================================================

/// Un header del map `headers` de la request, case-insensitive (los headers HTTP no
/// distinguen mayúsculas y el map viene del server tal cual llegó al socket).
fn header_of(headers: &IndexMap<String, SynValue>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.to_string())
}

/// `label=valor` → (label, valor). El label es el primer `=` del header.
fn split_labeled(s: &str) -> Option<(&str, &str)> {
    let (label, rest) = s.split_once('=')?;
    let label = label.trim();
    if label.is_empty() {
        return None;
    }
    Some((label, rest.trim()))
}

/// Extrae un parámetro `;name="value"` del string de signature-params.
fn param_str(params: &str, name: &str) -> Option<String> {
    let needle = format!(";{}=\"", name);
    let start = params.find(&needle)? + needle.len();
    let rest = &params[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extrae un parámetro numérico `;name=123`.
fn param_int(params: &str, name: &str) -> Option<i64> {
    let needle = format!(";{}=", name);
    let start = params.find(&needle)? + needle.len();
    let rest = &params[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn b_http_signature_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "http_signature_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(request, key, opts?) takes 2 or 3 arguments", F)));
    }
    let req = req_map(&args[0], F)?;
    let opts = opts_map(args.get(2), F)?;

    // El algoritmo lo fija el VERIFICADOR — obligatorio, sin default. Leerlo del
    // mensaje permitiría el ataque de confusión de algoritmo (ver el doc del módulo).
    let mut alg: Option<SigAlg> = None;
    let mut max_age = DEFAULT_MAX_AGE;
    for (k, v) in &opts {
        match k.as_str() {
            "alg" => alg = Some(SigAlg::parse(&v.to_string(), F)?),
            "max_age" => match v {
                SynValue::Number(n) => match n.to_i64_trunc() {
                    Some(s) if s >= 0 => max_age = s,
                    _ => return Err(err(format!("{}: max_age must be an integer >= 0", F))),
                },
                other => {
                    return Err(err(format!(
                        "{}: max_age must be an integer (seconds), got {}",
                        F,
                        other.type_name()
                    )))
                }
            },
            other => {
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: alg, max_age)",
                    F, other
                )))
            }
        }
    }
    let alg = alg.ok_or_else(|| {
        err(format!(
            "{}: opts.alg is REQUIRED (\"ed25519\" or \"hmac-sha256\") — the verifier pins the algorithm; \
             taking it from the message allows an algorithm-confusion forgery",
            F
        ))
    })?;

    // El material de clave: para ed25519 es la PÚBLICA (32 bytes o hex), para HMAC
    // el secreto compartido. Verificar no gatea `sign` (no se firma nada).
    let key: Vec<u8> = match (&args[1], alg) {
        (SynValue::Secret(s), _) => s.expose_bytes().to_vec(),
        (SynValue::Bytes(b), _) => b.to_vec(),
        (SynValue::Text(s), SigAlg::Ed25519) => synsema_core::bytesutil::hex_decode(
            s.trim().strip_prefix("0x").unwrap_or(s.trim()),
        )
        .map_err(|_| {
            err(format!(
                "{}: the ed25519 public key as text must be hex (or pass bytes)",
                F
            ))
        })?,
        (SynValue::Text(s), SigAlg::HmacSha256) => s.as_bytes().to_vec(),
        (other, _) => {
            return Err(err(format!(
                "{}: the key must be a secret, text or bytes, got {}",
                F,
                other.type_name()
            )))
        }
    };

    // Toda falla del mensaje → `nothing`, sin detalle de por qué (mismo contrato que
    // `jwt_verify`: un endpoint no debe poder distinguirse por la causa del rechazo).
    Ok(verify_inner(&req, &key, alg, max_age).unwrap_or_else(syn_nothing))
}

fn verify_inner(
    req: &IndexMap<String, SynValue>,
    key: &[u8],
    alg: SigAlg,
    max_age: i64,
) -> Option<SynValue> {
    let method = match req.get("method")? {
        SynValue::Text(s) => s.trim().to_string(),
        _ => return None,
    };
    let url = match req.get("url")? {
        SynValue::Text(s) => s.trim().to_string(),
        _ => return None,
    };
    let headers = match req.get("headers")? {
        SynValue::Map(m) => m.borrow().clone(),
        _ => return None,
    };
    let body = match req.get("body") {
        None | Some(SynValue::Nothing) => Vec::new(),
        Some(SynValue::Text(s)) => s.as_bytes().to_vec(),
        Some(SynValue::Bytes(b)) => b.to_vec(),
        Some(_) => return None,
    };

    let sig_input = header_of(&headers, "signature-input")?;
    let sig_header = header_of(&headers, "signature")?;
    let (in_label, params) = split_labeled(&sig_input)?;
    let (sig_label, sig_b64) = split_labeled(&sig_header)?;
    // Los labels de Signature-Input y Signature deben ser el mismo bloque.
    if in_label != sig_label {
        return None;
    }
    let sig_bytes = synsema_core::bytesutil::b64_decode(sig_b64.trim().trim_matches(':')).ok()?;

    // El alg declarado DEBE coincidir con el que pineó el verificador.
    if param_str(params, "alg")? != alg.name() {
        return None;
    }
    let keyid = param_str(params, "keyid")?;
    let created = param_int(params, "created")?;
    let nonce = param_str(params, "nonce");

    // Ventana anti-replay: `created` dentro de ±max_age (un reloj adelantado del
    // cliente tampoco vale — la firma futura serviría para replay diferido).
    let now = unix_now();
    if max_age > 0 && (now - created).abs() > max_age {
        return None;
    }

    // El Content-Digest declarado debe corresponder al body REAL (si no, el body
    // podría cambiarse sin tocar la firma) — comparación constant-time.
    let declared_digest = header_of(&headers, "content-digest")?;
    let real_digest = content_digest(&body);
    if !constant_time_eq(declared_digest.trim().as_bytes(), real_digest.as_bytes()) {
        return None;
    }

    // Base reconstruida con los MISMOS componentes del perfil y los params tal cual
    // llegaron (así el orden/formato exacto que firmó el cliente se respeta).
    let base = signature_base(&method, &url, &real_digest, params);

    let ok = match alg {
        SigAlg::Ed25519 => {
            let pk: [u8; 32] = key.get(..32)?.try_into().ok()?;
            if key.len() != 32 {
                return None;
            }
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).ok()?;
            let sig_arr: [u8; 64] = sig_bytes.get(..64)?.try_into().ok()?;
            if sig_bytes.len() != 64 {
                return None;
            }
            use ed25519_dalek::Verifier;
            vk.verify(base.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .is_ok()
        }
        SigAlg::HmacSha256 => {
            let expected = hmac_compute(Algo::Sha256, key, base.as_bytes());
            constant_time_eq(&expected, &sig_bytes)
        }
    };
    if !ok {
        return None;
    }

    // El resultado identifica QUIÉN firmó (keyid) y trae el nonce para que el
    // llamador lo cheque contra su store de replay en rutas de mutación.
    let mut out = IndexMap::new();
    out.insert("keyid".to_string(), syn_text(keyid.as_str()));
    out.insert("alg".to_string(), syn_text(alg.name()));
    out.insert("created".to_string(), syn_int(created));
    out.insert(
        "nonce".to_string(),
        match nonce {
            Some(n) => syn_text(n.as_str()),
            None => syn_nothing(),
        },
    );
    Some(syn_map(out))
}

// =========================================================
// Registro
// =========================================================

/// Registra `http_sign` (gateado por `sign(NAME)` + audit) y
/// `http_signature_verify` (puro). Wired en `wire_common_with_state`.
pub fn register_httpsig_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    let c = caps.clone();
    interp.register_builtin(
        "http_sign",
        -1,
        Rc::new(move |_i, a, l| b_http_sign(a, l, &c)),
    );
    interp.register_builtin(
        "http_signature_verify",
        -1,
        Rc::new(|_i, a, _l| b_http_signature_verify(a)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_bytes;

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

    fn imap(pairs: Vec<(&str, SynValue)>) -> IndexMap<String, SynValue> {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("unexpected error: {}", e),
            Err(_) => panic!("unexpected control flow"),
        }
    }

    /// Firma HMAC directa (sin pasar por el builtin, que exige un secret sellado y
    /// el gate `sign`): arma exactamente la misma base y devuelve los headers.
    fn sign_hmac(
        method: &str,
        url: &str,
        body: &[u8],
        key: &[u8],
        created: i64,
        nonce: Option<&str>,
    ) -> IndexMap<String, SynValue> {
        let digest = content_digest(body);
        let params = signature_params(SigAlg::HmacSha256, created, "agent-1", nonce);
        let base = signature_base(method, url, &digest, &params);
        let mac = hmac_compute(Algo::Sha256, key, base.as_bytes());
        imap(vec![
            ("Content-Digest", text(&digest)),
            ("Signature-Input", text(&format!("sig1={}", params))),
            ("Signature", text(&format!("sig1=:{}:", b64_encode(&mac)))),
        ])
    }

    fn request_with(headers: IndexMap<String, SynValue>, body: &str) -> SynValue {
        map(vec![
            ("method", text("POST")),
            ("url", text("https://api.example.com/orders")),
            ("headers", SynValue::Map(Rc::new(RefCell::new(headers)))),
            ("body", text(body)),
        ])
    }

    #[test]
    fn signature_base_is_rfc9421_shaped() {
        let params = signature_params(SigAlg::Ed25519, 1618884473, "agent-1", None);
        assert_eq!(
            params,
            "(\"@method\" \"@target-uri\" \"content-digest\");created=1618884473;keyid=\"agent-1\";alg=\"ed25519\""
        );
        let base = signature_base("post", "https://x/y", &content_digest(b""), &params);
        let lines: Vec<&str> = base.split('\n').collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "\"@method\": POST", "el método va en mayúsculas");
        assert_eq!(lines[1], "\"@target-uri\": https://x/y");
        assert!(lines[2].starts_with("\"content-digest\": sha-256=:"));
        assert_eq!(lines[3], format!("\"@signature-params\": {}", params));
        // Vector conocido: sha-256 del body vacío (RFC 9530 / NIST).
        assert_eq!(
            content_digest(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    #[test]
    fn verify_roundtrip_hmac() {
        let key = b"shared-secret";
        let now = unix_now();
        let h = sign_hmac("POST", "https://api.example.com/orders", b"{\"n\":1}", key, now, None);
        let req = request_with(h, "{\"n\":1}");
        let opts = map(vec![("alg", text("hmac-sha256"))]);
        let out = ok(b_http_signature_verify(&[req, text("shared-secret"), opts]));
        match out {
            SynValue::Map(m) => {
                let m = m.borrow();
                assert_eq!(m.get("keyid").unwrap().to_string(), "agent-1");
                assert_eq!(m.get("alg").unwrap().to_string(), "hmac-sha256");
                assert!(matches!(m.get("nonce"), Some(SynValue::Nothing)));
            }
            other => panic!("expected verification map, got {}", other),
        }
    }

    #[test]
    fn verify_rejects_tampering() {
        let key = b"shared-secret";
        let now = unix_now();
        let good = sign_hmac("POST", "https://api.example.com/orders", b"{\"n\":1}", key, now, None);
        let alg = || map(vec![("alg", text("hmac-sha256"))]);

        // (1) Body cambiado (misma firma) → el Content-Digest ya no cierra.
        let req = request_with(good.clone(), "{\"n\":999}");
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), alg()])),
            SynValue::Nothing
        ));

        // (2) Método cambiado → la base cambia.
        let mut m = imap(vec![
            ("method", text("DELETE")),
            ("url", text("https://api.example.com/orders")),
            ("headers", SynValue::Map(Rc::new(RefCell::new(good.clone())))),
            ("body", text("{\"n\":1}")),
        ]);
        let req = SynValue::Map(Rc::new(RefCell::new(std::mem::take(&mut m))));
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), alg()])),
            SynValue::Nothing
        ));

        // (3) URL cambiada (mismo método y body).
        let mut m = imap(vec![
            ("method", text("POST")),
            ("url", text("https://api.example.com/admin")),
            ("headers", SynValue::Map(Rc::new(RefCell::new(good.clone())))),
            ("body", text("{\"n\":1}")),
        ]);
        let req = SynValue::Map(Rc::new(RefCell::new(std::mem::take(&mut m))));
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), alg()])),
            SynValue::Nothing
        ));

        // (4) Clave equivocada.
        let req = request_with(good.clone(), "{\"n\":1}");
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("otra-clave"), alg()])),
            SynValue::Nothing
        ));

        // (5) Firma truncada / basura.
        let mut bad = good.clone();
        bad.insert("Signature".to_string(), text("sig1=:AAAA:"));
        let req = request_with(bad, "{\"n\":1}");
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), alg()])),
            SynValue::Nothing
        ));

        // (6) Sin headers de firma.
        let req = request_with(imap(vec![]), "{\"n\":1}");
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), alg()])),
            SynValue::Nothing
        ));
    }

    #[test]
    fn verify_replay_window() {
        let key = b"shared-secret";
        let old = unix_now() - 3600;
        let h = sign_hmac("POST", "https://api.example.com/orders", b"", key, old, None);
        let req = request_with(h.clone(), "");
        // Fuera de la ventana por defecto (300 s) → rechazo.
        let opts = map(vec![("alg", text("hmac-sha256"))]);
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), opts])),
            SynValue::Nothing
        ));
        // Con una ventana amplia, la MISMA firma vale (prueba que lo que rechazó
        // fue la edad, no la firma).
        let req = request_with(h.clone(), "");
        let opts = map(vec![("alg", text("hmac-sha256")), ("max_age", syn_int(7200))]);
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), opts])),
            SynValue::Map(_)
        ));
        // Un `created` en el FUTURO también se rechaza (replay diferido).
        let future = unix_now() + 3600;
        let h = sign_hmac("POST", "https://api.example.com/orders", b"", key, future, None);
        let req = request_with(h, "");
        let opts = map(vec![("alg", text("hmac-sha256"))]);
        assert!(matches!(
            ok(b_http_signature_verify(&[req, text("shared-secret"), opts])),
            SynValue::Nothing
        ));
    }

    #[test]
    fn verify_pins_the_algorithm() {
        // EL ataque: el mensaje dice hmac-sha256 y usa la clave PÚBLICA ed25519 como
        // clave HMAC. Si el verificador leyera el alg del mensaje, verificaría bien.
        let pubkey = [7u8; 32];
        let now = unix_now();
        let h = sign_hmac("POST", "https://api.example.com/orders", b"", &pubkey, now, None);
        let req = request_with(h, "");
        // El verificador pinea ed25519 → el mensaje hmac-sha256 se rechaza.
        let opts = map(vec![("alg", text("ed25519"))]);
        assert!(matches!(
            ok(b_http_signature_verify(&[req, syn_bytes(pubkey.to_vec()), opts])),
            SynValue::Nothing
        ));
        // Y omitir `alg` es ERROR del programador, no un default permisivo.
        let h = sign_hmac("POST", "https://api.example.com/orders", b"", &pubkey, now, None);
        let req = request_with(h, "");
        let e = b_http_signature_verify(&[req, syn_bytes(pubkey.to_vec())]);
        assert!(e.is_err(), "sin opts.alg debe ser error");
    }

    #[test]
    fn verify_returns_nonce_for_replay_stores() {
        let key = b"shared-secret";
        let now = unix_now();
        let h = sign_hmac("POST", "https://api.example.com/orders", b"", key, now, Some("n-42"));
        let req = request_with(h, "");
        let opts = map(vec![("alg", text("hmac-sha256"))]);
        match ok(b_http_signature_verify(&[req, text("shared-secret"), opts])) {
            SynValue::Map(m) => {
                assert_eq!(m.borrow().get("nonce").unwrap().to_string(), "n-42");
            }
            other => panic!("expected map, got {}", other),
        }
    }

    #[test]
    fn param_parsing_is_strict() {
        let p = "(\"@method\");created=1700000000;keyid=\"k1\";alg=\"ed25519\";nonce=\"abc\"";
        assert_eq!(param_str(p, "keyid").as_deref(), Some("k1"));
        assert_eq!(param_str(p, "alg").as_deref(), Some("ed25519"));
        assert_eq!(param_str(p, "nonce").as_deref(), Some("abc"));
        assert_eq!(param_int(p, "created"), Some(1700000000));
        assert_eq!(param_str(p, "missing"), None);
        assert_eq!(param_int(p, "expires"), None);
    }

    #[test]
    fn sign_opts_and_request_fail_strong() {
        let key = text("no-es-secret");
        let req = map(vec![("method", text("GET")), ("url", text("https://x/"))]);
        let loc = SourceLocation { file: "t".into(), line: 1, column: 1, offset: 0 };
        let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
        // La clave DEBE ser un secret sellado (nunca un string pelado).
        assert!(b_http_sign(&[req.clone(), key, SynValue::Nothing], &loc, &caps).is_err());
        // Opt desconocida → error (typo, no silencio).
        let bad_opts = map(vec![("algorithm", text("ed25519"))]);
        assert!(b_http_sign(&[req.clone(), text("k"), bad_opts], &loc, &caps).is_err());
        // Request sin url / con body de tipo raro.
        let no_url = map(vec![("method", text("GET"))]);
        assert!(b_http_sign(&[no_url, text("k"), SynValue::Nothing], &loc, &caps).is_err());
        let bad_body = map(vec![
            ("method", text("POST")),
            ("url", text("https://x/")),
            ("body", syn_int(5)),
        ]);
        assert!(b_http_sign(&[bad_body, text("k"), SynValue::Nothing], &loc, &caps).is_err());
    }
}
