//! Pruebas **W3C Data Integrity** sobre documentos JSON (T3/T4 del spec de identidad):
//! `document_sign` / `document_verify`, con las suites que canonizan por JCS (RFC 8785):
//! `eddsa-jcs-2022` (ed25519; VC Data Integrity EdDSA Cryptosuites v1.0, W3C Recommendation
//! del 2025-05-15) y `ecdsa-jcs-2019` (P-256, la misma construcción con ECDSA/SHA-256).
//! La suite RDF (`eddsa-rdfc-2022`) queda afuera a propósito: canonizar RDF es una
//! dependencia conceptual enorme sin ganancia; JCS es suficiente y el estándar lo ofrece
//! como primera clase.
//!
//! Con esto, el recibo de una unidad de trabajo (T4) y la tarjeta del server (T3) son
//! documentos que **cualquier verificador de credenciales del mundo valida** sin saber qué
//! es Synsema, y nosotros no dependemos de nadie: `did:key` + JCS + ed25519 son aritmética.
//!
//! La construcción (§3.3 de la spec EdDSA, idéntica en la ECDSA):
//! ```text
//! proofConfig = proof options sin `proofValue` (+ el `@context` del documento, si tiene)
//! hashData    = sha256(JCS(proofConfig)) ‖ sha256(JCS(documento sin `proof`))
//! proofValue  = "z" + base58btc(firma(hashData))       // ed25519: 64 bytes; P-256: r‖s crudos
//! ```
//!
//! Doctrina:
//! - `document_sign` con un `secret` pasa por el gate `sign("NAME")` y su audit, como
//!   `ed25519_sign` (es la MISMA operación: autorizar con la clave). Con un PEM P-256 en texto
//!   no hay gate — el programa ya tiene el plaintext, como en `ecdsa_p256_sign`.
//! - `document_verify` es PURO y devuelve `nothing` en toda falla (firma, suite desconocida,
//!   `proofPurpose`/`challenge`/`domain` que no coinciden con lo exigido): un verificador no
//!   se distingue por el motivo. Errores sólo por forma mal armada (falta `proof`, clave que no
//!   se entiende).
//! - La clave pública de `document_verify` es bytes (32 = ed25519; 33/65 = P-256), un
//!   `did:key` (se resuelve offline) o un JWK (`OKP`/`EC`).
//! - `created` es OPCIONAL (así lo permite la spec): sin él no se lee el reloj y el builtin no
//!   exige `time`; el programa lo pasa si lo quiere (`opts.created`).

use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use synsema_capabilities::model::CapabilitySet;
use synsema_core::bytesutil::{b64url_decode, base58_decode, base58_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_map, syn_nothing, syn_text, SynValue};

use std::cell::RefCell;
use std::rc::Rc;

use crate::blockchain::{ed25519_seed, gate_and_audit, key_material};
use crate::canonical::canonical_json;
use crate::didkey::{self, KeyAlg};
use crate::webauth::{es256_sign, es256_verify, pem_text, private_key_from_pem, public_key_from_pem, AsymPrivate, AsymPublic};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

pub const SUITE_EDDSA: &str = "eddsa-jcs-2022";
pub const SUITE_ECDSA: &str = "ecdsa-jcs-2019";
const PROOF_TYPE: &str = "DataIntegrityProof";

fn as_map(v: &SynValue, who: &str, what: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!("{}: {} must be a map, got {}", who, what, other.type_name()))),
    }
}

fn text_opt(m: &IndexMap<String, SynValue>, k: &str, who: &str) -> Result<Option<String>, Control> {
    match m.get(k) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Text(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
        Some(_) => Err(err(format!("{}: opts.{} must be a non-empty text", who, k))),
    }
}

/// `sha256(JCS(proofConfig)) ‖ sha256(JCS(doc sin proof))`.
fn hash_data(proof_config: &SynValue, doc_without_proof: &SynValue) -> Result<Vec<u8>, Control> {
    let cfg = canonical_json(proof_config)?;
    let doc = canonical_json(doc_without_proof)?;
    let mut out = Sha256::digest(cfg.as_bytes()).to_vec();
    out.extend_from_slice(&Sha256::digest(doc.as_bytes()));
    Ok(out)
}

// =========================================================
// firmar
// =========================================================

pub(crate) enum Signer {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::SecretKey),
}

impl Signer {
    fn suite(&self) -> &'static str {
        match self {
            Signer::Ed25519(_) => SUITE_EDDSA,
            Signer::P256(_) => SUITE_ECDSA,
        }
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Signer::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                sk.sign(msg).to_bytes().to_vec()
            }
            Signer::P256(sk) => es256_sign(sk, msg),
        }
    }
    /// El `did:key` de la clave que firma (el `issuer` de un recibo: derivado, no declarado).
    pub(crate) fn did_key(&self) -> Result<String, String> {
        match self {
            Signer::Ed25519(sk) => didkey::encode(KeyAlg::Ed25519, &sk.verifying_key().to_bytes()),
            Signer::P256(sk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                didkey::encode(KeyAlg::P256, sk.public_key().to_encoded_point(true).as_bytes())
            }
        }
    }
    /// `did:key:z…#z…` de la clave que firma: el verificationMethod por defecto.
    fn did_key_verification_method(&self) -> Result<String, String> {
        let did = self.did_key()?;
        let mb = did.strip_prefix("did:key:").unwrap_or(&did).to_string();
        Ok(format!("{}#{}", did, mb))
    }
}

/// La clave de firma: un `secret` (32 bytes; ed25519 salvo que la suite pedida sea ECDSA,
/// gate `sign("NAME")` + audit) o un PEM P-256 en texto (sin gate, como `ecdsa_p256_sign`).
pub(crate) fn signer_from(
    key: &SynValue,
    suite: Option<&str>,
    who: &str,
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<Signer, Control> {
    match key {
        SynValue::Text(_) => {
            let pem = pem_text(key, who, "the signing key")?;
            match private_key_from_pem(&pem, who)? {
                AsymPrivate::P256(k) => {
                    if matches!(suite, Some(s) if s != SUITE_ECDSA) {
                        return Err(err(format!(
                            "{}: a P-256 key signs with {:?}, not {:?}",
                            who, SUITE_ECDSA, suite.unwrap_or("")
                        )));
                    }
                    Ok(Signer::P256(k))
                }
                AsymPrivate::Ed25519(k) => {
                    if matches!(suite, Some(s) if s != SUITE_EDDSA) {
                        return Err(err(format!(
                            "{}: an ed25519 key signs with {:?}, not {:?}",
                            who, SUITE_EDDSA, suite.unwrap_or("")
                        )));
                    }
                    Ok(Signer::Ed25519(k))
                }
                AsymPrivate::Rsa(_) => Err(err(format!(
                    "{}: Data Integrity has no RSA suite here; sign with an ed25519 secret ({}) or a P-256 key ({})",
                    who, SUITE_EDDSA, SUITE_ECDSA
                ))),
            }
        }
        SynValue::Secret(_) => {
            let (name, mut raw) = key_material(key, who)?;
            let curve = if suite == Some(SUITE_ECDSA) { "p256" } else { "ed25519" };
            if let Err(e) = gate_and_audit(caps, &name, curve, loc) {
                raw.zeroize();
                return Err(e);
            }
            if suite == Some(SUITE_ECDSA) {
                if raw.len() != 32 {
                    raw.zeroize();
                    return Err(err(format!("{}: a P-256 private scalar is 32 bytes (the key value is never shown)", who)));
                }
                let sk = p256::SecretKey::from_slice(&raw);
                raw.zeroize();
                let sk = sk.map_err(|_| err(format!("{}: the secret is not a valid P-256 scalar (the key value is never shown)", who)))?;
                Ok(Signer::P256(sk))
            } else {
                Ok(Signer::Ed25519(ed25519_seed(raw, who)?))
            }
        }
        other => Err(err(format!(
            "{}: the signing key must be a secret (ed25519 seed, or a P-256 scalar with cryptosuite {:?}) or an ed25519 / P-256 private key PEM, got {}",
            who,
            SUITE_ECDSA,
            other.type_name()
        ))),
    }
}

/// Firma un documento (map) y devuelve el documento con su `proof`. Pública dentro del
/// crate: el recibo (T4) la usa desde el runtime.
pub fn sign_document(
    doc: &SynValue,
    key: &SynValue,
    opts: &IndexMap<String, SynValue>,
    who: &str,
    loc: &SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    let suite_opt = validate_suite_opt(opts, who)?;
    let signer = signer_from(key, suite_opt.as_deref(), who, loc, caps)?;
    sign_document_with(doc, &signer, opts, who)
}

/// `opts.cryptosuite`, validada (o `None`).
pub(crate) fn validate_suite_opt(opts: &IndexMap<String, SynValue>, who: &str) -> Result<Option<String>, Control> {
    let suite_opt = text_opt(opts, "cryptosuite", who)?;
    if let Some(s) = &suite_opt {
        if s != SUITE_EDDSA && s != SUITE_ECDSA {
            return Err(err(format!(
                "{}: opts.cryptosuite must be {:?} or {:?}, got {:?}",
                who, SUITE_EDDSA, SUITE_ECDSA, s
            )));
        }
    }
    Ok(suite_opt)
}

/// Firma con un firmante YA preparado (puerta `sign` y audit ya pasados): el recibo arma
/// el documento con el `issuer` derivado de esa misma clave y recién entonces firma.
pub(crate) fn sign_document_with(
    doc: &SynValue,
    signer: &Signer,
    opts: &IndexMap<String, SynValue>,
    who: &str,
) -> Result<SynValue, Control> {
    let doc_map = as_map(doc, who, "document")?;
    if doc_map.contains_key("proof") {
        return Err(err(format!(
            "{}: the document already carries a `proof`; sign the document without it (proof sets are not supported: one proof per document)",
            who
        )));
    }
    for k in opts.keys() {
        if !matches!(
            k.as_str(),
            "verification_method" | "proof_purpose" | "created" | "cryptosuite" | "challenge" | "domain"
        ) {
            return Err(err(format!(
                "{}: unknown option {:?} (valid options: verification_method, proof_purpose, created, cryptosuite, challenge, domain)",
                who, k
            )));
        }
    }
    if let Some(s) = validate_suite_opt(opts, who)? {
        if s != signer.suite() {
            return Err(err(format!(
                "{}: opts.cryptosuite is {:?} but the key signs with {:?}",
                who, s, signer.suite()
            )));
        }
    }
    // `verification_method`: la URL de la clave pública que usará el verificador. Sin opción,
    // la que se deriva con verdad de la clave que firma: su `did:key` (`did:key:z…#z…`), que
    // cualquier verificador resuelve offline. Se puede dar otra (un `did:web`, una URL propia).
    let vm = match text_opt(opts, "verification_method", who)? {
        Some(v) => v,
        None => signer.did_key_verification_method().map_err(|e| err(format!("{}: {}", who, e)))?,
    };
    let purpose = text_opt(opts, "proof_purpose", who)?.unwrap_or_else(|| "assertionMethod".to_string());

    // proofConfig (§3.3.3): sin proofValue; con el @context del documento si lo tiene.
    let mut cfg = IndexMap::new();
    if let Some(ctx) = doc_map.get("@context") {
        cfg.insert("@context".to_string(), ctx.clone());
    }
    cfg.insert("type".to_string(), syn_text(PROOF_TYPE));
    cfg.insert("cryptosuite".to_string(), syn_text(signer.suite()));
    if let Some(c) = text_opt(opts, "created", who)? {
        cfg.insert("created".to_string(), syn_text(c));
    }
    cfg.insert("verificationMethod".to_string(), syn_text(vm));
    cfg.insert("proofPurpose".to_string(), syn_text(purpose));
    if let Some(c) = text_opt(opts, "challenge", who)? {
        cfg.insert("challenge".to_string(), syn_text(c));
    }
    if let Some(d) = text_opt(opts, "domain", who)? {
        cfg.insert("domain".to_string(), syn_text(d));
    }
    let cfg_val = syn_map(cfg.clone());
    let data = hash_data(&cfg_val, doc)?;
    let sig = signer.sign(&data);
    cfg.insert("proofValue".to_string(), syn_text(format!("z{}", base58_encode(&sig))));

    let mut out = doc_map;
    out.insert("proof".to_string(), syn_map(cfg));
    Ok(syn_map(out))
}

fn b_document_sign(args: &[SynValue], loc: &SourceLocation, caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "document_sign";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(document, key, opts) takes 2 or 3 arguments", F)));
    }
    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(v) => as_map(v, F, "opts")?,
    };
    sign_document(&args[0], &args[1], &opts, F, loc, caps)
}

// =========================================================
// verificar
// =========================================================

enum Verifier {
    Ed25519([u8; 32]),
    P256(p256::ecdsa::VerifyingKey),
}

impl Verifier {
    fn suite(&self) -> &'static str {
        match self {
            Verifier::Ed25519(_) => SUITE_EDDSA,
            Verifier::P256(_) => SUITE_ECDSA,
        }
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            Verifier::Ed25519(pk) => {
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else { return false };
                let Ok(sa): Result<[u8; 64], _> = sig.try_into() else { return false };
                vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sa)).is_ok()
            }
            Verifier::P256(vk) => es256_verify(vk, msg, sig),
        }
    }
}

/// La clave pública: bytes, `did:key`, o JWK (`OKP` Ed25519 / `EC` P-256).
/// El `did:key` de una clave pública dada como bytes, did:key, PEM o JWK — para atar el
/// `issuer` de un recibo a la clave que lo verifica.
pub(crate) fn did_key_of_public_key(v: &SynValue, who: &str) -> Result<String, Control> {
    let did = match verifier_from(v, who)? {
        Verifier::Ed25519(pk) => didkey::encode(KeyAlg::Ed25519, &pk),
        Verifier::P256(vk) => didkey::encode(KeyAlg::P256, vk.to_encoded_point(true).as_bytes()),
    };
    did.map_err(|e| err(format!("{}: {}", who, e)))
}

fn verifier_from(v: &SynValue, who: &str) -> Result<Verifier, Control> {
    let from_bytes = |b: &[u8]| -> Result<Verifier, Control> {
        match b.len() {
            32 => Ok(Verifier::Ed25519(b.try_into().expect("32"))),
            33 | 65 => p256::ecdsa::VerifyingKey::from_sec1_bytes(b)
                .map(Verifier::P256)
                .map_err(|_| err(format!("{}: public_key is not a valid P-256 point", who))),
            n => Err(err(format!(
                "{}: public_key must be 32 bytes (ed25519) or 33/65 bytes (P-256 SEC1), got {}",
                who, n
            ))),
        }
    };
    match v {
        SynValue::Bytes(b) => from_bytes(b),
        SynValue::Text(s) if s.contains("-----BEGIN") => match public_key_from_pem(s, who)? {
            AsymPublic::Ed25519(vk) => Ok(Verifier::Ed25519(vk.to_bytes())),
            AsymPublic::P256(vk) => Ok(Verifier::P256(vk)),
            AsymPublic::Rsa(_) => Err(err(format!(
                "{}: Data Integrity has no RSA suite here (ed25519 or P-256 only)",
                who
            ))),
        },
        SynValue::Text(s) if s.trim().starts_with("did:") => {
            let (alg, key, _) = didkey::decode(s).map_err(|e| err(format!("{}: {}", who, e)))?;
            match alg {
                KeyAlg::Ed25519 | KeyAlg::P256 => from_bytes(&key),
                other => Err(err(format!(
                    "{}: a {} key does not sign Data Integrity proofs (ed25519 or P-256 only)",
                    who,
                    other.name()
                ))),
            }
        }
        SynValue::Map(m) => {
            let m = m.borrow();
            let t = |k: &str| match m.get(k) {
                Some(SynValue::Text(s)) => Some(s.to_string()),
                _ => None,
            };
            match t("kty").as_deref() {
                Some("OKP") => {
                    let x = b64url_decode(&t("x").unwrap_or_default())
                        .map_err(|_| err(format!("{}: public_key.x is not base64url", who)))?;
                    from_bytes(&x)
                }
                Some("EC") => {
                    let x = b64url_decode(&t("x").unwrap_or_default())
                        .map_err(|_| err(format!("{}: public_key.x is not base64url", who)))?;
                    let y = b64url_decode(&t("y").unwrap_or_default())
                        .map_err(|_| err(format!("{}: public_key.y is not base64url", who)))?;
                    let mut sec1 = vec![0x04];
                    sec1.extend_from_slice(&x);
                    sec1.extend_from_slice(&y);
                    from_bytes(&sec1)
                }
                _ => Err(err(format!(
                    "{}: public_key must be bytes, a did:key, or a JWK with kty \"OKP\" (Ed25519) or \"EC\" (P-256)",
                    who
                ))),
            }
        }
        SynValue::Secret(_) => Err(err(format!(
            "{}: public_key must be the PUBLIC key, got a secret — derive it (ed25519_pubkey(secret)) or pass your did:key",
            who
        ))),
        other => Err(err(format!(
            "{}: public_key must be bytes, a did:key text, a public key PEM or a JWK map, got {}",
            who,
            other.type_name()
        ))),
    }
}

/// Verifica un documento firmado. `Ok(None)` = rechazo; `Err` = forma mal armada.
pub fn verify_document(
    doc: &SynValue,
    public_key: &SynValue,
    opts: &IndexMap<String, SynValue>,
    who: &str,
) -> Result<Option<SynValue>, Control> {
    let mut doc_map = as_map(doc, who, "document")?;
    let verifier = verifier_from(public_key, who)?;
    for k in opts.keys() {
        if !matches!(k.as_str(), "proof_purpose" | "challenge" | "domain") {
            return Err(err(format!(
                "{}: unknown option {:?} (valid options: proof_purpose, challenge, domain)",
                who, k
            )));
        }
    }
    let Some(SynValue::Map(proof)) = doc_map.shift_remove("proof") else {
        return Err(err(format!(
            "{}: the document has no `proof` map — nothing to verify (was it signed with document_sign?)",
            who
        )));
    };
    let mut proof = proof.borrow().clone();
    let t = |m: &IndexMap<String, SynValue>, k: &str| -> Option<String> {
        match m.get(k) {
            Some(SynValue::Text(s)) => Some(s.to_string()),
            _ => None,
        }
    };
    if t(&proof, "type").as_deref() != Some(PROOF_TYPE) {
        return Ok(None);
    }
    let suite = t(&proof, "cryptosuite").unwrap_or_default();
    if suite != verifier.suite() {
        return Ok(None);
    }
    let Some(pv) = t(&proof, "proofValue") else { return Ok(None) };
    let Some(pv58) = pv.strip_prefix('z') else { return Ok(None) };
    let Ok(sig) = base58_decode(pv58) else { return Ok(None) };
    // Lo que el verificador EXIGE tiene que coincidir con lo que el proof dice.
    if let Some(p) = text_opt(opts, "proof_purpose", who)? {
        if t(&proof, "proofPurpose").as_deref() != Some(p.as_str()) {
            return Ok(None);
        }
    }
    if let Some(c) = text_opt(opts, "challenge", who)? {
        if t(&proof, "challenge").as_deref() != Some(c.as_str()) {
            return Ok(None);
        }
    }
    if let Some(d) = text_opt(opts, "domain", who)? {
        if t(&proof, "domain").as_deref() != Some(d.as_str()) {
            return Ok(None);
        }
    }
    // El @context del proof, si hay, tiene que ser el del documento (§3.3.4).
    if let (Some(pc), Some(dc)) = (proof.get("@context"), doc_map.get("@context")) {
        if canonical_json(pc)? != canonical_json(dc)? {
            return Ok(None);
        }
    }
    proof.shift_remove("proofValue");
    let cfg_val = syn_map(proof.clone());
    let data = hash_data(&cfg_val, &syn_map(doc_map))?;
    if !verifier.verify(&data, &sig) {
        return Ok(None);
    }
    let mut out = IndexMap::new();
    out.insert("verified".to_string(), SynValue::Bool(true));
    out.insert("cryptosuite".to_string(), syn_text(suite));
    for k in ["verificationMethod", "proofPurpose", "created", "challenge", "domain"] {
        let key = match k {
            "verificationMethod" => "verification_method",
            "proofPurpose" => "proof_purpose",
            other => other,
        };
        out.insert(key.to_string(), proof.get(k).cloned().unwrap_or_else(syn_nothing));
    }
    Ok(Some(syn_map(out)))
}

fn b_document_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "document_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(document, public_key, opts?) takes 2 or 3 arguments", F)));
    }
    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(v) => as_map(v, F, "opts")?,
    };
    Ok(verify_document(&args[0], &args[1], &opts, F)?.unwrap_or_else(syn_nothing))
}

/// Registra `document_sign` (gate `sign` cuando la clave es un secret) y `document_verify`
/// (puro).
pub fn register_integrity_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    interp.register_builtin("document_sign", -1, Rc::new(move |_i, a, l| b_document_sign(a, l, &caps)));
    interp.register_builtin("document_verify", -1, Rc::new(|_i, a, _l| b_document_verify(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_capabilities::model::{Capability, CapabilityType};
    use synsema_core::secret::SecretInner;
    use synsema_core::types::{syn_int, syn_list};

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
    fn entries(v: &SynValue) -> IndexMap<String, SynValue> {
        match v {
            SynValue::Map(m) => m.borrow().clone(),
            other => panic!("map, got {}", other),
        }
    }
    fn caps_with_sign(name: &str) -> Rc<RefCell<CapabilitySet>> {
        let mut cs = CapabilitySet::new("test");
        cs.grant(Capability::new(CapabilityType::Sign, Some(name.to_string())));
        Rc::new(RefCell::new(cs))
    }
    fn secret(name: &str, seed: [u8; 32]) -> SynValue {
        SynValue::Secret(Rc::new(SecretInner::new(name.to_string(), hex(&seed))))
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
    fn loc() -> SourceLocation {
        SourceLocation { file: "t.syn".into(), line: 1, column: 1, offset: 0 }
    }
    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }
    fn err_of(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.to_string(),
            Ok(v) => panic!("esperaba error, got {}", v),
            Err(_) => panic!("control"),
        }
    }

    fn doc() -> SynValue {
        map(vec![
            ("@context", syn_list(vec![text("https://www.w3.org/ns/credentials/v2")])),
            ("type", syn_list(vec![text("VerifiableCredential"), text("SynsemaReceipt")])),
            ("issuer", text("did:key:z6Mk…")),
            ("credentialSubject", map(vec![("subject", text("agent-7")), ("spend", syn_int(3))])),
        ])
    }

    #[test]
    fn eddsa_jcs_2022_roundtrip_and_every_tamper_is_nothing() {
        let seed = [42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let did = didkey::encode(KeyAlg::Ed25519, &pk).unwrap();
        let caps = caps_with_sign("ISSUER");
        let opts = entries(&map(vec![
            ("verification_method", text(&format!("{}#{}", did, &did["did:key:".len()..]))),
            ("created", text("2026-09-22T12:00:00Z")),
            ("challenge", text("nonce-1")),
            ("domain", text("orders-api")),
        ]));
        let signed = ok(sign_document(&doc(), &secret("ISSUER", seed), &opts, "document_sign", &loc(), &caps));
        let proof = entries(&entries(&signed)["proof"]);
        assert_eq!(proof["type"].to_string(), "DataIntegrityProof");
        assert_eq!(proof["cryptosuite"].to_string(), "eddsa-jcs-2022");
        assert!(proof["proofValue"].to_string().starts_with('z'));
        assert!(proof.contains_key("@context"), "el @context del documento viaja en el proofConfig");

        // Verifica con bytes, con did:key y con JWK.
        let bytes_key = SynValue::Bytes(Rc::from(pk.clone().into_boxed_slice()));
        let v = verify_document(&signed, &bytes_key, &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().expect("verifica");
        let v = entries(&v);
        assert!(matches!(v["verified"], SynValue::Bool(true)));
        assert_eq!(v["proof_purpose"].to_string(), "assertionMethod");
        assert_eq!(v["challenge"].to_string(), "nonce-1");
        assert!(verify_document(&signed, &text(&did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_some());
        let jwk = map(vec![("kty", text("OKP")), ("crv", text("Ed25519")), ("x", text(&synsema_core::bytesutil::b64url_encode(&pk)))]);
        assert!(verify_document(&signed, &jwk, &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_some());
        // Lo exigido tiene que coincidir.
        let want = |k: &str, v: &str| entries(&map(vec![(k, text(v))]));
        assert!(verify_document(&signed, &text(&did), &want("challenge", "nonce-1"), "document_verify").map_err(|_| ()).unwrap().is_some());
        assert!(verify_document(&signed, &text(&did), &want("challenge", "nonce-2"), "document_verify").map_err(|_| ()).unwrap().is_none());
        assert!(verify_document(&signed, &text(&did), &want("domain", "other"), "document_verify").map_err(|_| ()).unwrap().is_none());
        assert!(verify_document(&signed, &text(&did), &want("proof_purpose", "authentication"), "document_verify").map_err(|_| ()).unwrap().is_none());
        // Un byte cambiado en el documento → nothing.
        let mut tampered = entries(&signed);
        tampered.insert("issuer".to_string(), text("did:key:zOther"));
        assert!(verify_document(&syn_map(tampered), &text(&did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_none());
        // Otra clave → nothing.
        let other = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes().to_vec();
        let other_did = didkey::encode(KeyAlg::Ed25519, &other).unwrap();
        assert!(verify_document(&signed, &text(&other_did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_none());
        // Sin `proof` → error de forma.
        let e = err_of(b_document_verify(&[doc(), text(&did)]));
        assert!(e.contains("has no `proof`"), "{}", e);
    }

    #[test]
    fn signing_needs_the_sign_capability_and_defaults_the_verification_method_to_the_did_key() {
        let seed = [9u8; 32];
        let no_caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        let opts = entries(&map(vec![("verification_method", text("did:key:zX#zX"))]));
        let e = err_of(sign_document(&doc(), &secret("K", seed), &opts, "document_sign", &loc(), &no_caps));
        assert!(e.contains("sign"), "{}", e);
        // Sin `verification_method`: el did:key de la clave que firma, y el documento verifica con él.
        let signed = sign_document(&doc(), &secret("K", seed), &IndexMap::new(), "document_sign", &loc(), &caps_with_sign("K")).map_err(|_| ()).unwrap();
        let proof = entries(&entries(&signed)["proof"]);
        let vm = proof["verificationMethod"].to_string();
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let did = didkey::encode(KeyAlg::Ed25519, &pk).unwrap();
        assert_eq!(vm, format!("{}#{}", did, &did[8..]));
        assert!(verify_document(&signed, &text(&did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_some());
        // un documento ya firmado no se re-firma encima
        let signed = ok(sign_document(&doc(), &secret("K", seed), &opts, "document_sign", &loc(), &caps_with_sign("K")));
        let e = err_of(sign_document(&signed, &secret("K", seed), &opts, "document_sign", &loc(), &caps_with_sign("K")));
        assert!(e.contains("already carries a `proof`"), "{}", e);
    }

    #[test]
    fn ecdsa_jcs_2019_with_a_p256_secret_and_a_did_key() {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let scalar: [u8; 32] = sk.to_bytes().into();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let pk = sk.public_key().to_encoded_point(true).as_bytes().to_vec();
        let did = didkey::encode(KeyAlg::P256, &pk).unwrap();
        let opts = entries(&map(vec![
            ("verification_method", text(&did)),
            ("cryptosuite", text(SUITE_ECDSA)),
            ("proof_purpose", text("authentication")),
        ]));
        let signed = ok(sign_document(&doc(), &secret("ATTESTED", scalar), &opts, "document_sign", &loc(), &caps_with_sign("ATTESTED")));
        let proof = entries(&entries(&signed)["proof"]);
        assert_eq!(proof["cryptosuite"].to_string(), "ecdsa-jcs-2019");
        let v = verify_document(&signed, &text(&did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().expect("verifica");
        assert_eq!(entries(&v)["proof_purpose"].to_string(), "authentication");
        // la clave ed25519 equivocada de suite → nothing (la suite la fija la clave)
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes().to_vec();
        let ed_did = didkey::encode(KeyAlg::Ed25519, &ed).unwrap();
        assert!(verify_document(&signed, &text(&ed_did), &IndexMap::new(), "document_verify").map_err(|_| ()).unwrap().is_none());
    }
}
