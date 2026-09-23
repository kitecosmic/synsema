//! `receipt(opts?)` (T4 del spec de identidad): el recibo de la unidad de trabajo en curso,
//! **derivado, no redactado**. Un agente no puede darle forma, igual que no puede darle forma
//! a `/openapi.json`: lo que sale es lo que el motor registró — el sujeto en cuyo nombre
//! corrió, los tokens bajo los que corrió, cada capability pedida/concedida/denegada (el
//! audit del `CapabilitySet` de la unidad), el gasto contabilizado a esa identidad, los
//! `declassify` ejecutados, los pasos, la medida del programa y el motor. Con `opts.sign`
//! sale firmado como prueba **W3C Data Integrity** (`document_sign`), con forma de
//! **Verifiable Credential**: cualquier verificador de credenciales lo valida sin saber qué es
//! Synsema, y ERC-8004 lo apunta como evidencia. Sin firma, es el mismo documento sin `proof`
//! ni `issuer` (nadie responde por él).
//!
//! Qué deriva el motor y qué NO puede derivar (auditoría T1–T4, ronda 1):
//! - `issuer` = el `did:key` de la clave que firma. Siempre. No es una opción: un recibo
//!   emitido "a nombre de otro" es exactamente lo que un verificador de VC rechaza, y
//!   `receipt_verify` exige que `issuer` y `proof.verificationMethod` sean de la clave con
//!   la que verifica.
//! - `validFrom` (y el `created` de la prueba) = el reloj del motor al emitir, si la unidad
//!   tiene `time`; sin reloj (`--deterministic`, un token con ese caveat) se OMITEN, no se
//!   inventan ni se aceptan de la mano del programa (antedatar era trivial).
//! - `declared_result_sha256`: el hash del valor que el programa PASA como `result`. El motor
//!   no puede saber cuál es "el resultado" antes del `give`, así que el nombre dice lo que es:
//!   una declaración del programa, no una medida del motor.
//!
//! Lo que un recibo NO puede prometer, dicho en voz alta: completitud. Un agente sólo enseña
//! los recibos buenos y ninguna criptografía arregla eso (spec §4.2); lo que sí se promete es
//! que cada recibo es verdad y verificable. El audit que lleva es la FOTO al momento de
//! emitirlo: la propia firma del recibo (su `sign`) llega después y no puede cubrirse a sí
//! misma.
//!
//! `receipt_verify(receipt, public_key, opts?)` = `document_verify` + "es un recibo" (el
//! `type` lleva `SynsemaReceipt`) + "lo emitió esta clave" (`issuer` y `verificationMethod`
//! son el did:key de `public_key`).

use std::cell::RefCell;
use std::rc::Rc;

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use synsema_capabilities::model::{AuditEntry, Capability, CapabilitySet, CapabilityType, DelegationSource};
use synsema_core::bytesutil::hex_encode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue};

use crate::canonical::canonical_json;
use crate::integrity::{did_key_of_public_key, sign_document_with, signer_from, validate_suite_opt, verify_document};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

pub const RECEIPT_TYPE: &str = "SynsemaReceipt";
const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

fn audit_to_syn(e: &AuditEntry) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("capability".to_string(), syn_text(e.capability.clone()));
    m.insert("granted".to_string(), SynValue::Bool(e.granted));
    m.insert("source".to_string(), syn_text(e.source.clone()));
    m.insert("reason".to_string(), syn_text(e.reason.clone()));
    m.insert("origin".to_string(), syn_text(e.origin.clone()));
    syn_map(m)
}

fn label_to_syn(l: &[Rc<str>]) -> SynValue {
    syn_list(l.iter().map(|p| syn_text(p.to_string())).collect())
}

/// `YYYY-MM-DDTHH:MM:SSZ` de un instante unix (calendario proléptico gregoriano; el
/// algoritmo civil-from-days de Hinnant). Sin dependencia nueva.
fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

/// El instante de emisión, si la unidad tiene reloj (`time`): un chequeo AUDITADO (leer el
/// reloj es leer el reloj). Sin `time` → `None` (se omite, no se inventa).
fn issued_at(caps: &Rc<RefCell<CapabilitySet>>) -> Option<String> {
    let has_time = caps.borrow_mut().check_cause(&Capability::new(CapabilityType::Time, None), "receipt").is_ok();
    if has_time {
        Some(rfc3339_utc(synsema_core::clock::now_secs()))
    } else {
        None
    }
}

/// El recibo (sin firmar) de la unidad de trabajo que corre en `interp` con `caps`.
/// `issuer` es el did:key de la clave que firmará (o `None` si no se firma); `valid_from`
/// el instante del motor (o `None` sin reloj).
pub fn build_receipt(
    interp: &Interpreter,
    caps: &Rc<RefCell<CapabilitySet>>,
    issuer: Option<&str>,
    valid_from: Option<&str>,
    result: Option<&SynValue>,
) -> Result<SynValue, Control> {
    let mut subject = IndexMap::new();
    let identity = interp.request_identity().map(str::to_string).or_else(|| interp.current_agent().map(str::to_string));
    subject.insert("id".to_string(), identity.clone().map(syn_text).unwrap_or_else(syn_nothing));
    let (tokens, audit): (Vec<SynValue>, Vec<SynValue>) = {
        let cs = caps.borrow();
        let tokens = cs
            .delegated
            .iter()
            .filter_map(|d| match &d.source {
                DelegationSource::Token(id) => Some(syn_text(id.clone())),
                DelegationSource::Block => None,
            })
            .collect();
        let audit = cs.audit_log.iter().map(|e| audit_to_syn(&AuditEntry::from(e))).collect();
        (tokens, audit)
    };
    subject.insert("tokens".to_string(), syn_list(tokens));
    subject.insert("capabilities".to_string(), syn_list(audit));
    // El gasto imputado a esta identidad: los acumulados del proceso por unidad (el ledger
    // mide por identidad, no por unidad de trabajo — el nombre lo dice).
    let spend: Vec<SynValue> = match &identity {
        Some(id) => crate::spend::identity_spend_snapshot(id)
            .into_iter()
            .map(|(unit, total)| {
                let mut m = IndexMap::new();
                m.insert("unit".to_string(), syn_text(unit));
                m.insert("total".to_string(), syn_text(total));
                syn_map(m)
            })
            .collect(),
        None => Vec::new(),
    };
    subject.insert("identity_spend_totals".to_string(), syn_list(spend));
    let declassified: Vec<SynValue> = interp
        .declassify_log()
        .iter()
        .map(|d| {
            let mut m = IndexMap::new();
            m.insert("reason".to_string(), syn_text(d.reason.clone()));
            m.insert("from".to_string(), label_to_syn(&d.from));
            m.insert("to".to_string(), label_to_syn(&d.to));
            m.insert("line".to_string(), syn_int(d.loc.line as i64));
            syn_map(m)
        })
        .collect();
    subject.insert("declassified".to_string(), syn_list(declassified));
    subject.insert("steps".to_string(), syn_int(interp.steps() as i64));
    subject.insert(
        "program_sha".to_string(),
        crate::attest::current_program_sha().map(|s| syn_text(hex_encode(&s))).unwrap_or_else(syn_nothing),
    );
    subject.insert("engine".to_string(), syn_text(crate::attest::engine_version()));
    if let Some(v) = result {
        if !matches!(v, SynValue::Nothing) {
            subject.insert(
                "declared_result_sha256".to_string(),
                syn_text(hex_encode(&Sha256::digest(canonical_json(v)?.as_bytes()))),
            );
        }
    }

    let mut doc = IndexMap::new();
    doc.insert("@context".to_string(), syn_list(vec![syn_text(VC_CONTEXT)]));
    doc.insert(
        "type".to_string(),
        syn_list(vec![syn_text("VerifiableCredential"), syn_text(RECEIPT_TYPE)]),
    );
    if let Some(i) = issuer {
        doc.insert("issuer".to_string(), syn_text(i));
    }
    if let Some(c) = valid_from {
        doc.insert("validFrom".to_string(), syn_text(c));
    }
    doc.insert("credentialSubject".to_string(), syn_map(subject));
    Ok(syn_map(doc))
}

fn b_receipt(
    i: &Interpreter,
    args: &[SynValue],
    loc: &synsema_core::tokens::SourceLocation,
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "receipt";
    if args.len() > 1 {
        return Err(err(format!("{}(opts?) takes at most 1 argument", F)));
    }
    let opts = match args.first() {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name()))),
    };
    for k in opts.keys() {
        match k.as_str() {
            "sign" | "verification_method" | "cryptosuite" | "challenge" | "domain" | "result" => {}
            "issuer" => {
                return Err(err(format!(
                    "{}: `issuer` is not an option — it is derived: the did:key of the key that signs (a receipt issued in someone else's name is what a verifier rejects)",
                    F
                )))
            }
            "created" => {
                return Err(err(format!(
                    "{}: `created` is not an option — the receipt is dated by the engine's clock when the unit has `time` (and undated without it); a program cannot antedate it",
                    F
                )))
            }
            _ => {
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: sign, verification_method, cryptosuite, challenge, domain, result)",
                    F, k
                )))
            }
        }
    }
    let valid_from = issued_at(caps);
    match opts.get("sign") {
        None | Some(SynValue::Nothing) => build_receipt(i, caps, None, valid_from.as_deref(), opts.get("result")),
        Some(key) => {
            // El firmante primero (puerta `sign` + audit): su did:key es el issuer.
            let suite = validate_suite_opt(&opts, F)?;
            let signer = signer_from(key, suite.as_deref(), F, loc, caps)?;
            let issuer = signer.did_key().map_err(|e| err(format!("{}: {}", F, e)))?;
            let doc = build_receipt(i, caps, Some(&issuer), valid_from.as_deref(), opts.get("result"))?;
            let mut sopts = IndexMap::new();
            for k in ["verification_method", "cryptosuite", "challenge", "domain"] {
                if let Some(v) = opts.get(k) {
                    sopts.insert(k.to_string(), v.clone());
                }
            }
            if let Some(c) = &valid_from {
                sopts.insert("created".to_string(), syn_text(c.clone()));
            }
            sign_document_with(&doc, &signer, &sopts, F)
        }
    }
}

fn b_receipt_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "receipt_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(receipt, public_key, opts?) takes 2 or 3 arguments", F)));
    }
    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name()))),
    };
    let (is_receipt, issuer) = match &args[0] {
        SynValue::Map(m) => {
            let m = m.borrow();
            let is_receipt = match m.get("type") {
                Some(SynValue::List(l)) => l.borrow().iter().any(|t| t.to_string() == RECEIPT_TYPE),
                _ => false,
            };
            let issuer = match m.get("issuer") {
                Some(SynValue::Text(s)) => Some(s.to_string()),
                _ => None,
            };
            (is_receipt, issuer)
        }
        other => return Err(err(format!("{}: receipt must be a map, got {}", F, other.type_name()))),
    };
    if !is_receipt {
        return Ok(syn_nothing());
    }
    // La clave que verifica ES el emisor: `issuer` y `proof.verificationMethod` tienen que ser
    // su did:key. Un recibo firmado con otra clave "a nombre de" este did es nothing.
    let did = did_key_of_public_key(&args[1], F)?;
    if issuer.as_deref() != Some(did.as_str()) {
        return Ok(syn_nothing());
    }
    let Some(v) = verify_document(&args[0], &args[1], &opts, F)? else {
        return Ok(syn_nothing());
    };
    let vm_ok = match &v {
        SynValue::Map(m) => match m.borrow().get("verification_method") {
            Some(SynValue::Text(s)) => s.as_ref() == did.as_str() || s.starts_with(&format!("{}#", did)),
            _ => false,
        },
        _ => false,
    };
    if !vm_ok {
        return Ok(syn_nothing());
    }
    Ok(v)
}

/// Registra `receipt` (firma con gate `sign` cuando `opts.sign` es un secret) y
/// `receipt_verify` (puro).
pub fn register_receipt_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    interp.register_builtin("receipt", -1, Rc::new(move |i, a, l| b_receipt(i, a, l, &caps)));
    interp.register_builtin("receipt_verify", -1, Rc::new(|_i, a, _l| b_receipt_verify(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_utc_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_750_000_000), "2025-06-15T15:06:40Z");
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
    }
}
