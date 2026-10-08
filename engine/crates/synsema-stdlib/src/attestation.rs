//! T3.1 — `attestation_verify(doc: bytes, opts: map) → map`: verificar un documento de attestation
//! de hardware y devolver una forma **normalizada** para que el cliente no dependa de la plataforma.
//!
//! Puro: sin `require`, sin reloj (`opts.now` es OBLIGATORIO: dentro de un enclave no hay reloj
//! confiable y el veredicto tiene que ser reproducible), sin red. Compila al perfil wasm.
//!
//! ## Formatos
//!
//! - `"nitro"` — AWS Nitro Enclaves (y quien lo reutiliza: Marlin Oyster, Vela). El documento es un
//!   `COSE_Sign1` (con o sin tag 18) con `alg` ES384 en el header protegido; el payload es el mapa
//!   CBOR del NSM: `module_id`, `digest`, `timestamp` (ms), `pcrs`, `certificate` (hoja DER),
//!   `cabundle` (raíz primero, luego intermedios), `public_key`/`user_data`/`nonce` (bytes o null).
//!   Se verifica, en este orden y fallando cerrado ante la primera duda: estructura y tipos exactos
//!   del payload; que la raíz del `cabundle` sea **por SHA-256 del DER** la raíz pineada de la AWS
//!   Nitro Attestation PKI (embebida abajo); la cadena X.509 completa (cada firma es
//!   ecdsa-with-SHA384 sobre P-384, `issuer` = `subject` del emisor byte a byte, `BasicConstraints`
//!   CA en los no-hoja si está presente, validez `not_before ≤ now ≤ not_after` en TODOS los
//!   certificados); y por último la firma COSE ES384 con la clave de la hoja.
//! - `"mock"` — el mismo formato que `nitro` pero EXIGE `opts.root`: es lo que produce el driver
//!   `mock` de `attest` (cadena P-384 generada) y lo que corre en CI. Sin raíz explícita no hay
//!   nada en qué confiar y se rechaza.
//! - `"nitro-tpm"` — EC2 instance attestation (NitroTPM dentro de una VM). El MISMO `COSE_Sign1`
//!   ES384 bajo la MISMA raíz pineada de AWS, con dos diferencias que el formato fija: el payload
//!   es un mapa CBOR de longitud indefinida y las medidas vienen en `nitrotpm_pcrs` (índices
//!   0..=23, SHA-384). Es un formato DISTINTO de `nitro` a propósito: un documento de una VM nunca
//!   sale etiquetado como enclave (`nitro` rechaza `nitrotpm_pcrs` y `nitro-tpm` rechaza `pcrs`).
//! - `"sev-snp"` — el reporte de AMD SEV-SNP con su cadena VEK ← ASK/ASVK ← ARK; ver
//!   [`crate::attestation_snp`]. Toma `opts.aux` (la tabla de certificados del host) u `opts.vek`.
//! - `"tdx"`, `"sgx"` — NO los verifica esta release; devuelven un error explícito.
//!   Qué haría falta: el quote DCAP v4 (ECDSA P-256 del QE sobre el report, firma del
//!   attestation key por la PCK cert) más el colateral (cadena PCK ← Intel SGX Root CA pineada,
//!   `tcb_info` y `qe_identity` firmados, con su propia validez) para poblar `tcb` y decidir
//!   `UpToDate`/`SWHardeningNeeded`/…. El sabor "token de
//!   plataforma" (Confidential Space, Azure MAA) lo cubre `jwt_verify` con claves inline (T3.2).
//!
//! ## Salida
//!
//! `{format, measurements: {"pcr0": hex, …}, report_data: bytes, user_data: bytes|nothing,
//! public_key: bytes|nothing, nonce: bytes|nothing, timestamp: int (segundos), module_id: text,
//! digest: text, chain: [{subject, not_before, not_after}] (hoja primero), tcb: nothing}`.
//! Con `opts.expect = {"measurements": {"pcr0": hex, …}}` compara (case-insensitive) y lanza
//! `measurement pcrN mismatch` sin volcar los valores enteros (8 hex de cada lado alcanzan).
//! `opts.expect.report_data` (bytes o hex) compara contra `report_data` completo; en los formatos
//! de ancho fijo (`sev-snp`: 64) un valor más corto se rellena con ceros a la derecha; en los de
//! ancho variable (`nitro`, `nitro-tpm`, `mock`: el `user_data` tal cual) la igualdad es exacta.
//!
//! ## Raíz pineada (procedencia)
//!
//! `fixtures/attestation/aws_nitro_root_g1.der` es el `root.pem` (convertido a DER) de
//! `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`, descargado el
//! 2026-09-18. SHA-256 del zip: `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`
//! (el valor que AWS documenta en "Verifying the root of trust"). SHA-256 del DER:
//! [`AWS_NITRO_ROOT_SHA256`] (un test lo recomputa). `opts.root` (DER en bytes o PEM en texto) sólo
//! se acepta con `format: "mock"`; con `nitro` es error: la pineada es la única confiable.
//!
//! Vectores reales: dos documentos de `marlinprotocol/NitroProver` (`test/nitro-attestation/`;
//! el fork `HorizenOfficial/NitroProver` trae los mismos bytes), embebidos como golden. Están
//! expirados, así que los tests fijan `now` dentro de la ventana de la hoja.

use synsema_core::types::SynMap;
use std::rc::Rc;

use p384::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_SIG_ECDSA_WITH_SHA384};
use x509_parser::prelude::*;

use synsema_core::bytesutil::hex_encode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_bytes, syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue};

use crate::cbor::{Cbor, CoseSign1, COSE_ALG_ES384};
use crate::webauth::{pem_decode, DerReader};

const F: &str = "attestation_verify";
const SUPPORTED_FORMATS: &str = "nitro, nitro-tpm, sev-snp, mock";

/// La raíz de la AWS Nitro Attestation PKI (G1), DER. Ver la procedencia en el doc del módulo.
pub const AWS_NITRO_ROOT_G1_DER: &[u8] = include_bytes!("fixtures/attestation/aws_nitro_root_g1.der");
/// SHA-256 (hex) de [`AWS_NITRO_ROOT_G1_DER`]. Es el fingerprint que publican todos los
/// verificadores de Nitro; un test lo recomputa desde los bytes embebidos.
pub const AWS_NITRO_ROOT_SHA256: &str = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(format!("{}: {}", F, msg.into())))
}

// =========================================================
// Opciones
// =========================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Nitro,
    NitroTpm,
    Mock,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Nitro => "nitro",
            Format::NitroTpm => "nitro-tpm",
            Format::Mock => "mock",
        }
    }
}

struct Opts {
    format: String,
    now: i64,
    /// DER de la raíz que reemplaza a la pineada (tests / `mock`).
    root: Option<Vec<u8>>,
    /// `expect.measurements`, claves en minúsculas, valores hex en minúsculas.
    expect_measurements: Vec<(String, String)>,
    /// `expect.report_data` (T6).
    expect_report_data: Option<Vec<u8>>,
    /// `sev-snp`: el `auxblob` de configfs-tsm (tabla de certificados del host).
    aux: Option<Vec<u8>>,
    /// `sev-snp`: la VCEK/VLEK en DER (si vino en PEM, ya decodificada).
    vek: Option<Vec<u8>>,
}

/// Bytes o hex (con o sin `0x`) → bytes.
fn bytes_or_hex(v: &SynValue, field: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Bytes(b) => Ok(b.to_vec()),
        SynValue::Text(s) => {
            let h = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            synsema_core::bytesutil::hex_decode(h).map_err(|_| err(format!("{} must be bytes or hex text (it is not hex)", field)))
        }
        other => Err(err(format!("{} must be bytes or hex text, got {}", field, other.type_name()))),
    }
}

fn parse_opts(v: Option<&SynValue>) -> Result<Opts, Control> {
    let opts = match v {
        Some(SynValue::Map(m)) => m.borrow().to_map(),
        None | Some(SynValue::Nothing) => return Err(err("opts is required ({\"format\": ..., \"now\": ...})")),
        Some(other) => return Err(err(format!("opts must be a map, got {}", other.type_name()))),
    };
    let mut format: Option<String> = None;
    let mut now: Option<i64> = None;
    let mut root: Option<Vec<u8>> = None;
    let mut expect_measurements: Vec<(String, String)> = Vec::new();
    let mut expect_report_data: Option<Vec<u8>> = None;
    let mut aux: Option<Vec<u8>> = None;
    let mut vek: Option<Vec<u8>> = None;
    for (k, v) in &opts {
        match k.as_str() {
            "format" => {
                format = Some(match v {
                    SynValue::Text(s) => s.to_string(),
                    other => return Err(err(format!("opts.format must be text, got {}", other.type_name()))),
                })
            }
            "now" => {
                now = Some(match v {
                    SynValue::Number(n) if n.is_integer() => match n.to_i64_trunc() {
                        Some(i) if i >= 0 => i,
                        _ => return Err(err(format!("opts.now must be a unix timestamp in seconds (integer >= 0), got {}", v))),
                    },
                    other => return Err(err(format!("opts.now must be an integer (unix seconds), got {}", other.type_name()))),
                })
            }
            "root" => {
                root = Some(match v {
                    SynValue::Bytes(b) => b.to_vec(),
                    SynValue::Text(pem) => {
                        let (label, der) = pem_decode(pem).map_err(|e| err(format!("opts.root: {}", e)))?;
                        if label != "CERTIFICATE" {
                            return Err(err(format!("opts.root: expected a CERTIFICATE PEM, got {:?}", label)));
                        }
                        der
                    }
                    other => return Err(err(format!("opts.root must be the root certificate as DER bytes or PEM text, got {}", other.type_name()))),
                })
            }
            "expect" => {
                let m = match v {
                    SynValue::Map(m) => m.borrow().to_map(),
                    other => return Err(err(format!("opts.expect must be a map, got {}", other.type_name()))),
                };
                for (ek, ev) in &m {
                    match ek.as_str() {
                        "measurements" => {
                            let mm = match ev {
                                SynValue::Map(mm) => mm.borrow().to_map(),
                                other => return Err(err(format!("opts.expect.measurements must be a map of name → hex, got {}", other.type_name()))),
                            };
                            for (name, val) in &mm {
                                let hex = match val {
                                    SynValue::Text(s) => s.to_string(),
                                    SynValue::Bytes(b) => hex_encode(b),
                                    other => {
                                        return Err(err(format!(
                                            "opts.expect.measurements.{} must be hex text or bytes, got {}",
                                            name,
                                            other.type_name()
                                        )))
                                    }
                                };
                                let hex = hex.trim().trim_start_matches("0x").trim_start_matches("0X").to_ascii_lowercase();
                                if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                                    return Err(err(format!("opts.expect.measurements.{} is not hex", name)));
                                }
                                expect_measurements.push((name.to_ascii_lowercase(), hex));
                            }
                        }
                        "report_data" => {
                            let b = bytes_or_hex(ev, "opts.expect.report_data")?;
                            if b.is_empty() {
                                return Err(err("opts.expect.report_data is empty"));
                            }
                            expect_report_data = Some(b);
                        }
                        other => return Err(err(format!("opts.expect: unknown key {:?} (valid keys: measurements, report_data)", other))),
                    }
                }
            }
            "aux" => {
                aux = Some(match v {
                    SynValue::Bytes(b) => b.to_vec(),
                    other => return Err(err(format!("opts.aux must be bytes (the auxblob of the report), got {}", other.type_name()))),
                })
            }
            "vek" => {
                vek = Some(match v {
                    SynValue::Bytes(b) => b.to_vec(),
                    SynValue::Text(pem) => {
                        let (label, der) = pem_decode(pem).map_err(|e| err(format!("opts.vek: {}", e)))?;
                        if label != "CERTIFICATE" {
                            return Err(err(format!("opts.vek: expected a CERTIFICATE PEM, got {:?}", label)));
                        }
                        der
                    }
                    other => return Err(err(format!("opts.vek must be the VCEK/VLEK certificate as DER bytes or PEM text, got {}", other.type_name()))),
                })
            }
            other => return Err(err(format!("unknown option {:?} (valid options: format, now, root, expect, aux, vek)", other))),
        }
    }
    let format = format.ok_or_else(|| err(format!("opts.format is required (supported: {})", SUPPORTED_FORMATS)))?;
    let now = now.ok_or_else(|| {
        err("opts.now is required (unix seconds): an enclave has no trusted clock and the verdict must be reproducible, so the verifier never reads the wall clock")
    })?;
    if format != "sev-snp" {
        for (given, name) in [(aux.is_some(), "aux"), (vek.is_some(), "vek")] {
            if given {
                return Err(err(format!("opts.{} is only accepted with format \"sev-snp\"", name)));
            }
        }
    }
    Ok(Opts { format, now, root, expect_measurements, expect_report_data, aux, vek })
}

/// T6: `expect.report_data` contra `report_data`. `width` = ancho fijo del formato (el valor
/// esperado más corto se rellena con ceros a la derecha); `None` = ancho variable, igualdad exacta.
/// El error dice cuántos bytes coinciden, nunca los valores.
fn check_report_data(got: &[u8], want: &Option<Vec<u8>>, width: Option<usize>) -> Result<(), Control> {
    let Some(want) = want else { return Ok(()) };
    let mut want = want.clone();
    if let Some(w) = width {
        if want.len() > w {
            return Err(err(format!("opts.expect.report_data has {} bytes, more than the {} of the format", want.len(), w)));
        }
        want.resize(w, 0);
    }
    if want != got {
        let same = want.iter().zip(got).take_while(|(a, b)| a == b).count();
        return Err(err(format!(
            "report_data mismatch (the first {} of {} bytes match; expected {} bytes)",
            same,
            got.len(),
            want.len()
        )));
    }
    Ok(())
}

// =========================================================
// Payload del NSM
// =========================================================

struct NitroPayload {
    module_id: String,
    digest: String,
    timestamp_ms: i128,
    /// `(índice, valor)` en el orden del documento; índices únicos en `0..=31`.
    pcrs: Vec<(u8, Vec<u8>)>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

const PAYLOAD_KEYS: &[&str] = &["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"];
/// EC2 instance attestation: las mismas claves con `nitrotpm_pcrs` en lugar de `pcrs`.
const PAYLOAD_KEYS_TPM: &[&str] = &["module_id", "digest", "timestamp", "nitrotpm_pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"];

fn opt_bytes(m: &Cbor, key: &str) -> Result<Option<Vec<u8>>, String> {
    match m.get(key) {
        None | Some(Cbor::Null) => Ok(None),
        Some(Cbor::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(format!("payload.{} must be bytes or null", key)),
    }
}

/// Estructura y tipos EXACTOS del payload del NSM. Cualquier desvío es error (fail closed).
///
/// `format` decide el juego de claves: `nitro`/`mock` llevan `pcrs` (y la codificación definida
/// que produce NSM); `nitro-tpm` lleva `nitrotpm_pcrs` (0..=23, SHA-384). Las claves se miran
/// ANTES que la codificación, así un documento de NitroTPM pasado como `nitro` se rechaza por la
/// clave que lo delata.
fn parse_payload(bytes: &[u8], format: Format) -> Result<NitroPayload, String> {
    let (item, indefinite) = crate::cbor::decode_allow_indefinite(bytes).map_err(|e| format!("payload is not valid CBOR: {}", e))?;
    let pairs = item.as_map().ok_or("payload must be a CBOR map")?;
    let (keys, pcrs_key) = match format {
        Format::NitroTpm => (PAYLOAD_KEYS_TPM, "nitrotpm_pcrs"),
        Format::Nitro | Format::Mock => (PAYLOAD_KEYS, "pcrs"),
    };
    let mut seen: Vec<&str> = Vec::new();
    for (k, _) in pairs {
        let k = k.as_text().ok_or("payload keys must be text")?;
        let known = match keys.iter().find(|x| **x == k) {
            Some(x) => x,
            None if k == "nitrotpm_pcrs" => {
                return Err(format!("payload has the key \"nitrotpm_pcrs\": this is an EC2 instance (NitroTPM) document, verify it with format \"nitro-tpm\", not {:?}", format.name()))
            }
            None if k == "pcrs" && format == Format::NitroTpm => {
                return Err("payload has the key \"pcrs\": this is a Nitro Enclaves document, verify it with format \"nitro\", not \"nitro-tpm\"".to_string())
            }
            None => return Err(format!("payload has an unknown key {:?}", k)),
        };
        if seen.contains(known) {
            return Err(format!("payload has a duplicate key {:?}", k));
        }
        seen.push(*known);
    }
    for required in ["module_id", "digest", "timestamp", pcrs_key, "certificate", "cabundle"] {
        if !seen.contains(&required) {
            return Err(format!("payload is missing {:?}", required));
        }
    }
    // NSM (enclave) codifica todo con longitud definida; sólo EC2 instance attestation usa el
    // mapa indefinido. Un `nitro` indefinido no es lo que firma un enclave: se rechaza.
    if indefinite && format != Format::NitroTpm {
        return Err(format!("payload uses indefinite-length CBOR, which Nitro Enclaves documents never do (format {:?})", format.name()));
    }
    let module_id = item.get("module_id").and_then(Cbor::as_text).ok_or("payload.module_id must be text")?.to_string();
    if module_id.is_empty() {
        return Err("payload.module_id is empty".to_string());
    }
    let digest = item.get("digest").and_then(Cbor::as_text).ok_or("payload.digest must be text")?.to_string();
    let pcr_len = match digest.as_str() {
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        other => return Err(format!("payload.digest {:?} is not SHA256/SHA384/SHA512", other)),
    };
    // NitroTPM mide con SHA-384 y tiene 24 PCRs (0..=23); un enclave hasta 32.
    let max_pcr = if format == Format::NitroTpm {
        if digest != "SHA384" {
            return Err(format!("payload.digest {:?} is not SHA384 (NitroTPM PCRs are SHA-384)", digest));
        }
        23
    } else {
        31
    };
    let timestamp_ms = item.get("timestamp").and_then(Cbor::as_int).ok_or("payload.timestamp must be an integer (ms)")?;
    if timestamp_ms <= 0 {
        return Err("payload.timestamp must be positive".to_string());
    }
    let pcr_pairs = item.get(pcrs_key).and_then(Cbor::as_map).ok_or_else(|| format!("payload.{} must be a map", pcrs_key))?;
    if pcr_pairs.is_empty() {
        return Err(format!("payload.{} is empty", pcrs_key));
    }
    let mut pcrs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(pcr_pairs.len());
    for (k, v) in pcr_pairs {
        let idx = k.as_int().ok_or_else(|| format!("payload.{} keys must be integers", pcrs_key))?;
        if !(0..=max_pcr).contains(&idx) {
            return Err(format!("payload.{} index {} is out of range (0..={})", pcrs_key, idx, max_pcr));
        }
        let idx = idx as u8;
        if pcrs.iter().any(|(i, _)| *i == idx) {
            return Err(format!("payload.{} has a duplicate index {}", pcrs_key, idx));
        }
        let val = v.as_bytes().ok_or_else(|| format!("payload.{}[{}] must be bytes", pcrs_key, idx))?;
        if val.len() != pcr_len {
            return Err(format!("payload.{}[{}] has {} bytes, expected {} for {}", pcrs_key, idx, val.len(), pcr_len, digest));
        }
        pcrs.push((idx, val.to_vec()));
    }
    let certificate = item.get("certificate").and_then(Cbor::as_bytes).ok_or("payload.certificate must be bytes")?.to_vec();
    if certificate.is_empty() {
        return Err("payload.certificate is empty".to_string());
    }
    let cabundle_items = item.get("cabundle").and_then(Cbor::as_array).ok_or("payload.cabundle must be an array")?;
    if cabundle_items.is_empty() {
        return Err("payload.cabundle is empty (it must start with the root)".to_string());
    }
    let mut cabundle = Vec::with_capacity(cabundle_items.len());
    for (i, c) in cabundle_items.iter().enumerate() {
        let der = c.as_bytes().ok_or_else(|| format!("payload.cabundle[{}] must be bytes", i))?;
        if der.is_empty() {
            return Err(format!("payload.cabundle[{}] is empty", i));
        }
        cabundle.push(der.to_vec());
    }
    Ok(NitroPayload {
        module_id,
        digest,
        timestamp_ms,
        pcrs,
        certificate,
        cabundle,
        public_key: opt_bytes(&item, "public_key")?,
        user_data: opt_bytes(&item, "user_data")?,
        nonce: opt_bytes(&item, "nonce")?,
    })
}

// =========================================================
// X.509 (P-384 / ecdsa-with-SHA384)
// =========================================================

/// Un eslabón de la cadena en la salida normalizada.
pub(crate) struct ChainEntry {
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
}

pub(crate) fn parse_cert<'a>(der: &'a [u8], what: &str) -> Result<X509Certificate<'a>, String> {
    let (rem, cert) = X509Certificate::from_der(der).map_err(|e| format!("{} is not a valid X.509 certificate: {}", what, e))?;
    if !rem.is_empty() {
        return Err(format!("{} has {} trailing byte(s) after the certificate", what, rem.len()));
    }
    Ok(cert)
}

/// La clave P-384 del SPKI de un certificado (rechaza cualquier otro algoritmo/curva).
pub(crate) fn p384_key_of(cert: &X509Certificate<'_>, what: &str) -> Result<p384::ecdsa::VerifyingKey, String> {
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(format!("{} public key is not an EC key (only P-384 is accepted)", what));
    }
    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).ok_or_else(|| format!("{} EC public key has no named curve", what))?;
    if curve != OID_NIST_EC_P384 {
        return Err(format!("{} public key is not on P-384", what));
    }
    p384::ecdsa::VerifyingKey::from_sec1_bytes(spki.subject_public_key.data.as_ref()).map_err(|_| format!("{} P-384 public key is malformed", what))
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` → `r‖s` crudo de `2n` bytes.
fn ecdsa_sig_value_to_raw(der: &[u8], n: usize) -> Result<Vec<u8>, String> {
    let mut outer = DerReader::new(der);
    let (tag, seq) = outer.tlv()?;
    if tag != 0x30 || !outer.done() {
        return Err("signature is not a DER SEQUENCE".to_string());
    }
    let mut r = DerReader::new(seq);
    let (t1, rb) = r.tlv()?;
    let (t2, sb) = r.tlv()?;
    if t1 != 0x02 || t2 != 0x02 || !r.done() {
        return Err("signature is not SEQUENCE { INTEGER, INTEGER }".to_string());
    }
    let mut out = Vec::with_capacity(2 * n);
    for int in [rb, sb] {
        if int.is_empty() || int[0] & 0x80 != 0 {
            return Err("signature integer is empty or negative".to_string());
        }
        let v = match int.iter().position(|b| *b != 0) {
            Some(p) => &int[p..],
            None => &int[int.len() - 1..], // el cero
        };
        if v.len() > n {
            return Err(format!("signature integer has {} bytes, more than the {} of the curve", v.len(), n));
        }
        out.extend(std::iter::repeat(0u8).take(n - v.len()));
        out.extend_from_slice(v);
    }
    Ok(out)
}

/// `child` está firmado por `issuer`: algoritmo ecdsa-with-SHA384 (en ambos campos, RFC 5280
/// §4.1.1.2), `issuer` = `subject` del emisor byte a byte, firma P-384 sobre el TBS.
fn verify_issued_by(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>, what: &str) -> Result<(), String> {
    if child.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA384 || child.tbs_certificate.signature.algorithm != OID_SIG_ECDSA_WITH_SHA384 {
        return Err(format!("{} is not signed with ecdsa-with-SHA384", what));
    }
    if child.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(format!("{} issuer does not match the subject of its issuing certificate", what));
    }
    let vk = p384_key_of(issuer, &format!("the issuer of {}", what))?;
    let raw = ecdsa_sig_value_to_raw(child.signature_value.data.as_ref(), 48).map_err(|e| format!("{}: {}", what, e))?;
    let sig = p384::ecdsa::Signature::from_slice(&raw).map_err(|_| format!("{} signature is malformed", what))?;
    vk.verify(child.tbs_certificate.as_ref(), &sig).map_err(|_| format!("{} signature does not verify against its issuer", what))
}

pub(crate) fn check_validity(cert: &X509Certificate<'_>, now: i64, what: &str) -> Result<(), String> {
    let v = cert.validity();
    let (nb, na) = (v.not_before.timestamp(), v.not_after.timestamp());
    if now < nb || now > na {
        return Err(format!("{} is not valid at now={} (valid from {} to {})", what, now, nb, na));
    }
    Ok(())
}

/// `BasicConstraints` de un emisor: si está, tiene que decir CA y respetar `pathLenConstraint`
/// (`below` = cuántos CAs hay debajo de él en la cadena).
pub(crate) fn check_ca(cert: &X509Certificate<'_>, below: usize, what: &str) -> Result<(), String> {
    match cert.basic_constraints().map_err(|e| format!("{} has a malformed BasicConstraints extension: {}", what, e))? {
        Some(bc) => {
            if !bc.value.ca {
                return Err(format!("{} signs certificates but its BasicConstraints says CA:FALSE", what));
            }
            if let Some(max) = bc.value.path_len_constraint {
                if below as u64 > max as u64 {
                    return Err(format!("{} has pathLenConstraint {} but {} CA(s) hang below it", what, max, below));
                }
            }
            Ok(())
        }
        None => Ok(()),
    }
}

pub(crate) fn entry_of(cert: &X509Certificate<'_>) -> ChainEntry {
    let v = cert.validity();
    ChainEntry { subject: cert.subject().to_string(), not_before: v.not_before.timestamp(), not_after: v.not_after.timestamp() }
}

/// Verifica `leaf ← cabundle[n-1] ← … ← cabundle[0] (= raíz confiable)` y devuelve la clave de
/// la hoja más la cadena (hoja primero) para la salida.
fn verify_chain(leaf_der: &[u8], cabundle: &[Vec<u8>], trusted_root: &[u8], now: i64) -> Result<(p384::ecdsa::VerifyingKey, Vec<ChainEntry>), String> {
    let got = Sha256::digest(&cabundle[0]);
    let want = Sha256::digest(trusted_root);
    if got != want {
        return Err(format!(
            "the chain root is not the trusted root (sha256 {}… vs trusted {}…)",
            &hex_encode(&got)[..16],
            &hex_encode(&want)[..16]
        ));
    }
    let mut cas: Vec<X509Certificate<'_>> = Vec::with_capacity(cabundle.len());
    for (i, der) in cabundle.iter().enumerate() {
        cas.push(parse_cert(der, &format!("cabundle[{}]", i))?);
    }
    let leaf = parse_cert(leaf_der, "certificate")?;
    let n = cas.len();
    // Validez de TODOS, antes que nada: un cert vencido no firma nada aunque la firma cierre.
    check_validity(&leaf, now, "the leaf certificate")?;
    for (i, c) in cas.iter().enumerate() {
        check_validity(c, now, &format!("cabundle[{}]", i))?;
    }
    // La raíz se autofirma (la confianza viene del pin; la autofirma descarta un DER corrupto).
    verify_issued_by(&cas[0], &cas[0], "the root certificate")?;
    check_ca(&cas[0], n - 1, "the root certificate")?;
    for i in 1..n {
        verify_issued_by(&cas[i], &cas[i - 1], &format!("cabundle[{}]", i))?;
        check_ca(&cas[i], n - 1 - i, &format!("cabundle[{}]", i))?;
    }
    verify_issued_by(&leaf, &cas[n - 1], "the leaf certificate")?;
    let leaf_key = p384_key_of(&leaf, "the leaf certificate")?;
    let mut chain = Vec::with_capacity(n + 1);
    chain.push(entry_of(&leaf));
    for c in cas.iter().rev() {
        chain.push(entry_of(c));
    }
    Ok((leaf_key, chain))
}

// =========================================================
// nitro / nitro-tpm / mock
// =========================================================

fn chain_to_syn(chain: &[ChainEntry]) -> SynValue {
    syn_list(
        chain
            .iter()
            .map(|e| {
                let mut m = SynMap::new();
                m.insert("subject", syn_text(e.subject.as_str()));
                m.insert("not_before", syn_int(e.not_before));
                m.insert("not_after", syn_int(e.not_after));
                syn_map(m)
            })
            .collect(),
    )
}

/// `expect.measurements` contra las medidas normalizadas (hex en minúsculas).
fn check_measurements(measurements_hex: &[(String, String)], expect: &[(String, String)]) -> Result<(), Control> {
    for (name, want) in expect {
        match measurements_hex.iter().find(|(n, _)| n == name) {
            None => return Err(err(format!("measurement {} is not present in the document", name))),
            Some((_, got)) if got != want => {
                return Err(err(format!(
                    "measurement {} mismatch (expected {}…, got {}…)",
                    name,
                    &want[..want.len().min(8)],
                    &got[..got.len().min(8)]
                )))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn verify_nitro(doc: &[u8], opts: &Opts, format: Format) -> Result<SynValue, Control> {
    let cose = CoseSign1::parse(doc).map_err(|e| err(format!("doc is not a COSE_Sign1: {}", e)))?;
    let alg = cose.alg().map_err(err)?;
    if alg != COSE_ALG_ES384 {
        return Err(err(format!("COSE alg {} is not ES384 (-35); nitro documents are always ES384", alg)));
    }
    let payload_bytes = cose.payload.as_deref().ok_or_else(|| err("COSE_Sign1 payload is detached (nil); the document must embed it"))?;
    let payload = parse_payload(payload_bytes, format).map_err(err)?;
    let trusted_root: &[u8] = match &opts.root {
        Some(r) => r,
        None => AWS_NITRO_ROOT_G1_DER,
    };
    let (leaf_key, chain) = verify_chain(&payload.certificate, &payload.cabundle, trusted_root, opts.now).map_err(err)?;
    // La firma COSE, recién con una hoja que ya cerró contra la raíz.
    if cose.signature.len() != 96 {
        return Err(err(format!("COSE signature has {} bytes, ES384 needs 96 (r‖s)", cose.signature.len())));
    }
    let sig = p384::ecdsa::Signature::from_slice(&cose.signature).map_err(|_| err("COSE signature is malformed"))?;
    leaf_key.verify(&cose.sig_structure(), &sig).map_err(|_| err("COSE signature does not verify against the leaf certificate"))?;

    // Medidas normalizadas: "pcrN" → hex, por índice.
    let mut pcrs = payload.pcrs.clone();
    pcrs.sort_by_key(|(i, _)| *i);
    let mut measurements: SynMap = SynMap::new();
    let mut measurements_hex: Vec<(String, String)> = Vec::new();
    for (i, v) in &pcrs {
        let h = hex_encode(v);
        measurements.insert(format!("pcr{}", i), syn_text(h.as_str()));
        measurements_hex.push((format!("pcr{}", i), h));
    }
    check_measurements(&measurements_hex, &opts.expect_measurements)?;
    let report_data = payload.user_data.clone().unwrap_or_default();
    check_report_data(&report_data, &opts.expect_report_data, None)?;

    let opt_bytes_val = |v: &Option<Vec<u8>>| match v {
        Some(b) => syn_bytes(b.clone()),
        None => syn_nothing(),
    };
    let mut out: SynMap = SynMap::new();
    out.insert("format", syn_text(format.name()));
    out.insert("measurements", syn_map(measurements));
    out.insert("report_data", syn_bytes(report_data));
    out.insert("user_data", opt_bytes_val(&payload.user_data));
    out.insert("public_key", opt_bytes_val(&payload.public_key));
    out.insert("nonce", opt_bytes_val(&payload.nonce));
    out.insert("timestamp", syn_int((payload.timestamp_ms / 1000) as i64));
    out.insert("module_id", syn_text(payload.module_id.as_str()));
    out.insert("digest", syn_text(payload.digest.as_str()));
    out.insert("chain", chain_to_syn(&chain));
    out.insert("tcb", syn_nothing());
    Ok(syn_map(out))
}

// =========================================================
// sev-snp
// =========================================================

fn tcb_to_syn(t: &crate::attestation_snp::Tcb) -> SynValue {
    let mut m = SynMap::new();
    if let Some(fmc) = t.fmc {
        m.insert("fmc", syn_int(fmc as i64));
    }
    m.insert("boot_loader", syn_int(t.boot_loader as i64));
    m.insert("tee", syn_int(t.tee as i64));
    m.insert("snp", syn_int(t.snp as i64));
    m.insert("microcode", syn_int(t.microcode as i64));
    syn_map(m)
}

/// `GUEST_POLICY` (SEV-SNP ABI, tabla 9): los campos con nombre más el valor crudo.
fn policy_to_syn(p: u64) -> SynValue {
    let bit = |n: u32| syn_bool(p & (1u64 << n) != 0);
    let mut m = SynMap::new();
    m.insert("raw", syn_text(format!("{:016x}", p)));
    m.insert("abi_minor", syn_int((p & 0xff) as i64));
    m.insert("abi_major", syn_int(((p >> 8) & 0xff) as i64));
    m.insert("smt", bit(16));
    m.insert("migrate_ma", bit(18));
    m.insert("debug", bit(19));
    m.insert("single_socket", bit(20));
    m.insert("cxl_allow", bit(21));
    m.insert("mem_aes_256_xts", bit(22));
    m.insert("rapl_dis", bit(23));
    m.insert("ciphertext_hiding", bit(24));
    m.insert("page_swap_disable", bit(25));
    syn_map(m)
}

/// Verifica un reporte SEV-SNP con las raíces que da `roots` (la API pública: las pineadas).
fn verify_sev_snp_with(
    doc: &[u8],
    opts: &Opts,
    roots: &dyn Fn(crate::attestation_snp::Product) -> Result<crate::attestation_snp::ProductRoots<'static>, String>,
) -> Result<SynValue, Control> {
    let v = crate::attestation_snp::verify(doc, opts.aux.as_deref(), opts.vek.as_deref(), opts.now, roots).map_err(err)?;
    // 10. expect: sólo `measurement` y `host_data`.
    let measurements_hex = vec![("measurement".to_string(), hex_encode(&v.measurement)), ("host_data".to_string(), hex_encode(&v.host_data))];
    for (name, _) in &opts.expect_measurements {
        if !measurements_hex.iter().any(|(n, _)| n == name) {
            return Err(err(format!("opts.expect.measurements: unknown key {:?} for sev-snp (valid keys: measurement, host_data)", name)));
        }
    }
    check_measurements(&measurements_hex, &opts.expect_measurements)?;
    check_report_data(&v.report_data, &opts.expect_report_data, Some(64))?;

    let mut measurements = SynMap::new();
    for (n, h) in &measurements_hex {
        measurements.insert(n.clone(), syn_text(h.as_str()));
    }
    let mut tcb = SynMap::new();
    tcb.insert("product", syn_text(v.product.name()));
    tcb.insert("signing_key", syn_text(v.signing_key.name()));
    if let Some(csp) = &v.csp_id {
        tcb.insert("csp_id", syn_text(csp.as_str()));
    }
    tcb.insert("chip_id", syn_text(hex_encode(&v.chip_id)));
    tcb.insert("vmpl", syn_int(v.vmpl as i64));
    tcb.insert("reported", tcb_to_syn(&v.reported));
    tcb.insert("current", tcb_to_syn(&v.current));
    tcb.insert("committed", tcb_to_syn(&v.committed));
    tcb.insert("launch", tcb_to_syn(&v.launch));

    let mut out: SynMap = SynMap::new();
    out.insert("format", syn_text("sev-snp"));
    out.insert("measurements", syn_map(measurements));
    out.insert("report_data", syn_bytes(v.report_data.clone()));
    out.insert("user_data", syn_nothing());
    out.insert("public_key", syn_nothing());
    out.insert("nonce", syn_nothing());
    // SEV-SNP no trae hora: no se inventa.
    out.insert("timestamp", syn_nothing());
    out.insert("module_id", syn_nothing());
    out.insert("digest", syn_text("SHA384"));
    out.insert("chain", chain_to_syn(&v.chain));
    out.insert("tcb", syn_map(tcb));
    out.insert("policy", policy_to_syn(v.policy));
    out.insert("version", syn_int(v.version as i64));
    Ok(syn_map(out))
}

fn b_attestation_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.len() != 2 {
        return Err(err("(doc, opts) takes 2 arguments"));
    }
    let doc: &[u8] = match &args[0] {
        SynValue::Bytes(b) => b,
        other => return Err(err(format!("doc must be bytes (the raw document), got {}", other.type_name()))),
    };
    let opts = parse_opts(args.get(1))?;
    // L4: con un formato de plataforma la única raíz es la pineada. Aceptar `root` permitiría que
    // un documento de una PKI ajena saliera etiquetado como `nitro`, `nitro-tpm` o `sev-snp`.
    if opts.root.is_some() && matches!(opts.format.as_str(), "nitro" | "nitro-tpm" | "sev-snp") {
        return Err(err(format!(
            "opts.root is only accepted with format \"mock\" ({} trusts only its pinned roots; \
             use format \"mock\" to verify a chain of your own)",
            opts.format
        )));
    }
    match opts.format.as_str() {
        "nitro" => verify_nitro(doc, &opts, Format::Nitro),
        "nitro-tpm" => verify_nitro(doc, &opts, Format::NitroTpm),
        "sev-snp" => verify_sev_snp_with(doc, &opts, &crate::attestation_snp::pinned_roots),
        "mock" => {
            if opts.root.is_none() {
                return Err(err("format \"mock\" needs opts.root (the mock chain is not trusted by default)"));
            }
            verify_nitro(doc, &opts, Format::Mock)
        }
        f @ ("tdx" | "sgx") => Err(err(format!("format {:?} is not verified by this release (supported: {})", f, SUPPORTED_FORMATS))),
        other => Err(err(format!("unknown format {:?} (supported: {})", other, SUPPORTED_FORMATS))),
    }
}

/// `attestation_verify(doc, opts)` desde Rust (T9: el cliente atestado verifica cada documento
/// exactamente como lo haría un programa).
pub(crate) fn verify_value(args: &[SynValue]) -> Result<SynValue, Control> {
    b_attestation_verify(args)
}

/// Registra `attestation_verify`. Puro: sin `CapabilitySet`.
pub fn register_attestation_builtins(interp: &Interpreter) {
    interp.register_builtin("attestation_verify", 2, Rc::new(|_i, a, _l| b_attestation_verify(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::cose_protected_alg;
    use p384::ecdsa::signature::Signer as _;
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
    use synsema_core::bytesutil::hex_decode;

    /// `marlinprotocol/NitroProver` `test/nitro-attestation/sample_attestation.bin`
    /// (sha256 3a4a0301e6aa2839f9321c59995a37700cfa25552ba423ba91acf6f4b0dbee66; los mismos bytes en
    /// `HorizenOfficial/NitroProver`). Instancia ap-south-1, 2024-02-26.
    const REAL_1: &[u8] = include_bytes!("fixtures/attestation/nitro_marlin_sample_attestation.bin");
    /// `sample_attestation2.bin` (sha256 b723381a39ecd4d54a8d83621239ae7a8e78f419af33dc9ab27d9181de6c252e),
    /// otra instancia, 2024-04-03.
    const REAL_2: &[u8] = include_bytes!("fixtures/attestation/nitro_marlin_sample_attestation2.bin");

    fn ok(r: Result<SynValue, Control>) -> SynMap {
        match r {
            Ok(SynValue::Map(m)) => m.borrow().to_map(),
            Ok(other) => panic!("esperaba map, got {}", other),
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

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn text_of(v: &SynValue) -> String {
        match v {
            SynValue::Text(s) => s.to_string(),
            other => panic!("esperaba text, got {}", other),
        }
    }

    fn bytes_of(v: &SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b.to_vec(),
            other => panic!("esperaba bytes, got {}", other),
        }
    }

    fn int_of(v: &SynValue) -> i64 {
        match v {
            SynValue::Number(n) => n.to_i64_trunc().unwrap(),
            other => panic!("esperaba number, got {}", other),
        }
    }

    fn map_of(v: &SynValue) -> SynMap {
        match v {
            SynValue::Map(m) => m.borrow().to_map(),
            other => panic!("esperaba map, got {}", other),
        }
    }

    fn list_of(v: &SynValue) -> Vec<SynValue> {
        match v {
            SynValue::List(l) => l.borrow().to_vec(),
            other => panic!("esperaba list, got {}", other),
        }
    }

    fn verify(doc: &[u8], opts: Vec<(&str, SynValue)>) -> Result<SynValue, Control> {
        b_attestation_verify(&[syn_bytes(doc.to_vec()), map(opts)])
    }

    // ---------- raíz pineada ----------

    #[test]
    fn aws_root_pin_matches_the_documented_fingerprint() {
        assert_eq!(hex_encode(&Sha256::digest(AWS_NITRO_ROOT_G1_DER)), AWS_NITRO_ROOT_SHA256);
        assert_eq!(AWS_NITRO_ROOT_G1_DER.len(), 533);
        let root = parse_cert(AWS_NITRO_ROOT_G1_DER, "root").unwrap();
        assert!(root.subject().to_string().contains("CN=aws.nitro-enclaves"), "{}", root.subject());
        assert_eq!(root.validity().not_before.timestamp(), 1_572_269_285); // 2019-10-28T13:28:05Z
        assert_eq!(root.validity().not_after.timestamp(), 2_519_044_085); // 2049-10-28T14:28:05Z
        assert!(root.is_ca());
        // Autofirmada con ecdsa-with-SHA384 sobre P-384: exactamente lo que el verificador exige.
        verify_issued_by(&root, &root, "root").unwrap();
    }

    // ---------- vectores reales ----------

    const REAL_1_NOW: i64 = 1_708_930_921; // = timestamp del documento, dentro de la ventana de la hoja
    const REAL_1_LEAF_NB: i64 = 1_708_930_773; // 2024-02-26T06:59:33Z
    const REAL_1_LEAF_NA: i64 = 1_708_941_576; // 2024-02-26T09:59:36Z

    #[test]
    fn real_nitro_document_1_verifies_byte_for_byte() {
        let out = ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))]));
        assert_eq!(text_of(&out["format"]), "nitro");
        assert_eq!(text_of(&out["module_id"]), "i-0df237f0418feb41e-enc018d1c7ef94eb110");
        assert_eq!(text_of(&out["digest"]), "SHA384");
        assert_eq!(int_of(&out["timestamp"]), 1_708_930_921);
        let m = map_of(&out["measurements"]);
        assert_eq!(m.len(), 16);
        assert_eq!(m.keys().take(3).cloned().collect::<Vec<_>>(), vec!["pcr0", "pcr1", "pcr2"]);
        assert_eq!(text_of(&m["pcr0"]), "17bf8f048519797be90497001a7559a3d555395937117d76f8baaedf56ca6d97952de79479bc0c76e5d176d20f663790");
        assert_eq!(text_of(&m["pcr1"]), "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16");
        assert_eq!(text_of(&m["pcr2"]), "249037310daa90f4eb0703e7b105a241fdb09f12d3c40b7aea2f39e57b07b887e6ff4e4f9757943e127e391626b5e4d5");
        assert_eq!(text_of(&m["pcr3"]), "0".repeat(96));
        assert_eq!(text_of(&m["pcr4"]), "bed9c17c27bdec410da8cabfa9aeb868e557679c88f49f90f5b538460c5538c2c674049f1122951f46554bdf2fb0ce74");
        assert_eq!(text_of(&m["pcr15"]), "0".repeat(96));
        assert_eq!(hex_encode(&bytes_of(&out["public_key"])), "d239fd059dd0e0a01e280bec44903bb8143bae7e578b9844c6df5fd6351eddc0");
        assert_eq!(bytes_of(&out["user_data"]), br#"{"total_memory":2091298816,"total_cpus":1}"#.to_vec());
        assert_eq!(bytes_of(&out["report_data"]), bytes_of(&out["user_data"]));
        assert!(matches!(out["nonce"], SynValue::Nothing));
        assert!(matches!(out["tcb"], SynValue::Nothing));
        let chain = list_of(&out["chain"]);
        assert_eq!(chain.len(), 5, "hoja + 3 intermedios + raíz");
        let leaf = map_of(&chain[0]);
        assert!(text_of(&leaf["subject"]).contains("i-0df237f0418feb41e-enc018d1c7ef94eb110.ap-south-1.aws"), "{}", text_of(&leaf["subject"]));
        assert_eq!(int_of(&leaf["not_before"]), REAL_1_LEAF_NB);
        assert_eq!(int_of(&leaf["not_after"]), REAL_1_LEAF_NA);
        let root = map_of(&chain[4]);
        assert!(text_of(&root["subject"]).contains("aws.nitro-enclaves"));
        assert_eq!(int_of(&root["not_before"]), 1_572_269_285);
        // La misma salida con el documento envuelto en el tag 18 (forma COSE canónica).
        let tagged = CoseSign1::parse(REAL_1).unwrap().encode_tagged();
        assert_eq!(tagged[0], 0xd2);
        let out2 = ok(verify(&tagged, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))]));
        assert_eq!(text_of(&map_of(&out2["measurements"])["pcr0"]), text_of(&m["pcr0"]));
    }

    #[test]
    fn real_nitro_document_2_verifies() {
        let out = ok(verify(REAL_2, vec![("format", syn_text("nitro")), ("now", syn_int(1_712_149_702))]));
        assert_eq!(text_of(&out["module_id"]), "i-058bac400e426cc24-enc018e0924a1c4673e");
        assert_eq!(text_of(&map_of(&out["measurements"])["pcr0"]), "ea6ff0cc81650a6a2e5e6b009b058d684600ea08006beafb60a693e2eeb362e3a06039ff8341f0715543672c5c9ffa61");
        assert_eq!(hex_encode(&bytes_of(&out["public_key"])), "2161b92813246981fda99f0c910e0246f97df74f4ad936f711f0ae6a84bd71d6");
        assert_eq!(int_of(&map_of(&list_of(&out["chain"])[0])["not_before"]), 1_712_149_680);
    }

    #[test]
    fn real_document_expect_measurements() {
        let pcr0_upper = "17BF8F048519797BE90497001A7559A3D555395937117D76F8BAAEDF56CA6D97952DE79479BC0C76E5D176D20F663790";
        let good = map(vec![("measurements", map(vec![("PCR0", syn_text(pcr0_upper)), ("pcr3", syn_text(&*"0".repeat(96)))]))]);
        ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", good)]));
        // "0x" y bytes también valen.
        let with_prefix = map(vec![("measurements", map(vec![("pcr0", syn_text(&*format!("0x{}", pcr0_upper)))]))]);
        ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", with_prefix)]));
        let as_bytes = map(vec![("measurements", map(vec![("pcr0", syn_bytes(hex_decode(pcr0_upper).unwrap()))]))]);
        ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", as_bytes)]));
        // Mismatch: error con 8 hex de cada lado, sin volcar el valor entero.
        let bad = map(vec![("measurements", map(vec![("pcr0", syn_text(&*"ab".repeat(48)))]))]);
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", bad)]));
        assert!(e.contains("attestation_verify: measurement pcr0 mismatch"), "{}", e);
        assert!(e.contains("expected abababab…, got 17bf8f04…"), "{}", e);
        assert!(!e.contains(&pcr0_upper.to_ascii_lowercase()), "no vuelca el valor completo: {}", e);
        // Una medida que no está en el documento.
        let missing = map(vec![("measurements", map(vec![("pcr20", syn_text(&*"00".repeat(48)))]))]);
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", missing)])).contains("pcr20 is not present"));
        // Claves desconocidas en expect y hex inválido: errores del caller.
        let unknown = map(vec![("pcrs", map(vec![]))]);
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", unknown)])).contains("unknown key \"pcrs\""));
        let not_hex = map(vec![("measurements", map(vec![("pcr0", syn_text("zz"))]))]);
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("expect", not_hex)])).contains("is not hex"));
    }

    #[test]
    fn real_document_time_window_is_enforced_on_the_whole_chain() {
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_LEAF_NB - 1))]));
        assert!(e.contains("the leaf certificate is not valid at now=1708930772"), "{}", e);
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_LEAF_NA + 1))]));
        assert!(e.contains("is not valid at now="), "{}", e);
        // Justo en los bordes es válido (≤ / ≥).
        ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_LEAF_NB))]));
        ok(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_LEAF_NA))]));
        // Hoy (2026) el documento está vencido: sin `now` explícito el verificador no adivina.
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro"))]));
        assert!(e.contains("opts.now is required"), "{}", e);
    }

    #[test]
    fn real_document_tampering_is_detected() {
        // Un bit de la firma COSE.
        let mut doc = REAL_1.to_vec();
        let last = doc.len() - 1;
        doc[last] ^= 0x01;
        let e = err_of(verify(&doc, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))]));
        assert!(e.contains("COSE signature does not verify"), "{}", e);
        // Un byte del payload (pcr0): el payload está firmado.
        let cose = CoseSign1::parse(REAL_1).unwrap();
        let mut payload = crate::cbor::decode(cose.payload.as_ref().unwrap()).unwrap();
        if let Cbor::Map(pairs) = &mut payload {
            for (k, v) in pairs.iter_mut() {
                if k.as_text() == Some("pcrs") {
                    if let Cbor::Map(pcrs) = v {
                        if let Cbor::Bytes(b) = &mut pcrs[0].1 {
                            b[0] ^= 0xff;
                        }
                    }
                }
            }
        }
        let forged = CoseSign1 { payload: Some(payload.encode()), ..cose.clone() };
        let e = err_of(verify(&forged.encode_untagged(), vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))]));
        assert!(e.contains("COSE signature does not verify"), "{}", e);
        // Firma de longitud rara.
        let short = CoseSign1 { signature: vec![1; 64], ..cose.clone() };
        assert!(err_of(verify(&short.encode_untagged(), vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))])).contains("needs 96"));
        // Payload detached.
        let detached = CoseSign1 { payload: None, ..cose.clone() };
        assert!(err_of(verify(&detached.encode_untagged(), vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))])).contains("detached"));
        // alg distinto en el header protegido (la firma ya no cierra, pero se rechaza ANTES por alg).
        let other_alg = CoseSign1 { protected: cose_protected_alg(-7), ..cose.clone() };
        let e = err_of(verify(&other_alg.encode_untagged(), vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW))]));
        assert!(e.contains("COSE alg -7 is not ES384"), "{}", e);
        // Basura y no-bytes.
        assert!(err_of(verify(b"not cbor at all", vec![("format", syn_text("nitro")), ("now", syn_int(1))])).contains("not a COSE_Sign1"));
        assert!(err_of(b_attestation_verify(&[syn_text("x"), map(vec![("format", syn_text("nitro")), ("now", syn_int(1))])])).contains("doc must be bytes"));
    }

    #[test]
    fn root_override_and_mock_format() {
        // `mock` sin root: el error exacto del contrato.
        let e = err_of(verify(REAL_1, vec![("format", syn_text("mock")), ("now", syn_int(REAL_1_NOW))]));
        assert_eq!(e, "attestation_verify: format \"mock\" needs opts.root (the mock chain is not trusted by default)");
        // `mock` con la raíz de AWS como root explícito: el documento real verifica y el formato
        // de salida dice "mock" (la confianza vino del caller, no del pin).
        let out = ok(verify(REAL_1, vec![("format", syn_text("mock")), ("now", syn_int(REAL_1_NOW)), ("root", syn_bytes(AWS_NITRO_ROOT_G1_DER.to_vec()))]));
        assert_eq!(text_of(&out["format"]), "mock");
        // La raíz también entra como PEM.
        let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", synsema_core::bytesutil::b64_encode(AWS_NITRO_ROOT_G1_DER));
        ok(verify(REAL_1, vec![("format", syn_text("mock")), ("now", syn_int(REAL_1_NOW)), ("root", syn_text(pem.as_str()))]));
        // Una raíz distinta (sintética) NO acepta el documento real.
        let other = TestCa::root("other root", (2020, 1, 1), (2040, 1, 1));
        let e = err_of(verify(REAL_1, vec![("format", syn_text("mock")), ("now", syn_int(REAL_1_NOW)), ("root", syn_bytes(other.der()))]));
        assert!(e.contains("the chain root is not the trusted root"), "{}", e);
        // L4: con `nitro`, `opts.root` se rechaza de plano — incluso si es la propia raíz de AWS.
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("root", syn_bytes(other.der()))]));
        assert!(e.starts_with("attestation_verify: opts.root is only accepted with format \"mock\""), "{}", e);
        assert!(e.contains("use format \"mock\" to verify a chain of your own"), "{}", e);
        let e = err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(REAL_1_NOW)), ("root", syn_bytes(AWS_NITRO_ROOT_G1_DER.to_vec()))]));
        assert!(e.contains("opts.root is only accepted with format \"mock\""), "{}", e);
        // PEM que no es un certificado.
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("mock")), ("now", syn_int(1)), ("root", syn_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"))])).contains("expected a CERTIFICATE PEM"));
    }

    #[test]
    fn unsupported_formats_are_honest_errors() {
        for f in ["tdx", "sgx"] {
            let e = err_of(verify(REAL_1, vec![("format", syn_text(f)), ("now", syn_int(1))]));
            assert_eq!(e, format!("attestation_verify: format \"{}\" is not verified by this release (supported: nitro, nitro-tpm, sev-snp, mock)", f));
        }
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("tpm")), ("now", syn_int(1))])).contains("unknown format \"tpm\""));
        assert!(err_of(verify(REAL_1, vec![("now", syn_int(1))])).contains("opts.format is required"));
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_text("1"))])).contains("opts.now must be an integer"));
        assert!(err_of(verify(REAL_1, vec![("format", syn_text("nitro")), ("now", syn_int(1)), ("clock", syn_int(1))])).contains("unknown option \"clock\""));
        assert!(err_of(b_attestation_verify(&[syn_bytes(vec![]), syn_nothing()])).contains("opts is required"));
    }

    // ---------- cadena sintética (lo que produce el driver `mock` de `attest`) ----------

    struct TestCa {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    fn params(cn: &str, ca: bool, nb: (i32, u8, u8), na: (i32, u8, u8)) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = if ca { IsCa::Ca(BasicConstraints::Unconstrained) } else { IsCa::NoCa };
        p.not_before = date_time_ymd(nb.0, nb.1, nb.2);
        p.not_after = date_time_ymd(na.0, na.1, na.2);
        p
    }

    impl TestCa {
        fn root(cn: &str, nb: (i32, u8, u8), na: (i32, u8, u8)) -> TestCa {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let cert = params(cn, true, nb, na).self_signed(&key).unwrap();
            TestCa { cert, key }
        }
        fn issue(&self, cn: &str, ca: bool, nb: (i32, u8, u8), na: (i32, u8, u8), alg: &'static rcgen::SignatureAlgorithm) -> TestCa {
            let key = KeyPair::generate_for(alg).unwrap();
            let cert = params(cn, ca, nb, na).signed_by(&key, &self.cert, &self.key).unwrap();
            TestCa { cert, key }
        }
        fn der(&self) -> Vec<u8> {
            self.cert.der().to_vec()
        }
        /// El escalar P-384 del PKCS#8 de ring → clave de firma de RustCrypto (para la firma COSE).
        fn p384_signing_key(&self) -> p384::ecdsa::SigningKey {
            let pkcs8 = self.key.serialize_der();
            let (_, pki) = DerReader::new(&pkcs8).tlv().unwrap();
            let mut r = DerReader::new(pki);
            let _version = r.tlv().unwrap();
            let _alg = r.tlv().unwrap();
            let (t, ec_private) = r.tlv().unwrap();
            assert_eq!(t, 0x04);
            let (_, ec_seq) = DerReader::new(ec_private).tlv().unwrap();
            let mut r2 = DerReader::new(ec_seq);
            let _v1 = r2.tlv().unwrap();
            let (t2, scalar) = r2.tlv().unwrap();
            assert_eq!(t2, 0x04);
            assert_eq!(scalar.len(), 48);
            let sk = p384::ecdsa::SigningKey::from_slice(scalar).unwrap();
            assert_eq!(sk.verifying_key().to_encoded_point(false).as_bytes(), self.key.public_key_raw(), "la clave de ring y la de RustCrypto coinciden");
            sk
        }
    }

    struct Doc {
        root: TestCa,
        inter: TestCa,
        leaf: TestCa,
    }

    const NOW_OK: i64 = 1_800_000_000; // 2027-01-15

    impl Doc {
        fn new() -> Doc {
            let root = TestCa::root("mock root", (2020, 1, 1), (2050, 1, 1));
            let inter = root.issue("mock intermediate", true, (2026, 1, 1), (2030, 1, 1), &PKCS_ECDSA_P384_SHA384);
            let leaf = inter.issue("mock leaf", false, (2026, 12, 1), (2027, 3, 1), &PKCS_ECDSA_P384_SHA384);
            Doc { root, inter, leaf }
        }

        fn payload(&self, cabundle: Vec<Vec<u8>>) -> Cbor {
            Cbor::map_text(vec![
                ("module_id", Cbor::text("mock-module-1")),
                ("digest", Cbor::text("SHA384")),
                ("timestamp", Cbor::Int(NOW_OK as i128 * 1000 + 123)),
                ("pcrs", Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![0xaa; 48])), (Cbor::Int(1), Cbor::Bytes(vec![0xbb; 48])), (Cbor::Int(2), Cbor::Bytes(vec![0; 48]))])),
                ("certificate", Cbor::Bytes(self.leaf.der())),
                ("cabundle", Cbor::Array(cabundle.into_iter().map(Cbor::Bytes).collect())),
                ("public_key", Cbor::Bytes(vec![4; 65])),
                ("user_data", Cbor::Bytes(b"hello".to_vec())),
                ("nonce", Cbor::Null),
            ])
        }

        fn sign(&self, payload: &Cbor, alg: i128) -> Vec<u8> {
            let protected = cose_protected_alg(alg);
            let payload_bytes = payload.encode();
            let sig_structure = crate::cbor::cose_sign1_sig_structure(&protected, &payload_bytes);
            let sig: p384::ecdsa::Signature = self.leaf.p384_signing_key().sign(&sig_structure);
            CoseSign1 { protected, unprotected: Cbor::Map(vec![]), payload: Some(payload_bytes), signature: sig.to_bytes().to_vec() }.encode_tagged()
        }

        fn doc(&self) -> Vec<u8> {
            self.sign(&self.payload(vec![self.root.der(), self.inter.der()]), COSE_ALG_ES384)
        }

        fn opts(&self, now: i64) -> Vec<(&'static str, SynValue)> {
            vec![("format", syn_text("mock")), ("now", syn_int(now)), ("root", syn_bytes(self.root.der()))]
        }
    }

    #[test]
    fn synthetic_mock_chain_verifies() {
        let d = Doc::new();
        let out = ok(verify(&d.doc(), d.opts(NOW_OK)));
        assert_eq!(text_of(&out["format"]), "mock");
        assert_eq!(text_of(&out["module_id"]), "mock-module-1");
        let m = map_of(&out["measurements"]);
        assert_eq!(text_of(&m["pcr0"]), "aa".repeat(48));
        assert_eq!(text_of(&m["pcr1"]), "bb".repeat(48));
        assert_eq!(m.len(), 3);
        assert_eq!(bytes_of(&out["public_key"]), vec![4; 65]);
        assert_eq!(bytes_of(&out["user_data"]), b"hello".to_vec());
        assert_eq!(bytes_of(&out["report_data"]), b"hello".to_vec());
        assert!(matches!(out["nonce"], SynValue::Nothing));
        assert_eq!(int_of(&out["timestamp"]), NOW_OK);
        let chain = list_of(&out["chain"]);
        assert_eq!(chain.len(), 3);
        assert_eq!(text_of(&map_of(&chain[0])["subject"]), "CN=mock leaf");
        assert_eq!(text_of(&map_of(&chain[1])["subject"]), "CN=mock intermediate");
        assert_eq!(text_of(&map_of(&chain[2])["subject"]), "CN=mock root");
        // El mismo documento como `nitro` (raíz pineada de AWS) se rechaza: la raíz sintética no
        // es la de AWS. Y sin `root` como `mock` tampoco.
        let e = err_of(verify(&d.doc(), vec![("format", syn_text("nitro")), ("now", syn_int(NOW_OK))]));
        assert!(e.contains("the chain root is not the trusted root"), "{}", e);
        let e = err_of(verify(&d.doc(), vec![("format", syn_text("mock")), ("now", syn_int(NOW_OK))]));
        assert!(e.contains("needs opts.root"), "{}", e);
        // Con expect coherente.
        let expect = map(vec![("measurements", map(vec![("pcr0", syn_text(&*"AA".repeat(48)))]))]);
        let mut o = d.opts(NOW_OK);
        o.push(("expect", expect));
        ok(verify(&d.doc(), o));
        // Sin intermedio (hoja directa de la raíz) también cierra.
        let d2 = Doc::new();
        let leaf = d2.root.issue("direct leaf", false, (2026, 1, 1), (2028, 1, 1), &PKCS_ECDSA_P384_SHA384);
        let d2 = Doc { leaf, ..d2 };
        let doc = d2.sign(&d2.payload(vec![d2.root.der()]), COSE_ALG_ES384);
        let out = ok(verify(&doc, d2.opts(NOW_OK)));
        assert_eq!(list_of(&out["chain"]).len(), 2);
    }

    #[test]
    fn synthetic_chain_rejections() {
        let d = Doc::new();
        let doc = d.doc();
        // Expirado / todavía no válido: la hoja vale 2026-12-01..2027-03-01.
        assert!(err_of(verify(&doc, d.opts(1_780_000_000))).contains("the leaf certificate is not valid at now=1780000000"));
        assert!(err_of(verify(&doc, d.opts(1_900_000_000))).contains("is not valid at now="));
        // Intermedio vencido aunque la hoja esté vigente.
        let inter_old = d.root.issue("old intermediate", true, (2020, 1, 1), (2021, 1, 1), &PKCS_ECDSA_P384_SHA384);
        let leaf2 = inter_old.issue("leaf of old", false, (2026, 12, 1), (2027, 3, 1), &PKCS_ECDSA_P384_SHA384);
        let d2 = Doc { root: TestCa::root("unused", (2020, 1, 1), (2050, 1, 1)), inter: inter_old, leaf: leaf2 };
        let doc2 = d2.sign(&d2.payload(vec![d.root.der(), d2.inter.der()]), COSE_ALG_ES384);
        let e = err_of(verify(&doc2, d.opts(NOW_OK)));
        assert!(e.contains("cabundle[1] is not valid at now="), "{}", e);
        // Cadena rota: intermedio de OTRA raíz.
        let other = Doc::new();
        let broken = d.sign(&d.payload(vec![d.root.der(), other.inter.der()]), COSE_ALG_ES384);
        let e = err_of(verify(&broken, d.opts(NOW_OK)));
        assert!(e.contains("cabundle[1] issuer does not match") || e.contains("cabundle[1] signature does not verify"), "{}", e);
        // Hoja que no fue emitida por el último del cabundle.
        let broken2 = d.sign(&d.payload(vec![d.root.der()]), COSE_ALG_ES384);
        let e = err_of(verify(&broken2, d.opts(NOW_OK)));
        assert!(e.contains("the leaf certificate issuer does not match"), "{}", e);
        // Firma COSE con OTRA clave (hoja legítima en el payload, firmante ajeno).
        let stranger = d.inter.issue("stranger", false, (2026, 12, 1), (2027, 3, 1), &PKCS_ECDSA_P384_SHA384);
        let payload = d.payload(vec![d.root.der(), d.inter.der()]);
        let forged = Doc { leaf: stranger, root: TestCa::root("x", (2020, 1, 1), (2050, 1, 1)), inter: TestCa::root("y", (2020, 1, 1), (2050, 1, 1)) }.sign(&payload, COSE_ALG_ES384);
        let e = err_of(verify(&forged, d.opts(NOW_OK)));
        assert!(e.contains("COSE signature does not verify against the leaf certificate"), "{}", e);
        // alg ES256 en el header: rechazo por alg.
        let e = err_of(verify(&d.sign(&d.payload(vec![d.root.der(), d.inter.der()]), -7), d.opts(NOW_OK)));
        assert!(e.contains("COSE alg -7 is not ES384"), "{}", e);
        // Intermedio con clave P-256 firmado con ecdsa-with-SHA256: algoritmo rechazado.
        let inter_p256 = d.root.issue("p256 intermediate", true, (2026, 1, 1), (2030, 1, 1), &PKCS_ECDSA_P256_SHA256);
        let leaf3 = inter_p256.issue("leaf of p256", false, (2026, 12, 1), (2027, 3, 1), &PKCS_ECDSA_P384_SHA384);
        let d3 = Doc { root: TestCa::root("unused", (2020, 1, 1), (2050, 1, 1)), inter: inter_p256, leaf: leaf3 };
        let doc3 = d3.sign(&d3.payload(vec![d.root.der(), d3.inter.der()]), COSE_ALG_ES384);
        let e = err_of(verify(&doc3, d.opts(NOW_OK)));
        // La hoja está firmada por un emisor P-256 (SHA-256): cae por alg o por curva, nunca pasa.
        assert!(e.contains("not signed with ecdsa-with-SHA384") || e.contains("not on P-384"), "{}", e);
        // Emisor con CA:FALSE explícito.
        let mut p = params("not a ca", false, (2026, 1, 1), (2030, 1, 1));
        p.is_ca = IsCa::ExplicitNoCa;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = p.signed_by(&key, &d.root.cert, &d.root.key).unwrap();
        let not_ca = TestCa { cert, key };
        let leaf4 = not_ca.issue("leaf of not-ca", false, (2026, 12, 1), (2027, 3, 1), &PKCS_ECDSA_P384_SHA384);
        let d4 = Doc { root: TestCa::root("unused", (2020, 1, 1), (2050, 1, 1)), inter: not_ca, leaf: leaf4 };
        let doc4 = d4.sign(&d4.payload(vec![d.root.der(), d4.inter.der()]), COSE_ALG_ES384);
        let e = err_of(verify(&doc4, d.opts(NOW_OK)));
        assert!(e.contains("BasicConstraints says CA:FALSE"), "{}", e);
    }

    #[test]
    fn payload_structure_is_strict() {
        let d = Doc::new();
        let base = d.payload(vec![d.root.der(), d.inter.der()]);
        let pairs = match &base {
            Cbor::Map(p) => p.clone(),
            _ => unreachable!(),
        };
        let without = |key: &str| Cbor::Map(pairs.iter().filter(|(k, _)| k.as_text() != Some(key)).cloned().collect());
        let replaced = |key: &str, v: Cbor| Cbor::Map(pairs.iter().map(|(k, old)| if k.as_text() == Some(key) { (k.clone(), v.clone()) } else { (k.clone(), old.clone()) }).collect());
        let check = |payload: Cbor, needle: &str| {
            let e = err_of(verify(&d.sign(&payload, COSE_ALG_ES384), d.opts(NOW_OK)));
            assert!(e.contains(needle), "esperaba {:?} en {}", needle, e);
        };
        for k in ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle"] {
            check(without(k), &format!("payload is missing \"{}\"", k));
        }
        // Opcionales ausentes: válido.
        let minimal = Cbor::Map(pairs.iter().filter(|(k, _)| !matches!(k.as_text(), Some("public_key") | Some("user_data") | Some("nonce"))).cloned().collect());
        let out = ok(verify(&d.sign(&minimal, COSE_ALG_ES384), d.opts(NOW_OK)));
        assert!(matches!(out["public_key"], SynValue::Nothing));
        assert_eq!(bytes_of(&out["report_data"]), Vec::<u8>::new());
        // Tipos.
        check(replaced("module_id", Cbor::Int(1)), "payload.module_id must be text");
        check(replaced("module_id", Cbor::text("")), "payload.module_id is empty");
        check(replaced("digest", Cbor::text("MD5")), "payload.digest \"MD5\"");
        check(replaced("timestamp", Cbor::text("1")), "payload.timestamp must be an integer");
        check(replaced("timestamp", Cbor::Int(-5)), "payload.timestamp must be positive");
        check(replaced("pcrs", Cbor::Array(vec![])), "payload.pcrs must be a map");
        check(replaced("pcrs", Cbor::Map(vec![])), "payload.pcrs is empty");
        check(replaced("pcrs", Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![0; 32]))])), "payload.pcrs[0] has 32 bytes, expected 48 for SHA384");
        check(replaced("pcrs", Cbor::Map(vec![(Cbor::Int(32), Cbor::Bytes(vec![0; 48]))])), "index 32 is out of range");
        check(replaced("pcrs", Cbor::Map(vec![(Cbor::text("0"), Cbor::Bytes(vec![0; 48]))])), "payload.pcrs keys must be integers");
        check(replaced("pcrs", Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![0; 48])), (Cbor::Int(0), Cbor::Bytes(vec![0; 48]))])), "duplicate index 0");
        check(replaced("certificate", Cbor::text("x")), "payload.certificate must be bytes");
        check(replaced("certificate", Cbor::Bytes(vec![0x30, 0x00])), "certificate is not a valid X.509");
        check(replaced("cabundle", Cbor::Array(vec![])), "payload.cabundle is empty");
        check(replaced("cabundle", Cbor::Array(vec![Cbor::Int(1)])), "payload.cabundle[0] must be bytes");
        check(replaced("user_data", Cbor::text("x")), "payload.user_data must be bytes or null");
        check(replaced("nonce", Cbor::Int(1)), "payload.nonce must be bytes or null");
        // Claves desconocidas, duplicadas o no-texto; payload que no es mapa.
        let mut extra = pairs.clone();
        extra.push((Cbor::text("extra"), Cbor::Int(1)));
        check(Cbor::Map(extra), "unknown key \"extra\"");
        let mut dup = pairs.clone();
        dup.push((Cbor::text("nonce"), Cbor::Null));
        check(Cbor::Map(dup), "duplicate key \"nonce\"");
        let mut int_key = pairs.clone();
        int_key.push((Cbor::Int(1), Cbor::Null));
        check(Cbor::Map(int_key), "payload keys must be text");
        check(Cbor::Array(vec![]), "payload must be a CBOR map");
        // SHA256 con PCRs de 32 bytes: válido (la longitud sigue al digest).
        let sha256 = replaced("digest", Cbor::text("SHA256"));
        let sha256 = match sha256 {
            Cbor::Map(p) => Cbor::Map(p.into_iter().map(|(k, v)| if k.as_text() == Some("pcrs") { (k, Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![7; 32]))])) } else { (k, v) }).collect()),
            _ => unreachable!(),
        };
        let out = ok(verify(&d.sign(&sha256, COSE_ALG_ES384), d.opts(NOW_OK)));
        assert_eq!(text_of(&map_of(&out["measurements"])["pcr0"]), "07".repeat(32));
    }

    #[test]
    fn ecdsa_sig_value_decoding() {
        // r = 1, s = 2^383 (necesita el 0x00 de relleno en DER).
        let mut s = vec![0x80u8];
        s.extend(vec![0u8; 47]);
        let mut der = vec![0x30, 0x36, 0x02, 0x01, 0x01, 0x02, 0x31, 0x00];
        der.extend_from_slice(&s);
        let raw = ecdsa_sig_value_to_raw(&der, 48).unwrap();
        assert_eq!(raw.len(), 96);
        assert_eq!(raw[47], 1);
        assert_eq!(&raw[48..], &s[..]);
        // Negativo, sobrelargo, trailing y no-SEQUENCE: rechazos.
        assert!(ecdsa_sig_value_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01], 48).is_err());
        let mut long = vec![0x30, 0x35, 0x02, 0x31, 0x01];
        long.extend(vec![0u8; 48]);
        long.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(ecdsa_sig_value_to_raw(&long, 48).is_err());
        assert!(ecdsa_sig_value_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], 48).is_err());
        assert!(ecdsa_sig_value_to_raw(&[0x04, 0x01, 0x01], 48).is_err());
    }
}

/// Tests de la tanda TEE (spec `tee.md` §2): `sev-snp`, `nitro-tpm` y `expect.report_data`, con
/// los fixtures sacados de AWS (`c6a.large` con SEV-SNP, us-east-2, 2026-10-07). Sin red.
#[cfg(test)]
mod tee_platform_tests {
    use super::*;
    use crate::attest::der;
    use crate::attestation_snp::{Product, ProductRoots};
    use sha2::Sha384;

    /// `outblob` de configfs-tsm: reporte SEV-SNP v5 (sha256 a42c97b4…f8fb).
    const SNP_REPORT: &[u8] = include_bytes!("fixtures/attestation/aws_snp_c6a_report.bin");
    /// `auxblob`: la tabla de certificados del host, con una entrada VLEK de 1319 bytes.
    const SNP_AUX: &[u8] = include_bytes!("fixtures/attestation/aws_snp_c6a_auxblob.bin");
    /// La VLEK de esa tabla, suelta (sha256 660274b7…fefd). Serial 0: no positivo.
    const SNP_VLEK: &[u8] = include_bytes!("fixtures/attestation/aws_snp_c6a_vlek.der");
    /// `/.well-known/attestation` servido por v0.6.42 en esa VM.
    const SNP_IDENTITY: &str = include_str!("fixtures/attestation/aws_snp_c6a_identity.json");
    /// EC2 instance attestation de NitroTPM en la MISMA VM (sha256 40a089f9…1a46).
    const NITROTPM_DOC: &[u8] = include_bytes!("fixtures/attestation/aws_nitrotpm_c6a_doc.bin");

    const SNP_NOW: i64 = 1_791_400_000;
    const TPM_NOW: i64 = 1_791_400_300;
    const MEASUREMENT: &str = "7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766";
    const BINDING: &str = "0a61b9f5f745699a757a966ffe382d70779d62926791ed4848fe1069dd7aedec";
    const PCR4: &str = "40811f47db13c1d188559123a3e491aa6203167c861d0fcbad5fe24e9a469545dd0ff54e362255a03d3ac6ece636401d";

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn verify(doc: &[u8], opts: Vec<(&str, SynValue)>) -> Result<SynValue, Control> {
        b_attestation_verify(&[syn_bytes(doc.to_vec()), map(opts)])
    }

    fn ok(r: Result<SynValue, Control>) -> SynMap {
        match r {
            Ok(SynValue::Map(m)) => m.borrow().to_map(),
            Ok(other) => panic!("esperaba map, got {}", other),
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

    fn m(v: &SynValue) -> SynMap {
        match v {
            SynValue::Map(m) => m.borrow().to_map(),
            other => panic!("esperaba map, got {}", other),
        }
    }

    fn t(v: &SynValue) -> String {
        match v {
            SynValue::Text(s) => s.to_string(),
            other => panic!("esperaba text, got {}", other),
        }
    }

    fn i(v: &SynValue) -> i64 {
        match v {
            SynValue::Number(n) => n.to_i64_trunc().unwrap(),
            other => panic!("esperaba number, got {}", other),
        }
    }

    fn b(v: &SynValue) -> Vec<u8> {
        match v {
            SynValue::Bytes(b) => b.to_vec(),
            other => panic!("esperaba bytes, got {}", other),
        }
    }

    fn bo(v: &SynValue) -> bool {
        match v {
            SynValue::Bool(b) => *b,
            other => panic!("esperaba bool, got {}", other),
        }
    }

    fn snp(opts: Vec<(&str, SynValue)>) -> Vec<(&str, SynValue)> {
        let mut o = vec![("format", syn_text("sev-snp")), ("now", syn_int(SNP_NOW))];
        o.extend(opts);
        o
    }

    // ---------- raíces de AMD ----------

    #[test]
    fn amd_roots_match_their_pins_and_are_self_signed_with_pss() {
        for p in [Product::Milan, Product::Genoa, Product::Turin] {
            let r = crate::attestation_snp::pinned_roots(p).unwrap();
            assert_ne!(r.ask, r.asvk);
            let ark = parse_cert(r.ark, "ark").unwrap();
            assert!(ark.subject().to_string().contains(&format!("ARK-{}", p.name())), "{}", ark.subject());
        }
        // Las nueve DER, recomputadas contra la tabla del spec.
        let pins = crate::attestation_snp::AMD_PINS;
        assert_eq!(pins.len(), 3);
        assert_eq!(hex_encode(&Sha256::digest(crate::attestation_snp::AMD_ARK_MILAN_DER)), pins[0].1);
    }

    // ---------- sev-snp: el reporte real de AWS ----------

    fn assert_real_snp(out: &SynMap) {
        assert_eq!(t(&out["format"]), "sev-snp");
        assert_eq!(t(&out["digest"]), "SHA384");
        assert_eq!(i(&out["version"]), 5);
        let ms = m(&out["measurements"]);
        assert_eq!(t(&ms["measurement"]), MEASUREMENT);
        assert_eq!(t(&ms["host_data"]), "00".repeat(32));
        let rd = b(&out["report_data"]);
        assert_eq!(rd.len(), 64);
        assert_eq!(hex_encode(&rd[..32]), BINDING);
        assert!(rd[32..].iter().all(|x| *x == 0));
        for k in ["user_data", "public_key", "nonce", "timestamp", "module_id"] {
            assert!(matches!(out[k], SynValue::Nothing), "{} debería ser nothing", k);
        }
        let tcb = m(&out["tcb"]);
        assert_eq!(t(&tcb["signing_key"]), "vlek");
        assert_eq!(t(&tcb["product"]), "Milan");
        assert_eq!(t(&tcb["csp_id"]), "CN=cc-us-east-2.amazonaws.com");
        assert_eq!(i(&tcb["vmpl"]), 0);
        let rep = m(&tcb["reported"]);
        assert_eq!((i(&rep["boot_loader"]), i(&rep["tee"]), i(&rep["snp"]), i(&rep["microcode"])), (4, 0, 29, 222));
        assert!(!rep.contains_key("fmc"), "Milan no tiene fmc");
        // CURRENT_TCB es distinto (…1f e1): por eso se compara contra REPORTED_TCB.
        let cur = m(&tcb["current"]);
        assert_eq!((i(&cur["snp"]), i(&cur["microcode"])), (31, 225));
        let pol = m(&out["policy"]);
        assert!(!bo(&pol["debug"]));
        assert!(bo(&pol["smt"]));
        assert!(bo(&pol["page_swap_disable"]));
        assert_eq!(t(&pol["raw"]), "0000000002030000");
        let chain = match &out["chain"] {
            SynValue::List(l) => l.borrow().to_vec(),
            _ => panic!(),
        };
        assert_eq!(chain.len(), 3, "VLEK, ASVK, ARK");
        let leaf = m(&chain[0]);
        assert!(t(&leaf["subject"]).contains("CN=SEV-VLEK"), "{}", t(&leaf["subject"]));
        assert_eq!((i(&leaf["not_before"]), i(&leaf["not_after"])), (1_773_084_605, 1_804_620_605));
        assert!(t(&m(&chain[1])["subject"]).contains("SEV-VLEK-Milan"));
        assert!(t(&m(&chain[2])["subject"]).contains("ARK-Milan"));
    }

    #[test]
    fn sev_snp_real_report_verifies_with_aux() {
        let out = ok(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))])));
        assert_real_snp(&out);
    }

    #[test]
    fn sev_snp_real_report_verifies_with_vek_instead_of_aux() {
        assert_real_snp(&ok(verify(SNP_REPORT, snp(vec![("vek", syn_bytes(SNP_VLEK.to_vec()))]))));
        // PEM también, y las dos fuentes juntas si coinciden.
        let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", synsema_core::bytesutil::b64_encode(SNP_VLEK));
        assert_real_snp(&ok(verify(SNP_REPORT, snp(vec![("vek", syn_text(pem.as_str()))]))));
        assert_real_snp(&ok(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("vek", syn_bytes(SNP_VLEK.to_vec()))]))));
        // Las dos fuentes y distintas: error.
        let mut other = SNP_VLEK.to_vec();
        let last = other.len() - 1;
        other[last] ^= 1;
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("vek", syn_bytes(other))])));
        assert!(e.contains("opts.vek differs from the VLEK in opts.aux"), "{}", e);
    }

    #[test]
    fn sev_snp_changed_report_data_breaks_the_signature() {
        let mut doc = SNP_REPORT.to_vec();
        doc[0x50] ^= 0x01;
        let e = err_of(verify(&doc, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))])));
        assert_eq!(e, "attestation_verify: report signature does not verify against the VLEK");
        // Y uno en la medida también.
        let mut doc = SNP_REPORT.to_vec();
        doc[0x90] ^= 0x80;
        assert!(err_of(verify(&doc, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))]))).contains("report signature does not verify"));
    }

    #[test]
    fn sev_snp_changed_vlek_breaks_the_chain() {
        // Un byte del punto P-384 de la VLEK (dentro del TBS firmado por la ASVK).
        let pos = SNP_VLEK.windows(4).position(|w| w == [0x04, 0x4f, 0xeb, 0x3b]).expect("punto de la VLEK");
        let mut vlek = SNP_VLEK.to_vec();
        vlek[pos + 10] ^= 0x01;
        let e = err_of(verify(SNP_REPORT, snp(vec![("vek", syn_bytes(vlek.clone()))])));
        assert_eq!(e, "attestation_verify: the VLEK signature does not verify against its issuer");
        // Lo mismo si la VLEK cambiada viene en la tabla aux.
        let mut aux = SNP_AUX.to_vec();
        let off = aux.windows(SNP_VLEK.len()).position(|w| w == SNP_VLEK).unwrap();
        aux[off..off + vlek.len()].copy_from_slice(&vlek);
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(aux))])));
        assert!(e.contains("the VLEK signature does not verify against its issuer"), "{}", e);
    }

    #[test]
    fn sev_snp_now_outside_the_vlek_names_the_vlek() {
        for now in [1_773_084_604i64, 1_804_620_606] {
            let e = err_of(verify(SNP_REPORT, vec![("format", syn_text("sev-snp")), ("now", syn_int(now)), ("aux", syn_bytes(SNP_AUX.to_vec()))]));
            assert!(e.contains(&format!("the VLEK is not valid at now={} (valid from 1773084605 to 1804620605)", now)), "{}", e);
        }
        // Justo en los bordes vale.
        for now in [1_773_084_605i64, 1_804_620_605] {
            ok(verify(SNP_REPORT, vec![("format", syn_text("sev-snp")), ("now", syn_int(now)), ("aux", syn_bytes(SNP_AUX.to_vec()))]));
        }
        // Sin `now`, como siempre: no se lee el reloj.
        assert!(err_of(verify(SNP_REPORT, vec![("format", syn_text("sev-snp")), ("aux", syn_bytes(SNP_AUX.to_vec()))])).contains("opts.now is required"));
    }

    #[test]
    fn sev_snp_unsigned_report_is_rejected_before_looking_for_the_vek() {
        let mut doc = SNP_REPORT.to_vec();
        doc[0x48] = 7 << 2;
        // Sin aux ni vek: igual dice "not signed" (el chequeo va antes de buscar la VEK).
        let e = err_of(verify(&doc, snp(vec![])));
        assert_eq!(e, "attestation_verify: report KEY_INFO.SIGNING_KEY is 7: the report is not signed");
        doc[0x48] = 2 << 2;
        assert!(err_of(verify(&doc, snp(vec![]))).contains("SIGNING_KEY is 2, not 0 (VCEK) or 1 (VLEK)"));
    }

    #[test]
    fn sev_snp_without_the_vek_is_a_clear_error() {
        // aux con sólo la entrada terminadora.
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(vec![0u8; 24]))])));
        assert!(e.contains("opts.aux has no VLEK entry and opts.vek is missing"), "{}", e);
        let e = err_of(verify(SNP_REPORT, snp(vec![])));
        assert!(e.contains("neither opts.aux nor opts.vek was given"), "{}", e);
        // Tabla rota: sin terminador, rango fuera del blob, GUID desconocido, entrada repetida.
        let mut unterminated = SNP_AUX[..16].to_vec();
        unterminated.extend_from_slice(&24u32.to_le_bytes());
        unterminated.extend_from_slice(&1u32.to_le_bytes());
        unterminated.push(0x30);
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(unterminated))])));
        assert!(e.contains("no terminating all-zero entry"), "{}", e);
        let mut aux = SNP_AUX.to_vec();
        aux[20..24].copy_from_slice(&100_000u32.to_le_bytes());
        assert!(err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(aux))]))).contains("the VLEK entry points outside the blob"));
        let mut aux = SNP_AUX.to_vec();
        aux[0] ^= 0xff;
        assert!(err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(aux))]))).contains("unknown certificate GUID"));
        let mut aux = SNP_AUX[..24].to_vec();
        aux.extend_from_slice(&SNP_AUX[..24]);
        aux.extend_from_slice(&[0u8; 24]);
        aux.extend_from_slice(&SNP_AUX[0x30..]);
        assert!(err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(aux))]))).contains("appears twice"));
    }

    #[test]
    fn sev_snp_rejects_root_and_strange_fields() {
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("root", syn_bytes(AWS_NITRO_ROOT_G1_DER.to_vec()))])));
        assert!(e.starts_with("attestation_verify: opts.root is only accepted with format \"mock\" (sev-snp trusts only its pinned roots"), "{}", e);
        // Tamaño, versión, algoritmo.
        let e = err_of(verify(&SNP_REPORT[..1000], snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))])));
        assert!(e.contains("doc has 1000 bytes; a SEV-SNP report is 1184"), "{}", e);
        for (off, val, needle) in [(0x00usize, 6u8, "report VERSION 6 is not supported"), (0x00, 1, "report VERSION 1"), (0x34, 2, "SIGNATURE_ALGO is 2")] {
            let mut doc = SNP_REPORT.to_vec();
            doc[off] = val;
            let e = err_of(verify(&doc, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))])));
            assert!(e.contains(needle), "{}: {}", needle, e);
        }
        // CPUID que no es Milan aunque la VLEK diga Milan (y la firma, que va después, ni se mira).
        let mut doc = SNP_REPORT.to_vec();
        doc[0x189] = 0x11;
        assert!(err_of(verify(&doc, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))]))).contains("model 0x11 is Genoa, but the VLEK says Milan"));
        // Bytes de la firma más allá de los 48 de P-384.
        let mut doc = SNP_REPORT.to_vec();
        doc[0x2A0 + 50] = 1;
        assert!(err_of(verify(&doc, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec()))]))).contains("SIGNATURE.R has non-zero bytes beyond the 48"));
        // aux/vek con otro formato: rechazados.
        assert!(err_of(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW)), ("aux", syn_bytes(vec![]))])).contains("opts.aux is only accepted with format \"sev-snp\""));
        // expect con una medida que sev-snp no tiene.
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("expect", map(vec![("measurements", map(vec![("pcr0", syn_text("00"))]))]))])));
        assert!(e.contains("unknown key \"pcr0\" for sev-snp (valid keys: measurement, host_data)"), "{}", e);
        // expect con la medida correcta y con una equivocada.
        ok(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("expect", map(vec![("measurements", map(vec![("measurement", syn_text(&*MEASUREMENT.to_uppercase()))]))]))])));
        let e = err_of(verify(SNP_REPORT, snp(vec![("aux", syn_bytes(SNP_AUX.to_vec())), ("expect", map(vec![("measurements", map(vec![("host_data", syn_text(&*"11".repeat(32)))]))]))])));
        assert!(e.contains("measurement host_data mismatch"), "{}", e);
    }

    // ---------- T6: expect.report_data ----------

    #[test]
    fn expect_report_data_pads_fixed_width_formats_and_is_exact_otherwise() {
        let aux = || ("aux", syn_bytes(SNP_AUX.to_vec()));
        let binding = synsema_core::bytesutil::hex_decode(BINDING).unwrap();
        // 32 bytes → se rellena hasta 64; bytes y hex valen igual.
        ok(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_bytes(binding.clone()))]))])));
        ok(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_text(BINDING))]))])));
        let mut full = binding.clone();
        full.resize(64, 0);
        ok(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_bytes(full))]))])));
        // Distinto: dice cuántos coinciden, no los valores.
        let mut wrong = binding.clone();
        wrong[10] ^= 1;
        let e = err_of(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_bytes(wrong))]))])));
        assert_eq!(e, "attestation_verify: report_data mismatch (the first 10 of 64 bytes match; expected 64 bytes)");
        assert!(!e.contains(BINDING));
        // Más largo que el ancho del formato.
        let e = err_of(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_bytes(vec![0; 65]))]))])));
        assert!(e.contains("65 bytes, more than the 64 of the format"), "{}", e);
        assert!(err_of(verify(SNP_REPORT, snp(vec![aux(), ("expect", map(vec![("report_data", syn_text("zz"))]))]))).contains("not hex"));
        // nitro-tpm: ancho variable, igualdad exacta con `user_data`.
        let tpm = |rd: SynValue| verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW)), ("expect", map(vec![("report_data", rd)]))]);
        ok(tpm(syn_bytes(b"hello".to_vec())));
        ok(tpm(syn_text("68656c6c6f")));
        assert!(err_of(tpm(syn_bytes(b"hell".to_vec()))).contains("report_data mismatch (the first 4 of 5 bytes match; expected 4 bytes)"));
        assert!(err_of(tpm(syn_bytes(b"hello\0".to_vec()))).contains("report_data mismatch"));
    }

    // ---------- binding del identity servido por v0.6.42 ----------

    #[test]
    fn identity_binding_recomputes_from_the_published_fields() {
        let id: serde_json::Value = serde_json::from_str(SNP_IDENTITY).unwrap();
        assert_eq!(id["format"], "sev-snp");
        assert_eq!(id["driver"], "tsm");
        let doc = synsema_core::bytesutil::b64_decode(id["document"].as_str().unwrap()).unwrap();
        assert_eq!(doc, SNP_REPORT, "el documento publicado es el fixture");
        let aux = synsema_core::bytesutil::b64_decode(id["aux"].as_str().unwrap()).unwrap();
        assert_eq!(aux, SNP_AUX);
        // config_sha = sha256(config compacto con claves ordenadas).
        let cfg: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_value(id["config"].clone()).unwrap();
        let compact = serde_json::to_string(&cfg).unwrap();
        assert_eq!(compact, r#"{"ceiling":"unbounded","engine":"v0.6.42","labels":true,"profile":"native","tls_key":"attested"}"#);
        assert_eq!(hex_encode(&Sha256::digest(compact.as_bytes())), id["config_sha"].as_str().unwrap());
        // report_data[0..32] = sha256(spki ‖ program_sha ‖ config_sha).
        let mut h = Sha256::new();
        h.update(synsema_core::bytesutil::hex_decode(id["public_key_hex"].as_str().unwrap()).unwrap());
        h.update(synsema_core::bytesutil::hex_decode(id["program_sha"].as_str().unwrap()).unwrap());
        h.update(synsema_core::bytesutil::hex_decode(id["config_sha"].as_str().unwrap()).unwrap());
        let binding = h.finalize().to_vec();
        assert_eq!(hex_encode(&binding), BINDING);
        // Y el cliente lo escribe así, sin acordarse del relleno.
        ok(verify(&doc, snp(vec![("aux", syn_bytes(aux)), ("expect", map(vec![("report_data", syn_bytes(binding))]))])));
    }

    // ---------- nitro-tpm ----------

    #[test]
    fn nitro_tpm_real_document_verifies() {
        let out = ok(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW))]));
        assert_eq!(t(&out["format"]), "nitro-tpm");
        assert_eq!(t(&out["digest"]), "SHA384");
        assert_eq!(t(&out["module_id"]), "i-07f49d0166cb57518-tpm0000000000000000");
        assert_eq!(b(&out["user_data"]), b"hello".to_vec());
        assert_eq!(b(&out["report_data"]), b"hello".to_vec());
        assert!(matches!(out["public_key"], SynValue::Nothing));
        assert!(matches!(out["nonce"], SynValue::Nothing));
        assert!(matches!(out["tcb"], SynValue::Nothing));
        assert_eq!(i(&out["timestamp"]), 1_791_400_277);
        let ms = m(&out["measurements"]);
        assert_eq!(ms.len(), 24);
        assert_eq!(t(&ms["pcr4"]), PCR4);
        assert!(ms.contains_key("pcr23") && !ms.contains_key("pcr24"));
        let chain = match &out["chain"] {
            SynValue::List(l) => l.borrow().to_vec(),
            _ => panic!(),
        };
        let leaf = m(&chain[0]);
        assert_eq!((i(&leaf["not_before"]), i(&leaf["not_after"])), (1_791_400_274, 1_791_411_077));
        assert!(t(&m(&chain[chain.len() - 1])["subject"]).contains("aws.nitro-enclaves"));
        // expect de PCRs, como en nitro.
        let expect = map(vec![("measurements", map(vec![("pcr4", syn_text(PCR4))]))]);
        ok(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW)), ("expect", expect)]));
        // Un byte del payload firmado.
        let mut doc = NITROTPM_DOC.to_vec();
        let pos = doc.windows(5).position(|w| w == b"hello").unwrap();
        doc[pos] = b'j';
        assert!(err_of(verify(&doc, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW))])).contains("COSE signature does not verify"));
    }

    #[test]
    fn nitro_tpm_and_nitro_never_swap_labels() {
        // Un documento de VM no sale como enclave.
        let e = err_of(verify(NITROTPM_DOC, vec![("format", syn_text("nitro")), ("now", syn_int(TPM_NOW))]));
        assert!(e.contains("payload has the key \"nitrotpm_pcrs\""), "{}", e);
        assert!(e.contains("format \"nitro-tpm\""), "{}", e);
        // Ni como mock (con la raíz de AWS explícita).
        let e = err_of(verify(NITROTPM_DOC, vec![("format", syn_text("mock")), ("now", syn_int(TPM_NOW)), ("root", syn_bytes(AWS_NITRO_ROOT_G1_DER.to_vec()))]));
        assert!(e.contains("nitrotpm_pcrs"), "{}", e);
        // Y un enclave no sale como VM.
        let real1 = include_bytes!("fixtures/attestation/nitro_marlin_sample_attestation.bin");
        let e = err_of(verify(real1, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(1_708_930_921))]));
        assert!(e.contains("payload has the key \"pcrs\""), "{}", e);
        // root con nitro-tpm: rechazado como con nitro.
        let e = err_of(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW)), ("root", syn_bytes(AWS_NITRO_ROOT_G1_DER.to_vec()))]));
        assert!(e.contains("opts.root is only accepted with format \"mock\" (nitro-tpm trusts only its pinned roots"), "{}", e);
    }

    #[test]
    fn nitro_tpm_outside_the_leaf_window_is_rejected() {
        let e = err_of(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(1_791_411_078))]));
        assert!(e.contains("the leaf certificate is not valid at now=1791411078"), "{}", e);
        ok(verify(NITROTPM_DOC, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(1_791_411_077))]));
    }

    #[test]
    fn nitro_tpm_payload_rules() {
        // Mismo sobre y cadena del documento real, payload cambiado → la firma no cierra, pero lo
        // estructural se rechaza ANTES (por eso se puede probar sin la clave de AWS).
        let cose = CoseSign1::parse(NITROTPM_DOC).unwrap();
        let (payload, indefinite) = crate::cbor::decode_allow_indefinite(cose.payload.as_ref().unwrap()).unwrap();
        assert!(indefinite, "el fixture es un mapa indefinido");
        let pairs = payload.as_map().unwrap().to_vec();
        let with = |f: &dyn Fn(&mut Vec<(Cbor, Cbor)>)| {
            let mut p = pairs.clone();
            f(&mut p);
            let doc = CoseSign1 { payload: Some(Cbor::Map(p).encode()), ..cose.clone() }.encode_untagged();
            err_of(verify(&doc, vec![("format", syn_text("nitro-tpm")), ("now", syn_int(TPM_NOW))]))
        };
        let set = |key: &'static str, v: Cbor| {
            move |p: &mut Vec<(Cbor, Cbor)>| {
                for (k, old) in p.iter_mut() {
                    if k.as_text() == Some(key) {
                        *old = v.clone();
                    }
                }
            }
        };
        assert!(with(&set("digest", Cbor::text("SHA256"))).contains("payload.digest \"SHA256\" is not SHA384"));
        assert!(with(&set("nitrotpm_pcrs", Cbor::Map(vec![(Cbor::Int(24), Cbor::Bytes(vec![0; 48]))]))).contains("payload.nitrotpm_pcrs index 24 is out of range (0..=23)"));
        assert!(with(&set("nitrotpm_pcrs", Cbor::Map(vec![(Cbor::Int(0), Cbor::Bytes(vec![0; 32]))]))).contains("nitrotpm_pcrs[0] has 32 bytes, expected 48"));
        assert!(with(&|p: &mut Vec<(Cbor, Cbor)>| p.retain(|(k, _)| k.as_text() != Some("nitrotpm_pcrs"))).contains("payload is missing \"nitrotpm_pcrs\""));
        assert!(with(&|p: &mut Vec<(Cbor, Cbor)>| p.push((Cbor::text("pcrs"), Cbor::Map(vec![])))).contains("payload has the key \"pcrs\""));
        assert!(with(&|p: &mut Vec<(Cbor, Cbor)>| p.push((Cbor::text("extra"), Cbor::Int(1)))).contains("unknown key \"extra\""));
        assert!(with(&|p: &mut Vec<(Cbor, Cbor)>| p.push((Cbor::text("nonce"), Cbor::Null))).contains("duplicate key \"nonce\""));
        // Codificado definido, el mismo contenido: estructuralmente válido (la firma ya no cierra
        // porque los bytes firmados cambiaron).
        assert!(with(&|_p: &mut Vec<(Cbor, Cbor)>| {}).contains("COSE signature does not verify"));
    }

    #[test]
    fn nitro_rejects_indefinite_payloads() {
        // Un payload de enclave con mapa indefinido (el mismo contenido que el documento real 1):
        // se rechaza por la codificación, antes de mirar la firma.
        let real1 = include_bytes!("fixtures/attestation/nitro_marlin_sample_attestation.bin");
        let cose = CoseSign1::parse(real1).unwrap();
        let enc = cose.payload.clone().unwrap();
        assert_eq!(enc[0] & 0xe0, 0xa0, "mapa definido");
        let n = (enc[0] & 0x1f) as usize;
        assert!(n < 24, "cabecera de un byte");
        let mut indef = vec![0xbfu8];
        indef.extend_from_slice(&enc[1..]);
        indef.push(0xff);
        let doc = CoseSign1 { payload: Some(indef), ..cose.clone() }.encode_untagged();
        let e = err_of(verify(&doc, vec![("format", syn_text("nitro")), ("now", syn_int(1_708_930_921))]));
        assert!(e.contains("payload uses indefinite-length CBOR"), "{}", e);
    }

    // ---------- sev-snp sintético: lo que va DESPUÉS de la firma (política) y Turin ----------
    //
    // La API pública sólo confía en las raíces pineadas de AMD, así que estos casos usan una cadena
    // de prueba RSA-PSS propia inyectada por `verify_sev_snp_with` (interna). Turin no tiene fixture
    // real: su disposición sale de la spec de AMD (SEV-SNP ABI, pub. 56860) y de `virtee/sev`
    // (`TcbVersion::from_turin_bytes`: fmc, bl, tee, snp, -, -, -, ucode; CPUID 0x1A/0x00..=0x11).

    const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
    const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

    fn amd_oid(tail: &[u8]) -> Vec<u8> {
        let mut o = vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01];
        o.extend_from_slice(tail);
        o
    }

    fn null() -> Vec<u8> {
        der::tlv(0x05, &[])
    }

    fn pss_alg(salt: u8) -> Vec<u8> {
        let sha = der::seq(&[der::oid(OID_SHA384), null()]);
        der::seq(&[
            der::oid(OID_RSASSA_PSS),
            der::seq(&[der::ctx(0, &sha), der::ctx(1, &der::seq(&[der::oid(OID_MGF1), sha.clone()])), der::ctx(2, &der::uint(&[salt]))]),
        ])
    }

    fn name(cn: &str) -> Vec<u8> {
        der::seq(&[der::set(&[der::seq(&[der::oid(der::OID_COMMON_NAME), der::utf8(cn)])])])
    }

    fn ext(oid: &[u8], value: &[u8]) -> Vec<u8> {
        der::seq(&[der::oid(oid), der::octets(value)])
    }

    fn rsa_spki(k: &rsa::RsaPrivateKey) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let pk = der::seq(&[der::uint(&k.n().to_bytes_be()), der::uint(&k.e().to_bytes_be())]);
        der::seq(&[der::seq(&[der::oid(OID_RSA), null()]), der::bitstring(&pk)])
    }

    fn rsa_cert(serial: u8, issuer: &str, subject: &str, spki: Vec<u8>, extensions: Vec<Vec<u8>>, signer: &rsa::RsaPrivateKey, salt: u8) -> Vec<u8> {
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let alg = pss_alg(salt);
        let tbs = der::seq(&[
            der::ctx(0, &der::uint(&[2])),
            der::uint(&[serial]),
            alg.clone(),
            name(issuer),
            der::seq(&[der::utc_time("200101000000Z"), der::generalized_time("20991231235959Z")]),
            name(subject),
            spki,
            der::ctx(3, &der::seq(&extensions)),
        ]);
        let sk = rsa::pss::SigningKey::<Sha384>::new_with_salt_len(signer.clone(), salt as usize);
        let sig = sk.sign_with_rng(&mut rand::rngs::OsRng, &tbs).to_vec();
        der::seq(&[tbs, alg, der::bitstring(&sig)])
    }

    fn ca_ext() -> Vec<u8> {
        der::seq(&[der::oid(der::OID_BASIC_CONSTRAINTS), der::boolean(true), der::octets(&der::seq(&[der::boolean(true)]))])
    }

    fn int_der(v: u8) -> Vec<u8> {
        der::uint(&[v])
    }

    struct SynthChain {
        ark: &'static [u8],
        /// ASK (firma VCEKs) y ASVK (firma VLEKs) con claves y nombres DISTINTOS: así un test que
        /// cruce VCEK y VLEK falla por la cadena y no pasa por casualidad.
        ask: &'static [u8],
        asvk: &'static [u8],
        vlek: Vec<u8>,
        vlek_key: p384::ecdsa::SigningKey,
        vcek: Vec<u8>,
        vcek_key: p384::ecdsa::SigningKey,
        hwid: [u8; 64],
    }

    fn rsa_keys() -> &'static (rsa::RsaPrivateKey, rsa::RsaPrivateKey, rsa::RsaPrivateKey) {
        static K: std::sync::OnceLock<(rsa::RsaPrivateKey, rsa::RsaPrivateKey, rsa::RsaPrivateKey)> = std::sync::OnceLock::new();
        K.get_or_init(|| {
            let mut rng = rand::rngs::OsRng;
            (rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap(), rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap(), rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap())
        })
    }

    /// `tcb` = (fmc, bl, tee, snp, ucode) que declara la VLEK; `asvk_salt` permite fabricar una
    /// firma con otra sal.
    fn synth_chain(product: &str, tcb: (Option<u8>, u8, u8, u8, u8), asvk_salt: u8) -> SynthChain {
        let (ark_k, asvk_k, ask_k) = rsa_keys();
        let ark = rsa_cert(1, &format!("ARK-{}", product), &format!("ARK-{}", product), rsa_spki(ark_k), vec![ca_ext()], ark_k, 48);
        let asvk = rsa_cert(2, &format!("ARK-{}", product), &format!("SEV-VLEK-{}", product), rsa_spki(asvk_k), vec![ca_ext()], ark_k, asvk_salt);
        let ask = rsa_cert(3, &format!("ARK-{}", product), &format!("SEV-{}", product), rsa_spki(ask_k), vec![ca_ext()], ark_k, 48);
        let vlek_key = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = vlek_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let mut tcb_exts = vec![
            ext(&amd_oid(&[0x02]), &der::tlv(0x16, product.as_bytes())),
            ext(&amd_oid(&[0x03, 0x01]), &int_der(tcb.1)),
            ext(&amd_oid(&[0x03, 0x02]), &int_der(tcb.2)),
            ext(&amd_oid(&[0x03, 0x03]), &int_der(tcb.3)),
            ext(&amd_oid(&[0x03, 0x08]), &int_der(tcb.4)),
        ];
        if let Some(fmc) = tcb.0 {
            tcb_exts.push(ext(&amd_oid(&[0x03, 0x09]), &int_der(fmc)));
        }
        let mut hwid = [0u8; 64];
        for (k, b) in hwid.iter_mut().enumerate() {
            *b = 0x40 + k as u8;
        }
        let vcek_key = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let vcek_point = vcek_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let mut vcek_exts = tcb_exts.clone();
        vcek_exts.push(ext(&amd_oid(&[0x04]), &der::octets(&hwid)));
        let vcek = rsa_cert(4, &format!("SEV-{}", product), "SEV-VCEK", der::ec_spki(der::OID_SECP384R1, &vcek_point), vcek_exts, ask_k, 48);
        let mut exts = vec![
            ext(&amd_oid(&[0x02]), &der::tlv(0x16, product.as_bytes())),
            ext(&amd_oid(&[0x03, 0x01]), &int_der(tcb.1)),
            ext(&amd_oid(&[0x03, 0x02]), &int_der(tcb.2)),
            ext(&amd_oid(&[0x03, 0x03]), &int_der(tcb.3)),
            ext(&amd_oid(&[0x03, 0x08]), &int_der(tcb.4)),
            ext(&amd_oid(&[0x05]), &der::tlv(0x16, b"CN=test-csp")),
        ];
        if let Some(fmc) = tcb.0 {
            exts.push(ext(&amd_oid(&[0x03, 0x09]), &int_der(fmc)));
        }
        let vlek = rsa_cert(0, &format!("SEV-VLEK-{}", product), "SEV-VLEK", der::ec_spki(der::OID_SECP384R1, &point), exts, asvk_k, 48);
        SynthChain { ark: Box::leak(ark.into_boxed_slice()), ask: Box::leak(ask.into_boxed_slice()), asvk: Box::leak(asvk.into_boxed_slice()), vlek, vlek_key, vcek, vcek_key, hwid }
    }

    /// Un reporte v5 firmado con la VLEK sintética.
    fn synth_report(c: &SynthChain, policy: u64, cpuid: (u8, u8), reported_tcb: [u8; 8]) -> Vec<u8> {
        let mut doc = vec![0u8; 0x4A0];
        doc[0..4].copy_from_slice(&5u32.to_le_bytes());
        doc[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
        doc[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        doc[0x48..0x4C].copy_from_slice(&(1u32 << 2).to_le_bytes());
        doc[0x50..0x70].copy_from_slice(&[0xab; 32]);
        doc[0x90..0xC0].copy_from_slice(&[0x5a; 48]);
        for off in [0x38usize, 0x180, 0x1E0, 0x1F0] {
            doc[off..off + 8].copy_from_slice(&reported_tcb);
        }
        doc[0x188] = cpuid.0;
        doc[0x189] = cpuid.1;
        sign_report(&mut doc, &c.vlek_key);
        doc
    }

    /// (Re)firma los 0x2A0 bytes del reporte con `key` (R y S en little-endian de 72 bytes).
    fn sign_report(doc: &mut [u8], key: &p384::ecdsa::SigningKey) {
        use p384::ecdsa::signature::Signer as _;
        let sig: p384::ecdsa::Signature = key.sign(&doc[..0x2A0]);
        let (r, s) = (sig.r().to_bytes(), sig.s().to_bytes());
        for (off, v) in [(0x2A0usize, r), (0x2E8usize, s)] {
            for (k, byte) in v.iter().rev().enumerate() {
                doc[off + k] = *byte;
            }
        }
    }

    /// Un reporte v5 firmado por la VCEK sintética: KEY_INFO.SIGNING_KEY = 0 y CHIP_ID = `chip_id`.
    fn synth_vcek_report(c: &SynthChain, chip_id: &[u8; 64]) -> Vec<u8> {
        let mut doc = synth_report(c, POLICY_OK, (0x19, 0x01), MILAN_TCB);
        doc[0x48..0x4C].copy_from_slice(&0u32.to_le_bytes());
        doc[0x1A0..0x1E0].copy_from_slice(chip_id);
        sign_report(&mut doc, &c.vcek_key);
        doc
    }

    fn synth_verify(c: &SynthChain, doc: &[u8]) -> Result<SynValue, Control> {
        synth_verify_vek(c, doc, &c.vlek)
    }

    fn synth_verify_vek(c: &SynthChain, doc: &[u8], vek: &[u8]) -> Result<SynValue, Control> {
        let opts = parse_opts(Some(&map(vec![("format", syn_text("sev-snp")), ("now", syn_int(SNP_NOW)), ("vek", syn_bytes(vek.to_vec()))]))).unwrap_or_else(|_| panic!("opts"));
        let (ark, ask, asvk) = (c.ark, c.ask, c.asvk);
        verify_sev_snp_with(doc, &opts, &move |_p| Ok(ProductRoots { ark, ask, asvk }))
    }

    const MILAN_TCB: [u8; 8] = [4, 0, 0, 0, 0, 0, 29, 222];
    const POLICY_OK: u64 = 0x0003_0000;

    #[test]
    fn synthetic_chain_verifies_and_debug_policy_is_always_an_error() {
        let c = synth_chain("Milan", (None, 4, 0, 29, 222), 48);
        let out = ok(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), MILAN_TCB)));
        assert_eq!(t(&m(&out["tcb"])["csp_id"]), "CN=test-csp");
        assert!(!bo(&m(&out["policy"])["debug"]));
        // DEBUG (bit 19) prendido: error de política, sin opción. Va DESPUÉS de la firma: el
        // reporte está bien firmado y la cadena cierra.
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK | (1 << 19), (0x19, 0x01), MILAN_TCB)));
        assert_eq!(e, "attestation_verify: report POLICY.DEBUG is set: the guest allows debug: the host can read its memory");
        // TCB de la VLEK distinta de REPORTED_TCB.
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), [4, 0, 0, 0, 0, 0, 30, 222])));
        assert_eq!(e, "attestation_verify: report REPORTED_TCB.snp is 30 but the VLEK snpSPL is 29");
        // Bytes reservados de la TCB distintos de cero.
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), [4, 0, 1, 0, 0, 0, 29, 222])));
        assert!(e.contains("REPORTED_TCB has non-zero reserved bytes for Milan"), "{}", e);
    }

    #[test]
    fn synthetic_chain_rejects_another_pss_salt() {
        let c = synth_chain("Milan", (None, 4, 0, 29, 222), 32);
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), MILAN_TCB)));
        assert_eq!(e, "attestation_verify: the AMD ASVK RSASSA-PSS salt length is 32, not 48");
    }

    #[test]
    fn synthetic_turin_uses_the_turin_tcb_layout() {
        // Turin: fmc, bl, tee, snp, -, -, -, ucode (sin fixture real; ver el comentario de arriba).
        let c = synth_chain("Turin", (Some(1), 2, 3, 4, 5), 48);
        let turin_tcb = [1, 2, 3, 4, 0, 0, 0, 5];
        let out = ok(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x1a, 0x02), turin_tcb)));
        let tcb = m(&out["tcb"]);
        assert_eq!(t(&tcb["product"]), "Turin");
        let rep = m(&tcb["reported"]);
        assert_eq!((i(&rep["fmc"]), i(&rep["boot_loader"]), i(&rep["tee"]), i(&rep["snp"]), i(&rep["microcode"])), (1, 2, 3, 4, 5));
        // fmcSPL distinto: error.
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x1a, 0x02), [9, 2, 3, 4, 0, 0, 0, 5])));
        assert!(e.contains("REPORTED_TCB.fmc is 9 but the VLEK fmcSPL is 1"), "{}", e);
        // Una VLEK de Turin con CPUID de Milan.
        let e = err_of(synth_verify(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), turin_tcb)));
        assert!(e.contains("is Milan, but the VLEK says Turin"), "{}", e);
        // Producto desconocido en la VEK.
        let c2 = synth_chain("Venice", (None, 4, 0, 29, 222), 48);
        let e = err_of(synth_verify(&c2, &synth_report(&c2, POLICY_OK, (0x19, 0x01), MILAN_TCB)));
        assert!(e.contains("productName \"Venice\" is not Milan, Genoa or Turin"), "{}", e);
    }

    #[test]
    fn synthetic_vcek_path_checks_the_ask_and_the_chip_id() {
        let c = synth_chain("Milan", (None, 4, 0, 29, 222), 48);
        // VCEK ← ASK ← ARK, hwID = CHIP_ID: verifica.
        let out = ok(synth_verify_vek(&c, &synth_vcek_report(&c, &c.hwid), &c.vcek));
        let tcb = m(&out["tcb"]);
        assert_eq!(t(&tcb["signing_key"]), "vcek");
        assert!(matches!(tcb.get("csp_id"), None | Some(SynValue::Nothing)), "una VCEK no tiene csp_id");
        // Otro chip.
        let mut other = c.hwid;
        other[0] ^= 1;
        let e = err_of(synth_verify_vek(&c, &synth_vcek_report(&c, &other), &c.vcek));
        assert_eq!(e, "attestation_verify: report CHIP_ID does not match the VCEK hwID");
        // CHIP_ID enmascarado (MASK_CHIP_ID): un reporte VCEK no se puede atar al chip.
        let e = err_of(synth_verify_vek(&c, &synth_vcek_report(&c, &[0; 64]), &c.vcek));
        assert!(e.contains("CHIP_ID is masked"), "{}", e);
    }

    #[test]
    fn synthetic_vcek_and_vlek_cannot_stand_in_for_each_other() {
        let c = synth_chain("Milan", (None, 4, 0, 29, 222), 48);
        // Reporte firmado por la VCEK que dice ser de la VCEK, pero se pasa la VLEK: la VLEK no la
        // emitió la ASK (ni la firma cierra).
        let e = err_of(synth_verify_vek(&c, &synth_vcek_report(&c, &c.hwid), &c.vlek));
        assert!(e.contains("the VCEK issuer does not match"), "{}", e);
        // Reporte que dice VLEK, pasando la VCEK: la VCEK no la emitió la ASVK.
        let e = err_of(synth_verify_vek(&c, &synth_report(&c, POLICY_OK, (0x19, 0x01), MILAN_TCB), &c.vcek));
        assert!(e.contains("the VLEK issuer does not match"), "{}", e);
        // KEY_INFO cambiado a VCEK sobre un reporte de la VLEK (re-firmado con la VLEK): la VLEK
        // no cierra contra la ASK.
        let mut doc = synth_report(&c, POLICY_OK, (0x19, 0x01), MILAN_TCB);
        doc[0x48..0x4C].copy_from_slice(&0u32.to_le_bytes());
        doc[0x1A0..0x1E0].copy_from_slice(&c.hwid);
        sign_report(&mut doc, &c.vlek_key);
        assert!(err_of(synth_verify_vek(&c, &doc, &c.vlek)).contains("the VCEK issuer does not match"));
    }

    #[test]
    fn synthetic_reserved_fields_must_be_zero() {
        let c = synth_chain("Milan", (None, 4, 0, 29, 222), 48);
        let base = synth_report(&c, POLICY_OK, (0x19, 0x01), MILAN_TCB);
        // KEY_INFO bits 31:5.
        let mut doc = base.clone();
        doc[0x48..0x4C].copy_from_slice(&((1u32 << 2) | (1 << 5)).to_le_bytes());
        sign_report(&mut doc, &c.vlek_key);
        assert_eq!(err_of(synth_verify(&c, &doc)), "attestation_verify: report KEY_INFO has reserved bits set (0x00000024)");
        // La palabra de 0x4C.
        let mut doc = base.clone();
        doc[0x4C] = 1;
        sign_report(&mut doc, &c.vlek_key);
        assert_eq!(err_of(synth_verify(&c, &doc)), "attestation_verify: report reserved field at 0x4C is not zero");
        // La cola de la firma (fuera de lo firmado): la firma sigue verificando, el byte no.
        let mut doc = base.clone();
        doc[0x49F] = 1;
        assert_eq!(err_of(synth_verify(&c, &doc)), "attestation_verify: report SIGNATURE has non-zero reserved bytes after R and S");
        let mut doc = base;
        doc[0x330] = 1;
        assert!(err_of(synth_verify(&c, &doc)).contains("non-zero reserved bytes after R and S"));
    }
}
