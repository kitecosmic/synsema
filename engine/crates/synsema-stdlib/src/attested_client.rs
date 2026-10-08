//! T9 — `fetch(url, {"attested": …})` / `ws_connect(url, h, {"attested": …})`: conectarse a un
//! `serve --attested` sin conocer su clave de antemano (la idea de RA-TLS).
//!
//! El documento de attestation se autentica solo (lo firma el hardware y ata la clave del
//! servidor), así que se puede leer por una conexión cuya cadena TLS no se valida **siempre que la
//! clave del handshake sea la del documento y todo verifique antes de mandar nada**. Un
//! intermediario no puede completar el handshake con la clave atestada.
//!
//! Este módulo es la parte PURA: las opciones y la verificación del identity contra la SPKI que se
//! vio en el handshake. El transporte (una sola conexión: handshake → `GET
//! /.well-known/attestation` → verificación → recién ahí el request del usuario) está en `http.rs`
//! y `ws.rs`; en el perfil wasm el transporte del host no puede hacerlo y falla cerrado.

use sha2::{Digest, Sha256};
use synsema_core::bytesutil::{b64_decode, hex_decode, hex_encode};
use synsema_core::interpreter::{Control, RuntimeError};
use synsema_core::types::{syn_bytes, syn_int, syn_map, syn_text, SynMap, SynValue};

/// Lo que el cliente exige del servidor.
#[derive(Clone, Debug)]
pub struct AttestedSpec {
    /// El programa que tiene que estar corriendo (`synsema code sha`), hex en minúsculas.
    pub program_sha: String,
    /// Los formatos que tienen que estar y verificar (`sev-snp`, `nitro-tpm`, …).
    pub formats: Vec<String>,
    /// `expect.measurements` por formato; `None` = `"any"`, la renuncia explícita a comparar.
    /// Todo formato pedido salvo `mock` tiene su entrada (sin medidas el documento sólo prueba
    /// "una VM de esa plataforma", no qué código corre).
    pub measurements: Vec<(String, Option<SynValue>)>,
    /// La hora de la verificación (segundos unix); `None` = el reloj del sistema.
    pub now: Option<i64>,
}

/// Lo que se verificó (sale en la respuesta como `attested`).
#[derive(Clone, Debug)]
pub struct AttestedInfo {
    pub program_sha: String,
    pub public_key_hex: String,
    pub formats: Vec<String>,
    /// El `config` publicado, como JSON.
    pub config_json: String,
}

impl AttestedInfo {
    pub fn to_syn(&self) -> SynValue {
        let mut m = SynMap::new();
        m.insert("program_sha", syn_text(self.program_sha.as_str()));
        m.insert("public_key_hex", syn_text(self.public_key_hex.as_str()));
        m.insert("formats", synsema_core::types::syn_list(self.formats.iter().map(|f| syn_text(f.as_str())).collect()));
        m.insert("config", crate::json_exact::parse(&self.config_json).unwrap_or(SynValue::Nothing));
        syn_map(m)
    }
}

fn cerr(msg: String) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// `opts.attested` = `{program_sha, formats, measurements?, now?}`. Los dos primeros son
/// obligatorios: sin `program_sha` la atestación no dice qué código corre; sin `formats` no hay
/// nada que exigir.
pub fn parse_attested_spec(v: &SynValue, who: &str) -> Result<AttestedSpec, Control> {
    let m = match v {
        SynValue::Map(m) => m.borrow().to_map(),
        other => return Err(cerr(format!("{}: attested must be a map {{program_sha, formats, measurements?, now?}}, got {}", who, other.type_name()))),
    };
    let mut program_sha = None;
    let mut formats: Option<Vec<String>> = None;
    let mut measurements = Vec::new();
    let mut now = None;
    for (k, val) in &m {
        match k.as_str() {
            "program_sha" => {
                let t = match val {
                    SynValue::Text(t) => t.trim().trim_start_matches("0x").to_ascii_lowercase(),
                    other => return Err(cerr(format!("{}: attested.program_sha must be hex text, got {}", who, other.type_name()))),
                };
                if t.len() != 64 || !t.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(cerr(format!("{}: attested.program_sha must be 64 hex characters (the output of `synsema code sha`)", who)));
                }
                program_sha = Some(t);
            }
            "formats" => {
                let list = match val {
                    SynValue::List(l) => l.borrow().to_vec(),
                    other => return Err(cerr(format!("{}: attested.formats must be a list of formats, got {}", who, other.type_name()))),
                };
                let mut out = Vec::new();
                for f in list {
                    match f {
                        SynValue::Text(t) if !t.is_empty() => {
                            if out.contains(&t.to_string()) {
                                return Err(cerr(format!("{}: attested.formats names {:?} twice", who, t.to_string())));
                            }
                            out.push(t.to_string())
                        }
                        other => return Err(cerr(format!("{}: attested.formats must hold format names, got {}", who, other))),
                    }
                }
                formats = Some(out);
            }
            "measurements" => {
                let mm = match val {
                    SynValue::Map(mm) => mm.borrow().to_map(),
                    other => return Err(cerr(format!("{}: attested.measurements must be a map format → {{name: hex}}, got {}", who, other.type_name()))),
                };
                for (f, exp) in mm {
                    let expect = match &exp {
                        SynValue::Map(m) if m.borrow().len() == 0 => {
                            return Err(cerr(format!("{}: attested.measurements.{} is an empty map: it would compare nothing; name the measurements, or write \"any\" to accept any on purpose", who, f)))
                        }
                        SynValue::Map(_) => Some(exp.clone()),
                        SynValue::Text(t) if &**t == "any" => None,
                        _ => return Err(cerr(format!("{}: attested.measurements.{} must be a map name → hex, or \"any\"", who, f))),
                    };
                    measurements.push((f.to_string(), expect));
                }
            }
            "now" => {
                now = Some(match val {
                    SynValue::Number(n) if n.is_integer() => n.to_i64_trunc().filter(|i| *i >= 0).ok_or_else(|| cerr(format!("{}: attested.now must be unix seconds", who)))?,
                    other => return Err(cerr(format!("{}: attested.now must be an integer (unix seconds), got {}", who, other.type_name()))),
                })
            }
            other => return Err(cerr(format!("{}: attested: unknown key {:?} (valid keys: program_sha, formats, measurements, now)", who, other))),
        }
    }
    let program_sha = program_sha.ok_or_else(|| cerr(format!("{}: attested.program_sha is required: without it the attestation does not say which code runs", who)))?;
    let formats = formats.filter(|f| !f.is_empty()).ok_or_else(|| cerr(format!("{}: attested.formats is required and cannot be empty (e.g. [\"sev-snp\", \"nitro-tpm\"])", who)))?;
    for (f, _) in &measurements {
        if !formats.contains(f) {
            return Err(cerr(format!("{}: attested.measurements names {:?}, which is not in attested.formats", who, f)));
        }
    }
    // Sin medidas, un documento de plataforma prueba que hay UNA VM o enclave de esa plataforma,
    // no qué código corre: cualquiera que alquile una declara el program_sha esperado y pasa.
    for f in &formats {
        if f != "mock" && !measurements.iter().any(|(m, _)| m == f) {
            return Err(cerr(format!(
                "{}: attested.measurements has no entry for {:?}: without the expected measurements the document proves only that some {} machine answered, not which code runs; pass them (e.g. {{\"{}\": {{...}}}}), or {{\"{}\": \"any\"}} to accept any on purpose",
                who, f, f, f, f
            )));
        }
    }
    Ok(AttestedSpec { program_sha, formats, measurements, now })
}

/// JSON compacto con las claves ordenadas (lo que `serve --attested` hashea como `config_sha`).
fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys.iter().map(|k| format!("{}:{}", serde_json::Value::String((*k).clone()), canonical(&o[*k]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn field<'a>(j: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    j.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("the identity has no {:?}", k))
}

fn unhex(s: &str, what: &str) -> Result<Vec<u8>, String> {
    hex_decode(s.trim()).map_err(|_| format!("the identity's {} is not hex", what))
}

/// Verifica el identity de `/.well-known/attestation` contra la SPKI del handshake y lo que exige
/// el cliente. Cualquier duda es error (y el request del usuario no sale).
pub fn verify_identity(body: &[u8], handshake_spki: &[u8], spec: &AttestedSpec) -> Result<AttestedInfo, String> {
    let j: serde_json::Value = serde_json::from_slice(body).map_err(|_| "the identity is not JSON".to_string())?;
    // 3. La clave del documento es la del handshake.
    let pk_hex = field(&j, "public_key_hex")?.to_ascii_lowercase();
    if unhex(&pk_hex, "public_key_hex")? != handshake_spki {
        return Err("the identity's public_key_hex is not the key of this TLS connection".to_string());
    }
    // 4. config_sha y program_sha.
    let config = j.get("config").ok_or("the identity has no \"config\"")?;
    let config_sha = unhex(field(&j, "config_sha")?, "config_sha")?;
    if Sha256::digest(canonical(config).as_bytes()).as_slice() != config_sha.as_slice() {
        return Err("the identity's config_sha does not match its config".to_string());
    }
    let program_sha = field(&j, "program_sha")?.to_ascii_lowercase();
    // Viene de un JSON todavía sin verificar: se valida la forma antes de mirarlo (cortarlo por
    // bytes con un carácter multibyte haría panic).
    if program_sha.len() != 64 || !program_sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("the identity's program_sha is not 64 hex characters".to_string());
    }
    if program_sha != spec.program_sha {
        return Err(format!("the server runs program_sha {}…, not the expected {}…", &program_sha[..12], &spec.program_sha[..12]));
    }
    let mut h = Sha256::new();
    h.update(handshake_spki);
    h.update(unhex(&program_sha, "program_sha")?);
    h.update(&config_sha);
    let binding = h.finalize().to_vec();
    // 5. Cada documento.
    let docs: Vec<serde_json::Value> = match j.get("documents").and_then(|d| d.as_array()) {
        Some(d) => d.clone(),
        None => vec![j.clone()],
    };
    if docs.is_empty() {
        return Err("the identity has no documents".to_string());
    }
    let now = spec.now.unwrap_or_else(synsema_core::clock::now_secs);
    let mut verified: Vec<String> = Vec::new();
    for d in &docs {
        let format = field(d, "format")?.to_string();
        if format == "mock" && !spec.formats.iter().any(|f| f == "mock") {
            return Err("the server is attested by the mock driver (forgeable on purpose) and attested.formats does not name \"mock\"".to_string());
        }
        let document = b64_decode(field(d, "document")?).map_err(|_| format!("the {} document is not base64", format))?;
        let mut expect = SynMap::new();
        expect.insert("report_data", syn_bytes(binding.clone()));
        if let Some((_, Some(m))) = spec.measurements.iter().find(|(f, _)| *f == format) {
            expect.insert("measurements", m.clone());
        }
        let mut opts = SynMap::new();
        opts.insert("format", syn_text(format.as_str()));
        opts.insert("now", syn_int(now));
        opts.insert("expect", syn_map(expect));
        if let Some(aux) = d.get("aux").and_then(|a| a.as_str()) {
            opts.insert("aux", syn_bytes(b64_decode(aux).map_err(|_| format!("the {} aux is not base64", format))?));
        }
        if format == "mock" {
            let root = d.get("root").and_then(|r| r.as_str()).ok_or("the mock document carries no root")?;
            opts.insert("root", syn_bytes(b64_decode(root).map_err(|_| "the mock root is not base64".to_string())?));
        }
        crate::attestation::verify_value(&[syn_bytes(document), syn_map(opts)]).map_err(|c| match c {
            Control::Error(e) => format!("the {} document does not verify: {}", format, e.into_message()),
            _ => format!("the {} document does not verify", format),
        })?;
        if verified.contains(&format) {
            return Err(format!("the identity has two {} documents", format));
        }
        verified.push(format);
    }
    for f in &spec.formats {
        if !verified.contains(f) {
            return Err(format!("attested.formats asks for {:?} but the server published no such document (it has: {})", f, verified.join(", ")));
        }
    }
    Ok(AttestedInfo { program_sha, public_key_hex: hex_encode(handshake_spki), formats: verified, config_json: config.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut out = SynMap::new();
        for (k, v) in pairs {
            out.insert(k, v);
        }
        syn_map(out)
    }

    fn parse(formats: &[&str], measurements: Option<SynValue>) -> Result<AttestedSpec, String> {
        let mut pairs = vec![
            ("program_sha", syn_text("ab".repeat(32))),
            ("formats", synsema_core::types::syn_list(formats.iter().map(|f| syn_text(*f)).collect())),
        ];
        if let Some(ms) = measurements {
            pairs.push(("measurements", ms));
        }
        parse_attested_spec(&m(pairs), "fetch").map_err(|c| match c {
            Control::Error(e) => e.into_message(),
            _ => "?".to_string(),
        })
    }

    #[test]
    fn a_platform_format_needs_its_measurements_or_an_explicit_any() {
        let e = parse(&["sev-snp"], None).unwrap_err();
        assert!(e.contains("attested.measurements has no entry for \"sev-snp\"") && e.contains("\"any\""), "{}", e);
        let e = parse(&["nitro-tpm"], Some(m(vec![("nitro-tpm", m(vec![]))]))).unwrap_err();
        assert!(e.contains("is an empty map"), "{}", e);
        let e = parse(&["nitro-tpm"], Some(m(vec![("nitro-tpm", syn_text("anything"))]))).unwrap_err();
        assert!(e.contains("must be a map name → hex, or \"any\""), "{}", e);
        // Con medidas, con la renuncia explícita, y `mock` sin nada (no es una plataforma).
        let s = parse(&["sev-snp", "nitro-tpm", "mock"], Some(m(vec![("sev-snp", syn_text("any")), ("nitro-tpm", m(vec![("pcr4", syn_text("00"))]))]))).unwrap();
        assert!(s.measurements.iter().any(|(f, x)| f == "sev-snp" && x.is_none()));
        assert!(s.measurements.iter().any(|(f, x)| f == "nitro-tpm" && x.is_some()));
        assert!(parse(&["mock"], None).is_ok());
    }

    fn spec() -> AttestedSpec {
        AttestedSpec { program_sha: "ab".repeat(32), formats: vec!["mock".into()], measurements: Vec::new(), now: Some(1) }
    }

    fn identity(program_sha: &str) -> Vec<u8> {
        let config = serde_json::json!({});
        let config_sha = hex_encode(&Sha256::digest(canonical(&config).as_bytes()));
        serde_json::json!({"public_key_hex": "0102", "config": config, "config_sha": config_sha, "program_sha": program_sha, "documents": []}).to_string().into_bytes()
    }

    #[test]
    fn a_program_sha_that_is_not_hex_is_an_error_not_a_panic() {
        // 64 BYTES pero multibyte: cortarlo en [..12] haría panic.
        let e = verify_identity(&identity(&"é".repeat(32)), &[1, 2], &spec()).unwrap_err();
        assert_eq!(e, "the identity's program_sha is not 64 hex characters");
        assert!(verify_identity(&identity("abc"), &[1, 2], &spec()).unwrap_err().contains("not 64 hex"));
        // Hex válido pero otro programa.
        assert!(verify_identity(&identity(&"cd".repeat(32)), &[1, 2], &spec()).unwrap_err().contains("not the expected"));
        // La clave del handshake manda antes que todo.
        assert!(verify_identity(&identity(&"ab".repeat(32)), &[9], &spec()).unwrap_err().contains("not the key of this TLS connection"));
        // Sin documentos.
        assert_eq!(verify_identity(&identity(&"ab".repeat(32)), &[1, 2], &spec()).unwrap_err(), "the identity has no documents");
    }
}
