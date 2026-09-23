//! Lo PURO del cliente HTTP — compartido por el transporte nativo (`http.rs`, sockets +
//! rustls) y el del perfil wasm (`http_stub.rs`, transporte provisto por el host vía
//! `hostcap`). Acá viven: el gate `net(host)`, la forma de la respuesta, los parsers
//! de args de los builtins y el registro de los seis builtins cliente
//! (`http`/`http_get`/`http_post`/`http_put`/`http_delete`/`fetch`).
//!
//! Una sola verdad para los dos perfiles: el chequeo de capability corre ANTES del
//! transporte, con la MISMA canonización de host, en nativo y en wasm — el host
//! embebedor puede ofrecer `http`, pero el programa sigue teniendo que declarar
//! `require net("host")` y el techo del embebedor sigue mandando.

use std::cell::RefCell;
use std::rc::Rc;

use indexmap::IndexMap;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use sha2::{Digest, Sha256};
use synsema_core::types::{syn_bool, syn_bytes, syn_int, syn_map, syn_nothing, syn_text, SynValue};

use crate::json::{dumps, json_to_syn, syn_to_json};

/// Chequea la capability `net(host)` del URL; convierte la violación en `Control::Error`
/// SIN ubicación (como secure.rs/database.rs). Scope = hostname (minúsculas, sin puerto);
/// si no se puede extraer, se usa el URL crudo (fail-closed). `net` NO es tipo-ruta →
/// `covers()` usa el glob de host (`net("*.example.com")` cubre `api.example.com`).
pub fn require_net(
    caps: &Rc<RefCell<CapabilitySet>>,
    url: &str,
    source: &str,
) -> Result<(), Control> {
    let host = match url_hostname(url) {
        Some(h) if !h.is_empty() => h,
        _ => url.to_string(),
    };
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(host)), source)
        .map_err(|v| Control::Error(v.into_error()))
}

/// Respuesta estructurada (espeja el dict del oráculo).
pub struct HttpResult {
    pub status: i64,
    pub ok: bool,
    pub body: String,
    /// v0.6.20 — el body exacto, byte a byte (`body` es su lectura como texto, lossy para
    /// binarios). Lo expone `http_bytes(...)` como `bytes of r`.
    pub body_bytes: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub error: Option<String>,
}

pub fn err_result(error: String) -> HttpResult {
    HttpResult {
        status: 0,
        ok: false,
        body: String::new(),
        body_bytes: Vec::new(),
        headers: Vec::new(),
        error: Some(error),
    }
}

/// Transporte de una request: (method, url, headers, query, body, timeout_secs).
/// Nativo = sockets; wasm = el `http` del host (o el stub "sin transporte").
/// v0.6.20 — el body va en BYTES: texto, binario o el JSON que `body_arg` ya serializó.
pub type Transport = fn(
    &str,
    &str,
    Option<&[(String, String)]>,
    Option<&[(String, String)]>,
    Option<&[u8]>,
    u64,
) -> HttpResult;

pub fn urlencode(q: &[(String, String)]) -> String {
    q.iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// URL + query string (si hay pares). Compartido por los dos transportes.
pub fn url_with_query(url: &str, query: Option<&[(String, String)]>) -> String {
    match query {
        Some(q) if !q.is_empty() => {
            let sep = if url.contains('?') { "&" } else { "?" };
            format!("{}{}{}", url, sep, urlencode(q))
        }
        _ => url.to_string(),
    }
}

pub fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

pub fn map_pairs(v: Option<&SynValue>) -> Option<Vec<(String, String)>> {
    match v {
        Some(SynValue::Map(m)) => Some(
            m.borrow()
                .iter()
                .map(|(k, val)| (k.clone(), val.to_string()))
                .collect(),
        ),
        _ => None,
    }
}

/// Mapa de headers → pares, MATERIALIZANDO secrets (el borde del socket es donde el
/// secret se expone: `{"Authorization": bearer(secret("KEY"))}`).
pub fn header_pairs(v: Option<&SynValue>) -> Option<Vec<(String, String)>> {
    match v {
        Some(SynValue::Map(m)) => Some(
            m.borrow()
                .iter()
                .map(|(k, val)| match val {
                    SynValue::Secret(s) => (k.clone(), s.expose().to_string()),
                    other => (k.clone(), other.to_string()),
                })
                .collect(),
        ),
        _ => None,
    }
}

pub fn timeout_arg(v: Option<&SynValue>) -> u64 {
    match v {
        Some(SynValue::Number(n)) => {
            let secs = n.to_f64();
            if secs > 0.0 && secs.is_finite() {
                (secs as u64).max(1)
            } else {
                30
            }
        }
        _ => 30,
    }
}

/// v0.6.20 — el body de una request según su TIPO: texto tal cual; bytes crudos; un map o
/// una lista → JSON, con `Content-Type: application/json` si el caller no puso uno. Antes
/// un map viajaba como su texto de display (`{name: Alice}`) y sin Content-Type: ninguna API
/// lo aceptaba. Un `secret` sigue redactado (fail-closed: el body no es canal de secretos).
pub fn body_arg(v: Option<&SynValue>) -> (Option<Vec<u8>>, Option<&'static str>) {
    match v {
        None | Some(SynValue::Nothing) => (None, None),
        Some(SynValue::Text(s)) => (Some(s.as_bytes().to_vec()), None),
        Some(SynValue::Bytes(b)) => (Some(b.to_vec()), None),
        Some(v @ SynValue::Map(_)) | Some(v @ SynValue::List(_)) => {
            (Some(dumps(&syn_to_json(v)).into_bytes()), Some("application/json"))
        }
        Some(other) => (Some(raw_str(other).into_bytes()), None),
    }
}

/// v0.6.20 — agrega el `Content-Type` por defecto si el caller no mandó uno (case-insensitive).
pub fn with_default_content_type(
    headers: Option<Vec<(String, String)>>,
    default: Option<&str>,
) -> Option<Vec<(String, String)>> {
    let Some(ct) = default else { return headers };
    let mut h = headers.unwrap_or_default();
    if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        h.push(("Content-Type".to_string(), ct.to_string()));
    }
    Some(h)
}

fn header_lookup<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// v0.6.20 — `json`: el body parseado cuando el Content-Type dice JSON y parsea; si no,
/// `nothing` (la misma convención que `json of request` en el servidor).
fn parsed_json(headers: &[(String, String)], body: &str) -> SynValue {
    let is_json = header_lookup(headers, "content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("json"))
        .unwrap_or(false);
    if !is_json {
        return syn_nothing();
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => json_to_syn(&v),
        Err(_) => syn_nothing(),
    }
}

/// v0.6.20 — la respuesta de `http_bytes`: `bytes` exactos en vez de `body` texto.
pub fn response_to_syn_bytes(r: HttpResult) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("status".to_string(), syn_int(r.status));
    m.insert("ok".to_string(), syn_bool(r.ok));
    m.insert("bytes".to_string(), syn_bytes(r.body_bytes));
    if !r.headers.is_empty() {
        let mut hm = IndexMap::new();
        for (k, v) in r.headers {
            hm.insert(k, syn_text(v));
        }
        m.insert("headers".to_string(), syn_map(hm));
    }
    if let Some(e) = r.error {
        m.insert("error".to_string(), syn_text(e));
    }
    syn_map(m)
}

pub fn response_to_syn(r: HttpResult) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("status".to_string(), syn_int(r.status));
    m.insert("ok".to_string(), syn_bool(r.ok));
    let json = parsed_json(&r.headers, &r.body);
    m.insert("body".to_string(), syn_text(r.body));
    m.insert("json".to_string(), json);
    if !r.headers.is_empty() {
        let mut hm = IndexMap::new();
        for (k, v) in r.headers {
            hm.insert(k, syn_text(v));
        }
        m.insert("headers".to_string(), syn_map(hm));
    }
    if let Some(e) = r.error {
        m.insert("error".to_string(), syn_text(e));
    }
    syn_map(m)
}

/// Registra los seis builtins cliente sobre `transport`. Cada uno gatea `net(host)`
/// ANTES de tocar el transporte — misma firma y mismo retorno en los dos perfiles.
pub fn register_http_client_builtins(
    interp: &Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    transport: Transport,
) {
    // http(method, url, headers?, query?, body?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http",
            -1,
            Rc::new(move |_i, args, _loc| {
                let method = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                let url = raw_str(args.get(1).unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http()")?;
                let query = map_pairs(args.get(3));
                let (body, default_ct) = body_arg(args.get(4));
                let headers = with_default_content_type(header_pairs(args.get(2)), default_ct);
                let r = transport(
                    &method,
                    &url,
                    headers.as_deref(),
                    query.as_deref(),
                    body.as_deref(),
                    timeout_arg(args.get(5)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_get(url, headers?, query?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http_get",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http_get()")?;
                let headers = header_pairs(args.get(1));
                let query = map_pairs(args.get(2));
                let r = transport(
                    "GET",
                    &url,
                    headers.as_deref(),
                    query.as_deref(),
                    None,
                    timeout_arg(args.get(3)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_post(url, body, headers?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http_post",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http_post()")?;
                let (body, default_ct) = body_arg(args.get(1));
                let headers = with_default_content_type(header_pairs(args.get(2)), default_ct);
                let r = transport(
                    "POST",
                    &url,
                    headers.as_deref(),
                    None,
                    body.as_deref(),
                    timeout_arg(args.get(3)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_put(url, body, headers?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http_put",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http_put()")?;
                let (body, default_ct) = body_arg(args.get(1));
                let headers = with_default_content_type(header_pairs(args.get(2)), default_ct);
                let r = transport(
                    "PUT",
                    &url,
                    headers.as_deref(),
                    None,
                    body.as_deref(),
                    timeout_arg(args.get(3)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_delete(url, headers?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http_delete",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http_delete()")?;
                let headers = header_pairs(args.get(1));
                let r = transport(
                    "DELETE",
                    &url,
                    headers.as_deref(),
                    None,
                    None,
                    timeout_arg(args.get(2)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }

    // fetch(url, method?, headers?, body?, timeout?) — cliente HTTP real, gateado por net.
    // Default GET; mismo retorno que http_* (response_to_syn).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "fetch",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "fetch()")?;
                let method = args.get(1).map(raw_str).unwrap_or_else(|| "GET".to_string());
                let (body, default_ct) = body_arg(args.get(3));
                let headers = with_default_content_type(header_pairs(args.get(2)), default_ct);
                let r = transport(
                    &method,
                    &url,
                    headers.as_deref(),
                    None,
                    body.as_deref(),
                    timeout_arg(args.get(4)),
                );
                Ok(response_to_syn(r))
            }),
        );
    }
    // v0.6.20 — http_bytes(method, url, headers?, query?, body?, timeout?): la misma request
    // que `http`, con la respuesta en `bytes` exactos en vez de `body` texto (fuentes,
    // imágenes, tarballs: un binario que pasa por texto se corrompe).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "http_bytes",
            -1,
            Rc::new(move |_i, args, _loc| {
                let method = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                let url = raw_str(args.get(1).unwrap_or(&SynValue::Nothing));
                require_net(&caps, &url, "http_bytes()")?;
                let query = map_pairs(args.get(3));
                let (body, default_ct) = body_arg(args.get(4));
                let headers = with_default_content_type(header_pairs(args.get(2)), default_ct);
                let r = transport(
                    &method,
                    &url,
                    headers.as_deref(),
                    query.as_deref(),
                    body.as_deref(),
                    timeout_arg(args.get(5)),
                );
                Ok(response_to_syn_bytes(r))
            }),
        );
    }
    // v0.6.20 — multipart_encode(parts) → {body: bytes, content_type}: puro, sin gate (no toca
    // la red); se manda con `http_post(url, body of m, {"Content-Type": content_type of m})`.
    interp.register_builtin("multipart_encode", 1, Rc::new(|_i, args, _loc| multipart_encode(args)));
}

fn merr(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Valor de un parámetro de `Content-Disposition`: sin comillas, CR ni LF (RFC 7578 §4.2).
fn disposition_value(s: &str) -> String {
    s.replace('"', "%22").replace(['\r', '\n'], "")
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// v0.6.20 — cuerpo `multipart/form-data` (RFC 7578). `parts`: lista de mapas
/// `{name, value}` (un campo) o `{name, filename, bytes, content_type?}` (un archivo).
/// El boundary se deriva de un hash de las partes: puro y determinista (mismas partes →
/// mismos bytes); si por azar apareciera dentro de un dato, se re-deriva con una sal.
pub fn multipart_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "multipart_encode";
    let parts = match args.first() {
        Some(SynValue::List(l)) => l.borrow().clone(),
        Some(other) => {
            return Err(merr(format!(
                "{}: parts must be a list of {{name, value}} or {{name, filename, bytes, content_type?}}, got {}",
                F,
                other.type_name()
            )))
        }
        None => return Err(merr(format!("{}(parts) takes the list of parts", F))),
    };
    if parts.is_empty() {
        return Err(merr(format!("{}: parts is empty (a multipart body needs at least one part)", F)));
    }
    let mut encoded: Vec<(String, Vec<u8>)> = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        let SynValue::Map(m) = p else {
            return Err(merr(format!("{}: part {} must be a map, got {}", F, i, p.type_name())));
        };
        let m = m.borrow();
        for k in m.keys() {
            if !matches!(k.as_str(), "name" | "value" | "bytes" | "filename" | "content_type") {
                return Err(merr(format!(
                    "{}: part {} has an unknown key {:?} (valid: name, value, bytes, filename, content_type)",
                    F, i, k
                )));
            }
        }
        let name = match m.get("name") {
            Some(SynValue::Text(s)) if !s.is_empty() => s.to_string(),
            _ => return Err(merr(format!("{}: part {} needs a non-empty text \"name\"", F, i))),
        };
        let text_opt = |k: &str| -> Result<Option<String>, Control> {
            match m.get(k) {
                None | Some(SynValue::Nothing) => Ok(None),
                Some(SynValue::Text(s)) => Ok(Some(s.to_string())),
                Some(other) => Err(merr(format!(
                    "{}: part {} {:?} must be text, got {}",
                    F,
                    i,
                    k,
                    other.type_name()
                ))),
            }
        };
        let filename = text_opt("filename")?;
        let content_type = text_opt("content_type")?;
        let data: Vec<u8> = match (m.get("bytes"), m.get("value")) {
            (Some(SynValue::Bytes(b)), None) => b.to_vec(),
            (Some(other), None) => {
                return Err(merr(format!("{}: part {} \"bytes\" must be bytes, got {}", F, i, other.type_name())))
            }
            (None, Some(SynValue::Secret(_))) => {
                return Err(merr(format!("{}: part {} value is a secret — a form body is not a channel for secrets", F, i)))
            }
            (None, Some(SynValue::Bytes(b))) => b.to_vec(),
            (None, Some(other)) => raw_str(other).into_bytes(),
            (Some(_), Some(_)) => return Err(merr(format!("{}: part {} has both \"bytes\" and \"value\"; pass one", F, i))),
            (None, None) => return Err(merr(format!("{}: part {} needs \"value\" or \"bytes\"", F, i))),
        };
        let mut head = format!("Content-Disposition: form-data; name=\"{}\"", disposition_value(&name));
        if let Some(f) = &filename {
            head.push_str(&format!("; filename=\"{}\"", disposition_value(f)));
        }
        head.push_str("\r\n");
        let ct = content_type.or_else(|| filename.as_ref().map(|_| "application/octet-stream".to_string()));
        if let Some(ct) = ct {
            head.push_str(&format!("Content-Type: {}\r\n", ct));
        }
        encoded.push((head, data));
    }
    let mut seed: Vec<u8> = Vec::new();
    for (h, d) in &encoded {
        seed.extend_from_slice(h.as_bytes());
        seed.extend_from_slice(d);
        seed.push(0);
    }
    let mut salt: u32 = 0;
    let boundary = loop {
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(salt.to_le_bytes());
        let digest = hasher.finalize();
        let hex: String = digest[..16].iter().map(|b| format!("{:02x}", b)).collect();
        let b = format!("----synsema{}", hex);
        let collides = encoded.iter().any(|(h, d)| h.contains(&b) || contains_bytes(d, b.as_bytes()));
        if !collides {
            break b;
        }
        salt = salt.wrapping_add(1);
    };
    let mut body: Vec<u8> = Vec::new();
    for (h, d) in &encoded {
        body.extend_from_slice(format!("--{}\r\n{}\r\n", boundary, h).as_bytes());
        body.extend_from_slice(d);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    let mut out = IndexMap::new();
    out.insert("body".to_string(), syn_bytes(body));
    out.insert(
        "content_type".to_string(),
        syn_text(format!("multipart/form-data; boundary={}", boundary)),
    );
    Ok(syn_map(out))
}

#[cfg(test)]
mod v0620_tests {
    use super::*;
    use synsema_core::types::syn_list;

    fn map(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.clone());
        }
        syn_map(m)
    }

    /// §5.1a — el body según su tipo: texto tal cual; map → JSON + Content-Type por defecto;
    /// bytes crudos; un Content-Type del caller gana.
    #[test]
    fn body_by_type_and_default_content_type() {
        let (b, ct) = body_arg(Some(&syn_text("hola")));
        assert_eq!(b.as_deref(), Some(&b"hola"[..]));
        assert_eq!(ct, None);
        let m = map(&[("email", syn_text("a@b.c")), ("n", syn_int(1))]);
        let (b, ct) = body_arg(Some(&m));
        assert_eq!(String::from_utf8(b.unwrap()).unwrap(), "{\"email\": \"a@b.c\", \"n\": 1}");
        assert_eq!(ct, Some("application/json"));
        let (b, ct) = body_arg(Some(&syn_bytes(vec![0, 255])));
        assert_eq!(b, Some(vec![0, 255]));
        assert_eq!(ct, None);
        assert_eq!(body_arg(None), (None, None));
        let h = with_default_content_type(None, Some("application/json")).unwrap();
        assert_eq!(h, vec![("Content-Type".to_string(), "application/json".to_string())]);
        let mine = vec![("content-type".to_string(), "text/plain".to_string())];
        let h = with_default_content_type(Some(mine.clone()), Some("application/json")).unwrap();
        assert_eq!(h, mine, "el Content-Type del caller gana");
    }

    /// §5.1b — `json` parseado sólo con Content-Type JSON; `error` sólo si falló el transporte.
    #[test]
    fn response_has_json_key_and_conditional_error() {
        let r = HttpResult {
            status: 200,
            ok: true,
            body: "{\"a\": [1, 2]}".to_string(),
            body_bytes: b"{\"a\": [1, 2]}".to_vec(),
            headers: vec![("Content-Type".to_string(), "application/json; charset=utf-8".to_string())],
            error: None,
        };
        let v = response_to_syn(r);
        let SynValue::Map(m) = &v else { panic!() };
        let keys: Vec<String> = m.borrow().keys().cloned().collect();
        assert_eq!(keys, vec!["status", "ok", "body", "json", "headers"]);
        assert_eq!(m.borrow().get("json").unwrap().to_string(), "{a: [1, 2]}");
        let r = HttpResult {
            status: 200,
            ok: true,
            body: "plain".to_string(),
            body_bytes: b"plain".to_vec(),
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            error: None,
        };
        let SynValue::Map(m) = response_to_syn(r) else { panic!() };
        assert!(matches!(m.borrow().get("json"), Some(SynValue::Nothing)));
        let SynValue::Map(m) = response_to_syn(err_result("connection refused".into())) else { panic!() };
        assert_eq!(m.borrow().get("error").unwrap().to_string(), "connection refused");
        assert_eq!(m.borrow().get("status").unwrap().to_string(), "0");
    }

    /// §5.1c — `http_bytes` devuelve los bytes exactos.
    #[test]
    fn bytes_response_is_exact() {
        let r = HttpResult {
            status: 200,
            ok: true,
            body: String::from_utf8_lossy(&[0xff, 0x00, 0x89]).to_string(),
            body_bytes: vec![0xff, 0x00, 0x89],
            headers: Vec::new(),
            error: None,
        };
        let SynValue::Map(m) = response_to_syn_bytes(r) else { panic!() };
        assert!(matches!(m.borrow().get("bytes"), Some(SynValue::Bytes(b)) if b.to_vec() == vec![0xff, 0x00, 0x89]));
        assert!(m.borrow().get("body").is_none());
    }

    /// §5.1d — multipart: determinista, con el formato RFC 7578, y el parser del servidor lo lee.
    #[test]
    fn multipart_round_trips_through_the_server_parser() {
        let parts = syn_list(vec![
            map(&[("name", syn_text("title")), ("value", syn_text("hola \"mundo\""))]),
            map(&[
                ("name", syn_text("file")),
                ("filename", syn_text("a.bin")),
                ("content_type", syn_text("application/octet-stream")),
                ("bytes", syn_bytes(vec![1, 2, 3, 13, 10, 45, 45])),
            ]),
        ]);
        let SynValue::Map(m1) = multipart_encode(&[parts.clone()]).ok().unwrap() else { panic!() };
        let SynValue::Map(m2) = multipart_encode(&[parts]).ok().unwrap() else { panic!() };
        let body = match m1.borrow().get("body") { Some(SynValue::Bytes(b)) => b.to_vec(), _ => panic!() };
        let body2 = match m2.borrow().get("body") { Some(SynValue::Bytes(b)) => b.to_vec(), _ => panic!() };
        assert_eq!(body, body2, "determinista");
        let ct = m1.borrow().get("content_type").unwrap().to_string();
        let boundary = crate::routing::multipart_boundary(&ct).expect("boundary");
        let parsed = crate::routing::parse_multipart(&boundary, &body);
        assert_eq!(parsed.len(), 2, "{:?}", String::from_utf8_lossy(&body));
        let e = multipart_encode(&[syn_list(vec![map(&[("name", syn_text("x"))])])]);
        assert!(matches!(e, Err(_)), "una parte sin value ni bytes es error");
    }
}
