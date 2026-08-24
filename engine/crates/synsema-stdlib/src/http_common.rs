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
use synsema_core::types::{syn_bool, syn_int, syn_map, syn_text, SynValue};

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
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// Respuesta estructurada (espeja el dict del oráculo).
pub struct HttpResult {
    pub status: i64,
    pub ok: bool,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub error: Option<String>,
}

pub fn err_result(error: String) -> HttpResult {
    HttpResult {
        status: 0,
        ok: false,
        body: String::new(),
        headers: Vec::new(),
        error: Some(error),
    }
}

/// Transporte de una request: (method, url, headers, query, body, timeout_secs).
/// Nativo = sockets; wasm = el `http` del host (o el stub "sin transporte").
pub type Transport = fn(
    &str,
    &str,
    Option<&[(String, String)]>,
    Option<&[(String, String)]>,
    Option<&str>,
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

pub fn response_to_syn(r: HttpResult) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("status".to_string(), syn_int(r.status));
    m.insert("ok".to_string(), syn_bool(r.ok));
    m.insert("body".to_string(), syn_text(r.body));
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
                let headers = header_pairs(args.get(2));
                let query = map_pairs(args.get(3));
                let body = args.get(4).map(raw_str);
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
                let body = args.get(1).map(raw_str);
                let headers = header_pairs(args.get(2));
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
                let body = args.get(1).map(raw_str);
                let headers = header_pairs(args.get(2));
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
                let headers = header_pairs(args.get(2));
                let body = args.get(3).map(raw_str);
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
}
