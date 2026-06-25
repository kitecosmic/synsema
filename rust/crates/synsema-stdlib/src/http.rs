//! HTTP nativo. Port de `synsema/stdlib/http.py`.
//!
//! Cliente mínimo: `http://` usa `std::net::TcpStream` directo; `https://` envuelve
//! el mismo stream con `rustls` (ring + root CAs del SO). La lógica de HTTP/1.1 es
//! idéntica en ambos caminos — solo el stream subyacente cambia.
//!
//! Nota: `http`/`http_get`/`http_post`/… NO chequean capability (a diferencia de
//! `fetch`, que sí). Es el contrato del oráculo.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;


use indexmap::IndexMap;

use synsema_core::interpreter::Interpreter;
use synsema_core::types::{syn_bool, syn_int, syn_map, syn_text, SynValue};

/// Respuesta estructurada (espeja el dict del oráculo).
pub struct HttpResult {
    pub status: i64,
    pub ok: bool,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub error: Option<String>,
}

fn err_result(error: String) -> HttpResult {
    HttpResult {
        status: 0,
        ok: false,
        body: String::new(),
        headers: Vec::new(),
        error: Some(error),
    }
}

/// Petición HTTP. Devuelve la respuesta o un resultado de error (nunca panica).
pub fn http_request(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> HttpResult {
    // URL con query.
    let full_url = match query {
        Some(q) if !q.is_empty() => {
            let sep = if url.contains('?') { "&" } else { "?" };
            format!("{}{}{}", url, sep, urlencode(q))
        }
        _ => url.to_string(),
    };
    match do_request(method, &full_url, headers, body, timeout_secs) {
        Ok(r) => r,
        Err(e) => err_result(e),
    }
}

fn parse_url(url: &str) -> Result<(String, String, u16, String), String> {
    let idx = url.find("://").ok_or_else(|| "invalid URL (no scheme)".to_string())?;
    let scheme = url[..idx].to_lowercase();
    let rest = &url[idx + 3..];
    let path_start = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let path = if path_start < rest.len() { &rest[path_start..] } else { "/" };
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let h = authority[..i].to_string();
            let p: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| format!("invalid port in URL: {}", authority))?;
            (h, p)
        }
        None => (
            authority.to_string(),
            if scheme == "https" { 443 } else { 80 },
        ),
    };
    Ok((scheme, host, port, path.to_string()))
}

/// Carga los root CAs del SO una vez y los devuelve como `RootCertStore`.
fn root_cert_store() -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    // Los errores de carga parcial no son fatales — usamos los que sí cargaron.
    for cert in native.certs {
        let _ = roots.add(cert); // ignora certs mal formados individualmente
    }
    if roots.is_empty() {
        return Err("no root CAs found in system store".to_string());
    }
    Ok(roots)
}

fn build_http_request(method: &str, path: &str, host: &str, headers: Option<&[(String, String)]>, body: Option<&str>) -> Vec<u8> {
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method.to_uppercase(),
        path,
        host
    );
    if let Some(hs) = headers {
        for (k, v) in hs {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    req.into_bytes()
}

fn do_request(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<HttpResult, String> {
    let (scheme, host, port, path) = parse_url(url)?;
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme '{}': only http and https are supported", scheme));
    }

    let addr = format!("{}:{}", host, port);
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("could not resolve host: {}", host))?;
    let timeout = Duration::from_secs(timeout_secs);
    let tcp = TcpStream::connect_timeout(&sa, timeout).map_err(|e| e.to_string())?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let req_bytes = build_http_request(method, &path, &host, headers, body);
    let mut buf = Vec::new();

    if scheme == "https" {
        let roots = root_cert_store()?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name: rustls::pki_types::ServerName<'static> = host
            .as_str()
            .try_into()
            .map(|n: rustls::pki_types::ServerName| n.to_owned())
            .map_err(|_| format!("invalid server name: {}", host))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| e.to_string())?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    } else {
        let mut stream = tcp;
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    }

    parse_response(&buf)
}

fn parse_response(buf: &[u8]) -> Result<HttpResult, String> {
    let text = String::from_utf8_lossy(buf);
    let split = text.find("\r\n\r\n").ok_or_else(|| "malformed HTTP response".to_string())?;
    let head = &text[..split];
    let body = &text[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: i64 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if let Some(ci) = line.find(':') {
            headers.push((line[..ci].trim().to_string(), line[ci + 1..].trim().to_string()));
        }
    }
    Ok(HttpResult {
        status,
        ok: (200..300).contains(&status),
        body: body.to_string(),
        headers,
        error: None,
    })
}

fn urlencode(q: &[(String, String)]) -> String {
    q.iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn pct(s: &str) -> String {
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

// -- Builtins (no gateados por capability) --

fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// Map SynValue → pares (clave, str(valor)). Para query params: un `secret` se
/// **redacta** vía Display (fail-closed; los query params terminan en la URL, que se
/// loguea). Para credenciales usar headers + `bearer()`.
fn map_pairs(v: Option<&SynValue>) -> Option<Vec<(String, String)>> {
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

/// Igual que `map_pairs` pero para **headers**: un `secret` (o el resultado de
/// `bearer()`) se materializa a su plaintext SÓLO acá, en el borde del socket — el
/// String vive en el runtime y se escribe al header; nunca vuelve a user-space (§4).
fn header_pairs(v: Option<&SynValue>) -> Option<Vec<(String, String)>> {
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

fn response_to_syn(r: HttpResult) -> SynValue {
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

pub fn register_http_builtins(interp: &Interpreter) {
    // http(method, url, headers?, query?, body?, timeout?)
    interp.register_builtin(
        "http",
        -1,
        Rc::new(move |_i, args, _loc| {
            let method = raw_str(args.first().unwrap_or(&SynValue::Nothing));
            let url = raw_str(args.get(1).unwrap_or(&SynValue::Nothing));
            let headers = header_pairs(args.get(2));
            let query = map_pairs(args.get(3));
            let body = args.get(4).map(raw_str);
            let r = http_request(
                &method,
                &url,
                headers.as_deref(),
                query.as_deref(),
                body.as_deref(),
                30,
            );
            Ok(response_to_syn(r))
        }),
    );

    // http_get(url, headers?, query?)
    interp.register_builtin(
        "http_get",
        -1,
        Rc::new(move |_i, args, _loc| {
            let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
            let headers = header_pairs(args.get(1));
            let query = map_pairs(args.get(2));
            let r = http_request("GET", &url, headers.as_deref(), query.as_deref(), None, 30);
            Ok(response_to_syn(r))
        }),
    );

    // http_post(url, body, headers?)
    interp.register_builtin(
        "http_post",
        -1,
        Rc::new(move |_i, args, _loc| {
            let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
            let body = args.get(1).map(raw_str);
            let headers = header_pairs(args.get(2));
            let r = http_request("POST", &url, headers.as_deref(), None, body.as_deref(), 30);
            Ok(response_to_syn(r))
        }),
    );

    // http_put(url, body, headers?)
    interp.register_builtin(
        "http_put",
        -1,
        Rc::new(move |_i, args, _loc| {
            let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
            let body = args.get(1).map(raw_str);
            let headers = header_pairs(args.get(2));
            let r = http_request("PUT", &url, headers.as_deref(), None, body.as_deref(), 30);
            Ok(response_to_syn(r))
        }),
    );

    // http_delete(url, headers?)
    interp.register_builtin(
        "http_delete",
        -1,
        Rc::new(move |_i, args, _loc| {
            let url = raw_str(args.first().unwrap_or(&SynValue::Nothing));
            let headers = header_pairs(args.get(1));
            let r = http_request("DELETE", &url, headers.as_deref(), None, None, 30);
            Ok(response_to_syn(r))
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_invalid_url() {
        let r = http_request("GET", "http://this-does-not-exist-12345.invalid", None, None, None, 5);
        assert!(!r.ok);
        assert_eq!(r.status, 0);
        assert!(r.error.is_some());
    }

    #[test]
    fn header_pairs_reveal_at_socket_but_map_pairs_redacts() {
        use indexmap::IndexMap;
        use synsema_core::types::{syn_secret, syn_text, SynValue};
        let mut m = IndexMap::new();
        m.insert("Authorization".to_string(), syn_secret("STRIPE_KEY", "Bearer sk_live_LEAKCANARY"));
        m.insert("X-Trace".to_string(), syn_text("plain"));
        let map = SynValue::Map(std::rc::Rc::new(std::cell::RefCell::new(m)));

        // headers: el secret se MATERIALIZA (borde del socket) → plaintext real.
        let hp = header_pairs(Some(&map)).unwrap();
        let auth = hp.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer sk_live_LEAKCANARY");
        assert!(hp.iter().any(|(k, v)| k == "X-Trace" && v == "plain"));

        // query params (map_pairs): el secret se REDACTA (fail-closed; va a la URL).
        let qp = map_pairs(Some(&map)).unwrap();
        let auth = qp.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "secret(STRIPE_KEY)");
        assert!(!auth.1.contains("LEAKCANARY"));
    }
}
