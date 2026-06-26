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

/// Conecta (TCP, o TLS para `https`), envía el request y lee la respuesta cruda
/// (head + body) hasta EOF. Base compartida por `do_request` (→ `String`) y
/// `http_request_bytes` (→ bytes crudos, para descargar binarios sin corromperlos).
fn fetch_raw(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<Vec<u8>, String> {
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
        read_to_end_tolerant(&mut stream, &mut buf)?;
    } else {
        let mut stream = tcp;
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        read_to_end_tolerant(&mut stream, &mut buf)?;
    }
    Ok(buf)
}

fn do_request(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<HttpResult, String> {
    let buf = fetch_raw(method, url, headers, body, timeout_secs)?;
    parse_response(&buf)
}

/// Como `http_request` pero devuelve el body como **bytes crudos** (sin pasar por
/// `String`, que corrompería un binario). Para descargar release assets. Devuelve
/// `(status, body_bytes, headers)`. No sigue redirects — el caller los maneja.
pub fn http_request_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    timeout_secs: u64,
) -> Result<(i64, Vec<u8>, Vec<(String, String)>), String> {
    let buf = fetch_raw(method, url, headers, None, timeout_secs)?;
    parse_response_bytes(&buf)
}

/// Igual que `parse_response` pero devuelve el body como bytes crudos (para binarios).
fn parse_response_bytes(buf: &[u8]) -> Result<(i64, Vec<u8>, Vec<(String, String)>), String> {
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let head = String::from_utf8_lossy(&buf[..split]);
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
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let body_bytes = &buf[split + 4..];
    let body = if chunked { dechunk_bytes(body_bytes) } else { body_bytes.to_vec() };
    Ok((status, body, headers))
}

/// Lee hasta EOF tolerando el cierre sin `close_notify`. rustls es estricto: si el peer
/// cierra el TLS sin el alert `close_notify` (común en muchos servidores/LBs, p.ej.
/// MiniMax) devuelve `UnexpectedEof` — pero con `Connection: close` los bytes recibidos
/// ya son la respuesta completa. Sólo es error real si NO se recibió nada.
fn read_to_end_tolerant<R: Read>(stream: &mut R, buf: &mut Vec<u8>) -> Result<(), String> {
    match stream.read_to_end(buf) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn parse_response(buf: &[u8]) -> Result<HttpResult, String> {
    let text = String::from_utf8_lossy(buf);
    // El head es ASCII → el offset de char en `text` == offset de byte en `buf`.
    let split = text.find("\r\n\r\n").ok_or_else(|| "malformed HTTP response".to_string())?;
    let head = &text[..split];
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
    // De-chunk si la respuesta es `Transfer-Encoding: chunked` (HTTP/1.1 sin
    // Content-Length — p.ej. la API de Anthropic). El body crudo trae los prefijos de
    // tamaño hex por chunk; sin des-chunkear NO es JSON válido.
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let body_bytes = &buf[split + 4..];
    let body = if chunked {
        dechunk_body(body_bytes)
    } else {
        String::from_utf8_lossy(body_bytes).to_string()
    };
    Ok(HttpResult {
        status,
        ok: (200..300).contains(&status),
        body,
        headers,
        error: None,
    })
}

/// Des-chunkea un body `Transfer-Encoding: chunked` a `String` (texto).
fn dechunk_body(data: &[u8]) -> String {
    String::from_utf8_lossy(&dechunk_bytes(data)).to_string()
}

/// Des-chunkea un body `Transfer-Encoding: chunked` a bytes: cada chunk es
/// `<hex>\r\n<datos>\r\n` y termina con un chunk de tamaño 0. Concatena los datos
/// (ignora trailers). Opera en bytes para servir tanto a texto como a binarios.
fn dechunk_bytes(mut data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    while let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&data[..line_end]);
        // El tamaño puede traer extensiones tras `;` — quedate sólo con el hex.
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(hex, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = start + size;
        if end > data.len() {
            out.extend_from_slice(&data[start..]);
            break;
        }
        out.extend_from_slice(&data[start..end]);
        // Saltá los datos + el `\r\n` que cierra el chunk.
        data = if end + 2 <= data.len() { &data[end + 2..] } else { &[] };
    }
    out
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
    fn parse_response_dechunks_chunked_body() {
        // Respuesta HTTP/1.1 `Transfer-Encoding: chunked` (como Anthropic sobre 1.1):
        // dos chunks de 5 bytes → el body crudo trae los prefijos de tamaño; debe
        // des-chunkearse a JSON limpio y concatenado.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n5\r\n\"bc\"}\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{\"a\":\"bc\"}");
    }

    #[test]
    fn parse_response_nonchunked_unchanged() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, "{\"a\":1}");
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
