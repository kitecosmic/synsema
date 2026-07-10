//! HTTP nativo. Port de `synsema/stdlib/http.py`.
//!
//! Cliente mínimo: `http://` usa `std::net::TcpStream` directo; `https://` envuelve
//! el mismo stream con `rustls` (ring + root CAs del SO). La lógica de HTTP/1.1 es
//! idéntica en ambos caminos — solo el stream subyacente cambia.
//!
//! Nota: TODO el HTTP (`http`/`http_get`/`http_post`/`http_put`/`http_delete`/`fetch`)
//! es deny-by-default — gateado por `net(host)` (egress real, como file/db). El host es
//! el hostname del URL (minúsculas, sin puerto), no el URL completo.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;


use indexmap::IndexMap;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_int, syn_map, syn_text, SynValue};

/// Chequea la capability `net(host)` del URL; convierte la violación en `Control::Error`
/// SIN ubicación (como secure.rs/database.rs). Scope = hostname (minúsculas, sin puerto);
/// si no se puede extraer, se usa el URL crudo (fail-closed). `net` NO es tipo-ruta →
/// `covers()` usa el glob de host (`net("*.example.com")` cubre `api.example.com`).
fn require_net(caps: &Rc<RefCell<CapabilitySet>>, url: &str, source: &str) -> Result<(), Control> {
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

/// Conecta (TCP, o TLS para `https`) y envía el request; devuelve el stream listo
/// para leer la respuesta (un `Box<dyn Read>` unifica los dos brazos — la lógica de
/// HTTP/1.1 es idéntica, solo el transporte cambia). Base compartida por `fetch_raw`
/// (lee hasta EOF) y `http_request_stream` (lee incrementalmente). El read/write
/// timeout del socket aplica POR operación, no a la duración total.
fn connect_and_send(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<Box<dyn Read>, String> {
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
        Ok(Box::new(stream))
    } else {
        let mut stream = tcp;
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        Ok(Box::new(stream))
    }
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
    let mut stream = connect_and_send(method, url, headers, body, timeout_secs)?;
    let mut buf = Vec::new();
    read_to_end_tolerant(&mut stream, &mut buf)?;
    Ok(buf)
}

/// Como `http_request` pero entrega el BODY incrementalmente: parsea el head, y va
/// invocando `on_data` con cada tramo de body YA des-chunkeado a medida que llega.
/// `on_data` devuelve `false` para abortar la lectura (el caller corta). Devuelve
/// `(status, headers)` al terminar (EOF o abort). El read-timeout del socket aplica
/// POR `read()` → mide **silencio** entre bytes, no duración total: una respuesta
/// larga que gotea fluye; un host mudo sigue fallando al timeout.
///
/// Tolerancia EOF: mismo criterio que `read_to_end_tolerant` — un `UnexpectedEof`
/// durante el body (head ya recibido) NO es error (peers que cierran TLS sin
/// `close_notify`, p.ej. MiniMax).
pub fn http_request_stream(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
    on_data: &mut dyn FnMut(&[u8]) -> bool,
) -> Result<(i64, Vec<(String, String)>), String> {
    let mut stream = connect_and_send(method, url, headers, body, timeout_secs)?;
    let mut read_buf = [0u8; 8192];

    // Fase 1: acumular hasta el fin del head (`\r\n\r\n`) y parsearlo. Un EOF antes
    // de completar el head sí es error (respuesta malformada, como en parse_response).
    let mut acc: Vec<u8> = Vec::new();
    let (status, resp_headers, leftover) = loop {
        match stream.read(&mut read_buf) {
            Ok(0) => return Err("malformed HTTP response".to_string()),
            Ok(n) => {
                acc.extend_from_slice(&read_buf[..n]);
                if let Some(split) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&acc[..split]).to_string();
                    let (status, headers) = parse_head(&head);
                    break (status, headers, acc.split_off(split + 4));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err("malformed HTTP response".to_string())
            }
            Err(e) => return Err(e.to_string()),
        }
    };

    // Fase 2: body incremental, des-chunkeado al vuelo si corresponde.
    let chunked = resp_headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let mut decoder = ChunkDecoder::new();
    let mut push = |raw: &[u8], on_data: &mut dyn FnMut(&[u8]) -> bool| -> bool {
        let bytes = if chunked { decoder.feed(raw) } else { raw.to_vec() };
        bytes.is_empty() || on_data(&bytes)
    };
    if !push(&leftover, on_data) {
        return Ok((status, resp_headers));
    }
    loop {
        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                if !push(&read_buf[..n], on_data) {
                    break;
                }
            }
            // Head + bytes ya recibidos → cierre sin close_notify tolerado.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok((status, resp_headers))
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

/// Parsea el head crudo de una respuesta HTTP/1.1 (status-line + headers, SIN el
/// `\r\n\r\n` final) → `(status, headers)`. Compartido por `parse_response`,
/// `parse_response_bytes` y `http_request_stream`.
fn parse_head(head: &str) -> (i64, Vec<(String, String)>) {
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
    (status, headers)
}

/// Igual que `parse_response` pero devuelve el body como bytes crudos (para binarios).
fn parse_response_bytes(buf: &[u8]) -> Result<(i64, Vec<u8>, Vec<(String, String)>), String> {
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let (status, headers) = parse_head(&String::from_utf8_lossy(&buf[..split]));
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
    let (status, headers) = parse_head(&text[..split]);
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
/// Una pasada = `ChunkDecoder::feed` con el buffer completo (misma salida de siempre).
fn dechunk_bytes(data: &[u8]) -> Vec<u8> {
    ChunkDecoder::new().feed(data)
}

/// Estado del de-chunker incremental (para `http_request_stream`, donde los chunks
/// llegan partidos en cualquier punto entre `read()`s). Tolerancia idéntica al
/// de-chunk histórico: tamaño hex inválido → corta y devuelve lo acumulado (no es
/// error); datos truncados → entrega los bytes parciales que hayan llegado.
struct ChunkDecoder {
    /// Bytes crudos aún no decodificados (fragmento de línea de tamaño o de trailer).
    buf: Vec<u8>,
    state: ChunkState,
}

enum ChunkState {
    /// Esperando la línea `<hex>\r\n` con el tamaño del próximo chunk.
    Size,
    /// Leyendo los datos del chunk actual (faltan `remaining` bytes).
    Data { remaining: usize },
    /// Saltando el `\r\n` que cierra el chunk (faltan `remaining` bytes).
    Skip { remaining: usize },
    /// Chunk de tamaño 0 (o tamaño inválido): fin — el resto se ignora (trailers).
    Done,
}

impl ChunkDecoder {
    fn new() -> Self {
        Self { buf: Vec::new(), state: ChunkState::Size }
    }

    /// Alimenta bytes crudos; devuelve los datos de chunk decodificados hasta ahora
    /// (los datos se emiten a medida que llegan — no se espera el chunk completo).
    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        if matches!(self.state, ChunkState::Done) {
            return Vec::new();
        }
        self.buf.extend_from_slice(input);
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.state {
                ChunkState::Size => {
                    let Some(line_end) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                        break;
                    };
                    // El tamaño puede traer extensiones tras `;` — quedate sólo con el hex.
                    let size_line = String::from_utf8_lossy(&self.buf[..line_end]).to_string();
                    let hex = size_line.split(';').next().unwrap_or("").trim().to_string();
                    self.buf.drain(..line_end + 2);
                    match usize::from_str_radix(&hex, 16) {
                        Ok(0) | Err(_) => {
                            self.state = ChunkState::Done;
                            break;
                        }
                        Ok(size) => self.state = ChunkState::Data { remaining: size },
                    }
                }
                ChunkState::Data { remaining } => {
                    if self.buf.is_empty() {
                        break;
                    }
                    let take = remaining.min(self.buf.len());
                    out.extend_from_slice(&self.buf[..take]);
                    self.buf.drain(..take);
                    if take == remaining {
                        // Saltá el `\r\n` que cierra el chunk.
                        self.state = ChunkState::Skip { remaining: 2 };
                    } else {
                        self.state = ChunkState::Data { remaining: remaining - take };
                        break;
                    }
                }
                ChunkState::Skip { remaining } => {
                    if self.buf.is_empty() {
                        break;
                    }
                    let take = remaining.min(self.buf.len());
                    self.buf.drain(..take);
                    if take == remaining {
                        self.state = ChunkState::Size;
                    } else {
                        self.state = ChunkState::Skip { remaining: remaining - take };
                        break;
                    }
                }
                ChunkState::Done => break,
            }
        }
        out
    }
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

/// Timeout opcional de las builtins HTTP (MF-012): número positivo → segundos (piso 1);
/// ausente/`Nothing`/inválido (0, negativo, texto) → 30, el default histórico. Tolerante
/// como los knobs: un valor inválido cae al default, no es error.
fn timeout_arg(v: Option<&SynValue>) -> u64 {
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

pub fn register_http_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
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
                let r = http_request(
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
                let r = http_request(
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
                let r = http_request(
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
                let r = http_request(
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
                let r = http_request(
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
                let r = http_request(
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

    // -- MF-012: timeout_arg --

    #[test]
    fn timeout_arg_valid_and_defaults() {
        use synsema_core::types::{syn_float, syn_nothing};
        // Válidos: enteros y floats positivos (piso 1 segundo).
        assert_eq!(timeout_arg(Some(&syn_int(120))), 120);
        assert_eq!(timeout_arg(Some(&syn_int(1))), 1);
        assert_eq!(timeout_arg(Some(&syn_float(0.5))), 1, "positivo chico → piso 1");
        // Inválidos/ausentes → 30 (default histórico, tolerante).
        assert_eq!(timeout_arg(Some(&syn_int(0))), 30);
        assert_eq!(timeout_arg(Some(&syn_int(-5))), 30);
        assert_eq!(timeout_arg(Some(&syn_text("abc"))), 30);
        assert_eq!(timeout_arg(Some(&syn_nothing())), 30);
        assert_eq!(timeout_arg(None), 30);
    }

    // -- ChunkDecoder: una pasada == dechunk_bytes histórico; incremental == misma salida --

    const CHUNKED_BODY: &[u8] = b"5\r\n{\"a\":\r\n5\r\n\"bc\"}\r\n0\r\n\r\n";

    #[test]
    fn chunk_decoder_one_pass_matches_dechunk() {
        assert_eq!(dechunk_bytes(CHUNKED_BODY), b"{\"a\":\"bc\"}");
        // Extensión tras `;` en la línea de tamaño.
        assert_eq!(dechunk_bytes(b"5;ext=1\r\nhola!\r\n0\r\n\r\n"), b"hola!");
        // Hex inválido → corta y devuelve lo acumulado (no error).
        assert_eq!(dechunk_bytes(b"5\r\nhola!\r\nZZ\r\nresto"), b"hola!");
        // Chunk final truncado → conserva los bytes parciales.
        assert_eq!(dechunk_bytes(b"a\r\nsolo4"), b"solo4");
    }

    #[test]
    fn chunk_decoder_incremental_any_split_same_output() {
        for step in [1usize, 3, 7, CHUNKED_BODY.len()] {
            let mut dec = ChunkDecoder::new();
            let mut out = Vec::new();
            for piece in CHUNKED_BODY.chunks(step) {
                out.extend_from_slice(&dec.feed(piece));
            }
            assert_eq!(out, b"{\"a\":\"bc\"}", "split de {} bytes", step);
        }
    }

    // -- http_request_stream contra un TcpListener local --

    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration as TestDuration, Instant};

    /// Server fake de un solo accept: ejecuta `serve` sobre el socket aceptado.
    fn one_shot_server(
        serve: impl FnOnce(std::net::TcpStream) + Send + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                serve(sock);
            }
        });
        (format!("http://127.0.0.1:{}/", port), handle)
    }

    /// Lee y descarta el request entrante (hasta el fin del head; el GET no trae body).
    fn drain_request(sock: &mut std::net::TcpStream) {
        let mut buf = [0u8; 4096];
        let mut acc: Vec<u8> = Vec::new();
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    #[test]
    fn http_request_stream_chunked_in_batches() {
        let (url, handle) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .unwrap();
            sock.write_all(b"5\r\n{\"a\":\r\n").unwrap();
            thread::sleep(TestDuration::from_millis(100));
            sock.write_all(b"5\r\n\"bc\"}\r\n").unwrap();
            thread::sleep(TestDuration::from_millis(100));
            sock.write_all(b"0\r\n\r\n").unwrap();
        });
        let mut batches: Vec<Vec<u8>> = Vec::new();
        let (status, headers) =
            http_request_stream("GET", &url, None, None, 5, &mut |bytes| {
                batches.push(bytes.to_vec());
                true
            })
            .unwrap();
        handle.join().unwrap();
        assert_eq!(status, 200);
        assert!(headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")));
        assert!(batches.len() >= 2, "esperaba ≥2 tandas, llegaron {}", batches.len());
        let total: Vec<u8> = batches.concat();
        assert_eq!(total, b"{\"a\":\"bc\"}");
    }

    #[test]
    fn http_request_stream_abort_on_false() {
        let (url, _handle) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .unwrap();
            sock.write_all(b"5\r\nhola!\r\n").unwrap();
            // El resto no debería leerse: el cliente aborta en la primera tanda.
            thread::sleep(TestDuration::from_millis(200));
            let _ = sock.write_all(b"5\r\nchau!\r\n0\r\n\r\n");
        });
        let mut seen: Vec<u8> = Vec::new();
        let (status, _) = http_request_stream("GET", &url, None, None, 5, &mut |bytes| {
            seen.extend_from_slice(bytes);
            false
        })
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(seen, b"hola!", "debe cortar tras la primera tanda");
    }

    // El caso clave del bug MF-011: el read-timeout mide SILENCIO, no duración total.
    #[test]
    fn http_request_stream_timeout_is_silence_not_total_duration() {
        // (1) Silencio real: el server no manda NADA por 3s con timeout de 1s → falla.
        let (url, _h) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            thread::sleep(TestDuration::from_secs(3));
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });
        let start = Instant::now();
        let r = http_request_stream("GET", &url, None, None, 1, &mut |_| true);
        assert!(r.is_err(), "silencio de 3s con timeout 1s debe fallar");
        assert!(
            start.elapsed() < TestDuration::from_secs(3),
            "debe fallar por timeout, no esperar al server"
        );

        // (2) Goteo: un byte por segundo durante 3s con timeout de 2s → completa OK
        //     (cada byte renueva el read-timeout; con el camino no-stream fallaría si
        //     la duración total excediera el timeout).
        let (url2, h2) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
            for b in [b"a", b"b", b"c"] {
                thread::sleep(TestDuration::from_secs(1));
                sock.write_all(b).unwrap();
            }
        });
        let mut body: Vec<u8> = Vec::new();
        let (status, _) = http_request_stream("GET", &url2, None, None, 2, &mut |bytes| {
            body.extend_from_slice(bytes);
            true
        })
        .expect("el goteo lento debe completar: el timeout mide silencio");
        h2.join().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"abc");
    }

    // MF-012 (integración): un server que acepta y NO responde corta al timeout pedido.
    #[test]
    fn http_request_short_timeout_cuts_fast() {
        let (url, _h) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            thread::sleep(TestDuration::from_secs(5));
        });
        let start = Instant::now();
        let r = http_request("GET", &url, None, None, None, 1);
        assert!(!r.ok);
        assert!(r.error.is_some());
        assert!(
            start.elapsed() < TestDuration::from_secs(4),
            "timeout de 1s no debe esperar los 30s del default"
        );
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
