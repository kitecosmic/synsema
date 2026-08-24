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



use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};

// Lo puro del cliente (gate net, forma de respuesta, parsers de args, registro de
// los seis builtins) vive en http_common y se comparte con el perfil wasm.
pub use crate::http_common::{err_result, header_pairs, require_net, HttpResult};
#[allow(unused_imports)]
use crate::http_common::{
    map_pairs, raw_str, register_http_client_builtins, response_to_syn, timeout_arg, url_with_query,
    urlencode,
};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
#[allow(unused_imports)]
use synsema_core::types::{syn_bool, syn_float, syn_int, syn_nothing, syn_text, SynValue};

/// Petición HTTP. Devuelve la respuesta o un resultado de error (nunca panica).
pub fn http_request(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> HttpResult {
    let full_url = url_with_query(url, query);
    match do_request(method, &full_url, headers, body.map(str::as_bytes), timeout_secs) {
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

// =========================================================
// T5 — Identidad mTLS del cliente (SPIFFE-like)
// =========================================================

/// La identidad de cliente TLS de ESTE proceso: cadena de certs + clave privada,
/// ya parseadas. `None` = sin identidad (comportamiento histórico, byte-idéntico).
///
/// Es del PROCESO y no de cada request a propósito: en una malla de servicios el
/// certificado identifica al *workload* (el agente), no a la llamada — es la misma
/// idea que SPIFFE, y la misma tesis de identidad de agente del diseño. Además
/// evita colgar un slot de opciones nuevo en los seis builtins `http_*`.
type ClientIdentity = (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
);

fn client_identity() -> &'static std::sync::Mutex<Option<ClientIdentity>> {
    static ID: std::sync::OnceLock<std::sync::Mutex<Option<ClientIdentity>>> =
        std::sync::OnceLock::new();
    ID.get_or_init(|| std::sync::Mutex::new(None))
}

/// Hosts a los que SÍ se le presenta la identidad mTLS (`opts.hosts` de
/// `mtls_identity`). Vacío = a cualquier host que el programa pueda alcanzar (que
/// ya está acotado por `require net(...)`).
fn client_identity_hosts() -> &'static std::sync::Mutex<Vec<String>> {
    static HOSTS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    HOSTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// ¿Se le presenta el certificado de cliente a este host? Sin `hosts` declarados,
/// a todos (comportamiento base). Con ellos, sólo a los que matcheen — mismo
/// criterio de comodín que `require net`: `*.dominio` cubre subdominios.
fn identity_applies_to(host: &str, scopes: &[String]) -> bool {
    if scopes.is_empty() {
        return true;
    }
    let host = host.trim().to_ascii_lowercase();
    scopes.iter().any(|s| {
        let s = s.trim().to_ascii_lowercase();
        match s.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{}", suffix)),
            None => host == s,
        }
    })
}

/// Construye la `ClientConfig` de rustls para UN host: con auth de cliente sólo si
/// el proceso declaró identidad mTLS y ese host está en su alcance.
///
/// El certificado de cliente es la identidad del workload: presentarlo es decir
/// "yo soy este agente". Por eso el alcance es por host y no global — un servidor
/// cualquiera que pida cert de cliente no debería poder cosechar la identidad sólo
/// por pedirla. Sin `hosts` el alcance son los hosts que `require net` ya permite.
fn tls_client_config(host: &str) -> Result<rustls::ClientConfig, String> {
    let roots = root_cert_store()?;
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let guard = client_identity().lock().map_err(|_| "TLS identity lock poisoned".to_string())?;
    let scopes =
        client_identity_hosts().lock().map_err(|_| "TLS identity lock poisoned".to_string())?;
    match guard.as_ref() {
        Some((certs, key)) if identity_applies_to(host, &scopes) => builder
            .with_client_auth_cert(certs.clone(), key.clone_key())
            .map_err(|e| format!("the client certificate/key pair was rejected by TLS: {}", e)),
        _ => Ok(builder.with_no_client_auth()),
    }
}

/// Lee la cadena de certificados PEM del cliente. Errores claros: un PEM vacío o
/// ilegible es un fallo de configuración, no algo que se degrade en silencio.
fn load_client_certs(
    path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Control> {
    let file = std::fs::File::open(path).map_err(|e| {
        Control::Error(RuntimeError::new(format!(
            "mtls_identity: cannot read the certificate {:?}: {}",
            path, e
        )))
    })?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(file))
        .collect::<Result<_, _>>()
        .map_err(|e| {
            Control::Error(RuntimeError::new(format!(
                "mtls_identity: {:?} is not a valid PEM certificate chain: {}",
                path, e
            )))
        })?;
    if certs.is_empty() {
        return Err(Control::Error(RuntimeError::new(format!(
            "mtls_identity: {:?} has no certificates (expected a PEM chain)",
            path
        ))));
    }
    Ok(certs)
}

/// Lee la clave privada PEM del cliente (PKCS#8, PKCS#1 o SEC1). El contenido
/// jamás se loguea ni entra en un mensaje de error.
fn load_client_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Control> {
    let file = std::fs::File::open(path).map_err(|e| {
        Control::Error(RuntimeError::new(format!(
            "mtls_identity: cannot read the private key {:?}: {}",
            path, e
        )))
    })?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(file))
        .map_err(|_| {
            Control::Error(RuntimeError::new(format!(
                "mtls_identity: {:?} is not a valid PEM private key (the key content is never shown)",
                path
            )))
        })?
        .ok_or_else(|| {
            Control::Error(RuntimeError::new(format!(
                "mtls_identity: {:?} contains no private key",
                path
            )))
        })
}

/// Carga los root CAs del SO una vez y los devuelve como `RootCertStore`.
/// `pub(crate)`: ws.rs (cliente WebSocket) usa el MISMO trust store para `wss://`.
pub(crate) fn root_cert_store() -> Result<rustls::RootCertStore, String> {
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

fn build_http_request(method: &str, path: &str, host: &str, headers: Option<&[(String, String)]>, body: Option<&[u8]>) -> Vec<u8> {
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
    let mut out = req.into_bytes();
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    out
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
    body: Option<&[u8]>,
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
        // Con identidad mTLS declarada (`mtls_identity`), el handshake presenta el
        // certificado del workload; sin ella, exactamente como antes.
        let config = tls_client_config(&host)?;
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
    body: Option<&[u8]>,
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
    let mut stream = connect_and_send(method, url, headers, body.map(str::as_bytes), timeout_secs)?;
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
    body: Option<&[u8]>,
    timeout_secs: u64,
) -> Result<HttpResult, String> {
    let buf = fetch_raw(method, url, headers, body, timeout_secs)?;
    parse_response(&buf)
}

/// Como `http_request` pero con el body como **bytes crudos** (para POSTear
/// binarios sin corromperlos, p.ej. el SignedTxn msgpack de Algorand a
/// `/v2/transactions` con `application/x-binary`). `pub(crate)`: lo usa
/// blockchain_rpc.rs; el gate `net(host)` corre en el caller.
pub(crate) fn http_request_body_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: &[u8],
    timeout_secs: u64,
) -> HttpResult {
    match do_request(method, url, headers, Some(body), timeout_secs) {
        Ok(r) => r,
        Err(e) => err_result(e),
    }
}

/// Respuesta HTTP con body binario: `(status, body_bytes, headers)`.
pub type BytesResponse = (i64, Vec<u8>, Vec<(String, String)>);

/// Como `http_request` pero devuelve el body como **bytes crudos** (sin pasar por
/// `String`, que corrompería un binario). Para descargar release assets. Devuelve
/// `(status, body_bytes, headers)`. No sigue redirects — el caller los maneja.
pub fn http_request_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    timeout_secs: u64,
) -> Result<BytesResponse, String> {
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
fn parse_response_bytes(buf: &[u8]) -> Result<BytesResponse, String> {
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

pub fn register_http_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // T5 — mtls_identity(cert_path, key_path) → true. Declara la identidad de
    // cliente TLS de ESTE proceso: a partir de acá, todo `https://` presenta ese
    // certificado en el handshake (mallas de servicios, APIs bancarias, SPIFFE).
    //
    // Gateada por `file.read` sobre AMBAS rutas: leer una clave privada del disco
    // es una lectura de archivo y se declara como tal (no se inventa una capability
    // nueva — G: cero capabilities nuevas si una existente cubre el efecto).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "mtls_identity",
            -1,
            Rc::new(move |_i, args, _loc| {
                if !(2..=3).contains(&args.len()) {
                    return Err(Control::Error(RuntimeError::new(
                        "mtls_identity(cert_path, key_path, opts?) takes 2 or 3 arguments",
                    )));
                }
                let cert_path = match args.first() {
                    Some(SynValue::Text(s)) if !s.trim().is_empty() => s.trim().to_string(),
                    _ => {
                        return Err(Control::Error(RuntimeError::new(
                            "mtls_identity(cert_path, key_path, opts?): the certificate path must be a non-empty text",
                        )))
                    }
                };
                let key_path = match args.get(1) {
                    Some(SynValue::Text(s)) if !s.trim().is_empty() => s.trim().to_string(),
                    _ => {
                        return Err(Control::Error(RuntimeError::new(
                            "mtls_identity(cert_path, key_path, opts?): the key path must be a non-empty text",
                        )))
                    }
                };
                // opts.hosts — a QUÉ hosts se le presenta esta identidad. Sin la
                // opción, a los que `require net` ya permita.
                let mut hosts: Vec<String> = Vec::new();
                match args.get(2) {
                    None | Some(SynValue::Nothing) => {}
                    Some(SynValue::Map(m)) => {
                        for (k, v) in m.borrow().iter() {
                            if k != "hosts" {
                                return Err(Control::Error(RuntimeError::new(format!(
                                    "mtls_identity: unknown option {:?} (valid options: hosts)",
                                    k
                                ))));
                            }
                            match v {
                                SynValue::List(l) => {
                                    for h in l.borrow().iter() {
                                        let h = raw_str(h).trim().to_string();
                                        if h.is_empty() {
                                            return Err(Control::Error(RuntimeError::new(
                                                "mtls_identity: hosts entries must be non-empty text (e.g. \"*.mesh.internal\")",
                                            )));
                                        }
                                        hosts.push(h);
                                    }
                                }
                                SynValue::Text(s) if !s.trim().is_empty() => {
                                    hosts.push(s.trim().to_string())
                                }
                                other => {
                                    return Err(Control::Error(RuntimeError::new(format!(
                                        "mtls_identity: hosts must be a list of hosts (or one host as text), got {}",
                                        other.type_name()
                                    ))))
                                }
                            }
                        }
                    }
                    Some(other) => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "mtls_identity: opts must be a map, got {}",
                            other.type_name()
                        ))))
                    }
                }
                for p in [&cert_path, &key_path] {
                    caps.borrow_mut()
                        .require(
                            &Capability::new(CapabilityType::FileRead, Some(p.clone())),
                            "mtls_identity()",
                        )
                        .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
                }
                let certs = load_client_certs(&cert_path)?;
                let key = load_client_key(&key_path)?;
                match (client_identity().lock(), client_identity_hosts().lock()) {
                    (Ok(mut guard), Ok(mut scope)) => {
                        *guard = Some((certs, key));
                        *scope = hosts;
                    }
                    _ => {
                        return Err(Control::Error(RuntimeError::new(
                            "mtls_identity: the TLS identity lock is poisoned",
                        )))
                    }
                }
                Ok(syn_bool(true))
            }),
        );
    }

    // Los seis builtins cliente (http/http_get/http_post/http_put/http_delete/fetch):
    // registro compartido con el perfil wasm (http_common), transporte = sockets.
    register_http_client_builtins(interp, caps, http_request);
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

    /// El certificado de cliente es la identidad del workload: sólo se presenta a
    /// los hosts declarados en `opts.hosts` (sin la opción, a todos los que
    /// `require net` permita).
    #[test]
    fn mtls_identity_is_scoped_to_its_hosts() {
        // Sin alcance declarado: se presenta a cualquier host alcanzable.
        assert!(identity_applies_to("api.example.com", &[]));
        // Host exacto.
        let exact = vec!["api.bank.example".to_string()];
        assert!(identity_applies_to("api.bank.example", &exact));
        assert!(identity_applies_to("API.Bank.Example", &exact), "el host no es case-sensitive");
        assert!(!identity_applies_to("evil.example", &exact));
        // Comodín de subdominios, igual que `require net("*.dominio")`.
        let wild = vec!["*.mesh.internal".to_string()];
        assert!(identity_applies_to("payments.mesh.internal", &wild));
        assert!(identity_applies_to("a.b.mesh.internal", &wild));
        assert!(identity_applies_to("mesh.internal", &wild), "el dominio raíz también");
        assert!(!identity_applies_to("mesh.internal.evil.com", &wild), "sufijo falso");
        assert!(!identity_applies_to("notmesh.internal", &wild));
        // Varios alcances a la vez.
        let many = vec!["*.mesh.internal".to_string(), "vault.example".to_string()];
        assert!(identity_applies_to("vault.example", &many));
        assert!(identity_applies_to("x.mesh.internal", &many));
        assert!(!identity_applies_to("other.example", &many));
    }
}
