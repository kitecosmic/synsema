//! HTTP nativo. Port de `synsema/stdlib/http.py`.
//!
//! Cliente mínimo: `http://` usa `std::net::TcpStream` directo; `https://` envuelve
//! el mismo stream con `rustls` (ring + root CAs del SO). La lógica de HTTP/1.1 es
//! idéntica en ambos caminos — solo el stream subyacente cambia.
//!
//! Nota: TODO el HTTP (`http`/`http_get`/`http_post`/`http_put`/`http_delete`/`fetch`)
//! es deny-by-default — gateado por `net(host)` (egress real, como file/db). El host es
//! el hostname del URL (minúsculas, sin puerto), no el URL completo.

use synsema_core::synlist::{list_values};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
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

/// v0.6.20 — el transporte de los builtins cliente: body en BYTES (texto, binario o el JSON
/// que `http_common::body_arg` ya serializó). `http_request` (texto) queda para los módulos
/// que lo llaman por nombre (blockchain_rpc, oidc, …).
fn http_transport(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
    tls: Option<&crate::http_common::TlsCheck>,
) -> HttpResult {
    let full_url = url_with_query(url, query);
    match do_request_pinned(method, &full_url, headers, body, timeout_secs, tls) {
        Ok(r) => r,
        Err(e) => err_result(e),
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
    let full_url = url_with_query(url, query);
    match do_request(method, &full_url, headers, body.map(str::as_bytes), timeout_secs) {
        Ok(r) => r,
        Err(e) => err_result(e),
    }
}

/// Como `http_request` pero con body **binario** (un ciphertext, un PNG): el mismo
/// transporte y el mismo `Content-Length`, sin pasar por `&str`. Lo usa `push_send`
/// (el cuerpo `aes128gcm` de Web Push no es UTF-8).
pub fn http_request_with_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
) -> HttpResult {
    match do_request(method, url, headers, body, timeout_secs) {
        Ok(r) => r,
        Err(e) => err_result(e),
    }
}

/// Una URL `http(s)://[user:pass@]host[:port][/path][?query]`: esquema, host (sin corchetes
/// si es IPv6), puerto, ruta+query, y las credenciales si vinieron (`user:pass@`, ya
/// decodificadas del %-encoding) — van como `Authorization: Basic`, como en curl o requests.
fn parse_url(url: &str) -> Result<(String, String, u16, String, Option<Vec<u8>>), String> {
    let idx = url.find("://").ok_or_else(|| "invalid URL (no scheme)".to_string())?;
    let scheme = url[..idx].to_lowercase();
    let rest = &url[idx + 3..];
    let path_start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let mut path = if path_start < rest.len() { rest[path_start..].to_string() } else { "/".to_string() };
    if let Some(h) = path.find('#') {
        path.truncate(h); // el fragmento no viaja
    }
    if path.starts_with('?') {
        path.insert(0, '/');
    }
    if path.is_empty() {
        path.push('/');
    }
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(percent_decode(&authority[..i])), &authority[i + 1..]),
        None => (None, authority),
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        // IPv6: `[::1]:8080`
        let close = inner.find(']').ok_or_else(|| format!("invalid IPv6 host in URL: {}", hostport))?;
        let h = inner[..close].to_string();
        let after = &inner[close + 1..];
        let p = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("invalid port in URL: {}", hostport))?,
            None => default_port,
        };
        (h, p)
    } else {
        match hostport.rfind(':') {
            Some(i) => {
                let p: u16 = hostport[i + 1..].parse().map_err(|_| format!("invalid port in URL: {}", hostport))?;
                (hostport[..i].to_string(), p)
            }
            None => (hostport.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err("invalid URL: it has no host (expected scheme://host/…)".to_string());
    }
    Ok((scheme, host, port, path, userinfo))
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Bytes, no `&str`: `%` seguido de un carácter multibyte no es un borde de carácter.
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

// =========================================================
// T5 — Identidad mTLS del cliente (SPIFFE-like)
// =========================================================

/// La identidad de cliente TLS de UNA corrida: cadena de certs + clave privada, ya
/// parseadas. `None` = sin identidad (comportamiento histórico, byte-idéntico).
///
/// Es del programa que corre y no de cada request a propósito: en una malla de servicios
/// el certificado identifica al *workload* (el agente), no a la llamada — es la misma
/// idea que SPIFFE, y la misma tesis de identidad de agente del diseño. Además evita
/// colgar un slot de opciones nuevo en los seis builtins `http_*`. Hasta v0.6.50 era del
/// PROCESO: otro programa del mismo proceso (un embebedor, los tests) presentaba la
/// identidad del primero. Desde v0.6.51 (G1) cuelga del `RunScope` de la corrida.
type ClientIdentity = (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
);

#[derive(Default)]
struct ClientTls {
    identity: std::sync::Mutex<Option<ClientIdentity>>,
    /// Hosts a los que SÍ se le presenta la identidad (`opts.hosts` de `mtls_identity`).
    /// Vacío = a cualquier host que el programa pueda alcanzar (que ya está acotado por
    /// `require net(...)`).
    hosts: std::sync::Mutex<Vec<String>>,
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
fn tls_client_config(host: &str, verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>, client_auth: bool) -> Result<rustls::ClientConfig, String> {
    let builder = match verifier {
        Some(v) => rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(v),
        None => rustls::ClientConfig::builder().with_root_certificates(root_cert_store()?),
    };
    // Un hilo sin corrida no tiene identidad que presentar (cerrado por defecto).
    let Some(tls) = synsema_core::run_scope::current().map(|r| r.ext::<ClientTls>()) else {
        return Ok(builder.with_no_client_auth());
    };
    let guard = tls.identity.lock().map_err(|_| "TLS identity lock poisoned".to_string())?;
    let scopes = tls.hosts.lock().map_err(|_| "TLS identity lock poisoned".to_string())?;
    match guard.as_ref() {
        Some((certs, key)) if client_auth && identity_applies_to(host, &scopes) => builder
            .with_client_auth_cert(certs.clone(), key.clone_key())
            .map_err(|e| format!("the client certificate/key pair was rejected by TLS: {}", e)),
        _ => Ok(builder.with_no_client_auth()),
    }
}

/// Lee la cadena de certificados PEM del cliente. Errores claros: un PEM vacío o
/// ilegible es un fallo de configuración, no algo que se degrade en silencio.
fn load_client_certs(
    path: &str,
    file: std::fs::File,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Control> {
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
fn load_client_key(path: &str, file: std::fs::File) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Control> {
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

/// T5 — `tls_pin`: verificador de certificado del servidor que REEMPLAZA la validación contra las
/// raíces del SO y el nombre del host por una igualdad exacta: la SubjectPublicKeyInfo del
/// certificado hoja presentado tiene que ser, byte a byte, la fijada. No apaga nada más: la firma
/// del handshake (TLS 1.2/1.3) la sigue verificando rustls con esa misma clave, con los algoritmos
/// del proveedor por defecto. Es lo que necesita un cliente de `serve --attested`, cuyo
/// certificado es autofirmado con la clave atestada (`public_key_hex`).
#[derive(Debug)]
pub(crate) struct PinnedSpki {
    spki: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedSpki {
    pub(crate) fn new(spki: &[u8]) -> PinnedSpki {
        PinnedSpki { spki: spki.to_vec(), algs: rustls::crypto::ring::default_provider().signature_verification_algorithms }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedSpki {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use x509_parser::prelude::FromDer;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("tls_pin: the server certificate does not parse".to_string()))?;
        if cert.tbs_certificate.subject_pki.raw != self.spki.as_slice() {
            return Err(rustls::Error::General("tls_pin: the server public key (SPKI) does not match the pinned key".to_string()));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// T9 — verificador del handshake de `attested`: NO valida la cadena ni el nombre, pero GUARDA la
/// SPKI de la hoja; la firma del handshake se sigue verificando con esa clave. Por sí solo no
/// confía en nada: la conexión no lleva el request del usuario hasta que el identity de esa misma
/// conexión verifica y nombra ESA clave (`attest_over`).
#[derive(Debug)]
pub(crate) struct RecordingSpki {
    seen: std::sync::Mutex<Option<Vec<u8>>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl RecordingSpki {
    pub(crate) fn new() -> RecordingSpki {
        RecordingSpki { seen: std::sync::Mutex::new(None), algs: rustls::crypto::ring::default_provider().signature_verification_algorithms }
    }
    pub(crate) fn seen(&self) -> Option<Vec<u8>> {
        self.seen.lock().ok()?.clone()
    }
}

impl rustls::client::danger::ServerCertVerifier for RecordingSpki {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use x509_parser::prelude::FromDer;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("attested: the server certificate does not parse".to_string()))?;
        if let Ok(mut g) = self.seen.lock() {
            *g = Some(cert.tbs_certificate.subject_pki.raw.to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Tope del identity leído por la conexión atestada.
const MAX_IDENTITY: usize = 1 << 20;

/// Lee UNA respuesta HTTP/1.1 completa (sólo con `Content-Length`) sin consumir de más: la
/// conexión sigue abierta para el request del usuario. → `(status, body)`.
fn read_one_response<S: Read>(stream: &mut S) -> Result<(i64, Vec<u8>), String> {
    let mut acc: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    // Cabecera de a un byte (es corta): así no se lee nada más allá de la respuesta.
    let split = loop {
        let n = stream.read(&mut byte).map_err(|e| format!("attested: reading the identity: {}", e))?;
        if n == 0 {
            return Err("attested: the server closed the connection before answering the identity".to_string());
        }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n\r\n") {
            break acc.len();
        }
        if acc.len() > 64 * 1024 {
            return Err("attested: the identity response head is too large".to_string());
        }
    };
    let (status, headers) = parse_head(&String::from_utf8_lossy(&acc[..split - 4]));
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string());
    // Sólo `Content-Length` exacto: con `chunked` el fin se adivina por patrón y la respuesta
    // del usuario podría quedar desalineada. `serve --attested` siempre manda el largo.
    if header("transfer-encoding").is_some() {
        return Err("attested: the identity response must carry Content-Length, not Transfer-Encoding".to_string());
    }
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .ok_or("attested: the identity response has no Content-Length (the connection cannot carry the request after it)")?;
    if len > MAX_IDENTITY {
        return Err("attested: the identity is larger than 1 MiB".to_string());
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).map_err(|e| format!("attested: reading the identity: {}", e))?;
    Ok((status, body))
}

/// T9: por una conexión TLS ya abierta con [`RecordingSpki`], pide `/.well-known/attestation`,
/// exige que su clave sea la del handshake y lo verifica entero. Sólo si todo pasa la conexión
/// puede llevar el request del usuario.
pub(crate) fn attest_over<S: Read + Write>(
    stream: &mut S,
    host_hdr: &str,
    recorder: &RecordingSpki,
    spec: &crate::attested_client::AttestedSpec,
) -> Result<crate::attested_client::AttestedInfo, String> {
    let req = format!(
        "GET /.well-known/attestation HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: keep-alive\r\nUser-Agent: synsema\r\n\r\n",
        host_hdr
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("attested: {}", e))?;
    let (status, body) = read_one_response(stream)?;
    if status != 200 {
        return Err(format!("attested: GET /.well-known/attestation answered {} (is this a serve --attested?)", status));
    }
    let spki = recorder.seen().ok_or("attested: the TLS handshake presented no certificate")?;
    crate::attested_client::verify_identity(&body, &spki, spec).map_err(|e| format!("attested: {}", e))
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
    match body {
        Some(b) => req.push_str(&format!("Content-Length: {}\r\n", b.len())),
        // Un POST/PUT/PATCH sin cuerpo lleva `Content-Length: 0` (RFC 9110 §8.6: el método
        // define un contenido, así que se declara que no hay) — sin él, algunos servidores
        // responden 411 o esperan un cuerpo que nunca llega (visto con `push_send(sub, nothing)`).
        None => {
            if matches!(method.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH") {
                req.push_str("Content-Length: 0\r\n");
            }
        }
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
/// v0.6.49 (§C): `localhost` resuelve primero a `::1` en Windows, y un `serve` en `0.0.0.0` sólo
/// escucha IPv4: el rechazo lo dice, en vez de un "connection refused" que parece un servidor caído.
#[cold]
#[inline(never)]
fn connect_error(e: std::io::Error, host: &str, sa: std::net::SocketAddr) -> String {
    let refused = e.kind() == std::io::ErrorKind::ConnectionRefused;
    if refused && sa.ip().is_loopback() && sa.is_ipv6() && host.parse::<std::net::IpAddr>().is_err() {
        return format!(
            "{} — {} resolved to ::1 (IPv6) and nothing listens there; a `serve` on 0.0.0.0 listens on IPv4 only: use http://127.0.0.1:{}",
            e,
            host,
            sa.port()
        );
    }
    e.to_string()
}

fn connect_and_send(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
    tls: Option<&crate::http_common::TlsCheck>,
) -> Result<(Box<dyn Read>, Option<crate::attested_client::AttestedInfo>), String> {
    let (scheme, host, port, path, userinfo) = parse_url(url)?;
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme '{}': only http and https are supported", scheme));
    }
    // Un pin o una atestación sobre http:// no fijan nada: fallar cerrado ANTES de resolver o
    // conectar (ni DNS ni TCP hacia un destino que no se puede verificar).
    if scheme == "http" {
        match tls {
            Some(crate::http_common::TlsCheck::Pin(_)) => return Err("tls_pin needs an https:// URL (there is no server key to pin over plain http)".to_string()),
            Some(crate::http_common::TlsCheck::Attested(_)) => return Err("attested needs an https:// URL (there is no server key to check over plain http)".to_string()),
            None => {}
        }
    }
    // `user:pass@` → `Authorization: Basic …`, salvo que el programa ya mande uno.
    let with_auth: Option<Vec<(String, String)>> = match &userinfo {
        Some(ui) if !headers.unwrap_or(&[]).iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")) => {
            let mut h: Vec<(String, String)> = headers.map(|h| h.to_vec()).unwrap_or_default();
            h.push(("Authorization".to_string(), format!("Basic {}", synsema_core::bytesutil::b64_encode(ui))));
            Some(h)
        }
        _ => None,
    };
    let headers: Option<&[(String, String)]> = match &with_auth {
        Some(h) => Some(h.as_slice()),
        None => headers,
    };

    let addr = if host.contains(':') { format!("[{}]:{}", host, port) } else { format!("{}:{}", host, port) };
    let addrs: Vec<std::net::SocketAddr> = addr.to_socket_addrs().map_err(|e| e.to_string())?.collect();
    if addrs.is_empty() {
        return Err(format!("could not resolve host: {}", host));
    }
    let timeout = Duration::from_secs(timeout_secs);
    // v0.6.46 (E7): cada IP se chequea antes de conectar (no hay segunda resolución). v0.6.53: si
    // una rechaza, se prueba la siguiente (`localhost` → `::1`, después `127.0.0.1`).
    let check = |ip: std::net::IpAddr| crate::http_common::dest_check(&host, port, ip);
    let tcp = crate::http_common::connect_each(&addrs, &check, timeout).map_err(|f| match f {
        crate::http_common::ConnectFail::Denied(m) => m,
        crate::http_common::ConnectFail::Io(e, sa) => connect_error(e, &host, sa),
    })?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    // `Host` lleva el puerto si no es el del esquema (RFC 9110 §7.2) y los corchetes de IPv6.
    let default_port = if scheme == "https" { 443 } else { 80 };
    let host_hdr = match (host.contains(':'), port == default_port) {
        (true, true) => format!("[{}]", host),
        (true, false) => format!("[{}]:{}", host, port),
        (false, true) => host.clone(),
        (false, false) => format!("{}:{}", host, port),
    };
    let req_bytes = build_http_request(method, &path, &host_hdr, headers, body);

    if scheme == "https" {
        // Con identidad mTLS declarada (`mtls_identity`), el handshake presenta el
        // certificado del workload; sin ella, exactamente como antes.
        use crate::http_common::TlsCheck;
        let recorder = matches!(tls, Some(TlsCheck::Attested(_))).then(|| Arc::new(RecordingSpki::new()));
        let verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = match (tls, &recorder) {
            (Some(TlsCheck::Pin(pin)), _) => Some(Arc::new(PinnedSpki::new(pin))),
            (Some(TlsCheck::Attested(_)), Some(r)) => Some(r.clone()),
            _ => None,
        };
        // T9: con `attested` el servidor todavía no se verificó durante el handshake: no se le
        // presenta la identidad mTLS del workload (TLS 1.3 la manda antes de poder atestar nada).
        let config = tls_client_config(&host, verifier, !matches!(tls, Some(TlsCheck::Attested(_))))?;
        let server_name: rustls::pki_types::ServerName<'static> = host
            .as_str()
            .try_into()
            .map(|n: rustls::pki_types::ServerName| n.to_owned())
            .map_err(|_| format!("invalid server name: {}", host))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| e.to_string())?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        // T9: primero el identity por ESTA conexión; el request del usuario sale sólo si verifica.
        let info = match (tls, &recorder) {
            (Some(TlsCheck::Attested(spec)), Some(r)) => Some(attest_over(&mut stream, &host_hdr, r, spec)?),
            _ => None,
        };
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        Ok((Box::new(stream), info))
    } else {
        let mut stream = tcp;
        stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
        Ok((Box::new(stream), None))
    }
}

/// Conecta (TCP, o TLS para `https`), envía el request y lee la respuesta cruda
/// (head + body) hasta su fin (`read_response`, v0.6.56). Base compartida por `do_request` (→ `String`) y
/// `http_request_bytes` (→ bytes crudos, para descargar binarios sin corromperlos).
fn fetch_raw(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
    tls: Option<&crate::http_common::TlsCheck>,
) -> Result<(Vec<u8>, Option<crate::attested_client::AttestedInfo>), String> {
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
    let (mut stream, info) = connect_and_send(method, url, headers, body, timeout_secs, tls)?;
    let buf = read_response(&mut stream, method)?;
    Ok((buf, info))
}

/// v0.6.56 (ítem 7): dónde termina el cuerpo de una respuesta (RFC 9112 §6.3), para no esperar a
/// que el servidor cierre: el pedido manda `Connection: close`, pero Chrome, varios proxies y
/// servidores embebidos contestan y dejan la conexión abierta.
enum Framing {
    /// `HEAD`, 1xx, 204 y 304: sin cuerpo aunque digan `Content-Length`.
    Empty,
    /// Exactamente estos bytes (en el streaming, los que faltan).
    Length(usize),
    /// Hasta el chunk de largo 0 y sus trailers.
    Chunked(ChunkDecoder),
    /// Ni largo ni chunked (HTTP/1.0, o un servidor que no lo dice): hasta EOF.
    UntilClose,
}

fn framing_of(method: &str, status: i64, headers: &[(String, String)]) -> Framing {
    if method.eq_ignore_ascii_case("HEAD") || (100..200).contains(&status) || status == 204 || status == 304 {
        return Framing::Empty;
    }
    if let Some((_, te)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        // Con otra codificación de transferencia el fin sólo lo marca el cierre (§6.3, punto 4).
        return if te.to_ascii_lowercase().contains("chunked") {
            Framing::Chunked(ChunkDecoder::new())
        } else {
            Framing::UntilClose
        };
    }
    // Varios `Content-Length` distintos, o uno que no es un número: el largo no es confiable.
    let mut len: Option<usize> = None;
    // Un header puede traer una lista de valores iguales (`2, 2`, la deja un proxy que une
    // headers): RFC 9110 §8.6 deja tomarla como un solo largo (ronda 1, M1).
    for (_, v) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        // Los elementos vacíos de la lista se ignoran (RFC 9110 §5.6.1) y un largo es sólo dígitos
        // (§8.6, `1*DIGIT`: nada de `+2`) (ronda 2, M4).
        for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let n = if part.bytes().all(|b| b.is_ascii_digit()) { part.parse::<usize>().ok() } else { None };
            match (n.ok_or(()), len) {
                (Ok(n), None) => len = Some(n),
                (Ok(n), Some(m)) if n == m => {}
                _ => return Framing::UntilClose,
            }
        }
    }
    len.map_or(Framing::UntilClose, Framing::Length)
}

/// Un 1xx que no es 101 es intermedio (`100 Continue`, `103 Early Hints`): la respuesta de verdad
/// viene después, por la misma conexión.
fn is_interim(status: i64) -> bool {
    (100..200).contains(&status) && status != 101
}

/// Tope del head de una respuesta (status + headers, sin el cuerpo): uno más largo es un servidor
/// roto u hostil. 1 MiB, como `DefaultMaxHeaderBytes` de Go.
const MAX_HEAD: usize = 1 << 20;

fn head_too_large() -> String {
    format!("the HTTP response head is larger than {} bytes", MAX_HEAD)
}

/// Sin el fin del head en `read` bytes: ya no puede caber. El fin (`\r\n\r\n`) empieza a lo sumo
/// 3 bytes antes del final de lo leído, así que hasta `MAX_HEAD + 3` todavía puede ser un head de
/// `MAX_HEAD` bytes (ronda 2, M3).
fn head_cut(read: usize) -> bool {
    read > MAX_HEAD + 3
}

/// Cuántos 1xx intermedios se saltean antes de la respuesta (ronda 2, M4): un servidor podría
/// mandarlos para siempre. Go corta igual («too many 1xx informational responses»).
const MAX_INTERIM: usize = 8;

fn too_many_interim() -> String {
    format!("the server sent more than {} interim (1xx) responses", MAX_INTERIM)
}

/// El fin del head en `buf`, buscando sólo en lo que no se miró (ronda 1, N3: buscar desde 0 en
/// cada lectura era cuadrático, 6,5 s de CPU para un head de 16 MB). `scanned` es hasta dónde ya
/// se buscó sin encontrarlo; vuelve a 0 cuando `buf` pierde su principio.
fn head_end(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    let from = (*scanned).saturating_sub(3).min(buf.len());
    match buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => Some(from + p),
        None => {
            *scanned = buf.len();
            None
        }
    }
}

/// v0.6.56 (ítem 7): lee una respuesta (head + body crudos, como antes) y para cuando está
/// completa según su `Framing`, sin esperar el EOF. rustls es estricto: si el peer cierra el TLS
/// sin el alert `close_notify` (común en servidores y balanceadores, p. ej. MiniMax) devuelve
/// `UnexpectedEof`; con bytes ya recibidos no es error. Un EOF antes de tiempo entrega lo que
/// llegó (lo que `parse_response` ya toleraba). Sólo es error real si NO se recibió nada.
pub(crate) fn read_response<R: Read>(stream: &mut R, method: &str) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    // Dónde empieza el cuerpo (después del head final) y cuánto del cuerpo vio el de-chunker.
    let mut body_at: Option<usize> = None;
    let mut framing = Framing::UntilClose;
    let mut fed = 0usize;
    let mut scanned = 0usize;
    let mut interim = 0usize;
    loop {
        // Buscar el head (y saltear los 1xx intermedios) con lo que ya llegó.
        while body_at.is_none() {
            let Some(p) = head_end(&buf, &mut scanned) else {
                if head_cut(buf.len()) {
                    return Err(head_too_large());
                }
                break;
            };
            if p > MAX_HEAD {
                return Err(head_too_large());
            }
            let (status, headers) = parse_head(&String::from_utf8_lossy(&buf[..p]));
            if is_interim(status) {
                interim += 1;
                if interim > MAX_INTERIM {
                    return Err(too_many_interim());
                }
                buf.drain(..p + 4);
                scanned = 0;
                continue;
            }
            body_at = Some(p + 4);
            framing = framing_of(method, status, &headers);
        }
        if let Some(at) = body_at {
            let body = buf.len() - at;
            match &mut framing {
                Framing::Empty => {
                    buf.truncate(at);
                    return Ok(buf);
                }
                Framing::Length(n) if body >= *n => {
                    buf.truncate(at + *n);
                    return Ok(buf);
                }
                Framing::Chunked(d) => {
                    d.feed(&buf[at + fed..]);
                    fed = body;
                    if d.complete() {
                        return Ok(buf);
                    }
                }
                _ => {}
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => return Ok(buf),
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Como `http_request` pero entrega el BODY incrementalmente: parsea el head, y va
/// invocando `on_data` con cada tramo de body YA des-chunkeado a medida que llega.
/// `on_data` devuelve `false` para abortar la lectura (el caller corta). Devuelve
/// `(status, headers)` al terminar (EOF o abort). El read-timeout del socket aplica
/// POR `read()` → mide **silencio** entre bytes, no duración total: una respuesta
/// larga que gotea fluye; un host mudo sigue fallando al timeout.
///
/// Tolerancia EOF: mismo criterio que `read_response` — un `UnexpectedEof`
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
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
    let (mut stream, _) = connect_and_send(method, url, headers, body.map(str::as_bytes), timeout_secs, None)?;
    let mut read_buf = [0u8; 8192];

    // Fase 1: acumular hasta el fin del head (`\r\n\r\n`) y parsearlo. Un EOF antes
    // de completar el head sí es error (respuesta malformada, como en parse_response).
    let mut acc: Vec<u8> = Vec::new();
    let mut scanned = 0usize;
    let mut interim = 0usize;
    let (status, resp_headers, leftover) = 'head: loop {
        // v0.6.56: un 1xx intermedio se saltea; la respuesta de verdad viene después.
        while let Some(split) = head_end(&acc, &mut scanned) {
            if split > MAX_HEAD {
                return Err(head_too_large());
            }
            let head = String::from_utf8_lossy(&acc[..split]).to_string();
            let (status, headers) = parse_head(&head);
            if is_interim(status) {
                interim += 1;
                if interim > MAX_INTERIM {
                    return Err(too_many_interim());
                }
                acc.drain(..split + 4);
                scanned = 0;
                continue;
            }
            break 'head (status, headers, acc.split_off(split + 4));
        }
        if head_cut(acc.len()) {
            return Err(head_too_large());
        }
        match stream.read(&mut read_buf) {
            Ok(0) => return Err("malformed HTTP response".to_string()),
            Ok(n) => acc.extend_from_slice(&read_buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err("malformed HTTP response".to_string())
            }
            Err(e) => return Err(e.to_string()),
        }
    };

    // Fase 2: body incremental, des-chunkeado al vuelo si corresponde. v0.6.56 (ítem 7): termina
    // cuando la respuesta está completa según su `Framing`, sin esperar a que el servidor cierre.
    let mut framing = framing_of(method, status, &resp_headers);
    // `true` si la respuesta terminó (o el callback cortó): no hay que leer más.
    let mut push = |raw: &[u8], on_data: &mut dyn FnMut(&[u8]) -> bool| -> bool {
        let (bytes, done) = match &mut framing {
            Framing::Empty => return true,
            Framing::Length(left) => {
                let take = (*left).min(raw.len());
                *left -= take;
                (raw[..take].to_vec(), *left == 0)
            }
            Framing::Chunked(d) => {
                let b = d.feed(raw);
                (b, d.complete())
            }
            Framing::UntilClose => (raw.to_vec(), false),
        };
        // El callback puede correr código del usuario (un `llm_stream` con su task): mientras
        // corre, vuelve a contar contra la CPU del pool (sección inversa de la espera).
        let go_on = bytes.is_empty() || {
            let _r = synsema_core::waiting::resumed();
            on_data(&bytes)
        };
        done || !go_on
    };
    if push(&leftover, on_data) {
        return Ok((status, resp_headers));
    }
    loop {
        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                if push(&read_buf[..n], on_data) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
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
    do_request_pinned(method, url, headers, body, timeout_secs, None)
}

fn do_request_pinned(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
    tls: Option<&crate::http_common::TlsCheck>,
) -> Result<HttpResult, String> {
    let (buf, info) = fetch_raw(method, url, headers, body, timeout_secs, tls)?;
    let mut r = parse_response(&buf)?;
    r.attested = info;
    Ok(r)
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

/// v0.6.46 (E7): el cliente de las requests del MOTOR (providers de LLM y del juez, el webhook de
/// aprobación, `synsema update`): la configuración del host, que llega a una IP privada sin que un
/// programa la nombre (un modelo local en `localhost`). Las mismas funciones, en contexto de host.
pub mod host {
    use super::{BytesResponse, HttpResult};

    pub fn http_request(
        method: &str,
        url: &str,
        headers: Option<&[(String, String)]>,
        query: Option<&[(String, String)]>,
        body: Option<&str>,
        timeout_secs: u64,
    ) -> HttpResult {
        crate::http_common::host_request(|| super::http_request(method, url, headers, query, body, timeout_secs))
    }

    pub fn http_request_stream(
        method: &str,
        url: &str,
        headers: Option<&[(String, String)]>,
        body: Option<&str>,
        timeout_secs: u64,
        on_data: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(i64, Vec<(String, String)>), String> {
        crate::http_common::host_request(|| super::http_request_stream(method, url, headers, body, timeout_secs, on_data))
    }

    pub fn http_request_bytes(
        method: &str,
        url: &str,
        headers: Option<&[(String, String)]>,
        timeout_secs: u64,
    ) -> Result<BytesResponse, String> {
        crate::http_common::host_request(|| super::http_request_bytes(method, url, headers, timeout_secs))
    }
}

/// Como `http_request` pero devuelve el body como **bytes crudos** (sin pasar por
/// `String`, que corrompería un binario). Para descargar release assets. Devuelve
/// `(status, body_bytes, headers)`. No sigue redirects — el caller los maneja.
pub fn http_request_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    timeout_secs: u64,
) -> Result<BytesResponse, String> {
    let (buf, _) = fetch_raw(method, url, headers, None, timeout_secs, None)?;
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
    let body_raw = &buf[split + 4..];
    // v0.6.20 — se conservan los bytes exactos; `body` es su lectura como texto.
    let body_bytes = if chunked { dechunk_bytes(body_raw) } else { body_raw.to_vec() };
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    Ok(HttpResult {
        status,
        ok: (200..300).contains(&status),
        body,
        body_bytes,
        headers,
        error: None,
        attested: None,
    })
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
    /// v0.6.56: llegó el chunk de largo 0 (no un tamaño inválido): faltan los trailers, que
    /// terminan en una línea vacía.
    last_chunk: bool,
    /// Hasta dónde de `buf` ya se buscó el fin de la línea de tamaño sin encontrarlo (ronda 2, N1).
    scanned: usize,
}

/// Tope de la línea de tamaño de un chunk (con sus extensiones), como `maxLineLength` del lector
/// chunked de Go. Una más larga es un tamaño inválido: corta y entrega lo acumulado (ronda 2, N1).
const MAX_CHUNK_LINE: usize = 4096;

/// Sin `\r\n` en `len` bytes de línea: ya no puede medir `MAX_CHUNK_LINE`. Su `\r` puede ser el último
/// byte leído y el `\n` venir en la lectura siguiente (ronda 3, M1; lo mismo que `head_cut`).
fn chunk_line_cut(len: usize) -> bool {
    len > MAX_CHUNK_LINE + 1
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
        Self { buf: Vec::new(), state: ChunkState::Size, last_chunk: false, scanned: 0 }
    }

    /// v0.6.56 (ítem 7): la respuesta chunked está completa: el chunk 0 y la línea vacía que
    /// cierra los trailers (o un tamaño inválido, que corta como siempre). Trailers de más de
    /// 64 KiB también cortan: no se espera para siempre a un servidor que no los termina.
    fn complete(&self) -> bool {
        matches!(self.state, ChunkState::Done)
            && (!self.last_chunk
                || self.buf.starts_with(b"\r\n")
                || self.buf.windows(4).any(|w| w == b"\r\n\r\n")
                || self.buf.len() > 64 * 1024)
    }

    /// Alimenta bytes crudos; devuelve los datos de chunk decodificados hasta ahora
    /// (los datos se emiten a medida que llegan — no se espera el chunk completo).
    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        if matches!(self.state, ChunkState::Done) {
            // v0.6.56: se guardan los trailers hasta su fin (`complete`); los datos ya terminaron.
            if !self.complete() {
                self.buf.extend_from_slice(input);
            }
            return Vec::new();
        }
        self.buf.extend_from_slice(input);
        // Ronda 2 (N2): se avanza un cursor y se suelta lo consumido una sola vez al salir; un
        // `drain` por chunk movía todo el resto del buffer (cuadrático en la cantidad de chunks).
        let mut pos = 0usize;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.state {
                ChunkState::Size => {
                    // Ronda 2 (N1): el fin de la línea se busca sólo en lo que no se miró.
                    let from = self.scanned.saturating_sub(1).max(pos);
                    let Some(rel) = self.buf[from..].windows(2).position(|w| w == b"\r\n") else {
                        self.scanned = self.buf.len();
                        if chunk_line_cut(self.buf.len() - pos) {
                            self.state = ChunkState::Done;
                        }
                        break;
                    };
                    let line_end = from + rel;
                    if line_end - pos > MAX_CHUNK_LINE {
                        self.state = ChunkState::Done;
                        break;
                    }
                    // El tamaño puede traer extensiones tras `;` — quedate sólo con el hex.
                    let size_line = String::from_utf8_lossy(&self.buf[pos..line_end]).to_string();
                    let hex = size_line.split(';').next().unwrap_or("").trim().to_string();
                    pos = line_end + 2;
                    self.scanned = pos;
                    match usize::from_str_radix(&hex, 16) {
                        Ok(0) => {
                            self.state = ChunkState::Done;
                            self.last_chunk = true;
                            break;
                        }
                        Err(_) => {
                            self.state = ChunkState::Done;
                            break;
                        }
                        Ok(size) => self.state = ChunkState::Data { remaining: size },
                    }
                }
                ChunkState::Data { remaining } => {
                    if pos == self.buf.len() {
                        break;
                    }
                    let take = remaining.min(self.buf.len() - pos);
                    out.extend_from_slice(&self.buf[pos..pos + take]);
                    pos += take;
                    if take == remaining {
                        // Saltá el `\r\n` que cierra el chunk.
                        self.state = ChunkState::Skip { remaining: 2 };
                    } else {
                        self.state = ChunkState::Data { remaining: remaining - take };
                        break;
                    }
                }
                ChunkState::Skip { remaining } => {
                    if pos == self.buf.len() {
                        break;
                    }
                    let take = remaining.min(self.buf.len() - pos);
                    pos += take;
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
        self.buf.drain(..pos);
        self.scanned = self.scanned.saturating_sub(pos);
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
            Rc::new(move |i, args, _loc| {
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
                                    for h in list_values(&l).iter() {
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
                        .map_err(|v| Control::Error(v.into_error()))?;
                }
                // v0.6.45 — se abre la ruta normalizada, la que se chequeó (en Unix `link/..` de la
                // cruda lleva a otro lado). v0.6.46 (E8): y sin ventana entre el chequeo y la apertura.
                let open = |raw: &str, what: &str| {
                    let p = synsema_core::capscope::normalize_path(raw);
                    synsema_capabilities::secure::open_checked(
                        &caps,
                        &p,
                        synsema_capabilities::nofollow::OpenFor::READ,
                        &[CapabilityType::FileRead],
                        "mtls_identity()",
                    )
                    .map(|f| (p.clone(), f))
                    .map_err(|r| match r {
                        synsema_capabilities::nofollow::Refused::Denied(c) => c,
                        synsema_capabilities::nofollow::Refused::Io(e) => Control::Error(RuntimeError::new(format!(
                            "mtls_identity: cannot read the {} {:?}: {}",
                            what, p, e
                        ))),
                    })
                };
                let (cp, cf) = open(&cert_path, "certificate")?;
                let certs = load_client_certs(&cp, cf)?;
                let (kp, kf) = open(&key_path, "private key")?;
                let key = load_client_key(&kp, kf)?;
                let tls = i.run_scope().ext::<ClientTls>();
                match (tls.identity.lock(), tls.hosts.lock()) {
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
    register_http_client_builtins(interp, caps, http_transport);
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

    /// La respuesta del identity se lee con su `Content-Length` exacto y sin pasarse: lo que sigue
    /// en la conexión queda para el request del usuario. `chunked` o sin largo: error.
    #[test]
    fn the_identity_response_needs_an_exact_content_length() {
        let mut c = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}NEXT".to_vec());
        assert_eq!(read_one_response(&mut c).unwrap(), (200, b"{}".to_vec()));
        assert_eq!(c.position(), 40, "no se consumió nada de lo que sigue");
        let mut c = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec());
        assert_eq!(read_one_response(&mut c).unwrap_err(), "attested: the identity response must carry Content-Length, not Transfer-Encoding");
        let mut c = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec());
        assert!(read_one_response(&mut c).unwrap_err().contains("has no Content-Length"));
        let mut c = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}".to_vec());
        assert!(read_one_response(&mut c).unwrap_err().starts_with("attested: reading the identity"));
        let mut c = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent".to_vec());
        assert!(read_one_response(&mut c).unwrap_err().contains("closed the connection"));
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

    /// v0.6.56 (ítem 7): un servidor que contesta y NO cierra (Chrome, proxies, servidores
    /// embebidos). Escribe cada tramo con una pausa y retiene la conexión 3 s: el cliente tiene que
    /// terminar al completar la respuesta, no al cerrar ni al vencer su timeout (5 s).
    fn holding_server(parts: Vec<&'static [u8]>) -> String {
        let (url, _handle) = one_shot_server(move |mut sock| {
            drain_request(&mut sock);
            for p in parts {
                sock.write_all(p).unwrap();
                thread::sleep(TestDuration::from_millis(50));
            }
            thread::sleep(TestDuration::from_secs(3));
        });
        url
    }

    fn quick(method: &str, parts: Vec<&'static [u8]>) -> HttpResult {
        let url = holding_server(parts);
        let t0 = std::time::Instant::now();
        let r = host::http_request(method, &url, None, None, None, 5);
        assert!(t0.elapsed() < TestDuration::from_secs(2), "esperó al cierre: {:?} ({:?})", t0.elapsed(), r.error);
        r
    }

    #[test]
    fn response_ends_at_content_length_without_close() {
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", b"{}"]);
        assert_eq!((r.status, r.body.as_str(), r.error.clone()), (200, "{}", None));
        // Lo que sobra después del largo no es del cuerpo.
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}EXTRA"]);
        assert_eq!(r.body, "{}");
        // Varios `Content-Length` iguales valen; uno solo partido en dos lecturas también.
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\ncontent-length: 4\r\n\r\nab", b"cd"]);
        assert_eq!(r.body, "abcd");
    }

    #[test]
    fn response_ends_at_the_last_chunk_and_its_trailers() {
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n", b"0\r\n\r\n"]);
        assert_eq!((r.status, r.body.as_str()), (200, "{}"));
        // Trailers partidos: se espera la línea vacía que los cierra.
        let r = quick(
            "GET",
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n", b"\r\n"],
        );
        assert_eq!(r.body, "abc");
        // El `0\r\n` y el `\r\n` final en lecturas distintas.
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n", b"\r\n"]);
        assert_eq!(r.body, "z");
    }

    #[test]
    fn head_204_and_304_have_no_body() {
        let r = quick("HEAD", vec![b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"]);
        assert_eq!((r.status, r.body.as_str(), r.error.clone()), (200, "", None));
        let r = quick("GET", vec![b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"]);
        assert_eq!((r.status, r.body.as_str()), (204, ""));
        let r = quick("GET", vec![b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n"]);
        assert_eq!((r.status, r.body.as_str()), (304, ""));
    }

    #[test]
    fn an_interim_1xx_is_skipped() {
        let r = quick(
            "GET",
            vec![b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"],
        );
        assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    }

    /// Ronda 1, M1: una lista de largos iguales en un header vale; si difieren, hasta el cierre.
    #[test]
    fn a_list_of_equal_lengths_is_one_length() {
        let r = quick("GET", vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok"]);
        assert_eq!((r.status, r.body.as_str(), r.error.clone()), (200, "ok", None));
        let h = |v: &str| vec![("Content-Length".to_string(), v.to_string())];
        assert!(matches!(framing_of("GET", 200, &h("2, 2")), Framing::Length(2)));
        assert!(matches!(framing_of("GET", 200, &h("2,2,2")), Framing::Length(2)));
        assert!(matches!(framing_of("GET", 200, &h("2, 3")), Framing::UntilClose));
        // Ronda 2 (M4): los elementos vacíos se ignoran; un largo es sólo dígitos.
        assert!(matches!(framing_of("GET", 200, &h("2,")), Framing::Length(2)));
        assert!(matches!(framing_of("GET", 200, &h("2, , 2")), Framing::Length(2)));
        assert!(matches!(framing_of("GET", 200, &h("+2")), Framing::UntilClose));
        assert!(matches!(framing_of("GET", 200, &h("2, +2")), Framing::UntilClose));
        assert!(matches!(framing_of("GET", 200, &h(" , ")), Framing::UntilClose));
    }

    /// Un lector que entrega de a 8 KiB (como un socket).
    struct Drip(std::io::Cursor<Vec<u8>>);
    impl Read for Drip {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(8192);
            self.0.read(&mut out[..n])
        }
    }

    /// Ronda 1, N3: el fin del head se busca sólo en lo nuevo (antes, 6,5 s de CPU con 16 MB), y un
    /// head de más de 1 MiB corta con su error en los dos lectores.
    #[test]
    fn a_long_head_is_read_in_linear_time_and_has_a_ceiling() {
        let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
        while head.len() < MAX_HEAD - 2048 {
            head.extend_from_slice(format!("X-Pad-{}: {}\r\n", head.len(), "a".repeat(900)).as_bytes());
        }
        head.extend_from_slice(b"Content-Length: 2\r\n\r\nokEXTRA");
        let raw = read_response(&mut Drip(std::io::Cursor::new(head)), "GET").unwrap();
        assert!(raw.ends_with(b"\r\n\r\nok"));
        // Ronda 2 (M2): sin umbral de tiempo. Con `scanned` pasado el primer fin, `head_end`
        // encuentra el segundo: buscar desde 0 encontraría el primero.
        let two = b"AB\r\n\r\nCDEF\r\n\r\n";
        let mut scanned = 8;
        assert_eq!(head_end(two, &mut scanned), Some(10));
        let mut scanned = 0;
        assert_eq!(head_end(two, &mut scanned), Some(2));
        // Sin fin de head: corta al pasar el tope, no espera ni junta para siempre.
        let endless = b"HTTP/1.1 200 OK\r\n".iter().copied().chain(std::iter::repeat(b'a').take(MAX_HEAD + 20_000)).collect();
        let e = read_response(&mut Drip(std::io::Cursor::new(endless)), "GET").unwrap_err();
        assert_eq!(e, "the HTTP response head is larger than 1048576 bytes");
        // El de streaming, contra un servidor que manda un head sin fin.
        let url = holding_server(vec![b"HTTP/1.1 200 OK\r\n", Box::leak(vec![b'a'; MAX_HEAD + 20_000].into_boxed_slice())]);
        let e = host::http_request_stream("GET", &url, None, None, 5, &mut |_| true).unwrap_err();
        assert_eq!(e, "the HTTP response head is larger than 1048576 bytes");
        // El `\r\n\r\n` partido entre dos lecturas se encuentra igual.
        let mut c = Drip(std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz".to_vec()));
        let mut scanned = 0;
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r";
        assert_eq!(head_end(buf, &mut scanned), None);
        assert_eq!(scanned, buf.len());
        let mut more = buf.to_vec();
        more.extend_from_slice(b"\nz");
        assert_eq!(head_end(&more, &mut scanned), Some(buf.len() - 3));
        assert!(read_response(&mut c, "GET").unwrap().ends_with(b"\r\n\r\nz"));
    }

    /// Un lector que entrega cada parte en una lectura.
    struct Parts(std::collections::VecDeque<Vec<u8>>);
    impl Read for Parts {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let Some(mut p) = self.0.pop_front() else { return Ok(0) };
            let n = p.len().min(out.len());
            out[..n].copy_from_slice(&p[..n]);
            if n < p.len() {
                self.0.push_front(p.split_off(n));
            }
            Ok(n)
        }
    }

    /// Un head cuyo `\r\n\r\n` empieza en `p` (los bytes antes del fin).
    fn head_of(p: usize) -> Vec<u8> {
        let mut h = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX: ".to_vec();
        h.resize(p, b'a');
        h.extend_from_slice(b"\r\n\r\nok");
        h
    }

    /// Ronda 2 (M3): el tope se mide sobre el head, no sobre lo leído. Un head de `MAX_HEAD` bytes
    /// cortado en la lectura justo dentro de su `\r\n\r\n` pasa; uno de `MAX_HEAD + 1`, no.
    #[test]
    fn the_head_ceiling_is_on_the_head_not_on_what_was_read() {
        for p in [MAX_HEAD - 2, MAX_HEAD] {
            let mut h = head_of(p);
            let rest = h.split_off(p + 3);
            let mut r = Parts(vec![h, rest].into());
            let raw = read_response(&mut r, "GET").unwrap_or_else(|e| panic!("p = {}: {}", p, e));
            assert!(raw.ends_with(b"\r\n\r\nok"));
        }
        let mut r = Parts(vec![head_of(MAX_HEAD + 1)].into());
        assert_eq!(read_response(&mut r, "GET").unwrap_err(), head_too_large());
    }

    /// Ronda 2 (M4): hasta 8 respuestas 1xx intermedias se saltean; la novena corta con su error.
    #[test]
    fn too_many_interim_responses_is_an_error() {
        let many = |n: usize| {
            let mut v = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(n);
            v.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            v
        };
        let raw = read_response(&mut Drip(std::io::Cursor::new(many(8))), "GET").unwrap();
        assert!(raw.starts_with(b"HTTP/1.1 200 OK") && raw.ends_with(b"ok"));
        let e = read_response(&mut Drip(std::io::Cursor::new(many(9))), "GET").unwrap_err();
        assert_eq!(e, "the server sent more than 8 interim (1xx) responses");
        let url = holding_server(vec![&*Box::leak(many(9).into_boxed_slice())]);
        let e = host::http_request_stream("GET", &url, None, None, 5, &mut |_| true).unwrap_err();
        assert_eq!(e, "the server sent more than 8 interim (1xx) responses");
    }

    /// Ronda 3 (M1): una línea de tamaño de exactamente 4096 bytes vale, llegue entera o cortada justo
    /// después de su `\r`; una de 4097 es un tamaño inválido de las dos formas.
    #[test]
    fn the_chunk_size_line_ceiling_does_not_depend_on_the_reads() {
        let line = |n: usize| {
            let mut l = b"1;".to_vec();
            l.resize(n, b'e');
            l
        };
        let tail: &[u8] = b"\nz\r\n0\r\n\r\n";
        for (n, want) in [(4096usize, &b"z"[..]), (4097, &b""[..])] {
            let mut whole = line(n);
            whole.push(b'\r');
            whole.extend_from_slice(tail);
            let mut d = ChunkDecoder::new();
            assert_eq!(d.feed(&whole), want, "{} bytes de una vez", n);
            let mut d = ChunkDecoder::new();
            let mut cut = line(n);
            cut.push(b'\r');
            let mut out = d.feed(&cut);
            out.extend(d.feed(tail));
            assert_eq!(out, want, "{} bytes cortados en el \\r", n);
            assert!(d.complete());
        }
    }

    /// Ronda 2 (N1): una línea de tamaño sin fin corta al pasar 4096 bytes (tamaño inválido: se
    /// entrega lo acumulado). `scanned` queda al final de lo mirado (con el tope, buscar de nuevo desde
    /// el principio de la línea tendría un costo acotado, así que eso no se prueba por tiempo).
    #[test]
    fn a_chunk_size_line_has_a_ceiling() {
        let mut d = ChunkDecoder::new();
        assert_eq!(d.feed(b"2\r\nok\r\n"), b"ok");
        d.feed(&[b'a'; 3000]);
        assert_eq!(d.scanned, d.buf.len());
        assert!(!d.complete());
        d.feed(&[b'a'; 3000]);
        assert!(d.complete(), "una línea de más de 4096 bytes es un tamaño inválido");
        assert!(!d.last_chunk);
        // Por `read_response`: un head chunked y 2 MiB sin `\r\n` terminan con el cuerpo de antes.
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n".to_vec();
        raw.extend(std::iter::repeat(b'a').take(2 << 20));
        let got = read_response(&mut Drip(std::io::Cursor::new(raw)), "GET").unwrap();
        assert!(got.len() < 64 * 1024, "leyó {} bytes", got.len());
        // Una línea partida byte a byte se encuentra igual (el `\r` y el `\n` en lecturas distintas).
        let mut d = ChunkDecoder::new();
        let mut out = Vec::new();
        for b in b"3;ext=1\r\nabc\r\n0\r\n\r\n" {
            out.extend(d.feed(&[*b]));
        }
        assert_eq!(out, b"abc");
        assert!(d.complete() && d.last_chunk);
    }

    /// Ronda 2 (N2): de-chunkear muchos chunks chicos es lineal. Con un `drain` por chunk, 2¹⁸ chunks
    /// de 1 byte cuestan segundos en debug (×4 por cada ×2); con el cursor, milisegundos: el umbral de
    /// 1 s queda lejos de los dos lados.
    #[test]
    fn many_small_chunks_dechunk_in_linear_time() {
        let raw = b"1\r\nx\r\n".repeat(1 << 18);
        let mut all = raw.clone();
        all.extend_from_slice(b"0\r\n\r\n");
        let t0 = std::time::Instant::now();
        let out = dechunk_bytes(&all);
        assert_eq!(out.len(), 1 << 18);
        assert!(t0.elapsed() < TestDuration::from_secs(1), "cuadrático: {:?}", t0.elapsed());
    }

    #[test]
    fn without_a_length_the_body_runs_to_the_close() {
        let (url, _h) = one_shot_server(|mut sock| {
            drain_request(&mut sock);
            sock.write_all(b"HTTP/1.0 200 OK\r\n\r\nab").unwrap();
            thread::sleep(TestDuration::from_millis(100));
            sock.write_all(b"cd").unwrap();
        });
        let r = host::http_request("GET", &url, None, None, None, 5);
        assert_eq!((r.status, r.body.as_str()), (200, "abcd"));
    }

    #[test]
    fn the_stream_reader_also_ends_without_close() {
        for parts in [
            vec![&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab"[..], b"cdIGNORED"],
            vec![&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n"[..], b"2\r\ncd\r\n0\r\n\r\n"],
        ] {
            let url = holding_server(parts);
            let t0 = std::time::Instant::now();
            let mut got: Vec<u8> = Vec::new();
            let (status, _) = host::http_request_stream("GET", &url, None, None, 5, &mut |b| {
                got.extend_from_slice(b);
                true
            })
            .unwrap();
            assert!(t0.elapsed() < TestDuration::from_secs(2), "el stream esperó al cierre: {:?}", t0.elapsed());
            assert_eq!((status, got.as_slice()), (200, &b"abcd"[..]));
        }
        let url = holding_server(vec![b"HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n"]);
        let t0 = std::time::Instant::now();
        let mut calls = 0;
        let (status, _) = host::http_request_stream("GET", &url, None, None, 5, &mut |_| {
            calls += 1;
            true
        })
        .unwrap();
        assert!(t0.elapsed() < TestDuration::from_secs(2));
        assert_eq!((status, calls), (204, 0));
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
            host::http_request_stream("GET", &url, None, None, 5, &mut |bytes| {
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
        let (status, _) = host::http_request_stream("GET", &url, None, None, 5, &mut |bytes| {
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
        let r = host::http_request_stream("GET", &url, None, None, 1, &mut |_| true);
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
        let (status, _) = host::http_request_stream("GET", &url2, None, None, 2, &mut |bytes| {
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
        use crate::http_common::{header_pairs_to, map_pairs_to, Outgoing};
        use synsema_core::types::{syn_secret, syn_text, SynValue};
        let mut m = synsema_core::types::SynMap::new();
        // Como lo devuelve `secret("STRIPE_KEY")` (v0.6.49: sólo uno así se puede atar).
        let read = |v: &str| SynValue::Secret(synsema_core::types::Obj::new(synsema_core::secret::SecretInner::new("STRIPE_KEY", v).from_config(true)));
        m.insert("Authorization", read("Bearer sk_live_LEAKCANARY"));
        m.insert("X-Trace", syn_text("plain"));
        let map = SynValue::Map(m.into_ref());

        // headers: el secret se MATERIALIZA (borde del socket) → plaintext real.
        let mut out = Outgoing::for_url("https://api.stripe.com/v1", "t");
        let hp = header_pairs_to(Some(&map), &mut out).ok().unwrap().unwrap();
        let auth = hp.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer sk_live_LEAKCANARY");
        assert!(hp.iter().any(|(k, v)| k == "X-Trace" && v == "plain"));

        // query params: un secret NO atado es ERROR (iría en la URL), y el mensaje dice cómo atarlo
        // (v0.6.46, E1; antes sólo decía que no había forma).
        let mut out = Outgoing::for_url("https://api.stripe.com/v1", "http_get");
        let e = match map_pairs_to(Some(&map), &mut out) {
            Err(synsema_core::interpreter::Control::Error(e)) => e.into_message(),
            _ => panic!("expected an error"),
        };
        assert!(e.contains("query parameter \"Authorization\" is secret(STRIPE_KEY)") && !e.contains("LEAKCANARY"), "{}", e);
        assert!(e.contains("require secret(\"STRIPE_KEY\") for net(\"api.stripe.com\")"), "{}", e);
        // v0.6.49 (§C): uno derivado o sellado por el programa no se puede atar: el error no lo sugiere.
        let mut derived = synsema_core::types::SynMap::new();
        derived.insert("k", syn_secret("H", "derivado"));
        let mut out = Outgoing::for_url("https://api.stripe.com/v1", "http_get");
        let e = match map_pairs_to(Some(&SynValue::Map(derived.into_ref())), &mut out) {
            Err(synsema_core::interpreter::Control::Error(e)) => e.into_message(),
            _ => panic!("expected an error"),
        };
        assert!(e.contains("made by the program") && !e.contains("for net(\"api.stripe.com\")") && !e.contains("derivado"), "{}", e);
    }

    /// El certificado de cliente es la identidad del workload: sólo se presenta a
    /// los hosts declarados en `opts.hosts` (sin la opción, a todos los que
    /// `require net` permita).
    /// v0.6.51 (G1-4): la identidad mTLS es de la corrida que la declaró: otra corrida del mismo
    /// proceso (o un hilo sin corrida) no la presenta.
    #[test]
    fn g1_4_the_mtls_identity_belongs_to_the_run_that_declared_it() {
        use synsema_core::run_scope::RunScope;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(Vec::new()).unwrap().self_signed(&key).unwrap();
        let der: rustls::pki_types::PrivateKeyDer<'static> =
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let (a, b) = (RunScope::new(), RunScope::new());
        *a.ext::<ClientTls>().identity.lock().unwrap() = Some((vec![cert.der().clone()], der));
        let presents = |run: Option<&Arc<RunScope>>| {
            let _e = run.map(|r| r.enter());
            let v: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(PinnedSpki::new(&[0]));
            tls_client_config("api.example", Some(v), true).unwrap().client_auth_cert_resolver.has_certs()
        };
        assert!(presents(Some(&a)), "la corrida que la declaró la presenta");
        assert!(!presents(Some(&b)), "otra corrida del proceso no");
        assert!(!presents(None), "un hilo sin corrida tampoco");
    }

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

#[cfg(test)]
mod content_length_tests {
    use super::{build_http_request, connect_error};

    /// RFC 9110 §8.6: un POST/PUT/PATCH sin cuerpo declara `Content-Length: 0`; un GET/DELETE
    /// sin cuerpo no lleva ninguno; con cuerpo, el largo real.
    #[test]
    fn bodyless_post_declares_content_length_zero() {
        let post = String::from_utf8(build_http_request("POST", "/push", "h", None, None)).unwrap();
        assert!(post.contains("\r\nContent-Length: 0\r\n"), "{}", post);
        assert!(post.ends_with("\r\n\r\n"));
        for m in ["put", "PATCH"] {
            let r = String::from_utf8(build_http_request(m, "/x", "h", None, None)).unwrap();
            assert!(r.contains("Content-Length: 0"), "{}", r);
        }
        let get = String::from_utf8(build_http_request("GET", "/x", "h", None, None)).unwrap();
        assert!(!get.contains("Content-Length"), "{}", get);
        let del = String::from_utf8(build_http_request("DELETE", "/x", "h", None, None)).unwrap();
        assert!(!del.contains("Content-Length"), "{}", del);
        let with = String::from_utf8(build_http_request("POST", "/x", "h", None, Some(b"abc"))).unwrap();
        assert!(with.contains("Content-Length: 3\r\n") && with.ends_with("\r\n\r\nabc"), "{}", with);
    }

    #[test]
    fn a_refused_localhost_on_ipv6_names_the_ipv4_address() {
        let refused = || std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let v6: std::net::SocketAddr = "[::1]:8080".parse().unwrap();
        let e = connect_error(refused(), "localhost", v6);
        assert!(e.contains("localhost resolved to ::1") && e.contains("http://127.0.0.1:8080"), "{}", e);
        // Una IP literal ya es lo que el programa pidió; IPv4 y otros errores quedan como estaban.
        assert!(!connect_error(refused(), "::1", v6).contains("127.0.0.1"));
        assert!(!connect_error(refused(), "localhost", "127.0.0.1:8080".parse().unwrap()).contains("resolved"));
        let timed_out = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert!(!connect_error(timed_out, "localhost", v6).contains("resolved"));
    }
}
