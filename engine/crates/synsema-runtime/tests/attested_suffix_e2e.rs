//! v0.6.51 (auditoría, ronda 3, N3): bajo `serve --attested` el sufijo `.md`/`.json`/`.html` de una
//! ruta literal nunca se lleva una URL reservada del runtime, tampoco con `private` (que no la
//! publica): es la misma regla que el chequeo de carga, que no deja declararla. Una URL que no es
//! reservada se sigue negociando. Va en su propio binario porque la identidad atestada es del
//! proceso: un segundo `serve --attested` en `attested_serve_e2e` no arranca.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};
use synsema_stdlib::attest::parse_http_response;

/// Acepta cualquier certificado: el test mira la respuesta, no la identidad.
#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn https_get(port: u16, path: &str) -> (u16, String) {
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    tls.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    // Un servidor que cierra sin close_notify da UnexpectedEof: si ya hay bytes, es la respuesta.
    let _ = tls.read_to_end(&mut raw);
    parse_http_response(&raw).unwrap()
}

#[test]
fn attested_serve_never_lets_a_suffix_take_a_reserved_url() {
    std::env::set_var("SYNSEMA_ATTEST", "mock");
    let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let prog = "require serve(8080)\nserve on 8080\n    private\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /openapi\"\n        give content(page([heading(1, \"Mia\")], {\"title\": \"T\"}))\n";
    let ov = ServeOverrides { port: Some(port), bind: Some("127.0.0.1".to_string()), attested: true, ..Default::default() };
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run_serve_program_with_overrides(prog, "suffix.syn", false, ov);
        let _ = tx.send(r.errors.join(" | "));
    });
    let mut ready = false;
    for _ in 0..300 {
        if let Ok(errors) = rx.try_recv() {
            panic!("el serve atestado terminó antes de servir: {}", errors);
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el serve atestado no quedó listo");
    let (status, body) = https_get(port, "/openapi.json");
    assert_eq!(status, 404, "la ruta se llevó una URL reservada: {}", body);
    // Ronda 4 (N1): tampoco con barras repetidas, que el router ignora.
    let (status, body) = https_get(port, "//openapi.json");
    assert_eq!(status, 404, "la ruta se llevó una URL reservada: {}", body);
    let (status, body) = https_get(port, "/openapi.md");
    assert!(status == 200 && body.contains("# Mia"), "{} {}", status, body);
}
