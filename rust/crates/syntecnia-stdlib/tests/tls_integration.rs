//! A2 — Tests de integración del stack web nuevo: TLS (rustls/ring) sobre el
//! servidor std::net, HSTS automático, y la redirección http→https (:80 → 301).
//!
//! Genera un cert self-signed en runtime con rcgen (backend ring) y abre un
//! cliente rustls que confía en él, ejercitando el handshake real.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use syntecnia_stdlib::server::{
    build_tls_config, build_tls_config_sni, serve_forever_tls, serve_redirect, ServeRuntime,
};

/// Genera un cert+key self-signed para "localhost" y devuelve los PEM + el DER
/// del cert (para meterlo en el root store del cliente).
fn make_cert() -> (String, String, rustls::pki_types::CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let der = certified.cert.der().clone();
    (cert_pem, key_pem, der)
}

fn write_pems(tag: &str, cert_pem: &str, key_pem: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("syn_tls_it_{}", tag));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (cert_path, key_path)
}

fn static_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("syn_tls_it_www_{}", tag));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.txt"), b"hola tls").unwrap();
    dir
}

fn client_config(root: rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

fn static_rt(www: &std::path::Path) -> ServeRuntime {
    ServeRuntime::new(
        0,
        "0.0.0.0".to_string(),
        Vec::new(),
        None,
        None,
        64,
        vec![("/".to_string(), www.to_string_lossy().into_owned())],
        None,
        None,
        None,
        Vec::new(),
        false,
        false,
    )
}

#[test]
fn tls_serves_static_with_hsts() {
    let (cert_pem, key_pem, der) = make_cert();
    let (cert_path, key_path) = write_pems("hsts", &cert_pem, &key_pem);
    let www = static_dir("hsts");

    let tls_config =
        build_tls_config(&cert_path.to_string_lossy(), &key_path.to_string_lossy()).expect("tls config");

    let mut rt = static_rt(&www);
    rt.tls_enabled = true;
    let rt = Arc::new(rt);

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_forever_tls(rt, listener, tls_config));

    // Cliente TLS que confía en el cert self-signed.
    let cfg = client_config(der);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(cfg, server_name).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    tls.write_all(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    // El server cierra sin close_notify → read_to_end devuelve Err pero `resp` ya
    // tiene los bytes; lo toleramos.
    let _ = tls.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp);

    // hyper escribe los header names en minúscula (HTTP/2-style); chequeo case-insensitive.
    let lower = text.to_lowercase();
    assert!(text.starts_with("HTTP/1.1 200"), "status inesperado: {}", text);
    assert!(
        lower.contains("strict-transport-security: max-age=31536000; includesubdomains"),
        "falta HSTS: {}",
        text
    );
    assert!(lower.contains("etag:"), "falta ETag en estático: {}", text);
    assert!(text.contains("hola tls"), "falta el body: {}", text);
}

#[test]
fn redirect_to_https_default_port() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_redirect(listener, 443));

    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.write_all(b"GET /path?x=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp);

    assert!(text.starts_with("HTTP/1.1 301"), "status inesperado: {}", text);
    assert!(
        text.contains("Location: https://example.com/path?x=1"),
        "Location inesperada: {}",
        text
    );
}

#[test]
fn redirect_keeps_custom_https_port() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_redirect(listener, 8443));

    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // El Host trae el puerto :80; debe descartarse y usarse el puerto https.
    sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost:80\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp);

    assert!(
        text.contains("Location: https://localhost:8443/"),
        "Location inesperada: {}",
        text
    );
}

// ===================== Lote 1: SNI por-host (vhost) =====================

/// Genera un cert self-signed con SAN `name` y lo escribe; devuelve (cert_path,
/// key_path, cert_der).
fn write_named_cert(
    tag: &str,
    name: &str,
) -> (String, String, rustls::pki_types::CertificateDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let dir = std::env::temp_dir().join("syn_sni_it");
    std::fs::create_dir_all(&dir).unwrap();
    let cp = dir.join(format!("{}.pem", tag));
    let kp = dir.join(format!("{}.key.pem", tag));
    std::fs::write(&cp, c.cert.pem()).unwrap();
    std::fs::write(&kp, c.key_pair.serialize_pem()).unwrap();
    (
        cp.to_string_lossy().into_owned(),
        kp.to_string_lossy().into_owned(),
        c.cert.der().clone(),
    )
}

/// ¿Completa el handshake TLS contra `port` con SNI `server_name`, confiando sólo
/// en `trusted`? (Si el server presenta otro cert, falla la verificación → false.)
fn handshake_ok(
    port: u16,
    server_name: &str,
    trusted: rustls::pki_types::CertificateDer<'static>,
) -> bool {
    let mut roots = rustls::RootCertStore::empty();
    let _ = roots.add(trusted);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let sn = match rustls::pki_types::ServerName::try_from(server_name.to_string()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let conn = match rustls::ClientConnection::new(Arc::new(cfg), sn) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let sock = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut tls = rustls::StreamOwned::new(conn, sock);
    // El handshake (incl. verificación del cert) ocurre al primer IO.
    tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").is_ok()
        && tls.flush().is_ok()
}

#[test]
fn sni_selects_per_host_cert() {
    let (dc, dk, _dder) = write_named_cert("def", "localhost");
    let (ac, ak, ader) = write_named_cert("a", "a.example.com");
    let (bc, bk, bder) = write_named_cert("b", "b.example.com");

    let cfg = build_tls_config_sni(
        &dc,
        &dk,
        vec![("a.example.com".to_string(), ac, ak), ("b.example.com".to_string(), bc, bk)],
    )
    .expect("sni config");

    let mut rtm = ServeRuntime::new(
        0,
        "0.0.0.0".to_string(),
        Vec::new(),
        None,
        None,
        64,
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
        false,
        false,
    );
    rtm.tls_enabled = true;
    let rt = Arc::new(rtm);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_forever_tls(rt, listener, cfg));

    // SNI a.example.com → server presenta cert_a → confiar en cert_a verifica.
    assert!(handshake_ok(port, "a.example.com", ader.clone()), "SNI host-a debió verificar con cert_a");
    // SNI b.example.com confiando SÓLO en cert_a → server presenta cert_b → falla.
    assert!(!handshake_ok(port, "a.example.com", bder.clone()), "host-a no debería verificar con cert_b");
    // SNI b.example.com → server presenta cert_b → confiar en cert_b verifica.
    assert!(handshake_ok(port, "b.example.com", bder.clone()), "SNI host-b debió verificar con cert_b");
    // SNI b.example.com confiando en cert_a → falla (cert distinto por host).
    assert!(!handshake_ok(port, "b.example.com", ader.clone()), "host-b no debería verificar con cert_a");
}
