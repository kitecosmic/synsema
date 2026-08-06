//! T5 — El handshake mTLS de verdad: un servidor rustls que EXIGE certificado de
//! cliente acepta al que presenta uno firmado por su CA y rechaza al que no.
//!
//! Este test vive del lado stdlib (no runtime) porque acá se puede construir el
//! `ClientConfig` con la CA de prueba; el cliente HTTP del engine usa los root CAs
//! del SISTEMA a propósito, y un test jamás debe tocarlos. Lo que se verifica es
//! el contrato TLS que `mtls_identity` habilita: `with_client_auth_cert` presenta
//! la cadena y el servidor la valida.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct Pki {
    ca_der: rustls::pki_types::CertificateDer<'static>,
    server_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    client_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    client_key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn make_pki() -> Pki {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "synsema-test-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut srv = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv.distinguished_name.push(DnType::CommonName, "localhost");
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let mut cli = CertificateParams::new(Vec::new()).unwrap();
    cli.distinguished_name.push(DnType::CommonName, "agent-7");
    let cli_key = KeyPair::generate().unwrap();
    let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

    Pki {
        ca_der: ca_cert.der().clone(),
        server_chain: vec![srv_cert.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::try_from(srv_key.serialize_der()).unwrap(),
        client_chain: vec![cli_cert.der().clone()],
        client_key: rustls::pki_types::PrivateKeyDer::try_from(cli_key.serialize_der()).unwrap(),
    }
}

/// Servidor TLS que exige cert de cliente. Devuelve (puerto, flag "vi un cert").
fn start_server(pki: &Pki) -> (u16, Arc<AtomicBool>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki.server_chain.clone(), pki.server_key.clone_key())
        .unwrap();
    let config = Arc::new(config);

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let saw_cert = Arc::new(AtomicBool::new(false));
    let saw = saw_cert.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let cfg = config.clone();
            let saw = saw.clone();
            thread::spawn(move || {
                let conn = match rustls::ServerConnection::new(cfg) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut buf = [0u8; 512];
                // El handshake corre en el primer read; si el cliente no presenta
                // cert, falla acá y no se registra nada.
                if tls.read(&mut buf).is_err() {
                    return;
                }
                if tls.conn.peer_certificates().is_some() {
                    saw.store(true, Ordering::SeqCst);
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
            });
        }
    });
    (port, saw_cert)
}

fn client_config(pki: &Pki, with_identity: bool) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let cfg = if with_identity {
        // Esto es EXACTAMENTE lo que hace `tls_client_config()` de http.rs cuando
        // el programa declaró `mtls_identity(cert, key)`.
        builder
            .with_client_auth_cert(pki.client_chain.clone(), pki.client_key.clone_key())
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(cfg)
}

/// Intenta una request; devuelve true si el servidor respondió 200.
fn try_request(port: u16, cfg: Arc<rustls::ClientConfig>) -> bool {
    let name: rustls::pki_types::ServerName<'static> = "localhost".try_into().unwrap();
    let Ok(conn) = rustls::ClientConnection::new(cfg, name) else { return false };
    let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)) else { return false };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    if tls
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut resp = String::new();
    let _ = tls.read_to_string(&mut resp);
    resp.starts_with("HTTP/1.1 200")
}

#[test]
fn client_certificate_is_required_and_accepted() {
    let pki = make_pki();
    let (port, saw_cert) = start_server(&pki);

    // (1) SIN identidad de cliente: el servidor corta el handshake.
    assert!(
        !try_request(port, client_config(&pki, false)),
        "sin certificado de cliente el servidor debe rechazar"
    );
    assert!(
        !saw_cert.load(Ordering::SeqCst),
        "no debería haber visto ningún certificado"
    );

    // (2) CON la identidad (lo que habilita `mtls_identity`): pasa y el servidor
    //     ve el certificado del workload.
    assert!(
        try_request(port, client_config(&pki, true)),
        "con certificado de cliente la request debe completar"
    );
    assert!(
        saw_cert.load(Ordering::SeqCst),
        "el servidor debe haber recibido el certificado del cliente"
    );
}
