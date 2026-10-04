//! v0.6.42, auditoría ronda 2 — `tls auto` tal como lo arma `serve`, de punta a punta contra
//! **Pebble** (la CA de prueba de Let's Encrypt) y `pebble-challtestsrv` (su DNS de prueba):
//! - un nombre fijo (`domain [...]`) se emite al arrancar por HTTP-01 en el listener de
//!   `SYNSEMA_ACME_HTTP_PORT` que levanta `serve`;
//! - un nombre nuevo que aprueba la task de `domain ask` se emite durante el handshake, también
//!   por HTTP-01;
//! - la ruta contesta por HTTPS con el certificado de cada nombre; uno que `ask` rechaza no
//!   tiene certificado (el handshake termina en un alerta TLS).
//!
//! `#[ignore]` (necesita los binarios). Correr con:
//!   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//!   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//!   cargo test -p synsema-runtime --test v0642_acme_serve_pebble -- --ignored --nocapture

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn go_bin(name: &str) -> PathBuf {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
    let exe = if cfg!(windows) { format!("{}.exe", name) } else { name.to_string() };
    PathBuf::from(home).join("go").join("bin").join(exe)
}

fn wait_tcp(port: u16, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Acepta cualquier certificado (la cadena de Pebble no importa acá) pero lo guarda, para mirar
/// a qué nombre se emitió.
#[derive(Debug)]
struct Capture(std::sync::Mutex<Option<Vec<u8>>>);

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// GET por HTTPS con ese SNI: `Ok((certificado DER, respuesta))` o el error del handshake.
fn https_get(port: u16, sni: &str) -> Result<(Vec<u8>, String), String> {
    let capture = Arc::new(Capture(std::sync::Mutex::new(None)));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let sn = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), sn).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", sni).as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    match tls.read_to_end(&mut out) {
        Ok(_) => {}
        Err(e) if out.is_empty() => return Err(e.to_string()),
        Err(_) => {}
    }
    let cert = capture.0.lock().unwrap().clone().unwrap_or_default();
    Ok((cert, String::from_utf8_lossy(&out).to_string()))
}

fn names_in(der: &[u8]) -> Vec<String> {
    let (_, x) = x509_parser::parse_x509_certificate(der).unwrap();
    x.subject_alternative_name()
        .ok()
        .flatten()
        .map(|s| {
            s.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "requiere pebble y pebble-challtestsrv (go install …); correr con --ignored"]
fn serve_issues_fixed_and_on_demand_names_by_http01_against_pebble() {
    let (pebble, chal) = (go_bin("pebble"), go_bin("pebble-challtestsrv"));
    assert!(pebble.is_file() && chal.is_file(), "faltan {} o {}", pebble.display(), chal.display());

    let base = std::env::temp_dir().join(format!("syn_acme_serve_pebble_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let certdir = base.join("certs");
    std::fs::create_dir_all(&certdir).unwrap();
    let dir_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    let dir_cert_path = base.join("dir_cert.pem");
    let dir_key_path = base.join("dir_key.pem");
    std::fs::write(&dir_cert_path, dir_cert.cert.pem()).unwrap();
    std::fs::write(&dir_key_path, dir_cert.key_pair.serialize_pem()).unwrap();

    let (dir_port, mgmt_port, dns_port, chal_mgmt, http01_port, https_port) =
        (free_port(), free_port(), free_port(), free_port(), free_port(), free_port());

    let _chal = Killer(
        Command::new(&chal)
            .args(["-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""])
            .args(["-dnsserver", &format!("127.0.0.1:{}", dns_port)])
            .args(["-doh", "", "-http01", "", "-https01", "", "-tlsalpn01", ""])
            .args(["-management", &format!("127.0.0.1:{}", chal_mgmt)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("challtestsrv"),
    );
    assert!(wait_tcp(chal_mgmt, 20), "challtestsrv no quedó listo");

    // Pebble valida HTTP-01 contra el puerto que escucha `serve` (SYNSEMA_ACME_HTTP_PORT).
    let fwd = |p: &PathBuf| p.to_string_lossy().replace('\\', "/");
    let cfg = format!(
        r#"{{"pebble": {{"listenAddress": "127.0.0.1:{d}", "managementListenAddress": "127.0.0.1:{m}",
  "certificate": "{c}", "privateKey": "{k}", "httpPort": {h}, "tlsPort": {t},
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "profiles": {{"default": {{"description": "default", "validityPeriod": 7776000}}}}}}}}"#,
        d = dir_port,
        m = mgmt_port,
        c = fwd(&dir_cert_path),
        k = fwd(&dir_key_path),
        h = http01_port,
        t = https_port
    );
    let cfg_path = base.join("pebble.json");
    std::fs::write(&cfg_path, cfg).unwrap();
    let _pebble = Killer(
        Command::new(&pebble)
            .arg("-config")
            .arg(&cfg_path)
            .args(["-dnsserver", &format!("127.0.0.1:{}", dns_port)])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("pebble"),
    );
    assert!(wait_tcp(dir_port, 20), "Pebble no quedó listo");

    std::env::set_var("SYNSEMA_ACME_DIRECTORY", format!("https://127.0.0.1:{}/dir", dir_port));
    std::env::set_var("SYNSEMA_ACME_CA", &dir_cert_path);
    std::env::set_var("SYNSEMA_CERT_DIR", &certdir);
    std::env::set_var("SYNSEMA_ACME_HTTP_PORT", http01_port.to_string());
    std::env::set_var("SYNSEMA_ENV_FILE", "");

    let p = https_port;
    let prog = format!(
        r#"require serve({p})

task approve_host(host)
    give host == "dyn.test"

serve on {p}
    tls auto "admin@example.test"
    domain ["fixed.test"]
    domain ask approve_host
    route "GET /"
        give "hola"
"#,
        p = p
    );
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run_serve_program(&prog, "v0642_acme_serve_pebble.syn", false);
        let _ = tx.send(format!("success={} errors={:?} output={:?}", r.success, r.errors, r.output));
    });
    // El HTTPS arranca después de emitir (o no) los fijos.
    if !wait_tcp(p, 60) {
        panic!("el HTTPS no quedó escuchando: {:?}", rx.try_recv());
    }
    // El puerto se abre antes de emitir: se espera al fijo (que se emite por HTTP-01).
    let deadline = Instant::now() + Duration::from_secs(60);
    while !certdir.join("fixed.test.pem").is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(certdir.join("fixed.test.pem").is_file(), "el fijo se emitió al arrancar, por HTTP-01: {:?}", rx.try_recv());
    thread::sleep(Duration::from_millis(300));

    let (cert, resp) = https_get(p, "fixed.test").expect("handshake con el fijo");
    assert!(names_in(&cert).contains(&"fixed.test".to_string()), "{:?}", names_in(&cert));
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("hola"), "{}", resp);

    // Bajo demanda: el primer handshake dispara la emisión y espera el certificado.
    let (cert, resp) = https_get(p, "dyn.test").expect("handshake bajo demanda");
    assert!(names_in(&cert).contains(&"dyn.test".to_string()), "{:?}", names_in(&cert));
    assert!(resp.contains("hola"), "{}", resp);

    // `ask` dice que no: alerta TLS, sin certificado ni archivo.
    let e = https_get(p, "nope.test").err().expect("sin certificado no hay handshake");
    assert!(e.to_lowercase().contains("alert") || e.to_lowercase().contains("handshake"), "{}", e);
    assert!(!certdir.join("nope.test.pem").exists());

    for v in ["SYNSEMA_ACME_DIRECTORY", "SYNSEMA_ACME_CA", "SYNSEMA_CERT_DIR", "SYNSEMA_ACME_HTTP_PORT"] {
        std::env::remove_var(v);
    }
}
