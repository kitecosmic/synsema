//! v0.6.42 — certificados administrados (`acme_manager`) de punta a punta contra **Pebble** (la CA
//! de prueba de Let's Encrypt) y su DNS de prueba `pebble-challtestsrv`:
//! - un wildcard (`*.wild.test`) al arrancar, por DNS-01, publicando el TXT con la "task" del
//!   programa (acá, la API de challtestsrv);
//! - la cuenta ACME queda guardada en disco;
//! - un SNI nuevo aprobado por `ask` se emite DURANTE el handshake, por TLS-ALPN-01, con el
//!   servidor HTTPS administrado ya sirviendo; uno que `ask` rechaza no se emite.
//!
//! `#[ignore]` (necesita los binarios). Correr con:
//!   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//!   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//!   cargo test -p synsema-stdlib --test acme_manager_pebble -- --ignored --nocapture

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use synsema_stdlib::acme_manager::{AcmeOptions, AskFn, CertManager, DnsFn};
use synsema_stdlib::server::{self, ServeRuntime};

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

/// POST JSON a la API de management de challtestsrv.
fn chal_post(port: u16, path: &str, body: &str) -> Result<(), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.write_all(
        format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            body.len(),
            body
        )
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    if resp.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(resp)
    }
}

/// Un handshake TLS con ese SNI (la verificación del cliente falla a propósito: lo que importa es
/// que el servidor reciba el ClientHello y decida si emite).
fn touch(port: u16, sni: &str) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let sn = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), sn).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let _ = tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
}

#[test]
#[ignore = "requiere pebble y pebble-challtestsrv (go install …); correr con --ignored"]
fn wildcard_by_dns01_and_on_demand_by_tls_alpn_against_pebble() {
    let (pebble, chal) = (go_bin("pebble"), go_bin("pebble-challtestsrv"));
    assert!(pebble.is_file() && chal.is_file(), "faltan {} o {}", pebble.display(), chal.display());

    let base = std::env::temp_dir().join(format!("syn_acme_mgr_pebble_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let certdir = base.join("certs");
    std::fs::create_dir_all(&certdir).unwrap();

    // Cert del directorio de Pebble (el cliente ACME confía en él).
    let dir_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    let dir_cert_path = base.join("dir_cert.pem");
    let dir_key_path = base.join("dir_key.pem");
    std::fs::write(&dir_cert_path, dir_cert.cert.pem()).unwrap();
    std::fs::write(&dir_key_path, dir_cert.key_pair.serialize_pem()).unwrap();

    let (dir_port, mgmt_port, dns_port, chal_mgmt, https_port) =
        (free_port(), free_port(), free_port(), free_port(), free_port());

    std::env::set_var("SYNSEMA_ACME_DIRECTORY", format!("https://127.0.0.1:{}/dir", dir_port));
    std::env::set_var("SYNSEMA_ACME_CA", &dir_cert_path);
    std::env::set_var("SYNSEMA_CERT_DIR", &certdir);
    std::env::set_var("SYNSEMA_ACME_DNS_WAIT", "0");

    // La "task" de `tls dns`: publica y retira el TXT (acá contra challtestsrv; en un programa,
    // contra la API del proveedor de DNS).
    let dns: DnsFn = Arc::new(move |name: &str, value: &str, action: &str| match action {
        "set" => chal_post(chal_mgmt, "/set-txt", &format!(r#"{{"host":"{}.","value":"{}"}}"#, name, value)),
        _ => chal_post(chal_mgmt, "/clear-txt", &format!(r#"{{"host":"{}."}}"#, name)),
    });

    // (0) Auditoría ronda 2 (R2): un nombre fijo con la CA todavía caída. El arranque no lo
    //     consigue (y no se cuelga); la pasada de renovación lo consigue cuando la CA aparece.
    let late = CertManager::new_for_test(
        AcmeOptions { email: None, domains: vec!["late.test".to_string()], ask: None, dns: Some(dns.clone()), http_store: None },
        Duration::ZERO,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();
    assert_eq!(late.bootstrap().unwrap(), vec!["late.test".to_string()]);
    assert!(t0.elapsed() < Duration::from_secs(30), "el arranque no se cuelga: {:?}", t0.elapsed());
    assert!(late.cert_for("late.test").is_none());

    // DNS de prueba: todo nombre resuelve a 127.0.0.1; el TXT lo publica la "task".
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
        h = free_port(),
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

    // (0, sigue) La CA ya está: la renovación consigue el nombre que faltaba.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let still = rt.block_on(late.renew_due());
    assert!(still.is_empty(), "sigue faltando: {:?}", still);
    assert!(late.cert_for("late.test").is_some(), "el nombre fijo se reintentó y se emitió");
    let ask: AskFn = Arc::new(|host: &str| host == "ok.test");
    let mgr = CertManager::new(AcmeOptions {
        email: Some("admin@example.test".to_string()),
        domains: vec!["*.wild.test".to_string()],
        ask: Some(ask),
        dns: Some(dns),
        http_store: None,
    });

    // (1) Arranque: el wildcard por DNS-01.
    mgr.bootstrap().expect("wildcard por DNS-01 contra Pebble");
    assert!(mgr.cert_for("k7f3q9.wild.test").is_some(), "el wildcard cubre un subdominio");
    assert!(certdir.join("_.wild.test.pem").is_file(), "el cert queda en disco");
    let account = std::fs::read_dir(&certdir)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("account-"));
    assert!(account, "la cuenta ACME queda guardada para reusarse");

    // (2) El HTTPS administrado sirviendo; un SNI nuevo se pregunta y se emite por TLS-ALPN-01.
    let mut rtm = ServeRuntime::new(0, "0.0.0.0".to_string(), Vec::new(), None, None, 64, Vec::new(), None, None, None, Vec::new(), false, false);
    rtm.tls_enabled = true;
    let rt = Arc::new(rtm);
    let https = TcpListener::bind(("127.0.0.1", https_port)).unwrap();
    {
        let m = mgr.clone();
        thread::spawn(move || server::serve_forever_tls_managed(rt, https, m));
    }
    assert!(wait_tcp(https_port, 10));
    touch(https_port, "ok.test");
    let deadline = Instant::now() + Duration::from_secs(20);
    while mgr.cert_for("ok.test").is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
    }
    assert!(mgr.cert_for("ok.test").is_some(), "`ask` dijo que sí: se emite durante el handshake");

    // (3) `ask` dice que no: nada se emite.
    touch(https_port, "no.test");
    thread::sleep(Duration::from_millis(500));
    assert!(mgr.cert_for("no.test").is_none());
    assert!(!certdir.join("no.test.pem").exists());

    for v in ["SYNSEMA_ACME_DIRECTORY", "SYNSEMA_ACME_CA", "SYNSEMA_CERT_DIR", "SYNSEMA_ACME_DNS_WAIT"] {
        std::env::remove_var(v);
    }
}
