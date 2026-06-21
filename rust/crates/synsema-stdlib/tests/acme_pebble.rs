//! A2 batch 2 — Gate end-to-end de ACME/auto-HTTPS contra **Pebble** (CA ACME de
//! prueba de Let's Encrypt). Obtiene un cert real vía HTTP-01 (servido por NUESTRO
//! listener), lo guarda, sirve HTTPS con él y verifica el handshake.
//!
//! Está `#[ignore]` porque necesita el binario `pebble` (no se asume en toda CI).
//! Correr con:
//!   $env:PEBBLE = "$env:USERPROFILE\go\bin\pebble.exe"   # opcional (default ese path)
//!   cargo test -p synsema-stdlib --test acme_pebble -- --ignored --nocapture
//!
//! Instalar Pebble:  go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use synsema_stdlib::server::{self, ServeRuntime};

fn free_port() -> u16 {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    l.local_addr().unwrap().port()
}

fn pebble_path() -> PathBuf {
    if let Ok(p) = std::env::var("PEBBLE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    PathBuf::from(home).join("go").join("bin").join("pebble.exe")
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

/// Mata Pebble al salir del scope (incluso si el test paniquea).
struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requiere el binario pebble (go install .../pebble); correr con --ignored"]
fn acme_http01_end_to_end_against_pebble() {
    let pebble = pebble_path();
    assert!(
        pebble.is_file(),
        "no se encontró el binario pebble en {} — seteá $PEBBLE o `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`",
        pebble.display()
    );

    let base = std::env::temp_dir().join("syn_acme_pebble");
    std::fs::create_dir_all(&base).unwrap();
    let certdir = base.join("certs");
    let _ = std::fs::remove_dir_all(&certdir); // estado limpio
    std::fs::create_dir_all(&certdir).unwrap();

    // (1) Cert self-signed para el TLS del directorio Pebble (SAN: IP + localhost).
    //     El cliente ACME confiará en este mismo cert (builder_with_root).
    let dir_cert = rcgen::generate_simple_self_signed(vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "localhost".to_string(),
    ])
    .unwrap();
    let dir_cert_path = base.join("pebble_dir_cert.pem");
    let dir_key_path = base.join("pebble_dir_key.pem");
    std::fs::write(&dir_cert_path, dir_cert.cert.pem()).unwrap();
    std::fs::write(&dir_key_path, dir_cert.key_pair.serialize_pem()).unwrap();

    // (2) Puertos: directorio + management de Pebble, challenge HTTP (nuestro), HTTPS (nuestro).
    let dir_port = free_port();
    let mgmt_port = free_port();
    let challenge_port = free_port();
    let https_port = free_port();

    // (3) Config de Pebble. Paths con '/' (Go las acepta en Windows).
    let fwd = |p: &PathBuf| p.to_string_lossy().replace('\\', "/");
    let cfg = format!(
        r#"{{
  "pebble": {{
    "listenAddress": "127.0.0.1:{dir}",
    "managementListenAddress": "127.0.0.1:{mgmt}",
    "certificate": "{cert}",
    "privateKey": "{key}",
    "httpPort": {http},
    "tlsPort": {tls},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "profiles": {{
      "default": {{ "description": "default", "validityPeriod": 7776000 }}
    }}
  }}
}}"#,
        dir = dir_port,
        mgmt = mgmt_port,
        cert = fwd(&dir_cert_path),
        key = fwd(&dir_key_path),
        http = challenge_port,
        tls = free_port(),
    );
    let cfg_path = base.join("pebble_config.json");
    std::fs::write(&cfg_path, cfg).unwrap();

    // (4) Arranca Pebble (NOSLEEP para validación rápida).
    let child = Command::new(&pebble)
        .arg("-config")
        .arg(&cfg_path)
        .env("PEBBLE_VA_NOSLEEP", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("no se pudo arrancar Pebble");
    let _killer = Killer(child);
    assert!(wait_tcp(dir_port, 20), "Pebble no quedó listo en :{}", dir_port);

    // (5) Listener de challenge HTTP-01 (NUESTRO server) compartiendo el store.
    let store: server::ChallengeStore = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let chal = TcpListener::bind(("127.0.0.1", challenge_port)).unwrap();
    {
        let s = store.clone();
        thread::spawn(move || server::serve_acme_http(chal, https_port, s));
    }

    // (6) Configura el flujo ACME contra Pebble (directorio + CA de confianza + dir de certs).
    std::env::set_var("SYNSEMA_ACME_DIRECTORY", format!("https://127.0.0.1:{}/dir", dir_port));
    std::env::set_var("SYNSEMA_ACME_CA", &dir_cert_path);
    std::env::set_var("SYNSEMA_CERT_DIR", &certdir);

    // (7) Emite el cert end-to-end (cuenta → orden → HTTP-01 → finalize → cert).
    let (cert_path, key_path) =
        synsema_stdlib::acme::obtain_and_save("127.0.0.1", Some("admin@example.com"), store.clone())
            .expect("emisión ACME contra Pebble falló");
    assert!(cert_path.is_file() && key_path.is_file(), "no se guardaron cert/key");

    // (8) Construye el TLS config con el cert emitido y sirve HTTPS.
    let tls_cfg = server::build_tls_config(&cert_path.to_string_lossy(), &key_path.to_string_lossy())
        .expect("build_tls_config con el cert de Pebble");

    let www = base.join("www");
    std::fs::create_dir_all(&www).unwrap();
    std::fs::write(www.join("hello.txt"), b"hola acme").unwrap();
    let mut rtm = ServeRuntime::new(
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
    );
    rtm.tls_enabled = true;
    let rt = Arc::new(rtm);
    let cell: server::SharedServerConfig = Arc::new(RwLock::new(tls_cfg));
    let https = TcpListener::bind(("127.0.0.1", https_port)).unwrap();
    thread::spawn(move || server::serve_forever_tls_auto(rt, https, cell));

    // (9) Cliente TLS que confía en la cadena emitida; handshake real + GET.
    let chain_pem = std::fs::read(&cert_path).unwrap();
    let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &chain_pem[..]).collect::<Result<_, _>>().unwrap();
    assert!(!chain.is_empty(), "cadena de cert vacía");
    let mut roots = rustls::RootCertStore::empty();
    for c in &chain {
        let _ = roots.add(c.clone());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ccfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let sn = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(ccfg), sn).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", https_port)).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    tls.write_all(b"GET /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp); // cierre sin close_notify → Err tolerado
    let text = String::from_utf8_lossy(&resp);

    // Limpieza de env para no contaminar otros tests del proceso.
    std::env::remove_var("SYNSEMA_ACME_DIRECTORY");
    std::env::remove_var("SYNSEMA_ACME_CA");
    std::env::remove_var("SYNSEMA_CERT_DIR");

    assert!(
        text.starts_with("HTTP/1.1 200"),
        "el handshake/GET HTTPS con el cert de Pebble falló: {}",
        text
    );
    assert!(text.contains("hola acme"), "no llegó el body sobre HTTPS: {}", text);
    // hyper escribe header names en minúscula → chequeo case-insensitive.
    assert!(
        text.to_lowercase().contains("strict-transport-security"),
        "falta HSTS sobre HTTPS: {}",
        text
    );
}
