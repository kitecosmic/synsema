//! v0.6.46 (E6-h) — `serve --auditor`: un recibo sellado por request que corre código del programa,
//! escrito ANTES de mandar la respuesta, firmado con la clave de identidad del host
//! (`SYNSEMA_IDENTITY_KEY`) y con lo de la rama privada adentro del sobre.
//!
//! Binario propio: los recibos de `serve` se instalan una vez por proceso.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};
use synsema_stdlib::sealed;

const PROG: &str = r#"require serve(8080)
require random
require time
serve on 8080
    route "GET /r"
        let s be private(5, "app")
        let a be random()
        when s > 3
            let b be random()
            let t be now()
        give {"a": a}
    route "GET /plain"
        give "hola"
"#;

const STREAM: &str = r#"require serve(8080)
serve on 8080
    route "GET /s"
        stream
            emit("x")
"#;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
    let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn lines(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("cada línea es un recibo JSON"))
        .collect()
}

#[test]
fn e6_serve_receipt_per_request() {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let seed = [0x42u8; 32];
    std::env::set_var("SYNSEMA_IDENTITY_KEY", synsema_core::bytesutil::hex_encode(&seed));
    let (sk, pk) = sealed::generate_keypair();
    let auditor = sealed::parse_auditor_key(&pk).unwrap();
    let sk = synsema_core::bytesutil::b64url_decode(&sk).unwrap();
    let dest = std::env::temp_dir().join(format!("e6_serve_receipts_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&dest);

    // Una ruta `stream` manda su body mientras corre: con auditor no carga.
    let (tx, rx) = std::sync::mpsc::channel();
    let ov = ServeOverrides { port: Some(free_port()), auditor: Some(auditor), ..Default::default() };
    thread::spawn(move || {
        let r = run_serve_program_with_overrides(STREAM, "e6_stream.syn", false, ov);
        let _ = tx.send((r.success, r.errors.join(" | ")));
    });
    let (ok, err) = rx.recv_timeout(Duration::from_secs(30)).expect("el serve con stream no retornó");
    assert!(!ok && err.contains("is a stream route"), "{}", err);

    let port = free_port();
    let ov = ServeOverrides {
        port: Some(port),
        auditor: Some(auditor),
        receipt: Some(dest.to_string_lossy().into_owned()),
        sealed_bytes: Some(8192),
        ..Default::default()
    };
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(PROG, "e6_serve.syn", false, ov);
    });
    let mut ready = false;
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo");

    // El recibo ya está escrito cuando llega la respuesta.
    let resp = http_get(port, "/plain");
    assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
    assert_eq!(lines(&dest).len(), 1, "la request que corrió código dejó su recibo antes de la respuesta");
    // Sin código del programa (404 del router), no hay recibo.
    let resp = http_get(port, "/nope");
    assert!(resp.starts_with("HTTP/1.1 404"), "{}", resp);
    assert_eq!(lines(&dest).len(), 1);
    let resp = http_get(port, "/r");
    assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
    let rs = lines(&dest);
    assert_eq!(rs.len(), 2);

    let expected_pub = synsema_core::bytesutil::b64url_encode(&sealed::RunKey::from_identity_seed(&seed).public_bytes());
    for r in &rs {
        let h = sealed::verify_receipt(r).expect("el recibo verifica");
        assert_eq!(h["run_key"]["identity"], "identity");
        assert_eq!(h["run_key"]["public"], Value::String(expected_pub.clone()));
        assert_eq!(h["sealed_bytes"], 8192);
    }
    // La forma no depende de lo que pasó en la rama privada.
    assert_eq!(rs[0]["sealed"].as_str().unwrap().len(), rs[1]["sealed"].as_str().unwrap().len());

    // Lo de la rama privada (el segundo `random` y el `now`) va adentro del sobre, no afuera.
    let public = rs[1]["public"].as_array().unwrap();
    assert!(public.iter().all(|e| e["capability"] != "time"), "{:?}", public);
    let opened = sealed::open_receipt(&rs[1], &sk).expect("el auditor lo abre");
    let entries = opened["entries"].as_array().unwrap();
    assert!(
        entries.iter().any(|e| e["sealed"] == true && e["entry"]["capability"] == "time"),
        "{:?}",
        entries
    );
    assert!(entries.iter().any(|e| e["sealed"] == true && e["entry"]["capability"] == "random"));
    assert_eq!(opened["clock"].as_array().map(Vec::len), Some(1));
    let _ = std::fs::remove_file(&dest);
}
