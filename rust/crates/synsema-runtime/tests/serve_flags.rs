//! Pieza A — flags de CLI para la config de despliegue del `serve`.
//! Corre programas .syn REALES por el motor con overrides (como los pasaría
//! `synsema serve <file> --port ... --tls-auto ...`) y verifica precedencia + fail-loud.
//!
//! Los flags viven en la capa de lanzamiento: NO tocan la gramática del `serve`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

/// Serializa los tests que tocan env-vars del proceso (ACME directory/cert dir).
static ENV_LOCK: Mutex<()> = Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Lanza el server en un hilo detached y espera readiness en `addr:port`.
fn start_bg(prog: String, addr: &str, port: u16, ov: ServeOverrides) {
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(&prog, "serve_flags.syn", false, ov);
    });
    for _ in 0..100 {
        if TcpStream::connect((addr, port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server no quedó listo en {}:{}", addr, port);
}

fn http_get(addr: &str, port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect((addr, port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(4)));
    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, addr);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp.to_ascii_lowercase()
}

/// Corre el serve hasta que retorna (para casos de ERROR; nunca debería bloquear).
/// Devuelve (success, errors_unidos). Si bloquea más de `secs`, el test falla.
fn run_to_completion(prog: String, ov: ServeOverrides, secs: u64) -> (bool, String) {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run_serve_program_with_overrides(&prog, "serve_flags.syn", false, ov);
        let _ = tx.send((r.success, r.errors.join(" | ")));
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(_) => panic!("serve no retornó en {}s (bloqueó inesperadamente)", secs),
    }
}

const PROG_8080: &str = r#"require serve(8080)
serve on 8080
    route "GET /ping"
        give {"ok": true}
"#;

// ── Test 1: --port sobreescribe `serve on N` ────────────────────────────────────
#[test]
fn flag_port_overrides_serve_on() {
    let p = free_port();
    let ov = ServeOverrides { port: Some(p), ..Default::default() };
    start_bg(PROG_8080.to_string(), "127.0.0.1", p, ov);
    let resp = http_get("127.0.0.1", p, "/ping");
    assert!(resp.starts_with("http/1.1 200"), "esperaba 200 en el puerto override: {}", resp);
    assert!(resp.contains("\"ok\""), "resp: {}", resp);
}

// ── Test 2: --port satisface la capability sin require serve(P) ──────────────────
#[test]
fn flag_port_satisfies_capability() {
    // El archivo NO declara `require serve(...)`: sin el flag, `serve on N` fallaría con
    // "missing capability". El operador que pasa --port es la autoridad → concede serve(P).
    let p = free_port();
    let src = r#"serve on 8080
    route "GET /"
        give "ok"
"#;
    let ov = ServeOverrides { port: Some(p), ..Default::default() };
    start_bg(src.to_string(), "127.0.0.1", p, ov);
    let resp = http_get("127.0.0.1", p, "/");
    assert!(resp.starts_with("http/1.1 200"), "esperaba 200 (cap concedida por el flag): {}", resp);
}

// ── Test 3: --tls-auto es el toggle dev↔prod ────────────────────────────────────
#[test]
fn flag_tls_auto_is_the_toggle() {
    // Sin flag → HTTP plano (dev).
    let p = free_port();
    let ov = ServeOverrides { port: Some(p), ..Default::default() };
    start_bg(PROG_8080.to_string(), "127.0.0.1", p, ov);
    let resp = http_get("127.0.0.1", p, "/ping");
    assert!(resp.starts_with("http/1.1 200"), "sin flag debe ser HTTP plano: {}", resp);

    // Con --tls-auto + --domain → entra en modo ACME aunque el archivo no tenga `tls`.
    // El directorio ACME apunta a un puerto cerrado → falla rápido (sin red real), lo que
    // PRUEBA que el toggle prendió TLS/ACME (no siguió en HTTP plano).
    let _g = env_lock();
    let dead = free_port(); // puerto libre → nadie escucha → connection refused
    let acme_http = free_port();
    let cert_dir = std::env::temp_dir().join(format!("syn_certs_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cert_dir);
    std::env::set_var("SYNSEMA_ACME_DIRECTORY", format!("http://127.0.0.1:{}/dir", dead));
    std::env::set_var("SYNSEMA_ACME_HTTP_PORT", acme_http.to_string());
    std::env::set_var("SYNSEMA_CERT_DIR", &cert_dir);

    let p2 = free_port();
    let ov2 = ServeOverrides {
        port: Some(p2),
        domains: Some(vec!["example.test".to_string()]),
        tls_auto_email: Some("admin@example.test".to_string()),
        ..Default::default()
    };
    let (ok, err) = run_to_completion(PROG_8080.to_string(), ov2, 30);

    std::env::remove_var("SYNSEMA_ACME_DIRECTORY");
    std::env::remove_var("SYNSEMA_ACME_HTTP_PORT");
    std::env::remove_var("SYNSEMA_CERT_DIR");
    let _ = std::fs::remove_dir_all(&cert_dir);

    assert!(!ok, "con --tls-auto debió entrar en ACME y fallar, no servir HTTP plano");
    assert!(err.to_ascii_lowercase().contains("acme"), "esperaba error ACME, got: {}", err);
}

// ── Test 4: precedencia — el flag pisa la cláusula del archivo ───────────────────
#[test]
fn flag_precedence_over_file_clause() {
    // `serve on 8080` en el archivo, pero --port P + --bind 127.0.0.1 ganan.
    let p = free_port();
    let ov = ServeOverrides {
        port: Some(p),
        bind: Some("127.0.0.1".to_string()),
        ..Default::default()
    };
    start_bg(PROG_8080.to_string(), "127.0.0.1", p, ov);
    let resp = http_get("127.0.0.1", p, "/ping");
    assert!(resp.starts_with("http/1.1 200"), "el flag debe pisar `serve on 8080`: {}", resp);
}

// ── Test 5: fail-loud (sin dominio / mutua exclusión) ───────────────────────────
#[test]
fn flag_errors_fail_loud() {
    // --tls-auto sin dominio (ni flag ni archivo) → error claro (antes de tocar la red).
    let p = free_port();
    let ov = ServeOverrides {
        port: Some(p),
        tls_auto_email: Some("a@b.com".to_string()),
        ..Default::default()
    };
    let (ok, err) = run_to_completion(PROG_8080.to_string(), ov, 15);
    assert!(!ok, "--tls-auto sin dominio debió fallar");
    assert!(err.to_ascii_lowercase().contains("domain"), "esperaba error de dominio, got: {}", err);

    // --tls-auto + --tls-cert → mutuamente excluyentes (validación fail-loud).
    let ov2 = ServeOverrides {
        tls_auto_email: Some("a@b.com".to_string()),
        tls_cert: Some("/x/cert.pem".to_string()),
        tls_key: Some("/x/key.pem".to_string()),
        ..Default::default()
    };
    let (ok2, err2) = run_to_completion(PROG_8080.to_string(), ov2, 15);
    assert!(!ok2, "--tls-auto + --tls-cert debió fallar");
    assert!(
        err2.to_ascii_lowercase().contains("mutually exclusive"),
        "esperaba error de exclusión mutua, got: {}",
        err2
    );
}

// ── Bonus: --tls-cert prende TLS manual aunque el archivo no tenga tls ───────────
#[test]
fn flag_tls_cert_enables_manual_tls() {
    let p = free_port();
    let ov = ServeOverrides {
        port: Some(p),
        tls_cert: Some("/no/such/cert.pem".to_string()),
        tls_key: Some("/no/such/key.pem".to_string()),
        ..Default::default()
    };
    // Archivos inexistentes → build_tls_config falla → "TLS error", lo que prueba que el
    // flag activó el modo TLS manual (el archivo no declara `tls`).
    let (ok, err) = run_to_completion(PROG_8080.to_string(), ov, 15);
    assert!(!ok, "--tls-cert inexistente debió fallar en modo TLS");
    assert!(err.to_ascii_lowercase().contains("tls"), "esperaba TLS error, got: {}", err);
}

// ── Generalidad: --tls-auto NO debe romperse si el archivo tiene certs por-host ──
// Un flag de CLL que fuerza TLS es la autoridad y define TLS por completo (ignora las
// cláusulas `tls` del archivo, incl. los certs por-host/SNI). Antes del fix, un archivo
// con un vhost que declara `tls cert ...` + `--tls-auto` daba el error espurio
// "per-host ... requires a default tls cert". Ahora llega a ACME (modo TLS correcto).
#[test]
fn tls_auto_ignores_file_per_host_certs() {
    let src = r#"require serve(8080)
serve on 8080
    host "www.example.test"
        tls cert "/no/such/host-cert.pem" key "/no/such/host-key.pem"
        route "GET /"
            give "vhost"
    route "GET /"
        give "default"
"#;
    let _g = env_lock();
    let dead = free_port();
    let acme_http = free_port();
    let cert_dir = std::env::temp_dir().join(format!("syn_certs_phc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cert_dir);
    std::env::set_var("SYNSEMA_ACME_DIRECTORY", format!("http://127.0.0.1:{}/dir", dead));
    std::env::set_var("SYNSEMA_ACME_HTTP_PORT", acme_http.to_string());
    std::env::set_var("SYNSEMA_CERT_DIR", &cert_dir);

    let ov = ServeOverrides {
        port: Some(free_port()),
        domains: Some(vec!["example.test".to_string()]),
        tls_auto_email: Some("admin@example.test".to_string()),
        ..Default::default()
    };
    let (ok, err) = run_to_completion(src.to_string(), ov, 30);

    std::env::remove_var("SYNSEMA_ACME_DIRECTORY");
    std::env::remove_var("SYNSEMA_ACME_HTTP_PORT");
    std::env::remove_var("SYNSEMA_CERT_DIR");
    let _ = std::fs::remove_dir_all(&cert_dir);

    assert!(!ok);
    let e = err.to_ascii_lowercase();
    assert!(e.contains("acme"), "esperaba modo ACME, got: {}", err);
    assert!(!e.contains("per-host"), "el cert por-host del archivo NO debe interferir: {}", err);
}

// ── Bonus: política de múltiples bloques serve con flags → rechazo claro ─────────
#[test]
fn flag_rejected_with_multiple_serve_blocks() {
    let a = free_port();
    let b = free_port();
    let src = format!(
        "require serve({a})\nrequire serve({b})\nserve on {a}\n    route \"GET /\"\n        give \"a\"\nserve on {b}\n    route \"GET /\"\n        give \"b\"\n",
        a = a,
        b = b
    );
    let ov = ServeOverrides { port: Some(free_port()), ..Default::default() };
    let (ok, err) = run_to_completion(src, ov, 15);
    assert!(!ok, "flags + múltiples `serve` debió ser rechazado");
    assert!(err.contains("exactly one `serve` block"), "got: {}", err);
}
