//! A1.v3 e2e: al encolarse un gate bajo serve sale UN webhook POST firmado (HMAC-SHA256
//! en `X-Synsema-Signature`) con el payload D2, y el humano puede decidir abriendo el
//! `respond_link_yes`/`no` (GET de un solo uso, HTML). Con el webhook caído el gate
//! sigue esperando igual (fire-and-forget). Todo en UN test: knobs por env de proceso y
//! sink de logs globales — los sub-escenarios van en secuencia.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, method: &str, target: &str, body: Option<&str>) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

/// Receptor fake del webhook: acepta conexiones para siempre, lee head + body (por
/// Content-Length), responde 200 y guarda `(head, body)` de cada POST.
fn spawn_webhook_receiver() -> (u16, Arc<Mutex<Vec<(String, String)>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { return };
            let mut acc: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&acc[..pos]).to_string();
                    let clen: usize = head
                        .to_lowercase()
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:").map(str::trim).map(String::from))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if acc.len() >= pos + 4 + clen {
                        let body =
                            String::from_utf8_lossy(&acc[pos + 4..pos + 4 + clen]).to_string();
                        rec.lock().unwrap().push((head, body));
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                        break;
                    }
                }
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => acc.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
        }
    });
    (port, received)
}

fn wait_server(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn wait_webhook(received: &Arc<Mutex<Vec<(String, String)>>>, count: usize) -> (String, String) {
    let start = Instant::now();
    loop {
        {
            let g = received.lock().unwrap();
            if g.len() >= count {
                return g[count - 1].clone();
            }
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no llegó el webhook #{}", count);
        thread::sleep(Duration::from_millis(30));
    }
}

/// `http://127.0.0.1:PORT/path?query` → `/path?query` (para el helper de requests).
fn link_target(link: &str, port: u16) -> String {
    link.strip_prefix(&format!("http://127.0.0.1:{}", port))
        .unwrap_or_else(|| panic!("el link no apunta al server: {}", link))
        .to_string()
}

#[test]
fn approval_webhook_and_links_end_to_end() {
    let (hook_port, received) = spawn_webhook_receiver();
    let serve_port = free_port();
    let public = format!("http://127.0.0.1:{}", serve_port);
    std::env::set_var("SYNSEMA_ENV_FILE", ""); // ≡ --no-env-file
    std::env::set_var("SYNSEMA_HUMAN_WEBHOOK", format!("http://127.0.0.1:{}/hook", hook_port));
    std::env::set_var("SYNSEMA_HUMAN_WEBHOOK_SECRET", "key");
    std::env::set_var("SYNSEMA_HUMAN_PUBLIC_URL", &public);

    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /gate"
        let ok be approve "Delete the production table?" within 25s
        give {{"approved": ok}}
"#,
        p = serve_port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_approvals_webhook.syn", false);
    });
    wait_server(serve_port);

    // -- 1: el encolado dispara UN webhook con el payload D2 y la firma verifica.
    let gate = thread::spawn(move || request(serve_port, "GET", "/gate", None));
    let (head, body) = wait_webhook(&received, 1);
    let sig = head
        .lines()
        .find_map(|l| l.to_lowercase().starts_with("x-synsema-signature:").then(|| l.split_once(':').unwrap().1.trim().to_string()))
        .expect("falta X-Synsema-Signature");
    let expected = format!(
        "sha256={}",
        synsema_stdlib::secrets::hmac_sha256_hex(b"key", body.as_bytes())
    );
    assert_eq!(sig, expected, "la firma HMAC debe verificar contra el body");

    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["type"], "approve");
    assert_eq!(payload["message"], "Delete the production table?");
    let token = payload["token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64, "OTT de 32 bytes en hex");
    let id = payload["id"].as_str().unwrap().to_string();
    assert_eq!(payload["respond_path"], format!("/approvals/{}", id));
    let link_yes = payload["respond_link_yes"].as_str().unwrap().to_string();
    let link_no = payload["respond_link_no"].as_str().unwrap().to_string();
    assert!(link_yes.starts_with(&public) && link_yes.ends_with("?d=yes"), "{}", link_yes);

    // `d` inválido → 400.
    let bad_d = request(
        serve_port,
        "GET",
        &link_target(&link_yes, serve_port).replace("?d=yes", "?d=quizas"),
        None,
    );
    assert!(bad_d.contains("400"), "d inválido debe dar 400: {}", bad_d);

    // Token malo → 403 HTML y el gate sigue (la pendiente sigue listada).
    let bad_tok = request(
        serve_port,
        "GET",
        &format!("/approvals/{}/{}?d=yes", id, "0".repeat(64)),
        None,
    );
    assert!(bad_tok.contains("403"), "token malo debe dar 403: {}", bad_tok);
    assert!(request(serve_port, "GET", "/approvals", None).contains(&id));

    // El humano abre el link YES → HTML de aprobado (sin el token) y el gate responde.
    let approved = request(serve_port, "GET", &link_target(&link_yes, serve_port), None);
    assert!(approved.contains("200"), "link yes: {}", approved);
    assert!(approved.contains("Approved") && approved.contains("HUMAN"), "{}", approved);
    let html_body = approved.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(!html_body.contains(&token), "el HTML no puede contener el token");
    let gate_resp = gate.join().unwrap();
    assert!(gate_resp.contains("\"approved\": true"), "gate: {}", gate_resp);

    // El link ya usado → 404 (un solo uso; también cubre el `no`, mismo camino).
    let reuse = request(serve_port, "GET", &link_target(&link_no, serve_port), None);
    assert!(reuse.contains("404"), "link reusado debe dar 404: {}", reuse);

    // -- 2: webhook CAÍDO → el gate espera igual (encolado, respondible) y muere por
    //       `within` si nadie contesta. Nuevo serve con la URL apuntando a un puerto
    //       cerrado (los knobs se leen al ejecutar el bloque serve).
    let dead_port = free_port(); // nadie escucha acá
    std::env::set_var("SYNSEMA_HUMAN_WEBHOOK", format!("http://127.0.0.1:{}/hook", dead_port));
    let serve2 = free_port();
    let prog2 = format!(
        r#"require serve({p})
serve on {p}
    route "GET /gate"
        let ok be approve "still works?" within 3s
        give {{"approved": ok}}
"#,
        p = serve2
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog2, "serve_approvals_webhook2.syn", false);
    });
    wait_server(serve2);
    let gate2 = thread::spawn(move || request(serve2, "GET", "/gate", None));
    // Mientras espera, la pendiente está listada (el webhook fallido no la rompió).
    let start = Instant::now();
    let mut listed = false;
    while start.elapsed() < Duration::from_secs(2) {
        if request(serve2, "GET", "/approvals", None).contains("interact_") {
            listed = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(listed, "con el webhook caído la pendiente debe seguir encolada");
    let gate2_resp = gate2.join().unwrap();
    assert!(
        gate2_resp.contains("\"approved\": false"),
        "sin respuesta el gate vence fail-closed: {}",
        gate2_resp
    );

    for k in ["SYNSEMA_HUMAN_WEBHOOK", "SYNSEMA_HUMAN_WEBHOOK_SECRET", "SYNSEMA_HUMAN_PUBLIC_URL", "SYNSEMA_ENV_FILE"] {
        std::env::remove_var(k);
    }
}
