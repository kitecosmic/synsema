//! A1.v2 e2e: un `approve`/`ask` dentro de un handler de `serve` se ENCOLA y el
//! request bloquea hasta la respuesta humana (POST /approvals/{id} con el token de un
//! solo uso que salió por la consola del server) o el deadline (`within`), que DENIEGA
//! fail-closed. Todo el flujo va en UN test: el sink de logs de serve es global al
//! proceso y los sub-escenarios comparten el server.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::{run_serve_program, set_serve_log_sink};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, method: &str, target: &str, body: Option<&str>) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // Generoso: el GET /gate queda BLOQUEADO esperando la respuesta humana.
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

/// Extrae `(id, token)` de la línea de consola
/// `[synsema] approval pending <id> — "…" … {"decision": true|false, "token": "<tok>"}`.
fn parse_notice(line: &str) -> (String, String) {
    let after = line.strip_prefix("[synsema] approval pending ").expect("prefijo del aviso");
    let id = after.split_whitespace().next().expect("id en el aviso").to_string();
    let tok_marker = "\"token\": \"";
    let tpos = line.rfind(tok_marker).expect("token en el aviso") + tok_marker.len();
    let token = line[tpos..].trim_end_matches(['"', '}']).to_string();
    (id, token)
}

/// Espera (poll) a que aparezca un aviso de encolado NUEVO más allá de `seen`.
fn wait_notice(captured: &Arc<Mutex<Vec<String>>>, seen: usize) -> String {
    let start = Instant::now();
    loop {
        {
            let lines = captured.lock().unwrap();
            if let Some(l) = lines
                .iter()
                .skip(seen)
                .find(|l| l.starts_with("[synsema] approval pending "))
            {
                return l.clone();
            }
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no llegó el aviso de encolado");
        thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn approvals_queue_end_to_end() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let c = captured.clone();
        set_serve_log_sink(Some(Arc::new(move |line: &str| {
            c.lock().unwrap().push(line.to_string());
        })));
    }

    let port = free_port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /gate"
        let ok be approve "¿operación sensible?" within 25s
        give {{"approved": ok}}
    route "GET /gate-fast"
        let ok be approve "¿rápido?" within 1s
        give {{"approved": ok}}
    route "GET /ask"
        let v be ask "¿color?" within 25s
        give {{"value": v}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_approvals.syn", false);
    });
    let mut ready = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo en :{}", port);

    // -- 1: el gate queda esperando; GET /approvals lo lista SIN token; el POST con el
    //       token de la consola y decision:true → el request original {"approved": true}.
    let gate = thread::spawn(move || request(port, "GET", "/gate", None));
    let notice = wait_notice(&captured, 0);
    let (id, token) = parse_notice(&notice);
    assert!(!token.is_empty() && token.len() == 64, "token hex de 32 bytes: {}", token);

    let list = request(port, "GET", "/approvals", None);
    assert!(list.contains("200"), "GET /approvals: {}", list);
    assert!(list.contains(&id), "la pendiente debe listarse: {}", list);
    assert!(list.contains("expires_at"), "la pendiente lleva vencimiento: {}", list);
    assert!(!list.contains(&token), "el token NO puede salir por GET /approvals");

    // Token inválido → 403 y el gate SIGUE esperando (la pendiente sigue listada).
    let bad = request(
        port,
        "POST",
        &format!("/approvals/{}", id),
        Some("{\"token\": \"nope\", \"decision\": true}"),
    );
    assert!(bad.contains("403"), "token inválido debe dar 403: {}", bad);
    let list2 = request(port, "GET", "/approvals", None);
    assert!(list2.contains(&id), "tras el 403 el gate sigue esperando: {}", list2);

    // Body malformado → 400.
    let malformed =
        request(port, "POST", &format!("/approvals/{}", id), Some("esto no es json"));
    assert!(malformed.contains("400"), "body malformado debe dar 400: {}", malformed);

    // Respuesta buena → 200 y el handler bloqueado devuelve {"approved": true}.
    let ok = request(
        port,
        "POST",
        &format!("/approvals/{}", id),
        Some(&format!("{{\"token\": \"{}\", \"decision\": true}}", token)),
    );
    assert!(ok.contains("200") && ok.contains("\"ok\": true"), "respond: {}", ok);
    let gate_resp = gate.join().unwrap();
    assert!(
        gate_resp.contains("\"approved\": true"),
        "el gate aprobado debe dar approved:true: {}",
        gate_resp
    );

    // Un solo uso: el mismo id + token ya no existe → 404.
    let again = request(
        port,
        "POST",
        &format!("/approvals/{}", id),
        Some(&format!("{{\"token\": \"{}\", \"decision\": true}}", token)),
    );
    assert!(again.contains("404"), "el token es de un solo uso: {}", again);

    // -- 2: mismo gate con decision:false → {"approved": false}.
    let seen = captured.lock().unwrap().len();
    let gate2 = thread::spawn(move || request(port, "GET", "/gate", None));
    let (id2, token2) = parse_notice(&wait_notice(&captured, seen));
    let deny = request(
        port,
        "POST",
        &format!("/approvals/{}", id2),
        Some(&format!("{{\"token\": \"{}\", \"decision\": false}}", token2)),
    );
    assert!(deny.contains("200"), "respond deny: {}", deny);
    let gate2_resp = gate2.join().unwrap();
    assert!(
        gate2_resp.contains("\"approved\": false"),
        "decision:false debe dar approved:false: {}",
        gate2_resp
    );

    // -- 3 (D5): `ask` también va por la cola; el humano responde `value`.
    let seen = captured.lock().unwrap().len();
    let ask = thread::spawn(move || request(port, "GET", "/ask", None));
    let (id3, token3) = parse_notice(&wait_notice(&captured, seen));
    let ans = request(
        port,
        "POST",
        &format!("/approvals/{}", id3),
        Some(&format!("{{\"token\": \"{}\", \"value\": \"azul\"}}", token3)),
    );
    assert!(ans.contains("200"), "respond ask: {}", ans);
    let ask_resp = ask.join().unwrap();
    assert!(
        ask_resp.contains("\"value\": \"azul\""),
        "el ask debe devolver el value humano: {}",
        ask_resp
    );

    // -- 4 (D1): sin respuesta → al deadline el gate DENIEGA fail-closed.
    let timed = request(port, "GET", "/gate-fast", None);
    assert!(
        timed.contains("\"approved\": false"),
        "el gate vencido debe denegar fail-closed: {}",
        timed
    );

    set_serve_log_sink(None);
}
