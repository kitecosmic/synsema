//! E2E de la tanda "aplicaciones agénticas" (spec `agentic-apps-gaps.md`) por el
//! runtime REAL, sin red externa:
//!
//! - rutas `socket` (WebSocket entrante): eco text/binary, cierre limpio 1000, 426 sin
//!   upgrade, 401 con `requires auth`, 1011 + motivo si el cuerpo falla, `ws_stats.role`;
//! - `socket` + `proc_spawn` + `select`: la salida de un proceso hijo llega al cliente
//!   línea a línea y termina con su exit code;
//! - SSE alimentado por el bus (`bus_subscribe` en un `stream`, `bus_publish` desde otra
//!   ruta) + heartbeat `: keepalive` automático;
//! - `timeout` del serve/route: 504 al vencer, el handler queda CANCELADO (no sigue
//!   ejecutando), `timeout none` lo anula por ruta;
//! - `agents()` / `agent_stop(id)` en modo run;
//! - errores de parseo fail-loud (`socket` + `stream`, `socket` en POST, `timeout` doble).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::engine::{run_program, run_source};
use synsema_runtime::serve::run_serve_program;
use tungstenite::Message;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn start(prog: String) -> u16 {
    let port = free_port();
    let prog = prog.replace("{p}", &port.to_string());
    thread::spawn(move || {
        let r = run_serve_program(&prog, "<agentic-e2e>", false);
        if !r.success {
            eprintln!("serve terminó con errores: {:?}", r.errors);
        }
    });
    wait_ready(port);
    port
}

fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)], body: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn shell_require() -> &'static str {
    if cfg!(windows) {
        "require exec(\"cmd\")"
    } else {
        "require exec(\"sh\")"
    }
}

fn shell_spawn(unix: &str, win: &str) -> String {
    if cfg!(windows) {
        format!("proc_spawn(\"cmd\", [\"/C\", \"{}\"])", win)
    } else {
        format!("proc_spawn(\"sh\", [\"-c\", \"{}\"])", unix)
    }
}

// =========================================================
// socket
// =========================================================

fn socket_server() -> u16 {
    start(
        r#"require serve({p})
require time

task check(token)
    give when token == "secreto" then {"name": "agente"} otherwise nothing

serve on {p}
    auth with check

    route "GET /ws"
        socket
            ws_send(socket, "role:" + ws_stats(socket)["role"])
            while true
                let ev be ws_recv(socket, 10)
                when ev == nothing
                    stop
                when ev["type"] == "close"
                    stop
                when ev["type"] == "binary"
                    ws_send(socket, ev["data"])
                otherwise
                    ws_send(socket, "echo:" + ev["data"])

    route "GET /private" requires auth
        socket
            ws_send(socket, "hello " + request.user.name)

    route "GET /boom"
        socket
            let first be ws_recv(socket, 5)
            raise "handler exploded on purpose"

    route "GET /hang"
        timeout 1
        socket
            let never be ws_recv(socket, 30)

    route "GET /health"
        give {"ok": true}
"#
        .to_string(),
    )
}

#[test]
fn socket_route_echoes_text_and_binary_then_closes_cleanly() {
    let port = socket_server();
    let (mut ws, resp) = tungstenite::connect(format!("ws://127.0.0.1:{}/ws", port)).expect("handshake 101");
    assert_eq!(resp.status().as_u16(), 101);
    // Primer mensaje: el rol visto desde el handler.
    match ws.read().unwrap() {
        Message::Text(t) => assert_eq!(t.as_str(), "role:server"),
        other => panic!("esperaba texto, got {:?}", other),
    }
    ws.send(Message::text("hola")).unwrap();
    match ws.read().unwrap() {
        Message::Text(t) => assert_eq!(t.as_str(), "echo:hola"),
        other => panic!("esperaba eco, got {:?}", other),
    }
    ws.send(Message::binary(vec![1u8, 2, 3, 255])).unwrap();
    match ws.read().unwrap() {
        Message::Binary(b) => assert_eq!(b.as_ref(), &[1u8, 2, 3, 255]),
        other => panic!("esperaba binario, got {:?}", other),
    }
    // El cliente cierra → el handler ve `close`, termina, y el server cierra limpio.
    ws.close(None).unwrap();
    let t0 = Instant::now();
    loop {
        assert!(t0.elapsed() < Duration::from_secs(10), "el cierre no llegó");
        match ws.read() {
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => break,
            Err(e) => panic!("error inesperado al cerrar: {}", e),
        }
    }
    // El server sigue vivo para HTTP normal.
    assert_eq!(status(&request(port, "GET", "/health", &[], "")), 200);
}

#[test]
fn socket_route_without_upgrade_is_426_and_auth_is_enforced_before_upgrade() {
    let port = socket_server();
    let r = request(port, "GET", "/ws", &[], "");
    assert_eq!(status(&r), 426, "{}", r);
    let low = r.to_lowercase();
    assert!(low.contains("upgrade: websocket"), "{}", r);
    assert!(r.contains("upgrade required"), "{}", r);

    // Sin token: 401 ANTES del upgrade (tungstenite lo reporta como error HTTP).
    match tungstenite::connect(format!("ws://127.0.0.1:{}/private", port)) {
        Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status().as_u16(), 401),
        Ok(_) => panic!("el handshake sin auth debía fallar"),
        Err(e) => panic!("error inesperado: {}", e),
    }
    // Con token: el binding `request.user` está disponible dentro del socket.
    use tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://127.0.0.1:{}/private", port).into_client_request().unwrap();
    req.headers_mut().insert("Authorization", "Bearer secreto".parse().unwrap());
    let (mut ws, _) = tungstenite::connect(req).expect("handshake con auth");
    match ws.read().unwrap() {
        Message::Text(t) => assert_eq!(t.as_str(), "hello agente"),
        other => panic!("{:?}", other),
    }
}

#[test]
fn socket_handler_error_closes_with_1011_and_reason() {
    let port = socket_server();
    let (mut ws, _) = tungstenite::connect(format!("ws://127.0.0.1:{}/boom", port)).unwrap();
    ws.send(Message::text("go")).unwrap();
    let t0 = Instant::now();
    loop {
        assert!(t0.elapsed() < Duration::from_secs(10));
        match ws.read() {
            Ok(Message::Close(Some(frame))) => {
                assert_eq!(u16::from(frame.code), 1011, "close code: {:?}", frame);
                assert!(frame.reason.contains("exploded"), "motivo: {}", frame.reason);
                break;
            }
            Ok(Message::Close(None)) => panic!("close sin código: se esperaba 1011 + motivo"),
            Ok(_) => continue,
            Err(e) => panic!("esperaba un Close 1011, got error {}", e),
        }
    }
}

#[test]
fn socket_route_timeout_closes_with_1001_going_away_and_reason() {
    // `timeout 1` en una ruta socket: el server cancela el handler (que estaba en un
    // ws_recv de 30 s) y despide al cliente con 1001 + motivo — ni mudo ni 1011.
    let port = socket_server();
    let (mut ws, _) = tungstenite::connect(format!("ws://127.0.0.1:{}/hang", port)).unwrap();
    let t0 = Instant::now();
    loop {
        assert!(t0.elapsed() < Duration::from_secs(10), "el timeout de 1 s no cerró el socket");
        match ws.read() {
            Ok(Message::Close(Some(frame))) => {
                assert_eq!(u16::from(frame.code), 1001, "close code: {:?}", frame);
                assert!(frame.reason.contains("timed out"), "motivo: {}", frame.reason);
                assert!(t0.elapsed() < Duration::from_secs(5), "cerró a los {:?}, no al vencer el timeout", t0.elapsed());
                break;
            }
            Ok(Message::Close(None)) => panic!("close sin código: se esperaba 1001 + motivo"),
            Ok(_) => continue,
            Err(e) => panic!("esperaba un Close 1001, got error {}", e),
        }
    }
}

#[test]
fn socket_forwards_child_process_output_via_select() {
    let prog = format!(
        r#"require serve({{p}})
require time
{req}

serve on {{p}}
    route "GET /run"
        socket
            let child be {spawn}
            while true
                let ev be select({{"sock": socket, "child": child}}, 10)
                when ev == nothing
                    ws_send(socket, "timeout")
                    stop
                when ev["name"] == "sock"
                    stop
                when ev["type"] == "exit"
                    ws_send(socket, "exit:" + text(ev["data"]["exit_code"]))
                    stop
                ws_send(socket, ev["type"] + ":" + ev["data"])
"#,
        req = shell_require(),
        spawn = shell_spawn("echo one; echo two; exit 4", "echo one& echo two& exit /b 4"),
    );
    let port = start(prog);
    let (mut ws, _) = tungstenite::connect(format!("ws://127.0.0.1:{}/run", port)).unwrap();
    let mut lines = Vec::new();
    let t0 = Instant::now();
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let s = t.as_str().trim_end().to_string();
                let done = s.starts_with("exit:");
                lines.push(s);
                if done {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => panic!("{} (líneas: {:?})", e, lines),
        }
        assert!(t0.elapsed() < Duration::from_secs(15), "{:?}", lines);
    }
    assert_eq!(lines, vec!["stdout:one", "stdout:two", "exit:4"], "{:?}", lines);
}

#[test]
fn socket_client_vanishing_without_close_handshake_is_a_close_event() {
    let port = start(
        r#"require serve({p})
require time

serve on {p}
    route "GET /vanish"
        socket
            let ev be ws_recv(socket, 10)
            state_set("vanish", ev["type"] + ":" + text(ev["data"]))

    route "GET /check"
        give {"vanish": state_get("vanish")}
"#
        .to_string(),
    );
    {
        let (ws, _) = tungstenite::connect(format!("ws://127.0.0.1:{}/vanish", port)).unwrap();
        // Dropear el socket SIN handshake de cierre (tab matada, red caída).
        drop(ws);
    }
    let mut seen = String::new();
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(100));
        seen = request(port, "GET", "/check", &[], "");
        if seen.contains("close:") {
            break;
        }
    }
    assert!(seen.contains("close:connection reset"), "el handler debe ver un close con motivo, got: {}", seen);
}

// =========================================================
// SSE + bus + keepalive
// =========================================================

#[test]
fn sse_stream_is_fed_by_the_bus_from_another_route_and_heartbeats_when_idle() {
    std::env::set_var("SYNSEMA_SSE_KEEPALIVE", "1");
    let port = start(
        r#"require serve({p})
require time

serve on {p}
    route "GET /events"
        stream
            let sub be bus_subscribe("ui.*")
            let got be 0
            while got < 2
                let ev be bus_recv(sub, 10)
                when ev == nothing
                    stop
                send ev["data"] as "ui"
                set got to got + 1

    route "POST /pub"
        let n be bus_publish("ui.click", request.json)
        give {"delivered": n}
"#
        .to_string(),
    );
    // Abrir el stream primero (suscribe), luego publicar desde otra ruta.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    // Esperar el head + el primer heartbeat (idle ≥ 1 s sin frames).
    let mut buf = Vec::new();
    let t0 = Instant::now();
    loop {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).unwrap_or(0);
        buf.extend_from_slice(&chunk[..n]);
        let s = String::from_utf8_lossy(&buf);
        if s.contains(": keepalive") {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(8), "sin heartbeat: {}", s);
        if n == 0 {
            thread::sleep(Duration::from_millis(50));
        }
    }
    let head = String::from_utf8_lossy(&buf).to_lowercase();
    assert!(head.contains("text/event-stream"), "{}", head);

    let r1 = request(port, "POST", "/pub", &[], r#"{"x": 1}"#);
    assert!(r1.contains("\"delivered\":1") || r1.contains("\"delivered\": 1"), "{}", r1);
    let _ = request(port, "POST", "/pub", &[], r#"{"x": 2}"#);
    let t1 = Instant::now();
    loop {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).unwrap_or(0);
        buf.extend_from_slice(&chunk[..n]);
        let s = String::from_utf8_lossy(&buf);
        if s.matches("event: ui\n").count() >= 2 {
            assert!(s.contains("\"x\":1") || s.contains("\"x\": 1"), "{}", s);
            assert!(s.contains("\"x\":2") || s.contains("\"x\": 2"), "{}", s);
            break;
        }
        assert!(t1.elapsed() < Duration::from_secs(10), "eventos del bus no llegaron: {}", s);
        if n == 0 {
            thread::sleep(Duration::from_millis(50));
        }
    }
}

// =========================================================
// timeout + cancelación
// =========================================================

#[test]
fn route_timeout_answers_504_and_actually_cancels_the_handler() {
    let port = start(
        r#"require serve({p})
require time

serve on {p}
    timeout 1

    route "GET /slow"
        state_set("started", true)
        while true
            sleep(0.05)
        state_set("finished", true)
        give {"never": true}

    route "GET /unlimited"
        timeout none
        sleep(1.6)
        give {"slept": true}

    route "GET /check"
        give {"started": state_get("started"), "finished": state_get("finished")}
"#
        .to_string(),
    );
    let t0 = Instant::now();
    let r = request(port, "GET", "/slow", &[], "");
    assert_eq!(status(&r), 504, "{}", r);
    assert!(r.contains("exceeded 1s"), "{}", r);
    assert!(t0.elapsed() < Duration::from_secs(4), "el 504 llegó al vencer, no después: {:?}", t0.elapsed());
    // El handler fue cancelado: `finished` jamás se setea (el `while true` murió).
    thread::sleep(Duration::from_millis(700));
    let c = request(port, "GET", "/check", &[], "");
    assert!(c.contains("\"started\":true") || c.contains("\"started\": true"), "{}", c);
    assert!(c.contains("\"finished\":null") || c.contains("\"finished\": null"), "cancelado de verdad: {}", c);
    // `timeout none` por ruta anula el default del serve.
    let u = request(port, "GET", "/unlimited", &[], "");
    assert_eq!(status(&u), 200, "{}", u);
}

// =========================================================
// agents() / agent_stop
// =========================================================

#[test]
fn agents_lists_live_agents_and_agent_stop_cancels_them() {
    let src = r#"agent Looper
    while true
        wait_for "job" timeout 0.2

spawn Looper
sleep(0.3)
let before be agents()
print(length(before))
print(before[0]["name"])
print(before[0]["state"])
print(agent_stop(before[0]["id"], "test"))
sleep(0.6)
print(agents()[0]["state"])
print(agent_stop("no-such-agent"))
"#;
    // `run_program` = el camino de `synsema run` (swarm real: hilos por agente).
    let r = run_program(src, "<agents>");
    assert!(r.success, "{:?}", r.errors);
    assert!(r.output.len() >= 6, "salida: {:?}", r.output);
    assert_eq!(r.output[0], "1", "{:?}", r.output);
    assert_eq!(r.output[1], "Looper", "{:?}", r.output);
    assert!(r.output[2] == "working" || r.output[2] == "waiting", "{:?}", r.output);
    assert_eq!(r.output[3], "true");
    assert_eq!(r.output[4], "stopped", "{:?}", r.output);
    assert_eq!(r.output[5], "false");
}

// =========================================================
// parseo fail-loud
// =========================================================

#[test]
fn a_handlers_bus_subscriptions_do_not_outlive_its_request() {
    // Los workers de serve reusan su intérprete: sin reset del hub, cada request que
    // suscribe y termina dejaría una cola viva en el bus para siempre (fuga de memoria y,
    // con el tiempo, "too many live subscriptions"). El siguiente request debe ver 0.
    let prog = concat!(
        "require serve({p})\n",
        "serve on {p}\n",
        "    route \"GET /sub\"\n",
        "        let sub be bus_subscribe(\"leak.*\")\n",
        "        give {\"handle\": sub}\n",
        "    route \"GET /topics\"\n",
        "        give {\"topics\": bus_topics()}\n",
    )
    .to_string();
    let port = start(prog);
    for _ in 0..6 {
        let r = request(port, "GET", "/sub", &[], "");
        assert_eq!(status(&r), 200, "{}", r);
    }
    let r = request(port, "GET", "/topics", &[], "");
    assert_eq!(status(&r), 200, "{}", r);
    let body = r.split("\r\n\r\n").nth(1).unwrap_or("");
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("\"topics\":[]"), "las suscripciones de requests terminados se retiraron: {}", body);
}

#[test]
fn timeout_clause_outside_a_route_is_a_loud_error() {
    // Escribir `timeout 30` donde no es cláusula (top-level, task, dentro de un `when`)
    // no se ignora en silencio.
    let r = run_source("timeout 30\nprint(1)\n", "<timeout-misplaced>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("'timeout' is a clause")), "{:?}", r.errors);
}

fn parse_err(src: &str) -> String {
    match synsema_core::parser::parse_source(src, "<parse>") {
        Ok(_) => panic!("debía fallar el parseo:\n{}", src),
        Err(e) => e.to_string(),
    }
}

#[test]
fn socket_and_timeout_parse_errors_are_loud() {
    let e = parse_err("require serve(1)\nserve on 1\n    route \"POST /ws\"\n        socket\n            give 1\n");
    assert!(e.contains("GET"), "{}", e);
    let e = parse_err("require serve(1)\nserve on 1\n    route \"GET /ws\"\n        stream\n            send 1\n        socket\n            give 1\n");
    assert!(e.contains("mixes"), "{}", e);
    let e = parse_err("require serve(1)\nserve on 1\n    timeout 5\n    timeout 6\n    route \"GET /\"\n        give 1\n");
    assert!(e.contains("at most once"), "{}", e);
    let e = parse_err("require serve(1)\nserve on 1\n    route \"GET /\"\n        timeout 5\n        timeout none\n        give 1\n");
    assert!(e.contains("at most once"), "{}", e);
    // `socket` fuera de una ruta: el nombre sigue siendo una variable común.
    let r = run_source("let socket be 3\nprint(socket + 1)\n", "<var>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "4");
}



// =========================================================
// `synsema test` cablea el swarm (v0.6.10+)
// =========================================================

/// Bajo `synsema test` los agentes corren de verdad (hilo propio, `agents()` existe,
/// blackboard/señales funcionan) y un agente que termina en ERROR hace fallar el test
/// que lo spawneó — y sólo ese.
#[test]
fn synsema_test_runs_agents_for_real_and_agent_errors_fail_that_test() {
    let src = r#"agent Worker
    share n * 2 as "doubled"
    signal "done"

agent Broken
    raise "agent exploded on purpose"

test "spawn corre en su hilo y el blackboard llega"
    spawn Worker with n = 21
    wait_for "done" timeout 5
    observe "doubled" as d
    assert_eq(d, 42)
    assert(length(agents()) >= 1)

test "un agente roto hace fallar SU test"
    spawn Broken
    sleep(0.2)

test "el test siguiente arranca limpio"
    assert_eq(1 + 1, 2)
"#;
    let r = synsema_runtime::engine::run_tests(src, "<swarm-test>.syn");
    let names: Vec<(String, bool, Option<String>)> =
        r.outcomes.iter().map(|o| (o.name.clone(), o.passed, o.message.clone())).collect();
    assert_eq!(r.outcomes.len(), 3, "{:?}", names);
    assert!(r.outcomes[0].passed, "{:?}", names);
    assert!(!r.outcomes[1].passed, "{:?}", names);
    let msg = r.outcomes[1].message.clone().unwrap_or_default();
    assert!(msg.contains("Agent error") && msg.contains("exploded on purpose"), "{}", msg);
    assert!(r.outcomes[2].passed, "el error del agente no contamina el test siguiente: {:?}", names);
    assert_eq!((r.passed, r.failed), (2, 1));
}
