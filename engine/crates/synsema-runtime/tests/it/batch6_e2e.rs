//! E2E del Batch 6 que requieren el host: serve real y estado ERROR del swarm.
//! Los canales dinámicos se prueban en `tests/batch6_e2e.test.syn`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_agents::swarm::AgentState;
use synsema_core::types::SendValue;
use synsema_runtime::engine::Engine;
use synsema_runtime::serve::run_serve_program;

fn text(s: &str) -> SendValue {
    SendValue::Text(s.to_string())
}

// =========================================================
// Fix 1 — spawn desde una route (el bug: "No agent defined")
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_server(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "batch6_e2e.syn", false);
    });
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn post(port: u16, path: &str, body: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn spawn_from_route_returns_200() {
    let port = free_port();
    // El agente se define al top-level (ANTES de serve); una route lo spawnea.
    let prog = format!(
        r#"require serve({p})
agent Worker
    share "worked" as "result"
serve on {p}
    route "POST /run"
        spawn Worker
        give ok("spawned")
"#,
        p = port
    );
    start_server(prog, port);
    // Antes del fix: 500 "No agent defined". Con el fix: 200.
    let r = post(port, "/run", "{}");
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "esperaba 200 (spawn desde route), got: {}",
        r.lines().next().unwrap_or("")
    );
    assert!(!r.to_lowercase().contains("no agent defined"), "el agente no se encontró: {}", r);
}

#[test]
fn spawn_from_route_multiple_agents() {
    // Varios agentes definidos al top-level; distintas routes los spawnean. Confirma que
    // TODAS las defs viajan en el snapshot por request (no sólo la primera).
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
agent Alpha
    share "a" as "alpha"
agent Beta
    share "b" as "beta"
serve on {p}
    route "POST /alpha"
        spawn Alpha
        give ok("a")
    route "POST /beta"
        spawn Beta
        give ok("b")
"#,
        p = port
    );
    start_server(prog, port);
    assert!(post(port, "/alpha", "{}").starts_with("HTTP/1.1 200"), "alpha falló");
    assert!(post(port, "/beta", "{}").starts_with("HTTP/1.1 200"), "beta falló");
}

// =========================================================
// Fix 3 — un agente con try/recover + raise termina en ERROR (no DONE)
// =========================================================

#[test]
fn agent_with_raise_ends_in_error() {
    let engine = Engine::new();
    let src = "agent Risky\n    try\n        let x be (1 / 0)\n    recover err\n        raise(err)\n\nspawn Risky";
    let r = engine.run(src, "<t>");
    assert!(r.success, "el programa principal no falla; el agente sí: {:?}", r.errors);
    engine.swarm.wait_all();
    let states = engine.swarm.agent_states();
    assert!(
        states.iter().any(|(_, st)| matches!(st, AgentState::Error)),
        "el agente con raise(err) debería terminar en ERROR, estados: {:?}",
        states.iter().map(|(id, st)| (id.clone(), st.name())).collect::<Vec<_>>()
    );
}
