//! E2E del Batch 7: el `timeout` configurable de `wait_for` se RESPETA (medido por reloj):
//! sin emisor devuelve a ~timeout (no 30 s), con emisor despierta enseguida, y un route con
//! `wait_for ... timeout 1` responde en ~1 s (el caso que motivó el fix).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use synsema_core::types::SendValue;
use synsema_runtime::engine::Engine;
use synsema_runtime::serve::run_serve_program;

fn text(s: &str) -> SendValue {
    SendValue::Text(s.to_string())
}

// =========================================================
// El timeout se respeta (medido), no el default de 30 s
// =========================================================

#[test]
fn timeout_respected_when_no_emitter() {
    // Un agente espera un canal que NADIE emite, con timeout 1 s → debe volver a ~1 s
    // (NO a los 30 s del default). Medimos el reloj alrededor del join del agente.
    let engine = Engine::new();
    let src = "agent Waiter\n    wait_for \"never\" timeout 1 as r\n    share \"woke\" as \"result\"\n\nspawn Waiter";
    let start = Instant::now();
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let elapsed = start.elapsed();
    // El agente corrió (volvió del wait_for con nothing y compartió).
    assert_eq!(engine.swarm.blackboard.read("result", ""), Some(text("woke")));
    // Respetó ~1 s: claramente menos que el default de 30 s.
    assert!(
        elapsed >= Duration::from_millis(700) && elapsed < Duration::from_secs(8),
        "el timeout de 1 s no se respetó (elapsed = {:?}; debería ser ~1 s, no 30 s)",
        elapsed
    );
}

#[test]
fn fast_wake_when_signal_arrives_before_timeout() {
    // Waiter con timeout 30, pero el Sender emite enseguida → despierta YA (no espera 30 s).
    let engine = Engine::new();
    let src = "agent Waiter\n    wait_for \"go\" timeout 30 as r\n    share r as \"result\"\n\
               agent Sender\n    signal \"go\" with \"hello\"\n\
               spawn Waiter\nspawn Sender";
    let start = Instant::now();
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let elapsed = start.elapsed();
    assert_eq!(engine.swarm.blackboard.read("result", ""), Some(text("hello")));
    assert!(
        elapsed < Duration::from_secs(8),
        "despertó tarde (elapsed = {:?}); con la señal debería ser inmediato, no esperar el timeout",
        elapsed
    );
}

#[test]
fn timeout_zero_returns_immediately() {
    // timeout 0 = chequeo inmediato: sin señal vuelve enseguida con nothing.
    let engine = Engine::new();
    let src = "agent Waiter\n    wait_for \"never\" timeout 0 as r\n    share \"checked\" as \"result\"\n\nspawn Waiter";
    let start = Instant::now();
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let elapsed = start.elapsed();
    assert_eq!(engine.swarm.blackboard.read("result", ""), Some(text("checked")));
    assert!(elapsed < Duration::from_secs(3), "timeout 0 no fue inmediato (elapsed = {:?})", elapsed);
}

#[test]
fn dynamic_channel_with_timeout() {
    // Canal dinámico (Batch 6) + timeout (Batch 7): sin emisor en `done:1` → ~1 s, nothing.
    let engine = Engine::new();
    let src = "agent Waiter\n    let id be 1\n    wait_for \"done:\" + text(id) timeout 1 as r\n    share \"timed-out\" as \"result\"\n\nspawn Waiter";
    let start = Instant::now();
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let elapsed = start.elapsed();
    assert_eq!(engine.swarm.blackboard.read("result", ""), Some(text("timed-out")));
    assert!(elapsed >= Duration::from_millis(700) && elapsed < Duration::from_secs(8), "elapsed = {:?}", elapsed);
}

// =========================================================
// E2E serve — el caso que motivó el fix (route que no cuelga 30 s)
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_server(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "batch7_e2e.syn", false);
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

#[test]
fn route_with_timeout_responds_fast_when_no_signal() {
    // Un route hace `wait_for "done" timeout 1` y NADIE emite. Antes (30 s hardcodeados) el
    // request colgaba 30 s; ahora responde en ~1 s.
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "POST /wait"
        wait_for "done" timeout 1 as r
        give ok("returned")
"#,
        p = port
    );
    start_server(prog, port);
    let start = Instant::now();
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = "POST /wait HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    let elapsed = start.elapsed();
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {}", resp.lines().next().unwrap_or(""));
    assert!(
        elapsed < Duration::from_secs(8),
        "el request colgó (elapsed = {:?}); con timeout 1 debería responder en ~1 s, no 30 s",
        elapsed
    );
}
