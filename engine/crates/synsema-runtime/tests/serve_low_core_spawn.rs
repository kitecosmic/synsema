//! Regresión pocos-cores: `spawn` desde una route con el pool del intérprete en 1 worker.
//!
//! El bug: el intérprete base se cachea por worker y `reset_for_request` borraba
//! `agent_definitions` sin restaurarlas → el SEGUNDO request del mismo worker daba
//! "No agent defined". Con muchos cores el pool es grande y los requests suelen caer
//! en workers vírgenes (intérprete fresco → funciona), por eso sólo se veía en VPS de
//! 1-2 cores. Acá forzamos `SYNSEMA_SERVE_WORKERS=1` — todos los requests reusan el
//! mismo worker — y el bug (si volviera) aparece determinísticamente en el request 2.
//!
//! Archivo propio (proceso propio): el pool es un `OnceLock` global del proceso y el
//! env var debe fijarse ANTES del primer serve, sin carreras con otros tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_server(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_low_core_spawn.syn", false);
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
fn spawn_from_route_survives_worker_reuse() {
    // ANTES de arrancar el serve: el pool se inicializa perezosamente al primer uso.
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "1");
    let port = free_port();
    // El agente queda vivo unos segundos (wait_for con timeout) — como el Courier real
    // colgado del LLM — mientras los requests siguientes llegan al MISMO worker.
    let prog = format!(
        r#"require serve({p})
agent Courier
    wait_for "never" timeout 3
    share "done" as "result"
serve on {p}
    route "POST /run"
        spawn Courier
        give ok("spawned")
"#,
        p = port
    );
    start_server(prog, port);
    // Requests 2+ reusan el intérprete cacheado del único worker. Antes del fix: el 1
    // daba 200 y el 2-4 daban 500 "No agent defined". Con el fix: todos 200.
    for i in 1..=4 {
        let r = post(port, "/run", "{}");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "request {} esperaba 200, got: {} — body: {}",
            i,
            r.lines().next().unwrap_or(""),
            r
        );
        assert!(!r.to_lowercase().contains("no agent defined"), "request {}: {}", i, r);
    }
}
