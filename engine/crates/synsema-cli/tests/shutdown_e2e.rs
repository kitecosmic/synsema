//! Shutdown ordenado de `synsema serve` (SIGINT/SIGTERM) contra el BINARIO real, como
//! proceso hijo — la única forma de probarlo: el drain termina en `process::exit`.
//! Sólo Unix (en Windows no hay forma portable de mandar Ctrl-C a un hijo desde un
//! test; la ruta de código es la misma: `tokio::signal::ctrl_c`).
//!
//! Lo que se afirma: (1) el server loguea el drain; (2) un stream SSE vivo recibe la
//! cancelación (`event: error` + cierre) en vez de quedar colgado; (3) el proceso sale
//! con código 0 dentro de la gracia; (4) tras el SIGINT ya no se aceptan conexiones.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(30) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if buf.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("el server no levantó en 30 s");
}

#[test]
fn sigint_drains_streams_and_exits_zero() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("synsema-shutdown-e2e-{}", port));
    std::fs::create_dir_all(&dir).unwrap();
    let prog = dir.join("app.syn");
    std::fs::write(
        &prog,
        format!(
            "require serve({p})\nrequire time\n\nserve on {p}\n    route \"GET /events\"\n        stream\n            let sub be bus_subscribe(\"x\")\n            while true\n                let ev be bus_recv(sub, 30)\n                when ev != nothing\n                    send ev[\"data\"] as \"x\"\n    route \"GET /ping\"\n        give {{\"pong\": true}}\n",
            p = port
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", prog.to_str().unwrap()])
        .env("SYNSEMA_SHUTDOWN_GRACE", "5")
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synsema serve");
    wait_ready(port);

    // Un stream SSE vivo (bloqueado en bus_recv) durante el shutdown.
    let mut sse = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sse.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    sse.write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(500));

    let status = Command::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    assert!(status.success(), "kill -INT");

    let t0 = Instant::now();
    let mut sse_out = String::new();
    let _ = sse.read_to_string(&mut sse_out);
    assert!(sse_out.starts_with("HTTP/1.1 200"), "{}", sse_out);
    assert!(sse_out.contains("event: error"), "el stream vivo recibió la cancelación como evento error: {}", sse_out);
    assert!(sse_out.contains("shutting down"), "el motivo nombra el shutdown: {}", sse_out);

    let out = child.wait_with_output().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(12), "salió en {:?} (gracia 5 s)", t0.elapsed());
    assert_eq!(out.status.code(), Some(0), "un shutdown pedido sale con 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shutting down: draining"), "log del drain: {}", stderr);
    assert!(stderr.contains("[serve] stopped"), "log final: {}", stderr);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "el listener se cerró");
    let _ = std::fs::remove_dir_all(&dir);
}
