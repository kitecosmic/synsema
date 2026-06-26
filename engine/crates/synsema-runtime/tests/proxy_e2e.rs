//! Lote 2 — Gate end-to-end del reverse proxy: parsea y ejecuta un programa REAL
//! con `proxy to "http://..."` (vía run_serve_program, NO construyendo RouteSpec a
//! mano) y verifica el forward al upstream. Cubre el parser + el runtime juntos.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Upstream de prueba: responde con el request-line que vio (prueba el forward).
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
            }
            let body = format!("upstream saw: {}", line.trim());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

#[test]
fn proxy_to_parses_and_forwards() {
    let up = spawn_upstream();
    let port = free_port();
    // Programa REAL: el parser debe aceptar `proxy to "..."`.
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"GET /up/*path\"\n        proxy to \"http://127.0.0.1:{up}\"\n",
        p = port,
        up = up
    );
    // run_serve_program parsea + bindea + spawnea el accept loop (queda en background);
    // lo corremos detached (muere al salir el proceso de test).
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "proxy_e2e.syn", false);
    });

    // Esperar a que el server bindee.
    let mut ready = false;
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server proxy no quedó listo en :{}", port);
    thread::sleep(Duration::from_millis(150));

    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.write_all(b"GET /up/hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);

    assert!(resp.starts_with("HTTP/1.1 200"), "status: {}", resp);
    // El body viene del upstream y refleja el path forwardeado.
    assert!(resp.contains("upstream saw: GET /up/hello"), "forward body: {}", resp);
}
