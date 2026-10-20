//! v0.6.45 (A5): un programa con `serve` puede terminar limpio ANTES de escuchar. Una app de
//! escritorio de una sola instancia (el patrón de `synsema init --desktop`) necesita "si ya estoy
//! corriendo, mostrá la ventana y salí"; `exit(0)` daba error y `shutdown()` también. Ya
//! escuchando, `exit` sigue siendo error (cortaría los requests en vuelo: para eso está `shutdown`).
//!
//! Una sola función a propósito: "ya escucha" es del proceso, así que los casos van en orden.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::last_run_exit_code;
use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn program(port: u16, preamble: &str) -> String {
    format!(
        r#"require serve({port})
print("antes")
{preamble}
serve on {port}
    route "GET /"
        give "sirviendo"
    route "GET /exit"
        exit(0)
        give "no llega"
"#
    )
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn exit_before_listening_ends_clean_and_after_listening_it_is_refused() {
    // 1) `exit(0)` en el preámbulo: termina sin error, con código 0, y el puerto nunca se abre.
    let p = free_port();
    let r = run_serve_program(&program(p, "exit(0)"), "a5.syn", false);
    assert!(r.success, "{:?}", r.errors);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.output, ["antes"]);
    assert_eq!(last_run_exit_code(), Some(0));
    assert!(TcpStream::connect(("127.0.0.1", p)).is_err(), "no debía escuchar");

    // 2) Con otro código: el fin pedido, sin "Runtime error", y el código llega.
    let r = run_serve_program(&program(free_port(), "exit(3)"), "a5.syn", false);
    assert!(!r.success);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(last_run_exit_code(), Some(3));

    // 3) Ya escuchando, `exit` desde una ruta es error (500) y el server sigue sirviendo.
    let p = free_port();
    let src = program(p, "");
    thread::spawn(move || {
        let _ = run_serve_program(&src, "a5.syn", false);
    });
    let mut ready = false;
    for _ in 0..150 {
        if TcpStream::connect(("127.0.0.1", p)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo");
    let resp = get(p, "/exit");
    assert!(resp.starts_with("HTTP/1.1 500"), "{}", resp.lines().next().unwrap_or(""));
    let resp = get(p, "/");
    assert!(resp.contains("sirviendo"), "el server debía seguir: {}", resp);
}
