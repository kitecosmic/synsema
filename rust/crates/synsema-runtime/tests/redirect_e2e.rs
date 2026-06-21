//! E2E del builtin `redirect()` y de la selección de vhost por header `Host` (HTTP/1.1).
//! Corre programas .syn REALES (parser + runtime + builtin) y verifica los bytes en el
//! socket. El caso HTTP/2 (vhost por `:authority`) vive en synsema-stdlib/http2_proxy.rs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Levanta un server con las rutas de prueba y espera a que bindee.
fn start(port: u16) {
    // Raw string: preserva la indentación (Synsema es sensible a ella) y deja `\r\n`
    // como literal de DOS chars para que el lexer .syn lo interprete como CR/LF.
    let prog = format!(
        r#"require serve({p})
serve on {p}
    host "www.example.com"
        route "GET /*path"
            give redirect("https://example.com/" + params.path)
    route "GET /perm"
        give redirect("https://example.com/new")
    route "GET /temp"
        give redirect("/elsewhere", 302)
    route "GET /empty"
        give redirect("")
    route "GET /badstatus"
        give redirect("/x", 200)
    route "GET /crlf"
        give redirect("https://x/\r\nSet-Cookie: evil")
    route "GET /"
        give "apex"
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "redirect_e2e.syn", false);
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

/// Envía una request cruda (método/target/Host) y devuelve la respuesta completa (lower-case).
fn request(port: u16, method: &str, target: &str, host: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp.to_ascii_lowercase()
}

#[test]
fn redirect_builtin_and_vhost_e2e() {
    let port = free_port();
    start(port);

    // 301 permanente + Location.
    let r = request(port, "GET", "/perm", "127.0.0.1");
    assert!(r.starts_with("http/1.1 301"), "perm status: {}", r);
    assert!(r.contains("location: https://example.com/new"), "perm location: {}", r);

    // 302 temporal con status explícito.
    let r = request(port, "GET", "/temp", "127.0.0.1");
    assert!(r.starts_with("http/1.1 302"), "temp status: {}", r);
    assert!(r.contains("location: /elsewhere"), "temp location: {}", r);

    // URL vacía → 500 (rechazada por el builtin).
    let r = request(port, "GET", "/empty", "127.0.0.1");
    assert!(r.starts_with("http/1.1 500"), "empty status: {}", r);

    // status fuera de 3xx → 500 (no se clampea en silencio).
    let r = request(port, "GET", "/badstatus", "127.0.0.1");
    assert!(r.starts_with("http/1.1 500"), "badstatus status: {}", r);

    // CR/LF en la URL → 500 y NUNCA se inyecta el Set-Cookie (anti header-injection).
    let r = request(port, "GET", "/crlf", "127.0.0.1");
    assert!(r.starts_with("http/1.1 500"), "crlf status: {}", r);
    assert!(!r.contains("set-cookie"), "CRLF se inyectó: {}", r);

    // HEAD lleva el Location igual que GET (sin body).
    let r = request(port, "HEAD", "/perm", "127.0.0.1");
    assert!(r.starts_with("http/1.1 301"), "head status: {}", r);
    assert!(r.contains("location: https://example.com/new"), "head location: {}", r);

    // Selección de vhost por header Host (HTTP/1.1): www.example.com → catch-all que redirige.
    let r = request(port, "GET", "/docs", "www.example.com");
    assert!(r.starts_with("http/1.1 301"), "vhost status: {}", r);
    assert!(r.contains("location: https://example.com/docs"), "vhost location: {}", r);

    // El mismo path en el host por defecto (apex) NO matchea el catch-all del vhost → 404.
    let r = request(port, "GET", "/docs", "127.0.0.1");
    assert!(r.starts_with("http/1.1 404"), "apex /docs debería ser 404: {}", r);
}
