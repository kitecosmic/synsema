//! Serve binario byte-exacto: respuesta y eco de body por sockets reales.
//! Los casos de hashing, secret e I/O de archivos viven en `tests/bytes_e2e.test.syn`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

// =========================================================
// Serve binario byte-exacto (A1 respuesta, A4 eco de body)
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_server(port: u16) {
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /payload"
        give binary(bytes(range(256)), "application/octet-stream")
    route "GET /direct"
        give bytes(range(256))
    route "GET /png"
        give binary(bytes([137, 80, 78, 71]), "image/png")
    route "POST /echo"
        give binary(read_body_bytes())
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "bytes_e2e.syn", false);
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

/// Manda una request cruda (bytes) y devuelve la respuesta completa (bytes), leyendo
/// hasta EOF (Connection: close).
fn raw_request(port: u16, req: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.write_all(req).unwrap();
    sock.flush().unwrap();
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp).unwrap();
    resp
}

/// Separa la respuesta en (headers en minúsculas, body bytes crudos).
fn split_response(resp: &[u8]) -> (String, Vec<u8>) {
    let pos = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("respuesta sin separador headers/body");
    let head = String::from_utf8_lossy(&resp[..pos]).to_ascii_lowercase();
    (head, resp[pos + 4..].to_vec())
}

fn http_get(port: u16, path: &str) -> (String, Vec<u8>) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    split_response(&raw_request(port, req.as_bytes()))
}

#[test]
fn serve_binary_response_byte_identical() {
    let port = free_port();
    start_server(port);
    let expected: Vec<u8> = (0u8..=255).collect();

    // A1: binary() con los 256 valores → body byte-idéntico, octet-stream, sin gzip.
    let (head, body) = http_get(port, "/payload");
    assert!(head.starts_with("http/1.1 200"), "payload status: {}", head);
    assert!(head.contains("content-type: application/octet-stream"), "ct: {}", head);
    assert!(!head.contains("content-encoding"), "no debe comprimirse binario: {}", head);
    assert_eq!(body, expected, "payload no es byte-idéntico");

    // give bytes(...) directo → octet-stream 200.
    let (head, body) = http_get(port, "/direct");
    assert!(head.starts_with("http/1.1 200"), "direct status: {}", head);
    assert!(head.contains("content-type: application/octet-stream"), "direct ct: {}", head);
    assert_eq!(body, expected, "direct no es byte-idéntico");

    // binary() con content-type explícito.
    let (head, body) = http_get(port, "/png");
    assert!(head.contains("content-type: image/png"), "png ct: {}", head);
    assert_eq!(body, vec![137u8, 80, 78, 71], "png magic no es byte-idéntico");
}

#[test]
fn serve_read_body_bytes_echo_byte_identical() {
    let port = free_port();
    start_server(port);

    // A4: POST con los 256 valores (incl. 0x00 y 0xFF) → el eco debe ser byte-idéntico.
    // Body pequeño (256 bytes < MEM_SPILL) → prueba el camino en-memoria (body_raw),
    // que antes pasaba por from_utf8_lossy y corrompía los no-UTF-8.
    let payload: Vec<u8> = (0u8..=255).collect();
    let mut req = format!(
        "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    req.extend_from_slice(&payload);

    let (head, body) = split_response(&raw_request(port, &req));
    assert!(head.starts_with("http/1.1 200"), "echo status: {}", head);
    assert_eq!(body, payload, "el eco del body NO es byte-idéntico (punto lossy abierto)");
}
