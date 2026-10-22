//! E2E del tipo `bytes` (Batch 1) — partes que dependen del motor: hashing SHA,
//! invariante de `secret` (G6), I/O de archivos binario y serve binario byte-exacto.
//!
//! Corre programas .syn REALES por el motor. La parte pura (construcción/decode/ops)
//! vive en `synsema-core/tests/bytes_conformance.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

// =========================================================
// Hashing SHA (vectores publicados) — sha256/sha512 → bytes
// =========================================================

#[test]
fn sha256_known_vector() {
    // decode(sha256(bytes("abc")), "hex") == vector NIST.
    let r = run_source(
        "print(decode(sha256(bytes(\"abc\")), \"hex\"))\n\
         print(decode(sha256(\"abc\"), \"hex\"))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    // bytes("abc") y "abc" deben hashear igual (UTF-8 de "abc").
    assert_eq!(r.output, vec![expected.to_string(), expected.to_string()]);
}

#[test]
fn sha512_known_vector_and_lengths() {
    let r = run_source(
        "print(decode(sha512(\"abc\"), \"hex\"))\n\
         print(text(length(sha256(\"x\"))))\n\
         print(text(length(sha512(\"x\"))))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    let sha512_abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                      2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(r.output, vec![sha512_abc.to_string(), "32".to_string(), "64".to_string()]);
}

#[test]
fn sha256_to_base64() {
    // decode(sha256(x), "base64") debe componer sin pre-hornear representaciones.
    let r = run_source("print(decode(sha256(bytes(\"abc\")), \"base64\"))", "t.syn");
    assert!(r.success, "errs: {:?}", r.errors);
    assert_eq!(r.output, vec!["ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=".to_string()]);
}

// =========================================================
// Invariante de secret (G6): no hay camino secret → bytes/hash
// =========================================================

#[test]
fn bytes_of_secret_errors() {
    let r = run_source(
        "require secret(\"API\")\nlet s be secret(\"API\", \"plaintext_value\")\nprint(bytes(s))",
        "t.syn",
    );
    assert!(!r.success, "bytes(secret) debería errorar");
    let errs = r.errors.join("\n");
    assert!(errs.contains("Cannot convert secret to bytes"), "errs: {:?}", r.errors);
    // El plaintext NUNCA aparece en el error.
    assert!(!errs.contains("plaintext_value"), "fuga de plaintext: {:?}", r.errors);
}

#[test]
fn sha256_of_secret_errors() {
    let r = run_source(
        "require secret(\"API\")\nlet s be secret(\"API\", \"plaintext_value\")\nprint(sha256(s))",
        "t.syn",
    );
    assert!(!r.success, "sha256(secret) debería errorar");
    let errs = r.errors.join("\n");
    assert!(errs.to_lowercase().contains("secret"), "errs: {:?}", r.errors);
    assert!(!errs.contains("plaintext_value"), "fuga de plaintext: {:?}", r.errors);
}

#[test]
fn decode_of_secret_errors() {
    let r = run_source(
        "require secret(\"API\")\nlet s be secret(\"API\", \"plaintext_value\")\nprint(decode(s))",
        "t.syn",
    );
    assert!(!r.success, "decode(secret) debería errorar");
    let errs = r.errors.join("\n");
    assert!(errs.contains("decode expects bytes"), "errs: {:?}", r.errors);
    assert!(!errs.contains("plaintext_value"), "fuga de plaintext: {:?}", r.errors);
}

// =========================================================
// I/O de archivos binario (gateado) — round-trip byte-idéntico
// =========================================================

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("syn_bytes_{}_{}", std::process::id(), name));
    // Forward slashes: std::fs los acepta en Windows y evita escapes en el .syn.
    p.to_string_lossy().replace('\\', "/")
}

#[test]
fn file_roundtrip_all_256_values() {
    let path = temp_path("roundtrip.bin");
    let src = format!(
        "require file(\"{p}\")\n\
         let data be bytes(range(256))\n\
         write_file(\"{p}\", data)\n\
         let back be read_file_bytes(\"{p}\")\n\
         print(text(data == back))\n\
         print(text(length(back)))\n",
        p = path
    );
    let r = run_source(&src, "t.syn");
    let _ = std::fs::remove_file(&path);
    assert!(r.success, "errs: {:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string(), "256".to_string()]);
}

#[test]
fn write_file_bytes_requires_capability() {
    let path = temp_path("nogrant.bin");
    let src = format!("write_file(\"{p}\", bytes([1, 2, 3]))", p = path);
    let r = run_source(&src, "t.syn");
    let _ = std::fs::remove_file(&path);
    assert!(!r.success, "write_file(bytes) sin grant debería errorar");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted") && e.contains("file_write")),
        "errs: {:?}",
        r.errors
    );
}

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
