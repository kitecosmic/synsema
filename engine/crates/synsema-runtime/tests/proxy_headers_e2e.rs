//! Gate end-to-end: el reverse proxy (`proxy to`) debe reenviar los headers
//! end-to-end de la respuesta del upstream al cliente (Location, Set-Cookie,
//! Cache-Control/ETag/Vary, headers custom), preservando status + content-type +
//! body byte-exacto, SIN reenviar los hop-by-hop (RFC 7230 §6.1) y dejando que
//! hyper recalcule Content-Length (incl. el caso chunked→dechunk).
//!
//! Corre un programa REAL con `proxy to "http://..."` contra un upstream de prueba
//! que emite cada caso. Cubre parser + runtime + stdlib juntos.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Upstream de prueba que responde según el path que ve, emitiendo cada caso de §4.
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
            // Drenar el resto de los headers de la request.
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
            }
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();

            let resp: Vec<u8> = if path.starts_with("/redirect") {
                // §4.1: 301 con Location (y Content-Length: 0).
                b"HTTP/1.1 301 Moved Permanently\r\n\
                  Location: /en/0.4.x/21-secrets\r\n\
                  Content-Type: text/html\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n"
                    .to_vec()
            } else if path.starts_with("/headers") {
                // §4.2/§4.3/§4.4 + §4.6: dos Set-Cookie, Cache-Control/ETag/Vary,
                // X-Foo custom, y un hop-by-hop (Keep-Alive) que NO debe reenviarse.
                let body = b"hello";
                let mut r = Vec::new();
                r.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
                r.extend_from_slice(b"Content-Type: text/plain\r\n");
                r.extend_from_slice(b"Set-Cookie: a=1\r\n");
                r.extend_from_slice(b"Set-Cookie: b=2\r\n");
                r.extend_from_slice(b"Cache-Control: max-age=60\r\n");
                r.extend_from_slice(b"ETag: \"abc123\"\r\n");
                r.extend_from_slice(b"Vary: Accept-Encoding\r\n");
                r.extend_from_slice(b"X-Foo: bar\r\n");
                r.extend_from_slice(b"Keep-Alive: timeout=5\r\n"); // hop-by-hop
                r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
                r.extend_from_slice(b"Connection: close\r\n\r\n");
                r.extend_from_slice(body);
                r
            } else if path.starts_with("/png") {
                // §4.5: body binario byte-exacto (magic PNG) + content-type.
                let body: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
                let mut r = Vec::new();
                r.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n");
                r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
                r.extend_from_slice(b"Connection: close\r\n\r\n");
                r.extend_from_slice(&body);
                r
            } else if path.starts_with("/chunked") {
                // §4.7: Transfer-Encoding: chunked → el proxy dechunkea; el cliente ve
                // Content-Length real y NINGÚN Transfer-Encoding. Body = "Hello, world!".
                let mut r = Vec::new();
                r.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/plain\r\n\
                      Transfer-Encoding: chunked\r\n\
                      Connection: close\r\n\r\n",
                );
                r.extend_from_slice(b"6\r\nHello,\r\n7\r\n world!\r\n0\r\n\r\n");
                r
            } else if path.starts_with("/badheader") {
                // §9: header con un byte de control (0x01) en el valor → HeaderValue
                // inválido. El edge debe descartarlo, NO panicar, y servir el body.
                let body = b"ok-body";
                let mut r = Vec::new();
                r.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
                r.extend_from_slice(b"Content-Type: text/plain\r\n");
                r.extend_from_slice(b"X-Bad: va\x01lue\r\n");
                r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
                r.extend_from_slice(b"Connection: close\r\n\r\n");
                r.extend_from_slice(body);
                r
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            };
            let _ = s.write_all(&resp);
        }
    });
    port
}

/// Levanta un edge (`proxy to` catch-all) contra un upstream fresco. Devuelve el
/// puerto del edge, ya listo para recibir requests.
fn setup() -> u16 {
    let up = spawn_upstream();
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"GET /*path\"\n        proxy to \"http://127.0.0.1:{up}\"\n",
        p = port,
        up = up
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "proxy_headers_e2e.syn", false);
    });
    let mut ready = false;
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el edge proxy no quedó listo en :{}", port);
    thread::sleep(Duration::from_millis(150));
    port
}

/// GET crudo (Connection: close) → (head como String, body como bytes exactos).
fn raw_get(port: u16, path: &str) -> (String, Vec<u8>) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("respuesta sin CRLFCRLF");
    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
    let body = buf[pos + 4..].to_vec();
    (head, body)
}

/// Headers del head como pares (nombre-en-minúsculas, valor). Preserva duplicados.
fn header_pairs(head: &str) -> Vec<(String, String)> {
    head.split("\r\n")
        .skip(1) // status line
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect()
}

fn values<'a>(hs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    hs.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
}

fn has(hs: &[(String, String)], name: &str, value: &str) -> bool {
    hs.iter().any(|(k, v)| k == name && v == value)
}

// §4.1 [central] — un 301 upstream cruza CON Location.
#[test]
fn proxy_forwards_location_on_redirect() {
    let port = setup();
    let (head, _) = raw_get(port, "/redirect");
    assert!(head.starts_with("HTTP/1.1 301"), "status: {}", head);
    let hs = header_pairs(&head);
    assert_eq!(values(&hs, "location"), vec!["/en/0.4.x/21-secrets"], "Location: {}", head);
}

// §4.2 — dos Set-Cookie llegan ambas (no colapsadas), en orden.
#[test]
fn proxy_forwards_multiple_set_cookie() {
    let port = setup();
    let (head, _) = raw_get(port, "/headers");
    let hs = header_pairs(&head);
    assert_eq!(values(&hs, "set-cookie"), vec!["a=1", "b=2"], "Set-Cookie: {}", head);
}

// §4.3/§4.4 — Cache-Control, ETag, Vary y header custom X-Foo llegan intactos.
#[test]
fn proxy_forwards_cache_and_custom_headers() {
    let port = setup();
    let (head, _) = raw_get(port, "/headers");
    let hs = header_pairs(&head);
    assert!(has(&hs, "cache-control", "max-age=60"), "Cache-Control: {}", head);
    assert!(has(&hs, "etag", "\"abc123\""), "ETag: {}", head);
    assert!(has(&hs, "vary", "Accept-Encoding"), "Vary: {}", head);
    assert!(has(&hs, "x-foo", "bar"), "X-Foo: {}", head);
}

// §4.5 [no-regresión] — status + content-type + body binario byte-exacto.
#[test]
fn proxy_preserves_binary_body_and_content_type() {
    let port = setup();
    let (head, body) = raw_get(port, "/png");
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    let hs = header_pairs(&head);
    assert!(has(&hs, "content-type", "image/png"), "content-type: {}", head);
    assert_eq!(body, vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "PNG byte-exacto");
}

// §4.6 — hop-by-hop del upstream NO se reenvían (Keep-Alive).
#[test]
fn proxy_drops_hop_by_hop_headers() {
    let port = setup();
    let (head, _) = raw_get(port, "/headers");
    let hs = header_pairs(&head);
    assert!(values(&hs, "keep-alive").is_empty(), "Keep-Alive no debe reenviarse: {}", head);
}

// §4.7 — chunked→dechunk: body correcto, Content-Length real, sin Transfer-Encoding.
#[test]
fn proxy_dechunks_and_sets_content_length() {
    let port = setup();
    let (head, body) = raw_get(port, "/chunked");
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    assert_eq!(body, b"Hello, world!".to_vec(), "body dechunkeado");
    let hs = header_pairs(&head);
    assert_eq!(values(&hs, "content-length"), vec!["13"], "Content-Length: {}", head);
    assert!(values(&hs, "transfer-encoding").is_empty(), "Transfer-Encoding no debe reenviarse: {}", head);
}

// §9 — un header inválido del upstream (byte de control) se descarta sin panic:
// el cliente recibe status + body sin ese header, y el edge sigue vivo después.
#[test]
fn proxy_drops_invalid_upstream_header_without_panic() {
    let port = setup();
    let (head, body) = raw_get(port, "/badheader");
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    assert_eq!(body, b"ok-body".to_vec(), "body intacto pese al header inválido");
    let hs = header_pairs(&head);
    assert!(values(&hs, "x-bad").is_empty(), "el header inválido no debe cruzar: {}", head);
    // Request normal posterior: el edge no se cayó por el header malformado.
    let (head2, body2) = raw_get(port, "/png");
    assert!(head2.starts_with("HTTP/1.1 200"), "request posterior: {}", head2);
    assert_eq!(body2, vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "edge sigue sano");
}
