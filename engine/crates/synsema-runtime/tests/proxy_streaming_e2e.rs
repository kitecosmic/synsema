//! Gate end-to-end del reverse proxy en STREAMING (`specs/proxy-streaming.md`): a
//! través de un edge `proxy to` deben pasar SSE en tiempo real, un upgrade WebSocket
//! (túnel bidireccional), bodies grandes con `Content-Length` preservado, HEAD como
//! HEAD y los `X-Forwarded-*`; un upstream caído es 502, un target `https://` es
//! error de ARRANQUE y el tope de streams da 503.
//!
//! Upstreams de prueba en `std::net` (crudos, un hilo por conexión) y, para el
//! dogfood, un `synsema serve` real con una ruta `socket` detrás del edge y un
//! cliente `ws_connect` del propio lenguaje.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

/// Lee la request entera (request-line + headers) y devuelve (método, path, headers).
fn read_request(reader: &mut BufReader<TcpStream>) -> Option<(String, String, Vec<(String, String)>)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }
    Some((method, path, headers))
}

/// Upstream crudo con un caso por path.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            thread::spawn(move || {
                let mut reader = BufReader::new(s.try_clone().unwrap());
                let Some((method, path, headers)) = read_request(&mut reader) else { return };
                let mut s = s;
                if path.starts_with("/sse") {
                    // SSE chunked: evento 1, pausa de 3 s, evento 2, fin.
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n",
                    );
                    let ev1 = b"data: {\"n\":1}\n\n";
                    let _ = s.write_all(format!("{:x}\r\n", ev1.len()).as_bytes());
                    let _ = s.write_all(ev1);
                    let _ = s.write_all(b"\r\n");
                    let _ = s.flush();
                    thread::sleep(Duration::from_secs(3));
                    let ev2 = b"data: {\"n\":2}\n\n";
                    let _ = s.write_all(format!("{:x}\r\n", ev2.len()).as_bytes());
                    let _ = s.write_all(ev2);
                    let _ = s.write_all(b"\r\n0\r\n\r\n");
                    let _ = s.flush();
                } else if path.starts_with("/big") {
                    // 4 MiB con Content-Length, en trozos de 64 KiB con pausas.
                    let total = 4 * 1024 * 1024;
                    let _ = s.write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", total)
                            .as_bytes(),
                    );
                    let chunk = vec![0xABu8; 64 * 1024];
                    let mut sent = 0;
                    while sent < total {
                        if s.write_all(&chunk).is_err() {
                            return;
                        }
                        sent += chunk.len();
                        thread::sleep(Duration::from_millis(1));
                    }
                } else if path.starts_with("/method") {
                    let body = format!("method={}", method);
                    let _ = s.write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
                            .as_bytes(),
                    );
                } else if path.starts_with("/xff") {
                    let mut body = String::new();
                    for (k, v) in &headers {
                        if k.starts_with("x-forwarded-") || k == "host" || k == "accept-encoding" {
                            body.push_str(&format!("{}={}\n", k, v));
                        }
                    }
                    let _ = s.write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
                            .as_bytes(),
                    );
                } else if path.starts_with("/closed") {
                    // Sin length ni chunked: el fin es el cierre de la conexión.
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nclose-delimited body");
                } else {
                    let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    port
}

/// Upstream WebSocket (tungstenite) que hace eco; marca `closed` al recibir Close.
fn spawn_ws_upstream(closed: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let closed = closed.clone();
            thread::spawn(move || {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(w) => w,
                    Err(_) => return,
                };
                loop {
                    match ws.read() {
                        Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                            if ws.send(m).is_err() {
                                return;
                            }
                        }
                        Ok(tungstenite::Message::Close(_)) => {
                            closed.store(true, Ordering::SeqCst);
                            return;
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
            });
        }
    });
    port
}

/// Edge `proxy to` catch-all (GET + POST + `/`; HEAD entra por la ruta GET) contra `up`.
fn spawn_edge(up: u16, extra_serve_lines: &str) -> u16 {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire net(\"127.0.0.1\")\nserve on {p}\n{extra}    route \"GET /\"\n        proxy to \"http://127.0.0.1:{up}\"\n    route \"GET /*path\"\n        proxy to \"http://127.0.0.1:{up}\"\n    route \"POST /*path\"\n        proxy to \"http://127.0.0.1:{up}\"\n",
        p = port,
        up = up,
        extra = extra_serve_lines
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "proxy_streaming_e2e.syn", false);
    });
    wait_ready(port);
    port
}

fn send_raw(port: u16, req: &str) -> TcpStream {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.write_all(req.as_bytes()).unwrap();
    sock
}

fn read_head(sock: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            return (head, buf[pos + 4..].to_vec());
        }
    }
    panic!("respuesta sin head: {:?}", String::from_utf8_lossy(&buf));
}

fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

// -- SSE en tiempo real --

#[test]
fn sse_events_arrive_before_upstream_finishes() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "");
    let t0 = Instant::now();
    let mut sock = send_raw(port, "GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (head, rest) = read_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    assert_eq!(header(&head, "content-type").as_deref(), Some("text/event-stream"), "{}", head);
    // Primer evento: debe llegar ANTES de que el upstream termine (pausa de 3 s).
    let mut got = rest;
    let mut tmp = [0u8; 1024];
    while !String::from_utf8_lossy(&got).contains("{\"n\":1}") {
        let n = sock.read(&mut tmp).expect("leyendo evento 1");
        assert!(n > 0, "EOF antes del evento 1");
        got.extend_from_slice(&tmp[..n]);
    }
    let first_at = t0.elapsed();
    assert!(first_at < Duration::from_millis(1500), "el evento 1 tardó {:?}: el edge bufferiza", first_at);
    // Segundo evento tras la pausa del upstream.
    while !String::from_utf8_lossy(&got).contains("{\"n\":2}") {
        let n = sock.read(&mut tmp).expect("leyendo evento 2");
        assert!(n > 0, "EOF antes del evento 2");
        got.extend_from_slice(&tmp[..n]);
    }
    assert!(t0.elapsed() >= Duration::from_millis(2500), "el evento 2 llegó antes de la pausa del upstream");
}

// -- WebSocket: túnel a través del edge --

#[test]
fn websocket_tunnel_echoes_frames() {
    let closed = Arc::new(AtomicBool::new(false));
    let up = spawn_ws_upstream(closed.clone());
    let port = spawn_edge(up, "");
    let (mut ws, resp) = tungstenite::connect(format!("ws://127.0.0.1:{}/chat", port).as_str()).expect("handshake a través del edge");
    assert_eq!(resp.status().as_u16(), 101);
    assert!(resp.headers().get("sec-websocket-accept").is_some(), "el 101 del upstream cruza con su Accept");
    ws.send(tungstenite::Message::Text("hola edge".into())).unwrap();
    match ws.read().unwrap() {
        tungstenite::Message::Text(t) => assert_eq!(t.as_str(), "hola edge"),
        other => panic!("esperaba eco de texto, got {:?}", other),
    }
    ws.send(tungstenite::Message::Binary(vec![1u8, 2, 3].into())).unwrap();
    match ws.read().unwrap() {
        tungstenite::Message::Binary(b) => assert_eq!(b.as_ref(), &[1u8, 2, 3]),
        other => panic!("esperaba eco binario, got {:?}", other),
    }
    ws.close(None).unwrap();
    let _ = ws.read(); // Close del upstream
    let t0 = Instant::now();
    while !closed.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(closed.load(Ordering::SeqCst), "el Close del cliente debe llegar al upstream por el túnel");
}

// Dogfood: backend `synsema serve` con ruta `socket` (eco) detrás del edge; el cliente
// es `ws_connect` del propio lenguaje.
#[test]
fn websocket_tunnel_via_synsema_socket_route() {
    let back = free_port();
    let backend = format!(
        r#"require serve({b})
serve on {b}
    route "GET /echo"
        socket
            ws_send(socket, "ready")
            while true
                let ev be ws_recv(socket, 10)
                when ev == nothing
                    stop
                when ev["type"] == "close"
                    stop
                otherwise
                    ws_send(socket, "echo:" + ev["data"])
"#,
        b = back
    );
    thread::spawn(move || {
        let _ = run_serve_program(&backend, "backend_socket.syn", false);
    });
    wait_ready(back);
    let port = spawn_edge(back, "");
    let r = run_source(
        &format!(
            r#"require net("127.0.0.1")
let conn be ws_connect("ws://127.0.0.1:{p}/echo")
print(ws_recv(conn, 5)["data"])
ws_send(conn, "ping")
print(ws_recv(conn, 5)["data"])
ws_close(conn)
"#,
            p = port
        ),
        "client.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["ready", "echo:ping"]);
}

// -- Bodies grandes: Content-Length preservado, bytes exactos --

#[test]
fn large_body_streams_with_content_length() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "");
    let mut sock = send_raw(port, "GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let (head, mut body) = read_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    assert_eq!(header(&head, "content-length").as_deref(), Some("4194304"), "{}", head);
    assert!(header(&head, "transfer-encoding").is_none(), "{}", head);
    let _ = sock.read_to_end(&mut body);
    assert_eq!(body.len(), 4 * 1024 * 1024);
    assert!(body.iter().all(|b| *b == 0xAB));
}

#[test]
fn close_delimited_body_passes_through() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "");
    let mut sock = send_raw(port, "GET /closed HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (head, mut body) = read_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    let _ = sock.read_to_end(&mut body);
    let text = String::from_utf8_lossy(&body).to_string();
    let text = if header(&head, "transfer-encoding").map(|v| v.contains("chunked")).unwrap_or(false) {
        // Cliente h1: hyper re-encodea chunked; desarmar.
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some((size, after)) = rest.split_once("\r\n") {
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.push_str(&after[..n]);
            rest = &after[n + 2..];
        }
        out
    } else {
        text
    };
    assert_eq!(text, "close-delimited body");
}

// -- HEAD, X-Forwarded-*, Accept-Encoding passthrough --

#[test]
fn head_is_forwarded_as_head() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "");
    let mut sock = send_raw(port, "HEAD /method HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let (head, mut body) = read_head(&mut sock);
    let _ = sock.read_to_end(&mut body);
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    assert!(body.is_empty(), "HEAD no lleva body: {:?}", String::from_utf8_lossy(&body));
    // El upstream vio HEAD: su body sería "method=HEAD" (11 bytes) → Content-Length 11.
    assert_eq!(header(&head, "content-length").as_deref(), Some("11"), "{}", head);
}

#[test]
fn x_forwarded_headers_reach_upstream() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "");
    let mut sock = send_raw(
        port,
        "GET /xff HTTP/1.1\r\nHost: edge.example:8080\r\nX-Forwarded-For: 10.0.0.9\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    let (head, mut body) = read_head(&mut sock);
    let _ = sock.read_to_end(&mut body);
    assert!(head.starts_with("HTTP/1.1 200"), "status: {}", head);
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(text.contains("x-forwarded-for=10.0.0.9, 127.0.0.1"), "{}", text);
    assert!(text.contains("x-forwarded-proto=http"), "{}", text);
    assert!(text.contains("x-forwarded-host=edge.example:8080"), "{}", text);
    assert!(text.contains(&format!("host=127.0.0.1:{}", up)), "Host = authority del upstream: {}", text);
    assert!(text.contains("accept-encoding=gzip"), "Accept-Encoding cruza al upstream: {}", text);
}

// -- Errores: upstream caído, target inválido, tope de streams --

#[test]
fn upstream_down_is_502() {
    let dead = free_port();
    let port = spawn_edge(dead, "");
    let mut sock = send_raw(port, "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let (head, mut body) = read_head(&mut sock);
    let _ = sock.read_to_end(&mut body);
    assert!(head.starts_with("HTTP/1.1 502"), "status: {}", head);
    assert!(String::from_utf8_lossy(&body).contains("proxy error: connect"), "{}", String::from_utf8_lossy(&body));
}

#[test]
fn https_target_is_a_startup_error() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire net(\"api.example.com\")\nserve on {p}\n    route \"GET /*path\"\n        proxy to \"https://api.example.com\"\n",
        p = port
    );
    let r = run_serve_program(&prog, "bad_target.syn", false);
    assert!(!r.success, "un target https:// debe fallar al arrancar");
    let msg = r.errors.join("\n");
    assert!(msg.contains("proxy to:") && msg.contains("http://"), "{}", msg);
}

#[test]
fn stream_slot_exhaustion_is_503() {
    let up = spawn_upstream();
    let port = spawn_edge(up, "    max_streams 1\n");
    let mut first = send_raw(port, "GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    first.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (head1, _) = read_head(&mut first);
    assert!(head1.starts_with("HTTP/1.1 200"), "{}", head1);
    let mut second = send_raw(port, "GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    second.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (head2, _) = read_head(&mut second);
    assert!(head2.starts_with("HTTP/1.1 503"), "con max_streams 1 el segundo SSE debe ser 503: {}", head2);
    assert_eq!(header(&head2, "retry-after").as_deref(), Some("5"));
    // Un sized (Content-Length) NO ocupa slot: sigue pasando.
    let mut third = send_raw(port, "GET /method HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let (head3, _) = read_head(&mut third);
    assert!(head3.starts_with("HTTP/1.1 200"), "{}", head3);
}

// deny-by-default: el upstream es una conexión saliente → exige `net(host)` como
// http_get/ws_connect. Sin la capability el serve NO arranca (error claro), jamás
// un 502 por request.
#[test]
fn proxy_without_net_capability_fails_at_startup() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"GET /*path\"\n        proxy to \"http://127.0.0.1:9\"\n",
        p = port
    );
    let r = run_serve_program(&prog, "no_net.syn", false);
    assert!(!r.success, "sin `require net` el proxy debe fallar al arrancar");
    let msg = r.errors.join("\n");
    assert!(msg.contains("net") && msg.contains("127.0.0.1"), "{}", msg);
    // Con la capability del host correcto arranca (el upstream caído es un 502, no un error de arranque).
    let prog_ok = format!(
        "require serve({p})\nrequire net(\"127.0.0.1\")\nserve on {p}\n    route \"GET /*path\"\n        proxy to \"http://127.0.0.1:9\"\n",
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog_ok, "with_net.syn", false);
    });
    wait_ready(port);
}
