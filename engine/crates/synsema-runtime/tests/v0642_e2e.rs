//! v0.6.42 — e2e de túneles contra un server REAL (`run_serve_program`) y programas `run`:
//! - el túnel entero en Synsema: una ruta crea un `pipe()`, un agente une un extremo con
//!   `tcp_connect` al servicio local y la ruta hace `proxy to` sobre el otro (HTTP y SSE);
//! - `proxy to` con destino por request, y su `net` chequeado por request;
//! - una `route "OPTIONS …"` declarada gana sobre la respuesta automática (preflight de CORS);
//! - `tcp_connect` con `net("host:puerto")` exacto, eco, cierre y `select`;
//! - `exit(code)`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..120 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn start(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "v0642_e2e.syn", false);
    });
    wait_ready(port);
}

/// Servicio "local" (lo que está detrás del túnel): una respuesta por path, SSE en `/sse` y un
/// preflight propio en `OPTIONS`.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut xff = String::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    if h.to_ascii_lowercase().starts_with("x-forwarded-for:") {
                        xff = h[16..].trim().to_string();
                    }
                }
                let mut s = stream;
                if method == "OPTIONS" {
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nX-Upstream-Preflight: yes\r\nAccess-Control-Allow-Methods: PUT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return;
                }
                if path.starts_with("/sse") {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                    let ev1 = b"data: uno\n\n";
                    let _ = s.write_all(format!("{:x}\r\n", ev1.len()).as_bytes());
                    let _ = s.write_all(ev1);
                    let _ = s.write_all(b"\r\n");
                    let _ = s.flush();
                    thread::sleep(Duration::from_millis(1500));
                    let ev2 = b"data: dos\n\n";
                    let _ = s.write_all(format!("{:x}\r\n", ev2.len()).as_bytes());
                    let _ = s.write_all(ev2);
                    let _ = s.write_all(b"\r\n0\r\n\r\n");
                    return;
                }
                let body = format!("upstream {} {} xff={}", method, path, xff);
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body)
                        .as_bytes(),
                );
            });
        }
    });
    port
}

fn get(port: u16, path: &str, extra: &str) -> (u16, String, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let req = format!("GET {} HTTP/1.1\r\nHost: t.example\r\nConnection: close\r\n{}\r\n", path, extra);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_lowercase(), body.to_string())
}

/// El programa del edge: la ruta abre un pipe, el agente lo une al servicio por TCP.
fn tunnel_program(port: u16, up: u16) -> String {
    format!(
        r#"require serve({port})
require net("127.0.0.1:{up}")

agent Bridge
    require net("127.0.0.1:{up}")
    let svc be tcp_connect("127.0.0.1", {up})
    let live be true
    while live
        let m be select({{"pipe": peer, "svc": svc}}, 20)
        when m == nothing
            set live to false
        otherwise when m["type"] == "close"
            set live to false
        otherwise when m["name"] == "pipe"
            tcp_send(svc, m["data"])
        otherwise
            pipe_send(peer, m["data"])
    tcp_close(svc)
    pipe_close(peer)

serve on {port}
    route "GET /*path"
        -- el túnel: un pipe por request; el agente lleva el otro extremo al servicio
        let p be pipe()
        spawn Bridge with peer = p["b"]
        proxy to p["a"]
"#,
        port = port,
        up = up
    )
}

#[test]
fn a_tunnel_written_in_synsema_carries_http_and_sse() {
    let up = spawn_upstream();
    let port = free_port();
    start(tunnel_program(port, up), port);

    let (status, _head, body) = get(port, "/hola?x=1", "X-Forwarded-For: 6.6.6.6\r\n");
    assert_eq!(status, 200, "{}", body);
    // El servicio ve la request entera y el XFF honesto (el del cliente se descartó).
    assert_eq!(body, "upstream GET /hola?x=1 xff=127.0.0.1");

    // SSE sin buffering: el primer evento llega antes de que el servicio mande el segundo.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"GET /sse HTTP/1.1\r\nHost: t.example\r\nConnection: close\r\n\r\n").unwrap();
    let t0 = Instant::now();
    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&acc).contains("uno") {
        let n = sock.read(&mut buf).unwrap();
        assert!(n > 0, "el stream se cortó antes del primer evento");
        acc.extend_from_slice(&buf[..n]);
    }
    assert!(t0.elapsed() < Duration::from_millis(1200), "el primer evento esperó al segundo: {:?}", t0.elapsed());
    let mut rest = Vec::new();
    let _ = sock.read_to_end(&mut rest);
    acc.extend_from_slice(&rest);
    assert!(String::from_utf8_lossy(&acc).contains("dos"));
}

#[test]
fn proxy_to_with_a_per_request_destination_checks_net_per_request() {
    let up = spawn_upstream();
    let port = free_port();
    let prog = format!(
        r#"require serve({port})
require net("127.0.0.1:{up}")

task pick(r)
    when r["query"]["to"] == "bad"
        give "http://10.255.255.1:9"
    give "http://127.0.0.1:{up}"

serve on {port}
    route "GET /dyn"
        when query["to"] == "none"
            give {{"offline": true}}
        proxy to pick(request)
    route "OPTIONS /api/*rest"
        proxy to "http://127.0.0.1:{up}"
    route "PUT /api/*rest"
        give "put"
"#,
        port = port,
        up = up
    );
    start(prog, port);

    let (status, _, body) = get(port, "/dyn?to=ok", "");
    assert_eq!(status, 200, "{}", body);
    assert!(body.starts_with("upstream GET /dyn?to=ok"), "{}", body);

    // La ruta decide no reenviar: respuesta normal.
    let (status, _, body) = get(port, "/dyn?to=none", "");
    assert_eq!(status, 200);
    assert!(body.contains("offline"), "{}", body);

    // Un destino calculado sin `net` concedido no sale: error, nunca una conexión.
    let (status, _, body) = get(port, "/dyn?to=bad", "");
    assert_eq!(status, 500, "{}", body);
    assert!(body.to_lowercase().contains("capability"), "{}", body);

    // El preflight lo contesta el servicio de atrás (la ruta OPTIONS declarada gana).
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"OPTIONS /api/x HTTP/1.1\r\nHost: t.example\r\nOrigin: https://a.example\r\nAccess-Control-Request-Method: PUT\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 204"), "{}", resp);
    assert!(resp.to_lowercase().contains("x-upstream-preflight: yes"), "{}", resp);
}

#[test]
fn an_options_without_a_declared_route_is_still_answered_by_the_server() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"GET /a\"\n        give 1\n    route \"POST /a\"\n        give 2\n",
        p = port
    );
    start(prog, port);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"OPTIONS /a HTTP/1.1\r\nHost: t.example\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 204"), "{}", resp);
    assert!(resp.contains("GET, HEAD, OPTIONS, POST"), "{}", resp);
}

// ---------------------------------------------------------------------------------
// Programas `run`
// ---------------------------------------------------------------------------------

fn echo_server() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if &buf[..n] == b"bye" {
                                return; // cierra: el programa ve {type: "close"}
                            }
                            let _ = s.write_all(&buf[..n]);
                        }
                    }
                }
            });
        }
    });
    port
}

/// `last_run_exit_code` es del proceso: los tests que corren programas no se pisan.
static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run(src: &str) -> synsema_core::interpreter::RunResult {
    synsema_runtime::engine::run_program(src, "v0642_run.syn")
}

#[test]
fn tcp_connect_echo_close_and_select() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let port = echo_server();
    let src = format!(
        r#"require net("127.0.0.1:{port}")
let c be tcp_connect("127.0.0.1", {port})
tcp_send(c, "hola")
let m be tcp_recv(c, 5)
print(m["type"])
print(decode(m["data"]))
tcp_send(c, "bye")
let ev be select([c], 5)
print(ev["type"])
print(ev["source"])
tcp_close(c)
"#,
        port = port
    );
    let r = run(&src);
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["data", "hola", "close", "tcp"]);
}

#[test]
fn tcp_connect_needs_the_exact_port() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let port = echo_server();
    let other = free_port();
    let src = format!("require net(\"127.0.0.1:{}\")\nlet c be tcp_connect(\"127.0.0.1\", {})\n", port, other);
    let r = run(&src);
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("Capability not granted")), "{:?}", r.errors);
}

#[test]
fn a_pipe_carries_bytes_and_close_inside_one_program() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let r = run("let p be pipe({\"max_buffer\": 8})\npipe_send(p[\"a\"], \"hola\")\nlet m be pipe_recv(p[\"b\"], 1)\nprint(decode(m[\"data\"]))\npipe_close(p[\"a\"])\nprint(pipe_recv(p[\"b\"], 1)[\"type\"])\n");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["hola", "close"]);
}

#[test]
fn exit_sets_the_code_of_the_run() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let r = run("print(\"antes\")\nexit(7)\nprint(\"después\")\n");
    assert!(!r.success);
    assert!(r.errors.is_empty(), "exit no es un error: {:?}", r.errors);
    assert_eq!(r.output, vec!["antes"]);
    assert_eq!(synsema_runtime::engine::last_run_exit_code(), Some(7));
    let r = run("exit(0)\n");
    assert!(r.success);
    assert_eq!(synsema_runtime::engine::last_run_exit_code(), Some(0));
    let r = run("print(1)\n");
    assert!(r.success);
    assert_eq!(synsema_runtime::engine::last_run_exit_code(), None);
}

/// Upstream que lee el body por `Content-Length` y contesta cuántos bytes recibió.
fn spawn_counting_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut buf = vec![0u8; 64 * 1024];
                let mut got = 0usize;
                while got < len {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                let body = format!("got {}", got);
                let mut s = stream;
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes(),
                );
            });
        }
    });
    port
}

fn post(port: u16, path: &str, size: usize) -> (u16, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    sock.write_all(format!("POST {} HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, size).as_bytes())
        .unwrap();
    let chunk = vec![b'x'; 64 * 1024];
    let mut sent = 0;
    while sent < size {
        let n = chunk.len().min(size - sent);
        if sock.write_all(&chunk[..n]).is_err() {
            break; // el server cortó (413): leer la respuesta
        }
        sent += n;
    }
    // `read_to_end` conserva lo leído aunque el server cierre con datos sin leer (RST).
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw);
    let resp = String::from_utf8_lossy(&raw).to_string();
    let status = resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, resp)
}

#[test]
fn a_proxied_body_streams_and_max_body_still_holds() {
    let up = spawn_counting_upstream();
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire net(\"127.0.0.1:{up}\")\nserve on {p}\n    max_body \"16mb\"\n    route \"POST /up\"\n        proxy to \"http://127.0.0.1:{up}\"\n",
        p = port,
        up = up
    );
    start(prog, port);
    // 8 MB pasan sin que el edge los junte en memoria (el upstream los cuenta).
    let (status, resp) = post(port, "/up", 8 * 1024 * 1024);
    assert_eq!(status, 200, "{}", resp);
    assert!(resp.ends_with(&format!("got {}", 8 * 1024 * 1024)), "{}", resp);
    // Un `Content-Length` por encima de `max_body`: 413 apenas llegan los headers, sin esperar
    // (ni leer) el body.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(format!("POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n", 20 * 1024 * 1024).as_bytes())
        .unwrap();
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw);
    let resp = String::from_utf8_lossy(&raw).to_string();
    assert!(resp.starts_with("HTTP/1.1 413"), "{}", &resp[..resp.len().min(300)]);
}

#[test]
fn behind_a_trusted_proxy_x_forwarded_proto_sets_the_scheme() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    trust proxy \"127.0.0.1\"\n    route \"GET /health\"\n        give \"ok\"\n    route \"GET /ip\"\n        give ip of request\n",
        p = port
    );
    start(prog, port);
    let (status, _, body) = get(port, "/sitemap.xml", "X-Forwarded-Proto: https\r\n");
    assert_eq!(status, 200, "{}", body);
    assert!(body.contains("https://t.example/health"), "{}", body);
    // Y `ip of request` es el cliente real de la cadena (el par es un proxy de confianza).
    let (_, _, body) = get(port, "/ip", "X-Forwarded-For: 203.0.113.7\r\n");
    assert!(body.contains("203.0.113.7"), "{}", body);
}

#[test]
fn a_destination_built_from_the_request_cannot_smuggle_another_host() {
    let up = spawn_upstream();
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire net(\"127.0.0.1:{up}\")\nserve on {p}\n    route \"GET /go\"\n        proxy to \"http://\" + query[\"svc\"]\n",
        p = port,
        up = up
    );
    start(prog, port);
    let (status, _, body) = get(port, &format!("/go?svc=127.0.0.1:{}", up), "");
    assert_eq!(status, 200, "{}", body);
    // `127.0.0.1:UP?.x.attacker:6379`: antes se chequeaba 127.0.0.1:UP y se conectaba a otro host.
    let (status, _, body) = get(port, &format!("/go?svc=127.0.0.1:{}%3F.x.attacker.example:6379", up), "");
    assert_eq!(status, 500, "{}", body);
    assert!(body.contains("not part of a host"), "{}", body);
}

#[test]
fn a_proxy_route_that_reads_the_body_sees_it_and_still_forwards_it() {
    let up = spawn_counting_upstream();
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire net(\"127.0.0.1:{up}\")\nserve on {p}\n    route \"POST /filter\"\n        when contains(read_body(), \"<script\")\n            give respond(\"blocked\", \"text/plain\", 400)\n        proxy to \"http://127.0.0.1:{up}\" + \"\"\n",
        p = port,
        up = up
    );
    start(prog, port);
    let (status, resp) = post(port, "/filter", 5);
    assert_eq!(status, 200, "{}", resp);
    assert!(resp.ends_with("got 5"), "el upstream recibe el body que la ruta ya leyó: {}", resp);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    sock.write_all(b"POST /filter HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\nConnection: close\r\n\r\n<script>").unwrap();
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw);
    let resp = String::from_utf8_lossy(&raw).to_string();
    assert!(resp.starts_with("HTTP/1.1 400"), "el filtro ve el body (no un vacío en silencio): {}", resp);
}

/// Auditoría ronda 2 (R4): lo que la detección estática no ve (una task que lee `r.body`,
/// `get(request, "body")`, `request[k]`) ya no evalúa el filtro sobre `""` y deja pasar el body:
/// el `request` de una ruta en streaming no tiene esas claves, así que el filtro falla (500) y
/// nada llega al destino.
#[test]
fn a_streamed_body_cannot_be_read_around_the_static_check() {
    let up = spawn_counting_upstream();
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
require net("127.0.0.1:{up}")

task looks_bad(r)
    give contains(r.body, "<script")

serve on {p}
    route "POST /task"
        when looks_bad(request)
            give respond("blocked", "text/plain", 400)
        proxy to "http://127.0.0.1:{up}" + ""
    route "POST /get"
        when contains(get(request, "body"), "<script")
            give respond("blocked", "text/plain", 400)
        proxy to "http://127.0.0.1:{up}" + ""
    route "POST /idx"
        let k be "body"
        when contains(request[k], "<script")
            give respond("blocked", "text/plain", 400)
        proxy to "http://127.0.0.1:{up}" + ""
    route "POST /plain"
        proxy to "http://127.0.0.1:{up}" + ""
"#,
        p = port,
        up = up
    );
    start(prog, port);
    for path in ["/task", "/get", "/idx"] {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        sock.write_all(format!("POST {} HTTP/1.1
Host: t
Content-Length: 8
Connection: close

<script>", path).as_bytes())
            .unwrap();
        let mut raw = Vec::new();
        let _ = sock.read_to_end(&mut raw);
        let resp = String::from_utf8_lossy(&raw).to_string();
        assert!(resp.starts_with("HTTP/1.1 500"), "{}: el filtro no corre sobre un body vacío: {}", path, resp);
        assert!(!resp.contains("got "), "{}: el body no llegó al destino: {}", path, resp);
    }
    // Sin leerlo, sigue en streaming y llega entero.
    let (status, resp) = post(port, "/plain", 1024 * 1024);
    assert_eq!(status, 200, "{}", resp);
    assert!(resp.ends_with(&format!("got {}", 1024 * 1024)), "{}", resp);
}

#[test]
fn two_host_headers_are_a_bad_request() {
    let port = free_port();
    start(format!("require serve({p})\nserve on {p}\n    route \"GET /\"\n        give 1\n", p = port), port);
    let (status, _, _) = get(port, "/", "Host: other.example\r\n");
    assert_eq!(status, 400);
}

#[test]
fn a_pipe_half_close_still_lets_the_other_side_answer() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let r = run("let p be pipe()\npipe_send(p[\"a\"], \"req\")\npipe_close(p[\"a\"], \"write\")\nprint(decode(pipe_recv(p[\"b\"], 1)[\"data\"]))\nprint(pipe_recv(p[\"b\"], 1)[\"type\"])\npipe_send(p[\"b\"], \"resp\")\nprint(decode(pipe_recv(p[\"a\"], 1)[\"data\"]))\n");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["req", "close", "resp"]);
}

/// Auditoría ronda 2 (R7): un par que hace `SHUT_WR` y espera la respuesta la recibe (al
/// entregar el `close` se hacía `shutdown(Both)`). Y el `close` queda pegado: otro `tcp_recv`
/// después lo devuelve enseguida, no al vencer su timeout.
#[test]
fn a_tcp_peer_that_half_closes_still_gets_the_answer() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"pregunta").unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let _ = s.read_to_end(&mut got);
        let _ = tx.send(got);
    });
    let src = format!(
        r#"require net("127.0.0.1:{port}")
let c be tcp_connect("127.0.0.1", {port})
print(decode(tcp_recv(c, 10)["data"]))
print(tcp_recv(c, 10)["type"])
print(tcp_recv(c, 10)["type"])
tcp_send(c, "respuesta")
tcp_close(c)
"#,
        port = port
    );
    let t0 = std::time::Instant::now();
    let r = run(&src);
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["pregunta", "close", "close"]);
    assert!(t0.elapsed() < Duration::from_secs(5), "el segundo close no esperó el timeout: {:?}", t0.elapsed());
    let got = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(got, b"respuesta", "el par que hizo SHUT_WR recibe la respuesta");
}

/// Auditoría ronda 2 (R6): después del EOF, `pipe_recv` devuelve `close` enseguida.
#[test]
fn a_pipe_close_is_sticky() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t0 = std::time::Instant::now();
    let r = run("let p be pipe()
pipe_close(p[\"a\"])
print(pipe_recv(p[\"b\"], 10)[\"type\"])
print(pipe_recv(p[\"b\"], 10)[\"type\"])
print(select([p[\"b\"]], 10)[\"type\"])
");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["close", "close", "close"]);
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
}

#[test]
fn exit_stops_live_agents_instead_of_hanging() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let src = "require time\nagent Forever\n    while true\n        sleep(0.05)\nspawn Forever\nprint(\"main\")\nexit(3)\n";
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run(src);
        let _ = tx.send((r, synsema_runtime::engine::last_run_exit_code()));
    });
    let (r, code) = rx.recv_timeout(Duration::from_secs(20)).expect("exit con un agente vivo se colgó");
    assert_eq!(r.output, vec!["main"]);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(code, Some(3));
}
