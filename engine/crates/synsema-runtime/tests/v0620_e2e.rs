//! v0.6.20 — e2e de la Tanda 4 contra un server REAL (`run_serve_program`):
//! - `private` por ruta fuera de /openapi.json y /llms.txt (pero servida);
//! - las URLs reservadas ganan a una ruta `GET /:param`;
//! - `openapi_json()` desde una ruta propia;
//! - salud opt-in del host (`SYNSEMA_HEALTH_PATH`), fuera de discovery;
//! - cliente HTTP: un map como body viaja como JSON con Content-Type, `json of r`,
//!   `http_bytes` exacto, `multipart_encode` que el servidor parsea como `form of request`;
//! - una ruta `stream` montada desde un grupo `export routes`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(prog: String, entry: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, &entry, false);
    });
    for _ in 0..120 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(200));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn request(port: u16, method: &str, target: &str, extra: &str, body: &str) -> (u16, String, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_lowercase(), body.to_string())
}

fn get(port: u16, target: &str) -> (u16, String, String) {
    request(port, "GET", target, "", "")
}

struct Tree {
    root: std::path::PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0620-e2e-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }
    fn write(&self, rel: &str, content: &str) -> String {
        let p = self.root.join(rel);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }
}

/// Un server con todo lo de la tanda junto: discovery, private, health y el cliente HTTP
/// hablándose a sí mismo (net("127.0.0.1")).
#[test]
fn private_reserved_urls_openapi_json_health_and_http_client() {
    // Salud opt-in del HOST: la variable se lee al construir el servidor.
    std::env::set_var("SYNSEMA_HEALTH_PATH", "/__health");
    let p = free_port();
    let prog = format!(
        r#"require serve({p})
require net("127.0.0.1")

task spec()
    give openapi_json()

serve on {p}
    route "GET /:lang"
        give {{"lang": "any"}}
    route "GET /admin/secret"
        private
        give {{"secret": true}}
    route "POST /echo"
        give {{"headers": headers of request, "body": body of request, "json": json of request}}
    route "GET /bin"
        give "héllo"
    route "GET /spec"
        give spec()
    route "GET /probe"
        let r be http_post("http://127.0.0.1:{p}/echo", {{"a": 1, "b": "x"}})
        give {{"status": status of r, "echo": json of r}}
    route "GET /probe_bytes"
        let r be http_bytes("GET", "http://127.0.0.1:{p}/bin")
        give {{"n": length(bytes of r), "status": status of r}}
    route "POST /form"
        give form of request
    route "GET /probe_multipart"
        let m be multipart_encode([{{"name": "title", "value": "hola"}}, {{"name": "who", "value": "mundo"}}])
        let r be http_post("http://127.0.0.1:{p}/form", body of m, {{"Content-Type": content_type of m}})
        give {{"status": status of r, "form": json of r}}
"#,
        p = p
    );
    start(prog, "v0620_e2e.syn".to_string(), p);

    // 1. Las URLs reservadas ganan a `GET /:lang`; la ruta con parámetro sigue viva.
    let (st, head, body) = get(p, "/openapi.json");
    assert_eq!(st, 200, "{}", body);
    assert!(head.contains("application/json"), "{}", head);
    assert!(body.contains("\"/echo\""), "{}", body);
    assert!(!body.contains("/admin/secret"), "una ruta private no se publica: {}", body);
    let (st, _, body) = get(p, "/es");
    assert_eq!(st, 200);
    assert!(body.contains("\"lang\""), "{}", body);
    let (st, _, body) = get(p, "/llms.txt");
    assert_eq!(st, 200);
    assert!(body.contains("POST /echo"), "{}", body);
    assert!(!body.contains("/admin/secret"), "{}", body);
    assert!(!body.contains("/__health"), "la salud no aparece en discovery: {}", body);
    // 2. …pero la ruta private se SIRVE.
    let (st, _, body) = get(p, "/admin/secret");
    assert_eq!(st, 200);
    assert!(body.contains("\"secret\": true"), "{}", body);
    // 3. openapi_json() desde una ruta propia = el mismo documento.
    let (st, _, body) = get(p, "/spec");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("openapi") && body.contains("/echo") && !body.contains("/admin/secret"), "{}", body);
    // 4. Salud opt-in del host.
    let (st, head, body) = get(p, "/__health");
    assert_eq!(st, 200, "{}", body);
    assert!(head.contains("application/json"), "{}", head);
    assert!(body.contains("\"ok\":true") && body.contains("\"in_flight\""), "{}", body);
    // 5. Cliente HTTP: un map viaja como JSON con Content-Type y `json of r` lo parsea.
    let (st, _, body) = get(p, "/probe");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("\"status\": 200"), "{}", body);
    assert!(body.contains("application/json"), "el echo vio el Content-Type: {}", body);
    assert!(body.contains("\"a\": 1"), "el echo parseó el JSON del body: {}", body);
    // 6. http_bytes: bytes EXACTOS del cuerpo que el servidor mandó (JSON con `é`
    //    escapado: 12 bytes; el punto es que coincida byte a byte con lo servido).
    let (_, _, bin) = get(p, "/bin");
    let (st, _, body) = get(p, "/probe_bytes");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains(&format!("\"n\": {}", bin.len())), "{} vs cuerpo {:?}", body, bin);
    // 7. multipart_encode → el servidor lo lee como `form of request`.
    let (st, _, body) = get(p, "/probe_multipart");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("\"title\": \"hola\"") && body.contains("\"who\": \"mundo\""), "{}", body);
}

/// §6.3 — una ruta `stream` montada desde un grupo `export routes` emite SSE como una directa.
#[test]
fn a_stream_route_mounted_from_a_group_emits_sse() {
    let t = Tree::new("stream-group");
    t.write(
        "live.syn",
        "export routes live\n    route \"GET /events\"\n        stream\n            send {\"n\": 1}\n            send {\"n\": 2} as \"tick\"\n",
    );
    let p = free_port();
    let prog = format!(
        "require serve({p})\nuse \"./live.syn\" as live\n\nserve on {p}\n    mount live.live\n    route \"GET /plain\"\n        give 1\n",
        p = p
    );
    let entry = t.write("main.syn", &prog);
    start(prog.clone(), entry, p);
    let (st, head, body) = get(p, "/events");
    assert_eq!(st, 200, "{}\n{}", head, body);
    assert!(head.contains("text/event-stream"), "{}", head);
    assert!(body.contains("data: {\"n\": 1}"), "{}", body);
    assert!(body.contains("event: tick"), "{}", body);
    let (st, _, _) = get(p, "/plain");
    assert_eq!(st, 200);
    // El grupo montado con un stream también se publica como tal.
    let (_, _, oa) = get(p, "/openapi.json");
    assert!(oa.contains("/events"), "{}", oa);
}
