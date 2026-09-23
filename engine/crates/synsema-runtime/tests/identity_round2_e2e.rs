//! Auditoría de T1–T4, ronda 1: las sondas del auditor, como tests.
//!
//! - `errors with` corre bajo el MISMO techo delegado que la ruta: la página de error de una
//!   request denegada no puede leer lo que la ruta no pudo (antes era una escalada: el 403 de
//!   la ruta traía el archivo en el cuerpo de su propia página de error).
//! - Los gates que arman su propio texto (`spend`, `render`/`file.read`) conservan la CAUSA:
//!   bajo un token que no delega la capability → 403 fijo, jamás un 500 con "add `require …`"
//!   ni con el id del token y la ruta.
//! - `SYNSEMA_IDENTITY` se lee del `.env` como todo knob (antes sólo del environ).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_program;
use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)]) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body_of(resp: &str) -> String {
    resp.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
}

fn field(resp: &str, name: &str) -> String {
    let needle = format!("\"{}\": \"", name);
    let start = resp.find(&needle).unwrap_or_else(|| panic!("no está {} en {}", name, resp)) + needle.len();
    let rest = &resp[start..];
    rest[..rest.find('"').expect("cierre")].to_string()
}

fn scratch_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("synsema-r2-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.txt"), "hello from the file").unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

/// Un serve con `errors with` cuya página de error LEE el archivo (lo que la ruta lee), y
/// rutas que gastan (`spend`) y renderizan (`render` → `file.read`): las tres capabilities
/// las declara el programa; el token del caller decide.
fn start_server(port: u16, dir: &str) -> String {
    let prog = format!(
        r##"require serve({p})
require random
require time
require file.read("{d}/*")
require file.read("tests/fixtures/*")
require spend("USD")

let root be "root-key-r2"

task check_agent(token, request)
    give captoken_verify(token, root, {{"aud": "r2"}})

task error_page(status, message, request)
    give html("<h1>" + text(status) + "</h1><pre>" + read_file("{d}/note.txt") + "</pre>")

serve on {p}
    auth with check_agent
    errors with error_page

    route "GET /tokens"
        let net_only be captoken_mint({{"net": "api.example.com"}}, root, {{"aud": "r2", "ttl": 600, "id": "agent-net"}})
        let with_file be captoken_mint({{"file.read": ["{d}/*", "tests/fixtures/*"]}}, root, {{"aud": "r2", "ttl": 600, "id": "agent-file"}})
        let with_spend be captoken_mint({{"spend": "USD"}}, root, {{"aud": "r2", "ttl": 600, "id": "agent-spend", "spend": {{"USD": 10}}}})
        give {{"net_only": net_only, "with_file": with_file, "with_spend": with_spend}}

    route "GET /read" requires auth
        give {{"content": read_file("{d}/note.txt")}}

    route "GET /spend" requires auth
        give {{"total": spend(1, "USD", "probe")}}

    route "GET /render" requires auth
        give render("tests/fixtures/identity_r2_tpl.html", {{"x": 1}})
"##,
        p = port,
        d = dir
    );
    thread::spawn(move || {
        let r = run_serve_program(&prog, "identity_round2_e2e.syn", false);
        eprintln!("serve ended: success={} errors={:?}", r.success, r.errors);
    });
    wait_ready(port);
    request(port, "GET", "/tokens", &[])
}

#[test]
fn the_error_page_runs_under_the_callers_ceiling_and_the_gates_keep_the_cause() {
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "1");
    let port = free_port();
    let dir = scratch_dir("serve");
    let tokens = start_server(port, &dir);
    let net_only = field(&tokens, "net_only");
    let with_file = field(&tokens, "with_file");
    let with_spend = field(&tokens, "with_spend");
    let bearer = |t: &str| format!("Bearer {}", t);

    // 1) Ruta denegada por el token → 403; la página de error NO puede leer el archivo bajo
    //    el mismo token, así que el cuerpo es el JSON fijo y jamás el contenido.
    let r = request(port, "GET", "/read", &[("Authorization", &bearer(&net_only))]);
    assert_eq!(status(&r), 403, "{}", r);
    let body = body_of(&r);
    assert!(!body.contains("hello from the file"), "la página de error escaló el techo: {}", body);
    assert!(body.contains("insufficient permissions"), "{}", body);

    // 2) La misma página de error, con un token que SÍ delega file.read (un 404 cualquiera):
    //    corre bajo ese sujeto y lee. Es la prueba de que el sujeto se aplica, no de que el
    //    error path esté capado.
    let r = request(port, "GET", "/does-not-exist", &[("Authorization", &bearer(&with_file))]);
    assert_eq!(status(&r), 404, "{}", r);
    assert!(body_of(&r).contains("hello from the file"), "{}", r);

    // 3) `spend` denegado por el token → 403 fijo, no un 500 con "add `require spend`".
    let r = request(port, "GET", "/spend", &[("Authorization", &bearer(&net_only))]);
    assert_eq!(status(&r), 403, "{}", r);
    let body = body_of(&r);
    assert!(!body.contains("require") && !body.contains("USD") && !body.contains("agent-net"), "{}", body);
    // …y con un token que lo delega, gasta.
    let r = request(port, "GET", "/spend", &[("Authorization", &bearer(&with_spend))]);
    assert_eq!(status(&r), 200, "{}", r);

    // 4) `render` (file.read del template) denegado por el token → 403 fijo, sin el id del
    //    token, la capability ni la ruta del template.
    let r = request(port, "GET", "/render", &[("Authorization", &bearer(&net_only))]);
    assert_eq!(status(&r), 403, "{}", r);
    let body = body_of(&r);
    assert!(!body.contains("agent-net") && !body.contains("file.read") && !body.contains("identity_r2_tpl"), "{}", body);
    let r = request(port, "GET", "/render", &[("Authorization", &bearer(&with_file))]);
    assert_eq!(status(&r), 200, "{}", r);
    assert!(body_of(&r).contains("<p>1</p>"), "{}", r);
}

#[test]
fn the_operator_identity_comes_from_dot_env_too() {
    let dir = scratch_dir("env");
    let env_file = format!("{}/.env", dir);
    std::fs::write(&env_file, "SYNSEMA_IDENTITY=alice-from-dotenv\n").unwrap();
    std::env::remove_var("SYNSEMA_IDENTITY");
    std::env::set_var("SYNSEMA_ENV_FILE", &env_file);
    let r = run_program("print(\"id: \" + text(receipt()[\"credentialSubject\"][\"id\"]))", "operator_env.syn");
    std::env::remove_var("SYNSEMA_ENV_FILE");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("id: alice-from-dotenv"), "{}", out);
}
