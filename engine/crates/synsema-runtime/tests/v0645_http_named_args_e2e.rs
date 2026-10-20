//! v0.6.45 (B8): los builtins HTTP aceptan argumentos con nombre. Un mapa de opciones habría sido
//! ambiguo (el argumento siguiente ya es un mapa: los headers, o un body JSON); los nombres no.
//! La forma posicional sigue andando (sale en v1 del tercer opcional en adelante).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use synsema_runtime::engine::run_program;

/// Contesta con lo que recibió: el método, la ruta, el header `X-T` y el body.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("").to_string();
                let xt = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("x-t:"))
                    .map(|l| l[4..].trim().to_string())
                    .unwrap_or_default();
                let body = req.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
                let out = format!("{} | {} | {}", first, xt, body);
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", out.len(), out);
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn http_builtins_take_named_arguments() {
    let p = echo_server();
    let src = format!(
        r#"require net("127.0.0.1:{p}")
let u be "http://127.0.0.1:{p}"
print(http_get(u + "/a", timeout = 5)["body"])
print(http_get(u + "/b", query = {{"q": "x y"}}, headers = {{"X-T": "1"}})["body"])
print(http_post(u + "/c", {{"a": 1}}, headers = {{"X-T": "2"}}, timeout = 5)["body"])
print(http(method = "PUT", url = u + "/d", body = "hola")["body"])
print(http_get(u + "/e", {{"X-T": "3"}}, {{"k": "v"}}, 5)["body"])
let e1 be "ok"
try
    http_get(u, tiemout = 5)
recover e
    set e1 to e
print(e1)
let e2 be "ok"
try
    http_get(u, {{}}, headers = {{}})
recover e
    set e2 to e
print(e2)
"#
    );
    let r = run_program(&src, "<b8>");
    assert!(r.success, "{:?}", r.errors);
    let o = &r.output;
    assert!(o[0].starts_with("GET /a HTTP/1.1 |  |"), "{}", o[0]);
    assert!(o[1].starts_with("GET /b?q=x+y HTTP/1.1 | 1 |") || o[1].starts_with("GET /b?q=x%20y HTTP/1.1 | 1 |"), "{}", o[1]);
    assert!(o[2].starts_with("POST /c HTTP/1.1 | 2 | {\"a\":1}") || o[2].contains("| 2 | {\"a\": 1}"), "{}", o[2]);
    assert!(o[3].starts_with("PUT /d HTTP/1.1 |  | hola"), "{}", o[3]);
    assert!(o[4].starts_with("GET /e?k=v HTTP/1.1 | 3 |"), "la forma posicional sigue: {}", o[4]);
    assert!(o[5].contains("tiemout"), "un nombre desconocido es error: {}", o[5]);
    assert!(o[6].contains("duplicate argument 'headers'"), "por posición y por nombre a la vez: {}", o[6]);
}
