//! v0.6.45 (A8): `state_merge` y `state_cas` atómicos bajo `serve`. El caso real: 13 webhooks
//! simultáneos que hacían leer-modificar-guardar sobre un mismo mapa con `state_get`/`state_set`
//! dejaron 7 entradas y perdieron 6 en silencio.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or(out);
    // Un texto viaja como JSON: se compara su contenido.
    body.trim().trim_matches('"').to_string()
}

fn start(port: u16) {
    let src = format!(
        r#"require serve({port})
require time

serve on {port}
    route "POST /hook/:id"
        let patch be {{}}
        set patch[params.id] to true
        sleep(0.05)
        state_merge("canales", patch)
        give "ok"
    route "GET /count"
        give text(length(keys(state_get("canales", {{}}))))
    route "POST /cas"
        let first be state_cas("version", nothing, 1)
        let stale be state_cas("version", nothing, 2)
        let next be state_cas("version", 1, 2)
        let as_float be state_cas("version", 2.0, 3)
        give `{{first}} {{stale}} {{next}} {{as_float}} {{state_get("version")}}`
    route "POST /bad"
        state_set("n", 5)
        let failed be "no"
        try
            state_merge("n", {{"a": 1}})
        recover e
            set failed to "si"
        give failed
"#
    );
    thread::spawn(move || {
        let _ = run_serve_program(&src, "a8.syn", false);
    });
    for _ in 0..150 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo");
}

#[test]
fn state_merge_keeps_every_concurrent_write_and_state_cas_compares_like_the_language() {
    let port = free_port();
    start(port);
    let hooks: Vec<_> = (0..13)
        .map(|i| thread::spawn(move || request(port, "POST", &format!("/hook/c{i}"))))
        .collect();
    for h in hooks {
        assert_eq!(h.join().unwrap(), "ok");
    }
    assert_eq!(request(port, "GET", "/count"), "13", "se perdieron escrituras concurrentes");
    // Ausente == nothing; el segundo pierde; 1 → 2; `2.0` es igual a `2` como en el lenguaje.
    assert_eq!(request(port, "POST", "/cas"), "true false true true 3");
    // Mezclar sobre algo que no es un mapa es error, no un pisado silencioso.
    assert_eq!(request(port, "POST", "/bad"), "si");
}
