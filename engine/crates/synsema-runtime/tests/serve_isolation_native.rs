//! Aislamiento de las globales entre requests con el NIVEL NATIVO instalado (como lo corre el CLI;
//! `serve_isolation.rs` corre sin él). Archivo aparte porque instalar el nivel es global al proceso.
//!
//! Los bucles calientes de un handler escriben en globales por las vías en el lugar de la VM y del
//! JIT (`append`, `set` con camino, texto que crece, contadores): nada de eso puede llegar a la
//! request siguiente. El test exige que los bucles hayan corrido en nativo: si no, no prueba nada
//! (desde v0.6.39 el cuerpo de una ruta corre en la VM y sus bucles suben a nativo; antes, en el
//! tree-walker, este test no podía pasar).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn get(port: u16, target: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

#[test]
fn native_loops_do_not_leak_writes_to_globals() {
    synsema_jit::install();
    synsema_core::native_tier::set_eager(true);
    let before = synsema_core::native_tier::stats();

    let port = free_port();
    let prog = format!(
        r#"require serve({p})
let rows be [{{"id": 1, "name": "orig"}}]
let tags be ["a"]
let nums be [0]
let cfg be {{"limits": [1, 2]}}
let trail be "t"
let counter be 0
serve on {p}
    route "GET /hot"
        each i in range(0, 5000)
            set tags to append(tags, "x")
            set nums to append(nums, i)
            set rows[0].name to "hot"
            set cfg.limits[1] to i
            set trail to trail + "."
            set counter to counter + 1
        give {{"t": length(tags), "n": length(nums), "c": counter, "l": length(trail), "k": cfg.limits[1], "r": rows[0].name}}
    route "GET /get"
        give {{"t": length(tags), "n": length(nums), "c": counter, "l": length(trail), "k": cfg.limits[1], "r": rows[0].name}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_isolation_native.syn", false);
    });
    let mut up = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "el server no quedó listo en :{}", port);

    let original = r#"{"t": 1, "n": 1, "c": 0, "l": 1, "k": 2, "r": "orig"}"#;
    let hot = r#"{"t": 5001, "n": 5001, "c": 5000, "l": 5001, "k": 4999, "r": "hot"}"#;
    for round in 0..8 {
        assert_eq!(get(port, "/hot"), hot, "ronda {}", round);
        assert_eq!(get(port, "/get"), original, "ronda {}", round);
    }
    let after = synsema_core::native_tier::stats();
    assert!(
        after.osr > before.osr,
        "los bucles del handler no entraron a código nativo (osr {} → {}; units {} → {}, entries {} → {}, deopts {} → {}): el test no prueba las vías del JIT",
        before.osr,
        after.osr,
        before.units,
        after.units,
        before.entries,
        after.entries,
        before.deopts,
        after.deopts
    );
}

/// Un bucle de un handler que lee una global se compila encontrándola un entorno arriba (en el
/// global). Si en otra request el mismo cuerpo define antes un nombre igual en su scope, la VM lo
/// encuentra primero: el código nativo no puede seguir leyendo la global.
#[test]
fn native_loops_follow_a_name_the_request_shadows() {
    synsema_jit::install();
    synsema_core::native_tier::set_eager(true);
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
let x be 1
serve on {p}
    route "GET /sum"
        let total be 0
        when get(query, "shadow", "0") == "1"
            let x be 100
        each i in range(0, 5000)
            set total to total + x
        give {{"t": total}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_isolation_shadow.syn", false);
    });
    let mut up = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "el server no quedó listo en :{}", port);
    let before = synsema_core::native_tier::stats();
    for round in 0..6 {
        assert_eq!(get(port, "/sum"), r#"{"t": 5000}"#, "ronda {} sin sombra", round);
        assert_eq!(get(port, "/sum?shadow=1"), r#"{"t": 500000}"#, "ronda {} con sombra", round);
    }
    let after = synsema_core::native_tier::stats();
    assert!(after.osr > before.osr, "el bucle no entró a código nativo: el test no prueba nada");
}
