//! v0.6.45 (A3): cuando el otro lado de un WebSocket o de un TCP se va sin despedirse (RST: el
//! proceso murió, la red cayó; en Windows `os error 10054`), `select` lanzaba
//! `select: connection N: IO error: …` y cortaba la espera de TODAS las conexiones. Ahora esa
//! conexión llega como `{type: "close", reason: "connection reset by peer"}` y las demás siguen.
//!
//! El RST se fuerza de forma portable: el servidor cierra el socket con datos SIN LEER en su buffer
//! de recepción (Windows y Linux contestan con RST en vez de FIN).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_program;

/// Acepta una conexión, espera a que el cliente mande algo, y la cierra sin leerlo (RST).
fn resetting_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(300)); // lo que mande el cliente queda sin leer
            drop(sock);
        }
    });
    port
}

/// Acepta una conexión y le manda "tarde" después de un rato.
fn late_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(900));
            let _ = sock.write_all(b"tarde");
            thread::sleep(Duration::from_millis(2000));
        }
    });
    port
}

/// Un WebSocket que hace el handshake, espera el primer mensaje del cliente sin leerlo y corta.
fn resetting_ws_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(ws) = tungstenite::accept(stream) {
                thread::sleep(Duration::from_millis(300));
                drop(ws); // sin frame de cierre, con el mensaje del cliente sin leer: RST
            }
        }
    });
    port
}

#[test]
fn a_reset_tcp_peer_is_a_close_and_the_other_connections_keep_going() {
    let gone = resetting_server();
    let late = late_server();
    let src = format!(
        r#"require net("127.0.0.1:{gone}")
require net("127.0.0.1:{late}")
let a be tcp_connect("127.0.0.1", {gone})
let b be tcp_connect("127.0.0.1", {late})
tcp_send(a, "esto queda sin leer")
let first be select({{"a": a, "b": b}}, 5)
print(first["name"])
print(first["type"])
print(first["reason"])
let second be select({{"b": b}}, 5)
print(second["name"])
print(second["type"])
let failed be "no"
try
    tcp_send(a, "otra vez")
recover e
    set failed to "si"
print(failed)
"#
    );
    let r = run_program(&src, "<a3-tcp>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["a", "close", "connection reset by peer", "b", "data", "si"], "{:?}", r.output);
}

#[test]
fn a_reset_websocket_peer_is_a_close_not_an_error() {
    let port = resetting_ws_server();
    let src = format!(
        r#"require net("127.0.0.1:{port}")
let w be ws_connect("ws://127.0.0.1:{port}/")
ws_send(w, "esto queda sin leer")
let ev be select({{"w": w}}, 5)
print(ev["name"])
print(ev["type"])
"#
    );
    let r = run_program(&src, "<a3-ws>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["w", "close"], "{:?}", r.output);
}
