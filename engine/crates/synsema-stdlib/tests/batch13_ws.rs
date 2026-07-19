//! Cliente WebSocket (Batch 13, alcance B) — dogfood contra un servidor WS LOCAL
//! (tungstenite `accept` en un thread del harness), SIN red externa:
//! connect/send/recv round-trip, timeout → `nothing`, close limpio, headers
//! custom, límite anti-DoS de tamaño de mensaje, y el gate G21 (`net(host)`
//! deny-by-default, mismo scope que http_*).

use std::cell::RefCell;
use std::net::TcpListener;
use std::rc::Rc;
use std::thread;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_bytes, syn_int, syn_map, syn_text, SynValue};
use synsema_stdlib::ws::register_ws_builtins;

/// Servidor WS local de eco en un thread: acepta `conns` conexiones; a cada una
/// le responde eco de text/binary hasta el close. Devuelve el puerto.
fn echo_server(conns: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..conns {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            thread::spawn(move || {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                loop {
                    match ws.read() {
                        Ok(msg @ tungstenite::Message::Text(_))
                        | Ok(msg @ tungstenite::Message::Binary(_)) => {
                            if ws.send(msg).is_err() {
                                return;
                            }
                        }
                        Ok(tungstenite::Message::Close(_)) | Err(_) => return,
                        Ok(_) => continue,
                    }
                }
            });
        }
    });
    port
}

fn interp_with_net(host_scope: Option<&str>) -> Interpreter {
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    if let Some(h) = host_scope {
        caps.borrow_mut().grant(Capability::new(CapabilityType::Net, Some(h.to_string())));
    }
    register_ws_builtins(&interp, caps);
    interp
}

fn call(interp: &mut Interpreter, name: &str, args: Vec<SynValue>) -> Result<SynValue, Control> {
    let f = interp
        .global_env
        .borrow()
        .bindings
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("builtin {} no registrado", name));
    interp.call_task(f, args)
}

fn ok(r: Result<SynValue, Control>) -> SynValue {
    match r {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn err_msg(r: Result<SynValue, Control>) -> String {
    match r {
        Err(Control::Error(e)) => e.message,
        Ok(v) => panic!("esperaba error, obtuve {}", v.type_name()),
        Err(_) => panic!("control inesperado"),
    }
}

/// Extrae ("type", "data") de un mensaje de ws_recv.
fn msg_parts(v: SynValue) -> (String, SynValue) {
    match v {
        SynValue::Map(m) => {
            let m = m.borrow();
            let ty = match m.get("type") {
                Some(SynValue::Text(t)) => t.to_string(),
                other => panic!("type debía ser text: {:?}", other.map(|v| v.type_name())),
            };
            (ty, m.get("data").cloned().unwrap_or(SynValue::Nothing))
        }
        other => panic!("esperaba map de mensaje, got {}", other.type_name()),
    }
}

#[test]
fn ws_roundtrip_text_binary_timeout_and_close() {
    let port = echo_server(1);
    let mut i = interp_with_net(Some("127.0.0.1"));
    let conn = ok(call(&mut i, "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/feed", port).as_str())]));
    assert!(matches!(conn, SynValue::Number(_)), "el handle es un entero opaco");

    // Texto: eco.
    ok(call(&mut i, "ws_send", vec![conn.clone(), syn_text("hola synsema")]));
    let (ty, data) = msg_parts(ok(call(&mut i, "ws_recv", vec![conn.clone()])));
    assert_eq!(ty, "text");
    assert_eq!(data.to_string(), "hola synsema");

    // Binario: eco fiel byte a byte.
    ok(call(&mut i, "ws_send", vec![conn.clone(), syn_bytes(vec![0, 159, 146, 150])]));
    let (ty, data) = msg_parts(ok(call(&mut i, "ws_recv", vec![conn.clone()])));
    assert_eq!(ty, "binary");
    match data {
        SynValue::Bytes(b) => assert_eq!(&b[..], &[0, 159, 146, 150]),
        other => panic!("data binaria debía ser bytes, got {}", other.type_name()),
    }

    // Timeout corto sin tráfico → nothing (jamás cuelga).
    let t0 = std::time::Instant::now();
    let r = ok(call(&mut i, "ws_recv",
        vec![conn.clone(), SynValue::Number(synsema_core::number::Number::Float(0.3))]));
    assert!(matches!(r, SynValue::Nothing), "timeout devuelve nothing");
    assert!(t0.elapsed() < std::time::Duration::from_secs(5), "y vuelve a tiempo");

    // Close limpio e idempotente; el handle muere.
    ok(call(&mut i, "ws_close", vec![conn.clone()]));
    ok(call(&mut i, "ws_close", vec![conn.clone()])); // no-op
    let e = err_msg(call(&mut i, "ws_send", vec![conn, syn_text("tarde")]));
    assert!(e.contains("unknown or closed"), "{}", e);
}

#[test]
fn ws_gate_g21_denies_without_net_and_respects_scope() {
    let port = echo_server(1);
    // Sin `net` en absoluto → deny-by-default con el fix sugerido.
    let mut i = interp_with_net(None);
    let e = err_msg(call(&mut i, "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", port).as_str())]));
    assert!(e.contains("net"), "la denegación nombra la capability: {}", e);
    // Con net de OTRO host → el scope no cubre y deniega (mismo criterio que http_*).
    let mut i2 = interp_with_net(Some("api.example.com"));
    let e2 = err_msg(call(&mut i2, "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", port).as_str())]));
    assert!(e2.contains("net"), "{}", e2);
    // El host correcto sí conecta (misma semántica de scope por hostname).
    let mut i3 = interp_with_net(Some("127.0.0.1"));
    ok(call(&mut i3, "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", port).as_str())]));
}

// El callback de tungstenite devuelve Result<Response, ErrorResponse> — ambas
// variantes son grandes por diseño del crate; no está en nuestras manos achicarlo.
#[allow(clippy::result_large_err)]
#[test]
fn ws_custom_headers_reach_the_server() {
    // Server que valida el header y responde con su valor.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let got: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
        let got2 = got.clone();
        let cb = move |req: &tungstenite::handshake::server::Request,
                       resp: tungstenite::handshake::server::Response| {
            if let Some(v) = req.headers().get("x-api-key") {
                *got2.borrow_mut() = v.to_str().unwrap_or("").to_string();
            }
            Ok(resp)
        };
        let mut ws = tungstenite::accept_hdr(stream, cb).expect("handshake");
        let _ = ws.send(tungstenite::Message::text(got.borrow().clone()));
    });
    let mut i = interp_with_net(Some("127.0.0.1"));
    let mut headers = indexmap::IndexMap::new();
    headers.insert("X-Api-Key".to_string(), syn_text("s3cr3t-key"));
    let conn = ok(call(&mut i, "ws_connect", vec![
        syn_text(format!("ws://127.0.0.1:{}/", port).as_str()),
        syn_map(headers),
    ]));
    let (ty, data) = msg_parts(ok(call(&mut i, "ws_recv", vec![conn])));
    assert_eq!(ty, "text");
    assert_eq!(data.to_string(), "s3cr3t-key", "el header custom llegó al server");
}

#[test]
fn ws_max_message_size_is_enforced() {
    // El server manda 1 KiB; el cliente se acota a 64 bytes → error atrapable
    // (Capacity), no un buffer sin límite.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut ws = tungstenite::accept(stream).expect("handshake");
        let _ = ws.send(tungstenite::Message::text("x".repeat(1024)));
        // mantener viva la conexión un momento
        let _ = ws.read();
    });
    let mut i = interp_with_net(Some("127.0.0.1"));
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_message_size".to_string(), syn_int(64));
    let conn = ok(call(&mut i, "ws_connect", vec![
        syn_text(format!("ws://127.0.0.1:{}/", port).as_str()),
        SynValue::Nothing,
        syn_map(opts),
    ]));
    let e = err_msg(call(&mut i, "ws_recv", vec![conn]));
    assert!(e.contains("size limit") || e.contains("Capacity") || e.contains("too long"),
        "el límite corta el mensaje: {}", e);
}

#[test]
fn ws_connect_refused_and_bad_scheme_error_clearly() {
    let mut i = interp_with_net(Some("127.0.0.1"));
    // Puerto sin listener → error de conexión atrapable (rápido).
    let e = err_msg(call(&mut i, "ws_connect", vec![syn_text("ws://127.0.0.1:1/")]));
    assert!(e.contains("cannot connect"), "{}", e);
    // Scheme http → error dirigido a ws://.
    let mut i2 = interp_with_net(Some("example.com"));
    let e2 = err_msg(call(&mut i2, "ws_connect", vec![syn_text("http://example.com/")]));
    assert!(e2.contains("ws://"), "{}", e2);
    // Handle inventado → error claro en send/recv.
    let e3 = err_msg(call(&mut i, "ws_recv", vec![syn_int(9999)]));
    assert!(e3.contains("unknown or closed"), "{}", e3);
}
