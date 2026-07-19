//! WebSocket de primera clase (Batch 15) — multiplexado, backpressure, subprotocolos
//! y tope de conexiones, contra servidores WS LOCALES (tungstenite `accept` en
//! threads del harness), SIN red externa. La reconexión, el keepalive/half-open y el
//! patrón `parallel_map` se prueban por el runtime real en `batch15_e2e.rs` (necesitan
//! definir tasks Synsema).
//!
//! Foco de G25 (no busy-spin) medido con el contador `POLL_ITERS`: una espera ociosa
//! de `ws_select` hace UNA sola iteración de `mio::Poll` (duerme en el kernel, CPU ~0).

use std::cell::RefCell;
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_int, syn_map, syn_text, SynValue};
use synsema_stdlib::ws::{register_ws_builtins, POLL_ITERS};

/// Serializa los tests del archivo: el test de tope usa el env global
/// `SYNSEMA_WS_MAX_CONNS`, que se filtraría a los demás si corrieran en paralelo.
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn interp_net() -> Interpreter {
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Net, Some("127.0.0.1".to_string())));
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

fn map_get(v: &SynValue, key: &str) -> SynValue {
    match v {
        SynValue::Map(m) => m.borrow().get(key).cloned().unwrap_or(SynValue::Nothing),
        _ => panic!("esperaba map"),
    }
}

fn as_i64(v: &SynValue) -> i64 {
    match v {
        SynValue::Number(n) => n.to_i64_trunc().unwrap(),
        _ => panic!("esperaba número, got {}", v.type_name()),
    }
}

/// Un server que hace el handshake y luego llama a `serve(ws)` en un thread.
fn ws_server(serve: impl Fn(&mut tungstenite::WebSocket<std::net::TcpStream>) + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let serve = std::sync::Arc::new(serve);
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let serve = serve.clone();
            thread::spawn(move || {
                if let Ok(mut ws) = tungstenite::accept(stream) {
                    serve(&mut ws);
                }
            });
        }
    });
    port
}

// =========================================================
// ws_select: cuál conexión disparó + equidad
// =========================================================

#[test]
fn ws_select_reports_which_conn_fired() {
    let _g = serial();
    // Dos servers de eco.
    let echo = |ws: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
        match ws.read() {
            Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                if ws.send(m).is_err() {
                    return;
                }
            }
            _ => return,
        }
    };
    let p1 = ws_server(echo);
    let p2 = ws_server(echo);
    let mut i = interp_net();
    let c1 = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p1).as_str())])));
    let c2 = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p2).as_str())])));
    // Mandar sólo por c2 → ws_select debe devolver c2.
    ok(call(&mut i, "ws_send", vec![syn_int(c2), syn_text("hola")]));
    let conns = SynValue::List(Rc::new(RefCell::new(vec![syn_int(c1), syn_int(c2)])));
    let sel = ok(call(&mut i, "ws_select", vec![conns, syn_int(5)]));
    assert_eq!(as_i64(&map_get(&sel, "conn")), c2, "ws_select devuelve CUÁL disparó");
    assert_eq!(map_get(&sel, "type").to_string(), "text");
    assert_eq!(map_get(&sel, "data").to_string(), "hola");
}

#[test]
fn ws_select_by_name_map_tags_name() {
    let _g = serial();
    let echo = |ws: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
        match ws.read() {
            Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                if ws.send(m).is_err() {
                    return;
                }
            }
            _ => return,
        }
    };
    let p = ws_server(echo);
    let mut i = interp_net();
    let c = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str())])));
    ok(call(&mut i, "ws_send", vec![syn_int(c), syn_text("ping")]));
    let mut names = indexmap::IndexMap::new();
    names.insert("trades".to_string(), syn_int(c));
    let sel = ok(call(&mut i, "ws_select", vec![syn_map(names), syn_int(5)]));
    assert_eq!(map_get(&sel, "name").to_string(), "trades", "un map nombre→handle etiqueta el nombre");
    assert_eq!(as_i64(&map_get(&sel, "conn")), c);
}

// =========================================================
// G25: ws_select ocioso NO busy-spinea (POLL_ITERS)
// =========================================================

#[test]
fn ws_select_idle_sleeps_no_busy_spin() {
    let _g = serial();
    // Server que acepta y no manda nada (feed ocioso).
    let p = ws_server(|ws| {
        // sostener la conexión sin enviar; leer para procesar el close eventual
        loop {
            match ws.read() {
                Ok(tungstenite::Message::Close(_)) | Err(_) => return,
                _ => {}
            }
        }
    });
    let mut i = interp_net();
    let c = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str())])));
    let before = POLL_ITERS.with(|x| x.get());
    let start = Instant::now();
    let conns = SynValue::List(Rc::new(RefCell::new(vec![syn_int(c)])));
    let sel = ok(call(&mut i, "ws_select", vec![conns, syn_int(1)]));
    let elapsed = start.elapsed();
    let iters = POLL_ITERS.with(|x| x.get()) - before;
    assert!(matches!(sel, SynValue::Nothing), "sin datos → nothing al vencer");
    // Durmió ~1s en el kernel, no giró en vacío.
    assert!(elapsed >= Duration::from_millis(800), "debe DORMIR el timeout, no volver ya: {:?}", elapsed);
    // Un puñado de iteraciones de poll (no miles): readiness-driven, CPU ~0.
    assert!(iters <= 3, "espera ociosa debe hacer ~1 iteración de poll, hizo {}", iters);
}

// =========================================================
// Equidad: rotación round-robin — un feed parlanchín no hambrea al resto
// =========================================================

#[test]
fn ws_select_round_robin_no_starvation() {
    let _g = serial();
    let echo = |ws: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
        match ws.read() {
            Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                if ws.send(m).is_err() {
                    return;
                }
            }
            _ => return,
        }
    };
    let p1 = ws_server(echo);
    let p2 = ws_server(echo);
    let mut i = interp_net();
    let c1 = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p1).as_str())])));
    let c2 = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p2).as_str())])));
    // c1 acumula backlog (3 mensajes), c2 tiene 1. Sin rotación, los primeros 3
    // selects devolverían SIEMPRE c1 (c2 hambreado mientras c1 tenga cola).
    for _ in 0..3 {
        ok(call(&mut i, "ws_send", vec![syn_int(c1), syn_text("a")]));
    }
    ok(call(&mut i, "ws_send", vec![syn_int(c2), syn_text("b")]));
    // Esperar a que TODO esté encolado (ticks no-bloqueantes vía ws_status).
    let start = Instant::now();
    loop {
        ok(call(&mut i, "ws_status", vec![syn_int(c1)]));
        let q1 = as_i64(&map_get(&ok(call(&mut i, "ws_stats", vec![syn_int(c1)])), "queued"));
        let q2 = as_i64(&map_get(&ok(call(&mut i, "ws_stats", vec![syn_int(c2)])), "queued"));
        if (q1 >= 3 && q2 >= 1) || start.elapsed() > Duration::from_secs(10) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let conns = SynValue::List(Rc::new(RefCell::new(vec![syn_int(c1), syn_int(c2)])));
    let s1 = as_i64(&map_get(&ok(call(&mut i, "ws_select", vec![conns.clone(), syn_int(5)])), "conn"));
    let s2 = as_i64(&map_get(&ok(call(&mut i, "ws_select", vec![conns.clone(), syn_int(5)])), "conn"));
    let seen: std::collections::HashSet<i64> = [s1, s2].into_iter().collect();
    assert!(
        seen.contains(&c2),
        "equidad: con backlog en c1, c2 debe salir dentro de los primeros 2 selects (salieron {:?})",
        (s1, s2)
    );
}

// =========================================================
// Escala: ws_select sobre 1000 conexiones a la vez (spec §9)
// =========================================================

#[test]
fn ws_select_over_many_connections() {
    let _g = serial();
    // UN server de eco local; 1000 conexiones multiplexadas en un solo thread.
    let echo = |ws: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
        match ws.read() {
            Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                if ws.send(m).is_err() {
                    return;
                }
            }
            _ => return,
        }
    };
    const N: usize = 1000;
    let p = ws_server(echo);
    let mut i = interp_net();
    let mut handles = Vec::new();
    for _ in 0..N {
        let c = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str())])));
        handles.push(c);
    }
    // Mandar en todos; recibir de todos vía ws_select (event-loop de N feeds en 1 thread).
    for &c in &handles {
        ok(call(&mut i, "ws_send", vec![syn_int(c), syn_text(format!("m{}", c).as_str())]));
    }
    let conns = SynValue::List(Rc::new(RefCell::new(handles.iter().map(|&c| syn_int(c)).collect())));
    let mut seen = std::collections::HashSet::new();
    let start = Instant::now();
    while seen.len() < N && start.elapsed() < Duration::from_secs(30) {
        let sel = ok(call(&mut i, "ws_select", vec![conns.clone(), syn_int(5)]));
        if let SynValue::Map(_) = sel {
            seen.insert(as_i64(&map_get(&sel, "conn")));
        }
    }
    assert_eq!(seen.len(), N, "los {} feeds se multiplexaron en un solo thread", N);
}

// =========================================================
// G26: backpressure — la cola inbound se acota (política block)
// =========================================================

#[test]
fn ws_backpressure_bounds_the_inbound_queue() {
    let _g = serial();
    // Server que inunda con muchos mensajes chicos sin parar.
    let p = ws_server(|ws| {
        for n in 0..100_000u64 {
            if ws.send(tungstenite::Message::text(format!("{}", n))).is_err() {
                return;
            }
        }
        // seguir vivo
        loop {
            if ws.read().is_err() {
                return;
            }
        }
    });
    let mut i = interp_net();
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_queue".to_string(), syn_int(16));
    // política por default = block (backpressure TCP): jamás supera max_queue.
    let c = as_i64(&ok(call(
        &mut i,
        "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str()), SynValue::Nothing, syn_map(opts)],
    )));
    // Tickear el pump varias veces SIN drenar (ws_status hace un tick no-bloqueante).
    for _ in 0..5 {
        ok(call(&mut i, "ws_status", vec![syn_int(c)]));
        thread::sleep(Duration::from_millis(20));
    }
    let stats = ok(call(&mut i, "ws_stats", vec![syn_int(c)]));
    let queued = as_i64(&map_get(&stats, "queued"));
    assert!(queued <= 16, "backpressure acota la cola a max_queue, quedó {}", queued);
    assert!(queued > 0, "pero SÍ leyó algo antes de frenar: {}", queued);
    ok(call(&mut i, "ws_close", vec![syn_int(c)]));
}

// =========================================================
// G26: la cota vale también en BYTES (frames grandes, no sólo cantidad)
// =========================================================

#[test]
fn ws_backpressure_bounds_bytes_not_just_count() {
    let _g = serial();
    // Frames GRANDES (100 KiB): con cota sólo por cantidad, 1000 frames serían
    // ~100 MiB encolados. max_queue alto a propósito — la que frena es la de bytes.
    let p = ws_server(|ws| {
        let big = "x".repeat(100 * 1024);
        for _ in 0..1000 {
            if ws.send(tungstenite::Message::text(big.clone())).is_err() {
                return;
            }
        }
        loop {
            if ws.read().is_err() {
                return;
            }
        }
    });
    let mut i = interp_net();
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_queue".to_string(), syn_int(1000));
    opts.insert("max_queue_bytes".to_string(), syn_int(300 * 1024));
    let c = as_i64(&ok(call(
        &mut i,
        "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str()), SynValue::Nothing, syn_map(opts)],
    )));
    for _ in 0..5 {
        ok(call(&mut i, "ws_status", vec![syn_int(c)]));
        thread::sleep(Duration::from_millis(20));
    }
    let stats = ok(call(&mut i, "ws_stats", vec![syn_int(c)]));
    let queued_bytes = as_i64(&map_get(&stats, "queued_bytes"));
    // Cota: max_queue_bytes + a lo sumo un frame de gracia (se pausa al alcanzarla).
    assert!(
        queued_bytes <= (300 + 100) * 1024,
        "la cota en bytes debe frenar los frames grandes, quedaron {} bytes",
        queued_bytes
    );
    assert!(queued_bytes > 0, "pero SÍ leyó algo antes de frenar");
    ok(call(&mut i, "ws_close", vec![syn_int(c)]));
}

// =========================================================
// on_full: "error" es un ERROR atrapable (jamás descarte silencioso);
// "drop_oldest" conserva los más nuevos
// =========================================================

#[test]
fn ws_on_full_error_surfaces_catchable_never_silent_drop() {
    let _g = serial();
    let p = ws_server(|ws| {
        for n in 0..10_000u64 {
            if ws.send(tungstenite::Message::text(format!("{}", n))).is_err() {
                return;
            }
        }
        loop {
            if ws.read().is_err() {
                return;
            }
        }
    });
    let mut i = interp_net();
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_queue".to_string(), syn_int(4));
    opts.insert("on_full".to_string(), syn_text("error"));
    let c = as_i64(&ok(call(
        &mut i,
        "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str()), SynValue::Nothing, syn_map(opts)],
    )));
    // Drenar: los ≤4 encolados salen, y DESPUÉS el overflow emerge como error
    // atrapable con mensaje claro — nunca un stream que sigue "andando" con hoyos.
    let mut drained = 0;
    let e = loop {
        match call(&mut i, "ws_recv", vec![syn_int(c), syn_int(2)]) {
            Ok(SynValue::Map(_)) => {
                drained += 1;
                assert!(drained <= 4, "con max_queue 4 no pueden salir más de 4 mensajes antes del error");
            }
            Ok(_) => panic!("no debe devolver nothing: el overflow debe ERROREAR"),
            Err(Control::Error(e)) => break e.message,
            Err(_) => panic!("control inesperado"),
        }
    };
    assert!(e.contains("overflowed"), "el error debe nombrar el overflow: {}", e);
}

#[test]
fn ws_on_full_drop_oldest_keeps_newest() {
    let _g = serial();
    let p = ws_server(|ws| {
        for n in 0..100u64 {
            if ws.send(tungstenite::Message::text(format!("{}", n))).is_err() {
                return;
            }
        }
        loop {
            if ws.read().is_err() {
                return;
            }
        }
    });
    let mut i = interp_net();
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_queue".to_string(), syn_int(8));
    opts.insert("on_full".to_string(), syn_text("drop_oldest"));
    let c = as_i64(&ok(call(
        &mut i,
        "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str()), SynValue::Nothing, syn_map(opts)],
    )));
    // Con drop_oldest la lectura NO se pausa: se leen los 100 y quedan los últimos 8.
    let start = Instant::now();
    loop {
        ok(call(&mut i, "ws_status", vec![syn_int(c)]));
        let received = as_i64(&map_get(&ok(call(&mut i, "ws_stats", vec![syn_int(c)])), "received"));
        if received >= 100 || start.elapsed() > Duration::from_secs(10) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let stats = ok(call(&mut i, "ws_stats", vec![syn_int(c)]));
    assert!(as_i64(&map_get(&stats, "queued")) <= 8, "drop_oldest respeta el tope");
    let m = ok(call(&mut i, "ws_recv", vec![syn_int(c), syn_int(2)]));
    let first: i64 = map_get(&m, "data").to_string().parse().expect("número");
    assert!(first >= 50, "los VIEJOS se descartaron; el primero drenado debe ser reciente, fue {}", first);
    ok(call(&mut i, "ws_close", vec![syn_int(c)]));
}

// =========================================================
// Frames fragmentados a nivel TCP: ws_select junta el frame completo
// =========================================================

#[test]
fn ws_select_reassembles_tcp_fragmented_frames() {
    let _g = serial();
    // Server que tras el handshake escribe UN frame de texto de 1000 bytes en 3
    // pedazos TCP con pausas — el cliente ve WouldBlock a mitad de frame y debe
    // bufferear hasta juntarlo (jamás entregar un frame parcial ni romperse).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(mut ws) = tungstenite::accept(stream) {
                use std::io::Write;
                let payload = "y".repeat(1000);
                // Frame server→cliente sin máscara: FIN|text (0x81), len extendido 16-bit.
                let mut frame = vec![0x81u8, 126, 0x03, 0xE8];
                frame.extend_from_slice(payload.as_bytes());
                let raw = ws.get_mut();
                let _ = raw.write_all(&frame[..4]);
                let _ = raw.flush();
                thread::sleep(Duration::from_millis(80));
                let _ = raw.write_all(&frame[4..504]);
                let _ = raw.flush();
                thread::sleep(Duration::from_millis(80));
                let _ = raw.write_all(&frame[504..]);
                let _ = raw.flush();
                // Mantener viva la conexión hasta que el cliente cierre.
                loop {
                    match ws.read() {
                        Ok(tungstenite::Message::Close(_)) | Err(_) => return,
                        _ => {}
                    }
                }
            }
        }
    });
    let mut i = interp_net();
    let c = as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", port).as_str())])));
    let conns = SynValue::List(Rc::new(RefCell::new(vec![syn_int(c)])));
    let sel = ok(call(&mut i, "ws_select", vec![conns, syn_int(5)]));
    assert_eq!(map_get(&sel, "type").to_string(), "text");
    assert_eq!(map_get(&sel, "data").to_string().len(), 1000, "el frame fragmentado llegó COMPLETO");
    ok(call(&mut i, "ws_close", vec![syn_int(c)]));
}

// =========================================================
// Subprotocolos: se negocia y el handle lo expone
// =========================================================

#[test]
fn ws_subprotocol_is_negotiated_and_exposed() {
    let _g = serial();
    // Server que acepta ofreciendo "json" en la respuesta.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // El Err de tungstenite (ErrorResponse) es grande; no está en nuestras manos.
            #[allow(clippy::result_large_err)]
            let cb = |_req: &tungstenite::handshake::server::Request,
                      mut resp: tungstenite::handshake::server::Response| {
                resp.headers_mut().insert(
                    tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                    tungstenite::http::header::HeaderValue::from_static("json"),
                );
                Ok(resp)
            };
            if let Ok(mut ws) = tungstenite::accept_hdr(stream, cb) {
                let _ = ws.read();
            }
        }
    });
    let mut i = interp_net();
    let mut opts = indexmap::IndexMap::new();
    opts.insert(
        "subprotocols".to_string(),
        SynValue::List(Rc::new(RefCell::new(vec![syn_text("json"), syn_text("cbor")]))),
    );
    let c = as_i64(&ok(call(
        &mut i,
        "ws_connect",
        vec![syn_text(format!("ws://127.0.0.1:{}/", port).as_str()), SynValue::Nothing, syn_map(opts)],
    )));
    let stats = ok(call(&mut i, "ws_stats", vec![syn_int(c)]));
    assert_eq!(map_get(&stats, "subprotocol").to_string(), "json", "el subprotocolo acordado se expone");
}

// =========================================================
// Tope de conexiones: error claro al pasarlo (anti-footgun)
// =========================================================

#[test]
fn ws_connection_budget_errors_clearly() {
    let _g = serial();
    // Bajar el tope a 2 vía el knob de entorno.
    std::env::set_var("SYNSEMA_WS_MAX_CONNS", "2");
    let p = ws_server(|ws| loop {
        match ws.read() {
            Ok(tungstenite::Message::Close(_)) | Err(_) => return,
            _ => {}
        }
    });
    let mut i = interp_net();
    let url = format!("ws://127.0.0.1:{}/", p);
    let _c1 = ok(call(&mut i, "ws_connect", vec![syn_text(url.as_str())]));
    let _c2 = ok(call(&mut i, "ws_connect", vec![syn_text(url.as_str())]));
    let e = call(&mut i, "ws_connect", vec![syn_text(url.as_str())]);
    std::env::remove_var("SYNSEMA_WS_MAX_CONNS");
    match e {
        Err(Control::Error(e)) => assert!(
            e.message.contains("budget"),
            "el 3er connect sobre el tope debe errar claro: {}",
            e.message
        ),
        _ => panic!("esperaba error de tope de conexiones"),
    }
}

// =========================================================
// ws_broadcast + ws_select_all
// =========================================================

#[test]
fn ws_broadcast_and_select_all() {
    let _g = serial();
    let echo = |ws: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
        match ws.read() {
            Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                if ws.send(m).is_err() {
                    return;
                }
            }
            _ => return,
        }
    };
    let mut i = interp_net();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let p = ws_server(echo);
        handles.push(as_i64(&ok(call(&mut i, "ws_connect", vec![syn_text(format!("ws://127.0.0.1:{}/", p).as_str())]))));
    }
    let conns = SynValue::List(Rc::new(RefCell::new(handles.iter().map(|&c| syn_int(c)).collect())));
    // Un solo broadcast → los 3 reciben eco.
    let sent = as_i64(&ok(call(&mut i, "ws_broadcast", vec![conns.clone(), syn_text("hey")])));
    assert_eq!(sent, 3, "broadcast a las 3 conexiones");
    // Drenar de a tandas con ws_select_all hasta juntar 3.
    let mut got = 0;
    let start = Instant::now();
    while got < 3 && start.elapsed() < Duration::from_secs(10) {
        let batch = ok(call(&mut i, "ws_select_all", vec![conns.clone(), syn_int(2)]));
        if let SynValue::List(l) = batch {
            got += l.borrow().len();
        }
    }
    assert_eq!(got, 3, "ws_select_all drena los mensajes listos del tick");
}
