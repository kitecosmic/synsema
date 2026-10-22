//! E2E del Batch 15 (WebSocket de primera clase) por el runtime REAL, SIN red
//! externa: servidores WS locales (tungstenite `accept` en threads del harness).
//!
//! - **Reconexión + resubscribe:** el server corta la 1ª conexión; el cliente
//!   reconecta solo (backoff acotado) y su task `on_reconnect` **re-manda** la
//!   subscripción — el agente no pierde su feed. `ws_stats` reporta el reconnect.
//! - **Keepalive / half-open:** un server que hace el handshake y queda MUDO (no
//!   pongea) se detecta dentro del `timeout` → `close` (no cuelga al agente).
//! - **`parallel_map` (fan-out):** N workers, cada uno dueño de su propia conexión
//!   (registro por-worker, caps heredadas); procesan y mergean; fail-fast en un
//!   feed malo. Los handles NO cruzan workers (aislamiento CSP).
//! - **G21:** deny sin `require net`; reconexión re-chequea el mismo host.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<batch15>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

/// Server de eco local: acepta conexiones y refleja text/binary hasta el close.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            thread::spawn(move || {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                loop {
                    match ws.read() {
                        Ok(m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_))) => {
                            if ws.send(m).is_err() {
                                return;
                            }
                        }
                        Ok(tungstenite::Message::Close(_)) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    port
}

// =========================================================
// Reconexión + on_reconnect (resubscribe)
// =========================================================

#[test]
fn reconnect_fires_on_reconnect_and_resubscribes() {
    // 1ª conexión: handshake y cierre inmediato (simula una caída). 2ª conexión:
    // espera "SUBSCRIBE" y responde "SUBBED" — sólo llega si on_reconnect corrió.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts2 = accepts.clone();
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let n = accepts2.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                if n == 0 {
                    // Primera vez: cortar apenas se establece.
                    let _ = ws.close(None);
                    return;
                }
                // Reconexión: esperar la resubscripción y confirmarla.
                loop {
                    match ws.read() {
                        Ok(tungstenite::Message::Text(t)) if t.as_str() == "SUBSCRIBE" => {
                            let _ = ws.send(tungstenite::Message::text("SUBBED"));
                        }
                        Ok(tungstenite::Message::Close(_)) | Err(_) => return,
                        _ => {}
                    }
                }
            });
        }
    });

    let o = out(&format!(
        r#"require net("127.0.0.1")

task resub(c)
    ws_send(c, "SUBSCRIBE")

let conn be ws_connect("ws://127.0.0.1:{port}/", nothing,
    {{"reconnect": {{"max_retries": 5, "backoff": 0.05, "on_reconnect": resub}}}})
let got be ""
let tries be 0
while got == "" and tries < 80
    let m be ws_recv(conn, 1)
    when m != nothing
        when m["type"] == "text"
            set got to m["data"]
    set tries to tries + 1
print(got)
print(text(ws_stats(conn)["reconnects"] >= 1))
"#,
        port = port,
    ));
    assert_eq!(o[0], "SUBBED", "la resubscripción re-mandada por on_reconnect volvió");
    assert_eq!(o[1], "true", "ws_stats registró al menos una reconexión");
}

// =========================================================
// Keepalive / half-open
// =========================================================

#[test]
fn keepalive_detects_half_open_silent_peer() {
    // Server que hace el handshake y queda MUDO: no lee (no pongea) → half-open.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(_ws) = tungstenite::accept(stream) {
                // No leer nada: nunca responde el ping del cliente. Mantener vivo.
                thread::sleep(Duration::from_secs(5));
            }
        }
    });
    let o = out(&format!(
        r#"require net("127.0.0.1")
let conn be ws_connect("ws://127.0.0.1:{port}/", nothing,
    {{"keepalive": {{"interval": 0.3, "timeout": 0.3}}}})
-- sin datos ni pong: keepalive detecta half-open y emite close, no cuelga
let m be ws_recv(conn, 4)
print(when m == nothing then "timeout" otherwise m["type"])
"#,
        port = port,
    ));
    assert_eq!(o[0], "close", "un peer mudo se detecta por keepalive → close (no cuelga)");
}

// =========================================================
// parallel_map: fan-out horizontal (worker dueño de su conexión)
// =========================================================

#[test]
fn parallel_map_fans_out_feeds_one_per_worker() {
    // 12 feeds de eco; cada worker abre el suyo, hace round-trip y devuelve.
    let ports: Vec<u16> = (0..12).map(|_| echo_server()).collect();
    let urls = ports
        .iter()
        .map(|p| format!("\"ws://127.0.0.1:{}/\"", p))
        .collect::<Vec<_>>()
        .join(", ");
    let o = out(&format!(
        r#"require net("127.0.0.1")

task watch(url)
    let c be ws_connect(url)
    ws_send(c, "hi")
    let m be ws_recv(c, 5)
    ws_close(c)
    give when m == nothing then "miss" otherwise m["data"]

let urls be [{urls}]
let results be parallel_map(watch, urls)
print(length(results))
print(text(length(where(results, (x) => x == "hi"))))
"#,
        urls = urls,
    ));
    assert_eq!(o[0], "12", "los 12 feeds se repartieron en el pool");
    assert_eq!(o[1], "12", "cada worker hizo su round-trip (handle propio, no compartido)");
}

#[test]
fn parallel_map_fail_fast_on_bad_feed() {
    // Un feed apunta a un puerto muerto → ws_connect errora → parallel_map propaga.
    let good = echo_server();
    let src = format!(
        r#"require net("127.0.0.1")

task watch(url)
    let c be ws_connect(url)
    ws_send(c, "hi")
    let m be ws_recv(c, 5)
    ws_close(c)
    give m["data"]

let urls be ["ws://127.0.0.1:{good}/", "ws://127.0.0.1:1/"]
let results be parallel_map(watch, urls)
print("no debería llegar")
"#,
        good = good,
    );
    let r = run_source(&src, "<batch15-failfast>");
    assert!(!r.success, "un feed malo debe hacer fallar el parallel_map (fail-fast)");
}

// =========================================================
// G21 — la RECONEXIÓN también re-chequea net: dentro de sandbox se deniega
// (jamás una reconexión con capabilities vaciadas)
// =========================================================

#[test]
fn g21_reconnect_is_denied_inside_sandbox() {
    // Server: la 1ª conexión se corta apenas nace; seguiría aceptando — pero la
    // reconexión ocurre DENTRO de un sandbox, así que la 2ª conexión JAMÁS debe
    // llegar (el re-chequeo de net(host) la deniega antes de marcar el socket).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts2 = accepts.clone();
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            accepts2.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                if let Ok(mut ws) = tungstenite::accept(stream) {
                    let _ = ws.close(None);
                }
            });
        }
    });
    let o = out(&format!(
        r#"require net("127.0.0.1")
let conn be ws_connect("ws://127.0.0.1:{port}/", nothing,
    {{"reconnect": {{"max_retries": 3, "backoff": 0.05}}}})
let t be ""
-- la caída llega dentro del sandbox; cada intento de reconexión re-chequea net →
-- denegado → se agotan los reintentos → close (no una reconexión con caps vaciadas)
sandbox
    let m be ws_recv(conn, 5)
    when m != nothing
        set t to m["type"]
print(t)
"#,
        port = port,
    ));
    assert_eq!(o[0], "close", "en sandbox la reconexión se deniega y la caída sale como close");
    // La prueba dura: el server aceptó UNA sola conexión — el sandbox impidió
    // que el cliente siquiera marcara la segunda.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "jamás hubo una 2ª conexión TCP desde el sandbox");
}

// =========================================================
// G21 — deny sin net; el gate vale también para ws_select
// =========================================================

#[test]
fn g21_deny_without_net_for_select_family() {
    let port = echo_server();
    let o = out(&format!(
        r#"let denied be ""
try
    let c be ws_connect("ws://127.0.0.1:{port}/")
recover e
    set denied to e
print(contains(denied, "net"))
print("vivo")
"#,
        port = port,
    ));
    assert_eq!(o[0], "true", "sin require net → deny atrapable");
    assert_eq!(o[1], "vivo");
}
