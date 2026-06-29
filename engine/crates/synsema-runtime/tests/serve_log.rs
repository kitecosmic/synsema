//! DE-034: un `log`/`print` DENTRO de un handler de `serve` debe verse (antes el buffer
//! `output` se limpiaba por request sin volcarse → operar el server era a ciegas). El
//! fix cablea un `log_hook` en el intérprete base de serve que emite cada línea en vivo
//! (a stdout por defecto). Acá instalamos un sink propio vía `set_serve_log_sink` para
//! capturar las líneas sin depender de stdout del proceso, y verificamos que el marcador
//! de un `log` dentro del handler llega.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program, set_serve_log_sink};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn get(port: u16, target: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn serve_handler_log_reaches_sink() {
    // Sink de captura instalado ANTES de arrancar el server (se resuelve por worker al
    // construir el intérprete base, en el primer request).
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let c = captured.clone();
        set_serve_log_sink(Some(Arc::new(move |line: &str| {
            c.lock().unwrap().push(line.to_string());
        })));
    }

    let port = free_port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /ping"
        log "PING-LOG-MARKER"
        give {{"ok": true}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_log.syn", false);
    });
    // Esperar a que el server escuche.
    let mut ready = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo en :{}", port);

    let resp = get(port, "/ping");
    assert!(resp.contains("200"), "el handler debe responder 200: {}", resp);

    let lines = captured.lock().unwrap();
    assert!(
        lines.iter().any(|l| l.contains("PING-LOG-MARKER")),
        "el `log` del handler debe llegar al sink; capturado={:?}",
        lines
    );

    // Limpiar el sink global para no afectar a otros tests del proceso.
    set_serve_log_sink(None);
}
