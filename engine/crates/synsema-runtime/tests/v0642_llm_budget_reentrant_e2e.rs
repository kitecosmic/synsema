//! v0.6.42, auditoría ronda 2 (R1): con un techo de tokens, cada llamada LLM ocupa uno de los W
//! lugares del proceso. Un `reason` dentro del `on_chunk` de un `llm_stream` pedía un segundo
//! lugar mientras el stream retenía el primero: con `SYNSEMA_SERVE_WORKERS=1` la request quedaba
//! colgada para siempre y, como la espera estaba dentro del callback, el pool tampoco arrancaba
//! otras rutas. El lugar ahora es reentrante en el hilo: contesta enseguida y sin el marcador de
//! "llm busy". Test ÚNICO en su binario: muta variables de entorno del proceso.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::run_serve_program;

/// Respuesta SSE de Anthropic: 20k de entrada + 5k de salida, un chunk de texto.
fn sse() -> Vec<u8> {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":20000,\"output_tokens\":0}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"respuesta\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5000}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn get(port: u16, target: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, body.to_string())
}

#[test]
fn a_reason_inside_on_chunk_does_not_wait_for_a_second_slot() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU32::new(0));
    {
        let hits = hits.clone();
        thread::spawn(move || {
            for conn in upstream.incoming() {
                let Ok(mut sock) = conn else { continue };
                let hits = hits.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 16384];
                    if let Ok(n) = sock.read(&mut buf) {
                        if n > 0 {
                            hits.fetch_add(1, Ordering::SeqCst);
                            let _ = sock.write_all(&sse());
                        }
                    }
                });
            }
        });
    }

    std::env::set_var("SYNSEMA_LLM_PROVIDER", "anthropic");
    std::env::set_var("ANTHROPIC_API_KEY", "k");
    std::env::set_var("SYNSEMA_LLM_BASE_URL", format!("http://127.0.0.1:{}", up_port));
    // El plazo de la espera de un lugar: sin reentrancia la request tardaría esto y volvería
    // con el marcador "llm busy" (antes del arreglo, colgaba para siempre).
    std::env::set_var("SYNSEMA_LLM_TIMEOUT", "8");
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "1");
    std::env::set_var("SYNSEMA_LLM_BUDGET", "10000000");

    let p = free_port();
    let prog = format!(
        r#"require serve({p})
require llm

task on_tok(t)
    let inner be reason "resumí este pedazo"
    give true

serve on {p}
    route "GET /s"
        let full be llm_stream("contá algo", "", on_tok)
        give {{"full": full}}
    route "GET /ping"
        give {{"ok": true}}
"#,
        p = p
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "v0642_llm_budget_reentrant_e2e.syn", false);
    });
    let mut ready = false;
    for _ in 0..150 {
        if TcpStream::connect(("127.0.0.1", p)).is_ok() {
            ready = true;
            thread::sleep(Duration::from_millis(200));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo en :{}", p);

    let t0 = Instant::now();
    let (st, body) = get(p, "/s");
    let took = t0.elapsed();
    assert_eq!(st, 200, "body: {}", body);
    assert!(body.contains("respuesta") && !body.contains("llm busy"), "body: {}", body);
    assert!(took < Duration::from_secs(5), "tardó {:?}: esperó un segundo lugar", took);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "el stream y el reason de adentro llegan al modelo");

    // Y el único worker sigue sirviendo.
    let (st, body) = get(p, "/ping");
    assert_eq!(st, 200, "body: {}", body);
}
