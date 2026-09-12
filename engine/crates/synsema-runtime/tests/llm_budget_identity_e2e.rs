//! v0.6.20 (auditoría B1) — el techo LLM POR IDENTIDAD es del PROCESO bajo `serve`, no de cada
//! worker: con varios workers y requests que caen en hilos distintos, la suma de tokens de una
//! misma identidad corta cuando corresponde. Números de verdad: cada llamada cuesta 25 000
//! tokens (una tarea normal gasta 20k+); el techo de `alice` es 60 000 → pasan tres (75k) y la
//! cuarta devuelve el marcador sin tocar el modelo. `bob` no tiene techo y sigue.
//! Test ÚNICO en su binario: muta variables de entorno del proceso.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

/// Respuesta SSE de Anthropic con `usage` REAL repartido como lo manda la API: los tokens de
/// entrada en `message_start`, los de salida en `message_delta`.
fn sse(input_tokens: u64, output_tokens: u64) -> Vec<u8> {
    let body = format!(
        concat!(
            "event: message_start\n",
            "data: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":{in_t},\"output_tokens\":0}}}}}}\n\n",
            "event: content_block_delta\n",
            "data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"respuesta\"}}}}\n\n",
            "event: message_delta\n",
            "data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":{out_t}}}}}\n\n",
            "event: message_stop\n",
            "data: {{\"type\":\"message_stop\"}}\n\n",
        ),
        in_t = input_tokens,
        out_t = output_tokens
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

fn request(port: u16, target: &str, token: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, body.to_string())
}

#[test]
fn identity_budget_is_process_wide_across_serve_workers() {
    // 1. El "Anthropic" falso: cada request cuesta 20k de entrada + 5k de salida. Tarda un
    //    poco en responder para que tres requests simultáneas ocupen tres workers distintos.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU32::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (hits, stop) = (hits.clone(), stop.clone());
        thread::spawn(move || {
            for conn in upstream.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut sock) = conn else { continue };
                let hits = hits.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 16384];
                    if let Ok(n) = sock.read(&mut buf) {
                        if n > 0 {
                            hits.fetch_add(1, Ordering::SeqCst);
                            thread::sleep(Duration::from_millis(400));
                            let _ = sock.write_all(&sse(20_000, 5_000));
                        }
                    }
                });
            }
        });
    }

    // 2. Host: provider real apuntado al falso, 4 workers, techo de alice = 60 000 tokens.
    std::env::set_var("SYNSEMA_LLM_PROVIDER", "anthropic");
    std::env::set_var("ANTHROPIC_API_KEY", "k");
    std::env::set_var("SYNSEMA_LLM_BASE_URL", format!("http://127.0.0.1:{}", up_port));
    std::env::set_var("SYNSEMA_LLM_TIMEOUT", "10");
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "4");
    std::env::set_var("SYNSEMA_LLM_BUDGET_PER_IDENTITY", "alice=60000");

    let p = free_port();
    let prog = format!(
        r#"require serve({p})
require llm

task who(token, request)
    give {{"id": token}}

serve on {p}
    auth with who
    route "GET /ask" requires auth
        let r be reason "resumí el pedido"
        give {{"answer": r}}
    route "GET /ask_stream" requires auth
        stream
            let r be reason "resumí el pedido"
            send {{"answer": r}}
"#,
        p = p
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "llm_budget_identity_e2e.syn", false);
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

    // 3. Tres requests de alice a la vez (tres workers): 3 × 25k = 75k, todas contestan.
    let firsts: Vec<_> = (0..3)
        .map(|_| thread::spawn(move || request(p, "/ask", "alice")))
        .collect();
    for h in firsts {
        let (st, body) = h.join().unwrap();
        assert_eq!(st, 200, "{}", body);
        assert!(body.contains("\"answer\": \"respuesta\""), "{}", body);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3, "las tres llegaron al modelo");
    assert_eq!(synsema_runtime::llm_providers::llm_identity_tokens("alice"), 75_000);

    // 4. La cuarta de alice, caiga en el worker que caiga, NO toca el modelo: el techo es del
    //    proceso. El marcador vuelve como valor (el programa sigue; no es un error).
    let (st, body) = request(p, "/ask", "alice");
    assert_eq!(st, 200, "{}", body);
    assert!(
        body.contains("budget exceeded for identity alice") && body.contains("75000 of 60000"),
        "{}",
        body
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3, "la cuarta no delegó");

    // 5. bob no tiene techo por identidad: sigue hablando con el modelo.
    let (st, body) = request(p, "/ask", "bob");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("\"answer\": \"respuesta\""), "{}", body);
    assert_eq!(hits.load(Ordering::SeqCst), 4);
    assert_eq!(synsema_runtime::llm_providers::llm_identity_tokens("alice"), 75_000);

    // 6. Segunda ronda de la auditoría — una ruta `stream` DIRECTA corre con la misma
    //    identidad: alice agotada recibe el marcador por SSE sin tocar el modelo; bob delega.
    let (st, body) = request(p, "/ask_stream", "alice");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("budget exceeded for identity alice"), "{}", body);
    assert_eq!(hits.load(Ordering::SeqCst), 4, "la ruta stream de alice no delegó");
    let (st, body) = request(p, "/ask_stream", "bob");
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("data: {\"answer\": \"respuesta\"}"), "{}", body);
    assert_eq!(hits.load(Ordering::SeqCst), 5);

    stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(("127.0.0.1", up_port));
}
