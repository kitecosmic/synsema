//! v0.6.45 (A1): los workers de `parallel_map` comparten el provider del llamador, y con él el
//! techo de tokens del proceso (`SYNSEMA_LLM_BUDGET`): un fan-out no puede gastar más de lo que
//! gastaría el mismo trabajo en el hilo principal. Binario propio: muta el entorno del proceso.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use synsema_runtime::engine::run_source;

/// Una respuesta SSE de Anthropic que gasta 25k tokens (20k de entrada + 5k de salida).
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

#[test]
fn the_process_token_budget_holds_across_parallel_map_workers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU32::new(0));
    {
        let hits = hits.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
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
    std::env::set_var("SYNSEMA_LLM_BASE_URL", format!("http://127.0.0.1:{}", port));
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    // Alcanza para UNA llamada: la primera gasta 25k y deja el contador en el techo.
    std::env::set_var("SYNSEMA_LLM_BUDGET", "25000");

    // `limit` 1: los items corren uno tras otro, así el corte es determinista.
    let src = r#"task summarize(t)
    give reason "summarize this"
let out be parallel_map(summarize, ["a", "b", "c"], 1)
print(out[0])
print(contains(out[1], "budget"))
print(contains(out[2], "budget"))
"#;
    let r = run_source(src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["respuesta", "true", "true"], "un worker gastó por encima del techo");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "los items cortados no deben tocar la red");
}
