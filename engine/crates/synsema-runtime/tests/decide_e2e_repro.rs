//! E2e del contrato de `decide` (DE-039) por el camino REAL de `synsema run`:
//! `run_program` + provider resuelto por env, apuntado a un server fake que responde
//! texto fuera del set — el contrato debe hacer 2 requests (original + reintento con
//! feedback) y degradar al crudo. Cubre el wiring completo (arm del core → callback
//! dedicado → decide_with_contract), no sólo las piezas.
//! Mutación de env-vars: test ÚNICO en su binario de integración → sin carreras.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use synsema_runtime::engine::run_program;

fn sse_text_verde() -> Vec<u8> {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"verde\"}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n{}", body).into_bytes()
}

#[test]
fn run_program_decide_contract_retries_via_env_provider() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(0u32));
    let h = hits.clone();
    let handle = thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept() else { return };
            let mut buf = [0u8; 8192];
            // una conexión de drenaje (cierre sin bytes) no cuenta como request
            match sock.read(&mut buf) {
                Ok(n) if n > 0 => {
                    *h.lock().unwrap() += 1;
                    let _ = sock.write_all(&sse_text_verde());
                }
                _ => {}
            }
        }
    });

    std::env::set_var("SYNSEMA_LLM_PROVIDER", "anthropic");
    std::env::set_var("ANTHROPIC_API_KEY", "k");
    std::env::set_var("SYNSEMA_LLM_BASE_URL", format!("http://127.0.0.1:{}", port));
    std::env::set_var("SYNSEMA_LLM_TIMEOUT", "5");
    std::env::set_var("SYNSEMA_ENV_FILE", ""); // ≡ --no-env-file

    let src = "require llm\n\
               let d be decide between [\"ROJO\", \"AZUL\"] given \"elegí\"\n\
               print(d)\n";
    let res = run_program(src, "<stdin>");
    assert!(res.success, "{:?}", res.errors);
    // desbloquea el accept si quedó esperando la 2ª conexión (drenaje sin bytes)
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    let _ = handle.join();
    let n = *hits.lock().unwrap();
    assert_eq!(n, 2, "el contrato debía reintentar UNA vez (2 requests), hubo {}; out={:?}", n, res.output);
    assert_eq!(res.output, vec!["verde".to_string()], "fallback crudo esperado");
}
