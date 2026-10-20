//! v0.6.45 (A1): cada item de `parallel_map` corre en un intérprete nuevo, y ese intérprete no
//! cableaba los providers: `judge` daba OFFLINE (`available: false`) y `reason` el placeholder,
//! mientras el mismo código en el hilo principal contestaba. Ahora el worker usa las MISMAS
//! instancias que el llamador (`engine::WiredProviders`). Binario propio: muta el entorno del
//! proceso (los dos tests ponen los mismos valores).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use synsema_runtime::engine::run_source;

/// Respuesta SSE de Anthropic con un solo chunk de texto.
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

/// Un Anthropic falso en 127.0.0.1 que cuenta los pedidos. Se levanta una vez por proceso.
fn upstream() -> Arc<AtomicU32> {
    static HITS: std::sync::OnceLock<Arc<AtomicU32>> = std::sync::OnceLock::new();
    HITS.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicU32::new(0));
        let h = hits.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let h = h.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 16384];
                    if let Ok(n) = sock.read(&mut buf) {
                        if n > 0 {
                            h.fetch_add(1, Ordering::SeqCst);
                            let _ = sock.write_all(&sse());
                        }
                    }
                });
            }
        });
        std::env::set_var("SYNSEMA_JUDGE_PROVIDER", "mock");
        std::env::set_var("SYNSEMA_LLM_PROVIDER", "anthropic");
        std::env::set_var("ANTHROPIC_API_KEY", "k");
        std::env::set_var("SYNSEMA_LLM_BASE_URL", format!("http://127.0.0.1:{}", port));
        std::env::set_var("SYNSEMA_ENV_FILE", "");
        hits
    })
    .clone()
}

#[test]
fn judge_inside_parallel_map_uses_the_callers_provider() {
    upstream();
    let src = r#"task classify(t)
    let v be judge t
        refund: whether "Is the customer asking for money back?"
    give v.refund.available
print(judge_available())
print(parallel_map(classify, ["a", "b", "c"]))
"#;
    let r = run_source(src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "true");
    assert_eq!(r.output[1], "[true, true, true]", "un worker de parallel_map quedó OFFLINE");
}

#[test]
fn reason_inside_parallel_map_reaches_the_callers_provider() {
    let hits = upstream();
    let before = hits.load(Ordering::SeqCst);
    let src = r#"task summarize(t)
    let r be reason "summarize this"
    give r
print(parallel_map(summarize, ["a", "b"]))
"#;
    let r = run_source(src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], r#"["respuesta", "respuesta"]"#,"un worker de parallel_map no tenía provider LLM");
    assert!(hits.load(Ordering::SeqCst) - before >= 2, "los workers no llegaron al provider");
}
