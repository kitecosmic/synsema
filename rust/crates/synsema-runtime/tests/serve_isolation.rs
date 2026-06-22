//! Aislamiento entre requests con el intérprete REUSADO por worker (perf/interp-reuse).
//!
//! El serve ahora construye el intérprete (builtins + globales + tasks) UNA vez por
//! worker y lo reusa entre requests, en vez de reconstruirlo por request (era el ~46%
//! del CPU, medido en la VPS). El contrato de aislamiento: las variables locales de un
//! handler y las bindings de request (`request`/`query`/`params`/`read_body`) viven en
//! un scope HIJO efímero del global → no se filtran al siguiente request; el estado
//! transitorio (output/blackboard/caps/…) se resetea entre requests.
//!
//! Estos tests corren programas .syn REALES (parser + runtime + serve) y verifican,
//! bajo concurrencia y bajo reuso secuencial, que cada respuesta refleja SOLO su propio
//! input (cero contaminación cruzada).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Server con un handler que bindea LOCALES (`mine`, `doubled`) desde su propio
/// `params.tag`. Si esos locales (o las bindings de request) se filtraran entre
/// requests al reusar el intérprete, una respuesta traería el tag de OTRA request.
fn start(port: u16) {
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /echo/:tag"
        let mine be params.tag
        let doubled be mine + "-" + mine
        give {{"tag": mine, "doubled": doubled}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_isolation.syn", false);
    });
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
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

/// La respuesta de `/echo/<tag>` debe traer EXACTAMENTE su propio tag (las comillas de
/// cierre desambiguan tag5 de tag50).
fn check(resp: &str, tag: &str) -> Result<(), String> {
    let want_tag = format!("\"tag\": \"{}\"", tag);
    let want_dbl = format!("\"doubled\": \"{}-{}\"", tag, tag);
    if resp.starts_with("HTTP/1.1 200") && resp.contains(&want_tag) && resp.contains(&want_dbl) {
        Ok(())
    } else {
        Err(format!("tag={} resp={}", tag, resp))
    }
}

#[test]
fn concurrent_requests_do_not_leak_handler_state() {
    let port = free_port();
    start(port);

    // 64 requests CONCURRENTES, cada una con un tag único, repartidas entre los workers
    // del pool (cada worker reusa su intérprete cacheado). Si los locales del handler o
    // las bindings de request se filtraran, alguna respuesta traería un tag ajeno.
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for i in 0..64u32 {
        let errors = errors.clone();
        handles.push(thread::spawn(move || {
            let tag = format!("tag{}", i);
            let resp = get(port, &format!("/echo/{}", tag));
            if let Err(e) = check(&resp, &tag) {
                errors.lock().unwrap().push(format!("req {}: {}", i, e));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let errs = errors.lock().unwrap();
    assert!(
        errs.is_empty(),
        "contaminación/error en {} de 64 requests concurrentes:\n{}",
        errs.len(),
        errs.join("\n---\n")
    );
}

#[test]
fn many_sequential_requests_stay_correct() {
    // Reuso SECUENCIAL: muchas requests una tras otra golpean los mismos workers (que
    // reusan su intérprete). Cada respuesta debe traer su propio tag, request tras
    // request (sin acumulación ni arrastre de estado).
    let port = free_port();
    start(port);
    for i in 0..120u32 {
        let tag = format!("seq{}", i);
        let resp = get(port, &format!("/echo/{}", tag));
        check(&resp, &tag).unwrap_or_else(|e| panic!("request secuencial #{}: {}", i, e));
    }
}
