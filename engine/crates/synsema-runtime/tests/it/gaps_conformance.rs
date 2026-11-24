//! Casos de `gaps-fogueo-p4` que siguen en Rust: salida del host, modo secure/run,
//! `run_swarm_dump` y estado compartido entre requests de serve. Los ocho casos de
//! comportamiento del lenguaje están en `tests/gaps_conformance.test.syn`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_source_secure, run_swarm_dump};
use synsema_runtime::serve::run_serve_program;

// =========================================================
// sandbox AÍSLA capabilities (el fix de seguridad)
// =========================================================

// =========================================================
// Gate de capability `llm` para las ops LLM (reason/decide/analyze/generate)
// =========================================================

#[test]
fn llm_op_denied_in_secure_without_require() {
    // En secure, una op LLM sin `require llm` debe DENEGARSE (igual que cualquier
    // otra capability). Cubre el path de placeholder (sin provider real).
    let r = run_source_secure("let e be generate \"x\" given \"y\"\n", "<t>");
    assert!(!r.success, "secure sin `require llm` debería denegar la op LLM");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: llm")),
        "errs: {:?}",
        r.errors
    );
}

#[test]
fn llm_op_allowed_in_secure_with_require() {
    // En secure, declarar `require llm` concede la capability → la op LLM corre.
    let r = run_source_secure(
        "require llm\nlet e be generate \"x\" given \"y\"\nprint(\"ok\")\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["ok".to_string()]);
}

// =========================================================
// when/then inline (gap #5) — devuelve el valor de la rama
// =========================================================

// =========================================================
// checkpoint con expresión (gap #7) — parsea y corre (decorativo)
// =========================================================

// =========================================================
// agentes ven tasks del top-level (gap #6)
// =========================================================

#[test]
fn agent_sees_top_level_task() {
    // El agente llama una task definida en el top-level (greet) sin HTTP.
    let dump = run_swarm_dump(
        "task greet(name)\n    give \"hello \" + name\n\n\
         agent Worker\n    let msg be greet(\"world\")\n    share msg as \"result\"\n\n\
         spawn Worker",
        "<t>",
    );
    assert!(
        dump.blackboard.iter().any(|(k, v)| k == "result" && v.contains("hello world")),
        "el agente debería poder llamar greet(); blackboard: {:?}",
        dump.blackboard
    );
}

// =========================================================
// state_* compartido entre requests (gap #9) — serve E2E
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_server(port: u16) {
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"POST /incr\"\n        state_incr(\"counter\")\n        give \"ok\"\n    route \"GET /count\"\n        give state_get(\"counter\", 0)\n",
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "gaps_state.syn", false);
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

fn request(port: u16, req: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.write_all(req.as_bytes()).unwrap();
    sock.flush().unwrap();
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp).unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

#[test]
fn state_shared_across_requests() {
    let port = free_port();
    start_server(port);
    let post = "POST /incr HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    // Tres incrementos en requests separados.
    for _ in 0..3 {
        let _ = request(port, post);
    }
    let get = "GET /count HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let resp = request(port, get);
    // El contador (compartido entre requests) debe ser 3 — un global normal volvería a 0.
    let body = resp.rsplit("\r\n\r\n").next().unwrap_or("");
    assert!(body.contains('3'), "state_* debería compartir el contador entre requests; body: {:?}", body);
    // DE-009: un contador entero sale como JSON `3`, NO `3.0` (state_incr hace aritmética
    // entera cuando current y delta son Int).
    assert!(!body.contains("3.0"), "state_incr de enteros debe dar Int, no Float; body: {:?}", body);
}

#[test]
fn sandbox_print_is_denied_inside_and_sandbox_under_lets_it_through() {
    // v0.6.51 (N5): un `sandbox` pelado deniega toda capability, `stdout` también (antes `print`
    // pasaba); `sandbox under {}` deja pasar las del proceso dentro del techo del host.
    let r = run_source("sandbox\n    print(\"inside\")\n", "<t>");
    assert!(!r.success);
    assert!(r.errors.join("\n").contains("Capability not granted: stdout"), "{:?}", r.errors);
    let r = run_source("sandbox under {}\n    print(\"inside\")\n", "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["inside".to_string()]);
}
