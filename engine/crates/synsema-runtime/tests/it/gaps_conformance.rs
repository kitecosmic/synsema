//! Regresión de los gaps de la rama `gaps-fogueo-p4` (+ el fix de aislamiento de
//! `sandbox`). Cubre lo testeable in-process: aislamiento de capabilities del sandbox
//! (seguridad — el fix principal), `when/then` inline, `checkpoint` con expresión,
//! agentes que ven tasks del top-level, y el estado compartido `state_*` en serve.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_source_secure, run_swarm_dump};
use synsema_runtime::serve::run_serve_program;

// =========================================================
// sandbox AÍSLA capabilities (el fix de seguridad)
// =========================================================

#[test]
fn sandbox_denies_granted_capability() {
    // `random` está concedido, pero DENTRO del sandbox debe estar denegado.
    let r = run_source(
        "require random\nsandbox\n    let x be random()\n",
        "<t>",
    );
    assert!(!r.success, "el sandbox debería denegar random()");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "errs: {:?}",
        r.errors
    );
}

#[test]
fn sandbox_restores_capabilities_after() {
    // random() funciona afuera, el sandbox computa sin caps, y random() vuelve a
    // funcionar DESPUÉS (las capabilities se restauran).
    let r = run_source(
        "require random\n\
         print(text(random() >= 0))\n\
         let c be 0\n\
         sandbox\n    set c to 2 + 3\n\
         print(text(c))\n\
         print(text(random() >= 0))\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string(), "5".to_string(), "true".to_string()]);
}

#[test]
fn sandbox_print_works_inside() {
    // `print` NO está gateado → el sandbox puede imprimir y computar.
    let r = run_source("sandbox\n    print(\"inside\")\n", "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["inside".to_string()]);
}

#[test]
fn sandbox_require_cannot_escape() {
    // Un `require` dentro de un sandbox es no-op → no se puede re-grantear para escapar.
    let r = run_source(
        "sandbox\n    require random\n    let x be random()\n",
        "<t>",
    );
    assert!(!r.success, "require no debería poder escapar del sandbox");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "errs: {:?}",
        r.errors
    );
}

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

#[test]
fn llm_op_autogranted_in_run() {
    // Retrocompat: en no-secure (`run`/`conform`) `llm` se auto-concede como
    // stdout/time → los programas existentes sin `require llm` siguen andando.
    let r = run_source("let e be generate \"x\" given \"y\"\nprint(\"ok\")\n", "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["ok".to_string()]);
}

#[test]
fn llm_op_denied_inside_sandbox() {
    // El gate se COMPONE con el aislamiento del sandbox: aunque `llm` esté concedida
    // afuera (auto-grant), dentro del sandbox el CapabilitySet se vacía → denegada.
    let r = run_source(
        "let e be generate \"outside\"\nsandbox\n    let f be generate \"inside\"\n",
        "<t>",
    );
    assert!(!r.success, "el sandbox debería denegar la op LLM");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: llm")),
        "errs: {:?}",
        r.errors
    );
}

// =========================================================
// when/then inline (gap #5) — devuelve el valor de la rama
// =========================================================

#[test]
fn when_then_inline_returns_value() {
    let r = run_source(
        "let a be when 5 > 0 then \"pos\" otherwise \"neg\"\n\
         let b be when 5 < 0 then \"pos\" otherwise \"neg\"\n\
         print(a)\nprint(b)\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["pos".to_string(), "neg".to_string()]);
}

#[test]
fn when_block_form_still_works() {
    // Regresión: la forma de bloque (sin `then`) sigue funcionando.
    let r = run_source("when 1 > 0\n    print(\"yes\")\n", "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["yes".to_string()]);
}

// =========================================================
// checkpoint con expresión (gap #7) — parsea y corre (decorativo)
// =========================================================

#[test]
fn checkpoint_accepts_expression() {
    let r = run_source(
        "let i be 3\ncheckpoint \"step_\" + text(i)\nprint(\"ok\")\n",
        "<t>",
    );
    assert!(r.success, "checkpoint con expresión debería parsear y correr: {:?}", r.errors);
    assert_eq!(r.output, vec!["ok".to_string()]);
}

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
