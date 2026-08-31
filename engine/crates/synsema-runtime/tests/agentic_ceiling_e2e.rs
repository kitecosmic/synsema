//! Techo del host bajo `serve` (`synsema serve --sandbox | --cap-set`), spec
//! `agentic-apps-gaps.md` §7: un handler Y un agente spawneado desde un handler no
//! pueden exceder lo que el operador fijó, aunque su cuerpo declare `require`.
//!
//! Vive en su propio binario de test: el techo de serve es política del PROCESO
//! (`OnceLock`), y no debe contaminar a los demás e2e del runtime.
//!
//! También verifica que el agente spawneado desde un handler nace con el wiring de
//! serve (`state_*` compartido) y queda observable con `agents()`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_capabilities::model::{Capability, CapabilityType};
use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..100 {
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
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn shell() -> &'static str {
    if cfg!(windows) {
        "cmd"
    } else {
        "sh"
    }
}

#[test]
fn host_ceiling_binds_the_whole_serve_under_the_host_ceiling() {
    // UN solo serve por proceso: `SERVE_CEILING` es un `OnceLock` (política del proceso;
    // en producción un `synsema serve` = un proceso = un techo). Este test cubre, contra
    // ese único serve, las tres formas en que el programa podría intentar exceder el techo:
    //   (1) el PREÁMBULO (statements antes de `serve on`) — regresión de la auditoría 2026-08-30;
    //   (2) un HANDLER, en el primer request Y en los siguientes (reúso de worker, §0 spec);
    //   (3) un AGENTE spawneado desde un handler.
    let port = free_port();
    let sh = shell();
    let run_call = if cfg!(windows) {
        "run(\"cmd\", [\"/C\", \"echo PWNED\"])"
    } else {
        "run(\"sh\", [\"-c\", \"echo PWNED\"])"
    };
    let prog = format!(
        r#"require serve({p})
require time

try
    let pr be {run_call}
    state_set("preamble", pr["stdout"])
recover e
    state_set("preamble", "denied")

agent Runner
    require exec("{sh}")
    let r be {run_call}
    state_set("agent_ran", r["stdout"])

serve on {p}
    route "GET /exec"
        require exec("{sh}")
        let r be {run_call}
        give {{"out": r["stdout"]}}

    route "GET /spawn"
        spawn Runner
        give {{"spawned": true}}

    route "GET /state"
        give {{"preamble": state_get("preamble"), "agent_ran": state_get("agent_ran"), "agents": agents()}}
"#,
        p = port,
        sh = sh,
        run_call = run_call
    );
    // Techo: stdout + time + el serve del puerto — SIN exec.
    let ceiling = vec![
        Capability::new(CapabilityType::Stdout, None),
        Capability::new(CapabilityType::Time, None),
        Capability::new(CapabilityType::Serve, Some(port.to_string())),
    ];
    let ov = ServeOverrides { ceiling: Some(ceiling), ..Default::default() };
    thread::spawn(move || {
        let r = run_serve_program_with_overrides(&prog, "<ceiling>", false, ov);
        if !r.success {
            eprintln!("serve terminó con errores: {:?}", r.errors);
        }
    });
    wait_ready(port);

    // (1) El PREÁMBULO no pudo `run`: el techo lo denegó (sin él, escapaba serve --sandbox).
    let st0 = get(port, "/state");
    assert!(!st0.contains("PWNED"), "el preámbulo escapó el techo: {}", st0);
    assert!(st0.contains("\"preamble\":\"denied\"") || st0.contains("\"preamble\": \"denied\""), "el preámbulo debía ser denegado: {}", st0);

    // (2) El handler no puede `require exec` — ni en el primer request NI en los siguientes
    //     (reúso de worker: el pool tiene tantos workers como cores, así que se pega
    //     `workers + 2` veces para forzar la reutilización).
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).max(2);
    for i in 0..(workers + 2) {
        let r = get(port, "/exec");
        assert_eq!(status(&r), 500, "request #{} al handler: el techo se perdió: {}", i + 1, r);
        assert!(!r.contains("PWNED"), "request #{}: {}", i + 1, r);
        let low = r.to_lowercase();
        assert!(low.contains("exec") && (low.contains("ceiling") || low.contains("not permitted") || low.contains("denied") || low.contains("capability")), "{}", r);
    }

    // (3) El agente spawneado desde el handler tampoco: termina en error, visible en agents().
    let s = get(port, "/spawn");
    assert_eq!(status(&s), 200, "{}", s);
    let mut seen_error = false;
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(100));
        let st = get(port, "/state");
        if st.contains("\"state\":\"error\"") || st.contains("\"state\": \"error\"") {
            assert!(st.contains("\"agent_ran\":null") || st.contains("\"agent_ran\": null"), "el agente NO ejecutó: {}", st);
            let low = st.to_lowercase();
            assert!(low.contains("exec"), "el error nombra la capability: {}", st);
            seen_error = true;
            break;
        }
    }
    assert!(seen_error, "el agente debía fallar por el techo del host");
}
