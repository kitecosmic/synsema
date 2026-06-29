//! DE-029 — el provider LLM real debe cablearse también bajo `serve` (no solo en `run`).
//! Bug original: `wire_real_llm_provider` se llamaba en el camino `run` pero NO en
//! `build_base_interp` de serve → `llm_available()` era `false` bajo serve pese a tener
//! provider configurado, y reason/decide/generate/llm_step caían a placeholders.
//!
//! Este test NO hace llamadas HTTP reales: solo verifica `llm_available()` (que chequea si
//! el callback quedó instalado). Con un provider configurado por env, debe ser `true` bajo
//! serve. Vive en su propio binario de test (proceso aislado) porque muta variables de
//! entorno del proceso, que son globales.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

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

/// Con un provider configurado por env (`SYNSEMA_LLM_PROVIDER=openai` + `OPENAI_API_KEY`),
/// `llm_available()` debe ser `true` dentro de un route handler. Antes del fix era `false`
/// (el callback nunca se instalaba en serve). No se invoca ninguna op LLM → sin HTTP.
#[test]
fn llm_available_is_true_under_serve_with_provider() {
    // Configurar un provider ANTES de arrancar el server (la clave es falsa: nunca se usa
    // para una llamada real, solo gatea la instalación del callback).
    std::env::set_var("SYNSEMA_LLM_PROVIDER", "openai");
    std::env::set_var("OPENAI_API_KEY", "sk-test-fake-not-used");

    let port = free_port();
    let prog = format!(
        r#"require llm
require serve({p})
serve on {p}
    route "GET /llm"
        give {{"live": llm_available()}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "<stdin>", false);
    });
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

    let resp = get(port, "/llm");
    assert!(resp.starts_with("HTTP/1.1 200"), "esperaba 200, llegó:\n{}", resp);
    assert!(
        resp.contains("\"live\": true"),
        "esperaba `\"live\": true` (provider cableado en serve), llegó:\n{}",
        resp
    );
}
