//! DE-028 — el `progress` debe sobrevivir entre requests bajo `serve` (como ya hace la
//! memoria). Bug original: cada intérprete de request tenía su propio `ProgressManager`
//! fresco (reseteado por `reset_for_request`), así que un plan creado en `/plan-create`
//! no existía en `/plan-read` → `resume_point` daba `nothing` y el ciclo PLAN→ADVANCE
//! crasheaba (`Cannot get length of nothing` aguas abajo).
//!
//! Fix: un `SharedProgressStore = Arc<Mutex<ProgressManager>>` compartido entre todos los
//! handlers/requests + `register_serve_progress_builtins` (gemelo de la memoria).
//!
//! Filename `<stdin>` → sin persistencia a disco: este test verifica el SHARING en memoria
//! (el must-have), hermético y sin tocar el filesystem.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(port: u16) {
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /plan-create"
        create_progress("myplan", ["uno", "dos", "tres"])
        give {{"created": true, "resume_mismo_request": resume_point("myplan")}}
    route "GET /plan-read"
        give {{"resume_otro_request": resume_point("myplan")}}
    route "GET /plan-advance"
        let rp be resume_point("myplan")
        start_step("myplan", rp)
        complete_step("myplan", rp, "done")
        give {{"completed": rp, "next": resume_point("myplan")}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "<stdin>", false);
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

fn assert_contains(resp: &str, fragment: &str, label: &str) {
    assert!(resp.starts_with("HTTP/1.1 200"), "{}: esperaba 200, llegó:\n{}", label, resp);
    assert!(
        resp.contains(fragment),
        "{}: esperaba `{}` en el body, llegó:\n{}",
        label,
        fragment,
        resp
    );
}

/// El corazón de DE-028: un plan creado en un request es legible (y avanzable) en los
/// siguientes. Antes del fix, `/plan-read` daba `null` y `/plan-advance` crasheaba.
#[test]
fn progress_survives_across_requests() {
    let port = free_port();
    start(port);

    // Crear el plan en un request: resume del MISMO request = primer paso.
    let create = get(port, "/plan-create");
    assert_contains(&create, "\"created\": true", "/plan-create");
    assert_contains(&create, "\"resume_mismo_request\": \"uno\"", "/plan-create");

    // Leerlo en OTRO request: antes del fix daba null; ahora persiste el mismo "uno".
    assert_contains(&get(port, "/plan-read"), "\"resume_otro_request\": \"uno\"", "/plan-read");

    // Avanzar un paso en otro request: completa "uno", el resume pasa a "dos".
    let adv = get(port, "/plan-advance");
    assert_contains(&adv, "\"completed\": \"uno\"", "/plan-advance");
    assert_contains(&adv, "\"next\": \"dos\"", "/plan-advance");

    // El avance también persiste: un request posterior ve "dos" como resume.
    assert_contains(&get(port, "/plan-read"), "\"resume_otro_request\": \"dos\"", "/plan-read#2");
}
