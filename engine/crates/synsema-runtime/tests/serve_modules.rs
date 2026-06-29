//! DE-027 — los módulos deben sobrevivir al snapshot/rebuild de `serve` y `parallel_map`.
//!
//! Bug original: bajo `serve` (y `parallel_map`), una task exportada de un módulo que
//! llama a una hermana por su nombre simple daba `Undefined variable`, porque el snapshot
//! solo guardaba el Map de exports y al reconstruir las tasks cerraban sobre el global del
//! request (donde la hermana no existe). El fix snapshotea el `module_env` COMPLETO y, al
//! reconstruir, recrea un `module_env` compartido (hijo del global) que TODAS las tasks
//! del módulo capturan — reproduciendo `load_module_inner` de core.
//!
//! Fixture del módulo: `tests/fixtures/serve_mod_sibling.syn`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

/// Ruta absoluta (en el dir de fixtures) usada como archivo importador, para que el
/// `use "./serve_mod_sibling.syn"` resuelva contra el fixture sin depender del CWD.
fn importer_path() -> String {
    format!("{}/tests/fixtures/serve_modbug_main.syn", env!("CARGO_MANIFEST_DIR"))
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_serve(port: u16) {
    let prog = format!(
        r#"require serve({p})
use "./serve_mod_sibling.syn" as m
serve on {p}
    route "GET /direct"
        give {{"r": m.inner("a")}}
    route "GET /sibling"
        give {{"r": m.outer("a")}}
    route "GET /internal"
        give {{"r": m.via_internal("a")}}
"#,
        p = port
    );
    let importer = importer_path();
    thread::spawn(move || {
        let _ = run_serve_program(&prog, &importer, false);
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

fn assert_ok_body(resp: &str, expected_fragment: &str, label: &str) {
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "{}: esperaba 200, llegó:\n{}",
        label,
        resp
    );
    assert!(
        resp.contains(expected_fragment),
        "{}: esperaba el fragmento `{}` en el body, llegó:\n{}",
        label,
        expected_fragment,
        resp
    );
}

/// El corazón de DE-027 bajo `serve`: una task de módulo llama a una hermana exportada
/// (`outer`→`inner`) y a una hermana NO exportada (`via_internal`→`helper`). Antes del fix,
/// `/sibling` y `/internal` daban 500 `Undefined variable`.
#[test]
fn serve_module_sibling_call_resolves() {
    let port = free_port();
    start_serve(port);

    // Caso de control: acceso directo a una export sin llamada a hermana (ya andaba).
    assert_ok_body(&get(port, "/direct"), "\"r\": \"a!\"", "/direct");
    // Export → hermana EXPORTADA por nombre simple.
    assert_ok_body(&get(port, "/sibling"), "\"r\": \"a!\"", "/sibling");
    // Export → hermana NO exportada por nombre simple (el caso real de Alfred).
    assert_ok_body(&get(port, "/internal"), "\"r\": \"h:a\"", "/internal");
}

/// Mismo snapshot/rebuild de globales, vía `parallel_map`: una task top-level (cierra
/// sobre el global) invoca dentro a `m.outer`, que a su vez llama a su hermana `inner`.
/// Antes del fix, el módulo reconstruido en el worker perdía el `module_env` y `inner` no
/// resolvía.
#[test]
fn parallel_map_module_sibling_call_resolves() {
    let src = "\
use \"./serve_mod_sibling.syn\" as m
task call_outer(x)
    give m.outer(x)
let r be parallel_map(call_outer, [\"a\", \"b\", \"c\"])
print(text(r))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[a!, b!, c!]".to_string()]);
}

/// DE-030: pasar una task de módulo DIRECTO a `parallel_map` (sin wrapper top-level). La
/// task aplicada viaja por `TaskSnapshot`, no por el snapshot de globales; antes perdía su
/// `module_env` (cerraba sobre el global del worker) y una llamada a una hermana daba
/// `Undefined variable`. Cubre hermana exportada (`outer`→`inner`) y NO exportada
/// (`via_internal`→`helper`).
#[test]
fn parallel_map_module_task_passed_directly() {
    // Estado a un temp (DE-031 lo crearía en fixtures): este test no usa persistencia.
    std::env::set_var(
        "SYNSEMA_STATE_DIR",
        std::env::temp_dir().join("synsema_test_state"),
    );
    let src = "\
use \"./serve_mod_sibling.syn\" as m
let a be parallel_map(m.outer, [\"a\", \"b\"])
let b be parallel_map(m.via_internal, [\"x\", \"y\"])
print(text(a))
print(text(b))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["[a!, b!]".to_string(), "[h:x, h:y]".to_string()]
    );
}

fn start_serve_selfmap(port: u16) {
    // `m.dispatch` referencia el sibling `let MAP` (auto-referencial) y despacha; `m.TOOLS`
    // expone ese MAP para acceso directo. Ambos cierran sobre el module_env del módulo.
    let prog = format!(
        r#"require serve({p})
use "./serve_mod_selfmap.syn" as m
serve on {p}
    route "GET /dispatch"
        give {{"r": m.dispatch("a")}}
    route "GET /direct"
        give {{"r": m.TOOLS.t("a")}}
"#,
        p = port
    );
    let importer = importer_path();
    thread::spawn(move || {
        let _ = run_serve_program(&prog, &importer, false);
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

/// DE-032: un `let MAP` auto-referencial del módulo (sus tasks llaman a hermanas). Antes,
/// bajo serve ese map se reconstruía con un module_env VACÍO → `Undefined variable:
/// 'helper'`. `/dispatch` referencia el sibling MAP desde una export; `/direct` accede al
/// MAP exportado y lo indexa. Ambos deben dar "h:a".
#[test]
fn serve_module_selfref_map_resolves() {
    let port = free_port();
    start_serve_selfmap(port);
    assert_ok_body(&get(port, "/dispatch"), "\"r\": \"h:a\"", "/dispatch");
    assert_ok_body(&get(port, "/direct"), "\"r\": \"h:a\"", "/direct");
}

/// DE-032 vía `parallel_map`: aplicar DIRECTO una export que usa el MAP auto-referencial.
/// El snapshot de la task aplicada (DE-030) lleva el module_env, cuyo MAP self-ref se
/// reconstruye cerrando sobre el mismo module_env → `dispatch` resuelve sus hermanas.
#[test]
fn parallel_map_module_selfref_dispatch() {
    std::env::set_var(
        "SYNSEMA_STATE_DIR",
        std::env::temp_dir().join("synsema_test_state"),
    );
    let src = "\
use \"./serve_mod_selfmap.syn\" as m
print(text(parallel_map(m.dispatch, [\"a\", \"b\"])))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[h:a, h:b]".to_string()]);
}
