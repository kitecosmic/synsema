//! DE-033 — identidad de módulos en snapshot/rebuild bajo `serve` y `parallel_map`.
//!
//! Bug original (v2 del spec, sondas del 2026-07-03): con un DIAMANTE de imports
//! (B y C importan D — la topología normal de cualquier app con un módulo
//! `util`/`config`/`state` compartido), bajo `run` el `module_cache` de core garantiza
//! UN solo `module_env` de D, pero el snapshot/rebuild de serve/parallel_map
//! reconstruía D como N envs DISTINTOS: `b.bwrite("hello")` escribía en la copia 1 y
//! `c.cread()` leía "init" de la copia 2 — divergencia run ≠ serve/parallel_map SIN
//! ningún error. Además, el entry del alias (`d.STATE`) se materializaba por separado
//! del binding `STATE` del env → mutar vía el alias no lo veían las tasks del módulo.
//!
//! El fix: identidad por ID estable (el `name` del `module_env`, "module:<resolved>") —
//! el env viaja UNA vez por árbol de snapshot y un `ModuleRegistry` per-rebuild hace
//! que toda referencia resuelva al MISMO env; los exports del alias se cosechan del env
//! reconstruido (identidad alias↔env, como `load_module_inner`).
//!
//! El ciclo A↔B por `use` NO llega vivo a este código: core lo rechaza al cargar
//! ("circular import") — cubierto por `circular_import_errors` en
//! `synsema-core/src/interpreter.rs` (P1 del spec).
//!
//! Fixtures: `tests/fixtures/diamond_{b,c,d}.syn` (calcadas de las sondas de §1).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

/// Ruta absoluta (en el dir de fixtures) usada como archivo importador, para que
/// `use "./diamond_b.syn"` resuelva contra las fixtures sin depender del CWD.
fn importer_path() -> String {
    format!("{}/tests/fixtures/diamond_main.syn", env!("CARGO_MANIFEST_DIR"))
}

/// Estado a un temp dir: estos tests no usan persistencia y no deben crear un .db
/// en el árbol de fixtures.
fn isolate_state_dir() {
    std::env::set_var(
        "SYNSEMA_STATE_DIR",
        std::env::temp_dir().join("synsema_test_state"),
    );
}

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

/// P2 bajo `parallel_map`: una task top-level escribe vía B y lee vía C. Con el
/// diamante roto (dos copias de D en el worker), devolvía `[init]`; con la identidad
/// por ID + registro, B y C comparten UN solo D → `[hello]`, igual que bajo `run`.
#[test]
fn parallel_map_diamond_shares_module_state() {
    isolate_state_dir();
    let src = "\
use \"./diamond_b.syn\" as b
use \"./diamond_c.syn\" as c
task rt(x)
    let w be b.bwrite(x)
    give c.cread()
print(text(parallel_map(rt, [\"hello\"])))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[hello]".to_string()]);
}

/// P2 bajo `serve`: un route handler escribe vía B y lee vía C en el mismo request.
/// Antes devolvía `{"r": "init"}` (D reconstruido dos veces por el rebuild del
/// worker); ahora `{"r": "hello"}`.
#[test]
fn serve_diamond_shares_module_state() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
use "./diamond_b.syn" as b
use "./diamond_c.syn" as c
serve on {p}
    route "GET /diamond"
        let w be b.bwrite("hello")
        give {{"r": c.cread()}}
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
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let resp = get(port, "/diamond");
    assert!(resp.starts_with("HTTP/1.1 200"), "/diamond: esperaba 200, llegó:\n{}", resp);
    assert!(
        resp.contains("\"r\": \"hello\""),
        "/diamond: la escritura vía b no la vio c (¿dos copias de D?), llegó:\n{}",
        resp
    );
}

/// P3 — identidad alias↔env: mutar `d.STATE["v"]` vía el ALIAS y leer vía una TASK del
/// módulo deben ver el mismo objeto (bajo `run` el alias se cosecha con `env_get` del
/// module_env). Antes, el rebuild materializaba el entry del alias por separado → la
/// escritura por el alias no la veía `read_d` y devolvía el valor del snapshot.
#[test]
fn parallel_map_alias_env_identity() {
    isolate_state_dir();
    let src = "\
use \"./diamond_d.syn\" as d
task wr(x)
    set d.STATE[\"v\"] to x
    give d.read_d()
print(text(parallel_map(wr, [\"zz\"])))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[zz]".to_string()]);
}

/// Task de módulo aplicada DIRECTO a `parallel_map` cuando el módulo TAMBIÉN es global:
/// ejercita la rama registry-first de `reconstruct_task` (el `module_env` de la task es
/// LA MISMA instancia que la del alias global `b`, no una segunda copia). El resultado
/// observable es el de siempre (`bwrite` da "w"); la identidad profunda la cubren los
/// tests del diamante (D compartido vía registry en ambos caminos).
#[test]
fn parallel_map_module_task_direct_uses_global_module_env() {
    isolate_state_dir();
    let src = "\
use \"./diamond_b.syn\" as b
print(text(parallel_map(b.bwrite, [\"z\"])))
";
    let r = run_source(src, &importer_path());
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[w]".to_string()]);
}
