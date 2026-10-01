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

/// Lo que un handler escribe en una GLOBAL vale durante esa request y no en la siguiente
/// (serve.md: "A `set globalVar to ...` inside a route handler does NOT persist"). Hasta
/// v0.6.37 el worker reusado conservaba la escritura: la misma GET daba respuestas distintas
/// según qué worker la atendía, y lo que guardaba una request lo veía otra.
#[test]
fn writes_to_globals_do_not_outlive_the_request() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
let rows be [{{"id": 1, "name": "orig"}}]
let counter be 0
let tags be ["a"]
let cfg be {{"mode": "base", "limits": [1, 2]}}
let trail be "t"
let nums be [0]
task bump()
    set counter to counter + 100
    set cfg.limits[0] to 99
    give counter
serve on {p}
    route "GET /mutpath"
        set rows[0].name to "cambiado"
        give rows[0].name
    route "GET /mutappend"
        set tags to append(tags, "b")
        set tags to append(tags, "c")
        give length(tags)
    route "GET /mutset"
        set counter to counter + 1
        set cfg.mode to "otro"
        give {{"c": counter, "m": cfg.mode}}
    route "GET /muttask"
        give {{"b": bump(), "l": cfg.limits[0]}}
    route "GET /hot"
        each i in range(0, 5000)
            set tags to append(tags, "x")
            set nums to append(nums, i)
            set rows[0].name to "hot"
            set cfg.limits[1] to i
            set trail to trail + "."
            set counter to counter + 1
        give {{"t": length(tags), "n": length(nums), "c": counter, "l": length(trail), "k": cfg.limits[1]}}
    route "GET /get"
        give {{"name": rows[0].name, "tags": length(tags), "counter": counter, "mode": cfg.mode, "limit": cfg.limits[0], "trail": length(trail), "nums": length(nums), "k": cfg.limits[1]}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_isolation_globals.syn", false);
    });
    let mut up = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "el server no quedó listo en :{}", port);
    let body = |resp: &str| resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    // Dentro de la request la escritura se ve; después, en ningún worker.
    let original = r#"{"name": "orig", "tags": 1, "counter": 0, "mode": "base", "limit": 1, "trail": 1, "nums": 1, "k": 2}"#;
    for round in 0..12 {
        assert_eq!(body(&get(port, "/mutpath")), r#""cambiado""#, "ronda {}", round);
        assert_eq!(body(&get(port, "/mutappend")), "3", "ronda {}", round);
        assert_eq!(body(&get(port, "/mutset")), r#"{"c": 1, "m": "otro"}"#, "ronda {}", round);
        assert_eq!(body(&get(port, "/muttask")), r#"{"b": 100, "l": 99}"#, "ronda {}", round);
        assert_eq!(body(&get(port, "/get")), original, "ronda {}", round);
        // Bucles calientes (código nativo, vías en el lugar de la VM y del JIT): lo mismo.
        assert_eq!(body(&get(port, "/hot")), r#"{"t": 5001, "n": 5001, "c": 5000, "l": 5001, "k": 4999}"#, "ronda {}", round);
        assert_eq!(body(&get(port, "/get")), original, "ronda {} tras /hot", round);
    }
    // Concurrentes: cada worker del pool tiene que dar lo mismo.
    let mut hs = Vec::new();
    for _ in 0..32 {
        hs.push(thread::spawn(move || {
            let _ = get(port, "/mutset");
            get(port, "/get")
        }));
    }
    for h in hs {
        assert_eq!(body(&h.join().unwrap()), original);
    }
}

/// Lo mismo para el estado de un MÓDULO importado: una task del módulo que escribe sus variables
/// (`hits`, `seen`) no deja nada para la request siguiente (hasta v0.6.37 se acumulaba: 2, 3, 4…).
#[test]
fn module_state_does_not_outlive_the_request() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
use "./serve_isolation_mod.syn" as m
serve on {p}
    route "GET /bump"
        let a be m.bump("a")
        give m.bump("b")
"#,
        p = port
    );
    let importer = format!("{}/tests/fixtures/serve_isolation_main.syn", env!("CARGO_MANIFEST_DIR"));
    thread::spawn(move || {
        let _ = run_serve_program(&prog, &importer, false);
    });
    let mut up = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "el server no quedó listo en :{}", port);
    for round in 0..16 {
        let resp = get(port, "/bump");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        // Dentro de la request las dos llamadas se ven (2); entre requests, nada.
        assert_eq!(body, r#"{"hits": 2, "seen": 2}"#, "ronda {}", round);
    }
}
