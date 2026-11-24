//! v0.6.30: pendientes de la auditoría de v0.6.29. Un test por ítem, con el comportamiento que
//! quedó; cada uno falla con el código de v0.6.29.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
use synsema_runtime::engine::run_program;

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "audit.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let r = run_program(src, "audit.syn");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

/// Un programa con módulos en un directorio temporal propio (el contador hace único el nombre).
fn run_files(files: &[(&str, &[u8])], main: &str) -> synsema_core::interpreter::RunResult {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synsema-audit630-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in files {
        std::fs::write(dir.join(name), src).unwrap();
    }
    let path = dir.join("main.syn");
    std::fs::write(&path, main).unwrap();
    let r = run_program(main, path.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// Los avisos de `synsema check` de un programa.
fn check_warnings(src: &str) -> Vec<String> {
    let program = synsema_core::parser::parse_source(src, "w.syn").unwrap();
    let mut w = Vec::new();
    synsema_core::deprecated::check_warnings(&program, "w.syn", &mut w);
    w
}






fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn post(port: u16, body: &[u8]) -> String {
    for _ in 0..100 {
        if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
            let mut req = format!(
                "POST /j HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            req.extend_from_slice(body);
            sock.write_all(&req).unwrap();
            let mut resp = String::new();
            let _ = sock.read_to_string(&mut resp);
            if !resp.is_empty() {
                return resp;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no respondió en :{}", port);
}

// A6 — `request.json` y `json_decode(request.body)` salen del mismo parser: `-0` es `0` en los
// dos y un BOM al principio no es un 400.
#[test]
fn a6_request_json_matches_json_decode() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"POST /j\"\n        give {{\"v\": text(request.json.v), \"same\": text(request.json) == text(json_decode(request.body))}}\n",
        p = port
    );
    std::thread::spawn(move || {
        let _ = synsema_runtime::serve::run_serve_program(&prog, "a6.syn", false);
    });
    let r = post(port, br#"{"v": -0}"#);
    assert!(r.contains("{\"v\": \"0\", \"same\": true}"), "{}", r);
    let r = post(port, "\u{feff}{\"v\": 1.50}".as_bytes());
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("{\"v\": \"1.5\", \"same\": true}"), "{}", r);
    let r = post(port, br#"{"v": 115792089237316195423570985008687907853269984665640564039457584007913129639935}"#);
    assert!(r.contains("115792089237316195423570985008687907853269984665640564039457584007913129639935"), "{}", r);
    assert!(post(port, b"{\"v\": NaN}").starts_with("HTTP/1.1 400"));
}

// A7 — Parquet: una duration se escribe (INT64 con su unidad en `synsema.durations`) y vuelve
// igual; la duration de Arrow (pyarrow, polars) se lee como duration, no como un entero sin unidad.
// B1 — index_of no copia la lista: un acierto temprano es O(1), como `in` y `contains`.
#[test]
fn b1_index_of_early_hit_is_constant() {
    let t = Instant::now();
    assert_eq!(
        out("let xs be range(100000)\nlet hits be 0\neach i in range(2000)\n    set hits to hits + index_of(xs, 0)\nprint(hits)\nprint(index_of(xs, (x) => x == 3))\nprint(index_of(xs, -1))"),
        vec!["0", "3", "nothing"]
    );
    let e = t.elapsed();
    assert!(e < Duration::from_secs(2), "2000 búsquedas tardaron {:?}", e);
}

// C1 — un alias deprecado en un módulo importado avisa al cargarlo, igual que en el principal.
#[test]
fn c1_deprecated_alias_in_imported_module_warns() {
    let r = run_files(&[("lib.syn", b"export task f()\n    give eth_rpc\n")], "use \"./lib.syn\" as lib\nprint(\"ok\")\n");
    assert!(r.success, "{:?}", r.errors);
    assert!(synsema_core::deprecated::warned_at_load().contains(&"eth_rpc".to_string()));
}


// C3 — `//` como comentario: al principio de una línea es un error de parser con la pista; en
// `x // palabra` con una palabra indefinida, el error lo dice. `//` sigue siendo división entera.
#[test]
fn c3_c_style_comment_gets_a_hint() {
    let e = fails("let x be 1\n// comentario\nprint(x)\n");
    assert!(e.contains("comments in Synsema start with `--`"), "{}", e);
    let e = fails("let x be 1 // comentario\nprint(x)\n");
    assert!(e.contains("Undefined variable: 'comentario'") && e.contains("comments in Synsema start with `--`"), "{}", e);
    let e = fails("let x be 1 //comentario\nprint(x)\n");
    assert!(e.contains("Undefined variable") && !e.contains("comments"), "{}", e);
    assert_eq!(out("let comentario be 2\nprint(7 // comentario, 7 // 2, -7 // 2)"), vec!["3 3 -4"]);
}

// C4 — asignar fuera de rango dice dónde y el largo, como la lectura.
#[test]
fn c4_set_index_out_of_range_says_where() {
    let e = fails("let xs be [1, 2, 3]\nset xs[10] to 1\n");
    assert!(e.contains("audit.syn:2:") && e.contains("Index 10 out of bounds (list length 3)"), "{}", e);
    assert!(fails("let xs be [1, 2, 3]\nset xs[-4] to 1\n").contains("Index -4 out of bounds (list length 3)"));
    assert_eq!(out("let xs be [1, 2, 3]\nset xs[-1] to 9\nprint(xs)"), vec!["[1, 2, 9]"]);
}




// C8 — el aviso de `\u` sólo cuando el escape de verdad se decodifica.
#[test]
fn c8_check_unicode_escape_warning_only_when_decoded() {
    let bs = '\\';
    let warns = |lit: &str| check_warnings(&format!("print(\"{}\")\n", lit)).iter().any(|w| w.contains("is now an escape"));
    assert!(!warns(&format!("{}uD800", bs)), "un sustituto suelto queda literal");
    assert!(!warns(&format!("{}u{{110000}}", bs)), "fuera de Unicode queda literal");
    assert!(!warns(&format!("{}u{{1234567}}", bs)));
    assert!(warns(&format!("{}u00e9", bs)));
    assert!(warns(&format!("{}u{{1F600}}", bs)));
    assert!(warns(&format!("{}uD83D{}uDE00", bs, bs)));
}

// C9 — un task que escribe en su parámetro y no lo devuelve pierde la escritura (semántica de
// valor): `check` lo dice, como para `each r` + `set r[…]`.
#[test]
fn c9_check_task_param_write_lost() {
    let warns = |src: &str| check_warnings(src).iter().any(|w| w.contains("own copy of the argument"));
    assert!(warns("task touch(cfg)\n    set cfg[\"x\"] to 1\nlet c be {\"x\": 0}\ntouch(c)\n"));
    assert!(warns("task touch(cfg, n)\n    set cfg.x to n\n    give n\n"));
    // No avisa: lo devuelve, lo pasa a otra llamada, lo religa o lee lo que escribió.
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    give cfg\n"));
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    print(cfg)\n"));
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    give cfg[\"x\"] + 1\n"));
    assert!(!warns("task touch(cfg)\n    set cfg to {}\n    give 1\n"));
    assert_eq!(out("task touch(cfg)\n    set cfg[\"x\"] to 1\nlet c be {\"x\": 0}\ntouch(c)\nprint(c)"), vec!["{x: 0}"]);
}

// C10 — la pista para un enum no exportado es `export enum`.
#[test]
fn c10_module_hint_for_enum() {
    let lib: &[u8] = b"enum Color\n    red\n    green\ntask helper()\n    give 1\nlet k be 2\nexport task f()\n    give 1\n";
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.Color)\n").errors.join("\n");
    assert!(e.contains("write `export enum Color` there"), "{}", e);
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.helper)\n").errors.join("\n");
    assert!(e.contains("write `export task helper` there"), "{}", e);
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.k)\n").errors.join("\n");
    assert!(e.contains("export let"), "{}", e);
}



// C3 (segunda vuelta) — un comentario de C de varias palabras (el caso común) no parsea por
// lo que sigue al `//`; el error lo nombra igual. Un `//` dentro de un string o después de `--`
// no cuenta.
#[test]
fn c3b_c_style_comment_hint_on_parse_and_lex_errors() {
    for src in [
        "let x be 10 // this is a note\nprint(x)\n",
        "let x be 10\n    // indented note\nprint(x)\n",
        "print(1) // don't\n",
        "let x be 10 // TODO: fix\n",
    ] {
        let e = fails(src);
        assert!(e.contains("comments in Synsema start with `--`"), "{:?}: {}", src, e);
    }
    let e = fails("print(\"a // b\" is)\n");
    assert!(!e.contains("comments in Synsema"), "{}", e);
    assert_eq!(out("print(\"https://x.com\") -- note // not code"), vec!["https://x.com"]);
}
