//! Auditoría de R2 (specs/modelo-memoria-regiones.md): leer una global congelada nunca escribe.
//!
//! Las listas sin caja (`range(...)`, enteros o floats a 8 B por elemento) se congelan tal cual. Hasta
//! la auditoría, leerlas con `count`, `in`, `+` o un índice desde un worker de `parallel_map` o de
//! `serve` pasaba la lista a valores EN EL LUGAR (`list_values`) y el motor entraba en pánico: "an
//! immortal value cannot be written". Estos tests corren programas reales (parser + runtime) por los
//! dos caminos que congelan: `parallel_map` (con alcance) y `serve` (para siempre).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Lecturas de globales sin caja dentro de la task (VM / nivel nativo) y un item sin caja.
#[test]
fn parallel_map_reads_frozen_unboxed_globals() {
    let src = r#"let IDS be range(0, 100)
let FL be [1.5, 2.5, 3.5]
task f(x)
    give [count(IDS), 5 in IDS, 500 in IDS, length(IDS + IDS), IDS[3], mean(FL), length(slice(IDS, 10, 20)), x]
print(parallel_map(f, [1, 2]))
print(parallel_map((r) => r, [range(0, 3)]))
print(parallel_map((r) => count(r) + r[1], [range(0, 3), range(5, 9)]))
"#;
    let r = synsema_runtime::engine::run_program_ceiled_opts(src, "frozen_reads.syn", None, false);
    assert!(r.success, "{:?} {:?}", r.output, r.errors);
    assert_eq!(
        r.output,
        vec![
            "[[100, true, false, 200, 3, 2.5, 10, 1], [100, true, false, 200, 3, 2.5, 10, 2]]".to_string(),
            "[[0, 1, 2]]".to_string(),
            "[4, 10]".to_string(),
        ]
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

/// Las globales de `serve` se congelan para siempre: una ruta que lee un `range` global.
#[test]
fn serve_routes_read_frozen_unboxed_globals() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
let IDS be range(0, 100)
serve on {p}
    route "GET /in"
        give {{"in": 5 in IDS, "n": count(IDS), "sum": length(IDS + IDS), "third": IDS[3]}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = synsema_runtime::serve::run_serve_program(&prog, "frozen_reads_serve.syn", false);
    });
    let mut ready = false;
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            thread::sleep(Duration::from_millis(150));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "el server no quedó listo en :{}", port);
    // Varias veces: requests que caen en distintos workers.
    for _ in 0..8 {
        let resp = get(port, "/in");
        assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
        for want in ["\"in\": true", "\"n\": 100", "\"sum\": 200", "\"third\": 3"] {
            assert!(resp.contains(want), "falta {} en {}", want, resp);
        }
    }
}

/// Casi todas las lecturas del lenguaje sobre listas congeladas (sin caja y de valores) y un mapa, desde
/// los workers de `parallel_map`: el resultado es el mismo que sin congelar (corriendo el cuerpo en
/// el hilo principal) y nada entra en pánico.
#[test]
fn every_read_of_frozen_globals_matches_the_unfrozen_run() {
    let reads = r#"task lee(z)
    let r be []
    set r to append(r, count(IDS))
    set r to append(r, length(IDS))
    set r to append(r, 5 in IDS)
    set r to append(r, length(IDS + IDS))
    set r to append(r, mean(FL))
    set r to append(r, sum(IDS))
    set r to append(r, min(IDS))
    set r to append(r, max(FL))
    set r to append(r, IDS[3])
    set r to append(r, FL[-1])
    set r to append(r, length(sort(IDS)))
    set r to append(r, length(reverse(IDS)))
    set r to append(r, length(unique(IDS)))
    set r to append(r, length(apply(IDS, (x) => x * 2)))
    set r to append(r, length(where(IDS, (x) => x > 50)))
    set r to append(r, reduce(IDS, (a, x) => a + x, 0))
    set r to append(r, text(FL))
    set r to append(r, join(VS, ","))
    set r to append(r, length(chunk(IDS, 7)))
    set r to append(r, index_of(IDS, 42))
    set r to append(r, length(slice(IDS, 10, 20)))
    set r to append(r, IDS == IDS)
    set r to append(r, count(M["ids"]))
    set r to append(r, 3 in M["ids"])
    set r to append(r, length(keys(M)))
    set r to append(r, json_encode(M))
    set r to append(r, json_encode(IDS))
    each x in FL
        set r to append(r, x)
    give r
"#;
    let src = format!(
        "let IDS be range(0, 100)\nlet FL be [1.5, 2.5, 3.5]\nlet VS be [\"a\", \"b\", 3]\nlet M be {{\"ids\": range(0, 5), \"n\": 1}}\n{}print(lee(0))\nprint(parallel_map(lee, [1, 2, 3]))\n",
        reads
    );
    let r = synsema_runtime::engine::run_program_ceiled_opts(&src, "frozen_reads_all.syn", None, false);
    assert!(r.success, "{:?} {:?}", r.output, r.errors);
    let unfrozen = &r.output[0];
    let workers = &r.output[1];
    assert_eq!(*workers, format!("[{}, {}, {}]", unfrozen, unfrozen, unfrozen));
}
