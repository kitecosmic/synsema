//! Los handlers de `serve` corren en la VM y sus bucles en nativo (v0.6.39); el tree-walker sigue
//! siendo la referencia. Este diferencial levanta el MISMO programa dos veces —un server con los
//! intérpretes en modo referencia y otro con la VM y el nivel nativo ansioso— y compara cada
//! respuesta, incluido `steps()`. Las rutas leen y escriben globales del programa (que viven un
//! entorno arriba del cuerpo de la ruta) por todas las vías: escalares, floats, `append`, `set` con
//! camino, texto que crece, tasks y lambdas que las leen, un nombre que la request tapa, salidas
//! tempranas y errores. Cada ruta se pide varias veces: el nativo entra desde la segunda.
//!
//! El modo referencia se fija al crear cada intérprete: el server de referencia arranca y atiende
//! todas sus requests antes de apagar el modo y levantar el otro.

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
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    // Status + cuerpo (los headers llevan la fecha).
    let status = resp.lines().next().unwrap_or("").to_string();
    format!("{} {}", status, resp.split("\r\n\r\n").nth(1).unwrap_or(""))
}

const ROUTES: &[&str] = &[
    "/int", "/float", "/scalar", "/append", "/path", "/text", "/task", "/lambda", "/shadow", "/shadow?s=1",
    "/each_global", "/nested", "/early", "/stop", "/error", "/map_dict", "/floats_list", "/count_write",
];

fn program(port: u16) -> String {
    format!(
        r#"require serve({p})
let K be 7
let F be 0.5
let N be 3000
let counter be 0
let items be [1, 2, 3]
let cfg be {{"a": {{"b": [1, 2, 3]}}, "n": 0}}
let trail be "t"
let nums be range(0, 200)
let fl be [0.5, 1.5, 2.5]
let dict be {{}}
task weight(i)
    give i % K + counter
serve on {p}
    route "GET /int"
        let t be 0
        each i in range(0, N)
            set t to t + i % K
        give {{"r": t, "s": steps()}}
    route "GET /float"
        let t be 0.0
        each i in range(0, N)
            set t to t + F * i
        give {{"r": t, "s": steps()}}
    route "GET /scalar"
        each i in range(0, N)
            set counter to counter + 1
        give {{"r": counter, "s": steps()}}
    route "GET /append"
        each i in range(0, N)
            set items to append(items, i)
        give {{"r": length(items), "last": items[length(items) - 1], "s": steps()}}
    route "GET /path"
        each i in range(0, N)
            set cfg.a.b[1] to cfg.a.b[1] + i
            set cfg.n to i
        give {{"r": cfg, "s": steps()}}
    route "GET /text"
        each i in range(0, 300)
            set trail to trail + "."
        give {{"r": length(trail), "s": steps()}}
    route "GET /task"
        let t be 0
        each i in range(0, N)
            set t to t + weight(i)
        give {{"r": t, "s": steps()}}
    route "GET /lambda"
        let ys be apply(nums, (v) => v * K + F)
        let zs be where(nums, (v) => v % K == 0)
        give {{"r": [length(ys), ys[10], length(zs)], "s": steps()}}
    route "GET /shadow"
        let t be 0
        when get(query, "s", "0") == "1"
            let K be 100
        each i in range(0, N)
            set t to t + K
        give {{"r": t, "s": steps()}}
    route "GET /each_global"
        let t be 0
        each v in nums
            set t to t + v * K
        give {{"r": t, "s": steps()}}
    route "GET /nested"
        let t be 0
        each i in range(0, 60)
            each j in range(0, 60)
                set t to t + (i * j) % K
        give {{"r": t, "s": steps()}}
    route "GET /early"
        each i in range(0, N)
            when i == 1234
                give {{"r": i * K, "s": steps()}}
        give {{"r": -1}}
    route "GET /stop"
        let t be 0
        each i in range(0, N)
            when i == 777
                stop
            set t to t + K
        give {{"r": t, "s": steps()}}
    route "GET /error"
        let t be 0
        each i in range(0, N)
            set t to t + K // (1000 - i)
        give {{"r": t}}
    route "GET /map_dict"
        each i in range(0, 300)
            set dict["k" + text(i % 40)] to get(dict, "k" + text(i % 40), 0) + i
        give {{"r": length(keys(dict)), "k3": dict["k3"], "s": steps()}}
    route "GET /floats_list"
        let t be 0.0
        each i in range(0, N)
            set t to t + fl[i % 3] * F
        give {{"r": t, "s": steps()}}
    route "GET /count_write"
        let t be 0
        each i in range(0, N)
            set counter to counter + K
            set t to t + counter
        give {{"r": [t, counter], "s": steps()}}
"#,
        p = port
    )
}

fn serve_and_collect(rounds: usize) -> Vec<String> {
    let port = free_port();
    let prog = program(port);
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "serve_handlers_reference.syn", false);
    });
    let mut up = false;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            up = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "el server no quedó listo en :{}", port);
    let mut out = Vec::new();
    for round in 0..rounds {
        for r in ROUTES {
            out.push(format!("ronda {} {} → {}", round, r, get(port, r)));
        }
    }
    out
}

#[test]
fn handlers_in_the_vm_match_the_reference() {
    // Un solo worker: las rondas caen en el mismo intérprete, así que una request ve el código que
    // compiló otra (lo que hay que probar: p. ej. un nombre tapado después de compilar). El pool se
    // dimensiona una vez por proceso, con el primer server; este archivo tiene un solo test.
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "1");
    synsema_jit::install();
    synsema_core::native_tier::set_eager(true);

    synsema_core::interpreter::set_reference_mode(true);
    let reference = serve_and_collect(4);
    synsema_core::interpreter::set_reference_mode(false);

    let before = synsema_core::native_tier::stats();
    let fast = serve_and_collect(4);
    let after = synsema_core::native_tier::stats();

    let diffs: Vec<String> = reference
        .iter()
        .zip(&fast)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| format!("referencia: {}\nVM/nativo:  {}", a, b))
        .collect();
    assert!(diffs.is_empty(), "{} respuesta(s) distintas:\n{}", diffs.len(), diffs.join("\n---\n"));
    // Que haya corrido en nativo de verdad, y que las rutas den algo (no un 500 en todas).
    assert!(after.osr > before.osr + 10, "los bucles de los handlers casi no entraron a nativo: osr {} → {}", before.osr, after.osr);
    assert!(fast.iter().filter(|l| l.contains("HTTP/1.1 200")).count() > ROUTES.len() * 3, "{:#?}", fast);
}
