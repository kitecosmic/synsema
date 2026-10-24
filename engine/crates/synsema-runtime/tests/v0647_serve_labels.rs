//! v0.6.47 (T1, ronda 3): `serve` con etiquetas no tiene modo dueño.
//! - Lo que imprime un request se escribe en el log del server al terminar, y no se escribe si lo
//!   cortaron las etiquetas (en el bloque o al rechazar la respuesta): en vivo, cuántas líneas
//!   salieron antes del corte lo elegía el dato, y bajo `--attested` el log está fuera del enclave.
//! - La salida de los agentes no se escribe.
//! - `agents()` y `agent_stop` sólo ven los agentes del propio request: el corte de un agente no deja
//!   `agents()` en 500 para los demás, y un request no ve ni frena los de otro.
//! - Lo que un request (o un agente suyo) escribió en el blackboard se deshace si el request se corta
//!   (ronda 4): cuántas claves quedaban lo elegía el dato. Lo mismo con las señales que dejó en cola.
//!   La corrida entera (el request y todos sus agentes) es la unidad: `specs/t1-diario-modelo.md`.
//!
//! Binario propio: las etiquetas y el sink del log son de todo el proceso.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program_with_overrides, set_serve_log_sink, ServeOverrides};

const WITHHELD: &str = "private(labels): the run was stopped by the flow checker";

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(6)));
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

#[test]
fn serve_with_labels_holds_the_log_and_scopes_the_agents() {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let all: Arc<Mutex<Vec<String>>> = Arc::default();
    let (l2, a2) = (log.clone(), all.clone());
    set_serve_log_sink(Some(Arc::new(move |line: &str| {
        l2.lock().unwrap().push(line.to_string());
        a2.lock().unwrap().push(line.to_string());
    })));
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
require time
agent Lento
    print("eco del agente")
    sleep(3)
agent Escribe
    share "y" as "ag"
    share "del agente" as "w"
agent Corta
    let t be private(1, "app")
    when t == 1
        print("x")
agent Previo
    share "1" as "px"
agent CortaTarde
    sleep(0.5)
    let t be private(1, "app")
    when t == 1
        print("x")
agent TerminaTarde
    sleep(0.5)
    share "a" as "t4a"
agent CortaPronto
    sleep(0.3)
    let t be private(1, "app")
    when t == 1
        print("x")
agent EscribeDespues
    sleep(0.9)
    share "x" as "c12"
agent Lanzador
    spawn Hijo
agent Hijo
    share "h" as "c11"
agent PrevioCorta
    sleep(1)
    let t be private(1, "app")
    when t == 1
        print("x")
task pag(status, message, request)
    when status == 404
        print("pagina")
        let k be private(1, "app")
        give {{"k": k}}
    give nothing
task tick()
    spawn Lento
    print("ve " + text(length(agents())))
cron_every(0.3, tick)
spawn Previo
spawn PrevioCorta
serve on {p}
    errors with pag
    route "GET /vueltas"
        let s be private(int(query["s"]), "app")
        each i in range(5)
            print("vuelta")
            let z be 1 / (s - i)
        give "ok"
    route "GET /respuesta"
        let s be private(int(query["s"]), "app")
        print("antes")
        when s == 1
            let z be 1 / 0
        give {{"b": s}}
    route "GET /lanza"
        spawn Lento
        give {{"n": length(agents()), "id": agents()[0]["id"]}}
    route "GET /mira"
        give {{"n": length(agents())}}
    route "GET /frena"
        give {{"ok": agent_stop(query["id"])}}
    route "GET /pone"
        let s be private(int(query["s"]), "app")
        each i in range(10)
            share "x" as "k" + text(i)
            let z be 1 / (s - i)
        give "ok"
    route "GET /pone-agente"
        let s be private(int(query["s"]), "app")
        share "del request" as "w"
        spawn Escribe
        let n be 0
        while n < 40 and agents()[0]["state"] != "done"
            sleep(0.1)
            set n to n + 1
        let z be 1 / (s - 1)
        give "ok"
    route "GET /senala"
        let s be private(int(query["s"]), "app")
        each i in range(5)
            signal "t" with 1
            let z be 1 / (s - i)
        give "ok"
    route "GET /espera"
        let n be 0
        let sigue be true
        while sigue
            wait_for "t" timeout 0.2 as v
            when v == nothing
                set sigue to false
            otherwise
                set n to n + 1
        give {{"n": n}}
    route "GET /px"
        observe "px" as v
        give {{"px": v != nothing}}
    route "GET /tarde-corta"
        share "r" as "t5"
        spawn CortaTarde
        give "ok"
    route "GET /tarde-bien"
        share "r" as "t4"
        spawn TerminaTarde
        give "ok"
    route "GET /doce"
        spawn CortaPronto
        spawn EscribeDespues
        give "ok"
    route "GET /nietos"
        let s be private(int(query["s"]), "app")
        spawn Lanzador
        sleep(0.8)
        let z be 1 / (s - 1)
        give "ok"
    route "GET /hay"
        observe query["k"] as v
        give {{"hay": v != nothing}}
    route "GET /cuenta"
        let n be 0
        each k in ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "ag", "w"]
            observe k as v
            when v != nothing
                set n to n + 1
        give {{"n": n}}
    route "GET /corta-y-mira"
        spawn Corta
        sleep(0.5)
        give {{"n": length(agents())}}
    route "GET /corta"
        spawn Corta
        give "lanzado"
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(&prog, "v0647_serve.syn", false, ServeOverrides::default());
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));
    let take = |path: &str| {
        log.lock().unwrap().clear();
        let r = http_get(port, path);
        thread::sleep(Duration::from_millis(100));
        let lines: Vec<String> =
            log.lock().unwrap().iter().filter(|l| !l.starts_with("[serve:") && !l.contains("serve") && !l.starts_with("ve ")).cloned().collect();
        (r, lines)
    };

    // Caso 14 de `specs/t1-diario-modelo.md`: el preámbulo es una corrida que el dueño cierra al
    // empezar a servir, pero sigue abierta mientras le quede un agente. Un agente suyo que se corta ya
    // sirviendo deshace también lo que escribió otro agente del preámbulo que terminó bien.
    thread::sleep(Duration::from_millis(1500));
    let r = http_get(port, "/px");
    assert!(body(&r).contains("false"), "quedó lo del preámbulo cortado: {}", r);

    let hay = |k: &str| body(&http_get(port, &format!("/hay?k={}", k))).contains("true");
    // Caso 12: un agente que sigue vivo cuando otro de su corrida se cortó no llega a escribir (`share`
    // es un sumidero y la corrida está cortada); no queda nada.
    let (_, _) = take("/doce");
    thread::sleep(Duration::from_millis(1500));
    assert!(!hay("c12"), "quedó lo escrito después del corte de la corrida");

    // Caso 11: el agente que lanza un agente es de la misma corrida; si el request se corta, se
    // deshace lo del nieto (y sin corte, queda).
    let (r, _) = take("/nietos?s=1");
    assert!(r.starts_with("HTTP/1.1 500"), "{}", r);
    assert!(!hay("c11"), "quedó lo del agente lanzado por un agente");
    let (r, _) = take("/nietos?s=5");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    assert!(hay("c11"), "sin corte, lo del nieto se perdió");

    // Casos 4 y 5: el request cierra bien y su agente sigue. Si el agente termina bien, queda todo; si
    // se corta, se deshace la corrida entera, también lo que escribió el request.
    let (r, _) = take("/tarde-bien");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    let (r, _) = take("/tarde-corta");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    thread::sleep(Duration::from_millis(1000));
    assert!(hay("t4") && hay("t4a"), "la corrida que terminó bien no se confirmó");
    assert!(!hay("t5"), "quedó lo del request cuyo agente se cortó después");


    // El sitio del corte lo elige el dato: el log es el mismo (sólo la línea fija).
    let (r1, l1) = take("/vueltas?s=1");
    let (r3, l3) = take("/vueltas?s=3");
    assert!(r1.starts_with("HTTP/1.1 500") && r3.starts_with("HTTP/1.1 500"), "{} / {}", r1, r3);
    assert_eq!(l1, l3);
    assert_eq!(l1.len(), 1, "{:?}", l1);
    assert!(l1[0].starts_with(WITHHELD), "{:?}", l1);
    // Sin corte, todo al terminar.
    let (r9, l9) = take("/vueltas?s=9");
    assert!(r9.starts_with("HTTP/1.1 200"), "{}", r9);
    assert_eq!(l9, vec!["vuelta".to_string(); 5]);

    // Un corte en el bloque y el rechazo de la respuesta dejan el mismo log (y el mismo cuerpo).
    let (a, la) = take("/respuesta?s=1");
    let (b, lb) = take("/respuesta?s=2");
    assert_eq!(body(&a), body(&b));
    assert_eq!(la, lb);
    assert!(la.len() == 1 && la[0].starts_with(WITHHELD), "{:?}", la);

    // La página de error que no puede salir por etiquetas es un corte como el de una ruta.
    let (r, l) = take("/no-existe");
    assert!(r.starts_with("HTTP/1.1 404"), "{}", r);
    assert!(l.len() == 1 && l[0].starts_with(WITHHELD), "{:?}", l);

    // Cada request ve y frena sólo sus agentes; la salida de los agentes no se escribe.
    let (r, _) = take("/lanza");
    let v: serde_json::Value = serde_json::from_str(body(&r)).unwrap_or_else(|_| panic!("{}", r));
    assert_eq!(v["n"], 1, "{}", r);
    let id = v["id"].as_str().unwrap().to_string();
    let (r, _) = take("/mira");
    assert!(body(&r).contains("\"n\": 0") || body(&r).contains("\"n\":0"), "otro request vio el agente: {}", r);
    let (r, _) = take(&format!("/frena?id={}", id));
    assert!(body(&r).contains("false"), "otro request frenó el agente: {}", r);
    assert!(!all.lock().unwrap().iter().any(|l| l.contains("eco del agente")), "{:?}", all.lock().unwrap());

    // El blackboard: lo escrito antes del corte se deshace (también lo de un agente que terminó bien
    // antes de que su request se cortara); sin corte, queda.
    let n_of = |r: &str| -> i64 {
        let v: serde_json::Value = serde_json::from_str(body(r)).unwrap_or_else(|_| panic!("{}", r));
        v["n"].as_i64().unwrap()
    };
    for s in [2, 6] {
        let (r, _) = take(&format!("/pone?s={}", s));
        assert!(r.starts_with("HTTP/1.1 500"), "{}", r);
        let (r, _) = take("/cuenta");
        assert_eq!(n_of(&r), 0, "secreto {}: {}", s, r);
    }
    let (r, _) = take("/pone-agente?s=1");
    assert!(r.starts_with("HTTP/1.1 500"), "{}", r);
    let (r, _) = take("/cuenta");
    // El request y su agente escribieron "w": es una sola corrida, no vuelve lo del request.
    assert_eq!(n_of(&r), 0, "lo del agente o del request quedó: {}", r);
    let (r, _) = take("/pone-agente?s=5");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    let (r, _) = take("/pone?s=20");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    let (r, _) = take("/cuenta");
    assert_eq!(n_of(&r), 12, "{}", r);

    // Las señales que dejó en cola un request cortado no le llegan a otro.
    for s in [1, 3] {
        let (r, _) = take(&format!("/senala?s={}", s));
        assert!(r.starts_with("HTTP/1.1 500"), "{}", r);
        let (r, _) = take("/espera");
        assert_eq!(n_of(&r), 0, "secreto {}: {}", s, r);
    }
    let (r, _) = take("/senala?s=9");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    let (r, _) = take("/espera");
    assert_eq!(n_of(&r), 5, "{}", r);

    // El corte de un agente es de su request: quien lo lanzó adopta el corte al mirarlo (el estado lo
    // eligió el dato), y `agents()` no queda en 500 para los que siguen.
    let (r, l) = take("/corta-y-mira");
    assert!(r.starts_with("HTTP/1.1 500") && body(&r).contains("label_violation"), "{}", r);
    assert!(l.len() == 1 && l[0].starts_with(WITHHELD), "{:?}", l);
    let (r, _) = take("/corta");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
    thread::sleep(Duration::from_millis(300));
    let (r, _) = take("/mira");
    assert!(r.starts_with("HTTP/1.1 200"), "agents() quedó en 500: {}", r);

    // Cada tick del cron es su propia corrida: ve sólo el agente que lanzó él (el intérprete del hilo
    // no arrastra el corte ni los agentes del tick anterior).
    thread::sleep(Duration::from_millis(1200));
    let all = all.lock().unwrap();
    let ticks: Vec<&String> = all.iter().filter(|l| l.starts_with("ve ")).collect();
    assert!(ticks.len() >= 2 && ticks.iter().all(|l| l.as_str() == "ve 1"), "{:?}", ticks);
}
