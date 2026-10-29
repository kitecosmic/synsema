//! v0.6.51 (G1, `specs/v0.6.51-modelos.md`): lo que es de una corrida vive en su `RunScope`, no en el
//! proceso. Estos tests corren dos programas en el MISMO proceso (lo que hace este binario de tests y
//! un embebedor) y piden que ninguno vea el estado del otro: el `shutdown()` de un `serve` no termina
//! al vecino, un `serve` que ya escucha no le quita el `exit()` del preámbulo a otro, un `run` no es
//! un `serve`, y el techo del host es el de cada corrida.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use synsema_capabilities::model::{Capability, CapabilityType};
use synsema_runtime::engine::run_source;
use synsema_runtime::serve::{run_serve_program, run_serve_program_with_overrides, ServeOverrides};
use synsema_core::interpreter::RunResult;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..300 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server de {} no quedó listo", port);
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// Un `serve` con `/stop` (pide su shutdown) y `/` (dice quién es).
fn server(port: u16, name: &str, preamble: &str) -> String {
    format!(
        r#"require serve({port})
{preamble}
task apagar(x)
    shutdown("{name} termina desde un worker")
    give x

serve on {port}
    route "GET /"
        give "soy {name}"
    route "GET /stop"
        shutdown("{name} termina")
        give "chau"
    route "GET /stop-par"
        parallel_map(apagar, [1])
        give "chau"
    route "GET /exit"
        exit(0)
        give "no llega"
"#
    )
}

/// Arranca el programa en su hilo; el canal trae su `RunResult` cuando la corrida termina.
fn start(src: String, ov: ServeOverrides) -> mpsc::Receiver<RunResult> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(run_serve_program_with_overrides(&src, "g1.syn", false, ov));
    });
    rx
}

fn stop(port: u16, done: &mpsc::Receiver<RunResult>) -> RunResult {
    let r = get(port, "/stop");
    assert!(r.contains("chau"), "{}", r);
    done.recv_timeout(Duration::from_secs(30)).expect("la corrida no terminó después de su shutdown()")
}

/// G1-3: el `shutdown()` de un `serve` termina SU corrida (que vuelve con éxito a quien la empezó)
/// y el otro `serve` del proceso sigue atendiendo. Antes el canal de shutdown era del proceso (el
/// otro también drenaba) y el último listener hacía `process::exit`.
#[test]
fn g1_3_the_shutdown_of_one_serve_does_not_drain_another_in_the_same_process() {
    let (pa, pb) = (free_port(), free_port());
    let a = start(server(pa, "a", ""), ServeOverrides::default());
    let b = start(server(pb, "b", ""), ServeOverrides::default());
    wait_ready(pa);
    wait_ready(pb);
    let ra = stop(pa, &a);
    assert!(ra.success, "{:?}", ra.errors);
    assert!(TcpStream::connect(("127.0.0.1", pa)).is_err(), "a ya no escucha");
    let r = get(pb, "/");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("soy b"), "b debía seguir sirviendo: {}", r);
    assert!(b.try_recv().is_err(), "b no terminó");
    let rb = stop(pb, &b);
    assert!(rb.success, "{:?}", rb.errors);
}

/// G1-3: un worker de `parallel_map` es de la corrida de su llamador: su `shutdown()` apaga ESE
/// `serve` (sin la corrida, el worker no sabía que estaba bajo `serve`).
#[test]
fn g1_3_a_parallel_map_worker_shuts_down_the_run_of_its_caller() {
    let pa = free_port();
    let a = start(server(pa, "a", ""), ServeOverrides::default());
    wait_ready(pa);
    let r = get(pa, "/stop-par");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("chau"), "{}", r);
    let ra = a.recv_timeout(Duration::from_secs(30)).expect("la corrida no terminó con el shutdown() del worker");
    assert!(ra.success, "{:?}", ra.errors);
}

/// G1-2: un `serve` que ya escucha no le quita a otro el `exit()` de su preámbulo (antes "ya
/// escucha" era del proceso).
#[test]
fn g1_2_exit_in_the_preamble_works_while_another_serve_listens() {
    let pa = free_port();
    let a = start(server(pa, "a", ""), ServeOverrides::default());
    wait_ready(pa);
    // `a` ya escucha: su `exit()` se rechaza (cortaría requests en vuelo).
    let r = get(pa, "/exit");
    assert!(r.starts_with("HTTP/1.1 500") && r.contains("use shutdown(reason)"), "{}", r);
    let pb = free_port();
    let r = run_serve_program(&server(pb, "b", "exit(0)"), "g1.syn", false);
    assert!(r.success && r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.exit_code, Some(0));
    assert!(TcpStream::connect(("127.0.0.1", pb)).is_err(), "b no debía escuchar");
    let ra = stop(pa, &a);
    assert!(ra.success, "{:?}", ra.errors);
}

/// G1-1: un `run` en el mismo proceso que un `serve` no es un `serve`: su `shutdown()` es el error
/// de `run`, y no apaga al `serve` vecino (antes "bajo serve" era del proceso: el `run` lo apagaba).
#[test]
fn g1_1_a_run_beside_a_serve_is_not_a_serve() {
    let pa = free_port();
    let a = start(server(pa, "a", ""), ServeOverrides::default());
    wait_ready(pa);
    let r = run_source("shutdown(\"desde run\")\n", "g1_run.syn");
    assert!(!r.success);
    let errs = r.errors.join("\n");
    assert!(errs.contains("only available under serve"), "{}", errs);
    let resp = get(pa, "/");
    assert!(resp.contains("soy a"), "el serve vecino debía seguir: {}", resp);
    assert!(a.try_recv().is_err(), "el serve vecino no terminó");
    let ra = stop(pa, &a);
    assert!(ra.success, "{:?}", ra.errors);
}

/// G1-6: el techo del host es de cada corrida. Dos `serve` del mismo proceso con techos distintos:
/// uno sin `exec` (la ruta falla) y otro con `exec` (la ruta corre). Antes el primero fijaba el
/// techo de todos (`OnceLock` del proceso).
#[test]
fn g1_6_each_serve_keeps_its_own_host_ceiling() {
    let sh = if cfg!(windows) { "cmd" } else { "sh" };
    let call = if cfg!(windows) { r#"run("cmd", ["/C", "echo CORRIO"])"# } else { r#"run("sh", ["-c", "echo CORRIO"])"# };
    let prog = |port: u16, name: &str| {
        format!(
            r#"require serve({port})
require time
task probar()
    try
        require exec("{sh}")
        let r be {call}
        state_set("cron", "corrio")
    recover e
        state_set("cron", "denegado")

cron_every(0.1, probar)

serve on {port}
    route "GET /cron"
        give state_get("cron")
    route "GET /exec"
        require exec("{sh}")
        let r be {call}
        give r["stdout"]
    route "GET /stop"
        shutdown("{name} termina")
        give "chau"
"#
        )
    };
    let ceiling = |port: u16, exec: bool| {
        let mut c = vec![
            Capability::new(CapabilityType::Stdout, None),
            Capability::new(CapabilityType::Time, None),
            Capability::new(CapabilityType::Serve, Some(port.to_string())),
        ];
        if exec {
            c.push(Capability::new(CapabilityType::Exec, Some(sh.to_string())));
        }
        ServeOverrides { ceiling: Some(c), ..Default::default() }
    };
    let (pa, pb) = (free_port(), free_port());
    let a = start(prog(pa, "a"), ceiling(pa, false));
    wait_ready(pa);
    let b = start(prog(pb, "b"), ceiling(pb, true));
    wait_ready(pb);
    let ra = get(pa, "/exec");
    assert!(ra.starts_with("HTTP/1.1 500") && !ra.contains("CORRIO"), "a no tiene exec en su techo: {}", ra);
    let rb = get(pb, "/exec");
    assert!(rb.starts_with("HTTP/1.1 200") && rb.contains("CORRIO"), "b sí lo tiene: {}", rb);
    // El job de cron corre bajo el techo de SU corrida.
    let cron = |port: u16| {
        for _ in 0..100 {
            let r = get(port, "/cron");
            if r.contains("corrio") || r.contains("denegado") {
                return r;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("el job de cron de {} no corrió", port);
    };
    let ca = cron(pa);
    assert!(ca.contains("denegado"), "el cron de a no tiene exec: {}", ca);
    let cb = cron(pb);
    assert!(cb.contains("corrio"), "el de b sí: {}", cb);
    assert!(stop(pa, &a).success);
    assert!(stop(pb, &b).success);
}

/// Ronda 1, B1: cuando la corrida de un `serve` vuelve, los workers del pool sueltan el intérprete
/// que cacheaban para ella, y con él la base que tenía abierta. Antes quedaba retenido hasta que
/// muriera el proceso (en Windows el `.db` no se podía borrar; un embebedor que corre un `serve`
/// después de otro acumulaba intérpretes).
#[test]
fn b1_the_pool_lets_go_of_a_finished_run() {
    let dir = std::env::temp_dir().join(format!("synsema-b1-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("b1.db");
    let _ = std::fs::remove_file(&db);
    let pa = free_port();
    let path = db.to_string_lossy().replace('\\', "/");
    let preamble = format!(
        "require db({p:?})\ndb_open({p:?})\nsql_exec(\"CREATE TABLE IF NOT EXISTS t (v TEXT)\")\nsql_exec(\"INSERT INTO t VALUES ('x')\")",
        p = path
    );
    let src = server(pa, "a", &preamble).replace("        give \"soy a\"", "        give length(sql(\"SELECT * FROM t\"))");
    let a = start(src, ServeOverrides::default());
    wait_ready(pa);
    for _ in 0..16 {
        let r = get(pa, "/");
        assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("1"), "{}", r);
    }
    let ra = stop(pa, &a);
    assert!(ra.success, "{:?}", ra.errors);
    let mut gone = false;
    for _ in 0..100 {
        if std::fs::remove_file(&db).is_ok() {
            gone = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(gone, "la base de la corrida terminada sigue abierta");
}

/// Ronda 1, N4: lo que limita al llamador viaja al hijo de `run_program` en una variable de entorno;
/// si no entra, el error es del motor (antes, en Windows, fallaba el `spawn` con uno del sistema).
#[test]
fn n4_a_caller_whose_capabilities_do_not_fit_gets_an_engine_error() {
    let mut src = String::from("require sandbox_run\n");
    for i in 0..400 {
        src.push_str(&format!("require file.read(\"/var/lib/synsema/a/rather/long/folder/for/the/grant/number/{i}/data.csv\")\n"));
    }
    src.push_str("let r be run_program(\"print(1)\", {\"timeout\": 5})\nprint(r)\n");
    let r = run_source(&src, "n4.syn");
    assert!(!r.success);
    assert!(r.errors.join("\n").contains("too many to pass to the child"), "{:?}", r.errors);
}

/// Ronda 2, B1: un preámbulo que falla después de un `serve on` que ya escucha cierra igual su
/// corrida. `run_serve_program` vuelve con el error y el server deja de atender y suelta su puerto;
/// antes seguía sirviendo en un embebedor, sin nada que lo parara salvo una señal.
#[test]
fn b1_a_failed_preamble_lets_go_of_its_server() {
    let pa = free_port();
    let src = format!("require serve({pa})\nserve on {pa}\n    route \"GET /\"\n        give \"ok\"\nlet xs be [1]\nlet x be xs[5]\n");
    let r = run_serve_program(&src, "b1r2.syn", false);
    assert!(!r.success, "el preámbulo tenía que fallar: {:?}", r.output);
    let mut free = false;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", pa)).is_err() && TcpListener::bind(("0.0.0.0", pa)).is_ok() {
            free = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(free, "el server de una corrida que volvió con error sigue escuchando");
}

/// Ronda 2, N2: lo que se mide es la línea de comandos entera del hijo, no sólo su techo. Un
/// `filename` largo la pasaba y el `spawn` fallaba en Windows con `os error 206`.
#[test]
fn n2_a_child_command_line_that_does_not_fit_gets_an_engine_error() {
    let label = "a".repeat(31_000);
    let src = format!("require sandbox_run\nlet r be run_program(\"print(1)\", {{\"timeout\": 5, \"filename\": \"{label}\"}})\nprint(r)\n");
    let r = run_source(&src, "n2.syn");
    assert!(!r.success);
    assert!(r.errors.join("\n").contains("the child's command line would be"), "{:?}", r.errors);
}
