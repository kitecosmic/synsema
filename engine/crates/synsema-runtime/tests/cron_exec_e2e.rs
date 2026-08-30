//! E2E de la ejecución REAL de cron por el runtime (antes: closure no-op que
//! mentía en run_count). Cubre el plan del spec:
//! - El task registrado EJECUTA (marker observable) bajo `run` y bajo `serve`.
//! - Verdad observacional: run_count == ejecuciones completadas, errors ==
//!   fallidas, jamás un conteo sin ejecución.
//! - Un solo scheduler por proceso serve: un job registrado desde una ruta es
//!   visible (y ejecuta) desde cualquier worker.
//! - Errores: log por el sink de serve, el job sigue, el server sigue vivo, el
//!   secret jamás aparece en el log del tick fallido.
//! - Validación en la REGISTRACIÓN: task con parámetros / inexistente / interval
//!   no-positivo → error claro y atrapable.
//! - Sin solapamiento (task lento), re-registración (mismo nombre reemplaza),
//!   registración anidada (un task registra otro cron) sin deadlock, 50 jobs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::{run_serve_program, set_serve_log_sink};

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

/// Path temporal único (forward slashes — válidos en Windows y embebibles en .syn).
fn temp_marker(tag: &str) -> (PathBuf, String) {
    let p = std::env::temp_dir().join(format!(
        "syn_cron_{}_{}_{}.txt",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    let s = p.display().to_string().replace('\\', "/");
    (p, s)
}

// =========================================================
// Ejecución real bajo `run` (la esencia de la sonda de aceptación)
// =========================================================

#[test]
fn run_mode_executes_the_task_and_counts_truthfully() {
    let (path, spath) = temp_marker("exec");
    let o = out(&format!(
        r#"require file("{p}")
require time

task write_marker()
    write_file("{p}", "cron ran")

cron_after(0.2, write_marker)
sleep(1.2)
each j in cron_list()
    print(j["name"] + " runs=" + text(j["run_count"]) + " errors=" + text(j["errors"]))"#,
        p = spath
    ));
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert_eq!(content, "cron ran", "el task DEBE ejecutar (marker escrito)");
    assert_eq!(o, vec!["write_marker runs=1 errors=0"], "run_count == ejecuciones reales");
}

#[test]
fn cron_after_zero_delay_runs_immediately() {
    let (path, spath) = temp_marker("zero");
    out(&format!(
        r#"require file("{p}")
require time
task ya()
    write_file("{p}", "ya")
cron_after(0, ya)
sleep(0.5)"#,
        p = spath
    ));
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert_eq!(content, "ya");
}

#[test]
fn repeated_ticks_count_equals_observable_effect() {
    let (path, spath) = temp_marker("ticks");
    let o = out(&format!(
        r#"require file("{p}")
require time

task cuenta()
    append_file("{p}", "x")

cron_every(0.15, cuenta)
sleep(1.2)
each j in cron_list()
    print("runs=" + text(j["run_count"]))"#,
        p = spath
    ));
    let effects = std::fs::read_to_string(&path).unwrap_or_default().matches('x').count();
    let _ = std::fs::remove_file(&path);
    let runs: usize = o[0].trim_start_matches("runs=").parse().expect("run_count numérico");
    assert!(runs >= 3, "cron_every(0.15) por ~1.2 s debe ejecutar ≥ 3 veces, got {}", runs);
    // El efecto observable creció al menos tanto como el conteo (un tick en vuelo
    // puede haber apendeado después de leer cron_list — jamás lo inverso: conteo
    // sin efecto sería la mentira que este fix elimina).
    assert!(
        effects >= runs,
        "efectos ({}) < run_count ({}): conteo fantasma",
        effects,
        runs
    );
}

#[test]
fn errors_are_counted_and_the_job_survives() {
    let o = out(
        r#"require time
task boom()
    raise("kaput")
cron_every(0.2, boom)
sleep(1.1)
each j in cron_list()
    print(j["name"] + " runs=" + text(j["run_count"]) + " errors=" + text(j["errors"]) + " active=" + text(j["active"]))"#,
    );
    assert_eq!(o.len(), 1, "{:?}", o);
    let line = &o[0];
    assert!(line.starts_with("boom runs=0 "), "run_count NO avanza por ticks fallidos: {}", line);
    let errors: usize = line
        .split("errors=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .expect("errors numérico");
    assert!(errors >= 3, "cada tick fallido cuenta y el job sigue programado: {}", line);
    assert!(line.ends_with("active=true"), "el job sigue vivo tras errores: {}", line);
}

#[test]
fn capability_denied_in_task_counts_as_error() {
    // El task corre con las caps del PROGRAMA: sql() sin `require db` → el mismo
    // error de capability que en un handler, contado en errors.
    let o = out(
        r#"require time
task quiere_db()
    let x be sql("SELECT 1")
cron_after(0.1, quiere_db)
sleep(0.8)
each j in cron_list()
    print(j["name"] + " runs=" + text(j["run_count"]) + " errors=" + text(j["errors"]))"#,
    );
    assert_eq!(o, vec!["quiere_db runs=0 errors=1"]);
}

// =========================================================
// Validación en la REGISTRACIÓN (errores claros, atrapables)
// =========================================================

#[test]
fn registration_errors_are_clear_and_catchable() {
    let o = out(
        r#"require time
task con_arg(x)
    print(x)
task cero()
    print("cero")
let m1 be ""
try
    cron_every(1, con_arg)
recover err
    set m1 to err
print(contains(m1, "takes 1 parameter") and contains(m1, "zero-argument"))
let m2 be ""
try
    cron_every(1, "no_existe")
recover err
    set m2 to err
print(contains(m2, "not defined"))
let m3 be ""
try
    cron_every(0, cero)
recover err
    set m3 to err
print(contains(m3, "positive"))
let m4 be ""
try
    cron_after(0-1, cero)
recover err
    set m4 to err
print(contains(m4, "non-negative"))
print("sigue vivo")"#,
    );
    assert_eq!(o, vec!["true", "true", "true", "true", "sigue vivo"]);
}

// =========================================================
// Semántica: sin solapamiento, mismo nombre reemplaza, registración anidada
// =========================================================

#[test]
fn slow_task_never_overlaps_itself() {
    let o = out(
        r#"require time
task lento()
    sleep(0.4)
cron_every(0.1, lento)
sleep(1.4)
each j in cron_list()
    print("runs=" + text(j["run_count"]))"#,
    );
    let runs: usize = o[0].trim_start_matches("runs=").parse().expect("run_count numérico");
    // Ciclo ≈ 0.1 de espera + 0.4 de ejecución = 0.5 s → ~2-3 ticks en 1.4 s. Si el
    // job se solapara consigo mismo serían ~13. Delay fijo ENTRE FIN e inicio (G5).
    assert!((1..=4).contains(&runs), "los ticks deben serializarse, got {}", runs);
}

#[test]
fn same_name_reregisters_and_replaces() {
    let (path, spath) = temp_marker("rereg");
    let o = out(&format!(
        r#"require file("{p}")
require time
task v1()
    append_file("{p}", "a")
cron_every(0.15, v1)
sleep(0.6)
cron_every(60, v1)
sleep(0.4)
let n be 0
each j in cron_list()
    set n to n + 1
    print(j["name"] + " interval=" + text(j["interval"]) + " runs=" + text(j["run_count"]))
print("jobs=" + text(n))"#,
        p = spath
    ));
    // Un solo job con el intervalo nuevo y el contador reseteado (job NUEVO).
    assert_eq!(o[0], "v1 interval=60.0 runs=0", "{:?}", o);
    assert_eq!(o[1], "jobs=1", "{:?}", o);
    // Y el task viejo dejó de producir efectos: el archivo no crece más.
    let before = std::fs::read_to_string(&path).unwrap_or_default().len();
    thread::sleep(Duration::from_millis(500));
    let after = std::fs::read_to_string(&path).unwrap_or_default().len();
    let _ = std::fs::remove_file(&path);
    assert_eq!(before, after, "el job viejo debe estar cancelado");
}

#[test]
fn a_task_can_register_another_cron_without_deadlock() {
    let (path, spath) = temp_marker("nested");
    let o = out(&format!(
        r#"require file("{p}")
require time
task hijo()
    write_file("{p}", "hijo corrio")
task padre()
    cron_after(0.1, hijo)
cron_after(0.1, padre)
sleep(1.2)
let names be ""
each j in cron_list()
    set names to names + j["name"] + ","
print(names)"#,
        p = spath
    ));
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert_eq!(content, "hijo corrio", "el cron registrado DESDE un tick ejecuta");
    assert!(o[0].contains("hijo"), "y es visible en cron_list(): {:?}", o);
}

#[test]
fn fifty_jobs_register_execute_and_cancel() {
    let (path, spath) = temp_marker("fifty");
    let mut src = format!("require file(\"{}\")\nrequire time\n", spath);
    for i in 0..50 {
        src.push_str(&format!(
            "task t{i}()\n    append_file(\"{p}\", \"x\")\n",
            i = i,
            p = spath
        ));
    }
    for i in 0..50 {
        src.push_str(&format!("cron_every(0.15, t{})\n", i));
    }
    src.push_str(
        r#"sleep(1.0)
let n be 0
each j in cron_list()
    set n to n + 1
    cron_cancel(j["name"])
print("jobs=" + text(n))
"#,
    );
    let o = out(&src);
    assert_eq!(o, vec!["jobs=50"]);
    // Todos ejecutaron al menos una vez…
    thread::sleep(Duration::from_millis(400)); // ticks en vuelo terminan
    let count = std::fs::read_to_string(&path).unwrap_or_default().matches('x').count();
    assert!(count >= 50, "50 jobs × ≥1 tick, got {} efectos", count);
    // …y la cancelación los apagó a todos (el archivo no crece más).
    thread::sleep(Duration::from_millis(300));
    let count2 = std::fs::read_to_string(&path).unwrap_or_default().matches('x').count();
    let _ = std::fs::remove_file(&path);
    assert_eq!(count, count2, "hilos zombies tras cancel");
}

// =========================================================
// serve — estado compartido, scheduler único, errores logueados, server vivo
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, target: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // HTTP/1.0: el body llega sin chunked encoding → parseable tal cual.
    let req = format!("GET {target} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn wait_ready(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

/// Pollea `target` hasta que el body (int) alcance `min`, con deadline.
fn poll_int_at_least(port: u16, target: &str, min: i64, secs: f64) -> i64 {
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let mut last = -1;
    while Instant::now() < deadline {
        let body = request(port, target);
        // Un `give text(...)` responde JSON → el número viaja entre comillas.
        last = body_of(&body).trim().trim_matches('"').parse().unwrap_or(-1);
        if last >= min {
            return last;
        }
        thread::sleep(Duration::from_millis(150));
    }
    panic!("{} nunca llegó a {} (último: {})", target, min, last);
}

#[test]
fn serve_executes_jobs_with_shared_state_and_one_scheduler() {
    // Capturar el sink de logs de serve ANTES de arrancar (se resuelve al construir
    // los intérpretes): acá se verifica la línea "[cron] job '…' failed" y que el
    // secret jamás se filtra en el log del tick fallido.
    let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap = captured.clone();
    set_serve_log_sink(Some(std::sync::Arc::new(move |line: &str| {
        cap.lock().unwrap().push(line.to_string());
    })));

    let port = free_port();
    let prog = format!(
        r#"require serve({p})
require time

state_set("n", 0)
state_set("m", 0)

task tick()
    state_incr("n", 1)

task tick2()
    state_incr("m", 1)

task boom()
    let s be as_secret("hunter2", "API_KEY")
    raise("kaput")

cron_every(0.2, tick)

serve on {p}
    route "GET /n"
        give text(state_get("n"))
    route "GET /m"
        give text(state_get("m"))
    route "GET /reg"
        cron_every(0.2, tick2)
        give "ok"
    route "GET /regboom"
        cron_every(0.3, boom)
        give "ok"
    route "GET /jobs"
        let resumen be ""
        each j in cron_list()
            set resumen to resumen + j["name"] + ":" + text(j["run_count"]) + ":" + text(j["errors"]) + ","
        give resumen
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "cron_exec_e2e.syn", false);
    });
    wait_ready(port);

    // 1. El job del top-level ejecuta con el estado compartido del proceso: una
    //    ruta ve el contador crecer (ejecución real, no un intérprete isla).
    poll_int_at_least(port, "/n", 2, 8.0);

    // 2. Job registrado DESDE una ruta → ejecuta, y cron_list desde OTRA request
    //    (otro worker) lo ve: un solo scheduler por proceso.
    assert!(request(port, "/reg").contains(" 200 "));
    poll_int_at_least(port, "/m", 1, 8.0);
    let jobs = request(port, "/jobs");
    assert!(jobs.contains("tick2:"), "el job dinámico es visible globalmente: {}", jobs);

    // 3. Task que falla: errors cuenta, run_count no, el log del sink lo dice, el
    //    secret va redactado, y el server sigue atendiendo.
    assert!(request(port, "/regboom").contains(" 200 "));
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut boom_line = None;
    while Instant::now() < deadline && boom_line.is_none() {
        thread::sleep(Duration::from_millis(200));
        boom_line = captured
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.contains("[cron] job 'boom' failed:"))
            .cloned();
    }
    set_serve_log_sink(None);
    let line = boom_line.expect("línea de error del tick en el sink de serve");
    assert!(line.contains("kaput"), "mensaje del error de runtime: {}", line);
    // G8: el task manipuló un secret y falló — su plaintext jamás toca el log.
    assert!(!line.contains("hunter2"), "el secret JAMÁS aparece en el log: {}", line);
    let jobs = request(port, "/jobs");
    let boom_entry = jobs
        .split(',')
        .find(|s| s.contains("boom:"))
        .map(|s| s.to_string())
        .unwrap_or_default();
    assert!(boom_entry.starts_with("boom:0:"), "run_count 0 para el job que falla: {}", jobs);
    assert!(request(port, "/n").contains(" 200 "), "el server sigue vivo");
}

#[test]
fn serve_with_only_jobs_stays_alive_and_executes() {
    let (path, spath) = temp_marker("only_jobs");
    let prog = format!(
        r#"require time
require file("{p}")

task marca()
    append_file("{p}", "x")

cron_every(0.2, marca)
"#,
        p = spath
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "cron_only_jobs.syn", false);
    });
    // Sin rutas: el proceso queda vivo y los jobs ejecutan (promesa documentada de
    // `synsema serve` con programas solo-cron).
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        thread::sleep(Duration::from_millis(200));
        let n = std::fs::read_to_string(&path).unwrap_or_default().matches('x').count();
        if n >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "el job jamás ejecutó bajo serve solo-jobs");
    }
    let _ = std::fs::remove_file(&path);
}

// =========================================================
// Expresiones cron de pared (`cron_every("0 9 * * *", task, opts?)`)
// =========================================================

#[test]
fn expr_registers_and_lists_next_run() {
    let o = out(
        r#"require time
task t()
    print("tick")
let name be cron_every("*/5 * * * *", t)
print(name)
let j be cron_list()[0]
print(j["schedule"])
print(j["interval"] == nothing)
print(j["tz"])
print(j["repeating"])
let n be j["next_run"]
print(n > now())
print(n - now() <= 300)
print(floor(n) % 300)
print(contains(cron_status(), "at '*/5 * * * *' (UTC), next "))
cron_cancel("t")"#,
    );
    assert_eq!(o, vec!["t", "*/5 * * * *", "true", "UTC", "true", "true", "true", "0", "true"]);
}

#[test]
fn tz_offset_shifts_next_run() {
    let o = out(
        r#"require time
task a()
    print("a")
task b()
    print("b")
cron_every("0 9 * * *", a)
cron_every("0 9 * * *", b, {"tz": "-03:00"})
let na be cron_list()[0]["next_run"]
let nb be cron_list()[1]["next_run"]
-- 09:00 en -03:00 es 12:00Z: la diferencia es +3 h (mod 24 h).
print((floor(nb) - floor(na) + 86400) % 86400)
cron_cancel("a")
cron_cancel("b")"#,
    );
    assert_eq!(o, vec!["10800"]);
}

#[test]
fn expr_errors_are_clear() {
    let o = out(
        r#"require time
task t()
    print("t")
task probe(expr, opts)
    try
        when opts == nothing
            cron_every(expr, t)
        otherwise
            cron_every(expr, t, opts)
        give "registered"
    recover err
        give err
print(probe("0 9 *", nothing))
print(probe("0 25 * * *", nothing))
print(probe("@reboot", nothing))
print(probe("0 9 * * *", {"tz": "America/Sao_Paulo"}))
print(probe("0 9 * * *", {"zone": "UTC"}))
print(probe("0 0 31 2 *", nothing))
print(probe(5, {"tz": "UTC"}))
print(probe(true, nothing))
print(length(cron_list()))"#,
    );
    assert!(o[0].contains("bad cron expression \"0 9 *\"") && o[0].contains("expected 5 fields"), "{}", o[0]);
    assert!(o[1].contains("hour 25 is out of range 0-23"), "{}", o[1]);
    assert!(o[2].contains("cron_after(0, task)"), "{}", o[2]);
    assert!(o[3].contains("not supported") && o[3].contains("-03:00"), "{}", o[3]);
    assert!(o[4].contains("unknown option \"zone\""), "{}", o[4]);
    assert!(o[5].contains("never matches within the next 5 years"), "{}", o[5]);
    assert!(o[6].contains("options are only accepted with a cron expression"), "{}", o[6]);
    assert!(o[7].contains("number of seconds or a cron expression"), "{}", o[7]);
    assert_eq!(o[8], "0", "ningún job debe quedar registrado tras los errores");
}

#[test]
fn numeric_text_is_still_an_interval() {
    let o = out(
        r#"require time
task t()
    print("t")
cron_every("2", t)
let j be cron_list()[0]
print(j["schedule"])
print(j["interval"])
print(j["tz"] == nothing)
print(j["next_run"] > now())
cron_cancel("t")"#,
    );
    assert_eq!(o, vec!["every 2.0s", "2.0", "true", "true"]);
}

// Dispara de verdad en el próximo minuto de pared (≤ 60 s + margen). El marker
// prueba el efecto; `run_count` la contabilidad; `next_run` avanza 60 s exactos.
#[test]
fn expr_fires_at_the_next_wall_clock_minute() {
    let (path, spath) = temp_marker("wall");
    let o = out(&format!(
        r#"require file("{p}")
require time

task cuenta()
    append_file("{p}", "x")

cron_every("* * * * *", cuenta)
let first be cron_list()[0]["next_run"]
let deadline be now() + 75
while now() < deadline and cron_list()[0]["run_count"] < 1
    sleep(0.5)
let j be cron_list()[0]
print(j["run_count"] >= 1)
print(floor(j["next_run"]) - floor(first))
print(floor(first) % 60)"#,
        p = spath
    ));
    let effects = std::fs::read_to_string(&path).unwrap_or_default().matches('x').count();
    let _ = std::fs::remove_file(&path);
    assert_eq!(o[0], "true", "el job debe ejecutar en el próximo minuto de pared");
    assert!(effects >= 1, "efecto observable ausente");
    assert_eq!(o[1], "60", "next_run avanza exactamente un minuto");
    assert_eq!(o[2], "0", "next_run está alineado al minuto");
}
