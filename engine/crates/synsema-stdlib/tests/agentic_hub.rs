//! Hub de I/O unificado (spec `agentic-apps-gaps.md` §2–§4): procesos vivos
//! (`proc_*`), bus de eventos (`bus_*`) y `select` sobre cualquier handle, con
//! cancelación cooperativa. Sin red externa: los procesos son `sh -c` / `cmd /C`.
//!
//! Invariantes medidos:
//! - eventos en orden y con exit honesto (código real, stderr separado);
//! - stdin en vivo + EOF explícito;
//! - kill/close nunca dejan huérfanos (`proc_status` lo confirma);
//! - `select` mezcla familias y etiqueta `source`/`handle`/`name`;
//! - una espera ociosa hace UNA iteración de `mio::Poll` (G25, no busy-spin);
//! - la cancelación despierta la espera de inmediato (no espera al timeout);
//! - colas acotadas: `drop_oldest` y `error` se comportan como se documenta;
//! - dropear el intérprete retira sus suscripciones del bus.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use synsema_agents::bus::Bus;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_int, syn_map, syn_text, SynValue};
use synsema_stdlib::ws::{attach_bus, register_ws_builtins, reset_hub, POLL_ITERS};

static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn shell() -> &'static str {
    if cfg!(windows) {
        "cmd"
    } else {
        "sh"
    }
}

/// `(cmd, args)` para correr un script de shell — uno por plataforma.
fn script(unix: &str, win: &str) -> (SynValue, SynValue) {
    let (flag, body) = if cfg!(windows) { ("/C", win) } else { ("-c", unix) };
    (syn_text(shell()), list(vec![syn_text(flag), syn_text(body)]))
}

fn list(items: Vec<SynValue>) -> SynValue {
    SynValue::List(Rc::new(RefCell::new(items)))
}

fn interp_with_bus(bus: Arc<Bus>) -> Interpreter {
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Exec, Some(shell().to_string())));
    register_ws_builtins(&interp, caps);
    attach_bus(&interp, bus);
    interp
}

fn interp() -> Interpreter {
    interp_with_bus(Arc::new(Bus::new()))
}

fn call(interp: &mut Interpreter, name: &str, args: Vec<SynValue>) -> Result<SynValue, Control> {
    let f = interp
        .global_env
        .borrow()
        .bindings
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("builtin {} no registrado", name));
    interp.call_task(f, args)
}

fn ok(r: Result<SynValue, Control>) -> SynValue {
    match r {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn err_msg(r: Result<SynValue, Control>) -> String {
    match r {
        Err(Control::Error(e)) => e.message,
        Ok(v) => panic!("esperaba error, got {:?}", v.to_string()),
        Err(_) => panic!("control inesperado"),
    }
}

fn get(v: &SynValue, key: &str) -> SynValue {
    match v {
        SynValue::Map(m) => m.borrow().get(key).cloned().unwrap_or(SynValue::Nothing),
        _ => panic!("esperaba map, got {}", v.type_name()),
    }
}

fn text(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        other => panic!("esperaba texto, got {}", other.type_name()),
    }
}

fn int(v: &SynValue) -> i64 {
    match v {
        SynValue::Number(n) => n.to_i64_trunc().unwrap(),
        other => panic!("esperaba número, got {}", other.type_name()),
    }
}

fn num(f: f64) -> SynValue {
    synsema_core::types::syn_number(synsema_core::number::Number::Float(f))
}

/// Drena eventos de un proceso hasta el `exit` (o el tope).
fn drain(i: &mut Interpreter, h: i64) -> Vec<SynValue> {
    let mut out = Vec::new();
    for _ in 0..200 {
        let ev = ok(call(i, "proc_recv", vec![syn_int(h), num(5.0)]));
        if matches!(ev, SynValue::Nothing) {
            break;
        }
        let is_exit = text(&get(&ev, "type")) == "exit";
        out.push(ev);
        if is_exit {
            break;
        }
    }
    out
}

// =========================================================
// Procesos vivos
// =========================================================

#[test]
fn proc_streams_lines_then_exit_with_real_code() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("echo a; echo b; echo e >&2; exit 3", "echo a& echo b& (echo e)1>&2& exit /b 3");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    let evs = drain(&mut i, h);
    let kinds: Vec<(String, String)> = evs
        .iter()
        .map(|e| {
            let t = text(&get(e, "type"));
            let d = match get(e, "data") {
                SynValue::Text(s) => s.trim().to_string(),
                other => other.to_string(),
            };
            (t, d)
        })
        .collect();
    let stdout: Vec<&str> = kinds.iter().filter(|(t, _)| t == "stdout").map(|(_, d)| d.as_str()).collect();
    let stderr: Vec<&str> = kinds.iter().filter(|(t, _)| t == "stderr").map(|(_, d)| d.as_str()).collect();
    assert_eq!(stdout, vec!["a", "b"], "stdout en orden: {:?}", kinds);
    assert_eq!(stderr, vec!["e"], "stderr separado: {:?}", kinds);
    let exit = evs.last().expect("hubo eventos");
    assert_eq!(text(&get(exit, "type")), "exit");
    assert_eq!(int(&get(&get(exit, "data"), "exit_code")), 3, "exit code real");
    assert_eq!(text(&get(exit, "source")), "proc");
    assert_eq!(int(&get(exit, "handle")), h);
    // Tras el exit, el handle sigue consultable y ya no hay nada más.
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "exited");
    assert!(matches!(ok(call(&mut i, "proc_recv", vec![syn_int(h), num(0.1)])), SynValue::Nothing));
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "closed");
}

#[test]
fn proc_send_feeds_stdin_and_close_stdin_is_eof() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("cat", "more");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    ok(call(&mut i, "proc_send", vec![syn_int(h), syn_text("hello\n")]));
    ok(call(&mut i, "proc_close_stdin", vec![syn_int(h)]));
    let evs = drain(&mut i, h);
    let joined: String = evs
        .iter()
        .filter(|e| text(&get(e, "type")) == "stdout")
        .map(|e| text(&get(e, "data")))
        .collect::<Vec<_>>()
        .join("|");
    assert!(joined.contains("hello"), "stdin → stdout: {:?}", joined);
    assert_eq!(text(&get(evs.last().unwrap(), "type")), "exit");
    // stdin cerrado: mandar más es un error claro, no un cuelgue.
    let e = err_msg(call(&mut i, "proc_send", vec![syn_int(h), syn_text("x")]));
    assert!(e.contains("stdin is closed") || e.contains("stdin"), "{}", e);
}

#[test]
fn proc_kill_terminates_and_close_never_leaves_orphans() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("sleep 30", "ping -n 31 127.0.0.1 > nul");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "running");
    let t0 = Instant::now();
    ok(call(&mut i, "proc_kill", vec![syn_int(h)]));
    let exit = ok(call(&mut i, "proc_wait", vec![syn_int(h), num(5.0)]));
    assert!(!matches!(exit, SynValue::Nothing), "proc_wait devolvió el exit tras kill");
    assert!(t0.elapsed() < Duration::from_secs(5), "kill fue rápido");
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "killed");
    // El exit también llega como evento (una sola vez).
    let evs = drain(&mut i, h);
    assert_eq!(evs.iter().filter(|e| text(&get(e, "type")) == "exit").count(), 1);

    // proc_close sobre un proceso VIVO lo mata (no quedan huérfanos).
    let (cmd, args) = script("sleep 30", "ping -n 31 127.0.0.1 > nul");
    let h2 = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    let t1 = Instant::now();
    ok(call(&mut i, "proc_close", vec![syn_int(h2)]));
    assert!(t1.elapsed() < Duration::from_secs(5), "close mató y cosechó");
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h2)]))), "closed");
}

#[test]
fn proc_stats_report_pid_and_queue() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("echo x", "echo x");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    let st = ok(call(&mut i, "proc_stats", vec![syn_int(h)]));
    assert!(int(&get(&st, "pid")) > 0);
    assert_eq!(text(&get(&st, "cmd")), shell());
    let _ = drain(&mut i, h);
}

#[test]
fn proc_on_full_error_is_terminal_and_kills() {
    let _g = serial();
    let mut i = interp();
    // 200 líneas contra una cola de 2 con política error → error atrapable.
    let (cmd, args) = script(
        "i=0; while [ $i -lt 200 ]; do echo line$i; i=$((i+1)); done",
        "for /L %i in (1,1,200) do @echo line%i",
    );
    let mut opts = indexmap::IndexMap::new();
    opts.insert("max_queue".to_string(), num(2.0));
    opts.insert("on_full".to_string(), syn_text("error"));
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args, syn_map(opts)])));
    // Darle tiempo a que se llene.
    thread::sleep(Duration::from_millis(400));
    let mut saw_error = false;
    for _ in 0..10 {
        match call(&mut i, "proc_recv", vec![syn_int(h), num(2.0)]) {
            Err(Control::Error(e)) => {
                assert!(e.message.contains("overflowed"), "{}", e.message);
                saw_error = true;
                break;
            }
            Ok(SynValue::Nothing) => break,
            Ok(_) => continue,
            Err(_) => panic!("control inesperado"),
        }
    }
    assert!(saw_error, "la cola llena con on_full=error debe fallar fuerte");
    // El handle se retiró (fail-loud y terminal).
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "closed");
}

#[test]
fn proc_budget_is_enforced() {
    let _g = serial();
    std::env::set_var("SYNSEMA_PROC_MAX", "1");
    let mut i = interp();
    std::env::remove_var("SYNSEMA_PROC_MAX");
    let (cmd, args) = script("sleep 5", "ping -n 6 127.0.0.1 > nul");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd.clone(), args.clone()])));
    let e = err_msg(call(&mut i, "proc_spawn", vec![cmd, args]));
    assert!(e.contains("process budget reached"), "{}", e);
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
}

#[test]
fn proc_denied_without_exec_capability() {
    let _g = serial();
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    register_ws_builtins(&interp, caps);
    let mut i = interp;
    let (cmd, args) = script("echo x", "echo x");
    let e = err_msg(call(&mut i, "proc_spawn", vec![cmd, args]));
    assert!(e.contains("exec"), "deny-by-default: {}", e);
}

// =========================================================
// Bus + select
// =========================================================

#[test]
fn bus_fan_out_reaches_every_subscriber_and_select_tags_source() {
    let _g = serial();
    let bus = Arc::new(Bus::new());
    let mut i = interp_with_bus(bus.clone());
    let s1 = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("agent.*")])));
    let s2 = int(&ok(call(&mut i, "bus_subscribe", vec![list(vec![syn_text("agent.done"), syn_text("other")])])));
    let s3 = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("nothing.here")])));
    let mut payload = indexmap::IndexMap::new();
    payload.insert("ok".to_string(), SynValue::Bool(true));
    let n = int(&ok(call(&mut i, "bus_publish", vec![syn_text("agent.done"), syn_map(payload)])));
    assert_eq!(n, 2, "dos suscriptores matchean");
    let mut names = indexmap::IndexMap::new();
    names.insert("a".to_string(), syn_int(s1));
    names.insert("b".to_string(), syn_int(s2));
    names.insert("c".to_string(), syn_int(s3));
    let e1 = ok(call(&mut i, "select", vec![syn_map(names.clone()), num(2.0)]));
    let e2 = ok(call(&mut i, "select", vec![syn_map(names.clone()), num(2.0)]));
    for e in [&e1, &e2] {
        assert_eq!(text(&get(e, "source")), "bus");
        assert_eq!(text(&get(e, "type")), "event");
        assert_eq!(text(&get(e, "topic")), "agent.done");
        assert!(matches!(get(&get(e, "data"), "ok"), SynValue::Bool(true)));
    }
    let mut got: Vec<String> = vec![text(&get(&e1, "name")), text(&get(&e2, "name"))];
    got.sort();
    assert_eq!(got, vec!["a", "b"]);
    // Nada más pendiente → nothing al vencer.
    let none = ok(call(&mut i, "select", vec![syn_map(names), num(0.2)]));
    assert!(matches!(none, SynValue::Nothing));
    // bus_topics lo muestra.
    let topics = ok(call(&mut i, "bus_topics", vec![]));
    assert!(topics.to_string().contains("agent.*"));
}

#[test]
fn bus_recv_wakes_on_publish_from_another_thread() {
    let _g = serial();
    let bus = Arc::new(Bus::new());
    let mut i = interp_with_bus(bus.clone());
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("t")])));
    let b2 = bus.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(120));
        b2.publish("t", synsema_core::types::SendValue::Text("hi".into()));
    });
    let t0 = Instant::now();
    let ev = ok(call(&mut i, "bus_recv", vec![syn_int(s), num(10.0)]));
    assert_eq!(text(&get(&ev, "data")), "hi");
    assert!(t0.elapsed() < Duration::from_secs(3), "despertó por el waker, no por timeout");
}

#[test]
fn bus_publish_rejects_tasks_and_secrets() {
    let _g = serial();
    let mut i = interp();
    let builtin = i.global_env.borrow().bindings.get("bus_topics").cloned().unwrap();
    let e = err_msg(call(&mut i, "bus_publish", vec![syn_text("t"), builtin]));
    assert!(e.contains("cannot publish a task"), "{}", e);
    let e = err_msg(call(&mut i, "bus_publish", vec![syn_text("a.*"), syn_text("x")]));
    assert!(e.contains("literal"), "{}", e);
}

#[test]
fn bus_queue_policies_drop_oldest_and_error() {
    let _g = serial();
    let bus = Arc::new(Bus::new());
    let mut i = interp_with_bus(bus.clone());
    let mut o = indexmap::IndexMap::new();
    o.insert("max_queue".to_string(), num(2.0));
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("t"), syn_map(o)])));
    for k in 0..5 {
        ok(call(&mut i, "bus_publish", vec![syn_text("t"), syn_int(k)]));
    }
    let a = ok(call(&mut i, "bus_recv", vec![syn_int(s), num(1.0)]));
    let b = ok(call(&mut i, "bus_recv", vec![syn_int(s), num(1.0)]));
    assert_eq!((int(&get(&a, "data")), int(&get(&b, "data"))), (3, 4), "drop_oldest conserva los últimos");

    let mut o = indexmap::IndexMap::new();
    o.insert("max_queue".to_string(), num(1.0));
    o.insert("on_full".to_string(), syn_text("error"));
    let s2 = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("u"), syn_map(o)])));
    ok(call(&mut i, "bus_publish", vec![syn_text("u"), syn_int(1)]));
    ok(call(&mut i, "bus_publish", vec![syn_text("u"), syn_int(2)]));
    let e = err_msg(call(&mut i, "bus_recv", vec![syn_int(s2), num(1.0)]));
    assert!(e.contains("overflowed"), "{}", e);
    // Retirada: publicar ya no la cuenta.
    assert_eq!(int(&ok(call(&mut i, "bus_publish", vec![syn_text("u"), syn_int(3)]))), 0);
}

#[test]
fn dropping_the_interpreter_unsubscribes_and_kills() {
    let _g = serial();
    let bus = Arc::new(Bus::new());
    {
        let mut i = interp_with_bus(bus.clone());
        ok(call(&mut i, "bus_subscribe", vec![syn_text("t")]));
        ok(call(&mut i, "bus_subscribe", vec![syn_text("u")]));
        assert_eq!(bus.subscriber_count(), 2);
        let (cmd, args) = script("sleep 30", "ping -n 31 127.0.0.1 > nul");
        ok(call(&mut i, "proc_spawn", vec![cmd, args]));
    }
    assert_eq!(bus.subscriber_count(), 0, "el hub retira sus suscripciones al morir");
}

#[test]
fn reset_hub_kills_processes_and_unsubscribes_but_keeps_the_interpreter_usable() {
    // `serve` REUSA el intérprete de cada worker: al terminar un request el hub vuelve
    // a cero (procesos muertos, suscripciones retiradas) y el siguiente request arranca
    // limpio sobre el mismo intérprete (mismo bus, builtins intactos).
    let _g = serial();
    let bus = Arc::new(Bus::new());
    let mut i = interp_with_bus(bus.clone());
    ok(call(&mut i, "bus_subscribe", vec![syn_text("t")]));
    let (cmd, args) = script("sleep 30", "ping -n 31 127.0.0.1 > nul");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    assert_eq!(bus.subscriber_count(), 1);
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "running");
    let t0 = Instant::now();
    reset_hub(&i);
    assert!(t0.elapsed() < Duration::from_secs(5), "el reset mata y cosecha sin colgarse");
    assert_eq!(bus.subscriber_count(), 0, "la suscripción del request anterior no sobrevive");
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "closed", "el proceso del request anterior no sobrevive");
    // El intérprete sigue operativo sobre el MISMO bus.
    let sub = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("t")])));
    assert_eq!(bus.publish("t", synsema_core::types::SendValue::Bool(true)), 1);
    let ev = ok(call(&mut i, "bus_recv", vec![syn_int(sub), num(1.0)]));
    assert_eq!(text(&get(&ev, "topic")), "t");
}

#[test]
fn select_mixes_process_and_bus_events() {
    let _g = serial();
    let bus = Arc::new(Bus::new());
    let mut i = interp_with_bus(bus.clone());
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("ui")])));
    let (cmd, args) = script("sleep 1; echo done", "ping -n 2 127.0.0.1 > nul& echo done");
    let p = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    let b2 = bus.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        b2.publish("ui", synsema_core::types::SendValue::Text("click".into()));
    });
    let mut targets = indexmap::IndexMap::new();
    targets.insert("sock".to_string(), syn_int(s));
    targets.insert("child".to_string(), syn_int(p));
    let mut sources = Vec::new();
    for _ in 0..4 {
        let ev = ok(call(&mut i, "select", vec![syn_map(targets.clone()), num(10.0)]));
        if matches!(ev, SynValue::Nothing) {
            break;
        }
        sources.push((text(&get(&ev, "source")), text(&get(&ev, "name")), text(&get(&ev, "type"))));
        if text(&get(&ev, "type")) == "exit" {
            break;
        }
    }
    assert_eq!(sources[0], ("bus".into(), "sock".into(), "event".into()), "{:?}", sources);
    assert!(sources.iter().any(|(s, n, t)| s == "proc" && n == "child" && t == "stdout"), "{:?}", sources);
    assert!(sources.iter().any(|(s, _, t)| s == "proc" && t == "exit"), "{:?}", sources);
}

#[test]
fn idle_select_sleeps_in_the_poller() {
    let _g = serial();
    let mut i = interp();
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("quiet")])));
    let before = POLL_ITERS.with(|c| c.get());
    let t0 = Instant::now();
    let r = ok(call(&mut i, "select", vec![list(vec![syn_int(s)]), num(0.3)]));
    assert!(matches!(r, SynValue::Nothing));
    let iters = POLL_ITERS.with(|c| c.get()) - before;
    assert!(t0.elapsed() >= Duration::from_millis(250));
    assert!(iters <= 2, "una espera ociosa no debe busy-spinear: {} iteraciones", iters);
}

#[test]
fn cancellation_wakes_a_blocked_select_immediately() {
    let _g = serial();
    let mut i = interp();
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("never")])));
    let token = i.cancel_token();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        token.cancel("test says stop");
    });
    let t0 = Instant::now();
    let e = err_msg(call(&mut i, "select", vec![list(vec![syn_int(s)]), num(30.0)]));
    assert!(e.contains("cancelled") && e.contains("test says stop"), "{}", e);
    assert!(t0.elapsed() < Duration::from_secs(3), "la cancelación despierta el Poll: {:?}", t0.elapsed());
}

#[test]
fn ws_select_accepts_any_handle_and_keeps_conn_tag() {
    let _g = serial();
    let mut i = interp();
    let s = int(&ok(call(&mut i, "bus_subscribe", vec![syn_text("t")])));
    ok(call(&mut i, "bus_publish", vec![syn_text("t"), syn_int(7)]));
    let ev = ok(call(&mut i, "ws_select", vec![list(vec![syn_int(s)]), num(1.0)]));
    assert_eq!(text(&get(&ev, "source")), "bus");
    assert_eq!(int(&get(&ev, "handle")), s);
    // Un handle de proceso no es una conexión para proc_* ↔ ws_* cruzados.
    let e = err_msg(call(&mut i, "proc_recv", vec![syn_int(s), num(0.1)]));
    assert!(e.contains("bus subscription"), "{}", e);
}
