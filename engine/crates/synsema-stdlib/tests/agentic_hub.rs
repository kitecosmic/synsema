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
//! - dropear el intérprete retira sus suscripciones del bus;
//! - tree-kill: `proc_kill`/`proc_close` matan al NIETO (grupo de procesos en Unix, Job
//!   Object en Windows); `process_group: false` lo desprende a propósito;
//! - file-watch: create/modify/delete honestos, `ignore`/`recursive`, gate `file_read`,
//!   tope de entradas en voz alta, y el handle entra en `select` etiquetado.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use synsema_agents::bus::Bus;
use synsema_capabilities::model::{normalize_path, Capability, CapabilitySet, CapabilityType};
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
// Pseudo-terminal (`pty: true`)
// =========================================================

fn pty_opts(extra: &[(&str, SynValue)]) -> SynValue {
    let mut m = indexmap::IndexMap::new();
    m.insert("pty".to_string(), SynValue::Bool(true));
    for (k, v) in extra {
        m.insert(k.to_string(), v.clone());
    }
    syn_map(m)
}

/// Salida plana (sin ANSI) de todos los eventos stdout.
fn plain_stdout(i: &mut Interpreter, evs: &[SynValue]) -> String {
    let raw: String = evs
        .iter()
        .filter(|e| text(&get(e, "type")) == "stdout")
        .map(|e| text(&get(e, "data")))
        .collect::<Vec<_>>()
        .join("");
    text(&ok(call(i, "strip_ansi", vec![syn_text(raw)])))
}

#[test]
fn pty_child_sees_a_terminal_and_output_is_one_stream() {
    let _g = serial();
    let mut i = interp();
    // Unix: `-t 0` es la prueba canónica. Windows: bajo ConPTY `cmd` imprime igual;
    // lo que se verifica ahí es que la salida llega, con exit real y `pty: true`.
    let (cmd, args) = script(
        "if [ -t 0 ] && [ -t 1 ]; then echo TTY_YES; else echo TTY_NO; fi; echo err_line >&2; exit 4",
        "echo TTY_YES& (echo err_line)1>&2& exit /b 4",
    );
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args, pty_opts(&[])])));
    let st = ok(call(&mut i, "proc_stats", vec![syn_int(h)]));
    assert!(matches!(get(&st, "pty"), SynValue::Bool(true)));
    let evs = drain(&mut i, h);
    let out = plain_stdout(&mut i, &evs);
    assert!(out.contains("TTY_YES"), "el hijo ve una tty: {:?}", out);
    // Un solo stream: stderr viaja por la tty como stdout.
    assert!(out.contains("err_line"), "stderr llega por el mismo stream: {:?}", out);
    assert!(evs.iter().all(|e| text(&get(e, "type")) != "stderr"), "no hay eventos stderr en modo pty");
    let exit = evs.last().unwrap();
    assert_eq!(text(&get(exit, "type")), "exit");
    assert_eq!(int(&get(&get(exit, "data"), "exit_code")), 4, "exit code real");
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
}

#[test]
fn pty_answers_an_interactive_prompt() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = if cfg!(windows) {
        (
            syn_text("cmd"),
            list(vec![syn_text("/V:ON"), syn_text("/C"), syn_text("set /p a=continue? [y/N] && echo got:!a!")]),
        )
    } else {
        script("printf 'continue? [y/N] '; read a; echo \"got:$a\"", "")
    };
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args, pty_opts(&[])])));
    // Esperar el prompt (bytes crudos, puede venir en varios chunks).
    let mut seen = String::new();
    for _ in 0..50 {
        let ev = ok(call(&mut i, "proc_recv", vec![syn_int(h), num(5.0)]));
        if matches!(ev, SynValue::Nothing) {
            break;
        }
        if text(&get(&ev, "type")) == "stdout" {
            seen.push_str(&text(&get(&ev, "data")));
        }
        if seen.contains("[y/N]") {
            break;
        }
    }
    assert!(seen.contains("[y/N]"), "prompt visto: {:?}", seen);
    ok(call(&mut i, "proc_send", vec![syn_int(h), syn_text("y\r")]));
    let evs = drain(&mut i, h);
    let out = plain_stdout(&mut i, &evs);
    assert!(out.contains("got:y"), "la respuesta llegó al programa: {:?}", out);
    assert_eq!(text(&get(evs.last().unwrap(), "type")), "exit");
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
}

#[test]
fn pty_resize_and_pipe_rejects_it() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("sleep 5", "ping -n 6 127.0.0.1 > nul");
    let h = int(&ok(call(
        &mut i,
        "proc_spawn",
        vec![cmd.clone(), args.clone(), pty_opts(&[("cols", num(120.0)), ("rows", num(40.0))])],
    )));
    ok(call(&mut i, "proc_resize", vec![syn_int(h), num(200.0), num(50.0)]));
    let e = err_msg(call(&mut i, "proc_resize", vec![syn_int(h), num(0.0), num(50.0)]));
    assert!(e.contains("cols"), "{}", e);
    // Un pty no tiene stdin aparte que cerrar: error claro, no silencio.
    let e = err_msg(call(&mut i, "proc_close_stdin", vec![syn_int(h)]));
    assert!(e.contains("EOF key"), "{}", e);
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));

    let h2 = int(&ok(call(&mut i, "proc_spawn", vec![cmd.clone(), args.clone()])));
    let e = err_msg(call(&mut i, "proc_resize", vec![syn_int(h2), num(80.0), num(24.0)]));
    assert!(e.contains("pty: true"), "{}", e);
    ok(call(&mut i, "proc_close", vec![syn_int(h2)]));

    // cols/rows sin pty: error de uso.
    let mut m = indexmap::IndexMap::new();
    m.insert("cols".to_string(), num(80.0));
    let e = err_msg(call(&mut i, "proc_spawn", vec![cmd, args, syn_map(m)]));
    assert!(e.contains("only apply with pty"), "{}", e);
}

#[test]
fn pty_kill_and_close_terminate_the_session() {
    let _g = serial();
    let mut i = interp();
    let (cmd, args) = script("sleep 30", "ping -n 31 127.0.0.1 > nul");
    let h = int(&ok(call(&mut i, "proc_spawn", vec![cmd.clone(), args.clone(), pty_opts(&[])])));
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "running");
    let t0 = Instant::now();
    ok(call(&mut i, "proc_kill", vec![syn_int(h)]));
    let exit = ok(call(&mut i, "proc_wait", vec![syn_int(h), num(5.0)]));
    assert!(!matches!(exit, SynValue::Nothing), "proc_wait devolvió el exit tras kill");
    assert!(t0.elapsed() < Duration::from_secs(5), "kill fue rápido");
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h)]))), "killed");
    let evs = drain(&mut i, h);
    assert_eq!(evs.iter().filter(|e| text(&get(e, "type")) == "exit").count(), 1, "{:?}", evs.len());
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));

    let h2 = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args, pty_opts(&[])])));
    let t1 = Instant::now();
    ok(call(&mut i, "proc_close", vec![syn_int(h2)]));
    assert!(t1.elapsed() < Duration::from_secs(5), "close mató y cosechó");
    assert_eq!(text(&ok(call(&mut i, "proc_status", vec![syn_int(h2)]))), "closed");
}

#[test]
fn pty_needs_the_same_exec_capability() {
    let _g = serial();
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    register_ws_builtins(&interp, caps);
    let mut i = interp;
    let (cmd, args) = script("echo x", "echo x");
    let e = err_msg(call(&mut i, "proc_spawn", vec![cmd, args, pty_opts(&[])]));
    assert!(e.contains("exec"), "deny-by-default, mismo gate: {}", e);
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

// =========================================================
// Tree-kill (el árbol, no sólo el hijo)
// =========================================================

/// Lanza un shell que engendra un NIETO de larga vida y devuelve `(handle, pid_nieto)`.
/// Unix: `sh` publica el pid del `sleep` en background y se queda en `wait`.
/// Windows: `cmd` corre `ping` (hijo directo de cmd = nieto de synsema); el pid se
/// consulta al SO por el ParentProcessId.
fn spawn_with_grandchild(i: &mut Interpreter, opts: Option<SynValue>) -> (i64, u32) {
    let (cmd, args) = script("sleep 30 & echo $!; wait", "ping -n 31 127.0.0.1 > nul");
    let mut a = vec![cmd, args];
    if let Some(o) = opts {
        a.push(o);
    }
    let h = int(&ok(call(i, "proc_spawn", a)));
    let grandchild: u32 = if cfg!(windows) {
        let pid = int(&get(&ok(call(i, "proc_stats", vec![syn_int(h)])), "pid"));
        let mut found = 0u32;
        for _ in 0..100 {
            let out = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "(Get-CimInstance Win32_Process -Filter \"ParentProcessId={}\" | Where-Object {{ $_.Name -like 'ping*' }} | Select-Object -First 1).ProcessId",
                        pid
                    ),
                ])
                .output()
                .expect("powershell");
            if let Ok(p) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() {
                found = p;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        found
    } else {
        let ev = ok(call(i, "proc_recv", vec![syn_int(h), num(5.0)]));
        assert_eq!(text(&get(&ev, "type")), "stdout");
        text(&get(&ev, "data")).trim().parse().expect("pid del nieto")
    };
    assert!(grandchild > 0, "encontró el nieto");
    (h, grandchild)
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !alive {
            return false;
        }
        // Distinguir zombie (Z) de vivo leyendo /proc si existe (Linux).
        match std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
            Ok(st) => !st.contains(") Z"),
            Err(_) => true,
        }
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
            .output()
            .expect("tasklist");
        String::from_utf8_lossy(&out.stdout).contains(&format!("\"{}\"", pid))
    }
}

fn wait_dead(pid: u32, max: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < max {
        if !pid_alive(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    !pid_alive(pid)
}

fn kill_pid_hard(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill").args(["/F", "/T", "/PID", &pid.to_string()]).output();
    }
}

#[test]
fn tree_kill_close_reaches_the_grandchild() {
    let _g = serial();
    let mut i = interp();
    let (h, gc) = spawn_with_grandchild(&mut i, None);
    assert!(pid_alive(gc), "el nieto está vivo antes del close");
    let stats = ok(call(&mut i, "proc_stats", vec![syn_int(h)]));
    assert!(matches!(get(&stats, "tree"), SynValue::Bool(true)), "tree: true por defecto");
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
    let dead = wait_dead(gc, Duration::from_secs(5));
    if !dead {
        kill_pid_hard(gc);
    }
    assert!(dead, "proc_close mató al nieto {}", gc);
}

#[test]
fn tree_kill_proc_kill_reaches_the_grandchild() {
    let _g = serial();
    let mut i = interp();
    let (h, gc) = spawn_with_grandchild(&mut i, None);
    ok(call(&mut i, "proc_kill", vec![syn_int(h)]));
    let exit = ok(call(&mut i, "proc_wait", vec![syn_int(h), num(5.0)]));
    assert!(!matches!(exit, SynValue::Nothing), "el hijo terminó");
    let dead = wait_dead(gc, Duration::from_secs(5));
    if !dead {
        kill_pid_hard(gc);
    }
    assert!(dead, "proc_kill mató al nieto {}", gc);
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
}

#[test]
fn process_group_false_detaches_on_purpose() {
    let _g = serial();
    let mut i = interp();
    let mut o = indexmap::IndexMap::new();
    o.insert("process_group".to_string(), SynValue::Bool(false));
    let (h, gc) = spawn_with_grandchild(&mut i, Some(syn_map(o)));
    let stats = ok(call(&mut i, "proc_stats", vec![syn_int(h)]));
    assert!(matches!(get(&stats, "tree"), SynValue::Bool(false)), "tree: false cuando se pidió");
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
    thread::sleep(Duration::from_millis(500));
    let survived = pid_alive(gc);
    kill_pid_hard(gc);
    assert!(survived, "con process_group: false el nieto {} sobrevive al close", gc);
}

#[test]
fn tree_kill_also_under_pty() {
    let _g = serial();
    let mut i = interp();
    let (h, gc) = spawn_with_grandchild(&mut i, Some(pty_opts(&[])));
    ok(call(&mut i, "proc_close", vec![syn_int(h)]));
    let dead = wait_dead(gc, Duration::from_secs(5));
    if !dead {
        kill_pid_hard(gc);
    }
    assert!(dead, "close bajo pty mató al nieto {}", gc);
}

// =========================================================
// File-watch
// =========================================================

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("synsema-watch-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> String {
        normalize_path(&self.0.to_string_lossy())
    }
    fn file(&self, rel: &str) -> std::path::PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn interp_fs(dir: &TempDir) -> Interpreter {
    let interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Exec, Some(shell().to_string())));
    caps.borrow_mut().grant(Capability::new(CapabilityType::FileRead, Some(dir.path())));
    caps.borrow_mut().grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/*", dir.path()))));
    register_ws_builtins(&interp, caps);
    attach_bus(&interp, Arc::new(Bus::new()));
    interp
}

fn fast_opts(extra: &[(&str, SynValue)]) -> SynValue {
    let mut m = indexmap::IndexMap::new();
    m.insert("interval".to_string(), num(0.05));
    for (k, v) in extra {
        m.insert(k.to_string(), v.clone());
    }
    syn_map(m)
}

/// Próximo evento del watch (hasta 3 s), o `nothing`.
fn next_ev(i: &mut Interpreter, w: i64) -> SynValue {
    ok(call(i, "watch_recv", vec![syn_int(w), num(3.0)]))
}

fn path_ends_with(ev: &SynValue, suffix: &str) -> bool {
    text(&get(ev, "path")).ends_with(suffix)
}

#[test]
fn watch_reports_create_modify_delete_and_nested_dirs() {
    let _g = serial();
    let d = TempDir::new("cmd");
    let mut i = interp_fs(&d);
    let w = int(&ok(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[])])));
    // Nada del contenido inicial: silencio.
    assert!(matches!(ok(call(&mut i, "watch_recv", vec![syn_int(w), num(0.2)])), SynValue::Nothing));

    std::fs::write(d.file("a.txt"), "hola").unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "create");
    assert!(path_ends_with(&ev, "/a.txt"), "path con `/`: {}", text(&get(&ev, "path")));
    assert!(matches!(get(&ev, "is_dir"), SynValue::Bool(false)));
    assert_eq!(text(&get(&ev, "source")), "watch");
    assert_eq!(int(&get(&ev, "handle")), w);

    // Modificar: el tamaño cambia aunque el mtime tenga granularidad gruesa.
    std::fs::write(d.file("a.txt"), "hola mundo").unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "modify");
    assert!(path_ends_with(&ev, "/a.txt"));

    // Directorio anidado + archivo adentro (recursivo por defecto).
    std::fs::create_dir(d.file("sub")).unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "create");
    assert!(path_ends_with(&ev, "/sub"));
    assert!(matches!(get(&ev, "is_dir"), SynValue::Bool(true)));
    std::fs::write(d.file("sub/b.txt"), "x").unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "create");
    assert!(path_ends_with(&ev, "/sub/b.txt"));

    std::fs::remove_file(d.file("a.txt")).unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "delete");
    assert!(path_ends_with(&ev, "/a.txt"));

    let st = ok(call(&mut i, "watch_stats", vec![syn_int(w)]));
    assert_eq!(text(&get(&st, "path")), d.path());
    assert!(int(&get(&st, "scans")) >= 4);
    assert_eq!(int(&get(&st, "entries")), 3, "raíz + sub + sub/b.txt");
    assert_eq!(int(&get(&st, "dropped")), 0);
    ok(call(&mut i, "watch_close", vec![syn_int(w)]));
    ok(call(&mut i, "watch_close", vec![syn_int(w)])); // idempotente
    let e = err_msg(call(&mut i, "watch_recv", vec![syn_int(w), num(0.1)]));
    assert!(e.contains("unknown or closed watch handle"), "{}", e);
}

#[test]
fn watch_honours_ignore_and_non_recursive() {
    let _g = serial();
    let d = TempDir::new("ign");
    std::fs::create_dir(d.file("sub")).unwrap();
    let mut i = interp_fs(&d);
    let ignore = list(vec![syn_text("*.log")]);
    let w = int(&ok(call(
        &mut i,
        "watch",
        vec![syn_text(d.path()), fast_opts(&[("recursive", SynValue::Bool(false)), ("ignore", ignore)])],
    )));
    std::fs::write(d.file("sub/deep.txt"), "x").unwrap();
    std::fs::write(d.file("noise.log"), "x").unwrap();
    assert!(
        matches!(ok(call(&mut i, "watch_recv", vec![syn_int(w), num(0.4)])), SynValue::Nothing),
        "ni lo anidado ni lo ignorado producen eventos"
    );
    std::fs::write(d.file("real.txt"), "x").unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "create");
    assert!(path_ends_with(&ev, "/real.txt"));
}

#[test]
fn watch_joins_select_with_processes_and_is_tagged() {
    let _g = serial();
    let d = TempDir::new("sel");
    let mut i = interp_fs(&d);
    let w = int(&ok(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[])])));
    let (cmd, args) = script("sleep 2", "ping -n 3 127.0.0.1 > nul");
    let p = int(&ok(call(&mut i, "proc_spawn", vec![cmd, args])));
    let mut targets = indexmap::IndexMap::new();
    targets.insert("files".to_string(), syn_int(w));
    targets.insert("build".to_string(), syn_int(p));
    std::fs::write(d.file("c.txt"), "x").unwrap();
    let ev = ok(call(&mut i, "select", vec![syn_map(targets), num(3.0)]));
    assert_eq!(text(&get(&ev, "source")), "watch");
    assert_eq!(text(&get(&ev, "name")), "files");
    assert_eq!(text(&get(&ev, "type")), "create");
    // Un handle de watch no es un proceso (y viceversa): el error lo dice.
    let e = err_msg(call(&mut i, "proc_kill", vec![syn_int(w)]));
    assert!(e.contains("is a file watch, not a process"), "{}", e);
    let e = err_msg(call(&mut i, "watch_stats", vec![syn_int(p)]));
    assert!(e.contains("is a process, not a file watch"), "{}", e);
    ok(call(&mut i, "proc_close", vec![syn_int(p)]));
}

#[test]
fn watch_needs_file_read_and_an_existing_path() {
    let _g = serial();
    let d = TempDir::new("gate");
    let mut plain = interp();
    let e = err_msg(call(&mut plain, "watch", vec![syn_text(d.path())]));
    assert!(e.contains("file_read("), "{}", e);
    let mut i = interp_fs(&d);
    let e = err_msg(call(&mut i, "watch", vec![syn_text(format!("{}/nope", d.path()))]));
    assert!(e.contains("no such file or directory"), "{}", e);
    // Un archivo suelto también se puede mirar.
    std::fs::write(d.file("one.txt"), "1").unwrap();
    let w = int(&ok(call(&mut i, "watch", vec![syn_text(format!("{}/one.txt", d.path())), fast_opts(&[])])));
    std::fs::write(d.file("one.txt"), "12").unwrap();
    let ev = next_ev(&mut i, w);
    assert_eq!(text(&get(&ev, "type")), "modify");
    assert!(path_ends_with(&ev, "/one.txt"));
}

#[test]
fn watch_max_entries_fails_loud_at_open_and_later() {
    let _g = serial();
    let d = TempDir::new("max");
    for n in 0..5 {
        std::fs::write(d.file(&format!("f{}.txt", n)), "x").unwrap();
    }
    let mut i = interp_fs(&d);
    let e = err_msg(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[("max_entries", num(3.0))])]));
    assert!(e.contains("more than 3 entries"), "{}", e);
    // Con tope 10 arranca; al superarlo después, el próximo recv es un error terminal.
    let w = int(&ok(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[("max_entries", num(10.0))])])));
    for n in 5..20 {
        std::fs::write(d.file(&format!("f{}.txt", n)), "x").unwrap();
    }
    let e = err_msg(call(&mut i, "watch_recv", vec![syn_int(w), num(3.0)]));
    assert!(e.contains("more than 10 entries"), "{}", e);
    let e = err_msg(call(&mut i, "watch_stats", vec![syn_int(w)]));
    assert!(e.contains("unknown or closed watch handle"), "{}", e);
}

#[test]
fn watch_budget_is_enforced() {
    let _g = serial();
    std::env::set_var("SYNSEMA_WATCH_MAX", "2");
    let d = TempDir::new("budget");
    let mut i = interp_fs(&d);
    std::env::remove_var("SYNSEMA_WATCH_MAX");
    ok(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[])]));
    ok(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[])]));
    let e = err_msg(call(&mut i, "watch", vec![syn_text(d.path()), fast_opts(&[])]));
    assert!(e.contains("watch budget reached"), "{}", e);
}
