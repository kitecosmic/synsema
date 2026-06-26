//! Integración Rust del swarm (capa 7) — espeja `test_concurrency.py`.
//! Determinismo: en vez de `time.sleep`, joineamos los hilos con `swarm.wait_all()`.

use synsema_agents::swarm::AgentState;
use synsema_core::number::Number;
use synsema_core::types::SendValue;
use synsema_runtime::engine::{run_program, run_with_diagnostics, Engine};

fn text(s: &str) -> SendValue {
    SendValue::Text(s.to_string())
}
fn num(n: i64) -> SendValue {
    SendValue::Number(Number::Int(n))
}

#[test]
fn agent_define_does_not_execute() {
    let engine = Engine::new();
    let r = engine.run(
        "agent Worker\n    print(\"I am running!\")\n\nprint(\"After definition\")",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    // El cuerpo del agente NO corre al definirlo (sólo al spawnear).
    assert_eq!(r.output, vec!["After definition"]);
}

#[test]
fn spawn_runs_agent_body() {
    let engine = Engine::new();
    let r = engine.run(
        "agent Greeter\n    share \"hello from agent\" as \"greeting\"\n\nspawn Greeter",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    assert_eq!(engine.swarm.blackboard.read("greeting", ""), Some(text("hello from agent")));
}

#[test]
fn spawn_with_arguments() {
    let engine = Engine::new();
    let r = engine.run(
        "agent Calculator\n    let result be x * 2\n    share result as \"calc_result\"\n\nspawn Calculator with x = 21",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    assert_eq!(engine.swarm.blackboard.read("calc_result", ""), Some(num(42)));
}

#[test]
fn two_agents_communicate_via_blackboard() {
    let engine = Engine::new();
    let src = "agent Producer\n    share \"data_from_producer\" as \"shared_data\"\n    signal \"data_ready\"\n\nagent Consumer\n    wait_for \"data_ready\"\n    observe \"shared_data\" as data\n    share data as \"consumed\"\n\nspawn Producer\nspawn Consumer";
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    assert_eq!(engine.swarm.blackboard.read("shared_data", ""), Some(text("data_from_producer")));
    assert_eq!(engine.swarm.blackboard.read("consumed", ""), Some(text("data_from_producer")));
}

#[test]
fn signal_wakes_waiting_agent() {
    let engine = Engine::new();
    let src = "agent Sender\n    share \"preparing\" as \"status\"\n    signal \"ready\"\n\nagent Receiver\n    wait_for \"ready\"\n    share \"received\" as \"status\"\n\nspawn Receiver\nspawn Sender";
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    // El último write gana: Receiver escribe "received" tras despertar.
    assert_eq!(engine.swarm.blackboard.read("status", ""), Some(text("received")));
}

#[test]
fn main_shares_agent_observes() {
    let engine = Engine::new();
    let src = "share \"hello from main\" as \"main_data\"\n\nagent Reader\n    observe \"main_data\" as data\n    share data as \"agent_read\"\n\nspawn Reader";
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    assert_eq!(engine.swarm.blackboard.read("agent_read", ""), Some(text("hello from main")));
}

#[test]
fn spawn_undefined_agent_fails() {
    let engine = Engine::new();
    let r = engine.run("spawn NonExistent", "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("No agent defined") || e.contains("NonExistent")));
}

#[test]
fn swarm_dashboard_shows_agents() {
    let engine = Engine::new();
    let r = engine.run("agent Worker\n    share \"done\" as \"status\"\n\nspawn Worker", "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    assert!(engine.swarm.total_agents() >= 1);
    let states = engine.swarm.agent_states();
    assert!(states.iter().any(|(id, _)| id.contains("Worker")));
}

#[test]
fn multiple_spawns_of_same_agent() {
    let engine = Engine::new();
    let src = "agent Adder\n    let result be n + 100\n    share result as \"sum\"\n\nspawn Adder with n = 1\nspawn Adder with n = 2\nspawn Adder with n = 3";
    let r = engine.run(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let val = engine.swarm.blackboard.read("sum", "");
    assert!(matches!(val, Some(SendValue::Number(Number::Int(n))) if (101..=103).contains(&n)), "got {:?}", val);
    assert_eq!(engine.swarm.total_agents(), 3);
}

#[test]
fn agent_error_captured_in_swarm() {
    let engine = Engine::new();
    let r = engine.run("agent Crasher\n    let x be 1 / 0\n\nspawn Crasher", "<t>");
    // El programa principal tiene éxito aunque el agente crashee.
    assert!(r.success, "{:?}", r.errors);
    engine.swarm.wait_all();
    let states = engine.swarm.agent_states();
    let crasher = states.iter().find(|(id, _)| id.contains("Crasher"));
    assert!(crasher.is_some(), "no se encontró Crasher en {:?}", states);
    assert_eq!(crasher.unwrap().1, AgentState::Error);
}

// -- DE-011: aislamiento de agentes en `synsema run` (vía run_program) --

#[test]
fn run_program_isolates_agent_error_and_keeps_main_output() {
    // probe_19: un `raise` sin recover dentro de un agente NO debe tumbar el main ni
    // truncar su salida. Antes (camino sin swarm) se imprimía solo "A".
    let src = "agent Crasher\n    raise(\"boom del agente\")\n\nprint(\"A\")\nspawn Crasher\nprint(\"B\")\nprint(\"C\")";
    let r = run_program(src, "<t>");
    // (1) La salida del main se preserva completa.
    assert_eq!(r.output, vec!["A", "B", "C"]);
    // (4) Política de exit: ≠0 porque un agente terminó en ERROR ...
    assert!(!r.success, "se esperaba fallo por agente en ERROR");
    // (3) ... y el error del agente se reporta (no se traga en silencio).
    assert!(
        r.errors.iter().any(|e| e.contains("boom del agente")),
        "el error del agente no se reportó: {:?}",
        r.errors
    );
}

#[test]
fn run_program_delayed_agent_crash_does_not_abort_main() {
    // probe_20: crash TARDÍO. El agente espera y luego falla; el main debe completar
    // su salida igualmente (no es una carrera: la salida del main no se descarta).
    let src = "agent Slow\n    sleep(0.2)\n    raise(\"late boom\")\n\nprint(\"A\")\nspawn Slow\nprint(\"B\")\nprint(\"C\")";
    let r = run_program(src, "<t>");
    assert_eq!(r.output, vec!["A", "B", "C"]);
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("late boom")), "errors={:?}", r.errors);
}

#[test]
fn run_program_happy_path_blackboard_and_signal() {
    // probe_13 (criterio 5): caso feliz intacto — spawn + share + signal coordinan bien
    // entre main y agente (idéntico a conform --swarm).
    let src = "agent Producer\n    share \"payload\" as \"out\"\n    signal \"done\"\n\nspawn Producer\nwait_for \"done\"\nobserve \"out\" as got\nprint(got)";
    let r = run_program(src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["payload"]);
}

#[test]
fn run_program_without_agents_is_unaffected() {
    // Programa sin agentes: comportamiento normal, sin regresión.
    let r = run_program("print(\"hello\")\nprint(1 + 1)", "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["hello", "2"]);
}

// -- DE-014: `run --explain` (run_with_diagnostics) también aísla agentes --

#[test]
fn run_with_diagnostics_isolates_agent_error_and_keeps_main_output() {
    // Antes (DE-014): el camino de diagnóstico era single-thread y un raise de agente
    // abortaba el main (solo se veía "A"). Ahora cablea el swarm como `run`.
    let src = "agent Crasher\n    raise(\"boom del agente\")\n\nprint(\"A\")\nspawn Crasher\nprint(\"B\")\nprint(\"C\")";
    let run = run_with_diagnostics(src, "<t>");
    assert_eq!(run.result.output, vec!["A", "B", "C"]);
    assert!(!run.result.success);
    // El main NO falló → no hay diagnóstico rico ...
    assert!(run.diagnostics.is_empty(), "el main no falló: no debería haber diagnóstico");
    // ... pero el error del agente se refleja (aislado).
    assert!(
        run.result.errors.iter().any(|e| e.contains("boom del agente")),
        "errors={:?}",
        run.result.errors
    );
}

#[test]
fn run_with_diagnostics_main_error_still_has_rich_diagnostic() {
    // Sin regresión de DE-003/012/013: un error del MAIN sigue dando diagnóstico rico,
    // con variables solo de usuario.
    let run = run_with_diagnostics("let m be {\"a\": 1}\nprint(m[\"k\"])", "p.syn");
    assert!(!run.result.success);
    let diag = run.diagnostics.first().expect("debería haber diagnóstico del main");
    assert!(diag.message.contains("no key"), "msg={}", diag.message);
    assert!(diag.visible_variables.contains_key("m"));
    assert!(!diag.visible_variables.contains_key("print"), "no debería listar builtins");
}
