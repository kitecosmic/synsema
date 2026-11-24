//! Integración Rust del swarm que afirma salida y diagnósticos del host.
//! Los casos observables desde el lenguaje viven en `tests/engine_concurrency.test.syn`.

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
