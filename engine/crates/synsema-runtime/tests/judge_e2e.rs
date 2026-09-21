//! E2E del primitivo `judge` a través del MOTOR (capabilities + provider por knob), sin red:
//! `SYNSEMA_JUDGE_PROVIDER=mock` cablea el provider determinista de `synsema-llm`. Cubre lo
//! que el core no puede ver: la capability propia (`require judge`, que NO concede `llm`),
//! el techo determinista, `sandbox`, y que el provider llega al intérprete por el mismo
//! camino que el LLM. Spec: specs/system-one-judge.md §5, §6, §8 J1.

use synsema_capabilities::model::{build_ceiling_deterministic, Capability, CapabilityType};
use synsema_runtime::engine::{run_source, run_source_ceiled};

const BLOCK: &str = r#"let ticket be {"text": "I want my money back NOW"}
let v be judge ticket
    refund: whether "The customer is asking for money back"
    team:   choose "Which team should handle this?" between {"billing": "Payments", "technical": "Bugs"} or nothing
    anger:  rate "How frustrated is the customer?" across ["Calm", "Frustrated", "Very angry"]
"#;

fn with_mock() {
    // Process-global a propósito: todos los tests de este binario usan el mismo valor.
    std::env::set_var("SYNSEMA_JUDGE_PROVIDER", "mock");
}

fn cap(t: CapabilityType) -> Capability {
    Capability::new(t, None)
}

#[test]
fn mock_provider_wires_through_the_engine_and_answers_deterministically() {
    with_mock();
    let src = format!(
        "require judge\n{}print(judge_available())\nprint(v.refund.probability)\nprint(v.team.choice)\n\
         print(v.team.confidence)\nprint(v.anger.level)\nprint(v.anger.score)\nprint(v.refund.available)\n\
         print(judge_model())\nprint(judge_usage())\n",
        BLOCK
    );
    let r = run_source(&src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        ["true", "0.5", "billing", "1.0", "Frustrated", "1.0", "true", "mock-judge", "0"]
    );
}

#[test]
fn non_secure_run_grants_judge_ambiently_like_llm() {
    with_mock();
    // Sin `require judge`, en `run` no-secure el bloque corre igual (paridad con las ops LLM).
    let src = format!("{}print(v.team.choice)\n", BLOCK);
    let r = run_source(&src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["billing"]);
}

#[test]
fn require_llm_does_not_grant_judge_under_a_ceiling() {
    with_mock();
    // Techo con `llm` y `stdout` pero sin `judge`: el programa declara `require llm` y aun
    // así el bloque `judge` tiene que fallar. Clasificar y generar son derechos distintos.
    let src = format!("require llm\n{}print(v.team.choice)\n", BLOCK);
    let r = run_source_ceiled(&src, "<test>", Some(vec![cap(CapabilityType::Llm), cap(CapabilityType::Stdout)]));
    assert!(!r.success, "debía fallar sin `judge`: {:?}", r.output);
    assert!(
        r.errors.iter().any(|e| e.contains("judge")),
        "el error debe nombrar la capability judge: {:?}",
        r.errors
    );
}

#[test]
fn require_judge_under_a_ceiling_that_has_it_works() {
    with_mock();
    let src = format!("require judge\n{}print(v.team.choice)\n", BLOCK);
    let r = run_source_ceiled(&src, "<test>", Some(vec![cap(CapabilityType::Judge), cap(CapabilityType::Stdout)]));
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["billing"]);
}

#[test]
fn deterministic_ceiling_denies_judge() {
    with_mock();
    // El techo determinista es sólo `stdout`: `judge` es I/O de red no determinista.
    let src = format!("require judge\n{}print(v.team.choice)\n", BLOCK);
    let r = run_source_ceiled(&src, "<test>", Some(build_ceiling_deterministic()));
    assert!(!r.success, "debía fallar bajo --deterministic: {:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains("judge")), "{:?}", r.errors);
}

#[test]
fn sandbox_denies_judge() {
    with_mock();
    let src = "require judge\nsandbox\n    let v be judge \"x\"\n        a: whether \"Is it?\"\n    print(v.a.probability)\n";
    let r = run_source(src, "<test>");
    assert!(!r.success, "debía fallar dentro de sandbox: {:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains("judge")), "{:?}", r.errors);
}

#[test]
fn decide_is_served_by_the_judge_when_the_knob_is_on() {
    with_mock();
    std::env::set_var("SYNSEMA_JUDGE_DECIDE", "1");
    // El mock elige la primera opción: `decide` devuelve "alpha" byte a byte, sin LLM.
    let src = "require judge\nlet d be decide between [\"alpha\", \"beta\"] given \"speed matters\"\nprint(d)\nprint(judge_usage())\n";
    let r = run_source(src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["alpha", "0"]);
    // Bajo un techo sin `judge`, el `decide` servido por el juez lo dice con nombre y apellido.
    let src = format!("require llm\nlet d be decide between [\"alpha\", \"beta\"] given \"x\"\nprint(d)\n");
    let r = run_source_ceiled(&src, "<test>", Some(vec![cap(CapabilityType::Llm), cap(CapabilityType::Stdout)]));
    assert!(!r.success, "{:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains("SYNSEMA_JUDGE_DECIDE") && e.contains("require judge")), "{:?}", r.errors);
    std::env::remove_var("SYNSEMA_JUDGE_DECIDE");
}

#[test]
fn judge_and_llm_are_parallel_slots() {
    with_mock();
    // El slot de judge cableado no cablea el LLM ni viceversa: cada uno se consulta aparte.
    let src = format!("{}print(judge_available())\nprint(llm_available())\n", BLOCK);
    let r = run_source(&src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "true");
    // llm_available depende del entorno del proceso de test; sólo afirmamos que es un bool.
    assert!(r.output[1] == "true" || r.output[1] == "false");
}
