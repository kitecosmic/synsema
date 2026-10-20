//! v0.6.45 (A1, extendido): un agente de `spawn` corre en su propio hilo con su propio intérprete
//! (`setup_swarm_interpreter`), igual que un worker de `parallel_map`, y tampoco cableaba los
//! providers. Binario propio: muta el entorno del proceso.

use synsema_runtime::engine::run_program;

#[test]
fn judge_inside_a_spawned_agent_uses_the_callers_provider() {
    std::env::set_var("SYNSEMA_JUDGE_PROVIDER", "mock");
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    let src = r#"agent Classifier
    let v be judge "I want my money back"
        refund: whether "Is the customer asking for money back?"
    share v.refund.available as "available"
    signal "done"

print(judge_available())
spawn Classifier
wait_for "done" timeout 5
observe "available" as a
print(a)
"#;
    let r = run_program(src, "<spawn-judge>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output.last().map(String::as_str), Some("true"), "el agente quedó OFFLINE: {:?}", r.output);
}
