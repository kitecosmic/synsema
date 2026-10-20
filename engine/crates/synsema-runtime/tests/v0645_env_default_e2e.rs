//! v0.6.45 (A2): el default de `env`/`secret` pasaba por la forma de texto de Python:
//! `env(n, nothing)` daba `"None"` (un valor "válido" que fallaba lejos de la causa),
//! `secret(n, nothing)` sellaba el texto `"None"` y `env(n, true)` daba `"True"`.

use synsema_runtime::engine::run_source;

const UNDEF: &str = "SYNSEMA_V0645_A2_SURELY_UNDEFINED";

fn run(body: &str) -> Vec<String> {
    std::env::remove_var(UNDEF);
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    let src = format!("require env(\"{UNDEF}\")\nrequire secret(\"{UNDEF}\")\n{body}");
    let r = run_source(&src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    r.output
}

#[test]
fn a_nothing_default_gives_nothing() {
    let out = run(&format!(
        "print(env(\"{UNDEF}\", nothing) == nothing)\nprint(secret(\"{UNDEF}\", nothing) == nothing)\n"
    ));
    assert_eq!(out, ["true", "true"]);
}

#[test]
fn a_bool_default_is_synsema_text_and_a_number_keeps_its_text() {
    let out = run(&format!(
        "print(env(\"{UNDEF}\", true))\nprint(env(\"{UNDEF}\", 8080))\nprint(type_of(env(\"{UNDEF}\", 8080)))\n"
    ));
    assert_eq!(out, ["true", "8080", "text"]);
}

#[test]
fn without_a_default_an_undefined_variable_is_still_an_error() {
    std::env::remove_var(UNDEF);
    let src = format!("require env(\"{UNDEF}\")\nprint(env(\"{UNDEF}\"))\n");
    let r = run_source(&src, "<test>");
    assert!(!r.success, "debía fallar: {:?}", r.output);
}

#[test]
fn a_defined_variable_wins_over_a_nothing_default() {
    let key = "SYNSEMA_V0645_A2_DEFINED";
    std::env::set_var(key, "valor");
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    let src = format!("require env(\"{key}\")\nprint(env(\"{key}\", nothing))\n");
    let r = run_source(&src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["valor"]);
}
