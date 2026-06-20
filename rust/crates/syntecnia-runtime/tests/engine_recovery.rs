//! Capa 9 — diagnósticos ricos del engine (espeja test_recovery.py, integración).

use syntecnia_runtime::engine::run_with_diagnostics;

#[test]
fn rich_diagnostic_on_error() {
    let d = run_with_diagnostics("let x be 0\nlet y be 10 / x\n", "t.syn");
    assert!(!d.result.success);
    assert!(!d.diagnostics.is_empty());
    let diag = &d.diagnostics[0];
    assert_eq!(diag.error_category, "data");
    assert!(diag.recoverable);
    assert!(!diag.suggestions.is_empty());
}

#[test]
fn rich_diagnostic_undefined_var() {
    let d = run_with_diagnostics("print(unknown_var)", "t.syn");
    assert!(!d.result.success);
    assert!(!d.diagnostics.is_empty());
    assert_eq!(d.diagnostics[0].error_category, "logic");
}

#[test]
fn rich_diagnostic_with_intent() {
    let src = "intent: \"Calculate payroll\"\nlet salary be 5000\nlet hours be 0\nlet rate be salary / hours\n";
    let d = run_with_diagnostics(src, "t.syn");
    assert!(!d.result.success);
    assert!(!d.diagnostics.is_empty());
    assert_eq!(d.diagnostics[0].active_intent.as_deref(), Some("Calculate payroll"));
}

#[test]
fn diagnostic_shows_variables() {
    let src = "let name be \"Alice\"\nlet balance be 100\nlet items be [1, 2, 3]\nlet bad be 10 / 0\n";
    let d = run_with_diagnostics(src, "t.syn");
    assert!(!d.result.success);
    let diag = &d.diagnostics[0];
    assert!(diag.visible_variables.contains_key("name"));
    assert!(diag.visible_variables["name"].contains("Alice"));
}

#[test]
fn diagnostic_format_agent() {
    let d = run_with_diagnostics("let x be 1 / 0", "t.syn");
    assert!(!d.result.success);
    let agent = d.diagnostics[0].format_agent();
    assert!(agent.get("suggestions").is_some());
    assert!(agent.get("error_category").is_some());
    assert_eq!(agent["recoverable"], true);
}
