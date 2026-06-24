//! E2E del runner `synsema test` (Batch 3): `engine::run_tests` sobre programas `.syn`
//! reales. Cubre aislamiento entre tests (G5), no-abort, setup top-level visible,
//! capabilities (G4) y el reporte agregado.

use synsema_runtime::engine::run_tests;

fn names_passed(src: &str) -> Vec<(String, bool)> {
    let r = run_tests(src, "<t>.syn");
    r.outcomes.into_iter().map(|o| (o.name, o.passed)).collect()
}

#[test]
fn three_tests_one_fails_no_abort() {
    // Un test pasa, uno falla por aserción, uno por error de runtime. El runner corre los
    // 3 (no aborta en el primero que falla, G5) → 1 passed, 2 failed.
    let src = "test \"pasa\"\n    assert_eq(1 + 1, 2)\n\
               test \"falla por assert\"\n    assert(false, \"boom\")\n\
               test \"falla por runtime\"\n    let x be undefined_var\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.passed, 1, "outcomes: {:?}", r.outcomes);
    assert_eq!(r.failed, 2, "outcomes: {:?}", r.outcomes);
    // El primero pasa; el segundo falla por aserción (assertion=true); el tercero por runtime.
    assert!(r.outcomes[0].passed);
    assert!(!r.outcomes[1].passed && r.outcomes[1].assertion);
    assert!(r.outcomes[1].message.as_deref().unwrap().contains("boom"));
    assert!(!r.outcomes[2].passed && !r.outcomes[2].assertion);
}

#[test]
fn setup_top_level_visible_in_tests() {
    // task + let top-level (setup) son visibles dentro de los tests.
    let src = "task helper(n)\n    give n * 2\nlet fixture be 21\n\
               test \"usa setup\"\n    assert_eq(helper(fixture), 42)\n";
    assert_eq!(names_passed(src), vec![("usa setup".to_string(), true)]);
}

#[test]
fn isolation_between_tests() {
    // Un `let x be 1` dentro de test A NO es visible en test B (entornos hijos aislados, G5).
    let src = "test \"A define x\"\n    let x be 1\n    assert_eq(x, 1)\n\
               test \"B no ve x\"\n    assert_error(() => x)\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.passed, 2, "x no debería filtrarse entre tests: {:?}", r.outcomes);
}

#[test]
fn setup_failure_reports_single_outcome() {
    // Si el setup top-level falla, se devuelve un único outcome de error de setup.
    let src = "let bad be undefined_top\ntest \"nunca llega\"\n    assert(true)\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.failed, 1);
    assert_eq!(r.passed, 0);
    assert_eq!(r.outcomes.len(), 1);
    assert_eq!(r.outcomes[0].name, "<setup>");
}

#[test]
fn capabilities_via_require_g4() {
    // Un require al top concede la capability; el test la usa igual que un programa normal.
    // (random no requiere argumentos de I/O; basta para probar el gating en el runner.)
    let granted = "require random\ntest \"random con grant\"\n    let r be random()\n    assert(r >= 0)\n";
    let r = run_tests(granted, "<t>.syn");
    assert_eq!(r.passed, 1, "outcomes: {:?}", r.outcomes);

    // Sin el grant, el test falla con error de capability — pero el runner NO se rompe.
    let denied = "test \"random sin grant\"\n    let r be random()\n";
    let r2 = run_tests(denied, "<t>.syn");
    assert_eq!(r2.failed, 1);
    assert!(r2.outcomes[0].message.as_deref().unwrap().to_lowercase().contains("capab"));
}

#[test]
fn assert_inside_task_called_from_test_marks_failed() {
    // assert dentro de un task llamado desde un test → el fallo propaga y marca el test ✗.
    let src = "task check(n)\n    assert(n > 0, \"must be positive\")\n\
               test \"usa check ok\"\n    check(5)\n\
               test \"usa check mal\"\n    check(-1)\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.passed, 1, "outcomes: {:?}", r.outcomes);
    assert!(r.outcomes[1].message.as_deref().unwrap().contains("must be positive"));
}

#[test]
fn print_output_captured_not_in_outcomes() {
    // El `print` dentro de un test va a `report.output` (sólo con -v), no contamina outcomes.
    let src = "test \"con print\"\n    print(\"hola desde el test\")\n    assert(true)\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.passed, 1);
    assert!(r.output.iter().any(|l| l.contains("hola desde el test")));
}

#[test]
fn parse_error_is_a_failure() {
    let r = run_tests("test \"sin nombre\"\n    let x be )(\n", "<t>.syn");
    assert_eq!(r.failed, 1);
    assert!(r.outcomes[0].message.as_deref().unwrap().contains("error"));
}
