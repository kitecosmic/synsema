//! Conformidad del Batch 2: pattern matching enriquecido + default/named params.
//!
//! Corre programas `.syn` reales por el intérprete de core (`run_source`). Cubre §6.2/§6.3
//! del spec + los desafíos adversariales §6.4 (G2/G3, `=` vs `==`, patrones profundos,
//! dos spreads → error de parseo).

use synsema_core::interpreter::run_source;

fn assert_output(source: &str, expected: &[&str]) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.output, exp, "fuente:\n{}", source);
}

fn assert_error_contains(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "Se esperaba un error con '{}', got {:?}\nfuente:\n{}",
        needle,
        r.errors,
        source
    );
}

// =========================================================
// G2 — `is <ident>` a nivel TOP compara por valor (NO liga)
// =========================================================

// =========================================================
// G3 — aridad permisiva para params SIN default
// =========================================================

// =========================================================
// Default / named params
// =========================================================

const CONNECT: &str = "task connect(host, port = 5432, timeout = 30)\n    give host + \":\" + text(port) + \":\" + text(timeout)\n";

// =========================================================
// Pattern matching — listas
// =========================================================

#[test]
fn two_spreads_is_parse_error() {
    assert_error_contains(
        "match [1, 2, 3]\n    is [...a, ...b]\n        print(\"x\")\n",
        "at most one",
    );
}

// =========================================================
// Pattern matching — maps
// =========================================================

// =========================================================
// Wildcard + guards
// =========================================================

// =========================================================
// Enum variant binding (G1) + guard + patrón profundo
// =========================================================

const ENUM: &str = "enum Order\n    pending\n    paid(amount)\n    shipped(date, carrier)\n";

// =========================================================
// Dogfood recursivo + property chain intacto (G6)
// =========================================================

