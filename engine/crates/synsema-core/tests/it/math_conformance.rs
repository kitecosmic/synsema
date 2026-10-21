//! Conformidad de la completitud matemática (Batch 4): números complejos + funciones
//! especiales/hiperbólicas. Corre programas `.syn` reales por el intérprete de core.
//! Incluye los guardrails G1 (real intacto), G3 (orden), G4 (igualdad Pythónica) y los
//! vectores publicados de gamma/erf/beta con tolerancia 1e-9.

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

/// `print(expr)` → debe imprimir exactamente `expected`.
fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

/// La expresión booleana debe ser `true` (para comparaciones aproximadas con tolerancia).
fn t(expr: &str) {
    assert_eq!(out(&format!("print(text({}))", expr)), vec!["true".to_string()], "expr: {}", expr);
}

fn fails_with(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba error con '{}', got {:?}",
        needle,
        r.errors
    );
}

// =========================================================
// G1 — comportamiento REAL idéntico a hoy
// =========================================================

#[test]
fn g1_real_unchanged() {
    t("is_nan(sqrt(-1))"); // sqrt(-1) real → NaN (NO complejo)
    shows("text(ln(0))", "-inf"); // ln(0) → -inf
    shows("text(sqrt(4))", "2.0"); // Float
    t("abs(sqrt(2) - 1.4142135623730951) < 0.000000001");
    shows("text(abs(-5))", "5"); // Int preservado (no "5.0")
    shows("text(abs(-5))", "5");
    t("type_of(abs(-3)) == \"number\"");
    shows("text(min(3, 5, 1))", "1"); // type-preservation
}

// =========================================================
// Constructor / accesores
// =========================================================

#[test]
fn complex_constructor_and_display() {
    shows("complex(3, 2)", "3+2i");
    shows("complex(3, -2)", "3-2i");
    shows("complex(0, 1)", "0+1i");
    shows("complex(1.5, -2.5)", "1.5-2.5i");
    shows("type_of(complex(1, 2))", "complex");
}

#[test]
fn complex_accessors() {
    shows("text(real(complex(3, 4)))", "3.0");
    shows("text(imag(complex(3, 4)))", "4.0");
    shows("text(abs(complex(3, 4)))", "5.0"); // módulo (Float, no Complex)
    shows("conj(complex(3, 4))", "3-4i");
    t("abs(arg(complex(0, 1)) - 1.5707963267948966) < 0.000000001"); // π/2
    // accesores sobre un real (ergonomía)
    shows("text(real(5))", "5.0");
    shows("text(imag(5))", "0.0");
}

#[test]
fn is_complex_and_truthy() {
    t("is_complex(complex(1, 0))");
    t("not is_complex(5)");
    t("not is_complex(\"x\")");
    // complex(0,0) es falsy; cualquier parte no-cero es truthy.
    shows("text(is_complex(complex(0, 0)))", "true");
    assert_eq!(
        out("when complex(0, 0)\n    print(\"t\")\notherwise\n    print(\"f\")"),
        vec!["f"]
    );
    assert_eq!(
        out("when complex(0, 1)\n    print(\"t\")\notherwise\n    print(\"f\")"),
        vec!["t"]
    );
}

// =========================================================
// Aritmética fluida (incl. promoción real→complex)
// =========================================================

#[test]
fn complex_arithmetic() {
    shows("complex(1, 2) + complex(3, 4)", "4+6i");
    shows("complex(5, 3) - complex(2, 1)", "3+2i");
    shows("complex(1, 2) * complex(3, 4)", "-5+10i");
    shows("2 * complex(0, 1)", "0+2i"); // promoción real→complex
    shows("3 + complex(0, 2)", "3+2i");
    shows("complex(0, 2) + 3", "3+2i");
    shows("complex(0, 1) ** 2", "-1+0i"); // entero exacto (powi)
    shows("complex(2, 0) ** 3", "8+0i");
    shows("complex(1, 1) / complex(1, 1)", "1+0i");
    shows("-complex(3, 2)", "-3-2i");
}

#[test]
fn complex_division_by_zero() {
    fails_with("print(complex(1, 0) / complex(0, 0))", "Division by zero");
}

#[test]
fn complex_plus_text_is_concat() {
    // G adversarial: complex + text → concatenación vía Display, NO error.
    shows("complex(3, 2) + \" units\"", "3+2i units");
    shows("\"z = \" + complex(0, 1)", "z = 0+1i");
}

// =========================================================
// Igualdad (G4) y orden (G3)
// =========================================================

#[test]
fn complex_equality_pythonic() {
    t("complex(3, 0) == 3"); // G4: complex(a,0) == a (real)
    t("3 == complex(3, 0)");
    t("complex(3, 2) == complex(3, 2)");
    t("complex(3, 2) != 3"); // im != 0 → distinto del real
    t("complex(3, 2) != complex(3, 5)");
    t("not (complex(2, 0) == 3)");
}

#[test]
fn complex_not_ordered() {
    fails_with("print(complex(1, 0) < complex(2, 0))", "complex numbers are not ordered");
    fails_with("print(complex(1, 0) > 2)", "complex numbers are not ordered");
    fails_with("print(5 <= complex(1, 0))", "complex numbers are not ordered");
}

// =========================================================
// cmath (transcendentales polimórficas)
// =========================================================

#[test]
fn cmath_euler_and_roots() {
    // Identidad de Euler: exp(iπ) = -1.
    t("abs(real(exp(complex(0, pi))) + 1) < 0.000000001");
    t("abs(imag(exp(complex(0, pi)))) < 0.000000001");
    // sqrt(-1) como complejo → i (exacto vía el fast-path real de num-complex).
    shows("sqrt(complex(-1, 0))", "0+1i");
    // ln(-1) como complejo → iπ.
    t("abs(real(ln(complex(-1, 0)))) < 0.000000001");
    t("abs(imag(ln(complex(-1, 0))) - pi) < 0.000000001");
    // sin/cos complejos siguen siendo complejos.
    t("is_complex(sin(complex(1, 1)))");
}

#[test]
fn real_transcendentals_unchanged() {
    // Las mismas funciones con arg real → resultado real (G1).
    t("not is_complex(sqrt(2))");
    t("not is_complex(exp(1))");
    t("not is_complex(sin(0))");
    // log10/log2/atan2/hypot quedan real-only (error con complex).
    fails_with("print(log10(complex(1, 1)))", "expects a number");
    fails_with("print(hypot(complex(1, 1), 2))", "expects a number");
}

// =========================================================
// Funciones especiales (vectores publicados, tol 1e-9)
// =========================================================

#[test]
fn special_functions() {
    t("abs(gamma(5) - 24) < 0.000000001"); // 4!
    t("abs(gamma(0.5) - 1.7724538509055159) < 0.000000001"); // √π
    t("abs(lgamma(10) - 12.801827480081469) < 0.000000001");
    t("erf(0) == 0");
    t("abs(erf(1) - 0.8427007929497149) < 0.000000001");
    t("erfc(0) == 1");
    t("abs(beta(2, 3) - 0.08333333333333333) < 0.000000001"); // 1/12
}

#[test]
fn special_functions_reject_complex() {
    fails_with("print(gamma(complex(1, 1)))", "gamma is not defined for complex numbers");
    fails_with("print(erf(complex(1, 0)))", "erf is not defined for complex numbers");
}

// =========================================================
// Hiperbólicas (real + complejo)
// =========================================================

#[test]
fn hyperbolics() {
    t("sinh(0) == 0");
    t("cosh(0) == 1");
    t("tanh(0) == 0");
    t("abs(asinh(sinh(1)) - 1) < 0.000000001");
    t("abs(cosh(1) - 1.5430806348152437) < 0.000000001");
    // sinh(i) = i·sin(1) → parte imaginaria ≈ sin(1), real ≈ 0.
    t("abs(real(sinh(complex(0, 1)))) < 0.000000001");
    t("abs(imag(sinh(complex(0, 1))) - 0.8414709848078965) < 0.000000001");
}
