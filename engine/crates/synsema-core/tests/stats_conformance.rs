//! Conformidad de la estadística descriptiva (Batch 8): `median`/`percentile`/`histogram`
//! contra valores NumPy conocidos, sobre listas Y arrays, con errores claros (vacío, NaN,
//! p fuera de [0,100], bordes no crecientes). Programas `.syn` reales por el intérprete.

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

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
// median
// =========================================================

#[test]
fn median_even_and_odd() {
    shows("text(median([1, 2, 3, 4]))", "2.5"); // N par → promedio de los centrales
    shows("text(median([1, 2, 3]))", "2.0"); // N impar → el central (Float)
    shows("text(median([5]))", "5.0");
    // No exige datos ordenados.
    shows("text(median([3, 1, 4, 1, 5]))", "3.0");
}

// =========================================================
// percentile (interpolación lineal, semántica default de NumPy)
// =========================================================

#[test]
fn percentile_extremes_and_median() {
    shows("text(percentile([1, 5, 9], 0))", "1.0"); // p=0 → min
    shows("text(percentile([1, 5, 9], 100))", "9.0"); // p=100 → max
    t("percentile([3, 1, 4, 1, 5], 50) == median([3, 1, 4, 1, 5])");
}

#[test]
fn percentile_numpy_vectors() {
    // np.percentile([1,2,3,4], 25) == 1.75 (interpolación lineal)
    shows("text(percentile([1, 2, 3, 4], 25))", "1.75");
    // np.percentile([15,20,35,40,50], 40) == 29.0
    shows("text(percentile([15, 20, 35, 40, 50], 40))", "29.0");
    // np.percentile([1,2,3,4,5], 95) == 4.8
    t("abs(percentile([1, 2, 3, 4, 5], 95) - 4.8) < 0.000000001");
}

// =========================================================
// histogram (semántica NumPy: edges == counts+1, último bin cerrado)
// =========================================================

#[test]
fn histogram_uniform_bins() {
    let o = out(
        "let h be histogram(range(10), 5)\n\
         print(h[\"counts\"])\n\
         print(length(h[\"edges\"]))\n\
         print(text(h[\"edges\"][0]))\n\
         print(text(h[\"edges\"][5]))",
    );
    assert_eq!(o, vec!["[2, 2, 2, 2, 2]", "6", "0.0", "9.0"]);
}

#[test]
fn histogram_explicit_edges_last_bin_closed() {
    // Bins [0,2) y [2,4]: el 2 y el 4 caen en el último bin (cerrado).
    let o = out("print(histogram([1, 2, 3, 4], [0, 2, 4])[\"counts\"])");
    assert_eq!(o, vec!["[1, 3]"]);
    // Valores fuera de los bordes explícitos se descartan (NumPy).
    let o = out("print(histogram([-5, 1, 99], [0, 2])[\"counts\"])");
    assert_eq!(o, vec!["[1]"]);
}

#[test]
fn histogram_all_equal_expands_range() {
    // min == max → rango [v-0.5, v+0.5] (como NumPy); sin división por cero.
    let o = out("print(histogram([7, 7, 7], 2)[\"counts\"])");
    assert_eq!(o, vec!["[0, 3]"]);
}

#[test]
fn histogram_default_ten_bins() {
    t("length(histogram(range(100))[\"counts\"]) == 10");
}

// =========================================================
// Listas y arrays: mismo resultado (Batch 5 interop)
// =========================================================

#[test]
fn arrays_and_lists_agree() {
    t("median(array([1, 2, 3, 4])) == median([1, 2, 3, 4])");
    t("percentile(array([15, 20, 35, 40, 50]), 40) == percentile([15, 20, 35, 40, 50], 40)");
    t("histogram(array([1, 2, 3]), 2) == histogram([1, 2, 3], 2)");
}

// =========================================================
// Errores claros (G5)
// =========================================================

#[test]
fn errors_empty_nan_and_bad_p() {
    fails_with("median([])", "empty");
    fails_with("median([1, nan, 3])", "NaN");
    fails_with("percentile([1, 2], 101)", "between 0 and 100");
    fails_with("percentile([1, 2], -1)", "between 0 and 100");
    fails_with("histogram([1, 2], [3, 2])", "strictly increasing");
    fails_with("histogram([1, 2], 0)", "at least 1");
    fails_with("median([1, \"x\"])", "expects a list of numbers");
    fails_with("median(\"nope\")", "list of numbers or an array");
}

#[test]
fn existing_aggregates_untouched_g1() {
    // mean/sum/std siguen intactos y consistentes con lo nuevo.
    shows("text(mean([1, 2, 3, 4]))", "2.5");
    t("mean([1, 2, 3, 4]) == percentile([1, 2, 3, 4], 50)");
    shows("text(sum([1, 2, 3]))", "6");
}
