//! Conformidad de arrays n-dimensionales + álgebra lineal (Batch 5). Corre programas
//! `.syn` reales por el intérprete de core. Igualdad exacta donde los resultados son
//! enteros en f64 (matmul de enteros, broadcasting); tolerancia 1e-9 (vía `norm`) para
//! solve/inv/svd. Incluye G1 (listas intactas) y los casos de error (G3).

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

/// `print(expr)` → exactamente `expected`.
fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

/// La expresión booleana debe ser `true`.
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
// G1 — listas/escalares intactos
// =========================================================

#[test]
fn g1_lists_unchanged() {
    shows("text(sum([1, 2, 3]))", "6");
    shows("text(mean([1, 2, 3]))", "2.0");
    shows("text(min([3, 5, 1]))", "1");
    shows("text(max([3, 5, 1]))", "5");
    shows("text(product([1, 2, 3, 4]))", "24");
    shows("text(min(3, 5, 1))", "1"); // variádico de escalares intacto
}

// =========================================================
// Construcción / introspección / conversión
// =========================================================

#[test]
fn construction_and_introspection() {
    shows("shape(array([[1, 2], [3, 4]]))", "[2, 2]");
    shows("text(ndim(array([[1, 2], [3, 4]])))", "2");
    shows("text(size(array([[1, 2], [3, 4]])))", "4");
    shows("type_of(array([1, 2, 3]))", "array");
    shows("array([1, 2, 3])", "[1, 2, 3]");
    shows("array([[1, 2], [3, 4]])", "[[1, 2], [3, 4]]");
    t("is_array(array([1]))");
    t("not is_array([1])"); // una lista NO es un array
    shows("zeros([2, 3])", "[[0, 0, 0], [0, 0, 0]]");
    shows("ones(3)", "[1, 1, 1]");
    shows("full([2], 7)", "[7, 7]");
    shows("arange(0, 5)", "[0, 1, 2, 3, 4]");
    shows("linspace(0, 1, 5)", "[0, 0.25, 0.5, 0.75, 1]");
    shows("identity(3)", "[[1, 0, 0], [0, 1, 0], [0, 0, 1]]");
}

#[test]
fn to_list_round_trip() {
    t("array(to_list(array([[1, 2], [3, 4]]))) == array([[1, 2], [3, 4]])");
    // los elementos son f64 → su `text()` lleva `.0` (el Display NumPy-like los recorta).
    shows("to_list(array([1, 2, 3]))", "[1.0, 2.0, 3.0]");
}

#[test]
fn construction_errors() {
    fails_with("print(array([[1, 2], [3]]))", "ragged"); // filas de distinto largo
    fails_with("print(array([[1, 2], [3, \"x\"]]))", "expects numbers"); // no-numérico
}

#[test]
fn reshape_transpose_flatten() {
    t("reshape(arange(0, 6), [2, 3]) == array([[0, 1, 2], [3, 4, 5]])");
    fails_with("print(reshape(arange(0, 6), [2, 2]))", "cannot reshape");
    t("transpose(array([[1, 2], [3, 4]])) == array([[1, 3], [2, 4]])");
    t("flatten(array([[1, 2], [3, 4]])) == array([1, 2, 3, 4])");
}

// =========================================================
// Indexación
// =========================================================

#[test]
fn indexing() {
    shows("array([10, 20, 30])[1]", "20.0"); // 1D → escalar f64
    shows("text(array([10, 20, 30])[1])", "20.0");
    t("array([[1, 2], [3, 4]])[0] == array([1, 2])"); // 2D → fila
    shows("text(at(array([[1, 2], [3, 4]]), [1, 1]))", "4.0");
    fails_with("print(array([1, 2, 3])[5])", "out of bounds");
    fails_with("print(array([1, 2, 3])[-1])", "out of bounds");
    fails_with("print(at(array([[1, 2], [3, 4]]), [1]))", "expected 2 indices");
    fails_with("print(at(array([[1, 2], [3, 4]]), [5, 0]))", "out of bounds");
}

// =========================================================
// Aritmética vectorizada
// =========================================================

#[test]
fn vectorized_arithmetic() {
    t("array([1, 2, 3]) + array([10, 20, 30]) == array([11, 22, 33])");
    t("array([1, 2, 3]) - array([1, 1, 1]) == array([0, 1, 2])");
    t("array([1, 2, 3]) * 2 == array([2, 4, 6])"); // escalar
    t("2 * array([1, 2, 3]) == array([2, 4, 6])");
    t("10 - array([1, 2, 3]) == array([9, 8, 7])"); // scalar ⊕ array (orden importa)
    // broadcasting [2,2] + [2]
    t("array([[1, 2], [3, 4]]) + array([10, 20]) == array([[11, 22], [13, 24]])");
    t("-array([1, -2, 3]) == array([-1, 2, -3])"); // unario
}

#[test]
fn star_is_elementwise_not_matmul() {
    // `*` es ELEMENTWISE (Hadamard), NO producto matricial.
    t("array([[1, 2], [3, 4]]) * array([[1, 0], [0, 1]]) == array([[1, 0], [0, 4]])");
    // y NO es igual al producto matricial (que sería la propia A).
    t("array([[1, 2], [3, 4]]) * array([[1, 0], [0, 1]]) != array([[1, 2], [3, 4]])");
    // matmul SÍ da el producto matricial.
    t("matmul(array([[1, 2], [3, 4]]), array([[1, 0], [0, 1]])) == array([[1, 2], [3, 4]])");
}

#[test]
fn broadcasting_incompatible_errors() {
    fails_with("print(array([1, 2, 3]) + array([1, 2, 3, 4]))", "not broadcastable");
    fails_with(
        "print(array([[1, 2, 3], [4, 5, 6]]) + array([1, 2, 3, 4]))",
        "not broadcastable",
    );
}

// =========================================================
// Reducciones (total y por eje) + std/var
// =========================================================

#[test]
fn reductions() {
    shows("text(sum(array([1, 2, 3, 4])))", "10.0"); // array → f64
    shows("text(mean(array([1, 2, 3, 4])))", "2.5");
    shows("text(min(array([3, 1, 2])))", "1.0");
    shows("text(max(array([3, 1, 2])))", "3.0");
    shows("text(product(array([1, 2, 3, 4])))", "24.0");
    // por eje (axis 0 = columnas, axis 1 = filas)
    t("sum(array([[1, 2], [3, 4]]), 0) == array([4, 6])");
    t("sum(array([[1, 2], [3, 4]]), 1) == array([3, 7])");
    t("mean(array([[1, 2], [3, 4]]), 0) == array([2, 3])");
    // std/var (poblacional, ddof=0)
    shows("text(var(array([1, 2, 3])))", "0.6666666666666666");
    t("abs(std(array([2, 4, 4, 4, 5, 5, 7, 9])) - 2) < 0.000000001");
    // std/var sobre lista (ergonomía)
    shows("text(var([1, 2, 3]))", "0.6666666666666666");
}

// =========================================================
// Álgebra lineal (vectores publicados, tol 1e-9)
// =========================================================

#[test]
fn matmul_and_dot() {
    t("matmul(array([[1, 2], [3, 4]]), array([[5, 6], [7, 8]])) == array([[19, 22], [43, 50]])");
    shows("text(dot(array([1, 2, 3]), array([4, 5, 6])))", "32.0"); // 1·4+2·5+3·6
    fails_with(
        "print(matmul(array([[1, 2, 3]]), array([[1, 2]])))",
        "incompatible",
    );
}

#[test]
fn det_inv_solve() {
    shows("text(det(array([[1, 2], [3, 4]])))", "-2.0");
    // inv(A) · A ≈ I
    t("norm(matmul(inv(array([[1, 2], [3, 4]])), array([[1, 2], [3, 4]])) - identity(2)) < 0.000000001");
    // solve: A x = b. NOTA: el ejemplo del spec `solve([[3,2],[1,2]],[5,5])→[1,1]` es
    // inconsistente (matmul daría [5,3]≠[5,5]; la solución real es [0, 2.5]). Uso un
    // sistema con solución limpia [1,1]: [[2,1],[1,3]]·[1,1] = [3,4].
    let solve = "let a be array([[2, 1], [1, 3]])\nlet x be solve(a, array([3, 4]))\n\
                 print(text(norm(matmul(a, reshape(x, [2, 1])) - reshape(array([3, 4]), [2, 1])) < 0.000000001))\n\
                 print(text(norm(x - array([1, 1])) < 0.000000001))";
    assert_eq!(out(solve), vec!["true", "true"]);
    // El ejemplo (inconsistente) del spec igual resuelve bien por residual: A·x ≈ b.
    let spec_solve = "let a be array([[3, 2], [1, 2]])\nlet x be solve(a, array([5, 5]))\n\
                 print(text(norm(matmul(a, reshape(x, [2, 1])) - reshape(array([5, 5]), [2, 1])) < 0.000000001))";
    assert_eq!(out(spec_solve), vec!["true"]);
}

#[test]
fn norm_and_trace() {
    shows("text(norm(array([3, 4])))", "5.0"); // L2 de un vector
    shows("text(norm(array([[1, 2], [3, 4]]), \"l1\"))", "10.0"); // suma de |x|
    shows("text(trace(array([[1, 2], [3, 4]])))", "5.0");
}

#[test]
fn singular_errors() {
    fails_with("print(inv(array([[1, 2], [2, 4]])))", "singular");
    fails_with("print(solve(array([[1, 2], [2, 4]]), array([1, 2])))", "singular");
    fails_with("print(inv(array([1, 2, 3])))", "2D"); // LA requiere 2D
}

#[test]
fn eig_symmetric() {
    // A = [[2,1],[1,2]] (simétrica): autovalores 1 y 3; suma = trace = 4, im ≈ 0.
    let src = "let r be eig(array([[2, 1], [1, 2]]))\n\
               print(text(abs((real(r.values[0]) + real(r.values[1])) - 4) < 0.000000001))\n\
               print(text(abs(imag(r.values[0])) + abs(imag(r.values[1])) < 0.000000001))\n\
               print(text(length(r.values)))";
    assert_eq!(out(src), vec!["true", "true", "2"]);
}

#[test]
fn svd_reconstructs() {
    // A = U·diag(s)·Vt → reconstruir: (U * s) ⊕ broadcast · Vt ≈ A.
    let src = "let a be array([[1, 2], [3, 4]])\n\
               let r be svd(a)\n\
               let recon be matmul(r.u * r.s, r.vt)\n\
               print(text(norm(recon - a) < 0.000000001))";
    assert_eq!(out(src), vec!["true"]);
}
