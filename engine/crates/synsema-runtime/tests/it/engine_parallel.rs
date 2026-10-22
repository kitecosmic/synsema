//! A1 Fase 1 — concurrencia. parallel_map ≡ apply (invariante), chunk, y
//! concurrencia real (wall-clock < secuencial). Feature nueva (no differential).

use std::time::Instant;
use synsema_runtime::engine::run_source;

#[test]
fn parallel_map_equals_apply() {
    let src = "\
task double(x)
    give x * 2
let nums be [1, 2, 3, 4, 5]
let a be apply(double, nums)
let b be parallel_map(double, nums)
print(text(a == b))
print(text(b))
";
    let r = run_source(src, "t.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string(), "[2, 4, 6, 8, 10]".to_string()]);
}

#[test]
fn parallel_map_preserves_order_with_limit() {
    // Con limit bajo y muchos items, el resultado sigue en orden de entrada.
    let src = "\
task inc(x)
    give x + 100
let nums be [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
print(text(parallel_map(inc, nums, 3) == apply(inc, nums)))
";
    let r = run_source(src, "t.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string()]);
}

#[test]
fn chunk_correct() {
    let src = "\
print(text(chunk([1, 2, 3, 4, 5], 2)))
print(text(chunk([1, 2, 3], 3)))
print(text(flatten(chunk([1, 2, 3, 4, 5, 6], 2))))
";
    let r = run_source(src, "t.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "[[1, 2], [3, 4], [5]]".to_string(),
            "[[1, 2, 3]]".to_string(),
            "[1, 2, 3, 4, 5, 6]".to_string(),
        ]
    );
}

#[test]
fn parallel_map_fail_fast_propagates() {
    // Una task que falla en un item → el error se propaga (no cuelga).
    let src = "\
task risky(x)
    give 10 / x
let nums be [1, 2, 0, 4]
let r be parallel_map(risky, nums)
print(text(r))
";
    let r = run_source(src, "t.syn");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("Division by zero")), "errors: {:?}", r.errors);
}

#[test]
fn parallel_is_actually_concurrent() {
    // 8 tareas que duermen 0.2s, con limit 8 → wall-clock ~0.2s, no ~1.6s secuencial.
    let src = "\
require time
task slow(x)
    sleep(0.2)
    give x * 2
let nums be [1, 2, 3, 4, 5, 6, 7, 8]
print(text(parallel_map(slow, nums, 8)))
";
    let start = Instant::now();
    let r = run_source(src, "t.syn");
    let elapsed = start.elapsed();
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(r.output, vec!["[2, 4, 6, 8, 10, 12, 14, 16]".to_string()]);
    // Secuencial sería ~1.6s; en paralelo ~0.2s. Tolerante: < 1.0s.
    assert!(elapsed.as_secs_f64() < 1.0, "tardó {:?} (no parece paralelo)", elapsed);
}

#[test]
fn parallel_map_scales_many_tasks() {
    // A1 Fase 2 (tokio M:N): 64 tareas I/O concurrentes (sleep 0.05s) con limit 64 →
    // wall-clock ~0.05s (no ~3.2s secuencial), resultados EN ORDEN.
    let src = "\
require time
task slow(x)
    sleep(0.05)
    give x + 1
let nums be range(64)
let p be parallel_map(slow, nums, 64)
print(text(length(p)))
print(text(p[0]))
print(text(p[63]))
";
    let start = Instant::now();
    let r = run_source(src, "t.syn");
    let elapsed = start.elapsed();
    assert!(r.success, "errors: {:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["64".to_string(), "1".to_string(), "64".to_string()],
        "orden/resultados incorrectos"
    );
    // 64×0.05s secuencial = 3.2s; concurrente ≈ 0.05s. Tolerante: < 1.5s.
    assert!(elapsed.as_secs_f64() < 1.5, "tardó {:?} (no escaló)", elapsed);
}
