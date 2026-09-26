//! La VM de F3: qué código genera (`explain`, L10). Que dé lo mismo que la referencia lo prueba el
//! oráculo diferencial (synsema-runtime) sobre todo el corpus; acá se fija la forma del bytecode.

use synsema_core::interpreter::explain_source;

#[test]
fn a_task_body_is_compiled_with_its_frame() {
    let out = explain_source(include_str!("../../../../specs/compute-bench/fib.syn"));
    assert!(out.contains("Define {"), "{}", out);
    assert!(out.contains("frame: [n]"), "{}", out);
    // `n` es un parámetro: se lee del slot 0 del frame, sin buscarlo por nombre.
    assert!(out.contains("a: Local(0)"), "{}", out);
    assert!(out.contains("Give { src: Local(0) }"), "{}", out);
}

#[test]
fn a_loop_counts_its_steps_once_per_block() {
    let out = explain_source(include_str!("../../../../specs/compute-bench/langs/loop.syn"));
    // La condición `i < 10000000` son tres nodos: un solo `Steps(3)` por vuelta.
    assert!(out.contains("Steps(3)"), "{}", out);
    // `set total to total + …` pasa primero por la vía en el lugar, como la referencia.
    assert!(out.contains("TryInPlace"), "{}", out);
    // Las globales se buscan por nombre.
    assert!(out.contains("LoadName"), "{}", out);
}

#[test]
fn locals_live_in_frame_slots_in_resolver_order() {
    let src = "task f(a, b)\n    when a\n        let c be 1\n    let d be b\n    give d\nprint(f(true, 2))\n";
    let out = explain_source(src);
    assert!(out.contains("frame: [a, b, c, d]"), "{}", out);
    assert!(out.contains("LetLocal { src: Const(0), slot: 2"), "{}", out);
    assert!(out.contains("LetLocal { src: Local(1), slot: 3"), "{}", out);
}
