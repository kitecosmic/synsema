//! La VM de F3: qué código genera (`explain`, L10). Que dé lo mismo que la referencia lo prueba el
//! oráculo diferencial (synsema-runtime) sobre todo el corpus; acá se fija la forma del bytecode.

use synsema_core::interpreter::{explain_after_run, explain_source};

/// Los programas del arnés (specs/compute-bench, que no se versiona): `fib` recursivo y el bucle
/// contador de la comparación con otros lenguajes.
const FIB: &str = "task fib(n)
    when n < 2
        give n
    give fib(n - 1) + fib(n - 2)

print(fib(27))
";
const LOOP: &str = "let total be 0
let i be 0
while i < 10000000
    set total to total + i % 7
    set i to i + 1
print(total)
";

#[test]
fn a_task_body_is_compiled_with_its_frame() {
    let out = explain_source(FIB);
    assert!(out.contains("Define {"), "{}", out);
    assert!(out.contains("frame: [n]"), "{}", out);
    // `n` es un parámetro: se lee del slot 0 (del frame en registros: `fib` no deja ver su frame),
    // sin buscarlo por nombre.
    assert!(out.contains("a: RLocal(0)"), "{}", out);
    assert!(out.contains("Give { src: RLocal(0) }"), "{}", out);
}

#[test]
fn a_loop_counts_its_steps_once_per_block() {
    let out = explain_source(LOOP);
    // La condición `i < 10000000` son tres nodos: un solo `Steps(3)` por vuelta.
    assert!(out.contains("Steps(3)"), "{}", out);
    // `set total to total + …` pasa primero por la vía en el lugar, como la referencia.
    assert!(out.contains("TryInPlace"), "{}", out);
    // Las globales del nivel superior se leen y escriben por el lugar cacheado (F3.5).
    assert!(out.contains("LoadGlobal"), "{}", out);
    assert!(out.contains("SetGlobal"), "{}", out);
    // Cada sentencia del cuerpo empieza con sus pasos y el chequeo de cancelación juntos (F3.5).
    assert!(out.contains("StepsCancel("), "{}", out);
}

#[test]
fn locals_live_in_frame_slots_in_resolver_order() {
    let src = "task f(a, b)\n    when a\n        let c be 1\n    let d be b\n    give d\nprint(f(true, 2))\n";
    let out = explain_source(src);
    assert!(out.contains("frame: [a, b, c, d]"), "{}", out);
    // (Esta task no deja ver su frame: va en registros, con los mismos slots.)
    assert!(out.contains("LetRLocal { src: Const(0), slot: 2"), "{}", out);
    assert!(out.contains("LetRLocal { src: RLocal(1), slot: 3"), "{}", out);
}

#[test]
fn calls_each_and_match_run_in_the_vm() {
    let src = "task f(xs)\n    let t be 0\n    each x in xs\n        match x\n            is [a, b]\n                set t to t + a\n            otherwise\n                set t to t + g(x)\n    give t\ntask g(v)\n    give v\nprint(f([1, [2, 3]]))\n";
    let out = explain_source(src);
    assert!(out.contains("EachInit"), "{}", out);
    assert!(out.contains("EachNext"), "{}", out);
    assert!(out.contains("MatchArm"), "{}", out);
    assert!(out.contains("Call {"), "{}", out);
    // `t` es de la llamada; adentro de la vuelta y del brazo está un frame (o dos) más afuera.
    assert!(out.contains("SetOuter"), "{}", out);
    // Salir de un brazo o de un bucle vuelve a la profundidad de afuera.
    assert!(out.contains("Unwind"), "{}", out);
}

#[test]
fn frames_nobody_can_see_live_in_registers() {
    // `fib` no define closures, no tiene nodos fríos ni frames propios: su frame va en registros.
    let out = explain_source(FIB);
    assert!(out.contains("frame en registros"), "{}", out);
    // Con un `each` cuyas vueltas nadie ve (F3.4), también: la vuelta vive en la ventana.
    let out = explain_source("task f(xs)\n    let t be 0\n    each x in xs\n        set t to t + x\n    give t\nprint(f([1]))\n");
    let task_header = out.lines().find(|l| l.contains("hijo 0 (")).unwrap_or("");
    assert!(task_header.contains("frame en registros"), "{}", out);
    // Con un `match` (el brazo es un frame hijo del de la llamada) no.
    let out = explain_source("task f(x)\n    match x\n        is [a]\n            give a\n    give 0\nprint(f([1]))\n");
    let task_header = out.lines().find(|l| l.contains("hijo 0 (")).unwrap_or("");
    assert!(!task_header.contains("frame en registros"), "{}", out);
    // Si define una lambda, la lambda captura el frame: tampoco (la lambda sí puede).
    let out = explain_source("task f(k)\n    let g be (x) => x + k\n    give g(1)\nprint(f(1))\n");
    let task_header = out.lines().find(|l| l.contains("hijo 0 (")).unwrap_or("");
    assert!(!task_header.contains("frame en registros"), "{}", out);
}

#[test]
fn each_turns_nobody_sees_live_in_the_window() {
    // F3.4: ni closure, ni nodo frío, ni brazo de `match` en el cuerpo: la variable de la vuelta
    // vive en la ventana de locales, sin frame por vuelta.
    let out = explain_source("let t be 0\neach i in range(0, 3)\n    let sq be i * i\n    set t to t + sq\nprint(t)\n");
    assert!(out.contains("EachNextV"), "{}", out);
    assert!(out.contains("EachRange"), "{}", out);
    assert!(out.contains("ventana de 2"), "{}", out);
    assert!(!out.contains("EachInit {"), "{}", out);
    // Una lambda que captura la variable de la vuelta: la vuelta tiene frame.
    let out = explain_source("let fs be []\neach x in [1, 2]\n    set fs to append(fs, () => x)\nprint(length(fs))\n");
    assert!(out.contains("EachInit {"), "{}", out);
    assert!(!out.contains("EachNextV"), "{}", out);
}

#[test]
fn operators_specialize_by_the_types_they_see() {
    // F3.4: el compilador emite `Binary` (adaptativo); corriendo, `fib` se especializa en enteros.
    let before = explain_source(FIB);
    assert!(before.contains("Binary {"), "{}", before);
    let after = explain_after_run(FIB);
    // `when n < 2`: compara y salta en una instrucción (F3.5).
    assert!(after.contains("IntCmpJump {"), "{}", after);
    assert!(after.contains("op: \"<\""), "{}", after);
    assert!(after.contains("IntArith {"), "{}", after);
    assert!(!after.contains("Binary {"), "{}", after);
    // Un sitio que alterna tipos queda genérico (se desoptimiza hasta `BinaryAny`).
    let alt = "task add(a, b)\n    give a + b\nlet xs be [1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5]\neach x in xs\n    print(add(x, 1))\n";
    let after = explain_after_run(alt);
    assert!(after.contains("BinaryAny {"), "{}", after);
    assert!(!after.contains("IntArith {"), "{}", after);
    // Texto: no hay forma especializada, queda genérico desde la primera vez.
    let after = explain_after_run("task cat(a)\n    give a + \"!\"\nprint(cat(\"x\"))\nprint(cat(\"y\"))\n");
    assert!(after.contains("BinaryAny {"), "{}", after);
}

#[test]
fn float_operators_specialize_too() {
    // F3.4c: con un float en juego, `+ - * /` y las comparaciones (exactas entre enteros y floats).
    let src = "task f(n)\n    let s be 0.0\n    let i be 0\n    while i < n\n        set s to s + 1.5 / (i + 1)\n        when s < 2.5\n            set s to s * 1.0\n        set i to i + 1\n    give s\nprint(f(10))\nprint(f(10))\n";
    let after = explain_after_run(src);
    assert!(after.contains("FloatArith {"), "{}", after);
    assert!(after.contains("NumCmp {"), "{}", after);
    // `i < n` sigue siendo de enteros (y compara y salta, F3.5).
    assert!(after.contains("IntCmpJump {"), "{}", after);
}
