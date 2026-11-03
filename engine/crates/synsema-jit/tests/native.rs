//! El nivel nativo corre de verdad y respeta lo observable que el oráculo diferencial no puede
//! comparar (la cancelación llega en un momento que no es determinista). Que dé exactamente lo
//! mismo que la referencia lo prueban el oráculo (synsema-runtime) y `fuzz.rs`.

use std::time::{Duration, Instant};

use synsema_core::interpreter::{run_source, Control, Interpreter};
use synsema_core::native_tier;
use synsema_core::parser::parse_source;

#[test]
fn a_hot_recursive_task_runs_native() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source("task fib(n)\n    when n < 2\n        give n\n    give fib(n - 1) + fib(n - 2)\nprint(fib(25))\n", "fib.syn");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["75025"]);
    let after = native_tier::stats();
    assert!(after.units > before.units, "fib no se compiló");
    assert!(after.entries > before.entries, "fib no entró al código nativo");
}

/// Un `while` sin fin dentro de una task nativa: la cancelación lo corta, con el error de siempre.
#[test]
fn cancellation_stops_a_native_loop() {
    synsema_jit::install();
    // `spin` se llama pocas veces: que se compile en su segunda llamada.
    native_tier::set_eager(true);
    let src = "task spin(n)\n    let i be 0\n    while i < n\n        set i to i + 1\n    give i\n\
               let out be []\n\
               each n in [10, 20, 30, 40, 9223372036854775807]\n    let r be spin(n)\n    set out to append(out, r)\n\
               print(out)\n";
    let program = parse_source(src, "spin.syn").expect("parsea");
    let before = native_tier::stats();
    // Si la cancelación no cortara el bucle, el hilo no terminaría nunca: se espera con un tope.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let mut interp = Interpreter::new();
            let token = interp.cancel_token();
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                token.cancel("deadline");
            });
            let start = Instant::now();
            let r = interp.execute(&program);
            canceller.join().unwrap();
            let _ = tx.send((
                r.err().map(|c| match c {
                    Control::Error(e) => e.to_string(),
                    _ => "otro control".to_string(),
                }),
                start.elapsed(),
            ));
        })
        .unwrap();
    let out = rx.recv_timeout(Duration::from_secs(20)).expect("la cancelación no cortó el bucle nativo en 20 s");
    let (err, took) = out;
    assert_eq!(err.as_deref(), Some("cancelled: deadline"), "el bucle nativo no se cortó con el error de la VM");
    assert!(took < Duration::from_secs(10), "la cancelación tardó {:?}", took);
    let after = native_tier::stats();
    assert!(after.entries > before.entries && after.deopts > before.deopts, "el bucle no corría en nativo: {:?} → {:?}", before, after);
}

/// F4.2: un bucle del nivel superior (globales) pasa a nativo a mitad de camino (OSR) y da lo
/// mismo; las globales vuelven a su lugar al salir.
#[test]
fn a_hot_top_level_loop_enters_native_midway() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source("let total be 0\nlet i be 0\nwhile i < 200000\n    set total to total + i % 7\n    set i to i + 1\nprint(total)\nprint(i)\n", "loop.syn");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["599994", "200000"]);
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el bucle no entró al código nativo");
}

/// F4.2: un `while true` del nivel superior corriendo en nativo (OSR): la cancelación lo corta con
/// el error de la VM (si no lo cortara, el hilo no terminaría: se espera con un tope).
#[test]
fn cancellation_stops_a_native_top_level_loop() {
    synsema_jit::install();
    let program = parse_source("let n be 0\nwhile true\n    set n to n + 1\nprint(n)\n", "forever.syn").expect("parsea");
    let before = native_tier::stats();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let mut interp = Interpreter::new();
            let token = interp.cancel_token();
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                token.cancel("deadline");
            });
            let r = interp.execute(&program);
            canceller.join().unwrap();
            let _ = tx.send(r.err().map(|c| match c {
                Control::Error(e) => e.to_string(),
                _ => "otro control".to_string(),
            }));
        })
        .unwrap();
    let err = rx.recv_timeout(Duration::from_secs(20)).expect("la cancelación no cortó el bucle nativo en 20 s");
    assert_eq!(err.as_deref(), Some("cancelled: deadline"));
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el bucle no corría en nativo: {:?} → {:?}", before, after);
}

/// F4.2b: un `each` sobre `range` del nivel superior pasa a nativo a mitad de camino, con el
/// iterador perezoso en el código nativo.
#[test]
fn a_hot_each_over_range_enters_native_midway() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source("let total be 0\neach i in range(0, 200000)\n    set total to total + i % 7\nprint(total)\n", "each.syn");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["599994"]);
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el each no entró al código nativo");
}

/// F4.7a: un bucle del nivel superior con floats pasa a nativo a mitad de camino (antes el `Float`
/// lo dejaba en la VM) y da lo mismo, `-0.0` incluido.
#[test]
fn a_hot_float_loop_enters_native_midway() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source(
        "let s be 0.0\nlet z be 0.0\neach i in range(0, 200000)\n    set s to s + i / 4 - 0.5\n    set z to -(z * 1.0)\nprint(s)\nprint(z)\n",
        "floats.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["4999875000.0", "0.0"]);
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el bucle con floats no entró al código nativo");
}

/// F4.7a: una task con parámetros `Float` entra al código nativo por `CallNative`.
#[test]
fn a_hot_float_task_runs_native() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source(
        "task area(w, h)\n    give w * h * 0.5\nlet t be 0.0\neach i in range(0, 5000)\n    set t to t + area(i * 1.0, 2.0)\nprint(t)\n",
        "area.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["12497500.0"]);
    let after = native_tier::stats();
    assert!(after.units > before.units, "la task con floats no se compiló");
}

/// F4.7b: un `each` sobre una lista del nivel superior, con lecturas de un mapa por forma, pasa a
/// nativo a mitad de camino y da lo mismo.
#[test]
fn a_hot_each_over_a_list_enters_native_midway() {
    synsema_jit::install();
    let before = native_tier::stats();
    let r = run_source(
        "let xs be range(0, 200000)\nlet m be {\"k\": 2, \"f\": 0.5}\nlet s be 0\nlet f be 0.0\neach x in xs\n    set s to s + x % 7 * m.k\n    set f to f + m[\"f\"]\nprint(s)\nprint(f)\n",
        "each_list.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["1199988", "100000.0"]);
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el each sobre la lista no entró al código nativo");
}

/// F4.7b: un bucle nativo sin fin que lee una lista y un mapa: la cancelación lo corta con el error
/// de la VM (si no, el hilo no terminaría: se espera con un tope).
#[test]
fn cancellation_stops_a_native_loop_reading_data() {
    synsema_jit::install();
    let program = parse_source(
        "let xs be [1, 2, 3, 4]\nlet m be {\"a\": 1}\nlet n be 0\nwhile true\n    set n to n + xs[n % 4] + m.a\nprint(n)\n",
        "forever_data.syn",
    )
    .expect("parsea");
    let before = native_tier::stats();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let mut interp = Interpreter::new();
            let token = interp.cancel_token();
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                token.cancel("deadline");
            });
            let r = interp.execute(&program);
            canceller.join().unwrap();
            let _ = tx.send(r.err().map(|c| match c {
                Control::Error(e) => e.to_string(),
                _ => "otro control".to_string(),
            }));
        })
        .unwrap();
    let err = rx.recv_timeout(Duration::from_secs(20)).expect("la cancelación no cortó el bucle nativo en 20 s");
    assert_eq!(err.as_deref(), Some("cancelled: deadline"));
    let after = native_tier::stats();
    assert!(after.osr > before.osr, "el bucle no corría en nativo: {:?} → {:?}", before, after);
}

/// v0.6.55 (R4): un array no es verdadero ni falso. Un bucle nativo que pregunta la verdad de
/// valores con caja (`when v`, `not v`, `v and …`) sale a la VM cuando le toca un array, y la VM da
/// el error con el texto de cada sitio (el de la referencia).
#[test]
fn a_native_condition_on_an_array_exits_with_the_vm_error() {
    synsema_jit::install();
    let cases = [
        ("when v\n        set n to n + 1", "an array is not true or false — some(m) / every(m) for a mask, length(a) > 0 for \"not empty\""),
        ("when not v\n        set n to n + 1", "not needs true or false, got a mask — negate a mask with logical_not(m)"),
        ("when v and i > 0\n        set n to n + 1", "and needs true or false, got a mask — combine masks with logical_and(m1, m2)"),
        ("when i < 0 or v\n        set n to n + 1", "or needs true or false, got a mask — combine masks with logical_or(m1, m2)"),
    ];
    for (body, want) in cases {
        let src = format!(
            "let vals be [[1], [], \"s\", \"\", 3, 0, array([1, 5]) > 2]\nlet n be 0\neach i in range(0, 300000)\n    let k be i % 6\n    when i == 299999\n        set k to 6\n    let v be vals[k]\n    {}\nprint(n)\n",
            body
        );
        let before = native_tier::stats();
        let r = run_source(&src, "truth.syn");
        let after = native_tier::stats();
        assert!(!r.success, "tenía que fallar:\n{}", src);
        assert!(r.errors.iter().any(|e| e.contains(want)), "{:?}\n{}", r.errors, src);
        assert!(after.osr > before.osr, "el bucle no entró al código nativo:\n{}", src);
        assert!(after.deopts > before.deopts, "el bucle no salió a la VM:\n{}", src);
    }
}
