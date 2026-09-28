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
