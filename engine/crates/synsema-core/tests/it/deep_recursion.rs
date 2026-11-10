//! Una recursión cerca del tope (`MAX_RECURSION = 3000`) tiene que funcionar, y pasarlo tiene que
//! dar el error atrapable, no tumbar el proceso por desborde de pila. En builds de debug (como
//! corren los tests) el frame de `exec_node` sin optimizar llegó a ~300 KB y el proceso se caía a
//! los ~1.750 niveles (specs/compute-rendimiento.md F1.10). Este test es la guardia.

use synsema_core::interpreter::run_source;

fn depth(n: u32) -> synsema_core::interpreter::RunResult {
    let src = format!(
        "task f(n)\n    when n == 0\n        give 0\n    give f(n - 1) + 1\nprint(f({}))\n",
        n
    );
    run_source(&src, "<deep>")
}

#[test]
fn recursion_near_the_cap_works_and_past_it_is_an_error() {
    let r = depth(2900);
    assert!(r.success, "2900 niveles fallaron: {:?}", r.errors);
    assert_eq!(r.output, vec!["2900".to_string()]);

    let r = depth(3500);
    assert!(!r.success, "3500 niveles tendrían que pasar el tope");
    assert!(
        r.errors.iter().any(|e| e.contains("maximum recursion depth exceeded")),
        "se esperaba el error del tope, no otro: {:?}",
        r.errors
    );
}

/// Ronda 8 (v0.6.58, §4.5): el aviso de la pila tiene que verse también en un host donde 512 MB
/// alcanzan (x86_64), sin depender del CI de macOS. Un hilo de 64 MB (el más chico que corre el
/// intérprete: `serve`, `stream`, `cron`, aprobaciones, ACME) que avisa su pila, con etiquetas
/// (todo en la referencia) y una task con 6 `when` × 2999 llamadas: el resultado o el error de
/// recursión, nunca el proceso abortado. Sin `enter_thread` desborda (medido, debug).
///
/// No va más chico: las primeras 64 llamadas no miran la pila (`recursion_cap`), y en debug con
/// etiquetas cada una de esta task cuesta más de ~110 KB: un hilo de 8 MB desborda a las 60.
#[test]
fn a_small_thread_that_announces_its_stack_gets_the_error_not_an_overflow() {
    const SMALL: usize = 64 * 1024 * 1024;
    let mut src = String::from("task h(n)\n    let big be [0]\n    when n == 0\n        give 0\n");
    let mut ind = String::from("    ");
    for _ in 0..6 {
        src += &format!("{ind}when true\n");
        ind += "    ";
    }
    src += &format!("{ind}give h(n - 1) + 1\n    give -1\nprint(h(2999))\n");
    for labels in [true, false] {
        let src = src.clone();
        let (ok, out, err) = std::thread::Builder::new()
            .stack_size(SMALL)
            .spawn(move || {
                synsema_core::stack::enter_thread(SMALL);
                let program = synsema_core::parser::parse_source(&src, "<small>").expect("parse");
                let mut interp = synsema_core::interpreter::Interpreter::new();
                interp.set_labels(labels);
                let r = interp.execute(&program);
                let err = match &r {
                    Err(synsema_core::interpreter::Control::Error(e)) => e.to_string(),
                    _ => String::new(),
                };
                (r.is_ok(), std::mem::take(&mut interp.output), err)
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(
            (ok && out == ["2999"]) || err.contains("maximum recursion depth exceeded"),
            "labels = {labels}: ok {ok}, {out:?}, {err}"
        );
        eprintln!("labels = {labels}: {}", if ok { "2999" } else { "el error de recursión" });
    }
}

/// Ronda 9: en debug, avisar un hilo de menos de 64 MB es un error del motor (el guardián no mira la
/// pila en las primeras 64 llamadas: con 8 MB, una task con 6 `when` y etiquetas desborda a las 60).
#[cfg(debug_assertions)]
#[test]
fn announcing_a_thread_smaller_than_64_mb_is_refused_in_debug() {
    let r = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| synsema_core::stack::enter_thread(8 * 1024 * 1024))
        .unwrap()
        .join();
    let msg = r.expect_err("8 MB tendría que dar el assert");
    let msg = msg.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(msg.contains("needs at least 64 MB"), "{msg}");
}
