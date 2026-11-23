//! Queda en Rust (v0.6.68, migas §1): maneja el `Interpreter` de Rust directamente
//! (`call_callback`/`call_task`/`env_get`), no un programa vía `run_source`.
//! El resto de los tests de dx conviven en `tests/dx_conformance.test.syn`.

use synsema_core::interpreter::{env_get, Control, Interpreter};
use synsema_core::parser::parse_source;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_int, SynValue};

#[test]
fn host_callback_arity_fails_before_body_and_recovers_on_next_call() {
    let program = parse_source("let hit be 0\ntask f(a, b)\n    set hit to hit + 1\n    give a + b\n", "<host>").expect("source");
    let mut interp = Interpreter::new();
    assert!(interp.execute(&program).is_ok());
    let func = env_get(&interp.global_env, "f").expect("task");
    let loc = SourceLocation { file: "<host>".into(), line: 0, column: 0, offset: 0 };
    let error = interp.call_callback(func.clone(), vec![syn_int(2)], &loc);
    let Err(Control::Error(error)) = error else { panic!("required argument was omitted") };
    assert!(error.to_string().contains("missing argument 'b'"));
    assert_eq!(env_get(&interp.global_env, "hit").unwrap().to_string(), "0");
    let result = interp.call_task(func, vec![syn_int(2), syn_int(3)]);
    assert!(matches!(result, Ok(SynValue::Number(_))));
    assert_eq!(env_get(&interp.global_env, "hit").unwrap().to_string(), "1");
}
