//! Ejecutor del oráculo diferencial (`tests/reference_oracle.rs`): corre un `.syn` por el mismo
//! camino que `synsema run --format json` y escribe en stdout un JSON con `ok`, `output`,
//! `errors` y `steps`. Con `--reference` los intérpretes no toman atajos de ejecución.
//!
//! Es un proceso aparte a propósito: un programa que no termina (un `serve`, una espera) se
//! mata desde afuera sin llevarse puesto al test.

fn main() {
    let mut reference = false;
    let mut path = None;
    for a in std::env::args().skip(1) {
        if a == "--reference" {
            reference = true;
        } else {
            path = Some(a);
        }
    }
    let Some(path) = path else {
        eprintln!("uso: oracle_run [--reference] <archivo.syn>");
        std::process::exit(2);
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {}", path, e);
            std::process::exit(2);
        }
    };
    synsema_core::interpreter::set_reference_mode(reference);
    let r = synsema_runtime::engine::run_program_ceiled_opts(&source, &path, None, false);
    // Si la corrida tocó datos privados, `steps` no se publica (igual que `run --format json`).
    let steps = if synsema_runtime::engine::last_run_touched_private() {
        serde_json::Value::Null
    } else {
        serde_json::json!(synsema_runtime::engine::last_run_steps())
    };
    let report = serde_json::json!({
        "ok": r.success,
        "output": r.output,
        "errors": r.errors,
        "steps": steps,
    });
    println!("{}", report);
}
