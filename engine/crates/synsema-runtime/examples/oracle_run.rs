//! Ejecutor del oráculo diferencial (`tests/reference_oracle.rs`): corre un `.syn` por el mismo
//! camino que `synsema run --format json` y escribe en stdout un JSON con `ok`, `output`,
//! `errors` y `steps`. Con `--reference` los intérpretes no toman atajos de ejecución. Con
//! `--resolver-check` además compara cada búsqueda por nombre con lo que predijo el resolver
//! (F3.0) y lo informa en `resolver`. Sin `--reference` el nivel nativo está instalado, como en el
//! binario (F4); con `--jit-eager` además compila cada task caliente en su segunda llamada, para que
//! lo nativo corra en todo el corpus.
//!
//! Es un proceso aparte a propósito: un programa que no termina (un `serve`, una espera) se
//! mata desde afuera sin llevarse puesto al test.
//!
//! Con `--request` el programa entero corre como el cuerpo de una ruta de `serve`
//! (`run_request_block`): así el oráculo compara también ese camino (VM y nativo en los handlers).

fn main() {
    let mut reference = false;
    let mut resolver_check = false;
    let mut jit_eager = false;
    let mut request = false;
    let mut path = None;
    for a in std::env::args().skip(1) {
        if a == "--reference" {
            reference = true;
        } else if a == "--resolver-check" {
            resolver_check = true;
        } else if a == "--jit-eager" {
            jit_eager = true;
        } else if a == "--request" {
            request = true;
        } else {
            path = Some(a);
        }
    }
    let Some(path) = path else {
        eprintln!("uso: oracle_run [--reference] [--resolver-check] [--jit-eager] [--request] <archivo.syn>");
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
    if !reference {
        synsema_jit::install();
        synsema_core::native_tier::set_eager(jit_eager);
    }
    synsema_core::resolve::check::set_enabled(resolver_check);
    synsema_runtime::engine::set_request_mode(request);
    let r = synsema_runtime::engine::run_program_ceiled_opts(&source, &path, None, false);
    // Si la corrida tocó datos privados, `steps` no se publica (igual que `run --format json`).
    let steps = if synsema_runtime::engine::last_run_touched_private() {
        serde_json::Value::Null
    } else {
        serde_json::json!(synsema_runtime::engine::last_run_steps())
    };
    let mut report = serde_json::json!({
        "ok": r.success,
        "output": r.output,
        "errors": r.errors,
        "steps": steps,
    });
    if jit_eager {
        let s = synsema_core::native_tier::stats();
        report["native"] = serde_json::json!({ "units": s.units, "entries": s.entries, "deopts": s.deopts, "osr": s.osr });
    }
    if resolver_check {
        let c = synsema_core::resolve::check::take_report();
        report["resolver"] = serde_json::json!({
            "checked": c.checked,
            "unchecked": c.unchecked,
            "violations": c.violations,
        });
    }
    println!("{}", report);
}
