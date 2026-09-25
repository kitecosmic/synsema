//! Corre un `.syn` con el intérprete de `core` solo (sin stdlib, runtime ni CLI): para iterar
//! sobre el lenguaje sin recompilar toda la cadena. Sólo hay los builtins de `core`.
//!
//! `cargo run -p synsema-core --example run -- archivo.syn`

use std::time::Instant;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("uso: run <archivo.syn>");
        std::process::exit(2);
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {}", path, e);
            std::process::exit(2);
        }
    };
    let start = Instant::now();
    let r = synsema_core::interpreter::run_source(&source, &path);
    let elapsed = start.elapsed();
    for line in &r.output {
        println!("{}", line);
    }
    for e in &r.errors {
        eprintln!("{}", e);
    }
    eprintln!("[{:.1} ms]", elapsed.as_secs_f64() * 1000.0);
    std::process::exit(if r.success { 0 } else { 1 });
}
