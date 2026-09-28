//! Como `synsema-core/examples/run.rs` (sólo el intérprete de core, sin stdlib ni CLI), con el
//! nivel nativo instalado: para iterar y medir F4 (specs/compute-bench, `pgo_variant.sh`).
//!
//! `cargo run -p synsema-jit --example run -- [--jitless] archivo.syn`
//!
//! `--jitless`: sin el nivel nativo (para entrenar PGO sólo con la VM, como la release).

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let jitless = args.iter().any(|a| a == "--jitless");
    let Some(path) = args.into_iter().find(|a| a != "--jitless") else {
        eprintln!("uso: run [--jitless] <archivo.syn>");
        std::process::exit(2);
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {}", path, e);
            std::process::exit(2);
        }
    };
    if !jitless {
        synsema_jit::install();
    }
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
