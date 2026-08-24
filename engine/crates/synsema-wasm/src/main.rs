//! synsema-wasm — la CLI wasip1 del intérprete Synsema.
//!
//! Un binario chico para `wasm32-wasip1`: lee un `.syn` (path, o `-` = stdin), lo
//! corre con el perfil PURO de la stdlib e imprime la salida; `--test` corre los
//! bloques `test` del archivo. El host (wasmtime, un TEE, un worker de edge) carga
//! el `.wasm` y le da el programa — nadie instala Synsema en el host.
//!
//! Toda la lógica vive en la lib de este crate (`synsema_wasm::{run, test}`): el
//! MISMO wiring puro que usa el cdylib embebible (`synsema-wasm-web`). Bajo la CLI
//! de wasmtime no hay hooks del host (el runner no provee imports), así que red/LLM/
//! memoria fallan con la verdad del entorno; `.env` y archivos van por WASI (`--dir`).
//!
//! Compila también nativo: `cargo test --workspace` lo construye y el smoke test
//! corre sin toolchain wasm (mismo main, hilo con stack grande en vez del stack
//! linkeado del target wasm).

use std::io::Read;

use synsema_capabilities::model::build_ceiling;
use synsema_wasm::RunOptions;

/// Mismo criterio que INTERP_STACK_SIZE del runtime (tree-walking recursivo). En
/// wasm el stack se fija al linkear (ver .cargo/config.toml); esto es el fallback
/// del build nativo.
#[cfg(not(target_family = "wasm"))]
const NATIVE_STACK: usize = 512 * 1024 * 1024;

fn with_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    // En wasm no hay threads: el stack grande viene del linker (.cargo/config.toml).
    #[cfg(target_family = "wasm")]
    {
        f()
    }
    #[cfg(not(target_family = "wasm"))]
    {
        std::thread::Builder::new()
            .stack_size(NATIVE_STACK)
            .spawn(f)
            .expect("no se pudo crear el hilo del motor")
            .join()
            .expect("el hilo del motor falló")
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    const USAGE: &str = "usage: synsema-wasm [--test] [--sandbox | --cap-set <list>] <file.syn | ->";
    let mut test_mode = false;
    let mut sandbox = false;
    let mut cap_set: Option<String> = None;
    let mut path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--test" => test_mode = true,
            "--sandbox" => sandbox = true,
            // Mismas formas que `synsema run`: `--cap-set <list>` y `--cap-set=<list>`.
            "--cap-set" => match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => {
                    cap_set = Some(v.clone());
                    i += 1;
                }
                _ => {
                    eprintln!(
                        "synsema-wasm: --cap-set requires a value (e.g. \"stdout,secret=ETH_*\")"
                    );
                    std::process::exit(2);
                }
            },
            p if p.starts_with("--cap-set=") => {
                cap_set = Some(p.trim_start_matches("--cap-set=").to_string());
            }
            "--version" | "-V" => {
                println!("synsema-wasm {}", synsema_wasm::version());
                return;
            }
            "--help" | "-h" => {
                println!(
                    "synsema-wasm — run a Synsema program (pure profile)\n\n{}\n\n\
                     --test             run the file's `test` blocks instead of the program\n\
                     --sandbox          host ceiling = [stdout, time] (compute + print only)\n\
                     --cap-set <list>   host ceiling = the listed capabilities (name or name=scope,\n\
                     \x20                  comma-separated) — a `require` above it is denied\n\
                     --version          print the artifact version\n\
                     -                  read the program from stdin",
                    USAGE
                );
                return;
            }
            // Una flag desconocida NUNCA se toma como ruta: `--sandbox` mal tipeado que corre
            // el programa sin techo y sin avisar sería un agujero, no una comodidad.
            p if p.starts_with('-') && p != "-" => {
                eprintln!("synsema-wasm: unknown option '{}'\n{}", p, USAGE);
                std::process::exit(2);
            }
            other => {
                if path.is_some() {
                    eprintln!("synsema-wasm: only one program per run (got '{}')\n{}", other, USAGE);
                    std::process::exit(2);
                }
                path = Some(other.to_string());
            }
        }
        i += 1;
    }
    let Some(path) = path else {
        eprintln!("synsema-wasm: missing program\n{}", USAGE);
        std::process::exit(2);
    };
    // Techo del host: mismo parser que `synsema run` (synsema-capabilities::build_ceiling).
    let ceiling = match build_ceiling(sandbox, cap_set.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("synsema-wasm: {}", e);
            std::process::exit(2);
        }
    };
    let (source, filename) = if path == "-" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("synsema-wasm: could not read stdin: {}", e);
            std::process::exit(2);
        }
        (buf, "<stdin>".to_string())
    } else {
        match std::fs::read_to_string(&path) {
            Ok(s) => (s, path.clone()),
            Err(e) => {
                eprintln!("synsema-wasm: could not read {}: {}", path, e);
                std::process::exit(2);
            }
        }
    };
    // `env: None` → EnvStore::load_default(): el `.env` llega por WASI (`--dir .`) y el
    // environ por `wasmtime --env`, igual que hasta ahora.
    let opts = RunOptions { filename, env: None, ceiling, no_fs: false };

    if test_mode {
        let r = with_big_stack(move || synsema_wasm::test(&source, &opts));
        for l in &r.lines {
            println!("{}", l);
        }
        println!("passed {}, failed {}", r.passed, r.failed);
        std::process::exit(if r.failed > 0 { 1 } else { 0 });
    } else {
        let r = with_big_stack(move || synsema_wasm::run(&source, &opts));
        for line in &r.output {
            println!("{}", line);
        }
        for e in &r.errors {
            eprintln!("{}", e);
        }
        std::process::exit(if r.ok { 0 } else { 1 });
    }
}
