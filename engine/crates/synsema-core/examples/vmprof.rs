//! El perfil de la VM sobre un conjunto de programas (F3.5 de specs/compute-rendimiento.md: elegir
//! superinstrucciones por lo que corre de verdad). Sólo con la feature `vm-profile`:
//!
//! `cargo run --release -p synsema-core --features vm-profile --example vmprof -- a.syn b.syn …`

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("uso: vmprof <archivo.syn>…");
        std::process::exit(2);
    }
    let mut ok = 0;
    for path in &files {
        let Ok(source) = std::fs::read_to_string(path) else { continue };
        let r = synsema_core::interpreter::run_source(&source, path);
        if r.success {
            ok += 1;
        }
    }
    println!("programas: {} ({} sin error)", files.len(), ok);
    print!("{}", synsema_core::interpreter::vm_profile::take());
}
