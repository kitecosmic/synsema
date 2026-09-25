//! Oráculo diferencial (specs/compute-rendimiento.md §5): todo atajo de ejecución del intérprete
//! tiene que dar exactamente lo mismo que el camino de referencia. Cada `.syn` del repo corre tres
//! veces en un proceso aparte (`examples/oracle_run.rs`): referencia, atajos, referencia. Si las
//! dos de referencia difieren, el programa no es determinista (hora, azar, hilos, puertos, estado
//! en disco que otro programa cambia) y no dice nada. Se comparan el éxito, la salida, los errores
//! y `steps()`.
//!
//! `conformance/` está en `.gitignore`: en un checkout limpio (CI) el corpus son los `.syn`
//! versionados; en una máquina de desarrollo, además los ~1.400 de conformance.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Un programa que tarda más que esto se cuenta como "no termina" y no se compara.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Carpetas del repo que se recorren (las que existan).
const ROOTS: &[&str] = &[
    // Casos propios de los atajos (versionados: los ve CI), incluidos los caminos de error.
    "engine/crates/synsema-runtime/tests/oracle_cases",
    "conformance",
    "examples",
    "tests",
    "packages/guests/vela",
    "specs/compute-bench/alloc",
    "specs/compute-bench/alloc2",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("..")
}

/// El ejecutor lo compila `cargo test` junto con los ejemplos del paquete:
/// `target/<perfil>/deps/<test>` → `target/<perfil>/examples/oracle_run`.
fn runner() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let profile_dir = exe.parent().and_then(|d| d.parent()).expect("target/<perfil>");
    profile_dir.join("examples").join(format!("oracle_run{}", std::env::consts::EXE_SUFFIX))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let skip = ["target", "node_modules", ".git", "dist", "build", ".synsema", "serve_tmp"];
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().and_then(|s| s.to_str()).is_some_and(|n| skip.contains(&n)) {
                continue;
            }
            collect(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("syn") {
            out.push(p);
        }
    }
}

#[derive(PartialEq, Debug)]
enum Outcome {
    /// El JSON que imprimió el ejecutor.
    Done(serde_json::Value),
    /// Terminó sin informe (un pánico que abortó, un desborde de pila): el código de salida.
    Crash(String),
    Timeout,
}

fn run(runner: &Path, file: &Path, reference: bool) -> Outcome {
    let mut cmd = Command::new(runner);
    if reference {
        cmd.arg("--reference");
    }
    cmd.arg(file)
        .current_dir(file.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Crash(format!("spawn: {}", e)),
    };
    // Leer en otro hilo: un programa que escribe mucho no puede trabar el pipe.
    let mut stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let text = reader.join().unwrap_or_default();
                let last = text.lines().rev().find(|l| l.starts_with('{')).unwrap_or("");
                return match serde_json::from_str(last) {
                    Ok(v) => Outcome::Done(v),
                    Err(_) => Outcome::Crash(format!("{}", status)),
                };
            }
            Ok(None) if start.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::Timeout;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Outcome::Crash(format!("wait: {}", e)),
        }
    }
}

fn clip(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 300 {
        format!("{}…", s.chars().take(300).collect::<String>())
    } else {
        s
    }
}

/// Qué campos difieren entre la corrida de referencia y la de atajos.
fn describe(reference: &Outcome, fast: &Outcome) -> String {
    match (reference, fast) {
        (Outcome::Done(a), Outcome::Done(b)) => ["ok", "output", "errors", "steps"]
            .iter()
            .filter(|k| a.get(**k) != b.get(**k))
            .map(|k| {
                format!(
                    "{}: referencia {} / atajos {}",
                    k,
                    clip(a.get(*k).unwrap_or(&serde_json::Value::Null)),
                    clip(b.get(*k).unwrap_or(&serde_json::Value::Null))
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        _ => format!("referencia {:?} / atajos {:?}", reference, fast),
    }
}

#[derive(Default)]
struct Tally {
    compared: usize,
    nondeterministic: usize,
    timeouts: usize,
    mismatches: Vec<String>,
}

#[test]
fn shortcuts_match_the_reference_interpreter() {
    let runner = runner();
    assert!(
        runner.exists(),
        "no está el ejecutor del oráculo en {} (lo compila `cargo test -p synsema-runtime`)",
        runner.display()
    );
    let root = repo_root();
    let mut files = Vec::new();
    for r in ROOTS {
        collect(&root.join(r), &mut files);
    }
    files.sort();
    assert!(files.len() >= 20, "el oráculo encontró sólo {} programas: ¿cambió la ruta del repo?", files.len());

    let queue = Mutex::new(files.clone());
    let tally = Mutex::new(Tally::default());
    let workers = std::thread::available_parallelism().map(|n| (n.get() / 2).clamp(1, 4)).unwrap_or(2);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let Some(file) = queue.lock().unwrap().pop() else { break };
                let rel = file.strip_prefix(&root).unwrap_or(&file).display().to_string().replace('\\', "/");
                // Referencia, atajos, referencia: la corrida con atajos queda EN MEDIO. Un programa
                // que depende de estado de afuera (un archivo, una base en /tmp que otro programa
                // del corpus escribe en paralelo) cambia entre las dos referencias si ese estado
                // cambió en cualquier momento de la ventana, y se descarta como no determinista.
                // Si las dos referencias coinciden y la de atajos no, la diferencia es real.
                let first = run(&runner, &file, true);
                if first == Outcome::Timeout {
                    tally.lock().unwrap().timeouts += 1;
                    continue;
                }
                let fast = run(&runner, &file, false);
                let second = run(&runner, &file, true);
                if first != second {
                    tally.lock().unwrap().nondeterministic += 1;
                    continue;
                }
                let mut t = tally.lock().unwrap();
                t.compared += 1;
                if fast != first {
                    t.mismatches.push(format!("{}: {}", rel, describe(&first, &fast)));
                }
            });
        }
    });

    let mut t = tally.into_inner().unwrap();
    t.mismatches.sort();
    eprintln!(
        "oráculo: {} programas, {} comparados, {} no deterministas, {} sin terminar en {:?}, {} con diferencias",
        files.len(),
        t.compared,
        t.nondeterministic,
        t.timeouts,
        TIMEOUT,
        t.mismatches.len()
    );
    assert!(
        t.mismatches.is_empty(),
        "los atajos cambian lo observable en {} programa(s):\n{}",
        t.mismatches.len(),
        t.mismatches.join("\n")
    );
}
