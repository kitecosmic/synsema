//! Synsema CLI. Espeja `synsema/cli.py` y `__main__.py` (capa 11, en progreso).
//!
//! Subcomando de conformidad (gate de paridad contra el oráculo Python):
//!
//!     synsema conform <archivo.syn>
//!
//! Ejecuta el programa y emite a STDOUT una sola línea JSON:
//!     {"ok": <bool>, "out": [<líneas de print>], "err": [<errores>]}
//! Exit 0 siempre que pueda producir el JSON (el fallo del programa va en el JSON).
//! Exit != 0 sólo si el CLI no pudo (archivo ilegible / args inválidos), con el
//! motivo en STDERR. Nada más que el JSON va a STDOUT.

use std::process::ExitCode;

// El conform usa el motor (runtime): intérprete + modelo de seguridad cableado.
use synsema_runtime::daemon;
use synsema_runtime::engine::{repl, run_source, run_swarm_dump, run_tests, TestReport};
use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

const USAGE: &str = "uso: synsema <conform [--swarm] [--flat] | serve [--secure] [--port N] [--domain d1,d2] [--tls-auto <email> | --tls-cert <p> --tls-key <p>] [--bind addr] | run | test [-v] <archivo|dir> | check | tokens | ast | repl | daemon | version> [--env-file <path> | --no-env-file] <archivo.syn>";

/// Serializa un mapa (clave→string) como objeto JSON ordenado.
fn json_obj(pairs: Vec<(String, String)>) -> String {
    let map: std::collections::BTreeMap<String, String> = pairs.into_iter().collect();
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Procesa `--env-file <path>` / `--env-file=<path>` / `--no-env-file`: setea la
/// env-var `SYNSEMA_ENV_FILE` (la fuente de verdad que lee el runtime) y devuelve los
/// args sin esos flags, para que el resto del parseo no los confunda con el archivo.
/// `--no-env-file` ≡ `SYNSEMA_ENV_FILE=` vacío (desactiva la auto-carga del `.env`).
fn take_env_file_flags(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--no-env-file" {
            std::env::set_var("SYNSEMA_ENV_FILE", "");
        } else if a == "--env-file" {
            match args.get(i + 1) {
                Some(p) => {
                    std::env::set_var("SYNSEMA_ENV_FILE", p);
                    i += 1; // consume el valor
                }
                None => eprintln!("synsema: --env-file requires a path"),
            }
        } else if let Some(p) = a.strip_prefix("--env-file=") {
            std::env::set_var("SYNSEMA_ENV_FILE", p);
        } else {
            out.push(args[i].clone());
        }
        i += 1;
    }
    out
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("conform") => cmd_conform(&args),
        Some("serve") => cmd_serve(&args),
        Some("run") => cmd_run(&args),
        Some("test") => cmd_test(&args),
        Some("check") => cmd_check(&args),
        Some("tokens") => cmd_tokens(&args),
        Some("ast") => cmd_ast(&args),
        Some("repl") => {
            repl();
            ExitCode::SUCCESS
        }
        Some("daemon") => cmd_daemon(&args),
        Some("version") | Some("--version") | Some("-V") => {
            println!("Synsema v{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("subcomando desconocido: '{}'. Disponibles: conform, serve, run, test, check, tokens, ast, repl, daemon, version", other);
            ExitCode::from(2)
        }
        None => {
            eprintln!("{}", USAGE);
            ExitCode::from(2)
        }
    }
}

fn cmd_conform(args: &[String]) -> ExitCode {
    // conform [--swarm] [--flat] [--env-file <p>|--no-env-file] <archivo.syn>
    let args = take_env_file_flags(args);
    let args = args.as_slice();
    let mut swarm = false;
    let mut flat = false;
    let mut path: Option<String> = None;
    for a in &args[2..] {
        match a.as_str() {
            "--swarm" => swarm = true,
            "--flat" => flat = true,
            p if !p.starts_with("--") => path = Some(p.to_string()),
            _ => {}
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::from(2);
        }
    };

    // Leer el archivo UTF-8. El path se usa tal cual como nombre de fuente para que
    // el prefijo de ubicación de los errores sea reproducible contra el oráculo.
    let mut source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    // --flat: pre-procesa sintaxis flat → estándar antes de ejecutar.
    if flat {
        source = synsema_core::flat_syntax::translate_flat(&source);
    }

    if swarm {
        // Modo swarm: tras joinear los hilos, agrega blackboard + estados de agentes.
        let dump = run_swarm_dump(&source, &path);
        let out = serde_json::to_string(&dump.result.output).unwrap_or_else(|_| "[]".to_string());
        let err = serde_json::to_string(&dump.result.errors).unwrap_or_else(|_| "[]".to_string());
        println!(
            "{{\"ok\": {}, \"out\": {}, \"err\": {}, \"blackboard\": {}, \"agents\": {}}}",
            dump.result.success,
            out,
            err,
            json_obj(dump.blackboard),
            json_obj(dump.agents)
        );
    } else {
        let result = run_source(&source, &path);
        // serde_json escapa correctamente los strings (comillas, \n, control, unicode).
        let out = serde_json::to_string(&result.output).unwrap_or_else(|_| "[]".to_string());
        let err = serde_json::to_string(&result.errors).unwrap_or_else(|_| "[]".to_string());
        println!("{{\"ok\": {}, \"out\": {}, \"err\": {}}}", result.success, out, err);
    }

    ExitCode::SUCCESS
}

/// serve [--secure] [deploy flags] <archivo.syn>: levanta el server y bloquea hasta kill.
/// Flags de despliegue (Pieza A) que sobreescriben el bloque `serve` (flag > archivo >
/// default): `--port N`, `--domain d1,d2`, `--tls-auto <email>`, `--tls-cert <p>
/// --tls-key <p>`, `--bind <addr>`. Imprime la línea de readiness a STDOUT.
fn cmd_serve(args: &[String]) -> ExitCode {
    let args = take_env_file_flags(args);
    let mut secure = false;
    let mut path: Option<String> = None;
    let mut ov = ServeOverrides::default();
    let mut i = 2;
    while i < args.len() {
        // Toma el valor del flag siguiente, o error claro (fail-loud).
        macro_rules! next_val {
            ($flag:expr) => {{
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("synsema serve: {} requires a value", $flag);
                        return ExitCode::from(2);
                    }
                }
            }};
        }
        match args[i].as_str() {
            "--secure" => secure = true,
            "--port" => {
                let v = next_val!("--port");
                match v.parse::<u16>() {
                    Ok(p) if p >= 1 => ov.port = Some(p),
                    _ => {
                        eprintln!(
                            "synsema serve: --port must be a valid port (1-65535), got '{}'",
                            v
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            "--domain" => {
                let v = next_val!("--domain");
                let ds: Vec<String> =
                    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                if ds.is_empty() {
                    eprintln!("synsema serve: --domain requires at least one domain");
                    return ExitCode::from(2);
                }
                ov.domains = Some(ds);
            }
            "--tls-auto" => ov.tls_auto_email = Some(next_val!("--tls-auto")),
            "--tls-cert" => ov.tls_cert = Some(next_val!("--tls-cert")),
            "--tls-key" => ov.tls_key = Some(next_val!("--tls-key")),
            "--bind" => ov.bind = Some(next_val!("--bind")),
            p if !p.starts_with("--") => path = Some(p.to_string()),
            other => {
                eprintln!("synsema serve: unknown flag '{}'", other);
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    // Validación fail-loud de combinaciones inválidas (mutua exclusión, par cert/key).
    if let Err(e) = ov.validate() {
        eprintln!("synsema serve: {}", e);
        return ExitCode::from(2);
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::from(2);
        }
    };

    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };

    // Bloquea mientras el server corra; sólo retorna si no se levantó o falló.
    let result = run_serve_program_with_overrides(&source, &path, secure, ov);
    if !result.success {
        for e in &result.errors {
            eprintln!("{}", e);
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// run <archivo.syn> [--flat]: ejecuta el programa, imprime la salida, exit≠0 si falla.
fn cmd_run(args: &[String]) -> ExitCode {
    let args = take_env_file_flags(args);
    let args = args.as_slice();
    let mut flat = false;
    let mut path: Option<String> = None;
    for a in &args[2..] {
        match a.as_str() {
            "--flat" => flat = true,
            p if !p.starts_with("--") => path = Some(p.to_string()),
            _ => {}
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("uso: synsema run [--flat] <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let mut source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    if flat || path.ends_with(".fsyn") {
        source = synsema_core::flat_syntax::translate_flat(&source);
    }
    let result = run_source(&source, &path);
    for line in &result.output {
        println!("{}", line);
    }
    if !result.success {
        for e in &result.errors {
            eprintln!("{}", e);
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// test [-v] [--flat] <archivo.syn | dir>: corre los bloques `test` y reporta ✓/✗.
/// Exit 0 si todos pasan; 1 si alguno falla; 2 por error de uso/archivo ilegible.
fn cmd_test(args: &[String]) -> ExitCode {
    let args = take_env_file_flags(args);
    let args = args.as_slice();
    let mut flat = false;
    let mut verbose = false;
    let mut path: Option<String> = None;
    for a in &args[2..] {
        match a.as_str() {
            "--flat" => flat = true,
            "-v" | "--verbose" => verbose = true,
            p if !p.starts_with('-') => path = Some(p.to_string()),
            _ => {}
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("uso: synsema test [-v] [--flat] <archivo.syn | dir>");
            return ExitCode::from(2);
        }
    };
    let files = match collect_syn_files(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("no se pudo acceder a '{}': {}", path, e);
            return ExitCode::from(2);
        }
    };
    if files.is_empty() {
        eprintln!("no se encontraron archivos .syn en '{}'", path);
        return ExitCode::from(2);
    }
    let multi = files.len() > 1;
    let mut total_passed = 0usize;
    let mut total_failed = 0usize;
    for file in &files {
        let mut source = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("no se pudo leer '{}': {}", file, e);
                total_failed += 1;
                continue;
            }
        };
        if flat || file.ends_with(".fsyn") {
            source = synsema_core::flat_syntax::translate_flat(&source);
        }
        if multi {
            println!("{}:", file);
        }
        let report = run_tests(&source, file);
        print_test_report(&report, verbose);
        total_passed += report.passed;
        total_failed += report.failed;
    }
    let total = total_passed + total_failed;
    println!("{} passed, {} failed ({} total)", total_passed, total_failed, total);
    if total_failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Imprime el reporte de un archivo: ✓/✗ por test (+ stdout de los tests sólo con `-v`).
fn print_test_report(report: &TestReport, verbose: bool) {
    if verbose {
        for line in &report.output {
            println!("  | {}", line);
        }
    }
    for o in &report.outcomes {
        if o.passed {
            println!("  \u{2713} {}", o.name); // ✓
        } else {
            let msg = o.message.as_deref().unwrap_or("failed");
            println!("  \u{2717} {}: {}", o.name, msg); // ✗
        }
    }
}

/// Recolecta archivos `.syn`: un archivo solo, o todos los `*.syn` de un dir (recursivo).
fn collect_syn_files(path: &str) -> std::io::Result<Vec<String>> {
    let p = std::path::Path::new(path);
    if p.is_file() {
        return Ok(vec![path.to_string()]);
    }
    if p.is_dir() {
        let mut out = Vec::new();
        collect_syn_dir(p, &mut out)?;
        out.sort();
        return Ok(out);
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no es un archivo ni un directorio"))
}

fn collect_syn_dir(dir: &std::path::Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_syn_dir(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("syn") {
            out.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// check <archivo.syn>: parsea sin ejecutar; reporta cantidad de statements o el error.
fn cmd_check(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema check <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    use synsema_core::parser::CompileError;
    match synsema_core::parser::parse_source(&source, &path) {
        Ok(program) => {
            println!("OK: {} statements parsed.", program.statements.len());
            ExitCode::SUCCESS
        }
        Err(CompileError::Lex(e)) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
        Err(CompileError::Parse(e)) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// tokens <archivo.syn>: muestra el stream de tokens (debug).
fn cmd_tokens(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema tokens <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    match synsema_core::lexer::Lexer::new(&source, &path).tokenize() {
        Ok(tokens) => {
            for tok in &tokens {
                println!("  {:?}", tok);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Lexer error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// ast <archivo.syn>: muestra el AST parseado (debug).
fn cmd_ast(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema ast <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    use synsema_core::parser::CompileError;
    match synsema_core::parser::parse_source(&source, &path) {
        Ok(program) => {
            for stmt in &program.statements {
                println!("{:#?}", stmt.kind);
            }
            ExitCode::SUCCESS
        }
        Err(CompileError::Lex(e)) => {
            eprintln!("Lexer error: {}", e);
            ExitCode::from(1)
        }
        Err(CompileError::Parse(e)) => {
            eprintln!("Parse error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// daemon <start|stop|status|logs|restart> [program.syn]: gestiona procesos background.
fn cmd_daemon(args: &[String]) -> ExitCode {
    let action = match args.get(2).map(String::as_str) {
        Some(a) => a,
        None => {
            eprintln!("uso: synsema daemon <start|stop|status|logs|restart> [program.syn]");
            return ExitCode::from(2);
        }
    };

    if action == "status" {
        let statuses = daemon::daemon_status();
        println!("{}", daemon::format_status_table(&statuses));
        return ExitCode::SUCCESS;
    }

    let target = match args.get(3) {
        Some(t) => t.clone(),
        None => {
            eprintln!("uso: synsema daemon {} <program.syn>", action);
            return ExitCode::from(2);
        }
    };
    let extra: Vec<String> = args.get(4..).map(|s| s.to_vec()).unwrap_or_default();

    match action {
        "start" => {
            let r = daemon::daemon_start(&target, &extra);
            println!("{}", r.message);
            if r.status == "error" {
                return ExitCode::from(1);
            }
        }
        "stop" => {
            let r = daemon::daemon_stop(&target);
            println!("{}", r.message);
        }
        "restart" => {
            let r = daemon::daemon_restart(&target, &extra);
            println!("{}", r.message);
            if r.status == "error" {
                return ExitCode::from(1);
            }
        }
        "logs" => {
            let lines = args.get(4).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
            println!("{}", daemon::daemon_logs(&target, lines));
        }
        other => {
            eprintln!("acción de daemon desconocida: {}", other);
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
