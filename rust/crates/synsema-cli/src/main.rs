//! Synsema CLI. Espeja `synsema/cli.py` y `__main__.py` (capa 11, en progreso).
//!
//! Subcomando de conformidad (gate de paridad contra el oráculo Python):
//!
//!     synsema-cli conform <archivo.syn>
//!
//! Ejecuta el programa y emite a STDOUT una sola línea JSON:
//!     {"ok": <bool>, "out": [<líneas de print>], "err": [<errores>]}
//! Exit 0 siempre que pueda producir el JSON (el fallo del programa va en el JSON).
//! Exit != 0 sólo si el CLI no pudo (archivo ilegible / args inválidos), con el
//! motivo en STDERR. Nada más que el JSON va a STDOUT.

use std::process::ExitCode;

// El conform usa el motor (runtime): intérprete + modelo de seguridad cableado.
use synsema_runtime::daemon;
use synsema_runtime::engine::{repl, run_source, run_swarm_dump};
use synsema_runtime::serve::run_serve_program;

const USAGE: &str = "uso: synsema-cli <conform [--swarm] [--flat] | serve [--secure] | run | check | tokens | ast | repl | daemon | version> [--env-file <path> | --no-env-file] <archivo.syn>";

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
            eprintln!("subcomando desconocido: '{}'. Disponibles: conform, serve, run, check, tokens, ast, repl, daemon, version", other);
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

/// serve [--secure] <archivo.syn>: levanta el server y bloquea hasta kill.
/// Imprime la línea de readiness ("Serving HTTP on port PORT (N route(s))") a STDOUT.
fn cmd_serve(args: &[String]) -> ExitCode {
    let args = take_env_file_flags(args);
    let args = args.as_slice();
    let (secure, path) = match args.get(2).map(String::as_str) {
        Some("--secure") => match args.get(3) {
            Some(p) => (true, p.clone()),
            None => {
                eprintln!("{}", USAGE);
                return ExitCode::from(2);
            }
        },
        Some(p) if args.len() == 3 => (false, p.to_string()),
        _ => {
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
    let result = run_serve_program(&source, &path, secure);
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
            eprintln!("uso: synsema-cli run [--flat] <archivo.syn>");
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

/// check <archivo.syn>: parsea sin ejecutar; reporta cantidad de statements o el error.
fn cmd_check(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema-cli check <archivo.syn>");
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
            eprintln!("uso: synsema-cli tokens <archivo.syn>");
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
            eprintln!("uso: synsema-cli ast <archivo.syn>");
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
            eprintln!("uso: synsema-cli daemon <start|stop|status|logs|restart> [program.syn]");
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
            eprintln!("uso: synsema-cli daemon {} <program.syn>", action);
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
