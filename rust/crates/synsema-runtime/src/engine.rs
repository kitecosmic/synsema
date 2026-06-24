//! Motor de ejecución. Análogo de `SynsemaEngine.run_source`.
//!
//! Dos caminos:
//! - `run_source` / `run_source_secure`: programa de un solo hilo (conform capas 1-6).
//!   share/observe usan el blackboard local del intérprete.
//! - `Engine` + `run_swarm_dump`: con swarm real — cada `spawn` corre el cuerpo del
//!   agente en su propio hilo con su propio `Interpreter` (paridad: `std::thread`,
//!   no tokio). share/observe/signal/wait_for van al swarm compartido.
//!
//! Todo corre en hilos con stack grande (intérprete tree-walking + recursión).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use synsema_llm::human::{AutoHandler, InteractionManager};
use synsema_llm::provider::{LLMProvider, LLMRequest, MockProvider};

use synsema_agents::builtins::register_agent_builtins;
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_agents::swarm::{AgentState, Swarm};
use synsema_capabilities::model::{
    capability_type_from_name, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::ast::Node;
use synsema_core::interpreter::{Control, Interpreter, RunResult, SwarmHooks, TestOutcome};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{from_send, to_send, SendValue, SynValue};
use synsema_stdlib::cron::{register_cron_builtins, CronScheduler};
use synsema_stdlib::database::{register_database_builtins, DatabaseManager};
use synsema_stdlib::http::register_http_builtins;
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

pub(crate) const INTERP_STACK_SIZE: usize = 512 * 1024 * 1024;

/// Wiring común de un intérprete: capabilities + builtins seguros/stdlib + grant hook.
/// En modo no-secure se auto-conceden STDOUT y TIME (engine.py:99-101).
pub(crate) fn wire_common(interp: &mut Interpreter, caps: &Rc<RefCell<CapabilitySet>>, secure: bool) {
    wire_common_with_state(
        interp,
        caps,
        secure,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
    );
}

/// Igual que `wire_common` pero con handles de progress/memory provistos por el caller
/// (para que `run_source` pueda cargar/guardar estado persistido alrededor del run).
pub(crate) fn wire_common_with_state(
    interp: &mut Interpreter,
    caps: &Rc<RefCell<CapabilitySet>>,
    secure: bool,
    progress: Rc<RefCell<ProgressManager>>,
    memory: Rc<RefCell<AgentMemory>>,
) {
    if !secure {
        caps.borrow_mut().grant(Capability::new(CapabilityType::Stdout, None));
        caps.borrow_mut().grant(Capability::new(CapabilityType::Time, None));
    }
    register_secure_builtins(interp, caps.clone());
    // Secretos/env: carga el `.env` (antes de evaluar require/serve) y registra
    // env/secret/reveal/bearer/crypto. Deny-by-default: env()/secret()/reveal() exigen
    // su capability incluso en modo no-secure (NO se auto-conceden como stdout/time).
    register_secret_builtins(interp, caps.clone(), Rc::new(EnvStore::load_default()));
    register_http_builtins(interp);
    // Hashing SHA (puro, sin capability): sha256/sha512 → bytes.
    synsema_stdlib::hashing::register_hash_builtins(interp);
    // cron/db/progress/memory: sus builtins clonan el Rc internamente → viven mientras
    // viva el intérprete.
    register_cron_builtins(interp, Rc::new(CronScheduler::new()));
    register_database_builtins(interp, Rc::new(RefCell::new(DatabaseManager::new())));
    register_agent_builtins(interp, progress, memory);
    // Helpers de respuesta + vocabulario de contenido (ok/created/.../content). El
    // oráculo los registra en el intérprete principal siempre.
    synsema_stdlib::server::register_serve_builtins(interp);
    // A1 concurrencia (Fase 1): parallel_map + chunk.
    crate::parallel::register_parallel_builtins(interp, caps, secure);
    // render real (sobrescribe el placeholder de core): SSR de templates → raw response.
    interp.register_builtin(
        "render",
        -1,
        Rc::new(|i, args, _loc| {
            let path = args.first().map(|v| v.to_string()).unwrap_or_default();
            let html = synsema_core::templates::render_template(i, &path, args.get(1))?;
            Ok(synsema_core::templates::make_raw(html, "text/html; charset=utf-8", 200))
        }),
    );
    let c = caps.clone();
    interp.set_grant_hook(Rc::new(move |name, scope| {
        if let Some(ty) = capability_type_from_name(name) {
            c.borrow_mut().grant(Capability::new(ty, scope.map(|s| s.to_string())));
        }
    }));
}

fn finish(mut interp: Interpreter, result: Result<SynValue, Control>) -> RunResult {
    match result {
        Ok(_) => RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new() },
        Err(Control::Error(e)) => RunResult {
            success: false,
            output: std::mem::take(&mut interp.output),
            errors: vec![format!("Runtime error: {}", e)],
        },
        Err(Control::Give(_)) | Err(Control::Stop(_)) => RunResult {
            success: false,
            output: std::mem::take(&mut interp.output),
            errors: vec!["Runtime error: 'give'/'stop' used outside of a task or loop".to_string()],
        },
    }
}

// =========================================================
// Camino sin swarm (conform capas 1-6)
// =========================================================

fn run_inner(source: &str, filename: &str, secure: bool) -> RunResult {
    match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Lexer error: {}", e)],
        },
        Err(CompileError::Parse(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Parse error: {}", e)],
        },
        Ok(program) => {
            let mut interp = Interpreter::new();
            let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
            let progress = Rc::new(RefCell::new(ProgressManager::new()));
            let memory = Rc::new(RefCell::new(AgentMemory::new()));
            wire_common_with_state(&mut interp, &caps, secure, progress.clone(), memory.clone());

            // StatePersistence cross-run (espeja engine.run_source del oráculo): para
            // archivos nombrados (no "<stdin>") carga el estado previo antes de ejecutar
            // y lo guarda después → memory/progress sobreviven reinicios.
            let persistence = state_persistence_for(filename);
            if let Some(p) = &persistence {
                p.load_into(&mut memory.borrow_mut(), &mut progress.borrow_mut());
            }

            let r = interp.execute(&program);

            if let Some(p) = &persistence {
                p.save_from(&memory.borrow(), &progress.borrow());
            }
            finish(interp, r)
        }
    }
}

/// Abre la persistencia de estado para `filename` (None si es `<stdin>`). El nombre
/// de programa es el `stem` del archivo, idéntico al oráculo.
fn state_persistence_for(filename: &str) -> Option<crate::persistence::StatePersistence> {
    if filename == "<stdin>" {
        return None;
    }
    let stem = std::path::Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "default".to_string());
    crate::persistence::StatePersistence::open(&stem).ok()
}

fn spawn_run(source: &str, filename: &str, secure: bool) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_inner(&src, &fname, secure))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec!["el motor abortó (probable desborde de stack nativo)".to_string()],
        })
}

/// Modo no-secure (default real): auto-concede STDOUT y TIME. Lo que usa `conform`.
pub fn run_source(source: &str, filename: &str) -> RunResult {
    spawn_run(source, filename, false)
}

// =========================================================
// Test framework (Batch 3): `synsema test`
// =========================================================

/// Reporte agregado de correr los bloques `test` de un archivo. `output` lleva los `print`
/// de los tests (para mostrarse sólo con `-v`).
pub struct TestReport {
    pub outcomes: Vec<TestOutcome>,
    pub passed: usize,
    pub failed: usize,
    pub output: Vec<String>,
}

fn report_with_failure(name: &str, message: String) -> TestReport {
    TestReport {
        outcomes: vec![TestOutcome { name: name.to_string(), passed: false, message: Some(message), assertion: false }],
        passed: 0,
        failed: 1,
        output: Vec::new(),
    }
}

fn run_tests_inner(source: &str, filename: &str) -> TestReport {
    let program = match parse_source(source, filename) {
        Ok(p) => p,
        Err(CompileError::Lex(e)) => return report_with_failure("<parse>", format!("Lexer error: {}", e)),
        Err(CompileError::Parse(e)) => return report_with_failure("<parse>", format!("Parse error: {}", e)),
    };
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    let progress = Rc::new(RefCell::new(ProgressManager::new()));
    let memory = Rc::new(RefCell::new(AgentMemory::new()));
    // Wiring no-secure (igual que `run`): los `require` del archivo conceden capabilities (G4).
    wire_common_with_state(&mut interp, &caps, false, progress, memory);
    let outcomes = interp.run_test_blocks(&program);
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let failed = outcomes.len() - passed;
    TestReport { outcomes, passed, failed, output: std::mem::take(&mut interp.output) }
}

/// Corre los bloques `test` de un archivo en un hilo con stack grande (como `spawn_run`).
pub fn run_tests(source: &str, filename: &str) -> TestReport {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_tests_inner(&src, &fname))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| {
            report_with_failure("<runner>", "el motor abortó (probable desborde de stack nativo)".to_string())
        })
}

/// REPL interactivo (espeja `engine.repl()` del oráculo). Mantiene UN intérprete
/// con estado entre líneas; ejecuta cada línea e imprime la salida nueva.
pub fn repl() {
    use std::io::{self, BufRead, Write};
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("repl")));
    wire_common(&mut interp, &caps, false);
    println!("Synsema REPL — escribí sentencias; Ctrl+Z (Windows) / Ctrl+D para salir.");
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut printed = 0usize;
    loop {
        print!(">>> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        match handle.read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.trim().is_empty() {
            continue;
        }
        match parse_source(trimmed, "<repl>") {
            Ok(prog) => match interp.execute(&prog) {
                Ok(_) => {}
                Err(Control::Error(e)) => println!("Runtime error: {}", e),
                Err(_) => println!("Runtime error: 'give'/'stop' used outside of a task or loop"),
            },
            Err(CompileError::Lex(e)) => println!("Lexer error: {}", e),
            Err(CompileError::Parse(e)) => println!("Parse error: {}", e),
        }
        while printed < interp.output.len() {
            println!("{}", interp.output[printed]);
            printed += 1;
        }
    }
    println!();
}

/// Resultado con diagnósticos ricos (capa 9: error_reporter). Espeja
/// `EngineResult.diagnostics` del oráculo.
pub struct DiagRun {
    pub result: RunResult,
    pub diagnostics: Vec<crate::error_reporter::ErrorDiagnostic>,
}

fn run_diag_inner(source: &str, filename: &str) -> DiagRun {
    use crate::error_reporter::ErrorReporter;
    let program = match parse_source(source, filename) {
        Ok(p) => p,
        Err(CompileError::Lex(e)) => {
            let msg = e.to_string();
            return DiagRun {
                result: RunResult { success: false, output: Vec::new(), errors: vec![format!("Lexer error: {}", e)] },
                diagnostics: vec![ErrorReporter::new().build_diagnostic("LexerError", &msg, None, None)],
            };
        }
        Err(CompileError::Parse(e)) => {
            let msg = e.to_string();
            return DiagRun {
                result: RunResult { success: false, output: Vec::new(), errors: vec![format!("Parse error: {}", e)] },
                diagnostics: vec![ErrorReporter::new().build_diagnostic("ParseError", &msg, None, None)],
            };
        }
    };
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    wire_common(&mut interp, &caps, false);
    match interp.execute(&program) {
        Ok(_) => DiagRun {
            result: RunResult { success: true, output: std::mem::take(&mut interp.output), errors: Vec::new() },
            diagnostics: Vec::new(),
        },
        Err(Control::Error(e)) => {
            let mut reporter = ErrorReporter::new();
            reporter.load_source(filename, source);
            if let Some(intent) = interp.intent() {
                reporter.set_intent(intent);
            }
            let vars: Vec<(String, String)> = interp
                .global_env
                .borrow()
                .bindings
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            let diag = reporter.build_diagnostic("RuntimeError", &e.message, e.location.as_ref(), Some(&vars));
            DiagRun {
                result: RunResult { success: false, output: interp.output.clone(), errors: vec![format!("Runtime error: {}", e)] },
                diagnostics: vec![diag],
            }
        }
        Err(_) => DiagRun {
            result: RunResult {
                success: false,
                output: std::mem::take(&mut interp.output),
                errors: vec!["Runtime error: 'give'/'stop' used outside of a task or loop".to_string()],
            },
            diagnostics: Vec::new(),
        },
    }
}

/// Corre un programa y devuelve diagnósticos ricos en caso de error (capa 9).
pub fn run_with_diagnostics(source: &str, filename: &str) -> DiagRun {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_diag_inner(&src, &fname))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| DiagRun {
            result: RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] },
            diagnostics: Vec::new(),
        })
}

/// Modo secure: sin auto-grants. Para el modo seguro/serve y las integraciones.
pub fn run_source_secure(source: &str, filename: &str) -> RunResult {
    spawn_run(source, filename, true)
}

/// Corre con un configurador del intérprete (para cablear callbacks host-config
/// como human/llm). El configurador se ejecuta dentro del hilo del run (los hooks
/// son `Rc`, no cruzan hilos).
fn run_configured(source: &str, filename: &str, configure: impl FnOnce(&mut Interpreter)) -> RunResult {
    match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Lexer error: {}", e)],
        },
        Err(CompileError::Parse(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Parse error: {}", e)],
        },
        Ok(program) => {
            let mut interp = Interpreter::new();
            let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
            wire_common(&mut interp, &caps, false);
            configure(&mut interp);
            let r = interp.execute(&program);
            finish(interp, r)
        }
    }
}

/// Corre con un callback humano (host-config) respaldado por `AutoHandler`.
pub fn run_with_human(source: &str, filename: &str, default_approve: bool) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let mgr = InteractionManager::new(Arc::new(AutoHandler::new(default_approve, "")));
                interp.set_human_callback(mgr.get_callback());
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] })
}

/// Corre con un proveedor LLM mock (host-config) con respuestas predecibles.
pub fn run_with_llm(source: &str, filename: &str, responses: HashMap<String, String>) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let provider = Arc::new(MockProvider::new(responses));
                interp.set_llm_callback(Rc::new(move |op: &str| provider.call(&LLMRequest::new(op)).content));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] })
}

// =========================================================
// Camino con swarm (agentes en hilos)
// =========================================================

/// Cablea los hooks del swarm en un intérprete (capturando el `Arc<Swarm>` y el
/// nombre del agente para las escrituras al blackboard).
pub(crate) fn wire_swarm_hooks(interp: &mut Interpreter, swarm: Arc<Swarm>, agent_name: &str) {
    let name = agent_name.to_string();

    let share: Rc<dyn Fn(&str, &SynValue)> = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |k, v| sw.blackboard.write(k, to_send(v), &n))
    };
    let observe: Rc<dyn Fn(&str) -> Option<SynValue>> = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |k| sw.blackboard.read(k, &n).map(|sv| from_send(&sv)))
    };
    let signal: Rc<dyn Fn(&str, Option<SynValue>)> = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |sig_name, data| sw.signal(sig_name, &n, data.map(|v| to_send(&v))))
    };
    let wait_for: Rc<dyn Fn(&str) -> Option<SynValue>> = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |sig_name| {
            // Estado WAITING mientras bloquea (no-op si `n` no es agente registrado, p.ej. "main").
            sw.set_state(&n, AgentState::Waiting);
            let sig = sw.wait_for_signal(sig_name, Duration::from_secs(30));
            sw.set_state(&n, AgentState::Working);
            sig.and_then(|s| s.data).map(|d| from_send(&d))
        })
    };
    let spawn: Rc<
        dyn Fn(&str, Vec<Node>, Vec<(String, SynValue)>) -> Result<String, Control>,
    > = {
        let sw = swarm.clone();
        Rc::new(move |agent, body, args| {
            let send_args: Vec<(String, SendValue)> =
                args.iter().map(|(k, v)| (k.clone(), to_send(v))).collect();
            Ok(spawn_agent(sw.clone(), agent.to_string(), body, send_args))
        })
    };

    interp.set_swarm_hooks(SwarmHooks { share, observe, signal, wait_for, spawn });
}

/// Crea un intérprete con el wiring común + los hooks del swarm.
fn setup_swarm_interpreter(swarm: Arc<Swarm>, agent_name: &str) -> Interpreter {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("agent")));
    wire_common(&mut interp, &caps, false);
    wire_swarm_hooks(&mut interp, swarm, agent_name);
    interp
}

/// Lanza un agente en su propio hilo con su propio `Interpreter`. Devuelve el
/// instance_id. El estado pasa STARTING→WORKING→DONE/ERROR; el error se captura
/// (no crashea el programa) y se emite una señal `__agent_error:<id>`.
fn spawn_agent(
    swarm: Arc<Swarm>,
    agent_name: String,
    body: Vec<Node>,
    send_args: Vec<(String, SendValue)>,
) -> String {
    let instance_id = swarm.register_new_agent(&agent_name);
    let sw = swarm.clone();
    let id = instance_id.clone();
    let handle = std::thread::Builder::new()
        .name(id.clone())
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            let mut interp = setup_swarm_interpreter(sw.clone(), &id);
            for (k, v) in &send_args {
                interp.set_global(k, from_send(v));
            }
            sw.set_state(&id, AgentState::Working);
            match interp.run_block(&body) {
                Ok(_) => sw.set_state(&id, AgentState::Done),
                Err(Control::Error(e)) => {
                    sw.set_error(&id, e.to_string());
                    sw.signal(&format!("__agent_error:{}", id), &id, None);
                }
                Err(_) => {
                    sw.set_error(&id, "'give'/'stop' used outside of a task or loop".to_string());
                    sw.signal(&format!("__agent_error:{}", id), &id, None);
                }
            }
            sw.set_finished(&id);
        })
        .expect("no se pudo crear el hilo del agente");
    swarm.add_thread(handle);
    instance_id
}

fn run_swarm_inner(source: &str, filename: &str, swarm: Arc<Swarm>) -> RunResult {
    match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Lexer error: {}", e)],
        },
        Err(CompileError::Parse(e)) => RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![format!("Parse error: {}", e)],
        },
        Ok(program) => {
            let mut interp = setup_swarm_interpreter(swarm, "main");
            let r = interp.execute(&program);
            finish(interp, r)
        }
    }
}

/// Motor que retiene el `Swarm` para inspección post-run (estado interno).
pub struct Engine {
    pub swarm: Arc<Swarm>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self { swarm: Arc::new(Swarm::new()) }
    }

    /// Corre el programa (con swarm cableado) en un hilo con stack grande. Los hilos
    /// de agentes lanzados quedan en `self.swarm` (usar `wait_all` para joinearlos).
    pub fn run(&self, source: &str, filename: &str) -> RunResult {
        let swarm = self.swarm.clone();
        let src = source.to_string();
        let fname = filename.to_string();
        std::thread::Builder::new()
            .stack_size(INTERP_STACK_SIZE)
            .spawn(move || run_swarm_inner(&src, &fname, swarm))
            .expect("no se pudo crear el hilo del motor")
            .join()
            .unwrap_or_else(|_| RunResult {
                success: false,
                output: Vec::new(),
                errors: vec!["el motor abortó (probable desborde de stack nativo)".to_string()],
            })
    }
}

/// Salida del modo `--swarm`: RunResult + estado terminal del blackboard y agentes.
pub struct SwarmDump {
    pub result: RunResult,
    /// (clave, str(value)) del blackboard.
    pub blackboard: Vec<(String, String)>,
    /// (instance_id, estado) de cada agente.
    pub agents: Vec<(String, String)>,
}

/// Corre con swarm, joinea todos los agentes, y devuelve el dump de estado interno.
pub fn run_swarm_dump(source: &str, filename: &str) -> SwarmDump {
    let engine = Engine::new();
    let result = engine.run(source, filename);
    engine.swarm.wait_all();
    let blackboard: Vec<(String, String)> = engine
        .swarm
        .blackboard
        .snapshot()
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    let agents: Vec<(String, String)> = engine
        .swarm
        .agent_states()
        .into_iter()
        .map(|(id, st)| (id, st.name().to_string()))
        .collect();
    SwarmDump { result, blackboard, agents }
}
