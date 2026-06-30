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
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use synsema_llm::human::{AutoHandler, InteractionManager};
use synsema_llm::provider::{LLMProvider, LLMRequest, MockProvider};

// Re-export de los tipos del provider tool-aware (FASE 1): los usa este módulo y, a
// la vez, los expone para que los tests de integración guionen pasos sin depender
// directo de `synsema-llm`.
pub use synsema_llm::provider::{LlmStep, LlmStepResponse, ToolSpec};

use synsema_agents::builtins::register_agent_builtins;
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_agents::swarm::{AgentState, Swarm};
use synsema_capabilities::model::{
    capability_type_from_name, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::ast::Node;
use synsema_core::interpreter::{
    Control, Interpreter, RunResult, StepCatalogEntry, StepResult, SwarmHooks, TestOutcome,
};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{from_send, to_send, SendValue, SynValue};
use crate::serve::{val_to_global, rebuild_globals, GlobalVal};
use synsema_stdlib::cron::{register_cron_builtins, CronScheduler};
use synsema_stdlib::database::{register_database_builtins, DatabaseManager};
use synsema_stdlib::http::register_http_builtins;
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

pub(crate) const INTERP_STACK_SIZE: usize = 512 * 1024 * 1024;

/// Wiring común de un intérprete: capabilities + builtins seguros/stdlib + grant hook.
/// En modo no-secure se auto-conceden STDOUT, TIME y LLM; en secure/serve hay que
/// declararlas (`require llm` para las ops LLM). También instala el gate de las ops LLM.
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
        // Las ops LLM (reason/decide/analyze/generate) exigen la capability `llm`
        // (gateadas más abajo). En no-secure se auto-concede como stdout/time, por
        // ergonomía + retrocompat; en secure/serve hay que declarar `require llm`.
        caps.borrow_mut().grant(Capability::new(CapabilityType::Llm, None));
    }
    register_secure_builtins(interp, caps.clone());
    // Secretos/env: carga el `.env` (antes de evaluar require/serve) y registra
    // env/secret/reveal/bearer/crypto. Deny-by-default: env()/secret()/reveal() exigen
    // su capability incluso en modo no-secure (NO se auto-conceden como stdout/time).
    register_secret_builtins(interp, caps.clone(), Rc::new(EnvStore::load_default()));
    register_http_builtins(interp, caps.clone());
    // Hashing SHA (puro, sin capability): sha256/sha512 → bytes.
    synsema_stdlib::hashing::register_hash_builtins(interp);
    // cron/db/progress/memory: sus builtins clonan el Rc internamente → viven mientras
    // viva el intérprete.
    register_cron_builtins(interp, Rc::new(CronScheduler::new()));
    register_database_builtins(interp, Rc::new(RefCell::new(DatabaseManager::new())), caps.clone());
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
            // `require reveal` pelado concede reveal para CUALQUIER secret (grueso). Es
            // compat, pero desaconsejado: preferir `require reveal("NAME")` scopeado al
            // secret concreto (§6.5b). Warning a stderr, no bloquea.
            if ty == CapabilityType::Reveal && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require reveal` permits revealing ANY secret; \
                     scope it with `require reveal(\"NAME\")` (the name/label of the secret)"
                );
            }
            c.borrow_mut().grant(Capability::new(ty, scope.map(|s| s.to_string())));
        }
    }));
    // Gate de las ops LLM: cada reason/decide/analyze/generate exige la capability
    // `llm` (auto-concedida en no-secure arriba; en secure/serve la concede `require
    // llm`). Cierra sobre el mismo CapabilitySet → el audit_log registra cada chequeo.
    let caps_llm = caps.clone();
    interp.set_llm_cap_hook(Rc::new(move || {
        caps_llm
            .borrow_mut()
            .require(&Capability::new(CapabilityType::Llm, None), "llm operation")
            .map_err(|v| v.message)
    }));
    // Aislamiento de `sandbox`: al entrar guarda y VACÍA el CapabilitySet (deniega todo);
    // al salir, restaura. Stack para sandboxes anidados. Cubre TODOS los builtins gateados
    // de una sola vez (leen el mismo CapabilitySet vía el `caps` Rc compartido).
    #[allow(clippy::type_complexity)]
    let saved: Rc<RefCell<Vec<(HashSet<Capability>, HashSet<Capability>, Option<Rc<RefCell<CapabilitySet>>>)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let caps_sb = caps.clone();
    interp.set_sandbox_hook(Rc::new(move |entering| {
        let mut cs = caps_sb.borrow_mut();
        if entering {
            let g = std::mem::take(&mut cs.granted);
            let d = std::mem::take(&mut cs.denied);
            let p = cs.parent.take();
            saved.borrow_mut().push((g, d, p));
        } else if let Some((g, d, p)) = saved.borrow_mut().pop() {
            cs.granted = g;
            cs.denied = d;
            cs.parent = p;
        }
    }));
    // Aislamiento por-tool (least-privilege): cuando el loop despacha una tool con
    // `call_tool`, restringe el CapabilitySet a las caps DECLARADAS por la tool que el
    // agente YA tenía (∩ agente, SIN heredar el padre). Reusa el patrón save/restore del
    // sandbox-hook (stack para tools anidadas). Hace ENFORCED el `require` por-tool: una
    // tool no puede usar una capability que no declaró, aunque el agente la tenga.
    #[allow(clippy::type_complexity)]
    let saved_tool: Rc<RefCell<Vec<(HashSet<Capability>, HashSet<Capability>, Option<Rc<RefCell<CapabilitySet>>>)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let caps_tool = caps.clone();
    interp.set_tool_scope_hook(Rc::new(move |entering, declared: &[(String, Option<String>)]| {
        let mut cs = caps_tool.borrow_mut();
        if entering {
            // Las declaradas que el set ACTUAL (efectivo, incl. padre) ya satisface → la
            // tool no puede exceder al agente. `check` audita y camina la cadena de padres.
            let mut allowed: HashSet<Capability> = HashSet::new();
            for (name, scope) in declared {
                if let Some(ty) = capability_type_from_name(name) {
                    let cap = Capability::new(ty, scope.clone());
                    if cs.check(&cap, "tool-scope") {
                        allowed.insert(cap);
                    }
                }
            }
            // Guardar y REEMPLAZAR por sólo las permitidas, SIN padre → la tool no hereda
            // caps no declaradas (aunque el agente las tenga).
            let g = std::mem::replace(&mut cs.granted, allowed);
            let d = std::mem::take(&mut cs.denied);
            let p = cs.parent.take();
            saved_tool.borrow_mut().push((g, d, p));
        } else if let Some((g, d, p)) = saved_tool.borrow_mut().pop() {
            cs.granted = g;
            cs.denied = d;
            cs.parent = p;
        }
    }));
}

/// Cablea el provider LLM REAL (HTTP) si hay uno configurado. Resuelve los knobs con
/// precedencia `environ del proceso > .env (EnvStore protegido) > default` (DE-007): así la
/// clave puede vivir SOLO en el `.env` (gitignoreado) sin exportarla. Cablea AMBOS
/// callbacks: el de texto (reason/decide/analyze/generate) y el de paso tool-aware
/// (`llm_step`). Si no hay provider (offline): NO cablea nada → las ops LLM caen a los
/// placeholders descriptivos del core (`run` no se rompe). NO concede capabilities: el
/// gate `require llm` sigue idéntico (lo cableó `wire_common`).
///
/// `pub(crate)` para que `serve` también cablee el provider en sus intérpretes (DE-029):
/// sin esto, `llm_available()` era false bajo serve y reason/decide/generate/llm_step caían
/// a placeholders pese a `require llm` + `.env` con la clave.
pub(crate) fn wire_real_llm_provider(interp: &mut Interpreter) {
    // `load_default` lee `SYNSEMA_ENV_FILE`/`.env` (idempotente; honra `--env-file` y
    // `--no-env-file`). El environ del proceso sigue ganando sobre el `.env`.
    let store = EnvStore::load_default();
    let provider = match crate::llm_providers::provider_from_config(&store) {
        Some(p) => p,
        None => return,
    };
    // Callback de texto: arma `LLMRequest::new(op)` + `data["prompt"]` → `call().content`.
    let p_text = provider.clone();
    interp.set_llm_callback(Rc::new(move |op: &str, prompt: &str| {
        let mut req = LLMRequest::new(op);
        req.data.insert("prompt".to_string(), prompt.to_string());
        p_text.call(&req).content
    }));
    // Callback de paso tool-aware: arma `LLMRequest::new("step").with_tools(catalog)` +
    // `data["prompt"]`/`data["context"]` → `call_step` → mapea `LlmStep`→`StepResult`.
    interp.set_llm_step_callback(Rc::new(
        move |prompt: &str, catalog: &[StepCatalogEntry], context: &str| {
            let mut req = LLMRequest::new("step").with_tools(
                catalog
                    .iter()
                    .map(|e| ToolSpec {
                        name: e.name.clone(),
                        description: e.description.clone(),
                        params: e.params.clone(),
                    })
                    .collect(),
            );
            req.data.insert("prompt".to_string(), prompt.to_string());
            req.data.insert("context".to_string(), context.to_string());
            let r = provider.call_step(&req);
            match r.step {
                LlmStep::Final(t) => StepResult::Final { text: t, tokens: r.tokens_used },
                LlmStep::ToolCall { name, args } => {
                    StepResult::Tool { name, args, tokens: r.tokens_used }
                }
            }
        },
    ));
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

/// Corre el main. Si `swarm` es `Some`, cablea sus hooks en el intérprete principal
/// (agente "main") → cada `spawn` corre en su propio hilo aislado (camino de
/// `synsema run`, DE-011). Con `None`, comportamiento de un solo hilo (lo que usa
/// `conform` y los tests de `run_source`): `spawn` cae al fallback in-process.
///
/// Nota: el main NO recibe `log_hook` (a diferencia de `setup_swarm_interpreter`), para
/// que su salida vaya solo a `output` y el CLI la imprima una sola vez. Los agentes sí
/// transmiten su `log`/`print` en tiempo real (prefijo `[id]`).
fn run_inner(
    source: &str,
    filename: &str,
    secure: bool,
    swarm: Option<Arc<Swarm>>,
    live_output: bool,
) -> RunResult {
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
            // Salida en vivo sólo en `run` interactivo; en conform/test la salida se colecta
            // (flush/read_line no drenan a stdout). Ver DE-019.
            interp.live_output = live_output;
            let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
            let progress = Rc::new(RefCell::new(ProgressManager::new()));
            let memory = Rc::new(RefCell::new(AgentMemory::new()));
            wire_common_with_state(&mut interp, &caps, secure, progress.clone(), memory.clone());
            // Conectividad LLM real: si hay provider por env, cablea texto + paso
            // tool-aware; offline (sin key) deja los placeholders del core.
            wire_real_llm_provider(&mut interp);

            // Swarm real (DE-011): los hooks de spawn/share/observe/signal/wait_for del
            // main van al swarm compartido → los agentes corren en hilos aislados.
            if let Some(sw) = swarm {
                wire_swarm_hooks(&mut interp, sw, "main");
            }

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

/// Abre la persistencia de estado para `filename` (None si es `<stdin>`). DE-031: la ruta
/// es **project-local** por default — `<dir-del-programa>/.synsema/state/<name>.db` — para
/// que el estado viva junto al proyecto, sea portable/gitignorable y NO colisione entre
/// proyectos distintos con el mismo nombre de archivo. Overrides (de mayor a menor
/// prioridad):
///   1. `SYNSEMA_STATE_DIR` — dir de estado explícito (absoluto o relativo al cwd).
///      Escape hatch; restaura el viejo global con `SYNSEMA_STATE_DIR=~/.synsema/state`.
///   2. project-local (default): el dir del archivo de programa.
///
/// Nombre de la DB: `SYNSEMA_STATE_NAME` si está (para que varios archivos de entrada del
/// mismo proyecto compartan UNA memoria), si no el `stem` del archivo. Si el dir elegido
/// no es escribible, cae al global `~/.synsema/state` con un warning (no rompe).
pub(crate) fn state_persistence_for(filename: &str) -> Option<crate::persistence::StatePersistence> {
    if filename == "<stdin>" {
        return None;
    }
    // Nombre de la DB.
    let name = std::env::var("SYNSEMA_STATE_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::path::Path::new(filename)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "default".to_string())
        });
    // Dir de estado: override explícito, o project-local (`<dir>/.synsema/state`).
    let dir = match std::env::var("SYNSEMA_STATE_DIR").ok().filter(|s| !s.is_empty()) {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let base = std::path::Path::new(filename)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            base.join(".synsema").join("state")
        }
    };
    // Crear el dir; si falla (read-only/permisos), fallback al global con warning.
    let dir = match std::fs::create_dir_all(&dir) {
        Ok(()) => dir,
        Err(e) => {
            let fallback = crate::persistence::home_state_dir();
            eprintln!(
                "warning: no se pudo crear el dir de estado '{}' ({}); usando '{}'",
                dir.display(),
                e,
                fallback.display()
            );
            let _ = std::fs::create_dir_all(&fallback);
            fallback
        }
    };
    let path = dir.join(format!("{}.db", name));
    crate::persistence::StatePersistence::open_path(&path).ok()
}

fn spawn_run(source: &str, filename: &str, secure: bool) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_inner(&src, &fname, secure, None, false))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec!["el motor abortó (probable desborde de stack nativo)".to_string()],
        })
}

/// Modo no-secure (default real): auto-concede STDOUT y TIME. Lo que usa `conform`.
/// Camino de un solo hilo: `spawn` corre el agente in-process (sin swarm).
pub fn run_source(source: &str, filename: &str) -> RunResult {
    spawn_run(source, filename, false)
}

/// Camino de `synsema run` (DE-011): cablea el swarm real → cada `spawn` corre en su
/// propio hilo con su intérprete (aislado), igual que `conform --swarm`/`serve`, pero con
/// la salida normal de `run` (no JSON). Un `raise` sin recover dentro de un agente queda
/// CONTENIDO (estado ERROR), no tumba el main ni trunca su salida.
///
/// Tras terminar el main, joinea todos los hilos de agentes (`wait_all`) y refleja sus
/// errores. Política de exit (DE-011): el resultado es `success=false` si el main falla
/// **o** si algún agente terminó en ERROR — sin perder la salida ya producida por el main.
/// Recolecta los agentes que terminaron en ERROR como líneas legibles
/// `Agent error [<id>]: <msg>` (para reflejarlos en el exit code + stderr de `run`).
fn collect_agent_errors(swarm: &Swarm) -> Vec<String> {
    swarm
        .agent_states()
        .into_iter()
        .filter(|(_, st)| *st == AgentState::Error)
        .map(|(id, _)| {
            let msg = swarm.agent_error(&id).unwrap_or_else(|| "agent error".to_string());
            format!("Agent error [{}]: {}", id, msg)
        })
        .collect()
}

pub fn run_program(source: &str, filename: &str) -> RunResult {
    let swarm = Arc::new(Swarm::new());
    let sw = swarm.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let mut result = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_inner(&src, &fname, false, Some(sw), true))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec!["el motor abortó (probable desborde de stack nativo)".to_string()],
        });

    // Joinea los agentes lanzados por el main; ya no hay nadie más que pueda spawnear.
    swarm.wait_all();

    // Refleja los agentes en ERROR (exit ≠0 + línea de error), sin tocar la salida del main.
    let agent_errors = collect_agent_errors(&swarm);
    if !agent_errors.is_empty() {
        result.success = false;
        result.errors.extend(agent_errors);
    }
    result
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

/// Como `run_program` pero capturando el diagnóstico rico del error del MAIN. Si `swarm`
/// es `Some`, los `spawn` corren en hilos aislados (DE-014): un error de agente NO se
/// propaga al main; lo refleja el caller tras `wait_all` (en `run_with_diagnostics`).
fn run_diag_inner(source: &str, filename: &str, swarm: Option<Arc<Swarm>>) -> DiagRun {
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
    // Camino de `run --explain` (interactivo): salida en vivo (DE-019).
    interp.live_output = true;
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    wire_common(&mut interp, &caps, false);
    // Swarm real (DE-014): mismos hooks que `run` → los agentes corren aislados y un
    // `raise` de agente no aborta el main ni trunca su diagnóstico.
    if let Some(sw) = swarm {
        wire_swarm_hooks(&mut interp, sw, "main");
    }
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

/// Corre un programa y devuelve diagnósticos ricos en caso de error (capa 9). Cablea el
/// swarm real (DE-014): los errores de agente quedan aislados (no abortan el main) y se
/// reflejan tras `wait_all` como líneas `Agent error [<id>]` + `success=false`, igual que
/// `run_program`. El diagnóstico rico sigue siendo el del error del MAIN.
pub fn run_with_diagnostics(source: &str, filename: &str) -> DiagRun {
    let swarm = Arc::new(Swarm::new());
    let sw = swarm.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let mut run = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_diag_inner(&src, &fname, Some(sw)))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|_| DiagRun {
            result: RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] },
            diagnostics: Vec::new(),
        });

    swarm.wait_all();
    let agent_errors = collect_agent_errors(&swarm);
    if !agent_errors.is_empty() {
        run.result.success = false;
        run.result.errors.extend(agent_errors);
    }
    run
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

/// Host-config de test: corre con un callback de texto que GRABA `(op, prompt)` de cada
/// op LLM (reason/decide/analyze/generate) y responde `"ok"`. Devuelve los pares grabados
/// junto al resultado — para aseverar que el prompt threadea su contexto (`with`/`given`)
/// sin pegarle a la red.
pub fn run_capturing_llm(source: &str, filename: &str) -> (RunResult, Vec<(String, String)>) {
    let captured: Arc<std::sync::Mutex<Vec<(String, String)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap_outer = captured.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let result = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let cap = captured.clone();
                interp.set_llm_callback(Rc::new(move |op: &str, prompt: &str| {
                    cap.lock().unwrap().push((op.to_string(), prompt.to_string()));
                    "ok".to_string()
                }));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] });
    let pairs = cap_outer.lock().unwrap().clone();
    (result, pairs)
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
                // El mock keyea por `op` e ignora el prompt (retrocompat de los tests).
                interp.set_llm_callback(Rc::new(move |op: &str, _prompt: &str| {
                    provider.call(&LLMRequest::new(op)).content
                }));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|_| RunResult { success: false, output: Vec::new(), errors: vec!["el motor abortó".to_string()] })
}

/// Corre con un proveedor LLM tool-aware GUIONADO (host-config, FASE 1): cablea
/// `llm_step` a un `MockProvider::scripted` determinista (sin red). Espejo de
/// `run_with_llm`. Para los tests del loop seguro en-lenguaje. Camino no-secure: la
/// capability `llm` se auto-concede (igual que `run`); en secure/serve hay que
/// declarar `require llm`.
pub fn run_with_llm_steps(source: &str, filename: &str, steps: Vec<LlmStepResponse>) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let provider = Arc::new(MockProvider::scripted(steps));
                interp.set_llm_step_callback(Rc::new(
                    move |prompt: &str, catalog: &[StepCatalogEntry], context: &str| {
                        let mut req = LLMRequest::new("step").with_tools(
                            catalog
                                .iter()
                                .map(|e| ToolSpec {
                                    name: e.name.clone(),
                                    description: e.description.clone(),
                                    params: e.params.clone(),
                                })
                                .collect(),
                        );
                        req.data.insert("prompt".to_string(), prompt.to_string());
                        req.data.insert("context".to_string(), context.to_string());
                        let r = provider.call_step(&req);
                        match r.step {
                            LlmStep::Final(t) => StepResult::Final { text: t, tokens: r.tokens_used },
                            LlmStep::ToolCall { name, args } => {
                                StepResult::Tool { name, args, tokens: r.tokens_used }
                            }
                        }
                    },
                ));
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
    let wait_for: Rc<dyn Fn(&str, Option<f64>) -> Option<SynValue>> = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |sig_name, timeout| {
            // Timeout configurable (Batch 7): segundos del `wait_for ... timeout <expr>`, o
            // 30 s por defecto (G1). Clamp [0, 3600] como `sleep`.
            let secs = timeout.unwrap_or(30.0).clamp(0.0, 3600.0);
            // Estado WAITING mientras bloquea (no-op si `n` no es agente registrado, p.ej. "main").
            sw.set_state(&n, AgentState::Waiting);
            let sig = sw.wait_for_signal(sig_name, Duration::from_secs_f64(secs));
            sw.set_state(&n, AgentState::Working);
            sig.and_then(|s| s.data).map(|d| from_send(&d))
        })
    };
    let spawn: Rc<
        dyn Fn(&str, Vec<Node>, Vec<(String, SynValue)>, Vec<(String, SynValue)>) -> Result<String, Control>,
    > = {
        let sw = swarm.clone();
        Rc::new(move |agent, body, args, globals| {
            let send_args: Vec<(String, SendValue)> =
                args.iter().map(|(k, v)| (k.clone(), to_send(v))).collect();
            // Convertir el snapshot de globales del llamador a GlobalVal (preserva tasks).
            let global_snap: Arc<Vec<(String, GlobalVal)>> = Arc::new(
                globals.iter().map(|(k, v)| (k.clone(), val_to_global(v))).collect(),
            );
            Ok(spawn_agent(sw.clone(), agent.to_string(), body, send_args, global_snap))
        })
    };

    interp.set_swarm_hooks(SwarmHooks { share, observe, signal, wait_for, spawn });
}

/// Crea un intérprete con el wiring común + los hooks del swarm.
/// El `log_hook` manda los `log` del agente a stdout del proceso principal en tiempo
/// real — así los agentes no son silenciosos durante el desarrollo.
fn setup_swarm_interpreter(swarm: Arc<Swarm>, agent_name: &str) -> Interpreter {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("agent")));
    wire_common(&mut interp, &caps, false);
    wire_swarm_hooks(&mut interp, swarm, agent_name);
    let name = agent_name.to_string();
    interp.log_hook = Some(Arc::new(move |line: &str| {
        println!("[{}] {}", name, line);
    }));
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
    globals: Arc<Vec<(String, GlobalVal)>>,
) -> String {
    let instance_id = swarm.register_new_agent(&agent_name);
    let sw = swarm.clone();
    let id = instance_id.clone();
    let handle = std::thread::Builder::new()
        .name(id.clone())
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            let mut interp = setup_swarm_interpreter(sw.clone(), &id);
            // Restaurar tareas y valores del top-level para que el agente
            // los pueda llamar directamente sin necesitar HTTP.
            rebuild_globals(&mut interp, &globals);
            // Los spawn_args sobreescriben cualquier global con el mismo nombre.
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
