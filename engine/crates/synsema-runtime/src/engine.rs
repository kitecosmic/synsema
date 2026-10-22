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

use synsema_core::types::SynMap;
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

use synsema_agents::builtins::{
    register_agent_builtins, register_serve_memory_builtins, register_serve_progress_builtins,
    register_shared_rules_builtins, MemoryGate,
};
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_agents::swarm::{AgentState, Swarm};
use synsema_capabilities::model::{
    capability_type_from_name, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::ast::Node;
use synsema_core::interpreter::{
    Control, Interpreter, RunResult, RuntimeError, StepCatalogEntry, StepResult, SwarmHooks, TestOutcome,
};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{from_send, to_send, SendValue, SynValue};
use crate::serve::{val_to_global_shared, rebuild_globals, GlobalVal};
use synsema_stdlib::cron::{register_cron_builtins, CronScheduler};
use synsema_stdlib::database::{register_database_builtins, DatabaseManager};
use synsema_stdlib::http::register_http_builtins;
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

pub(crate) const INTERP_STACK_SIZE: usize = 512 * 1024 * 1024;

// =========================================================
// memoria declarada (DB-M1): identidad + stores compartidos
// =========================================================

/// Contexto de la memoria DECLARADA de un programa (`require memory("nombre")`).
/// La declaración es la identidad (decisión #3): un solo `.db` (`<nombre>.db`),
/// stores compartidos entre TODOS los contextos de ejecución del programa (top-level,
/// agentes swarm, workers de `parallel_map`, ticks de cron, handlers de serve) y
/// persistencia on-write. Todo `Arc` (Send+Sync) → cruza hilos sin copias divergentes.
#[derive(Clone)]
pub(crate) struct MemoryCtx {
    /// Nombre declarado (ya validado, G-6). Es el scope de la capability `memory`.
    pub(crate) name: String,
    pub(crate) memory: std::sync::Arc<std::sync::Mutex<AgentMemory>>,
    pub(crate) progress: std::sync::Arc<std::sync::Mutex<ProgressManager>>,
    pub(crate) on_write_mem: std::sync::Arc<dyn Fn(&AgentMemory) + Send + Sync>,
    pub(crate) on_write_prog: std::sync::Arc<dyn Fn(&ProgressManager) + Send + Sync>,
    /// Lo que `run_program` necesita de la memoria de ESTA corrida (`None` si no persiste).
    pub(crate) child: Option<ChildState>,
}

/// v0.6.45 (ronda 5, M1 y B1) — el estado de una corrida, visto desde `run_program`: la carpeta
/// ABSOLUTA donde vive su `.db` (el hijo la recibe como `SYNSEMA_STATE_DIR`) y cómo recargar la base
/// cuando el hijo vuelve. Es de la corrida, no del proceso: `synsema test`/`conform` corren muchos
/// programas en un proceso y cada uno pasa la suya (antes un `OnceLock` la fijaba el primero).
#[derive(Clone)]
pub(crate) struct ChildState {
    pub(crate) dir: std::path::PathBuf,
    /// Trae lo que el hijo escribió en la base compartida y sube el contador de ids (si no, el
    /// próximo `remember` del padre reusaba el id de una entrada del hijo y la pisaba).
    pub(crate) reload: Arc<dyn Fn() + Send + Sync>,
}

/// La memoria declarada tal como viaja por `serve` y por los ticks de cron (que arman sus
/// intérpretes en otros hilos, desde argumentos `Send`): el nombre y, si persiste, su `ChildState`.
/// Ronda 5 (revisión): antes los workers leían el `ChildState` de un static del proceso, y con dos
/// `serve` en un proceso el hijo de uno guardaba en la carpeta del otro.
#[derive(Clone)]
pub(crate) struct MemName {
    pub(crate) name: String,
    pub(crate) child: Option<ChildState>,
}

/// El `ChildState` de una memoria con base en disco. Mismo orden de locks que los `on_write`
/// (el store primero, después la base).
pub(crate) fn child_state_for(
    dir: std::path::PathBuf,
    sp: Arc<std::sync::Mutex<crate::persistence::StatePersistence>>,
    memory: Arc<std::sync::Mutex<AgentMemory>>,
    progress: Arc<std::sync::Mutex<ProgressManager>>,
) -> ChildState {
    let reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Ok(mut m) = memory.lock() {
            if let Ok(p) = sp.lock() {
                p.reload_memory(&mut m);
            }
        }
        if let Ok(mut g) = progress.lock() {
            if let Ok(p) = sp.lock() {
                p.reload_progress(&mut g);
            }
        }
    });
    ChildState { dir, reload }
}

/// Identidad declarada resuelta: nombre + persistencia abierta (None si el `.db`
/// no pudo abrirse — se degrada a memoria compartida en-proceso, sin romper).
pub(crate) struct DeclaredState {
    pub(crate) name: String,
    pub(crate) persistence: Option<crate::persistence::StatePersistence>,
    /// La carpeta (absoluta) del `.db` abierto; `None` sin persistencia.
    pub(crate) dir: Option<std::path::PathBuf>,
}

/// Sugerencia de nombre para el error/warning (decisión #8): el stem del archivo,
/// saneado a `[a-zA-Z0-9_-]` para que la línea sugerida sea válida tal cual.
pub(crate) fn suggested_memory_name(filename: &str) -> String {
    if filename == "<stdin>" {
        return "my-agent".to_string();
    }
    let stem = std::path::Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let s: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '-' })
        .collect();
    if s.is_empty() { "my-agent".to_string() } else { s }
}

/// Gate de memoria SIN declaración: toda la familia de estado persistente falla con
/// el error de capability + el fix exacto (decisión #2/#8). No se crea ningún archivo
/// (G-1): este gate corta antes de tocar los stores.
pub(crate) fn undeclared_memory_gate(suggest: String) -> MemoryGate {
    Rc::new(move || {
        Err(RuntimeError::new(format!(
            "Capability not granted: memory. Persistent agent state (remember/recall, rules, progress) requires a declared memory — the declared name identifies its .db file. Add: require memory(\"{}\") at the top of the program",
            suggest
        )))
    })
}

/// Gate de memoria CON declaración: chequea `memory("<nombre>")` contra el
/// capabilitySet VIVO del contexto — así `sandbox` (set vaciado), `call_tool`
/// (intersección declarada) y el techo del host (`--sandbox`/`--cap-set`) lo
/// deniegan por la misma maquinaria que el resto de capabilities (G-2).
pub(crate) fn declared_memory_gate(caps: Rc<RefCell<CapabilitySet>>, name: String) -> MemoryGate {
    Rc::new(move || {
        caps.borrow_mut()
            .require(
                &Capability::new(CapabilityType::Memory, Some(name.clone())),
                "memory builtin",
            )
            .map_err(|v| v.into_error())
    })
}

/// Gate según haya o no contexto declarado. `suggest` alimenta el mensaje del caso
/// sin declaración.
pub(crate) fn memory_gate_for(
    caps: &Rc<RefCell<CapabilitySet>>,
    mem: Option<&MemoryCtx>,
    suggest: &str,
) -> MemoryGate {
    match mem {
        Some(ctx) => declared_memory_gate(caps.clone(), ctx.name.clone()),
        None => undeclared_memory_gate(suggest.to_string()),
    }
}

/// Escanea las declaraciones `require memory("<nombre>")` del TOP-LEVEL del programa
/// (misma doctrina que el scan de requires de `call_tool`: sólo literales top-level;
/// un require anidado/dinámico no define identidad). Valida G-6 y exige un único
/// nombre (decisión #3). `Ok(None)` = programa sin memoria declarada.
pub(crate) fn declared_memory_name(
    statements: &[Node],
) -> Result<Option<String>, String> {
    use synsema_core::ast::NodeKind;
    let mut found: Option<String> = None;
    for stmt in statements {
        if let NodeKind::RequireStatement { capability, scope, .. } = &stmt.kind {
            if capability != "memory" {
                continue;
            }
            // El parser ya rechaza `require memory` sin scope; acá sólo cuentan los
            // scopes LITERALES (la identidad no puede ser dinámica).
            if let Some(scope_node) = scope {
                if let NodeKind::TextLiteral { value } = &scope_node.kind {
                    synsema_capabilities::model::validate_memory_name(value)?;
                    match &found {
                        Some(prev) if prev != value => {
                            return Err(format!(
                                "Multiple memory declarations: require memory(\"{}\") and require memory(\"{}\"). A program has exactly ONE declared memory (the declared name IS its identity) — keep one declaration",
                                prev, value
                            ));
                        }
                        _ => found = Some(value.clone()),
                    }
                }
            }
        }
    }
    Ok(found)
}

/// Resuelve la identidad declarada del programa (DB-M1, §3.2). Con declaración:
/// abre `<dir>/.synsema/state/<nombre>.db` (`SYNSEMA_STATE_DIR` lo pisa; el dir se
/// crea SOLO acá). Sin declaración: cero archivos (G-1) + chequeo de transición G-4
/// (si existe el viejo `<stem>.db`, warning fuerte con el fix — nada se carga ni se
/// escribe). `SYNSEMA_STATE_NAME` queda deprecada (decisión #6): warning si está
/// seteada; con declaración se ignora. `ceiling` = techo del host (`--sandbox`/
/// `--cap-set`): si NO cubre `memory("<nombre>")`, no se crea ni abre nada en disco
/// (los builtins ya fallan con el error de capability; un `.db` vacío bajo un techo
/// que deniega la memoria sería el efecto colateral que el techo debía impedir).
pub(crate) fn resolve_declared_state(
    statements: &[Node],
    filename: &str,
    ceiling: Option<&[Capability]>,
) -> Result<Option<DeclaredState>, String> {
    let declared = declared_memory_name(statements)?;
    let legacy_name = std::env::var("SYNSEMA_STATE_NAME").ok().filter(|s| !s.is_empty());
    match declared {
        None => {
            // G-4: transición ruidosa-no-rota. Localizar dónde habría vivido la DB del
            // mundo viejo (stem + overrides de env) SIN crear nada; si existe, avisar.
            if filename != "<stdin>" {
                let stem = std::path::Path::new(filename)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "default".to_string());
                let old_name = legacy_name.clone().unwrap_or_else(|| stem.clone());
                let old_dir = match std::env::var("SYNSEMA_STATE_DIR").ok().filter(|s| !s.is_empty()) {
                    Some(d) => std::path::PathBuf::from(d),
                    None => std::path::Path::new(filename)
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join(".synsema")
                        .join("state"),
                };
                let old_db = old_dir.join(format!("{}.db", old_name));
                if old_db.is_file() {
                    eprintln!(
                        "synsema: warning: found existing persistent state at '{}' but this program declares no memory.\n\
                         Persistent state is now opt-in: nothing was loaded and nothing will be written.\n\
                         To keep using this state, add this line at the top of the program:\n\
                         \x20   require memory(\"{}\")\n\
                         (the declared name maps to '<name>.db' in the same directory — keep the file if the name matches, or rename it)",
                        old_db.display(),
                        suggested_memory_name(filename)
                    );
                }
            }
            Ok(None)
        }
        Some(name) => {
            if legacy_name.is_some() {
                eprintln!(
                    "synsema: warning: SYNSEMA_STATE_NAME is deprecated and ignored — the declared name in require memory(\"{}\") is the identity",
                    name
                );
            }
            // Perfil puro (`--profile pure`): "sin filesystem" también cubre la memoria
            // declarada — la identidad existe pero SIN disco (in-memory para esta corrida),
            // igual que bajo wasm. El gate de la capability sigue mandando aparte.
            if crate::host::profile() == crate::host::Profile::Pure {
                return Ok(Some(DeclaredState { name, persistence: None, dir: None }));
            }
            // Techo del host: memoria declarada pero denegada por `--cap-set`/`--sandbox`
            // → identidad sin disco (cero archivos; el uso falla con el error de siempre).
            if let Some(ceil) = ceiling {
                let want = Capability::new(CapabilityType::Memory, Some(name.clone()));
                if !ceil.iter().any(|c| c.covers(&want)) {
                    return Ok(Some(DeclaredState { name, persistence: None, dir: None }));
                }
            }
            // Ronda 5 (M1): un hijo de `run_program` guarda donde le dice el padre
            // (`SYNSEMA_STATE_DIR`); si el padre no se lo dio es porque el padre no persiste, y el
            // hijo tampoco: si no, caía junto a su `filename`, relativo al `cwd` que elige el programa.
            if crate::run_program::is_child() && std::env::var("SYNSEMA_STATE_DIR").ok().filter(|s| !s.is_empty()).is_none() {
                return Ok(Some(DeclaredState { name, persistence: None, dir: None }));
            }
            // Dir de estado: override explícito, o project-local (`<dir>/.synsema/state`).
            // `<stdin>` no tiene dir de programa: sin `SYNSEMA_STATE_DIR`, la memoria
            // declarada queda compartida en-proceso pero SIN disco (no inventamos una
            // ubicación; con el override sí hay una ubicación bien definida) — degradar
            // con AVISO: el programa cree que persiste y no.
            let dir = match std::env::var("SYNSEMA_STATE_DIR").ok().filter(|s| !s.is_empty()) {
                Some(d) => std::path::PathBuf::from(d),
                None if filename == "<stdin>" => {
                    eprintln!(
                        "synsema: warning: memory \"{}\" is declared but the program has no file location (<stdin>): state lives in memory for this run only and will NOT persist. Run from a .syn file, or set SYNSEMA_STATE_DIR, to persist it",
                        name
                    );
                    return Ok(Some(DeclaredState { name, persistence: None, dir: None }));
                }
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
                    // Ronda 4 (revisión): sin `HOME`/`USERPROFILE` el respaldo quedaba RELATIVO
                    // (`.synsema/state`) y se creaba en el cwd, que en un hijo de `run_program` elige
                    // el programa. Sin un home absoluto, la memoria vive sólo en esta corrida.
                    if !fallback.is_absolute() {
                        eprintln!(
                            "synsema: warning: could not create state dir '{}' ({}) and there is no home directory: memory \"{}\" lives in memory for this run only and will NOT persist",
                            dir.display(),
                            e,
                            name
                        );
                        return Ok(Some(DeclaredState { name, persistence: None, dir: None }));
                    }
                    eprintln!(
                        "synsema: warning: could not create state dir '{}' ({}); using '{}'",
                        dir.display(),
                        e,
                        fallback.display()
                    );
                    let _ = std::fs::create_dir_all(&fallback);
                    fallback
                }
            };
            let path = dir.join(format!("{}.db", name));
            // Fallo al abrir (corrupto, lockeado, permisos): degradar con AVISO —
            // la memoria funciona este run pero NO persiste (doctrina: las fallas no
            // rompen la cadena del agente, pero siempre avisan).
            let persistence = match crate::persistence::StatePersistence::open_path(&path) {
                Ok(p) => Some(p),
                Err(e) => {
                    eprintln!(
                        "synsema: warning: could not open state db '{}' ({}): memory \"{}\" will work for this run but will NOT persist. Repair or remove the file to restore persistence",
                        path.display(),
                        e,
                        name
                    );
                    None
                }
            };
            let dir = persistence.as_ref().and_then(|_| {
                if dir.is_absolute() {
                    Some(dir)
                } else {
                    std::env::current_dir().ok().map(|c| c.join(dir))
                }
            });
            Ok(Some(DeclaredState { name, persistence, dir }))
        }
    }
}

/// Construye el `MemoryCtx` de un `DeclaredState`: stores compartidos, carga inicial
/// desde el `.db` y callbacks on-write (misma pareja `save_memory_only`/
/// `save_progress_only` que serve — tablas distintas, sin pisarse, DE-028).
pub(crate) fn build_memory_ctx(rs: DeclaredState) -> MemoryCtx {
    use std::sync::{Arc, Mutex};
    let memory = Arc::new(Mutex::new(AgentMemory::new()));
    let progress = Arc::new(Mutex::new(ProgressManager::new()));
    let sp: Option<Arc<Mutex<crate::persistence::StatePersistence>>> =
        rs.persistence.map(|p| Arc::new(Mutex::new(p)));
    if let Some(p) = &sp {
        p.lock().unwrap().load_into(&mut memory.lock().unwrap(), &mut progress.lock().unwrap());
    }
    // Ronda 5 (B1): un hijo de `run_program` que comparte la base marca sus ids.
    if sp.is_some() && crate::run_program::is_child() {
        memory.lock().unwrap().set_id_tag(format!("p{}", std::process::id()));
    }
    let child = match (&sp, rs.dir) {
        (Some(p), Some(dir)) => Some(child_state_for(dir, p.clone(), memory.clone(), progress.clone())),
        _ => None,
    };
    let on_write_mem: Arc<dyn Fn(&AgentMemory) + Send + Sync> = {
        let sp = sp.clone();
        Arc::new(move |mem: &AgentMemory| {
            if let Some(p) = &sp {
                if let Ok(guard) = p.lock() {
                    guard.save_memory_only(mem);
                }
            }
        })
    };
    let on_write_prog: Arc<dyn Fn(&ProgressManager) + Send + Sync> = {
        let sp = sp.clone();
        Arc::new(move |prog: &ProgressManager| {
            if let Some(p) = &sp {
                if let Ok(guard) = p.lock() {
                    guard.save_progress_only(prog);
                }
            }
        })
    };
    MemoryCtx { name: rs.name, memory, progress, on_write_mem, on_write_prog, child }
}

/// Resolución + contexto en un paso (camino común de run/test/diag/swarm).
/// `Err` = declaración inválida (G-6) o múltiple (decisión #3) → error de arranque.
pub(crate) fn memory_ctx_for(
    statements: &[Node],
    filename: &str,
    ceiling: Option<&[Capability]>,
) -> Result<Option<MemoryCtx>, String> {
    Ok(resolve_declared_state(statements, filename, ceiling)?.map(build_memory_ctx))
}

/// Wiring común de un intérprete: capabilities + builtins seguros/stdlib + grant hook.
/// En modo no-secure se auto-conceden STDOUT, TIME y LLM; en secure/serve hay que
/// declararlas (`require llm` para las ops LLM). También instala el gate de las ops LLM.
/// `mem` es el contexto de memoria DECLARADA (DB-M1): con `Some`, los builtins de la
/// familia de estado persistente van a los stores compartidos (gateados por
/// `memory("<nombre>")`); con `None`, fallan con el error de capability + sugerencia.
pub(crate) fn wire_common(
    interp: &mut Interpreter,
    caps: &Rc<RefCell<CapabilitySet>>,
    secure: bool,
    mem: Option<&MemoryCtx>,
    suggest: &str,
) {
    let gate = memory_gate_for(caps, mem, suggest);
    wire_common_with_state(
        interp,
        caps,
        secure,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
        gate.clone(),
        mem.cloned(),
    );
    // Con memoria declarada: sobrescribir la familia per-intérprete con los stores
    // COMPARTIDOS (misma maquinaria que serve, G-9) → una sola verdad + persistencia
    // on-write en todos los contextos. Las REGLAS también (misma tabla del `.db`);
    // serve NO pasa por acá para las reglas (mantiene el snapshot per-worker, gap-15).
    if let Some(ctx) = mem {
        register_serve_memory_builtins(interp, ctx.memory.clone(), ctx.on_write_mem.clone(), gate.clone());
        register_serve_progress_builtins(interp, ctx.progress.clone(), ctx.on_write_prog.clone(), gate.clone());
        register_shared_rules_builtins(interp, ctx.memory.clone(), ctx.on_write_mem.clone(), gate);
    }
}

/// Las cuatro listas de clasificación de etiquetas viven en `synsema_stdlib::label_lists` desde
/// v0.6.45 (D1): el wasm (`synsema-wasm`) registra sus sumideros desde la MISMA lista que el nativo.
pub use synsema_stdlib::label_lists::{
    LABEL_OS_READ_BUILTINS, LABEL_PURE_BUILTINS, LABEL_SINKS_SERVE_ONLY, LABEL_SINK_BUILTINS,
};

/// Todos los builtins registrados en el wiring NATIVO (un intérprete de `run`), ordenados.
/// Es la fuente de verdad del anti-rot `every_effectful_family_is_a_label_sink`: la lista de
/// sumideros se cruza contra lo que el motor registra DE VERDAD, no contra sí misma.
pub fn registered_builtin_names() -> Vec<String> {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("probe")));
    wire_common(&mut interp, &caps, false, None, "probe");
    let env = interp.global_env.borrow();
    let mut names: Vec<String> = env
        .bindings
        .iter()
        .filter(|(_, v)| matches!(v, synsema_core::types::SynValue::Builtin(_)))
        .map(|(k, _)| k.to_string())
        .collect();
    names.sort();
    names
}

/// `(nombre, param_count)` de cada builtin del wiring nativo: el anti-rot de la aridad
/// estricta (v0.6.29) exige que todo variádico (`-1`) esté en `BUILTIN_ARITY`.
pub fn registered_builtin_arities() -> Vec<(String, i32)> {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("probe")));
    wire_common(&mut interp, &caps, false, None, "probe");
    let env = interp.global_env.borrow();
    let mut out: Vec<(String, i32)> = env
        .bindings
        .iter()
        .filter_map(|(k, v)| match v {
            // El nombre del BUILTIN, no el del binding: un alias deprecado comparte el del nuevo.
            synsema_core::types::SynValue::Builtin(b) => { let _ = k; Some((b.name.clone(), b.param_count)) }
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// ¿Existe un builtin con ese nombre en el wiring nativo? (anti-rot de `LABEL_SINK_BUILTINS`).
pub fn builtin_exists(name: &str) -> bool {
    thread_local! {
        static NAMES: std::collections::HashSet<String> = {
            let mut interp = Interpreter::new();
            let caps = Rc::new(RefCell::new(CapabilitySet::new("probe")));
            wire_common(&mut interp, &caps, false, None, "probe");
            let set = interp.global_env.borrow().bindings.keys().map(|k| k.to_string()).collect();
            set
        };
    }
    NAMES.with(|n| n.contains(name))
}

/// Igual que `wire_common` pero con handles de progress/memory provistos por el caller
/// (serve pre-carga las reglas del top-level en su AgentMemory per-worker) y el gate de
/// memoria explícito. `mem` (si hay) viaja a los ejecutores de cron y a los workers de
/// `parallel_map` para que TODOS los contextos compartan la misma memoria declarada.
pub(crate) fn wire_common_with_state(
    interp: &mut Interpreter,
    caps: &Rc<RefCell<CapabilitySet>>,
    secure: bool,
    progress: Rc<RefCell<ProgressManager>>,
    memory: Rc<RefCell<AgentMemory>>,
    mem_gate: MemoryGate,
    mem: Option<MemoryCtx>,
) {
    let child_state = mem.as_ref().and_then(|m| m.child.clone());
    // Etiquetas de flujo por proceso (`--labels`, `serve --attested`). Se fijan
    // acá porque TODOS los intérpretes del runtime (run, serve por request, agentes, cron,
    // Parallel_map) pasan por este wiring: un intérprete sin etiquetas en un proceso con
    // etiquetas sería un agujero, no un knob.
    if crate::host::labels() {
        interp.set_labels(true);
        // Todo builtin con EFECTO es un sumidero público. Un valor privado en
        // cualquiera de sus argumentos, o la llamada bajo una rama que dependió de datos privados,
        // Es `label_violation` ANTES de ejecutar el efecto (el archivo no se escribe, el socket no
        // recibe nada). Los del core (`share`/`signal`/`send`/`reason`/... y `CORE_SINK_BUILTINS`)
        // Ya lo hacen; éstos son los del stdlib/agents/runtime. Fail-closed: un nombre que no
        // exista en este proceso se ignora (registrar de más no cuesta nada).
        for name in LABEL_SINK_BUILTINS.iter().chain(synsema_core::interpreter::CORE_SINK_BUILTINS.iter()) {
            interp.register_label_sink(name);
        }
        // Bajo `run/test --labels` el registro de `declassify` no se veía en ningún
        // lado (sin `log_hook` sólo lo drena el host wasm). Si nadie instaló un hook (serve pone
        // El suyo por worker), cada `declassify` sale por stderr como `[INF] declassify: …`; las
        // demás líneas del hook (print/log/show ya van a `output`) se ignoran para no duplicarlas.
        if interp.log_hook.is_none() {
            interp.log_hook = Some(Arc::new(|line: &str| {
                if line.starts_with("[INF] declassify:") {
                    eprintln!("{}", line);
                }
            }));
            // Sólo observa: `log` sigue yendo a stderr bajo `synsema run`.
            interp.log_hook_observes_only = true;
        }
    }
    if !secure {
        caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Stdout, None));
        caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Time, None));
        // Las ops LLM (reason/decide/analyze/generate) exigen la capability `llm`
        // (gateadas más abajo). En no-secure se auto-concede como stdout/time, por
        // ergonomía + retrocompat; en secure/serve hay que declarar `require llm`.
        caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Llm, None));
        // `judge` (System One) es capability PROPIA: misma ergonomía que `llm` en no-secure,
        // pero en secure/serve hay que declarar `require judge` (clasificar y generar son
        // derechos distintos).
        caps.borrow_mut().grant_ambient(Capability::new(CapabilityType::Judge, None));
    }
    // v0.6.46 (E3): `declassify` es una capability (D3, el `unsafe` de Rust): de ambiente sin
    // techo, también bajo secure/serve; con techo, sólo lo que el techo nombra.
    synsema_stdlib::captoken::install_declassify_hook(interp, caps.clone());
    // v0.6.46 (E5): datos privados hacia el modelo, sólo con `llm=P@<host>` en el techo. El host
    // sale del provider cableado en ESTE intérprete al momento de la llamada (se cablea después,
    // y uno que se recarga puede cambiar de host); sin provider, nada sale del proceso: `local`.
    {
        let cell = provider_cell(interp);
        synsema_stdlib::captoken::install_llm_data_hook(
            interp,
            caps.clone(),
            Rc::new(move |judge| {
                let w = cell.borrow();
                let ep = if judge {
                    w.judge.as_ref().map(|(p, _)| p.endpoint())
                } else {
                    w.llm.as_ref().map(|p| p.endpoint())
                };
                ep.unwrap_or_else(|| "local".to_string())
            }),
        );
    }
    // v0.6.46 (E3b): los módulos de confianza del host (`--trusted`), para `use "trusted:…"`.
    if let Some(t) = crate::host::trusted() {
        synsema_stdlib::captoken::install_trusted_modules(interp, caps.clone(), &t.modules, t.ceiling.clone());
    }
    register_secure_builtins(interp, caps.clone());
    // Secretos/env: carga el `.env` (antes de evaluar require/serve) y registra
    // env/secret/reveal/bearer/crypto. Deny-by-default: env()/secret()/reveal() exigen
    // su capability incluso en modo no-secure (NO se auto-conceden como stdout/time).
    let env_store = Rc::new(EnvStore::load_default());
    // Nombres que Synsema trata como SECRETOS: `run()`/`proc_spawn` los quitan del entorno
    // de un proceso hijo (cierra `run("printenv")` con `exec` pero sin `env`/`secret`).
    // = claves de proveedor LLM + secretos del humano + lo cargado del `.env`.
    {
        let mut sensitive: std::collections::HashSet<String> =
            crate::llm_providers::LLM_ENV_VARS.iter().map(|s| s.to_string()).collect();
        sensitive.extend(crate::llm_providers::HUMAN_ENV_VARS.iter().map(|s| s.to_string()));
        sensitive.extend(crate::judge_provider::JUDGE_ENV_VARS.iter().map(|s| s.to_string()));
        sensitive.extend(env_store.keys());
        interp.set_sensitive_env(sensitive);
    }
    register_secret_builtins(interp, caps.clone(), env_store);
    register_http_builtins(interp, caps.clone());
    // Hashing SHA + Keccak (puro, sin capability): sha256/sha512/keccak256/sha512_256 → bytes.
    synsema_stdlib::hashing::register_hash_builtins(interp);
    // Bits sobre enteros de 64 bits y `xor_bytes` (puro, v0.6.44).
    synsema_stdlib::bits::register_bit_builtins(interp);
    synsema_stdlib::encoding::register_encoding_builtins(interp);
    synsema_stdlib::headers::register_header_builtins(interp);
    synsema_stdlib::qr::register_qr_builtins(interp);
    synsema_stdlib::html::register_html_builtins(interp);
    // JSON del lenguaje (puro, sin capability): json_encode/json_for_script/json_decode.
    // Vivían dentro de register_database_builtins; ahora en json.rs para que existan
    // también en el perfil wasm (sin `native`).
    synsema_stdlib::json::register_json_builtins(interp);
    // v0.6.29 (DATOS-16): Parquet, bytes ↔ filas (puro; el archivo va por read_file_bytes/write_file).
    synsema_stdlib::parquet_io::register_parquet_builtins(interp);
    // Web auth (tanda web-auth): random_bytes/token/password_hash/password_verify/
    // jwt_sign/jwt_verify/totp/totp_verify. random_bytes/token GATEADOS por
    // `random` (la misma puerta deny-by-default de random()/random_int() — libres
    // la volverían decorativa); el resto puro sin capability (criterio
    // hmac_sha256). Registrados acá → existen en el intérprete principal Y en
    // los de serve/parallel/cron.
    synsema_stdlib::webauth::register_webauth_builtins(interp, caps.clone());
    // T2 (identidad): WebAuthn / passkeys — verificación pura del registro y la assertion.
    synsema_stdlib::webauthn::register_webauthn_builtins(interp);
    // T3/T4 (identidad): JCS (RFC 8785), did:key y pruebas W3C Data Integrity.
    synsema_stdlib::canonical::register_canonical_builtins(interp);
    synsema_stdlib::tools::register_tool_builtins(interp);
    // Linaje (DATOS-17): los resultados estructurados se hashean sobre su JSON canónico.
    interp.lineage_canonical = Some(Rc::new(|v: &synsema_core::types::SynValue| {
        match synsema_stdlib::canonical::canonical_json(v) {
            Ok(s) => Some((s.into_bytes(), "jcs")),
            // JCS no lleva enteros de más de 2^53: el JSON exacto de `json_encode`.
            Err(_) => Some((
                synsema_stdlib::json::dumps_syn(v).into_bytes(),
                "json",
            )),
        }
    }));
    synsema_stdlib::didkey::register_didkey_builtins(interp);
    synsema_stdlib::integrity::register_integrity_builtins(interp, caps.clone());
    synsema_stdlib::receipt::register_receipt_builtins(interp, caps.clone());
    // Identidad de agentes : firmas de request con perfil RFC 9421 pineado
    // (`http_sign` gateado por `sign(NAME)` + audit — la misma puerta que firmar
    // on-chain; `http_signature_verify` puro) y tokens de capacidad atenuables
    // (`captoken_*`, puros: el poder vive en la clave raíz sellada, y lo que un
    // token concede lo sigue gateando el CapabilitySet de quien lo usa).
    synsema_stdlib::httpsig::register_httpsig_builtins(interp, caps.clone());
    synsema_stdlib::captoken::register_captoken_builtins(interp, caps.clone());
    // OIDC de terceros (RS256/ES256 + JWKS): "login with Google" y workload
    // identity de nube. El fetch del JWKS es red → gateado por `net(host)`.
    synsema_stdlib::oidc::register_oidc_builtins(interp, caps.clone());
    // Web Push (tanda PWA): `push_send` gateado por `net(host del endpoint)` — la MISMA
    // puerta que http_*/fetch (el push service es un host más); `push_vapid_keys`
    // gateado por `random` (material secreto nuevo, como token()/random_bytes()).
    synsema_stdlib::webpush::register_webpush_builtins(interp, caps.clone());
    // Tanda escritorio: `platform()` (un hecho del binario, sin capability) y `shutdown(reason?)`
    // (el drain ordenado de serve pedido por el programa; bajo `run` es un error claro).
    synsema_stdlib::platform::register_platform_builtin(interp, std::env::consts::OS, std::env::consts::ARCH);
    synsema_stdlib::server::register_shutdown_builtin(interp);
    // Blockchain (Batch 11): encoding/verify/derive PUROS + firma GATEADA por `sign(NAME)`
    // + audit (cierra sobre el mismo CapabilitySet → sandbox lo vacía, deny-by-default).
    synsema_stdlib::blockchain::register_blockchain_builtins(interp, caps.clone());
    // spend/spend_total (FRAMEWORK F1): gasto declarado y auditado, gateado por
    // `spend(unidad)` — deny-by-default SIEMPRE (jamás auto-granted), como sign/wallet.
    synsema_stdlib::spend::register_spend_builtins(interp, caps.clone());
    // WebSocket cliente (Batch 13): transporte general gateado por `net(host)` (G21),
    // la MISMA capability y scope que http_*/fetch — sandbox lo deniega igual.
    synsema_stdlib::ws::register_ws_builtins(interp, caps.clone());
    // Bus por defecto (programas sin swarm: run_source/conform/test): los `bus_*` existen
    // y funcionan in-process. Con swarm, `wire_swarm_hooks` lo reemplaza por el del
    // proceso ANTES de que corra código del usuario.
    synsema_stdlib::ws::attach_bus(interp, Arc::new(synsema_agents::bus::Bus::new()));
    // cron/db/progress/memory: sus builtins clonan el Rc internamente → viven mientras
    // viva el intérprete.
    // Cron con ejecución REAL también bajo run/test/conform: el ejecutor toma un
    // snapshot `Send` del programa en la registración y corre el task en el hilo del
    // job con su propio intérprete (cacheado por hilo — misma maquinaria que serve).
    // El scheduler arranca cada job al registrarlo; al dropear el intérprete se
    // cancelan todos (fin del programa = fin de los jobs, sin hilos zombies).
    let cron_sched = Arc::new(CronScheduler::new());
    register_cron_builtins(
        interp,
        synsema_stdlib::cron::SchedRef::Strong(cron_sched.clone()),
        crate::serve::run_mode_cron_executor(caps.clone(), secure, &cron_sched, mem.clone()),
    );
    register_database_builtins(interp, Rc::new(RefCell::new(DatabaseManager::new())), caps.clone());
    register_agent_builtins(interp, progress, memory, mem_gate);
    // Helpers de respuesta + vocabulario de contenido (ok/created/.../content). El
    // oráculo los registra en el intérprete principal siempre.
    synsema_stdlib::server::register_serve_builtins(interp);
    // A1 concurrencia (Fase 1): parallel_map + chunk. El ctx de memoria declarada viaja
    // a los workers (comparten los mismos stores; sus caps heredadas traen el grant).
    // v0.6.20 — módulos nuevos de la stdlib + raster con fuentes propias (DESPUÉS de
    // register_serve_builtins: la última registración por nombre gana).
    synsema_stdlib::xml::register_xml_builtins(interp);
    synsema_stdlib::toml_fmt::register_toml_builtins(interp);
    synsema_stdlib::crypto::register_crypto_builtins(interp, caps.clone());
    // `attest`/`attest_key` gateados por `attest` (deny-by-default, jamás
    // ambiente: ningún techo empaquetado la lista) + `attestation_document`/`attestation_key`
    // (la identidad de `serve --attested`; fuera de ese modo, error claro).
    synsema_stdlib::attest::register_attest_builtins(interp, caps.clone());
    // Verificar attestation (nitro/mock; puro, `now` explícito), ruido
    // determinista para privacidad de salida y verificación Groth16 (BN254, JSON de snarkjs).
    // Puros y sin capability; los mismos que entran al perfil wasm.
    synsema_stdlib::attestation::register_attestation_builtins(interp);
    synsema_stdlib::privacy::register_privacy_builtins(interp);
    synsema_stdlib::zk::register_zk_builtins(interp);
    synsema_stdlib::archive::register_archive_builtins(interp, caps.clone());
    // v0.6.46 (C4): Parquet desde el disco, por partes (pide `file.read`).
    synsema_stdlib::parquet_io::register_parquet_scan(interp, caps.clone());
    synsema_stdlib::raster::register_raster_builtins_with_caps(interp, caps.clone());
    crate::parallel::register_parallel_builtins(interp, caps, secure, mem);
    // render real (sobrescribe el placeholder de core): SSR de templates → raw response.
    interp.register_builtin(
        "render",
        -1,
        Rc::new(|i, args, _loc| {
            let path = args.first().map(|v| v.to_string()).unwrap_or_default();
            // Gate de `file.read` para la llamada de NIVEL SUPERIOR (el vector de LFI: el
            // path puede venir de un request). Un template del bundle es el programa: sin
            // gate. Los include/layout ANIDADOS pasan por el mismo gate en `templates.rs`
            // (v0.6.45; antes sólo se los confinaba al cwd).
            if synsema_core::bundle::get(&synsema_core::bundle::normalize_name(&path).unwrap_or_default()).is_none() {
                i.gate_template_read(&path)?;
            }
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
            // Ídem para `sign`: firmar autoriza mover valor — un `require sign` sin
            // scope habilita firmar con CUALQUIER clave. Se aconseja acotarlo al name
            // del secret de la clave (Batch 11).
            if ty == CapabilityType::Sign && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require sign` permits signing with ANY key; \
                     scope it with `require sign(\"KEY_NAME\")` (the name of the key's secret)"
                );
            }
            // Ídem para `spend`: sin scope habilita gastar en CUALQUIER unidad
            // (FRAMEWORK F1). Compat permitida, con aviso — espejo de sign/wallet.
            if ty == CapabilityType::Spend && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require spend` permits spending in ANY unit; \
                     scope it with `require spend(\"USD\")` (the unit being spent)"
                );
            }
            // Ídem para `wallet`: crear custodia (mnemónicos/HD/keystores) sin scope
            // habilita crear claves desde/para CUALQUIER secret (Batch 13).
            if ty == CapabilityType::Wallet && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require wallet` permits creating custody from ANY secret; \
                     scope it with `require wallet(\"NAME\")` (the source secret's name, or the new \
                     secret's label when generating)"
                );
            }
            // v0.6.46 (E3): ídem para `declassify` (publicar lo privado de cualquier principal).
            if ty == CapabilityType::Declassify && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require declassify` permits publishing data private to ANY principal; \
                     scope it with `require declassify(\"principal\")` (the principal the call removes)"
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
            .map_err(|v| v.into_error())
    }));
    // Gate de `judge`: cada bloque exige la capability `judge`, propia y no concedida por
    // `llm`. Mismo CapabilitySet → mismo audit_log. Sin provider cableado el bloque igual
    // pasa por acá: el gate es del lenguaje, no del transporte.
    let caps_judge = caps.clone();
    interp.set_judge_cap_hook(Rc::new(move || {
        caps_judge
            .borrow_mut()
            .require(&Capability::new(CapabilityType::Judge, None), "judge block")
            .map_err(|v| v.into_error())
    }));
    // `sandbox under <caps>` (T1): el cuerpo corre bajo un techo delegado apilado sobre el
    // mismo CapabilitySet. Mismo helper que el host wasm (paridad).
    synsema_stdlib::captoken::install_ceiling_hook(interp, caps.clone());
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

    // args(): los argumentos del programa (proceso). Sin capability.
    interp.set_program_args(crate::host::program_args());
    // Gate de stdout: SÓLO cuando el host puso un techo (`--sandbox`/`--cap-set`). Sin
    // techo, `print` sigue libre como siempre (secure incluido); con techo, un
    // `--cap-set` sin `stdout` deniega la salida en el primer `print` — si no, el audit
    // diría "stdout rechazado por el techo" mientras la salida aparece.
    {
        let caps_out = caps.clone();
        interp.set_stdout_hook(Rc::new(move || {
            let mut cs = caps_out.borrow_mut();
            if cs.ceiling.is_none() {
                return Ok(());
            }
            cs.require(&Capability::new(CapabilityType::Stdout, None), "print()")
                .map_err(|v| v.message)
        }));
    }
    // Gate de lectura de templates a disco (`render`/`include`/`layout`): mismo
    // `file.read` que `read_file`, con el path CRUDO (los assets del bundle no llegan acá).
    {
        let caps_tpl = caps.clone();
        interp.set_template_read_hook(Rc::new(move |raw: &str| {
            let path = synsema_capabilities::model::normalize_path(raw);
            caps_tpl
                .borrow_mut()
                .require(&Capability::new(CapabilityType::FileRead, Some(path)), "render()")
                .map_err(|v| v.into_error())
        }));
        // v0.6.46 (E8): y se abre sin ventana con ese gate: la MISMA ruta que juzgó (la normalizada
        // de `raw`), no la que `resolve_template_path` resolvió después (ronda 1, E8-A3: entre el
        // gate y ese `canonicalize` un link podía cambiar, y la ruta resuelta ya no tiene links que
        // obliguen a re-juzgar). Con un link en el camino, el mismo gate juzga dónde quedó abierto el
        // template, y además que siga adentro del directorio de trabajo, el otro chequeo de la carga.
        let caps_open = caps.clone();
        interp.set_template_open_hook(Rc::new(move |raw: &str| {
            use synsema_capabilities::nofollow::{open_checked, OpenFor, Refused};
            let path = synsema_capabilities::model::normalize_path(raw);
            let recheck = |real: &str| {
                synsema_core::capscope::with_physical(&path, real, || {
                    caps_open
                        .borrow_mut()
                        .require(&Capability::new(CapabilityType::FileRead, Some(path.clone())), "render()")
                        .map_err(|v| v.into_error())
                })?;
                let cwd = std::env::current_dir().and_then(|p| p.canonicalize()).map_err(|e| RuntimeError::new(e.to_string()))?;
                if std::path::Path::new(real).starts_with(&cwd) {
                    Ok(())
                } else {
                    Err(RuntimeError::new(format!("template path escapes the working directory: '{}'", raw)))
                }
            };
            open_checked(&path, OpenFor::READ, &recheck).map_err(|r| match r {
                Refused::Denied(e) => e,
                Refused::Io(_) => RuntimeError::new(format!("template not found: {}", raw)),
            })
        }));
    }
    // run_program(source, opts): Synsema ejecutando Synsema en un proceso hijo bajo
    // techo ∩ padre (gateado por `sandbox_run`).
    crate::run_program::register_run_program_builtin(interp, caps.clone(), child_state);
    // `--profile pure`: la segunda pared. Se registra AL FINAL para pisar por nombre a
    // los builtins OS-facing ya cableados (última registración gana).
    if crate::host::profile() == crate::host::Profile::Pure {
        synsema_stdlib::pure::register_os_stubs(interp, synsema_stdlib::pure::NATIVE_HINT);
        synsema_stdlib::pure::register_no_fs_stubs(interp, synsema_stdlib::pure::NATIVE_HINT);
        // v0.6.20 — en puro, `svg_to_*` vuelve a la variante sin acceso a archivos
        // (`opts.fonts` falla claro en vez de leer disco).
        synsema_stdlib::raster::register_raster_builtins(interp);
    }
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
/// Cablea el provider de `judge` (System One) si hay uno configurado: `TYPESAFE_API_KEY`
/// presente o `SYNSEMA_JUDGE_PROVIDER` explícito (`typesafe` | `mock`). Slot PARALELO al de
/// LLM: los dos pueden estar cableados a la vez y es lo normal (Jev decide, el LLM escribe).
/// Offline: no cablea nada → cada respuesta degrada a `available: false` con confianza 0.
/// Se llama en los mismos tres lugares que `wire_real_llm_provider` (run y los dos caminos
/// de serve): el bug DE-029 del LLM fue justamente olvidarse de serve.
pub(crate) fn wire_real_judge_provider(interp: &mut Interpreter) {
    let store = EnvStore::load_default();
    let provider = match crate::judge_provider::provider_from_config(&store) {
        Some(p) => p,
        None => return,
    };
    let decide = crate::judge_provider::decide_via_judge(&store);
    wire_judge_with(interp, provider, decide);
}

fn wire_judge_with(
    interp: &mut Interpreter,
    provider: Arc<crate::judge_provider::WiredJudgeProvider>,
    decide_via_judge: bool,
) {
    let stash = provider.clone();
    interp.set_judge_usage_callback(Rc::new(crate::judge_provider::judge_tokens_total));
    interp.set_judge_model_callback(Rc::new(crate::judge_provider::judge_last_model));
    interp.set_judge_callback(Rc::new(move |req| provider.judge_for_interpreter(req)));
    // v0.6.26 — `SYNSEMA_JUDGE_DECIDE=1`: `decide between […] given X` se sirve con el juez
    // (una pregunta `choose`), calibrado y sin normalización ni reintento. Opt-in del host:
    // cambia qué modelo contesta. Sólo con provider de judge cableado (arriba).
    if decide_via_judge {
        interp.set_decide_via_judge(true);
    }
    provider_cell(interp).borrow_mut().judge = Some((stash, decide_via_judge));
}

/// v0.6.45 (A1) — los providers reales que tiene cableados un intérprete, guardados en su `ext`
/// para que lo que corre EN SU NOMBRE en otro hilo (cada item de `parallel_map`, cada agente de
/// `spawn`) use las MISMAS instancias: sin releer el `.env`, y con exactamente lo que tiene el
/// llamador (si está offline, el otro también). Antes esos intérpretes no cableaban nada y
/// `judge`/`reason` caían a OFFLINE/placeholder. Cruzan hilos sin problema: los providers son
/// `Send + Sync` y los contadores de presupuesto (`LLM_TOKENS_USED`, `IDENTITY_TOKENS_USED`, los
/// del judge) son estáticos del proceso, así que compartir la instancia no saltea ningún techo.
#[derive(Clone, Default)]
pub(crate) struct WiredProviders {
    llm: Option<Arc<dyn LLMProvider>>,
    judge: Option<(Arc<crate::judge_provider::WiredJudgeProvider>, bool)>,
}

const WIRED_PROVIDERS_KEY: &str = "synsema.wired_providers";

/// La celda (una por intérprete) es compartida a propósito: el hook de `spawn` se arma en
/// `wire_swarm_hooks` ANTES de que se cableen los providers, así que captura la celda y la lee
/// recién cuando el programa hace `spawn`.
type ProviderCell = RefCell<WiredProviders>;

fn provider_cell(interp: &Interpreter) -> Rc<ProviderCell> {
    let found = interp
        .ext
        .borrow()
        .get(WIRED_PROVIDERS_KEY)
        .and_then(|a| a.clone().downcast::<ProviderCell>().ok());
    if let Some(cell) = found {
        return cell;
    }
    let cell = Rc::new(ProviderCell::default());
    interp.ext.borrow_mut().insert(WIRED_PROVIDERS_KEY, cell.clone() as Rc<dyn std::any::Any>);
    cell
}

pub(crate) fn wired_providers(interp: &Interpreter) -> WiredProviders {
    provider_cell(interp).borrow().clone()
}

/// Cablea en `interp` los providers de otro intérprete (ver [`WiredProviders`]).
pub(crate) fn wire_providers(interp: &mut Interpreter, wired: &WiredProviders) {
    if let Some(p) = &wired.llm {
        wire_llm_with(interp, p.clone());
    }
    if let Some((p, decide)) = &wired.judge {
        wire_judge_with(interp, p.clone(), *decide);
    }
}

pub(crate) fn wire_real_llm_provider(interp: &mut Interpreter) {
    // `load_default` lee `SYNSEMA_ENV_FILE`/`.env` (idempotente; honra `--env-file` y
    // `--no-env-file`). El environ del proceso sigue ganando sobre el `.env`.
    let store = EnvStore::load_default();
    // v0.6.20 — envuelto en `ReloadingProvider`: un SIGHUP (recarga del .env) reconstruye el
    // provider real con la clave nueva sin reiniciar el proceso.
    let provider: Arc<dyn LLMProvider> = match crate::llm_providers::provider_from_config(&store) {
        Some(p) => Arc::new(crate::llm_providers::ReloadingProvider::new(p)),
        None => return,
    };
    wire_llm_with(interp, provider);
}

fn wire_llm_with(interp: &mut Interpreter, provider: Arc<dyn LLMProvider>) {
    provider_cell(interp).borrow_mut().llm = Some(provider.clone());
    // llm_usage(): tokens LLM acumulados del proceso (F-A). Se cablea junto al
    // provider (con provider real siempre hay metering — MeteredProvider); offline el
    // callback no se setea y el builtin del core devuelve 0.
    interp.set_llm_usage_callback(Rc::new(crate::llm_providers::llm_tokens_total));
    // Callback de texto: arma `LLMRequest::new(op)` + `data["prompt"]` → `call().content`.
    let p_text = provider.clone();
    interp.set_llm_callback(Rc::new(move |op: &str, prompt: &str, _principals: &[Rc<str>]| {
        let mut req = LLMRequest::new(op);
        req.data.insert("prompt".to_string(), prompt.to_string());
        Ok(p_text.call(&req).content)
    }));
    // Callback dedicado de `decide` (DE-039): las opciones viajan estructuradas y el
    // contrato completo (tool/enum forzado → normalización → 1 reintento → fallback
    // con aviso) vive en `decide_with_contract`.
    let p_decide = provider.clone();
    interp.set_llm_decide_callback(Rc::new(move |prompt: &str, options: &[String]| {
        crate::llm_providers::decide_with_contract(p_decide.as_ref(), prompt, options)
    }));
    // Callback de streaming (`llm_stream`, F2): mismo armado de request que llm_step
    // (prompt + context) → `call_stream` pasa el sink al provider. El local streamea
    // token a token; mock y providers de red heredan el default del trait (UN chunk).
    let p_stream = provider.clone();
    interp.set_llm_stream_callback(Rc::new(
        move |prompt: &str, context: &str, sink: &mut dyn FnMut(&str) -> bool| {
            let mut req = LLMRequest::new("stream");
            req.data.insert("prompt".to_string(), prompt.to_string());
            req.data.insert("context".to_string(), context.to_string());
            p_stream.call_stream(&req, sink).content
        },
    ));
    // Callback de paso tool-aware: arma `LLMRequest::new("step").with_tools(catalog)` +
    // `data["prompt"]`/`data["context"]` → `call_step` → mapea `LlmStep`→`StepResult`.
    interp.set_llm_step_callback(Rc::new(
        move |prompt: &str, catalog: &[StepCatalogEntry], context: &str| {
            llm_step_with(provider.as_ref(), prompt, catalog, context)
        },
    ));
}

/// Un paso tool-aware contra `provider`: arma `LLMRequest::new("step").with_tools(catalog)` +
/// `data["prompt"]`/`data["context"]` → `call_step` → mapea `LlmStep`→`StepResult`.
fn llm_step_with(provider: &dyn LLMProvider, prompt: &str, catalog: &[StepCatalogEntry], context: &str) -> StepResult {
    let mut req = LLMRequest::new("step").with_tools(
        catalog
            .iter()
            .map(|e| ToolSpec {
                name: e.name.clone(),
                description: e.description.clone(),
                params: e.params.clone(),
                types: e.types.iter().map(|t| t.map_or("", |t| t.json_schema()).to_string()).collect(),
                optional: e.optional.clone(),
            })
            .collect(),
    );
    req.data.insert("prompt".to_string(), prompt.to_string());
    req.data.insert("context".to_string(), context.to_string());
    let r = provider.call_step(&req);
    match r.step {
        LlmStep::Final(t) => StepResult::Final { text: t, tokens: r.tokens_used },
        LlmStep::ToolCall { name, args } => {
            let args = typed_step_args(catalog, &name, args);
            StepResult::Tool { name, args, tokens: r.tokens_used }
        }
    }
}

/// v0.6.46 (F1): el proveedor manda los argumentos de una tool-call como texto (`synsema-llm` no
/// tiene dependencias: un número llega `"3"`, una lista `"[1,2]"`). Un parámetro que el catálogo
/// declara de un tipo distinto de `text` vuelve a su tipo decodificando ese JSON; si no da el tipo
/// declarado queda como texto y `call_tool` lo rechaza con el error que lo dice. Los parámetros sin
/// tipo siguen llegando como texto.
fn typed_step_args(catalog: &[StepCatalogEntry], tool: &str, args: Vec<(String, String)>) -> Vec<(String, SynValue)> {
    let entry = catalog.iter().find(|e| e.name == tool);
    args.into_iter()
        .filter_map(|(k, s)| {
            let ty = entry
                .and_then(|e| e.params.iter().position(|p| *p == k).and_then(|i| e.types.get(i).copied().flatten()));
            // v0.6.46 (ronda 1 de cf1, N2): muchos modelos mandan `null` para lo que no quieren pasar.
            // En un parámetro opcional, o tipado y no `text`, es "no lo pasó": corre el default, o
            // `call_tool` dice que falta (antes llegaba el texto "null").
            let optional = entry.is_some_and(|e| e.optional.contains(&k));
            if s == "null" && (optional || ty.is_some_and(|t| t != synsema_core::ast::ParamType::Text)) {
                return None;
            }
            let v = match ty {
                Some(t) if t != synsema_core::ast::ParamType::Text => serde_json::from_str::<serde_json::Value>(&s)
                    .ok()
                    .map(|j| synsema_stdlib::json::json_to_syn(&j))
                    .filter(|v| t.accepts(v)),
                _ => None,
            };
            Some((k, v.unwrap_or_else(|| synsema_core::types::syn_text(s))))
        })
        .collect()
}

fn finish(mut interp: Interpreter, result: Result<SynValue, Control>) -> RunResult {
    // T5 (ronda 6, B2): la salida de una corrida cortada por el chequeo de flujo no se entrega
    // — la cantidad de líneas antes del corte depende del dato privado. Ver `redact_output_for_host`.
    interp.redact_output_for_host(&result);
    // v0.6.42 — `exit(code)`: el fin pedido, no una falla. Sin "Runtime error"; el código lo
    // lee el CLI con `last_run_exit_code()` (se pisa en cada corrida, nunca queda uno viejo).
    let exit = match &result {
        Err(Control::Error(e)) => e.exit_code,
        _ => None,
    };
    LAST_RUN_EXIT.store(exit.unwrap_or(-1), std::sync::atomic::Ordering::SeqCst);
    RUN_EXIT.with(|c| c.set(exit));
    if let Some(code) = exit {
        return RunResult { success: code == 0, output: std::mem::take(&mut interp.output), errors: Vec::new() };
    }
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
// camino sin swarm (conform capas 1-6)
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
    ceiling: Option<Vec<Capability>>,
) -> RunResult {
    // T4: la medida del programa que corre, para el recibo (`receipt()`).
    synsema_stdlib::attest::note_program_sha(source, filename);
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
            // Techo del host (--sandbox/--cap-set): setear ANTES de wire_common para que los
            // auto-grants (stdout/time/llm) también se filtren. Se propaga a los agentes
            // swarm como `Arc` (Send) más abajo.
            if let Some(cl) = &ceiling {
                caps.borrow_mut().ceiling = Some(Rc::new(cl.clone()));
            }
            let ceiling_arc: Option<Arc<Vec<Capability>>> = ceiling.map(Arc::new);
            // Identidad declarada (DB-M1): scan top-level + apertura del `.db` (o el
            // chequeo de transición G-4 si no hay declaración). Declaración inválida
            // (G-6) o múltiple (decisión #3) = error de arranque.
            let mem_ctx = match memory_ctx_for(
                &program.statements,
                filename,
                ceiling_arc.as_ref().map(|a| a.as_slice()),
            ) {
                Ok(m) => m,
                Err(msg) => {
                    return RunResult {
                        success: false,
                        output: Vec::new(),
                        errors: vec![format!("Runtime error: {}", msg)],
                    }
                }
            };
            let suggest = suggested_memory_name(filename);
            let gate = memory_gate_for(&caps, mem_ctx.as_ref(), &suggest);
            wire_common_with_state(
                &mut interp,
                &caps,
                secure,
                Rc::new(RefCell::new(ProgressManager::new())),
                Rc::new(RefCell::new(AgentMemory::new())),
                gate.clone(),
                mem_ctx.clone(),
            );
            if let Some(ctx) = &mem_ctx {
                register_serve_memory_builtins(&interp, ctx.memory.clone(), ctx.on_write_mem.clone(), gate.clone());
                register_serve_progress_builtins(&interp, ctx.progress.clone(), ctx.on_write_prog.clone(), gate.clone());
                register_shared_rules_builtins(&interp, ctx.memory.clone(), ctx.on_write_mem.clone(), gate.clone());
            }
            // Conectividad LLM real: si hay provider por env, cablea texto + paso
            // tool-aware; offline (sin key) deja los placeholders del core.
            wire_real_llm_provider(&mut interp);
            wire_real_judge_provider(&mut interp);
            // Gates humanos (DX-3 etapa 1, A1.v1): en `run` interactivo (TTY) el humano
            // decide DE VERDAD (ConsoleHandler espera en la terminal); sin TTY (pipe/CI)
            // se DENIEGA fail-closed con aviso — nunca auto-aprobar en silencio. En
            // conform/test (`live_output=false`) NO se cablea: quedan los fallbacks
            // deterministas del core (los tests no bloquean en un prompt). `serve`
            // cablea su propio DenyHandler en build_base_interp.
            if live_output {
                use std::io::IsTerminal;
                let handler: Arc<dyn synsema_llm::human::HumanHandler> =
                    if std::io::stdin().is_terminal() {
                        Arc::new(synsema_llm::human::ConsoleHandler)
                    } else {
                        Arc::new(synsema_llm::human::DenyHandler::new("non-interactive run, no TTY"))
                    };
                let mgr = synsema_llm::human::InteractionManager::new(handler);
                interp.set_human_callback(mgr.get_callback());
            }

            // Swarm real (DE-011): los hooks de spawn/share/observe/signal/wait_for del
            // main van al swarm compartido → los agentes corren en hilos aislados. El techo
            // del host se propaga a cada agente spawneado (nunca lo exceden), y el ctx de
            // memoria declarada también (namespaces por `source`, decisión #4).
            if let Some(sw) = swarm {
                wire_swarm_hooks(&mut interp, sw, "main", ceiling_arc.clone(), mem_ctx.clone(), None, &caps);
            }
            // T1: `run` corre en nombre del OPERADOR (`SYNSEMA_IDENTITY` si está puesto). Lo
            // heredan los agentes que el main spawnee; sin él, el sujeto queda anónimo.
            let _operator_scope = crate::subject::Subject::operator().apply(&mut interp, &caps);

            // La persistencia es on-write (el ctx guarda tras cada mutación, como serve):
            // no hay save final que pueda perderse si el programa crashea a mitad.
            let r = if REQUEST_MODE.load(std::sync::atomic::Ordering::SeqCst) {
                interp.run_request_block(&program.statements, Vec::new())
            } else {
                interp.execute(&program)
            };
            note_run_steps(&interp);
            finish(interp, r)
        }
    }
}

fn spawn_run(source: &str, filename: &str, secure: bool) -> RunResult {
    spawn_run_ceiled(source, filename, secure, None)
}

/// El error de un hilo del motor que terminó en pánico: es un BUG del motor (un error del
/// programa nunca es un pánico), y el mensaje lo dice con el texto del pánico en vez de
/// adivinar la causa. Un desborde de stack nativo no llega acá: aborta el proceso.
pub fn abort_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    let what = payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string());
    format!("internal error in the engine (a bug, not your program — please report it): {}", what)
}

fn spawn_run_ceiled(source: &str, filename: &str, secure: bool, ceiling: Option<Vec<Capability>>) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_inner(&src, &fname, secure, None, false, ceiling))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult {
            success: false,
            output: Vec::new(),
            errors: vec![abort_message(&p)],
        })
}

/// Sólo el oráculo diferencial (`oracle_run --request`): corre el programa entero como el cuerpo
/// de una ruta de `serve` (`run_request_block`, en un scope hijo del global) en vez de como
/// programa, para comparar ese camino entre la referencia y la VM/nativo. No es un knob de usuario.
static REQUEST_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[doc(hidden)]
pub fn set_request_mode(on: bool) {
    REQUEST_MODE.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// Modo no-secure (default real): auto-concede STDOUT y TIME. Lo que usa `conform`.
/// Camino de un solo hilo: `spawn` corre el agente in-process (sin swarm).
/// v0.6.20 — pasos del intérprete del ÚLTIMO programa ejecutado en este proceso (`run`,
/// `test`, `conform`): lo que `run --format json` reporta como `steps`. Determinista.
static LAST_RUN_STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// T5 (ronda 5): ¿esa corrida tocó datos privados? El contador de pasos es lineal en lo que el
/// programa recorrió, así que después de una rama privada ES el dato privado con otra aritmética
/// encima — y el host lo publica solo, en `run --format json` y en el documento de `run --attest`,
/// que es justo el artefacto que un tercero verifica. Con esto el host puede omitirlo.
static LAST_RUN_PRIVATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// v0.6.42 — el código que pidió `exit(code)` en la última corrida (-1 = no llamó a `exit`).
static LAST_RUN_EXIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

thread_local! {
    /// v0.6.46 — el `exit(code)` de la corrida de ESTE hilo del motor (lo fija `finish`). El motor
    /// decide con éste, no con `LAST_RUN_EXIT`: con dos corridas a la vez en un proceso (un
    /// embebedor, un binario de tests), la otra lo pisaba en el medio y un agente vivo quedaba
    /// corriendo para siempre. `LAST_RUN_EXIT` queda para la CLI, que corre una por proceso.
    static RUN_EXIT: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

/// v0.6.45 (A5) — `serve` anota el código de un `exit(code)` del preámbulo (antes de escuchar),
/// o que no lo hubo, por el mismo canal que `run`.
pub(crate) fn note_exit_code(code: Option<i32>) {
    LAST_RUN_EXIT.store(code.unwrap_or(-1), std::sync::atomic::Ordering::SeqCst);
}

/// El código de `exit(code)` de la última corrida, si el programa lo llamó.
pub fn last_run_exit_code() -> Option<i32> {
    match LAST_RUN_EXIT.load(std::sync::atomic::Ordering::SeqCst) {
        c if c >= 0 => Some(c),
        _ => None,
    }
}

fn note_run_steps(interp: &Interpreter) {
    LAST_RUN_STEPS.store(interp.steps(), std::sync::atomic::Ordering::SeqCst);
    LAST_RUN_PRIVATE.store(interp.private_seen(), std::sync::atomic::Ordering::SeqCst);
}

pub fn last_run_steps() -> u64 {
    LAST_RUN_STEPS.load(std::sync::atomic::Ordering::SeqCst)
}

/// ¿La última corrida tocó datos privados? Si sí, `steps` no se publica (ver `LAST_RUN_PRIVATE`).
pub fn last_run_touched_private() -> bool {
    LAST_RUN_PRIVATE.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn run_source(source: &str, filename: &str) -> RunResult {
    spawn_run(source, filename, false)
}

/// Como `run_source` pero con el techo del host (`conform --sandbox/--cap-set`): la misma
/// semántica que `run`/`test`, sin el swarm real.
pub fn run_source_ceiled(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> RunResult {
    spawn_run_ceiled(source, filename, false, ceiling)
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
    run_program_ceiled(source, filename, None)
}

/// Como `run_program` pero con un **techo de capabilities del host** opcional
/// (`--sandbox`/`--cap-set`): el programa y todos los agentes que spawnee jamás exceden
/// `ceiling`. `None` = sin techo (idéntico a `run_program`).
pub fn run_program_ceiled(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> RunResult {
    run_program_ceiled_opts(source, filename, ceiling, true)
}

/// Como `run_program_ceiled` pero eligiendo si la salida va en vivo a stdout
/// (`live_output`, el `run` interactivo) o se COLECTA en `output` (`run --format json`,
/// el informe con la forma de `syn.run()`).
pub fn run_program_ceiled_opts(
    source: &str,
    filename: &str,
    ceiling: Option<Vec<Capability>>,
    live_output: bool,
) -> RunResult {
    let swarm = Arc::new(Swarm::new());
    let sw = swarm.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let result = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            RUN_EXIT.with(|c| c.set(None));
            let r = run_inner(&src, &fname, false, Some(sw), live_output, ceiling);
            (r, RUN_EXIT.with(|c| c.get()))
        })
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|p| {
            (RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] }, None)
        });
    let (mut result, run_exit) = result;

    // v0.6.42 (auditoría) — `exit(code)` termina el programa: los agentes vivos se detienen (si
    // no, `wait_all` esperaba a uno en bucle para siempre) y el código lo decide `exit`.
    let exited = run_exit.is_some();
    // Los que `exit` detuvo: su error es la cancelación y no se informa. Un agente que ya había
    // fallado antes del `exit` sí (auditoría ronda 2: se descartaban todos).
    let stopped: std::collections::HashSet<String> = if exited {
        swarm.agents_info().into_iter().map(|(id, _)| id).filter(|id| swarm.stop_agent(id, "exit()")).collect()
    } else {
        Default::default()
    };
    // Joinea los agentes lanzados por el main; ya no hay nadie más que pueda spawnear.
    swarm.wait_all();

    // Refleja los agentes en ERROR (exit ≠0 + línea de error), sin tocar la salida del main.
    let mut agent_errors = collect_agent_errors(&swarm);
    agent_errors.retain(|line| !stopped.iter().any(|id| line.starts_with(&format!("Agent error [{}]:", id))));
    if !agent_errors.is_empty() {
        result.success = false;
        result.errors.extend(agent_errors);
    }
    result
}

// =========================================================
// test framework (Batch 3): `synsema test`
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

fn run_tests_inner(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> TestReport {
    let program = match parse_source(source, filename) {
        Ok(p) => p,
        Err(CompileError::Lex(e)) => return report_with_failure("<parse>", format!("Lexer error: {}", e)),
        Err(CompileError::Parse(e)) => return report_with_failure("<parse>", format!("Parse error: {}", e)),
    };
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    // Techo del host (--sandbox/--cap-set): antes de wire_common para filtrar los auto-grants.
    if let Some(cl) = &ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new(cl.clone()));
    }
    // Identidad declarada (DB-M1): misma resolución que `run` (§3.2 — aplica idéntico
    // en run/test/conform/serve). Declaración inválida/múltiple = fallo de arranque.
    let mem_ctx = match memory_ctx_for(&program.statements, filename, ceiling.as_deref()) {
        Ok(m) => m,
        Err(msg) => return report_with_failure("<startup>", format!("Runtime error: {}", msg)),
    };
    // Wiring no-secure (igual que `run`): los `require` del archivo conceden capabilities (G4).
    wire_common(&mut interp, &caps, false, mem_ctx.as_ref(), &suggested_memory_name(filename));
    // Swarm real, como en `run` (v0.6.10+): `spawn` corre el agente en su propio hilo,
    // `agents()`/`agent_stop` existen, el bus es el del swarm. Al terminar cada bloque
    // `test` se joinean sus agentes y un agente en ERROR hace fallar ESE test — un
    // programa con agentes se prueba con `synsema test`, sin scripts externos.
    let swarm = Arc::new(Swarm::new());
    let ceiling_arc: Option<Arc<Vec<Capability>>> = ceiling.as_ref().map(|c| Arc::new(c.clone()));
    wire_swarm_hooks(&mut interp, swarm.clone(), "main", ceiling_arc, mem_ctx.clone(), None, &caps);
    let mut reported: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut after_each = |_name: &str| -> Option<String> {
        swarm.wait_all();
        let mut fresh: Vec<String> = Vec::new();
        for (id, st) in swarm.agent_states() {
            if st == AgentState::Error && reported.insert(id.clone()) {
                let msg = swarm.agent_error(&id).unwrap_or_else(|| "agent error".to_string());
                fresh.push(format!("Agent error [{}]: {}", id, msg));
            }
        }
        if fresh.is_empty() {
            None
        } else {
            Some(fresh.join("; "))
        }
    };
    let outcomes = interp.run_test_blocks_with(&program, &mut after_each);
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let failed = outcomes.len() - passed;
    TestReport { outcomes, passed, failed, output: std::mem::take(&mut interp.output) }
}

/// Corre los bloques `test` de un archivo en un hilo con stack grande (como `spawn_run`).
pub fn run_tests(source: &str, filename: &str) -> TestReport {
    run_tests_ceiled(source, filename, None)
}

/// Como `run_tests` pero con un techo de capabilities del host (`--sandbox`/`--cap-set`).
pub fn run_tests_ceiled(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> TestReport {
    synsema_stdlib::attest::note_program_sha(source, filename);
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_tests_inner(&src, &fname, ceiling))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|p| {
            report_with_failure("<runner>", abort_message(&p))
        })
}

/// REPL interactivo (espeja `engine.repl()` del oráculo). Mantiene UN intérprete
/// con estado entre líneas; ejecuta cada línea e imprime la salida nueva.
pub fn repl() {
    use std::io::{self, BufRead, Write};
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("repl")));
    wire_common(&mut interp, &caps, false, None, "my-agent");
    // DB-M1 en el REPL: la declaración llega DESPUÉS del wiring (línea a línea), así
    // que el gate estático "sin declaración" dejaría la familia muerta con una
    // sugerencia que no arregla nada. Acá el gate mira el CapabilitySet VIVO: tipear
    // `require memory("<nombre>")` en la sesión habilita la memoria EFÍMERA del REPL
    // (stores per-intérprete, sin disco — como `<stdin>`). Deny-by-default intacto.
    let repl_gate: MemoryGate = {
        let caps = caps.clone();
        Rc::new(move || {
            let declared = caps
                .borrow()
                .granted
                .iter()
                .any(|c| c.ty == CapabilityType::Memory);
            if declared {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "Capability not granted: memory. Persistent agent state (remember/recall, rules, progress) requires a declared memory. In the REPL, type: require memory(\"my-agent\") to enable a session-only in-memory store (nothing is written to disk)",
                ))
            }
        })
    };
    register_agent_builtins(
        &interp,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
        repl_gate,
    );
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
fn run_diag_inner(source: &str, filename: &str, swarm: Option<Arc<Swarm>>, ceiling: Option<Vec<Capability>>) -> DiagRun {
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
    // Techo del host: antes de wire_common (filtra auto-grants); a los agentes como Arc.
    if let Some(cl) = &ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new(cl.clone()));
    }
    let ceiling_arc: Option<Arc<Vec<Capability>>> = ceiling.map(Arc::new);
    // Identidad declarada (DB-M1): `run --explain` es una variante de run — misma
    // resolución/gate que run_inner.
    let mem_ctx = match memory_ctx_for(
        &program.statements,
        filename,
        ceiling_arc.as_ref().map(|a| a.as_slice()),
    ) {
        Ok(m) => m,
        Err(msg) => {
            return DiagRun {
                result: RunResult {
                    success: false,
                    output: Vec::new(),
                    errors: vec![format!("Runtime error: {}", msg)],
                },
                diagnostics: vec![ErrorReporter::new().build_diagnostic("RuntimeError", &msg, None, None)],
            }
        }
    };
    wire_common(&mut interp, &caps, false, mem_ctx.as_ref(), &suggested_memory_name(filename));
    // Swarm real (DE-014): mismos hooks que `run` → los agentes corren aislados y un
    // `raise` de agente no aborta el main ni trunca su diagnóstico.
    if let Some(sw) = swarm {
        wire_swarm_hooks(&mut interp, sw, "main", ceiling_arc.clone(), mem_ctx.clone(), None, &caps);
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
                .map(|(k, v)| (k.to_string(), v.to_string()))
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
    run_with_diagnostics_ceiled(source, filename, None)
}

/// Como `run_with_diagnostics` pero con un techo de capabilities del host
/// (`--sandbox`/`--cap-set`): el main y sus agentes jamás exceden `ceiling`.
pub fn run_with_diagnostics_ceiled(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> DiagRun {
    let swarm = Arc::new(Swarm::new());
    let sw = swarm.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let mut run = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || run_diag_inner(&src, &fname, Some(sw), ceiling))
        .expect("no se pudo crear el hilo del motor")
        .join()
        .unwrap_or_else(|p| DiagRun {
            result: RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] },
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
            // Identidad declarada (DB-M1): mismos gates que run también en los
            // harnesses host-config (run_with_human/run_with_llm/…). Sin techo acá.
            let mem_ctx = match memory_ctx_for(&program.statements, filename, None) {
                Ok(m) => m,
                Err(msg) => {
                    return RunResult {
                        success: false,
                        output: Vec::new(),
                        errors: vec![format!("Runtime error: {}", msg)],
                    }
                }
            };
            wire_common(&mut interp, &caps, false, mem_ctx.as_ref(), &suggested_memory_name(filename));
            configure(&mut interp);
            let r = interp.execute(&program);
            note_run_steps(&interp);
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
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] })
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
                interp.set_llm_callback(Rc::new(move |op: &str, prompt: &str, _principals: &[Rc<str>]| {
                    cap.lock().unwrap().push((op.to_string(), prompt.to_string()));
                    Ok("ok".to_string())
                }));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] });
    let pairs = cap_outer.lock().unwrap().clone();
    (result, pairs)
}

/// Host-config de test (DE-039): corre con el callback DEDICADO de `decide` que graba
/// `(prompt, opciones)` y responde `respuesta`. Para aseverar que las opciones del
/// `between [...]` llegan ESTRUCTURADAS (no sólo embebidas en el prompt) sin red.
pub fn run_capturing_decide(
    source: &str,
    filename: &str,
    respuesta: &str,
) -> (RunResult, Vec<(String, Vec<String>)>) {
    type Captured = Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>;
    let captured: Captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap_outer = captured.clone();
    let src = source.to_string();
    let fname = filename.to_string();
    let resp = respuesta.to_string();
    let result = std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let cap = captured.clone();
                interp.set_llm_decide_callback(Rc::new(move |prompt: &str, options: &[String]| {
                    cap.lock().unwrap().push((prompt.to_string(), options.to_vec()));
                    resp.clone()
                }));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] });
    let pairs = cap_outer.lock().unwrap().clone();
    (result, pairs)
}

/// Corre con un proveedor LLM mock (host-config) con respuestas predecibles.
///
/// NOTA (F1): este harness — como [`run_with_llm_steps`] — cablea el mock DIRECTO al
/// callback, bypaseando `provider_from_config` → NO pasa por `MeteredProvider` y no
/// se metra (`llm_usage()` no crece acá). Deliberado y aceptable: son atajos de test
/// sin red; el metering cubre todos los caminos con provider real.
pub fn run_with_llm(source: &str, filename: &str, responses: HashMap<String, String>) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                let provider = Arc::new(MockProvider::new(responses));
                // El mock keyea por `op` e ignora el prompt (retrocompat de los tests).
                interp.set_llm_callback(Rc::new(move |op: &str, _prompt: &str, _principals: &[Rc<str>]| {
                    Ok(provider.call(&LLMRequest::new(op)).content)
                }));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] })
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
                        llm_step_with(provider.as_ref(), prompt, catalog, context)
                    },
                ));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] })
}

/// Corre con un callback de STREAMING guionado (host-config, F2): `llm_stream` recibe
/// la secuencia fija de `chunks` en orden y devuelve su concatenación. Respeta el
/// contrato del sink: si `on_chunk` (la task del usuario) falla, el sink devuelve
/// `false` y la "generación" corta ahí — igual que el provider real. Espejo de
/// `run_with_llm_steps`, para los tests deterministas sin modelo.
pub fn run_with_llm_stream(source: &str, filename: &str, chunks: Vec<String>) -> RunResult {
    let src = source.to_string();
    let fname = filename.to_string();
    std::thread::Builder::new()
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            run_configured(&src, &fname, move |interp| {
                interp.set_llm_stream_callback(Rc::new(
                    move |_prompt: &str, _context: &str, sink: &mut dyn FnMut(&str) -> bool| {
                        let mut full = String::new();
                        for ch in &chunks {
                            if !sink(ch) {
                                break;
                            }
                            full.push_str(ch);
                        }
                        full
                    },
                ));
            })
        })
        .expect("hilo del motor")
        .join()
        .unwrap_or_else(|p| RunResult { success: false, output: Vec::new(), errors: vec![abort_message(&p)] })
}

// =========================================================
// camino con swarm (agentes en hilos)
// =========================================================

/// Cablea los hooks del swarm en un intérprete (capturando el `Arc<Swarm>` y el
/// nombre del agente para las escrituras al blackboard).
/// Constructor `Send` de intérpretes con el wiring completo de un `serve` (state_*, DB
/// compartida, approvals, cron, bus, memoria). Los agentes spawneados desde handlers o
/// ticks de cron nacen con él — no en una isla con builtins frescos.
pub(crate) type InterpBuilder = Arc<dyn Fn() -> (Interpreter, Rc<RefCell<CapabilitySet>>) + Send + Sync>;

pub(crate) fn wire_swarm_hooks(
    interp: &mut Interpreter,
    swarm: Arc<Swarm>,
    agent_name: &str,
    ceiling: Option<Arc<Vec<Capability>>>,
    mem: Option<MemoryCtx>,
    builder: Option<InterpBuilder>,
    caps: &Rc<RefCell<CapabilitySet>>,
) {
    let name = agent_name.to_string();
    // Bus de eventos del proceso: `bus_*`/`select` del hub de I/O publican y suscriben
    // contra el MISMO bus que agentes, cron y handlers (vive en el swarm).
    synsema_stdlib::ws::attach_bus(interp, swarm.bus.clone());
    // Observabilidad de agentes desde el lenguaje: `agents()` (snapshot de estados) y
    // `agent_stop(id)` (cancelación cooperativa). Sin capability: introspección del
    // propio proceso.
    {
        let sw = swarm.clone();
        interp.register_builtin(
            "agents",
            0,
            Rc::new(move |_i, _args, _loc| {
                use synsema_core::types::{syn_map, syn_number, syn_text};
                let items: Vec<SynValue> = sw
                    .agents_info()
                    .into_iter()
                    .map(|(id, a)| {
                        let mut m = SynMap::new();
                        m.insert("id", syn_text(id.clone()));
                        // `name` = el agente declarado (sin el sufijo de instancia `_N`).
                        let base = id.rsplit_once('_').map(|(b, n)| if n.bytes().all(|c| c.is_ascii_digit()) { b.to_string() } else { id.clone() }).unwrap_or(id.clone());
                        m.insert("name", syn_text(base));
                        m.insert("state", syn_text(agent_state_str(a.state)));
                        m.insert("error", a.error.clone().map(syn_text).unwrap_or(SynValue::Nothing));
                        m.insert("started_at", syn_number(synsema_core::number::Number::Float(a.started_at)));
                        m.insert(
                            "finished_at".to_string(),
                            if a.finished_at > 0.0 { syn_number(synsema_core::number::Number::Float(a.finished_at)) } else { SynValue::Nothing },
                        );
                        syn_map(m)
                    })
                    .collect();
                Ok(SynValue::List(synsema_core::types::ListRef::new(items.into())))
            }),
        );
        let sw = swarm.clone();
        interp.register_builtin(
            "agent_stop",
            -1,
            Rc::new(move |_i, args, _loc| {
                let id = match args.first() {
                    Some(SynValue::Text(s)) => s.to_string(),
                    Some(other) => {
                        return Err(Control::Error(synsema_core::interpreter::RuntimeError::new(format!(
                            "agent_stop: the agent id must be text (from agents()), got {}",
                            other.type_name()
                        ))))
                    }
                    None => return Err(Control::Error(synsema_core::interpreter::RuntimeError::new("agent_stop: missing the agent id"))),
                };
                let reason = match args.get(1) {
                    Some(SynValue::Text(s)) => s.to_string(),
                    _ => "stopped by agent_stop".to_string(),
                };
                Ok(synsema_core::types::syn_bool(sw.stop_agent(&id, &reason)))
            }),
        );
    }

    let share: synsema_core::interpreter::ShareHook = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |k, v| sw.blackboard.write(k, to_send(v), &n))
    };
    let observe: synsema_core::interpreter::ObserveHook = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |k| sw.blackboard.read(k, &n).map(|sv| from_send(&sv)))
    };
    let signal: synsema_core::interpreter::SignalHook = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |sig_name, data| sw.signal(sig_name, &n, data.map(|v| to_send(&v))))
    };
    let wait_for: synsema_core::interpreter::WaitForHook = {
        let sw = swarm.clone();
        let n = name.clone();
        Rc::new(move |sig_name, timeout, cancel: &Arc<std::sync::atomic::AtomicBool>| {
            // Timeout configurable (Batch 7): segundos del `wait_for ... timeout <expr>`, o
            // 30 s por defecto (G1). Clamp [0, 3600] como `sleep`.
            let secs = timeout.unwrap_or(30.0).clamp(0.0, 3600.0);
            // Estado WAITING mientras bloquea (no-op si `n` no es agente registrado, p.ej. "main").
            sw.set_state(&n, AgentState::Waiting);
            // La espera sale apenas llega la cancelación (timeout de handler, shutdown,
            // agent_stop): el intérprete la convierte en error al volver.
            let c = cancel.clone();
            let sig = sw.wait_for_signal_cancellable(sig_name, Duration::from_secs_f64(secs), &|| {
                c.load(std::sync::atomic::Ordering::Relaxed)
            });
            sw.set_state(&n, AgentState::Working);
            sig.and_then(|s| s.data).map(|d| from_send(&d))
        })
    };
    let spawn: synsema_core::interpreter::SpawnHook = {
        let sw = swarm.clone();
        let ceiling = ceiling.clone();
        let mem = mem.clone();
        let builder = builder.clone();
        let caps_spawn = caps.clone();
        let providers = provider_cell(interp);
        Rc::new(move |agent, body, args, globals, spawn_subject| {
            let send_args: Vec<(String, SendValue)> =
                args.iter().map(|(k, v)| (k.clone(), to_send(v))).collect();
            // Convertir el snapshot de globales del llamador a GlobalVal (preserva tasks).
            let global_snap: Arc<Vec<(String, GlobalVal)>> = Arc::new(
                // Lo ya congelado para siempre (las globales de `serve`) se comparte sin copia; lo
                // demás se copia: el agente vive libre (R2.4).
                globals.iter().map(|(k, v)| (k.clone(), val_to_global_shared(v))).collect(),
            );
            // El techo del host se propaga al agente (Arc → Send cruza el hilo): un agente
            // spawneado jamás excede el techo, aunque su cuerpo declare `require exec(...)`.
            // El ctx de memoria declarada también (mismos stores + namespace por `source`).
            // T1: y el SUJETO entero del llamador — identidad, techo de gasto, techo
            // delegado del token, presupuesto LLM — la identidad viaja con el techo.
            let subject = crate::subject::Subject {
                identity: spawn_subject.identity,
                spend_limits: spawn_subject.spend_limits,
                llm_tokens: crate::llm_providers::current_delegated_llm_budget(),
                delegations: caps_spawn.borrow().delegations(),
            };
            // v0.6.45 (A1): el agente usa los mismos providers que el que lo spawnea.
            let wired = providers.borrow().clone();
            Ok(spawn_agent(sw.clone(), agent.to_string(), body, send_args, global_snap, ceiling.clone(), mem.clone(), builder.clone(), subject, wired))
        })
    };

    interp.set_swarm_hooks(SwarmHooks { share, observe, signal, wait_for, spawn });
}

/// Crea un intérprete con el wiring común + los hooks del swarm.
/// El `log_hook` manda los `log` del agente a stdout del proceso principal en tiempo
/// real — así los agentes no son silenciosos durante el desarrollo.
fn setup_swarm_interpreter(
    swarm: Arc<Swarm>,
    agent_name: &str,
    ceiling: Option<Arc<Vec<Capability>>>,
    mem: Option<MemoryCtx>,
    grant_memory: bool,
) -> (Interpreter, Rc<RefCell<CapabilitySet>>) {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("agent")));
    // Techo del host: antes de wire_common (filtra los auto-grants stdout/time/llm del
    // agente). El `Arc` compartido se reconvierte a `Rc` local del hilo del agente.
    if let Some(cl) = &ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new((**cl).clone()));
    }
    wire_common(&mut interp, &caps, false, mem.as_ref(), "my-agent");
    // Para AGENTES spawneados de un programa con memoria declarada: la declaración
    // top-level cubre a sus agentes (una identidad por programa, decisión #3) — el
    // grant pasa por `grant()` así el techo del host sigue mandando (G-2). El "main"
    // NO recibe este grant: su propio `require memory(...)` lo concede al ejecutarse.
    if grant_memory {
        if let Some(ctx) = &mem {
            caps.borrow_mut()
                .grant(Capability::new(CapabilityType::Memory, Some(ctx.name.clone())));
        }
    }
    // Propaga el techo (y el ctx de memoria) a los sub-agentes que este agente spawnee.
    wire_swarm_hooks(&mut interp, swarm, agent_name, ceiling, mem, None, &caps);
    let name = agent_name.to_string();
    // El hook del agente es un destino (lleva su prefijo), no un observador como el de `run --labels`.
    interp.log_hook_observes_only = false;
    interp.log_hook = Some(Arc::new(move |line: &str| {
        // `conform` exige stdout = SOLO el JSON final: bajo ese modo el eco vivo
        // ([main]/[agente]) va a stderr (sigue siendo visible, no rompe el parse).
        if AGENT_ECHO_TO_STDERR.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[{}] {}", name, line);
        } else {
            println!("[{}] {}", name, line);
        }
    }));
    (interp, caps)
}

/// `conform` (JSON en stdout) activa esto para desviar el eco vivo de agentes a
/// stderr. Default false: `run` conserva el eco en stdout (observabilidad en vivo).
pub static AGENT_ECHO_TO_STDERR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Lanza un agente en su propio hilo con su propio `Interpreter`. Devuelve el
/// instance_id. El estado pasa STARTING→WORKING→DONE/ERROR; el error se captura
/// (no crashea el programa) y se emite una señal `__agent_error:<id>`.
#[allow(clippy::too_many_arguments)]
fn spawn_agent(
    swarm: Arc<Swarm>,
    agent_name: String,
    body: std::sync::Arc<[Node]>,
    send_args: Vec<(String, SendValue)>,
    globals: Arc<Vec<(String, GlobalVal)>>,
    ceiling: Option<Arc<Vec<Capability>>>,
    mem: Option<MemoryCtx>,
    builder: Option<InterpBuilder>,
    subject: crate::subject::Subject,
    providers: WiredProviders,
) -> String {
    let instance_id = swarm.register_new_agent(&agent_name);
    let sw = swarm.clone();
    let id = instance_id.clone();
    // v0.6.46 (E6): el agente escribe en el registro sellado de la corrida que lo lanzó.
    let sealed_log = synsema_core::sealed::current();
    let handle = std::thread::Builder::new()
        .name(id.clone())
        .stack_size(INTERP_STACK_SIZE)
        .spawn(move || {
            let _sealed = sealed_log.map(synsema_core::sealed::install_thread);
            let (mut interp, caps) = match &builder {
                // Bajo serve: el MISMO wiring que un tick de cron (state_*, DB, approvals,
                // cron, bus, memoria, techo del host); los hooks se re-cablean con la
                // identidad del agente (share/observe/signal atribuyen por nombre).
                Some(b) => {
                    let (mut interp, caps) = b();
                    wire_swarm_hooks(&mut interp, sw.clone(), &id, ceiling.clone(), mem.clone(), Some(b.clone()), &caps);
                    (interp, caps)
                }
                // Bajo serve el builder ya cablea los providers; sin builder (`run`), los del
                // que lo spawneó.
                None => {
                    let (mut interp, caps) = setup_swarm_interpreter(sw.clone(), &id, ceiling, mem, true);
                    wire_providers(&mut interp, &providers);
                    (interp, caps)
                }
            };
            // T1: el agente corre EN NOMBRE del sujeto que lo spawneó, bajo su techo delegado
            // y sus presupuestos. El guard vive hasta el final del hilo.
            let _subject_scope = subject.apply(&mut interp, &caps);
            // Token de cancelación del agente (`agent_stop` / shutdown).
            if let Some(tok) = sw.cancel_token(&id) {
                interp.set_cancel_token(tok);
            }
            // Namespace de memoria (DB-M1 #4): el `source` de remember/recall dentro
            // del agente es su NOMBRE declarado (no el instance_id — `from = "writer"`
            // debe cruzar a ese namespace sin adivinar sufijos de instancia).
            interp.set_agent_context(&agent_name);
            // Restaurar tareas y valores del top-level para que el agente
            // los pueda llamar directamente sin necesitar HTTP.
            let registry = rebuild_globals(&mut interp, &globals, None);
            // A cargo del intérprete del agente: se vacían cuando termina (ver `adopt_module_envs`).
            interp.adopt_module_envs(registry.into_values());
            // Los spawn_args sobreescriben cualquier global con el mismo nombre.
            for (k, v) in &send_args {
                interp.set_global(k, from_send(v));
            }
            sw.set_state(&id, AgentState::Working);
            match interp.run_block(&body) {
                Ok(_) => sw.set_state(&id, AgentState::Done),
                // Cancelado cooperativamente (agent_stop/shutdown): estado STOPPED, no
                // ERROR — parar un agente no es una falla del agente.
                Err(Control::Error(_)) if interp.is_cancelled() => {
                    sw.set_state(&id, AgentState::Stopped);
                }
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

fn agent_state_str(s: AgentState) -> &'static str {
    match s {
        AgentState::Idle => "idle",
        AgentState::Starting => "starting",
        AgentState::Working => "working",
        AgentState::Waiting => "waiting",
        AgentState::Done => "done",
        AgentState::Error => "error",
        AgentState::Stopped => "stopped",
    }
}

fn run_swarm_inner(
    source: &str,
    filename: &str,
    swarm: Arc<Swarm>,
    ceiling: Option<Arc<Vec<Capability>>>,
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
            // Identidad declarada (DB-M1): también en el camino con swarm retenido
            // (`conform --swarm` / Engine::run).
            let mem_ctx = match memory_ctx_for(
                &program.statements,
                filename,
                ceiling.as_ref().map(|a| a.as_slice()),
            ) {
                Ok(m) => m,
                Err(msg) => {
                    return RunResult {
                        success: false,
                        output: Vec::new(),
                        errors: vec![format!("Runtime error: {}", msg)],
                    }
                }
            };
            let (mut interp, caps) = setup_swarm_interpreter(swarm, "main", ceiling, mem_ctx, false);
            let _operator_scope = crate::subject::Subject::operator().apply(&mut interp, &caps);
            let r = interp.execute(&program);
            note_run_steps(&interp);
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
        self.run_ceiled(source, filename, None)
    }

    /// Como `run` pero con el techo del host (`conform --swarm --sandbox/--cap-set`).
    pub fn run_ceiled(&self, source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> RunResult {
        let swarm = self.swarm.clone();
        let src = source.to_string();
        let fname = filename.to_string();
        let ceiling_arc = ceiling.map(Arc::new);
        std::thread::Builder::new()
            .stack_size(INTERP_STACK_SIZE)
            .spawn(move || run_swarm_inner(&src, &fname, swarm, ceiling_arc))
            .expect("no se pudo crear el hilo del motor")
            .join()
            .unwrap_or_else(|p| RunResult {
                success: false,
                output: Vec::new(),
                errors: vec![abort_message(&p)],
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
    run_swarm_dump_ceiled(source, filename, None)
}

/// Como `run_swarm_dump` pero con el techo del host (`conform --swarm --sandbox/--cap-set`).
pub fn run_swarm_dump_ceiled(source: &str, filename: &str, ceiling: Option<Vec<Capability>>) -> SwarmDump {
    let engine = Engine::new();
    let result = engine.run_ceiled(source, filename, ceiling);
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

#[cfg(all(test, any(target_os = "linux", windows)))]
mod v0646_e8_tests {
    use super::*;

    fn link_dir(target: &std::path::Path, link: &std::path::Path) {
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link.to_string_lossy().replace('/', "\\"))
            .arg(target.to_string_lossy().replace('/', "\\"))
            .output()
            .unwrap()
            .status
            .success());
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    /// Saca el link (una junction en Windows es un directorio; un symlink en Unix, un archivo).
    fn unlink(link: &std::path::Path) {
        if std::fs::remove_dir(link).is_err() {
            std::fs::remove_file(link).unwrap();
        }
    }

    /// v0.6.46 (E8): el template ya gateado, y DESPUÉS su carpeta pasa a ser un link afuera del
    /// grant (pero adentro del cwd): la apertura lo niega con el mensaje del link. En el orden de la
    /// ejecución real (ronda 1, E8-A3): gate, cambio, el `canonicalize` de `resolve_template_path` (que
    /// ya no ve links) y recién ahí la apertura. Un link que queda adentro, sí.
    #[test]
    fn e8_template_open_is_judged_where_it_opened() {
        // Adentro del cwd (el del crate): `render` sólo lee plantillas de ahí.
        let name = format!(".e8-tpl-test-{}", std::process::id());
        let d = std::env::current_dir().unwrap().join(&name);
        let _ = std::fs::remove_dir_all(&d);
        // Se limpia aunque falle una aserción: la carpeta vive en el crate, no en temp.
        struct Limpia(std::path::PathBuf);
        impl Drop for Limpia {
            fn drop(&mut self) {
                let sub = self.0.join("proj/sub");
                if std::fs::remove_dir(&sub).is_err() {
                    let _ = std::fs::remove_file(&sub);
                }
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _limpia = Limpia(d.clone());
        std::fs::create_dir_all(d.join("proj/real")).unwrap();
        std::fs::create_dir_all(d.join("proj/otra")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        std::fs::write(d.join("proj/real/t.html"), "adentro").unwrap();
        std::fs::write(d.join("proj/otra/t.html"), "otra").unwrap();
        std::fs::write(d.join("afuera/t.html"), "SECRETO").unwrap();
        link_dir(&d.join("proj/real"), &d.join("proj/sub"));
        let mut interp = Interpreter::new();
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        caps.borrow_mut().grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/proj/**", name))));
        wire_common(&mut interp, &caps, false, None, "t");
        let open = interp.template_open_hook().expect("el motor cablea la apertura de templates");
        let raw = format!("{}/proj/sub/t.html", name);
        let read = |f: std::fs::File| std::io::read_to_string(f).unwrap();
        let gate = || interp.gate_template_read(&raw).is_ok();
        assert!(gate());
        assert_eq!(read(open(&raw).unwrap()), "adentro");
        // La carrera: el gate pasa con `sub` → `real`, y antes de abrir `sub` lleva afuera.
        assert!(gate());
        unlink(&d.join("proj/sub"));
        link_dir(&d.join("afuera"), &d.join("proj/sub"));
        let resolved = d.join("proj/sub/t.html").canonicalize().unwrap();
        assert!(resolved.ends_with("afuera/t.html") || resolved.ends_with("afuera\\t.html"));
        let e = open(&raw).unwrap_err();
        assert!(e.message.contains("a link (symlink or junction) on the way leads outside"), "{}", e.message);
        // Un link que queda adentro del grant, sí.
        unlink(&d.join("proj/sub"));
        link_dir(&d.join("proj/otra"), &d.join("proj/sub"));
        assert_eq!(read(open(&raw).unwrap()), "otra");
    }
}
