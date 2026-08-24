//! synsema-wasm — el intérprete Synsema como artefacto WebAssembly (biblioteca).
//!
//! Una sola verdad del wiring PURO (`wire_pure`) para los dos artefactos wasm:
//! - el bin wasip1 de este crate (`main.rs`: CLI para wasmtime / TEEs / runners), y
//! - el cdylib `synsema-wasm-web` (`wasm32-unknown-unknown`: navegador, Node/Bun/Deno,
//!   Python vía wasmtime-py, Go vía wazero — ABI JSON + hooks del host).
//!
//! API embebible (sin tipos de Rust en la frontera final — la frontera JSON la arma
//! synsema-wasm-web sobre estas funciones):
//! - [`run`]     → salida de `print` + errores + audit de capabilities.
//! - [`test`]    → los bloques `test` del archivo.
//! - [`check`]   → parse + validaciones estáticas (declaración de memoria).
//! - [`handle`]  → `serve` en modo handler: un request → una respuesta (edge).
//! - [`version`].
//!
//! El perfil puro es el MISMO lenguaje en un entorno que sólo otorga lo que el host
//! presta (`hostcap::HostProvider`): red (`fetch`/`http_*`/RPC read-side) si el host
//! ofrece `http`; LLM real si ofrece `llm`; memoria persistente (`remember`/`recall`/
//! progress/rules) y `state_*` si ofrece `kv`. Lo que el host NO presta falla con la
//! verdad del entorno — nunca con "Undefined variable". El programa sigue teniendo
//! que declarar (`require net/llm/memory`) y el techo del embebedor (`ceiling`)
//! sigue mandando: ningún hook del host se llama sin pasar por `caps.require`.
//!
//! El wiring espeja el subconjunto puro de `wire_common_with_state` de
//! synsema-runtime/src/engine.rs (que no compila a wasm por sus módulos nativos);
//! si aquel cambia hooks o registraciones puras, esto se actualiza a mano.

pub mod handler;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use synsema_agents::builtins::{
    register_agent_builtins, register_serve_memory_builtins, register_serve_progress_builtins,
    register_shared_rules_builtins, MemoryGate,
};
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_capabilities::model::{
    capability_type_from_name, validate_memory_name, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::ast::{Node, NodeKind, Program};
use synsema_core::interpreter::{Control, Interpreter, RunResult, RuntimeError};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{syn_bool, syn_list, syn_map, SynValue};
use synsema_stdlib::hostcap::{self, HostProvider};
use synsema_stdlib::json::{dumps, json_to_syn, syn_to_json};
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

pub use synsema_capabilities::model::build_ceiling;
pub use synsema_stdlib::hostcap::{HostHttpRequest, HostLlmResult, HttpResult};

pub(crate) fn rt_err(msg: &str) -> Control {
    Control::Error(RuntimeError::new(msg.to_string()))
}

/// Versión del artefacto: el tag del release (`SYNSEMA_VERSION`, lo setea release.yml)
/// o `v<crate>-dev` en un build desde fuente — misma regla que el binario nativo.
pub fn version() -> String {
    match option_env!("SYNSEMA_VERSION") {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => format!("v{}-dev", env!("CARGO_PKG_VERSION")),
    }
}

// =========================================================
// Opciones + reportes (la API embebible)
// =========================================================

/// Cómo correr un programa. `env` reemplaza al `.env`/environ (un host sin FS ni
/// proceso lo pasa como mapa); `None` = `EnvStore::load_default()` (el bin wasip1 lee
/// `.env` por WASI). `ceiling` = techo del host (`--sandbox`/`--cap-set`, ver
/// [`parse_ceiling`]).
#[derive(Default)]
pub struct RunOptions {
    pub filename: String,
    pub env: Option<HashMap<String, String>>,
    pub ceiling: Option<Vec<Capability>>,
    /// El host NO tiene filesystem (navegador, Node sin WASI…): los builtins de archivos
    /// existen y lo dicen. `false` en el bin wasip1 (FS por WASI, `--dir`).
    pub no_fs: bool,
}

impl RunOptions {
    pub fn new(filename: &str) -> Self {
        RunOptions { filename: filename.to_string(), env: None, ceiling: None, no_fs: false }
    }
}

/// `"sandbox"` → techo [stdout, time]; otro texto → la lista de `--cap-set`
/// (`"stdout,secret=ETH_*"`); vacío → sin techo.
pub fn parse_ceiling(spec: &str) -> Result<Option<Vec<Capability>>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    if spec == "sandbox" {
        return build_ceiling(true, None);
    }
    build_ceiling(false, Some(spec))
}

/// Una entrada del audit log de capabilities: lo que el programa pidió y si se le
/// concedió — el embebedor ve qué hizo el programa con sus capabilities.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub capability: String,
    pub granted: bool,
    pub source: String,
    pub reason: String,
}

fn export_audit(caps: &Rc<RefCell<CapabilitySet>>) -> Vec<AuditEntry> {
    caps.borrow()
        .audit_log
        .iter()
        .map(|e| AuditEntry {
            capability: e.capability.to_string(),
            granted: e.granted,
            source: e.source.clone(),
            reason: e.reason.clone(),
        })
        .collect()
}

pub struct Report {
    pub ok: bool,
    pub output: Vec<String>,
    pub errors: Vec<String>,
    pub audit: Vec<AuditEntry>,
    /// Tokens LLM consumidos vía el hook `llm` del host (lo que `llm_usage()` ve).
    pub llm_tokens: u64,
}

pub struct TestReport {
    pub passed: usize,
    pub failed: usize,
    pub lines: Vec<String>,
    pub audit: Vec<AuditEntry>,
}

pub struct CheckReport {
    pub ok: bool,
    pub errors: Vec<String>,
}

// =========================================================
// Estado compartido del wiring (memoria declarada, tokens LLM)
// =========================================================

thread_local! {
    /// Tokens LLM acumulados por el hook `llm` del host (una cuenta por instancia
    /// wasm, como `llm_tokens_total` del proceso nativo).
    static LLM_TOKENS: RefCell<u64> = const { RefCell::new(0) };
}

/// Tokens LLM acumulados en esta instancia (lo que devuelve `llm_usage()`).
pub fn llm_tokens_total() -> u64 {
    LLM_TOKENS.with(|t| *t.borrow())
}

/// Escanea las declaraciones `require memory("<nombre>")` del TOP-LEVEL (mismo
/// criterio que `declared_memory_name` del runtime: sólo literales, una sola
/// identidad, G-6). `Ok(None)` = sin memoria declarada.
pub fn declared_memory_name(statements: &[Node]) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    for stmt in statements {
        if let NodeKind::RequireStatement { capability, scope } = &stmt.kind {
            if capability != "memory" {
                continue;
            }
            if let Some(scope_node) = scope {
                if let NodeKind::TextLiteral { value } = &scope_node.kind {
                    validate_memory_name(value)?;
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

/// Nombre de memoria sugerido en el error sin declaración (stem del archivo).
fn suggested_memory_name(filename: &str) -> String {
    let stem = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .trim_end_matches(".syn")
        .trim_end_matches(".fsyn");
    let cleaned: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    if cleaned.is_empty() || filename == "<stdin>" {
        "my-agent".to_string()
    } else {
        cleaned
    }
}

/// Namespace del KV del host para una memoria declarada: `memory:<nombre>` — la
/// identidad sigue siendo el NOMBRE DECLARADO (doctrina DB-M1), en cualquier host.
pub fn memory_namespace(name: &str) -> String {
    format!("memory:{}", name)
}

/// Contexto de la memoria DECLARADA respaldada por el KV del host.
pub struct HostMemoryCtx {
    pub name: String,
    pub memory: Arc<Mutex<AgentMemory>>,
    pub progress: Arc<Mutex<ProgressManager>>,
}

/// Abre (carga) la memoria declarada desde el KV del host. `None` si el programa no
/// declara memoria o el host no ofrece `kv` (entonces la familia falla con el gate).
fn open_host_memory(name: &str, host: Option<&Rc<dyn HostProvider>>) -> Option<HostMemoryCtx> {
    let host = host?;
    if !host.offers("kv") {
        return None;
    }
    let ns = memory_namespace(name);
    let mut mem = AgentMemory::new();
    mem.backend = Some("host-kv".to_string());
    if let Some(Some(json)) = host.kv_get(&ns, "memory") {
        mem.load_json(&json);
    }
    let mut prog = ProgressManager::new();
    if let Some(Some(json)) = host.kv_get(&ns, "progress") {
        prog.load_json(&json);
    }
    Some(HostMemoryCtx {
        name: name.to_string(),
        memory: Arc::new(Mutex::new(mem)),
        progress: Arc::new(Mutex::new(prog)),
    })
}

fn kv_write(ns: &str, key: &str, value: &str) {
    if let Some(p) = hostcap::provider() {
        if let Some(Err(e)) = p.kv_set(ns, key, value) {
            hostcap::log(&format!("synsema: warning: host kv write failed ({}/{}): {}", ns, key, e));
        }
    }
}

// =========================================================
// Wiring puro
// =========================================================

/// Lo que `wire_pure` necesita además del intérprete y el CapabilitySet.
pub struct WireCtx<'a> {
    pub env: Rc<EnvStore>,
    /// Statements del programa (para la declaración de memoria).
    pub statements: &'a [Node],
    pub filename: &'a str,
    pub no_fs: bool,
}

/// Cablea el perfil puro: builtins puros de la stdlib, hooks de capabilities
/// (grant/sandbox/tool-scope/llm), parallel_map secuencial, y — según lo que el host
/// ofrezca — red, LLM, memoria y `state_*`. Idempotente por intérprete.
pub fn wire_pure(interp: &mut Interpreter, caps: &Rc<RefCell<CapabilitySet>>, ctx: &WireCtx<'_>) {
    let host = hostcap::provider();

    // No-secure (paridad con `synsema run`): stdout/time/llm auto-concedidas; el
    // resto lo conceden los `require` del programa vía el grant hook de abajo.
    caps.borrow_mut().grant(Capability::new(CapabilityType::Stdout, None));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Time, None));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Llm, None));

    register_secure_builtins(interp, caps.clone());
    if ctx.no_fs {
        register_no_fs_stubs(interp);
    }
    register_secret_builtins(interp, caps.clone(), ctx.env.clone());
    synsema_stdlib::hashing::register_hash_builtins(interp);
    synsema_stdlib::json::register_json_builtins(interp);
    synsema_stdlib::webauth::register_webauth_builtins(interp, caps.clone());
    synsema_stdlib::httpsig::register_httpsig_builtins(interp, caps.clone());
    synsema_stdlib::captoken::register_captoken_builtins(interp);
    synsema_stdlib::oidc::register_oidc_builtins(interp, caps.clone());
    synsema_stdlib::blockchain::register_blockchain_builtins(interp, caps.clone());
    synsema_stdlib::spend::register_spend_builtins(interp, caps.clone());
    // Respuesta + vocabulario content() (respond.rs, puro): ok/created/…/page/heading/
    // prose/content — registra también charts y raster, el MISMO camino que el nativo.
    synsema_stdlib::respond::register_serve_builtins(interp);
    // Red (F3): los seis builtins cliente, gateados por `net(host)` ANTES del transporte;
    // el transporte es el `http` del host o el stub "sin transporte" (http_stub.rs).
    synsema_stdlib::http::register_http_builtins(interp, caps.clone());
    // Lo que este perfil NO compila (WebSocket, DB, scheduler): los nombres EXISTEN y
    // fallan con la verdad del entorno. "Undefined variable: 'sql'" haría creer que el
    // nombre no existe o está mal escrito; el error debe nombrar el problema y el fix.
    register_unavailable_stubs(interp);

    // sleep(): el de secure.rs usa std::thread::sleep, que en un host sin SO panica;
    // acá va por el reloj del motor (pausa del host o no-op). Misma capability `time`.
    {
        let caps_sleep = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |_i, args, _loc| {
                caps_sleep
                    .borrow_mut()
                    .require(&Capability::new(CapabilityType::Time, None), "sleep()")
                    .map_err(|v| Control::Error(RuntimeError::new(v.message)))?;
                let secs = match args.first() {
                    Some(SynValue::Number(n)) => n.to_f64(),
                    _ => 0.0,
                };
                synsema_core::clock::sleep_secs(secs.clamp(0.0, 3600.0));
                Ok(SynValue::Nothing)
            }),
        );
    }

    // chunk + parallel_map: en wasm no hay threads — chunk es puro (misma validación
    // que runtime/parallel.rs) y parallel_map corre SECUENCIAL con la misma semántica
    // observable (resultados en orden de entrada, fail-fast en el primer error, como
    // el `apply` secuencial). `limit` se acepta y se ignora: es un knob de
    // paralelismo, no de semántica.
    interp.register_builtin(
        "chunk",
        2,
        Rc::new(|_i, args, _loc| {
            let list = match args.first() {
                Some(SynValue::List(l)) => l.borrow().clone(),
                _ => return Err(rt_err("chunk: first argument must be a list")),
            };
            let size = match args.get(1) {
                Some(SynValue::Number(n)) => n.to_i64_trunc().unwrap_or(0),
                _ => return Err(rt_err("chunk: size must be a number")),
            };
            if size <= 0 {
                return Err(rt_err("chunk size must be positive"));
            }
            let size = size as usize;
            let chunks: Vec<SynValue> =
                list.chunks(size).map(|c| syn_list(c.to_vec())).collect();
            Ok(syn_list(chunks))
        }),
    );
    interp.register_builtin(
        "parallel_map",
        -1,
        Rc::new(|i, args, _loc| {
            let task = match args.first() {
                Some(t @ (SynValue::Task(_) | SynValue::Builtin(_))) => t.clone(),
                _ => return Err(rt_err("parallel_map: first argument must be a task")),
            };
            let list = match args.get(1) {
                Some(SynValue::List(l)) => l.borrow().clone(),
                _ => return Err(rt_err("parallel_map: second argument must be a list")),
            };
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                out.push(i.call_task(task.clone(), vec![item])?);
            }
            Ok(syn_list(out))
        }),
    );

    // Familia de estado persistente (F4). Tres casos, todos con la verdad del entorno:
    //  - sin `require memory("x")`: error de capability + la sugerencia (como nativo);
    //  - declarada pero el host no ofrece `kv`: error que lo dice;
    //  - declarada y el host ofrece `kv`: stores compartidos cargados del KV y
    //    persistidos on-write (misma maquinaria que run/serve nativo, G-9), gateados por
    //    `memory("x")` contra el CapabilitySet VIVO (sandbox/tool-scope/techo).
    let declared = match declared_memory_name(ctx.statements) {
        Ok(d) => d,
        Err(e) => {
            hostcap::log(&format!("synsema: warning: {}", e));
            None
        }
    };
    let suggest = suggested_memory_name(ctx.filename);
    let gate: MemoryGate = match &declared {
        None => Rc::new(move || {
            Err(format!(
                "Capability not granted: memory. Persistent agent state (remember/recall, rules, progress) requires a declared memory — the declared name identifies its store. Add: require memory(\"{}\") at the top of the program",
                suggest
            ))
        }),
        Some(name) => {
            let caps_m = caps.clone();
            let name = name.clone();
            let has_kv = host.as_ref().is_some_and(|h| h.offers("kv"));
            Rc::new(move || {
                caps_m
                    .borrow_mut()
                    .require(&Capability::new(CapabilityType::Memory, Some(name.clone())), "memory builtin")
                    .map_err(|v| v.message)?;
                if !has_kv {
                    return Err(format!(
                        "memory \"{}\" is declared but this host provides no durable storage (wasm profile) — the embedder can offer it through the `kv` host hook, or run the program with the native `synsema` binary",
                        name
                    ));
                }
                Ok(())
            })
        }
    };
    register_agent_builtins(
        interp,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
        gate.clone(),
    );
    if let Some(name) = &declared {
        if let Some(mctx) = open_host_memory(name, host.as_ref()) {
            let ns = memory_namespace(name);
            let ns_m = ns.clone();
            let on_write_mem: Arc<dyn Fn(&AgentMemory) + Send + Sync> =
                Arc::new(move |m: &AgentMemory| kv_write(&ns_m, "memory", &m.to_json()));
            let ns_p = ns.clone();
            let on_write_prog: Arc<dyn Fn(&ProgressManager) + Send + Sync> =
                Arc::new(move |p: &ProgressManager| kv_write(&ns_p, "progress", &p.to_json()));
            register_serve_memory_builtins(interp, mctx.memory.clone(), on_write_mem.clone(), gate.clone());
            register_serve_progress_builtins(interp, mctx.progress.clone(), on_write_prog, gate.clone());
            register_shared_rules_builtins(interp, mctx.memory.clone(), on_write_mem, gate.clone());
        }
    }

    // state_* (el estado compartido de serve): sobre el KV del host (namespace `state`)
    // si lo ofrece — durable entre requests/invocaciones del handler —; si no, un mapa
    // en memoria de ESTE intérprete (vive lo que la instancia).
    register_state_builtins(interp, host.as_ref().is_some_and(|h| h.offers("kv")));

    // LLM (F3): si el host ofrece `llm`, las ops reason/decide/analyze/generate van al
    // host (llm_available() = true; llm_usage() suma los tokens que el host reporte).
    // Sin él: placeholders offline del core, como hasta ahora. `require llm` no cambia.
    if host.as_ref().is_some_and(|h| h.offers("llm")) {
        interp.set_llm_callback(Rc::new(|op: &str, prompt: &str| {
            match hostcap::provider().and_then(|p| p.llm(op, prompt)) {
                Some(r) => {
                    LLM_TOKENS.with(|t| *t.borrow_mut() += r.tokens);
                    r.content
                }
                None => format!("[llm: the host returned no answer for {}]", op),
            }
        }));
        interp.set_llm_usage_callback(Rc::new(llm_tokens_total));
    }

    // render real (sobrescribe el placeholder de core) — mismo snippet que engine.rs.
    interp.register_builtin(
        "render",
        -1,
        Rc::new(|i, args, _loc| {
            let path = args.first().map(|v| v.to_string()).unwrap_or_default();
            let html = synsema_core::templates::render_template(i, &path, args.get(1))?;
            Ok(synsema_core::templates::make_raw(html, "text/html; charset=utf-8", 200))
        }),
    );

    // Grant hook: `require X(scope)` concede — con los mismos avisos que el runtime
    // para los grants sin scope que amplían poder (reveal/sign/spend/wallet). Los
    // avisos van al log del host (stderr en wasip1).
    let c = caps.clone();
    interp.set_grant_hook(Rc::new(move |name, scope| {
        if let Some(ty) = capability_type_from_name(name) {
            if ty == CapabilityType::Reveal && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require reveal` permits revealing ANY secret; \
                     scope it with `require reveal(\"NAME\")` (the name/label of the secret)",
                );
            }
            if ty == CapabilityType::Sign && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require sign` permits signing with ANY key; \
                     scope it with `require sign(\"KEY_NAME\")` (the name of the key's secret)",
                );
            }
            if ty == CapabilityType::Spend && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require spend` permits spending in ANY unit; \
                     scope it with `require spend(\"USD\")` (the unit being spent)",
                );
            }
            if ty == CapabilityType::Wallet && scope.is_none() {
                hostcap::log(
                    "synsema: warning: bare `require wallet` permits creating custody from ANY secret; \
                     scope it with `require wallet(\"NAME\")` (the source secret's name, or the new \
                     secret's label when generating)",
                );
            }
            c.borrow_mut().grant(Capability::new(ty, scope.map(|s| s.to_string())));
        }
    }));

    // Gate de las ops LLM (reason/decide/analyze/generate): auto-concedida arriba,
    // pero el chequeo queda auditado en el mismo CapabilitySet (paridad runtime).
    let caps_llm = caps.clone();
    interp.set_llm_cap_hook(Rc::new(move || {
        caps_llm
            .borrow_mut()
            .require(&Capability::new(CapabilityType::Llm, None), "llm operation")
            .map_err(|v| v.message)
    }));

    // Aislamiento de `sandbox`: guarda y VACÍA el CapabilitySet al entrar; restaura
    // al salir (stack para anidados) — idéntico al runtime.
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

    // Aislamiento por-tool (least-privilege): la tool corre con sus caps declaradas
    // ∩ las del agente, sin heredar el padre — idéntico al runtime.
    #[allow(clippy::type_complexity)]
    let saved_tool: Rc<RefCell<Vec<(HashSet<Capability>, HashSet<Capability>, Option<Rc<RefCell<CapabilitySet>>>)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let caps_tool = caps.clone();
    interp.set_tool_scope_hook(Rc::new(move |entering, declared: &[(String, Option<String>)]| {
        let mut cs = caps_tool.borrow_mut();
        if entering {
            let mut allowed: HashSet<Capability> = HashSet::new();
            for (name, scope) in declared {
                if let Some(ty) = capability_type_from_name(name) {
                    let cap = Capability::new(ty, scope.clone());
                    if cs.check(&cap, "tool-scope") {
                        allowed.insert(cap);
                    }
                }
            }
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

/// `state_set/get/incr/delete/all` (paridad con serve.rs). Con `host_kv`, cada valor
/// vive en el KV del host bajo el namespace `state` (JSON); sin él, en un mapa de
/// este intérprete.
fn register_state_builtins(interp: &Interpreter, host_kv: bool) {
    const NS: &str = "state";
    let local: Rc<RefCell<IndexMap<String, SynValue>>> = Rc::new(RefCell::new(IndexMap::new()));

    fn load(host_kv: bool, local: &Rc<RefCell<IndexMap<String, SynValue>>>, key: &str) -> Option<SynValue> {
        if host_kv {
            let raw = hostcap::provider().and_then(|p| p.kv_get(NS, key)).flatten()?;
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            Some(json_to_syn(&v))
        } else {
            local.borrow().get(key).cloned()
        }
    }
    fn store(host_kv: bool, local: &Rc<RefCell<IndexMap<String, SynValue>>>, key: &str, v: &SynValue) {
        if host_kv {
            kv_write(NS, key, &dumps(&syn_to_json(v)));
        } else {
            local.borrow_mut().insert(key.to_string(), v.clone());
        }
    }
    fn key_arg(args: &[SynValue], who: &str) -> Result<String, Control> {
        match args.first() {
            Some(v) => Ok(v.to_string()),
            None => Err(rt_err(&format!("{}: missing key", who))),
        }
    }

    {
        let l = local.clone();
        interp.register_builtin("state_set", 2, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_set")?;
            let val = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            store(host_kv, &l, &key, &val);
            Ok(val)
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_get", -1, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_get")?;
            Ok(load(host_kv, &l, &key).unwrap_or_else(|| args.get(1).cloned().unwrap_or(SynValue::Nothing)))
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_incr", -1, Rc::new(move |_i, args, _l| {
            use synsema_core::number::Number;
            let key = key_arg(args, "state_incr")?;
            let delta = match args.get(1) {
                Some(SynValue::Number(n)) => n.clone(),
                _ => Number::Int(1),
            };
            let current = match load(host_kv, &l, &key) {
                Some(SynValue::Number(n)) => n,
                _ => Number::Int(0),
            };
            // Entero cuando AMBOS son Int (contadores → JSON `1`, no `1.0`); Float si no.
            let new_val = match (&current, &delta) {
                (Number::Int(a), Number::Int(b)) => Number::Int(a + b),
                _ => Number::Float(current.to_f64() + delta.to_f64()),
            };
            let v = SynValue::Number(new_val);
            store(host_kv, &l, &key, &v);
            Ok(v)
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_delete", 1, Rc::new(move |_i, args, _l| {
            let key = key_arg(args, "state_delete")?;
            if host_kv {
                if let Some(p) = hostcap::provider() {
                    let _ = p.kv_delete(NS, &key);
                }
            } else {
                l.borrow_mut().shift_remove(&key);
            }
            Ok(syn_bool(true))
        }));
    }
    {
        let l = local.clone();
        interp.register_builtin("state_all", 0, Rc::new(move |_i, _args, _l| {
            let mut map = IndexMap::new();
            if host_kv {
                if let Some(p) = hostcap::provider() {
                    for k in p.kv_list(NS).unwrap_or_default() {
                        if let Some(v) = load(true, &l, &k) {
                            map.insert(k, v);
                        }
                    }
                }
            } else {
                for (k, v) in l.borrow().iter() {
                    map.insert(k.clone(), v.clone());
                }
            }
            Ok(syn_map(map))
        }));
    }
}

/// Builtins de los módulos `native` que este perfil no compila (ws/database/cron):
/// se registran como stubs que fallan con un error claro. La lista espeja las
/// registraciones de esos módulos; si uno suma un builtin, se suma acá (la sonda
/// `tests/wasm_unavailable.probe.syn` cubre un representante de cada familia).
/// Los de red (`fetch`/`http_*`) YA NO son stubs: son los builtins reales sobre el
/// transporte del host (F3); `mtls_identity` sí (identidad TLS del proceso).
pub fn register_unavailable_stubs(interp: &Interpreter) {
    const NET: &[&str] = &[
        "mtls_identity",
        "ws_connect", "ws_send", "ws_recv", "ws_close", "ws_status", "ws_stats",
        "ws_select", "ws_select_all", "ws_broadcast",
    ];
    const DB: &[&str] = &[
        "db_open", "db_close", "sql", "sql_exec", "sql_tables", "sql_batch", "paged",
        "mongo_find", "mongo_find_one", "mongo_insert", "mongo_insert_many", "mongo_update",
        "mongo_delete", "mongo_count", "mongo_aggregate", "mongo_collections",
        "redis_get", "redis_set", "redis_del", "redis_exists", "redis_expire", "redis_ttl",
        "redis_persist", "redis_type", "redis_keys", "redis_incr", "redis_incrby",
        "redis_decr", "redis_mget", "redis_mset", "redis_hget", "redis_hset", "redis_hdel",
        "redis_hgetall", "redis_hincrby", "redis_lpush", "redis_rpush", "redis_lpop",
        "redis_rpop", "redis_lrange", "redis_llen", "redis_sadd", "redis_srem",
        "redis_smembers", "redis_sismember", "redis_lock", "redis_unlock",
    ];
    const CRON: &[&str] = &["cron_every", "cron_after", "cron_cancel", "cron_list", "cron_status"];
    let families: [(&[&str], &str); 3] = [
        (NET, "this build has no network sockets (WebSocket/TLS identity need an event loop and a process)"),
        (DB, "this build has no database drivers"),
        (CRON, "this build has no scheduler threads"),
    ];
    for (names, why) in families {
        for name in names {
            let name: &'static str = name;
            let why: &'static str = why;
            interp.register_builtin(
                name,
                -1,
                Rc::new(move |_i, _args, _loc| {
                    Err(rt_err(&format!(
                        "{}: not available in the wasm profile — {} (run the program with the \
                         native `synsema` binary)",
                        name, why
                    )))
                }),
            );
        }
    }
}

/// Builtins de archivos para un host SIN filesystem (navegador, Node sin WASI…): los
/// nombres existen y fallan diciendo la verdad. El bin wasip1 NO los registra (tiene
/// FS por WASI, `--dir`); los registra synsema-wasm-web.
pub fn register_no_fs_stubs(interp: &Interpreter) {
    const FS: &[&str] = &[
        "read_file", "read_file_bytes", "write_file", "append_file", "edit_file", "list_dir",
        "file_info", "file_exists", "grep", "run",
    ];
    for name in FS {
        let name: &'static str = name;
        interp.register_builtin(
            name,
            -1,
            Rc::new(move |_i, _args, _loc| {
                Err(rt_err(&format!(
                    "{}: this host has no filesystem — pass data in through the program's \
                     source/env, or run the program with the native `synsema` binary (or the \
                     wasip1 build under wasmtime with --dir)",
                    name
                )))
            }),
        );
    }
}

// =========================================================
// run / test / check
// =========================================================

fn parse_errors(e: CompileError) -> String {
    match e {
        CompileError::Lex(e) => format!("Lexer error: {}", e),
        CompileError::Parse(e) => format!("Parse error: {}", e),
    }
}

fn env_store(opts: &RunOptions) -> Rc<EnvStore> {
    Rc::new(match &opts.env {
        Some(vars) => EnvStore::from_vars(vars.clone()),
        None => EnvStore::load_default(),
    })
}

/// Intérprete + CapabilitySet cableados para `program`, con el techo aplicado ANTES
/// de los auto-grants (idéntico al runtime).
pub(crate) fn prepare(program: &Program, opts: &RunOptions) -> (Interpreter, Rc<RefCell<CapabilitySet>>) {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    if let Some(cl) = &opts.ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new(cl.clone()));
    }
    let ctx = WireCtx { env: env_store(opts), statements: &program.statements, filename: &opts.filename, no_fs: opts.no_fs };
    wire_pure(&mut interp, &caps, &ctx);
    (interp, caps)
}

pub(crate) fn finish(mut interp: Interpreter, result: Result<SynValue, Control>) -> RunResult {
    finish_keep(&mut interp, result)
}

/// Como `finish` pero sin consumir el intérprete (el handler-mode lo conserva).
pub(crate) fn finish_keep(interp: &mut Interpreter, result: Result<SynValue, Control>) -> RunResult {
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

/// Corre el programa. Nunca panica por un error del programa: parse/runtime van a
/// `errors`; la salida de `print` a `output` (el core la colecta con
/// `live_output = false` — no se toca stdout).
pub fn run(source: &str, opts: &RunOptions) -> Report {
    let program = match parse_source(source, &opts.filename) {
        Err(e) => {
            return Report { ok: false, output: Vec::new(), errors: vec![parse_errors(e)], audit: Vec::new(), llm_tokens: 0 }
        }
        Ok(p) => p,
    };
    let (mut interp, caps) = prepare(&program, opts);
    let result = interp.execute(&program);
    let r = finish(interp, result);
    Report { ok: r.success, output: r.output, errors: r.errors, audit: export_audit(&caps), llm_tokens: llm_tokens_total() }
}

/// Corre los bloques `test` del archivo con el mismo wiring puro.
pub fn test(source: &str, opts: &RunOptions) -> TestReport {
    let program = match parse_source(source, &opts.filename) {
        Err(e) => return TestReport { passed: 0, failed: 1, lines: vec![parse_errors(e)], audit: Vec::new() },
        Ok(p) => p,
    };
    let (mut interp, caps) = prepare(&program, opts);
    let outcomes = interp.run_test_blocks(&program);
    let mut lines = Vec::with_capacity(outcomes.len());
    let mut passed = 0usize;
    for o in &outcomes {
        if o.passed {
            passed += 1;
            lines.push(format!("  ok  {}", o.name));
        } else {
            let msg = o.message.clone().unwrap_or_default();
            lines.push(format!("FAIL  {} — {}", o.name, msg));
        }
    }
    let failed = outcomes.len() - passed;
    TestReport { passed, failed, lines, audit: export_audit(&caps) }
}

/// Parse + validaciones estáticas (sin ejecutar): lexer/parser y la declaración de
/// memoria (nombre válido, una sola identidad).
pub fn check(source: &str, filename: &str) -> CheckReport {
    let program = match parse_source(source, filename) {
        Err(e) => return CheckReport { ok: false, errors: vec![parse_errors(e)] },
        Ok(p) => p,
    };
    let mut errors = Vec::new();
    if let Err(e) = declared_memory_name(&program.statements) {
        errors.push(e);
    }
    CheckReport { ok: errors.is_empty(), errors }
}

pub use handler::{handle, HandleReport, HttpRequestIn, HttpResponseOut};
