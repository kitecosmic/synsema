//! synsema-wasm — el intérprete Synsema como artefacto WebAssembly.
//!
//! Un binario chico para `wasm32-wasip1`: lee un `.syn` (path, o `-` = stdin), lo
//! corre con el perfil PURO de la stdlib e imprime la salida; `--test` corre los
//! bloques `test` del archivo. El host (wasmtime, un TEE, un worker de edge) carga
//! el `.wasm` y le da el programa — nadie instala Synsema en el host.
//!
//! El perfil puro es el MISMO lenguaje en un entorno que no otorga net/sql/serve:
//! los builtins de red/DB/server no se registran (o fallan con error claro vía el
//! stub de http) — la doctrina deny-by-default contada por el entorno, no un
//! dialecto. Las ops LLM caen a los placeholders del core (offline), los gates
//! humanos a sus fallbacks deterministas, y la memoria persistente falla con un
//! error que lo dice (un job wasm no tiene almacenamiento durable).
//!
//! El wiring espeja el subconjunto puro de `wire_common_with_state` de
//! synsema-runtime/src/engine.rs (que no compila a wasm por sus módulos nativos);
//! si aquel cambia hooks o registraciones puras, esto se actualiza a mano.
//!
//! Compila también nativo: `cargo test --workspace` lo construye y el smoke test
//! corre sin toolchain wasm (mismo main, hilo con stack grande en vez del stack
//! linkeado del target wasm).

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::Read;
use std::rc::Rc;

use synsema_agents::builtins::{register_agent_builtins, MemoryGate};
use synsema_agents::memory::AgentMemory;
use synsema_agents::progress::ProgressManager;
use synsema_capabilities::model::{
    capability_type_from_name, Capability, CapabilitySet, CapabilityType,
};
use synsema_capabilities::secure::register_secure_builtins;
use synsema_core::interpreter::{Control, Interpreter, RunResult, RuntimeError};
use synsema_core::parser::{parse_source, CompileError};
use synsema_core::types::{syn_list, SynValue};
use synsema_stdlib::secrets::{register_secret_builtins, EnvStore};

fn rt_err(msg: &str) -> Control {
    Control::Error(RuntimeError::new(msg.to_string()))
}

/// Mismo criterio que INTERP_STACK_SIZE del runtime (tree-walking recursivo). En
/// wasm el stack se fija al linkear (ver .cargo/config.toml); esto es el fallback
/// del build nativo.
#[cfg(not(target_family = "wasm"))]
const NATIVE_STACK: usize = 512 * 1024 * 1024;

fn wire_pure(interp: &mut Interpreter, caps: &Rc<RefCell<CapabilitySet>>) {
    // No-secure (paridad con `synsema run`): stdout/time/llm auto-concedidas; el
    // resto lo conceden los `require` del programa vía el grant hook de abajo.
    caps.borrow_mut().grant(Capability::new(CapabilityType::Stdout, None));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Time, None));
    caps.borrow_mut().grant(Capability::new(CapabilityType::Llm, None));

    register_secure_builtins(interp, caps.clone());
    register_secret_builtins(interp, caps.clone(), Rc::new(EnvStore::load_default()));
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

    // Familia de estado persistente: los builtins EXISTEN y fallan con la verdad
    // del entorno (sin almacenamiento durable), no con "unknown function".
    let gate: MemoryGate = Rc::new(|| {
        Err("Capability not granted: memory. Persistent agent state (remember/recall, \
             rules, progress) needs durable storage, and this wasm build has none — \
             run the program with the native binary to use a declared memory"
            .to_string())
    });
    register_agent_builtins(
        interp,
        Rc::new(RefCell::new(ProgressManager::new())),
        Rc::new(RefCell::new(AgentMemory::new())),
        gate,
    );

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
    // para los grants sin scope que amplían poder (reveal/sign/spend/wallet).
    let c = caps.clone();
    interp.set_grant_hook(Rc::new(move |name, scope| {
        if let Some(ty) = capability_type_from_name(name) {
            if ty == CapabilityType::Reveal && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require reveal` permits revealing ANY secret; \
                     scope it with `require reveal(\"NAME\")` (the name/label of the secret)"
                );
            }
            if ty == CapabilityType::Sign && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require sign` permits signing with ANY key; \
                     scope it with `require sign(\"KEY_NAME\")` (the name of the key's secret)"
                );
            }
            if ty == CapabilityType::Spend && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require spend` permits spending in ANY unit; \
                     scope it with `require spend(\"USD\")` (the unit being spent)"
                );
            }
            if ty == CapabilityType::Wallet && scope.is_none() {
                eprintln!(
                    "synsema: warning: bare `require wallet` permits creating custody from ANY secret; \
                     scope it with `require wallet(\"NAME\")` (the source secret's name, or the new \
                     secret's label when generating)"
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

fn run_program(source: &str, filename: &str) -> RunResult {
    let program = match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => {
            return RunResult {
                success: false,
                output: Vec::new(),
                errors: vec![format!("Lexer error: {}", e)],
            }
        }
        Err(CompileError::Parse(e)) => {
            return RunResult {
                success: false,
                output: Vec::new(),
                errors: vec![format!("Parse error: {}", e)],
            }
        }
        Ok(p) => p,
    };
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    wire_pure(&mut interp, &caps);
    let result = interp.execute(&program);
    match result {
        Ok(_) => RunResult {
            success: true,
            output: std::mem::take(&mut interp.output),
            errors: Vec::new(),
        },
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

/// `--test`: corre los bloques `test` con el mismo wiring puro. Devuelve
/// (líneas de reporte, pasados, fallados).
fn run_tests(source: &str, filename: &str) -> (Vec<String>, usize, usize) {
    let program = match parse_source(source, filename) {
        Err(CompileError::Lex(e)) => return (vec![format!("Lexer error: {}", e)], 0, 1),
        Err(CompileError::Parse(e)) => return (vec![format!("Parse error: {}", e)], 0, 1),
        Ok(p) => p,
    };
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("program")));
    wire_pure(&mut interp, &caps);
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
    (lines, passed, failed)
}

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
    let mut test_mode = false;
    let mut path: Option<String> = None;
    for a in &args[1..] {
        match a.as_str() {
            "--test" => test_mode = true,
            "--help" | "-h" => {
                println!(
                    "synsema-wasm — run a Synsema program (pure profile)\n\n\
                     usage: synsema-wasm [--test] <file.syn | ->\n\n\
                     --test  run the file's `test` blocks instead of the program\n\
                     -       read the program from stdin"
                );
                return;
            }
            other => path = Some(other.to_string()),
        }
    }
    let Some(path) = path else {
        eprintln!("synsema-wasm: missing program (usage: synsema-wasm [--test] <file.syn | ->)");
        std::process::exit(2);
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

    if test_mode {
        let (lines, passed, failed) = with_big_stack(move || run_tests(&source, &filename));
        for l in &lines {
            println!("{}", l);
        }
        println!("passed {}, failed {}", passed, failed);
        std::process::exit(if failed > 0 { 1 } else { 0 });
    } else {
        let r = with_big_stack(move || run_program(&source, &filename));
        for line in &r.output {
            println!("{}", line);
        }
        for e in &r.errors {
            eprintln!("{}", e);
        }
        std::process::exit(if r.success { 0 } else { 1 });
    }
}
