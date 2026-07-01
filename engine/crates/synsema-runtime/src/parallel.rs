//! A1 — Concurrencia, Fase 1. Implementa `parallel_map` + `chunk` (ver
//! SPEC-CONCURRENCIA.md). Es feature NUEVA (no está en el oráculo Python).
//!
//! `parallel_map(task, list, limit?)`: aplica `task` a cada item concurrentemente
//! sobre un **pool de hilos acotado** (`limit`, default 64), cada hilo con su propio
//! intérprete sync (modelo CSP/SendValue, como `spawn`) que hereda las capabilities
//! del scope. Resultados **en orden de entrada**; **fail-fast** (el primer error —
//! el de menor índice, como `apply` secuencial — cancela el resto y propaga).
//! `chunk(list, size)`: parte una lista en sublistas de `size`.
//!
//! El intérprete sigue síncrono; la concurrencia se agrega alrededor (std::thread).
//! rayon (cómputo puro) y tokio (C100k, Fase 2) quedan diferidos. Coordinación
//! cross-worker por blackboard no está en Fase 1 (cada worker aislado).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use synsema_capabilities::model::{Capability, CapabilitySet};
use synsema_core::ast::{Node, Param};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{from_send, syn_list, to_send, SendValue, SynTaskValue, SynValue};

use crate::engine::{wire_common, INTERP_STACK_SIZE};
use crate::serve::{
    rebuild_globals, rebuild_module_env, snapshot_globals, snapshot_module_env, GlobalVal,
};

fn err(msg: &str) -> Control {
    Control::Error(RuntimeError::new(msg.to_string()))
}

fn num_i64(n: &Number) -> i64 {
    // Trunca a i64 (Int/Big/Float/Decimal). Para tamaños de chunk/worker.
    n.to_i64_trunc().unwrap_or(0)
}

/// Convierte un `Control` de error en `RuntimeError` (preservando la ubicación del
/// worker, para que el error de `parallel_map` sea idéntico al de `apply` secuencial).
fn control_to_error(c: Control) -> RuntimeError {
    match c {
        Control::Error(e) => e,
        Control::Give(_) => RuntimeError::new("'give' used outside of a task".to_string()),
        Control::Stop(_) => RuntimeError::new("'stop' used outside of a loop".to_string()),
    }
}

/// Snapshot `Send` del task a aplicar (task de usuario con su AST, o un builtin por nombre).
enum TaskSnapshot {
    User {
        name: String,
        parameters: Vec<Param>,
        body: Vec<Node>,
        required_capabilities: Vec<(String, Option<String>)>,
        /// Si la task aplicada venía de un módulo (su `closure_env` era el `module_env`),
        /// el snapshot COMPLETO de ese env (todas las hermanas) para reconstruirlo en el
        /// worker; si no, `None` y la task cierra sobre el global (DE-030).
        module: Option<Vec<(String, GlobalVal)>>,
    },
    Builtin(String),
}

/// Intérprete worker fresco: builtins + caps heredadas + globales reconstruidos.
fn build_worker_interp(
    globals: &[(String, GlobalVal)],
    granted: &[Capability],
    denied: &[Capability],
    secure: bool,
    ceiling: &Option<Arc<Vec<Capability>>>,
) -> Interpreter {
    let mut interp = Interpreter::new();
    let caps = Rc::new(RefCell::new(CapabilitySet::new("parallel")));
    // Techo del host (--sandbox/--cap-set): setear ANTES de grants/wire_common. Así el
    // task del worker no puede reconceder por encima del techo (un `require exec(...)` en
    // su cuerpo llega al grant_hook y se filtra). El `Arc` compartido → `Rc` local del worker.
    if let Some(cl) = ceiling {
        caps.borrow_mut().ceiling = Some(Rc::new((**cl).clone()));
    }
    {
        let mut c = caps.borrow_mut();
        for cap in granted {
            c.grant(cap.clone());
        }
        for cap in denied {
            c.deny(cap.clone());
        }
    }
    wire_common(&mut interp, &caps, secure);
    rebuild_globals(&mut interp, globals);
    interp.freeze_intent(); // corre bajo el intent congelado
    interp
}

fn reconstruct_task(interp: &Interpreter, snap: &TaskSnapshot) -> SynValue {
    match snap {
        TaskSnapshot::User { name, parameters, body, required_capabilities, module } => {
            // DE-030: si la task vino de un módulo, cerrarla sobre un `module_env`
            // reconstruido (con todas las hermanas) en vez del global del worker —
            // así una task de módulo aplicada que llame a una hermana resuelve, igual
            // que las tasks de los globales (DE-027). Sin módulo: comportamiento actual.
            let closure_env = match module {
                Some(env) => rebuild_module_env(env, &interp.global_env),
                None => interp.global_env.clone(),
            };
            SynValue::Task(Rc::new(SynTaskValue {
                name: name.clone(),
                parameters: parameters.clone(),
                body: body.clone(),
                closure_env,
                origin: None,
                required_capabilities: required_capabilities.clone(),
            }))
        }
        TaskSnapshot::Builtin(name) => {
            interp.global_env.borrow().bindings.get(name).cloned().unwrap_or(SynValue::Nothing)
        }
    }
}

/// A1 Fase 2 — Corre `task` sobre `items` con concurrencia `limit` sobre **tokio**
/// (runtime multi-thread + `spawn_blocking` por item, acotado por un semáforo). Cada
/// item corre en un intérprete sync fresco (modelo CSP). Resultados **en orden de
/// entrada**; **fail-fast** con el error de menor índice. Semántica idéntica a `apply`
/// secuencial; tokio sólo cambia el scheduling (M:N, escala a muchas tareas).
#[allow(clippy::too_many_arguments)]
fn run_parallel(
    globals: Arc<Vec<(String, GlobalVal)>>,
    granted: Arc<Vec<Capability>>,
    denied: Arc<Vec<Capability>>,
    task_snap: Arc<TaskSnapshot>,
    items: Vec<SendValue>,
    limit: usize,
    secure: bool,
    ceiling: Option<Arc<Vec<Capability>>>,
) -> Result<Vec<SendValue>, RuntimeError> {
    let n = items.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let limit = limit.max(1);
    // Runtime acotado: el pool de blocking se topea al `limit` (concurrencia real de
    // los intérpretes sync). El stack grande cubre la recursión del intérprete.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(limit)
        .thread_stack_size(INTERP_STACK_SIZE)
        .build()
        .map_err(|e| RuntimeError::new(format!("parallel_map: no se pudo crear el runtime: {}", e)))?;

    let items = Arc::new(items);
    let aborted = Arc::new(AtomicBool::new(false));
    let error: Arc<Mutex<Option<(usize, RuntimeError)>>> = Arc::new(Mutex::new(None));

    runtime.block_on(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(limit));
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            // Acquire bloquea hasta que haya un slot libre → concurrencia ≤ limit.
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            if aborted.load(Ordering::Relaxed) {
                drop(permit);
                break;
            }
            let globals = globals.clone();
            let granted = granted.clone();
            let denied = denied.clone();
            let ceiling = ceiling.clone();
            let task_snap = task_snap.clone();
            let items = items.clone();
            let aborted = aborted.clone();
            let error = error.clone();
            let h = tokio::task::spawn_blocking(move || -> Option<SendValue> {
                let _permit = permit; // libera el slot al terminar
                if aborted.load(Ordering::Relaxed) {
                    return None;
                }
                let mut interp = build_worker_interp(&globals, &granted, &denied, secure, &ceiling);
                let task_value = reconstruct_task(&interp, &task_snap);
                let item = from_send(&items[i]);
                match interp.call_task(task_value, vec![item]) {
                    Ok(v) => Some(to_send(&v)),
                    Err(c) => {
                        let re = control_to_error(c);
                        let mut e = error.lock().unwrap();
                        if e.as_ref().map_or(true, |(idx, _)| i < *idx) {
                            *e = Some((i, re));
                        }
                        aborted.store(true, Ordering::Relaxed);
                        None
                    }
                }
            });
            handles.push(h);
        }

        // Resultados en orden de entrada (handles en orden 0..n).
        let mut out: Vec<SendValue> = Vec::with_capacity(handles.len());
        for h in handles {
            out.push(h.await.ok().flatten().unwrap_or(SendValue::Nothing));
        }
        if let Some((_, re)) = error.lock().unwrap().take() {
            return Err(re);
        }
        Ok(out)
    })
}

/// Registra `parallel_map` y `chunk` (lo llama `wire_common`).
pub fn register_parallel_builtins(interp: &Interpreter, caps: &Rc<RefCell<CapabilitySet>>, secure: bool) {
    // chunk(list, size) — parte una lista en sublistas de `size`. Puro.
    interp.register_builtin(
        "chunk",
        2,
        Rc::new(|_i, args, _loc| {
            let list = match args.first() {
                Some(SynValue::List(l)) => l.borrow().clone(),
                _ => return Err(err("chunk: first argument must be a list")),
            };
            let size = match args.get(1) {
                Some(SynValue::Number(n)) => num_i64(n),
                _ => return Err(err("chunk: size must be a number")),
            };
            if size <= 0 {
                return Err(err("chunk size must be positive"));
            }
            let size = size as usize;
            let chunks: Vec<SynValue> = list.chunks(size).map(|c| syn_list(c.to_vec())).collect();
            Ok(syn_list(chunks))
        }),
    );

    // parallel_map(task, list, limit?) — fan-out acotado, resultados en orden.
    let caps = caps.clone();
    interp.register_builtin(
        "parallel_map",
        -1,
        Rc::new(move |i, args, _loc| {
            let task = match args.first() {
                Some(t @ (SynValue::Task(_) | SynValue::Builtin(_))) => t,
                _ => return Err(err("parallel_map: first argument must be a task")),
            };
            let list = match args.get(1) {
                Some(SynValue::List(l)) => l.borrow().clone(),
                _ => return Err(err("parallel_map: second argument must be a list")),
            };
            let limit = match args.get(2) {
                Some(SynValue::Number(n)) => {
                    let v = num_i64(n);
                    if v <= 0 {
                        64
                    } else {
                        v as usize
                    }
                }
                _ => 64,
            };
            let task_snap = match task {
                SynValue::Task(t) => {
                    // DE-030: si el mapper es una task de módulo (cierra sobre un env
                    // "module:…"), snapshotear su `module_env` completo para reconstruir
                    // las hermanas en el worker; si no, `None` (cierra sobre el global).
                    let module = if t.closure_env.borrow().name.starts_with("module:") {
                        Some(snapshot_module_env(&t.closure_env))
                    } else {
                        None
                    };
                    TaskSnapshot::User {
                        name: t.name.clone(),
                        parameters: t.parameters.clone(),
                        body: t.body.clone(),
                        required_capabilities: t.required_capabilities.clone(),
                        module,
                    }
                }
                SynValue::Builtin(b) => TaskSnapshot::Builtin(b.name.clone()),
                _ => unreachable!(),
            };
            let globals = snapshot_globals(i);
            let granted: Vec<Capability> = caps.borrow().granted.iter().cloned().collect();
            let denied: Vec<Capability> = caps.borrow().denied.iter().cloned().collect();
            // Techo del host: se snapshotea del set del padre y se propaga a cada worker
            // (Arc → cruza a los hilos de tokio). Sin techo → None (comportamiento actual).
            let ceiling: Option<Arc<Vec<Capability>>> =
                caps.borrow().ceiling.as_ref().map(|rc| Arc::new((**rc).clone()));
            let items: Vec<SendValue> = list.iter().map(to_send).collect();
            match run_parallel(
                globals,
                Arc::new(granted),
                Arc::new(denied),
                Arc::new(task_snap),
                items,
                limit,
                secure,
                ceiling,
            ) {
                Ok(results) => Ok(syn_list(results.iter().map(from_send).collect())),
                Err(re) => Err(Control::Error(re)),
            }
        }),
    );
}
