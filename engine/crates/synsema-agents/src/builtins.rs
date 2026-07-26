//! Builtins de progress, memory y reglas. Port de `synsema/agents/builtins.py`.
//! Comparten un `ProgressManager` y un `AgentMemory` (Rc<RefCell>) con el motor.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde_json::Map as JsonMap;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_float, syn_list, syn_map, syn_text, SynValue};

use crate::memory::AgentMemory;
use crate::progress::ProgressManager;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

fn nth(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

/// 2º arg lista → Vec<String> (cada elemento por su Display).
fn str_list(v: Option<&SynValue>) -> Vec<String> {
    match v {
        Some(SynValue::List(l)) => l.borrow().iter().map(|x| x.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Arg numérico opcional → `usize` (negativos/no-finitos/no-números → None). DE-035:
/// usado por el `limit` opcional de `recall`.
fn opt_usize(v: Option<&SynValue>) -> Option<usize> {
    match v {
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if f.is_finite() && f >= 0.0 { Some(f as usize) } else { None }
        }
        _ => None,
    }
}

/// Gate de la capability `memory` (DB-M1): lo construye el MOTOR (que conoce la
/// declaración y el CapabilitySet vivo) y lo chequea CADA builtin de la familia de
/// estado persistente (memory + rules + progress) antes de tocar nada. `Err(msg)` →
/// el builtin falla con ese mensaje (deny-by-default: sin declaración, sin sandbox
/// escape, sin exceder el techo del host). Este crate no depende de capabilities:
/// la lógica viaja en el closure, igual que `llm_cap_hook`.
pub type MemoryGate = Rc<dyn Fn() -> Result<(), String>>;

/// `source` de una escritura / namespace por defecto de una lectura (DB-M1 #4):
/// dentro de `agent X` es `"X"`; en el top-level es `"main"`.
fn mem_source(i: &Interpreter) -> String {
    i.current_agent().unwrap_or("main").to_string()
}

/// Resuelve el arg nombrado `from` de `recall` (DB-M1 #4) al filtro de `source`:
/// ausente/`nothing` → el namespace propio (agente) o global (top-level);
/// `"*"` → global explícito; otro string → ese namespace.
fn recall_source(i: &Interpreter, from: Option<&SynValue>) -> Option<String> {
    match from {
        None | Some(SynValue::Nothing) => i.current_agent().map(|a| a.to_string()),
        Some(v) => {
            let s = raw_str(v);
            if s == "*" { None } else { Some(s) }
        }
    }
}

/// Nombres de parámetros de `recall` (G-8: `from` es un arg nombrado más, como
/// `mode`/`limit`; sin sintaxis nueva). Compartidos por el camino de run y serve.
const RECALL_PARAMS: [&str; 6] = ["category", "tags", "search", "mode", "limit", "from"];

pub fn register_agent_builtins(
    interp: &Interpreter,
    progress: Rc<RefCell<ProgressManager>>,
    memory: Rc<RefCell<AgentMemory>>,
    gate: MemoryGate,
) {
    // ===== Progress =====
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("create_progress", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let steps = str_list(args.get(1));
            p.borrow_mut().create(&name, &steps);
            Ok(syn_text(name))
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("start_step", 2, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            p.borrow_mut().start_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?)).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("complete_step", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let result = args.get(2).map(raw_str);
            p.borrow_mut().complete_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), result).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("fail_step", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let error = args.get(2).map(raw_str);
            p.borrow_mut().fail_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), error).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("resume_point", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            match p.borrow().get_resume_point(&raw_str(nth(args, 0)?)) {
                Some(name) => Ok(syn_text(name)),
                None => Ok(SynValue::Nothing),
            }
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("progress_display", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let pm = p.borrow();
            match pm.tasks.get(&name) {
                Some(tp) => Ok(syn_text(tp.format_display())),
                None => Ok(syn_text(format!("No progress for '{}'", name))),
            }
        }));
    }
    {
        let p = progress.clone();
        let g = gate.clone();
        interp.register_builtin("progress_percent", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let pm = p.borrow();
            Ok(syn_float(pm.tasks.get(&name).map(|tp| tp.progress_percent()).unwrap_or(0.0)))
        }));
    }

    // ===== Memory =====
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("remember", -1, Rc::new(move |i, args, _l| {
            g().map_err(err)?;
            let category = raw_str(nth(args, 0)?);
            let content = raw_str(nth(args, 1)?);
            let tags = str_list(args.get(2));
            // Namespace (DB-M1 #4): el `source` es el agente en ejecución o "main".
            let source = mem_source(i);
            let id = m.borrow_mut().remember(&category, &content, JsonMap::new(), tags, &source).map_err(err)?;
            Ok(syn_text(id))
        }));
    }
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin_named("recall", RECALL_PARAMS.to_vec(), Rc::new(move |i, args, _l| {
            g().map_err(err)?;
            // `nothing` (o ausente) en category/search = sin filtro. Chequear el valor
            // directo: raw_str(nothing) es "None", no "nothing" → un filtro por string
            // no lo capturaba (bug preexistente en category, ahora corregido).
            let opt_arg = |a: Option<&SynValue>| match a {
                None | Some(SynValue::Nothing) => None,
                Some(v) => Some(raw_str(v)),
            };
            let category = opt_arg(args.first());
            let tags = if matches!(args.get(1), Some(SynValue::List(_))) { Some(str_list(args.get(1))) } else { None };
            let search = opt_arg(args.get(2));
            // 4º arg opcional `mode`: "all" (AND) o "any"/ausente (OR, default). (MF-005)
            let match_all = args.get(3).map(raw_str).map(|m| m.to_lowercase() == "all").unwrap_or(false);
            // 5º arg opcional `limit` (número): máximo de entradas. Sin él, el default de
            // recall_mode (200). DE-035.
            let limit = opt_usize(args.get(4));
            // 6º arg (nombrado) `from` (DB-M1 #4): namespace a leer. Default: el propio
            // (agente) o global (top-level). `from = "*"` = global explícito.
            let source = recall_source(i, args.get(5));
            let entries = m.borrow().recall_mode(category.as_deref(), tags.as_deref(), search.as_deref(), match_all, limit, source.as_deref());
            let result: Vec<SynValue> = entries.iter().map(|e| {
                let mut map = IndexMap::new();
                map.insert("id".to_string(), syn_text(e.id.as_str()));
                map.insert("category".to_string(), syn_text(e.category.value()));
                map.insert("content".to_string(), syn_text(e.content.as_str()));
                map.insert("source".to_string(), syn_text(e.source.as_str()));
                map.insert("tags".to_string(), syn_list(e.tags.iter().map(|t| syn_text(t.as_str())).collect()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("forget_memory", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            m.borrow_mut().forget(&raw_str(nth(args, 0)?));
            Ok(syn_bool(true))
        }));
    }

    // ===== Reglas =====
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("add_rule", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let level = raw_str(nth(args, 1)?);
            let description = raw_str(nth(args, 2)?);
            let category = args.get(3).map(raw_str).unwrap_or_default();
            m.borrow_mut().add_rule(&name, &level, &description, None, &category).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("check_rules", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let category = args.first().map(raw_str);
            let mut context: HashMap<String, f64> = HashMap::new();
            if let Some(SynValue::Map(cm)) = args.get(1) {
                for (k, v) in cm.borrow().iter() {
                    if let SynValue::Number(n) = v {
                        context.insert(k.clone(), n.to_f64());
                    }
                }
            }
            let violations = m.borrow_mut().check_rules(category.as_deref(), &context);
            let result: Vec<SynValue> = violations.iter().map(|v| {
                let mut map = IndexMap::new();
                map.insert("rule".to_string(), syn_text(v.rule.name.as_str()));
                map.insert("level".to_string(), syn_text(v.rule.level.value()));
                map.insert("message".to_string(), syn_text(v.to_string()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("get_rules", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let category = args.first().map(raw_str);
            let rules = m.borrow().get_rules(category.as_deref(), None);
            let result: Vec<SynValue> = rules.iter().map(|r| {
                let mut map = IndexMap::new();
                map.insert("name".to_string(), syn_text(r.name.as_str()));
                map.insert("level".to_string(), syn_text(r.level.value()));
                map.insert("description".to_string(), syn_text(r.description.as_str()));
                map.insert("category".to_string(), syn_text(r.category.as_str()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
    {
        let m = memory.clone();
        let g = gate.clone();
        interp.register_builtin("memory_summary", 0, Rc::new(move |_i, _args, _l| {
            g().map_err(err)?;
            Ok(syn_text(m.borrow().format_summary()))
        }));
    }
}

/// Sobrescribe los builtins de memoria (`remember`, `recall`, `forget_memory`,
/// `memory_summary`) para que usen un `AgentMemory` compartido entre hilos
/// (`Arc<Mutex>`). Usado por `synsema serve` para que todos los route handlers
/// compartan y persistan la misma memoria, tanto entre requests como entre
/// reinicios del proceso.
///
/// Debe llamarse DESPUÉS de `register_agent_builtins` (o `wire_common_with_state`)
/// para que las versiones compartidas sobrescriban las per-intérprete.
///
/// Las reglas (`add_rule`/`check_rules`/`get_rules`) NO se tocan: siguen usando
/// el `AgentMemory` per-intérprete que ya recibe las reglas del top-level via el
/// snapshot de serve (gap-15 fix).
///
/// `on_write` se llama con la memoria después de cada mutación para persistir a disco.
pub fn register_serve_memory_builtins(
    interp: &Interpreter,
    shared: Arc<Mutex<AgentMemory>>,
    on_write: Arc<dyn Fn(&AgentMemory) + Send + Sync>,
    gate: MemoryGate,
) {
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("remember", -1, Rc::new(move |i, args, _l| {
            g().map_err(err)?;
            let category = raw_str(nth(args, 0)?);
            let content  = raw_str(nth(args, 1)?);
            let tags     = str_list(args.get(2));
            // Namespace (DB-M1 #4): handlers top-level escriben como "main"; un
            // agente restaurado en el worker escribe con su propio nombre.
            let source   = mem_source(i);
            let mut mem  = s.lock().unwrap();
            let id = mem.remember(&category, &content, JsonMap::new(), tags, &source).map_err(err)?;
            ow(&mem);
            Ok(syn_text(id))
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin_named("recall", RECALL_PARAMS.to_vec(), Rc::new(move |i, args, _l| {
            g().map_err(err)?;
            let category = args.first().map(raw_str).filter(|s| s != "nothing" && s != "None");
            let tags = if matches!(args.get(1), Some(SynValue::List(_))) {
                Some(str_list(args.get(1)))
            } else {
                None
            };
            let search = args.get(2).map(raw_str).filter(|s| s != "nothing" && s != "None");
            // DE-035: exponer también bajo serve el 4º arg `mode` ("all"=AND, "any"/ausente=OR)
            // y el 5º arg `limit` (número), a la par del camino de run.
            let match_all = args.get(3).map(raw_str).map(|m| m.to_lowercase() == "all").unwrap_or(false);
            let limit = opt_usize(args.get(4));
            // `from` nombrado (DB-M1 #4), a la par del camino de run.
            let source = recall_source(i, args.get(5));
            let mem = s.lock().unwrap();
            let entries = mem.recall_mode(category.as_deref(), tags.as_deref(), search.as_deref(), match_all, limit, source.as_deref());
            let result: Vec<SynValue> = entries.iter().map(|e| {
                let mut map = IndexMap::new();
                map.insert("id".to_string(),       syn_text(e.id.as_str()));
                map.insert("category".to_string(), syn_text(e.category.value()));
                map.insert("content".to_string(),  syn_text(e.content.as_str()));
                map.insert("source".to_string(),   syn_text(e.source.as_str()));
                map.insert("tags".to_string(),
                    syn_list(e.tags.iter().map(|t| syn_text(t.as_str())).collect()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("forget_memory", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let mut mem = s.lock().unwrap();
            mem.forget(&raw_str(nth(args, 0)?));
            ow(&mem);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("memory_summary", 0, Rc::new(move |_i, _args, _l| {
            g().map_err(err)?;
            Ok(syn_text(s.lock().unwrap().format_summary()))
        }));
    }
}

/// Sobrescribe los builtins de REGLAS (`add_rule`/`check_rules`/`get_rules`) para que
/// usen el `AgentMemory` compartido entre hilos. Lo usa el camino de RUN con memoria
/// declarada (DB-M1): las reglas son parte de la familia persistente (misma tabla
/// `rules` del `.db`), así que van al mismo store compartido + `on_write`. `serve` NO
/// lo usa: ahí las reglas siguen per-intérprete pre-pobladas del snapshot (gap-15,
/// G-9 — semántica de serve intacta).
pub fn register_shared_rules_builtins(
    interp: &Interpreter,
    shared: Arc<Mutex<AgentMemory>>,
    on_write: Arc<dyn Fn(&AgentMemory) + Send + Sync>,
    gate: MemoryGate,
) {
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("add_rule", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let level = raw_str(nth(args, 1)?);
            let description = raw_str(nth(args, 2)?);
            let category = args.get(3).map(raw_str).unwrap_or_default();
            let mut mem = s.lock().unwrap();
            mem.add_rule(&name, &level, &description, None, &category).map_err(err)?;
            ow(&mem);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("check_rules", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let category = args.first().map(raw_str);
            let mut context: HashMap<String, f64> = HashMap::new();
            if let Some(SynValue::Map(cm)) = args.get(1) {
                for (k, v) in cm.borrow().iter() {
                    if let SynValue::Number(n) = v {
                        context.insert(k.clone(), n.to_f64());
                    }
                }
            }
            let mut mem = s.lock().unwrap();
            let violations = mem.check_rules(category.as_deref(), &context);
            let result: Vec<SynValue> = violations.iter().map(|v| {
                let mut map = IndexMap::new();
                map.insert("rule".to_string(), syn_text(v.rule.name.as_str()));
                map.insert("level".to_string(), syn_text(v.rule.level.value()));
                map.insert("message".to_string(), syn_text(v.to_string()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("get_rules", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let category = args.first().map(raw_str);
            let mem = s.lock().unwrap();
            let rules = mem.get_rules(category.as_deref(), None);
            let result: Vec<SynValue> = rules.iter().map(|r| {
                let mut map = IndexMap::new();
                map.insert("name".to_string(), syn_text(r.name.as_str()));
                map.insert("level".to_string(), syn_text(r.level.value()));
                map.insert("description".to_string(), syn_text(r.description.as_str()));
                map.insert("category".to_string(), syn_text(r.category.as_str()));
                syn_map(map)
            }).collect();
            Ok(syn_list(result))
        }));
    }
}

/// Sobrescribe los builtins de progreso (`create_progress`/`start_step`/`complete_step`/
/// `fail_step`/`resume_point`/`progress_display`/`progress_percent`) para que usen un
/// `ProgressManager` compartido entre hilos (`Arc<Mutex>`). Gemelo exacto de
/// `register_serve_memory_builtins`: bajo `synsema serve` todos los route handlers
/// comparten y persisten el MISMO progreso, tanto entre requests como entre reinicios
/// (DE-028). Sin esto, cada intérprete de request tenía su propio `ProgressManager`
/// fresco (reseteado por `reset_for_request`) → un plan creado en un request no existía
/// en el siguiente, y el ciclo PLAN→ADVANCE crasheaba.
///
/// Debe llamarse DESPUÉS de `register_agent_builtins` (o `wire_common_with_state`) para
/// que las versiones compartidas sobrescriban las per-intérprete.
///
/// `on_write` se llama con el progreso después de cada mutación para persistir a disco.
pub fn register_serve_progress_builtins(
    interp: &Interpreter,
    shared: Arc<Mutex<ProgressManager>>,
    on_write: Arc<dyn Fn(&ProgressManager) + Send + Sync>,
    gate: MemoryGate,
) {
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("create_progress", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let steps = str_list(args.get(1));
            let mut pm = s.lock().unwrap();
            pm.create(&name, &steps);
            ow(&pm);
            Ok(syn_text(name))
        }));
    }
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("start_step", 2, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let mut pm = s.lock().unwrap();
            pm.start_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?)).map_err(err)?;
            ow(&pm);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("complete_step", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let result = args.get(2).map(raw_str);
            let mut pm = s.lock().unwrap();
            pm.complete_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), result).map_err(err)?;
            ow(&pm);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = shared.clone();
        let ow = on_write.clone();
        let g = gate.clone();
        interp.register_builtin("fail_step", -1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let error = args.get(2).map(raw_str);
            let mut pm = s.lock().unwrap();
            pm.fail_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), error).map_err(err)?;
            ow(&pm);
            Ok(syn_bool(true))
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("resume_point", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            match s.lock().unwrap().get_resume_point(&raw_str(nth(args, 0)?)) {
                Some(name) => Ok(syn_text(name)),
                None => Ok(SynValue::Nothing),
            }
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("progress_display", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let pm = s.lock().unwrap();
            match pm.tasks.get(&name) {
                Some(tp) => Ok(syn_text(tp.format_display())),
                None => Ok(syn_text(format!("No progress for '{}'", name))),
            }
        }));
    }
    {
        let s = shared.clone();
        let g = gate.clone();
        interp.register_builtin("progress_percent", 1, Rc::new(move |_i, args, _l| {
            g().map_err(err)?;
            let name = raw_str(nth(args, 0)?);
            let pm = s.lock().unwrap();
            Ok(syn_float(pm.tasks.get(&name).map(|tp| tp.progress_percent()).unwrap_or(0.0)))
        }));
    }
}
