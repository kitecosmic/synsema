//! Builtins de progress, memory y reglas. Port de `syntecnia/agents/builtins.py`.
//! Comparten un `ProgressManager` y un `AgentMemory` (Rc<RefCell>) con el motor.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use indexmap::IndexMap;
use serde_json::Map as JsonMap;

use syntecnia_core::interpreter::{Control, Interpreter, RuntimeError};
use syntecnia_core::types::{syn_bool, syn_float, syn_list, syn_map, syn_text, SynValue};

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

fn nth<'a>(args: &'a [SynValue], i: usize) -> Result<&'a SynValue, Control> {
    args.get(i).ok_or_else(|| err("missing argument"))
}

/// 2º arg lista → Vec<String> (cada elemento por su Display).
fn str_list(v: Option<&SynValue>) -> Vec<String> {
    match v {
        Some(SynValue::List(l)) => l.borrow().iter().map(|x| x.to_string()).collect(),
        _ => Vec::new(),
    }
}

pub fn register_agent_builtins(
    interp: &Interpreter,
    progress: Rc<RefCell<ProgressManager>>,
    memory: Rc<RefCell<AgentMemory>>,
) {
    // ===== Progress =====
    {
        let p = progress.clone();
        interp.register_builtin("create_progress", -1, Rc::new(move |_i, args, _l| {
            let name = raw_str(nth(args, 0)?);
            let steps = str_list(args.get(1));
            p.borrow_mut().create(&name, &steps);
            Ok(syn_text(name))
        }));
    }
    {
        let p = progress.clone();
        interp.register_builtin("start_step", 2, Rc::new(move |_i, args, _l| {
            p.borrow_mut().start_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?)).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        interp.register_builtin("complete_step", -1, Rc::new(move |_i, args, _l| {
            let result = args.get(2).map(raw_str);
            p.borrow_mut().complete_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), result).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        interp.register_builtin("fail_step", -1, Rc::new(move |_i, args, _l| {
            let error = args.get(2).map(raw_str);
            p.borrow_mut().fail_step(&raw_str(nth(args, 0)?), &raw_str(nth(args, 1)?), error).map_err(err)?;
            Ok(syn_bool(true))
        }));
    }
    {
        let p = progress.clone();
        interp.register_builtin("resume_point", 1, Rc::new(move |_i, args, _l| {
            match p.borrow().get_resume_point(&raw_str(nth(args, 0)?)) {
                Some(name) => Ok(syn_text(name)),
                None => Ok(SynValue::Nothing),
            }
        }));
    }
    {
        let p = progress.clone();
        interp.register_builtin("progress_display", 1, Rc::new(move |_i, args, _l| {
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
        interp.register_builtin("progress_percent", 1, Rc::new(move |_i, args, _l| {
            let name = raw_str(nth(args, 0)?);
            let pm = p.borrow();
            Ok(syn_float(pm.tasks.get(&name).map(|tp| tp.progress_percent()).unwrap_or(0.0)))
        }));
    }

    // ===== Memory =====
    {
        let m = memory.clone();
        interp.register_builtin("remember", -1, Rc::new(move |_i, args, _l| {
            let category = raw_str(nth(args, 0)?);
            let content = raw_str(nth(args, 1)?);
            let tags = str_list(args.get(2));
            let id = m.borrow_mut().remember(&category, &content, JsonMap::new(), tags, "agent").map_err(err)?;
            Ok(syn_text(id))
        }));
    }
    {
        let m = memory.clone();
        interp.register_builtin("recall", -1, Rc::new(move |_i, args, _l| {
            let category = args.get(0).map(raw_str).filter(|s| s != "nothing");
            let tags = if matches!(args.get(1), Some(SynValue::List(_))) { Some(str_list(args.get(1))) } else { None };
            let search = args.get(2).map(raw_str);
            let entries = m.borrow().recall(category.as_deref(), tags.as_deref(), search.as_deref());
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
        interp.register_builtin("forget_memory", 1, Rc::new(move |_i, args, _l| {
            m.borrow_mut().forget(&raw_str(nth(args, 0)?));
            Ok(syn_bool(true))
        }));
    }

    // ===== Reglas =====
    {
        let m = memory.clone();
        interp.register_builtin("add_rule", -1, Rc::new(move |_i, args, _l| {
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
        interp.register_builtin("check_rules", -1, Rc::new(move |_i, args, _l| {
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
        interp.register_builtin("get_rules", -1, Rc::new(move |_i, args, _l| {
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
        interp.register_builtin("memory_summary", 0, Rc::new(move |_i, _args, _l| {
            Ok(syn_text(m.borrow().format_summary()))
        }));
    }
}
