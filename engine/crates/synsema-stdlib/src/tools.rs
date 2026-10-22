//! v0.6.46 (F1): `tool_spec(task, describe)` → la entrada del catálogo de `llm_step` sacada de la
//! firma de la task: `{name, describe, params, optional}`, con cada parámetro `"nombre: tipo"` si lo
//! declara y en `optional` los que tienen default. La firma *es* el esquema que ve el modelo; el
//! catálogo ya no se escribe a mano (y no se desincroniza de la task).

use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_list, syn_map, syn_text, SynMap, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn b_tool_spec(args: &[SynValue]) -> Result<SynValue, Control> {
    let t = match args.first() {
        Some(SynValue::Task(t)) if t.name != "<lambda>" => t,
        Some(SynValue::Task(_)) => {
            return Err(err("tool_spec needs a named task: a lambda has no name for the model to call"))
        }
        Some(SynValue::Builtin(b)) => {
            return Err(err(format!("tool_spec needs a task of the program, not the builtin '{}'", b.name)))
        }
        Some(other) => {
            return Err(err(format!("tool_spec(task, describe) takes a task, got {}", other.type_name())))
        }
        None => return Err(err("tool_spec(task, describe) takes a task")),
    };
    let describe = match args.get(1) {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(SynValue::Nothing) | None => String::new(),
        Some(other) => {
            return Err(err(format!("tool_spec: the description is text, got {}", other.type_name())))
        }
    };
    let params = t
        .parameters
        .iter()
        .map(|p| match p.ty {
            Some(ty) => syn_text(format!("{}: {}", p.name, ty.name())),
            None => syn_text(&*p.name),
        })
        .collect();
    let optional = t.parameters.iter().filter(|p| p.default.is_some()).map(|p| syn_text(&*p.name)).collect();
    let mut m = SynMap::new();
    m.insert("name", syn_text(t.name.as_str()));
    m.insert("describe", syn_text(describe));
    m.insert("params", syn_list(params));
    m.insert("optional", syn_list(optional));
    Ok(syn_map(m))
}

/// Registra `tool_spec`. PURO (sin capability): lee la firma, no corre la task.
pub fn register_tool_builtins(interp: &Interpreter) {
    interp.register_builtin("tool_spec", -1, Rc::new(|_i, a, _l| b_tool_spec(a)));
}
