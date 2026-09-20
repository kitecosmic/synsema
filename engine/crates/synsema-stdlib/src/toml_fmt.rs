//! v0.6.20 — `toml_parse(text) → map` y `toml_encode(map) → text`.
//!
//! TOML es el manifiesto de proyecto de la plataforma (`syn.toml`, `catalog.toml`) y el de
//! Cargo, Python y GitHub; el lenguaje sólo traía JSON. Mapeo: tabla → map (en el orden del
//! documento), array → list, entero/flotante/bool tal cual, y las fechas TOML → texto ISO 8601
//! (Synsema no tiene tipo fecha; se dice, no se inventa). `toml_encode` acepta valores
//! JSON-like con un map en la raíz (un documento TOML ES una tabla) y falla claro con
//! `nothing`, `bytes` o `secret`. Puro: sin I/O.
//!

use std::rc::Rc;
use std::str::FromStr;

use indexmap::IndexMap;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{syn_bool, syn_list, syn_map, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn toml_to_syn(v: &::toml::Value) -> SynValue {
    match v {
        ::toml::Value::String(s) => syn_text(s.as_str()),
        ::toml::Value::Integer(i) => SynValue::Number(Number::Int(*i)),
        ::toml::Value::Float(f) => SynValue::Number(Number::Float(*f)),
        ::toml::Value::Boolean(b) => syn_bool(*b),
        ::toml::Value::Datetime(d) => syn_text(d.to_string()),
        ::toml::Value::Array(items) => syn_list(items.iter().map(toml_to_syn).collect()),
        ::toml::Value::Table(t) => table_to_syn(t),
    }
}

fn table_to_syn(t: &::toml::Table) -> SynValue {
    let mut m: IndexMap<String, SynValue> = IndexMap::new();
    for (k, v) in t.iter() {
        m.insert(k.clone(), toml_to_syn(v));
    }
    syn_map(m)
}

pub fn toml_parse(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "toml_parse";
    let text = match args.first() {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(SynValue::Bytes(b)) => String::from_utf8(b.to_vec())
            .map_err(|_| err(format!("{}: the bytes are not valid UTF-8 text", F)))?,
        Some(other) => {
            return Err(err(format!("{}: expected TOML text, got {}", F, other.type_name())))
        }
        None => return Err(err(format!("{}(text) takes the TOML document as text", F))),
    };
    let table = ::toml::Table::from_str(&text).map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(table_to_syn(&table))
}

fn syn_to_toml(v: &SynValue, path: &str, who: &str) -> Result<::toml::Value, Control> {
    Ok(match v {
        SynValue::Text(s) => ::toml::Value::String(s.to_string()),
        SynValue::Bool(b) => ::toml::Value::Boolean(*b),
        SynValue::Number(Number::Int(i)) => ::toml::Value::Integer(*i),
        SynValue::Number(Number::Float(f)) => ::toml::Value::Float(*f),
        SynValue::List(l) => {
            let mut out = Vec::new();
            for (i, item) in l.borrow().iter().enumerate() {
                out.push(syn_to_toml(item, &format!("{}[{}]", path, i), who)?);
            }
            ::toml::Value::Array(out)
        }
        SynValue::Map(m) => {
            let mut t = ::toml::Table::new();
            for (k, item) in m.borrow().iter() {
                let p = if path.is_empty() { k.clone() } else { format!("{}.{}", path, k) };
                t.insert(k.clone(), syn_to_toml(item, &p, who)?);
            }
            ::toml::Value::Table(t)
        }
        SynValue::Nothing => {
            return Err(err(format!(
                "{}: TOML has no null — {} is nothing (drop the key or give it a value)",
                who,
                if path.is_empty() { "the value" } else { path }
            )))
        }
        other => {
            return Err(err(format!(
                "{}: {} cannot be written as TOML: {} (use text, numbers, booleans, lists and maps)",
                who,
                if path.is_empty() { "the value" } else { path },
                other.type_name()
            )))
        }
    })
}

pub fn toml_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "toml_encode";
    let v = args
        .first()
        .ok_or_else(|| err(format!("{}(map) takes the document as a map", F)))?;
    let root = match syn_to_toml(v, "", F)? {
        ::toml::Value::Table(t) => t,
        _ => {
            return Err(err(format!(
                "{}: a TOML document is a table — pass a map at the top level (got {})",
                F,
                v.type_name()
            )))
        }
    };
    Ok(syn_text(root.to_string()))
}

pub fn register_toml_builtins(interp: &Interpreter) {
    interp.register_builtin("toml_parse", -1, synsema_core::interpreter::with_fallback(1, Rc::new(|_i, a, _l| toml_parse(a))));
    interp.register_builtin("toml_encode", 1, Rc::new(|_i, a, _l| toml_encode(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn get(v: &SynValue, k: &str) -> SynValue {
        match v {
            SynValue::Map(m) => m.borrow().get(k).cloned().unwrap_or_else(|| panic!("sin clave {}", k)),
            other => panic!("no es un map: {}", other),
        }
    }

    #[test]
    fn syn_toml_manifest_parses_with_dotted_keys_tables_and_arrays() {
        let doc = r#"
name = "control"
version = "0.1.0"
entry.file = "app.syn"   # clave con punto
tags = ["web", "api"]

[deploy]
region = "eu-west-1"
replicas = 2
public = true

[[routes]]
path = "/"
[[routes]]
path = "/api"

[dates]
built = 2026-09-11T10:00:00Z
"#;
        let v = ok(toml_parse(&[syn_text(doc)]));
        assert_eq!(get(&v, "name").to_string(), "control");
        assert_eq!(get(&get(&v, "entry"), "file").to_string(), "app.syn");
        assert_eq!(get(&get(&v, "deploy"), "replicas").to_string(), "2");
        assert!(matches!(get(&get(&v, "deploy"), "public"), SynValue::Bool(true)));
        match get(&v, "routes") {
            SynValue::List(l) => assert_eq!(l.borrow().len(), 2),
            other => panic!("{}", other),
        }
        // Las fechas salen como texto ISO: se dice, no se inventa un tipo.
        assert_eq!(get(&get(&v, "dates"), "built").to_string(), "2026-09-11T10:00:00Z");
        // El orden del documento se conserva (preserve_order).
        if let SynValue::Map(m) = &v {
            let keys: Vec<String> = m.borrow().keys().cloned().collect();
            assert_eq!(keys, vec!["name", "version", "entry", "tags", "deploy", "routes", "dates"]);
        }
    }

    #[test]
    fn encode_round_trips_and_refuses_nothing() {
        let doc = "title = \"x\"\n\n[a]\nn = 1\nlist = [1, 2]\n";
        let v = ok(toml_parse(&[syn_text(doc)]));
        let text = ok(toml_encode(&[v.clone()])).to_string();
        let again = ok(toml_parse(&[syn_text(text.as_str())]));
        assert_eq!(get(&get(&again, "a"), "n").to_string(), "1");
        assert_eq!(get(&again, "title").to_string(), "x");
        let mut m = IndexMap::new();
        m.insert("k".to_string(), SynValue::Nothing);
        let e = match toml_encode(&[syn_map(m)]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("TOML has no null"), "{}", e);
        let e = match toml_encode(&[syn_text("plain")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("pass a map at the top level"), "{}", e);
    }

    #[test]
    fn invalid_toml_fails_with_position() {
        let e = match toml_parse(&[syn_text("a = \n")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.starts_with("toml_parse:"), "{}", e);
    }
}
