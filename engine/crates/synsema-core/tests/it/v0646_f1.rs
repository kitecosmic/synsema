//! v0.6.46, F1: lo que queda en Rust (v0.6.68, migas §1) — error de PARSEO de la firma (un
//! .test.syn entero tiene que parsear), el valor etiquetado vía `labels` del host y el outline
//! de codeintel sobre archivos. Los de frontera `call`/`call_tool` viven en
//! `tests/v0646_f1.test.syn`.

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

fn error_of(source: &str) -> String {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}\nsalida: {:?}", source, r.output);
    r.errors.join("\n")
}

#[test]
fn f1_a_wrong_type_is_a_parse_error() {
    let e = error_of("task h(x: nmber)\n    give x\n");
    assert!(
        e.contains("unknown type 'nmber' for parameter 'x': the parameter types are text, number, bool, list or map"),
        "{}",
        e
    );
    let e = error_of("task h(x: number = \"3\")\n    give x\n");
    assert!(e.contains("the default of 'x: number' is a text"), "{}", e);
    let e = error_of("task h(x:)\n    give x\n");
    assert!(e.contains("Expected a parameter type after ':'"), "{}", e);
}

/// Un valor etiquetado se compara por su valor interno.
#[test]
fn f1_a_labelled_value_is_checked_inside() {
    use synsema_core::ast::ParamType;
    use synsema_core::labels::{label_from, mark};
    use synsema_core::types::{syn_int, syn_text};
    let v = mark(syn_int(3), label_from(&["a"]));
    assert!(ParamType::Number.accepts(&v));
    assert!(!ParamType::Text.accepts(&v));
    assert!(ParamType::Text.accepts(&mark(syn_text("x"), label_from(&["a"]))));
}

/// `code outline --json`: los parámetros con tipo, obligatoriedad y default literal, y la firma como
/// JSON Schema. `params` (los nombres) queda igual.
#[test]
fn f1_outline_publishes_the_signature() {
    let dir = std::env::temp_dir().join(format!("syn_f1_outline_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("t.syn"),
        "export task estado(id: text, items: bool = false, n = 1 + 1, ctx)\n    give id\n",
    )
    .unwrap();
    let root = synsema_core::codeintel::Root::new(&dir);
    let v = synsema_core::codeintel::outline(&root, Some("t.syn"), true);
    let task = find_task(&v, "estado").unwrap_or_else(|| panic!("sin la task"));
    assert_eq!(task["params"], serde_json::json!(["id", "items", "n", "ctx"]));
    assert_eq!(
        task["parameters"],
        serde_json::json!([
            {"name": "id", "type": "text", "required": true},
            {"name": "items", "type": "bool", "required": false, "default": false},
            {"name": "n", "type": null, "required": false},
            {"name": "ctx", "type": null, "required": true},
        ])
    );
    assert_eq!(
        task["input_schema"],
        serde_json::json!({
            "type": "object",
            "properties": {"id": {"type": "string"}, "items": {"type": "boolean", "default": false}, "n": {}, "ctx": {}},
            "required": ["id", "ctx"],
        })
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// v0.6.46 (ronda 1 de cf1, N4): `= -3` es un literal y se publica; un default `nothing` no va al
/// esquema (no es del tipo) y `call` acepta pasarlo a mano.
#[test]
fn f1_negative_and_nothing_defaults() {
    let dir = std::env::temp_dir().join(format!("syn_f1_defaults_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("t.syn"), "export task d(n: number = -3, t: text = nothing)\n    give n\n").unwrap();
    let root = synsema_core::codeintel::Root::new(&dir);
    let v = synsema_core::codeintel::outline(&root, Some("t.syn"), true);
    let task = find_task(&v, "d").unwrap_or_else(|| panic!("sin la task"));
    assert_eq!(
        task["input_schema"]["properties"],
        serde_json::json!({"n": {"type": "number", "default": -3}, "t": {"type": "string"}})
    );
    assert_eq!(task["input_schema"]["required"], serde_json::json!([]));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out("task d(t: text = nothing)\n    give t\nprint(call(d, {\"t\": nothing}))\n"), vec!["nothing"]);
    let e = error_of("task d(t: text = \"x\")\n    give t\nprint(call(d, {\"t\": nothing}))\n");
    assert!(e.contains("'t' must be text"), "{}", e);
}

fn find_task<'a>(v: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("task") && o.get("name").and_then(|k| k.as_str()) == Some(name) {
                return Some(v);
            }
            o.values().find_map(|x| find_task(x, name))
        }
        serde_json::Value::Array(a) => a.iter().find_map(|x| find_task(x, name)),
        _ => None,
    }
}
