//! v0.6.46, F1: tipos en los parámetros de task como metadato. Se validan sólo en la frontera
//! (`call`, `call_tool`: los argumentos llegan como un mapa de datos); una llamada normal no paga nada.

use synsema_core::ast::ParamType;
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

const LIB: &str = "task g(n: number, label: text = \"x\", tags: list = [], opts: map = {}, on: bool = false)\n    give [type_of(n), label, length(tags), length(opts), on]\n";

#[test]
fn f1_the_signature_parses_and_a_normal_call_does_not_check() {
    assert_eq!(out(&format!("{LIB}print(g(1))\nprint(g(2, \"y\", [1], {{\"a\": 1}}, true))\n")), vec![
        "[\"number\", \"x\", 0, 0, false]",
        "[\"number\", \"y\", 1, 1, true]",
    ]);
    // Metadato: una llamada normal no valida (eso es F2, medido aparte).
    assert_eq!(out(&format!("{LIB}print(g(\"tres\")[0])\n")), vec!["text"]);
    // `nothing` es el default de un parámetro opcional de cualquier tipo.
    assert_eq!(out("task h(n: number = nothing)\n    give n\nprint(h())\n"), vec!["nothing"]);
}

#[test]
fn f1_call_and_call_tool_check_the_declared_types() {
    assert_eq!(out(&format!("{LIB}print(call(g, {{\"n\": 3, \"tags\": [1, 2], \"on\": true}}))\n")), vec![
        "[\"number\", \"x\", 2, 0, true]",
    ]);
    assert_eq!(out(&format!("{LIB}print(call_tool(g, {{\"n\": decimal(\"1.5\")}})[0])\n")), vec!["decimal"]);
    let e = error_of(&format!("{LIB}print(call(g, {{\"n\": \"tres\"}}))\n"));
    assert!(e.contains("call(g): 'n' must be number, got text — a tool call from `llm_step`"), "{}", e);
    let e = error_of(&format!("{LIB}print(call_tool(g, {{\"n\": 1, \"tags\": \"[1]\"}}))\n"));
    assert!(e.contains("call_tool(g): 'tags' must be list, got text"), "{}", e);
    let e = error_of(&format!("{LIB}print(call(g, {{\"n\": 1, \"on\": 1}}))\n"));
    assert!(e.contains("call(g): 'on' must be bool, got number") && !e.contains("llm_step"), "{}", e);
    // Estricto: `nothing` no es un número aunque el parámetro tenga default.
    let e = error_of(&format!("{LIB}print(call(g, {{\"n\": 1, \"opts\": nothing}}))\n"));
    assert!(e.contains("'opts' must be map, got nothing"), "{}", e);
    // Un secret cuenta como texto: en el runtime (`as_secret` es de stdlib), `v0646_f1` de it.
    // Un parámetro tipado sin default que no llegó (`call` liga a `nothing` lo que falta, sin tipo
    // sigue igual); una lambda no tiene tipos.
    let e = error_of(&format!("{LIB}print(call(g, {{}}))\n"));
    assert!(e.contains("call(g): missing 'n' (number)"), "{}", e);
    assert_eq!(out("task u(a, b)\n    give type_of(b)\nprint(call(u, {\"a\": 1}))\n"), vec!["nothing"]);
    assert_eq!(out("print(call((x) => x, {\"x\": \"a\"}))\n"), vec!["a"]);
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
    let s = serde_json::to_string(&v).unwrap();
    let task = find_task(&v, "estado").unwrap_or_else(|| panic!("sin la task: {}", s));
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
    let task = find_task(&v, "d").unwrap_or_else(|| panic!("sin la task: {}", v));
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
