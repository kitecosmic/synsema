//! v0.6.46, F1: la firma de una task como esquema de herramienta. `tool_spec` arma la entrada del
//! catálogo de `llm_step` desde la firma; los argumentos que el modelo manda para un parámetro tipado
//! vuelven a su tipo (el proveedor los pasa como texto) y `call_tool` valida.

use synsema_runtime::engine::{run_program, run_with_llm_steps, LlmStep, LlmStepResponse};

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "v0646_f1.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn tool(name: &str, args: &[(&str, &str)]) -> LlmStepResponse {
    LlmStepResponse {
        step: LlmStep::ToolCall {
            name: name.to_string(),
            args: args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        },
        tokens_used: 1,
    }
}

const ADD: &str = "task add(a: number, b: number = 1, note, tags: list = [])\n    give a + b + length(tags)\n";

#[test]
fn f1_tool_spec_takes_the_catalog_from_the_signature() {
    assert_eq!(
        out(&format!("{ADD}print(json_encode(tool_spec(add, \"Adds two numbers\")))\n")),
        vec![r#"{"name": "add", "describe": "Adds two numbers", "params": ["a: number", "b: number", "note", "tags: list"], "optional": ["b", "tags"]}"#]
    );
    assert_eq!(out(&format!("{ADD}print(tool_spec(add).describe == \"\")\n")), vec!["true"]);
    let r = run_program("print(tool_spec((x) => x))\n", "v0646_f1.syn");
    assert!(r.errors.join("\n").contains("tool_spec needs a named task"), "{:?}", r.errors);
    let r = run_program("print(tool_spec(length))\n", "v0646_f1.syn");
    assert!(r.errors.join("\n").contains("not the builtin 'length'"), "{:?}", r.errors);
    // Un secret cuenta como texto para `call` (y sigue opaco).
    assert_eq!(
        out("task k(key: text)\n    give type_of(key)\nprint(call(k, {\"key\": as_secret(\"s\")}))\n"),
        vec!["secret"]
    );
}

/// El proveedor manda `"2"`, `"[1, 2]"`: con el catálogo tipado vuelven a número y lista, `note` (sin
/// tipo) sigue siendo texto aunque parezca un número. Lo que no da el tipo queda como texto y
/// `call_tool` lo rechaza diciendo por qué.
#[test]
fn f1_a_typed_catalog_brings_typed_arguments() {
    let src = format!(
        "{ADD}let catalog be [tool_spec(add, \"Adds\")]\n\
         let s be llm_step(\"q\", catalog, \"\")\n\
         print(type_of(s.args.a), type_of(s.args.b), type_of(s.args.note), type_of(s.args.tags))\n\
         print(call_tool(add, s.args))\n\
         let s2 be llm_step(\"q\", catalog, \"\")\n\
         print(type_of(s2.args.a))\n\
         try\n    print(call_tool(add, s2.args))\nrecover e\n    print(e)\n\
         let s3 be llm_step(\"q\", [{{\"name\": \"add\", \"params\": [\"a\", \"b\"]}}], \"\")\n\
         print(type_of(s3.args.a))\n"
    );
    let r = run_with_llm_steps(
        &src,
        "v0646_f1.syn",
        vec![
            tool("add", &[("a", "2"), ("b", "3"), ("note", "7"), ("tags", "[1, 2]")]),
            tool("add", &[("a", "dos"), ("note", "x")]),
            tool("add", &[("a", "2"), ("b", "3")]),
        ],
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "number number text list");
    assert_eq!(r.output[1], "7");
    assert_eq!(r.output[2], "text");
    assert!(r.output[3].contains("call_tool(add): 'a' must be number, got text"), "{:?}", r.output);
    // Un catálogo sin tipos: como antes, texto.
    assert_eq!(r.output[4], "text");
}

#[test]
fn f1_an_unknown_type_in_the_catalog_is_an_error() {
    let r = run_with_llm_steps(
        "let s be llm_step(\"q\", [{\"name\": \"t\", \"params\": [\"n: nmber\"]}], \"\")\n",
        "v0646_f1.syn",
        vec![tool("t", &[])],
    );
    assert!(r.errors.join("\n").contains("tool 't' declares the parameter 'n: nmber' with an unknown type"), "{:?}", r.errors);
}

/// v0.6.46 (ronda 1 de cf1, N2): un `null` del modelo es "no lo pasó": en un opcional corre el
/// default, en uno tipado obligatorio `call_tool` dice que falta (antes llegaba el texto "null").
#[test]
fn f1_a_null_from_the_model_is_a_missing_argument() {
    let src = format!(
        "{ADD}let catalog be [tool_spec(add, \"Adds\")]\n\
         let s be llm_step(\"q\", catalog, \"\")\n\
         print(call_tool(add, s.args))\n\
         let s2 be llm_step(\"q\", catalog, \"\")\n\
         try\n    print(call_tool(add, s2.args))\nrecover e\n    print(e)\n"
    );
    let r = run_with_llm_steps(
        &src,
        "v0646_f1.syn",
        vec![
            tool("add", &[("a", "2"), ("b", "null"), ("note", "n"), ("tags", "null")]),
            tool("add", &[("a", "null"), ("note", "n")]),
        ],
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output[0], "3");
    assert!(r.output[1].contains("missing 'a' (number)"), "{:?}", r.output);
}
