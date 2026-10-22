//! Tests deterministas de la primitiva `llm_stream` (F2, sin modelo ni red).
//!
//! Calcan el patrón de `tool_calling_e2e`: `run_with_llm_stream` cablea un callback
//! GUIONADO que entrega una secuencia fija de chunks. Verifican: gate por `llm`,
//! placeholder sin provider (sin invocar `on_chunk`), invocación por chunk en orden +
//! retorno completo, y propagación del error de `on_chunk` (corta la generación).

use synsema_runtime::engine::{run_source, run_source_secure, run_with_llm_stream};

fn chunks(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// Gate: en secure SIN `require llm`, el gate corta antes de tocar el callback.
#[test]
fn llm_stream_requires_llm_capability_in_secure_mode() {
    let src = "task on_tok(t)\n    print(t)\nlet full be llm_stream(\"q\", \"\", on_tok)\n";
    let r = run_source_secure(src, "<test>");
    assert!(!r.success, "debía fallar por falta de `require llm`: {:?}", r.output);
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: llm")),
        "esperaba 'Capability not granted: llm', got {:?}",
        r.errors
    );
}

// §4.2: sin provider cableado → placeholder y `on_chunk` NO invocada.
#[test]
fn llm_stream_without_provider_placeholder_no_chunks() {
    let src = "require llm\n\
               task on_tok(t)\n    print(\"CHUNK:\" + t)\n\
               let full be llm_stream(\"q\", \"\", on_tok)\n\
               print(\"FULL:\" + full)\n";
    let r = run_source(src, "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["FULL:[no llm provider]".to_string()]);
}

// §4.3: mock guionado → `on_chunk` invocada por chunk EN ORDEN; retorno = concatenación.
#[test]
fn llm_stream_scripted_chunks_in_order() {
    let src = "require llm\n\
               task on_tok(t)\n    print(\"CHUNK:\" + t)\n\
               let full be llm_stream(\"q\", \"\", on_tok)\n\
               print(\"FULL:\" + full)\n";
    let r = run_with_llm_stream(src, "<test>", chunks(&["Ho", "la"]));
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["CHUNK:Ho".to_string(), "CHUNK:la".to_string(), "FULL:Hola".to_string()]
    );
}

// §4.3: `on_chunk` que falla al PRIMER chunk → el error propaga (el programa cae como
// con cualquier error no recuperado) y NO hay segunda invocación.
#[test]
fn llm_stream_on_chunk_error_propagates_and_stops() {
    let src = "require llm\n\
               task on_tok(t)\n    print(\"CHUNK:\" + t)\n    raise(\"sink roto\")\n\
               let full be llm_stream(\"q\", \"\", on_tok)\n\
               print(\"FULL:\" + full)\n";
    let r = run_with_llm_stream(src, "<test>", chunks(&["Ho", "la"]));
    assert!(!r.success, "el error del on_chunk debía propagar: {:?}", r.output);
    assert!(
        r.errors.iter().any(|e| e.contains("sink roto")),
        "el error debía ser el del sink, got {:?}",
        r.errors
    );
    // Se invocó con el 1er chunk, se cortó ANTES del 2do, y el retorno nunca se imprimió.
    assert_eq!(r.output, vec!["CHUNK:Ho".to_string()]);
}

// El error de `on_chunk` es recuperable con try/recover — se desenrolla como cualquier
// error de Synsema, no como un caso especial.
#[test]
fn llm_stream_on_chunk_error_is_recoverable() {
    let src = "require llm\n\
               task on_tok(t)\n    raise(\"sink roto\")\n\
               try\n    let full be llm_stream(\"q\", \"\", on_tok)\n    print(\"NO-LLEGA\")\nrecover err\n    print(\"RECUPERADO\")\n";
    let r = run_with_llm_stream(src, "<test>", chunks(&["Ho", "la"]));
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["RECUPERADO".to_string()]);
}
