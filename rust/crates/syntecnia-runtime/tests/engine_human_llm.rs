//! Integración Rust de human + llm a nivel motor (capa 7, Stage 5).
//! Son host-config (callbacks seteados por el embebedor), igual que secure=True.

use std::collections::HashMap;

use syntecnia_runtime::engine::{run_with_human, run_with_llm};

#[test]
fn human_interaction_in_engine() {
    // AutoHandler que aprueba → approve no bloquea, sigue al print.
    let src = "approve \"Deploy to production?\"\nprint(\"deployed!\")\n";
    let r = run_with_human(src, "<t>", true);
    assert!(r.success, "{:?}", r.errors);
    assert!(r.output.contains(&"deployed!".to_string()));
}

#[test]
fn human_denial_in_engine() {
    // AutoHandler que deniega → approved=false → rama otherwise.
    let src = "let approved be approve \"Do dangerous thing?\"\nwhen approved\n    print(\"did it\")\notherwise\n    print(\"denied\")\n";
    let r = run_with_human(src, "<t>", false);
    assert!(r.success, "{:?}", r.errors);
    assert!(r.output.contains(&"denied".to_string()));
}

#[test]
fn mock_provider_in_engine() {
    // analyze usa el MockProvider → devuelve la respuesta configurada.
    let mut responses = HashMap::new();
    responses.insert("analyze".to_string(), "Positive sentiment".to_string());
    responses.insert("decide".to_string(), "refund".to_string());
    let src = "let data be {\"issue\": \"broken item\"}\nlet result be analyze data for \"sentiment\"\nprint(result)\n";
    let r = run_with_llm(src, "<t>", responses);
    assert!(r.success, "{:?}", r.errors);
    assert!(r.output[0].contains("Positive sentiment"), "got {:?}", r.output);
}
