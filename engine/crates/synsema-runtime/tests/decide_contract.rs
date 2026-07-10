//! DE-039: el brazo `decide between [...]` pasa las opciones ESTRUCTURADAS al callback
//! dedicado (no sólo embebidas en el prompt) y devuelve su resultado tal cual. Sin red:
//! `run_capturing_decide` graba `(prompt, opciones)` de cada decide.

use synsema_runtime::engine::{run_capturing_decide, run_capturing_llm};

#[test]
fn decide_between_passes_structured_options() {
    let src = "require llm\n\
               let d be decide between [\"ROJO\", \"AZUL\"] given \"un color\"\n\
               print(d)\n";
    let (res, caps) = run_capturing_decide(src, "<test>", "ROJO");
    assert!(res.success, "{:?}", res.errors);
    assert_eq!(caps.len(), 1, "un decide → una llamada al callback dedicado");
    let (prompt, options) = &caps[0];
    assert_eq!(options, &vec!["ROJO".to_string(), "AZUL".to_string()]);
    assert!(prompt.contains("un color"), "el `given` debe llegar al prompt: {}", prompt);
    assert_eq!(res.output, vec!["ROJO".to_string()], "decide devuelve lo del callback");
}

#[test]
fn decide_without_list_passes_empty_options() {
    // `decide "a, b"` (opciones como texto plano, no lista) → el callback dedicado
    // recibe opciones vacías: el contrato no aplica y el provider va por texto.
    let src = "require llm\nlet d be decide \"a, b\" given \"speed\"\n";
    let (res, caps) = run_capturing_decide(src, "<test>", "ok");
    assert!(res.success, "{:?}", res.errors);
    assert_eq!(caps.len(), 1);
    assert!(caps[0].1.is_empty(), "sin lista no hay opciones estructuradas: {:?}", caps[0].1);
}

#[test]
fn decide_falls_back_to_text_callback_without_dedicated_one() {
    // Retrocompat: sin callback dedicado (mocks/wirings viejos), decide usa el
    // callback de texto genérico como siempre.
    let src = "require llm\nlet d be decide between [\"a\", \"b\"] given \"x\"\n";
    let (res, caps) = run_capturing_llm(src, "<test>");
    assert!(res.success, "{:?}", res.errors);
    assert!(
        caps.iter().any(|(op, _)| op == "decide"),
        "el callback de texto debe seguir recibiendo decide: {:?}",
        caps
    );
}
