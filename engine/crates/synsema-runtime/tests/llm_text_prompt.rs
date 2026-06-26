//! Las ops LLM de texto (reason/decide/analyze/generate) deben THREADEAR su contexto
//! (`with k=v` / `given …`) dentro del prompt que recibe el LLM — no sólo el subject.
//! Regresión del fix de ETAPA 3 (reason/generate descartaban el contexto). Sin red:
//! `run_capturing_llm` graba el `(op, prompt)` de cada op vía un callback de texto.

use synsema_runtime::engine::run_capturing_llm;

fn prompt_for<'a>(caps: &'a [(String, String)], op: &str) -> &'a str {
    caps.iter()
        .find(|(o, _)| o == op)
        .map(|(_, p)| p.as_str())
        .unwrap_or_else(|| panic!("la op `{}` no fue llamada; caps={:?}", op, caps))
}

#[test]
fn reason_threads_with_context_into_prompt() {
    let src = "require llm\nlet r be reason about \"the weather\" with detail = \"hourly\"\n";
    let (res, caps) = run_capturing_llm(src, "<test>");
    assert!(res.success, "{:?}", res.errors);
    let p = prompt_for(&caps, "reason");
    assert!(p.contains("the weather"), "el subject debe estar en el prompt: {}", p);
    assert!(p.contains("hourly"), "el `with detail=hourly` debe llegar al prompt: {}", p);
}

#[test]
fn generate_threads_given_and_params_into_prompt() {
    let src = "require llm\nlet g be generate \"a report\" given \"sales data\" with tone = \"formal\"\n";
    let (res, caps) = run_capturing_llm(src, "<test>");
    assert!(res.success, "{:?}", res.errors);
    let p = prompt_for(&caps, "generate");
    assert!(p.contains("a report"), "el target debe estar: {}", p);
    assert!(p.contains("sales data"), "el `given` debe llegar al prompt: {}", p);
    assert!(p.contains("formal"), "el `with tone=formal` debe llegar al prompt: {}", p);
}

#[test]
fn decide_and_analyze_thread_their_context() {
    // decide/analyze ya threadeaban; los cubrimos para que no regresionen.
    let src = "require llm\n\
               let d be decide between \"a, b\" given \"speed matters\"\n\
               let a be analyze \"some data\" for \"sentiment\"\n";
    let (res, caps) = run_capturing_llm(src, "<test>");
    assert!(res.success, "{:?}", res.errors);
    let dp = prompt_for(&caps, "decide");
    assert!(dp.contains("speed matters"), "decide `given` ausente: {}", dp);
    let ap = prompt_for(&caps, "analyze");
    assert!(
        ap.contains("sentiment") && ap.contains("some data"),
        "analyze debe llevar data + objetivo: {}",
        ap
    );
}
