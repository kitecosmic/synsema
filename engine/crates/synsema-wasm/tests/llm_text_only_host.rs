//! v0.6.54 (§D de v0.6.51): con un host que ofrece `llm`, `llm_step` y `llm_stream` devolvían el
//! placeholder `"[no llm provider]"`, que parecía una respuesta del modelo. El hook del host sólo
//! contesta texto: ahora son un error que lo dice. Sin host, siguen los placeholders offline.

use std::rc::Rc;

use synsema_stdlib::hostcap::{self, HostLlmResult, HostProvider};
use synsema_wasm::{run, RunOptions};

struct LlmHost;

impl HostProvider for LlmHost {
    fn offers(&self, what: &str) -> bool {
        what == "llm"
    }
    fn llm(&self, _op: &str, _prompt: &str, _principals: &[String]) -> Option<Result<HostLlmResult, String>> {
        Some(Ok(HostLlmResult { content: "texto del host".to_string(), tokens: 1 }))
    }
}

fn run_src(src: &str, host: bool) -> synsema_wasm::Report {
    hostcap::install(if host { Some(Rc::new(LlmHost)) } else { None });
    let report = run(src, &RunOptions::new("t.syn"));
    hostcap::install(None);
    report
}

#[test]
fn llm_step_and_stream_say_the_host_answers_text_only() {
    let r = run_src("require llm\nprint(reason \"hola\")\n", true);
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(r.output, vec!["texto del host".to_string()]);

    let r = run_src("require llm\nlet s be llm_step(\"hola\", [])\nprint(s)\n", true);
    assert!(!r.ok, "{:?}", r.output);
    assert!(
        r.errors.iter().any(|e| e.contains("llm_step: the host gives the model through its `llm` hook, which answers whole texts (reason/decide/analyze/generate); tool calling is not available in this embedding")),
        "{:?}",
        r.errors
    );

    let r = run_src("require llm\nlet s be llm_stream(\"hola\", \"\", (c) => print(c))\nprint(s)\n", true);
    assert!(!r.ok, "{:?}", r.output);
    assert!(
        r.errors.iter().any(|e| e.contains("llm_stream:")
            && e.contains("whole texts (reason/decide/analyze/generate); streaming is not available")),
        "{:?}",
        r.errors
    );

    // Sin host que ofrezca `llm`: el placeholder offline de siempre.
    let r = run_src("require llm\nprint(llm_stream(\"hola\", \"\", (c) => print(c)))\n", false);
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(r.output, vec!["[no llm provider]".to_string()]);
}
