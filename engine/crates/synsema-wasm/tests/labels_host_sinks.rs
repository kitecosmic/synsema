//! v0.6.45 (D1): con `labels: true` el wasm encendía las etiquetas sin registrar ningún sumidero.
//! `print` redactaba, pero `fetch`/`http_*` hacia el hook del host, `state_set` al KV y la rama
//! sobre un secreto salían sin chequeo; en nativo los mismos programas daban `label_violation`
//! (sonda de `proyectos/datos/.../sonda_trifecta.ts`). Ahora el wasm registra los sumideros desde
//! la misma lista que el nativo (`synsema_stdlib::label_lists`).

use std::cell::RefCell;
use std::rc::Rc;

use synsema_stdlib::hostcap::{self, HostHttpRequest, HostProvider, HttpResult};
use synsema_wasm::{run, RunOptions};

/// Un host que presta red y KV y anota qué le llegó.
#[derive(Default)]
struct Spy {
    http: RefCell<Vec<String>>,
    kv: RefCell<Vec<String>>,
}

struct Host(Rc<Spy>);

impl HostProvider for Host {
    fn offers(&self, what: &str) -> bool {
        matches!(what, "http" | "kv")
    }
    fn http(&self, req: &HostHttpRequest<'_>) -> Option<Result<HttpResult, String>> {
        let body = req.body.map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
        self.0.http.borrow_mut().push(format!("{} {} {}", req.method, req.url, body));
        Some(Ok(HttpResult {
            status: 200,
            ok: true,
            body: "{}".to_string(),
            body_bytes: b"{}".to_vec(),
            headers: Vec::new(),
            error: None,
            attested: None,
        }))
    }
    fn kv_get(&self, _ns: &str, _key: &str) -> Option<Option<String>> {
        Some(None)
    }
    fn kv_set(&self, ns: &str, key: &str, value: &str) -> Option<Result<(), String>> {
        self.0.kv.borrow_mut().push(format!("{}/{}={}", ns, key, value));
        Some(Ok(()))
    }
}

/// Corre `body` con `input.tarjeta` privado (una fuente del host) y devuelve el reporte y lo que
/// vio el host.
fn run_with_secret(body: &str) -> (synsema_wasm::Report, Rc<Spy>) {
    let spy = Rc::new(Spy::default());
    hostcap::install(Some(Rc::new(Host(spy.clone()))));
    let mut opts = RunOptions::new("d1.syn");
    opts.labels = true;
    opts.input = Some(("input".to_string(), serde_json::json!({"tarjeta": "4111-1111", "nombre": "Ana"})));
    opts.sources = vec![("tarjeta".to_string(), vec!["cliente".to_string()])];
    let src = format!("require net(\"x.test\")\n{}", body);
    let report = run(&src, &opts);
    hostcap::install(None);
    (report, spy)
}

fn violation(r: &synsema_wasm::Report) -> bool {
    r.errors.iter().any(|e| e.contains("label_violation"))
}

#[test]
fn a_private_value_never_reaches_the_host_network_hook() {
    let (r, spy) = run_with_secret("http_post(\"https://x.test/\", {\"t\": input.tarjeta})\n");
    assert!(!r.ok && violation(&r), "debía ser label_violation: {:?}", r.errors);
    assert!(spy.http.borrow().is_empty(), "el dato privado llegó al host: {:?}", spy.http.borrow());
}

#[test]
fn a_branch_on_a_private_value_cannot_call_the_network() {
    let (r, spy) = run_with_secret(
        "when input.tarjeta == \"4111-1111\"\n    fetch(\"https://x.test/si\", {\"method\": \"GET\"})\n",
    );
    assert!(!r.ok && violation(&r), "debía ser label_violation: {:?}", r.errors);
    assert!(spy.http.borrow().is_empty(), "el bit de la rama salió: {:?}", spy.http.borrow());
}

#[test]
fn a_private_value_never_reaches_the_host_kv() {
    let (r, spy) = run_with_secret("state_set(\"k\", input.tarjeta)\n");
    assert!(!r.ok && violation(&r), "debía ser label_violation: {:?}", r.errors);
    assert!(spy.kv.borrow().iter().all(|w| !w.contains("4111")), "el dato privado llegó al KV: {:?}", spy.kv.borrow());
}

/// v0.6.45 (auditoría, M5): en wasm el número de `sleep` cruza el ABI hacia el hook del host, así
/// que con etiquetas es un sumidero (en nativo es sólo tiempo). Antes `sleep(input.pin / 1e6)` le
/// entregaba el PIN al host.
#[test]
fn a_private_value_cannot_reach_the_host_sleep_hook() {
    let (r, _spy) = run_with_secret("sleep(length(input.tarjeta) / 1000)\n");
    assert!(!r.ok && violation(&r), "debía ser label_violation: {:?}", r.errors);
    let (r, _spy) = run_with_secret("when input.tarjeta == \"4111-1111\"\n    sleep(0.001)\n");
    assert!(!r.ok && violation(&r), "la rama privada tampoco: {:?}", r.errors);
    let (r, _spy) = run_with_secret("sleep(0.001)\n");
    assert!(r.ok, "un sleep público sigue: {:?}", r.errors);
}

/// El control va por el KV del host: `state_set` del wasm habla siempre con el hook. La red no sirve
/// de control acá: con `cargo test --workspace` las features se unifican, `synsema-stdlib` queda con
/// `native` y `http_post` sale por el transporte real en vez del hook (en el build wasm no pasa).
#[test]
fn public_values_still_reach_the_host() {
    let (r, spy) = run_with_secret("state_set(\"k\", input.nombre)\n");
    assert!(r.ok, "{:?}", r.errors);
    let kv = spy.kv.borrow();
    assert!(kv.len() == 1 && kv[0].contains("Ana"), "el control: un valor público sí sale: {:?}", kv);
}

/// Anti-rot del wasm (par de `every_effectful_family_is_a_label_sink` del runtime): todo builtin que
/// registra el wasm — con un host que presta red y KV, así se cablean sus hooks — está clasificado
/// en las listas de `synsema_stdlib::label_lists` (o es `label_aware` del core). Un builtin nuevo del
/// wasm que hable con el host rompe este test hasta que alguien decida de qué lado está.
#[test]
fn every_wasm_builtin_is_classified() {
    use std::collections::BTreeSet;
    use synsema_stdlib::label_lists as l;
    let spy = Rc::new(Spy::default());
    hostcap::install(Some(Rc::new(Host(spy))));
    let mut opts = RunOptions::new("antirot.syn");
    opts.labels = true;
    let registered = synsema_wasm::registered_builtin_names(&opts);
    hostcap::install(None);
    assert!(registered.len() > 300, "el wasm registra {} builtins", registered.len());
    let known: BTreeSet<&str> = l::LABEL_SINK_BUILTINS
        .iter()
        .chain(l::LABEL_PURE_BUILTINS)
        .chain(l::LABEL_SINKS_SERVE_ONLY)
        .chain(synsema_core::interpreter::CORE_SINK_BUILTINS)
        .chain(synsema_core::interpreter::PROTECTED_BUILTIN_NAMES)
        .chain(synsema_core::interpreter::CORE_LLM_LABEL_AWARE)
        .copied()
        .collect();
    let unclassified: Vec<&String> = registered.iter().filter(|n| !known.contains(n.as_str())).collect();
    assert!(unclassified.is_empty(), "builtins del wasm SIN clasificar: {:?}", unclassified);
}

/// v0.6.46 (E3): `ceiling: "declassify=a"` acota lo que el programa puede publicar en wasm igual que
/// `--cap-set` en el nativo (el gate se cablea en `wire_pure` con el mismo helper).
#[test]
fn e3_wasm_ceiling_bounds_declassify() {
    hostcap::install(None);
    let run_with = |body: &str, ceiling: Option<&str>| {
        let mut opts = RunOptions::new("e3.syn");
        opts.labels = true;
        opts.ceiling = ceiling.map(|c| synsema_wasm::parse_ceiling(c).unwrap().unwrap());
        run(&format!("let x be private(1, \"a\")\nlet y be private(2, \"b\")\n{}", body), &opts)
    };
    let r = run_with("print(declassify(x, \"m\"))\n", Some("stdout,declassify=a"));
    assert!(r.ok, "{:?}", r.errors);
    let r = run_with("print(declassify(y, \"m\"))\n", Some("stdout,declassify=a"));
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("declassify is not granted")), "{:?}", r.errors);
    // Sin techo, de ambiente como en el nativo.
    let r = run_with("print(declassify(y, \"m\"))\n", None);
    assert!(r.ok, "{:?}", r.errors);
}

/// v0.6.46 (E3b): `trusted` del embebedor. Bajo un `ceiling` sin `declassify`, el programa publica
/// sólo por la tool de confianza; directo, no.
#[test]
fn e3b_wasm_trusted_tool_publishes_its_policy_only() {
    hostcap::install(None);
    let run_with = |body: &str| {
        let mut opts = RunOptions::new("e3b.syn");
        opts.labels = true;
        opts.ceiling = Some(synsema_wasm::parse_ceiling("stdout").unwrap().unwrap());
        opts.trusted = vec![(
            "t".to_string(),
            "export task inicial(c)\n    require declassify(\"clientes\")\n    give declassify(c.nombre, \"la inicial del cliente\")\n".to_string(),
        )];
        run(&format!("use \"trusted:t\" as t\nlet c be private({{\"nombre\": \"Ana\"}}, \"clientes\")\n{}", body), &opts)
    };
    let r = run_with("print(t.inicial(c))\n");
    assert!(r.ok && r.output.iter().any(|l| l == "Ana"), "{:?} {:?}", r.output, r.errors);
    let r = run_with("print(declassify(c.nombre, \"m\"))\n");
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("declassify is not granted")), "{:?}", r.errors);
}

/// v0.6.46 (E5): un host que presta `llm` y anota (prompt, principales). `falla`: el hook "lanza".
struct LlmHost(Rc<RefCell<Vec<(String, Vec<String>)>>>, bool);

impl HostProvider for LlmHost {
    fn offers(&self, what: &str) -> bool {
        what == "llm"
    }
    fn llm(&self, _op: &str, prompt: &str, principals: &[String]) -> Option<Result<hostcap::HostLlmResult, String>> {
        self.0.borrow_mut().push((prompt.to_string(), principals.to_vec()));
        if self.1 {
            return Some(Err("the hook threw: boom".to_string()));
        }
        Some(Ok(hostcap::HostLlmResult { content: "respuesta".to_string(), tokens: 0 }))
    }
}

/// v0.6.46 (E5): en wasm el modelo es el del host que embebe, `llm=P@embedder` en el techo. Sin ese
/// ítem el dato privado no llega al hook; con él llega sin redactar, el hook recibe los principales
/// y la respuesta sale privada. Un hook que falla es error de la llamada (antes: `""` con `ok`).
#[test]
fn e5_wasm_private_to_the_embedder_needs_the_ceiling() {
    let run_with = |ceiling: &str, falla: bool| {
        let seen = Rc::new(RefCell::new(Vec::new()));
        hostcap::install(Some(Rc::new(LlmHost(seen.clone(), falla))));
        let mut opts = RunOptions::new("e5.syn");
        opts.labels = true;
        opts.ceiling = Some(synsema_wasm::parse_ceiling(ceiling).unwrap().unwrap());
        let r = run(
            "require llm(\"a\")\nlet x be private(\"dato-secreto\", \"a\")\nlet r be reason x\nprint(label_of(r))\n",
            &opts,
        );
        hostcap::install(None);
        let seen = seen.borrow().clone();
        (r, seen)
    };
    let (r, seen) = run_with("stdout,llm=a@embedder", false);
    assert!(r.ok, "{:?}", r.errors);
    // `label_of` da los nombres etiquetados: `print` los redacta.
    assert_eq!(r.output, vec!["[private(a)]".to_string()]);
    assert_eq!(seen.len(), 1);
    assert!(seen[0].0.contains("dato-secreto") && !seen[0].0.contains("private("), "{:?}", seen);
    assert_eq!(seen[0].1, vec!["a".to_string()]);
    for c in ["stdout,llm=a@local", "stdout,llm", "stdout,llm=b@embedder"] {
        let (r, seen) = run_with(c, false);
        assert!(!r.ok && violation(&r), "{}: {:?}", c, r.errors);
        assert!(seen.is_empty(), "{}: el dato llegó al hook: {:?}", c, seen);
    }
    let (r, _) = run_with("stdout,llm=a@embedder", true);
    // El mensaje sale redactado (la llamada tocó datos privados); lo que cambia es que ya no es
    // una respuesta vacía con `ok`.
    assert!(!r.ok && r.output.is_empty() && !r.errors.is_empty(), "{:?} {:?}", r.output, r.errors);
}

/// v0.6.46 (E5): `judge` se gatea en wasm como en el nativo (antes no había gate: el bloque pasaba
/// aunque el techo no lo diera).
#[test]
fn e5_wasm_judge_gate() {
    hostcap::install(None);
    let run_with = |ceiling: Option<&str>| {
        let mut opts = RunOptions::new("e5j.syn");
        opts.ceiling = ceiling.map(|c| synsema_wasm::parse_ceiling(c).unwrap().unwrap());
        run("let v be judge \"hola\"\n    q: whether \"Is it a greeting?\"\nprint(v.q.available)\n", &opts)
    };
    let r = run_with(Some("stdout"));
    assert!(!r.ok && r.errors.iter().any(|e| e.contains("judge")), "{:?}", r.errors);
    let r = run_with(Some("stdout,judge"));
    assert!(r.ok, "{:?}", r.errors);
    let r = run_with(None);
    assert!(r.ok, "{:?}", r.errors);
}
