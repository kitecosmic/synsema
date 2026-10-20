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

#[test]
fn public_values_still_reach_the_host() {
    let (r, spy) = run_with_secret("http_post(\"https://x.test/\", {\"n\": input.nombre})\n");
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(spy.http.borrow().len(), 1, "el control: un valor público sí sale");
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
        .copied()
        .collect();
    let unclassified: Vec<&String> = registered.iter().filter(|n| !known.contains(n.as_str())).collect();
    assert!(unclassified.is_empty(), "builtins del wasm SIN clasificar: {:?}", unclassified);
}
