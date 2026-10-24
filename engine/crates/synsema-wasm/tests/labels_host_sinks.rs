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
    fn kv_get(&self, _ns: &str, _key: &str) -> Option<Result<Option<String>, String>> {
        Some(Ok(None))
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

/// v0.6.47 (T1): el dato privado elige cuál de N sitios corta la corrida (`fetch`, `state_set`, un
/// `http_post` con el dato, `print`, una asignación). Lo que ve el programa (`ok`, `output`, `errors`,
/// `exit_code`) es idéntico byte a byte; cuál fue queda en `operator_detail`.
#[test]
fn t1_the_site_a_private_input_chooses_is_the_same_text_for_the_program() {
    let sites = [
        "fetch(\"https://x.test/si\", {\"method\": \"GET\"})",
        "state_set(\"k\", 1)",
        "http_post(\"https://x.test/\", {\"d\": d})",
        "print(\"x\")",
        "set a to 1",
    ];
    let mut body = String::from("require net(\"x.test\")\nlet d be input.d\nlet a be 0\n");
    for (i, site) in sites.iter().enumerate() {
        body.push_str(&format!("when d == {}\n    {}\n", i, site));
    }
    let mut seen = Vec::new();
    let mut details = Vec::new();
    for k in 0..sites.len() {
        let spy = Rc::new(Spy::default());
        hostcap::install(Some(Rc::new(Host(spy.clone()))));
        let mut opts = RunOptions::new("t1.syn");
        opts.labels = true;
        opts.input = Some(("input".to_string(), serde_json::json!({"d": k})));
        opts.sources = vec![("d".to_string(), vec!["cliente".to_string()])];
        let r = run(&body, &opts);
        hostcap::install(None);
        assert!(!r.ok, "sitio {}: tenía que cortar", k);
        assert!(spy.http.borrow().is_empty() && spy.kv.borrow().is_empty(), "sitio {}: salió algo al host", k);
        seen.push(format!("{:?} {:?} {:?} {:?}", r.ok, r.output, r.errors, r.exit_code));
        details.push(r.operator_detail.clone().unwrap_or_else(|| panic!("sitio {}: sin operator_detail: {:?}", k, r.errors)));
    }
    for (k, s) in seen.iter().enumerate() {
        assert_eq!(s, &seen[0], "el sitio {} se distingue del 0 hacia el programa", k);
    }
    assert!(seen[0].contains("the flow checker stopped the run (private to cliente)"), "{}", seen[0]);
    for (k, d) in details.iter().enumerate() {
        assert!(d.contains(&format!("t1.syn:{}:", 5 + 2 * k)), "sitio {}: el detalle lleva su línea: {}", k, d);
    }
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
    // v0.6.47 (T1): el programa ve el texto fijo; el motivo va en `operator_detail`.
    let r = run_with("print(declassify(y, \"m\"))\n", Some("stdout,declassify=a"));
    assert!(!r.ok && r.errors.iter().all(|e| !e.contains("declassify is not granted")), "{:?}", r.errors);
    assert!(r.operator_detail.as_deref().is_some_and(|d| d.contains("declassify is not granted")), "{:?}", r.operator_detail);
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
    assert!(!r.ok && r.errors.iter().all(|e| !e.contains("declassify is not granted")), "{:?}", r.errors);
    assert!(r.operator_detail.as_deref().is_some_and(|d| d.contains("declassify is not granted")), "{:?}", r.operator_detail);
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
    // una respuesta vacía con `ok`. v0.6.47 (T1): la salida de un corte es siempre la línea fija.
    assert!(!r.ok && r.output.len() == 1 && r.output[0].contains("its output is withheld") && !r.errors.is_empty(), "{:?} {:?}", r.output, r.errors);
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

/// v0.6.46 (E6-g): con `RunOptions.auditor`, `Report.receipt` trae el recibo sellado de la corrida:
/// verifica, lo de la rama privada va adentro del sobre, y el `program_sha` es el del fuente. Sin
/// auditor no hay recibo.
#[test]
fn e6_wasm_report_carries_the_receipt() {
    let (sk, pk) = synsema_stdlib::sealed::generate_keypair();
    let src = "require random\nlet p be private(5, \"app\")\nwhen p > 3\n    let r be random()\nprint(\"hola\")\n";
    let mut opts = RunOptions::new("e6.syn");
    opts.labels = true;
    let plain = run(src, &opts);
    assert!(plain.ok, "{:?}", plain.errors);
    assert!(plain.receipt.is_none());

    opts.auditor = Some(synsema_stdlib::sealed::parse_auditor_key(&pk).unwrap());
    opts.sealed_bytes = Some(8192);
    let r = run(src, &opts);
    assert!(r.ok, "{:?}", r.errors);
    assert_eq!(r.output, ["hola"]);
    let receipt = r.receipt.expect("el recibo");
    let header = synsema_stdlib::sealed::verify_receipt(&receipt).expect("verifica");
    assert_eq!(header["program_sha"], synsema_core::bytesutil::hex_encode(&synsema_stdlib::attest::sha256(src.as_bytes())));
    assert_eq!(header["sealed_bytes"], 8192);
    let sk = synsema_core::bytesutil::b64url_decode(&sk).unwrap();
    let opened = synsema_stdlib::sealed::open_receipt(&receipt, &sk).expect("el auditor lo abre");
    assert!(
        opened["entries"].as_array().unwrap().iter().any(|e| e["sealed"] == true && e["entry"]["capability"] == "random"),
        "{}",
        opened
    );
    assert!(receipt["public"].as_array().unwrap().iter().all(|e| e.get("line") != Some(&serde_json::json!(4))));
}

/// v0.6.47 (T1): un corte antes de toda salida y uno después dan la misma salida (la línea fija).
#[test]
fn t1_a_cut_before_any_output_looks_like_a_cut_after_it() {
    let out = |k: u32| {
        let (r, _) = run_with_secret(&format!(
            "let s be private({k}, \"app\")\nwhen s == 1\n    print(\"x\")\nprint(\"antes\")\nwhen s == 2\n    print(\"y\")\n"
        ));
        (r.ok, r.output, r.errors)
    };
    let (a, b) = (out(1), out(2));
    assert_eq!(a, b);
    assert!(!a.0 && a.1.len() == 1 && a.1[0].contains("its output is withheld"), "{:?}", a);
}

/// v0.6.47 (T1, ronda 6, M2): en el handler, como en serve, un corte es siempre el 500 fijo, aunque
/// nazca en un `expect` o en una denegación del token bajo una rama privada (era 400 con el `field`
/// o 403: el status decía qué sitio cortó). El detalle va al operador.
#[test]
fn m2_a_cut_in_the_handler_is_always_the_fixed_500() {
    let src = r#"require serve(8080)
require time
require random
let root be "root-key-m2"
task check_agent(token, request)
    give captoken_verify(token, root, {"aud": "m2"})
serve on 8080
    auth with check_agent
    route "GET /token"
        give {"t": captoken_mint({"net": "api.example.com"}, root, {"aud": "m2", "ttl": 600, "id": "m2", "deterministic": true})}
    route "GET /corta"
        let s be private(int(query["s"]), "app")
        when s == 1
            let z be 1 / 0
        give 1
    route "POST /valida"
        let s be private(int(query["s"]), "app")
        when s == 1
            expect body {item: text}
        give 1
    route "GET /niega" requires auth
        let s be private(int(query["s"]), "app")
        when s == 1
            let r be now()
        give 1
"#;
    let mut opts = RunOptions::new("m2.syn");
    opts.labels = true;
    let call = |method: &str, path: &str, headers: Vec<(String, String)>, body: &str| {
        let req = synsema_wasm::HttpRequestIn {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body: body.as_bytes().to_vec(),
            client_ip: "127.0.0.1".to_string(),
        };
        synsema_wasm::handle(src, &opts, &req)
    };
    let json = vec![("content-type".to_string(), "application/json".to_string())];
    let corte = call("GET", "/corta?s=1", Vec::new(), "");
    assert_eq!(corte.response.status, 500, "{:?}", String::from_utf8_lossy(&corte.response.body));
    let v = call("POST", "/valida?s=1", json.clone(), "{}");
    assert_eq!(v.response.status, 500, "{}", String::from_utf8_lossy(&v.response.body));
    assert_eq!(v.response.body, corte.response.body);
    assert!(v.operator_detail.is_some());
    assert_eq!(call("POST", "/valida?s=2", json, "{}").response.status, 200);

    let tok = call("GET", "/token", Vec::new(), "");
    let t: serde_json::Value = serde_json::from_slice(&tok.response.body).unwrap();
    let auth = vec![("authorization".to_string(), format!("Bearer {}", t["t"].as_str().unwrap()))];
    let n = call("GET", "/niega?s=1", auth.clone(), "");
    assert_eq!(n.response.status, 500, "{}", String::from_utf8_lossy(&n.response.body));
    assert_eq!(n.response.body, corte.response.body);
    assert!(n.operator_detail.is_some());
    assert_eq!(call("GET", "/niega?s=2", auth, "").response.status, 200);
}

/// v0.6.47 (T1, ronda 7, B1): en el handler, la página de `errors with` que se corta o devuelve algo
/// que la respuesta rechaza es un corte, como en serve: el log es la línea fija y el detalle va al
/// operador.
#[test]
fn b1_an_error_page_cut_leaves_the_fixed_log() {
    let src = r#"require serve(8080)
task pag(status, message, request)
    print("pagina")
    let k be private(1, "app")
    when status == 404
        give {"k": k}
    when k == 1
        let z be 1 / 0
    give nothing
serve on 8080
    errors with pag
    route "GET /x"
        give 1
"#;
    let mut opts = RunOptions::new("b1.syn");
    opts.labels = true;
    for (method, path) in [("GET", "/nada"), ("POST", "/x")] {
        let req = synsema_wasm::HttpRequestIn {
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            client_ip: "127.0.0.1".to_string(),
        };
        let r = synsema_wasm::handle(src, &opts, &req);
        assert_eq!(r.log, vec![synsema_core::interpreter::LABELS_WITHHELD_OUTPUT.to_string()], "{} {}", method, path);
        assert!(r.operator_detail.is_some(), "{} {}", method, path);
    }
}
