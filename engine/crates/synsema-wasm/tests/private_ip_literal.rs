//! v0.6.54 (§D de v0.6.51): en wasm una IP privada literal llegaba al hook `http` del host sin
//! chequeo (`http_get("http://169.254.169.254/")` con `require net`). Ahora se juzga con la misma
//! regla que en nativo: una dirección privada la tiene que nombrar el programa. También en la forma
//! que lee un navegador (`2852039166`).

use std::cell::RefCell;
use std::rc::Rc;

use synsema_stdlib::hostcap::{self, HostHttpRequest, HostProvider, HttpResult};
use synsema_wasm::{run, RunOptions};

struct Host(Rc<RefCell<Vec<String>>>);

impl HostProvider for Host {
    fn offers(&self, what: &str) -> bool {
        what == "http"
    }
    fn http(&self, req: &HostHttpRequest<'_>) -> Option<Result<HttpResult, String>> {
        self.0.borrow_mut().push(req.url.to_string());
        Some(Ok(HttpResult {
            status: 200,
            ok: true,
            body: "hola".to_string(),
            body_bytes: b"hola".to_vec(),
            headers: Vec::new(),
            error: None,
            attested: None,
        }))
    }
}

fn run_src(src: &str) -> (synsema_wasm::Report, Vec<String>) {
    let seen = Rc::new(RefCell::new(Vec::new()));
    hostcap::install(Some(Rc::new(Host(seen.clone()))));
    let report = run(src, &RunOptions::new("t.syn"));
    hostcap::install(None);
    let seen = seen.borrow().clone();
    (report, seen)
}

#[test]
fn a_private_literal_ip_needs_to_be_named() {
    // v0.6.54 (M1 de la ronda 1): también percent-encoding, ceros largos y `\` (que para un
    // navegador termina el host: `example.com` es la contraseña).
    for url in [
        "http://169.254.169.254/latest",
        "http://2852039166/latest",
        "http://%31%36%39.254.169.254/",
        "http://0000000000000000000000000000177.0.0.1/",
        "http://169.254.169.254\\@example.com/",
    ] {
        let (r, seen) = run_src(&format!("require net\nlet r be http_get({:?})\nprint(r.ok)\nprint(r.error)\n", url));
        assert!(seen.is_empty(), "llegó al hook: {:?}", seen);
        assert_eq!(r.output.first().map(String::as_str), Some("false"), "{:?} {:?}", r.output, r.errors);
        assert!(r.output.iter().any(|l| l.contains("private address")), "{:?}", r.output);
    }
    // `http:` sin barras: el navegador lo lee como `http://`; acá es un error antes del hook.
    let (r, seen) = run_src("require net\nlet r be http_get(\"http:169.254.169.254/latest\")\nprint(r)\n");
    assert!(seen.is_empty(), "llegó al hook: {:?} {:?}", seen, r.errors);
    // Un host que no es ASCII (dígitos de ancho completo): error, y no llega al hook.
    let (r, seen) = run_src("require net\nlet r be http_get(\"http://\u{ff11}\u{ff16}\u{ff19}\u{ff0e}254.169.254/\")\nprint(r.ok)\nprint(r.error)\n");
    assert!(seen.is_empty(), "llegó al hook: {:?}", seen);
    assert_eq!(r.output.first().map(String::as_str), Some("false"), "{:?} {:?}", r.output, r.errors);
    assert!(r.output.iter().any(|l| l.contains("not plain ASCII")), "{:?}", r.output);
    // Nombrada por el programa: llega.
    let (r, seen) = run_src("require net(\"169.254.169.254\")\nlet r be http_get(\"http://169.254.169.254/latest\")\nprint(r.ok)\n");
    assert_eq!(seen, vec!["http://169.254.169.254/latest".to_string()]);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
    // Una IP pública y un nombre: como antes.
    let (r, seen) = run_src("require net\nlet a be http_get(\"http://93.184.215.14/\")\nlet b be http_get(\"https://example.com/\")\nprint(a.ok and b.ok)\n");
    assert_eq!(seen.len(), 2, "{:?}", seen);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
}

/// v0.6.54 (R2-1 de la ronda 2): con `require net("example.org")`, un URL que el navegador lee con
/// otro host (`http://evil.example\@example.org/` conecta a `evil.example`) es un error antes del
/// hook. En el texto del programa la barra va escrita `\\`.
#[test]
fn a_url_read_differently_never_reaches_the_hook() {
    let (r, seen) = run_src(
        "require net(\"example.org\")\nlet r be http_get(\"http://evil.example\\\\@example.org/\")\nprint(r.ok)\nprint(r.error)\n",
    );
    assert!(seen.is_empty(), "llegó al hook: {:?}", seen);
    assert_eq!(r.output.first().map(String::as_str), Some("false"), "{:?} {:?}", r.output, r.errors);
    assert!(r.output.iter().any(|l| l.contains("a browser reads the host")), "{:?}", r.output);
    // El mismo permiso, con el URL escrito derecho: llega.
    let (r, seen) = run_src("require net(\"example.org\")\nlet r be http_get(\"http://example.org/\")\nprint(r.ok)\n");
    assert_eq!(seen, vec!["http://example.org/".to_string()]);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
    // R3-1 de la ronda 3: un permiso con puerto, y el navegador leyendo otro puerto.
    let (r, seen) = run_src(
        "require net(\"example.org:443\")\nlet r be http_get(\"https://example.org:8443\\\\@example.org:443/\")\nprint(r.ok)\nprint(r.error)\n",
    );
    assert!(seen.is_empty(), "llegó al hook: {:?}", seen);
    assert_eq!(r.output.first().map(String::as_str), Some("false"), "{:?} {:?}", r.output, r.errors);
    assert!(r.output.iter().any(|l| l.contains("example.org:8443")), "{:?}", r.output);
    let (r, seen) = run_src("require net(\"example.org:443\")\nlet r be http_get(\"https://example.org:443/\")\nprint(r.ok)\n");
    assert_eq!(seen, vec!["https://example.org:443/".to_string()]);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
}

/// v0.6.54 (R3-3 de la ronda 3): en wasm, como en nativo, los builtins http hablan http y https:
/// otro esquema es un error antes del hook.
#[test]
fn a_scheme_other_than_http_never_reaches_the_hook() {
    for url in ["ftp://example.org/", "foo:bar://example.org/", "ws://example.org/"] {
        let (r, seen) = run_src(&format!("require net(\"example.org\")\nlet r be http_get({:?})\nprint(r.ok)\nprint(r.error)\n", url));
        assert!(seen.is_empty(), "{}: llegó al hook: {:?}", url, seen);
        assert_eq!(r.output.first().map(String::as_str), Some("false"), "{}: {:?} {:?}", url, r.output, r.errors);
        assert!(r.output.iter().any(|l| l.contains("unsupported scheme")), "{}: {:?}", url, r.output);
    }
    // v0.6.54 (R4-1 de la ronda 4): un espacio Unicode adelante no es lo que quita WHATWG (C0 y el
    // espacio ASCII); para un navegador el URL es inválido y el nativo lo niega. El carácter va
    // crudo en el fuente, sin escape.
    for url in ["\u{3000}http://example.org/", "\u{a0}http://example.org/"] {
        let (r, seen) = run_src(&format!("require net(\"example.org\")\nlet r be http_get(\"{}\")\nprint(r.ok)\nprint(r.error)\n", url));
        assert!(seen.is_empty(), "{:?}: llegó al hook: {:?}", url, seen);
        assert_eq!(r.output.first().map(String::as_str), Some("false"), "{:?}: {:?} {:?}", url, r.output, r.errors);
        assert!(r.output.iter().any(|l| l.contains("unsupported scheme")), "{:?}: {:?}", url, r.output);
    }
    // El control: un espacio ASCII adelante WHATWG lo quita, y llega.
    let (r, seen) = run_src("require net(\"example.org\")\nlet r be http_get(\" http://example.org/\")\nprint(r.ok)\n");
    assert_eq!(seen.len(), 1, "{:?}", seen);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
    let (r, seen) = run_src("require net(\"example.org\")\nlet r be http_get(\"HTTP://example.org/\")\nprint(r.ok)\n");
    assert_eq!(seen.len(), 1, "{:?}", seen);
    assert_eq!(r.output, vec!["true".to_string()], "{:?}", r.errors);
}
