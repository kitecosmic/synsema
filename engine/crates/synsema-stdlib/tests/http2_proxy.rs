//! Lote 2 — Gates de HTTP/2 (ALPN h2 + GET 200) y reverse proxy (forward al upstream),
//! sobre el server async (tokio/hyper/rustls).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use synsema_stdlib::server::{
    build_tls_config, serve_forever, serve_forever_tls, GiveOutcome, Handler, RouteSpec, ServeRuntime,
};

fn empty_rt(routes: Vec<RouteSpec>, tls: bool) -> Arc<ServeRuntime> {
    let mut rt = ServeRuntime::new(
        0,
        "0.0.0.0".to_string(),
        routes,
        None,
        None,
        64,
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
        false,
        false,
    );
    rt.tls_enabled = tls;
    Arc::new(rt)
}

fn dummy_handler() -> Handler {
    Arc::new(|_ctx| GiveOutcome::Give(None))
}

// ===================== reverse proxy =====================

/// Upstream de prueba: responde con el request-line que vio (prueba el forward).
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
            }
            let body = format!("upstream saw: {}", line.trim());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn reverse_proxy_forwards_to_upstream() {
    let up = spawn_upstream();
    let route = RouteSpec {
        method: "GET".to_string(),
        path: "/up/*path".to_string(),
        param_names: vec!["path".to_string()],
        requires_auth: false,
        streaming: false,
        rate_limit: None,
        rate_zone: None,
        handler: dummy_handler(),
        stream_handler: None,
        proxy_target: Some(format!("http://127.0.0.1:{}", up)),
    };
    let rt = empty_rt(vec![route], false);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_forever(rt, listener));
    thread::sleep(Duration::from_millis(300));

    let resp = http_get(port, "/up/hello");
    assert!(resp.starts_with("HTTP/1.1 200"), "status: {}", resp);
    assert!(resp.contains("content-type: text/plain") || resp.contains("Content-Type: text/plain"), "ct: {}", resp);
    // El body viene del upstream y refleja el path forwardeado.
    assert!(resp.contains("upstream saw: GET /up/hello"), "forward body: {}", resp);
}

// ===================== HTTP/2 (ALPN h2 + GET) =====================

#[test]
fn http2_alpn_handshake_and_get() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = std::env::temp_dir().join("syn_h2_it");
    std::fs::create_dir_all(&dir).unwrap();
    let cp = dir.join("cert.pem");
    let kp = dir.join("key.pem");
    std::fs::write(&cp, cert.cert.pem()).unwrap();
    std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
    let cert_der = cert.cert.der().clone();

    let cfg = build_tls_config(&cp.to_string_lossy(), &kp.to_string_lossy()).expect("tls config");

    // Estático para que el GET h2 dé 200.
    let www = dir.join("www");
    std::fs::create_dir_all(&www).unwrap();
    std::fs::write(www.join("ok.txt"), b"ok").unwrap();
    let mut rtm = ServeRuntime::new(
        0,
        "0.0.0.0".to_string(),
        Vec::new(),
        None,
        None,
        64,
        vec![("/".to_string(), www.to_string_lossy().into_owned())],
        None,
        None,
        None,
        Vec::new(),
        false,
        false,
    );
    rtm.tls_enabled = true;
    let rt = Arc::new(rtm);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_forever_tls(rt, listener, cfg));
    thread::sleep(Duration::from_millis(300));

    // Cliente h2 async: ALPN h2 + handshake HTTP/2 + GET.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (alpn_is_h2, status) = runtime.block_on(async move {
        let mut roots = rustls::RootCertStore::empty();
        let _ = roots.add(cert_der);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(sni, tcp).await.unwrap();
        let alpn_is_h2 = tls.get_ref().1.alpn_protocol() == Some(&b"h2"[..]);

        let io = hyper_util::rt::TokioIo::new(tls);
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .uri("/ok.txt")
            .header("host", "localhost")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        (alpn_is_h2, resp.status().as_u16())
    });

    assert!(alpn_is_h2, "ALPN no negoció h2");
    assert_eq!(status, 200, "GET sobre HTTP/2 debió dar 200");
}

// ===================== vhost por :authority sobre HTTP/2 =====================

/// Regresión: en HTTP/2 el Host viaja en el pseudo-header `:authority`, no en
/// `headers()`. La selección de vhost debe sintetizar el host desde la authority,
/// o todo cliente h2 (los navegadores) cae al host por defecto.
#[test]
fn vhost_selected_by_authority_over_http2() {
    use std::rc::Rc;
    use synsema_core::types::{ServerValue, SynValue};

    // Host por defecto: solo "GET /" → "/foo" no matchea (sería 404 sin elegir el vhost).
    let apex = RouteSpec {
        method: "GET".to_string(),
        path: "/".to_string(),
        param_names: vec![],
        requires_auth: false,
        streaming: false,
        rate_limit: None,
        rate_zone: None,
        handler: dummy_handler(),
        stream_handler: None,
        proxy_target: None,
    };
    // vhost www.example.com: catch-all que redirige 301.
    let redir: Handler = Arc::new(|_ctx| {
        let v = SynValue::Server(Rc::new(ServerValue::Redirect {
            location: "https://example.com/moved".to_string(),
            status: 301,
        }));
        GiveOutcome::Give(Some(v))
    });
    let vhost_route = RouteSpec {
        method: "GET".to_string(),
        path: "/*path".to_string(),
        param_names: vec!["path".to_string()],
        requires_auth: false,
        streaming: false,
        rate_limit: None,
        rate_zone: None,
        handler: redir,
        stream_handler: None,
        proxy_target: None,
    };
    let mut rtm = ServeRuntime::new(
        0,
        "0.0.0.0".to_string(),
        vec![apex],
        None,
        None,
        64,
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
        false,
        false,
    );
    rtm.add_vhost("www.example.com".to_string(), vec![vhost_route], Vec::new(), None);
    let rt = Arc::new(rtm);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve_forever(rt, listener));
    thread::sleep(Duration::from_millis(300));

    // Cliente h2c (HTTP/2 en claro, prior-knowledge): request con :authority
    // www.example.com y SIN header `host` → ejercita la síntesis del host.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (status, location) = runtime.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .uri("http://www.example.com/foo")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let loc = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        (resp.status().as_u16(), loc)
    });

    assert_eq!(status, 301, "vhost por :authority sobre h2 debió dar 301 (sin el fix: 404 del host default)");
    assert_eq!(location, "https://example.com/moved", "Location del redirect del vhost");
}
