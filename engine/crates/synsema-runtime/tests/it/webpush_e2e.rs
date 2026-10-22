//! Web Push (tanda PWA) e2e: `push_send` contra un push service SIMULADO en loopback.
//! Lo que un push service real recibiría se captura entero (head + body) y se verifica
//! como lo haría el navegador: los headers de RFC 8030/8292 y el body `aes128gcm`
//! descifrado con la clave privada de la suscripción (RFC 8291). También las puertas:
//! `net(host)` para mandar, `random` para generar el par VAPID, y que la privada nace
//! sellada.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use synsema_core::bytesutil::b64url_encode;
use synsema_runtime::engine::run_source;
use synsema_stdlib::webpush::{decrypt_with, keygen, private_b64, public_b64};

struct Captured {
    head: String,
    body: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Un push service de mentira: acepta UNA request, la guarda y responde `status`.
fn mock_push_service(status: &'static str) -> (u16, thread::JoinHandle<Captured>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = s.read(&mut tmp).unwrap();
            if n == 0 {
                panic!("la request terminó antes del head");
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).to_string();
                let cl: usize = header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                while buf.len() < i + 4 + cl {
                    let n = s.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = buf[i + 4..i + 4 + cl].to_vec();
                let resp = format!("HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
                s.write_all(resp.as_bytes()).unwrap();
                return Captured { head, body };
            }
        }
    });
    (port, h)
}

fn program(port: u16, p256dh: &str, auth: &str, vpub: &str, vpriv: &str, extra_opts: &str, requires: &str) -> String {
    format!(
        // La privada va SELLADA (as_secret: la doctrina de clave privada = secret; en una
        // app real viene de secret("VAPID_PRIVATE_KEY")).
        "{requires}\nlet sub be {{\"endpoint\": \"http://127.0.0.1:{port}/push/v1/abc\", \"keys\": {{\"p256dh\": \"{p256dh}\", \"auth\": \"{auth}\"}}}}\nlet r be push_send(sub, {{\"title\": \"hola\"}}, {{\"vapid\": {{\"public\": \"{vpub}\", \"private\": as_secret(\"{vpriv}\", \"vapid\"), \"subject\": \"mailto:ops@example.com\"}}{extra_opts}}})\nprint(r[\"status\"])\nprint(r[\"ok\"])\nprint(r[\"gone\"])\n"
    )
}

#[test]
fn push_send_delivers_an_rfc8291_body_the_browser_can_decrypt() {
    let ua = keygen();
    let auth = [42u8; 16];
    let vapid = keygen();
    let (port, svc) = mock_push_service("201 Created");
    let src = program(
        port,
        &public_b64(&ua),
        &b64url_encode(&auth),
        &public_b64(&vapid),
        &private_b64(&vapid),
        ", \"ttl\": 120, \"urgency\": \"high\", \"topic\": \"t1\"",
        "require net(\"127.0.0.1\")",
    );
    let r = run_source(&src, "<push>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["201", "true", "false"]);

    let cap = svc.join().unwrap();
    assert!(cap.head.starts_with("POST /push/v1/abc HTTP/1.1"), "{}", cap.head);
    assert_eq!(header(&cap.head, "ttl"), Some("120"));
    assert_eq!(header(&cap.head, "urgency"), Some("high"));
    assert_eq!(header(&cap.head, "topic"), Some("t1"));
    assert_eq!(header(&cap.head, "content-encoding"), Some("aes128gcm"));
    assert_eq!(header(&cap.head, "content-type"), Some("application/octet-stream"));
    let authz = header(&cap.head, "authorization").expect("Authorization");
    assert!(authz.starts_with("vapid t="), "{}", authz);
    assert!(authz.contains(&format!(", k={}", public_b64(&vapid))), "{}", authz);
    // El cuerpo lo lee SÓLO quien tiene la privada de la suscripción.
    let plain = decrypt_with(&cap.body, &ua, &auth).expect("descifra como el navegador");
    assert_eq!(plain, b"{\"title\": \"hola\"}");
    let other = keygen();
    assert!(decrypt_with(&cap.body, &other, &auth).is_err());
}

#[test]
fn push_send_reports_gone_subscriptions() {
    let ua = keygen();
    let vapid = keygen();
    let (port, svc) = mock_push_service("410 Gone");
    let src = program(port, &public_b64(&ua), &b64url_encode(&[1u8; 16]), &public_b64(&vapid), &private_b64(&vapid), "", "require net(\"127.0.0.1\")");
    let r = run_source(&src, "<push>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["410", "false", "true"]);
    let _ = svc.join().unwrap();
}

#[test]
fn push_send_is_gated_by_net_of_the_endpoint_host() {
    let ua = keygen();
    let vapid = keygen();
    // Sin `require net` no se abre ni el socket (el mock no hace falta: no debe llegar nada).
    let src = program(1, &public_b64(&ua), &b64url_encode(&[1u8; 16]), &public_b64(&vapid), &private_b64(&vapid), "", "");
    let r = run_source(&src, "<push>");
    assert!(!r.success);
    let e = r.errors.join("\n");
    assert!(e.contains("net") && e.contains("127.0.0.1"), "{}", e);
}

#[test]
fn push_send_refuses_plaintext_endpoints_off_loopback() {
    let ua = keygen();
    let vapid = keygen();
    let src = format!(
        "require net(\"push.example.com\")\nlet sub be {{\"endpoint\": \"http://push.example.com/x\", \"keys\": {{\"p256dh\": \"{}\", \"auth\": \"{}\"}}}}\npush_send(sub, \"x\", {{\"vapid\": {{\"public\": \"{}\", \"private\": as_secret(\"{}\", \"vapid\"), \"subject\": \"mailto:a@b.c\"}}}})\n",
        public_b64(&ua),
        b64url_encode(&[1u8; 16]),
        public_b64(&vapid),
        private_b64(&vapid)
    );
    let r = run_source(&src, "<push>");
    assert!(!r.success);
    assert!(r.errors.join("\n").contains("must be https://"), "{:?}", r.errors);
}

#[test]
fn push_send_refuses_a_plain_text_private_key() {
    let ua = keygen();
    let vapid = keygen();
    let vpriv = private_b64(&vapid);
    // La misma clave, válida, pero como texto plano: error de doctrina, sin filtrar el valor.
    let src = format!(
        "require net(\"127.0.0.1\")\nlet sub be {{\"endpoint\": \"http://127.0.0.1:1/x\", \"keys\": {{\"p256dh\": \"{}\", \"auth\": \"{}\"}}}}\npush_send(sub, \"x\", {{\"vapid\": {{\"public\": \"{}\", \"private\": \"{}\", \"subject\": \"mailto:a@b.c\"}}}})\n",
        public_b64(&ua),
        b64url_encode(&[1u8; 16]),
        public_b64(&vapid),
        vpriv
    );
    let r = run_source(&src, "<push>");
    assert!(!r.success);
    let e = r.errors.join("\n");
    assert!(e.contains("must be a secret"), "{}", e);
    assert!(!e.contains(&vpriv), "el valor no se filtra: {}", e);
}

#[test]
fn push_vapid_keys_needs_random_and_seals_the_private_key() {
    let r = run_source("let k be push_vapid_keys()\nprint(k[\"public\"])\n", "<keys>");
    assert!(!r.success);
    assert!(r.errors.join("\n").contains("random"), "{:?}", r.errors);

    // reveal() es ruidoso a propósito: capability por nombre del secret + audit.
    let r = run_source(
        "require random\nrequire reveal(\"vapid_private\")\nlet k be push_vapid_keys()\nprint(length(k[\"public\"]))\nprint(k[\"private\"])\nprint(length(reveal(k[\"private\"])))\n",
        "<keys>",
    );
    assert!(r.success, "{:?}", r.errors);
    // Pública: 65 bytes → 87 chars base64url. Privada: 32 bytes → 43 chars, y al imprimirla
    // sin reveal() sale redactada.
    assert_eq!(r.output[0], "87");
    assert!(r.output[1].contains("secret") && !r.output[1].contains("="), "{}", r.output[1]);
    assert_eq!(r.output[2], "43");
}
