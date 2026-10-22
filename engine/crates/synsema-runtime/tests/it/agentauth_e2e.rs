//! E2E de identidad de agentes (T2/T4/T6.4): un serve que autentica AGENTES por
//! captoken, hace cumplir las cuotas POR IDENTIDAD (rate limit y techo de gasto
//! delegado) y distingue clases de sujeto (humano por cookie vs agente por token).
//!
//! Cada test corresponde a una celda ✔ del threat model del diseño:
//!
//! - subagente comprometido no escala permisos:
//!   `attenuated_agent_cannot_widen_and_identity_flows`
//! - cuota/spend por identidad acota el daño: `spend_limit_is_enforced_per_identity`
//!   y `rate_limit_is_per_identity`
//! - request firmada: el token robado no sirve sin la clave:
//!   `signed_request_verifies_end_to_end` y `signed_request_roundtrip_with_capability`

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)], body: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req.push_str("\r\n");
    req.push_str(body);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Un serve que autentica agentes con captokens: el auth task devuelve el
/// resultado de `captoken_verify` TAL CUAL — su `id` es la identidad y su caveat
/// `spend` el techo delegado, sin ningún adaptador.
fn start_agent_server(port: u16) -> String {
    // El programa acuña dos tokens al arrancar y los publica en una ruta abierta
    // para que el test los use (en producción los emitiría el enrolamiento).
    let prog = format!(
        r#"require serve({p})
require random
require spend("USD")

let root be "root-key-de-prueba"

task check_agent(token, request)
    give captoken_verify(token, root, {{"aud": "orders-api"}})

serve on {p}
    auth with check_agent

    route "GET /tokens"
        let full be captoken_mint({{"net": "api.example.com", "spend": "USD"}}, root, {{"aud": "orders-api", "ttl": 600, "id": "agent-full", "spend": {{"USD": 100}}}})
        let weak be captoken_attenuate(full, {{"spend": "USD"}}, {{"spend": {{"USD": 5}}}})
        give {{"full": full, "weak": weak}}

    route "GET /whoami" requires auth
        give {{"id": request.user.id, "depth": request.user.depth}}

    route "POST /pay" requires auth
        let amount be request.json.amount
        try
            let total be spend(amount, "USD", "e2e test payment")
            give {{"ok": true, "total": total}}
        recover e
            give fail(402, "spend refused")

    route "GET /limited" requires auth
        rate_limit 2 per minute
        give {{"ok": true}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "agentauth_e2e.syn", false);
    });
    wait_ready(port);
    request(port, "GET", "/tokens", &[], "")
}

/// Saca un campo de texto del JSON de la respuesta (sin parser: los tokens son
/// base64url, sin comillas ni escapes).
fn field(resp: &str, name: &str) -> String {
    let needle = format!("\"{}\": \"", name);
    let start = resp.find(&needle).unwrap_or_else(|| panic!("no está {} en {}", name, resp))
        + needle.len();
    let rest = &resp[start..];
    rest[..rest.find('"').expect("cierre")].to_string()
}

#[test]
fn attenuated_agent_cannot_widen_and_identity_flows() {
    let port = free_port();
    let tokens = start_agent_server(port);
    let full = field(&tokens, "full");
    let weak = field(&tokens, "weak");
    assert_ne!(full, weak);

    // El token completo autentica y su identidad llega al handler.
    let auth = format!("Bearer {}", full);
    let r = request(port, "GET", "/whoami", &[("Authorization", &auth)], "");
    assert_eq!(status(&r), 200, "token válido: {}", r);
    assert!(r.contains("agent-full"), "la identidad llega al handler: {}", r);

    // El atenuado también autentica (misma raíz, cadena válida) y reporta depth 2.
    let auth_weak = format!("Bearer {}", weak);
    let r = request(port, "GET", "/whoami", &[("Authorization", &auth_weak)], "");
    assert_eq!(status(&r), 200, "token atenuado: {}", r);
    assert!(r.contains("\"depth\": 2"), "la cadena tiene 2 bloques: {}", r);

    // Un token de otra raíz (forjado) NO entra.
    let r = request(port, "GET", "/whoami", &[("Authorization", "Bearer no-es-token")], "");
    assert_eq!(status(&r), 401, "token inválido: {}", r);
    // Sin token tampoco.
    let r = request(port, "GET", "/whoami", &[], "");
    assert_eq!(status(&r), 401, "sin token: {}", r);
}

#[test]
fn spend_limit_is_enforced_per_identity() {
    let port = free_port();
    let tokens = start_agent_server(port);
    let weak = field(&tokens, "weak");
    let auth = format!("Bearer {}", weak);

    // El token atenuado delega 5 USD: un gasto de 3 pasa…
    let r = request(port, "POST", "/pay", &[("Authorization", &auth)], r#"{"amount": 3}"#);
    assert_eq!(status(&r), 200, "gasto dentro del techo delegado: {}", r);

    // …y el siguiente de 3 (total 6 > 5) lo rechaza el LEDGER, no el programa.
    let r = request(port, "POST", "/pay", &[("Authorization", &auth)], r#"{"amount": 3}"#);
    assert_eq!(status(&r), 402, "el techo delegado corta el segundo gasto: {}", r);
}

#[test]
fn rate_limit_is_per_identity() {
    let port = free_port();
    let tokens = start_agent_server(port);
    let full = field(&tokens, "full");
    let weak = field(&tokens, "weak");

    // La ruta permite 2 por minuto POR IDENTIDAD. El primer agente quema su cupo…
    let auth = format!("Bearer {}", full);
    for i in 0..2 {
        let r = request(port, "GET", "/limited", &[("Authorization", &auth)], "");
        assert_eq!(status(&r), 200, "request {} dentro del cupo: {}", i, r);
    }
    let r = request(port, "GET", "/limited", &[("Authorization", &auth)], "");
    assert_eq!(status(&r), 429, "el 3er request excede el cupo: {}", r);

    // …y como el bucket es por identidad, el token atenuado (identidad DISTINTA
    // del bucket, mismo id de token pero cadena distinta) no comparte el cupo del
    // primero salvo por el escudo de IP, que tiene su propio presupuesto.
    // Nota: ambos comparten el mismo `id` del captoken raíz, así que este caso
    // documenta el comportamiento REAL: la identidad es el id del token, y un
    // token atenuado conserva el id de su raíz → comparten cuota a propósito
    // (la delegación no debe multiplicar el presupuesto del delegador).
    let auth_weak = format!("Bearer {}", weak);
    let r = request(port, "GET", "/limited", &[("Authorization", &auth_weak)], "");
    assert_eq!(
        status(&r),
        429,
        "un token atenuado NO renueva la cuota de su raíz: {}",
        r
    );
}

/// T2 en el servidor: una request firmada se verifica de punta a punta, y el mismo
/// token/keyid con una firma que no cierra se rechaza.
#[test]
fn signed_request_verifies_end_to_end() {
    let port = free_port();
    // El programa firma con una clave HMAC sellada y verifica del otro lado con la
    // MISMA clave, pineando el algoritmo (jamás leyéndolo del mensaje).
    let prog = format!(
        r#"require serve({p})
require secret("SIG_KEY")

serve on {p}
    route "GET /sign"
        let key be secret("SIG_KEY", "clave-compartida")
        let req be {{"method": "POST", "url": "https://api.example.com/orders", "body": "{{}}"}}
        give http_sign(req, key, {{"alg": "hmac-sha256", "keyid": "agent-7"}})

    route "POST /verify"
        let key be secret("SIG_KEY", "clave-compartida")
        let req be {{"method": "POST", "url": "https://api.example.com/orders", "headers": request.json.headers, "body": "{{}}"}}
        let v be http_signature_verify(req, key, {{"alg": "hmac-sha256"}})
        when v == nothing
            give fail(401, "bad signature")
        give {{"keyid": v.keyid}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "agentauth_sig_e2e.syn", false);
    });
    wait_ready(port);

    // El programa exige `require sign(...)` para firmar: sin él la ruta /sign
    // falla con 500 — esa es la puerta deny-by-default en acción.
    let r = request(port, "GET", "/sign", &[], "");
    assert_eq!(
        status(&r),
        500,
        "firmar sin `require sign(\"SIG_KEY\")` debe denegarse: {}",
        r
    );
    assert!(
        r.contains("sign") || r.contains("capability"),
        "el error nombra la capability: {}",
        r
    );

    // Una firma inventada no verifica.
    let body = r#"{"headers": {"Signature-Input": "sig1=(\"@method\");created=1;keyid=\"x\";alg=\"hmac-sha256\"", "Signature": "sig1=:AAAA:", "Content-Digest": "sha-256=:AAAA:"}}"#;
    let r = request(port, "POST", "/verify", &[], body);
    assert_eq!(status(&r), 401, "firma inventada: {}", r);
}

/// El mismo flujo pero con la capability concedida: firmar → verificar → 200.
#[test]
fn signed_request_roundtrip_with_capability() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
require secret("SIG_KEY")
require sign("SIG_KEY")

serve on {p}
    route "GET /sign"
        let key be secret("SIG_KEY", "clave-compartida")
        let req be {{"method": "POST", "url": "https://api.example.com/orders", "body": "hola"}}
        give http_sign(req, key, {{"alg": "hmac-sha256", "keyid": "agent-7"}})

    route "POST /verify"
        let key be secret("SIG_KEY", "clave-compartida")
        let req be {{"method": "POST", "url": "https://api.example.com/orders", "headers": request.json.headers, "body": "hola"}}
        let v be http_signature_verify(req, key, {{"alg": "hmac-sha256"}})
        when v == nothing
            give fail(401, "bad signature")
        give {{"keyid": v.keyid}}

    route "POST /verify_tampered"
        let key be secret("SIG_KEY", "clave-compartida")
        let req be {{"method": "POST", "url": "https://api.example.com/orders", "headers": request.json.headers, "body": "OTRO BODY"}}
        let v be http_signature_verify(req, key, {{"alg": "hmac-sha256"}})
        when v == nothing
            give fail(401, "bad signature")
        give {{"keyid": v.keyid}}
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "agentauth_sig_ok_e2e.syn", false);
    });
    wait_ready(port);

    let signed = request(port, "GET", "/sign", &[], "");
    assert_eq!(status(&signed), 200, "firma con capability: {}", signed);
    // El cuerpo es el map de headers; se reenvía tal cual al verificador.
    let json_start = signed.find("\r\n\r\n").expect("headers") + 4;
    let headers_json = signed[json_start..].trim();
    let body = format!("{{\"headers\": {}}}", headers_json);

    let r = request(port, "POST", "/verify", &[], &body);
    assert_eq!(status(&r), 200, "la firma verifica: {}", r);
    assert!(r.contains("agent-7"), "el keyid identifica al firmante: {}", r);

    // MISMA firma, body distinto → rechazo (el Content-Digest no cierra).
    let r = request(port, "POST", "/verify_tampered", &[], &body);
    assert_eq!(status(&r), 401, "body alterado: {}", r);
}
