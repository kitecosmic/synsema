//! v0.6.47 (T1, ronda 6, M2): bajo `serve` con etiquetas, un corte es siempre el 500 fijo, aunque
//! nazca en un `expect` (era 400 con el `field`) o en una denegación del token (era 403) bajo una
//! rama privada: el status decía qué sitio cortó. También la línea de una task de `auth with` que se
//! corta va al log retenido de su entrada (B1), no en vivo.
//!
//! Binario propio: las etiquetas son de todo el proceso.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)], body: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(6)));
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

#[test]
fn a_cut_under_serve_is_always_the_fixed_500() {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let port = free_port();
    // Las mismas dos rutas, montadas desde un módulo (`run_mounted_route` tiene sus propias guardas).
    let dir = std::env::temp_dir().join(format!("synsema-m2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("grupo.syn"),
        r#"export routes grupo
    route "POST /m/valida"
        let s be private(int(query["s"]), "app")
        when s == 1
            expect body {item: text}
        give 1
    route "GET /m/niega" requires auth
        let s be private(int(query["s"]), "app")
        when s == 1
            let r be now()
        give 1
"#,
    )
    .unwrap();
    let main = dir.join("main.syn").to_string_lossy().into_owned();
    let prog = format!(
        r#"require serve({p})
require random
require time
use "./grupo.syn" as g
let root be "root-key-m2"
task check_agent(token, request)
    give captoken_verify(token, root, {{"aud": "m2"}})
serve on {p}
    auth with check_agent
    mount g.grupo
    route "GET /token"
        give {{"t": captoken_mint({{"net": "api.example.com"}}, root, {{"aud": "m2", "ttl": 600, "id": "m2", "deterministic": true}})}}
    route "GET /corta"
        let s be private(int(query["s"]), "app")
        when s == 1
            let z be 1 / 0
        give 1
    route "POST /valida"
        let s be private(int(query["s"]), "app")
        when s == 1
            expect body {{item: text}}
        give 1
    route "GET /niega" requires auth
        let s be private(int(query["s"]), "app")
        when s == 1
            let r be now()
        give 1
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(&prog, &main, false, ServeOverrides::default());
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));

    let corte = request(port, "GET", "/corta?s=1", &[], "");
    assert_eq!(status(&corte), 500, "{}", corte);

    // El `expect` que falla bajo la rama privada: el mismo 500 y el mismo cuerpo, sin el `field`.
    let v = request(port, "POST", "/valida?s=1", &[], "{}");
    assert_eq!(status(&v), 500, "{}", v);
    assert_eq!(body(&v), body(&corte), "{}", v);
    // Sin la rama privada, el `expect` sigue siendo el 400 de siempre.
    let ok = request(port, "POST", "/valida?s=2", &[], "{}");
    assert_eq!(status(&ok), 200, "{}", ok);

    // La denegación del token bajo la rama privada (el reloj, con un token `deterministic`; un
    // sumidero denegado ya cortaba por la etiqueta antes del permiso): el mismo 500.
    let tok = request(port, "GET", "/token", &[], "");
    let t = serde_json::from_str::<serde_json::Value>(body(&tok)).unwrap_or_else(|_| panic!("{}", tok))["t"].as_str().unwrap().to_string();
    let n = request(port, "GET", "/niega?s=1", &[("Authorization", &format!("Bearer {}", t))], "");
    assert_eq!(status(&n), 500, "{}", n);
    assert_eq!(body(&n), body(&corte), "{}", n);

    let v = request(port, "POST", "/m/valida?s=1", &[], "{}");
    assert_eq!(status(&v), 500, "montada: {}", v);
    assert_eq!(body(&v), body(&corte), "montada: {}", v);
    let n = request(port, "GET", "/m/niega?s=1", &[("Authorization", &format!("Bearer {}", t))], "");
    assert_eq!(status(&n), 500, "montada: {}", n);
    assert_eq!(body(&n), body(&corte), "montada: {}", n);
    let n = request(port, "GET", "/m/niega?s=2", &[("Authorization", &format!("Bearer {}", t))], "");
    assert_eq!(status(&n), 200, "montada, sin la rama: {}", n);
}
