//! E2E de T1 (spec de identidad): **el token ES el techo**. Bajo `serve`, los `caps` del
//! captoken que devuelve `auth with` se vuelven el techo delegado de la request: lo que el
//! token no lista se deniega aunque el programa lo declare, y hacia afuera eso es un **403
//! con cuerpo fijo** (nunca "te falta file.read"). Las capabilities locales al proceso no
//! las gobierna el token (`now()` sigue andando) salvo con el caveat `deterministic`. Y el
//! techo delegado es de la request: el siguiente request del mismo worker no lo hereda.
//!
//! También `sandbox under <caps>` (el tercer punto de aplicación, in-process) por `run`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_program;
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

fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)]) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn field(resp: &str, name: &str) -> String {
    let needle = format!("\"{}\": \"", name);
    let start = resp.find(&needle).unwrap_or_else(|| panic!("no está {} en {}", name, resp)) + needle.len();
    let rest = &resp[start..];
    rest[..rest.find('"').expect("cierre")].to_string()
}

/// Un directorio temporal propio con `note.txt`, en forma de ruta con `/` (válida en el
/// fuente `.syn` en cualquier SO).
fn scratch_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("synsema-t1-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.txt"), "hello from the file").unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

/// Un serve que autentica agentes por captoken y cuyos handlers usan `file.read` y el
/// reloj. El programa DECLARA `file.read` y `time`; el token decide si el caller las tiene.
fn start_server(port: u16, dir: &str) -> String {
    let prog = format!(
        r#"require serve({p})
require random
require time
require file.read("{d}/*")

let root be "root-key-t1"

task check_agent(token, request)
    give captoken_verify(token, root, {{"aud": "files-api"}})

serve on {p}
    auth with check_agent

    route "GET /tokens"
        let with_file be captoken_mint({{"file.read": "{d}/*"}}, root, {{"aud": "files-api", "ttl": 600, "id": "agent-files"}})
        let without be captoken_mint({{"net": "api.example.com"}}, root, {{"aud": "files-api", "ttl": 600, "id": "agent-net"}})
        let frozen be captoken_mint({{"file.read": "{d}/*"}}, root, {{"aud": "files-api", "ttl": 600, "id": "agent-frozen", "deterministic": true}})
        give {{"with_file": with_file, "without": without, "frozen": frozen}}

    route "GET /read" requires auth
        give {{"content": read_file("{d}/note.txt")}}

    route "GET /clock" requires auth
        give {{"t": now()}}

    route "GET /public-read"
        give {{"content": read_file("{d}/note.txt")}}
"#,
        p = port,
        d = dir
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "delegated_ceiling_e2e.syn", false);
    });
    wait_ready(port);
    request(port, "GET", "/tokens", &[])
}

#[test]
fn token_is_the_ceiling_and_the_refusal_is_generic() {
    // Un solo worker: así el request "público" de abajo corre en el MISMO intérprete que
    // el request denegado y prueba que el techo delegado no se filtra entre requests.
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "1");
    let port = free_port();
    let dir = scratch_dir("serve");
    let tokens = start_server(port, &dir);
    let with_file = field(&tokens, "with_file");
    let without = field(&tokens, "without");
    let frozen = field(&tokens, "frozen");

    // El programa declara file.read; el token del caller no lo delega → 403 con cuerpo
    // FIJO: no nombra la capability, no cuenta qué falta, no dice "no existe".
    let r = request(port, "GET", "/read", &[("Authorization", &format!("Bearer {}", without))]);
    assert_eq!(status(&r), 403, "{}", r);
    assert!(r.contains("insufficient permissions"), "{}", r);
    assert!(!r.contains("file") && !r.contains("Capability") && !r.contains("ceiling"), "la respuesta enumera la superficie: {}", r);

    // El request siguiente del MISMO worker, sin token, ve el techo del host completo: el
    // techo delegado era de la request anterior, no del worker.
    let r = request(port, "GET", "/public-read", &[]);
    assert_eq!(status(&r), 200, "{}", r);
    assert!(r.contains("hello from the file"), "{}", r);

    // Con un token que sí delega file.read, el handler lee.
    let r = request(port, "GET", "/read", &[("Authorization", &format!("Bearer {}", with_file))]);
    assert_eq!(status(&r), 200, "{}", r);
    assert!(r.contains("hello from the file"), "{}", r);

    // `time` es local al proceso: un token que no la lista NO la corta…
    let r = request(port, "GET", "/clock", &[("Authorization", &format!("Bearer {}", without))]);
    assert_eq!(status(&r), 200, "{}", r);
    // …salvo con el caveat `deterministic`: entonces el reloj se niega y es culpa del token.
    let r = request(port, "GET", "/clock", &[("Authorization", &format!("Bearer {}", frozen))]);
    assert_eq!(status(&r), 403, "{}", r);
    assert!(r.contains("insufficient permissions"), "{}", r);
    // …y el mismo token sigue leyendo el archivo que sí delega.
    let r = request(port, "GET", "/read", &[("Authorization", &format!("Bearer {}", frozen))]);
    assert_eq!(status(&r), 200, "{}", r);
}

#[test]
fn sandbox_under_is_a_least_privilege_block() {
    let dir = scratch_dir("run");
    let prog = format!(
        r#"require file.read("{d}/*")

-- Lo que el bloque lista, pasa (sigue gateado por el require del programa).
sandbox under {{"file.read": ["{d}/*"]}}
    print("ok: " + read_file("{d}/note.txt"))

-- Lo que el bloque no lista, se deniega aunque el programa lo declare; es atrapable.
try
    sandbox under {{"net": "api.example.com"}}
        print(read_file("{d}/note.txt"))
recover e
    print("denied: " + text(e))

-- Un `require` adentro es no-op: no se puede re-conceder para escapar del bloque.
try
    sandbox under {{"net": "api.example.com"}}
        require file.read("{d}/*")
        print(read_file("{d}/note.txt"))
recover e
    print("still denied")

-- Lo local al proceso no es delegable ni por bloque.
try
    sandbox under {{"stdout": nothing}}
        print("never")
recover e
    print("rejected: " + text(e))
"#,
        d = dir
    );
    let r = run_program(&prog, "sandbox_under.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("ok: hello from the file"), "{}", out);
    assert!(out.contains("denied: ") && out.contains("sandbox under"), "{}", out);
    assert!(out.contains("still denied"), "{}", out);
    assert!(out.contains("rejected: ") && out.contains("process-local"), "{}", out);
}
