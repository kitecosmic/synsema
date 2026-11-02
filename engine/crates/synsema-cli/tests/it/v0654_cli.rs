//! Tests del binario real para v0.6.54.

use super::v0646_tanda_e_cli::project;
use super::v0653_cli::{free_port, wait_http, Served};

/// Pendiente de v0.6.53 (ronda 3, §4): el error de un agente lanzado desde una ruta de `serve` no
/// dejaba ninguna línea en la consola (en `run` sí: `Agent error [id]: …`). Ahora sale en el momento.
/// Con etiquetas no: qué agente falló puede depender de un dato privado.
#[test]
fn an_agent_error_under_serve_reaches_the_console() {
    let dir = project("agent-error-serve");
    let port = free_port();
    let src = format!(
        "require serve({port})\nagent Falla\n    let xs be [1]\n    print(xs[5])\n\nserve on {port}\n    bind \"127.0.0.1\"\n    route \"GET /go\"\n        spawn Falla\n        give {{\"ok\": true}}\n"
    );
    std::fs::write(dir.join("a.syn"), &src).unwrap();
    let s = Served::start(&dir, "a.syn");
    let (status, _) = wait_http(port, "GET", "/go", "");
    assert_eq!(status, 200);
    let out = s.wait_for("Agent error [Falla_");
    assert!(out.contains("Index 5 out of bounds (list length 1)"), "{}", out);
    drop(s);

    // Con etiquetas, ninguna línea (como el eco y el stderr de los agentes en ese modo).
    let port = free_port();
    std::fs::write(dir.join("b.syn"), src.replace(&format!("{}", port_of(&src)), &port.to_string())).unwrap();
    let s = Served::start_args(&dir, &["serve", "--labels", "b.syn"], &[]);
    let (status, _) = wait_http(port, "GET", "/go", "");
    assert_eq!(status, 200);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let out = s.wait_for("Serving HTTP");
    assert!(!out.contains("Agent error"), "{}", out);
}

fn port_of(src: &str) -> u16 {
    src.split("serve(").nth(1).and_then(|r| r.split(')').next()).and_then(|p| p.parse().ok()).unwrap()
}

/// Pendiente de v0.6.53: `synsema check` avisa de `tls auto` con dos IPs en `domain` (el `serve` lo
/// rechaza al arrancar con el mismo texto). Una IP y un nombre, o sin `tls auto`, no avisa.
#[test]
fn check_warns_of_two_ips_with_tls_auto() {
    let dir = project("check-tls-ips");
    let prog = |domain: &str, auto: bool| {
        format!(
            "require serve(443)\nserve on 443\n    {}\n    domain {}\n    route \"GET /\"\n        give \"x\"\n",
            if auto { "tls auto \"ops@example.com\"" } else { "redirect https" },
            domain
        )
    };
    let check = |src: String| {
        std::fs::write(dir.join("s.syn"), src).unwrap();
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
            .args(["check", "s.syn"])
            .current_dir(&dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap();
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stderr).into_owned())
    };
    let (code, err) = check(prog("[\"203.0.113.7\", \"[2001:db8::1]\", \"example.com\"]", true));
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("s.syn:4: warning: tls auto: one IP per serve (2 are listed: 203.0.113.7, [2001:db8::1])"), "{}", err);
    for (domain, auto) in [("[\"203.0.113.7\", \"example.com\"]", true), ("\"203.0.113.7\"", true)] {
        let (code, err) = check(prog(domain, auto));
        assert_eq!(code, 0, "{}", err);
        assert!(!err.contains("one IP per serve"), "{}: {}", domain, err);
    }
}
