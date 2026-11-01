//! Tests del binario real para v0.6.53.

use super::v0646_tanda_e_cli::{project, synsema, synsema_env};

/// Un `secret()` en el `env`, los argumentos o el `stdin` de `run` es error antes de lanzar nada
/// (antes llegaba al hijo el texto `secret(K)`), y el valor no aparece en ningún lado. Con
/// `reveal()` el hijo lo recibe.
#[test]
fn a_secret_for_the_child_of_run_is_an_error_and_reveal_passes_it() {
    let dir = project("run-secret");
    let (sh, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
    let echo = if cfg!(windows) { "echo %K%" } else { "echo $K" };
    let cases = [
        ("env", format!("run(\"{sh}\", [\"{flag}\", \"{echo}\"], 10, {{\"env\": {{\"K\": secret(\"K\")}}}})"), "env \"K\""),
        ("args", format!("run(\"{sh}\", [\"{flag}\", secret(\"K\")], 10)"), "argument 2"),
        ("stdin", format!("run(\"{sh}\", [\"{flag}\", \"{echo}\"], 10, {{\"stdin\": secret(\"K\")}})"), "stdin"),
    ];
    for (name, call, what) in cases {
        let src = format!("require exec(\"{sh}\")\nrequire secret(\"K\")\nlet r be {call}\nprint(r[\"stdout\"])\n");
        std::fs::write(dir.join("s.syn"), src).unwrap();
        let (code, out, err) = synsema_env(&dir, &["run", "s.syn"], None, &[("K", "sentinel-v0653")]);
        assert_eq!(code, 1, "{}: {}{}", name, out, err);
        assert!(err.contains(&format!("run: {} is a secret — reveal()", what)) && err.contains("nothing ran"), "{}: {}", name, err);
        assert!(!out.contains("sentinel") && !err.contains("sentinel") && !out.contains("secret(K)"), "{}: {}{}", name, out, err);
    }
    let src = format!(
        "require exec(\"{sh}\")\nrequire secret(\"K\")\nrequire reveal(\"K\")\nlet r be run(\"{sh}\", [\"{flag}\", \"{echo}\"], 10, {{\"env\": {{\"K\": reveal(secret(\"K\"))}}}})\nprint(r[\"stdout\"])\n"
    );
    std::fs::write(dir.join("r.syn"), src).unwrap();
    let (code, out, err) = synsema_env(&dir, &["run", "r.syn"], None, &[("K", "sentinel-v0653")]);
    assert!(code == 0 && out.contains("sentinel-v0653"), "{}{}", out, err);
}

/// El programa de un `run` aislado que es un link a un archivo fuera de lo delegado (el `python` de
/// un venv de uv o pyenv) corre, y synsema avisa qué carpeta delegar; delegada, no avisa.
#[cfg(target_os = "linux")]
#[test]
fn isolate_warns_when_the_program_leads_out_of_what_is_granted() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project("isolate-venv-link");
    std::fs::create_dir_all(dir.join("base").join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("v").join("bin")).unwrap();
    let tool = dir.join("base").join("bin").join("tool");
    std::fs::write(&tool, "#!/bin/sh\necho corre\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("../../base/bin/tool", dir.join("v").join("bin").join("tool")).unwrap();
    let head = "require exec(\"./v/bin/tool\")\nrequire file.read(\"./v/**\")\nrequire file.read(\"./base/**\")\n";
    let base = std::fs::canonicalize(dir.join("base")).unwrap();
    for (reads, warns) in [("\"./v/**\"", true), ("[\"./v/**\", \"./base/**\"]", false)] {
        let src = format!("{head}let r be run(\"./v/bin/tool\", [], 10, {{\"isolate\": {{\"file.read\": {reads}}}}})\nprint(r[\"stdout\"])\n");
        std::fs::write(dir.join("l.syn"), src).unwrap();
        let (code, out, err) = synsema_env(&dir, &["run", "l.syn"], None, &[]);
        if err.contains("isolate needs Landlock ABI") {
            return;
        }
        assert!(code == 0 && out.contains("corre"), "{}: {}{}", reads, out, err);
        let warning = format!("add \"{}/**\" to \"file.read\" in \"isolate\"", base.display());
        assert_eq!(err.contains(&warning), warns, "{}: {}", reads, err);
        assert_eq!(err.matches("synsema: warning: run:").count(), warns as usize, "{}: {}", reads, err);
    }
}

/// Un link a una carpeta (en Windows, una junction).
fn link_dir(target: &std::path::Path, link: &std::path::Path) {
    #[cfg(windows)]
    {
        let ok = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output().unwrap().status.success();
        assert!(ok, "mklink /J");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// `make_dir` crea la carpeta y las de arriba, vuelve `true` si ya existe, y es error sin
/// `file.write`, con un archivo en el camino, y fuera de lo concedido (por nombre, o por un link que
/// lleva afuera: ni la carpeta ni las de arriba se crean del otro lado).
#[test]
fn make_dir_creates_each_folder_it_is_allowed_to() {
    let dir = project("make-dir");
    for d in ["out", "outside"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(dir.join("out").join("f.txt"), "x").unwrap();
    link_dir(&dir.join("outside"), &dir.join("out").join("link"));
    let grant = "require file.write(\"./out/**\")\n";
    let run = |name: &str, body: &str| {
        std::fs::write(dir.join(name), format!("{grant}{body}")).unwrap();
        synsema_env(&dir, &["run", name], None, &[])
    };
    // Anidada, de una vez; otra vez da true.
    let (code, out, err) = run("a.syn", "print(make_dir(\"./out/a/b/c\"))\nprint(make_dir(\"./out/a/b/c\"))\nprint(make_dir(\"./out\"))\n");
    assert_eq!((code, out.trim()), (0, "true\ntrue\ntrue"), "{}", err);
    assert!(dir.join("out/a/b/c").is_dir());
    // Un archivo en el camino.
    let (code, _, err) = run("f.syn", "make_dir(\"./out/f.txt/x\")\n");
    assert!(code != 0 && err.contains("make_dir: \"out/f.txt\" is a file"), "{}", err);
    let (code, _, err) = run("g.syn", "make_dir(\"./out/f.txt\")\n");
    assert!(code != 0 && err.contains("is a file"), "{}", err);
    // Fuera del permiso, por nombre: nada se crea.
    let (code, _, err) = run("n.syn", "make_dir(\"./elsewhere/x\")\n");
    assert!(code != 0 && err.contains("Capability not granted") && err.contains("file.write"), "{}", err);
    assert!(!dir.join("elsewhere").exists());
    // Por un link que lleva afuera: ni `x` ni `x/y` aparecen en `outside`.
    let (code, _, err) = run("l.syn", "make_dir(\"./out/link/x/y\")\n");
    assert!(code != 0 && err.contains("Capability not granted"), "{}", err);
    assert!(!dir.join("outside").join("x").exists(), "creó del otro lado del link");
    // Sin `file.write` del todo.
    std::fs::write(dir.join("s.syn"), "make_dir(\"./out/z\")\n").unwrap();
    let (code, _, err) = synsema_env(&dir, &["run", "s.syn"], None, &[]);
    assert!(code != 0 && err.contains("Capability not granted") && !dir.join("out/z").exists(), "{}", err);
}

/// Una carpeta de arriba que falta también se juzga: con permiso sólo para `./out/a/**`, crear
/// `./out/a/b` cuando no existe `./out` pide permiso para `./out`, y no la crea.
#[test]
fn make_dir_judges_the_folders_above_it_creates() {
    let dir = project("make-dir-above");
    std::fs::write(dir.join("m.syn"), "require file.write(\"./out/a/**\")\nmake_dir(\"./out/a/b\")\n").unwrap();
    let (code, _, err) = synsema_env(&dir, &["run", "m.syn"], None, &[]);
    assert!(code != 0 && err.contains("Capability not granted: file_write(\"out\")"), "{}", err);
    assert!(!dir.join("out").exists(), "creó una carpeta sin permiso");
}

/// `max_file_mb` sin `isolate` es error, como `max_memory_mb` (no hay con qué imponerlo).
#[test]
fn max_file_mb_without_isolate_is_an_error() {
    let dir = project("max-file-plain");
    std::fs::write(dir.join("p.syn"), "require exec(\"sh\")\nrun(\"sh\", [\"-c\", \"true\"], 10, {\"max_file_mb\": 1})\n").unwrap();
    let (code, _, err) = synsema_env(&dir, &["run", "p.syn"], None, &[]);
    assert!(
        code != 0 && err.contains("run: max_file_mb is enforced only for an isolated child — add \"isolate\" (e.g. {\"isolate\": true, \"max_file_mb\": 100})"),
        "{}",
        err
    );
}

/// `max_file_mb` es el tope de cada archivo: debajo, el hijo escribe y sale bien; un archivo que
/// lo pasa lo mata `SIGXFSZ`, y `r.killed_by` lo dice (`exit_code` -1). El archivo queda en el tope.
#[cfg(target_os = "linux")]
#[test]
fn max_file_mb_kills_a_child_that_writes_a_bigger_file_and_says_so() {
    let dir = project("max-file");
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let src = [
        "require exec(\"sh\")",
        "require file.write(\"./out/**\")",
        "require file.read(\"./out/**\")",
        "let iso be {\"file.write\": \"./out/**\", \"file.read\": \"./out/**\"}",
        "each n in [500000, 3000000]",
        "    let r be run(\"sh\", [\"-c\", \"exec head -c \" + text(n) + \" /dev/zero > out/f\" + text(n)], 10, {\"isolate\": iso, \"max_file_mb\": 1})",
        "    print(`{n} {r.exit_code} {r.killed_by} {r.isolation.max_file_mb}`)",
        "let r be run(\"sh\", [\"-c\", \"kill -TERM $$\"], 10, {\"isolate\": true})",
        "print(`term {r.exit_code} {r.killed_by} {r.isolation.max_file_mb}`)",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("m.syn"), src).unwrap();
    let (code, out, err) = synsema_env(&dir, &["run", "m.syn"], None, &[]);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!(code, 0, "{}{}", out, err);
    assert_eq!(out.trim(), "500000 0 nothing 1\n3000000 -1 max_file_mb 1\nterm -1 signal 15 nothing", "{}", err);
    assert_eq!(std::fs::metadata(dir.join("out/f500000")).unwrap().len(), 500000);
    assert_eq!(std::fs::metadata(dir.join("out/f3000000")).unwrap().len(), 1024 * 1024);
}

/// `http_get("http://localhost:…")` llega a un servidor que sólo escucha IPv4 (como un `serve` en
/// 0.0.0.0) aunque `localhost` dé `::1` primero (Windows), sin esperar el rechazo de `::1`.
#[test]
fn http_get_to_localhost_reaches_an_ipv4_only_server() {
    use std::io::{BufRead, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            while r.read_line(&mut line).unwrap_or(0) > 2 {
                line.clear();
            }
            let mut s = s;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nhola");
        }
    });
    let dir = project("http-localhost");
    let src = format!(
        "require net(\"localhost\")\nlet r be http_get(\"http://localhost:{port}/x\")\nprint(`{{r.status}} {{r.body}}`)\n"
    );
    std::fs::write(dir.join("h.syn"), src).unwrap();
    let t0 = std::time::Instant::now();
    let (code, out, err) = synsema_env(&dir, &["run", "h.syn"], None, &[]);
    assert!(code == 0 && out.trim().starts_with("200 hola"), "{}{}", out, err);
    assert!(t0.elapsed() < std::time::Duration::from_millis(3000), "tardó {:?}", t0.elapsed());
}

/// Un `GET /` a `127.0.0.1:port`: el cuerpo, o `None` si no conecta.
#[cfg(target_os = "linux")]
fn get_body(port: u16) -> Option<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ok()?;
    let mut r = String::new();
    s.read_to_string(&mut r).ok()?;
    r.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

#[cfg(target_os = "linux")]
fn wait_body(port: u16) -> Option<String> {
    for _ in 0..100 {
        if let Some(b) = get_body(port) {
            return Some(b);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// G1: con la activación por socket de systemd (`LISTEN_PID` + `LISTEN_FDS`, el socket en el fd 3)
/// `serve` escucha en ese socket en vez de abrir el puerto (que ya está tomado: un bind propio
/// fallaría). Con el `LISTEN_PID` de otro proceso no lo toca y el bind falla como siempre.
#[cfg(target_os = "linux")]
#[test]
fn serve_listens_on_the_socket_systemd_passes_in() {
    let dir = project("listen-fds");
    let port = free_port();
    std::fs::write(dir.join("s.syn"), format!("require serve({port})\nserve on {port}\n    route \"GET /\"\n        give \"heredado\"\n")).unwrap();
    // El lanzador hace lo que systemd: el socket en el fd 3, y las variables con su propio pid (que
    // `execv` conserva).
    let launcher = "import os, socket, sys\n\
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
        s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(64)\n\
        os.dup2(s.fileno(), 3); os.set_inheritable(3, True)\n\
        os.environ['LISTEN_FDS'] = '1'\n\
        os.environ['LISTEN_PID'] = str(os.getpid() + int(sys.argv[2]))\n\
        os.execv(sys.argv[3], sys.argv[3:])\n";
    for (offset, adopts) in [(0, true), (1, false)] {
        let mut child = std::process::Command::new("python3")
            .args(["-c", launcher, &port.to_string(), &offset.to_string(), env!("CARGO_BIN_EXE_synsema"), "serve", "s.syn"])
            .current_dir(&dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        if adopts {
            let body = wait_body(port);
            let _ = child.kill();
            let o = child.wait_with_output().unwrap();
            let err = String::from_utf8_lossy(&o.stderr);
            assert_eq!(body.as_deref(), Some("\"heredado\""), "{}", err);
            assert!(err.contains(&format!("port {}: listening on the socket systemd passed in", port)), "{}", err);
        } else {
            // Tiene que fallar enseguida: si sigue corriendo, adoptó un socket ajeno.
            let t0 = std::time::Instant::now();
            while child.try_wait().unwrap().is_none() && t0.elapsed() < std::time::Duration::from_secs(15) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if child.try_wait().unwrap().is_none() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("con el LISTEN_PID de otro proceso tomó el socket y quedó sirviendo");
            }
            let o = child.wait_with_output().unwrap();
            let err = String::from_utf8_lossy(&o.stderr);
            assert!(!o.status.success() && err.contains("could not start server") && !err.contains("systemd"), "{}", err);
        }
    }
}

/// G1: con `SYNSEMA_REUSE_PORT=1` un `serve` nuevo escucha en el mismo puerto que el viejo; el
/// viejo recibe SIGTERM, deja de aceptar y drena, y el puerto sigue atendiendo sin cortes. Sin el
/// knob, el segundo es «address in use», como siempre.
#[cfg(target_os = "linux")]
#[test]
fn reuse_port_lets_a_new_serve_take_over_while_the_old_one_drains() {
    let dir = project("reuse-port");
    let port = free_port();
    for v in ["viejo", "nuevo"] {
        std::fs::write(dir.join(format!("{v}.syn")), format!("require serve({port})\nserve on {port}\n    route \"GET /\"\n        give \"{v}\"\n")).unwrap();
    }
    let start = |name: &str, reuse: bool| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"));
        c.args(["serve", name]).current_dir(&dir).env("SYNSEMA_NO_UPDATE_CHECK", "1").env("SYNSEMA_SHUTDOWN_GRACE", "2");
        if reuse {
            c.env("SYNSEMA_REUSE_PORT", "1");
        }
        c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap()
    };
    // Sin el knob: el segundo no arranca.
    let mut a = start("viejo.syn", false);
    assert_eq!(wait_body(port).as_deref(), Some("\"viejo\""));
    let o = start("nuevo.syn", false).wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("could not start server"), "{}", String::from_utf8_lossy(&o.stderr));
    let _ = a.kill();
    let _ = a.wait();
    // Con el knob: los dos escuchan; SIGTERM al viejo y el puerto sigue respondiendo (el nuevo).
    let mut a = start("viejo.syn", true);
    assert_eq!(wait_body(port).as_deref(), Some("\"viejo\""));
    let mut b = start("nuevo.syn", true);
    let mut saw_new = false;
    for _ in 0..200 {
        if get_body(port).as_deref() == Some("\"nuevo\"") {
            saw_new = true;
            break;
        }
    }
    let ok = std::process::Command::new("kill").args(["-TERM", &a.id().to_string()]).status().unwrap().success();
    assert!(ok);
    let _ = a.wait();
    let after: Vec<Option<String>> = (0..20).map(|_| get_body(port)).collect();
    let _ = b.kill();
    let _ = b.wait();
    assert!(saw_new, "el nuevo nunca atendió");
    assert!(after.iter().all(|r| r.as_deref() == Some("\"nuevo\"")), "{:?}", after);
}

/// G3: `approve … then <task>` fuera de `serve`: el gate se contesta en el acto (sin TTY se niega)
/// y la task corre con (decisión, mensaje, id); devuelve el id. `when approve … then a otherwise b`
/// sigue siendo la forma inline del `when`.
#[test]
fn approve_then_outside_serve_answers_on_the_spot_and_calls_the_task() {
    let dir = project("approve-then-run");
    std::fs::write(
        dir.join("a.syn"),
        "task settle(ok, message, id)\n    print(`decided {ok} | {message} | {id}`)\n\
         let id be approve \"Go?\" then settle\nprint(`id {id}`)\n\
         let c be confirm \"Sure?\" then settle\n\
         let v be when approve \"x\" then \"si\" otherwise \"no\"\nprint(`inline {v}`)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "a.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    let id = out.lines().find_map(|l| l.strip_prefix("id ")).expect("id").to_string();
    assert!(out.contains(&format!("decided false | Go? | {}", id)), "{}", out);
    assert!(out.contains("decided false | Sure? |"), "{}", out);
    assert!(out.contains("inline no"), "{}", out);
    for (src, want) in [
        ("let x be 1\napprove \"Go?\" then x\n", "\"x\" is not a task of the program"),
        ("task two(a, b)\n    print(a)\napprove \"Go?\" then two\n", "\"two\" takes 2 parameter(s); it is called with three"),
        ("approve \"Go?\" then \"settle\"\n", "Expected the name of a task after 'then'"),
    ] {
        std::fs::write(dir.join("e.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "e.syn"], None);
        assert!(code != 0 && err.contains(want), "{}: {}{}", src, out, err);
    }
}

/// Una petición HTTP a `127.0.0.1:port`: (status, cuerpo), o `None` si no conecta.
fn http(port: u16, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut r = String::new();
    s.read_to_string(&mut r).ok()?;
    let status = r.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, r.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()))
}

/// Un `serve` con la salida (stdout) en un buffer que se puede mirar mientras corre.
struct Served {
    child: std::process::Child,
    out: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Served {
    fn start(dir: &std::path::Path, file: &str) -> Served {
        Served::start_with(dir, file, &[])
    }

    fn start_with(dir: &std::path::Path, file: &str, env: &[(&str, &str)]) -> Served {
        use std::io::Read;
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
            .args(["serve", file])
            .current_dir(dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        for mut pipe in [Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>, Box::new(child.stderr.take().unwrap())] {
            let out = out.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    out.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            });
        }
        Served { child, out }
    }

    fn wait_for(&self, what: &str) -> String {
        for _ in 0..200 {
            if self.out.lock().unwrap().contains(what) {
                return self.out.lock().unwrap().clone();
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no apareció {:?} en:\n{}", what, self.out.lock().unwrap());
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    for _ in 0..200 {
        if let Some(r) = http(port, method, path, body) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("el server no contestó en :{}", port);
}

/// G3: bajo `serve`, `approve … then <task>` no bloquea la ruta (devuelve el id); lo pendiente
/// queda en `.synsema/state/approvals-<puerto>.json` (con el hash del token, no el token), sobrevive
/// a un reinicio, y la respuesta por `POST /approvals/<id>` con el token de antes llama a la task con
/// la decisión, el mensaje y el id. Resuelta, el archivo se borra.
#[test]
fn approve_then_under_serve_survives_a_restart_and_the_answer_calls_the_task() {
    let dir = project("approve-then-serve");
    let port = free_port();
    std::fs::write(
        dir.join("a.syn"),
        format!(
            "require serve({port})\n\ntask settle(ok, message, id)\n    print(`decided {{ok}} | {{message}} | {{id}}`)\n\n\
             serve on {port}\n    route \"POST /pay\"\n        let id be approve \"Pay 800?\" within 1h then settle\n        give {{\"pending\": id}}\n"
        ),
    )
    .unwrap();
    let a = Served::start(&dir, "a.syn");
    wait_http(port, "GET", "/approvals", "");
    let t0 = std::time::Instant::now();
    // Una sola vez: si la ruta esperara a la persona, esto vence (10 s) y no hay cuerpo.
    let (status, body) = http(port, "POST", "/pay", "").expect("la ruta contesta sin esperar");
    assert!(status == 200 && body.contains("approval_"), "{} {}", status, body);
    assert!(t0.elapsed() < std::time::Duration::from_secs(8), "la ruta no esperó a la persona");
    let id = body.split('"').find(|p| p.starts_with("approval_")).unwrap().to_string();
    let log = a.wait_for("\"token\": \"");
    let line = log.lines().find(|l| l.contains("approval pending") && l.contains(&id)).expect("aviso con el token");
    let token = line.rsplit("\"token\": \"").next().unwrap().trim_end_matches(['"', '}']).to_string();
    assert_eq!(token.len(), 64, "{}", line);
    let file = dir.join(".synsema").join("state").join(format!("approvals-{}.json", port));
    let saved = std::fs::read_to_string(&file).expect("lo pendiente se guarda");
    assert!(saved.contains(&id) && saved.contains("settle") && !saved.contains(&token), "{}", saved);
    drop(a);

    let b = Served::start(&dir, "a.syn");
    let (_, list) = wait_http(port, "GET", "/approvals", "");
    assert!(list.contains(&id), "recuperada tras el reinicio: {}", list);
    let (status, _) = http(port, "POST", &format!("/approvals/{}", id), "{\"decision\": true, \"token\": \"mal\"}").unwrap();
    assert_eq!(status, 403);
    let (status, body) = http(port, "POST", &format!("/approvals/{}", id), &format!("{{\"decision\": true, \"token\": \"{}\"}}", token)).unwrap();
    assert_eq!(status, 200, "{}", body);
    let out = b.wait_for(&format!("decided true | Pay 800? | {}", id));
    assert!(out.contains(&format!("approval {} answered: ran settle", id)), "{}", out);
    for _ in 0..40 {
        if !file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!file.exists(), "resuelta, no queda archivo");
}

/// Ronda 1 de v0.6.53, A1 (y §5 del modelo): `then` y `cron_*` agendan algo que corre después con
/// las capacidades del programa; desde un marco recortado son un error, en `run` también. A3: un
/// gate dentro de `parallel_map` usa el canal del programa (sin TTY, niega). B3: «nadie contestó» en
/// un `ask … with [...]` es la primera opción.
#[test]
fn then_and_cron_are_errors_in_a_narrowed_frame_and_children_share_the_human_channel() {
    let dir = project("g3-narrowed");
    let settle = "task settle(ok, message, id)\n    print(`decided {ok} | {message} | {id}`)\n";
    for (src, want) in [
        (
            format!("{settle}sandbox\n    let id be approve \"x\" then settle\n"),
            "approve … then settle: not allowed inside a sandbox",
        ),
        (
            "task w()\n    print(\"w\")\nsandbox\n    cron_after(1, w)\n".to_string(),
            "cron_after: not allowed inside a sandbox",
        ),
        (
            format!("{settle}task item(x)\n    give approve `pay {{x}}` then settle\nsandbox\n    let r be parallel_map(item, [1, 2])\n"),
            "not allowed inside a sandbox",
        ),
    ] {
        std::fs::write(dir.join("e.syn"), &src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "e.syn"], None);
        assert!(code != 0 && err.contains(want), "{}\n---\n{}{}", src, out, err);
        assert!(!out.contains("decided"), "la task no corrió: {}", out);
    }
    std::fs::write(
        dir.join("a.syn"),
        format!(
            "{settle}task ask_one(x)\n    give approve `main? {{x}}`\n\
             let m be approve \"main?\"\nprint(`main {{m}}`)\nprint(parallel_map(ask_one, [1, 2]))\n\
             task pick(color, message, id)\n    print(`picked {{color}}`)\n\
             let p be ask \"Color?\" with [\"rojo\", \"azul\"] within 0s then pick\n\
             task kind(choice, message, id)\n    print(`kind {{type_of(choice)}}`)\n\
             let k be ask \"n?\" with [1, 2] within 0s then kind\n\
             let a be ask \"n?\" with [1, 2] within 0s\nprint(`plain {{type_of(a)}}`)\n"
        ),
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "a.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("main false"), "{}", out);
    assert!(out.contains("[false, false]"), "los items no se aprueban solos: {}", out);
    assert!(out.contains("picked rojo"), "{}", out);
    // Ronda 2, R2-7: la task de un `ask … then` recibe texto, como bajo `serve`.
    assert!(out.contains("kind text"), "{}", out);
    // Ronda 3, R3-1: el `ask` que espera da lo mismo, texto.
    assert!(out.contains("plain text"), "{}", out);
}

/// Ronda 1 de v0.6.53 bajo `serve`: A1 (un `then` dentro de un `sandbox` da 500 y la task no
/// escribe nada), A3 (`parallel_map` con `then` deja dos pendientes de verdad), B3 (un `ask` con
/// opciones que vence llama a la task con la primera) y B7 (el archivo de otro puerto se nombra).
#[test]
fn under_serve_then_respects_the_sandbox_children_leave_pending_approvals_and_ask_expires_to_its_first_option() {
    let dir = project("g3-serve-r1");
    let port = free_port();
    let state = dir.join(".synsema").join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("approvals-1.json"), "[{\"id\":\"approval_viejo\"}]").unwrap();
    std::fs::write(
        dir.join("a.syn"),
        format!(
            "require serve({port})\nrequire file.write(\"./out/**\")\n\n\
             task writer(ok, message, id)\n    write_file(\"./out/escaped.txt\", `ok={{ok}}`)\n\n\
             task settle(ok, message, id)\n    print(`decided {{ok}} | {{message}} | {{id}}`)\n\n\
             task item(x)\n    give approve `pay {{x}}` within 1h then settle\n\n\
             task pick(color, message, id)\n    print(`picked {{color}}`)\n\n\
             serve on {port}\n\
             \x20   route \"POST /sb\"\n        sandbox\n            let id be approve \"inofensivo\" within 1s then writer\n        give {{\"pending\": \"sb\"}}\n\
             \x20   route \"POST /many\"\n        give {{\"pending\": parallel_map(item, [1, 2])}}\n\
             \x20   route \"POST /ask\"\n        give {{\"pending\": ask \"Color?\" with [\"rojo\", \"azul\"] within 1s then pick}}\n"
        ),
    )
    .unwrap();
    let a = Served::start(&dir, "a.syn");
    wait_http(port, "GET", "/approvals", "");
    let (status, body) = http(port, "POST", "/sb", "").unwrap();
    assert!(status == 500 && body.contains("not allowed inside a sandbox"), "{} {}", status, body);
    let (status, body) = http(port, "POST", "/many", "").unwrap();
    assert_eq!(status, 200, "{}", body);
    assert_eq!(body.matches("approval_").count(), 2, "{}", body);
    let (_, list) = http(port, "GET", "/approvals", "").unwrap();
    for id in body.split('"').filter(|p| p.starts_with("approval_")) {
        assert!(list.contains(id), "{} no está en /approvals: {}", id, list);
    }
    let (status, _) = http(port, "POST", "/ask", "").unwrap();
    assert_eq!(status, 200);
    let out = a.wait_for("picked rojo");
    assert!(out.contains("approvals-1.json") && out.contains("another port"), "{}", out);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(!dir.join("out").join("escaped.txt").exists(), "la task del sandbox no corrió");
}

/// Ronda 1 de v0.6.53, A2: en el traspaso de `SYNSEMA_REUSE_PORT` los dos procesos comparten el
/// archivo de pendientes; una que vence corre su task UNA vez, contando los dos.
#[cfg(unix)]
#[test]
fn two_serves_on_one_port_settle_an_expired_approval_once() {
    let dir = project("g3-handoff");
    let port = free_port();
    std::fs::write(
        dir.join("a.syn"),
        format!(
            "require serve({port})\n\ntask settle(ok, message, id)\n    print(`decided {{ok}} | {{message}} | {{id}}`)\n\n\
             serve on {port}\n    route \"POST /pay\"\n        let id be approve \"Pay 800?\" within 4s then settle\n        give {{\"pending\": id}}\n"
        ),
    )
    .unwrap();
    let env = [("SYNSEMA_REUSE_PORT", "1")];
    let a = Served::start_with(&dir, "a.syn", &env);
    a.wait_for("running");
    wait_http(port, "GET", "/approvals", "");
    let (status, body) = http(port, "POST", "/pay", "").unwrap();
    assert_eq!(status, 200, "{}", body);
    let b = Served::start_with(&dir, "a.syn", &env);
    b.wait_for("running");
    std::thread::sleep(std::time::Duration::from_secs(7));
    let runs = a.out.lock().unwrap().matches("decided false | Pay 800?").count() + b.out.lock().unwrap().matches("decided false | Pay 800?").count();
    assert_eq!(runs, 1, "A:\n{}\nB:\n{}", a.out.lock().unwrap(), b.out.lock().unwrap());
}

/// Ronda 2 de v0.6.53, R2-4 (N2): un SIGTERM con la task de una aprobación en curso espera a que
/// termine, dentro de `SYNSEMA_SHUTDOWN_GRACE`.
#[cfg(target_os = "linux")]
#[test]
fn a_shutdown_waits_for_a_running_approval_task() {
    let dir = project("g3-shutdown-wait");
    let port = free_port();
    std::fs::write(
        dir.join("a.syn"),
        format!(
            "require serve({port})\nrequire time\n\n\
             task slow(ok, message, id)\n    print(\"slow start\")\n    sleep(2)\n    print(\"slow done\")\n\n\
             serve on {port}\n    route \"POST /pay\"\n        let id be approve \"x\" within 1s then slow\n        give {{\"pending\": id}}\n"
        ),
    )
    .unwrap();
    let mut a = Served::start_with(&dir, "a.syn", &[("SYNSEMA_SHUTDOWN_GRACE", "10")]);
    wait_http(port, "GET", "/approvals", "");
    let (status, _) = http(port, "POST", "/pay", "").unwrap();
    assert_eq!(status, 200);
    a.wait_for("slow start");
    let ok = std::process::Command::new("kill").args(["-TERM", &a.child.id().to_string()]).status().unwrap().success();
    assert!(ok);
    let _ = a.child.wait();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let out = a.out.lock().unwrap().clone();
    assert!(out.contains("slow done"), "el cierre no esperó a la task: {}", out);
}

/// Ronda 2 de v0.6.53, R2-1: una tool que corre `call_tool` tiene sólo las caps que declaró; un
/// `then` o un `cron_after` desde ahí correrían después con las del programa. Es error en `run` y
/// en `serve`.
#[test]
fn then_and_cron_inside_call_tool_are_errors() {
    let dir = project("g3-call-tool");
    let pre = "require file.write(\"./out/**\")\nrequire time\n\n\
               task writer(ok, message, id)\n    write_file(\"./out/escaped.txt\", `ok={ok}`)\n\n\
               task writer0()\n    write_file(\"./out/escaped.txt\", \"cron\")\n\n";
    for (body, want) in [
        ("    give approve \"inofensivo\" within 1s then writer\n", "then writer: not allowed inside a tool run by call_tool"),
        ("    give cron_after(1, writer0)\n", "cron_after: not allowed inside a tool run by call_tool"),
    ] {
        let src = format!("{pre}task harmless(x)\n{body}\nprint(call_tool(harmless, {{\"x\": 1}}))\n");
        std::fs::write(dir.join("t.syn"), &src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "t.syn"], None);
        assert!(code != 0 && err.contains(want), "{}\n---\n{}{}", src, out, err);
    }
    let port = free_port();
    std::fs::write(
        dir.join("s.syn"),
        format!(
            "require serve({port})\n{pre}task harmless(x)\n    give approve \"inofensivo\" within 1s then writer\n\n\
             serve on {port}\n    route \"POST /tool\"\n        give {{\"r\": call_tool(harmless, {{\"x\": 1}})}}\n"
        ),
    )
    .unwrap();
    let _s = Served::start(&dir, "s.syn");
    wait_http(port, "GET", "/approvals", "");
    let (status, body) = http(port, "POST", "/tool", "").unwrap();
    assert!(status == 500 && body.contains("inside a tool run by call_tool"), "{} {}", status, body);
    std::thread::sleep(std::time::Duration::from_millis(2500));
    assert!(!dir.join("out").join("escaped.txt").exists(), "la task no corrió con las caps del programa");
}
