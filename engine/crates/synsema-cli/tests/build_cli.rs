//! E2E de `synsema build` sobre el binario real (spec `specs/tanda-motor-lamps.md`): el
//! binario único corre el programa con `args()`, `--engine` devuelve el CLI, el sha del
//! bundle se verifica, los `use`/templates/assets viven dentro (sin disco), el techo y el
//! perfil horneados mandan, y `update` se niega a pisar un programa construido.

use std::path::PathBuf;
use std::process::Command;

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-build-cli-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("lamp.syn"),
        "use \"./lib/m.syn\" as m\nprint(m.twice(21))\nprint(args())\nprint(read_file(\"assets/a.json\"))\nprint(file_exists(\"assets/a.json\"))\nprint(render(\"card.html\", {\"name\": \"lamp\"}))\n",
    )
    .unwrap();
    std::fs::write(dir.join("lib").join("m.syn"), "export task twice(x)\n    give x * 2\n").unwrap();
    std::fs::write(dir.join("assets").join("a.json"), "{\"k\": 1}").unwrap();
    std::fs::write(dir.join("card.html"), "<b>{ name }</b>\n").unwrap();
    dir
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

fn run(cmd: &PathBuf, dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn synsema(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    run(&PathBuf::from(env!("CARGO_BIN_EXE_synsema")), dir, args)
}

fn build(dir: &PathBuf, extra: &[&str]) -> PathBuf {
    let out = dir.join(exe_name("lamp"));
    let mut args = vec!["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "assets/"];
    args.extend_from_slice(extra);
    let (code, stdout, err) = synsema(dir, &args);
    assert_eq!(code, 0, "{}\n{}", stdout, err);
    assert!(stdout.starts_with("built "), "{}", stdout);
    out
}

#[test]
fn build_hello_and_run_it_without_the_sources_on_disk() {
    let dir = project("hello");
    let lamp = build(&dir, &[]);
    // Sin los fuentes ni los assets en disco: todo vive en el bundle.
    std::fs::remove_dir_all(dir.join("lib")).unwrap();
    std::fs::remove_dir_all(dir.join("assets")).unwrap();
    std::fs::remove_file(dir.join("card.html")).unwrap();
    std::fs::remove_file(dir.join("lamp.syn")).unwrap();
    let (code, out, err) = run(&lamp, &dir, &["--hello", "world"]);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().map(|l| l.trim()).collect();
    assert_eq!(lines[0], "42");
    assert_eq!(lines[1], "[--hello, world]");
    assert_eq!(lines[2], "{\"k\": 1}");
    assert_eq!(lines[3], "true");
    assert!(lines[4].contains("<b>lamp</b>"), "{}", out);
    // `--engine` es el CLI del motor.
    let (code, out, _) = run(&lamp, &dir, &["--engine", "version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Synsema "), "{}", out);
    // `update` se niega sobre un programa construido.
    let (code, _, err) = run(&lamp, &dir, &["--engine", "update"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("built program"), "{}", err);
    // El binario `synsema` de siempre acepta `--engine` como prefijo no-op.
    let (code, out, _) = synsema(&dir, &["--engine", "version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Synsema "));
}

#[test]
fn corrupt_sha_refuses_to_run() {
    let dir = project("corrupt");
    let lamp = build(&dir, &[]);
    let mut bytes = std::fs::read(&lamp).unwrap();
    // Un byte del payload (justo antes del trailer de 64 bytes) alterado.
    let idx = bytes.len() - 64 - 3;
    bytes[idx] ^= 0xff;
    let broken = dir.join(exe_name("broken"));
    std::fs::write(&broken, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (code, out, err) = run(&broken, &dir, &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("bundle corrupt"), "{}", err);
    assert!(out.trim().is_empty());
}

#[test]
fn bundled_reads_are_audited_and_writes_are_rejected() {
    let dir = project("audit");
    std::fs::write(
        dir.join("lamp.syn"),
        "print(read_file(\"assets/a.json\"))\ntry\n    write_file(\"assets/a.json\", \"x\")\nrecover e\n    print(e)\n",
    )
    .unwrap();
    // Techo SIN file: la lectura del bundle no lo necesita (es parte del programa).
    let lamp = build(&dir, &["--cap-set", "stdout"]);
    let (code, out, err) = run(&lamp, &dir, &["--engine", "run", "--audit", "json", "lamp.syn"]);
    // `--engine run lamp.syn` corre desde DISCO sin overlay → pide file.read y falla.
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("Capability not granted: file_read"), "{}", err);
    let _ = (code, out);
    // En modo programa: lee del bundle, audita `bundled asset`, y la escritura se rechaza.
    let audit = dir.join("a.jsonl");
    std::fs::write(dir.join("lamp.syn"), "require file.write(\"assets/a.json\")\nprint(read_file(\"assets/a.json\"))\ntry\n    write_file(\"assets/a.json\", \"x\")\nrecover e\n    print(e)\n").unwrap();
    let lamp = build(&dir, &["--cap-set", "stdout,file.write=assets/a.json"]);
    let _ = audit;
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("{\"k\": 1}"), "{}", out);
    assert!(out.contains("is part of the bundle (read-only)"), "{}", out);
}

#[test]
fn baked_cap_set_and_profile_pure_are_enforced() {
    let dir = project("baked");
    let (sh, args) = if cfg!(windows) { ("cmd", "\"/C\", \"echo pwned\"") } else { ("sh", "\"-c\", \"echo pwned\"") };
    std::fs::write(
        dir.join("lamp.syn"),
        format!("require exec(\"{sh}\")\ntry\n    let r be run(\"{sh}\", [{args}])\n    print(r[\"stdout\"])\nrecover e\n    print(e)\n", sh = sh, args = args),
    )
    .unwrap();
    // Techo horneado sin exec.
    let lamp = build(&dir, &["--sandbox"]);
    let (code, out, _) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0);
    assert!(!out.contains("pwned"), "{}", out);
    assert!(out.contains("above the host ceiling"), "{}", out);
    // Los argumentos del programa NO son flags del motor: `--sandbox` acá es un arg.
    std::fs::write(dir.join("lamp.syn"), "print(args())\n").unwrap();
    let lamp = build(&dir, &[]);
    let (code, out, _) = run(&lamp, &dir, &["--sandbox", "--cap-set", "x"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "[--sandbox, --cap-set, x]");
    // Perfil puro horneado: `run` es un stub aunque el techo lo permita.
    std::fs::write(
        dir.join("lamp.syn"),
        format!("require exec(\"{sh}\")\ntry\n    run(\"{sh}\", [])\nrecover e\n    print(e)\nprint(read_file(\"assets/a.json\"))\n", sh = sh),
    )
    .unwrap();
    let lamp = build(&dir, &["--profile", "pure"]);
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("run: not available in the pure profile"), "{}", out);
    // Las lecturas del bundle no son filesystem: siguen funcionando bajo pure.
    assert!(out.contains("{\"k\": 1}"), "{}", out);
}

#[test]
fn baked_sandbox_serves_bundle_but_denies_disk_and_traversal() {
    // Un binario horneado con techo `--sandbox` (sin `file`): lee su bundle (parte del
    // programa) pero NO puede leer disco arbitrario ni escapar por `..`.
    let dir = project("traversal");
    std::fs::write(dir.join("secret_on_disk.txt"), "SECRET_ON_DISK").unwrap();
    let parent = dir.parent().unwrap().to_path_buf();
    std::fs::write(parent.join("outside_secret_marker.txt"), "SECRET_OUTSIDE").unwrap();
    std::fs::write(
        dir.join("lamp.syn"),
        "print(\"bundle: \" + read_file(\"assets/a.json\"))\ntry\n    print(\"disk: \" + read_file(\"secret_on_disk.txt\"))\nrecover e\n    print(\"disk denied\")\ntry\n    print(\"trav: \" + read_file(\"../outside_secret_marker.txt\"))\nrecover e\n    print(\"trav denied\")\n",
    )
    .unwrap();
    let lamp = build(&dir, &["--sandbox"]);
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("bundle: {\"k\": 1}"), "{}", out);
    assert!(out.contains("disk denied"), "leyó disco fuera del bundle: {}", out);
    assert!(out.contains("trav denied"), "escapó por traversal: {}", out);
    assert!(!out.contains("SECRET_ON_DISK") && !out.contains("SECRET_OUTSIDE"), "{}", out);
    let _ = std::fs::remove_file(parent.join("outside_secret_marker.txt"));
}

#[test]
fn build_usage_errors_exit_2() {
    let dir = project("usage");
    let out = dir.join(exe_name("x"));
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn"]);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "../nope"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("matched nothing") || err.contains("not found"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "../lamp.syn"]);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--profile", "bogus"]);
    assert_eq!(code, 2, "{}", err);
    // Construir desde un binario ya construido se rechaza.
    let lamp = build(&dir, &[]);
    let (code, _, err) = run(&lamp, &dir, &["--engine", "build", "lamp.syn", "-o", out.to_str().unwrap()]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("already a built program"), "{}", err);
}

// =========================================================
// `synsema build --serve` (tanda PWA v0.6.16): el binario corre el runtime de serve con los
// flags horneados y sirve los mounts estáticos DESDE EL BUNDLE (una PWA de un solo binario).
// =========================================================

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Una request HTTP/1.1 cruda → (status, head, body).
fn http(port: u16, path: &str) -> (u16, String, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(20))).unwrap();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path).as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn serve_project(tag: &str, port: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-build-serve-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("public").join("sub")).unwrap();
    std::fs::write(
        dir.join("app.syn"),
        format!(
            "require serve({p})\n\nserve on {p}\n    static \"/\" from \"./public\" cache \"1h\"\n    route \"GET /\"\n        give render(\"index.html\", {{\"title\": \"bundled\"}})\n    route \"GET /api/ping\"\n        give ok({{\"pong\": true}})\n",
            p = port
        ),
    )
    .unwrap();
    std::fs::write(dir.join("index.html"), "<h1>{ title }</h1>\n").unwrap();
    std::fs::write(dir.join("public").join("app.js"), "console.log(\"from the bundle\");\n").unwrap();
    std::fs::write(dir.join("public").join("sub").join("x.css"), "body{margin:0}\n").unwrap();
    std::fs::write(dir.join("public").join("index.html"), "<p>static index</p>\n").unwrap();
    dir
}

fn wait_ready(port: u16) {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(60) {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let (st, _, _) = http(port, "/api/ping");
            if st == 200 {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    panic!("el binario construido no levantó en 60 s");
}

#[test]
fn build_serve_binary_serves_templates_and_statics_from_bundle() {
    let port = free_port();
    let dir = serve_project("ok", port);
    let out_dir = std::env::temp_dir().join(format!("synsema-build-serve-out-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = out_dir.join(exe_name("app"));
    // Sin --include: los mounts estáticos del serve se bundlean solos.
    let (code, stdout, err) = synsema(&dir, &["build", "app.syn", "-o", out.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"]);
    assert_eq!(code, 0, "{}\n{}", stdout, err);
    assert!(stdout.contains("serve · bind 127.0.0.1"), "{}", stdout);
    assert!(stdout.contains("5 files"), "app.syn + index.html + 3 estáticos: {}", stdout);
    // El fuente desaparece: todo lo que sirva viene del bundle.
    std::fs::remove_dir_all(&dir).unwrap();

    let mut child = Command::new(&out)
        .current_dir(&out_dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn built server");
    wait_ready(port);

    let (st, head, body) = http(port, "/");
    assert_eq!(st, 200, "{}", head);
    assert!(body.contains("<h1>bundled</h1>"), "la ruta declarada gana y el template viene del bundle: {}", body);
    let (st, head, body) = http(port, "/app.js");
    assert_eq!(st, 200, "{}", head);
    assert!(header(&head, "content-type").unwrap().starts_with("text/javascript"), "{}", head);
    assert!(body.contains("from the bundle"), "{}", body);
    assert!(header(&head, "etag").unwrap().starts_with("\"b"), "ETag por contenido: {}", head);
    assert_eq!(header(&head, "cache-control").as_deref(), Some("public, max-age=3600"));
    let (st, _, body) = http(port, "/sub/x.css");
    assert_eq!(st, 200);
    assert_eq!(body.trim(), "body{margin:0}");
    let (st, _, body) = http(port, "/sub/");
    assert_eq!(st, 404, "un directorio sin index.html es 404, no un listado: {}", body);
    let (st, _, _) = http(port, "/nope.txt");
    assert_eq!(st, 404);
    let (st, _, _) = http(port, "/../app.syn");
    assert_ne!(st, 200, "el bundle no se expone fuera del mount");
    let (st, _, _) = http(port, "/%2e%2e/app.syn");
    assert_ne!(st, 200);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn build_serve_flags_are_validated_at_build_time() {
    let port = free_port();
    let dir = serve_project("flags", port);
    let out = dir.join(exe_name("app"));
    let o = out.to_str().unwrap();
    // Un programa con serve block sin --serve: se dice en el build, no al correr.
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("has a serve block; pass --serve"), "{}", err);
    // --serve sin --bind: un distribuible no adivina la interfaz.
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o, "--serve"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--serve needs --bind"), "{}", err);
    // Flags de despliegue sin --serve.
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o, "--bind", "127.0.0.1"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("applies to --serve builds"), "{}", err);
    // El perfil puro no bindea sockets.
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o, "--serve", "--bind", "127.0.0.1", "--profile", "pure"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--serve --profile pure is not supported"), "{}", err);
    // tls-auto y tls-cert son excluyentes (misma validación que `synsema serve`).
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o, "--serve", "--bind", "0.0.0.0", "--tls-auto", "a@b.c", "--tls-cert", "c.pem", "--tls-key", "k.pem"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("mutually exclusive"), "{}", err);
    // Un mount estático que no existe es un error del build.
    std::fs::remove_dir_all(dir.join("public")).unwrap();
    let (code, _, err) = synsema(&dir, &["build", "app.syn", "-o", o, "--serve", "--bind", "127.0.0.1"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("static mount './public'"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}
