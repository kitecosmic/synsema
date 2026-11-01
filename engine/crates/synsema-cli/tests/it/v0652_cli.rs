//! Tests del binario real para v0.6.52.

use super::v0646_tanda_e_cli::{project, synsema};

/// Un programa con 1.000 niveles de anidamiento: `run` lo corre en el hilo del motor; `check`,
/// `ast`, `openapi` y `code` lo parseaban en el hilo principal y desbordaban la pila (en Windows, el
/// release ya con ~90 niveles).
fn deep_source() -> String {
    let n = 1000;
    format!("let x be {}1{}\nprint(x)\n", "(".repeat(n), ")".repeat(n))
}

/// `check` de un archivo profundo, y de uno chico que está en la misma carpeta (los avisos de
/// capabilities parsean la carpeta): los dos terminan bien, sin desbordar la pila.
#[test]
fn check_and_ast_parse_a_deeply_nested_program_without_overflowing() {
    let dir = project("deep-check");
    std::fs::write(dir.join("deep.syn"), deep_source()).unwrap();
    std::fs::write(dir.join("ok.syn"), "print(1)\n").unwrap();
    for args in [["check", "deep.syn"], ["check", "ok.syn"], ["ast", "deep.syn"], ["openapi", "deep.syn"]] {
        let (code, out, err) = synsema(&dir, &args, None);
        assert!(!err.contains("overflowed its stack"), "{:?}: {}", args, err);
        assert!(code == 0 || args[0] == "openapi", "{:?} → {}\n{}\n{}", args, code, out, err);
    }
    let (code, _, err) = synsema(&dir, &["code", "outline", "deep.syn"], None);
    assert!(!err.contains("overflowed its stack") && code == 0, "code outline → {}\n{}", code, err);
}

/// Un handle que no es un número nombra el builtin que lo da. `term_write(nothing, …)` hablaba de
/// `ws_connect()`, y el `nothing` venía de `term_open()` sin terminal (acá stdout es un pipe).
#[test]
fn a_missing_handle_names_the_builtin_that_gives_it() {
    let dir = project("handle-source");
    let term = "require stdin\nlet t be term_open()\nprint(t)\nterm_write(t, \"x\")\n";
    std::fs::write(dir.join("term.syn"), term).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--cap-set", "stdin,stdout", "term.syn"], None);
    assert_eq!((code, out.trim()), (1, "nothing"), "{}", err);
    assert!(
        err.contains("term_write: expected a terminal handle from term_open(), got nothing — term_open() gives nothing when there is no terminal")
            && !err.contains("ws_connect"),
        "{}",
        err
    );
    for (call, want) in [
        ("proc_wait(nothing)", "proc_wait: expected a process handle from proc_spawn(), got nothing"),
        ("watch_close(nothing)", "watch_close: expected a watch handle from watch(), got nothing"),
        ("bus_recv(nothing)", "bus_recv: expected a subscription handle from bus_subscribe(), got nothing"),
        ("tcp_close(nothing)", "tcp_close: expected a connection handle from tcp_connect(), got nothing"),
        ("pipe_close(nothing)", "pipe_close: expected a pipe end from pipe(), got nothing"),
        ("ws_close(nothing)", "ws_close: expected a connection handle from ws_connect() or a `socket` route, got nothing"),
        ("select([nothing])", "select: expected a handle from ws_connect() or a `socket` route, proc_spawn(), watch(), term_open(), bus_subscribe(), tcp_connect() or pipe(), got nothing"),
        // Ronda 1 (N4): `ws_select` es `select` y toma las mismas familias.
        ("ws_select([nothing])", "ws_select: expected a handle from ws_connect() or a `socket` route, proc_spawn(), watch(), term_open(), bus_subscribe(), tcp_connect() or pipe(), got nothing"),
    ] {
        std::fs::write(dir.join("h.syn"), format!("{}\n", call)).unwrap();
        let (code, _, err) = synsema(&dir, &["run", "h.syn"], None);
        assert!(code != 0 && err.contains(want), "{} → {}\n{}", call, code, err);
    }
}

/// `set r["status"]` / `set r.status` sobre lo que devuelve `ok`/`respond`/`render`/…: es de sólo
/// lectura, y el error lo dice con cómo armar otro. v0.6.51 decía `Cannot set index on map` sobre
/// un valor cuyo `type_of` es `map`. Un número sigue con el texto de siempre.
#[test]
fn setting_a_field_of_a_server_response_says_it_is_read_only() {
    let dir = project("server-set");
    for (target, what) in [("r[\"status\"]", "index"), ("r.status", "property")] {
        for make in ["ok(1)", "respond(\"x\", \"text/plain\")", "with_header(ok(1), \"X-A\", \"1\")"] {
            std::fs::write(dir.join("s.syn"), format!("let r be {}\nset {} to 500\n", make, target)).unwrap();
            let (code, _, err) = synsema(&dir, &["run", "s.syn"], None);
            let want = format!("Cannot set {} on a server response", what);
            assert!(
                code != 0 && err.contains(&want) && err.contains("read-only") && err.contains("respond(r[\"body\"], r[\"content_type\"], 500)"),
                "{} / {} → {}\n{}",
                make,
                target,
                code,
                err
            );
        }
    }
    std::fs::write(dir.join("n.syn"), "let n be 1\nset n[\"a\"] to 2\n").unwrap();
    let (_, _, err) = synsema(&dir, &["run", "n.syn"], None);
    assert!(err.contains("Cannot set index on number"), "{}", err);
}

/// `net("localhost:*")` no concedía nada (ni `localhost:8080`) y se aceptaba callado. Ahora es error
/// en cada lugar por donde entra un scope de `net`: el `require` literal (al cargar: `check` también),
/// el calculado (al correr), el host de un secret atado y `--cap-set`. `localhost` sigue llegando a
/// todos los puertos.
#[test]
fn a_net_scope_whose_port_is_not_a_port_is_an_error() {
    let dir = project("net-port");
    let want = "the port is a number from 1 to 65535, written with digits only, or nothing — `net(\"localhost\")` already reaches every port of localhost";
    for (name, src) in [
        ("lit.syn", "require net(\"localhost:*\")\nprint(1)\n"),
        // Ronda 1 (B2): `u16::from_str` acepta `+8080`, y el host quedaba `localhost:+8080`.
        ("plus.syn", "require net(\"localhost:+8080\")\nprint(1)\n"),
        ("dyn.syn", "let p be \"*\"\nrequire net(\"localhost:\" + p)\nprint(1)\n"),
        ("bound.syn", "require secret(\"K\") for net(\"localhost:*\")\nprint(1)\n"),
    ] {
        std::fs::write(dir.join(name), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", name], None);
        assert!(code != 0 && err.contains(want) && !out.contains('1'), "{} → {}\n{}{}", name, code, out, err);
    }
    let (code, _, err) = synsema(&dir, &["check", "lit.syn"], None);
    assert!(code != 0 && err.contains(want), "check → {}\n{}", code, err);
    std::fs::write(dir.join("ok.syn"), "require net(\"localhost\")\nrequire net(\"localhost:8080\")\nprint(1)\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "ok.syn"], None);
    assert_eq!((code, out.trim()), (0, "1"), "{}", err);
    let (code, _, err) = synsema(&dir, &["run", "--cap-set", "stdout,net=localhost:*", "ok.syn"], None);
    assert!(code != 0 && err.contains("--cap-set: net(\"localhost:*\"): the port is a number"), "{}\n{}", code, err);
}

/// L2 (`specs/v0.6.52-modelos.md`): con `file.read("./proj/**")` y `file.read("./outside/**")`,
/// `proj/out_link` → `outside` se lee, se lista y se mira por el link (v0.6.51 pedía un permiso que
/// cubriera las dos cosas, `./**`). Sin el segundo permiso sigue rechazado, con el mensaje de siempre.
#[test]
fn a_link_to_another_granted_place_works_with_the_two_grants() {
    let dir = project("l2-link");
    std::fs::create_dir_all(dir.join("proj")).unwrap();
    std::fs::create_dir_all(dir.join("outside")).unwrap();
    std::fs::write(dir.join("outside").join("a.txt"), "hola").unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(dir.join("proj").join("out_link"))
        .arg(dir.join("outside"))
        .output()
        .unwrap()
        .status
        .success());
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("outside"), dir.join("proj").join("out_link")).unwrap();
    let body = "print(read_file(\"./proj/out_link/a.txt\"))\nprint(list_dir(\"./proj/out_link\"))\nprint(file_info(\"./proj/out_link/a.txt\")[\"size\"])\n";
    std::fs::write(dir.join("two.syn"), format!("require file.read(\"./proj/**\")\nrequire file.read(\"./outside/**\")\n{}", body)).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "two.syn"], None);
    assert_eq!((code, out.trim()), (0, "hola\n[{name: \"a.txt\", is_dir: false, size: 4, is_link: false}]\n4"), "{}", err);
    std::fs::write(dir.join("one.syn"), format!("require file.read(\"./proj/**\")\n{}", body)).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "one.syn"], None);
    assert!(code != 0 && err.contains("grant the place the link points to"), "{}\n{}", code, err);
}

/// `run(…, {"isolate": …})`: lo que no se puede imponer o no se tiene para delegar es error antes de
/// lanzar nada, en cualquier sistema.
#[test]
fn isolate_refuses_what_it_cannot_enforce_or_delegate() {
    let dir = project("isolate-opts");
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data").join("a.csv"), "x\n").unwrap();
    let head = "require exec(\"nothing-runs\")\nrequire file.read(\"./data/**\")\n";
    for (opts, want) in [
        ("{\"isolate\": {\"file.write\": \"./data/**\"}}", "Capability not granted"),
        ("{\"isolate\": {\"file.read\": \"./other/**\"}}", "Capability not granted"),
        ("{\"isolate\": {\"file.read\": \"./data/*.csv\"}}", "the kernel grants whole folders (\"./data/**\") or single files"),
        ("{\"isolate\": {\"file.read\": \"./data\"}}", "is a folder: grant it as \"./data/**\""),
        ("{\"isolate\": {\"file.read\": \"./data/a.csv/**\"}}", "is a file: grant it without \"/**\""),
        ("{\"isolate\": {\"file.read\": \"./data/nope/**\"}}", "make_dir() it first"),
        ("{\"isolate\": {\"file.read\": [\"./data/**\", 1]}}", "lists paths (text), got number"),
        ("{\"isolate\": {\"net\": \"api.example.com\"}}", "an isolated child has no network yet"),
        ("{\"isolate\": {\"env\": \"x\"}}", "\"isolate\" takes \"file.read\" and \"file.write\""),
        ("{\"isolate\": \"yes\"}", "\"isolate\" is true or a map"),
        ("{\"isolate\": true, \"max_memory_mb\": 0}", "max_memory_mb is a whole number of megabytes"),
        ("{\"isolate\": true, \"max_memory_mb\": 1.5}", "max_memory_mb is a whole number of megabytes"),
        ("{\"max_memory_mb\": 512}", "max_memory_mb is enforced only for an isolated child"),
        // Ronda 1: `..` después de una carpeta (A1) y una opción mal escrita (M3).
        ("{\"isolate\": {\"file.read\": \"./x/../data/**\"}}", "has `..` after a folder"),
        ("{\"isolated\": true}", "unknown option \"isolated\" (valid options: cwd, stdin, max_output, env, env_clean, isolate, max_memory_mb, max_file_mb)"),
    ] {
        std::fs::write(dir.join("i.syn"), format!("{}run(\"nothing-runs\", [], 10, {})\n", head, opts)).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "i.syn"], None);
        assert!(code != 0 && err.contains(want), "{} → {}\n{}{}", opts, code, out, err);
        assert!(!err.contains("cannot start"), "{}: llegó a lanzar\n{}", opts, err);
    }
}

/// Ronda 1 (M3): `proc_spawn` no tiene `isolate` todavía y una opción que no conoce es error; el
/// ejecutable con `..` después de una carpeta, también (en `run` y en `proc_spawn`). Nada corre.
#[test]
fn proc_spawn_refuses_isolate_and_unknown_options() {
    let dir = project("isolate-proc");
    #[cfg(windows)]
    let (prog, args) = ("cmd", "[\"/C\", \"echo hi> marker.txt\"]");
    #[cfg(not(windows))]
    let (prog, args) = ("sh", "[\"-c\", \"echo hi > marker.txt\"]");
    for (call, want) in [
        (format!("proc_spawn(\"{}\", {}, {{\"isolate\": true}})", prog, args), "proc_spawn: \"isolate\" comes in a later version"),
        (format!("proc_spawn(\"{}\", {}, {{\"isolated\": true}})", prog, args), "proc_spawn: unknown option \"isolated\""),
        ("run(\"./x/../tool\", [], 10)".to_string(), "run: the program \"./x/../tool\" has `..` after a folder"),
        ("proc_spawn(\"./x/../tool\", [])".to_string(), "proc_spawn: the program \"./x/../tool\" has `..` after a folder"),
        // Ronda 2 (B2): unas opciones que no son un mapa no se ignoran.
        (format!("run(\"{}\", {}, 10, \"isolate\")", prog, args), "run: options must be a map, got text"),
        (format!("run(\"{}\", {}, 10, [{{\"isolate\": true}}])", prog, args), "run: options must be a map, got list"),
    ] {
        let src = format!("require exec(\"{}\")\nrequire exec(\"./tool\")\nlet h be {}\n", prog, call);
        std::fs::write(dir.join("p.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
        assert!(code != 0 && err.contains(want), "{} → {}\n{}{}", call, code, out, err);
        assert!(!dir.join("marker.txt").exists(), "{}: el hijo corrió", call);
    }
}

/// Fuera de Linux no hay con qué aislar: falla cerrado y el hijo no corre (no se cae a correrlo sin
/// aislar).
#[cfg(not(target_os = "linux"))]
#[test]
fn isolate_fails_closed_where_the_kernel_cannot_enforce_it() {
    let dir = project("isolate-closed");
    #[cfg(windows)]
    let (prog, args) = ("cmd", "[\"/C\", \"echo hi> marker.txt\"]");
    #[cfg(not(windows))]
    let (prog, args) = ("sh", "[\"-c\", \"echo hi > marker.txt\"]");
    let src = format!("require exec(\"{0}\")\nprint(run(\"{0}\", {1}, 10, {{\"isolate\": true}}))\n", prog, args);
    std::fs::write(dir.join("c.syn"), src).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "c.syn"], None);
    assert!(code != 0 && err.contains("isolate is available on Linux only for now") && err.contains("nothing ran"), "{}\n{}{}", code, out, err);
    assert!(!dir.join("marker.txt").exists(), "el hijo corrió sin aislar");
}

/// En Linux el hijo lee y escribe lo delegado y nada más; el resultado dice lo que se impuso. Con un
/// kernel sin Landlock ABI 6 falla cerrado (y tampoco corre). Delegar escritura pide también
/// `file.read` (ronda 2, M1: para el kernel lo que se escribe también se lee).
#[cfg(target_os = "linux")]
#[test]
fn isolate_gives_the_child_only_what_is_delegated() {
    let dir = project("isolate-linux");
    for d in ["data", "out", "private"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(dir.join("data").join("a.txt"), "de-data\n").unwrap();
    std::fs::write(dir.join("private").join("s.txt"), "secreto").unwrap();
    let script = "cat data/a.txt; echo w > out/b.txt; cat private/s.txt 2>/dev/null || echo NO-PRIVATE; echo x > data/c.txt 2>/dev/null || echo NO-WRITE";
    let src = format!(
        "require exec(\"sh\")\nrequire file.read(\"./data/**\")\nrequire file.write(\"./out/**\")\nrequire file.read(\"./out/**\")\nrequire file.read(\"./private/**\")\n\
         let r be run(\"sh\", [\"-c\", {:?}], 10, {{\"isolate\": {{\"file.read\": \"./data/**\", \"file.write\": \"./out/**\"}}, \"max_memory_mb\": 256}})\n\
         print(r[\"stdout\"])\nprint(r[\"isolation\"][\"network\"])\nprint(r[\"isolation\"][\"max_memory_mb\"])\nprint(r[\"isolation\"][\"landlock_abi\"] >= 6)\n",
        script
    );
    std::fs::write(dir.join("l.syn"), src).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "l.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        assert!(code != 0 && !dir.join("out").join("b.txt").exists(), "{}", err);
        return;
    }
    assert_eq!((code, out.trim()), (0, "de-data\nNO-PRIVATE\nNO-WRITE\n\nnone\n256\ntrue"), "{}", err);
    assert_eq!(std::fs::read_to_string(dir.join("out").join("b.txt")).unwrap().trim(), "w");
    assert!(!dir.join("data").join("c.txt").exists());
}

/// Lo que el hijo aislado deja corriendo en segundo plano muere con él: `run` no se queda esperando
/// a un nieto que tiene las pipes (sin aislar, `run` esperaría los 30 s del `sleep`).
#[cfg(target_os = "linux")]
#[test]
fn isolate_ends_what_the_child_left_running() {
    let dir = project("isolate-tree");
    let src = "require exec(\"sh\")\nlet r be run(\"sh\", [\"-c\", \"sleep 30 & echo listo\"], 20, {\"isolate\": true})\nprint(r[\"stdout\"])\n";
    std::fs::write(dir.join("t.syn"), src).unwrap();
    let t0 = std::time::Instant::now();
    let (code, out, err) = synsema(&dir, &["run", "t.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!((code, out.trim()), (0, "listo"), "{}", err);
    assert!(t0.elapsed() < std::time::Duration::from_secs(15), "tardó {:?}", t0.elapsed());
}

/// Ronda 1 (A2): un hijo aislado con escritura en `./work` cambia `./work/sub` (la base de un grant
/// del programa) por un link a otro lado. Desde ahí ni el programa ni otro hijo siguen ese link:
/// sin el arreglo, los dos leían un secreto que ningún grant nombra. Lo que el hijo escribió se
/// sigue leyendo. Ronda 2: tampoco se sigue como programa a correr ni como `cwd` (N1), y el link se
/// puede borrar: borrar un link se juzga por dónde está, no por dónde lleva (B3). Ronda 3 (A1):
/// borrar `./work/sub/l` pasa por el link del hijo aunque un grant (`./work/sub/**`) se mueva con
/// él: no se borra `outside/l`.
#[cfg(target_os = "linux")]
#[test]
fn isolate_child_cannot_repoint_a_grant() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project("isolate-repoint");
    for d in ["work/sub", "outside"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(dir.join("outside").join("secret.txt"), "SECRETO").unwrap();
    std::os::unix::fs::symlink(dir.join("outside").join("secret.txt"), dir.join("outside").join("l")).unwrap();
    let tool = dir.join("outside").join("tool");
    std::fs::write(&tool, "#!/bin/sh\necho corre-el-de-afuera\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let w = dir.canonicalize().unwrap();
    let script = format!(
        "rm -rf work/sub && ln -s {w}/outside work/sub && ln -s {w}/outside/tool work/tool && echo hecho > work/out.txt && echo repuntado",
        w = w.display()
    );
    let src = [
        "require exec(\"sh\")",
        "require exec(\"cat\")",
        "require exec(\"./work/tool\")",
        "require file.write(\"./work/**\")",
        "require file.read(\"./work/**\")",
        "require file.read(\"./work/sub/**\")",
        "require file.write(\"./work/sub/**\")",
        &format!("let r be run(\"sh\", [\"-c\", {:?}], 10, {{\"isolate\": {{\"file.write\": \"./work/**\"}}}})", script),
        "print(r[\"stdout\"])",
        "print(read_file(\"./work/out.txt\"))",
        "try",
        "    print(read_file(\"./work/sub/secret.txt\"))",
        "recover e",
        "    print(\"PADRE: \" + e)",
        "try",
        "    print(run(\"cat\", [\"work/sub/secret.txt\"], 10, {\"isolate\": {\"file.read\": \"./work/sub/**\"}})[\"stdout\"])",
        "recover e",
        "    print(\"HIJO2: \" + e)",
        "try",
        "    print(run(\"./work/tool\", [], 10)[\"stdout\"])",
        "recover e",
        "    print(\"EXEC: \" + e)",
        "try",
        "    print(run(\"cat\", [\"secret.txt\"], 10, {\"cwd\": \"./work/sub\"})[\"stdout\"])",
        "recover e",
        "    print(\"CWD: \" + e)",
        "try",
        "    print(delete_file(\"./work/sub/l\"))",
        "recover e",
        "    print(\"DEL-AFUERA: \" + e)",
        "when delete_file(\"./work/sub\")",
        "    print(\"BORRADO\")",
        "when not file_exists(\"./work/sub\")",
        "    print(\"YA-NO-ESTA\")",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("r.syn"), src).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "r.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(!out.contains("SECRETO") && !out.contains("corre-el-de-afuera"), "el link del hijo llevó afuera:\n{}", out);
    assert!(out.contains("repuntado") && out.contains("hecho"), "{}", out);
    let want = "goes through a link inside";
    for who in ["PADRE: ", "HIJO2: ", "EXEC: ", "CWD: ", "DEL-AFUERA: "] {
        assert!(out.lines().any(|l| l.starts_with(who) && l.contains(want)), "{}: {}", who, out);
    }
    assert!(out.contains("BORRADO") && out.contains("YA-NO-ESTA"), "{}", out);
    assert!(dir.join("outside").join("secret.txt").exists(), "borrar el link no toca su destino");
    assert!(std::fs::symlink_metadata(dir.join("outside").join("l")).is_ok(), "el link de afuera no se borra por el link del hijo");
}

/// Ronda 3 (B1): arrancado con `SIGCHLD` ignorado (lo hereda de quien lo lanza),
/// un `run` aislado termina enseguida y con su código de salida, no al timeout ni con `-1`.
#[cfg(target_os = "linux")]
#[test]
fn isolate_with_sigchld_ignored_returns_at_once() {
    let dir = project("isolate-sigchld");
    let src = "require exec(\"sh\")\nlet r be run(\"sh\", [\"-c\", \"echo hola\"], 5, {\"isolate\": true})\nprint(r[\"exit_code\"])\nprint(r[\"stdout\"])\n";
    std::fs::write(dir.join("s.syn"), src).unwrap();
    let t0 = std::time::Instant::now();
    // Con `sh -c "trap '' CHLD; exec …"` synsema no lo recibía ignorado (sacar el arreglo no hacía
    // caer el test); con perl sí, como en la sonda del auditor.
    let o = std::process::Command::new("perl")
        .args(["-e", "$SIG{CHLD}=\"IGNORE\"; exec @ARGV", env!("CARGO_BIN_EXE_synsema"), "run", "s.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!(out.split_whitespace().collect::<Vec<_>>(), ["0", "hola"], "{}", err);
    assert!(t0.elapsed() < std::time::Duration::from_secs(2), "tardó {:?}", t0.elapsed());
}

/// Ronda 4 (A1): mientras un hijo con escritura en `./work` corre, otra tarea no toca `./work` (ni
/// lo delega a otro hijo): lo que juzga y después actúa por nombre no puede seguir un link que el
/// hijo pone en el medio. Cuando `run` vuelve, se toca como siempre.
#[cfg(target_os = "linux")]
#[test]
fn a_folder_in_use_by_an_isolated_child_is_not_touched_until_it_returns() {
    let dir = project("isolate-in-use");
    std::fs::create_dir_all(dir.join("work")).unwrap();
    std::fs::write(dir.join("work").join("x.txt"), "x").unwrap();
    let src = [
        "require exec(\"sh\")",
        "require time",
        "require file.write(\"./work/**\")",
        "require file.read(\"./work/**\")",
        "task t(n)",
        "    when n == 0",
        "        give run(\"sh\", [\"-c\", \"sleep 2; echo listo\"], 20, {\"isolate\": {\"file.write\": \"./work/**\"}})[\"stdout\"]",
        "    sleep(0.7)",
        "    let out be \"\"",
        "    try",
        "        set out to out + text(length(list_dir(\"./work\")))",
        "    recover e",
        "        set out to out + \"LIST: \" + e + \"\\n\"",
        "    try",
        "        set out to out + text(delete_file(\"./work/x.txt\"))",
        "    recover e",
        "        set out to out + \"DEL: \" + e + \"\\n\"",
        "    try",
        "        set out to out + run(\"sh\", [\"-c\", \"echo otro\"], 10, {\"isolate\": {\"file.write\": \"./work/**\"}})[\"stdout\"]",
        "    recover e",
        "        set out to out + \"OTRO: \" + e + \"\\n\"",
        "    give out",
        "each s in parallel_map(t, [0, 1])",
        "    print(s)",
        "print(\"DESPUES \" + text(delete_file(\"./work/x.txt\")))",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("u.syn"), src).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "u.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!(code, 0, "{}\n{}", out, err);
    let want = "is using right now";
    for who in ["LIST: ", "DEL: ", "OTRO: "] {
        assert!(out.lines().any(|l| l.starts_with(who) && l.contains(want)), "{}: {}", who, out);
    }
    assert!(out.contains("listo") && out.contains("DESPUES true"), "{}", out);
}

/// Ronda 5 (M2): dos `run` aislados en paralelo, cada uno leyendo todo el proyecto (`./**`, que
/// contiene la carpeta del otro) y escribiendo la suya, corren juntos: ninguno espera lo que el otro
/// juzgó mientras su hijo corre, y no se traban esperándose (antes, uno fallaba a los 10 s según el
/// orden de las claves).
#[cfg(target_os = "linux")]
#[test]
fn two_isolated_runs_reading_the_whole_project_run_together() {
    let dir = project("isolate-pair");
    std::fs::create_dir_all(dir.join("w0")).unwrap();
    std::fs::create_dir_all(dir.join("w1")).unwrap();
    let src = [
        "require exec(\"sh\")",
        "require file.read(\"./**\")",
        "require file.write(\"./w0/**\")",
        "require file.write(\"./w1/**\")",
        "task t(n)",
        "    let iso be {\"file.read\": \"./**\", \"file.write\": \"./w\" + text(n) + \"/**\"}",
        "    when n >= 2",
        "        set iso to {\"file.write\": \"./w\" + text(n - 2) + \"/**\", \"file.read\": \"./**\"}",
        "    try",
        "        give \"exit \" + text(run(\"sh\", [\"-c\", \"sleep 2\"], 30, {\"isolate\": iso})[\"exit_code\"])",
        "    recover e",
        "        give \"ERROR \" + e",
        "each s in parallel_map(t, [0, 1])",
        "    print(s)",
        "each s in parallel_map(t, [2, 3])",
        "    print(s)",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("p.syn"), src).unwrap();
    let t0 = std::time::Instant::now();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert_eq!(out.lines().filter(|l| *l == "exit 0").count(), 4, "{}\n{}", out, err);
    // Juntos: unos 2 s por par. De a uno (cada préstamo esperando al otro hijo) serían 8.
    assert!(t0.elapsed() < std::time::Duration::from_secs(7), "tardó {:?}", t0.elapsed());
}

/// Ronda 5 (M3) y ronda 6 (M2): lo que el hijo dejó corriendo y se mató no deja la carpeta prestada
/// por quedar zombie en su grupo: ni con synsema como quien recoge a los huérfanos (PID 1 de un
/// contenedor, o subreaper), ni con otro proceso que los adopta y no los recoge (un lanzador que
/// sólo espera a su hijo, como el de npm siendo PID 1). `run` vuelve enseguida y la carpeta se suelta.
/// Siendo synsema quien los adopta, además los recoge: no le quedan zombies mientras sigue corriendo.
///
/// v0.6.53 (1a): también sin carpetas de escritura (`{"isolate": true}`), donde no hay préstamo que
/// soltar: antes no se recogían nunca (`specs/v0.6.53-sondas/reap.out`).
#[cfg(target_os = "linux")]
#[test]
fn isolate_lets_the_folder_go_whoever_adopts_the_orphans() {
    use std::io::BufRead;
    let dir = project("isolate-reaper");
    std::fs::create_dir_all(dir.join("work")).unwrap();
    let src = [
        "require exec(\"sh\")",
        "require file.write(\"./work/**\")",
        "require file.read(\"./work/**\")",
        "let r be run(\"sh\", [\"-c\", \"sleep 30 & echo hijo\"], 10, {\"isolate\": {\"file.write\": \"./work/**\"}})",
        "print(r[\"stdout\"])",
        "print(\"lista \" + text(length(list_dir(\"./work\"))))",
        "sleep(2)",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("g.syn"), src).unwrap();
    let bare = [
        "require exec(\"sh\")",
        "let r be run(\"sh\", [\"-c\", \"sleep 30 & echo hijo\"], 10, {\"isolate\": true})",
        "print(r[\"stdout\"])",
        "print(\"lista 0\")",
        "sleep(2)",
        "",
    ]
    .join("\n");
    std::fs::write(dir.join("b.syn"), bare).unwrap();
    // PR_SET_CHILD_SUBREAPER (36) se conserva en `execve`: con `execv`, synsema arranca siendo
    // subreaper; con `Popen(…).wait()`, el subreaper es python, que no recoge a los que adopta.
    let wrappers = [
        ("import ctypes, os, sys; ctypes.CDLL(None).prctl(36, 1, 0, 0, 0); os.execv(sys.argv[1], sys.argv[1:])", true),
        ("import ctypes, subprocess, sys; ctypes.CDLL(None).prctl(36, 1, 0, 0, 0); sys.exit(subprocess.Popen(sys.argv[1:]).wait())", false),
    ];
    for ((w, synsema_adopts), file) in wrappers.into_iter().flat_map(|w| [(w, "g.syn"), (w, "b.syn")]) {
        let t0 = std::time::Instant::now();
        let mut child = std::process::Command::new("python3")
            .args(["-c", w, env!("CARGO_BIN_EXE_synsema"), "run", file])
            .current_dir(&dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut out = String::new();
        for l in lines.by_ref() {
            let l = l.unwrap();
            out.push_str(&l);
            out.push('\n');
            if l.starts_with("lista") {
                break;
            }
        }
        let elapsed = t0.elapsed();
        // Mientras synsema duerme: ¿le quedó algún hijo zombie? (con `execv`, el pid es el suyo)
        let zombies: Vec<String> = if synsema_adopts {
            std::fs::read_dir("/proc")
                .unwrap()
                .flatten()
                .filter_map(|e| std::fs::read_to_string(e.path().join("stat")).ok())
                .filter(|st| {
                    let rest = &st[st.rfind(')').map_or(0, |i| i + 1)..];
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    f.len() > 1 && f[0] == "Z" && f[1] == child.id().to_string()
                })
                .collect()
        } else {
            Vec::new()
        };
        let o = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        if err.contains("isolate needs Landlock ABI") {
            return;
        }
        assert!(out.contains("hijo") && out.contains("lista 0"), "{} {}: {}\n{}", w, file, out, err);
        assert!(elapsed < std::time::Duration::from_millis(1500), "{} {}: tardó {:?}", w, file, elapsed);
        assert!(zombies.is_empty(), "{} {}: synsema no recogió a los que adoptó: {:?}", w, file, zombies);
    }
}

/// Ronda 1 (N1): un ejecutable sin bit de ejecución da «not executable», no la pista del aislamiento.
#[cfg(target_os = "linux")]
#[test]
fn isolate_says_when_the_program_is_not_executable() {
    let dir = project("isolate-noexec");
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(dir.join("bin").join("tool"), "#!/bin/sh\necho hola\n").unwrap();
    let src = "require exec(\"./bin/tool\")\nrun(\"./bin/tool\", [], 10, {\"isolate\": true})\n";
    std::fs::write(dir.join("n.syn"), src).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "n.syn"], None);
    if err.contains("isolate needs Landlock ABI") {
        return;
    }
    assert!(
        code != 0 && err.contains("the file is not executable (chmod +x)") && !err.contains("sees only the system folders"),
        "{}",
        err
    );
}

/// Ronda 2 (B3): borrar un link borra la entrada y se juzga por dónde está, no por dónde lleva (como
/// `unlink`): v0.6.51 lo rechazaba si llevaba fuera del scope, y su mensaje pedía borrar el link. El
/// destino queda intacto. En Windows, una junction (se borra como carpeta).
#[test]
fn delete_file_removes_a_link_not_where_it_leads() {
    let dir = project("delete-link");
    for d in ["out", "outside"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(dir.join("outside").join("keep.txt"), "x").unwrap();
    let link = dir.join("out").join("link");
    #[cfg(windows)]
    {
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(dir.join("outside"))
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "mklink /J");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("outside"), &link).unwrap();
    std::fs::write(dir.join("d.syn"), "require file.write(\"./out/**\")\nprint(delete_file(\"./out/link\"))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "d.syn"], None);
    assert_eq!((code, out.trim()), (0, "true"), "{}", err);
    assert!(std::fs::symlink_metadata(&link).is_err(), "el link sigue");
    assert!(dir.join("outside").join("keep.txt").exists(), "borrar el link tocó su destino");
}
