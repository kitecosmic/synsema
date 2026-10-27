//! Tests del binario real para v0.6.50: A, un módulo no ve los globales de quien lo importa (regla y
//! tabla de casos en `specs/v0.6.50-a-modelo.md`; cada test nombra sus filas).

use super::v0646_tanda_e_cli::{project, synsema};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const HINT: &str = "is a name of the program that imports this module";

/// `synsema <args>` con un plazo: un binario que queda colgado (un agente que nadie detiene) se mata
/// por su handle y da `None`, en vez de colgar el test.
fn synsema_within(dir: &PathBuf, args: &[&str], secs: u64) -> Option<(i32, String, String)> {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn synsema");
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if t0.elapsed() > Duration::from_secs(secs) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let o = child.wait_with_output().unwrap();
    Some((o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned()))
}

/// `lib.syn` y `main.syn` en un proyecto nuevo; corre `synsema <cmd> main.syn`.
fn modules(tag: &str, lib: &str, main: &str, cmd: &str) -> (i32, String, String) {
    let dir = project(tag);
    std::fs::write(dir.join("lib.syn"), lib).unwrap();
    std::fs::write(dir.join("main.syn"), main).unwrap();
    synsema(&dir, &[cmd, "main.syn"], None)
}

/// Filas 1, 2 y 22: el módulo no lee un global del programa, definido antes o después del `use`; el
/// suyo, sí.
#[test]
fn a_module_does_not_read_the_importer_globals() {
    let lib = "export task cobrar(n)\n    give n * TASA\n";
    // 1) Antes del `use`.
    let (code, out, err) = modules("a-r1", lib, "let TASA be 2\nuse \"./lib.syn\" as lib\nprint(lib.cobrar(10))\n", "run");
    assert!(code != 0 && !out.contains("20"), "{}", out);
    assert!(err.contains("Undefined variable: 'TASA'") && err.contains(HINT), "{}", err);
    // 2) Después del `use`, leído al llamar.
    let (code, out, err) = modules("a-r2", lib, "use \"./lib.syn\" as lib\nlet TASA be 2\nprint(lib.cobrar(10))\n", "run");
    assert!(code != 0 && !out.contains("20"), "{}", out);
    assert!(err.contains("Undefined variable: 'TASA'") && err.contains(HINT), "{}", err);
    // Sin el global en el programa, el error de siempre (sin la pista).
    let (code, _, err) = modules("a-r2b", lib, "use \"./lib.syn\" as lib\nprint(lib.cobrar(10))\n", "run");
    assert!(code != 0 && err.contains("Undefined variable: 'TASA'") && !err.contains(HINT), "{}", err);
    // 22) El módulo define el suyo: gana el suyo.
    let lib22 = "let TASA be 3\nexport task cobrar(n)\n    give n * TASA\n";
    let (code, out, err) = modules("a-r22", lib22, "let TASA be 2\nuse \"./lib.syn\" as lib\nprint(lib.cobrar(10))\n", "run");
    assert_eq!((code, out.trim()), (0, "30"), "{}", err);
}

/// Fila 3: el módulo no escribe un global del programa.
#[test]
fn a_module_does_not_write_the_importer_globals() {
    let lib = "export task contar()\n    set N to N + 1\n";
    let (code, out, err) = modules("a-r3", lib, "let N be 0\nuse \"./lib.syn\" as lib\ntry\n    lib.contar()\nrecover e\n    print(\"error\")\nprint(N)\n", "run");
    assert_eq!((code, out.trim()), (0, "error\n0"), "{}", err);
    // Sin `try`: el texto dice por qué.
    let (code, _, err) = modules("a-r3b", "export task poner()\n    set N to 5\n", "let N be 0\nuse \"./lib.syn\" as lib\nlib.poner()\n", "run");
    assert!(code != 0 && err.contains("Cannot set undefined variable: 'N'") && err.contains(HINT), "{}", err);
}

/// Filas 4–6: los builtins y las constantes sí; un builtin que el programa religó, el builtin.
#[test]
fn a_module_sees_the_builtins_even_if_the_program_rebinds_one() {
    let lib = "export task f(x)\n    give upper(x) + \" \" + text(length([1, 2])) + \" \" + text(round(pi))\n";
    let (code, out, err) = modules("a-r4", lib, "use \"./lib.syn\" as lib\nprint(lib.f(\"a\"))\n", "run");
    assert_eq!((code, out.trim()), (0, "A 2 3"), "{}", err);
    // 5) El programa liga `upper` a otra cosa, antes y después del `use`.
    let (code, out, err) = modules("a-r5", lib, "let upper be 3\nuse \"./lib.syn\" as lib\nprint(lib.f(\"a\"))\n", "run");
    assert_eq!((code, out.trim()), (0, "A 2 3"), "{}", err);
    let (code, out, err) = modules("a-r5b", lib, "use \"./lib.syn\" as lib\nlet upper be 3\nprint(lib.f(\"a\"))\n", "run");
    assert_eq!((code, out.trim()), (0, "A 2 3"), "{}", err);
}

/// Fila 9: un callback del programa cierra sobre el programa.
#[test]
fn a_callback_from_the_program_keeps_its_own_scope() {
    let lib = "export task aplicar(f, x)\n    give f(x)\n";
    let (code, out, err) = modules("a-r9", lib, "let TASA be 2\nuse \"./lib.syn\" as lib\nprint(lib.aplicar((n) => n * TASA, 10))\n", "run");
    assert_eq!((code, out.trim()), (0, "20"), "{}", err);
}

/// Fila 10: un módulo que importa otro no le presta sus nombres.
#[test]
fn a_module_does_not_lend_its_names_to_the_modules_it_imports() {
    let dir = project("a-r10");
    std::fs::write(dir.join("b.syn"), "export task g()\n    give DE_A\n").unwrap();
    std::fs::write(dir.join("a.syn"), "let DE_A be 1\nuse \"./b.syn\" as b\nexport task f()\n    give b.g()\n").unwrap();
    std::fs::write(dir.join("main.syn"), "use \"./a.syn\" as a\nprint(a.f())\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "main.syn"], None);
    assert!(code != 0 && !out.contains('1'), "{}", out);
    assert!(err.contains("Undefined variable: 'DE_A'"), "{}", err);
}

/// Fila 18: `synsema test`, igual que `run`.
#[test]
fn a_test_block_sees_the_same_rule() {
    let lib = "export task cobrar(n)\n    give n * TASA\n";
    let main = "let TASA be 2\nuse \"./lib.syn\" as lib\ntest \"cobra\"\n    assert_eq(lib.cobrar(10), 20)\n";
    let (code, out, err) = modules("a-r18", lib, main, "test");
    assert!(code != 0, "{}\n{}", out, err);
    assert!(format!("{}{}", out, err).contains("Undefined variable: 'TASA'"), "{}\n{}", out, err);
}

/// Fila 14: `parallel_map` con una task de módulo.
#[test]
fn parallel_map_rebuilds_the_module_without_the_program_globals() {
    let lib = "export task por(n)\n    give n * TASA\nexport task doble(n)\n    give n * 2 + length([1])\n";
    let (code, out, err) = modules("a-r14", lib, "let TASA be 2\nuse \"./lib.syn\" as lib\nprint(parallel_map(lib.doble, [1, 2]))\nprint(parallel_map(lib.por, [1, 2]))\n", "run");
    assert!(out.contains("[3, 5]"), "{}\n{}", out, err);
    assert!(code != 0 && err.contains("Undefined variable: 'TASA'"), "{}\n{}", out, err);
}

/// Fila 14b: un módulo que no es global (el `use` dentro de una task) llega al worker con la task.
#[test]
fn parallel_map_rebuilds_a_local_module_without_the_program_globals() {
    let lib = "export task por(n)
    give n * TASA
export task doble(n)
    give n * 2 + length([1])
";
    let main = "let TASA be 2
task correr(nombre)
    use \"./lib.syn\" as l
    when nombre == \"doble\"
        give parallel_map(l.doble, [1, 2])
    give parallel_map(l.por, [1, 2])
print(correr(\"doble\"))
print(correr(\"por\"))
";
    let (code, out, err) = modules("a-r14b", lib, main, "run");
    assert!(out.contains("[3, 5]"), "{}
{}", out, err);
    assert!(code != 0 && err.contains("Undefined variable: 'TASA'"), "{}
{}", out, err);
}

/// Fila 15: un agente con swarm que llama una task de módulo.
#[test]
fn an_agent_rebuilds_the_module_without_the_program_globals() {
    let lib = "export task por(n)\n    give n * TASA\nexport task doble(n)\n    give upper(\"a\") + text(n * 2)\n";
    let main = "let TASA be 2\nuse \"./lib.syn\" as lib\nagent A\n    print(lib.doble(4))\n    print(lib.por(4))\nspawn A\n";
    let (_, out, err) = modules("a-r15", lib, main, "run");
    assert!(out.contains("A8"), "{}\n{}", out, err);
    assert!(!out.lines().any(|l| l.trim() == "8"), "{}", out);
    assert!(err.contains("Undefined variable: 'TASA'"), "{}\n{}", out, err);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http_get(port: u16, path: &str) -> Option<String> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path).as_bytes()).ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    Some(buf)
}

/// Levanta `main.syn` (con `{p}` por el puerto) y pide cada ruta.
fn serve_get(dir: &PathBuf, main: &str, paths: &[&str]) -> Vec<String> {
    serve_get_with(dir, &[], main, paths)
}

/// `serve_get` con flags antes de `main.syn` (`--trusted t=t.syn`).
fn serve_get_with(dir: &PathBuf, flags: &[&str], main: &str, paths: &[&str]) -> Vec<String> {
    let port = free_port();
    std::fs::write(dir.join("main.syn"), main.replace("{p}", &port.to_string())).unwrap();
    let mut args = vec!["serve"];
    args.extend_from_slice(flags);
    args.push("main.syn");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(&args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn synsema serve");
    let t0 = Instant::now();
    let mut ready = false;
    while t0.elapsed() < Duration::from_secs(30) {
        if http_get(port, "/ping").is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let got = paths.iter().map(|p| if ready { http_get(port, p).unwrap_or_default() } else { String::new() }).collect();
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready, "el server no levantó");
    got
}

/// Filas 12, 13, 16 y 17: bajo `serve`, la misma regla que en `run`.
#[test]
fn serve_rebuilds_the_module_without_the_program_globals() {
    let dir = project("a-r12");
    std::fs::write(
        dir.join("lib.syn"),
        "task privado()\n    give \"p\"\nexport task por(n)\n    give n * TASA\nexport task bien(n)\n    give upper(\"a\") + text(n)\nexport routes rutas\n    route \"GET /m/ok\"\n        give privado() + text(length(text(request)) > 0)\n    route \"GET /m/global\"\n        give text(TASA)\n",
    )
    .unwrap();
    let main = "require serve({p})\nlet TASA be 2\nuse \"./lib.syn\" as lib\nserve on {p}\n    mount lib.rutas\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /bien\"\n        give lib.bien(4)\n    route \"GET /por\"\n        give text(lib.por(4))\n";
    let r = serve_get(&dir, main, &["/bien", "/por", "/m/ok", "/m/global"]);
    // 13) builtin dentro de la task del módulo.
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].contains("A4"), "{}", r[0]);
    // 12) el global del programa no se ve.
    assert!(!r[1].starts_with("HTTP/1.1 200") && !r[1].contains("\"8\""), "{}", r[1]);
    // 16) ruta montada: su helper privado y `request`.
    assert!(r[2].starts_with("HTTP/1.1 200") && r[2].contains("ptrue"), "{}", r[2]);
    // 17) …pero no el global del programa.
    assert!(!r[3].starts_with("HTTP/1.1 200"), "{}", r[3]);
}

/// Fila 24: bajo `serve`, un mapa de callbacks que armó una task del módulo cierra sobre el módulo
/// (antes de v0.6.50 se reconstruía colgado del global del request y no veía al módulo).
#[test]
fn serve_rebuilds_a_module_map_of_callbacks_on_the_module() {
    let dir = project("a-r24");
    std::fs::write(
        dir.join("lib.syn"),
        "task ayuda()
    give 40
task armar()
    give {\"f\": (x) => x + ayuda()}
export let M be armar()
",
    )
    .unwrap();
    let main = "require serve({p})
use \"./lib.syn\" as lib
serve on {p}
    route \"GET /ping\"
        give \"ok\"
    route \"GET /f\"
        give text(lib.M.f(2))
";
    let r = serve_get(&dir, main, &["/f"]);
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].ends_with("\"42\""), "{}", r[0]);
}

// =========================================================
// B — una tool de confianza en otro intérprete (`specs/v0.6.50-a-modelo.md` § B)
// =========================================================

const TOOL: &str = "let ESTADO be {\"n\": 0}\nprint(\"carga\")\nexport task f(x)\n    give upper(x) + text(ESTADO[\"n\"])\nexport task subir()\n    set ESTADO[\"n\"] to ESTADO[\"n\"] + 1\n    give ESTADO[\"n\"]\nexport task global()\n    give PROG\nexport task llamar(g)\n    give g(1)\nexport task leer()\n    require file.read(\"./d.txt\")\n    give read_file(\"./d.txt\")\n";

/// Filas B1–B5, B8 y B9: bajo `serve`, la tool de cada worker es la del programa.
#[test]
fn serve_runs_a_trusted_tool_in_its_own_scope() {
    let dir = project("b-serve");
    std::fs::write(dir.join("t.syn"), TOOL).unwrap();
    std::fs::write(dir.join("d.txt"), "secreto de la tool").unwrap();
    let main = "require serve({p})\nlet PROG be 1\nuse \"trusted:t\" as t\nprint(t.subir())\ntask mia(x)\n    give x\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /f\"\n        give t.f(\"a\")\n    route \"GET /global\"\n        give t.global()\n    route \"GET /set\"\n        set t.X to 1\n        give \"puso\"\n    route \"GET /deputy\"\n        give t.llamar(mia)\n    route \"GET /use\"\n        use \"trusted:t\" as t2\n        give t2.f(\"u\")\n    route \"GET /leer\"\n        give t.leer()\n    route \"GET /directo\"\n        give read_file(\"./d.txt\")\n";
    let r = serve_get_with(
        &dir,
        &["--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.read"],
        main,
        &["/f", "/global", "/set", "/deputy", "/use", "/leer", "/directo"],
    );
    // B1 + B2: la tool usa sus builtins y su estado (el nivel superior del programa subió `n`).
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].ends_with("\"A1\""), "{}", r[0]);
    // B3: no ve los globales del programa.
    assert!(!r[1].starts_with("HTTP/1.1 200") && r[1].contains("Undefined variable: 'PROG'"), "{}", r[1]);
    // B4: la vista no se escribe.
    assert!(!r[2].starts_with("HTTP/1.1 200") && r[2].contains("trusted module has no export 'X'"), "{}", r[2]);
    // B5: el confused deputy.
    assert!(!r[3].starts_with("HTTP/1.1 200") && r[3].contains("a trusted tool takes data, not code"), "{}", r[3]);
    // B9: `use` en una ruta: la misma tool, con su estado.
    assert!(r[4].starts_with("HTTP/1.1 200") && r[4].ends_with("\"U1\""), "{}", r[4]);
    // B8: la tool lee con lo suyo; el programa, sin `require file`, no.
    assert!(r[5].starts_with("HTTP/1.1 200") && r[5].contains("secreto de la tool"), "{}", r[5]);
    assert!(!r[6].starts_with("HTTP/1.1 200") && !r[6].contains("secreto de la tool"), "{}", r[6]);
}

/// B9, el nivel superior de la tool no vuelve a correr en el worker.
#[test]
fn serve_does_not_run_the_tool_top_level_again() {
    let dir = project("b-once");
    std::fs::write(dir.join("t.syn"), TOOL).unwrap();
    let port = free_port();
    std::fs::write(dir.join("main.syn"), format!("require serve({p})\nuse \"trusted:t\" as t\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /use\"\n        use \"trusted:t\" as t2\n        give t2.f(\"u\")\n", p = port)).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "--trusted", "t=t.syn", "main.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn synsema serve");
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(30) && !http_get(port, "/ping").is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
        std::thread::sleep(Duration::from_millis(100));
    }
    for _ in 0..3 {
        let r = http_get(port, "/use").unwrap_or_default();
        assert!(r.ends_with("\"U0\""), "{}", r);
    }
    let _ = child.kill();
    let mut out = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut out);
    let _ = child.wait();
    assert_eq!(out.matches("carga").count(), 1, "{}", out);
}

/// Filas B6–B8: bajo `run`, `parallel_map` y un agente llevan la tool.
#[test]
fn parallel_map_and_agents_carry_a_trusted_tool() {
    let dir = project("b-run");
    std::fs::write(dir.join("t.syn"), TOOL).unwrap();
    std::fs::write(dir.join("d.txt"), "secreto de la tool").unwrap();
    std::fs::write(
        dir.join("app.syn"),
        "use \"trusted:t\" as t\nprint(t.subir())\nprint(parallel_map(t.f, [\"b\", \"c\"]))\nprint(parallel_map((x) => t.leer(), [1]))\nagent A\n    print(t.f(\"d\"))\n    print(t.leer())\nspawn A\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.read", "app.syn"], None);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(out.contains("[\"B1\", \"C1\"]") && out.contains("D1"), "{}", out);
    assert_eq!(out.matches("secreto de la tool").count(), 2, "{}", out);
    // El programa, sin `require file`, no lee: la tool lee con lo suyo también en el worker y en el agente.
    std::fs::write(dir.join("app.syn"), "use \"trusted:t\" as t\nprint(parallel_map((x) => read_file(\"./d.txt\"), [1]))\n").unwrap();
    let (code, out, _) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.read", "app.syn"], None);
    assert!(code != 0 && !out.contains("secreto"), "{}", out);
}

/// Fila B10: con etiquetas, la tool reconstruida recibe el argumento con su etiqueta (como la que
/// envuelve `load_trusted_module`) y declasifica lo que su task declara.
#[test]
fn serve_hands_a_trusted_tool_the_labelled_argument() {
    let dir = project("b-labels");
    std::fs::write(dir.join("t.syn"), "export task nombre(c)\n    require declassify(\"customers\")\n    give declassify(c.name, \"the name is public\")\n").unwrap();
    let main = "require serve({p})\nuse \"trusted:t\" as t\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /n\"\n        let c be private({\"name\": \"Ana\"}, \"customers\")\n        give t.nombre(c)\n";
    let r = serve_get_with(
        &dir,
        &["--labels", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,declassify=customers"],
        main,
        &["/n"],
    );
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].ends_with("\"Ana\""), "{}", r[0]);
}

/// `RunResult`: el informe JSON publica `steps` de la corrida, y `null` si tocó datos privados (T5).
#[test]
fn the_json_report_takes_steps_from_its_run() {
    let dir = project("rr-steps");
    std::fs::write(dir.join("pub.syn"), "print(1 + 1)\n").unwrap();
    std::fs::write(dir.join("priv.syn"), "let x be private(3, \"app\")\nwhen x > 1\n    let y be 1\nprint(\"ok\")\n").unwrap();
    let report = |args: &[&str]| -> serde_json::Value {
        let (_, out, err) = synsema(&dir, args, None);
        serde_json::from_str(out.trim()).unwrap_or_else(|_| panic!("{} {}", out, err))
    };
    let j = report(&["run", "--format", "json", "pub.syn"]);
    assert!(j["steps"].as_u64().is_some_and(|n| n > 0), "{}", j);
    let j = report(&["run", "--labels", "--format", "json", "priv.syn"]);
    assert_eq!(j["ok"], true, "{}", j);
    assert!(j["steps"].is_null(), "{}", j);
}

/// `RunResult`: si un agente se cortó por etiquetas, la corrida termina con ese corte aunque el
/// principal pida `exit(0)` después: el código de un corte, no el de `exit` (sería el dato).
#[test]
fn an_agent_cut_wins_over_a_later_exit() {
    let dir = project("rr-cut");
    std::fs::write(
        dir.join("c.syn"),
        "require time\nlet t be private(\"7\", \"app\")\nagent A\n    when t == \"7\"\n        print(\"x\")\nspawn A\nsleep(1)\nexit(0)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "c.syn"], None);
    assert_eq!(code, 1, "{}{}", out, err);
    assert!(!out.contains('x'), "{}", out);
}

/// C4/C5: con un programa por proceso, el recibo trae el sha de ese programa.
#[test]
fn a_receipt_carries_the_sha_of_its_program() {
    let dir = project("rr-receipt");
    let src = "print(receipt()[\"credentialSubject\"][\"program_sha\"])\n";
    std::fs::write(dir.join("r.syn"), src).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "r.syn"], None);
    assert_eq!(code, 0, "{}", err);
    let want = synsema_core::bytesutil::hex_encode(&synsema_stdlib::attest::program_sha_of(src, "r.syn").unwrap());
    assert_eq!(out.trim(), want);
}

// =========================================================
// D: los templates de una tool de confianza (`--trusted-templates`)
// =========================================================

/// La tool de D: renderiza `r.html` con el dato privado y declasifica lo que el template muestra.
const TPL_TOOL: &str = "export task recibo(c)\n    require declassify(\"clientes\")\n    let html be render(\"r.html\", {\"c\": c})\n    give declassify(html, \"el template muestra los ultimos 4\")\nexport task hola()\n    give \"hola\"\n";

fn tpl_project(tag: &str) -> PathBuf {
    let dir = project(tag);
    std::fs::create_dir_all(dir.join("tpl/parts")).unwrap();
    std::fs::write(dir.join("tpl/r.html"), "{ layout \"l.html\" }<p>{upper(c.nombre)} **** {slice(c.tarjeta, 15)}</p>{ include \"parts/pie.html\" }").unwrap();
    std::fs::write(dir.join("tpl/l.html"), "<main>{ slot }</main>").unwrap();
    std::fs::write(dir.join("tpl/parts/pie.html"), "<i>pie</i>").unwrap();
    // El del programa, en su directorio de trabajo: la tool no lo lee.
    std::fs::write(dir.join("r.html"), "<p>{c.nombre} {c.tarjeta}</p>").unwrap();
    std::fs::write(dir.join("propio.html"), "<b>{x}</b>").unwrap();
    std::fs::write(dir.join("h.syn"), TPL_TOOL).unwrap();
    dir
}

const TPL_FLAGS: [&str; 8] = [
    "--trusted",
    "h=h.syn",
    "--trusted-templates",
    "h=tpl",
    "--trusted-cap-set",
    "stdout,declassify=clientes",
    "--cap-set",
    "stdout,file.read,file.write",
];

/// Filas D1–D6 y D10: la tool renderiza los templates que le dio el host (con su layout y su
/// include), no el `r.html` del programa ni lo que el programa escribe en `tpl/` después del
/// arranque; no pide `file.read`, y `{upper(…)}` es el builtin aunque el programa defina `upper`.
#[test]
fn a_trusted_tool_renders_the_templates_the_host_gave_it() {
    let dir = tpl_project("d-render");
    std::fs::write(
        dir.join("app.syn"),
        "require file.read(\"propio.html\")\nrequire file.write(\"tpl/r.html\")\ntask upper(s)\n    give \"FUGA\"\nlet c be private({\"nombre\": \"Ana\", \"tarjeta\": \"4111-1111-1111-1111\"}, \"clientes\")\nprint(render(\"propio.html\", {\"x\": \"antes\"}))\nwrite_file(\"tpl/r.html\", \"<p>{c.tarjeta}</p>\")\nuse \"trusted:h\" as h\nprint(h.recibo(c))\nprint(render(\"propio.html\", {\"x\": \"despues\"}))\n",
    )
    .unwrap();
    let mut a = vec!["run", "--labels"];
    a.extend_from_slice(&TPL_FLAGS);
    a.push("app.syn");
    let (code, out, err) = synsema(&dir, &a, None);
    assert_eq!(code, 0, "{} {}", out, err);
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 3, "{}", out);
    assert!(lines[0].contains("<b>antes</b>") && lines[2].contains("<b>despues</b>"), "{}", out);
    assert!(lines[1].contains("body: <main><p>ANA **** 1111</p><i>pie</i></main>"), "{}", out);
    assert!(!out.contains("FUGA") && !out.contains("4111-"), "{}", out);
}

/// Filas D7, D8, D9 y D11: lo que no está en el conjunto es error; sin templates del host, un
/// `render` literal falla al cargar la tool (antes de cualquier dato) y uno no literal al llamar,
/// los dos con el flag en el texto; `--trusted-templates` sin su `--trusted` es error de uso.
#[test]
fn a_trusted_tool_without_its_templates_says_how_to_give_them() {
    let dir = tpl_project("d-errors");
    let run = |app: &str, flags: &[&str]| {
        std::fs::write(dir.join("app.syn"), app).unwrap();
        let mut a = vec!["run"];
        a.extend_from_slice(flags);
        a.push("app.syn");
        synsema(&dir, &a, None)
    };
    // D8: literal y sin templates: falla en el `use`, con el dato todavía público.
    let (code, out, err) = run("print(\"antes\")\nuse \"trusted:h\" as h\nprint(h.hola())\n", &["--trusted", "h=h.syn"]);
    assert!(code != 0 && out.contains("antes") && !out.contains("hola"), "{} {}", out, err);
    assert!(err.contains("the trusted tool 'h' has no templates ('r.html')") && err.contains("--trusted-templates h=<dir>"), "{}", err);
    assert!(err.contains("trusted:h:3"), "la línea del render: {}", err);
    // D9: no literal, sin templates: al llamar.
    std::fs::write(dir.join("g.syn"), "export task pagina(n)\n    give render(n, {})\n").unwrap();
    let (code, _, err) = run("use \"trusted:g\" as g\nprint(g.pagina(\"r.html\"))\n", &["--trusted", "g=g.syn"]);
    assert!(code != 0 && err.contains("the trusted tool 'g' has no templates ('r.html')"), "{}", err);
    // D7: uno que existe en el directorio de trabajo pero no en el conjunto.
    let (code, _, err) = run("use \"trusted:g\" as g\nprint(g.pagina(\"propio.html\"))\n", &["--trusted", "g=g.syn", "--trusted-templates", "g=tpl"]);
    assert!(code != 0 && err.contains("template 'propio.html' is not among the templates the host gave the trusted tool 'g'"), "{}", err);
    // Y un `../` no sale del conjunto.
    let (code, _, err) = run("use \"trusted:g\" as g\nprint(g.pagina(\"../r.html\"))\n", &["--trusted", "g=g.syn", "--trusted-templates", "g=tpl"]);
    assert!(code != 0 && err.contains("is not among the templates"), "{}", err);
    // D11.
    let (code, _, err) = run("print(1)\n", &["--trusted", "g=g.syn", "--trusted-templates", "x=tpl"]);
    assert!(code == 2 && err.contains("--trusted-templates x: there is no --trusted x="), "{}", err);
}

/// Fila D12: bajo `serve`, cada worker tiene los templates de la tool.
#[test]
fn serve_gives_a_trusted_tool_its_templates() {
    let dir = tpl_project("d-serve");
    let main = "require serve({p})\nuse \"trusted:h\" as h\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /r\"\n        give h.recibo({\"nombre\": \"eva\", \"tarjeta\": \"0000-0000-0000-4242\"})\n";
    let r = serve_get_with(&dir, &["--trusted", "h=h.syn", "--trusted-templates", "h=tpl"], main, &["/r", "/r"]);
    for x in &r {
        assert!(x.starts_with("HTTP/1.1 200") && x.contains("EVA **** 4242"), "{}", x);
    }
}

/// N3: en un template, `{upper(c.nombre)}` y `{c.nombre}` con `c` privado escriben los dos el valor,
/// y el HTML sale con la etiqueta (antes el primero escribía el marcador `private(…)`). Un global
/// privado que el template lee también le deja su etiqueta.
#[test]
fn a_template_writes_a_private_value_and_the_html_carries_its_label() {
    let dir = project("n3");
    std::fs::write(dir.join("n3.html"), "<p>{upper(c.nombre)} / {c.nombre}</p>").unwrap();
    std::fs::write(dir.join("g.html"), "<p>{SECRETO}</p>").unwrap();
    std::fs::write(
        dir.join("p.syn"),
        "require file.read(\"*.html\")\nlet c be private({\"nombre\": \"ana\"}, \"clientes\")\nlet h be render(\"n3.html\", {\"c\": c})\nprint(declassify(h, \"prueba\"))\nlet SECRETO be private(\"tope\", \"otro\")\nlet g be render(\"g.html\", {})\nprint(g)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert!(lines[0].contains("body: <p>ANA / ana</p>"), "{}", out);
    assert!(lines[1].starts_with("private("), "el HTML lleva la etiqueta del global: {}", out);
    assert!(!out.contains("tope"), "{}", out);
}

/// Ronda 4 de v0.6.49, B1: con datos privados, el programa ve el texto fijo de un corte, el
/// operador el redactado y el auditor (el sobre del recibo) el porqué real: antes era
/// `private(clientes)` también en el sobre.
#[test]
fn a_render_error_with_private_data_tells_the_auditor_why() {
    let dir = tpl_project("d-b1");
    std::fs::write(dir.join("g.syn"), "export task pagina(c, n)\n    give render(n, {\"c\": c})\n").unwrap();
    std::fs::write(
        dir.join("app.syn"),
        "let c be private({\"nombre\": \"Ana\"}, \"clientes\")\nuse \"trusted:g\" as g\nprint(g.pagina(c, \"noesta.html\"))\n",
    )
    .unwrap();
    let (sk, pk) = super::v0646_tanda_e_cli::auditor_keys();
    let args = [
        "run", "--labels", "--cap-set", "stdout", "--auditor", &pk, "--receipt", "r.json", "--trusted", "g=g.syn", "--trusted-templates", "g=tpl",
        "app.syn",
    ];
    let (code, _, err) = synsema(&dir, &args, None);
    assert!(code != 0 && !err.contains("noesta"), "{}", err);
    let r: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("r.json")).unwrap()).unwrap();
    let opened = super::v0646_tanda_e_cli::open_receipt(&r, &sk);
    assert!(opened.to_string().contains("template 'noesta.html' is not among the templates"), "{}", opened);
}

/// Fila D1 en el nivel superior de la tool: también resuelve contra sus templates (no el disco).
#[test]
fn a_trusted_tool_renders_at_its_top_level_from_its_templates() {
    let dir = tpl_project("d-top");
    std::fs::write(dir.join("t.syn"), "let PAGINA be render(\"parts/pie.html\", {})\nexport task pagina()\n    give text(PAGINA)\n").unwrap();
    std::fs::create_dir_all(dir.join("parts")).unwrap();
    std::fs::write(dir.join("parts/pie.html"), "<i>DEL-PROGRAMA</i>").unwrap();
    std::fs::write(dir.join("app.syn"), "use \"trusted:t\" as t\nprint(t.pagina())\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-templates", "t=tpl", "app.syn"], None);
    assert!(code == 0 && out.contains("<i>pie</i>") && !out.contains("DEL-PROGRAMA"), "{} {}", out, err);
}

// =========================================================
// E: textos y la espera de los agentes (ítem 3; tabla en `specs/v0.6.50-a-modelo.md` § E)
// =========================================================

/// Filas E1–E3: `llm=P`/`judge=P` sin `@` avisa al arrancar; con el provider, o sin principal, no.
#[test]
fn a_ceiling_llm_item_without_a_provider_warns_at_start() {
    let dir = project("e-a");
    std::fs::write(dir.join("p.syn"), "print(\"ok\")\n").unwrap();
    std::fs::write(dir.join("t.syn"), "export task f()\n    give 1\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--cap-set", "stdout,llm=clientes", "p.syn"], None);
    assert!(code == 0 && out.contains("ok"), "{}", err);
    assert!(err.contains("warning: --cap-set llm=clientes:") && err.contains("llm=clientes@<provider host>"), "{}", err);
    for quiet in ["stdout,llm=clientes@api.x", "stdout,llm", "stdout,llm=*@*"] {
        let (code, _, err) = synsema(&dir, &["run", "--cap-set", quiet, "p.syn"], None);
        assert!(code == 0 && !err.contains("warning"), "{}: {}", quiet, err);
    }
    let (_, _, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", "judge=P", "p.syn"], None);
    assert!(err.contains("warning: --trusted-cap-set judge=P:"), "{}", err);
}

/// Filas E4–E6: el `require` que falta va donde corre el código.
#[test]
fn a_missing_require_points_to_where_the_code_runs() {
    let dir = project("e-b");
    std::fs::write(dir.join("x.txt"), "hola").unwrap();
    // E4: en un agente, a su cuerpo.
    std::fs::write(dir.join("a.syn"), "agent Lector\n    print(read_file(\"x.txt\"))\nspawn Lector\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "a.syn"], None);
    assert!(code != 0 && err.contains("to the body of agent Lector") && !err.contains("preamble"), "{}", err);
    // E5: un worker de `parallel_map` nombra los dos lugares, una vez cada uno.
    std::fs::write(
        dir.join("b.syn"),
        "task leer(f)\n    give read_file(f)\nagent Lector\n    print(parallel_map(leer, [\"x.txt\"]))\nspawn Lector\n",
    )
    .unwrap();
    let (code, _, err) = synsema(&dir, &["run", "b.syn"], None);
    assert!(code != 0 && err.contains("to the program's preamble, or to the body of the agent that runs this code"), "{}", err);
    assert_eq!(err.matches("preamble").count(), 1, "{}", err);
    assert_eq!(err.matches("the body of the agent that runs this code").count(), 1, "{}", err);
    // E6: el programa, a su preámbulo, como siempre.
    std::fs::write(dir.join("c.syn"), "print(read_file(\"x.txt\"))\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "c.syn"], None);
    assert!(code != 0 && err.contains("to the program's preamble (or to the importing file"), "{}", err);
}

/// Filas E7–E9: el `require` de una task que la tool no exporta avisa al cargar, una vez.
#[test]
fn a_require_in_a_task_the_tool_does_not_export_warns_at_load() {
    let dir = project("e-c");
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nuse \"trusted:t\" as t2\nprint(t.pub(1))\n").unwrap();
    std::fs::write(
        dir.join("t.syn"),
        "task helper(c)\n    require time\n    give c\nexport task pub(c)\n    give helper(c)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "p.syn"], None);
    assert!(code == 0 && out.contains('1'), "{}", err);
    let w = "warning: trusted:t:2: `require time` in task helper grants nothing";
    assert_eq!(err.matches(w).count(), 1, "{}", err);
    // E8 y E9: exportada (directo o con `export let`), sin aviso.
    for src in [
        "task helper(c)\n    require time\n    give c\nexport let pub be helper\n",
        "export task pub(c)\n    require time\n    give c\n",
    ] {
        std::fs::write(dir.join("t.syn"), src).unwrap();
        let (code, _, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "p.syn"], None);
        assert!(code == 0 && !err.contains("grants nothing"), "{}: {}", src, err);
    }
}

/// Fila E10: un agente lanzado por otro que termina antes: su salida sale.
#[test]
fn the_run_waits_for_an_agent_another_agent_spawned() {
    let dir = project("e-d1");
    std::fs::write(
        dir.join("p.syn"),
        "agent Pub\n    agent Sub\n        require time\n        sleep(0.5)\n        print(\"desde Sub\")\n    spawn Sub\nspawn Pub\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    assert!(code == 0 && out.contains("desde Sub"), "{} {}", out, err);
}

/// Fila E10 bajo `synsema test` (`wait_all` al final de cada bloque): el error de un agente lanzado
/// por otro que ya terminó hace fallar el test.
#[test]
fn a_test_block_waits_for_an_agent_another_agent_spawned() {
    let dir = project("e-d1t");
    std::fs::write(
        dir.join("p.syn"),
        "agent Pub\n    agent Sub\n        require time\n        sleep(0.5)\n        raise \"falla Sub\"\n    spawn Sub\ntest \"anidado\"\n    spawn Pub\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["test", "p.syn"], None);
    assert!(code != 0 && format!("{}{}", out, err).contains("falla Sub"), "{} {}", out, err);
}

/// Fila E11: ... y su corte llega aunque el de afuera haya terminado.
#[test]
fn the_cut_of_a_nested_agent_reaches_the_run() {
    let dir = project("e-d2");
    std::fs::write(
        dir.join("p.syn"),
        "agent Pub\n    agent Sub\n        require time\n        sleep(0.5)\n        let c be private({\"name\": \"Ana\"}, \"customers\")\n        print(declassify(c.name, \"public name\"))\n    spawn Sub\nspawn Pub\nprint(\"main\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout,time", "p.syn"], None);
    assert!(code != 0 && !out.contains("Ana") && !out.contains("main"), "{} {}", out, err);
}

/// Fila E12: con `exit`, el agente que lanzó otro y los dos se detienen: la corrida no queda colgada.
#[test]
fn exit_stops_the_agents_an_agent_spawned() {
    let dir = project("e-d3");
    std::fs::write(
        dir.join("p.syn"),
        "require time\nagent Pub\n    require time\n    agent Sub\n        require time\n        while true\n            sleep(0.05)\n    spawn Sub\n    while true\n        sleep(0.05)\nspawn Pub\nsleep(0.3)\nexit(3)\n",
    )
    .unwrap();
    let (code, _, err) = synsema_within(&dir, &["run", "p.syn"], 20).expect("la corrida quedó colgada");
    assert!(code == 3, "{}", err);
}

// =========================================================
// Ronda 1 de la auditoría (`specs/auditoria-v0.6.50-ronda1.md`)
// =========================================================

/// A1 (fila 9b): una lambda del programa que un módulo guarda cierra sobre el programa también al
/// cruzar a otro intérprete: un request de `serve`, un worker de `parallel_map` y un agente.
#[test]
fn a_program_lambda_kept_by_a_module_keeps_its_scope() {
    let dir = project("r1-a1");
    std::fs::write(dir.join("lib.syn"), "let CBS be {}\nexport task registrar(f)\n    set CBS to {\"f\": f}\n    give \"ok\"\nexport task llamar(x)\n    give CBS[\"f\"](x)\n").unwrap();
    let head = "let PRE be \"hola\"\nuse \"./lib.syn\" as lib\nprint(lib.registrar((x) => PRE + x))\n";
    std::fs::write(dir.join("r.syn"), format!("{head}print(lib.llamar(\"-run\"))\nprint(parallel_map((x) => lib.llamar(x), [\"-pm\"]))\n")).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "r.syn"], None);
    assert!(code == 0 && out.contains("hola-run") && out.contains("[\"hola-pm\"]"), "{} {}", out, err);
    std::fs::write(dir.join("ag.syn"), format!("{head}agent A\n    print(lib.llamar(\"-agente\"))\nspawn A\n")).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "ag.syn"], None);
    assert!(code == 0 && out.contains("hola-agente"), "{} {}", out, err);
    let main = format!("require serve({{p}})\n{head}serve on {{p}}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /c\"\n        give lib.llamar(\"-serve\")\n");
    for r in serve_get(&dir, &main, &["/c", "/c"]) {
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("hola-serve"), "{}", r);
    }
}

/// M1: en la REPL, un módulo tampoco ve los nombres que ligaron las líneas anteriores, y un builtin
/// que una línea religó es el builtin para el módulo.
#[test]
fn the_repl_module_does_not_see_earlier_lines() {
    let dir = project("r1-m1");
    std::fs::write(dir.join("lib.syn"), "export task cobrar(n)\n    give n * TASA\nexport task up(s)\n    give upper(s)\n").unwrap();
    let (_, out, err) = synsema(&dir, &["repl"], Some("let TASA be 2\nuse \"./lib.syn\" as lib\nprint(lib.cobrar(10))\n"));
    let all = format!("{}{}", out, err);
    assert!(all.contains("Undefined variable: 'TASA'") && all.contains(HINT) && !all.contains("20"), "{}", all);
    let (_, out, err) = synsema(&dir, &["repl"], Some("let upper be 3\nuse \"./lib.syn\" as lib\nprint(lib.up(\"a\"))\n"));
    let all = format!("{}{}", out, err);
    assert!(out.contains(">>> A") && !all.contains("error"), "{}", all);
}

/// M2: un `{ when }` que decide con un global privado deja su etiqueta en el HTML, aunque el valor no
/// llegue por los datos.
#[test]
fn a_when_on_private_data_labels_the_html() {
    let dir = project("r1-m2");
    std::fs::write(dir.join("w.html"), "<p>{ when VIP }VIP{ otherwise }normal{ end }</p>").unwrap();
    std::fs::write(
        dir.join("p.syn"),
        "require file.read(\"./**\")\nlet VIP be private(true, \"clientes\")\nlet h be render(\"w.html\", {\"x\": 1})\nprint(text(h))\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "p.syn"], None);
    assert!(code == 0 && out.trim().starts_with("private(clientes)"), "{} {}", out, err);
    assert!(!out.contains("VIP") && !out.contains("normal"), "{}", out);
}

/// M3 y N7: con `exit` y un agente vivo, `run --explain` y `synsema test` no quedan colgados, y
/// `--explain` sale con el código del `exit`, como `run`.
#[test]
fn exit_stops_the_agents_under_explain_and_test() {
    let dir = project("r1-m3");
    let agent = "agent Pub\n    require time\n    while true\n        sleep(0.05)\n";
    std::fs::write(dir.join("p.syn"), format!("require time\n{agent}spawn Pub\nsleep(0.3)\nexit(3)\n")).unwrap();
    std::fs::write(dir.join("t.syn"), format!("{agent}test \"x\"\n    spawn Pub\n    exit(3)\n")).unwrap();
    let (code, _, err) = synsema_within(&dir, &["run", "--explain", "p.syn"], 20).expect("--explain quedó colgado");
    assert!(code == 3, "{}", err);
    assert!(!err.contains("Agent error"), "el detenido no es un error: {}", err);
    let (code, out, err) = synsema_within(&dir, &["test", "t.syn"], 20).expect("synsema test quedó colgado");
    assert!(code != 0, "{} {}", out, err);
    assert!(!format!("{}{}", out, err).contains("Agent error"), "{} {}", out, err);
    // Ronda 2 (B4): `conform --swarm` también; el agente detenido sale STOPPED, no ERROR.
    let (_, out, err) = synsema_within(&dir, &["conform", "--swarm", "p.syn"], 20).expect("conform --swarm quedó colgado");
    assert!(out.contains("\"Pub_0\":\"STOPPED\"") && !out.contains("ERROR"), "{} {}", out, err);
}

/// B3: sin techo y con `--auditor`, el sobre lleva el texto real de un error que el corte redacta
/// (con techo ya lo llevaba).
#[test]
fn without_a_ceiling_the_auditor_gets_the_real_error() {
    let dir = project("r1-b3");
    std::fs::write(dir.join("app.syn"), "let s be private(5, \"clientes\")\nwhen s == 5\n    let x be 1 / 0\nprint(\"fin\")\n").unwrap();
    let (sk, pk) = super::v0646_tanda_e_cli::auditor_keys();
    for cap in [&[][..], &["--cap-set", "stdout"][..]] {
        let _ = std::fs::remove_file(dir.join("r.json"));
        let args = [&["run", "--labels"][..], cap, &["--auditor", &pk, "--receipt", "r.json", "app.syn"]].concat();
        let (code, _, _) = synsema(&dir, &args, None);
        assert!(code != 0, "{:?}", cap);
        let r: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("r.json")).unwrap()).unwrap();
        let opened = super::v0646_tanda_e_cli::open_receipt(&r, &sk);
        assert!(opened.to_string().contains("app.syn:3:16: Division by zero"), "{:?}: {}", cap, opened);
    }
}

/// B4: un `sandbox` sin `under` dice que el bloque no concede nada (no «add require» con el
/// `require` ya puesto), en el programa y en un agente; un `decide` del juez en un agente pide el
/// `require llm` en el cuerpo del agente.
#[test]
fn a_sandbox_and_a_judge_decide_say_where_the_capability_goes() {
    let dir = project("r1-b4");
    std::fs::write(dir.join("d.txt"), "hola").unwrap();
    let sb = "a `sandbox` block denies every capability, whatever the program declares: to allow it inside the block use `sandbox under {\"file.read\": …}`";
    for src in [
        "require file.read(\"./**\")\nprint(read_file(\"./d.txt\"))\nsandbox\n    print(read_file(\"./d.txt\"))\n",
        "agent A\n    require file.read(\"./**\")\n    print(read_file(\"./d.txt\"))\n    sandbox\n        print(read_file(\"./d.txt\"))\nspawn A\n",
    ] {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
        assert!(code != 0 && out.contains("hola") && err.contains(sb), "{}: {}", src, err);
        assert!(!err.contains("add `require"), "{}: {}", src, err);
    }
    // La forma que sugiere el texto anda.
    std::fs::write(dir.join("p.syn"), "require file.read(\"./**\")\nsandbox under {\"file.read\": [\"./**\"]}\n    print(read_file(\"./d.txt\"))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    assert!(code == 0 && out.contains("hola"), "{}", err);
    let env = [("SYNSEMA_JUDGE_PROVIDER", "mock"), ("SYNSEMA_JUDGE_DECIDE", "1"), ("SYNSEMA_ENV_FILE", "")];
    std::fs::write(dir.join("p.syn"), "agent A\n    require judge\n    print(decide between [\"alpha\", \"beta\"] given \"x\")\nspawn A\n").unwrap();
    let (code, _, err) = super::v0646_tanda_e_cli::synsema_env(&dir, &["run", "--cap-set", "stdout,judge", "p.syn"], None, &env);
    assert!(code != 0 && err.contains("falls back to the model") && err.contains("add `require llm` to the body of agent A"), "{}", err);
    assert!(!err.contains("preamble"), "{}", err);
}

/// B6 (E-c): una task de la tool que un export expone dentro de un mapa o una lista corre en el scope
/// de la tool, con su `require` y el techo de confianza, no con las capabilities del programa; y el
/// aviso de E-c no sale, porque está exportada.
#[test]
fn a_tool_task_exported_inside_a_map_runs_in_the_tool_scope() {
    let dir = project("r1-b6");
    std::fs::write(dir.join("d.txt"), "secreto").unwrap();
    std::fs::write(
        dir.join("t.syn"),
        "task helper()\n    require file.read(\"./**\")\n    give read_file(\"./d.txt\")\nexport let M be {\"f\": helper, \"n\": 1}\nexport let L be [helper]\n",
    )
    .unwrap();
    let run = |main: &str, tcap: &str| {
        std::fs::write(dir.join("p.syn"), main).unwrap();
        synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", tcap, "p.syn"], None)
    };
    // El programa tiene `file.read`; la tool, no: el permiso del programa no le llega.
    let (code, out, err) = run("require file.read(\"./**\")\nuse \"trusted:t\" as t\nprint(t.M[\"f\"]())\n", "stdout");
    assert!(code != 0 && !out.contains("secreto") && err.contains("above the host ceiling"), "{} {}", out, err);
    // La tool sí, el programa no: corre con lo de la tool.
    for call in ["t.M[\"f\"]()", "t.L[0]()"] {
        let (code, out, err) = run(&format!("use \"trusted:t\" as t\nprint({})\nprint(t.M[\"n\"])\n", call), "stdout,file.read=./**");
        assert!(code == 0 && out.contains("secreto") && out.contains('1'), "{}: {} {}", call, out, err);
        assert!(!err.contains("grants nothing"), "{}: {}", call, err);
    }
}

/// N1: `llm=P` sin `@` no avisa si el mismo techo tiene `llm=P@host`.
#[test]
fn a_ceiling_llm_item_with_its_provider_elsewhere_does_not_warn() {
    let dir = project("r1-n1");
    std::fs::write(dir.join("p.syn"), "print(\"ok\")\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--cap-set", "stdout,llm=clientes,llm=clientes@local", "p.syn"], None);
    assert!(code == 0 && !err.contains("warning"), "{}", err);
    let (_, _, err) = synsema(&dir, &["run", "--cap-set", "stdout,llm=clientes,llm=otros@local", "p.syn"], None);
    assert!(err.contains("warning: --cap-set llm=clientes:"), "{}", err);
}

// =========================================================
// Ronda 2 de la auditoría (`specs/auditoria-v0.6.50-ronda2.md`; regla R2 del modelo)
// =========================================================

/// R1–R4 (M1): una lambda del módulo A que guarda el módulo B cierra sobre A en cualquier orden de
/// los `use`, y nunca lee un nombre igual de B.
#[test]
fn a_module_lambda_kept_by_another_module_keeps_its_module() {
    let dir = project("r2-m1");
    std::fs::write(dir.join("a.syn"), "let SECRETO_A be \"deA\"\nexport task make()\n    give (x) => SECRETO_A + x\n").unwrap();
    let b = "let CB be nothing\nexport task reg(f)\n    set CB to f\n    give \"ok\"\nexport task call(x)\n    give CB(x)\n";
    std::fs::write(dir.join("b.syn"), b).unwrap();
    std::fs::write(dir.join("b2.syn"), format!("let SECRETO_A be \"deB\"\n{b}")).unwrap();
    for (tag, first) in [("ba", "b.syn"), ("same", "b2.syn")] {
        let head = format!("use \"./{first}\" as mb\nuse \"./a.syn\" as ma\nprint(mb.reg(ma.make()))\n");
        std::fs::write(dir.join("p.syn"), format!("{head}print(mb.call(\"-run\"))\nprint(parallel_map((x) => mb.call(x), [\"-pm\"]))\nagent A\n    print(mb.call(\"-ag\"))\nspawn A\n")).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
        assert!(code == 0 && out.contains("deA-run") && out.contains("[\"deA-pm\"]") && out.contains("deA-ag"), "{}: {} {}", tag, out, err);
        assert!(!out.contains("deB"), "{}: {}", tag, out);
        let main = format!("require serve({{p}})\n{head}serve on {{p}}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /c\"\n        give mb.call(\"-serve\")\n");
        for r in serve_get(&dir, &main, &["/c"]) {
            assert!(r.starts_with("HTTP/1.1 200") && r.contains("deA-serve") && !r.contains("deB"), "{}: {}", tag, r);
        }
    }
}

/// R5–R9 (B3): una task que cruza lleva los locales de quien la armó, copiados: en `parallel_map`
/// directo, desde una task de un módulo (con el nombre del módulo), una task local recursiva, y una
/// lambda que una task devuelve y un módulo guarda (bajo `serve` también). Escribir un local
/// capturado cambia la copia del worker, no el original.
#[test]
fn a_task_that_crosses_carries_the_locals_of_who_made_it() {
    let dir = project("r2-b3-local");
    std::fs::write(dir.join("m.syn"), "let BASE be 10\ntask hacer(n)\n    give parallel_map((x) => x * n + BASE, [1, 2])\nexport task correr(n)\n    give hacer(n)\n").unwrap();
    std::fs::write(dir.join("lib.syn"), "let ONE be nothing\nexport task reg_one(f)\n    set ONE to f\n    give \"ok\"\nexport task call_one(x)\n    give ONE(x)\n").unwrap();
    for (src, want) in [
        ("task f(n)\n    give parallel_map((x) => x * n, [1, 2])\nprint(f(3))\n", "[3, 6]"),
        ("use \"./m.syn\" as m\nprint(m.correr(3))\n", "[13, 16]"),
        ("task outer(k)\n    task cuenta(j)\n        when j <= 0\n            give 0\n        give 1 + cuenta(j - 1)\n    give parallel_map((x) => cuenta(x) + k, [2, 3])\nprint(outer(10))\n", "[12, 13]"),
        ("task g()\n    let c be 1\n    task inc(x)\n        set c to c + x\n        give c\n    print(parallel_map(inc, [10, 20]))\n    print(c)\ng()\n", "[11, 21]\n1"),
        ("task make(n)\n    give (x) => text(n) + x\nuse \"./lib.syn\" as lib\nprint(lib.reg_one(make(5)))\nprint(parallel_map((x) => lib.call_one(x), [\"-pm\"]))\nagent A\n    print(lib.call_one(\"-ag\"))\nspawn A\n", "[\"5-pm\"]"),
    ] {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
        assert!(code == 0 && out.contains(want), "{}: {} {}", src, out, err);
    }
    let main = "require serve({p})\ntask make(n)\n    give (x) => text(n) + x\nuse \"./lib.syn\" as lib\nprint(lib.reg_one(make(5)))\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /c\"\n        give lib.call_one(\"-serve\")\n";
    for r in serve_get(&dir, main, &["/c"]) {
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("5-serve"), "{}", r);
    }
}

/// R10 y R11 (B3): una lista con tasks cruza como un mapa con tasks: la del programa, la que guarda un
/// módulo, y la de una tool de confianza (en el scope de la tool, también bajo `serve`).
#[test]
fn a_list_of_tasks_crosses_like_a_map() {
    let dir = project("r2-b3-list");
    std::fs::write(dir.join("lib.syn"), "let CBS be []\nexport task reg_list(f)\n    set CBS to [f]\n    give \"ok\"\nexport task call_list(x)\n    give CBS[0](x)\n").unwrap();
    std::fs::write(
        dir.join("p.syn"),
        "let PRE be \"hola\"\nlet L be [(x) => PRE + x]\nprint(parallel_map((x) => L[0](x), [\"-pm\"]))\nuse \"./lib.syn\" as lib\nprint(lib.reg_list((x) => PRE + x))\nprint(parallel_map((x) => lib.call_list(x), [\"-pm-lib\"]))\nagent A\n    print(lib.call_list(\"-ag\"))\nspawn A\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    assert!(code == 0 && out.contains("[\"hola-pm\"]") && out.contains("[\"hola-pm-lib\"]") && out.contains("hola-ag"), "{} {}", out, err);
    std::fs::write(dir.join("d.txt"), "secreto").unwrap();
    std::fs::write(dir.join("t.syn"), "task helper()\n    require file.read(\"./**\")\n    give read_file(\"./d.txt\")\nexport let L be [{\"f\": helper}]\n").unwrap();
    let tool = ["--trusted", "t=t.syn", "--trusted-cap-set"];
    std::fs::write(dir.join("q.syn"), "use \"trusted:t\" as t\nprint(parallel_map((k) => t.L[0][\"f\"](), [1]))\nagent A\n    print(t.L[0][\"f\"]())\nspawn A\n").unwrap();
    let (code, out, err) = synsema(&dir, &[&["run"][..], &tool, &["stdout,file.read=./**", "q.syn"]].concat(), None);
    assert!(code == 0 && out.contains("[\"secreto\"]") && out.contains("[A_0] secreto"), "{} {}", out, err);
    // Con el techo de la tool sin `file.read`, el permiso del programa no le llega.
    std::fs::write(dir.join("q.syn"), "require file.read(\"./**\")\nuse \"trusted:t\" as t\nprint(parallel_map((k) => t.L[0][\"f\"](), [1]))\n").unwrap();
    let (code, out, err) = synsema(&dir, &[&["run"][..], &tool, &["stdout", "q.syn"]].concat(), None);
    assert!(code != 0 && !out.contains("secreto") && err.contains("above the host ceiling"), "{} {}", out, err);
    let main = "require serve({p})\nuse \"trusted:t\" as t\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /l\"\n        give t.L[0][\"f\"]()\n";
    for r in serve_get_with(&dir, &["--trusted", "t=t.syn", "--trusted-cap-set", "file.read=./**"], main, &["/l"]) {
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("secreto"), "{}", r);
    }
}

/// B1 (E-c): el aviso cuenta lo que la carga envuelve: una task que sólo nombra una lambda o una
/// llamada exportada no es exportada (avisa); la que llega a un export por otro nombre sí (no avisa).
#[test]
fn the_unexported_require_warning_counts_what_the_tool_wraps() {
    let dir = project("r2-b1");
    std::fs::write(dir.join("d.txt"), "secreto").unwrap();
    let helper = "task helper()\n    require file.read(\"./**\")\n    give read_file(\"./d.txt\")\n";
    for (tool, call, warns) in [
        ("export let W be () => helper()\n", "t.W()", 1),
        ("export task w()\n    give helper()\n", "t.w()", 1),
        ("export let N be 1\nlet X be helper\nexport task w()\n    give X()\n", "t.N", 1),
        ("let BASE be {\"f\": helper}\nexport let M be BASE\n", "t.M[\"f\"]()", 0),
    ] {
        std::fs::write(dir.join("t.syn"), format!("{helper}{tool}")).unwrap();
        std::fs::write(dir.join("p.syn"), format!("use \"trusted:t\" as t\nprint({})\n", call)).unwrap();
        let (_, out, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.read=./**", "p.syn"], None);
        assert_eq!(err.matches("grants nothing").count(), warns, "{}: {} {}", tool, out, err);
    }
}

/// B2 y N2: dentro de un `sandbox`, una capability del proceso no se propone en `sandbox under` (que
/// no la lleva); dentro de una task de confianza, el texto es el del bloque, no un `require` que ya está.
#[test]
fn a_sandbox_says_what_sandbox_under_cannot_carry() {
    let dir = project("r2-b2");
    std::fs::write(dir.join("d.txt"), "hola").unwrap();
    std::fs::write(dir.join("p.syn"), "require time\nsandbox\n    print(now())\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "p.syn"], None);
    assert!(code != 0 && err.contains("`sandbox under` cannot carry time") && err.contains("run this outside the block"), "{}", err);
    assert!(!err.contains("sandbox under {\"time\""), "{}", err);
    std::fs::write(dir.join("t.syn"), "export task leer()\n    require file.read(\"./**\")\n    sandbox\n        give read_file(\"./d.txt\")\n").unwrap();
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nprint(t.leer())\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.read=./**", "p.syn"], None);
    assert!(code != 0 && err.contains("a `sandbox` block denies every capability, whatever the trusted task declares"), "{}", err);
    assert!(!err.contains("add `require"), "{}", err);
}
