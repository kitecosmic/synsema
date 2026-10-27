//! Tests del binario real para v0.6.50: A, un módulo no ve los globales de quien lo importa (regla y
//! tabla de casos en `specs/v0.6.50-a-modelo.md`; cada test nombra sus filas).

use super::v0646_tanda_e_cli::{project, synsema};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const HINT: &str = "is a name of the program that imports this module";

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
