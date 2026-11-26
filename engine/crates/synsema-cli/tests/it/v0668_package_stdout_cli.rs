//! v0.6.68: `stdout` bajo el dominio de paquetes, con el binario real. Lo que sólo se ve mirando
//! los bytes del proceso: stdout y stderr enteros, el prompt de `read_line`, el techo del host y la
//! consola del `serve`. (Lo que se ve sin mirar los bytes está en
//! `synsema-runtime/tests/it/v0668_package_stdout.rs`.)

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::v0646_tanda_e_cli::synsema_env;
use super::v0658_get_cli::{modules, url, Pkg, Proj, Reg};

/// El rechazo del paquete `mudo`, entero.
const DENIED: &str = "Capability not granted: stdout — the package mudo does not declare it; add `require stdout` inside its tasks";
/// El mismo rechazo como llega en un cuerpo HTTP: el JSON de un 500 escapa la raya larga con una
/// secuencia Unicode, así que acá se busca la parte ASCII.
const DENIED_ASCII: &str = "the package mudo does not declare it; add `require stdout` inside its tasks";
/// El paquete `tok` declara `stdout` una vez, en su primera task: el dominio es el paquete entero.
const DECLARES: &str = "    require stdout\n";
const CACHE: &str = "SYNSEMA_MODULE_CACHE";

/// Las mismas tasks en los dos paquetes: `print`, `show`, `log`, `eprint`, el prompt de `read_line`,
/// un bucle de impresión repartido entre workers, un `parallel_map` del paquete, una ruta montada y
/// un handler.
fn package(decl: &str, route: &str) -> String {
    let mut src = String::new();
    for (task, body) in [
        ("p", "    print(\"PKG\")\n    give 1\n"),
        ("s", "    show \"PKG\"\n    give 1\n"),
        ("l", "    log \"PKG\"\n    give 1\n"),
        ("e", "    eprint(\"PKG\")\n    give 1\n"),
        ("r", "    require stdin\n    give read_line(\"PKG>\")\n"),
        ("eco(x)", "    print(\"E\" + text(x))\n    give x\n"),
        ("por_worker(f)", "    give parallel_map(f, [1])\n"),
        ("handler()", "    print(\"PKG-H\")\n    give {\"said\": \"PKG-H\"}\n"),
    ] {
        src.push_str(&format!("export task {task}\n{decl}{body}"));
    }
    src.push_str(&format!("export routes rutas\n    route \"GET {route}\"\n        print(\"PKG\")\n        give {{\"said\": \"PKG\"}}\n"));
    src
}

/// Un proyecto con dos paquetes ya instalados por `get`: `tok` declara `stdout` y `mudo` no.
fn project(tag: &str) -> Proj {
    let reg = Reg::start();
    let tok = Pkg::new(&format!("{}/tok", reg.base()), "0.1.0", &package(DECLARES, "/pkg-si"));
    let mudo = Pkg::new(&format!("{}/mudo", reg.base()), "0.1.0", &package("", "/pkg-no"));
    let u_tok = reg.publish("/tok/current", &tok);
    let u_mudo = reg.publish("/mudo/current", &mudo);
    let p = Proj::new(tag, modules(&[("tok", url(&u_tok)), ("mudo", url(&u_mudo))]));
    let report = p.ok(&[]);
    assert!(report.contains("task p: stdout"), "{report}");
    // `get` escribe lo que cada paquete declara: `tok` lista `stdout` entre sus `requires`, `mudo` no.
    let requires = |m: &str| p.json()["modules"][m]["requires"].as_array().cloned().unwrap_or_default();
    assert!(requires("tok").contains(&serde_json::json!("stdout")), "{}", p.json()["modules"]["tok"]["requires"]);
    assert!(!requires("mudo").contains(&serde_json::json!("stdout")), "{}", p.json()["modules"]["mudo"]["requires"]);
    p
}

/// `synsema run …` de `src` en el proyecto, con sus paquetes. Devuelve código, stdout y stderr.
fn run(p: &Proj, src: &str, flags: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    std::fs::write(p.dir.join("p.syn"), src).unwrap();
    let mut args = vec!["run"];
    args.extend_from_slice(flags);
    args.push("p.syn");
    let cache = p.cache.to_string_lossy().into_owned();
    synsema_env(&p.dir, &args, stdin, &[(CACHE, cache.as_str())])
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Un `serve` del proyecto con stdout y stderr capturados. `stop` lo apaga (sólo a ese proceso) y
/// devuelve lo que escribió.
struct Serving(Child);

impl Serving {
    fn start(p: &Proj, src: &str, flags: &[&str]) -> (Serving, u16) {
        let port = free_port();
        std::fs::write(p.dir.join("s.syn"), src.replace("__PORT__", &port.to_string())).unwrap();
        let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
        let mut args = vec!["serve"];
        args.extend_from_slice(flags);
        args.push("s.syn");
        c.args(&args)
            .current_dir(&p.dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .env(CACHE, &p.cache)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().expect("spawn synsema serve");
        let since = Instant::now();
        while !TcpStream::connect_timeout(&addr(port), Duration::from_millis(100)).is_ok() {
            assert!(since.elapsed() < Duration::from_secs(20), "el serve no escuchó en {port}");
            assert!(child.try_wait().unwrap().is_none(), "el serve murió al arrancar");
            std::thread::sleep(Duration::from_millis(30));
        }
        (Serving(child), port)
    }

    fn stop(mut self) -> (String, String) {
        let _ = self.0.kill();
        let out = self.0.wait_with_output().unwrap();
        (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(addr(port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

const CALLS: &str = "try\n    mudo.p()\nrecover e\n    print(\"p: \" + text(e))\ntry\n    mudo.s()\nrecover e\n    print(\"s: \" + text(e))\ntry\n    mudo.l()\nrecover e\n    print(\"l: \" + text(e))\ntry\n    mudo.e()\nrecover e\n    print(\"e: \" + text(e))\n";

/// `print`, `show`, `log` y `eprint` del paquete mudo: ni un byte en stdout ni en stderr, el error
/// es el del paquete y es atrapable; el programa imprime antes y después. Con y sin `--labels`.
#[test]
fn v0668_no_byte_of_a_denied_package_reaches_stdout_or_stderr() {
    let p = project("v0668-bytes");
    let src = format!("require stdin\nuse \"mudo\" as mudo\nprint(\"uno\")\n{CALLS}print(\"dos\")\n");
    let want = format!("uno\np: {DENIED}\ns: {DENIED}\nl: {DENIED}\ne: {DENIED}\ndos\n");
    for flags in [&[][..], &["--labels"][..]] {
        let (code, out, err) = run(&p, &src, flags, None);
        assert_eq!((code, out.as_str(), err.as_str()), (0, want.as_str(), ""), "flags {flags:?}");
    }
    // Un worker hereda el dominio: repartir la task del paquete, o un callback del programa dentro
    // del `parallel_map` del paquete, no imprime ni un byte y el error es el del paquete.
    for src in [
        "use \"mudo\" as mudo\nlet r be parallel_map(mudo.eco, [1, 2, 3])\nprint(length(r))\nprint(\"dos\")\n",
        "use \"mudo\" as mudo\ntask cb(x)\n    print(\"CB\")\n    give x\nprint(mudo.por_worker(cb))\nprint(\"dos\")\n",
    ] {
        for flags in [&[][..], &["--labels"][..]] {
            let (code, out, err) = run(&p, src, flags, None);
            assert_eq!((code, out.as_str()), (1, ""), "{src:?} flags {flags:?}: {out}\n{err}");
            assert!(err.contains(DENIED), "{src:?} flags {flags:?}: {err}");
        }
    }
}

/// Sin `recover`: lo que el programa ya emitió en vivo queda en stdout, el error del paquete va a
/// stderr con código 1, y nada del paquete sale.
#[test]
fn v0668_an_uncaught_denial_leaves_the_live_output_and_nothing_else() {
    let p = project("v0668-sin-recover");
    let src = "use \"mudo\" as mudo\nprint(\"uno\")\nmudo.p()\nprint(\"dos\")\n";
    for flags in [&[][..], &["--labels"][..]] {
        let (code, out, err) = run(&p, src, flags, None);
        assert_eq!((code, out.as_str()), (1, "uno\n"), "flags {flags:?}: {err}");
        assert!(err.contains("Runtime error: ") && err.contains(DENIED) && !err.contains("PKG"), "flags {flags:?}: {err}");
    }
}

/// El paquete que declara imprime en los dos sumideros, como siempre los usó el programa; y lo
/// que imprime un worker suyo llega a la consola del proceso.
#[test]
fn v0668_a_declaring_package_prints_to_stdout_and_stderr() {
    let p = project("v0668-declara");
    let src = "use \"tok\" as tok\ntok.p()\ntok.s()\ntok.l()\ntok.e()\nprint(\"dos\")\n";
    for flags in [&[][..], &["--labels"][..]] {
        let (code, out, err) = run(&p, src, flags, None);
        assert_eq!((code, out.as_str(), err.as_str()), (0, "PKG\nPKG\ndos\n", "[LOG] PKG\nPKG\n"), "flags {flags:?}");
    }
    // Lo que imprime un worker llega a la consola del proceso: cada item en el suyo.
    let (code, out, err) = run(&p, "use \"tok\" as tok\nlet r be parallel_map(tok.eco, [1, 2, 3])\nprint(length(r))\n", &[], None);
    assert_eq!((code, out.lines().filter(|l| l.starts_with('E')).count(), out.trim_end().lines().last()), (0, 3, Some("3")), "{out}\n{err}");
    // El callback del programa dentro del `parallel_map` del paquete, que declara.
    let (code, out, err) = run(&p, "use \"tok\" as tok\ntask cb(x)\n    print(\"CB\")\n    give x\nprint(tok.por_worker(cb))\nprint(\"dos\")\n", &[], None);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "CB\n[1]\ndos\n", ""), "{out}\n{err}");
}

/// El prompt de `read_line` es salida: el paquete mudo no lo escribe ni consume la entrada; el
/// programa lee la primera línea. El que declara `stdout` (y `stdin`) escribe el prompt.
#[test]
fn v0668_the_prompt_of_a_denied_package_is_not_written_and_input_is_not_consumed() {
    let p = project("v0668-prompt");
    let src = "require stdin\nuse \"mudo\" as mudo\ntry\n    print(mudo.r())\nrecover e\n    print(\"r: \" + text(e))\nprint(read_line())\n";
    let want = format!("r: {DENIED}\nfirst\n");
    for flags in [&[][..], &["--labels"][..]] {
        let (code, out, err) = run(&p, src, flags, Some("first\nsecond\n"));
        assert_eq!((code, out.as_str(), err.as_str()), (0, want.as_str(), ""), "flags {flags:?}");
    }
    let src = "require stdin\nuse \"tok\" as tok\nprint(tok.r())\nprint(read_line())\n";
    let (code, out, err) = run(&p, src, &[], Some("first\nsecond\n"));
    assert_eq!((code, out.as_str(), err.as_str()), (0, "PKG>first\nsecond\n", ""), "{out}\n{err}");
}

/// El techo del host sigue mandando sobre la declaración del paquete, y el paquete que no declara
/// se niega con su error también bajo techo.
#[test]
fn v0668_the_host_ceiling_still_rules_over_the_package_declaration() {
    let p = project("v0668-techo");
    let (code, out, err) = run(&p, "require stdout\nuse \"tok\" as tok\ntok.p()\nprint(\"dos\")\n", &["--cap-set", "time"], None);
    assert_eq!(code, 1, "{out}\n{err}");
    assert!(out.is_empty() && !err.contains("PKG"), "{out}\n{err}");
    assert!(err.contains("Capability not granted: stdout") && err.contains("host ceiling"), "{err}");
    let (code, out, err) = run(&p, "require stdout\nuse \"tok\" as tok\nuse \"mudo\" as mudo\ntok.p()\ntry\n    mudo.p()\nrecover e\n    print(text(e))\n", &["--cap-set", "stdout,time"], None);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(out, format!("PKG\n{DENIED}\n"));
    assert!(err.is_empty(), "{err}");
}

/// La consola del `serve`: cada request es su unidad de trabajo. Lo que imprimen el programa y el
/// paquete que declara aparece con `[serve] `; el mudo falla con 500 y su error, y no deja una
/// línea. Con y sin `--labels`.
#[test]
fn v0668_serve_logs_what_the_program_and_a_declaring_package_print_and_nothing_of_a_denied_one() {
    let p = project("v0668-serve");
    let src = "require serve(__PORT__)\nuse \"tok\" as tok\nuse \"mudo\" as mudo\nserve on __PORT__\n    mount tok.rutas\n\n    mount mudo.rutas\n\n    route \"GET /prog\"\n        print(\"PROG\")\n        give {\"said\": \"PROG\"}\n\n    route \"GET /si\"\n        give tok.handler()\n\n    route \"GET /no\"\n        give mudo.handler()\n";
    for flags in [&[][..], &["--labels"][..]] {
        let (server, port) = Serving::start(&p, src, flags);
        let (mut ok, mut denied) = (0, 0);
        for _ in 0..3 {
            for (path, status, said) in [("/prog", "200", "PROG"), ("/si", "200", "PKG-H"), ("/pkg-si", "200", "PKG"), ("/no", "500", ""), ("/pkg-no", "500", "")] {
                let r = get(port, path);
                assert!(r.starts_with(&format!("HTTP/1.1 {status}")), "{path} flags {flags:?}: {r}");
                if status == "200" {
                    assert!(r.contains(said) && !r.contains("Capability not granted"), "{path}: {r}");
                    ok += 1;
                } else {
                    assert!(r.contains("Capability not granted: stdout") && r.contains(DENIED_ASCII) && !r.contains("\"said\""), "{path}: {r}");
                    denied += 1;
                }
            }
        }
        let (out, err) = server.stop();
        // Tres vueltas: una línea por cada impresión permitida. Si el mudo hubiera impreso, sus
        // líneas (`[serve] PKG`, `[serve] PKG-H`) aparecerían el doble.
        let times = |line: &str| out.lines().filter(|l| *l == line).count();
        assert_eq!((times("[serve] PROG"), times("[serve] PKG-H"), times("[serve] PKG")), (3, 3, 3), "flags {flags:?}:\nstdout:\n{out}\nstderr:\n{err}");
        assert_eq!((ok, denied), (9, 6));
        assert_eq!(err.lines().filter(|l| l.contains(DENIED)).count(), denied, "flags {flags:?}:\n{err}");
    }
}
