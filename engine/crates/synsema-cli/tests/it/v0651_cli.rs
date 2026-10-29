//! Tests del binario real para v0.6.51 (los modelos están en `specs/v0.6.51-modelos.md`; cada test
//! nombra sus filas).

use super::v0646_tanda_e_cli::{project, synsema};
use super::v0650_cli::serve_get;

/// `a.syn` (sólo datos), `b.syn` (lee `a.X`) y `main.syn`; corre `synsema run main.syn`.
fn data_module(tag: &str, main: &str) -> (i32, String, String) {
    let dir = project(tag);
    std::fs::write(dir.join("a.syn"), "export let X be 1\n").unwrap();
    std::fs::write(dir.join("b.syn"), "use \"./a.syn\" as a\nexport task get()\n    give a.X\n").unwrap();
    std::fs::write(dir.join("main.syn"), main).unwrap();
    synsema(&dir, &["run", "main.syn"], None)
}

/// F2-1, F2-2, F2-4 y F2-5: un módulo sin tasks es una instancia; `set m.X` del programa lo ve la
/// vista que armó otro módulo, también en un worker de `parallel_map`.
#[test]
fn a_data_module_is_one_instance_for_every_view() {
    let main = "use \"./a.syn\" as m\nuse \"./a.syn\" as n\nuse \"./b.syn\" as b\nlet snap be m.X\nset m.X to 5\nprint([m.X, n.X, b.get(), snap])\nprint(parallel_map((k) => b.get(), [1]))\n";
    let (code, out, err) = data_module("f2-run", main);
    assert_eq!((code, out.trim()), (0, "[5, 5, 5, 1]\n[5]"), "{}", err);
}

/// F2-3: lo mismo bajo `serve`.
#[test]
fn serve_sees_a_data_module_as_one_instance() {
    let dir = project("f2-serve");
    std::fs::write(dir.join("a.syn"), "export let X be 1\n").unwrap();
    std::fs::write(dir.join("b.syn"), "use \"./a.syn\" as a\nexport task get()\n    give a.X\n").unwrap();
    let main = "require serve({p})\nuse \"./a.syn\" as m\nuse \"./b.syn\" as b\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /x\"\n        set m.X to 5\n        give text([m.X, b.get()])\n";
    let r = serve_get(&dir, main, &["/x"]);
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].contains("[5, 5]"), "{}", r[0]);
}

fn run_in(tag: &str, args: &[&str], main: &str) -> (i32, String, String) {
    let dir = project(tag);
    std::fs::write(dir.join("main.syn"), main).unwrap();
    let mut all = vec!["run"];
    all.extend_from_slice(args);
    all.push("main.syn");
    synsema(&dir, &all, None)
}

/// N5 (ronda 4 de v0.6.50): un `sandbox` pelado deniega `print` como deniega todo, con y sin techo
/// del host; `sandbox under {}` lo deja pasar (es del proceso); y el veredicto de un `print` anterior
/// no vale adentro (v0.6.50 imprimía con `--cap-set stdout` si el programa ya había impreso).
#[test]
fn a_plain_sandbox_denies_print_with_or_without_a_ceiling() {
    let deny = "a `sandbox` block denies every capability";
    for args in [&[][..], &["--cap-set", "stdout"][..]] {
        let (code, out, err) = run_in("n5-bare", args, "sandbox\n    print(\"dentro\")\n");
        assert!(code != 0 && !out.contains("dentro") && err.contains(deny), "{:?}: {}{}", args, out, err);
        let (code, out, err) = run_in("n5-after", args, "print(\"antes\")\nsandbox\n    print(\"dentro\")\n");
        assert!(code != 0 && out.contains("antes") && !out.contains("dentro") && err.contains(deny), "{:?}: {}{}", args, out, err);
        // Lo que computa el bloque se imprime afuera; y después del bloque se imprime como siempre.
        let (code, out, err) = run_in("n5-value", args, "let r be 0\nsandbox\n    set r to 40 + 2\nprint(r)\n");
        assert_eq!((code, out.trim()), (0, "42"), "{:?}: {}", args, err);
        let (code, out, err) = run_in("n5-under", args, "sandbox under {}\n    print(\"dentro\")\n");
        assert_eq!((code, out.trim()), (0, "dentro"), "{:?}: {}", args, err);
    }
}

/// v0.6.51: un valor del servidor se lee como el mapa que dice ser (`type_of` da `map`): `r["body"]`
/// es `r.body`, y `keys`, `values` y `contains` ven sus campos (antes: `Cannot index into map`).
#[test]
fn a_server_value_reads_like_the_map_it_says_it_is() {
    let dir = project("srv-map");
    std::fs::write(dir.join("t.html"), "<p>{nombre}</p>\n").unwrap();
    let main = "require file.read\nlet r be render(\"t.html\", {\"nombre\": \"Ana\"})\nprint(trim(r[\"body\"]))\nprint(keys(r))\nprint([contains(r, \"status\"), contains(r, \"x\")])\nlet e be ok({\"a\": 1})\nprint([e[\"status\"], e[\"value\"][\"a\"], values(e)])\ntry\n    print(r[\"nope\"])\nrecover err\n    print(err)\n";
    std::fs::write(dir.join("main.syn"), main).unwrap();
    for flags in [&[][..], &["--labels"][..]] {
        let mut args = vec!["run"];
        args.extend_from_slice(flags);
        args.push("main.syn");
        let (code, out, err) = synsema(&dir, &args, None);
        assert_eq!(
            (code, out.trim()),
            (0, "<p>Ana</p>\n[\"body\", \"content_type\", \"status\"]\n[true, false]\n[200, 1, [200, {a: 1}]]\nMap has no key 'nope'"),
            "{:?}: {}",
            flags,
            err
        );
    }
}

/// v0.6.51: `synsema check --templates <dir>` valida los `render("…")` de una herramienta de
/// confianza contra la carpeta que le da el host (`--trusted-templates nombre=<dir>`), desde
/// cualquier directorio; sin la opción, el template que falta nombra la opción.
#[test]
fn check_validates_a_tool_against_its_templates_folder() {
    let dir = project("check-tpl");
    std::fs::create_dir_all(dir.join("tpl")).unwrap();
    std::fs::write(dir.join("tpl").join("card.html"), "<h1>{t}</h1>\n{include \"parte.html\"}\n").unwrap();
    std::fs::write(dir.join("tpl").join("parte.html"), "<p>parte</p>\n").unwrap();
    std::fs::write(dir.join("tools.syn"), "export task card(t)\n    require file.read\n    give render(\"card.html\", {\"t\": t})\n").unwrap();
    let (code, _, err) = synsema(&dir, &["check", "tools.syn"], None);
    assert!(code != 0 && err.contains("template not found: card.html") && err.contains("synsema check --templates <dir> tools.syn"), "{}", err);
    let (code, out, err) = synsema(&dir, &["check", "--templates", "tpl", "tools.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("1 template(s) validated"), "{}", out);
    // Desde otra carpeta, con rutas absolutas.
    let abs_tpl = dir.join("tpl").to_string_lossy().into_owned();
    let abs_tool = dir.join("tools.syn").to_string_lossy().into_owned();
    let (code, _, err) = synsema(&dir.join("tpl"), &["check", "--templates", &abs_tpl, &abs_tool], None);
    assert_eq!(code, 0, "{}", err);
    // Los módulos del programa se siguen resolviendo desde su archivo, no desde la carpeta.
    std::fs::write(dir.join("lib.syn"), "export task saludo()\n    give \"hola\"\n").unwrap();
    std::fs::write(dir.join("main.syn"), "use \"./lib.syn\" as lib\nrequire file.read\nprint(render(\"card.html\", {\"t\": lib.saludo()}))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["check", "--templates", "tpl", "main.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("1 module(s) + 1 template(s) validated"), "{}", out);
    // Un `include` que falta en la carpeta falla.
    std::fs::remove_file(dir.join("tpl").join("parte.html")).unwrap();
    let (code, _, err) = synsema(&dir, &["check", "--templates", "tpl", "tools.syn"], None);
    assert!(code != 0 && err.contains("template not found: parte.html"), "{}", err);
}

/// v0.6.51: `state_*` fuera de un request de `serve` (un worker de `parallel_map`, un programa sin
/// `serve`) dice dónde existe y qué hacer, en vez del `Undefined variable` pelado.
#[test]
fn state_outside_a_request_says_where_it_lives() {
    let hint = "is the shared state of `serve`: it exists in a request";
    let (code, _, err) = run_in("state-run", &[], "print(state_get(\"k\"))\n");
    assert!(code != 0 && err.contains("Undefined variable: 'state_get'") && err.contains(hint), "{}", err);
    let dir = project("state-serve");
    let main = "require serve({p})\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /x\"\n        state_set(\"k\", 1)\n        give parallel_map((i) => state_get(\"k\"), [1, 2])\n";
    let r = serve_get(&dir, main, &["/x"]);
    assert!(r[0].contains("Undefined variable: ") && r[0].contains("state_get"), "{}", r[0]);
    assert!(r[0].contains("it exists in a request"), "{}", r[0]);
}

/// v0.6.51: `content()` — el `lang` de la meta llega a `<html lang>` (default `en`), el JSON no lleva
/// la presentación (`stylesheet`, `class`, `header`, `footer`) y el sufijo `.md`/`.json` vale también
/// en una ruta literal (`GET /historial.md` → `/historial`; antes 404, sólo en rutas con `:param`).
#[test]
fn content_carries_lang_drops_presentation_from_json_and_takes_a_suffix_on_literal_routes() {
    let dir = project("content-651");
    let main = "require serve({p})\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /historial\"\n        give content(page([heading(1, \"Hola\")], {\"title\": \"T\", \"lang\": \"es\", \"stylesheet\": \"/s.css\", \"class\": \"c\", \"header\": \"<b>h</b>\", \"footer\": \"pie\"}))\n    route \"GET /otro\"\n        give content(page([heading(1, \"Hi\")], {\"title\": \"O\"}))\n    route \"GET /post/:slug\"\n        give content(page([heading(1, params.slug)], {\"title\": params.slug}))\n";
    let r = serve_get(&dir, main, &["/historial", "/historial.md", "/historial.json", "/otro", "/post/a.md", "/nada.md"]);
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].contains("<html lang=\"es\">") && r[0].contains("/s.css"), "{}", r[0]);
    assert!(r[1].starts_with("HTTP/1.1 200") && r[1].contains("text/markdown") && r[1].contains("# Hola"), "{}", r[1]);
    assert!(r[2].starts_with("HTTP/1.1 200") && r[2].contains("application/json") && r[2].contains("\"lang\""), "{}", r[2]);
    for k in ["stylesheet", "\"class\"", "\"header\"", "\"footer\"", "/s.css", "pie"] {
        assert!(!r[2].contains(k), "{} en {}", k, r[2]);
    }
    assert!(r[3].contains("<html lang=\"en\">"), "{}", r[3]);
    assert!(r[4].starts_with("HTTP/1.1 200") && r[4].contains("# a"), "{}", r[4]);
    assert!(r[5].starts_with("HTTP/1.1 404"), "{}", r[5]);
}

/// Ronda 1, M1: el sufijo en ruta literal no tapa las URLs que publica el runtime. Una ruta
/// `GET /openapi` no se lleva `/openapi.json`, ni `GET /.well-known/agent-card` la agent card;
/// `/openapi.md`, que no es reservada, sigue siendo de la ruta.
#[test]
fn a_literal_route_does_not_take_the_urls_the_runtime_publishes() {
    let dir = project("reserved-651");
    let main = "require serve({p})\nserve on {p}\n    route \"GET /ping\"\n        give \"ok\"\n    route \"GET /openapi\"\n        give content(page([heading(1, \"Mia\")], {\"title\": \"API\"}))\n    route \"GET /.well-known/agent-card\"\n        give content(page([heading(1, \"Card\")], {\"title\": \"C\"}))\n";
    let r = serve_get(
        &dir,
        main,
        &["/openapi.json", "/.well-known/agent-card.json", "/openapi.md", "//openapi.json", "//.well-known/agent-card.json"],
    );
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].contains("\"openapi\"") && !r[0].contains("\"page\""), "{}", r[0]);
    assert!(r[1].starts_with("HTTP/1.1 200") && r[1].contains("supportedInterfaces") && !r[1].contains("\"page\""), "{}", r[1]);
    assert!(r[2].starts_with("HTTP/1.1 200") && r[2].contains("text/markdown") && r[2].contains("# Mia"), "{}", r[2]);
    // Ronda 4 (N1): con barras repetidas tampoco (el router las ignora; como en v0.6.50, 404).
    assert!(r[3].starts_with("HTTP/1.1 404") && !r[3].contains("\"page\""), "{}", r[3]);
    assert!(r[4].starts_with("HTTP/1.1 404") && !r[4].contains("\"page\""), "{}", r[4]);
    // Ronda 2 (N1): con `private` el runtime no las publica, y la ruta se las lleva (como una ruta
    // con parámetros); antes quedaban en 404.
    let private = main.replace("serve on {p}\n", "serve on {p}\n    private\n");
    let r = serve_get(&dir, &private, &["/openapi.json", "/.well-known/agent-card.json"]);
    assert!(r[0].starts_with("HTTP/1.1 200") && r[0].contains("\"page\"") && r[0].contains("Mia"), "{}", r[0]);
    assert!(r[1].starts_with("HTTP/1.1 200") && r[1].contains("\"page\"") && r[1].contains("Card"), "{}", r[1]);
}

/// Un listener local que acepta y corta, y cuenta las conexiones (C1: ¿llegó el hijo?).
fn counting_listener() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = n.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(s);
        }
    });
    (port, n)
}

/// C1-9 (specs/v0.6.51-modelos.md): el hijo de `run_program` hereda, capa por capa, lo que limitaba
/// al padre. Con `require net("*")` (sólo lo público) el padre no llega a 127.0.0.1, y antes podía
/// darle `net("127.0.0.1:…")` a su hijo (el comodín lo cubre por nombre) y el hijo conectaba.
#[test]
fn a_run_program_child_reaches_no_private_address_its_caller_could_not() {
    let (port, conns) = counting_listener();
    let child = format!("require net(\"127.0.0.1:{p}\")\nlet r be http_get(\"http://127.0.0.1:{p}/\")\nprint(r.error)\n", p = port);
    let parent = |net: &str| {
        format!(
            "require sandbox_run\nrequire net(\"{net}\")\nlet r be run_program({child:?}, {{\"ceiling\": {{\"net\": [\"127.0.0.1:{p}\"]}}, \"profile\": \"native\", \"timeout\": 20}})\nprint(json_encode(r))\n",
            net = net,
            child = child,
            p = port
        )
    };
    let (code, out, err) = run_in("c1-child-wild", &[], &parent("*"));
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("reaches only public addresses"), "{}", out);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(conns.load(std::sync::atomic::Ordering::SeqCst), 0, "el hijo conectó: {}", out);
    // Un padre que la nombra se la puede dar.
    let (code, out, err) = run_in("c1-child-named", &[], &parent(&format!("127.0.0.1:{}", port)));
    assert_eq!(code, 0, "{}{}", out, err);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(conns.load(std::sync::atomic::Ordering::SeqCst), 1, "{}", out);
}

/// Ronda 3, N2 (y ronda 2, B1): un preámbulo que falla después de `serve on` cierra el server y sale
/// con 1 y su error; el aviso dice que lo paró el motor, no que el programa pidió un shutdown.
#[test]
fn a_preamble_that_fails_after_serve_on_says_the_engine_stopped_the_server() {
    let dir = project("preamble-fails-651");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::fs::write(
        dir.join("main.syn"),
        format!("require serve({port})\nserve on {port}\n    route \"GET /\"\n        give \"ok\"\nlet xs be [1]\nlet x be xs[5]\n"),
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["serve", "main.syn"], None);
    assert_eq!(code, 1, "{}{}", out, err);
    assert!(err.contains("the preamble failed after `serve on`: stopping the server"), "{}", err);
    assert!(!err.contains("requested by the program"), "{}", err);
    assert!(err.contains("Runtime error"), "{}", err);
}
