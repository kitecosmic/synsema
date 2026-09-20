//! Los builtins con EFECTO son sumideros públicos bajo etiquetas:
//! con `serve --attested` (que enciende las etiquetas), un valor `private` que llega a
//! `write_file`, `http_post`, `remember`, `run`… es `label_violation` ANTES de ejecutar el efecto
//! (el archivo no se escribe, el sink HTTP no recibe nada), y una llamada a un sumidero bajo una
//! rama que dependió de datos privados también. Declassificado con motivo, el efecto ocurre.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start_bg(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program_with_overrides(&prog, "labels_sinks.syn", false, ServeOverrides::default());
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server no quedó listo en 127.0.0.1:{}", port);
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(6)));
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

/// Un "sink" HTTP que anota cada body que recibe.
fn sink_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            let seen = seen2.clone();
            thread::spawn(move || {
                let mut sock = sock;
                let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
                let mut buf = vec![0u8; 65536];
                let mut acc = Vec::new();
                while let Ok(n) = sock.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    acc.extend_from_slice(&buf[..n]);
                    if let Some(p) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&acc[..p]).to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                            .unwrap_or(0);
                        if acc.len() >= p + 4 + len {
                            seen.lock().unwrap().push(String::from_utf8_lossy(&acc[p + 4..p + 4 + len]).to_string());
                            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                            break;
                        }
                    }
                }
            });
        }
    });
    (port, seen)
}

#[test]
fn effectful_builtins_refuse_private_values_and_private_control_flow() {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let (sink_port, seen) = sink_server();
    let dir = std::env::temp_dir().join(format!("synsema-labels-sinks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out.txt").to_string_lossy().replace('\\', "/");
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
require net("127.0.0.1")
require file.write("{dir}/*")
serve on {p}
    route "GET /file-leak"
        write_file("{out}", "balance=" + text(private(5, "bank")))
        give {{"ok": true}}
    route "GET /http-leak"
        let r be http_post("http://127.0.0.1:{sink}/collect", {{"balance": private(5, "bank")}})
        give {{"ok": true}}
    route "GET /pc-leak"
        when private(true, "bank")
            http_post("http://127.0.0.1:{sink}/collect", {{"branch": "taken"}})
        give {{"ok": true}}
    route "GET /declassified"
        let total be declassify(private(5, "bank") + private(3, "airline"), "the aggregate is public by policy")
        let r be http_post("http://127.0.0.1:{sink}/collect", {{"total": total}})
        write_file("{out}", "total=" + text(total))
        give {{"ok": r["ok"]}}
"#,
        p = port,
        sink = sink_port,
        dir = dir.to_string_lossy().replace('\\', "/"),
        out = out
    );
    start_bg(prog, port);

    let leak = http_get(port, "/file-leak");
    assert!(leak.starts_with("HTTP/1.1 500"), "{}", leak);
    assert!(leak.contains("label_violation") && leak.contains("write_file"), "{}", leak);
    assert!(!std::path::Path::new(&out).exists(), "the file must not be written");

    let leak = http_get(port, "/http-leak");
    assert!(leak.starts_with("HTTP/1.1 500"), "{}", leak);
    assert!(leak.contains("label_violation") && leak.contains("http_post"), "{}", leak);
    thread::sleep(Duration::from_millis(200));
    assert!(seen.lock().unwrap().is_empty(), "the sink must not have received anything: {:?}", seen.lock().unwrap());

    let leak = http_get(port, "/pc-leak");
    assert!(leak.starts_with("HTTP/1.1 500"), "{}", leak);
    assert!(leak.contains("label_violation") && leak.contains("control flow"), "{}", leak);
    thread::sleep(Duration::from_millis(200));
    assert!(seen.lock().unwrap().is_empty(), "no call under private control flow: {:?}", seen.lock().unwrap());

    let ok = http_get(port, "/declassified");
    assert!(ok.starts_with("HTTP/1.1 200"), "{}", ok);
    thread::sleep(Duration::from_millis(200));
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{:?}", got);
    assert!(got[0].contains("\"total\":8") || got[0].contains("\"total\": 8"), "{}", got[0]);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "total=8");
}

/// Anti-rot: cada nombre de `LABEL_SINK_BUILTINS` tiene que existir de verdad como
/// builtin en el perfil nativo — un typo dejaría un efecto fuera del chequeo sin que nadie lo
/// note — y las familias con efecto conocidas tienen que estar en la lista.
#[test]
fn every_label_sink_name_is_a_real_builtin_and_the_families_are_covered() {
    let src = "print(1)\n";
    let r = synsema_runtime::engine::run_source(src, "sinks.syn");
    assert!(r.success, "{:?}", r.errors);
    // El intérprete del runtime, cableado igual que en una corrida normal.
    let missing: Vec<&str> = synsema_runtime::engine::LABEL_SINK_BUILTINS
        .iter()
        .copied()
        .filter(|name| !synsema_runtime::engine::LABEL_SINKS_SERVE_ONLY.contains(name))
        .filter(|name| !synsema_runtime::engine::builtin_exists(name))
        .collect();
    assert!(missing.is_empty(), "nombres que no existen como builtin: {:?}", missing);
    for name in ["write_file", "http_post", "sql", "ws_send", "remember", "run", "run_program", "env", "secret", "attest", "push_send", "state_set", "proc_spawn"] {
        assert!(
            synsema_runtime::engine::LABEL_SINK_BUILTINS.contains(&name),
            "{} tiene efecto y no está declarado como sumidero de etiquetas",
            name
        );
    }
}

/// Anti-rot — **el test que el comentario de `engine.rs` promete**:
/// la clasificación se cruza contra los builtins REGISTRADOS DE VERDAD en el wiring nativo, no contra
/// sí misma. Por el hueco de "la lista se valida sola" pasó `parallel_map`, que cruza a otro
/// intérprete y despojaba los valores antes de que el worker hiciera el efecto.
///
/// Cinco invariantes:
///   (a) todo builtin registrado está clasificado: sumidero, `label_aware` del core, o PURO explícito;
///   (b) ningún nombre de las listas es obsoleto (salvo los que sólo existen bajo `serve`/swarm);
///   (c) nada está en dos listas a la vez;
///   (d) toda familia OS-facing (las tablas del perfil puro, `synsema_stdlib::pure`) es sumidero o
///       LECTURA declarada — un builtin nuevo que hable con el SO rompe el test;
///   (e) las lecturas declaradas son puras, no sumideros.
#[test]
fn every_effectful_family_is_a_label_sink() {
    use std::collections::BTreeSet;
    let set = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|s| s.to_string()).collect() };

    let registered: BTreeSet<String> = synsema_runtime::engine::registered_builtin_names().into_iter().collect();
    assert!(registered.len() > 300, "el wiring nativo registra {} builtins", registered.len());
    let sinks: BTreeSet<String> = set(synsema_runtime::engine::LABEL_SINK_BUILTINS)
        .union(&set(synsema_core::interpreter::CORE_SINK_BUILTINS))
        .cloned()
        .collect();
    let aware = set(synsema_core::interpreter::PROTECTED_BUILTIN_NAMES);
    let pure = set(synsema_runtime::engine::LABEL_PURE_BUILTINS);
    let deferred = set(synsema_runtime::engine::LABEL_SINKS_SERVE_ONLY);
    let os_reads = set(synsema_runtime::engine::LABEL_OS_READ_BUILTINS);

    // (a) Nada sin clasificar. Un builtin nuevo cae acá hasta que alguien decida de qué lado está.
    let unclassified: Vec<&String> = registered
        .iter()
        .filter(|n| !sinks.contains(*n) && !aware.contains(*n) && !pure.contains(*n))
        .collect();
    assert!(
        unclassified.is_empty(),
        "builtins registrados SIN clasificar (¿tienen efecto fuera del intérprete? → LABEL_SINK_BUILTINS; \
         si no, → LABEL_PURE_BUILTINS, con su comentario): {:?}",
        unclassified
    );

    // (b) Sin nombres muertos: una lista con typos o restos deja de proteger sin que nadie lo note.
    let stale: Vec<&String> = sinks
        .iter()
        .chain(pure.iter())
        .filter(|n| !registered.contains(*n) && !deferred.contains(*n))
        .collect();
    assert!(stale.is_empty(), "nombres listados que NO existen como builtin: {:?}", stale);

    // (c) Un nombre en las dos listas sería una contradicción silenciosa.
    let both: Vec<&String> = sinks.intersection(&pure).collect();
    assert!(both.is_empty(), "declarados sumidero Y puro a la vez: {:?}", both);

    // (d) Toda familia que habla con el SO (la tabla del perfil puro) está clasificada a mano.
    use synsema_stdlib::pure;
    for (family, names) in [
        ("filesystem", pure::FS),
        ("archive", pure::ARCHIVE),
        ("exec", pure::EXEC),
        ("sockets", pure::SOCKETS),
        ("database", pure::DB),
        ("cron", pure::CRON),
        ("hub/proc", pure::HUB),
        ("bus", pure::BUS),
        ("agents", pure::AGENTS),
        ("process", pure::PROCESS),
    ] {
        let unclassified: Vec<&&str> = names
            .iter()
            .filter(|n| !sinks.contains(**n) && !os_reads.contains(**n))
            .collect();
        assert!(
            unclassified.is_empty(),
            "familia OS-facing `{}`: {:?} no son ni sumidero ni LECTURA declarada",
            family,
            unclassified
        );
    }

    // (e) Las lecturas declaradas son puras (si una pasa a tener efecto, hay que moverla a sumideros).
    for r in &os_reads {
        assert!(!sinks.contains(r), "{} está declarado como lectura Y como sumidero", r);
        assert!(
            pure.contains(r) || deferred.contains(r),
            "{} es una lectura declarada pero no está en LABEL_PURE_BUILTINS",
            r
        );
    }

    // Y lo que motivó todo: `parallel_map` cruza a otro intérprete → sumidero, nunca puro.
    assert!(sinks.contains("parallel_map"), "parallel_map tiene que ser sumidero (bloqueante 3)");
    assert!(!pure.contains("parallel_map"));

    // (f) Auditoría externa: lo mismo para el wiring de **serve** —el que usa `--attested`—
    // y el del swarm. Por este hueco `state_all` era el único de la familia de estado compartido
    // sin declarar, mientras `state_get` sí lo estaba.
    let serve_registered: BTreeSet<String> =
        synsema_runtime::serve::registered_serve_builtin_names().into_iter().collect();
    assert!(
        serve_registered.len() >= registered.len(),
        "el wiring de serve ({}) tiene que ser un superconjunto del de run ({})",
        serve_registered.len(),
        registered.len()
    );
    let unclassified_serve: Vec<&String> = serve_registered
        .iter()
        .filter(|n| !sinks.contains(*n) && !aware.contains(*n) && !pure.contains(*n))
        .collect();
    assert!(
        unclassified_serve.is_empty(),
        "builtins que SÓLO existen bajo serve/swarm y quedaron sin clasificar: {:?}",
        unclassified_serve
    );
    // Y los nombres declarados como serve-only existen de verdad ahí (si no, la lista miente).
    let missing: Vec<&String> = deferred.iter().filter(|n| !serve_registered.contains(*n)).collect();
    assert!(missing.is_empty(), "declarados serve/swarm-only pero ausentes del wiring de serve: {:?}", missing);
    assert!(sinks.contains("state_all"), "state_all lee el estado compartido: sumidero");
}
