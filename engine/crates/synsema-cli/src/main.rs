//! Synsema CLI. Espeja `synsema/cli.py` y `__main__.py` (capa 11, en progreso).
//!
//! Subcomando de conformidad (gate de paridad contra el oráculo Python):
//!
//!     synsema conform <archivo.syn>
//!
//! Ejecuta el programa y emite a STDOUT una sola línea JSON:
//!     {"ok": <bool>, "out": [<líneas de print>], "err": [<errores>]}
//! Exit 0 siempre que pueda producir el JSON (el fallo del programa va en el JSON).
//! Exit != 0 sólo si el CLI no pudo (archivo ilegible / args inválidos), con el
//! motivo en STDERR. Nada más que el JSON va a STDOUT.

use std::process::ExitCode;

// El conform usa el motor (runtime): intérprete + modelo de seguridad cableado.
use synsema_capabilities::model::build_ceiling;
use synsema_runtime::daemon;
use synsema_runtime::engine::{
    repl, run_program_ceiled, run_program_ceiled_opts, run_source_ceiled, run_swarm_dump_ceiled,
    run_tests_ceiled, run_with_diagnostics_ceiled, TestReport,
};
use synsema_runtime::host::{self, Profile};
use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};

mod build;
mod bundle_out;
mod icns;
mod init_templates;
mod pe;
mod stdio;
mod synfide;
mod update;
mod code;

const USAGE: &str = "uso: synsema <conform [--swarm] [--flat] | serve [--secure] [--watch] [--port N] [--domain d1,d2] [--tls-auto <email> | --tls-cert <p> --tls-key <p>] [--bind addr] | run [--flat] [--explain] [--format human|json] [--provider <name>] <archivo.syn | -> [-- args...] | test [-v] <archivo|dir> | build <main.syn> -o <salida> [--include <p>]... [--engine-binary <ruta>] [--serve [--bind addr] ...] [--no-console] [--icon <svg|png|ico>] [--bundle [--name <n>] [--id <id>]] | check | code <outline|symbol|refs|routes|caps|check|search|deps> [--json] | code --mcp | openapi [--out f] [--base-url URL] | tokens | ast | repl | daemon | init [dir] [--synfide | --pwa | --desktop] | llm status [--json] | version | update> [--sandbox | --cap-set <list>] [--profile native|pure] [--audit json|<ruta>|fd:N] [--env-file <path> | --no-env-file] <archivo.syn>";

// `build_ceiling` (--sandbox/--cap-set → techo) vive en synsema-capabilities: lo comparten
// este binario y `synsema-wasm` (mismas flags, misma semántica en los dos front-ends).

/// Serializa un mapa (clave→string) como objeto JSON ordenado.
fn json_obj(pairs: Vec<(String, String)>) -> String {
    let map: std::collections::BTreeMap<String, String> = pairs.into_iter().collect();
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Flags del HOST comunes a `run`/`test`/`conform`/`serve`/`build`: el techo
/// (`--sandbox`/`--cap-set`), el perfil (`--profile`), el audit (`--audit`), el `.env`
/// (`--env-file`/`--no-env-file`), el `--` que separa los argumentos del programa y el
/// `--filename` interno de `run -`. UN parser para todos (hasta v0.6.13 había cuatro
/// copias con tres políticas distintas de flag desconocido). Lo que no es del host queda
/// en `rest`, en orden, para que cada subcomando parsee lo suyo.
#[derive(Default, Debug, Clone)]
pub(crate) struct HostFlags {
    pub sandbox: bool,
    pub cap_set: Option<String>,
    pub profile: Option<String>,
    pub audit: Option<String>,
    pub filename: Option<String>,
    pub program_args: Vec<String>,
    pub rest: Vec<String>,
}

impl HostFlags {
    /// El techo del host (`build_ceiling`), o el error de uso ya impreso.
    fn ceiling(&self, cmd: &str) -> Result<Option<Vec<synsema_capabilities::model::Capability>>, ExitCode> {
        match build_ceiling(self.sandbox, self.cap_set.as_deref()) {
            Ok(c) => Ok(c),
            Err(e) => {
                eprintln!("synsema {}: {}", cmd, e);
                Err(ExitCode::from(2))
            }
        }
    }

    /// Fija el perfil del PROCESO (`--profile`), validando el nombre.
    fn apply_profile(&self, cmd: &str) -> Result<Profile, ExitCode> {
        let p = match self.profile.as_deref() {
            None => Profile::Native,
            Some(name) => match Profile::parse(name) {
                Some(p) => p,
                None => {
                    eprintln!("synsema {}: --profile must be 'native' or 'pure', got '{}'", cmd, name);
                    return Err(ExitCode::from(2));
                }
            },
        };
        host::set_profile(p);
        Ok(p)
    }

    /// Instala el sink de audit (`--audit`), y el colector si el subcomando va a emitir
    /// un informe JSON (`run --format json`).
    fn apply_audit(&self, cmd: &str, collect: bool) -> Result<(), ExitCode> {
        if self.audit.is_none() && !collect {
            return Ok(());
        }
        if let Err(e) = audit::install(self.audit.as_deref(), collect) {
            eprintln!("synsema {}: {}", cmd, e);
            return Err(ExitCode::from(2));
        }
        Ok(())
    }
}

/// Separa los flags del host de `args` (los que siguen al subcomando). Un valor de flag
/// nunca puede empezar con `--` (`run --cap-set --sandbox` era un error confuso).
pub(crate) fn take_host_flags(cmd: &str, args: &[String]) -> Result<HostFlags, ExitCode> {
    let mut h = HostFlags::default();
    let mut i = 0;
    let need_value = |flag: &str, v: Option<&String>| -> Result<String, ExitCode> {
        match v {
            Some(v) if !v.starts_with("--") => Ok(v.clone()),
            _ => {
                eprintln!("synsema {}: {} requires a value", cmd, flag);
                Err(ExitCode::from(2))
            }
        }
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                h.program_args.extend(args[i + 1..].iter().cloned());
                break;
            }
            "--no-env-file" => std::env::set_var("SYNSEMA_ENV_FILE", ""),
            "--env-file" => {
                let v = need_value("--env-file", args.get(i + 1))?;
                std::env::set_var("SYNSEMA_ENV_FILE", v);
                i += 1;
            }
            "--sandbox" => h.sandbox = true,
            "--cap-set" => {
                h.cap_set = Some(need_value("--cap-set", args.get(i + 1))?);
                i += 1;
            }
            "--profile" => {
                h.profile = Some(need_value("--profile", args.get(i + 1))?);
                i += 1;
            }
            "--audit" => {
                h.audit = Some(need_value("--audit", args.get(i + 1))?);
                i += 1;
            }
            "--filename" => {
                h.filename = Some(need_value("--filename", args.get(i + 1))?);
                i += 1;
            }
            _ => {
                if let Some(p) = a.strip_prefix("--env-file=") {
                    std::env::set_var("SYNSEMA_ENV_FILE", p);
                } else if let Some(p) = a.strip_prefix("--cap-set=") {
                    h.cap_set = Some(p.to_string());
                } else if let Some(p) = a.strip_prefix("--profile=") {
                    h.profile = Some(p.to_string());
                } else if let Some(p) = a.strip_prefix("--audit=") {
                    h.audit = Some(p.to_string());
                } else if let Some(p) = a.strip_prefix("--filename=") {
                    h.filename = Some(p.to_string());
                } else {
                    h.rest.push(args[i].clone());
                }
            }
        }
        i += 1;
    }
    if h.sandbox && h.cap_set.is_some() {
        eprintln!("synsema {}: --sandbox and --cap-set are mutually exclusive; choose one", cmd);
        return Err(ExitCode::from(2));
    }
    Ok(h)
}

/// Sink de `--audit json|<ruta>|fd:N` + colector del informe `--format json`. Una línea
/// JSON por chequeo (misma forma que `syn.run().audit` en wasm, más `ts`/`context`/
/// `file`/`line`), y una línea `{"summary": …}` al terminar.
mod audit {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use synsema_capabilities::model::audit_sink::{self, AuditEvent};

    struct Sink {
        writer: Option<Mutex<Box<dyn Write + Send>>>,
        collect: Option<Mutex<Vec<serde_json::Value>>>,
        granted: AtomicUsize,
        denied: AtomicUsize,
    }

    static SINK: OnceLock<Arc<Sink>> = OnceLock::new();

    fn event_json(ev: &AuditEvent<'_>) -> serde_json::Value {
        serde_json::json!({
            "ts": ev.ts,
            "context": ev.context,
            "capability": ev.entry.capability.to_string(),
            "granted": ev.entry.granted,
            "source": ev.entry.source,
            "reason": ev.entry.reason,
            "origin": ev.entry.origin,
            "file": ev.file,
            "line": ev.line,
        })
    }

    pub fn install(dest: Option<&str>, collect: bool) -> Result<(), String> {
        let writer: Option<Box<dyn Write + Send>> = match dest {
            None => None,
            Some("json") => Some(Box::new(std::io::stderr())),
            Some(fd) if fd.starts_with("fd:") => {
                let n: i32 = fd[3..].parse().map_err(|_| format!("--audit: invalid fd '{}'", fd))?;
                #[cfg(unix)]
                {
                    use std::os::unix::io::FromRawFd;
                    if n < 3 {
                        return Err("--audit fd:N needs N >= 3 (0-2 are stdin/stdout/stderr)".to_string());
                    }
                    Some(Box::new(unsafe { std::fs::File::from_raw_fd(n) }))
                }
                #[cfg(not(unix))]
                {
                    let _ = n;
                    return Err("--audit fd:N is only available on Unix; use --audit <path> or --audit json".to_string());
                }
            }
            Some(path) => Some(Box::new(
                std::fs::File::create(path).map_err(|e| format!("--audit: cannot create {}: {}", path, e))?,
            )),
        };
        let sink = Arc::new(Sink {
            writer: writer.map(Mutex::new),
            collect: if collect { Some(Mutex::new(Vec::new())) } else { None },
            granted: AtomicUsize::new(0),
            denied: AtomicUsize::new(0),
        });
        if SINK.set(sink.clone()).is_err() {
            return Err("--audit: the audit sink is already installed".to_string());
        }
        let s = sink;
        audit_sink::install(Box::new(move |ev: &AuditEvent<'_>| {
            if ev.entry.granted {
                s.granted.fetch_add(1, Ordering::Relaxed);
            } else {
                s.denied.fetch_add(1, Ordering::Relaxed);
            }
            let v = event_json(ev);
            if let Some(w) = &s.writer {
                if let Ok(mut w) = w.lock() {
                    let _ = writeln!(w, "{}", v);
                    let _ = w.flush();
                }
            }
            if let Some(c) = &s.collect {
                if let Ok(mut c) = c.lock() {
                    c.push(v);
                }
            }
        }));
        Ok(())
    }

    /// La línea final `{"summary": {"granted", "denied", "exit"}}` (si hay writer).
    pub fn summary(exit: i32) {
        if let Some(s) = SINK.get() {
            if let Some(w) = &s.writer {
                if let Ok(mut w) = w.lock() {
                    let _ = writeln!(
                        w,
                        "{}",
                        serde_json::json!({"summary": {
                            "granted": s.granted.load(Ordering::Relaxed),
                            "denied": s.denied.load(Ordering::Relaxed),
                            "exit": exit,
                        }})
                    );
                    let _ = w.flush();
                }
            }
        }
    }

    /// Las entradas colectadas (para `run --format json`).
    pub fn collected() -> Vec<serde_json::Value> {
        SINK.get()
            .and_then(|s| s.collect.as_ref())
            .and_then(|c| c.lock().ok().map(|c| c.clone()))
            .unwrap_or_default()
    }
}

/// Un binario de `synsema build` en MODO PROGRAMA: todo `argv` es del programa
/// (`args()`), el techo y el perfil son los horneados, el bundle queda montado como
/// overlay de lectura. `--engine` como primer argumento devuelve el CLI del motor.
fn run_bundled(bundle: synsema_core::bundle::Bundle, program_args: Vec<String>) -> ExitCode {
    let manifest = bundle.manifest.clone();
    let profile = Profile::parse(&manifest.profile).unwrap_or(Profile::Native);
    host::set_profile(profile);
    host::set_program_args(program_args);
    let ceiling = match manifest.ceiling.as_deref() {
        None => None,
        Some("sandbox") => match build_ceiling(true, None) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("synsema: bundle corrupt (ceiling): {}", e);
                return ExitCode::from(1);
            }
        },
        Some(list) => match build_ceiling(false, Some(list)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("synsema: bundle corrupt (ceiling): {}", e);
                return ExitCode::from(1);
            }
        },
    };
    let source = match bundle.get(&manifest.main) {
        Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        None => {
            eprintln!("synsema: bundle corrupt (main '{}' missing)", manifest.main);
            return ExitCode::from(1);
        }
    };
    let filename = manifest.main.clone();
    if !synsema_core::bundle::mount(bundle) {
        eprintln!("synsema: bundle already mounted");
        return ExitCode::from(1);
    }
    let source = if filename.ends_with(".fsyn") { synsema_core::flat_syntax::translate_flat(&source) } else { source };
    // `synsema build --serve`: el runtime de `synsema serve` con los flags horneados. Bloquea
    // mientras el server corra (Ctrl-C = shutdown ordenado, exit 0); exit 1 si no levanta.
    if manifest.mode == synsema_core::bundle::BundleMode::Serve {
        let Some(s) = manifest.serve.clone() else {
            eprintln!("synsema: bundle corrupt (serve settings missing)");
            return ExitCode::from(1);
        };
        let mut ov = ServeOverrides {
            port: s.port,
            domains: s.domains,
            tls_auto_email: s.tls_auto,
            tls_cert: s.tls_cert,
            tls_key: s.tls_key,
            bind: Some(s.bind),
            ceiling: None,
        };
        // Igual que `synsema serve --sandbox`: un server necesita `serve` además del techo.
        ov.ceiling = match (ceiling, manifest.ceiling.as_deref()) {
            (Some(mut c), Some("sandbox")) => {
                c.push(synsema_capabilities::model::Capability::new(synsema_capabilities::model::CapabilityType::Serve, None));
                Some(c)
            }
            (c, _) => c,
        };
        let result = run_serve_program_with_overrides(&source, &filename, s.secure, ov);
        if !result.success {
            for e in &result.errors {
                eprintln!("{}", e);
            }
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    let result = run_program_ceiled(&source, &filename, ceiling);
    for line in &result.output {
        println!("{}", line);
    }
    if !result.success {
        for e in &result.errors {
            eprintln!("{}", e);
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    // Antes del primer print: una salida sin lector nunca es un pánico (stdio.rs).
    stdio::install_broken_pipe_guard();
    let mut args: Vec<String> = std::env::args().collect();

    // `--engine` como primer argumento: el CLI del motor, en cualquier binario (en uno
    // de `synsema build` es la ÚNICA forma de llegar al motor; en `synsema` es un
    // prefijo no-op para que los scripts sean uniformes). Sin `--engine`, un binario
    // con bundle corre su programa; uno sin bundle es el CLI de siempre.
    let engine_prefix = args.get(1).map(|a| a == "--engine").unwrap_or(false);
    if engine_prefix {
        args.remove(1);
        // Un build `--no-console` (subsistema GUI) usado como CLI: que se vea en la consola
        // del padre si la hay (cmd/PowerShell); sin consola padre no cambia nada.
        stdio::attach_parent_console();
    } else {
        match std::env::current_exe()
            .map_err(|e| e.to_string())
            .and_then(|p| synsema_core::bundle::detect(&p))
        {
            Ok(synsema_core::bundle::Detected::Plain) => {}
            Ok(synsema_core::bundle::Detected::Bundle(b)) => {
                return run_bundled(b, args.iter().skip(1).cloned().collect());
            }
            Err(e) => {
                eprintln!("synsema: {}", e);
                return ExitCode::from(1);
            }
        }
    }

    match args.get(1).map(String::as_str) {
        Some("conform") => cmd_conform(&args),
        Some("build") => match take_host_flags("build", &args[2..]) {
            Ok(h) => build::cmd_build(h),
            Err(code) => code,
        },
        Some("serve") => cmd_serve(&args),
        Some("run") => cmd_run(&args),
        Some("test") => cmd_test(&args),
        Some("check") => cmd_check(&args),
        Some("code") => code::cmd_code(&args),
        Some("openapi") => cmd_openapi(&args),
        Some("tokens") => cmd_tokens(&args),
        Some("ast") => cmd_ast(&args),
        Some("repl") => {
            update::notify_if_outdated();
            repl();
            ExitCode::SUCCESS
        }
        Some("daemon") => cmd_daemon(&args),
        Some("init") => cmd_init(&args),
        Some("llm") => cmd_llm(&args),
        Some("update") => update::cmd_update(),
        Some("version") | Some("--version") | Some("-V") => {
            println!("Synsema {}", update::current_version());
            update::notify_if_outdated();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("subcomando desconocido: '{}'. Disponibles: init, conform, serve, run, test, build, check, code, openapi, tokens, ast, repl, daemon, llm, version, update", other);
            ExitCode::from(2)
        }
        None => {
            eprintln!("{}", USAGE);
            ExitCode::from(2)
        }
    }
}

/// Escribe UN archivo del scaffold con el patrón conffiles. Devuelve `true` si lo creó.
///
/// Existir NO alcanza para decidir: hay que saber SI es tuyo. Se compara el sha256 del
/// disco contra el contenido actual y contra los históricos (`InitFile::past`) — así un
/// archivo de fábrica pero viejo recibe las novedades en vez de quedar congelado para
/// siempre, y uno con ediciones tuyas jamás se pisa.
fn scaffold_file(base: &std::path::Path, f: &init_templates::InitFile) -> Result<bool, ExitCode> {
    let path = base.join(f.name);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("init: no se pudo crear {}: {}", parent.display(), e);
            return Err(ExitCode::from(1));
        }
    }
    let disk = std::fs::read(&path).ok();
    let action = match disk.as_deref() {
        None => InitAction::Write,
        Some(bytes) => {
            let h = crate::update::sha256_hex(bytes);
            if h == crate::update::sha256_hex(f.content.as_bytes()) {
                InitAction::UpToDate
            } else if f.past.contains(&h.as_str()) {
                InitAction::Refresh
            } else {
                InitAction::KeepYours
            }
        }
    };
    match action {
        InitAction::UpToDate => {
            println!("init: {} ya está al día", path.display());
            Ok(false)
        }
        InitAction::KeepYours => {
            // Patrón conffiles (apt/pacman): tu versión se conserva y la nueva
            // aterriza al lado, para que puedas ver la diferencia. Sin el `.new`
            // el usuario nunca se entera de qué se perdió.
            let new_path = base.join(format!("{}.new", f.name));
            if let Err(e) = std::fs::write(&new_path, f.content) {
                eprintln!("init: no se pudo escribir {}: {}", new_path.display(), e);
                return Err(ExitCode::from(1));
            }
            println!(
                "init: ⚠ {} tiene cambios tuyos — se conserva; la versión nueva quedó en {}",
                path.display(),
                new_path.display()
            );
            Ok(false)
        }
        InitAction::Write | InitAction::Refresh => match std::fs::write(&path, f.content) {
            Ok(()) => {
                if matches!(action, InitAction::Refresh) {
                    println!("init: {} actualizado (estaba sin ediciones tuyas)", path.display());
                    Ok(false)
                } else {
                    println!("init: {} creado", path.display());
                    Ok(true)
                }
            }
            Err(e) => {
                eprintln!("init: no se pudo escribir {}: {}", path.display(), e);
                Err(ExitCode::from(1))
            }
        },
    }
}

/// Los PNG de la PWA, DERIVADOS de `public/icon.svg` con el rasterizador del motor
/// (la misma fuente embebida que `svg_to_png`; sin herramientas externas). Regla:
/// - `icon.svg` de fábrica y los tres PNG presentes → nada que hacer;
/// - `icon.svg` editado por el usuario, o algún PNG faltante → se (re)generan los tres
///   (los PNG son derivados: "editá el svg y volvé a correr init" es el contrato);
/// - sin `icon.svg` → no se toca nada (el usuario trajo sus PNG y se dice).
fn pwa_icons(base: &std::path::Path) -> Result<String, String> {
    let mut generated: Vec<&str> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for (src, factory_svg) in init_templates::PWA_ICON_SOURCES {
        let outputs: Vec<(&str, u32)> = init_templates::PWA_ICONS
            .iter()
            .filter(|(s, _, _)| *s == src)
            .map(|(_, out, px)| (*out, *px))
            .collect();
        let svg_path = base.join(src);
        let svg = match std::fs::read_to_string(&svg_path) {
            Ok(s) => s,
            Err(_) => {
                notes.push(format!(
                    "{} no está — no se generan {} (traé los tuyos)",
                    src,
                    outputs.iter().map(|(o, _)| o.trim_start_matches("public/")).collect::<Vec<_>>().join(", ")
                ));
                continue;
            }
        };
        let factory = svg == factory_svg;
        let all_present = outputs.iter().all(|(o, _)| base.join(o).is_file());
        if factory && all_present {
            continue;
        }
        for (out, px) in outputs {
            let png = synsema_stdlib::raster::render_svg_png(&svg, px, px)
                .map_err(|e| format!("no se pudo rasterizar {}: {}", svg_path.display(), e))?;
            std::fs::write(base.join(out), png).map_err(|e| format!("no se pudo escribir {}: {}", out, e))?;
            generated.push(out.trim_start_matches("public/"));
        }
    }
    let mut msg = if generated.is_empty() {
        "init: los PNG de los íconos ya están (SVG de fábrica)".to_string()
    } else {
        format!("init: {} generados desde los SVG de public/", generated.join(", "))
    };
    for n in notes {
        msg.push_str(&format!("\ninit: {}", n));
    }
    Ok(msg)
}

/// Qué hacer con un archivo del scaffold que YA está en disco.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum InitAction {
    /// No existe → crearlo.
    Write,
    /// Idéntico al contenido actual → nada que hacer.
    UpToDate,
    /// De fábrica pero de una versión anterior → traerle las novedades.
    Refresh,
    /// No coincide con ninguna versión conocida → es TUYO, se conserva.
    KeepYours,
}

/// `synsema init [directorio]` — scaffold de proyecto (Spec DX-2): genera `hello.syn`
/// (tour del lenguaje con test), `.env.example` (providers como pares provider+key,
/// knobs comentados) y `.gitignore`. Un archivo existente JAMÁS se pisa si tiene
/// ediciones tuyas; si sigue siendo de fábrica (aunque de una versión vieja) recibe
/// las novedades. Los templates están test-verificados contra el engine
/// (init_templates.rs).
fn cmd_init(args: &[String]) -> ExitCode {
    // `--synfide`: además del scaffold base (sin hello.syn — el starter es app.syn),
    // instala el framework Synfide VERSIONADO desde su último release (manifest +
    // sha256 por archivo; ver synfide.rs).
    // `--pwa`: scaffold EMBEBIDO de una app instalable (tanda PWA, specs/pwa-mobile.md):
    // app.syn + página + manifest + service worker + íconos generados desde icon.svg.
    // Tampoco lleva hello.syn (el starter es app.syn). No descarga nada.
    // `--desktop` (tanda escritorio): el scaffold PWA (modular: app.syn monta api.syn) MÁS la
    // entrada de escritorio desk.syn (bind 127.0.0.1, ventana de app del navegador, socket
    // por ventana, shutdown() al cerrar la última) y public/desk.js. `--pwa --desktop` es lo mismo.
    let with_synfide = args.iter().any(|a| a == "--synfide");
    let with_desktop = args.iter().any(|a| a == "--desktop");
    let with_pwa = args.iter().any(|a| a == "--pwa") || with_desktop;
    if with_synfide && with_pwa {
        eprintln!("init: --synfide y --pwa/--desktop son starters distintos (cada uno trae su app.syn); elegí uno");
        return ExitCode::from(2);
    }
    if let Some(bad) = args
        .iter()
        .skip(2)
        .find(|a| a.starts_with("--") && !matches!(a.as_str(), "--synfide" | "--pwa" | "--desktop"))
    {
        eprintln!("init: flag desconocido '{}'\nuso: synsema init [dir] [--synfide | --pwa | --desktop]", bad);
        return ExitCode::from(2);
    }
    // El directorio es el primer positional, esté antes o después de los flags
    // (`synsema init --pwa miapp` y `synsema init miapp --pwa` son lo mismo).
    let dir = args
        .iter()
        .skip(2)
        .find(|a| !a.starts_with("--"))
        .map(String::as_str)
        .unwrap_or(".");
    let base = std::path::Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(base) {
        eprintln!("init: no se pudo crear '{}': {}", dir, e);
        return ExitCode::from(1);
    }
    let mut created = 0usize;
    for f in init_templates::INIT_FILES {
        if (with_synfide || with_pwa) && f.name == "hello.syn" {
            continue; // el tour lo reemplaza el app.syn del starter
        }
        match scaffold_file(base, &f) {
            Ok(true) => created += 1,
            Ok(false) => {}
            Err(code) => return code,
        }
    }
    if with_pwa {
        for f in init_templates::PWA_FILES {
            // El resumen final de --pwa son los "próximos pasos", no un conteo.
            if let Err(code) = scaffold_file(base, &f) {
                return code;
            }
        }
        if with_desktop {
            for f in init_templates::DESKTOP_FILES {
                if let Err(code) = scaffold_file(base, &f) {
                    return code;
                }
            }
        }
        match pwa_icons(base) {
            Ok(msg) => println!("{}", msg),
            Err(e) => {
                eprintln!("init: {}", e);
                return ExitCode::from(1);
            }
        }
        let prefix = if dir == "." { String::new() } else { format!("{}/", dir.trim_end_matches(['/', '\\'])) };
        println!();
        println!("Listo. Próximos pasos:");
        println!("  synsema serve {p}app.syn                  # http://localhost:8080 — Chrome/Edge la instalan desde localhost", p = prefix);
        println!("  synsema run {p}push_keys.syn              # (opcional) par VAPID para push nativo → pegalo en {p}.env", p = prefix);
        println!("  synsema serve {p}app.syn --domain app.example.com --tls-auto you@example.com   # en el VPS: el teléfono la instala", p = prefix);
        println!("  editá {p}public/icon.svg y volvé a correr `synsema init --pwa` para regenerar los PNG", p = prefix);
        if with_desktop {
            println!("  synsema serve {p}desk.syn                 # escritorio: abre la ventana de app; cerrala y el proceso termina", p = prefix);
            println!("  synsema build {p}desk.syn -o desk --serve --no-console --icon {p}public/icon.svg   # Windows: desk.exe con tu ícono", p = prefix);
            println!("  synsema build {p}desk.syn -o desk --serve --icon {p}public/icon.svg --bundle       # macOS: desk.app · Linux: desk/ + install.sh", p = prefix);
        }
        return ExitCode::SUCCESS;
    }
    if with_synfide {
        if let Err(e) = synfide::install(base) {
            eprintln!("init: synfide no se pudo instalar: {}", e);
            eprintln!("      (nada del framework quedó escrito a medias; reintentá con red)");
            return ExitCode::from(1);
        }
        let prefix = if dir == "." { String::new() } else { format!("{}/", dir.trim_end_matches(['/', '\\'])) };
        println!();
        println!("Listo. Próximos pasos:");
        println!("  cp {p}.env.example {p}.env       # elegí tu provider LLM y pegá su key", p = prefix);
        println!("  synsema run {}app.syn        # tu primera app durable", prefix);
        println!("  synsema test {}test_synfide.syn   # el suite del framework", prefix);
        return ExitCode::from(0);
    }
    if created == 0 {
        println!("init: nada que hacer (los 3 archivos ya existían).");
    } else {
        let prefix = if dir == "." { String::new() } else { format!("{}/", dir.trim_end_matches(['/', '\\'])) };
        println!();
        println!("Listo. Próximos pasos:");
        println!("  synsema run {}hello.syn      # correlo (funciona sin LLM)", prefix);
        println!("  synsema test {}hello.syn     # corré su test", prefix);
        println!("  synsema llm status           # conectá un provider (copiá .env.example a .env)");
    }
    ExitCode::SUCCESS
}

/// `synsema llm status [--json]` — imprime la configuración LLM RESUELTA (la que
/// `run`/`serve` van a usar de verdad), con la fuente de cada valor y el diagnóstico
/// cuando está offline. SEGURIDAD: jamás imprime valores de keys (solo presencia) —
/// el reporte viene de `llm_config_report`, cuyo tipo no puede transportar secretos.
/// No hace red. Exit: 0 = vivo, 1 = offline, 2 = uso.
fn cmd_llm(args: &[String]) -> ExitCode {
    let args: Vec<String> = match take_host_flags("llm", &args[2..]) {
        Ok(h) => std::iter::once(args[0].clone()).chain(std::iter::once(args[1].clone())).chain(h.rest).collect(),
        Err(code) => return code,
    };
    match args.get(2).map(String::as_str) {
        Some("status") => cmd_llm_status(args.iter().any(|a| a == "--json")),
        _ => {
            eprintln!("uso: synsema llm status [--json] [--env-file <path> | --no-env-file]");
            ExitCode::from(2)
        }
    }
}

/// Path efectivo del `.env` — espeja `EnvStore::load_default` (SYNSEMA_ENV_FILE >
/// `./.env` si existe > ninguno).
fn effective_env_file() -> Option<String> {
    match std::env::var("SYNSEMA_ENV_FILE") {
        Ok(p) if p.is_empty() => None,
        Ok(p) => Some(p),
        Err(_) => std::path::Path::new(".env")
            .exists()
            .then(|| std::fs::canonicalize(".env")
                .map(|p| strip_verbatim(&p))
                .unwrap_or_else(|_| ".env".to_string())),
    }
}

/// Windows: `fs::canonicalize` devuelve paths verbatim (`\\?\C:\…`) — sacá el prefijo
/// para imprimir. En otras plataformas es identidad.
fn strip_verbatim(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// Todos los `synsema(.exe)` distintos que hay en el PATH, en orden (el primero gana).
/// Solo paths de archivos — nada del entorno. Para avisar el shadowing de binarios
/// (release instalada vs build de cargo) que causa "probé contra el binario viejo".
fn synsema_binaries_in_path() -> Vec<std::path::PathBuf> {
    let mut seen = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in ["synsema.exe", "synsema"] {
                let cand = dir.join(name);
                if cand.is_file() {
                    let canon = std::fs::canonicalize(&cand).unwrap_or(cand);
                    if !seen.contains(&canon) {
                        seen.push(canon);
                    }
                }
            }
        }
    }
    seen
}

fn cmd_llm_status(json: bool) -> ExitCode {
    use synsema_runtime::llm_providers::{
        llm_config_report, OfflineReason, ProviderSelection,
    };
    use synsema_stdlib::secrets::EnvStore;

    let store = EnvStore::load_default();
    let report = llm_config_report(&store);

    if json {
        println!("{}", report.to_json());
        return if report.offline.is_none() { ExitCode::SUCCESS } else { ExitCode::from(1) };
    }

    // Cabecera: binario + versión + .env efectivo (diagnóstico de "¿QUÉ estoy corriendo?").
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".to_string());
    println!("Synsema {} — {}", update::current_version(), exe);
    match effective_env_file() {
        Some(p) => println!(".env: {}", p),
        None => println!(".env: (ninguno — solo environ del proceso y defaults)"),
    }
    let bins = synsema_binaries_in_path();
    if bins.len() > 1 {
        println!("⚠️  hay {} binarios `synsema` en el PATH (gana el primero):", bins.len());
        for b in &bins {
            println!("     {}", strip_verbatim(b));
        }
    }
    println!();

    let sel = match &report.selection {
        ProviderSelection::Forced(src) => format!("(SYNSEMA_LLM_PROVIDER, {})", src.label()),
        ProviderSelection::Auto => "(auto, por presencia de la key)".to_string(),
        ProviderSelection::None => String::new(),
    };
    if !report.provider.is_empty() {
        println!("Provider    {:<28} {}", report.provider, sel);
    }
    if let Some(var) = &report.key_var {
        match report.key_present {
            Some(src) => println!("Key         {:<28} ✓ presente ({})", var, src.label()),
            None => println!("Key         {:<28} ✗ FALTA", var),
        }
    }
    if !report.provider.is_empty() && report.provider != "local" && report.provider != "gguf" {
        println!("Model       {:<28} (SYNSEMA_LLM_MODEL, {})", report.model.value, report.model.source.label());
        println!("Max tokens  {:<28} ({})", report.max_tokens.value, report.max_tokens.source.label());
        let timeout_note = if report.transport.value == "streaming" {
            " — mide silencio entre bytes"
        } else {
            " — limita la llamada completa"
        };
        println!("Timeout     {:<28} ({}){}", format!("{}s", report.timeout_secs.value), report.timeout_secs.source.label(), timeout_note);
        println!("Transporte  {:<28} ({})", report.transport.value, report.transport.source.label());
        println!("Base URL    {:<28} ({})", report.base_url.value, report.base_url.source.label());
    }
    println!();

    match &report.offline {
        None => {
            println!("Estado: ✅ VIVO — reason/decide/analyze/generate/llm_step van a un modelo real.");
            ExitCode::SUCCESS
        }
        Some(reason) => {
            match reason {
                OfflineReason::KeyMissing { expected_var, misplaced } => {
                    println!("Estado: ✗ OFFLINE — falta {} (las ops devuelven placeholders).", expected_var);
                    if !misplaced.is_empty() {
                        println!("        Hay una clave bajo {} — ¿la guardaste bajo la variable equivocada?", misplaced.join(", "));
                    }
                    println!("        Fix: poné la clave en {} (en el .env o el environ).", expected_var);
                }
                OfflineReason::NoProviderNoKeys => {
                    println!("Estado: ✗ OFFLINE — sin provider ni API keys (las ops devuelven placeholders).");
                    println!("        Fix: seteá UNA de ANTHROPIC_API_KEY / OPENAI_API_KEY / MINIMAX_API_KEY /");
                    println!("        DEEPSEEK_API_KEY (el provider se auto-selecciona), o forzalo con");
                    println!("        SYNSEMA_LLM_PROVIDER. El .env del directorio actual se auto-carga.");
                }
                OfflineReason::LocalModelMissing => {
                    println!("Estado: ✗ OFFLINE — provider `local` necesita SYNSEMA_LLM_MODEL=<ruta al .gguf>.");
                }
                OfflineReason::LocalFeatureMissing => {
                    println!("Estado: ✗ OFFLINE — este binario NO tiene la feature llm-local compilada.");
                    println!("        Fix: cargo install --path crates/synsema-cli --features llm-local --force");
                }
                OfflineReason::UnknownProvider { name } => {
                    println!("Estado: ✗ OFFLINE — provider desconocido '{}'.", name);
                    println!("        Válidos: anthropic, openai, minimax, deepseek, local.");
                }
            }
            ExitCode::from(1)
        }
    }
}

fn cmd_conform(args: &[String]) -> ExitCode {
    // conform [--swarm] [--flat] [--sandbox | --cap-set L] [--profile P] [--audit D]
    //         [--env-file <p>|--no-env-file] <archivo.syn>
    // stdout de conform = SOLO el JSON: el eco vivo de agentes va a stderr.
    synsema_runtime::engine::AGENT_ECHO_TO_STDERR.store(true, std::sync::atomic::Ordering::Relaxed);
    let host = match take_host_flags("conform", &args[2..]) {
        Ok(h) => h,
        Err(code) => return code,
    };
    let mut swarm = false;
    let mut flat = false;
    let mut path: Option<String> = None;
    for a in &host.rest {
        match a.as_str() {
            "--swarm" => swarm = true,
            "--flat" => flat = true,
            p if !p.starts_with("--") => path = Some(p.to_string()),
            other => {
                eprintln!("synsema conform: unknown flag '{}'", other);
                return ExitCode::from(2);
            }
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::from(2);
        }
    };
    // El techo, el perfil y el audit: MISMA semántica que `run`/`test` (hasta v0.6.13
    // conform los ignoraba en silencio — el único subcomando que no sandboxeaba).
    let ceiling = match host.ceiling("conform") {
        Ok(c) => c,
        Err(code) => return code,
    };
    if let Err(code) = host.apply_profile("conform") {
        return code;
    }
    if let Err(code) = host.apply_audit("conform", false) {
        return code;
    }
    host::set_program_args(host.program_args.clone());

    // Leer el archivo UTF-8. El path se usa tal cual como nombre de fuente para que
    // el prefijo de ubicación de los errores sea reproducible contra el oráculo.
    let mut source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    // --flat (o `.fsyn`): pre-procesa sintaxis flat → estándar antes de ejecutar.
    if flat || path.ends_with(".fsyn") {
        source = synsema_core::flat_syntax::translate_flat(&source);
    }

    let ok;
    if swarm {
        // Modo swarm: tras joinear los hilos, agrega blackboard + estados de agentes.
        let dump = run_swarm_dump_ceiled(&source, &path, ceiling);
        let out = serde_json::to_string(&dump.result.output).unwrap_or_else(|_| "[]".to_string());
        let err = serde_json::to_string(&dump.result.errors).unwrap_or_else(|_| "[]".to_string());
        println!(
            "{{\"ok\": {}, \"out\": {}, \"err\": {}, \"blackboard\": {}, \"agents\": {}}}",
            dump.result.success,
            out,
            err,
            json_obj(dump.blackboard),
            json_obj(dump.agents)
        );
        ok = dump.result.success;
    } else {
        let result = run_source_ceiled(&source, &path, ceiling);
        // serde_json escapa correctamente los strings (comillas, \n, control, unicode).
        let out = serde_json::to_string(&result.output).unwrap_or_else(|_| "[]".to_string());
        let err = serde_json::to_string(&result.errors).unwrap_or_else(|_| "[]".to_string());
        println!("{{\"ok\": {}, \"out\": {}, \"err\": {}}}", result.success, out, err);
        ok = result.success;
    }
    // El exit sigue siendo 0 (el fallo del programa va en el JSON); el summary del
    // audit refleja el `ok` del programa.
    audit::summary(if ok { 0 } else { 1 });
    ExitCode::SUCCESS
}

/// serve [--secure] [deploy flags] <archivo.syn>: levanta el server y bloquea hasta kill.
/// Flags de despliegue (Pieza A) que sobreescriben el bloque `serve` (flag > archivo >
/// default): `--port N`, `--domain d1,d2`, `--tls-auto <email>`, `--tls-cert <p>
/// --tls-key <p>`, `--bind <addr>`. Imprime la línea de readiness a STDOUT.
fn cmd_serve(args: &[String]) -> ExitCode {
    let host = match take_host_flags("serve", &args[2..]) {
        Ok(h) => h,
        Err(code) => return code,
    };
    // `serve` no corre bajo el perfil puro (bindear un puerto es OS-facing): exit 2,
    // nunca en silencio.
    match host.apply_profile("serve") {
        Ok(Profile::Pure) => {
            eprintln!("synsema serve: --profile pure is not supported (a server binds a socket); run it natively");
            return ExitCode::from(2);
        }
        Ok(Profile::Native) => {}
        Err(code) => return code,
    }
    if let Err(code) = host.apply_audit("serve", false) {
        return code;
    }
    host::set_program_args(host.program_args.clone());
    let serve_sandbox = host.sandbox;
    let serve_cap_set = host.cap_set.clone();
    let args = host.rest.clone();
    let mut secure = false;
    let mut watch = false;
    let mut path: Option<String> = None;
    let mut ov = ServeOverrides::default();
    let mut i = 0;
    while i < args.len() {
        // Toma el valor del flag siguiente, o error claro (fail-loud).
        macro_rules! next_val {
            ($flag:expr) => {{
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("synsema serve: {} requires a value", $flag);
                        return ExitCode::from(2);
                    }
                }
            }};
        }
        match args[i].as_str() {
            "--secure" => secure = true,
            "--watch" => watch = true,
            // Techo del host para TODO el serve (requests, cron, agentes): mismas
            // reglas que `run` (`--sandbox`/`--cap-set` los parsea `take_host_flags`).
            "--port" => {
                let v = next_val!("--port");
                match v.parse::<u16>() {
                    Ok(p) if p >= 1 => ov.port = Some(p),
                    _ => {
                        eprintln!(
                            "synsema serve: --port must be a valid port (1-65535), got '{}'",
                            v
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            "--domain" => {
                let v = next_val!("--domain");
                let ds: Vec<String> =
                    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                if ds.is_empty() {
                    eprintln!("synsema serve: --domain requires at least one domain");
                    return ExitCode::from(2);
                }
                ov.domains = Some(ds);
            }
            "--tls-auto" => ov.tls_auto_email = Some(next_val!("--tls-auto")),
            "--tls-cert" => ov.tls_cert = Some(next_val!("--tls-cert")),
            "--tls-key" => ov.tls_key = Some(next_val!("--tls-key")),
            "--bind" => ov.bind = Some(next_val!("--bind")),
            p if !p.starts_with("--") => path = Some(p.to_string()),
            other => {
                eprintln!("synsema serve: unknown flag '{}'", other);
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    // Validación fail-loud de combinaciones inválidas (mutua exclusión, par cert/key).
    if let Err(e) = ov.validate() {
        eprintln!("synsema serve: {}", e);
        return ExitCode::from(2);
    }
    ov.ceiling = match build_ceiling(serve_sandbox, serve_cap_set.as_deref()) {
        // `--sandbox` = [stdout, time] como en `run`; un serve necesita además `serve`
        // (si no, jamás podría bindear). `--cap-set` lo lista el operador (p. ej.
        // "stdout,time,serve=8080,net=api.example.com").
        Ok(Some(mut c)) if serve_sandbox => {
            c.push(synsema_capabilities::model::Capability::new(synsema_capabilities::model::CapabilityType::Serve, None));
            Some(c)
        }
        Ok(c) => c,
        Err(e) => {
            eprintln!("synsema serve: {}", e);
            return ExitCode::from(2);
        }
    };

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::from(2);
        }
    };

    // --watch: supervisor de dev — corre el serve en un proceso hijo y lo reinicia
    // cuando cambia cualquier `.syn` bajo el directorio del programa. Los templates
    // y estáticos YA se recargan por request (no necesitan reinicio); esto cierra el
    // único hueco del loop de dev (cambios de rutas/lógica en el .syn).
    if watch {
        return run_serve_watch(&path);
    }

    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };

    // Bloquea mientras el server corra; sólo retorna si no se levantó o falló.
    let result = run_serve_program_with_overrides(&source, &path, secure, ov);
    if !result.success {
        for e in &result.errors {
            eprintln!("{}", e);
        }
        audit::summary(1);
        return ExitCode::from(1);
    }
    audit::summary(0);
    ExitCode::SUCCESS
}

/// run <archivo.syn> [--flat] [--explain] [--format human|json]: ejecuta el programa,
/// imprime la salida, exit≠0 si falla.
///
/// `--explain` activa el diagnóstico rico (ubicación, contexto de fuente, variables
/// visibles, sugerencias, clasificación) en caso de error. Sin la flag, el
/// comportamiento es el de siempre: la línea corta `Runtime error: ...` (apta para
/// scripting/CI). Con `--explain` el formato por defecto es humano (`format_human`); con
/// `--format json` se emite JSON estructurado (`format_agent`) para herramientas/agentes.
fn cmd_run(args: &[String]) -> ExitCode {
    let host = match take_host_flags("run", &args[2..]) {
        Ok(h) => h,
        Err(code) => return code,
    };
    let mut flat = false;
    let mut explain = false;
    let mut fmt_json = false; // --format json: con --explain, diagnóstico JSON; sin él, el INFORME
    let mut path: Option<String> = None;
    let mut program_args = host.program_args.clone();
    let rest = &host.rest;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--flat" => flat = true,
            "--explain" => explain = true,
            "--format=json" => fmt_json = true,
            "--format=human" => fmt_json = false,
            // `--format <valor>` con lookahead, igual que `--env-file`.
            "--format" => {
                match rest.get(i + 1).map(String::as_str) {
                    Some("json") => fmt_json = true,
                    Some("human") => fmt_json = false,
                    Some(other) => {
                        eprintln!(
                            "synsema run: --format must be 'human' or 'json', got '{}'",
                            other
                        );
                        return ExitCode::from(2);
                    }
                    None => {
                        eprintln!("synsema run: --format requires a value (human|json)");
                        return ExitCode::from(2);
                    }
                }
                i += 1; // consume el valor
            }
            // `--provider <name>`: elige el proveedor LLM por flag (gana sobre env/.env,
            // setea SYNSEMA_LLM_PROVIDER antes de cablear el LLM). Forma `=` también.
            "--provider" => match rest.get(i + 1) {
                Some(name) if !name.starts_with("--") => {
                    std::env::set_var("SYNSEMA_LLM_PROVIDER", name);
                    i += 1;
                }
                _ => {
                    eprintln!("synsema run: --provider requires a value (anthropic|openai|minimax|deepseek)");
                    return ExitCode::from(2);
                }
            },
            p if p.starts_with("--provider=") => {
                std::env::set_var("SYNSEMA_LLM_PROVIDER", p.trim_start_matches("--provider="));
            }
            // El programa: un path, o `-` (fuente por stdin). Lo que siga al programa
            // (sin `--`) también es del programa, salvo que parezca un flag.
            p if p == "-" || !p.starts_with('-') => {
                if path.is_some() {
                    program_args.push(p.to_string());
                } else {
                    path = Some(p.to_string());
                }
            }
            other => {
                // Un flag desconocido NUNCA se traga: `run --audit json p.syn` corriendo
                // sin audit (y con `json` como path) sería un agujero, no una comodidad.
                eprintln!("synsema run: unknown flag '{}'\n{}", other, USAGE);
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("uso: synsema run [--flat] [--explain] [--format human|json] [--provider <name>] [--sandbox | --cap-set <list>] [--profile native|pure] [--audit json|<ruta>|fd:N] <archivo.syn | -> [-- args...]");
            return ExitCode::from(2);
        }
    };
    let report_mode = fmt_json && !explain;
    let (mut source, filename) = if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("synsema run: could not read stdin: {}", e);
            return ExitCode::from(1);
        }
        (buf, host.filename.clone().unwrap_or_else(|| "<stdin>".to_string()))
    } else {
        match std::fs::read_to_string(&path) {
            Ok(s) => (s, path.clone()),
            Err(e) => {
                eprintln!("no se pudo leer '{}': {}", path, e);
                return ExitCode::from(1);
            }
        }
    };
    if flat || filename.ends_with(".fsyn") {
        source = synsema_core::flat_syntax::translate_flat(&source);
    }

    // Techo de capabilities del host (--sandbox/--cap-set): opt-in, defense-in-depth.
    let ceiling = match host.ceiling("run") {
        Ok(c) => c,
        Err(code) => return code,
    };
    if let Err(code) = host.apply_profile("run") {
        return code;
    }
    if let Err(code) = host.apply_audit("run", report_mode) {
        return code;
    }
    host::set_program_args(program_args);

    // Camino opt-in: diagnóstico rico. Reusa la API pública del runtime; el default
    // (línea corta) queda intacto más abajo para no romper scripting/CI.
    if explain {
        let run = run_with_diagnostics_ceiled(&source, &filename, ceiling);
        for line in &run.result.output {
            println!("{}", line);
        }
        if !run.result.success {
            if let Some(diag) = run.diagnostics.first() {
                // Error del MAIN → diagnóstico rico (humano o JSON).
                if fmt_json {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&diag.format_agent()).unwrap_or_default()
                    );
                } else {
                    eprintln!("{}", diag.format_human());
                }
                // Además, los errores de agente aislados (DE-014): el main pudo fallar y,
                // aparte, algún agente terminar en ERROR. Su línea corta se imprime junto
                // al diagnóstico (la "Runtime error:" del main ya la cubre el diagnóstico).
                for e in run.result.errors.iter().filter(|e| e.starts_with("Agent error [")) {
                    eprintln!("{}", e);
                }
            } else {
                // Sin diagnóstico del main: o bien sólo fallaron agentes (DE-014:
                // `Agent error [<id>]`), o un `give`/`stop` top-level (línea corta). En
                // ambos casos imprimir los errores. Nunca quedarse sin output.
                for e in &run.result.errors {
                    eprintln!("{}", e);
                }
            }
            audit::summary(1);
            return ExitCode::from(1);
        }
        audit::summary(0);
        return ExitCode::SUCCESS;
    }

    // `run --format json` (sin --explain): el INFORME con la forma de `syn.run()` de wasm
    // — `{ok, output, errors, audit, exit, llm_tokens}` — como ÚNICO contenido de stdout.
    // La salida del programa se colecta (no va en vivo). Es el transporte de
    // `run_program` y una API para cualquier runner.
    if report_mode {
        let result = run_program_ceiled_opts(&source, &filename, ceiling, false);
        let exit = if result.success { 0 } else { 1 };
        let report = serde_json::json!({
            "ok": result.success,
            "output": result.output,
            "errors": result.errors,
            "audit": audit::collected(),
            "exit": exit,
            "llm_tokens": synsema_runtime::llm_providers::llm_tokens_total(),
        });
        println!("{}", report);
        audit::summary(exit);
        return ExitCode::from(exit as u8);
    }

    // Camino normal: swarm real (DE-011). Los `spawn` corren en hilos aislados; un agente
    // que falla NO tumba el main ni trunca su salida. Sale ≠0 si el main falla o si algún
    // agente terminó en ERROR. El techo del host (si hay) se propaga a los agentes.
    let result = run_program_ceiled(&source, &filename, ceiling);
    for line in &result.output {
        println!("{}", line);
    }
    if !result.success {
        for e in &result.errors {
            eprintln!("{}", e);
        }
        audit::summary(1);
        return ExitCode::from(1);
    }
    audit::summary(0);
    ExitCode::SUCCESS
}

/// test [-v] [--flat] <archivo.syn | dir>: corre los bloques `test` y reporta ✓/✗.
/// Exit 0 si todos pasan; 1 si alguno falla; 2 por error de uso/archivo ilegible.
fn cmd_test(args: &[String]) -> ExitCode {
    let host = match take_host_flags("test", &args[2..]) {
        Ok(h) => h,
        Err(code) => return code,
    };
    let mut flat = false;
    let mut verbose = false;
    let mut path: Option<String> = None;
    for a in &host.rest {
        match a.as_str() {
            "--flat" => flat = true,
            "-v" | "--verbose" => verbose = true,
            p if !p.starts_with('-') => path = Some(p.to_string()),
            other => {
                eprintln!("synsema test: unknown flag '{}'", other);
                return ExitCode::from(2);
            }
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("uso: synsema test [-v] [--flat] [--sandbox | --cap-set <list>] [--profile native|pure] [--audit json|<ruta>|fd:N] <archivo.syn | dir>");
            return ExitCode::from(2);
        }
    };
    // Techo de capabilities del host (--sandbox/--cap-set): opt-in, defense-in-depth.
    let ceiling = match host.ceiling("test") {
        Ok(c) => c,
        Err(code) => return code,
    };
    if let Err(code) = host.apply_profile("test") {
        return code;
    }
    if let Err(code) = host.apply_audit("test", false) {
        return code;
    }
    host::set_program_args(host.program_args.clone());
    let files = match collect_syn_files(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("no se pudo acceder a '{}': {}", path, e);
            return ExitCode::from(2);
        }
    };
    if files.is_empty() {
        eprintln!("no se encontraron archivos .syn en '{}'", path);
        return ExitCode::from(2);
    }
    let multi = files.len() > 1;
    let mut total_passed = 0usize;
    let mut total_failed = 0usize;
    for file in &files {
        let mut source = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("no se pudo leer '{}': {}", file, e);
                total_failed += 1;
                continue;
            }
        };
        if flat || file.ends_with(".fsyn") {
            source = synsema_core::flat_syntax::translate_flat(&source);
        }
        if multi {
            println!("{}:", file);
        }
        let report = run_tests_ceiled(&source, file, ceiling.clone());
        print_test_report(&report, verbose);
        total_passed += report.passed;
        total_failed += report.failed;
    }
    let total = total_passed + total_failed;
    println!("{} passed, {} failed ({} total)", total_passed, total_failed, total);
    if total_failed > 0 {
        audit::summary(1);
        ExitCode::from(1)
    } else {
        audit::summary(0);
        ExitCode::SUCCESS
    }
}

/// Imprime el reporte de un archivo: ✓/✗ por test (+ stdout de los tests sólo con `-v`).
fn print_test_report(report: &TestReport, verbose: bool) {
    if verbose {
        for line in &report.output {
            println!("  | {}", line);
        }
    }
    for o in &report.outcomes {
        if o.passed {
            println!("  \u{2713} {}", o.name); // ✓
        } else {
            let msg = o.message.as_deref().unwrap_or("failed");
            println!("  \u{2717} {}: {}", o.name, msg); // ✗
        }
    }
}

/// Recolecta archivos `.syn`: un archivo solo, o todos los `*.syn` de un dir (recursivo).
fn collect_syn_files(path: &str) -> std::io::Result<Vec<String>> {
    let p = std::path::Path::new(path);
    if p.is_file() {
        return Ok(vec![path.to_string()]);
    }
    if p.is_dir() {
        let mut out = Vec::new();
        collect_syn_dir(p, &mut out)?;
        out.sort();
        return Ok(out);
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no es un archivo ni un directorio"))
}

fn collect_syn_dir(dir: &std::path::Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_syn_dir(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("syn") {
            out.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// `serve --watch`: proceso hijo `synsema serve <mismos args sin --watch>` + polling
/// de mtimes de los `.syn` bajo el directorio del programa. Cambio → kill + respawn.
/// Si el hijo muere solo (p.ej. error de arranque), se espera al PRÓXIMO cambio para
/// reintentar (nada de crash-loop girando).
fn run_serve_watch(entry: &str) -> ExitCode {
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime};

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("synsema serve --watch: could not resolve current exe: {}", e);
            return ExitCode::from(1);
        }
    };
    // argv del hijo = argv original sin `--watch` y sin el nombre del binario.
    let child_args: Vec<String> =
        std::env::args().skip(1).filter(|a| a != "--watch").collect();
    let entry_path = std::path::PathBuf::from(entry);
    let watch_root = entry_path
        .parent()
        .map(|p| p.to_path_buf())
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let snapshot = |root: &std::path::Path| -> HashMap<String, SystemTime> {
        let mut files: Vec<String> = vec![entry.to_string()];
        let _ = collect_syn_dir(root, &mut files);
        let mut map = HashMap::new();
        for f in files {
            if let Ok(meta) = std::fs::metadata(&f) {
                if let Ok(m) = meta.modified() {
                    map.insert(f, m);
                }
            }
        }
        map
    };
    let changed_file = |old: &HashMap<String, SystemTime>, new: &HashMap<String, SystemTime>| {
        for (f, m) in new {
            match old.get(f) {
                None => return Some(f.clone()),
                Some(om) if om != m => return Some(f.clone()),
                _ => {}
            }
        }
        old.keys().find(|f| !new.contains_key(*f)).cloned()
    };

    loop {
        let mut snap = snapshot(&watch_root);
        let mut child = match std::process::Command::new(&exe).args(&child_args).spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("synsema serve --watch: could not spawn server: {}", e);
                return ExitCode::from(1);
            }
        };
        // Vigilar: cambio de archivos → reinicio; hijo muerto → esperar un cambio.
        let reason: String;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = snapshot(&watch_root);
            if let Some(f) = changed_file(&snap, &now) {
                let _ = child.kill();
                let _ = child.wait();
                reason = f;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!(
                    "[watch] server exited ({}). Waiting for a file change to retry...",
                    status
                );
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    let now = snapshot(&watch_root);
                    if changed_file(&snap, &now).is_some() {
                        break;
                    }
                    snap = now;
                }
                reason = "restart after exit".to_string();
                break;
            }
            snap = now;
        }
        eprintln!("[watch] {} changed — restarting server", reason);
    }
}

/// check <archivo.syn>: parsea sin ejecutar; reporta cantidad de statements o el error.
fn cmd_check(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema check <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    use synsema_core::parser::CompileError;
    match synsema_core::parser::parse_source(&source, &path) {
        Ok(program) => {
            // Chequeo estático profundo: módulos `use` (recursivo, mismas reglas que
            // el runtime) + templates `render("literal")` (existen y parsean). Un
            // import roto o un template con typo falla en `check`, no en producción.
            match synsema_core::templates::check_program_static(&program, &path) {
                Ok((modules, templates)) => {
                    let mut extras = Vec::new();
                    if modules > 0 {
                        extras.push(format!("{} module(s)", modules));
                    }
                    if templates > 0 {
                        extras.push(format!("{} template(s)", templates));
                    }
                    if extras.is_empty() {
                        println!("OK: {} statements parsed.", program.statements.len());
                    } else {
                        println!(
                            "OK: {} statements parsed. {} validated.",
                            program.statements.len(),
                            extras.join(" + ")
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        Err(CompileError::Lex(e)) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
        Err(CompileError::Parse(e)) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// openapi <archivo.syn> [--out openapi.json] [--base-url URL]: el `/openapi.json` que
/// el server publicaría, SIN ejecutar el programa ni abrir el puerto (para CI/build).
/// Mismo emisor que el server; las rutas salen del AST (`route` + `mount` resueltos
/// sintácticamente). Exit 2 si el archivo no tiene `serve`.
fn cmd_openapi(args: &[String]) -> ExitCode {
    let mut path: Option<String> = None;
    let mut out: Option<String> = None;
    let mut base: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            "--base-url" => {
                i += 1;
                base = args.get(i).cloned();
            }
            other => path = Some(other.to_string()),
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("uso: synsema openapi <archivo.syn> [--out openapi.json] [--base-url URL]");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    let program = match synsema_core::parser::parse_source(&source, &path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };
    use synsema_core::route_meta::{api_routes_static, StaticProgram};
    let sp = match StaticProgram::load(program, &path) {
        Ok(sp) => sp,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };
    let (info, routes) = match api_routes_static(&sp) {
        Ok(Some(x)) => x,
        Ok(None) => {
            eprintln!("{}: no 'serve' block — nothing to describe", path);
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::from(1);
        }
    };
    let api = synsema_stdlib::discovery::ApiInfo {
        title: synsema_stdlib::discovery::ApiInfo::title_of(info.describe_about.as_deref(), info.intent.as_deref()),
        description: info.intent.clone(),
        version: info.describe_version.clone().unwrap_or_else(|| "0.0.0".to_string()),
        base_url: base.or_else(|| info.domain.as_ref().map(|d| format!("https://{}", d))),
        has_auth: info.has_auth_handler && routes.iter().any(|r| r.requires_auth),
        describe_api: info.describe_api.clone(),
    };
    let text = synsema_stdlib::discovery::openapi_text(&api, &routes);
    match out {
        Some(f) => {
            if let Err(e) = std::fs::write(&f, text.as_bytes()) {
                eprintln!("no se pudo escribir '{}': {}", f, e);
                return ExitCode::from(1);
            }
            eprintln!("{}: {} operation(s) → {}", path, routes.len(), f);
        }
        None => println!("{}", text),
    }
    ExitCode::SUCCESS
}

/// tokens <archivo.syn>: muestra el stream de tokens (debug).
fn cmd_tokens(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema tokens <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    match synsema_core::lexer::Lexer::new(&source, &path).tokenize() {
        Ok(tokens) => {
            for tok in &tokens {
                println!("  {:?}", tok);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Lexer error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// ast <archivo.syn>: muestra el AST parseado (debug).
fn cmd_ast(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("uso: synsema ast <archivo.syn>");
            return ExitCode::from(2);
        }
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo leer '{}': {}", path, e);
            return ExitCode::from(1);
        }
    };
    use synsema_core::parser::CompileError;
    match synsema_core::parser::parse_source(&source, &path) {
        Ok(program) => {
            for stmt in &program.statements {
                println!("{:#?}", stmt.kind);
            }
            ExitCode::SUCCESS
        }
        Err(CompileError::Lex(e)) => {
            eprintln!("Lexer error: {}", e);
            ExitCode::from(1)
        }
        Err(CompileError::Parse(e)) => {
            eprintln!("Parse error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// daemon <start|stop|status|logs|restart> [program.syn]: gestiona procesos background.
fn cmd_daemon(args: &[String]) -> ExitCode {
    let action = match args.get(2).map(String::as_str) {
        Some(a) => a,
        None => {
            eprintln!("uso: synsema daemon <start|stop|status|logs|restart> [program.syn]");
            return ExitCode::from(2);
        }
    };

    if action == "status" {
        let statuses = daemon::daemon_status();
        println!("{}", daemon::format_status_table(&statuses));
        return ExitCode::SUCCESS;
    }

    let target = match args.get(3) {
        Some(t) => t.clone(),
        None => {
            eprintln!("uso: synsema daemon {} <program.syn>", action);
            return ExitCode::from(2);
        }
    };
    let extra: Vec<String> = args.get(4..).map(|s| s.to_vec()).unwrap_or_default();

    match action {
        "start" => {
            let r = daemon::daemon_start(&target, &extra);
            println!("{}", r.message);
            if r.status == "error" {
                return ExitCode::from(1);
            }
        }
        "stop" => {
            let r = daemon::daemon_stop(&target);
            println!("{}", r.message);
        }
        "restart" => {
            let r = daemon::daemon_restart(&target, &extra);
            println!("{}", r.message);
            if r.status == "error" {
                return ExitCode::from(1);
            }
        }
        "logs" => {
            let lines = args.get(4).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
            println!("{}", daemon::daemon_logs(&target, lines));
        }
        other => {
            eprintln!("acción de daemon desconocida: {}", other);
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
