//! `synsema build <main.syn> -o <out> [--include <p>]… [--sandbox | --cap-set L]
//! [--profile native|pure] [--engine-binary <synsema>]`: un ejecutable único = el motor
//! + el programa (y su clausura de `use`, sus templates y los `--include`) anexados con un
//! trailer (`synsema_core::bundle`). El binario resultante corre el programa con `argv`
//! como `args()`, bajo el techo y el perfil HORNEADOS; `<out> --engine …` sigue siendo el
//! CLI del motor.
//!
//! El bundle es cerrado: un `use` que el resolutor estático no puede decidir es un error
//! del build, no un "lo busco en disco después". Sin compresión, sin strip: el tamaño es
//! el del motor.
//!
//! Escritorio: `--serve` hornea los settings de despliegue
//! (`manifest.serve`, bind explícito por `--bind` o por la cláusula `bind "…"`); `.exe`
//! automático si el MOTOR es PE; `--no-console` e `--icon` operan sobre la copia del motor
//! ANTES de anexar el bundle (`pe.rs`); `--bundle` escribe el `.app` (Mach-O) o el directorio
//! con `.desktop` + `install.sh` (ELF) (`bundle_out.rs`, `icns.rs`). Todo mira el formato del
//! artefacto, no el host que construye.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use synsema_core::bundle::{self, Bundle, BundleMode, Manifest, ServeSettings};
use synsema_core::templates::{program_closure_with, template_closure};

use crate::bundle_out::{self, EngineFormat};
use crate::{icns, pe, HostFlags};

const USAGE_BUILD: &str = "uso: synsema build <main.syn> -o <salida> [--include <archivo|dir|patrón>]... [--sandbox | --cap-set <list> | --deterministic] [--profile native|pure] [--audit json|<ruta>|fd:N|unix:<ruta>] [--engine-binary <ruta>] [--serve [--bind <addr>] [--port N] [--domain d1,d2] [--tls-auto <email> | --tls-cert <p> --tls-key <p>] [--secure]] [--no-console] [--icon <svg|png|ico>] [--bundle [--name <nombre>] [--id <com.ejemplo.app>]]";

/// Los flags de escritorio. Todos
/// miran el FORMATO DEL MOTOR donante (PE / Mach-O / ELF), no el host que construye.
#[derive(Debug, Clone, Default)]
pub struct DesktopOptions {
    /// `--no-console`: PE subsistema CONSOLE → GUI (sin ventana de consola).
    pub no_console: bool,
    /// `--icon <svg|png|ico>`: ícono del `.exe` (sección `.rsrc`), del `.app` (`.icns`) o del
    /// lanzador Linux (PNG 256/512).
    pub icon: Option<String>,
    /// `--bundle`: Mach-O → `Nombre.app/`, ELF → `<stem>/` + `install.sh`, PE → nada que hacer.
    pub bundle: bool,
    /// `--name`: nombre visible del bundle (default: el stem de `-o`).
    pub name: Option<String>,
    /// `--id`: identificador inverso (default `dev.synsema.<stem>`).
    pub id: Option<String>,
}

/// Lo que `build()` produjo, para la línea `built …`.
pub struct BuildOutcome {
    /// Ruta final: el binario, el `.app` o el directorio del bundle.
    pub out: PathBuf,
    pub files: usize,
    pub bytes: u64,
    /// Los settings de serve HORNEADOS (con el bind ya resuelto: `--bind` o la cláusula).
    pub serve: Option<ServeSettings>,
    /// Fragmentos de escritorio para la línea `built …` (`no-console`, `icon …`, `bundle …`).
    pub desktop: Vec<String>,
    /// Avisos (stderr) que no son errores: `+x` desde Windows, bundle sin ícono.
    pub notes: Vec<String>,
}

pub fn cmd_build(host: HostFlags) -> ExitCode {
    let mut out: Option<String> = None;
    let mut includes: Vec<String> = Vec::new();
    let mut engine_binary: Option<String> = None;
    let mut main: Option<String> = None;
    let mut serve = false;
    let mut serve_secure = false;
    let mut serve_flags: Vec<(String, String)> = Vec::new();
    let mut desktop = DesktopOptions::default();
    let rest = host.rest.clone();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-o" | "--out" => {
                i += 1;
                match rest.get(i) {
                    Some(v) if !v.starts_with('-') => out = Some(v.clone()),
                    _ => {
                        eprintln!("synsema build: -o requires a path");
                        return ExitCode::from(2);
                    }
                }
            }
            p if p.starts_with("--out=") => out = Some(p.trim_start_matches("--out=").to_string()),
            "--include" => {
                i += 1;
                match rest.get(i) {
                    Some(v) if !v.starts_with('-') => includes.push(v.clone()),
                    _ => {
                        eprintln!("synsema build: --include requires a path or pattern");
                        return ExitCode::from(2);
                    }
                }
            }
            p if p.starts_with("--include=") => includes.push(p.trim_start_matches("--include=").to_string()),
            "--engine-binary" => {
                i += 1;
                match rest.get(i) {
                    Some(v) if !v.starts_with('-') => engine_binary = Some(v.clone()),
                    _ => {
                        eprintln!("synsema build: --engine-binary requires a path");
                        return ExitCode::from(2);
                    }
                }
            }
            p if p.starts_with("--engine-binary=") => {
                engine_binary = Some(p.trim_start_matches("--engine-binary=").to_string())
            }
            // `--serve` + los flags de despliegue de `synsema serve`, HORNEADOS (en modo
            // programa todo argv es del programa, así que se deciden al construir).
            "--serve" => serve = true,
            "--secure" => serve_secure = true,
            "--bind" | "--port" | "--domain" | "--tls-auto" | "--tls-cert" | "--tls-key" => {
                let flag = rest[i].clone();
                i += 1;
                match rest.get(i) {
                    Some(v) if !v.starts_with('-') => serve_flags.push((flag, v.clone())),
                    _ => {
                        eprintln!("synsema build: {} requires a value", flag);
                        return ExitCode::from(2);
                    }
                }
            }
            // Escritorio (§3.6–§3.9): cirugía sobre la copia del motor y layouts de bundle.
            "--no-console" => desktop.no_console = true,
            "--bundle" => desktop.bundle = true,
            "--icon" | "--name" | "--id" => {
                let flag = rest[i].clone();
                i += 1;
                match rest.get(i) {
                    Some(v) if !v.starts_with('-') => match flag.as_str() {
                        "--icon" => desktop.icon = Some(v.clone()),
                        "--name" => desktop.name = Some(v.clone()),
                        _ => desktop.id = Some(v.clone()),
                    },
                    _ => {
                        eprintln!("synsema build: {} requires a value", flag);
                        return ExitCode::from(2);
                    }
                }
            }
            p if p.starts_with("--icon=") => desktop.icon = Some(p.trim_start_matches("--icon=").to_string()),
            p if p.starts_with("--name=") => desktop.name = Some(p.trim_start_matches("--name=").to_string()),
            p if p.starts_with("--id=") => desktop.id = Some(p.trim_start_matches("--id=").to_string()),
            p if p.starts_with('-') => {
                eprintln!("synsema build: unknown flag '{}'\n{}", p, USAGE_BUILD);
                return ExitCode::from(2);
            }
            p => {
                if main.is_some() {
                    eprintln!("synsema build: only one program per build (got '{}')\n{}", p, USAGE_BUILD);
                    return ExitCode::from(2);
                }
                main = Some(p.to_string());
            }
        }
        i += 1;
    }
    let (Some(main), Some(out)) = (main, out) else {
        eprintln!("{}", USAGE_BUILD);
        return ExitCode::from(2);
    };
    // v0.6.20 — `--audit` se HORNEA (como --cap-set/--profile): el binario emite el stream al
    // correr. `--deterministic` = perfil puro + techo sólo stdout, y excluye a los demás.
    if host.deterministic && (host.sandbox || host.cap_set.is_some() || matches!(host.profile.as_deref(), Some("native"))) {
        eprintln!("synsema build: --deterministic already fixes the profile (pure) and the ceiling (stdout); drop --sandbox/--cap-set/--profile native");
        return ExitCode::from(2);
    }
    let profile = host
        .profile
        .clone()
        .unwrap_or_else(|| if host.deterministic { "pure".to_string() } else { "native".to_string() });
    if synsema_runtime::host::Profile::parse(&profile).is_none() {
        eprintln!("synsema build: --profile must be 'native' or 'pure', got '{}'", profile);
        return ExitCode::from(2);
    }
    // El techo horneado se VALIDA acá con el mismo parser que `run` y se guarda como
    // texto (misma sintaxis) para que el manifest sea legible.
    let ceiling_text: Option<String> = if host.deterministic {
        Some("stdout".to_string())
    } else if host.sandbox {
        Some("sandbox".to_string())
    } else {
        host.cap_set.clone()
    };
    if let Err(e) = synsema_capabilities::model::build_ceiling(host.sandbox, host.cap_set.as_deref()) {
        eprintln!("synsema build: {}", e);
        return ExitCode::from(2);
    }

    // `--serve`: el binario corre el runtime de `synsema serve`. Fail-loud en el build, no al
    // correr: los flags de despliegue sin `--serve` no significan nada; `--serve` sin `--bind`
    // no adivina en qué interfaz escucha un distribuible; el perfil puro no bindea sockets.
    if !serve && (serve_secure || !serve_flags.is_empty()) {
        let first = serve_flags.first().map(|(f, _)| f.as_str()).unwrap_or("--secure");
        eprintln!("synsema build: {} applies to --serve builds (add --serve)", first);
        return ExitCode::from(2);
    }
    let serve_settings = if serve {
        if profile == "pure" {
            eprintln!("synsema build: --serve --profile pure is not supported (a server binds a socket)");
            return ExitCode::from(2);
        }
        match serve_settings_from_flags(&serve_flags, serve_secure) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("synsema build: {}", e);
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    // `--name`/`--id` describen un bundle: sin `--bundle` no significan nada (fail-loud).
    if (desktop.name.is_some() || desktop.id.is_some()) && !desktop.bundle && !out.to_ascii_lowercase().ends_with(".app") {
        let flag = if desktop.name.is_some() { "--name" } else { "--id" };
        eprintln!("synsema build: {} applies to --bundle builds (add --bundle)", flag);
        return ExitCode::from(2);
    }

    match build(&main, &out, &includes, engine_binary.as_deref(), ceiling_text, &profile, host.audit.clone(), serve_settings, &desktop) {
        Ok(r) => {
            let mut how: Vec<String> = Vec::new();
            if let Some(s) = &r.serve {
                let mut h = format!("serve · bind {}", s.bind);
                if let Some(p) = s.port {
                    h.push_str(&format!(" · port {}", p));
                }
                if let Some(d) = &s.domains {
                    h.push_str(&format!(" · domain {}", d.join(",")));
                }
                if s.tls_auto.is_some() {
                    h.push_str(" · tls auto");
                } else if s.tls_cert.is_some() {
                    h.push_str(" · tls cert");
                }
                if s.secure {
                    h.push_str(" · secure");
                }
                how.push(h);
            }
            how.extend(r.desktop.iter().cloned());
            if how.is_empty() {
                println!("built {} ({} files, {} bytes)", r.out.display(), r.files, r.bytes);
            } else {
                println!("built {} ({} files, {} bytes) · {}", r.out.display(), r.files, r.bytes, how.join(" · "));
            }
            for n in &r.notes {
                eprintln!("synsema build: note: {}", n);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("synsema build: {}", e);
            ExitCode::from(2)
        }
    }
}

/// Los flags de despliegue de `synsema build --serve` → lo que se hornea. Misma validación
/// que `synsema serve` (`ServeOverrides::validate`): puerto 1-65535, `--tls-auto` excluyente
/// con `--tls-cert/--tls-key`, cert y key juntos. `--bind` es obligatorio.
fn serve_settings_from_flags(flags: &[(String, String)], secure: bool) -> Result<ServeSettings, String> {
    let mut s = ServeSettings { secure, ..Default::default() };
    for (flag, v) in flags {
        match flag.as_str() {
            "--bind" => s.bind = v.clone(),
            "--port" => {
                s.port = Some(
                    v.parse::<u16>()
                        .ok()
                        .filter(|p| *p >= 1)
                        .ok_or_else(|| format!("--port must be a valid port (1-65535), got '{}'", v))?,
                )
            }
            "--domain" => {
                let ds: Vec<String> = v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                if ds.is_empty() {
                    return Err("--domain requires at least one domain".to_string());
                }
                s.domains = Some(ds);
            }
            "--tls-auto" => s.tls_auto = Some(v.clone()),
            "--tls-cert" => s.tls_cert = Some(v.clone()),
            "--tls-key" => s.tls_key = Some(v.clone()),
            other => return Err(format!("unknown serve flag '{}'", other)),
        }
    }
    // `bind` vacío acá es válido: el build lo toma de la cláusula `bind "…"` del serve block
    // (literal) y sólo si tampoco está ahí falla — ver `build()`.
    let ov = synsema_runtime::serve::ServeOverrides {
        port: s.port,
        domains: s.domains.clone(),
        tls_auto_email: s.tls_auto.clone(),
        tls_cert: s.tls_cert.clone(),
        tls_key: s.tls_key.clone(),
        bind: Some(s.bind.clone()),
        // v0.6.42 — no se hornea: el binario usa la cláusula `trust proxy` de su programa.
        trust_proxy: None,
        ceiling: None,
        // `--attested` no se hornea en el binario: se decide donde corre (como el techo).
        attested: false,
        // v0.6.46 (E6-h): el auditor tampoco: el binario lo lee de `SYNSEMA_AUDITOR_KEY` al correr.
        auditor: None,
        receipt: None,
        sealed_bytes: None,
    };
    ov.validate()?;
    Ok(s)
}

fn build(
    main: &str,
    out: &str,
    includes: &[String],
    engine_binary: Option<&str>,
    ceiling: Option<String>,
    profile: &str,
    audit: Option<String>,
    mut serve: Option<ServeSettings>,
    desktop: &DesktopOptions,
) -> Result<BuildOutcome, String> {
    let main_path = Path::new(main);
    if !main_path.is_file() {
        return Err(format!("cannot read '{}'", main));
    }
    let main_abs = main_path.canonicalize().map_err(|e| format!("cannot resolve '{}': {}", main, e))?;
    let main_dir = main_abs.parent().ok_or_else(|| "main program has no folder".to_string())?.to_path_buf();
    // v0.6.58 (§9, D-14): la raíz del bundle es la del proyecto (la carpeta de su `synsema.json`),
    // no la del `.syn`: un `use "../lib/y.syn"` desde `scripts/` queda adentro (B6). Sin proyecto,
    // la carpeta del `.syn`, como siempre.
    let project = synsema_core::project::resolve(main)?;
    let root = match (&project.manifest, &project.root) {
        (Some(_), Some(r)) => r.canonicalize().map_err(|e| format!("cannot resolve the bundle root: {}", e))?,
        _ => main_dir.clone(),
    };
    let main_name = main_abs
        .strip_prefix(&root)
        .map_err(|_| format!("'{}' is not under the project root {}", main, root.display()))?
        .to_string_lossy()
        .replace('\\', "/");
    if main_name.is_empty() {
        return Err("main program has no file name".to_string());
    }
    if !main_name.ends_with(".syn") {
        return Err(format!("main program must be a .syn file: '{}'", main_name));
    }

    // Todo se lee desde el directorio actual, como `run` (M5): ver `collect`.
    let (entries, bind_lit, packages) = collect(main, &main_name, &root, Path::new(out), includes, serve.is_some())?;
    // El bind horneado: `--bind` gana; si no vino, la cláusula `bind "…"` literal del serve
    // block; sin ninguna de las dos, un distribuible no adivina en qué interfaz escucha.
    if let Some(s) = serve.as_mut() {
        if s.bind.is_empty() {
            match bind_lit {
                Some(b) => s.bind = b,
                None => {
                    return Err("--serve needs to know where the server listens: pass --bind 127.0.0.1 (local app) or --bind 0.0.0.0 (public), or add `bind \"127.0.0.1\"` to the serve block".to_string())
                }
            }
        }
    }

    let engine_path: PathBuf = match engine_binary {
        Some(p) => PathBuf::from(p),
        None => std::env::current_exe().map_err(|e| format!("cannot resolve the engine binary: {}", e))?,
    };
    if bundle::is_built(&engine_path) {
        return Err(format!(
            "'{}' is already a built program — build from the plain `synsema` binary (or pass --engine-binary)",
            engine_path.display()
        ));
    }
    let mut engine_bytes = std::fs::read(&engine_path)
        .map_err(|e| format!("cannot read the engine binary {}: {}", engine_path.display(), e))?;
    // Un solo sitio decide el formato del ARTEFACTO; `.exe`, `--no-console`, `--icon` y
    // `--bundle` lo consultan (un donante Linux construido desde Windows no recibe `.exe`).
    let format = bundle_out::engine_format(&engine_bytes);

    // Salida: `.exe` automático si el motor es PE y `-o` no tiene extensión; `-o x.app` sobre
    // mach-O es sinónimo de `--bundle` (y un error claro sobre cualquier otro formato).
    let mut out_path = PathBuf::from(out);
    let mut want_bundle = desktop.bundle;
    let is_app = out_path.extension().is_some_and(|e| e.eq_ignore_ascii_case("app"));
    if is_app {
        if format != EngineFormat::MachO {
            return Err(format!(
                "-o '{}' ends with .app but the engine is {}; .app bundles are for macOS (Mach-O) engines",
                out,
                format.describe()
            ));
        }
        want_bundle = true;
        out_path.set_extension("");
    } else if format == EngineFormat::Pe && out_path.extension().is_none() {
        out_path.set_extension("exe");
    }
    let stem = out_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("-o '{}' has no file name", out))?;

    // Validaciones de escritorio contra el formato del motor: antes de escribir nada.
    if desktop.no_console && format != EngineFormat::Pe {
        return Err(format!("--no-console applies to Windows executables (PE); the engine is {}", format.describe()));
    }
    if want_bundle && format == EngineFormat::Unknown {
        return Err(format!("--bundle: the engine is {}", format.describe()));
    }
    let icon = match &desktop.icon {
        Some(p) => {
            match format {
                EngineFormat::Unknown => return Err(format!("--icon: the engine is {}", format.describe())),
                EngineFormat::MachO | EngineFormat::Elf if !want_bundle => {
                    return Err("--icon on a macOS/Linux engine needs --bundle (the icon lives in the .app / the launcher entry, not in the binary)".to_string())
                }
                _ => {}
            }
            Some(load_icon(p)?)
        }
        None => None,
    };
    if let Some(n) = &desktop.name {
        if n.trim().is_empty() || n.contains('/') || n.contains('\\') {
            return Err("--name must be a non-empty name without path separators".to_string());
        }
    }
    if let Some(id) = &desktop.id {
        if id.trim().is_empty() || id.contains(char::is_whitespace) {
            return Err("--id must be a reverse-DNS identifier like com.example.app".to_string());
        }
    }

    let mut how: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // Cirugía PE sobre la copia del motor, ANTES de anexar el bundle (el sha del payload no
    // cubre el motor ni tiene por qué).
    if desktop.no_console {
        pe::set_subsystem_gui(&mut engine_bytes)?;
        how.push("no-console".to_string());
    }
    if let (Some(ic), EngineFormat::Pe) = (&icon, format) {
        let images = ic.pe_images()?;
        pe::add_icon(&mut engine_bytes, &images)?;
        how.push(format!("icon {}", images.iter().map(|i| i.size.to_string()).collect::<Vec<_>>().join("/")));
    }

    let manifest = Manifest {
        format: bundle::FORMAT,
        engine: crate::update::current_version(),
        main: main_name.clone(),
        ceiling,
        profile: profile.to_string(),
        built_at: chrono_now(),
        mode: if serve.is_some() { BundleMode::Serve } else { BundleMode::Run },
        serve: serve.clone(),
        audit,
        packages: Vec::new(),
    };
    let n = entries.len();
    let b = if packages.is_empty() { Bundle::new(manifest, entries)? } else { Bundle::with_packages(manifest, entries, packages)? };
    let mut file = engine_bytes;
    let base = file.len() as u64;
    file.extend_from_slice(&b.serialize(base));

    let dir = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let version = crate::update::current_version();
    let display_name = desktop.name.clone().unwrap_or_else(|| stem.clone());
    let bundle_id = desktop.id.clone().unwrap_or_else(|| default_bundle_id(&stem));
    let final_path = match (want_bundle, format) {
        (true, EngineFormat::MachO) => {
            let icns = match &icon {
                Some(ic) => Some(icns::build(&ic.pngs(&icns::ICNS_TYPES.iter().map(|(s, _)| *s).collect::<Vec<_>>())?)?),
                None => None,
            };
            let spec = bundle_out::BundleSpec {
                display_name: &display_name,
                bin_name: &stem,
                bundle_id: &bundle_id,
                version: &version,
                binary: &file,
                icns: icns.as_deref(),
                pngs: &[],
            };
            let app = bundle_out::write_macos_app(&dir, &spec)?;
            if icns.is_some() {
                how.push("icon icns 16…1024".to_string());
            } else {
                notes.push("no --icon: the .app has no icon (Finder shows the generic one)".to_string());
            }
            how.push(format!("bundle .app · id {}", bundle_id));
            if cfg!(windows) {
                notes.push(format!(
                    "built on Windows, where the +x bit does not exist: on the Mac run chmod +x \"{}/Contents/MacOS/{}\"",
                    app.display(),
                    stem
                ));
            }
            app
        }
        (true, EngineFormat::Elf) => {
            let pngs = match &icon {
                Some(ic) => ic.pngs(&[256, 512])?,
                None => Vec::new(),
            };
            let spec = bundle_out::BundleSpec {
                display_name: &display_name,
                bin_name: &stem,
                bundle_id: &bundle_id,
                version: &version,
                binary: &file,
                icns: None,
                pngs: &pngs,
            };
            let out_dir = bundle_out::write_linux_dir(&dir, &spec)?;
            if pngs.is_empty() {
                notes.push("no --icon: the launcher entry has no icon".to_string());
            } else {
                how.push("icon png 256/512".to_string());
            }
            how.push(format!("bundle dir + install.sh · id {}", bundle_id));
            if cfg!(windows) {
                notes.push(format!(
                    "built on Windows, where the +x bit does not exist: on Linux run chmod +x \"{d}/{b}\" \"{d}/install.sh\"",
                    d = out_dir.display(),
                    b = stem
                ));
            }
            out_dir
        }
        _ => {
            if want_bundle {
                how.push("bundle: none needed on Windows".to_string());
            }
            write_binary(&dir, &out_path, &file)?;
            out_path.clone()
        }
    };
    Ok(BuildOutcome { out: final_path, files: n, bytes: file.len() as u64, serve, desktop: how, notes })
}

/// Escritura del binario: temp al lado + rename (mismo patrón que `synsema update`), 0o755 en Unix.
fn write_binary(dir: &Path, out_path: &Path, file: &[u8]) -> Result<(), String> {
    let tmp = dir.join(format!(".synsema-build-{}.tmp", std::process::id()));
    std::fs::write(&tmp, file).map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_file(out_path);
    std::fs::rename(&tmp, out_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write {}: {}", out_path.display(), e)
    })
}

/// `dev.synsema.<stem>` con el stem saneado a `[A-Za-z0-9.-]` (documentado como default).
fn default_bundle_id(stem: &str) -> String {
    let safe: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
        .collect();
    format!("dev.synsema.{}", safe)
}

/// La fuente del ícono (`--icon`): un SVG (se rasteriza a cada lado con el stack embebido),
/// un PNG (se re-escala) o un `.ico` (sus entradas tal cual para el PE; para `.icns`/Linux se
/// toma su PNG más grande y se re-escala — si sólo trae BMP, se dice).
pub enum IconSource {
    Svg(String),
    Png(Vec<u8>),
    Ico(Vec<pe::IconImage>),
}

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

impl IconSource {
    /// PNGs `(lado, bytes)` cuadrados para cada lado pedido.
    pub fn pngs(&self, sides: &[u32]) -> Result<Vec<(u32, Vec<u8>)>, String> {
        let mut out = Vec::with_capacity(sides.len());
        match self {
            IconSource::Svg(svg) => {
                for &s in sides {
                    let png = synsema_stdlib::raster::render_svg_png(svg, s, s).map_err(|e| format!("--icon: {}", e))?;
                    out.push((s, png));
                }
            }
            IconSource::Png(png) => {
                for &s in sides {
                    let p = synsema_stdlib::raster::resize_png(png, s).map_err(|e| format!("--icon: {}", e))?;
                    out.push((s, p));
                }
            }
            IconSource::Ico(images) => {
                let best = images
                    .iter()
                    .filter(|i| i.bytes.starts_with(PNG_SIG))
                    .max_by_key(|i| i.size)
                    .ok_or_else(|| "--icon: the .ico has no PNG image (only BMP entries); use an .svg or .png so the icon can be rasterized for this platform".to_string())?;
                for &s in sides {
                    let p = synsema_stdlib::raster::resize_png(&best.bytes, s).map_err(|e| format!("--icon: {}", e))?;
                    out.push((s, p));
                }
            }
        }
        Ok(out)
    }

    /// Las imágenes del recurso PE: 16/32/48/256 desde SVG/PNG, o las entradas del `.ico`.
    pub fn pe_images(&self) -> Result<Vec<pe::IconImage>, String> {
        match self {
            IconSource::Ico(images) => Ok(images.clone()),
            _ => Ok(self
                .pngs(&[16, 32, 48, 256])?
                .into_iter()
                .map(|(size, bytes)| pe::IconImage { size, bytes })
                .collect()),
        }
    }
}

/// Lee `--icon` por extensión (`.svg`, `.png`, `.ico`); cualquier otra cosa es un error claro.
pub fn load_icon(path: &str) -> Result<IconSource, String> {
    let ext = Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let bytes = std::fs::read(path).map_err(|e| format!("--icon: cannot read '{}': {}", path, e))?;
    match ext.as_str() {
        "svg" => {
            let svg = String::from_utf8(bytes).map_err(|_| format!("--icon: '{}' is not UTF-8 text", path))?;
            Ok(IconSource::Svg(svg))
        }
        "png" => {
            if !bytes.starts_with(PNG_SIG) {
                return Err(format!("--icon: '{}' is not a PNG file", path));
            }
            Ok(IconSource::Png(bytes))
        }
        "ico" => Ok(IconSource::Ico(pe::ico_images(&bytes)?)),
        _ => Err(format!("--icon accepts .svg, .png or .ico, got '{}'", path)),
    }
}

/// Lee el programa principal, su clausura de `use` y templates, y los `--include`.
/// Todos los nombres relativos a la raíz (= cwd durante la recolección).
/// Devuelve las entradas del bundle y el `bind "…"` literal del serve block (si hay).
/// Lo que `collect` junta: las entradas, el `bind` literal del serve y la sección de paquetes.
type Collected = (Vec<(String, Vec<u8>)>, Option<String>, Vec<synsema_core::bundle::BundledPackage>);

/// v0.6.58 (M5, ronda 1): todo se lee desde el directorio de quien invoca, como `run` (D-28): el
/// `.syn` y sus `use` (relativos al importador), las plantillas, los `static` y los `--include`
/// (relativos al directorio actual). Las claves del bundle son las que el binario busca al correr:
/// la de un módulo, su ruta relativa a la raíz del proyecto (`root`, así `use "../lib/y.syn"` desde
/// `scripts/` queda adentro, B6); la de una plantilla, un mount o un `--include`, su ruta relativa al
/// directorio actual, que es como el programa la escribe y como el binario la pide.
/// M7 (ronda 1): `f` (de un mount `dir`) tiene un segmento oculto: empieza con `.` y no es
/// `.well-known`. La misma regla que aplica el server al servir.
fn hidden_under(dir: &Path, f: &Path) -> bool {
    let rest = f.strip_prefix(dir).unwrap_or(f);
    rest.components().any(|c| match c {
        std::path::Component::Normal(s) => {
            let s = s.to_string_lossy();
            s.starts_with('.') && s != ".well-known"
        }
        _ => false,
    })
}

/// Ronda 3 (M-r3-2): el bundle tiene un solo espacio de nombres, y un mount sirve toda clave que cae
/// bajo la suya. El programa, sus módulos y el `synsema.json` entran por su ruta desde la raíz del
/// proyecto; los mounts, desde la carpeta actual. Cuando no son la misma carpeta, una de esas entradas
/// puede caer bajo un mount que en el disco no la sirve (`lib/secret.syn` bajo `static "/" from "."`
/// corrido desde `app/`). El binario la serviría: `build` falla en vez de distribuirla.
fn rooted_not_served(static_dirs: &[String], rooted: &[(String, PathBuf)], root: &Path) -> Result<(), String> {
    for dir in static_dirs {
        let Some(mk) = bundle::mount_key(dir) else { continue };
        let Ok(base) = Path::new(dir).canonicalize() else { continue };
        for (key, src) in rooted {
            let rest = if mk.is_empty() {
                key.as_str()
            } else if let Some(r) = key.strip_prefix(&format!("{}/", mk)) {
                r
            } else {
                continue;
            };
            // Lo oculto no se sirve nunca (M7): no importa que esté.
            if rest.split('/').any(|s| s.starts_with('.') && s != ".well-known") {
                continue;
            }
            let disk = Path::new(dir).join(rest);
            let same = disk.is_file()
                && served_from_disk(&base, &disk)
                && match (disk.canonicalize(), src.canonicalize()) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => false,
                };
            if !same {
                return Err(format!(
                    "'{}' (the program, a module or synsema.json, from the project root) would be served by static \"{}\" in the built binary, and the disk does not serve it there; mount a folder that holds only what is served (static \"/\" from \"pub\"), or run synsema build from the project root ({}), where static \".\" is the project root and serves all of it, the code included",
                    key,
                    dir,
                    root.display().to_string().trim_start_matches(r"\\?\")
                ));
            }
        }
    }
    Ok(())
}

/// Ronda 2 (M-r2-2): lo que el disco serviría de `f` bajo el mount `base` (canónico): donde
/// termina `f` siguiendo links (`read_within` del servidor) tiene que quedar adentro de la carpeta del
/// mount y no ser algo oculto. Un link que sale de la carpeta, o que lleva a `.git`, no viaja.
fn served_from_disk(base: &Path, f: &Path) -> bool {
    match f.canonicalize() {
        Ok(real) => real.starts_with(base) && !hidden_under(base, &real),
        Err(_) => false,
    }
}

/// `f` es el archivo que este build escribe (`-o`, o `-o x` → `x.exe` con un motor PE), de un
/// build anterior.
fn is_output(f: &Path, out: &Path) -> bool {
    let Ok(a) = f.canonicalize() else { return false };
    let exe = (out.extension().is_none()).then(|| out.with_extension("exe"));
    std::iter::once(out.to_path_buf()).chain(exe).any(|o| o.canonicalize().is_ok_and(|b| b == a))
}

fn collect(main: &str, main_name: &str, root: &Path, out: &Path, includes: &[String], serve_mode: bool) -> Result<Collected, String> {
    let source = std::fs::read_to_string(main).map_err(|e| format!("cannot read '{}': {}", main, e))?;
    let program = synsema_core::parser::parse_source(&source, main).map_err(|e| e.to_string())?;
    // Un programa con `serve on` sólo sirve bajo el runtime de serve: sin `--serve` el binario
    // fallaría al correr con "serve is only available through the Synsema engine runtime" —
    // se dice acá, en el build.
    if synsema_core::route_meta::has_serve_block(&program) && !serve_mode {
        return Err(format!(
            "'{}' has a serve block; pass --serve (and --bind <addr>, or a `bind \"…\"` clause) to build a server binary",
            main
        ));
    }
    let bind_lit = if serve_mode { synsema_core::route_meta::serve_bind_literal(&program)? } else { None };
    // Los mounts estáticos del serve (`static "/x" from "./dir"`) viajan dentro del binario:
    // el server los sirve del bundle antes que del disco. Un directorio que falta es un error
    // del build, no un 404 en producción.
    let static_dirs = synsema_core::route_meta::static_mount_dirs(&program)?;
    let (modules, templates) = program_closure_with(&program, main, &|resolved: &str, raw: &str| {
        let src = std::fs::read_to_string(resolved).map_err(|_| format!("module not found: {}", raw))?;
        synsema_core::parser::parse_source(&src, resolved).map_err(|e| e.to_string())
    })?;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    // Una clave, un archivo: dos archivos distintos con la misma clave (una plantilla `lib/y.syn`
    // del directorio actual y el módulo `lib/y.syn` de la raíz) son un error, no el primero que llegó.
    let push = |key: String, shown: &str, bytes: Vec<u8>, entries: &mut Vec<(String, Vec<u8>)>| -> Result<(), String> {
        match entries.iter().find(|(k, _)| *k == key) {
            Some((_, b)) if *b != bytes => Err(format!("'{}' names two different files in the bundle ({})", key, shown)),
            Some(_) => Ok(()),
            None => {
                entries.push((key, bytes));
                Ok(())
            }
        }
    };
    // La clave de lo relativo al directorio actual (plantillas, mounts, `--include`).
    let cwd_key = |name: &str| -> Result<String, String> {
        let name = name.trim_start_matches("./").trim_start_matches(".\\");
        bundle::normalize_name(name).ok_or_else(|| {
            format!("'{}' escapes the current directory ({})", name, std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default())
        })
    };
    // La clave de un módulo: su ruta relativa a la raíz del proyecto.
    let root_key = |path: &str| -> Result<String, String> {
        let abs = Path::new(path).canonicalize().map_err(|e| format!("cannot resolve module {}: {}", path, e))?;
        let rel = abs.strip_prefix(root).map_err(|_| format!("module {} is not under the bundle root {}", path, root.display()))?;
        bundle::normalize_name(&rel.to_string_lossy().replace('\\', "/")).ok_or_else(|| format!("module {} escapes the bundle root {}", path, root.display()))
    };
    // M-r3-2 (ronda 3): lo que entra por su ruta desde la raíz del proyecto (el programa, sus
    // módulos, el `synsema.json`), para ver al final si un mount `static` lo serviría.
    let mut rooted: Vec<(String, PathBuf)> = vec![(main_name.to_string(), PathBuf::from(main))];
    push(main_name.to_string(), main, source.into_bytes(), &mut entries)?;
    for m in modules {
        let bytes = std::fs::read(&m).map_err(|e| format!("cannot read module {}: {}", m, e))?;
        let key = root_key(&m)?;
        rooted.push((key.clone(), PathBuf::from(&m)));
        push(key, &m, bytes, &mut entries)?;
    }
    for t in templates {
        for tp in template_closure(&t)? {
            let bytes = std::fs::read(&tp).map_err(|e| format!("cannot read template {}: {}", tp, e))?;
            push(cwd_key(&tp)?, &tp, bytes, &mut entries)?;
        }
    }
    for dir in &static_dirs {
        let p = Path::new(dir);
        if !p.is_dir() {
            return Err(format!(
                "static mount '{}' (declared in the serve block) is not a directory under the current directory",
                dir
            ));
        }
        let base = p.canonicalize().map_err(|e| format!("static mount '{}': {}", dir, e))?;
        for f in expand_include(dir)? {
            // M7 (ronda 1): lo que el mount no sirve (lo oculto, salvo `.well-known`) tampoco viaja
            // en el binario, que se distribuye; ni el binario que se está escribiendo. M-r2-2: ni lo
            // que un link lleva afuera de la carpeta o a algo oculto (la regla del disco).
            if hidden_under(p, &f) || !served_from_disk(&base, &f) || is_output(&f, out) {
                continue;
            }
            let bytes = std::fs::read(&f).map_err(|e| format!("cannot read {}: {}", f.display(), e))?;
            let name = f.to_string_lossy().into_owned();
            push(cwd_key(&name)?, &name, bytes, &mut entries)?;
        }
    }
    for inc in includes {
        let mut found = 0usize;
        for p in expand_include(inc)? {
            if is_output(&p, out) {
                continue;
            }
            let bytes = std::fs::read(&p).map_err(|e| format!("cannot read {}: {}", p.display(), e))?;
            let name = p.to_string_lossy().into_owned();
            push(cwd_key(&name)?, &name, bytes, &mut entries)?;
            found += 1;
        }
        if found == 0 {
            return Err(format!("--include '{}' matched nothing", inc));
        }
    }
    // v0.6.58 (§9): el `synsema.json` del proyecto y los paquetes que alcanza el programa, leídos
    // y verificados como al correr (la misma tabla). Uno fuera del caché es N5 acá (B3).
    let mut packages = Vec::new();
    let project = synsema_core::project::resolve(main)?;
    if project.manifest.is_some() {
        let jp = root.join("synsema.json");
        let bytes = std::fs::read(&jp).map_err(|e| format!("cannot read synsema.json: {}", e))?;
        rooted.push(("synsema.json".to_string(), jp.clone()));
        push("synsema.json".to_string(), &jp.display().to_string(), bytes, &mut entries)?;
        let uses = synsema_core::loaded_modules::use_paths(&program);
        if !uses.is_empty() {
            let table = synsema_core::modtable::build(&project, main, uses)?;
            for p in &table.packages {
                let mut files = vec![("synsema.json".to_string(), p.index_bytes.to_vec())];
                let mut paths: Vec<&String> = p.files.keys().collect();
                paths.sort();
                for path in paths {
                    files.push((path.clone(), p.files[path].to_vec()));
                }
                packages.push((p.hash.clone(), files));
            }
        }
    }
    rooted_not_served(&static_dirs, &rooted, root)?;
    Ok((entries, bind_lit, packages))
}

/// `--include`: un archivo, un directorio (recursivo) o un patrón `*`/`?` de UN nivel
/// (`data/*.csv`) — el mismo `fnmatch` de los scopes de capability.
fn expand_include(spec: &str) -> Result<Vec<PathBuf>, String> {
    let spec_norm = spec.replace('\\', "/");
    if spec_norm.contains('*') || spec_norm.contains('?') {
        let (dir, pat) = match spec_norm.rsplit_once('/') {
            Some((d, p)) => (d.to_string(), p.to_string()),
            None => (".".to_string(), spec_norm.clone()),
        };
        if dir.contains('*') || dir.contains('?') {
            return Err(format!("--include '{}': patterns are allowed only in the last path component", spec));
        }
        let mut out = Vec::new();
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("--include '{}': {}", spec, e))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if synsema_capabilities::model::fnmatch(&name, &pat) {
                    out.push(if dir == "." { PathBuf::from(name) } else { Path::new(&dir).join(name) });
                }
            }
        }
        out.sort();
        return Ok(out);
    }
    let p = Path::new(spec);
    if p.is_file() {
        return Ok(vec![p.to_path_buf()]);
    }
    if p.is_dir() {
        let mut out = Vec::new();
        walk_dir(p, &mut out).map_err(|e| format!("--include '{}': {}", spec, e))?;
        out.sort();
        return Ok(out);
    }
    Err(format!("--include '{}': not found", spec))
}

fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk_dir(&p, out)?;
        } else if p.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// Fecha ISO-8601 (UTC, segundos) sin depender de chrono en el CLI.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Conversión civil (algoritmo de Howard Hinnant), suficiente para un sello.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}
