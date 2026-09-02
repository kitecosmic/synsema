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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use synsema_core::bundle::{self, Bundle, BundleMode, Manifest, ServeSettings};
use synsema_core::templates::{program_closure_with, template_closure};

use crate::HostFlags;

const USAGE_BUILD: &str = "uso: synsema build <main.syn> -o <salida> [--include <archivo|dir|patrón>]... [--sandbox | --cap-set <list>] [--profile native|pure] [--engine-binary <ruta>]";

pub fn cmd_build(host: HostFlags) -> ExitCode {
    let mut out: Option<String> = None;
    let mut includes: Vec<String> = Vec::new();
    let mut engine_binary: Option<String> = None;
    let mut main: Option<String> = None;
    let mut serve = false;
    let mut serve_secure = false;
    let mut serve_flags: Vec<(String, String)> = Vec::new();
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
    if host.audit.is_some() {
        eprintln!("synsema build: --audit applies when the program runs, not to the build");
        return ExitCode::from(2);
    }
    let profile = host.profile.clone().unwrap_or_else(|| "native".to_string());
    if synsema_runtime::host::Profile::parse(&profile).is_none() {
        eprintln!("synsema build: --profile must be 'native' or 'pure', got '{}'", profile);
        return ExitCode::from(2);
    }
    // El techo horneado se VALIDA acá con el mismo parser que `run` y se guarda como
    // texto (misma sintaxis) para que el manifest sea legible.
    let ceiling_text: Option<String> = if host.sandbox {
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

    match build(&main, &out, &includes, engine_binary.as_deref(), ceiling_text, &profile, serve_settings.clone()) {
        Ok((n, bytes)) => {
            match &serve_settings {
                Some(s) => {
                    let mut how = format!("serve · bind {}", s.bind);
                    if let Some(p) = s.port {
                        how.push_str(&format!(" · port {}", p));
                    }
                    if let Some(d) = &s.domains {
                        how.push_str(&format!(" · domain {}", d.join(",")));
                    }
                    if s.tls_auto.is_some() {
                        how.push_str(" · tls auto");
                    } else if s.tls_cert.is_some() {
                        how.push_str(" · tls cert");
                    }
                    if s.secure {
                        how.push_str(" · secure");
                    }
                    println!("built {} ({} files, {} bytes) · {}", out, n, bytes, how);
                }
                None => println!("built {} ({} files, {} bytes)", out, n, bytes),
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
    if s.bind.is_empty() {
        return Err("--serve needs --bind: a built server must say where it listens (--bind 127.0.0.1 for a local app, --bind 0.0.0.0 for a public one)".to_string());
    }
    let ov = synsema_runtime::serve::ServeOverrides {
        port: s.port,
        domains: s.domains.clone(),
        tls_auto_email: s.tls_auto.clone(),
        tls_cert: s.tls_cert.clone(),
        tls_key: s.tls_key.clone(),
        bind: Some(s.bind.clone()),
        ceiling: None,
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
    serve: Option<ServeSettings>,
) -> Result<(usize, u64), String> {
    let main_path = Path::new(main);
    if !main_path.is_file() {
        return Err(format!("cannot read '{}'", main));
    }
    let root: PathBuf = match main_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let root = root.canonicalize().map_err(|e| format!("cannot resolve the bundle root: {}", e))?;
    let main_name = main_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| "main program has no file name".to_string())?;
    if !main_name.ends_with(".syn") {
        return Err(format!("main program must be a .syn file: '{}'", main_name));
    }

    // Las resoluciones de `use` (relativas al importador) y de templates (relativas al
    // cwd) se hacen con cwd = raíz del bundle, así los paths resueltos SON las claves.
    let prev_cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    std::env::set_current_dir(&root).map_err(|e| format!("cannot enter {}: {}", root.display(), e))?;
    let result = collect(&main_name, includes, serve.is_some());
    let _ = std::env::set_current_dir(&prev_cwd);
    let entries = result?;

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
    let engine_bytes = std::fs::read(&engine_path)
        .map_err(|e| format!("cannot read the engine binary {}: {}", engine_path.display(), e))?;

    let manifest = Manifest {
        format: bundle::FORMAT,
        engine: crate::update::current_version(),
        main: main_name.clone(),
        ceiling,
        profile: profile.to_string(),
        built_at: chrono_now(),
        mode: if serve.is_some() { BundleMode::Serve } else { BundleMode::Run },
        serve,
    };
    let n = entries.len();
    let b = Bundle::new(manifest, entries)?;
    let mut file = engine_bytes;
    let base = file.len() as u64;
    file.extend_from_slice(&b.serialize(base));

    // Escritura: temp al lado + rename (mismo patrón que `synsema update`), 0o755 en Unix.
    let out_path = Path::new(out);
    let dir = out_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let tmp = dir.join(format!(".synsema-build-{}.tmp", std::process::id()));
    std::fs::write(&tmp, &file).map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_file(out_path);
    std::fs::rename(&tmp, out_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write {}: {}", out_path.display(), e)
    })?;
    Ok((n, file.len() as u64))
}

/// Lee el programa principal, su clausura de `use` y templates, y los `--include`.
/// Todos los nombres relativos a la raíz (= cwd durante la recolección).
fn collect(main_name: &str, includes: &[String], serve_mode: bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let source = std::fs::read_to_string(main_name).map_err(|e| format!("cannot read '{}': {}", main_name, e))?;
    let program = synsema_core::parser::parse_source(&source, main_name).map_err(|e| e.to_string())?;
    // Un programa con `serve on` sólo sirve bajo el runtime de serve: sin `--serve` el binario
    // fallaría al correr con "serve is only available through the Synsema engine runtime" —
    // se dice acá, en el build.
    if synsema_core::route_meta::has_serve_block(&program) && !serve_mode {
        return Err(format!(
            "'{}' has a serve block; pass --serve --bind <addr> to build a server binary",
            main_name
        ));
    }
    // Los mounts estáticos del serve (`static "/x" from "./dir"`) viajan dentro del binario:
    // el server los sirve del bundle antes que del disco. Un directorio que falta es un error
    // del build, no un 404 en producción.
    let static_dirs = synsema_core::route_meta::static_mount_dirs(&program)?;
    let (modules, templates) = program_closure_with(&program, main_name, &|resolved: &str, raw: &str| {
        let src = std::fs::read_to_string(resolved).map_err(|_| format!("module not found: {}", raw))?;
        synsema_core::parser::parse_source(&src, resolved).map_err(|e| e.to_string())
    })?;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let push = |name: String, bytes: Vec<u8>, entries: &mut Vec<(String, Vec<u8>)>| -> Result<(), String> {
        let key = bundle::normalize_name(&name)
            .ok_or_else(|| format!("'{}' escapes the bundle root ({})", name, std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default()))?;
        if !entries.iter().any(|(k, _)| *k == key) {
            entries.push((key, bytes));
        }
        Ok(())
    };
    push(main_name.to_string(), source.into_bytes(), &mut entries)?;
    for m in modules {
        let bytes = std::fs::read(&m).map_err(|e| format!("cannot read module {}: {}", m, e))?;
        push(m, bytes, &mut entries)?;
    }
    for t in templates {
        for tp in template_closure(&t)? {
            let bytes = std::fs::read(&tp).map_err(|e| format!("cannot read template {}: {}", tp, e))?;
            push(tp, bytes, &mut entries)?;
        }
    }
    for dir in &static_dirs {
        let p = Path::new(dir);
        if !p.is_dir() {
            return Err(format!(
                "static mount '{}' (declared in the serve block) is not a directory under the bundle root",
                dir
            ));
        }
        for f in expand_include(dir)? {
            let bytes = std::fs::read(&f).map_err(|e| format!("cannot read {}: {}", f.display(), e))?;
            let name = f.to_string_lossy().into_owned();
            let name = name.trim_start_matches("./").trim_start_matches(".\\").to_string();
            push(name, bytes, &mut entries)?;
        }
    }
    for inc in includes {
        let mut found = 0usize;
        for p in expand_include(inc)? {
            let bytes = std::fs::read(&p).map_err(|e| format!("cannot read {}: {}", p.display(), e))?;
            let name = p.to_string_lossy().into_owned();
            let name = name.trim_start_matches("./").trim_start_matches(".\\").to_string();
            push(name, bytes, &mut entries)?;
            found += 1;
        }
        if found == 0 {
            return Err(format!("--include '{}' matched nothing", inc));
        }
    }
    Ok(entries)
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
