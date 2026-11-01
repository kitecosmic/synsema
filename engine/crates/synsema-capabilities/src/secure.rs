//! Builtins seguros (gateados por capability). Port de `capabilities/enforcer.py`
//! (SecureOperations) + `capabilities/builtins.py` (register_secure_builtins).
//!
//! Reemplazan I/O cruda por operaciones chequeadas. La violación produce un
//! `Runtime error: Capability not granted: <cap>` (sin ubicación — la
//! capabilityViolation no la lleva; el prefijo de categoría lo agrega el motor).
//!
//! Capa 5: read_file/write_file/run hacen la op real (filesystem/proceso). El HTTP
//! (fetch/http_*) vive en synsema-stdlib/http.rs, gateado por `net`.

use synsema_core::types::SynMap;
use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// v0.6.45 (A6) — el proceso no tiene consola (un build `--no-console` de Windows): un hijo con
/// pipes se crea con `CREATE_NO_WINDOW`, si no abre una ventana de consola propia. Lo decide la
/// CLI al arrancar (`stdio::has_console`); embebido como librería queda apagado (lo de siempre).
/// Con consola no se toca: el hijo comparte la del padre y un `ssh` puede pedir la clave ahí.
static CHILD_NO_WINDOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_child_no_window(on: bool) {
    CHILD_NO_WINDOW.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// v0.6.46: el comando de `run`/`proc_spawn` con `cwd`: `(scope, programa)`. Un comando relativo con
/// separador (`./tool`) se resuelve contra el `cwd` del hijo, como en un shell (`cd sub && ./tool`), y
/// eso es lo que se pide: `exec("./sub/tool")`. Antes se pedía `exec("./tool")` tal cual y el archivo
/// que corría dependía de la plataforma (Unix lo buscaba en el `cwd` nuevo, Windows en el del
/// programa): el grant no decía qué archivo autorizaba. El programa se pasa absoluto, así no hay
/// segunda resolución. Sin `cwd`, sin separador (se busca en el `PATH`) o absoluto: tal cual.
pub fn exec_target(cmd: &str, cwd: Option<&str>) -> (String, String) {
    let Some(dir) = cwd else { return (cmd.to_string(), cmd.to_string()) };
    let has_sep = cmd.contains('/') || cmd.contains('\\');
    if !has_sep || std::path::Path::new(cmd).is_absolute() || cmd.starts_with('/') {
        return (cmd.to_string(), cmd.to_string());
    }
    let joined = crate::model::normalize_path(&format!("{}/{}", dir.trim_end_matches(['/', '\\']), cmd));
    let rooted = std::path::Path::new(&joined).is_absolute() || joined.starts_with('/');
    let scope = if rooted || joined.starts_with("../") { joined.clone() } else { format!("./{}", joined) };
    let program = if rooted {
        joined
    } else {
        std::env::current_dir().map(|h| h.join(&joined).to_string_lossy().into_owned()).unwrap_or(joined)
    };
    (scope, program)
}

/// v0.6.45 (A9) — las variables que un hijo con `env_clean` conserva: en Windows `SystemRoot`, sin
/// la cual el CRT y WinSock no arrancan (la misma única excepción que `run_program`). Todo lo demás
/// lo pasa el programa explícito por `env`.
pub fn clean_env_keep() -> Vec<(String, String)> {
    #[cfg(windows)]
    if let Ok(v) = std::env::var("SystemRoot") {
        return vec![("SystemRoot".to_string(), v)];
    }
    Vec::new()
}

/// `opts.env_clean` de `run`/`proc_spawn`: ausente o `false` = hereda (menos los secretos); `true` =
/// el hijo arranca sin entorno.
pub fn env_clean_opt(v: Option<&SynValue>, who: &str) -> Result<bool, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(Control::Error(RuntimeError::new(format!(
            "{}: env_clean must be a boolean, got {}",
            who,
            other.type_name()
        )))),
    }
}

/// Aplica `CREATE_NO_WINDOW` a `c` si el proceso no tiene consola (sólo Windows).
pub fn hide_child_window(c: &mut Command) {
    #[cfg(windows)]
    if CHILD_NO_WINDOW.load(std::sync::atomic::Ordering::Relaxed) {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = c;
}

/// v0.6.52 — ¿un `..` después de una carpeta (`./a/../b`)? El sistema lo resuelve en disco (si `a`
/// es un link, sube desde su destino) y el chequeo lo resuelve por nombre (`b`): juzgarían dos
/// lugares distintos. Un `..` al principio (`../x`) sube desde el cwd, que ya es físico.
pub fn dotdot_after_folder(p: &str) -> bool {
    let mut named = false;
    for seg in p.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." if named => return true,
            ".." => {}
            _ => named = true,
        }
    }
    false
}

/// El error de un `..` después de una carpeta en `what` (la ruta de un programa o de `isolate`).
pub fn dotdot_error(who: &str, what: &str, p: &str) -> Control {
    Control::Error(RuntimeError::new(format!(
        "{}: {} {:?} has `..` after a folder: the system resolves it on disk (from where a link in the path leads) and the permission check by name, so they would judge different places — write the path without it",
        who, what, p
    )))
}

/// Las opciones de `run` (`check_option_keys`).
const RUN_OPTIONS: &[&str] = &["cwd", "stdin", "max_output", "env", "env_clean", "isolate", "max_memory_mb", "max_file_mb"];

/// v0.6.52 (auditoría r1, M3) — una opción que `who` no conoce es error: una mal escrita no puede
/// pasar callada (`"isolated"` corría el hijo sin aislar), y tampoco unas opciones que no son un
/// mapa (ronda 2, B2: `"isolate"` como cuarto argumento). Público para `proc_spawn`.
pub fn check_option_keys(who: &str, opts: Option<&SynValue>, valid: &[&str]) -> Result<(), Control> {
    let m = match opts {
        None | Some(SynValue::Nothing) => return Ok(()),
        Some(SynValue::Map(m)) => m,
        Some(o) => {
            return Err(Control::Error(RuntimeError::new(format!(
                "{}: options must be a map, got {} — nothing ran",
                who,
                o.type_name()
            ))))
        }
    };
    for (k, _) in m.borrow().iter() {
        if !valid.contains(&k.as_str()) {
            return Err(Control::Error(RuntimeError::new(format!(
                "{}: unknown option {:?} (valid options: {}) — nothing ran",
                who,
                k.as_str(),
                valid.join(", ")
            ))));
        }
    }
    Ok(())
}

/// v0.6.52 (auditoría r1) — el ejecutable de `run`/`proc_spawn` no puede tener un `..` después de
/// una carpeta: `exec` lo juzga por nombre (`./lnk/../tool` es `./tool`) y el sistema ejecuta lo que
/// hay en disco (desde el destino de `lnk`). Lo mismo con el `cwd` contra el que se resuelve.
pub fn check_exec_path(who: &str, cmd: &str, cwd: Option<&str>) -> Result<(), Control> {
    let has_sep = cmd.contains('/') || cmd.contains('\\');
    if has_sep && dotdot_after_folder(cmd) {
        return Err(dotdot_error(who, "the program", cmd));
    }
    if let Some(dir) = cwd {
        if has_sep && !std::path::Path::new(cmd).is_absolute() && dotdot_after_folder(dir) {
            return Err(dotdot_error(who, "cwd", dir));
        }
        // Ronda 2 (N1): el hijo no arranca donde lleva un link que dejó un hijo aislado (el
        // ejecutable con ruta lo juzga `exec`, en `isolated_areas::crossing`).
        match crate::isolated_areas::crossing_dir(dir) {
            Some(crate::isolated_areas::Crossing::Link(area)) => {
                return Err(Control::Error(RuntimeError::new(format!(
                    "{}: cwd {:?} goes through a link inside {}, a folder an isolated child could write to (run with \"isolate\"): a link there leads nowhere — use the real place; nothing ran",
                    who,
                    dir,
                    area.display()
                ))));
            }
            Some(crate::isolated_areas::Crossing::InUse(area)) => {
                return Err(Control::Error(RuntimeError::new(format!(
                    "{}: cwd {:?} reaches {}, a folder a child isolated with write access is using right now (run with \"isolate\"): use it after that run returns; nothing ran",
                    who,
                    dir,
                    area.display()
                ))));
            }
            None => {}
        }
    }
    Ok(())
}

/// v0.6.52 (ronda 2, B3): si `path` es un link, dónde está la entrada: su carpeta resuelta en disco
/// más su nombre (sin seguir el link). `None` si no es un link o la carpeta no se resuelve (entonces
/// se juzga como siempre, por donde lleva).
fn link_entry(path: &str) -> Option<String> {
    let p = std::path::Path::new(path);
    if !std::fs::symlink_metadata(p).ok()?.file_type().is_symlink() {
        return None;
    }
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    let dir = std::fs::canonicalize(parent).ok()?;
    let dir = dir.to_string_lossy().replace('\\', "/");
    let dir = dir.strip_prefix("//?/").unwrap_or(&dir);
    Some(format!("{}/{}", dir.trim_end_matches('/'), p.file_name()?.to_string_lossy()))
}

/// Lo que `run` necesita de un hijo para esperarlo (un trait para probar el orden de `wait_step`).
trait Waitable {
    type Status;
    fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>>;
    fn wait(&mut self) -> std::io::Result<Self::Status>;
}

impl Waitable for std::process::Child {
    type Status = std::process::ExitStatus;
    fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>> {
        std::process::Child::try_wait(self)
    }
    fn wait(&mut self) -> std::io::Result<Self::Status> {
        std::process::Child::wait(self)
    }
}

/// Un paso de la espera de `run`: `Ok(None)` sigue corriendo, `Ok(Some(st))` terminó. v0.6.52
/// (auditoría r1 B3, r2 B1): aislado, la salida se mira sin recoger (`exited`, WNOWAIT), el grupo se
/// mata mientras el zombie retiene el número y recién después se recoge. `try_wait` no se llama
/// mientras corre: si el hijo salía entre `exited` y `try_wait`, se recogía sin matar al grupo.
/// Ronda 3 (B1): si no hay zombie (`Gone`: synsema arrancó con `SIGCHLD` ignorado y el kernel lo
/// recogió solo), se mata al grupo igual y `try_wait` da lo que se pueda (sin código, `-1`, como sin
/// aislar); antes esperaba hasta el timeout.
fn wait_step<C: Waitable>(
    child: &mut C,
    isolated: Option<u32>,
    exited: impl Fn(u32) -> synsema_isolate::ChildState,
    kill_group: impl Fn(u32),
) -> std::io::Result<Option<Option<C::Status>>> {
    use synsema_isolate::ChildState;
    match isolated {
        Some(pid) => match exited(pid) {
            ChildState::Running => Ok(None),
            ChildState::Exited => {
                kill_group(pid);
                Ok(Some(child.wait().ok()))
            }
            ChildState::Gone => {
                kill_group(pid);
                Ok(Some(child.try_wait().ok().flatten()))
            }
        },
        None => Ok(child.try_wait()?.map(Some)),
    }
}

/// ¿El archivo tiene algún bit de ejecución? (Para la pista de EACCES; fuera de Unix, sí.)
fn is_executable(cmd: &str) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !(cmd.contains('/')) {
            return true;
        }
        std::fs::metadata(cmd).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(true)
    }
    #[cfg(not(unix))]
    {
        let _ = cmd;
        true
    }
}

/// v0.6.52 — `run(…, {"isolate": …})`: lo que el programa le delega al hijo aislado. `true` = nada
/// más que el sistema (programas y bibliotecas, lectura) y una carpeta temporal propia; un mapa con
/// `"file.read"`/`"file.write"` (texto o lista) suma esas rutas, cada una con su permiso en el
/// programa (no se delega lo que no se tiene). El kernel concede carpetas enteras o archivos sueltos:
/// `"./data/**"` es la carpeta, `"./a.csv"` el archivo; otro glob no se puede imponer y es error.
/// `program`: el ejecutable con ruta (`./tool`), que el hijo tiene que poder leer para arrancar; lo
/// cubre el `exec` que ya pasó. Devuelve también dónde están de verdad las carpetas de escritura:
/// se registran (`isolated_areas`) recién cuando el hijo va a correr.
fn isolate_policy(
    caps: &Rc<RefCell<CapabilitySet>>,
    v: &SynValue,
    max_memory_mb: Option<&SynValue>,
    max_file_mb: Option<&SynValue>,
    program: &str,
) -> Result<(synsema_isolate::Policy, Vec<std::path::PathBuf>), Control> {
    let err = |m: String| Control::Error(RuntimeError::new(m));
    let mut policy = synsema_isolate::Policy::default();
    let mut write_areas = Vec::new();
    // Dónde quedó de verdad cada lugar delegado (para el aviso del programa que es un link).
    let mut granted = Vec::new();
    match v {
        SynValue::Bool(true) => {}
        SynValue::Map(m) => {
            for (k, val) in m.borrow().iter() {
                let ty = match k.as_str() {
                    "file.read" => CapabilityType::FileRead,
                    "file.write" => CapabilityType::FileWrite,
                    "net" => {
                        return Err(err(
                            "run: an isolated child has no network yet (\"net\" in \"isolate\" comes with the proxy that enforces the program's net grants) — nothing ran".into(),
                        ))
                    }
                    other => {
                        return Err(err(format!(
                            "run: \"isolate\" takes \"file.read\" and \"file.write\" (a path or a list), not {:?}",
                            other
                        )))
                    }
                };
                let scopes: Vec<String> = match val {
                    SynValue::Text(s) => vec![s.to_string()],
                    SynValue::List(l) => l
                        .borrow()
                        .to_vec()
                        .iter()
                        .map(|s| match s {
                            SynValue::Text(s) => Ok(s.to_string()),
                            o => Err(err(format!("run: \"isolate\".{:?} lists paths (text), got {}", k.as_str(), o.type_name()))),
                        })
                        .collect::<Result<_, _>>()?,
                    o => {
                        return Err(err(format!(
                            "run: \"isolate\".{:?} is a path or a list of paths, got {}",
                            k.as_str(),
                            o.type_name()
                        )))
                    }
                };
                for scope in scopes {
                    let pinned = isolate_path(caps, ty, &scope)?;
                    granted.push(pinned.real.clone());
                    if ty == CapabilityType::FileWrite {
                        if pinned.is_dir {
                            write_areas.push(pinned.real.clone());
                        }
                        policy.write.push(pinned.place);
                    } else {
                        policy.read.push(pinned.place);
                    }
                }
            }
        }
        o => {
            return Err(err(format!(
                "run: \"isolate\" is true or a map ({{\"file.read\": …, \"file.write\": …}}), got {}",
                o.type_name()
            )))
        }
    }
    let megabytes = |name: &str, v: Option<&SynValue>| match v {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Number(n)) if n.to_f64() >= 1.0 && n.to_f64().fract() == 0.0 && n.to_f64() <= (1u64 << 40) as f64 => {
            Ok(Some(n.to_f64() as u64 * 1024 * 1024))
        }
        Some(o) => Err(err(format!("run: {} is a whole number of megabytes (1 or more), got {}", name, o))),
    };
    policy.max_memory_bytes = megabytes("max_memory_mb", max_memory_mb)?;
    // v0.6.53: el tope de cada archivo que escribe el hijo (no del disco).
    policy.max_file_bytes = megabytes("max_file_mb", max_file_mb)?;
    if program.contains('/') || program.contains('\\') {
        // Atado como las rutas delegadas: el kernel concede el archivo que se resolvió acá.
        let pinned = synsema_isolate::pin(std::path::Path::new(program))
            .map_err(|e| err(format!("run: cannot resolve {:?}: {}", program, e)))?;
        if let Some(folder) = link_out_of_reach(&pinned.real, &granted) {
            warn_link_out_of_reach(program, &pinned.real, &folder);
        }
        policy.read.push(pinned.place);
    }
    Ok((policy, write_areas))
}

/// v0.6.53: el programa de un `run` aislado se delega resuelto (el archivo al que lleva el link),
/// pero sólo ese archivo. Si está fuera de las carpetas del sistema y de lo delegado, el hijo lo
/// ejecuta y no ve lo que tiene al lado: el `python` de un venv es un link al intérprete base (uv,
/// pyenv), que no encuentra su biblioteca y falla con un error propio que no dice por qué. Devuelve
/// la carpeta a delegar: la del archivo, o la de arriba si es un `bin/`.
fn link_out_of_reach(real: &std::path::Path, granted: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    let inside = |base: &std::path::Path| real.starts_with(base);
    if synsema_isolate::SYSTEM_READ.iter().map(std::path::Path::new).any(inside) || granted.iter().any(|g| inside(g)) {
        return None;
    }
    let dir = real.parent()?;
    match dir.file_name() {
        Some(n) if n == "bin" => Some(dir.parent().unwrap_or(dir).to_path_buf()),
        _ => Some(dir.to_path_buf()),
    }
}

/// El aviso de [`link_out_of_reach`], una vez por programa y carpeta (un `run` en un bucle no lo
/// repite).
fn warn_link_out_of_reach(program: &str, real: &std::path::Path, folder: &std::path::Path) {
    static SEEN: std::sync::Mutex<Vec<(String, std::path::PathBuf)>> = std::sync::Mutex::new(Vec::new());
    let key = (program.to_string(), folder.to_path_buf());
    let mut seen = SEEN.lock().unwrap_or_else(|p| p.into_inner());
    if seen.contains(&key) {
        return;
    }
    seen.push(key);
    eprintln!(
        "synsema: warning: run: {:?} leads to {}, outside what an isolated child sees: it can run that file but not read the folder around it (a venv's python is a link to its base interpreter) — add \"{}/**\" to \"file.read\" in \"isolate\"",
        program,
        real.display(),
        folder.display()
    );
}

/// Un permiso de `isolate` → el lugar que concede el kernel. Se juzga dos veces, como `open_checked`
/// (E8): por nombre (`require`, con su audit) y, ya abierto (`pin`), por dónde quedó de verdad
/// (`with_physical`). El kernel recibe ese mismo lugar abierto: un link cambiado después no mueve
/// nada.
fn isolate_path(
    caps: &Rc<RefCell<CapabilitySet>>,
    ty: CapabilityType,
    scope: &str,
) -> Result<synsema_isolate::Pin, Control> {
    let err = |m: String| Control::Error(RuntimeError::new(m));
    let (base, folder) = match scope.strip_suffix("/**") {
        Some(b) => (if b.is_empty() { "/" } else { b }, true),
        None => (scope, false),
    };
    if base.contains(['*', '?', '[']) {
        return Err(err(format!(
            "run: \"isolate\" path {:?}: the kernel grants whole folders (\"./data/**\") or single files (\"./data/a.csv\"), not a pattern — nothing ran",
            scope
        )));
    }
    if dotdot_after_folder(base) {
        return Err(dotdot_error("run", "\"isolate\" path", scope));
    }
    // Ronda 2 (M1): para Landlock lo que se escribe también se lee (`WRITE_*_RIGHTS`), así que la
    // escritura se delega sólo si el programa también puede leer ahí: el hijo no recibe nada que el
    // programa no tenga.
    let tys: &[CapabilityType] = if ty == CapabilityType::FileWrite {
        &[CapabilityType::FileWrite, CapabilityType::FileRead]
    } else {
        &[ty]
    };
    for &t in tys {
        require(caps, Capability::new(t, Some(scope.to_string())), "run() isolate").map_err(|e| {
            if t == ty {
                return e;
            }
            err(format!(
                "run: \"isolate\" {{\"file.write\": {:?}}} also lets the child read it: the program needs `file.read({:?})` too — nothing ran",
                scope, scope
            ))
        })?;
    }
    // Lo que se abre es la forma léxica (la que juzgó `require`).
    let lexical = synsema_core::capscope::absolute_path(base).unwrap_or_else(|| base.to_string());
    let pinned = synsema_isolate::pin(std::path::Path::new(&lexical)).map_err(|e| {
        err(format!(
            "run: \"isolate\" path {:?}: {} — the kernel grants what exists (make_dir() it first)",
            scope, e
        ))
    })?;
    let real = pinned.real.to_string_lossy();
    let real = real.strip_prefix(r"\\?\").unwrap_or(&real).replace('\\', "/");
    // El lugar fijado se juzga de nuevo con cada tipo (para una carpeta, `real/**`: `with_physical`
    // mueve la base del pedido con su patrón).
    if real.trim_end_matches('/') != lexical.trim_end_matches('/') {
        for &t in tys {
            let cap = Capability::new(t, Some(scope.to_string()));
            synsema_core::capscope::with_physical(base, &real, || require(caps, cap, "run() isolate"))?;
        }
    }
    if pinned.is_dir != folder {
        return Err(err(if folder {
            format!("run: \"isolate\" path {:?} is a file: grant it without \"/**\"", scope)
        } else {
            format!(
                "run: \"isolate\" path {:?} is a folder: grant it as \"{}/**\" (the child gets everything inside)",
                scope,
                scope.trim_end_matches('/')
            )
        }));
    }
    // El kernel no deja agujeros en una carpeta: un `deny` adentro se cumple no delegándola.
    if folder {
        let d = tys.iter().find_map(|&t| caps.borrow().deny_crossing(t, &real));
        if let Some(d) = d {
            return Err(err(format!(
                "run: \"isolate\" cannot delegate {:?}: `deny {}` lies inside it, and the kernel cannot leave a hole in a folder — delegate the parts the child may use",
                scope, d
            )));
        }
    }
    Ok(pinned)
}

use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};
use regex::RegexBuilder;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{
    syn_bool, syn_bytes, syn_float, syn_int, syn_list, syn_map, syn_text, SynValue,
};

use crate::model::{
    fnmatch, normalize_path, Capability, CapabilityAuditEntry, CapabilityType, CapabilitySet, BUNDLED_ASSET,
};

/// `str(value.raw)` estilo Python (texto crudo).
fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// v0.6.53 — lo que hace `make_dir`, con `path` ya juzgado por nombre. Recorre las carpetas desde
/// arriba: las que existen se dejan (un archivo en el camino es error) y las que faltan se juzgan
/// una por una (`file.write` por nombre, y por su lugar real si hay un link en el camino:
/// `nofollow::parent_checked`) y se crean relativas al handle de la de arriba.
fn make_dir_checked(caps: &Rc<RefCell<CapabilitySet>>, path: &str) -> Result<(), Control> {
    let fail = |m: String| Control::Error(RuntimeError::new(m));
    let chain: Vec<String> = {
        let mut v: Vec<String> = Path::new(path)
            .ancestors()
            .filter(|a| a.file_name().is_some())
            .map(|a| normalize_path(&a.to_string_lossy()))
            .collect();
        v.reverse();
        v
    };
    let check = |p: &str| {
        let recheck = |real: &str| {
            synsema_core::capscope::with_physical(p, real, || {
                require(caps, Capability::new(CapabilityType::FileWrite, Some(p.to_string())), "make_dir()")
            })
        };
        crate::nofollow::parent_checked(p, &recheck)
    };
    for p in &chain {
        match std::fs::metadata(p) {
            Ok(md) if md.is_dir() => {
                if p == chain.last().expect("no está vacía") {
                    // Ya existe: juzgada también por dónde está (un link puede llevar afuera).
                    if let Ok(real) = std::fs::canonicalize(p) {
                        let real = real.to_string_lossy();
                        let real = real.strip_prefix(r"\\?\").unwrap_or(&real).replace('\\', "/");
                        synsema_core::capscope::with_physical(p, &real, || {
                            require(caps, Capability::new(CapabilityType::FileWrite, Some(p.clone())), "make_dir()")
                        })?;
                    }
                }
                continue;
            }
            Ok(_) => return Err(fail(format!("make_dir: \"{}\" is a file", p))),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(fail(format!("Cannot create directory {}: {}", p, e)))
            }
            Err(_) => {}
        }
        require(caps, Capability::new(CapabilityType::FileWrite, Some(p.clone())), "make_dir()")?;
        #[cfg(test)]
        BETWEEN.with(|b| {
            if let Some(f) = b.borrow_mut().take() {
                f()
            }
        });
        let made = match check(p) {
            Ok(Some(dir)) => dir.make_dir(p),
            Ok(None) => std::fs::create_dir(p),
            Err(crate::nofollow::Refused::Denied(c)) => return Err(c),
            Err(crate::nofollow::Refused::Io(e)) => Err(e),
        };
        match made {
            Ok(()) => {}
            // Otro la creó en el medio: vale si es una carpeta (no un link ni un archivo).
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists
                && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) => {}
            Err(e) => return Err(fail(format!("Cannot create directory {}: {}", p, e))),
        }
    }
    Ok(())
}

/// v0.6.53: un `secret()` no llega al hijo de `run` como el texto `secret(K)` (ni se pierde, como
/// pasaba con `stdin`): es error antes de lanzar nada, como en `run_program` y en `proc_spawn`. El
/// programa que de verdad quiere pasarle el valor lo dice con `reveal()`, que queda en el audit.
fn no_secret_to_child(args: Option<&SynValue>, env: Option<&SynValue>, stdin: Option<&SynValue>) -> Result<(), Control> {
    let refuse = |what: String| {
        Err(Control::Error(RuntimeError::new(format!(
            "run: {} is a secret — reveal() it explicitly (audited) if the child really needs the value; nothing ran",
            what
        ))))
    };
    if let Some(SynValue::List(l)) = args {
        if let Some(n) = l.borrow().to_vec().iter().position(|v| matches!(v, SynValue::Secret(_))) {
            return refuse(format!("argument {}", n + 1));
        }
    }
    if let Some(SynValue::Map(m)) = env {
        if let Some((k, _)) = m.borrow().iter().find(|(_, v)| matches!(v, SynValue::Secret(_))) {
            return refuse(format!("env {:?}", k.as_str()));
        }
    }
    if matches!(stdin, Some(SynValue::Secret(_))) {
        return refuse("stdin".to_string());
    }
    Ok(())
}

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i)
        .ok_or_else(|| Control::Error(RuntimeError::new("missing argument")))
}

/// Lectura servida desde el bundle (`synsema build`): el asset es PARTE del programa,
/// así que no pide `file.read` — pero queda en el audit, con la razón explícita. Pública
/// para que cualquier builtin que lea un asset del bundle (el `from` de `zip_create`, las
/// `fonts` de `svg_to_*`) deje la misma línea que `read_file`.
pub fn bundled_audit(caps: &Rc<RefCell<CapabilitySet>>, ty: CapabilityType, path: &str, source: &str) {
    caps.borrow_mut().push_audit(CapabilityAuditEntry {
        capability: Capability::new(ty, Some(path.to_string())),
        granted: true,
        source: source.to_string(),
        reason: BUNDLED_ASSET.to_string(),
        origin: "runtime",
        context: None,
    });
}

/// Un path que está en el bundle es de sólo lectura: escribirlo sería mentir (la próxima
/// lectura seguiría viniendo del bundle).
fn reject_bundled_write(path: &str) -> Result<(), Control> {
    if synsema_core::bundle::get(path).is_some() {
        return Err(Control::Error(RuntimeError::new(format!(
            "\"{}\" is part of the bundle (read-only)",
            path
        ))));
    }
    Ok(())
}

/// v0.6.20 — prefijos de espacio: `bundle:<ruta>` fuerza el bundle de `synsema build`;
/// `disk:<ruta>` fuerza el disco aunque el bundle tenga esa ruta. Devuelve
/// `(espacio, ruta normalizada sin el prefijo)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Space {
    Auto,
    Bundle,
    Disk,
}

fn bundle_prefix(raw: &str) -> (Space, String) {
    if let Some(rest) = raw.strip_prefix("bundle:") {
        (Space::Bundle, normalize_path(rest))
    } else if let Some(rest) = raw.strip_prefix("disk:") {
        (Space::Disk, normalize_path(rest))
    } else {
        (Space::Auto, normalize_path(raw))
    }
}

/// v0.6.20 — de dónde se lee un archivo. Los assets del PROGRAMA (todo lo que `synsema build`
/// empaquetó: módulos, plantillas y lo pasado con `--include`) se resuelven contra el BUNDLE,
/// sin `file.read` (son el programa, no un recurso del host) y con su línea de audit: un
/// archivo dejado en el cwd jamás los sombrea. Todo lo demás es un archivo del USUARIO y va
/// al disco con `file.read`. `bundle:`/`disk:` fuerzan un espacio cuando una herramienta lo
/// necesita. La separación de espacios es lo que arregla al CLI construido con `synsema
/// build`: `list_dir` (abajo) lista SÓLO el disco.
enum Located {
    Disk(String),
    Bundled(String, &'static [u8]),
}

fn locate_for_read(caps: &Rc<RefCell<CapabilitySet>>, raw: &str, source: &str) -> Result<Located, Control> {
    let (space, path) = bundle_prefix(raw);
    if space != Space::Disk {
        if let Some(bytes) = synsema_core::bundle::get(&path) {
            bundled_audit(caps, CapabilityType::FileRead, &path, source);
            return Ok(Located::Bundled(path, bytes));
        }
        if space == Space::Bundle {
            return Err(Control::Error(RuntimeError::new(format!(
                "\"bundle:{}\" is not in the bundle (the program was not built with it, or the name differs)",
                path
            ))));
        }
    }
    require(caps, Capability::new(CapabilityType::FileRead, Some(path.clone())), source)?;
    Ok(Located::Disk(path))
}

/// v0.6.45 — el error de leer un archivo, con la causa real. Antes todo era `File not found`: un
/// archivo abierto en exclusiva por otro proceso, una carpeta, un link roto o un texto que no es
/// UTF-8 decían lo mismo, y quien lo lee (una persona o un agente) buscaba un archivo que estaba,
/// sin poder decidir si reintentar. `File not found` queda sólo para lo que no existe.
pub(crate) fn read_error(path: &str, e: &std::io::Error) -> Control {
    use std::io::ErrorKind;
    let why = if std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false) {
        "it is a directory (use list_dir)".to_string()
    } else if e.kind() == ErrorKind::NotFound {
        // v0.6.49 (§C): en Windows un nombre que termina en punto o espacio no existe como tal (la
        // API de Win32 lo recorta y `symlink_metadata` veía el otro archivo): decía "broken link".
        if cfg!(windows) && path.trim_end_matches(['/', '\\']).ends_with(['.', ' ']) && !path.ends_with("..") {
            return Control::Error(RuntimeError::new(format!(
                "File not found: {} (on Windows a file name cannot end in a dot or a space)",
                path
            )));
        }
        if std::fs::symlink_metadata(path).is_ok() {
            "it is a broken link (it points to something that does not exist)".to_string()
        } else {
            return Control::Error(RuntimeError::new(format!("File not found: {}", path)));
        }
    } else if cfg!(windows) && matches!(e.raw_os_error(), Some(32) | Some(33)) {
        // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION: otro proceso lo tiene abierto sin compartir.
        "in use by another process (it is open without sharing; retry later)".to_string()
    } else if e.kind() == ErrorKind::PermissionDenied {
        "permission denied".to_string()
    } else if e.kind() == ErrorKind::InvalidData {
        "it is not valid UTF-8 text (use read_file_bytes)".to_string()
    } else {
        e.to_string()
    };
    Control::Error(RuntimeError::new(format!("Cannot read file {}: {}", path, why)))
}

/// Rango de líneas 1-based (EOL preservado) sobre un texto en memoria (bundle).
fn lines_range_str(s: &str, offset: usize, limit: Option<usize>) -> String {
    s.split_inclusive('\n')
        .skip(offset.saturating_sub(1))
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

/// Chequea una capability; convierte la violación en `Control::Error` SIN ubicación.
fn require(caps: &Rc<RefCell<CapabilitySet>>, cap: Capability, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&cap, source)
        .map_err(|v| Control::Error(v.into_error()))
}

/// v0.6.46 (E8): abre `path`, que ya pasó `require` con cada uno de `tys`, sin ventana entre el
/// chequeo y la apertura (ver `nofollow`). Con un link en el camino, el chequeo se repite juzgando la
/// ubicación real del handle. Público para los builtins de otros crates que abren un archivo
/// chequeado (`zip_create`, `mtls_identity`, las fuentes de `raster`).
pub fn open_checked(
    caps: &Rc<RefCell<CapabilitySet>>,
    path: &str,
    how: crate::nofollow::OpenFor,
    tys: &[CapabilityType],
    source: &str,
) -> Result<std::fs::File, crate::nofollow::Refused<Control>> {
    let recheck = |real: &str| {
        synsema_core::capscope::with_physical(path, real, || {
            tys.iter().try_for_each(|ty| require(caps, Capability::new(*ty, Some(path.to_string())), source))
        })
    };
    crate::nofollow::open_checked(path, how, &recheck)
}

/// v0.6.46 (E8): `open_checked` para leer, con el error de lectura de siempre.
fn open_read(caps: &Rc<RefCell<CapabilitySet>>, path: &str, source: &str) -> Result<std::fs::File, Control> {
    open_checked(caps, path, crate::nofollow::OpenFor::READ, &[CapabilityType::FileRead], source).map_err(|r| match r {
        crate::nofollow::Refused::Io(e) => read_error(path, &e),
        crate::nofollow::Refused::Denied(c) => c,
    })
}

/// v0.6.46 (C4) — un archivo abierto para leerlo por partes: en disco (con el chequeo y la apertura
/// en un paso de E8) o embebido en el bundle.
pub enum OpenedForRead {
    Disk(String, std::fs::File),
    Bundled(String, &'static [u8]),
}

/// v0.6.46 (C4) — lo mismo que hace `read_file_bytes` antes de leer (bundle, `file.read`, apertura
/// sin carrera), para un builtin de stdlib que lee el archivo por partes (`parquet_scan`).
pub fn open_for_read(caps: &Rc<RefCell<CapabilitySet>>, raw: &str, source: &str) -> Result<OpenedForRead, Control> {
    match locate_for_read(caps, raw, source)? {
        Located::Bundled(p, b) => Ok(OpenedForRead::Bundled(p, b)),
        Located::Disk(p) => {
            let f = open_read(caps, &p, source)?;
            Ok(OpenedForRead::Disk(p, f))
        }
    }
}

/// Lee todo un archivo abierto como texto (UTF-8 estricto, como `read_to_string`).
fn read_text(mut f: std::fs::File) -> std::io::Result<String> {
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

/// Hostname de un URL, como `urlparse().hostname` de Python: minúsculas, sin
/// userinfo ni puerto. `None` si no hay esquema `scheme://`.
pub fn url_hostname(url: &str) -> Option<String> {
    let after = url.find("://").map(|i| &url[i + 3..])?;
    let end = after
        .find(['/', '?', '#'])
        .unwrap_or(after.len());
    let netloc = &after[..end];
    let host_port = match netloc.rfind('@') {
        Some(i) => &netloc[i + 1..],
        None => netloc,
    };
    // IPv6 entre corchetes (`[::1]:8080`, `[::1]`): el host es lo de adentro.
    if let Some(inner) = host_port.strip_prefix('[') {
        let close = inner.find(']')?;
        let rest = &inner[close + 1..];
        if !(rest.is_empty() || (rest.starts_with(':') && rest[1..].bytes().all(|b| b.is_ascii_digit()))) {
            return Some(String::new());
        }
        return Some(inner[..close].to_lowercase());
    }
    let host = match host_port.rfind(':') {
        Some(i) => {
            // `host:1:2` (dos puertos) no es un host: sin host, fail-closed.
            if host_port[..i].contains(':') || !host_port[i + 1..].bytes().all(|b| b.is_ascii_digit()) {
                return Some(String::new());
            }
            &host_port[..i]
        }
        None => host_port,
    };
    Some(host.to_lowercase())
}

// -- Helpers de time (UTC, como gmtime del oráculo) --

fn arg_f64(v: &SynValue) -> Result<f64, Control> {
    match v {
        SynValue::Number(n) => Ok(n.to_f64()),
        SynValue::Text(s) => s
            .trim()
            .parse::<f64>()
            .map_err(|_| Control::Error(RuntimeError::new("expected a number"))),
        _ => Err(Control::Error(RuntimeError::new("expected a number"))),
    }
}

/// Igual que `arg_f64` pero entero (trunca hacia cero).
fn arg_i64(v: &SynValue) -> Result<i64, Control> {
    Ok(arg_f64(v)?.trunc() as i64)
}

/// Escritura ATÓMICA: temp en el mismo dir (rename intra-FS, sin cross-device) + rename.
/// Crea los dirs padre si faltan. Limpia el temp si el rename falla. Reusado por
/// `write_file` y `edit_file`, con `path` ya chequeado con cada uno de `tys`.
///
/// v0.6.46 (E8): la carpeta se abre sin ventana con el chequeo (ver `nofollow::parent_checked`) y
/// el temporal, el rename y la limpieza van relativos a su handle. Las carpetas que faltan se
/// siguen creando por nombre, como v0.6.45.
pub fn atomic_write(
    caps: &Rc<RefCell<CapabilitySet>>,
    path: &str,
    data: &[u8],
    tys: &[CapabilityType],
    source: &str,
) -> Result<(), crate::nofollow::Refused<Control>> {
    use crate::nofollow::Refused;
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let recheck = |real: &str| {
        synsema_core::capscope::with_physical(path, real, || {
            tys.iter().try_for_each(|ty| require(caps, Capability::new(*ty, Some(path.to_string())), source))
        })
    };
    match crate::nofollow::parent_checked(path, &recheck)? {
        Some(dir) => {
            #[cfg(test)]
            BETWEEN.with(|b| {
                if let Some(f) = b.borrow_mut().take() {
                    f()
                }
            });
            dir.replace_with(data).map_err(Refused::Io)
        }
        None => atomic_write_by_name(path, data).map_err(Refused::Io),
    }
}

#[cfg(test)]
thread_local! {
    /// Ronda 1 (E8-B3): corre una vez entre `parent_checked` y `replace_with` (el test mueve la carpeta
    /// ahí): sin esto, "`atomic_write` siempre por nombre" pasaba los tests.
    static BETWEEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

/// La escritura atómica de v0.6.45, por nombre: donde no hay con qué abrir la carpeta sin links.
fn atomic_write_by_name(path: &str, data: &[u8]) -> std::io::Result<()> {
    // v0.6.45 — el temporal no se chequea contra el scope (es un nombre nuestro), así que no puede
    // seguir links: antes era `<ruta>.synsema.tmp` (predecible) con `fs::write`, y un link plantado
    // con ese nombre hacía escribir fuera del scope. Ahora lleva un sufijo al azar y se crea con
    // `create_new` (O_CREAT|O_EXCL / CREATE_NEW): falla si el nombre existe, sea link o no, y nunca
    // sigue uno. Si el nombre ya existe se prueba otro.
    let mut last = None;
    for _ in 0..8 {
        let tmp = format!("{}.{:016x}.synsema.tmp", path, rand::random::<u64>());
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp);
        let mut file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        // Ronda 2 (B5) y ronda 3 (B4): el reemplazo conserva los permisos del archivo que reemplaza
        // (un secreto 0600 reescrito quedaba 0644 por el umask), y se aplican sobre el handle ANTES
        // de escribir el contenido, no después por ruta.
        #[cfg(unix)]
        if let Ok(m) = std::fs::metadata(path) {
            let _ = file.set_permissions(m.permissions());
        }
        let written = file.write_all(data);
        // Cerrado antes del rename: en Windows no se renombra un archivo abierto.
        drop(file);
        return written.and_then(|_| std::fs::rename(&tmp, path)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        });
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("could not create a temporary file")))
}

/// Lee todo el stream pero guarda como mucho `cap` bytes; si hubo más, marca truncado.
/// Sigue drenando tras el tope (descartando) para que el hijo no se bloquee al escribir
/// en un pipe lleno. Usado por `run()` para capturar stdout/stderr en threads.
fn read_capped<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let take = (cap - out.len()).min(n);
                    out.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true; // ya lleno: drenar y descartar
                }
            }
            Err(_) => break,
        }
    }
    (out, truncated)
}

/// Junta los archivos a buscar para `grep`: si `path` es archivo → `[path]`; si es
/// carpeta → recursivo, filtrando por nombre con `glob` (fnmatch). Rutas con `/`.
fn grep_collect(path: &str, glob: &Option<String>, out: &mut Vec<String>) -> Result<(), Control> {
    let md = std::fs::metadata(path).map_err(|_| {
        Control::Error(RuntimeError::new(format!("grep: path not found: {}", path)))
    })?;
    if md.is_file() {
        out.push(path.to_string());
        return Ok(());
    }
    // v0.6.45 — el `file.read` se chequeó sobre `path`; lo que se recorre tiene que quedar adentro
    // EN DISCO. Un link a una carpeta no se sigue (como ripgrep; además evita ciclos) y un link a
    // un archivo entra sólo si lleva a algo dentro de `path`.
    fn walk(root: &str, dir: &str, glob: &Option<String>, out: &mut Vec<String>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(x) => x,
            Err(_) => return,
        };
        for e in rd.flatten() {
            let p = e.path();
            let ps = p.to_string_lossy().replace('\\', "/");
            let link = e.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if link && (p.is_dir() || !synsema_core::capscope::physically_beneath(root, &ps)) {
                continue;
            }
            if p.is_dir() {
                walk(root, &ps, glob, out);
            } else {
                let name = e.file_name().to_string_lossy().into_owned();
                let inc = match glob {
                    Some(g) => fnmatch(&name, g),
                    None => true,
                };
                if inc {
                    out.push(ps);
                }
            }
        }
    }
    walk(path, path, glob, out);
    Ok(())
}

/// Lee un archivo como líneas SIN el EOL (para el campo `text` de `grep`). Streamea por
/// línea (`read_until`); líneas no-UTF-8 se leen lossy (no se saltean en silencio).
fn grep_lines(f: std::fs::File) -> std::io::Result<Vec<String>> {
    let mut r = BufReader::new(f);
    let mut buf = Vec::new();
    let mut lines = Vec::new();
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let mut s = String::from_utf8_lossy(&buf).into_owned();
        while s.ends_with('\n') || s.ends_with('\r') {
            s.pop();
        }
        lines.push(s);
    }
    Ok(lines)
}

/// Lee las líneas `[offset, offset+limit)` 1-based, PRESERVANDO los EOL. Streamea por
/// línea con `read_until(b'\n')` (no carga el archivo entero ni corta multibyte: UTF-8
/// es auto-sincronizante en `\n`; `from_utf8_lossy` es por robustez). `limit=None` → hasta
/// el fin del archivo.
fn read_lines_range(f: std::fs::File, offset: usize, limit: Option<usize>) -> std::io::Result<String> {
    let mut reader = BufReader::new(f);
    let start = offset.saturating_sub(1); // 1-based → 0-based inclusivo
    let end = limit.map(|n| start.saturating_add(n)); // exclusivo
    let mut buf = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    let mut idx = 0usize;
    loop {
        if let Some(e) = end {
            if idx >= e {
                break;
            }
        }
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break; // EOF
        }
        if idx >= start {
            out.extend_from_slice(&buf); // read_until conserva el \n
        }
        idx += 1;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Patrón strftime opcional (2º arg de tipo texto).
fn opt_pattern(args: &[SynValue]) -> Option<String> {
    match args.get(1) {
        Some(SynValue::Text(s)) => Some(s.to_string()),
        _ => None,
    }
}

fn ts_to_utc(ts: f64) -> Result<DateTime<Utc>, Control> {
    let secs = ts.trunc() as i64;
    let nanos = ((ts - ts.trunc()) * 1e9).round() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .ok_or_else(|| Control::Error(RuntimeError::new("invalid timestamp")))
}

/// Inverso de format_time. Sin patrón parsea ISO-8601 (acepta 'Z'); naive→UTC.
fn parse_time_ts(s: &str, pattern: Option<&str>) -> Result<f64, Control> {
    if let Some(p) = pattern {
        // Un patrón de SÓLO fecha ("%Y-%m-%d") es medianoche UTC (antes: "input is not enough
        // for unique date and time").
        let naive = match NaiveDateTime::parse_from_str(s, p) {
            Ok(n) => n,
            Err(e) => match chrono::NaiveDate::parse_from_str(s, p) {
                Ok(d) => d.and_time(chrono::NaiveTime::MIN),
                Err(_) => return Err(Control::Error(RuntimeError::new(format!("invalid time: {}", e)))),
            },
        };
        return Ok(naive.and_utc().timestamp() as f64);
    }
    let s2 = s.replace('Z', "+00:00");
    if let Ok(dt) = DateTime::parse_from_rfc3339(&s2) {
        return Ok(dt.timestamp() as f64);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s2, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.and_utc().timestamp() as f64);
    }
    Err(Control::Error(RuntimeError::new(format!("invalid time: {}", s))))
}

/// Builtins de filesystem del PERFIL PURO: sin disco, pero el BUNDLE (`synsema build`)
/// sigue disponible — es parte del programa, no filesystem. Las lecturas sirven del
/// bundle o fallan con el error puro; las escrituras siempre fallan. Sobrescriben (por
/// nombre) a los builtins normales cuando el motor entra en perfil puro.
pub fn register_pure_fs(interp: &Interpreter, hint: &'static str) {
    fn no_fs(name: &str, hint: &str) -> Control {
        Control::Error(RuntimeError::new(format!(
            "{}: not available in the pure profile — this run has no filesystem ({})",
            name, hint
        )))
    }
    interp.register_builtin("read_file", -1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        match synsema_core::bundle::get(&path) {
            Some(bytes) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                if args.len() < 2 {
                    return Ok(syn_text(text));
                }
                let offset = arg_i64(arg(args, 1)?)?;
                if offset < 1 {
                    return Err(Control::Error(RuntimeError::new("read_file: offset must be >= 1")));
                }
                let limit = match args.get(2) {
                    Some(v) => Some(arg_i64(v)?.max(0) as usize),
                    None => None,
                };
                Ok(syn_text(lines_range_str(&text, offset as usize, limit)))
            }
            None => Err(no_fs("read_file", hint)),
        }
    }));
    interp.register_builtin("read_file_bytes", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        match synsema_core::bundle::get(&path) {
            Some(bytes) => Ok(syn_bytes(bytes.to_vec())),
            None => Err(no_fs("read_file_bytes", hint)),
        }
    }));
    interp.register_builtin("file_exists", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        Ok(syn_bool(synsema_core::bundle::get(&path).is_some()))
    }));
    interp.register_builtin("file_info", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        let mut m = SynMap::new();
        match synsema_core::bundle::get(&path) {
            Some(bytes) => {
                m.insert("exists", syn_bool(true));
                m.insert("is_dir", syn_bool(false));
                m.insert("size", syn_int(bytes.len() as i64));
                m.insert("modified", SynValue::Nothing);
                m.insert("bundled", syn_bool(true));
                m.insert("is_link", syn_bool(false));
            }
            None => {
                m.insert("exists", syn_bool(false));
                m.insert("is_dir", syn_bool(false));
                m.insert("size", syn_int(0));
                m.insert("modified", SynValue::Nothing);
                m.insert("is_link", syn_bool(false));
            }
        }
        Ok(syn_map(m))
    }));
    // v0.6.20 — borrar y `cwd()` no existen sin filesystem (ni sobre el bundle: es de sólo lectura).
    for name in ["delete_file", "delete_dir", "make_dir", "cwd"] {
        interp.register_builtin(name, -1, Rc::new(move |_i, _args, _loc| Err(no_fs(name, hint))));
    }
    interp.register_builtin("list_dir", 1, Rc::new(move |_i, args, _loc| {
        let path = normalize_path(&raw_str(arg(args, 0)?));
        let Some(b) = synsema_core::bundle::mounted() else {
            return Err(no_fs("list_dir", hint));
        };
        let under = b.list(&path);
        if under.is_empty() {
            return Err(no_fs("list_dir", hint));
        }
        let root = path.trim_matches(|c| c == '.' || c == '/' || c == '\\').is_empty();
        let prefix_len = match synsema_core::bundle::normalize_name(&path) {
            Some(n) if !root => n.len() + 1,
            _ => 0,
        };
        let mut seen: Vec<(String, bool, i64)> = Vec::new();
        for (name, size) in under {
            let rest = &name[prefix_len.min(name.len())..];
            let (entry, is_dir) = match rest.split_once('/') {
                Some((d, _)) => (d.to_string(), true),
                None => (rest.to_string(), false),
            };
            if !seen.iter().any(|(n, _, _)| *n == entry) {
                seen.push((entry, is_dir, if is_dir { 0 } else { size as i64 }));
            }
        }
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(syn_list(seen.into_iter().map(|(name, is_dir, size)| {
            let mut m = SynMap::new();
            m.insert("name", syn_text(name));
            m.insert("is_dir", syn_bool(is_dir));
            m.insert("size", syn_int(size));
            m.insert("is_link", syn_bool(false));
            syn_map(m)
        }).collect()))
    }));
    for name in ["write_file", "append_file", "edit_file", "grep"] {
        let name: &'static str = name;
        interp.register_builtin(name, -1, Rc::new(move |_i, _args, _loc| Err(no_fs(name, hint))));
    }
}

/// Registra los builtins seguros en el intérprete, compartiendo el `CapabilitySet`.
pub fn register_secure_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // read_file(path, offset?, limit?) → text. Requiere file_read("<path>").
    // arity-1: archivo completo (idéntico a hoy). arity-2/3: rango por LÍNEAS 1-based,
    // preservando los EOL; fin de archivo observable (sin truncado silencioso).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "read_file",
            -1,
            Rc::new(move |_i, args, _loc| {
                // v0.6.20 — assets del programa desde el bundle; archivos del usuario desde el disco
                // (ver locate_for_read).
                let (path, bundled) = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "read_file()")? {
                    Located::Disk(p) => (p, None),
                    Located::Bundled(p, b) => (p, Some(b)),
                };
                // arity-1: archivo completo, idéntico a hoy (read_to_string estricto).
                if args.len() < 2 {
                    if let Some(bytes) = bundled {
                        return Ok(syn_text(String::from_utf8_lossy(bytes).into_owned()));
                    }
                    return match read_text(open_read(&caps, &path, "read_file()")?) {
                        Ok(c) => Ok(syn_text(c)),
                        Err(e) => Err(read_error(&path, &e)),
                    };
                }
                // rango por líneas (1-based)
                let offset = match arg(args, 1)? {
                    SynValue::Number(_) => arg_i64(arg(args, 1)?)?,
                    other => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "read_file(path, offset, limit?): offset is the first line to read (a number ≥ 1), got {} — to read a file that may not exist, check file_exists(path) first, or catch it with try/recover",
                            other.type_name()
                        ))))
                    }
                };
                if offset < 1 {
                    return Err(Control::Error(RuntimeError::new(
                        "read_file: offset must be >= 1",
                    )));
                }
                let limit = match args.get(2) {
                    Some(v) => {
                        let n = arg_i64(v)?;
                        if n < 0 {
                            return Err(Control::Error(RuntimeError::new(
                                "read_file: limit must be >= 0",
                            )));
                        }
                        Some(n as usize)
                    }
                    None => None,
                };
                if let Some(bytes) = bundled {
                    return Ok(syn_text(lines_range_str(&String::from_utf8_lossy(bytes), offset as usize, limit)));
                }
                match read_lines_range(open_read(&caps, &path, "read_file()")?, offset as usize, limit) {
                    Ok(s) => Ok(syn_text(s)),
                    Err(e) => Err(read_error(&path, &e)),
                }
            }),
        );
    }

    // list_dir(path) → list de {name, is_dir, size}, ordenada por name. NO recursivo.
    // Incluye ocultos. path inexistente/no-carpeta → error. Requiere file_read("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "list_dir",
            1,
            Rc::new(move |_i, args, _loc| {
                let (space, path) = bundle_prefix(&raw_str(arg(args, 0)?));
                // v0.6.20 — el DISCO es el directorio; el bundle sólo con `bundle:` explícito
                // (`list_dir("bundle:")` = su raíz). Antes el bundle sombreaba el cwd y un CLI
                // construido con `synsema build` listaba sus propios assets en vez de la carpeta
                // donde lo invocaron.
                if space == Space::Bundle {
                    let Some(b) = synsema_core::bundle::mounted() else {
                        return Err(Control::Error(RuntimeError::new(
                            "list_dir(\"bundle:…\"): this program has no bundle (it was not built with `synsema build`)",
                        )));
                    };
                    let under = b.list(&path);
                    if under.is_empty() {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "list_dir: \"bundle:{}\" is not a directory in the bundle",
                            path
                        ))));
                    }
                    {
                        bundled_audit(&caps, CapabilityType::FileRead, &path, "list_dir()");
                        let root = path.trim_matches(|c| c == '.' || c == '/' || c == '\\').is_empty();
                        let prefix_len = match synsema_core::bundle::normalize_name(&path) {
                            Some(n) if !root => n.len() + 1,
                            _ => 0,
                        };
                        let mut seen: Vec<(String, bool, i64)> = Vec::new();
                        for (name, size) in under {
                            let rest = &name[prefix_len.min(name.len())..];
                            let (entry, is_dir) = match rest.split_once('/') {
                                Some((d, _)) => (d.to_string(), true),
                                None => (rest.to_string(), false),
                            };
                            if !seen.iter().any(|(n, _, _)| *n == entry) {
                                seen.push((entry, is_dir, if is_dir { 0 } else { size as i64 }));
                            }
                        }
                        seen.sort_by(|a, b| a.0.cmp(&b.0));
                        let items: Vec<SynValue> = seen
                            .into_iter()
                            .map(|(name, is_dir, size)| {
                                let mut m = SynMap::new();
                                m.insert("name", syn_text(name));
                                m.insert("is_dir", syn_bool(is_dir));
                                m.insert("size", syn_int(size));
                                m.insert("is_link", syn_bool(false));
                                syn_map(m)
                            })
                            .collect();
                        return Ok(syn_list(items));
                    }
                }
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "list_dir()",
                )?;
                let rd = std::fs::read_dir(&path).map_err(|_| {
                    Control::Error(RuntimeError::new(format!("Not a directory: {}", path)))
                })?;
                // v0.6.45 — un link (symlink, junction) dice `is_link: true` y su `is_dir` es el de
                // lo que apunta, igual que en `file_info` (antes una junction salía `is_dir: false`
                // acá y `true` allá). Su `size` es 0: el tamaño de algo que puede estar fuera del
                // scope no se da gratis; `file_info` lo da si el destino queda adentro.
                // v0.6.51 (L1): el destino se mira sólo si el programa podría leerlo (la decisión de
                // `file_info` sobre la ruta del link, juzgada en disco); uno que sale del permiso da
                // `is_dir: false` sin que el motor haga stat afuera.
                let mut entries: Vec<(String, bool, i64, bool)> = Vec::new();
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let is_link = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
                    let md = if !is_link {
                        e.metadata().ok()
                    } else {
                        let at = format!("{}/{}", path.trim_end_matches(['/', '\\']), name);
                        let readable = caps.borrow_mut().check_silent(&Capability::new(CapabilityType::FileRead, Some(at)));
                        if readable { std::fs::metadata(e.path()).ok() } else { None }
                    };
                    let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                    let size = if is_dir || is_link {
                        0
                    } else {
                        md.as_ref().map(|m| m.len() as i64).unwrap_or(0)
                    };
                    entries.push((name, is_dir, size, is_link));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0)); // orden estable por nombre
                let items = entries
                    .into_iter()
                    .map(|(name, is_dir, size, is_link)| {
                        let mut m = SynMap::new();
                        m.insert("name", syn_text(name));
                        m.insert("is_dir", syn_bool(is_dir));
                        m.insert("size", syn_int(size));
                        m.insert("is_link", syn_bool(is_link));
                        syn_map(m)
                    })
                    .collect();
                Ok(syn_list(items))
            }),
        );
    }

    // file_info(path) → {exists, is_dir, size, modified}. Si no existe, forma estable
    // {exists:false,...} (NO error: chequear existencia es su trabajo). Requiere file_read.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "file_info",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "file_info()")? {
                    Located::Bundled(_, bytes) => {
                        let mut m = SynMap::new();
                        m.insert("exists", syn_bool(true));
                        m.insert("is_dir", syn_bool(false));
                        m.insert("size", syn_int(bytes.len() as i64));
                        m.insert("modified", SynValue::Nothing);
                        m.insert("bundled", syn_bool(true));
                        m.insert("is_link", syn_bool(false));
                        return Ok(syn_map(m));
                    }
                    Located::Disk(p) => p,
                };
                let mut m = SynMap::new();
                // v0.6.45 — `is_link`: la ruta misma es un symlink o una junction (los datos de
                // abajo son los de lo que apunta). Un link roto da `exists: false, is_link: true`.
                let is_link = std::fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
                match std::fs::metadata(&path) {
                    Ok(md) => {
                        let modified = md
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| syn_int(d.as_secs() as i64))
                            .unwrap_or(SynValue::Nothing);
                        let is_dir = md.is_dir();
                        m.insert("exists", syn_bool(true));
                        m.insert("is_dir", syn_bool(is_dir));
                        m.insert(
                            "size".to_string(),
                            syn_int(if is_dir { 0 } else { md.len() as i64 }),
                        );
                        m.insert("modified", modified);
                    }
                    Err(_) => {
                        m.insert("exists", syn_bool(false));
                        m.insert("is_dir", syn_bool(false));
                        m.insert("size", syn_int(0));
                        m.insert("modified", SynValue::Nothing);
                    }
                }
                m.insert("is_link", syn_bool(is_link));
                Ok(syn_map(m))
            }),
        );
    }

    // file_exists(path) → bool. Azúcar de file_info(path).exists. Requiere file_read.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "file_exists",
            1,
            Rc::new(move |_i, args, _loc| {
                match locate_for_read(&caps, &raw_str(arg(args, 0)?), "file_exists()")? {
                    Located::Bundled(..) => Ok(syn_bool(true)),
                    Located::Disk(path) => Ok(syn_bool(std::fs::metadata(&path).is_ok())),
                }
            }),
        );
    }

    // grep(target, pattern, opts?) → {matches:[{file,line,col,text}], truncated}.
    // Busca en disco SIN cargar archivos enteros (streamea por línea). target archivo →
    // ese archivo; carpeta → recursivo. pattern LITERAL por defecto (opts.regex para RE2).
    // Un solo chequeo de file.read sobre el target (granularidad de IO-P1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "grep",
            -1,
            Rc::new(move |_i, args, _loc| {
                let pattern = raw_str(arg(args, 1)?);
                let target = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "grep()")? {
                    Located::Bundled(p, _) => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "grep: \"{}\" is a bundled asset — grep runs over the filesystem; use read_file() on it",
                            p
                        ))))
                    }
                    Located::Disk(p) => p,
                };
                // v0.6.45 (ronda 2, M3): buscar en una carpeta es leer su árbol entero; con el glob
                // por segmentos, `file.read("./proj")` es la carpeta sola. Hace falta lo mismo que
                // pide `static`: `file.read("<carpeta>/**")`.
                if std::fs::metadata(&target).map(|m| m.is_dir()).unwrap_or(false) {
                    require(
                        &caps,
                        Capability::new(CapabilityType::FileRead, Some(format!("{}/**", target.trim_end_matches('/')))),
                        "grep()",
                    )?;
                }
                if pattern.is_empty() {
                    return Err(Control::Error(RuntimeError::new("grep: empty pattern")));
                }

                // -- opts --
                let map_get = |k: &str| -> Option<SynValue> {
                    match args.get(2) {
                        Some(SynValue::Map(m)) => m.borrow().get(k).cloned(),
                        _ => None,
                    }
                };
                let ignore_case = matches!(map_get("ignore_case"), Some(SynValue::Bool(true)));
                let use_regex = matches!(map_get("regex"), Some(SynValue::Bool(true)));
                let glob = match map_get("glob") {
                    Some(SynValue::Text(s)) => Some(s.to_string()),
                    _ => None,
                };
                let max_results = match map_get("max_results") {
                    Some(SynValue::Number(n)) => Some(n.to_f64() as usize),
                    _ => None,
                };

                // -- matcher --
                let re = if use_regex {
                    Some(
                        RegexBuilder::new(&pattern)
                            .case_insensitive(ignore_case)
                            .build()
                            .map_err(|e| {
                                Control::Error(RuntimeError::new(format!(
                                    "grep: invalid regex pattern: {}",
                                    e
                                )))
                            })?,
                    )
                } else {
                    None
                };
                let needle = if ignore_case {
                    pattern.to_lowercase()
                } else {
                    pattern.clone()
                };

                // -- recorrido (orden estable: por ruta, luego por línea) --
                let mut files = Vec::new();
                grep_collect(&target, &glob, &mut files)?;
                // v0.6.45 — un `deny` dentro del árbol también vale para `grep` (antes sólo se
                // chequeaba la raíz y `deny file.read("./proj/.env")` no frenaba la búsqueda).
                files.retain(|f| !caps.borrow().denies(&Capability::new(CapabilityType::FileRead, Some(f.clone()))));
                files.sort();

                let mut out_matches: Vec<SynValue> = Vec::new();
                let mut truncated = false;
                'files: for f in &files {
                    // v0.6.46 (E8): cada archivo se abre sin ventana; un link que ahora lleva afuera
                    // se saltea, como el que ya llevaba afuera al recorrer.
                    let Ok(file) = open_checked(&caps, f, crate::nofollow::OpenFor::READ, &[CapabilityType::FileRead], "grep()") else {
                        continue;
                    };
                    let lines = match grep_lines(file) {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    for (i, line) in lines.iter().enumerate() {
                        let col_byte = if let Some(re) = &re {
                            re.find(line).map(|m| m.start())
                        } else if ignore_case {
                            line.to_lowercase().find(&needle)
                        } else {
                            line.find(&needle)
                        };
                        if let Some(b) = col_byte {
                            // col 1-based en chars (best-effort; bajo ignore_case literal se
                            // mide sobre el prefijo en minúsculas, misma cuenta de chars).
                            let prefix = if ignore_case && re.is_none() {
                                line.to_lowercase()
                            } else {
                                line.clone()
                            };
                            let col = prefix.get(..b).map(|p| p.chars().count()).unwrap_or(0) + 1;
                            let mut m = SynMap::new();
                            m.insert("file", syn_text(f.clone()));
                            m.insert("line", syn_int((i as i64) + 1));
                            m.insert("col", syn_int(col as i64));
                            m.insert("text", syn_text(line.clone()));
                            out_matches.push(syn_map(m));
                            if let Some(max) = max_results {
                                if out_matches.len() >= max {
                                    truncated = true;
                                    break 'files;
                                }
                            }
                        }
                    }
                }
                let mut out = SynMap::new();
                out.insert("matches", syn_list(out_matches));
                out.insert("truncated", syn_bool(truncated));
                Ok(syn_map(out))
            }),
        );
    }

    // read_file_bytes(path) → bytes (crudo, NO lossy). Requiere file_read("<path>"),
    // mismo gating que read_file. Cierra el punto lossy de read_file para binario.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "read_file_bytes",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = match locate_for_read(&caps, &raw_str(arg(args, 0)?), "read_file_bytes()")? {
                    Located::Bundled(_, bytes) => return Ok(syn_bytes(bytes.to_vec())),
                    Located::Disk(p) => p,
                };
                let mut b = Vec::new();
                match open_read(&caps, &path, "read_file_bytes()")?.read_to_end(&mut b) {
                    Ok(_) => Ok(syn_bytes(b)),
                    Err(e) => Err(read_error(&path, &e)),
                }
            }),
        );
    }

    // v0.6.20 — delete_file(path) → true. Requiere file_write("<path>"): el MISMO scope que
    // escribir (quien puede crear puede deshacer). Un asset del bundle es de sólo lectura.
    // Antes, borrar un archivo propio exigía `exec("rm")`: no tenerlo EMPEORABA la seguridad.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "delete_file",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                let cap = Capability::new(CapabilityType::FileWrite, Some(path.clone()));
                // v0.6.52 (ronda 2, B3): borrar un link borra la entrada, no lo que apunta (como
                // `unlink`): se juzga dónde está el link —su carpeta en disco, más su nombre—, no a
                // dónde lleva. Así se puede sacar el link que dejó un hijo aislado.
                if let Some(entry) = link_entry(&path) {
                    let judge = |real: &str| synsema_core::capscope::with_physical(&path, real, || require(&caps, cap.clone(), "delete_file()"));
                    judge(&entry)?;
                    reject_bundled_write(&path)?;
                    // Ronda 3 (A1): la carpeta se abre sin ventana (sin links, o siguiéndolos y
                    // juzgando otra vez su lugar real con el nombre) y se borra relativo a ella.
                    let gone = match crate::nofollow::parent_checked(&path, &judge) {
                        Ok(Some(dir)) => dir.remove_entry(&path),
                        Ok(None) => crate::nofollow::remove_link(&path),
                        Err(crate::nofollow::Refused::Denied(e)) => return Err(e),
                        Err(crate::nofollow::Refused::Io(e)) => Err(e),
                    };
                    return gone
                        .map(|_| syn_bool(true))
                        .map_err(|e| Control::Error(RuntimeError::new(format!("Cannot delete file {}: {}", path, e))));
                }
                require(&caps, cap, "delete_file()")?;
                reject_bundled_write(&path)?;
                match std::fs::metadata(&path) {
                    Err(_) => Err(Control::Error(RuntimeError::new(format!("File not found: {}", path)))),
                    Ok(md) if md.is_dir() => Err(Control::Error(RuntimeError::new(format!(
                        "delete_file: \"{}\" is a directory (use delete_dir)",
                        path
                    )))),
                    Ok(_) => std::fs::remove_file(&path).map(|_| syn_bool(true)).map_err(|e| {
                        Control::Error(RuntimeError::new(format!("Cannot delete file {}: {}", path, e)))
                    }),
                }
            }),
        );
    }

    // v0.6.20 — delete_dir(path, opts?) → true. Sólo vacío por defecto; `{"recursive": true}`
    // borra el árbol entero. Requiere file_write("<path>") (el scope debe cubrir el dir).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "delete_dir",
            -1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                let recursive = match args.get(1) {
                    None | Some(SynValue::Nothing) => false,
                    Some(SynValue::Map(m)) => {
                        for (k, v) in m.borrow().iter() {
                            if k != "recursive" {
                                return Err(Control::Error(RuntimeError::new(format!(
                                    "delete_dir: unknown option {:?} (valid options: recursive)",
                                    k
                                ))));
                            }
                            if !matches!(v, SynValue::Bool(_)) {
                                return Err(Control::Error(RuntimeError::new(
                                    "delete_dir: option `recursive` must be true or false",
                                )));
                            }
                        }
                        matches!(m.borrow().get("recursive"), Some(SynValue::Bool(true)))
                    }
                    Some(other) => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: opts must be a map, got {}",
                            other.type_name()
                        ))))
                    }
                };
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "delete_dir()",
                )?;
                reject_bundled_write(&path)?;
                match std::fs::metadata(&path) {
                    Err(_) => {
                        return Err(Control::Error(RuntimeError::new(format!("Directory not found: {}", path))))
                    }
                    Ok(md) if !md.is_dir() => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: \"{}\" is a file (use delete_file)",
                            path
                        ))))
                    }
                    Ok(_) => {}
                }
                // Auditoría externa — recursivo: `file.write` sobre CADA ruta del árbol antes de borrar
                // nada (el mismo scope que exigiría borrarlas una a una).
                if recursive {
                    let mut stack = vec![std::path::PathBuf::from(&path)];
                    let mut all: Vec<String> = Vec::new();
                    while let Some(dir) = stack.pop() {
                        let rd = std::fs::read_dir(&dir).map_err(|e| {
                            Control::Error(RuntimeError::new(format!("Cannot read directory {}: {}", dir.display(), e)))
                        })?;
                        for e in rd.flatten() {
                            let p = e.path();
                            all.push(normalize_path(&p.to_string_lossy()));
                            if e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false) {
                                stack.push(p);
                            }
                        }
                    }
                    for p in &all {
                        require(&caps, Capability::new(CapabilityType::FileWrite, Some(p.clone())), "delete_dir()")?;
                    }
                }
                let result = if recursive { std::fs::remove_dir_all(&path) } else { std::fs::remove_dir(&path) };
                match result {
                    Ok(_) => Ok(syn_bool(true)),
                    Err(e) if !recursive && e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                        Err(Control::Error(RuntimeError::new(format!(
                            "delete_dir: \"{}\" is not empty (pass {{\"recursive\": true}} to delete its contents)",
                            path
                        ))))
                    }
                    Err(e) => Err(Control::Error(RuntimeError::new(format!(
                        "Cannot delete directory {}: {}",
                        path, e
                    )))),
                }
            }),
        );
    }

    // v0.6.53 — make_dir(path) → true. Crea la carpeta y las que falten arriba (como `mkdir -p`).
    // Cada carpeta que crea pide `file.write` y se crea relativa a la carpeta de arriba ya abierta
    // (E8): con un link en el camino se juzga dónde queda de verdad, y un link en el nombre no se
    // sigue. Si ya existe, `true` (juzgada por dónde está).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "make_dir",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = normalize_path(&raw_str(arg(args, 0)?));
                require(&caps, Capability::new(CapabilityType::FileWrite, Some(path.clone())), "make_dir()")?;
                reject_bundled_write(&path)?;
                make_dir_checked(&caps, &path)?;
                Ok(syn_bool(true))
            }),
        );
    }

    // v0.6.20 — cwd() → el directorio de trabajo real, normalizado. Bajo `file.read(".")`:
    // el nombre absoluto de `.` es información del host (bajo --sandbox no se filtra gratis) y
    // es exactamente la misma grant que exige `list_dir(".")`; `file.read("./**")` y `"**"`
    // también la cubren (v0.6.45: `./*` son los archivos de la carpeta, no la carpeta). Bajo un binario de `synsema build` es el cwd de verdad, nunca el
    // overlay del bundle.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "cwd",
            0,
            Rc::new(move |_i, _args, _loc| match std::env::current_dir() {
                Ok(p) => {
                    require(&caps, Capability::new(CapabilityType::FileRead, Some(".".to_string())), "cwd()")?;
                    Ok(syn_text(normalize_path(&p.to_string_lossy())))
                }
                Err(e) => Err(Control::Error(RuntimeError::new(format!("cwd: {}", e)))),
            }),
        );
    }

    // write_file(path, content) → true. Requiere file_write("<path>"). Despacha por
    // tipo: si `content` es bytes, escribe los bytes crudos (binario, NO lossy); si no,
    // texto (raw_str). Escritura ATÓMICA: temp en el mismo dir + rename (sin lectores que
    // vean un archivo a medias). Mismo retorno/errores que antes.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "write_file",
            2,
            Rc::new(move |interp, args, _loc| {
                let raw_path = raw_str(arg(args, 0)?);
                let path = normalize_path(&raw_path);
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "write_file()",
                )?;
                reject_bundled_write(&path)?;
                // Escritura atómica (temp+rename); crea dirs padre. Despacha por tipo.
                let tys = [CapabilityType::FileWrite];
                // v0.6.46 (C3): lo escrito queda en los `outputs` del recibo.
                let text;
                let (data, enc): (&[u8], &'static str) = match arg(args, 1)? {
                    SynValue::Bytes(b) => (&b[..], "bytes"),
                    other => {
                        text = raw_str(other);
                        (text.as_bytes(), "text")
                    }
                };
                match atomic_write(&caps, &path, data, &tys, "write_file()") {
                    Ok(_) => {
                        interp.record_output("write_file", &raw_path, data, enc);
                        Ok(syn_bool(true))
                    }
                    Err(crate::nofollow::Refused::Denied(c)) => Err(c),
                    Err(crate::nofollow::Refused::Io(e)) => Err(Control::Error(RuntimeError::new(format!(
                        "Cannot write file {}: {}",
                        path, e
                    )))),
                }
            }),
        );
    }

    // edit_file(path, old, new, replace_all?) → {replaced:N}. Reemplaza por match exacto
    // de string. Sin replace_all exige UNICIDAD (0 → not found; >1 → ambiguo). Escritura
    // atómica. Pide file.write y, desde v0.6.45, también file.read: sus respuestas (no está /
    // ambiguo / cuántos reemplazó) dicen si un texto está adentro.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "edit_file",
            -1,
            Rc::new(move |interp, args, _loc| {
                let raw_path = raw_str(arg(args, 0)?);
                let path = normalize_path(&raw_path);
                let old = raw_str(arg(args, 1)?);
                let new = raw_str(arg(args, 2)?);
                let replace_all = matches!(args.get(3), Some(SynValue::Bool(true)));
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "edit_file()",
                )?;
                // v0.6.45 (ronda 2, B5): `edit_file` lee el archivo para buscar `old`, y sus
                // respuestas (no está / ambiguo / cuántos reemplazó) dicen si un texto está adentro:
                // es una lectura, y pide `file.read` también.
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "edit_file()",
                )?;
                reject_bundled_write(&path)?;
                if old.is_empty() {
                    return Err(Control::Error(RuntimeError::new("edit_file: empty pattern")));
                }
                let f = open_checked(
                    &caps,
                    &path,
                    crate::nofollow::OpenFor::READ,
                    &[CapabilityType::FileWrite, CapabilityType::FileRead],
                    "edit_file()",
                )
                .map_err(|r| match r {
                    crate::nofollow::Refused::Io(e) => read_error(&path, &e),
                    crate::nofollow::Refused::Denied(c) => c,
                })?;
                let content = read_text(f).map_err(|e| read_error(&path, &e))?;
                // v0.6.49 (B11): lo leído entra en `inputs`, como un `read_file` (antes sólo
                // quedaba el archivo como quedó, en `outputs`).
                interp.record_read("edit_file", &args[..1], &syn_text(&content))?;
                let count = content.matches(&old).count();
                if count == 0 {
                    return Err(Control::Error(RuntimeError::new("edit_file: pattern not found")));
                }
                if count > 1 && !replace_all {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "edit_file: ambiguous, {} occurrences (use replace_all to replace all)",
                        count
                    ))));
                }
                let (updated, replaced) = if replace_all {
                    (content.replace(&old, &new), count)
                } else {
                    (content.replacen(&old, &new, 1), 1)
                };
                atomic_write(
                    &caps,
                    &path,
                    updated.as_bytes(),
                    &[CapabilityType::FileWrite, CapabilityType::FileRead],
                    "edit_file()",
                )
                .map_err(|r| match r {
                    crate::nofollow::Refused::Io(e) => {
                        Control::Error(RuntimeError::new(format!("Cannot write file {}: {}", path, e)))
                    }
                    crate::nofollow::Refused::Denied(c) => c,
                })?;
                // v0.6.46 (C3): el archivo entero como quedó.
                interp.record_output("edit_file", &raw_path, updated.as_bytes(), "text");
                let mut m = SynMap::new();
                m.insert("replaced", syn_int(replaced as i64));
                Ok(syn_map(m))
            }),
        );
    }

    // append_file(path, content) → true. Agrega al final (crea si no existe, + dirs padre).
    // bytes → crudo; si no, texto. Append REAL (OpenOptions::append), no temp+rename: el
    // sentido de append es no reescribir el archivo. Requiere file.write("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "append_file",
            2,
            Rc::new(move |interp, args, _loc| {
                let raw_path = raw_str(arg(args, 0)?);
                let path = normalize_path(&raw_path);
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "append_file()",
                )?;
                reject_bundled_write(&path)?;
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // v0.6.46 (E8): sin ventana entre el chequeo y la apertura (ver `nofollow`).
                let mut f = open_checked(&caps, &path, crate::nofollow::OpenFor::APPEND, &[CapabilityType::FileWrite], "append_file()")
                    .map_err(|r| match r {
                        crate::nofollow::Refused::Io(e) => {
                            Control::Error(RuntimeError::new(format!("Cannot write file {}: {}", path, e)))
                        }
                        crate::nofollow::Refused::Denied(c) => c,
                    })?;
                let text;
                let (data, enc): (&[u8], &'static str) = match arg(args, 1)? {
                    SynValue::Bytes(b) => (&b[..], "bytes"),
                    other => {
                        text = raw_str(other);
                        (text.as_bytes(), "text")
                    }
                };
                f.write_all(data).map_err(|e| {
                    Control::Error(RuntimeError::new(format!("Cannot write file {}: {}", path, e)))
                })?;
                // v0.6.46 (C3): el pedazo agregado (no el archivo entero: no se relee).
                interp.record_output("append_file", &raw_path, data, enc);
                Ok(syn_bool(true))
            }),
        );
    }

    // run(cmd, args_list?, timeout?, opts?) → {exit_code, stdout, stderr,
    // stdout_truncated, stderr_truncated}. Gateado por exec("<cmd>"). SIN shell: args es
    // lista (sin inyección de quoting). exit≠0 NO es error (dato en exit_code); timeout
    // mata+raise; no-se-puede-lanzar → raise. std-only (timeout por polling try_wait+kill;
    // captura en threads para no deadlockear con pipes llenos).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "run",
            -1,
            Rc::new(move |i, args, _loc| {
                let cmd = raw_str(arg(args, 0)?);
                // args_list (opcional; si está, debe ser lista).
                let arg_list: Vec<String> = match args.get(1) {
                    None | Some(SynValue::Nothing) => Vec::new(),
                    Some(SynValue::List(l)) => l.borrow().to_vec().iter().map(raw_str).collect(),
                    Some(_) => {
                        return Err(Control::Error(RuntimeError::new("run: args must be a list")))
                    }
                };
                // timeout (default 120s).
                let timeout_secs = match args.get(2) {
                    Some(SynValue::Nothing) | None => 120.0,
                    Some(v) => arg_f64(v)?,
                };
                // opts.
                let opt = |k: &str| -> Option<SynValue> {
                    match args.get(3) {
                        Some(SynValue::Map(m)) => m.borrow().get(k).cloned(),
                        _ => None,
                    }
                };
                // v0.6.52 (auditoría r1, M3): una opción mal escrita (`"isolated"`) corría el hijo sin
                // aislar y sin avisar. Las de seguridad no pueden fallar abiertas.
                check_option_keys("run", args.get(3), RUN_OPTIONS)?;
                no_secret_to_child(args.get(1), opt("env").as_ref(), opt("stdin").as_ref())?;
                // Ronda 5 (M2): un `run` aislado arranca de a uno, desde antes de juzgar nada hasta
                // lanzar al hijo (`isolated_areas::startup`).
                let turn = match opt("isolate") {
                    None | Some(SynValue::Nothing) | Some(SynValue::Bool(false)) => None,
                    Some(_) => Some(crate::isolated_areas::startup()),
                };
                let cwd = match opt("cwd") {
                    Some(SynValue::Text(s)) => Some(s.to_string()),
                    _ => None,
                };
                check_exec_path("run", &cmd, cwd.as_deref())?;
                // capability: scope = cmd tal como se pasa (pre-PATH); con `cwd`, resuelto contra él.
                let (scope, cmd) = exec_target(&cmd, cwd.as_deref());
                require(&caps, Capability::new(CapabilityType::Exec, Some(scope)), "run()")?;
                let stdin_data: Option<Vec<u8>> = match opt("stdin") {
                    Some(SynValue::Bytes(b)) => Some(b[..].to_vec()),
                    Some(SynValue::Text(s)) => Some(s.as_bytes().to_vec()),
                    _ => None,
                };
                let max_output = match opt("max_output") {
                    Some(SynValue::Number(n)) => n.to_f64() as usize,
                    _ => 10 * 1024 * 1024,
                };
                // v0.6.52: `{"isolate": …}` — el hijo corre aislado por el kernel, con lo que el
                // programa le delega (`isolate_policy`). Donde no se puede imponer, falla cerrado.
                let policy = match opt("isolate") {
                    None | Some(SynValue::Nothing) | Some(SynValue::Bool(false)) => {
                        for (name, example) in [("max_memory_mb", 512), ("max_file_mb", 100)] {
                            if opt(name).is_some() {
                                return Err(Control::Error(RuntimeError::new(format!(
                                    "run: {name} is enforced only for an isolated child — add \"isolate\" (e.g. {{\"isolate\": true, \"{name}\": {example}}})",
                                ))));
                            }
                        }
                        None
                    }
                    Some(v) => Some(isolate_policy(&caps, &v, opt("max_memory_mb").as_ref(), opt("max_file_mb").as_ref(), &cmd)?),
                };

                // construir el comando.
                let mut c = Command::new(&cmd);
                c.args(&arg_list)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(dir) = &cwd {
                    c.current_dir(dir);
                }
                // F3: sacar las variables SECRETAS de Synsema (claves de proveedor,
                // secretos del `.env`) del entorno del hijo — un programa con `exec` pero
                // sin `env`/`secret` no debe exfiltrarlas por `run("printenv")`. El
                // programa que de verdad necesita una la pasa explícita por `opts.env`.
                for name in i.sensitive_env() {
                    c.env_remove(name);
                }
                // v0.6.45 (A9): `{"env_clean": true}` — el hijo no hereda nada del entorno.
                if env_clean_opt(opt("env_clean").as_ref(), "run")? {
                    c.env_clear();
                    c.envs(clean_env_keep());
                }
                // Aislado: entorno limpio (PATH, LANG, HOME/TMPDIR propios) y el aislamiento en el
                // hijo. Tiene que vivir hasta que el hijo termine (su carpeta temporal).
                let (prepared, mut borrowed) = match &policy {
                    Some((p, areas)) => {
                        let prepared = synsema_isolate::prepare(&mut c, p)
                            .map_err(|e| Control::Error(RuntimeError::new(format!("run: {}", e))))?;
                        // Desde acá el hijo puede poner links en sus carpetas de escritura: no se
                        // siguen por el resto de la corrida, y mientras corre nadie más las toca
                        // (ronda 4, A1): se sueltan cuando su grupo quedó vacío (`isolated_areas`).
                        let borrowed = match areas.is_empty() {
                            true => None,
                            false => Some(crate::isolated_areas::borrow(areas).map_err(|busy| {
                                Control::Error(RuntimeError::new(format!(
                                    "run: another task is still using {}, which reaches {} (a folder this child would write to); try again when it finishes — nothing ran",
                                    busy.held.display(),
                                    busy.area.display()
                                )))
                            })?),
                        };
                        (Some(prepared), borrowed)
                    }
                    None => (None, None),
                };
                if let Some(SynValue::Map(m)) = opt("env") {
                    for (k, v) in m.borrow().iter() {
                        c.env(k.as_str(), raw_str(v)); // override explícito (gana sobre el strip)
                    }
                }

                hide_child_window(&mut c);
                let mut child = c.spawn().map_err(|e| {
                    let hint = if prepared.is_some() && e.kind() == std::io::ErrorKind::PermissionDenied {
                        if is_executable(&cmd) {
                            " — an isolated child sees only the system folders and what \"isolate\" grants: the program has to be inside them (a venv: add its folder to \"file.read\")"
                        } else {
                            " — the file is not executable (chmod +x)"
                        }
                    } else {
                        ""
                    };
                    Control::Error(RuntimeError::new(format!(
                        "run: cannot start \"{}\": {}{}",
                        cmd, e, hint
                    )))
                })?;
                let isolated_pid = prepared.as_ref().map(|_| child.id());
                // Al volver, el grupo ya está matado: con carpetas de escritura el préstamo espera a
                // que quede vacío (y recoge a los huérfanos); sin ellas, `Adopted` sólo los recoge.
                let _adopted = match (borrowed.as_mut(), isolated_pid) {
                    (Some(b), Some(pid)) => {
                        b.child_group(pid);
                        None
                    }
                    (None, Some(pid)) => Some(crate::isolated_areas::Adopted(pid)),
                    _ => None,
                };
                // Ronda 5 (M2): desde acá `run` sólo espera, no actúa por nombre sobre lo que juzgó
                // (el ejecutable, el `cwd`, lo delegado ya quedó fijado): lo suelta, y suelta el turno.
                // La carpeta del hijo la cuida su préstamo.
                synsema_core::op_hold::release();
                drop(turn);

                // stdin: escribir en un thread (evita deadlock con stdin grande) y cerrar
                // (EOF). Sin data → `si` se dropea acá y cierra stdin.
                if let Some(si) = child.stdin.take() {
                    if let Some(data) = stdin_data {
                        std::thread::spawn(move || {
                            let mut si = si;
                            let _ = si.write_all(&data);
                        });
                    }
                }

                // captura concurrente (threads) para no bloquear con pipes llenos.
                let out = child.stdout.take().unwrap();
                let err = child.stderr.take().unwrap();
                let out_h = std::thread::spawn(move || read_capped(out, max_output));
                let err_h = std::thread::spawn(move || read_capped(err, max_output));

                // v0.6.42 — mientras el hijo corre, este hilo sólo espera: bajo `serve` suelta su
                // permiso de ejecución.
                let _w = synsema_core::waiting::waiting();
                // esperar con timeout (polling try_wait + kill); sin crate externa.
                let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs.max(0.0));
                let mut timed_out = false;
                // Aislado, se termina el grupo entero (el hijo no puede salir de él): lo que lanzó
                // no queda vivo ni retiene las pipes.
                let kill_tree = |pid: Option<u32>| {
                    if let Some(pid) = pid {
                        synsema_isolate::kill_group(pid);
                    }
                };
                let status = loop {
                    match wait_step(&mut child, isolated_pid, synsema_isolate::exited, synsema_isolate::kill_group) {
                        Ok(Some(st)) => break st,
                        Ok(None) => {
                            // Cancelación cooperativa: no dejar el hijo huérfano.
                            if i.is_cancelled() {
                                kill_tree(isolated_pid);
                                let _ = child.kill();
                                let _ = child.wait();
                                i.check_cancel()?;
                            }
                            if Instant::now() >= deadline {
                                kill_tree(isolated_pid);
                                let _ = child.kill();
                                let _ = child.wait();
                                timed_out = true;
                                break None;
                            }
                            std::thread::sleep(Duration::from_millis(15));
                        }
                        Err(_) => {
                            kill_tree(isolated_pid);
                            break None;
                        }
                    }
                };

                let (out_bytes, out_trunc) = out_h.join().unwrap_or((Vec::new(), false));
                let (err_bytes, err_trunc) = err_h.join().unwrap_or((Vec::new(), false));

                if timed_out {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "run: \"{}\" timed out after {}s",
                        cmd, timeout_secs as i64
                    ))));
                }
                let exit_code = status.and_then(|s| s.code()).unwrap_or(-1);

                let mut m = SynMap::new();
                m.insert("exit_code", syn_int(exit_code as i64));
                m.insert(
                    "stdout".to_string(),
                    syn_text(String::from_utf8_lossy(&out_bytes).into_owned()),
                );
                m.insert(
                    "stderr".to_string(),
                    syn_text(String::from_utf8_lossy(&err_bytes).into_owned()),
                );
                m.insert("stdout_truncated", syn_bool(out_trunc));
                m.insert("stderr_truncated", syn_bool(err_trunc));
                // Lo que se impuso de verdad (el kernel, no lo pedido).
                if let Some(p) = &prepared {
                    let mut iso = SynMap::new();
                    iso.insert("landlock_abi", syn_int(p.report.landlock_abi as i64));
                    iso.insert("network", syn_text(p.report.network.to_string()));
                    iso.insert(
                        "max_memory_mb",
                        p.report.max_memory_bytes.map(|b| syn_int((b / (1024 * 1024)) as i64)).unwrap_or(SynValue::Nothing),
                    );
                    iso.insert(
                        "max_file_mb",
                        p.report.max_file_bytes.map(|b| syn_int((b / (1024 * 1024)) as i64)).unwrap_or(SynValue::Nothing),
                    );
                    m.insert("isolation", syn_map(iso));
                    // v0.6.53: si lo terminó una señal, cuál (`"max_file_mb"`: escribió un archivo
                    // más grande que el tope). `exit_code` queda en -1, como siempre con una señal.
                    let killed = status.as_ref().and_then(|s| synsema_isolate::killed_by(s, &p.report));
                    m.insert("killed_by", killed.map(syn_text).unwrap_or(SynValue::Nothing));
                }
                drop(prepared);
                Ok(syn_map(m))
            }),
        );
    }

    // (fetch vive ahora en synsema-stdlib/http.rs: cliente HTTP real, gateado por net —
    // junto con http/http_get/http_post/http_put/http_delete. El stub "capa 6" se removió.)

    // -- Builtins de time (todos requieren la capability `time`; UTC) --

    // now() → timestamp unix (float).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "now",
            0,
            Rc::new(move |i, _args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "now()")?;
                let real = synsema_core::clock::now_secs_f64();
                // v0.6.46 (E6.4): con el recibo sellado, la lectura queda en el sobre (y con
                // etiquetas, el reloj está cercado).
                if synsema_core::sealed::active() {
                    if let Some(v) = synsema_core::sealed::read_clock(real, i.labels_enabled()) {
                        return Ok(syn_float(v));
                    }
                }
                Ok(syn_float(real))
            }),
        );
    }

    // sleep(seconds) → pausa (cap a 1h). Requiere time (como now()).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "sleep()")?;
                let secs = args.first().and_then(|v| arg_f64(v).ok()).unwrap_or(0.0);
                let secs = secs.clamp(0.0, 3600.0);
                // Dormir en tramos: una cancelación cooperativa (timeout de handler,
                // shutdown, agent_stop) corta el sleep en ≤100 ms, no al vencer.
                let deadline = Instant::now() + std::time::Duration::from_secs_f64(secs);
                // v0.6.42 — bajo `serve`, el hilo que duerme suelta su permiso de ejecución.
                let _w = synsema_core::waiting::waiting();
                loop {
                    i.check_cancel()?;
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(100)));
                }
                Ok(SynValue::Nothing)
            }),
        );
    }

    // format_time(ts | date | datetime, pattern?) → text. Default ISO-8601 ("…Z" para un
    // timestamp). PURO desde v0.6.29: formatear no lee el reloj (sólo `now()` pide `time`).
    {
        interp.register_builtin(
            "format_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                if let SynValue::Time(t) = arg(args, 0)? {
                    return match opt_pattern(args) {
                        Some(p) => Ok(syn_text(synsema_core::temporal::format(t, &p)?)),
                        None => Ok(syn_text(t.to_string())),
                    };
                }
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let out = match opt_pattern(args) {
                    Some(p) => synsema_core::temporal::strftime(&p, "format_time", "", |it| dt.format_with_items(it))?,
                    None => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                };
                Ok(syn_text(out))
            }),
        );
    }

    // parse_time(text, pattern?) → timestamp (float). Inverso de format_time. PURO (v0.6.29).
    {
        interp.register_builtin(
            "parse_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                let s = raw_str(arg(args, 0)?);
                let ts = parse_time_ts(&s, opt_pattern(args).as_deref())?;
                Ok(syn_float(ts))
            }),
        );
    }

    // date_parts(ts | date | datetime) → {year, month, day, hour, minute, second, …}. PURO
    // (v0.6.29); con un date/datetime, en su zona y con weekday/yearday.
    {
        interp.register_builtin(
            "date_parts",
            1,
            Rc::new(move |_i, args, _loc| {
                if let SynValue::Time(t) = arg(args, 0)? {
                    return synsema_core::temporal::parts(t)
                        .ok_or_else(|| Control::Error(RuntimeError::new("date_parts: a duration has no calendar parts")));
                }
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let mut m = SynMap::new();
                m.insert("year", syn_int(dt.year() as i64));
                m.insert("month", syn_int(dt.month() as i64));
                m.insert("day", syn_int(dt.day() as i64));
                m.insert("hour", syn_int(dt.hour() as i64));
                m.insert("minute", syn_int(dt.minute() as i64));
                m.insert("second", syn_int(dt.second() as i64));
                // v0.6.29: las mismas claves que con un date/datetime (un timestamp es UTC).
                m.insert("weekday", syn_int(dt.weekday().number_from_monday() as i64));
                m.insert("yearday", syn_int(dt.ordinal() as i64));
                m.insert("zone", syn_text("UTC"));
                Ok(syn_map(m))
            }),
        );
    }

    // -- Builtins de random (requieren la capability `random`) --
    // paridad con el oráculo: random() = float [0,1), random_int(lo,hi) = entero INCLUSIVO
    // [lo,hi]. RNG no-cripto como el `random` de Python (Mersenne Twister); los valores no
    // son byte-idénticos al oráculo (RNG distinto) — el contrato es rango+tipo+capability.

    // random() → float en [0,1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random",
            -1,
            Rc::new(move |i, args, loc| {
                // v0.6.29 (DATOS-12): `random(g)` con un generador de `rng(seed)` es PURO y
                // reproducible; `random()` sin generador sigue pidiendo la capability.
                if let Some(g) = args.first() {
                    return Ok(syn_float(synsema_core::rng::uniform(i, g, "random", loc)?));
                }
                require(&caps, Capability::new(CapabilityType::Random, None), "random()")?;
                if synsema_core::sealed::active() {
                    if let Some(x) = with_run_rng(|r| rand::Rng::gen::<f64>(r)) {
                        return Ok(syn_float(x));
                    }
                }
                Ok(syn_float(rand::random::<f64>()))
            }),
        );
    }

    // random_int(min, max) → entero inclusivo [min, max].
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random_int",
            -1,
            Rc::new(move |i, args, loc| {
                // Límites ENTEROS (v0.6.29): 1.7 ya no se trunca en silencio.
                let whole = |v: &SynValue, what: &str| -> Result<i64, Control> {
                    match v {
                        SynValue::Number(n) if n.is_integer() => n
                            .to_i64_trunc()
                            .ok_or_else(|| Control::Error(RuntimeError::new(format!("random_int: {} out of range", what)))),
                        other => Err(Control::Error(RuntimeError::new(format!(
                            "random_int: {} must be an integer, got {}",
                            what, other
                        )))),
                    }
                };
                // `random_int(g, min, max)` con un generador de `rng(seed)`: puro y reproducible.
                if args.len() == 3 {
                    let lo = whole(arg(args, 1)?, "min")?;
                    let hi = whole(arg(args, 2)?, "max")?;
                    let g = arg(args, 0)?.clone();
                    return Ok(syn_int(synsema_core::rng::int_in(i, &g, lo, hi, "random_int", loc)?));
                }
                require(&caps, Capability::new(CapabilityType::Random, None), "random_int()")?;
                let lo = whole(arg(args, 0)?, "min")?;
                let hi = whole(arg(args, 1)?, "max")?;
                if lo > hi {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "random_int: min ({}) is greater than max ({})",
                        lo, hi
                    ))));
                }
                if synsema_core::sealed::active() {
                    if let Some(x) = with_run_rng(|r| rand::Rng::gen_range(r, lo..=hi)) {
                        return Ok(syn_int(x));
                    }
                }
                // En nativo, `thread_rng` (ChaCha que se resiembra solo; ronda 4, B3: con `OsRng` era
                // una syscall por llamada, un 19 % más lento en un bucle). En wasm, `OsRng` (el
                // generador de la corrida, sembrado por llamada) con un error claro sin entropía.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    use rand::Rng;
                    return Ok(syn_int(rand::thread_rng().gen_range(lo..=hi)));
                }
                #[cfg(target_arch = "wasm32")]
                {
                    use rand::RngCore;
                    let span = (hi as i128 - lo as i128 + 1) as u128;
                    let zone = u64::MAX as u128 + 1 - ((u64::MAX as u128 + 1) % span);
                    loop {
                        let mut b = [0u8; 8];
                        rand::rngs::OsRng.try_fill_bytes(&mut b).map_err(|_| {
                            Control::Error(RuntimeError::new("random_int: no entropy available from the host"))
                        })?;
                        let x = u64::from_le_bytes(b) as u128;
                        if x < zone {
                            return Ok(syn_int((lo as i128 + (x % span) as i128) as i64));
                        }
                    }
                }
            }),
        );
    }
}

/// v0.6.46 (E6.4) — con el recibo sellado, `random()` y `random_int()` sin generador salen de un
/// ChaCha12 sembrado UNA vez por corrida: la semilla va al sobre, y con ella `--replay` reproduce los
/// mismos números. Cada hilo (el de la corrida, el de cada agente) tiene su flujo, derivado de la
/// semilla y del nombre del hilo, para que dos agentes no saquen la misma secuencia. `random_bytes`,
/// `token` y la generación de claves NO salen de acá (siguen con la entropía del SO): el auditor recibe
/// la semilla, y con ella reproduciría claves y tokens de sesión. `None` sin registro.
fn with_run_rng<T>(f: impl FnOnce(&mut rand::rngs::StdRng) -> T) -> Option<T> {
    use rand::SeedableRng;
    use sha2::{Digest, Sha256};
    thread_local! {
        static RUN_RNG: RefCell<Option<(u64, String, rand::rngs::StdRng)>> = const { RefCell::new(None) };
    }
    let log = synsema_core::sealed::current()?;
    let (id, master) = {
        let mut g = log.lock().unwrap_or_else(|p| p.into_inner());
        // Ronda 2 (R2-B1): cerrado entre el `current()` y el candado: como sin registro.
        if g.is_closed() {
            return None;
        }
        if g.seed.is_none() {
            let mut s = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
            g.seed = Some(synsema_core::bytesutil::hex_encode(&s));
        }
        (g.id, g.seed.clone().unwrap_or_default())
    };
    RUN_RNG.with(|r| {
        let mut r = r.borrow_mut();
        // v0.6.46 (ronda 1, E6-A2): el flujo es el de `sealed::stream()` (el ítem de un
        // `parallel_map`, o el nombre del hilo); cambia de ítem a ítem en el mismo worker.
        let stream = synsema_core::sealed::stream();
        if r.as_ref().map(|x| (x.0, x.1.as_str())) != Some((id, stream.as_str())) {
            let seed: [u8; 32] = Sha256::new()
                .chain_update(b"synsema-run-rng-v1")
                .chain_update(master.as_bytes())
                .chain_update(stream.as_bytes())
                .finalize()
                .into();
            *r = Some((id, stream, rand::rngs::StdRng::from_seed(seed)));
        }
        r.as_mut().map(|x| f(&mut x.2))
    })
}

/// v0.6.46 (ronda 1, E6-A2) — el prefijo de los flujos de un `parallel_map`: un número del flujo del
/// llamador, así dos llamadas (o una anidada en un ítem) no comparten flujos y `--replay` lo
/// reproduce. `None` sin registro de la corrida (y entonces nada cambia).
pub fn run_rng_fork() -> Option<String> {
    with_run_rng(|r| format!("{:032x}", rand::Rng::gen::<u128>(r)))
}

#[cfg(test)]
mod v0620_tests {
    use super::*;
    use synsema_core::parser::parse_source;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!("synsema-caps-v0620-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn slash(p: &std::path::Path) -> String {
        p.to_string_lossy().replace('\\', "/")
    }

    /// Corre un `.syn` con los builtins seguros y los grants dados; devuelve lo impreso.
    fn run(grants: &[(CapabilityType, Option<String>)], src: &str) -> Result<Vec<String>, String> {
        let mut interp = Interpreter::new();
        let mut set = CapabilitySet::new("test");
        for (ty, scope) in grants {
            set.grant(Capability::new(ty.clone(), scope.clone()));
        }
        register_secure_builtins(&interp, Rc::new(RefCell::new(set)));
        let program = parse_source(src, "<test>").map_err(|e| e.to_string())?;
        match interp.execute(&program) {
            Ok(_) => Ok(std::mem::take(&mut interp.output)),
            Err(Control::Error(e)) => Err(e.to_string()),
            Err(_) => Err("control flow escaped the program".to_string()),
        }
    }

    /// v0.6.46 (backlog §10): con `cwd`, un comando relativo se pedía y se corría tal cual: el grant
    /// `exec("./tool")` autorizaba el `./tool` de cualquier carpeta, y cuál corría dependía de la
    /// plataforma. Ahora se resuelve contra el `cwd` y eso es lo que se pide.
    #[test]
    fn run_resolves_a_relative_command_against_cwd() {
        assert_eq!(exec_target("./tool", Some("sub")), ("./sub/tool".to_string(), exec_target("./tool", Some("sub")).1));
        assert_eq!(exec_target("./tool", None).0, "./tool");
        assert_eq!(exec_target("git", Some("sub")).0, "git", "sin separador: el PATH");
        assert_eq!(exec_target("../bin/t", Some("./a/b")).0, "./a/bin/t");
        assert!(std::path::Path::new(&exec_target("./tool", Some("sub")).1).is_absolute(), "se corre absoluto");

        let d = scratch("exec-cwd");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let name = if cfg!(windows) { "tool.cmd" } else { "tool" };
        let body = if cfg!(windows) { "@echo off\r\necho from-sub\r\n" } else { "#!/bin/sh\necho from-sub\n" };
        std::fs::write(d.join("sub").join(name), body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("sub").join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let sub = slash(&d.join("sub"));
        let src = format!("let r be run(\"./{}\", [], 20, {{\"cwd\": \"{}\"}})\nprint(trim(r.stdout))", name, sub);
        let denied = run(&[(CapabilityType::Exec, Some(format!("./{}", name)))], &src).unwrap_err();
        assert!(denied.contains(&format!("{}/{}", sub, name)), "pide el archivo que corre: {}", denied);
        let out = run(&[(CapabilityType::Exec, Some(format!("{}/{}", sub, name)))], &src).unwrap();
        assert_eq!(out, vec!["from-sub".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bundle_prefix_is_recognized_and_stripped() {
        assert_eq!(bundle_prefix("bundle:data/x.json"), (Space::Bundle, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("bundle:./data/../x"), (Space::Bundle, "x".to_string()));
        assert_eq!(bundle_prefix("disk:data/x.json"), (Space::Disk, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("data/x.json"), (Space::Auto, "data/x.json".to_string()));
        assert_eq!(bundle_prefix("bundle:"), (Space::Bundle, ".".to_string()));
    }

    /// §4.1 — borrar bajo file.write: sin grant deniega; con grant borra; tipos y ausencias
    /// se dicen con claridad.
    #[test]
    fn delete_file_requires_file_write_and_is_honest() {
        let d = scratch("delete-file");
        let f = d.join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let scope = format!("{}/*", slash(&d));
        let fp = slash(&f);
        let denied = run(&[], &format!("print(delete_file(\"{}\"))", fp)).unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        assert!(f.exists(), "sin grant no se toca nada");
        let out = run(&[(CapabilityType::FileWrite, Some(scope.clone()))], &format!("print(delete_file(\"{}\"))", fp)).unwrap();
        assert_eq!(out, vec!["true"]);
        assert!(!f.exists());
        let missing = run(&[(CapabilityType::FileWrite, Some(scope.clone()))], &format!("print(delete_file(\"{}\"))", fp)).unwrap_err();
        assert!(missing.contains("File not found"), "{}", missing);
        // El scope `<dir>/*` cubre lo que está DENTRO del dir (no el dir mismo): el caso "es un
        // directorio" se prueba sobre un subdirectorio cubierto.
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let on_dir = run(&[(CapabilityType::FileWrite, Some(scope))], &format!("print(delete_file(\"{}\"))", slash(&sub))).unwrap_err();
        assert!(on_dir.contains("is a directory"), "{}", on_dir);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn delete_dir_is_non_recursive_by_default() {
        let d = scratch("delete-dir");
        let sub = d.join("sub");
        std::fs::create_dir_all(sub.join("deep")).unwrap();
        std::fs::write(sub.join("deep").join("f.txt"), "x").unwrap();
        let empty = d.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        // `**`: el recursivo exige `file.write` sobre cada ruta del árbol (v0.6.45: `*` es un nivel).
        let scope = format!("{}/**", slash(&d));
        let g = [(CapabilityType::FileWrite, Some(scope))];
        assert_eq!(run(&g, &format!("print(delete_dir(\"{}\"))", slash(&empty))).unwrap(), vec!["true"]);
        assert!(!empty.exists());
        let not_empty = run(&g, &format!("print(delete_dir(\"{}\"))", slash(&sub))).unwrap_err();
        assert!(not_empty.contains("is not empty"), "{}", not_empty);
        assert!(sub.exists(), "sin recursive no se borra nada");
        let bad_opt = run(&g, &format!("print(delete_dir(\"{}\", {{\"force\": true}}))", slash(&sub))).unwrap_err();
        assert!(bad_opt.contains("unknown option"), "{}", bad_opt);
        assert_eq!(run(&g, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&sub))).unwrap(), vec!["true"]);
        assert!(!sub.exists());
        let on_file = {
            let f = d.join("f.txt");
            std::fs::write(&f, "x").unwrap();
            run(&g, &format!("print(delete_dir(\"{}\"))", slash(&f))).unwrap_err()
        };
        assert!(on_file.contains("is a file"), "{}", on_file);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// §4.2 — cwd() bajo `file.read(".")` (la misma grant que `list_dir(".")`): sin grant o
    /// con una grant que no cubre `.` deniega; con `.`, `./**` o `**` la devuelve normalizada.
    /// v0.6.45: `./*` (los archivos de la carpeta) ya no cubre la carpeta misma; `**` sí.
    #[test]
    fn cwd_requires_file_read_on_dot() {
        let want = normalize_path(&std::env::current_dir().unwrap().to_string_lossy());
        let denied = run(&[], "print(cwd())").unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        let denied = run(&[(CapabilityType::FileRead, Some("./data/*".to_string()))], "print(cwd())").unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        let denied = run(&[(CapabilityType::FileRead, Some("./*".to_string()))], "print(cwd())").unwrap_err();
        assert!(denied.contains("Capability not granted"), "{}", denied);
        for scope in [".", "./**", "**"] {
            assert_eq!(run(&[(CapabilityType::FileRead, Some(scope.to_string()))], "print(cwd())").unwrap(), vec![want.clone()], "scope {}", scope);
        }
    }

    /// Auditoría externa — borrar recursivo exige `file.write` sobre cada ruta del árbol.
    #[test]
    fn delete_dir_recursive_requires_file_write_on_every_path() {
        let d = scratch("delete-tree-scope");
        let tree = d.join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::write(tree.join("sub").join("f.txt"), "x").unwrap();
        // Scope exacto sobre el dir raíz: cubre borrarlo a él, no a lo que tiene adentro.
        let exact = [(CapabilityType::FileWrite, Some(slash(&tree)))];
        let e = run(&exact, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&tree))).unwrap_err();
        assert!(e.contains("Capability not granted"), "{}", e);
        assert!(tree.join("sub").join("f.txt").exists(), "nada borrado");
        let wide = [(CapabilityType::FileWrite, Some(format!("{}/**", slash(&d))))];
        assert_eq!(run(&wide, &format!("print(delete_dir(\"{}\", {{\"recursive\": true}}))", slash(&tree))).unwrap(), vec!["true"]);
        assert!(!tree.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// §4.4 — sin bundle montado: el disco manda y `bundle:` explícito falla claro.
    #[test]
    fn user_files_go_to_disk_and_explicit_bundle_prefix_without_a_bundle() {
        let d = scratch("disk-first");
        let f = d.join("data.txt");
        std::fs::write(&f, "hola").unwrap();
        let g = [(CapabilityType::FileRead, Some(format!("{}/*", slash(&d))))];
        assert_eq!(run(&g, &format!("print(read_file(\"{}\"))", slash(&f))).unwrap(), vec!["hola"]);
        assert_eq!(run(&g, &format!("print(file_exists(\"{}\"))", slash(&f))).unwrap(), vec!["true"]);
        let e = run(&g, &format!("print(read_file(\"bundle:{}\"))", slash(&f))).unwrap_err();
        assert!(e.contains("is not in the bundle"), "{}", e);
        let e = run(&g, "print(list_dir(\"bundle:\"))").unwrap_err();
        assert!(e.contains("has no bundle"), "{}", e);
        // list_dir sobre el disco sigue igual (sobre un subdir cubierto por el scope `<dir>/*`).
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("one.txt"), "1").unwrap();
        let out = run(&g, &format!("print(length(list_dir(\"{}\")))", slash(&sub))).unwrap();
        assert_eq!(out, vec!["1"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod v0646_e8_tests {
    use super::*;

    fn link_dir(target: &Path, link: &Path) {
        #[cfg(windows)]
        assert!(Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link.to_string_lossy().replace('/', "\\"))
            .arg(target.to_string_lossy().replace('/', "\\"))
            .output()
            .unwrap()
            .status
            .success());
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    /// La carrera con el chequeo de verdad: `require` pasa con `proj/sub` como carpeta, y antes de
    /// abrir alguien la cambia por un link a otro lado. `open_read` juzga dónde quedó el handle y
    /// niega con el mensaje del link; un link que queda adentro sigue valiendo.
    #[test]
    fn the_open_is_judged_where_the_handle_really_is() {
        let d = std::env::temp_dir().join(format!("synsema-e8-secure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        std::fs::create_dir_all(d.join("proj/otra")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        std::fs::write(d.join("proj/sub/f.txt"), "adentro").unwrap();
        std::fs::write(d.join("proj/otra/f.txt"), "otra").unwrap();
        std::fs::write(d.join("afuera/f.txt"), "SECRETO").unwrap();
        let root = d.to_string_lossy().replace('\\', "/");
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        caps.borrow_mut().grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/proj/**", root))));
        let path = format!("{}/proj/sub/f.txt", root);
        assert!(require(&caps, Capability::new(CapabilityType::FileRead, Some(path.clone())), "read_file()").is_ok());
        std::fs::remove_dir_all(d.join("proj/sub")).unwrap();
        link_dir(&d.join("afuera"), &d.join("proj/sub"));
        let e = match open_read(&caps, &path, "read_file()") {
            Err(Control::Error(e)) => e.message.clone(),
            Ok(_) => panic!("abrió el archivo de afuera"),
            Err(_) => panic!("otro control"),
        };
        assert!(e.contains("a link (symlink or junction) on the way leads outside"), "{}", e);
        // Un link que queda adentro del grant, sí.
        std::fs::remove_dir_all(d.join("proj/sub")).ok();
        let _ = std::fs::remove_file(d.join("proj/sub"));
        link_dir(&d.join("proj/otra"), &d.join("proj/sub"));
        let Ok(f) = open_read(&caps, &path, "read_file()") else { panic!("un link que queda adentro se negó") };
        let t = read_text(f).unwrap();
        assert_eq!(t, "otra");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn denied_message(r: Result<(), crate::nofollow::Refused<Control>>) -> String {
        match r {
            Err(crate::nofollow::Refused::Denied(Control::Error(ref e))) => e.message.clone(),
            Err(crate::nofollow::Refused::Io(e)) => panic!("se esperaba una negación, fue de E/S: {}", e),
            _ => panic!("se esperaba una negación"),
        }
    }

    fn wrote(r: Result<(), crate::nofollow::Refused<Control>>) {
        match r {
            Ok(()) => {}
            Err(crate::nofollow::Refused::Io(e)) => panic!("no escribió: {}", e),
            Err(_) => panic!("no escribió: negado"),
        }
    }

    /// Lo mismo para reemplazar (`write_file`, `edit_file`): con la carpeta cambiada por un link
    /// afuera después del chequeo, no se escribe nada afuera; un link que queda adentro reemplaza
    /// donde lleva, y no deja temporales.
    #[test]
    fn the_replace_is_judged_where_the_folder_really_is() {
        let d = std::env::temp_dir().join(format!("synsema-e8-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        std::fs::create_dir_all(d.join("proj/otra")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        std::fs::write(d.join("proj/sub/f.txt"), "viejo").unwrap();
        std::fs::write(d.join("afuera/f.txt"), "INTACTO").unwrap();
        let root = d.to_string_lossy().replace('\\', "/");
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        caps.borrow_mut().grant(Capability::new(CapabilityType::FileWrite, Some(format!("{}/proj/**", root))));
        let path = format!("{}/proj/sub/f.txt", root);
        let tys = [CapabilityType::FileWrite];
        // Sin link: reemplaza, y no queda ningún temporal.
        wrote(atomic_write(&caps, &path, b"nuevo", &tys, "write_file()"));
        assert_eq!(std::fs::read_to_string(d.join("proj/sub/f.txt")).unwrap(), "nuevo");
        assert_eq!(std::fs::read_dir(d.join("proj/sub")).unwrap().count(), 1);
        // La carrera: pasó el chequeo y la carpeta pasa a ser un link afuera.
        assert!(require(&caps, Capability::new(CapabilityType::FileWrite, Some(path.clone())), "write_file()").is_ok());
        std::fs::remove_dir_all(d.join("proj/sub")).unwrap();
        link_dir(&d.join("afuera"), &d.join("proj/sub"));
        let m = denied_message(atomic_write(&caps, &path, b"PISADO", &tys, "write_file()"));
        assert!(m.contains("a link (symlink or junction) on the way leads outside"), "{}", m);
        assert_eq!(std::fs::read_to_string(d.join("afuera/f.txt")).unwrap(), "INTACTO");
        assert_eq!(std::fs::read_dir(d.join("afuera")).unwrap().count(), 1);
        // La carrera más fina: la carpeta ya se abrió y juzgó, y DESPUÉS se la mueve y en su lugar
        // queda un link afuera. El reemplazo va relativo al handle: cae en la carpeta juzgada (ahora
        // `sub_vieja`), no afuera.
        std::fs::remove_dir_all(d.join("proj/sub")).ok();
        let _ = std::fs::remove_file(d.join("proj/sub"));
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        let recheck = |_: &str| -> Result<(), Control> { panic!("sin link no se vuelve a juzgar") };
        let Ok(Some(dir)) = crate::nofollow::parent_checked(&path, &recheck) else { panic!("no abrió la carpeta") };
        std::fs::rename(d.join("proj/sub"), d.join("proj/sub_vieja")).unwrap();
        link_dir(&d.join("afuera"), &d.join("proj/sub"));
        dir.replace_with(b"en la juzgada").unwrap();
        drop(dir);
        assert_eq!(std::fs::read_to_string(d.join("proj/sub_vieja/f.txt")).unwrap(), "en la juzgada");
        assert_eq!(std::fs::read_to_string(d.join("afuera/f.txt")).unwrap(), "INTACTO");
        assert_eq!(std::fs::read_dir(d.join("afuera")).unwrap().count(), 1);
        // Lo mismo por `atomic_write` entera (ronda 1, E8-B3): la carpeta se mueve entre que se abre y
        // juzga y el reemplazo.
        let _ = std::fs::remove_dir(d.join("proj/sub"));
        let _ = std::fs::remove_file(d.join("proj/sub"));
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        let dd = d.clone();
        BETWEEN.with(|b| {
            *b.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(dd.join("proj/sub"), dd.join("proj/sub_vieja2")).unwrap();
                link_dir(&dd.join("afuera"), &dd.join("proj/sub"));
            }))
        });
        wrote(atomic_write(&caps, &path, b"en la juzgada 2", &tys, "write_file()"));
        assert_eq!(std::fs::read_to_string(d.join("proj/sub_vieja2/f.txt")).unwrap(), "en la juzgada 2");
        assert_eq!(std::fs::read_to_string(d.join("afuera/f.txt")).unwrap(), "INTACTO");
        assert_eq!(std::fs::read_dir(d.join("afuera")).unwrap().count(), 1);
        // Un link que queda adentro: reemplaza donde lleva.
        let _ = std::fs::remove_dir(d.join("proj/sub"));
        let _ = std::fs::remove_file(d.join("proj/sub"));
        link_dir(&d.join("proj/otra"), &d.join("proj/sub"));
        wrote(atomic_write(&caps, &path, b"por el link", &tys, "write_file()"));
        assert_eq!(std::fs::read_to_string(d.join("proj/otra/f.txt")).unwrap(), "por el link");
        assert_eq!(std::fs::read_dir(d.join("proj/otra")).unwrap().count(), 1);
        // Reemplazar un archivo abierto por otro (lectores sin compartir borrado no lo traban).
        let held = std::fs::File::open(d.join("proj/otra/f.txt")).unwrap();
        wrote(atomic_write(&caps, &path, b"con un lector", &tys, "write_file()"));
        drop(held);
        assert_eq!(std::fs::read_to_string(d.join("proj/otra/f.txt")).unwrap(), "con un lector");
        let _ = std::fs::remove_dir_all(&d);
    }
    /// v0.6.53 (`make_dir`): la carpeta de arriba pasa a ser un link afuera entre el juicio por
    /// nombre y la creación: no se crea nada afuera (se juzga dónde queda de verdad).
    #[test]
    fn make_dir_is_judged_where_the_folder_really_is() {
        let d = std::env::temp_dir().join(format!("synsema-e8-mkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        let root = d.to_string_lossy().replace('\\', "/");
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        caps.borrow_mut().grant(Capability::new(CapabilityType::FileWrite, Some(format!("{}/proj/**", root))));
        assert!(make_dir_checked(&caps, &format!("{}/proj/sub/x/y", root)).is_ok());
        assert!(d.join("proj/sub/x/y").is_dir());
        let dd = d.clone();
        BETWEEN.with(|b| {
            *b.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(dd.join("proj/sub"), dd.join("proj/sub_vieja")).unwrap();
                link_dir(&dd.join("afuera"), &dd.join("proj/sub"));
            }))
        });
        let r = make_dir_checked(&caps, &format!("{}/proj/sub/z", root));
        assert!(matches!(&r, Err(Control::Error(e)) if e.message.contains("Capability not granted")), "{:?}", r.err().map(|_| ()));
        assert!(!d.join("afuera/z").exists(), "creó del otro lado del link");
        assert_eq!(std::fs::read_dir(d.join("afuera")).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// v0.6.51 (L1, specs/v0.6.51-modelos.md): la fila de un link lleva el `is_dir` de su destino
    /// sólo si el programa podría leerlo; uno que sale del permiso dice `is_dir: false` sin mirar
    /// afuera, igual con el grant de la carpeta sola.
    #[test]
    fn list_dir_does_not_look_past_a_link_that_leaves_the_grant() {
        let d = std::env::temp_dir().join(format!("synsema-l1-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proj/otra")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        std::fs::write(d.join("proj/f.txt"), "abc").unwrap();
        link_dir(&d.join("proj/otra"), &d.join("proj/adentro"));
        link_dir(&d.join("afuera"), &d.join("proj/sale"));
        let root = d.to_string_lossy().replace('\\', "/");
        let list = |grant: String| -> Vec<String> {
            let mut interp = Interpreter::new();
            let mut set = CapabilitySet::new("t");
            set.grant(Capability::new(CapabilityType::FileRead, Some(grant)));
            register_secure_builtins(&interp, Rc::new(RefCell::new(set)));
            let src = format!("each e in list_dir(\"{}/proj\")\n    print(e.name + \" \" + text(e.is_dir) + \" \" + text(e.size) + \" \" + text(e.is_link))\n", root);
            let program = synsema_core::parser::parse_source(&src, "<t>").unwrap();
            assert!(interp.execute(&program).is_ok());
            std::mem::take(&mut interp.output)
        };
        let all = list(format!("{}/proj/**", root));
        assert_eq!(all, ["adentro true 0 true", "f.txt false 3 false", "otra true 0 false", "sale false 0 true"]);
        let folder = list(format!("{}/proj", root));
        assert_eq!(folder, ["adentro false 0 true", "f.txt false 3 false", "otra true 0 false", "sale false 0 true"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// v0.6.52, auditoría r1: lo que juzga `isolate` antes de lanzar (en cualquier sistema: `pin` es
/// `canonicalize` fuera de Linux).
#[cfg(test)]
mod v0652_isolate_tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("synsema-caps-v0652-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("data").join("secret")).unwrap();
        std::fs::create_dir_all(d.join("other")).unwrap();
        d
    }

    fn slash(p: &std::path::Path) -> String {
        let s = p.to_string_lossy().replace('\\', "/");
        s.strip_prefix("//?/").map(str::to_string).unwrap_or(s)
    }

    fn caps_with(grant: &str, deny: Option<&str>) -> Rc<RefCell<CapabilitySet>> {
        let mut set = CapabilitySet::new("test");
        set.grant(Capability::new(CapabilityType::FileRead, Some(grant.to_string())));
        if let Some(d) = deny {
            set.deny(Capability::new(CapabilityType::FileRead, Some(d.to_string())));
        }
        Rc::new(RefCell::new(set))
    }

    fn msg(r: Result<synsema_isolate::Pin, Control>) -> String {
        match r {
            Ok(_) => "ok".into(),
            Err(Control::Error(e)) => e.to_string(),
            Err(_) => "otro control".into(),
        }
    }

    /// M1: Landlock no tiene reglas de denegación. Un `deny` dentro de la carpeta delegada (o uno que
    /// la abarca por un patrón) rechaza la delegación; uno afuera no.
    #[test]
    fn a_deny_inside_a_delegated_folder_refuses_it() {
        let d = scratch("deny");
        let r = slash(&d);
        let data = format!("{}/data/**", r);
        for (deny, want) in [
            (Some(format!("{}/data/secret/**", r)), "lies inside it"),
            (Some(format!("{}/**/*.key", r)), "lies inside it"),
            (Some(format!("{}/*/secret/*", r)), "lies inside it"),
            (Some(format!("{}/data", r)), "lies inside it"),
            (Some(format!("{}/other/**", r)), "ok"),
            // Ronda 2 (N4): un patrón que no baja más que la carpeta no la alcanza.
            (Some(format!("{}/*.txt", r)), "ok"),
            // Ronda 3 (N2): el patrón que nombra la carpeta misma, como el literal.
            (Some(format!("{}/*", r)), "lies inside it"),
            (Some(format!("{}/*/x", r)), "lies inside it"),
            (Some(format!("{}/*/x", r).replace("/*/x", "/*.d/x")), "ok"),
            (Some(r.clone()), "ok"),
            (None, "ok"),
        ] {
            let caps = caps_with(&format!("{}/**", r), deny.as_deref());
            let got = msg(isolate_path(&caps, CapabilityType::FileRead, &data));
            assert!(got.contains(want), "{:?}: {}", deny, got);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A1: `..` después de una carpeta es error antes de juzgar (el `require` lo resolvería por
    /// nombre y el sistema en disco). Al principio (`../x`) vale.
    #[test]
    fn dotdot_after_a_folder_is_refused() {
        for (p, bad) in [
            ("./lnk/../work/**", true),
            ("a/b/..", true),
            ("/x/../y", true),
            ("../x/**", false),
            ("../../x", false),
            ("./data/**", false),
            ("a..b/c", false),
        ] {
            assert_eq!(dotdot_after_folder(p), bad, "{}", p);
        }
        let caps = caps_with("./**", None);
        let got = msg(isolate_path(&caps, CapabilityType::FileRead, "./x/../data/**"));
        assert!(got.contains("has `..` after a folder"), "{}", got);
        assert!(check_exec_path("run", "./lnk/../tool", None).is_err());
        assert!(check_exec_path("run", "./tool", Some("./a/../b")).is_err());
        assert!(check_exec_path("run", "python3", Some("./a/../b")).is_ok(), "sin ruta, el cwd no decide qué corre");
        assert!(check_exec_path("run", "../tool", None).is_ok());
    }

    /// M3: una opción desconocida es error y nombra las válidas.
    #[test]
    fn an_unknown_option_is_an_error() {
        let mut m = SynMap::new();
        m.insert("isolated", syn_bool(true));
        let opts = syn_map(m);
        let Err(Control::Error(e)) = check_option_keys("run", Some(&opts), RUN_OPTIONS) else { panic!("aceptó") };
        assert!(e.to_string().contains("unknown option \"isolated\" (valid options: cwd, stdin"), "{}", e);
        let mut m = SynMap::new();
        m.insert("isolate", syn_bool(true));
        assert!(check_option_keys("run", Some(&syn_map(m)), RUN_OPTIONS).is_ok());
        assert!(check_option_keys("run", Some(&SynValue::Nothing), RUN_OPTIONS).is_ok());
        // Ronda 2 (B2): unas opciones que no son un mapa no se ignoran.
        for bad in [syn_text("isolate".to_string()), syn_list(vec![syn_bool(true)])] {
            let Err(Control::Error(e)) = check_option_keys("run", Some(&bad), RUN_OPTIONS) else { panic!("aceptó {:?}", bad) };
            assert!(e.to_string().contains("run: options must be a map, got"), "{}", e);
        }
    }

    fn caps_rw(read: Option<&str>, write: &str, deny_read: Option<&str>) -> Rc<RefCell<CapabilitySet>> {
        let mut set = CapabilitySet::new("test");
        if let Some(r) = read {
            set.grant(Capability::new(CapabilityType::FileRead, Some(r.to_string())));
        }
        set.grant(Capability::new(CapabilityType::FileWrite, Some(write.to_string())));
        if let Some(d) = deny_read {
            set.deny(Capability::new(CapabilityType::FileRead, Some(d.to_string())));
        }
        Rc::new(RefCell::new(set))
    }

    /// Ronda 2 (M1): para el kernel una carpeta de escritura también se lee. Delegar escritura pide
    /// también `file.read`, y un `deny file.read` adentro rechaza la delegación.
    #[test]
    fn delegating_write_needs_read_too() {
        let d = scratch("write");
        let r = slash(&d);
        let all = format!("{}/**", r);
        let data = format!("{}/data/**", r);
        let got = msg(isolate_path(&caps_rw(None, &all, None), CapabilityType::FileWrite, &data));
        assert!(got.contains("also lets the child read it: the program needs `file.read("), "{}", got);
        assert_eq!(msg(isolate_path(&caps_rw(Some(&all), &all, None), CapabilityType::FileWrite, &data)), "ok");
        let secret = format!("{}/data/secret/**", r);
        let got = msg(isolate_path(&caps_rw(Some(&all), &all, Some(&secret)), CapabilityType::FileWrite, &data));
        assert!(got.contains("lies inside it"), "{}", got);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 2 (M2): con el lugar fijado (`with_physical`), un scope de carpeta (`base/**`) se juzga
    /// por ese lugar, no por una nueva resolución del nombre. Si la base es la de un grant (un link
    /// legítimo), el grant va con ella.
    #[test]
    fn a_folder_is_judged_by_its_pinned_place() {
        let d = scratch("pinned");
        let r = slash(&d);
        let check = |grant: &str, base: &str, real: &str, req: &str| {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(grant.to_string())));
            let req = Capability::new(CapabilityType::FileRead, Some(req.to_string()));
            synsema_core::capscope::with_physical(base, real, || set.check_cause(&req, "t").is_ok())
        };
        let (data, other) = (format!("{}/data", r), format!("{}/other", r));
        assert!(!check(&format!("{}/data/**", r), &format!("{}/data/secret", r), &other, &format!("{}/data/secret/**", r)));
        assert!(!check(&format!("{}/data/**", r), &format!("{}/data/secret", r), &other, &format!("{}/data/secret", r)));
        assert!(check(&format!("{}/data/**", r), &format!("{}/data/secret", r), &format!("{}/data/secret", r), &format!("{}/data/secret/**", r)));
        assert!(check(&format!("{}/data/**", r), &data, &other, &format!("{}/data/**", r)), "la base del grant es el link");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 3 (A1): dentro de un área, el lugar fijado (el handle de E8, el `pin` de `isolate`) tiene
    /// que ser adonde lleva el nombre sin seguir links del área. Con el link del hijo puesto se
    /// deniega; si el link ya volvió a ser carpeta (la carrera de dos cambios), el nombre no llega al
    /// lugar fijado y también. Sin cambios, el lugar de verdad pasa.
    #[cfg(unix)]
    #[test]
    fn a_fixed_place_inside_an_area_must_be_where_the_name_leads() {
        let d = scratch("fixed-area").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work").join("sub")).unwrap();
        std::fs::write(d.join("other").join("secret.txt"), "S").unwrap();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        // Registrada y ya soltada: el hijo terminó.
        drop(crate::isolated_areas::borrow(&[d.join("work")]).unwrap());
        let judge = |base: &str, real: &str, req: &str| {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/work/**", r))));
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/work/sub/**", r))));
            let req = Capability::new(CapabilityType::FileRead, Some(req.to_string()));
            synsema_core::capscope::with_physical(base, real, || set.check_cause(&req, "t"))
        };
        let (sub, other) = (format!("{}/work/sub", r), format!("{}/other", r));
        let file = format!("{}/work/sub/secret.txt", r);
        let area = |c: Result<(), crate::model::DenyCause>| matches!(c, Err(crate::model::DenyCause::IsolatedArea(_)));
        // Carpeta de verdad: el lugar fijado es el suyo.
        assert!(judge(&sub, &sub, &format!("{}/**", sub)).is_ok());
        // La carrera de dos cambios: el pin/handle siguió el link, ahora es carpeta otra vez.
        assert!(area(judge(&file, &format!("{}/secret.txt", other), &file)), "E8");
        assert!(area(judge(&sub, &other, &format!("{}/**", sub))), "pin");
        // Con el link del hijo puesto.
        std::fs::remove_dir(d.join("work").join("sub")).unwrap();
        std::os::unix::fs::symlink(d.join("other"), d.join("work").join("sub")).unwrap();
        assert!(area(judge(&file, &format!("{}/secret.txt", other), &file)), "E8");
        assert!(area(judge(&sub, &other, &format!("{}/**", sub))), "pin");
        // Un link del programa que lleva a uno del hijo tampoco: `x` → `work/sub` → afuera.
        std::os::unix::fs::symlink(d.join("work").join("sub"), d.join("x")).unwrap();
        let mut set = CapabilitySet::new("test");
        set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/x/**", r))));
        assert!(area(set.check_cause(&Capability::new(CapabilityType::FileRead, Some(format!("{}/x/secret.txt", r))), "t")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 4 (A1): mientras un hijo con escritura corre, su carpeta está prestada: ninguna ruta que
    /// pase por ella o termine en ella se concede (tampoco por un link del programa que lleva
    /// adentro, ni con un lugar fijado adentro). Al soltar, vuelve a concederse; con dos hijos sobre
    /// la misma carpeta, hasta que se suelten los dos.
    #[cfg(unix)]
    #[test]
    fn a_folder_in_use_by_a_running_child_is_not_touched() {
        let d = scratch("in-use").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::fs::write(d.join("work").join("f.txt"), "x").unwrap();
        std::fs::write(d.join("other").join("f.txt"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("work"), d.join("x")).unwrap();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let judge = |req: &str| {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", r))));
            set.check_cause(&Capability::new(CapabilityType::FileRead, Some(req.to_string())), "t")
        };
        let in_use = |c: Result<(), crate::model::DenyCause>| matches!(c, Err(crate::model::DenyCause::AreaInUse(_)));
        let work = format!("{}/work", r);
        let file = format!("{}/work/f.txt", r);
        let first = crate::isolated_areas::borrow(&[d.join("work")]).unwrap();
        let second = crate::isolated_areas::borrow(&[d.join("work")]).unwrap();
        assert!(in_use(judge(&file)), "un archivo adentro");
        assert!(in_use(judge(&work)), "la carpeta misma");
        assert!(in_use(judge(&format!("{}/x/f.txt", r))), "por un link del programa");
        assert!(in_use(synsema_core::capscope::with_physical(&file, &file, || judge(&file))), "lugar fijado");
        assert!(judge(&format!("{}/other/f.txt", r)).is_ok(), "afuera no se toca");
        drop(first);
        assert!(in_use(judge(&file)), "el otro hijo sigue corriendo");
        drop(second);
        assert!(judge(&file).is_ok() && judge(&format!("{}/x/f.txt", r)).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 4 (N1): un ciclo de links lejos de las áreas no se reporta como un link de un área (lo
    /// deniega la regla de siempre, o el sistema al abrir).
    #[cfg(unix)]
    #[test]
    fn a_link_cycle_away_from_the_areas_is_not_theirs() {
        let d = scratch("cycle").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::os::unix::fs::symlink(d.join("data").join("b"), d.join("data").join("a")).unwrap();
        std::os::unix::fs::symlink(d.join("data").join("a"), d.join("data").join("b")).unwrap();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        drop(crate::isolated_areas::borrow(&[d.join("work")]).unwrap());
        let mut set = CapabilitySet::new("test");
        set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/data/**", r))));
        let c = set.check_cause(&Capability::new(CapabilityType::FileRead, Some(format!("{}/data/a/f.txt", r))), "t");
        assert!(!matches!(c, Err(crate::model::DenyCause::IsolatedArea(_))), "{:?}", c);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 4 (A1): lo que otra tarea ya juzgó dentro de la carpeta (y todavía no terminó de hacer)
    /// se espera antes de prestarla; lo que juzgó afuera no.
    #[cfg(unix)]
    #[test]
    fn a_borrow_waits_for_what_another_task_already_judged_inside() {
        let d = scratch("hold-wait").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        synsema_core::op_hold::enable();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        // Otra tarea: juzga `req` dentro de un builtin que tarda `ms` en volver.
        let task = |req: String, ms: u64| {
            let run = run.clone();
            let r = r.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let h = std::thread::spawn(move || {
                let _in = run.enter();
                let _frame = synsema_core::op_hold::enter();
                let mut set = CapabilitySet::new("test");
                set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", r))));
                assert!(set.check_cause(&Capability::new(CapabilityType::FileRead, Some(req)), "t").is_ok());
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(ms));
            });
            rx.recv().unwrap();
            h
        };
        let t0 = std::time::Instant::now();
        let h = task(format!("{}/other/f.txt", r), 400);
        drop(crate::isolated_areas::borrow(&[d.join("work")]).unwrap());
        assert!(t0.elapsed() < std::time::Duration::from_millis(300), "afuera no se espera: {:?}", t0.elapsed());
        h.join().unwrap();
        let t0 = std::time::Instant::now();
        let h = task(format!("{}/work/f.txt", r), 400);
        drop(crate::isolated_areas::borrow(&[d.join("work")]).unwrap());
        assert!(t0.elapsed() >= std::time::Duration::from_millis(350), "adentro se espera: {:?}", t0.elapsed());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Otra tarea: juzga cada una de `reqs` dentro de un mismo builtin que tarda `ms` en volver.
    #[cfg(unix)]
    fn judging_task(run: &std::sync::Arc<synsema_core::run_scope::RunScope>, root: &str, reqs: Vec<String>, ms: u64) -> std::thread::JoinHandle<()> {
        let run = run.clone();
        let root = root.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let _in = run.enter();
            let _frame = synsema_core::op_hold::enter();
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", root))));
            for req in reqs {
                assert!(set.check_cause(&Capability::new(CapabilityType::FileRead, Some(req)), "t").is_ok());
            }
            tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(ms));
        });
        rx.recv().unwrap();
        h
    }

    /// Ronda 5 (A1): un builtin que juzga varias rutas las sostiene todas. El préstamo espera la que
    /// toca la carpeta aunque antes se haya juzgado otra lejos de ella (un extractor: sus entradas,
    /// después las carpetas por nombre). Si no termina a tiempo (`HOLD_WAIT`, 1 s en los tests), el
    /// error nombra esa ruta y la carpeta que toca (N1).
    #[cfg(unix)]
    #[test]
    fn a_borrow_waits_for_every_path_a_task_judged() {
        let d = scratch("hold-every").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        synsema_core::op_hold::enable();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let t0 = std::time::Instant::now();
        let h = judging_task(&run, &r, vec![format!("{}/other/f.txt", r), format!("{}/work/l/y", r)], 400);
        drop(crate::isolated_areas::borrow(&[d.join("work")]).unwrap());
        assert!(t0.elapsed() >= std::time::Duration::from_millis(350), "la segunda ruta se espera: {:?}", t0.elapsed());
        h.join().unwrap();
        let h = judging_task(&run, &r, vec![format!("{}/other/f.txt", r), format!("{}/work/f.txt", r)], 1600);
        let e = crate::isolated_areas::borrow(&[d.join("work")]).err().expect("no terminó a tiempo");
        assert_eq!((e.held, e.area), (d.join("work").join("f.txt"), d.join("work")));
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 5 (M1): una carpeta se reconoce por lo que es en disco, no sólo por su nombre. Prestada
    /// con otro nombre (acá un link; en la WSL, `./WORK` sobre `/mnt/c`, que no distingue
    /// mayúsculas), una ruta por el nombre de siempre igual llega a ella, un link del hijo adentro
    /// igual no se sigue, y lo que otra tarea juzgó por ese nombre igual se espera.
    #[cfg(unix)]
    #[test]
    fn a_folder_is_known_by_what_it_is_not_by_its_name() {
        let d = scratch("alias").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::fs::write(d.join("work").join("f.txt"), "x").unwrap();
        std::fs::write(d.join("other").join("f.txt"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("work"), d.join("alias")).unwrap();
        synsema_core::op_hold::enable();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let judge = |req: &str| {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", r))));
            set.check_cause(&Capability::new(CapabilityType::FileRead, Some(req.to_string())), "t")
        };
        let in_use = |c: Result<(), crate::model::DenyCause>| matches!(c, Err(crate::model::DenyCause::AreaInUse(_)));
        let lent = crate::isolated_areas::borrow(&[d.join("alias")]).unwrap();
        assert!(in_use(judge(&format!("{}/work/f.txt", r))), "adentro, por el otro nombre");
        assert!(in_use(judge(&format!("{}/work", r))), "la carpeta misma");
        assert!(judge(&format!("{}/other/f.txt", r)).is_ok(), "afuera no se toca");
        drop(lent);
        let t0 = std::time::Instant::now();
        let h = judging_task(&run, &r, vec![format!("{}/work/f.txt", r)], 400);
        drop(crate::isolated_areas::borrow(&[d.join("alias")]).unwrap());
        assert!(t0.elapsed() >= std::time::Duration::from_millis(350), "se espera: {:?}", t0.elapsed());
        h.join().unwrap();
        std::os::unix::fs::symlink(d.join("other"), d.join("work").join("l")).unwrap();
        let c = judge(&format!("{}/work/l/f.txt", r));
        assert!(matches!(c, Err(crate::model::DenyCause::IsolatedArea(_))), "el link del hijo: {:?}", c);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 7 (N1): una carpeta delegada se borra y otra nueva toma su inodo (ext4 lo reusa): la
    /// nueva no es un área, y un link que el programa pone adentro se sigue. Donde el inodo no se
    /// reusa (tmpfs) no hay nada que probar.
    #[cfg(unix)]
    #[test]
    fn a_folder_that_takes_the_inode_of_a_deleted_area_is_not_an_area() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("reused").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("v2")).unwrap();
        std::fs::write(d.join("v2").join("x.txt"), "x").unwrap();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let judge = |req: &str| {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", r))));
            set.check_cause(&Capability::new(CapabilityType::FileRead, Some(req.to_string())), "t")
        };
        for i in 0..200 {
            let (tmp, cache) = (d.join(format!("tmp{}", i)), d.join(format!("cache{}", i)));
            std::fs::create_dir(&tmp).unwrap();
            drop(crate::isolated_areas::borrow(&[tmp.clone()]).unwrap());
            let ino = std::fs::metadata(&tmp).unwrap().ino();
            std::fs::remove_dir(&tmp).unwrap();
            std::fs::create_dir(&cache).unwrap();
            if std::fs::metadata(&cache).unwrap().ino() != ino {
                continue;
            }
            std::os::unix::fs::symlink(d.join("v2"), cache.join("current")).unwrap();
            let c = judge(&format!("{}/cache{}/current/x.txt", r, i));
            assert!(c.is_ok(), "la carpeta nueva no es el área borrada: {:?}", c);
            // La de verdad sigue siendo un área: un link adentro no se sigue.
            std::fs::create_dir(&tmp).unwrap();
            std::os::unix::fs::symlink(d.join("v2"), tmp.join("l")).unwrap();
            let c = judge(&format!("{}/tmp{}/l/x.txt", r, i));
            assert!(matches!(c, Err(crate::model::DenyCause::IsolatedArea(_))), "por el nombre: {:?}", c);
            // Y si la nueva se delega, es un área por sí misma (no «la misma» que la borrada).
            drop(crate::isolated_areas::borrow(&[cache.clone()]).unwrap());
            std::os::unix::fs::symlink(d.join("v2"), cache.join("l")).unwrap();
            let c = judge(&format!("{}/cache{}/l/x.txt", r, i));
            assert!(matches!(c, Err(crate::model::DenyCause::IsolatedArea(_))), "delegada: {:?}", c);
            let _ = std::fs::remove_dir_all(&d);
            return;
        }
        eprintln!("el inodo no se reusó: no se prueba");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 6 (N2): lo mismo con un lugar fijado (un handle abierto, un `pin`). La carpeta prestada
    /// con otro nombre (`alias` → `work`), un fd en `work/f.txt` y un nombre que hoy lleva a otro
    /// lado (`x` → `other`): mientras está prestada, `InUse` por el fd; después, no coinciden y el fd
    /// está en un área, así que se deniega igual.
    #[cfg(unix)]
    #[test]
    fn a_fixed_place_in_a_folder_known_by_another_name() {
        let d = scratch("alias-fixed").canonicalize().unwrap();
        let r = slash(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::fs::write(d.join("work").join("f.txt"), "x").unwrap();
        std::fs::write(d.join("other").join("f.txt"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("work"), d.join("alias")).unwrap();
        std::os::unix::fs::symlink(d.join("other"), d.join("x")).unwrap();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let (lit, real) = (format!("{}/x/f.txt", r), format!("{}/work/f.txt", r));
        let judge = || {
            let mut set = CapabilitySet::new("test");
            set.grant(Capability::new(CapabilityType::FileRead, Some(format!("{}/**", r))));
            let req = Capability::new(CapabilityType::FileRead, Some(lit.clone()));
            synsema_core::capscope::with_physical(&lit, &real, || set.check_cause(&req, "t"))
        };
        let lent = crate::isolated_areas::borrow(&[d.join("alias")]).unwrap();
        let c = judge();
        assert!(matches!(c, Err(crate::model::DenyCause::AreaInUse(_))), "prestada: {:?}", c);
        drop(lent);
        let c = judge();
        assert!(matches!(c, Err(crate::model::DenyCause::IsolatedArea(_))), "después: {:?}", c);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un hijo falso que anota qué se le pidió.
    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Waitable for Fake {
        type Status = i32;
        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            self.calls.borrow_mut().push("try_wait");
            Ok(Some(0))
        }
        fn wait(&mut self) -> std::io::Result<i32> {
            self.calls.borrow_mut().push("wait");
            Ok(0)
        }
    }

    /// Ronda 2 (B1): aislado, nunca se recoge sin matar al grupo antes: con `exited` en falso no se
    /// llama a `try_wait` (que recogería al hijo que salió recién); con `exited`, `kill` antes de `wait`.
    #[test]
    fn an_isolated_child_is_reaped_only_after_its_group_dies() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut c = Fake { calls: calls.clone() };
        let kill = |_| calls.borrow_mut().push("kill");
        use synsema_isolate::ChildState;
        assert_eq!(wait_step(&mut c, Some(7), |_| ChildState::Running, kill).unwrap(), None);
        assert!(calls.borrow().is_empty(), "{:?}", calls.borrow());
        assert_eq!(wait_step(&mut c, Some(7), |_| ChildState::Exited, kill).unwrap(), Some(Some(0)));
        assert_eq!(*calls.borrow(), ["kill", "wait"]);
        calls.borrow_mut().clear();
        // Ronda 3 (B1): sin zombie (SIGCHLD ignorado) no se espera al timeout.
        assert_eq!(wait_step(&mut c, Some(7), |_| ChildState::Gone, kill).unwrap(), Some(Some(0)));
        assert_eq!(*calls.borrow(), ["kill", "try_wait"]);
        calls.borrow_mut().clear();
        assert_eq!(wait_step(&mut c, None, |_| panic!("sin aislar no hay grupo"), kill).unwrap(), Some(Some(0)));
        assert_eq!(*calls.borrow(), ["try_wait"]);
    }
}

/// v0.6.53: lo que juzga `run` antes de lanzar, en cualquier sistema.
#[cfg(test)]
mod v0653_run_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// El programa que lleva fuera del sistema y de lo delegado nombra la carpeta a delegar (la de
    /// arriba de un `bin/`); adentro de algo de eso, no hay aviso.
    #[test]
    fn a_program_that_leads_out_of_reach_names_the_folder_to_grant() {
        let uv = Path::new("/home/u/.local/share/uv/python/cpython-3.12/bin/python3.12");
        let venv = vec![PathBuf::from("/home/u/proj/venv")];
        assert_eq!(link_out_of_reach(uv, &venv), Some(PathBuf::from("/home/u/.local/share/uv/python/cpython-3.12")));
        assert_eq!(link_out_of_reach(Path::new("/home/u/tools/run.sh"), &venv), Some(PathBuf::from("/home/u/tools")));
        assert_eq!(link_out_of_reach(Path::new("/usr/bin/python3.8"), &venv), None, "sistema");
        let both = vec![venv[0].clone(), PathBuf::from("/home/u/.local/share/uv/python")];
        assert_eq!(link_out_of_reach(uv, &both), None, "delegado");
        // Por componentes, no por texto: `/usr2` no es `/usr`.
        assert_eq!(link_out_of_reach(Path::new("/usr2/bin/x"), &[]), Some(PathBuf::from("/usr2")));
    }

    fn secret() -> SynValue {
        SynValue::Secret(synsema_core::types::Obj::new(synsema_core::secret::SecretInner::new("K".to_string(), "v".to_string())))
    }

    /// Un `secret()` en los argumentos, el `env` o el `stdin` de `run` es error y dice dónde está.
    #[test]
    fn a_secret_for_the_child_of_run_is_an_error() {
        let list = |v: Vec<SynValue>| syn_list(v);
        let map = |k: &str, v: SynValue| {
            let mut m = SynMap::new();
            m.insert(k, v);
            syn_map(m)
        };
        let msg = |r: Result<(), Control>| match r {
            Err(Control::Error(e)) => e.message.to_string(),
            _ => String::new(),
        };
        let a = msg(no_secret_to_child(Some(&list(vec![syn_text("x".to_string()), secret()])), None, None));
        assert!(a.starts_with("run: argument 2 is a secret — reveal()") && a.ends_with("nothing ran"), "{}", a);
        let e = msg(no_secret_to_child(None, Some(&map("CLAVE", secret())), None));
        assert!(e.starts_with("run: env \"CLAVE\" is a secret"), "{}", e);
        let s = msg(no_secret_to_child(None, None, Some(&secret())));
        assert!(s.starts_with("run: stdin is a secret"), "{}", s);
        let ok = no_secret_to_child(Some(&list(vec![syn_text("x".to_string())])), Some(&map("A", syn_text("b".to_string()))), Some(&syn_text("in".to_string())));
        assert!(ok.is_ok());
    }
}
