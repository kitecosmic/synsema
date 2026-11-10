//! `run_program(source, opts)` — Synsema ejecutando Synsema bajo un techo que no puede
//! escapar. Gateado por `require sandbox_run` (deny-by-default, sin scope).
//!
//! El hijo es un PROCESO del mismo binario (`current_exe --engine run - --format json …`),
//! no un intérprete in-process: `env()` y los knobs leen `std::env::var` con prioridad
//! absoluta, no hay abstracción de cwd, y el ledger de `spend`/`sign`, la identidad mTLS
//! y la propiedad del TTY son estado del proceso — un hijo in-process no podría OCULTAR
//! nada del padre. Con un proceso, "env reemplazado", "cwd propio", "timeout duro" y
//! "exit code" son verdad gratis, y el audit del hijo vuelve como valor (el informe
//! `--format json` tiene la MISMA forma que `syn.run()` en wasm).
//!
//! Reglas:
//! - techo efectivo = `opts.ceiling` ∩ lo que el padre cubre en un `check` (grants,
//!   cadena de padres, techo del host, `sandbox` vigente). Lo que no cubre se recorta —
//!   no es error — y queda en el audit del padre con `reason: "above parent ceiling"`.
//! - `env` REEMPLAZA el entorno del hijo (más el protocolo: profundidad, sin `.env`,
//!   sin chequeo de updates, y `SystemRoot` en Windows — el CRT lo exige).
//! - un `secret` en `env` es error: el padre tiene que `reveal()` (auditado) a propósito.
//! - el hijo nunca es más nativo que el padre (`pure` padre → `pure` hijo).
//! - `timeout` (default 30 s) mata el ÁRBOL del hijo; la cancelación del padre también.

use synsema_core::types::SynMap;
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::time::{Duration, Instant};

use synsema_capabilities::model::{
    build_ceiling, Capability, CapabilityAuditEntry, CapabilitySet, CapabilityType, Delegation,
};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_int, syn_list, syn_map, syn_text, SynValue};
use synsema_stdlib::json::json_to_syn;

use crate::host::{profile, Profile};

/// `reason` del audit del padre por cada item del techo pedido que el padre no cubre.
pub const ABOVE_PARENT_CEILING: &str = "above parent ceiling";
/// `reason` del audit del padre cuando el hijo pidió `native` bajo un padre `pure`.
pub const ABOVE_PARENT_PROFILE: &str = "above parent profile";

/// Knobs del runtime que `run_program` lee del entorno (documentados en `.env.example`).
pub const RUN_PROGRAM_ENV_VARS: &[&str] = &["SYNSEMA_RUN_PROGRAM_MAX_DEPTH"];
/// Protocolo padre→hijo (NO es un knob de usuario): profundidad de anidamiento actual.
pub const DEPTH_VAR: &str = "SYNSEMA_RUN_DEPTH";
/// Protocolo interno padre → hijo (como `DEPTH_VAR`): el SUJETO del hijo (identidad, techo de
/// gasto y presupuesto LLM delegados) en JSON. Lo fija el runtime DESPUÉS del `env` del
/// programa: un programa no elige la identidad de su hijo. No es un knob del host.
pub const RUN_SUBJECT_VAR: &str = "SYNSEMA_RUN_SUBJECT";

/// v0.6.51 (ronda 1, N4): el máximo del sujeto (variable de entorno) y de la línea de comandos que
/// se le pasan al hijo; debajo del tope de Windows para una variable y para la línea (32 767).
pub const MAX_CHILD_CONTEXT_BYTES: usize = 30_000;

/// Cota superior del largo de la línea de comandos que arma Windows con `exe` y `args`: cada uno
/// entre comillas y separado por un espacio, con un escape por cada `"` y por cada `\`.
fn command_line_len(exe: &str, args: &[&str]) -> usize {
    std::iter::once(exe)
        .chain(args.iter().copied())
        .map(|a| a.len() + 3 + a.bytes().filter(|b| *b == b'"' || *b == b'\\').count())
        .sum()
}

/// v0.6.45 — un scope de ruta relativo (`./data/*`) se decidió contra el cwd del PADRE; el hijo lo
/// resolvería contra el suyo (con `cwd`, o un `cd` del hijo, el techo se anclaba en otro lado). Viaja
/// absoluto. Una URL de base de datos o `:memory:` no es una ruta.
fn absolute_paths(cap: &Capability) -> Capability {
    let is_path = matches!(
        cap.ty(),
        CapabilityType::File | CapabilityType::FileRead | CapabilityType::FileWrite | CapabilityType::Db
    );
    match cap.scope() {
        Some(s) if is_path && !(cap.ty() == CapabilityType::Db && (synsema_capabilities::model::is_db_url(s) || s == ":memory:")) => {
            cap.with_scope(Some(synsema_core::capscope::absolute_scope(s)))
        }
        _ => cap.clone(),
    }
}
pub const DEFAULT_MAX_DEPTH: u32 = 4;

/// v0.6.54 — las opciones que `run_program` entiende. Una clave mal escrita (`"ceilng"`) corría al
/// hijo sin el techo pedido; como `run` desde v0.6.52, una desconocida es error y no corre nada.
pub const RUN_PROGRAM_OPTIONS: &[&str] = &["ceiling", "profile", "env", "timeout", "cwd", "filename", "explain"];

/// v0.6.54 — cuánto stderr del hijo se guarda (el mismo default que `max_output` de `run`); lo que
/// pasa de ahí se drena y se descarta, y `stderr_truncated` lo dice.
pub const MAX_CHILD_STDERR_BYTES: usize = 10 * 1024 * 1024;
/// v0.6.54 (M2 de la ronda 1) — y cuántas líneas: cada línea es un valor de la lista, y 10 MB de
/// saltos de línea eran 10 millones de valores (476 MB en el padre). Pasado el tope también es
/// `stderr_truncated`.
pub const MAX_CHILD_STDERR_LINES: usize = 100_000;
/// v0.6.54 (N4 de la ronda 1) — el informe del hijo (su `stdout`) se lee hasta este tamaño; uno
/// más grande no se lee y es un error.
pub const MAX_CHILD_REPORT_BYTES: usize = 32 * 1024 * 1024;
/// v0.6.54 (N4) — cuántas líneas de `output` se guardan (lo demás se descarta y
/// `output_truncated` lo dice), y cuántas entradas de `errors` y de `audit`.
pub const MAX_CHILD_OUTPUT_LINES: usize = 100_000;
pub const DEFAULT_TIMEOUT_SECS: f64 = 30.0;

/// Ronda 3 (M4) — variables con las que el motor elige rutas del host.
fn engine_path_var(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    matches!(
        u.as_str(),
        "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TEMP" | "TMPDIR" | "APPDATA" | "LOCALAPPDATA"
            | "OLLAMA_MODELS"
    ) || u.starts_with("XDG_")
        || u.starts_with("HF_")
        || u.starts_with("HUGGINGFACE_")
}

fn rt(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn map_get(m: &SynValue, key: &str) -> Option<SynValue> {
    match m {
        SynValue::Map(m) => m.borrow().get(key).cloned(),
        _ => None,
    }
}

fn text_of(v: &SynValue, what: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        SynValue::Secret(_) => Err(rt(format!(
            "run_program: {} is a secret — reveal() it explicitly (audited) if the child really needs the value",
            what
        ))),
        other => Err(rt(format!("run_program: {} must be text, got {}", what, other.type_name()))),
    }
}

/// ¿Este proceso es el hijo de un `run_program`?
pub(crate) fn is_child() -> bool {
    depth_limits().0 > 0
}

/// Profundidad actual (0 en el proceso raíz) y máximo permitido.
fn depth_limits() -> (u32, u32) {
    let depth = std::env::var(DEPTH_VAR).ok().and_then(|v| v.parse().ok()).unwrap_or(0u32);
    let max = std::env::var("SYNSEMA_RUN_PROGRAM_MAX_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH);
    (depth, max)
}

/// Un proceso hijo que se mata como árbol (Job Object / grupo de procesos).
fn spawn_tree(cmd: &mut std::process::Command) -> Result<synsema_stdlib::proc::TreeChild, String> {
    synsema_stdlib::proc::spawn_tree(cmd)
}

/// Recarga la memoria del padre al volver el hijo (también si el padre se cancela en el medio).
struct ReloadOnDrop(Option<crate::engine::ChildState>);

impl Drop for ReloadOnDrop {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            (s.reload)();
        }
    }
}

/// `child`: la memoria con base en disco de la corrida que registra el builtin (`None` si no
/// persiste): su carpeta va al hijo y, si el techo le cede `memory`, se recarga al volver.
pub(crate) fn register_run_program_builtin(
    interp: &Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    child: Option<crate::engine::ChildState>,
) {
    interp.register_builtin(
        "run_program",
        -1,
        Rc::new(move |i, args, _loc| {
            // 1) La puerta: `require sandbox_run`.
            caps.borrow_mut()
                .require(&Capability::new(CapabilityType::SandboxRun, None), "run_program()")
                .map_err(|v| Control::Error(v.into_error()))?;

            let source = match args.first() {
                Some(v) => text_of(v, "source")?,
                None => return Err(rt("run_program: missing source")),
            };
            let opts = args.get(1).cloned().unwrap_or(SynValue::Nothing);
            synsema_capabilities::secure::check_option_keys("run_program", Some(&opts), RUN_PROGRAM_OPTIONS)?;

            // 2) Profundidad (protocolo por env; el knob es del host).
            let (depth, max_depth) = depth_limits();
            if depth + 1 > max_depth {
                return Err(rt(format!(
                    "run_program: max depth {} exceeded (set SYNSEMA_RUN_PROGRAM_MAX_DEPTH to raise it)",
                    max_depth
                )));
            }

            // 3) Perfil: nunca más nativo que el padre.
            let wanted = match map_get(&opts, "profile") {
                Some(v) => text_of(&v, "profile")?,
                None => "pure".to_string(),
            };
            let mut child_profile = Profile::parse(&wanted)
                .ok_or_else(|| rt(format!("run_program: profile must be \"native\" or \"pure\", got \"{}\"", wanted)))?;
            if child_profile == Profile::Native && profile() == Profile::Pure {
                caps.borrow_mut().push_audit(CapabilityAuditEntry {
                    capability: Capability::new(CapabilityType::SandboxRun, Some("profile=native".to_string())),
                    granted: false,
                    source: "run_program()".to_string(),
                    reason: ABOVE_PARENT_PROFILE.to_string(),
                    origin: "program",
                    context: None,
                });
                child_profile = Profile::Pure;
            }

            // 4) Techo pedido ∩ lo que el padre cubre. `check_silent` decide igual que un
            //    `check` (denials, techo del host, grants, padres, sandbox) sin auditar
            //    cada item; los recortados dejan UNA entrada con la razón.
            // v0.6.51 (C1): el token del `ceiling`, con todos sus bloques, como capa del hijo.
            let mut token_layer: Option<Delegation> = None;
            let requested: Vec<Capability> = match map_get(&opts, "ceiling") {
                // T1 (identidad): el map que devolvió `captoken_verify` (o un map literal de
                // caps): el hijo corre bajo ESA autoridad. Lo local al proceso sigue el
                // baseline de `--sandbox` (stdout + time) — un token no lo gobierna — salvo el
                // caveat `deterministic`, que le quita el reloj como se lo quita al padre.
                Some(SynValue::Map(m)) => {
                    let m = m.borrow();
                    let (caps_map, deterministic) = match m.get("caps") {
                        Some(SynValue::Map(c)) => (
                            c.borrow().to_map(),
                            matches!(m.get("caveats"), Some(SynValue::Map(cv)) if matches!(cv.borrow().get("deterministic"), Some(SynValue::Bool(true)))),
                        ),
                        _ => (m.to_map(), false),
                    };
                    let mut caps_list = synsema_stdlib::captoken::ceiling_from_caps_map(&caps_map)
                        .map_err(|e| rt(format!("run_program: ceiling: {}", e)))?;
                    if let Some(SynValue::Text(id)) = m.get("id") {
                        let earlier = synsema_stdlib::captoken::earlier_layers(&m, synsema_stdlib::captoken::ceiling_from_caps_map)
                            .map_err(|e| rt(format!("run_program: ceiling: {}", e)))?;
                        token_layer = Some(Delegation::token(id.to_string(), caps_list.clone(), deterministic).with_earlier(earlier));
                    }
                    caps_list.push(Capability::new(CapabilityType::Stdout, None));
                    if !deterministic {
                        caps_list.push(Capability::new(CapabilityType::Time, None));
                    }
                    caps_list
                }
                Some(v) => {
                    let spec = text_of(&v, "ceiling")?;
                    match spec.trim() {
                        "sandbox" => build_ceiling(true, None),
                        other => build_ceiling(false, Some(other)),
                    }
                    .map_err(|e| rt(format!("run_program: ceiling: {}", e)))?
                    .unwrap_or_default()
                }
                None => build_ceiling(true, None)
                    .map_err(|e| rt(format!("run_program: ceiling: {}", e)))?
                    .unwrap_or_default(),
            };
            let mut kept: Vec<Capability> = Vec::new();
            for cap in requested {
                let covered = caps.borrow_mut().check_silent(&cap);
                if covered {
                    kept.push(cap);
                } else {
                    caps.borrow_mut().push_audit(CapabilityAuditEntry {
                        capability: cap,
                        granted: false,
                        source: "run_program()".to_string(),
                        reason: ABOVE_PARENT_CEILING.to_string(),
                        origin: "program",
                        context: None,
                    });
                }
            }
            // v0.6.45 — un scope de ruta relativo (`./data/*`) se decidió contra el cwd del PADRE; el
            // hijo lo resolvería contra el suyo, y con `cwd` (o un `cd` del hijo) el techo se anclaba
            // en otro lado (`cwd: "/"` convertía `./data` en `/data`). Viajan absolutos.
            for cap in kept.iter_mut() {
                *cap = absolute_paths(cap);
            }
            // Ronda 2 (A5): el techo viaja como `--cap-set` separado por comas. Un scope con una
            // coma (`{"file.read": "data/x,exec,file.read=y"}`, o un cwd con coma al volverlo
            // absoluto) se partía en items y le daba al hijo `exec` sin scope. No viaja.
            // Ronda 3 (B4): un scope vacío o con espacios en los bordes tampoco viaja (`build_ceiling`
            // lo recorta y un `Some("")` se volvía una capability sin scope: total en el hijo).
            if let Some(bad) = kept.iter().find(|c| c.scope().is_some_and(|s| s.trim().is_empty() || s.trim() != s)) {
                return Err(rt(format!(
                    "run_program: ceiling: the scope of {} is empty or has spaces at its ends, which cannot travel to the child",
                    bad
                )));
            }
            if let Some(bad) = kept.iter().find(|c| c.scope().is_some_and(|s| s.contains(','))) {
                return Err(rt(format!(
                    "run_program: ceiling: the scope of {} has a comma, which cannot travel to the child",
                    bad
                )));
            }
            let cap_set = if kept.is_empty() {
                "none".to_string()
            } else {
                kept.iter().map(|c| c.cap_set_item()).collect::<Vec<_>>().join(",")
            };

            // 5) env (reemplaza), timeout, cwd, filename.
            let mut env: Vec<(String, String)> = Vec::new();
            match map_get(&opts, "env") {
                None | Some(SynValue::Nothing) => {}
                Some(SynValue::Map(m)) => {
                    for (k, v) in m.borrow().iter() {
                        // Ronda 2 (A6): una `SYNSEMA_*` configura al MOTOR del hijo, no al programa
                        // (`SYNSEMA_AUDIT` le hacía crear/truncar cualquier archivo, `SYNSEMA_STATE_DIR`
                        // y los modelos locales elegían rutas del host). Las que el hijo necesita las
                        // pone `run_program` más abajo; el programa no puede.
                        if k.to_ascii_uppercase().starts_with("SYNSEMA_") {
                            return Err(rt(format!(
                                "run_program: env cannot set {} (SYNSEMA_* variables configure the engine, not the program)",
                                k
                            )));
                        }
                        // Ronda 3 (M4): las variables con las que el motor del hijo elige RUTAS del
                        // host (dónde audita `reveal`, sus temporales, de dónde carga modelos) son la
                        // misma clase que `SYNSEMA_*`.
                        if engine_path_var(k) {
                            return Err(rt(format!(
                                "run_program: env cannot set {} (it chooses where the child's engine reads or writes on the host)",
                                k
                            )));
                        }
                        env.push((k.to_string(), text_of(v, &format!("env \"{}\"", k))?));
                    }
                }
                Some(_) => return Err(rt("run_program: env must be a map of text")),
            }
            // T1: el sujeto del hijo es el del padre — identidad, techo de gasto y presupuesto
            // LLM delegados — por una variable interna que se pisa después del `env` del
            // programa (el programa no elige la identidad de su hijo). El techo delegado ya
            // viaja como `--cap-set`.
            let mut subject = crate::subject::Subject::capture(i, &caps);
            // v0.6.51 (C1): el `--cap-set` es la intersección por nombre y pierde la regla de `net` (una
            // dirección privada la tiene que nombrar cada capa). Viaja además todo lo que limitaba al
            // padre, capa por capa (`layers_for_child`), y el token del `ceiling` con sus bloques.
            let mut layers = caps.borrow().layers_for_child();
            layers.extend(token_layer);
            for d in layers.iter_mut() {
                d.caps = d.caps.iter().map(absolute_paths).collect();
                d.earlier = d.earlier.iter().map(|l| l.iter().map(absolute_paths).collect()).collect();
            }
            subject.delegations = layers;
            // v0.6.51 (ronda 1, N4): el sujeto viaja en una variable de entorno, y Windows corta una
            // cerca de 32 767 caracteres: el `spawn` fallaba con un error del sistema. El mismo tope
            // en todas las plataformas (un programa no anda en Linux y se rompe en Windows), con un
            // mensaje del motor. La línea de comandos se mide entera más abajo.
            let subject_json = subject.to_env_json();
            if subject_json.len() > MAX_CHILD_CONTEXT_BYTES {
                return Err(rt(format!(
                    "run_program: the caller's capabilities are too many to pass to the child ({} bytes; the limit is {})",
                    subject_json.len(),
                    MAX_CHILD_CONTEXT_BYTES
                )));
            }
            env.retain(|(k, _)| k != "SYNSEMA_IDENTITY" && k != RUN_SUBJECT_VAR);
            let timeout_secs = match map_get(&opts, "timeout") {
                None | Some(SynValue::Nothing) => DEFAULT_TIMEOUT_SECS,
                Some(SynValue::Number(n)) => n.to_f64(),
                Some(_) => return Err(rt("run_program: timeout must be a number of seconds")),
            };
            if !(timeout_secs > 0.0) {
                return Err(rt("run_program: timeout must be > 0"));
            }
            let cwd = match map_get(&opts, "cwd") {
                None | Some(SynValue::Nothing) => None,
                Some(v) => Some(text_of(&v, "cwd")?),
            };
            let filename = match map_get(&opts, "filename") {
                None | Some(SynValue::Nothing) => "<run_program>".to_string(),
                Some(v) => text_of(&v, "filename")?,
            };
            // Ronda 3 (M4): `filename` es una ETIQUETA (errores y audit): con una carpeta, el estado
            // del hijo (`memory`) se anclaba ahí (`/x/y/p.syn` → `/x/y/.synsema/state`).
            if filename.contains(['/', '\\']) || filename.contains("..") {
                return Err(rt(format!(
                    "run_program: filename is a label, not a path (no folders): {:?}",
                    filename
                )));
            }

            // v0.6.54: `explain: true` — el informe del hijo trae el diagnóstico de `--explain`.
            let explain = match map_get(&opts, "explain") {
                None | Some(SynValue::Nothing) => false,
                Some(SynValue::Bool(b)) => b,
                Some(_) => return Err(rt("run_program: explain must be true or false")),
            };

            // 6) El hijo: el mismo binario, en modo motor, fuente por stdin, informe JSON.
            let exe = std::env::current_exe().map_err(|e| rt(format!("run_program: cannot resolve the engine binary: {}", e)))?;
            let mut args = vec![
                "--engine",
                "run",
                "-",
                "--format",
                "json",
                "--profile",
                child_profile.name(),
                "--cap-set",
                cap_set.as_str(),
                "--filename",
                filename.as_str(),
            ];
            if explain {
                args.push("--diagnostic");
            }
            // Ronda 2 (N2): Windows corta la línea de comandos ENTERA (el ejecutable, cada argumento
            // con sus comillas y escapes) en 32 767 caracteres. Se mide antes, en todas las
            // plataformas, y no sólo el techo: un `filename` largo también la pasaba.
            let line = command_line_len(&exe.to_string_lossy(), &args);
            if line > MAX_CHILD_CONTEXT_BYTES {
                return Err(rt(format!(
                    "run_program: the child's command line would be {} characters (its ceiling and filename); the limit is {}",
                    line, MAX_CHILD_CONTEXT_BYTES
                )));
            }
            let mut c = std::process::Command::new(&exe);
            c.args(args).env_clear();
            for (k, v) in &env {
                c.env(k, v);
            }
            // Ronda 4 (M3): dónde guarda el hijo su estado (`memory`) y sus temporales lo decide el
            // PADRE, no la opción `cwd` del programa (con `cwd` afuera, el hijo creaba
            // `<cwd>/.synsema/state` aunque el techo no tuviera ningún `file.write`). Va ABSOLUTO y es
            // el mismo lugar que usa el padre: su `SYNSEMA_STATE_DIR`, o `.synsema/state` junto al
            // archivo del programa que llama (con un programa por stdin, junto al cwd del padre). El
            // hijo comparte así las bases `memory` que su techo le deja (`memory=m`).
            // Ronda 4 (revisión): la carpeta de la ENTRADA del padre (no la del módulo que llama: con
            // `loc.file` un `run_program` desde `src/lib.syn` dejaba el estado en `src/.synsema`).
            // Ronda 5 (M1): la carpeta de la memoria de ESTA corrida (con varios programas en un
            // proceso, la del que llama). Sin base en disco (stdin, perfil puro, sin home), el hijo
            // no recibe ninguna y tampoco persiste (`resolve_declared_state`).
            if let Some(s) = &child {
                c.env("SYNSEMA_STATE_DIR", &s.dir);
            }
            // v0.6.58 (§5.1, P11): el caché de paquetes del hijo es el del padre, absoluto. El programa
            // no lo elige (no puede poner `SYNSEMA_*`); sin caché resoluble, el hijo no recibe ninguno.
            if let Ok(dir) = synsema_core::modtable::cache_dir(i.project().and_then(|p| p.root.as_deref())) {
                let abs = if dir.is_absolute() {
                    dir
                } else {
                    std::env::current_dir().map(|c| c.join(&dir)).unwrap_or(dir)
                };
                c.env("SYNSEMA_MODULE_CACHE", abs);
            }
            // Ronda 5 (B1): padre e hijo comparten la base; lo que el hijo escribió se trae al volver.
            // Un hijo `pure` no toca el disco: no hay nada que recargar (ronda 6, N1).
            let shares_memory =
                child_profile == Profile::Native && kept.iter().any(|c| c.ty() == CapabilityType::Memory);
            let _reload = ReloadOnDrop(if shares_memory { child.clone() } else { None });
            for k in ["TMP", "TEMP", "TMPDIR"] {
                if let Ok(v) = std::env::var(k) {
                    c.env(k, v);
                }
            }
            c.env(DEPTH_VAR, (depth + 1).to_string())
                .env(RUN_SUBJECT_VAR, &subject_json)
                .env("SYNSEMA_RUN_PROGRAM_MAX_DEPTH", max_depth.to_string())
                .env("SYNSEMA_NO_UPDATE_CHECK", "1")
                // Sin `.env` del cwd: el "reemplazo" de env no puede filtrar el del padre.
                .env("SYNSEMA_ENV_FILE", "");
            #[cfg(windows)]
            {
                // El CRT/WinSock no arranca sin SystemRoot. Única excepción del reemplazo.
                if let Ok(sr) = std::env::var("SystemRoot") {
                    c.env("SystemRoot", sr);
                }
            }
            if let Some(dir) = &cwd {
                c.current_dir(dir);
            }
            synsema_capabilities::secure::hide_child_window(&mut c);
            c.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut tree = spawn_tree(&mut c).map_err(|e| rt(format!("run_program: {}", e)))?;

            if let Some(mut si) = tree.child.stdin.take() {
                let src = source.clone();
                std::thread::spawn(move || {
                    let _ = si.write_all(src.as_bytes());
                });
            }
            let out = tree.child.stdout.take();
            let err = tree.child.stderr.take();
            let out_h = std::thread::spawn(move || match out {
                Some(o) => synsema_capabilities::secure::read_capped(o, MAX_CHILD_REPORT_BYTES),
                None => (Vec::new(), false),
            });
            let err_h = std::thread::spawn(move || match err {
                Some(e) => synsema_capabilities::secure::read_capped(e, MAX_CHILD_STDERR_BYTES),
                None => (Vec::new(), false),
            });

            let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
            let mut timed_out = false;
            let status = loop {
                match tree.child.try_wait() {
                    Ok(Some(st)) => break Some(st),
                    Ok(None) => {
                        if i.is_cancelled() {
                            tree.kill_tree();
                            let _ = tree.child.wait();
                            i.check_cancel()?;
                        }
                        if Instant::now() >= deadline {
                            tree.kill_tree();
                            let _ = tree.child.wait();
                            timed_out = true;
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break None,
                }
            };
            let (stdout_bytes, report_too_big) = out_h.join().unwrap_or_default();
            let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
            drop(stdout_bytes);
            let (stderr_bytes, mut stderr_truncated) = err_h.join().unwrap_or_default();
            let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
            drop(stderr_bytes);
            let exit_code = status.and_then(|s| s.code());
            // v0.6.54: el stderr del hijo (su `eprint` y los avisos de su motor), en líneas, hasta
            // `MAX_CHILD_STDERR_LINES`.
            let mut lines = stderr.lines();
            let stderr_lines =
                syn_list(lines.by_ref().take(MAX_CHILD_STDERR_LINES).map(|l| syn_text(l.to_string())).collect());
            if lines.next().is_some() {
                stderr_truncated = true;
            }

            // 7) El informe del hijo → valor.
            let mut r: SynMap = SynMap::new();
            let parsed: Option<(serde_json::Value, ReportCut)> = if timed_out || report_too_big {
                None
            } else {
                parse_child_report(stdout.trim())
            };
            drop(stdout);
            let mut output_truncated = false;
            let mut audit_truncated = false;
            match parsed {
                Some((v, cut)) => {
                    output_truncated = cut.output;
                    // R2-3: el hijo recorta su propio audit (`audit_dropped`); el padre, por si acaso,
                    // también (`cut.audit`). Ninguno de los dos cambia `ok`.
                    audit_truncated =
                        cut.audit || v.get("audit_dropped").and_then(|x| x.as_u64()).unwrap_or(0) > 0;
                    let (ok, errors) = mark_cut(
                        v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                        v.get("errors").cloned().unwrap_or(serde_json::Value::Array(vec![])),
                        &cut,
                    );
                    r.insert("ok", syn_bool(ok));
                    r.insert("output", json_to_syn(v.get("output").unwrap_or(&serde_json::Value::Array(vec![]))));
                    r.insert("errors", json_to_syn(&errors));
                    r.insert("audit", json_to_syn(v.get("audit").unwrap_or(&serde_json::Value::Array(vec![]))));
                    r.insert(
                        "exit",
                        match exit_code {
                            Some(c) => syn_int(c as i64),
                            None => SynValue::Nothing,
                        },
                    );
                    r.insert("timed_out", syn_bool(false));
                    r.insert(
                        "llm_tokens",
                        syn_int(v.get("llm_tokens").and_then(|x| x.as_i64()).unwrap_or(0)),
                    );
                    // v0.6.20 — pasos del intérprete hijo (contador determinista; ver `steps()`).
                    r.insert("steps", syn_int(v.get("steps").and_then(|x| x.as_i64()).unwrap_or(0)));
                    r.insert(
                        "diagnostic",
                        match v.get("diagnostic") {
                            Some(d) if explain && d.is_object() => json_to_syn(d),
                            _ => SynValue::Nothing,
                        },
                    );
                }
                None => {
                    let msg = if timed_out {
                        format!("run_program: timed out after {}s", timeout_secs)
                    } else if report_too_big {
                        format!(
                            "run_program: the child's report is larger than {} MB and was not read — \
                             print less (write big results to a file)",
                            MAX_CHILD_REPORT_BYTES / (1024 * 1024)
                        )
                    } else {
                        let tail: String = stderr.chars().rev().take(2000).collect::<Vec<_>>().into_iter().rev().collect();
                        format!(
                            "run_program: child exited {} without a report: {}",
                            exit_code.map(|c| c.to_string()).unwrap_or_else(|| "(killed)".to_string()),
                            tail.trim()
                        )
                    };
                    r.insert("ok", syn_bool(false));
                    r.insert("output", syn_list(Vec::new()));
                    r.insert("errors", syn_list(vec![syn_text(msg)]));
                    r.insert("audit", syn_list(Vec::new()));
                    r.insert(
                        "exit",
                        match exit_code {
                            Some(c) if !timed_out => syn_int(c as i64),
                            _ => SynValue::Nothing,
                        },
                    );
                    r.insert("timed_out", syn_bool(timed_out));
                    r.insert("llm_tokens", syn_int(0));
                    r.insert("steps", syn_int(0));
                    r.insert("diagnostic", SynValue::Nothing);
                }
            }
            r.insert("output_truncated", syn_bool(output_truncated));
            r.insert("audit_truncated", syn_bool(audit_truncated));
            r.insert("stderr", stderr_lines);
            r.insert("stderr_truncated", syn_bool(stderr_truncated));
            Ok(syn_map(r))
        }),
    );
}

/// v0.6.54 (N4) — qué listas del informe se recortaron.
#[derive(Default, Debug, PartialEq)]
struct ReportCut {
    output: bool,
    errors: bool,
    audit: bool,
}

/// v0.6.54 (N4) — un informe con `errors` recortados no está completo: no puede decir `ok`, y un
/// error más dice qué se descartó. Recortar `output` o `audit` no cambia `ok` (R2-3 de la ronda 2:
/// el audit crece con cada chequeo de permiso, algo que el programa no elige; su recorte lo dice
/// `audit_truncated`).
fn mark_cut(ok: bool, mut errors: serde_json::Value, cut: &ReportCut) -> (bool, serde_json::Value) {
    if !cut.errors {
        return (ok, errors);
    }
    if let serde_json::Value::Array(es) = &mut errors {
        es.push(serde_json::Value::String(format!(
            "run_program: the child's report had more than {} errors; the rest was dropped",
            MAX_CHILD_OUTPUT_LINES
        )));
    }
    (false, errors)
}

/// v0.6.54 (N4 de la ronda 1) — lee el informe del hijo sin armar más de
/// [`MAX_CHILD_OUTPUT_LINES`] elementos de `output`, `errors` y `audit`: los que pasan se saltean
/// sin guardarlos (cada uno sería un valor en el padre). `None` si no es un objeto JSON.
fn parse_child_report(s: &str) -> Option<(serde_json::Value, ReportCut)> {
    parse_report_capped(s, MAX_CHILD_OUTPUT_LINES)
}

fn parse_report_capped(s: &str, cap: usize) -> Option<(serde_json::Value, ReportCut)> {
    use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

    struct Capped(usize);
    impl<'de> DeserializeSeed<'de> for Capped {
        type Value = (Vec<serde_json::Value>, bool);
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for Capped {
        type Value = (Vec<serde_json::Value>, bool);
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while out.len() < self.0 {
                match a.next_element::<serde_json::Value>()? {
                    Some(v) => out.push(v),
                    None => return Ok((out, false)),
                }
            }
            let mut cut = false;
            while a.next_element::<IgnoredAny>()?.is_some() {
                cut = true;
            }
            Ok((out, cut))
        }
    }
    struct Report(usize);
    impl<'de> Visitor<'de> for Report {
        type Value = (serde_json::Map<String, serde_json::Value>, ReportCut);
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the child's report")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut m = serde_json::Map::new();
            let mut cut = ReportCut::default();
            while let Some(k) = a.next_key::<String>()? {
                let flag = match k.as_str() {
                    "output" => Some(&mut cut.output),
                    "errors" => Some(&mut cut.errors),
                    "audit" => Some(&mut cut.audit),
                    _ => None,
                };
                let v = match flag {
                    Some(flag) => {
                        let (v, c) = a.next_value_seed(Capped(self.0))?;
                        *flag |= c;
                        serde_json::Value::Array(v)
                    }
                    None => a.next_value::<serde_json::Value>()?,
                };
                m.insert(k, v);
            }
            Ok((m, cut))
        }
    }
    let mut de = serde_json::Deserializer::from_str(s);
    let (m, cut) = de.deserialize_map(Report(cap)).ok()?;
    de.end().ok()?;
    Some((serde_json::Value::Object(m), cut))
}

#[cfg(test)]
mod v0654_report_cap {
    use super::{mark_cut, parse_report_capped, ReportCut};

    #[test]
    fn a_cut_report_is_not_ok() {
        let none = ReportCut::default();
        assert_eq!(mark_cut(true, serde_json::json!([]), &none), (true, serde_json::json!([])));
        let out = ReportCut { output: true, ..Default::default() };
        assert_eq!(mark_cut(true, serde_json::json!([]), &out), (true, serde_json::json!([])));
        // R2-3 de la ronda 2: un audit recortado no cambia `ok` ni suma errores.
        let audit = ReportCut { audit: true, ..Default::default() };
        assert_eq!(mark_cut(true, serde_json::json!(["e1"]), &audit), (true, serde_json::json!(["e1"])));
        let (ok, errors) = mark_cut(true, serde_json::json!(["e1"]), &ReportCut { errors: true, ..Default::default() });
        assert!(!ok);
        assert_eq!(errors[0], "e1");
        let m = errors[1].as_str().unwrap();
        assert!(m.contains("more than 100000 errors") && m.contains("dropped"), "{}", m);
    }

    #[test]
    fn the_report_keeps_at_most_cap_lines() {
        let (v, cut) = parse_report_capped(r#"{"ok":true,"output":["a","b","c"],"errors":[],"audit":[1,2]}"#, 2).unwrap();
        assert_eq!(v["output"], serde_json::json!(["a", "b"]));
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(cut, ReportCut { output: true, errors: false, audit: false });
        let (_, cut) = parse_report_capped(r#"{"output":["a","b"],"errors":["x","y","z"],"audit":[1,2,3]}"#, 2).unwrap();
        assert_eq!(cut, ReportCut { output: false, errors: true, audit: true });
        // Justo en el tope: entero, sin recorte.
        let (v, cut) = parse_report_capped(r#"{"output":["a","b"],"diagnostic":{"line":3}}"#, 2).unwrap();
        assert_eq!(v["output"], serde_json::json!(["a", "b"]));
        assert_eq!(v["diagnostic"]["line"], serde_json::json!(3));
        assert_eq!(cut, ReportCut::default());
        // Lo que no es un objeto JSON no es un informe.
        for bad in ["", "[1]", "{\"ok\":true} basura", "{\"output\":3}"] {
            assert!(parse_report_capped(bad, 2).is_none(), "{}", bad);
        }
    }
}
