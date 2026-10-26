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
use std::io::{Read, Write};
use std::rc::Rc;
use std::time::{Duration, Instant};

use synsema_capabilities::model::{
    build_ceiling, Capability, CapabilityAuditEntry, CapabilitySet, CapabilityType,
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
pub const DEFAULT_MAX_DEPTH: u32 = 4;
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
                let is_path = matches!(
                    cap.ty,
                    CapabilityType::File | CapabilityType::FileRead | CapabilityType::FileWrite | CapabilityType::Db
                );
                if let (true, Some(s)) = (is_path, cap.scope.as_ref()) {
                    if !(cap.ty == CapabilityType::Db && (synsema_capabilities::model::is_db_url(s) || s == ":memory:")) {
                        cap.scope = Some(synsema_core::capscope::absolute_scope(s));
                    }
                }
            }
            // Ronda 2 (A5): el techo viaja como `--cap-set` separado por comas. Un scope con una
            // coma (`{"file.read": "data/x,exec,file.read=y"}`, o un cwd con coma al volverlo
            // absoluto) se partía en items y le daba al hijo `exec` sin scope. No viaja.
            // Ronda 3 (B4): un scope vacío o con espacios en los bordes tampoco viaja (`build_ceiling`
            // lo recorta y un `Some("")` se volvía una capability sin scope: total en el hijo).
            if let Some(bad) = kept.iter().find(|c| c.scope.as_deref().is_some_and(|s| s.trim().is_empty() || s.trim() != s)) {
                return Err(rt(format!(
                    "run_program: ceiling: the scope of {} is empty or has spaces at its ends, which cannot travel to the child",
                    bad
                )));
            }
            if let Some(bad) = kept.iter().find(|c| c.scope.as_deref().is_some_and(|s| s.contains(','))) {
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
            let subject = crate::subject::Subject::capture(i, &caps);
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

            // 6) El hijo: el mismo binario, en modo motor, fuente por stdin, informe JSON.
            let exe = std::env::current_exe().map_err(|e| rt(format!("run_program: cannot resolve the engine binary: {}", e)))?;
            let mut c = std::process::Command::new(&exe);
            c.arg("--engine")
                .arg("run")
                .arg("-")
                .arg("--format")
                .arg("json")
                .arg("--profile")
                .arg(child_profile.name())
                .arg("--cap-set")
                .arg(&cap_set)
                .arg("--filename")
                .arg(&filename)
                .env_clear();
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
            // Ronda 5 (B1): padre e hijo comparten la base; lo que el hijo escribió se trae al volver.
            // Un hijo `pure` no toca el disco: no hay nada que recargar (ronda 6, N1).
            let shares_memory =
                child_profile == Profile::Native && kept.iter().any(|c| c.ty == CapabilityType::Memory);
            let _reload = ReloadOnDrop(if shares_memory { child.clone() } else { None });
            for k in ["TMP", "TEMP", "TMPDIR"] {
                if let Ok(v) = std::env::var(k) {
                    c.env(k, v);
                }
            }
            c.env(DEPTH_VAR, (depth + 1).to_string())
                .env(RUN_SUBJECT_VAR, subject.to_env_json())
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
            let out_h = std::thread::spawn(move || read_all(out));
            let err_h = std::thread::spawn(move || read_all(err));

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
            let stdout = out_h.join().unwrap_or_default();
            let stderr = err_h.join().unwrap_or_default();
            let exit_code = status.and_then(|s| s.code());

            // 7) El informe del hijo → valor.
            let mut r: SynMap = SynMap::new();
            let parsed: Option<serde_json::Value> = if timed_out {
                None
            } else {
                serde_json::from_str::<serde_json::Value>(stdout.trim()).ok().filter(|v| v.is_object())
            };
            match parsed {
                Some(v) => {
                    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    r.insert("ok", syn_bool(ok));
                    r.insert("output", json_to_syn(v.get("output").unwrap_or(&serde_json::Value::Array(vec![]))));
                    r.insert("errors", json_to_syn(v.get("errors").unwrap_or(&serde_json::Value::Array(vec![]))));
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
                }
                None => {
                    let msg = if timed_out {
                        format!("run_program: timed out after {}s", timeout_secs)
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
                }
            }
            Ok(syn_map(r))
        }),
    );
}

fn read_all<R: Read>(r: Option<R>) -> String {
    let mut buf = Vec::new();
    if let Some(mut r) = r {
        let _ = r.read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}
