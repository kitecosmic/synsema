//! Daemon — corre agentes/servers como procesos background. Port de
//! `syntecnia/runtime/daemon.py`.
//!
//! ```text
//! syntecnia daemon start program.syn    arranca en background
//! syntecnia daemon stop   program.syn   detiene
//! syntecnia daemon status               lista todos
//! syntecnia daemon logs   program.syn   muestra logs
//! syntecnia daemon restart program.syn  reinicia
//! ```
//!
//! Se desacopla de la terminal (DETACHED_PROCESS en Windows, setsid en Unix),
//! escribe un PID file y redirige salida a un log. Archivos:
//! `~/.syntecnia/daemons/<name>/{pid,log,meta}`

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn home() -> PathBuf {
    let h = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    PathBuf::from(h)
}

fn daemon_dir() -> PathBuf {
    let d = home().join(".syntecnia").join("daemons");
    let _ = fs::create_dir_all(&d);
    d
}

/// Nombre del daemon = stem del path del programa.
pub fn daemon_name(program_path: &str) -> String {
    Path::new(program_path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program_path.to_string())
}

fn state_dir(name: &str) -> PathBuf {
    let d = daemon_dir().join(name);
    let _ = fs::create_dir_all(&d);
    d
}

fn read_pid(name: &str) -> Option<u32> {
    let pid_file = state_dir(name).join("pid");
    fs::read_to_string(pid_file).ok().and_then(|s| s.trim().parse().ok())
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// ¿El proceso `pid` está vivo? (tasklist en Windows, kill(0) en Unix.)
#[cfg(windows)]
fn is_running(pid: u32) -> bool {
    let out = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid)])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn is_running(pid: u32) -> bool {
    // En Unix, kill -0 chequea existencia.
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Resultado de una operación de daemon (mensaje listo para imprimir).
pub struct DaemonResult {
    pub status: String,
    pub name: String,
    pub pid: Option<u32>,
    pub message: String,
}

/// Lanza el comando detachado del terminal con stdout/stderr → `log`.
fn spawn_detached(program_path: &str, extra: &[String], log_file: fs::File) -> std::io::Result<u32> {
    let exe = std::env::current_exe()?;
    let log_err = log_file.try_clone()?;
    let mut cmd = Command::new(exe);
    // `serve` bindea cualquier `serve on PORT` y bloquea hasta kill (mantiene vivo el
    // daemon). El oráculo usa `run --serve`; acá `serve` es el equivalente que sí
    // levanta el server bajo el modelo std::net del port.
    cmd.arg("serve");
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg(program_path);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_err));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x8) | CREATE_NEW_PROCESS_GROUP (0x200)
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Nueva sesión: cerrar la terminal no mata el daemon.
        cmd.process_group(0);
    }

    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Quita el prefijo extended-length de Windows (`\\?\`) que deja `canonicalize`.
fn clean_path(p: String) -> String {
    p.strip_prefix(r"\\?\").map(|s| s.to_string()).unwrap_or(p)
}

pub fn daemon_start(program_path: &str, extra: &[String]) -> DaemonResult {
    let abs = std::fs::canonicalize(program_path)
        .map(|p| clean_path(p.to_string_lossy().into_owned()))
        .unwrap_or_else(|_| program_path.to_string());
    if !Path::new(&abs).exists() {
        return DaemonResult {
            status: "error".into(),
            name: String::new(),
            pid: None,
            message: format!("File not found: {}", abs),
        };
    }
    let name = daemon_name(&abs);
    let sdir = state_dir(&name);

    if let Some(existing) = read_pid(&name) {
        if is_running(existing) {
            return DaemonResult {
                status: "already_running".into(),
                name: name.clone(),
                pid: Some(existing),
                message: format!("Daemon '{}' is already running (PID {})", name, existing),
            };
        }
    }

    let log_path = sdir.join("log");
    let mut log_file = match fs::OpenOptions::new().create(true).append(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            return DaemonResult {
                status: "error".into(),
                name,
                pid: None,
                message: format!("could not open log: {}", e),
            }
        }
    };
    use std::io::Write;
    let _ = writeln!(log_file, "\n--- Daemon started ---");
    let _ = log_file.flush();

    match spawn_detached(&abs, extra, log_file) {
        Ok(pid) => {
            let _ = fs::write(sdir.join("pid"), pid.to_string());
            let meta = serde_json::json!({
                "program": abs,
                "name": name,
                "pid": pid,
                "started_at": now_secs(),
                "args": extra,
            });
            let _ = fs::write(sdir.join("meta"), serde_json::to_string_pretty(&meta).unwrap_or_default());
            DaemonResult {
                status: "started".into(),
                name: name.clone(),
                pid: Some(pid),
                message: format!("Daemon '{}' started (PID {}). Logs: {}", name, pid, log_path.display()),
            }
        }
        Err(e) => DaemonResult {
            status: "error".into(),
            name,
            pid: None,
            message: format!("could not start daemon: {}", e),
        },
    }
}

fn resolve_name(name_or_path: &str) -> String {
    if name_or_path.contains('/') || name_or_path.contains('\\') || name_or_path.contains('.') {
        daemon_name(name_or_path)
    } else {
        name_or_path.to_string()
    }
}

pub fn daemon_stop(name_or_path: &str) -> DaemonResult {
    let name = resolve_name(name_or_path);
    let pid = match read_pid(&name) {
        Some(p) => p,
        None => {
            return DaemonResult {
                status: "not_found".into(),
                name: name.clone(),
                pid: None,
                message: format!("No daemon '{}' found", name),
            }
        }
    };
    if !is_running(pid) {
        let _ = fs::remove_file(state_dir(&name).join("pid"));
        return DaemonResult {
            status: "not_running".into(),
            name: name.clone(),
            pid: Some(pid),
            message: format!("Daemon '{}' is not running (stale PID {})", name, pid),
        };
    }

    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }

    let _ = fs::remove_file(state_dir(&name).join("pid"));
    DaemonResult {
        status: "stopped".into(),
        name: name.clone(),
        pid: Some(pid),
        message: format!("Daemon '{}' stopped", name),
    }
}

pub struct DaemonInfo {
    pub name: String,
    pub pid: Option<u32>,
    pub running: bool,
    pub program: String,
    pub started_at: String,
}

pub fn daemon_status() -> Vec<DaemonInfo> {
    let mut out = Vec::new();
    let dir = daemon_dir();
    let mut entries: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect(),
        Err(_) => return out,
    };
    entries.sort();
    for sdir in entries {
        let name = sdir.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let pid = read_pid(&name);
        let running = pid.map(is_running).unwrap_or(false);
        let (mut program, mut started_at) = (String::new(), String::new());
        if let Ok(meta_txt) = fs::read_to_string(sdir.join("meta")) {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_txt) {
                program = meta.get("program").and_then(|v| v.as_str()).unwrap_or("").to_string();
                started_at = meta.get("started_at").map(|v| v.to_string()).unwrap_or_default();
            }
        }
        out.push(DaemonInfo { name, pid, running, program, started_at });
    }
    out
}

pub fn daemon_logs(name_or_path: &str, lines: usize) -> String {
    let name = resolve_name(name_or_path);
    let log_path = state_dir(&name).join("log");
    match fs::read_to_string(&log_path) {
        Ok(content) => {
            let all: Vec<&str> = content.split('\n').collect();
            let start = all.len().saturating_sub(lines);
            all[start..].join("\n")
        }
        Err(_) => format!("No logs for daemon '{}'", name),
    }
}

pub fn daemon_restart(name_or_path: &str, extra: &[String]) -> DaemonResult {
    let name = resolve_name(name_or_path);
    // Recupera el path del programa desde meta.
    let mut program_path = name_or_path.to_string();
    let mut args = extra.to_vec();
    if let Ok(meta_txt) = fs::read_to_string(state_dir(&name).join("meta")) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_txt) {
            if let Some(p) = meta.get("program").and_then(|v| v.as_str()) {
                program_path = p.to_string();
            }
            if args.is_empty() {
                if let Some(a) = meta.get("args").and_then(|v| v.as_array()) {
                    args = a.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
            }
        }
    }
    let _ = daemon_stop(&name);
    std::thread::sleep(std::time::Duration::from_millis(500));
    daemon_start(&program_path, &args)
}

pub fn format_status_table(statuses: &[DaemonInfo]) -> String {
    if statuses.is_empty() {
        return "No daemons found.".to_string();
    }
    let mut lines = vec!["Syntecnia Daemons:".to_string()];
    for s in statuses {
        let state = if s.running { "RUNNING" } else { "STOPPED" };
        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        lines.push(format!(
            "  [{:7}] {:20} PID={:8} {}  {}",
            state, s.name, pid, s.started_at, s.program
        ));
    }
    lines.join("\n")
}
