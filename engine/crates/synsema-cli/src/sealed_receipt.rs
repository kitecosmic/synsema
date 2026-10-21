//! v0.6.46 (E6) — el recibo sellado en el CLI: `run --auditor <pública>` (o `SYNSEMA_AUDITOR_KEY`),
//! `--receipt <ruta|fd:N>`, y `synsema receipt open|verify|keygen`.
//!
//! El recibo sale ANTES que la salida del programa: con auditor, la salida se junta (no va en vivo)
//! y se imprime después de entregar el recibo. Por defecto el recibo va a stderr, una línea JSON: el
//! stdout del programa queda igual para los pipes, como con `--audit`.

use std::io::Write;
use std::process::ExitCode;

use synsema_core::sealed::SharedLog;
use synsema_stdlib::sealed::{self as sealed, RunKey};

/// Los knobs del recibo sellado (el anti-rot los cruza con el `.env.example` de `init`).
#[cfg(test)]
pub const RECEIPT_ENV_VARS: &[&str] = &["SYNSEMA_AUDITOR_KEY", "SYNSEMA_RECEIPT_SEALED_BYTES"];

/// La precedencia de siempre: el environ del proceso, después el `.env`.
fn knob(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => synsema_stdlib::secrets::EnvStore::load_default().get(name).filter(|v| !v.trim().is_empty()),
    }
}

/// Una corrida con auditor.
pub struct Auditor {
    key: [u8; 32],
    dest: Option<String>,
    log: SharedLog,
    started: String,
    run_key: RunKey,
}

/// `--auditor`/`--receipt` del subcomando (o los knobs). `Ok(None)` sin auditor: todo queda como
/// antes. Un `--receipt` sin auditor es un error (no hay recibo que escribir).
pub fn from_flags(cmd: &str, flag: Option<String>, dest: Option<String>) -> Result<Option<Auditor>, ExitCode> {
    let fail = |msg: String| -> ExitCode {
        eprintln!("synsema {}: {}", cmd, msg);
        ExitCode::from(2)
    };
    let Some(raw) = flag.or_else(|| knob("SYNSEMA_AUDITOR_KEY")) else {
        if dest.is_some() {
            return Err(fail("--receipt needs an auditor: pass --auditor <X25519 public key> or set SYNSEMA_AUDITOR_KEY".to_string()));
        }
        return Ok(None);
    };
    let key = sealed::parse_auditor_key(&raw).map_err(|e| fail(format!("--auditor: {}", e)))?;
    let size = sealed::sealed_bytes_from(knob("SYNSEMA_RECEIPT_SEALED_BYTES").as_deref()).map_err(fail)?;
    // La clave que firma: la de identidad del host si la hay (Ed25519, la de la Agent Card); si no,
    // una efímera de la corrida (integridad, no identidad: el header lo dice).
    let run_key = match knob("SYNSEMA_IDENTITY_KEY") {
        Some(raw) => match synsema_core::bytesutil::hex_decode(raw.trim().trim_start_matches("0x")) {
            Ok(b) if b.len() == 32 => RunKey::from_identity_seed(&b.try_into().expect("32")),
            _ => return Err(fail("SYNSEMA_IDENTITY_KEY must be the ed25519 seed as 64 hex chars".to_string())),
        },
        None => RunKey::ephemeral(),
    };
    Ok(Some(Auditor {
        key,
        dest,
        log: sealed::new_run_log(size),
        started: rfc3339_now(),
        run_key,
    }))
}

/// v0.6.46 (E6-h): `serve --auditor`/`--receipt` (o los knobs) → la pública del auditor y el tamaño
/// del sobre. La clave que firma la elige el runtime (la atestada, la de identidad o una efímera).
pub fn serve_from_flags(flag: Option<String>, dest: &Option<String>) -> Result<Option<([u8; 32], usize)>, ExitCode> {
    let fail = |msg: String| -> ExitCode {
        eprintln!("synsema serve: {}", msg);
        ExitCode::from(2)
    };
    let Some(raw) = flag.or_else(|| knob("SYNSEMA_AUDITOR_KEY")) else {
        if dest.is_some() {
            return Err(fail("--receipt needs an auditor: pass --auditor <X25519 public key> or set SYNSEMA_AUDITOR_KEY".to_string()));
        }
        return Ok(None);
    };
    let key = sealed::parse_auditor_key(&raw).map_err(|e| fail(format!("--auditor: {}", e)))?;
    let size = sealed::sealed_bytes_from(knob("SYNSEMA_RECEIPT_SEALED_BYTES").as_deref()).map_err(fail)?;
    // Que cada entrada diga en qué línea nació (como con `--audit`).
    synsema_core::audit_loc::enable();
    Ok(Some((key, size)))
}

fn rfc3339_now() -> String {
    synsema_stdlib::receipt::rfc3339_utc(synsema_core::clock::now_secs())
}

impl Auditor {
    /// Instala el registro de la corrida (uno por proceso: el CLI corre un programa).
    pub fn install(&self) {
        synsema_core::sealed::install_process(Some(self.log.clone()));
        // Que cada entrada diga en qué línea nació (como con `--audit`).
        synsema_core::audit_loc::enable();
    }

    /// La pública de la clave que firma (va al `report_data` de `run --attest`).
    pub fn run_public(&self) -> [u8; 32] {
        // En el CLI la clave es Ed25519 siempre (efímera o `SYNSEMA_IDENTITY_KEY`).
        self.run_key.public_bytes().try_into().expect("the CLI's run key is Ed25519")
    }

    /// El recibo de la corrida que terminó.
    pub fn receipt(&self, config_sha: Option<String>) -> Result<serde_json::Value, String> {
        let program_sha = synsema_stdlib::attest::current_program_sha().map(|s| synsema_core::bytesutil::hex_encode(&s));
        let log = self.log.lock().unwrap_or_else(|p| p.into_inner());
        sealed::build_receipt(
            &log,
            &sealed::ReceiptContext { auditor: self.key, key: &self.run_key, program_sha, config_sha, started: self.started.clone() },
        )
    }

    /// Escribe el recibo en su destino (`--receipt <ruta>`, `fd:N`, o stderr).
    pub fn emit(&self, receipt: &serde_json::Value) -> Result<(), String> {
        let line = format!("{}\n", receipt);
        match self.dest.as_deref() {
            None => {
                let mut e = std::io::stderr().lock();
                e.write_all(line.as_bytes()).and_then(|_| e.flush()).map_err(|e| e.to_string())
            }
            Some(fd) if fd.starts_with("fd:") => {
                let n: i32 = fd[3..].parse().map_err(|_| format!("--receipt: invalid fd '{}'", fd))?;
                #[cfg(unix)]
                {
                    use std::os::unix::io::FromRawFd;
                    if n < 3 {
                        return Err("--receipt fd:N needs N >= 3 (0-2 are stdin/stdout/stderr)".to_string());
                    }
                    // SAFETY: `n` es un descriptor que abrió el proceso padre para esto (N >= 3); el
                    // `File` va en `ManuallyDrop`, así que no se cierra ni se toma como propio.
                    let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(n) });
                    f.write_all(line.as_bytes()).and_then(|_| f.flush()).map_err(|e| e.to_string())
                }
                #[cfg(not(unix))]
                {
                    let _ = n;
                    Err("--receipt fd:N is only available on Unix; use --receipt <path>".to_string())
                }
            }
            Some(path) => std::fs::write(path, line.as_bytes()).map_err(|e| format!("--receipt: cannot write {}: {}", path, e)),
        }
    }
}

/// `synsema receipt open <recibo> --key <privada>` / `verify <recibo>` / `keygen`.
pub fn cmd_receipt(args: &[String]) -> ExitCode {
    const USAGE: &str = "usage: synsema receipt open <receipt.json> --key <auditor private key | @file>\n       synsema receipt verify <receipt.json>\n       synsema receipt keygen";
    let sub = args.get(2).map(String::as_str);
    match sub {
        Some("keygen") => {
            let (sk, pk) = sealed::generate_keypair();
            println!("{}", serde_json::json!({"private": sk, "public": pk}));
            ExitCode::SUCCESS
        }
        Some(op @ ("open" | "verify")) => {
            let mut path: Option<&str> = None;
            let mut key: Option<String> = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--key" => {
                        key = args.get(i + 1).cloned();
                        i += 1;
                    }
                    p if !p.starts_with("--") && path.is_none() => path = Some(p),
                    other => {
                        eprintln!("synsema receipt: unknown argument '{}'\n{}", other, USAGE);
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            let Some(path) = path else {
                eprintln!("{}", USAGE);
                return ExitCode::from(2);
            };
            let text = match if path == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map(|_| s)
            } else {
                std::fs::read_to_string(path)
            } {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("synsema receipt: cannot read {}: {}", path, e);
                    return ExitCode::from(1);
                }
            };
            // La línea del recibo: la última línea JSON que sea un recibo (stderr puede traer más).
            let receipt = text
                .lines()
                .rev()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
                .find(|v| v.get("synsema_receipt").is_some())
                .or_else(|| serde_json::from_str(&text).ok());
            let Some(receipt) = receipt else {
                eprintln!("synsema receipt: {} has no sealed receipt", path);
                return ExitCode::from(1);
            };
            let out = if op == "verify" {
                sealed::verify_receipt(&receipt).map(|h| serde_json::json!({"ok": true, "header": h}))
            } else {
                let Some(k) = key else {
                    eprintln!("synsema receipt open: --key <auditor private key> is required");
                    return ExitCode::from(2);
                };
                let k = match k.strip_prefix('@') {
                    Some(file) => match std::fs::read_to_string(file) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("synsema receipt open: cannot read {}: {}", file, e);
                            return ExitCode::from(1);
                        }
                    },
                    None => k,
                };
                synsema_core::bytesutil::b64url_decode(k.trim())
                    .map_err(|e| format!("--key is not base64url: {}", e))
                    .and_then(|sk| sealed::open_receipt(&receipt, &sk))
            };
            match out {
                Ok(v) => {
                    println!("{}", v);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("synsema receipt {}: {}", op, e);
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("{}", USAGE);
            ExitCode::from(2)
        }
    }
}

/// `run --replay <recibo abierto>` (la salida de `synsema receipt open`): fija la semilla de
/// `random()`/`random_int()` y las lecturas de `now()` de la corrida grabada, y compara cada entrada
/// que lee el programa con la `sha256` grabada; en la primera que difiere, la corrida corta y dice
/// cuál. Las entradas se vuelven a leer de verdad (el recibo guarda hashes, no datos): lo que el
/// replay prueba es que leyó lo mismo e hizo lo mismo. No regenera claves ni tokens (salen de la
/// entropía del SO, a propósito).
pub fn install_replay(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("--replay: cannot read {}: {}", path, e))?;
    let opened: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("--replay: {} is not JSON: {}", path, e))?;
    if opened.get("entries").is_none() || opened.get("header").is_none() {
        return Err(format!("--replay: {} is not an opened receipt (run `synsema receipt open <receipt> --key <private>` first)", path));
    }
    let seed = opened.get("seed").and_then(|v| v.as_str()).ok_or("--replay: the opened receipt has no seed")?;
    let clock: Vec<f64> = opened.get("clock").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_f64()).collect()).unwrap_or_default();
    let inputs: Vec<(String, String)> = opened["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.get("entry")?;
            (e.get("kind")?.as_str()? == "input").then(|| Some((e.get("source")?.as_str()?.to_string(), e.get("sha256")?.as_str()?.to_string())))?
        })
        .collect();
    let truncated = opened.get("truncated").and_then(|v| v.as_u64()).unwrap_or(0);
    if truncated > 0 || opened.get("clock_truncated").is_some() {
        eprintln!("synsema run --replay: warning: the recorded run truncated {} sealed entries; the comparison covers what the envelope kept", truncated);
    }
    let size = opened.pointer("/header/sealed_bytes").and_then(|v| v.as_u64()).unwrap_or(sealed::DEFAULT_SEALED_BYTES as u64) as usize;
    let mut log = synsema_core::sealed::RunLog::new(size);
    log.seed = Some(seed.to_string());
    log.replay_clock = Some((clock, 0));
    log.replay_inputs = Some((inputs, 0));
    synsema_core::sealed::install_process(Some(std::sync::Arc::new(std::sync::Mutex::new(log))));
    Ok(())
}

/// El veredicto de un `--replay` al terminar: `Ok(resumen)` si leyó exactamente lo grabado.
pub fn replay_verdict() -> Result<String, String> {
    if let Some(e) = synsema_core::sealed::replay_error() {
        return Err(e);
    }
    let (used, recorded) = synsema_core::sealed::replay_progress().unwrap_or((0, 0));
    if used < recorded {
        return Err(format!("replay: the run read {} of the {} inputs of the recorded run", used, recorded));
    }
    Ok(format!("replay: the {} inputs match the recorded run (same seed, same clock readings)", recorded))
}
