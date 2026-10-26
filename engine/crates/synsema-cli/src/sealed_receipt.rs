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
    // v0.6.49 (§C): el error nombra de dónde vino la clave (antes, `--auditor: …` también para el knob).
    let origin = if flag.is_some() { "--auditor" } else { "SYNSEMA_AUDITOR_KEY" };
    let Some(raw) = flag.or_else(|| knob("SYNSEMA_AUDITOR_KEY")) else {
        if dest.is_some() {
            return Err(fail("--receipt needs an auditor: pass --auditor <X25519 public key> or set SYNSEMA_AUDITOR_KEY".to_string()));
        }
        return Ok(None);
    };
    let key = sealed::parse_auditor_key(&raw).map_err(|e| fail(format!("{}: {}", origin, e)))?;
    let size = sealed::sealed_bytes_from(knob("SYNSEMA_RECEIPT_SEALED_BYTES").as_deref()).map_err(fail)?;
    if let Some(d) = &dest {
        check_dest(d).map_err(fail)?;
    }
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
    // v0.6.49 (§C): el error nombra de dónde vino la clave (antes, `--auditor: …` también para el knob).
    let origin = if flag.is_some() { "--auditor" } else { "SYNSEMA_AUDITOR_KEY" };
    let Some(raw) = flag.or_else(|| knob("SYNSEMA_AUDITOR_KEY")) else {
        if dest.is_some() {
            return Err(fail("--receipt needs an auditor: pass --auditor <X25519 public key> or set SYNSEMA_AUDITOR_KEY".to_string()));
        }
        return Ok(None);
    };
    let key = sealed::parse_auditor_key(&raw).map_err(|e| fail(format!("{}: {}", origin, e)))?;
    let size = sealed::sealed_bytes_from(knob("SYNSEMA_RECEIPT_SEALED_BYTES").as_deref()).map_err(fail)?;
    if let Some(d) = dest {
        check_dest(d).map_err(fail)?;
    }
    // Que cada entrada diga en qué línea nació (como con `--audit`).
    synsema_core::audit_loc::enable();
    Ok(Some((key, size)))
}

/// Ronda 1 (E6-B1) — el destino de `--receipt`, antes de correr nada: un error ahí aparecía recién
/// al final, con los efectos del programa ya hechos y sin recibo. Una ruta se abre para agregar (se
/// crea si falta, sin vaciarla: si la corrida no llega a empezar, el recibo anterior queda; `run` la
/// reemplaza al escribir el suyo); `fd:N` sólo en Unix y con N >= 3.
fn check_dest(dest: &str) -> Result<(), String> {
    if let Some(n) = dest.strip_prefix("fd:") {
        if !cfg!(unix) {
            return Err(format!("--receipt {}: a file descriptor is only available on Unix; pass a path", dest));
        }
        return match n.parse::<i32>() {
            Ok(n) if n >= 3 => Ok(()),
            Ok(_) => Err("--receipt fd:N needs N >= 3 (0-2 are stdin/stdout/stderr)".to_string()),
            Err(_) => Err(format!("--receipt: invalid fd '{}'", dest)),
        };
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dest)
        .map(|_| ())
        .map_err(|e| format!("--receipt: cannot write {}: {}", dest, e))
}

fn rfc3339_now() -> String {
    synsema_stdlib::receipt::rfc3339_utc(synsema_core::clock::now_secs())
}

/// v0.6.49 (ronda 1, M3): el sha256 de cada módulo `--trusted` de la corrida (`{nombre: sha}`), o
/// `None` si no hay. Va al encabezado del recibo, y `--replay` lo compara: una tool de confianza
/// cambiada cambia lo que el programa hace sin cambiar su `program_sha`.
fn trusted_shas() -> Option<serde_json::Value> {
    sealed::trusted_shas(&synsema_runtime::host::trusted()?.modules)
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
        let mut log = self.log.lock().unwrap_or_else(|p| p.into_inner());
        // v0.6.46 (ronda 1, E6-M2): un agente que sigue vivo ya no anota en un recibo armado.
        log.close();
        sealed::build_receipt(
            &log,
            &sealed::ReceiptContext { auditor: self.key, key: &self.run_key, program_sha, config_sha, trusted: trusted_shas(), started: self.started.clone() },
        )
    }

    /// ¿Hay un `--receipt`? (Con `--format json` el recibo va en el informe, y además al destino si
    /// lo hay.)
    pub fn has_dest(&self) -> bool {
        self.dest.is_some()
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
    const USAGE: &str = "usage: synsema receipt open <receipt.json> --key <auditor private key | @file> [--line N]\n       synsema receipt verify <receipt.json>\n       synsema receipt keygen [--out <private key file>]";
    let sub = args.get(2).map(String::as_str);
    match sub {
        Some("keygen") => {
            let (sk, pk) = sealed::generate_keypair();
            // Ronda 1 (E6-B8): con `--out`, la privada va a un archivo nuevo que sólo lee el dueño
            // (0600 en Unix) y por stdout sale sólo la pública. Sin `--out`, como antes (redirigida,
            // queda con la umask).
            match (args.get(3).map(String::as_str), args.get(4)) {
                (None, _) => {
                    println!("{}", serde_json::json!({"private": sk, "public": pk}));
                    ExitCode::SUCCESS
                }
                (Some("--out"), Some(file)) if args.len() == 5 => {
                    let mut o = std::fs::OpenOptions::new();
                    o.write(true).create_new(true);
                    #[cfg(unix)]
                    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
                    match o.open(file).and_then(|mut f| f.write_all(sk.as_bytes()).and_then(|_| f.flush())) {
                        Ok(()) => {
                            println!("{}", serde_json::json!({"public": pk, "private_in": file}));
                            eprintln!("open receipts with: synsema receipt open <receipt.json> --key @{}", file);
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("synsema receipt keygen: cannot create {} (it must not exist): {}", file, e);
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
        Some(op @ ("open" | "verify")) => {
            let mut path: Option<&str> = None;
            let mut key: Option<String> = None;
            let mut line: Option<usize> = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--key" => {
                        key = args.get(i + 1).cloned();
                        i += 1;
                    }
                    "--line" if op == "open" => {
                        match args.get(i + 1).and_then(|n| n.parse::<usize>().ok()) {
                            Some(n) if n > 0 => line = Some(n),
                            _ => {
                                eprintln!("synsema receipt open: --line takes a line number (1, 2, …)\n{}", USAGE);
                                return ExitCode::from(2);
                            }
                        }
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
            // Ronda 4: sin el BOM que agrega un editor al guardar (escondía la línea 1: no era JSON ni
            // empezaba como un recibo, y `verify` contaba uno menos y salía verde).
            let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
            // Las líneas con un recibo (stderr de `run` trae otras; el archivo de `serve --receipt`, uno
            // por request), con su número de línea; si ninguna, el texto entero (un recibo con formato).
            let mut receipts: Vec<(usize, serde_json::Value)> = Vec::new();
            // Ronda 2 (R2-B2): una línea que empieza como un recibo y no lo es (cortada, con un byte
            // cambiado en la sintaxis) falla; antes quedaba afuera y `verify` salía verde. Ronda 3
            // (R3-B1): que EMPIECE así, no que lo contenga: el stderr de `run` trae también los
            // `eprint` del programa, y un log que nombra la clave volvía roto un recibo honesto.
            let mut broken: Vec<usize> = Vec::new();
            for (n, l) in text.lines().enumerate() {
                match serde_json::from_str::<serde_json::Value>(l.trim()) {
                    Ok(v) if v.get("synsema_receipt").is_some() => receipts.push((n + 1, v)),
                    _ if l.trim_start().starts_with("{\"synsema_receipt\":") => broken.push(n + 1),
                    _ => {}
                }
            }
            if receipts.is_empty() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    receipts.push((1, v));
                    broken.clear();
                }
            }
            if receipts.is_empty() {
                // v0.6.49 (§C): un recibo cortado no es "no hay recibo".
                match broken.first() {
                    Some(n) => eprintln!(
                        "synsema receipt: line {} of {} names a sealed receipt but is not one: it is cut or changed",
                        n, path
                    ),
                    None => eprintln!("synsema receipt: {} has no sealed receipt", path),
                }
                return ExitCode::from(1);
            }
            // v0.6.46 (ronda 1, E6-M3): con varios recibos, `verify` revisa TODOS (antes sólo el
            // último: una línea alterada más arriba pasaba) y `open` pide cuál.
            if op == "verify" && receipts.len() + broken.len() > 1 {
                let mut bad: Vec<(usize, String)> = receipts
                    .iter()
                    .filter_map(|(n, r)| sealed::verify_receipt(r).err().map(|e| (*n, e)))
                    .collect();
                bad.extend(broken.iter().map(|n| (*n, "the line names a sealed receipt but is not one (cut or changed)".to_string())));
                bad.sort();
                let bad: Vec<serde_json::Value> = bad.into_iter().map(|(n, e)| serde_json::json!({"line": n, "error": e})).collect();
                println!("{}", serde_json::json!({"ok": bad.is_empty(), "receipts": receipts.len() + broken.len(), "bad": bad}));
                return if bad.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) };
            }
            let receipt = match line {
                Some(n) => match receipts.iter().find(|(l, _)| *l == n) {
                    Some((_, r)) => r.clone(),
                    None => {
                        eprintln!("synsema receipt open: line {} of {} is not a sealed receipt", n, path);
                        return ExitCode::from(1);
                    }
                },
                None if receipts.len() > 1 => {
                    let at: Vec<String> = receipts.iter().map(|(l, _)| l.to_string()).collect();
                    eprintln!(
                        "synsema receipt open: {} has {} sealed receipts (lines {}): pick one with --line N",
                        path,
                        receipts.len(),
                        at.join(", ")
                    );
                    return ExitCode::from(2);
                }
                None => receipts.remove(0).1,
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

/// v0.6.49 (A7): lo que el veredicto de un `--replay` necesita saber del recibo.
struct ReplayInfo {
    /// El programa no es el del recibo y se corrió igual (`--replay-any-program`).
    other_program: bool,
    /// El recibo cortó lecturas del reloj: las de más salen del reloj real, y eso no es una diferencia.
    clock_truncated: bool,
}

static REPLAY_INFO: std::sync::OnceLock<ReplayInfo> = std::sync::OnceLock::new();

/// `run --replay <recibo abierto>` (la salida de `synsema receipt open`): fija la semilla de
/// `random()`/`random_int()` y las lecturas de `now()` de la corrida grabada, y compara cada entrada
/// que lee el programa con la `sha256` grabada; en la primera que difiere, la corrida corta y dice
/// cuál. Las entradas se vuelven a leer de verdad (el recibo guarda hashes, no datos): lo que el
/// replay prueba es que leyó lo mismo e hizo lo mismo. No regenera claves ni tokens (salen de la
/// entropía del SO, a propósito).
///
/// v0.6.49 (A7): antes de correr compara el `program_sha` del recibo con el de `source` (el mismo
/// cálculo que el recibo). Si no coincide, o el recibo no lo tiene, es error salvo `any_program`, y
/// entonces el veredicto dice que no es una verificación.
pub fn install_replay(path: &str, source: &str, filename: &str, any_program: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("--replay: cannot read {}: {}", path, e))?;
    let opened: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("--replay: {} is not JSON: {}", path, e))?;
    if opened.get("entries").is_none() || opened.get("header").is_none() {
        return Err(format!("--replay: {} is not an opened receipt (run `synsema receipt open <receipt> --key <private>` first)", path));
    }
    let seed = opened.get("seed").and_then(|v| v.as_str()).ok_or("--replay: the opened receipt has no seed")?;
    let recorded_sha = opened.pointer("/header/program_sha").and_then(|v| v.as_str());
    let here = synsema_stdlib::attest::program_sha_of(source, filename).map(|s| synsema_core::bytesutil::hex_encode(&s));
    let other_program = match (recorded_sha, here.as_deref()) {
        (Some(r), Some(h)) if r == h => false,
        (Some(r), Some(h)) if !any_program => {
            return Err(format!(
                "--replay: the receipt is of another program (program_sha {} in the receipt, {} here); to run this program against it anyway, add --replay-any-program (the result is not a verification)",
                r, h
            ))
        }
        (None, _) if !any_program => {
            return Err("--replay: the receipt has no program_sha, so it does not say which program it recorded; to run this program against it anyway, add --replay-any-program (the result is not a verification)".to_string())
        }
        (Some(_), None) if !any_program => {
            return Err(format!(
                "--replay: the program_sha of {} cannot be computed (a `use` that does not resolve?), so it cannot be compared with the receipt's; fix that, or add --replay-any-program (the result is not a verification)",
                filename
            ))
        }
        _ => true,
    };
    // Ronda 1 (M3): los módulos `--trusted` son parte de lo que corrió; si difieren de los grabados,
    // es otro programa aunque el `program_sha` coincida.
    let recorded_trusted = opened.pointer("/header/trusted").filter(|v| !v.is_null());
    let here_trusted = trusted_shas();
    let other_program = other_program
        || if recorded_trusted == here_trusted.as_ref() {
            false
        } else if any_program {
            true
        } else {
            return Err(format!(
                "--replay: the receipt's trusted modules ({}) are not the ones given here ({}); to run against it anyway, add --replay-any-program (the result is not a verification)",
                recorded_trusted.map_or("none".to_string(), |v| v.to_string()),
                here_trusted.map_or("none".to_string(), |v| v.to_string())
            ));
        };
    // Cada lectura del reloj viene como texto (la forma más corta del f64) y `str::parse` la vuelve
    // bit a bit; un número JSON lo leía `serde_json` a veces con un bit de diferencia.
    let clock: Vec<f64> = opened
        .get("clock")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().and_then(|s| s.parse::<f64>().ok())).collect())
        .unwrap_or_default();
    let inputs: Vec<(String, String)> = opened["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.get("entry")?;
            (e.get("kind")?.as_str()? == "input").then(|| Some((e.get("source")?.as_str()?.to_string(), e.get("sha256")?.as_str()?.to_string())))?
        })
        .collect();
    // El aviso nombra lo que se cortó: antes decía "truncated 0 sealed entries" cuando sólo se había
    // cortado el reloj.
    let truncated = opened.get("truncated").and_then(|v| v.as_u64()).unwrap_or(0);
    let clock_cut = opened.get("clock_truncated").and_then(|v| v.as_u64()).unwrap_or(0);
    if truncated > 0 {
        eprintln!("synsema run --replay: warning: the recorded run truncated {} sealed entries; the comparison covers what the envelope kept", truncated);
    }
    if clock_cut > 0 {
        eprintln!(
            "synsema run --replay: warning: the recorded run kept {} clock readings and truncated {}; readings past those come from the real clock",
            clock.len(),
            clock_cut
        );
    }
    if other_program {
        eprintln!("synsema run --replay: warning: this is not the program of the receipt (--replay-any-program); the result is not a verification");
    }
    let _ = REPLAY_INFO.set(ReplayInfo { other_program, clock_truncated: clock_cut > 0 });
    let size = opened.pointer("/header/sealed_bytes").and_then(|v| v.as_u64()).unwrap_or(sealed::DEFAULT_SEALED_BYTES as u64) as usize;
    let mut log = synsema_core::sealed::RunLog::new(size);
    log.seed = Some(seed.to_string());
    log.replay_clock = Some((clock, 0));
    log.replay_inputs = Some((inputs, 0));
    synsema_core::sealed::install_process(Some(std::sync::Arc::new(std::sync::Mutex::new(log))));
    Ok(())
}

/// El veredicto de un `--replay` al terminar: `Ok(resumen)` si leyó exactamente lo grabado.
///
/// v0.6.49 (A7): no dice "match" si la corrida terminó con error (`run_failed`: no se comparó hasta
/// el final), ni "same clock readings" si leyó el reloj otra cantidad de veces que la grabada (salvo
/// que el recibo las haya cortado), y con `--replay-any-program` dice que no es una verificación.
///
/// Ronda 1 (B3): `exit_code` es el de un `exit(n)` del programa. Es un fin pedido, no un error: se
/// compara hasta el final como una corrida terminada, y el veredicto dice `ended with exit(n)`.
pub fn replay_verdict(run_failed: bool, exit_code: Option<i32>) -> Result<String, String> {
    if let Some(e) = synsema_core::sealed::replay_error() {
        return Err(e);
    }
    let info = REPLAY_INFO.get();
    let ended = exit_code.map(|c| format!(", ended with exit({})", c)).unwrap_or_default();
    let other = format!("{}{}", ended, if info.is_some_and(|i| i.other_program) { " (another program: not a verification)" } else { "" });
    let (used, recorded) = synsema_core::sealed::replay_progress().unwrap_or((0, 0));
    if run_failed && exit_code.is_none() {
        return Err(format!(
            "replay: the run stopped with an error, so it was not compared to the end; the {} inputs it read match the first {} of the recorded run's {}{}",
            used, used, recorded, other
        ));
    }
    if used < recorded {
        return Err(format!("replay: the run read {} of the {} inputs of the recorded run{}", used, recorded, other));
    }
    let (clock_used, clock_recorded) = synsema_core::sealed::replay_clock_progress().unwrap_or((0, 0));
    let clock = if info.is_some_and(|i| i.clock_truncated) && clock_used >= clock_recorded {
        format!(
            "the {} recorded clock readings and {} from the real clock past the receipt's truncation",
            clock_recorded,
            clock_used - clock_recorded
        )
    } else if clock_used != clock_recorded {
        return Err(format!("replay: the run read the clock {} times, the recorded run {}{}", clock_used, clock_recorded, other));
    } else {
        format!("the same {} clock reading{}", clock_recorded, if clock_recorded == 1 { "" } else { "s" })
    };
    Ok(format!("replay: the {} inputs match the recorded run (same seed, {}){}", recorded, clock, other))
}
