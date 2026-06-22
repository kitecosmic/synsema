//! Builtins seguros (gateados por capability). Port de `capabilities/enforcer.py`
//! (SecureOperations) + `capabilities/builtins.py` (register_secure_builtins).
//!
//! Reemplazan I/O cruda por operaciones chequeadas. La violación produce un
//! `Runtime error: Capability not granted: <cap>` (sin ubicación — la
//! CapabilityViolation no la lleva; el prefijo de categoría lo agrega el motor).
//!
//! Capa 5: read_file/write_file hacen la op real de filesystem; fetch sólo chequea
//! la capability (el HTTP real es capa 6).

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};
use indexmap::IndexMap;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bool, syn_float, syn_int, syn_map, syn_text, SynValue};

use crate::model::{Capability, CapabilityType, CapabilitySet};

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

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i)
        .ok_or_else(|| Control::Error(RuntimeError::new("missing argument")))
}

/// Chequea una capability; convierte la violación en `Control::Error` SIN ubicación.
fn require(caps: &Rc<RefCell<CapabilitySet>>, cap: Capability, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&cap, source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// Hostname de un URL, como `urlparse().hostname` de Python: minúsculas, sin
/// userinfo ni puerto. `None` si no hay esquema `scheme://`.
pub fn url_hostname(url: &str) -> Option<String> {
    let after = url.find("://").map(|i| &url[i + 3..])?;
    let end = after
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(after.len());
    let netloc = &after[..end];
    let host_port = match netloc.rfind('@') {
        Some(i) => &netloc[i + 1..],
        None => netloc,
    };
    let host = match host_port.rfind(':') {
        Some(i) => &host_port[..i],
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
        let naive = NaiveDateTime::parse_from_str(s, p)
            .map_err(|e| Control::Error(RuntimeError::new(format!("invalid time: {}", e))))?;
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

/// Registra los builtins seguros en el intérprete, compartiendo el `CapabilitySet`.
pub fn register_secure_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // read_file(path) → text. Requiere file_read("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "read_file",
            1,
            Rc::new(move |_i, args, _loc| {
                let path = raw_str(arg(args, 0)?);
                require(
                    &caps,
                    Capability::new(CapabilityType::FileRead, Some(path.clone())),
                    "read_file()",
                )?;
                match std::fs::read_to_string(&path) {
                    Ok(c) => Ok(syn_text(c)),
                    Err(_) => Err(Control::Error(RuntimeError::new(format!(
                        "File not found: {}",
                        path
                    )))),
                }
            }),
        );
    }

    // write_file(path, content) → true. Requiere file_write("<path>").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "write_file",
            2,
            Rc::new(move |_i, args, _loc| {
                let path = raw_str(arg(args, 0)?);
                let content = raw_str(arg(args, 1)?);
                require(
                    &caps,
                    Capability::new(CapabilityType::FileWrite, Some(path.clone())),
                    "write_file()",
                )?;
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, content) {
                    Ok(_) => Ok(syn_bool(true)),
                    Err(e) => Err(Control::Error(RuntimeError::new(format!(
                        "Cannot write file {}: {}",
                        path, e
                    )))),
                }
            }),
        );
    }

    // fetch(url) — sólo chequeo de capability (HTTP real es capa 6).
    // Requiere net("<hostname>") (hostname del URL, no el URL completo).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "fetch",
            -1,
            Rc::new(move |_i, args, _loc| {
                let url = raw_str(arg(args, 0)?);
                let host = match url_hostname(&url) {
                    Some(h) if !h.is_empty() => h,
                    _ => url.clone(),
                };
                require(&caps, Capability::new(CapabilityType::Net, Some(host)), "fetch()")?;
                // Capability concedida: el HTTP real llega en capa 6.
                Err(Control::Error(RuntimeError::new(
                    "fetch: the HTTP runtime is not available yet (capa 6)",
                )))
            }),
        );
    }

    // -- Builtins de time (todos requieren la capability `time`; UTC) --

    // now() → timestamp unix (float).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "now",
            0,
            Rc::new(move |_i, _args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "now()")?;
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                Ok(syn_float(secs))
            }),
        );
    }

    // sleep(seconds) → pausa (cap a 1h). Requiere time (como now()).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "sleep",
            1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "sleep()")?;
                let secs = args.first().and_then(|v| arg_f64(v).ok()).unwrap_or(0.0);
                let secs = secs.clamp(0.0, 3600.0);
                std::thread::sleep(std::time::Duration::from_secs_f64(secs));
                Ok(SynValue::Nothing)
            }),
        );
    }

    // format_time(ts, pattern?) → text. Default ISO-8601 UTC ("…Z").
    {
        let caps = caps.clone();
        interp.register_builtin(
            "format_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "format_time()")?;
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let out = match opt_pattern(args) {
                    Some(p) => dt.format(&p).to_string(),
                    None => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                };
                Ok(syn_text(out))
            }),
        );
    }

    // parse_time(text, pattern?) → timestamp (float). Inverso de format_time.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "parse_time",
            -1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "parse_time()")?;
                let s = raw_str(arg(args, 0)?);
                let ts = parse_time_ts(&s, opt_pattern(args).as_deref())?;
                Ok(syn_float(ts))
            }),
        );
    }

    // date_parts(ts) → {year, month, day, hour, minute, second} (UTC).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "date_parts",
            1,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Time, None), "date_parts()")?;
                let ts = arg_f64(arg(args, 0)?)?;
                let dt = ts_to_utc(ts)?;
                let mut m = IndexMap::new();
                m.insert("year".to_string(), syn_int(dt.year() as i64));
                m.insert("month".to_string(), syn_int(dt.month() as i64));
                m.insert("day".to_string(), syn_int(dt.day() as i64));
                m.insert("hour".to_string(), syn_int(dt.hour() as i64));
                m.insert("minute".to_string(), syn_int(dt.minute() as i64));
                m.insert("second".to_string(), syn_int(dt.second() as i64));
                Ok(syn_map(m))
            }),
        );
    }

    // -- Builtins de random (requieren la capability `random`) --
    // Paridad con el oráculo: random() = float [0,1), random_int(lo,hi) = entero INCLUSIVO
    // [lo,hi]. RNG no-cripto como el `random` de Python (Mersenne Twister); los valores no
    // son byte-idénticos al oráculo (RNG distinto) — el contrato es rango+tipo+capability.

    // random() → float en [0,1).
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random",
            0,
            Rc::new(move |_i, _args, _loc| {
                require(&caps, Capability::new(CapabilityType::Random, None), "random()")?;
                Ok(syn_float(rand::random::<f64>()))
            }),
        );
    }

    // random_int(min, max) → entero inclusivo [min, max].
    {
        let caps = caps.clone();
        interp.register_builtin(
            "random_int",
            2,
            Rc::new(move |_i, args, _loc| {
                require(&caps, Capability::new(CapabilityType::Random, None), "random_int()")?;
                // int(arg) trunca hacia cero, como `int(args[i].raw)` del oráculo.
                let lo = arg_f64(arg(args, 0)?)?.trunc() as i64;
                let hi = arg_f64(arg(args, 1)?)?.trunc() as i64;
                if lo > hi {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "random_int: min ({}) is greater than max ({})",
                        lo, hi
                    ))));
                }
                use rand::Rng;
                Ok(syn_int(rand::thread_rng().gen_range(lo..=hi)))
            }),
        );
    }
}
