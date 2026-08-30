//! Expresiones cron de pared (5 campos POSIX + alias `@daily`…). Puro: parsea y
//! calcula "el próximo instante que matchea a partir de `t`" — nada de hilos ni I/O.
//!
//! Semántica (documentada en `specs/cron-wall-clock.md`):
//! - `minute hour day-of-month month day-of-week`; `*`, `a`, `a-b`, `*/n`, `a-b/n`,
//!   listas; nombres `jan..dec`/`sun..sat`; `0` y `7` = domingo.
//! - dom/dow con ambos restringidos → OR (regla de Vixie cron).
//! - Zona: offset FIJO (`UTC`, `+HH:MM`, `-HH:MM`). Sin IANA/DST (sería tzdata en el
//!   binario — extensión futura; la API ya lo admite).
//! - `next_after(t)` es estrictamente `> t`, con segundos = 0. Si no hay ocurrencia en
//!   5 años → `None` (el builtin lo rechaza al registrar).

use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, TimeZone, Timelike};

#[derive(Clone, Debug)]
pub struct CronExpr {
    minutes: u64, // bit i = minuto i (0-59)
    hours: u32,   // 0-23
    dom: u32,     // bit d = día d (1-31)
    months: u16,  // bit m = mes m (1-12)
    dow: u8,      // bit w = weekday w (0=dom … 6=sáb)
    dom_star: bool,
    dow_star: bool,
    source: String,
}

const MONTHS: [&str; 12] =
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Cinco años en segundos: horizonte de búsqueda de `next_after`.
const HORIZON_SECS: i64 = 5 * 366 * 86_400;

fn alias(name: &str) -> Result<&'static str, String> {
    Ok(match name {
        "@yearly" | "@annually" => "0 0 1 1 *",
        "@monthly" => "0 0 1 * *",
        "@weekly" => "0 0 * * 0",
        "@daily" | "@midnight" => "0 0 * * *",
        "@hourly" => "0 * * * *",
        "@reboot" => {
            return Err("unknown alias \"@reboot\" (use cron_after(0, task) to run once at start)".into())
        }
        other => return Err(format!("unknown alias \"{}\"", other)),
    })
}

/// Un campo → bitset de valores. `names` traduce nombres a números (offset `base`).
fn parse_field(
    field: &str,
    label: &str,
    lo: u32,
    hi: u32,
    names: Option<&[&str]>,
) -> Result<(u64, bool), String> {
    let mut bits: u64 = 0;
    let mut star = true;
    let value_of = |tok: &str| -> Result<u32, String> {
        if let Ok(n) = tok.parse::<u32>() {
            return Ok(n);
        }
        if let Some(names) = names {
            if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(tok)) {
                // dow: 0-based (sun=0); month: 1-based (jan=1)
                return Ok(i as u32 + if lo == 0 { 0 } else { 1 });
            }
            let kind = if lo == 0 { "weekday" } else { "month" };
            return Err(format!("unknown {} \"{}\"", kind, tok));
        }
        Err(format!("{} \"{}\" is not a number", label, tok))
    };
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("{}: empty list item", label));
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s
                    .trim()
                    .parse()
                    .map_err(|_| format!("{}: step \"{}\" is not a number", label, s))?;
                if step == 0 {
                    return Err(format!("{}: step must be > 0", label));
                }
                (r.trim(), step)
            }
            None => (part, 1),
        };
        let (a, b, explicit) = if range == "*" {
            (lo, hi, false)
        } else if let Some((x, y)) = range.split_once('-') {
            (value_of(x.trim())?, value_of(y.trim())?, true)
        } else {
            let v = value_of(range)?;
            // `5/10` en cron clásico = desde 5 hasta el máximo con paso 10.
            if step > 1 {
                (v, hi, true)
            } else {
                (v, v, true)
            }
        };
        if explicit {
            star = false;
        }
        for v in [a, b] {
            if v < lo || v > hi {
                return Err(format!("{} {} is out of range {}-{}", label, v, lo, hi));
            }
        }
        if a > b {
            return Err(format!("{}: range {}-{} is reversed", label, a, b));
        }
        let mut v = a;
        while v <= b {
            bits |= 1u64 << v;
            v += step;
        }
        if step > 1 {
            star = false;
        }
    }
    Ok((bits, star))
}

pub fn parse(expr: &str) -> Result<CronExpr, String> {
    let src = expr.trim();
    let body: String = if src.starts_with('@') {
        alias(&src.to_ascii_lowercase())?.to_string()
    } else {
        src.to_string()
    };
    let fields: Vec<&str> = body.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "expected 5 fields (minute hour day month weekday), got {}",
            fields.len()
        ));
    }
    let (minutes, _) = parse_field(fields[0], "minute", 0, 59, None)?;
    let (hours, _) = parse_field(fields[1], "hour", 0, 23, None)?;
    let (dom, dom_star) = parse_field(fields[2], "day", 1, 31, None)?;
    let (months, _) = parse_field(fields[3], "month", 1, 12, Some(&MONTHS))?;
    let (dow_raw, dow_star) = parse_field(fields[4], "weekday", 0, 7, Some(&DAYS))?;
    // 7 = domingo (bit 0).
    let mut dow = (dow_raw & 0x7f) as u8;
    if dow_raw & (1 << 7) != 0 {
        dow |= 1;
    }
    Ok(CronExpr {
        minutes,
        hours: hours as u32,
        dom: dom as u32,
        months: months as u16,
        dow,
        dom_star,
        dow_star,
        source: src.to_string(),
    })
}

/// `UTC` | `Z` | `+HH:MM` | `-HH:MM` | `+HHMM` → offset fijo.
pub fn parse_offset(tz: &str) -> Result<FixedOffset, String> {
    let t = tz.trim();
    if t.eq_ignore_ascii_case("utc") || t == "Z" || t.is_empty() {
        return Ok(FixedOffset::east_opt(0).unwrap());
    }
    let (sign, rest) = match t.chars().next() {
        Some('+') => (1, &t[1..]),
        Some('-') => (-1, &t[1..]),
        _ => {
            if t.contains('/') || t.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
                return Err(format!(
                    "tz \"{}\" is not supported — use a fixed offset like \"-03:00\" (IANA zones with DST are not available)",
                    t
                ));
            }
            return Err(format!("tz \"{}\" must be \"UTC\" or a fixed offset like \"+05:30\"", t));
        }
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("tz \"{}\" must be \"UTC\" or a fixed offset like \"+05:30\"", t));
    }
    let h: i32 = digits[..2].parse().unwrap();
    let m: i32 = digits[2..].parse().unwrap();
    if h > 23 || m > 59 {
        return Err(format!("tz \"{}\": offset out of range", t));
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
        .ok_or_else(|| format!("tz \"{}\": offset out of range", t))
}

/// Etiqueta normalizada de un offset: `UTC` o `+HH:MM`.
pub fn offset_label(off: FixedOffset) -> String {
    let secs = off.local_minus_utc();
    if secs == 0 {
        return "UTC".to_string();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.abs();
    format!("{}{:02}:{:02}", sign, a / 3600, (a % 3600) / 60)
}

impl CronExpr {
    pub fn source(&self) -> &str {
        &self.source
    }

    fn day_matches(&self, d: &DateTime<FixedOffset>) -> bool {
        let dom_ok = self.dom & (1 << d.day()) != 0;
        let dow_ok = self.dow & (1 << d.weekday().num_days_from_sunday()) != 0;
        match (self.dom_star, self.dow_star) {
            (true, true) => true,
            (false, true) => dom_ok,
            (true, false) => dow_ok,
            (false, false) => dom_ok || dow_ok,
        }
    }

    /// Primer instante estrictamente posterior a `after` (unix secs) que matchea, en
    /// `off`. `None` si no hay ninguno dentro de 5 años.
    pub fn next_after(&self, after: i64, off: FixedOffset) -> Option<i64> {
        let limit = after + HORIZON_SECS;
        // Arrancar en el próximo minuto entero.
        let mut t = after.div_euclid(60) * 60 + 60;
        while t <= limit {
            let dt = off.from_utc_datetime(&DateTime::from_timestamp(t, 0)?.naive_utc());
            if self.months & (1 << dt.month()) == 0 {
                // Saltar al 1º del mes siguiente 00:00 (hora local del offset).
                let (y, m) = if dt.month() == 12 { (dt.year() + 1, 1) } else { (dt.year(), dt.month() + 1) };
                t = local_ts(off, y, m, 1, 0, 0)?;
                continue;
            }
            if !self.day_matches(&dt) {
                let next_day = dt.date_naive().succ_opt()?;
                t = local_ts(off, next_day.year(), next_day.month(), next_day.day(), 0, 0)?;
                continue;
            }
            if self.hours & (1 << dt.hour()) == 0 {
                // Hora siguiente :00 (puede cruzar al día siguiente; el loop lo re-valida).
                t = t - (dt.minute() as i64) * 60 + 3600;
                continue;
            }
            if self.minutes & (1u64 << dt.minute()) == 0 {
                t += 60;
                continue;
            }
            return Some(t);
        }
        None
    }
}

/// Partes locales (en `off`) → unix secs. Con offset fijo nunca es ambiguo.
fn local_ts(off: FixedOffset, y: i32, m: u32, d: u32, h: u32, min: u32) -> Option<i64> {
    let naive = NaiveDate::from_ymd_opt(y, m, d)?.and_hms_opt(h, min, 0)?;
    off.from_local_datetime(&naive).single().map(|dt| dt.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).unwrap()
    }
    fn ts(s: &str) -> i64 {
        DateTime::parse_from_rfc3339(s).unwrap().timestamp()
    }
    fn iso(t: i64) -> String {
        DateTime::from_timestamp(t, 0).unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    #[test]
    fn daily_at_nine() {
        let e = parse("0 9 * * *").unwrap();
        let n = e.next_after(ts("2026-08-29T10:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-08-30T09:00:00Z");
        // Estricto: desde exactamente las 9:00 → mañana.
        let n2 = e.next_after(ts("2026-08-30T09:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n2), "2026-08-31T09:00:00Z");
        // 08:59:30 → hoy a las 9.
        let n3 = e.next_after(ts("2026-08-30T08:59:30Z"), utc()).unwrap();
        assert_eq!(iso(n3), "2026-08-30T09:00:00Z");
    }

    #[test]
    fn every_fifteen_aligned() {
        let e = parse("*/15 * * * *").unwrap();
        let n = e.next_after(ts("2026-08-29T10:07:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-08-29T10:15:00Z");
        let n = e.next_after(ts("2026-08-29T10:45:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-08-29T11:00:00Z");
    }

    #[test]
    fn monday_with_offset() {
        // 2026-08-29 es sábado. Lunes 08:30 en -03:00 = 11:30Z del 2026-08-31.
        let e = parse("30 8 * * 1").unwrap();
        let off = parse_offset("-03:00").unwrap();
        let n = e.next_after(ts("2026-08-29T10:00:00Z"), off).unwrap();
        assert_eq!(iso(n), "2026-08-31T11:30:00Z");
        let e2 = parse("30 8 * * MON").unwrap();
        assert_eq!(e2.next_after(ts("2026-08-29T10:00:00Z"), off), Some(n));
    }

    #[test]
    fn leap_day_and_month_skip() {
        let e = parse("0 0 29 2 *").unwrap();
        let n = e.next_after(ts("2025-03-01T00:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2028-02-29T00:00:00Z");
        let m = parse("0 0 1 jan *").unwrap();
        let n = m.next_after(ts("2026-08-29T10:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2027-01-01T00:00:00Z");
    }

    #[test]
    fn dom_dow_or_rule() {
        // Día 15 O viernes: desde 2026-08-29 (sáb) → viernes 2026-09-04 antes que el 15.
        let e = parse("0 0 15 * 5").unwrap();
        let n = e.next_after(ts("2026-08-29T10:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-09-04T00:00:00Z");
        // Sólo dom restringido → el 15.
        let e = parse("0 0 15 * *").unwrap();
        let n = e.next_after(ts("2026-08-29T10:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-09-15T00:00:00Z");
    }

    #[test]
    fn aliases_and_sunday_seven() {
        assert_eq!(parse("@hourly").unwrap().source(), "@hourly");
        let e = parse("0 0 * * 7").unwrap();
        let n = e.next_after(ts("2026-08-29T10:00:00Z"), utc()).unwrap();
        assert_eq!(iso(n), "2026-08-30T00:00:00Z"); // domingo
        let e = parse("@weekly").unwrap();
        assert_eq!(e.next_after(ts("2026-08-29T10:00:00Z"), utc()), Some(n));
    }

    #[test]
    fn never_matches_is_none() {
        let e = parse("0 0 31 2 *").unwrap();
        assert_eq!(e.next_after(ts("2026-08-29T10:00:00Z"), utc()), None);
    }

    #[test]
    fn errors_name_the_field() {
        assert!(parse("0 25 * * *").unwrap_err().contains("hour 25 is out of range 0-23"));
        assert!(parse("0 9 *").unwrap_err().contains("expected 5 fields"));
        assert!(parse("0 9 * foo *").unwrap_err().contains("unknown month \"foo\""));
        assert!(parse("*/0 * * * *").unwrap_err().contains("step must be > 0"));
        assert!(parse("@reboot").unwrap_err().contains("cron_after(0, task)"));
        assert!(parse("10-5 * * * *").unwrap_err().contains("reversed"));
        assert!(parse_offset("America/Sao_Paulo").unwrap_err().contains("not supported"));
        assert!(parse_offset("+25:00").unwrap_err().contains("out of range"));
        assert_eq!(offset_label(parse_offset("-0300").unwrap()), "-03:00");
        assert_eq!(offset_label(parse_offset("utc").unwrap()), "UTC");
        assert_eq!(offset_label(parse_offset("+05:30").unwrap()), "+05:30");
    }

    #[test]
    fn lists_ranges_steps_mixed() {
        let e = parse("0 1,15-20/5 * * *").unwrap();
        assert_eq!(e.hours, (1 << 1) | (1 << 15) | (1 << 20));
        let e = parse("5/10 * * * *").unwrap();
        assert_eq!(e.minutes, (1 << 5) | (1 << 15) | (1 << 25) | (1 << 35) | (1 << 45) | (1 << 55));
    }
}
