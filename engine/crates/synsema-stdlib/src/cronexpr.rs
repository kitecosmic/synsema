//! Expresiones cron de pared (5 campos POSIX + alias `@daily`…). Puro: parsea y
//! calcula "el próximo instante que matchea a partir de `t`" — nada de hilos ni I/O.
//!
//! Semántica:
//! - `minute hour day-of-month month day-of-week`; `*`, `a`, `a-b`, `*/n`, `a-b/n`,
//!   listas; nombres `jan..dec`/`sun..sat`; `0` y `7` = domingo.
//! - dom/dow con ambos restringidos → OR (regla de Vixie cron).
//! - Zona: `UTC`, un offset fijo (`+05:30`) o una zona IANA (`Europe/Madrid`), con sus
//!   cambios de hora según la regla de Vixie cron / cronie (la de los cron de Linux):
//!   - un horario FIJO (ni minuto ni hora empiezan con `*`) que cae en la hora que se salta en
//!     primavera corre en el primer instante después del salto, en vez de perderse;
//!   - un horario fijo que cae en la hora repetida de otoño corre una sola vez, la primera;
//!   - un trabajo con comodín en minuto u hora (`*/15 * * * *`, `0 * * * *`) sigue el tiempo
//!     real: los minutos saltados no existen y la hora repetida corre las dos veces.
//! - `next_after(t)` es estrictamente `> t`, con segundos = 0. Si no hay ocurrencia en
//!   5 años → `None` (el builtin lo rechaza al registrar).

use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Timelike};
use synsema_core::temporal::{Zone, UTC};

#[derive(Clone, Debug)]
pub struct CronExpr {
    minutes: u64, // bit i = minuto i (0-59)
    hours: u32,   // 0-23
    dom: u32,     // bit d = día d (1-31)
    months: u16,  // bit m = mes m (1-12)
    dow: u8,      // bit w = weekday w (0=dom … 6=sáb)
    dom_star: bool,
    dow_star: bool,
    /// Minuto u hora empiezan con `*` (los `MIN_STAR`/`HR_STAR` de Vixie): el trabajo sigue el
    /// tiempo real en un cambio de hora; si no, es un horario fijo de pared.
    wild: bool,
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
        wild: fields[0].starts_with('*') || fields[1].starts_with('*'),
        source: src.to_string(),
    })
}

/// La zona de `opts.tz`: `UTC`, un offset fijo (`+05:30`, `-0300`) o una zona IANA
/// (`America/Santiago`), con el mismo parser que `parse_datetime` y `to_timezone`.
pub fn parse_zone(tz: &str) -> Result<Zone, synsema_core::interpreter::Control> {
    let t = tz.trim();
    if t.is_empty() {
        return Ok(UTC);
    }
    synsema_core::temporal::tz_of(t, "cron_every")
}

/// Los offsets van de -12:00 a +14:00: una hora de pared `n` es un instante a menos de esto
/// de `n` leída como UTC.
const MAX_OFFSET_SECS: i64 = 15 * 3600;

impl CronExpr {
    pub fn source(&self) -> &str {
        &self.source
    }

    fn day_matches(&self, d: NaiveDate) -> bool {
        let dom_ok = self.dom & (1 << d.day()) != 0;
        let dow_ok = self.dow & (1 << d.weekday().num_days_from_sunday()) != 0;
        match (self.dom_star, self.dow_star) {
            (true, true) => true,
            (false, true) => dom_ok,
            (true, false) => dow_ok,
            (false, false) => dom_ok || dow_ok,
        }
    }

    /// La primera hora de pared (minuto entero) estrictamente posterior a `from` que matchea,
    /// sin pasar de `limit`.
    fn next_local(&self, from: NaiveDateTime, limit: NaiveDateTime) -> Option<NaiveDateTime> {
        let mut t = from.date().and_hms_opt(from.hour(), from.minute(), 0)? + Duration::minutes(1);
        while t <= limit {
            if self.months & (1 << t.month()) == 0 {
                // Al 1º del mes siguiente, 00:00.
                let (y, m) = if t.month() == 12 { (t.year() + 1, 1) } else { (t.year(), t.month() + 1) };
                t = NaiveDate::from_ymd_opt(y, m, 1)?.and_hms_opt(0, 0, 0)?;
                continue;
            }
            if !self.day_matches(t.date()) {
                t = t.date().succ_opt()?.and_hms_opt(0, 0, 0)?;
                continue;
            }
            if self.hours & (1 << t.hour()) == 0 {
                // La hora siguiente, :00 (puede cruzar al día siguiente; el loop lo re-valida).
                t = t.date().and_hms_opt(t.hour(), 0, 0)? + Duration::hours(1);
                continue;
            }
            if self.minutes & (1u64 << t.minute()) == 0 {
                t += Duration::minutes(1);
                continue;
            }
            return Some(t);
        }
        None
    }

    /// Los instantes en que corre la hora de pared `n` (que ya matcheó) en `zone`.
    fn instants(&self, n: NaiveDateTime, zone: Zone) -> Vec<i64> {
        match zone.from_local_datetime(&n) {
            LocalResult::Single(dt) => vec![dt.timestamp()],
            // La hora repetida de otoño: un horario fijo corre una vez (la primera); un
            // comodín sigue el tiempo real y corre en las dos.
            LocalResult::Ambiguous(a, b) if self.wild => vec![a.timestamp(), b.timestamp()],
            LocalResult::Ambiguous(a, _) => vec![a.timestamp()],
            // La hora que se salta en primavera: un comodín no la tiene; un horario fijo corre
            // en el primer instante después del salto (la primera hora de pared que existe).
            LocalResult::None if self.wild => vec![],
            LocalResult::None => (1..=26 * 60)
                .find_map(|k| zone.from_local_datetime(&(n + Duration::minutes(k))).earliest())
                .map(|dt| vec![dt.timestamp()])
                .unwrap_or_default(),
        }
    }

    /// Primer instante estrictamente posterior a `after` (unix secs) en que corre, en `zone`.
    /// `None` si no hay ninguno dentro de 5 años.
    pub fn next_after(&self, after: i64, zone: Zone) -> Option<i64> {
        let naive_ts = |n: NaiveDateTime| n.and_utc().timestamp();
        // Con un offset que no cambia (fijo o UTC), hora de pared e instante avanzan juntos.
        let offset = match zone {
            Zone::Fixed(f) => Some(f.local_minus_utc() as i64),
            z if z == UTC => Some(0),
            _ => None,
        };
        if let Some(off) = offset {
            let from = DateTime::from_timestamp(after + off, 0)?.naive_utc();
            let n = self.next_local(from, from + Duration::seconds(HORIZON_SECS))?;
            return Some(naive_ts(n) - off);
        }
        // Una zona IANA: en un cambio de hora la hora de pared no avanza junto con el instante
        // (la segunda 02:30 de otoño es posterior a la primera 02:59). Se recorren las horas de
        // pared que pueden dar un instante > `after` y se queda el menor: una hora de pared da
        // instantes a menos de MAX_OFFSET de ella, así que pasado `mejor + MAX_OFFSET` no hay
        // uno menor.
        let from = DateTime::from_timestamp(after - MAX_OFFSET_SECS, 0)?.naive_utc();
        let limit = DateTime::from_timestamp(after + HORIZON_SECS, 0)?.naive_utc();
        let mut best: Option<i64> = None;
        let mut n = from;
        while let Some(m) = self.next_local(n, limit) {
            if best.is_some_and(|b| naive_ts(m) > b + MAX_OFFSET_SECS) {
                break;
            }
            for t in self.instants(m, zone) {
                if t > after && best.is_none_or(|b| t < b) {
                    best = Some(t);
                }
            }
            n = m;
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc() -> Zone {
        UTC
    }
    fn zone(name: &str) -> Zone {
        parse_zone(name).map_err(|_| name.to_string()).unwrap()
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
        let off = zone("-03:00");
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
        assert!(parse_zone("America/Nowhere").is_err());
        assert!(parse_zone("+25:00").is_err());
        assert_eq!(zone("-0300").name(), "-03:00");
        assert_eq!(zone("utc").name(), "UTC");
        assert_eq!(zone("").name(), "UTC");
        assert_eq!(zone("+05:30").name(), "+05:30");
        assert_eq!(zone("America/Sao_Paulo").name(), "America/Sao_Paulo");
    }

    #[test]
    fn lists_ranges_steps_mixed() {
        let e = parse("0 1,15-20/5 * * *").unwrap();
        assert_eq!(e.hours, (1 << 1) | (1 << 15) | (1 << 20));
        let e = parse("5/10 * * * *").unwrap();
        assert_eq!(e.minutes, (1 << 5) | (1 << 15) | (1 << 25) | (1 << 35) | (1 << 45) | (1 << 55));
    }

    /// Los instantes en que corre, uno tras otro, desde `from`.
    fn runs(expr: &str, tz: &str, from: &str, n: usize) -> Vec<String> {
        let (e, z) = (parse(expr).unwrap(), zone(tz));
        let mut t = ts(from);
        (0..n)
            .map(|_| {
                t = e.next_after(t, z).unwrap();
                iso(t)
            })
            .collect()
    }

    // Los instantes esperados salen de zoneinfo (Python), no de este código. 2026:
    // Santiago -03 → -04 el 5 de abril a las 00:00 (23:00-23:59 del 4 se repiten) y -04 → -03
    // el 6 de septiembre a las 00:00 (00:00-00:59 no existen); Madrid +01 → +02 el 29 de marzo
    // a las 02:00 y +02 → +01 el 25 de octubre a las 03:00; Lord Howe +11 → +10:30 el 5 de
    // abril a las 02:00 (01:30-01:59 se repiten) y +10:30 → +11 el 4 de octubre a las 02:00
    // (02:00-02:29 no existen: un salto de media hora).

    #[test]
    fn iana_fixed_time_in_the_spring_gap_runs_right_after_it() {
        // Medianoche no existe el 6 de septiembre en Santiago: corre a la 01:00 (-03), el
        // primer instante después del salto; el día siguiente, a medianoche como siempre.
        assert_eq!(
            runs("0 0 * * *", "America/Santiago", "2026-09-05T12:00:00Z", 2),
            ["2026-09-06T04:00:00Z", "2026-09-07T03:00:00Z"]
        );
        assert_eq!(runs("30 2 * * *", "Europe/Madrid", "2026-03-28T12:00:00Z", 2), ["2026-03-29T01:00:00Z", "2026-03-30T00:30:00Z"]);
        // Dos horarios dentro del mismo salto corren una sola vez, al final del salto.
        assert_eq!(runs("0,30 2 * * *", "Europe/Madrid", "2026-03-28T23:00:00Z", 2), ["2026-03-29T01:00:00Z", "2026-03-30T00:00:00Z"]);
        // Lord Howe salta media hora: 02:15 no existe el 4 de octubre, corre a las 02:30 (+11).
        assert_eq!(runs("15 2 * * *", "Australia/Lord_Howe", "2026-10-03T00:00:00Z", 2), ["2026-10-03T15:30:00Z", "2026-10-04T15:15:00Z"]);
    }

    #[test]
    fn iana_fixed_time_in_the_autumn_repeat_runs_once() {
        assert_eq!(
            runs("30 23 * * *", "America/Santiago", "2026-04-04T12:00:00Z", 2),
            ["2026-04-05T02:30:00Z", "2026-04-06T03:30:00Z"]
        );
        assert_eq!(runs("30 2 * * *", "Europe/Madrid", "2026-10-24T12:00:00Z", 2), ["2026-10-25T00:30:00Z", "2026-10-26T01:30:00Z"]);
        assert_eq!(runs("45 1 * * *", "Australia/Lord_Howe", "2026-04-04T00:00:00Z", 2), ["2026-04-04T14:45:00Z", "2026-04-05T15:15:00Z"]);
    }

    #[test]
    fn iana_wildcard_follows_real_time() {
        // Otoño en Madrid: cada 30 minutos de tiempo real, pasando dos veces por las 02:00 y
        // las 02:30 (primero +02, después +01).
        assert_eq!(
            runs("*/30 * * * *", "Europe/Madrid", "2026-10-25T00:15:00Z", 4),
            ["2026-10-25T00:30:00Z", "2026-10-25T01:00:00Z", "2026-10-25T01:30:00Z", "2026-10-25T02:00:00Z"]
        );
        // Primavera en Madrid: 02:00 y 02:30 no existen; de 01:30 (+01) pasa a 03:00 (+02).
        assert_eq!(
            runs("*/30 * * * *", "Europe/Madrid", "2026-03-29T00:15:00Z", 3),
            ["2026-03-29T00:30:00Z", "2026-03-29T01:00:00Z", "2026-03-29T01:30:00Z"]
        );
        // Cada hora (`0 * * * *` es comodín en la hora): Santiago repite las 23:00.
        assert_eq!(
            runs("0 * * * *", "America/Santiago", "2026-04-05T01:30:00Z", 3),
            ["2026-04-05T02:00:00Z", "2026-04-05T03:00:00Z", "2026-04-05T04:00:00Z"]
        );
        // Lord Howe, la media hora repetida: 01:45 (+11), 01:30 y 01:45 (+10:30), 02:00.
        assert_eq!(
            runs("*/15 * * * *", "Australia/Lord_Howe", "2026-04-04T14:40:00Z", 4),
            ["2026-04-04T14:45:00Z", "2026-04-04T15:00:00Z", "2026-04-04T15:15:00Z", "2026-04-04T15:30:00Z"]
        );
    }

    #[test]
    fn iana_zone_without_changes_and_fixed_offsets_are_as_before() {
        // Kolkata no cambia de hora: 09:00 IST = 03:30Z todos los días.
        assert_eq!(runs("0 9 * * *", "Asia/Kolkata", "2026-03-28T12:00:00Z", 2), ["2026-03-29T03:30:00Z", "2026-03-30T03:30:00Z"]);
        // Un offset fijo sigue igual en el día del cambio de Madrid.
        assert_eq!(runs("30 2 * * *", "+01:00", "2026-03-28T12:00:00Z", 2), ["2026-03-29T01:30:00Z", "2026-03-30T01:30:00Z"]);
        // Fuera de los cambios, una zona IANA es su offset de ese momento.
        assert_eq!(runs("30 8 * * 1", "America/Santiago", "2026-08-29T10:00:00Z", 1), ["2026-08-31T12:30:00Z"]);
    }
}
