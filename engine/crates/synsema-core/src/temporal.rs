//! Fechas, instantes y duraciones como TIPOS (v0.6.29, DATOS-13) — el modelo de `java.time`,
//! Temporal de JS y polars: cosas distintas son tipos distintos.
//!
//! - `date`: un día civil, sin hora ni zona (`2026-01-03`).
//! - `datetime`: un instante con su zona IANA (horario de verano incluido). Se muestra como
//!   RFC 3339 con la zona entre corchetes cuando no es UTC (`2026-01-03T10:00:00-03:00[America/Buenos_Aires]`, RFC 9557).
//! - `duration`: una cantidad exacta de tiempo (nanosegundos), ISO 8601 al mostrarse (`PT1H30M`).
//!
//! Parsear, formatear, operar y comparar son PUROS; sólo `now()` pide la capability `time`.

use std::cmp::Ordering;
use std::fmt;
use std::rc::Rc;

use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;

use crate::interpreter::{Control, RuntimeError};
use crate::number::Number;
use crate::types::{syn_float, syn_int, syn_list, syn_map, syn_text, SynValue};

#[derive(Clone, Debug, PartialEq)]
pub enum Temporal {
    Date(NaiveDate),
    DateTime(DateTime<Tz>),
    Duration(ChronoDuration),
}

impl Temporal {
    pub fn type_name(&self) -> &'static str {
        match self {
            Temporal::Date(_) => "date",
            Temporal::DateTime(_) => "datetime",
            Temporal::Duration(_) => "duration",
        }
    }
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

pub fn value(t: Temporal) -> SynValue {
    SynValue::Time(Rc::new(t))
}

/// ISO 8601 de una duración: `P1DT2H30M5.5S`, `PT0S`, `-PT1H`.
fn duration_iso(d: &ChronoDuration) -> String {
    let neg = *d < ChronoDuration::zero();
    let d = if neg { -*d } else { *d };
    let total_ns = d.num_nanoseconds().unwrap_or(i64::MAX);
    let days = total_ns / 86_400_000_000_000;
    let mut rem = total_ns % 86_400_000_000_000;
    let hours = rem / 3_600_000_000_000;
    rem %= 3_600_000_000_000;
    let minutes = rem / 60_000_000_000;
    rem %= 60_000_000_000;
    let secs = rem / 1_000_000_000;
    let nanos = rem % 1_000_000_000;
    let mut s = String::from(if neg { "-P" } else { "P" });
    if days > 0 {
        s.push_str(&format!("{}D", days));
    }
    let mut t = String::new();
    if hours > 0 {
        t.push_str(&format!("{}H", hours));
    }
    if minutes > 0 {
        t.push_str(&format!("{}M", minutes));
    }
    if secs > 0 || nanos > 0 {
        if nanos > 0 {
            let frac = format!("{:09}", nanos);
            t.push_str(&format!("{}.{}S", secs, frac.trim_end_matches('0')));
        } else {
            t.push_str(&format!("{}S", secs));
        }
    }
    if !t.is_empty() {
        s.push('T');
        s.push_str(&t);
    }
    if days == 0 && t.is_empty() {
        s.push_str("T0S");
    }
    s
}

impl fmt::Display for Temporal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Temporal::Date(d) => write!(f, "{}", d.format("%Y-%m-%d")),
            Temporal::DateTime(dt) => {
                if dt.timezone() == Tz::UTC {
                    write!(f, "{}", dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
                } else {
                    write!(f, "{}[{}]", dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false), dt.timezone().name())
                }
            }
            Temporal::Duration(d) => write!(f, "{}", duration_iso(d)),
        }
    }
}

/// Orden dentro del mismo tipo (los instantes se comparan por el instante, no por la zona).
pub fn cmp(a: &Temporal, b: &Temporal) -> Option<Ordering> {
    match (a, b) {
        (Temporal::Date(x), Temporal::Date(y)) => Some(x.cmp(y)),
        (Temporal::DateTime(x), Temporal::DateTime(y)) => Some(x.cmp(y)),
        (Temporal::Duration(x), Temporal::Duration(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

pub fn tz_of(name: &str, who: &str) -> Result<Tz, Control> {
    if name.eq_ignore_ascii_case("utc") || name == "Z" {
        return Ok(Tz::UTC);
    }
    name.parse::<Tz>().map_err(|_| {
        err(format!(
            "{}: unknown time zone {:?} — use an IANA name like \"America/Buenos_Aires\", \"Europe/Madrid\" or \"UTC\"",
            who, name
        ))
    })
}

fn int_of(v: &SynValue, what: &str, who: &str) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) if n.is_integer() => n.to_i64_trunc().ok_or_else(|| err(format!("{}: {} out of range", who, what))),
        SynValue::Number(Number::Float(x)) if x.fract() == 0.0 => Ok(*x as i64),
        other => Err(err(format!("{}: {} must be an integer, got {}", who, what, other))),
    }
}

fn local_to_dt(tz: Tz, naive: NaiveDateTime, who: &str) -> Result<DateTime<Tz>, Control> {
    match tz.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Ok(dt),
        // En el cambio de hora hacia atrás una hora local ocurre dos veces: la primera, como
        // `java.time` y Temporal ("compatible").
        chrono::LocalResult::Ambiguous(first, _) => Ok(first),
        chrono::LocalResult::None => Err(err(format!(
            "{}: {} does not exist in {} (it falls in a daylight-saving gap)",
            who,
            naive,
            tz.name()
        ))),
    }
}

/// `date(y, m, d)` | `date("2026-01-03")` | `date(datetime)` (el día civil en su zona).
pub fn date(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "date";
    match args {
        [SynValue::Text(t)] => parse_iso_date(t, W).map(|d| value(Temporal::Date(d))),
        [SynValue::Time(t)] => match &**t {
            Temporal::DateTime(dt) => Ok(value(Temporal::Date(dt.date_naive()))),
            Temporal::Date(d) => Ok(value(Temporal::Date(*d))),
            Temporal::Duration(_) => Err(err("date(): a duration is not a date")),
        },
        [y, m, d] => {
            let (y, m, d) = (int_of(y, "the year", W)?, int_of(m, "the month", W)?, int_of(d, "the day", W)?);
            NaiveDate::from_ymd_opt(y as i32, m as u32, d as u32)
                .map(|d| value(Temporal::Date(d)))
                .ok_or_else(|| err(format!("date({}, {}, {}): not a valid calendar date", y, m, d)))
        }
        _ => Err(err("date(year, month, day), date(\"YYYY-MM-DD\") or date(datetime)")),
    }
}

fn parse_iso_date(t: &str, who: &str) -> Result<NaiveDate, Control> {
    NaiveDate::parse_from_str(t.trim(), "%Y-%m-%d")
        .map_err(|_| err(format!("{}: {:?} is not a date in the form YYYY-MM-DD (for other formats: parse_date(text, format))", who, t)))
}

/// `datetime("2026-01-03T10:00:00-03:00")`, `datetime("2026-01-03T10:00", tz)`,
/// `datetime(y, m, d, h?, mi?, s?, tz = "UTC")` o `datetime(timestamp, tz?)`.
pub fn datetime(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "datetime";
    let (positional, tz) = match args.last() {
        Some(SynValue::Text(t)) if args.len() >= 2 && !matches!(args.first(), Some(SynValue::Text(_)) if args.len() == 1) => {
            (&args[..args.len() - 1], Some(tz_of(t, W)?))
        }
        _ => (args, None),
    };
    match positional {
        [SynValue::Text(t)] => parse_iso_datetime(t, tz, W).map(|d| value(Temporal::DateTime(d))),
        [SynValue::Number(n)] => {
            let secs = n.to_f64();
            let whole = secs.floor();
            let nanos = ((secs - whole) * 1e9).round() as u32;
            let utc = DateTime::<Utc>::from_timestamp(whole as i64, nanos)
                .ok_or_else(|| err(format!("{}: timestamp {} is out of range", W, secs)))?;
            Ok(value(Temporal::DateTime(utc.with_timezone(&tz.unwrap_or(Tz::UTC)))))
        }
        [SynValue::Time(t)] => match &**t {
            Temporal::Date(d) => {
                let tz = tz.unwrap_or(Tz::UTC);
                Ok(value(Temporal::DateTime(local_to_dt(tz, d.and_time(NaiveTime::MIN), W)?)))
            }
            Temporal::DateTime(dt) => Ok(value(Temporal::DateTime(dt.with_timezone(&tz.unwrap_or(dt.timezone()))))),
            Temporal::Duration(_) => Err(err("datetime(): a duration is not an instant")),
        },
        parts if (3..=6).contains(&parts.len()) => {
            let mut v = [0i64; 6];
            let names = ["the year", "the month", "the day", "the hour", "the minute", "the second"];
            for (i, p) in parts.iter().enumerate() {
                v[i] = int_of(p, names[i], W)?;
            }
            let d = NaiveDate::from_ymd_opt(v[0] as i32, v[1] as u32, v[2] as u32)
                .ok_or_else(|| err(format!("{}: {}-{}-{} is not a valid calendar date", W, v[0], v[1], v[2])))?;
            let t = NaiveTime::from_hms_opt(v[3] as u32, v[4] as u32, v[5] as u32)
                .ok_or_else(|| err(format!("{}: {}:{}:{} is not a valid time", W, v[3], v[4], v[5])))?;
            Ok(value(Temporal::DateTime(local_to_dt(tz.unwrap_or(Tz::UTC), d.and_time(t), W)?)))
        }
        _ => Err(err("datetime(text, tz?), datetime(year, month, day, hour?, minute?, second?, tz?) or datetime(timestamp, tz?)")),
    }
}

fn parse_iso_datetime(t: &str, tz: Option<Tz>, who: &str) -> Result<DateTime<Tz>, Control> {
    let s = t.trim();
    // Con zona IANA entre corchetes (RFC 9557): `…[America/Buenos_Aires]`.
    if let Some(open) = s.rfind('[') {
        if s.ends_with(']') {
            let zone = tz_of(&s[open + 1..s.len() - 1], who)?;
            let inner = parse_iso_datetime(&s[..open], None, who)?;
            return Ok(inner.with_timezone(&zone));
        }
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&tz.unwrap_or(Tz::UTC)));
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, f) {
            return local_to_dt(tz.unwrap_or(Tz::UTC), naive, who);
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return local_to_dt(tz.unwrap_or(Tz::UTC), d.and_time(NaiveTime::MIN), who);
    }
    Err(err(format!(
        "{}: {:?} is not an ISO 8601 date-time (\"2026-01-03T10:00:00Z\", \"2026-01-03T10:00:00-03:00\", or local time plus a zone); for other formats: parse_datetime(text, format, tz)",
        who, t
    )))
}

/// `duration(days, hours, minutes, seconds, milliseconds, weeks)` — todos opcionales y con
/// nombre: `duration(hours = 1, minutes = 30)`. Fracciones permitidas (`hours = 1.5`).
pub fn duration(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "duration";
    let unit_ns: [f64; 6] = [86_400e9, 3_600e9, 60e9, 1e9, 1e6, 604_800e9];
    let mut total: f64 = 0.0;
    for (i, a) in args.iter().enumerate().take(6) {
        match a {
            SynValue::Nothing => {}
            SynValue::Number(n) => total += n.to_f64() * unit_ns[i],
            other => return Err(err(format!("{}: amounts must be numbers, got {}", W, other.type_name()))),
        }
    }
    if !total.is_finite() || total.abs() > i64::MAX as f64 {
        return Err(err("duration: out of range"));
    }
    Ok(value(Temporal::Duration(ChronoDuration::nanoseconds(total.round() as i64))))
}

/// Aritmética: date ± duration (días enteros), datetime ± duration, datetime − datetime,
/// date − date, duration ± duration, duration × número, duration ÷ número, duration ÷ duration.
pub fn binop(l: &SynValue, op: &str, r: &SynValue) -> Option<Result<SynValue, Control>> {
    use Temporal::*;
    let lt = if let SynValue::Time(t) = l { Some(&**t) } else { None };
    let rt = if let SynValue::Time(t) = r { Some(&**t) } else { None };
    if lt.is_none() && rt.is_none() {
        return None;
    }
    let bad = || Some(Err(err(format!(
        "Unsupported operation: {} {} {}",
        l.type_name(),
        op,
        r.type_name()
    ))));
    Some(Ok(match (lt, op, rt) {
        (Some(Date(d)), "+" | "-", Some(Duration(x))) => {
            if x.num_nanoseconds().map(|n| n % 86_400_000_000_000 != 0).unwrap_or(true) {
                return Some(Err(err(
                    "a date moves by whole days — use a datetime for hours and minutes: datetime(d, tz) + duration(hours = …)",
                )));
            }
            let days = ChronoDuration::days(x.num_days());
            let nd = if op == "+" { d.checked_add_signed(days) } else { d.checked_sub_signed(days) };
            match nd {
                Some(nd) => value(Date(nd)),
                None => return Some(Err(err("date out of range"))),
            }
        }
        (Some(Duration(x)), "+", Some(Date(d))) => match d.checked_add_signed(ChronoDuration::days(x.num_days())) {
            Some(nd) => value(Date(nd)),
            None => return Some(Err(err("date out of range"))),
        },
        (Some(Date(a)), "-", Some(Date(b))) => value(Duration(a.signed_duration_since(*b))),
        (Some(DateTime(a)), "+", Some(Duration(x))) | (Some(Duration(x)), "+", Some(DateTime(a))) => value(DateTime(*a + *x)),
        (Some(DateTime(a)), "-", Some(Duration(x))) => value(DateTime(*a - *x)),
        (Some(DateTime(a)), "-", Some(DateTime(b))) => value(Duration(a.signed_duration_since(*b))),
        (Some(Duration(a)), "+", Some(Duration(b))) => value(Duration(*a + *b)),
        (Some(Duration(a)), "-", Some(Duration(b))) => value(Duration(*a - *b)),
        (Some(Duration(a)), "/", Some(Duration(b))) => {
            let (x, y) = (a.num_nanoseconds().unwrap_or(0) as f64, b.num_nanoseconds().unwrap_or(0) as f64);
            if y == 0.0 {
                return Some(Err(err("Division by zero")));
            }
            syn_float(x / y)
        }
        (Some(Duration(a)), "*" | "/", None) | (None, "*", Some(Duration(a))) => {
            let other = if lt.is_some() { r } else { l };
            let k = match other {
                SynValue::Number(n) => n.to_f64(),
                _ => return bad(),
            };
            if op == "/" && k == 0.0 {
                return Some(Err(err("Division by zero")));
            }
            let ns = a.num_nanoseconds().unwrap_or(0) as f64;
            let v = if op == "*" { ns * k } else { ns / k };
            value(Duration(ChronoDuration::nanoseconds(v.round() as i64)))
        }
        _ => return bad(),
    }))
}

/// Partes de un `date`/`datetime` (en su zona) o de un timestamp (UTC).
pub fn parts(t: &Temporal) -> Option<SynValue> {
    let mut m = indexmap::IndexMap::new();
    match t {
        Temporal::Date(d) => {
            m.insert("year".to_string(), syn_int(d.year() as i64));
            m.insert("month".to_string(), syn_int(d.month() as i64));
            m.insert("day".to_string(), syn_int(d.day() as i64));
            m.insert("weekday".to_string(), syn_int(d.weekday().number_from_monday() as i64));
            m.insert("yearday".to_string(), syn_int(d.ordinal() as i64));
        }
        Temporal::DateTime(dt) => {
            m.insert("year".to_string(), syn_int(dt.year() as i64));
            m.insert("month".to_string(), syn_int(dt.month() as i64));
            m.insert("day".to_string(), syn_int(dt.day() as i64));
            m.insert("hour".to_string(), syn_int(dt.hour() as i64));
            m.insert("minute".to_string(), syn_int(dt.minute() as i64));
            m.insert("second".to_string(), syn_int(dt.second() as i64));
            m.insert("weekday".to_string(), syn_int(dt.weekday().number_from_monday() as i64));
            m.insert("yearday".to_string(), syn_int(dt.ordinal() as i64));
            m.insert("zone".to_string(), syn_text(dt.timezone().name()));
        }
        Temporal::Duration(_) => return None,
    }
    Some(syn_map(m))
}

/// `truncate(t, unit)`: el comienzo del período (`"year"`, `"quarter"`, `"month"`, `"week"`
/// (lunes), `"day"`, `"hour"`, `"minute"`, `"second"`) — para agrupar por período.
pub fn truncate(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "truncate";
    let unit = match args.get(1) {
        Some(SynValue::Text(u)) => u.to_string(),
        _ => return Err(err("truncate(t, unit): unit is \"year\", \"quarter\", \"month\", \"week\", \"day\", \"hour\", \"minute\" or \"second\"")),
    };
    let start_of_date = |d: NaiveDate| -> Result<NaiveDate, Control> {
        Ok(match unit.as_str() {
            "year" => NaiveDate::from_ymd_opt(d.year(), 1, 1).unwrap(),
            "quarter" => NaiveDate::from_ymd_opt(d.year(), ((d.month() - 1) / 3) * 3 + 1, 1).unwrap(),
            "month" => NaiveDate::from_ymd_opt(d.year(), d.month(), 1).unwrap(),
            "week" => d - ChronoDuration::days(d.weekday().num_days_from_monday() as i64),
            "day" | "hour" | "minute" | "second" => d,
            other => return Err(err(format!("{}: unknown unit {:?}", W, other))),
        })
    };
    match args.first() {
        Some(SynValue::Time(t)) => match &**t {
            Temporal::Date(d) => {
                if matches!(unit.as_str(), "hour" | "minute" | "second") {
                    return Err(err(format!("{}: a date has no {}s", W, unit)));
                }
                Ok(value(Temporal::Date(start_of_date(*d)?)))
            }
            Temporal::DateTime(dt) => {
                let local = dt.naive_local();
                let day = start_of_date(local.date())?;
                let time = match unit.as_str() {
                    "hour" => NaiveTime::from_hms_opt(local.hour(), 0, 0).unwrap(),
                    "minute" => NaiveTime::from_hms_opt(local.hour(), local.minute(), 0).unwrap(),
                    "second" => NaiveTime::from_hms_opt(local.hour(), local.minute(), local.second()).unwrap(),
                    _ => NaiveTime::MIN,
                };
                Ok(value(Temporal::DateTime(local_to_dt(dt.timezone(), day.and_time(time), W)?)))
            }
            Temporal::Duration(_) => Err(err("truncate: a duration has no calendar")),
        },
        Some(other) => Err(err(format!("{}: expected a date or datetime, got {}", W, other.type_name()))),
        None => Err(err("truncate(t, unit)")),
    }
}

/// Suma meses de calendario (fin de mes se ajusta: 31-ene + 1 mes = 28/29-feb).
fn add_months_date(d: NaiveDate, n: i64) -> Option<NaiveDate> {
    let total = d.year() as i64 * 12 + (d.month() as i64 - 1) + n;
    let (y, m) = (total.div_euclid(12) as i32, (total.rem_euclid(12) + 1) as u32);
    let last = NaiveDate::from_ymd_opt(if m == 12 { y + 1 } else { y }, if m == 12 { 1 } else { m + 1 }, 1)?.pred_opt()?.day();
    NaiveDate::from_ymd_opt(y, m, d.day().min(last))
}

/// `add_days(t, n)`: días de CALENDARIO — un datetime conserva su hora local aunque en el
/// medio haya un cambio de horario (sumar `duration(days = 1)` suma 24 h exactas).
pub fn add_days(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "add_days";
    let n = int_of(args.get(1).unwrap_or(&SynValue::Nothing), "the number of days", W)?;
    match args.first() {
        Some(SynValue::Time(t)) => match &**t {
            Temporal::Date(d) => d
                .checked_add_signed(ChronoDuration::days(n))
                .map(|d| value(Temporal::Date(d)))
                .ok_or_else(|| err("date out of range")),
            Temporal::DateTime(dt) => {
                let local = dt.naive_local();
                let nd = local.date().checked_add_signed(ChronoDuration::days(n)).ok_or_else(|| err("date out of range"))?;
                Ok(value(Temporal::DateTime(local_to_dt(dt.timezone(), nd.and_time(local.time()), W)?)))
            }
            Temporal::Duration(_) => Err(err("add_days: a duration has no calendar")),
        },
        _ => Err(err("add_days(date_or_datetime, n)")),
    }
}

/// `add_months(t, n)`: meses de calendario (no son una duración fija).
pub fn add_months(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "add_months";
    let n = int_of(args.get(1).unwrap_or(&SynValue::Nothing), "the number of months", W)?;
    match args.first() {
        Some(SynValue::Time(t)) => match &**t {
            Temporal::Date(d) => add_months_date(*d, n).map(|d| value(Temporal::Date(d))).ok_or_else(|| err("date out of range")),
            Temporal::DateTime(dt) => {
                let local = dt.naive_local();
                let nd = add_months_date(local.date(), n).ok_or_else(|| err("date out of range"))?;
                Ok(value(Temporal::DateTime(local_to_dt(dt.timezone(), nd.and_time(local.time()), W)?)))
            }
            Temporal::Duration(_) => Err(err("add_months: a duration has no calendar")),
        },
        _ => Err(err("add_months(date_or_datetime, n)")),
    }
}

/// `date_range(start, end, step)` → lista de `start` a `end` INCLUSIVE. `step` es una
/// duración o una unidad de calendario (`"day"`, `"week"`, `"month"`, `"quarter"`, `"year"`).
pub fn date_range(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "date_range";
    let (start, end) = match (args.first(), args.get(1)) {
        (Some(SynValue::Time(a)), Some(SynValue::Time(b))) => ((**a).clone(), (**b).clone()),
        _ => return Err(err("date_range(start, end, step): start and end are dates or datetimes")),
    };
    if std::mem::discriminant(&start) != std::mem::discriminant(&end) {
        return Err(err(format!("{}: start and end must be the same type", W)));
    }
    let step = args.get(2).cloned().unwrap_or_else(|| syn_text("day"));
    let mut out = Vec::new();
    let mut i: i64 = 0;
    loop {
        let cur = match &step {
            SynValue::Text(u) => {
                let months = match u.as_ref() {
                    "month" => Some(1),
                    "quarter" => Some(3),
                    "year" => Some(12),
                    _ => None,
                };
                match months {
                    Some(k) => add_months(&[value(start.clone()), syn_int(i * k)])?,
                    None => {
                        let days = match u.as_ref() {
                            "day" => 1,
                            "week" => 7,
                            other => return Err(err(format!("{}: unknown step {:?}", W, other))),
                        };
                        binop(&value(start.clone()), "+", &value(Temporal::Duration(ChronoDuration::days(days * i)))).unwrap()?
                    }
                }
            }
            SynValue::Time(t) if matches!(&**t, Temporal::Duration(d) if *d > ChronoDuration::zero()) => {
                let Temporal::Duration(d) = &**t else { unreachable!() };
                binop(&value(start.clone()), "+", &value(Temporal::Duration(*d * i as i32))).unwrap()?
            }
            other => return Err(err(format!("{}: step must be a positive duration or a unit, got {}", W, other))),
        };
        let SynValue::Time(ct) = &cur else { unreachable!() };
        if cmp(ct, &end) == Some(Ordering::Greater) {
            break;
        }
        out.push(cur);
        i += 1;
        if i > 1_000_000 {
            return Err(err(format!("{}: more than a million steps", W)));
        }
    }
    Ok(syn_list(out))
}

/// Formato strftime de un date/datetime (en su zona).
pub fn format(t: &Temporal, pattern: &str) -> Result<String, Control> {
    Ok(match t {
        Temporal::Date(d) => d.format(pattern).to_string(),
        Temporal::DateTime(dt) => dt.format(pattern).to_string(),
        Temporal::Duration(d) => duration_iso(d),
    })
}

/// `parse_date(text, format)` / `parse_datetime(text, format, tz?)`.
pub fn parse_date(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "parse_date";
    match (args.first(), args.get(1)) {
        (Some(SynValue::Text(t)), None) => parse_iso_date(t, W).map(|d| value(Temporal::Date(d))),
        (Some(SynValue::Text(t)), Some(SynValue::Text(f))) => NaiveDate::parse_from_str(t.trim(), f)
            .map(|d| value(Temporal::Date(d)))
            .map_err(|e| err(format!("{}: {:?} does not match {:?}: {}", W, t.as_ref(), f.as_ref(), e))),
        _ => Err(err("parse_date(text, format?)")),
    }
}

pub fn parse_datetime(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "parse_datetime";
    let tz = match args.get(2) {
        Some(SynValue::Text(z)) => Some(tz_of(z, W)?),
        _ => None,
    };
    match (args.first(), args.get(1)) {
        (Some(SynValue::Text(t)), None | Some(SynValue::Nothing)) => parse_iso_datetime(t, tz, W).map(|d| value(Temporal::DateTime(d))),
        (Some(SynValue::Text(t)), Some(SynValue::Text(f))) => {
            if let Ok(dt) = DateTime::parse_from_str(t.trim(), f) {
                return Ok(value(Temporal::DateTime(dt.with_timezone(&tz.unwrap_or(Tz::UTC)))));
            }
            let naive = NaiveDateTime::parse_from_str(t.trim(), f)
                .map_err(|e| err(format!("{}: {:?} does not match {:?}: {}", W, t.as_ref(), f.as_ref(), e)))?;
            local_to_dt(tz.unwrap_or(Tz::UTC), naive, W).map(|d| value(Temporal::DateTime(d)))
        }
        _ => Err(err("parse_datetime(text, format?, tz?)")),
    }
}

/// `timestamp(datetime)` → segundos desde 1970 (float, como `now()`).
pub fn timestamp(args: &[SynValue]) -> Result<SynValue, Control> {
    match args.first() {
        Some(SynValue::Time(t)) => match &**t {
            Temporal::DateTime(dt) => Ok(syn_float(dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 / 1e9)),
            other => Err(err(format!("timestamp() takes a datetime, got {}", other.type_name()))),
        },
        _ => Err(err("timestamp(datetime)")),
    }
}

/// `to_timezone(datetime, tz)`: el mismo instante visto en otra zona.
pub fn to_timezone(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "to_timezone";
    match (args.first(), args.get(1)) {
        (Some(SynValue::Time(t)), Some(SynValue::Text(z))) => match &**t {
            Temporal::DateTime(dt) => Ok(value(Temporal::DateTime(dt.with_timezone(&tz_of(z, W)?)))),
            other => Err(err(format!("{}: takes a datetime, got {}", W, other.type_name()))),
        },
        _ => Err(err("to_timezone(datetime, zone)")),
    }
}

/// Partes de una duración en una unidad: `in_units(d, "hours")` → float.
pub fn in_units(args: &[SynValue]) -> Result<SynValue, Control> {
    let (d, unit) = match (args.first(), args.get(1)) {
        (Some(SynValue::Time(t)), Some(SynValue::Text(u))) => match &**t {
            Temporal::Duration(d) => (*d, u.to_string()),
            other => return Err(err(format!("in_units() takes a duration, got {}", other.type_name()))),
        },
        _ => return Err(err("in_units(duration, unit): unit is \"days\", \"hours\", \"minutes\", \"seconds\" or \"milliseconds\"")),
    };
    let ns = d.num_nanoseconds().unwrap_or(0) as f64;
    let per = match unit.as_str() {
        "weeks" => 604_800e9,
        "days" => 86_400e9,
        "hours" => 3_600e9,
        "minutes" => 60e9,
        "seconds" => 1e9,
        "milliseconds" => 1e6,
        other => return Err(err(format!("in_units: unknown unit {:?}", other))),
    };
    Ok(syn_float(ns / per))
}
