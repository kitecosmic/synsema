//! Fechas, instantes y duraciones como TIPOS (v0.6.29, DATOS-13) — el modelo de `java.time`,
//! Temporal de JS y polars: cosas distintas son tipos distintos.
//!
//! - `date`: un día civil, sin hora ni zona (`2026-01-03`).
//! - `datetime`: un instante con su zona, que es IANA (horario de verano incluido) o un offset
//!   fijo (el `+05:30` de RFC 3339, como Python, `java.time` y Temporal: la hora local de una
//!   fecha de una API no se pierde). Se muestra como RFC 3339: `Z` en UTC, el offset solo con
//!   una zona de offset fijo (`2026-01-03T10:00:00+05:30`) y la zona entre corchetes con una
//!   IANA (`2026-01-03T10:00:00-03:00[America/Buenos_Aires]`, RFC 9557).
//! - `duration`: una cantidad exacta de tiempo (nanosegundos), ISO 8601 al mostrarse (`PT1H30M`).
//!
//! Parsear, formatear, operar y comparar son PUROS; sólo `now()` pide la capability `time`.

use std::cmp::Ordering;
use std::fmt;
use std::rc::Rc;

use chrono::{
    DateTime, Datelike, Duration as ChronoDuration, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, Offset,
    TimeZone, Timelike, Utc,
};
use chrono_tz::Tz;

use crate::interpreter::{Control, RuntimeError};
use crate::number::Number;
use crate::types::{syn_float, syn_int, syn_list, syn_map, syn_text, SynValue};

/// La zona de un `datetime`: una zona IANA (con sus cambios de horario) o un offset fijo
/// (`+05:30`, sin horario de verano). Un offset cero es siempre `UTC` (`Zone::fixed`), así
/// `Z`, `+00:00` y `UTC` son la misma zona.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    Iana(Tz),
    Fixed(FixedOffset),
}

pub const UTC: Zone = Zone::Iana(Tz::UTC);

impl Zone {
    /// La zona de un offset en segundos: `UTC` si es cero.
    pub fn fixed(secs: i32) -> Zone {
        match FixedOffset::east_opt(secs) {
            Some(f) if secs != 0 => Zone::Fixed(f),
            _ => UTC,
        }
    }

    /// El nombre que ven los programas: el IANA (`"Europe/Madrid"`, `"UTC"`) o el offset
    /// (`"+05:30"`).
    pub fn name(&self) -> String {
        match self {
            Zone::Iana(tz) => tz.name().to_string(),
            Zone::Fixed(f) => offset_text(f.local_minus_utc()),
        }
    }
}

/// El offset de un instante en una `Zone` (el de la IANA en ese instante, o el fijo).
#[derive(Clone, Copy, Debug)]
pub enum ZoneOffset {
    Iana(<Tz as TimeZone>::Offset),
    Fixed(FixedOffset),
}

impl Offset for ZoneOffset {
    fn fix(&self) -> FixedOffset {
        match self {
            ZoneOffset::Iana(o) => o.fix(),
            ZoneOffset::Fixed(f) => *f,
        }
    }
}

impl fmt::Display for ZoneOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `%Z`: la abreviatura de la IANA (`CET`, `-03`) o el offset.
            ZoneOffset::Iana(o) => write!(f, "{}", o),
            ZoneOffset::Fixed(x) => write!(f, "{}", x),
        }
    }
}

impl TimeZone for Zone {
    type Offset = ZoneOffset;

    fn from_offset(offset: &ZoneOffset) -> Zone {
        match offset {
            ZoneOffset::Iana(o) => Zone::Iana(Tz::from_offset(o)),
            ZoneOffset::Fixed(f) => Zone::Fixed(*f),
        }
    }

    fn offset_from_local_date(&self, local: &NaiveDate) -> LocalResult<ZoneOffset> {
        match self {
            Zone::Iana(tz) => tz.offset_from_local_date(local).map(ZoneOffset::Iana),
            Zone::Fixed(f) => f.offset_from_local_date(local).map(ZoneOffset::Fixed),
        }
    }

    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<ZoneOffset> {
        match self {
            Zone::Iana(tz) => tz.offset_from_local_datetime(local).map(ZoneOffset::Iana),
            Zone::Fixed(f) => f.offset_from_local_datetime(local).map(ZoneOffset::Fixed),
        }
    }

    fn offset_from_utc_date(&self, utc: &NaiveDate) -> ZoneOffset {
        match self {
            Zone::Iana(tz) => ZoneOffset::Iana(tz.offset_from_utc_date(utc)),
            Zone::Fixed(f) => ZoneOffset::Fixed(f.offset_from_utc_date(utc)),
        }
    }

    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> ZoneOffset {
        match self {
            Zone::Iana(tz) => ZoneOffset::Iana(tz.offset_from_utc_datetime(utc)),
            Zone::Fixed(f) => ZoneOffset::Fixed(f.offset_from_utc_datetime(utc)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Temporal {
    Date(NaiveDate),
    DateTime(DateTime<Zone>),
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
    // Segundos + nanosegundos (no `num_nanoseconds`, que desborda pasados ~292 años).
    let total_s = d.num_seconds();
    let nanos = d.subsec_nanos() as i64;
    let days = total_s / 86_400;
    let mut rem = total_s % 86_400;
    let hours = rem / 3_600;
    rem %= 3_600;
    let minutes = rem / 60;
    let secs = rem % 60;
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
            Temporal::DateTime(dt) => match dt.timezone() {
                z if z == UTC => write!(f, "{}", dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
                // Offset fijo: RFC 3339 tal cual (lo que lee cualquier API; el `[+05:30]` de
                // RFC 9557 sería redundante).
                Zone::Fixed(_) => write!(f, "{}", rfc3339_local(dt)),
                Zone::Iana(tz) => write!(f, "{}[{}]", rfc3339_local(dt), tz.name()),
            },
            Temporal::Duration(d) => write!(f, "{}", duration_iso(d)),
        }
    }
}

/// RFC 3339 con el offset local. Un offset con segundos (la hora solar de una zona IANA antes de
/// ~1920: Buenos Aires 1900 = `-04:16:48`) se escribe con sus segundos, como Python, java.time y
/// Temporal: redondearlo a minutos nombraría otro instante y no se podría volver a leer.
fn rfc3339_local(dt: &DateTime<Zone>) -> String {
    let off = dt.offset().fix().local_minus_utc();
    if off % 60 == 0 {
        return dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false);
    }
    format!("{}{}", dt.naive_local().format("%Y-%m-%dT%H:%M:%S%.f"), offset_text(off))
}

/// `±HH:MM`, o `±HH:MM:SS` si el offset tiene segundos.
fn offset_text(secs: i32) -> String {
    let (sign, a) = if secs < 0 { ('-', -secs) } else { ('+', secs) };
    let (h, m, s) = (a / 3600, a / 60 % 60, a % 60);
    if s == 0 {
        format!("{}{:02}:{:02}", sign, h, m)
    } else {
        format!("{}{:02}:{:02}:{:02}", sign, h, m, s)
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

/// Una zona por nombre: IANA (`"Europe/Madrid"`), `"UTC"`/`"Z"` o un offset fijo
/// (`"+05:30"`, `"-0300"`, `"+05"`).
pub fn tz_of(name: &str, who: &str) -> Result<Zone, Control> {
    if name.eq_ignore_ascii_case("utc") || name.eq_ignore_ascii_case("z") {
        return Ok(UTC);
    }
    if let Some(secs) = parse_offset(name) {
        return Ok(Zone::fixed(secs));
    }
    name.parse::<Tz>().map(Zone::Iana).map_err(|_| {
        err(format!(
            "{}: unknown time zone {:?} — use an IANA name like \"America/Buenos_Aires\", \"Europe/Madrid\" or \"UTC\", or a fixed offset like \"+05:30\"",
            who, name
        ))
    })
}

/// `±HH:MM`, `±HHMM`, `±HH`, o con segundos `±HH:MM:SS` / `±HHMMSS` (el formato de Python y
/// java.time) → segundos al este de UTC (menos de 24 h). Los dos puntos van en todas las
/// posiciones o en ninguna.
fn parse_offset(s: &str) -> Option<i32> {
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let colons: Vec<usize> = rest.match_indices(':').map(|(i, _)| i).collect();
    let well_placed = match digits.len() {
        2 => colons.is_empty(),
        4 => colons.is_empty() || colons == [2],
        6 => colons.is_empty() || colons == [2, 5],
        _ => false,
    };
    if !well_placed {
        return None;
    }
    let part = |i: usize| digits.get(i..i + 2).map_or(Some(0), |p| p.parse::<i32>().ok());
    let (h, m, sec) = (part(0)?, part(2)?, part(4)?);
    (h < 24 && m < 60 && sec < 60).then_some(sign * (h * 3600 + m * 60 + sec))
}

fn int_of(v: &SynValue, what: &str, who: &str) -> Result<i64, Control> {
    match v {
        SynValue::Number(n) if n.is_integer() => n.to_i64_trunc().ok_or_else(|| err(format!("{}: {} out of range", who, what))),
        SynValue::Number(Number::Float(x)) if x.fract() == 0.0 => Ok(*x as i64),
        other => Err(err(format!("{}: {} must be an integer, got {}", who, what, other))),
    }
}

/// Una hora local que cae en el hueco de un cambio de horario, empujada hacia adelante lo
/// que dura el hueco (02:30 en un salto de 02:00 a 03:00 → 03:30): la regla "compatible" de
/// Temporal y `java.time`. La usan las cuentas de calendario (`add_days`, `add_months`,
/// `truncate`, `date_range`, el comienzo de un día), donde fallar a mitad de una serie no
/// sirve: en un día sin medianoche, el día empieza a la 01:00. Construir o parsear una hora
/// que no existe sigue siendo error.
fn local_to_dt_forward(tz: Zone, naive: NaiveDateTime, who: &str) -> Result<DateTime<Zone>, Control> {
    if let chrono::LocalResult::None = tz.from_local_datetime(&naive) {
        let before = tz.offset_from_utc_datetime(&(naive - ChronoDuration::days(1))).fix();
        let utc = naive - ChronoDuration::seconds(before.local_minus_utc() as i64);
        return Ok(tz.from_utc_datetime(&utc));
    }
    local_to_dt(tz, naive, who)
}

/// Como `local_to_dt_forward`, pero en la hora REPETIDA de un atraso de reloj se queda con
/// el offset de `like`: truncar 02:30 de la segunda pasada a la hora da 02:00 de la segunda
/// pasada, no el de la primera (una hora antes).
fn local_to_dt_like(like: &DateTime<Zone>, naive: NaiveDateTime, who: &str) -> Result<DateTime<Zone>, Control> {
    let tz = like.timezone();
    match tz.from_local_datetime(&naive) {
        chrono::LocalResult::Ambiguous(a, b) => {
            Ok(if b.offset().fix() == like.offset().fix() { b } else { a })
        }
        _ => local_to_dt_forward(tz, naive, who),
    }
}

fn local_to_dt(tz: Zone, naive: NaiveDateTime, who: &str) -> Result<DateTime<Zone>, Control> {
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
            Ok(value(Temporal::DateTime(utc.with_timezone(&tz.unwrap_or(UTC)))))
        }
        [SynValue::Time(t)] => match &**t {
            Temporal::Date(d) => {
                let tz = tz.unwrap_or(UTC);
                Ok(value(Temporal::DateTime(local_to_dt_forward(tz, d.and_time(NaiveTime::MIN), W)?)))
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
            Ok(value(Temporal::DateTime(local_to_dt(tz.unwrap_or(UTC), d.and_time(t), W)?)))
        }
        _ => Err(err("datetime(text, tz?), datetime(year, month, day, hour?, minute?, second?, tz?) or datetime(timestamp, tz?)")),
    }
}

/// Un instante con offset explícito: RFC 3339 (`Z`, `+05:30`) o el offset sin dos puntos
/// (`+0530`, lo que acepta Python 3.11).
fn parse_with_offset(s: &str) -> Option<DateTime<FixedOffset>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt);
    }
    // La hora local y el offset por separado: así también `+0530`, `+05` y `-04:16:48` (lo que
    // escriben Python y java.time para un offset con segundos).
    let sep = s.find(['T', 't', ' '])?;
    let at = sep + s[sep..].rfind(['+', '-'])?;
    let off = FixedOffset::east_opt(parse_offset(&s[at..])?)?;
    let local = &s[..at];
    ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M", "%Y-%m-%dt%H:%M:%S%.f"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(local, f).ok())
        .and_then(|naive| off.from_local_datetime(&naive).single())
}

/// Una hora local sin offset (`2026-01-03T10:00`, `2026-01-03`) en la zona `tz`.
fn parse_local(s: &str, tz: Zone, who: &str) -> Option<Result<DateTime<Zone>, Control>> {
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, f) {
            return Some(local_to_dt(tz, naive, who));
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().map(|d| local_to_dt_forward(tz, d.and_time(NaiveTime::MIN), who))
}

/// ISO 8601 / RFC 3339 / RFC 9557, con el criterio de Temporal:
/// - con offset y sin zona → conserva el offset (`+05:30` sigue siendo las 10:00 en +05:30);
/// - con zona entre corchetes y sin offset → la hora LOCAL en esa zona (error si cae en el
///   hueco de un cambio de horario);
/// - con offset y zona → tienen que coincidir en ese instante, o es error;
/// - `tz` (el segundo argumento de `datetime`) convierte el resultado a esa zona; sin offset
///   ni zona en el texto, es la zona de la hora local.
fn parse_iso_datetime(t: &str, tz: Option<Zone>, who: &str) -> Result<DateTime<Zone>, Control> {
    let s = t.trim();
    let bad = || {
        err(format!(
            "{}: {:?} is not an ISO 8601 date-time (\"2026-01-03T10:00:00Z\", \"2026-01-03T10:00:00-03:00\", \"2026-01-03T10:00:00[Europe/Madrid]\", or local time plus a zone); for other formats: parse_datetime(text, format, tz)",
            who, t
        ))
    };
    // Zona entre corchetes (RFC 9557): `…[America/Buenos_Aires]` o `…[+05:30]`.
    if let Some(open) = s.rfind('[') {
        if s.ends_with(']') {
            let zone = tz_of(&s[open + 1..s.len() - 1], who)?;
            let body = s[..open].trim();
            let dt = match parse_with_offset(body) {
                Some(fixed) => {
                    let in_zone = fixed.with_timezone(&zone);
                    // `Z` (RFC 9557): el instante es exacto y el offset local se desconoce — se
                    // ve en la zona, sin comparar (Temporal y java.time hacen lo mismo).
                    let exact_instant = body.ends_with(['Z', 'z']);
                    if !exact_instant && in_zone.offset().fix() != *fixed.offset() {
                        return Err(err(format!(
                            "{}: {:?}: the offset {} does not match {} at that instant ({}) — drop the offset to read the local time in that zone, or drop the zone to keep the offset",
                            who,
                            t,
                            fixed.offset(),
                            zone.name(),
                            in_zone.offset().fix()
                        )));
                    }
                    in_zone
                }
                None => parse_local(body, zone, who).ok_or_else(bad)??,
            };
            return Ok(match tz {
                Some(z) => dt.with_timezone(&z),
                None => dt,
            });
        }
    }
    if let Some(dt) = parse_with_offset(s) {
        return Ok(match tz {
            Some(z) => dt.with_timezone(&z),
            None => dt.with_timezone(&Zone::fixed(dt.offset().local_minus_utc())),
        });
    }
    match parse_local(s, tz.unwrap_or(UTC), who) {
        Some(r) => r,
        None => Err(bad()),
    }
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

/// Una duración en segundos (float), sin pasar por nanosegundos en `i64` (desbordan en ~292 años).
fn secs_f64(d: &ChronoDuration) -> f64 {
    d.num_seconds() as f64 + d.subsec_nanos() as f64 / 1e9
}

/// La duración de `secs` segundos, redondeada al nanosegundo; `None` fuera de rango.
fn duration_of_secs(secs: f64) -> Option<ChronoDuration> {
    if !secs.is_finite() || secs.abs() > i64::MAX as f64 / 1_000.0 {
        return None;
    }
    let whole = secs.trunc();
    let nanos = ((secs - whole) * 1e9).round() as i64;
    ChronoDuration::try_seconds(whole as i64)?.checked_add(&ChronoDuration::nanoseconds(nanos))
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
            if x.subsec_nanos() != 0 || x.num_seconds() % 86_400 != 0 {
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
            let (x, y) = (secs_f64(a), secs_f64(b));
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
            let v = if op == "*" { secs_f64(a) * k } else { secs_f64(a) / k };
            match duration_of_secs(v) {
                Some(d) => value(Duration(d)),
                None => return Some(Err(err("duration out of range"))),
            }
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
                // Truncar a la hora (o menos) en la hora repetida conserva cuál de las dos
                // pasadas era; a un día (o más) es el PRIMER instante de ese día aunque su
                // medianoche se repita (Havana): un día no se parte en dos.
                let naive = day.and_time(time);
                let t = if matches!(unit.as_str(), "hour" | "minute" | "second") {
                    local_to_dt_like(dt, naive, W)?
                } else {
                    local_to_dt_forward(dt.timezone(), naive, W)?
                };
                Ok(value(Temporal::DateTime(t)))
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
                // En la hora repetida se queda con el offset de `t` (`add_days(t, 0)` es `t`).
                Ok(value(Temporal::DateTime(local_to_dt_like(dt, nd.and_time(local.time()), W)?)))
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
                Ok(value(Temporal::DateTime(local_to_dt_like(dt, nd.and_time(local.time()), W)?)))
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
                        // Días de CALENDARIO (como `add_days`): con un datetime la serie
                        // conserva la hora local aunque en el medio cambie el horario.
                        let days = match u.as_ref() {
                            "day" => 1,
                            "week" => 7,
                            // "hour", "minute", "second": tiempo transcurrido (una hora real, también
                            // en un cambio de horario), como `duration(hours = 1)`.
                            "hour" | "minute" | "second" => 0,
                            other => {
                                return Err(err(format!(
                                    "{}: unknown step {:?} (use \"second\", \"minute\", \"hour\", \"day\", \"week\", \"month\", \"quarter\", \"year\" or a duration)",
                                    W, other
                                )))
                            }
                        };
                        if days == 0 {
                            if matches!(start, Temporal::Date(_)) {
                                return Err(err(format!("{}: a date has no {}s — use datetimes, or step by \"day\"", W, u)));
                            }
                            let unit = match u.as_ref() {
                                "hour" => ChronoDuration::hours(1),
                                "minute" => ChronoDuration::minutes(1),
                                _ => ChronoDuration::seconds(1),
                            };
                            let d = unit.checked_mul(i32::try_from(i).map_err(|_| err(format!("{}: too many steps", W)))?)
                                .ok_or_else(|| err(format!("{}: too many steps", W)))?;
                            binop(&value(start.clone()), "+", &value(Temporal::Duration(d))).unwrap()?
                        } else {
                            add_days(&[value(start.clone()), syn_int(days * i)])?
                        }
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
        // Un paso de calendario que cae en un día que no existió (Pacific/Apia saltó el
        // 30/12/2011) da el mismo instante que el anterior: no se repite, se saltea.
        let repeated = matches!(out.last(), Some(SynValue::Time(prev)) if cmp(prev, ct) == Some(Ordering::Equal));
        if !repeated {
            out.push(cur);
        }
        i += 1;
        if i > 1_000_000 {
            return Err(err(format!("{}: more than a million steps", W)));
        }
    }
    Ok(syn_list(out))
}

/// Formato strftime de un date/datetime (en su zona).
pub fn format(t: &Temporal, pattern: &str) -> Result<String, Control> {
    const W: &str = "format_time";
    match t {
        Temporal::Date(d) => strftime(pattern, W, " — a date has no time of day or zone; format a datetime", |it| {
            d.format_with_items(it)
        }),
        Temporal::DateTime(dt) => strftime(pattern, W, "", |it| dt.format_with_items(it)),
        Temporal::Duration(d) => Ok(duration_iso(d)),
    }
}

/// strftime sin pánicos: chrono entra en pánico en `to_string()` con un especificador inválido
/// (`%Q`) o con uno que pide lo que el valor no tiene (`%H` de una fecha). Se valida el patrón
/// antes, nombrando el especificador, y se escribe con `write!`, que devuelve el error.
pub fn strftime<'a, F: fmt::Display>(
    pattern: &'a str,
    who: &str,
    missing: &str,
    render: impl FnOnce(chrono::format::StrftimeItems<'a>) -> F,
) -> Result<String, Control> {
    use chrono::format::{Item, StrftimeItems};
    use std::fmt::Write;
    if StrftimeItems::new(pattern).any(|i| matches!(i, Item::Error)) {
        let spec = bad_specifier(pattern).unwrap_or_else(|| pattern.to_string());
        return Err(err(format!(
            "{}: {:?} is not a strftime specifier (e.g. %Y %m %d %H %M %S %z; %% is a literal %)",
            who, spec
        )));
    }
    let mut out = String::new();
    write!(out, "{}", render(StrftimeItems::new(pattern))).map_err(|_| {
        err(format!("{}: the pattern {:?} asks for a field the value does not have{}", who, pattern, missing))
    })?;
    Ok(out)
}

/// El primer especificador de `pattern` que chrono no entiende: el `%` con lo que lo sigue.
fn bad_specifier(pattern: &str) -> Option<String> {
    use chrono::format::{Item, StrftimeItems};
    let mut rest = pattern;
    while let Some(i) = rest.find('%') {
        let tail = &rest[i..];
        let ends: Vec<usize> = tail.char_indices().map(|(k, _)| k).skip(2).chain([tail.len()]).collect();
        // El prefijo más corto (`%d`, `%-d`, `%.3f`, `%:z`…) que se lee sin error.
        match ends.iter().take(4).find(|&&e| !StrftimeItems::new(&tail[..e]).any(|x| matches!(x, Item::Error))) {
            Some(&e) => rest = &tail[e..],
            None => return Some(tail[..ends[0].min(tail.len())].to_string()),
        }
    }
    None
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
            // Con `%z` el texto trae su offset: se conserva (o se convierte a `tz` si se pasó).
            if let Ok(dt) = DateTime::parse_from_str(t.trim(), f) {
                let zone = tz.unwrap_or_else(|| Zone::fixed(dt.offset().local_minus_utc()));
                return Ok(value(Temporal::DateTime(dt.with_timezone(&zone))));
            }
            let naive = NaiveDateTime::parse_from_str(t.trim(), f)
                .map_err(|e| err(format!("{}: {:?} does not match {:?}: {}", W, t.as_ref(), f.as_ref(), e)))?;
            local_to_dt(tz.unwrap_or(UTC), naive, W).map(|d| value(Temporal::DateTime(d)))
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
    let secs = secs_f64(&d);
    let per = match unit.as_str() {
        "weeks" => 604_800.0,
        "days" => 86_400.0,
        "hours" => 3_600.0,
        "minutes" => 60.0,
        "seconds" => 1.0,
        "milliseconds" => 1e-3,
        other => return Err(err(format!("in_units: unknown unit {:?}", other))),
    };
    Ok(syn_float(secs / per))
}
