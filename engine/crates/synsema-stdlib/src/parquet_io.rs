//! Parquet (v0.6.29, DATOS-16): el formato de intercambio de datos (polars, pandas, DuckDB,
//! Spark, BigQuery). Transformación PURA bytes ↔ filas, espejo de `csv_parse`/`csv_encode`:
//! el archivo se lee con `read_file_bytes` y se escribe con `write_file`.
//!
//! - `parquet_read(bytes)` → lista de mapas (una tabla), con sus tipos: enteros exactos, floats,
//!   decimales, texto, bytes, `date`, `datetime` (UTC), listas y grupos anidados; un nulo es
//!   `nothing`.
//! - `parquet_write(rows, opts?)` → bytes. El esquema sale de los datos, columna por columna
//!   (todas opcionales: `nothing` es nulo): entero → INT64, número con decimales → DOUBLE,
//!   decimal → DECIMAL(38, escala), texto → STRING, bool, bytes, date → DATE,
//!   datetime → TIMESTAMP(µs, UTC), y la zona IANA de cada columna de datetimes va en los
//!   metadatos del archivo (`synsema.timezones`): al leer vuelve con su zona. Una `duration`
//!   va como INT64 (como la guarda Arrow) con su unidad en `synsema.durations`; al leer se
//!   reconoce esa clave y el tipo `Duration` del esquema Arrow (pyarrow, polars). Al leer también
//!   se entienden timestamps en milisegundos, microsegundos y NANOSEGUNDOS (los de polars y
//!   pandas). Una columna que mezcla tipos o un valor anidado es un error
//!   con el nombre de la columna. `opts.compression` = "snappy" (default), "zstd", "gzip",
//!   "lz4" o "none".

use synsema_core::types::{Key, SynMap};
use std::rc::Rc;
use std::sync::Arc;

use indexmap::IndexMap;
use num_bigint::BigInt;

use parquet::basic::{Compression, LogicalType, Repetition, TimeUnit, Type as PhysicalType};
use parquet::data_type::ByteArray;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use parquet::record::Field;
use parquet::schema::types::Type;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::temporal::Temporal;
use synsema_core::types::{syn_bool, syn_bytes, syn_float, syn_int, syn_list, syn_map, syn_number, syn_text, SynValue};

/// Clave de los metadatos del archivo con la zona IANA de cada columna de datetimes.
const TZ_KEY: &str = "synsema.timezones";
/// Clave de los metadatos con la unidad (`"us"` o `"ns"`) de cada columna de durations.
const DUR_KEY: &str = "synsema.durations";

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Lectura
// =========================================================

fn decimal_from_parquet(d: &parquet::data_type::Decimal) -> SynValue {
    let unscaled = BigInt::from_signed_bytes_be(d.data());
    let scale = d.scale().max(0) as u32;
    // Una columna decimal es decimal, de cualquier precisión (decimal(38, s) incluido): exacta.
    syn_number(Number::decimal_from_parts(unscaled, scale))
}

fn field_to_syn(f: &Field) -> SynValue {
    use chrono::{DateTime, NaiveDate};
    match f {
        Field::Null => SynValue::Nothing,
        Field::Bool(b) => syn_bool(*b),
        Field::Byte(x) => syn_number(Number::Int(*x as i64)),
        Field::Short(x) => syn_number(Number::Int(*x as i64)),
        Field::Int(x) => syn_number(Number::Int(*x as i64)),
        Field::Long(x) => syn_number(Number::Int(*x)),
        Field::UByte(x) => syn_number(Number::Int(*x as i64)),
        Field::UShort(x) => syn_number(Number::Int(*x as i64)),
        Field::UInt(x) => syn_number(Number::Int(*x as i64)),
        Field::ULong(x) => syn_number(Number::from_bigint(BigInt::from(*x))),
        Field::Float(x) => syn_float(*x as f64),
        Field::Double(x) => syn_float(*x),
        Field::Decimal(d) => decimal_from_parquet(d),
        Field::Str(s) => syn_text(s.as_str()),
        Field::Bytes(b) => syn_bytes(b.data().to_vec()),
        Field::Date(days) => match NaiveDate::from_ymd_opt(1970, 1, 1).and_then(|e| e.checked_add_signed(chrono::Duration::days(*days as i64))) {
            Some(d) => SynValue::Time(synsema_core::types::Obj::new(Temporal::Date(d))),
            None => SynValue::Nothing,
        },
        Field::TimestampMillis(ms) => match DateTime::from_timestamp_millis(*ms) {
            Some(dt) => SynValue::Time(synsema_core::types::Obj::new(Temporal::DateTime(dt.with_timezone(&synsema_core::temporal::UTC)))),
            None => SynValue::Nothing,
        },
        Field::TimestampMicros(us) => match DateTime::from_timestamp_micros(*us) {
            Some(dt) => SynValue::Time(synsema_core::types::Obj::new(Temporal::DateTime(dt.with_timezone(&synsema_core::temporal::UTC)))),
            None => SynValue::Nothing,
        },
        Field::Group(row) => {
            let mut m = SynMap::new();
            for (k, v) in row.get_column_iter() {
                m.insert(k.clone(), field_to_syn(v));
            }
            syn_map(m)
        }
        Field::ListInternal(list) => syn_list(list.elements().iter().map(field_to_syn).collect()),
        Field::MapInternal(map) => {
            let mut m = SynMap::new();
            for (k, v) in map.entries() {
                let key = match field_to_syn(k) {
                    SynValue::Text(t) => t.to_string(),
                    other => other.to_string(),
                };
                m.insert(key, field_to_syn(v));
            }
            syn_map(m)
        }
        Field::Float16(h) => syn_float(f64::from(h.to_f32())),
        // TIME (hora del día): Synsema no tiene ese tipo; es la `duration` desde medianoche.
        Field::TimeMillis(ms) => time_of_day(chrono::Duration::milliseconds(*ms as i64)),
        Field::TimeMicros(us) => time_of_day(chrono::Duration::microseconds(*us)),
    }
}

// =========================================================
// Zona horaria del esquema Arrow (polars, pyarrow)
// =========================================================

/// Clave de los metadatos donde polars y pyarrow guardan el esquema Arrow: un mensaje IPC en
/// base64 cuyo tipo `Timestamp` lleva la zona de la columna (Parquet sólo dice "ajustado a UTC").
const ARROW_KEY: &str = "ARROW:schema";

/// Lector mínimo de flatbuffers: tablas con su vtable, strings, vectores y uniones. Todo acceso
/// está acotado: un esquema roto da `None`, nunca un pánico.
struct Fb<'a>(&'a [u8]);

impl<'a> Fb<'a> {
    fn u16_at(&self, p: usize) -> Option<u16> {
        self.0.get(p..p.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32_at(&self, p: usize) -> Option<u32> {
        self.0.get(p..p.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// Sigue un offset relativo (uoffset) guardado en `p`.
    fn deref(&self, p: usize) -> Option<usize> {
        p.checked_add(self.u32_at(p)? as usize)
    }
    /// Posición del campo `i` de la tabla que empieza en `t`; `None` si no está.
    fn field(&self, t: usize, i: usize) -> Option<usize> {
        let soff = self.u32_at(t)? as i32 as i64;
        let vt = usize::try_from(t as i64 - soff).ok()?;
        let vsize = self.u16_at(vt)? as usize;
        let at = 4 + 2 * i;
        if at + 2 > vsize {
            return None;
        }
        match self.u16_at(vt + at)? as usize {
            0 => None,
            off => t.checked_add(off),
        }
    }
    fn table(&self, t: usize, i: usize) -> Option<usize> {
        self.deref(self.field(t, i)?)
    }
    fn byte(&self, t: usize, i: usize) -> Option<u8> {
        self.0.get(self.field(t, i)?).copied()
    }
    fn short(&self, t: usize, i: usize) -> Option<i16> {
        self.u16_at(self.field(t, i)?).map(|v| v as i16)
    }
    fn string(&self, t: usize, i: usize) -> Option<&'a str> {
        let s = self.table(t, i)?;
        let n = self.u32_at(s)? as usize;
        std::str::from_utf8(self.0.get(s + 4..(s + 4).checked_add(n)?)?).ok()
    }
    /// Un vector: (posición del primer elemento, cantidad).
    fn vector(&self, t: usize, i: usize) -> Option<(usize, usize)> {
        let v = self.table(t, i)?;
        Some((v + 4, self.u32_at(v)? as usize))
    }
}

/// Lo que el esquema Arrow dice de las columnas de primer nivel: `columna → zona` de los
/// timestamps con zona, y `columna → nanosegundos por unidad` de las durations (Arrow las guarda
/// como INT64 sin tipo lógico de Parquet: sin esto llegarían como enteros sin unidad). Un
/// esquema ilegible no es un error: el archivo se lee igual, en UTC y sin durations.
#[allow(clippy::type_complexity)]
fn arrow_schema(b64: &str) -> (std::collections::HashMap<String, String>, std::collections::HashMap<String, i64>) {
    // Arrow: Message.header_type Schema = 1; Type Timestamp = 10, Duration = 18;
    // TimeUnit SECOND = 0, MILLISECOND = 1 (el default de Duration), MICROSECOND = 2, NANOSECOND = 3.
    const SCHEMA: u8 = 1;
    const TIMESTAMP: u8 = 10;
    const DURATION: u8 = 18;
    let mut out = std::collections::HashMap::new();
    let mut durs = std::collections::HashMap::new();
    let Ok(raw) = synsema_core::bytesutil::b64_decode(b64.trim()) else { return (out, durs) };
    // Mensaje encapsulado: [0xFFFFFFFF] + largo (i32) + flatbuffer (el formato viejo no trae la marca).
    let mut p = if raw.get(..4) == Some(&[0xff; 4][..]) { 4 } else { 0 };
    let msg = match raw.get(p..p + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) {
        Some(n) if raw.len() >= p + 4 + n && n > 0 => {
            p += 4;
            &raw[p..p + n]
        }
        _ => &raw[..],
    };
    let fb = Fb(msg);
    let _ = (|| -> Option<()> {
        let root = fb.deref(0)?;
        if fb.byte(root, 1)? != SCHEMA {
            return None;
        }
        let schema = fb.table(root, 2)?;
        let (start, n) = fb.vector(schema, 1)?;
        for k in 0..n.min(100_000) {
            let f = fb.deref(start + 4 * k)?;
            match fb.byte(f, 2) {
                Some(TIMESTAMP) => {
                    if let (Some(name), Some(tz)) = (fb.string(f, 0), fb.table(f, 3).and_then(|ts| fb.string(ts, 1))) {
                        out.insert(name.to_string(), tz.to_string());
                    }
                }
                Some(DURATION) => {
                    let per = match fb.table(f, 3).and_then(|d| fb.short(d, 0)).unwrap_or(1) {
                        0 => 1_000_000_000,
                        1 => 1_000_000,
                        2 => 1_000,
                        3 => 1,
                        _ => continue,
                    };
                    if let Some(name) = fb.string(f, 0) {
                        durs.insert(name.to_string(), per);
                    }
                }
                _ => {}
            }
        }
        Some(())
    })();
    (out, durs)
}

/// Una duration de `n` unidades de `per` nanosegundos; `None` si no entra en una duration.
fn duration_of(n: i64, per: i64) -> Option<SynValue> {
    let d = match per {
        1 => chrono::Duration::nanoseconds(n),
        1_000 => chrono::Duration::microseconds(n),
        1_000_000 => chrono::Duration::try_milliseconds(n)?,
        _ => chrono::Duration::try_seconds(n)?,
    };
    Some(SynValue::Time(synsema_core::types::Obj::new(Temporal::Duration(d))))
}

/// La zona de un esquema Arrow como zona de Synsema: un nombre IANA (`Europe/Madrid`), `UTC`/`Z`
/// o un offset fijo (`+05:30`, que se conserva como offset, igual que en Arrow y pandas). Una
/// zona que no se entiende no rompe la lectura: el instante es exacto y queda en UTC.
fn arrow_zone(tz: &str) -> Option<synsema_core::temporal::Zone> {
    synsema_core::temporal::tz_of(tz.trim(), "parquet_read").ok()
}

/// Una hora del día (`TIME` de Parquet) como `duration` desde medianoche.
fn time_of_day(d: chrono::Duration) -> SynValue {
    SynValue::Time(synsema_core::types::Obj::new(Temporal::Duration(d)))
}

// =========================================================
// Topes de expansión (un archivo chico no puede pedir gigas)
// =========================================================

/// Tope por página descomprimida (un writer normal usa ~1 MiB; 256 MiB es generoso).
const MAX_PAGE_BYTES: u64 = 256 * 1024 * 1024;
/// Tope por defecto de celdas (filas × columnas) que se materializan; `{"max_cells": n}` lo sube.
const DEFAULT_MAX_CELLS: u64 = 50_000_000;

/// Lector mínimo de Thrift compact: lo justo para leer el encabezado de cada página
/// (`uncompressed_page_size`, `compressed_page_size`) y saltear el resto.
struct Thrift<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Thrift<'a> {
    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn varint(&mut self) -> Option<u64> {
        let mut out = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.byte()?;
            out |= ((b & 0x7f) as u64).checked_shl(shift)?;
            if b & 0x80 == 0 {
                return Some(out);
            }
        }
        None
    }
    fn zigzag(&mut self) -> Option<i64> {
        let v = self.varint()?;
        Some(((v >> 1) as i64) ^ -((v & 1) as i64))
    }
    fn skip(&mut self, ty: u8, depth: u32) -> Option<()> {
        if depth > 32 {
            return None;
        }
        match ty {
            1 | 2 => {}
            3 => {
                self.byte()?;
            }
            4..=6 => {
                self.varint()?;
            }
            7 => {
                self.i = self.i.checked_add(8)?;
            }
            8 => {
                let n = self.varint()? as usize;
                self.i = self.i.checked_add(n)?;
            }
            9 | 10 => {
                let h = self.byte()?;
                let n = if h >> 4 == 15 { self.varint()? } else { (h >> 4) as u64 };
                for _ in 0..n {
                    self.skip(h & 0x0f, depth + 1)?;
                }
            }
            11 => {
                let n = self.varint()?;
                if n > 0 {
                    let kv = self.byte()?;
                    for _ in 0..n {
                        self.skip(kv >> 4, depth + 1)?;
                        self.skip(kv & 0x0f, depth + 1)?;
                    }
                }
            }
            12 => self.skip_struct(depth + 1).map(|_| ())?,
            _ => return None,
        }
        (self.i <= self.b.len()).then_some(())
    }
    /// Recorre un struct; devuelve los i32 de los campos 2 y 3 del nivel de arriba.
    fn skip_struct(&mut self, depth: u32) -> Option<(Option<i64>, Option<i64>)> {
        let (mut f2, mut f3) = (None, None);
        let mut last: i16 = 0;
        loop {
            let h = self.byte()?;
            if h == 0 {
                return Some((f2, f3));
            }
            let ty = h & 0x0f;
            let delta = (h >> 4) as i16;
            let id = if delta == 0 { self.zigzag()? as i16 } else { last.checked_add(delta)? };
            last = id;
            if ty == 5 && (id == 2 || id == 3) && depth == 0 {
                let v = self.zigzag()?;
                if id == 2 { f2 = Some(v) } else { f3 = Some(v) }
            } else {
                self.skip(ty, depth)?;
            }
        }
    }
}

/// Recorre los encabezados de las páginas que se van a leer y rechaza el archivo si una página declara
/// más de `MAX_PAGE_BYTES` descomprimidos o si el total supera `max_total` — antes de que el
/// lector reserve esa memoria (un encabezado que miente pedía 2 GiB por columna y abortaba).
///
/// v0.6.45 (B4) — cuenta sólo los row groups (`rgs`) y las columnas de primer nivel
/// (`cols`) que se van a leer: pedir una columna de un archivo grande no debe fallar por el tamaño
/// de las demás.
///
/// v0.6.46 (C4) — los encabezados se leen por `fetch` (desde el archivo en disco con
/// `parquet_scan`, o una vista de los bytes con `parquet_read`), en una ventana chica que crece si el
/// encabezado no entra: no hace falta el archivo en memoria.
fn check_expansion_of(
    fetch: &Fetch,
    file_len: u64,
    meta: &parquet::file::metadata::ParquetMetaData,
    max_total: u64,
    fname: &str,
    rgs: Option<&[usize]>,
    cols: Option<&std::collections::HashSet<String>>,
) -> Result<(), Control> {
    let mut total: u64 = 0;
    for (ri, rg) in meta.row_groups().iter().enumerate() {
        if rgs.is_some_and(|r| !r.contains(&ri)) {
            continue;
        }
        for col in rg.columns() {
            if let Some(c) = cols {
                let root = col.column_path().parts().first().cloned().unwrap_or_default();
                if !c.contains(&root) {
                    continue;
                }
            }
            let start = col.dictionary_page_offset().unwrap_or(col.data_page_offset()).max(0) as u64;
            let len = col.compressed_size().max(0) as u64;
            let end = start.checked_add(len).filter(|e| *e <= file_len).ok_or_else(|| {
                err(format!("{}: a column chunk points outside the file (corrupt or truncated)", fname))
            })?;
            let mut pos = start;
            while pos < end {
                let ((unc, comp), used) = page_header(fetch, pos, end, fname)?;
                let (unc, comp) = match (unc, comp) {
                    (Some(u), Some(c)) if u >= 0 && c >= 0 => (u as u64, c as u64),
                    _ => return Err(err(format!("{}: a page header has no sizes (corrupt file)", fname))),
                };
                if unc > MAX_PAGE_BYTES {
                    return Err(err(format!(
                        "{}: a page declares {} MiB uncompressed (the limit is {} MiB per page; writers use about 1 MiB) — the file is malformed or hostile, refusing to allocate it",
                        fname,
                        unc / (1024 * 1024),
                        MAX_PAGE_BYTES / (1024 * 1024)
                    )));
                }
                total = total.saturating_add(unc);
                if total > max_total {
                    return Err(err(format!(
                        "{}: the file expands to more than {} bytes uncompressed (max_bytes) — raise it on purpose with {{\"max_bytes\": n}}",
                        fname,
                        max_total
                    )));
                }
                pos = pos
                    .checked_add(used)
                    .and_then(|p| p.checked_add(comp))
                    .ok_or_else(|| err(format!("{}: corrupt page size", fname)))?;
            }
        }
    }
    Ok(())
}

/// El encabezado de la página que empieza en `pos` (sus tamaños descomprimido y comprimido) y
/// cuántos bytes ocupa. Suele tener menos de 1 KiB (más con estadísticas grandes): se lee una
/// ventana de 8 KiB que se duplica, hasta el fin del chunk (`end`), si no entra.
fn page_header(fetch: &Fetch, pos: u64, end: u64, fname: &str) -> Result<((Option<i64>, Option<i64>), u64), Control> {
    let mut win = HEADER_WINDOW.min(end - pos);
    loop {
        let buf = fetch(pos, win as usize)?;
        let mut t = Thrift { b: &buf, i: 0 };
        match t.skip_struct(0) {
            Some(h) => return Ok((h, t.i as u64)),
            // v0.6.46 (ronda 1 de cf1, N5): con tope. Un encabezado que nunca termina de parsear hacía
            // leer el chunk entero a memoria; ninguno de verdad se acerca a esto.
            None if pos + win < end && win < MAX_PAGE_HEADER => win = (win * 2).min(end - pos).min(MAX_PAGE_HEADER),
            None if win >= MAX_PAGE_HEADER => {
                return Err(err(format!("{}: a page header larger than {} MiB (corrupt file)", fname, MAX_PAGE_HEADER >> 20)))
            }
            None => return Err(err(format!("{}: unreadable page header (corrupt file)", fname))),
        }
    }
}

/// Lee `len` bytes desde `start` de la fuente (el archivo o sus bytes).
type Fetch<'a> = dyn Fn(u64, usize) -> Result<bytes::Bytes, Control> + 'a;

/// La ventana inicial con la que se lee el encabezado de una página (ver `check_expansion_of`).
const HEADER_WINDOW: u64 = 8 * 1024;

/// El encabezado de página más grande que se lee (ver `page_header`).
const MAX_PAGE_HEADER: u64 = 16 * 1024 * 1024;

/// Las opciones de `parquet_read` y `parquet_scan`.
struct ReadOpts {
    max_cells: u64,
    max_bytes: Option<u64>,
    columns: Option<Vec<String>>,
    row_groups: Option<Vec<usize>>,
    limit: Option<u64>,
}

#[allow(non_snake_case)]
fn read_opts(opts: Option<&SynValue>, F: &str) -> Result<ReadOpts, Control> {
    // `{"max_cells": n, "max_bytes": n}`: los topes contra un archivo hostil (por defecto 50
    // millones de celdas y max(1 GiB, 64 × el archivo) descomprimidos). v0.6.45 (B4): `columns`
    // (sólo esas), `row_groups` (sólo esos, por índice) y `limit` (las primeras n filas). Un data
    // lake real no entra en memoria: se lee por partes.
    let (mut max_cells, mut max_bytes_opt) = (DEFAULT_MAX_CELLS, None::<u64>);
    let mut columns: Option<Vec<String>> = None;
    let mut row_groups: Option<Vec<usize>> = None;
    let mut limit: Option<u64> = None;
    match opts {
        None | Some(SynValue::Nothing) => {}
        Some(SynValue::Map(m)) => {
            for (k, v) in m.borrow().iter() {
                match k.as_str() {
                    "columns" => columns = Some(text_list(v, F, "columns")?),
                    "row_groups" => {
                        row_groups = Some(
                            int_list(v, F, "row_groups")?.into_iter().map(|n| n as usize).collect(),
                        )
                    }
                    _ => {
                        let n = match v {
                            SynValue::Number(Number::Int(n)) if *n > 0 => *n as u64,
                            other => return Err(err(format!("{}: option {:?} must be a positive integer, got {}", F, k, other))),
                        };
                        match k.as_str() {
                            "max_cells" => max_cells = n,
                            "max_bytes" => max_bytes_opt = Some(n),
                            "limit" => limit = Some(n),
                            other => {
                                return Err(err(format!(
                                    "{}: unknown option {:?} (valid: columns, row_groups, limit, max_cells, max_bytes)",
                                    F, other
                                )))
                            }
                        }
                    }
                }
            }
        }
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name()))),
    }
    Ok(ReadOpts { max_cells, max_bytes: max_bytes_opt, columns, row_groups, limit })
}

fn parquet_read(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "parquet_read";
    let o = read_opts(args.get(1), F)?;
    let data = match args.first() {
        Some(SynValue::Bytes(b)) => b.to_vec(),
        Some(other) => {
            return Err(err(format!(
                "{}: expected the file's bytes (read_file_bytes(path)), got {} — to read a file from disk without loading it, parquet_scan(path)",
                F,
                other.type_name()
            )))
        }
        None => return Err(err("parquet_read(bytes)")),
    };
    // v0.6.45 (B4): una sola copia de la entrada (antes `data.clone()` hacía dos); `Bytes` se
    // comparte por referencia entre el lector y el chequeo de expansión.
    read_bytes(bytes::Bytes::from(data), o, F)
}

/// Una tabla desde sus bytes en memoria (`parquet_read`, o un archivo del bundle).
#[allow(non_snake_case)]
fn read_bytes(data: bytes::Bytes, o: ReadOpts, F: &str) -> Result<SynValue, Control> {
    let len = data.len() as u64;
    let view = data.clone();
    let fetch = move |start: u64, n: usize| -> Result<bytes::Bytes, Control> {
        let s = start as usize;
        Ok(view.slice(s..s.saturating_add(n).min(view.len())))
    };
    read_table(data, &fetch, len, o, F)
}

/// v0.6.46 (C4) — `parquet_scan(path, opts?)`: la tabla desde el archivo EN DISCO, sin cargarlo. El
/// lector pide sólo lo que necesita (el pie con los metadatos, y de las columnas y row groups que se
/// leen, sus páginas), así un archivo de gigas con una columna pedida lee esa columna. Las mismas
/// opciones y topes que `parquet_read`. Pide `file.read` sobre la ruta y abre como `read_file`
/// (chequeo y apertura en un paso); un archivo del bundle se lee de memoria. Es una entrada del
/// linaje: la ruta y el sha256 de las filas devueltas (como `canonical_json`).
fn parquet_scan(caps: &Rc<std::cell::RefCell<synsema_capabilities::model::CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "parquet_scan";
    let raw = match args.first() {
        Some(SynValue::Text(t)) => t.to_string(),
        Some(other) => {
            return Err(err(format!(
                "{}: expected a path, got {} — for bytes already in memory, parquet_read(bytes)",
                F,
                other.type_name()
            )))
        }
        None => return Err(err("parquet_scan(path)")),
    };
    let o = read_opts(args.get(1), F)?;
    match synsema_capabilities::secure::open_for_read(caps, &raw, "parquet_scan()")? {
        synsema_capabilities::secure::OpenedForRead::Bundled(_, b) => read_bytes(bytes::Bytes::from_static(b), o, F),
        synsema_capabilities::secure::OpenedForRead::Disk(path, file) => {
            let io = |e: std::io::Error| err(format!("{}: cannot read {}: {}", F, path, e));
            let len = file.metadata().map_err(io)?.len();
            let probe = file.try_clone().map_err(io)?;
            let fetch = move |start: u64, n: usize| -> Result<bytes::Bytes, Control> {
                use parquet::file::reader::ChunkReader;
                probe.get_bytes(start, n).map_err(|e| err(format!("{}: {}", F, e)))
            };
            read_table(file, &fetch, len, o, F)
        }
    }
}

#[allow(non_snake_case)]
fn read_table<R: parquet::file::reader::ChunkReader + 'static>(
    src: R,
    fetch: &Fetch,
    file_len: u64,
    o: ReadOpts,
    F: &str,
) -> Result<SynValue, Control> {
    let ReadOpts { max_cells, max_bytes: max_bytes_opt, columns, row_groups, limit } = o;
    let reader = SerializedFileReader::new(src).map_err(|e| err(format!("{}: not a Parquet file: {}", F, e)))?;
    let max_bytes = max_bytes_opt.unwrap_or_else(|| (1024 * 1024 * 1024u64).max(file_len.saturating_mul(64)));
    let meta = reader.metadata();
    let all_cols: Vec<String> = meta.file_metadata().schema_descr().root_schema().get_fields().iter().map(|f| f.name().to_string()).collect();
    if let Some(cs) = &columns {
        for c in cs {
            if !all_cols.contains(c) {
                return Err(err(format!("{}: the file has no column {:?} (columns: {})", F, c, all_cols.join(", "))));
            }
        }
    }
    let n_rgs = meta.num_row_groups();
    if let Some(rs) = &row_groups {
        for &r in rs {
            if r >= n_rgs {
                return Err(err(format!("{}: row group {} does not exist (the file has {}: 0..{})", F, r, n_rgs, n_rgs)));
            }
        }
    }
    let col_set: Option<std::collections::HashSet<String>> = columns.as_ref().map(|c| c.iter().cloned().collect());
    check_expansion_of(fetch, file_len, meta, max_bytes, F, row_groups.as_deref(), col_set.as_ref())?;
    let rows_selected: u64 = match &row_groups {
        Some(rs) => rs.iter().map(|&r| meta.row_group(r).num_rows().max(0) as u64).sum(),
        None => meta.file_metadata().num_rows().max(0) as u64,
    };
    let cols_selected = columns.as_ref().map(|c| c.len()).unwrap_or(all_cols.len()) as u64;
    let cells = rows_selected.min(limit.unwrap_or(u64::MAX)).saturating_mul(cols_selected);
    if cells > max_cells {
        return Err(err(format!(
            "{}: the file has {} cells (rows × columns); the limit is {} — raise it on purpose with {{\"max_cells\": n}}",
            F, cells, max_cells
        )));
    }
    // Columnas TIMESTAMP en nanosegundos: el lector por filas del crate las entrega como un
    // entero; acá se convierten. Y la zona de cada columna, si la escribió `parquet_write`.
    let fmeta = reader.metadata().file_metadata();
    // Dos columnas con el mismo nombre darían un mapa que pierde una en silencio.
    let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for f in fmeta.schema_descr().root_schema().get_fields() {
        if !names.insert(f.name()) {
            return Err(err(format!(
                "{}: the file has two columns named {:?} — a row is a map and would lose one; rename it where the file is written",
                F,
                f.name()
            )));
        }
    }
    let mut nanos: std::collections::HashSet<String> = std::collections::HashSet::new();
    // TIME en nanosegundos (polars): el lector por filas también la entrega como un entero.
    let mut time_nanos: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in fmeta.schema_descr().columns() {
        match c.logical_type_ref() {
            Some(LogicalType::Timestamp(ts)) if ts.unit == TimeUnit::NANOS => {
                nanos.insert(c.name().to_string());
            }
            Some(LogicalType::Time(t)) if t.unit == TimeUnit::NANOS => {
                time_nanos.insert(c.name().to_string());
            }
            _ => {}
        }
    }
    let mut zones: std::collections::HashMap<String, synsema_core::temporal::Zone> = std::collections::HashMap::new();
    // Columnas INT64 que son durations: `columna → nanosegundos por unidad`.
    let mut durs: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if let Some(kvs) = fmeta.key_value_metadata() {
        // Primero la zona del esquema Arrow (polars, pyarrow); la nuestra, si está, manda.
        for kv in kvs.iter().filter(|kv| kv.key == ARROW_KEY) {
            let (tzs, ds) = arrow_schema(kv.value.as_deref().unwrap_or(""));
            for (col, z) in tzs {
                if let Some(tz) = arrow_zone(&z) {
                    zones.insert(col, tz);
                }
            }
            durs.extend(ds);
        }
        for kv in kvs.iter().filter(|kv| kv.key == DUR_KEY) {
            if let Some(Ok(serde_json::Value::Object(o))) = kv.value.as_deref().map(serde_json::from_str::<serde_json::Value>) {
                for (col, u) in o {
                    match u.as_str() {
                        Some("ns") => durs.insert(col, 1),
                        Some("us") => durs.insert(col, 1_000),
                        _ => None,
                    };
                }
            }
        }
        // Sólo cuentan las columnas INT64 de primer nivel sin tipo lógico: un metadato que diga
        // otra cosa de una columna de texto o de timestamps no la reinterpreta.
        let plain_i64: std::collections::HashSet<String> = fmeta
            .schema_descr()
            .columns()
            .iter()
            .filter(|c| c.physical_type() == PhysicalType::INT64 && c.logical_type_ref().is_none() && c.path().parts().len() == 1)
            .map(|c| c.name().to_string())
            .collect();
        durs.retain(|c, _| plain_i64.contains(c));
        for kv in kvs {
            if kv.key == TZ_KEY {
                if let Some(Ok(serde_json::Value::Object(o))) = kv.value.as_deref().map(serde_json::from_str::<serde_json::Value>) {
                    for (col, z) in o {
                        if let Some(tz) = z.as_str().and_then(arrow_zone) {
                            zones.insert(col, tz);
                        }
                    }
                }
            }
        }
    }
    // La proyección: el esquema con sólo las columnas pedidas, en el orden del archivo.
    let projection = match &columns {
        None => None,
        Some(cs) => {
            let fields: Vec<_> = fmeta
                .schema_descr()
                .root_schema()
                .get_fields()
                .iter()
                .filter(|f| cs.iter().any(|c| c == f.name()))
                .cloned()
                .collect();
            Some(
                parquet::schema::types::Type::group_type_builder(fmeta.schema_descr().root_schema().name())
                    .with_fields(fields)
                    .build()
                    .map_err(|e| err(format!("{}: {}", F, e)))?,
            )
        }
    };
    // Las columnas como claves una vez por lectura: cada fila suma una referencia (F4.4).
    let convert = |row: parquet::record::Row, keys: &mut Vec<Key>| -> Result<SynValue, Control> {
        let mut m = SynMap::with_capacity(keys.len());
        for (ci, (k, v)) in row.get_column_iter().enumerate() {
            let mut val = match (v, nanos.contains(k)) {
                (Field::Long(ns), true) => {
                    let (secs, sub) = (ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32);
                    match chrono::DateTime::from_timestamp(secs, sub) {
                        Some(dt) => SynValue::Time(synsema_core::types::Obj::new(Temporal::DateTime(dt.with_timezone(&synsema_core::temporal::UTC)))),
                        None => SynValue::Nothing,
                    }
                }
                (Field::Long(ns), false) if time_nanos.contains(k) => time_of_day(chrono::Duration::nanoseconds(*ns)),
                (Field::Long(n), false) if durs.contains_key(k) => duration_of(*n, durs[k]).ok_or_else(|| {
                    err(format!("{}: column {:?}: {} is out of the range of a duration", F, k, n))
                })?,
                _ => field_to_syn(v),
            };
            if let (Some(tz), SynValue::Time(t)) = (zones.get(k), &val) {
                if let Temporal::DateTime(dt) = &**t {
                    val = SynValue::Time(synsema_core::types::Obj::new(Temporal::DateTime(dt.with_timezone(tz))));
                }
            }
            if keys.len() <= ci {
                keys.push(Key::from(k));
            } else if keys[ci].as_str() != k.as_str() {
                keys[ci] = Key::from(k);
            }
            m.insert(keys[ci].clone(), val);
        }
        Ok(syn_map(m))
    };
    let cap = limit.unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let mut keys: Vec<Key> = Vec::new();
    match &row_groups {
        None => {
            for row in reader.get_row_iter(projection.clone()).map_err(|e| err(format!("{}: {}", F, e)))? {
                if out.len() as u64 >= cap {
                    break;
                }
                let row = row.map_err(|e| err(format!("{}: {}", F, e)))?;
                out.push(convert(row, &mut keys)?);
            }
        }
        Some(rs) => {
            'groups: for &r in rs {
                let rg = reader.get_row_group(r).map_err(|e| err(format!("{}: {}", F, e)))?;
                for row in rg.get_row_iter(projection.clone()).map_err(|e| err(format!("{}: {}", F, e)))? {
                    if out.len() as u64 >= cap {
                        break 'groups;
                    }
                    let row = row.map_err(|e| err(format!("{}: {}", F, e)))?;
                    out.push(convert(row, &mut keys)?);
                }
            }
        }
    }
    Ok(syn_list(out))
}

// =========================================================
// Escritura
// =========================================================

#[derive(Clone, Copy, PartialEq, Debug)]
enum ColKind {
    Int,
    Float,
    Decimal(u32),
    Text,
    Bool,
    Bytes,
    Date,
    DateTime,
    Duration,
}

fn kind_of(v: &SynValue, col: &str) -> Result<Option<ColKind>, Control> {
    Ok(Some(match v {
        SynValue::Nothing => return Ok(None),
        SynValue::Number(Number::Int(_)) => ColKind::Int,
        SynValue::Number(Number::Big(_)) => {
            return Err(err(format!(
                "parquet_write: column {:?} has an integer beyond 64 bits — store it as text (text(x)) or decimal",
                col
            )))
        }
        SynValue::Number(Number::Float(_)) => ColKind::Float,
        SynValue::Number(n @ (Number::Decimal(_) | Number::BigDec(_))) => ColKind::Decimal(n.exact_ratio().unwrap().1),
        SynValue::Text(_) => ColKind::Text,
        SynValue::Bool(_) => ColKind::Bool,
        SynValue::Bytes(_) => ColKind::Bytes,
        SynValue::Time(t) => match &**t {
            Temporal::Date(_) => ColKind::Date,
            Temporal::DateTime(_) => ColKind::DateTime,
            Temporal::Duration(_) => ColKind::Duration,
        },
        other => {
            return Err(err(format!(
                "parquet_write: column {:?} has a {} — a Parquet column holds scalars; json_encode(x) nested values first",
                col,
                other.type_name()
            )))
        }
    }))
}

/// Un valor de un flatbuffer a escribir: lo justo para el esquema Arrow.
enum Fv {
    U8(u8),
    I16(i16),
    I32(i32),
    I64(i64),
    Str(String),
    /// Una tabla: sus campos por índice (`None` = ausente).
    Table(Vec<Option<Fv>>),
    /// Un vector de tablas o strings.
    Vec(Vec<Fv>),
}

/// Escritor mínimo de flatbuffers, hacia adelante: cada tabla va después de su vtable y cada
/// referencia apunta a algo escrito después (los uoffset son positivos). Todo queda alineado a
/// su tamaño desde el principio del buffer, como pide el verificador de flatbuffers (Arrow C++
/// verifica el esquema antes de leerlo).
#[derive(Default)]
struct FbWriter(Vec<u8>);

impl FbWriter {
    fn align(&mut self, n: usize) {
        while self.0.len() % n != 0 {
            self.0.push(0);
        }
    }
    fn patch(&mut self, at: usize, target: usize) {
        self.0[at..at + 4].copy_from_slice(&((target - at) as u32).to_le_bytes());
    }
    /// Escribe `v` (una tabla, un string o un vector) y devuelve su posición.
    fn write(&mut self, v: &Fv) -> usize {
        match v {
            Fv::Str(t) => {
                self.align(4);
                let at = self.0.len();
                self.0.extend_from_slice(&(t.len() as u32).to_le_bytes());
                self.0.extend_from_slice(t.as_bytes());
                self.0.push(0);
                at
            }
            Fv::Vec(items) => {
                self.align(4);
                let at = self.0.len();
                self.0.extend_from_slice(&(items.len() as u32).to_le_bytes());
                let slots: Vec<usize> = items
                    .iter()
                    .map(|_| {
                        self.0.extend_from_slice(&[0; 4]);
                        self.0.len() - 4
                    })
                    .collect();
                for (slot, item) in slots.into_iter().zip(items) {
                    let target = self.write(item);
                    self.patch(slot, target);
                }
                at
            }
            Fv::Table(fields) => {
                // La vtable: tamaño de la vtable, tamaño de la tabla y el offset de cada campo.
                self.align(4);
                let vt = self.0.len();
                self.0.resize(vt + 4 + 2 * fields.len(), 0);
                self.align(8);
                let t = self.0.len();
                self.0.extend_from_slice(&((t - vt) as i32).to_le_bytes());
                let mut refs = Vec::new();
                for (i, f) in fields.iter().enumerate() {
                    let Some(f) = f else { continue };
                    let size = match f {
                        Fv::U8(_) => 1,
                        Fv::I16(_) => 2,
                        Fv::I64(_) => 8,
                        _ => 4,
                    };
                    self.align(size);
                    let at = self.0.len();
                    match f {
                        Fv::U8(x) => self.0.push(*x),
                        Fv::I16(x) => self.0.extend_from_slice(&x.to_le_bytes()),
                        Fv::I32(x) => self.0.extend_from_slice(&x.to_le_bytes()),
                        Fv::I64(x) => self.0.extend_from_slice(&x.to_le_bytes()),
                        other => {
                            self.0.extend_from_slice(&[0; 4]);
                            refs.push((at, other));
                        }
                    }
                    self.0[vt + 4 + 2 * i..vt + 6 + 2 * i].copy_from_slice(&((at - t) as u16).to_le_bytes());
                }
                let tsize = self.0.len() - t;
                self.0[vt..vt + 2].copy_from_slice(&((4 + 2 * fields.len()) as u16).to_le_bytes());
                self.0[vt + 2..vt + 4].copy_from_slice(&(tsize as u16).to_le_bytes());
                for (at, child) in refs {
                    let target = self.write(child);
                    self.patch(at, target);
                }
                t
            }
            Fv::U8(_) | Fv::I16(_) | Fv::I32(_) | Fv::I64(_) => unreachable!("un escalar va dentro de una tabla"),
        }
    }
}

/// El tipo Arrow de una columna, como lo escriben pyarrow, polars y arrow-rs.
fn arrow_type(k: ColKind, nanos: bool, zone: &str) -> (u8, Fv) {
    // Unidades de tiempo: MICROSECOND = 2, NANOSECOND = 3.
    let unit = Fv::I16(if nanos { 3 } else { 2 });
    match k {
        ColKind::Int => (2, Fv::Table(vec![Some(Fv::I32(64)), Some(Fv::U8(1))])),
        ColKind::Float => (3, Fv::Table(vec![Some(Fv::I16(2))])),
        ColKind::Bytes => (4, Fv::Table(vec![])),
        ColKind::Text => (5, Fv::Table(vec![])),
        ColKind::Bool => (6, Fv::Table(vec![])),
        ColKind::Decimal(sc) => (7, Fv::Table(vec![Some(Fv::I32(38)), Some(Fv::I32(sc as i32)), Some(Fv::I32(128))])),
        // DateUnit DAY = 0 (el default del esquema es MILLISECOND: va explícito).
        ColKind::Date => (8, Fv::Table(vec![Some(Fv::I16(0))])),
        ColKind::DateTime => (10, Fv::Table(vec![Some(unit), Some(Fv::Str(zone.to_string()))])),
        ColKind::Duration => (18, Fv::Table(vec![Some(unit)])),
    }
}

/// El esquema Arrow del archivo (`ARROW:schema`): un mensaje IPC `Schema` en base64. Con él,
/// pyarrow, pandas y polars leen cada columna con su tipo: una `duration` como duration (sin
/// él, un INT64 sin unidad) y un `datetime` con su zona (sin él, UTC).
fn arrow_schema_b64(cols: &[(String, ColKind, bool, String)]) -> String {
    let fields = cols
        .iter()
        .map(|(name, k, nanos, zone)| {
            let (type_type, ty) = arrow_type(*k, *nanos, zone);
            // Field: name, nullable, type_type, type, dictionary, children (vacío, pero presente:
            // Arrow C++ lo exige).
            Fv::Table(vec![Some(Fv::Str(name.clone())), Some(Fv::U8(1)), Some(Fv::U8(type_type)), Some(ty), None, Some(Fv::Vec(vec![]))])
        })
        .collect();
    // Schema: endianness (Little = 0), fields. Message: version (V5 = 4), header_type
    // (Schema = 1), header, bodyLength (0).
    let schema = Fv::Table(vec![Some(Fv::I16(0)), Some(Fv::Vec(fields))]);
    let message = Fv::Table(vec![Some(Fv::I16(4)), Some(Fv::U8(1)), Some(schema), Some(Fv::I64(0))]);
    let mut w = FbWriter::default();
    w.0.extend_from_slice(&[0; 8]); // offset a la raíz + relleno: la raíz queda alineada a 8
    let root = w.write(&message);
    w.patch(0, root);
    w.align(8);
    // Mensaje encapsulado: marca de continuación, largo, flatbuffer.
    let mut out = vec![0xff; 4];
    out.extend_from_slice(&(w.0.len() as u32).to_le_bytes());
    out.extend_from_slice(&w.0);
    synsema_core::bytesutil::b64_encode(&out)
}

/// Una columna con nanosegundos y un valor que no entra en nanosegundos: en microsegundos se
/// perderían en silencio (pyarrow también lo rechaza).
fn lost_nanos(col: &str, what: &str, range: &str) -> Control {
    err(format!(
        "parquet_write: column {:?} has {} with nanoseconds and one {} — one unit per column, and nanoseconds do not reach that far, so they would be lost — put the far values in another column, or store this one as text (text(x) keeps every digit)",
        col, what, range
    ))
}

fn merge_kind(a: ColKind, b: ColKind, col: &str) -> Result<ColKind, Control> {
    use ColKind::*;
    Ok(match (a, b) {
        (x, y) if x == y => x,
        (Int, Float) | (Float, Int) => Float,
        (Decimal(s), Decimal(t)) => Decimal(s.max(t)),
        (Decimal(s), Int) | (Int, Decimal(s)) => Decimal(s),
        (x, y) => {
            return Err(err(format!(
                "parquet_write: column {:?} mixes {:?} and {:?} — one type per column",
                col, x, y
            )))
        }
    })
}

fn build_type(name: &str, k: ColKind, nanos: bool) -> Result<Type, Control> {
    let b = match k {
        ColKind::Int => Type::primitive_type_builder(name, PhysicalType::INT64),
        ColKind::Float => Type::primitive_type_builder(name, PhysicalType::DOUBLE),
        ColKind::Decimal(s) => Type::primitive_type_builder(name, PhysicalType::BYTE_ARRAY)
            .with_logical_type(Some(LogicalType::decimal(s as i32, 38)))
            .with_precision(38)
            .with_scale(s as i32),
        ColKind::Text => Type::primitive_type_builder(name, PhysicalType::BYTE_ARRAY).with_logical_type(Some(LogicalType::String)),
        ColKind::Bool => Type::primitive_type_builder(name, PhysicalType::BOOLEAN),
        ColKind::Bytes => Type::primitive_type_builder(name, PhysicalType::BYTE_ARRAY),
        ColKind::Date => Type::primitive_type_builder(name, PhysicalType::INT32).with_logical_type(Some(LogicalType::Date)),
        // Como Arrow: INT64 sin tipo lógico; la unidad va en `synsema.durations`.
        ColKind::Duration => Type::primitive_type_builder(name, PhysicalType::INT64),
        ColKind::DateTime => Type::primitive_type_builder(name, PhysicalType::INT64).with_logical_type(Some(LogicalType::timestamp(
            true,
            if nanos { TimeUnit::NANOS } else { TimeUnit::MICROS },
        ))),
    };
    b.with_repetition(Repetition::OPTIONAL).build().map_err(|e| err(format!("parquet_write: column {:?}: {}", name, e)))
}

/// El valor sin escala de un decimal (o entero) en la escala `scale` de la columna, en bytes
/// big-endian con signo (el formato de Parquet). `None` si perdería dígitos o pasa de 38.
fn decimal_bytes(n: &Number, scale: u32) -> Option<Vec<u8>> {
    let (m, s) = n.exact_ratio()?;
    if s > scale {
        return None;
    }
    let unscaled = m * synsema_core::number::pow10_big(scale - s);
    if unscaled.magnitude().to_string().len() > 38 {
        return None;
    }
    Some(unscaled.to_signed_bytes_be())
}

fn parquet_write(args: &[SynValue]) -> Result<SynValue, Control> {
    use parquet::column::writer::ColumnWriter;
    const F: &str = "parquet_write";
    let rows = match args.first() {
        Some(SynValue::List(l)) => l.borrow().to_vec(),
        Some(other) => return Err(err(format!("{}: expected a list of rows (maps), got {}", F, other.type_name()))),
        None => return Err(err("parquet_write(rows, opts?)")),
    };
    let compression = match args.get(1) {
        None | Some(SynValue::Nothing) => Compression::SNAPPY,
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for k in m.keys() {
                if k != "compression" {
                    return Err(err(format!("{}: unknown option {:?} (valid: compression)", F, k)));
                }
            }
            match m.get("compression") {
                None => Compression::SNAPPY,
                Some(SynValue::Text(t)) => match t.as_ref() {
                    "snappy" => Compression::SNAPPY,
                    "zstd" => Compression::ZSTD(Default::default()),
                    "gzip" => Compression::GZIP(Default::default()),
                    "lz4" => Compression::LZ4_RAW,
                    "none" => Compression::UNCOMPRESSED,
                    other => return Err(err(format!("{}: compression {:?} (use snappy, zstd, gzip, lz4 or none)", F, other))),
                },
                Some(other) => return Err(err(format!("{}: compression must be text, got {}", F, other.type_name()))),
            }
        }
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name()))),
    };
    // Columnas: unión de claves en orden de aparición; tipo por columna.
    let mut cols: IndexMap<String, Option<ColKind>> = IndexMap::new();
    let mut maps = Vec::with_capacity(rows.len());
    for (i, r) in rows.iter().enumerate() {
        let m = match r {
            SynValue::Map(m) => m.borrow().to_map(),
            other => return Err(err(format!("{}: row {} is a {}, every row must be a map", F, i + 1, other.type_name()))),
        };
        for (k, v) in &m {
            let k2 = kind_of(v, k)?;
            let entry = cols.entry(k.to_string()).or_insert(None);
            *entry = match (*entry, k2) {
                (None, x) => x,
                (Some(a), None) => Some(a),
                (Some(a), Some(b)) => Some(merge_kind(a, b, k)?),
            };
        }
        maps.push(m);
    }
    // Una columna que mezcla enteros y floats se escribe DOUBLE: un entero más allá de 2^53 no
    // entra exacto en un float y se redondearía en silencio.
    for (name, k) in &cols {
        if *k != Some(ColKind::Float) {
            continue;
        }
        for (i, m) in maps.iter().enumerate() {
            if let Some(SynValue::Number(Number::Int(n))) = m.get(name) {
                if n.unsigned_abs() > 1u64 << 53 {
                    return Err(err(format!(
                        "{}: column {:?}, row {}: the integer {} does not fit a float exactly, and the column mixes integers and floats (it is written as DOUBLE) — convert the column to decimal or to text",
                        F,
                        name,
                        i + 1,
                        n
                    )));
                }
            }
        }
    }
    let mut fields = Vec::with_capacity(cols.len());
    let mut ns_cols: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut durs = serde_json::Map::new();
    // Por columna: (nombre, tipo, en nanosegundos) para el esquema Arrow.
    let mut arrow_cols: Vec<(String, ColKind, bool, String)> = Vec::with_capacity(cols.len());
    for (name, k) in &cols {
        // Una columna toda `nothing` se escribe como texto opcional (todo nulo).
        // Una columna de datetimes va en microsegundos (lo más compatible, 290 000 años de
        // rango) salvo que algún valor tenga nanosegundos: entonces en NANOS (como polars),
        // para que la ida y vuelta no los pierda — si todos entran en su rango (1677–2262).
        let nanos = *k == Some(ColKind::DateTime) && {
            let vals = maps.iter().filter_map(|m| match m.get(name) {
                Some(SynValue::Time(t)) => match &**t {
                    Temporal::DateTime(dt) => Some(dt.clone()),
                    _ => None,
                },
                _ => None,
            });
            let mut any_sub_micro = false;
            let mut all_fit = true;
            for dt in vals {
                if dt.timestamp_subsec_nanos() % 1000 != 0 {
                    any_sub_micro = true;
                }
                if dt.timestamp_nanos_opt().is_none() {
                    all_fit = false;
                }
            }
            if any_sub_micro && !all_fit {
                return Err(lost_nanos(name, "a datetime", "outside 1677-2262"));
            }
            any_sub_micro
        };
        // Una columna de durations: en microsegundos (±292 000 años) salvo que algún valor tenga
        // nanosegundos y todos entren en nanosegundos (±292 años), como los datetimes.
        let dur_nanos = *k == Some(ColKind::Duration) && {
            let (mut any_sub_micro, mut all_fit) = (false, true);
            for m in &maps {
                if let Some(SynValue::Time(t)) = m.get(name) {
                    if let Temporal::Duration(d) = &**t {
                        any_sub_micro |= d.subsec_nanos() % 1000 != 0;
                        all_fit &= d.num_nanoseconds().is_some();
                    }
                }
            }
            if any_sub_micro && !all_fit {
                return Err(lost_nanos(name, "a duration", "beyond ±292 years"));
            }
            any_sub_micro
        };
        if *k == Some(ColKind::Duration) {
            durs.insert(name.clone(), serde_json::Value::String(if dur_nanos { "ns" } else { "us" }.to_string()));
        }
        if nanos || dur_nanos {
            ns_cols.insert(name.clone());
        }
        arrow_cols.push((name.clone(), k.unwrap_or(ColKind::Text), nanos || dur_nanos, "UTC".to_string()));
        fields.push(Arc::new(build_type(name, k.unwrap_or(ColKind::Text), nanos)?));
    }
    let schema = Arc::new(
        Type::group_type_builder("schema").with_fields(fields).build().map_err(|e| err(format!("{}: {}", F, e)))?,
    );
    // La zona de cada columna de datetimes (si todos sus valores comparten una): Parquet guarda
    // el instante en UTC; la zona viaja en los metadatos y `parquet_read` la devuelve.
    let mut tzs = serde_json::Map::new();
    for (name, k) in &cols {
        if *k != Some(ColKind::DateTime) {
            continue;
        }
        let mut zone: Option<String> = None;
        let mut same = true;
        for m in &maps {
            if let Some(SynValue::Time(t)) = m.get(name) {
                if let Temporal::DateTime(dt) = &**t {
                    let z = dt.timezone().name().to_string();
                    match &zone {
                        None => zone = Some(z),
                        Some(prev) if *prev != z => same = false,
                        _ => {}
                    }
                }
            }
        }
        if let (true, Some(z)) = (same, zone) {
            if z != "UTC" {
                // En el esquema Arrow sólo una zona IANA: polars no acepta un offset fijo
                // (`+05:30`) y no abre el archivo. Con un offset, los demás ven el instante en
                // UTC y Synsema recupera el offset de `synsema.timezones`.
                if let (Some(c), true) = (arrow_cols.iter_mut().find(|c| c.0 == *name), z.contains('/')) {
                    c.3 = z.clone();
                }
                tzs.insert(name.clone(), serde_json::Value::String(z));
            }
        }
    }
    let mut pb = WriterProperties::builder().set_compression(compression);
    let mut kvs = vec![parquet::file::metadata::KeyValue::new(ARROW_KEY.to_string(), arrow_schema_b64(&arrow_cols))];
    if !tzs.is_empty() {
        kvs.push(parquet::file::metadata::KeyValue::new(TZ_KEY.to_string(), serde_json::Value::Object(tzs).to_string()));
    }
    if !durs.is_empty() {
        kvs.push(parquet::file::metadata::KeyValue::new(DUR_KEY.to_string(), serde_json::Value::Object(durs).to_string()));
    }
    pb = pb.set_key_value_metadata(Some(kvs));
    let props = Arc::new(pb.build());
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = SerializedFileWriter::new(&mut buf, schema, props).map_err(|e| err(format!("{}: {}", F, e)))?;
        let mut rg = w.next_row_group().map_err(|e| err(format!("{}: {}", F, e)))?;
        for (name, k) in &cols {
            let kind = k.unwrap_or(ColKind::Text);
            let vals: Vec<&SynValue> = maps.iter().map(|m| m.get(name).unwrap_or(&SynValue::Nothing)).collect();
            let defs: Vec<i16> = vals.iter().map(|v| if matches!(v, SynValue::Nothing) { 0 } else { 1 }).collect();
            let present = vals.iter().filter(|v| !matches!(v, SynValue::Nothing));
            // Parquet guarda un decimal con precisión 38 como máximo: uno más largo es error, no
            // un valor vacío.
            if let ColKind::Decimal(s) = kind {
                for v in vals.iter() {
                    if let SynValue::Number(n) = v {
                        if decimal_bytes(n, s).is_none() {
                            return Err(err(format!(
                                "{}: column {:?}: the decimal {} does not fit in Parquet's decimal(38, {}) — store the column as text (text(x))",
                                F, name, n, s
                            )));
                        }
                    }
                }
            }
            let mut col = rg
                .next_column()
                .map_err(|e| err(format!("{}: {}", F, e)))?
                .ok_or_else(|| err(format!("{}: internal: missing column {:?}", F, name)))?;
            let werr = |e: parquet::errors::ParquetError| err(format!("{}: column {:?}: {}", F, name, e));
            match (col.untyped(), kind) {
                (ColumnWriter::Int64ColumnWriter(cw), ColKind::Int) => {
                    let v: Vec<i64> = present.map(|x| if let SynValue::Number(Number::Int(i)) = x { *i } else { 0 }).collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::DoubleColumnWriter(cw), ColKind::Float) => {
                    let v: Vec<f64> = present.map(|x| if let SynValue::Number(n) = x { n.to_f64() } else { 0.0 }).collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::BoolColumnWriter(cw), ColKind::Bool) => {
                    let v: Vec<bool> = present.map(|x| matches!(x, SynValue::Bool(true))).collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::ByteArrayColumnWriter(cw), ColKind::Text | ColKind::Bytes | ColKind::Decimal(_)) => {
                    let v: Vec<ByteArray> = present
                        .map(|x| match (x, kind) {
                            (SynValue::Text(t), _) => ByteArray::from(t.as_bytes().to_vec()),
                            (SynValue::Bytes(b), _) => ByteArray::from(b.to_vec()),
                            (SynValue::Number(n), ColKind::Decimal(s)) if n.exact_ratio().is_some() => {
                                ByteArray::from(decimal_bytes(n, s).unwrap_or_default())
                            }
                            (other, _) => ByteArray::from(other.to_string().into_bytes()),
                        })
                        .collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::Int32ColumnWriter(cw), ColKind::Date) => {
                    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
                    let v: Vec<i32> = present
                        .map(|x| match x {
                            SynValue::Time(t) => match &**t {
                                Temporal::Date(d) => d.signed_duration_since(epoch).num_days() as i32,
                                _ => 0,
                            },
                            _ => 0,
                        })
                        .collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::Int64ColumnWriter(cw), ColKind::DateTime) => {
                    let ns = ns_cols.contains(name);
                    let v: Vec<i64> = present
                        .map(|x| match x {
                            SynValue::Time(t) => match &**t {
                                Temporal::DateTime(dt) if ns => dt.timestamp_nanos_opt().unwrap_or(0),
                                Temporal::DateTime(dt) => dt.timestamp_micros(),
                                _ => 0,
                            },
                            _ => 0,
                        })
                        .collect();
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                (ColumnWriter::Int64ColumnWriter(cw), ColKind::Duration) => {
                    let ns = ns_cols.contains(name);
                    let mut v: Vec<i64> = Vec::new();
                    for x in present {
                        if let SynValue::Time(t) = x {
                            if let Temporal::Duration(d) = &**t {
                                let n = if ns { d.num_nanoseconds() } else { d.num_microseconds() };
                                v.push(n.ok_or_else(|| {
                                    err(format!("{}: column {:?}: the duration {} does not fit 64-bit microseconds", F, name, x))
                                })?);
                            }
                        }
                    }
                    cw.write_batch(&v, Some(&defs), None).map_err(werr)?;
                }
                _ => return Err(err(format!("{}: internal: writer/type mismatch in column {:?}", F, name))),
            }
            col.close().map_err(|e| err(format!("{}: {}", F, e)))?;
        }
        rg.close().map_err(|e| err(format!("{}: {}", F, e)))?;
        w.close().map_err(|e| err(format!("{}: {}", F, e)))?;
    }
    Ok(syn_bytes(buf))
}

/// v0.6.45 (B4) — `parquet_info(bytes)` → `{rows, columns: [{name, type}], row_groups: [{rows,
/// bytes}]}`: lo que hay en el archivo sin leer los datos, para decidir qué columnas y qué row groups
/// pedir.
fn parquet_info(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "parquet_info";
    let data = match args.first() {
        Some(SynValue::Bytes(b)) => bytes::Bytes::from(b.to_vec()),
        Some(other) => return Err(err(format!("{}: expected the file's bytes (read_file_bytes(path)), got {}", F, other.type_name()))),
        None => return Err(err("parquet_info(bytes)")),
    };
    let reader = SerializedFileReader::new(data).map_err(|e| err(format!("{}: not a Parquet file: {}", F, e)))?;
    let meta = reader.metadata();
    let fmeta = meta.file_metadata();
    let mut cols = Vec::new();
    for f in fmeta.schema_descr().root_schema().get_fields() {
        let mut m = SynMap::new();
        m.insert("name", syn_text(f.name()));
        let ty = if f.is_primitive() {
            match f.get_basic_info().logical_type_ref() {
                Some(lt) => format!("{:?}", lt).to_lowercase(),
                None => format!("{}", f.get_physical_type()).to_lowercase(),
            }
        } else {
            "group".to_string()
        };
        m.insert("type", syn_text(ty));
        cols.push(syn_map(m));
    }
    let mut rgs = Vec::new();
    for rg in meta.row_groups() {
        let mut m = SynMap::new();
        m.insert("rows", syn_int(rg.num_rows()));
        m.insert("bytes", syn_int(rg.total_byte_size()));
        rgs.push(syn_map(m));
    }
    let mut out = SynMap::new();
    out.insert("rows", syn_int(fmeta.num_rows()));
    out.insert("columns", syn_list(cols));
    out.insert("row_groups", syn_list(rgs));
    Ok(syn_map(out))
}

fn text_list(v: &SynValue, f: &str, opt: &str) -> Result<Vec<String>, Control> {
    match v {
        SynValue::List(l) => l
            .borrow()
            .to_vec()
            .iter()
            .map(|x| match x {
                SynValue::Text(t) => Ok(t.to_string()),
                other => Err(err(format!("{}: {} must be a list of column names, got {}", f, opt, other.type_name()))),
            })
            .collect(),
        other => Err(err(format!("{}: {} must be a list, got {}", f, opt, other.type_name()))),
    }
}

fn int_list(v: &SynValue, f: &str, opt: &str) -> Result<Vec<u64>, Control> {
    match v {
        SynValue::List(l) => l
            .borrow()
            .to_vec()
            .iter()
            .map(|x| match x {
                SynValue::Number(Number::Int(n)) if *n >= 0 => Ok(*n as u64),
                other => Err(err(format!("{}: {} must be a list of indexes (0, 1, …), got {}", f, opt, other))),
            })
            .collect(),
        other => Err(err(format!("{}: {} must be a list, got {}", f, opt, other.type_name()))),
    }
}

pub fn register_parquet_builtins(interp: &Interpreter) {
    interp.register_builtin("parquet_info", 1, Rc::new(|_i, a, _l| parquet_info(a)));
    interp.register_builtin("parquet_read", -1, Rc::new(|_i, a, _l| parquet_read(a)));
    interp.register_builtin("parquet_write", -1, Rc::new(|_i, a, _l| parquet_write(a)));
}

/// v0.6.46 (C4) — `parquet_scan` lee del disco: va con las capabilities, en el perfil nativo (como
/// los archivos comprimidos), no en el puro que comparte el wasm.
pub fn register_parquet_scan(interp: &Interpreter, caps: Rc<std::cell::RefCell<synsema_capabilities::model::CapabilitySet>>) {
    interp.register_builtin("parquet_scan", -1, Rc::new(move |_i, a, _l| parquet_scan(&caps, a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.6.46 (C4): un encabezado más grande que la ventana inicial se lee entero (la ventana se
    /// duplica); uno cortado por el fin del chunk es un error, no un tamaño inventado.
    #[test]
    fn a_page_header_larger_than_the_window_is_read_whole() {
        // Thrift compact: campo 1 i32 (tipo 5) = 0, 2 = 1000 (descomprimido), 3 = 500
        // (comprimido), un campo 9 binario (tipo 8) de 20 000 bytes que no se mira, y el fin.
        let zz = |v: i64| -> Vec<u8> {
            let mut u = ((v << 1) ^ (v >> 63)) as u64;
            let mut out = Vec::new();
            loop {
                let b = (u & 0x7f) as u8;
                u >>= 7;
                if u == 0 {
                    out.push(b);
                    return out;
                }
                out.push(b | 0x80);
            }
        };
        let mut h = vec![0x15];
        h.extend(zz(0));
        h.push(0x15);
        h.extend(zz(1000));
        h.push(0x15);
        h.extend(zz(500));
        h.push(0x68); // delta 6 (campo 9), tipo 8
        let n = 20_000u64;
        let mut l = n;
        loop {
            let b = (l & 0x7f) as u8;
            l >>= 7;
            if l == 0 {
                h.push(b);
                break;
            }
            h.push(b | 0x80);
        }
        h.extend(std::iter::repeat(7u8).take(n as usize));
        h.push(0);
        let header_len = h.len() as u64;
        assert!(header_len > HEADER_WINDOW * 2);
        h.extend(std::iter::repeat(0u8).take(500));
        let data = bytes::Bytes::from(h);
        let fetch = |s: u64, n: usize| -> Result<bytes::Bytes, Control> {
            let s = s as usize;
            Ok(data.slice(s..(s + n).min(data.len())))
        };
        let (sizes, used) = page_header(&fetch, 0, data.len() as u64, "t").unwrap_or_else(|_| panic!("no leyó"));
        assert_eq!((sizes, used), ((Some(1000), Some(500)), header_len));
        // Cortado: el chunk termina antes que el encabezado.
        assert!(page_header(&fetch, 0, header_len - 1, "t").is_err());
        // v0.6.46 (ronda 1 de cf1, N5): uno que no termina nunca de parsear no se lee más allá del tope.
        let junk = bytes::Bytes::from(vec![0x18u8; (MAX_PAGE_HEADER + (1 << 20)) as usize]);
        let asked = std::cell::Cell::new(0usize);
        let fetch = |s: u64, n: usize| -> Result<bytes::Bytes, Control> {
            asked.set(asked.get().max(n));
            let s = s as usize;
            Ok(junk.slice(s..(s + n).min(junk.len())))
        };
        let e = match page_header(&fetch, 0, junk.len() as u64, "t") {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!("tenía que fallar"),
        };
        assert!(e.contains("larger than 16 MiB"), "{}", e);
        assert_eq!(asked.get() as u64, MAX_PAGE_HEADER);
    }

    /// El esquema Arrow que escribe `parquet_write` se lee de vuelta: cada columna con su tipo, la
    /// zona IANA de un timestamp y la unidad de una duration (pyarrow, pandas y polars lo leen
    /// igual; verificado con pyarrow 25 y polars al escribirlo).
    #[test]
    fn arrow_schema_round_trips_through_the_reader() {
        let cols = vec![
            ("i".to_string(), ColKind::Int, false, "UTC".to_string()),
            ("when".to_string(), ColKind::DateTime, false, "Europe/Madrid".to_string()),
            ("d".to_string(), ColKind::Duration, true, "UTC".to_string()),
            ("m".to_string(), ColKind::Duration, false, "UTC".to_string()),
            ("x".to_string(), ColKind::Decimal(2), false, "UTC".to_string()),
        ];
        let b64 = arrow_schema_b64(&cols);
        let raw = synsema_core::bytesutil::b64_decode(&b64).unwrap();
        assert_eq!(&raw[..4], &[0xff; 4], "mensaje encapsulado");
        assert_eq!(raw.len() % 8, 0, "alineado a 8");
        let (zones, durs) = arrow_schema(&b64);
        assert_eq!(zones.get("when").map(String::as_str), Some("Europe/Madrid"));
        assert_eq!(zones.get("i"), None);
        assert_eq!(durs.get("d"), Some(&1));
        assert_eq!(durs.get("m"), Some(&1_000));
        assert_eq!(durs.len(), 2);
    }

    /// Un Parquet de 3 row groups × 2 filas, columnas `a` (int64), `b` (texto), `c` (int64): a = 0..6.
    fn three_row_groups() -> Vec<u8> {
        use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
        use parquet::file::properties::WriterProperties;
        use parquet::file::writer::SerializedFileWriter;
        let schema = std::sync::Arc::new(
            parquet::schema::parser::parse_message_type("message s { required int64 a; required binary b (UTF8); required int64 c; }")
                .unwrap(),
        );
        let mut buf = Vec::new();
        let mut w = SerializedFileWriter::new(&mut buf, schema, std::sync::Arc::new(WriterProperties::builder().build())).unwrap();
        for g in 0..3i64 {
            let mut rg = w.next_row_group().unwrap();
            let a = [g * 2, g * 2 + 1];
            let mut col = rg.next_column().unwrap().unwrap();
            col.typed::<Int64Type>().write_batch(&a, None, None).unwrap();
            col.close().unwrap();
            let mut col = rg.next_column().unwrap().unwrap();
            let b: Vec<ByteArray> = a.iter().map(|n| ByteArray::from(format!("r{}", n).as_str())).collect();
            col.typed::<ByteArrayType>().write_batch(&b, None, None).unwrap();
            col.close().unwrap();
            let mut col = rg.next_column().unwrap().unwrap();
            col.typed::<Int64Type>().write_batch(&[100, 101], None, None).unwrap();
            col.close().unwrap();
            rg.close().unwrap();
        }
        w.close().unwrap();
        buf
    }

    fn opts(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.clone());
        }
        syn_map(m)
    }

    fn rows(v: SynValue) -> Vec<String> {
        let SynValue::List(l) = v else { panic!("esperaba una lista") };
        let items = l.borrow().to_vec();
        items.iter().map(|r| r.to_string()).collect()
    }

    /// v0.6.45 (B4): `columns`, `row_groups` y `limit` leen por partes; `parquet_info` dice qué hay.
    #[test]
    fn parquet_read_by_parts() {
        let file = syn_bytes(three_row_groups());
        let info = parquet_info(&[file.clone()]).ok().unwrap().to_string();
        assert!(info.contains("rows: 6"), "{}", info);
        assert_eq!(info.matches("rows: 2").count(), 3, "tres row groups de 2: {}", info);
        let only_a = rows(parquet_read(&[file.clone(), opts(&[("columns", syn_list(vec![syn_text("a")]))])]).ok().unwrap());
        assert_eq!(only_a.len(), 6);
        assert!(only_a.iter().all(|r| r.contains("a:") && !r.contains("b:")), "{:?}", only_a);
        let rg1 = rows(parquet_read(&[file.clone(), opts(&[("row_groups", syn_list(vec![syn_int(1)]))])]).ok().unwrap());
        assert_eq!(rg1.len(), 2);
        assert!(rg1[0].contains("a: 2") && rg1[1].contains("a: 3"), "{:?}", rg1);
        let lim = rows(parquet_read(&[file.clone(), opts(&[("limit", syn_int(3))])]).ok().unwrap());
        assert_eq!(lim.len(), 3);
        let both = rows(
            parquet_read(&[
                file.clone(),
                opts(&[("row_groups", syn_list(vec![syn_int(2), syn_int(0)])), ("columns", syn_list(vec![syn_text("b")])), ("limit", syn_int(3))]),
            ])
            .ok()
            .unwrap(),
        );
        assert_eq!(both, vec![r#"{b: "r4"}"#, r#"{b: "r5"}"#, r#"{b: "r0"}"#], "el orden es el de row_groups");
        let msg = |r: Result<SynValue, Control>| match r {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba un error"),
        };
        assert!(msg(parquet_read(&[file.clone(), opts(&[("columns", syn_list(vec![syn_text("zz")]))])])).contains("no column \"zz\""));
        assert!(msg(parquet_read(&[file, opts(&[("row_groups", syn_list(vec![syn_int(3)]))])])).contains("row group 3 does not exist"));
    }
}
