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
//!   datetime → TIMESTAMP(µs, UTC). Una columna que mezcla tipos o un valor anidado es un error
//!   con el nombre de la columna. `opts.compression` = "snappy" (default), "zstd", "gzip",
//!   "lz4" o "none".

use std::rc::Rc;
use std::sync::Arc;

use indexmap::IndexMap;
use num_bigint::{BigInt, Sign};

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
use synsema_core::types::{syn_bool, syn_bytes, syn_float, syn_list, syn_map, syn_number, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Lectura
// =========================================================

fn decimal_from_parquet(d: &parquet::data_type::Decimal) -> SynValue {
    let unscaled = BigInt::from_signed_bytes_be(d.data());
    let scale = d.scale().max(0) as u32;
    match unscaled.to_string().parse::<i128>().ok().and_then(|i| rust_decimal::Decimal::try_from_i128_with_scale(i, scale).ok()) {
        Some(dec) => syn_number(Number::Decimal(dec)),
        // Más de 28 dígitos no entran en rust_decimal: se entrega exacto como texto.
        None => syn_text(format!("{}e-{}", unscaled, scale)),
    }
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
            Some(d) => SynValue::Time(Rc::new(Temporal::Date(d))),
            None => SynValue::Nothing,
        },
        Field::TimestampMillis(ms) => match DateTime::from_timestamp_millis(*ms) {
            Some(dt) => SynValue::Time(Rc::new(Temporal::DateTime(dt.with_timezone(&chrono_tz::Tz::UTC)))),
            None => SynValue::Nothing,
        },
        Field::TimestampMicros(us) => match DateTime::from_timestamp_micros(*us) {
            Some(dt) => SynValue::Time(Rc::new(Temporal::DateTime(dt.with_timezone(&chrono_tz::Tz::UTC)))),
            None => SynValue::Nothing,
        },
        Field::Group(row) => {
            let mut m = IndexMap::new();
            for (k, v) in row.get_column_iter() {
                m.insert(k.clone(), field_to_syn(v));
            }
            syn_map(m)
        }
        Field::ListInternal(list) => syn_list(list.elements().iter().map(field_to_syn).collect()),
        Field::MapInternal(map) => {
            let mut m = IndexMap::new();
            for (k, v) in map.entries() {
                let key = match field_to_syn(k) {
                    SynValue::Text(t) => t.to_string(),
                    other => other.to_string(),
                };
                m.insert(key, field_to_syn(v));
            }
            syn_map(m)
        }
        // Tipos que no usamos (tiempo del día, float16, …): su forma de texto.
        other => syn_text(other.to_string()),
    }
}

fn parquet_read(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "parquet_read";
    let data = match args.first() {
        Some(SynValue::Bytes(b)) => b.to_vec(),
        Some(other) => {
            return Err(err(format!(
                "{}: expected the file's bytes (read_file_bytes(path)), got {}",
                F,
                other.type_name()
            )))
        }
        None => return Err(err("parquet_read(bytes)")),
    };
    let reader = SerializedFileReader::new(bytes::Bytes::from(data)).map_err(|e| err(format!("{}: not a Parquet file: {}", F, e)))?;
    let rows = reader.get_row_iter(None).map_err(|e| err(format!("{}: {}", F, e)))?;
    let mut out = Vec::new();
    for row in rows {
        let row = row.map_err(|e| err(format!("{}: {}", F, e)))?;
        let mut m = IndexMap::new();
        for (k, v) in row.get_column_iter() {
            m.insert(k.clone(), field_to_syn(v));
        }
        out.push(syn_map(m));
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
        SynValue::Number(Number::Decimal(d)) => ColKind::Decimal(d.scale()),
        SynValue::Text(_) => ColKind::Text,
        SynValue::Bool(_) => ColKind::Bool,
        SynValue::Bytes(_) => ColKind::Bytes,
        SynValue::Time(t) => match &**t {
            Temporal::Date(_) => ColKind::Date,
            Temporal::DateTime(_) => ColKind::DateTime,
            Temporal::Duration(_) => {
                return Err(err(format!("parquet_write: column {:?} has a duration — store in_units(d, \"seconds\")", col)))
            }
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

fn build_type(name: &str, k: ColKind) -> Result<Type, Control> {
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
        ColKind::DateTime => Type::primitive_type_builder(name, PhysicalType::INT64).with_logical_type(Some(LogicalType::timestamp(true, TimeUnit::MICROS))),
    };
    b.with_repetition(Repetition::OPTIONAL).build().map_err(|e| err(format!("parquet_write: column {:?}: {}", name, e)))
}

fn decimal_bytes(d: &rust_decimal::Decimal, scale: u32) -> Vec<u8> {
    let mut x = *d;
    x.rescale(scale);
    let unscaled = BigInt::from(x.mantissa());
    let (sign, _) = unscaled.to_bytes_be();
    let _ = sign == Sign::Minus;
    unscaled.to_signed_bytes_be()
}

fn parquet_write(args: &[SynValue]) -> Result<SynValue, Control> {
    use parquet::column::writer::ColumnWriter;
    const F: &str = "parquet_write";
    let rows = match args.first() {
        Some(SynValue::List(l)) => l.borrow().clone(),
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
            SynValue::Map(m) => m.borrow().clone(),
            other => return Err(err(format!("{}: row {} is a {}, every row must be a map", F, i + 1, other.type_name()))),
        };
        for (k, v) in &m {
            let k2 = kind_of(v, k)?;
            let entry = cols.entry(k.clone()).or_insert(None);
            *entry = match (*entry, k2) {
                (None, x) => x,
                (Some(a), None) => Some(a),
                (Some(a), Some(b)) => Some(merge_kind(a, b, k)?),
            };
        }
        maps.push(m);
    }
    let mut fields = Vec::with_capacity(cols.len());
    for (name, k) in &cols {
        // Una columna toda `nothing` se escribe como texto opcional (todo nulo).
        fields.push(Arc::new(build_type(name, k.unwrap_or(ColKind::Text))?));
    }
    let schema = Arc::new(
        Type::group_type_builder("schema").with_fields(fields).build().map_err(|e| err(format!("{}: {}", F, e)))?,
    );
    let props = Arc::new(WriterProperties::builder().set_compression(compression).build());
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = SerializedFileWriter::new(&mut buf, schema, props).map_err(|e| err(format!("{}: {}", F, e)))?;
        let mut rg = w.next_row_group().map_err(|e| err(format!("{}: {}", F, e)))?;
        for (name, k) in &cols {
            let kind = k.unwrap_or(ColKind::Text);
            let vals: Vec<&SynValue> = maps.iter().map(|m| m.get(name).unwrap_or(&SynValue::Nothing)).collect();
            let defs: Vec<i16> = vals.iter().map(|v| if matches!(v, SynValue::Nothing) { 0 } else { 1 }).collect();
            let present = vals.iter().filter(|v| !matches!(v, SynValue::Nothing));
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
                            (SynValue::Number(Number::Decimal(d)), ColKind::Decimal(s)) => ByteArray::from(decimal_bytes(d, s)),
                            (SynValue::Number(Number::Int(i)), ColKind::Decimal(s)) => {
                                ByteArray::from(decimal_bytes(&rust_decimal::Decimal::from(*i), s))
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
                    let v: Vec<i64> = present
                        .map(|x| match x {
                            SynValue::Time(t) => match &**t {
                                Temporal::DateTime(dt) => dt.timestamp_micros(),
                                _ => 0,
                            },
                            _ => 0,
                        })
                        .collect();
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

pub fn register_parquet_builtins(interp: &Interpreter) {
    interp.register_builtin("parquet_read", 1, Rc::new(|_i, a, _l| parquet_read(a)));
    interp.register_builtin("parquet_write", -1, Rc::new(|_i, a, _l| parquet_write(a)));
}
