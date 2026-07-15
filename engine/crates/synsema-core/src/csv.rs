//! CSV (Batch 8): `csv_parse` / `csv_encode` — transformación PURA texto↔valores,
//! espejo de `json_encode`/`json_decode` (sin capability; el I/O de archivos pasa por
//! `read_file`/`write_file`, que ya tienen las suyas).
//!
//! Semántica (spec batch-8 §3):
//! - RFC 4180 completo: campos entre comillas con delimitadores/comillas/saltos de
//!   línea embebidos, `""` como escape, CRLF y LF, BOM UTF-8 tolerado al inicio.
//! - `csv_parse` default = **lista de mapas** (primera fila = cabeceras), la MISMA
//!   forma que devuelve `sql()` → un CSV entra directo a `group_by`/`chart`.
//! - Default **lossless**: todo campo queda texto (`"00123"` NO se convierte en 123);
//!   `{"numbers": true}` convierte los campos que parsean como número.
//! - `csv_encode`: quoting mínimo, números como `text()` (enteros sin decimales,
//!   `decimal` exacto), `nothing` → vacío, `bytes` → base64, `secret` → `[redacted]`
//!   (G8, espeja `json_encode`), anidados → error claro orientando a `json_encode`.
//! - Errores en inglés, autocontenidos, SIEMPRE con línea/fila cuando aplica (G5) y
//!   atrapables con `try`/`recover` (G10) — jamás `unwrap()`/panic sobre input.
//!
//! AGNÓSTICO de fuente (G2): entrada = texto/valores del lenguaje; salida = valores/
//! texto. Este módulo no conoce conexiones ni importa nada de `database.rs`.

use indexmap::IndexMap;
use num_bigint::BigInt;

use crate::bytesutil::b64_encode;
use crate::interpreter::{Control, RuntimeError};
use crate::number::Number;
use crate::types::{syn_list, syn_map, syn_number, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Opciones
// =========================================================

/// Lee el mapa de opciones (2º argumento opcional) validando que las claves
/// pertenezcan a `valid` — una opción desconocida es un typo silencioso (G5).
fn opts_map(
    args: &[SynValue],
    name: &str,
    valid: &[&str],
) -> Result<IndexMap<String, SynValue>, Control> {
    match args.get(1) {
        None | Some(SynValue::Nothing) => Ok(IndexMap::new()),
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for k in m.keys() {
                if !valid.contains(&k.as_str()) {
                    return Err(err(format!(
                        "{}: unknown option {:?}; valid options are: {}",
                        name,
                        k,
                        valid.join(", ")
                    )));
                }
            }
            Ok(m.clone())
        }
        Some(other) => Err(err(format!(
            "{}: options must be a map, got {}",
            name,
            other.type_name()
        ))),
    }
}

fn opt_bool(opts: &IndexMap<String, SynValue>, key: &str, default: bool, name: &str) -> Result<bool, Control> {
    match opts.get(key) {
        None => Ok(default),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(err(format!(
            "{}: option {:?} must be true or false, got {}",
            name,
            key,
            other.type_name()
        ))),
    }
}

/// Delimitador: exactamente UN carácter ASCII (`,`, `;`, `\t`, …).
fn opt_delimiter(opts: &IndexMap<String, SynValue>, name: &str) -> Result<u8, Control> {
    match opts.get("delimiter") {
        None => Ok(b','),
        Some(SynValue::Text(s)) => {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c.is_ascii() => Ok(c as u8),
                _ => Err(err(format!(
                    "{}: option \"delimiter\" must be a single ASCII character, got {:?}",
                    name, s
                ))),
            }
        }
        Some(other) => Err(err(format!(
            "{}: option \"delimiter\" must be text, got {}",
            name,
            other.type_name()
        ))),
    }
}

// =========================================================
// csv_parse(text, opts?) → list
// =========================================================

/// Pre-validación RFC 4180 que el crate `csv` no hace: una comilla de apertura sin
/// su cierre consume hasta EOF en silencio — acá se detecta y se reporta con la
/// línea donde empezó el campo entrecomillado (G5, "nunca silencioso").
fn check_unclosed_quote(src: &str, delim: u8) -> Result<(), Control> {
    let delim = delim as char;
    let mut line = 1usize;
    let mut in_quotes = false;
    let mut quote_line = 0usize;
    let mut at_field_start = true;
    let mut it = src.chars().peekable();
    while let Some(c) = it.next() {
        if in_quotes {
            match c {
                '"' => {
                    if it.peek() == Some(&'"') {
                        it.next(); // "" = comilla escapada, sigue dentro del campo
                    } else {
                        in_quotes = false;
                        at_field_start = false;
                    }
                }
                '\n' => line += 1,
                _ => {}
            }
        } else if c == '"' && at_field_start {
            in_quotes = true;
            quote_line = line;
        } else if c == delim {
            at_field_start = true;
        } else if c == '\n' {
            line += 1;
            at_field_start = true;
        } else if c != '\r' {
            at_field_start = false;
        }
    }
    if in_quotes {
        return Err(err(format!(
            "csv_parse: unclosed quote in the field that starts on line {}",
            quote_line
        )));
    }
    Ok(())
}

/// Con `{"numbers": true}`: intenta leer el campo como número. Enteros preservan
/// Int/Big; el resto va por f64 con guardia de charset para NO tragar "inf"/"nan"
/// (que `f64::from_str` acepta pero un CSV de negocio no quiere convertir).
fn field_as_number(s: &str) -> Option<Number> {
    if s.is_empty() {
        return None;
    }
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(i) = s.parse::<i64>() {
            return Some(Number::Int(i));
        }
        if let Ok(b) = s.parse::<BigInt>() {
            return Some(Number::Big(b));
        }
    }
    if s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')) {
        if let Ok(f) = s.parse::<f64>() {
            if f.is_finite() {
                return Some(Number::Float(f));
            }
        }
    }
    None
}

fn field_value(s: &str, numbers: bool) -> SynValue {
    if numbers {
        if let Some(n) = field_as_number(s) {
            return syn_number(n);
        }
    }
    syn_text(s)
}

/// Traduce el error del crate `csv` a un mensaje autocontenido con línea (G5).
fn reader_err(e: csv::Error, headers: bool) -> Control {
    if let csv::ErrorKind::UnequalLengths { pos, expected_len, len } = e.kind() {
        let line = pos.as_ref().map(|p| p.line()).unwrap_or(0);
        let source = if headers { " (the header row)" } else { " (the first row)" };
        return err(format!(
            "csv_parse: line {}: record has {} field(s), but {} were expected from the first record{}",
            line, len, expected_len, source
        ));
    }
    err(format!("csv_parse: {}", e))
}

pub fn csv_parse(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "csv_parse expects (text, options?) — 1 or 2 argument(s), got {}",
            args.len()
        )));
    }
    let text = match &args[0] {
        SynValue::Text(s) => s,
        other => {
            return Err(err(format!(
                "csv_parse expects text as the first argument, got {}",
                other.type_name()
            )))
        }
    };
    let opts = opts_map(args, "csv_parse", &["headers", "delimiter", "numbers"])?;
    let headers = opt_bool(&opts, "headers", true, "csv_parse")?;
    let numbers = opt_bool(&opts, "numbers", false, "csv_parse")?;
    let delim = opt_delimiter(&opts, "csv_parse")?;

    // BOM UTF-8 tolerado al inicio (Excel lo escribe); texto vacío → [].
    let src = text.strip_prefix('\u{feff}').unwrap_or(text);
    if src.is_empty() {
        return Ok(syn_list(Vec::new()));
    }
    check_unclosed_quote(src, delim)?;

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false) // las cabeceras se manejan acá (duplicados + forma de salida)
        .delimiter(delim)
        .flexible(false)
        .from_reader(src.as_bytes());

    let mut records: Vec<csv::StringRecord> = Vec::new();
    for rec in rdr.records() {
        records.push(rec.map_err(|e| reader_err(e, headers))?);
    }
    if records.is_empty() {
        return Ok(syn_list(Vec::new()));
    }

    if !headers {
        // Lista de listas: todas las filas son datos.
        let rows = records
            .iter()
            .map(|rec| syn_list(rec.iter().map(|f| field_value(f, numbers)).collect()))
            .collect();
        return Ok(syn_list(rows));
    }

    // Lista de mapas: primera fila = cabeceras (misma forma que devuelve sql()).
    let header_row: Vec<String> = records[0].iter().map(|s| s.to_string()).collect();
    for (i, h) in header_row.iter().enumerate() {
        if header_row[..i].contains(h) {
            return Err(err(format!(
                "csv_parse: duplicate header {:?} on line 1; headers must be unique to build maps (use {{\"headers\": false}} for positional rows)",
                h
            )));
        }
    }
    let rows = records[1..]
        .iter()
        .map(|rec| {
            let mut m = IndexMap::with_capacity(header_row.len());
            for (h, f) in header_row.iter().zip(rec.iter()) {
                m.insert(h.clone(), field_value(f, numbers));
            }
            syn_map(m)
        })
        .collect();
    Ok(syn_list(rows))
}

// =========================================================
// csv_encode(value, opts?) → text
// =========================================================

/// Fin de línea: `"\r\n"` (RFC 4180 / Excel, default) o `"\n"`.
fn opt_eol(opts: &IndexMap<String, SynValue>) -> Result<csv::Terminator, Control> {
    match opts.get("eol") {
        None => Ok(csv::Terminator::CRLF),
        Some(SynValue::Text(s)) => match &**s {
            "\r\n" => Ok(csv::Terminator::CRLF),
            "\n" => Ok(csv::Terminator::Any(b'\n')),
            other => Err(err(format!(
                "csv_encode: option \"eol\" must be \"\\r\\n\" or \"\\n\", got {:?}",
                other
            ))),
        },
        Some(other) => Err(err(format!(
            "csv_encode: option \"eol\" must be text, got {}",
            other.type_name()
        ))),
    }
}

/// Cabeceras explícitas del encode: lista de textos (orden + subconjunto de columnas).
fn opt_headers_list(opts: &IndexMap<String, SynValue>) -> Result<Option<Vec<String>>, Control> {
    match opts.get("headers") {
        None => Ok(None),
        Some(SynValue::List(l)) => {
            let mut out = Vec::with_capacity(l.borrow().len());
            for v in l.borrow().iter() {
                match v {
                    SynValue::Text(s) => out.push(s.to_string()),
                    other => {
                        return Err(err(format!(
                            "csv_encode: option \"headers\" must be a list of text column names, got a {} inside",
                            other.type_name()
                        )))
                    }
                }
            }
            Ok(Some(out))
        }
        Some(other) => Err(err(format!(
            "csv_encode: option \"headers\" must be a list of column names, got {}",
            other.type_name()
        ))),
    }
}

/// Un valor escalar → su campo CSV. `row` es 1-based (para el mensaje de error).
fn encode_field(v: &SynValue, row: usize, col: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        // Espeja text(): enteros sin decimales ("42"), Float estilo Python, Decimal exacto.
        SynValue::Number(n) => Ok(n.to_string()),
        SynValue::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        SynValue::Nothing => Ok(String::new()),
        SynValue::Bytes(b) => Ok(b64_encode(b)),
        // G8: un secret JAMÁS se filtra a un CSV (espeja json_encode).
        SynValue::Secret(_) => Ok("[redacted]".to_string()),
        SynValue::List(_) | SynValue::Map(_) => Err(err(format!(
            "csv_encode: row {}, column {}: nested {} values cannot be a CSV field; encode the field first with json_encode(...)",
            row,
            col,
            v.type_name()
        ))),
        other => Err(err(format!(
            "csv_encode: row {}, column {}: cannot encode a {} as a CSV field; convert it with text(...) first",
            row,
            col,
            other.type_name()
        ))),
    }
}

pub fn csv_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "csv_encode expects (value, options?) — 1 or 2 argument(s), got {}",
            args.len()
        )));
    }
    let rows = match &args[0] {
        SynValue::List(l) => l.borrow().clone(),
        other => {
            return Err(err(format!(
                "csv_encode expects a list of maps or a list of lists, got {}",
                other.type_name()
            )))
        }
    };
    let opts = opts_map(args, "csv_encode", &["headers", "delimiter", "eol"])?;
    let delim = opt_delimiter(&opts, "csv_encode")?;
    let eol = opt_eol(&opts)?;
    let explicit_headers = opt_headers_list(&opts)?;

    let mut wtr = csv::WriterBuilder::new()
        .delimiter(delim)
        .terminator(eol)
        .quote_style(csv::QuoteStyle::Necessary) // quoting mínimo RFC 4180
        .from_writer(Vec::new());
    let write = |wtr: &mut csv::Writer<Vec<u8>>, rec: &[String]| -> Result<(), Control> {
        wtr.write_record(rec).map_err(|e| err(format!("csv_encode: {}", e)))
    };

    if rows.is_empty() {
        // Sin filas: con cabeceras explícitas se emite solo esa fila; si no, texto vacío.
        if let Some(hs) = &explicit_headers {
            write(&mut wtr, hs)?;
        }
    } else {
        match &rows[0] {
            SynValue::Map(first) => {
                // Lista de mapas: cabeceras = opts o claves del 1er mapa en su orden.
                let headers: Vec<String> = match &explicit_headers {
                    Some(hs) => hs.clone(),
                    None => first.borrow().keys().cloned().collect(),
                };
                write(&mut wtr, &headers)?;
                for (i, r) in rows.iter().enumerate() {
                    let m = match r {
                        SynValue::Map(m) => m.borrow(),
                        other => {
                            return Err(err(format!(
                                "csv_encode: row {} is a {}, but the first row is a map; all rows must have the same shape",
                                i + 1,
                                other.type_name()
                            )))
                        }
                    };
                    // Con cabeceras derivadas del 1er mapa, claves distintas = error claro
                    // (jamás columnas vacías en silencio). Con headers explícitos se
                    // exige el subconjunto pedido.
                    if explicit_headers.is_none() && m.len() != headers.len() {
                        return Err(err(format!(
                            "csv_encode: row {} has {} key(s) but the first row has {} ({}); pass {{\"headers\": [...]}} to select the columns",
                            i + 1,
                            m.len(),
                            headers.len(),
                            headers.join(", ")
                        )));
                    }
                    let mut rec = Vec::with_capacity(headers.len());
                    for h in &headers {
                        match m.get(h) {
                            Some(v) => rec.push(encode_field(v, i + 1, &format!("{:?}", h))?),
                            None => {
                                return Err(err(format!(
                                    "csv_encode: row {} is missing the column {:?} (present in the header row)",
                                    i + 1,
                                    h
                                )))
                            }
                        }
                    }
                    write(&mut wtr, &rec)?;
                }
            }
            SynValue::List(first) => {
                // Lista de listas: sin cabeceras (salvo opts), todas del mismo largo.
                let width = first.borrow().len();
                if let Some(hs) = &explicit_headers {
                    if hs.len() != width {
                        return Err(err(format!(
                            "csv_encode: option \"headers\" has {} column(s) but the rows have {}",
                            hs.len(),
                            width
                        )));
                    }
                    write(&mut wtr, hs)?;
                }
                for (i, r) in rows.iter().enumerate() {
                    let items = match r {
                        SynValue::List(l) => l.borrow().clone(),
                        other => {
                            return Err(err(format!(
                                "csv_encode: row {} is a {}, but the first row is a list; all rows must have the same shape",
                                i + 1,
                                other.type_name()
                            )))
                        }
                    };
                    if items.len() != width {
                        return Err(err(format!(
                            "csv_encode: row {} has {} field(s) but the first row has {}",
                            i + 1,
                            items.len(),
                            width
                        )));
                    }
                    let mut rec = Vec::with_capacity(items.len());
                    for (j, v) in items.iter().enumerate() {
                        rec.push(encode_field(v, i + 1, &(j + 1).to_string())?);
                    }
                    write(&mut wtr, &rec)?;
                }
            }
            other => {
                return Err(err(format!(
                    "csv_encode expects rows that are maps or lists, got a {} as the first row",
                    other.type_name()
                )))
            }
        }
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| err(format!("csv_encode: {}", e)))?;
    let text = String::from_utf8(bytes).map_err(|e| err(format!("csv_encode: {}", e)))?;
    Ok(syn_text(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_bytes, syn_int, syn_secret};

    /// `Control` no implementa Debug: desarma el Result a mano.
    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.message,
            Ok(v) => panic!("esperaba error, dio {}", v),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn parse(text: &str) -> SynValue {
        ok(csv_parse(&[syn_text(text)]))
    }

    fn encode(v: SynValue) -> String {
        match ok(csv_encode(&[v])) {
            SynValue::Text(s) => s.to_string(),
            other => panic!("expected text, got {}", other.type_name()),
        }
    }

    #[test]
    fn parse_headers_default() {
        let v = parse("a,b\r\n1,x\r\n2,y\r\n");
        let l = match v {
            SynValue::List(l) => l.borrow().clone(),
            _ => panic!(),
        };
        assert_eq!(l.len(), 2);
        match &l[0] {
            SynValue::Map(m) => {
                assert_eq!(m.borrow().get("a").unwrap().to_string(), "1"); // texto lossless
                assert_eq!(m.borrow().get("b").unwrap().to_string(), "x");
            }
            _ => panic!("expected map row"),
        }
    }

    #[test]
    fn quoted_fields_roundtrip() {
        let rows = syn_list(vec![syn_list(vec![
            syn_text("a,b"),
            syn_text("with \"quotes\""),
            syn_text("multi\nline"),
        ])]);
        let opts = {
            let mut m = IndexMap::new();
            m.insert("headers".to_string(), SynValue::Bool(false));
            syn_map(m)
        };
        let enc = ok(csv_encode(&[rows, SynValue::Nothing]));
        let enc_s = enc.to_string();
        assert_eq!(enc_s, "\"a,b\",\"with \"\"quotes\"\"\",\"multi\nline\"\r\n");
        let back = ok(csv_parse(&[syn_text(enc_s.as_str()), opts]));
        let l = match back {
            SynValue::List(l) => l.borrow().clone(),
            _ => panic!(),
        };
        match &l[0] {
            SynValue::List(fields) => {
                let f = fields.borrow();
                assert_eq!(f[0].to_string(), "a,b");
                assert_eq!(f[1].to_string(), "with \"quotes\"");
                assert_eq!(f[2].to_string(), "multi\nline");
            }
            _ => panic!("expected list row"),
        }
    }

    #[test]
    fn unclosed_quote_reports_line() {
        let m = msg(csv_parse(&[syn_text("a,b\n1,\"oops\n2,3\n")]));
        assert!(m.contains("unclosed quote"), "{}", m);
        assert!(m.contains("line 2"), "{}", m);
    }

    #[test]
    fn secret_redacted_and_bytes_b64() {
        let mut m = IndexMap::new();
        m.insert("k".to_string(), syn_secret("API_KEY", "hunter2"));
        m.insert("b".to_string(), syn_bytes(b"foo".to_vec()));
        m.insert("n".to_string(), syn_int(42));
        let out = encode(syn_list(vec![syn_map(m)]));
        assert!(out.contains("[redacted]"), "{}", out);
        assert!(!out.contains("hunter2"), "plaintext leaked: {}", out);
        assert!(out.contains("Zm9v"), "{}", out);
        assert!(out.contains("42"), "{}", out);
    }
}
