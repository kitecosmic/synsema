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

/// Delimitador: exactamente UN carácter ASCII (`,`, `;`, `\t`, …) que no sea la comilla ni un
/// fin de línea (con esos el archivo no se puede leer de vuelta).
fn opt_delimiter(opts: &IndexMap<String, SynValue>, name: &str) -> Result<u8, Control> {
    match opts.get("delimiter") {
        None => Ok(b','),
        Some(SynValue::Text(s)) => {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c @ ('"' | '\r' | '\n')), None) => Err(err(format!(
                    "{}: option \"delimiter\" cannot be {:?} (the quote and line ends have their own meaning in CSV)",
                    name, c
                ))),
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
                // Como `tokenize`: `\r\n`, `\n` y `\r` solo son UN fin de línea.
                '\n' => line += 1,
                '\r' if it.peek() != Some(&'\n') => line += 1,
                _ => {}
            }
        } else if c == '"' && at_field_start {
            in_quotes = true;
            quote_line = line;
        } else if c == delim {
            at_field_start = true;
        } else if c == '\n' || c == '\r' {
            // Un `\r` solo también termina el registro (el tokenizador lo lee así).
            if !(c == '\r' && it.peek() == Some(&'\n')) {
                line += 1;
            }
            at_field_start = true;
        } else {
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

/// Un campo leído: su texto y si vino entre comillas (`""` es texto vacío; un campo vacío
/// sin comillas es un dato faltante).
struct Field {
    text: String,
    quoted: bool,
}

/// Una fila: su línea (1-based, donde empieza) y sus campos; `None` = línea en blanco.
type Record = (usize, Option<Vec<Field>>);

/// RFC 4180 (v0.6.29): el lector propio para saber qué campos vinieron entre comillas, cosa
/// que el crate `csv` no expone. Fin de fila: `\n`, `\r\n` o `\r`. Una comilla sólo abre un
/// campo al principio; `""` adentro es una comilla; lo que sigue a la comilla de cierre se
/// agrega tal cual (`"x"y` → `xy`, como el crate `csv`). `check_unclosed_quote` ya corrió.
fn tokenize(src: &str, delim: u8) -> Vec<Record> {
    let delim = delim as char;
    let mut out: Vec<Record> = Vec::new();
    let mut line = 1usize;
    let mut it = src.chars().peekable();
    let mut fields: Vec<Field> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_quotes = false;
    let mut field_started = false; // hubo algo (texto o comillas) en la fila
    let mut rec_line = 1usize;
    loop {
        let c = it.next();
        if in_quotes {
            match c {
                Some('"') => {
                    if it.peek() == Some(&'"') {
                        it.next();
                        cur.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                Some(ch) => {
                    // `\r\n`, `\n` y `\r` solo son UN fin de línea, dentro y fuera de comillas.
                    if ch == '\n' || (ch == '\r' && it.peek() != Some(&'\n')) {
                        line += 1;
                    }
                    cur.push(ch);
                }
                None => {}
            }
            if c.is_some() {
                continue;
            }
        }
        match c {
            Some(ch) if ch == delim => {
                fields.push(Field { text: std::mem::take(&mut cur), quoted });
                quoted = false;
                field_started = true;
            }
            Some('"') if cur.is_empty() && !quoted => {
                quoted = true;
                in_quotes = true;
                field_started = true;
            }
            Some(ch @ ('\n' | '\r')) => {
                if ch == '\r' && it.peek() == Some(&'\n') {
                    it.next();
                }
                if field_started || !cur.is_empty() {
                    fields.push(Field { text: std::mem::take(&mut cur), quoted });
                    out.push((rec_line, Some(std::mem::take(&mut fields))));
                } else {
                    out.push((rec_line, None));
                }
                quoted = false;
                field_started = false;
                line += 1;
                rec_line = line;
            }
            Some(ch) => {
                cur.push(ch);
                field_started = true;
            }
            None => {
                if field_started || !cur.is_empty() {
                    fields.push(Field { text: std::mem::take(&mut cur), quoted });
                    out.push((rec_line, Some(fields)));
                }
                break;
            }
        }
    }
    out
}

/// Con `{"numbers": true}`: intenta leer el campo como número. Enteros preservan
/// Int/Big; el resto va por f64 con guardia de charset para NO tragar "inf"/"nan"
/// (que `f64::from_str` acepta pero un CSV de negocio no quiere convertir).
fn field_as_number(s: &str) -> Option<Number> {
    if s.is_empty() {
        return None;
    }
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    // Más de 4300 dígitos no es un número que convertir (cuadrático, el tope de `int()` y
    // JSON): queda como texto.
    if body.len() > crate::number::MAX_DEC_TEXT_DIGITS {
        return None;
    }
    if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(i) = s.parse::<i64>() {
            return Some(Number::Int(i));
        }
        if let Ok(b) = s.parse::<BigInt>() {
            return Some(Number::Big(Box::new(b)));
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

fn field_value(f: &Field, numbers: bool, missing: &[String]) -> SynValue {
    // v0.6.29 (DATOS-6): un campo vacío es un dato FALTANTE → `nothing`; `""` entre comillas es
    // texto vacío (y `csv_encode` escribe `nothing` vacío y `""` entre comillas: la ida y
    // vuelta es exacta).
    let s = f.text.as_str();
    if s.is_empty() {
        return if f.quoted { syn_text("") } else { SynValue::Nothing };
    }
    if is_missing_marker(f, missing) {
        return SynValue::Nothing;
    }
    if numbers {
        if let Some(n) = field_as_number(s) {
            return syn_number(n);
        }
    }
    syn_text(s)
}

/// `{"missing": ["NA", "NULL", "-"]}` (como `null_values` de polars / `na_values` de pandas):
/// esos textos, SIN comillas, son un dato faltante. Entre comillas (`"NA"`) siguen siendo texto:
/// alguien lo escribió a propósito.
fn is_missing_marker(f: &Field, missing: &[String]) -> bool {
    !f.quoted && missing.iter().any(|m| m == &f.text)
}

fn opt_missing(opts: &IndexMap<String, SynValue>) -> Result<Vec<String>, Control> {
    match opts.get("missing") {
        None | Some(SynValue::Nothing) => Ok(Vec::new()),
        Some(SynValue::Text(t)) => Ok(vec![t.to_string()]),
        Some(SynValue::List(l)) => l
            .borrow()
            .iter()
            .map(|v| match v {
                SynValue::Text(t) => Ok(t.to_string()),
                other => Err(err(format!("csv_parse: option \"missing\" must be a list of texts, got a {} inside", other.type_name()))),
            })
            .collect(),
        Some(other) => Err(err(format!("csv_parse: option \"missing\" must be a list of texts (e.g. [\"NA\", \"NULL\"]), got {}", other.type_name()))),
    }
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
    let opts = opts_map(args, "csv_parse", &["headers", "delimiter", "numbers", "types", "missing"])?;
    let missing = opt_missing(&opts)?;
    let headers = opt_bool(&opts, "headers", true, "csv_parse")?;
    let numbers = opt_bool(&opts, "numbers", false, "csv_parse")?;
    let types = opt_types(&opts)?;
    if types.is_some() && !headers {
        return Err(err("csv_parse: \"types\" names columns, so it needs headers (drop {\"headers\": false})"));
    }
    let delim = opt_delimiter(&opts, "csv_parse")?;

    // BOM UTF-8 tolerado al inicio (Excel lo escribe); texto vacío → [].
    let src = text.strip_prefix('\u{feff}').unwrap_or(text);
    if src.is_empty() {
        return Ok(syn_list(Vec::new()));
    }
    check_unclosed_quote(src, delim)?;

    let raw = tokenize(src, delim);
    // El ancho lo fija la primera fila. Una línea en blanco se saltea SIEMPRE, también en un CSV
    // de una columna (Python `csv`, pandas): por eso `csv_encode` escribe `""` una fila de un solo
    // campo `nothing`. Una línea en blanco dentro de un campo entre comillas es parte del campo.
    let width = raw.iter().find_map(|(_, r)| r.as_ref().map(|f| f.len())).unwrap_or(0);
    let mut records: Vec<(usize, Vec<Field>)> = Vec::new();
    for (ln, r) in raw.into_iter() {
        match r {
            Some(f) => {
                if f.len() != width {
                    let source = if headers { " (the header row)" } else { " (the first row)" };
                    return Err(err(format!(
                        "csv_parse: line {}: record has {} field(s), but {} were expected from the first record{}",
                        ln,
                        f.len(),
                        width,
                        source
                    )));
                }
                records.push((ln, f));
            }
            None => {}
        }
    }
    if records.is_empty() {
        return Ok(syn_list(Vec::new()));
    }

    if !headers {
        // Lista de listas: todas las filas son datos.
        let rows = records
            .iter()
            .map(|(_, rec)| syn_list(rec.iter().map(|f| field_value(f, numbers, &missing)).collect()))
            .collect();
        return Ok(syn_list(rows));
    }

    // Lista de mapas: primera fila = cabeceras (misma forma que devuelve sql()).
    let header_row: Vec<String> = records[0].1.iter().map(|f| f.text.clone()).collect();
    for (i, h) in header_row.iter().enumerate() {
        if header_row[..i].contains(h) {
            return Err(err(format!(
                "csv_parse: duplicate header {:?} on line 1; headers must be unique to build maps (use {{\"headers\": false}} for positional rows)",
                h
            )));
        }
    }
    if let Some(ts) = &types {
        for c in ts.keys() {
            if !header_row.contains(c) {
                return Err(err(format!("csv_parse: \"types\" names column {:?}, which is not in the header", c)));
            }
        }
    }
    let mut rows = Vec::with_capacity(records.len().saturating_sub(1));
    for (ln, rec) in records[1..].iter() {
        let mut m = IndexMap::with_capacity(header_row.len());
        for (h, f) in header_row.iter().zip(rec.iter()) {
            let v = match types.as_ref().and_then(|t| t.get(h)) {
                Some(_) if is_missing_marker(f, &missing) => SynValue::Nothing,
                Some(ty) => typed_field(&f.text, f.quoted, ty, h, *ln)?,
                None => field_value(f, numbers, &missing),
            };
            m.insert(h.clone(), v);
        }
        rows.push(syn_map(m));
    }
    Ok(syn_list(rows))
}

/// `{"types": {"col": "int" | "float" | "decimal" | "text" | "bool"}}` (v0.6.29, DATOS-16):
/// el tipo de cada columna, en vez de adivinar con `numbers: true` (que convierte `"007"` en 7
/// en todo el archivo). Un campo que no es de su tipo es error con línea y columna.
fn opt_types(opts: &IndexMap<String, SynValue>) -> Result<Option<IndexMap<String, String>>, Control> {
    match opts.get("types") {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Map(m)) => {
            let mut out = IndexMap::new();
            for (k, v) in m.borrow().iter() {
                let t = match v {
                    SynValue::Text(t) if matches!(t.as_ref(), "int" | "float" | "decimal" | "text" | "bool" | "date" | "datetime") => t.to_string(),
                    other => {
                        return Err(err(format!(
                            "csv_parse: type of column {:?} must be \"int\", \"float\", \"decimal\", \"text\", \"bool\", \"date\" or \"datetime\", got {}",
                            k, other
                        )))
                    }
                };
                out.insert(k.clone(), t);
            }
            Ok(Some(out))
        }
        Some(other) => Err(err(format!("csv_parse: option \"types\" must be a map column → type, got {}", other.type_name()))),
    }
}

fn typed_field(s: &str, quoted: bool, ty: &str, col: &str, line: usize) -> Result<SynValue, Control> {
    if s.is_empty() {
        // `""` entre comillas en una columna de texto es texto vacío; en las demás, y sin
        // comillas, falta el dato.
        return Ok(if quoted && ty == "text" { syn_text("") } else { SynValue::Nothing });
    }
    let article = if matches!(ty, "int") { "an" } else { "a" };
    let bad = || err(format!("csv_parse: line {}, column {:?}: {:?} is not {} {}", line, col, s, article, ty));
    let t = s.trim();
    Ok(match ty {
        "text" => syn_text(s),
        "int" => {
            let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            // El tope de `int()` y JSON: convertir un entero enorme es cuadrático.
            if digits.len() > crate::number::MAX_DEC_TEXT_DIGITS {
                return Err(err(format!(
                    "csv_parse: line {}, column {:?}: an integer with {} digits; the limit is {} — read the column as text",
                    line, col, digits.len(), crate::number::MAX_DEC_TEXT_DIGITS
                )));
            }
            syn_number(Number::from_bigint(t.parse::<BigInt>().map_err(|_| bad())?))
        }
        "float" => {
            let x = t.parse::<f64>().map_err(|_| bad())?;
            // `nan`/`inf` escritos así se leen; un número que no entra en un float (`1e400`)
            // es error, no infinito (se perdería en silencio, como en `json_decode`).
            let lower = t.trim_start_matches(['+', '-']).to_ascii_lowercase();
            if x.is_infinite() && !matches!(lower.as_str(), "inf" | "infinity") {
                return Err(err(format!(
                    "csv_parse: line {}, column {:?}: {:?} is out of range for a float — read the column as decimal or text",
                    line, col, s
                )));
            }
            syn_number(Number::Float(x))
        }
        "decimal" => syn_number(Number::parse_decimal(t).ok_or_else(bad)?),
        "date" => crate::temporal::date(&[syn_text(t)]).map_err(|_| bad())?,
        "datetime" => crate::temporal::datetime(&[syn_text(t)]).map_err(|_| bad())?,
        "bool" => match t.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => crate::types::syn_bool(true),
            "false" | "0" | "no" => crate::types::syn_bool(false),
            _ => return Err(bad()),
        },
        _ => unreachable!(),
    })
}

// =========================================================
// csv_encode(value, opts?) → text
// =========================================================

/// Fin de línea: `"\r\n"` (RFC 4180 / Excel, default) o `"\n"`.
fn opt_eol(opts: &IndexMap<String, SynValue>) -> Result<&'static str, Control> {
    match opts.get("eol") {
        None => Ok("\r\n"),
        Some(SynValue::Text(s)) => match &**s {
            "\r\n" => Ok("\r\n"),
            "\n" => Ok("\n"),
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

/// Un campo a escribir: su texto, si es un texto vacío (que va entre comillas) y si vino de un
/// texto (sólo el texto puede ser una fórmula: un número negativo `-5` no se toca).
struct Cell {
    text: String,
    empty_text: bool,
    is_text: bool,
    /// Viene de `nothing` (con `{"missing": marca}` se escribe la marca).
    is_missing: bool,
}

impl From<String> for Cell {
    fn from(text: String) -> Cell {
        Cell { text, empty_text: false, is_text: false, is_missing: false }
    }
}

/// Una cabecera es texto (también puede ser una fórmula).
fn header_cell(text: String) -> Cell {
    Cell { text, empty_text: false, is_text: true, is_missing: false }
}

/// El aviso de `csv_encode` para una tabla de UNA columna con algún `nothing` y sin `missing`: ahí
/// `nothing` se escribe `""` (una línea en blanco se ignoraría al leer) y vuelve como texto vacío.
pub const ONE_COLUMN_NOTHING_WARNING: &str = "csv_encode: a one-column table writes nothing as \"\" (it reads back as empty text); pass {\"missing\": \"NA\"} and read it with {\"missing\": [\"NA\"]} for an exact round trip";

/// Avisa una vez por proceso.
fn warn_one_column_nothing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| eprintln!("warning: {}", ONE_COLUMN_NOTHING_WARNING));
}

/// ¿Empieza como una fórmula de hoja de cálculo? (OWASP: `=`, `+`, `-`, `@`, tab, CR).
fn t_starts_formula(t: &str) -> bool {
    matches!(t.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'))
}

/// Un valor escalar → su campo CSV. `row` es 1-based (para el mensaje de error).
fn encode_field(v: &SynValue, row: usize, col: &str) -> Result<Cell, Control> {
    if let SynValue::Text(s) = v {
        return Ok(Cell { text: s.to_string(), empty_text: s.is_empty(), is_text: true, is_missing: false });
    }
    let is_missing = matches!(v, SynValue::Nothing);
    encode_scalar(v, row, col).map(|text| Cell { is_missing, ..Cell::from(text) })
}

fn encode_scalar(v: &SynValue, row: usize, col: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        // Espeja text(): enteros sin decimales ("42"), Float estilo Python, Decimal exacto.
        SynValue::Number(n) => Ok(n.to_string()),
        SynValue::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        SynValue::Nothing => Ok(String::new()),
        SynValue::Time(t) => Ok(t.to_string()),
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
    let opts = opts_map(args, "csv_encode", &["headers", "delimiter", "eol", "escape_formulas", "missing"])?;
    // OWASP "CSV injection": una celda de texto que empieza con = + - @ (o tab/CR) la abre
    // Excel/Sheets como FÓRMULA. Con `escape_formulas` se le antepone `'`, que la muestra como
    // texto. Apagado por defecto: cambia el dato (la ida y vuelta deja de ser exacta).
    let escape_formulas = opt_bool(&opts, "escape_formulas", false, "csv_encode")?;
    let delim = opt_delimiter(&opts, "csv_encode")?;
    let eol = opt_eol(&opts)?;
    let explicit_headers = opt_headers_list(&opts)?;
    // `{"missing": "NA"}` (el `na_rep` de pandas): cada `nothing` se escribe como la marca, sin
    // comillas, y un texto igual a la marca va entre comillas — con `csv_parse(t, {"missing":
    // ["NA"]})` la ida y vuelta es exacta con cualquier cantidad de columnas.
    let missing: Option<String> = match opts.get("missing") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(t)) => {
            let t = t.to_string();
            // Vacía no marca nada (un campo vacío YA es `nothing`) y en una tabla de una columna
            // escribiría líneas en blanco, que al leer se saltean: la fila se perdería.
            if t.is_empty() {
                return Err(err(
                    "csv_encode: option \"missing\" cannot be empty — an empty field already reads as nothing; use a mark such as \"NA\" (and read it back with {\"missing\": [\"NA\"]})",
                ));
            }
            if t.contains(delim as char) || t.contains('"') || t.contains('\n') || t.contains('\r') {
                return Err(err(format!(
                    "csv_encode: option \"missing\" cannot contain the delimiter, a quote or a line end, got {:?}",
                    t
                )));
            }
            Some(t)
        }
        Some(other) => {
            return Err(err(format!(
                "csv_encode: option \"missing\" must be a text (the mark written for nothing, e.g. \"NA\"), got {}",
                other.type_name()
            )))
        }
    };

    // Escritor RFC 4180 propio (v0.6.29): comillas sólo donde hacen falta —separador,
    // comilla, fin de línea— y SIEMPRE en un texto vacío (`""`), que así se distingue de
    // `nothing` (campo vacío sin comillas). Lo que escribe, `csv_parse` lo lee igual.
    let mut wtr = String::new();
    let d = delim as char;
    let write = |wtr: &mut String, rec: &[Cell]| -> Result<(), Control> {
        for (i, c) in rec.iter().enumerate() {
            if i > 0 {
                wtr.push(d);
            }
            if let (true, Some(mark)) = (c.is_missing, &missing) {
                wtr.push_str(mark);
                continue;
            }
            let escaped;
            let t = if escape_formulas && c.is_text && t_starts_formula(&c.text) {
                escaped = format!("'{}", c.text);
                escaped.as_str()
            } else {
                c.text.as_str()
            };
            // Una fila de un solo campo vacío sería una línea en blanco, que al leer se ignora:
            // se escribe `""`, como el writer de Python (un `nothing` ahí vuelve como `""`).
            let lone_empty = rec.len() == 1 && t.is_empty();
            if lone_empty && c.is_missing {
                warn_one_column_nothing();
            }
            // Un texto igual a la marca de `missing` va entre comillas, para no leerse como faltante.
            let is_mark = c.is_text && missing.as_deref() == Some(t);
            if c.empty_text || lone_empty || is_mark || t.contains(d) || t.contains('"') || t.contains('\n') || t.contains('\r') {
                wtr.push('"');
                wtr.push_str(&t.replace('"', "\"\""));
                wtr.push('"');
            } else {
                wtr.push_str(t);
            }
        }
        wtr.push_str(eol);
        Ok(())
    };

    if rows.is_empty() {
        // Sin filas: con cabeceras explícitas se emite solo esa fila; si no, texto vacío.
        if let Some(hs) = &explicit_headers {
            write(&mut wtr, &hs.iter().cloned().map(header_cell).collect::<Vec<_>>())?;
        }
    } else {
        match &rows[0] {
            SynValue::Map(first) => {
                // Lista de mapas: cabeceras = opts o claves del 1er mapa en su orden.
                let headers: Vec<String> = match &explicit_headers {
                    Some(hs) => hs.clone(),
                    None => first.borrow().keys().cloned().collect(),
                };
                write(&mut wtr, &headers.iter().cloned().map(header_cell).collect::<Vec<_>>())?;
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
                    write(&mut wtr, &hs.iter().cloned().map(header_cell).collect::<Vec<_>>())?;
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

    Ok(syn_text(wtr))
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
            Err(Control::Error(e)) => e.into_message(),
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
    fn blank_line_always_skipped() {
        // También en un CSV de una columna; `nothing` solo en una fila se escribe `""`.
        for src in ["x\n1\n2\n\n", "x\n1\n\n2\n"] {
            match parse(src) {
                SynValue::List(l) => assert_eq!(l.borrow().len(), 2, "{:?}", src),
                _ => panic!(),
            }
        }
        let mut m = IndexMap::new();
        m.insert("a".to_string(), SynValue::Nothing);
        assert_eq!(encode(syn_list(vec![syn_map(m)])), "a\r\n\"\"\r\n");
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
