//! Parser JSON propio de `json_decode`, `jsonl_decode` y el `json` de una respuesta HTTP
//! (v0.6.29): produce `SynValue` directo y los números salen EXACTOS sin pasar por
//! `serde_json` con `arbitrary_precision` (que cambiaba el `Number` de todo el workspace).
//!
//! - Un entero de cualquier tamaño llega exacto (`18446744073709551615`, un uint256),
//!   hasta 4300 dígitos: el mismo tope que Python (`sys.int_info.default_max_str_digits`),
//!   porque convertir un entero decimal enorme es cuadrático y un documento hostil no debe
//!   poder comprar minutos de CPU con un número. Más largo es error: pasalo como texto.
//! - Con punto o exponente es float (redondeo correcto de `f64`); uno que no entra en un
//!   f64 (`1e400`) es error, no `inf` (un número que no entra se perdería en silencio). Los
//!   tokens `NaN`, `Infinity` y `-Infinity` (los que escriben `json_encode` y Python) son error
//!   por defecto —un `NaN` pasa cualquier control `monto <= 0`— y se leen con `parse_opts(…, true)`
//!   (`json_decode(text, allow_nan = true)`).
//! - Un BOM de UTF-8 al principio se ignora.
//! - Anidamiento hasta 128 niveles (el límite que tenía `serde_json`); claves repetidas: gana
//!   la última, en la posición de la primera; `\u` con pares sustitutos, un sustituto suelto
//!   es error.
//! - (F4.4) Las claves repetidas se guardan una vez por llamada (el `memo` del decodificador de
//!   CPython): mil registros `{"id": …}` comparten la clave `"id"`. Un texto sin escapes se lee
//!   del documento sin armar un `String` intermedio, y un objeto nace con la capacidad del
//!   anterior del mismo nivel (registros de la misma forma: sin crecer a saltos).

use std::borrow::Cow;
use std::collections::HashSet;

use synsema_core::synmap::map_from_pairs;
use synsema_core::types::{Key, SynMap};
use synsema_core::number::Number;
use synsema_core::types::{syn_bool, syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue};

/// Dígitos máximos de un entero JSON (el de Python).
pub const MAX_INT_DIGITS: usize = 4300;
const MAX_DEPTH: usize = 128;

/// Parsea un documento JSON completo (estricto: sin `NaN`/`Infinity`).
pub fn parse(text: &str) -> Result<SynValue, String> {
    parse_opts(text, false)
}

/// Como `parse`; con `allow_nan` lee también `NaN`, `Infinity` y `-Infinity`.
pub fn parse_opts(text: &str, allow_nan: bool) -> Result<SynValue, String> {
    parse_with(text, allow_nan, &mut Memo::default())
}

/// Lo que varios documentos de una misma llamada comparten (`jsonl_decode`): las claves ya vistas
/// y la capacidad de los objetos por nivel.
#[derive(Default)]
pub struct Memo {
    keys: HashSet<Key>,
    cap: Vec<usize>,
    bufs: Vec<Vec<(Key, SynValue)>>,
}

/// Como `parse_opts`, compartiendo `memo` con los otros documentos de la llamada.
pub fn parse_with(text: &str, allow_nan: bool, memo: &mut Memo) -> Result<SynValue, String> {
    // Un BOM de UTF-8 al principio (lo escribe Excel/Notepad) no es parte del documento.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        depth: 0,
        allow_nan,
        keys: std::mem::take(&mut memo.keys),
        cap: std::mem::take(&mut memo.cap),
        bufs: std::mem::take(&mut memo.bufs),
    };
    let r = p.document();
    memo.keys = std::mem::take(&mut p.keys);
    memo.cap = std::mem::take(&mut p.cap);
    memo.bufs = std::mem::take(&mut p.bufs);
    r
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
    allow_nan: bool,
    /// Las claves ya vistas en esta llamada (se comparten).
    keys: HashSet<Key>,
    /// Por nivel, cuántas claves tuvo el último objeto: la capacidad del siguiente.
    cap: Vec<usize>,
    /// Por nivel, el búfer de pares del objeto que se está leyendo (se reusa).
    bufs: Vec<Vec<(Key, SynValue)>>,
}

impl<'a> Parser<'a> {
    fn document(&mut self) -> Result<SynValue, String> {
        self.ws();
        let v = self.value()?;
        self.ws();
        if self.i < self.s.len() {
            return Err(self.fail("trailing characters"));
        }
        Ok(v)
    }

    fn fail(&self, msg: &str) -> String {
        let upto = &self.s[..self.i.min(self.s.len())];
        let line = upto.iter().filter(|&&c| c == b'\n').count() + 1;
        let col = match upto.iter().rposition(|&c| c == b'\n') {
            Some(nl) => std::str::from_utf8(&upto[nl + 1..]).map(|t| t.chars().count()).unwrap_or(0) + 1,
            None => std::str::from_utf8(upto).map(|t| t.chars().count()).unwrap_or(0) + 1,
        };
        format!("{} at line {} column {}", msg, line, col)
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    /// ¿Empieza acá la palabra `word`, entera (no seguida de una letra, dígito o `_`)?
    fn word_at(&self, word: &[u8]) -> bool {
        self.s[self.i..].starts_with(word)
            && !self.s.get(self.i + word.len()).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
    }

    fn lit(&mut self, word: &[u8], v: SynValue) -> Result<SynValue, String> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.fail("expected value"))
        }
    }

    fn value(&mut self) -> Result<SynValue, String> {
        match self.peek() {
            None => Err(self.fail("EOF while parsing a value")),
            Some(b'n') => self.lit(b"null", syn_nothing()),
            Some(b't') => self.lit(b"true", syn_bool(true)),
            Some(b'f') => self.lit(b"false", syn_bool(false)),
            Some(b'"') => Ok(match self.string()? {
                Cow::Borrowed(t) => syn_text(t),
                Cow::Owned(t) => syn_text(t),
            }),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            // `NaN`, `Infinity`, `-Infinity`: no son JSON estándar, pero son lo que escriben
            // `json_encode` (y Python) para esos floats; se leen sólo si se pidió.
            // Sólo la palabra entera: `NaNa` o `Infinityx` son basura, no un NaN.
            Some(b'N' | b'I') if !self.allow_nan && (self.word_at(b"NaN") || self.word_at(b"Infinity")) => Err(self.fail(
                "NaN/Infinity is not JSON (a NaN passes every `x <= 0` check) — to read them on purpose: json_decode(text, allow_nan = true)",
            )),
            Some(b'-') if !self.allow_nan && self.word_at(b"-Infinity") => Err(self.fail(
                "-Infinity is not JSON — to read it on purpose: json_decode(text, allow_nan = true)",
            )),
            Some(b'N' | b'I') if !self.allow_nan => Err(self.fail("expected value")),
            Some(b'N') => self.lit(b"NaN", SynValue::Number(Number::Float(f64::NAN))),
            Some(b'I') => self.lit(b"Infinity", SynValue::Number(Number::Float(f64::INFINITY))),
            Some(b'-') if self.s[self.i..].starts_with(b"-Infinity") => {
                self.lit(b"-Infinity", SynValue::Number(Number::Float(f64::NEG_INFINITY)))
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.fail("expected value")),
        }
    }

    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.fail("nesting deeper than 128 levels"));
        }
        Ok(())
    }

    fn array(&mut self) -> Result<SynValue, String> {
        self.enter()?;
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(syn_list(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                None => return Err(self.fail("EOF while parsing a list")),
                Some(_) => return Err(self.fail("expected `,` or `]`")),
            }
        }
        self.depth -= 1;
        Ok(syn_list(out))
    }

    fn object(&mut self) -> Result<SynValue, String> {
        self.enter()?;
        self.i += 1;
        let d = self.depth;
        // Los pares van a un búfer por nivel (se reusa entre objetos) y el mapa se arma al final
        // con su forma: un malloc por objeto (F4.5).
        if self.bufs.len() <= d {
            self.bufs.resize_with(d + 1, Vec::new);
        }
        let mut out = std::mem::take(&mut self.bufs[d]);
        out.clear();
        out.reserve(self.cap.get(d).copied().unwrap_or(0));
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            self.bufs[d] = out;
            return Ok(syn_map(SynMap::new()));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.fail(if self.peek().is_none() { "EOF while parsing an object" } else { "key must be a string" }));
            }
            let k = self.key()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.fail("expected `:`"));
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            out.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                None => return Err(self.fail("EOF while parsing an object")),
                Some(_) => return Err(self.fail("expected `,` or `}`")),
            }
        }
        if self.cap.len() <= d {
            self.cap.resize(d + 1, 0);
        }
        let m = map_from_pairs(&mut out);
        self.cap[d] = m.borrow().len();
        self.bufs[d] = out;
        self.depth -= 1;
        Ok(SynValue::Map(m))
    }

    /// Una clave: la misma `Key` para el mismo texto en toda la llamada.
    fn key(&mut self) -> Result<Key, String> {
        let t = self.string()?;
        if let Some(k) = self.keys.get(&*t) {
            return Ok(k.clone());
        }
        let k = match t {
            Cow::Borrowed(t) => Key::from(t),
            Cow::Owned(t) => Key::from(t),
        };
        self.keys.insert(k.clone());
        Ok(k)
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.i..self.i + 4).ok_or_else(|| self.fail("EOF while parsing a string"))?;
        let t = std::str::from_utf8(h).map_err(|_| self.fail("invalid escape"))?;
        let v = u32::from_str_radix(t, 16).map_err(|_| self.fail("invalid escape"))?;
        if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.fail("invalid escape"));
        }
        self.i += 4;
        Ok(v)
    }

    /// Un texto JSON: prestado del documento si no tiene escapes, armado si los tiene.
    fn string(&mut self) -> Result<Cow<'a, str>, String> {
        self.i += 1; // la comilla
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'"' || c == b'\\' || c < 0x20 {
                break;
            }
            self.i += 1;
        }
        if self.peek() == Some(b'"') {
            let s: &'a [u8] = self.s;
            let t = std::str::from_utf8(&s[start..self.i]).map_err(|_| self.fail("invalid UTF-8"))?;
            self.i += 1;
            return Ok(Cow::Borrowed(t));
        }
        // Con escapes (o un error): el camino de siempre desde el principio del texto.
        self.i = start;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // El texto de entrada es &str: cortar en un byte ASCII siempre cae en un borde.
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| self.fail("invalid UTF-8"))?);
            match self.peek() {
                None => return Err(self.fail("EOF while parsing a string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(Cow::Owned(out));
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.fail("EOF while parsing a string"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(self.fail("lone leading surrogate in hex escape"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.fail("lone leading surrogate in hex escape"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.fail("lone trailing surrogate in hex escape"));
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or_else(|| self.fail("invalid escape"))?);
                        }
                        _ => {
                            self.i -= 1;
                            return Err(self.fail("invalid escape"));
                        }
                    }
                }
                Some(_) => return Err(self.fail("control character (\\u0000-\\u001F) found while parsing a string")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.peek() {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<SynValue, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let int_start = self.i;
        let n = self.digits();
        if n == 0 {
            return Err(self.fail("invalid number"));
        }
        if n > 1 && self.s[int_start] == b'0' {
            self.i = int_start + 1;
            return Err(self.fail("invalid number (leading zero)"));
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.fail("invalid number"));
            }
            is_float = true;
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.i += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.fail("invalid number"));
            }
            is_float = true;
        }
        let t = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("0");
        if is_float {
            let f: f64 = t.parse().map_err(|_| self.fail("invalid number"))?;
            if !f.is_finite() {
                let at = self.i;
                self.i = start;
                let e = self.fail(&format!("number {} is out of range for a float (JSON has no infinity; pass it as text)", clip(t)));
                self.i = at;
                return Err(e);
            }
            return Ok(SynValue::Number(Number::Float(f)));
        }
        if n <= 18 {
            return Ok(syn_int(t.parse::<i64>().map_err(|_| self.fail("invalid number"))?));
        }
        if n > MAX_INT_DIGITS {
            self.i = start;
            return Err(self.fail(&format!(
                "integer with {} digits; the limit is {} (converting longer ones is quadratic — pass it as text)",
                n, MAX_INT_DIGITS
            )));
        }
        let b = t.parse::<num_bigint::BigInt>().map_err(|_| self.fail("invalid number"))?;
        Ok(SynValue::Number(Number::from_bigint(b)))
    }
}

fn clip(t: &str) -> String {
    if t.len() > 40 {
        format!("{}…", &t[..40])
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> String {
        parse(s).unwrap().to_string()
    }

    #[test]
    fn exact_numbers() {
        assert_eq!(ok("18446744073709551615"), "18446744073709551615");
        assert_eq!(ok("-9223372036854775808"), "-9223372036854775808");
        assert_eq!(ok("115792089237316195423570985008687907853269984665640564039457584007913129639935"),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert_eq!(ok("1.5"), "1.5");
        assert_eq!(ok("1e2"), "100.0");
        assert_eq!(ok("0.1"), "0.1");
        assert!(matches!(parse("12").unwrap(), SynValue::Number(Number::Int(12))));
    }

    #[test]
    fn limits_and_errors() {
        assert!(parse("1e400").unwrap_err().contains("out of range"));
        assert!(parse(&"9".repeat(4300)).is_ok());
        assert!(parse(&"9".repeat(4301)).unwrap_err().contains("4301 digits"));
        assert!(parse(&"[".repeat(129)).unwrap_err().contains("nesting"));
        assert!(parse(&format!("{}{}", "[".repeat(128), "]".repeat(128))).is_ok());
        assert!(parse("01").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1,}").is_err());
        assert!(parse("\"\\ud800\"").is_err());
        assert!(parse("\"a\nb\"").is_err());
        assert_eq!(parse("[1] x").unwrap_err(), "trailing characters at line 1 column 5");
        assert!(parse("").unwrap_err().starts_with("EOF"));
    }

    #[test]
    fn strings_and_objects() {
        assert_eq!(ok(r#""\ud83d\ude00 \u00e9 \/ \n""#), "😀 é / \n");
        assert_eq!(ok(r#"{"a": 1, "b": [true, null], "a": 2}"#), "{a: 2, b: [true, nothing]}");
        assert_eq!(ok(" \r\n\t{ } "), "{}");
    }
}

#[cfg(test)]
mod memo_tests {
    use std::rc::Rc;

    use super::*;

    fn map_keys(v: &SynValue) -> Vec<Key> {
        match v {
            SynValue::Map(m) => m.borrow().keys().cloned().collect(),
            _ => panic!("no es un mapa"),
        }
    }

    /// F4.4: las claves repetidas de un documento son la misma `Key` (una sola copia del texto);
    /// valores, orden y claves con escapes, como siempre.
    #[test]
    fn repeated_keys_are_shared() {
        let v = parse(r#"[{"id": 1, "v": "a"}, {"v": "b", "id": 2}, {"id": 3, "id": 4}, {"a\"b": 1, "é": 2}]"#).unwrap();
        let rows = match &v {
            SynValue::List(l) => l.borrow().clone(),
            _ => panic!(),
        };
        let (k0, k1, k2, k3) = (map_keys(&rows[0]), map_keys(&rows[1]), map_keys(&rows[2]), map_keys(&rows[3]));
        assert_eq!(k0, ["id", "v"].map(Key::from).to_vec());
        assert_eq!(k1, ["v", "id"].map(Key::from).to_vec());
        assert!(Rc::ptr_eq(k0[0].rc(), k1[1].rc()), "\"id\" se copió");
        assert!(Rc::ptr_eq(k0[1].rc(), k1[0].rc()), "\"v\" se copió");
        assert!(Rc::ptr_eq(k0[0].rc(), k2[0].rc()));
        assert_eq!(k2.len(), 1);
        assert_eq!(k3, ["a\"b", "é"].map(Key::from).to_vec());
        assert_eq!(v.to_string(), r#"[{id: 1, v: "a"}, {v: "b", id: 2}, {id: 4}, {a"b: 1, é: 2}]"#);
    }

    /// `parse_with` comparte las claves entre documentos (`jsonl_decode`).
    #[test]
    fn memo_spans_documents() {
        let mut memo = Memo::default();
        let a = parse_with(r#"{"k": 1}"#, false, &mut memo).unwrap();
        let b = parse_with(r#"{"k": 2}"#, false, &mut memo).unwrap();
        assert!(Rc::ptr_eq(map_keys(&a)[0].rc(), map_keys(&b)[0].rc()));
    }
}
