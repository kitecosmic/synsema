//! v0.6.45 (B1, B2): codificaciones de bytes y de texto que un programa no debería escribir a mano.
//!
//! - `gzip(datos)` / `gunzip(bytes, {max_bytes})` (RFC 1952). Logs, dumps y data lakes se publican
//!   como `.json.gz`/`.csv.gz` sueltos; antes gzip sólo existía dentro de `tar_extract`. `gunzip`
//!   acepta varios miembros concatenados (lo que escriben `cat a.gz b.gz` y varios exportadores) y
//!   corta una bomba: por defecto el tope es el mayor entre 256 MiB y 64 veces la entrada.
//! - `url_encode(texto)` / `url_decode(texto)` (RFC 3986): todo lo que no es "unreserved"
//!   (`A-Z a-z 0-9 - . _ ~`) se codifica, como `quote(s, safe='')` de Python — más estricto que
//!   `encodeURIComponent`, que deja pasar `!'()*`. `url_decode` es estricto como
//!   `decodeURIComponent`: un `%` mal formado o UTF-8 inválido son error, nunca un texto a medias
//!   (Python los deja pasar en silencio). `+` NO es un espacio: eso es la codificación de formularios.
//!
//! Puros, sin capability, en los tres hosts (nativo, `--profile pure`, wasm). Viven en stdlib y no en
//! core a propósito (ver `specs/donde-nace-cada-cosa.md`).

use std::io::{Cursor, Read, Write};
use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bytes, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn text_arg<'a>(args: &'a [SynValue], f: &str) -> Result<&'a str, Control> {
    match args.first() {
        Some(SynValue::Text(t)) => Ok(t),
        Some(SynValue::Secret(_)) => Err(err(format!("{}: cannot encode a secret (it would leave as text)", f))),
        Some(other) => Err(err(format!("{}: expects text, got {}", f, other.type_name()))),
        None => Err(err(format!("{}: missing the text", f))),
    }
}

/// Tope por defecto de `gunzip`: el mayor entre 256 MiB y 64 veces lo comprimido.
fn default_max(compressed: usize) -> u64 {
    (256u64 << 20).max(compressed as u64 * 64)
}

fn gzip(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "gzip";
    let data: &[u8] = match args.first() {
        Some(SynValue::Bytes(b)) => b,
        Some(SynValue::Text(t)) => t.as_bytes(),
        Some(SynValue::Secret(_)) => return Err(err(format!("{}: cannot compress a secret", F))),
        Some(other) => return Err(err(format!("{}: expects bytes or text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the data", F))),
    };
    // Determinista: sin nombre de archivo ni fecha en el encabezado (mtime 0), nivel por defecto.
    let mut enc = flate2::GzBuilder::new().mtime(0).write(Vec::new(), flate2::Compression::default());
    enc.write_all(data).map_err(|e| err(format!("{}: {}", F, e)))?;
    let out = enc.finish().map_err(|e| err(format!("{}: {}", F, e)))?;
    Ok(syn_bytes(out))
}

fn gunzip(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "gunzip";
    let data: &[u8] = match args.first() {
        Some(SynValue::Bytes(b)) => b,
        Some(SynValue::Text(_)) => {
            return Err(err(format!("{}: expects bytes (read the file with read_bytes, or http_bytes for a download)", F)))
        }
        Some(other) => return Err(err(format!("{}: expects bytes, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the bytes", F))),
    };
    let mut max = default_max(data.len());
    match args.get(1) {
        None | Some(SynValue::Nothing) => {}
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for (k, v) in m.iter() {
                match (k.as_ref(), v) {
                    ("max_bytes", SynValue::Number(n)) if n.is_integer() && n.to_f64() > 0.0 => {
                        max = n.to_f64() as u64;
                    }
                    ("max_bytes", other) => {
                        return Err(err(format!("{}: max_bytes must be a positive integer, got {}", F, other)))
                    }
                    (other, _) => return Err(err(format!("{}: unknown option {:?} (valid options: max_bytes)", F, other))),
                }
            }
        }
        Some(other) => return Err(err(format!("{}: the options must be a map, got {}", F, other.type_name()))),
    }
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return Err(err(format!("{}: not gzip data (it does not start with 1f 8b)", F)));
    }
    let mut dec = flate2::read::MultiGzDecoder::new(Cursor::new(data));
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = dec.read(&mut chunk).map_err(|e| err(format!("{}: {}", F, e)))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() as u64 > max {
            return Err(err(format!(
                "{}: the uncompressed data is larger than max_bytes ({} bytes); raise it with {{\"max_bytes\": n}} if you expect that much",
                F, max
            )));
        }
    }
    Ok(syn_bytes(out))
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn url_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    let s = text_arg(args, "url_encode")?;
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
            out.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
        }
    }
    Ok(syn_text(out))
}

fn url_decode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "url_decode";
    let s = text_arg(args, F)?;
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            match (b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c))) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => {
                    return Err(err(format!(
                        "{}: malformed escape at position {} (a % must be followed by two hex digits)",
                        F, i
                    )))
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map(syn_text)
        .map_err(|_| err(format!("{}: the decoded bytes are not valid UTF-8", F)))
}

pub fn register_encoding_builtins(interp: &Interpreter) {
    interp.register_builtin("gzip", 1, Rc::new(|_i, a, _l| gzip(a)));
    interp.register_builtin("gunzip", -1, Rc::new(|_i, a, _l| gunzip(a)));
    interp.register_builtin("url_encode", 1, Rc::new(|_i, a, _l| url_encode(a)));
    interp.register_builtin("url_decode", 1, Rc::new(|_i, a, _l| url_decode(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SynValue {
        syn_text(s)
    }

    #[test]
    fn url_encode_follows_rfc3986() {
        let enc = |s: &str| url_encode(&[t(s)]).ok().unwrap().to_string();
        assert_eq!(enc("a b&c=d/é~_.-"), "a%20b%26c%3Dd%2F%C3%A9~_.-");
        assert_eq!(enc("!'()*"), "%21%27%28%29%2A");
    }

    #[test]
    fn url_decode_is_strict_and_roundtrips() {
        let dec = |s: &str| url_decode(&[t(s)]);
        assert_eq!(dec("a%20b%26c%3Dd%2F%C3%A9").ok().unwrap().to_string(), "a b&c=d/é");
        assert_eq!(dec("a+b").ok().unwrap().to_string(), "a+b", "+ no es espacio");
        assert!(dec("50%").is_err());
        assert!(dec("%zz").is_err());
        assert!(dec("%C3").is_err(), "UTF-8 incompleto es error");
    }

    #[test]
    fn gzip_roundtrips_is_deterministic_and_reads_concatenated_members() {
        let z = gzip(&[t("hola mundo")]).ok().unwrap();
        let z2 = gzip(&[t("hola mundo")]).ok().unwrap();
        assert_eq!(z.to_string(), z2.to_string(), "mismo contenido, mismos bytes");
        let SynValue::Bytes(zb) = &z else { panic!() };
        let back = gunzip(&[z.clone()]).ok().unwrap();
        let SynValue::Bytes(bb) = &back else { panic!() };
        assert_eq!(&bb[..], b"hola mundo");
        // `cat a.gz b.gz` también es gzip válido.
        let mut two = zb.to_vec();
        two.extend_from_slice(zb);
        let both = gunzip(&[syn_bytes(two)]).ok().unwrap();
        let SynValue::Bytes(bothb) = &both else { panic!() };
        assert_eq!(&bothb[..], b"hola mundohola mundo");
    }

    #[test]
    fn gunzip_cuts_a_bomb_and_rejects_non_gzip() {
        let big = vec![0u8; 10_000];
        let z = gzip(&[syn_bytes(big)]).ok().unwrap();
        let mut m = synsema_core::types::SynMap::new();
        m.insert("max_bytes", synsema_core::types::syn_int(1000));
        let r = gunzip(&[z, SynValue::Map(m.into_ref())]);
        assert!(r.unwrap_err_msg().contains("larger than max_bytes"));
        assert!(gunzip(&[syn_bytes(b"no".to_vec())]).unwrap_err_msg().contains("not gzip"));
    }

    trait ErrMsg {
        fn unwrap_err_msg(self) -> String;
    }
    impl ErrMsg for Result<SynValue, Control> {
        fn unwrap_err_msg(self) -> String {
            match self {
                Err(Control::Error(e)) => e.to_string(),
                _ => panic!("esperaba un error"),
            }
        }
    }
}
