//! `canonical_json(value) → text`: JSON Canonicalization Scheme, **RFC 8785 (JCS)**. El
//! encoder canónico que un documento firmado necesita (T3/T4 del spec de identidad): dos
//! implementaciones que sigan el RFC producen los MISMOS bytes para el mismo valor, así una
//! firma hecha acá la verifica cualquier librería DID/VC del mundo, y al revés.
//!
//! Reglas del RFC, todas:
//! - claves de objeto ordenadas por **unidades de código UTF-16** (no por codepoint: el
//!   emoji `😂` (U+1F602, surrogates D83D DE02) va ANTES que `ﬃ` (U+FB03));
//! - sin espacios; literales `true`/`false`/`null` (`nothing` → `null`);
//! - strings escapadas como `JSON.stringify` de ECMAScript: `\"` `\\` `\b` `\f` `\n` `\r`
//!   `\t`, el resto de los controles `< 0x20` como `\u00xx` (hex minúscula), y NADA más
//!   (ni `/`, ni no-ASCII, que va en UTF-8 tal cual);
//! - números como `Number.prototype.toString` de ECMAScript: la representación más corta
//!   que redondea de vuelta, `0` para ±0, exponente sólo fuera de `1e-7 ≤ |x| < 1e21`
//!   (`1e+21`, `1e-7`), sin `+` ni ceros de más.
//!
//! Los números de JCS son **doubles IEEE-754**. Synsema tiene enteros grandes y decimales
//! exactos; convertirlos en silencio a double perdería precisión, y este builtin no miente:
//! un entero fuera de ±2⁵³ o un decimal con más de 15 dígitos significativos es un ERROR que
//! dice qué hacer (ponerlo como texto — que es la doctrina del ledger para el dinero de todos
//! modos). `bytes` tampoco existe en JSON: codificalos vos (`decode(b, "base64url")`), explícito
//! antes que magia. Un `secret` jamás se serializa.

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

const MAX_DEPTH: usize = 64;

/// `Number.prototype.toString` de ECMAScript para un double finito (ES2023 §6.1.6.1.20).
pub fn es_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string(); // también -0
    }
    let neg = x < 0.0;
    let a = x.abs();
    // `{:e}` de Rust da los dígitos MÁS CORTOS que redondean de vuelta ("3.333333333333333e8").
    let s = format!("{:e}", a);
    let (mant, exp) = s.split_once('e').expect("formato científico");
    let exp: i32 = exp.parse().expect("exponente");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;
    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e < 0 { "-" } else { "+" };
        if k == 1 {
            format!("{}e{}{}", digits, sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
        }
    };
    if neg {
        format!("-{}", body)
    } else {
        body
    }
}

/// Escapa un string como `JSON.stringify` (RFC 8785 §3.2.2.2).
pub fn es_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_SAFE: i64 = 9_007_199_254_740_992; // 2^53

fn number_text(n: &Number, path: &str) -> Result<String, Control> {
    match n {
        Number::Int(i) => {
            if i.unsigned_abs() > MAX_SAFE as u64 {
                return Err(err(format!(
                    "canonical_json: {} is an integer beyond 2^53 ({}); JCS numbers are IEEE doubles and cannot carry it exactly — put it in the document as text",
                    path, i
                )));
            }
            Ok(i.to_string())
        }
        Number::Big(b) => Err(err(format!(
            "canonical_json: {} is an integer beyond 2^53 ({}); JCS numbers are IEEE doubles and cannot carry it exactly — put it in the document as text",
            path, b
        ))),
        Number::Float(f) => {
            if !f.is_finite() {
                return Err(err(format!(
                    "canonical_json: {} is {} and JSON has no such number",
                    path, f
                )));
            }
            Ok(es_number(*f))
        }
        Number::Decimal(_) | Number::BigDec(_) => {
            // Un decimal entra si vuelve EXACTO del double más corto: ≤ 15 dígitos
            // significativos garantizan la vuelta; más, y el double miente.
            let text = {
                let (mut m, mut s) = n.exact_ratio().unwrap();
                let ten = num_bigint::BigInt::from(10);
                while s > 0 && (&m % &ten) == num_bigint::BigInt::from(0) {
                    m /= &ten;
                    s -= 1;
                }
                Number::decimal_from_parts(m, s).to_string()
            };
            let sig: usize = text.chars().filter(|c| c.is_ascii_digit()).collect::<String>().trim_start_matches('0').len();
            if sig > 15 {
                return Err(err(format!(
                    "canonical_json: {} is the decimal {} with more than 15 significant digits; JCS numbers are IEEE doubles and would round it — put it in the document as text",
                    path, text
                )));
            }
            Ok(es_number(n.to_f64()))
        }
    }
}

fn write(v: &SynValue, out: &mut String, depth: usize, path: &str) -> Result<(), Control> {
    if depth > MAX_DEPTH {
        return Err(err(format!("canonical_json: {} is nested deeper than {} levels", path, MAX_DEPTH)));
    }
    match v {
        SynValue::Nothing => out.push_str("null"),
        SynValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        SynValue::Number(n) => out.push_str(&number_text(n, path)?),
        SynValue::Text(s) => es_string(s, out),
        SynValue::List(l) => {
            out.push('[');
            for (i, item) in l.borrow().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out, depth + 1, &format!("{}[{}]", path, i))?;
            }
            out.push(']');
        }
        SynValue::Map(m) => {
            let m = m.borrow();
            // Orden por unidades de código UTF-16 (RFC 8785 §3.2.3).
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| {
                let ua: Vec<u16> = a.encode_utf16().collect();
                let ub: Vec<u16> = b.encode_utf16().collect();
                ua.cmp(&ub)
            });
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                es_string(k, out);
                out.push(':');
                write(&m[k.as_str()], out, depth + 1, &format!("{}.{}", path, k))?;
            }
            out.push('}');
        }
        SynValue::Bytes(_) => {
            return Err(err(format!(
                "canonical_json: {} is bytes and JSON has no bytes — encode them first (decode(b, \"base64url\") or decode(b, \"hex\"))",
                path
            )))
        }
        SynValue::Secret(_) => {
            return Err(err(format!(
                "canonical_json: {} is a secret; a secret is never serialized (reveal it on purpose if that is really what you mean)",
                path
            )))
        }
        SynValue::Task(_) | SynValue::Builtin(_) => {
            return Err(err(format!(
                "canonical_json: {} is {}, not data — JSON cannot represent it (only text, numbers, bools, nothing, lists and maps)",
                path,
                synsema_core::rng::code_noun(v)
            )))
        }
        other => {
            return Err(err(format!(
                "canonical_json: {} is a {} and JSON cannot represent it (only text, numbers, bools, nothing, lists and maps)",
                path,
                other.type_name()
            )))
        }
    }
    Ok(())
}

/// Los bytes canónicos (UTF-8) de un valor, como texto.
pub fn canonical_json(v: &SynValue) -> Result<String, Control> {
    let mut out = String::new();
    write(v, &mut out, 0, "the value")?;
    Ok(out)
}

fn b_canonical_json(args: &[SynValue]) -> Result<SynValue, Control> {
    if args.len() != 1 {
        return Err(err("canonical_json(value) takes exactly 1 argument"));
    }
    Ok(syn_text(canonical_json(&args[0])?))
}

/// Registra `canonical_json`. PURO (sin capability).
pub fn register_canonical_builtins(interp: &Interpreter) {
    interp.register_builtin("canonical_json", 1, std::rc::Rc::new(|_i, a, _l| b_canonical_json(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use synsema_core::types::{syn_int, syn_list, syn_map, syn_nothing};

    fn text(s: &str) -> SynValue {
        syn_text(s)
    }
    fn float(f: f64) -> SynValue {
        SynValue::Number(Number::Float(f))
    }
    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }
    fn canon(v: &SynValue) -> String {
        canonical_json(v).unwrap_or_else(|e| match e {
            Control::Error(e) => panic!("{}", e),
            _ => panic!("control"),
        })
    }
    fn fails(v: &SynValue) -> String {
        match canonical_json(v) {
            Err(Control::Error(e)) => e.to_string(),
            Ok(s) => panic!("esperaba error, got {}", s),
            Err(_) => panic!("control"),
        }
    }

    /// El ejemplo de RFC 8785 §3.2.3 (y Appendix A): números, string con escapes, literales.
    #[test]
    fn rfc_8785_example() {
        let v = map(vec![
            (
                "numbers",
                syn_list(vec![float(333333333.33333329), float(1e30), float(4.50), float(2e-3), float(0.000000000000000000000000001)]),
            ),
            ("string", text("\u{20ac}$\u{000F}\u{000a}A'\u{0042}\u{0022}\u{005c}\\\"/")),
            ("literals", syn_list(vec![syn_nothing(), SynValue::Bool(true), SynValue::Bool(false)])),
        ]);
        assert_eq!(
            canon(&v),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    /// Orden de claves por unidades UTF-16 (RFC 8785 §3.2.3): el emoji va antes que `ﬃ`.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        let v = map(vec![
            ("\u{20ac}", text("Euro Sign")),
            ("\r", text("Carriage Return")),
            ("\u{fb33}", text("Hebrew Letter Dalet With Dagesh")),
            ("1", text("One")),
            ("\u{1f602}", text("Smiley")),
            ("\u{80}", text("Control")),
            ("\u{f6}", text("Latin Small Letter O With Diaeresis")),
        ]);
        assert_eq!(
            canon(&v),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f602}\":\"Smiley\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    /// Números como ECMAScript (Appendix B del RFC y los bordes del exponente).
    #[test]
    fn numbers_follow_ecmascript() {
        for (x, want) in [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.5, "-1.5"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (9007199254740992.0, "9007199254740992"),
            (333333333.33333329, "333333333.3333333"),
            (0.1, "0.1"),
            (123456789012345680000.0, "123456789012345680000"),
            (1.5e-10, "1.5e-10"),
        ] {
            assert_eq!(es_number(x), want, "{}", x);
        }
        assert_eq!(canon(&syn_int(42)), "42");
        assert_eq!(canon(&syn_int(-9007199254740992)), "-9007199254740992");
        let dec = SynValue::Number(Number::Decimal("19.99".parse().unwrap()));
        assert_eq!(canon(&dec), "19.99");
    }

    /// Lo que un double no puede llevar exacto es ERROR con el fix, nunca un redondeo callado.
    #[test]
    fn precision_is_never_lost_silently() {
        let e = fails(&syn_int(9007199254740993));
        assert!(e.contains("beyond 2^53") && e.contains("as text"), "{}", e);
        let big = SynValue::Number(Number::Decimal("0.1234567890123456789".parse().unwrap()));
        let e = fails(&map(vec![("amount", big)]));
        assert!(e.contains("the value.amount") && e.contains("15 significant digits"), "{}", e);
        let e = fails(&float(f64::INFINITY));
        assert!(e.contains("JSON has no such number"), "{}", e);
        let e = fails(&SynValue::Bytes(std::rc::Rc::from(vec![1u8, 2].into_boxed_slice())));
        assert!(e.contains("bytes") && e.contains("base64url"), "{}", e);
    }

    #[test]
    fn nesting_paths_and_strings() {
        let v = map(vec![("b", syn_list(vec![map(vec![("z", text("x")), ("a", syn_nothing())])])), ("a", text("tab\there"))]);
        assert_eq!(canon(&v), "{\"a\":\"tab\\there\",\"b\":[{\"a\":null,\"z\":\"x\"}]}");
        assert_eq!(canon(&text("/slash and ünïcode ✓")), "\"/slash and ünïcode ✓\"");
        assert_eq!(canon(&text("\u{1}\u{1f}\u{7f}")), "\"\\u0001\\u001f\u{7f}\"");
    }
}
