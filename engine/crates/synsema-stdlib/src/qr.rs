//! v0.6.45 (B7): códigos QR (ISO/IEC 18004). Emparejar un dispositivo, compartir un enlace a un
//! teléfono, TOTP (`otpauth://`), pagos (BIP-21, Pix, Lightning): todo pasa por un QR, y escribirlo
//! bien no es trivial (Reed-Solomon, máscaras, BCH de formato y versión). Atril y Lampson lo
//! escribían por su cuenta (Atril: 300 líneas en Synsema, versiones 1–10, nivel L).
//!
//! - `qr_matrix(datos, {ecc, version})` → filas de 0/1 (sin zona silenciosa): la base para dibujarlo
//!   como quieras (terminal, canvas, otra herramienta).
//! - `qr_svg(datos, {ecc, version, module, margin, dark, light})` → SVG listo, con la zona silenciosa
//!   de 4 módulos que pide la norma. Determinista: mismo dato y mismas opciones, mismos bytes.
//!
//! `ecc`: `"L"`, `"M"` (por defecto), `"Q"` o `"H"`. `version`: 1–40 (por defecto, la más chica que
//! entra). La codificación la hace el crate `qrcode` (kennytm, puro Rust, sin dependencias con
//! `default-features = false`); el SVG se arma acá.

use std::rc::Rc;

use qrcode::{Color, EcLevel, QrCode, Version};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_int, syn_list, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

struct Opts {
    ecc: EcLevel,
    version: Option<i16>,
    module: u32,
    margin: u32,
    dark: String,
    light: String,
}

fn color_ok(c: &str) -> bool {
    // Sólo colores que no pueden romper el atributo: #rgb/#rrggbb o un nombre en minúsculas.
    (c.starts_with('#') && matches!(c.len(), 4 | 7) && c[1..].chars().all(|x| x.is_ascii_hexdigit()))
        || (!c.is_empty() && c.chars().all(|x| x.is_ascii_lowercase()))
}

fn parse_opts(args: &[SynValue], f: &str, svg: bool) -> Result<Opts, Control> {
    let mut o = Opts { ecc: EcLevel::M, version: None, module: 8, margin: 4, dark: "#000000".into(), light: "#ffffff".into() };
    let m = match args.get(1) {
        None | Some(SynValue::Nothing) => return Ok(o),
        Some(SynValue::Map(m)) => m.clone(),
        Some(other) => return Err(err(format!("{}: the options must be a map, got {}", f, other.type_name()))),
    };
    let valid = if svg { "ecc, version, module, margin, dark, light" } else { "ecc, version" };
    for (k, v) in m.borrow().iter() {
        let int = |min: i64, max: i64| -> Result<i64, Control> {
            match v {
                SynValue::Number(n) if n.is_integer() && (min..=max).contains(&(n.to_f64() as i64)) => Ok(n.to_f64() as i64),
                other => Err(err(format!("{}: {} must be an integer from {} to {}, got {}", f, k.as_str(), min, max, other))),
            }
        };
        match k.as_str() {
            "ecc" => {
                o.ecc = match v {
                    SynValue::Text(t) => match t.to_ascii_uppercase().as_str() {
                        "L" => EcLevel::L,
                        "M" => EcLevel::M,
                        "Q" => EcLevel::Q,
                        "H" => EcLevel::H,
                        _ => return Err(err(format!("{}: ecc must be \"L\", \"M\", \"Q\" or \"H\", got {:?}", f, t.to_string()))),
                    },
                    other => return Err(err(format!("{}: ecc must be \"L\", \"M\", \"Q\" or \"H\", got {}", f, other))),
                }
            }
            "version" => o.version = Some(int(1, 40)? as i16),
            "module" if svg => o.module = int(1, 100)? as u32,
            "margin" if svg => o.margin = int(0, 40)? as u32,
            "dark" | "light" if svg => {
                let SynValue::Text(t) = v else {
                    return Err(err(format!("{}: {} must be a color like \"#000000\", got {}", f, k.as_str(), v.type_name())));
                };
                if !color_ok(t) {
                    return Err(err(format!("{}: {} must be #rgb, #rrggbb or a color name, got {:?}", f, k.as_str(), t.to_string())));
                }
                if k.as_str() == "dark" {
                    o.dark = t.to_string();
                } else {
                    o.light = t.to_string();
                }
            }
            other => return Err(err(format!("{}: unknown option {:?} (valid: {})", f, other, valid))),
        }
    }
    Ok(o)
}

fn encode(args: &[SynValue], f: &str, o: &Opts) -> Result<QrCode, Control> {
    let data: &[u8] = match args.first() {
        Some(SynValue::Text(t)) => t.as_bytes(),
        Some(SynValue::Bytes(b)) => b,
        Some(SynValue::Secret(_)) => return Err(err(format!("{}: cannot draw a secret (it would be readable by anyone who sees it)", f))),
        Some(other) => return Err(err(format!("{}: expects text or bytes, got {}", f, other.type_name()))),
        None => return Err(err(format!("{}: missing the data", f))),
    };
    let r = match o.version {
        Some(v) => QrCode::with_version(data, Version::Normal(v), o.ecc),
        None => QrCode::with_error_correction_level(data, o.ecc),
    };
    r.map_err(|e| {
        err(match e {
            qrcode::types::QrError::DataTooLong => format!(
                "{}: {} bytes do not fit{} (a QR holds up to 2953 bytes at ecc \"L\", version 40)",
                f,
                data.len(),
                o.version.map(|v| format!(" in version {} at this ecc", v)).unwrap_or_else(|| " at this ecc".into())
            ),
            other => format!("{}: {}", f, other),
        })
    })
}

fn qr_matrix(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "qr_matrix";
    let o = parse_opts(args, F, false)?;
    let code = encode(args, F, &o)?;
    let w = code.width();
    let colors = code.to_colors();
    let rows = colors
        .chunks(w)
        .map(|row| syn_list(row.iter().map(|c| syn_int(if *c == Color::Dark { 1 } else { 0 })).collect()))
        .collect();
    Ok(syn_list(rows))
}

fn qr_svg(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "qr_svg";
    let o = parse_opts(args, F, true)?;
    let code = encode(args, F, &o)?;
    let w = code.width() as u32;
    let colors = code.to_colors();
    let total = (w + 2 * o.margin) * o.module;
    let mut path = String::new();
    for (i, c) in colors.iter().enumerate() {
        if *c == Color::Dark {
            let (x, y) = ((i as u32 % w + o.margin) * o.module, (i as u32 / w + o.margin) * o.module);
            path.push_str(&format!("M{x} {y}h{m}v{m}h-{m}z", m = o.module));
        }
    }
    Ok(syn_text(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{t}\" height=\"{t}\" viewBox=\"0 0 {t} {t}\" shape-rendering=\"crispEdges\"><rect width=\"{t}\" height=\"{t}\" fill=\"{}\"/><path fill=\"{}\" d=\"{}\"/></svg>",
        o.light,
        o.dark,
        path,
        t = total
    )))
}

pub fn register_qr_builtins(interp: &Interpreter) {
    interp.register_builtin("qr_matrix", -1, Rc::new(|_i, a, _l| qr_matrix(a)));
    interp.register_builtin("qr_svg", -1, Rc::new(|_i, a, _l| qr_svg(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::SynMap;

    fn opts(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.clone());
        }
        SynValue::Map(m.into_ref())
    }

    fn rows(v: SynValue) -> Vec<Vec<i64>> {
        let SynValue::List(l) = v else { panic!() };
        let items = l.borrow().to_vec();
        items
            .iter()
            .map(|r| {
                let SynValue::List(r) = r else { panic!() };
                let cells = r.borrow().to_vec();
                cells.iter().map(|c| c.to_string().parse().unwrap()).collect()
            })
            .collect()
    }

    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba un error"),
        }
    }

    #[test]
    fn matrix_has_the_iso_structure() {
        let m = rows(qr_matrix(&[syn_text("hola")]).ok().unwrap());
        assert_eq!(m.len(), 21, "versión 1 = 21×21");
        assert!(m.iter().all(|r| r.len() == 21));
        // Patrón de búsqueda arriba a la izquierda: borde oscuro de 7×7 y anillo claro.
        assert!((0..7).all(|i| m[0][i] == 1 && m[6][i] == 1 && m[i][0] == 1 && m[i][6] == 1));
        assert!((1..6).all(|i| m[1][i] == 0 && m[5][i] == 0));
        let v10 = rows(qr_matrix(&[syn_text("hola"), opts(&[("version", syn_int(10))])]).ok().unwrap());
        assert_eq!(v10.len(), 57, "versión 10 = 17 + 4·10");
    }

    #[test]
    fn svg_is_deterministic_and_has_the_quiet_zone() {
        let a = qr_svg(&[syn_text("hola")]).ok().unwrap().to_string();
        assert_eq!(a, qr_svg(&[syn_text("hola")]).ok().unwrap().to_string());
        // (21 + 2·4) módulos × 8 px.
        assert!(a.contains("viewBox=\"0 0 232 232\""), "{}", &a[..120]);
    }

    #[test]
    fn errors_are_clear() {
        assert!(msg(qr_matrix(&[syn_text(&"x".repeat(4000))])).contains("do not fit"));
        assert!(msg(qr_matrix(&[syn_text("a"), opts(&[("ecc", syn_text("Z"))])])).contains("ecc must be"));
        assert!(msg(qr_matrix(&[syn_text("a"), opts(&[("module", syn_int(4))])])).contains("unknown option"));
        assert!(msg(qr_svg(&[syn_text("a"), opts(&[("dark", syn_text("red\" onload=\""))])])).contains("must be #rgb"));
        assert!(msg(qr_svg(&[syn_text(&"x".repeat(30)), opts(&[("version", syn_int(1)), ("ecc", syn_text("H"))])])).contains("version 1"));
    }
}
