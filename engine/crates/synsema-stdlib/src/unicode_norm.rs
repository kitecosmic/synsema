//! Normalización Unicode (v0.6.60): `nfc`, `nfd`, `nfkc`, `nfkd`. Texto → texto, puros, sin
//! capability; compilan para wasm.
//!
//! Cuatro funciones y no una con un argumento `"NFC"`: son un conjunto cerrado, y el argumento
//! sólo agregaría un camino de error. Son los nombres del estándar (UAX #15) y los de Rust
//! (`.nfc()`), Go (`norm.NFC`) y Zig (`zg`).
//!
//! `==`, las claves de mapa y los hashes siguen comparando bytes, como en Rust, Go, Zig y C:
//! `"\u00e9" == "e\u0301"` es `false`. Quien quiere que dos escrituras del mismo texto den igual
//! normaliza las dos con la misma forma.
//!
//! Sólo texto: `bytes`, números y listas son error (no se convierten ni se recorren). Un texto de
//! Synsema siempre es UTF-8 válido, así que no hay «entrada inválida».
//!
//! Las tablas son las de la crate `unicode-normalization`: [`UNICODE_VERSION`]. Subir la crate
//! cambia cómo se normalizan los caracteres que hoy no están asignados (la política de
//! estabilidad de Unicode cubre sólo los asignados), y con eso un `sha256` o una clave de mapa:
//! un test fija la versión para que el cambio pase por el CHANGELOG.

use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_text, SynValue};
use unicode_normalization::{
    is_nfc_quick, is_nfd_quick, is_nfkc_quick, is_nfkd_quick, IsNormalized, UnicodeNormalization,
};

/// La versión de Unicode de las cuatro formas.
pub const UNICODE_VERSION: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Nfc,
    Nfd,
    Nfkc,
    Nfkd,
}

impl Form {
    pub const ALL: [Form; 4] = [Form::Nfc, Form::Nfd, Form::Nfkc, Form::Nfkd];

    /// El nombre del builtin.
    pub fn name(self) -> &'static str {
        match self {
            Form::Nfc => "nfc",
            Form::Nfd => "nfd",
            Form::Nfkc => "nfkc",
            Form::Nfkd => "nfkd",
        }
    }

    /// La comprobación rápida de UAX #15: `Yes` si el texto ya está en la forma sin lugar a dudas.
    fn quick(self, s: &str) -> IsNormalized {
        match self {
            Form::Nfc => is_nfc_quick(s.chars()),
            Form::Nfd => is_nfd_quick(s.chars()),
            Form::Nfkc => is_nfkc_quick(s.chars()),
            Form::Nfkd => is_nfkd_quick(s.chars()),
        }
    }

    /// `s` en esta forma, o `None` si ya lo estaba (el llamador devuelve el mismo valor, sin copia).
    pub fn normalize(self, s: &str) -> Option<String> {
        if self.quick(s) == IsNormalized::Yes {
            return None;
        }
        let out: String = match self {
            Form::Nfc => s.nfc().collect(),
            Form::Nfd => s.nfd().collect(),
            Form::Nfkc => s.nfkc().collect(),
            Form::Nfkd => s.nfkd().collect(),
        };
        // La comprobación rápida contesta «quizás» con textos que sí estaban normalizados.
        (out != s).then_some(out)
    }
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// El cuerpo de los cuatro builtins.
pub fn normalize_builtin(form: Form, args: &[SynValue]) -> Result<SynValue, Control> {
    let name = form.name();
    // Si falta, el error genérico que el intérprete completa (`nfc() needs 1 argument, got 0`),
    // como en el resto de los builtins; que sobren lo corta el intérprete antes de llamar.
    if args.is_empty() {
        return Err(err("missing argument"));
    }
    if args.len() > 1 {
        return Err(err(format!("{}() takes at most 1 argument, got {}", name, args.len())));
    }
    match &args[0] {
        SynValue::Text(t) => Ok(match form.normalize(t) {
            None => args[0].clone(),
            Some(out) => syn_text(out),
        }),
        SynValue::Bytes(_) => Err(err(format!(
            "{} expects text, got bytes — decode it first: {}(decode(b))",
            name, name
        ))),
        other => Err(err(format!("{} expects text, got {}", name, other.type_name()))),
    }
}

/// Registra los cuatro builtins (lo llaman `engine.rs` y `synsema-wasm`, junto a `bits`).
pub fn register_unicode_norm_builtins(interp: &Interpreter) {
    for form in Form::ALL {
        interp.register_builtin(form.name(), 1, Rc::new(move |_i, a, _l| normalize_builtin(form, a)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::{syn_bytes, syn_int, syn_list};

    fn cps(s: &str) -> String {
        s.chars().map(|c| format!("{:04X}", c as u32)).collect::<Vec<_>>().join(" ")
    }
    fn run(form: Form, s: &str) -> String {
        match normalize_builtin(form, &[syn_text(s)]) {
            Ok(SynValue::Text(t)) => cps(&t),
            _ => panic!("expected text"),
        }
    }
    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!("expected an error"),
        }
    }

    /// La tabla A del diseño: entrada, NFC, NFD, NFKC, NFKD (puntos de código). Los esperados
    /// coinciden con `unicodedata.normalize` de Python 3.12 (`specs/v0.6.60-sondas`).
    const TABLE: &[(&str, &str, &str, &str, &str)] = &[
        ("e\u{301}", "00E9", "0065 0301", "00E9", "0065 0301"),
        ("\u{e9}", "00E9", "0065 0301", "00E9", "0065 0301"),
        ("\u{fb01}", "FB01", "FB01", "0066 0069", "0066 0069"),
        ("\u{ff21}", "FF21", "FF21", "0041", "0041"),
        ("x\u{b2}", "0078 00B2", "0078 00B2", "0078 0032", "0078 0032"),
        ("\u{1112}\u{1161}\u{11ab}", "D55C", "1112 1161 11AB", "D55C", "1112 1161 11AB"),
        ("\u{d55c}", "D55C", "1112 1161 11AB", "D55C", "1112 1161 11AB"),
        ("\u{212b}", "00C5", "0041 030A", "00C5", "0041 030A"),
        // El caso que distingue a las cuatro formas (UAX #15, figura 6).
        ("\u{1e9b}\u{323}", "1E9B 0323", "017F 0323 0307", "1E69", "0073 0323 0307"),
        // Orden canónico: las dos escrituras dan lo mismo.
        ("a\u{323}\u{307}", "1EA1 0307", "0061 0323 0307", "1EA1 0307", "0061 0323 0307"),
        ("a\u{307}\u{323}", "1EA1 0307", "0061 0323 0307", "1EA1 0307", "0061 0323 0307"),
        ("", "", "", "", ""),
        ("hola", "0068 006F 006C 0061", "0068 006F 006C 0061", "0068 006F 006C 0061", "0068 006F 006C 0061"),
    ];

    #[test]
    fn each_form_gives_its_own_result() {
        for (input, nfc, nfd, nfkc, nfkd) in TABLE {
            assert_eq!(run(Form::Nfc, input), *nfc, "nfc({})", cps(input));
            assert_eq!(run(Form::Nfd, input), *nfd, "nfd({})", cps(input));
            assert_eq!(run(Form::Nfkc, input), *nfkc, "nfkc({})", cps(input));
            assert_eq!(run(Form::Nfkd, input), *nfkd, "nfkd({})", cps(input));
        }
    }

    #[test]
    fn normalizing_twice_changes_nothing() {
        for (input, ..) in TABLE {
            for form in Form::ALL {
                let once = form.normalize(input).unwrap_or_else(|| input.to_string());
                assert_eq!(form.normalize(&once), None, "{}({})", form.name(), cps(input));
            }
        }
    }

    #[test]
    fn a_text_already_in_the_form_comes_back_as_the_same_value() {
        assert_eq!(Form::Nfc.normalize("hola"), None);
        assert_eq!(Form::Nfd.normalize("hola"), None);
        // ya en NFC, pero la comprobación rápida dice «quizás» (U+0307 puede componer)
        assert_eq!(Form::Nfc.normalize("\u{1ea1}\u{307}"), None);
        assert_eq!(Form::Nfc.normalize("\u{e9}"), None);
        assert_eq!(Form::Nfd.normalize("\u{e9}").as_deref(), Some("e\u{301}"));
    }

    #[test]
    fn only_text_is_accepted() {
        for form in Form::ALL {
            let n = form.name();
            assert_eq!(
                msg(normalize_builtin(form, &[syn_bytes("\u{e9}".as_bytes().to_vec())])),
                format!("{} expects text, got bytes — decode it first: {}(decode(b))", n, n)
            );
            assert_eq!(msg(normalize_builtin(form, &[syn_int(5)])), format!("{} expects text, got number", n));
            assert_eq!(msg(normalize_builtin(form, &[SynValue::Nothing])), format!("{} expects text, got nothing", n));
            assert_eq!(
                msg(normalize_builtin(form, &[syn_list(vec![syn_text("\u{e9}")])])),
                format!("{} expects text, got list", n)
            );
            assert_eq!(msg(normalize_builtin(form, &[])), "missing argument");
        }
    }

    /// Subir la crate cambia la normalización de los caracteres sin asignar: que sea a la vista.
    #[test]
    fn the_unicode_version_is_the_documented_one() {
        assert_eq!(UNICODE_VERSION, (17, 0, 0), "CHANGELOG + docs dicen Unicode 17.0");
        // U+A7F1 entró después de Unicode 15: con estas tablas NFKC lo lleva a `S`.
        assert_eq!(run(Form::Nfkc, "\u{a7f1}"), "0053");
    }

    #[test]
    fn long_inputs_stay_linear() {
        let big = "\u{e9}".repeat(200_000);
        let d = Form::Nfd.normalize(&big).unwrap();
        assert_eq!(d.len(), 600_000);
        assert_eq!(Form::Nfc.normalize(&d).as_deref(), Some(big.as_str()));
        // una letra con muchísimas marcas en desorden: el orden canónico no es cuadrático
        let marks = format!("a{}", "\u{307}\u{323}".repeat(100_000));
        let n = Form::Nfd.normalize(&marks).unwrap();
        assert_eq!(n.chars().count(), 200_001);
        assert!(n.starts_with("a\u{323}"));
    }
}
