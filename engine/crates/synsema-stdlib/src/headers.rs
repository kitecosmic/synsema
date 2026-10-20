//! v0.6.45 (B3): `header(r, nombre)` — un header HTTP sin distinguir mayúsculas (RFC 9110 los define
//! así). `headers of r` conserva la capitalización que mandó el servidor (decisión de v0.6.20, se
//! mantiene), y `get(headers of r, "retry-after")` daba `nothing` con `Retry-After` presente: los
//! reintentos ignoraban la espera que pedía la API sin que nada fallara.
//!
//! `r` puede ser una respuesta (`{status, headers, …}`: se mira su `headers`) o el mapa de headers
//! directamente (`request.headers` bajo `serve`). Devuelve el valor como texto, o `nothing` si no
//! está. Puro, en los tres hosts.

use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::SynValue;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn header(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "header";
    let name = match args.get(1) {
        Some(SynValue::Text(t)) => t.to_string(),
        Some(other) => return Err(err(format!("{}: the header name must be text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the header name", F))),
    };
    let map = match args.first() {
        Some(SynValue::Map(m)) => m.clone(),
        Some(other) => {
            return Err(err(format!("{}: expects a response or a map of headers, got {}", F, other.type_name())))
        }
        None => return Err(err(format!("{}: missing the response", F))),
    };
    let headers = {
        let m = map.borrow();
        match m.get("headers") {
            Some(SynValue::Map(h)) => h.clone(),
            _ => map.clone(),
        }
    };
    let h = headers.borrow();
    let found = h.iter().find(|(k, _)| k.eq_ignore_ascii_case(&name)).map(|(_, v)| v.clone());
    Ok(found.unwrap_or(SynValue::Nothing))
}

pub fn register_header_builtins(interp: &Interpreter) {
    interp.register_builtin("header", 2, Rc::new(|_i, a, _l| header(a)));
}
