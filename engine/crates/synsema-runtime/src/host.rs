//! Ajustes del PROCESO que decide quien invoca el binario (la CLI o un binario
//! `synsema build`): el perfil (`--profile native|pure`) y los argumentos del programa
//! (`args()`). Viven en `OnceLock` — como `SERVE_CEILING` — porque son política del
//! proceso, no un parámetro que viaje por seis firmas del motor. `run_program` se los
//! transmite al hijo por flag/env (es otro proceso).

use std::sync::OnceLock;

/// `native` (todo el stdlib) o `pure` (la pared: sin filesystem/procesos/sockets crudos/
/// DB/cron — los nombres existen y fallan con la verdad del entorno).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Native,
    Pure,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        match s {
            "native" => Some(Profile::Native),
            "pure" => Some(Profile::Pure),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Profile::Native => "native",
            Profile::Pure => "pure",
        }
    }
}

static PROFILE: OnceLock<Profile> = OnceLock::new();
static PROGRAM_ARGS: OnceLock<Vec<String>> = OnceLock::new();
/// Etiquetas de flujo de información (`private`/`declassify`) encendidas para
/// TODOS los intérpretes del proceso (`run --labels`, `test --labels`, `serve --attested`).
static LABELS: OnceLock<bool> = OnceLock::new();
/// v0.6.47 (T1): el diagnóstico de un corte de etiquetas sale entero hacia el programa. Sólo lo
/// enciende `run`/`test` sin techo (ver `Interpreter::set_labels_detail_to_program`).
static LABELS_DETAIL: OnceLock<bool> = OnceLock::new();

/// v0.6.46 (E3b): los módulos de confianza que cargó quien invoca el binario (`--trusted
/// nombre=ruta`, ya leídos: el programa no ve la ruta) y su techo (`--trusted-cap-set`).
#[derive(Clone, Default)]
pub struct Trusted {
    pub modules: Vec<(String, String)>,
    pub ceiling: Option<Vec<synsema_capabilities::model::Capability>>,
    /// v0.6.50 (D): los templates de cada tool (`--trusted-templates`), ya leídos.
    pub templates: Vec<(String, Vec<(String, String)>)>,
}

static TRUSTED: OnceLock<Trusted> = OnceLock::new();

/// v0.6.46 (E3b): fija los módulos de confianza del proceso (una vez).
pub fn set_trusted(t: Trusted) -> bool {
    TRUSTED.set(t).is_ok()
}

/// v0.6.46 (E3b): los módulos de confianza del proceso, si hay.
pub fn trusted() -> Option<&'static Trusted> {
    TRUSTED.get().filter(|t| !t.modules.is_empty())
}

/// Fija el perfil del proceso (una vez). `false` si ya estaba fijado.
pub fn set_profile(p: Profile) -> bool {
    PROFILE.set(p).is_ok()
}

pub fn profile() -> Profile {
    PROFILE.get().copied().unwrap_or(Profile::Native)
}

/// Fija los argumentos del programa (`args()`), una vez por proceso.
pub fn set_program_args(args: Vec<String>) -> bool {
    PROGRAM_ARGS.set(args).is_ok()
}

pub fn program_args() -> Vec<String> {
    PROGRAM_ARGS.get().cloned().unwrap_or_default()
}

/// Fija las etiquetas de flujo del proceso (una vez). `false` si ya estaban fijadas.
pub fn set_labels(on: bool) -> bool {
    LABELS.set(on).is_ok()
}

/// ¿Etiquetas de flujo encendidas? Apagadas por defecto: la variante `Private` no existe en
/// runtime y el coste es cero (ver `synsema_core::labels`).
pub fn labels() -> bool {
    LABELS.get().copied().unwrap_or(false)
}

/// v0.6.47 (T1): fija, una vez, si el diagnóstico de etiquetas sale entero hacia el programa.
pub fn set_labels_detail_to_program(on: bool) -> bool {
    LABELS_DETAIL.set(on).is_ok()
}

/// v0.6.47 (T1): ¿el diagnóstico de etiquetas sale entero hacia el programa? Apagado por defecto: el
/// programa recibe un texto fijo y el detalle va al operador.
pub fn labels_detail_to_program() -> bool {
    LABELS_DETAIL.get().copied().unwrap_or(false)
}
