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
