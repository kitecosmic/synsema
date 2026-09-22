//! Los knobs de la inferencia local.
//!
//! Vive aparte de `session.rs` a propósito: el runtime los resuelve **con o sin backend
//! compilado** (la precedencia `environ > .env > default` corre igual), así que
//! `llm_providers.rs` puede nombrarlos sin un `cfg`.
//!
//! Este crate **no los lee del entorno**: los recibe ya decididos. Quién elige el modelo y su
//! configuración es el operador, y esa resolución vive del lado del runtime — la misma razón
//! por la que un programa `.syn` nunca nombra un host ni una clave (spec §4.1).

/// Configuración de una corrida local. Los nombres de las variables que la alimentan están del
/// lado del runtime (`local_knobs_from_config` en `llm_providers.rs`).
#[derive(Clone, Debug, PartialEq)]
pub struct LocalKnobs {
    /// Ventana de contexto a usar, capada al contexto declarado por el modelo.
    pub ctx: usize,
    /// Threads del motor de CPU. Lo aplica el runtime antes de la primera carga; después, el
    /// pool global ya quedó fijado.
    pub threads: Option<usize>,
    /// `0` = greedy (default, determinista); `> 0` = muestreo con seed fija.
    pub temperature: f64,
    /// Instancias máximas del modelo vivas a la vez. El default `1` serializa las llamadas
    /// concurrentes; subirlo crea instancias extra bajo demanda, cada una re-leyendo el modelo
    /// (RAM proporcional — opt-in consciente).
    pub max_concurrent: usize,
    /// Chunks en vuelo entre la generación y la emisión en streaming.
    pub stream_buffer: usize,
}

impl Default for LocalKnobs {
    fn default() -> Self {
        Self { ctx: 4096, threads: None, temperature: 0.0, max_concurrent: 1, stream_buffer: 32 }
    }
}

// =========================================================
// Los knobs del MOTOR, resueltos por el runtime (no por este crate)
// =========================================================

use std::sync::OnceLock;

/// Qué motor corre y qué definiciones de arquitectura están disponibles.
///
/// Los dos son decisiones del **operador**, y por eso los resuelve el runtime con la precedencia
/// de la casa (`environ > .env > default`) y los instala acá una vez. Sin esta instalación el
/// crate cae a leer el entorno del proceso directamente, que es lo que hacía antes de I5: anda
/// igual, pero un `.env` no se ve — y el `.env.example` de `synsema init` los documenta en la
/// sección del LLM, que SÍ se lee del `.env`. La instalación es lo que hace verdad esa promesa.
#[derive(Clone, Debug, Default)]
pub struct EngineKnobs {
    /// `SYNSEMA_INFER_BACKEND`: `rust` = el backend propio; cualquier otra cosa = candle.
    pub backend: Option<String>,
    /// `SYNSEMA_INFER_ARCHDEF`: directorio con definiciones `<arch>.archdef` del operador.
    pub archdef_dir: Option<String>,
}

static ENGINE: OnceLock<EngineKnobs> = OnceLock::new();

/// Instala los knobs ya resueltos. **La primera instalación gana** y las siguientes se ignoran,
/// igual que el pool de modelos: qué motor corre no puede cambiar a mitad de proceso sin
/// invalidar lo que ya se cargó, así que fijarlo una vez es la semántica correcta, no una
/// limitación.
pub fn install_engine_knobs(k: EngineKnobs) {
    let _ = ENGINE.set(k);
}

/// El valor instalado de un knob, si el runtime llegó a instalarlo y traía algo.
fn installed(pick: fn(&EngineKnobs) -> Option<&String>) -> Option<String> {
    let v = pick(ENGINE.get()?)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// `SYNSEMA_INFER_BACKEND` resuelto: lo instalado, y si no, el entorno del proceso.
pub fn engine_backend() -> Option<String> {
    installed(|k| k.backend.as_ref()).or_else(|| {
        std::env::var("SYNSEMA_INFER_BACKEND")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// `SYNSEMA_INFER_ARCHDEF` resuelto: lo instalado, y si no, el entorno del proceso.
pub fn engine_archdef_dir() -> Option<String> {
    installed(|k| k.archdef_dir.as_ref()).or_else(|| {
        std::env::var(crate::ARCHDEF_DIR_ENV)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}
