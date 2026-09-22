//! Synsema infer: inferencia local en CPU, determinista y atestiguable.
//!
//! Corre modelos desde archivos locales —GGUF cuantizado hoy, safetensors en I3— sin red, sin
//! servidor aparte y sin API key. Es la capa que el motor usa para el provider `local` de LLM,
//! y la que en I3 servirá también al `judge` local y a los embeddings de la DB para agentes.
//!
//! ## Lo que este crate NO es
//!
//! No es un framework de ML. No hay GPU, no hay autodiff, no hay entrenamiento (spec
//! `specs/synsema-infer.md` §8). Synsema no necesita un framework de tensores: necesita correr
//! un puñado acotado de modelos, bien, de forma determinista y verificable. Es otra escala de
//! problema, y confundirlas es el error que el spec existe para evitar.
//!
//! ## Las tres puertas (§2.3)
//!
//! Una por consumidor, en vez de un `Model` genérico que cada llamador tenga que interpretar:
//!
//! | Puerta | Qué corre | Quién la usa | Estado |
//! |---|---|---|---|
//! | [`generate`] | decoder GGUF | provider `local` de `llm` | **I1, lista** |
//! | `embed` | encoder | `embedder-task` de la DB | I3 |
//! | `decide` | encoder + cabezas | `judge` local con Laya | I3 |
//!
//! Y una cuarta que no corre nada: [`resolve`] / [`discover`] encuentran el modelo en disco —
//! ruta, cache de Ollama o cache de Hugging Face— **sin descargar un byte** (§4).
//!
//! ## Cero candle en esta superficie (§2.1, regla 3)
//!
//! Nada de lo que se exporta acá menciona un tipo de candle, ni deja sacarle el tensor de
//! adentro a un [`Tensor`]. Es *la* regla del crate: si se rompe una vez, la mudanza de I4 deja
//! de ser posible y esto se vuelve una capa decorativa sobre una dependencia ajena. El criterio
//! C2 del spec la vigila con un `grep`, no con buena voluntad. (La *palabra* sí aparece, en el
//! `mod arch_candle` y en los `cfg`: lo que no puede aparecer es un tipo.)
//!
//! ## Sin backend compilado
//!
//! Un build sin la feature `candle-backend` no arrastra ninguna dependencia de cálculo, y este
//! crate queda reducido a [`backend_name`], [`LocalKnobs`] y una [`generate`] que devuelve un
//! error legible. Es lo que permite que el build default del motor —y el target WASM— no paguen
//! nada. Por eso cada módulo de cálculo va con su `cfg`: sin backend no hay tipos que exponer.
//!
//! ## Quién elige el modelo
//!
//! Este crate **descubre** modelos, pero **no elige**: recibe el spec y los knobs ya resueltos
//! por el operador. La única lectura del entorno es [`StoreConfig::from_env`], y mira **dónde
//! está el cache**, nunca **qué modelo usar**. Que el operador —y jamás el programa `.syn`—
//! elija qué corre es una decisión de seguridad (§4.1): descubrir el cache le ofrece candidatos
//! a quien configura, no le abre el disco al programa.

// Los knobs existen siempre: el runtime los resuelve con o sin backend, y así `llm_providers.rs`
// no necesita un `cfg` para nombrarlos.
pub mod knobs;
pub use knobs::{install_engine_knobs, EngineKnobs, LocalKnobs};

/// El nombre del knob que apunta al directorio de definiciones del operador.
///
/// Vive acá —y no en `arch_registry`— porque el runtime tiene que poder nombrarlo aunque el
/// binario se haya compilado sin backend propio: resolverlo es del operador, ejecutarlo no.
pub const ARCHDEF_DIR_ENV: &str = "SYNSEMA_INFER_ARCHDEF";

// La resolución de modelos no necesita backend: encontrar un archivo es leer directorios. Por
// eso `store` vive fuera del gating — `llm status` puede listar lo que hay aunque el binario se
// haya compilado sin motor de inferencia.
pub mod store;
pub use store::{discover, resolve, DiscoveredModel, ModelOrigin, ResolvedModel, StoreConfig};

// Las reglas del protocolo de Laya (preguntas tipadas, armado de secuencia, calibracion) son
// PURAS: no tocan tensores ni pesos, asi que viven fuera del gating y se testean sin checkpoint.
pub mod laya;
pub use laya::{Criteria, QType, Question};

// EL BACKEND PROPIO (tanda I4). No depende de candle: es la mitad del punto. Convive con el otro
// hasta que pase los goldens, y el oraculo compara sus salidas sobre los mismos pesos.
#[cfg(feature = "rust-backend")]
pub mod backend_rust;
#[cfg(feature = "rust-backend")]
pub mod tensor_rust;
/// Lector propio de `.safetensors`, sin dependencias de terceros.
#[cfg(feature = "rust-backend")]
pub mod safetensors;
/// ModernBERT + cabezas de Laya sobre el backend propio. El reemplazo de `arch_candle_laya`.
#[cfg(feature = "rust-backend")]
pub mod arch_modernbert;
/// Parser propio de GGUF (I4-c). El reemplazo de `gguf.rs`, que envuelve al de candle.
#[cfg(feature = "rust-backend")]
pub mod gguf_rust;
/// Dequantizacion de los esquemas de ggml (I4-c): Q8_0, Q4_K, Q6_K.
#[cfg(feature = "rust-backend")]
pub mod quant;
/// Los decoders (llama/qwen2/qwen3) sobre el backend propio, con KV cache.
#[cfg(feature = "rust-backend")]
pub mod arch_llama;
/// Matmul CUANTIZADO (I4-e): multiplicar sin dequantizar los pesos.
#[cfg(feature = "rust-backend")]
pub mod qmatmul;
/// Los bytes del modelo, MAPEADOS en vez de copiados (I4-d).
#[cfg(feature = "rust-backend")]
pub mod mapped;
/// El FORMATO de arquitectura declarativa (I5): parsear, validar y decir qué arreglar.
///
/// Es puro y no toca pesos, pero vive bajo la feature porque sin backend propio no hay nada que
/// ejecute lo que describe.
#[cfg(feature = "rust-backend")]
pub mod archdef;
/// El INTERPRETE de una definicion: ata los pasos a los tensores de un GGUF y los corre.
#[cfg(feature = "rust-backend")]
pub mod archrun;
/// Que arquitecturas conoce este binario: las embebidas mas las del directorio del operador.
#[cfg(feature = "rust-backend")]
pub mod arch_registry;
#[cfg(feature = "rust-backend")]
pub use tensor_rust::RTensor;

// Cuando en I4 exista `backend_rust`, estas condiciones pasan a ser
// `any(feature = "candle-backend", feature = "rust-backend")` y nada más cambia.
#[cfg(feature = "candle-backend")]
pub mod arch;
#[cfg(feature = "candle-backend")]
pub mod backend;
#[cfg(feature = "candle-backend")]
pub mod gguf;
/// Elección del próximo token. Es PURO: trabaja sobre `&[f32]` y sirve a los dos backends.
pub mod sampling;

/// `true` si el operador pidió el backend propio con `SYNSEMA_INFER_BACKEND=rust`.
///
/// El valor lo resuelve el runtime con la precedencia de la casa (`environ > .env > default`) y
/// lo instala con [`install_engine_knobs`]; si nadie lo instaló —un test del crate, o alguien
/// que lo usa como biblioteca— se cae al entorno del proceso. **Qué motor corre es una decisión
/// del operador**, igual que qué modelo: el `.syn` nunca lo elige. El default sigue siendo
/// candle mientras los dos coexistan (spec §7, tanda I4).
pub fn want_rust_backend() -> bool {
    knobs::engine_backend().is_some_and(|v| v.eq_ignore_ascii_case("rust"))
}

/// Las arquitecturas GGUF del backend candle, que están **compiladas** y no se pueden sumar sin
/// recompilar. Es la contracara de [`arch_registry::Registry`], y existe para que `llm status`
/// pueda listar la del backend que de verdad va a correr en vez de la unión de los dos.
pub fn candle_architectures() -> &'static [&'static str] {
    #[cfg(feature = "candle-backend")]
    {
        arch::SUPPORTED
    }
    #[cfg(not(feature = "candle-backend"))]
    {
        &[]
    }
}
#[cfg(feature = "candle-backend")]
pub mod session;
#[cfg(feature = "candle-backend")]
pub mod tensor;
#[cfg(feature = "candle-backend")]
pub mod tokenizer;
/// El tokenizer SentencePiece propio. Es PURO —vocabulario adentro, texto afuera— y no toca
/// candle; vive bajo la misma feature que `tokenizer` porque de ahí sale su vocabulario.
#[cfg(feature = "candle-backend")]
pub mod spm;

#[cfg(feature = "arch-modernbert")]
pub mod decide;

#[cfg(feature = "candle-backend")]
mod arch_candle;
#[cfg(feature = "arch-modernbert")]
mod arch_candle_laya;
#[cfg(feature = "candle-backend")]
mod backend_candle;

#[cfg(feature = "candle-backend")]
pub use arch::{Model, ModelKind};
#[cfg(feature = "candle-backend")]
pub use session::Session;
#[cfg(feature = "candle-backend")]
pub use tensor::Tensor;
#[cfg(feature = "arch-modernbert")]
pub use decide::{Answer, Decision, LayaSession};

/// Genera texto con un modelo local. Ésta es la puerta que usa el provider `local`.
///
/// La carga es lazy y memoizada por path para todo el proceso: la primera llamada paga la
/// lectura del GGUF, las siguientes no, y `serve` carga una sola vez para todos sus
/// intérpretes. Un path roto tampoco se reintenta por llamada — el error queda memoizado igual
/// que el éxito.
///
/// `sink`: si está, emite los fragmentos a medida que se generan (ver
/// [`session::Session::generate`] para las garantías de byte-exactitud y early-stop).
///
/// Devuelve `(texto, tokens usados = prompt + generados)`. **Nunca panica**: todo error sale
/// por el `Err`, y quien lo convierte en `[local error: …]` es el adaptador del runtime.
#[cfg(feature = "candle-backend")]
pub fn generate(
    model_spec: &str,
    store: &StoreConfig,
    user_text: &str,
    knobs: &LocalKnobs,
    max_tokens: u64,
    sink: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<(String, u64), String> {
    let arc = session::load(model_spec, store, knobs.max_concurrent);
    match arc.as_ref() {
        Err(e) => Err(format!("no se pudo cargar '{}': {}", model_spec, e)),
        Ok(session) => session.generate(user_text, knobs, max_tokens, sink),
    }
}

/// Sin backend no hay inferencia, y se dice claro en vez de degradar en silencio.
#[cfg(not(feature = "candle-backend"))]
pub fn generate(
    _model_spec: &str,
    _store: &StoreConfig,
    _user_text: &str,
    _knobs: &LocalKnobs,
    _max_tokens: u64,
    _sink: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<(String, u64), String> {
    Err("este binario se compiló sin backend de inferencia local".to_string())
}

/// Nombre del backend de cálculo activo. Va al audit y a `llm status`: cuando en I4 coexistan
/// dos, esto es lo que dice cuál corrió.
pub fn backend_name() -> &'static str {
    #[cfg(feature = "candle-backend")]
    {
        backend::name()
    }
    #[cfg(not(feature = "candle-backend"))]
    {
        "none"
    }
}

/// Las arquitecturas que este binario sabe correr. Sale del registro, no de una constante
/// suelta, así que no puede quedar desactualizada respecto de lo que de verdad carga.
pub fn supported_architectures() -> &'static [&'static str] {
    #[cfg(feature = "candle-backend")]
    {
        arch::SUPPORTED
    }
    #[cfg(not(feature = "candle-backend"))]
    {
        &[]
    }
}
