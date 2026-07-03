//! Synsema runtime. Espeja `synsema/runtime/`.
//! Capa 9: engine, daemon, persistence, recovery, speculative, error_reporter.
//!
//! Por ahora `engine` es mínimo: orquesta el intérprete (core) con el modelo de
//! seguridad (capabilities) — cablea el grant hook de `require`, registra los
//! builtins seguros y hace el preámbulo/freeze del intent. Se va ampliando por capa.

pub mod daemon;
pub mod engine;
pub mod error_reporter;
/// Provider LLM `local` (GGUF embebido con candle, CPU). Sólo con `--features llm-local`;
/// sin la feature el binario no arrastra candle y se comporta idéntico a antes.
#[cfg(feature = "llm-local")]
pub mod llm_local;
pub mod llm_providers;
pub mod parallel;
pub mod persistence;
pub mod recovery;
pub mod serve;
pub mod speculative;
