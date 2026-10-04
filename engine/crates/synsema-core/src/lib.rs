//! Synsema core.
//!
//! Espeja `synsema/core/` de la implementación Python (el oráculo de paridad).
//! Orden de port: lexer -> tokens -> parser -> ast -> types -> interpreter.

pub mod addressable;
pub mod arrays;
pub mod ast;
pub mod ast_api;
pub mod builtin_arity;
pub mod audit_loc;
pub mod bundle;
pub mod bytesutil;
pub mod capscope;
pub mod clock;
pub mod codeintel;
pub mod csv;
pub mod deprecated;
pub mod flat_syntax;
mod inline_vec;
pub mod interpreter;
pub mod judge;
pub mod labels;
pub mod lexer;
#[cfg(feature = "native-tier")]
#[doc(hidden)]
pub mod native_tier;
pub mod math;
pub mod number;
pub mod parser;
pub mod reflexes;
pub mod resolve;
pub mod rng;
pub mod rng_ziggurat;
pub mod stats;
pub mod synlist;
pub mod synmap;
/// R2: valores congelados que se leen desde varios hilos (specs/modelo-memoria-regiones.md).
pub mod frozen;
/// El montón propio (`Ref`/`RefMut` de listas y mapas, R1 de specs/modelo-memoria-regiones.md).
pub use synsema_heap as heap;
pub mod tabular;
pub mod temporal;
pub mod route_meta;
pub mod secret;
pub mod templates;
pub mod term_guard;
pub mod testgen;
pub mod tokens;
pub mod types;
pub mod waiting;
