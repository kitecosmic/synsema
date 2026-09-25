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
pub mod interpreter;
pub mod judge;
pub mod labels;
pub mod lexer;
pub mod math;
pub mod number;
pub mod parser;
pub mod reflexes;
pub mod rng;
pub mod rng_ziggurat;
pub mod stats;
pub mod tabular;
pub mod temporal;
pub mod route_meta;
pub mod secret;
pub mod templates;
pub mod term_guard;
pub mod testgen;
pub mod tokens;
pub mod types;
