//! Synsema core.
//!
//! Espeja `synsema/core/` de la implementación Python (el oráculo de paridad).
//! Orden de port: lexer -> tokens -> parser -> ast -> types -> interpreter.

pub mod addressable;
pub mod ast;
pub mod ast_api;
pub mod flat_syntax;
pub mod interpreter;
pub mod lexer;
pub mod number;
pub mod parser;
pub mod secret;
pub mod templates;
pub mod testgen;
pub mod tokens;
pub mod types;
