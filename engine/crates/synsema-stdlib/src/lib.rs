//! Synsema stdlib. Espeja `synsema/stdlib/`.
//! Capa 6 (http, database, cron) y capa 8 (server). templates vive en core
//! (acoplado al parser/intérprete).
//!
//! Feature `native` (default): los módulos que hablan con el SO — sockets
//! (http/server/ws/acme), threads de scheduler (cron) y drivers de base de datos
//! (database). Sin `native` (perfil wasm, `--no-default-features`) queda el
//! subconjunto PURO — el mismo lenguaje donde el entorno no otorga net/sql/serve;
//! http se reemplaza por el stub (blockchain_rpc compila entero, su red falla en
//! runtime con error claro). CI ancla este perfil contra wasm32-wasip1.

#[cfg(feature = "native")]
pub mod acme;
pub mod blockchain;
pub mod blockchain_abi;
pub mod blockchain_algorand;
pub mod blockchain_btc;
pub mod blockchain_btc_rpc;
pub mod blockchain_hd;
pub mod blockchain_rpc;
pub mod blockchain_solana;
pub mod captoken;
pub mod charts;
#[cfg(feature = "native")]
pub mod cron;
#[cfg(feature = "native")]
pub mod database;
pub mod hashing;
/// Protocolo host↔intérprete (F2): capabilities que un embebedor OFRECE (http/kv/llm/log).
pub mod hostcap;
/// Lo puro del cliente HTTP, compartido por los dos transportes.
pub mod http_common;
#[cfg(feature = "native")]
pub mod http;
#[cfg(not(feature = "native"))]
#[path = "http_stub.rs"]
pub mod http;
pub mod httpsig;
pub mod json;
pub mod mimetypes;
pub mod oidc;
pub mod raster;
pub mod respond;
/// Router + contrato de respuesta de `serve`, PUROS (compartidos con el handler-mode wasm).
pub mod routing;
pub mod secrets;
#[cfg(feature = "native")]
pub mod server;
pub mod spend;
pub mod webauth;
#[cfg(feature = "native")]
pub mod ws;
