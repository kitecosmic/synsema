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
// CBOR + COSE_Sign1 mínimos, compartidos por `attest` (producir) y
// `attestation_verify` (consumir). Puro, sin deps.
pub mod cbor;
// `attest` — drivers de plataforma (nitro/tsm/dstack detrás de `cfg`, mock
// En todo SO) + la identidad de `serve --attested`. Compila al perfil puro.
pub mod attest;
// `groth16_verify` sobre BN254 (JSON de snarkjs tal cual). Puro, sin deps del SO.
pub mod zk;
// `attestation_verify` (nitro/mock con raíz pineada) y ruido determinista
// (laplace_noise/gaussian_noise). Puros, compilan al perfil wasm.
pub mod attestation;
pub mod privacy;
// V0.6.20 — archivos comprimidos: SÓLO native (extraer toca disco; en puro son stubs).
#[cfg(feature = "native")]
pub mod archive;
// v0.6.20 — criptografía genérica (ECDH/HKDF/AES-GCM, nombres WebCrypto). Pura.
pub mod crypto;
pub mod charts;
#[cfg(feature = "native")]
pub mod cron;
pub mod cronexpr;
#[cfg(feature = "native")]
pub mod database;
pub mod discovery;
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
/// `platform()` → `{os, arch}`, sin capability (un hecho del binario, como `args()`).
pub mod platform;
// El perfil puro como pared (stubs OS-facing compartidos por nativo `--profile pure` y wasm).
pub mod pure;
pub mod raster;
// v0.6.20 — parsers de texto de la plataforma. Puros.
pub mod toml_fmt;
pub mod xml;
pub mod respond;
/// Router + contrato de respuesta de `serve`, PUROS (compartidos con el handler-mode wasm).
pub mod routing;
pub mod secrets;
#[cfg(feature = "native")]
pub mod server;
#[cfg(feature = "native")]
pub mod parquet_io;
pub mod spend;
pub mod webauth;
pub mod webauthn;
pub mod canonical;
pub mod didkey;
pub mod integrity;
pub mod receipt;
/// Web Push (RFC 8030/8291/8292): `push_send` gateado por `net(host)` + `push_vapid_keys`
/// gateado por `random`. El cifrado y VAPID son puros; la red va por `http` (nativo).
pub mod webpush;
#[cfg(feature = "native")]
pub mod proc;
#[cfg(feature = "native")]
pub mod term;
#[cfg(feature = "native")]
pub mod watch;
#[cfg(feature = "native")]
pub mod ws;
