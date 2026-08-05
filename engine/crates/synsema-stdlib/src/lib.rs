//! Synsema stdlib. Espeja `synsema/stdlib/`.
//! Capa 6 (http, database, cron) y capa 8 (server). templates vive en core
//! (acoplado al parser/intérprete).

pub mod acme;
pub mod blockchain;
pub mod blockchain_abi;
pub mod blockchain_algorand;
pub mod blockchain_btc;
pub mod blockchain_btc_rpc;
pub mod blockchain_hd;
pub mod blockchain_rpc;
pub mod blockchain_solana;
pub mod charts;
pub mod cron;
pub mod database;
pub mod hashing;
pub mod http;
pub mod mimetypes;
pub mod raster;
pub mod secrets;
pub mod server;
pub mod spend;
pub mod webauth;
pub mod ws;
