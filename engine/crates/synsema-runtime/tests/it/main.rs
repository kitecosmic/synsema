//! Los tests de integración de la crate en un solo binario (v0.6.46): cada archivo era un
//! ejecutable que se linkeaba entero, y la regresión se iba en linkear. Los que tocan estado
//! global del proceso (variables de entorno, el modo referencia, el nivel nativo, un
//! allocator propio, las etiquetas del host, el log y el techo de host de `serve`, `shutdown()`,
//! lo que lee `last_run_exit_code()`) siguen en `tests/` como binarios propios: acá correrían al
//! mismo tiempo que los demás.

mod agentauth_e2e;
mod agentic_bus_e2e;
mod batch10_e2e;
mod batch15_e2e;
mod batch6_e2e;
mod batch7_e2e;
mod batch8_e2e;
mod batch9_e2e;
mod bytes_e2e;
mod decide_contract;
mod discovery_e2e;
mod engine_concurrency;
mod engine_db;
mod engine_http;
mod engine_human_llm;
mod engine_io;
mod engine_mongo;
mod engine_mysql;
mod engine_parallel;
mod engine_pg;
mod engine_recovery;
mod engine_redis;
mod engine_security;
mod frozen_reads;
mod gaps_conformance;
mod hmac_bytes;
mod llm_stream_e2e;
mod llm_text_prompt;
mod memory_declared;
mod mtls_e2e;
mod proxy_e2e;
mod proxy_headers_e2e;
mod proxy_streaming_e2e;
mod redirect_e2e;
mod reference_oracle;
mod serve_frontend_e2e;
mod serve_isolation;
mod serve_progress_persist;
mod test_framework;
mod tool_calling_e2e;
mod v0629_audit;
mod v0629_datos;
mod v0629_language;
mod v0630_audit;
mod v0645_data_builtins_e2e;
mod v0645_http_named_args_e2e;
mod v0645_partial_write_e2e;
mod v0645_select_reset_e2e;
mod v0645_state_atomic_e2e;
mod webauth_e2e;
mod webpush_e2e;
