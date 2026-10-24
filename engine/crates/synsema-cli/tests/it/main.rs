//! Los tests de integración de la crate en un solo binario (v0.6.46): cada archivo era un
//! ejecutable que se linkeaba entero, y la regresión se iba en linkear. Los que tocan estado
//! global del proceso (variables de entorno, el modo referencia, el nivel nativo, un
//! allocator propio, las etiquetas del host, el log y el techo de host de `serve`, `shutdown()`)
//! siguen en `tests/` como binarios propios: acá correrían al mismo tiempo que los demás.

mod attest_cli;
mod build_cli;
mod code_cli;
mod desktop_build_cli;
mod desktop_cli;
mod host_flags_cli;
mod init_desktop_cli;
mod init_pwa_cli;
mod live_output_cli;
mod routes_group_cli;
mod run_program_cli;
mod shutdown_e2e;
mod stdio_cli;
mod v0645_check_undefined_call_cli;
mod v0645_fetch_deprecated_cli;
mod v0645_links_cli;
mod v0645_serve_exit_cli;
mod v0646_tanda_e_cli;
mod v0647_t1_cli;
