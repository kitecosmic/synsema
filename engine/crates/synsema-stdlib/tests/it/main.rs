//! Los tests de integración de la crate en un solo binario (v0.6.46): cada archivo era un
//! ejecutable que se linkeaba entero, y la regresión se iba en linkear. Los que tocan estado
//! global del proceso (variables de entorno, el modo referencia, el nivel nativo, un
//! allocator propio, las etiquetas del host, el log y el techo de host de `serve`, `shutdown()`)
//! siguen en `tests/` como binarios propios: acá correrían al mismo tiempo que los demás.

mod batch13_ws;
mod charts_golden;
mod http2_proxy;
mod mtls_handshake;
mod openapi_golden;
mod tls_integration;
mod v0642_trust_proxy;
