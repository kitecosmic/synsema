//! Los tests de integración de la crate en un solo binario (v0.6.46): cada archivo era un
//! ejecutable que se linkeaba entero, y la regresión se iba en linkear. Los que tocan estado
//! global del proceso (variables de entorno, el modo referencia, el nivel nativo, un
//! allocator propio, las etiquetas del host, el log y el techo de host de `serve`, `shutdown()`)
//! siguen en `tests/` como binarios propios: acá correrían al mismo tiempo que los demás.

mod arrays_conformance;
mod assert_conformance;
mod batch2_conformance;
mod batch6_conformance;
mod batch7_conformance;
mod builtin_meta;
mod bytes_conformance;
mod core_conformance;
mod csv_conformance;
mod deep_recursion;
mod dx_conformance;
mod frozen_threads;
mod invariant_conformance;
mod judge_conformance;
mod labels_conformance;
mod math_conformance;
mod merge_error_location;
mod range_edges;
mod resolver;
mod skill_snippets;
mod stats_conformance;
mod tool_calling_conformance;
mod type_sizes;
mod unboxed_lists;
mod v0620_conformance;
mod v0642_conformance;
mod v0646_tanda_c;
mod v0646_f1;
mod v0650_modules;
mod vm;
