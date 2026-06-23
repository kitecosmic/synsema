# `synsema/` (Python) — CONGELADO / FROZEN (2026-06-23)

La implementación de **producción de Synsema es Rust** (`rust/`). Este árbol Python
fue la implementación original y sirvió como **oráculo de paridad** durante el port a
Rust (testing diferencial: cada `.syn` se corría por ambas y se comparaba byte a byte).

## Estado: CONGELADO

**No se agregan features nuevas acá.** Rust es la **única fuente de verdad**. Las
features del lenguaje se implementan **solo en Rust**, validadas por:

- `cargo test --workspace` — **360+ tests** (lenguaje + producción: serve/TLS/secrets/
  concurrency/db). Incluye el golden Rust-nativo `tests/core_conformance.rs`.
- La **red de invariantes semánticos** `synsema-core/src/interpreter.rs::semantic_invariants`
  (igualdad estructural, orden, coerción, contains, match) — reemplaza la "segunda
  opinión" que daba el oráculo diferencial, justo donde estuvo el bug real (la igualdad
  origin-sensible de *este* árbol Python).

## Por qué se retiró

- Producción es Rust-only; este árbol Python ya era **incompleto** (solo core — sin
  TLS/HTTP-2/multi-core serve, sin tipos Secret/Server).
- Se escribía cada feature **dos veces** desde cero (ya no es un port).
- A veces el bug estaba acá (la igualdad origin-sensible era de Python; Rust ya era correcto).

Se mantiene **congelado** como referencia legible / historial. El harness diferencial
Python (`conformance/run_*.py`) puede seguir corriéndose contra el corpus existente, pero
**ya no es requisito** para trabajo nuevo.
