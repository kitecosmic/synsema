# v0.6.68: migración de tests Rust a Synsema

## Reanudar después de cambiar de modelo

1. Leer este archivo y `git status --short`. La rama de trabajo es `feat/v0668-tests-to-synsema`.
2. Ejecutar `python scripts/v0668_inventory.py` y `python scripts/v0668_overlaps.py`.
3. Leer `scripts/v0668_candidates.tsv`. Cada fila `PENDIENTE` requiere una decisión humana: `MIGRA` o `QUEDA`, con razón en `nota`. El inventario conserva esas dos columnas cuando se regenera.
4. Trabajar por **lotes de módulos**, registrar la decisión en el TSV y traducir sólo los tests que observan comportamiento ejecutable en Synsema. Verificar en bloque con `python scripts/v0668_verify.py --glob 'modulo*.test.syn' --rust core` (o `--rust runtime`). El script guarda logs completos en un directorio temporal y muestra sólo resúmenes y fallos.
5. Antes de borrar un test Rust, comparar sus aserciones con las del gemelo. Las dos suites verdes por sí solas no prueban equivalencia. Usar una mutación representativa del comportamiento compartido para comprobar que ambos corredores detectan el defecto. Borrar sólo los gemelos revisados, comprobar que no quedan duplicados y hacer commit del lote.

## Estado comprobado el 2026-11-24 (cierre de la barrida completa)

- Los 249 candidatos del TSV quedaron decididos: **143 MIGRA** (gemelos verdes en `tests/`, gemelos Rust borrados) y **106 QUEDA** (siguen en Rust con motivo en la columna `nota`).
- Core `it`: 297 passed (303 − 6). Runtime `it`: 333 passed, 29 ignored (456 − 123; dos de los borrados eran cfg(unix) y no corrían en Windows). Targets de primer nivel afectados verdes: engine_secrets 6, identity_e2e 2, serve_modules 4, delegated_ceiling_e2e 1, v0646_tanda_e 25.
- Todos los `*.test.syn` de `tests/`: **76/76 verdes** corridos uno por uno con `v0668_verify.py --glob '*.test.syn'`.
- 0 nombres duplicados Rust/Synsema según el comprobador local.
- Mutación representativa: 4 mutaciones (valor en v0629_audit, needle en engine_db, string exacto en engine_http, valor en v0659_transactions) — las 4 detectadas por el corredor `.syn` (1 failed cada una).
- El inventario mecánico quedó en 1421 tests Rust: 106 candidatos (todos QUEDA decidido) y 1315 exclusiones mecánicas (sin auditar por muestreo; quedó como trabajo opcional).
- Archivos enteros migrados y borrados: `it/engine_io.rs` (sólo sus 20 candidatos; los cfg-gated de `run` real siguen), `it/engine_db.rs`, `it/engine_http.rs`, `it/v0646_tanda_c.rs`, `it/v0666_filters.rs` (con sus líneas `mod` en `it/main.rs`).
- Los gemelos documentan en su cabecera `--` qué QUEDA y por qué; las convenciones descubiertas (grants acumulan por archivo, require en task es no-op, recover llega sin prefijo, fixtures copiados a `tests/fixtures/`) están anotadas allí.
- Los apuntes de lotes anteriores están en `specs/v0.6.68-rondas/` en este equipo. `specs/` está ignorado por Git; este README y los scripts son la referencia versionada para reanudar.

## Reglas de decisión

`MIGRA` si el test puede afirmar dentro de `.test.syn` el mismo valor, error recuperable o efecto observable que afirmaba Rust. `QUEDA` si el contrato observado depende del host: parseo/check estático, diagnóstico estructurado, conteo de pasos o memoria, stdout decorado del ejecutor, estado o variables del proceso, sockets/servicios reales, tiempos, o resultado `RunResult` que el runner `.syn` no expone. Revisar las llamadas indirectas a `run_program`: el clasificador las detecta, pero su motivo sigue siendo una pista.

No usar `synsema test tests/` como gate general: incluye archivos `.probe.syn` y requiere `ETH_KEY` en dos casos. Seleccionar archivos `*.test.syn` concretos. Comprobar si el destino ya existe antes de escribir; `tests/v0665_tables.test.syn` se sobrescribió accidentalmente una vez y hubo que recuperarlo.

## Próximo paso

La barrida de los 249 candidatos está cerrada (ver «Estado»). El TSV queda como libro de decisiones: las 106 filas restantes son QUEDA con motivo y **no hay que migrarlas** salvo que cambie el runner (por ejemplo, un modo secure bajo `synsema test` reabriría las de gates secure; exponer steps/memoria o ubicación en `recover` reabriría otras). Trabajo opcional pendiente: auditar por muestreo las 1315 exclusiones mecánicas del inventario, y los gemelos nuevos podría gobernarse con la regla de reejecutar `v0668_verify.py --glob '*.test.syn'` tras tocar el corredor de tests.
