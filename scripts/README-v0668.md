# v0.6.68: migración de tests Rust a Synsema

## Reanudar después de cambiar de modelo

1. Leer este archivo y `git status --short`. La rama de trabajo es `feat/v0668-tests-to-synsema`.
2. Ejecutar `python scripts/v0668_inventory.py` y `python scripts/v0668_overlaps.py`.
3. Leer `scripts/v0668_candidates.tsv`. Cada fila `PENDIENTE` requiere una decisión humana: `MIGRA` o `QUEDA`, con razón en `nota`. El inventario conserva esas dos columnas cuando se regenera.
4. Trabajar por **lotes de módulos**, registrar la decisión en el TSV y traducir sólo los tests que observan comportamiento ejecutable en Synsema. Verificar en bloque con `python scripts/v0668_verify.py --glob 'modulo*.test.syn' --rust core` (o `--rust runtime`). El script guarda logs completos en un directorio temporal y muestra sólo resúmenes y fallos.
5. Antes de borrar un test Rust, comparar sus aserciones con las del gemelo. Las dos suites verdes por sí solas no prueban equivalencia. Usar una mutación representativa del comportamiento compartido para comprobar que ambos corredores detectan el defecto. Borrar sólo los gemelos revisados, comprobar que no quedan duplicados y hacer commit del lote.

## Estado comprobado el 2026-11-24 (barrida y auditoría posterior)

- Los 249 candidatos del TSV quedaron decididos: **130 MIGRA** (gemelos verdes en `tests/`, gemelos Rust borrados) y **119 QUEDA** (siguen en Rust con motivo en la columna `nota`).
- Auditoría posterior del lote `2c27a78`: se restauraron 13 tests Rust. Uno comprobaba persistencia SQLite entre dos motores, siete usaban `run_source_secure` y cinco comprobaban stdout del host (cuatro de redacción y uno de `sandbox under`). Los gemelos que prueban un alcance menor tienen sufijo `_runner`. Además se recuperó la comparación exacta de errores de permisos DB/archivo y de seis diagnósticos de arrays, que los gemelos habían reducido a `contains`.
- Core `it`: 297 passed. Runtime `it`: 342 passed, 29 ignored. Los tests de primer nivel se ejecutan por separado; `engine_secrets` incluye ahora las cuatro pruebas de stdout restauradas.
- Todos los `*.test.syn` de `tests/`: **76/76 verdes** corridos uno por uno con `v0668_verify.py --glob '*.test.syn'`.
- 0 nombres duplicados Rust/Synsema según el comprobador local.
- Mutaciones pareadas verificadas después de la auditoría: se restauraron temporalmente los módulos Rust de `c66ce37` y se introdujeron cuatro defectos en el motor en una compilación: detección falsa de `RETURNING` en SQL (v0629_audit), texto de denegación DB (engine_db), texto de denegación HTTP (engine_http) y valor devuelto por `sql_transaction` (v0659_transactions). En los cuatro casos fallaron **el test Rust original y el gemelo `.syn` correspondiente**. Se restauraron los fuentes, se recompilaron CLI y ejecutor del oráculo, y el runtime volvió a 342 passed / 29 ignored. Esto verifica cuatro comportamientos representativos; no equivale a una prueba formal de todos los gemelos.
- Los 130 tests Rust retirados no están en el árbol actual de la rama. Sus versiones siguen en la historia de Git: 126 ya existen en el tag `v0.6.67`; cuatro se añadieron después de ese tag (`v0642_e2e` ×2 y `v0664_data` ×2), pero están en `c66ce37`.
- El inventario mecánico quedó en 1434 tests Rust: 119 candidatos (todos QUEDA decidido) y 1315 exclusiones mecánicas (sin auditar por muestreo).
- Archivos enteros migrados y borrados: `it/engine_http.rs`, `it/v0646_tanda_c.rs`, `it/v0666_filters.rs` (con sus líneas `mod` en `it/main.rs`). `it/engine_db.rs` volvió con su prueba entre motores; `it/engine_io.rs` conserva sus tests de ejecución real por SO.
- Los gemelos documentan en su cabecera `--` qué QUEDA y por qué; las convenciones descubiertas (grants acumulan por archivo, require en task es no-op, recover llega sin prefijo, fixtures copiados a `tests/fixtures/`) están anotadas allí.
- Los apuntes de lotes anteriores están en `specs/v0.6.68-rondas/` en este equipo. `specs/` está ignorado por Git; este README y los scripts son la referencia versionada para reanudar.

## Reglas de decisión

`MIGRA` si el test puede afirmar dentro de `.test.syn` el mismo valor, error recuperable o efecto observable que afirmaba Rust. `QUEDA` si el contrato observado depende del host: parseo/check estático, diagnóstico estructurado, conteo de pasos o memoria, stdout decorado del ejecutor, estado o variables del proceso, sockets/servicios reales, tiempos, o resultado `RunResult` que el runner `.syn` no expone. Revisar las llamadas indirectas a `run_program`: el clasificador las detecta, pero su motivo sigue siendo una pista.

No usar `synsema test tests/` como gate general: incluye archivos `.probe.syn` y requiere `ETH_KEY` en dos casos. Seleccionar archivos `*.test.syn` concretos. Comprobar si el destino ya existe antes de escribir; `tests/v0665_tables.test.syn` se sobrescribió accidentalmente una vez y hubo que recuperarlo.

## Próximo paso

La barrida de los 249 candidatos está cerrada (ver «Estado»). El TSV queda como libro de decisiones: las 119 filas restantes son QUEDA con motivo y **no hay que migrarlas** salvo que cambie el runner (por ejemplo, un modo secure bajo `synsema test` reabriría las de gates secure; exponer steps/memoria o ubicación en `recover` reabriría otras). Trabajo opcional pendiente: auditar por muestreo las 1315 exclusiones mecánicas del inventario y volver a ejecutar `v0668_verify.py --glob '*.test.syn'` tras tocar el corredor de tests.
