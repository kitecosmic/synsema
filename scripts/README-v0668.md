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
- Core `it`: 312 passed. Runtime `it`: 342 passed, 29 ignored después de construir `cargo build -p synsema-runtime --example oracle_run` (requerido por `reference_oracle`). Los tests de primer nivel se ejecutan por separado; `engine_secrets` incluye ahora las cuatro pruebas de stdout restauradas.
- Todos los `*.test.syn` de `tests/`: **74/74 verdes** con `python scripts/v0668_verify.py --glob '*.test.syn' --labels` en Windows, que es el modo usado por `programs-load` en CI; el gate completo de `programs-load` sigue pendiente.
- 0 nombres duplicados Rust/Synsema según el comprobador local.
- Mutaciones pareadas verificadas después de la auditoría: se restauraron temporalmente los módulos Rust de `c66ce37` y se introdujeron cuatro defectos en el motor en una compilación: detección falsa de `RETURNING` en SQL (v0629_audit), texto de denegación DB (engine_db), texto de denegación HTTP (engine_http) y valor devuelto por `sql_transaction` (v0659_transactions). En los cuatro casos fallaron **el test Rust original y el gemelo `.syn` correspondiente**. Se restauraron los fuentes, se recompilaron CLI y ejecutor del oráculo, y el runtime volvió a 342 passed / 29 ignored. Esto verifica cuatro comportamientos representativos; no equivale a una prueba formal de todos los gemelos.
- Los 130 tests Rust retirados no están en el árbol actual de la rama. Sus versiones siguen en la historia de Git: 126 ya existen en el tag `v0.6.67`; cuatro se añadieron después de ese tag (`v0642_e2e` ×2 y `v0664_data` ×2), pero están en `c66ce37`.
- El inventario mecánico quedó en 1434 tests Rust: 119 candidatos (todos QUEDA decidido) y 1315 exclusiones mecánicas (sin auditar por muestreo).
- Archivos enteros migrados y borrados: `it/engine_http.rs`, `it/v0646_tanda_c.rs`, `it/v0666_filters.rs` (con sus líneas `mod` en `it/main.rs`). `it/engine_db.rs` volvió con su prueba entre motores; `it/engine_io.rs` conserva sus tests de ejecución real por SO.
- Los gemelos documentan en su cabecera `--` qué QUEDA y por qué; las convenciones descubiertas (grants acumulan por archivo, require en task es no-op, recover llega sin prefijo, fixtures copiados a `tests/fixtures/`) están anotadas allí.
- Los apuntes de lotes anteriores están en `specs/v0.6.68-rondas/` en este equipo. `specs/` está ignorado por Git; este README y los scripts son la referencia versionada para reanudar.

## Auditoría local adicional (2026-11-24)

`python scripts/v0668_coverage_audit.py` compara todos los `#[test]` bajo
`engine/crates/**/tests/` del tag `v0.6.67` con la rama por crate, módulo y nombre.
Resultado: **2076 antes, 1547 todavía en Rust, 529 con gemelo `.test.syn`, 0 sin
gemelo**. Los ocho nombres repetidos bajo configuraciones `cfg` se conservan.
Esto cubre más crates que las 1434 filas Rust del inventario mecánico anterior.
El informe detallado se guarda en el directorio temporal. El emparejamiento
por nombre detecta pérdidas de pruebas, pero no prueba equivalencia de aserciones.

La comparación de aserciones reveló tres pérdidas más: la propiedad de 300
programas de `unboxed_lists_match_value_lists` ahora queda en Rust porque su
gemelo construía ambas listas con `append`; el error decorado exacto de
`described_invariant_names_itself_in_the_violation` vuelve a Rust y el gemelo
se llama `described_invariant_recover_text`; el caso `c6_json_garbage_is_not_nan`
comprueba ahora sus tres entradas contra el texto prohibido. Además,
`transpose_reorders_the_axes` comprueba los cinco errores exactos.

Los gemelos `batch6_conformance` y `batch7_conformance` tardaban 30,0 y
96,6 s: `wait_for` espera de verdad en `synsema test`, mientras los tests
originales prueban el parser con el hook sin espera fuera de swarm. Se
restauraron los dos módulos Rust completos y se retiraron esos gemelos. La
corrida de todos los archivos `.test.syn` bajó de 139,3 s (76 archivos) a
12,5 s (74 archivos); ambos estados dieron verde. El core Rust final dio
312/312 tests y 22/22 archivos Synsema asociados pasaron.

Medición local Windows, `cargo test --locked -p synsema-core --test it -j 2`,
`CARGO_INCREMENTAL=0`, tag y rama con directorios `target` separados:

| Medida | v0.6.67 | Rama v0.6.68 |
| --- | ---: | ---: |
| Compilación fría `--no-run` | 237,7 s | 237,7 s |
| Recompilación tras tocar un archivo de test | 6,2 s | 5,6 s antes del ajuste de `wait_for` |
| Ejecución de core `it`, dos hilos | 546 tests / 6,71 s | 312 tests / 4,84 s |
| Ciclo estable core, tiempo de pared | 9,4 s Rust | 5,4 s Rust + 6,8 s Synsema = 12,2 s |

La compilación fría del core no mejoró en esta medición. El ciclo completo
del core fue unos 2,8 s más lento con los gemelos, aunque editar y correr un
solo archivo `.test.syn` evita compilar Rust. Construir el CLI desde un
`target` limpio costó **1251 s** adicionales en este equipo; no se paga en
cada corrida si el binario ya existe. Estos son ensayos locales de una sola corrida, no
una predicción del CI Linux ni de todas las crates.

## Reglas de decisión

`MIGRA` si el test puede afirmar dentro de `.test.syn` el mismo valor, error recuperable o efecto observable que afirmaba Rust. `QUEDA` si el contrato observado depende del host: parseo/check estático, diagnóstico estructurado, conteo de pasos o memoria, stdout decorado del ejecutor, estado o variables del proceso, sockets/servicios reales, tiempos, o resultado `RunResult` que el runner `.syn` no expone. Revisar las llamadas indirectas a `run_program`: el clasificador las detecta, pero su motivo sigue siendo una pista.

No usar `synsema test tests/` como gate general: incluye archivos `.probe.syn` y requiere `ETH_KEY` en dos casos. Seleccionar archivos `*.test.syn` concretos. Comprobar si el destino ya existe antes de escribir; `tests/v0665_tables.test.syn` se sobrescribió accidentalmente una vez y hubo que recuperarlo.

## Próximo paso

La barrida de los 249 candidatos está cerrada (ver «Estado»). El TSV queda como libro de decisiones: las 119 filas restantes son QUEDA con motivo y **no hay que migrarlas** salvo que cambie el runner (por ejemplo, un modo secure bajo `synsema test` reabriría las de gates secure; exponer steps/memoria o ubicación en `recover` reabriría otras). Trabajo opcional pendiente: auditar por muestreo las 1315 exclusiones mecánicas del inventario y volver a ejecutar `v0668_verify.py --glob '*.test.syn'` tras tocar el corredor de tests.
