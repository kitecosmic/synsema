# v0.6.68: migración de tests Rust a Synsema

## Reanudar después de cambiar de modelo

1. Leer este archivo y `git status --short`. La rama de trabajo es `feat/v0668-tests-to-synsema`.
2. Ejecutar `python scripts/v0668_inventory.py` y `python scripts/v0668_overlaps.py`.
3. Leer `scripts/v0668_candidates.tsv`. Cada fila `PENDIENTE` requiere una decisión humana: `MIGRA` o `QUEDA`, con razón en `nota`. El inventario conserva esas dos columnas cuando se regenera.
4. Trabajar por **lotes de módulos**, registrar la decisión en el TSV y traducir sólo los tests que observan comportamiento ejecutable en Synsema. Verificar en bloque con `python scripts/v0668_verify.py --glob 'modulo*.test.syn' --rust core` (o `--rust runtime`). El script guarda logs completos en un directorio temporal y muestra sólo resúmenes y fallos.
5. Antes de borrar un test Rust, comparar sus aserciones con las del gemelo. Las dos suites verdes por sí solas no prueban equivalencia. Usar una mutación representativa del comportamiento compartido para comprobar que ambos corredores detectan el defecto. Borrar sólo los gemelos revisados, comprobar que no quedan duplicados y hacer commit del lote.

## Estado comprobado el 2026-11-24

- Último lote ya guardado en Git antes de crear estas herramientas: `04dbb24`. El árbol estaba limpio.
- Core `it`: 303 passed. Runtime `it`: 456 passed, 29 ignored. Se reconstruyó el ejecutor del oráculo antes de la suite runtime.
- 0 nombres duplicados Rust/Synsema según el comprobador local.
- Inventario mecánico: 1564 tests Rust, 249 candidatos en 59 archivos y 1315 exclusiones mecánicas. **249 no es la cantidad de tests que deben migrarse**: contiene falsos positivos conocidos, como pruebas de allocator y del host. Las exclusiones también merecen una auditoría por muestreo.
- Los apuntes de lotes anteriores están en `specs/v0.6.68-rondas/` en este equipo. `specs/` está ignorado por Git; este README y los scripts son la referencia versionada para reanudar.

## Reglas de decisión

`MIGRA` si el test puede afirmar dentro de `.test.syn` el mismo valor, error recuperable o efecto observable que afirmaba Rust. `QUEDA` si el contrato observado depende del host: parseo/check estático, diagnóstico estructurado, conteo de pasos o memoria, stdout decorado del ejecutor, estado o variables del proceso, sockets/servicios reales, tiempos, o resultado `RunResult` que el runner `.syn` no expone. Revisar las llamadas indirectas a `run_program`: el clasificador las detecta, pero su motivo sigue siendo una pista.

No usar `synsema test tests/` como gate general: incluye archivos `.probe.syn` y requiere `ETH_KEY` en dos casos. Seleccionar archivos `*.test.syn` concretos. Comprobar si el destino ya existe antes de escribir; `tests/v0665_tables.test.syn` se sobrescribió accidentalmente una vez y hubo que recuperarlo.

## Próximo paso

Clasificar los 249 candidatos en el TSV por familias; comenzar por archivos con menor número de casos, automatizar las traducciones repetitivas en borradores y revisar las diferencias. No borrar Rust a partir del inventario ni de un resultado verde aislado. Actualizar esta sección y el TSV en cada commit para que el siguiente modelo sepa exactamente qué queda.
