#!/usr/bin/env bash
# Entrenamiento de PGO para el binario del release (specs/compute-rendimiento.md F1.12; medido:
# −16 % a −32 % en el arnés de rendimiento). `release.yml` compila un `synsema` instrumentado
# (`-Cprofile-generate`), lo corre sobre este corpus y compila el binario publicado con el perfil
# (`-Cprofile-use`). El perfil sólo decide cómo ordena y optimiza el código el compilador: no cambia
# lo que hace ningún programa.
#
#   engine/pgo/train.sh <synsema instrumentado>
#
# El corpus es lo que un programa típico hace, sin red ni reloj: engine/pgo/train/ (tiene que correr
# sin error; si deja de hacerlo, el perfil entrenaría otra cosa y el script falla), los casos del
# oráculo (algunos terminan en error a propósito) y los tests del lenguaje. No usa
# specs/compute-bench, que es con lo que se mide la ganancia.
set -u
# Ruta absoluta: cada programa corre desde su carpeta (sus `use` relativos), y release.yml pasa la
# ruta del binario relativa a la raíz del repo.
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LIMIT=120

# `timeout` no existe en macOS: límite de tiempo en bash puro.
run_limited() {
    "$@" >/dev/null 2>&1 &
    local pid=$!
    ( sleep "$LIMIT"; kill "$pid" 2>/dev/null ) &
    local watcher=$!
    wait "$pid"
    local rc=$?
    kill "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    return $rc
}

n=0
bad=0
for f in "$ROOT"/engine/pgo/train/*.syn; do
    n=$((n + 1))
    if ! (cd "$(dirname "$f")" && run_limited "$BIN" run "$f"); then
        echo "::error::pgo: $f falló; el corpus de entrenamiento tiene que correr sin error"
        bad=$((bad + 1))
    fi
done
for f in "$ROOT"/engine/crates/synsema-runtime/tests/oracle_cases/*.syn "$ROOT"/engine/crates/synsema-runtime/tests/oracle_cases/errors/*.syn; do
    n=$((n + 1))
    (cd "$(dirname "$f")" && run_limited "$BIN" run "$f") || true
done
for f in "$ROOT"/tests/*.test.syn; do
    n=$((n + 1))
    (cd "$(dirname "$f")" && run_limited "$BIN" test "$f") || true
done
echo "pgo: $n programas de entrenamiento"
[ "$bad" -eq 0 ]
