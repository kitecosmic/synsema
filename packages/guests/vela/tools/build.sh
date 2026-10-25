#!/usr/bin/env bash
# Compila el guest de Vela y le pone los stubs de WASI: el módulo que publica la release, el que
# prueban las sondas y el que llena `embed.syn`. Lo usan ci.yml, release.yml (el build publicado y las
# dos patas de `guest-reproducible`) y el README, así la receta es una sola.
#
#   bash packages/guests/vela/tools/build.sh <salida.wasm>     (desde la raíz del repo)
#
# Deja el módulo sin stubs en engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm y el que tiene
# los stubs en <salida.wasm>.
#
# v0.6.48 (VG1): el wasm guarda las rutas de las fuentes (las ubicaciones de los panics de Rust). Sin
# remapearlas, el hash dependía de la carpeta del build y del CARGO_HOME, y sólo se reproducía en
# /home/runner/work/synsema/synsema. Con `--remap-path-prefix`, la raíz del repo pasa a ser `/synsema`
# y el CARGO_HOME pasa a ser `/cargo`. La otra mitad es que el workspace del guest esté en la raíz del
# repo (./Cargo.toml dice por qué). Con las dos, el mismo commit da el mismo hash en cualquier carpeta.
# `trim-paths` haría lo mismo, pero en cargo 1.99.1 todavía no es estable.
#
# Sólo en Linux (la WSL lo es). En Windows nativo el módulo sale distinto del publicado aunque el remap
# esté bien escrito. Medido el 2026-10-25: las rutas que quedan en el módulo usan `\`
# (`/cargo\registry\…`), porque el remap sólo cambia el comienzo. Además, por cómo funciona cargo, la
# ruta relativa con la que hashea cada crate del motor lleva esos mismos `\`. Rust no tiene cómo
# normalizar los separadores, así que el script corta en vez de dar un hash que nunca va a coincidir.
#
# Los remaps van por `--config`, no por RUSTFLAGS: RUSTFLAGS reemplaza los `rustflags` de
# `.cargo/config.toml` (el `-zstack-size` de 64 MB del intérprete), y los arrays de `--config` se suman
# a los del archivo. Por lo mismo, un RUSTFLAGS del entorno cambiaría el módulo: se rechaza.
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: bash packages/guests/vela/tools/build.sh <stubbed-output.wasm>   (from the repo root)" >&2
    exit 2
fi
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        echo "build.sh: build the guest on Linux or in WSL. On Windows the module comes out different from the published one (paths use '\\' inside the module and in cargo's crate hashes), so its hash would never match." >&2
        exit 2
        ;;
esac
if [ ! -f packages/guests/vela/Cargo.toml ] || [ ! -f engine/Cargo.toml ]; then
    echo "build.sh: run it from the repo root (packages/guests/vela/Cargo.toml not found here)" >&2
    exit 2
fi
if [ -n "${RUSTFLAGS:-}" ] || [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    echo "build.sh: RUSTFLAGS is set; it would replace the guest's rustflags and change the module. Unset it." >&2
    exit 2
fi

root=$(pwd -P)
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
remap="['--remap-path-prefix=$root=/synsema', '--remap-path-prefix=$cargo_home=/cargo']"

cargo build --locked --manifest-path packages/guests/vela/Cargo.toml --profile wasm --target wasm32-wasip1 \
    --target-dir engine/target --config "target.wasm32-wasip1.rustflags=$remap"
# La herramienta corre desde la raíz a propósito: el .cargo/config.toml del guest la compilaría a
# wasm32-wasip1. Sus rutas no llegan al módulo; se remapea igual, para que nada del build dependa de
# la carpeta.
cargo run --locked --manifest-path packages/guests/vela/tools/wasi-stub/Cargo.toml --config "build.rustflags=$remap" -- \
    engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm "$1"
