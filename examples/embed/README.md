# Embedding Synsema (WebAssembly)

Synsema agents inside apps written in other languages — no Synsema backend, nothing
installed on the host. Two artifacts (see `engine/crates/synsema-wasm*` and the docs page
*WebAssembly*):

| Artifact | Build | Use |
|---|---|---|
| `synsema-wasm-web.wasm` (`wasm32-unknown-unknown`) | `cargo build --manifest-path engine/Cargo.toml -p synsema-wasm-web --target wasm32-unknown-unknown --profile wasm` | **embed**: JSON ABI (`synsema_call`) + 3 imports (`synsema_host`); your app lends `http`/`kv`/`llm` |
| `synsema-wasm.wasm` (`wasm32-wasip1`) | `cargo build --manifest-path engine/Cargo.toml -p synsema-wasm --target wasm32-wasip1 --profile wasm` | **CLI** for wasmtime / TEEs / WASI hosts (files via `--dir`) |

Each example is a runnable demo that exits 1 if anything is off — CI runs all of them.

- `node/demo.mjs` — Node/Bun via the npm package `@synsema/wasm` (`packages/synsema-wasm`):
  sync host (`kv` + `llm`), `handle()` (serve in handler mode), async host (`runAsync`
  with a real `fetch`). `node examples/embed/node/demo.mjs`
- `node/run-wasip1.mjs` — the wasip1 CLI under Node's own WASI (`node:wasi`), no wasmtime.
  `node examples/embed/node/run-wasip1.mjs synsema-wasm.wasm program.syn`
- `python/` — `synsema_wasm.py` (glue over wasmtime-py, ~150 lines) + `demo.py`.
  `pip install wasmtime && python examples/embed/python/demo.py`
- `go/` — glue over wazero (pure Go, no CGO) + demo. `cd examples/embed/go && go run .`

The program keeps its manifest (`require net("host")`, `require llm`, `require
memory("name")`); the host decides what it lends; a `ceiling` from the host denies above
that; `audit` in every response lists each capability check.
