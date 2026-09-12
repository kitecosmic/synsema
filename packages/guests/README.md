# Guests — Synsema running inside another host

The engine exposes **one** generic embedding ABI, `synsema-wasm-web` (`synsema_alloc`,
`synsema_free`, `synsema_call` with JSON operations `run | test | check | handle | version`, plus
three optional host imports). Every host that wants Synsema inside — a confidential coprocessor,
a serverless runtime, a plugin system — gets a **thin adapter here**, never a crate in
`engine/crates`. This is the *host axis* of the two-axis rule:

- **Client axis** (Synsema talking *to* X): only protocol primitives with a public specification
  enter the stdlib, named by family (EVM, Solana, Bitcoin, WebCrypto), never by company. If X is
  compatible with a family already covered, the cost is zero and it lives in the program.
- **Host axis** (Synsema running *inside* X): the engine keeps one generic ABI; each host is a
  directory here — `packages/guests/<host>/` — that maps the host's exports onto that ABI, with
  the `.syn` program embedded. If an adapter needs something the generic ABI lacks, it is added as
  a new, documented `synsema_call` operation useful to every host — never as a special export for
  one of them. A company's name appears in this directory, not in the engine.

| Guest | Host ABI | Target | Status |
|---|---|---|---|
| [`vela/`](vela/) | Vela (Horizen) — `allocate`/`deallocate`/`load_module`/`deploy`/`deposit`/`process_request`/`trusted_request` | `wasm32-wasip1` (Vela's linker defines WASI only) | ABI read from `vela/pkg/wasm/wasmtime_runtime.go` + `vela-common-go` v0.2.0; probed under Node's WASI in CI and under wasmtime-go v1.0.0 (the Executor's runtime, `vela/tests/wasmtime-go/`); verified end to end in the starter kit (Docker): three example apps (ledger, `novaw`-compatible payment app, trigger-driven execution pool), a client in Synsema (`vela/examples/client/`: register, deploy, deposit ETH/ERC-20, encrypted requests, reports, events, facilitator meta-transactions), a trigger contract and an ERC-20 with permit |

## Adding a host — copy `vela/` and rename

1. `cp -r packages/guests/vela packages/guests/<host>`; rename the package in `Cargo.toml`
   (`synsema-<host>-guest`).
2. Read the host's contract **from its source**: which exports it calls, their exact signatures,
   how it writes inputs into guest memory, how it reads results, which imports it provides
   (WASI? nothing?), and what it forbids (time, randomness, network). Write that down at the top of
   `src/lib.rs` with the file and version it came from — the adapter is only as right as that
   reading.
3. Pick the target from the imports the host provides: `wasm32-wasip1` when it links WASI (stdout
   becomes your log channel), `wasm32-unknown-unknown` only if the host is willing to provide the
   `synsema_host` imports of the generic ABI.
4. Keep the shape: the host's exports decode inputs → build a context map → `run_app(task, …)`
   → encode the task's result map into the host's exact result format. Everything the program
   sees is a value; everything the host sees is its own struct. `fuel`/cost = the app's declared
   value or the interpreter's deterministic `steps`.
5. The ceiling is the contract of determinism: `"stdout"` means no `time`, no `random`, no host.
   Widen it only if the host really offers those things deterministically.
6. Write the Node (or wasmtime) probe under `tests/` and wire it in `ci.yml`; the release publishes
   the example artifact so people can try the guest before building their own.
7. Document the `.syn` contract in the guest's README: task names, the context each one receives,
   the map it must return, and how errors travel.
