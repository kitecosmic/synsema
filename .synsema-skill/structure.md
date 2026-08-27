# Synsema Codebase Structure

Synsema is a **Rust** language: a single static binary, one Cargo workspace. (The old
`synsema/` Python tree is **frozen** and not the source of truth — ignore it; everything
lives under `engine/`.)

```
engine/
├── Cargo.toml                       # workspace + pinned deps (all pure-Rust except bundled SQLite)
└── crates/
    ├── synsema-core/                # START HERE for language internals
    │   └── src/
    │       ├── tokens.rs            # token types + keyword map
    │       ├── lexer.rs             # source → tokens (significant whitespace)
    │       ├── ast.rs               # NodeKind = the grammar
    │       ├── parser.rs            # tokens → AST (recursive descent + Pratt)
    │       ├── interpreter.rs       # AST → execution (tree-walking) + builtins
    │       ├── types.rs             # SynValue (incl. bytes/complex/array), constructors
    │       ├── number.rs            # Int/Big/Float/Decimal tower (battle-tested; don't touch lightly)
    │       ├── math.rs              # math lib (trig/exp/gamma/erf/…) — pure fns over Number
    │       ├── arrays.rs            # numeric arrays + linear algebra (ndarray + faer)
    │       ├── bytesutil.rs         # hex/base64 (hand-rolled, zero-dep)
    │       ├── ast_api.rs           # structural manipulation (children, find, rename)
    │       ├── addressable.rs       # token-efficient code addressing
    │       ├── templates.rs         # SSR template engine (render)
    │       ├── secret.rs            # opaque `secret` value (zeroize + constant-time eq)
    │       └── flat_syntax.rs       # .fsyn → .syn translator
    │
    ├── synsema-capabilities/        # security layer (deny-by-default)
    │   └── src/{model.rs, secure.rs, intent.rs}   # CapabilitySet; gated builtins; intent freeze
    │
    ├── synsema-runtime/             # execution engine (wires everything)
    │   └── src/
    │       ├── engine.rs            # run_source / Engine / swarm wiring (capability + sandbox hooks)
    │       ├── serve.rs             # `serve on PORT`: per-request snapshot, state_*, routes
    │       ├── parallel.rs          # parallel_map / chunk (tokio M:N executor)
    │       ├── daemon.rs            # background process management
    │       ├── persistence.rs       # cross-run state (memory/progress)
    │       ├── recovery.rs          # retry/fallback/escalation
    │       └── error_reporter.rs    # rich diagnostics + suggestions
    │
    ├── synsema-stdlib/              # standard library — feature `native` (default) gates the
    │   │                            # OS-facing modules; without it the PURE subset compiles
    │   │                            # to wasm32 (CI-anchored against wasm32-wasip1)
    │   └── src/
    │       ├── http.rs              # HTTP client (std::net + rustls for https) [native]
    │       ├── http_stub.rs         # no-`native` stand-in: same transport signatures, errors at runtime
    │       ├── server.rs            # async HTTP server (hyper/tokio): response contract, TLS, vhost, proxy, WebSocket upgrade, timeouts, ordered shutdown [native]
    │       ├── ws.rs                # the I/O hub: ws client + incoming sockets + proc + bus subscriptions on one mio poll → `select` [native]
    │       ├── proc.rs              # live child processes (`proc_*`): reader threads per pipe, bounded queues, kill/reap; `pty: true` via portable-pty (openpty/ConPTY, DSR handshake) [native]
    │       ├── database.rs          # SQLite (rusqlite, bundled) + PG/MySQL/Mongo/Redis [native]
    │       ├── cron.rs              # cron scheduler [native]
    │       ├── json.rs              # JSON ↔ SynValue + content-tree-as-data + json_encode/decode builtins (pure)
    │       ├── respond.rs           # response helpers (ok/created/…/set_cookie) + content() vocabulary (pure)
    │       ├── secrets.rs           # env/secret/reveal/bearer + HMAC/sha hashing
    │       ├── acme.rs              # auto-HTTPS (ACME, instant-acme) [native]
    │       └── mimetypes.rs         # static-file content types
    │
    ├── synsema-agents/              # multi-agent system
    │   └── src/{blackboard.rs, bus.rs, swarm.rs, resource_lock.rs, progress.rs, memory.rs, builtins.rs}
    │       # bus.rs = in-process pub/sub (bounded per-subscriber queues, glob topics) used by `bus_*`
    │
    ├── synsema-llm/                 # LLM + human interaction
    │   └── src/{provider.rs, context.rs, validator.rs, human.rs}
    │
    ├── synsema-cli/                 # the `synsema` binary
    │   └── src/main.rs             # subcommands: run / check / test / serve / conform / repl / daemon
    │
    ├── synsema-wasm/                # lib (pure wiring, run/test/check/handle, HostProvider) + wasip1 CLI bin (v0.6.0+)
    └── synsema-wasm-web/            # cdylib wasm32-unknown-unknown: JSON ABI + `synsema_host` imports (browser/Node/Python/Go)
        └── src/main.rs             # run / --test / stdin over the PURE stdlib profile (see deploy.md § WebAssembly)
```

## Key entry points
- **Run a program**: `run_source()` in `synsema-runtime/src/engine.rs`.
- **Parse code**: `parse_source()` in `synsema-core/src/parser.rs`.
- **Add a pure builtin**: register in `synsema-core/src/interpreter.rs::register_builtins`.
- **Add a capability-gated builtin**: `synsema-capabilities/src/secure.rs` (wired in `engine.rs`).
- **Add a serve builtin**: `synsema-stdlib/src/server.rs` (or `serve.rs` for the per-request wiring).
- **Add a capability type**: `synsema-capabilities/src/model.rs`.
- **Add an LLM provider**: `LLMProvider` in `synsema-llm/src/provider.rs`.

## Tests
Per-crate Rust tests under `crates/*/tests/` and `#[cfg(test)]` modules. Run with
`cargo test --workspace`. The semantic-invariant net lives in `synsema-core` (equality/order/
coercion property tests). `.syn`-level self-tests use the native test framework (`synsema test`).
