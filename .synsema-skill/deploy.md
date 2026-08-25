# Synsema Deployment

Synsema ships as a **single static binary** (the Rust build) — no Python, no Node, no
runtime on the target. Install it with `npm i -g synsema` (the native binary via npm, v0.6.3+ — `npx synsema` works too), `cargo install --path engine/crates/synsema-cli` or
grab a prebuilt binary from the GitHub Releases page.

## Running modes

```bash
# Run once (exits when the program finishes)
synsema run program.syn

# Serve: stay alive for HTTP (serve on), crons and agents
synsema serve program.syn

# Background daemon (detaches from terminal, survives logout)
synsema daemon start program.syn

# Manage daemons
synsema daemon status                   # list all
synsema daemon logs program.syn         # view logs
synsema daemon stop program.syn         # graceful stop
synsema daemon restart program.syn      # restart
```

## Configuration & secrets (`.env` / environment)

Read config with `env("NAME", default?)` and secrets with `secret("NAME", default?)` —
see [secrets.md](secrets.md). Resolution: **process environment → `.env` file → default**.

- **Dev:** drop a `.env` in the working directory (`synsema serve app.syn` auto-loads it).
  Keep `.env` in `.gitignore`; commit a `.env.example` with the keys (no values).
- **Prod:** set real values via the environment — they **override** `.env` without editing
  the repo:
  - systemd: `Environment=DATABASE_URL=...` (or `EnvironmentFile=/etc/app.env`)
  - Docker: `-e DATABASE_URL=...` (as in the examples below)
  - Kubernetes: `env:` / `secretKeyRef:` (as in the example below)
- Override the `.env` location with `--env-file <path>` (or `SYNSEMA_ENV_FILE=<path>`);
  disable it with `--no-env-file`.
- `reveal()` (if you use it) appends to an audit log at `$SYNSEMA_AUDIT_DIR` or
  `~/.synsema/audit/reveal.log` — under systemd, set `SYNSEMA_AUDIT_DIR` or a writable
  `HOME`/`StateDirectory`, or `reveal()` will fail (by design: no audit, no reveal).
- `SYNSEMA_SERVE_WORKERS=N` sizes the request-handling interpreter pool (default:
  `#cores`, min 2). Raise it for I/O-bound handlers (more concurrent requests, more
  RAM); it is read **once, from the process environment** (systemd `Environment=`,
  `docker -e`, shell export — **not** `.env`, which only feeds `env()`/`secret()`)
  before the first server starts.

## Serve deployment flags (dev-clean `.syn` + prod flags)

The `serve` block stays **declarative and dev-clean** in the repo; deployment knobs
(port, TLS, domains, bind address) are injected at launch with CLI flags. The same
`.syn` runs locally with no setup (plain HTTP, high port) and in prod (443 + TLS +
domain) **without editing the file**.

```bash
synsema serve <file> [--secure]
    [--port N]                       # override `serve on N` AND grant serve(N)
    [--domain d1[,d2,...]]           # ACME SAN domains (overrides `domain` in the file)
    [--tls-auto <email> | --tls-cert <path> --tls-key <path>]
    [--bind <addr>]                  # bind address (default 0.0.0.0)
```

| Flag | Effect |
|---|---|
| `--port N` | Overrides `serve on N` **and grants the `serve(N)` capability** (the operator passing the flag is the authority, so the file's `require serve(...)` need not match). |
| `--domain d1,d2` | Sets/overrides the ACME SAN domains (comma-separated). |
| `--tls-auto <email>` | Turns on auto-HTTPS (ACME) with that account email. **Its presence is the dev↔prod toggle.** Brings up the `:80` challenge/redirect listener — move it with `SYNSEMA_ACME_HTTP_PORT=8080` (process env, not `.env`) when something else owns port 80, and forward external `:80` to it; the CA must reach the challenge from the public internet. Requires a domain (`--domain` or `domain` in the file). |
| `--tls-cert <p> --tls-key <p>` | Manual TLS. **Mutually exclusive** with `--tls-auto`. |
| `--bind <addr>` | Bind address (default `0.0.0.0`). |

**Precedence: CLI flag > file clause > default.**
- No `--tls-auto` and no `tls` in the file → **plain HTTP** (dev).
- `--tls-auto` (even if the file has no `tls`) → **TLS** (prod). This is the switch.
- `--port` overrides `serve on N` and satisfies `serve(N)`.
- Fail-loud: `--tls-auto` with no domain → error; `--tls-auto` together with `--tls-cert` → error; invalid port → error.
- The flags configure **one** deployment: with **multiple `serve` blocks** in the file they are rejected with a clear error (the common case is a single `serve`).

Canonical pattern — one servable file, dev-clean in the repo. The **filename is arbitrary**: name it after what the program *is* (`api.syn`, `agent.syn`, `worker.syn`, `app.syn`, …). There is no magic name and nothing is tied to `site` — `synsema serve <anyname>.syn` works:

```
require serve(8080)
serve on 8080
    static "/" from "./public"
    route "GET /" ...
```
- Dev:  `synsema serve app.syn`  → `:8080`, plain HTTP, runs with nothing else.
- Prod: `synsema serve app.syn --port 443 --domain example.com,www.example.com --tls-auto admin@example.com`

> Use `env()`/`secret()` for runtime **values** (DB URL, API keys) and these flags for
> the **deployment structure** of `serve`. The `serve` block has no `when`/conditionals
> by design — the flags keep it declarative.

## `synsema daemon` vs systemd — pick ONE

These are **two different supervisors**; don't run the same service under both.

- **`synsema daemon`** = Synsema's **built-in** background manager. Quick to start
  (`synsema daemon start app.syn`), no OS config. But it does **not** start on boot and does **not**
  restart on crash. Good for: dev, a box without systemd, quick background runs.
- **systemd** = the OS supervisor (the systemd unit above). Starts on boot (`enable`), restarts on
  crash (`Restart=always`), journald logs, `StateDirectory`/env. **Use this for production** (real
  service, HTTPS, auto-restart). To update it: replace the binary + `systemctl restart` (see above).

Rule of thumb: **production web service with TLS → systemd**; `synsema daemon` is the no-OS-setup
shortcut.

## Daemon details

- Detaches from terminal (real process fork on Unix, subprocess on Windows)
- Writes PID file at `~/.synsema/daemons/<name>/pid`
- Logs to `~/.synsema/daemons/<name>/log`
- Stores metadata at `~/.synsema/daemons/<name>/meta`
- Multiple daemons can run simultaneously
- Survives terminal close, SSH disconnect, etc.

## Docker

The image is **just the Synsema binary** — the same prebuilt static binary the site
installs; the `Dockerfile` fetches it from the GitHub release and verifies its checksum
(it does not compile). Mount your `.syn` program into `/app`.

```bash
docker build -t synsema .                      # or: --build-arg SYNSEMA_VERSION=v0.4.9

# Run once (mount the current directory)
docker run --rm -v "$PWD":/app -w /app synsema run hello.syn

# Persistent service
docker run -d --restart unless-stopped \
    -e ANTHROPIC_API_KEY=sk-... \
    -v "$PWD":/app -w /app -p 8080:8080 \
    synsema serve app.syn

# Or Docker Compose (see docker-compose.yml)
docker compose up -d
```

## VPS deployment (Linux)

```bash
# 1. Clone and build the single static binary (Rust)
git clone https://github.com/kitecosmic/synsema.git
cd synsema
cargo install --path engine/crates/synsema-cli    # installs the `synsema` binary
# (or download a prebuilt binary from the GitHub Releases page)

# 2. Start as daemon
synsema daemon start /path/to/agent.syn

# 3. Verify
synsema daemon status
synsema daemon logs agent
```

For auto-start on boot, create a systemd service:

```bash
cat > /etc/systemd/system/synsema-agent.service << 'EOF'
[Unit]
Description=Synsema Agent
After=network.target

[Service]
Type=simple
# The .syn stays dev-clean (`serve on 8080`, no tls/domain). Prod deployment config
# lives here as flags — the same file runs locally with just `synsema serve app.syn`.
ExecStart=/usr/local/bin/synsema serve /opt/agents/app.syn \
    --port 443 --domain example.com,www.example.com --tls-auto admin@example.com
Restart=always
RestartSec=5
User=synsema
# tls auto stores certs under ~/.synsema/certs, but systemd usually starts the
# service with an empty HOME. StateDirectory= creates /var/lib/synsema (owned by
# User=) where Synsema falls back to. Alternatively set Environment=HOME=/home/synsema
# or Environment=SYNSEMA_CERT_DIR=/some/abs/path.
StateDirectory=synsema

[Install]
WantedBy=multi-user.target
EOF

systemctl enable synsema-agent
systemctl start synsema-agent
```

## Multiple sites on one host (Synsema is its own edge proxy)

Two processes can't both bind `:443`, and you **don't need nginx/Caddy**. One Synsema process is the
**edge**: it terminates TLS for every domain (one SAN cert) and routes by `Host` to each backend, which
runs plain-HTTP on a private port.

```
-- edge.syn — TLS + Host routing for every site on the box
require serve(443)
require net("127.0.0.1")            -- deny-by-default: the edge only talks to localhost

serve on 443
    host "example.com"
        route "GET /"                              -- root: /*path does NOT match "/"
            proxy to "http://127.0.0.1:8080"
        route "GET /*path"
            proxy to "http://127.0.0.1:8080"
        route "POST /*path"
            proxy to "http://127.0.0.1:8080"
    host "docs.example.com"
        route "GET /"
            proxy to "http://127.0.0.1:8791"
        route "GET /*path"
            proxy to "http://127.0.0.1:8791"
        route "POST /*path"
            proxy to "http://127.0.0.1:8791"
```

Run the edge with a SAN cert for all domains; each backend runs plain-HTTP, localhost-only, with its own
repo/version/systemd unit:

```bash
synsema serve edge.syn --port 443 --domain example.com,docs.example.com --tls-auto admin@example.com
synsema serve app.syn  --port 8080 --bind 127.0.0.1     # backend 1
synsema serve docs.syn --port 8791 --bind 127.0.0.1     # backend 2
```

- **Root gotcha:** `route "GET /*path"` needs ≥1 segment — it does **not** match `/`. Add `route "GET /"`
  too (per method) so the home page reaches the backend.
- **Per method:** `route` binds method+path — declare each method you forward (GET, POST, …).
- `proxy to` forwards status + content-type + body **and** the upstream's end-to-end headers (`Location`,
  `Set-Cookie`, `Cache-Control`, `ETag`, …), so redirects/cookies/caching work through the edge; hop-by-hop
  are dropped and invalid headers skipped.
- **Independent deploys:** restart one backend without touching the others; each can even run a different
  Synsema version behind the same edge.

## Updating a deployed server (it does NOT auto-update)

A running server does **not** update itself. To roll out a new version:

```bash
synsema update                    # swaps the binary on disk (downloads the release, verifies sha256)
systemctl restart synsema-agent   # REQUIRED — the live process keeps the OLD binary until restart
```

- `synsema update` replaces the binary **file**, but the running process keeps the old binary in
  memory. The **`systemctl restart` is what applies the new version**.
- **Restart is safe — TLS certs persist.** `tls auto` stores certs (order: `SYNSEMA_CERT_DIR` →
  `~/.synsema/certs` → an absolute system default) and auto-renews them in the background (30 days
  before the 90-day expiry). A restart **reloads** the stored cert — it does **not** re-issue, so you
  won't hit Let's Encrypt rate limits.
- If `synsema update` targets a binary at a different path than the unit's `ExecStart`, update that
  path (or point both at the same binary), then restart.

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: synsema-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: synsema-agent
  template:
    metadata:
      labels:
        app: synsema-agent
    spec:
      containers:
      - name: agent
        image: synsema:latest
        command: ["synsema", "serve", "/app/agent.syn"]
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: api-keys
              key: anthropic
```

## Platform support

| Platform | run | serve | daemon | Docker |
|----------|-----|-------|--------|--------|
| Linux    | yes | yes   | yes    | yes    |
| macOS    | yes | yes   | yes    | yes    |
| Windows  | yes | yes   | yes    | yes    |

## WebAssembly — TEEs, confidential jobs, edge, and embedding in other apps (v0.6.0+)

Two wasm artifacts, one pure profile (same wiring, `engine/crates/synsema-wasm`):

- **`synsema-wasm.wasm` (wasm32-wasip1)** — a CLI for wasmtime / TEE job runners / any
  WASI host. Files and `.env` via WASI preopens; no host hooks (net/LLM/memory fail with
  the truth of the environment). Also runs under Node's `node:wasi` (examples/embed/node/run-wasip1.mjs).
- **`synsema-wasm-web.wasm` (wasm32-unknown-unknown, crate `synsema-wasm-web`)** — the
  EMBEDDABLE artifact: a plain JSON ABI (`synsema_call`) + three imports (`synsema_host`).
  Browser, Node/Bun/Deno (npm `@synsema/wasm`, packages/synsema-wasm), Python
  (wasmtime-py, examples/embed/python), Go (wazero, examples/embed/go). The HOST lends
  capabilities — `http`, `kv`, `llm`, `log`, `sleep` — and the program still declares
  `require net/llm/memory`; a `ceiling` from the embedder denies above what the host lends.
  No filesystem (`read_file` says so; pass data via `env`/source). ~7.5 MB (2.6 MB gzip).

```bash
# build (from a checkout)
rustup target add wasm32-wasip1 wasm32-unknown-unknown
cargo build --manifest-path engine/Cargo.toml -p synsema-wasm --target wasm32-wasip1 --profile wasm
cargo build --manifest-path engine/Cargo.toml -p synsema-wasm-web --target wasm32-unknown-unknown --profile wasm
# artifacts: engine/target/wasm32-wasip1/wasm/synsema-wasm.wasm
#            engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm

# wasip1 CLI (wasmtime): run / test / stdin / env / host ceiling — same flags as `synsema run`
wasmtime run --dir . synsema-wasm.wasm program.syn
wasmtime run --dir . synsema-wasm.wasm --test program.syn
wasmtime run --env ETH_KEY=... synsema-wasm.wasm -  < program.syn
wasmtime run --dir . synsema-wasm.wasm --sandbox program.syn                 # ceiling = [stdout, time]
wasmtime run --dir . synsema-wasm.wasm --cap-set stdout,secret=ETH_* program.syn
wasmtime run synsema-wasm.wasm --version      # the artifact's version (release tag, or v<crate>-dev)
```

`synsema-wasm [--test] [--sandbox | --cap-set <list>] [--version] <file.syn | ->`. An unknown
`--flag` is an error (exit 2), never silently taken as the program path. Exit codes: 0 ok,
1 runtime/test failure, 2 usage/read error.

```js
// embed (Node/Bun/browser) — @synsema/wasm
import { Synsema } from "@synsema/wasm";
const syn = await Synsema.load(new URL("@synsema/wasm/synsema.wasm", import.meta.url));
await syn.ready();
const host = {
  http: (req) => ({ status: 200, headers: [], body: "{}" }),        // sync; or async with runAsync
  kv: { get: (ns, k) => store.get(ns + "/" + k) ?? null, set: (ns, k, v) => store.set(ns + "/" + k, v) },
  llm: (op, prompt) => ({ content: "...", tokens: 12 }),
};
syn.run('require memory("agenda")\nremember("preference", "dark mode")', { host, filename: "agenda.syn" });
syn.run('require llm\nprint(reason about "x")', { host, ceiling: "stdout" });  // denied: ceiling wins
const res = syn.handle('require serve(1)\nserve on 1\n    route "GET /hi/:n"\n        give {"hi": params.n}', { method: "GET", path: "/hi/ana" }, { host });
await syn.runAsync(program, { host: { async http(req) { const r = await fetch(req.url); return { status: r.status, headers: r.headers, body: await r.text() }; } } });
```

API (same in JS/Python/Go): `run(source, {filename, env, ceiling, host})` →
`{ok, output, errors, audit, llm_tokens}`; `test` → `{passed, failed, lines}`; `check` →
`{ok, errors}` (parse + the memory-declaration rule — one `require memory`, valid name; a
`remember` WITHOUT `require memory` is NOT flagged here, it's denied at `run` — same as native
`synsema check`); `handle(source, request)` →
`{status, content_type, headers, body|body_base64, log, errors}` (serve in HANDLER mode:
routes/params/query/`auth with`/`errors with`/`content()` negotiation/`redirect`/
pagination/`state_*` durable through `kv`; NOT: `stream`, `proxy to`, rate limits,
`static`, vhosts, TLS — the edge platform does those); `version()`. Handler mode keeps the
native doctrine: `require serve(port)` is still mandatory (the manifest, not the socket), and
each request runs on a **snapshot of the globals** — a `set` on a global inside a handler does
NOT persist to the next request; shared state goes through `state_*` (durable via `kv`).

What the host lends: `http` backs `fetch`/`http_*`/blockchain RPC read-side AFTER the
`net(host)` gate (same URL canonicalization as native); `kv` backs `remember`/`recall`/
rules/progress (namespace `memory:<declared name>` — the declared name IS the identity;
`memory_summary` reports `Backend: host-kv`) and `state_*` (namespace `state`); `llm`
backs `reason`/`decide`/`analyze`/`generate` (`llm_available()` true, `llm_usage()` sums
the tokens the host reports). Async hosts (browser fetch, LLM SDKs): `runAsync`/
`handleAsync` run the interpreter in a Worker and block with `Atomics.wait` on a
SharedArrayBuffer (browsers need COOP/COEP); Node/Bun work out of the box. `now()` =
host clock, `random()`/`token()`/signature nonces = host entropy (`crypto.getRandomValues`,
`os.urandom`, `crypto/rand`). A trap (panic) discards the instance; the glue recreates it.
Errors of the program are DATA (`errors[]`), never exceptions. The `audit` lists every
capability check — `{capability, granted, source, reason, origin}`. `reason` says why a denial
happened (`No matching grant found` = never declared; `above host ceiling (--sandbox/--cap-set)` =
declared but the host doesn't lend it; `Explicitly denied by …`), and `origin` says who put the
entry there: `"program"` (a `require` or a call of the program) vs `"runtime"` (an ambient grant
the host tried — `time`/`llm` under a ceiling — that the program never asked for). "This tenant
tried to read STRIPE_KEY" = `origin == "program" && !granted`; no need to re-parse the source.

Value in wasm: `sign`/`spend`/`wallet`/`reveal` are fail-loud (no audit line → no operation). A wasm
host has no filesystem, so the audit line goes to the host `kv` under namespace `audit` (key
`sign.log`/`spend.log`/`wallet.log`/`reveal.log`, append-only, never key material). Offer `kv` → they
work under your ceiling (`sign=ETH_KEY`, `spend=USD`, `wallet=mnemonic*`); no `kv` → *this host
provides no audit sink*. Runaway recursion is a runtime error, never a trap.

Not a dialect: full language + templates, numeric tower + arrays, JSON/CSV/regex/stats,
`chart_svg` + PNG/PDF, hashing/HMAC/`secret`, the whole PURE blockchain side, web-auth
pure side, `sandbox`/`intent`/per-tool scoping, response helpers + `content()`,
multi-agent in-process, `parallel_map`/`chunk` sequential — all byte-identical to the
native binary (CI diffs the probes under wasmtime AND through the embed API under Node).
NOT in either artifact — the names exist and fail saying why: `ws_*`, `mtls_identity`
(no sockets/event loop), `db_open`/`sql`/`mongo_*`/`redis_*` (no drivers — in edge, reach
D1/Neon/Upstash over `http`), `cron_*` (the host schedules), real threads (`spawn`/
`parallel_map` run in-process). Without a host `http`: `fetch: … this host provides no http
transport`; without `kv`: `memory "x" is declared but this host provides no durable storage`;
without `llm`: the core's offline placeholders. Playground: `/play` on the docs site
(runs the wasm in the browser, no server). Release assets: `synsema-wasm-wasip1.wasm`,
`synsema-wasm-web.wasm` (+ .sha256).

