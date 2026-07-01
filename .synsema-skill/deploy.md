# Synsema Deployment

Synsema ships as a **single static binary** (the Rust build) — no Python, no Node, no
runtime on the target. Install it with `cargo install --path engine/crates/synsema-cli` or
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
| `--tls-auto <email>` | Turns on auto-HTTPS (ACME) with that account email. **Its presence is the dev↔prod toggle.** Brings up the `:80` challenge/redirect listener. Requires a domain (`--domain` or `domain` in the file). |
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

```bash
# Build
docker build -t synsema .

# Run once
docker run synsema run examples/hello.syn

# Run as persistent service
docker run -d --restart unless-stopped \
    -e ANTHROPIC_API_KEY=sk-... \
    -v $(pwd)/data:/data \
    synsema serve my_agent.syn

# Docker Compose (edit docker-compose.yml)
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
