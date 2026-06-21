# Synsema Deployment

Synsema ships as a **single static binary** (the Rust build) — no Python, no Node, no
runtime on the target. Install it with `cargo install --path rust/crates/synsema-cli` or
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
cargo install --path rust/crates/synsema-cli    # installs the `synsema` binary
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
ExecStart=/usr/local/bin/synsema serve /opt/agents/my_agent.syn
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
