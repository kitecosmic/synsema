# Synsema Deployment

## Running modes

```bash
# Foreground (exits when program finishes)
synsema run program.syn

# Foreground, stays alive for crons and agents
synsema run program.syn --serve

# Background daemon (detaches from terminal, survives logout)
synsema daemon start program.syn

# Manage daemons
synsema daemon status                   # list all
synsema daemon logs program.syn         # view logs
synsema daemon stop program.syn         # graceful stop
synsema daemon restart program.syn      # restart
```

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
    synsema run my_agent.syn --serve

# Docker Compose (edit docker-compose.yml)
docker compose up -d
```

## VPS deployment (Linux)

```bash
# 1. Clone and install
git clone https://github.com/kitecosmic/synsema.git
cd synsema && pip install -e .

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
ExecStart=/usr/local/bin/synsema run /opt/agents/my_agent.syn --serve
Restart=always
RestartSec=5
User=synsema

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
        command: ["synsema", "run", "/app/agent.syn", "--serve"]
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: api-keys
              key: anthropic
```

## Platform support

| Platform | run | --serve | daemon | Docker |
|----------|-----|---------|--------|--------|
| Linux    | yes | yes     | yes    | yes    |
| macOS    | yes | yes     | yes    | yes    |
| Windows  | yes | yes     | yes    | yes    |
