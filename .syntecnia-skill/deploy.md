# Syntecnia Deployment

## Running modes

```bash
# Foreground (exits when program finishes)
syntecnia run program.syn

# Foreground, stays alive for crons and agents
syntecnia run program.syn --serve

# Background daemon (detaches from terminal, survives logout)
syntecnia daemon start program.syn

# Manage daemons
syntecnia daemon status                   # list all
syntecnia daemon logs program.syn         # view logs
syntecnia daemon stop program.syn         # graceful stop
syntecnia daemon restart program.syn      # restart
```

## Daemon details

- Detaches from terminal (real process fork on Unix, subprocess on Windows)
- Writes PID file at `~/.syntecnia/daemons/<name>/pid`
- Logs to `~/.syntecnia/daemons/<name>/log`
- Stores metadata at `~/.syntecnia/daemons/<name>/meta`
- Multiple daemons can run simultaneously
- Survives terminal close, SSH disconnect, etc.

## Docker

```bash
# Build
docker build -t syntecnia .

# Run once
docker run syntecnia run examples/hello.syn

# Run as persistent service
docker run -d --restart unless-stopped \
    -e ANTHROPIC_API_KEY=sk-... \
    -v $(pwd)/data:/data \
    syntecnia run my_agent.syn --serve

# Docker Compose (edit docker-compose.yml)
docker compose up -d
```

## VPS deployment (Linux)

```bash
# 1. Clone and install
git clone https://github.com/kitecosmic/Syntecnia.git
cd Syntecnia && pip install -e .

# 2. Start as daemon
syntecnia daemon start /path/to/agent.syn

# 3. Verify
syntecnia daemon status
syntecnia daemon logs agent
```

For auto-start on boot, create a systemd service:

```bash
cat > /etc/systemd/system/syntecnia-agent.service << 'EOF'
[Unit]
Description=Syntecnia Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syntecnia run /opt/agents/my_agent.syn --serve
Restart=always
RestartSec=5
User=syntecnia

[Install]
WantedBy=multi-user.target
EOF

systemctl enable syntecnia-agent
systemctl start syntecnia-agent
```

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: syntecnia-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: syntecnia-agent
  template:
    metadata:
      labels:
        app: syntecnia-agent
    spec:
      containers:
      - name: agent
        image: syntecnia:latest
        command: ["syntecnia", "run", "/app/agent.syn", "--serve"]
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
