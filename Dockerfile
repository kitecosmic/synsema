# Synsema in a container — the same prebuilt static binary the website installs,
# dropped into a slim base. The image carries the release binary; it does not compile.
#
#   docker build -t synsema .                                      # latest release
#   docker build -t synsema --build-arg SYNSEMA_VERSION=v0.4.9 .   # pin a version
#
#   docker run --rm synsema version
#   docker run --rm -v "$PWD":/app -w /app synsema run hello.syn
#   docker run -d --restart unless-stopped -e ANTHROPIC_API_KEY=sk-... \
#       -v "$PWD":/app -w /app -p 8080:8080 synsema serve app.syn
#
# Only the linux-x86_64 release is published today (amd64). On an arm64 host
# (e.g. Apple Silicon), build and run with --platform=linux/amd64.
FROM debian:bookworm-slim

# ca-certificates: real TLS validation for https/wss and blockchain RPC (rustls
# uses the OS root store). curl: only to fetch the binary at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# `latest` tracks the newest release; pass --build-arg SYNSEMA_VERSION=vX.Y.Z to pin.
ARG SYNSEMA_VERSION=latest
RUN set -eu; \
    base="https://github.com/kitecosmic/synsema/releases"; \
    if [ "$SYNSEMA_VERSION" = "latest" ]; then dir="$base/latest/download"; else dir="$base/download/$SYNSEMA_VERSION"; fi; \
    curl -fsSL "$dir/synsema-linux-x86_64" -o /usr/local/bin/synsema; \
    curl -fsSL "$dir/synsema-linux-x86_64.sha256" -o /tmp/synsema.sha256; \
    echo "$(cut -d' ' -f1 /tmp/synsema.sha256)  /usr/local/bin/synsema" | sha256sum -c -; \
    chmod +x /usr/local/bin/synsema; \
    rm /tmp/synsema.sha256; \
    apt-get purge -y --auto-remove curl

WORKDIR /app
# The image ships only the binary — mount your .syn program into /app and run it.
ENTRYPOINT ["synsema"]
CMD ["version"]
