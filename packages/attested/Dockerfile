# Synsema attested base image: a container or a VM where Synsema is its own host. It ships ONE
# thing: the portable Linux binary of a published release, verified against a SHA-256 you choose
# to trust. The program (`/app/app.syn`, plus any `use` modules, templates and static files) is
# added by the image that builds FROM this one, or mounted at /app.
#
# Verify the binary's provenance first, then build the image against the hash you verified:
#
#   gh release download v0.6.24 --repo kitecosmic/synsema --pattern synsema-linux-x86_64
#   gh attestation verify synsema-linux-x86_64 --repo kitecosmic/synsema
#   docker build --build-arg SYNSEMA_VERSION=v0.6.24 \
#     --build-arg SYNSEMA_SHA256="$(sha256sum synsema-linux-x86_64 | cut -d' ' -f1)" \
#     -t synsema-attested:v0.6.24 packages/attested
#
# Without SYNSEMA_SHA256 the build still works, against the release's own `.sha256` — see the ARG
# below for what that does and does not prove.
#
# The release workflow builds this image for every tag and publishes its OCI digest as
# `measurements.json` (a Docker digest, NOT a TEE measurement: PCR0 / MRTD / RTMRs depend on
# how each platform wraps the image — see README.md).
#
# Base pinned by digest, not by tag: `bookworm-slim` moves with every Debian point release and
# the image digest we publish would silently follow. This is the multi-arch index of
# debian:bookworm-slim as of 2026-08-24 (linux/amd64 manifest sha256:5ae3c39e…2b867). Bump it on
# purpose, with `docker buildx imagetools inspect debian:bookworm-slim`, and say so in the release.
# The apt packages installed below are NOT pinned, so two builds of this file on different days
# are not byte-identical either: the digest is recorded per release, never promised reproducible.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Release tag of the binary to embed (the same tag the workflow builds). Required.
ARG SYNSEMA_VERSION
# Where the release assets live; override to mirror them (air-gapped builds).
ARG SYNSEMA_DOWNLOAD_BASE=https://github.com/kitecosmic/synsema/releases/download
# The SHA-256 the binary MUST have, as 64 lowercase hex digits. Set it to a hash you verified
# outside this build — `gh attestation verify synsema-linux-x86_64 --repo kitecosmic/synsema`
# checks GitHub's SLSA provenance of the asset; the release workflow does exactly that before it
# builds this image and passes the verified hash here. Empty = fall back to the release's own
# `.sha256` file, which only proves the download was not corrupted: it comes from the same origin
# as the binary, so it is integrity, not provenance (README.md, "What measurements.json is").
ARG SYNSEMA_SHA256=

# ca-certificates: the binary makes TLS connections (http_*, proxies, KMS); curl only to fetch
# the release asset — removed afterwards so the runtime image stays minimal. `gh` is not in
# bookworm's repositories, so provenance is verified by the caller (SYNSEMA_SHA256), not in here.
RUN set -eux; \
    test -n "${SYNSEMA_VERSION}" || { echo "SYNSEMA_VERSION build-arg is required (e.g. v0.6.24)"; exit 1; }; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -fsSL -o /usr/local/bin/synsema "${SYNSEMA_DOWNLOAD_BASE}/${SYNSEMA_VERSION}/synsema-linux-x86_64"; \
    if [ -n "${SYNSEMA_SHA256}" ]; then \
        expected="$(printf '%s' "${SYNSEMA_SHA256}" | tr 'A-F' 'a-f')"; \
        echo "verifying against the caller's SHA-256 (provenance checked outside this build)"; \
    else \
        curl -fsSL -o /tmp/synsema.sha256 "${SYNSEMA_DOWNLOAD_BASE}/${SYNSEMA_VERSION}/synsema-linux-x86_64.sha256"; \
        expected="$(tr -d '\r' < /tmp/synsema.sha256 | awk '{print tolower($1)}' | head -1)"; \
        rm -f /tmp/synsema.sha256; \
        echo "WARNING: verifying against the release's own .sha256 (same origin as the binary: integrity only, no provenance); pass --build-arg SYNSEMA_SHA256=<hash you verified with gh attestation verify>"; \
    fi; \
    echo "${expected}  /usr/local/bin/synsema" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/synsema; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*; \
    /usr/local/bin/synsema version

# Unprivileged user: the server binds 8443 (no capability needed) and writes only under /app
# (`.synsema/state` for remember/progress, when the program uses them). A fixed uid/gid so a
# derived image or a volume can chown to it without looking it up.
RUN set -eux; \
    groupadd --system --gid 10001 synsema; \
    useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin --no-create-home synsema; \
    mkdir -p /app; \
    chown synsema:synsema /app

# Attestation driver. Empty = autodetect at start-up (/dev/nsm -> nitro,
# /sys/kernel/config/tsm/report -> tsm, /var/run/dstack.sock -> dstack); the server refuses to
# start when nothing is found. Set `mock` ONLY for local development; it is never autodetected.
ENV SYNSEMA_ATTEST=
# No update checks from inside an enclave (no network surprises, no version drift).
ENV SYNSEMA_NO_UPDATE_CHECK=1
ENV HOME=/app

WORKDIR /app
EXPOSE 8443
USER synsema

# `--attested`: fresh P-256 key, attestation document bound to sha256(spki || program_sha),
# GET /.well-known/attestation, TLS self-signed with that key (pass --tls-cert/--tls-key in a
# derived image to use a real certificate; the announced key stays the pin for `ecdh_*`).
ENTRYPOINT ["synsema", "serve", "--attested", "--bind", "0.0.0.0", "--port", "8443", "/app/app.syn"]
