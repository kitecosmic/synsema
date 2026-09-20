# Synsema attested serve (form B TEEs)

A container or a confidential VM where **Synsema is its own host**: the same `synsema serve`
you run anywhere, started with `--attested`, inside a platform that can prove what code is
running. No adapter, no foreign ABI (that is form A, `packages/guests/`). Everything here is
generic engine surface: the `attest` capability, the platform drivers, `serve --attested`,
`run --attest`, `attest_key`, and the verifier family (`attestation_verify`) on the client.

## What `serve --attested` does

At start-up, before a single line of your program runs:

1. Generates an ephemeral **P-256 key pair** (the identity of this process).
2. Hashes the program: `program_sha = sha256(main.syn ‖ 0x00 ‖ sha256(module_1) ‖ …)` over
   the main file and every `use` module (templates and static files are part of the image, not
   of this hash).
3. Hashes the **configuration** it runs under: `config_sha = sha256(canonical JSON)` of
   `{"ceiling": "unbounded" | "none" | [sorted cap-set items], "engine": "<version>",
   "labels": bool, "profile": "native" | "pure", "tls_key": "attested" | "operator"}`
   (keys in that alphabetical order, no whitespace). A client learns not only *which*
   program runs but whether flow labels were on, which host ceiling applied, and whether the
   announced key is the TLS key.
4. Asks the platform for a document with
   `report_data = sha256(spki_der ‖ program_sha ‖ config_sha)`. If the platform does not
   answer, **the server does not start**.
5. Serves HTTPS with a **self-signed certificate issued with that same key** (unless you pass
   `--tls-cert/--tls-key` or `--tls-auto`, or the `serve` block has `tls cert`/`tls auto`; then
   `tls_key` is `"operator"` and the announced key is only for encrypting bodies), and publishes:

```
GET /.well-known/attestation          (trailing slash and repeated slashes hit the same URL)
{
  "format": "nitro" | "tdx" | "sev-snp" | "mock",
  "document": "<base64>",            // the platform's document / quote / report
  "public_key": "-----BEGIN PUBLIC KEY-----…",  // SPKI PEM of the P-256 key
  "public_key_hex": "<hex of the SPKI DER>",
  "program_sha": "<hex>",
  "config": {"ceiling": …, "engine": …, "labels": …, "profile": …, "tls_key": …},
  "config_sha": "<hex>",             // sha256 of the canonical JSON of `config`
  "tls_key": "attested" | "operator",// whether the TLS certificate carries the announced key
  "engine": "0.6.x",
  "driver": "nitro" | "tsm" | "dstack" | "mock",
  "mock": true,                      // ONLY with the mock driver: the document is forgeable
  "root": "<base64 DER>",            // ONLY with the mock driver: its test root, so CI can verify
  "aux": "<base64>",                 // only when the platform gives one (SEV-SNP cert chain)
  "event_log": "…"                   // only dstack (to reproduce RTMR3)
}
```

The program cannot declare a route on any reserved URL (`/.well-known/attestation`,
`/openapi.json`, `/docs`, `/llms.txt`, `/sitemap.xml`, `/robots.txt`) under `--attested`: it is a
load error, so nothing can shadow the identity endpoint.

Inside the program the same identity is available as `attestation_document()` (the JSON above,
as a map, to include in your own responses) and `attestation_key()` (the private P-256 scalar as
a **sealed** `secret`, gated by `require attest`, ready for
`ecdh_shared_secret(attestation_key(), peer, "P-256")`). Sealed means `reveal()` refuses it
even with `require reveal("attestation_key")`: the key that anchors TLS and the document never
leaves the process as plaintext. Outside `--attested` both fail with a clear error.

`--attested` and `--watch` are mutually exclusive: a restart would change the identity.

## How a client verifies (this is the whole point)

```synsema
-- Verified end to end against a live `serve --attested` (mock driver) with the binary of this
-- tanda: it verifies, it rejects a tampered document, and it rejects a document whose
-- program_sha does not match. Two API details worth copying exactly:
--   * `bytes(text, "hex"|"base64")` goes text → bytes; `decode(bytes, "hex")` goes the other way;
--   * a guard has to be a BLOCK (`when cond` + indented body). `when cond then raise "..."` in
--     statement position is the ternary form and its value is discarded: the guard never fires.
require file.read("att.json")     -- the identity document, fetched out of band (see the note below)
require time                      -- `opts.now` is mandatory; the verifier never reads the clock itself
require random                    -- the client's own ephemeral ECDH key and the AES-GCM nonce

let id be json_decode(read_file("att.json"))
let doc be bytes(id.document, "base64")
let spki be bytes(id.public_key_hex, "hex")   -- SubjectPublicKeyInfo DER (91 bytes for P-256)

-- 1. The document is genuine. `now` is unix SECONDS as an integer (`round(now())`): an enclave has
--    no trusted clock, so the verdict has to be reproducible.
let opts be {"format": id.format, "now": round(now())}
when id.format == "mock"
    -- The mock chain is a TEST chain: `attestation_verify` only trusts it if the caller passes it.
    -- With "nitro" the AWS root is pinned and `opts.root` is REJECTED on purpose.
    set opts["root"] to bytes(id.root, "base64")
let a be attestation_verify(doc, opts)

-- 2. The document is about THIS key, THIS program and THIS configuration. Recompute the binding;
--    never trust the published fields on their own.
let want be sha256(spki + bytes(id.program_sha, "hex") + bytes(id.config_sha, "hex"))
when a.report_data != want
    raise "attestation does not bind the announced key/program/config"
when id.config.labels != true
    raise "flow labels are off"
when id.config.tls_key != "attested"
    raise "TLS is not pinned to the attested key"
-- ...and compare `a.measurements` with what you expect for the image you deploy:
-- attestation_verify(doc, {"format": id.format, "now": round(now()), "expect": {"measurements": {"pcr0": "…"}}})
print("verified: format=" + a.format + " module=" + a.module_id + " pcr0=" + slice(a.measurements.pcr0, 0, 16) + "...")

-- 3. Encrypt a body to the enclave: the SEC1 point is the last 65 bytes of the SPKI DER.
let point be slice(spki, 26)
let mine be ecdh_keypair("P-256")
let shared be ecdh_shared_secret(mine.private, point, "P-256")
let key be hkdf_sha256(shared, "", "synsema-attested", 32)
let nonce be random_bytes(12)
let sealed be aes_gcm_encrypt(key, nonce, "{\"amount\": 10}")
-- send {"pub": decode(mine.public, "hex"), "nonce": decode(nonce, "hex"), "body": decode(sealed, "base64")};
-- the enclave answers with ecdh_shared_secret(attestation_key(), bytes(request.json.pub, "hex"), "P-256")
```

**Fetching the document.** With `tls_key: "attested"` the certificate is self-signed, so a client
that speaks plain HTTPS cannot validate it — that is the point (trust comes from the document, not
from a CA). Synsema's `http_*` has no "skip verification / pin this key" option today, so a
Synsema client fetches `/.well-known/attestation` out of band (curl with `--insecure` plus its own
pin, a sidecar, or the operator's fronting proxy) and then pins. If you want ordinary HTTPS
clients to work, give the server a real certificate with `--tls-cert/--tls-key`: the document then
says `tls_key: "operator"` and the announced key is only for encrypting bodies, not for the channel.

**What `attestation_verify` verifies in this release.** `"nitro"` (AWS root pinned) and `"mock"`
(with `opts.root`). `"tdx"`, `"sgx"` and `"sev-snp"` are rejected with a clear error: the quote
formats of the dstack and configfs-tsm recipes below are **produced** by this engine but not yet
**verified** by it, so a client of those platforms has to verify the quote with its own tooling
(Intel PCS / AMD KDS collateral) until that lands.

Order matters: verify the document, recompute `report_data`, compare the measurements, and
**only then** send anything. A document that verifies but binds a different key or program is
worthless; a key that matches but has no document is just a key.

`program_sha` proves *which* `.syn` runs; the platform measurement proves *which image* runs
it (the interpreter). Same idea as the Vela slot: one audited interpreter, many programs.

### What `measurements.json` is (and is not)

The release workflow builds this Dockerfile for every tag and publishes `measurements.json`
with the image's **OCI digest**. That is a Docker digest, not a TEE measurement: PCR0 (Nitro),
MRTD/RTMRs (TDX) or `measurement` (SEV-SNP) depend on how each platform wraps the image (EIF
build, dstack's OS image + compose hash, Confidential Space's image policy). Use the digest to
pin the image you deploy; get the expected platform measurement from the platform's build step
(below) and put *that* in `expect.measurements`.

**The binary inside the image.** The Dockerfile downloads `synsema-linux-x86_64` of the tag and
checks it against a SHA-256. In the release workflow that hash comes from
`gh attestation verify synsema-linux-x86_64 --repo kitecosmic/synsema`, run on the runner
*before* the build (GitHub's SLSA provenance of the asset), and is passed as
`--build-arg SYNSEMA_SHA256=…`; `gh` is not in Debian bookworm's repositories, so the provenance
check is not inside the image build. A local build without that argument falls back to the
release's own `.sha256`, which comes from the **same origin** as the binary: it proves the
download is intact, not who built it — run `gh attestation verify` yourself and pass the hash.
The base image is pinned by digest and the server runs as the unprivileged user `synsema`
(uid 10001); the apt packages are not pinned, so the image digest is recorded per release, not
promised reproducible.

## Recipes by platform

Driver selection: `SYNSEMA_ATTEST=nitro|tsm|dstack` or autodetection on Linux (`/dev/nsm`,
`/sys/kernel/config/tsm/report`, `/var/run/dstack.sock` or `/var/run/tappd.sock`). `mock` is
never autodetected.

### dstack / Phala (TDX)

`docker-compose.yml` for the dstack app (the guest agent socket is mounted into the container):

```yaml
services:
  app:
    image: ghcr.io/you/your-app:1.0.0      # FROM synsema-attested, ADD app.syn /app/app.syn
    ports: ["8443:8443"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      SYNSEMA_ATTEST: dstack
```

`format` is `tdx`; the response carries `event_log` so the verifier can replay RTMR3 (the
compose hash). Sealed state: `attest_key("state")` calls the agent's `/GetKey` (a key derived
from the app's identity by dstack's KMS) and returns it as a `secret`; encrypt your state file
or your DB with `aes_gcm_*` under that key.

Local dev: `dstack-simulator` publishes a fake `dstack.sock`; point `DSTACK_SIMULATOR_ENDPOINT`
at it (a socket path or `http://host:port`) **and** set `SYNSEMA_ATTEST=dstack` explicitly: the
simulator endpoint never selects the driver on its own (autodetection only looks at the real
guest-agent sockets).

### AWS Nitro Enclaves (direct, or Marlin Oyster)

Build the EIF from an image derived from this one, then run it:

```sh
docker build -t your-app:1.0.0 .            # FROM synsema-attested; ADD app.syn /app/app.syn
nitro-cli build-enclave --docker-uri your-app:1.0.0 --output-file app.eif
# Prints PCR0/PCR1/PCR2 — PCR0 is the measurement clients put in expect.measurements.pcr0.
nitro-cli run-enclave --eif-path app.eif --cpu-count 2 --memory 1024 --enclave-cid 16
```

The enclave has no network of its own: expose 8443 through a vsock proxy on the parent
(`socat`/`vsock-proxy`) as usual. `format` is `nitro`; `attestation_verify` pins the AWS Nitro
Attestation PKI root. Nitro does not derive sealed keys: `attest_key` fails on purpose. Release
the state key from AWS KMS with `Recipient` = this attestation document (the recipe needs
SigV4; an `aws_sigv4` pure builtin is pending — see below).

### Google Confidential Space, Azure CVM, Constellation / Contrast (SEV-SNP / TDX VMs)

Run the container as-is on the confidential VM; the `tsm` driver reads the report through
configfs-tsm (Linux ≥ 6.7). `provider` decides the format (`tdx_guest` → `tdx`, `sev_guest` →
`sev-snp`); an SEV-SNP `auxblob` (VCEK chain) is returned as `aux`. Notes:

- Confidential Space additionally issues a **platform token** (a JWT with the measurements as
  claims); verifying that token is `jwt_verify` with inline keys, not this driver.
- Constellation/Contrast measure the whole VM image; take the expected values from their
  `measurements` output for the release you deploy.
- No fallback to `/dev/tdx_guest` / `/dev/sev-guest` yet: kernels older than 6.7 are not
  supported by this driver.

### Double TEE (integrity, not confidentiality)

Run the same program on two platforms (say dstack/TDX and Nitro) and let the client compare:

```synsema
-- Verified: this snippet runs as written (it is the client side, outside any enclave).
-- `parallel_map(task, list)` takes the TASK FIRST; comments are `--`; the guard is a BLOCK
-- (`when cond` + indented body), never `if … then`.
require net("enclave-a.example")
require net("enclave-b.example")

task run_attested_job(endpoint)
    -- verify_and_call: fetch /.well-known/attestation, verify it, recompute report_data,
    -- compare measurements, and only then send the job. See the client snippet above.
    give verify_and_call(endpoint)

let endpoints be ["https://enclave-a.example", "https://enclave-b.example"]
let results be parallel_map(run_attested_job, endpoints)
when results[0].state_root != results[1].state_root
    raise "TEE disagreement"
```

Both must be verified independently first. This raises integrity (a bug or a compromised
operator on one side is caught); it does **not** raise confidentiality (each enclave still sees
the plaintext).

**Limit — `parallel_map` and flow labels.** Under flow labels (`serve --attested` turns them on,
`run --labels` too) `parallel_map` is a **sink**: if any item carries a label, or it is called
under private control flow, it fails closed with `label_violation` *before* launching a worker.
A worker runs in a fresh interpreter in another thread, and the caller's control-flow label
cannot be reconstructed there, so fanning private data out would silently run the mapper's
effects on stripped values. Fan out over **public** data (endpoints, ids, chunk indexes) and keep
the private part inside the handler, or `declassify` explicitly what may leave. This snippet is
the intended shape: the list is a pair of public URLs.

## `synsema run --attest` (job / coprocessor mode)

Runs under `--deterministic` (pure profile, `stdout` only), prints the program's output and
then exactly one JSON line:

```json
{"output_sha": "<hex>", "steps": 123, "state_root": "<hex keccak256(output)>",
 "program_sha": "<hex>", "input_sha": "<hex sha256(args joined by \\0)>",
 "attestation": {"format": "nitro", "document": "<base64>", "driver": "mock"}}
```

plus `"config": {"ceiling": ["stdout"], "engine": …, "labels": bool, "profile": "pure",
"tls_key": "none"}` and `"config_sha"`, with
`report_data = sha256(program_sha ‖ input_sha ‖ output_sha ‖ config_sha)`. `output` is the
program's collected output — `print` **and** `log`/`show` lines — joined with `\n`; `steps` is
informative and is **not** part of `report_data`. With `--format json` the same fields are
merged into the run report. The driver is validated before the program runs: no platform →
error and exit ≠ 0, and nothing executes.

## Information-flow labels under `--attested`

`serve --attested` also turns on the engine's information-flow labels (`synsema serve --labels`
does the same without an attestation, for development). A label is a set of principals:
`private(body, "bank")` marks a value as the bank's; `private(x, "airline") + private(y, "bank")`
is `{airline, bank}`; every operation, builtin and field read propagates the union, a branch on a
private condition labels what it assigns and returns, and `print` redacts. **The HTTP response and
every stream (`emit`, SSE) are public sinks**: a private value that reaches them without
`declassify(value, "reason")` fails the request with `label_violation` and the path in the error
(`response.total is private to airline,bank, the sink accepts (public)`) — the value never leaves.
That is the clean-room shape: each party's input arrives labelled, the cross is computed inside,
and only the declassified aggregate goes out; `declassify(v, "reason", ["bank"])` narrows to a
subset instead of publishing, and `synsema code check app.syn --json` lists every `declassify`
with its reason for review. Per-route sources and sinks (`labels: {"sources": …, "sinks": …}`) are
not fixed yet: the program marks its inputs itself with `private` until the first real case sets
the exact form.

## Driver status (honest)

| Driver | Platforms | Status |
|---|---|---|
| `mock` (`format: "mock"`) | any OS (CI, Windows/macOS dev) | **Tested in CI**: deterministic P-384 chain, COSE ES384 document, e2e `serve --attested` + `run --attest`. **Forgeable by design** (the key derives from `SYNSEMA_ATTEST_MOCK_SEED`): the process warns on stderr and every document carries `"mock": true`. Never pin the mock root outside CI |
| `nitro` | AWS Nitro Enclaves, Marlin Oyster | **Untested on hardware.** ioctl numbers and CBOR shapes confirmed against `aws-nitro-enclaves-nsm-api` source |
| `tsm` | TDX / SEV-SNP guests via configfs-tsm | Quotes not verified by `attestation_verify` yet. **Untested on hardware.** Follows the Linux ≥ 6.7 configfs-tsm ABI; no `/dev/*_guest` fallback |
| `dstack` | dstack / Phala Cloud (TDX) | **Untested**, and its `tdx` quotes are not verified by `attestation_verify` yet against the simulator or a real CVM. Routes/JSON confirmed against the dstack Go SDK and `sdk/curl/api-tappd.md` |

Per the repo rule (no probe, no doc), the public docs will mark each driver "untested" until
one real run on Nitro and one on TDX have been made.

## Pending

- `aws_sigv4` (pure builtin) for the AWS KMS `Decrypt`/`GenerateDataKey` with `Recipient`
  recipe on Nitro; until then release the state key from a KMS proxy on the parent instance.
- `/dev/tdx_guest` / `/dev/sev-guest` fallback for kernels < 6.7.
- Real-hardware probes (Nitro, TDX) before the docs page "Attested serve".
