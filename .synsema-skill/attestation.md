# Attestation — proving *which code* produced an answer

**What it is.** The other half of confidential computing. [labels.md](labels.md) keeps data from
leaving; attestation lets a remote party check **what is running before it sends the data in**. The
platform (a TEE: AWS Nitro, Intel TDX, AMD SEV-SNP, dstack) signs a document that binds a
measurement of the code to a value you choose, and a client verifies that document against a pinned
root. No trust in the operator is required — that is the whole point.

**Two shapes, and they are different jobs.** `serve --attested` attests a **service**: a long-lived
identity whose public key terminates TLS, so "I am talking to that code" is a property of the
channel. `run --attest` attests a **result**: one program, one input, one output, one document a
third party can check offline. Pick by whether the verifier talks to you or reads an artefact.

## The five builtins

```synsema
require attest

let doc be attest({"report_data": sha256(bytes("the answer is 42"))})
print(doc["format"])                       -- nitro | nitro-tpm | sev-snp | tdx | mock
print(doc["driver"])                       -- which driver produced it

let k be attest_key("signing")             -- a secret sealed to this measurement

let opts be {"now": floor(now()), "format": doc["format"]}   -- now: whole unix seconds
when get(doc, "aux") != nothing
    set opts["aux"] to doc["aux"]          -- sev-snp: the host's certificate table (VLEK/VCEK)
when get(doc, "root") != nothing
    set opts["root"] to doc["root"]        -- mock only
let seen be attestation_verify(doc["document"], opts)
print(seen["measurements"])                -- pcrN (nitro, nitro-tpm, mock) or measurement/host_data (sev-snp)
```

| builtin | capability | what it gives |
|---|---|---|
| `attest(opts?)` → map | **`require attest`** | a fresh document from the platform |
| `attest_key(purpose)` → secret | **`require attest`** | a key the platform derives from the measurement |
| `attestation_document()` → map | none | the identity of the `serve --attested` you are running inside |
| `attestation_key()` → secret | **`require attest`** | that identity's private key, **sealed** |
| `attestation_verify(doc, opts)` → map | none (pure) | the verdict, normalised across platforms |

- **`attest(opts?)`** — `opts = {"report_data"?: bytes (≤ 64), "nonce"?: bytes, "public_key"?:
  bytes}`. Returns `{"format", "document": bytes, "driver": text, "report_data": bytes, "aux"?:
  bytes, "event_log"?: text, "root"?: bytes}`. `report_data` is the 64 bytes **you** get to choose:
  it is how the document stops being "some enclave exists" and becomes "*this* enclave computed
  *that*". Hash your answer into it. `root` comes back **only from the `mock` driver**, so CI can
  pass it to `attestation_verify`; a real platform's root is pinned, not supplied.
- **`attest_key(purpose)`** — a key derived by the platform for this measurement: different code
  gets a different key, so data sealed to one build cannot be read by another. dstack derives it
  (`GetKey`); the `mock` driver uses HKDF of its seed. With `nitro`, `nitro-tpm` and `tsm` it is an
  error that points at the KMS recipe in `packages/attested/README.md`. Nitro and TDX have no such
  key. SEV-SNP does (`SNP_GET_DERIVED_KEY`), but on EC2 the measurement it is bound to is the
  firmware's, not your program's, so it would seal nothing to *this* code — the engine does not
  offer it. The secret's label carries the purpose (`secret(attest_key:<purpose>)`), so two
  purposes are visibly two keys in a log. With a driver list, `attest()`/`attest_key()` use the
  first driver.
- **`attestation_document()` / `attestation_key()`** — the identity of the server you are running
  inside. Outside `serve --attested` they fail with a clear error, so a route that serves the
  document is honest by construction. `attestation_key()` returns a **sealed** secret: `reveal()`
  refuses it *even with the `reveal` capability*, and only ECDH-with-your-own-key and one-way
  MAC/hash may consume it. Exporting the key that anchors both TLS and the document would void the
  attestation, so the engine does not let you.
- **`attestation_verify(doc, opts)`** — pure: no capability, no network, and **`opts.now` is
  mandatory** (a unix timestamp in seconds). Inside an enclave there is no trustworthy clock, and a
  verdict has to be reproducible; the certificate-validity window is checked against the timestamp
  you pass, not against whatever the host says. `opts.format` = `nitro` | `nitro-tpm` | `sev-snp`
  | `mock`. `opts.expect` compares and fails closed:
  - `"measurements": {"pcr0": "<hex>", …}` — `pcrN` for `nitro`/`nitro-tpm`/`mock`; `measurement`
    and `host_data` for `sev-snp` (another name → error). A mismatch raises `measurement <name>
    mismatch (expected abababab…, got 17bf8f04…)` — 8 hex each side, never the full value.
  - `"report_data": <bytes or hex>` (v0.6.43+) — the whole `report_data`. `sev-snp` (64 bytes) pads
    a shorter value with zeros, so `sha256(spki ‖ program_sha ‖ config_sha)` is enough; `nitro`,
    `nitro-tpm`, `mock` compare exactly (`report_data` = `user_data` as is). A mismatch:
    `report_data mismatch (the first N of M bytes match; expected K bytes)` — counts, no values.
  - `opts.aux` (bytes) and `opts.vek` (DER bytes or PEM text) — only with `sev-snp` (else error).
  - `opts.root` (DER or PEM) — only with `mock`; with `nitro`, `nitro-tpm` and `sev-snp` it is
    refused: those trust only their pinned roots.
  - Unknown option → error listing `format, now, root, expect, aux, vek`.

Output: `{format, measurements, report_data, user_data, public_key, nonce, timestamp (seconds),
module_id, digest, chain: [{subject, not_before, not_after}] (leaf first), tcb}` — `tcb` is
`nothing` except in `sev-snp`, which also adds `policy` and `version` (below).

**What it verifies, in order, failing closed at the first doubt.**

`nitro` (AWS Nitro Enclaves) and `mock` (same format, root from `opts.root`): the payload's exact
structure and types (unknown or duplicate keys, wrong types, PCR sizes that do not match `digest`,
indefinite-length CBOR — an enclave's NSM never writes it); that the `cabundle` root is, **by SHA-256
of its DER**, the pinned AWS Nitro Attestation PKI root embedded in the engine; the full X.509 chain
(ecdsa-with-SHA384 over P-384, `issuer` = the issuer's `subject` byte for byte, `BasicConstraints`
CA where present, `not_before ≤ now ≤ not_after` on **every** certificate); and last the COSE ES384
signature with the leaf's key.

`nitro-tpm` (v0.6.43+, EC2 instance attestation — NitroTPM inside a VM): the same envelope, root and
chain checks. Its payload is an indefinite-length CBOR map and its measurements are `nitrotpm_pcrs`
(indices 0..=23, `digest` must be `SHA384`) → `measurements` `pcr0`…`pcr23`; `public_key`/`nonce`
come as null; `report_data` = `user_data`. A **different format on purpose**: a VM document passed as
`nitro` fails with `payload has the key "nitrotpm_pcrs": this is an EC2 instance (NitroTPM) document,
verify it with format "nitro-tpm"`, and an enclave document passed as `nitro-tpm` names `pcrs` —
a VM never comes out labelled as an enclave. The leaf certificate lives ~3 hours.

`sev-snp` (v0.6.43+, AMD SEV-SNP): `doc` = the 1184-byte report (`attest()["document"]`,
configfs-tsm's `outblob`). The signing key (VLEK on AWS, VCEK elsewhere) comes from `opts.aux` —
the host's certificate table, `attest()["aux"]` or the identity's `aux` (base64) — or `opts.vek`
(e.g. a VCEK you fetched from AMD yourself); both given and different → error. Order:
1. length 0x4A0 and `VERSION` ∈ {2,3,4,5}; `SIGNATURE_ALGO` = 1 (ECDSA P-384/SHA-384);
2. `KEY_INFO.SIGNING_KEY`: 0 VCEK, 1 VLEK, 7 → `the report is not signed` (before looking for the
   key), anything else → error;
3. the VEK from `vek` or the `aux` table (24-byte entries `GUID ‖ offset ‖ length`, ended by an
   all-zero entry; offsets checked; unknown GUID or a repeated entry → error). Its ASK/ARK entries
   are **ignored**;
4. the product from the VEK's `productName` (`Milan`, `Genoa`, `Turin`; `Milan-B0` → `Milan`;
   anything else → error), cross-checked with the report's CPUID family/model when `VERSION ≥ 3`;
5. the chain VEK ← ASK (VCEK) or ASVK (VLEK) ← ARK with **AMD's certificates embedded in the
   engine, pinned by SHA-256** (fetched from AMD KDS on 2026-10-07): validity of **each** certificate
   against `now` (an AWS VLEK lives one year — `the VLEK is not valid at now=…`), RSASSA-PSS with
   SHA-384, MGF1-SHA-384 and a 48-byte salt and nothing else, issuer/subject byte for byte;
6. the report's signature: ECDSA P-384/SHA-384 over bytes 0..0x2A0 with the VEK (`R`/`S` are 72
   little-endian bytes whose top 24 must be zero);
7. the VEK's TCB extensions (blSPL, teeSPL, snpSPL, ucodeSPL; fmcSPL on Turin) equal to
   `REPORTED_TCB` (not `CURRENT_TCB`; reserved TCB bytes must be zero); a VCEK's `hwID` equal to
   `CHIP_ID` (a masked, all-zero `CHIP_ID` cannot match a VCEK);
8. `POLICY` bit 19 (DEBUG) set → `the guest allows debug: the host can read its memory`. **No
   option skips it**;
9. `expect`.
Output: `measurements: {measurement, host_data}` (hex), `report_data` (64 bytes), `digest:
"SHA384"`, `tcb: {product, signing_key: "vlek"|"vcek", csp_id (VLEK, e.g.
"CN=cc-us-east-2.amazonaws.com"), chip_id (hex), vmpl, reported/current/committed/launch:
{boot_loader, tee, snp, microcode, fmc (Turin)}}`, `policy: {raw (hex), abi_minor, abi_major, smt,
migrate_ma, debug, single_socket, cxl_allow, mem_aes_256_xts, rapl_dis, ciphertext_hiding,
page_swap_disable}`, `version`, and `nothing` for `timestamp` (the report has no time — none is
invented), `module_id`, `user_data`, `public_key`, `nonce`. Only **Milan** is exercised with a real
report (AWS `c6a`, VLEK). **Turin + VCEK is not supported** (its `hwID` may not be 64 bytes; such a
report is refused). AMD CRLs are not consulted. Genoa, Turin, the VCEK path (`hwID` = `CHIP_ID`) and the policy, TCB and
reserved-field rejections are tested with synthetic chains built to AMD's spec and `virtee/sev`, with
no real report behind them yet.

**`tdx` and `sgx` are not verified by this release** — they return an explicit error, not a `false`
and not an optimistic `true`. `attest` produces `tdx`, so an enclave can *emit* what its platform
gives; verifying it needs DCAP v4 collateral, which is not in. The platform-token flavour
(Confidential Space, Azure MAA) is `jwt_verify`/`oidc_verify` with inline keys today.

## `serve --attested`

```bash
synsema serve --attested app.syn
```

At startup the server generates a P-256 keypair, asks the platform for a document binding
`sha256(spki ‖ program_sha ‖ config_sha)`, and publishes it at `GET /.well-known/attestation`.
**If the platform does not answer, the server does not start** — there is no degraded mode. With
several drivers (`SYNSEMA_ATTEST=tsm,nitro-tpm`, or both auto-detected) **every** driver signs the
same binding, and one failing driver stops the start (the error names it: `serve --attested: driver
nitro-tpm: …`).

**Renewal (v0.6.43+).** A Nitro/NitroTPM leaf certificate lives ~3 hours, so the server asks every
driver for fresh documents — same key, same binding — at half the life of the shortest leaf, at least once a
day, and swaps them all at once. SEV-SNP expires with the VLEK/VCEK in its `aux` (~1 year on AWS);
renewing does not bring a new VLEK, so past half its life the server renews at half of what is left
(daily while months remain). `/.well-known/attestation` and `attestation_document()` always give
the current ones; `/.well-known/attestation` answers `503` rather than an expired document. A failed
renewal retries with backoff (stderr: `[serve] attestation renewal failed (…); retrying in Ns (the
current documents expire at T)`); if the current documents expire without a renewal the server
**shuts down with an error** (`serve --attested: the attestation documents expired at T and could
not be renewed (…)`, exit ≠ 0) — never an expired document, never a dropped driver. `run --attest`
does not renew: it is one run's artefact.

**`program_sha`** = `sha256(source ‖ 0x00 ‖ sha256(module_1) ‖ … ‖ sha256(module_n))`: each `use`d
module **once** (by resolved path), depth first in the order the `use` lines appear in the source —
a `use` inside a task that never runs counts too (up to v0.6.42 a module imported from two places
counted twice, so such a program has another `program_sha` since v0.6.43). `code sha` runs the
static check first; `--json` paths are relative to the program's folder, with `/`. Do not
reimplement it:

```bash
synsema code sha app.syn          # 95cb46a4…a91c  — the hex alone, for scripts
synsema code sha app.syn --json   # {"program_sha": "…", "modules": [{"path": "…", "sha256": "…"}]}
```

(also the `sha` tool of `synsema code --mcp`). It does not cover templates or static files (they
belong to the image).

```synsema
require serve(8080)
require attest

serve on 8080
    route "GET /identity"
        give attestation_document()
```

- **TLS.** Without `--tls-cert`/`--tls-auto`, the channel uses a self-signed certificate issued with
  **that same key**, so a client pins the key from the document and knows the TLS peer is the
  attested code. With an operator certificate the published `tls_key` says `"operator"` instead of
  `"attested"`: the announced key is then *not* the channel's, and the client must not pin it.
- **Labels are on, always.** `--attested` turns on information-flow labels for every interpreter in
  the process. The HTTP response and every stream are **public sinks** — a private value there is a
  `label_violation`. This is not optional and cannot be turned off: an attested deployment that
  could publish its inputs would be attesting the wrong property. Read [labels.md](labels.md)
  before writing routes.
- **`--attested` and `--watch` are mutually exclusive** (exit 2): a restart would change the
  attested identity underneath live clients.
- **Reserved routes.** Under `--attested` the program cannot declare any of `/.well-known/attestation`
  (with or without a trailing slash), `/openapi.json`, `/docs`, `/llms.txt`, `/sitemap.xml` or
  `/robots.txt`. The server **refuses to start**, naming the route and the reserved list — the
  declaration is never silently shadowed.

The published JSON:

```json
{"format": "sev-snp", "driver": "tsm", "engine": "v0.6.43",
 "public_key": "-----BEGIN PUBLIC KEY-----…", "public_key_hex": "<SPKI in hex>",
 "program_sha": "<hex>", "config_sha": "<hex>",
 "config": {"ceiling": "unbounded", "drivers": ["tsm", "nitro-tpm"], "engine": "v0.6.43",
            "labels": true, "profile": "native", "tls_key": "attested"},
 "document": "<base64>", "aux": "<base64>", "tls_key": "attested",
 "documents": [
   {"format": "sev-snp", "driver": "tsm", "document": "<base64>", "aux": "<base64>"},
   {"format": "nitro-tpm", "driver": "nitro-tpm", "document": "<base64>"}]}
```

The top-level `format`/`driver`/`document`/`aux` are the **first** driver's (unchanged for existing
clients); `documents` (v0.6.43+) has one entry per driver, in order. `config.drivers` (v0.6.43+)
names them, so it is inside `config_sha`.

The `mock` driver adds two keys of its own: `"mock": true` and `"root"` (its generated root, so a
CI client can pass it as `opts.root`). A real platform sends neither.

`config` is the **mode** the program ran under, not just which program: the ceiling, whether labels
were on, the profile, the drivers, and where the TLS key came from. `config_sha` is SHA-256 of that
object as canonical JSON (sorted keys, no spaces — `sha256(canonical_json(config))` in Synsema), and
it is inside the signed `user_data` — so an operator cannot attest
a hardened configuration and then serve a loose one. The client recomputes
`sha256(spki ‖ program_sha ‖ config_sha)` and compares it with `user_data`. A `mock` document also
carries `"mock": true`, and announces `format: "mock"` — the development driver never claims to be a
platform.

## `run --attest`

```bash
synsema run --attest report.syn -- 2026-09     # program output, then one JSON line
```

The program's output is printed as usual, then **one JSON line** on stdout:

```json
{"output_sha": "<hex>", "steps": 412, "state_root": "<keccak256 hex>",
 "program_sha": "<hex>", "input_sha": "<hex>",
 "config": {"ceiling": ["stdout"], "drivers": ["nitro"], "engine": "v0.6.43", "labels": false,
            "profile": "pure", "tls_key": "none"},
 "config_sha": "<hex>",
 "attestation": {"format": "nitro", "document": "<base64>", "driver": "nitro"},
 "attestations": [{"format": "nitro", "driver": "nitro", "document": "<base64>"}]}
```

`attestation` is the first driver's document; `attestations` (v0.6.43+) has one per driver, all
binding the same `report_data`. One failing driver → no artefact. The drivers are chosen and checked
before running (no platform → the program does not even run); a driver that fails when asked for
the document fails after: the output is already printed, the JSON line is missing, exit 1.

- **`--attest` implies `--deterministic`**: the pure profile plus a `stdout`-only ceiling, so the
  same program and input give the same output. Combining it with `--explain`, `--sandbox`,
  `--cap-set` or `--profile native` is a **usage error (exit 2)** with the reason — the flags are not
  silently dropped.
- `report_data = sha256(program_sha ‖ input_sha ‖ output_sha ‖ config_sha)`. The *output* is
  everything the program collected — `print` **and `log` and `show`**, they share the buffer —
  joined with `\n`, no trailing newline.
- `state_root` is keccak256 of that same output: the value two enclaves (or a contract) compare.
- **`steps` is informative and is NOT in `report_data`** — it is the interpreter's counter, not a
  property of the result. And it is **`null` when the run touched a private value**, because two runs
  with different secrets could otherwise give the same `output_sha` with different `steps`, which is
  a channel inside the artefact whose whole job is to be published.

## Drivers

Chosen by `SYNSEMA_ATTEST` — one driver, or a comma-separated list (`tsm,nitro-tpm`; v0.6.43+) —
or auto-detected on Linux. **`mock` is never auto-selected** and cannot be combined with other
drivers. A repeated driver (also through an alias: `tsm,snp`), an empty item or an unknown name is
an error that names it, before anything runs.

| driver | where | format | status |
|---|---|---|---|
| `tsm` | Linux ≥ 6.7, configfs-tsm; `provider` picks the format | `sev-snp` | **exercised on hardware**: AWS `c6a.large` with SEV-SNP, us-east-2, 2026-10-07 (engine v0.6.42); the report verifies with `attestation_verify` since v0.6.43 |
| `tsm` | the same in a TDX guest | `tdx` | **not yet exercised on hardware**; `tdx` is not verified |
| `nitro-tpm` | Linux, an EC2 instance with NitroTPM (`/dev/tpm0`, then `/dev/tpmrm0`) | `nitro-tpm` | **new in v0.6.43**, talks to the TPM directly (no `nitro-tpm-attest`, no external binary); protocol tested against a simulated TPM, **not yet on hardware** |
| `nitro` | Linux, AWS Nitro Enclaves via `/dev/nsm` (NSM ioctl, CBOR) | `nitro` | **not yet exercised on hardware** |
| `dstack` | Unix, the guest agent's unix socket | `tdx` | **not yet exercised against a real VM** |
| `mock` | any OS — CI and local development | `mock` | exercised; **never** a production claim |

Auto-detection: `/dev/nsm` → `nitro` alone; otherwise configfs-tsm → `tsm` **and** a TPM that answers
AWS's NitroTPM vendor command → `nitro-tpm` (both when both, `tsm` first); otherwise a dstack
socket. A TPM by itself is not enough (an Azure/GCP vTPM is not a NitroTPM): the engine asks it the
vendor command and a plain TPM answers that it does not know it. `SYNSEMA_ATTEST=nitro-tpm` without
a TPM device → `NitroTPM is not available: the AMI needs TpmSupport=v2.0 and UEFI`; on a TPM that is
not a NitroTPM → `NitroTPM NSM request failed: TPM response code 0x143`. The NitroTPM driver
replicates AWS's `nitro-tpm-attest` (EK, an NV message buffer, a salted HMAC session, the vendor
command); `user_data`/`nonce`/`public_key` are capped at 1024 bytes each.

**How the `nitro-tpm` driver uses the TPM** (tested against a simulated TPM, not yet on a NitroTPM):
one request at a time per process; it opens `/dev/tpm0` (exclusive in Linux), waits up to 10 s if
another process holds it, and only then uses `/dev/tpmrm0`. With `/dev/tpm0` it first releases what
a process killed mid-request left (loaded objects and sessions, and 8 KiB NV buffers of exactly its
own shape — other owners' NV indices are never touched); otherwise a few SIGKILL/OOM kills fill the
TPM. Consequences, rare and failing closed: (1) two Synsema processes attesting at once, one on
`/dev/tpmrm0` → the other's cleanup can remove its buffer mid-request; that request errors and
`serve --attested` retries; (2) objects/sessions another app loaded through `/dev/tpm0` directly are
released — apps on `/dev/tpmrm0` (most TPM tools) are unaffected; do not run a raw-`/dev/tpm0` app
alongside the `nitro-tpm` driver.

The hardware drivers are written against the vendors' own SDKs and tools (numbers and wire shapes
confirmed against `aws-nitro-enclaves-nsm-api`, `aws/NitroTPM-Tools`, configfs-tsm, and the dstack Go
SDK) but this repo does not claim what it has not probed. The `mock` driver warns once on stderr and
marks every document it produces, so a mock cannot be mistaken for a platform in a log or in a client.

## What each document measures (read before writing a client)

- **SEV-SNP on EC2** proves the VM's memory is encrypted with a key AWS does not hold. Its
  `measurement` covers **only the firmware (OVMF) and the initial vCPU state** — not the kernel, the
  disk or the Synsema binary. The `program_sha` in its `report_data` is *declared* by a binary nobody
  measured: whoever operates the image could change it.
- **NitroTPM with an Attestable AMI** measures the boot: PCR4 = the boot binary (UKI), PCR12 = its
  command line, which carries the dm-verity hash of a read-only root. That ties the **disk, and the
  engine on it,** to the document.
- So one server publishes **both**, bound to the same key (`SYNSEMA_ATTEST=tsm,nitro-tpm`): SEV-SNP
  for "the memory is private", NitroTPM for "this is the code". A client verifies both; the expected
  PCRs come from whoever built the AMI and the expected SEV-SNP `measurement` from whoever knows the
  firmware — the engine provides neither.

**Host knobs** (process environment — Docker `-e`, systemd — not the `.env`):
`SYNSEMA_ATTEST` (force a driver or a list), `SYNSEMA_ATTEST_MOCK_SEED`, `SYNSEMA_ATTEST_MOCK_PCRS`,
`SYNSEMA_ATTEST_MOCK_TIMESTAMP`, and `DSTACK_SIMULATOR_ENDPOINT` — which is honoured **only** with an
explicit `SYNSEMA_ATTEST=dstack`, so the simulator can never pick the driver by itself.

Anything unclear — an unknown driver, an odd `provider`, a response that does not parse,
`report_data` over 64 bytes — is an explicit error. There is no "probably fine" document.

## Two primitives that belong to this deployment

- **`groth16_verify(vk, proof, public_inputs)` → bool** (pure, no capability). Verify a Groth16 proof
  over BN254 — the `bn128` curve of circom/snarkjs (Semaphore, zk-passport, most zkTLS) — taking
  snarkjs's `verification_key.json`, `proof.json` and `public.json` **as they are**, as maps or as
  JSON text. An enclave can accept untrusted input with a proof attached and needs no oracle. Fails
  closed: an **invalid proof** that is well formed returns `false`; a **dubious format** is an error
  (wrong protocol/curve, a point off the curve or outside the subgroup, a non-canonical coordinate,
  `nPublic` that does not match `IC` or the inputs, a scalar ≥ r).
- **`laplace_noise(seed, scale)` / `gaussian_noise(seed, sigma)` → float** (pure, no capability).
  Differential-privacy noise that is **deterministic in its seed** — the randomness does not come
  from `random()`. That is the design, not a limitation: an enclave has no trustworthy entropy, and
  *the same query over the same state returns the same noise*, so repeating a query cannot average
  the noise away (the attack that beats fresh noise). Want fresh noise per query? Put a counter or a
  report id in the seed — `decode(hmac(keccak256(state), report_id), "hex")` is the pattern. The ε budget is
  the program's to carry in its own state. `scale`/`sigma` must be finite and `> 0`; the result is
  always a float.

  **Two things you must do yourself.** The result is only the *noise*; snapping (Mironov 2012 — the
  low bits of a noised float leak the true value) has to be applied to the published **sum**:
  `round((value + noise) / lambda) * lambda` with `lambda` a power of two `≥ scale`, plus a clamp.
  And say so in the `declassify` reason. Also: `ln`/`cos` come from the platform's libm, so the value
  is reproducible within one binary or `.wasm` but **not promised bit-for-bit across native and
  wasm** — 1 ulp differences are possible.

## Which DATA went in — the lineage in the receipt (v0.6.29+)

Attestation proves *which code* ran; the receipt's lineage proves *which data it read*. The engine
records every input — `read_file`/`read_file_bytes`/`list_dir`/`grep`/`parquet_read` (the path), HTTP
(the **host only**, never `user:pass@`, the path or the query where an API key may travel; a 4xx/5xx
answer counts, marked `status N`; a request that never arrived does not), SQL/Mongo/Redis reads and
chain RPC reads (the **sha256 of the query**, never the text), socket/process messages, the answers of
a model (`reason`/`decide`/`analyze`/`generate`: source `llm`, the prompt's hash), `read_line`
(stdin), what `run`/`run_program` returned — each with the sha256 of the bytes the program received
and an `encoding` that says which bytes those were (`"text"`, `"bytes"`, `"jcs"` =
`canonical_json(x)`, or `"json"` = `json_encode(x)` when the value holds an integer beyond 2^53), so
a verifier can recompute every hash.
`lineage()` returns that list; `receipt()` carries it as `credentialSubject.inputs` next to
`program_sha`, `engine`, the capability audit and `declared_result_sha256`. Signed, one document
then says: *this measured code read these
inputs and declared this output*. A verifier recomputes the sha256 of the inputs it holds. To fix
the receipt in time, anchor `sha256(canonical_json(signed_receipt))` on a chain (calldata or an event
of your contract, via `evm_tx` + `evm_send`). What it does not cover: values that are
not reads (`env`/`secret`, the blackboard) and completeness across units. Full
contract: [builtins.md](builtins.md) § Lineage.

## Verifying what you downloaded

Attestation answers *which code is running inside the enclave*. The question before it is *which
code did I install* — and the release answers that too, at three levels of strength. They are worth
knowing, because `serve --attested` binds `program_sha` and `measurements.json` pins an image built
from these very bytes: if you cannot tell where the binary came from, the rest of the chain rests on
nothing.

**1. The checksum — integrity of the download.** Every asset ships a `.sha256` next to it, and
`install.sh` verifies it before installing. If it finds no `sha256sum`/`shasum` it **aborts** rather
than installing unverified. This catches a truncated download or a tampered mirror; it does not tell
you who built the file.

**2. The build provenance — who built it, from what.** All eight artefacts of a release (the four
platform binaries, the three `.wasm`, and `measurements.json`) are signed with GitHub's build
provenance. Anyone can check it, with no trust in the project:

```sh
gh attestation verify synsema-linux-x86_64 --repo kitecosmic/synsema
```

It answers with the workflow, the commit and the tag that produced *those exact bytes* — for
v0.6.24, `release.yml@refs/tags/v0.6.24` at commit `8284861`. This is the check to run, and the one
`attested-image` runs on the Linux binary before it ever goes into the image whose digest
`measurements.json` publishes.

**3. Reproducibility — can someone else get the same bytes?** For the **Vela guest** the release
rebuilds `synsema-vela-guest.wasm` on two different Ubuntu versions with the pinned toolchain and
compares both against the asset it published. On v0.6.24 all three agreed:
`87bad7b8d20c1d249fbfd06a9cf48c73e51af533bfd87754351922ee587d0325`. It matters there because the
chain verifies a `wasmSha256`, so "rebuild it yourself and compare" is a real check a counterparty
can run.

**What is not promised, stated plainly.** That comparison **warns, it does not fail** the release:
reproducibility is *reported*, not guaranteed. And the four native binaries have **no reproducibility
check at all** — what is guaranteed for them is the provenance of level 2. Empirically, the Linux
binary of v0.6.24 came out byte-identical across two independent release runs
(`b57a7f630b60d4cf649b4e79bff605c1f827d6a824eabcd41758977ada05d0e0`); the Windows one did not. Do not
read "the Linux build is reproducible" into that: it is one observation on one runner image, not a
property the project enforces.

## Checklist for a confidential deployment

1. **Check the engine you are deploying** — `gh attestation verify <the asset> --repo
   kitecosmic/synsema` before it goes into an image or an enclave (above). Attesting a program
   built by an engine of unknown provenance attests the wrong half.
2. Write the program so it works with labels on — `private` at the boundary, `declassify` with a
   reason at every publication. `synsema run --labels` locally, `synsema code check --json` to read
   the declassify list before shipping.
3. `serve --attested`, no `--watch`. Decide TLS: attested key (client pins) or operator certificate
   (client does not pin).
4. Publish `program_sha` and the expected measurements wherever your users will look for them.
5. The client gets the identity, verifies **every** document with `attestation_verify` (`now`,
   `expect.measurements`, `expect.report_data = sha256(spki ‖ program_sha ‖ config_sha)`), checks
   `program_sha` against `synsema code sha` of the audited source and `config` against `config_sha`,
   and **only then** talks to the key — `fetch(url, {"attested": …})` does all of it in one call;
   see *Talking to the attested key* below.
6. In CI, `SYNSEMA_ATTEST=mock` with a fixed seed: the whole path is exercised, and the `mock: true`
   marker makes it impossible to confuse with the real thing.

## Talking to the attested key — `attested` and `tls_pin` (v0.6.43+)

**The one-call way: `attested`** (in `fetch`'s options map and in `ws_connect`'s opts):

```synsema
require net("203.0.113.7")

let r be fetch("https://203.0.113.7:8443/hola", {"attested": {
    "program_sha": args()[0],                       -- `synsema code sha app.syn` of the audited source
    "formats": ["sev-snp", "nitro-tpm"],
    "measurements": {"sev-snp": "any",              -- on purpose: SEV-SNP only for "memory is private"
                     "nitro-tpm": {"pcr4": args()[1], "pcr12": args()[2]}}   -- from the AMI builder
}})
print(r["attested"])        -- {program_sha, public_key_hex, formats, config}
```

On ONE TLS connection, failing closed at the first doubt: (1) the handshake records the leaf's SPKI
without validating any chain or name (the handshake signature is still verified with that key);
(2) `GET /.well-known/attestation` over that same connection (keep-alive) — nothing of your request
leaves yet; (3) its `public_key_hex` must equal the handshake's SPKI byte for byte; (4) `config_sha`
must equal `sha256(canonical config)` and `program_sha` must equal `attested.program_sha`
(**mandatory**); (5) every document (`documents`, or the top-level one) passes `attestation_verify`
with its `aux`, `now` and `expect.report_data = sha256(spki ‖ program_sha ‖ config_sha)`; every
format in `attested.formats` (**mandatory**, non-empty) must be present and verify, and an extra
document that does not verify is an error too; `attested.measurements` **must name every format
except `mock`** with a non-empty map, or `"any"` to accept any measurement of that format on purpose
(otherwise: `attested.measurements has no entry for "nitro-tpm": without the expected measurements
the document proves only that some nitro-tpm machine answered, not which code runs` — `program_sha`
alone is declared by the very binary being checked; on EC2 the SEV-SNP `measurement` covers only
OVMF, so NitroTPM PCR4/PCR12 are what pin the code; never PCR16/PCR23, root resets them);
a `mock` document is accepted only if `formats` names `"mock"`; (6) only then your request goes out
on the same connection. Any failure → `error of r` (status 0) and **the server never receives your
request**. Errors you will see: `attested: the identity's public_key_hex is not the key of this TLS
connection` (a man in the middle), `attested: the server runs program_sha 1a2b…, not the expected
95cb…`, `attested.formats asks for "nitro-tpm" but the server published no such document`, `the
server is attested by the mock driver … attested.formats does not name "mock"`, `the sev-snp document
does not verify: …`. Raised before connecting: `attested.program_sha is required`, `attested.formats
is required and cannot be empty`, `tls_pin and attested are two ways of fixing the server key; pass
one`, `fetch: attested is nothing` (same for `tls_pin`: `nothing` never turns a check off — leave
the key out), unknown keys. The identity must come with `Content-Length` (`attested: the identity
response must carry Content-Length, not Transfer-Encoding`), so the connection can carry your
request after it; `the identity has two <format> documents` is an error too. Over `http://`/`ws://` → error. `now` (unix seconds) is optional: the system
clock by default, like any TLS check (`attestation_verify` itself still requires it). In
`ws_connect` the upgrade leaves after step 5, on every reconnect too (an explicit `now` advances by
the time since the first connection); `ws_stats(c)["attested"]` holds what the last one verified. The wasm profile (the host's
`http`) cannot do it and fails closed.

**By hand** — for an identity you already hold (a copy, an artefact), then `tls_pin`:

```synsema
require net("203.0.113.7")
require file.read("identity.json")

let BASE be "https://203.0.113.7:8443"
let EXPECTED_PROGRAM be args()[0]     -- `synsema code sha app.syn` of the source you audited
let NOW be int(args()[1])             -- the time you trust, unix seconds

-- The identity proves itself, so it can come from any channel (see the note below).
let id be json_decode(read_file("identity.json"))

when decode(sha256(canonical_json(id["config"])), "hex") != id["config_sha"]
    raise "config_sha does not match the published config"
when id["program_sha"] != EXPECTED_PROGRAM
    raise "this server runs another program"
let binding be sha256(bytes(id["public_key_hex"], "hex") + bytes(id["program_sha"], "hex") + bytes(id["config_sha"], "hex"))

each d in id["documents"]
    let opts be {"format": d["format"], "now": NOW, "expect": {"report_data": binding}}
    when get(d, "aux") != nothing
        set opts["aux"] to bytes(d["aux"], "base64")
    let seen be attestation_verify(bytes(d["document"], "base64"), opts)
    print(d["driver"] + ": " + seen["format"] + " verified")

let r be fetch(BASE + "/hola", {"tls_pin": id["public_key_hex"]})
print(r["json"])
```

- `tls_pin` — in `fetch`'s options map and in `ws_connect`'s opts — is the server's
  SubjectPublicKeyInfo (hex, bytes or `PUBLIC KEY` PEM). It **replaces** the check against the OS
  roots and the host name with byte equality of the presented key; rustls still verifies the
  handshake signature with that key. Another key: `error of r` = `… tls_pin: the server public key
  (SPKI) does not match the pinned key`. Without `tls_pin`, nothing changes (a self-signed
  certificate → unknown issuer, as always). Needs `https://`/`wss://` and `require net(host)`.
- **Reading the identity from the server itself** is what `attested` does (above). Plain `fetch`
  of `/.well-known/attestation` from a self-signed server is refused, and there is no "skip
  verification" option: the only unvalidated connection the engine opens is `attested`'s, and it
  carries nothing of yours until the identity on it verified.
- **Clients that are not Synsema** (curl, Python, Go): do the same steps — TLS without validation but
  keeping the peer certificate (Python `ssl.CERT_NONE` + `getpeercert(binary_form=True)`), the
  identity over that same keep-alive connection, its key == the certificate's SPKI, the documents
  verified, and only then the request on that connection.
- With an operator certificate (`tls_key: "operator"`) do not pin the announced key: it is not the
  channel's — and `attested` fails against such a server by design. Verify the identity by hand and
  trust the operator's certificate as usual.

## See also

- [labels.md](labels.md) — the other half: `private`/`declassify`, and what a public sink is
- [capabilities.md](capabilities.md) — `require attest`, ceilings, `--deterministic`
- [secrets.md](secrets.md) — secrets, and what a **sealed** one refuses
- [guests.md](guests.md) — the Vela guest, where labels are always on and the sink is the chain
- [serve.md](serve.md) — TLS, reserved routes, the rest of the server
