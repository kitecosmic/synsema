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
print(doc["format"])                       -- nitro | tdx | sev-snp | mock
print(doc["driver"])                       -- which driver produced it

let k be attest_key("signing")             -- a secret sealed to this measurement

let seen be attestation_verify(doc["document"], {"now": now(), "format": doc["format"]})
print(seen["measurements"]["pcr0"])
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
  (`GetKey`); the `mock` driver uses HKDF of its seed. **Raw Nitro/TDX/SEV-SNP do not seal keys**
  and say so with an error that points at the KMS recipe in `packages/attested/README.md` — that is
  a platform fact, not a missing feature.
- **`attestation_document()` / `attestation_key()`** — the identity of the server you are running
  inside. Outside `serve --attested` they fail with a clear error, so a route that serves the
  document is honest by construction. `attestation_key()` returns a **sealed** secret: `reveal()`
  refuses it *even with the `reveal` capability*, and only ECDH-with-your-own-key and one-way
  MAC/hash may consume it. Exporting the key that anchors both TLS and the document would void the
  attestation, so the engine does not let you.
- **`attestation_verify(doc, opts)`** — pure: no capability, no network, and **`opts.now` is
  mandatory** (a unix timestamp in seconds). Inside an enclave there is no trustworthy clock, and a
  verdict has to be reproducible; the certificate-validity window is checked against the timestamp
  you pass, not against whatever the host says. `opts.format` names the format; `opts.expect =
  {"measurements": {"pcr0": "<hex>", …}}` compares and raises `measurement pcrN mismatch` (without
  dumping either value in full).

Output: `{format, measurements: {"pcr0": hex, …}, report_data, user_data, public_key, nonce,
timestamp (seconds), module_id, digest, chain: [{subject, not_before, not_after}] (leaf first),
tcb: nothing}`.

**What it verifies, in order, failing closed at the first doubt** (`nitro`, and `mock` which shares
the format): the payload's exact structure and types; that the `cabundle` root is, **by SHA-256 of
its DER**, the pinned AWS Nitro Attestation PKI root embedded in the engine; the full X.509 chain
(ecdsa-with-SHA384 over P-384, `issuer` = the issuer's `subject` byte for byte, `BasicConstraints`
CA where present, `not_before ≤ now ≤ not_after` on **every** certificate); and last the COSE ES384
signature with the leaf's key.

**`tdx`, `sgx` and `sev-snp` are not verified by this release** — they return an explicit error, not
a `false` and not an optimistic `true`. `attest` produces those formats, so an enclave can *emit*
what its platform gives; verifying them needs DCAP v4 collateral (SGX/TDX) or the VCEK ← ASK ← ARK
chain (SEV-SNP), which is not in. The platform-token flavour (Confidential Space, Azure MAA) is
`jwt_verify`/`oidc_verify` with inline keys today.

## `serve --attested`

```bash
synsema serve --attested app.syn
```

At startup the server generates a P-256 keypair, asks the platform for a document binding
`sha256(spki ‖ program_sha ‖ config_sha)`, and publishes it at `GET /.well-known/attestation`.
**If the platform does not answer, the server does not start** — there is no degraded mode.

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
- **Reserved routes.** `/.well-known/attestation` (with or without a trailing slash) and
  `/openapi.json` cannot be declared by the program under `--attested` — it is a **load error**, not
  a silent shadow.

The published JSON:

```json
{"format": "nitro", "driver": "nitro", "engine": "0.6.24",
 "public_key": "-----BEGIN PUBLIC KEY-----…", "public_key_hex": "<SPKI in hex>",
 "program_sha": "<hex>", "config_sha": "<hex>",
 "config": {"ceiling": "unbounded", "engine": "0.6.24", "labels": true,
            "profile": "native", "tls_key": "attested"},
 "document": "<base64>", "tls_key": "attested"}
```

`config` is the **mode** the program ran under, not just which program: the ceiling, whether labels
were on, the profile, and where the TLS key came from. `config_sha` is SHA-256 of that object as
canonical JSON (sorted keys), and it is inside the signed `user_data` — so an operator cannot attest
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
 "config": {"ceiling": "stdout", "labels": false, "profile": "pure", "tls_key": "none"},
 "config_sha": "<hex>",
 "attestation": {"format": "nitro", "document": "<base64>", "driver": "nitro"}}
```

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

Chosen by `SYNSEMA_ATTEST`, or auto-detected on Linux. **`mock` is never auto-selected.**

| driver | where | status |
|---|---|---|
| `nitro` | Linux, AWS Nitro Enclaves via `/dev/nsm` (NSM ioctl, CBOR) | **not yet exercised on hardware** |
| `tsm` | Linux ≥ 6.7, configfs-tsm; `provider` picks `tdx` or `sev-snp` | **not yet exercised on hardware** |
| `dstack` | Unix, the guest agent's unix socket | **not yet exercised against a real VM** |
| `mock` | any OS — CI and local development, `format: "mock"` | exercised; **never** a production claim |

The three hardware drivers are written against the vendors' own SDKs (numbers and wire shapes
confirmed against `aws-nitro-enclaves-nsm-api`, configfs-tsm, and the dstack Go SDK) but this repo
does not claim what it has not probed. The `mock` driver warns once on stderr and marks every
document it produces, so a mock cannot be mistaken for a platform in a log or in a client.

**Host knobs** (process environment — Docker `-e`, systemd — not the `.env`):
`SYNSEMA_ATTEST` (force a driver), `SYNSEMA_ATTEST_MOCK_SEED`, `SYNSEMA_ATTEST_MOCK_PCRS`,
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
  report id in the seed — `hmac_sha256(keccak256(state), report_id)` is the pattern. The ε budget is
  the program's to carry in its own state. `scale`/`sigma` must be finite and `> 0`; the result is
  always a float.

  **Two things you must do yourself.** The result is only the *noise*; snapping (Mironov 2012 — the
  low bits of a noised float leak the true value) has to be applied to the published **sum**:
  `round((value + noise) / lambda) * lambda` with `lambda` a power of two `≥ scale`, plus a clamp.
  And say so in the `declassify` reason. Also: `ln`/`cos` come from the platform's libm, so the value
  is reproducible within one binary or `.wasm` but **not promised bit-for-bit across native and
  wasm** — 1 ulp differences are possible.

## Checklist for a confidential deployment

1. Write the program so it works with labels on — `private` at the boundary, `declassify` with a
   reason at every publication. `synsema run --labels` locally, `synsema code check --json` to read
   the declassify list before shipping.
2. `serve --attested`, no `--watch`. Decide TLS: attested key (client pins) or operator certificate
   (client does not pin).
3. Publish `program_sha` and the expected measurements wherever your users will look for them.
4. The client fetches `/.well-known/attestation`, verifies with `attestation_verify` passing `now`
   and `expect.measurements`, recomputes `sha256(spki ‖ program_sha ‖ config_sha)`, compares with
   `user_data`, checks `config`, and **only then** pins the key and sends the data.
5. In CI, `SYNSEMA_ATTEST=mock` with a fixed seed: the whole path is exercised, and the `mock: true`
   marker makes it impossible to confuse with the real thing.

## See also

- [labels.md](labels.md) — the other half: `private`/`declassify`, and what a public sink is
- [capabilities.md](capabilities.md) — `require attest`, ceilings, `--deterministic`
- [secrets.md](secrets.md) — secrets, and what a **sealed** one refuses
- [guests.md](guests.md) — the Vela guest, where labels are always on and the sink is the chain
- [serve.md](serve.md) — TLS, reserved routes, the rest of the server
