# Security: the Synsema guest for confidential platforms

This document is for anyone who has to trust a Synsema program running inside a TEE — an app
author, a user of a Vela application, an operator of an attested container — and for an
external auditor engaged to review it. It says what a guest is made of, what an audit of a
fixed tag covers, how the audited artifact is pinned, and how a downloaded asset is checked
against what CI built. It is written for the current state of the code and is updated with it;
what has not been measured is marked as such.

## What a guest is

A Synsema guest is one WebAssembly module: the Synsema interpreter (the same engine as the
native binary, compiled with the pure profile) plus the `.syn` program of one application,
embedded in a fixed **app slot**, exposed to a host through a thin adapter. The program runs
under the `stdout` ceiling: no clock, no randomness, no network, no files, no LLM, no host
calls beyond writing its log. Determinism is a property of that runtime, not of the program's
discipline. One `.wasm` is exactly one app, and the hash a platform verifies covers interpreter
and program together.

Every application shares the interpreter. An audit of the interpreter and the adapter therefore
covers every program they carry, which is the point of auditing a tag rather than an app.

## Scope of an external audit

An audit of a tagged release covers, in this order of importance:

1. **The interpreter under the `stdout` ceiling** — `engine/crates/synsema-core` (parser,
   interpreter, type system, `steps()`, invariants, the secret type) and the pure subset of
   `engine/crates/synsema-stdlib` that the guest links (`no_fs`, no `native` feature). The
   question is whether a program can observe or influence anything outside its inputs, and
   whether the same inputs can produce different bytes.
2. **The Vela adapter** — `packages/guests/vela/src/lib.rs`: how the host's inputs (raw bytes,
   pointers, request types) become values, how the program's result becomes the host's exact
   result format, what an error carries on-chain, and what the app slot guarantees
   (`SYNSEMA.APPSLOT1`, one contiguous run, header with length).
3. **`tools/embed.syn` and `tools/verify.syn`** — the tool that puts a program into a released
   module without a compiler, and its inverse. `verify.syn` reads the app slot (program name and
   bytes; `--extract` writes them out), optionally compares the program with `--source`,
   downloads the release's `synsema-vela-guest.wasm` and its `.sha256` (or takes a local file
   with `--asset`) and checks the asset against that `.sha256`, rebuilds what the module should be
   with `embed.syn`'s algorithm and compares the two **byte by byte** (reporting the first
   differing offset and whether it is inside or outside the slot), and with `--audited <sha256>`
   compares the asset's hash with the one you pass. That is all it does: it verifies **no
   provenance, no signature and no certificate chain** — the `.sha256` comes from the same
   origin as the asset, so it is an integrity check, not a provenance check. There is no
   `--attested` flag. Both are Synsema programs covered by their own tests.
4. **`tools/wasi-stub`** — the post-processing step that replaces the WASI imports Vela v0.3.0
   refuses by local stubs returning `ENOSYS` (`fd_prestat_get`: `EBADF`). It touches and checks
   **imports only**: its own verification is that no import outside the allowed set remains and
   that the output re-parses as a valid module. That exports, the memory and the app slot come
   through unchanged is not something the tool asserts — it is what the probes CI runs on the
   stubbed module establish (Node WASI, wasmtime-go v1.0.0 and v47, `embed.syn` followed by a
   probe of the embedded module). It is a small Rust program on `walrus`, with its own lockfile,
   outside the engine's dependency tree.
5. **`attest` and its drivers** — the capability through which a program running as its own
   host in an attested container or VM (AWS Nitro, TDX/SEV-SNP via `configfs-tsm`, dstack,
   the `mock` driver) obtains an attestation document, and what it binds (report data, TLS key).
6. **`attestation_verify`** — the client-side verification of an attestation document (COSE
   signature, certificate chain to the platform's root, PCR/measurement expectations, nonce and
   freshness), in the stdlib.

Out of scope: the platforms themselves (Vela's Executor, Manager and contracts; AWS Nitro; Intel
and AMD firmware), the client-side cryptography a program's users run outside the enclave, the
native binary's features that the pure profile does not link (HTTP server, databases, LLM
providers, processes), and the applications built on the kits — each app is audited by its
owner against its own tests; the shared part is what this audit covers.

## The audited tag and its hashes

An audit is of one git tag and of the assets CI built from it. The record below is the only
place where "audited" is asserted; a newer release is *not* audited until this file says so.

| Field | Value |
|---|---|
| Audited tag | pending |
| Audited commit | pending |
| Audited SHA-256 of `synsema-vela-guest.wasm` (stubbed, example app in the slot) | pending |
| Audited SHA-256 of `synsema-wasm-wasip1.wasm` | pending |
| Audited SHA-256 of `synsema-linux-x86_64` | pending |
| Auditor and report | pending |

How the hashes are fixed — **from the first release built by the current workflow onwards**; the
attestations and the reproducibility job described here are new, so releases published before then
have their `.sha256` files and nothing else, and `gh attestation verify` on those answers "no
attestations found". The release workflow (`.github/workflows/release.yml`) publishes each asset
with a `.sha256` file and a **SLSA build provenance attestation** signed by GitHub's Sigstore
instance, stating that this workflow built this exact file from this commit. The
`guest-reproducible` job rebuilds the guest on two runners with the pinned toolchain and reports
whether the hashes match — and compares both with the hash of the asset the `wasm` job actually
published; if the three differ, the release says so (a warning with all three hashes) and does
not claim reproducibility. When an audit closes, the tag, commit and hashes above are filled in
from those artifacts; `tools/verify.syn --audited <sha256>` then compares the release asset's
hash with the value you copy from this table (it takes the hash from you; it does not know this
file).

A program embedded with `embed.syn` changes the module's hash — that is what Vela verifies
on-chain — but not the interpreter or the adapter. Whether a given deployed module carries the
release's interpreter is checked by `verify.syn`: it embeds the program found in the slot into
the release asset and compares the result with the module byte by byte, so any difference
outside the slot is reported as "the interpreter is not the release's". The slot's contents are
the app author's.

## Verifying an asset you downloaded

For any release `vX.Y.Z` and asset `A` (`synsema-vela-guest.wasm`, `synsema-wasm-wasip1.wasm`,
`synsema-wasm-web.wasm`, `synsema-linux-x86_64`). Step 1 works on every release ever published;
step 2 only on those built after provenance was added to the workflow — on an older one it reports
that there are no attestations, which is a fact about the release, not a failed verification:

```sh
# 1. Integrity: the hash matches the one the release published next to it. Both files come from
#    the same origin, so this only says the download is intact — not who built it.
sha256sum -c A.sha256

# 2. Provenance: A was built by .github/workflows/release.yml of this repository, from the commit
#    the tag points at, by GitHub's own runners (Sigstore-signed). This is a manual step: no tool
#    in this repository performs it for you.
gh attestation verify A --repo kitecosmic/synsema
#    or, without gh: gh attestation download A --repo kitecosmic/synsema  and verify the bundle
#    with cosign / sigstore-python against the repository's workflow identity.

# 3. Vela: the SHA-256 the ProcessorEndpoint holds for your application must equal the hash of
#    the module you deployed — the released guest with your app in its slot, so compute it on
#    that file, not on the asset. For an attested container: pin the image digest from the
#    release's measurements.json, which is a Docker digest, not a TEE measurement.
```

Steps 1 and 2 answer "is this the file CI built from that tag". The audited-SHA record above
answers "is that tag the one an auditor read". For the Vela guest, `verify.syn` does step 1 on
the release asset and adds the slot comparison (your module = release asset + the program in its
slot, byte by byte) and, with `--audited`, the comparison with the hash from the table above;
step 2 stays yours to run.

## Reporting a vulnerability

Report privately to the maintainers (see the repository's security policy) with the tag, the
asset hash and a reproduction. A weakness in the interpreter or the adapter affects every
application built on that tag; a fix ships as a new tag, and this file records which tags carry
which findings once they are public.
