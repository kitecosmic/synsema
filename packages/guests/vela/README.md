# synsema-vela-guest — write a Vela app in Synsema

[Vela](https://docs.horizen.io/vela/introduction/) (Horizen) runs application logic inside a TEE
and settles the result onchain. Its Executor instantiates a WebAssembly module once and calls a
fixed set of exports with pointers into the guest's memory. This crate is that module: the Synsema
interpreter (the generic `synsema-wasm-web` ABI) plus **your `.syn` program embedded**, exposed
through Vela's ABI. One `.wasm` is exactly one app, so the SHA-256 that Vela verifies onchain
covers the interpreter and the logic together.

It is an adapter outside the engine on purpose (see [`../README.md`](../README.md)): nothing in
`engine/crates` knows Vela's name; what Vela needed and was generic — WebCrypto primitives
(`ecdh_*`, `hkdf_sha256`, `aes_gcm_*`) for the client side, `--deterministic`, `steps()` — went into
the language with generic names.

## Your program → a module (no compiler)

Every release publishes this crate built with the example `app.syn` as `synsema-vela-guest.wasm`. The
program lives in an **app slot** — a fixed block of data with a header — and `tools/embed.syn` finds
the slot in the file and overwrites it with any `.syn`, in a second, without Rust:

```sh
synsema run tools/embed.syn -- synsema-vela-guest.wasm my_app.syn my_app.wasm
```

Test the program natively first — it is plain Synsema: `synsema test my_app.syn`. The kits
(`SYNSEMA/vela-transfers` and the templates built on it) wrap this in `scripts/build.sh`.

`tools/verify.syn` is the pair of `embed.syn`, for whoever receives a `.wasm` and wants to know what
is in it: it reads the program out of the slot (`--extract out.syn` writes it), compares it with
`--source app.syn` byte by byte, downloads the release's `synsema-vela-guest.wasm` (checked against
its `.sha256`; `--audited <sha256>` pins the interpreter an external audit covered), rebuilds the
module the way `embed.syn` would and reports the first differing offset — inside the slot (the
program) or outside it (the interpreter) — then prints the module's sha256, the `wasmSha256` the
chain checks at deploy. `--release` is mandatory (a program cannot read the CLI's version); `--cache
<dir>` keeps the asset; `--asset <guest.wasm>` takes a guest on disk instead of the release's (offline,
vouched for by nothing but its own sha256). The slot's filler is 0x20 in `build.rs`, `embed.syn` and
`verify.syn` alike, so a module `build.rs` compiled verifies too. Limit: the module a Manager runs is
not downloadable by third parties, so `verify` serves whoever the app hands its `.wasm` to (a kit's
release, a CI artifact).

```sh
synsema run tools/verify.syn -- my_app.wasm --release v0.6.23 --source my_app.syn [--audited <sha256>]
```

## The adapter (Rust)

Only if you change the adapter itself:

```sh
rustup target add wasm32-wasip1
cd packages/guests/vela
cargo build --profile wasm                       # default target: wasm32-wasip1 (.cargo/config.toml)
# → ../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm  (≈ 7.8 MB, 512 KB of it the slot)

SYNSEMA_VELA_APP=/path/to/my_app.syn cargo build --profile wasm   # fill the slot at build time instead of app.syn

# From any other directory (a CI job at the repo root) the crate's .cargo/config.toml does not
# apply — say the target and the shared target dir explicitly, or you get a native cdylib:
cargo build --locked --manifest-path packages/guests/vela/Cargo.toml --profile wasm --target wasm32-wasip1 --target-dir engine/target
```

Then **stub the WASI imports Vela v0.3.0 refuses** (see the subsection below) — the stubbed file is
the module: the one the probes load, the release publishes and `embed.syn` fills. From the repo
root (inside `packages/guests/vela` the crate's `.cargo/config.toml` would cross-compile the tool
itself to wasm):

```sh
cargo run --locked --manifest-path packages/guests/vela/tools/wasi-stub/Cargo.toml -- \
  engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm engine/target/wasm32-wasip1/wasm/synsema_vela_guest.stubbed.wasm
# wasi-stub: replaced (15): fd_close -> ENOSYS(52), … fd_prestat_get -> EBADF(8), … poll_oneoff -> ENOSYS(52)
#   kept (6): clock_time_get, environ_get, environ_sizes_get, fd_write, proc_exit, random_get
#   imports: 21 -> 6; bytes: 7834135 -> 7525412
```

Then probe the stubbed module the way the Executor drives it: `node ../../../tests/vela_guest.probe.mjs <the stubbed .wasm>`
(Node's WASI ≈ wasmtime-go's `DefineWasi()`; the probe checks imports, exports, every entry point,
result formats, determinism and memory hygiene), and under the two Go runtimes — `tests/wasmtime-go/`
(wasmtime-go v1.0.0, the v0.2.0 Executor's) and `tests/wasmtime-go-v47/` (v47, Vela dev's, configured
flag by flag as its Executor does: pinned features, the closed import set, epoch interruption with
the 10 s bound). Both print compile and instantiate times (≈ 2.6–4 s and ≈ 1 ms on a laptop for the
7.5 MB module; v0.3.0 bounds one guest operation, instantiation included, to 10 s).

Run the Node probe on Node 20 or Node 24+ — **not 22**: Node 22.x segfaults intermittently
inside V8 while executing this module (the concurrent tier-up race; reproduced with 22.23.2 on
Linux, one crash in three runs, none on 20 or 24). `node --no-wasm-dynamic-tiering …` works
around it. It is the host, not the guest: `tests/wasmtime-go/` (wasmtime-go v1.0.0, the
Executor's exact runtime) is unaffected, and CI runs both probes — and embeds another program with
`tools/embed.syn` and probes that too.

### Vela v0.3.0: closed import set

Vela `dev` (v0.3.0, `pkg/wasm/guest_imports.go`, "Host imports: a closed set" in its
`WASM_HOST_ABI.md`) checks the module's import section after compiling and before instantiating,
and refuses any module that **declares** a `wasi_snapshot_preview1` import outside eight:
`args_get`, `args_sizes_get`, `clock_time_get`, `environ_get`, `environ_sizes_get`, `fd_write`,
`proc_exit`, `random_get` — the set TinyGo emits for a guest with no I/O. The refusal is by
*declaration*, not by call (a host call runs outside the epoch bound, so a blocking import such as
`poll_oneoff` could stall every app; Vela prefers to refuse at load rather than neuter the call),
and it is a signed `FAILED_LOADING_OR_GETTING_MODULE`: the app simply does not deploy.

As built, this crate declares 21. The extra fifteen (`fd_close`, `fd_fdstat_get`, `fd_filestat_get`,
`fd_prestat_get`, `fd_prestat_dir_name`, `fd_read`, `fd_readdir`, `path_*`, `poll_oneoff`) come from
`std::fs` linked by the engine; the program can never reach them — it runs under the `stdout`
ceiling (`no_fs`), which is a property of the runtime, not of the linker. **`tools/wasi-stub`**
(a small Rust bin on `walrus`, its own lockfile, outside the engine) replaces each import outside
the set by a local function of the same type that returns `ENOSYS` (52); `fd_prestat_get` returns
`EBADF` (8), which is how std's preopen scan ends cleanly at start-up. The tool rewrites and checks
**imports only** — that no import outside the allowed set is left, and that the output re-parses as
a valid module. It asserts nothing about the rest: that the exports, the memory and the **app slot**
come through unchanged is what the probes establish, which is why CI runs all of them on the
stubbed module and then embeds a program into it with `embed.syn` and probes that too.
`clock_time_get` and `random_get` stay imported because std uses them at start-up; the `stdout`
ceiling still denies `now()` and `random()` to the program, which is what matters.

**From the next release onwards**, the published `synsema-vela-guest.wasm` is the stubbed module —
assets of v0.6.23 and earlier are not stubbed and declare 21 imports, so a v0.3.0 devnet refuses
them; run `tools/wasi-stub` on those yourself, or take a newer asset. Every module CI probes (Node,
wasmtime-go v1.0.0 and v47, the embedded payment app) and the size budget is the stubbed one. If
Horizen widens the list, widen `DEFAULT_ALLOW` in `tools/wasi-stub/src/main.rs` and the two Go
probes together.
Deploying the stubbed module on a v0.3.0 devnet is still pending (dev is unpublished; the images
have to be built) — until then the Go v47 probe runs the same check as `guest_imports.go`.

## Start from the kit

[`SYNSEMA/vela-transfers`](https://github.com/SYNSEMA/vela-transfers) is a template repository built on this crate, private transfers with an invoice and a public receipt each: the app with
its tests, the client, `scripts/build.sh` (the release's guest with your app in its slot — no compiler), `scripts/smoke.mjs`,
`scripts/devnet.sh` (Horizen's starter kit in Docker) and `scripts/e2e.sh`, plus a CI workflow that builds
`app.wasm` on every push.

[`SYNSEMA/vela-payroll`](https://github.com/SYNSEMA/vela-payroll) is a complete app built on the kit: private payroll in a
stablecoin — pay runs from a CSV, one encrypted payslip per person, a public receipt per run, pull-payment withdrawals
through the facilitator (people need no ETH), an auditor's report. Its client adds `fund`, `payrun`, `payslips`,
`withdraw`, `pending` and `claim-for` with amounts in tokens, and its `scripts/devnet.sh` deploys and allowlists the
test ERC-20 from `examples/erc20/` locally. Verified end to end on the public devnet.

[`SYNSEMA/vela-policy-engine`](https://github.com/SYNSEMA/vela-policy-engine) is the payment policy engine: policy inside, LLM outside. An agent
proposes payments with its own key; the enclave applies the owner's policy (proposers, payees with caps, an automatic
limit, an allowance) and pays through its trigger contract (the cycle of `examples/trigger_app.syn`, with ERC-20) or holds the
proposal for the owner's approval; the agent worker reads an inbox, and the client protocol is a module both it and the CLI
use. Verified end to end on the public devnet.

[`SYNSEMA/vela-dark-pool`](https://github.com/SYNSEMA/vela-dark-pool) is a dark pool for block trades, mechanically a sealed-bid batch auction: bids encrypted to the enclave, the
matching inside (uniform price or pay-as-bid, exact integer ranking), settlement from escrow, losing bids never
revealed, public `opened`/`cleared` receipts with no bidder in them. The four kits are recipes in
[`synsema/recipes`](https://github.com/synsema/recipes).

Each kit's recipe entry is a web app (`web.syn`): the payroll console, the policy engine's console (its trigger made
through a factory contract on the stack), the dark pool's console (the seller's desk and a desk per buyer) and the
private transfers workbench (deploy your `app.syn`, register, deposit, any payload, events, users, reports). Deployed
from synsema.com, a project's environment is provisioned from the public devnet at creation; locally,
`synsema serve web.syn`. All four verified end to end on the public devnet from the browser.

## The public devnet

`devnet.synsema.app` runs Horizen's starter kit v0.2.0 behind HTTPS, with a token as the first path segment
(`/<token>/rpc`, `/<token>/authority`, `/<token>/subgraph/…`). A token of your own is one command:
`vela_client.syn -- devnet` (or `curl -X POST https://devnet.synsema.app/token`) writes the `VELA_*` lines into
`.env`, and the client works unchanged (it declares `require net("devnet.synsema.app")`). The token brings an
account of its own (ETH, `DEPLOYER_ROLE`, test tokens) and an admin desk (`VELA_ADMIN_URL`) that signs
`allow-token` and `allow-authority` for you: yours to run, and no admin key leaves the machine. A devnet: known
keys, no attestation, reset from time to time; `https://devnet.synsema.app/` shows it live. Details on the docs page.

## What ships with the crate

| Path | What | Tests |
|---|---|---|
| `app.syn` | A private ledger: balances per account and token, transfers, withdrawals with a public **ABI receipt** (`app_events` + `data_hex` + a label subtype), a deanonymization report, and a `trusted` task that decodes `(address,address,uint256)` from `payload_hex`. The Node probe drives this one, with and without an output policy. | `synsema test app.syn` (10) |
| `examples/payment_app.syn` | Horizen's own Private Transfer app (`vela-nova` `payment_app`) rewritten in Synsema, **wire-compatible with the `novaw` wallet**: the same payload instructions, event bodies (`balance` in Uint256 hex), deploy params (`allowedTokens`) and reports (`balances`, `tx_history`), keccak invoice receipts — so `novaw deployapp / registeruser / deposit / privatetransfer / withdraw / getprivatebalance / requestreport` drive it unchanged. No timestamps (there is no clock in the enclave; the Go reference calls `time.Now()`): `tx_history` filters by address. `SYNSEMA_VELA_APP=examples/payment_app.syn cargo build --profile wasm`, then the starter kit's hello-world with this `.wasm`. | 10 |
| `examples/trigger_app.syn` | An execution pool for the trigger cycle (starter kit doc 4): `execute` locks funds, withdraws to the trigger contract and emits `execute_requested` with abi.encode`(bytes16,address,uint256,bytes)`; `trusted` decodes `(bytes16,uint256,uint8)` from `payload_hex`, credits the remainder and clears the lock, emitting no app event so the loop ends. Deploy it with `{"triggerContract": "0x…"}` **and** the same address in `submitDeployRequestWithTrigger`. | 8 |
| `examples/trigger/` | `src/PoolTrigger.sol` (extends Vela's `AbstractTrigger`: runs the call from the pool, builds the TRUSTPROCESS payload), `foundry.toml`, `build.sh` — clones `HorizenOfficial/vela` v0.2.0 (BSL, never vendored) and `forge create`s with the deployer key. Only `IERC20` is a stub. | — |
| `examples/erc20/` | `src/TestToken.sol`, a minimal ERC-20 **with EIP-2612 `permit`**, and `build.sh` (deploy + `TokenAllowlist.addAllowedToken`). | — |
| `examples/client/vela_client.syn` | The client, below. | 7 |
| `tests/wasmtime-go/` | The Go probe on wasmtime-go v1.0.0, the v0.2.0 Executor's runtime; also runs Vela v0.3.0's import check and prints compile/instantiate times. | — |
| `tests/wasmtime-go-v47/` | The Go probe on wasmtime-go v47, Vela dev's (v0.3.0) runtime, configured as its Executor does: pinned features, GC off, closed import set, epoch interruption with the 10 s bound, per-store limits. | — |
| `tools/wasi-stub/` | Rust bin (on `walrus`, its own lockfile): rewrites the built module so it declares only the WASI imports Vela v0.3.0 admits — the step between `cargo build` and everything else. | `cargo test --manifest-path packages/guests/vela/tools/wasi-stub/Cargo.toml` (7) |

## The client: everything outside the enclave, in Synsema

`novaw` only speaks the payment app's payload; every other app needs its own client. `examples/client/vela_client.syn`
does all of it natively with the v0.6.20 builtins (`ecdh_*`, `hkdf_sha256`, `aes_gcm_*`, `abi_*`,
`eip712_digest`, `evm_tx`, `multipart_encode`, `http_post`). Copy `.env.example` to `.env`
(`VELA_RPC_URL`, `VELA_PROCESSOR`, `VELA_TEE_AUTHENTICATOR`, `VELA_AUTHORITY_URL`, `VELA_SUBGRAPH_URL`,
`VELA_APP_ID`, `VELA_MAX_FEE`, `VELA_SECP_KEY`, `VELA_P521_KEY`/`VELA_P521_PUB`, `VELA_USER_KEY`).

| `synsema run vela_client.syn -- …` | Does |
|---|---|
| `keys` | a fresh P-521 pair, printed for `.env` |
| `address` | the signing address (`VELA_SECP_KEY`) |
| `tee` | the Executor's P-521 key from `TeeAuthenticator.getPubSecp521r1()` |
| `tee --verify [--pcr0 <hex>]` | the Nitro attestation behind that key, verified here instead of trusted from the contract: the last `TeeUpdate` log → the `updateTee(bytes)` / `updateTeeStep1(bytes)` calldata → `attestation_verify(doc, {"format": "nitro", …})` → the document's `public_key` must be `getPubSecp521r1()` (raw or DER), its `user_data` the 20-byte `getTeeSigner()`, its PCR0 the contract's `pcr0()` and, if given, `--pcr0`. Prints `module_id`, PCR0–2, timestamp and the certificate chain. Honest about what it proves: the document dates from the enclave's start and carries no nonce of ours — identity of the code, not freshness. On a `NoAttestationTeeAuthenticator` (the starter kit, the public devnet) it says "this deployment has no attestation to verify" and exits 1. `--verified` on `register` / `send` / `report` / `register-for` / `send-for` runs this check before encrypting anything |
| `governance [--json]` | who controls what, read from the chain (logs from `VELA_FROM_BLOCK`): `ProcessorEndpoint.feeCollector()`, `minFeePerRequest()`, `maxNumOfApplications()`, `maxQueueSize()`, and on Vela dev `selectionGrace()` / `extension()` (n/a on v0.2.0); `TeeAuthenticator.owner()`, `pcr0()`, `nitroProver()`, `maxVerificationAge()`, `teeSigner`, the `PcrZeroUpdate` history (values read back from each `updatePcr0(bytes)` calldata, since the event's parameters are `indexed bytes`) and the `TeeUpdate` history; `AuthorityRegistry` (from `ProcessorEndpoint.authorityRegistry()`) with its `owner()`, `defaultAuthorityContract()` and `appAuthorityContracts(VELA_APP_ID)`; the allowlist of the app's authority contract, replayed from `AddedAuthority` / `RemovedAuthority` and confirmed with `checkAuthorityIsAllowed` |
| `deploy <wasm> [params-json\|-] [trigger]` | multipart upload to `/deploy/upload`, then `submitDeployRequest` / `submitDeployRequestWithTrigger` with the JSON descriptor; ids from the `DeployRequestSubmitted` log; waits on the subgraph |
| `register` | AssociateKey: your P-521 public key ‖ the seed encrypted for the Executor (226 bytes); the seed is `secp256k1_sign(keccak256("subtype-key-v1"))`, like novaw |
| `deposit <amount> [token]` | ETH (wei) with an empty payload, or an allowlisted ERC-20 after `approve` |
| `send '<json>' [wei]` | PROCESS with the payload encrypted for the Executor (optional ETH deposit on the same request) |
| `report '<json>'`, `report-download <id>` | DEANONYMIZATION (the caller must be an allowed authority), then the report fetched from the authority service (`/nonce`, EIP-191 signature, `/getreport`) and decrypted |
| `events [n]`, `app-events [n]` | your events, filtered by your 50 HMAC subtypes and decrypted; the app's public events with the label decoded |
| `status <requestId>` | the subgraph row |
| `user`, `register-for`, `send-for '<json>' [amount token]`, `events-for [n]` | **facilitator / meta-transactions** (`submitRequestFor`): the user (`VELA_USER_KEY`, needs no ETH) signs an EIP-712 `RequestAuthorization` and, for an ERC-20 deposit, an EIP-2612 `Permit`; `VELA_SECP_KEY` submits and pays gas and fee. Only ASSOCIATEKEY and PROCESS; the deposit can only be an ERC-20 |

## The contract of your `.syn`

The adapter calls **one task per Vela entry point**. Each task receives **one map** and returns
**one map**. Tasks you don't define fall back as noted.

| Vela export | task | `ctx` the task receives | map it returns |
|---|---|---|---|
| `deploy(appId, params)` | `deploy(ctx)` | `{app_id, kind: "deploy", params}` — `params` is the constructor JSON already decoded (`nothing` when empty) | `{state, policy?, fuel?}` — `state` required; `policy` is the output policy below, stored by the adapter inside the state under `_vela` |
| `load_module(appId)` | `load_module(ctx)` → falls back to `deploy` with `params: nothing` | `{app_id, kind: "load_module", params: nothing}` | `{state, fuel?}` — the Executor calls this only to warm its module cache (after a restart) and **discards the state**; if the fallback `deploy` fails (it needed params), the adapter logs `WRN` and answers an empty state rather than an error, which would leave the app unloadable |
| `deposit(appId, sender, token, value, state)` | `deposit(ctx)` | `{app_id, kind: "deposit", sender, token, value, value_hex, state}` — addresses as `0x…` (40 hex, lowercase); `value` as **exact decimal text**, `value_hex` as `0x…`; `state` decoded from JSON (or text if it isn't JSON) | `{state?, events?, app_events?, fuel?, error?}` |
| `process_request(…, requestType = 1)` | `process(ctx)` | `{app_id, kind: "process", request_type: 1, sender, payload, payload_hex, state}` — `payload` decoded from JSON, or text; `payload_hex` the raw bytes as `0x…` | `{state?, events?, app_events?, withdrawals?, fuel?, error?}` |
| `process_request(…, requestType = 2)` (deanonymization) | `deanonymize(ctx)` → falls back to `process` | same, `kind: "deanonymize"`, `request_type: 2` | `{report, state?, fuel?}` — `report` **required** (Vela refuses a type-2 result without it; on any other type a report is dropped with a warning) |
| `trusted_request(appId, payload, state)` (TRUSTPROCESS from a trigger contract) | `trusted(ctx)` → falls back to `process` | `{app_id, kind: "trusted", request_type: 4, sender: nothing, payload, payload_hex, state}` — the payload is what the trigger contract's `getTrustProcessPayload` returned: **ABI bytes, in clear**; read `payload_hex` and `abi_decode` it | like `process` — and emit **no `app_events`** (an app event fires the trigger again; an empty one ends the loop) |
| (after every transition) | `invariants(ctx)` — optional | `{kind, before, after, deposit?, withdrawals, events}` — see "Invariants per transition" below | a list of descriptions of what is broken (`[]` or `nothing` = fine). Non-empty, or an error: the request fails as `invariant_violation`, state not applied |

Two request types never reach the program: `AssociateKey` (3, a user registering a P-521 key and
seed — the Executor handles it) and a `PROCESS` with an **empty payload** (the Executor returns
the state untouched without calling the module; a deposit still runs `deposit`).

Shapes inside the returned map:

- `state` — any value; a text is sent as-is, anything else as compact JSON in the key order your
  program built (deterministic). Omitted (or `nothing`) on `deposit`/`process`: the state stays as
  it came, byte for byte.
- `events` — `[{user: "0x…", subtype?, data?}]`. `user` becomes `userId`; a missing `subtype` is
  32 zero bytes (for a user who registered a seed the Executor overwrites it with an HMAC of the
  seed anyway). **Every `user` must have registered a P-521 key** (`novaw registeruser` /
  `AssociateKey`): an event for an unregistered address makes the Executor fail the whole request
  (`CodePubKeyNotRegistered`, code 9) — so don't emit to a recipient you can't vouch for.
- `app_events` — the same without `user`: public, unencrypted, indexed by the subgraph and handed
  to a trigger contract during `stateUpdate`.
- `subtype` — `"0x"` + 64 hex (32 bytes), or a **short label** of at most 32 bytes
  (`"execute_requested"`) that lands left-aligned and zero-padded, the starter kit's
  `subtypeToBytes32` convention a trigger contract compares against.
- **Bytes fields** (`state`, `report`, an event's `data`) come in three forms, first one found wins:
  `<field>_hex` (`"0x…"`, exact bytes — what a contract `abi.decode`s; build them with
  `abi_encode` and `decode(b, "hex")`), `<field>_base64`, or `<field>` (a text as-is, a map/list
  as compact JSON). A Synsema `bytes` value inside `data` would be JSON-encoded as base64 text —
  use `data_hex` when the bytes matter.
- `withdrawals` — `[{token?: "0x…", to: "0x…", amount}]`; `token` defaults to the zero address (ETH).
  Pull-payment: the recipient later calls `claim(token, payee)` on the ProcessorEndpoint. For a
  trigger app, `to` is the trigger contract and the matching `app_event` carries the call.
- `amount`, `fuel`, `value` — integers as **decimal text** (`text(n)`) to stay exact at 256 bits;
  a JSON integer or a `0x…` text is accepted too. The adapter renders them as Vela's `Uint256` hex.
- `error` — a non-empty value makes the request fail (state and events are not applied). What
  reaches the chain is a **code**: give `{"error": "insufficient_balance"}` — `^[a-z0-9_]{1,32}$` —
  and it is published as is; any other text is published as `app_error` and the text itself goes
  to the Executor's log (`WRN`). `{"error": <code>, "error_detail": <text>}` keeps the sentence
  (with the balance, the address, whatever you need to debug) in the log only. A runtime error in
  the program, or a broken contract with the adapter (no such task, a `deploy` without `state`, a
  malformed address), is published as `runtime_error` with the engine's message in the log
  (`ERR`). Never free text: `RequestCompleted.errorMsg` is public on-chain.
- `fuel` — accepted for compatibility, **not what the chain sees**. The adapter reports **one
  value per app** in every response (deploy, deposit, process, deanonymize, trusted, and every
  error): the policy's `fuel` if declared, else the largest literal in your source (`"fuel": "N"`,
  `"fuel": N` or `let FUEL be "N"`), else `SYNSEMA_VELA_FUEL` fixed at build time, else 50. What
  the task returned goes to the log (`INF fuel: reported 0x32, app declared 0x32`); `steps()` is
  not logged at all (see below). Vela charges `fuel × EXECUTOR_FUEL_PRICE_PER_UNIT` (at least
  `MIN_FEE_PER_REQUEST`, 10 wei in the starter kit) against the request's `maxFeeValue` and
  **fails the request if it doesn't cover it**; `novaw`'s default reserve of 100 wei covers 50.

  That scan is **textual**, like the one that finds your tasks, and it pays to know what that
  means. It reads decimal and hex (`"50"`, `50`, `"0x32"`), it skips comments, and a literal it
  cannot parse cleanly (`"3.5"`, `"abc"`, `-3`) is **ignored with a `WRN`** rather than rounded —
  `let FUEL be "0x50"` used to scan as 0 and bill a fee of zero, in silence. It does not know
  which code runs: a big literal in a dead branch, or in a `test` block, raises the fee of the
  whole app. When you want one exact number and nothing else, put it in the policy:
  `"policy": {"fuel": "50"}` wins over the scan.

`print` inside the program goes to the Executor's log (`INF …` on WASI stdout), and that log sits
**outside** the enclave under Nitro, so `print` is a public sink. The value is redacted when it is
private, but the *number of lines* cannot be: one `print` per loop iteration over private data
spells that data out by line count. Since v0.6.23 the engine closes that itself — under
information-flow labels (which the guest always turns on) `print`, `show` and `log` are refused
with `label_violation` when they run **under a private branch**, before anything is written:

```
label_violation: print called under private control flow (pc = [app]); stdout is public and the
NUMBER of lines is not redacted, so one line per iteration spells the private data out. Move it
out of the private branch, or declassify(<the condition>, "<why it may be published>")
```

Printing a private *value* from public control flow still works and still redacts (`private(app)`).
The result of your task travels only through the returned map.

### What the chain sees, and the output policy

`RequestCompleted(appId, requestId, applicationFees, result, errCode, errorMsg)` is a public
event: the fee **is** the fuel, and `errorMsg` is the guest's error text (truncated to 100
characters, signed). A failed request carries no events, so its user gets no reason either. The
adapter closes these channels for every app; a **policy** returned by `deploy` (or `load_module`)
as `"policy": {...}` opens the private alternatives:

| key | values | effect |
|---|---|---|
| `reject` | `"private"` \| `"public"` (default) | `private`: on a PROCESS request (type 1) only, a `{"error": …}` the app returns becomes a **successful** result — the state the app sees is unchanged, no withdrawals, no app events — with **one encrypted event to the sender**, `{"rejected": <code>, "detail": <error_detail or the free text, or nothing>}`. On-chain the request is OK. It also turns on the state sealing below (`state_pad` and the `n` counter), without which the mode hides nothing on-chain. Never for `deposit` (a failed deposit must fail, or the contract holds funds with no balance), `trusted` or `deanonymize`; never for `runtime_error`/`invariant_violation`, which stay public |
| `events_pad` | integer ≥ 1 (bytes) | each private event whose `data` is a JSON object (a map, or text that parses to one) gets a key `"_"` of spaces so the compact JSON measures the smallest multiple of N that holds it. Deterministic; transparent to clients (ignore `_`). `data_hex`/`data_base64`/plain text are sent as they are (one `WRN`) |
| `events_min` | integer ≥ 0 | filler events `{"_": "pad…"}` to the `sender` (padded to the bucket too) until the request carries at least K events — a transfer (2) and a withdrawal (1) stop being distinguishable by count. Needs a sender: a `trusted_request` has none (`WRN`) |
| `state_pad` | integer ≥ 0 (bytes), default **256** under `reject: "private"` | the whole state — `_vela` included — is padded with a key `"_"` of spaces to the smallest multiple of N that holds it, so an accepted and a rejected request return states of the **same size**. `0` turns it off by hand (one `WRN`). Without it, `reject: "private"` hides nothing from whoever watches the chain: round 4 recovered the exact amount of a sealed bid in 49 replays reading only the state's length |
| `fuel` | integer or decimal text | the single fuel of the app, above the source scan |

Any other key or type fails the deploy with `runtime_error` (detail in the log). The adapter
stores the policy inside the state under the key **`_vela`** (last key; the state must be a JSON
object, otherwise the request fails with `runtime_error` rather than dropping the policy
silently), so it travels with the signed state and survives Executor restarts. On every call it is
removed from what the app sees in `ctx["state"]` and re-inserted into the `state` the app returns;
a `state` returned as `state_hex`/`state_base64`/text cannot carry it, and an app that has a
policy and returns one of those fails with `runtime_error`. `app_events` and `withdrawals` are public by design and are never
padded or hidden.

**Replay, and what the log does not say.** The Executor chooses the `state` it passes in, and the
adapter does not restrict it, so whoever drives the Executor can re-run the same sealed request
against a state of their choosing — an old one, or one where the balance is zero. If anything in
the log differed between "went through" and "was rejected", each replay would be one bit and a
handful of them would recover the amount. So under `reject: "private"` a request logs **one line,
the same line, whatever happens**:

```
INF fuel: reported 0x32
```

No error code, no "rejected privately", no `app declared none` (a failure path returns no `fuel`,
so that field alone separated success from rejection), no `declassify` trace (it carries the line
number, which names the instruction), no `steps`. `cargo test -p …` runs 50 replays of one sealed
withdrawal against 50 different balances, 25 of them accepted and 25 rejected, and asserts the 50
logs are byte-identical (`fifty_replays_against_different_balances_leave_the_same_log`).

Two residues, stated plainly:

- **The reason still reaches the sender**, encrypted, as `{"rejected": <code>, "detail": …}` —
  that is the point of the feature: the user has to learn why. The adapter asks the Executor to
  encrypt that event to the request's `sender`, so the guarantee rests on a property of the
  **Executor**, not of this guest: *that it only hands a user event to the key of the principal
  that sealed the payload*. If an Executor encrypts to whoever submitted the request instead, a
  replayer reads the detail computed over someone else's payload. That code is not in this
  repository and we have not audited it; if you cannot rely on it, run with `reject: "public"`
  (the default: the request fails on-chain and the detail never leaves the enclave) or keep the
  detail out of the rejection by returning `{"error": code}` with no `error_detail`.
- The on-chain **metadata of the replay itself** — that a request was submitted, by whom, when,
  and the fee — is public as always. Nothing in the adapter can hide that; the chain is the chain.
  What the adapter *does* close, since round 4, is the state itself. Under `reject: "private"` the
  rejected request used to return the previous state **byte for byte** while an accepted one had
  grown, so the state's **size** was one bit per request and 49 replays recovered the exact amount
  of a sealed bid without reading a single log line. Two halves close it, and each alone leaves the
  other open: a counter `n` inside `_vela` that goes up on **every** transition, so the state root
  always moves and "the root stayed put" stops being the signal; and `state_pad`, which rounds the
  whole state up to a bucket so both outcomes measure the same. What remains observable is which
  bucket the state fell into — that it crossed 256 bytes — not a bit per request: the same
  property, and the same limit, as `events_pad`.

| | before | after |
|---|---|---|
| `errorMsg` of a failed request | the app's text (`"Insufficient balance 5 for withdrawal 10 for account 0x…"`) or the engine's (`"index 7 out of range"`, `"Invariant violation: …"`) | a code: `insufficient_balance`, `app_error`, `runtime_error`, `invariant_violation` |
| the sentence behind that code | — | to the **sender**, encrypted, under `reject: "private"`. The Executor's log gets `(private)` as soon as the run touched private data; the engine redacts its own messages the same way |
| the log of a privately rejected request | the code, the detail, the declared fuel, the steps | one line: `INF fuel: reported 0x32` — identical to the log of a request that went through |
| `steps()` (one per AST node: how many accounts or bids the handler walked) | in the Executor's log, per request | not logged |
| `applicationFees` (fee = fuel) | the branch's constant (5 / 20 / 35 / 50 / 60 / 80: names the instruction) or `steps()` (one per AST node: how many accounts a loop visited) | one value per app, identical for deploy, deposit, transfer, withdraw, deanonymize, trusted and every error |
| a rejected instruction | a failed request, reason public, user told nothing | with `reject: "private"`: a successful request, the reason encrypted to the sender |
| number and size of encrypted events | transfer = 2, withdraw = 1; `data` length = the JSON's | with `events_min`/`events_pad`: at least K events, each a multiple of N bytes |
| size of the state on-chain | the rejected one came back byte for byte, the accepted one had grown: one bit per request, 49 replays recover a sealed bid | with `state_pad` (on by default under `reject: "private"`): the same bucket either way, and a counter that moves the root every time |
| a bug in `process` | signs whatever the program returned | `invariants(ctx)` refuses the transition (`invariant_violation`) — see below |
| deposits, withdrawals, sender, facilitator, timing, `app_events`, the report's existence | public | public (by design; documented on the docs page) |

### Invariants per transition

Attestation proves *which* program ran, not that it is right: a bug in `process` signs away
money with a perfect attestation. Define `task invariants(ctx)` and the adapter calls it after
every `deploy`, `load_module`, `deposit`, `process` and `trusted` that did not already fail (not
after `deanonymize`, which changes no state) with

```
ctx = {"kind": "deposit" | "process" | "trusted" | "deploy" | "load_module",
       "before": <the previous state as a value, without _vela; nothing on deploy>,
       "after":  <the new state as a value, without _vela>,
       "deposit": {"token": "0x…", "value": "<decimal text>", "value_hex": "0x…"},   -- deposit only
       "withdrawals": [{"token": "0x…", "to": "0x…", "amount": "<decimal text>", "amount_hex": "0x…"}],
       "events": [<the events exactly as the task returned them>]}
```

Return a list of descriptions of what is broken; `[]` or `nothing` means the transition stands.
Anything else — or a `raise` inside — fails the request with the public code `invariant_violation`,
the descriptions go to the log (`ERR`), and the state is not applied. Conservation is two lines:
per token, `sum(after.balances) == sum(before.balances) + deposit − withdrawn`, with amounts as
exact integers (`decimal(text)` or `bytes_to_int`). `app.syn`, `examples/payment_app.syn` and
`examples/trigger_app.syn` each carry one (balances, balances + locks), and their `test` blocks
call `invariants(...)` after every case, so `synsema test` checks the same thing the enclave will.
Inside the language, `invariant "description": expr` (v0.6.24+, the description names the
violation) is the inline form for a single task.

### Information-flow labels: what leaves the enclave, and to whom

The guest runs the program with **information-flow labels** on (the engine's `private` /
`declassify`, generic — nothing in the engine knows Vela). A label is a *set of principals*; Vela
has one, `app`. The adapter marks the **sources** before calling your task: `ctx["state"]`,
`ctx["payload"]` and `ctx["payload_hex"]` arrive as `private(…, "app")` (and `before`, `after`,
`events` in the `invariants` ctx). Everything computed from them stays `{app}` — through
arithmetic, text, `json_encode`, `keccak256`, a field read, a `when` that branched on them — and a
`print` of a private value reaches the Executor's log redacted as `private(app)`. `sender`,
`token`, `value`, `app_id` and `params` are public (they are on-chain already).

The adapter then applies the **sinks**, field by field, on what your task returns:

| Field of the returned map | Sink | Accepts |
|---|---|---|
| `state`, `report` (and `_hex`/`_base64`) | encrypted state / report to the authority | `{app}` |
| `events[*].data`, `events[*].user` | encrypted to that user (the Executor sees the address) | `{app}` |
| `error_detail` | the Executor's log | `{app}` |
| `app_events`, `withdrawals`, `error`, `fuel`, `policy`, `events[*].subtype` | **the chain** | public only |

A private value in a public sink fails the request with the public code `label_violation`; the
log gets the path and the label, never the value: `ERR label_violation: app_events[0].data.amount
is private to app, the sink accepts (public)`. Nothing is applied. To publish something on purpose
— a receipt, a pull-payment, an aggregate — wrap it in `declassify(value, "why it is public")`:

```
let receipt be declassify({"subtype": "withdrawal", "data_hex": …}, "public ABI receipt of the withdrawal: (to, token, amount)")
let pull be declassify({"token": token, "to": payload["to"], "amount": payload["amount"]}, "the withdrawal settles on-chain")
give {"state": s1, "events": [...], "app_events": [receipt], "withdrawals": [pull], "fuel": FUEL}
```

Control flow counts too. A branch that depends on private data (`when balance < amount`, `match
payload["type"]`) labels everything it produces: every literal written inside it, every value it
assigns and the value it returns. That is fine and expected: **the root of the returned map is the
`{app}` sink**, not a public one, so a handler may dispatch on the private payload and return a
labelled map — what each field needs is decided field by field, by the table above. Declassify the
**value that actually goes on-chain**, never the map around it:

```
-- Right: the code is published, the sentence stays inside.
give {"error": declassify("insufficient_balance", "the outcome code is public on-chain"),
      "error_detail": "withdrawal: have " + text(balance) + ", need " + text(amount)}

-- Wrong: this declassifies the sentence too, and the sentence carries the balance to the
-- Executor's log, which under Nitro is outside the enclave.
give declassify({"error": "insufficient_balance", "error_detail": "… have " + text(balance) + " …"}, "…")
```

Do not declassify the dispatch either (`let kind be declassify(text(payload["type"]), …)`): with
the root sink at `{app}` it buys nothing, and the argument for it — "the fee reveals the
instruction anyway" — is false here, because the adapter reports **one fuel for every branch and
every error**. A `let x be declassify(…)`, `set x to declassify(…)` or `give declassify(…)` keeps exactly the label
`declassify` returned even inside such a branch: the declassify site is the explicit, audited
decision, and `declassify` records the branch's label in `from` (`from [app] to []`). Assigning
under a private branch to a variable that is not already at least as private is refused
(`label_violation`): accumulators written inside a loop over private data are born private
(`let totals be private({}, "app")`), and the ledger's `set state["balances"][to] to x` works because
`state` already is. `synsema code check --json` marks the declassify sites whose argument is a
constant (`"constant": true`): those publish only *which branch ran*.

Runtime errors are the one channel `declassify` does not govern: a `raise`, an index out of range
or a `decimal("abc")` on user input inside a private branch fails the request in public with
`runtime_error` — also under `reject: "private"`, which only rewrites deliberate `{"error": …}`
answers. Their text never leaves the enclave: when the run touched private values the engine
redacts the message to `app.syn:12:5: private(app)` — the location survives, the balance or the
key does not.

**The Executor's log is a public sink.** Under Nitro it is written outside the enclave, so the
adapter treats it that way: `error_detail` is logged as `(private)` whenever the value came from
private data **or the run touched private values at all** (which is every real request: the state
is private). The text is not lost — the encrypted event to the sender under `reject: "private"`
carries it in full, and that is the channel the user can actually read. The same applies to
`invariants`, and there the *count* mattered too: one line per description meant `n` lines where
`n` was computed over the private state, so whoever reads the log counts what it cannot read. A
violation whose run touched private data is now **one fixed line**, `ERR invariant_violation:
(private)`, whatever the list holds; when the run touched nothing private the count says nothing
about anybody and the full diagnosis is kept.

What the adapter **never** writes to that log, each because it was a measurable channel:

| | why |
|---|---|
| `steps` | one step per AST node: linear in how many accounts or bids the handler walked (1962/3473/5009/8156 for 1/2/3/5 bids) — it undid the `events_min` padding |
| the `fuel` the task declared | no app returns `fuel` on an error path, so `0x50` vs `none` was one uniform bit: success or rejection |
| the error **code**, under `reject: "private"` | the rejection is a success on-chain, so the log was the only signal left — and `insufficient_balance` is exactly the bit a replay is fishing for |
| the trace of executed `declassify` | it carried the source line, which names the instruction that ran |
| the **number** of `invariant_violation` lines | one per description, and the descriptions are built by a loop over the private state: the count was the number itself (round 4) |

A failing request under `reject: "public"` does log its code (it is going on-chain anyway) with
the detail redacted. `events_min` without `events_pad` hides little — filler events differ in size
from the real ones — so the adapter warns once and you should set both.

Two names are reserved: the program may not mention `__vela_in` or `__vela_out` (the adapter's own
bindings for the context and the result) anywhere in its code, or the request fails with
`runtime_error` before anything runs. A top-level `let __vela_in be …` used to shadow the labelled
context and hand the task a public one of the program's own making.

`synsema code check app.syn --json` lists every `declassify` site of the program with its
reason, and marks the ones whose argument is a constant (`"constant": true` — those publish only
*which branch ran*): that list is what an auditor reviews. An `error` code must be a **literal**
(`"insufficient_balance"`): a code computed from the payload (`"unknown_" + text(p["type"])`)
would carry it to the chain and is refused.

A `give` inside a branch that depended on private data labels the **whole result** with `{app}`,
and the adapter accepts that at the root: the fields decide. So a handler dispatches on the
private payload without ceremony and declassifies only what it publishes:

```
task process(ctx)
    let payload be ctx["payload"]
    -- The payload is private; branching on it labels everything the branch produces — and the
    -- root sink is {app}, so no declassify is needed for the dispatch itself.
    match payload["type"]
        is "transfer"
            give transfer(ctx, ctx["state"], payload)
        otherwise
            give {"error": declassify("unknown_type", "the outcome code is public on-chain"),
                  "error_detail": "unsupported instruction type: " + text(payload["type"])}
```

That is the honest shape: exactly the values that reach the chain are named at their declassify
site (an outcome code, a receipt, a pull-payment), the amounts and the sentences stay inside, and
an auditor reads the list. `synsema test --labels app.syn` runs your tests with the same semantics, and the test
helpers must mark the sources the way the adapter does (`"state": private(state, "app")`,
`"payload": private(payload, "app")`) or they are testing a different program than the enclave
runs. `declassify` is the identity with labels off, but `private` is an error then — on purpose:
nobody should believe a value is protected when the labels are not on.

## What the guest cannot do, by construction

The program runs under the ceiling `stdout`: **no `now()`, no `random()`/`token()`, no network, no
files, no LLM**. Vela signs the state root, so the same inputs must produce the same bytes — the
ceiling makes that a property of the runtime, not of discipline (the Go reference app stamps
`time.Now()` on every transaction; here that line does not compile into the enclave). Maps keep
insertion order and JSON is emitted in that order, so the state bytes are the same across runs and
across instances. Everything pure is available: types, JSON, `decimal` (exact, 28 digits),
`bytes_to_int`/`int_to_bytes` for exact 256-bit integers (`bytes(h, "hex")` takes no `0x` prefix —
see `hex_to_int` in `examples/payment_app.syn`), hashing (`keccak256`, `sha256`), `abi_encode` /
`abi_decode`, `match`, `try`/`recover`, modules-free single-file programs, and `test` blocks that
run natively with `synsema test`.

Numbers in JSON: a `decimal` or big integer is written as a bare JSON number, and a bare number
above 2⁵³ comes back as a float when the state is decoded on the next call. Keep amounts as
**text** in the state (`text(n)`, or the Uint256 hex the payment app uses) and convert on use.

## Vela's ABI, as implemented (read from `vela/pkg/wasm/wasmtime_runtime.go` and `vela-common-go/wasm`, v0.2.0)

- Exports: `memory`, `allocate(i32) -> i32`, `deallocate(i32, i32)`, `load_module(i64) -> i32`,
  `deploy(i64, i32, i32) -> i32`, `deposit(i64, i32×8) -> i32`, `process_request(i64, i32, i32, i32, i32, i32, i32, i32) -> i32`,
  `trusted_request(i64, i32, i32, i32, i32) -> i32`; optional `get_allocated_memory_stats(i32)` and
  `get_memory_stats() -> i32`.
- Inputs are raw bytes the host writes with `allocate` (`ptr = 0` for empty): addresses are 20 bytes,
  `value` is the big-endian bytes of a `big.Int`, state/payload/params are the JSON text — except a
  TRUSTPROCESS payload, which is whatever bytes the trigger contract returned (ABI).
- Request types (`vela/pkg/common/types.go`): `Deploy` 0, `Process` 1, `Deanonymize` 2,
  `AssociateKey` 3, `TrustProcess` 4. The Executor routes 4 to the `trusted_request` export
  (and fails the request if the module lacks it), handles 3 itself, and passes 1 and 2 to
  `process_request`.
- Outputs are `[u32 little-endian length][JSON]`; the host frees them with `deallocate(ptr, 4 + len)`.
- Result JSON uses Go's tags: `state`/`report`/`data` are **base64** (`[]byte`), addresses `0x…`,
  `Uint256`/`Big` as `0x…` hex without leading zeros (`0x0`; the host's `common.Big` accepts only a
  quoted lowercase `0x` string with at least one digit), `eventSubType` as an array of 32 numbers,
  `appEvents`/`withdrawals` present as arrays; `error` non-empty = failure. A report on a type ≠ 2
  fails the request; a missing report on type 2 fails it too.
- The Executor links WASI only, never calls `_start`, and caches the instance across requests. A
  `deposit` and a `process_request` from the same on-chain request run back to back on the same
  instance, the second on the state the first returned.
- Fuel is self-declared (the reference app returns constants); there is no metering and the call
  has no deadline beyond the Executor's 30 s communication timeout — keep handlers small.
- Toolchain compatibility: wasmtime-go 1.0 (wasmtime 1.0, 2022). Rust's default wasm features
  (bulk memory, sign extension, mutable globals, non-trapping float→int, multi-value, reference
  types) were all standardized before it. If a Vela Executor ever rejects the module, build with
  `RUSTFLAGS="-C target-feature=-reference-types,-multivalue"` and report it.

## Verified against the real thing (2026-09-12, starter kit v0.2.0 in Docker)

- `tests/wasmtime-go/` drives the module under **wasmtime-go v1.0.0**, the Executor's exact
  runtime (`go run . <the .wasm>`; needs Go + a C compiler): compiles, instantiates with WASI only,
  every export answers. Rust's default wasm features are accepted by wasmtime 1.0 as built.
- `examples/payment_app.syn` built into this crate, uploaded with `novaw deployapp` to the
  starter kit (Anvil + Manager + Executor + Authority Service + subgraph): deploy confirmed
  on-chain in ~12 s (fingerprint verified inside the Executor), then `registeruser`, `deposit 1 ETH`,
  `getprivatebalance` → `1 ETH` (the wallet decrypts the guest's event and reads `balance`),
  `privatetransfer` with an invoice (public keccak receipt as an app event), `withdraw 0.1 ETH` →
  `0.9 ETH`, `getpendingpayments` / `claimpendingpayments` back to the public address, then
  `requestreport` (`balances` and `tx_history`) and `downloadreport` — the decrypted reports carry
  what the `deanonymize` task returned. All from Horizen's wallet, unchanged. (`requestreport`
  reverts with `AuthorityNotAllowed` until the caller is allowed: `cast send <DefaultAuthority>
  "addAllowedAuthority(uint256,address)" <appId> <caller>` from the deployer account.)
- The same payment app from the Synsema client: `register`, `deposit`, an encrypted `send` with an
  invoice, `events` decrypted. ERC-20: `TestToken` deployed and allowlisted, the app deployed from
  the client with `{"allowedTokens": [...]}`, `deposit 1000000 <token>` (approve + pull), a token
  transfer, events with `tokenAddress`, the endpoint's custody holding the tokens.
- **Trigger contract, end to end:** `PoolTrigger` deployed with `forge`; `trigger_app.syn` deployed
  from the client with `submitDeployRequestWithTrigger`; `deposit 0.1 ETH`; `send` `execute` of
  0.01 ETH to a target → the target's balance grew by exactly 0.01 ETH during `stateUpdate`, and
  ~25 s later the TRUSTPROCESS came back as `execution_outcome: success` with the lock cleared and
  the private balance at 0.09 ETH; the public `execute_requested` event carries the ABI bytes;
  `report` + `report-download` show the balances and the empty lock table.
- **Facilitator:** a user with **0 ETH** was registered (`register-for`) and deposited 2 TST through an
  EIP-2612 permit plus a transfer (`send-for … 2000000 <token>`), the facilitator paying gas and
  85 wei of fees; the user's events decrypt with the user's own seed (`events-for`); the user's ETH
  balance stayed 0 and the facilitator nonce advanced to 2.
- Not testable locally: real Nitro attestation (the kit uses `NoAttestationTeeAuthenticator`; the
  Executor does the attestation, neither the guest nor the client see it).
- The adapter's own unit tests: `RUST_MIN_STACK=16777216 cargo test --target <your host triple>`.
  The crate's default target is wasm32-wasip1, so a bare `cargo test` builds a `.wasm` it cannot
  run; and the tests that replay a whole example app need a bigger stack than the 2 MB libtest
  gives a test thread — the interpreter is a recursive tree-walker, and on Windows the default
  overflows with `STATUS_STACK_OVERFLOW` on `example_payment_app_runs_end_to_end_under_labels`.

Not covered here: encryption of payloads and events (the Executor does it), signing (the Executor
does it), and the client side outside the enclave — that is ordinary Synsema with `net`, `secret`,
`ecdh_*`/`hkdf_sha256`/`aes_gcm_*` and the blockchain builtins. The wire format a client needs:
payload = JSON bytes encrypted with AES-256-GCM (12-byte random nonce prepended, no AAD) under
HKDF-SHA256(ECDH-P-521 shared X, no salt, no info, 32 bytes) between the user's P-521 key and the
Executor's communication key; events come back the same way in reverse; `AssociateKey` (type 3)
carries the user's 133-byte uncompressed P-521 public key, optionally followed by a 93-byte
encrypted seed. See `vela/pkg/crypto/cipher.go` and `vela-common-ts`.
