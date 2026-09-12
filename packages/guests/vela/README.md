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

## Build

```sh
rustup target add wasm32-wasip1
cd packages/guests/vela
cargo build --profile wasm                       # default target: wasm32-wasip1 (.cargo/config.toml)
# → ../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm  (≈ 7–8 MB)

SYNSEMA_VELA_APP=/path/to/my_app.syn cargo build --profile wasm   # embed YOUR program instead of app.syn
```

Test the program natively first — it is plain Synsema: `synsema test app.syn`. Then probe the
module the way the Executor drives it: `node ../../../tests/vela_guest.probe.mjs <the .wasm>`
(Node's WASI ≈ wasmtime-go's `DefineWasi()`; the probe checks imports, exports, every entry point,
result formats, determinism and memory hygiene).

The release publishes `synsema-vela-guest.wasm` — this crate built with the example `app.syn` —
so you can deploy something to the Vela starter kit before writing a line.

## What ships with the crate

| Path | What | Tests |
|---|---|---|
| `app.syn` | A private ledger: balances per account and token, transfers, withdrawals with a public **ABI receipt** (`app_events` + `data_hex` + a label subtype), a deanonymization report, and a `trusted` task that decodes `(address,address,uint256)` from `payload_hex`. The Node probe drives this one. | `synsema test app.syn` (8) |
| `examples/payment_app.syn` | Horizen's own Private Transfer app (`vela-nova` `payment_app`) rewritten in Synsema, **wire-compatible with the `novaw` wallet**: the same payload instructions, event bodies (`balance` in Uint256 hex), deploy params (`allowedTokens`) and reports (`balances`, `tx_history`), keccak invoice receipts — so `novaw deployapp / registeruser / deposit / privatetransfer / withdraw / getprivatebalance / requestreport` drive it unchanged. No timestamps (there is no clock in the enclave; the Go reference calls `time.Now()`): `tx_history` filters by address. `SYNSEMA_VELA_APP=examples/payment_app.syn cargo build --profile wasm`, then the starter kit's hello-world with this `.wasm`. | 9 |
| `examples/trigger_app.syn` | An execution pool for the trigger cycle (starter kit doc 4): `execute` locks funds, withdraws to the trigger contract and emits `execute_requested` with abi.encode`(bytes16,address,uint256,bytes)`; `trusted` decodes `(bytes16,uint256,uint8)` from `payload_hex`, credits the remainder and clears the lock, emitting no app event so the loop ends. Deploy it with `{"triggerContract": "0x…"}` **and** the same address in `submitDeployRequestWithTrigger`. | 6 |
| `examples/trigger/` | `src/PoolTrigger.sol` (extends Vela's `AbstractTrigger`: runs the call from the pool, builds the TRUSTPROCESS payload), `foundry.toml`, `build.sh` — clones `HorizenOfficial/vela` v0.2.0 (BSL, never vendored) and `forge create`s with the deployer key. Only `IERC20` is a stub. | — |
| `examples/erc20/` | `src/TestToken.sol`, a minimal ERC-20 **with EIP-2612 `permit`**, and `build.sh` (deploy + `TokenAllowlist.addAllowedToken`). | — |
| `examples/client/vela_client.syn` | The client, below. | 7 |
| `tests/wasmtime-go/` | The Go probe on wasmtime-go v1.0.0, the Executor's runtime. | — |

## The client: everything outside the enclave, in Synsema

`novaw` only speaks the payment app's payload; every other app needs its own client. `examples/client/vela_client.syn`
does all of it natively with the v0.6.20 builtins (`ecdh_*`, `hkdf_sha256`, `aes_gcm_*`, `abi_*`,
`eip712_digest`, `tx_eip1559`, `multipart_encode`, `http_post`). Copy `.env.example` to `.env`
(`VELA_RPC_URL`, `VELA_PROCESSOR`, `VELA_TEE_AUTHENTICATOR`, `VELA_AUTHORITY_URL`, `VELA_SUBGRAPH_URL`,
`VELA_APP_ID`, `VELA_MAX_FEE`, `VELA_SECP_KEY`, `VELA_P521_KEY`/`VELA_P521_PUB`, `VELA_USER_KEY`).

| `synsema run vela_client.syn -- …` | Does |
|---|---|
| `keys` | a fresh P-521 pair, printed for `.env` |
| `tee` | the Executor's P-521 key from `TeeAuthenticator.getPubSecp521r1()` |
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
| `deploy(appId, params)` | `deploy(ctx)` | `{app_id, kind: "deploy", params}` — `params` is the constructor JSON already decoded (`nothing` when empty) | `{state, fuel?}` — `state` required |
| `load_module(appId)` | `load_module(ctx)` → falls back to `deploy` with `params: nothing` | `{app_id, kind: "load_module", params: nothing}` | `{state, fuel?}` — the Executor calls this only to warm its module cache (after a restart) and **discards the state**; if the fallback `deploy` fails (it needed params), the adapter logs `WRN` and answers an empty state rather than an error, which would leave the app unloadable |
| `deposit(appId, sender, token, value, state)` | `deposit(ctx)` | `{app_id, kind: "deposit", sender, token, value, value_hex, state}` — addresses as `0x…` (40 hex, lowercase); `value` as **exact decimal text**, `value_hex` as `0x…`; `state` decoded from JSON (or text if it isn't JSON) | `{state?, events?, app_events?, fuel?, error?}` |
| `process_request(…, requestType = 1)` | `process(ctx)` | `{app_id, kind: "process", request_type: 1, sender, payload, payload_hex, state}` — `payload` decoded from JSON, or text; `payload_hex` the raw bytes as `0x…` | `{state?, events?, app_events?, withdrawals?, fuel?, error?}` |
| `process_request(…, requestType = 2)` (deanonymization) | `deanonymize(ctx)` → falls back to `process` | same, `kind: "deanonymize"`, `request_type: 2` | `{report, state?, fuel?}` — `report` **required** (Vela refuses a type-2 result without it; on any other type a report is dropped with a warning) |
| `trusted_request(appId, payload, state)` (TRUSTPROCESS from a trigger contract) | `trusted(ctx)` → falls back to `process` | `{app_id, kind: "trusted", request_type: 4, sender: nothing, payload, payload_hex, state}` — the payload is what the trigger contract's `getTrustProcessPayload` returned: **ABI bytes, in clear**; read `payload_hex` and `abi_decode` it | like `process` — and emit **no `app_events`** (an app event fires the trigger again; an empty one ends the loop) |

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
- `error` — a non-empty text makes the request fail with that message (state and events are not
  applied). A runtime error in the program does the same, with the engine's message.
- `fuel` — what you declare, or, if absent, the interpreter's `steps()` for that call: a
  deterministic count of executed statements. Vela charges `fuel × EXECUTOR_FUEL_PRICE_PER_UNIT`
  (at least `MIN_FEE_PER_REQUEST`, 10 wei in the starter kit) against the request's `maxFeeValue`
  and **fails the request if it doesn't cover it** — with `steps()` a handler is typically a few
  hundred units, so either declare a constant like the reference app (`5`/`20`/`35`/`50`) or tell
  your users to reserve more than `novaw`'s default of 100 wei.

`print` inside the program goes to the Executor's log (`INF …` on WASI stdout); it is not a data
channel. The result travels only through the returned map.

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
- The adapter's own unit tests: `cargo test --target <your host triple>` (the crate's default
  target is wasm32-wasip1, so a bare `cargo test` builds a `.wasm` it cannot run).

Not covered here: encryption of payloads and events (the Executor does it), signing (the Executor
does it), and the client side outside the enclave — that is ordinary Synsema with `net`, `secret`,
`ecdh_*`/`hkdf_sha256`/`aes_gcm_*` and the blockchain builtins. The wire format a client needs:
payload = JSON bytes encrypted with AES-256-GCM (12-byte random nonce prepended, no AAD) under
HKDF-SHA256(ECDH-P-521 shared X, no salt, no info, 32 bytes) between the user's P-521 key and the
Executor's communication key; events come back the same way in reverse; `AssociateKey` (type 3)
carries the user's 133-byte uncompressed P-521 public key, optionally followed by a 93-byte
encrypted seed. See `vela/pkg/crypto/cipher.go` and `vela-common-ts`.
