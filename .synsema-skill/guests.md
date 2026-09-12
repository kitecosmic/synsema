# Guests — Synsema inside a host with its own wasm ABI (Vela / Horizen)

Read this when the user writes a **Vela app** in `.syn`, a **client** that talks to it, a **trigger
contract** for it, or wants Synsema inside another host that instantiates a wasm module and calls
its own exports (not a WASI command, not the `synsema_host` imports). Everything below was read
from HorizenOfficial's code (`vela`, `vela-common-go`, `vela-nova`, `vela-starterkit`, v0.2.0) and
verified against the starter kit running in Docker; nothing is a guess. Repo:
`packages/guests/vela/` (README = the contract), `tests/vela_guest.probe.mjs`.
**Starter kit:** `github.com/synsema/vela-app` (template repo) — app + tests, the client, `scripts/build.sh` / `smoke.mjs` / `devnet.sh` / `e2e.sh`, CI that builds `app.wasm`. Point a user there first; a shared devnet for the cohort exists (`devnet.synsema.app`, token on request; the client declares `require net("devnet.synsema.app")`).

**The two-axis rule.** Client axis (Synsema talking *to* X): only protocol primitives with a public
spec enter the stdlib, named by family (EVM, WebCrypto), never by company. Host axis (Synsema
running *inside* X): the engine keeps one generic ABI (`synsema-wasm-web`: `synsema_call`), and each
host is a thin adapter in `packages/guests/<host>/` with the `.syn` embedded. Nothing enters
`engine/crates`; a company's name lives in that directory only.

## Build, test, probe

```sh
rustup target add wasm32-wasip1
cd packages/guests/vela
synsema test app.syn                                   # the app, natively (same code runs in the enclave)
cargo build --profile wasm                             # → ../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm (≈ 7.3 MB; 2–5 min, LTO)
SYNSEMA_VELA_APP=examples/payment_app.syn cargo build --profile wasm   # embed ANOTHER program (one .wasm = one app; the SHA-256 Vela verifies covers both)
node ../../../tests/vela_guest.probe.mjs <the .wasm>   # Node 20 or 24+ (NOT 22, see below); WASI ≈ the Executor: imports, exports, every entry point, formats, determinism, memory
cd tests/wasmtime-go && go run . <the .wasm>           # wasmtime-go v1.0.0 = the Executor's exact runtime (needs Go + a C compiler)
cargo test --target <host triple>                      # the adapter's unit tests — the crate's DEFAULT target is wasm, a bare `cargo test` builds a .wasm it cannot run
```

The build always targets `wasm32-wasip1` (`.cargo/config.toml`): Vela's linker defines WASI only,
and `print` becomes the Executor's log (`INF …`). Vela's upload limit is 50 MB.

Node probe = Node 20 or 24+, **never 22**: Node 22.x segfaults intermittently inside V8 while
running this module (concurrent tier-up race; 22.23.2 on Linux crashed 1 run in 3, 20 and 24
never; `node --no-wasm-dynamic-tiering` is the workaround). Host bug, not guest: wasmtime-go
v1.0.0 (the Executor) is unaffected — CI runs both probes.

## The `.syn` contract (one task per export, one map in, one map out)

| Vela export | task | `ctx` | returns |
|---|---|---|---|
| `deploy(appId, params)` | `deploy(ctx)` | `{app_id, kind: "deploy", params}` — `params` = constructorParams JSON decoded, `nothing` if empty | `{state, fuel?}` (`state` required) |
| `load_module(appId)` | `load_module(ctx)` → falls back to `deploy` with `params: nothing` | `{app_id, kind: "load_module", params: nothing}` | `{state, fuel?}` — cache warm-up after an Executor restart, the state is **discarded**; if the fallback `deploy` errors (it needed params) the adapter answers an empty state with `WRN` (an error here would leave the app unloadable) |
| `deposit(appId, sender, token, value, state)` | `deposit(ctx)` | `{app_id, kind: "deposit", sender, token, value, value_hex, state}` — addresses `0x`+40 hex lowercase; `value` exact **decimal text**, `value_hex` `0x…`; `state` = previous state decoded from JSON (text if not JSON) | `{state?, events?, app_events?, fuel?, error?}` |
| `process_request(…, type 1)` | `process(ctx)` | `{app_id, kind: "process", request_type: 1, sender, payload, payload_hex, state}` — `payload` decoded from JSON (or text), `payload_hex` the raw bytes | `{state?, events?, app_events?, withdrawals?, fuel?, error?}` |
| `process_request(…, type 2)` (deanonymization) | `deanonymize(ctx)` → falls back to `process` | same, `kind: "deanonymize"`, `request_type: 2` | `{report, state?, fuel?}` — `report` **required** on type 2; on any other type a report is dropped with `WRN` (Vela fails the request otherwise) |
| `trusted_request(appId, payload, state)` (TRUSTPROCESS) | `trusted(ctx)` → falls back to `process` | `{app_id, kind: "trusted", request_type: 4, sender: nothing, payload, payload_hex, state}` — the payload is what the trigger's `getTrustProcessPayload` returned: **ABI bytes in clear** → `abi_decode(types, hex_bytes(ctx["payload_hex"]))` | like `process`, and emit **no `app_events`** (an app event fires the trigger again; an empty one ends the loop) |

Never reaches the program: `AssociateKey` (type 3, the Executor registers the user's P-521 key +
seed itself) and a PROCESS with an **empty payload** (the Executor returns the state untouched
without calling the module; a deposit on that request still runs `deposit`). A deposit and a
process from the same on-chain request run back to back, the second on the state the first returned.

**Shapes in the returned map**
- `state` — any value: text as-is, anything else as compact JSON in the program's key order
  (deterministic). Omitted or `nothing` on deposit/process = unchanged, byte for byte.
- `events` — `[{user: "0x…", subtype?, data?}]` → encrypted for `user` by the Executor. **`user`
  must have registered a P-521 key** (`novaw registeruser` / the client's `register`), or the
  Executor fails the WHOLE request (`CodePubKeyNotRegistered`, code 9). A missing `subtype` = 32
  zero bytes (for a user with a seed the Executor overwrites it with an HMAC of the seed anyway).
- `app_events` — same without `user`: public, indexed by the subgraph, handed to a trigger contract.
- `subtype` — `"0x"`+64 hex, **or a label ≤ 32 bytes** (`"execute_requested"`) left-aligned and
  zero-padded (the starter kit's `subtypeToBytes32`, what a trigger contract compares against).
- **Bytes fields** (`state`, `report`, an event's `data`): first found wins — `<field>_hex`
  (`"0x…"`, exact bytes: what a contract `abi.decode`s), `<field>_base64`, or `<field>` (text
  as-is / map as compact JSON). A Synsema `bytes` value put in `data` would be JSON-encoded as
  base64 text — use `data_hex`.
- `withdrawals` — `[{token?: "0x…", to: "0x…", amount}]`; `token` defaults to ETH (zero address);
  pull-payment: the recipient later `claim`s on the ProcessorEndpoint. In a trigger app, `to` is
  the trigger contract and the matching app event carries the call.
- `amount`, `fuel`, `value` — decimal text (`text(n)`) to stay exact at 256 bits; a JSON int or a
  `0x…` text is accepted too; rendered as Vela's `Uint256` hex.
- `error` — non-empty text fails the request with that message (nothing applied). A runtime error
  does the same with the engine's message. Never a trap.
- `fuel` — declared, or the interpreter's deterministic `steps()`. Vela charges
  `fuel × EXECUTOR_FUEL_PRICE_PER_UNIT` (≥ `MIN_FEE_PER_REQUEST`, 10 wei in the kit) against the
  request's `maxFeeValue` and **fails the request if it doesn't cover it** — `steps()` is a few
  hundred per call, `novaw` reserves 100 wei by default: declare constants (the reference app uses
  5/20/35/50) or reserve more.

**Determinism.** The program runs under the `stdout` ceiling: no `now()`, `random()`, `token()`,
network, files, LLM (the Go reference app stamps `time.Now()`; here that line cannot compile in).
Maps keep insertion order, JSON is emitted in that order — the same input gives the same bytes
across runs and instances (verified: 5 processes, identical hashes). Available: types, JSON,
`decimal` (exact, 28 digits), `bytes_to_int`/`int_to_bytes` (exact 256-bit), `keccak256`,
`sha256`, `abi_encode`/`abi_decode`, `match`, `try`/`recover`, `test` blocks. **Numbers in JSON**:
a decimal/big int is written as a bare JSON number and comes back as a float above 2⁵³ — keep
amounts as **text** in the state (`text(n)`, or Uint256 hex) and convert on use. Hex helpers you
will write in every app (`bytes(h, "hex")` takes no `0x` and needs an even length; `Uint256.ToHex`
strips leading zeros): see `hex_to_int`/`int_to_hex` in `examples/payment_app.syn`.

## Vela facts the adapter encodes (so you don't have to re-read Go)

- Request types (`vela/pkg/common/types.go`): `Deploy` 0, `Process` 1, `Deanonymize` 2,
  `AssociateKey` 3, `TrustProcess` 4. 4 goes to the `trusted_request` export (missing export =
  failed request), 3 is handled by the Executor, 1/2 go to `process_request`. `submitRequest`
  refuses 0 and 4; a deploy has its own entry points.
- Inputs: raw bytes via `allocate` (`ptr = 0` when empty): 20-byte addresses, `big.Int` big-endian
  value, JSON text for state/payload/params — except a TRUSTPROCESS payload (ABI bytes). Output:
  `[u32 LE length][JSON]`, freed by the host with `deallocate(ptr, 4+len)`. Result JSON uses Go's
  tags: `state`/`report`/`data` base64, addresses `0x…`, `Uint256`/`Big` as quoted lowercase `0x…`
  without leading zeros (`"0x0"`; at least one digit), `eventSubType` an array of 32 numbers,
  `appEvents`/`withdrawals` arrays, non-empty `error` = failure.
- The Executor: wasmtime-go **v1.0.0**, `DefineWasi()` only, never calls `_start`, caches the
  instance, one request per block, 30 s communication timeout, no metering (fuel is
  self-declared), memory ≤ 2 GB. Rust's default wasm features are accepted as built.
- Encryption (`vela/pkg/crypto/cipher.go`): payloads and events = `nonce(12) ‖ AES-256-GCM(key,
  data)`, no AAD, `key = HKDF-SHA256(ECDH-P-521 shared X, no salt, no info, 32)` between the
  user's P-521 key and the Executor's communication key (`TeeAuthenticator.getPubSecp521r1()`,
  133 bytes uncompressed). AssociateKey payload = user P-521 public (133) ‖ encrypted seed (93)
  = 226 bytes (133 alone is accepted); seed = `secp256k1_sign(keccak256("subtype-key-v1"))` (65
  bytes); per-user event subtypes = `HMAC-SHA256(seed, byte(i))`, i = 1..50. Reports are encrypted
  for the requester's registered key.
- Trigger cycle (`4_trigger-contract-app.md`): `process` returns a withdrawal to the trigger + ONE
  app event with the ABI call; during `stateUpdate` the ProcessorEndpoint claims the ETH into the
  trigger, calls `execute(appEventData)`, `withdraw()` sweeps what's left, `getTrustProcessPayload`
  returns bytes → if non-empty a TRUSTPROCESS is enqueued (priority queue, `maxFeeValue = 0`, no
  sender) → `trusted_request`. The guard `appEventData.events.length == 0 → ""` ends the loop.
- On-chain: `deployapp` needs `DEPLOYER_ROLE` (Anvil #0 in the kit); `requestreport` needs
  `AuthorityRegistry.checkAuthorityIsAllowed` → `DefaultAuthority.addAllowedAuthority(appId,
  addr)` from the admin (revert `AuthorityNotAllowed` otherwise); ERC-20 only if in
  `TokenAllowlist` (`addAllowedToken`, ADMIN role); multi-app works in 0.2.0 (each deploy gets its
  own applicationId from the requestId).

## What ships in `packages/guests/vela/`

| Path | What | Tests |
|---|---|---|
| `app.syn` | private ledger: balances per account/token, transfers, withdrawals with a public **ABI receipt** (`app_events` + `data_hex` + label subtype), deanonymization report, a `trusted` task decoding `(address,address,uint256)` from `payload_hex` | 8; drives the Node probe |
| `examples/payment_app.syn` | Horizen's Private Transfer app (`vela-nova` `payment_app`) in Synsema, **wire-compatible with the `novaw` wallet** (same payload instructions, event bodies with `balance` in Uint256 hex, `allowedTokens` deploy params, `balances`/`tx_history` reports, keccak invoice receipts). No timestamps (no clock in the enclave) — `tx_history` filters by address | 9 |
| `examples/trigger_app.syn` | execution pool for the trigger cycle: `execute` locks funds, withdraws to the trigger, emits `execute_requested` with abi `(bytes16,address,uint256,bytes)`; `trusted` decodes `(bytes16,uint256,uint8)`, credits the remainder, clears the lock; no app events on the way back | 6 |
| `examples/trigger/` | `src/PoolTrigger.sol` (extends `AbstractTrigger`), `foundry.toml`, `build.sh` (clones `HorizenOfficial/vela` v0.2.0 — BSL, never vendored — and `forge create`s with the deployer key); only `IERC20` is a stub | — |
| `examples/erc20/` | `src/TestToken.sol` (minimal ERC-20 **with EIP-2612 `permit`**), `build.sh` (deploy + `addAllowedToken`) | — |
| `examples/client/vela_client.syn` | the client, below | 7 |
| `tests/wasmtime-go/` | Go probe on wasmtime-go v1.0.0 | — |
| `src/lib.rs` | the adapter | 4 (`cargo test --target <host>`) |

## The client: `examples/client/vela_client.syn`

`novaw` only speaks the payment app's payload; every other app needs its own client. This one does
everything a client can do, natively, with the builtins from v0.6.20 — no Go, no TS. Config in
`.env` (`.env.example`): `VELA_RPC_URL`, `VELA_PROCESSOR`, `VELA_TEE_AUTHENTICATOR`,
`VELA_AUTHORITY_URL`, `VELA_SUBGRAPH_URL`, `VELA_APP_ID`, `VELA_MAX_FEE` (wei), `VELA_SECP_KEY`
(hex; signs txs, pays), `VELA_P521_KEY` / `VELA_P521_PUB` (from `keys`), `VELA_USER_KEY`
(facilitator commands only).

| `synsema run vela_client.syn -- …` | Does |
|---|---|
| `keys` | a fresh P-521 pair printed for `.env` (`ecdh_keypair` + `reveal`) |
| `address` | the signing address (`VELA_SECP_KEY`) |
| `tee` | the Executor's P-521 key, read on-chain |
| `deploy <wasm> [params-json\|-] [trigger]` | multipart upload to `<authority>/deploy/upload` (`multipart_encode`), then `submitDeployRequest(0, descriptor)` or `submitDeployRequestWithTrigger(0, descriptor, trigger)`; `applicationId`/`requestId` from the `DeployRequestSubmitted` log; waits on the subgraph; tells you the `VELA_APP_ID` |
| `register` | AssociateKey (226 bytes) for `VELA_SECP_KEY`'s address |
| `deposit <amount> [token]` | ETH (wei) via `submitRequest` with an empty payload, or an allowlisted ERC-20 after `approve(processor, amount)` |
| `send '<json>' [wei]` | PROCESS: payload encrypted for the Executor; optional ETH deposit on the same request |
| `report '<json>'` / `report-download <id>` | DEANONYMIZATION (caller must be an allowed authority), then GET `/nonce` → EIP-191 signature of `chainId(8)‖appId(8)‖reportId(32)‖nonce(32)` → POST `/getreport` → decrypt → the guest's `report` (unwrapped from `reportDataBytes`) |
| `events [n]` / `app-events [n]` | your events (filtered by your 50 HMAC subtypes, decrypted) / the app's public events (label decoded when the subtype is one) |
| `status <requestId>` | the subgraph's `requestCompleteds` / `deployRequestCompleteds` row |
| `user` / `register-for` / `send-for '<json>' [amount token]` / `events-for [n]` | **facilitator** (`submitRequestFor`): the USER (`VELA_USER_KEY`, needs no ETH) signs an EIP-712 `RequestAuthorization` (domain `Vela`/`"0"`/chainId/endpoint, `nonce = getFacilitatorNonce(user)`) and, for an ERC-20 deposit, an EIP-2612 `Permit` under the token's domain; `VELA_SECP_KEY` submits and pays gas + fee (`msg.value = maxFee`). Only ASSOCIATEKEY and PROCESS; the deposit can only be an ERC-20 (never ETH) |

Every request waits for `RequestCompleted` through the subgraph (`status != 0` → the error code
and message). The pure parts have tests (`synsema test vela_client.syn`): cipher round trip, seed
and subtypes, log parsing, calldata, EIP-712 digests.

## Local stack (starter kit v0.2.0) — the recipe that worked on Windows

- `git clone HorizenOfficial/vela-starterkit`, `cp dockerfiles/.env.dev dockerfiles/.env`,
  `docker compose up -d` (9 images ≈ 1.5 GB; internal network `dockerfiles_pes_network`; chain
  `:8545`, authority `:8081`, subgraph `:8000` published on localhost). Addresses written by the
  deployer: ProcessorEndpoint `0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9`, TeeAuthenticator
  `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0`, TokenAllowlist `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9`,
  DefaultAuthority `0x5FbDB2315678afecb367f032d93F642f64180aa3`. Anvil #0 = deployer/admin.
- `novaw-linux` (vela-nova release): not runnable straight from a Windows bind mount
  (`input/output error`) — `docker run --rm --network dockerfiles_pes_network --entrypoint sh -v
  <wallet>:/wallet -w /wallet postgres:14 -c 'cp /wallet/novaw-linux /usr/local/bin/novaw && chmod
  +x /usr/local/bin/novaw && novaw <cmd>'` with `MSYS_NO_PATHCONV=1` in Git Bash; `wallet.conf`
  points at `10.10.40.30:8545`, `10.10.40.40:8081`, `vela-skit-subgraph-node:8000`.
- `forge`/`cast` are inside `horizen/cce-chain:v0.2.0`. Build contracts in a container on the
  DEFAULT network with `RPC_URL=http://host.docker.internal:8545` (the chain container itself has
  no DNS for solc/GitHub downloads): `docker run --rm --entrypoint sh -v <dir>:/x -w /x -e RPC_URL=…
  horizen/cce-chain:v0.2.0 -c 'sh build.sh'`.
- Timing: deploy ≈ 12 s, a request ≈ 10–15 s, a TRUSTPROCESS round trip ≈ 25 s.

## Language gotchas met while writing guests and clients

- `to` and `from` are reserved words — not even as parameter names. No `0xab` literals — write
  `171`. `index_of` takes a list, not text (digits: `floor(number(ch))`). Maps are shared by
  reference: a task that `set`s inside the state it received mutates the caller's map (matters in
  tests that reuse a state).
- `ecdh_shared_secret`/`hkdf_sha256`/`aes_gcm_*` take keys as **bytes/secret bytes**: a hex key from
  `.env` is `as_secret(bytes(env("K"), "hex"), "K")` (a text `secret()` is the hex characters).
  `hmac_sha256(data, key)` stringifies a `bytes` — wrap both in `as_secret`. `ecdh_keypair`'s
  private is labelled `ecdh_keypair.private` (`require reveal("ecdh_keypair.private")` to print it).
- `secp256k1_sign` returns `r‖s‖v` with v = 0/1; OpenZeppelin's `ECDSA.recover` and EIP-2612
  `permit` want 27/28 — add 27. `eip712_digest(domain, types, primary, message)` with the standard
  JSON shape (`{"Type": [{"name","type"}, …]}`, domain keys `name`/`version`/`chainId`/`verifyingContract`).
- `http_post(url, map)` sends JSON with the Content-Type; `bytes` bodies go raw; the response has
  `status`, `ok`, `body`, `json`, `headers`. `multipart_encode(parts)` → `{body, content_type}`.
  `require file.read("*")` for a path given on the CLI; `args()` needs no capability; `sleep` needs
  `time`; `secp256k1_sign` needs `sign("<secret label>")`.

## Adding another host

Copy `packages/guests/vela/`, rename the crate, read the host's contract **from its source** (exports,
signatures, how it writes inputs and reads results, which imports it provides, what it forbids),
write that at the top of `src/lib.rs` with file + version. Keep the shape: decode inputs → one ctx
map → `run_app(task, fallback, ctx)` → encode the task's map into the host's exact result. Pick
`wasm32-wasip1` when the host links WASI, `wasm32-unknown-unknown` only if it provides the
`synsema_host` imports. The ceiling is the determinism contract. Write the probe, wire CI, document
the `.syn` contract in the guest's README. If the generic ABI lacks something, add a documented
`synsema_call` operation useful to every host — never a host-specific export.
