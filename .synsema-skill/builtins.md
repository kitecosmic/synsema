# Synsema Built-in Tasks

> **This file is dense — jump to the `## ` section you need instead of reading it all:**
> Core · Error handling (`try`/`recover`/`raise`) · Strings · Regex · Bytes / binary (hashing,
> blockchain encoders, WebSocket client) · JSON · CSV · Math · Numeric arrays + linear algebra ·
> Assertions / tests · Config & secrets · Web auth (passwords, JWT, TOTP) · Agent identity & auth ·
> Spend ledger · Intentional operations (replace loops) · I/O · HTTP · Database ·
> HTTP server (serve) · Cron · Agent operations

## Core
- `print(values...)` — output text
- `length(collection)` → number
- `text(value)` → string conversion (integers show no decimal: `text(42)` → `"42"`)
- `number(value)` → numeric conversion (always float: `number("42")` → `42.0`)
- `floor(x)` → **integer** rounded toward −∞ (`floor(3.7)` → `3`, `floor(-3.7)` → `-4`)
- `ceil(x)` → **integer** rounded toward +∞ (`ceil(3.2)` → `4`, `ceil(-3.2)` → `-3`)
- `trunc(x)` → **integer** rounded toward zero (`trunc(3.7)` → `3`, `trunc(-3.7)` → `-3`)
- `round(x)` → nearest **integer**; ties round to the **even** value (banker's rounding, like Python's `round`): `round(2.5)` → `2`, `round(3.5)` → `4`. A non-number errors. These four are **pure** (no capability), and an already-integer argument is returned unchanged.
- `append(list, item)` → new list with item added
- `keys(map)` → list of keys
- `enumerate(list)` → `[{index, item}, …]` — indexed iteration in the language AND in templates (`each e in enumerate(xs)` → `e.index` / `e.item`). Pure; non-list → error.
- `values(map)` → list of values
- `contains(collection, item)` → bool (lists/text/maps; also `bytes`: subsequence, or a single byte 0–255)
- `split(text, separator)` → list
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list
- `type_of(value)` → text ("number", "decimal", "complex", "text", "bytes", "bool", "list", "map", "array", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection (lists/text/`bytes`; Python-style negatives)
- `length(x)` also works on `bytes` (byte count) and `array` (total elements). Indexing `x[i]` works on lists, maps, `bytes` (→ int 0–255) and `array` (→ row or scalar).
- `raise(message)` → **always raises a runtime error** with `message` (coerced to text). Use it to fail deliberately, or to **re-propagate** a caught error inside `recover` (see below). `raise()` with no arg errors. (`fail(...)` is for HTTP responses, NOT for raising runtime errors.) The statement form **`raise "msg"` / `raise err`** (no parens) also works — it desugars to the same call — and a bare `raise` alone is a loud parse error. ⚠️ **On engine ≤ v0.5.1 the no-parens form silently did NOTHING** (it parsed as two inert expressions); on those binaries always use `raise("msg")`.
- `read_line(prompt?)` → text — read one line from stdin (CLI). Optional `prompt` is printed first (no newline). Returns the line without the trailing newline; `nothing` on EOF. Works with a TTY **and** piped/redirected input (`printf 'x\n' | synsema run f.syn`) — unlike free-text `ask`. Under `synsema run` it **auto-flushes** pending `print` output before prompting, so a `read_line` loop is a real interactive REPL. (Reads stdin in any mode; the flush is `run`-only — see `flush`.) See [human.md](human.md).
- `flush()` → nothing — `run`-interactive primitive: `print` output is buffered and shown when the program ends; `flush()` writes the pending output to stdout **now** (live feedback for REPLs / long loops). Mode-aware: under `conform`/`test`/`serve` (which collect output for JSON/responses) `flush()` and `read_line`'s auto-flush are **no-ops** — output stays collected, stdout is never polluted.
- `llm_available()` → bool — `true` when a real LLM provider is wired, `false` offline. Branch on it instead of string-matching placeholders. See [llm.md](llm.md).
- `llm_usage()` → number — LLM tokens (input + output) consumed by this **process** so far; `0` offline. No capability (introspection). Pairs with `SYNSEMA_LLM_BUDGET` (ops degrade to a `[llm budget exceeded: …]` marker at the ceiling — never an error). See [llm.md](llm.md).

## Error handling — `try` / `recover` / `raise`
```
try
    risky()
recover err
    log "failed: " + err          -- err is the error message (text)
    raise(err)                    -- RE-PROPAGATE so the caller/agent sees a real failure
```
Without `raise`, `recover` **swallows** the error (the task/agent ends normally — DONE). With
`raise(err)`, the error propagates again (an agent ends in **ERROR**, not DONE). `give`/`stop` are
not errors and pass through `try/recover` untouched.

## Strings
- `fmt(template, map)` → interpolated text: `fmt("Hi {name}", {"name": "Alice"})` → `"Hi Alice"`
- `upper(text)` → uppercase
- `lower(text)` → lowercase
- `fold(text)` → lowercase **and** strips accents/diacritics — for accent-insensitive matching: `fold("Continúa")` → `"continua"`, `contains(fold("Está aquí"), "esta")` → true
- `trim(text)` → strip whitespace
- `starts_with(text, prefix)` → bool
- `ends_with(text, suffix)` → bool
- `replace_text(text, old, new)` → text with literal replacements

## Regex (pure — no capability)
- `matches(text, pattern)` → bool — **full match**: true only if the *whole* text matches. Built for validation, so an unanchored pattern is already safe (`matches("12345", "[0-9]+")` → true, `matches("a 5 b", "[0-9]+")` → false). For "does the pattern appear somewhere", use `find_all`/`capture`.
- `find_all(text, pattern)` → list of every whole match, in order (partial search): `find_all("a1b2", "[0-9]")` → `["1","2"]`
- `capture(text, pattern)` → first match (partial search): with groups, a list of group values; without groups, the whole match as text; no match → `nothing`
- `replace_re(text, pattern, replacement)` → text (`\1`/`\2` backreferences supported)
- ⚠️ A pathological pattern can be slow (ReDoS) — don't feed untrusted input as a *pattern* without care.

## Bytes / binary (pure — no capability)
- `bytes(text)` → utf8 bytes; `bytes(text, "hex"|"base64"|"base64url"|"base58"|"base32")` → decode; `bytes([72,73])` → from ints 0–255; `bytes(bytes)` → identity. `bytes(secret)` → **error** (plaintext never materializes). base58 = Bitcoin/Solana; base32 = RFC 4648 (Algorand); base64url = URL-safe `-_` (JWT/tokens; accepts input with or without `=` padding). `bytes + bytes` = concat.
- `decode(b)` / `decode(b, "utf8")` → text (UTF-8 **strict**, errors on invalid); `decode(b, "utf8_lossy")` → with `U+FFFD`; `decode(b, "hex"|"base64"|"base64url"|"base58"|"base32")` → text (base64url output is unpadded). (so `bytes(...)` ↔ `decode(...)` are inverses)
- `is_bytes(x)` → bool. `b[i]` → int 0–255; `bytes + bytes` → concatenation; `length`/`slice`/`contains` work on bytes.
- `sha256(x)` / `sha512(x)` → **bytes** (raw digest). x: text → hashes utf8; bytes → raw. Hex via `decode(sha256(x), "hex")`. `sha256(secret)` → error.
- `keccak256(x)` / `sha512_256(x)` → **bytes(32)**. ⚠️ `keccak256` is PRE-NIST Keccak (Ethereum), NOT SHA3-256 (`keccak256("")`=`c5d24601…`). Same rules as `sha256` (secret → error).
- `bytes_to_int(b)` → non-negative integer from big-endian bytes, **exact** (empty → 0; 256-bit values never touch float). `int_to_bytes(n, size?)` → big-endian bytes: minimal without `size` (no leading zeros; 0 → empty), zero-padded to exactly `size` with it (error if it doesn't fit). Inverses. Use them to put a signature's r/s into RLP as integers.
- `int_to_bytes_le(n, size)` → **little-endian** bytes of exactly `size` (error if it doesn't fit; `size` is mandatory — LE is a fixed-width binary-struct format). E.g. Solana System-transfer data: `int_to_bytes_le(2, 4) + int_to_bytes_le(lamports, 8)`.

Blockchain — sign/verify/derive (all pure-Rust; see stdlib.md for the security model):
- `secp256k1_sign(digest32, secret)` → bytes(65) `r‖s‖v` — **requires `sign("NAME")`** + audit; RFC 6979 deterministic, low-s. digest must be exactly 32 bytes (keccak256 it first).
- `secp256k1_verify(digest, sig, pubkey)` → bool; `secp256k1_recover(digest, sig65)` → bytes(65) pubkey (ecrecover); `secp256k1_pubkey(secret, compressed?)` → bytes(33|65). Pure.
- `ed25519_sign(message, secret)` → bytes(64) — **requires `sign("NAME")`** + audit. ⚠️ signs the RAW message (do NOT pre-hash). `ed25519_verify(msg, sig, pubkey)` → bool (**strict**: rejects small-order keys/points, matching what Solana/Algorand accept); `ed25519_pubkey(secret)` → bytes(32). Pure.
- `eth_address(pubkey_or_secret)` → EIP-55 text; `rlp_encode(value)` → bytes (bytes/non-neg int/list; text→error); `rlp_decode(bytes)` → value (**canonical-strict**: non-minimal encodings error, like Ethereum's decoders). `bech32_encode(hrp, data, variant?)` / `bech32_decode(text)`→`{hrp,data,variant}`. Pure.
- ABI (pure): `abi_encode(sig, values)` → bytes selector+args for a contract call (`abi_encode("transfer(address,uint256)", [addr, amount])`); `abi_decode(types, data)` → list (`types` = `"(address,uint256)"` or list of texts; **strict**: hostile offsets / dirty padding / short-long data → error); `abi_selector(sig)` → bytes(4). Signature is CANONICAL: no spaces/param names (`uint`/`int` normalize to `uint256`/`int256`). Types: uint8..256, int8..256, address (EIP-55 validated if mixed-case; bytes(20) ok), bool, bytes1..32, bytes, string, T[], T[k], tuples `(…)`. uint256 amounts need EXACT integers (big ints fine; floats error).
- EIP-191/712 (pure): `eip191_digest(message)` → bytes(32) personal_sign/SIWE digest; `eip712_digest(domain, types, primary_type, message)` → bytes(32) typed-data digest from READABLE maps (standard JSON shape: `{"Person": [{"name": "name", "type": "string"}, …]}`; nested structs, arrays, optional domain fields in fixed EIP order; missing/extra field → error naming it). Sign the digest with `secp256k1_sign` (no separate sign builtin — one gate only).
- Solana (pure): `solana_message({fee_payer, recent_blockhash, instructions, version?})` → message bytes ready for `ed25519_sign` (legacy default; `"version": 0` → v0, signature covers the 0x80 prefix; `lookup_tables` → clear error, stage 3). Accounts auto-ordered by runtime rules (payer first, then writable signers / ro signers / writable non-signers / ro non-signers, each sorted by pubkey bytes). Pubkeys: bytes(32) or base58 text. `solana_tx(msg, sig_or_list)` → wire tx (validates count vs header) → `decode(tx, "base64")` for sendTransaction.
- Solana PDA/SPL (pure): `solana_pda(seeds, program)` → `{address: bytes(32), bump: int}` (findProgramAddress; off-curve, seeds are bytes/text ≤32, max 15). `spl_ata(owner, mint, token_program?)` → bytes(32) associated token account. `spl_transfer_data(amount)` → SPL Transfer ix data (tag 3 ‖ u64 LE); `spl_transfer_checked_data(amount, decimals)` → TransferChecked (tag 12, recommended).
- Algorand (pure): `algorand_tx_encode(txn_map)` → `"TX"‖canonical msgpack` ready for `ed25519_sign` (protocol short keys: type/snd/rcv/amt/fee/fv/lv/gen/gh/note…; keys sorted, zero/empty/false fields OMITTED — required by the network; text addresses checksum-validated → bytes32). `algorand_tx(txn_map, sig64)` → SignedTxn msgpack for POST `/v2/transactions` (`application/x-binary`). `algo_address(pubkey_or_secret)` → base32 text with checksum. TXID = `decode(sha512_256(algorand_tx_encode(txn)), "base32")`.
- EIP-1559 builders (pure — no gate, nothing sent): `tx_eip1559({chain_id, nonce, to, value, gas, max_fee, max_priority, data?, access_list?})` → `{digest: bytes(32), fields, chain_id, nonce, to (EIP-55 text), value, gas, max_fee, max_priority}` — EVERY value-moving field is required (no silent defaults; missing → error naming the reader: `eth_chain_id`/`eth_nonce`/`eth_estimate_gas`/`eth_fee_history`); `max_priority > max_fee` → error; `access_list` = `[{address, storage_keys: [bytes32,…]}, …]`; unknown key → error. Sign `tx["digest"]` with `secp256k1_sign`, then `tx_eip1559_raw(tx, sig65)` → signed raw bytes for `eth_send_raw` (v/r/s assembled; a 27/28 v is rejected — typed txs use y-parity 0/1).
- Bitcoin — the UTXO matrix (all pure unless noted; spend FROM P2WPKH/P2TR key-path, send TO any standard type; networks `"mainnet"` default | `"testnet"` | `"signet"` | `"regtest"`):
  - `hash160(x)` → bytes(20) `ripemd160(sha256(x))` (the address hash; bytes/text, secret→error). `btc_address(pubkey_or_secret, kind?, network?)` → text; `kind` = `"p2wpkh"` (default, bech32) | `"p2tr"` (bech32m; the address is the TWEAKED BIP-341 key-path key, applied internally) | `"p2pkh"` (base58). An uncompressed pubkey → error (segwit needs the 33-byte compressed form).
  - `btc_address_decode(text)` → `{kind, network, program: bytes, encoding}` — STRICT: base58check checksum OR bech32/bech32m per BIP-350 (a v0 address in bech32m, or v1 in bech32, is REJECTED), exact lengths, network identified. `btc_script(address)` → scriptPubKey bytes of a standard address. `btc_txid(raw)` → hex text (dSHA256 without witness, **byte-reversed** — the explorer/RPC form).
  - `schnorr_sign(digest32, secret, "taproot"?)` → bytes(64) BIP-340 — **requires `sign("NAME")`** + audit (the SAME gate as secp256k1/ed25519 — no new capability). `"taproot"` applies the BIP-341 key-path tweak internally (spend from a P2TR address); omit it for plain BIP-340. Deterministic (aux-rand fixed at 32 zero bytes → byte-exact vs BIP-340/341 vectors). `schnorr_verify(digest32, sig64, xonly32)` → bool; `schnorr_pubkey(secret)` → bytes(32) x-only. Pure.
  - `btc_tx(params)` → `{digests: [bytes32, … ONE PER INPUT], fee, vsize, fee_rate, total_in, total_out, network, rbf, locktime, version, inputs, outputs}` — PURE builder. `params` = `{inputs, outputs, fee, network?, rbf?, locktime?, allow_absurd_fee?}`. `inputs`: `[{txid (64-hex or bytes32, display order), vout, amount (SATS int), address, pubkey?}]` — `amount`+`address` REQUIRED (BIP-143/341 sign the amounts; read them with `btc_utxos`); P2WPKH needs `pubkey` (the witness reveals it; `secp256k1_pubkey(secret)` or 33-byte bytes), P2TR key-path takes no pubkey (optional cross-check of the internal key). `outputs`: `[{address, amount}]` in SATS (integers exact; a float/decimal → error with the conversion). **G28: `sum(inputs) == sum(outputs) + fee`, fee DECLARED** — if it doesn't balance the error names the exact sat difference ("did you forget the change output?"). Change is one more explicit output. Dust (546/294/330) → error naming the limit; `fee > sum(outputs)` → error unless `"allow_absurd_fee": true`. `rbf` default true (sequence 0xFFFFFFFD); false → 0xFFFFFFFE. `sighash` key → error (only SIGHASH_ALL/DEFAULT; NONE/SINGLE/ANYONECANPAY out of scope).
  - `btc_tx_raw(tx, signatures)` → signed tx bytes for `btc_send` — PURE. `signatures` = one per input, SAME order (count mismatch → error); each is the 64/65-byte `secp256k1_sign` output (P2WPKH, DER+SIGHASH_ALL assembled, low-s enforced) or 64-byte `schnorr_sign(…, "taproot")` output (P2TR). VERIFIES each signature against the UTXO's key before assembling (wrong key → error, nothing broadcast).
  - PSBT (BIP-174, v0, pure): `psbt_encode(tx)` → base64 text of the UNSIGNED PSBT (witness_utxo per input, importable in Sparrow/Electrum/Ledger/Trezor/Coldcard) from a `btc_tx` map. `psbt_decode(text, network?)` → `{txid, version, locktime, inputs [{txid, vout, sequence, amount, kind, address, signed, …}], outputs, total_in, total_out, fee, complete}` — audit a PSBT with `show`/`confirm` before signing/broadcasting. `psbt_finalize(text)` → signed tx bytes if the PSBT comes fully signed (P2WPKH partial_sig or P2TR key sig) → `btc_send`. The flagship cold-custody flow: agent `btc_tx`+`psbt_encode` → human signs on hardware wallet → agent `psbt_finalize`+`btc_send` (the key never existed on the agent's machine).
- Bitcoin read-side — **all require `net(host)`** (Esplora REST primary, strict decode: amounts over 21M BTC / malformed txids → catchable error; errors name the host):
  - `btc_utxos(url, address)` → `[{txid, vout, amount, confirmations, confirmed}]` (Esplora; ready for `btc_tx`); `btc_balance(url, address)` → `{confirmed, mempool, total}` exact sats (mempool may be negative); `btc_fee_estimates(url)` → `{"<block-target>": sat/vB, …}` (raw numbers, ascending); `btc_send(url, raw)` → txid text (re-checked: the node's txid must match the broadcast bytes' hash); `btc_wait(url, txid, confirmations?, timeout?)` → confirmed info map or `nothing` at timeout (bounded poll; Esplora 404 = "not in mempool yet", keeps waiting).
  - `btc_rpc(url, method, params?, auth?)` → decoded JSON — Bitcoin Core JSON-RPC escape hatch (regtest / own nodes). `auth` = `{user, pass}` where `pass` may be a `secret` (materialized as Basic auth ONLY at the socket edge).
  - `wif_import(text, label?)` → **secret** — **requires `wallet`** + audit; imports a WIF private key (checksum validated, version 0x80 mainnet / 0xef testnet; the WIF value is never echoed). NO reverse export (G2: no builtin returns a key; the deliberate backup is `reveal()` of the mnemonic). HD for Bitcoin: `hd_derive(seed, "m/84'/0'/0'/0/0")` (BIP-84, P2WPKH) / `"m/86'/0'/0'/0/0"` (BIP-86, P2TR) → feed `btc_address`.
- Chain read-side — **all require `net(host)`** (same scope as `http_*`; strict decode: malformed/hostile/>16 MiB response → catchable error; errors name the host, never the full URL):
  - EVM: `eth_rpc(url, method, params?)` → decoded JSON (escape hatch; int params → hex-quantity, bytes → `0x…`); `eth_nonce(url, addr)` → int ("pending"); `eth_balance(url, addr, block?)` → exact wei int; `eth_gas_price(url)` / `eth_chain_id(url)` → int; `eth_estimate_gas(url, tx_map)` → int; `eth_call(url, {to, data}, block?)` → RAW bytes (feed `abi_decode`); `eth_fee_history(url, blocks?, percentiles?)` → `{base_fee (NEXT block), priority (median of first percentile col), base_fees, rewards}`; `eth_send_raw(url, raw)` → `"0x…"` hash text; `eth_receipt(url, hash)` → typed receipt map (quantities int, addresses EIP-55, hashes `"0x…"`, log data bytes) or `nothing`; `eth_wait_receipt(url, hash, confirmations?, timeout?)` → receipt after N confs (1–1000, default 1) or `nothing` at timeout. `block?` = `"latest"` (default) | `"earliest"|"pending"|"safe"|"finalized"` | number.
  - Solana: `solana_rpc(url, method, params?)` → decoded JSON (plain-JSON params; raw bytes → error, encode explicitly); `solana_latest_blockhash(url)` → bytes(32) (feeds `solana_message`); `solana_balance(url, pubkey)` → lamports int; `solana_send(url, tx_bytes)` → base58 signature text; `solana_confirm(url, sig, timeout?)` → `{slot, confirmations, confirmation_status, err}` (waits confirmed/finalized; `err != nothing` = landed but FAILED) or `nothing` at timeout; `spl_balance(url, owner, mint, token_program?)` → `{amount, decimals, ata}` (missing ATA → catchable ERROR, never a silent 0).
  - Algorand (algod REST; each takes a trailing `headers?` map — `X-Algo-API-Token` may be a `secret`): `algorand_params(url, headers?)` → `{fee (PER-BYTE), min_fee (flat 1000 µAlgo), fv, lv (= fv+1000), gh: bytes(32), gen}`; `algorand_account(url, addr, headers?)` → account map (checksum validated BEFORE the network); `algorand_send(url, signed_bytes, headers?)` → 52-char txid (binary `application/x-binary` POST handled); `algorand_wait(url, txid, timeout?, headers?)` → confirmed info map, `nothing` at timeout, ERROR on pool rejection (definitive).
  - Waiters are BOUNDED polls (like `ws_recv`): default timeout 60 s, `nothing` when it expires — never hang. A TRANSIENT failure mid-wait (transport error or HTTP 5xx) does NOT kill the wait: after a first successful poll the waiter retries by itself until the deadline (one `synsema: warning:` line on stderr — no agent action needed); if the deadline expires while the node is still failing, the ERROR surfaces (catchable, says "deadline expired during this failure") instead of `nothing` — "unconfirmed" and "node stopped answering" stay distinguishable. A dead node / wrong URL still fails fast on the FIRST poll; definitive answers (4xx, invalid JSON, node RPC errors, hostile decode) error immediately. Broadcasting is `net`-gated, not `sign`-gated (the signature already happened; `sign` stays the only value door).
- HD custody — **all require `wallet`**, all return a `secret` (mnemonic/seed/key NEVER materialize; audited in `wallet.log`; denied in `sandbox`):
  - `mnemonic_generate(words?, label?)` → secret (12/15/18/21/24 words, OS entropy); `mnemonic_to_seed(mnemonic, passphrase?)` → secret (64-byte BIP-39 seed, checksum-validated; mnemonic AND passphrase must be secrets — seal a value in hand with `as_secret(x, "LABEL")`); `mnemonic_from_entropy(entropy, label?)` / `mnemonic_to_entropy(mnemonic)` → secret.
  - `hd_derive(seed, path, curve?, label?)` → secret. `curve` = `"secp256k1"` (default, BIP-32; ETH `m/44'/60'/0'/0/i`) | `"ed25519"` (SLIP-0010, hardened-only; Solana `m/44'/501'/i'/0'`). Use the result directly with `eth_address`/`ed25519_pubkey`/`secp256k1_sign`.
  - `algorand_mnemonic(secret32)` / `algorand_mnemonic_to_key(mnemonic, label?)` → secret (25-word Pera/Defly format — NOT BIP-39). `keystore_import(json_text, passphrase, label?)` → secret (Geth V3, scrypt/pbkdf2 + AES-128-CTR; wrong pass → error, no material); `keystore_export(secret, passphrase, opts?)` → text (encrypted V3 JSON; `opts` = `{"kdf": "scrypt"|"pbkdf2", "n", "r", "p", "c"}`, defaults = Geth scrypt n=262144).
  - `label?` names the resulting secret (it defaults to a derived name like `W.seed` / `W/path`) — the `wallet`/`sign`/`reveal` scopes match against that name.
- The key is always a `secret` (text→hex, bytes→raw); never a plain string. Errors describe size/shape, never the key/mnemonic. Signing/custody DENIED inside `sandbox`; ALL the encoding/digest/PDA builtins above are pure and work everywhere.
- WebSocket client (transport, gated by `net(host)` — same as HTTP; reconnects re-check it):
  - `ws_connect(url, headers?, opts?)` → handle (`ws://`/`wss://`). `opts` = `{timeout, max_message_size (16 MiB default / 64 MiB ceiling), subprotocols (list), max_queue (messages, default 1024), max_queue_bytes (default 64 MiB, ceiling 1 GiB), on_full ("block" default | "drop_oldest" | "error"), reconnect: {max_retries (default 10), backoff (secs, default 0.5), backoff_max (default 30), on_reconnect (a task, receives the handle)}, keepalive: {interval, timeout (default = interval)}}`. Unknown opt → error.
  - `ws_send(conn, text_or_bytes)` → true (a `secret` is refused); `ws_recv(conn, timeout?)` → `{type: "text"|"binary"|"close", data}` or **`nothing`** on timeout (never blocks); `ws_close(conn)` (idempotent).
  - `ws_select(conns, timeout?)` → `{conn, type, data, name?}` of the FIRST ready connection (round-robin fair), or `nothing` on timeout/empty set. `conns` = list of handles or name→handle map (adds `name`). A dropped conn surfaces as `{type: "close", conn}` and is retired; a fatal protocol error → catchable error naming `conn`.
  - `ws_select_all(conns, timeout?)` → list of every message ready this tick (≤1 per connection); `ws_broadcast(conns, data)` → count sent (dead handles skipped).
  - `ws_status(conn)` → `"open"|"reconnecting"|"closed"` (unknown handle → `"closed"`, never errors); `ws_stats(conn)` → `{sent, received, reconnects, queued, queued_bytes, last_pong_ago (secs or nothing), status, subprotocol}`.
  - Sync-engine boundary: keepalive/reconnect tick INSIDE `ws_select`/`ws_recv`/`ws_status`. Per-interpreter connection cap via `SYNSEMA_WS_MAX_CONNS` (default 4096). See stdlib.md § WebSocket.
- Note: `text(b)` / `print(b)` show a hex repr like `bytes(48656c6c6f)`, **not** a decode. `bytes != text` always.

## JSON (pure — no capability)
- `json_encode(value)` → text: serialize any value to a JSON string. Maps/lists nest; **secret → `"[redacted]"`** (safe), `bytes` → base64 string, `decimal` (`1.50d`) → exact JSON number, `nothing` → `null`. ⚠️ NOT safe to embed inside a `<script>` tag — use `json_for_script` there.
- `json_for_script(value)` → text: same JSON but with `<`, `>`, `&` escaped as `\u00XX` — **the safe way to embed data in an inline `<script>`** (`{ raw json_for_script(x) }`); a value containing `</script>` cannot break out of the tag.
- `json_decode(text)` → value: parse a JSON string to a Synsema value (object→map, array→list, number→number, etc.). Errors clearly on invalid JSON.
- Round-trippable: `json_decode(json_encode(x))` reconstructs `x` (the idiomatic way to store structured data in a Redis/text value: `redis_set(k, json_encode({...}))`).

## CSV (pure — no capability; see [dataviz.md](dataviz.md))
- `csv_parse(text, opts?)` → list of maps (first row = headers; the same shape `sql()` returns). RFC 4180 (quoted fields, `""` escapes, CRLF/LF, BOM). Opts: `{headers: false}` → list of lists, `{delimiter: ";"}`, `{numbers: true}` (default is **lossless text**: `"00123"` stays text). Errors carry the line (unclosed quote, uneven fields, duplicate headers, unknown option).
- `csv_encode(value, opts?)` → text. List of maps (headers = first map's keys) or list of lists. Opts: `{headers: [..]}` (order/subset), `{delimiter}`, `{eol}` (`"\r\n"` default). Minimal quoting; integers without decimals; `nothing` → empty; `bytes` → base64; **secret → `[redacted]`**; nested list/map → error suggesting `json_encode`.

## Math (pure — no capability)
Constants (bare values): `pi`, `tau`, `e`, `inf`, `nan`.
- magnitude/selection (type-preserving): `abs`, `sign`, `min`, `max`, `clamp`. `abs(complex)` → modulus.
- roots/powers: `sqrt`, `cbrt`, `hypot`, `pow`. exp/log: `exp`, `ln`, `log10`, `log2`, `log_base`. (no bare `log` — it's a soft keyword; use `ln`/`log10`/`log2`.)
- trig (radians): `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2`, `radians`, `degrees`.
- hyperbolic: `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, `atanh`.
- number theory (integers): `gcd`, `lcm`, `factorial`.
- introspection: `is_nan`, `is_infinite`, `is_finite`, `round_to`.
- aggregates over a list: `sum`, `product`, `mean` (also work on `array`, see below).
- **descriptive statistics** (list of numbers or `array`; see [dataviz.md](dataviz.md)): `median(x)`, `percentile(x, p)` (p ∈ [0,100], linear interpolation — NumPy default), `histogram(x, bins?)` → `{counts, edges}` (`bins` = int, default 10, or explicit ascending edges; last bin closed). Empty data or NaN → clear error.
- **Special functions:** `gamma`, `lgamma`, `erf`, `erfc`, `beta` (real-only; via `libm`).
- **Polymorphic:** `sqrt`/`exp`/`ln`/`sin`/`cos`/`tan`/`asin`/`acos`/`atan`/hyperbolics accept a real **or** a `complex`. Real arg → real result (unchanged: `sqrt(-1)` → NaN). Complex arg → complex (cmath): `sqrt(complex(-1,0))` → `complex(0,1)`, `exp(complex(0, pi))` ≈ `-1`.

### Complex numbers
- `complex(re, im)` → complex; `real(z)` / `imag(z)` → float; `conj(z)`, `arg(z)` (phase), `is_complex(x)`. Fluid arithmetic with real promotion (`3 + complex(0,2)`); `complex(0,1)**2` == `-1+0i` (exact). `complex(a,0) == a`; **not ordered** (`<`/`>` → error).

## Numeric arrays + linear algebra (pure — no capability)
n-dimensional f64 arrays (NumPy-equivalent core).
- **Construct:** `array(nested_list)`, `zeros(shape)`, `ones(shape)`, `full(shape, v)`, `arange(start, stop, step?)`, `linspace(start, stop, n)`, `identity(n)` / `eye(n)`. `shape` is an int or a list like `[2,3]`.
- **Inspect/convert:** `shape(a)`, `ndim(a)`, `size(a)`, `is_array(a)`, `to_list(a)`, `reshape(a, shape)`, `transpose(a)`, `flatten(a)`, `at(a, [i,j])` (element), `a[i]` (row or scalar).
- **Vectorized:** `+ - * /` are **elementwise** with broadcasting (`array([1,2,3]) + array([10,20,30])`, `a * 2`). ⚠️ `*` is **elementwise (Hadamard), NOT matrix product** — use `matmul`.
- **Reductions** (whole array or along an `axis`): `sum`, `mean`, `min`, `max`, `product`, `std`, `var` — e.g. `sum(a, 0)`.
- **Linear algebra** (2D, via `faer`): `matmul(a, b)` / `dot(a, b)`, `solve(A, b)`, `det(A)`, `inv(A)`, `norm(a, kind?)`, `trace(A)`, `eig(A)` → `{values, vectors}` (eigenvalues are `complex`), `svd(A)` → `{u, s, vt}`. A singular matrix in `inv`/`solve` → clear error (never silent NaN).

## Assertions / tests (see [testing.md](testing.md))
- `assert(cond, msg?)`, `assert_eq(actual, expected, msg?)`, `assert_ne(a, b, msg?)`, `assert_error(fn)`. Work anywhere as defensive checks; `test "..."` blocks + `synsema test` are the harness.

## Config & secrets (see [secrets.md](secrets.md))
Resolution for `env`/`secret`: process environ → `.env` → default → else error. Both are deny-by-default and scoped by name (`require env("X")` / `require secret("X")`, or a `X_*` prefix).
- `env(name, default?)` → plain text config
- `secret(name, default?)` → an opaque, **redacted** `secret` (LLM-proof; never prints/logs/serializes its value)
- `as_secret(value, label?)` → seal a **runtime** value (text/bytes) as an opaque `secret`. **No `require`** (pure; only strengthens). Idempotent. For a key that arrives at runtime (e.g. a user's request header), not from config.
- `reveal(secret)` → plaintext (a bytes-secret reveals as `bytes`) — requires `require reveal("NAME")` **scoped to the secret's name/label**; audits every attempt (granted/denied); fails if it can't audit; bare `require reveal` = any (compat, warns). Use sparingly.
- `bearer(secret)` → a tainted `Bearer <secret>` header value (materialized only at the socket)
- `hmac_sha256(data, secret)` → hex MAC (not secret)
- `verify_hmac(data, signature, secret, algo?)` → bool, constant-time. `algo` = `"sha256"` (default) or `"sha512"`; decodes hex/base64 signatures (Stripe/GitHub/Shopify). SHA-1 is rejected.
- `constant_time_eq(a, b)` → bool, constant-time; accepts a `secret` on either side

## Web auth (passwords, JWT, TOTP, CSPRNG)
`random_bytes`/`token` **require `require random`** — the same deny-by-default gate as
`random()`/`random_int()` (their purpose IS producing randomness; denied in `sandbox`).
The rest are pure transforms — no capability. Every key/password argument accepts a
sealed `secret`, text (raw UTF-8 bytes) or `bytes`; anything else is a clear error.
- `random_bytes(n)` → n bytes from the **OS CSPRNG** (1–65536). Never use `random()` for anything security-related.
- `token(n?)` → unguessable base64url text of n random bytes (16–256, default 32 → 43 chars). Session ids, CSRF tokens, API keys, device codes.
- `password_hash(pw)` → PHC text (`$argon2id$v=19$m=19456,t=2,p=1$…`, OWASP params, random salt). Store this string as-is.
- `password_verify(pw, phc)` → bool (constant-time). Malformed/unknown PHC → **error**, not `false` ("wrong password" and "corrupt hash in DB" must never be confused).
- `jwt_sign(claims, key, opts?)` → HS256 token. Sets `iat` (your explicit claim wins); `opts.expires_in` (seconds) sets `exp` (passing both an `exp` claim and `expires_in` is an error).
- `jwt_verify(token, key, opts?)` → claims map or `nothing` on ANY failure (bad signature, expired `exp`, future `nbf`, malformed, `alg` ≠ HS256 — the verifier pins the algorithm; `"none"`/`RS256` tokens are rejected). `opts.leeway` seconds (default 60). RS256/ES256 (third-party OIDC) is not supported yet.
- `totp(key, opts?)` → code text (defaults: sha1, 6 digits, 30 s — the Google Authenticator profile). Opts: `algo` (`"sha1"|"sha256"`), `digits` (6–8), `period`, `at` (unix ts, for deterministic tests).
- `totp_verify(key, code, opts?)` → bool (constant-time), `opts.window` = ±N periods (default 1). The code must be **text** (leading zeros matter).

```syn
require random                                      -- gates token()/random_bytes only

let phc be password_hash(pw)                        -- at signup
when password_verify(pw, stored_phc)                -- at login
    let sid be token()
let seed be random_bytes(20)                        -- TOTP enrolment
let uri be "otpauth://totp/App:user?secret=" + decode(seed, "base32") + "&issuer=App"
when totp_verify(seed, submitted_code)              -- 2FA check
```

## Agent identity & auth (agents as first-class subjects)

Web auth (above) is for a **human with a browser**. This section is for **agents**:
proving who they are without carrying a long-lived secret, delegating a *weaker*
slice of their own authority to sub-agents, and being metered per identity. See
[serve.md](serve.md) § Agent identity for the server side.

**Capability tokens — delegation that can only narrow** (pure, no capability):
An orchestrator mints a token for itself and hands sub-agents an *attenuated* copy
— offline, without the root key. Attenuation can **never** widen: it's checked when
you attenuate (clear error) and again when you verify (rejected), so a hand-forged
token can't widen either. The scopes are the same shapes as `require`.
- `captoken_mint(caps, root_key, opts?)` → token text. `caps` = `{capability: scope | [scopes] | nothing}` (`nothing` = the capability with no scope). Opts: `id` (what you revoke; random if omitted), `ttl` (seconds, **default 900** — short on purpose, see revocation), `aud`, `ip`, `method`, `spend` (`{unit: max}`).
- `captoken_attenuate(token, caps, opts?)` → a narrower token. **Takes no key** — that's the point. Same opts; anything wider than the parent is an error.
- `captoken_verify(token, root_key, opts?)` → `{id, caps, depth, caveats}` or `nothing` on ANY failure. Opts supply the context the caveats are checked against — `aud`, `ip`, `method`, `at` (unix ts), `revoked` (list of ids). **Fail-closed:** a caveat in the token that you don't supply context for → rejected.
- `captoken_allows(verified, capability, scope?)` → bool. Takes the *output of verify* (so you can't ask about an unverified token); `nothing` → `false`.
- **Revocation:** attenuation is offline, so there is no central check. Short TTLs + a denylist of ids (`opts.revoked`, typically from redis) is the pattern. Say it out loud in your design; don't improvise it during an incident.

```syn
-- the unit is whatever the host works in (fiat, crypto, commodities, credits)
let t be captoken_mint({"net": "*.example.com", "spend": "ETH"}, secret("ROOT_KEY"),
                       {"ttl": 600, "spend": {"ETH": 0.5}})
let sub be captoken_attenuate(t, {"net": "api.example.com"},        -- no root key here
                              {"ttl": 60, "spend": {"ETH": 0.01}})
let caps be captoken_verify(sub, secret("ROOT_KEY"))                -- map | nothing
when captoken_allows(caps, "net", "api.example.com") ...
```

**Signed requests (proof-of-possession)** — a stolen bearer token is useless without
the key. Pinned profile of RFC 9421: covers `@method`, `@target-uri` and
`content-digest` (always, even with an empty body), plus `created`/`keyid`/`alg`.
- `http_sign(request, key, opts?)` → map of headers to send (`Signature-Input`, `Signature`, `Content-Digest`). `request` = `{method, url, body?}`. **Requires `sign("KEY_NAME")`** + audit (the same door as signing on-chain); the key must be a sealed `secret`. Opts: `alg` (`"ed25519"` default, or `"hmac-sha256"`), `keyid` (defaults to the secret's name), `created`, `nonce`, `label`.
- `http_signature_verify(request, key, opts?)` → `{keyid, alg, created, nonce}` or `nothing`. `request` = `{method, url, headers, body?}`. Pure (verifying signs nothing). **`opts.alg` is REQUIRED** — the verifier pins the algorithm; reading it from the message is the classic confusion forgery. Opts: `max_age` (seconds, default 300 — the anti-replay window; `created` in the future is rejected too).
- The key material follows each algorithm's rule: ed25519 = curve material (hex text or bytes, like `ed25519_sign`); hmac-sha256 = the shared string's raw bytes.

**Third-party OIDC (RS256/ES256)** — "login with Google" and cloud workload identity:
- `oidc_verify(token, opts)` → claims map or `nothing`. **`iss` and `aud` are mandatory** (verifying a signature without checking the audience accepts tokens minted for another app of the same provider — the classic confused deputy). Keys: `jwks_url` (fetched and cached 10 min, re-fetched when a `kid` is unknown — **needs `require net(host)`**) or `jwks` (the document inline). Opts: `leeway` (default 60), `alg` (`RS256`/`ES256`; HS256 belongs to `jwt_verify`). RSA keys under 2048 bits are rejected.
- A failing *token* is `nothing`; a failing *fetch* is an error — "I couldn't check it" must never look like "it isn't valid".

**mTLS client identity** (workload identity by certificate):
- `mtls_identity(cert_path, key_path, opts?)` → true. Declares this **process's** TLS client identity: `https://` requests to the hosts in scope present that certificate. **Requires `file.read`** on both PEMs. It's per-process, not per-request, because a certificate identifies the *workload* (SPIFFE-style). `opts.hosts` — a list of hosts (or one host as text) that the identity is presented to, with the same wildcard rule as `require net`: `"*.mesh.internal"` covers the domain and its subdomains. **Omit `hosts` and it goes to every host the program can reach** (already bounded by `require net`); declare them when your `net` scope is broad, so a third party can't harvest your workload identity just by asking for a client certificate.

## Spend ledger (see [capabilities.md](capabilities.md))
- `spend(amount, unit, reason)` → number (the unit's accumulated total after this spend) — **requires `spend("UNIT")`** (deny-by-default ALWAYS, never auto-granted; denied in `sandbox`; a tool must declare it for `call_tool`). Declares an external spend BEFORE the program makes the actual payment call: validates (`amount` > 0, `unit`/`reason` non-empty text), checks the capability, enforces the host ceiling (`SYNSEMA_SPEND_CEILING="EUR:500,ETH:0.1,bbl:100"` — breach = **hard catchable error**; do NOT proceed with the payment call after it), and writes an append-only, **fail-loud** ledger entry to `spend.log` (amount as canonical decimal text + reason + file:line; no written entry → the spend errors). The **unit is free text and no currency is privileged** — fiat, crypto, commodities, credits, kWh, tokens: `spend(0.000000000000000001, "ETH", …)` (one wei) and `spend(1500, "JPY", …)` (no decimals) are equally valid. Amounts take the exact **decimal** path with up to **28 decimal places** — an 18-decimal crypto unit fits whole and cents never accumulate binary error; a finer subdivision than 28 places errors clearly (spend in the base unit instead). Totals are per **process**, monotonic.
- **Per-identity metering:** under `serve`, the spend is booked to the authenticated subject (`request.user`'s `id`/`sub`/`keyid`) and the audit line carries `identity="…"`. Three ceilings apply, all of them, always the strictest: the host's per-unit one (`SYNSEMA_SPEND_CEILING`), the host's per-identity one (`SYNSEMA_SPEND_CEILING_PER_IDENTITY="agent-1=EUR:50,researcher=ETH:0.01"` — its own variable, with `=` before the unit, so a unit containing `:` can never collide with an identity key) and the one **delegated by a captoken** (its `spend` caveat, when the auth task returns the verified token). That last one is how an orchestrator caps a sub-agent's budget and the server enforces it.
- `spend_total(unit, identity?)` → number — without the 2nd argument, the process's accumulated total for that unit (`0` if none); with it, that identity's. Introspection, no capability (like `llm_usage()`). Time-windowed policy belongs to the framework: read `spend.log` (grant `file.read` over the audit dir — `$SYNSEMA_AUDIT_DIR` or `~/.synsema/audit`).

## Intentional operations (replace loops)

Dual-order: every op below that takes a callable accepts BOTH `(fn, list, …)` and
`(list, fn, …)` — task/lambda and list are distinguishable at runtime, so either English
reading works. The canonical documented order is the one shown. Extra args (`predicate?`,
`initial?`) always stay at the end; two tasks or two lists where one-and-one is expected
is an explicit error (never guessed). `collect` (property is text) and `flatten` (unary)
have a single form.

- `apply(function, list)` → list with function applied to each
- `where(list, predicate)` → filtered list
- `collect(list, "property_name")` → list of property values
- `transform(list, function, predicate?)` → selectively transformed list
- `reduce(list, function, initial)` → single accumulated value
- `sort_by(list, key_function)` → sorted list
- `group_by(list, key_function)` → map of key → list
- `find_first(list, predicate)` → first match or nothing
- `every(list, predicate)` → true if all match
- `some(list, predicate)` → true if any match
- `count_where(list, predicate)` → number
- `flatten(list_of_lists)` → flat list
- `zip_with(list_a, list_b, combiner)` → combined list
- `unique(list)` → deduplicated, first-appearance order (structural equality, same as `==`/`contains` — maps/lists dedupe by value)
- `index_of(list, item_or_predicate)` → 0-based index of the first match, or **`nothing`** if absent (not -1 — check `when idx != nothing`); callable 2nd arg = predicate, anything else = structural equality

## I/O (require capabilities)
- `fetch(url, method?, headers?, body?)` → map with status, headers, body
- `read_file(path, offset?, limit?)` → text — requires `file.read`. No extra args = whole file (lossy for non-UTF-8; use the bytes variant for binary). With `offset` (1-based line) and optional `limit` (max lines), reads a **line range**, preserving EOLs: `read_file(f, 1, 100)` = lines 1–100; `read_file(f, 500)` = from line 500 to EOF. Fewer lines than `limit` ⇒ end of file. `offset < 1` or `limit < 0` → error.
- `read_file_bytes(path)` → `bytes` — requires `file.read` (byte-exact; no range)
- `write_file(path, content)` → bool — requires `file.write`. **Atomic** (temp + rename); creates parent dirs. If `content` is `bytes`, writes raw bytes; else text.
- `list_dir(path)` → list of maps `{name, is_dir, size}`, **sorted by `name`**, non-recursive, includes hidden entries (`size` = bytes, `0` for dirs) — requires `file.read`. Errors if `path` is not a directory.
- `file_info(path)` → `{exists, is_dir, size, modified}` (`modified` = unix seconds, or `nothing`); a missing path returns `{exists:false, is_dir:false, size:0, modified:nothing}` (no error) — requires `file.read`
- `file_exists(path)` → bool (sugar for `file_info(path).exists`) — requires `file.read`
- `grep(target, pattern, opts?)` → `{matches: [{file, line, col, text}], truncated}` — requires `file.read`. Searches **per line** (streams, never loads the whole file). `target` = file or directory (recursive). **Literal by default**; `opts`: `{regex, ignore_case, glob, max_results}` (`glob` filters filenames; `truncated:true` when `max_results` is hit). `line`/`col` are 1-based.
- `edit_file(path, old, new, replace_all?)` → `{replaced: N}` — requires `file.write`. Exact-string replace; `old` must be **unique** (errors: `pattern not found` / `ambiguous, N occurrences`). `replace_all:true` replaces all. Atomic (temp+rename).
- `append_file(path, content)` → bool — requires `file.write`. Appends to the end (creates the file + parent dirs). `content` bytes = raw, else text. Real append (not a full rewrite).
- `run(cmd, args_list?, timeout?, opts?)` → `{exit_code, stdout, stderr, stdout_truncated, stderr_truncated}` — requires `exec("<cmd>")`. Runs a process **without a shell** (args as a list → no quoting injection). `timeout` default 120s → on expiry kills the process and **raises** (`timed out after Ns`); catch with `try`/`recover`. `opts`: `{cwd, env (inherits environ + overrides), stdin (text/bytes), max_output (default 10MB)}`. **Non-zero `exit_code` is data, not an error**; can't-launch and timeout raise. `exec` is deny-by-default (not auto-granted, even in `run`). Scope = the command string as passed.
- `now()` → unix timestamp (number) — requires `time`
- `sleep(seconds)` → pause execution (e.g. to pace an SSE stream) — requires `time`
- `format_time(timestamp, pattern?)` → text — requires `time`. Default ISO-8601 UTC (`format_time(0)` → `"1970-01-01T00:00:00Z"`); with a strftime pattern: `format_time(t, "%Y-%m-%d %H:%M")`
- `parse_time(text, pattern?)` → timestamp — requires `time`. Inverse of `format_time` (ISO-8601 by default; a trailing `Z` is accepted; times are UTC)
- `date_parts(timestamp)` → `{year, month, day, hour, minute, second}` (UTC) — requires `time`
- `random()` → float 0-1
- `random_int(min, max)` → integer

## HTTP
Both `http://` and **`https://` (TLS)** are supported (rustls + OS root CAs, real cert validation). **All HTTP (`http*` and `fetch`) is gated by `net(host)`** — `require net("host")` (deny-by-default, even in `run`; `require net` / `net("*")` = any). See capabilities.md.
- `http(method, url, headers?, query?, body?, timeout?)` → response map {status, ok, body, json, headers, error}
- `http_get(url, headers?, query?)` → response map
- `http_post(url, body, headers?)` → response map
- `http_put(url, body, headers?)` → response map
- `http_delete(url, headers?)` → response map

## Database
Opened with `db_open`, routed by target. SQL family (SQLite/Postgres/MySQL) + document family (MongoDB) +
key-value family (Redis). Scope of `require db(...)` for remote URLs is the canonical `scheme://host/db`.
Wrong family on a connection errors clearly.
- `db_open(path, mode?)` — file path / `postgres://` / `mysql://` / `mongodb://` / `redis://`. mode (SQLite only): "readwrite" (default), "readonly", "memory"
- `db_close(path?)` — close connection

### SQL (SQLite / Postgres / MySQL)
- `sql(query, params?)` → list of row maps (SELECT)
- `sql_exec(statement, params?)` → {rows_affected, last_id} (INSERT/UPDATE/DELETE/CREATE).
  `last_id`: SQLite rowid; MySQL `last_insert_id()`; Postgres `0` (use `RETURNING`).
- `sql_batch(statement, params_list)` → {rows_affected} (batch operations)
- `sql_tables()` → list of table names
- Placeholders: `?` everywhere (Postgres rewrites to `$n` internally; MySQL uses `?` natively)
- `paged(query, params?)` → paginated result for `give` in a (non-streaming) serve route (SQL LIMIT/OFFSET pushdown, exact COUNT total)

### MongoDB (`mongodb://`) — documents/filters are maps ↔ BSON
- `mongo_find(coll, filter?, opts?)` → list of docs. opts: `{limit, skip, sort: {f: 1/-1}, fields: {f: 1}}`
- `mongo_find_one(coll, filter?)` → doc map, or `nothing`
- `mongo_insert(coll, doc)` → the `_id` (text hex if ObjectId)
- `mongo_insert_many(coll, docs_list)` → list of `_id`
- `mongo_update(coll, filter, update)` → {matched, modified}. `update` uses operators (`{"$set": …}`)
- `mongo_delete(coll, filter)` → {deleted}
- `mongo_count(coll, filter?)` → number
- `mongo_aggregate(coll, pipeline_list)` → list of docs
- `mongo_collections()` → list of collection names

### Redis (`redis://` / `rediss://`) — key-value/cache/structures + TTL + distributed lock
Values are byte-strings: returns `text` if UTF-8 else `bytes`; integers → `number`. **Arg types accepted:
text/bytes/number (else error → use `json_encode`).** db-index gotcha: `redis://host:6379` → scope
`redis://host` (no `/0`); `redis://host:6379/0` → scope `redis://host/0` (different).
- `redis_get(key)` → text/bytes or `nothing`; `redis_set(key, val, ttl_secs?)` → `nothing`
- `redis_del(key...)` → number; `redis_exists(key...)` → number
- `redis_mget(keys_list)` → list (each text/bytes/`nothing`); `redis_mset(map)` → `nothing`
- `redis_keys(pattern)` → list of text (KEYS is O(N)); `redis_type(key)` → text ("string"/"hash"/…)
- `redis_incr(key)` / `redis_decr(key)` → number; `redis_incrby(key, n)` → number (atomic)
- `redis_expire(key, secs)` → bool; `redis_ttl(key)` → number (`-1` no TTL, `-2` absent); `redis_persist(key)` → bool
- `redis_hget(key, field)` → text/bytes or `nothing`; `redis_hset(key, map)` → number (new fields)
- `redis_hgetall(key)` → map; `redis_hdel(key, field...)` → number; `redis_hincrby(key, field, n)` → number
- `redis_lpush(key, val...)` / `redis_rpush(key, val...)` → number (new length)
- `redis_lpop(key)` / `redis_rpop(key)` → text/bytes or `nothing`; `redis_lrange(key, start, stop)` → list; `redis_llen(key)` → number
- `redis_sadd(key, member...)` / `redis_srem(key, member...)` → number; `redis_smembers(key)` → list; `redis_sismember(key, member)` → bool
- `redis_lock(key, ttl_ms?)` → token (text) or `nothing` if held (SET NX PX, default ttl 30000ms)
- `redis_unlock(key, token)` → bool (frees only if the token matches, atomic Lua)
- Structured data: `redis_set(k, json_encode(...))` / `json_decode(redis_get(k))`
- `_id` reads as text hex; a 24-hex string under `_id` in a filter is coerced to an ObjectId

## HTTP server (serve) — see serve.md
Response helpers (set the HTTP status; body follows the response contract):
- `ok(x)` → 200
- `created(x)` → 201
- `not_found(x)` → 404 — `not_found(text)` → `{"error": text, "status": 404}`; `not_found(map)` → the map as-is
- `fail(code, msg)` → `{"error": msg, "status": code}`; also `fail(msg)` → 400, and `fail(code)`
- `html(content)` → 200, `text/html; charset=utf-8`, raw body (no JSON encoding)
- `respond(content, content_type, status?)` → raw body with an arbitrary content-type and optional status
- `render(template_path, data?)` → `text/html` from a template file. A hole `{ x }` is a **data field** (a single name — even a reserved word like `type`) or an **expression** (`{ format_time(created) }`, your own tasks included). Values are auto-escaped (XSS-safe); `{ raw expr }` opts out; **`{ raw }`…`{ end }` is a VERBATIM block (inline CSS/JS with literal braces)**; `{ each x in xs }…{ otherwise }…{ end }` (empty branch; `enumerate(xs)` for indexes) and `{ when c }…{ otherwise when c2 }…{ otherwise }…{ end }` reuse Synsema flow; `{ include "p" [with {props}] }`, `{ layout }`/`{ slot }`/`{ slot "name" }`+`{ fill "name" }` compose; `{ -- comment }`. Parsed templates are cached (mtime-invalidated → hot-reload per request). cwd-relative + traversal-blocked; `render("literal")` templates are validated at startup (recursively, includes/layouts too) and by `synsema check`; errors carry `file:line`. See serve.md and [frontend.md](frontend.md).
- `form of request` → parsed form body (urlencoded → `{field: text}`; multipart → text fields + files as `{filename, content_type, data: bytes}`; no form body → empty map) — inside a route handler. See serve.md.
- `read_body()` → full request body **text** (lossy for non-UTF-8) — inside a route handler
- `read_body_bytes()` → full request body as `bytes` (byte-exact, for binary uploads) — inside a route handler
- `binary(bytes, content_type?, status?)` → a binary response (default `application/octet-stream`, 200). Also `give bytes(...)` directly → octet-stream.
- **Shared state across requests** (serve): `state_set(key, value)`, `state_get(key, default?)`, `state_incr(key, delta?)`, `state_delete(key)`, `state_all()` (snapshot map of every key) — an in-memory store shared across all handlers/requests (a `set` on a global does NOT persist across requests). See serve.md.

### Semantic content (negotiated HTML / Markdown / JSON — see serve.md)
- `content(tree)` → a negotiable response: HTML (default), Markdown (`Accept: text/markdown` or `.md`), or JSON (`.json`). Opt-in; only `content()` is negotiated.
- `page(nodes, meta?)` → document root; `meta` map (`title`, `description`) feeds `<head>` + JSON-LD
- `heading(level, text)`, `prose(text)`
- `list(items)`, `ordered_list(items)` — items may be text or nodes
- `link(text, href)`, `image(src, alt)`
- `section(nodes)`, `code(text, lang?)`
- `raw(html)` → raw HTML escape hatch (NOT auto-escaped); everything else in HTML output IS auto-escaped (XSS-safe)
- `chart(kind, data, opts?)` → a **negotiated chart node**: HTML = inline SVG, Markdown = a data table (agents get the NUMBERS), JSON = structured series. Same args as `chart_svg`. See [dataviz.md](dataviz.md).

### Charts (pure — no capability; see [dataviz.md](dataviz.md))
- `chart_svg(kind, data, opts?)` → **plain SVG text** (embed with `{ raw ... }`, serve with `respond(svg, "image/svg+xml")`, save with `write_file`). `kind`: `"bar"`/`"line"`/`"pie"`/`"scatter"`. Data: list of maps + `{x, y}` opts (rows from any source), map label→value, list of numbers, `[x,y]` pairs, or 1-D `array`. Opts: `title`, `x`/`y` (multi-series: `y` as list), `x_label`/`y_label`, `width`/`height`, `colors` (replaces the palette), `legend`, `background`. Deterministic; XSS-safe; colorblind-safe 8-color palette in fixed order — **>8 series/slices without custom `colors` → error** (colors are never cycled); NaN/inf in plotted values → error.

### PNG / PDF export (pure — no capability; see [dataviz.md](dataviz.md))
- `svg_to_png(svg, opts?)` → PNG **bytes** from ANY SVG text (deterministic: embedded font, no system fonts). Opts: `width`/`height` (one keeps aspect), `scale`, `background` (hex), `max_pixels` (overridable anti-DoS ceiling, default ~16.7M). External `<image href>` never fetched (no net/disk); `<script>` ignored; `secret` → error.
- `svg_to_pdf(svg, opts?)` → single-page **vector** PDF bytes. Opts: `width`/`height` in points (both must match the SVG aspect ratio). Compose: `write_file(path, b)`, `give binary(b, "image/png"|"application/pdf")`.

## Cron (Scheduled Tasks)
- `cron_every(seconds, task)` → job name (repeating; executes the task for real; interval must be > 0; task must take 0 params and exist at top level — validated at registration)
- `cron_after(seconds, task)` → job name (one-shot; delay ≥ 0; same validation)
- `cron_cancel(name)` → bool
- `cron_list()` → list of `{name, interval, repeating, active, run_count, errors}` — run_count = completed runs, errors = failed ticks (real counts, never phantom)
- `cron_status()` → formatted text

## Agentic apps — `select`, live processes, event bus, agent control (engine v0.6.7+)

One wait for everything (no capability; handles from `ws_connect`, a `socket` route, `proc_spawn`, `bus_subscribe`):
- `select(targets, timeout?)` → first ready event tagged `source` (`"ws"`/`"proc"`/`"bus"`), `handle`, `name` (map form); `nothing` at timeout / all gone. `targets` = list of handles or map name → handle. See [concurrency.md](concurrency.md).

Live processes (gated by `exec(cmd)` like `run`; see [processes.md](processes.md)):
- `proc_spawn(cmd, args?, opts?)` → handle. `opts`: `cwd`, `env`, `line_mode` (true), `stderr` (`"separate"`|`"merge"`), `max_queue` (4096), `max_queue_bytes` (64 MiB), `on_full` (`"block"`|`"drop_oldest"`|`"error"`)
- `proc_recv(h, timeout?)` → `{type: "stdout"|"stderr"|"exit", data}` or `nothing`; `proc_select(list|map, timeout?)`
- `proc_send(h, text|bytes)` → true (blocking write); `proc_close_stdin(h)`
- `proc_status(h)` → `"running"|"exited"|"killed"|"closed"`; `proc_stats(h)` → `{pid, cmd, status, exit_code, queued, queued_bytes, dropped, uptime}`
- `proc_kill(h, "TERM"|"KILL"?)`; `proc_wait(h, timeout?)` → `{exit_code, signal}` or `nothing`; `proc_close(h)` (kills if alive; no orphans)

Event bus — one per program, in-process fan-out, no capability (see [agents.md](agents.md)):
- `bus_publish(topic, value)` → subscribers reached (literal topic; data only — a task/secret errors)
- `bus_subscribe(topic|[topics], opts?)` → handle; globs `*`/`?`; `opts`: `max_queue` (1024), `max_queue_bytes` (16 MiB), `on_full` (`"drop_oldest"` default | `"error"`)
- `bus_recv(sub, timeout?)` → `{type: "event", topic, data, timestamp}` or `nothing`; `bus_unsubscribe(sub)`; `bus_topics()` → `[{topic, subscribers}]`

Agent control (no capability; `run` and `serve`):
- `agents()` → `[{id, name, state, error, started_at, finished_at}]`; `agent_stop(id, reason?)` → bool (cooperative cancellation → state `stopped`)

Inside a `socket` route the binding `socket` is a WS handle: `ws_send`/`ws_recv`/`ws_select`/`ws_stats` (`role: "server"`)/`ws_close` all apply — [serve.md](serve.md) § WebSocket routes.

## Agent operations

**All of these require the declared-memory capability** — `require memory("name")` at the
top of the program (deny-by-default, even under `run`; the name keys the `.db` file). See
[memory.md](memory.md).

- `create_progress(task_name, [step_names])` → task_name
- `start_step(task_name, step_name)` → bool
- `complete_step(task_name, step_name, result?)` → bool
- `fail_step(task_name, step_name, error?)` → bool
- `resume_point(task_name)` → step name or nothing
- `progress_display(task_name)` → formatted text
- `progress_percent(task_name)` → number 0-100
- `remember(category, content, tags?)` → entry_id. Inside `agent X` the entry's `source` is `"X"`; top-level writes `"main"`.
- `recall(category?, tags?, search?, mode?, limit?, from?)` → list of entries. `mode` (text) controls multi-tag matching: `"any"` (default, OR) or `"all"` (AND — entry must have every tag). `limit` (number) caps results (default 200). `from` (text) picks the `source` namespace: inside an agent the default is its OWN entries; `from = "other-agent"` crosses, `from = "*"` reads all; top-level defaults to all. All six accept named-arg form (`recall(from = "writer", limit = 10)`); pass `nothing` to skip a positional arg. See memory.md.
- `forget_memory(entry_id)` → bool
- `add_rule(name, level, description, category?)` → bool
- `check_rules(category?, context_map?)` → list of violations
- `get_rules(category?)` → list of rules
- `memory_summary()` → formatted text
