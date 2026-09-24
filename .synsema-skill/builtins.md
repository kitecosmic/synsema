# Synsema Built-in Tasks

> **This file is dense — jump to the `## ` section you need instead of reading it all:**
> Core · Error handling (`try`/`recover`/`raise`) · **Renamed in v0.6.29** (old → new names) · Strings · Regex · Bytes / binary (hashing,
> blockchain encoders, WebSocket client) · JSON · CSV · Math · Numeric arrays + linear algebra ·
> Assertions / tests · Config & secrets · Web auth (passwords, JWT, TOTP) · Agent identity & auth ·
> Spend ledger · Intentional operations (replace loops) · I/O · HTTP · Database ·
> HTTP server (serve) · Cron · Agent operations

## Core
- `print(values...)` — output text. Under `synsema run` each line is written **immediately** (v0.6.29+; before, it was held until the end); `test`/`serve`/`conform`/`--format json` still collect it. Inside a list or map, text is shown **quoted** (v0.6.29+): `print(["1", 1, {"a": "b"}])` → `["1", 1, {a: "b"}]` (keys stay bare); a top-level `print("x")` is unchanged (`x`). `text(list)` renders the same way.
- `length(collection)` → number
- `text(value)` → string conversion (integers show no decimal: `text(42)` → `"42"`)
- `int(x)` / `int(x, default)` → **exact integer** (v0.6.29+). Accepts an integer; text with optional sign and `_` between digits (`int("-42")`, `int("1_000")`); `0x…`/`0X…`/`0b…` text (leading zeros fine: `int("0x0000…1f18")` → `7960`); a float/decimal whose value is whole (`int(3.0)` → `3`). Big values stay exact (`int("123456789012345678901")`). **Errors:** `int(1.5)` → `not a whole number — round it on purpose: floor/round/trunc`; `int("1.5")` → `Cannot convert`; bytes → use `bytes_to_int`. With the 2nd argument it returns `default` instead of raising. ⚠️ **There is no base argument**: `int("ff", 16)` returns **16** (the total form — 16 is the default); write `int("0xff")`.
- `number(value)` → numeric conversion (always float: `number("42")` → `42.0`). An integer text beyond ±2^53 → **error naming `int`** (v0.6.29+; it used to round silently) — use `int(x)`; `number(x, default)` returns the default in that case.
- `hex(x)` → text (v0.6.29+). An integer ≥ 0 → the EVM **quantity** form, no leading zeros (`hex(7960)` → `"0x1f18"`, `hex(0)` → `"0x0"`); `bytes` → the **data** form with every byte (`hex(bytes([0, 255]))` → `"0x00ff"`). Negative / float / text → error. Round trips: `int(hex(n)) == n`, `bytes(hex(b), "hex") == b`.
- `is_integer(x)` (exact integers only — `is_integer(1.0)` → `false`), `is_text(x)`, `is_list(x)`, `is_map(x)` → bool (v0.6.29+; `is_bytes`/`is_decimal`/`is_complex`/`is_array` already existed).
- `floor(x)` → **integer** rounded toward −∞ (`floor(3.7)` → `3`, `floor(-3.7)` → `-4`)
- `ceil(x)` → **integer** rounded toward +∞ (`ceil(3.2)` → `4`, `ceil(-3.2)` → `-3`)
- `trunc(x)` → **integer** rounded toward zero (`trunc(3.7)` → `3`, `trunc(-3.7)` → `-3`)
- `round(x)` → nearest **integer**; ties round to the **even** value (banker's rounding, like Python's `round`): `round(2.5)` → `2`, `round(3.5)` → `4`. A non-number errors. These four are **pure** (no capability), and an already-integer argument is returned unchanged.
- `append(list, item)` → new list with item added — `set xs to append(xs, x)` (and `set xs to xs + [...]`) is **O(1) amortized** when nobody else holds the list (v0.6.29+: 100k appends went from minutes to under a second). Lists/maps have value semantics, so a copy someone kept is never changed — see [types.md](types.md) § Values.
- `keys(map)` → list of keys
- `enumerate(list)` → `[{index, item}, …]` — indexed iteration in the language AND in templates (`each e in enumerate(xs)` → `e.index` / `e.item`). Pure; non-list → error.
- `values(map)` → list of values
- `items(map)` → `[{key, value}, …]` in insertion order (v0.6.29+): `items({"x": 1})` → `[{key: "x", value: 1}]`
- `get(map, key)` / `get(map, key, default)` → the value, or `nothing` / `default` when the key is missing (v0.6.29+ — Python's `d.get`). Also lists: `get(xs, i, default)` (negative `i` counts from the end; out of range → default)
- `remove(map, key)` → a NEW map without `key` (v0.6.29+; the original is untouched)
- `merge(a, b, …)` → a NEW map, the rightmost value wins on a shared key (v0.6.29+): `merge({"a": 1, "b": 2}, {"b": 3, "c": 4})` → `{a: 1, b: 3, c: 4}`
- `sort(list)` / `sort(list, desc = true)` → a NEW sorted list (v0.6.29+). **Total, stable order**: numbers (exact, int vs float compared exactly), text by code point (`sort(["b", "a", "C"])` → `["C", "a", "b"]`), `false < true`, bytes and lists lexicographic; `nothing` and NaN go **last** in both directions (NaN before nothing). Mixed incomparable types → error `cannot order number and text together`; maps → error `… has no order`. `sort_by(list, key, desc = true)` uses the same order.
- `contains(collection, item)` → bool (lists/text/maps; also `bytes`: subsequence, or a single byte 0–255). The operator form is `item in collection` / `item not in collection` ([syntax.md](syntax.md))
- `split(text, separator)` → list. `split(text, "")` → the **characters** (Unicode scalars) — v0.6.20+ (before: an error)
- `reverse(list | text)` → a NEW list in reverse order; on text, the characters reversed (by Unicode scalar, not grapheme-aware) — v0.6.20+, pure. Anything else is a clear error
- `steps()` → number (v0.6.20+) — statements the interpreter executed so far in this program. Counts nodes, not time: the same program gives the same number every run (a deterministic cost for metering/tests/fuel-style limits). No capability (introspection, like `llm_usage()`), every profile. `run --format json` reports the total as `steps`
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list. Every argument must be an integer (`2.0` is fine): `range(0, 2.5)` / `range(0, 1, 0.25)` → error `… must be an integer, got …` (v0.6.29+)
- `type_of(value)` → text ("number", "decimal", "complex", "text", "bytes", "bool", "list", "map", "array", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection (lists/text/`bytes`; Python-style negatives)
- `length(x)` also works on `bytes` (byte count) and `array` (total elements). Indexing `x[i]` works on lists, maps, `bytes` (→ int 0–255), `array` (→ row or scalar) and — v0.6.29+ — **text** (`s[i]` = one character, counted like `length`). Negative indexes count from the end (`xs[-1]`, `b[-1]`, `"abc"[-1]` → `"c"`). An index must be an integer: `xs[1.7]` → `index must be an integer, got 1.7` (`xs[1.0]` is fine).
- **Calls check their arity** (v0.6.29+). A task or lambda called with too few arguments → `task 'f' is missing argument 'b' — pass it, or give the parameter a default`; too many → `task 'f' takes 1 argument, got 3`. A builtin given more than its maximum → `append() takes at most 2 arguments, got 3` (before, the extras were silently dropped — `trim(s, "x")`, `json_encode(x, 2)`, `upper("a", "b")`). Builtins take arguments **by position**: `f(x = …)` on one that has no named form → `f() does not accept named arguments (got x = …); pass it by position`. The named forms are the documented ones (`sort`/`sort_by` `desc = true`, `recall(from = …)`, …). Callbacks invoked BY a builtin or the host (`apply`/`where`/`reduce`, route handlers, cron, `errors with`) still receive what they get — the callback declares only what it uses.
- `raise(message)` → **always raises a runtime error** with `message` (coerced to text). Use it to fail deliberately, or to **re-propagate** a caught error inside `recover` (see below). `raise()` with no arg errors. (`fail(...)` is for HTTP responses, NOT for raising runtime errors.) The statement form **`raise "msg"` / `raise err`** (no parens) also works — it desugars to the same call — and a bare `raise` alone is a loud parse error. ⚠️ **On engine ≤ v0.5.1 the no-parens form silently did NOTHING** (it parsed as two inert expressions); on those binaries always use `raise("msg")`.
- `read_line(prompt?)` → text — read one line from stdin (CLI). Optional `prompt` is printed first (no newline; it's output, so under a `--cap-set` without `stdout` it's denied — v0.6.14+). Returns the line without the trailing newline; `nothing` on EOF. Works with a TTY **and** piped/redirected input (`printf 'x\n' | synsema run f.syn`) — unlike free-text `ask`. Under `synsema run` pending `print` output is already on screen before the prompt (v0.6.29+ writes each `print` immediately; older engines auto-flushed here), so a `read_line` loop is a real interactive REPL. It reads stdin in any mode. See [human.md](human.md).
- `flush()` → nothing — writes pending `print` output to stdout now. Since v0.6.29 `print` under `synsema run` is written line by line, so `flush()` only matters on older engines (where `print` was held until the program ended). Mode-aware: under `conform`/`test`/`serve` (which collect output for JSON/responses) it is a **no-op** — output stays collected, stdout is never polluted.
- `llm_available()` → bool — `true` when a real LLM provider is wired, `false` offline. Branch on it instead of string-matching placeholders. See [llm.md](llm.md).
- `judge_available()` → bool — a `judge` provider is wired (v0.6.25+). `judge_usage()` → input tokens the judge consumed in this process (output is free). `judge_model()` → the versioned model id that answered the last `judge` block (`"jev-1.13.0"`, never the alias) or `nothing`. No gate. See [judge.md](judge.md).
- `llm_usage()` → number — LLM tokens (input + output) consumed by this **process** so far; `0` offline. No capability (introspection). Pairs with `SYNSEMA_LLM_BUDGET` (ops degrade to a `[llm budget exceeded: …]` marker at the ceiling — never an error). See [llm.md](llm.md).
- `args()` → list of text (v0.6.14+) — the program's own argv: what follows `--` in `synsema run prog.syn -- a b` (→ `["a","b"]`), positionals after the path, or the whole argv of a `synsema build` binary. **No capability** (input the caller typed, not a host resource). Empty under `synsema test` and in the browser wasm.
- `self_path()` → text (v0.6.14+) — this executable's path, exactly as the OS gives it (`\` on Windows). Pass it verbatim to `run`/`proc_spawn` — the `exec` scope matches byte-for-byte. **No capability** (identity, not access). Under `--profile pure`/wasm: errors (`no process`).
- `platform()` → `{os, arch}` (v0.6.18+) — `"windows"` / `"macos"` / `"linux"` (other OSes as Rust names them), `"x86_64"` / `"aarch64"`; `"wasm"` / `"wasm32"` in the browser build. **No capability**; the same answer under `--sandbox` and `--profile pure` (a fact of the binary, like `args()`). Use it to pick `cmd` / `open` / `xdg-open` at run time — never `env("OS")` or a `self_path()` suffix.
- `shutdown(reason?)` → nothing (v0.6.18+) — asks the running server for its **ordered drain** (listener closed, in-flight work drained, cron/agents stopped, exit 0) from a route, a `socket` block, a cron job or an agent. Log: `[serve] shutdown requested by the program: <reason>`. Idempotent. **Errors** under `synsema run` (a run program ends with its top level — `stop` leaves a loop or a task) and before anything listens (`nothing is running yet`); a `secret` reason is refused (it goes to the log). **No capability** (quitting is not a host resource). Under wasm: `not available in the pure profile`.
- `run_program(source, opts)` → map (v0.6.14+) — **requires `sandbox_run`**. Runs another Synsema program in a **child process of the same binary** under a ceiling = `opts.ceiling ∩` the parent's — the child can never exceed the parent. `opts` (all optional): `ceiling` (`--cap-set` syntax, or `"sandbox"`/`"none"`; default `"sandbox"`; v0.6.28+ also the **map returned by `captoken_verify`** or a `{capability: scopes}` map — the child then runs under that token's authority, with `stdout`+`time` kept unless the token says `deterministic`), `profile` (`"native"`/`"pure"`, default `"pure"`, never above the parent), `env` (map — **replaces** the child's environment; a `secret` value is an error), `timeout` (seconds, default 30; on expiry kills the child tree), `cwd`, `filename`. Returns `{ok, output:[lines], errors:[text], audit:[entries], exit:n|nothing, timed_out:bool, llm_tokens:n}` — the audit is a **value**, not a log to parse. Asking for more than the parent lends is trimmed (parent audit: `above parent ceiling`), not fatal. Recursion allowed if the child holds `sandbox_run` (depth `SYNSEMA_RUN_PROGRAM_MAX_DEPTH`, default 4). See [processes.md](processes.md).

## Error handling — `try` / `recover` / `raise`
```synsema
try
    risky()
recover err
    log "failed: " + err          -- err is the error message (text)
    raise(err)                    -- RE-PROPAGATE so the caller/agent sees a real failure
```
Without `raise`, `recover` **swallows** the error (the task/agent ends normally — DONE). With
`raise(err)`, the error propagates again (an agent ends in **ERROR**, not DONE). `give`/`stop` are
not errors and pass through `try/recover` untouched.

## Renamed in v0.6.29 (old names work until v1.0; `synsema check` warns)

The old name is a **deprecated alias**: it still runs (a program that uses one prints a single
warning on stderr when it loads), `synsema check` flags every use, and it goes away in v1.0. Write
the new name. Blockchain follows `<family>_<action>` (Bitcoin already did: `btc_tx`/`btc_tx_raw`/
`btc_send`/`btc_wait`).

| Old | New | Note |
|---|---|---|
| `replace_text` | `replace` | same shape |
| `find_all` | `regex_find_all` | same shape |
| `replace_re` | `regex_replace` | same shape |
| `capture` | `regex_capture` | ⚠️ **different shape**: `regex_capture` is ALWAYS a list — the groups, or `[match]` without groups — or `nothing`; the old `capture` keeps returning the bare match text without groups |
| `fold` | `fold_text` | lowercase + strip accents (not Python's `casefold`) |
| `eye` | `identity` | numeric arrays |
| `hmac_sha256(data, key)` → hex text | `hmac(data, key, algo?)` → **bytes** | ⚠️ different result type: `hex(mac)` to show it (`"0x…"`) |
| `eth_rpc` · `eth_nonce` · `eth_balance` · `eth_gas_price` · `eth_chain_id` · `eth_estimate_gas` · `eth_call` · `eth_fee_history` | `evm_rpc` · `evm_nonce` · `evm_balance` · `evm_gas_price` · `evm_chain_id` · `evm_estimate_gas` · `evm_call` · `evm_fee_history` | the JSON-RPC **method** names you pass to `evm_rpc` stay `"eth_call"`, `"eth_getLogs"`, … |
| `eth_send_raw` · `eth_receipt` · `eth_wait_receipt` · `eth_address` | `evm_send` · `evm_receipt` · `evm_wait` · `evm_address` | |
| `tx_eip1559` · `tx_eip1559_raw` | `evm_tx` · `evm_tx_raw` | contract creation is `evm_tx_create` |
| `solana_message` (builds) | `solana_tx` | the NEW `solana_tx(params)` builds the message |
| `solana_tx(message, signatures)` (assembles) | `solana_tx_raw(message, signatures)` | the old 2-argument `solana_tx` form → error pointing to `solana_tx_raw` |
| `solana_confirm` | `solana_wait` | |
| `algorand_tx_encode` (bytes to sign) | `algorand_tx` | the NEW `algorand_tx(txn)` returns the bytes to sign |
| `algorand_tx(txn, sig)` (signed) | `algorand_tx_raw(txn, sig)` | the old 2-argument `algorand_tx` form → error pointing to `algorand_tx_raw` |
| `algo_address` | `algorand_address` | |

Unchanged on purpose: `matches`, `find_first`, `read_file(path, line, limit)` (1-based line).

## Strings
- `fmt(template, map)` → interpolated text: `fmt("Hi {name}", {"name": "Alice"})` → `"Hi Alice"`. **Strict** (v0.6.29+): a `{name}` with no value in the map → error `fmt: no value for {a} — pass it in the map, or write {{a}} for a literal brace`; `{{` / `}}` are literal braces; braces that do not surround a name stay literal (JSON/CSS pass through: `fmt("{a} {\"k\": 1}", {"a": 1})` → `1 {"k": 1}`)
- `upper(text)` → uppercase
- `lower(text)` → lowercase
- `fold_text(text)` (was `fold`) → lowercase **and** strips accents/diacritics — for accent-insensitive matching: `fold_text("Continúa")` → `"continua"`, `contains(fold_text("Está aquí"), "esta")` → true. Not Python's `casefold`
- `trim(text)` → strip whitespace
- `starts_with(text, prefix)` → bool
- `ends_with(text, suffix)` → bool
- `replace(text, old, new)` (was `replace_text`) → text with literal replacements
- `index_of(text, piece)` → the **character** position of the first occurrence, or `nothing` (v0.6.29+): `index_of("héllo", "llo")` → `2`. (On a list, see Intentional operations)
- `text + x`: text + number/bool concatenates (`"n=" + 1` → `"n=1"`); text + `nothing`/list/map/bytes → **error** (v0.6.29+) `Cannot add text and nothing — convert it on purpose: text(x), or interpolate it`
- `strip_ansi(text)` → plain text out of terminal output: CSI/OSC/charset escapes and control bytes removed (`\n`/`\t` kept), `\r` redraws keep the last frame (`"10%\r100%\r\n"` → `"100%\n"`). Pure; pairs with `proc_spawn(..., {pty: true})` (processes.md)

## Regex (pure — no capability)
- `matches(text, pattern)` → bool — **full match**: true only if the *whole* text matches. Built for validation, so an unanchored pattern is already safe (`matches("12345", "[0-9]+")` → true, `matches("a 5 b", "[0-9]+")` → false). For "does the pattern appear somewhere", use `regex_find_all`/`regex_capture`.
- `regex_find_all(text, pattern)` (was `find_all`) → list of every whole match, in order (partial search): `regex_find_all("a1b2", "[0-9]")` → `["1", "2"]`
- `regex_capture(text, pattern)` (v0.6.29+) → the first match (partial search) as **always a list**: the group values with groups (`regex_capture("2026-09", "([0-9]+)-([0-9]+)")` → `["2026", "09"]`), `[match]` without groups (`regex_capture("hello world", "w[a-z]+")` → `["world"]`); no match → `nothing`. (The deprecated `capture` returned the bare text `"world"` without groups, and still does.)
- `regex_replace(text, pattern, replacement)` (was `replace_re`) → text (`\1`/`\2` backreferences supported)
- ⚠️ A pathological pattern can be slow (ReDoS) — don't feed untrusted input as a *pattern* without care.

## Bytes / binary (pure — no capability)
- `bytes(text)` → utf8 bytes; `bytes(text, "hex"|"base64"|"base64url"|"base58"|"base32")` → decode; `bytes([72,73])` → from ints 0–255; `bytes(bytes)` → identity. `bytes(secret)` → **error** (plaintext never materializes). `"hex"` accepts an optional `0x`/`0X` prefix (v0.6.29+: `bytes("0x00ff", "hex")` works); an odd length is still an error — for a quantity like `"0x9"` use `int("0x9")`. base58 = Bitcoin/Solana; base32 = RFC 4648 (Algorand); base64url = URL-safe `-_` (JWT/tokens; accepts input with or without `=` padding). `bytes + bytes` = concat.
- `decode(b)` / `decode(b, "utf8")` → text (UTF-8 **strict**, errors on invalid); `decode(b, "utf8_lossy")` → with `U+FFFD`; `decode(b, "hex"|"base64"|"base64url"|"base58"|"base32")` → text (base64url output is unpadded). (so `bytes(...)` ↔ `decode(...)` are inverses)
- `is_bytes(x)` → bool. `b[i]` → int 0–255 (`b[-1]` = last byte); `bytes + bytes` → concatenation; `length`/`slice`/`contains`/`in` work on bytes; `each x in b` walks the bytes as ints 0–255. `hex(b)` → `"0x…"` (every byte).
- `sha256(x)` / `sha512(x)` → **bytes** (raw digest). x: text → hashes utf8; bytes → raw. Hex via `decode(sha256(x), "hex")` (bare) or `hex(sha256(x))` (`0x`-prefixed). `sha256(secret)` → error.
- `keccak256(x)` / `sha512_256(x)` → **bytes(32)**. ⚠️ `keccak256` is PRE-NIST Keccak (Ethereum), NOT SHA3-256 (`keccak256("")`=`c5d24601…`). Same rules as `sha256` (secret → error).
- `bytes_to_int(b)` → non-negative integer from big-endian bytes, **exact** (empty → 0; 256-bit values never touch float). `int_to_bytes(n, size?)` → big-endian bytes: minimal without `size` (no leading zeros; 0 → empty), zero-padded to exactly `size` with it (error if it doesn't fit). Inverses. Use them to put a signature's r/s into RLP as integers.
- `int_to_bytes_le(n, size)` → **little-endian** bytes of exactly `size` (error if it doesn't fit; `size` is mandatory — LE is a fixed-width binary-struct format). E.g. Solana System-transfer data: `int_to_bytes_le(2, 4) + int_to_bytes_le(lamports, 8)`.

Blockchain — sign/verify/derive (all pure-Rust; see stdlib.md for the security model):
- `secp256k1_sign(digest32, secret)` → bytes(65) `r‖s‖v` — **requires `sign("NAME")`** + audit; RFC 6979 deterministic, low-s. digest must be exactly 32 bytes (keccak256 it first).
- `secp256k1_verify(digest, sig, pubkey)` → bool; `secp256k1_recover(digest, sig65)` → bytes(65) pubkey (ecrecover); `secp256k1_pubkey(secret, compressed?)` → bytes(33|65). Pure. **`secp256k1_sign` returns `v` (byte 65) as the raw recovery id, 0/1** — what go-ethereum's `crypto.Sign`, libsecp256k1 and typed EIP-1559 transactions use. Contracts (`ecrecover`, OpenZeppelin `ECDSA.recover`, EIP-2612 `permit`) and wallets (MetaMask / ethers / viem `personal_sign`, `signTypedData`) write it as **27/28**: `evm_signature(sig)` (v0.6.29+) → the same 65 bytes with `v` = 27/28 (idempotent — a 27/28 signature comes back unchanged; any other `v` → error). `secp256k1_recover` accepts `v` = 0, 1, 27 or 28 (v0.6.29+), so a wallet's signature goes in as-is; `v` ≥ 35 (EIP-155 legacy `chain_id*2+35`) → error that explains it. `secp256k1_verify` ignores `v`.
- `evm_signature(sig65)` → bytes(65) with `v` = 27/28 (v0.6.29+, pure) — the form a wallet, Solidity `ecrecover` and OpenZeppelin `ECDSA.recover` expect. Typed transactions (`evm_tx_raw`) want the raw 0/1 — pass the `secp256k1_sign` output there, not this.
- `ed25519_sign(message, secret)` → bytes(64) — **requires `sign("NAME")`** + audit. ⚠️ signs the RAW message (do NOT pre-hash). `ed25519_verify(msg, sig, pubkey)` → bool (**strict**: rejects small-order keys/points, matching what Solana/Algorand accept); `ed25519_pubkey(secret)` → bytes(32). Pure.
- `evm_address(x)` (was `eth_address`) → EIP-55 checksummed text. `x` = a pubkey (bytes 33/65), a key `secret`, **20 raw bytes**, or a `"0x…"` 40-hex text (v0.6.29+; a mixed-case text is checksum-validated). `evm_create_address(sender, nonce)` → the address a CREATE deploys to (`keccak256(rlp([sender, nonce]))`); `evm_create2_address(deployer, salt32, init_code_hash32)` → the EIP-1014 CREATE2 address (`salt` must be 32 bytes). Both pure, EIP-55 text (v0.6.29+). `rlp_encode(value)` → bytes (bytes/non-neg int/list; text→error); `rlp_decode(bytes)` → value (**canonical-strict**: non-minimal encodings error, like Ethereum's decoders). `bech32_encode(hrp, data, variant?)` / `bech32_decode(text)`→`{hrp,data,variant}`. Pure.
- ABI (pure): `abi_encode(sig, values)` → bytes selector+args for a contract call (`abi_encode("transfer(address,uint256)", [addr, amount])`, 4 + 32·n bytes). **With types instead of a function signature** — `"(address,uint256)"`, `"uint256"` or a list of texts `["uint256"]` — it encodes **without a selector** (v0.6.29+): constructor arguments to append to init code, a log's `data`, the exact inverse of `abi_decode` (`abi_decode(t, abi_encode(t, v)) == v`). `abi_decode(types, data)` → list (`types` = `"(address,uint256)"` or list of texts; **strict**: hostile offsets / dirty padding / short-long data → error); `abi_selector(sig)` → bytes(4). Signature is CANONICAL: no spaces/param names (`uint`/`int` normalize to `uint256`/`int256`). Types: uint8..256, int8..256, address (EIP-55 validated if mixed-case; bytes(20) ok), bool, bytes1..32, bytes, string, T[], T[k], tuples `(…)`. uint256 amounts need EXACT integers (big ints fine; floats error — and `1e18` IS a float: write `10**18`).
- Events (pure, v0.6.29+): `abi_event_topic(sig_or_fragment)` → **text** `"0x…"` — the event's topic0, comparable with `log.topics[0]` (`abi_event_topic("Transfer(address,address,uint256)")` → `"0xddf252ad…b3ef"`; also takes the ABI fragment map). `abi_decode_log(event, log)` / `abi_decode_log(event, log, default)` → map **by parameter name**. `event` = the ABI JSON fragment `{name, inputs: [{name, type, indexed, components?}], anonymous?}` (as in a contract's ABI file); `log` = a map with `topics` and `data` (what `evm_receipt`/`evm_logs` return). **Strict**: topic0 must match the event, the topic count must match the indexed params, `data` decodes with no trailing bytes — otherwise an error (or `default`). An indexed dynamic value (string/bytes/array/tuple) comes back as its **bytes(32) keccak hash** (that is all the log carries); unnamed inputs are `arg0`, `arg1`, …
- EIP-191/712 (pure): `eip191_digest(message)` → bytes(32) personal_sign/SIWE digest; `eip712_digest(domain, types, primary_type, message)` → bytes(32) typed-data digest from READABLE maps (standard JSON shape: `{"Person": [{"name": "name", "type": "string"}, …]}`; nested structs, arrays, optional domain fields in fixed EIP order; missing/extra field → error naming it). Sign the digest with `secp256k1_sign` (no separate sign builtin — one gate only).
- Solana (pure): `solana_tx({fee_payer, recent_blockhash, instructions, version?})` (was `solana_message`) → message bytes ready for `ed25519_sign` (legacy default; `"version": 0` → v0, signature covers the 0x80 prefix; `lookup_tables` → clear error, stage 3). Accounts auto-ordered by runtime rules (payer first, then writable signers / ro signers / writable non-signers / ro non-signers, each sorted by pubkey bytes). Pubkeys: bytes(32) or base58 text. `solana_tx_raw(msg, sig_or_list)` (was the 2-argument `solana_tx`) → wire tx (validates count vs header) → `decode(tx, "base64")` for sendTransaction. The old `solana_tx(msg, sigs)` form now errors and points to `solana_tx_raw`.
- Solana PDA/SPL (pure): `solana_pda(seeds, program)` → `{address: bytes(32), bump: int}` (PDA/ATA addresses stay **bytes** on purpose — they re-enter as seeds and account keys) (findProgramAddress; off-curve, seeds are bytes/text ≤32, max 15). `spl_ata(owner, mint, token_program?)` → bytes(32) associated token account. `spl_transfer_data(amount)` → SPL Transfer ix data (tag 3 ‖ u64 LE); `spl_transfer_checked_data(amount, decimals)` → TransferChecked (tag 12, recommended).
- Algorand (pure): `algorand_tx(txn_map)` (was `algorand_tx_encode`) → `"TX"‖canonical msgpack` ready for `ed25519_sign` (protocol short keys: type/snd/rcv/amt/fee/fv/lv/gen/gh/note…; keys sorted, zero/empty/false fields OMITTED — required by the network; text addresses checksum-validated → bytes32). `algorand_tx_raw(txn_map, sig64)` (was the 2-argument `algorand_tx`; that old form now errors pointing here) → SignedTxn msgpack for POST `/v2/transactions` (`application/x-binary`). `algorand_address(pubkey_or_secret)` (was `algo_address`) → base32 text with checksum. TXID = `decode(sha512_256(algorand_tx(txn)), "base32")`.
- EIP-1559 builders (pure — no gate, nothing sent): `evm_tx({chain_id, nonce, to, value, gas, max_fee, max_priority, data?, access_list?})` (was `tx_eip1559`) → `{digest: bytes(32), fields, chain_id, nonce, to (EIP-55 text), value, gas, max_fee, max_priority}` — EVERY value-moving field is required (no silent defaults; missing → error naming the reader: `evm_chain_id`/`evm_nonce`/`evm_estimate_gas`/`evm_fee_history`); `max_priority > max_fee` → error; `access_list` = `[{address, storage_keys: [bytes32,…]}, …]`; unknown key → error; **no `to` → error pointing to `evm_tx_create`**. Sign `tx["digest"]` with `secp256k1_sign`, then `evm_tx_raw(tx, sig65)` (was `tx_eip1559_raw`) → signed raw bytes for `evm_send` (v/r/s assembled; a 27/28 v is rejected — typed txs use y-parity 0/1).
- **Contract creation** (pure, v0.6.29+): `evm_tx_create({chain_id, nonce, from, value, gas, max_fee, max_priority, data, access_list?})` → the same map as `evm_tx` with `to: nothing`, plus `from` and `contract_address` (EIP-55 — where the contract will live, `== evm_create_address(from, nonce)`). `data` is the init code (bytecode + `abi_encode(types, args)` for the constructor); **required**: a `to` key → error, empty `data` → error, `data` over 49 152 bytes (EIP-3860) → error. `from` is not decoration: `evm_tx_raw(tx, sig)` on a map that carries `from` **recovers the signer** and errors if it is not `from` (`the signature is from 0x…, but the creation declared from 0x…`) — so `contract_address` is computed from the account that actually signs (with the `nonce` you read via `evm_nonce`).
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
  - EVM (`evm_*`, formerly `eth_*`): `evm_rpc(url, method, params?)` → decoded JSON (escape hatch; int params → hex-quantity, bytes → `0x…`; the `method` is the node's JSON-RPC name, e.g. `"eth_getLogs"`); `evm_block_number(url)` → int (v0.6.29+); `evm_nonce(url, addr, block?)` → int (default `"pending"`); `evm_balance(url, addr, block?)` → exact wei int; `evm_gas_price(url)` / `evm_chain_id(url)` → int; `evm_estimate_gas(url, tx_map)` → int; `evm_call(url, {to, data}, block?)` → RAW bytes (feed `abi_decode`); `evm_fee_history(url, blocks?, percentiles?)` → `{base_fee (NEXT block), priority (median of first percentile col), base_fees, rewards}`; `evm_send(url, raw)` → `"0x…"` hash text; `evm_receipt(url, hash)` → typed receipt map (quantities int, addresses EIP-55, hashes `"0x…"`, log data bytes) or `nothing`; `evm_wait(url, hash, confirmations?, timeout?)` → receipt after N confs (1–1000, default 1) or `nothing` at timeout. `block?` = `"latest"` (default) | `"earliest"|"pending"|"safe"|"finalized"` | number | the node's own `"0x…"` quantity (v0.6.29+; validated canonical, ≤ 256 bits).
  - `evm_logs(url, filter)` → list of logs decoded like receipt logs (v0.6.29+) — feed each to `abi_decode_log`. `filter` uses the **wire names** and is validated: `address` (one or a list), `topics` (list; each entry a `"0x…"`/bytes32, `nothing` = any, or a list = OR), `fromBlock`/`toBlock` (same forms as `block?`) **or** `blockHash` (not both). Example: `evm_logs(url, {"address": token, "topics": [abi_event_topic("Transfer(address,address,uint256)")], "fromBlock": hex(evm_block_number(url) - 1000)})`.
  - Solana: `solana_rpc(url, method, params?)` → decoded JSON (plain-JSON params; raw bytes → error, encode explicitly); `solana_latest_blockhash(url)` → bytes(32) (feeds `solana_tx`); `solana_balance(url, pubkey)` → lamports int; `solana_send(url, tx_bytes)` → base58 signature text; `solana_wait(url, sig, timeout?)` (was `solana_confirm`) → `{slot, confirmations, confirmation_status, err}` (waits confirmed/finalized; `err != nothing` = landed but FAILED) or `nothing` at timeout; `spl_balance(url, owner, mint, token_program?)` → `{amount, decimals, ata}` (missing ATA → catchable ERROR, never a silent 0).
  - Algorand (algod REST; each takes a trailing `headers?` map — `X-Algo-API-Token` may be a `secret`): `algorand_params(url, headers?)` → `{fee (PER-BYTE), min_fee (flat 1000 µAlgo), fv, lv (= fv+1000), gh: bytes(32), gen}`; `algorand_account(url, addr, headers?)` → account map (checksum validated BEFORE the network); `algorand_send(url, signed_bytes, headers?)` → 52-char txid (binary `application/x-binary` POST handled); `algorand_wait(url, txid, timeout?, headers?)` → confirmed info map, `nothing` at timeout, ERROR on pool rejection (definitive).
  - Waiters are BOUNDED polls (like `ws_recv`): default timeout 60 s, `nothing` when it expires — never hang. A TRANSIENT failure mid-wait (transport error or HTTP 5xx) does NOT kill the wait: after a first successful poll the waiter retries by itself until the deadline (one `synsema: warning:` line on stderr — no agent action needed); if the deadline expires while the node is still failing, the ERROR surfaces (catchable, says "deadline expired during this failure") instead of `nothing` — "unconfirmed" and "node stopped answering" stay distinguishable. A dead node / wrong URL still fails fast on the FIRST poll; definitive answers (4xx, invalid JSON, node RPC errors, hostile decode) error immediately. Broadcasting is `net`-gated, not `sign`-gated (the signature already happened; `sign` stays the only value door).
- HD custody — **all require `wallet`**, all return a `secret` (mnemonic/seed/key NEVER materialize; audited in `wallet.log`; denied in `sandbox`):
  - `mnemonic_generate(words?, label?)` → secret (12/15/18/21/24 words, OS entropy); `mnemonic_to_seed(mnemonic, passphrase?)` → secret (64-byte BIP-39 seed, checksum-validated; mnemonic AND passphrase must be secrets — seal a value in hand with `as_secret(x, "LABEL")`); `mnemonic_from_entropy(entropy, label?)` / `mnemonic_to_entropy(mnemonic)` → secret.
  - `hd_derive(seed, path, curve?, label?)` → secret. `curve` = `"secp256k1"` (default, BIP-32; ETH `m/44'/60'/0'/0/i`) | `"ed25519"` (SLIP-0010, hardened-only; Solana `m/44'/501'/i'/0'`). Use the result directly with `evm_address`/`ed25519_pubkey`/`secp256k1_sign`.
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

## ECDH / HKDF / AES-GCM (pure except key generation — v0.6.20+)
WebCrypto names and shapes. Secrets stay `secret` (a derived key is USED — as the AES key — never printed).
- `ecdh_keypair(curve)` → `{private: secret, public: bytes}` — `curve` = `"P-256"` | `"P-521"` (anything else: clear error); public = SEC1 uncompressed point (65 / 133 bytes). **Requires `random`** (it creates a key — the gate of `random_bytes`).
- `ecdh_shared_secret(private, peer_public, curve)` → secret (the raw X coordinate, like WebCrypto `deriveBits`). Pure.
- `hkdf_sha256(ikm, salt, info, length)` → bytes (RFC 5869; a `secret` when `ikm` is one). Pure.
- `aes_gcm_encrypt(key, nonce, plaintext, aad?)` → bytes (ciphertext ‖ 16-byte tag) / `aes_gcm_decrypt(key, nonce, ciphertext, aad?)` → bytes. Key 16 bytes = AES-128-GCM, 32 = AES-256-GCM (else: `the key must be 16 bytes … or 32 bytes`); nonce 12 bytes, never reused with a key; auth failure → `authentication failed (wrong key, nonce, aad, or tampered data)`, never partial bytes — or the fallback, with the total form `aes_gcm_decrypt(key, nonce, ct, aad, default)` (below). Pure.

**Total variants — validating untrusted input without an exception (v0.6.24+).** Every parser below
takes one **extra last argument** that is returned *instead of raising*, so a malformed payload is a
value you test, not an error you catch:

```synsema
let d be json_decode(payload, nothing)     -- no error, so nothing to catch
when d == nothing
    give bad_request("malformed payload")
```

| operation | total form |
|---|---|
| `json_decode` | `json_decode(text, default)` |
| `number` · `decimal` · `float` · `int` | `number(value, default)` / `int(value, default)` |
| `aes_gcm_decrypt` | `aes_gcm_decrypt(key, nonce, ct, aad, default)` — `aad` goes explicit (may be `nothing`) so the fallback has a fixed slot |
| `toml_parse` · `bech32_decode` · `rlp_decode` | `f(x, default)` |
| `abi_decode` | `abi_decode(types, data, default)` |
| `abi_decode_log` | `abi_decode_log(event, log, default)` |

Why it exists, beyond convenience: **under `--labels` an error caused by private data cannot be
caught** (see [labels.md](labels.md)), so `try`/`recover` is not an option for input an enclave
receives from anyone. With no error there is no bit. Two details: the fallback is **evaluated
eagerly** (an effect inside it fires on the happy path too), and it never swallows a label
violation. Still without a total form: `parse_time`, `csv_parse`, `bytes(text, encoding)`,
`decode`, `psbt_decode` and key/index access — their arity is already variable, so the slot has to
be decided one by one.

## Attestation & confidential computing — see [attestation.md](attestation.md)

Proving **which code** produced an answer. Full contract, drivers, the `serve --attested` identity
and the `run --attest` artefact are in [attestation.md](attestation.md); the data half (`private` /
`declassify`) is [labels.md](labels.md).

- `attest(opts?)` → map. **`require attest`.** Asks the platform (AWS Nitro / TDX / SEV-SNP /
  dstack, plus a `mock` driver for CI that is never auto-detected) for a document binding
  `opts.report_data` (bytes, ≤ 64 — yours to choose) to the measurement of the running code.
  → `{format, document: bytes, driver, report_data, aux?, event_log?, root?}`.
- `attest_key(purpose)` → secret. **`require attest`.** A key the platform derives from the
  measurement, so another build cannot read what this one sealed. Raw Nitro/TDX/SEV-SNP do not seal
  keys and say so with an explicit error.
- `attestation_document()` → map (no capability) and `attestation_key()` → secret
  (**`require attest`**): the identity of the `serve --attested` you are running inside; outside
  that mode, a clear error. The key is **sealed** — `reveal()` refuses it even with `reveal`.
- `attestation_verify(doc, opts)` → map. Pure, no capability, no network. **`opts.now` (unix
  seconds) is mandatory**: an enclave has no trustworthy clock and a verdict must be reproducible.
  `opts.format` names the format, `opts.expect.measurements` compares PCRs. Verifies the COSE ES384
  signature and the whole X.509 chain against the **pinned** AWS Nitro root. `tdx`/`sgx`/`sev-snp`
  return an **explicit error** in this release, never an optimistic `true`.
- `groth16_verify(vk, proof, public_inputs)` → bool. Pure. A Groth16 proof over BN254, taking
  snarkjs's `verification_key.json` / `proof.json` / `public.json` as they are. An invalid proof is
  `false`; a dubious format is an error.
- `laplace_noise(seed, scale)` / `gaussian_noise(seed, sigma)` → float. Pure. Differential-privacy
  noise **deterministic in its seed** (not from `random()`): the same query over the same state
  gives the same noise, so repeating cannot average it away. You apply the snapping to the
  published sum yourself — see [attestation.md](attestation.md).

## JSON (pure — no capability)
- `json_encode(value)` → text: serialize any value to a JSON string. Maps/lists nest; **secret → `"[redacted]"`** (safe), `bytes` → base64 string, `decimal` (`1.50d`) → exact JSON number, `nothing` → `null`. ⚠️ NOT safe to embed inside a `<script>` tag — use `json_for_script` there.
- `json_for_script(value)` → text: same JSON but with `<`, `>`, `&` escaped as `\u00XX` — **the safe way to embed data in an inline `<script>`** (`{ raw json_for_script(x) }`); a value containing `</script>` cannot break out of the tag.
- `json_decode(text)` → value: parse a JSON string to a Synsema value (object→map, array→list, number→number, etc.). Integers of **any size stay exact** (v0.6.29+: `{"id": 12345678901234567890}`, a uint256 — they used to become floats); a number with `.` or an exponent is a float. Errors clearly on invalid JSON; `json_decode(text, default)` returns `default` instead (see **Total variants** above).
- Round-trippable: `json_decode(json_encode(x))` reconstructs `x` (the idiomatic way to store structured data in a Redis/text value: `redis_set(k, json_encode({...}))`).

## XML / TOML (pure — no capability — v0.6.20+)
- `xml_parse(text)` → map, **xmltodict convention**: an element is a map, attributes are `@name` keys, a text-only element IS its text, repeated children → a **list**, namespace prefixes kept (`cfdi:Emisor`); root = `{"<root tag>": {...}}`. Malformed → error with `line:col`. DTDs/external entities NOT processed (no XXE). No `xml_encode`.
- `toml_parse(text)` → map: tables → maps, arrays/`[[tables]]` → lists, ints/floats/bools → numbers/bools, **dates/times → ISO 8601 text** (no date type). Dotted keys, inline tables, multi-line strings OK.
- `toml_encode(map)` → text for JSON-like values; `nothing` refused (`TOML has no null — <key> is nothing (drop the key or give it a value)`), `bytes`/`secret` too.

## CSV (pure — no capability; see [dataviz.md](dataviz.md))
- `csv_parse(text, opts?)` → list of maps (first row = headers; the same shape `sql()` returns). RFC 4180 (quoted fields, `""` escapes, CRLF/LF, BOM). Opts: `{headers: false}` → list of lists, `{delimiter: ";"}`, `{numbers: true}` (default is **lossless text**: `"00123"` stays text). Errors carry the line (unclosed quote, uneven fields, duplicate headers, unknown option).
- `csv_encode(value, opts?)` → text. List of maps (headers = first map's keys) or list of lists. Opts: `{headers: [..]}` (order/subset), `{delimiter}`, `{eol}` (`"\r\n"` default). Minimal quoting; integers without decimals; `nothing` → empty; `bytes` → base64; **secret → `[redacted]`**; nested list/map → error suggesting `json_encode`.

## Math (pure — no capability)
Constants (bare values): `pi`, `tau`, `e`, `inf`, `nan`.
- magnitude/selection (type-preserving): `abs`, `sign`, `min`, `max`, `clamp`. `abs(complex)` → modulus. `min`/`max` (a list, or variadic `max(a, b, c)`) also take **texts** (all texts: `min(["b", "a"])` → `"a"`); `nothing` values are **skipped** as missing data (`min([3, nothing, 1])` → `1`); any NaN → the result is NaN; all values missing → error (v0.6.29+).
- floor division: the operator `a // b` (v0.6.29+) — exact for integers of any size, floors like Python (`-7 // 2` → `-4`, `7.5 // 2` → `3.0`); see [syntax.md](syntax.md). `a / b` is always float.
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
- **Construct:** `array(nested_list)`, `zeros(shape)`, `ones(shape)`, `full(shape, v)`, `arange(start, stop, step?)`, `linspace(start, stop, n)`, `identity(n)` (`eye(n)` is its deprecated alias). `shape` is an int or a list like `[2,3]`.
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
- `hmac(data, key, algo?)` → the MAC as **bytes** (v0.6.29+; was `hmac_sha256`, which returned hex text and is a deprecated alias). `key` may be a `secret` or text; show it with `hex(mac)` (`"0x…"`) or `decode(mac, "hex")` (bare hex, what `hmac_sha256` returned). `algo` = `"sha256"` (default) or `"sha512"` (SHA-1 is rejected). Not secret
- `verify_hmac(data, signature, secret, algo?)` → bool, constant-time. `algo` = `"sha256"` (default) or `"sha512"`; decodes hex/base64 signatures (Stripe/GitHub/Shopify). SHA-1 is rejected.
- `constant_time_eq(a, b)` → bool, constant-time; accepts a `secret` on either side

## Web auth (passwords, JWT, TOTP, CSPRNG)
`random_bytes`/`token` **require `require random`** — the same deny-by-default gate as
`random()`/`random_int()` (their purpose IS producing randomness; denied in `sandbox`).
The rest are pure transforms — no capability. Every key/password argument accepts a
sealed `secret`, text (raw UTF-8 bytes) or `bytes`; anything else is a clear error.

**Anything that reads the clock needs `require time`.** Ten builtins do: the verifiers
`jwt_verify`, `totp_verify`, `captoken_verify`, `captoken_attenuate`, `http_signature_verify` and
`oidc_verify`, the emitters `jwt_sign` (`iat`/`exp`), `captoken_mint` (`now`) and `http_signature`
(`created`), and `totp`. Plain `synsema run` and `--sandbox` grant `time` automatically, so you
only notice under a ceiling that does not — `--deterministic`, an explicit `--cap-set`, the guest
of an enclave — and there the error names both ways out:

```
jwt_verify: this needs the clock. Add `require time` to the program, or pass opts.now
explicitly (a unix timestamp in seconds) to verify against a clock you choose.
```

Passing the time explicitly is not a workaround, it is the right answer inside an enclave: a
machine with no trustworthy clock must take the verifier's, and a verdict computed from an
explicit timestamp is reproducible. (`attestation_verify` always requires `opts.now`, for the
same reason.)
- `random_bytes(n)` → n bytes from the **OS CSPRNG** (1–65536). Never use `random()` for anything security-related.
- `token(n?)` → unguessable base64url text of n random bytes (16–256, default 32 → 43 chars). Session ids, CSRF tokens, API keys, device codes.
- `password_hash(pw)` → PHC text (`$argon2id$v=19$m=19456,t=2,p=1$…`, OWASP params, random salt). Store this string as-is.
- `password_verify(pw, phc)` → bool (constant-time). Malformed/unknown PHC → **error**, not `false` ("wrong password" and "corrupt hash in DB" must never be confused).
- `jwt_sign(claims, key, opts?)` → token. Default **HS256** with a shared key. **`opts.alg = "RS256" | "ES256" | "EdDSA"`** (v0.6.20+; EdDSA v0.6.28+) signs with a **PEM private key passed as a `secret`** (PKCS#8 or PKCS#1 for RSA; PKCS#8 or SEC1 for P-256; PKCS#8 for Ed25519 — or the 32-byte ed25519 seed as hex text / bytes) — GitHub Apps, service accounts, agent-to-agent JWTs signed with the same key as your `did:key`. **EdDSA with a `secret` goes through `require sign("NAME")` + audit** (it is your identity key, the same gate as `ed25519_sign`/`document_sign`; a PEM or seed passed as text has no gate — the material is already visible); `opts.kid` goes to the header (for a did:key signer use `did:key:z…#z…`, the verificationMethod URL). The signer picks the algorithm, never the token; an unknown `alg` is an error (`supported: HS256, RS256, ES256, EdDSA`). Sets `iat` (your explicit claim wins); `opts.expires_in` (seconds) sets `exp` (passing both an `exp` claim and `expires_in` is an error). **Reads the clock → `require time`** (or pass it: `opts.iat` and `opts.exp` as explicit claims).
- `jwt_verify(token, key, opts?)` → claims map or `nothing` on ANY failure (bad signature, expired `exp`, future `nbf`, malformed, `alg` ≠ HS256 — the verifier pins the algorithm; `"none"`/`RS256` tokens are rejected). `opts.leeway` seconds (default 60). Verifying a third party's RS256/ES256 token is `oidc_verify` (below). **A public key you hold** goes as a map instead of a secret — `{"pem": public_key_pem}`, `{"jwks": document}` (text or map; `kid` selects) or (v0.6.28+) **`{"did": "did:key:z…"}`** (ed25519 → EdDSA, P-256 → ES256; resolved offline, no JWKS, no network — how you verify another server's Agent Card or an agent's JWT from its did) — and then the KEY fixes the algorithm (a P-256 key never verifies an EdDSA token, an RSA key never an ES256 one); a token that carries a `kid` must match the key's (`did:key:z…#z…` for a did). A did that cannot verify (x25519, secp256k1) is an error, not `nothing`. **Reads the clock → `require time`** (or pass it: `opts.now`, a unix timestamp in seconds).
- `rsa_sign_sha256(msg, pem_secret)` → bytes (PKCS#1 v1.5, 256 bytes for a 2048-bit key) / `rsa_verify_sha256(msg, sig, pub_pem)` → bool; `ecdsa_p256_sign(msg, pem_secret)` → bytes / `ecdsa_p256_verify(msg, sig, pub_pem)` → bool (v0.6.20+) — the raw primitives behind RS256/ES256. Pure, **no `sign` capability** (that gate is for moving value on-chain; here the key is already a `secret`).
- `totp(key, opts?)` → code text (defaults: sha1, 6 digits, 30 s — the Google Authenticator profile). Opts: `algo` (`"sha1"|"sha256"`), `digits` (6–8), `period`, `at` (unix ts, for deterministic tests). **Reads the clock → `require time`** (or pass it: `opts.at`).
- `totp_verify(key, code, opts?)` → bool (constant-time), `opts.window` = ±N periods (default 1). The code must be **text** (leading zeros matter). **Reads the clock → `require time`** (or pass it: `opts.at`).

```syn
require random                                      -- gates token()/random_bytes only

let phc be password_hash(pw)                        -- at signup
when password_verify(pw, stored_phc)                -- at login
    let sid be token()
let seed be random_bytes(20)                        -- TOTP enrolment
let uri be "otpauth://totp/App:user?secret=" + decode(seed, "base32") + "&issuer=App"
when totp_verify(seed, submitted_code)              -- 2FA check
```

## Web Push — installable apps notify their users (engine v0.6.15+)
Native **Web Push** (RFC 8030 protocol · RFC 8291/8188 `aes128gcm` encryption · RFC 8292 VAPID),
the same thing `web-push`/`pywebpush` do — no provider needed. A provider you already have
(OneSignal, FCM, Pusher Beams) still works: call its REST API with `http_post` under
`require net(...)`; nothing forces the native path. The browser side (service worker,
`pushManager.subscribe`, the install prompt) ships in `synsema init --pwa` — see
[serve.md](serve.md) § Installable app (PWA).

- `push_vapid_keys()` → `{public, private}` — a fresh P-256 pair. **`require random`** (it creates
  secret material, like `token()`). `public` is base64url text (65-byte uncompressed point, 87
  chars — what the browser needs in `applicationServerKey`); `private` is born **sealed** as a
  `secret` labelled `vapid_private` (32-byte scalar, base64url). To persist it once:
  `require reveal("vapid_private")` + `reveal(keys["private"])` → `.env` (audited, on purpose);
  then load it with `secret("VAPID_PRIVATE_KEY")`. Same formats as `web-push generate-vapid-keys`.
- `push_send(subscription, payload, opts)` → `{status, ok, gone, retry_after, body}`.
  **`require net("<host of the endpoint>")`** — the push service is a host like any other:
  `fcm.googleapis.com` **and** `jmt17.google.com` (Chrome/Android/Brave/Opera — Chrome hands out
  either FCM domain), `*.notify.windows.com` (Edge/Windows), `updates.push.services.mozilla.com`
  (Firefox), `web.push.apple.com` (Safari/iOS/macOS). A browser you didn't declare → the usual
  capability error naming the exact `require net(...)`; treat it as **your config, not a dead
  subscription** — keep the subscription, add the host, resend (the scaffold's `recover` does).
  Exact hosts on purpose: `net("*.google.com")` would open egress far beyond push.
  - `subscription`: the map the browser gives you — `PushSubscription.toJSON()`:
    `{"endpoint": "https://…", "keys": {"p256dh": "…", "auth": "…"}}` (`expirationTime` is ignored).
    Endpoint must be `https://` (plain `http://` only on loopback, for mocks/tests).
  - `payload`: text as-is · map/list → JSON (same text as `json_encode`) · `bytes` · `nothing` =
    no body (a "something changed" tickle). **Max 3993 bytes** (the encrypted body must stay
    ≤ 4096, the services' limit). A `secret` payload is an error (it would leave the process);
    a secret *inside* a map travels redacted.
  - `opts.vapid` (**required**): `{"public": text, "private": secret, "subject": "mailto:you@x" | "https://…"}`.
    `private` is accepted **only as a `secret`** (from `secret("VAPID_PRIVATE_KEY")`, `as_secret(...)`,
    or `push_vapid_keys()`) — a plain string is refused, like the private key of `sign` (whoever
    holds it can push to every user). `public` is checked against `private`: a crossed pair
    fails here, not as an opaque 401 from the service.
  - `opts.ttl` seconds the service keeps an undelivered message (default `86400`) ·
    `opts.urgency` `"very-low" | "low" | "normal" | "high"` · `opts.topic` 1–32 chars
    `[A-Za-z0-9_-]` (a newer message with the same topic replaces the pending one) ·
    `opts.timeout` seconds (default 30).
  - Returns: `status` (201 = accepted), `ok`, **`gone`** (`true` on 404/410 — the subscription is
    dead: delete it), `retry_after` (text or `nothing`, on 429/503), `body`. The push service
    unreachable → error. Encryption keys (an ephemeral P-256 key + a 16-byte salt) come from
    the OS CSPRNG per message — protocol-internal, no `random` needed (like the TLS handshake).
- Not in the wasm/pure profile (delivering needs sockets): `push_send` fails with the build's
  message; `push_vapid_keys` works everywhere.

```syn
require random
require reveal("vapid_private")                    -- only in the one-off keygen script
let k be push_vapid_keys()
print("VAPID_PUBLIC_KEY=" + k["public"])
print("VAPID_PRIVATE_KEY=" + reveal(k["private"]))  -- paste both into .env, run once

require secret("VAPID_PRIVATE_KEY")                -- in the app
require env("VAPID_PUBLIC_KEY")
require net("fcm.googleapis.com")                  -- one line per push service you serve
require net("web.push.apple.com")
let r be push_send(sub, {"title": "Order shipped", "body": "#1042 is on its way", "url": "/orders/1042"},
    {"vapid": {"public": env("VAPID_PUBLIC_KEY"), "private": secret("VAPID_PRIVATE_KEY"), "subject": "mailto:ops@example.com"},
     "ttl": 3600, "urgency": "high", "topic": "order-1042"})
when r["gone"]
    sql_exec("DELETE FROM push_subs WHERE endpoint = ?", [sub["endpoint"]])
```

## Passkeys — WebAuthn (v0.6.28+; pure, no capability)

The human side of proof-of-possession: the browser/device holds the key, the server sees only
signatures over a challenge IT chose (generate it with `random_bytes(32)` → `require random`, keep
it in the session). Both take **exactly what the browser produces** — the JSON of
`PublicKeyCredential.toJSON()` (`{id, rawId, response: {…}}`, base64url) or a flat map with those
keys (camelCase or snake_case; binaries as `bytes` or base64url text).
- `webauthn_register(credential, opts)` → `{id, public_key, alg, sign_count, fmt, aaguid, user_present, user_verified, backup_eligible, backup_state, transports}` — verifies the `webauthn.create` ceremony (challenge, origin, `rp_id` hash, flags; `fmt: "none"|"packed"|…` reported) and returns the credential's **public key as a JWK map** (`{kty: "EC", crv: "P-256", alg: "ES256", x, y}` / `RSA` / `OKP` Ed25519) — store `id`, `public_key` and `sign_count`. **Attestation is ignored on purpose**: `attStmt` is not verified (trusting the brand of a key means shipping manufacturer trust lists; not a dependency this engine takes). A malformed shape or missing option is an **error** with the fix; a wrong challenge/origin/rp is `nothing`.
- `webauthn_verify(assertion, credential, opts)` → `{id, user_handle, alg, sign_count, user_present, user_verified, backup_eligible, backup_state}` or **`nothing` on ANY verification failure** (challenge, origin, rpId, flags, signature, counter, a credential id that is not the stored one — never the reason). **`credential` is the map `webauthn_register` returned** (`{id, public_key, …}`, or its JSON), plus the `sign_count` and `user_handle` you keep next to it: `rawId` and `userHandle` are NOT covered by the signature, so the engine binds the assertion to the STORED id (mismatch → `nothing`) and returns the stored `id` — never what the assertion declares. `user_handle` is the stored one (and must match the assertion's when both exist; `nothing` if you stored none). Passing the key alone is an error with the fix. The algorithm is fixed by the **registered key** (ES256 / RS256 / EdDSA), never read from the message. An assertion carrying attested-credential data (flag AT) or extension bytes without the ED flag is `nothing`.
- Opts (both): `rp_id` (mandatory), `origin` (text or **list** — several front ends), `challenge` (the base64url you generated; mandatory), `user_verification` (`"required"` demands UV; default `"preferred"`), and for verify `sign_count` (the stored counter; `credential.sign_count` works too: a counter that does not advance = possible cloned key → `nothing`). **Stateless**: the builtins keep nothing; you store the counter and pass it back.
- The verify map follows the `identity_of` convention (`id` = credential id): return it from `auth with` and the request has an identity — quotas, spend, audit — with no adapter.

```syn
require random
let challenge be decode(random_bytes(32), "base64url")          -- keep it in the session
let reg be webauthn_register(credential_from_browser, {"rp_id": "app.example", "origin": "https://app.example", "challenge": challenge})
-- later: assertion from navigator.credentials.get()
let v be webauthn_verify(assertion, stored, {"rp_id": "app.example", "origin": ["https://app.example", "https://m.app.example"], "challenge": challenge})   -- `stored` = the map register returned (+ sign_count, user_handle you keep)
when v == nothing
    give fail(401, "sign in failed")               -- never say why
```

## Identity documents — `did:key`, canonical JSON, signed documents, receipts (v0.6.28+)

Portable identity for agents and servers without a registry: a key IS an identifier (`did:key`),
a document is signed in a form any verifier understands (W3C Data Integrity over JCS), and what a
unit of work did is a **receipt** — a Verifiable Credential **derived** from the audit, never
written by the agent. All pure except signing with a `secret` (gate `sign("NAME")`).
- `canonical_json(value)` → text: **RFC 8785 (JCS)** — keys sorted by UTF-16 code units, ES6 number formatting, no whitespace, `nothing` → `null`. Deterministic bytes for hashing and signing. **Errors, not approximations:** an integer beyond 2^53, a decimal with more than 15 significant digits (JCS numbers are IEEE doubles — put it in the document as text), `bytes` (encode first: `decode(b, "base64url")`), a `secret`, nesting deeper than 64.
- `did_key_encode(public_key, alg?)` → `did:key:z…` (multicodec varint + base58btc). `alg` = `"ed25519"` (default; 32 bytes), `"p256"` (33/65-byte SEC1), `"x25519"`, `"secp256k1"`. `ed25519_pubkey(secret)` gives the bytes for your own key.
- `did_key_decode(did)` → `{alg, public_key (bytes), multibase, did}`; malformed → error.
- `did_key_document(did)` → the **DID Document** (`id`, `verificationMethod` [Multikey], `authentication`, `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`; for ed25519 also `keyAgreement` with the derived X25519 key) — what a resolver would return, computed offline.
- `document_sign(doc, key, opts?)` → the map with a `proof` (**W3C Data Integrity**, `type: "DataIntegrityProof"`). Suites: **`eddsa-jcs-2022`** (default; key = an ed25519 `secret` → **`require sign("NAME")`** + audit, or an Ed25519 PKCS#8 PEM as text) and **`ecdsa-jcs-2019`** (P-256: a 32-byte scalar `secret`, or a SEC1/PKCS#8 PEM as text, no gate — same rule as `ecdsa_p256_sign`). Opts: `verification_method` (default: the `did:key` of the signing key, `did:key:z…#z…` — pass your own URL to point elsewhere), `proof_purpose` (default `assertionMethod`), `created`, `cryptosuite`, `challenge`, `domain`. `proofValue` = `z` + base58 of the signature over `sha256(JCS(proof config)) ‖ sha256(JCS(document))`.
- `document_verify(doc, public_key, opts?)` → `{verified: true, cryptosuite, verification_method, proof_purpose, created, challenge, domain}` or **`nothing` on ANY failure** (tampered, wrong key, wrong suite, `challenge`/`domain` in opts that do not match). `public_key` = 32 bytes / SEC1 bytes, a `did:key`, a public-key PEM, or a JWK map (`OKP`/`EC`). A key type that cannot verify these suites (RSA, x25519) is an error.
- `receipt(opts?)` → the **receipt of the running unit of work**, derived by the engine: a Verifiable Credential (`@context` credentials/v2, `type: ["VerifiableCredential", "SynsemaReceipt"]`) whose `credentialSubject` is `{id (the request identity / agent), tokens (captoken ids in force), capabilities (the audit: every capability asked, granted or denied, with reason and source — the snapshot at issue time; the receipt's own signature comes after it), identity_spend_totals (this identity's running totals per unit, process-wide — the ledger meters identities, not units of work), declassified, steps, program_sha, engine, declared_result_sha256 (the sha256 of the value YOU pass as `result` — a declaration, and the name says so)}`. **Derived, not written:** `issuer` is always the `did:key` of the signing key (there is no `issuer` option — a receipt in someone else's name is what a verifier rejects); `validFrom` and the proof's `created` are the engine's clock when the unit has `time` and are omitted without it (no `created` option: a program cannot antedate). Opts: `sign` (a key as in `document_sign` → signed proof), `verification_method` (default: the signing key's did), `cryptosuite`, `challenge`, `domain`, `result`. Under `serve` the identity is the request's; under `run`, the operator's. Unsigned, it is the same document without `proof` and without `issuer`. **What a receipt cannot promise: completeness** — an agent only shows the receipts it likes; what it promises is that every receipt is true and verifiable.
- `receipt_verify(receipt, public_key, opts?)` → the `document_verify` map, or `nothing` — also when the document is not a receipt (no `SynsemaReceipt` in `type`) and when **the issuer is not the key**: `issuer` must be the `did:key` of `public_key` and `proof.verificationMethod` must belong to it (a receipt signed with your key "in the name of" another did is `nothing`).

```syn
require sign("ID")                                     -- signing with a secret goes through the sign gate
let k be secret("ID_SEED")                             -- 32-byte ed25519 seed (hex in .env)
let did be did_key_encode(ed25519_pubkey(k))
let vm be did + "#" + did_key_decode(did).multibase
let signed be document_sign({"offer": 12, "unit": "credits"}, k, {"verification_method": vm})
document_verify(signed, did)                           -- {verified: true, ...} — or nothing
let r be receipt({"sign": k, "verification_method": vm, "result": answer})   -- what this unit did, signed
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
- `captoken_mint(caps, root_key, opts?)` → token text. `caps` = `{capability: scope | [scopes] | nothing}` (`nothing` = the capability with no scope). Opts: `id` (what you revoke; random if omitted), `ttl` (seconds, **default 900** — short on purpose, see revocation), `aud`, `ip`, `method`, `spend` (`{unit: max}`), and (v0.6.28+) `deterministic` (bool — the holder runs without clock or entropy) and `llm_tokens` (int — a delegated LLM budget). **Reads the clock → `require time`** (or pass it: `opts.now`). **`stdout`/`stdin`/`time`/`random` cannot be minted** (`… is process-local: a token cannot delegate it`): a token carries transferable authority, not another process's clock — use the `deterministic` caveat to switch the clock off.
- `captoken_attenuate(token, caps, opts?)` → a narrower token. **Takes no key** — that's the point. Same opts; anything wider than the parent is an error (a longer `ttl`, a higher `spend` or `llm_tokens`, `deterministic` turned back off). **Reads the clock → `require time`** (or pass it: `opts.now`).
- `captoken_verify(token, root_key, opts?)` → `{id, caps, depth, caveats}` or `nothing` on ANY failure. `caveats` = `{exp, aud, ip, method, spend, deterministic, llm_tokens}`. Opts supply the context the caveats are checked against — `aud`, `ip`, `method`, `at` (unix ts), `revoked` (list of ids). **Fail-closed:** a caveat in the token that you don't supply context for → rejected. **Reads the clock → `require time`** (or pass it: `opts.at`).
- `captoken_allows(verified, capability, scope?)` → bool. Takes the *output of verify* (so you can't ask about an unverified token); `nothing` → `false`; asking about a process-local capability is an error.
- **The token IS the ceiling (v0.6.28+).** The verified map is not advisory: return it from `auth with` and its `caps` become the request's **delegated ceiling** (what the token doesn't list is denied even if the program declares it → the client gets a 403 `insufficient permissions`); pass it as `run_program(src, {"ceiling": verified})` and the child runs under it; write `sandbox under verified` and a block runs under it in-process. `llm`/`judge` are in scope (list them if the holder must reason); `stdout`/`time`/`random` are not (the host governs them). See [capabilities.md](capabilities.md) § delegated ceiling and [serve.md](serve.md).
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
- `http_sign(request, key, opts?)` → map of headers to send (`Signature-Input`, `Signature`, `Content-Digest`). `request` = `{method, url, body?}`. **Requires `sign("KEY_NAME")`** + audit (the same door as signing on-chain); the key must be a sealed `secret`. Opts: `alg` (`"ed25519"` default, or `"hmac-sha256"`), `keyid` (defaults to the secret's name), `created`, `nonce`, `label`. **Reads the clock → `require time`** (or pass it: `opts.created`).
- `http_signature_verify(request, key, opts?)` → `{keyid, alg, created, nonce}` or `nothing`. `request` = `{method, url, headers, body?}`. Pure (verifying signs nothing). **`opts.alg` is REQUIRED** — the verifier pins the algorithm; reading it from the message is the classic confusion forgery. Opts: `max_age` (seconds, default 300 — the anti-replay window; `created` in the future is rejected too). **Reads the clock → `require time`** (or pass it: `opts.now`).
- The key material follows each algorithm's rule: ed25519 = curve material (hex text or bytes, like `ed25519_sign`); hmac-sha256 = the shared string's raw bytes.

**Third-party OIDC (RS256/ES256)** — "login with Google" and cloud workload identity:
- `oidc_verify(token, opts)` → claims map or `nothing`. **`iss` and `aud` are mandatory** (verifying a signature without checking the audience accepts tokens minted for another app of the same provider — the classic confused deputy). Keys: `jwks_url` (fetched and cached 10 min, re-fetched when a `kid` is unknown — **needs `require net(host)`**) or `jwks` (the document inline). Opts: `leeway` (default 60), `alg` (`RS256`/`ES256`; HS256 belongs to `jwt_verify`). RSA keys under 2048 bits are rejected. **Reads the clock → `require time`** (or pass it: `opts.now`).
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
- `sort_by(list, key_function)` / `sort_by(list, key_function, desc = true)` → sorted list (stable; the total order of `sort` — mixed incomparable keys or map keys → error, never a silently unsorted list as before v0.6.29)
- `group_by(list, key_function)` → map of key → list
- `find_first(list, predicate)` → first match or nothing
- `every(list, predicate)` → true if all match
- `some(list, predicate)` → true if any match
- `count_where(list, predicate)` → number
- `flatten(list_of_lists)` → flat list
- `zip_with(list_a, list_b, combiner)` → combined list
- `unique(list)` → deduplicated, first-appearance order (structural equality, same as `==`/`contains` — maps/lists dedupe by value)
- `index_of(list, item_or_predicate)` (on text: `index_of(text, piece)` → character position) → 0-based index of the first match, or **`nothing`** if absent (not -1 — check `when idx != nothing`); callable 2nd arg = predicate, anything else = structural equality

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
- `delete_file(path)` → `true` (v0.6.20+) — requires `file.write` on that path. A missing file is an **error** (`File not found`), a directory too (`use delete_dir`); never a silent `false`. A path inside a `synsema build` bundle is read-only → refused.
- `delete_dir(path, opts?)` → `true` (v0.6.20+) — requires `file.write` on the directory **and, with `{"recursive": true}`, on every path inside it** (checked before anything is deleted; the same grant that would let you delete them one by one — `file.write("./tmp")` alone fails at the first child `file_write("tmp/k")`, add `file.write("./tmp/*")`). Without `recursive` only an empty dir: `"tmp" is not empty (pass {"recursive": true} to delete its contents)`. Unknown option → error.
- `cwd()` → text (v0.6.20+) — the REAL working directory, normalized to `/` (`C:/Users/me/proj`). Requires **`file.read(".")`** — the same grant `list_dir(".")` needs (`./*` and `*` cover it; `./data/*` does not): the absolute path is host information, not free under `--sandbox`. In a `synsema build` binary it is where the binary was started, never the bundle.
- **`bundle:` / `disk:` prefixes** (v0.6.20+, `synsema build` binaries): a path that IS in the bundle is the program — `read_file`/`read_file_bytes`/`file_exists`/`file_info`/`grep` read it from the bundle with no `file` capability (audit `reason: bundled asset (part of the program)`), and a same-named file in the cwd never shadows it; a path NOT in the bundle is the user's → disk with `file.read`. `read_file("bundle:x")` forces the bundle (error if absent), `read_file("disk:x")` forces the disk. `list_dir(p)` lists the **disk** only; `list_dir("bundle:")` / `list_dir("bundle:sub/")` list the bundle.
- `zip_create(entries, opts?)` → bytes / `tar_create(entries, {"gzip": true}?)` → bytes (v0.6.20+, native only) — `entries` = `[{"path", "bytes"} | {"path", "from": <file>}]`; `from` needs `file.read` (a bundled asset needs none). Archive paths normalized to `/`; `..`/absolute refused at creation. **Deterministic** (fixed mtimes: same entries → same bytes).
- `zip_extract(bytes, dest, opts?)` / `tar_extract(bytes, dest, opts?)` → list of the paths written (v0.6.20+, native only; tar detects gzip by magic). Requires **`file.write` on every path it writes** (like `write_file` would: `file.write("./out/*")` extracts into `./out`, created if missing; an exact scope on `./out` alone is denied at the first entry). **Zip-slip rejected** (`entry "../evil.txt" would escape the destination directory (rejected, nothing written)`); symlinks/hardlinks skipped. `opts.max_entries` (10 000) and `opts.max_bytes` (512 MB) count the **real** decompressed bytes (a lying header does not help): over the ceiling → error, nothing written. Price of "nothing written": the content is held in memory up to `max_bytes` before the first file lands — lower it or extract in parts for huge archives. Under `--profile pure`/wasm all four are honest stubs.
- `run(cmd, args_list?, timeout?, opts?)` → `{exit_code, stdout, stderr, stdout_truncated, stderr_truncated}` — requires `exec("<cmd>")`. Runs a process **without a shell** (args as a list → no quoting injection). `timeout` default 120s → on expiry kills the process and **raises** (`timed out after Ns`); catch with `try`/`recover`. `opts`: `{cwd, env (adds/overrides), stdin (text/bytes), max_output (default 10MB)}`. **Non-zero `exit_code` is data, not an error**; can't-launch and timeout raise. `exec` is deny-by-default (not auto-granted, even in `run`). Scope = the command string as passed. **The child does NOT inherit Synsema's secrets** (v0.6.14+): the LLM provider keys and `.env`-loaded variables are stripped from its environment (the base OS env — `PATH`, etc. — is kept, so commands work); pass a secret a child truly needs explicitly via `opts.env` (which routes through `reveal`/`env`). `proc_spawn` strips the same. To run **Synsema under a ceiling** instead of an OS command, prefer `run_program` (isolated env/cwd/timeout by construction).
- `now()` → unix timestamp (number) — requires `time`
- `sleep(seconds)` → pause execution (e.g. to pace an SSE stream) — requires `time`
- `format_time(timestamp, pattern?)` → text — requires `time`. Default ISO-8601 UTC (`format_time(0)` → `"1970-01-01T00:00:00Z"`); with a strftime pattern: `format_time(t, "%Y-%m-%d %H:%M")`
- `parse_time(text, pattern?)` → timestamp — requires `time`. Inverse of `format_time` (ISO-8601 by default; a trailing `Z` is accepted; times are UTC)
- `date_parts(timestamp)` → `{year, month, day, hour, minute, second}` (UTC) — requires `time`
- `random()` → float 0-1
- `random_int(min, max)` → integer

## HTTP
Both `http://` and **`https://` (TLS)** are supported (rustls + OS root CAs, real cert validation). **All HTTP (`http*` and `fetch`) is gated by `net(host)`** — `require net("host")` (deny-by-default, even in `run`; `require net` / `net("*")` = any). See capabilities.md and [stdlib.md](stdlib.md) § HTTP.
- `http(method, url, headers?, query?, body?, timeout?)` → response map `{status, ok, body, json, headers}` (+ `error` ONLY when the transport failed)
- `http_get(url, headers?, query?, timeout?)` / `http_post(url, body, headers?, timeout?)` / `http_put(url, body, headers?, timeout?)` / `http_delete(url, headers?, timeout?)` / `fetch(url, method?, headers?, body?, timeout?)` → response map
- **Body by type (v0.6.20+):** a **map or list** is sent as JSON with `Content-Type: application/json` (your own `Content-Type` header wins); **text** goes out as-is (no content type added); **bytes** raw. (≤ v0.6.19 a map went out as display text with no header — `json_encode(map)` + the header still works.)
- **`json of r`** (v0.6.20+): the parsed body when the response content type says JSON and it parses; otherwise `nothing` (never an error). `body of r` stays the raw text.
- `http_bytes(method, url, headers?, query?, body?, timeout?)` → `{status, ok, bytes, headers}` (v0.6.20+) — the exact bytes the server sent (PDF, image, protobuf); no `body` key. Same `net` gate.
- `multipart_encode(parts)` → `{body: bytes, content_type: "multipart/form-data; boundary=…"}` (v0.6.20+, pure, deterministic boundary) — `parts` = `[{"name", "value"} | {"name", "filename", "content_type"?, "bytes"}]`; send with `http_post(url, body of m, {"Content-Type": content_type of m})`; a Synsema `serve` reads it as `form of request`. Built in memory (no streaming of huge files).

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
- `openapi_json()` → text (v0.6.20+) — the OpenAPI document THIS server publishes (already filtered: `private` routes out), from a route of your own: `give respond(openapi_json(), "application/json")` (a bare `give` would JSON-quote the text). Per server (several `serve on` in one process → each its own). Under `run`: error `only available under serve`.
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
- `svg_to_png(svg, opts?)` → PNG **bytes** from ANY SVG text (deterministic: embedded font; system fonts only if YOU pass them). Opts: `width`/`height` (one keeps aspect), `scale`, `background` (hex), `max_pixels` (overridable anti-DoS ceiling, default ~16.7M), **`fonts`** (v0.6.20+: list of `.ttf`/`.otf` paths, each under `file.read` — a bundled font needs none — loaded for that call; `font-family="Arial"` resolves with `C:/Windows/Fonts/arial.ttf`; unknown families still fall back to DejaVu; same SVG + same fonts → same bytes; `svg_to_pdf` takes it too). External `<image href>` never fetched (no net/disk); `<script>` ignored; `secret` → error.
- `svg_to_pdf(svg, opts?)` → single-page **vector** PDF bytes. Opts: `width`/`height` in points (both must match the SVG aspect ratio). Compose: `write_file(path, b)`, `give binary(b, "image/png"|"application/pdf")`.

## Cron (Scheduled Tasks)
- `cron_every(seconds, task)` → job name (repeating; fixed delay between the END of a run and the next start; interval must be > 0; task must take 0 params and exist at top level — validated at registration)
- `cron_every(expr, task, opts?)` → job name (v0.6.12+) — **wall-clock cron expression** (text): 5 fields `min hour day month weekday` (`*`, `a-b`, `*/n`, lists, `jan..dec`/`sun..sat`, `0`/`7` = Sunday; day+weekday both set → OR, like Vixie cron) or an alias `@hourly`/`@daily`/`@weekly`/`@monthly`/`@yearly`. `opts = {"tz": "UTC" | "+HH:MM" | "-HH:MM"}` (fixed offset; default UTC; IANA zones with DST are NOT supported → clear error). Fires at the next matching minute AFTER the previous run ends (occurrences skipped while a run is in progress are dropped, never queued); no persistence, no catch-up. Bad expression / never-matching (`0 0 31 2 *`) / unknown option → error at registration
- `cron_after(seconds, task)` → job name (one-shot; delay ≥ 0; same validation)
- `cron_cancel(name)` → bool
- `cron_list()` → list of `{name, schedule, interval, repeating, active, run_count, errors, next_run, tz}` — `schedule` = `"every 300.0s"` / `"after 60.0s"` / the cron expression; `interval` = seconds or `nothing` (expression jobs); `next_run` = unix timestamp of the next fire (`nothing` once a one-shot ran); `tz` = `"UTC"`/`"+HH:MM"` or `nothing` (interval jobs); run_count = completed runs, errors = failed ticks (real counts, never phantom)
- `cron_status()` → formatted text (`[active] report: at '0 9 * * *' (UTC), next 2026-08-30T09:00:00Z, runs: 3, errors: 0`) (`[active] report: at '0 9 * * *' (UTC), next 2026-08-30T09:00:00Z, runs: 3, errors: 0`)

## Agentic apps — `select`, live processes, event bus, agent control (engine v0.6.7+)

One wait for everything (no capability; handles from `ws_connect`, a `socket` route, `proc_spawn`, `bus_subscribe`):
- `select(targets, timeout?)` → first ready event tagged `source` (`"ws"`/`"proc"`/`"bus"`/`"watch"`/`"term"`), `handle`, `name` (map form); `nothing` at timeout / all gone. `targets` = list of handles or map name → handle. See [concurrency.md](concurrency.md).

Live processes (gated by `exec(cmd)` like `run`; see [processes.md](processes.md)):
- `proc_spawn(cmd, args?, opts?)` → handle. `opts`: `cwd`, `env`, `line_mode` (true), `stderr` (`"separate"`|`"merge"`), `max_queue` (4096), `max_queue_bytes` (64 MiB), `on_full` (`"block"`|`"drop_oldest"`|`"error"`), **`pty`** (false; v0.6.8+ — real pseudo-terminal for y/N prompts, passwords, TUIs; then one `stdout` stream, raw text chunks with ANSI (`data` is always text, never `bytes`), `line_mode` false, echo on), `cols` (80), `rows` (24), `term` (`"xterm-256color"`) — the last three only with `pty: true`; **`process_group`** (true; v0.6.9+ — own process group / Windows Job Object, so `proc_kill`/`proc_close` kill the whole tree incl. grandchildren; `false` detaches a daemon on purpose)
- `proc_resize(h, cols, rows)` → true (pty only, v0.6.8+); `strip_ansi(text)` (Text section) to read pty output as a human
- `proc_recv(h, timeout?)` → `{type: "stdout"|"stderr"|"exit", data}` or `nothing`; `proc_select(list|map, timeout?)`
- `proc_send(h, text|bytes)` → true (blocking write; on a pty these are keystrokes: Enter = `"\r"`, Ctrl-C = `bytes([3])`); `proc_close_stdin(h)` (pipes only — on a pty it errors and names the EOF key)
- `proc_status(h)` → `"running"|"exited"|"killed"|"closed"`; `proc_stats(h)` → `{pid, cmd, status, exit_code, pty, tree, queued, queued_bytes, dropped, uptime}`
- `proc_kill(h, "TERM"|"KILL"?)` (reaches the whole tree); `proc_wait(h, timeout?)` → `{exit_code, signal}` or `nothing`; `proc_close(h)` (kills the tree if alive; no orphans)

File-watch (v0.6.9+; gated by `file_read(path)` like `list_dir`; polling with a snapshot — same events on every OS; see [processes.md](processes.md) § File-watch):
- `watch(path, opts?)` → handle (also in `select`, `source: "watch"`). `opts`: `recursive` (true), `interval` seconds (0.5), `ignore` (names/`*` globs; default `[".git", "node_modules", "target"]`), `max_entries` (100000; over it → error), `max_queue` (4096, drop-oldest)
- `watch_recv(h, timeout?)` → `{type: "create"|"modify"|"delete", path, is_dir}` or `nothing`; `path` with `/`, relative if the root was; rename = delete + create; dirs only create/delete; nothing for pre-existing content
- `watch_stats(h)` → `{path, recursive, interval, entries, scans, queued, dropped}`; `watch_close(h)` (idempotent; stops the scanner). Budget `SYNSEMA_WATCH_MAX` (64)

The program's own terminal (v0.6.11+; gated by `stdin`; see [processes.md](processes.md) § The program's own terminal):
- `term_open(opts?)` → handle (also in `select`, `source: "term"`) or **`nothing`** without a TTY / under `serve`, `test`, `conform` / in wasm → fall back to `read_line`. `opts`: `paste` (true), `kitty` (true), `ctrl_c` (`"exit"` = restore + exit 130 | `"key"`), `max_queue` (16384)
- `term_recv(h, timeout?)` → `{type: "key", key, text, ctrl, alt, shift}` (`key` = `"char"`|`"enter"`|`"tab"`|`"backtab"`|`"backspace"`|`"delete"`|`"insert"`|`"escape"`|`"up"`|`"down"`|`"left"`|`"right"`|`"home"`|`"end"`|`"pageup"`|`"pagedown"`|`"f1"`…`"f12"`), `{type: "paste", text}` (Unix), `{type: "resize", cols, rows}`, `{type: "focus", gained}`, `{type: "eof"}` (once; handle gone) or `nothing`
- `term_size(h)` → `{cols, rows}`; `term_write(h, text)` → writes to stdout now (ANSI ok); `term_stats(h)` → `{kitty, paste, ansi, keys, queued, dropped}`; `term_close(h)` (idempotent; the runtime restores on drop/error/panic anyway)

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
