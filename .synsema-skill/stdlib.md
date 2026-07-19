# Synsema Standard Library — HTTP, Database, Cron

Synsema is a **Rust** language (the `synsema/` Python tree is frozen; Rust is the source of truth).
Single static binary. The HTTP server runs on an async `hyper`/`tokio` stack; bundled SQLite via
`rusqlite`. For numeric/scientific builtins (bytes, complex, special math, arrays + linear algebra)
see [builtins.md](builtins.md).

## HTTP

```
-- Full control. Don't hardcode credentials: pass a `secret` (materialized at the
-- socket, redacted in logs). bearer() builds the Authorization: Bearer <token> value.
let r be http("POST", "https://api.store.com/orders",
    {"Authorization": bearer(secret("STORE_API_KEY")), "Content-Type": "application/json"},
    {"page": "1"},
    {"product": "laptop", "quantity": 1}
)

-- Shorthands
let r be http_get("https://api.store.com/products")
let r be http_get(url, {"Authorization": bearer(secret("STORE_API_KEY"))}, {"page": "1"})
let r be http_post(url, {"name": "Alice"}, {"Authorization": bearer(secret("STORE_API_KEY"))})
let r be http_put(url, {"name": "Bob"})
let r be http_delete(url, {"x-api-key": secret("STORE_API_KEY")})  -- any header, not just Bearer
```

**Timeout (optional, trailing arg on every HTTP builtin):** seconds as a positive number; absent
or invalid → **30** (the historical default). Signatures: `http(method, url, headers?, query?,
body?, timeout?)`, `http_get(url, headers?, query?, timeout?)`, `http_post(url, body, headers?,
timeout?)`, `http_put(url, body, headers?, timeout?)`, `http_delete(url, headers?, timeout?)`,
`fetch(url, method?, headers?, body?, timeout?)`. Use it for slow APIs (>30s) or to fail fast:
`http("GET", url, nothing, nothing, nothing, 120)`.

> **Credentials go in headers:** pass a `secret` directly as a header value —
> `{"x-api-key": secret("KEY")}` or any custom header; it's materialized only at the
> socket and redacted in logs/errors. `bearer(s)` is sugar for `Authorization: Bearer
> <token>`. For a key that arrives at runtime (not from `.env`), seal it with
> `as_secret(...)`. In query params and the body a `secret` is **redacted** (fail-closed).
> See **[secrets.md](secrets.md)**.

**HTTPS works**: `http://` and `https://` are both supported (TLS via `rustls` with the OS
root CAs — real certificate validation, pure-Rust). So `http_get("https://api.example.com")`
is fine for real-world APIs. **All HTTP (`http*` and `fetch`) is gated by `net(host)`** (deny-by-default,
even in `run`): `require net("host")` — see capabilities.md. `require net` / `net("*")` = any host.

Response is always a map:
```
status of r      -- 200
ok of r          -- true (200-299)
body of r        -- raw text
json of r        -- auto-parsed if content-type is json
headers of r     -- response headers map
error of r       -- error message if failed
```

## WebSocket (live feeds — general transport, not just blockchain)

A synchronous WebSocket **client** for anything that streams: RPC subscriptions,
exchange fills, Discord/Slack, mempool. Replaces cron+polling with a live feed. Gated by
the SAME `net(host)` capability and scope as HTTP (deny-by-default, denied in `sandbox`);
`wss://` validates the server cert against the OS root CAs like `https://`.

```
require net("stream.exchange.com")
let conn be ws_connect("wss://stream.exchange.com/ws")   -- opaque handle; headers? + opts? optional
ws_send(conn, json_encode({"op": "subscribe", "channel": "trades"}))  -- text or bytes
let msg be ws_recv(conn, 5)         -- next message, or `nothing` after the 5s timeout (never blocks forever)
-- msg is {"type": "text"|"binary"|"close", "data": …}
if msg is not nothing and msg["type"] is "text"
    print(msg["data"])
ws_close(conn)                      -- clean close frame (idempotent)
```

- `ws_connect(url, headers?, opts?)` → handle. `headers` is a text→text map (a `secret`
  value materializes only at the socket, like HTTP). `opts`: `{"timeout": secs,
  "max_message_size": bytes}` (default 16 MiB, hard ceiling 64 MiB — a huge frame errors,
  it never buffers unbounded).
- `ws_recv(conn, timeout?)` → the message map, or **`nothing`** on timeout (default 30s,
  same as `wait_for`). It NEVER blocks forever; ping/pong are handled transparently.
- `ws_send(conn, data)` / `ws_close(conn)`. A dead connection errors on send/recv (the
  handle is retired) — atrapable with `try`/`recover`.
- **Under `serve`:** a handler can open an outbound WS (to an RPC/exchange) and forward it
  over SSE — the "WS→SSE bridge". (Accepting *incoming* WS connections is a separate
  feature; chat/notifications already ship with POST+SSE — see serve.md.)
- **`eth_subscribe` (newHeads/logs) is composable in userland today:** `ws_connect` to the
  node's WS endpoint, `ws_send` the JSON-RPC subscribe frame, `ws_recv` the notifications
  (parse with `json_decode`); one-shot reads go through the typed read-side
  (stdlib.md § Blockchain) instead.

## Database

Five backends, all pure-Rust (single static binary, no OpenSSL/`*-sys`), all opened with `db_open` and
routed by the target. **Three API families:**
- **SQL** (SQLite / Postgres / MySQL) — universal API `sql`/`sql_exec`/`sql_batch`/`sql_tables`/`paged`.
- **Document store** (MongoDB) — its own `mongo_*` API (no SQL); see [MongoDB](#mongodb-no-sql-document-store).
- **Key-value / cache / structures** (Redis) — its own `redis_*` API (no SQL, no documents); see
  [Redis](#redis-no-sql-key-valuecachestructures).

**Deny-by-default: every DB op needs `require db(scope)`** (see capabilities). Using the wrong family on a
connection errors clearly (`sql()` on Mongo/Redis, `mongo_*` on SQL/Redis, or `redis_*` on SQL/Mongo).

### SQL (SQLite / Postgres / MySQL)

Universal API routed by the `db_open` target: a **file path** → SQLite (built-in, `rusqlite`);
`postgres://…` → Postgres; `mysql://…` → MySQL. Parameterized queries everywhere (safe from injection).
`bytes` columns round-trip to/from `BLOB`/`BYTEA` byte-exactly (binary-safe).

```
require db("./store.db")           -- declare the DB you use (db("*") / require db = any)

-- Open
db_open("./store.db")              -- file (persistent)
db_open(":memory:", "memory")      -- in-memory (fast, temporary)
db_open("./data.db", "readonly")   -- read-only

-- Create tables
sql_exec("CREATE TABLE products (name TEXT, price REAL, stock INTEGER)")

-- Insert (parameterized — safe)
sql_exec("INSERT INTO products VALUES (?, ?, ?)", ["Laptop", 999, 15])

-- Query → list of maps
let products be sql("SELECT * FROM products WHERE price > ?", [100])
each p in products
    print(name of p + ": $" + text(price of p))

-- Paginated query for HTTP routes (see serve.md): SQL LIMIT/OFFSET pushdown
-- with an exact COUNT(*) total. Use only with `give` in a route handler.
give paged("SELECT * FROM products ORDER BY id")

-- Batch insert
sql_batch("INSERT INTO logs VALUES (?)", [["event1"], ["event2"], ["event3"]])

-- List tables
let tables be sql_tables()

-- Binary: bytes <-> BLOB (byte-exact)
sql_exec("CREATE TABLE files (data BLOB)")
sql_exec("INSERT INTO files VALUES (?)", [read_file_bytes("./logo.png")])
let raw be (sql("SELECT data FROM files"))[0]["data"]   -- type_of -> "bytes"

-- Close
db_close()
```

### Remote SQL: Postgres & MySQL
Same builtins, different `db_open` URL. The capability **scope is the canonical URL** —
`scheme://host/db` with **no credentials/port/query** (e.g. `mysql://user:pw@localhost:3306/appdb` →
`mysql://localhost/appdb`). `db("*")` / bare `require db` cover any DB. Connections apply a 10s
connect-timeout (a dead host fails fast, never hangs).

```
-- Postgres: `?` placeholders are rewritten to $1,$2…; no last_id (use RETURNING).
require db("postgres://localhost/appdb")
db_open("postgres://user:pw@host:5432/appdb")        -- TLS on by default; add ?sslmode=disable to turn off
sql_exec("INSERT INTO users (name) VALUES (?) RETURNING id", ["Ada"])
-- pgvector runs server-side: pass a list as ?::vector, order by <-> / <=>
let near be sql("SELECT id FROM docs ORDER BY emb <-> ?::vector LIMIT ?", [q_embedding, 5])

-- MySQL: `?` placeholders are NATIVE (not rewritten); last_id = last_insert_id() works.
require db("mysql://localhost/appdb")
db_open("mysql://user:pw@host:3306/appdb")           -- plaintext by default; TLS opt-in: ?ssl-mode=REQUIRED
let r be sql_exec("INSERT INTO users (name) VALUES (?)", ["Ada"])
print(text(r["last_id"]))                            -- the AUTO_INCREMENT id (real)
```

**Backends at a glance:**

| | SQLite (file) | Postgres (`postgres://`) | MySQL (`mysql://`) |
|---|---|---|---|
| Placeholders | `?` | `?` → `$n` (rewritten) | `?` (native) |
| `last_id` | rowid | `0` (use `RETURNING`) | `last_insert_id()` (real) |
| TLS | n/a | default on (`?sslmode=disable` off) | opt-in (`?ssl-mode=REQUIRED`) |
| Vector | in-Synsema (below) | pgvector (server-side) | — |

**Type mapping** (both remote backends): int→number, float→number, **DECIMAL/NUMERIC→`decimal`**
(`type_of` "decimal"), text→text, **BLOB/BYTEA→`bytes`** (byte-exact; MySQL distinguishes BLOB vs TEXT by
the column's binary charset), **JSON/JSONB→`map`/`list`**, date/time→ISO text, NULL→`nothing`.

### MongoDB (no-SQL document store)
A **document store**, not SQL: `db_open("mongodb://…")` then the **`mongo_*`** builtins. Documents and
filters are **Synsema maps ↔ BSON** (no query strings). Same capability gate (`require db`, scope =
canonical URL). The connection validates on open (ping; dead host fails within the 10s timeout). `sql()`
on a Mongo connection errors and tells you to use `mongo_*`.

```
require db("mongodb://localhost/appdb")
db_open("mongodb://synsema:synsema@host:27017/appdb?authSource=admin")  -- plaintext; TLS via ?tls=true

-- Insert → returns the _id (text hex if ObjectId)
let id be mongo_insert("users", {"name": "Ana", "age": 30, "tags": ["a", "b"], "score": 9.99d})
let many be mongo_insert_many("users", [{"name": "Bo"}, {"name": "Cy"}])   -- list of _ids

-- Find: filter is a map; opts = {limit, skip, sort, fields}. Filtering by _id accepts the text hex.
let adults be mongo_find("users", {"age": {"$gte": 18}}, {"sort": {"age": -1}, "limit": 10})
let one be mongo_find_one("users", {"_id": id})            -- map, or nothing

-- Update (operators required: $set/$inc/…) → {matched, modified}; delete → {deleted}
mongo_update("users", {"name": "Ana"}, {"$set": {"age": 31}})
mongo_delete("users", {"name": "Ana"})

let n be mongo_count("users", {"age": {"$gte": 18}})       -- number
let report be mongo_aggregate("users", [{"$group": {"_id": nothing, "total": {"$sum": "$age"}}}])
let colls be mongo_collections()                           -- list of names
db_close()
```

**BSON mapping** (recursive): int→number, float→number, **`decimal` (`1.50d`)↔Decimal128** (`type_of`
"decimal"), text→text, **`bytes`↔Binary** (byte-exact), list↔Array, map↔Document, NULL↔`nothing`,
**ObjectId→text hex** (24 chars). The `_id` reads back as text; in a filter, a 24-hex string under `_id`
(incl. inside `$in`) is auto-coerced to an ObjectId so `mongo_find("c", {"_id": id})` matches.

### Redis (no-SQL key-value/cache/structures)
A **key-value store with structures and TTL** — not SQL, not documents: `db_open("redis://…")` then the
**`redis_*`** builtins. Values are **byte-strings**: `text` if valid UTF-8, else `bytes`; integers come back
as `number`. Same capability gate (`require db`, scope = canonical URL). The connection validates on open
(`PING`; a dead host fails within the 10s timeout). `sql()` / `mongo_*` on a Redis connection error and tell
you to use `redis_*`. **db-index gotcha:** `redis://host:6379` → scope `redis://host` (db 0 implicit, **no**
`/0`), but `redis://host:6379/0` → scope `redis://host/0` — *different scopes*. Match `require db(...)` to the
exact form of `db_open(...)`.

```
require db("redis://localhost")               -- redis://host:6379 → scope redis://host (no /0!)
db_open("redis://localhost:6379")             -- rediss:// for TLS (ring); auth via redis://:pw@host

-- KV + cache + TTL
redis_set("greet", "hi")                       -- redis_set(key, val, ttl_secs?) → nothing
redis_set("session:42", token, 3600)           -- with TTL (seconds)
let v be redis_get("greet")                    -- text/bytes, or nothing if absent
redis_del("greet")                             -- → number deleted; redis_exists(k...) → number
redis_mset({"a": "1", "b": "2"})               -- multi-set from a map
let vals be redis_mget(["a", "b", "x"])        -- list (each text/bytes/nothing)
redis_expire("session:42", 60)                 -- → bool; redis_ttl(k) → secs (-1 none, -2 absent)
redis_persist("session:42")                    -- remove TTL → bool

-- Atomic counters
let hits be redis_incr("hits")                 -- +1 atomic → number; redis_decr / redis_incrby(k, n)

-- Hashes (field→value maps)
redis_hset("user:1", {"name": "Ana", "role": "admin"})   -- → number of new fields
let name be redis_hget("user:1", "name")
let all be redis_hgetall("user:1")             -- → map; redis_hdel(k, f...); redis_hincrby(k, f, n)

-- Lists (queues/stacks) and Sets
redis_rpush("jobs", "t1", "t2")                -- push right → new length; redis_lpush = left
let job be redis_lpop("jobs")                   -- pop left (FIFO with rpush); redis_rpop = right
let page be redis_lrange("jobs", 0, -1)         -- list (negatives ok); redis_llen(k)
redis_sadd("tags", "x", "y")                    -- → added count; redis_srem(k, m...)
let members be redis_smembers("tags")           -- list; redis_sismember(k, m) → bool

-- Keys / type (KEYS is O(N): in prod prefer a bounded pattern)
let ks be redis_keys("user:*")                  -- list of text; redis_type(k) → "string"/"hash"/…

-- Structured data: explicit, no magic auto-JSON
redis_set("cfg", json_encode({"theme": "dark", "n": 3}))
let cfg be json_decode(redis_get("cfg"))        -- → map
db_close()
```

**Distributed lock (agent-native, the star primitive).** Safe single-node Redlock: acquire with a unique
token + TTL, release **only if the token is still ours** (atomic Lua) so you never free another agent's lock.
The TTL prevents deadlocks if the holder dies; the token-checked unlock prevents releasing a lock you no
longer own (e.g. it expired and another agent took it). Not a multi-node Redlock — one Redis node.

```
let tok be redis_lock("lock:job-7", 10000)      -- SET NX PX; → token (text), or nothing if held
if tok != nothing
    -- critical section: only one agent enters
    redis_unlock("lock:job-7", tok)             -- → true if freed (was ours), false otherwise
```

**Value mapping** (explicit, binary-safe): **Synsema→Redis** — text→UTF-8 bytes, `bytes`→raw bytes,
number→decimal repr (so `INCR` works), secret→revealed at the DB edge; **bool/map/list/nothing → error**
(use `json_encode`). **Redis→Synsema** — bulk string UTF-8→`text` else `bytes`, integer→`number`,
nil→`nothing`, array/set→`list`, hash→`map`. Structured data is explicit via `json_encode`/`json_decode`.

### Vector search with SQLite (no extension)
No `sqlite-vec`/ANN (rusqlite is bundled without `load_extension`). For small/medium corpora, store
embeddings as TEXT and rank by cosine **in Synsema** (`array`/`dot`/`norm`):
```
require db("./vec.db")
task to_vec(s)
    give array(apply((x) => number(x), split(s, ",")))
task cosine(a, b)
    give dot(a, b) / (norm(a) * norm(b))

let q be array(query_embedding)                  -- from an embeddings API (http_post) or a model (run)
let rows be sql("SELECT title, emb FROM docs")   -- pre-filter by metadata in SQL if you want
let scored be apply((r) => {"title": r["title"], "score": cosine(to_vec(r["emb"]), q)}, rows)
let top be sort_by(scored, (x) => 0 - x["score"])  -- best first
```
For real ANN at scale: delegate to a server that does vectors (pgvector via a Postgres HTTP API, or
ClickHouse over HTTP) and query it with `fetch` — the index runs server-side, no in-process extension.

## Cron (Scheduled Tasks)

Background scheduler. Non-blocking. Each job runs its task for real on its own thread
(parked between ticks — zero CPU); the counters in `cron_list()` reflect real executions.

```
-- Repeat every N seconds
task sync_inventory()
    let data be http_get("https://api.warehouse.com/stock")
    share data as "inventory"

cron_every(300, sync_inventory)    -- every 5 minutes

-- One-shot after delay (0 = right away)
task send_reminder()
    log "Sending reminder"

cron_after(3600, send_reminder)    -- once, after 1 hour

-- Manage
cron_cancel("sync_inventory")     -- stop a job
let jobs be cron_list()            -- list all jobs
print(cron_status())               -- formatted status
```

Semantics (know these before reaching for cron):
- Signatures: `cron_every(seconds, task)` / `cron_after(seconds, task)` → both **return
  the job name (text)**, which is what `cron_cancel(name)` takes. The `task` argument is
  a task reference (`sync_inventory`) or its name as text (`"sync_inventory"`).
- The task must take **0 parameters** and be defined at the top level (the job runs it
  by name). Required parameters → clear error **at registration**; wrap it instead.
- **Intervals, not wall-clock cron**: fixed delay between the END of one run and the
  start of the next. No `"0 9 * * MON"` expressions. A job never overlaps itself.
- `cron_every` requires interval > 0; `cron_after` accepts delay ≥ 0.
- Same name re-registered → **replaces** the old job (counters restart at 0).
- Errors: `errors`+1, one log line (`[serve] [cron] job 'x' failed: …`), the job stays
  scheduled and the process stays up. `run_count` counts COMPLETED runs only.
- `cron_list()` entries: `{name, interval, repeating, active, run_count, errors}`.
- In-memory, no persistence/catch-up: a restart re-registers with run_count = 0.
- Under `serve`, jobs share the process state with routes (db, `state_*`, memory,
  blackboard) and run with the program's capabilities; top-level jobs start once the
  server is serving, and registering from a route works and is globally visible.
- Under `run`, jobs share state with EACH OTHER; to exchange data with the rest of
  the program use external effects (a file, an on-disk db, or `share`/`observe`).

## Serve mode (keep crons alive)

Under `run`, jobs execute while the program lives and stop when it ends. Use
`synsema serve` to keep the process alive — even with no routes:

```bash
synsema serve server.syn
# Serving 3 cron job(s). Press Ctrl+C to stop.
```

## Blockchain (read → build → sign → send → confirm — ETH/Avalanche/Solana/Algorand)

Operate on-chain from an agent with the private key sealed as a `secret` that NEVER
materializes. The full autonomous loop: READ what you need (nonce/fees/blockhash/params),
BUILD the tx, SIGN it (the ONE gated door), SEND it, CONFIRM it — no hand-rolled
JSON-RPC, no hex-quantity bugs. Reading/sending is `net(host)`-gated (same capability
as `http_*`); ONLY signing moves value — a monitor agent with `net` can read everything
and spend nothing.

```
require net("rpc.example.com")
require sign("HOT_KEY")   -- signing is deny-by-default + audited (NOT ambient)
let k be as_secret("<hex>", "HOT_KEY")   -- or secret("HOT_KEY") from .env
let url be "https://rpc.example.com"

-- ETH end-to-end: read → build (tx_eip1559) → sign → assemble → send → confirm
let nonce be eth_nonce(url, eth_address(k))      -- eth_getTransactionCount ("pending")
let fees be eth_fee_history(url)                 -- {base_fee, priority, base_fees, rewards}
let tx be tx_eip1559({"chain_id": eth_chain_id(url), "nonce": nonce,
    "to": dest, "value": 100000000000000000, "gas": 21000,
    "max_fee": fees["base_fee"] * 2, "max_priority": fees["priority"]})
-- tx echoes every value-moving number (tx["max_fee"], tx["value"], tx["to"]) —
-- show them in a `confirm` BEFORE signing (anti blind-signing, extended to fees)
let sig be secp256k1_sign(tx["digest"], k)       -- bytes(65) r‖s‖v; RFC6979, low-s
let raw be tx_eip1559_raw(tx, sig)               -- assembles 0x02||rlp(...+[v,r,s]) for you
let hash be eth_send_raw(url, raw)               -- "0x…" tx hash (net-gated: already signed)
let receipt be eth_wait_receipt(url, hash, 1, 120)  -- bounded poll; nothing on timeout
-- receipt["status"] == 1 → success; 0 → REVERTED (it landed but failed — always check)

-- read contract state: eth_call returns RAW bytes → abi_decode
let calldata be abi_encode("balanceOf(address)", [owner])
let bal be abi_decode("uint256", eth_call(url, {"to": token, "data": calldata}))[0]
let d712 be eip712_digest(domain, types, "Permit", permit_map)  -- readable maps in

-- Solana end-to-end: blockhash → message → ed25519_sign → tx → send → confirm
let bh be solana_latest_blockhash(url)           -- bytes(32), feeds solana_message directly
let msg be solana_message({"fee_payer": payer, "recent_blockhash": bh,
    "instructions": [{"program": "11111111111111111111111111111111",
        "accounts": [{"pubkey": payer, "signer": true, "writable": true},
                     {"pubkey": dest_pk, "writable": true}],
        "data": int_to_bytes_le(2, 4) + int_to_bytes_le(lamports, 8)}]})
let stx be solana_tx(msg, ed25519_sign(msg, k))
let signature be solana_send(url, stx)           -- base58 signature text
let status be solana_confirm(url, signature, 60) -- waits confirmed/finalized; nothing on timeout
-- status["err"] == nothing → success; anything else = landed but FAILED on-chain

-- Algorand end-to-end: params → canonical msgpack → sign → send (BINARY) → wait
let p be algorand_params(url)   -- {fee (PER-BYTE, often 0), min_fee (flat), fv, lv, gh, gen}
let txn be {"type": "pay", "snd": algo_address(k), "rcv": rcv, "amt": 123456,
    "fee": p["min_fee"], "fv": p["fv"], "lv": p["lv"], "gh": p["gh"], "gen": p["gen"]}
let stx be algorand_tx(txn, ed25519_sign(algorand_tx_encode(txn), k))
let txid be algorand_send(url, stx)              -- POSTs application/x-binary for you
let info be algorand_wait(url, txid, 60)         -- info["confirmed-round"]; nothing on timeout
```

**HD wallets / custody (`require wallet` — creating custody, deny-by-default + audited):**
An agent generates a wallet from scratch, backs it up as a phrase, and derives N
accounts — like Metamask/Phantom. EVERYTHING returns a `secret` (the mnemonic/seed/key
NEVER materialize); the phrase and passphrase come IN as secrets.

```
require wallet                                   -- creating custody (separate from `sign`)
let phrase be mnemonic_generate(12, "W")         -- secret: 12 words, OS entropy (not seedable)
let seed be mnemonic_to_seed(phrase)             -- secret: 64-byte BIP-39 seed (optional passphrase)
let ethk be hd_derive(seed, "m/44'/60'/0'/0/0")  -- secret: BIP-32 secp256k1 (default) → use with eth_address/secp256k1_sign
let solk be hd_derive(seed, "m/44'/501'/0'/0'", "ed25519")  -- secret: SLIP-0010 (Solana; hardened-only)
print(eth_address(ethk))                         -- derive the PUBLIC address (no gate)
-- Algorand phrase is its OWN 25-word format (NOT BIP-39):
let am be algorand_mnemonic(algo_secret32)       -- secret: 25 words (Pera/Defly format)
let ak be algorand_mnemonic_to_key(am)           -- secret: back to the 32-byte key
-- Import an existing wallet from a Geth/MyEtherWallet keystore V3:
let k be keystore_import(json_text, secret("KS_PASS"), "HOT")  -- secret; wrong pass → error, no leak
let json be keystore_export(k, secret("KS_PASS"))             -- text (encrypted JSON V3)
```

**Solana PDAs + SPL (pure):**
```
let pda be solana_pda(["metadata", program_bytes, mint], program)  -- {address: bytes(32), bump: int}
let ata be spl_ata(owner_pubkey, mint)           -- associated token account (a PDA)
let data be spl_transfer_checked_data(amount, decimals)  -- SPL TransferChecked ix data (tag 12)
```

**Read-side / RPC builtins (all `net(host)`-gated; a node is UNTRUSTED input — every
decode is strict, malformed/oversized/hostile responses → catchable error, never silent
bad data; errors name the host only, never the full URL — API keys live in the path):**
- EVM JSON-RPC: `eth_rpc(url, method, params?)` (escape hatch: ints→hex-quantity,
  bytes→`0x…`, result as decoded JSON); `eth_nonce(url, addr)`; `eth_balance(url, addr, block?)`
  → exact wei int; `eth_gas_price(url)`; `eth_chain_id(url)`; `eth_estimate_gas(url, tx_map)`;
  `eth_call(url, {to, data}, block?)` → RAW bytes (feed `abi_decode`);
  `eth_fee_history(url, blocks?, percentiles?)` → `{base_fee, priority, base_fees, rewards}`
  (base_fee = NEXT block; priority = median of the first percentile column; raw arrays
  included — the derivation is transparent, not an oracle); `eth_send_raw(url, raw)` → `"0x…"`
  hash; `eth_receipt(url, hash)` → typed receipt map or `nothing`;
  `eth_wait_receipt(url, hash, confirmations?, timeout?)` → receipt after N confs or `nothing`.
  Receipt decoding is typed: quantities→int, addresses→EIP-55 text, hashes→`"0x…"` text,
  log `data`→bytes.
- EIP-1559 builders (PURE): `tx_eip1559(params)` with `{chain_id, nonce, to, value, gas,
  max_fee, max_priority, data?, access_list?}` — EVERY value-moving field explicit (no
  silent defaults; a missing field errors naming the reader helper) → `{digest, fields,
  + echo of every number}`; `tx_eip1559_raw(tx, sig65)` → signed raw bytes (v/r/s handled).
- Solana RPC: `solana_rpc(url, method, params?)` (escape hatch, plain JSON params);
  `solana_latest_blockhash(url)` → bytes(32); `solana_balance(url, pubkey)` → lamports int;
  `solana_send(url, tx_bytes)` → base58 signature; `solana_confirm(url, sig, timeout?)` →
  status map (`err`, `confirmation_status`, `slot`) or `nothing`;
  `spl_balance(url, owner, mint, token_program?)` → `{amount, decimals, ata}` — a missing
  ATA is a catchable ERROR, never a silent 0 (a wrong owner/mint would read 0 forever).
- Algorand REST (algod; optional trailing `headers?` map on each — `X-Algo-API-Token`
  can be a `secret`, it materializes only at the socket): `algorand_params(url)` →
  `{fee, min_fee, fv, lv, gh, gen}` (lv = fv+1000, the protocol max window);
  `algorand_account(url, addr)` (checksum validated BEFORE touching the network);
  `algorand_send(url, signed_bytes)` → txid (binary POST handled); `algorand_wait(url,
  txid, timeout?)` → confirmed info, `nothing` on timeout, ERROR on pool rejection.
- All three waiters are BOUNDED polls (like `ws_recv`): they return `nothing` at the
  deadline, they never hang an agent. Mid-wait TRANSIENT failures (transport / HTTP 5xx)
  are retried until the deadline after a first successful poll (one stderr notice; a
  deadline that expires mid-failure surfaces the ERROR, not `nothing`); a dead node /
  wrong URL fails fast on the FIRST poll; definitive answers (4xx, invalid JSON, node
  RPC errors, hostile decode) error immediately.

Builtins:
- Hashes (pure): `keccak256(x)`/`sha512_256(x)` → bytes(32). ⚠️ keccak256 is PRE-NIST
  Keccak (Ethereum), NOT SHA3-256 — `keccak256("")` = `c5d24601…`, not `a7ffc6f8…`.
- Encoding (pure): `bytes(t, "base58"|"base32")` / `decode(b, …)`; `bech32_encode(hrp, data, variant?)` / `bech32_decode(text)` → `{hrp, data, variant}`.
- secp256k1: `secp256k1_sign(digest32, secret)` [**require sign**], `secp256k1_verify(digest, sig, pubkey)`, `secp256k1_recover(digest, sig65)`, `secp256k1_pubkey(secret, compressed?)`.
- ed25519: `ed25519_sign(message, secret)` [**require sign**], `ed25519_verify(msg, sig, pubkey)`, `ed25519_pubkey(secret)`.
- EVM (pure): `eth_address(pubkey_or_secret)` → EIP-55 text; `rlp_encode(value)` / `rlp_decode(bytes)`; `abi_encode(sig, values)` / `abi_decode(types, data)` / `abi_selector(sig)`; `eip191_digest(message)`; `eip712_digest(domain, types, primary, message)`.
- Solana (pure): `solana_message(params)` (legacy + `"version": 0`; `lookup_tables` → error) / `solana_tx(msg, sigs)`; `int_to_bytes_le(n, size)` for instruction data; `solana_pda(seeds, program)` → `{address, bump}`; `spl_ata(owner, mint, token_program?)`; `spl_transfer_data(amount)` / `spl_transfer_checked_data(amount, decimals)`.
- Algorand (pure): `algorand_tx_encode(txn)` / `algorand_tx(txn, sig)` / `algo_address(pubkey_or_secret)`; TXID = `decode(sha512_256(algorand_tx_encode(txn)), "base32")`.
- HD custody [**require wallet**]: `mnemonic_generate(words?, label?)`, `mnemonic_to_seed(mnemonic, passphrase?)`, `mnemonic_from_entropy(entropy, label?)` / `mnemonic_to_entropy(mnemonic)`, `hd_derive(seed, path, curve?, label?)` (`"secp256k1"` default | `"ed25519"` SLIP-0010), `algorand_mnemonic(secret32)` / `algorand_mnemonic_to_key(mnemonic, label?)`, `keystore_import(json, passphrase, label?)` / `keystore_export(secret, passphrase, opts?)` (`opts` = `{"kdf": "scrypt"|"pbkdf2", "n", "r", "p", "c"}`; defaults = Geth scrypt n=262144). ALL return a `secret`; `label?` names it (default: a derived name like `W.seed` / `W/path` — what `wallet`/`sign`/`reveal` scopes match).

**Instinct vs. reality (money code — get these right):**
- keccak256 ≠ SHA3-256 (different padding). Use `keccak256`, not any SHA3.
- ed25519 signs the RAW message (hashes internally, RFC 8032) — do NOT pre-hash.
  secp256k1 takes a 32-byte digest; ed25519 takes the message.
- In the signed tx, r/s are RLP **integers** (minimal, leading zeros stripped), NOT
  32-byte blobs — pasting `slice(sig, 0, 32)` raw makes ~1 in 128 txs invalid.
  `tx_eip1559_raw(tx, sig)` handles v/r/s for you; hand-rolling, use
  `bytes_to_int(slice(sig, 0, 32))`; `int_to_bytes(n, 32)` restores the fixed width.
- An RPC node is UNTRUSTED input: it can lie, be compromised, or return garbage. The
  read-side decodes strictly (a non-canonical hex-quantity, a wrong shape, a >16 MiB
  response → catchable error) — but WHICH node you trust is your decision; Synsema
  gives you the primitive, not the trust.
- Broadcasting (`eth_send_raw`/`solana_send`/`algorand_send`) is `net`-gated, NOT
  `sign`-gated: the signature already happened upstream and without a valid one the
  node rejects the bytes. That split is useful: a read-only monitor agent holds `net`
  but not `sign` and cannot spend.
- A receipt/status is INCLUSION, not success: check `receipt["status"]` (1 ok, 0
  reverted) and Solana `status["err"]` (`nothing` = ok) — a tx can land AND fail.
- Algorand's suggested `fee` is PER BYTE (often 0); the real flat minimum is
  `min_fee` (1000 µAlgo). Confusing them = rejected tx or overpaid fee — that's why
  `algorand_params` returns BOTH.
- `tx_eip1559` has NO fee/gas defaults on purpose: every value-moving field is
  explicit (read it from the chain or state it) and echoed back in the result map —
  show the numbers in a `confirm` BEFORE `secp256k1_sign(tx["digest"], k)`.
- Strict by default: `rlp_decode` rejects non-canonical encodings (like Ethereum's
  decoders); `ed25519_verify` is verify-strict (rejects small-order keys — what the
  chains reject). If either says no, the input is malformed, not the builtin.
- Signing needs `require sign("KEY_NAME")` (scoped to the secret's name) + writes an
  audit entry; deny-by-default; DENIED inside `sandbox`. Everything else is pure.
- The key is a `secret`, never a plain string. A text secret = hex (with/without 0x);
  a bytes secret = raw. Errors describe size/shape, never the key value.
- A top-level `secret` is REDACTED when it crosses into a cron job / spawned agent
  (safe, unusable there) — resolve the key INSIDE the task body.
- ABI signatures are CANONICAL: no spaces, no parameter names — `"transfer(address,uint256)"`.
  A malformed signature = a different selector = a silent call to a nonexistent function;
  `abi_encode`/`abi_selector` reject it (and normalize `uint`→`uint256`).
- uint256 amounts need EXACT integers — big int literals just work; floats are rejected
  (`1e24` as a float is not exact money).
- Algorand msgpack is CANONICAL: keys sorted bytewise and zero/empty/false fields OMITTED
  (`amt: 0` disappears — that's what the network requires; otherwise the TXID differs).
- Solana does NOT keep your account order: fee payer first, then writable signers,
  ro signers, writable non-signers, ro non-signers (buckets sorted by pubkey bytes,
  matching the official SDK). The compiled indices point at the reordered table.
- v0 Solana messages carry the 0x80 version prefix and the signature COVERS it —
  `solana_message({..., "version": 0})` already includes it; just `ed25519_sign` the bytes.
- Custody (`require wallet`) is SEPARATE from signing (`require sign`): `wallet` creates
  keys (mnemonic/seed/HD/keystore), `sign` moves value. An agent can derive addresses
  without being able to spend. Both deny-by-default, audited, DENIED in `sandbox`, scoped
  to the source secret's name.
- BIP-32 ≠ SLIP-0010: Solana does NOT derive with plain BIP-32 — `hd_derive(seed, path,
  "ed25519")` (SLIP-0010, hardened-only; a non-hardened index errors). ETH is the default
  `"secp256k1"`. Standard paths: ETH `m/44'/60'/0'/0/i`, Solana `m/44'/501'/i'/0'`.
- Algorand does NOT use BIP-39: its wallet phrase is a 25-word format (checksum over the
  key via sha512_256), `algorand_mnemonic`/`_to_key` — feeding it to `mnemonic_to_seed`
  is wrong. The BIP-39 12/24-word path is for ETH/Solana.
- The mnemonic/seed/derived key is a `secret`, not a string — `text()`/`json_encode` show
  `secret(NAME)`/`[redacted]`, never the value. Back a phrase up on purpose with
  `reveal()` (gated by `reveal("NAME")` + audited). A bad checksum/passphrase → error
  that never echoes the material.
- All pure-Rust (k256/ed25519-dalek/sha3/bech32/bip39/scrypt/aes), zero `*-sys`. Chains:
  ETH + Avalanche-C + Solana + Algorand END-TO-END (read → build → sign → send → confirm,
  SDK-exact), with HD custody + keystore V3 import/export + Solana PDAs/SPL; Avalanche
  X/P signable. Not yet: Avalanche X/P serialization helpers, Bitcoin, typed
  `eth_subscribe` over WS (composable in userland with `ws_connect` + `eth_rpc`-style
  JSON, see the WebSocket section).

## Capabilities

HTTP requires `net` capability. Database requires `db` capability. Signing requires
`sign(KEY_NAME)` capability.

```
require net("api.store.com")
require db("./store.db")
require sign("HOT_KEY")
```

## Platform

- HTTP, SQL, Cron: work on Linux, Windows, Mac.
- Single static binary (the one C dependency is bundled SQLite in `rusqlite`, which needs a C
  compiler at build time on Windows). Numeric deps (`libm`, `num-complex`, `ndarray`, `faer`) and the
  remote DB drivers (`postgres`, `mysql`, `mongodb` — all TLS via rustls/ring) are pure-Rust — no
  OpenSSL/`*-sys`.
