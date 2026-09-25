# Synsema Standard Library — HTTP, Database, Cron

Synsema is a **Rust** language (the `synsema/` Python tree is frozen; Rust is the source of truth).
Single static binary. The HTTP server runs on an async `hyper`/`tokio` stack; bundled SQLite via
`rusqlite`. For numeric/scientific builtins (bytes, complex, special math, arrays + linear algebra)
see [builtins.md](builtins.md).

> **This file is long (~700 lines) — jump to the `## ` section you need instead of reading it all:**
> HTTP · WebSocket (live feeds) · Database (SQL / MongoDB / Redis) · Data analysis (tables, files,
> dates, seeded randomness, lineage) · Cron (Scheduled Tasks) ·
> Serve mode (keep crons alive) · Blockchain (ETH/Avalanche/Solana/Algorand/Bitcoin) ·
> Capabilities · Platform

## HTTP

```
-- Full control. Don't hardcode credentials: pass a `secret` (materialized at the
-- socket, redacted in logs). bearer() builds the Authorization: Bearer <token> value.
let r be http("POST", "https://api.store.com/orders",
    {"Authorization": bearer(secret("STORE_API_KEY")), "Content-Type": "application/json"},
    {"page": "1"},
    json_encode({"product": "laptop", "quantity": 1})
)

-- Shorthands
let r be http_get("https://api.store.com/products")
let r be http_get(url, {"Authorization": bearer(secret("STORE_API_KEY"))}, {"page": "1"})
let r be http_post(url, {"name": "Alice"}, {"Authorization": bearer(secret("STORE_API_KEY"))})  -- a map → JSON + Content-Type (v0.6.20+)
let r be http_put(url, {"name": "Bob"})
let r be http_delete(url, {"x-api-key": secret("STORE_API_KEY")})  -- any header, not just Bearer
```

> **The body is sent by TYPE (v0.6.20+).** A **map or list** goes out as JSON with
> `Content-Type: application/json` (your own `Content-Type` header wins); **text** goes out as-is,
> no content type added; **bytes** raw. On engines ≤ v0.6.19 a map was sent as its display text
> (`{name: Alice}`) with no header — `json_encode(map)` + the header still works on every version.
> Verified against a local `serve` echo route (engine v0.6.20).

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
> See **[secrets.md](secrets.md)**. A URL with `user:pass@` sends `Authorization: Basic …`
> (percent-decoded to raw bytes, like curl; your own `Authorization` header wins) — v0.6.29+. A
> URL with no host (`http://alice:pw@/rpc`) is the error `the URL has no host`, which never echoes
> the URL; `require net("https://user:pw@api.x.com/v1?k=…")` is stored as `net("api.x.com")`
> (credentials, port, path and query are dropped from the scope), `require net("[::1]")` =
> `net("::1")`.

**HTTPS works**: `http://` and `https://` are both supported (TLS via `rustls` with the OS
root CAs — real certificate validation, pure-Rust). So `http_get("https://api.example.com")`
is fine for real-world APIs. **All HTTP (`http*` and `fetch`) is gated by `net(host)`** (deny-by-default,
even in `run`): `require net("host")` — see capabilities.md. `require net` / `net("*")` = any host.

Response is always a map with exactly these keys (verified v0.6.20: `keys(r)` on a normal
response is `[status, ok, body, json, headers]`; `json` exists since v0.6.20):
```
status of r      -- 200
ok of r          -- true (200-299)
body of r        -- raw text — ALWAYS text (a binary body is lossy: use http_bytes)
json of r        -- the parsed body when the content type says JSON and it parses; else nothing (v0.6.20+)
headers of r     -- response headers map, names exactly as the server sent them
error of r       -- ONLY present when the transport failed (DNS, refused, timeout)
```

- `json of r` is `nothing` for text/HTML/binary responses — never an error. Branch on it, or keep
  `json_decode(body of r)` under `try`/`recover` for a server that lies about its content type.
- **Binary bodies:** `http_bytes(method, url, headers?, query?, body?, timeout?)` (v0.6.20+) has the
  signature of `http` and returns `{status, ok, bytes, headers}` — the exact bytes, no `body` key.
- **File uploads:** `multipart_encode(parts)` → `{body: bytes, content_type}` (v0.6.20+, pure,
  deterministic boundary); `parts` = `[{"name", "value"} | {"name", "filename", "content_type"?, "bytes"}]`;
  send with `http_post(url, body of m, {"Content-Type": content_type of m})`. A Synsema `serve`
  reads it as `form of request`. Built in memory (no streaming of huge files).
- `error of r` does **not** exist on a normal response, not even a 404/500 — reading it is
  `Map has no key 'error'`. Branch on `ok of r` / `status of r`, or `contains(r, "error")`.
- Header names keep the server's casing (`Content-Type` from GitHub, `content-type` from your
  own `serve`). Look one up without guessing:
  ```
  task header(r, name)
      each k in keys(headers of r)
          when lower(k) == lower(name)
              give (headers of r)[k]
      give nothing
  ```

## WebSocket (live feeds — general transport, not just blockchain)

A synchronous WebSocket **client** for anything that streams: RPC subscriptions,
exchange fills, Discord/Slack, mempool. Replaces cron+polling with a live feed. Gated by
the SAME `net(host)` capability and scope as HTTP (deny-by-default, denied in `sandbox`);
`wss://` validates the server cert against the OS root CAs like `https://`.

> **Incoming WebSockets** (a WS *server*) are a `route … socket` block under `serve`
> (engine v0.6.7+): the same `ws_*` family works on the incoming handle, and `select`
> waits on sockets + child processes + the event bus at once — see [serve.md](serve.md)
> § WebSocket routes and [concurrency.md](concurrency.md) § `select`.

```
require net("stream.exchange.com")
let conn be ws_connect("wss://stream.exchange.com/ws")   -- opaque handle; headers? + opts? optional
ws_send(conn, json_encode({"op": "subscribe", "channel": "trades"}))  -- text or bytes
let msg be ws_recv(conn, 5)         -- next message, or `nothing` after the 5s timeout (never blocks forever)
-- msg is {"type": "text"|"binary"|"close", "data": …}
when msg != nothing and msg["type"] == "text"
    print(msg["data"])
ws_close(conn)                      -- clean close frame (idempotent)
```

- `ws_connect(url, headers?, opts?)` → handle. `headers` is a text→text map (a `secret`
  value materializes only at the socket, like HTTP). `opts`: `{"timeout", "max_message_size"
  (16 MiB default, 64 MiB ceiling), "subprotocols" (list → negotiate Sec-WebSocket-Protocol),
  "max_queue" (inbound cap in MESSAGES, default 1024), "max_queue_bytes" (inbound cap in
  BYTES, default 64 MiB, ceiling 1 GiB — the queue is bounded in BOTH dimensions),
  "on_full", "reconnect", "keepalive"}`.
- `ws_recv(conn, timeout?)` → the message map, or **`nothing`** on timeout (default 30s).
  NEVER blocks forever; ping/pong handled transparently.
- `ws_send(conn, data)` / `ws_close(conn)`. A dead connection errors on send/recv (the
  handle is retired) — atrapable with `try`/`recover`.

**Multiplexing thousands of feeds — `ws_select` (the event-loop primitive).** Watch M
connections from ONE thread, react to the first ready, no thread-per-connection. This is
Go's `select {}` over channels, in one call. Readiness-driven (epoll/kqueue/IOCP via `mio`):
CPU ~0 while idle, scales to thousands.

```
require net("feed.example.com")
let feeds be {"trades": ws_connect("wss://feed.example.com/trades"),
              "book": ws_connect("wss://feed.example.com/book")}  -- name→handle map
let live be true
while live
    let m be ws_select(feeds, 30)        -- first ready of ALL feeds, or nothing on timeout
    when m == nothing
        set live to false                 -- 30s idle → done (tune to your feed)
    when m != nothing
        -- m adds "conn" (WHICH handle fired) and, for a map, "name"
        when m["type"] == "close"
            print("feed " + m["name"] + " dropped")   -- you know exactly which one
        when m["type"] == "text"
            print(m["name"] + ": " + m["data"])
```

- `ws_select(conns, timeout?)` → `{conn, type, data, name?}` of the first ready connection,
  or `nothing` on timeout. `conns` is a list of handles **or** a name→handle map (then the
  result carries `name`). Delivery is **round-robin fair**: a chatty feed with a backlog
  cannot starve the others. A connection that drops surfaces as `{type: "close", conn}` and is
  retired — you know WHICH to resubscribe. A fatal protocol error surfaces as a catchable error.
- `ws_select_all(conns, timeout?)` → a list of every message ready this tick (one per
  connection; batch processing).
- `ws_broadcast(conns, data)` → send the same message to many connections at once → count sent.

**Resilience (opt-in — without these, batch-13 behavior is unchanged, nothing silent):**
- `"reconnect": {"max_retries"?, "backoff"?, "backoff_max"?, "on_reconnect"?}` — transparent
  reconnection with bounded exponential backoff. `on_reconnect` is a **task** run after
  reconnecting (it receives the handle) — resubscribe there so you never lose your feed state.
  Every reconnect re-checks `net(host)` (never escalates scope) and `wss` re-validates the cert.
- `"keepalive": {"interval", "timeout"?}` — auto-ping every `interval`; no pong within `timeout`
  → the connection is dead → reconnect (if enabled) or `close`. **Half-open detection** most
  libraries skip.
- `ws_status(conn)` → `"open" | "reconnecting" | "closed"`; `ws_stats(conn)` →
  `{sent, received, reconnects, queued, queued_bytes, last_pong_ago (seconds since the
  last pong, nothing if none yet), status, subprotocol}`. Stats never lie: `sent` counts
  only messages that went out (or got queued for flush), never failed sends.
- `on_full` (what happens when the inbound queue hits max_queue/max_queue_bytes):
  `"block"` (default — real TCP backpressure: stop reading the socket, the TCP window
  throttles the peer; no loss), `"drop_oldest"` (evict oldest until the new one fits),
  `"error"` (TERMINAL: already-queued messages drain first, then a catchable error
  naming the overflow — NEVER a silent drop; no reconnect, the condition is local).
  Inbound traffic of any kind counts as liveness for keepalive — a pong delayed behind
  a busy feed never falsely kills a live connection.

**Fan-out with `parallel_map` (thousands of feeds across the pool).** Each worker gets its
own interpreter (inheriting caps) and its OWN WebSocket registry — a worker `ws_connect`s its
feed, processes it, returns. Handles do NOT cross workers (CSP isolation): never share a handle.

```synsema
task watch(url)
    let c be ws_connect(url)
    let m be ws_recv(c, 30)
    ws_close(c)
    give m
let results be parallel_map(watch, thousands_of_urls)   -- N workers × 1 conn each
```

- **Under `serve`:** a handler can open an outbound WS and forward it over SSE — the
  "WS→SSE bridge". (Accepting *incoming* WS connections is a separate feature; chat/
  notifications already ship with POST+SSE — see serve.md.) `ws_select` also works inside a
  handler to multiplex several outbound WS on its thread.
- **`eth_subscribe` (newHeads/logs) is composable in userland today:** `ws_connect` to the
  node's WS endpoint, `ws_send` the JSON-RPC subscribe frame, `ws_recv`/`ws_select` the
  notifications (parse with `json_decode`; decode each log with `abi_decode_log`); one-shot reads
  go through the typed read-side (`evm_logs`, `evm_receipt` — stdlib.md § Blockchain) instead.

## Web Push (installable apps notify their users — engine v0.6.15+)

Native Web Push: the server encrypts a message for ONE browser (RFC 8291 `aes128gcm`) and
hands it, signed with your VAPID key (RFC 8292), to that browser's push service (RFC 8030).
Gate: **`net(<host of the subscription endpoint>)`** — the push service is a host like any
other; the private VAPID key is accepted **only as a `secret`**. Full reference (every
option, return fields, the four push-service hosts) in [builtins.md](builtins.md) § Web Push;
the browser side and the scaffold in [serve.md](serve.md) § Installable app (PWA).

```synsema
require random                          -- keygen, once (push_keys.syn from `synsema init --pwa`)
require reveal("vapid_private")
let k be push_vapid_keys()              -- {public: text, private: secret}
print("VAPID_PUBLIC_KEY=" + k["public"] + "\nVAPID_PRIVATE_KEY=" + reveal(k["private"]))
```

```
require secret("VAPID_PRIVATE_KEY")
require env("VAPID_PUBLIC_KEY")
require net("fcm.googleapis.com")       -- Chrome/Android (Chrome also hands out jmt17.google.com);
require net("jmt17.google.com")         -- add *.notify.windows.com (Edge),
require net("web.push.apple.com")       -- updates.push.services.mozilla.com (Firefox), Apple
let vapid be {"public": env("VAPID_PUBLIC_KEY"), "private": secret("VAPID_PRIVATE_KEY"), "subject": "mailto:ops@example.com"}
each sub in sql("SELECT endpoint, keys FROM push_subs")
    let r be push_send({"endpoint": sub["endpoint"], "keys": json_decode(sub["keys"])},
        {"title": "Report ready", "url": "/reports/today"}, {"vapid": vapid, "ttl": 3600, "topic": "report"})
    when r["gone"]                      -- 404/410: the browser unsubscribed → forget it
        sql_exec("DELETE FROM push_subs WHERE endpoint = ?", [sub["endpoint"]])
```

`payload`: text · map/list (JSON) · bytes · `nothing` (no body); ≤ 3993 bytes. Returns
`{status, ok, gone, retry_after, body}`. A provider you already use (OneSignal/FCM/Pusher)
keeps working through `http_post` — native push is optional. Not available in the wasm/pure
profile (needs sockets); `push_vapid_keys` is.

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
let row be sql("INSERT INTO users (name) VALUES (?) RETURNING id", ["Ada"])   -- rows back: sql, not sql_exec
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
```synsema
require db("./vec.db")
task to_vec(s)
    give array(apply((x) => number(x), split(s, ",")))
task cosine(a, b)
    give dot(a, b) / (norm(a) * norm(b))

let q be array(query_embedding)                  -- from an embeddings API (http_post) or a model (run)
let rows be sql("SELECT title, emb FROM docs")   -- pre-filter by metadata in SQL if you want
let scored be apply((r) => {"title": r["title"], "score": cosine(to_vec(r["emb"]), q)}, rows)
let top be sort_by(scored, (x) => x["score"], desc = true)  -- best first
```
For real ANN at scale: delegate to a server that does vectors (pgvector via a Postgres HTTP API, or
ClickHouse over HTTP) and query it with `fetch` — the index runs server-side, no in-process extension.

## Data analysis (v0.6.29+ — tables, file formats, dates, seeded randomness, lineage)

What pandas/polars/numpy do, as plain builtins (all pure except reading the files). **A table is a
list of maps** — the exact shape `sql()`, `mongo_find`, `csv_parse`, `parquet_read` and
`jsonl_decode` return — so a query result goes straight into the same pipeline as a file.

```synsema
require db("./shop.db")
require file.write("./out/*")
db_open("./shop.db")

-- SQL rows are already a table; nothing = NULL = missing
let orders be sql("SELECT region, amount, created FROM orders")
let clean be drop_missing(orders, "amount")
let by_region be summarize(clean, "region", {"total": sum_of("amount"), "orders": count(), "p90": quantile_of("amount", 0.9)})
let ranked be sort_by(by_region, (r) => r.total, desc = true)
write_file("./out/by_region.csv", csv_encode(ranked))
write_file("./out/by_region.parquet", parquet_write(ranked))
write_file("./out/by_region.svg", chart_svg("bar", ranked, {"x": "region", "y": "total"}))
```

- **File formats:** CSV (`csv_parse` with `{"types": {...}}` — an empty field is `nothing`),
  JSON Lines (`jsonl_encode`/`jsonl_decode`), Parquet (`parquet_read(bytes)`/`parquet_write(rows,
  opts?)`, zstd/snappy/gzip/lz4, native only). Bytes/text in and out; the disk is
  `read_file`/`read_file_bytes`/`write_file` with `file.read`/`file.write`.
- **Tables:** `group_by` → `[{key, items}]`, `summarize` + `sum_of`/`mean_of`/`min_of`/`max_of`/
  `median_of`/`quantile_of`/`first_of`/`n_unique_of`/`count()`, `count_by`, `join` (inner/left/right/outer/semi/anti),
  `pivot`, `is_missing`/`count`/`count_missing`/`fill_missing`/`drop_missing`/`fill_nan`.
- **Reductions** (`sum`, `mean`, `median`, `std`, …): `nothing` skipped, NaN propagates, `axis =`
  on arrays, `std`/`var` sample (`ddof = 1`), decimals stay decimal.
- **Dates:** `date` / `datetime` (IANA zone, DST-aware) / `duration` types; `truncate(d, "month")` to
  group by period; `date_range`, `add_months`, `parse_date`/`parse_datetime`, `to_timezone`. Pure —
  only `now()` needs `require time`. A SQL `created` column arrives as whatever the driver gives
  (text or number) — re-type it with `datetime(x)` / `datetime(ts)`.
- **Seeded randomness:** `let g be rng(42)` → `g()`, `random_int(g, lo, hi)`, `random_normal(g)`,
  `shuffle`/`sample`/`choice(g, …)`, `rng_spawn(g, n)` — the same numbers as
  `numpy.random.default_rng(42)`, no capability (train/test splits, simulations).
  `parallel_map(f, rng_spawn(g, n))` gives each worker a copy of its own child (numpy's
  `g.spawn(n)`); one generator in two items is an error.
- **Lineage:** the engine records every read (`read_file`/`list_dir`/`grep`/`parquet_read`, HTTP host,
  the hash of each SQL/Mongo/Redis query, chain RPC reads, socket/process messages, model answers,
  stdin, what `run`/`run_program` returned) → `lineage()`, and `receipt()` publishes it as
  `inputs` — sign it to prove which data produced the result. Each entry's `encoding` (`text`,
  `bytes`, `jcs`, `json`) says which bytes the sha256 covers, so it can be recomputed.

Contracts and examples: [builtins.md](builtins.md) § Tables, § Reductions, § Dates, § Seeded
randomness, § Parquet, § Lineage; the step-by-step pipeline and the missing-data model:
[dataviz.md](dataviz.md) § Data analysis.

## Cron (Scheduled Tasks)

Background scheduler. Non-blocking. Each job runs its task for real on its own thread
(parked between ticks — zero CPU); the counters in `cron_list()` reflect real executions.

```
-- Repeat every N seconds
task sync_inventory()
    let data be http_get("https://api.warehouse.com/stock")
    share data as "inventory"

cron_every(300, sync_inventory)    -- every 5 minutes (interval: end → next start)

-- Wall-clock: a cron expression (5 fields) or an alias; UTC unless `tz` says otherwise
task daily_report()
    log "report"

cron_every("0 9 * * *", daily_report)                         -- every day 09:00 UTC
cron_every("30 8 * * mon-fri", daily_report, {"tz": "-03:00"}) -- weekdays 08:30 in a fixed -03:00 offset
cron_every("*/15 * * * *", sync_inventory)                    -- :00 :15 :30 :45, aligned (an interval of 900 would drift)
cron_every("@hourly", rotate_logs)    

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
- **Two kinds of schedule, one door.** A number = interval: fixed delay between the END of
  one run and the start of the next (drifts by the run's duration — fine for "every 6 h").
  A text = **cron expression**: `minute hour day month weekday` (`*`, `a-b`, `*/n`, lists,
  `jan..dec`/`sun..sat`, `0`/`7` = Sunday; day AND weekday both restricted → either matches,
  Vixie rule) or `@hourly`/`@daily`/`@weekly`/`@monthly`/`@yearly`. Fires at the next matching
  minute (seconds = 0) **after the previous run ends** — occurrences that fall while a run is
  in progress are skipped, not queued. Either way a job never overlaps itself.
- **Time zone: UTC by default** (like every `time` builtin). `{"tz": "-03:00"}` / `"+05:30"` is a
  fixed offset; `{"tz": "America/Santiago"}` is an IANA zone and follows its clock changes with the
  rule every Linux cron uses (Vixie cron / cronie): a FIXED time (`30 2 * * *`) that falls in the
  skipped spring hour runs right after the jump (not lost); in the repeated autumn hour it runs
  once, the first time. A job with `*` in the minute or hour field (`*/15 * * * *`, `0 * * * *`)
  follows real time: skipped minutes do not exist, the repeated hour runs twice. A numeric text
  (`"300"`) is still an interval.
- `cron_every` requires interval > 0; `cron_after` accepts delay ≥ 0. A bad expression, an
  expression that never matches (`0 0 31 2 *`), an unknown `tz`, or options with an interval
  → error **at registration** (the job is not created).
- Same name re-registered → **replaces** the old job (counters restart at 0).
- Errors: `errors`+1, one log line (`[serve] [cron] job 'x' failed: …`), the job stays
  scheduled and the process stays up. `run_count` counts COMPLETED runs only.
- `cron_list()` entries: `{name, schedule, interval, repeating, active, run_count, errors,
  next_run, tz}` — `next_run` is the unix timestamp of the next fire (`interval`/`tz` are
  `nothing` when they don't apply). `cron_status()` prints `at '0 9 * * *' (UTC), next <ISO>`.
- In-memory, no persistence/catch-up: a restart re-registers with run_count = 0, and runs
  missed while the process was down do not exist. If you need "it ran late", keep `last_run`
  yourself (a file or a table) and compare it with `next_run` on start — see patterns.md.
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

## Blockchain (read → build → sign → send → confirm — ETH/Avalanche/Solana/Algorand/Bitcoin)

Operate on-chain from an agent with the private key sealed as a `secret` that NEVER
materializes. The full autonomous loop: READ what you need (nonce/fees/blockhash/params),
BUILD the tx, SIGN it (the ONE gated door), SEND it, CONFIRM it — no hand-rolled
JSON-RPC, no hex-quantity bugs. Reading/sending is `net(host)`-gated (same capability
as `http_*`); ONLY signing moves value — a monitor agent with `net` can read everything
and spend nothing.

**Names follow `<family>_<action>`** (v0.6.29+): `evm_*` (every EVM chain — Ethereum, Avalanche C,
L2s), `solana_*`, `algorand_*`, `btc_*`; the action is `tx` (build the bytes to sign), `tx_raw`
(assemble the signed tx), `send`, `wait`, `address`. The old names (`eth_nonce`, `tx_eip1559`,
`solana_message`, `solana_confirm`, `algorand_tx_encode`, `algo_address`…) still run as deprecated
aliases until v1.0 and `synsema check` warns — table in [builtins.md](builtins.md) § Renamed in
v0.6.29. JSON-RPC **method** names passed to `evm_rpc` stay as the node spells them (`"eth_call"`,
`"eth_getLogs"`).

```
require net("rpc.example.com")
require sign("HOT_KEY")   -- signing is deny-by-default + audited (NOT ambient)
let k be as_secret("<hex>", "HOT_KEY")   -- or secret("HOT_KEY") from .env
let url be "https://rpc.example.com"

-- EVM end-to-end: read → build (evm_tx) → sign → assemble → send → confirm
let nonce be evm_nonce(url, evm_address(k))      -- eth_getTransactionCount ("pending")
let fees be evm_fee_history(url)                 -- {base_fee, priority, base_fees, rewards}
let tx be evm_tx({"chain_id": evm_chain_id(url), "nonce": nonce,
    "to": dest, "value": 10**17, "gas": 21000,   -- 0.1 ETH in wei: 10**17, never 1e17 (a float)
    "max_fee": fees["base_fee"] * 2, "max_priority": fees["priority"]})
-- tx echoes every value-moving number (tx.max_fee, tx.value, tx.to) —
-- show them in a `confirm` BEFORE signing (anti blind-signing, extended to fees)
let sig be secp256k1_sign(tx.digest, k)          -- bytes(65) r‖s‖v (v = 0/1); RFC6979, low-s
let raw be evm_tx_raw(tx, sig)                   -- assembles 0x02||rlp(...+[v,r,s]) for you
let hash be evm_send(url, raw)                   -- "0x…" tx hash (net-gated: already signed)
let receipt be evm_wait(url, hash, 1, 120)       -- bounded poll; nothing on timeout
-- receipt["status"] == 1 → success; 0 → REVERTED (it landed but failed — always check)

-- read contract state: evm_call returns RAW bytes → abi_decode
let calldata be abi_encode("balanceOf(address)", [owner])
let bal be abi_decode("uint256", evm_call(url, {"to": token, "data": calldata}))[0]
let d712 be eip712_digest(domain, types, "Permit", permit_map)  -- readable maps in
let wallet_sig be evm_signature(secp256k1_sign(d712, k))       -- v = 27/28: what permit/ecrecover want

-- deploy a contract: evm_tx_create computes where it lands and checks the signer
let me be evm_address(k)
let init be bytecode + abi_encode("(address,uint256)", [owner, 10**24])  -- constructor args, no selector
let ctx be evm_tx_create({"chain_id": evm_chain_id(url), "nonce": evm_nonce(url, me),
    "from": me, "value": 0, "gas": 1500000,
    "max_fee": fees["base_fee"] * 2, "max_priority": fees["priority"], "data": init})
print(ctx.contract_address)                      -- == evm_create_address(me, ctx.nonce), EIP-55
let dh be evm_send(url, evm_tx_raw(ctx, secp256k1_sign(ctx.digest, k)))  -- errors if the signer is not `from`

-- events: logs → maps by parameter name
let transfer be {"name": "Transfer", "inputs": [
    {"name": "from", "type": "address", "indexed": true},
    {"name": "to", "type": "address", "indexed": true},
    {"name": "value", "type": "uint256", "indexed": false}]}   -- the fragment from the contract's ABI JSON
let head be evm_block_number(url)
let logs be evm_logs(url, {"address": token, "topics": [abi_event_topic(transfer)],
    "fromBlock": hex(head - 1000), "toBlock": "latest"})
each lg in logs
    let ev be abi_decode_log(transfer, lg)       -- {from, to, value}
    print(ev.from + " → " + ev.to + ": " + text(ev.value))

-- Solana end-to-end: blockhash → message → ed25519_sign → tx → send → confirm
let bh be solana_latest_blockhash(url)           -- bytes(32), feeds solana_tx directly
let msg be solana_tx({"fee_payer": payer, "recent_blockhash": bh,
    "instructions": [{"program": "11111111111111111111111111111111",
        "accounts": [{"pubkey": payer, "signer": true, "writable": true},
                     {"pubkey": dest_pk, "writable": true}],
        "data": int_to_bytes_le(2, 4) + int_to_bytes_le(lamports, 8)}]})
let stx be solana_tx_raw(msg, ed25519_sign(msg, k))
let signature be solana_send(url, stx)           -- base58 signature text
let status be solana_wait(url, signature, 60)    -- waits confirmed/finalized; nothing on timeout
-- status["err"] == nothing → success; anything else = landed but FAILED on-chain

-- Algorand end-to-end: params → canonical msgpack → sign → send (BINARY) → wait
let p be algorand_params(url)   -- {fee (PER-BYTE, often 0), min_fee (flat), fv, lv, gh, gen}
let txn be {"type": "pay", "snd": algorand_address(k), "rcv": rcv, "amt": 123456,
    "fee": p["min_fee"], "fv": p["fv"], "lv": p["lv"], "gh": p["gh"], "gen": p["gen"]}
let stx be algorand_tx_raw(txn, ed25519_sign(algorand_tx(txn), k))
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
let ethk be hd_derive(seed, "m/44'/60'/0'/0/0")  -- secret: BIP-32 secp256k1 (default) → use with evm_address/secp256k1_sign
let solk be hd_derive(seed, "m/44'/501'/0'/0'", "ed25519")  -- secret: SLIP-0010 (Solana; hardened-only)
print(evm_address(ethk))                         -- derive the PUBLIC address (no gate)
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

**Bitcoin — the UTXO matrix (spend FROM P2WPKH/P2TR key-path, send TO any standard type):**
Bitcoin is NOT an account chain — the fee is IMPLICIT (inputs − outputs), so forgetting the
change output DONATES the remainder to miners. `btc_tx` makes that structurally impossible
(G28: `sum(inputs) == sum(outputs) + fee`, fee declared, or an error naming the exact diff).
You sign ONCE PER INPUT (BIP-143 for P2WPKH, BIP-341 Schnorr for P2TR — `btc_tx` picks the
right sighash). `schnorr_sign` uses the SAME `sign` gate — no new capability.
```
require net("blockstream.info")
require sign("HOT")
let url be "https://blockstream.info/api"
let k be secret("HOT")
let addr be btc_address(k)                       -- P2WPKH (BIP-84) default; "p2tr"/"p2pkh" too
-- READ → BUILD → SIGN → SEND → CONFIRM
let utxos be btc_utxos(url, addr)                -- [{txid, vout, amount, confirmations}]
let tx be btc_tx({"inputs": [{"txid": utxos[0]["txid"], "vout": utxos[0]["vout"],
        "amount": utxos[0]["amount"], "address": addr, "pubkey": secp256k1_pubkey(k)}],
    "outputs": [{"address": dest, "amount": 20000},
                {"address": addr, "amount": utxos[0]["amount"] - 20000 - 500}],  -- CHANGE (explicit!)
    "fee": 500})                                 -- tx echoes fee/vsize/total_in for a confirm
let sig be secp256k1_sign(tx["digests"][0], k)   -- one sig per input, same order
let raw be btc_tx_raw(tx, [sig])                 -- witness assembled (DER+SIGHASH_ALL, low-s)
let txid be btc_send(url, raw)                   -- re-checks the node's txid vs the bytes
let info be btc_wait(url, txid, 1, 600)          -- bounded poll; nothing on timeout
-- Taproot key-path: the BIP-341 tweak is applied INSIDE schnorr_sign (never by hand)
let sigt be schnorr_sign(tx_taproot["digests"][0], kt, "taproot")
-- PSBT cold custody: agent PREPARES, human signs on hardware wallet, agent finalizes
let psbt be psbt_encode(tx)                       -- base64, importable in Sparrow/Ledger/…
let audit be psbt_decode(signed_psbt)             -- {inputs, outputs, amounts, fee, complete}
let raw2 be psbt_finalize(signed_psbt)            -- → btc_send (the key never touched the agent)
```

**Read-side / RPC builtins (all `net(host)`-gated; a node is UNTRUSTED input — every
decode is strict, malformed/oversized/hostile responses → catchable error, never silent
bad data; errors name the host only, never the full URL — API keys live in the path; the raw
answers of `evm_rpc`/`solana_rpc`/`btc_rpc`/`algorand_account`/`algorand_wait` keep integers beyond
64 bits exact):**
- EVM JSON-RPC: `evm_rpc(url, method, params?)` (escape hatch: ints→hex-quantity,
  bytes→`0x…`, result as decoded JSON; `method` = the node's name, `"eth_…"`);
  `evm_block_number(url)` → int; `evm_nonce(url, addr, block?)` (default `"pending"`);
  `evm_balance(url, addr, block?)` → exact wei int; `evm_gas_price(url)`; `evm_chain_id(url)`;
  `evm_estimate_gas(url, tx_map, block?)`; `evm_call(url, {to, data}, block?)` → RAW bytes (feed
  `abi_decode`); `evm_fee_history(url, blocks?, percentiles?, newest?)` → `{base_fee, priority, base_fees,
  rewards}` (base_fee = NEXT block; priority = median of the first percentile column; raw arrays
  included — the derivation is transparent, not an oracle); `evm_send(url, raw)` → `"0x…"`
  hash; `evm_receipt(url, hash)` → typed receipt map or `nothing`;
  `evm_wait(url, hash, confirmations?, timeout?)` → receipt after N confs or `nothing`;
  `evm_logs(url, filter)` → logs decoded like receipt logs (filter = wire names, validated:
  `address` one or a list, `topics` list — each `"0x…"`/bytes32, `nothing` = any, a list = OR —
  and `fromBlock`/`toBlock` **or** `blockHash`, not both). A `block` argument is `"latest"`
  (default) / `"earliest"`/`"pending"`/`"safe"`/`"finalized"` / a number / the node's own
  `"0x…"` quantity (validated canonical, ≤ 256 bits — so `hex(n)` and a value read from the node
  both work). Receipt decoding is typed: quantities→int, addresses→EIP-55 text, hashes→`"0x…"`
  text, log `data`→bytes.
- **EVM L2s work out of the box** (Base, Optimism, Arbitrum, Polygon — same JSON-RPC wire):
  point the `url` at the L2's RPC and READ the chain id with `evm_chain_id(url)` (never
  hardcode it). One honest caveat: on OP-stack chains (Base/Optimism) `evm_estimate_gas`
  covers only the L2 execution — the total cost adds an L1 DATA fee that arrives in the
  receipt as `l1Fee`/`l1GasUsed`/`l1GasPrice` (decoded to exact ints): total paid =
  `gasUsed × effectiveGasPrice + l1Fee`. Arbitrum folds its L1 component into `gasUsed`
  instead (no extra field).
- EIP-1559 builders (PURE): `evm_tx(params)` with `{chain_id, nonce, to, value, gas,
  max_fee, max_priority, data?, access_list?}` — EVERY value-moving field explicit (no
  silent defaults; a missing field errors naming the reader helper; no `to` → error pointing
  to `evm_tx_create`) → `{digest, fields, + echo of every number}`; `evm_tx_raw(tx, sig65)` →
  signed raw bytes (v/r/s handled). `evm_tx_raw` recomputes the digest from `fields` and checks
  every echoed number against them: an edited map → error (`… does not match "fields" — the map
  was modified after evm_tx/evm_tx_create; build it again instead of editing it`).
- Contract creation (PURE): `evm_tx_create({chain_id, nonce, from, value, gas, max_fee,
  max_priority, data, access_list?})` → the `evm_tx` map with `to: nothing` + `from` +
  `contract_address` (EIP-55). `to` → error; empty `data` → error; `data` > 49 152 bytes
  (EIP-3860) → error. `evm_tx_raw` on it recovers the signer and errors if it isn't `from`; a
  creation map without `from` → error, and `contract_address` is re-derived and must match.
  `evm_create_address(sender, nonce)` / `evm_create2_address(deployer, salt32,
  init_code_hash32)` → EIP-55 text (CREATE / EIP-1014 CREATE2, pure).
- Solana RPC: `solana_rpc(url, method, params?)` (escape hatch, plain JSON params);
  `solana_latest_blockhash(url)` → bytes(32); `solana_balance(url, pubkey)` → lamports int;
  `solana_send(url, tx_bytes)` → base58 signature; `solana_wait(url, sig, timeout?)` →
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
- EVM (pure): `evm_address(x)` → EIP-55 text (`x` = pubkey, key secret, 20 raw bytes or `"0x…"` text); `evm_create_address` / `evm_create2_address`; `evm_signature(sig)` → v = 27/28; `rlp_encode(value)` / `rlp_decode(bytes)`; `abi_encode(sig, values)` (selector + args) / `abi_encode(types, values)` (no selector — constructor args; inverse of `abi_decode`) / `abi_decode(types, data)` / `abi_selector(sig)`; `abi_event_topic(sig_or_fragment)` → `"0x…"` text; `abi_decode_log(event_fragment, log, default?)` → map by parameter name; `eip191_digest(message)`; `eip712_digest(domain, types, primary, message)`.
- Solana (pure): `solana_tx(params)` (legacy + `"version": 0`; `lookup_tables` → error) / `solana_tx_raw(msg, sigs)`; `int_to_bytes_le(n, size)` for instruction data; `solana_pda(seeds, program)` → `{address, bump}`; `spl_ata(owner, mint, token_program?)`; `spl_transfer_data(amount)` / `spl_transfer_checked_data(amount, decimals)`.
- Algorand (pure): `algorand_tx(txn)` (bytes to sign) / `algorand_tx_raw(txn, sig)` / `algorand_address(pubkey_or_secret)`; TXID = `decode(sha512_256(algorand_tx(txn)), "base32")`.
- Bitcoin (pure): `hash160(x)` → bytes(20); `btc_address(pubkey_or_secret, kind?, network?)` (`"p2wpkh"` default | `"p2tr"` | `"p2pkh"`; networks mainnet/testnet/signet/regtest); `btc_address_decode(text)` → `{kind, network, program, encoding}` (BIP-350 strict); `btc_script(address)` → scriptPubKey bytes; `btc_txid(raw)` → hex (byte-reversed); `schnorr_sign(digest32, secret, "taproot"?)` [**require sign**] / `schnorr_verify(digest32, sig64, xonly32)` / `schnorr_pubkey(secret)`; `btc_tx(params)` → `{digests, fee, vsize, + echo}` (G28) / `btc_tx_raw(tx, signatures)`; `psbt_encode(tx)` / `psbt_decode(text, network?)` / `psbt_finalize(text)`.
- Bitcoin read-side [**require net**]: `btc_utxos(url, addr)`, `btc_balance(url, addr)`, `btc_fee_estimates(url)`, `btc_send(url, raw)`, `btc_wait(url, txid, confs?, timeout?)`, `btc_rpc(url, method, params?, auth?)` (`auth.pass` may be a secret). `wif_import(text, label?)` [**require wallet**] → secret (no reverse export). HD: `hd_derive(seed, "m/84'/0'/0'/0/0")` BIP-84 / `"m/86'/0'/0'/0/0"` BIP-86 → `btc_address`.
- HD custody [**require wallet**]: `mnemonic_generate(words?, label?)`, `mnemonic_to_seed(mnemonic, passphrase?)`, `mnemonic_from_entropy(entropy, label?)` / `mnemonic_to_entropy(mnemonic)`, `hd_derive(seed, path, curve?, label?)` (`"secp256k1"` default | `"ed25519"` SLIP-0010), `algorand_mnemonic(secret32)` / `algorand_mnemonic_to_key(mnemonic, label?)`, `keystore_import(json, passphrase, label?)` / `keystore_export(secret, passphrase, opts?)` (`opts` = `{"kdf": "scrypt"|"pbkdf2", "n", "r", "p", "c"}`; defaults = Geth scrypt n=262144). ALL return a `secret`; `label?` names it (default: a derived name like `W.seed` / `W/path` — what `wallet`/`sign`/`reveal` scopes match).

**Instinct vs. reality (money code — get these right):**
- keccak256 ≠ SHA3-256 (different padding). Use `keccak256`, not any SHA3.
- ed25519 signs the RAW message (hashes internally, RFC 8032) — do NOT pre-hash.
  secp256k1 takes a 32-byte digest; ed25519 takes the message.
- The recovery byte `v` has two conventions. `secp256k1_sign` returns the RAW one, 0/1 (go-ethereum
  `crypto.Sign`, libsecp256k1, typed EIP-1559 txs — `evm_tx_raw` wants exactly that). Anything a
  CONTRACT verifies — `ecrecover`, OpenZeppelin `ECDSA.recover`, an EIP-2612 `permit`, an EIP-712
  authorization — and every wallet (MetaMask / ethers / viem `personal_sign`, `signTypedData`) uses
  27/28: `evm_signature(sig)` converts (idempotent; any other `v` → error). The other way needs
  nothing: `secp256k1_recover` accepts 0, 1, 27 and 28 (v ≥ 35 — a legacy EIP-155 value — is an
  error that says so); `secp256k1_verify` ignores `v`. (≤ v0.6.28: add/subtract 27 by hand,
  `slice(sig, 0, 64) + bytes([sig[64] + 27])`.)
- In the signed tx, r/s are RLP **integers** (minimal, leading zeros stripped), NOT
  32-byte blobs — pasting `slice(sig, 0, 32)` raw makes ~1 in 128 txs invalid.
  `evm_tx_raw(tx, sig)` handles v/r/s for you; hand-rolling, use
  `bytes_to_int(slice(sig, 0, 32))`; `int_to_bytes(n, 32)` restores the fixed width.
- An RPC node is UNTRUSTED input: it can lie, be compromised, or return garbage. The
  read-side decodes strictly (a non-canonical hex-quantity, a wrong shape, a >16 MiB
  response → catchable error) — but WHICH node you trust is your decision; Synsema
  gives you the primitive, not the trust.
- Broadcasting (`evm_send`/`solana_send`/`algorand_send`/`btc_send`) is `net`-gated, NOT
  `sign`-gated: the signature already happened upstream and without a valid one the
  node rejects the bytes. That split is useful: a read-only monitor agent holds `net`
  but not `sign` and cannot spend.
- A receipt/status is INCLUSION, not success: check `receipt["status"]` (1 ok, 0
  reverted) and Solana `status["err"]` (`nothing` = ok) — a tx can land AND fail.
- Algorand's suggested `fee` is PER BYTE (often 0); the real flat minimum is
  `min_fee` (1000 µAlgo). Confusing them = rejected tx or overpaid fee — that's why
  `algorand_params` returns BOTH.
- `evm_tx` has NO fee/gas defaults on purpose: every value-moving field is
  explicit (read it from the chain or state it) and echoed back in the result map —
  show the numbers in a `confirm` BEFORE `secp256k1_sign(tx["digest"], k)`.
- Deploying is `evm_tx_create`, not `evm_tx` without `to`: it computes `contract_address`
  from `from` + `nonce` and `evm_tx_raw` refuses a signature from any other account — the
  address you print is the one the chain will use (given the right nonce).
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
- uint256 amounts need EXACT integers — big int literals just work; floats are rejected.
  `1e24` IS a float literal (like Python) — write `10**24`; from text, `int("…")` (also
  `int("0x…")` for a node's quantity). Divide amounts with `//` (exact), never `/` (a float).
- `hex(n)` is the node's quantity form (`"0x1f18"`, `"0x0"`, no leading zeros); `hex(b)` the data
  form (every byte). `bytes("0x…", "hex")` accepts the prefix; an odd-length `"0x9"` is a
  quantity → `int("0x9")`. `json_decode` keeps a uint256 in JSON exact.
- Algorand msgpack is CANONICAL: keys sorted bytewise and zero/empty/false fields OMITTED
  (`amt: 0` disappears — that's what the network requires; otherwise the TXID differs).
- Solana does NOT keep your account order: fee payer first, then writable signers,
  ro signers, writable non-signers, ro non-signers (buckets sorted by pubkey bytes,
  matching the official SDK). The compiled indices point at the reordered table.
- v0 Solana messages carry the 0x80 version prefix and the signature COVERS it —
  `solana_tx({..., "version": 0})` already includes it; just `ed25519_sign` the bytes.
- Solana PDA/ATA addresses stay **bytes** (`solana_pda(...).address`, `spl_ata(...)`) on
  purpose: they re-enter as seeds and account keys. `decode(b, "base58")` to show one.
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
- Bitcoin (G28): the fee is IMPLICIT (inputs − outputs) — forgetting the change output
  donates the remainder to miners. `btc_tx` requires the fee declared and checks
  `sum(inputs) == sum(outputs) + fee`, or errors with the exact sat difference. Change is
  ONE MORE explicit output; coin selection is yours (out of scope). Amounts are exact SATS
  (a float/decimal errors; 1 BTC = 100_000_000 sats).
- Bitcoin signs ONCE PER INPUT (not per tx): `btc_tx` returns `digests` (one per input),
  each over its own sighash (BIP-143 P2WPKH / BIP-341 P2TR — `btc_tx` picks). Pass one
  signature per input to `btc_tx_raw`, same order. Only SIGHASH_ALL/DEFAULT.
- A taproot address is the TWEAKED key, not the internal one: `btc_address(k, "p2tr")`
  and `schnorr_sign(digest, k, "taproot")` apply the BIP-341 key-path tweak internally.
  `schnorr_sign` uses the SAME `sign` gate as secp256k1/ed25519 — no new capability.
- Bitcoin bech32 vs bech32m (BIP-350): witness v0 (P2WPKH/P2WSH) = bech32, v1 (taproot) =
  bech32m; the wrong variant is REJECTED (lax decode = burned funds). A cross-network
  address in a tx errors naming both networks. `btc_txid` is byte-reversed (explorer form).
- All pure-Rust (k256 incl. schnorr / ed25519-dalek / sha3 / ripemd / bech32 / bip39 /
  scrypt / aes), zero `*-sys`. Chains: ETH + Avalanche-C + Solana + Algorand + **Bitcoin**
  END-TO-END (read → build → sign → send → confirm, vector-exact), with HD custody +
  keystore V3 + Solana PDAs/SPL + Bitcoin PSBT cold custody; Avalanche X/P signable. Not
  yet: Avalanche X/P serialization helpers, typed `eth_subscribe` over WS (composable in
  userland with `ws_connect` + `evm_rpc`-style JSON, see the WebSocket section).

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
