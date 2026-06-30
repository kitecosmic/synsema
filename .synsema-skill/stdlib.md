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

Background scheduler. Non-blocking. Each task runs in its own thread.

```
-- Repeat every N seconds
task sync_inventory()
    let data be http_get("https://api.warehouse.com/stock")
    share data as "inventory"

cron_every(300, sync_inventory)    -- every 5 minutes

-- One-shot after delay
task send_reminder()
    log "Sending reminder"

cron_after(3600, send_reminder)    -- once, after 1 hour

-- Manage
cron_cancel("sync_inventory")     -- stop a job
let jobs be cron_list()            -- list all jobs
print(cron_status())               -- formatted status
```

## Serve mode (keep crons alive)

By default, when the program ends, cron jobs stop (daemon threads).
Use `synsema serve` to keep the process alive:

```bash
synsema serve server.syn
# Serving 3 cron job(s). Press Ctrl+C to stop.
```

## Capabilities

HTTP requires `net` capability. Database requires `db` capability.

```
require net("api.store.com")
require db("./store.db")
```

## Platform

- HTTP, SQL, Cron: work on Linux, Windows, Mac.
- Single static binary (the one C dependency is bundled SQLite in `rusqlite`, which needs a C
  compiler at build time on Windows). Numeric deps (`libm`, `num-complex`, `ndarray`, `faer`) and the
  remote DB drivers (`postgres`, `mysql`, `mongodb` — all TLS via rustls/ring) are pure-Rust — no
  OpenSSL/`*-sys`.
