# Synsema Standard Library — HTTP, Database, Cron

Synsema is a **Rust** language (the `synsema/` Python tree is frozen; Rust is the source of truth).
Single static binary. The HTTP server runs on an async `hyper`/`tokio` stack; bundled SQLite via
`rusqlite`. For numeric/scientific builtins (bytes, complex, special math, arrays + linear algebra)
see [builtins.md](builtins.md).

## HTTP

```
-- Full control
let r be http("POST", "https://api.store.com/orders",
    {"Authorization": "Bearer sk-123", "Content-Type": "application/json"},
    {"page": "1"},
    {"product": "laptop", "quantity": 1}
)

-- Shorthands
let r be http_get("https://api.store.com/products")
let r be http_get(url, {"Authorization": "Bearer sk-123"}, {"page": "1"})
let r be http_post(url, {"name": "Alice"}, {"Authorization": "Bearer sk-123"})
let r be http_put(url, {"name": "Bob"})
let r be http_delete(url, {"Authorization": "Bearer sk-123"})
```

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

## Database (SQL)

One **universal API** (`db_open`/`sql`/`sql_exec`/`sql_batch`/`sql_tables`/`paged`) over three backends,
routed by the `db_open` target: a **file path** → SQLite (built-in, `rusqlite`); `postgres://…` →
Postgres; `mysql://…` → MySQL. All drivers are pure-Rust (single static binary, no OpenSSL/`*-sys`).
Parameterized queries everywhere (safe from injection). **Deny-by-default: every DB op needs
`require db(scope)`** (see capabilities). `bytes` columns round-trip to/from `BLOB`/`BYTEA` byte-exactly
(binary-safe).

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
  remote SQL drivers (`postgres`, `mysql`, both TLS via rustls/ring) are pure-Rust — no OpenSSL/`*-sys`.
