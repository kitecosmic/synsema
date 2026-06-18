# Syntecnia Standard Library — HTTP, Database, Cron

Zero external dependencies. All built on Python stdlib.

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

SQLite built-in. Parameterized queries (safe from injection).

```
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

-- Batch insert
sql_batch("INSERT INTO logs VALUES (?)", [["event1"], ["event2"], ["event3"]])

-- List tables
let tables be sql_tables()

-- Close
db_close()
```

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
Use `--serve` to keep the process alive:

```bash
syntecnia run server.syn --serve
# Serving 3 cron job(s). Press Ctrl+C to stop.
```

## Capabilities

HTTP requires `net` capability. Database requires `db` capability.

```
require net("api.store.com")
require db("./store.db")
```

## Platform

- HTTP: works on Linux, Windows, Mac (Python stdlib urllib)
- SQL: works on Linux, Windows, Mac (Python stdlib sqlite3)
- Cron: works on Linux, Windows, Mac (Python stdlib threading.Timer)
- All zero external dependencies
