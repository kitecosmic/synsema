# Synsema Common Patterns

Complete programs first — **copy, adapt, run**. Every program in this file was executed
verbatim against engine v0.5.9. If you know Python but are new to Synsema, read
[python-diff.md](python-diff.md) before adapting these.

## Complete program: data pipeline (CSV → stats → report)

Pure — no capabilities needed. `synsema run report.syn`

```
let raw be `date,region,amount
2026-01-05,north,120
2026-01-06,south,80
2026-01-07,north,200
2026-01-08,west,150`

let rows be csv_parse(raw, {"numbers": true})
let amounts be collect(rows, "amount")
print("orders: " + text(length(rows)))
print("total:  " + text(sum(amounts)))
print("median: " + text(median(amounts)))

let by_region be group_by(rows, (r) => r.region)
each region in keys(by_region)
    let subtotal be sum(collect(by_region[region], "amount"))
    print(`  {region}: {subtotal}`)
```

Swap the literal for `read_file("data.csv")` + `require file("data.csv")`, or a
`sql(...)` query — the pipeline shape stays the same. Charts: [dataviz.md](dataviz.md).

## Complete program: JSON API (SQLite + bearer auth + validation)

`synsema serve api.syn` (NOT `run` — see [serve.md](serve.md))

```
require serve(8091)
require db("./demo.db")

db_open("./demo.db")
sql_exec("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")

task check_token(token)
    when token == "demo-token"
        give {"name": "admin"}
    give nothing

serve on 8091
    auth with check_token
    route "GET /products"
        give sql("SELECT id, name, price FROM products")
    route "POST /products" requires auth
        expect body {name: text, price: number}
        let b be json of request
        sql_exec("INSERT INTO products (name, price) VALUES (?, ?)", [b.name, b.price])
        give {"created": b.name, "by": name of (user of request)}
```

Verified behavior: `POST` without `Authorization: Bearer demo-token` → **401**; with the
token but a body missing `price` → **400** (the `expect body` contract); a good `POST` →
`{"created": "Widget", "by": "admin"}`; `GET /products` → the paginated envelope
`{"items": [...], "count": 1, "total": 1, "cursor": null}` (the runtime paginates every
list you `give`). In production don't hardcode the token — `secret("API_TOKEN")` +
`constant_time_eq` ([secrets.md](secrets.md)).

## Complete program: fan-out over all cores, error-safe

`parallel_map` is fail-fast; the wrap-in-`try/recover` pattern collects partial results
instead of aborting. `synsema run fanout.syn`

```
task risky_work(n)
    when n % 7 == 0
        raise("cannot process " + text(n))
    give n * n

task safe_work(n)
    try
        give {"ok": risky_work(n)}
    recover err
        give {"error": err}

let results be parallel_map(safe_work, range(1, 15))
let failures be where(results, (r) => contains(r, "error"))
print("done: " + text(length(results)) + ", failed: " + text(length(failures)))
each f in failures
    print("  " + f["error"])
```

Prints `done: 14, failed: 2` then the two messages — same order as `apply`, all cores.
For huge inputs, batch first: `chunk(items, 1000)` → [concurrency.md](concurrency.md).

## Complete program: two coordinated agents (blackboard + signals)

`synsema run duo.syn` — `run` joins spawned agents before exiting.

```
agent Doubler
    wait_for "job" timeout 5 as n
    share n * 2 as "doubled"
    signal "done"

spawn Doubler
signal "job" with 21
wait_for "done" timeout 5
observe "doubled" as result
print("doubled: " + text(result))
```

Prints `doubled: 42`. **Always bound `wait_for` with `timeout`** — without it a missing
emitter blocks the default 30 s ([pitfalls.md](pitfalls.md)). Blackboard `share`/`observe`
is state, signals are events; agents also see a COPY of top-level tasks/values
([agents.md](agents.md)).

## Complete program: LLM decision with the offline guard

`synsema run decide.syn` — works with or without a provider configured.

```
require llm

let ticket be {"complaint": "item arrived broken", "customer_since": 2019}
let choice be decide between ["refund", "replace", "escalate"] given ticket

when llm_available()
    print("decision: " + choice)
otherwise
    -- offline: choice is the placeholder "[decision pending]" — NOT one of the options
    print("no provider configured; got placeholder: " + choice)
```

With a provider, `choice` is guaranteed to be one of YOUR options byte-for-byte; offline
it's a placeholder — that's why the `llm_available()` guard matters ([llm.md](llm.md)).

## Idioms

### Safe division
```
when divisor != 0
    give total / divisor
otherwise
    give 0
```

### Intentional ops instead of loops
```
-- Instead of:
let result be []
each item in items
    when is_valid(item)
        set result to append(result, process(item))

-- Write:
let result be apply(process, where(items, is_valid))
```

### Guard a map key (`and` does NOT short-circuit — nest instead)
```
when contains(m, "discount")
    when m["discount"] > 0.2
        raise("discount too high")
```

### Re-propagate a caught error (recover swallows by default)
```
try
    risky_operation()
recover err
    log "failed: " + err
    raise(err)              -- without this, the caller sees a normal completion
```

### Agent with full lifecycle
```
intent: "Process daily orders"
require net("api.shop.com")
require memory("daily-orders")      -- declared memory: gates remember/rules/progress, names the .db

add_rule("max_discount", "must", "discount <= 0.20", "pricing")
remember("context", "Peak season, expect high volume", ["operations"])

create_progress("daily", ["fetch", "validate", "process", "report"])

let resume be resume_point("daily")
when resume != nothing
    log "Resuming from step: " + resume

start_step("daily", "fetch")
let orders be fetch("https://api.shop.com/orders")
complete_step("daily", "fetch", text(length(orders)) + " orders")
```

### LLM with rule checking
```
let action be decide between ["discount", "full_price"] given customer_data
let violations be check_rules("pricing", {"discount": 0.15})
when length(violations) > 0
    set action to "full_price"
```

### Pipe chain
```
let report be raw_data |> clean |> validate |> summarize |> format
```

### Type constructor + collect
```
type Product
    name: text
    price: number

let products be [Product("A", 10), Product("B", 20), Product("C", 30)]
let names be collect(products, "name")
let expensive be where(products, is_expensive)
```

### Error-safe I/O
```
require file("/data/*")
when file_exists("/data/cache.json")
    let cached be read_file("/data/cache.json")
otherwise
    let cached be fetch("https://api.example.com/data")
    write_file("/data/cache.json", cached)
```
