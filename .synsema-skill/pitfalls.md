# Synsema Pitfalls — Common Errors and Solutions

Read this FIRST if something fails. Each row is a real mistake that costs hours to debug.

> **Just upgraded and something that worked now fails?** Start at *Upgrading to v0.6.29* (then
> *Upgrading to v0.6.24*), right below.
>
> **Jump to the `## ` section that matches your failure:** Errors (parse/runtime messages) ·
> Database SQL · Database MongoDB · Database Redis · HTTP server (serve) · Language features
> (bytes, complex, arrays, match, params, tests) · Data & charts · Blockchain ·
> Behavioral surprises · Anti-patterns · Secrets & config
> Coming from Python? The traps that LOOK like Python but aren't are also collected in
> [python-diff.md](python-diff.md).

## Upgrading to v0.6.29 — what stops working and what to write instead

v0.6.29 fixes the language before v1.0. Old builtin names keep working as **deprecated aliases**
until v1.0 (a program that uses one prints one warning on stderr at load; `synsema check` flags
each use) — the full old → new list is [builtins.md](builtins.md) § Renamed in v0.6.29. What
actually changes behavior:

| You see | What changed | What to write |
|---|---|---|
| `task 'f' is missing argument 'b' — pass it, or give the parameter a default` / `task 'f' takes 1 argument, got 3` | **Strict arity** for calls written in the program (tasks and lambdas). A missing argument used to become `nothing`; extras were ignored | Pass it, or give the parameter a default (`task f(a, b = 0)`). Callbacks that a builtin/host invokes (`apply`/`where`/`reduce`, route handlers, cron, `errors with`) are unchanged |
| `append() takes at most 2 arguments, got 3` (also `trim(s, "x")`, `json_encode(x, 2)`, `upper("a", "b")`) | Extra arguments to a builtin used to be **silently dropped** | Remove them — they never did anything |
| `… does not accept named arguments (got x = …); pass it by position` | Named arguments on a builtin that has no named form | Pass it by position. Named forms that exist: `sort`/`sort_by` `desc = true`, `recall(from = …)`… |
| A task `set`s inside a map/list it received and the caller no longer sees it | Lists and maps have **value semantics** (copy-on-write): passing or `let`-binding gives a logical copy | `give` the changed value back and `set` it in the caller. Shared state goes through the blackboard, `memory`, the bus, `state_*` |
| `Cannot add text and nothing — convert it on purpose: text(x), or interpolate it` (or `…and list/map/bytes`) | `text + nothing/list/map/bytes` used to concatenate the display form | `text(x)` on purpose, or a backtick string. `text + number/bool` still concatenates |
| `fmt: no value for {a} — pass it in the map, or write {{a}} for a literal brace` | `fmt` used to leave an unknown `{a}` in the output | Pass the value, or write `{{a}}`. Braces that do not surround a name (JSON/CSS) still pass through |
| `number(…)` errors naming `int` on a long integer text | An integer text beyond ±2^53 used to be **rounded silently** by `number` | `int(x)` (exact). `number(x, default)` returns the default instead |
| `2**53 + 1 == 9007199254740992.0` is now `false`; a sort involving huge ints and floats changed order | Int vs float compare **exactly** (it went through a float) | Nothing to do unless code relied on the rounding |
| `json_decode` returns an integer where you got a float (`{"id": 12345678901234567890}`) | JSON integers of any size stay **exact** | `number(x)` if you truly want a float; numbers with `.`/exponent are still floats |
| `print(["1", 1])` shows `["1", 1]`, `text(list)` quotes its texts | Inside lists/maps text is shown **quoted** (keys stay bare). Top-level `print("x")` is unchanged | Fix tests that asserted the old `[1, 1]` form |
| `sort_by` raises `cannot order number and text together` / `… has no order` | `sort_by` used to leave the list **unchanged** on keys it could not order | Make the keys comparable (all numbers or all texts); `nothing` and NaN are fine — they go last |
| `index must be an integer, got 1.7` (also `range(0, 2.5)`, `range(0, 1, 0.25)`) | Indexes, positions and steps must be integers (`2.0` is fine) | `floor`/`round`/`trunc` on purpose, or build the float sequence with `apply` |
| A lexer error about `--` on `5--1` | `--` opens a comment only at line start or after whitespace (or `(` `[` `{` `,`) | `5 - -1` for arithmetic, `5 -- note` for a comment |
| `` `of` needs a plain name on its left `` | `p["a"] of p` (a non-name left of `of`) is a parse error | `p["a"]` or `a of p` |
| `-2 ** 2` gives `-4`; `1 + 2 \|> f` gives `f(3)` | `**` binds tighter than unary minus; `\|>` has the lowest precedence and passes the value as the FIRST argument of a call step | Parenthesize if you meant `(-2) ** 2`; `xs \|> sort_by(f)` is `sort_by(xs, f)` |
| `1 in "a1"` errors | Substring `in` needs text on both sides | `text(1) in "a1"` |
| `capture` and `regex_capture` disagree | `regex_capture` is ALWAYS a list (`[match]` without groups) or `nothing`; the deprecated `capture` keeps the old shape | Switch to `regex_capture` and index `[0]` for the whole match |
| `hmac(...)` returns bytes, `hmac_sha256` returned hex | The new name returns **bytes** | `hex(mac)` (`"0x…"`) or `decode(mac, "hex")` (bare hex, the old text) |
| `solana_tx(message, signatures)` → error pointing to `solana_tx_raw`; `algorand_tx(txn, sig)` → error pointing to `algorand_tx_raw` | The names now mean **build** (`solana_tx(params)`, `algorand_tx(txn)`); assembling the signed tx is `…_raw` | `solana_tx_raw(msg, sigs)` / `algorand_tx_raw(txn, sig)` |
| `evm_tx` without `to` → error pointing to `evm_tx_create` | Contract creation has its own builder that computes the address and checks the signer | `evm_tx_create({…, "from": addr, "data": init_code})` |
| A loop that used to stop at `Loop exceeded maximum iterations` now runs forever | `while` has no iteration cap (it was 1,000,000) | Make the condition change; bound it yourself if you relied on the cap |
| Output of a long `synsema run` appears as it happens | `print` under `run` is written line by line (it was held until the end) | Nothing — `flush()` is no longer needed there |
| `std`/`var` give a larger number than before (`std([1,2,3,4])` → `1.29…`, was `1.118…`) | `std`/`var` are **sample** statistics now (`ddof = 1`, like pandas/polars/R/Excel `STDEV.S`); they were population. `synsema check` warns at each call | Nothing if you wanted what pandas gives. For the old (numpy) value: `std(xs, ddof = 0)` |
| `keys() requires a map` / `an index must be an integer, got text` on the result of `group_by` (`keys(groups)`, `groups["north"]`) | `group_by` returns **`[{key, items}]`** in first-appearance order (it returned a map keyed by the TEXT of the key); keys keep their type | `each g in group_by(rows, "region")` … `g.key` / `g.items`; for totals per group use `summarize(rows, "region", {"total": sum_of("amount")})` |
| `dot(...)` errors `use matmul(a, b)` | `dot` is only the inner product of two **1-D vectors** now | `matmul(a, b)` for matrices; `dot(u, v)` for vectors |
| A CSV field that was `""` is now `nothing` (and `text + nothing` errors, `== ""` is false) | `csv_parse` reads an **empty field as `nothing`** — missing data | `is_missing(x)` / `fill_missing(rows, "")` if you want the old empty text; `drop_missing(rows, "col")` to drop them |
| `min([nan, 3])` is now `nan` (it gave `3`); `median` of data with a NaN returns `nan` instead of erroring | NaN **propagates** through every reduction, in any position; `nothing` is what gets skipped | `fill_nan(xs, 0)` or `where(xs, is_finite)` before reducing |
| `format_time` / `parse_time` / `date_parts` work without `require time` | They never read the clock, so they are **pure** now; only `now()` and `sleep()` need `time` | Nothing (drop the `require time` if it was only for them) |
| `random_int(1.5, 6)` errors | `random_int` bounds must be integers (1.5 used to be truncated) | `random_int(floor(x), 6)` on purpose |
| `round_to(2.675, 2)` → `2.67` | `round_to` rounds the float's REAL value like Python (2.675 is 2.67499…); it used to multiply by 10ⁿ | For decimal-exact rounding use decimals: `round_to(2.675d, 2)` → `2.68`; they round half to EVEN (`round_to(1.005d, 2)` → `1.00`, `round_to(2.665d, 2)` → `2.66`) |

## Upgrading to v0.6.24 — what stops working and what to write instead

The full list with the reasoning is in [CHANGELOG.md](../CHANGELOG.md); this table is the short
version, ordered by how likely it is to hit you. The first three affect programs that never
touch labels or enclaves.

| You see | What changed | What to write |
|---|---|---|
| `jwt_verify: this needs the clock…` (or `totp`, `captoken_*`, `http_sign*`, `oidc_verify`) | Ten builtins read the clock and now require it. Plain `run` and `--sandbox` grant `time` automatically, so this only bites under `--deterministic`, an explicit `--cap-set`, or inside a guest | `require time`, or pass it: `opts.now` / `opts.at` / `opts.created` / explicit `iat`+`exp` |
| `unexpected TEXT/NUMBER/IDENTIFIER after the end of this statement` on a line that used to run | A statement may no longer carry leftover tokens. `assert_eq 1, 2` parsed as the bare identifier and asserted **nothing**; a Python-shaped `return v` parsed as two inert expressions and failed later, if at all | Write the parentheses: `assert_eq(1, 2)`. For `return v`, the word is `give` — see [python-diff.md](python-diff.md) |
| `Capability not granted: secret("B")` where `require secret "A"` used to be enough | `require <cap> "<scope>"` without parentheses used to **discard** the scope, granting the capability unscoped | Declare what you use — `require secret("B")` — or the wide form on purpose: `require secret` |
| `'print' is a protected builtin…` at load | `private`, `declassify`, `label_of`, `is_private` and `print` cannot be bound to anything callable | Rename your task. Binding the name to a plain value is still fine |
| `when cond then raise "…"` no longer raises | The inline `when … then …` is an *expression*; in statement position its value was discarded, so guards were silent no-ops. Now it is a load error | Use the block form (`when cond` + indented body) |
| A public alias stopped seeing writes made through `private(container, …)` | `private()` over a list or map makes a **private copy** — sharing the `Rc` would leave a public alias into private data | Build the container after marking, or declassify the scalar you want to publish |
| `label_violation: print called under private control flow` | Under `--labels`, stdout is a public sink: the *number* of lines is not redactable | Move it out of the private branch, or `declassify` the condition → [labels.md](labels.md) |
| `try`/`recover` stopped catching something | Under `--labels`, an error **caused by private data** is not catchable — whether an operation failed is the bit | Use the **total variant**: `json_decode(x, nothing)`, `number(x, nothing)`, `aes_gcm_decrypt(k, n, ct, aad, nothing)` → [builtins.md](builtins.md) § Total variants |
| `"steps": null` in `run --format json` | The step counter is linear in what the program walked, so after a private branch it *is* the secret | `declassify(steps(), "<why>")` if you mean to publish it |
| The guest module is rejected by the Executor | The build has one more step | Run `packages/guests/vela/tools/wasi-stub` over the `.wasm` → [guests.md](guests.md) |

Everything above is inert with labels off, except the first three rows.

## Errors

| Error message | Cause | Solution |
|---|---|---|
| `Unterminated string` | Literal newline inside `"..."` | Use `\n` escape. Strings are single-line only. |
| `Capability not granted: file_write(...)` | Missing `require` or scope too narrow | Add `require file("/path/*")` at top of program |
| `Capability not granted: net(...)` | Missing `require` for the domain | Add `require net("domain.com")` |
| `Invalid memory category: 'preferencia'` | Categories are English-only | Use exactly: `preference`, `rule`, `learning`, `decision`, `context` |
| `Capability not granted: memory` on `remember`/`recall`/`add_rule`/`create_progress` | Persistent state is opt-in: the program declares no memory (it is NOT auto-granted, even under `run`) | Add `require memory("<name>")` at the top — the name keys `<dir>/.synsema/state/<name>.db` ([memory.md](memory.md)) |
| `require memory needs a name` (parse error) | Bare `require memory` — a declaration with no name has no identity (no `.db` to open) | Give it a name: `require memory("my-agent")` (`[a-zA-Z0-9_-]+` only) |
| `Multiple memory declarations` at startup | Two `require memory` with different names — a program has exactly ONE declared memory | Keep one declaration (two entry files that DECLARE THE SAME name share one memory) |
| Old memory "disappeared" after upgrading | Identity moved from file-stem to the **declared name**; a warning on stderr names the old `.db` and the exact line to add | Add `require memory("<old-stem>")` to keep the same file, or rename the `.db` to the new declared name |
| `remember` in one agent, `recall()` in another finds nothing | `recall()` inside an agent defaults to its OWN namespace (`source` = agent name) | Cross explicitly: `recall(from = "writer")`, or `from = "*"` for everything ([memory.md](memory.md)) |
| `No agent defined with name 'X'` | `spawn X` before `agent X` definition (the error lists the agents the context DOES know) | Define the agent before spawning it. If the error says "no agents are defined in this execution context" and your agent IS defined top-level, that's the runtime, not your code — on engine ≤ v0.4.9, `spawn` inside a route fails from the 2nd request on a reused serve worker (fixed in v0.5.0; workaround: spawn a long-lived worker at boot and enqueue via `signal`) |
| `Division by zero` | Divisor is 0 (`/`, `//`, `%`) | Guard with `when divisor != 0` or use `try/recover` |
| ``return` is not a Synsema statement: `give <value>` returns from a task`` (also `def`, `for`, `if`, `import`, `class`, `break`, `throw`…) | A Python/JS reflex (v0.6.29+ names the Synsema word) | `give v`, `task`, `each`, `when`, `use`, `type`, `stop`, `raise` — see [python-diff.md](python-diff.md) |
| ``declare with `let x be …`, change it with `set x to …` `` | `x = 6` | `let x be 6` the first time, `set x to 6` after |
| `Synsema blocks have no colon` | `when x > 0:` | Drop the `:` |
| `Undefined variable: 'len'` — in Synsema: `length(x)` (same for `str`, `None`, `null`, `True`, `filter`, `map`, `sorted`, `zip`, `isinstance`, `open`, `dict`, `self`…) | A Python builtin name | Use the name the error gives |
| `Synsema has no methods: set xs to append(xs, item)` | `xs.append(2)` or another method call | Builtins are plain tasks: `append(xs, x)`, `upper(s)`, `keys(m)` |
| `Cannot iterate over number` | `each` on a non-list value | Check type with `type_of()` or wrap in `[value]` |
| `Map has no key 'X'` | Accessing a property that doesn't exist | `get(map, "X", default)` (v0.6.29+) returns a default instead; or check with `"X" in map` / `contains(map, "X")` first — `contains(m, "X") and m["X"] == v` is fine on v0.6.10+ (`and` short-circuits); on older engines nest the `when` |
| `contains(m,"k") and m["k"] == v` errors anyway | You are on an engine ≤ 0.6.9: `and`/`or` did not short-circuit there | `synsema update` (v0.6.10+ short-circuits) or nest: `when contains(m, "k")` … then index inside |
| `let x be y or "default"` gives `true` | `and`/`or` always return a **bool** (they short-circuit, but never yield the operand like Python) | `let x be y` + `when x == nothing` … `set x to "default"` |
| `raise "msg"` does nothing (no error raised) | **Engine ≤ v0.5.1**: without parens it parsed as TWO inert expressions — a silent no-op | Upgrade (newer engines accept the statement form `raise "msg"` / `raise err`, and a bare `raise` errors loudly); on old binaries always `raise("msg")` |
| `'decide' is a reserved word` naming an export/param/variable (older engines: `Expected IDENTIFIER, got DECIDE`) | A hard keyword used as a name you bind — `export task decide(...)`, `task wait(reason)`, `task send(to)` | Rename (`resolve`, `why`, `dest`) — see [syntax.md](syntax.md). After a `.` any word is fine since v0.6.29 (`mod.decide(...)`, `tx.to`, `ev.type`); on older engines that also failed |
| `Cannot set undefined variable` | Using `set` before `let` | Define with `let x be value` first, then `set x to new_value` |
| `Expected indented block` | Missing indentation after when/each/task/etc | Indent body with 4 spaces |
| `'while' is a reserved word in Synsema` | Using a hard keyword as a name | Pick another name. (HTTP words like `route`/`auth` ARE allowed as names — they're soft keywords.) |

## Database — SQL (SQLite / Postgres / MySQL)

One universal API (`db_open`/`sql`/`sql_exec`/…) routed by the `db_open` target: a file path → SQLite,
`postgres://…` → Postgres, `mysql://…` → MySQL. (MongoDB is a separate document API, Redis a separate
key-value API — see below.) Use `?` placeholders everywhere.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `require db("postgres://user:pw@host:5432/appdb")` is the scope | Credentials/port/query are stripped: scope is `postgres://host/appdb` | Grant the **canonical URL** `db("postgres://host/appdb")` (same for `mysql://`). A path scope never covers a URL |
| `sql_exec(INSERT)` returns the new id on Postgres | Postgres `last_id` is always `0` | Use `INSERT … RETURNING id` and read it from `sql(...)`. (MySQL `last_id` = `last_insert_id()`, real; SQLite = rowid) |
| Postgres connects without TLS by default | TLS is **on** by default | Add `?sslmode=disable` for plaintext (e.g. local dev) |
| MySQL connects with TLS by default | MySQL TLS is **opt-in** (plaintext default) | Add `?ssl-mode=REQUIRED` to enable rustls TLS |
| `db_open("postgres://deadhost/db")` hangs | A 10s connect-timeout applies, then errors | Expected: a dead host fails fast, never hangs the agent |
| A `BLOB`/`BYTEA` column round-trips as text | It returns `bytes` (`type_of` "bytes"); `decode()` for text | Binary is byte-exact — use `bytes(...)` to insert, `decode(...)` to read text |
| `DECIMAL`/`NUMERIC` comes back as a float | It's a `decimal` (`type_of` "decimal"), exact | Keep it as `decimal` for money; don't coerce through float |
| `?` in a Postgres query must be `$1` | The runtime rewrites `?`→`$n` for you (MySQL uses `?` natively) | Just write `?` everywhere; for pgvector pass a list as `?::vector` |
| A SQL trigger can call a Synsema task (e.g. re-embed on INSERT) | Triggers run inside the database — they can NEVER call back into your program | Keep the write-path in ONE task (e.g. `insert_product` that also updates the vector table) and use it everywhere; triggers are fine for SQL-only sync (like FTS5 external-content) |

## Database — MongoDB (document store, `mongo_*`)

`db_open("mongodb://…")` then `mongo_find`/`mongo_insert`/… — **not** `sql()`. Filters and docs are
Synsema maps ↔ BSON.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sql("SELECT …")` works on a Mongo connection | Errors: "this is a MongoDB connection — use mongo_*" | Use `mongo_find`/`mongo_aggregate`/etc. (and `mongo_*` on a SQL connection errors symmetrically) |
| `mongo_update(c, filt, {"age": 31})` sets age | Mongo rejects a plain doc as the update | Use an operator: `{"$set": {"age": 31}}` (also `$inc`, `$push`, …) |
| `mongo_find(c, {"_id": "<hex>"})` finds nothing | Without coercion a string ≠ ObjectId | The runtime coerces a 24-hex string under `_id` (incl. in `$in`) to an ObjectId — pass the hex you got back from `mongo_insert` |
| `"price": 9.99` stores an exact decimal | `9.99` is a **float** → BSON Double → reads back `number` | Use a decimal literal `9.99d` (or `decimal("9.99")`) → BSON Decimal128 → reads back `decimal` |
| `require db("mongodb://u:p@host:27017/appdb?authSource=admin")` is the scope | Credentials/port/query stripped: scope is `mongodb://host/appdb` | Grant the canonical URL `db("mongodb://host/appdb")` |
| `db_open("mongodb://…")` is lazy and always succeeds | It pings on open — a dead host / bad auth fails there (within 10s) | Expected: connectivity is validated at `db_open`, like the SQL backends |
| `mongo_insert` returns the doc | It returns the new `_id` (text hex for ObjectId) | Read it back with `mongo_find_one(c, {"_id": id})` |

## Database — Redis (key-value/cache/structures, `redis_*`)

`db_open("redis://…")` then `redis_get`/`redis_set`/`redis_hset`/… — **not** `sql()` or `mongo_*`. Values are
byte-strings (text/bytes/number); structured data goes via `json_encode`/`json_decode`.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sql("SELECT …")` works on a Redis connection | Errors: "this is a Redis connection — use the redis_* builtins" | Use `redis_*` (and `redis_*` on a SQL/Mongo connection errors symmetrically) |
| `require db("redis://localhost")` covers `db_open("redis://localhost:6379/0")` | **No** — `:6379` (no path) → scope `redis://localhost`, but `/0` → scope `redis://localhost/0` (different) | Match the `require db(...)` form to `db_open(...)` exactly: no `/N` ⇒ no db in the scope; `/0` ⇒ `/0` in the scope |
| `redis_set(k, {"a": 1})` stores the map | Errors: redis values must be text/bytes/number | Serialize: `redis_set(k, json_encode({"a": 1}))`, read with `json_decode(redis_get(k))` |
| `redis_get` of UTF-8 data returns `bytes` | Returns `text` if the bytes are valid UTF-8, else `bytes` | Binary-safe heuristic; raw/non-UTF8 values round-trip as `bytes` byte-exactly |
| `redis_unlock(k)` frees the lock | It needs the **token** from `redis_lock` and only frees if it still matches | Keep the token: `let t be redis_lock(k, ttl)`; `if t != nothing` … `redis_unlock(k, t)`. A 2nd `redis_lock` on a held key returns `nothing` |
| `redis_lock` blocks until the lock is free | Non-blocking: returns `nothing` immediately if held | Check the return; the TTL auto-releases if the holder dies (single-node Redlock, not multi-node) |
| `redis_keys("*")` is fine in prod | `KEYS` is O(N) — scans the whole keyspace | Use a bounded pattern (`user:*`); a non-blocking `redis_scan` may come later |

## HTTP server (serve)

### Errors

| Error message | Cause | Solution |
|---|---|---|
| `serve on 8080 is not permitted: missing capability serve(8080)` | No `require serve(PORT)` | Add `require serve(8080)` at the top |
| `route "..." uses 'requires auth' but ... no 'auth with'` | A route has `requires auth` but the block has no auth task | Declare `auth with <task>` in the `serve` block |
| `send can only be used inside a stream` | `send` used outside a `stream` block | Put `send` inside a route's `stream` block |
| `500` from a route using `paged(...)` | Your query has its own `LIMIT`/`;` | Remove them — `paged()` adds `LIMIT`/`OFFSET`; the runtime owns pagination |
| `503 too many concurrent streams` | Open SSE streams > `max_streams` | Raise `max_streams N`, or shorten streams (each holds a thread) |
| `429 rate limit exceeded` | More requests than `rate_limit` allows for that IP | Slow down, or raise/relax the route's `rate_limit` |
| `413 payload too large` | Request body over `max_body` (default 1 MB) | Raise `max_body "10mb"`, or stream large uploads |

### Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `give sql("... LIMIT 10")` reports `total: 10` | `give <list>` paginates what you return; `total` = what you gave | Return the full collection (no `LIMIT`). For big tables use `paged()` |
| `give <list>` of a huge table is fine | Loads the whole collection into memory per request | Use `paged("SELECT ...")` — `LIMIT`/`OFFSET` pushdown + exact `COUNT(*)` |
| `rate_limit 100 per minute` on the block = 100 per route | It's 100/min per IP **shared** across all routes using the default | For independent budgets, set `rate_limit` per route (own zone) |
| No `rate_limit` and I'm already protected | No — rate limiting is **opt-in** | Declare `rate_limit` on the block and/or sensitive routes |
| `read_body()` returns binary intact | Decodes as UTF-8 (lossy for binary) | Use `read_body_bytes()` for byte-exact binary uploads |
| `proxy to` without `require net("<upstream host>")` | The upstream is an outbound connection: deny-by-default, the serve refuses to start | Declare the upstream host (`require net("127.0.0.1")` for local backends) |
| A `stream` route also runs `give` | `stream` and `give` are mutually exclusive | A route either streams (with `send`) or gives — not both |
| POST with invalid JSON is silently ignored | With `Content-Type: application/json` it's a `400` | Send valid JSON, or omit the JSON content-type to get the raw body |
| `serve on PORT` returns and the program exits | The CLI keeps the process alive while servers run (Ctrl+C to stop) | Expected; the server runs in the background |
| `request` works inside a helper task called from a route | `Undefined variable: 'request'` — `request`/`query`/`params` exist ONLY in the handler's scope (the error says so) | Pass it as a parameter: `task handle(request)` and call `handle(request)` from the route |
| `X-Forwarded-For` sets the client for rate limiting | The real peer IP is used; XFF is ignored | XFF is forgeable; trusted-proxy/per-user keying is future work |
| Behind a proxy the sitemap/robots/OpenAPI `servers` say `https://127.0.0.1:PORT/...` | The proxy rewrote `Host` to the backend authority; `X-Forwarded-Host` is ignored on purpose (forgeable → host header injection) | Declare `domain "example.com"` in the serve block — that is the base URL |
| `give "<h1>Hi</h1>"` renders as an HTML page | It's JSON — the response is the quoted string `"<h1>Hi</h1>"` | Use `html("<h1>Hi</h1>")` (or `respond(...)`) for a real page |
| `static "./public"` also needs `require file(...)` | No — the `static` declaration **is** the read permission for that dir | Just declare `static "./public"`; the path is relative to the working dir |
| `cors "*"` works with `Authorization`/cookies | The CORS spec forbids `*` for credentialed requests | Use a specific origin: `cors "https://app.example.com"` |
| A static file shadows my declared route | Declared routes always win; static is only the fallback | Expected — rename the file or the route if you really want the file |
| A catch-all `*path` swallows a more specific route | Precedence is by specificity, not order: exact > `:param` > `*catchall` | Expected — the exact/`:param` route wins even if declared after the catch-all |
| `route "GET /files/*path"` matches bare `/files` | A catch-all needs ≥1 segment to capture | Add `route "GET /files"` if you want to handle the bare path |
| Two `static "./a"` / `static "./b"` (both root) | Silent shadowing is now a startup **error** | Mount one under a prefix: `static "/b" from "./b"` |
| `*rest` not the last path segment | Parse error — a catch-all must be last | Put `*name` as the final segment: `/files/*path` |
| User HTML in a `content()` page renders as a live tag | `content()` HTML **auto-escapes** all text (XSS-safe) | That's the point; use `raw(html)` to embed trusted HTML on purpose |
| `/blog/hola.json` runs `:slug` = "hola.json" | The `.md`/`.json`/`.html` suffix is stripped first; slug is "hola" | Expected for `content()` routes; a real `hola.json` file or a literal route wins |
| `Accept: text/markdown` changes my JSON/`{map}` route | Negotiation applies **only** to `content()` values | Wrap the tree in `content(...)`; plain `give {map}` is always JSON |
| `give heading(...)` renders an HTML heading | Without `content()` a node degrades to its **JSON** form | Wrap the tree in `content(page([...]))` to get HTML/Markdown |
| My internal server exposes `/llms.txt` with all its routes | `/llms.txt`, `/robots.txt`, `/sitemap.xml`, `/openapi.json` and `/docs` are ON by default (agent-discoverable) | Add `private` to the serve block: the generated documents → 404, robots `Disallow: /` (`docs off` removes only the `/docs` page) |
| `/openapi.json` shows no `requestBody` for my route | Only a **top-level** `expect body` in the route is a contract; one inside a `when` is a branch | Move the `expect` to the top of the route body |
| I declared `route "GET /docs"` and the API page vanished | Your route/static file wins over every generated document (`/llms.txt`, `/openapi.json`, `/docs`…) | Intended; rename your route, or use `docs off` if you only wanted the page gone |
| `/sitemap.xml` lacks `/blog/:slug` | Parametric routes are never expanded (the runtime can't know the slugs); auth/stream/proxy routes are excluded too | Expected — declare literal routes for pages you want listed |
| `x-synsema-capabilities` lists `net` for a route that never called `fetch` | It's static: the `require` of every task the route may call, transitively, plus builtin implications | Expected — it's the contract, not a trace; the runtime still gates each call |
| `this host provides no audit sink for sign.log` (wasm) | `sign`/`spend`/`wallet`/`reveal` need an audit line; a wasm host has no files | Offer `kv` to the embedded runtime — the line lands in `kv` under the `audit` namespace |
| `secp256k1_recover: the recovery id (byte 65) must be 0..=3` (≤ v0.6.28) or an error about **EIP-155** | ≤ v0.6.28 rejected a wallet's 27/28; v0.6.29+ accepts `v` = 0, 1, 27, 28 and rejects only `v` ≥ 35 (a legacy EIP-155 `chain_id*2+35` value, not a message signature) | v0.6.29+: pass the wallet's signature as-is. On older engines subtract 27 by hand: `slice(sig, 0, 64) + bytes([sig[64] - 27])`. `secp256k1_verify` ignores `v` |
| A contract reverts `InvalidSignature` / `InvalidSigner` / `invalid permit` on a signature made with `secp256k1_sign` | `ecrecover`, OpenZeppelin `ECDSA.recover` and EIP-2612 `permit` want `v` = 27/28; `secp256k1_sign` returns the raw recovery id 0/1 (what typed txs use) | `evm_signature(sig)` (v0.6.29+, idempotent) before sending it to a contract or a wallet; keep the raw `sig` for `evm_tx_raw` (see stdlib.md § Blockchain) |
| `synsema openapi` exits 2 | The file has no `serve` block (or the path is missing) | Point it at the entry file that serves |
| `describe`/`private`/`docs` can't be used as variable names | They're soft keywords — only special in a serve block | `let private be 1`, `let docs be 2` and `let describe be x` are still valid |
| CSS `body { }` inline in a `render()` template breaks | `{`/`}` are template hole delimiters | Wrap the CSS/JS block in `{ raw }` … `{ end }` (verbatim), or serve it from `static`; single literal brace via `{ "{" }` |
| `<script>const D = { raw json_encode(x) };</script>` is safe | It's XSS — a value containing `</script>` breaks out of the tag | Use `{ raw json_for_script(x) }` (escapes `<`/`>`/`&` as `\u00XX`) |
| User HTML in `{ expr }` renders as a live tag | `render()` auto-escapes every hole (XSS-safe) | Use `{ raw expr }` for trusted HTML on purpose |
| `render("/etc/passwd", ...)` reads any file | Template paths are cwd-relative; escaping the cwd is blocked | Keep templates under the project; absolute/`..` paths error |
| `{ type }` in a template fails ("reserved word") | A single-name hole is a direct data lookup — reserved words work | Just use `{ type }`; the field resolves from the data |
| `{ include "partials/nav.html" }` inside `pages/home.html` looks in `pages/partials/` | Include/layout paths resolve against the **working dir**, not the including template | Write all template paths from the project root (`partials/nav.html` everywhere) |
| `{ fmt(x) }` in a template → `Undefined variable` under serve | The task was defined **after** the `serve` block — the per-request snapshot is taken there | Define tasks **before** `serve on`; then they're callable in holes |
| `{ each x in m }` over a map iterates entries | It walks the **keys** (v0.6.29+, in templates and in the language alike) | For pairs, `{ each e in items(m) }` → `e.key` / `e.value`; for indexes use `enumerate(list)` |
| Editing a template/CSS needs a server restart | Templates & statics hot-reload **per request** (mtime-based) | Just refresh the browser; only `.syn` changes need a restart (`serve --watch` automates it) |
| A typo in a `render("x.html")` path only fails on first request | `render("literal")` templates are validated **at startup** (fail-fast), and by `synsema check` | Fix the path/syntax; the program won't start until it's valid |
| `f.email` on a form without that field gives nothing | A missing map key is a hard error (`Map has no key`) | `get(f, "email")` → `nothing` when absent (v0.6.29+; `get(f, "email", "")` for a default), or check first: `"email" in f` / `contains(keys(f), "email")` |
| A CRLF (Windows) file with blank lines inside a block fails to parse | Fixed — blank `\r\n` lines no longer emit a phantom dedent (engine > v0.5.9) | Update the binary if you see `Unexpected token: INDENT` on a CRLF file |
| My `500` leaks a stack/message in production | Detail is shown in **dev**; `--secure` returns a generic body | Run with `--secure` in prod; the full detail still goes to the server log; an `errors with` task receives the redacted message under `--secure` |
| A slow handler is cut off after 30 s | Only if you declared `timeout` — **by default there is no limit** | `timeout N` on the serve block / `timeout none` per route; at the deadline: `504` + the handler is cancelled (v0.6.7+) |
| `try`/`recover` around a cancelled wait keeps the handler alive | Cancellation (`cancelled: …`) is observable but not curable — the next statement raises again | Clean up in `recover` and leave; kill/close what you own |
| `timeout 30` inside a `when` / a task | Runtime error: it is a clause of the serve block or the top of a route body | Move it to the top of the route body (once) or to the serve block |
| Opening a WebSocket to a `socket` route returns 426 | The request lacked the upgrade headers (or came over HTTP/2) | Use a real WebSocket client (`new WebSocket(url)`, `ws_connect`); the browser does it right |
| A `socket` route declared as `POST` | Parse error — the handshake is a GET (RFC 6455) | `route "GET /ws"` + `socket` |
| A `socket` handle stored in `state_*` to push from a cron | Handles don't cross requests (isolation) | Each socket handler subscribes to the bus (`bus_subscribe`) and forwards; the cron does `bus_publish` |
| My SSE clients need a "ping" event so proxies don't cut them | The server already writes `: keepalive` every 15 s idle (`SYNSEMA_SSE_KEEPALIVE`) | Drop the ping loop; keep `bus_recv(sub, 25)`-style bounded waits |
| Ctrl-C kills in-flight requests instantly | It drains: no new connections, streams/sockets cancelled, sized requests get `SYNSEMA_SHUTDOWN_GRACE` (10 s), exit 0 | Second Ctrl-C = exit 130 now; `SYNSEMA_SHUTDOWN_GRACE=0` for immediate |
| `give agents()` returns `{"items": …}` | `give <list>` always paginates | Expected — read `items`; or `give {"agents": agents()}` |

### Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| `give sql(...)` for a large table | Loads everything into memory each request | `paged()` for anything that can grow |
| Trusting `X-Forwarded-For` for identity | Rate limit uses the real peer IP (XFF is forgeable) | Don't trust XFF; per-user/trusted-proxy is future work |
| `give <list>` with `LIMIT` in your SQL | `total` becomes wrong (it counts only what you returned) | Return the full list, or use `paged()` |
| Long-lived SSE streams with default `max_streams` | Each holds a thread; you hit `503` under load | Size `max_streams` to your thread budget; keep streams short |

### Web auth (cookies, passwords, JWT, TOTP)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sha256(pw)` is fine for passwords | Fast hashes are crackable offline at GPU speed | ALWAYS `password_hash`/`password_verify` (argon2id, salted, tuned). `sha256`/`hmac` are for integrity, never for passwords |
| `set_cookie(..., {"same_site": "None"})` just works | Error: `SameSite=None` requires `secure: true` | Browsers reject SameSite=None cookies without `Secure` — the builtin fails at write time instead of you debugging a cookie that "never arrives" |
| Cookies work on `http://localhost` despite the `Secure` default | They DO — localhost is a secure context in modern browsers | If something odd remains, `{"secure": false}` in dev ONLY; never ship it |
| `totp(secret("TOTP_B32"))` with a base32 secret | The text is taken as raw UTF-8 → wrong codes | The classic TOTP confusion: decode first — `totp(bytes(seed_b32, "base32"))` |
| Any value can go in a cookie | RFC 6265 forbids spaces, quotes, `;`, `,`, `\` | Encode it: `set_cookie(resp, "v", decode(bytes(v), "base64url"))` (the error message says so) |
| `cors "*"` + cookie sessions | The CORS spec forbids `*` for credentialed requests | Use a specific origin: `cors "https://app.example.com"` |
| `jwt_verify` tells you WHY a token failed | It returns `nothing` for every failure (signature/exp/malformed) | By design: an endpoint must not be distinguishable by rejection cause. Log the attempt server-side if you need forensics |
| `token(8)` for a short session id | Error: minimum is 16 bytes | Fewer than 16 bytes of entropy is guessable; the default 32 is right for sessions |
| `token()`/`random_bytes()` work without a `require` | Capability error: `random` not granted | Randomness is deny-by-default, same gate as `random()` — add `require random`. The pure transforms (`password_hash`/`jwt_*`/`totp*`) need nothing |
| `totp_verify(seed, 094287)` (code as number) | Error: the code must be text | Leading zeros matter — quote the code |
| Store the PAT/API key as-is in the DB | A DB leak leaks every live credential | Store `sha256(token)`, compare hashes with `constant_time_eq` |

### Web Push / PWA (engine v0.6.15+)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `push_send(sub, msg, {"vapid": {"private": "BJx…"}})` with the key as text | Error: `opts.vapid.private must be a secret … Never pass a private key as a plain string` | Same doctrine as `sign`: `secret("VAPID_PRIVATE_KEY")` from `.env`, or `as_secret(v, "vapid")` for a runtime value |
| One `require net` covers push | `Capability not granted: net("web.push.apple.com")` for Safari users, or `net("jmt17.google.com")` for some Chrome users | Each browser has its own push service — and Chrome uses TWO domains: declare `fcm.googleapis.com`, `jmt17.google.com`, `*.notify.windows.com`, `updates.push.services.mozilla.com`, `web.push.apple.com` (the error names the missing one). Never "fix" it with `net("*.google.com")`: that opens egress far beyond push |
| A capability error in `push_send` = a dead subscription | It isn't — it's YOUR missing `require net`; dropping the subscription loses the user | Keep it and log; drop only on `gone` (404/410) or an error that names `subscription` (broken keys/endpoint). The v0.6.17 scaffold's `recover` does exactly that |
| `push_send` needs `require random` (it encrypts) | It doesn't — only `push_vapid_keys()` does | The per-message salt/ephemeral key are protocol-internal (like TLS); creating the VAPID pair IS new secret material |
| `print(keys["private"])` shows the key | `secret(vapid_private)` — redacted | It's born sealed; `require reveal("vapid_private")` + `reveal()` once (audited) to paste into `.env` |
| `push_send` returns `ok: false` and you retry forever | `gone: true` (404/410) means the browser unsubscribed | Delete that subscription; `retry_after` is set on 429/503 |
| A 5 KB notification body | Error: `payload is N bytes; Web Push allows at most 3993` | Push carries a pointer, not the data: send `{title, url}` and let the page fetch |
| Push works on the iPhone from Safari | Nothing (no `PushManager`) | iOS 16.4+ only from the app **installed** to the Home Screen, and after a tap; the scaffold's page says so |
| `/sw.js` mounted under `/static/` | The worker's scope is `/static/`, not the site | Serve it from the origin root: `static "/" from "./public"` |
| `manifest.webmanifest` served as `application/octet-stream` | Chrome won't offer install | The engine pins `application/manifest+json` (v0.6.15+); on older engines use `respond(read_file(p), "application/manifest+json")` |
| The scaffold's `POST /api/push/test` in production | Anyone can push to all your users | It's a demo button (rate-limited); put `requires auth` on it or send from a cron/agent |
| `init --pwa` on top of my app overwrote `app.syn` | It didn't — yours is kept, the factory one is `app.syn.new` | Copy what you need from the `.new`; `public/` is new either way |
| I changed `app.js` but the installed app still runs the old one | The shell is stale-while-revalidate: the cached copy answers, the refresh lands for the NEXT open | Open twice, or bump `CACHE` in `sw.js` (its `activate` drops the old cache) when you need it now |
| Tapping a notification opens a second, blank copy of the app | Not with the scaffold's `sw.js` (v0.6.16+): it focuses the open window and posts `{type: "notificationclick", url}` to it | Handle that message in `app.js` (the scaffold navigates to `url`); persist state that must survive an OS kill in `localStorage`/IndexedDB |
| Android shows a generic bell in the status bar | No `badge` in the notification | The scaffold sends `badge: "/badge-96.png"` (monochrome, generated from `badge.svg`); keep the file when you add it to an existing app |
| `pushManager.subscribe` fails right after "Allow" on Android | Known: the first subscribe after the permission grant can fail; the second works | The scaffold waits for the *activated* worker, reuses `getSubscription()`, and retries with backoff — copy that flow, and show `e.name + e.message` |
| `navigator.onLine` says online but nothing works | It only knows if there is a network, not if YOUR server answers | Probe `/api/ping` with `{cache: "no-store"}` (the scaffold's status line does) |
| Lighthouse: "any maskable" purpose flagged | Combined purposes are discouraged | Separate icons: `icon-512.png` (`any`) + `icon-maskable-512.png` (`maskable`) — what the v0.6.16+ manifest ships; add `screenshots` yourself |
| `synsema build` of the PWA fails: `has a serve block; pass --serve` | A `serve on` program only runs under the serve runtime | `synsema build app.syn -o app --serve --bind 0.0.0.0` (v0.6.16+); `public/` is bundled automatically |
| `synsema build --serve` stops with `needs to know where the server listens` | No `--bind` and no `bind "…"` clause in the serve block | Add `bind "127.0.0.1"` (local app) to the serve block or pass `--bind 0.0.0.0` (v0.6.18+; the flag wins) |
| `--icon on a macOS/Linux engine needs --bundle` | There the icon lives in the `.app` / the launcher entry, not in the binary | Add `--bundle` (or `-o x.app` on a Mach-O engine); `--icon` alone is for Windows engines |
| `--no-console applies to Windows executables (PE)` on a Mac/Linux build | The flag flips the PE subsystem; Mach-O/ELF have no console subsystem | Drop it: `LSUIElement` in the `.app` and `Terminal=false` in the `.desktop` are the equivalents `--bundle` writes |
| A `--no-console` build prints nothing, not even errors | By design: a GUI-subsystem exe has no stdout/stderr (discarded, no panic when launched by double-click, `Start-Process` or `cmd`) | Debug with the console build first; write your own log with `append_file` under `file.write` |
| `desk.exe --engine version` prints nothing (≤ v0.6.18) or, captured from PowerShell, dies with `failed printing to stdout … (os error 232)` | A GUI-subsystem exe has no console; PowerShell does not wait for GUI programs and closes the pipe under them | v0.6.19+: in `--engine` mode the build attaches to the parent console (prints in cmd/PowerShell; a redirected file/pipe is respected), and a vanished reader is a quiet exit 0 — same for `synsema run x.syn \| head` on Unix. Nothing to fix in the app |
| The desktop app never quits after its window is closed | Edge/Chrome are single-instance: the `--app=` launcher exits at once, so watching its process lies | Count windows with a `socket` route and call `shutdown()` from a cron tick when there are none (docs `41c-desktop`) |
| `shutdown() is only available under serve` | Called from a `synsema run` program | A run program ends with its top level; `stop` leaves a loop or a task. `shutdown()` is for routes/sockets/cron/agents under `serve` |
| Inline `<script>` in the desktop page breaks `render()` (`invalid expression { … }`) | Braces are template holes | Wrap literal JS/CSS in `{ raw } … { end }` or serve it from the static mount |
| Explorer still shows the old icon after a rebuild | Explorer caches icons per file name | Use a new file name or restart Explorer; the shell does read the new `.rsrc` (verified with `ExtractAssociatedIcon`) |
| `Name.app` from a download won't open on macOS | Gatekeeper: unsigned / not notarized, like any app without Developer ID | Right-click → Open (≤ 14) / "Open Anyway" (15); a locally built `.app` carries no quarantine. Built from Windows: `chmod +x Name.app/Contents/MacOS/<stem>` (the build says so) |
| `'rate_limit' inside a 'routes' group is not supported yet` at serve start (≤ v0.6.18) | Per-route `rate_limit`/`timeout` inside `export routes` were rejected, so a shared API lost its fine limits | v0.6.19+: they work inside groups (own zone per mounted route, a mount prefix is another zone). Older engine: set them on the serve block, or `synsema update` |
| `synsema check` says OK but `serve` refuses the routes group (`stream`/`socket` in a group) | ≤ v0.6.18 `check` did not run that validation | v0.6.19+ `check` fails with the same message; `stream`/`socket` routes stay in the serve block (not in groups) |
| `synsema --version` is not the version you just installed | Two `synsema` binaries in PATH (e.g. `%LOCALAPPDATA%\Synsema` and an old `~/.cargo/bin`) | `where synsema` / `which -a synsema`; remove the stale one — `synsema update` only updates the binary it runs from |
| Play/TWA can't verify the origin | It reads `/.well-known/assetlinks.json` | Put it under `public/.well-known/`; the static mount serves dot-directories as JSON |

### Spend ledger — units

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| The ledger is for money, so amounts are cents-sized | The unit is **free text and no currency is privileged** — fiat, crypto, commodities, credits, kWh | `spend(0.000000000000000001, "ETH", …)` (a wei) and `spend(1500, "JPY", …)` (no decimals) are equally valid; the scope of `require spend("…")` is whatever string you use |
| Any tiny amount works | Up to **28 decimal places**; finer errors clearly | 18-decimal crypto fits whole. Below that, spend in the base unit (wei instead of ether) rather than losing precision silently |
| `SYNSEMA_SPEND_CEILING="agent-1:EUR:50"` caps that agent | That's parsed as the **unit** `agent-1:EUR` | Per-identity ceilings live in their own variable with `=`: `SYNSEMA_SPEND_CEILING_PER_IDENTITY="agent-1=EUR:50"` — kept apart so a unit containing `:` can never collide with an identity |

### Agent identity (captokens, signed requests, OIDC, mTLS)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `let key be secret("X")` at the top level works inside a route | The handler gets it **redacted as text** (`http_sign`/`hmac` then error with "got text") | Globals are snapshotted per request and secrets are redacted crossing that boundary — by design. Resolve it **inside** the handler: `route "…"` → `let key be secret("X")` |
| `captoken_attenuate(t, caps, opts)` needs the root key | It deliberately does **not** take one — attenuating offline is the whole point | Only `mint` and `verify` take the key. If you find yourself passing it to attenuate, you're re-minting, not delegating |
| A sub-agent's attenuated token gets its own rate-limit budget | It keeps the **root token's `id`**, so it shares the delegator's quota | On purpose: delegating must not multiply the budget. Mint separate tokens (different `id`) if you really want separate quotas |
| `captoken_verify` tells you the token expired vs was forged | It returns `nothing` for every failure | Same doctrine as `jwt_verify`: an endpoint must not be distinguishable by rejection cause. Log server-side if you need forensics |
| The handler declares `require db("orders")`, so `sql(...)` works for any authenticated agent | With a captoken that does not carry `db("orders")` the call is **denied** and the client gets `403 insufficient permissions` (v0.6.28+) | The token IS the ceiling: `caps_effective ⊆ require ∩ host ceiling ∩ token`. Mint the token with what the holder needs (`llm`/`judge` included if it must reason). Return the identity as text from `auth with` if you truly don't want the ceiling |
| A 403 for a missing capability names what is missing | The body is always `{"error": "insufficient permissions", "status": 403}` | By design (never enumerate the surface to the caller). The detail is in the server log and the audit (`above delegated ceiling (token <id>)`) |
| `captoken_mint({"time": nothing, ...})` delegates the clock | Error: `"time" is process-local … a token cannot delegate it` | `stdout`/`stdin`/`time`/`random` belong to the process, not to the caller. To run the holder without clock/entropy use the caveat `{"deterministic": true}` |
| `Capability not granted: net("api.x")` means something is broken | It is a **permission**, and the message now says so and gives the exact line: `add require net("api.x") to the program's preamble (or to the importing file, when this code runs in a module)` | Add the `require` — in the file that IMPORTS a module (a top-level `require` in a module is an error). `synsema check` warns about it before you run |
| `sandbox under {"net": "x"}` on one line with an expression, like `sandbox expr` | Parse error: `sandbox under <caps> needs an indented body on the next line` | The `under` form is a block. `sandbox <expr>` (no `under`) is still the inline, no-capabilities form |
| A token with an `aud`/`ip`/`method` caveat verifies without passing that context | It's **rejected** (fail-closed) | You can't claim a condition holds if you never checked it. Pass it: `captoken_verify(t, k, {"aud": "orders-api"})` |
| `http_signature_verify(req, key)` picks the algorithm from the message | Error: `opts.alg` is required | Reading `alg` from the message is the classic confusion forgery (sign with the *public* key as an HMAC secret). The verifier pins it |
| A signed request verifies with a different body | The `Content-Digest` is part of the signature → rejected | Expected. Sign and verify the **same bytes**: serialize once (`json_encode`) and pass that exact text as `body` |
| `http_sign` works with a plain-string key | The key must be a sealed `secret` (its name is what scopes `require sign(...)`) | `secret("SIG_KEY")`, plus `require sign("SIG_KEY")`. Without the capability it's denied and audited, like signing on-chain |
| An hmac-sha256 signing key can be any text | Yes — but an **ed25519** key as text must be **hex** | Each algorithm keeps the engine-wide rule for its material: curve keys are hex/bytes, shared HMAC strings are raw |
| `jwt_verify` can check a Google/Auth0 token with `{"alg": "RS256"}` | It can't — that's `oidc_verify`, a different builtin | `jwt_verify` = HS256 with a secret you own (pure). `oidc_verify` = third-party RS256/ES256, mandatory `iss`+`aud`, and JWKS over the network (`require net(host)`) |
| `oidc_verify` without `aud` just checks the signature | It's an **error**, on purpose | A valid token minted for *another app of the same provider* would verify — the confused-deputy attack. `aud` is mandatory |
| A JWKS fetch failure means the token is invalid | Fetch failures are **errors**, not `nothing` | "I couldn't verify it" must never look like "it isn't valid". Only token problems are `nothing` |
| `webauthn_register` tells you which brand of key enrolled | It reports `fmt` and ignores `attStmt` on purpose (v0.6.28+) | Verifying attestation means shipping manufacturer trust lists — a dependency the engine does not take. Enrol keys, not brands |
| `webauthn_verify` keeps the counter between logins | It is stateless: `sign_count` comes back and you pass the stored one next time | Store `id`, `public_key`, `sign_count` at register; pass `opts.sign_count` (or keep it in the credential map) at verify — a counter that does not advance (cloned key) is `nothing` |
| `webauthn_verify(assertion, public_key, opts)` with the JWK alone | Error: pass the credential map (`{id, public_key, …}`), not the key alone | `rawId`/`userHandle` are not signed: the engine binds the assertion to the STORED credential id and returns the stored `id`/`user_handle`, never what the assertion declares (an attacker's key + the victim's id was an identity swap) |
| `receipt({"issuer": my_did})` / `receipt({"created": …})` | Errors: neither is an option | `issuer` is the did:key of the key that signs, `validFrom`/`created` are the engine's clock (omitted without `time`) — derived, so nothing can be antedated or issued in another's name; `receipt_verify` rejects an issuer that is not the verifying key |
| `webauthn_verify` says why it failed | `nothing` for every verification failure (challenge, origin, rpId, flags, signature, counter) | Same doctrine as `jwt_verify`. Only a malformed shape or a missing option (`rp_id`, `challenge`) is an error, with the fix |
| `canonical_json` serializes any map | It refuses what JCS cannot carry exactly: integers beyond 2^53, decimals with >15 significant digits, `bytes`, a `secret` | Put big numbers in the document as text; encode bytes first (`decode(b, "base64url")`); a secret is never serialized |
| `document_sign(doc, secret("K"))` just works | Denied: signing with a secret goes through `require sign("K")` (audited), like `http_sign` and on-chain signing | Add `require sign("K")`. A PEM passed as **text** (P-256 SEC1/PKCS#8, Ed25519 PKCS#8) needs no gate, like `ecdsa_p256_sign` |
| `receipt()` proves an agent did everything it was asked | It proves what THIS unit did (audit, tokens, spend, declassify, program sha) — not that there were no other units | Completeness is not a property any signature gives. Ask for receipts per request and count them yourself |
| The Agent Card says `supportedInterfaces: []`, so discovery is broken | It is the truth: the server does not speak the A2A transport (`message/send`), and the card never claims it | What is true is there: skills from the routes, auth, the did, OpenAPI. An A2A client reads it; an A2A *transport* is not what a Synsema server is |
| The Agent Card has no `signatures` / no `did` | No identity key configured | `SYNSEMA_IDENTITY_KEY=<64 hex ed25519 seed>` in `.env`, or `serve --attested` (then the attested P-256 key signs, `ES256`). Nothing is invented without a key |
| `jwt_verify(tok, {"did": did})` with a P-256 did on an EdDSA token | `nothing` — the key fixes the algorithm | Use the did of the key that signed; `kid` in the token (if any) must be `did:key:z…#z…` |
| `mtls_identity` applies to one request | It's **per process** (the certificate identifies the workload, SPIFFE-style) | Call it once at startup. Needs `require file.read` on both PEMs |
| Without `opts.hosts`, the certificate only goes where you meant | It goes to **every host the program may reach** — any server that asks for a client cert gets your workload identity | Bounded by `require net`, so with a narrow `net` scope it's already contained. With a broad one, scope it: `mtls_identity(c, k, {"hosts": ["*.mesh.internal"]})` |
| The server can require client certificates (`client_ca`) | Not yet — only the **client** side ships | Terminating mTLS on the serve side needs a new `serve` clause (parser work); use a reverse proxy in front meanwhile |

## The program's own terminal — `term_*` (engine v0.6.11+)

- **`term_open` returned `nothing` — that is the pipe/CI/serve/test path, not a bug**: fall
  back to `read_line`. It is also `nothing` in wasm. Never treat it as an error.
- **Waiting for a human with the default timeout**: `term_recv(h)` / `select([term])` time out
  after 30 s and return `nothing` — pass a timeout and `continue` on `nothing`.
- **Ctrl+C in raw mode is a key, not SIGINT**: the default `ctrl_c: "exit"` restores and exits
  130 for you; with `"key"` a hung loop is yours to break.
- **Shift+Enter is a plain Enter on most terminals** (needs the kitty keyboard protocol):
  make Alt+Enter the multi-line shortcut. On Windows a paste is a burst of `key` events, not one
  `paste` (`term_stats(h)["paste"]` is `false`).
- **Draw with `term_write`, not `print`**: `term_write` hits stdout now and is made for redraws
  (on engines ≤ v0.6.28 `print` was also held until `read_line`/`flush`/the end; v0.6.29+ writes it
  line by line under `run`). `print` still works (no staircase) — just not for redraws.
- **A second `term_open` errors** (one per interpreter, one per process): `term_close` first;
  a spawned agent cannot take the terminal while main holds it.
- **Don't undo what you didn't do**: the runtime restores raw mode/paste/kitty on close, drop,
  error and panic; the cursor you hid or the colours you set are yours to reset.

## Agentic apps — `select`, `proc_*`, `bus_*` (engine v0.6.7+)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `proc_spawn` works without a `require` | `Capability not granted: exec("cmd")` — same gate as `run`, never auto-granted | `require exec("cargo")` (scope = the command as written) |
| Under `synsema test` my agent never runs / `agents()` is unknown | Engines ≤ 0.6.9 did not wire the swarm in `test` (`spawn` ran the body in-process, blocking). v0.6.10+ runs agents for real in `test` | `synsema update`; each `test` block joins its agents at the end and an agent in `ERROR` fails that test |
| A `proc_spawn` child outlives the request / program | It is killed when its interpreter ends (TERM, KILL after 2 s) | For work that must survive, use `cron_after` or an agent |
| `proc_close`/`proc_kill` only killed the shell, its `node`/`python` child kept running (port still taken) | Fixed in v0.6.9: the child runs in its own process group / Job Object and kill reaches the **tree** (`proc_stats(h)["tree"]` is `true`) | Older engines: `run("taskkill", ["/T", "/F", "/PID", ...])` / `kill -- -pgid` yourself; to keep a daemon alive on purpose use `{"process_group": false}` |
| `watch` misses a change / reports it late | It polls (`interval`, default 0.5 s): the state at each tick, not the history | Lower `interval`; expect a rename as `delete` + `create`; dirs only `create`/`delete` |
| `watch(".")` is slow or errors "more than 100000 entries" | It walks the tree every tick; `.git`/`node_modules`/`target` are skipped by default, the rest is not | Narrow the path, add `ignore`, or raise `max_entries` |
| `proc_send` returns immediately | It is a blocking pipe write — a child that never reads stdin blocks you | Send what it reads; `proc_close_stdin` for EOF |
| `proc_recv` gives me a prompt without a newline | `line_mode` delivers per line; a partial line arrives at exit/EOF | `{"line_mode": false}` for raw chunks (still **text**, ≤ 64 KiB, UTF-8 safe) |
| The child skips its `y/N` question, hangs, or says "not a terminal" (`ssh`, `sudo`, `npm`, `inquirer` menus, `vim`, an agentic CLI) | Pipes are not a tty; the program decided before you could answer | `proc_spawn(cmd, args, {"pty": true})` (v0.6.8+); try `--yes` / `CI=1` first |
| Under `pty: true` my `proc_send("y\n")` is ignored | A tty wants keystrokes: Enter is `\r`; the prompt text also arrives with ANSI noise | `proc_send(h, "y\r")`; read with `strip_ansi(...)`; Ctrl-C = `bytes([3])`, Ctrl-D = `bytes([4])` |
| `proc_close_stdin` errors on a pty / stderr events never come | A pty has one stream and no separate stdin | Send the EOF key; stderr arrives as `stdout` |
| `proc_resize` errors | Only a pty has a size | Spawn with `pty: true` (`cols`/`rows` there too) |
| `bus_publish("agent.*", x)` broadcasts | Error: a published topic is literal — globs are for `bus_subscribe` | Publish `"agent.done"`; subscribe to `"agent.*"` |
| `bus_publish(topic, my_task)` | Error: tasks/secrets don't cross the bus (data only) | Publish text/number/bool/list/map/bytes |
| A slow subscriber stalls the publisher | Default `on_full` is `drop_oldest` (bounded queue); the publisher never blocks | Read faster / raise `max_queue`; `"error"` if losing events must be loud |
| The bus reaches another process / node | In-process only | Same API on Redis is the roadmap; today one process |
| `select([])` waits | Returns `nothing` at once (nothing to wait for) | Check you passed live handles |
| `ws_select` rejects a process handle | It accepts any handle now (with its historical `conn` tag) | `select` is the same wait with `source`/`handle` tags |
| `agent_stop(id)` returns `false` | The agent was already `done`/`error`/`stopped` (or the id is wrong — ids come from `agents()`) | Use the `id` (`Name_0`), not the declared name |

## Language features — bytes, complex, arrays, match, params, tests

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `text(bytes(...))` decodes to a string | Shows a hex repr like `bytes(48656c6c6f)` | By design (non-lossy). Use `decode(b)` to get the text (UTF-8 strict). |
| `decode(b)` on non-UTF-8 returns garbage | It **errors** (UTF-8 is strict by default) | Use `decode(b, "utf8_lossy")` to replace invalid bytes with `U+FFFD` |
| `bytes("abc") == "abc"` | `false` — bytes **never** equals text, whatever the content | Compare `decode(b) == "abc"` instead (or `hex(b) == "0x…"`) |
| `bytes("0x9", "hex")` for a quantity | Error — odd length (the message points to `int("0x9")`) | `bytes(…, "hex")` is for data (the `0x` prefix is accepted since v0.6.29); a quantity is `int("0x9")` |
| `sqrt(-1)` returns a complex number | Returns `NaN` (real math is unchanged) | Use `sqrt(complex(-1, 0))` → `complex(0,1)` for the complex root |
| `complex(1,0) < complex(2,0)` works | Error: "complex numbers are not ordered" | Complex has no ordering (like Python). Compare `abs(z)` if you need magnitude. |
| `array * array` is the matrix product | It's **elementwise** (Hadamard) | Use `matmul(a, b)` for the matrix product (`dot` is 1-D vectors only since v0.6.29). `*` is elementwise. |
| `inv`/`solve` of a singular matrix returns NaN | It **errors** (no silent NaN) | Check `det(A)` first, or `try/recover` |
| Linear algebra works on n-D arrays | LA (`solve`/`det`/`eig`/`svd`) is **2D only** | Reshape to 2D; n-D is for storage/vectorized math (like `numpy.linalg`) |
| An array holds ints/strings | Arrays are **f64** only (this version) | Use a `list` for mixed/other types; `to_list(a)` converts back |
| `match x is {}` matches an empty map | Matches **any** map (`{}` is a map pattern) | To match an empty map use a guard: `is m when length(m) == 0` |
| `match x is myvar` binds `myvar` | Top-level `is myvar` **compares** against the value of `myvar` (does NOT bind) | Binders live only inside `[...]`/`{...}`/variant patterns and `_`. To always match, use `is _`. |
| `match x is {status}` works on a serve response value | Map patterns match plain `map` values, not server response values | Match the underlying map, or check fields with `of` |
| `apply(list, fn)` errors ("apply takes fn first") | Both orders work now: the intentional family (`apply`/`where`/`transform`/`reduce`/`sort_by`/`group_by`/`find_first`/`every`/`some`/`count_where`/`zip_with`) accepts `(fn, list, …)` AND `(list, fn, …)` | Either reads fine; the canonical documented idiom stays `apply(fn, list)`. Two tasks or two lists where one-and-one is expected → explicit error (never guessed) |
| `user of request.role` gets the user's role | It parses as `user of (request.role)` → `Map has no key 'role'` (the error now carries this hint) | Bind first: `let u be user of request`, then `u.role` |
| `f(1)` to `task f(a, b)` quietly passes `nothing` for `b` | Error since v0.6.29: `task 'f' is missing argument 'b' — pass it, or give the parameter a default` (before, `b` was `nothing`); one too many is an error too | Give `b` a default: `task f(a, b = 0)`; or pass it |
| `set xs to append(xs, x)` in a loop is quadratic | O(1) amortized since v0.6.29 when nobody else holds the list (100k appends: minutes → under a second) | Keep writing it; don't keep an extra alias to the list inside the loop (a shared list is copied on write) |
| A task changes the map it received and the caller sees it | Value semantics since v0.6.29: the task changed its own copy | `give` the new map and `set m to f(m)` in the caller |
| `int("ff", 16)` parses hex | Returns **16** — there is no base argument; the 2nd argument is the default of the total form | `int("0xff")` (also `0b…`); `int(1.5)` errors on purpose (`floor`/`round`/`trunc`) |
| `1e18` is an exact wei amount | `1e18` is a **float** (like Python) — `abi_encode` rejects it for a uint256, and a float is not exact money | `10**18` or `1_000_000_000_000_000_000` |
| `sort([1, "a"])` puts numbers first | Error `cannot order number and text together`; maps → `… has no order` | Make the values comparable; `nothing`/NaN are fine (they go last, NaN before nothing) |
| `sort(["b", "a", "C"])` is case-insensitive | Text sorts by code point: `["C", "a", "b"]` | `sort_by(xs, (s) => lower(s))` |
| `min([3, nothing, 1])` errors | `nothing` is skipped as missing data → `1`; a NaN anywhere → NaN; all missing → error. Every reduction behaves the same (`sum`, `mean`, `median`, `std`, … — v0.6.29) | Filter first if missing must be loud |
| `std(xs, 0)` is the population std | Error (`std() takes a list (or an array)` on a list; on an array the positional 2nd argument is the **axis**) | `ddof` is named-only: `std(xs, ddof = 0)` |
| `length(array([[1,2],[3,4]]))` counts every element | It is the **first dimension** (`2`), like numpy `len` (v0.6.29) | `size(a)` for the total (`4`) |
| `"x"[0]` / `xs[-1]` error | They work since v0.6.29 (text is indexable by character; negatives from the end) | — |
| `f(x = 1)` and `f(x == 1)` are the same | `=` is a **named arg**; `==` is an equality expression passed positionally | Use `=` for named args/defaults, `==` for comparison |
| `test "..."` blocks run under `synsema run` | They're **skipped** by `run`; only `synsema test` runs them | Run `synsema test file.syn`. See [testing.md](testing.md). |
| `assert_error(() => give 5)` passes | A `give` is not an error → it **fails** | `assert_error` passes only if the function raises a runtime error |
| `try/recover` lets the error bubble up | `recover` **swallows** it — the task/agent ends normally (DONE) | To re-propagate, call `raise(err)` inside `recover` (agent ends ERROR). `fail()` is HTTP-only, not for this. |
| `signal "x:" + text(id)` must be a literal | The channel name is an **expression** — dynamic names work | Use `signal`/`wait_for` with a computed name for per-job channels (see agents.md) |
| A route's `wait_for` hangs the request 30s when no signal comes | That's the **default** timeout | Set it: `wait_for "x" timeout 2 as r` (seconds, 0–3600). Bounds the wait so requests don't pile up. |

## Data & charts (CSV / stats / chart_svg — see [dataviz.md](dataviz.md))

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `csv_parse` converts `"42"` to a number | Everything stays **text** by default (lossless: `"00123"` is preserved) | Type the columns: `{"types": {"qty": "int", "price": "decimal", "day": "date"}}` (v0.6.29). `{"numbers": true}` still exists but guesses (`"007"` → `7`) |
| An empty CSV cell is `""` | It is **`nothing`** (missing) since v0.6.29, typed or not | `drop_missing(rows, "col")` / `fill_missing(rows, {"col": 0})` on purpose |
| `percentile(xs, 0.9)` is the 90th percentile | `percentile` takes **p ∈ [0, 100]** — that is the 0.9th percentile; `synsema check` warns on a literal in (0, 1) | `quantile(xs, 0.9)` (q ∈ [0, 1]) or `percentile(xs, 90)`. `quantile(xs, 90)` errors (`between 0 and 1`) |
| `join(rows, other, "id")` joins text | With 3–4 arguments `join` joins **tables**; with 2 it joins text (`join(xs, ", ")`) | Arity decides — `join(xs, sep)` is unchanged |
| A repeated column after `join` overwrote mine | The right side's non-key column gets the suffix **`_right`** (`a`, `a_right`) | Rename or `collect` the one you want after the join |
| `pivot` keeps the first value when two rows share a cell | **Error** `… rows fall in the same cell … — pass agg` (never a silent first) | `pivot(rows, "day", "product", "qty", sum_of("qty"))` |
| `summarize(rows, (r) => …, aggs)` keeps a column with my name | With a **function** key the key goes in a column called `key`; with a column name it keeps that name | Name the key column afterwards, or group by a real column |
| `parquet_write` of rows with a list/map value, or a column mixing int and text | Error — Parquet here is flat and one type per column (`… mixes …`, `json_encode` first) | `json_encode` the nested column; make the column one type (int + float is fine → DOUBLE). A `duration` → store `in_units(d, "seconds")` |
| `parquet_read` in the browser/wasm build | Not there — Parquet is native only | Convert on the server, ship JSON/JSONL |
| `date(2026, 1, 1) + duration(hours = 1)` | Error: `a date moves by whole days — use a datetime …` | `datetime(d, "UTC") + duration(hours = 1)` (or the right zone) |
| `datetime("2026-03-29T02:30:00", "Europe/Madrid")` | Error: that local time **does not exist** (DST gap); a repeated local time (fall back) takes the first | Build from UTC or an offset (`datetime("…T01:30:00Z")`), or catch it and move the time |
| `dt + duration(days = 1)` keeps the wall-clock time | A duration is **elapsed** time: across a DST change `+1 day` lands an hour off (Madrid 12:00 → 13:00) | `add_days(dt, 1)` (same local time), `add_months` for months |
| `datetime("2026-01-03T10:00:00-03:00")` keeps `-03:00` | An offset without a zone name is stored as the instant and shown in **UTC** (`…13:00:00Z`) | Pass the zone: `datetime("2026-01-03T10:00:00", "America/Buenos_Aires")`, or `to_timezone(dt, "America/Buenos_Aires")` |
| `date("31/01/2026")` | Error — `date(text)` is ISO only (`YYYY-MM-DD`) | `parse_date("31/01/2026", "%d/%m/%Y")` |
| `let h be g` gives an independent copy of the generator `g` | A generator is ONE stream: `g` and `h` take turns on the same sequence | Separate streams need separate seeds: `rng(1)`, `rng(2)` |
| `rng(seed)` for a token/password/nonce | It is a reproducible PRNG — anyone with the seed has the output | `token()` / `random_bytes(n)` + `require random` |
| A 9th series/pie-slice picks a 9th color | **Error** — colors are never cycled (colorblind-safety: the fixed order is the mechanism) | Group the tail into an "Other" bucket, or pass your own `{"colors": [...]}` |
| `{"x": "mes"}` works with a map or number list | Error: `x`/`y` only apply to a **list of maps** (rows) | Other shapes carry their own x (labels/index/pairs) — drop the opts |
| A NaN/infinite value plots as a gap | **Error** (a silent gap or a broken SVG would lie to the reader) | Filter first with `where(...)` + `is_finite(...)` |
| `histogram` counts every value with explicit edges | Values **outside the edges are discarded** (NumPy semantics) | Widen the edges, or use integer `bins` (auto range [min, max]) |
| `chart(...)` returns SVG text | It returns a **content node** (negotiated HTML/MD/JSON) | For raw SVG text use `chart_svg(...)`; `chart()` lives inside `content(page([...]))` |
| A `"stacked_bar"` kind exists | No — stacking is an **opt**: `"bar"`/`"area"` + `{"stack": true}` | Stacked area with mixed signs at one x errors (ambiguous) → use stacked bar |
| Waterfall takes running totals | It takes **deltas**; the running total is computed for you | The MD/JSON outputs include both `delta` and `running` |
| `{"center": n}` works with the default heatmap scale | Error — `center` requires explicit `{"scale": "diverging"}` | `"auto"` already centers on 0 when values cross it; `center` is for other pivots |
| `{"bins": 4.0}` (float) works like `4` | Error — bins must be an **integer** or an ascending **edge list** | Mirrors `histogram()`; convert first with `int(x)` (whole floats) or `round(x)`/`floor(x)` |
| Boxplot draws a group of 1 value | Error — **≥2 values per group** (a 1-point box is garbage) | Aggregate differently or drop the group |
| `svg_to_png` renders animations / scripts | The PNG is the **static** state (resvg ignores scripts/SMIL) | By design — nothing in an SVG ever executes |
| A `<image href="http://...">` loads in the PNG | Never fetched — **no network, no disk** from a pure builtin | Embed the image as a `data:` URL if you need it rasterized |
| Any font in the SVG renders as requested | One embedded sans (DejaVu); unknown families fall back to it unless you pass them in `opts.fonts` (v0.6.20+, `file.read` per font); missing glyphs (full CJK, color emoji) → tofu | Deterministic by design; custom/system fonts may come later |
| Huge `width`/`scale` just works | Above ~16.7M output pixels → error naming `max_pixels` | Deliberate anti-DoS ceiling; raise it explicitly: `{"max_pixels": n}` |

## Blockchain (sign/verify — see stdlib.md § Blockchain)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `keccak256` == SHA3-256 | Different padding: `keccak256("")` = `c5d24601…`, SHA3-256 = `a7ffc6f8…` | Ethereum uses PRE-NIST Keccak; `keccak256` gives you the Ethereum one |
| Pre-hash the message before `ed25519_sign` | Wrong signature (double hash) | ed25519 signs the **raw message** (RFC 8032); only secp256k1 takes a 32-byte digest |
| Pass the key as a hex string | Error — the key must be a `secret` | `require secret("K")` + `secret("K")`, or `as_secret(hex, "K")`; text secret = hex, bytes secret = raw |
| Signing works like hashing (pure) | Deny-by-default: needs `require sign("KEY_NAME")` + writes an audit entry; denied inside `sandbox` | Signing moves value — scope it to the key secret's name |
| Paste `slice(sig, 0, 32)` as r into the tx list | ~1 in 128 txs invalid (r/s must be RLP **integers**, minimal) | `bytes_to_int(slice(sig, 0, 32))`; `int_to_bytes(n, 32)` restores fixed width |
| `rlp_decode` accepts anything `rlp_encode`-shaped | Non-canonical encodings **error** (like Ethereum's decoders) | Two different byte strings never decode to the same structure silently |
| `ed25519_verify` accepts any RFC 8032 signature | **Strict**: small-order keys/points rejected (what Solana/Algorand reject) | A lenient verifier would accept forgeries the chain refuses |
| Sign inside a `cron` job with a top-level secret | The secret crosses **redacted** (safe but unusable) | Resolve the key INSIDE the task body: `let k be secret("HOT_KEY")` |
| `abi_encode("transfer(address to, uint256 amount)", …)` | Error — the ABI signature is **canonical** | No spaces, no parameter names: `"transfer(address,uint256)"` (the error shows the canonical form; `uint`→`uint256` normalizes) |
| Pass a token amount as a float (`1e24`) | Error — uint256 needs **exact integers**, and `1e24` is a float literal | `10**24` or the integer literal (`1_000_000_000_000_000_000_000_000` promotes to big int exactly); from text, `int("…")`; floats lose precision on money |
| Divide a big amount with `/` | `/` always goes through a float — above 2^53 it silently rounds | `a // b` (v0.6.29+) is exact floor division for integers of any size; `a % b` the remainder |
| `number("123456789012345678901")` | Error naming `int` since v0.6.29 (it used to round silently) | `int("…")` — exact |
| `algorand_tx` keeps `amt: 0` / empty `note` | Zero/empty/false fields are **OMITTED** (canonical msgpack, keys sorted) | That's what the network requires — emitting them changes the TXID or gets the tx rejected |
| Solana keeps accounts in the order you list them | Reordered by runtime rules (payer first; writable signers → ro signers → writable non-signers → ro non-signers; buckets sorted by pubkey bytes) | Matches the official SDK byte-for-byte; instruction indices point at the reordered table |
| Sign a v0 Solana message without its 0x80 prefix | Invalid signature on-chain — the signature **covers the version prefix** | `solana_tx({..., "version": 0})` already includes the prefix; sign its output as-is |
| Pass `lookup_tables` to `solana_tx` | Clear error: "not supported yet" | v0 without tables works today; PDAs/SPL now ship (`solana_pda`/`spl_ata`/`spl_transfer_checked_data`) |
| A deeply nested type / typed-data / txn / derivation path is fine | Nesting over **64 levels** (or a path over 256 chars / 32 segments) errors, atrapable | A DoS guard (like RLP's) — no real payload/path is that deep; hostile input can't crash the process |
| Derive Solana with a normal BIP-32 path | Wrong key — Solana uses **SLIP-0010**: `hd_derive(seed, "m/44'/501'/0'/0'", "ed25519")` (hardened-only; a non-hardened index errors) | ETH is the default `"secp256k1"`; ed25519 has no non-hardened derivation |
| Load an Algorand wallet phrase with `mnemonic_to_seed` | Algorand's 25-word phrase is **NOT BIP-39** — use `algorand_mnemonic`/`algorand_mnemonic_to_key` | Different checksum (sha512_256 over the key) and 11-bit packing; the 12/24-word BIP-39 path is for ETH/Solana |
| `mnemonic_generate`/`hd_derive`/`keystore_import` return usable bytes | They return a `secret` — `text()`/`json_encode` show `secret(NAME)`/`[redacted]` | Use it directly with `hd_derive`/`evm_address`/`secp256k1_sign`; back a phrase up on purpose with `reveal()` (gated + audited) |
| `reveal("W")` reveals the seed derived from a `"W"` mnemonic | Derived secrets carry a **derived name**: `mnemonic_to_seed` → `W.seed`, `algorand_mnemonic` → `W.mnemonic`, `hd_derive` → `W/path` | Grant with the prefix `reveal("W*")` (or the exact derived name); the `wallet`/`sign` scope of a derived key follows the same derived name |
| Custody works with `require sign` (or ambient) | Creating custody needs its OWN capability: `require wallet` (deny-by-default, audited in `wallet.log`, denied in `sandbox`) | `wallet` creates keys, `sign` moves value — an agent can derive addresses without spending |
| A wrong keystore passphrase returns garbage / partial key | Clear "wrong passphrase" error, **no material** — the MAC is checked before decrypting | Same for a bad mnemonic checksum: the error never echoes the phrase |
| A keystore with huge scrypt `n` grinds the CPU | Rejected fast ("out of the accepted range") before any KDF work | Anti-DoS cap on n·r and pbkdf2 c; Geth defaults (n=262144) pass |
| `ws_recv` blocks until a message arrives | Returns **`nothing`** after the timeout (default 30s) — never blocks forever | `let m be ws_recv(conn, 5)`; ping/pong handled transparently; a huge frame errors (16 MiB default cap), never buffers unbounded |
| `ws_connect` needs a new capability | It reuses **`net(host)`** (same scope as `http_*`); denied in `sandbox`; `wss://` validates the cert (every reconnect too) | No new door — WebSocket is transport, gated exactly like HTTP |
| Loop `ws_recv` over N connections to watch many feeds | O(N) busy-poll — use **`ws_select(conns, timeout)`** (readiness-driven, CPU ~0 idle, scales to thousands) | One call watches all; it returns `conn` (WHICH fired) and `name` if `conns` is a name→handle map |
| `ws_select` tells you a message arrived but not from where | It returns `{conn, type, data, name?}` — `conn` is the handle that fired | For a name→handle map you also get `name`; a dropped feed comes back `{type: "close", conn}` so you know which to resubscribe |
| Reconnection happens automatically | **Opt-in only:** `ws_connect(url, nothing, {"reconnect": {...}})`. Without it a drop is a `close`/error (batch-13 behavior) | Nothing silent — you asked for it. `on_reconnect` (a task) runs after reconnect to resubscribe; every attempt re-checks `net(host)` |
| Keepalive runs in the background | The engine is sync — keepalive/reconnect only tick **inside** `ws_select`/`ws_recv`/`ws_status` | Run your event loop (`while` + `ws_select`); a lone `ws_send` with no later recv won't advance timers |
| A slow consumer + fast feed grows memory unbounded | Inbound queue bounded in **messages AND bytes** (`max_queue` 1024 / `max_queue_bytes` 64 MiB) + **TCP backpressure**: at either cap it stops reading the socket, the peer throttles (no loss, no OOM) | `on_full`: `"block"` (default, backpressure), `"drop_oldest"`, or `"error"` (drains what's queued, then a catchable error — never a silent drop). A flooding server can't OOM you, even with big frames |
| A handle from one `parallel_map` worker works in another | Handles do **not** cross workers (CSP isolation) — each worker owns its own WS registry | The fan-out pattern is `parallel_map(watch_feed, urls)`: N workers × 1 connection each; never pass a handle between them |
| A half-open socket (peer vanished silently) stays "open" | With `keepalive` it's detected within `timeout` (auto-ping, no pong → dead) → reconnect or `close` | `{"keepalive": {"interval": 20, "timeout": 10}}`; `ws_status`/`ws_stats` report the truth |
| Opening connections in a loop is fine | A soft per-interpreter cap (`SYNSEMA_WS_MAX_CONNS`, default 4096) errors clearly when exceeded | Anti-footgun: a runaway loop can't open 100k sockets; close handles you're done with |
| The RPC read-side (`evm_*`/`solana_*`/`algorand_*`/`btc_*` net calls) needs a new capability | Same **`net(host)`** as `http_*`; broadcasting is `net`-gated too (the signature already happened; `sign` stays the only value door) | A monitor agent with `net` reads everything and spends nothing |
| `evm_tx` fills sensible gas/fee defaults | **No silent defaults** — a missing `max_fee`/`gas`/`value` errors naming the reader helper (`evm_fee_history`/`evm_estimate_gas`) | Anti blind-signing extended to fees; the result map echoes every number for a `confirm` before signing |
| Reassemble the signed tx by hand (`bytes([2]) + rlp_encode(...)`) | Still works, but `evm_tx_raw(tx, sig)` does v/r/s (y-parity, minimal ints) for you | Pass the 65-byte sig from `secp256k1_sign` as-is — 27/28 v values (an `evm_signature` output) are rejected with a clear error |
| Deploy a contract with `evm_tx` and no `to` | Error pointing to `evm_tx_create` (v0.6.29+; before, a creation tx could not be built at all) | `evm_tx_create({chain_id, nonce, from, value, gas, max_fee, max_priority, data})` → `contract_address` included; `data` = bytecode + `abi_encode("(types)", args)`; empty `data` or > 49 152 bytes → error |
| Sign a creation with a different key than `from` | `evm_tx_raw` recovers the signer and errors: `the signature is from 0x…, but the creation declared from 0x…` | The `contract_address` is derived from `from` + `nonce`; sign with that account's key |
| `evm_create2_address(deployer, salt, hash)` with a short salt | Error — `salt` and the init-code hash are exactly 32 bytes | `int_to_bytes(n, 32)` / `keccak256(init_code)` |
| Compare `abi_event_topic(…)` with `bytes` | It returns **text** `"0x…"` — the form `log.topics[0]` has | Compare text with text |
| `abi_decode_log` on a log from another event / a different ABI | Error (topic0, topic count and `data` are all checked strictly) — or the `default` you pass | Filter by topic0 first (`evm_logs(url, {"topics": [topic]})`), or use the total form `abi_decode_log(ev, log, nothing)` |
| An indexed `string` in `abi_decode_log` gives back the text | It gives its **bytes(32) keccak hash** — that is all the log carries | Compare with `keccak256("expected")` |
| `evm_logs` filter with `from_block` / both `fromBlock` and `blockHash` | Error — the filter uses the node's **wire names** and they are validated | `fromBlock`/`toBlock` **or** `blockHash`; `topics` entries: `"0x…"`, `nothing` (any), a list (OR) |
| A weird RPC response gets patched up | **Strict decode**: non-canonical hex-quantity (`0x01`), wrong shape, mismatched id, >16 MiB body → catchable error | A node is untrusted input (G23) — bad data never silently becomes a number |
| `evm_wait` ≠ success; `receipt` ≠ profit | It confirms **inclusion**: check `receipt["status"]` (0 = reverted) and Solana `status["err"]` | A tx can land AND fail; the waiters return the data, you check it |
| `evm_wait`/`solana_wait`/`algorand_wait`/`btc_wait` hang until confirmed | Bounded polls: **`nothing`** at the timeout (default 60s), like `ws_recv` | An unconfirmed tx never hangs the agent; `algorand_wait` errors on a pool rejection (definitive) |
| Algorand's suggested `fee` is the flat fee | It's **per byte** (often 0); the flat minimum is `min_fee` (1000 µAlgo) | `algorand_params` returns BOTH so neither mistake compiles into a rejected/overpaid tx |
| `spl_balance` on a missing token account returns 0 | Catchable **error** (the ATA doesn't exist) | A wrong owner/mint would silently read 0 forever; on success the map includes the derived `ata` so you can verify it |
| A network blip (5xx / dropped connection) mid-wait kills the waiter | After a first successful poll, **transient** failures retry until the deadline (one stderr notice, no agent action needed) | Deadline mid-failure → the ERROR surfaces (not `nothing`) — "unconfirmed" ≠ "node stopped answering"; a wrong URL still fails fast on the FIRST poll |
| An L2 (Base/Arbitrum/Optimism) needs its own builtins | Same EVM wire — `evm_*` work as-is; read the chain id with `evm_chain_id(url)`, never hardcode | OP-stack: `evm_estimate_gas` is L2-execution only; the L1 data fee lands in the receipt (`l1Fee`, exact int) — total = gasUsed×effectiveGasPrice + l1Fee. Arbitrum folds it into gasUsed |
| `btc_tx` puts the fee wherever there's leftover | The fee is IMPLICIT (inputs − outputs); `btc_tx` requires it **declared** and checks `sum(inputs) == sum(outputs) + fee` (G28) | If it doesn't balance, the error names the exact sat diff ("did you forget the change output?") — forgetting change donates it to miners |
| The builder computes the change output | **No** — change is one more EXPLICIT output to your own address; coin selection is yours (out of scope) | Add `{"address": my_addr, "amount": total_in - sent - fee}`; a float amount errors (everything is exact SATS, 1 BTC = 100_000_000) |
| Sign the Bitcoin transaction once | Sign **once per input** — `btc_tx` returns `digests` (one each, right sighash: BIP-143 P2WPKH / BIP-341 P2TR); pass one sig per input to `btc_tx_raw`, same order | Only SIGHASH_ALL/DEFAULT; NONE/SINGLE/ANYONECANPAY error (out of scope) |
| A taproot address is my public key | It's the **TWEAKED** key (BIP-341 key-path); `btc_address(k, "p2tr")` / `schnorr_sign(digest, k, "taproot")` tweak internally | You never tweak by hand — the classic bug. `schnorr_sign` uses the SAME `sign` gate (no new capability) |
| bech32 works for every segwit address | BIP-350: v0 (P2WPKH/P2WSH) = **bech32**, v1 (taproot) = **bech32m**; the wrong variant is REJECTED | Lax decode = burned funds. A cross-network address in a tx errors naming both networks |
| Read the txid straight off the raw bytes | `btc_txid` is dSHA256 **without witness**, **byte-reversed** (the explorer/RPC form) | Avoids the classic "my txid is backwards"; `btc_send` re-checks the node's txid against the bytes |
| `btc_tx_raw` trusts the signatures I pass | It VERIFIES each signature against the UTXO's key **before assembling** — a wrong-key sig errors, nothing broadcast | The P2WPKH witness is DER+SIGHASH_ALL (low-s enforced) — you never touch DER |
| A tiny output (100 sats) is fine | Below the dust limit (546 P2PKH / 294 P2WPKH / 330 P2TR) → error naming the limit (it wouldn't relay) | `fee > sum(outputs)` also errors unless `"allow_absurd_fee": true` (explicit opt-in) |
| Export a WIF back out of a secret | `wif_import` exists (gated by `wallet`); the reverse export does NOT — no builtin returns a key | The deliberate backup is `reveal()` of the mnemonic; HD for BTC: `hd_derive(seed, "m/84'/0'/0'/0/0")` (BIP-84) / `"m/86'/0'/0'/0/0"` (BIP-86) |
| PSBT needs a signing capability | `psbt_encode`/`psbt_decode`/`psbt_finalize` are PURE — the cold-custody flow (agent prepares, human signs on a hardware wallet, agent finalizes+sends) needs no `sign` | The key never exists on the agent's machine; `psbt_decode` audits amounts/fee before you broadcast someone else's PSBT |

## Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| String on multiple lines | `Unterminated string` error | Use `\n` or concatenate: `"line1\n" + "line2"` |
| `remember("preferencia", ...)` works | Error: invalid category | Categories are English: `preference`, `rule`, `learning`, `decision`, `context` |
| `intent: "..."` restricts what the program can do | No — the intent is descriptive only | Security is enforced by capabilities (`require`), in any language. The intent text never blocks. |
| `wait_for` wakes all waiters on one `signal` | Only ONE waiter gets it | Signals are a queue (consumed on read). For fan-out, emit N signals or use blackboard. |
| `wait_for` hangs forever on dead agent | Returns `nothing` quickly | The runtime detects this and returns — but ONLY when agents WERE spawned and all of them died. |
| `wait_for "x"` returns instantly when no agent was ever spawned | It blocks until the `timeout` (default 30s) | The fast return is for "all spawned agents died", not "zero agents". With no producer ever spawned, the runtime can't know none is coming → it waits. **Always pass a bounded `timeout`** when an emitter might be absent: `wait_for "x" timeout 2 as r`. |
| Agent shares state with main program | Each agent has its own interpreter | Use `share`/`observe` via blackboard to communicate. |
| `number("1200")` gives integer | Gives `1200.0` (float) | `int("1200")` → `1200` (exact, v0.6.29+) |
| `/tmp/file.txt` works on Windows | Maps to `C:\tmp\file.txt` | Use absolute paths. For agent data, use `~/.synsema/` paths. |
| Cron output appears after program ends | Output is buffered | Fixed in recent versions. Update to latest. Use `synsema serve` to keep the process alive for live output. |
| An unknown `--flag` is ignored | (v0.6.14+) it's a **usage error, exit 2** on `run`/`test`/`conform` | Typos are caught, not silently dropped. `synsema run --audit json p.syn` now works; before, `--audit` was ignored and `json` taken as the path. |
| `print` works under any `--cap-set` | (v0.6.14+) under a ceiling, `stdout` is a real capability | A `--cap-set` without `stdout` denies output at the first `print`/`show`/`log`. `--sandbox` includes it; no ceiling = output free. |
| `render("page.html")` needs no capability | (v0.6.14+) a **disk** template read needs `require file.read("page.html")` | Closes reading arbitrary files via a request-derived path. Nested `include`/`layout` and **bundled** (`synsema build`) templates don't; one line covers a tree: `require file.read("templates/*")`. |
| `run("printenv")` under `exec` dumps my API keys | (v0.6.14+) Synsema's secrets (provider keys + `.env` vars) are stripped from the child env | The base OS env (`PATH`…) is kept; pass a secret a child needs explicitly via `opts.env`. Same for `proc_spawn`. |

## Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| No `try/recover` around HTTP/SQL/LLM | Agent dies on first network error | Wrap I/O in `try/recover` with fallback |
| Relying on the `intent:` text to restrict actions | The intent doesn't authorize anything | Declare permissions with `require`; the intent is only a description |
| One `signal` for N consumers | Only one gets it | Use blackboard keys per worker, or emit N signals |
| `share x as "result"` from N workers | Last write wins, others lost | Use dynamic keys: `share x as "result_" + text(n)` |
| No `require` and wondering why I/O fails | Zero-access-by-default | Always declare `require` at top of program |
| `set x to 5` without prior `let x be ...` | Runtime error | Always `let` before `set` |

## v0.6.20 — what changed under your feet (verified live)

| What you expect (from ≤ v0.6.19) | What actually happens now | Why / workaround |
|---|---|---|
| `http_post(url, {"a": 1})` sends `{a: 1}` as text with no header | It sends **JSON** with `Content-Type: application/json` (a list too); text goes as-is, bytes raw | Your own `Content-Type` header wins. `json_encode(map)` + header still works everywhere |
| `json of r` → `Map has no key 'json'` | `json of r` exists: the parsed body when the server said JSON, else `nothing` | Branch on it; `json_decode(body of r)` still fine |
| `body of r` is enough for a PDF/image | Still lossy text | `http_bytes(...)` → `bytes of r` (exact) |
| `split(s, "")` errors | Returns the characters | Same as JS/Python `list(s)` |
| `cwd()` works without a capability | `Capability not granted: file_read(".")` | `require file.read(".")` (or `./*` / `*`) — the grant of `list_dir(".")`; `./data/*` does NOT cover it |
| `delete_dir("./tmp")` removes a tree | Error `"tmp" is not empty (pass {"recursive": true} …)` | `{"recursive": true}` + `file.write` on the dir AND every path inside (`./tmp` + `./tmp/*`) |
| `zip_extract(z, "./out")` with `file.write("./out")` extracts | Denied at the first entry (`file_write("out/a.txt")`) | The grant is per path written: `file.write("./out/*")` (dest need not exist) |
| `use "../lib/x.syn"` is always blocked | Allowed while it stays under the **project root** (the entry file's dir); above it → `escapes the project root` | Move the file into the project or restructure; the root is the entry's directory, not the cwd |
| `route "GET /:lang"` serves `/openapi.json` as a lang | The reserved URLs (`/openapi.json`, `/docs`, `/llms.txt`, `/sitemap.xml`, `/robots.txt`) are served **first**; `synsema check` warns | Declare a **literal** route (or a static file at the exact path) if you really want to override one |
| A `private` route is unreachable | `private` (route/group) only hides it from discovery/OpenAPI — it is still served | Auth is `requires auth`; `private` is about publication |
| `give openapi_json()` returns the document | A bare `give` JSON-quotes the text (`"{\"openapi\"…"`) | `give respond(openapi_json(), "application/json")` |
| `--health healthz` works | Exit 2: needs an absolute path | `--health /healthz` (or `SYNSEMA_HEALTH_PATH=/healthz`); a declared route at that path wins, with a warning |
| A `stream` route with `requires auth` ignores per-identity ceilings | Since v0.6.20 it runs with the request's identity: per-identity `spend`/`sign`/LLM ceilings apply | Hardening; a service that relied on the gap now sees the ceilings |
| `--deterministic` + `--sandbox` narrows further | Exit 2 — `--deterministic already fixes the ceiling` | It is `--profile pure` + `stdout`-only ceiling; use it alone |
| `--audit unix:/x.sock` on Windows | Exit 2 (`only available on Unix`), like `fd:N` | Use `json` or a path |
| The v0.6.20 Linux binary runs anywhere / `FROM scratch` | `GLIBC_2.39 not found` on Ubuntu 20.04/22.04 and Debian bookworm (it was linked on the 24.04 runner); `FROM scratch` has no libc at all | Upgrade to v0.6.21+ (glibc floor 2.17, guarded by the release); base images with a libc: `gcr.io/distroless/cc-debian12`, `debian:*-slim` |
| `toml_encode({"a": nothing})` writes `a = null` | Error `TOML has no null` | Drop the key or give it a value |
| `xml_parse` expands entities / fetches DTDs | Never (no XXE); a malformed doc errors with `line:col` | By design |

## `synsema update`

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `synsema update` on Windows: `no se pudo mover el binario actual: Acceso denegado (os error 5)` | A `synsema serve` started **before the previous update** is still running the old image, now named `synsema.exe.old`; Windows lets a running exe be renamed but not deleted or overwritten, and the updater (≤ v0.6.16) tried to reuse that name | Restart those old serves (they run the old version anyway) or rename the file (`ren synsema.exe.old synsema.exe.old-x`) and run `synsema update` again. Fixed after v0.6.16: the updater picks a fresh `.old-<pid>` name and cleans stale ones next time |

## Secrets & config (see [secrets.md](secrets.md))

| Pattern | Problem | Better approach |
|---|---|---|
| Using `reveal()` to "get the value" | Defeats the whole point; it's loud and audited | Use `bearer()`/`hmac()`/`verify_hmac()`/`constant_time_eq()` — they consume the secret without exposing it. `reveal` is a last resort. |
| Committing `.env` | Leaks real secrets into git history | `.gitignore` the `.env`; commit a `.env.example` with keys (no values) |
| `print(my_secret)` to debug | You only ever see `secret(NAME)` (redacted by design) | That's expected — secrets never print their value. If you truly need the value, `reveal()` (audited). |
| `secret("X")` without `require secret("X")` | `secret("X") not permitted: missing capability` | Add `require secret("X")` (or a `require secret("X_*")` prefix). Same for `env`. |
| `… not permitted: declared but above the host ceiling (--sandbox/--cap-set)` | The `require` IS there; the HOST's ceiling (`--sandbox`, `--cap-set`, the embedder's `ceiling`) does not lend it | Nothing to change in the program — do NOT add the `require` again (loop). The host widens the ceiling or the call stays denied. Same text for `net`/`db`/`file`… via `Capability not granted: … — declared but above the host ceiling` |
| Comparing a secret with `==` in a loop over guesses | Fine — `==` on a secret is constant-time | For HMAC/signature checks use `verify_hmac` (also constant-time) |
| Expecting `env("X")` to return `nothing` when unset | It raises a clear error (fail-loud) | Pass a default: `env("X", "devvalue")`, or set it in `.env`/the environment |
| Putting a secret in a query param or JSON body | Redacted (fail-closed) → the upstream gets `secret(NAME)` | Send credentials via a header: `{"Authorization": bearer(secret("KEY"))}` |

## WebAssembly (wasip1 CLI + `@synsema/wasm` embed) — see [deploy.md](deploy.md) § WebAssembly

- **`.env` is NOT read by the embeddable artifact** (`synsema-wasm-web`): there is no
  filesystem or process. Pass `env: {KEY: "..."}` in `run`/`handle` opts; `secret("KEY")`
  resolves from there. (The wasip1 CLI DOES read `.env` through `wasmtime --dir .`.)
- **An async host hook with the sync API fails, by design**: `syn.run(src, {host: {http: async …}})`
  makes the call fail with `the host \`http\` hook returned a Promise — use runAsync/handleAsync`
  (the program sees it in `r["error"]`; a `kv` write is dropped with that warning in `log`). Async
  hooks (browser `fetch`, IndexedDB, LLM SDKs) need `runAsync`/`handleAsync` (Worker +
  `Atomics.wait`); in browsers that needs cross-origin isolation (COOP `same-origin` + COEP
  `require-corp`) — without it, use sync hooks.
- **`require` still rules**: the host lending `http`/`kv`/`llm` grants nothing — without
  `require net("host")`/`require memory("x")`/`require llm` the builtin fails with `Capability not
  granted` BEFORE the host is called; and the embedder's `ceiling` denies above what the host lends.
- **Handler mode is the native serve, not a lighter one**: `require serve(port)` is mandatory
  (`serve on 8080 is not permitted: missing capability serve(8080)`), and each request runs on a
  snapshot of the globals — a `set` on a global in a route does NOT persist; use `state_*`
  (durable through the host `kv`). `stream`/`proxy to` answer 501; `static`/rate limits are the
  platform's job.
- **Not in either artifact** (names exist, errors say why): `ws_*`, `mtls_identity`, `db_open`/`sql`/
  `mongo_*`/`redis_*`, `cron_*`, real threads (`spawn`/`parallel_map` run in-process). In wasip1
  without a host, `fetch` with `require net` fails `this host provides no http transport`.
- **A trap discards the instance** (a panic in wasm aborts): the JS glue recreates it on the next
  call; program errors never trap — they come back in `errors[]`.
- **The Vela guest probe segfaults under Node 22 — host bug, not yours**: Node 22.x crashes
  intermittently inside V8 (concurrent tier-up race) while running `synsema_vela_guest.wasm`
  (22.23.2 on Linux: 1 run in 3). Use Node 20 or 24+, or `node --no-wasm-dynamic-tiering`.
  wasmtime-go v1.0.0 (Vela's Executor) is unaffected — see [guests.md](guests.md).

## `judge` (System One / Jev) — engine v0.6.25+ (see [judge.md](judge.md))

- **`Unsupported operation: nothing > number` on `v.x.probability > 0.5`** — the judge is offline
  (no `TYPESAFE_API_KEY`, over `SYNSEMA_JUDGE_BUDGET`, or the API failed) and the answer degraded to
  `available: false` with `probability`/`choice`/`score` = `nothing`. That is the honest form — an
  invented 0.5 would be indistinguishable from a real one. Gate on `available` or on `confidence`
  (0 offline) before comparing; the stderr notice says what to set.
- **`Capability not granted: judge` under `serve` although you wrote `require llm`** — `judge` is its
  own capability. Add `require judge`. Under `--deterministic` it is denied by design (network I/O).
- **`v.x.type` / `v.x.probabilities.nothing` fail** — on engines ≤ v0.6.28 they do not parse (`type`
  and `nothing` are reserved); since v0.6.29 any word parses after a `.`, but the fields do not
  exist. The field is `kind`; the escape key is `none` (`choice` itself is `nothing` when the escape
  wins).
- **`'rate' takes ordered levels: write rate … across […]`** (or the mirror for `choose … across`) —
  the prepositions are fixed: `between` = unordered options, `across` = ordered levels.
- **Confident wrong answer on a state that fits no option** — you wrote `choose … between {…}`
  without `or nothing`. Measured: 0.69 on a no-fit message, 0.79 at confidence 0.68 with the right
  value missing from the candidates. Add `or nothing` and check `choice == nothing`.
- **`choose needs at least 2 options`** — the API accepts one and answers with confidence 1.0; the
  engine refuses before the call. Same for `rate` (2–10 levels, distinct ids).
- **A `whether` about a total, a sum, a count of many items, or a date difference is wrong** — the
  model recognises the shape of an answer, it does not calculate (a six-line total: 0.32 for a true
  statement). Compute in Synsema, judge the result. Small counts were fine; do not rely on it.
- **`P(A)` and `P(not A)` do not add up to 1** (0.37 + 0.78 measured) — never derive one from the
  other; ask in the positive and negate in code.
- **Your test asserts `probability == 0.72` and flakes** — the same request twice moves by a few
  hundredths. Assert the winner and a range. `SYNSEMA_JUDGE_PROVIDER=mock` for exact, offline CI.
- **`judge[0]` suddenly "expected an indented block"** — it cannot; `[` never opens `judge`. If you
  see that error, `judge` is followed by an identifier, string, `{` or literal on the same line and
  the block is missing or badly indented.
- **`warning: judge 'x' refers to `ticket.text` but the state has no such path`** (v0.6.26+) — you
  wrote `judge ticket` and the question says `` `ticket.text` ``. The model sees the *value* of
  `ticket`, not its name. Write `judge {"ticket": ticket}` or drop the `ticket.` prefix; the warning
  says which.
- **`synsema check` now fails on a `judge` block that used to run** (v0.6.26+) — literal criteria with
  1 option, 11 levels or a duplicate id, an empty instruction, or a numeric literal state. Those were
  a 400 or a fake certainty at run time; `check` catches them first. Warnings (negative `whether`,
  arithmetic, two blocks over the same state) never change the exit code.
- **`decide` says `Capability not granted: judge … SYNSEMA_JUDGE_DECIDE is set`** — the host serves
  `decide` with the judge; under `serve` add `require judge`, or unset the knob.
