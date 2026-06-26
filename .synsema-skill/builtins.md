# Synsema Built-in Tasks

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
- `values(map)` → list of values
- `contains(collection, item)` → bool (lists/text/maps; also `bytes`: subsequence, or a single byte 0–255)
- `split(text, separator)` → list
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list
- `type_of(value)` → text ("number", "decimal", "complex", "text", "bytes", "bool", "list", "map", "array", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection (lists/text/`bytes`; Python-style negatives)
- `length(x)` also works on `bytes` (byte count) and `array` (total elements). Indexing `x[i]` works on lists, maps, `bytes` (→ int 0–255) and `array` (→ row or scalar).
- `raise(message)` → **always raises a runtime error** with `message` (coerced to text). Use it to fail deliberately, or to **re-propagate** a caught error inside `recover` (see below). `raise()` with no arg errors. (`fail(...)` is for HTTP responses, NOT for raising runtime errors.)
- `read_line(prompt?)` → text — read one line from stdin (CLI). Optional `prompt` is printed first (no newline). Returns the line without the trailing newline; `nothing` on EOF. Works with a TTY **and** piped/redirected input (`printf 'x\n' | synsema run f.syn`) — unlike free-text `ask`. Under `synsema run` it **auto-flushes** pending `print` output before prompting, so a `read_line` loop is a real interactive REPL. (Reads stdin in any mode; the flush is `run`-only — see `flush`.) See [human.md](human.md).
- `flush()` → nothing — `run`-interactive primitive: `print` output is buffered and shown when the program ends; `flush()` writes the pending output to stdout **now** (live feedback for REPLs / long loops). Mode-aware: under `conform`/`test`/`serve` (which collect output for JSON/responses) `flush()` and `read_line`'s auto-flush are **no-ops** — output stays collected, stdout is never polluted.
- `llm_available()` → bool — `true` when a real LLM provider is wired, `false` offline. Branch on it instead of string-matching placeholders. See [llm.md](llm.md).

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
- `bytes(text)` → utf8 bytes; `bytes(text, "hex")` / `bytes(text, "base64")` → decode; `bytes([72,73])` → from ints 0–255; `bytes(bytes)` → identity. `bytes(secret)` → **error** (plaintext never materializes).
- `decode(b)` / `decode(b, "utf8")` → text (UTF-8 **strict**, errors on invalid); `decode(b, "utf8_lossy")` → with `U+FFFD`; `decode(b, "hex")` / `decode(b, "base64")` → text. (so `bytes(...)` ↔ `decode(...)` are inverses)
- `is_bytes(x)` → bool. `b[i]` → int 0–255; `bytes + bytes` → concatenation; `length`/`slice`/`contains` work on bytes.
- `sha256(x)` / `sha512(x)` → **bytes** (raw digest). x: text → hashes utf8; bytes → raw. Hex via `decode(sha256(x), "hex")`. `sha256(secret)` → error.
- Note: `text(b)` / `print(b)` show a hex repr like `bytes(48656c6c6f)`, **not** a decode. `bytes != text` always.

## Math (pure — no capability)
Constants (bare values): `pi`, `tau`, `e`, `inf`, `nan`.
- magnitude/selection (type-preserving): `abs`, `sign`, `min`, `max`, `clamp`. `abs(complex)` → modulus.
- roots/powers: `sqrt`, `cbrt`, `hypot`, `pow`. exp/log: `exp`, `ln`, `log10`, `log2`, `log_base`. (no bare `log` — it's a soft keyword; use `ln`/`log10`/`log2`.)
- trig (radians): `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2`, `radians`, `degrees`.
- hyperbolic: `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, `atanh`.
- number theory (integers): `gcd`, `lcm`, `factorial`.
- introspection: `is_nan`, `is_infinite`, `is_finite`, `round_to`.
- aggregates over a list: `sum`, `product`, `mean` (also work on `array`, see below).
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
- `reveal(secret)` → plaintext — requires `require reveal`, writes a persistent audit entry, fails if it can't audit. Use sparingly.
- `bearer(secret)` → a tainted `Bearer <secret>` header value (materialized only at the socket)
- `hmac_sha256(data, secret)` → hex MAC (not secret)
- `verify_hmac(data, signature, secret, algo?)` → bool, constant-time. `algo` = `"sha256"` (default) or `"sha512"`; decodes hex/base64 signatures (Stripe/GitHub/Shopify). SHA-1 is rejected.
- `constant_time_eq(a, b)` → bool, constant-time; accepts a `secret` on either side

## Intentional operations (replace loops)
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

## I/O (require capabilities)
- `fetch(url, method?, headers?, body?)` → map with status, headers, body
- `read_file(path)` → text — requires `file.read` (lossy for non-UTF-8; use the bytes variant for binary)
- `read_file_bytes(path)` → `bytes` — requires `file.read` (byte-exact)
- `write_file(path, content)` → bool — requires `file.write`. If `content` is `bytes`, writes raw bytes; else text.
- `list_dir(path)` → list of filenames
- `file_exists(path)` → bool
- `run(command, args_list?, timeout?)` → map with exit_code, stdout, stderr
- `get_env(name)` → text or nothing
- `now()` → unix timestamp (number) — requires `time`
- `sleep(seconds)` → pause execution (e.g. to pace an SSE stream) — requires `time`
- `format_time(timestamp, pattern?)` → text — requires `time`. Default ISO-8601 UTC (`format_time(0)` → `"1970-01-01T00:00:00Z"`); with a strftime pattern: `format_time(t, "%Y-%m-%d %H:%M")`
- `parse_time(text, pattern?)` → timestamp — requires `time`. Inverse of `format_time` (ISO-8601 by default; a trailing `Z` is accepted; times are UTC)
- `date_parts(timestamp)` → `{year, month, day, hour, minute, second}` (UTC) — requires `time`
- `random()` → float 0-1
- `random_int(min, max)` → integer

## HTTP
Both `http://` and **`https://` (TLS)** are supported (rustls + OS root CAs, real cert validation). `http*` are NOT capability-gated (`fetch` is — see capabilities.md).
- `http(method, url, headers?, query?, body?, timeout?)` → response map {status, ok, body, json, headers, error}
- `http_get(url, headers?, query?)` → response map
- `http_post(url, body, headers?)` → response map
- `http_put(url, body, headers?)` → response map
- `http_delete(url, headers?)` → response map

## Database (SQL)
- `db_open(path, mode?)` — mode: "readwrite" (default), "readonly", "memory"
- `db_close(path?)` — close connection
- `sql(query, params?)` → list of row maps (SELECT)
- `sql_exec(statement, params?)` → {rows_affected, last_id} (INSERT/UPDATE/DELETE/CREATE)
- `sql_batch(statement, params_list)` → {rows_affected} (batch operations)
- `sql_tables()` → list of table names
- `paged(query, params?)` → paginated result for `give` in a (non-streaming) serve route (SQL LIMIT/OFFSET pushdown, exact COUNT total)

## HTTP server (serve) — see serve.md
Response helpers (set the HTTP status; body follows the response contract):
- `ok(x)` → 200
- `created(x)` → 201
- `not_found(x)` → 404 — `not_found(text)` → `{"error": text, "status": 404}`; `not_found(map)` → the map as-is
- `fail(code, msg)` → `{"error": msg, "status": code}`; also `fail(msg)` → 400, and `fail(code)`
- `html(content)` → 200, `text/html; charset=utf-8`, raw body (no JSON encoding)
- `respond(content, content_type, status?)` → raw body with an arbitrary content-type and optional status
- `render(template_path, data?)` → `text/html` from a template file. A hole `{ x }` is a **data field** (a single name — even a reserved word like `type`) or an **expression** (`{ format_time(created) }`). Values are auto-escaped (XSS-safe); `{ raw expr }` opts out; `{ each x in xs }…{ end }` and `{ when c }…{ otherwise }…{ end }` reuse Synsema flow. cwd-relative + traversal-blocked; `render("literal")` templates are validated at startup; errors carry `file:line`. See serve.md.
- `read_body()` → full request body **text** (lossy for non-UTF-8) — inside a route handler
- `read_body_bytes()` → full request body as `bytes` (byte-exact, for binary uploads) — inside a route handler
- `binary(bytes, content_type?, status?)` → a binary response (default `application/octet-stream`, 200). Also `give bytes(...)` directly → octet-stream.
- **Shared state across requests** (serve): `state_set(key, value)`, `state_get(key, default?)`, `state_incr(key, delta?)`, `state_delete(key)` — an in-memory store shared across all handlers/requests (a `set` on a global does NOT persist across requests). See serve.md.

### Semantic content (negotiated HTML / Markdown / JSON — see serve.md)
- `content(tree)` → a negotiable response: HTML (default), Markdown (`Accept: text/markdown` or `.md`), or JSON (`.json`). Opt-in; only `content()` is negotiated.
- `page(nodes, meta?)` → document root; `meta` map (`title`, `description`) feeds `<head>` + JSON-LD
- `heading(level, text)`, `prose(text)`
- `list(items)`, `ordered_list(items)` — items may be text or nodes
- `link(text, href)`, `image(src, alt)`
- `section(nodes)`, `code(text, lang?)`
- `raw(html)` → raw HTML escape hatch (NOT auto-escaped); everything else in HTML output IS auto-escaped (XSS-safe)

## Cron (Scheduled Tasks)
- `cron_every(seconds, task)` → job name (repeating background job)
- `cron_after(seconds, task)` → job name (one-shot delayed execution)
- `cron_cancel(name)` → bool
- `cron_list()` → list of job info maps
- `cron_status()` → formatted text

## Agent operations
- `create_progress(task_name, [step_names])` → task_name
- `start_step(task_name, step_name)` → bool
- `complete_step(task_name, step_name, result?)` → bool
- `fail_step(task_name, step_name, error?)` → bool
- `resume_point(task_name)` → step name or nothing
- `progress_display(task_name)` → formatted text
- `progress_percent(task_name)` → number 0-100
- `remember(category, content, tags?)` → entry_id
- `recall(category?, tags?, search?, mode?)` → list of entries. `mode` (text) controls multi-tag matching: `"any"` (default, OR) or `"all"` (AND — entry must have every tag). `category`/`search` always narrow; pass `nothing` to skip a positional arg. See memory.md.
- `forget_memory(entry_id)` → bool
- `add_rule(name, level, description, category?)` → bool
- `check_rules(category?, context_map?)` → list of violations
- `get_rules(category?)` → list of rules
- `memory_summary()` → formatted text
