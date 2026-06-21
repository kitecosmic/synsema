# Synsema Built-in Tasks

## Core
- `print(values...)` — output text
- `length(collection)` → number
- `text(value)` → string conversion (integers show no decimal: `text(42)` → `"42"`)
- `number(value)` → numeric conversion (always float: `number("42")` → `42.0`)
- `append(list, item)` → new list with item added
- `keys(map)` → list of keys
- `values(map)` → list of values
- `contains(collection, item)` → bool
- `split(text, separator)` → list
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list
- `type_of(value)` → text ("number", "text", "bool", "list", "map", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection

## Strings
- `fmt(template, map)` → interpolated text: `fmt("Hi {name}", {"name": "Alice"})` → `"Hi Alice"`
- `upper(text)` → uppercase
- `lower(text)` → lowercase
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
- `read_file(path)` → text
- `write_file(path, content)` → bool
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
- `read_body()` → full request body text (from memory or the temp file) — inside a route handler

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
- `recall(category?, tags?, search?)` → list of entries
- `forget_memory(entry_id)` → bool
- `add_rule(name, level, description, category?)` → bool
- `check_rules(category?, context_map?)` → list of violations
- `get_rules(category?)` → list of rules
- `memory_summary()` → formatted text
