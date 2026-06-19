# Syntecnia Pitfalls — Common Errors and Solutions

Read this FIRST if something fails. Each row is a real mistake that costs hours to debug.

## Errors

| Error message | Cause | Solution |
|---|---|---|
| `Unterminated string` | Literal newline inside `"..."` | Use `\n` escape. Strings are single-line only. |
| `Capability not granted: file_write(...)` | Missing `require` or scope too narrow | Add `require file("/path/*")` at top of program |
| `Capability not granted: net(...)` | Missing `require` for the domain | Add `require net("domain.com")` |
| `Invalid memory category: 'preferencia'` | Categories are English-only | Use exactly: `preference`, `rule`, `learning`, `decision`, `context` |
| `No agent defined with name 'X'` | `spawn X` before `agent X` definition | Define the agent before spawning it |
| `Division by zero` | Divisor is 0 | Guard with `when divisor != 0` or use `try/recover` |
| `Cannot iterate over number` | `each` on a non-list value | Check type with `type_of()` or wrap in `[value]` |
| `Map has no key 'X'` | Accessing a property that doesn't exist | Check with `contains(map, "X")` first |
| `Cannot set undefined variable` | Using `set` before `let` | Define with `let x be value` first, then `set x to new_value` |
| `Loop exceeded maximum iterations` | Infinite loop (condition never false) | Check that loop variable actually changes |
| `Expected indented block` | Missing indentation after when/each/task/etc | Indent body with 4 spaces |
| `'while' is a reserved word in Syntecnia` | Using a hard keyword as a name | Pick another name. (HTTP words like `route`/`auth` ARE allowed as names — they're soft keywords.) |

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
| `read_body()` returns binary intact | Decodes as UTF-8 (lossy for binary) | Use `body_file of request` (temp file path) for binary bodies |
| A `stream` route also runs `give` | `stream` and `give` are mutually exclusive | A route either streams (with `send`) or gives — not both |
| POST with invalid JSON is silently ignored | With `Content-Type: application/json` it's a `400` | Send valid JSON, or omit the JSON content-type to get the raw body |
| `serve on PORT` returns and the program exits | The CLI keeps the process alive while servers run (Ctrl+C to stop) | Expected; the server runs in the background |
| `X-Forwarded-For` sets the client for rate limiting | The real peer IP is used; XFF is ignored | XFF is forgeable; trusted-proxy/per-user keying is future work |

### Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| `give sql(...)` for a large table | Loads everything into memory each request | `paged()` for anything that can grow |
| Trusting `X-Forwarded-For` for identity | Rate limit uses the real peer IP (XFF is forgeable) | Don't trust XFF; per-user/trusted-proxy is future work |
| `give <list>` with `LIMIT` in your SQL | `total` becomes wrong (it counts only what you returned) | Return the full list, or use `paged()` |
| Long-lived SSE streams with default `max_streams` | Each holds a thread; you hit `503` under load | Size `max_streams` to your thread budget; keep streams short |

## Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| String on multiple lines | `Unterminated string` error | Use `\n` or concatenate: `"line1\n" + "line2"` |
| `remember("preferencia", ...)` works | Error: invalid category | Categories are English: `preference`, `rule`, `learning`, `decision`, `context` |
| `intent: "..."` restricts what the program can do | No — the intent is descriptive only | Security is enforced by capabilities (`require`), in any language. The intent text never blocks. |
| `wait_for` wakes all waiters on one `signal` | Only ONE waiter gets it | Signals are a queue (consumed on read). For fan-out, emit N signals or use blackboard. |
| `wait_for` hangs forever on dead agent | Returns `nothing` quickly | The runtime detects no alive agents and returns. But only if ALL agents are dead. |
| Agent shares state with main program | Each agent has its own interpreter | Use `share`/`observe` via blackboard to communicate. |
| `number("1200")` gives integer | Gives `1200.0` (float) | `text()` on integers shows no decimal. Use `text(number(...))` for display. |
| `/tmp/file.txt` works on Windows | Maps to `C:\tmp\file.txt` | Use absolute paths. For agent data, use `~/.syntecnia/` paths. |
| Cron output appears after program ends | Output is buffered | Fixed in recent versions. Update to latest. Use `--serve` for live output. |

## Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| No `try/recover` around HTTP/SQL/LLM | Agent dies on first network error | Wrap I/O in `try/recover` with fallback |
| Relying on the `intent:` text to restrict actions | The intent doesn't authorize anything | Declare permissions with `require`; the intent is only a description |
| One `signal` for N consumers | Only one gets it | Use blackboard keys per worker, or emit N signals |
| `share x as "result"` from N workers | Last write wins, others lost | Use dynamic keys: `share x as "result_" + text(n)` |
| No `require` and wondering why I/O fails | Zero-access-by-default | Always declare `require` at top of program |
| `set x to 5` without prior `let x be ...` | Runtime error | Always `let` before `set` |
