# Synsema Language Skill

You are working with Synsema, a programming language designed for AI agents. This document is your complete reference for understanding, writing, and debugging Synsema programs.

## Project structure

```
synsema/
├── core/                  # Language foundation — start here for syntax/semantics
│   ├── tokens.py          # All 60+ token types and keywords
│   ├── lexer.py           # Tokenizer (significant whitespace, -- comments)
│   ├── ast_nodes.py       # All 40+ AST node types (the grammar)
│   ├── parser.py          # Recursive descent parser (source → AST)
│   ├── interpreter.py     # Tree-walking evaluator (AST → execution)
│   ├── types.py           # Type system: SynValue wraps every value
│   ├── ast_api.py         # Structural code manipulation (find, rename, extract)
│   ├── testgen.py         # Auto-generates tests from types/signatures
│   ├── intentional_ops.py # apply, where, transform, reduce, sort_by, group_by
│   ├── addressable.py     # Token-efficient code addressing (file:task:name)
│   └── flat_syntax.py     # Document-style .fsyn translator
├── capabilities/          # Security layer — zero access by default
│   ├── model.py           # Capability types, sets, audit trail
│   ├── enforcer.py        # Checks capabilities + intent before every I/O
│   ├── builtins.py        # Secure builtins: fetch, read_file, write_file, run
│   └── intent.py          # Intent parsing, enforcement, freeze
├── runtime/               # Execution engine
│   ├── engine.py          # SynsemaEngine — ties everything together
│   ├── speculative.py     # Fork/rollback/commit execution
│   ├── error_reporter.py  # Rich diagnostics (variables, call stack, suggestions)
│   └── recovery.py        # Auto-recovery protocol + human escalation
├── agents/                # Multi-agent coordination
│   ├── blackboard.py      # Thread-safe shared state with versioning
│   ├── swarm.py           # Agent lifecycle, signals, dashboard
│   ├── resource_lock.py   # Preventive locking (exclusive/shared/advisory)
│   ├── progress.py        # Task step tracking with crash resume
│   ├── memory.py          # Persistent memory + owner rules
│   └── builtins.py        # Agent builtins: remember, recall, check_rules, etc.
├── human/                 # Human interaction
│   └── interaction.py     # 5 types × 4 backends (terminal, auto, queue, callback)
├── llm/                   # LLM integration
│   └── provider.py        # Anthropic, OpenAI, MiniMax, Ollama, Mock
└── cli.py                 # CLI: run, repl, check, tokens, ast, testgen
```

## Complete syntax reference

### Keywords (all lowercase)

Flow: `when`, `otherwise`, `each`, `in`, `while`, `match`, `is`, `then`, `stop`
Definitions: `task`, `give`, `let`, `be`, `set`, `to`, `type`, `as`, `of`, `with`
Agent: `agent`, `spawn`, `share`, `observe`, `state`, `signal`, `wait_for`
Security: `require`, `allow`, `deny`, `sandbox`, `verify`
Human: `approve`, `confirm`, `ask`, `show`
LLM: `reason`, `decide`, `analyze`, `generate`, `intent`, `invariant`
Observability: `trace`, `log`, `measure`, `checkpoint`
Logic: `and`, `or`, `not`
Literals: `true`, `false`, `nothing`

### Operators

Arithmetic: `+`, `-`, `*`, `/`, `%`, `**`
Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
Special: `|>` (pipe), `->` (arrow), `=>` (fat arrow)

### Statement patterns

```
-- Variable binding
let name be expression

-- Mutation (variable must exist)
set name to expression

-- Conditional
when condition
    body
otherwise when condition
    body
otherwise
    body

-- Iteration
each variable in collection
    body

-- Loop
while condition
    body

-- Pattern match
match value
    is pattern
        body
    is pattern
        body

-- Function definition
task name(param1, param2)
    body
    give return_value

-- Type definition
type Name
    field1: type
    field2: type

-- Agent definition
agent Name
    require capability("scope")
    task do_work()
        ...

-- Capability declaration
require net("domain.com")
require file("/path/*")

-- Intent declaration (must be at top, freezes after first statement)
intent: "description of what this program does"

-- Invariant (checked at runtime)
invariant: condition

-- Human interaction
approve "message"
confirm "message"
show value as "label"
let answer be ask "question" with ["option1", "option2"]

-- LLM operations
let result be reason about subject with context = data
let choice be decide between ["a", "b", "c"] given data
let analysis be analyze data for "objective"
let content be generate "target" given data with param = value

-- Observability
trace "name"
    body
log "message"
measure "name"
    body
checkpoint "name"

-- Agent coordination
share value as "key"
observe "key" as variable
spawn AgentName with param = value
signal "name" with data
wait_for "signal_name" as variable

-- Sandbox
sandbox
    untrusted_body

-- Progress tracking
create_progress("task_name", ["step1", "step2", "step3"])
start_step("task_name", "step1")
complete_step("task_name", "step1", "result description")
let next be resume_point("task_name")

-- Memory
remember("category", "content", ["tag1", "tag2"])
let entries be recall("category", ["tag"])
forget_memory("entry_id")

-- Rules
add_rule("name", "must", "description with condition <= value", "category")
let violations be check_rules("category", {"field": value})
```

### Built-in tasks

Core: `print`, `length`, `text`, `number`, `append`, `keys`, `values`, `contains`, `split`, `join`, `range`, `type_of`, `slice`

Intentional: `apply`, `where`, `collect`, `transform`, `reduce`, `sort_by`, `group_by`, `find_first`, `every`, `some`, `count_where`, `flatten`, `zip_with`

I/O (require capabilities): `fetch`, `read_file`, `write_file`, `list_dir`, `file_exists`, `run`, `get_env`, `now`, `random`, `random_int`

Agent: `create_progress`, `start_step`, `complete_step`, `fail_step`, `resume_point`, `progress_display`, `progress_percent`, `remember`, `recall`, `forget_memory`, `add_rule`, `check_rules`, `get_rules`, `memory_summary`

### Types

`number` (int or float), `text` (string), `bool` (true/false), `nothing` (null), `list` ([items]), `map` ({"key": value}), `task` (callable)

### Property access

```
name of person          -- natural syntax
person.name             -- dot syntax
person["name"]          -- index syntax
```

### Pipe operator

```
let result be data |> clean |> validate |> transform
-- equivalent to: transform(validate(clean(data)))
```

### Comments

```
-- This is a comment (double dash)
```

### Blocks

Blocks use indentation (4 spaces or 1 tab). No braces, no end keywords in standard syntax. Flat syntax (.fsyn) uses periods and "end" keywords.

### Error diagnostics

When errors occur, Synsema provides:
- File, line, column
- Source code context (lines around error)
- All visible variables at failure point
- Call stack
- Active intent and trace
- Error classification (data, io, logic, capability, type)
- Whether it's recoverable
- Specific fix suggestions

### Capability types

`net` (HTTP), `file` (read+write), `file.read`, `file.write`, `exec` (processes), `env` (environment vars), `time`, `random`, `stdout`, `stdin`, `llm`, `db`

### Rule levels

`must` — hard block, violation is error
`should` — soft, violation is warning  
`avoid` — preference against
`prefer` — preference for

### Running

```bash
synsema run file.syn                    # Standard run
synsema run file.syn --provider claude  # With LLM
synsema run file.syn --secure           # All caps must be granted
synsema run file.syn --grant net:*.api.com  # Grant capability
synsema run file.fsyn                   # Flat syntax
synsema repl                            # Interactive
synsema testgen file.syn                # Auto-generate tests
```

## Common patterns

### Safe iteration with intentional ops instead of loops
```
-- Instead of:
let result be []
each item in items
    when is_valid(item)
        set result to append(result, transform(item))

-- Write:
let result be apply(transform, where(items, is_valid))
```

### Error-safe operations
```
invariant: quantity > 0
when quantity == 0
    give 0
otherwise
    give total / quantity
```

### Agent with memory and rules
```
intent: "Process customer orders"
require net("api.shop.com")

add_rule("max_discount", "must", "discount <= 0.20", "pricing")

create_progress("orders", ["fetch", "validate", "process", "notify"])

start_step("orders", "fetch")
let orders be fetch("https://api.shop.com/orders")
complete_step("orders", "fetch", text(length(orders)) + " orders")

remember("learning", "Fetched at " + text(now()), ["performance"])
```
