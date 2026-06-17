# Syntecnia Codebase Structure

```
syntecnia/
├── core/                      # START HERE for language internals
│   ├── tokens.py              # 60+ token types, keyword map
│   ├── lexer.py               # Source → tokens (significant whitespace)
│   ├── ast_nodes.py           # 40+ AST node types = the grammar
│   ├── parser.py              # Tokens → AST (recursive descent + Pratt)
│   ├── interpreter.py         # AST → execution (tree-walking evaluator)
│   ├── types.py               # SynValue, type constructors, BuiltinTask
│   ├── ast_api.py             # Structural manipulation (find, rename, extract)
│   ├── testgen.py             # Auto test generation from types
│   ├── intentional_ops.py     # apply, where, reduce, sort_by, etc.
│   ├── addressable.py         # Token-efficient code addressing
│   └── flat_syntax.py         # .fsyn → .syn translator
│
├── capabilities/              # Security layer
│   ├── model.py               # Capability, CapabilitySet, CapabilityViolation
│   ├── enforcer.py            # SecureOperations (gates every I/O)
│   ├── builtins.py            # fetch, read_file, write_file, run, etc.
│   └── intent.py              # IntentEnforcer, parse_intent, freeze
│
├── runtime/                   # Execution engine
│   ├── engine.py              # SyntecniaEngine — the main entry point
│   ├── speculative.py         # Fork/rollback/commit
│   ├── error_reporter.py      # Rich diagnostics + suggestions
│   └── recovery.py            # Retry/fallback/escalation protocol
│
├── agents/                    # Multi-agent system
│   ├── blackboard.py          # Thread-safe shared state
│   ├── swarm.py               # AgentSwarm manager
│   ├── resource_lock.py       # Preventive locking
│   ├── progress.py            # Task step tracking
│   ├── memory.py              # AgentMemory + OwnerRule
│   └── builtins.py            # remember, recall, check_rules, etc.
│
├── human/                     # Human interaction
│   └── interaction.py         # Terminal, Auto, Queue, Callback handlers
│
├── llm/                       # LLM integration
│   ├── provider.py            # Anthropic, OpenAI, MiniMax, Ollama, Mock
│   ├── context.py             # Context builder for enriched prompts
│   └── validator.py           # Response validation + retry
│
├── cli.py                     # CLI entry point
├── __main__.py                # python -m syntecnia
└── __init__.py                # Version
```

## Key entry points
- **Run a program**: `SyntecniaEngine.run_source()` in `runtime/engine.py`
- **Parse code**: `parse()` in `core/parser.py`
- **Add a builtin**: register in `core/interpreter.py._register_builtins()`
- **Add a capability**: define in `capabilities/model.py`
- **Add an LLM provider**: subclass `LLMProvider` in `llm/provider.py`
