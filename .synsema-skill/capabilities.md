# Synsema Security

## Zero access by default
Nothing works without declaring capabilities.

## Capability types
`net`, `file`, `file.read`, `file.write`, `exec`, `env`, `time`, `random`, `stdout`, `stdin`, `llm`, `db`, `serve`

`serve(PORT)` allows binding an HTTP server to that port — see [serve.md](serve.md).

## Declaring capabilities
```
require net("api.example.com")
require net("*.example.com")        -- wildcard
require file("/data/*")
require exec("ffmpeg")
require env("API_KEY")
require time
require serve(8080)                 -- bind an HTTP server to this port
require db("./store.db")            -- open this SQLite database
```

`require` in the program body grants the capability for real. This is NOT just a declaration — it enables the operation.

## Intent (descriptive)

```
intent: "Process customer orders and generate reports"
```

The `intent:` is a **human-readable description** of what the program is for. It is used for:
- Auditing (shown in `--audit`)
- LLM context (every reasoning call sees the program's purpose)
- Documentation

**The intent does NOT authorize or block actions.** Security is enforced *only* by capabilities (`require`). This is deliberate: the language has exactly ONE explicit authorization model, so behavior is predictable. You can write the intent in any language — it is never parsed for security.

To restrict what the program can do, use `require` with precise scopes. Anything not declared fails with a clear, actionable `Capability not granted` error — there is no guessing and no silent permissive fallback.

- The intent **freezes** after execution starts: a prompt injection cannot redeclare a broader intent (redeclaring a frozen intent is an error).

> Earlier versions tried to infer allowed action categories by scanning the intent prose for verb keywords, with a permissive fallback when nothing matched. That was unpredictable and language-dependent, so it was removed. Use `require` to declare permissions.

## Per-task sandboxing

Tasks with `require` run in an **isolated capability sandbox**:

```
task fetch_orders()
    require net("api.shop.com")
    give fetch("https://api.shop.com/orders")
```

- The task can ONLY access `api.shop.com`, even if the program has broader `net` capabilities.
- The sandbox is created when the task is called and destroyed when it returns.
- Capabilities granted inside a task do NOT leak to the global scope.
- The task still has `stdout` and `time` by default.

## Sandbox blocks
```
sandbox
    -- code here has NO capabilities (fully isolated)
    let result be compute(untrusted_data)
```

## Invariants
```
invariant: balance > 0              -- checked at runtime, error if false
```

## Audit
```bash
synsema run program.syn --audit
```

Shows every capability check: what was requested, granted or denied, and why.

## Capability scoping rules
- `deny` overrides `grant`
- Sandbox does NOT inherit parent capabilities
- Per-task `require` creates an isolated scope
- Wildcard: `net("*.example.com")` covers all subdomains
- Path glob: `file("/data/*")` covers all files in /data/
