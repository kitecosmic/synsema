# Syntecnia Security

## Zero access by default
Nothing works without declaring capabilities.

## Capability types
`net`, `file`, `file.read`, `file.write`, `exec`, `env`, `time`, `random`, `stdout`, `stdin`, `llm`, `db`

## Declaring capabilities
```
require net("api.example.com")
require net("*.example.com")        -- wildcard
require file("/data/*")
require exec("ffmpeg")
require env("API_KEY")
require time
```

`require` in the program body grants the capability for real. This is NOT just a declaration — it enables the operation.

## Intent enforcement

```
intent: "Read data from api.shop.com and generate reports"
```

How the intent works internally:
- The enforcer parses the intent text looking for **action verbs** (keywords).
- Each verb maps to allowed action categories (FILE_READ, NET_WRITE, etc.).
- Actions outside those categories are **blocked** in strict mode.
- The intent **freezes** after the first non-intent statement — prompt injection cannot expand it.
- Without an `intent:` declaration = fully permissive (only capabilities apply).

**Recognized verbs (English only):** read, fetch, get, download, process, analyze, calculate, write, save, store, update, create, delete, send, post, upload, notify, email, run, execute, deploy, build, spawn, delegate, manage, generate, report

**Write the intent in English** to activate category enforcement. The intent, like all keywords in the language, is English.

**If no verbs match** (e.g. intent in another language), the enforcer **degrades to permissive** in categories — it won't block anything by category. Domains and paths in the intent text are still enforced. This means a non-English intent is safe (not blocking) but provides no category restriction.

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
syntecnia run program.syn --audit
```

Shows every capability check: what was requested, granted or denied, and why.

## Capability scoping rules
- `deny` overrides `grant`
- Sandbox does NOT inherit parent capabilities
- Per-task `require` creates an isolated scope
- Wildcard: `net("*.example.com")` covers all subdomains
- Path glob: `file("/data/*")` covers all files in /data/
