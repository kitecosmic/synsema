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

## Intent enforcement
```
intent: "Read data from api.shop.com and generate reports"
-- Intent FREEZES after first non-intent statement
-- Actions outside intent are BLOCKED
-- Prompt injection cannot expand the intent
```

## Per-task sandboxing
```
task fetch_orders()
    require net("api.shop.com")     -- this task can ONLY access api.shop.com
    give fetch("https://api.shop.com/orders")
```

## Sandbox blocks
```
sandbox
    -- code here has NO capabilities (isolated)
    let result be compute(untrusted_data)
```

## Invariants
```
invariant: balance > 0              -- checked at runtime, error if false
```

## Audit
Run with `--audit` to see every capability check:
```bash
syntecnia run program.syn --audit
```

## Capability scoping
- `deny` overrides `grant`
- Sandbox does NOT inherit parent capabilities
- Per-task require creates isolated scope
- Wildcard: `net("*.example.com")` covers all subdomains
- Path glob: `file("/data/*")` covers all files in /data/
