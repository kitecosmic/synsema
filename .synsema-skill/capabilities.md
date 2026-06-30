# Synsema Security

## Zero access by default
Nothing works without declaring capabilities.

## Capability types
`net`, `file`, `file.read`, `file.write`, `exec`, `env`, `time`, `random`, `stdout`, `stdin`, `llm`, `db`, `serve`, `secret`, `reveal`

`serve(PORT)` allows binding an HTTP server to that port — see [serve.md](serve.md).

`env("NAME")`, `secret("NAME")` and `reveal("NAME")` gate config and secrets — see [secrets.md](secrets.md). All three are scoped by **name/label** (or a `NAME_*` prefix): `reveal("NAME")` can only reveal the secret whose name (`secret("NAME")`) or label (`as_secret(v,"label")`) matches, and every `reveal()` is written to a persistent audit log (**granted or denied**). Bare `require reveal` (coarse, any secret) still works for compat but **warns**. Separately, `as_secret(value, label?)` seals a **runtime** value as a `secret` and is **pure — no `require`** (see [secrets.md](secrets.md)).

## Declaring capabilities
```
require net("api.example.com")
require net("*.example.com")        -- wildcard
require file("/data/*")             -- read AND write under /data/
require file.read("./logs/*")       -- read-only (least-privilege)
require file.write("./out/*")       -- write-only
require exec("ffmpeg")
require env("API_KEY")
require secret("STRIPE_API_KEY")    -- read as an opaque, redacted secret
require secret("APP_*")             -- name prefix: APP_DB, APP_KEY, … (only a trailing *)
require reveal("STRIPE_API_KEY")    -- enable reveal() for THAT secret only (loud + audited; scoped by name/label)
require time
require llm                         -- enable LLM ops (reason/decide/analyze/generate)
require serve(8080)                 -- bind an HTTP server to this port
require db("./store.db")            -- open a SQLite database (scope = file path)
require db("postgres://localhost/appdb")  -- Postgres (scope = canonical URL)
require db("mysql://localhost/appdb")     -- MySQL (scope = canonical URL)
require db("mongodb://localhost/appdb")   -- MongoDB (scope = canonical URL)
require db("redis://localhost")           -- Redis (scope = canonical URL; redis://host:6379 → redis://host)
require db("*")                     -- any database (file or remote); bare `require db` = same
```

`require` in the program body grants the capability for real. This is NOT just a declaration — it enables the operation.

## The `llm` capability

The LLM operations — `reason`, `decide`, `analyze`, `generate` — and the tool-calling primitive
`llm_step` are gated like every other side-effecting operation. They require the `llm` capability:

```
require llm
let summary be generate "a summary" given report
```

- In **secure mode** (`serve`, the secure runtime) an LLM op without `require llm` fails with
  `Capability not granted: llm`. So you can audit a program's LLM use by reading its `require` lines.
- In plain **`run`/`conform`** (the non-secure dev mode) `llm` is **auto-granted** for convenience —
  exactly like `stdout` and `time` — so quick scripts don't need to declare it.
- Inside a `sandbox` the capability is stripped like any other: an LLM op inside a `sandbox` is
  **denied** even if it was granted outside.

For agent tool-calling, `llm` only gates the *decision* (`llm_step`); dispatch each chosen tool with
`call_tool`, which runs it under **only its declared capabilities** (∩ the program's) — see
[Per-tool least-privilege](#per-tool-least-privilege-call_tool) below and the safe loop in
[llm.md](llm.md).

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

## Per-tool least-privilege (`call_tool`)

A plain task call runs with the program's **ambient** capabilities — a task's own `require` lines are
declarations, not an automatic sandbox. To run a task under **least-privilege** (e.g. dispatching a
model-chosen tool), use `call_tool`:

```
task fetch_orders()
    require net("api.shop.com")          -- the tool's declared capability
    give fetch("https://api.shop.com/orders")

let result be call_tool(fetch_orders, nothing)
```

- Under `call_tool` the task runs with ONLY the capabilities it declared (its top-level `require`)
  **intersected** with the program's: it cannot use a capability it did not declare, even if the
  program granted it, and it cannot exceed the program.
- The restricted scope is created when `call_tool` dispatches and restored when it returns (also on
  error); nested calls keep the restriction.
- A `require` **nested** inside the tool body (under `when`/`if`/…) is a **no-op** — a tool cannot
  self-grant a capability to escape its scope. (The top-of-body `require` IS the declaration.)
- `print` and pure computation always work; declare `time`/`random`/etc. to use them.

**Two sides — the program must also GRANT.** `call_tool` runs the tool with `declared ∩ program`. So a
tool that declares `require file.write("out/*")` still fails with `Capability not granted` if the
**program** didn't grant `file`. Wire both: the tool **declares** (top of body, literal scope) and the
**entry grants** the superset.

> **Under `serve` (secure mode) this bites:** a per-task `require` does **not** grant ambient capability
> — it's only the **declaration** `call_tool` intersects. The real grant goes at the **top-level of the
> `serve` file**. (In `run` the per-task `require` suffices, but declare-in-tool + grant-in-entry works
> in both.) Symptom: a file/exec tool under serve returns `Capability not granted` — you're missing the
> `require` in the **entry**.

**Directory-tree scope:** to read/write files under a dir, grant **both** `file("dir")` (the dir node,
for `list_dir`) **and** `file("dir/*")` (the files inside). Scopes are **literal** — `require exec(cmd)`
with a variable does not parse; use `require exec` for any command, `exec("git")` for one.

Plain `call`/normal invocation does NOT isolate — use `call_tool` for untrusted, model-chosen tools.

## Sandbox blocks
```
sandbox
    -- code here has NO capabilities (fully isolated): net/file/time/random/db/secret
    -- are all DENIED inside, even if the program granted them. `require` inside is a
    -- no-op (can't re-grant to escape). `print` works (not gated); restored on exit.
    let result be compute(untrusted_data)

-- Sandbox can also be an EXPRESSION (returns the value of its body):
let enriched be sandbox transform(untrusted_data)   -- isolated AND returns a value
```
Use it to run untrusted/enriching logic that must NOT touch the network, disk, or any
capability — only pure computation in, value out.

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
- `call_tool` runs a task with ONLY its declared capabilities (∩ the program's); a plain call uses the program's ambient capabilities
- Wildcard: `net("*.example.com")` covers all subdomains
- Path glob: `file("/data/*")` covers all files in /data/. `file` grants **read+write**; use `file.read(scope)` / `file.write(scope)` for least-privilege. Path scope is **faithful**: a `..` escape (`file("./data/*")` + `read_file("./data/../../etc/passwd")`) normalizes outside the scope and is denied. `require file` / `file("*")` cover the whole disk.
- Name prefix: `secret("APP_*")` / `env("APP_*")` / `reveal("APP_*")` covers `APP_DB`, `APP_KEY`, … (only a trailing `*`)
- `db` scope: a **file path** for SQLite; a **canonical URL** for remote engines (Postgres/MySQL/MongoDB/Redis) —
  `scheme://host/db` with **no credentials, port, or query** (so `mysql://user:pw@localhost:3306/appdb?ssl-mode=REQUIRED`
  is gated by `db("mysql://localhost/appdb")`, and `mongodb://u:p@host:27017/appdb?authSource=admin` by
  `db("mongodb://host/appdb")`). A path scope never covers a URL and vice-versa (distinct canonical forms).
  **Redis db-index gotcha:** `redis://host:6379` canonicalizes to `redis://host` (no `/0`), but
  `redis://host:6379/0` to `redis://host/0` — different scopes; match the grant to the `db_open` form.
  Host/db globbing works: `db("postgres://localhost/*")` covers any DB on that host. The gate is the same
  for SQL and Mongo (`mongo_*` ops check `db` exactly like `sql`).
