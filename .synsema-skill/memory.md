# Synsema Agent Memory & Rules

## Declared memory — `require memory("name")` (REQUIRED)

Persistent agent state is **opt-in and declared**. The whole family — memory
(`remember`/`recall`/`forget_memory`/`memory_summary`), owner rules (`add_rule`/
`check_rules`/`get_rules`), and progress (`create_progress`/`start_step`/`complete_step`/
`fail_step`/`resume_point`/`progress_display`/`progress_percent`) — is gated by ONE
capability you must declare at the top of the program:

```
require memory("support-agent")
remember("context", "customer prefers email")
```

Without the declaration every one of those builtins fails (also under plain `run` —
`memory` is **never auto-granted**, because it writes files to disk):

```
Capability not granted: memory. Persistent agent state (remember/recall, rules,
progress) requires a declared memory — the declared name identifies its .db file.
Add: require memory("<stem>") at the top of the program
```

…and **no file or directory is created**. Programs that don't declare memory leave
zero footprint on disk.

**The declared name IS the identity.** State lives in
`<program-dir>/.synsema/state/<name>.db` (gitignore `.synsema/`) — keyed by the
**declared name**, NOT the filename:

- Renaming the `.syn` file changes nothing — same declared name, same memory.
- Two entry points (`cli.syn`, `web.syn`) that declare the **same** name **share** one
  memory — no env var needed.
- Changing the declared name points at a new `.db`; the old one is left untouched
  (migrate by renaming the file to `<new-name>.db`).
- Exactly **one** declared name per program: two `require memory` with different names
  is a startup error. Repeating the same name is fine.
- Names must match `[a-zA-Z0-9_-]+` — no `/`, `\`, `..`, no empty string, no `.db`
  suffix. Invalid names fail **at the declaration**, before anything runs.
- `require memory` without a name is a **parse error** (a declaration with no name has
  no identity).

**Env vars:** `SYNSEMA_STATE_DIR` still relocates the state directory (tests, deploys;
tip: `SYNSEMA_STATE_DIR=$(mktemp -d)` keeps test runs from writing `.synsema/` into the
tree). `SYNSEMA_STATE_NAME` is **deprecated and ignored** (warning) — the declaration
replaced it. If the project-local dir isn't writable it falls back to
`~/.synsema/state/` with a warning.

**Migrating from the pre-declaration engine** (state used to auto-persist keyed by file
stem): running an undeclared program next to an old `<stem>.db` prints a warning with
the exact line to add — `require memory("<stem>")` — and touches nothing. The schema is
unchanged: migration is just declaring the name (and renaming the `.db` if you pick a
different one).

**Everywhere the same identity:** `run`, `test`, `serve` (handlers, cron ticks),
`parallel_map` workers, and spawned agents all share the program's ONE declared memory,
with write-through persistence (each mutation is saved immediately — a crash loses
nothing already written). In the **REPL** type `require memory("x")` to enable a
session-only in-memory store (nothing on disk). Programs run from `<stdin>` get the
same in-memory-only degradation, with a warning.

**Capability semantics** (same doctrine as `db`/`sign`/`wallet`):
- Denied inside `sandbox` blocks like everything else.
- `call_tool` intersects it: a tool that doesn't declare `require memory("<name>")`
  cannot touch the state even if the program granted it.
- The host ceiling gates it: `--cap-set` without `memory` denies the whole family (and
  creates **no** `.db`); `--cap-set "memory=shop-*"` allows only declared names under
  that prefix.

## Persistence

`remember()` in run 1 → `recall()` in run 2 finds it. If a daemon crashes and restarts,
it retains all its knowledge. **Both memory AND progress persist across `serve`
requests** (so a plan started in one request advances in the next; concurrent writers:
last-write-wins per entry).

## Progress tracking
```
require memory("sync-agent")
create_progress("sync", ["fetch", "validate", "update", "notify"])
start_step("sync", "fetch")
complete_step("sync", "fetch", "got 100 items")
start_step("sync", "validate")
fail_step("sync", "validate", "3 items invalid")

-- After crash/restart, find where to resume:
let next be resume_point("sync")    -- returns "validate" (retry failed)

-- Display:
show progress_display("sync")
-- Output:
--   [OK] fetch → got 100 items
--   [XX] validate ERROR: 3 items invalid
--   [  ] update
--   [  ] notify
```

Progress persists to disk. A restarted daemon resumes where it left off.

## Persistent memory
```
require memory("assistant")

-- Store
remember("preference", "Customer prefers formal tone", ["communication"])
remember("learning", "API slow on Mondays", ["api", "performance"])
remember("context", "Project deadline is June 30", ["timeline"])

-- Retrieve
let prefs be recall("preference")
let api_notes be recall("learning", ["api"])
let search be recall(nothing, nothing, "Monday")

-- Remove
forget_memory(entry_id)
```

**`recall` full signature — 6 args, all skippable, named args accepted:**
`recall(category, tags, search, mode, limit, from)`. Positionally skip with `nothing`,
or use names: `recall("learning", limit = 10)`, `recall(from = "writer")`.

**`recall` multi-tag mode — OR (default) or AND.** `recall("learning", ["api", "perf"])` returns
entries tagged with **at least one** of the tags (OR / any). To require **all** tags, pass the 4th arg
`mode = "all"`: `recall("learning", ["api", "perf"], nothing, "all")` returns only entries that have
both. (`category` and `search` always narrow; the mode applies only to the tags.)

**`recall` order — newest-first.** Results are sorted **most-recent-first** by last-write time
(`updated_at`): `recall(...)[0]` is the entry written/updated most recently, and the **last** element is
the oldest. (Re-`remember`/`update` on an entry bumps it to the front.) Don't take `xs[length - 1]` to get
"the latest" — that's the **oldest**; use `xs[0]`.

**`recall` limit — default 200, configurable (5th arg).** `recall` returns at most **200** entries by
default. Pass a 5th arg to change it: `recall("context", nothing, nothing, "any", 1000)` returns up to
1000. Mind this when counting: `length(recall(cat))` is capped at the limit, so for long histories pass an
explicit limit (or use `state_incr` for a counter). The same args work under `serve`.
(Earlier engine versions silently truncated to 20.)

**Categories are a fixed set (English only):**
`preference`, `rule`, `learning`, `decision`, `context`

Using any other string (e.g. `"preferencia"`) raises an error:
`Invalid memory category: 'preferencia'. Valid categories: preference, rule, learning, decision, context`

## Per-agent namespaces (`source` / `from`)

Every entry records who wrote it in its `source` field: `remember` inside `agent X`
writes `source = "X"`; top-level code (and serve route handlers) write `source = "main"`.
Reads are namespaced **by default** so agents sharing one memory don't confuse each
other's notes:

```
require memory("newsroom")

agent Writer
    remember("context", "draft done")          -- source = "Writer"

agent Analyzer
    let mine   be recall()                     -- ONLY Analyzer's own entries (default)
    let theirs be recall(from = "Writer")      -- cross-namespace, explicit opt-in
    let all    be recall(from = "*")           -- everything

spawn Writer
spawn Analyzer

let everything be recall()                     -- top-level sees ALL by default
let top_only   be recall(from = "main")        -- just the top-level's own entries
```

- Inside an agent: `recall()` defaults to the agent's own namespace; `from = "name"`
  crosses into another; `from = "*"` reads everything.
- At top-level: `recall()` reads everything; filter with `from = "main"` / `from = "X"`.
- `from` is the 6th arg of `recall` — a named arg like `mode`/`limit` (no new syntax).
- Rules and progress are NOT namespaced — they are program-global (one rulebook, one
  plan board).

## Owner rules
```
require memory("pricing-agent")

-- Define rules
add_rule("max_discount", "must", "discount <= 0.20", "pricing")
add_rule("formal_tone", "prefer", "Use formal tone in emails", "communication")
add_rule("no_delete", "must", "Never delete customer data", "data")

-- Check before acting
let violations be check_rules("pricing", {"discount": 0.25})
when length(violations) > 0
    approve "Rule violation detected. Override?"

-- List active rules
let rules be get_rules("pricing")
```

Rule levels:
- `must` — hard block, violation is an error
- `should` — soft, violation is a warning
- `avoid` — preference against doing something
- `prefer` — preference for doing something

Rules with numeric conditions (e.g. `"discount <= 0.20"`) are auto-extracted and evaluated against the context map.

## Summary
```
print(memory_summary())
```
