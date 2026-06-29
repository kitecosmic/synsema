# Synsema Agent Memory & Rules

## Persistence

Memory, progress, and rules **automatically persist between executions** in SQLite. Auto-loaded on startup, auto-saved after execution.

**Location (project-local by default):** `<program-dir>/.synsema/state/<name>.db` — next to the `.syn`, inside the project (portable, gitignore `.synsema/`). `<name>` = the file stem (`alfred.syn` → `alfred.db`), or the `SYNSEMA_STATE_NAME` env override (so several entry files in one project — CLI/REPL/web — can **share** one memory). `SYNSEMA_STATE_DIR` overrides the directory. Falls back to the old global `~/.synsema/state/` (with a warning) if the local dir isn't writable; set `SYNSEMA_STATE_DIR=~/.synsema/state` to restore the old behavior. (Tip: `SYNSEMA_STATE_DIR=$(mktemp -d)` to keep test runs from writing `.synsema/` into the tree.)

This means: `remember()` in run 1 → `recall()` in run 2 finds it. If a daemon crashes and restarts, it retains all its knowledge. **Both memory AND progress persist across `serve` requests** (so a plan started in one request advances in the next).

## Progress tracking
```
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

**`recall` multi-tag mode — OR (default) or AND.** `recall("learning", ["api", "perf"])` returns
entries tagged with **at least one** of the tags (OR / any). To require **all** tags, pass the 4th arg
`mode = "all"`: `recall("learning", ["api", "perf"], nothing, "all")` returns only entries that have
both. (`category` and `search` always narrow; the mode applies only to the tags. Pass `nothing` for an
earlier positional arg you want to skip.)

**`recall` order — newest-first.** Results are sorted **most-recent-first** by last-write time
(`updated_at`): `recall(...)[0]` is the entry written/updated most recently, and the **last** element is
the oldest. (Re-`remember`/`update` on an entry bumps it to the front.) Don't take `xs[length - 1]` to get
"the latest" — that's the **oldest**; use `xs[0]`.

**`recall` limit — default 200, configurable (5th arg).** `recall` returns at most **200** entries by
default. Pass a 5th arg to change it: `recall("context", nothing, nothing, "any", 1000)` returns up to
1000. Mind this when counting: `length(recall(cat))` is capped at the limit, so for long histories pass an
explicit limit (or use `state_incr` for a counter). The same 4th/5th args (`mode`, `limit`) work under
`serve`. (Earlier engine versions silently truncated to 20.)

**Categories are a fixed set (English only):**
`preference`, `rule`, `learning`, `decision`, `context`

Using any other string (e.g. `"preferencia"`) raises an error:
`Invalid memory category: 'preferencia'. Valid categories: preference, rule, learning, decision, context`

## Owner rules
```
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
