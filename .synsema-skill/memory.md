# Synsema Agent Memory & Rules

## Persistence

Memory, progress, and rules **automatically persist between executions**. Stored in SQLite at `~/.synsema/state/<program_name>.db`. Auto-loaded on startup, auto-saved after execution.

This means: `remember()` in run 1 → `recall()` in run 2 finds it. If a daemon crashes and restarts, it retains all its knowledge.

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

**`recall` with multiple tags is OR, not AND.** `recall("learning", ["api", "perf"])` returns entries
tagged with **at least one** of the tags (any), not only those with all of them. To narrow by a
specific combination, use a single **composite tag** in both `remember` and `recall`
(e.g. `"objective:" + session`) instead of multiple tags. (`category` and `search` still narrow as
expected; the OR only applies among the tags.)

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
