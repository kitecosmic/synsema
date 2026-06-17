# Syntecnia Agent Memory & Rules

## Progress tracking
```
create_progress("sync", ["fetch", "validate", "update", "notify"])
start_step("sync", "fetch")
complete_step("sync", "fetch", "got 100 items")
start_step("sync", "validate")
fail_step("sync", "validate", "3 items invalid")

-- After crash, find where to resume:
let next be resume_point("sync")    -- returns "validate" (retry failed)

-- Display:
show progress_display("sync")
-- Output:
--   [OK] fetch → got 100 items
--   [XX] validate ERROR: 3 items invalid
--   [  ] update
--   [  ] notify
```

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

Categories: `preference`, `rule`, `learning`, `decision`, `context`

## Owner rules
```
-- Define rules
add_rule("max_discount", "must", "discount <= 0.20", "pricing")
add_rule("formal_tone", "prefer", "Use formal tone in emails", "communication")
add_rule("no_delete", "must", "Never delete customer data", "data")
add_rule("minimize_api", "avoid", "Avoid unnecessary API calls", "performance")

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

## Summary
```
print(memory_summary())
-- Output:
--   Agent Memory: 5 entries, 3 rules
--   Entries: 2 preference, 2 learning, 1 context
--   Rules:
--     [must  ] max_discount: discount <= 0.20
--     [prefer] formal_tone: Use formal tone in emails
```
