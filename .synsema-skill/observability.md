# Synsema Observability

> **What's real today:** `log` and the error diagnostics (below) are fully functional. `trace`,
> `measure` and `checkpoint` are **decorative markers** — they run their body but the
> timing/snapshot instrumentation is a stub in the current runtime. `trace`/`measure` take a
> **literal** name; `checkpoint` takes an **expression** (`checkpoint "step_" + text(i)`) but is
> still decorative — it does NOT persist anything. For real **logging** use `log` (also an
> expression); for **crash-resume / step tracking** use the progress builtins (NOT `checkpoint`).

## Logging (real)
```
log "Processing order " + order_id        -- `log` takes a full expression
```

## Tracing / Measurement / Checkpoints (decorative markers — literal name)
```
trace "payment_processing"
    process_payment(order)

measure "db_query"
    run_query(sql)

checkpoint "before_payment"
```
`trace`/`measure` names are literal labels; `checkpoint` accepts an expression
(`checkpoint step`). But ALL of these are decorative — they do NOT persist state; `checkpoint`
does not snapshot variables for resume.

## Crash-resume / step tracking (the real mechanism — see builtins.md / memory.md)
For "ingest done, died in validation, resume there", use the **progress** builtins, not
`checkpoint`:
```
create_progress("import", ["ingest", "validate", "load"])
start_step("import", "ingest")
complete_step("import", "ingest", result)
-- after a restart:
let where be resume_point("import")        -- the step to resume from
```

## Error diagnostics
When an error occurs, Synsema provides:
- **Location**: file, line, column
- **Source context**: code lines around the error, with error line marked
- **Call stack**: readable trace of function calls
- **Variables**: all visible variables and their values at failure
- **Intent**: what the program was trying to do
- **Classification**: data, io, logic, capability, type
- **Recoverable**: yes/no
- **Suggestions**: specific fix suggestions for the error type

## Auto-recovery
1. Retry with backoff (IO/transient errors)
2. Fallback to cached/default data
3. Partial results
4. Speculative alternatives (fork, try, pick best)
5. Human escalation

## Speculative execution
```python
# Fork: try multiple approaches, pick the best
spec.fork(env, [approach_a, approach_b, approach_c])
spec.choose_and_apply(env, results, best_index)
```
