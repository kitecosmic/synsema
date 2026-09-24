# Synsema Observability

> **What's real today:** `log` and the error diagnostics (below) are fully functional. `trace`,
> `measure` and `checkpoint` are **decorative markers** — they run their body but the
> timing/snapshot instrumentation is a stub in the current runtime. `trace`/`measure` take a
> **literal** name; `checkpoint` takes an **expression** (`checkpoint "step_" + text(i)`) but is
> still decorative — it does NOT persist anything. For real **logging** use `log` (also an
> expression); for **crash-resume / step tracking** use the progress builtins (NOT `checkpoint`).

## Logging (real)
```synsema
log "Processing order " + order_id        -- `log` takes a full expression
```

## Logging under `serve` (and where it shows up)

Under `serve`, `log` and `print` go to the **server's terminal**, prefixed:
- `log "msg"` → `[serve] [LOG] msg`
- `print(x)`  → `[serve] x`

There is **no automatic access log** — `serve` does **not** log requests for you, so the terminal
is quiet by default (this surprises people and makes dev hard). **Add a `log` in your handlers** to
see traffic while developing:

```synsema
serve on 8080
    route "GET /items/:id"
        log "GET /items/" + params.id      -- shows as: [serve] [LOG] GET /items/42
        give get_item(params.id)
```

(A spawned agent's `log`/`print` also appear, prefixed `[AgentName]`.) Under `conform`/`conform --swarm` that live `[main]`/`[agent]` echo goes to **stderr** — stdout carries ONLY the final JSON (parse-safe). Under plain `run`, `print`
is written **immediately**, line by line (v0.6.29+; older engines buffered it until the program ended — `flush()` there).

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
`checkpoint` (they need the declared memory: `require memory("<name>")` at the top —
[memory.md](memory.md)):
```synsema
require memory("import-agent")
create_progress("import", ["ingest", "validate", "load"])
start_step("import", "ingest")
complete_step("import", "ingest", result)
-- after a restart:
let where be resume_point("import")        -- the step to resume from
```

## Step counter — `steps()` (v0.6.20+)
`steps()` → statements executed so far in this program. Counts nodes, not time → deterministic
(same program, same number); no capability; every profile. `synsema run --format json` reports it
as `steps` next to `llm_tokens`. Use it as a cost for metering/tests/fuel-style limits:
```synsema
let before be steps()
process(batch)
log "cost: " + text(steps() - before) + " steps"
```

**Under information-flow labels** (`--labels`, `serve --attested`) `steps()` carries the union of
everything private the run has touched, and the host reports `"steps": null` in `--format json`
and in the `--attest` document once the run touched private data. That is not caution: the counter
is one step per AST node, so it is *linear in what the program walked*, and after a loop whose
condition depended on a secret it **is** the secret with a multiplication and an addition on top —
`(steps() - base - 24) / 4` reconstructed a private scalar exactly, in one line. Before the first
private value it is a plain public number and works as it always did. To publish it afterwards,
say so:
```synsema
let cost be declassify(steps(), "the step count is published as a cost metric")
```
which is recorded in the declassify log and listed by `synsema code check --json`.

## Capability audit without a flag (v0.6.20+)
`SYNSEMA_AUDIT=json|<path>|fd:N|unix:<path>` in the process environ turns the audit stream on — the way
a container does it, and it also works inside a `synsema build` binary; `synsema build --audit …`
bakes the sink; the `--audit` flag wins over the variable. `unix:` (a socket somebody listens on;
loud failure if nobody does) and `fd:N` are Unix only (Windows → exit 2). See [capabilities.md](capabilities.md).

## Error diagnostics
When an error occurs, Synsema can provide a rich report:
- **Location**: file, line, column
- **Source context**: code lines around the error, with error line marked
- **Call stack**: readable trace of function calls
- **Variables**: all visible variables and their values at failure
- **Intent**: what the program was trying to do
- **Classification**: data, io, logic, capability, type
- **Recoverable**: yes/no
- **Suggestions**: specific fix suggestions for the error type

### How to see it
The rich report is **opt-in** via `--explain` (so plain `run` stays script/CI friendly):
```
synsema run --explain program.syn               # human-readable report on stderr
synsema run --explain --format json program.syn # structured JSON (for tools/agents)
```
Without `--explain`, `synsema run` prints only the short line
(`Runtime error: <file>:<line>:<col>: <msg>`) — the stable, parseable form for scripting.
The process exit code is unchanged either way (1 on failure, 0 on success).

## Auto-recovery
1. Retry with backoff (IO/transient errors)
2. Fallback to cached/default data
3. Partial results
4. Speculative alternatives (fork, try, pick best)
5. Human escalation

Auto-recovery (including speculative fork/try/pick-best) is an internal runtime strategy — there
is no user-facing API to drive it; you get it via `try`/`recover` and the recovery protocol.
