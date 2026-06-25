# Synsema Multi-Agent System

> **LLM tool-calling agents** (a model that picks tools in a loop) are built from the `llm_step` +
> `call_tool` primitives plus an in-language allow-list — see the safe loop in
> [llm.md](llm.md#safe-tool-calling-llm_step--call_tool). The `agent`/`spawn` system below is the
> *concurrency* layer (real threads + blackboard); the two compose.

## Agent definition
Defining an agent **registers** it. The body does NOT run until spawned.
```
agent Researcher
    require net("*.wikipedia.org")
    let data be fetch("https://en.wikipedia.org/api/...")
    share data as "research_results"
    signal "search_done"
```

## Spawning (runs in a real thread)
```
spawn Researcher with query = "AI safety"
```
- Each `spawn` creates a new thread with its own interpreter.
- Multiple spawns of the same agent create independent instances.
- The parent program continues immediately (non-blocking).
- **Top-level tasks and values are snapshotted into the agent** (a COPY) — so the agent can call
  your top-level tasks directly, no HTTP needed. But it's a copy: mutating a value inside the
  agent does NOT affect the parent or other agents. Share state via the blackboard. (Secrets are
  redacted when they cross into an agent.)
- **Agent `log`/`print` appears in the main process stdout**, prefixed `[AgentName]` — agents are
  not silent during development.

## Blackboard (shared state)
```
share value as "key"                     -- publish (key can be expression)
share value as "result_" + text(id)      -- dynamic key
observe "key" as variable                -- read (key can be expression too)
observe "result_" + text(id) as data     -- dynamic key
```
The blackboard is thread-safe, versioned, and watchable.

## Signals (consumable queue)
```
signal "done"                    -- emit a signal
signal "result" with data        -- emit with data
wait_for "done" as result        -- blocks until signal arrives, CONSUMES it (default 30s)
wait_for "done" timeout 2 as r   -- block at most 2 seconds, then `nothing`
wait_for "done" timeout 0.5      -- sub-second; `timeout 0` = immediate check
```
Syntax: `wait_for <channel> [timeout <seconds>] [as <var>]`. The `timeout` (a number of seconds,
int/float, clamped to 0–3600) bounds how long the wait blocks — IMPORTANT in a route handler so a
request doesn't hang the default 30s when the emitter never signals. A non-number timeout errors.

**The channel name is an EXPRESSION** (not only a literal) — so you can have an independent
channel **per job/worker** (push, not poll):
```
-- cancel a specific job by id (e.g. from a DELETE route)
signal "cancel:" + text(job_id)

-- the worker for that job waits on its OWN channel
wait_for "cancel:" + text(job_id) as reason
```
With literal names all jobs share one namespace; with dynamic names each `job_id` is its own
channel. (Per-job cancellation/coordination used to require polling blackboard keys — now it's a
real push channel.)

**Important semantics:**
- Signals are a **queue**, not a latch. Each `wait_for` consumes one signal (pop).
- A single `signal` does NOT wake N consumers reliably. For fan-out, emit N signals or use the blackboard.
- `wait_for` returns `nothing` if **no agents are alive** that could emit, or when the `timeout` elapses. Default is 30s — set `timeout <secs>` to bound it (e.g. in HTTP route handlers, to avoid hanging requests / exhausting threads).
- Pattern for N workers: a dynamic channel per worker (`"work:" + text(id)`), or each worker writes to its own blackboard key and the coordinator reads all keys.

## Resource locking (preventive)
Agents declare what they're working on BEFORE touching it:
- `exclusive` — one agent only (write)
- `shared` — multiple readers, no writers
- `advisory` — logged but not enforced

## Swarm state dump
The swarm runtime tracks agent states (IDLE/STARTING/WORKING/WAITING/DONE/ERROR), blackboard
contents, signals (pending + consumed), and detected conflicts. To inspect them after a run, use
the swarm dump (JSON: `{ok, out, err, blackboard, agents}`):
```bash
synsema conform --swarm program.syn
```
(Note: a live `run --dashboard` flag is **not currently wired** — `synsema run` ignores it. Use
`conform --swarm` for the state dump.)

## Coordination patterns

**Producer-consumer (1:1):**
```
-- Producer
share processed_data as "results"
signal "batch_done"

-- Consumer
wait_for "batch_done"
observe "results" as data
```

**N workers (fan-out):**
```
-- Each worker writes to unique key
agent Worker
    let key be "result_" + text(n)
    share computed_value as key

spawn Worker with n = 1
spawn Worker with n = 2
spawn Worker with n = 3
-- Coordinator reads: observe "result_1" as r1, etc.
```

**Error-safe coordination:**
```
agent Risky
    try
        let data be fetch(url)
        share data as "output"
        signal "done"
    recover err
        share err as "error"
        signal "done"

spawn Risky with url = "https://api.example.com"
wait_for "done"
observe "error" as err
when err != nothing
    print("Agent failed: " + err)
```
