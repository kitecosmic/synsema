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
- **What the agent does NOT see**: tasks defined inside imported modules (only the entry
  program's top-level bindings are snapshotted — re-export what the agent needs as a top-level
  task), and a task passed as a `spawn` argument arrives as **text** (closures do not cross
  threads — pass data, or the name of a top-level task and call it inside). Each agent is a
  fresh interpreter with its own capability set: it needs its **own `require`** lines in its
  body (bounded by the host ceiling), the parent's grants are not inherited.
- **Agent `log`/`print` appears in the main process stdout**, prefixed `[AgentName]` — agents are
  not silent during development.

**Testing agents.** `synsema test` wires the same real swarm as `run` (engine v0.6.10+): inside a
`test` block `spawn` runs the agent in its own thread, `agents()`/`agent_stop` exist, blackboard
and signals work. When the block's body ends the runner **joins** that block's agents; an agent
that finished in `ERROR` fails **that** test (message `Agent error [<id>]: …`), and the next
block starts clean. On engines ≤ 0.6.9 `test` had no swarm (`spawn` ran the body in-process and
blocking; `agents()` did not exist) — that is why older projects test agents from `synsema run`.

**Agent lifecycle & isolation (`run`, `conform --swarm`, `serve`, `test` all use real threads).** An agent
runs in its own isolated interpreter: a failing agent (e.g. a `raise` with no `recover`) is
**contained** — it transitions to state `ERROR` and does **not** abort the main program or truncate
its output. When the main program finishes, `synsema run` **joins** the spawned agents (waits for
them) before exiting, so the process does not return while agents are still working. **Exit code:**
`synsema run` exits non-zero if the main program fails **or** if any agent ended in `ERROR` (each
such failure is reported on stderr as `Agent error [<id>]: <message>`); a clean run with all agents
`DONE` exits 0. (For the post-run state dump — blackboard + per-agent states as JSON — use
`conform --swarm`.)

## Blackboard (shared state)
```
share value as "key"                     -- publish (key can be expression)
share value as "result_" + text(id)      -- dynamic key
observe "key" as variable                -- read (key can be expression too)
observe "result_" + text(id) as data     -- dynamic key
```
The blackboard is thread-safe, versioned, and watchable. (It's ephemeral coordination —
for state that must survive restarts, agents share the program's **declared memory**:
`require memory("name")` at top-level covers every spawned agent, each agent writes under
its own `source` namespace, and `recall()` inside an agent defaults to its OWN entries —
cross with `recall(from = "other")` / `from = "*"`. See [memory.md](memory.md).)

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

## Event bus — `bus_*` (fan-out, no polling) — engine v0.6.7+

`signal`/`wait_for` is point-to-point: one receiver consumes the signal. A live UI needs
**fan-out**: N handlers (one per SSE/socket client) receive the same event an agent, a cron
or another request published — without polling. That is the bus. **One bus per program**,
seen from everywhere: top-level, `parallel_map` workers, cron ticks, spawned agents, and
every handler of every `serve` worker. In-process only (no Redis yet — that will reuse this
API). No capability (same trust level as `share`/`signal`).

```
-- publisher (an agent, a cron tick, a POST route…)
bus_publish("agent.progress", {"step": 3, "of": 10})      -- → how many subscribers got it

-- subscriber (an SSE route, a socket route, a worker loop…)
let sub be bus_subscribe("agent.*")                        -- one topic or a list; globs `*` / `?`
let ev be bus_recv(sub, 25)                                -- {type: "event", topic, data, timestamp} or nothing
bus_unsubscribe(sub)
bus_topics()                                               -- [{topic, subscribers}] (patterns as subscribed)
```

- The value must be **data** (text/number/bool/list/map/bytes): a task or a `secret` →
  error, never silently degraded. Published topics are literal (a glob in `bus_publish` is
  an error — globs belong to `bus_subscribe`).
- **Bounded per subscriber**, in both count and bytes: `bus_subscribe(topic, {"max_queue":
  1024, "max_queue_bytes": 16777216, "on_full": "drop_oldest"})`. Default
  `"drop_oldest"` — a slow subscriber never stalls the publisher; `"error"` makes the
  next recv raise a catchable error and drops the subscription.
- A subscription lives as long as its interpreter: when a handler/agent ends, its
  subscriptions are removed — a publisher never fills a queue nobody reads.
- Inside `select` a bus event is tagged `source: "bus"` (+ `handle`, `name`).

SSE fed by the bus (the whole point):

```
route "GET /events"
    stream
        let sub be bus_subscribe("agent.*")
        while true
            let ev be bus_recv(sub, 25)
            when ev != nothing
                send ev["data"] as ev["topic"]
```

## Observing and stopping agents — `agents()` / `agent_stop` (engine v0.6.7+)

```
agents()                 -- [{id, name, state, error, started_at, finished_at}]
agent_stop(id, reason?)  -- true if it was alive; the agent ends in state "stopped"
```

`id` is the instance (`Researcher_0`), `name` the declared agent. States: `idle`,
`starting`, `working`, `waiting`, `done`, `error`, `stopped`. `agent_stop` is
**cooperative cancellation**: the agent's interpreter raises `cancelled: <reason>` before
its next statement, and any wait (`wait_for`, `sleep`, `select`, `bus_recv`, `proc_*`,
`run`) wakes immediately — a `while true` agent is no longer immortal. Available under
`run` and `serve`, no capability (introspection of your own process).

## Agents under `serve` (engine v0.6.7+)

An agent spawned from a handler or a cron tick gets **the same wiring a cron tick has**:
`state_*`, the shared database, the approvals queue, cron, the bus and the declared memory
— not an island with fresh builtins. It runs under the host ceiling of `synsema serve
--sandbox | --cap-set <list>` (a `require` inside it never exceeds what the operator
fixed, exactly like `run`), and an ordered shutdown (`Ctrl-C`) stops it via `agent_stop`.

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
