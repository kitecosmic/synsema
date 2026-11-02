# Concurrency

Real multi-core parallelism, no GIL. Two builtins: `parallel_map` and `chunk`
(`parallel_map` runs on a `tokio` M:N executor with backpressure). The sequential
equivalent is `apply`.

## parallel_map(task, list, limit?)

Applies `task` to each item of `list` **concurrently**, returns results **in input
order**. `limit` caps how many run at once (backpressure); omit it for a sensible default
(64 for I/O fan-out, num-cpus for pure compute).

```synsema
task fetch_user(id)
    give fetch("https://api.example.com/users/" + text(id))

let users be parallel_map(fetch_user, ids, 50)   -- 50 concurrent, order preserved
```

**Key invariant:** `parallel_map(t, list)` returns the same result and order as
`apply(t, list)` — it only adds concurrency, never changes semantics.

**Failure (fail-fast):** the first error cancels the rest and propagates. To collect
partial results instead, wrap the task so it returns a value-or-error:

```synsema
task safe_fetch(id)
    try
        give fetch(url_for(id))
    recover e
        give {"error": e}

let results be parallel_map(safe_fetch, ids)   -- never aborts; each item is value-or-error
```

**A lambda or a local task carries its locals (v0.6.50+).** The task you pass can use the locals
of the task that built it; they cross **copied** (a `set` on a captured local changes the
worker's copy, not the original), and only the ones it names (a big unused local costs nothing):
```synsema
task scale(xs, n)
    give parallel_map((x) => x * n, xs)        -- [10, 20, 30] for scale([1, 2, 3], 10)

task shift(xs)
    let base be 7
    task plus(x)                               -- a local task: also recursive ones work
        give x + base
    give parallel_map(plus, xs)                -- [8, 9] for shift([1, 2])
```
Up to v0.6.49 both failed with `Undefined variable: 'n'`. The same holds for agents and `serve`
requests. Also crossing now: a **list of tasks** (`let L be [(x) => x + 1]`, then `L[0](x)` in a
worker; before, `Cannot call value of type text`), a **builtin under another name** (`let up be
upper`), a `type` constructor / `enum` variant, a trusted task in a variable (keeps the tool's
scope), and `parallel_map(t.f, xs)` with a trusted tool. What cannot cross says so: a generator
held in a local (`the generator rng(1) is a local of the task that made this lambda; here it would
restart the same sequence in every request/worker — create it inside the lambda, or give each
parallel_map item its own with rng_spawn(g, n)`), an engine closure (`'read_body' is a closure of
the engine that does not cross into a worker: call it before and pass its result`), and a builtin
the worker lacks (`state_*` in a `parallel_map` worker of a request → `Undefined variable:
'state_get'`: call it in the route, pass the value).

**Isolation:** each item runs in its own interpreter scope (CSP model — inputs are
snapshot-copied, like `spawn`). It inherits the caller's capabilities under the frozen
intent: a `fetch`/`read_file` inside still needs its `require`. A module's exported state is one
per worker, whichever alias reaches it ([modules.md](modules.md)). The LLM operations and `judge`
inside an item use the **same providers** as the caller (v0.6.45+; before, under `synsema run`, they
gave offline placeholders / `available: false` there), and `SYNSEMA_LLM_BUDGET` holds across items.
The same holds for `spawn`ed agents.

**Human gates inside an item (v0.6.53+, breaking).** An `approve`/`confirm`/`ask` in an item uses
the program's human channel: under `serve` it waits for a person (or, with `then`, leaves a pending
approval); in a run without a terminal it is denied — `parallel_map(one, [1, 2])` where `one` does
`give approve …` gives `[false, false]`. Before v0.6.53 an item had no channel and **approved
itself** (`true`). `approve … then` and `cron_every`/`cron_after` are fine in an item, but not in an
item launched from inside a `sandbox` or a tool run by `call_tool` (`… not allowed inside a sandbox
…`): the task would run later with the program's capabilities. See [human.md](human.md).

**Seeded generators** (v0.6.29+): a generator given as an item reaches its worker as a **copy of
its state** — pass one child per item and the results are numpy's `g.spawn(n)` bit for bit. The
same generator in two items is an error (each worker would draw the same numbers):

```synsema
task draw(g)
    give g()
let draws be parallel_map(draw, rng_spawn(rng(42), 3))   -- [0.9167441575549085, 0.4674907799518424, 0.07123920291270869]
```
Pass generators as items. A top-level generator used inside a worker (by name, or inside a global
map) is an error — `the generator rng(1) was created at the top level; here it would restart the same sequence in every request/worker …` — because every worker would repeat the same numbers.
See [builtins.md](builtins.md) § Seeded randomness.

## chunk(list, size)

Splits a list into sublists of `size` (last one may be shorter). `size <= 0` is an error, and so
is a non-integer size (`chunk(xs, 1.5)` → `chunk: size must be an integer, got 1.5 — round it on
purpose first`; a float like `2.0` too).

```
chunk([1, 2, 3, 4, 5], 2)   -- [[1, 2], [3, 4], [5]]
```

## The "10k as 10×1000, then merge" pattern

```synsema
let batches be chunk(items, 1000)                         -- 10 batches
let partial be parallel_map(process_batch, batches, 10)   -- 10 batches in parallel
let merged be flatten(partial)                            -- join the results
```

## When to use what

- **`parallel_map`** — fan-out the *same* task over many items (I/O fan-out, batch
  compute, datalake processing). Hundreds to thousands of concurrent tasks (thread pool).
- **`spawn` / swarm** (see agents.md) — run *different* agents concurrently that
  coordinate via blackboard/signals. Heterogeneous concurrency.

## One event loop: `select` (sockets + processes + bus + watches + the terminal) — engine v0.6.7+

An agent in the loop waits on several things at once: the client's socket, the process
it launched, an upstream feed, the bus. `select` is **the one wait** for all of them —
no polling with `sleep`:

```
let ev be select({"sock": socket, "child": child, "feed": feed, "cancel": sub}, 60)
-- targets: a list of handles, or a map name → handle (any mix of ws_connect / socket /
-- proc_spawn / bus_subscribe / watch / term_open handles). Returns the FIRST ready event, tagged with
--   source: "ws" | "proc" | "bus" | "watch" | "term",  handle,  name (when you passed a map)
-- plus the event's own fields (type/data for ws and proc; topic/data/timestamp for bus).
-- nothing at the timeout, or when every target is gone.
```

Fair (round-robin between targets), sleeps in the kernel poller while idle (never
busy-spins), fails fast with a catchable error when a target dies with a protocol/queue
error, and wakes at once on cancellation (route `timeout`, shutdown, `agent_stop`).
`ws_select` now accepts any handle too (it keeps its historical `conn` tag);
`proc_select` is the same wait restricted to processes. Details: [serve.md](serve.md)
§ WebSocket routes, [processes.md](processes.md) § Live processes / § The program's own
terminal (`term_open`: every key as an event — a chat prompt that stays alive while a
sub-agent reports on the bus), [agents.md](agents.md) § Event bus.

## The HTTP server is already async (high concurrency, no `async` keyword)

The `serve` stack runs on an async `hyper`/`tokio` runtime (one task per connection), with
your route handlers running **synchronously** on a blocking pool. So the server handles many
thousands of concurrent connections cheaply, while the language stays simple (sync handlers).
This is why Synsema has **no `async`/`await` in the language** — concurrency is solved in the
runtime. Measured on a Linux VPS, web throughput **beats Go** (with the security + agent-native
edge Go lacks). For concurrent I/O *inside* a handler, use `parallel_map` (it's tokio-backed).
