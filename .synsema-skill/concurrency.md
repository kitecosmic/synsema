# Concurrency

Real multi-core parallelism, no GIL. Two builtins: `parallel_map` and `chunk`
(`parallel_map` runs on a `tokio` M:N executor with backpressure). The sequential
equivalent is `apply`.

## parallel_map(task, list, limit?)

Applies `task` to each item of `list` **concurrently**, returns results **in input
order**. `limit` caps how many run at once (backpressure); omit it for a sensible default
(64 for I/O fan-out, num-cpus for pure compute).

```
task fetch_user(id)
    give fetch("https://api.example.com/users/" + text(id))

let users be parallel_map(fetch_user, ids, 50)   -- 50 concurrent, order preserved
```

**Key invariant:** `parallel_map(t, list)` returns the same result and order as
`apply(t, list)` — it only adds concurrency, never changes semantics.

**Failure (fail-fast):** the first error cancels the rest and propagates. To collect
partial results instead, wrap the task so it returns a value-or-error:

```
task safe_fetch(id)
    try
        give fetch(url_for(id))
    recover e
        give {"error": e}

let results be parallel_map(safe_fetch, ids)   -- never aborts; each item is value-or-error
```

**Isolation:** each item runs in its own interpreter scope (CSP model — inputs are
snapshot-copied, like `spawn`). It inherits the caller's capabilities under the frozen
intent: a `fetch`/`read_file` inside still needs its `require`.

## chunk(list, size)

Splits a list into sublists of `size` (last one may be shorter). `size <= 0` is an error.

```
chunk([1, 2, 3, 4, 5], 2)   -- [[1, 2], [3, 4], [5]]
```

## The "10k as 10×1000, then merge" pattern

```
let batches be chunk(items, 1000)                         -- 10 batches
let partial be parallel_map(process_batch, batches, 10)   -- 10 batches in parallel
let merged be flatten(partial)                            -- join the results
```

## When to use what

- **`parallel_map`** — fan-out the *same* task over many items (I/O fan-out, batch
  compute, datalake processing). Hundreds to thousands of concurrent tasks (thread pool).
- **`spawn` / swarm** (see agents.md) — run *different* agents concurrently that
  coordinate via blackboard/signals. Heterogeneous concurrency.

## One event loop: `select` (sockets + processes + bus) — engine v0.6.7+

An agent in the loop waits on several things at once: the client's socket, the process
it launched, an upstream feed, the bus. `select` is **the one wait** for all of them —
no polling with `sleep`:

```
let ev be select({"sock": socket, "child": child, "feed": feed, "cancel": sub}, 60)
-- targets: a list of handles, or a map name → handle (any mix of ws_connect / socket /
-- proc_spawn / bus_subscribe handles). Returns the FIRST ready event, tagged with
--   source: "ws" | "proc" | "bus",  handle,  name (when you passed a map)
-- plus the event's own fields (type/data for ws and proc; topic/data/timestamp for bus).
-- nothing at the timeout, or when every target is gone.
```

Fair (round-robin between targets), sleeps in the kernel poller while idle (never
busy-spins), fails fast with a catchable error when a target dies with a protocol/queue
error, and wakes at once on cancellation (route `timeout`, shutdown, `agent_stop`).
`ws_select` now accepts any handle too (it keeps its historical `conn` tag);
`proc_select` is the same wait restricted to processes. Details: [serve.md](serve.md)
§ WebSocket routes, [processes.md](processes.md) § Live processes, [agents.md](agents.md)
§ Event bus.

## The HTTP server is already async (high concurrency, no `async` keyword)

The `serve` stack runs on an async `hyper`/`tokio` runtime (one task per connection), with
your route handlers running **synchronously** on a blocking pool. So the server handles many
thousands of concurrent connections cheaply, while the language stays simple (sync handlers).
This is why Synsema has **no `async`/`await` in the language** — concurrency is solved in the
runtime. Measured on a Linux VPS, web throughput **beats Go** (with the security + agent-native
edge Go lacks). For concurrent I/O *inside* a handler, use `parallel_map` (it's tokio-backed).
