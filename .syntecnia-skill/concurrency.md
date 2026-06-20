# Concurrency (Rust implementation)

Real multi-core parallelism, no GIL. Two builtins: `parallel_map` and `chunk`.
(Available in the Rust interpreter. The Python reference has `apply`, the sequential
equivalent.)

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
- **Deferred:** >10k simultaneous I/O operations in a single fan-out would need an async
  interpreter. The current thread-pool model covers the realistic range.
