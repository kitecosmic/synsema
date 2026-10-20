# @synsema/wasm

[Synsema](https://github.com/kitecosmic/synsema) — the programming language for AI agents —
embedded as WebAssembly. Run `.syn` programs inside a browser, Node/Bun/Deno or an edge
runtime, and lend them exactly the capabilities your app decides to: `http`, a `kv`
store, an `llm`, a `log`. No Synsema backend, nothing to install on the host.

```js
import { Synsema } from "@synsema/wasm";

// Node (also Next.js API routes and Server Actions): the .wasm that ships in this package.
const syn = await Synsema.loadNode();
// Browser / edge: serve synsema.wasm with your static files and load it by URL:
//   const syn = await Synsema.load("/synsema.wasm");
await syn.ready();

const r = syn.run(`print(keccak256("hola"))`);
r.output;  // ["…"]  — the program's print lines
r.errors;  // []     — parse/runtime errors are data, never exceptions
r.audit;   // every capability check: {capability, granted, source, reason, origin}
           // origin: "program" (asked/called by the program) | "runtime" (ambient host grant)
           // sign/spend/wallet/reveal need an audit sink: offer `kv` (namespace "audit") or they refuse
```

## Untrusted code: labels, limits, concurrency

Code a model wrote is the usual reason to embed Synsema. These options make that safe to run
inside a server:

```js
const syn = await Synsema.loadNode({ workers: 4 }); // async calls run on up to 4 Workers

const r = await syn.runAsync(code, {
  host,
  labels: true,                                    // information-flow labels on
  input: { var: "customer", value: row, sources: { card: ["customer"] } },
  result: "out",                                   // r.result = the final value of `out`
  timeoutMs: 2000,                                 // the Worker is stopped past this
  maxSteps: 5_000_000,                             // interpreter steps, deterministic
  maxMemoryMb: 64,                                 // memory the run reserves
});
```

- With `labels: true`, every key listed in `sources` reaches the program as a private value. A
  private value, or a branch that depended on one, never reaches `print`, your `http` hook
  (`fetch`/`http_*`), your `kv` (`state_*`, `remember`), your `llm` or your `sleep` (its number
  crosses to the host): the call fails with `label_violation` before the hook runs.
  `r.private_seen` says whether one went through; then `r.steps` is `null` (how many steps the
  run took depended on the data). `sources` needs `labels: true`.
- `result: "out"` returns the final value of the global `out` in `r.result`, with its labels: a
  private part comes back as `{"$private": ["customer"], "value": …}`. `r.declassify` lists each
  `declassify` the run made. Without `labels`, `result` is plain JSON.
- `timeoutMs` (async mode): `0` means no deadline; otherwise milliseconds, up to 2147483647,
  counted from when the call starts running, not while it waits in the queue. Past it the call
  fails with a clear error and its Worker is replaced. The server's own thread never blocks. A
  host hook already running (a `fetch`) is not cut; its result is discarded. A host hook with no
  deadline of its own that never answers keeps its Worker busy unless the call has a `timeoutMs`.
- `maxSteps` and `maxMemoryMb` (both modes): the run ends with `ok: false` and an error that says
  which limit it hit — never a trap. `maxSteps` counts interpreter steps from the start of the run
  (in `handle`, of each request); `maxMemoryMb` counts the memory the run reserves, not what the
  instance already held. Both are positive integers: `0` is an error, not "no limit". No call
  inherits the limits of the previous one.
- Concurrent async calls wait in one queue and go to the first free Worker (up to `workers: n`). A
  Worker that does not start in `startMs` (an option of `Synsema.load`/`loadNode`, default 30 s) is
  stopped. A Worker that dies fails the call it was running (not retried: it may have had
  effects) and is replaced. `close()` is final: what waits fails with "closed".
- A host hook that returns something that is not JSON (a `BigInt`, a circular object) or throws a
  value without a message counts as that hook failing in that call, in both APIs — not a hung
  Worker or a trapped module.
- In the sync API a trap recreates the instance by itself (the call throws
  `synsema: the module trapped (…); the instance was recreated`; the next call works).

## Lending capabilities (the host)

The program keeps its manifest (`require net("api.example")`, `require llm`,
`require memory("agenda")`) and your app decides what it actually gets. A missing hook
makes the builtin fail with a clear error; a `ceiling` denies above what the host offers.

```js
const host = {
  http: (req) => ({ status: 200, headers: [["content-type", "application/json"]], body: "{}" }),
  kv: { get: (ns, k) => store.get(ns + "/" + k) ?? null, set: (ns, k, v) => store.set(ns + "/" + k, v) },
  llm: (op, prompt) => ({ content: "…", tokens: 12 }),
  log: (line) => console.log(line),
};

syn.run(`require memory("agenda")\nremember("preference", "dark mode")`, { host, filename: "agenda.syn" });
syn.run(`require llm\nprint(reason about "the weather")`, { host, ceiling: "stdout" }); // denied: ceiling wins
```

- `kv` backs persistent agent memory (`remember`/`recall`, rules, progress — namespace
  `memory:<declared name>`) and `state_*` (namespace `state`). `delete` and `list` are optional.
- `kv.cas(ns, key, expected, value)` (optional) is compare-and-swap: write `value` only if the
  stored text is exactly `expected` (`null` = the key does not exist) and return `true` or
  `false` — anything else fails the call with `kv.cas must return true or false`. Your store must
  compare and write in one step (a transaction, a conditional put):

  ```js
  cas: (ns, k, expected, v) => {
    if ((store.get(ns + "/" + k) ?? null) !== expected) return false;
    store.set(ns + "/" + k, v);
    return true;
  },
  ```

  `state_merge(key, map)` and `state_cas(key, expected, new)` depend on it. With a host `kv`
  that has `cas` they are atomic, also across instances sharing the store. With a host `kv`
  without `cas` they fail saying so (`the host's kv does not offer cas (kv.cas) …`) instead of
  risking a lost write. With no host `kv`, the state belongs to the wasm instance and is atomic:
  it lasts across that instance's `handle` requests, and each `run` starts with an empty state.
- `llm` backs `reason`/`decide`/`analyze`/`generate`; `llm_usage()` sums the tokens you report.
- `http` backs `fetch`/`http_*` and the blockchain read-side RPC — after the `net(host)`
  gate, with the same URL canonicalization as the native binary.

## Async hosts (browser `fetch`, IndexedDB, LLM SDKs)

The interpreter is synchronous. `runAsync`/`handleAsync` run it in a Worker and block on
`Atomics.wait` while your Promises resolve on the main thread:

```js
const r = await syn.runAsync(program, { host: { async http(req) { const res = await fetch(req.url); return { status: res.status, headers: res.headers, body: await res.text() }; } } });
await syn.close();
```

Node/Bun/Deno: works out of the box. Browsers: needs cross-origin isolation
(`Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp`)
for `SharedArrayBuffer`. Without it, use the sync API with a sync host.

## `serve` without sockets (edge handler)

```js
const app = `require serve(8080)
serve on 8080
    route "GET /hello/:name"
        give {"hi": params.name, "visits": state_incr("visits")}`;
const res = syn.handle(app, { method: "GET", path: "/hello/ana", headers: {} }, { host });
res.status; res.content_type; res.headers; res.body;
```

Routes, params, query, `auth with`, `errors with`, `content()` negotiation, `redirect`,
pagination and `state_*` (durable through your `kv`) work as in the native server. Not in
handler mode: `stream` (SSE), `proxy to`, rate limits, `static` mounts, vhosts, TLS —
your edge platform does those before calling the handler.

## Also: `test`, `check`, `version`

`syn.test(source)` runs the file's `test` blocks; `syn.check(source)` parses and
validates without running; `syn.version()` is the artifact's release tag.

## Files, time, randomness

This artifact has **no filesystem** (`read_file` says so; pass data through `env` or the
source). `now()` comes from `Date.now()`. Each call asks the host once for 32 bytes of
entropy (`crypto.getRandomValues`), which seed that run's own ChaCha generator: `random()`,
`random_bytes(n)`, `token()` and RSA blinding draw from it and never ask the host again, so how
much randomness a run used does not show. With `labels`, `now()` returns the clock read at the
start of the run and at each interaction with the host (a hook call), so when and how often the
program read the clock does not show either. For file-based confidential jobs use the wasip1 build
under wasmtime (see the Synsema docs, *WebAssembly*).

## Other languages

The `.wasm` has a plain JSON ABI (`synsema_call`) and three imports (`synsema_host`),
so it embeds anywhere: see `examples/embed/python` (wasmtime-py) and `examples/embed/go`
(wazero) in the repository.
