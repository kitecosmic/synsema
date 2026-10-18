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

## Untrusted code: labels, time limit, concurrency

Code a model wrote is the usual reason to embed Synsema. Three options make that safe to run
inside a server:

```js
const syn = await Synsema.loadNode({ workers: 4 }); // async calls run on up to 4 Workers

const r = await syn.runAsync(code, {
  host,
  labels: true,                                    // information-flow labels on
  input: { var: "customer", value: row, sources: { card: ["customer"] } },
  timeoutMs: 2000,                                 // the Worker is stopped past this
});
```

- With `labels: true`, every key listed in `sources` reaches the program as a private value. A
  private value, or a branch that depended on one, never reaches `print`, your `http` hook
  (`fetch`/`http_*`), your `kv` (`state_*`, `remember`) or your `llm`: the call fails with
  `label_violation` before the hook runs. `r.private_seen` says whether one went through.
- `timeoutMs` (async mode): the call fails with a clear error and its Worker is replaced; the
  server's own thread never blocks.
- Concurrent async calls queue per Worker; `workers: n` spreads them. In the sync API a trap
  recreates the instance by itself.

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
  `memory:<declared name>`) and `state_*` (namespace `state`).
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
source). `now()` comes from `Date.now()`; `random()`, `token()` and every signature nonce
come from `crypto.getRandomValues`. For file-based confidential jobs use the wasip1 build
under wasmtime (see the Synsema docs, *WebAssembly*).

## Other languages

The `.wasm` has a plain JSON ABI (`synsema_call`) and three imports (`synsema_host`),
so it embeds anywhere: see `examples/embed/python` (wasmtime-py) and `examples/embed/go`
(wazero) in the repository.
