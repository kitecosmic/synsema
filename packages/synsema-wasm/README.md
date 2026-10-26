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
- With `labels: true`, a run that hits `maxMemoryMb` reports `steps: null` and
  `private_seen: true` (whether it ran out of memory can depend on a private value): treat it as
  sensitive, like any run with `private_seen`.

### Ceilings for labelled code (v0.6.46)

- **`declassify` is bounded by `ceiling`.** With `labels: true` and a ceiling, only the principals
  the ceiling names can be published: `ceiling: "stdout,declassify=customers"` (globs work:
  `declassify=cust*`; a bare `declassify` allows any; `"sandbox"` never grants it). Otherwise
  `declassify` fails with `label_violation: declassify is not granted for what this value is private
  to (customers) …`, which `try`/`recover` cannot catch. Without a ceiling, or without `labels`,
  nothing changes. **Breaking** for a host that runs labelled code under a ceiling and expects it to
  publish: add `declassify=<principal>`.
- **Private data to your `llm` hook:** the program declares `require llm("customers")` and the
  ceiling says `llm=customers@embedder` (or `llm=customers@*`). Then the prompt carries the data,
  your hook gets `info.principals` (`["customers"]`), the answer comes back private, and `audit`
  has `llm("customers@embedder")` (source `llm-data`). Anything less (`llm=customers@local`,
  `llm=customers`, no ceiling, a bare `require llm`) refuses it before the hook runs. `judge` is the
  same with `require judge("…")` and `judge=…@embedder`.
- **`judge` checks its capability:** a `ceiling` without `judge` refuses a `judge` block
  (`Capability not granted: judge — declared but above the host ceiling …`).

### Trusted tools: `trusted`, `trustedCeiling` (v0.6.46)

```js
const trusted = { tools: `export task first_name(c)
    require declassify("customers")
    give declassify(c.name, "the customer's own name")
` };
const code = `use "trusted:tools" as t
let c be private({"name": "Ana", "card": "4111"}, "customers")
print(t.first_name(c))`;
syn.run(code, { labels: true, ceiling: "stdout", trusted, trustedCeiling: "declassify=customers" });  // prints Ana
```

Code you do not trust can only call the exported tasks of a module you lend; each runs with its own
`require`, bounded by `trustedCeiling` (give one: without it a trusted task declassifies any
principal), and nothing from the caller. Its arguments are data (a task or a lambda among them is
an error). Works in `run`, `test`, `handle` and their `*Async` forms.

### Sealed receipts: `auditor` (v0.6.46)

The engine accepts `auditor` (an X25519 public key in base64url, from `synsema receipt keygen`) and
`sealedBytes` (4096–16777216, default 65536) in `run()`/`runAsync()` and returns the sealed receipt
in `receipt`. `test` and `handle` build no receipt: an `auditor` or `sealedBytes` there is an
error (`auditor: only run seals a receipt`). Before v0.6.49 `run()`/`runAsync()` did not
pass `auditor` on.

```js
import { Synsema } from "@synsema/wasm";
const syn = await Synsema.loadNode();
await syn.ready();
const r = syn.run(code, { filename: "app.syn", labels: true, auditor: AUDITOR_PUBLIC_KEY });
r.receipt;   // the receipt object: write it as one JSON line for `synsema receipt verify` / `open`
```

## Lending capabilities (the host)

The program keeps its manifest (`require net("api.example")`, `require llm`,
`require memory("agenda")`) and your app decides what it actually gets. A missing hook
makes the builtin fail with a clear error; a `ceiling` denies above what the host offers.

```js
const host = {
  http: (req) => ({ status: 200, headers: [["content-type", "application/json"]], body: "{}" }),
  kv: { get: (ns, k) => store.get(ns + "/" + k) ?? null, set: (ns, k, v) => store.set(ns + "/" + k, v) },
  llm: (op, prompt, info) => ({ content: "…", tokens: 12 }),   // info.principals (v0.6.46)
  log: (line) => console.log(line),
};

syn.run(`require memory("agenda")\nremember("preference", "dark mode")`, { host, filename: "agenda.syn" });
syn.run(`require llm\nprint(reason about "the weather")`, { host, ceiling: "stdout" }); // denied: ceiling wins
```

- `kv` backs persistent agent memory (`remember`/`recall`, rules, progress — namespace
  `memory:<declared name>`) and `state_*` (namespace `state`). `delete` and `list` are optional
  (without `list`, `state_all()` is `{}`). `get` returns the stored **text** or `null`/`undefined`;
  `list` returns the key names as an array of strings.
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
- `llm(op, prompt, info)` backs `reason`/`decide`/`analyze`/`generate`; `llm_usage()` sums the
  tokens you report. `info.principals` lists the owners of the private data in the prompt (`[]`
  with public data).
- `http` backs `fetch`/`http_*` and the blockchain read-side RPC — after the `net(host)`
  gate, with the same URL canonicalization as the native binary.

### What a hook must answer (v0.6.46 — breaking)

A hook that fails, or answers something unexpected, is an **error of the builtin that asked**, not
"the key is not there" (before, the next write replaced what your store held):

| Your hook | The program gets |
|---|---|
| `kv.get` throws / rejects | `state_get: host kv.get failed: <message>` |
| `kv.get` returns a number, boolean or object | `… kv.get must return a string or null, got a number` |
| the stored text is not JSON | `state_incr: the stored value of 'c' is not JSON (…)`; nothing is written |
| `kv.list` throws, or returns `{keys: [{name}]}` (Cloudflare KV), `[{name}]`, `undefined` | `state_all: host kv.list failed: kv.list must return a list of strings, got an object` |
| a declared `memory` fails to load or is unreadable | the memory is not opened: `memory "agenda" could not be loaded (…); nothing was loaded, so nothing is written over it` |
| reading the audit log of `reveal`/`sign`/`wallet`/`spend` fails | the operation is refused; the log stays as it was |
| `llm` throws | that call fails with the hook's message (`the host's llm hook threw` without one); redacted when the prompt carried private data |

To migrate: give back the exact text the engine handed to `set` (it is JSON; do not parse it), and
make `list` return key names. Over a store whose `list` answers `{keys: [{name}]}`:

```js
list: async (ns) => (await store.list({ prefix: `${ns}/` })).keys.map((x) => x.name.slice(ns.length + 1)),
```

### The `http` hook: redirects and private addresses (v0.6.46)

- A request that carries a secret (URL, query, body, form or any header) arrives with
  `req.redirect === "error"`. Honor it — with `fetch`, pass `redirect: req.redirect ?? "follow"` —
  or a 3xx carries the key to a host the program never named.
- In wasm the engine checks the host **name** against `require net`, never the address. Natively a
  wildcard `net` grant reaches only public addresses; here that is your hook's job if the programs
  are not yours: resolve the name, check the address against loopback, the private networks (RFC
  1918, CGNAT `100.64.0.0/10`, ULA `fc00::/7`), link-local (`169.254.0.0/16`, the cloud metadata
  endpoint, `fe80::/10`), multicast and the documentation ranges (an IPv4 inside an IPv6 counts as
  that IPv4), and connect to that same address. The hook does not know whether the program named
  the host, so name the private destinations your programs need in the hook. A complete Node hook
  (`node:https` with a checking `lookup`) is in the Synsema docs, *WebAssembly*.

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
pagination and `state_*` (durable through your `kv`) work as in the native server. `receipt()`
in a handler lists only what that request read (v0.6.46: not what the top-level read). Not in
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
