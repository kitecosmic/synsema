# Synsema Modules (`use` / `export`)

Your program doesn't have to live in one file. Synsema has **native modules**: split code across
several `.syn` files and share `task`, `type`, `let`, `enum` — and **`routes`** (whole groups of
HTTP routes a serve can `mount`) — between them. **Local `.syn` only** — no `use "https://…"`, no
FFI to other languages. That's deny-by-default security: no arbitrary code, no supply chain.

## In 30 seconds

`orders.syn` — a module:
```
export task total_orders()
    give 42

export task greet_order(name)
    give "order for " + name

task secret_helper()        -- no `export` → private to the module
    give "internal"
```
`main.syn` — uses it:
```
use "./orders.syn" as orders

print(text(orders.total_orders()))     -- 42
print(orders.greet_order("Wayne"))     -- order for Wayne
```
Run it: `synsema run main.syn`.

## How it works

- **`export <task|type|let|enum> …`** marks what the module exposes. Anything not marked is **private**.
- **`use "./path.syn" as alias`** imports the module under a name.
- The imported module is effectively a **`map` of its exports**: access with `alias.name(...)` (tasks)
  and `alias.NAME` (constants / types / enums).
- **Real encapsulation:** non-exported names are invisible from outside.
  ```
  print(text(keys(orders)))     -- ["total_orders", "greet_order"]   (only the exports)
  orders.secret_helper()        -- error: Map has no key 'secret_helper'
  ```

## Export data and types, not just tasks
```synsema
-- lexicon.syn
export let VERBS be ["create", "fix", "document"]
export type Point
    x: number
    y: number
```
```
use "./lexicon.syn" as lex
print(text(length(lex.VERBS)))         -- use the exported list
each v in lex.VERBS
    print(v)
let p be lex.Point(1, 2)               -- and the exported types
```
Enums export too: `export enum Status`, then construct and `match` across files
(`alias.Status.variant(...)`, `is alias.Status.variant`). See [types.md](types.md).

## Module state — an exported `let` is one variable (v0.6.29+)

The module's variable is shared by its tasks and its importers: what a module task writes is seen
through `lib.X`, and what you write through `lib.X` is seen by the module's tasks.
```
-- lib.syn
export let STATE be {"n": 0}
export let X be 1
export task bump()
    set STATE["n"] to STATE["n"] + 1
export task read_x()
    give X
```
```
use "./lib.syn" as lib
let snap be lib.STATE          -- a SNAPSHOT (a value): later changes do not touch it
lib.bump()
print(lib.STATE, snap)         -- {n: 1} {n: 0}
set lib.STATE["k"] to 5        -- writes the module's variable
set lib.X to 42                -- rebinds it, like lib.X = 42 in Python
print(lib.read_x())            -- 42
```
- `set lib.Nuevo to 1` (not exported) → error `module has no export 'Nuevo'`; `set lib.bump to 1` →
  error `cannot replace the module task 'bump' from outside the module`. `set lib["X"] to v` follows
  the same rules as `set lib.X to v` (rebinds the export; a new name or a task → the same errors).
- **One module, one state, whatever the path to it** (v0.6.29+): two aliases (`use` of the same file
  from two files), a re-export (`export let L be lib` in another module), a module kept in a map
  (`let mods be {"l": lib}` then `set mods.l.STATE["k"] to v`) — every write lands in the module's
  own `STATE`, and `lib.count()` sees it. The same holds inside a `parallel_map` worker and a `serve`
  request (one state per worker/request — see *Loaded once* below).
- Only the module's variables are shared; a map of data you build (even one holding tasks,
  `{"f": lib.f}`) is an ordinary value, copied on write — what stays shared inside it is the module
  itself (`{"l": lib}`), not copies of its values.

```
-- other.syn:  use "./lib.syn" as l2  /  export let L be l2
use "./lib.syn" as lib
use "./other.syn" as o
set o.L.STATE["b"] to 2            -- through the re-export
let mods be {"l": lib}
set mods.l.STATE["c"] to 3         -- through a map holding the module
print(length(lib.STATE))           -- 3: one STATE ({n: 0} from lib.syn above, plus b and c)
```

## Export ROUTES — split a big serve into modules

A module can export a whole **routes group**; the app's serve block mounts it. Route
bodies can call the module's **private** helpers by simple name:

```
-- shop.syn
task fmt(n)                        -- private
    give "$" + text(n)

export routes tienda
    route "GET /shop"
        give html("<h1>" + fmt(99) + "</h1>")
    route "POST /shop/buy"
        expect body {item: text}
        ...
```
```
-- app.syn
use "./shop.syn" as shop
serve on 8080
    mount shop.tienda              -- or: mount shop.tienda at "/store"
```

Rules: `route` entries inside the group, each with its own `rate_limit` / `timeout`
(v0.6.19+: a mounted route gets its own rate zone; a mount prefix is another zone —
≤ v0.6.18 both were refused inside a group); `stream`/`socket` routes in a group work since
v0.6.20 (mounted like a direct route); a route or the whole group can be `private` (v0.6.20+:
the line `private` at the top — served but out of discovery/OpenAPI); a mounted `requires
auth` still demands `auth with` on the serve block; the
group's shape is validated when the serve is built. Full details in
[serve.md](serve.md) ("Mounted routes").

## Rules (verified)

- **Paths are relative to the importing file.** `../` climbs **inside the project** (v0.6.20+): the
  boundary is the **project root** = the directory of the entry file, so `src/site/pages.syn` can
  `use "../core/i18n.syn"`; above the root → `module path escapes the project root` (from the entry
  file itself the message stays `escapes the importing directory`). Decided on absolute paths, so
  `cd proj && synsema run main.syn` is as safe as an absolute path. (≤ v0.6.19: `../` was blocked at
  the importing directory.)
- **`.syn` only.** `use "./x.txt"` errors (`module path must end in '.syn'`); absolute / root-relative
  paths are rejected (must be relative).
- **Transitive imports:** a module can `use` another. If `main` uses `core` and `core` uses `data`, the
  whole chain loads.
- **Loaded once (cached):** importing the same module twice (even from different files) runs its
  top-level a single time and shares the same exports. This holds under `serve` and `parallel_map`
  too: within a request/worker, all importers share the same module instance — a shared
  `state`/`config` module keeps one identity (write via one importer, read via another), same as
  `run`. Across requests/workers nothing is shared (CSP isolation): use `state_*`, SQL or
  `remember` for that.
- **Cycles are detected:** a circular import gives a clear error (`circular import: …`), not a hang.
- **A module must not contain a `serve` block or a top-level `require`** — those belong to the entry
  file. (A per-task `require` *inside* a task is fine.)
- **`intent:`** is declared only by the entry file; modules don't override it.

## Example layout (entry → core → data)
```
main.syn       -- entry: front-end + tests     (use "./core.syn" as core)
core.syn       -- the logic / public API       (use "./data.syn" as data)
data.syn       -- constants & lists            (export let …)
```
The entry calls `core.handle(...)`; `core` uses `data.LABELS`, etc. `core`'s internal helpers
(`norm`, `render_*`) are **not** exported — they stay encapsulated.

## Recommended pattern
- A **`*_data` / `*_lexicon`** module for constants (`export let`).
- A **`*_core` / `*_brain`** module for the logic (export only the public API).
- A small **entry**: front-end + the `use` imports + tests.
- Export **only what other files need**; keep everything else private.

## Gotchas
- Forgot `export`? The symbol simply **doesn't exist** for importers (`Map has no key '…'`). This is the
  #1 cause of "my module doesn't work".
- Calls **within the same file** are direct (`foo()`); only **cross-file** calls need the alias prefix
  (`mod.foo()`).
- `test "…"` blocks can live in any file and run with `synsema test <file>`; they can call another
  module's exported API (e.g. `assert_eq(core.triage("…"), "task")`). See [testing.md](testing.md).
- **`synsema check` warns (v0.6.20+, exit code unchanged)** when a top-level `let` or an `export routes`
  group has the same name as a `use … as` alias — inside that scope the name is the local, not the module.
- **`synsema check entry.syn` validates the whole import graph** (resolves and parses every
  `use` recursively, with the same rules as the runtime — broken paths, cycles, `serve`/top-level
  `require` inside a module all fail the check) and every `render("literal.html")` template.
