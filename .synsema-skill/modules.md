# Synsema Modules (`use` / `export`)

Your program doesn't have to live in one file. Synsema has **native modules**: split code across
several `.syn` files and share `task`, `type`, `let`, and `enum` between them. **Local `.syn` only** —
no `use "https://…"`, no FFI to other languages. That's deny-by-default security: no arbitrary code,
no supply chain.

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
  print(text(keys(orders)))     -- [total_orders, greet_order]   (only the exports)
  orders.secret_helper()        -- error: Map has no key 'secret_helper'
  ```

## Export data and types, not just tasks
```
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

## Rules (verified)

- **Paths are relative to the importing file**, with directory traversal blocked — you can't escape your
  project. Use `./` for the same directory; `../` is restricted (`module path escapes the importing
  directory`).
- **`.syn` only.** `use "./x.txt"` errors (`module path must end in '.syn'`); absolute / root-relative
  paths are rejected (must be relative).
- **Transitive imports:** a module can `use` another. If `main` uses `core` and `core` uses `data`, the
  whole chain loads.
- **Loaded once (cached):** importing the same module twice (even from different files) runs its
  top-level a single time and shares the same exports.
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
