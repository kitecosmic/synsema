# Synsema Modules (`use` / `export`)

Your program doesn't have to live in one file. Synsema has **native modules**: split code across
several `.syn` files and share `task`, `type`, `let`, `enum` — and **`routes`** (whole groups of
HTTP routes a serve can `mount`) — between them. A `use` names a **local `.syn` file**
(`use "./x.syn"`) or, since v0.6.58, a **package by name** (`use "textkit"`) that the project file
`synsema.json` pins by hash and `synsema get` downloads — see *Packages* below. Never a URL in the
code, never FFI to other languages, nothing downloaded while a program runs, and a package only uses
the capabilities it declares **and** the program granted.

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
- **A module sees only its own names and the builtins (v0.6.50+, breaking).** A name the module
  does not define is looked up in the prelude (builtins, `pi`, `tau`, `e`, `inf`, `nan`, what the
  host registered), **never in the program that imports it** — as in Rust, OCaml, Go or Python (a
  Python module sees its globals and `builtins`, never `__main__`'s). A program that defines
  `task upper(x)` or `let upper be 3` does not change its modules' `upper(…)`. Same under `serve`,
  `parallel_map`, agents, `synsema test` and the REPL.
  ```
  -- lib.syn                          -- main.syn
  export task charge(n)               use "./lib.syn" as lib
      give n * RATE   -- not here!    let RATE be 2
                                      print(lib.charge(5))   -- error (v0.6.50+)
  ```
  → `Undefined variable: 'RATE' — 'RATE' is a name of the program that imports this module, and a
  module sees only its own names and the builtins: pass it as an argument or define it in the
  module`. A `set RATE to …` in the module gives `Cannot set undefined variable: 'RATE'. Use 'let'
  first. — 'RATE' is a name of the program …`. **Fix:** pass it (`export task charge(n, rate)` →
  `lib.charge(5, RATE)`) or move it into the module (`export let RATE be 2`; the program reads
  `lib.RATE`). Up to v0.6.49 the module read (and could `set`) the importer's globals, defined
  before or after the `use`.
- **What the program passes in keeps its own scope**: an argument, a callback or a lambda of the
  program runs with the program's names, also when the module keeps it and calls it later (from a
  request, a worker or an agent). A lambda of module `a` kept by module `b` closes over `a`,
  whatever the order of the `use` lines.

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
- **Under `serve`, a module that exports only data built by its tasks is still a module**
  (v0.6.50+): with `export let M be build()` (a map of callbacks), `m.M["price"](3)` in a route runs
  in the module and can call its private helpers (up to v0.6.49: `Undefined variable` under `serve`,
  fine under `run`). Its `export type`/`export enum` constructors work in a route too
  (`m.Point2(3)`, `m.Status.paid("x")`; up to v0.6.49 `Cannot call value of type text`).

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
  boundary is the **project root**, so `src/site/pages.syn` can `use "../core/i18n.syn"`; above the
  root → `module path escapes the project root` (from the entry file itself the message is
  `module path escapes the importing directory: '../lib/y.syn'`). Decided on absolute paths, so
  `cd proj && synsema run main.syn` is as safe as an absolute path. (≤ v0.6.19: `../` was blocked at
  the importing directory.)
  - **The project root (v0.6.58+, breaking)** is the folder of the nearest `synsema.json` at or above
    the entry file's folder; without one it is the entry file's folder, as before. So with
    `synsema.json` in `app/`, `app/scripts/x.syn` can `use "../lib/y.syn"` (before v0.6.58:
    `escapes the importing directory`), from `app/` (`synsema run scripts/x.syn`) or from
    `app/scripts/` (`synsema run x.syn`). `{}` is a valid `synsema.json` that only marks the root.
  - A module of an entry outside the current folder (`synsema run ../app/main.syn`) resolves against
    the entry's folder (v0.6.58 fix; before, against the current folder).
- **Modules are read once per process (v0.6.58+, breaking).** Before the first statement the engine
  reads every module the program can reach (also inside a task or a branch that never runs) and
  every worker, agent and `spawn` uses those bytes. A program that rewrites `m.syn` and loads it
  again in a `parallel_map` worker gets the first version; a running `serve` does not see a change
  to a module used inside a task (restart it). A `use` of a `.syn` that did not exist when the
  program started fails even if the file appears later:
  `module not found: ./late.syn (it did not exist when the program started)`. A `use` of a missing
  `.syn` inside a branch that never runs still works as before under `run` (`synsema check` reports
  it: `module not found: ./missing.syn`); only names and packages are checked before running.
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
- **A module with no tasks is one instance too (v0.6.51+):** `set m.X to 5` in the program is seen
  by another module that imports the same file (`a.X` is `5`), even when it only exports data; before
  v0.6.51 that module's map became a copy once it finished loading and `b` kept seeing `1`.
- **Cycles are detected:** a circular import gives a clear error (`circular import: …`), not a hang.
- **A module must not contain a `serve` block or a top-level `require`** — those belong to the entry
  file. (A per-task `require` *inside* a task is fine.)
- **`intent:`** is declared only by the entry file; modules don't override it.

## Trusted modules — `use "trusted:<name>"` (v0.6.46+)

A **trusted module** is a module the **host** loads, written by a person, that code the host does
not trust (a program written by a model) can only **call**. Each exported task runs with **its own**
`require`s, not the caller's: so a program under a ceiling without `declassify` cannot publish a
customer's data, but it can call `t.reply(customer, text)`, whose policy declassifies only that
customer's own address.

```sh
synsema run   --labels --cap-set stdout --trusted tools=./tools.syn app.syn
synsema test  --labels --cap-set stdout --trusted tools=./tools.syn app.test.syn
synsema run   … --trusted tools=./tools.syn --trusted-cap-set "stdout,declassify=customers" app.syn
synsema serve --labels --trusted tools=./tools.syn --trusted-cap-set "stdout,declassify=customers" app.syn   # v0.6.50+
synsema run   --trusted tools=./tools.syn --trusted-templates tools=./tools-templates app.syn         # v0.6.50+
```

```synsema
-- tools.syn — written by a person, loaded by the host
export task reply(customer, body)
    require declassify("customers")
    let dest be declassify(customer.email, "the reply goes to the customer's own address")
    give {"to": dest, "length": declassify(length(body), "the length of a reply is public")}
```

```synsema
-- app.syn — may be written by a model; it cannot declassify by itself under this ceiling
use "trusted:tools" as t
let c be private({"email": "ana@example.org", "name": "Ana"}, "customers")
print(t.reply(c, "your order shipped"))       -- {to: "ana@example.org", length: 18}
print(declassify(c.email, "direct"))          -- label_violation: declassify is not granted …
```

**Flags.**
- `--trusted <name>=<path>` (repeatable; on `synsema run`, `synsema test` and, v0.6.50+,
  `synsema serve`; `conform` refuses it): `name` is letters, digits, `_` or `-`; the path is
  relative to the working directory. Errors: `--trusted takes name=path (a name of letters, digits,
  '_' or '-'), e.g. --trusted tools=./tools.syn`, `--trusted tools: cannot read ./x.syn: …`,
  `--trusted tools: the name is given twice`.
- `--trusted-cap-set "<list>"`: the ceiling of **every** trusted module (same syntax as
  `--cap-set`). In wasm the options are `trusted: {tools: source}` (or `{tools: {source,
  templates}}`) and `trustedCeiling`.
- `--trusted-templates <name>=<dir>` (v0.6.50+, repeatable): the tool's templates — see *Templates
  of a trusted tool* below. Errors: `--trusted-templates tools: cannot read ./tpl: …`,
  `--trusted-templates x: there is no --trusted x=… to give them to`, and without any `--trusted`,
  `--trusted-cap-set and --trusted-templates go with the modules of --trusted; pass --trusted
  name=./file.syn too`.
- **Under `synsema serve` (v0.6.50+; up to v0.6.49 it refused the flag)** each worker gets the same
  tool the program loaded (its tasks, the tools it imports, its top-level state). The tool's top
  level runs **once**, at load, and **each request starts from the state the tool had then** (a
  call counter in the tool gives `1` in every request), like a file module. A `use "trusted:t"`
  inside a route gets that same tool. Everything below holds as under `run`.

**What a trusted task may do.**
- Its capabilities are its own `require`s **inside each exported task** (a top-level `require` in
  the module is a load error: `module 'trusted:tt' must not have a top-level 'require': each
  exported task declares its own`), bounded by `--trusted-cap-set` when the host gives one. Nothing
  comes from the caller: not its grants, not its `--cap-set`, not a `sandbox` around the call. A
  task that uses `net` without `require net("…")` fails like any program
  (`Capability not granted: net("…")`), even if the program has it; with a `--trusted-cap-set` that
  does not name it, `… declared but above the host ceiling`.
- **`declassify` in a trusted task is what the task declares, within `--trusted-cap-set`**
  (v0.6.49+): with `declassify=customers` a task with `require declassify("customers")` publishes
  `customers` and nothing else, and a task **without** that line publishes nothing (v0.6.46–v0.6.48
  the trusted ceiling alone allowed it). The refusal says ``This runs in a trusted module, which
  declares its capabilities per exported task: add `require declassify("<principal>")` to the
  exported task that runs it …``. While the module loads nothing is declared, not even by a task its
  top level calls; a non-exported helper grants nothing. Without a `--trusted-cap-set` a trusted
  task declassifies like a program without a ceiling — **any principal** — so give the trusted
  modules a ceiling.
- A trusted module can `use` another trusted module (`use "trusted:base" as base`); a file module
  (`use "./x.syn"`) is an error: `a trusted module imports only other trusted modules
  (\`use "trusted:…"\`), not './x.syn': a file module is read from disk, where the program can
  write it, and it would run with the tool's capabilities`.
- **A `require` in a task the module does not export grants nothing — and warns at load**
  (v0.6.50+, once per line, stderr): ``warning: trusted:tools:2: `require time` in task helper
  grants nothing: the module does not export helper, and a trusted task runs with what the exported
  task the program calls declares. Declare it in that exported task``. A task exposed in an export
  (directly, under another name, or inside a map or a list) counts as exported; one an exported
  task only calls does not.
- **A tool task held in an export runs in the tool's scope** (v0.6.50+): `export let M be {"f":
  helper}` → `t.M["f"]()` runs with the tool's `require` ∩ `--trusted-cap-set` (before: with the
  program's capabilities).
- Its audit entries carry `context: "trusted:tools"` and `file: "trusted:tools"`, and its
  `declassify` log lines say `at trusted:tools:<line>`.

**What the program can and cannot do with it.**
- **Arguments are data.** A task, a lambda or a builtin among them — also inside a list or an
  `ok(…)` — is an error, because it would run with the tool's capabilities:
  `trusted:tools.apply_it: a trusted tool takes data, not code — an argument holds a task, which
  would run with the tool's capabilities; pass the values it needs instead`.
- **It never sees the program's names**: a program that defines `task upper(x)` before or after the
  `use` does not change what the tool's `upper(...)` runs.
- **It cannot change the module**: `set t.config to …` (or `set t.config["limit"] to …`) changes
  only the program's own copy of an exported value; the tool's tasks and another `use` see the
  original. Replacing a task or adding a name is an error (v0.6.49+): `cannot replace the trusted
  task 'reply' from outside the module`, `trusted module has no export 'nuevo' — its names are the
  ones it exports, and the program cannot add one`.
- **It reaches workers and agents** (v0.6.50+, under `run`): `parallel_map(t.double, [1, 2, 3])` →
  `[2, 4, 6]`, and an agent's body can call `t.double(21)` (before: `Cannot call value of type
  nothing`, and the agent did not find the tool).
- **It cannot load one itself**: the name comes only from the host, and the program never sees the
  path. An unknown name is a load error: `no trusted module named 'tools': the host loads it
  (\`synsema run --trusted tools=./file.syn\`, or \`trusted: { tools: source }\` in wasm); a
  program cannot load one itself`. `print(t)` shows `{reply: builtin:trusted:tools.reply, …}`.
- **Its tasks take named arguments** (v0.6.49+; before, by position only): `t.reply(c, body =
  "hi")`, and they go to a model as they are: `tool_spec(t.reply, …)` lists the parameters (without
  types: `["customer", "body"]`) and `call_tool(t.reply, {"customer": c, "body": "hi"})` dispatches
  it, in the module's scope; typed parameters are checked, and a task or a lambda among the
  arguments is still an error. To give the model the **types**, wrap it in a program task: `task
  reply(customer: map, body: text)` → `give t.reply(customer, body)`. Note that `call(t.reply,
  {…})` with a private value in the argument map gives a **private** result even when the tool
  declassified what it returns; `call_tool` and the direct call keep the public result.

**Templates of a trusted tool (v0.6.50+).** A template is code (`{upper(x)}` calls a task), and one
read from the working directory could be written by the program. So a tool renders **only the
templates the host gives it**:
```
-- tools.syn; ./tools-templates/greeting.html holds <p>Hello {upper(name)}</p>
export task greeting(name)
    give render("greeting.html", {"name": name})
```
`synsema run --trusted tools=./tools.syn --trusted-templates tools=./tools-templates app.syn`, and
`t.greeting("ana").body` is `<p>Hello ANA</p>` (`render` gives `{status, body, content_type}`;
read the page as `.body` — `r["body"]` on a `render` result fails with `Cannot index into map`).
- The directory is read **at startup**, before the program runs. Inside the tool `render`,
  `include` and `layout` resolve only against that set — never the working directory or the
  program's bundle — and need no `file.read`. Symlinks are not followed.
- A template's free names are the **builtins**, not the program's (`{upper(x)}` is the builtin even
  if the program defines `task upper`). A private value in the data is written as its value and the
  HTML carries its label (labels.md).
- Without templates from the host: ``render: the trusted tool 'tools' has no templates
  ('greeting.html'): a template is code, … the host gives the tool its templates with
  `--trusted-templates tools=<dir>` (in wasm, `trusted: { tools: { source, templates } }`)``. A
  `render` with a literal name fails **when the tool loads**, before any data reaches it.
- wasm: `trusted: { tools: { source, templates: { "greeting.html": "<p>…</p>" } } }`; names are
  normalized as `render` looks them up, and two names for one template are an error
  (`trusted.tools.templates: './greeting.html' and another name are the same template
  (greeting.html)`).
- `synsema check --templates <dir> tools.syn` (v0.6.51+) validates each `render("literal.html")`
  (and its `include`/`layout`) against that folder, the way the tool reads the folder the host
  gives it with `--trusted-templates name=<dir>` → `OK: 1 statements parsed. 1 template(s)
  validated.` The tool's modules are still resolved from the file. Without the option `check`
  looks in the working directory, and a missing template says to pass it: `template validation
  failed for render("card.html"): template not found: card.html (render() reads templates from
  the current directory; if this file is a trusted tool, check it against the folder the host
  gives it: synsema check --templates <dir> tool.syn)`.
- The sealed receipt's `trusted` sha of a tool with templates covers source **and** templates, so
  `--replay` refuses a run whose template changed (observability.md).

**What it does not do yet** — each one is an error inside a trusted tool, naming the reason:
defining or spawning an agent, `parallel_map` (`parallel_map: a trusted tool cannot fan out yet —
its workers would run with the tool's capabilities next to the program's names; loop over the items
in the tool`), `cron_every`/`cron_after`, and a `use` of a file module. (`render` works since
v0.6.50, with the host's templates.) With trusted modules the **whole program runs on the
tree-walker**, without the bytecode VM (measured: a 3 M-iteration loop, 0.07 s → 0.8 s).

## Packages — `use "name"`, `synsema.json` and `synsema get` (v0.6.58+)

A **package** is someone else's code (a tree of `.syn` files and templates) published at a URL. The
program uses it **by name**; the project file `synsema.json` says where the name comes from and pins
it by hash; `synsema get` (and only `get`) downloads it into a cache. Running never touches the
network.

### In 30 seconds

`synsema.json`, next to the program (you write only the `url`):
```json
{
  "synsema": "0.6.58",
  "modules": {
    "textkit": {"url": "https://pkg.example.org/textkit/0.1.0/synsema.json"}
  }
}
```
```sh
synsema get              # downloads, checks, writes id/version/hash/requires, prints what each task asks for
synsema run main.syn
```
```synsema
use "textkit" as tk
print(tk.shout("hi"))
```
`synsema get` prints, per package, what each task declares, and writes the pins:
```
textkit 0.1.0 (tree-sha256:3872…), new
  task status: net("127.0.0.1")
https://pkg.example.org/base 0.1.0 (tree-sha256:1325…), new
  requires nothing
```
```json
{
  "synsema": "0.6.58",
  "modules": {
    "textkit": {
      "url": "https://pkg.example.org/textkit/0.1.0/synsema.json",
      "id": "https://pkg.example.org/textkit",
      "version": "0.1.0",
      "hash": "tree-sha256:3872035464255df87affa3cb6aec653197f168ec556065d2329d86e6d4dc7a2a",
      "requires": ["net(\"127.0.0.1\")"]
    }
  },
  "indirect": {
    "https://pkg.example.org/base": {
      "url": "https://pkg.example.org/base/0.1.0/synsema.json",
      "version": "0.1.0",
      "hash": "tree-sha256:1325896bc3ab3257b9f897548f1680258a84d9bd8f3f3488b0fd7cdc534de92f",
      "requires": []
    }
  }
}
```
Commit `synsema.json`: it is the lock file too (the hash fixes every byte; a PR diff shows a new
`requires` or a new `indirect` entry). Don't commit the cache.

### `use` — the three forms

| `use "…"` | what it is |
|---|---|
| `"./x.syn"`, `"../lib/y.syn"` | a file module, as before |
| `"textkit"` | a package by name: `^[a-z][a-z0-9_-]{0,63}$`, declared in `synsema.json` |
| `"trusted:tools"` | a tool the host loads (*Trusted modules* above) |

Anything else stops the program **before its first statement**:
- `use "https://reg.example.org/textkit/0.1.0/textkit.syn"` → `a module from a URL goes in synsema.json,
  not in the code: add {"modules": {"textkit": {"url": "https://reg.example.org/textkit/0.1.0/textkit.syn"}}},
  run synsema get, then use "textkit" as textkit`
- `use "Text/kit"` or `use "data.json"` → `not a module name (lowercase letters, digits, '-' and '_')
  nor a path to a .syn file`

`use "./textkit.syn"` and `use "textkit"` are two different modules, side by side.

### `synsema.json` — the project file

| key | who writes it | what it is |
|---|---|---|
| `synsema` | you (optional) | the **minimum engine**, three numbers: `"0.6.58"` |
| `modules.<name>.url` | you | where the package's index is (`https://…`; `http://` only to `127.0.0.1`, `::1`, `localhost`) |
| `modules.<name>.id`, `.version`, `.hash`, `.requires` | `synsema get` | the package's identity, its version, `tree-sha256:<64 hex>` of every byte, and the sorted union of its `require`s |
| `indirect.<id>` | only `synsema get` | each dependency of a dependency: `url`, `version`, `hash`, `requires` |

- **The project** is the folder of the nearest `synsema.json` at or above the entry file's folder
  (the search stops at the first one). It is the root for `../` (above), for a relative
  `SYNSEMA_MODULE_CACHE` and for `synsema build`. A program without one works as before (and cannot
  `use` a name). `synsema get` looks for it from the **current** folder upward.
- **Checked before anything runs, by every command** (`run`, `serve`, `test`, `check`, `build`,
  `code`, `openapi`, `get`); each stops everything:
  - `"synsema": "0.6.60"` on 0.6.58 → `synsema run: this project needs synsema >= 0.6.60; this is
    0.6.58: synsema update` (a lower minimum, or none, runs);
  - `"v0.6.58"` or `"0.6"` → `synsema.json: "synsema" is a minimum version like "0.6.58" (three
    numbers), not "v0.6.58"`;
  - an unknown key → `synsema.json: unknown key "module" (known: "synsema", "modules", "indirect"; a
    package also has "id", "version", "main", "files")`; in an entry → `get: synsema.json: module "x"
    has an unknown key "branch" (known: "url", "id", "version", "hash", "requires")`;
  - broken JSON → `synsema.json:2:14: key must be a string` (line and column);
  - a bad name → `get: synsema.json: "Bad" is not a module name (lowercase letters, digits, '-' and '_',
    starting with a letter, up to 64)`; an entry without `url` → `get: synsema.json: module "x" has no
    "url"`.
  An unrelated file called `synsema.json` above your program now matters: rename it, or move the
  program.
- **Ignored, with a warning on stderr** (the program runs as if there were none): a `synsema.json`
  right in the system temp folder — `ignoring synsema.json in C:\Users\me\AppData\Local\Temp: it is
  in the system temp directory`, always (`SYNSEMA_SAFE_PROJECT=*` or that folder does not change it).
  Keep projects in a subfolder of the temp folder, never at its root.
- `synsema init` writes `{"synsema": "<this version>", "modules": {}}` if there is no `synsema.json`;
  an existing one is never touched (no `.new` either).

### Nothing is downloaded when a program runs

Before the first statement (`run`, `serve`, `test`, `check`, `build`, `code`, `openapi`), the engine
resolves every name the program can reach — **also inside a branch or a task that never runs** —
reads every file of every package once, checks every hash and keeps the bytes; workers of `serve`
and `parallel_map`, agents and `spawn` use those same bytes. So nothing prints before one of these:

| error (before the first statement) | fix |
|---|---|
| `use "textkit": a module by name is declared in synsema.json, and there is none in <dir> or above; add {"modules": {"textkit": {"url": "…"}}} and run synsema get` | write `synsema.json` (or `synsema init`) |
| `use "textkit": a module by name is declared in synsema.json, and a program without a file has no synsema.json` | stdin / `-` / a source string: save it to a file in the project |
| `use "other": synsema.json (<dir>) has no module "other"; add it under "modules" and run synsema get` | add the entry |
| `use "textkit": module textkit has no hash yet: run synsema get (it needs the network)` | `synsema get` |
| `use "textkit": module textkit 0.1.0 is not downloaded: run synsema get (it needs the network)` | `synsema get` (another machine, a clean CI, another cache) |
| `use "memo": the cached files of memo (tree-sha256:701a…) no longer match their hash (changed on disk?); delete <cache>\tree-sha256-701a… and run synsema get` | delete that folder (`rm -rf` / `Remove-Item -Recurse` work) and `synsema get` — `get` alone repeats the error |
| `use "fmt" in report: the dependency https://pkg.example.org/fmt is not in synsema.json: run synsema get` | an `indirect` entry was removed: `synsema get` (it asks for `--accept`, below) |
| `module newer (0.1.0) needs synsema >= 0.6.99; this is 0.6.58: synsema update` | the package needs a newer engine |

`synsema check` gives the same errors (`Error: use "nope": …`), so CI catches them without running.

### `synsema get`

```
usage: synsema get [--update <name>] [--accept <name>@<hash>]... | --check
  (no flags)                fetch what is missing and write its hash
  --update <name>           fetch <name> again from its url and show what changed
  --accept <name>@<hash>    accept a change get showed (with the hash it printed)
  --check                   change nothing: fail if synsema.json and the cache do not match
```
- **No flags.** An entry without `hash` is downloaded: the index, then each file, each checked
  against its sha256 in the index; the package is validated (below), dependencies are resolved, and
  `id`, `version`, `hash`, `requires` and `indirect` are written (2 spaces, key order kept). An entry
  with `hash` that is in the cache is only verified — **no connection**, even if its `url` now serves
  something else (that is `--update`). With `hash` and not in the cache, it downloads and compares.
  Exit 0 and nothing printed for `"modules": {}`.
- **`--check`** — no network. Every entry has a hash, is in the cache, the cache matches, `requires`
  and `version` re-read from the cached tree match what is written, and the version selection gives
  the same `indirect` → `get --check: synsema.json matches the module cache (2 packages)`. Use it in
  CI after a PR. Failures: `get --check: memo 0.1.0 is not in the cache: run synsema get`;
  `get --check: memo: synsema.json says requires [] but tree-sha256:e9ef… requires
  net("evil.example.org"); run synsema get --update memo` (a PR that changed only the hash);
  `get --check: indirect has no https://pkg.example.org/fmt (the selection gives 0.3.1); run synsema get`.
  With another flag: `get: --check does not change anything; run it alone`.
- **`--update <name>`** fetches that entry again from its `url` and prints the change:
  `clock 0.1.0 → 0.2.0 (tree-sha256:b7c7…)`, or `…, unchanged`. If it needs nothing below, it writes.
  Unknown name → `get: --update nope: synsema.json has no module "nope"`.
- **Nothing that changes what runs is written silently.** `get` writes nothing and prints the
  command that accepts it, **with the hash**, when:
  1. the `requires` of an entry already written grow:
     `get: notes 0.2.0 now requires net("api.example.org") (0.1.0 required nothing); nothing was changed. To accept: synsema get --update notes --accept notes@tree-sha256:9b3f5add…`
  2. the version of an `id` already written changes (up or down):
     `get: https://pkg.example.org/fmt 0.3.0 → 0.3.1 because chart requires it (from https://pkg.example.org/chart/0.1.0/synsema.json); nothing was changed. To accept: synsema get --accept https://pkg.example.org/fmt@tree-sha256:8eba7858…`
  3. a package already there brings a new `id`:
     `get: chart 0.1.0 brings a new dependency https://pkg.example.org/fmt (requires nothing); nothing was changed. To accept: synsema get --accept chart@tree-sha256:4ff38a62…`
  4. a version is chosen above what an edge asked for, by another package (also in the first `get`):
     `get: https://pkg.example.org/fmt 0.3.1 is chosen because chart requires it (from …); report asked for 0.3.0; nothing was installed. To accept: synsema get --accept chart@tree-sha256:4ff38a62…`
  
  Run the printed command as is. `--accept <direct name>@<hash>` accepts everything that comes
  through that package; `--accept <id>@<hash>` accepts one `id`.
  Without the hash →
  `get: --accept needs the hash shown by get (--accept notes@tree-sha256:…)`. If what you accept
  resolves to another hash now (the registry changed between the two runs), nothing is written and
  the cases are printed again: `get: notes is now tree-sha256:9b3f…, not the one shown
  (tree-sha256:0000…); nothing was changed`. The first `get` of a package with none of these cases
  asks nothing.
- **The hash errors**, checked in this order (nothing is installed, `synsema.json` unchanged):

  | message | meaning / fix |
  |---|---|
  | `get: could not download notes from <url>: HTTP 404; nothing was installed` (or `<file>: HTTP 404`, `<file> does not match its sha256 in the index`, `synsema.json is not JSON…`, `more than 5 redirects`, the OS error of the connection) | a broken download; fix the URL or retry |
  | `get: the registry changed the content of notes 0.1.0 without changing its version (expected tree-sha256:74cb…, got tree-sha256:0551…): it may be tampering or a republication; nothing was installed. If you trust the change, remove the hash of notes in synsema.json and run synsema get again` | same version, other bytes |
  | `get: <url> now serves memo 0.2.0, but synsema.json pins memo 0.1.0 (tree-sha256:701a…); nothing was installed. To move to 0.2.0: synsema get --update memo` | the URL moved on (a `latest` URL) |
  | `get: notes: <url> serves tree-sha256:0551…, but synsema.json pins tree-sha256:74cb…; nothing was installed` | a hash written by hand, without `version` |
- **URLs** (checked before any connection): `get: tok: http:// is only allowed to this machine
  (127.0.0.1, ::1, localhost); use https://`; `get: tok: a URL with credentials is not supported`;
  `get: tok: the url has a dot segment or an encoded separator: <url>` (a `.`/`..` segment);
  `get: u: the url path has ';'; a package url uses only letters, digits, / and - . _ ~ ! $ & ' ( ) *
  + , = : @ (no %-escapes, no ;): <url>` (the same for `'%'`). Up to 5 redirects; a relative `Location`
  resolves against the URL that sent it; the package's files are fetched relative to the **final**
  URL of the index; a redirect to `http://` of another host → `get: textkit: <url> redirects to
  http://…; only https redirects are followed`.
- **Validation of a package** (nothing installed on any of these):
  - `get: topreq: require net("x.example") in m.syn:2 is outside a task; a package declares its capabilities inside its tasks` (also inside a top-level `when`)
  - `get: nonlit: require net(H) in task f is not a literal; a package declares its capabilities with literals so they can be reviewed`
  - `get: tst: require file.read("./**") in t.syn:2 is inside a test block; a package's tests do not declare capabilities`
  - `get: srv: m.syn:3 has a 'serve' block; a package does not serve, the program that uses it does`
  - `get: trs: use "trusted:tools" in m.syn: a package cannot use the host's trusted tools; the program passes it a callback instead`
  - `get: rnd: render("missing.html") in m.syn is not in files`
  - `get: dat: data.csv is neither a .syn file nor a template the package renders; data goes in a .syn literal`
  - `get: cb: the package says it is https://pkg.example.org/k/cb, but it was fetched from https://pkg.example.org/k/mirror/synsema.json; a package is fetched from under its id`
  - `get: loud: the package's synsema.json has no "id" (the URL prefix it is published under)`;
    `get: badver: "version" is three numbers like "0.1.0", not "1.0"`; `get: nomain: invalid path in
    files: "other.syn" (main is not in files)`; `get: upper: invalid path in files: "M.syn" (it differs
    from "m.syn" only in case)`; an unknown key in the index → the `unknown key` error above
  - a file that nests deeper than 1024 levels → `get: tok: h5000.syn nests deeper than 1024`
- **Limits** (constants, no knob): 256 files (`get: files257: the file list (257 files) is larger
  than 256 files`), 4 MiB per file (`get: bigfile: big.syn is larger than 4 MiB`), 32 MiB per package
  (`get: big9: the package is larger than 32 MiB`), 128 bytes per path (`get: longpath: the path
  "aaa….syn" is larger than 128 bytes`), 1024 packages in the graph (`get: the dependency graph is
  larger than 1024 packages`), 64 levels of dependencies (`get: the dependency depth is larger than
  64 levels`).
- Other errors: `get: there is no synsema.json in <dir> or above; write {"modules": {"tok": {"url":
  "https://…"}}} (synsema init writes one)`; `get: a and b are the same package
  (https://pkg.example.org/k/cb); keep one`; `get: unknown argument '--frobnicate' (synsema get
  [--update <name>] [--accept <name>@<hash>]... | --check)`.

### Dependencies of dependencies — minimal version selection

A package's index pins its own dependencies (`url`, `id`, `version`, `hash`). `get` builds the whole
graph and, **for each `id`, picks the highest version asked for anywhere** (Go's MVS): with `report`
asking `fmt` 0.3.0 and `chart` asking 0.3.1, both run with 0.3.1 (after the `--accept` of case 2 or 4
above). What the project does not name goes in `indirect`, keyed by `id`. A package never sees the
project's `synsema.json`: inside `report`, `use "fmt"` resolves through `report`'s own index to the
`id`, and the version is the one the project's selection wrote.

**The `id` is a URL prefix** the package declares (`"id": "https://pkg.example.org/textkit"`), and a
package is only accepted when its `url` (and every redirect) is under `id + "/"`. Only who can serve
files under that URL can publish that `id` — like a Go module path. A **mirror** works only for an
entry whose `hash` is already written (change the `url`, keep the `hash`). One limit: a code host that
serves a fork's commit under the original repository's URL (raw file hosts of git forges do) lets a
fork claim the original `id`; `get` still never lets it in silently (case 2 or 4 above). A package
with dependents is better published on a host you control.

### The cache

- `~/.synsema/modules/` (Windows: `%USERPROFILE%\.synsema\modules\`), or **`SYNSEMA_MODULE_CACHE`** —
  in the **process environment** (a `.env` line is not read for it). A relative value is relative to
  the project root, from any folder (`SYNSEMA_MODULE_CACHE=./vendor`). No home and no knob →
  `get: no home directory to keep modules in; set SYNSEMA_MODULE_CACHE`.
- One folder per package, `tree-sha256-<hex>/`, with its files **read-only**, and `index/` with the
  indexes `get --check` uses. Deleting a folder is safe (`rm -rf`, `Remove-Item -Recurse`): `get`
  downloads it again.

### Inside a package — it only uses what it declares, and only if the program granted it

Every task and lambda written in a package runs with **the package's `requires` (the union of every
`require` in it) ∩ what is in force** — the program's grants, the host ceiling, a `sandbox`, a
captoken — by any path: a direct call, a callback, a lambda it returned and the program calls later,
a `parallel_map` worker. Entering a package only subtracts.

| the package | the program | result |
|---|---|---|
| declares nothing, calls `http_get` | `require net("127.0.0.1:19010")` | `Capability not granted: net("127.0.0.1:19010") — the package pure does not declare it` |
| `require net("127.0.0.1:19010")` in a task | nothing | `Capability not granted: net("127.0.0.1:19010") — this is a permission, not a bug: add `require net("127.0.0.1:19010")` to the program's preamble …` |
| `require net(…)` in **any** of its tasks | the same grant | works — in **every** task and lambda of the package (the domain is the whole package, not each task) |
| declares nothing; the program passes `() => read_file("data.txt")` as a callback | `require file.read("./**")` | `Capability not granted: file_read("data.txt") — the package pure does not declare it` (the callback runs with the intersection) |

- A `require` in a package **does not grant anything**: it declares (what `get` writes in
  `requires`, what `--accept` guards). It goes inside a task, with literals (`get` refuses the rest,
  above); one inside a `when` in a task declares too. After a refusal inside the package the
  program keeps its own grants.
- `read_file` and friends inside a package resolve against the **current folder** (the user's data),
  with the attenuated permission: a package that declares `file.read("./**")` reads the program's
  `data.txt` when the program granted it.
- **Errors inside a package** (the code would run later or in another interpreter, outside the
  package's limits): `cron_after: not allowed inside the package guard — the task would run later
  without the package's limits` (the same for `cron_every`, also from a program callback the package
  calls); `agent 'Helper': a package cannot define or spawn agents` (an `agent` in the package, or a
  `spawn` from a program callback while the package runs). `approve … then done` in a package fails
  too: `approve … then done: "done" is not a task of the program (it is called by name with the
  decision, the message and the id)`.
- **Its exports are read-only** for the program: `set g.CONFIG["limit"] to 9`, `set g.CONFIG to {}`
  and `set g.limit to 1` → `set guard.CONFIG: a package's exports are read-only; its code is fixed by
  its hash` (unlike a file module, whose exported `let` you can write). `let c be g.CONFIG` is a copy
  you can change.
- `use "./lib/helpers.syn"` inside a package is relative to the importing file and **only** reaches
  files listed in its index (`module not found: ./lib/helpers.syn` otherwise); `../` past the
  package → `module path escapes the package: '../x.syn'`. A package cannot `use "trusted:…"`.
- Errors inside a package name its file as `pkg:tree-sha256-<hex>/<file>:line:col`.
- **Data** (a vocabulary, a table) goes as a literal in a `.syn` (`export let VOCAB be {…}`): it is
  hashed and loaded with the code. A data file in the package is refused by `get`.

### A package's templates are its own

`render`, `include` and `layout` written in a package resolve **only against the package's files**:
no `file.read`, never the disk or the current folder, even when the program has a file with the same
name. A package template sees the builtins and the package, never the program's names.
- `render("card.html", {"name": "ana"})` in the package → the package's `card.html`, while the
  program's own `render("card.html", …)` still reads the program's file.
- A computed name not in the package → `template not found: nope.html` (never the disk).
- `{ helper(1) }` in a package template, with `task helper` defined by the program →
  `helped.html:1:1: Undefined variable: 'helper' — 'helper' is a name of the program that imports this
  module, …`.
- A program template that does `{ layout "shell.html" }` of a package template →
  `template not found: shell.html`: the program does not see the package's files; the package
  exposes a task that renders.
- `get` refuses a literal `render("x.html")` whose file is not in the index (above).

### Publishing a package

A package is a folder served over HTTPS (any static host): the files, plus an **index** named
`synsema.json`:
```json
{
  "id": "https://pkg.example.org/loud",
  "version": "0.1.0",
  "main": "loud.syn",
  "files": [{"path": "loud.syn", "sha256": "7649…"}],
  "synsema": "0.6.58",
  "modules": {"base": {"url": "https://pkg.example.org/base/0.1.0/synsema.json",
                        "id": "https://pkg.example.org/base", "version": "0.1.0", "hash": "tree-sha256:1325…"}}
}
```
- `id` (required): the URL prefix it is published under; serve each version under it
  (`https://pkg.example.org/loud/0.1.0/synsema.json`). `version`: three numbers. `main`: the `.syn`
  that `use "loud"` loads; it must be in `files`. `files`: **every** file with the sha256 (hex) of
  its bytes — `.syn` files and the templates the package renders. A bad path is
  `get: p: invalid path in files: "<path>" (<rule>)`: `(relative, '/' between segments of letters,
  digits, '.', '_' and '-')` for `../x.syn` or `a\b.syn`, `(a name Windows reserves)` for `COM1.syn`,
  `(the index is not one of the files)` for `synsema.json`, `(it differs from "m.syn" only in case)`.
  `modules`: its dependencies, each with `hash` (`get: tok: its dependency bpe has no hash; a package
  pins its dependencies`). `synsema`: the minimum engine.
- The package's `hash` is `tree-sha256:` over the index and every file (Go's `h1:`), so changing a
  byte means a new version.
- **Workflow:** develop the package as a project (its folder's `synsema.json` holds `modules` with
  the `url`s; `synsema get` there pins them; `use "./loud.syn"` from a scratch file there tries it),
  then write the index. This program writes it, keeping `synsema` and `modules`:
```synsema
-- make_index.syn: synsema run make_index.syn -- <folder> <id> <version> <main>
require file.read("./**")
require file.write("./**")

task files_of(dir, prefix)
    let out be []
    each e in list_dir(dir)
        let rel be when prefix == "" then e.name otherwise prefix + "/" + e.name
        when e.is_dir
            set out to out + files_of(dir + "/" + e.name, rel)
        otherwise when rel != "synsema.json"
            let sha be decode(sha256(read_file_bytes(dir + "/" + e.name)), "hex")
            set out to append(out, {"path": rel, "sha256": sha})
    give out

let a be args()
let path be a[0] + "/synsema.json"
let old be when file_exists(path) then json_decode(read_file(path)) otherwise {}
let index be {"id": a[1], "version": a[2], "main": a[3], "files": files_of(a[0], "")}
when "synsema" in old
    set index["synsema"] to old["synsema"]
when "modules" in old
    let deps be {}
    each name in old["modules"]
        let d be old["modules"][name]
        set deps[name] to {"url": d["url"], "id": d["id"], "version": d["version"], "hash": d["hash"]}
    set index["modules"] to deps
write_file(path, json_encode(index))
print("wrote " + path + " with " + text(length(index.files)) + " files")
```
  `synsema run make_index.syn -- loud/0.1.0 https://pkg.example.org/loud 0.1.0 loud.syn` →
  `wrote loud/0.1.0/synsema.json with 1 files`. Run it after the last edit (a stale sha256 is
  `get: could not download … does not match its sha256 in the index`), then upload the folder.
- Tools: `synsema code sha --json main.syn` lists the packages a program reaches (`name`, `id`,
  `version`, `hash`, `main` as `pkg:tree-sha256-…/<file>`); packages do not enter `program_sha`.

### What packages do not do

- No central registry, no search, no version ranges: a `url` names one version (or a moving URL you
  update with `--update`), the `hash` pins it.
- Nothing is fetched by `run`/`serve`/`test`, ever; only `synsema get` uses the network.
- No signature of the publisher yet: the trust is the `id` (who serves under that URL) plus the hash
  and the `--accept` gate.
- A package cannot serve, define agents, schedule, or use trusted tools (above).

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
- **`module textkit 0.1.0 is not downloaded: run synsema get`** on a fresh machine or in CI: the
  pins travel in `synsema.json`, the bytes do not. Run `synsema get` once (network), then
  `synsema get --check` (no network) to prove the cache matches. A program never downloads.
- **`Capability not granted: … — the package pure does not declare it`**: the program granted it,
  the package did not declare it. Nothing in the program can widen a package; use a version that
  declares it (`synsema get --update`, which shows the new `requires` and asks for `--accept`).
- **A `.syn` you generate at run time and then `use`** fails (`it did not exist when the program
  started`): modules are read before the first statement (v0.6.58+). Write the file in an earlier
  run.
- **`Undefined variable: 'X' — 'X' is a name of the program that imports this module …`** (v0.6.50+):
  the module used a global of the file that imports it. Pass it as an argument or define it in the
  module (see *How it works*).
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
