# Information-flow labels (`private` / `declassify`)

**What it is.** A second wall, next to capabilities. Capabilities answer *may this program touch
the network at all?*; labels answer *may **this value** leave?* You mark a value as belonging to a
principal, and the engine tracks it through every operation — arithmetic, text, field reads,
`json_encode`, hashes, and the branches taken because of it — and refuses to let it reach a public
sink unless you say, in writing and on the record, why it may be published.

**When it is on.** Off by default: `synsema run app.syn` behaves exactly as it always has, down to
the step counter. It is on with `--labels` (also on `test`, `serve`, `conform`), always on under
`serve --attested`, and always on inside a guest adapter (Vela). Write programs that work either
way: with labels off, `private(…)` **raises the moment it is called** — `private: labels are off; run
with --labels or serve --attested` — so a program that needs the second wall cannot quietly run
without it. Note *called*, not loaded: `synsema check` passes, and a `private(…)` inside a branch
that never runs never fires. If the program must refuse to start without labels, call one at the
top.

**When you want it.** A confidential deployment (TEE/enclave) where the operator runs the code but
must not read the data; a multi-tenant service that must not cross tenants; anything where "we are
careful" is not an acceptable answer.

## The four builtins

```synsema
let balance be private(1200, "app")        -- mark: this belongs to the principal "app"
let doubled be balance * 2                 -- private(app) — every operation propagates
print(label_of(doubled))                   -- [private(app)]  ← see below
print(is_private(doubled))                 -- private(app)    ← see below
let code be declassify("insufficient", "the outcome code is public on-chain")
print(code)                                -- insufficient
```

- `private(value, "principal")` — mark a value. The principal is a **text literal written at the
  call**: a computed principal is refused (it would be a channel of its own). Over a list or map
  it makes a **private copy**, so a pre-existing public alias keeps seeing the public original.
- `declassify(value, "reason")` — publish it, on the record. The reason is mandatory and public;
  every `declassify` is logged with its source line and listed by `synsema code check --json`
  before anything runs, which is what an auditor reads.
- `declassify(value, "reason", [...])` — narrow instead of publishing. The third argument must be
  a **subset of what the value is already private to**, because `declassify` may only narrow:
  a value private to `["app", "bank"]` can come out private to `["bank"]` alone, but asking a
  value private to `"app"` for `["bank"]` is *widening* and the engine refuses it by name
  (`cannot widen a label — [bank] is not a subset of what this value is private to`).
- `label_of(v)` → the list of principals; `is_private(v)` → bool. **Both answers are as private
  as what you asked about**, which is why the example above prints them redacted: if they came
  back public they would be an oracle — one bit per question, and the branch you take on the
  answer would be a public branch on private data. Use them to *decide* inside the program, not
  to report.

Narrowing, in one example:

```synsema
let joint be private(private(500, "app"), "bank")   -- private to both
let only_bank be declassify(joint, "the bank settles it", ["bank"])
print(declassify(text(label_of(only_bank)), "probe"))   -- ["bank"]
```

These five names (the four plus `print`) are **protected**: a program cannot bind them to
something callable, because redefining one would silently un-label its own sources and mislead the
audit listing. Binding one to a plain value is fine — they are soft keywords.

**`declassify` and `private` are called by their name, nowhere else (v0.6.46+, breaking).** Reading
either one as a value is a **load error** — the program does not start, not even its first line:

```text
let d be declassify                -- an alias
let xs be [declassify]             -- a list entry
let m be {"k": declassify}         -- a map entry
f(declassify, x)                   -- an argument
task g()
    give private                   -- a returned value
call(declassify, {"value": x})     -- also through call()
let m be {private: 1}              -- a BARE key evaluates the name, so this is one too
```

```
Runtime error: app.syn:1:10: 'declassify' is read as a value here (an alias, a list or map entry,
an argument): it can only be called by its name, `declassify(…)`, so that every call is in the
review (`synsema code check`)
```

Why: before v0.6.46 every one of those forms published for real while `synsema code check --json`
listed none of them, so the review missed the call. Now every `declassify` is a call the inventory
sees. Fixes: call it by name (`declassify(x, "why")`; the pipe `x |> declassify("why")` is a call by
name too and still works); for a map key, quote it (`{"private": 1}` — a bare key is evaluated, and
v0.6.45 printed `{builtin:private: 1}`). A program that **binds the name to a value** still loads
(`let private be 5`, a parameter called `private`): the name is then that value. The error fires
with or without `--labels` (`synsema run`, `synsema test`, `synsema code check`); plain
`synsema check` (the parse check) does not report it.

## `declassify` is a capability: the program declares it, the host bounds it (v0.6.46+, v0.6.49+)

`declassify` is the one place private data leaves, so it works like `require net`: under a ceiling
the **program** declares what it publishes (`require declassify("customers")`) and the **host's
ceiling** has to allow it too (`declassify=customers`). Think of it like `unsafe` in your own Rust
crate: explicit, with its mandatory reason, listed in full by `synsema code check --json`.

| How the program runs (with `--labels`) | What `declassify` may remove |
|---|---|
| no ceiling (plain `run`/`test`/`serve`) | any principal — granted by the runtime, `require` or not |
| `--cap-set …` without a `declassify` item | **nothing** |
| `--cap-set "stdout,declassify=customers"` + `require declassify("customers")` | `customers` only |
| `--cap-set "stdout,declassify=customers"` **without** the `require` | **nothing** (v0.6.49+; v0.6.46–v0.6.48 the ceiling alone allowed it) |
| `--cap-set "stdout,declassify=cust*"` + `require declassify("customers")` | `customers` (a `require declassify("cust*")` needs a glob in the ceiling) |
| `--cap-set "stdout,declassify"` or `declassify=*` | what the program declares — a bare `require declassify` too, with a warning at start |
| a scoped ceiling + a **bare** `require declassify` | **refused whole** (wider than the ceiling, as `require net` under `net=api.x.com`) |
| `--sandbox`, `--deterministic` | nothing (they never grant it) |
| inside a `sandbox` block | nothing |
| inside `sandbox under {"declassify": "customers"}` | `customers` (globs work), still within the host ceiling and the program's `require` |
| wasm: `ceiling: "stdout,declassify=customers"` | the same as `--cap-set` |

```sh
synsema run --labels --cap-set "stdout,declassify=customers" app.syn
```

```synsema
require declassify("customers")                  -- what this program publishes (v0.6.49+ under a ceiling)
let c be private(3, "customers")
sandbox under {"declassify": "customers"}       -- delegate it to this block only
    print(declassify(c, "the count is public"))
```

**Where the `require` goes** (v0.6.49+): in the program's preamble; in an **agent's** body (an agent
declares its own capabilities, the preamble does not reach it; a `parallel_map` inside the agent
inherits the agent's); in a **trusted task** (each exported task declares its own, within
`--trusted-cap-set`; nothing is declared while the module loads, not even by a task its top level
calls — move the `declassify` into an exported task the program calls). A non-exported helper
grants nothing. The refusal says which of these applies.

- **What is checked is what the call removes.** `declassify(v, "why")` removes every principal of
  `v`; the narrowing form `declassify(v, "why", ["bank"])` removes the rest, so with
  `declassify=app` a value private to `["app", "bank"]` can be narrowed to `["bank"]`. A
  `declassify` of a value that is not private removes nothing and always passes.
- **Breaking:** a program that declassifies and runs with `--labels` under `--cap-set`, `--sandbox`
  or `--deterministic` stops at the `declassify` (v0.6.46+). Migrate by adding
  `declassify=<principal>` to the `--cap-set` (for `--sandbox`/`--deterministic`, switch to an
  explicit `--cap-set`, e.g. `--cap-set "stdout,time,declassify=app"`) **and**, since v0.6.49,
  `require declassify("<principal>")` to the program (or the agent, or the trusted task).
- **A refusal is a `label_violation`, and `try`/`recover` cannot catch it** (whether it passes
  depends on the real label of the value — a catchable refusal would be an oracle). Like every label
  violation, it ends the run and withholds the buffered output. **Under a ceiling the error does not
  say which `declassify` it was** (see [What a cut shows, and to whom](#what-a-cut-shows-and-to-whom-v0647));
  without a ceiling, as the owner's own run, it does:

```
Runtime error: app.syn:3:17: label_violation: declassify is not granted for what this value is
private to (customers,others). With a ceiling the program declares what it publishes (`require
declassify("<principal>")` in the program's preamble, or in the body of the agent that runs this
code: an agent declares its own, also for its `parallel_map`) and the host's ceiling has to allow
it too (`--cap-set declassify=<principal>`); inside a `sandbox` only a `sandbox under` that
delegates `declassify` allows it
```

  The set in parentheses is the program's **declared** set (every principal it marks anywhere),
  never the value's real label — the real one would tell which value it was. The
  `[INF] declassify: … (from […] to […])` log line names the declared set too (v0.6.49+: `from
  principals the program does not declare` when it declares none).
- **Without `--labels` nothing is checked**: `private(…)` raises (labels are off) and `declassify`
  is the identity.
- **`require declassify("customers")`** grants it under a ceiling (v0.6.49+; v0.6.46–v0.6.48 only
  the ceiling decided, and v0.6.45 ignored the line). Without a ceiling it changes nothing:
  `declassify` is granted, like `unsafe` in your own crate. `synsema code check` suggests the line
  for a `declassify` without it. A **bare** `require declassify` prints a warning at start:
  `synsema: warning: bare \`require declassify\` permits publishing data private to ANY principal;
  scope it with \`require declassify("principal")\` (the principal the call removes)`.
- The Vela guest runs its app under `stdout,declassify=app` (its only principal is `app`), so the
  app declares `require declassify("app")` (v0.6.49+; see [guests.md](guests.md)).

## What a cut shows, and to whom (v0.6.47+)

A cut by the flow checker (any `label_violation`) used to tell the program and the log **where** it
fell, and that was itself a channel: a private value can choose which of N sites fails. Now who runs
the program decides what it sees:

| How it runs (with labels) | What the program and its output show | Where the detail goes |
|---|---|---|
| `run`/`test` **without** a ceiling (native or the wasip1 binary) | the full error, with file, line and what failed (the owner's own run) | the same, on stderr |
| `run --cap-set …`, `--sandbox`, `--deterministic`, `--trusted` | a fixed error with **no location** | only the sealed receipt with `--auditor` |
| `serve --labels` / `serve --attested` | a 500 with the fixed text (below) | the server's stderr line has the same fixed text; the detail only in the sealed receipt with `--auditor` |
| embeddable WebAssembly (`run`/`handle` with `labels: true`) | `errors` has the fixed text | `operator_detail` in the result (the `log` hook does not get it) |
| the Vela guest | `{"error": "label_violation"}` | the Executor's log gets one fixed line ([guests.md](guests.md)) |

In every case the output printed before the cut is replaced by one line:

```
private(labels): the run was stopped by the flow checker; its output is withheld because the NUMBER of lines before the stop depends on private data
```

and the fixed error, under a ceiling, under `serve` and in WebAssembly, is the same for every site:

```
Runtime error: label_violation: the flow checker stopped the run (private to customers); what failed, where and how to fix it go to the operator, not to the program
```

(`customers` is the program's **declared** set of principals, a constant of the program — never the
label of the value that failed.) Measured on v0.6.47: the same program, `run --labels` prints
`cut.syn:4:10: label_violation: print called under private control flow (pc = [customers]) …`, and
`run --labels --cap-set stdout` prints the fixed line above. **To debug a cut, run it yourself
without a ceiling**, or read `operator_detail` in WebAssembly; the program cannot see the detail.

- **A cut in an agent cuts the run it belongs to**: under `run`, the whole program (it ends with
  the same fixed error; without a ceiling the detail starts with `agent Leaky_0: …`); under
  `serve --labels`, the request or tick that spawned it. From then on every sink of that run fails.
- **`serve --labels`: each request, cron tick and socket handler is its own run.** Its stdout and
  stderr are held and written when it ends, or replaced by the fixed line if it was cut; agent
  output is not written. The server says so at startup:
  `[serve] labels: request and cron output is logged when each one ends, and not at all if a label cut stopped it; agent output is not logged (which agent stopped would be the private data)`.
  For a live log while developing, run without `--labels`. `agents()` and `agent_stop` see only the
  agents of the same run.
- **`serve --labels` and the blackboard and signals**: a run (the request, or the preamble, with all
  its agents) is **committed once**, when all of it has ended without a cut, and **undone entirely**
  if any part is cut, including what its agents wrote after the request answered. What other runs
  read while it was open, and signals already consumed, stay (as with any effect before a cut).

## What `receipt()` publishes after private data (v0.6.46+)

With `--labels`, `receipt()` no longer carries what depended on a private value (each was a leak
with the program counter public and no `label_violation`):

- `steps` is `nothing` once a private value was seen (it was the raw count: a loop over a private
  `n` gave its size). Before the first private value it is the number.
- `declassified[]` lists `{reason, from, to, line}`, and **`from` is the declared set**, not the
  value's real label (`["a","b","c"]` even when the value was private to `a` and `c` only). A
  `declassify` **inside a private branch** is left out of the list, and its `[INF] declassify` log
  line is not written — how many there were told which branch ran.
- `inputs`: a read inside a private branch (`read_file`, `env`, …) is refused as a sink
  (`read_file called under private control flow …`), so it never reaches the list.

## `read_line`, `flush` and the order of the output (v0.6.46+)

- **The prompt of `read_line(prompt)` is a public sink, like `print`.** A private prompt, or a
  prompt inside a private branch, is a `label_violation`: inside a branch, `read_line prompt under
  private control flow (pc = [a]) …`; a private prompt outside one (v0.6.49+), `the read_line prompt
  is private (to a) and the prompt goes to stdout, which is public. Ask with a public prompt, or
  declassify(<the prompt>, "<why it may be published>")`. `read_line()`
  without a prompt inside a private branch is allowed.
- **With `--labels`, `flush()` and `read_line` do not write the pending output live.** `print`
  already kept it until the end; now the prompts come out first and the printed lines at the end
  (`print("one"); flush(); read_line("> ")` shows `> one`). Without `--labels` nothing changes.

## Private data to a model the host chose (v0.6.46+)

Any private value in `reason`, `analyze`, `decide`, `generate`, `judge`, `llm_step` or
`llm_stream` was a `label_violation`. Now it may go to a model **the host** allows, per principal
and per provider, and the answer stays private:

```sh
synsema run --labels --cap-set "stdout,llm=customers@api.anthropic.com,declassify=customers" app.syn
```

```synsema
require llm("customers")                     -- whose data this program may send
let note be private("Ana Perez, order 3141", "customers")
let summary be reason about "Summarize the note in one line" with context = note
print(summary)                               -- private(customers): the answer carries the label
```

The full rules (`@local`, `@*`, `judge=`, `llm_step`, `llm_stream`, audit, lineage, what it does not
give) are in [llm.md](llm.md) § Private data to a model.

## Trusted tools: code a person wrote, called by code a model wrote (v0.6.46+)

Under a ceiling without `declassify`, a program written by a model cannot publish anything private.
The host can still give it **tools** a person wrote, whose own policy declassifies — `synsema run
--labels --cap-set stdout --trusted tools=./tools.syn app.syn`, then `use "trusted:tools" as t` in
the program. See [modules.md](modules.md) § Trusted modules.

## What propagates, and what a sink is

Every operation carries the union of its operands' labels. Branching on a private value puts the
branch under that label, so what it assigns and returns comes out private too.

A **public sink** is anything with an effect outside the program: the HTTP response, streams,
files, the network, databases, memory, processes, `parallel_map`, and **stdout** (`print`, `show`,
`log`). A sink refuses two things, before the effect happens:

1. a labelled value in any argument, at any depth;
2. **the call itself**, when it sits under a branch that depended on private data.

The second one surprises people, so it is worth stating plainly: the *number* of lines you print
is not redactable even when each value is. One `print` per iteration of a loop that branches on a
secret spells the secret out by line count.

Three more places the branch itself is the leak (v0.6.45+):

- **`require` in a private branch is a `label_violation`** — what is granted cannot depend on
  private data (a later public `try random_int(...)` published which way the branch went). Also a
  `require` whose scope is a private value, and a `require` inside a `task` (the tool's ceiling under
  `call_tool`) whose scope is private or whose task is defined in a private branch:
  the error reads "label_violation: \`require net\` runs in a branch decided by a private value
  (or its scope is private); what is granted cannot depend on private data — declare it at the top
  of the program …".
  Declare capabilities at the top of the program, with literal scopes.
- **Operations that write the audit log do not run in a private branch**: `sign` and the signing
  builtins, `spend`, `reveal`, the wallet operations fail with `label_violation` and write nothing
  (whether their audit entry existed told the operator which way the branch went). Decide with a
  public value, or `declassify` the condition first (that leaves its own record).
- **A capability check inside a private branch leaves no audit entry** (`--audit` and the wasm
  `audit`): how many entries there were would tell the branch or how many times a private loop ran.

Two more that catch people, because the redaction happens **at the sink** and nowhere else:

- **`text(v)` does not sanitise.** It returns the real content, still private. Passing a value
  through `text` does not make it safe to hand to anything — `is_private(text(v))` is true, and
  `declassify(text(v), …)` gives you the value back in full.
- **A private value inside a concatenation takes the whole string with it.**
  `print("balance: " + text(v))` prints `private(app)`, not `balance: private(app)`: the prefix
  is part of a private text now, and the sink replaces the whole thing.

```synsema
let secret be private(42, "app")
let n be 0
when secret > 10
    set n to 1
```

```
label_violation: cannot assign to 'n' (public) under private control flow (pc = [app]); declare it
private first (let n be private(<its initial value>, "app")) or declassify(<the value>, "<why it
may be published>") at this site
```

The fix is in the message, and it is usually the first one: make the destination private
(`let n be private(0, "app")`). Declassify when you have decided that the value is publishable and
can say why.

## Early exits, and how far a label reaches

Leaving a block early from a private branch is itself information, so it colours what follows —
and how far depends on where the jump lands:

| jump | how far the label reaches |
|---|---|
| `give` / `raise` | to the end of the task body: reaching the next line already means the branch did not fire |
| `stop` | to the end of **its loop**: after the loop both paths converge again |

So this compiles — the log line is public, constant, and printed exactly once either way:

```synsema
let floor_price be private(50, "venue")
let orders be [80, 70, 60, 40, 90]
task settle(orders, floor_price)
    each o in orders
        when o < floor_price
            stop
    log "settle: " + text(length(orders)) + " orders considered"
```

and this does not, because the counter would hold the secret:

```synsema
let secret be private(181, "app")
let counter be 0
each i in range(0, 256)
    when secret == i
        stop
    set counter to counter + 1
```

A `stop` may not **leave the task it is written in** under private control flow: it would break
the *caller's* loop, and whether a call does that is a question the engine cannot answer before
the loop has already run. Write the `stop` in the loop it belongs to, and `give` a value to decide
with.

## Errors

An error that was **born under a private branch, or caused by private data**, is not catchable:
`try`/`recover` re-propagates it and `assert_error` does not absorb it. Whether an operation failed
is exactly the bit the labels exist to hide — `xs[private_index]`, `1 / (secret - i)` — and a
`recover` that swallowed it would let the loop before it leave the secret in a public variable.
An error independent of the private data is caught as always; its message comes out labelled with
whatever the `try` body touched.

Which leaves a real question: **how do you validate untrusted input, then?** An enclave receives
payloads from anyone, and `try`/`recover` is no longer the answer. The answer is not to raise at
all — the operations that parse external input have a **total** form that returns a fallback:

```synsema
let d be json_decode(payload, nothing)     -- no error, so no bit
when d == nothing
    set status to private("malformed payload", "app")

let n be number(field, nothing)            -- same for the conversion
```

With no error there is no bit, and the program validates without exceptions. Without the second
argument both still raise, and the message names the fallback.

**What an error says when it leaves the process.** The text becomes `private(app)` — and **nothing
else**: no `file:line:column`. If the secret chooses which of N sites fails, the location is
log₂(N) bits, so it does not cross the boundary (the local CLI still prints it: there the host is
whoever wrote the `private(…)`). A run the checker stopped does not hand over its buffered output
either: the number of lines before the stop depends on the private data.

**And the redaction text itself is constant.** `private(app)` names the principals the *program
declares*, never the ones of that particular value. It used to name the value's own, and that was
a channel of its own: `print(xs[private_index])` answered `private(app,p0)` or `private(app,p1)`
depending on which entry was selected, so a table of 256 entries spelled a byte out in one line —
with the run succeeding and the static review green. In a multi-tenant deployment the principal
*is* the tenant, so printing a redacted value told the operator whose data it was.

**A label violation ends the whole `synsema test --labels` run**, with a single outcome naming the
violation — not a `✗` on that block with the suite carrying on. A per-block verdict would be
*catching the enforcement itself*: eight blocks each probing one bit, and the column of ✓/✗ spells
the byte. An ordinary failure — a failed assertion, an error — is still a per-block verdict, as
always.

## `steps()` and the cost of a run

`steps()` is one step per AST node, so after a loop whose condition depended on a secret it *is*
the secret with arithmetic on top. It comes out labelled with everything the run has touched, and
`run --format json` / `run --attest` report `"steps": null` for such a run. Before the first
private value it is a plain public number. To publish it afterwards, say so:

```synsema
let cost be declassify(steps(), "the step count is published as a cost metric")
```

## Reviewing a program before it runs

```
synsema code check app.syn --json
```

lists every `declassify` with its file, line, reason, target labels and whether the value is a
source-level constant. That listing is the review: a program with no `declassify` publishes
nothing private, and every line of the listing is a decision somebody made and wrote down.

```json
{"ok": true, "files": 1, "errors": [], "warnings": [],
 "declassify": [
   {"file": "app.syn", "line": 2, "column": 20, "reason": "the count is public", "to": null, "constant": false},
   {"file": "app.syn", "line": 3, "column": 20, "reason": "doubled", "to": [], "constant": false}]}
```

`to` is `null` for the two-argument form (publish) and the list for the narrowing form. Since
v0.6.46 the inventory is **complete** — `declassify` can only be called by its name, so there is no
call it cannot see — and the `declassify_static_only` field is gone (a tool that read it must stop).
A program that reads `declassify` as a value gives `"ok": false` with the load error in `errors`
and an empty `declassify` list. When the program declassifies without any `require declassify`,
`warnings` carries `top-level needs capability \`declassify\` but the program never requires it`.

## Limits, stated

- **Termination is one bit per *run*, and a server run is one *request*.** A run the checker
  stopped tells an observer that it stopped. Under `synsema run` that is one bit and the program
  is over. Under `serve` — and under a guest, where every transaction is a run — the caller
  chooses how many runs to make, so it is one bit **per request, without a ceiling**: eight public
  HTTP requests recover a value by binary search. That is the honest statement of the limit, and
  it is the mode that matters in an attested deployment. If a request's outcome must not depend
  on private data, do not let a private branch decide whether it fails.
- **Progress.** Effects the program already performed *before* the stop — a `write_file` per
  iteration — did happen. The engine withholds the buffered output and rolls back what the request
  wrote to the shared `state_*` store, because both live in its own memory; a file or an HTTP call
  it cannot undo. Do not put public effects in a loop that branches on private data.
- **Timing and resource use** are not modelled at all.
- **Audit in private branches.** Since v0.6.45 audit-writing operations refuse to run there and
  capability checks there are not logged. Since v0.6.46 a host can designate an auditor
  (`synsema run --labels --auditor <X25519 public key> --receipt <path>`): then `reveal`, `sign` and
  the wallet operations do run in a private branch and their audit line goes into a sealed receipt
  only the auditor opens ([attestation.md](attestation.md)). Without an auditor they are still
  refused. An LLM or judge operation under a private branch is refused **before** the capability
  check, so it no longer leaves a "granted llm" entry in `--audit` either.
- **Crossing into another interpreter** (`parallel_map`, `run_program`, cron, the bus, the swarm)
  is a sink: a labelled argument is refused, before any worker starts. That is a **deliberate
  fail-closed decision, not an impossibility** — the channel between interpreters does carry
  labels (it is what keeps the `serve` global snapshot from de-labelling itself), so making
  `parallel_map` label-aware is a matter of specifying what a worker may do with a private value
  and what its result means, not of plumbing. Until that is specified it refuses, because the
  alternative it replaced was worse: the worker used to receive the value already stripped and
  did the effect in the clear while the result came back labelled, so the leak looked tracked.

## See also

- [attestation.md](attestation.md) — the other half of confidential computing: proving WHICH code
  answered (`serve --attested`, `run --attest`, `attestation_verify`), and the deterministic
  DP noise (`laplace_noise`/`gaussian_noise`) you publish an aggregate with
- [capabilities.md](capabilities.md) — the other wall: `require`, ceilings, `sandbox`, `attest`
- [guests.md](guests.md) — the guest adapter, where labels are always on and the sinks are the chain
- [observability.md](observability.md) — `steps()` and the rest of the instrumentation
