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
print(declassify(text(label_of(only_bank)), "probe"))   -- [bank]
```

These five names (the four plus `print`) are **protected**: a program cannot bind them to
something callable, because redefining one would silently un-label its own sources and mislead the
audit listing. Binding one to a plain value is fine — they are soft keywords.

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
