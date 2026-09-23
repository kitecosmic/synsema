# Synsema Security

## Zero access by default
Nothing works without declaring capabilities.

## Capability types
`net`, `file`, `file.read`, `file.write`, `exec`, `env`, `time`, `random`, `stdout`, `stdin`, `llm`, `judge` (v0.6.25+ — the `judge` block, see [judge.md](judge.md)), `db`, `serve`, `secret`, `reveal`, `sign`, `wallet`, `spend`, `memory`, `sandbox_run` (v0.6.14+ — `run_program`), `attest` (ask the platform for an attestation document). In `--cap-set`, `none` = an empty ceiling.

`serve(PORT)` allows binding an HTTP server to that port — see [serve.md](serve.md).

`env("NAME")`, `secret("NAME")` and `reveal("NAME")` gate config and secrets — see [secrets.md](secrets.md). All three are scoped by **name/label** (or a `NAME_*` prefix): `reveal("NAME")` can only reveal the secret whose name (`secret("NAME")`) or label (`as_secret(v,"label")`) matches, and every `reveal()` is written to a persistent audit log (**granted or denied**). Bare `require reveal` (coarse, any secret) still works for compat but **warns**. Separately, `as_secret(value, label?)` seals a **runtime** value as a `secret` and is **pure — no `require`** (see [secrets.md](secrets.md)).

`sign("KEY_NAME")` gates blockchain signing (`secp256k1_sign`/`ed25519_sign`/`schnorr_sign`) — the most dangerous operation (it authorizes moving value), so it is **deny-by-default** (never ambient), scoped to the key secret's **name/label**, and writes a persistent audit entry (granted or denied) that never contains the key. Denied inside `sandbox`. Bare `require sign` (any key) warns. The host can additionally cap **how many** signatures each key makes per process: `SYNSEMA_SIGN_CEILING="HOT_KEY:100"` — signature N+1 fails with a catchable error and a `denied_by=ceiling` audit entry; without the variable, behavior is unchanged. See [stdlib.md](stdlib.md) (Blockchain).

`wallet("NAME")` gates creating **custody** — generating/deriving/importing key material (`mnemonic_generate`, `mnemonic_to_seed`, `hd_derive`, `algorand_mnemonic*`, `keystore_import`/`keystore_export`, `mnemonic_from_entropy`/`_to_entropy`). Distinct from `sign`: `wallet` creates keys, `sign` moves value — an agent can derive addresses without being able to spend. Deny-by-default (never ambient), scoped to the **source secret's name** (or the new secret's label when generating), audited in `wallet.log` (granted or denied, never the material), denied inside `sandbox`. Bare `require wallet` (any) warns. WebSocket (`ws_connect`) needs no new capability — it reuses `net(host)`. So does **Web Push** (v0.6.15+): `push_send` is gated by `net(<host of the subscription endpoint>)` — one `require net(...)` per push service (`fcm.googleapis.com` and `jmt17.google.com` for Chrome, `*.notify.windows.com`, `updates.push.services.mozilla.com`, `web.push.apple.com` — exact hosts, never `*.google.com`) — and `push_vapid_keys()` by `random` (it creates secret material, like `token()`); the VAPID private key is accepted only as a `secret`.

`spend("UNIT")` gates `spend(amount, unit, reason)` — the audited declaration of an **external spend** (the actual payment call is the program's own `fetch`/tool; `spend` writes the forensic ledger entry BEFORE it and enforces the host ceiling). Deny-by-default **always** (never auto-granted, even under `run`), scoped by **unit** — any unit the host works in, no currency is privileged (`"EUR"`, `"ETH"`, `"bbl"`, `"kWh"`, `"credits"`; exact name or a trailing-`*` prefix like `secret`), audited fail-loud in `spend.log` (no written entry → no approved spend). Denied inside `sandbox`; a tool that doesn't declare it can't spend via `call_tool` even if the program can. Bare `require spend` (any unit) warns. The host caps totals per process with `SYNSEMA_SPEND_CEILING="EUR:500,ETH:0.1,bbl:100"`, and per authenticated agent with `SYNSEMA_SPEND_CEILING_PER_IDENTITY="agent-1=EUR:50"` — a breach of any of them is a **hard catchable error** (`try`/`recover`): after it, do NOT proceed with the payment call. See [builtins.md](builtins.md) and [secrets.md](secrets.md) (audit). LLM **tokens** have their own per-process ceiling, `SYNSEMA_LLM_BUDGET` (process environment or `.env`): at the ceiling the LLM ops **degrade** to a `[llm budget exceeded: …]` marker instead of erroring — see [llm.md](llm.md).

`memory("NAME")` gates the **whole persistent-state family** — memory (`remember`/`recall`/`forget_memory`/`memory_summary`), owner rules (`add_rule`/`check_rules`/`get_rules`) and progress (`create_progress`/…/`resume_point`). The declared name **IS the identity**: state lives in `<program-dir>/.synsema/state/<NAME>.db`, keyed by the name, not the filename. Deny-by-default **even under `run`** (it writes files — never ambient); without the declaration the builtins fail with the exact line to add and **no file is created**. One name per program; bare `require memory` is a parse error (no name = no identity). Denied inside `sandbox`; `call_tool` intersects it; `--cap-set "memory=shop-*"` scopes by prefix. See [memory.md](memory.md). The **host** relocates that directory with `SYNSEMA_STATE_DIR` (process environment, not `.env`): the `.db` is created there and nothing is written under the program dir — mount a volume there and keep the code read-only (verified v0.6.19).

## Declaring capabilities
```
require net("api.example.com")
require net("*.example.com")        -- wildcard
require file("/data/*")             -- read AND write under /data/
require file.read("./logs/*")       -- read-only (least-privilege)
require file.write("./out/*")       -- write-only
require exec("ffmpeg")
require env("API_KEY")
require secret("STRIPE_API_KEY")    -- read as an opaque, redacted secret
require secret("APP_*")             -- name prefix: APP_DB, APP_KEY, … (only a trailing *)
require reveal("STRIPE_API_KEY")    -- enable reveal() for THAT secret only (loud + audited; scoped by name/label)
require time
require llm                         -- enable LLM ops (reason/decide/analyze/generate)
require judge                       -- enable the `judge` block (System One judgments); NOT granted by `llm`
require serve(8080)                 -- bind an HTTP server to this port
require sign("HOT_KEY")             -- enable signing with THAT key (deny-by-default + audited)
require wallet                      -- enable creating custody (mnemonics/HD/keystore); scope with wallet("NAME")
require spend("USD")                -- enable spend(amount, "USD", reason) (deny-by-default + audited ledger)
require db("./store.db")            -- open a SQLite database (scope = file path)
require db("postgres://localhost/appdb")  -- Postgres (scope = canonical URL)
require db("mysql://localhost/appdb")     -- MySQL (scope = canonical URL)
require db("mongodb://localhost/appdb")   -- MongoDB (scope = canonical URL)
require db("redis://localhost")           -- Redis (scope = canonical URL; redis://host:6379 → redis://host)
require db("*")                     -- any database (file or remote); bare `require db` = same
require memory("support-agent")     -- persistent agent state (remember/rules/progress); the name IS the .db identity
```

`require` in the program body grants the capability for real. This is NOT just a declaration — it enables the operation.

## The `judge` capability (v0.6.25+)

The `judge` block ([judge.md](judge.md)) needs `require judge`. It is **its own** capability — `require llm`
does not grant it and vice versa — because classifying and generating are different rights: a program
that may judge cannot exfiltrate through free text or be talked into writing. Same ergonomics as `llm`
otherwise: auto-granted in plain `run`/`conform`, required under `serve` and in secure mode
(`Capability not granted: judge`), emptied inside `sandbox`, denied under `--deterministic` (network
I/O), always offline in a wasm guest. Coarse, no scope: the host is fixed by the runtime
(`SYNSEMA_JUDGE_BASE_URL`), never by the program. `--cap-set judge` = may judge, may not call the LLM.
With `SYNSEMA_JUDGE_DECIDE=1` (v0.6.26+) every `decide` is served by the judge and therefore needs
this capability too — under `serve`, a `decide` without `require judge` fails naming the knob.

## The `llm` capability

The LLM operations — `reason`, `decide`, `analyze`, `generate` — and the tool-calling primitive
`llm_step` are gated like every other side-effecting operation. They require the `llm` capability:

```synsema
require llm
let summary be generate "a summary" given report
```

- In **secure mode** (`serve`, the secure runtime) an LLM op without `require llm` fails with
  `Capability not granted: llm`. So you can audit a program's LLM use by reading its `require` lines.
- In plain **`run`/`conform`** (the non-secure dev mode) `llm` is **auto-granted** for convenience —
  exactly like `stdout` and `time` — so quick scripts don't need to declare it.
- Inside a `sandbox` the capability is stripped like any other: an LLM op inside a `sandbox` is
  **denied** even if it was granted outside.

For agent tool-calling, `llm` only gates the *decision* (`llm_step`); dispatch each chosen tool with
`call_tool`, which runs it under **only its declared capabilities** (∩ the program's) — see
[Per-tool least-privilege](#per-tool-least-privilege-call_tool) below and the safe loop in
[llm.md](llm.md).

## Intent (descriptive)

```synsema
intent: "Process customer orders and generate reports"
```

The `intent:` is a **human-readable description** of what the program is for. It is used for:
- Auditing (shown in `--audit`)
- LLM context (every reasoning call sees the program's purpose)
- Documentation

**The intent does NOT authorize or block actions.** Security is enforced *only* by capabilities (`require`). This is deliberate: the language has exactly ONE explicit authorization model, so behavior is predictable. You can write the intent in any language — it is never parsed for security.

To restrict what the program can do, use `require` with precise scopes. Anything not declared fails with a clear, actionable `Capability not granted` error — there is no guessing and no silent permissive fallback.

- The intent **freezes** after execution starts: a prompt injection cannot redeclare a broader intent (redeclaring a frozen intent is an error).

> Earlier versions tried to infer allowed action categories by scanning the intent prose for verb keywords, with a permissive fallback when nothing matched. That was unpredictable and language-dependent, so it was removed. Use `require` to declare permissions.

## Per-tool least-privilege (`call_tool`)

A plain task call runs with the program's **ambient** capabilities — a task's own `require` lines are
declarations, not an automatic sandbox. To run a task under **least-privilege** (e.g. dispatching a
model-chosen tool), use `call_tool`:

```synsema
task fetch_orders()
    require net("api.shop.com")          -- the tool's declared capability
    give fetch("https://api.shop.com/orders")

let result be call_tool(fetch_orders, nothing)
```

- Under `call_tool` the task runs with ONLY the capabilities it declared (its top-level `require`)
  **intersected** with the program's: it cannot use a capability it did not declare, even if the
  program granted it, and it cannot exceed the program.
- The restricted scope is created when `call_tool` dispatches and restored when it returns (also on
  error); nested calls keep the restriction.
- A `require` **nested** inside the tool body (under `when`/`if`/…) is a **no-op** — a tool cannot
  self-grant a capability to escape its scope. (The top-of-body `require` IS the declaration.)
- `print` and pure computation always work; declare `time`/`random`/etc. to use them.

**Two sides — the program must also GRANT.** `call_tool` runs the tool with `declared ∩ program`. So a
tool that declares `require file.write("out/*")` still fails with `Capability not granted` if the
**program** didn't grant `file`. Wire both: the tool **declares** (top of body, literal scope) and the
**entry grants** the superset.

> **Under `serve` (secure mode) this bites:** a per-task `require` does **not** grant ambient capability
> — it's only the **declaration** `call_tool` intersects. The real grant goes at the **top-level of the
> `serve` file**. (In `run` the per-task `require` suffices, but declare-in-tool + grant-in-entry works
> in both.) Symptom: a file/exec tool under serve returns `Capability not granted` — you're missing the
> `require` in the **entry**.

**Directory-tree scope:** to read/write files under a dir, grant **both** `file("dir")` (the dir node,
for `list_dir`) **and** `file("dir/*")` (the files inside). Scopes are **literal** — `require exec(cmd)`
with a variable does not parse; use `require exec` for any command, `exec("git")` for one.
exec` gates both `run` (one-shot) and `proc_spawn` (live process, v0.6.7+; also with
pty: true`, v0.6.8+ — a pseudo-terminal grants no extra OS power, so there is no separate
capability) with the same scope; `/openapi.json` lists it under `x-synsema-capabilities` for
routes that call either. `file.read` also gates `watch(path)` (v0.6.9+): watching a tree is
reading it, same scope shape as `list_dir` (`file("dir")` + `file("dir/*")`).

Plain `call`/normal invocation does NOT isolate — use `call_tool` for untrusted, model-chosen tools.

## Sandbox blocks
```synsema
sandbox
    -- code here has NO capabilities (fully isolated): net/file/time/random/db/secret
    -- are all DENIED inside, even if the program granted them. `require` inside is a
    -- no-op (can't re-grant to escape). `print` works (not gated); restored on exit.
    let result be compute(untrusted_data)

-- Sandbox can also be an EXPRESSION (returns the value of its body):
let enriched be sandbox transform(untrusted_data)   -- isolated AND returns a value
```
Use it to run untrusted/enriching logic that must NOT touch the network, disk, or any
capability — only pure computation in, value out.

**`sandbox under <caps>` (v0.6.28+) — a least-privilege block.** The body runs under a **delegated
ceiling** instead of with nothing: what the map lists stays (still gated by the program's own
`require` and by the host ceiling), what it doesn't list is denied, and `require` inside is still a
no-op. The map is either a literal `{capability: scope | [scopes] | nothing}` or the map returned
by `captoken_verify` — then the block runs under **that token**, exactly like a `serve` request does:

```synsema
require net("api.example.com")
require db("orders")

sandbox under {"db": "orders"}                 -- this step may touch the DB, not the network
    let rows be sql(db, "select …")

let agent be captoken_verify(token, secret("ROOT_KEY"))
sandbox under agent                            -- run this step with the caller's authority only
    give summarize(fetch(url))                 -- fetch works only if the token carries net(url's host)
```

Needs an indented body on the next line. Process-local capabilities (`stdout`, `stdin`, `time`,
`random`) are not delegable and error at the block (`… is process-local`); a nested `sandbox under`
stacks (every ceiling on the stack must cover the use). A denial inside is `Capability not granted:
X — outside the ceiling of the enclosing sandbox under block …` (catchable), or, when the block runs
under a verified token, the token's own message.

## Host capability ceiling (`--sandbox` / `--cap-set`) — v0.4.3+

`require`/`sandbox`/`call_tool` all assume you **trust** the code. When you don't — running an
LLM-generated `.syn`, a user's plugin, a public playground — the **host** imposes a ceiling the code
can't exceed, no matter what it declares:

```
synsema run  --sandbox program.syn                 # ceiling = [stdout, time] only
synsema run  --cap-set "stdout,db=:memory:" program.syn
synsema test --cap-set "stdout,time,random,secret,file=scratch_*" program.syn
```

- **`--sandbox`** ≡ `--cap-set "stdout,time"` — compute + `print`, nothing else.
- **`--cap-set "<list>"`** — comma-separated `name` or `name=scope`. Semantics: `caps_effective ⊆
  require ∩ ceiling`. A `require net("*")` under `--cap-set "net=api.mock"` grants **nothing** (the
  ceiling doesn't cover the wildcard) — the code never rises above the ceiling.
- Applies to `run`, `test`, `conform` (v0.6.14+ — before, `conform` silently ignored the ceiling) and `serve`. `--sandbox` and `--cap-set` are mutually exclusive; an unknown capability name errors, and (v0.6.14+) an **unknown `--flag` is a usage error (exit 2)**, not silently ignored.
- **`--cap-set none`** = an empty ceiling (nothing, not even `stdout`). **`stdout` is a real capability under a ceiling** (v0.6.14+): a `--cap-set` without `stdout` denies output at the first `print`/`show`/`log` (`--sandbox` includes it; no ceiling = output free). The audit gained two `reason`s: `auto-granted by the runtime` (an ambient grant that succeeded now leaves a trace, `origin: runtime`) and `bundled asset (part of the program)` (a `synsema build` read).
- **`--deterministic`** (v0.6.20+, `run`/`test`/`build`) = `--profile pure` **plus** a ceiling of `stdout` only — no `time`, no `random` (`now()`/`random()` fail with `Capability not granted`): the same program gives the same output. An alias, so combining it with `--sandbox`/`--cap-set`/`--profile native` is exit 2 (`--deterministic already fixes the ceiling …`). `build` bakes it.
- **The pure profile is a second, independent wall** (`--profile native|pure`, v0.6.14+): under `pure`, every filesystem/exec/socket/db/cron builtin fails with `<name>: not available in the pure profile — <why>`, regardless of the ceiling. `fetch`/`http_*` with `net`, agents, `run_program` and `remember` (in-memory) stay. `serve --profile pure` is a usage error. See [deploy.md](deploy.md) and the ceiling below compose.
- **`attest` capability**: `require attest` lets `attest(opts)` / `attest_key(purpose)` ask the
  **platform** for an attestation document binding `report_data` to the code that is running (AWS
  Nitro, TDX/SEV-SNP via configfs-tsm, dstack, plus a `mock` driver for CI that is never
  auto-detected). It is I/O against a device or socket of the host, so it is deny-by-default like
  every other capability, and it is **absent from every packaged ceiling**: neither `--sandbox`
  nor the deterministic one list it, so `--deterministic` denies it on its own. The whole family
  (`attest`, `attest_key`, `attestation_document`, `attestation_key`, `attestation_verify`),
  `serve --attested` and `run --attest` are in [attestation.md](attestation.md).

- **`sandbox_run` capability** (v0.6.14+): `require sandbox_run` lets a program run *another* Synsema program with `run_program(source, {ceiling, profile, env, timeout})` in a child process under a ceiling that is the intersection with its own — the child can never exceed the parent (asking for more is trimmed, not fatal, and the parent's audit records it as `above parent ceiling`). See [builtins.md](builtins.md) and [processes.md](processes.md).
- **`render` of a disk template reads a file:** the top-level `render(path)` needs `require file.read("<path>")` (v0.6.14+; nested `include`/`layout` and bundled templates don't).
- **The error names who can fix it — and says it is a permission, not a bug.** Not declared →
  `Capability not granted: X — this is a permission, not a bug: add `require X` to the program's preamble
  (or to the importing file, when this code runs in a module)` (v0.6.28+: the exact line to add is in the
  message; an agent reading it must not go looking for another cause). Declared but above the host ceiling →
  `… declared but above the host ceiling (--sandbox/--cap-set). The program cannot fix this; the host must
  widen the ceiling` — do NOT re-add a `require` you already have (that loop is exactly what this message
  prevents). Declared but not delegated by the caller's captoken (v0.6.28+, see the delegated ceiling
  below) → `… denied by the delegated ceiling of token <id>: the program declares it, but the caller's token
  does not grant it` — the **caller** must present a token that carries it; under `serve` the client only
  sees a 403 `insufficient permissions`. The audit trail carries the same split: `reason` = `No matching grant
  found` / `above host ceiling (--sandbox/--cap-set)` / `above delegated ceiling (token <id>)` / `above sandbox
  ceiling (sandbox under)` / `Explicitly denied by …`, and `origin` = `program` (a `require` or a call of the
  program) vs `runtime` (an ambient grant the host tried — `time`/`llm` under a ceiling — the program never
  asked). Same for `sign`/`spend`/`wallet`/`reveal`.
- It only ever **removes**, never widens. Auto-grants (`stdout`/`time`/`llm`) are filtered too (so
  `--sandbox` won't spend your LLM key). It propagates to **agents** and **`parallel_map` workers** — a
  spawned agent can't exceed the ceiling either.
- **The delegated ceiling — the token IS the ceiling (v0.6.28+).** A verified captoken is not advisory
  any more. Three places apply it, all on the same `CapabilitySet` machinery, stacked *under* the host
  ceiling (`caps_effective ⊆ require ∩ host ceiling ∩ token`): under **`serve`**, the `caps` of the map
  your `auth with` task returns become the request's ceiling (see [serve.md](serve.md) § Agent identity);
  **`run_program(src, {"ceiling": verified})`** runs the child under the token; **`sandbox under verified`**
  runs a block under it in-process. `caps` are **transferable authority** (`net`, `file*`, `exec`, `env`, `db`,
  `llm`, `judge`, `serve`, `secret`, `reveal`, `sign`, `wallet`, `spend`, `memory`, `sandbox_run`, `attest`):
  what the token does not list is denied even though the program declares it, `llm` and `judge` included.
  **Process-local** capabilities (`stdout`, `stdin`, `time`, `random`) are never in a token — nobody delegates
  another process's clock — and a token cannot even be minted with them; the host ceiling and the program
  govern them as always. Two caveats constrain *execution* instead: `deterministic: true` (the holder runs
  without clock or entropy, like `--deterministic`) and `llm_tokens: N` (a delegated LLM budget, metered
  against the token's `id` beside `SYNSEMA_LLM_BUDGET_PER_IDENTITY`). **The identity travels with the
  ceiling**: agents spawned from a request, `parallel_map` workers and `run_program` children run on behalf
  of the same subject, under the same delegated ceiling and budgets; a cron tick runs as `cron:<job>`; `run`
  runs as the operator (`SYNSEMA_IDENTITY`, optional).
- **The audit is a receipt.** `receipt()` turns the unit's audit (every capability asked, granted
  or denied, with reason and source), its tokens, spend and `declassify` log into a Verifiable
  Credential; `receipt({"sign": key, ...})` signs it (W3C Data Integrity). Derived, never
  written by the program — see builtins.md § Identity documents.
- **Scope `file`/`db`/`memory`:** a bare `--cap-set "…,file"` lets the code read any absolute path; use a prefix
  like `file=scratch_*` (or `db=:memory:`, `memory=shop-*`) so it can only touch what you intend. A ceiling
  without `memory` denies the persistent-state family entirely — and creates no `.db` file at all.

This is what makes "run code you don't trust" safe at the language level. For a public deploy, compose
it with an OS sandbox/container (defense in depth).

## Invariants
```
invariant: balance > 0              -- checked at runtime, error if false
```

## Audit — `--audit json|<path>|fd:N` (v0.6.14+)

```bash
synsema run  --audit json        program.syn   # one JSON line per check, on stderr
synsema run  --audit ./audit.jsonl program.syn # … to a file
synsema run  --audit fd:3        program.syn   # … to a file descriptor (Unix only; Windows → exit 2)
synsema run  --audit unix:/run/audit.sock program.syn   # … to a Unix socket (v0.6.20+; Unix only; fails loud if nobody listens)
SYNSEMA_AUDIT=json ./app                       # v0.6.20+: the same values from the ENVIRON — no flag; also a synsema build binary
synsema build app.syn -o app --audit json      # v0.6.20+: bake the sink into the binary (flag > SYNSEMA_AUDIT)
```

One line per capability check: `{ts, context, capability, granted, source, reason, origin, file, line}`
(`context` = which CapabilitySet: `program`/`agent`/`request`/`worker`/`sandbox:`/`tool:`; `origin` =
`program` | `runtime`; `source` = the builtin or `ceiling`/`ambient`/`secret-builtin`). A final line
`{"summary": {"granted": N, "denied": M, "exit": code}}`. **Secret VALUES never appear** — scopes are
names. Works on `run`/`test`/`conform`/`serve`. It is the same audit the wasm `run()` returns as
`r.audit` (plus `ts`/`context`/`file`/`line`); `run_program` returns its child's audit as `r["audit"]`.

## Capability scoping rules
- `deny` overrides `grant`
- Sandbox does NOT inherit parent capabilities
- `call_tool` runs a task with ONLY its declared capabilities (∩ the program's); a plain call uses the program's ambient capabilities
- Wildcard: `net("*.example.com")` covers all subdomains
- Path glob: `file("/data/*")` covers all files in /data/. `file` grants **read+write**; use `file.read(scope)` / `file.write(scope)` for least-privilege. Path scope is **faithful**: a `..` escape (`file("./data/*")` + `read_file("./data/../../etc/passwd")`) normalizes outside the scope and is denied. `require file` / `file("*")` cover the whole disk. `~/` expands to the home dir in scopes AND paths (v0.6.20+: `file.read("~/.config/app/*")`; `~user/` unsupported). `cwd()` needs `file.read(".")` — the grant of `list_dir(".")` (`./*`, `*` cover it; `./data/*` does not). `delete_*` and `zip_extract`/`tar_extract` need `file.write` on **every** path they remove/write.
- Name prefix: `secret("APP_*")` / `env("APP_*")` / `reveal("APP_*")` covers `APP_DB`, `APP_KEY`, … (only a trailing `*`)
- `db` scope: a **file path** for SQLite; a **canonical URL** for remote engines (Postgres/MySQL/MongoDB/Redis) —
  `scheme://host/db` with **no credentials, port, or query** (so `mysql://user:pw@localhost:3306/appdb?ssl-mode=REQUIRED`
  is gated by `db("mysql://localhost/appdb")`, and `mongodb://u:p@host:27017/appdb?authSource=admin` by
  `db("mongodb://host/appdb")`). A path scope never covers a URL and vice-versa (distinct canonical forms).
  **Redis db-index gotcha:** `redis://host:6379` canonicalizes to `redis://host` (no `/0`), but
  `redis://host:6379/0` to `redis://host/0` — different scopes; match the grant to the `db_open` form.
  Host/db globbing works: `db("postgres://localhost/*")` covers any DB on that host. The gate is the same
  for SQL and Mongo (`mongo_*` ops check `db` exactly like `sql`).
