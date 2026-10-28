# Synsema Observability

> **What's real today:** `log` and the error diagnostics (below) are fully functional. `trace`,
> `measure` and `checkpoint` are **decorative markers** — they run their body but the
> timing/snapshot instrumentation is a stub in the current runtime. `trace`/`measure` take a
> **literal** name; `checkpoint` takes an **expression** (`checkpoint "step_" + text(i)`) but is
> still decorative — it does NOT persist anything. For real **logging** use `log` (also an
> expression); for **crash-resume / step tracking** use the progress builtins (NOT `checkpoint`).

## Logging (real)
```synsema
log "Processing order " + order_id        -- `log` takes a full expression
```

## Logging under `serve` (and where it shows up)

Under `serve`, `log` and `print` go to the **server's terminal**, prefixed:
- `log "msg"` → `[serve] [LOG] msg`
- `print(x)`  → `[serve] x`

There is **no automatic access log** — `serve` does **not** log requests for you, so the terminal
is quiet by default (this surprises people and makes dev hard). **Add a `log` in your handlers** to
see traffic while developing:

```synsema
serve on 8080
    route "GET /items/:id"
        log "GET /items/" + params.id      -- shows as: [serve] [LOG] GET /items/42
        give get_item(params.id)
```

(A spawned agent's `log`/`print` also appear, prefixed `[AgentName]`.) Under `conform`/`conform --swarm` that live `[main]`/`[agent]` echo goes to **stderr** — stdout carries ONLY the final JSON (parse-safe). Under plain `run`, `print`
is written **immediately**, line by line (v0.6.29+; older engines buffered it until the program ended — `flush()` there).

## Tracing / Measurement / Checkpoints (decorative markers — literal name)
```
trace "payment_processing"
    process_payment(order)

measure "db_query"
    run_query(sql)

checkpoint "before_payment"
```
`trace`/`measure` names are literal labels; `checkpoint` accepts an expression
(`checkpoint step`). But ALL of these are decorative — they do NOT persist state; `checkpoint`
does not snapshot variables for resume.

## Crash-resume / step tracking (the real mechanism — see builtins.md / memory.md)
For "ingest done, died in validation, resume there", use the **progress** builtins, not
`checkpoint` (they need the declared memory: `require memory("<name>")` at the top —
[memory.md](memory.md)):
```synsema
require memory("import-agent")
create_progress("import", ["ingest", "validate", "load"])
start_step("import", "ingest")
complete_step("import", "ingest", result)
-- after a restart:
let where be resume_point("import")        -- the step to resume from
```

## Step counter — `steps()` (v0.6.20+)
`steps()` → statements executed so far in this program. Counts nodes, not time → deterministic
(same program, same number); no capability; every profile. `synsema run --format json` reports it
as `steps` next to `llm_tokens`. Use it as a cost for metering/tests/fuel-style limits:
```synsema
let before be steps()
process(batch)
log "cost: " + text(steps() - before) + " steps"
```

**Under information-flow labels** (`--labels`, `serve --attested`) `steps()` carries the union of
everything private the run has touched, and the host reports `"steps": null` in `--format json`
and in the `--attest` document once the run touched private data. That is not caution: the counter
is one step per AST node, so it is *linear in what the program walked*, and after a loop whose
condition depended on a secret it **is** the secret with a multiplication and an addition on top —
`(steps() - base - 24) / 4` reconstructed a private scalar exactly, in one line. Before the first
private value it is a plain public number and works as it always did. To publish it afterwards,
say so:
```synsema
let cost be declassify(steps(), "the step count is published as a cost metric")
```
which is recorded in the declassify log and listed by `synsema code check --json`.

## Capability audit without a flag (v0.6.20+)
`SYNSEMA_AUDIT=json|<path>|fd:N|unix:<path>` in the process environ turns the audit stream on — the way
a container does it, and it also works inside a `synsema build` binary; `synsema build --audit …`
bakes the sink; the `--audit` flag wins over the variable. `unix:` (a socket somebody listens on;
loud failure if nobody does) and `fd:N` are Unix only (Windows → exit 2). See [capabilities.md](capabilities.md).

## Outputs — what the run WROTE (`receipt().credentialSubject.outputs`, v0.6.46+)
Every `write_file`, `append_file`, `edit_file`, `zip_extract`, `tar_extract`, in order, as
`{source, what, sha256, bytes, encoding}` — the same fields as an `inputs` (lineage) entry:
- `what` = the path **as the program wrote it** (`"./out/a.txt"`); an extraction = destination as
  written + the entry's name (`"./out/zx/z/one.txt"`), one entry per extracted file.
- `sha256` = hex, no `0x`, of the bytes that hit the disk; `encoding` = `"text"` (text, UTF-8) or
  `"bytes"` (bytes, and every extracted entry). `write_file` = whole content; **`append_file` = only
  the appended chunk**; `edit_file` = the file **as it was left**.
- `parallel_map`: the workers' reads and writes are included, **in item order**, also when an item
  fails (what they did until then stays). Under `serve`: the request's own (and `inputs` too —
  before v0.6.46 `inputs` also held earlier requests of the same worker, maybe another user's).
- Cap 10 000 like `inputs`; `outputs_truncated: true` / `inputs_truncated: true` appear **only when an
  entry was dropped** (absent otherwise; before v0.6.46 `inputs_truncated` was `true` at exactly 10 000).
- **No salt** on the hash (as `inputs`): a short value written after a `declassify` (a PIN) can be
  guessed by hashing candidates — don't write short secrets in a run whose receipt you publish.
- With labels, a write in a private context is refused (sink) → never in `outputs`. An
  `append_file` that fails half-way can leave unlisted bytes. `print`/`log` are not outputs. The file
  `edit_file` reads first IS an input (v0.6.49+; `source: "edit_file"`, the file before the edit).
  `lineage()` lists inputs only.
```synsema
require file.write("./out/**")

write_file("./out/model.txt", "weights v1")
append_file("./out/model.txt", " +bias")
let outs be receipt().credentialSubject.outputs
print(outs[0].source + " " + outs[0].what + " " + text(outs[0].bytes))   -- write_file ./out/model.txt 10
print(outs[1].source + " " + text(outs[1].bytes))                        -- append_file 6
print("0x" + outs[0].sha256 == hex(sha256(bytes("weights v1", "utf8"))))  -- true
```

## Sealed receipts for an auditor — `--auditor` (v0.6.46+)
**Why:** with `--labels`, `reveal`/`sign`/wallet ops in a branch decided by a private value are a
`label_violation` (whether the audit line exists tells the branch). With an auditor the HOST names
(X25519 public key), they run and their capability check + audit line go into an **HPKE envelope**
(RFC 9180, X25519 / HKDF-SHA256 / AES-128-GCM) only the auditor opens; anyone can still verify the
receipt is whole and signed.
```bash
synsema receipt keygen --out auditor.key                                   # auditor, once
synsema run --labels --auditor <public> --receipt run.json program.syn     # host
synsema receipt verify run.json                                            # anyone
synsema receipt open run.json --key @auditor.key > opened.json             # auditor
synsema run --labels --replay opened.json program.syn                      # auditor, again
```
**Keys.** `synsema receipt keygen` → stdout `{"private","public"}` (X25519, 32 bytes each, base64url
no padding). `--out f` → private to a NEW file, stdout `{"public","private_in": "f"}`, stderr hint
`open receipts with: synsema receipt open <receipt.json> --key @f`; existing file or missing folder →
`cannot create f (it must not exist): <OS error>`, exit 1.

**Turning it on.** `run --auditor <pub>` / `serve --auditor <pub>`, or `SYNSEMA_AUDITOR_KEY` in the environment or `.env` (flag
wins; listed commented in `synsema init`'s `.env.example`); a `synsema build` binary reads the variable; wasm: the `auditor` option ([deploy.md](deploy.md) § WebAssembly / docs 72-wasm). `synsema test --auditor <pub> [--receipt <path>]` (v0.6.49+, reads the variable too) seals ONE
run, so one test file (`--auditor seals one run; pass one test file (2 found)`); before v0.6.49 it
had no `--auditor`. A bad `SYNSEMA_AUDITOR_KEY` is named as the variable (`SYNSEMA_AUDITOR_KEY: the
auditor key is not base64url: …`). Without
`--labels` it works too (all entries public; still a signed log + recorded seed/clock for replay).
Pre-run errors (exit 2): `--auditor: the auditor key must be an X25519 public key of 32 bytes, got N`
(hex is not accepted: use keygen's base64url) · `--auditor: the auditor key is not base64url: …`
(same text for a bad env var) · `--auditor: the auditor key cannot seal (a low-order X25519 point,
such as all zeros): …` · `--receipt needs an auditor: pass --auditor <X25519 public key> or set
SYNSEMA_AUDITOR_KEY` · `--auditor and --explain are mutually exclusive (…)`.

**Fixed size.** `SYNSEMA_RECEIPT_SEALED_BYTES` (host: env or `.env`; default **65536**, range 4096–16777216;
else `… must be between 4096 and 16777216, got N` / `… must be a number of bytes, got "abc"`, exit 2):
the plaintext is always that size, so the receipt is as long with 0 sealed entries as with 50
(~89 KB at the default; envelope = 32 + N + 16 bytes, base64url). What doesn't fit is cut INSIDE and
counted: clock readings first, then the LAST entries (`truncated` in the opened receipt; the chain
covers what was kept). `truncated > 0` → raise the size.

**Shape** (one JSON line): `{"synsema_receipt": 1, "header": {v: 1, suite:
"HPKE-Base-X25519-SHA256-AES128GCM", engine, program_sha (= synsema code sha = receipt()'s),
config_sha (null except run --attest / serve --attested), started (UTC, seconds), run_key {alg,
public, identity}, auditor, seed_sha256 (= sha256 of the seed's bytes), public_entries,
sealed_bytes}, "public": [...], "sealed": "<base64url enc‖ct>", "root": "<hex>", "signature":
"<base64url>"}`.
- `public` = entries made with the PC public, in order, by `kind`: `capability` (the `--audit json`
  line, no `ts`), `input` (lineage entry), `output`. Sealed = `capability` (with `ts`) and `op`
  `{"kind":"op","line":"<audit line>","log":"reveal.log"}`. A sealed op's line goes into the envelope
  **INSTEAD of** `~/.synsema/audit/reveal.log` / `sign.log` / `wallet.log`.
- `root`: `h0 = sha256("synsema-receipt-v1" ‖ jcs(header))`, `hi = sha256(hi-1 ‖ "P"|"S" ‖ jcs(entry))`
  over ALL entries in run order (`jcs` = `canonical_json`); the public part has no positions, so
  only the auditor recomputes it.
- `signature` over `"synsema-receipt-v1" ‖ sha256(jcs(header)) ‖ sha256(jcs(public)) ‖
  sha256(envelope bytes) ‖ root`. The envelope's AAD is `sha256(jcs(header))`: any header change
  (even re-signing with another key) → `open` fails `the envelope does not open with this key …`.
- Hand verification (another language must repeat this):
```synsema
require file.read("run.json")
require file.read("opened.json")

let r be json_decode(read_file("run.json"))
let o be json_decode(read_file("opened.json"))
let D be bytes("synsema-receipt-v1", "utf8")
let h be r["header"]

task digest(v)
    give sha256(bytes(canonical_json(v), "utf8"))

-- anyone: the signature (an Ed25519 run key; a P-256 one is ECDSA, r ‖ s)
let msg be D + digest(h) + digest(r["public"]) + sha256(bytes(r["sealed"], "base64url")) + bytes(r["root"], "hex")
print(ed25519_verify(msg, bytes(r["signature"], "base64url"), bytes(h["run_key"]["public"], "base64url")))   -- true

-- the auditor: the chain, over the opened entries in run order
let x be sha256(D + bytes(canonical_json(h), "utf8"))
each e in o["entries"]
    let tag be "P"
    when e["sealed"]
        set tag to "S"
    set x to sha256(x + bytes(tag, "utf8") + bytes(canonical_json(e["entry"]), "utf8"))
print(slice(hex(x), 2) == r["root"])                                                                         -- true
```

**Who signs (`run_key.identity`).** `"identity"` = host's `SYNSEMA_IDENTITY_KEY` (Ed25519 seed, 64
hex; bad → `SYNSEMA_IDENTITY_KEY must be the ed25519 seed as 64 hex chars`, exit 2) → tamper
evidence. `"attested"` = under `serve --attested`, the attested P-256 key (same as the attestation
document; `public` = compressed point, 33 bytes; signature r‖s, 64 bytes) — [attestation.md](attestation.md).
`"ephemeral"` = a key made for the run → **detects accidental damage only**: whoever can change the
receipt can make a new one, envelope and signature included. Tamper evidence = `SYNSEMA_IDENTITY_KEY`,
`run --attest` (binds the ephemeral key into `report_data`, [attestation.md](attestation.md)) or
`serve --attested`.

**Before the output.** `run` writes the receipt to stderr (or `--receipt <path>`) and ONLY THEN
prints: with an auditor `print`, `flush()` and the `read_line` prompt are NOT live; `eprint` is (sink,
stderr). `--receipt <path>` is REPLACED each run; unwritable → `--receipt: cannot write <path>: …`
(exit 2) before running, and the old receipt stays. A run that fails (parse/runtime error) still
writes its receipt (exit 1). `--receipt fd:N` = Unix only (Windows: `--receipt fd:3: a file
descriptor is only available on Unix; pass a path`, exit 2). `run --format json` → `receipt` is the
FIRST key (then `ok`, `output` — which then includes the prompts —, `steps`…), and also goes to
`--receipt`.

**`serve --auditor [--receipt <path|fd:N>]`.** One receipt per request that RUNS program code
(none for a 404 or `/openapi.json`), before the response, to stderr or APPENDED to `--receipt` (one
per line; a restart appends). `inputs`/`outputs` = the request's. A `stream`/`socket` route is a LOAD
error: ``serve --auditor: route `GET /events` is a stream route: its body leaves while it runs, before
the request's sealed receipt exists`` — serve those from a server without an auditor. Cron jobs /
agents outside a request have no receipt → an audited op in a private branch there is still a
`label_violation`. The file is opened for each receipt (v0.6.49+): one deleted or moved while it
runs is created again by the next request — rotate by moving it (before, on Windows, the following
receipts were lost in silence).

**In a private branch, with an auditor:**
| | |
|---|---|
| `reveal`, `sign`/signing builtins | run; check + audit line sealed |
| wallet ops | check + audit line sealed, but a builtin returning a NEW secret there (`mnemonic_generate`, `hd_derive`…) fails `label_violation: a secret cannot be created or chosen under private control flow — …; create or pick the secret before the `when` (or the loop) that depends on the private value` (v0.6.49+; before `a secret is already opaque; …`) → make keys outside the branch. A secret made FROM a private value (`as_secret(p, "K")`): `a secret cannot be made from, combined with or chosen by a private value — …` |
| `spend` | refused (`label_violation`): a shared budget would tell the branch |
| a signature under `SYNSEMA_SIGN_CEILING` | refused: `label_violation: a signature that counts against SYNSEMA_SIGN_CEILING cannot run in a branch decided by a private value — …; sign outside the branch, or decide with a public value` (v0.6.49+; before `Runtime error: private(app)`) |
| `secret()`, `print`, `write_file`, every sink | still `label_violation` (an auditor seals audit lines; it does not open the walls) — read secrets BEFORE the branch |
| `declassify` | runs, recorded nowhere (no `[INF]` line, nothing sealed) |

**Seed and clock.** `random()`/`random_int()` come from a seed recorded in the envelope (header:
`seed_sha256`); each `parallel_map` item has its own stream (also under replay). `random_bytes`,
`token`, key generation = OS, NOT reproduced. Every `now()` reading is recorded as TEXT
(`"1792711237.7256045"`, bit-exact); at most a quarter of the envelope, then counted
(`clock_truncated`), never pushing out an entry. **With labels the clock is FENCED**: `now()` = the
time of the last public moment (an outside read like `read_file`, or an effect like `write_file`, with
the PC public); pure computation, `print`, `eprint` do NOT move it → `now() - now()` around a branch
(or any computation) is 0. Without labels: real clock, just recorded.

**`synsema receipt verify <file>`** — signature only. One receipt → `{"ok": true, "header": {…}}`
exit 0; bad → reason on stderr, exit 1 (`the receipt's signature does not verify (the header, the
public part, the envelope or the root was changed)`). A `serve --receipt` file → `{"ok", "receipts":
N, "bad": [{"line", "error"}]}` (exit 1 if any bad), incl. `the line names a sealed receipt but is not
one (cut or changed)`. Each receipt stands alone: one deleted whole, or a line cut before its first
key, is NOT noticed. Nothing receipt-like (or one receipt cut short) → `<file> has no sealed
receipt`, exit 1.

**`synsema receipt open <file> --key <private | @file> [--line N]`** — signature + envelope +
**chain** (an entry dropped from `public` and re-signed by the key holder passes `verify` but fails
here: `the chain does not verify: the entries are not the ones the run signed`). Prints one line
`{"header", "entries": [{"seq", "sealed", "entry"}…] (whole run, in order), "seed", "clock": [text…],
"truncated", "clock_truncated"? (only if readings were dropped)}`. Several receipts → `--line N`
(1-based) or `<file> has 2 sealed receipts (lines 1, 2): pick one with --line N`. Errors (exit 1):
`the envelope does not open with this key (wrong key, or the envelope or the header was changed)`,
`--key is not base64url: …`, `line N of <file> is not a sealed receipt`, `cannot read <file>: …`;
(exit 2) `--key <auditor private key> is required`, `--line takes a line number (1, 2, …)`.

**`synsema run --replay <OPENED receipt> program.syn`** — reruns with the recorded seed and clock
readings, comparing each input (source + sha256) in order; stops at the first difference:
`replay: input #1 differs from the recorded run — read_file returned sha256 …, the recorded run read
read_file with sha256 …`. Final stderr line: `replay: the N inputs match the recorded run (same
seed, the same 1 clock reading)` (exit 0) / `replay: the run read 0 of the 1 inputs of the recorded
run` (exit 1). **It checks the program first** (v0.6.49+): `header.program_sha` against the
program's (`synsema code sha`) and the `--trusted` modules' hashes (`trusted`) → another program
does not run, exit 2: `--replay: the receipt is of another program (program_sha … in the receipt, …
here); to run this program against it anyway, add --replay-any-program (the result is not a
verification)`; no `program_sha` → `the receipt has no program_sha`. **v0.6.50+:** a tool with
`--trusted-templates` hashes its source **and** its templates, so a changed template is refused
(``--replay: the receipt's trusted modules ({"tools":"19deb…"}) are not the ones given here
({"tools":"0346…"}); to run against it anyway, add --replay-any-program …``); a tool without
templates keeps its source's sha. `program_sha` describes the program of the process: one that ran
two different programs (an embedder; `synsema test` on several files after the first) carries
`null` (before, the second carried the first one's sha). The real text of an error redacted for
touching private data goes into the envelope as a sealed `label_violation` entry (labels.md). `--replay-any-program` runs it,
warns, and the verdict ends `(another program: not a verification)`. **The clock counts**: more or
fewer `now()` readings than recorded = a difference (exit 1, `replay: the run read the clock 2 times,
the recorded run 1`), unless the envelope cut them (warning `the recorded run kept 36 clock readings
and truncated 364; readings past those come from the real clock`; verdict `the 36 recorded clock
readings and 364 from the real clock past the receipt's truncation`). A run that stops with an error
is not a match (`replay: the run stopped with an error, so it was not compared to the end; …`, exit
1); `exit(n)` is compared to the end, verdict `ended with exit(n)`, a match exits `n`, any
difference 1. Not opened → `--replay: f is not an opened receipt (run synsema receipt open <receipt>
--key <private> first)` (exit 2). With `--auditor`/`--explain`/`--format json`/`--attest` → exit 2;
`serve` has no `--replay`. Pass `--labels` if the run had it. **Effects are real** (files are
written again). If the envelope cut sealed entries it warns `the recorded run truncated N sealed
entries; …`.

**What it does NOT hide:** that the run touched private data (`steps: null`), the run's wall-clock
time (`started`, when the receipt appears), whether it stopped on an error/limit (exit code; an error
run still writes its receipt) — one bit per run/request. It is not `receipt()` (the program's own VC).

## Error diagnostics
When an error occurs, Synsema can provide a rich report:
- **Location**: file, line, column
- **Source context**: code lines around the error, with error line marked
- **Call stack**: readable trace of function calls
- **Variables**: all visible variables and their values at failure
- **Intent**: what the program was trying to do
- **Classification**: data, io, logic, capability, type
- **Recoverable**: yes/no
- **Suggestions**: specific fix suggestions for the error type

### How to see it
The rich report is **opt-in** via `--explain` (so plain `run` stays script/CI friendly):
```
synsema run --explain program.syn               # human-readable report on stderr
synsema run --explain --format json program.syn # structured JSON (for tools/agents)
```
Without `--explain`, `synsema run` prints only the short line
(`Runtime error: <file>:<line>:<col>: <msg>`) — the stable, parseable form for scripting.
The process exit code is unchanged either way (1 on failure, 0 on success).

## Auto-recovery
1. Retry with backoff (IO/transient errors)
2. Fallback to cached/default data
3. Partial results
4. Speculative alternatives (fork, try, pick best)
5. Human escalation

Auto-recovery (including speculative fork/try/pick-best) is an internal runtime strategy — there
is no user-facing API to drive it; you get it via `try`/`recover` and the recovery protocol.
