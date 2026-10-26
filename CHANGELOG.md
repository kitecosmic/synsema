# Changelog

Notable changes to the Synsema language, engine and tooling. The entries that matter most are the
**breaking** ones: a program that used to load and no longer does, or that behaves differently.
Each says what changed, why, and what to write instead.

Versions follow the release tags (`v0.6.24`, `v0.6.25`, …). Dates are the release date.

## Unreleased

**Behavior changes (read these first).**
- **Under a ceiling, a program publishes only what it declares: `require declassify("P")` bounds
  `declassify`, like `require net` bounds the network** (with `--labels`). Since v0.6.46 the ceiling
  alone decided: `--cap-set stdout,declassify=customers` let `declassify` remove `customers` from a
  program that never declared it. Now, under a ceiling (`--cap-set`, `ceiling` in wasm) nothing is
  granted from the environment: the program's `require declassify("customers")` grants it, and it
  goes through the ceiling like any other `require` (`--sandbox` and `--deterministic` have no
  `declassify` to allow: under them nothing is published, as before). A
  `require declassify("billing")` under `declassify=customers` is refused (the audit says so), and a
  bare `require declassify` under a scoped ceiling is wider than the ceiling and refused whole, as
  `require net` is under `net=api.x.com`. Without a ceiling nothing changes (`declassify` is still
  granted, like `unsafe` in your own crate), and without `--labels` it is not checked. A trusted
  task is "a program" here: under `--trusted-cap-set` it publishes what its own `require
  declassify(...)` declares (what the v0.6.46 entry already said; it is now true), and so is an
  agent, which declares its own capabilities: the program's `require` does not reach it.
  **Breaking:** a program that runs under a ceiling with `--labels` and declassifies needs `require
  declassify("<principal>")` in its preamble, in the trusted task, or in the agent that
  declassifies. The refusal says where the line goes: in a trusted module, the exported task that
  runs it and `--trusted-cap-set` (also when an agent calls it; while the module loads nothing
  is declared, not even by a task its top level calls, so it says to move it into an exported task
  that the program calls); in an agent, that agent's body (an
  agent spawned by another declares its own too); otherwise the program's preamble or the body of
  the agent that runs the code (a `parallel_map` inside an agent inherits the agent's
  capabilities, so the agent's line covers it).
- **The Vela guest's bundled app, and the two example apps, now declare `require
  declassify("app")`**, for the change above (the guest runs its app under `stdout,declassify=app`).
  An app written for the v0.6.48 guest that declassifies without declaring it gets a
  `label_violation` from this guest on: add the line. The guest's sha256 changes with its app.
- **A secret inside the payload of `push_send` is an error**, as in `json_encode` (A4). Before, the
  payload carried the marker `[redacted]` as if it were data, with a `[serve]` warning. The error
  names where the secret is (`push_send: the payload["k"] is secret(K)…`); the payload goes to the
  browser, another owner, so there is no host to bind it to: leave it out. A task or a builtin
  inside the payload is an error too.
- **`run --replay` refuses a receipt of another program.** It compares the receipt's `program_sha`
  with the program's (the same hash as `synsema code sha`) before running, and stops with exit 2 if
  they differ or the receipt has none; the receipt's header now also records the sha256 of each
  `--trusted` module (`trusted`), and a replay with other trusted modules stops the same way: `--replay: the receipt is of another program (program_sha …
  in the receipt, … here); to run this program against it anyway, add --replay-any-program (the
  result is not a verification)`. With `--replay-any-program` it runs, and the verdict ends with
  `(another program: not a verification)`. Before, a different program replayed in silence and
  could end in "match".
- **The `reason` of an `llm-data` audit entry names the permission**: `Granted by
  llm("customers@api.anthropic.com")`, like any other permission used (before it was the operation,
  `generate`). Receipts and audits written before this version say `generate`; a tool that reads
  them has to accept both. There is one entry per call, with the principals the program declares
  (never the real ones of the value, which would depend on the data).
- **Replacing a task of a trusted module from outside is an error** (`set t.reply to f`: `cannot
  replace the trusted task 'reply' from outside the module`), and so is adding a name it does not
  export (`set t.NEW to 1`). Before, the first changed only the program's copy and the second added
  a key; a module loaded from a file already refused both. Setting an exported variable still
  changes the program's copy only.

**Corrections to the v0.6.46 entry** (the engine already did this; the entry said otherwise, and is
corrected in place):
- the clock is fenced in the whole program, not only in a private branch (A2);
- `mnemonic_generate`, `hd_derive` and any operation that creates or returns a new secret do not run
  in a private branch (A3); `reveal` and `sign` do;
- a CIDR grant covers the addresses written inside it, never a name, whatever it resolves to (A5);
- `discovery off` turns `/robots.txt` off too, with `private` or without it (A6).

**Fixes.**
- **`@synsema/wasm`: `run()` and `runAsync()` pass `auditor` and `sealedBytes`**, and return
  `receipt`. Before, only the raw ABI did, so the sealed receipt the v0.6.46 entry announced for
  wasm never came back through the package. `test()` and `handle()` build no receipt: an `auditor`
  or a `sealedBytes` there is an error (`auditor: only run seals a receipt`), where the engine used
  to ignore it. `index.d.ts` declares them,
  with `dispatchHostSync` and `module`.
- **wasm: the audit entries of a trusted tool carry `context: "trusted:<module>"`**, as in the native
  runtime.
- **A `require llm("P")` (or `judge("P")`) refused by a ceiling with a bare `llm` says why**: the
  ceiling's `llm` allows public data only, and data private to `P` goes to the model with
  `llm=P@<provider host>` (before, only "above host ceiling"). The rule does not change: a bare `llm`
  in the ceiling never covered private data.
- **The redaction warning names `serve` only under `serve`.** Outside it (`evm_rpc` under `synsema
  run`, …) it says `synsema: warning: secret(K) was redacted in a value serialized to JSON`.
- **`synsema --help` (and `help`, `-h`) prints the usage**, which now lists `--trusted`,
  `--trusted-cap-set` and `--replay-any-program`.
- **`synsema code check`**: a deprecation warning has its line and the file as given (it had line 0
  and the absolute path in the message); a missing-capability warning points at the call that
  needs it, not at the start of the task; the `check` tool of the MCP server describes what it
  returns today. For a `declassify` without `require`, it suggests `require declassify("<principal>")`
  (a bare one allows any principal).
- **`synsema check` sees `declassify`/`private` read as a value** (an alias, a list entry, an
  argument), like `run` and `code check`: exit 1 with the file, line and column.
- **The tasks of a trusted module can be described with `tool_spec` and dispatched with
  `call_tool`**, with named arguments (`call_tool(t.reply, {"customer": c, "text": "hi"})`), and
  called with named arguments (`t.reply(c, text = "hi")`). They run in the module's scope as when
  called by position; typed parameters are checked; a task or a lambda among the arguments is still
  an error. Before, they could only be called by position.
- **`read_line` with a private prompt outside a private branch** says the prompt is private and goes
  to stdout (before, it said "under private control flow").
- **Sealed receipts:** what `edit_file` reads is a lineage input, like `read_file`; `synsema test`
  takes `--auditor` (and `--receipt`) for one test file, as `run` does; `serve` opens the
  `--receipt` file for each receipt, so one deleted or moved while it runs is created again (before,
  on Windows, the following receipts were lost in silence).
- **`--replay` says what it compared.** After a run that stopped with an error it no longer says
  "match" (it says how far it got); a run that ends with `exit(n)` is compared to the end, and the
  verdict says `ended with exit(n)` (a match exits with `n`; any difference exits with 1, with or
  without `exit(n)`, so a matching `exit(1)` and a difference share the code and the verdict's
  text tells them apart); it counts the clock readings (`the same 2 clock readings`) and
  a run that read the clock more or fewer times than the recorded one is a difference (exit 1),
  unless the receipt cut its clock readings, which the verdict then names; the warning names what
  was cut (`kept N clock readings and truncated M`), never "truncated 0 sealed entries".
- **`sign` with `SYNSEMA_SIGN_CEILING` in a private branch says the rule** (it said `Runtime error:
  private(app)`), and so does creating a secret there or from a private value: `a secret cannot be
  created or chosen under private control flow — … create or pick the secret before the when (or
  the loop) that depends on the private value`, and `a secret cannot be made from, combined with or
  chosen by a private value — …` (it said `a secret is already opaque; use private on the value you
  compute`). The texts are fixed: they name no site, key or value.
- **A CIDR grant and a name**: the error explains that the grant covers addresses, never a name,
  and gives the line to write (`require net("db.internal:5432")`).
- **A warning at load for `generate "x" + c`**: it reads `(generate "x") + c`, so the model does not
  see `c`; the warning (once per site, also in `check` and `code check`) suggests `generate "x"
  given c`.

**Messages.**
- `in_units(5, "hours")` suggests a duration in the unit asked for (it always said `"minutes"`);
  `in_units("5", "hours")` says the first argument is not a duration (it said the unit was wrong);
  an unknown unit lists the valid ones.
- `parquet_read`/`parquet_scan`: `row group 3 does not exist — the file has 3 row groups, numbered 0
  to 2` (it used Rust's range notation, `0..3`).
- `decide` served by the judge (`SYNSEMA_JUDGE_DECIDE`) under a ceiling with `judge` and without
  `llm` gives the line and says why it needs `llm` (it falls back to the model when the judge does
  not choose), with private data too (whatever the `given` is: the check runs before `given` is
  evaluated; a `decide` whose statement already touched the private value before it, as in
  `[c + "!", decide … given c]`, still gets the redacted text, so give it its own line), and names both forms (`require llm`, or `require llm("<principal>")` with
  `llm=<principal>@<provider host>` for private data); before, `Runtime error: private(…)` with
  neither. Inside a private branch the first error is still `decide called under private control
  flow`.
- A `require` missing inside a trusted task says to add it to that task (within the host's
  `--trusted-cap-set`), not to the program's preamble.
- The `[INF] declassify` log says `from principals the program does not declare` instead of
  `from […]`.
- A bad `SYNSEMA_AUDITOR_KEY` is named as the variable (it said `--auditor: …`), in `run`, `test`
  and `serve`; a cut receipt alone in its file says it is cut (it said the file had none).
- On Windows, `read_file("a.txt.")` says the file is not found and why (a name cannot end in a dot
  or a space there); it said "a broken link".
- A secret the program made (`as_secret`, `hkdf_sha256`, …) in a URL, a query or a body says such a
  secret only goes in a header, and to keep the final value in the configuration; it suggested a
  binding, which only a secret read with `secret("NAME")` (or built only from such secrets, like
  `bearer(secret("K"))`) can have.
- A form field or a header of the wrong type says `must be text, a number, a bool or a secret` (a
  bool was accepted but not named).
- A refused connection to `localhost` that resolved to `::1` (Windows) says so and gives the
  `127.0.0.1` URL: a `serve` on `0.0.0.0` listens on IPv4 only.

## v0.6.48 — 2026-10-25

**Security: RUSTSEC-2026-0387 fixed.** v0.6.47 shipped `crypto-bigint` 0.5.5, where some operations
meant to run in constant time may branch on secret values. The elliptic-curve crates now come from
the 0.14 generation (`k256`, `p256`, `p384`, `p521` 0.14, `ecdsa` 0.17, `elliptic-curve` 0.14), which
uses `crypto-bigint` 0.7.8. That covers every operation with an EC secret key: ES256 and VAPID
signing, Web Push ECDH, P-256 and P-521 ECDH (`ecdh_*`), secp256k1 and Schnorr (taproot) signing.
The advisory is no longer ignored in `.cargo/audit.toml`, and `cargo audit` passes on the engine and
the Vela guest.

Nothing changes for a program: signatures are byte for byte the same (RFC 6979 is deterministic; a
new test pins ES256 to the RFC's own vectors, and secp256k1 was already pinned to eth-account's), and
keys, points and DER/PEM encodings are read and written as before. One behavior does change: when
the host gives no entropy, `push_send` and `push_vapid_keys` now return an error instead of
panicking. The embeddable WebAssembly module grows by about 10 KB gzipped; the Vela guest is about
6 KB smaller and declares the same six WASI imports.

**The Vela guest now rebuilds byte for byte from any folder.** Before, the module depended on where
it was built: Rust leaves source paths in it (panic locations), and cargo hashed the absolute folder
of the engine's crates into their `-C metadata`, which changes the generated code. So a rebuild only
matched the published hash in GitHub Actions' own folders (`/home/runner/work/synsema/synsema`,
`/home/runner/.cargo`). Now:
- the source paths are remapped to `/synsema` and `/cargo`;
- the guest's workspace is a new `Cargo.toml` at the repo root, so the engine sits under it. Its
  lockfile moves from `packages/guests/vela/Cargo.lock` to `./Cargo.lock`.

The build is one script, `packages/guests/vela/tools/build.sh`, used by CI, by the release and in
the guest's README. The release's `guest-reproducible` check now builds one of its two copies from
another folder with another `CARGO_HOME`, so a path dependency fails the comparison. The guest's
sha256 changes once more than usual in this release (RustCrypto plus the paths), and from here on a
rebuild of the tag gives the published hash from any folder on Linux (or WSL). Native Windows does
not reach it: the source paths inside the module use `\` there, which Rust cannot normalize, so
`build.sh` refuses to run under Git Bash, MSYS or Cygwin instead of producing a hash that never
matches.

The release build uses `cc` 1.10 (was 1.2.65). `cc` 1.8.0 fixed how it forwarded rustc's
`-Cprofile-generate`/`-Cprofile-use` to clang-based C compilers (zig cc, Apple clang; cc-rs#1986),
which made the instrumented PGO binary crash on exit with rustc 1.99.1, so the workarounds v0.6.47
added (in `engine/pgo/zig`, and in `release.yml` for macOS) are gone.

## v0.6.47 — 2026-10-24

**Built with Rust 1.99.1 (was 1.96.0).** The releases in between fix four miscompilations (MIR
optimization in 1.96.1, an LLVM optimization in 1.97.1, vtables in 1.98.1, FFI `bool` returns on
x86_64 in 1.99.1). The Vela guest's sha256 changes, as it does every release; the published module
declares the same six WASI imports as v0.6.46, all inside Vela's eight (rustc 1.99.1 links two
more, `fd_seek` and `sched_yield`, which `tools/wasi-stub` replaces like the others; `sched_yield`
now returns success, since a single-threaded guest has nothing to yield to). The new compiler also
exposed a latent bug in the guest, caught before any release: comparing the app slot's header
against the literal magic left a second copy of `SYNSEMA.APPSLOT1` in the module's data, and
`tools/embed.syn`, `tools/verify.syn` and the probes, which require exactly one slot, refused the
module. The guest now recognizes the header by a hash of the magic, so no optimizer can bring the
literal back. Guests published up to v0.6.46 are not affected.

LLVM 23 compiles two of the interpreter's hottest paths with more instructions: the name lookup of
the tree-walker (iterating the frame's two halves as one chained iterator) and the arithmetic path,
where the array check (`array_binop`) is no longer inlined. Both are now written so that they do not
depend on the inliner. The net cost against v0.6.46, in instructions executed on the 31 programs of
the `perf-guard` corpus (deterministic, without PGO, as `perf-guard` measures, on x86-64):
- native tier (the default): −1.9 % to +1.2 % (`s_csv` +1.2 %, the other text and data programs
  at most +0.9 %);
- the VM alone (`--jitless`, and WebAssembly without labels): −1.8 % to +1.4 % (`s_matrix_list`
  +1.4 %, `s_csv` and `s_records` +0.9 %);
- the tree-walker (`--labels`, `serve --attested`, the Vela guest, WebAssembly with
  `labels: true`): −1.5 % to +1.2 %; 25 of the 31 programs run fewer instructions than in v0.6.46.

Release binaries are built with PGO, which shifts where the cost lands. On the same 31 programs:
native tier −2.2 % to +3.0 % (`s_text_join`), the VM −1.0 % to +3.7 % (`c_depth16`; 30 of the 31
run more instructions, median +2.3 %), the tree-walker −4.6 % to +1.9 % (`s_nbody_chico`). The new
name lookup costs the VM 0.5 to 2.6 points (median 1.7), mainly through how LLVM allocates
registers in the dispatch loop, and the native tier up to 1.8 where it falls back to the VM. The
previous lookup gives that back but costs the tree-walker up to 13.7 points with PGO (`c_depth16`;
median 0.8) and 3.7 without, so the new one stays. What was not recovered is tracked to be worked on
again. The `perf-guard` anchor (`engine/perf/baseline.json`) was re-measured on CI with rustc 1.99.1
in this same change, so it now measures against the new compiler.

**Known, not fixed in this release: RUSTSEC-2026-0387** (`crypto-bigint` 0.5.5, published
2026-10-23). Some operations meant to run in constant time may branch on secret values, depending on
the compiler and the CPU. It reaches Synsema through the elliptic-curve crates (`k256`, `p256`, `p384`,
`p521` 0.13), which handle secret keys in ES256 and VAPID signing, Web Push ECDH, P-521 ECDH and
`k256` transaction signing. Every release up to v0.6.46 ships the same version. The 0.5 series gets no
fix, so the fix is moving to the 0.14 curve crates. That is the first item of the next release; this
one ignores the advisory in `.cargo/audit.toml` with that reason.

**Breaking, with labels: a flow-checker cut no longer tells the program or the log where it
happened.** Before, the text of a `label_violation` named the site and the label, and how much
output, log or shared state survived depended on where the cut fell, which a private value could
choose. Now:
- under a ceiling (`--cap-set`, `--sandbox`, `--deterministic`, `--trusted`), under `serve`, and in
  the embeddable WebAssembly module, the program sees one fixed text, `private(labels): the run was
  stopped by the flow checker`, with no location, and output before the cut is replaced by that one
  line. `run` and `test` without a ceiling (native or the wasip1 binary) keep the detail, as the
  owner's own run. The detail goes to the operator: stderr without a ceiling, the sealed receipt
  with `--auditor`, and `operator_detail` in WebAssembly (`run` and `handle`), never `errors` nor
  the program's log;
- a cut in an agent cuts its whole run: from then on every sink of the run fails;
- `serve --labels`: each request, cron tick and socket handler is its own run. Its stdout and stderr
  are held and written when it ends, or replaced by the fixed line if it was cut (a notice at
  startup says so; run without `--labels` for a live log). Agents' output is not written.
  `agents()` and `agent_stop` see only the agents of the same run. A cut is always a 500 with the
  fixed text (a refused response counts as a cut);
- `serve --labels` and the blackboard and signal queue: a run (the request, or the preamble, with
  all its agents) is committed once, when all of it has ended without a cut, and undone entirely if
  any part is cut, including what its agents wrote after the request answered. What other runs read
  while it was open, and signals already consumed, stay (as with any effect before a cut);
- the Vela guest: any cut by the flow checker answers `{"error": "label_violation"}` on chain, the
  same code as a private value reaching a public field. That includes a `declassify` the host did not
  grant and a runtime error on private data, which used to be `runtime_error`. The Executor's log gets
  one fixed line, `ERR label_violation: the flow checker stopped the run; what failed and where stay
  in the enclave`, instead of the path and the label. An error that touches no private data is still
  `runtime_error`, with its text in the log.

**The audit names the same grant every run: the narrowest one.** When two grants covered a use
(`require llm` and `require llm("clientes")`, or `net("*.x.com")` and `net("api.x.com")`), the
audit's `Granted by …` named one at random, because grants were kept in a hash set whose seed
changes per run. A program with private data could not choose it, but the audit of the same run
differed from one execution to the next. Grants and denies are now kept in a fixed order, the grant
that covers least first, read the way each type matches: a scope before none, no wildcard (`*`,
`?`) before a wildcard, more literal characters before fewer. A CIDR counts as a range by its
prefix (`net("10.1.2.3")` before `net("10.1.0.0/16")` before `net("10.0.0.0/8")`, and a port
narrows it as it narrows a host: `net("10.0.0.0/8:9")` before `net("10.0.0.0/8")`); `[` is a literal
character, not a wildcard; a secret bound to hosts (`secret("k") for net("*.x.com")`) comes before
the unbound one; and in `llm`/`judge`, where the scope names whose private data may be sent, the
unscoped grant covers only public data, so a public call names `llm` and a call with data of `P`
names `llm("P…")`. The order is read from the text of the declaration, so a relative path against
an absolute one compares by length. Ties break by type and scope. The same order picks the `deny`
that the audit and the error name, the `deny` of a private-address `net` check and of a `static`
root, and the order of the hosts of a bound secret.

**The skill for coding agents moved to `skills/synsema/` and installs in any agent.** It was in
`.synsema-skill/`, a hidden folder that only the Claude Code installer knew, and its `SKILL.md`
frontmatter did not parse as YAML for strict readers (a `:` inside the unquoted description), so
`npx skills add` found no skill. Now it is the open Agent Skills layout (`skills/<name>/SKILL.md`,
description under 1024 characters) and installs once per machine with `npx skills add kitecosmic/synsema -g -y` (Claude
Code, Codex, opencode, Cursor, Gemini CLI, GitHub Copilot, Windsurf, …), as a Claude Code plugin
(`/plugin marketplace add kitecosmic/synsema`, then `/plugin install synsema@synsema`) or a Codex
plugin (`codex plugin marketplace add kitecosmic/synsema`, then `codex plugin add synsema@synsema`).
`install-skill.sh` copies the whole folder (no file list to keep in sync), still writes
`~/.claude/skills/synsema` by default, and takes `--agents` (`~/.agents/skills`, read by Codex and
opencode), `--dir <folder>` and `--ref <tag>` (a release's skill; tags up to v0.6.46 are read from
the old folder). `SYNSEMA_SKILL.md` described a Python prototype that no longer exists; it is now a
pointer to the skill. Links to `.synsema-skill/…` from older docs or projects stop working: use
`skills/synsema/…`.

## v0.6.46 — 2026-10-22

**Behavior changes (read these first).**
- **`json_encode`, `jsonl_encode`, `json_for_script` and `csv_encode` of a secret are an error.**
  Before, the secret came out as `"[redacted]"`: the key never leaked, but the program got a
  marker it could send on as if it were the data (in a body, in a file, to another agent). The
  error names the secret and where it is (`json_encode: the value["auth"]["key"] is secret(K)…`).
  Pass the secret to the request itself (a header, or the body or the URL once it is bound, see
  New) and the engine writes it at the socket; or leave it out of what you encode.
- **A list or a map with a secret inside, in a template hole, is an error.** `` `creds={creds}` ``
  with `creds = {"k": secret(...)}` gave the text `creds={k: secret(K)}`: plain text that could end
  up in a header or a URL with the placeholder instead of the key. Take the secret out on its own
  (`` `{creds.k}` ``, which stays a secret) or use `bearer(...)`/`basic(...)`. A secret on its own
  in a hole is unchanged.
- **`declassify` and `private` can only be called by their name.** Reading them as a value is a
  load error: an alias (`let d be declassify`), a list or map entry (`[declassify][0]`,
  `{"k": declassify}`), an argument (`f(declassify, x)`), a returned value or a pipe through an
  alias. Before, all of these published for real while `synsema code check --json` listed none of
  them, so the review missed the call. A program that binds the name to a value
  (`let private be 5`, a parameter called `private`) still loads; there, with labels on, a call
  that does not use the name (`g(x, "why")` with `g` the builtin) fails at the call. The
  `code check --json` inventory is now complete, and its `declassify_static_only` field is gone.
  A bare key with one of these names (`{private: 1}`) is a load error too: a bare key evaluates the
  name (v0.6.45 printed `{builtin:private: 1}`); write it quoted, `{"private": 1}`.
- **`declassify` is a capability, and a host ceiling bounds it** (with `--labels`). Without a
  ceiling nothing changes: the runtime grants it, like `unsafe` in your own Rust crate (explicit,
  with its mandatory reason, and listed in full by `synsema code check --json`). With a ceiling
  (`--cap-set`, `ceiling` in wasm) only the principals the ceiling names can be published:
  `--cap-set stdout,declassify=clientes` lets `declassify` remove `clientes` and nothing else
  (globs work, as for `secret`). **This breaks a program that runs under `--cap-set`, `--sandbox`
  or `--deterministic` with `--labels` and declassifies:** add `declassify=<principal>` to the
  ceiling (`--sandbox` and `--deterministic` never grant it). Inside a `sandbox` there is no
  `declassify` unless `sandbox under {"declassify": "…"}` delegates it. A refusal is a
  `label_violation` that `try`/`recover` cannot catch (whether it passes depends on the real label
  of the value) and its message names the declared set, never the real one. Without `--labels` it is not checked:
  `declassify` stays the identity. `require declassify("P")` is now understood (before it was
  ignored), and a bare `require declassify` warns like a bare `require sign`. The Vela guest
  (`synsema-vela-guest.wasm`) runs its app under `stdout,declassify=app` for this reason: its only
  principal is `app`, and the app publishes its outcome codes and withdrawal receipts itself.
- **A `net` grant with a wildcard reaches only public IP addresses.** `require net` without a
  scope, `net("*")`, `net("*.x.com")`, a host ceiling `--cap-set net`, a `sandbox under` and a
  capability token (`auth with`, `sandbox under verified`, the ceiling of `run_program`) with a
  wildcard no longer reach loopback, the private networks (RFC 1918, CGNAT, ULA), link-local (with
  the cloud metadata endpoint `169.254.169.254`), multicast or the documentation ranges. Before,
  `net` compared only the name: `127.0.0.1.nip.io` or any name that resolved inside reached it.
  The client resolves once, checks the address it is going to use and connects to that one (no
  window for a DNS answer that changes in between); an IPv4 mapped or translated in IPv6 counts as
  that IPv4. To reach a private address, every layer has to name it: the exact host
  (`require net("db")`, `net("localhost")`), the address, or a CIDR that contains it
  (`require net("10.0.0.0/8")`, which covers the addresses inside it written as such in the URL,
  never a name, whatever the name resolves to; this line was ambiguous until v0.6.49). A
  `deny` of a CIDR set by an embedder (`CapabilitySet::deny`) now also stops a name that resolves
  inside. The error names the line
  to write: ``http_get(): `db` resolved to 10.0.0.5, a private address; a `net` grant with a
  wildcard reaches only public addresses. Name it: `require net("db:5432")`…``. When the URL comes
  from the configuration, name it from there: `require net(env("CONTROL_URL"))`. It applies to
  `http`/`fetch` and the `http_*` builtins, `ws_connect` (and every reconnection), `tcp_connect`,
  the blockchain RPC builtins, `push_send`, `oidc_verify` and `proxy to` (on every connection; the
  client gets a 502 `proxy error: upstream not allowed` and the reason, with the address, goes to
  the server's log). A secret bound to a host goes to a private address only if its binding names
  it too. The engine's own requests (LLM and judge providers, the approval webhook, `synsema
  update`, ACME) are the host's configuration and are not affected, and neither are the database
  connections (`postgres`, `mysql`, `mongo`, `redis`), which come from the configuration. In
  `@synsema/wasm` the connection belongs to the embedder's `http` hook and the engine does not see
  the address: the hook has to resolve the name, check the address it connects to against the same
  ranges (listed in `Host.http`) and connect to that one; it does not know whether the program
  named the host.
- **A `require` with a name that does not exist is a load error.** Before, `require nett("x")`
  parsed and granted nothing, with no warning, and the program failed later with an error that
  did not name the typo. Now the error names it and, when there is one, the closest real name:
  ``unknown capability `nett` in `require` — did you mean `require net`?``, followed by the list
  of known names. The same holds for a dotted name (`require file.raed(...)`) and for a `require`
  inside a task or an agent. The audit form (`file_read`, `file_write`) still loads.
- **The `http`, `http_bytes`, `http_post` and `http_put` builtins take one more optional argument,
  `form`** (see New); a program never passed it, so nothing breaks, but a host that embeds the
  engine and implements `http` receives a new field, **`redirect: "error"`, when the request carries
  a secret** (in the URL, the query, the body or a header). A redirect would carry it to a host the
  program never named (a cross-origin redirect in `fetch` drops `Authorization`, but not `X-Api-Key`
  or any other header), and the native runtime does not follow redirects either; honor the field
  (the browser `fetch` option of the same name does) or the protection is lost on that host. `examples/embed/node/demo.mjs` and `@synsema/wasm`'s types show
  it.
- **In wasm, `judge` checks its capability, and a `llm` hook that throws is an error.** A `judge`
  block ran even when the `ceiling` did not grant `judge` (the native runtime always refused it);
  now it is refused the same way. A host `llm` hook that threw gave the program an empty answer
  with `ok: true`; now that call fails with the hook's message (or `the host's llm hook threw`;
  redacted like any error when the call carried private data). The hook receives a third
  argument, `{principals}` (see New).
- **A recursive `watch` needs `file.read("<folder>/**")`, like `grep` and `static`.** A program that
  watched a folder with `file.read("src")` (or `"src/*"`) no longer starts the watch: grant
  `"src/**"` or pass `{"recursive": false}`. The grant was checked only on the root, so it reported
  the names of files under `src/sub/`, which the program cannot read. A non-recursive `watch` still
  needs only the folder (like `list_dir`). A root that is a file when the watch starts, without
  the tree granted, is watched as `recursive: false`: if a folder replaces it, only its first level
  is seen (before, the whole tree). A root that does not exist is an error, as before. A `deny`
  the host sets inside the tree takes that part out of the watch: no entries and no events from
  there.
- **`run` and `proc_spawn` with `cwd` resolve a relative command against that folder, and that is
  what the grant must name.** `run("./tool", [], 60, {"cwd": "sub"})` asks for `exec("./sub/tool")`
  and runs that file, as `cd sub && ./tool` would. Before, it asked for `exec("./tool")` and which
  file ran depended on the platform (the one in `sub` on Unix, the one next to the program on
  Windows), so the grant did not say which file it allowed. A command without a separator (looked
  up in `PATH`) or an absolute path is unchanged. **Breaking:** a grant written for the old form
  has to name the path inside `cwd`. With `pty: true` on Windows, a path that does not exist as
  written is an error: before, the terminal layer tried the `PATHEXT` extensions, so a grant for
  `notes.txt` could run `notes.bat`, and an absolute path without an extension (`C:/x/node`) ran
  `node.exe`; now name the file with its extension. A command without a separator (`notes`) is
  still looked up with `PATHEXT`, and so is a path that disappears between the check and the
  start.
- **In `@synsema/wasm`, a host `kv` that fails or answers something else is an error, not "the key
  is not there".** Before, each of these read as an absent key, and the next write replaced what the
  host had stored:
  - a `kv.get` that throws, or that returns something other than a string or `null` (a number, an
    object already parsed);
  - a stored value that is not JSON (cut half-way, or written by something else): `state_incr` over
    it gave 1;
  - a `kv.list` that throws or that returns something other than a list of strings (the
    `{keys: [{name}]}` form of Cloudflare KV, a list of `{name}`, `undefined`): `state_all` gave
    `{}`.

  `state_get`, `state_incr`, `state_all`, `state_merge` and `state_cas` fail and say why. A
  declared `memory` whose load fails, or whose stored memory or progress is not readable, is not
  opened: its builtins fail and say why (before, it opened empty and the first `remember` replaced
  it). The audit log of `reveal`, `sign`, `wallet` and `spend` is not written over either: if
  reading it fails, the operation is refused (before, the log was replaced by one line and the
  operation went on). **Breaking** for a host whose `kv.get` returns numbers or objects, or whose
  `kv.list` returns another shape: return the stored text, and the list of key names. For an
  embedder written in Rust, `HostProvider::kv_get` now returns
  `Option<Result<Option<String>, String>>` and `kv_list` `Option<Result<Vec<String>, String>>`.

**Security.**
- **Dependencies with advisories updated:** `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382, a
  certificate chain could be accepted through a distrusted intermediate), and `webpki-roots` and
  `webpki-root-certs` 1.0.10 (RUSTSEC-2026-0381 and 0383, distrusted emSign intermediates in the
  bundled roots). `cargo audit` is clean.
- **`receipt()` no longer publishes what depended on a private value** (with `--labels`). Three
  leaks, all with the program counter public and no `label_violation`: `steps` was the raw count
  (a loop with `when i < n` over a private `n` gave 222 or 378), now `nothing` once a private value
  was seen; `inputs` counted the reads made in a branch decided by a private value, which are now
  left out of the public lineage; and `declassified[].from` was the real label (`["a","c"]` or
  `["b","c"]` by a private index), now the declared set, and a `declassify` inside a private branch
  is left out of the list (and its `[INF] declassify` log line is not written), since how many
  there were told which branch was taken.
- **The prompt of `read_line(prompt)` is a public sink, like `print`** (with `--labels`). It was
  printed as is: a private prompt came out in clear (the labelled dispatch hands the builtin its
  arguments without labels), and so did a prompt inside a branch decided by a private value. Both
  are a `label_violation` now. `read_line()` without a prompt in a private branch is still allowed.
- **With `--labels`, `flush()` and `read_line` no longer write the pending output live.** `print`
  already kept it until the end with labels on, but these two emptied it to stdout, so how many
  lines came out before a prompt could depend on a private branch. The output now comes out at the
  end, after the prompts; without `--labels` nothing changes.
- **In `@synsema/wasm`, a run with `labels` that hits the memory limit reports `steps: null` and
  `private_seen: true`.** Whether the run ran out of memory can depend on a private value (one bit
  per run, like any error it causes), so the host treats that result as sensitive, the same as a
  run that ended with `private_seen`.
- **An LLM operation under a private branch no longer writes a "granted llm" audit entry before
  failing** (with `--labels`). `reason`/`decide`/`analyze`/`generate`/`judge` checked the
  capability first and the program counter second, so the audit said the call was allowed inside
  a branch decided by a private value, which tells which branch ran. The program counter is
  checked first now, and nothing is written.
- **A link swapped between the check and the open no longer takes a file operation outside the
  grant** (on Linux and Windows). v0.6.45 checked the path on disk and then opened it by name, so a
  folder changed into a link in between was followed. Now the file is opened without following any
  link (`openat2` with `RESOLVE_NO_SYMLINKS` on Linux, `NtCreateFile` with `OBJ_DONT_REPARSE` on
  Windows): if it opens, it is the file the check judged. With a link on the way, it is opened
  following it but without access to its data (`O_PATH` on Linux, its attributes only on Windows),
  the same check runs again on where it really is, and only then the same file is reopened with the
  access asked for: a FIFO or a device outside the grant is refused before it is opened. A link
  that stays inside the grant still works, as in v0.6.45. To
  replace a file (`write_file`, `edit_file`, `zip_extract`/`tar_extract`), the folder is opened the
  same way and the temporary file, the rename and the cleanup all go relative to that folder, so the
  name is never resolved again.
  - It covers `read_file` (whole or a range of lines), `read_file_bytes`, `edit_file`,
    `write_file`, `append_file`, `grep`, the files of `zip_create`/`tar_create` and the entries of
    `zip_extract`/`tar_extract`, `mtls_identity`, the fonts of `svg_to_png`/`svg_to_pdf`, `render`
    (and its `include`/`layout`) and the files of a `static` route (judged against the served
    folder).
  - `zip_extract` and `tar_extract` now write each entry like `write_file`: atomically (no half
    file if it fails) and, when a link has the entry's name, the link is replaced instead of
    written through.
  - Cost, measured in release with the open alone: without a link on the way, +1 to +3 µs on
    Windows (an open of 25 to 50 µs, depending on the antivirus) and +0.4 to +0.9 µs on Linux (a
    4.5 µs open); with a link, one more open, the query of the real path and the check again
    (Windows 66 → 131 µs and Linux 4.3 → 9.5 µs, without the check).
  - What remains as in v0.6.45: `list_dir`, `file_exists`, `file_info`, `delete_file`,
    `delete_dir`, the folders `write_file` creates when they are missing, and the PEM files of a
    `tls cert … key …` block in `serve` (read by the TLS setup after the check); macOS, a Linux
    kernel without `openat2` (before 5.6) or a container whose seccomp refuses it (Docker before
    20.10), and UNC paths on Windows; and a hard link, which is not visible from its name.
  - On Windows, a name the Win32 layer used to normalize is now opened as written: `a.txt.` and
    `a.txt ` (a trailing dot or space) no longer open `a.txt`, and `…/CON` no longer opens the
    device; they are "not found".
- **A `static` route honours a `deny` the host sets.** A file under a denied path is a 404, and a
  `deny` on the served folder itself (or on all of it) stops the server at start with a message.
  Before, only the `file.read("<dir>/**")` grant was checked. The `deny` is judged again where the
  file was opened, so a link swapped in between does not serve it. To deny a folder's content, deny
  `<folder>/**` (as everywhere in the engine, `<folder>` alone names only the folder).
- **`serve` checks the literal `render("…")` templates at start only with what the run may read.**
  The check read and parsed each template and its `include`/`layout` files from the working
  directory without the grant, so the start read files `render()` could not. Now each file passes
  the same check as `render()` before it is opened. One the start cannot read yet (its
  `require file.read` is inside the route) is not opened: a `note:` on stderr says so, and
  `render()` checks it when the route runs, as before. A template inside the bundle of
  `synsema build` does not need the grant. `synsema check` and `synsema build` still read them, as
  tools of the project.
- **`synsema code check` (and the `check` tool of `synsema-code` over MCP) shows the warnings of
  `synsema check`**, with file and line: a call to a name that does not exist, a positional
  `fetch(url, method, …)`, a third optional argument by position, a secret in a URL or body that is
  not bound to a host, and the warnings of the static check (an alias that hides a module, a missing
  export, a route that captures a reserved URL). Before, it only listed missing capabilities.
- **SQLite says why it refuses `ATTACH` and `VACUUM INTO` a file.** The message now explains that a
  query cannot open a database the program did not declare, and to use `db_open` (which needs
  `require db(...)`). Before, it was SQLite's `not authorized`.
- **`svg_to_png`/`svg_to_pdf` with `opts.fonts` reuse the restricted fallback copy across texts.**
  The cache key had every character of the SVG (text and markup), so a server rendering a different
  text per request rebuilt the copy each time. The key is now what the copy carries: two texts that
  miss the same glyphs share it.
- **A `serve` process sweeps the request-body spill folders that dead processes left in the temp
  folder** (`synsema-spill-*`, after a kill or a crash), once, when it first spills a body. Only
  real folders (not links), untouched for a day, with only files as old; on Unix, also of the same
  owner and with mode `0700` (on Windows the temp folder is per user and neither is checked). The temporary
  files of an atomic write (`<name>.<random>.synsema.tmp`) that a crash leaves next to the file are
  not swept (it would cost a folder listing per write); they can be deleted.

**New.**
- **Sealed receipts for an auditor: `--auditor <X25519 public key>`** (or `SYNSEMA_AUDITOR_KEY`)
  on `synsema run` and `synsema serve`, and `auditor` in wasm. With labels on, what a program does
  in a branch decided by a private value had to be refused (a signature, a `reveal`, an audit line
  would tell which branch ran). With an auditor the host designates, it runs, and what it leaves
  goes into an envelope only the auditor can open: HPKE (RFC 9180, X25519 / HKDF-SHA256 /
  AES-128-GCM) of a **fixed size** (`SYNSEMA_RECEIPT_SEALED_BYTES`, 64 KiB by default), so the
  receipt is as long after 0 sealed entries as after 50. What does not fit is cut inside and
  counted.
  - The receipt is one JSON line: a header (engine, `program_sha`, `config_sha`, the signing key,
    the auditor, a commitment to the run's seed), the public entries, the envelope, the root of a
    hash chain over all the entries in run order, and a signature. Anyone can check it with
    `synsema receipt verify` (on the file of `serve --receipt`, one receipt per line, it checks all
    of them and names the lines that fail, also a line that begins like a receipt and is not one,
    such as a receipt cut short; each receipt stands alone, so a receipt deleted whole from the
    file, or cut before its first key, is not noticed); the auditor opens it with `synsema receipt open
    <receipt> --key <private | @file> [--line N]`, which also checks the chain. `synsema receipt
    keygen` makes the auditor's keys; with `--out <file>` the private key goes to a new file (0600
    on Unix) and only the public one is printed.
  - It is signed with the host's `SYNSEMA_IDENTITY_KEY` if there is one, with the attested key
    under `serve --attested` (P-256; the same key the attestation document names), or with a key
    made for the run (`"identity": "ephemeral"`). An ephemeral key only detects accidental damage:
    whoever can change the receipt can make a new one, envelope and signature included. For tamper
    evidence, use `SYNSEMA_IDENTITY_KEY`, `run --attest` or `serve --attested`.
  - **It comes out before the output.** `run` writes it to stderr or to `--receipt <path|fd:N>`
    and only then prints; with an auditor `print`, `flush()` and the prompt of `read_line` do not go
    out live (`eprint` does: it is a sink, and it goes to stderr as it runs). A `--receipt` that
    cannot be written, or an auditor key that cannot seal, is an error before the program runs
    (and a receipt already in that file stays until a run writes its own).
    `fd:N` is Unix only, and N is a descriptor the parent left open: the program's children
    (`proc_spawn`, `run`) inherit it too. `run --format json` puts it first, as `receipt` (and also
    writes it to `--receipt`); wasm returns it in `receipt`. A binary from `synsema build` reads
    `SYNSEMA_AUDITOR_KEY` too.
    `serve` writes one per request that runs program code, to stderr or appended to `--receipt`,
    before the response; if it cannot be written the client gets a 500 instead. A `stream` or
    `socket` route is a load error with an auditor (its body leaves while it runs).
  - `reveal` and `sign` run in a private branch; their audit line goes into the envelope. **`spend`
    does not** (it spends a shared budget, and whether the next spend fits would tell what the
    branch did), nor a signature that counts against `SYNSEMA_SIGN_CEILING`, nor an operation that
    creates or returns a new secret (`mnemonic_generate`, `hd_derive`): a secret carries no label,
    so the branch would be lost in it. (Corrected in v0.6.49: this line said "the wallet operations"
    run there.)
  - The run's `random()` and `random_int()` come from a seed recorded in the envelope (each item
    of a `parallel_map` has its own stream, also under `--replay`), and with labels the clock is
    fenced in the whole program: `now()` returns the reading of the last public moment (the first
    reading, then each sink or outside read that runs with the program counter public; `print` and
    `eprint` do not count), so two `now()` in a row read the same time, and so does a `now()` after
    a loop over a private value. (Corrected in v0.6.49: this line said only "in a private
    branch".) The clock readings take at most a
    quarter of the envelope; past that they are counted (`clock_truncated`) and never push out an
    entry. Each reading is stored as text (`"1792711237.7256045"`), so it comes back bit for bit.
    `synsema run --replay <opened receipt>` runs the program again with that seed and those clock
    readings and stops, naming it, at the first input that differs. Keys and tokens
    (`random_bytes`, `token`, key generation) still come from the OS and are not reproduced.
  - **`run --attest` with an auditor binds the receipt's key:** `report_data` gets `sha256(run_key)`
    at the end, and the JSON line carries `run_key`. Without an auditor `report_data` does not
    change. A verifier of `run --attest` documents has to add it when `run_key` is present.
  - **What it does not hide:** that the run touched private data (`steps: null` already says so);
    the wall-clock time of the run (and, in wasm, when each host call arrives); and whether it
    stopped on a limit (`maxSteps`, `maxMemoryMb`, a handler's `timeout`): one bit per run, or per
    request. Under `serve`, a cron job or an agent outside a request has no receipt, so an audited
    operation in a private branch there is still refused; so is one that an agent started by a
    request (or by `run`) attempts after the receipt was built.
- **A secret bound to a host: `require secret("K") for net("api.example.com")`.** APIs that take
  the key in the URL (Alchemy, Infura, Telegram, Maps), in the query or in the body (OAuth
  `client_secret_post`) were an error, and the only way out was `reveal()`. A bound secret goes in
  the URL (`` `https://h/v2/{k}` ``), the query, a JSON body at any depth, a form or a header, only
  to the hosts it names (several: `for net("a.x.com"), net("b.x.com")`; a subdomain wildcard
  `*.x.com`), and only over https or wss (http and ws only to `127.0.0.1`, `localhost`, `::1`).
  - The host of a request never comes from a secret: in a URL that is a secret, the scheme and
    host have to be written out before it (`https://{k}.evil/`, `https://{k}@h/` and
    `https://h{k}/` are errors).
  - Adding two bound secrets keeps the hosts both allow (none in common is an error); `bearer`,
    `basic` and `oauth_basic` keep the binding of what they wrap.
  - An unbound secret still goes only in a header; in the URL, the query or the body the error now
    gives the exact line, with the host: `require secret("K") for net("api.example.com")`.
  - What the server echoes back (the body, the headers and the error of the response, a WebSocket
    text frame, a JSON-RPC error) is masked: each secret that went out, as is, percent-encoded,
    JSON-escaped or in base64, becomes `[secret K]`. It is a defense against an accidental echo,
    not against a hostile server; the guarantee is the binding.
  - The audit gets one entry per bound secret sent, `secret(K) → host` (source `bound-send`), and
    `lineage()` (and the receipt's `inputs`) names the secrets of each request in `secrets`; never
    the URL nor the value.
  - The host ceiling can bind too: `--cap-set secret=K@api.example.com` (or a delegated ceiling,
    `run_program`'s `ceiling`). A program that asks for `K` unbound, or bound to another host, gets
    the line to write. A child whose ceiling asks for `K` unbound gets nothing above its parent's
    binding.
  - `evm_rpc` and the other JSON-RPC builtins, `algod`, `btc_rpc` and `ws_connect` take a bound
    URL.
  - `synsema check` warns an unbound secret that goes in the URL, the query, the body or the form of
    a request, with the line to write.
  - A secret derived from a bound one (`hkdf_sha256`, `hd_derive`) is a new secret and is not
    bound; `as_secret` makes an unbound secret.
- **Private data can reach a model the host chose, and the answer stays private** (with
  `--labels`). Until now any private value in `reason`, `analyze`, `decide`, `generate`, `judge`,
  `llm_step` or `llm_stream` was a `label_violation`. Now the program declares whose data it may
  send (`require llm("customers")`, `require judge("customers")`) and the host allows it per
  principal and per provider in its ceiling: `--cap-set "llm=customers@api.anthropic.com"` (the
  host of `SYNSEMA_LLM_BASE_URL`, or the provider's default), `llm=customers@local` for a model in
  the process (`SYNSEMA_LLM_PROVIDER=local`, the judge `laya`), `llm=customers@embedder` in wasm
  (the host's `llm` hook). An item without a provider (`llm=customers`, `llm=*`) does not allow
  private data; `llm=customers@*` allows any provider, written on purpose. An item with a scope
  also allows the calls with public data, to whichever provider is configured. The program does not name the provider: the host picks it, and the
  check follows the provider of each call (one that reloads its `.env` and changes host is checked
  against the new one). A `decide` answered by the judge (`SYNSEMA_JUDGE_DECIDE`) is checked
  against `judge=`. Without the ceiling item, or under a private branch, it is still a
  `label_violation` and nothing is sent. With it, the prompt carries the data itself (before, the
  few cases that got through sent `private(customers)`), the answer carries the label of what went
  in (the whole map of `llm_step`, so choosing a tool with `r.name` needs a `declassify`, which
  has its own ceiling; each chunk of `llm_stream`, whose callback runs under the label of the answer,
  like the body of an `each` over a private list: how many chunks there were is private too, so a
  public effect in it is a `label_violation`), and each call writes an audit entry
  (`llm("customers@api.anthropic.com")`, source `llm-data`). In the receipt's lineage the answer
  to a private prompt is hashed with the prompt's salt and its length is left out. A bare
  `require llm` still means public data only, and `require llm("P")` now also covers public data
  (before it broke every LLM operation). In wasm the `llm` hook gets a third argument,
  `{principals}`, the owners of the private data in the prompt. **What this does not give:** the
  provider sees the data (this allows a provider the host trusts; it does not protect the data
  from it); what the model answers is private but not trusted (a `declassify` with its ceiling is
  what stands between it and a sink); and the size of the prompt is visible on the network, as in
  any `https` request.
- **Trusted tools: the host loads a module of its own, and code it does not trust can only call
  it.** `synsema run --trusted tools=./tools.syn app.syn` (repeatable; `trusted: {tools: source}`
  in wasm) and, in the program, `use "trusted:tools" as t`. Each exported task of a trusted module
  runs with **its own** `require` (bounded by `--trusted-cap-set`, `trusted_ceiling` in wasm, if
  the host gives one) and nothing from the caller: not its grants, not its ceiling, not a
  `sandbox`. So a program written by a model, under a ceiling without `declassify`, cannot publish
  a customer's data, but it can call `t.reply(customer, text)`, whose policy (written by a person)
  declassifies only the customer's own address. With `--trusted-cap-set`, a trusted task gets what
  it declares (`require declassify("customers")`, `require net("mail.example.com")`) within that
  ceiling; without it, it declassifies like a program without a ceiling (any principal), so give
  the trusted modules a ceiling. Its arguments are data: a task, a lambda or a builtin among them
  (also inside `ok(...)` or `content(...)`) is an error, since it would run with the tool's
  capabilities. A trusted module sees the builtins and its own names, never the program's: a
  program that defines `upper` before or after the `use` does not change what the tool runs. A
  task of the program that would still run inside a tool (a callback such as the `on_reconnect` of
  a WebSocket the program opened and passed to the tool) is an error there, not a call with the
  tool's capabilities. And a
  program cannot change a trusted module: `set t.x to …` changes only its own copy of the module's
  exports, and another `use` sees the original. Its audit entries carry the module's name
  (`trusted:tools`). A program cannot load a trusted module itself: the name comes only from the
  host (an unknown one is a load error), and the program never sees the path. **What it does not
  do yet:** inside a trusted tool, what would run in another interpreter next to the program's
  names is an error (defining or spawning an agent, `parallel_map`, `cron_every`/`cron_after`, a
  `use` of a file module; a trusted module can `use` another trusted one); so is `render` (with its
  `include`s and layouts), since the template file lives where the program can write it and it would
  run with the tool's capabilities: a tool builds its text itself. `--trusted` runs
  under `synsema run` and `synsema test`, not `serve`. With trusted modules the whole program runs
  on the tree-walker, without the bytecode VM.
- **`form = {...}` in `http`, `http_bytes`, `http_post`, `http_put` and `fetch`** sends an
  `application/x-www-form-urlencoded` body (the encoder of `oauth_basic`). Fields are text, a
  number, a bool or a bound secret; `body` and `form` together are an error.
- **`enumerate` takes an array** and walks its first axis, like `length(a)` and `a[i]`: each `item`
  is a number (1-D) or the row. A 0-d array is an error that says so.
- **Clearer errors.** `log(x)` says which logarithm to use (`ln`, `log10`, `log2`, `log_base`) and
  that `log "message"` is the log statement; `in_units` with a number shows how to make the
  duration (`in_units(duration(seconds = 90), "minutes")`). A named argument that a task or a
  builtin does not have lists the ones it has and the closest one (`unknown parameter 'limt' —
  did you mean 'limit'?; the parameters are: limit, offset`); before, a misspelled name on a task
  said that the right one was missing.
- **The receipt names what the run wrote.** `credentialSubject.outputs` lists each `write_file`,
  `append_file`, `edit_file`, `zip_extract` and `tar_extract` with `source`, `what` (the path),
  `sha256`, `bytes` and `encoding`, in order: a trained model written to disk is in the receipt
  without hashing it by hand. `what` is the path as the program wrote it (for an extraction, the
  destination as written plus the entry's name). `append_file` records the appended chunk;
  `edit_file`, the file as it was left. What the workers of `parallel_map` read and write is
  included, in the order of the items (their `inputs` were missing too), also when an item fails:
  what the workers read and wrote until then stays in the receipt. Under `serve`, `inputs` and
  `outputs` are those of the request (before, `inputs` also listed what earlier requests of the
  same worker read, which could be another user's). The same in the handler mode of
  `@synsema/wasm`: what the top-level read is no longer in the first request's receipt. The same cap as `inputs`, 10 000 entries;
  `inputs_truncated`/`outputs_truncated` now mean that an entry was dropped (they were `true` with
  exactly 10 000). With `--auditor`, each write also goes to the sealed receipt (`kind: "output"`),
  in the order it happened: the writes of `parallel_map` workers, in the order they were made, not
  of the items (as their `capability` entries).
  A write under a private context is refused (writing is a public sink), so it never reaches
  `outputs`. The `sha256` has no salt, as for `inputs`: after a `declassify`, the hash of a short
  value (a PIN) can be guessed by trying. An `append_file` that fails half-way can leave bytes on
  disk that are not listed.
- **`parquet_scan(path, opts)`** reads a Parquet file from disk by parts: only the footer, the
  row groups and the columns that `opts` asks for (`columns`, `row_groups`, `limit`, the same
  options and the same checks against hostile files as `parquet_read`). It needs `file.read` and
  is a lineage input with the path. `parquet_read(bytes)` is unchanged.
- **`discovery off` in a `serve` block**, for an edge that only forwards with `proxy to`: the
  server generates none of `/llms.txt`, `/openapi.json`, `/sitemap.xml`, `/robots.txt`, `/docs`,
  the Agent Cards and `/.well-known/synsema-auth`, and they reach the program's routes like any
  other URL (a `GET /*path` forwards them; without a route they are 404). Before, an edge had to
  declare each reserved URL as a literal route, and every new one the engine added published the
  edge's own page in silence. That includes `/robots.txt` with `private` too, and `private` still
  hides `/.well-known/synsema-auth`. (Corrected in v0.6.49: this line said `private` still answered
  `/robots.txt`.) `/.well-known/attestation` is identity, not discovery: under
  `--attested` it is still served and a route still cannot take it. Under `--attested`, a literal
  route on a reserved URL is still a load error (a `GET /*path` does receive them).
  `synsema openapi` still describes the routes: it is an offline tool you ask for.
- **Types on task parameters: `task estado(id: text, items: bool = false)`.** The same five types as
  `expect body` (`text`, `number`, `bool`, `list`, `map`); an unknown type, or a literal default of
  another type, is a load error. They are metadata, checked only where arguments arrive as data:
  `call(task, map)` and `call_tool(task, map)` reject a value of the wrong type or a missing typed
  parameter without a default (`call_tool(add): 'a' must be number, got text`), strictly, without
  converting; a normal call does not check them and costs nothing. A secret counts as `text`.
  - `tool_spec(task, describe)` builds the `llm_step` catalog entry from the signature
    (`{name, describe, params: ["a: number", …], optional: [...]}`), so the catalog is no longer
    written by hand. A catalog parameter can be `"name: type"`, and `optional` takes names out of
    `required`. The hosted providers (Anthropic, OpenAI-compatible) send each declared type in the
    tool's JSON Schema; the `local` provider lists them in its prompt (`a (number)`,
    `[optional]`). An argument the model returns for a typed parameter comes back with its type when
    it decodes to that type (`2` and `"2"` both give the number 2; an argument for a `text`
    parameter stays text); one that does not decode stays text and `call_tool` rejects it. A `null`
    for an optional parameter, or for a typed one other than `text`, counts as not passed (the
    default runs, or `call_tool` says it is missing). The model's JSON `null` and the text `"null"`
    arrive the same, so `"null"` for an optional `text` parameter also runs the default. From the
    program, `call_tool(f, {"n": nothing})` is still an error unless the default is `nothing`. Before, every argument arrived as text;
    parameters without a type still do. A parameter whose default is `nothing` accepts `nothing`
    in `call` and `call_tool`, and its `input_schema` has no `default`.
  - `synsema code outline --json` publishes, per task, `parameters` (name, type, required, literal
    default) and `input_schema` (the signature as JSON Schema); `params` is unchanged.

## v0.6.45 — 2026-10-20

**Behavior changes (read these first).**
- **A `*` in a file scope stays inside one folder.** Path scopes are now globs by segment, like
  gitignore and shell globs: `*` and `?` match within one path segment, `**` crosses folders (and
  `./data/**` also covers `./data` itself), and no wildcard matches `..` or jumps from a relative
  path to an absolute one. Before, `*` matched across `/` and `..`: `require file.read("./*")`
  granted `/etc/passwd`, and `file.read("*.csv")` any `.csv` on the disk, while the docs called them
  "this folder". To read a folder with its subfolders, write `./data/**`; `./data/*` is its files.
  `cwd()` now needs `file.read(".")`, `"./**"` or `"**"` (`"./*"` names the files, not the folder).
  The whole-disk grant is still `require file.read` with no scope.
- **`static "/x" from "./public"` needs `require file.read("./public/**")`.** Serving a folder is
  reading it, and the file is chosen by a remote client; before, nothing was declared (even
  `static "/" from "/"` served the disk). The error at startup says the exact line to add. A folder
  that travels inside a `synsema build` binary is part of the program and needs nothing, as with
  `read_file`. The `--pwa` and `--desktop` templates carry the line.
- **`{ include }` and `{ layout }` read from disk need `file.read`, like `render()`.** Before they
  were only kept inside the working directory, so a program that can write templates could include
  `.env` in a page without declaring it reads it.
- **`grep` on a folder needs `file.read("<folder>/**")`.** It reads the whole tree; with the new
  globs, `file.read("./proj")` is the folder alone. Same as `static`.
- **`edit_file` needs `file.read` as well as `file.write`.** It reads the file to find the text,
  and its answers (not found / ambiguous / how many replaced) tell whether a text is inside.
- **`tls cert "<c>" key "<k>"` in a `serve` block needs `file.read` on both files**, like
  `mtls_identity`. The `--tls-cert`/`--tls-key` flags are the operator's and need nothing.
- **A `static` folder that travels inside a `synsema build` binary is served only from the bundle:**
  a file that is not in the bundle no longer falls back to the disk without a grant.
- **SQLite refuses `ATTACH DATABASE '<file>'` and `VACUUM INTO '<file>'`,** with the name written
  out or computed (`ATTACH ? AS x`, `'a' || '.db'`), and the pragmas `temp_store_directory` and
  `data_store_directory`. They opened or created any file without `require db(...)` (and, with an
  SQL injection, the attacker picked the path). Open another database with `db_open`, which is
  gated. A plain `VACUUM` and `ATTACH ':memory:'` still work. `db_open` refuses a `file:` URI
  (`file:/etc/x.db`, also written `./file:…`) and a path with `://` that is not a known server: they
  name another place than the one the scope sees; open the database by its path. Connections run in
  SQLite's defensive mode: no `PRAGMA writable_schema`, no `journal_mode=OFF`, no hand writes to the
  schema or to FTS5's internal tables (FTS5 views, triggers and `rebuild` still work).
- **With labels on, a `require` in a branch decided by a private value (or with a private scope)
  is a `label_violation`:** what is granted cannot depend on private data (a later public
  `try random_int(...)` published the branch). Declare capabilities at the top of the program. The
  same holds for a `require` inside a `task` (it is the tool's ceiling in `call_tool`): a task with
  a `require` whose scope is private, or defined in a private branch, is a `label_violation`.
- **With labels on, an operation that writes the audit log (`sign` and the signing builtins,
  `spend`, `reveal`, the wallet operations) does not run in a branch decided by a private value.**
  Whether its audit entry existed told the operator (or the wasm host's `kv`) which way the branch
  went. It now fails with `label_violation` and writes nothing; decide with a public value, or
  `declassify` the condition first (that leaves its own record). A sealed run receipt that audits
  these without revealing the branch is planned for the next version.
- **`run_program` refuses an `env` that sets `SYNSEMA_*` variables or the ones the engine uses to
  pick host paths** (`HOME`, `USERPROFILE`, `TMP`/`TEMP`/`TMPDIR`, `APPDATA`, `XDG_*`,
  `OLLAMA_MODELS`, `HF_*`: `SYNSEMA_AUDIT` made the child create or truncate any file, `HOME` chose
  where `reveal` audits), **a ceiling whose scope has a comma or is empty** (it split into extra items:
  `{"file.read": "x,exec"}` gave the child `exec`), **and a `filename` with folders** (it is a label;
  with a folder, the child's `memory` state landed there). The child keeps its state and its
  temporary files where the parent keeps its own — the folder of the parent's `memory` database,
  absolute (with several programs in one `synsema test`, the one of the program that calls) — never
  in the `cwd` the program passes nor next to the module that calls; a parent whose memory does not
  persist (stdin, `--profile pure`) gives the child none, and the child's memory lives in memory
  for that run (also with `profile: "pure"`, the default: a pure child never touches the disk). A
  `"native"` child whose ceiling grants `memory=m` shares `m.db` with the parent — also from a
  `cron` tick or a `serve` handler: each process now writes only the entries it changed, the
  child's new ids carry a mark (`mem_<n>_p<process>`) so they cannot collide with the parent's, and
  when the child returns the parent reloads the base. Before, the child rewrote every entry from its
  own snapshot (a `forget` the parent did meanwhile came back) and the parent's next `remember`
  reused the id of the child's entry and overwrote it. Without a home
  directory to fall back on, a `memory` that cannot get its folder lives in memory for that run
  (it was a relative path, created in the working directory).
- **`env(name, nothing)` and `secret(name, nothing)` give `nothing` when the variable is not
  defined.** Before, the default went through its Python text form: `env` gave the text `"None"`,
  which passed as a valid value (an address, a name) and failed far from the cause, and `secret`
  sealed the text `"None"` (sent as a header it went out as `Bearer None`). Check it with
  `when v == nothing`. A defined variable still wins over the default, and without a default an
  undefined variable is still an error.
- **A bool default of `env` is Synsema text:** `env(name, true)` gives `"true"`, not `"True"`. A
  number keeps its text (`env("PORT", 8080)` → `"8080"`).
- **`read_file` says why it cannot read a file.** Everything was `File not found`, even a file that
  exists: one another process holds open without sharing (`in use by another process … retry
  later`), a folder (`it is a directory`), a broken link, a file that is not UTF-8 text
  (`use read_file_bytes`), or a permission. `File not found` is now only for what does not exist.
  Same for `read_file_bytes` and `edit_file`.
- **`svg_to_png`/`svg_to_pdf` refuse a `<text>` longer than 16 384 characters** (counting its
  `tspan`s and the text a `<tref>` pulls in, with entities expanded, and inside an SVG embedded in a
  `data:` URL; also for the icons of `synsema build --icon` and `synsema init --pwa`). The renderer lays a
  text out in a time that grows with the square of its length: 16 k characters take 0.3 s, 64 k
  2.6 s, 128 k 10 s, 400 k several minutes. A title that comes in the data could hold a `serve`
  worker for minutes. The error says how many characters there are; raise the limit with
  `{"max_text_chars": n}`, like `max_pixels`, or split the text into several `<text>` (the limit is
  per `<text>`, so a long document with one `<text>` per line is not affected). Content the renderer
  draws many times (`<use>`, markers, masks) multiplies the cost of the text inside it; a limit for
  that comes in a later version.

**Fixes.**
- **`svg_to_png`/`svg_to_pdf` refuse a font in `opts.fonts` that would make every lookup slow**
  (more than 16 character-map subtables, a format 13 subtable with more than 4096 groups, a face
  with more than 64 tables), take at most 16 fonts with at most 64 faces in total (a collection
  counts all its faces: pass the single faces you use instead of a whole "Super OTC"), and try at
  most 16 fallback fonts for one run of text (beyond that, the rest is shown as missing glyphs): the
  renderer looks every font up for every character and reshapes the whole text with each fallback,
  and crafted fonts made a render take minutes. The error names the font. Real fonts (one CJK
  collection per weight, color emoji, variable fonts, Apple's LastResort) are accepted.
- **`svg_to_png`/`svg_to_pdf` with `opts.fonts` fall back per glyph.** A title in your font with one
  character it lacks (an arrow, an emoji) came out entirely in the fallback font; now only that
  character does, and the rest keeps your font, as in a browser. Without `opts.fonts` the output is
  byte for byte the same. When the per-glyph layout would leave a missing glyph (your font forms a
  ligature or a combining mark in that text, or the fallback is a `.ttc` collection), the whole
  document is laid out as before, where the fallback replaces the run. A font with a malformed
  character map is used as before, without a per-glyph copy, and so is every pair of fonts after
  the first 16 in one document (each per-glyph copy weighs as much as its fallback font).
- **`judge` and the LLM operations inside `parallel_map` and inside a `spawn`ed agent** use the
  same providers as the code that started them. Before, each `parallel_map` item and each agent
  under `synsema run` ran in a fresh interpreter without providers: `judge` answered OFFLINE
  (`available: false`) and `reason`/`decide`/`analyze`/`generate` gave their placeholders, while
  the same code on the main thread got real answers. Under `serve`, agents were already wired. The
  process token budget (`SYNSEMA_LLM_BUDGET`) holds inside them too.
- **A WebSocket or TCP peer that goes away without closing (a reset: the process died, the network
  dropped; `os error 10054` on Windows) arrives as a `close` event with `connection reset by peer`**
  (TCP: `{type: "close", reason: …}`; WebSocket, with the same field its close events always had:
  `{type: "close", data: …}`). Before, `select` (and `ws_recv`/`tcp_recv`) raised `select: connection N: IO error: …`
  and the error cut the wait of every other connection in the same `select`. Sending on that TCP
  connection afterwards is an error that says the other side is gone. A protocol violation (an
  invalid frame, a message over the size limit) is still an error, as before.
- **`exit(code)` works in a `serve` program before it listens.** A single-instance desktop app can
  now do "if another instance is running, ask it to show its window and leave" in the lines before
  `serve on`: the process ends with that code and no error (before it was `exit() ends a synsema run
  program…`, and `synsema serve` exited with 1). Once the server listens, `exit` is still an error
  — it would cut the requests in flight — and `shutdown(reason)` is the way out, as before.
- **Windows: a `--no-console` binary no longer opens a console window for each child.** `run`,
  `proc_spawn` and `run_program` with pipes created the child (`ssh`, `git`, `powershell`) with its
  own visible console window, which the user could close and kill the process with. When the
  process has no console, children are now created with `CREATE_NO_WINDOW`. With a console (a
  program run from a terminal) nothing changes: the child shares it, so `ssh` can still ask for a
  password there.

**Security.**
- **A link no longer takes a path out of its limit.** `use`, the `file`/`file.read`/`file.write`
  scopes (the program's `require`, the host ceiling and a delegated ceiling) and `grep` compared
  paths by name, so a symlink or a junction under the allowed folder that pointed elsewhere passed:
  `use "./ext/o.syn"` loaded code from outside the project (what was approved by hash was not what
  ran), and `read_file("data/ext/x")` read outside `file.read("./data/**")`. Now the path is also
  judged where it really leads:
  - A link that IS part of the granted path (the project reached through a link, `./data` itself a
    link) still works; a link below it that leads out is refused with its own message (`a link
    (symlink or junction) on the way leads outside it`). A `deny` of a place also catches a path
    that reaches it through a link.
  - A broken link is followed to where it points: writing through `data/log.txt ->
    ~/.ssh/authorized_keys` (target not created yet) is refused, for `append_file`, `zip_extract`,
    `db_open` and the rest. If a path cannot be resolved, the answer is no: a link target with `..`
    after a name (which the system resolves through that name), a volume without a letter or a
    network share as a link target.
  - The temporary file of `write_file`/`edit_file` has a random name and is created with
    `create_new`, so a link planted with its name is never followed (it was `<path>.synsema.tmp`).
  - In a case-sensitive folder (those WSL creates), `DATA` and `data` are different places; a scope
    at a drive root (`C:/**`) covers the drive (it covered nothing); a `\\?\` path is resolved.
  - `grep` does not follow links to folders, and respects a `deny` inside the tree it searches.
  - `run_program` sends the child's ceiling with absolute paths, anchored where the parent decided
    them (with `cwd`, `./data` used to resolve against the child's folder).
  - `db_open`, `mtls_identity`, templates and `static` open the path that was checked (they checked
    the normalized path and opened the raw one).
  - A large request body spilled to disk goes to a private folder of the process, created once
    with a random name and mode 0700, each file 0600 and `create_new` (it was a predictable name in
    the temp folder, written through links, in a folder anyone could create first).
  - On Windows, a `/data` scope is compared as `<drive of the working directory>:/data` against a
    path with a drive, so a `run_program` child that declares `/data/**` fits the parent's ceiling.
  - Cost, only for file operations under a scoped grant: one disk query per path segment below the
    grant, up to four; deeper, or when a link shows up, the path and the grant are resolved on disk.
    Measured in release on Windows (every query goes through the antivirus), for a 54 µs read:
    +29 µs one level below the grant, +57 two, +80 three, +103 four, +117 deeper. Linux: +2.5 µs /
    +3.9 µs one and two levels below, for a 5 µs read. The interpreter is untouched.
  - What remains: the check and the open are two steps, so a link swapped in between is not caught
    (the fix is to open relative to the grant's folder with `openat2`/`RESOLVE_BENEATH` on Linux and
    `OBJ_DONT_REPARSE` on Windows: planned for the next version), and a hard link is not visible
    from its name.
- **RS256 signing (`jwt_sign` with `"alg": "RS256"`, `rsa_sign_sha256`) is constant-time or
  blinded.** The `rsa` crate is not constant-time on private-key operations (RUSTSEC-2023-0071,
  "Marvin"; no stable fix upstream) and the signature did not even use blinding. The native binary
  now signs with `ring` (BoringSSL, already in the binary for TLS) the keys `ring` accepts: 2048 to
  4096 bits, e ≥ 65537, two primes. Other keys (1024 or 8192 bits, e = 3, multi-prime), and every
  key in the wasm build, where `ring` does not compile, are signed by `rsa` with blinding. The
  signature bytes are the same either way. Blinding needs entropy: a wasm host without
  `host_random_fill` now gets an error instead of a trap. The audit configuration claimed the crate was only used to verify,
  which stopped being true in v0.6.20; it now says what is true.
- **Dependencies with advisories updated:** `rustls` 0.23.46 (RUSTSEC-2026-0346…0349), `zip` 9
  for `zip_extract`/`zip_create` (RUSTSEC-2026-0367…0369 — never reachable through `zip_extract`,
  which never used the affected `extract`), `lru` 0.18 (unsound `pop`), and `rust_decimal` 1.43,
  which drops `rkyv` 0.7 from the lock. `mysql` 28.0.4, `chacha20` and `private-gemm-x86` replace
  yanked versions. `cargo audit` is clean, also for the lock of the Vela guest, which CI now audits
  too (it still had `rkyv` 0.7).
- **`proc_spawn(…, {"pty": true})` no longer passes Synsema's secrets to the child.** Since the
  v0.6.14 audit, `run` and `proc_spawn` remove the provider keys, the human-channel secrets and the
  names loaded from `.env` from a child's environment, so a program with `exec` but without
  `env`/`secret` cannot read them with `printenv`. The pseudo-terminal path skipped that step: a
  child started with `pty: true` saw, for example, `ANTHROPIC_API_KEY`. It is removed there too.
- **`@synsema/wasm` with labels on now refuses private data at the host's hooks.** The embedded
  engine turned labels on but registered no sinks: `print` redacted, while `fetch`/`http_*` to
  your `http` hook, `state_set`/`remember` to your `kv` and a branch on a private value went out
  with the data in clear (natively the same programs gave `label_violation`). The wasm now uses the
  same sink list as the native engine, and a test fails if a new wasm builtin is left
  unclassified. The JS package also forwarded nothing: `labels`, `result` and `input` (with
  `sources`) are now passed through and typed.

**New.**
- **`tcp_write(conn, data)` and `pipe_write(end, data)`** take what fits right now and return how
  many bytes they took, never waiting (`0` = full right now). `tcp_send`/`pipe_send` stay
  all-or-timeout. A loop that serves many streams credits each one with what it really took,
  instead of parsing the text of a timeout error.
- **`pipe_stats(end)`** → `{queued_in, queued_out, status}`, like `tcp_stats`.
- **`state_merge(key, map)` and `state_cas(key, expected, new)`** under `serve`, both atomic.
  Read-modify-write of a shared map with `state_get`/`state_set` lost writes under concurrency (13
  simultaneous webhooks left 7 entries). `state_merge` merges the map into the stored one (shallow)
  and returns the result; merging into a value that is not a map is an error. `state_cas` writes
  `new` only if the current value equals `expected` (a missing key is `nothing`; `2.0` equals `2`,
  as in the language) and returns whether it wrote. `state_incr` was and stays the atomic counter.
- **`{"env_clean": true}` in `run` and `proc_spawn`**: the child starts with no environment from
  the parent, only what the program passes in `env` (plus `SystemRoot` on Windows, without which
  the C runtime and sockets do not start). Without it, the child inherits the environment minus
  Synsema's secrets, as before. The command itself is still found on the parent's `PATH`; pass
  `PATH` in `env` if the child starts other programs.
- **`synsema check` warns a call to a name that exists nowhere**: `without(xs, k)` with no `task
  without` and no builtin of that name passed `check` and failed only when that line ran. The
  warning names the line and, for a Python reflex (`len`, `str`), the Synsema form. It only fires
  when the name is not a builtin and is not defined or used as a value anywhere in the file, so it
  gives no false positives (run over 2325 `.syn` files: only deliberate cases). A warning does not
  change the exit code.

- **`@synsema/wasm` for untrusted code in a server.**
  - `maxSteps` and `maxMemoryMb` per call, in both modes (in `handle`, for each request): the run
    ends with `ok: false` and an error that says which limit it hit, never a trap. `maxSteps` counts
    deterministic interpreter steps from the start of the run; `maxMemoryMb` counts the bytes the
    run reserves — the module's allocator refuses the reservation that would go over (it counts
    bytes requested; the module's own memory can grow up to about twice that and is not given
    back). A `0` is an error, not "no limit". No call inherits the limits of the previous one. Cost in the wasm build: counting allocations is ~3–4 % on
    allocation-heavy code without limits; with limits on, 1–3 % when allocating and 9–14 % on a
    tight compute loop. The native binary compiles none of this.
  - `timeoutMs` in the async API, counted from when the call starts running (not while it waits in
    the queue): past it the call fails with a clear error and its Worker is replaced, so the
    server's thread never blocks. A host hook already running (a `fetch`) is not cut; its result is
    discarded.
  - Async calls wait in one queue and go to a free Worker, so a burst spreads over `workers: n`. A
    Worker that dies fails the call it was running (not retried: it may have had effects) and is
    replaced. `close()` is final: what waits fails with "closed", including on a Worker still
    starting. A Worker that does not start in `startMs` (default 30 s, an option of `Synsema.load`)
    is stopped. A host hook that returns something that is not JSON (a `BigInt`, a circular object)
    or throws a value without a message is an error of that call, in both APIs, not a hung Worker or
    a trapped module; `timeoutMs` is 0 (no deadline) or a finite number of milliseconds up to 2³¹−1.
  - With `labels`, `sleep` is a sink in the wasm build: its number crosses to the host's `sleep`
    hook, so a private value (or a private branch) cannot reach it.
  - With `labels`, `steps` is `null` when the run touched a private value or branch (how many steps
    it took depended on the data), as in the native binary.
  - With `labels`, a capability check made inside a private branch leaves no audit entry (here and
    in the native `--audit`): how many entries there were told which way the branch went, or how
    many times a private loop ran. The sealed run receipt of the next version will record them
    without revealing the branch.
  - The host sees a fixed shape: each call asks it for 32 bytes of entropy once, which seed the
    run's own ChaCha generator (`random_bytes(n)`, `token`, `random()` and RSA blinding never ask
    again, so a private `n` does not show); and with `labels`, `now()` returns the clock read at the
    start and at each interaction with the host, so when and how often it was called does not
    show.
  - `kv_cas`: a host that does not answer, or answers `swapped` with something other than a bool,
    gets its own error (it read as "kept changing under concurrent writers"), and the package
    requires the host's `kv.cas` to return `true` or `false`. `handle` keeps a separate prepared app
    per `labels` setting and per set of host hooks.
  - Concurrent async calls queue instead of failing with "one call at a time per instance", and
    `Synsema.load(src, { workers: n })` spreads them over n Workers (concurrent calls at startup
    no longer create more Workers than `n`).
  - After a trap, the sync API recreates the instance by itself (before, the next call asked for
    `await syn.ready()`).
  - `Synsema.loadNode()` loads the `synsema.wasm` that ships in the package, so it works in Next.js
    routes and Server Actions without resolving paths. The README's
    `new URL("@synsema/wasm/synsema.wasm", import.meta.url)` never resolved a package name and is
    replaced.
  - `state_merge` and `state_cas` exist in wasm too. With the host's `kv` they are atomic only if it
    offers `kv.cas(ns, key, expected, value)` (new, optional); without it they say so instead of
    risking lost writes. Without a host `kv`, the state belongs to the instance and is atomic.

- **Data builtins** (pure, in the native engine, `--profile pure` and wasm unless noted):
  - `gzip(data)` / `gunzip(bytes, {"max_bytes": n})` for loose `.json.gz`/`.csv.gz` files.
    `gunzip` reads concatenated members and stops a bomb: by default it refuses more than the larger
    of 256 MiB and 64 × the input. `gzip` is deterministic (no name or time in the header).
  - `url_encode(text)` / `url_decode(text)` (RFC 3986). Everything but `A-Z a-z 0-9 - . _ ~` is
    encoded; decoding is strict (a malformed `%` or invalid UTF-8 is an error) and `+` is not a
    space.
  - `header(r, name)`: a response header regardless of case (`get(r["headers"], "retry-after")`
    missed `Retry-After`). It takes a response or a map of headers (`request.headers`).
  - `parquet_read(bytes, {"columns": […], "row_groups": […], "limit": n})` reads a part of a file:
    the limits count only what is read, and the input is copied once instead of twice.
    `parquet_info(bytes)` gives the columns, the row count and the row groups without reading the
    data. (Native only, like the rest of Parquet.)
  - `chart_svg(…, {"x_axis": {"angle": 45, "every": 2, "format": "%b %d"}})` rotates, thins and
    formats the category labels under the X axis (bar, line, area, heatmap, boxplot, waterfall).
    `format` is the strftime of `format_time`. Without `x_axis` the SVG is byte for byte as before.
  - `qr_matrix(data, {"ecc", "version"})` → rows of 0/1, and `qr_svg(data, {…, "module", "margin",
    "dark", "light"})` → an SVG with the quiet zone (ISO/IEC 18004; `ecc` L/M/Q/H, default M).
  - `html_select(html, css)` → `[{tag, attrs, text, html}]` on real HTML (WHATWG parsing: unclosed
    tags, unquoted attributes, entities), `html_text(html)` → the readable text (no scripts or
    styles, one line per block) and `html_unescape(text)`. What they return keeps the input's
    labels: reading a private page does not make it public.

- **HTTP builtins take named arguments:** `http_get(url, headers = {…}, query = {…}, timeout = 10)`,
  `http_post(url, body, headers = {…}, timeout = 30)`, `http(method = "PUT", url = u, body = b)`;
  also `http_bytes`, `http_put`, `http_delete`. Positional calls keep working. An unknown name is an
  error, and so is passing the same argument by position and by name.
- **`list_dir` and `file_info` tell links apart:** each entry has `is_link`. A link's `is_dir` is
  that of what it points to, the same in both (a junction was `is_dir: false` in `list_dir` and
  `true` in `file_info`); in `list_dir` a link's `size` is 0 (ask `file_info`, which only answers
  when the link leads inside the grant).

**Deprecated.**
- **The positional form of `fetch(url, method, headers, body, timeout)` goes away in v1.** Write
  `fetch(url, {"method": …, "headers": …, "body": …, "timeout": …})`, the main form since v0.6.43.
  Until v1 the positional form still works and prints one notice per process to stderr;
  `synsema check` points at each call whose second argument is a text literal or `nothing`.
- **Beyond two optional positional arguments, pass them by name.** `http_get(url, headers, query,
  timeout)`, `http(…)`, `http_bytes(…)`, `http_post(…)` and `http_put(…)` with a third optional
  argument by position still work; `synsema check` says which name to use (`timeout = …`). The
  positional form of those goes away in v1. (An options map, as `fetch` has, would have been
  ambiguous here: the next argument is already a map — the headers, or a JSON body.)

## v0.6.44 — 2026-10-08

`hmac` with bytes, bit operations, values that leave as text are never their printed form, and the full list of drivers in the `serve --attested` notice.

**Behavior changes (read these first).**
- **`hmac`, `verify_hmac`, `hmac_sha256` and `constant_time_eq` use the raw bytes of a `bytes`
  argument.** Before, a `bytes` value was turned into its printed form (`bytes(6b6579)`) and that
  text was hashed: `hmac(bytes("data"), bytes("key"))` gave another MAC than `hmac("data", "key")`,
  with no warning. Now both give `0x5031fe3d…1bd0`, and binary keys can be chained (AWS SigV4,
  HKDF by hand). **Text gives exactly the same MAC as before**, so existing webhook signatures do
  not change. Any argument that is not text, bytes or a secret (a number, a list, `nothing`) is
  now an error naming the argument and its type, instead of being hashed as its printed form; the
  `algo` argument must be text. A `nothing` key used to be hashed as the text `"nothing"`, a key
  anyone can guess: it is an error now. `verify_hmac` also accepts the signature as the raw MAC in
  bytes; a text signature that does not decode is still `false`, and so is a missing one (`nothing`,
  the header did not come), so a webhook handler answers 401 and not 500.
- **Values that leave as text are never their printed form.** A header, a query parameter or
  `bearer(...)` takes text, a number, a bool or a secret. `nothing` (a missing env var or map key),
  `bytes`, lists and maps are an error naming the header or parameter: before, they went out as
  their printed form (`bearer(nothing)` sent `Authorization: Bearer None`). A secret in a query
  parameter or in a body (directly or inside a map or list) is an error: it used to go out as the
  text `secret(NAME)`, which the server took as the value. A sealed secret
  (`attestation_key()`) or a secret holding bytes that are not UTF-8 is an error wherever it would
  leave as text (headers, `bearer`, `btc_rpc` auth, a mnemonic or passphrase for the HD wallet
  builtins), never the placeholder `secret(NAME)`.
- **`+` with a secret follows the text rules.** Numbers and bools join as before; `nothing`,
  bytes, lists and maps are an error, as they are with text (before, with a secret they joined as
  their printed form: `secret + nothing` gave "…nothing"). A sealed secret is an error (it gave an
  unsealed secret holding the text `secret(NAME)`), and so is a secret holding bytes that are not
  UTF-8 (it changed silently, so a chained HMAC key came out different). A backtick template
  is unchanged: every hole shows its text (`token={tok} scopes={xs}` with `tok` a secret gives a
  secret holding the list as text, as without a secret); only a sealed secret or a non-UTF-8 bytes
  secret in a template is an error.
- **A bytes secret as a database parameter keeps its bytes** (SQLite BLOB, Postgres `bytea`, MySQL
  bytes, Mongo binary, Redis): it used to be converted to text, and bytes that are not UTF-8
  changed. A sealed secret as a database parameter is an error, also nested in a list or a
  document.

**New builtins.**
- `basic(user, secret)`: the `Authorization: Basic base64(user:password)` header value (RFC 7617)
  as a secret, materialized only at the socket — the pair of `bearer`. OAuth client credentials
  (RFC 6749 §2.3.1) and Basic-auth APIs could not be called with the password as a secret before
  without `reveal()`. The user cannot contain `:`.
- `oauth_basic(client_id, secret)`: the same for OAuth client credentials, with both parts
  form-encoded first as RFC 6749 §2.3.1 asks (a secret with `+`, `/` or `=` is rejected by strict
  servers otherwise).
- Bits on 64-bit signed integers: `bit_and(a, b)`, `bit_or(a, b)`, `bit_xor(a, b)`, `bit_not(a)`,
  `shl(x, n)`, `shr(x, n)` (arithmetic, keeps the sign). `n` is 0..63; a value outside 64 bits, a
  float, or a `shl` that overflows is an error — nothing wraps around silently.
- `xor_bytes(a, b)`: XOR of two `bytes` of the same length (different lengths or text → error).

**`serve --attested`.** The startup line names every driver and format, in order:
`Attested: drivers=tsm,nitro-tpm formats=sev-snp,nitro-tpm program_sha=… — GET
/.well-known/attestation` (it said `driver=`/`format=` with only the first one).

## v0.6.43 — 2026-10-08

Confidential VMs: AMD SEV-SNP reports verify, NitroTPM documents are produced and verified, one
attested server can publish both, and a Synsema client can pin the attested key. All of it is
hardware formats and pure primitives.

**Behavior changes (read these first).**
- **`program_sha` counts each module once.** The static check loads a `use`d module more than
  once, and up to v0.6.42 its hash went into `program_sha` once per load. Now each module enters
  once (by resolved path), depth first in the order the `use` lines appear in the source, a `use`
  inside a task that never runs included:
  `sha256(source ‖ 0x00 ‖ sha256(module_1) ‖ … ‖ sha256(module_n))`. A program with `use` gets a different `program_sha` than under v0.6.42; one
  without modules gets the same. `synsema code sha <file>` prints it.
- **`run`, `test` and `serve` no longer hash the program at startup.** The `program_sha` of
  `receipt()` is computed the first time a receipt asks for it, from the same bytes the module
  loader read to run (nothing is read or parsed again). Measured on `synsema run` (median of 40):
  a program with eight 1100-line modules started in 146.6 ms and now in 65.1 ms; one with eight
  small modules 22.9 → 18.9 ms; a program without modules is unchanged (~17 ms).
- **`config` in `/.well-known/attestation` and in `run --attest` gains `drivers`** (the attestation
  drivers, in order), so `config_sha` changes. Recompute it from the published `config`, as before.

**`attestation_verify`.**
- `format: "sev-snp"`: the 1184-byte report (`attest()["document"]`, configfs-tsm's `outblob`),
  with the VCEK or VLEK from `opts.aux` (the host's certificate table, `attest()["aux"]`) or
  `opts.vek` (DER or PEM). The chain uses AMD's ARK/ASK/ASVK for Milan, Genoa and Turin embedded
  in the engine and pinned by SHA-256 (the ones in `aux` are ignored); RSASSA-PSS with SHA-384 and
  a 48-byte salt and nothing else; validity of every certificate against `opts.now`; the report's
  ECDSA P-384 signature; the VEK's TCB against `REPORTED_TCB`; and `POLICY.DEBUG` set is an error
  with no option. Returns `measurements: {measurement, host_data}`, `tcb` and `policy`;
  `timestamp` is `nothing` (the report carries no time). `opts.root` is rejected.
- `format: "nitro-tpm"`: EC2 instance attestation (NitroTPM in a VM) under the same pinned AWS
  root as `nitro`, with `nitrotpm_pcrs` (`pcr0`..`pcr23`). It is a different format on purpose: a
  VM's document never verifies as `nitro` and an enclave's never as `nitro-tpm`.
- `opts.expect.report_data` (bytes or hex) for every format. In `sev-snp` a shorter value is
  padded with zeros to 64 bytes, so `sha256(spki ‖ program_sha ‖ config_sha)` is enough; in
  `nitro`/`nitro-tpm`/`mock` it must match exactly. A mismatch says how many bytes match, not the
  values.

**Attestation drivers.**
- `nitro-tpm`: produces the EC2 instance attestation document by talking to the TPM directly (no
  external tool). One request at a time per process; with `/dev/tpm0` (opened exclusively, waited
  for up to 10 s) it first releases what a killed process left in the TPM (loaded objects and
  sessions, and message buffers of exactly its own shape). Auto-detected only when the TPM answers AWS's vendor command; forced with
  `SYNSEMA_ATTEST=nitro-tpm`.
- `SYNSEMA_ATTEST` takes a list, e.g. `tsm,nitro-tpm`. `serve --attested` and `run --attest` ask
  every driver for a document binding the same `report_data`, and do not start if one fails.
  Auto-detection uses both when SEV-SNP and NitroTPM are present (`tsm` first). The identity's
  top-level fields stay those of the first driver and a new `documents` list carries all of
  them; `run --attest` keeps `attestation` and adds `attestations`. `attest()` and `attest_key()`
  use the first driver.

**Clients.**
- `fetch(url, {method, headers, body, timeout, tls_pin, attested})`: the options map is the main form of
  `fetch` (the positional `fetch(url, method?, headers?, body?, timeout?)` stays as the short
  form). With a map, no argument may follow it; an unknown key is an error that lists the valid
  ones.
- `tls_pin` in `fetch` and in `ws_connect`'s options: the server's SubjectPublicKeyInfo (hex, bytes
  or a `PUBLIC KEY` PEM — the `public_key_hex` of `/.well-known/attestation`). It replaces the
  check against the system roots and the host name with byte equality of the presented key; the
  handshake signature is still verified with it. It needs `https://`/`wss://` and `require net`
  as always. Without it nothing changes. `tls_pin: nothing` (and `attested: nothing`) is an error:
  a missing value never turns the check off.

- `attested` in `fetch`'s map and in `ws_connect`'s options: `{program_sha, formats, measurements?,
  now?}` connects to a `serve --attested` without knowing its key. On one TLS connection the
  handshake records the server's key without trusting any certificate authority, the identity is
  read over that same connection, its key must be the handshake's, `config_sha` and `program_sha`
  must match, every document must verify with its binding and every requested format must be there;
  only then is your request sent. If anything fails it is never sent and `error of r` says why. The
  answer carries `attested`. Not together with `tls_pin`. `attested.measurements` must name every
  format but `mock` (a non-empty map, or `"any"` to accept any measurement of that format on
  purpose): without expected measurements a platform document proves only that some machine of
  that platform answered, and `program_sha` alone is declared by the binary being checked. In
  `ws_connect`, `ws_stats(c)` gains `attested`, and an explicit `now` advances on reconnects. It fails against a server with an
  operator certificate (the channel's key is not the attested one). In the WebAssembly embedding
  (`synsema-wasm-web`), `tls_pin` and `attested` fail closed: the host's transport cannot do them.

**`serve --attested` renews its documents.** A Nitro/NitroTPM leaf lives about three hours: the
server asks every driver for fresh documents (same key, same binding) at half the life of the
shortest one, at least once a day, and swaps them all at once. A SEV-SNP report expires with the
VLEK/VCEK in its `aux` (about a year on AWS). If the current documents expire without a renewal,
the server shuts down with an error instead of serving an expired document, and
`/.well-known/attestation` answers `503` rather than an expired one.

**Tooling.**
- `synsema code sha <file>` (and the `sha` tool of `synsema code --mcp`): the `program_sha` that
  `serve --attested` and `run --attest` would bind; it runs the static check first, and `--json`
  adds each module with its sha256 and its path relative to the program's folder, written with `/`.

## v0.6.42 — 2026-10-04

Tunnels, programs that speak over stdio, and certificates that do not run into the CA's limits.
Everything is language primitives: a tunnel product (accounts, pages, quotas) is written in
Synsema on top of them.

**Behavior changes (read these first).**
- **`X-Forwarded-*` from an untrusted peer are dropped.** `proxy to` used to append the client's
  own `X-Forwarded-For`, so any client could tell the service behind it which IP it came from.
  Now `X-Forwarded-For`, `-Proto`, `-Host` and `Forwarded` are kept only when the TCP peer is
  listed in `trust proxy` (or `--trust-proxy`); from anyone else they are removed before the
  program, the generated URLs or a `proxy to` see them. Behind nginx/Caddy/a load balancer, add
  `trust proxy ["127.0.0.1"]` (or its address/CIDR) to the `serve` block; `ip of request` is then
  the real client. The trusted proxy must set (not pass through) `X-Forwarded-Proto`/`-Host`;
  `Forwarded` is dropped, not parsed. A request with more than one `Host` header is a 400.
- **`log` writes to stderr under `synsema run`** (like Go's `log`, Python's `logging` and the MCP
  stdio rule): stdout is the program's result, so `synsema run x.syn | jq` and stdio servers stay
  clean. Under `test`, `serve`, `run --format json`, `--explain` and `--attest` it is collected as
  before; inside an agent it keeps the agent's prefix.
- **Under `--labels`, the right side of `and`/`or` runs under the left side's label.** It only
  runs when the left side lets it, so `secret or exit(1)`, `secret and print("x")` or
  `when secret and notify()` reveal the secret; they are now a `label_violation`, like the same
  code written with `when`. The label of the result is unchanged.
- **`eprint` is a reserved builtin name** (like `print`, it is checked for private data): a program
  that defined its own `task eprint` must rename it.
- **In a route that runs `proxy to`, the request body streams to the destination** without being
  read first (with `max_body` still counting bytes, and a declared `Content-Length` above it
  answered with 413 right away) — unless the route reads it (`read_body`, `read_body_bytes`,
  `expect`, or the request's `body`/`form`/`json` written in the route): then it is read whole, up
  to `max_body`, and forwarded as is. Read any other way (in a task the route calls,
  `get(request, "body")`, `request[k]`), a streamed body fails instead of looking empty: that
  `request` has no `body`, `json`, `form` or `body_file`, and `read_body` says how to read it.
- **`tls auto` starts even if the CA cannot be reached**: names without a certificate are logged
  and retried in the background instead of stopping the server — every minute while a `domain`
  name is missing, each name waiting 1 min after a failure, doubling up to 1 h. Each issuance has
  a 2-minute limit (plus `SYNSEMA_ACME_DNS_WAIT`), so a CA that does not answer does not hold the
  start; the fixed names are requested in parallel.
- **`tls auto` keeps one certificate per name** (it was one certificate for every `domain`):
  adding a domain no longer re-issues the others. On the first start after upgrading, names that
  were only in the old shared certificate get their own.

**Tunnels.**
- `tcp_connect(host, port, opts?)`, `tcp_send`, `tcp_recv`, `tcp_close`, `tcp_stats`: outbound TCP,
  gated by `net("host:port")` with the exact port (a grant for `:8080` does not reach `:8081`).
  Bounded buffers both ways; `tcp_recv` gives `{type: "data", data}` or `{type: "close"}`, `nothing`
  on timeout; handles mix with the rest in `select`. `close` means the peer stopped sending: the
  connection stays open for an answer until `tcp_close`, and every later `tcp_recv` (or `select`)
  gives `close` again at once, like a closed channel in Go — drop the handle from a `select` you
  keep running. Name resolution runs in its own thread, at most 64 at a time in the process.
- `pipe(opts?)` → `{a, b}`: two connected byte ends with a bound per direction (`pipe_send`,
  `pipe_recv`, `pipe_close`, in `select`). An end can be handed to another interpreter (a route to
  an agent, a request to a `socket` route): the first one that uses it owns it. `close` is sticky
  as in TCP, and `pipe_close(x, "write")` is a half close. An end nobody took is closed after 60 s
  without activity on its pair (checked every 5 s); a program can have at most 4096 ends waiting
  to be taken.
- `proxy to <expr>` can run anywhere in a route body — after checking a token, or instead of an
  "offline" page — and its destination can depend on the request: a URL (its `net` grant is
  checked per request) or a pipe end, over which the engine speaks HTTP/1.1, SSE and WebSocket
  upgrades included. A literal, a constant or `env(...)` is still checked once at startup.
- A declared `route "OPTIONS …"` wins over the automatic answer, so a CORS preflight reaches the
  service behind a proxy. The automatic answer now lists the methods of the request's own vhost.

**Programs over stdio, and waiting without holding the server.**
- `eprint(…)` writes to stderr (a public sink, like `print`). `exit(code?)` ends a `synsema run`
  with that code (0–255); `try` does not catch it; agents still running are stopped; under `serve`
  it points to `shutdown(reason)`; inside a `test` block it fails that test. `run --format json`
  and `run()` of `@synsema/wasm` report it as `exit`.
- `serve` no longer lets a waiting handler hold a worker: `sleep`, `wait_for`, `select`, HTTP and
  LLM calls, databases (also while waiting for the shared connection another route is using),
  approvals and child processes release their CPU permit while they wait,
  and the pool adds threads (up to `SYNSEMA_SERVE_MAX_WAITING`, default 256) while others wait.
  CPU work is still capped at `SYNSEMA_SERVE_WORKERS`. With 2 permits, six routes sleeping 2 s
  now finish together in ~2.7 s and a fast route answers meanwhile; before, they ran two at a
  time and the fast route waited behind them. No new keyword: code stays straight-line. A thread
  coming back from a wait never blocks (it takes its permit back on credit), so a wait with a
  lock held cannot deadlock the server; extra threads leave as soon as the queue is empty. While a
  callback runs inside a wait (the `on_chunk` of an `llm_stream`), it holds a permit again, so CPU
  work can briefly exceed `SYNSEMA_SERVE_WORKERS` by the threads coming back from a wait.
- **With a token budget (`SYNSEMA_LLM_BUDGET` and friends), LLM calls in flight are capped** at
  `SYNSEMA_SERVE_WORKERS` (default: the CPU count), so the budget is not overshot by the extra
  threads. The cap is process-wide and also applies under `synsema run`: a `parallel_map` over 100
  prompts with a budget runs that many at a time. A call made from inside another one on the same
  thread (a `reason` in the `on_chunk` of an `llm_stream`) uses its slot; a call that gets no slot
  within `SYNSEMA_LLM_TIMEOUT`, or whose request was cancelled, returns a `[llm busy: …]` marker
  instead of waiting forever.

**Certificates (`tls auto`).**
- The ACME account is stored and reused (`SYNSEMA_CERT_DIR`); certificates renew by their real
  expiry.
- `domain ["x.app", "*.x.app"]` with `tls dns <task>`: wildcards through DNS-01, where the task
  `(name, value, "set" | "clear")` publishes the TXT record with your DNS provider over HTTP. The
  engine knows no provider.
- `domain ask <task>`: on-demand certificates. A new name in a handshake is offered to the task
  (`true` issues) and issued with HTTP-01 on the `:80` listener (`SYNSEMA_ACME_HTTP_PORT`), or
  TLS-ALPN-01 if the CA does not offer HTTP-01. There is no
  on-demand issuance without `ask`. One issuance per name at a time (parallel connections share
  it), a certificate on disk is reused after a restart, `ask` runs at most 8 at a time and 20 new
  names per second (the rest is refused at once, not remembered), `SYNSEMA_ACME_MAX_PER_HOUR`
  (20) caps on-demand issuance, failures back off per name, and `SYNSEMA_ACME_DNS_WAIT` (20 s) is
  the TXT propagation wait. Keys are written atomically, 0600 in Unix (also an older key found
  on disk), and checked against their certificate; the previous key is kept until the new
  certificate is in place, so an interrupted renewal still starts with the old pair. A
  certificate on disk is used only if it names the domain, and an expired one is not served (an
  on-demand name is issued again). `SYNSEMA_CERT_DIR`, `SYNSEMA_ACME_DIRECTORY`, `SYNSEMA_ACME_CA` and
  `SYNSEMA_ACME_HTTP_PORT` are now in the `.env.example` of `synsema init`.

**Also.**
- A comment (or several) before the first statement of a `socket`, `stream` or `reason` block
  parses; it gave `Unexpected token: INDENT`.
- `synsema check` warns about `alias.name` when the module does not export `name`, about a local
  variable, parameter, `each` or `recover` variable that shadows a module alias, and about a
  wildcard `domain` without `tls dns`.
- `ecdh_public(private, curve)`, and `"X25519"` for `ecdh_keypair`/`ecdh_shared_secret` (RFC 7748).
- A `net` grant or `deny` written without a scheme ignores case, like a URL: `net("API.x.com")`
  covers `api.x.com` (a `deny` in capitals used to miss it).
- `proxy to` drops the response headers the upstream names in its `Connection` header, and reads
  repeated `X-Forwarded-*` the same way everywhere (the first `-Proto`/`-Host`, every `-For`).
- After `exit`, an agent that had already failed is still reported; the ones `exit` stopped are not.
- `select` results count as external input for lineage, like `tcp_recv` and `pipe_recv`.

## v0.6.41 — 2026-10-03

Data work, faster: reading and writing CSV, `join`, `summarize`/`group_by` and record lambdas do
less work per row. The same language — every program gives the same results, errors and
`steps()`. Nothing to change in your programs. One fix you may notice (below).

**A data-science pipeline** — 1 M sales rows: `csv_parse`, `where`, `join` with a category
table, `apply` building a derived column, `summarize`, `sort_by`, `mean`/`std`/`median` —
takes **2.65 → 1.46 s** on Windows with the release builds (best of 5; v0.6.40 as released →
v0.6.41). The same program, same machine: pandas 1.61 s, Node 2.07 s, CPython without
libraries 4.31 s, polars 0.66 s, Go 0.67 s.

| step (1 M rows) | v0.6.40 | v0.6.41 |
|---|---:|---:|
| `csv_parse` | 0.49 s | **0.26 s** |
| `join` | 0.99 s | **0.29 s** |
| `summarize` | 0.53 s | **0.26 s** |
| `apply` (derived column) | 0.22 s | 0.20 s |
| `mean` + `std` + `median` | 0.12 s | 0.10 s |

Memory is unchanged: a table is still a list of maps (a columnar layout is the next step).

**What changed.**
- `csv_parse` reads the text in one pass and builds each row with one allocation (it was four);
  fields without escaped quotes are not copied before they become values. `csv_encode` writes
  every field straight into the output and formats numbers without intermediate text.
- `join`, `summarize`, `group_by` and `pivot` hash a key by its value (the same equality as `==`)
  instead of building a text form for every row, read columns by position when rows share a
  shape, read keys and numbers without copying them, and copy a left row's values in one go when
  its shape is the output's. The hash stays the standard library's keyed SipHash: tables often hold
  data a server received from third parties, and a faster unkeyed hash would let them build
  collisions.
- `r.field` on the VM reads the record where it is, without a copy per read.
- `sum` of only floats or only integers adds them directly; a float is formatted (`text`,
  `csv_encode`, `json_encode`) without intermediate strings.
- `csv_parse` checks for duplicate headers with a set: a header row with a huge number of columns
  no longer takes quadratic time.

**Fixed: reading a field after a row with more than 32 keys.** A read site on the VM or in native
code (`r.g`, `r["g"]`) that met a row in dictionary mode — a map with more than 32 keys —
remembered that row's position together with the previous row's shape. The next row with that
shape could then read another key: in v0.6.40, `apply(rows, (r) => r.g)` over
`[{"g": "a", "v": 1}, <a row with 40 keys and "g": "D">, {"g": "b", "v": 2}]` gave
`["a", "D", 2]`, and `set r.g to …` inside a task could write into `v`. The cache now forgets the shape when it
remembers a dictionary position (the new column readers of `group_by`, `summarize`, `join` and
`csv_encode` use the same cache, and are covered by the same fix).

## v0.6.40 — 2026-10-03

Memory, third step: the program's data is shared between threads instead of copied. A server's
workers, the items of a `parallel_map`, agents and `cron` read the same globals in place, so memory
no longer grows with the number of workers. The same language — every program gives the same
results, errors and `steps()`; a write to shared data copies first (copy-on-write), exactly as
before. Nothing to change in your programs.

**`serve`: memory decided by the data, not by the workers.** The top-level globals are frozen in
place once, when the program finishes setting them up, and every worker reads them (a write inside a
handler copies first, so v0.6.39's rule still holds: each request starts from the program's
globals). Before, each worker built its own copy on its first request. Measured on Windows with the
release builds (v0.6.39 as released → v0.6.40), a global of 1 M records plus 1 M integers:

| workers | memory with every worker warm | first request of a worker |
|---:|---:|---:|
| 1 | 839 → **176 MB** | 479 → **25 ms** |
| 4 | 1315 → **190 MB** | 302 → **8 ms** |
| 12 | 2575 → **225 MB** | 309 → **9 ms** |

Startup memory also drops (700 → 232 MB): the copy every worker was built from is gone. (Node 24,
the same service: 195 MB.) `SYNSEMA_SERVE_WORKERS` is again a CPU decision: more workers cost a few
MB each.

**Modules are shared too.** The bodies of tasks, lambdas, agents and routes are shared between
interpreters instead of copied (local build): a worker that rebuilt an app with 26 `use` (41 modules) reserved
13.1 MB, now 0.8 MB; that app with 12 workers 301 → 109 MB, first request 79 → 5 ms.

**`parallel_map`** reads the globals and its items frozen for the duration of the call (they are
thawed when every item has finished), instead of copying them for each item. Release builds on Windows,
v0.6.39 → v0.6.40: a global of 200 k records read from 10 calls of 16 items, 3.1 s / 291 MB →
**0.36 s / 44 MB**; a module with 20 k records and 200 calls of 5 items, 6.0 s / 142 MB → **1.2 s /
33 MB**. Same order of results and the same fail-fast as before.

**Agents and `cron`** started under `serve` share what is already frozen (the program's globals) and
copy the rest (local build): a handler that spawns an agent reading a global of 300 k records, ~200 ms → 4–5 ms
per request. Outside `serve`, an agent still gets its own copy.

**Fixed:** a module environment could inherit another module's variables when it was created at the
address of one that had been released (the module registry now checks the environment it recorded).

**How.** A new crate, `synsema-heap`, holds the engine's own heap objects: lists, maps, map shapes
and read-only values are objects with an 8-byte header and their own count, and can be made
*immortal* — readable from any thread, never written, never freed while shared. Every write decides
by the count, so a frozen value is always copied before it changes. All of its `unsafe` lives in that
crate (and the `Send`/`Sync` of a frozen value in `synsema-core/src/frozen.rs`), checked with Miri on
x86_64, i686 and s390x and with Miri's data-race detector over the frozen-value tests. The parser
builds the syntax tree without spare capacity, so sharing it costs nothing extra.

**For contributors.** `ListRef` and `MapRef` are `synsema-heap` objects (`ListRef::new(..)`,
`ListRef::ptr_eq`, `ListRef::strong_count` instead of the `Rc` functions). `synlist::list_values(&l)`
returns a `ListRead` (borrowed, or a copy when the list is frozen and unboxed): it never writes a
frozen list. `FrozenValue::new(v)` freezes for good or gives `v` back untouched; `ScopedFreeze` freezes
for one call and thaws after joining its threads. On `x86_64-pc-windows-gnu`, `.cargo/config.toml`
builds mimalloc with `MI_WIN_INIT_USE_FLS=1` (GCC ignores the TLS callbacks mimalloc uses to notice a
thread ending, so the memory of every finished thread was abandoned); the released Windows binary is
MSVC and was not affected.

## v0.6.39 — 2026-10-01

`serve`: route bodies run on the VM and the native tier, and every request starts from the program's
own globals. Programs give the same results, errors and `steps()`; the one behaviour that changes is
a bug fix (below).

**Faster handlers.** A route body used to run on the reference interpreter; now it runs like
`synsema run`: on the bytecode VM, with its hot loops in native code (reading the program's globals
from inside the loop stays native). A 1-million-iteration loop written in a handler: **~0.3 s →
~5 ms per request**. With `--labels` or `serve --attested`, route bodies still run on the reference
interpreter, like any program under labels.

**Each request starts from the program's globals (behaviour change).** `serve.md` always said that a
`set` of a global inside a handler does not reach the next request, but up to v0.6.38 such a write
could stay in the worker that served the request — the same `GET` answered differently depending
on which worker took it. From v0.6.39 every request starts from the values the program set up, for
every kind of write: a path (`set rows[0].name to …`), an in-place `append`, a scalar, a write from a
task the handler calls, and a module's own variables. **What to write instead**, if a program relied
on it: what must outlive a request goes in `state_*`, a database or the memory. The originals are
kept as shared references (nothing is copied); a write during a request copies first
(copy-on-write), so the next request still sees the originals.

**Memory per worker, documented.** Each worker builds its own copy of the top-level globals on its
first request, so RAM is about the size of the globals × the workers (1 M small records in a global
≈ 160–190 MB per worker). With large data in globals keep `SYNSEMA_SERVE_WORKERS` low or keep the
data in a database (`deploy.md`, `serve.md` § Performance and memory of a server).

**Memory leak in `parallel_map` and `spawn`, fixed.** Each `parallel_map` item and each spawned
agent runs on an interpreter rebuilt from the program, imported modules included. A task of a module
and the module's environment point at each other, and nothing broke that cycle when the interpreter
ended: every item and every agent left the program's modules alive. A long-running program that
calls `parallel_map` (from a `cron_every`, a handler, an agent) grew without bound — measured: a
module with 20 000 records, ~22 MB more per call, never released. Now the modules an interpreter
rebuilt are released with it: the same program stays flat (33 MB with 5 calls or with 20, nothing
left alive at the end). Nothing to change in your programs.

Also: a CLI test that writes an executable and runs it right away retries when Linux reports
"Text file busy" (a race between tests running in parallel, not a bug in the binary).

## v0.6.38 — 2026-10-01

Speed and memory, second step: the native tier runs code over data, lists of numbers take a third of
the memory, and text is built in place. The same language — every program gives the same result,
the same errors (text and location) and the same `steps()` count; copy-on-write, insertion order
and `==` by value are unchanged — only faster and lighter. Nothing to change in your programs.

**Faster and lighter.** Whole process on Windows, best of 5, this build *without* PGO (the release
is built with PGO, usually 20–35 % faster) against v0.6.37 as released:

| | v0.6.37 | v0.6.38 | CPython 3.12 |
|---|---:|---:|---:|
| sort 2 M integers | 1187 ms / 148 MB | **135 ms / 44.5 MB** | 1642 ms / 111 MB |
| n-body (records of floats) | 13.6 s | **1.53 s** | 2.87 s |
| 2 M records built and summed | 1113 ms / 330 MB | **603 ms / 254 MB** | 753 ms / 517 MB |
| `where` over 2 M integers | 516 ms / 145 MB | **192 ms / 37 MB** | 344 ms / 103 MB |
| `json_encode` + `json_decode`, 500 k rows | 883 ms / 322 MB | **737 ms / 168 MB** | 1070 ms / 337 MB |
| word count (map of thousands of keys) | 1679 ms / 282 MB | **1030 ms / 127 MB** | 1001 ms / 247 MB |
| `join` of 2 M texts | 842 ms / 223 MB | **577 ms / 84 MB** | 471 ms / 147 MB |
| `set s to s + x`, 100 k times | 3897 ms | **61 ms** | 703 ms |
| spectral norm (floats) | 461 ms | **97 ms** | 506 ms |
| matrix multiply on lists | 399 ms | **126 ms** | 275 ms |
| `while` loop, 10 M | 84 ms | **56 ms** | 1192 ms |

Small programs that compile native code use 1–3 MB more than v0.6.37 at peak (compiling with
Cranelift); that is the next thing to work on.

**How.**

- **The native tier runs loops over data**: reading and writing list elements and map fields
  (`set bodies[i].vx to …`), floats, `length`, `sqrt`, `abs`, `float` and `get` as instructions,
  text constants, and calls to any builtin or task from inside a native loop. Anything it does not do
  still runs in the VM, exactly as before.
- **Builtins that take a function** (`apply`, `where`, `reduce`, `count_where`, `every`, `some`,
  `find_first`, `sort_by`) call it without per-element overhead, straight into its native code when
  it has some.
- **Lists of integers or of floats are stored unboxed** (8 bytes per element instead of 24) and
  `sort` orders them as numbers. A list becomes a regular one the first time something needs it to
  (a mixed element, most builtins); the result is always the same.
- **Text**: up to 15 bytes inline (no allocation), `set s to s + x` appends in place when nothing
  else shares `s`, `text(n)` and `join` write digits and parts directly; `json_encode` and `serve`
  responses are written without an intermediate tree, and a paginated response reads only its page.
- **In place**: `set P to append(P, e)` appends without copying when `P` is the only owner; a map
  literal with constant keys builds its shape once per site.

**For contributors.** `ListRef` is `Rc<RefCell<SynList>>`. Read elements with `l.borrow().get(i)` /
`.len()`; for code that needs `&[SynValue]`, `synlist::list_values(&l)` (turns an unboxed list into
values for good) or `synlist::list_read(&l)` (reads a copy without changing it); build lists with
`syn_list(vec)` or `syn_list_of(SynList::from_ints(…))`. Every private value is built by
`labels::labelled` (a test checks it), which lets responses skip the label walk when there is none.
Still no `unsafe` in core. The differential oracle (508 programs), the native fuzzers (data, writes,
foreign calls, calls from builtins) and a new test that builds every list both ways cover it.

## v0.6.37 — 2026-09-29

Memory, first step: maps take a fraction of the memory they used to. The same language — every
program gives the same result, the same errors and the same `steps()` count; maps keep their
insertion order, copy-on-write and `==` by value — only lighter and faster. Nothing to change in
your programs.

**Lighter.** A list of 2 million records `{"id": i, "valor": i * i}` (built with `apply`, then
read): peak memory of the whole process **664 MB → 327 MB** against the previous build, and
**787 MB → 327 MB** against v0.6.36. A 500,000-row `csv_parse`: **560 MB → 284 MB** against v0.6.36.
A record literal is now **one** allocation (it was 5 in v0.6.36); a `csv_parse` row, 4 (was 8).

**Faster.** Instructions executed (release build without PGO, deterministic), against v0.6.36:
building and reading records **−30 %**, `csv_parse` **−25 %**, the n-body simulation (records of
floats) **−4 %**, word counting with a map of thousands of keys **−2.6 %**. Wall time on Windows:
the 2 million records **−35 %**, the 500,000-row CSV **−26 %**. Everything else within ±0.5 %,
native tier and `--jitless`.

**How.** The way V8 and JavaScriptCore represent objects:

- **Shared keys.** A key is stored once and shared by every map that has it: the keys of a literal,
  of `set m.k`, the columns of a CSV or of an SQL result, the repeated keys of a JSON document
  (`json_decode` and `jsonl_decode` no longer copy the document either).
- **Shapes with inline values.** Maps built with the same keys in the same order share a *shape*
  (the keys and where each one is); the map itself is a single block with its values inline, sized
  when it is built. Reading `r.valor` in a loop checks the shape and loads the value, without
  looking at the key. A map that grows keeps its shape and stores the extra values apart; past 32
  keys, or with keys that rarely repeat (a map used as a dictionary, like word counts), it switches
  to a hash table, as before.
- The hash seed is per process (like CPython and V8), not per map.

**For contributors.** `MapRef` is `Rc<RefCell<MapObj>>`; `SynMap` (the map you build before it
becomes a value) is the same type without inline slots and has the same API as before
(`IndexMap`-like: `insert`, `get`, `shift_remove`, `swap_remove`, `iter`, `get_index`, …). To turn a
`SynMap` into a value, `syn_map(m)` or `m.into_ref()` (not `Rc::new(RefCell::new(m))`); to copy a
map out of a value, `m.borrow().to_map()`. Still no `unsafe` in core. The differential oracle, a
fuzz of the map against `IndexMap` in every mode and a comparison of 467 programs against v0.6.36
cover it.

## v0.6.36 — 2026-09-28

Speed, sixth step: hot code runs as machine code. The same language — every program gives the
same result, the same errors (text and location) and the same `steps()` count; `Int` still becomes
a big integer instead of wrapping, cancellation and `timeout` still stop any loop — only much
faster. Nothing to change in your programs.

**Faster.** Measured on the interpreter built like the release (with PGO), against v0.6.35, best of
15 alternating runs:

- Recursive `fib(30)`: **258 ms → 14.6 ms**.
- A 10-million-iteration loop over integers: with `each i in range(…)` **691 ms → 28.5 ms**; with
  `while` **1305 ms → 55 ms**. Loops at the top level of a program (whose variables are globals)
  count too.
- Task calls from a loop, and chains of calls 16 deep: **−95 % to −97 %**; a loop calling a builtin
  (`abs(i)`): **−20 %**.
- With `--jitless` (the VM alone), no row is slower than v0.6.35.
- Everything else within the build-to-build variation of a PGO binary (about ±5 %).

**How.** A native tier compiles hot code with Cranelift (a code generator written in Rust):
tasks that are called often and loops that turn often (entered mid-loop, the way V8 and the JVM do
on-stack replacement), starting with integer and boolean arithmetic, comparisons, jumps, locals,
globals, calls between those tasks and `each` over `range`. It compiles the code the VM already
specialized, and it never produces a result or an error of its own: before anything it does not
handle (an overflow into a big integer, a division by zero, a cancellation, a value of another
type), it hands the exact state back to the VM, which carries on from that instruction. On x86-64 and
aarch64 (Linux, macOS, Windows); the wasm builds and embedded guests keep the VM. Calls to builtins
from the VM got their own fast path too (`CALL_BUILTIN_FAST` of CPython).

**New flag: `--jitless`** (like `node --jitless`), for every command that runs programs: no native
tier and no executable memory; everything runs in the VM. It turns no check off. `serve --attested`
implies it (a smaller surface in what is attested). With labels (`--labels`, `serve --attested`) the
reference interpreter runs, as before.

**For contributors.** New crate `synsema-jit` (Cranelift 0.136.1; the only `unsafe` of the engine
lives in its `abi.rs`, and a test fails if it appears anywhere else); core gains a safe hook
(`native_tier`, feature `native-tier`, no new dependencies). The generated code only touches memory
through its context at fixed offsets and its own stack slots (checked on every compiled function).
The differential oracle has an eager native pass (every hot task and loop compiled at once) and
fuzzing against the reference interpreter. Measuring: instructions executed (`cachegrind`) are now
the main metric — deterministic; time with PGO is the second one.

## v0.6.35 — 2026-09-28

Speed, fifth step: lighter task calls. The same language — every program gives the same result,
the same errors and the same `steps()` count — only faster. Nothing to change in your programs.

**Faster.** Measured on the interpreter built like the release (with PGO, same training corpus),
against v0.6.34, best of 15 alternating runs in both orders:

- A task call with 4 arguments: **−17 % to −18 %**; with 1 argument: **−10 %**; recursive `fib`:
  **−12 %**. The more arguments a call has, the more it saves.
- Everything else within the build-to-build variation of a PGO binary (about ±5 %).

**How.** A task whose variables nothing else can see now takes its parameters in the machine's
registers, and its registers start exactly where the caller left the arguments (the calling
convention of Lua): nothing is copied on entry. The bookkeeping of a call got smaller too.

**For contributors.** `vm.rs`: parameters as `r0..r(n-1)` of a body with its frame in registers
(the block value moves to `r(n)`), `VmFrame.top` (the register stack goes back to its length before
the call: frames can nest inside their caller's window), no labels taint in the VM's frames. New
oracle cases `vm_frames` and `errors/vm_frames_error`. Measuring: two PGO builds of the same code
differ by up to ±8 % on some rows (the training profile is not deterministic), and a binary without
PGO moves ±5 % with any change to the VM's dispatch loop; compare with PGO builds, and trust only
differences above that band.

## v0.6.34 — 2026-09-27

Speed, fourth step: the virtual machine learns from what it runs. The same language — every
program gives the same result, the same errors and the same `steps()` count — only faster.
Nothing to change in your programs.

**Faster.** Measured on the interpreter against v0.6.33 (same machine, best of 9 alternating
runs, without counting PGO or the Windows allocator, which both still apply on top):

- A loop counting to 10 million at the top level of a program: **−61 %**; the same loop inside
  a task: **−73 %**. Recursive `fib`: **−41 %**.
- Arithmetic and comparisons on integers: **−50 % to −56 %**; on floats: **−68 % to −78 %**.
- `each`: **−41 % to −53 %**; reading a variable several scopes up: −60 %.
- Reading records: `r.price` **−61 %**, `r["price"]` **−71 %**, `xs[i]` −62 %.
- `set`, `let`, a text literal, a builtin call: −37 % to −54 %; task calls: −22 % to −27 %.

**How.** Each operator starts generic and, the first time it runs, rewrites itself into a
version for the types it sees (two integers, a float): if other types arrive later it goes back
to the generic one, and an integer that overflows still becomes a big integer (the technique of
CPython 3.11, *quickening*). An `each` whose loop variable nothing captures keeps it in a
register instead of creating an environment per iteration (what Lua, CPython and V8 do). The
most frequent instruction pairs, measured over real programs, run as one instruction (the start
of every statement; a comparison and the jump that uses it). Global variables go straight to
where they are, and a map remembers where it found a key the last time (it still compares the
key, so nothing changes about how values behave). `m["k"]` no longer asks for memory to build
the key.

**For contributors.** `vm.rs` gained the adaptive `Binary` with its specialized forms
(`IntArith`, `IntCmp`, `IntCmpJump`, `FloatArith`, `NumCmp`, `BinaryAny`), `each` turns in the
VM's locals window (`EachInitV`, `EachNextV`, …; the choice is a fixpoint in `compile_unit`),
`StepsCancel`, `LoadGlobal`/`SetGlobal` and key caches on `GetProp`/`GetIndex`.
`explain_after_run` (hidden) shows the code after it specialized. A hidden cargo feature,
`vm-profile`, counts what the VM runs (`cargo run --release -p synsema-core --features vm-profile
--example vmprof -- files…`). New oracle cases `vm_quicken`, `vm_each_window`, `vm_superinstr`,
`vm_key_cache` and ten error cases. Note for measuring on Windows: two byte-identical copies of a
binary can differ by up to 9 % because of address-space randomization; compare binaries linked
with `-Wl,--no-dynamicbase`.

## v0.6.33 — 2026-09-27

Speed, third step: a bytecode virtual machine. The same language — every program gives the same
result, the same errors and the same `steps()` count — only faster. Nothing to change in your
programs.

**Faster.** Measured on the interpreter against v0.6.32 (same machine, best of 9 alternating
runs, without counting PGO or the Windows allocator, which both still apply on top):

- Task calls: **−21 % to −25 %**; recursive `fib`: **−15 %**; a builtin call: −7 %.
- `each`: **−36 %**; reading a variable several scopes up: **−45 %** (16 levels, now independent
  of the depth).
- A text literal: **−31 %**, and it no longer asks for memory; `set`: −21 %; `let`, `+`, `==`:
  −12 % to −15 %; `<` and a `while` loop: −6 % to −11 %.
- Programs that build data: maps −8 %, text −8 %, closures −3 %; lists and rows of maps unchanged.

**How.** Task bodies and the top level of a program are compiled to a register bytecode and run
by a small virtual machine; calls between compiled tasks no longer go through the Rust stack, and
a task whose variables nothing else can see keeps them in registers instead of an environment.
The tree-walking interpreter is still there and still the reference: it runs every program with
information-flow labels on, and everything the machine does not compile is handed back to it.

**For contributors.** New `synsema-core/src/resolve.rs` (where each variable lives, what
escapes, what closures capture) and `synsema-core/src/vm.rs` (compiler and machine). The
differential oracle (`reference_oracle.rs`) now also checks every by-name lookup of the reference
run against the resolver (`oracle_run --resolver-check`, a test-only cargo feature), and runs the
compiled path against the reference over the whole corpus: same output, errors and `steps()`.
`steps()` is counted per basic block and corrected on the error path, so it stays exact.
`cargo test` gained `resolver.rs`, `vm.rs` and new oracle cases (`vm_*.syn`, `resolver_scopes.syn`);
the allocation table now expects zero for a text literal.

## v0.6.32 — 2026-09-26

Speed, second step. The same language — every program gives the same result — only faster: a
task call, an `each` iteration and a builtin call no longer ask for memory at all, and variables
are found faster. Nothing to change in your programs.

**Faster.** Measured on the interpreter against v0.6.31 (same machine, best of 9 alternating
runs, without counting PGO or the Windows allocator, which both still apply on top):

- `each`: **−60 %**; a task call with 4 arguments: **−52 %**, with 1: **−39 %**, without
  arguments: **−21 %**; recursive `fib(27)`: **−49 %**; a builtin call: **−20 %**.
- Reading a variable several scopes up: **−43 %** (16 levels); `let`: −14 %; a `while` loop,
  `<` and `set`: −11 %.
- Programs that build data: closures −22 %, rows of maps −19 %, text −13 %, lists −9 %,
  maps −6 %.
- A call (with any number of arguments), an `each` iteration and a builtin call went from 1–9
  heap allocations to **none**: the environment of a call or an iteration that nothing captured
  is reused by the next one, and variables live in a small inline table instead of a hash map.
  A closure keeps exactly what it captured, and a call never sees the previous call's variables.

**For contributors.** `Bindings` (the variables of a scope) is now two parallel arrays with a
fast index past 16 names; a binding never changes position (the format a future compiler will
index). `cargo test` gained `frame_reuse.rs`, which checks captures and isolation in both the
reference and the fast path, and the allocation counts of `alloc_counts.rs` now expect zero for
calls and `each`.

## v0.6.31 — 2026-09-25

Speed. The same language — every program gives the same result — only faster: the interpreter's hot
paths no longer allocate or compare text, the released binaries are built with profile-guided
optimization, and the Windows binary uses a faster memory allocator. Three small fixes came out of
the checks that prove nothing else changed.

**Faster.** Measured on the interpreter (release build, same machine, best of 9 alternating runs,
before → after, without counting PGO below):

- a `while` loop: **−52 %**; `<` and `==` between integers: **−61 % / −56 %**; `set`: **−53 %**;
  `let`: **−50 %**; a builtin call: **−48 %**; task calls: **−47 % to −64 %**; `each`: **−43 %**;
  recursive `fib(27)`: **−37 %**. A loop, a `set`, a `let` and an integer comparison no longer ask
  for memory at all (they asked 4 to 7 times per iteration).
- **`each i in range(…)` does not build the list**: `each i in range(0, 5000000)` peaks at 6 MB
  instead of 311 MB, and `each` over a list no longer copies it first (a list of a million: 67 →
  36 MB).
- **Parsing**: a 20,000-line program loads 32 % faster (the file name was copied for every token).
- **Profile-guided optimization** in the released binaries: an instrumented build runs a training
  corpus (`engine/pgo/`) and the published binary is compiled with that profile. On Linux, measured
  on the release path: a further **−24 % to −38 %** on every row. The release fails if the profile
  did not apply, instead of shipping a slower binary.
- **Windows**: the binary uses mimalloc as its allocator. The system allocator made everything that
  allocates (calls, `each`, maps, lists, text, closures) 1.3–1.5× slower than on Linux; now the gap
  is 1.03–1.09× (**−17 % to −28 %** on those programs on Windows). Linux, macOS and wasm keep their
  allocator.
- A debug build of the engine (the one tests use) no longer crashes with a stack overflow at about
  1,750 levels of recursion: it reaches the 3,000 limit and gives the catchable
  `maximum recursion depth exceeded`, like the release build always did.

**Fixes (behaves differently).**

- **`steps()` counts one step per evaluated node on every path.** Since v0.6.29, `set x to x + 1`
  counted one step too many and `set xs to append(xs, v)` (also `insert`, `merge`, `xs + […]` on
  the same variable) one or two too few, because an internal shortcut took them. The count is now
  the same as the reference path; a program that stored exact `steps()` values for those
  statements sees them move by one or two. (The Vela guest's fee never used `steps()`.)
- **`range(a, b, step)` near the integer limits ends**: `range(9223372036854775800,
  9223372036854775807, 5)` → two numbers, like Python. It used to wrap around to negative numbers in
  the release build and loop until memory ran out.
- **`merge()` errors say where**: `merge(m, 5)` → `app.syn:3:15: merge(): argument 2 is number, not
  a map`. The line was missing when the call was written as `let n be merge(m, 5)` and present when
  it was `set m to merge(m, 5)`.

**For contributors.** `cargo test` gained guards that keep this from regressing: a differential
oracle that runs every `.syn` in the repo with and without the engine's shortcuts and demands the
same result, output, errors and `steps()`; exact heap-allocation counts per construct; size caps on
the values every evaluation moves; and a test of recursion near the limit.

## v0.6.30 — 2026-09-25

Fixes from the v0.6.29 audit, plus three things data and scheduling code kept asking for: cron in
an IANA time zone, decimals written with an exponent, and Parquet files that pandas and polars read
with their types. Nothing that worked right stops working; what changes is silent wrong results that
are now errors, and error messages that now say what to write.

**New.**

- **`cron_every` takes an IANA zone**: `cron_every("0 9 * * *", report, {"tz": "America/Santiago"})`
  runs at 09:00 Santiago time all year. Clock changes follow the rule every Linux cron uses (Vixie
  cron / cronie): a fixed time that falls in the hour skipped in spring runs right after the jump
  instead of being lost; a fixed time in the hour repeated in autumn runs once, the first time; a job
  with `*` in the minute or hour field (`*/15 * * * *`, `0 * * * *`) follows real time, so skipped
  minutes do not exist and the repeated hour runs twice. Fixed offsets (`"-03:00"`) work as before;
  an unknown zone is an error at registration. `cron_list()` shows the zone name in `tz`.
- **A decimal can be written with an exponent**: `decimal("1.5e-3")` → `0.0015`, `decimal("1e5")` →
  `100000`, `2e3d` → `2000`. The value is exact (mantissa × 10^exponent), like Postgres `numeric`;
  the scale is the mantissa's minus the exponent (`decimal("1.50e1")` → `15.0`). A CSV column typed
  `decimal` reads the same way. A value of more than 4300 digits (`"1e999999999"`) is an error, so a
  short text cannot ask for unbounded memory.
- **`parquet_write` writes the Arrow schema** (`ARROW:schema`), as pyarrow, polars and arrow-rs do:
  pandas, pyarrow and polars read a `duration` column as a duration (`timedelta64`) and a `datetime`
  column with its IANA zone (`datetime64[us, Europe/Madrid]`), not as an integer and UTC. A
  fixed-offset zone (`+05:30`) goes as UTC in that schema, because polars cannot open a file with
  one; Synsema still reads the offset back.
- **`synsema test` takes several files and directories** (`synsema test a.syn b.syn tests/`), and
  expands a glob the shell passed as is (PowerShell and cmd do not expand `tests/*.test.syn`). It
  used to run only the last path, without saying so.

**Silent wrong results that are now errors (or right).**

- **`parse_datetime` with `%Z` no longer ignores the zone.** `parse_datetime("24/09/2026 10:00 IST",
  "%d/%m/%Y %H:%M %Z")` gave 10:00 UTC. An abbreviation does not identify a zone (IST is India,
  Ireland or Israel), so it is now an error. `UTC` and `GMT` are unambiguous and still work, in any
  case, as in Python (an HTTP date parses); with `%z` in the same format (`"+0530 (IST)"`) the offset
  decides and the abbreviation is just text. **What to write instead:** `%z` for an offset
  (`+05:30`), or drop the abbreviation from the text and pass the zone:
  `parse_datetime(text, format, "Asia/Kolkata")`.
- **`parse_datetime` with a date-only format is midnight**: `parse_datetime("03/01/2026", "%d/%m/%Y")`
  → `2026-01-03T00:00:00Z` (it failed with `input is not enough`), like Python's `strptime` and
  `parse_time`; with a zone, midnight in that zone.
- **`polyval` keeps `nothing` apart from NaN.** A missing coefficient is an error (there is no
  polynomial); a missing `x` in a list stays `nothing` in its place, like `cumsum`:
  `polyval([2.0, 1.0], [1, nothing, 3])` → `[3.0, nothing, 7.0]` (was `[3.0, nan, 7.0]`). The same
  error for a missing value in `lstsq`'s `b`. **What to write instead:** `drop_missing(xs)` first.
- **`length` of a 0-d array is an error** (it gave 0, so a scalar looked empty; numpy raises too).
  **What to write instead:** `size(a)`, which is 1.
- **`json_encode`, `jsonl_encode` and `json_for_script` reject a task or a generator** instead of
  writing its text (`json_encode(rng(1))` gave `"builtin:rng(1)"`, revealing the seed and not the
  state). The error names where it is: `json_encode: the value["f"] is a task, not data`.
  `canonical_json` now says "generator" for a generator. **What to write instead:** store what the
  task computes, or leave it out of the value.
- **`int(x, 2.0)` is the same mistake as `int(x, 2)`**: a number with an integral value from 2 to
  36 in second place is an error that points at `base =` or `fallback =` (it returned `2.0` for any
  text that did not parse). **What to write instead:** `int(x, base = 2)` or `int(x, fallback = 2.0)`.
- **`request.json` reads the body with the same parser as `json_decode`**: `{"v": -0}` gives `0` in
  both (it was `-0.0` in `request.json`), and a body that starts with a byte order mark is read
  instead of answered with 400.
- **Parquet: durations round-trip.** `parquet_write` writes a `duration` column as INT64 (as Arrow
  does) with its unit in the file metadata (`synsema.durations`), in microseconds, or nanoseconds
  when a value needs them; `parquet_read` reads it back as a duration, and also reads the Arrow
  `duration` type that pyarrow and polars write (it came back as an integer without a unit).
  `parquet_read(parquet_write(rows)) == rows` holds with durations, including a `TIME` column read
  from another tool.
- **Parquet: nanoseconds are never dropped.** A column is written in one unit; one that had a value
  with nanoseconds and another beyond the nanosecond range (a datetime outside 1677-2262, a duration
  beyond ±292 years) went in microseconds and lost the nanoseconds without a word. It is now an
  error naming the column, as in pyarrow. **What to write instead:** put the far values in another
  column, or store that column as text (`text(x)` keeps every digit).

**Faster.**

- **`index_of` no longer copies the list** before searching: an early hit is O(1), like `in` and
  `contains`.

**Warnings and messages.**

- The deprecated-name warning is printed for a module loaded with `use`, once, like for the main file.
- `solana_message(1, 2)` and `algorand_tx_encode({}, 1)` name the function that was called (they
  spoke about `solana_tx` and `algorand_tx`).
- A C-style `//` comment gets the hint "comments in Synsema start with `--`": at the start of a line,
  after code (`let x be 1 // a note of several words`, whose error was about whatever word came
  next), on an indented line of its own, and when the note has an apostrophe (`// don't`, an
  unterminated string); also in `let x be 1 // note` when `note` is not a variable. `//` is integer
  division, which does not change.
- `set xs[10] to 1` out of range says where and the length, like reading `xs[10]`.
- `bytes(33)` suggests `int_to_bytes(33, size)` and `bytes([33])`.
- `json_decode("Infinityx")` and `json_decode("NaNa")` are the generic invalid-JSON error with the
  position, not "NaN/Infinity is not JSON".
- `format_time(t, "%#z")` says that `%#z` is a parsing-only specifier and points at `%z` / `%:z`.
- `synsema check` warns about `\u` only where the escape is decoded (`"\uD800"` alone and
  `"\u{110000}"` stay literal text, as before).
- `synsema check` warns when a task writes into a parameter and neither gives it back, passes it on,
  nor reads what it wrote: with value semantics that write is lost. **What to write instead:** end
  the task with `give cfg` and call it as `set c to touch(c)`.
- Reading a name a module does not export suggests the form it has: `export enum Color`,
  `export task helper`.
- `synsema check` decides file scopes with the runtime's own matcher: `require file.read("./**")`
  covers `read_file("x.csv")`, as it does when the program runs.

## v0.6.29 — 2026-09-24

Everything that had to break before v1.0, broken once (after v1.0 nothing breaks), plus EVM
contract deployment and events, and the start of data analysis (tables, dates, seeded randomness,
Parquet, lineage). Old names keep working as deprecated aliases until v1.0:
`synsema check` warns about each one, and a program that uses them says so once on stderr.

**Breaking, on purpose.**

- **Lists and maps are values (copy-on-write).** `let ys be xs` and passing a list or map to a task
  give a logical copy: `set ys[0] to 9` changes only `ys`, and a task that `set`s inside a map it
  received no longer changes the caller's. **What to write instead:** `give` the map back (that is
  how a change leaves a task). Shared state stays explicit: blackboard, memory, bus, `state_*`.
  Modules are namespaces, not values: an exported variable is ONE variable, seen the same by the
  module's tasks and by `mod.STATE` (`set mod.STATE[k] to v` writes it, `set mod.X to v` rebinds it);
  `let snap be mod.STATE` is a snapshot — through every alias, a re-export (`export let L be mod`),
  a module kept in a map, `parallel_map` and `serve`. A module gains no names from outside and its
  tasks are not replaceable (`set mod.f to …` and `set mod["f"] to …` are errors). The common idioms
  stay O(1) per step: `set xs to append(xs, v)`, `xs + [...]`, `insert(xs, i, v)`, `merge(m, …)` and
  `set m[k] to v` write in place, also through a path (`set s.items to append(s.items, v)`).
- **A `set` target starts from a variable**: `set get(m, "a")["b"] to 1` is an error (with value
  semantics it either wrote a throwaway copy or leaked into shared data). **What to write instead:**
  the path from the variable, `set m["a"]["b"] to 1`.
- **Strict arity** for calls written in the program: a missing parameter without default or an
  extra argument is an error (`task 'f' takes 1 argument, got 3`, `append() takes at most 2
  arguments, got 3`). Before, extras were dropped silently (`append([1], 2, 3)` lost the 3,
  `trim(s, "x")` ignored the `"x"`) and missing ones arrived as `nothing`. Callbacks that a builtin
  or the host calls (`apply`, `where`, route handlers, cron) keep receiving what they get.
- **`-2 ** 2` is -4** (power binds tighter than unary minus, as in math and Python).
- **`|>` has the lowest precedence** and a call step receives the value as its first argument:
  `1 + 2 |> double` is `double(3)`, `xs |> sort_by(f)` is `sort_by(xs, f)`.
- **`number(text)` of an integer beyond ±2⁵³ is an error** naming `int` (it used to lose digits).
- **Integer vs float comparison is exact**: `2**53 + 1 == 9007199254740992.0` is `false`.
- **A non-integer index, position or step is an error** (`xs[1.7]`, `range(0, 2.5)`); `2.0` is fine.
- **Text + `nothing`/list/map/bytes is an error** (was `"xnothing"`); text + number/bool still joins.
  A template hole takes any value, like an f-string: `` `xs={xs} n={nothing}` `` → `xs=[1, 2] n=nothing`.
- **Inside lists and maps, text is shown quoted**: `print(["1", 1])` → `["1", 1]`.
- **`--` glued to a value and followed by a number or `(` is a lexer error** (`5--1` and `x--(y)` used
  to be a value plus a comment: a silent arithmetic result). Followed by anything else it is still a
  comment, as in v0.6.28: `print(1)--note`, `x--note`, `"a"--note`. Inside
  parentheses, `print(x --1)` is a lexer error that points at `x - -1` (as a comment it would swallow
  the `)`); it fires only when a value comes before on the same line, a digit or `(` comes after, the
  innermost bracket is `(` and its closing `)` is on that same line. Any other `--` is a comment, as
  always: `"a": 1,  --TODO` in a multiline map or list, or `4 --note` in a call that spans lines,
  keeps working.
- **`sort_by` orders totally or errors** (it silently left mixed or NaN lists as they came);
  `nothing` and NaN go last; `min`/`max` skip `nothing` and propagate NaN.
- **`fmt` errors on a `{name}` without a value** (it was left in the text). `{a.b}` reads the key
  `"a.b"` if the map has it, else the field `b` of the map `a`; `{ x }` with spaces, and `{obj.prop}`
  when the map has no `obj`, stay literal (CSS and JavaScript in a template are safe). Text between
  braces that is EXACTLY a key of the map is always replaced, whatever its shape
  (`fmt("[{0}] {a-b}", {"0": "z", "a-b": 1})` → `[z] 1`). Otherwise a hole is a name that starts with
  a letter or `_` (dots between names): regex quantifiers such as `{3}` and `{3,5}`, `{}` and `{a..b}`
  stay literal — `fmt("^[0-9]{3}-{n}$", {"n": 1})` → `^[0-9]{3}-1$`.
- **`solana_tx` and `algorand_tx` now BUILD** (they were `solana_message` / `algorand_tx_encode`);
  assembling the signed transaction is `solana_tx_raw` / `algorand_tx_raw`. The old two-argument
  call errors pointing there.
- **`json_decode("1e400")` is an error** (it gave infinity, which JSON cannot carry back); integers of
  more than 4300 digits are an error in `json_decode`/`jsonl_decode`/`int(text)`/`number(text)` (the
  Python limit: converting them is quadratic, so a hostile document could buy minutes of CPU).
- **`int("ff", 16)` is an error that says why** (any whole number 2..36 as the second argument of
  `int`, whatever the first argument is — the result never depends on the data): that argument is the
  fallback, not the base. **What to write instead:**
  `int("ff", base = 16)`, or name a numeric fallback: `int(text, fallback = 10)`.
- **Float `//` and `%` are CPython's**: `7 // 0.1` is 69.0 and `7 % 0.1` is 0.09999999999999962 (they
  were 70.0 and 0.0); arrays too, as numpy.
- **Number literals take `_` only between digits** (`1_000`, `0x_ff`): `1__0`, `1_`, `1_.5`, `1e3_`
  are lexer errors, as in Python (`1__0` was 10 and `1_` was 1).
- **`\uXXXX` and `\u{1F600}` in a string are escapes** (`"\u00e9"` is `"é"`; a surrogate pair
  `"\uD83D\uDE00"` is one character); before, the six characters stayed as written. `synsema check`
  flags every literal that uses one. **What to write instead:** `"\\u00e9"` for a literal backslash + u.
  Anything that is not a complete escape stays literal (`"C:\users"`, `"\u12"`), `\x` is NOT an escape
  (`"C:\build\x64"` and the regex `"a\x2eb"` are unchanged), and inside a backtick only the four-digit
  form is one — `` `x\u{a}y` `` still interpolates `a`.
- **`decimal` has arbitrary precision and a stable type** (the best of Java's `BigDecimal`,
  Postgres `numeric`, Python `decimal` and Julia's promotion rules):
  - `+`, `-`, `*`, `//`, `%`, `**` with an integer exponent and every comparison are EXACT at any size.
    `1d + 10**30` is the decimal 1000000000000000000000000000001, `1d < 10**30` is true, and
    `1.1d ** 30` has its 30 decimals. Before, a result past 28 digits turned into a float.
  - `/` and `std` round to 28 SIGNIFICANT digits, half to even (Python's default context), never cutting
    the integer part (like Postgres). `0.00000000000000000001d / 10000000000d` is 1e-30 exactly; it was
    `0`, because the old decimal only had 28 places after the point.
  - A decimal operation always gives a decimal; it never turns into a float or an integer depending on the
    value. Literals, `decimal(text)`, CSV `decimal` columns, Parquet decimal columns and Postgres
    `numeric` take any number of digits (up to 4300 in text). A Parquet decimal of more than 28 digits
    used to come back as text.
  - `floor`, `ceil`, `round` and `trunc` of a decimal give the exact integer. They returned the decimal
    unchanged.
- **A decimal compared with a float is an error wherever they really meet**, as `1d == 1.0` already
  was: inside lists and maps (`[1d] == [1.0]`), in `in`, `match` value patterns, `contains` and
  `index_of` (`contains([1.5d], 1.5)` was a silent `false`; a `match` fell to `otherwise`), and as a
  key of `group_by`, `unique`, `join`… (details under Added). Integers mix freely (`[1d] == [1]` is
  `true`). **What to write instead:** convert first, `decimal(x)` or `float(x)`.
- **`join(xs, sep)` with `nothing`, a list or a map inside is an error** (it wrote "a,nothing"), and
  text + a task is an error like text + a list.
- `while` has no iteration cap (was 1,000,000; the wasm build keeps it — its host has no `timeout`,
  threads or signal to stop a loop that never ends, and would hang); `print`, `log` and `show` under `synsema run` are
  written immediately, in order.

### Added

- **Numbers:** `int(x)` / `int(x, default)` / `int(text, base = b)` (exact; decimal, `0x…`, `0b…`,
  a sign before `0x`), the floor-division
  operator `//` (exact for integers of any size), `hex(x)` (quantity for integers, data for bytes),
  literals `0x1f18`, `0b101`, `1e-9`, `json_decode` keeps integers of any size exact,
  `bytes(s, "hex")` accepts `0x`, `is_integer`/`is_text`/`is_list`/`is_map`.
- **Syntax:** `in` / `not in`, chained comparisons (`1 < x <= 10`), negative indexes (`xs[-1]`),
  text indexing (`s[0]`), any word as a member after `.` (`ev.type`, `tx.to`), `each` over maps
  (keys), text (characters) and bytes, a trailing comma in calls, as in lists and maps.
- **Maps and order:** `insert(xs, i, v)`, `get(m, k, default)`, `remove`, `merge`, `items`, `sort(xs, desc = true)`,
  `sort_by(xs, key, desc = true)`, `index_of` on text, `min`/`max` on text.
- **Renamed** (old names are deprecated aliases): `replace_text`→`replace`,
  `find_all`→`regex_find_all`, `capture`→`regex_capture` (always a list or `nothing`),
  `replace_re`→`regex_replace`, `fold`→`fold_text`, `eye`→`identity`, `hmac_sha256`→`hmac` (bytes).
- **Blockchain, `<family>_<action>`:** `eth_*`/`tx_eip1559*` → `evm_*` (`evm_tx`, `evm_tx_raw`,
  `evm_send`, `evm_wait`, `evm_balance`, …), `solana_confirm`→`solana_wait`,
  `algo_address`→`algorand_address`. New: `evm_tx_create` (contract deployment), `evm_tx_raw` checks
  what is signed (it recomputes the digest from `fields`, every echoed field must match `fields`, a
  creation must carry `from`, the signer must be `from` and `contract_address` is re-derived — a map
  edited after `evm_tx` is refused), `evm_create_address`, `evm_create2_address`, `evm_signature`
  (v = 27/28 for wallets and `ecrecover`), `secp256k1_recover` accepts v = 27/28,
  `evm_block_number`, block parameters accept the node's `0x…` quantity (also in
  `evm_estimate_gas(url, tx, block?)` and `evm_fee_history(url, blocks?, percentiles?, newest?)`), `evm_logs`,
  `abi_event_topic`, `abi_decode_log`, `abi_encode(types, values)` without selector (constructor
  arguments), `evm_address` of 20 raw bytes.
- **Errors that speak Python:** `return x`, `x = 1`, `x += 1`, `if x:`, `len(xs)`, `None`,
  `xs.append(y)`, `d.get(k)`, `f"…"`, `lambda y: y`, `x is None`, `a if c else b`, `xs[1:]`,
  `type(x)`, `"%d" % x` and friends get the Synsema form in the message.
- **HTTP:** a URL with `user:pass@` sends `Authorization: Basic` (as curl and requests do); a URL with
  a query and no path, IPv6 hosts and fragments work; `Host` carries a non-default port. A URL
  without a host is an error that does not echo the URL, and `require net("https://u:p@api.x.com/v1")`
  is stored as `net("api.x.com")`: credentials never reach a message or the audit. An EXPLICIT port is
  part of the grant: `require net("http://localhost:8545")` is `net("localhost:8545")` and covers only
  that port (v0.6.28 did not take a URL as a grant at all); `net("localhost")` still covers any port,
  and `[::1]:8545` works.
- **Strings and numbers:** the `\u` escapes above; octal literals `0o17`; `number("1_000.5")`. A decimal
  with a float is an error also inside lists when a comparison meets them at the same position
  (`sort([[1.5d], [1.0]])`; `sort([[1d, 1.5], [2d, 2.5]])` sorts fine) and as a `join` key (they never
  match — it returned `[]`). The same error, `cannot mix decimal and float`, whenever a decimal and a
  float are really compared: in `x in list` (item by item: `1.5 in [1.5d]` is an error,
  `"a" in ["a", 1.5, 1d]` is `true`), and in `group_by`, `count_by`, `summarize`, `unique`, `mode`,
  `pivot` and `n_unique_of` when two keys land on the same number (`unique([1.5d, 1.5])` gave both;
  `unique(["a", 1.5, 1d])` is fine, 1.5 and 1 never meet). NaN does not count. `match` value patterns,
  `contains` and `index_of` follow the same rule (`contains([1.5d], 1.5)` was a silent `false`; a
  `match` fell to `otherwise`). Every equality stops at the first difference: `["a", 1d] == ["b", 1.0]`
  is `false`, and two maps with different keys are `false`. `==` on lists and maps
  compares item by item with the same rule — `[1d] == [1.0]` and `{"a": 1d} == {"a": 1.0}` are the
  error of `1d == 1.0` (they were `false` in silence), `[1d] == [1]` is `true`, and `in` compares
  the same way.
- **More Python/pandas reflexes:** `else`/`pass`/`break`/`continue` on their own line, `c ? a : b`,
  comprehensions, `round(x, 2)`, `x --1` inside parentheses, `dropna`/`fillna`/`groupby`/`value_counts`.
- An engine panic reports itself as an internal error with its message (it blamed a stack overflow).
- Clearer errors: `if (x > 0)` with an indented body says `if` is not a Synsema statement (use
  `when`) instead of `Unexpected token: INDENT` on the next line; an error inside a template hole
  points at the hole (it said 1:1); SQLite's own texts are rewritten — a statement that returns rows
  in `sql_exec`/`sql_batch`, and `the statement has 1 parameter(s) but 0 value(s) were passed`.
  `synsema check` no longer says a glob `require file.read("./*")` misses `read_file("./x.csv")`.
- **Fixed:** `btc_rpc` against a real Bitcoin Core failed with an empty `RPC error:` — JSON-RPC 1.0 sends
  `"error": null` in every good answer. On SQLite, `sql_exec` refuses a `RETURNING`
  statement before running it (SQLite had already written the row); the word inside a string or a
  comment does not count. Postgres and MySQL run it as before and return the count. `sql_batch` does
  the same check before running any row (it wrote the first one and then failed).
  `abi_decode_log` refuses two inputs that would get the same name (one value was lost), `evm_logs` a
  filter with more than 4 topics, `evm_create_address` a nonce of 2^64 − 1 or more (EIP-2681).
  `synsema code caps` reads `require net(<url>)` as its host (and its port, when the URL has one), like
  the runtime. `except`/`catch` after a `try` and `finally` name the Synsema form.

**Breaking, on purpose (data).**

- **`std` and `var` are sample statistics** (`ddof = 1`, like pandas, polars, R and Excel `STDEV.S`):
  `std([1,2,3,4])` is 1.29, not 1.118. **What to write instead:** `std(xs, ddof = 0)` for the population
  figure. `synsema check` flags every `std`/`var` until v1.0.
- **`group_by(rows, key)` returns `[{key, items}]`** in first-appearance order, with the key's own type
  (`1` and `1.0` are one group). It returned a map keyed by text. **What to write instead:**
  `each g in group_by(rows, "region")` → `g.key`, `g.items`; for per-group figures, `summarize`.
- **`dot` is the inner product of two vectors only**; for matrices use `matmul(a, b)`.
- **Reductions skip `nothing` and propagate NaN** (`mean([1, nothing, 3])` is 2.0; `median` no longer
  errors on NaN, it returns NaN).
- **An empty CSV field is `nothing`** (was `""`); a quoted `""` is empty text, and `csv_encode` writes
  them apart, so a round trip is exact. `synsema check` warns about `x == ""` in a program that reads CSV.
  A blank line is always skipped when reading, also in a one-column CSV (like Python `csv` and pandas):
  `csv_parse("x\n1\n\n2\n")` has 2 rows. So a row whose only field is `nothing` is written `""`, as
  Python's writer does — the one case where the round trip does not tell `nothing` from `""`: in a
  one-column CSV a missing value comes back as empty text (or `nothing` if the column has a type), and
  `csv_encode` warns once on stderr. For an exact round trip with any number of columns,
  `csv_encode(rows, {"missing": "NA"})` writes each `nothing` as `NA` without quotes (pandas'
  `na_rep`) and quotes a text that equals the mark; read it back with `{"missing": ["NA"]}`. An empty
  mark is an error (an empty field already reads as `nothing`, and in one column it would be a blank
  line that reading skips).
  A quote left open in a CSV whose lines end in `\r` (old Mac) is an error with the right line, like
  `\n` and `\r\n` (it was read to the end of the text in silence).
- **A column name that no row has is an error** in `group_by`, `summarize` aggregates (`sum_of("vv")`),
  `join` and `pivot` (a misspelling summed to 0); an aggregate named like a key column, or two pivot
  values that would become the same column, are errors instead of overwriting.
- **`polyfit` errors when the data does not determine the fit** (fewer distinct x than degree + 1);
  numpy only warns.
- **`round_to` rounds a float's real binary value, like Python** (`round_to(2.675, 2)` is 2.67) and keeps
  decimals decimal.
- `format_time`, `parse_time` and `date_parts` no longer require `time` (they don't read the clock).
- **Fixed:** `format_time` with an unknown specifier (`%Q`), or with one the value does not have (`%H`
  of a `date`), crashed the engine and `try` could not catch it. Now it is an error that names it:
  `format_time: "%Q" is not a strftime specifier (…)`.

### Added (data)

- **Tables** (lists of maps): `summarize(rows, by, aggs)` with `sum_of`, `mean_of`, `min_of`, `max_of`,
  `median_of`, `quantile_of`, `first_of`, `n_unique_of`, `count()`; `count_by`; `join(left, right, on,
  how?)` (inner/left/right/outer/semi/anti, by hash, every output row with every column);
  `pivot(rows, index, columns, values, agg?)`; `is_missing`, `fill_missing`, `drop_missing`,
  `fill_nan`; `mode`; `count(xs)` (present values) and `count_missing(xs)`. A column is checked
  against the whole table (ragged rows are fine; a name no row has is an error); `join` refuses an
  output name that already exists (not in `semi`/`anti`, which add no right columns). Keys follow `==`: maps with
  the same entries in another order, the same instant in another zone, `1` and `1.0` are one group;
  the text `"1"` is another; NaN is one group. `unique`, `mode` and `n_unique_of` are linear.
- **Reductions:** named `axis =` and `ddof =`, `quantile(values, q)`, decimals kept, `min`/`max` on
  dates. **Arrays:** elementwise math, `**`/`//`/`%`, `length`, negative index, `slice`, `apply`,
  `where` as a mask, `concat`, `stack`, `argmin`, `argmax` (a list skips `nothing`), `cumsum`, `diff`.
  **Statistics:** `corr`, `cov`, `lstsq` (numpy's: SVD, minimum norm, works rank-deficient),
  `polyfit`, `polyval`. `median`, `var`, `std`, `quantile` and `percentile` of decimals (with integers of
  any size) are computed exactly, like Python's `statistics`, and are always decimals — exact when the
  result terminates, else 28 significant digits (`std` of decimals that differ by 1e-15 is
  `0.000000000000001527525231651946668862682398`, never `0`).
- **Seeded randomness, pure — the same numbers as numpy:** `rng(s)` is `numpy.random.default_rng(s)`
  bit for bit (SeedSequence + PCG64): `g()`/`random(g)`, `random_int(g, lo, hi)` (=
  `integers(lo, hi + 1)`), `random_normal(g, mean =, std =)` (numpy's ziggurat), `shuffle`
  (`permutation`), `choice`, `sample` (`choice(…, replace=False)`) and `rng_spawn(g, n)` (`spawn`) —
  verified value by value against numpy 2.2. A generator is a process, like numpy's: `let h be g` is
  the same stream; `rng_spawn` gives independent ones, and they travel to `parallel_map` workers,
  which hand back how far they advanced (as `apply` would: using `g` or the children again continues
  the sequence). Passing the SAME generator to two items (at any depth), or using a top-level
  generator — by name, inside a global map or list — inside a worker or a `serve` request, is an
  error (numpy silently repeats the sequence).
  Allowed under `--deterministic`.
- **Dates as types:** `date`, `datetime` (an IANA zone, DST-correct, or a fixed offset) and `duration`,
  with arithmetic,
  comparison, `add_days`, `add_months`, `truncate`, `date_range` (by `"second"`, `"minute"`, `"hour"`
  — elapsed time — or by a calendar unit or a duration), `to_timezone`, `timestamp`,
  `in_units`, `parse_date`, `parse_datetime`; JSON and CSV write them as ISO 8601. Calendar steps keep
  the local time across a DST change, a day without midnight starts when it starts (01:00), a day
  that never existed is skipped by `date_range` instead of repeating the next one (Pacific/Apia,
  30/12/2011), and
  truncating or adding days/months inside the repeated hour keeps which of the two it was
  (`add_days(t, 0)` is `t`); a day whose midnight repeats is one day. **An offset is kept**, as in
  Python, java.time, Temporal, Arrow and pandas: `datetime("2026-09-24T02:00:00+05:30")` prints as
  such, `date_parts` gives hour 2 and zone `"+05:30"`, and calendar operations use that local time
  (equality and order are by instant); `+0530` reads too, and a zone can be a fixed offset anywhere
  (`to_timezone(t, "-03:00")`, `parse_datetime` with `%z`). RFC 9557 as in Temporal:
  `…T10:00:00[Asia/Kolkata]` is 10:00 local time there (a DST gap → error), and an offset that does
  not match its bracketed zone → error.
- **Formats:** `csv_parse(text, {"types": {...}})` (int/float/decimal/text/bool/date/datetime per
  column) and `{"missing": ["NA", "NULL"]}` (those texts, unquoted, are `nothing` — polars'
  `null_values`; a quoted `"NA"` stays text); a `float` column refuses `1e400` (it was infinity) and
  reads `nan`/`inf` written as such; an integer of more than 4300 digits is an error, as in `int()`;
  the delimiter cannot be the quote or a line end. `csv_encode(rows, {"escape_formulas": true})`
  prefixes `'` to a text that starts with `=`, `+`, `-`, `@`, tab or CR, so Excel and Sheets show it
  instead of running it (OWASP "CSV injection"; off by default because it changes the data).
  `jsonl_encode`/`jsonl_decode`, `parquet_read`/`parquet_write` (read and written by polars in
  tests; zstd/snappy/gzip/lz4; a datetime column keeps its zone, also the zone polars and pyarrow
  write in the Arrow schema (`ARROW:schema`), a fixed offset such as `+05:30` included; nanoseconds
  are read and written; a file with two columns of the same name is an error, and so is writing an
  integer beyond 2^53 in a column that mixes integers and floats (it would be rounded to a DOUBLE); a
  `TIME` column (time of day) reads as a `duration` since midnight, in ms, µs or ns (polars writes ns;
  it came back as a bare integer);
  a file that would expand past its caps — a page over 256 MiB, max(1 GiB, 64 × the file), 50 million
  cells — is refused before allocating, `{"max_cells": n, "max_bytes": n}` raises them; not in the
  wasm build). `json_decode` skips a BOM and reads the `NaN`/`Infinity` that `json_encode` writes only
  when asked — `json_decode(text, allow_nan = true)` (also `jsonl_decode`); by default they are an
  error, because a NaN passes every `amount <= 0` check;
  raw RPC answers (`evm_rpc`, `solana_rpc`, `btc_rpc`, algod) keep integers beyond 64 bits exact.
- **Lineage:** the engine records every input the program reads — files, directory listings, `grep`,
  Parquet, stdin and the terminal, HTTP, SQL/Mongo/Redis reads, `recall`, chain nodes (EVM, Solana,
  Algorand, Bitcoin), sockets and processes, and every model answer (`reason`/`decide`/`analyze`/
  `generate`) and what `run`/`run_program` return — with the sha256 of what it received and its
  `encoding` — `"text"` (utf-8), `"bytes"`, `"jcs"` (`canonical_json(x)`), `"json"` (`json_encode(x)`,
  for integers beyond 2^53 or NaN) or `"display"` (the printed form, for what neither can carry) — so
  anyone recomputes it; `lineage()` lists it and `receipt()` publishes it as `inputs`, so a signed receipt
  proves which inputs, which program and which output. A host is published without credentials,
  path or query; a read that never arrived is not an input.
  - **The receipt never carries data.** An input's `what` is only a path the program passed as text,
    a host, a salted commitment or a size: `parquet_read(bytes)` records `bytes <n>` (not the file's
    first bytes), `grep` the target and never the pattern, and a host comes only from the CONNECTION —
    the URL of `http_*`/`fetch` or the node of a chain reader — with a network scheme (`http`, `https`,
    `ws`, `wss`): a `://` inside a SQL query, a redis or Mongo key, or a `recall` category such as
    `"session://TOKEN"` is data, not a host, and only its salted commitment is published.
  - **Queries and prompts are salted commitments**, like SD-JWT disclosures. This covers a SQL query, a
    Mongo filter, `run` arguments, an RPC call and a model prompt.
  - The receipt publishes `query sha256-salted:<hex>` = `sha256(salt ‖ canonical_json([args…]))`, with a
    fresh 128-bit salt per entry. Nobody can recover the query by hashing guesses (a plain sha256 of
    `run("id", "-u")` can be recovered that way).
  - The salt stays in the local `lineage()` (`salt`, `committed_encoding`) and never in the receipt.
    With it, the owner can later reveal one query and anyone can check it:
    `hex(sha256(bytes(salt, "hex") + bytes(canonical_json(args), "utf8")))`.
  - Redis counters (`redis_incr`, `redis_incrby`, `redis_decr`, `redis_hincrby`) are inputs too.
- **`synsema check`** also warns about `each r in rows` + `set r[…]` (it changes the loop's copy):
  it warns when the write is lost, even if the loop reads other fields to compute it
  (`set r["total"] to r["p"] * 2`, `when r.p > 1`), and stays quiet when `r` leaves the loop whole
  (passed, appended, printed) or a field the loop wrote is read afterwards.


## v0.6.28 — 2026-09-22

Identity and trust between agents: the token is the ceiling, passkeys, `did:key`, signed
documents, receipts and the Agent Card. One breaking change, on purpose, below.

**Breaking, on purpose.** Under `serve`, when the `auth with` task returns the map of
`captoken_verify`, the token's `caps` are now the request's **delegated ceiling**: a capability the
program declares but the token does not carry is **denied at use**, `llm` and `judge` included, and
the client receives `403 {"error": "insufficient permissions", "status": 403}` — a fixed body that
never names the capability. Before, the `caps` were advisory (`captoken_allows` only) and only the
`spend` caveat was enforced; a handler that ignored the token's `caps` kept working. It keeps
working only if the token carries what the handler uses. **What to write instead:** mint the token
with the capabilities the holder needs (list `llm`/`judge` if it must reason); or, if you never
wanted the ceiling, return the identity as text from `auth with` rather than the token map.

**Breaking, on purpose (tokens).** `captoken_mint`/`captoken_attenuate` refuse the process-local
capabilities `stdout`, `stdin`, `time`, `random` (`… is process-local: a token cannot delegate it`),
and `captoken_allows` errors when asked about them. A token carries transferable authority, not
another process's clock; the host ceiling governs those. To run a holder without clock or entropy,
use the new caveat `deterministic: true`.

### Added

- **The delegated ceiling, in three places.** A verified captoken is the ceiling of a `serve`
  request (above), of a child program (`run_program(src, {"ceiling": verified})`, which also takes a
  plain `{capability: scopes}` map) and of a block: **`sandbox under <caps>`**, a least-privilege block
  that runs its body under `caps ∩ the current ceiling` — a literal map or the map of
  `captoken_verify` — with `require` inside still a no-op. Nested blocks stack; every level must cover
  the use. Process-local capabilities are never delegable; the host ceiling always wins.
- **Two caveats.** `deterministic: true` (the holder runs without `time` and `random`, like
  `--deterministic`; once set, no attenuation turns it off) and `llm_tokens: N` (a delegated LLM
  budget, metered on the token's `id` beside `SYNSEMA_LLM_BUDGET_PER_IDENTITY`; can only decrease).
  `captoken_verify` reports both in `caveats`.
- **The subject travels with the ceiling.** An agent spawned from a handler, a `parallel_map` worker
  and a `run_program` child run on behalf of the same identity, under the same delegated ceiling,
  spend limits and LLM budget (the child gets them through an internal variable set after the
  program's `env`: a program cannot choose its child's identity); the `errors with` page runs under
  the request's subject too; a cron tick runs as `cron:<job>`; `synsema run` runs as the operator
  (`SYNSEMA_IDENTITY`, optional, from the environ or `.env`, in `.env.example`).
- **A verified token's ceiling never opens.** Process-local names in a token's `caps` are ignored
  (a token minted by an earlier engine keeps being a ceiling); an unknown name closes it (empty
  ceiling, one stderr warning). The `sign`, `spend`, `wallet`, `secret`/`env`, `reveal` and
  `render` gates keep the delegated cause: denied by the caller's token → the fixed 403, never a
  500 that says `add require …` about a program that already declares it.
- **Denials say they are permissions.** `Capability not granted: X` now ends with `— this is a
  permission, not a bug: add `require X` to the program's preamble (or to the importing file, when
  this code runs in a module)`; a denial by a token says `denied by the delegated ceiling of token
  <id>` (the caller must present a token that carries it), a `sandbox under` one says so too. The
  audit gains the reasons `above delegated ceiling (token <id>)` and `above sandbox ceiling (sandbox
  under)`, with `source: token`/`sandbox` on rejected grants.
- **`synsema check` warns about undeclared capabilities**, including what an imported module's tasks
  need and the importing file does not declare, with the exact `require` to add (reusing `synsema
  code caps`). Warning, not error.
- **Handler mode (wasm)** applies the same delegated ceiling and 403, so the native ↔ wasm audit
  parity holds.
- **Passkeys (WebAuthn), pure.** `webauthn_register(credential, opts)` verifies the registration
  ceremony and returns the credential's public key as a JWK (`id`, `public_key`, `alg`,
  `sign_count`, `fmt`, `aaguid`, flags, `transports`); `webauthn_verify(assertion, credential,
  opts)` takes the **stored credential map** (what register returned, plus the `sign_count` and
  `user_handle` you keep) and verifies an authentication (challenge, origin — one or a list —,
  `rp_id`, flags, signature over `authenticatorData ‖ sha256(clientDataJSON)`, the counter, and
  that the assertion's credential id IS the stored one — `rawId`/`userHandle` are not signed, so the
  returned `id`/`user_handle` are the stored ones, never what the assertion declares) and returns
  `{id, user_handle, alg, sign_count, …}` or `nothing` on any failure. ES256, RS256 and EdDSA; the
  registered key fixes the algorithm. Attestation is reported (`fmt`) and not verified, on
  purpose; the builtins keep no state.
- **`canonical_json` (RFC 8785 / JCS)**: deterministic bytes for hashing and signing; refuses what
  JCS cannot carry exactly (integers beyond 2^53, decimals over 15 significant digits, bytes,
  secrets) instead of approximating.
- **`did:key`**: `did_key_encode(public_key, alg?)` (ed25519, p256, x25519, secp256k1),
  `did_key_decode`, `did_key_document` (DID Document with Multikey verification methods and, for
  ed25519, the derived X25519 `keyAgreement`).
- **Signed documents (W3C Data Integrity)**: `document_sign(doc, key, opts?)` adds a
  `DataIntegrityProof` — `eddsa-jcs-2022` with an ed25519 secret (gate `sign("NAME")`, audited) or
  PKCS#8 PEM, `ecdsa-jcs-2019` with a P-256 scalar or PEM (`verificationMethod` defaults to the
  signing key's `did:key`); `document_verify(doc, public_key, opts?)`
  takes bytes, a `did:key`, a public-key PEM or a JWK and returns the proof's metadata or
  `nothing`.
- **Receipts**: `receipt(opts?)` — the receipt of the running unit of work as a Verifiable
  Credential **derived by the engine**: identity, captoken ids in force, the capability audit (the
  snapshot at issue time), this identity's spend totals per unit, `declassify` log, steps,
  `program_sha`, engine version and `declared_result_sha256` (of the value the program passes as
  `result`). `issuer` is always the `did:key` of the signing key and `validFrom`/`created` are the
  engine's clock (omitted without `time`): neither is an option, so a receipt cannot be antedated
  or issued in another's name. Opts: `sign`, `verification_method`, `cryptosuite`, `challenge`,
  `domain`, `result`. `receipt_verify(receipt, public_key, opts?)` also requires the issuer and the
  verification method to be the verifying key's did.
- **EdDSA JWTs**: `jwt_sign` gains `opts.alg = "EdDSA"` (Ed25519 PKCS#8 PEM or the 32-byte seed;
  with a `secret` it goes through `require sign("NAME")` + audit, like `ed25519_sign`);
  `jwt_verify`'s key map gains `{"did": "did:key:z…"}` (ed25519 → EdDSA, P-256 → ES256, resolved
  offline; a `kid` in the token must be `did:key:z…#z…`); `oidc_verify` accepts OKP/Ed25519 JWKs.
- **The Agent Card, derived and signed.** Every `serve` publishes
  `/.well-known/agent-card.json` (alias `/.well-known/agent.json`): the **A2A 1.0** card shape
  (`message AgentCard` of `a2a.proto` in proto-JSON: `securitySchemes` as `httpAuthSecurityScheme`
  / `apiKeySecurityScheme`, `securityRequirements`, no `url`) — skills from the route table,
  security schemes when auth is wired, and inside `capabilities.extensions` the Synsema extension
  with the server's `did:key`, base URL, OpenAPI, auth discovery, attestation (under `--attested`)
  and engine — with `supportedInterfaces: []` because a Synsema server does not speak the A2A
  transport and the card never claims it. Signed as a JWS (A2A §8.4, payload = JCS of the card, `kid` = the did's
  verification method) with **`SYNSEMA_IDENTITY_KEY`** (new knob: the server's ed25519 seed, 64
  hex, in `.env.example`) or, under `serve --attested`, with the attested P-256 key. Without a key
  the card is served unsigned and without `did`. Both paths are reserved (`synsema check` warns
  on a parametric route that would swallow them); `/llms.txt` lists the card.
- **ERC-8004 as an example module** (`examples/erc8004/`): the registration file (pointing at the
  Agent Card and the did), `document_hash`, and the calldata of the Identity, Reputation and
  Validation registries via `abi_encode` — a client of the registry, not a primitive of the engine.

## v0.6.27 — 2026-09-21

No breaking changes to programs: a program that loads on v0.6.26 loads unchanged, and the new
inference engine is opt-in. **One answer does change, on purpose:** a GGUF of the llama family
(llama 1/2, Mistral, Gemma) was being tokenised wrong and now is not, so with those weights the
local provider generates different — correct — text than it did before. See *Fixed*.

### Added

- **`synsema-infer`: local inference is now a crate of our own.** The GGUF loading, the tokenizer,
  the instance pool, the KV cache, generation and sampling moved out of `llm_local.rs` into
  `engine/crates/synsema-infer`, behind a facade with three doors — `generate` (the `local` LLM
  provider), `embed` and `decide` (the local judge). candle is one backend behind our own trait,
  not the shape of the code. Nothing in the language changed; the reason is in
  `specs/synsema-infer.md`.

- **`SYNSEMA_LLM_MODEL` takes a name, not only a path.** Three forms, and **none of them downloads
  anything**: a path to a `.gguf`, a `model:tag` already in the Ollama cache, or an `org/repo`
  already in the Hugging Face cache. A developer who already has Ollama runs their first `.syn`
  with a local model without fetching a byte. Ollama's store is content-addressed, so the sha256
  of the weights comes for free and is reported as provenance.

- **A backend written by us: `SYNSEMA_INFER_BACKEND=rust`.** No candle in the tree for that path.
  Two things it buys today: it runs **gemma3**, which candle does not ship quantized, and it picks
  its SIMD (AVX, AVX2+FMA, AVX-512, NEON) **at run time**, so the official binary uses the
  instructions of the machine it lands on — the `-C target-cpu=native` rebuild that the docs used
  to ask for is no longer the only way to get it. The default stays candle while both exist:
  switching engines changes the generated text, so it is part of what you declare to reproduce an
  output, next to the binary and the weights.

- **Architectures are declared in a file, not compiled in: `SYNSEMA_INFER_ARCHDEF`.** An
  architecture is a list of named steps over the tensors of a GGUF (`.archdef`) — the four we ship
  (llama, qwen2, qwen3, gemma3) are embedded in the binary, and a directory of your own adds new
  ones, or replaces ours, **without recompiling anything**. The format has no conditionals, no
  loops and no way to read a file, open a socket or call anything, so using someone else's
  definition does not execute their code: the worst it can do is not load, or give wrong numbers
  with your own weights. A file that fails to parse leaves **that** architecture unavailable with
  the error of the file — it never silently falls back to ours. `synsema llm status` says which
  definition is running and with what sha.

- **`judge` runs locally: `SYNSEMA_JUDGE_PROVIDER=laya`.** The third backend of the judge slot,
  next to `typesafe` and `mock`: a Laya (ModernBERT) checkpoint on disk answers `whether`, `choose`
  and `rate` **with no network, no secret and no cost per token**, so the offline degradation to
  confidence 0 stops being the common case. The same `judge` block runs unchanged; point
  `SYNSEMA_JUDGE_MODEL` at the checkpoint directory (or an `org/repo` already in the Hugging Face
  cache). The official binaries ship with it compiled in.

- **`synsema llm status` says what is actually on this machine.** The models already downloaded
  (name, origin and sha when the store gives it for free), the architectures this binary knows with
  their origin and sha, and the definitions from your directory that failed to load with their
  error. `--json` carries the same under an `inference` key, with the **full** sha — provenance is
  only useful if it can be compared, and comparing prose is not comparing.

- **`synsema judge status` shows only what applies to the backend.** `typesafe` gets key, model,
  base URL and timeout; `laya` gets the checkpoint; `mock` gets none of it. It used to print
  `TYPESAFE_API_KEY ✗ FALTA` and a base URL nobody was going to call, which is noise that makes
  people doubt a diagnosis that is right.

### Fixed

- **The SentencePiece tokenizer was wrong for the whole llama family.** GGUF files whose
  `tokenizer.ggml.model` is `llama` (llama 1 and 2, Mistral, Gemma) store **ranks**, not
  log-probabilities, and we were segmenting them with a Viterbi pass that maximises the sum of the
  scores. `The capital of France is` entered the model as eleven fragments instead of five words,
  and nothing failed — the model just answered badly. It is now the reference algorithm (merge the
  neighbouring pair with the best score, as llama.cpp does), written by us, with literal
  recognition of special tokens, byte fallback and `add_space_prefix` read from the metadata. The
  BPE family (qwen, llama 3) was never affected.

- **gemma3's MLP activation was `silu` and it is `gelu_pytorch_tanh`.** Copied from candle's
  `quantized_gemma3`, which hardcodes `silu` while its own non-quantized `gemma3` reads the config.
  With the tokenizer fixed, both produce readable text — the difference shows in the numbers (top
  logit 7.91 vs 27.02) and in the exact answer. The engine now generates, token for token, what
  Ollama generates for the same prompt.

- **Gemma had no chat template.** `<start_of_turn>` was not recognised, so a gemma GGUF fell back
  to plain mode and behaved like a base model.

- **`synsema llm status` listed the wrong architectures with candle active.** It printed the four
  `.archdef` definitions — gemma3 among them, and any file of yours — no matter which backend was
  selected, while candle runs neither. The runtime was always right; the report was the one
  dressing it up. It now lists the architectures of the backend that will actually run.

- **`SYNSEMA_INFER_BACKEND` and `SYNSEMA_INFER_ARCHDEF` are read from the `.env`.** They were
  resolved straight from the process environment while `synsema init` documents them in the LLM
  section of `.env.example`, which is the part that *is* auto-loaded. Setting them there did
  nothing, silently. They now follow the same `environ > .env > default` precedence as every other
  knob, and `synsema init` writes both.

## v0.6.26 — 2026-09-20

No breaking changes to programs. `synsema check` is stricter on `judge` blocks: see below.

### Added

- **`synsema check` fails on a `judge` block the API would reject.** With literal criteria: fewer than
  2 options or levels (the API accepts one and answers with confidence 1.0 — an empty answer dressed
  as certainty), more than 255 options or 10 levels, duplicate option or level ids; also an empty
  literal instruction and a literal `state` that is a number, a bool or `nothing`. These were a 400
  in production or a fake certainty; they are a check error now. Dynamic criteria keep the run-time
  check before the call.
- **`synsema check` warns**, never fails, on a `whether` phrased in the negative (P(not A) is not
  1 − P(A): measured 0.37 + 0.78), on an instruction that asks for arithmetic or counting over the
  state (the model recognises the shape of an answer, it does not calculate), on an empty literal
  state, and on the same `judge <variable>` appearing in more than one block (one call would do).
- **Backticked paths are verified against the state before the call.** `` `ticket.messages[0].text` ``
  is the vendor's idiom and it points at the exact element; a path the state does not have gets a
  warning with the fix — including the common trap of `judge ticket` with `` `ticket.x` `` in the
  question, where the model sees the value and not the variable name.
- **`synsema judge status [--json]`**: the resolved configuration of the judge slot with the source
  of each value — provider, key presence (never the value), model, base URL, timeout, budget, whether
  `decide` is served by the judge — and, when offline, one line that names what is missing. Exit 0
  live, 1 offline. Same `--env-file` / `--no-env-file` as the rest.
- **`SYNSEMA_JUDGE_DECIDE=1`: `decide` served by the judge.** Every `decide between […] given X`
  becomes one calibrated `choose`: one of your options byte-for-byte, no normalisation, no retry,
  cheaper and faster than a chat model, with no change to the program. Opt-in and off by default
  because it changes which model answers; it needs the `judge` capability (under `serve` a `decide`
  without `require judge` fails naming the knob); when the judge is unavailable the `decide` falls
  back to the LLM path. Verified live. Written by `synsema init` into `.env.example`.

## v0.6.25 — 2026-09-20

No breaking changes. Programs that load on v0.6.24 load unchanged.

### Added

- **`judge` — calibrated judgments as values.** A new expression asks a *System One* model (the first
  backend is TypeSafe's Jev) typed questions about one `state` and gets probabilities back, not text:
  `whether "…"` (the probability a statement is true), `choose "…" between {…} [or nothing]` (an
  option, its distribution and a confidence), `rate "…" across […]` (a position on ordered levels,
  the winning level, the distribution and a confidence). One block is one call; the block is the
  only form on purpose. The result is a flat map id → answer; every answer carries `kind` and
  `available`. `or nothing` adds an escape option so a state that fits no option yields `choice` =
  `nothing` instead of a confident wrong pick. Options and levels take a list or a map (id →
  description) under one rule. The instruction may be a map (read as structure).

- **`require judge`, a capability of its own.** Not granted by `llm` and not granting it: classifying
  and generating are different rights. Auto-granted in plain `run`/`conform`, required under `serve`
  and in secure mode, emptied in `sandbox`, denied under `--deterministic`, offline in a wasm guest.
  Under `--labels` the block is a declared public sink.

- **Honest degradation.** Without a provider, over `SYNSEMA_JUDGE_BUDGET`, or after a network
  failure, every answer is `available: false` with `confidence: 0` and its main value `nothing` —
  a confidence gate then routes to the human path by itself, and a direct comparison fails loud
  instead of branching in silence. An invented probability is never returned.

- **The parallel slot.** `TYPESAFE_API_KEY`, `SYNSEMA_JUDGE_PROVIDER` (`typesafe` | `mock`),
  `SYNSEMA_JUDGE_MODEL`, `SYNSEMA_JUDGE_BASE_URL`, `SYNSEMA_JUDGE_TIMEOUT`, `SYNSEMA_JUDGE_BUDGET`,
  all written by `synsema init` into `.env.example`. The key never enters the program; the host is
  fixed by the runtime. 429/529 are retried with backoff honouring `retry-after`; a 400/422 is a
  runtime error carrying the vendor's message. Builtins `judge_available()`, `judge_usage()`,
  `judge_model()`.

- **Checks before the call**: verbs and prepositions, `or nothing` only after `choose`, duplicate
  ids and an empty block at load time; 2–255 options, 2–10 levels, duplicate option or level ids,
  empty instruction and the type of the state at run time, before any token is spent.

### Not in this release

`synsema judge status`, static checking of option counts by `check`, `whether` with explicit yes/no
criteria, the non-calibrated `llm` fallback, the Cloudflare Workers AI wire variant, and serving
`decide` with the judge. The skill page `.synsema-skill/judge.md` lists what was measured live.

## v0.6.24 — 2026-09-20

### Breaking

- **A protected builtin cannot be bound to something callable.** The five builtins that decide a
  program's information-flow labels — `private`, `declassify`, `label_of`, `is_private` and
  `print` — can no longer be bound to a task, a lambda, or anything else callable, and a call to
  one of those names must resolve to the builtin itself. A program that redefined `declassify`
  could otherwise un-label its own sources in silence and still look clean in the audit listing
  that `synsema code check` produces.

  They remain **soft keywords**: binding one to a plain value is still legal, so `let private be 5`
  and `print(private)` keep working. What is refused is `task print(x) …`, `let declassify be
  (v, r) => v`, and `set label_of to …` with a callable on the right.

  The rule is active **with or without `--labels`**, because the same file can be loaded by a host
  that turns labels on — the guest adapters do exactly that.

- **`when <condition> then <statement>` is a load error.** The inline `when … then …` is an
  *expression*: in statement position its value is discarded, so a guard written after `then` —
  `raise`, `give`, `set` — never took effect and the program carried on with no warning. That
  turned security checks into silent no-ops. It is an error rather than a warning because there is
  no legitimate case: in statement position the value is never used.

  Write the block form:

  ```synsema
  when balance < amount
      raise "insufficient funds"
  ```

  The inline form still belongs anywhere a value is consumed:
  `let fee be when premium then 0 otherwise 25`.

- **Under `--labels`, `print`, `show` and `log` are refused inside a private branch.** Writing to
  stdout is an effect on something outside the program, so it follows the rule every other
  effectful builtin already follows: called under control flow that depended on private data, it
  is a `label_violation` *before* anything is written.

  Redacting the value was only half the job — the *number of lines* is not redactable, so one
  `print` per loop iteration over private data spells that data out by line count to whoever reads
  the output. Under a guest running inside an enclave, that reader is the operator, outside it.

  ```
  label_violation: print called under private control flow (pc = [app]); stdout is public and the
  NUMBER of lines is not redacted, so one line per iteration spells the private data out. Move it
  out of the private branch, or declassify(<the condition>, "<why it may be published>")
  ```

  Printing a private **value** from public control flow is unchanged and still redacts
  (`private(app)`). With labels off — the default for `synsema run` — nothing changes at all.

- **Anything that reads the clock needs `time`, and now says so.** Ten builtins read it: the
  **verifiers** `jwt_verify`, `totp_verify`, `captoken_verify`, `captoken_attenuate`,
  `http_signature_verify` and `oidc_verify`, the **emitters** `jwt_sign` (`iat`/`exp`),
  `captoken_mint` (`now`) and `http_signature` (`created`), and `totp`. When the `time` capability is not granted they used to fail with a diagnosis rather than
  an action. They now all say the same thing, and the action comes first:

  ```
  jwt_verify: this needs the clock. Add `require time` to the program, or pass opts.now
  explicitly (a unix timestamp in seconds) to verify against a clock you choose.
  ```

  What actually changed for a running program: nothing, unless it runs **under a ceiling without
  `time`** (`--deterministic`, or `--cap-set` without it) and verifies tokens without passing the
  clock. Plain `synsema run` and `--sandbox` grant `time`, so they are unaffected. The reason for
  the requirement is that an enclave has no trustworthy clock, and reading the host's silently
  turns the verdict into a host oracle.

  `attestation_verify` is deliberately *not* in that list: there `opts.now` is required always.

- **`steps()` carries what the run touched, and the host stops publishing it.** Under `--labels`
  the step counter comes out labelled with the union of everything private the run has touched,
  and `run --format json` / `run --attest` report `"steps": null` for such a run. The counter is
  one step per AST node — linear in what the program walked — so after a loop whose condition
  depended on a secret it *is* the secret with arithmetic on top: `(steps() - base - 24) / 4`
  reconstructed a private scalar exactly, with no `declassify` and no violation, and the attested
  document published it unasked. Before the first private value it is a plain public number, as
  before. To publish it afterwards: `declassify(steps(), "<why>")`.

- **A `stop` may not leave the task it is written in, under private control flow.** A `stop` with
  no enclosing loop in its own task breaks the *caller's* loop. When the branch that fires it is
  in the caller and the jump is indirect (`when secret == i` → `bail()`, with `task bail() /
  stop`), whether a call breaks a loop is an interprocedural question the engine cannot answer
  before the loop runs — and by the time the `stop` fires, the earlier iterations have already
  written public state in the clear. It is now refused:

  ```
  label_violation: 'stop' left the task 'bail' under private control flow (pc = [app]); a 'stop'
  that breaks the CALLER's loop cannot be checked until the loop has already run, so it is
  refused. Write the 'stop' in the loop it belongs to (give a value and decide there), or
  declassify(<the condition>, "<why it may be published>")
  ```

  With public control flow the same program is unchanged. Writing the `stop` inside its own loop —
  the ordinary form — was never affected.

- **A label violation stops the whole `synsema test --labels` run.** It used to become a `✗` on
  that block and the suite carried on. That is catching the enforcement verdict: with eight blocks
  each probing one bit, the column of ✓/✗ spells the byte. The run now ends with a single outcome
  naming the violation. An ordinary failure — a failed assertion, an error — is still a per-block
  verdict, as always.

- **`require <cap> "<scope>"` without parentheses now honours the scope.** The unparenthesised
  form parsed and then **threw the scope away**, so `require secret "API_KEY"` granted the
  capability *unscoped* — wider than what the program said, which is the worst kind of no-op. It
  now means the same as `require secret("API_KEY")`.

  What breaks: a program that declared one destination and used another. `require secret "A"` then
  `secret("B")`, or `require file "data/in.txt"` then `read_file("data/out.txt")`, used to run and
  now fail with the capability error naming the scope. That is the declaration finally being
  enforced, but it *is* a behaviour change, and it applies to **every** capability with a
  destination, not just `net`. If you meant the wide form, write it: `require secret`.

- **A statement may not carry leftover tokens.** The parser used to discard whatever followed a
  complete statement, in silence. `assert_eq 1, 2` (no parentheses) parsed as the bare identifier
  `assert_eq` and the rest vanished — a test that asserted nothing and always passed. Anything
  after the end of a statement is now a load error naming the two fixes (write the parentheses, or
  put the statements on separate lines).

- **`private(v, "p")` over a container COPIES it.** Marking a public list or map private gives a
  private copy, so a pre-existing public alias keeps seeing the public original and no longer
  observes writes made through the private handle. Sharing the `Rc` would have left a public alias
  into private data, which is the leak the labels exist to stop. The guest apps declassify
  explicitly where they used to rely on the alias.

- **The guest build has one more step.** Between `cargo build` and everything else, run
  `packages/guests/vela/tools/wasi-stub` over the module: it rewrites the built `.wasm` so it declares only the WASI
  imports Vela v0.3.0 admits. A module built without it is rejected by the Executor.

- **An error caused by private data is not catchable, and the output of a stopped run is
  withheld.** `try/recover` already refused to catch an error *born under a private branch*. It
  now also refuses one *caused by private data* — `xs[private_index]`, `1 / (secret - i)` — because
  whether the operation failed is exactly the bit the rule exists to hide. Until now the
  catchability test looked only at the control context while the message redaction looked at the
  context *union what the node touched*, and through that asymmetry a loop could leave a private
  scalar whole in a public counter and still exit 0. The same union now decides both.

  Two consequences. A label violation ends a `synsema test --labels` run even when it arrives as an
  ordinary error (eight blocks were eight bits). And the buffered output of a run the flow checker
  stopped is replaced by one fixed line: the *number* of lines printed before the stop depends on
  the private data. Effects the prefix already performed on sinks the engine does not own — a
  `write_file`, an HTTP call — did happen; that residue is documented, not fixed. (What it *does*
  own it now undoes: see the `state_*` rollback below.)

- **`steps()` is per request under `serve`.** The server reuses the interpreter between requests
  and the counter used to carry over, so a request could read the previous one's private work with
  no label on it. It now starts at zero for each request, which is also what "the cost of this
  request" should have meant.

- **The redaction text no longer names the value's own principals.** A redacted value printed as
  `private(<the principals of that value>)`, and that list varies with *which* value was selected,
  so the mechanism that exists to hide the data published it:

  ```synsema
  let xs be [private(10, "p0"), private(20, "p1")]
  print(xs[private(n, "app")])      -- used to answer private(app,p0) or private(app,p1)
  ```

  A table of 256 entries spelled a byte out in one line of output, with the run succeeding and
  `synsema code check` green. In a multi-tenant deployment the principal *is* the tenant, so
  printing a redacted value told the operator whose data it was. What comes out now is the set of
  principals the **program declares** — collected from the source before anything runs, so it is
  constant. A program with one principal (the guest, and any enclave) is unchanged:
  `private(app)`. A program with several loses the precision, which is exactly where the channel
  was. The same applies to the violation message, to the `declassify` trace and to the `from`
  field the wasm host reports.

- **An error the flow checker raised carries no location toward the host.** The text was already
  redacted; the line was not, so if a secret chooses which of N sites fails, `file:line:column` is
  log₂(N) bits — and under `serve` the caller makes one request per query. The HTTP response, the
  guest's report and the test runner's outcome now carry the message alone, and the runner no
  longer names the block it stopped at (the block name is written by whoever wrote the program).
  The local CLI still prints the location: there the host is whoever wrote the `private(…)`.

- **What a stopped request wrote to the shared `state_*` store is rolled back.** The prefix of a
  loop could `state_incr` with public control flow — legal at that moment — and then the request
  died on the secret's iteration, leaving the counter for another route to read as a public
  number. Every write a request makes is journalled while labels are on and undone if the flow
  checker stopped it. A request that ends any other way keeps its writes, as always.

- **`json_decode(text, default)` and `number(value, default)` — total variants.** Since an error
  caused by private data cannot be caught, a program had no way left to validate untrusted input:
  neither `try`/`recover` nor declaring the destination private. That is precisely an enclave's
  job, so parsing external input now has a form that returns a fallback instead of raising:

  ```synsema
  let d be json_decode(payload, nothing)
  when d == nothing
      set status to private("malformed payload", "app")
  ```

  With no error there is no bit. Without the second argument both still raise, and the message
  names the fallback.

- **A builtin's result now carries what its callback touched.** The label of a builtin's result
  was computed from its **arguments** only, so a callable that read a private value by *capture*
  was invisible — the predicate runs in Rust, so the language's private-context machinery never
  entered. The same count written by hand failed closed and the idiomatic one published the
  secret:

  ```synsema
  let n be 0                                 let n be count_where(range(0, 256),
  each v in range(0, 256)                        (v) => v < SECRET)
      when v < SECRET                        -- used to give 165, label_of(n) = []
          set n to n + 1
  -- label_violation
  ```

  That is not a side channel: it is **explicit flow** coming out unlabelled, in the builtins on
  the first page of the manual — `count_where`, `where`, `find_first`, `index_of`, `every`,
  `some`, `sort_by`, `group_by`. The fix is the mechanism the interpreter already uses to scope
  what a node "saw", applied to the boundary with Rust: the call is scoped, and whatever the
  builtin unwrapped joins the result's label. It covers those eight, and any builtin a host
  registers later. A result that touched nothing private stays public, as before.

- **Total variants for the rest of the untrusted input.** `aes_gcm_decrypt(key, nonce, ct, aad,
  default)` — the canonical operation of an enclave: a tampered tag is "reject this request", not
  "the process dies". Also `decimal`, `float`, `toml_parse`, `abi_decode`, `bech32_decode` and
  `rlp_decode`, all with the same shape: one extra argument, which is returned instead of raising.
  The fallback **never swallows a label error** — that would be a `try`/`recover` in disguise.

  Two details of the language, not of these builtins: the fallback is **evaluated eagerly**, so an
  effect inside it fires on the happy path too; and the result's label does not reveal whether the
  operation failed (valid and invalid input give the same thing at the sink).

### Added

- **Information-flow labels** (`--labels`, and always on under `serve --attested`). `private(v,
  "principal")` marks a value as belonging to a principal; every operation, field read, index and
  builtin propagates the union; branching on a private condition labels what the branch assigns
  and returns; a private value printed from public control flow shows as `private(app)`. Public
  sinks — stdout, the HTTP response, streams, files, network, memory, processes — refuse a
  labelled value, and refuse the call itself under a private branch, unless the value
  goes out through `declassify(value, "reason")`, which is recorded for review and listed by
  `synsema code check --json`. `declassify(v, "reason", ["bank"])` narrows to a subset instead of
  publishing outright.

- **`attest` capability** and **`serve --attested`**. `attest(opts)` asks the platform for an
  attestation document binding `report_data` to the code that is running (AWS Nitro, TDX/SEV-SNP
  through configfs-tsm, dstack, plus a `mock` driver that is never auto-detected). Deny-by-default
  like every other capability, absent from `--sandbox` and from the deterministic ceiling.
  `serve --attested` generates a P-256 identity before the program's first statement, binds it and
  a hash of the program and its configuration into the document, serves TLS with that key and
  publishes `GET /.well-known/attestation`. `synsema run --attest` is the job form: it runs under
  `--deterministic` and closes with one JSON line tying program, input and output together.

- **`attestation_verify(document, opts)`** — the client side: COSE signature, certificate chain to
  the platform's pinned root, measurement expectations and an explicit `now`. `nitro` and `mock`
  verify today; other formats answer with an honest error rather than a guess.

- **`groth16_verify(vk, proof, public_inputs)`** — Groth16 over BN254, taking snarkjs JSON as it
  comes. Pure, no capability, no network: an enclave can verify a proof carried in its own payload
  instead of trusting an oracle.

- **Deterministic noise** for published aggregates (`laplace_noise`, `gaussian_noise`): same seed,
  same noise, so repeating a query does not average the noise away.

- **`invariant`** conditions evaluated per state transition, with the guest adapters running them
  on every entry point.

- **Vela guest: `state_pad` and the `_vela.n` counter.** Under the output policy `reject:
  "private"` the state that goes on-chain is now padded to a bucket (256 bytes by default,
  `state_pad: N` to tune it, `state_pad: 0` to turn it off with a warning) and carries a counter
  that goes up on every transition. Without them, a rejected request returned the previous state
  byte for byte while an accepted one had grown, so its **size** — and the fact that the state root
  had not moved — was one bit per request.

## v0.6.23 and earlier

Not covered here — this file starts with the release that follows it (`v0.6.23` is the last tag as
of this writing). For older versions see the release notes attached to each tag.
