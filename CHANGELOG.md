# Changelog

Notable changes to the Synsema language, engine and tooling. The entries that matter most are the
**breaking** ones: a program that used to load and no longer does, or that behaves differently.
Each says what changed, why, and what to write instead.

Versions follow the release tags (`v0.6.24`, `v0.6.25`, …). Dates are the release date.

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
