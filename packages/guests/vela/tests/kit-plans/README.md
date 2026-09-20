# Kit flow plans

A kit (`vela-transfers`, `vela-payroll`, `vela-policy-engine`, `vela-dark-pool`) is a separate
repository, so its app cannot be a test of this crate. What lives here is the *plan* of a full
run — the same calls the Executor makes, in order — so that "verified end to end under labels"
is a command anyone can repeat, not a claim.

```sh
cd packages/guests/vela
SYNSEMA_KIT_APP=/path/to/vela-transfers/app/app.syn \
SYNSEMA_KIT_STEPS=tests/kit-plans/transfers.json \
cargo test --target x86_64-pc-windows-gnu -j 2 external_kit -- --ignored --nocapture
```

The test (`external_kit_runs_its_flow_under_labels` in `src/lib.rs`, `#[ignore]` because the app
it needs is not in this repository) deploys the app and replays every step through the real
adapter entry points, with information-flow labels on and the sources marked exactly as the guest
marks them. A `label_violation` anywhere, or an error where the plan expects success, fails the
test.

A plan is `{"deploy": <constructorParams|null>, "steps": [...]}`. Each step is one call:

| Field | Meaning |
|---|---|
| `kind` | `deposit`, `process`, `deanonymize` or `trusted` |
| `sender` | the caller's address (`deposit`, `process`, `deanonymize`) |
| `token`, `value` | the deposited asset, amount as decimal text (`deposit`) |
| `payload` | the request body the app decodes (`process`, `deanonymize`) |
| `payload_hex` | the raw ABI bytes a trigger contract sends (`trusted`) |
| `expect_error` | the code this step must fail with; `"*"` means "any error of the app's own" (never `label_violation` or `runtime_error`) |
| `expect` | what the RESULT must look like, beyond the error (below) |

A step without `expect_error` must succeed, and its state feeds the next one.

## `expect`: pin what the chain sees

Until round 3 a plan only asserted on `error`, and that is how two kits shipped a broken reader:
an app changed the ABI signature of its public receipt, the plans stayed green, and the client and
the console could no longer decode their own event (`abi_decode: the data is truncated`). `expect`
closes that: it pins the **shape of the public output**, which is exactly what a reader depends on.

| Key | Asserts |
|---|---|
| `app_events`, `withdrawals`, `events` | how many of each the step produced |
| `app_event_bytes` | the exact byte length of each app event's `data` — **this pins the ABI signature**: `cleared(bytes16,uint256,uint8)` is 96 bytes, adding a `uint256` makes it 128 and the step fails, naming the readers to update |
| `app_event_subtypes` | each app event's label (`"cleared"`, or `"0x…"` for a 32-byte digest) |
| `withdrawal_amounts` | the amounts as Vela emits them (Uint256 hex) |
| `event_bytes_multiple_of` | every encrypted event's `data` is a multiple of N bytes (the `events_pad` bucket) |
| `state_contains` | a substring of the returned state (compact JSON) |

```json
{ "kind": "process", "sender": "0x1111…", "payload": {"type": "close", "auction": "0x…01"},
  "expect": {"app_events": 1, "app_event_subtypes": ["cleared"], "app_event_bytes": [96], "withdrawals": 0} }
```

When you change a receipt on purpose, update the plan in the same commit: the diff of those bytes
is the review that the kit's readers were updated too.
