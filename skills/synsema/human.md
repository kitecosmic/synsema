# Synsema Human Interaction

## Primitives
```synsema
approve "Deploy to production?"                    -- yes/no gate
confirm "Send email to 500 customers?"             -- confirmation
show data as "Preview"                             -- display to human
let choice be ask "Which env?" with ["staging", "prod"]  -- question
```

## As expressions (return values)
```synsema
let approved be approve "Large payment: $" + text(amount)
when approved
    process_payment()
otherwise
    cancel()
```

## Timeouts: `within` (optional, on approve/confirm/ask)
`approve "Delete prod?" within 2h` — max wait for the human answer (suffixes `s|m|h|d`).
Precedence: `within` > `SYNSEMA_HUMAN_TIMEOUT` (seconds, env/`.env`) > 300s. On expiry the gate
returns `false` (ask → its fallback) + a one-time stderr notice. Never hangs forever.

## Where the answer comes from (guaranteed: NEVER silently auto-approved)
- **`run` with a TTY** — prompts in the terminal (`[approve] … (y/n):`, accepts y/yes/si/sí/n/no)
  and waits with no timeout; EOF denies.
- **`run` without TTY (pipes/CI/agent-driven)** — DENIES instantly, fail-closed, with a one-time
  notice that explicitly tells AI agents a HUMAN must approve. An agent cannot fake approval.
- **`serve`** — the gate is QUEUED and the request blocks until a human answers or the deadline
  denies. The server console prints one line per pending approval with a **one-time token**
  (64 hex) and the ready-to-use command. Reserved routes: `GET /approvals` (lists
  `{id, message, type, expires_at}` — never tokens) and `POST /approvals/{id}` with
  `{"token", "decision": true|false}` (or `{"token", "value"}` for ask) → 200/400/403/404.
  Wrong token = 403 and the gate keeps waiting; the token is single-use and expires with the
  deadline. A blocked gate holds its request thread — use `within` of minutes under serve.
  **Webhooks (any channel)**: with `SYNSEMA_HUMAN_WEBHOOK=<url>` each queued gate also fires a
  POST (signed HMAC-SHA256 in `X-Synsema-Signature` when `SYNSEMA_HUMAN_WEBHOOK_SECRET` is set)
  whose payload includes the token and — with `SYNSEMA_HUMAN_PUBLIC_URL` — ready-to-forward
  `respond_link_yes`/`no` (`GET /approvals/{id}/{token}?d=yes|no`, single-use, returns HTML).
  Fire-and-forget (one attempt, 10s): a dead channel never blocks the gate. A Synsema channel
  is a route doing `json_decode(body of request)` and forwarding the links.
- **`test`/`conform`** — deterministic auto-pass (suites never block on a prompt).
- **Inside `parallel_map` and agents (v0.6.53+)** the gate uses the program's channel: under
  `serve` it waits like any other (or, with `then`, leaves a pending approval); in a run without a
  terminal it is denied. Measured: `parallel_map(one, [1, 2])` where `one` does
  `give approve …` → `[false, false]`; an agent's `approve` → `false`. (Before v0.6.53 they had
  no channel and **approved themselves**.)

## Approvals that do not wait: `approve … then <task>` (v0.6.53+)

A gate that waits holds its request (and its thread) until a person answers. For an approval that
can take hours, add `then <task>`: the gate does not wait, and the engine calls the task when the
answer comes. Also `confirm … then` and `ask … then`.

```synsema
require serve(8080)
task decided(ok, message, id)
    when ok
        print(`approved: {message}`)
    otherwise
        print(`denied or expired: {id}`)
serve on 8080
    route "POST /pay"
        let id be approve `Pay {body of request}?` within 1h then decided
        give {"pending": id}
```

- **Under `serve` the route goes on at once.** The gate's value is the id of the pending approval
  (text, `approval_…`). It is listed and answered by the same `GET /approvals`,
  `POST /approvals/{id}` (with the console token), console line and webhook as a gate that waits.
- **The task is called `task(decision, message, id)`** — it must be a task of the program that
  takes exactly three parameters. `decision` is `true`/`false` for `approve`/`confirm`, the answer
  text for `ask`. Measured console: `[serve] decided true | Pay 40? | approval_fe4a…`, then
  `[serve] approval approval_fe4a… answered: ran decided`.
- **On expiry** (`within`, or `SYNSEMA_HUMAN_TIMEOUT`, default 300 s) it is called with what a gate
  that waits gives when nobody answers: `false`, or for `ask … with [options]` the first option
  **as text** (`""` without options). Console: `approval … timed out: ran decided`.
- **It survives a restart.** What is pending is kept in `.synsema/state/approvals-<port>.json` (in
  the program's folder, not the working directory), or in `SYNSEMA_STATE_DIR`: one entry per approval with `id`,
  `type`, `message`, `options`, `task`, `expires_at` and **`token_sha256`** — a hash, never the
  token. After a restart the same `GET /approvals` lists it and the token printed before still
  answers it. A program that never uses `then` writes nothing there (no folder, no file).
- **Each approval is answered or expires once**, also with two `serve` sharing the file (the
  handoff of `SYNSEMA_REUSE_PORT`, see [serve.md](serve.md) § Restarting without refusing
  connections): a second answer gets `404 no pending approval with that id`. While a `serve` is
  shutting down an answer gets 503 and stays pending.
- **The task runs at most once.** Once an answer is taken, a crash before the task finishes loses
  it. A shutdown waits for a running task within `SYNSEMA_SHUTDOWN_GRACE`. Make the task idempotent
  and record what it did if losing one matters.
- **The file has to be private and not a link.** On Unix: owned by the user that runs `serve`,
  mode 600 (synsema creates it so). On Windows it takes the permissions of its folder. Only the
  tasks the program names in a `then` can be called from it; an entry that does not qualify is
  ignored with a warning and left in the file. **A Windows drive mounted in WSL (`/mnt/c`) cannot
  hold it** (it does not keep Unix permissions): the gate fails with ``… the lock of the pending
  approvals ./.synsema/state/approvals-8080.json.lock can be read or written by other users (mode
  777); it has to be private (chmod 600; a filesystem that does not keep Unix permissions, like a
  Windows drive mounted in WSL, cannot hold it); SYNSEMA_STATE_DIR can point the pending approvals
  to another folder`` → `SYNSEMA_STATE_DIR=$HOME/.myapp-state synsema serve app.syn`.
- **The port is part of the name.** Serving the same folder on another port prints at start:
  ``[serve] notice: .\.synsema\state\approvals-51087.json has 1 pending approval(s) of a `serve` on
  another port; this one (approvals-51999.json) does not answer them. Serve on that port again to
  resolve them, or remove the file``.
- **Outside `serve`** (`run`) the gate is answered on the spot, as without `then` (terminal prompt,
  or denied without one), the task runs right away, and the gate's value is an id like
  `interact_now_1`.
- **Where `then` is an error** — the task would run later with the program's full capabilities,
  so it is refused inside a `sandbox`, a trusted tool, a tool run by `call_tool`, an agent, or a
  request authenticated with a capability token:
  ``approve … then t: not allowed inside a sandbox — the task would run later with the program's
  capabilities; use the gate that waits (approve without `then`), or move the gate out`` (the
  same with `inside an agent`, `inside a tool run by call_tool`, …). The gate that waits still
  works there.
- **Other errors at the gate:** ``approve … then two: "two" takes 2 parameter(s); it is called with
  three (decision, message, id)`` and ``approve … then f: "f" is not a task of the program (it is
  called by name with the decision, the message and the id)`` (also for a name that does not
  exist).
- **Inside the condition of a `when`, `then` belongs to the `when`:**
  `let v be when approve "x" then "yes" otherwise "no"` is still the inline `when` (`v` is `"no"`
  without a human).
- **A gate that waits is not handed over on a restart.** With `SYNSEMA_REUSE_PORT` it stays in the
  old process, and while both listen an answer can reach the new one and get 404. Approvals that
  must survive a restart use `then`.

## No TTY (pipes / CI / redirection)
In `synsema run` **without an interactive TTY**, free-text `ask "question"` returns `""` (empty
string) and `ask "question" with [opts]` takes the **first** option **as text** (v0.6.53+:
`ask "n?" with [1, 2]` gives `"1"`, like an answer typed by a person; before it gave the number
`1`, so `a == 1` passed in CI and failed when a person answered) — with a one-time notice that no
human actually answered. Don't rely on free-text `ask` for input in those contexts.

For raw stdin that works with pipes/redirection, use **`read_line(prompt?)`** (returns the line, or
`nothing` on EOF) — see [builtins.md](builtins.md):
```synsema
let name be read_line("Your name: ")   -- works with `printf 'Ana\n' | synsema run f.syn`
```
For an **interactive** prompt (a chat CLI, a `/` palette that filters as you type, history, a
↑↓ menu to approve), `term_open()` (engine v0.6.11+, `require stdin`) delivers every key as an
event in `select`; it returns `nothing` without a TTY so the `read_line` fallback is one `when` —
see [processes.md](processes.md) § The program's own terminal. `ask`/`approve`/`confirm` keep
working while it is open (raw mode is suspended while the human answers).

For config-style input, `env()` / a file also work and are easy to test:
```synsema
let name be env("NAME", "")            -- works in CI, pipes, and tests
```

## Escalation protocol
When automatic recovery fails:
1. Shows what happened and what was tried
2. Presents options with descriptions and impact
3. Human chooses
4. Decision is recorded for future precedent

## Decision persistence
Past decisions are recorded for precedent: the runtime can consult a prior human choice for the
same error/context and apply it automatically instead of asking again.
