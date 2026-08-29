# Synsema Human Interaction

## Primitives
```
approve "Deploy to production?"                    -- yes/no gate
confirm "Send email to 500 customers?"             -- confirmation
show data as "Preview"                             -- display to human
let choice be ask "Which env?" with ["staging", "prod"]  -- question
```

## As expressions (return values)
```
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

## No TTY (pipes / CI / redirection)
In `synsema run` **without an interactive TTY**, free-text `ask "question"` returns `""` (empty
string) and `ask "question" with [opts]` takes the **first** option — with a one-time notice
that no human actually answered. Don't rely on free-text `ask` for input in those contexts.

For raw stdin that works with pipes/redirection, use **`read_line(prompt?)`** (returns the line, or
`nothing` on EOF) — see [builtins.md](builtins.md):
```
let name be read_line("Your name: ")   -- works with `printf 'Ana\n' | synsema run f.syn`
```
For an **interactive** prompt (a chat CLI, a `/` palette that filters as you type, history, a
↑↓ menu to approve), `term_open()` (engine v0.6.11+, `require stdin`) delivers every key as an
event in `select`; it returns `nothing` without a TTY so the `read_line` fallback is one `when` —
see [processes.md](processes.md) § The program's own terminal. `ask`/`approve`/`confirm` keep
working while it is open (raw mode is suspended while the human answers).

For config-style input, `env()` / a file also work and are easy to test:
```
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
