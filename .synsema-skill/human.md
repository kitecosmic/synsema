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

## Backends
- **Terminal** — stdin/stdout, interactive
- **Auto** — auto-approves everything (for CI/testing)
- **Queue** — async, agent blocks while human responds later (web UI)
- **Callback** — programmatic, for embedding

## No TTY (pipes / CI / redirection)
In `synsema run` **without an interactive TTY** (output piped, run in CI, or stdin redirected),
free-text `ask "question"` returns `""` (empty string) and `ask "question" with [opts]` takes the
**first** option. Don't rely on free-text `ask` for input in those contexts.

For raw stdin that works with pipes/redirection, use **`read_line(prompt?)`** (returns the line, or
`nothing` on EOF) — see [builtins.md](builtins.md):
```
let name be read_line("Your name: ")   -- works with `printf 'Ana\n' | synsema run f.syn`
```
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
