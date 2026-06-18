# Syntecnia Pitfalls — Common Errors and Solutions

Read this FIRST if something fails. Each row is a real mistake that costs hours to debug.

## Errors

| Error message | Cause | Solution |
|---|---|---|
| `Unterminated string` | Literal newline inside `"..."` | Use `\n` escape. Strings are single-line only. |
| `Capability not granted: file_write(...)` | Missing `require` or scope too narrow | Add `require file("/path/*")` at top of program |
| `Capability not granted: net(...)` | Missing `require` for the domain | Add `require net("domain.com")` |
| `Invalid memory category: 'preferencia'` | Categories are English-only | Use exactly: `preference`, `rule`, `learning`, `decision`, `context` |
| `No agent defined with name 'X'` | `spawn X` before `agent X` definition | Define the agent before spawning it |
| `Division by zero` | Divisor is 0 | Guard with `when divisor != 0` or use `try/recover` |
| `Cannot iterate over number` | `each` on a non-list value | Check type with `type_of()` or wrap in `[value]` |
| `Map has no key 'X'` | Accessing a property that doesn't exist | Check with `contains(map, "X")` first |
| `Cannot set undefined variable` | Using `set` before `let` | Define with `let x be value` first, then `set x to new_value` |
| `Loop exceeded maximum iterations` | Infinite loop (condition never false) | Check that loop variable actually changes |
| `Expected indented block` | Missing indentation after when/each/task/etc | Indent body with 4 spaces |

## Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| String on multiple lines | `Unterminated string` error | Use `\n` or concatenate: `"line1\n" + "line2"` |
| `remember("preferencia", ...)` works | Error: invalid category | Categories are English: `preference`, `rule`, `learning`, `decision`, `context` |
| `intent: "..."` restricts what the program can do | No — the intent is descriptive only | Security is enforced by capabilities (`require`), in any language. The intent text never blocks. |
| `wait_for` wakes all waiters on one `signal` | Only ONE waiter gets it | Signals are a queue (consumed on read). For fan-out, emit N signals or use blackboard. |
| `wait_for` hangs forever on dead agent | Returns `nothing` quickly | The runtime detects no alive agents and returns. But only if ALL agents are dead. |
| Agent shares state with main program | Each agent has its own interpreter | Use `share`/`observe` via blackboard to communicate. |
| `number("1200")` gives integer | Gives `1200.0` (float) | `text()` on integers shows no decimal. Use `text(number(...))` for display. |
| `/tmp/file.txt` works on Windows | Maps to `C:\tmp\file.txt` | Use absolute paths. For agent data, use `~/.syntecnia/` paths. |
| Cron output appears after program ends | Output is buffered | Fixed in recent versions. Update to latest. Use `--serve` for live output. |

## Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| No `try/recover` around HTTP/SQL/LLM | Agent dies on first network error | Wrap I/O in `try/recover` with fallback |
| Relying on the `intent:` text to restrict actions | The intent doesn't authorize anything | Declare permissions with `require`; the intent is only a description |
| One `signal` for N consumers | Only one gets it | Use blackboard keys per worker, or emit N signals |
| `share x as "result"` from N workers | Last write wins, others lost | Use dynamic keys: `share x as "result_" + text(n)` |
| No `require` and wondering why I/O fails | Zero-access-by-default | Always declare `require` at top of program |
| `set x to 5` without prior `let x be ...` | Runtime error | Always `let` before `set` |
