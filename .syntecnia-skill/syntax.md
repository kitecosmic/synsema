# Syntecnia Syntax

## Keywords
Flow: `when`, `otherwise`, `each`, `in`, `while`, `match`, `is`, `then`, `stop`
Definitions: `task`, `give`, `let`, `be`, `set`, `to`, `type`, `as`, `of`, `with`
Agent: `agent`, `spawn`, `share`, `observe`, `signal`, `wait_for`
Security: `require`, `sandbox`, `invariant`, `intent`
Human: `approve`, `confirm`, `ask`, `show`
LLM: `reason`, `decide`, `analyze`, `generate`
Error handling: `try`, `recover`
HTTP server: `serve`, `on`, `route`, `auth`, `requires`, `expect`
Observability: `trace`, `log`, `measure`, `checkpoint`
Logic: `and`, `or`, `not`
Literals: `true`, `false`, `nothing`

## Operators
Arithmetic: `+`, `-`, `*`, `/`, `%`, `**`
Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
Pipe: `|>` — chains: `data |> clean |> validate`
Comments: `-- comment`

## Strings
- Single line only. A literal newline inside `"..."` gives `Unterminated string`.
- Use escape sequences: `\n` (newline), `\t` (tab), `\\` (backslash), `\"` (quote).
- Concatenation: `"hello" + " " + "world"`
- Interpolation: `fmt("Hello {name}", {"name": value})`

## Numbers
- Integer or float: `42`, `3.14`, `1_000_000`
- Arithmetic always returns float for division: `10 / 3` → `3.333...`
- `text(42)` → `"42"` (no decimal for integers), `text(3.14)` → `"3.14"`

## Blocks
Indentation-based (4 spaces or 1 tab). No braces.

## Statements

```
let name be value
set name to new_value
give value                          -- return from task

when condition
    body
otherwise when condition
    body
otherwise
    body

each item in collection
    body

while condition
    body

match value
    is pattern
        body

task name(param1, param2)
    body
    give return_value

type Name
    field1: type_name
    field2: type_name

-- Error handling
try
    risky_operation()
recover err
    print("Failed: " + err)
    use_fallback()
-- Catches all runtime errors. err contains the error message.
-- give and stop propagate through try/recover (not caught).

intent: "description"               -- must be at top, freezes after
invariant: condition                 -- checked at runtime
require capability("scope")         -- declare needed permissions
sandbox
    untrusted_body
```

## Property access
```
name of person         -- natural
person.name            -- dot
person["name"]         -- index
```

## Paths
Paths are resolved relative to the working directory. For portability:
- Use absolute paths for agent data
- Avoid `/tmp` on cross-platform code (Windows maps it to `C:\tmp`)
- Use `~/.syntecnia/` for agent state (auto-managed)

## Flat syntax (.fsyn files)
```
task name(params):
    When condition, action.
    Otherwise, other_action.
    Then give result.
end
```
