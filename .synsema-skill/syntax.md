# Synsema Syntax

## Reserved (hard) keywords
These cannot be used as names; using one (e.g. `let task be 1`) gives a clear
"reserved word" error.

Flow: `when`, `otherwise`, `each`, `in`, `while`, `match`, `is`, `then`, `stop`
Definitions: `task`, `give`, `let`, `be`, `set`, `to`, `type`, `as`, `of`, `with`
Agent: `agent`, `spawn`, `share`, `observe`, `signal`, `wait_for`
Security: `require`, `sandbox`, `invariant`, `intent`
Human: `approve`, `confirm`, `ask`, `show`
LLM: `reason`, `decide`, `analyze`, `generate`
Error handling: `try`, `recover`
Observability: `trace`, `log`, `measure`, `checkpoint`
Logic: `and`, `or`, `not`
Literals: `true`, `false`, `nothing`

## Soft keywords (NOT reserved)
`serve`, `on`, `route`, `auth`, `requires`, `expect`, `max_body`, `max_streams`,
`stream`, `send`, `rate_limit`, `per`, `static`, `from`, `cors`, `describe`,
`private` — special **only** at the start of their HTTP-server construction
(`serve on N`, `route "..."`, `requires auth`, `expect body {...}`,
`max_body "10mb"`, `max_streams N`, a `stream` block, `send` inside one,
`rate_limit N per window`, `static "./dir"`, `static "/p" from "./dir"`,
`cors "*"`, a `describe` block, `private`). Everywhere else they are ordinary
identifiers, so `let route be "/x"`, `let static be 1`, `let from be 3`,
`let private be 1` and `task auth(x)` are valid. The parser uses fixed lookahead,
never heuristics. See [serve.md](serve.md).

`test` is also a soft keyword: `test "name"` at the start of a statement begins a test block
(see [testing.md](testing.md)); anywhere else `test` is an ordinary identifier
(`let test be 5`, `task f(test)` are valid).

## Operators
Arithmetic: `+`, `-`, `*`, `/`, `%`, `**` (on `array`, these are **elementwise** with broadcasting — matrix product is `matmul`)
Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
Assignment of a default / named arg: `=` (in `task f(x, y = 1)` and `f(x, y = 2)`). Distinct from `==` (equality). `=` is NOT a general assignment statement — use `let`/`set`.
Pipe: `|>` — chains: `data |> clean |> validate`
Lambda: `(params) => expr`
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
    is "literal"                     -- value match (==)
    is Status.paid(amount)           -- enum variant + positional binding
    is Status.shipped(d, c) when c == "DHL"   -- guard: arm matches only if cond holds
    is [first, ...rest]              -- list pattern: head + tail (also [a,b], [], [...init, last])
    is {name, age} when age >= 18    -- map pattern: binds keys (subset; extra keys ignored)
    is {status: 200, body}           -- map field with sub-pattern + binder
    is _                             -- wildcard: matches anything, binds nothing
        body
    otherwise                        -- default if no `is` matched
        body
-- NOTE: top-level `is x` (a bare identifier) still COMPARES against the value of x
-- (it does NOT bind). Binders appear only inside list/map/variant patterns and `_`.

task name(param1, param2 = 10)        -- default value with `=` (evaluated at call time)
    body
    give return_value

name("a")                             -- param2 defaults to 10
name("a", 20)                         -- positional
name("a", param2 = 20)                -- named arg (any order; like `spawn ... with k = v`)

test "description"                    -- test block (run only by `synsema test`, skipped by run)
    assert_eq(name("a"), expected)    -- see testing.md

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
- Use `~/.synsema/` for agent state (auto-managed)

## Flat syntax (.fsyn files)
```
task name(params):
    When condition, action.
    Otherwise, other_action.
    Then give result.
end
```
