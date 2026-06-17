# Syntecnia Syntax

## Keywords
Flow: `when`, `otherwise`, `each`, `in`, `while`, `match`, `is`, `then`, `stop`
Definitions: `task`, `give`, `let`, `be`, `set`, `to`, `type`, `as`, `of`, `with`
Agent: `agent`, `spawn`, `share`, `observe`, `signal`, `wait_for`
Security: `require`, `sandbox`, `invariant`, `intent`
Human: `approve`, `confirm`, `ask`, `show`
LLM: `reason`, `decide`, `analyze`, `generate`
Observability: `trace`, `log`, `measure`, `checkpoint`
Logic: `and`, `or`, `not`
Literals: `true`, `false`, `nothing`

## Operators
Arithmetic: `+`, `-`, `*`, `/`, `%`, `**`
Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
Pipe: `|>` — chains: `data |> clean |> validate`
Comments: `-- comment`

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

## Flat syntax (.fsyn files)
```
task name(params):
    When condition, action.
    Otherwise, other_action.
    Then give result.
end
```
