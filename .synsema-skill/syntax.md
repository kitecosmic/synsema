# Synsema Syntax

> Coming from Python? Read [python-diff.md](python-diff.md) first — it maps the Python
> reflexes to these forms and flags the semantic traps (verified against the engine).

## Reserved (hard) keywords
These cannot be used as names you **bind** — variables, parameters, task/export names; using one
(e.g. `let task be 1`, `task send(to)`, `export task decide(...)`) gives a clear "reserved word"
error. **After a `.` any word is a member name** (v0.6.29+): `ev.type`, `tx.to`, `r.match`,
`mod.decide(…)` all parse (before v0.6.29 they failed with the same "reserved word" error). So a
map with a `"to"` or `"type"` key reads naturally with a dot, but a parameter still cannot be
called `to`. The LLM words `reason`/`decide`/`analyze`/`generate` are the ones that bite in real
APIs — name tasks and parameters `resolve`, `why`, etc.

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

`judge` (v0.6.25+) is a soft keyword in **expression** position: `judge <state>` followed by an
indented block of questions (see [judge.md](judge.md)) opens the construction only when the next
token can start an operand — an identifier, a string, a template, `{` or a scalar literal. `judge[0]`,
`f(judge, 2)`, `judge.x`, `x of judge` and `let x be judge` at the end of a line keep `judge` as an
ordinary name (`[` never opens it: bind a list state first). Inside the block, `whether`, `choose`,
`rate`, `between` and `across` are special; outside it they are plain identifiers
(`let rate be 2` is valid). The answers use the field `kind` (not `type`) and the escape key `none`
(not `nothing`) — chosen when those reserved words could not follow a `.`; since v0.6.29 they
parse there, but the fields are still named `kind` and `none` (`v.x.type` → no such key).

## Operators
Arithmetic: `+`, `-`, `*`, `/`, `//`, `%`, `**` (on `array`, these are **elementwise** with broadcasting — matrix product is `matmul`)
- `/` always returns float (like Python 3). `//` (v0.6.29+) is **floor division**: exact for integers of any size, integer result (`(10**30) // 3` → `333…333`, `-7 // 2` → `-4`); with floats it floors like Python (`7.5 // 2` → `3.0`), and float `//` / `%` give exactly CPython's (and numpy's) results (`7 // 0.1` → `69.0`, `7 % 0.1` → `0.09999999999999962`, because `0.1` is stored as slightly more than 0.1); decimal → decimal; `x // 0` → `Division by zero`. Invariant with `%`: `a == b * (a // b) + a % b`. Same precedence as `*` `/` `%`.
- `**` binds tighter than unary minus and is right-associative (v0.6.29+): `-2 ** 2` → `-4`, `(-2) ** 2` → `4`, `2 ** -1` → `0.5`, `2 ** 3 ** 2` → `512`.

Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`. **Chained like Python** (v0.6.29+): `1 < x <= 10` means `1 < x and x <= 10`; each operand is evaluated once and it short-circuits. Int vs float compare exactly (`2**53 + 1 == 9007199254740992.0` → `false`). `bytes == text` is always `false`.
Membership (v0.6.29+): `x in coll` / `x not in coll` — list membership, map **key**, substring (text needs text: `1 in "a1"` is an error — `text(1) in "a1"`), bytes subsequence. (`in` also stays the keyword of `each x in xs`.)
Logic: `and`, `or`, `not` — **short-circuit** (engine v0.6.10+): `contains(m, "k") and m["k"] == 1` is a valid guard (the index does not run when `contains` is false; same for `or`). The result is always a **bool**, never the operand — `x or default` is NOT a Synsema idiom (use `when`). On engines ≤ 0.6.9 both sides always evaluated: guard with a nested `when` there.
Precedence, loosest first: `|>` · `or` · `and` · `not` · comparisons/`in` · `+ -` · `* / // %` · unary `-` · `**`.
Assignment of a default / named arg: `=` (in `task f(x, y = 1)` and `f(x, y = 2)`). Distinct from `==` (equality). `=` is NOT a general assignment statement — use `let`/`set`.
Pipe: `|>` — chains: `data |> clean |> validate`. It has the **lowest** precedence (v0.6.29+): `1 + 2 |> double` is `double(3)`. A bare function step is called with the value; a step that is a call receives the value as its **first** argument: `xs |> sort_by((x) => x.k)` = `sort_by(xs, (x) => x.k)`.
Lambda: `(params) => expr`
Comments: `-- comment`. Glued to a value and followed by a number or `(` — `5--1`, `x--(y)` — `--` is a lexer error that explains the two readings: `5 - -1` (subtraction of a negative) vs `5 -- comment`. Anywhere else it opens a comment, glued or not: `print(1)--note`, `x--note` and `"a"--note` are a value plus a comment.

## Strings — two kinds

**Quoted `"..."` / `'...'`** — single-line, escape sequences:
- A **literal** newline inside `"..."` is an error (`Unterminated string`). For a newline, use the escape `\n`.
- Escapes: `\n` (newline), `\t` (tab), `\\` (backslash), `\"` / `\'` (quote). `"a\nb"` is 3 chars (the `\n` is ONE real newline), and `split("a\nb", "\n")` returns 2 items.
- Unicode escapes (v0.6.29+): `\u00e9` (exactly 4 hex digits) → `é`, a surrogate pair `\uD83D\uDE00` → `😀` (one character, as JSON and JavaScript write it), `\u{1F600}` (1–6 hex digits) → `😀`. In a backtick string only the 4-digit form is an escape — `` `x\u{a}y` `` interpolates `a`. When what follows is not a complete escape the backslash stays literal, as before: `"C:\users"`, `"\u12"`. **`\x` is not an escape**: `"C:\build\x64"` and the regex `"a\x2eb"` are exactly what you wrote. `synsema check` flags every literal that uses a `\u` escape (they were literal text before v0.6.29); for a literal backslash + u write `\\u`.
- Concatenation: `"hello" + " " + "world"`. Safe for JSON (single-line, literal).

**Backtick `` `...` ``** — multiline + interpolation + escapes:
- **Real newlines work** — press Enter inside the backticks (great for SQL / HTML / multi-line text).
- **Escapes also work** (`\n`, `\t`, `\\`, `\uXXXX`) — `` `a\nb` `` is the same 3 chars as `"a\nb"`; `\u{…}` is not an escape here (the braces interpolate).
- **Interpolation:** `` `Hello {name}, you have {count} items` `` — `{expr}` evaluates a full expression. Escape a literal brace/backtick with `\{` / `` \` ``. A hole takes **any value**, like a Python f-string (v0.6.29+): `` `xs={xs}` `` → `xs=[1, "a"]`, `` `n={nothing}` `` → `n=nothing`. `+` stays strict: `"x" + [1]` is an error whose message suggests interpolating.
- ⚠️ Common confusion: backticks are NOT "raw" — they DO process `\n`/`\t`. The difference from `"..."` is that backticks also allow **literal** newlines and `{expr}` interpolation.

**Multi-line text (e.g. SQL):** use a backtick string with real newlines:
```synsema
let q be `
    SELECT id, name FROM users
    WHERE active = 1
    ORDER BY name
`
```
(`fmt("Hello {name}", {"name": value})` is the older map-based interpolation — strict since v0.6.29: a `{name}` missing from the map is an error, `{{`/`}}` are literal braces; backtick `{expr}` is usually nicer.)

**Indexing text** (v0.6.29+): `s[i]` is one character (same counting as `length`), negatives from the end: `"abc"[-1]` → `"c"`.

## Numbers
- Integer or float: `42`, `3.14`, `1_000_000`, `1_000.5`. `_` goes **only between two digits** (or right after a `0x`/`0o`/`0b` prefix: `0x_ff`); anything else is a lexer error (v0.6.29+) — `1__0`, `1_`, `0x1_`, `1_.5`, `1e3_` → ``Invalid number literal: 1__0 — `_` goes only between two digits (1_000, 1_000.5)``.
- Hex / octal / binary integer literals (v0.6.29+): `0x1f18` (7960), `0o17` (15), `0b101` (5), `0xFF_FF` — exact integers. A digit outside the base is an error (`0o8` → `Invalid octal literal`). Exponent literals `1e3`, `1.5e-3`, `1E+9` are **floats** (like Python): `1e18` is a float, not an exact wei amount — write `10**18` or `1_000_000_000_000_000_000`.
- Arithmetic always returns float for division: `10 / 3` → `3.333...`. Floor division is `//` (exact integer for integers): `10 // 3` → `3`.
- `int(x)` → exact integer from text (`"-42"`, `"1_000"`, `"0x1f18"`, `"0o17"`, `"0b101"`, `"-0x10"` → `-16`) or a whole float. The base and the fallback both go **by name** — `int("ff", base = 16)` → `255` (2–36), `int("abc", fallback = 0)` → `0` — so the call reads the same to a Python reader and to the engine: `int("ff", 16)` (any integer 2..36 as the 2nd positional, whatever the first argument is) is an error that names both forms. `hex(n)` → `"0x…"`.
- `text(42)` → `"42"` (no decimal for integers), `text(3.14)` → `"3.14"`

## Blocks
Indentation-based (4 spaces or 1 tab). No braces.

## Statements

```
let name be value
set name to new_value
set m["a"]["b"] to v                -- a set path starts from a VARIABLE
give value                          -- return from task

when condition
    body
otherwise when condition
    body
otherwise
    body

-- Inline conditional EXPRESSION (usable in let/map/apply/call args):
let label be when score >= 50 then "pass" otherwise "fail"
let kind be when n > 0 then "pos" otherwise when n < 0 then "neg" otherwise "zero"
-- `when <cond> then <expr> [otherwise [when ...] <expr>]` returns the taken branch's value.

each item in collection              -- list; map → its keys (insertion order); text → characters;
    body                             -- bytes → ints 0–255 (maps/text/bytes: v0.6.29+)

while condition                      -- no iteration cap (v0.6.29+; it was 1,000,000)
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
-- Arity is strict (v0.6.29+): name() → "task 'name' is missing argument 'param1' — pass it, or
-- give the parameter a default"; one argument too many is an error too (a 1-param task `f`
-- called f(1, 2, 3) → "task 'f' takes 1 argument, got 3"). Lambdas too.
max(1, 2,)                            -- a trailing comma is fine in calls (v0.6.29+), as in lists/maps
max(
    1,
    2,
)

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
-- To RE-PROPAGATE a caught error (so the caller/agent sees a real failure), use raise(err)
-- inside recover. Without it, recover swallows the error. See builtins.md (Error handling).

intent: "description"               -- must be at top, freezes after
invariant: condition                 -- checked at runtime
require capability("scope")         -- declare needed permissions
sandbox
    untrusted_body
```

**`set` targets start from a variable** (v0.6.29+): `set m["a"]["b"] to v`, `set s.items to …`,
`set xs[0] to …`. A target that starts from a call is an error: `set get(m, "a")["b"] to 1` →
`Invalid set target: it must start from a variable — write the path from the variable, e.g. set m["a"]["b"] to v`.
`set P to append(P, v)` (also `P + [...]`, `insert(P, i, v)`, `merge(P, m)`) updates in place, with
no copy of `P`, even when `P` is a path (`set s.items to append(s.items, x)`).

## Modules (`use` / `export`)
Split code across files. `export` makes a `task`/`type`/`let`/`enum`/`routes` public; anything
else is private. `use` imports a local `.syn` module under an alias (the module is a `map` of
its exports). An `export routes <name>` group (a block of `route ...` definitions) is mounted
by a serve block with `mount alias.name [at "/prefix"]` — see [modules.md](modules.md) and
[serve.md](serve.md).
```
-- lib.syn
export task greet(name)
    give "hi " + name
export let VERSION be "1.0"
task helper()                 -- no `export` → private
    give 1
```
```
-- main.syn
use "./lib.syn" as lib
print(lib.greet("Ana"))       -- cross-file call needs the alias prefix
print(lib.VERSION)
```
Paths are relative to the importing file (`.syn` only, no URLs/FFI, traversal blocked); imports are
cached, transitive, and cycle-checked. An exported `let` is ONE variable: `set lib.X to v` and
`set lib.STATE["k"] to v` write the module's own variable (its tasks see it) — through any alias,
a re-export or a map holding the module, all reach the same one; `let snap be lib.STATE`
is a snapshot (a value). Full guide: [modules.md](modules.md) (§ Module state).

## Property access
```
name of person         -- natural
person.name            -- dot (any word after the dot: tx.to, ev.type)
person["name"]         -- index
xs[-1]                 -- negative index = from the end (lists, text, bytes)
```
`of` needs a plain name on its left: `p["a"] of p` → parse error ``of` needs a plain name on its
left``. An index must be an integer (`xs[1.7]` → `index must be an integer, got 1.7`; `2.0` is fine).
A missing key is an error (`Map has no key`); `get(m, "k", default)` returns a default instead.

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
