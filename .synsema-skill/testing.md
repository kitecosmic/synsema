# Synsema Testing — native `assert` + `test` blocks

Synsema has a built-in test framework. No dependencies.

## Assertions (work anywhere — also as defensive checks in normal code)

```
assert(cond)                       -- fails if cond is falsy ("assertion failed")
assert(cond, "message")            -- custom failure message
assert_eq(actual, expected)        -- fails if actual != expected (shows both)
assert_eq(actual, expected, "msg")
assert_ne(a, b)                    -- fails if a == b
assert_error(fn)                   -- passes if calling fn() raises an error; FAILS if it returns
```

- Equality is structural value equality (same as `==`).
- `assert_error` takes a 0-arg task/lambda (`assert_error(() => int(1.5))`). A `give` is NOT an error → a function that gives
  makes `assert_error` FAIL (not pass).
- An `assert` that fails inside a called task propagates and fails the surrounding test.

## `test` blocks

```synsema
task add(a, b)
    give a + b

test "addition works"
    assert_eq(add(2, 3), 5)

test "bytes round-trip"
    assert_eq(decode(bytes("48656c6c6f", "hex")), "Hello")
```

- `test` is a **soft keyword**: `test "name"` starts a block; elsewhere `test` is a normal name.
- Top-level definitions (tasks, `let`, enums, types) and `require` grants are visible inside tests.
- Each test runs **isolated** in its own child scope — a `let x` in one test is not visible in
  another. A failing test does NOT abort the others.

## Running tests

```bash
synsema test path/to/file.syn       -- run the test blocks in a file
synsema test path/to/dir            -- run every .syn under a directory
synsema test file.syn -v            -- also show the tests' print() output
```

Output: `✓ name` / `✗ name: reason`, then `N passed, M failed (K total)`.
Exit code: **0** if all pass, **1** if any fail, **2** on usage/file error (incl. an unknown `--flag`, v0.6.14+).

`test` honors the host ceiling and profile like `run`: `synsema test --sandbox tests.syn`,
`--cap-set "stdout,time,net=api.x"`, `--profile pure` (the second wall — filesystem/exec/db/socket/
cron builtins gone), and `--audit json|<path>|fd:N` to log every capability check. So you can prove a
program stays inside a ceiling from a `test` block (v0.6.14+).

## Tests do NOT run under `synsema run`

`test` blocks are **skipped** by `synsema run` (so production code with embedded tests doesn't
run them). They run **only** under `synsema test`. So an `assert(false)` inside a `test` block
does not fail a normal `run`.

## Agents inside tests (engine v0.6.10+)
`spawn` inside a `test` block starts a real agent thread (same swarm as `run`); `wait_for`,
`observe`, `agents()` work. At the end of the block the runner joins its agents — an agent that
ended in `ERROR` fails that test, the next block starts clean. See [agents.md](agents.md).

## Note
`synsema check` does not run tests: it parses, resolves imports and templates, and warns (e.g. a
deprecated builtin name — v0.6.29 renamed several, see [builtins.md](builtins.md) § Renamed in
v0.6.29). Use `synsema test` to actually execute assertions.

A test that compares **printed output** of lists/maps must expect text quoted inside them since
v0.6.29 (`["1", 1]`, `{a: "b"}`); `assert_eq` on the values themselves is unaffected. Equality
between int and float is exact (`2**53 + 1 == 9007199254740992.0` is `false`).
