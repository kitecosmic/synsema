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
- `assert_error` takes a 0-arg task/lambda. A `give` is NOT an error → a function that gives
  makes `assert_error` FAIL (not pass).
- An `assert` that fails inside a called task propagates and fails the surrounding test.

## `test` blocks

```
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
Exit code: **0** if all pass, **1** if any fail, **2** on usage/file error.

## Tests do NOT run under `synsema run`

`test` blocks are **skipped** by `synsema run` (so production code with embedded tests doesn't
run them). They run **only** under `synsema test`. So an `assert(false)` inside a `test` block
does not fail a normal `run`.

## Note
`synsema check` is still parse-only (it does not run tests or do semantic checks). Use
`synsema test` to actually execute assertions.
