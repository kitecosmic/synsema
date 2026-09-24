# Synsema Types

## Primitive types
- `number` — int or float: `42`, `3.14`, `1_000_000`, `0x1f18`, `0b101`, `0xFF_FF` (exact integers), `1e3`, `1.5e-3`, `1E+9` (**floats**, like Python — so `1e18` is a float; write wei as `10**18` or `1_000_000_000_000_000_000`). Integers are arbitrary-precision (promote past i64). `/` always returns float; `//` is floor division and stays an exact integer for integers (`(10**30) // 3`). `int(x)` converts to an exact integer (text, `0x…`, whole floats), `hex(n)` back to `"0x…"`; `is_integer(1)` → true, `is_integer(1.0)` → false. Int vs float compare **exactly** (v0.6.29+): `2**53 + 1 == 9007199254740992.0` is `false` (it was `true`), for `==`, `<`, `>`, `sort`… `text(42)` shows no decimal; `text(3.14)` shows decimal. See [builtins.md](builtins.md) § Core and [syntax.md](syntax.md) § Numbers.
- `decimal` — exact base-10 (money/finance): literal `1.50d` or `decimal("1234.56")`; `float(x)` back; `is_decimal(x)`. `0.1d + 0.2d == 0.3d`. **Decimal ⊕ Float → error** (Int mixes freely).
- `complex` — `complex(re, im)`; `real`/`imag`/`conj`/`arg`/`abs`/`is_complex`. Fluid arithmetic with promotion (`3 + complex(0,2)`); `**` with integer exponent is exact. `complex(a,0) == a`; **not ordered** (`<`/`>` → error). See [builtins.md](builtins.md).
- `bytes` — binary data: `bytes("hi")` (utf8), `bytes(s, "hex"|"base64")`, `bytes([72,73])`; `decode(b, "utf8"|"utf8_lossy"|"hex"|"base64")` (utf8 **strict** by default); `is_bytes`. `b[i]`→int 0–255 (`b[-1]` last), `length`/`slice`/`contains`/`in`/`+`, `each x in b` (ints), `hex(b)` → `"0x…"`. `bytes == text` is **always `false`** (`bytes("abc") == "abc"` → false; compare `decode(b) == "abc"`); `text(b)`/`print(b)` show a hex repr, NOT a decode. See [builtins.md](builtins.md).
- `text` — string: `"hello"`, `'world'`, supports `\n`, `\t`, `\\`; backtick `` `hi {x}` `` for interpolation + multiline. Indexable (v0.6.29+): `s[i]` is one character, counted like `length` (`"héllo"[1]` → `"é"`, `"abc"[-1]` → `"c"`); `each c in s` walks the characters. `text + number/bool` concatenates (`"n=" + 1`); `text + nothing/list/map/bytes` is an **error** (`Cannot add text and nothing — convert it on purpose: text(x), or interpolate it`). `is_text(x)`.
- `bool` — `true` or `false`
- `nothing` — null equivalent. In data (CSV, Parquet, SQL, tables) `nothing` means **missing**: reductions skip it (`mean([1, nothing, 3])` → `2.0`), `csv_parse` gives it for an empty field. NaN is a different thing — an invalid number, and it propagates. See [dataviz.md](dataviz.md) § Data analysis.
- `date`, `datetime`, `duration` — time as types (v0.6.29+), see § Dates below.

## Dates — `date`, `datetime`, `duration` (v0.6.29+)
Three distinct types (the java.time / JS Temporal / polars model), `type_of` → `"date"` / `"datetime"` / `"duration"`. All pure: only `now()` and `sleep()` touch the clock. Constructors and every builtin: [builtins.md](builtins.md) § Dates, instants and durations.

| Type | What it is | Build | Displays as |
|---|---|---|---|
| `date` | a civil day — no time, no zone | `date(2026, 1, 31)`, `date("2026-01-31")`, `parse_date(t, "%d/%m/%Y")` | `2026-01-31` |
| `datetime` | an instant + an IANA zone (DST-aware) | `datetime("2026-01-03T10:00:00Z")`, `datetime("2026-03-29T01:30:00", "Europe/Madrid")`, `datetime(2026, 1, 3, 10, 0, 0, "UTC")`, `datetime(ts)` | RFC 3339: `2026-01-03T10:00:00Z` in UTC; `2026-03-29T01:30:00+01:00[Europe/Madrid]` otherwise (RFC 9557) |
| `duration` | an exact amount of time (ns) | `duration(days = 1)`, `duration(hours = 1, minutes = 30)`, `t2 - t1` | ISO 8601: `P29D`, `PT1H30M`, `PT0S` |

**Arithmetic** (anything else → `Unsupported operation: …`):
- `date ± duration` → date, **whole days only**: `date(2026, 1, 31) + duration(days = 1)` → `2026-02-01`; `+ duration(hours = 1)` → error `a date moves by whole days — use a datetime for hours and minutes: datetime(d, tz) + duration(hours = …)`.
- `datetime ± duration` → datetime; the duration is **elapsed time**, so it is DST-correct: in Madrid, `datetime("2026-03-29T01:30:00", "Europe/Madrid") + duration(hours = 1)` → `2026-03-29T03:30:00+02:00[Europe/Madrid]` (02:00–03:00 does not exist that night). `duration(days = 1)` is 24 h, not "same time tomorrow" across a DST change — that is `add_days(t, 1)`.
- `datetime − datetime` and `date − date` → duration (`date("2026-03-01") - date(2026, 1, 31)` → `P29D`).
- `duration ± duration`, `duration * number`, `duration / number` → duration; `duration / duration` → float (`duration(hours = 3) / duration(minutes = 30)` → `6.0`).
- Calendar days and months are not fixed durations: `add_days(t, n)` keeps the local time, `add_months(t, n)` (31 Jan + 1 → 28/29 Feb).

**Comparison**: `<`, `>`, `==`, `sort`, `sort_by` work within one type, and so do `min`/`max`/`min_of`/`max_of`. Datetimes compare by the **instant**, whatever their zones (`datetime("2026-01-01T12:00:00Z") == datetime("2026-01-01T09:00:00-03:00")` → true). A date is not a datetime: convert with `datetime(d, tz)` or `date(dt)`.

**DST**: a local time that does not exist (the spring-forward gap) → error `… does not exist in Europe/Madrid (it falls in a daylight-saving gap)`; a local time that happens twice (fall back) → the **first** one. Zones are IANA names (`"America/Buenos_Aires"`), or `"UTC"`; an unknown one → error listing examples.

**Crossing boundaries**: `json_encode` and `csv_encode` write the ISO text; `json_decode` gives text back (re-type with `date(x)`/`datetime(x)`); `csv_parse` types a column with `{"types": {"when": "date"}}`; Parquet DATE/TIMESTAMP ↔ date/datetime (UTC). `timestamp(dt)` → unix seconds (float), `datetime(seconds)` back.

## Collection types
- `list` — `[1, 2, 3]`, `["a", "b"]`, mixed types allowed. `xs[-1]` is the last element. `is_list(x)`.
- `map` — `{"key": value, "key2": value2}` (preserves insertion order). `each k in m` walks the keys in insertion order (v0.6.29+); `get(m, k, default)`, `items(m)`, `merge`, `remove`. `is_map(x)`.
- `array` — n-dimensional **numeric** array (f64): `array([[1,2],[3,4]])`, `zeros`/`ones`/`arange`/`linspace`/`identity`. Vectorized math + broadcasting (`*` is **elementwise**, not matrix product); `matmul`/`solve`/`det`/`inv`/`eig`/`svd`. See [builtins.md](builtins.md). NumPy-equivalent core.
- **Display:** inside a list or map, text is shown quoted (v0.6.29+): `print(["1", 1, {"a": "b"}])` → `["1", 1, {a: "b"}]` (map keys stay bare); `text(xs)` is the same form. A top-level `print("x")` prints `x`.

## Values — lists and maps are values (copy-on-write, v0.6.29+)
A list or map behaves like a number: binding it or passing it gives a **logical copy**.
```synsema
let xs be [1, 2]
let ys be xs
set ys[0] to 9
print(xs, ys)                 -- [1, 2] [9, 2]

task poke(state)
    set state["a"]["b"] to 2  -- changes the task's copy only
    give state                -- give it back: that is how a change leaves a task
let m be {"a": {"b": 1}}
let m2 be poke(m)
print(m, m2)                  -- {a: {b: 1}} {a: {b: 2}}
```
Nothing is copied up front: a real copy happens only when a **shared** value is written, one level
at a time, so `set xs to append(xs, x)` / `set xs to xs + [...]` stay O(1) amortized when nobody
else holds the list. Before v0.6.29 maps and lists were shared by reference (a task that `set`
inside a map it received changed the caller's) — code that relied on that must now `give` the map
back. Shared state is explicit: the blackboard (`share`/`observe`), `memory`, the event bus,
`state_*` under `serve`.

A **module** is a namespace, not a value: `use "./store.syn" as store` then
`set store.CACHE["k"] to v` writes the module's own `CACHE`, the one its tasks read (also inside
`parallel_map` workers and `serve`). Only data is copied on write; module globals stay shared.

## Sum types (enums)
```synsema
enum OrderStatus
    pending
    paid(amount)
    shipped(date, carrier)

let s be OrderStatus.paid(100)
match s
    is OrderStatus.paid(amount)
        print("paid " + text(amount))
    is _
        print("other")
```
Construct `Name.variant(...)`; nullary `Name.pending` is a value. Match by variant with positional binding; modules can `export enum` and you construct/match it cross-file as `alias.Name.variant(...)` (see [modules.md](modules.md)). See [syntax.md](syntax.md) for rich patterns (guards, list/map).

## Callable
- `task` — function value, supports closures, default params (`task f(x, y = 10)`) and named args at call (`f(x, timeout = 5)`). Arity is **strict** (v0.6.29+): a missing argument without a default, or one too many, is an error — for lambdas too

## Custom types
```synsema
type Person
    name: text
    age: number

let p be Person("Alice", 30)
print(name of p)    -- "Alice"
print(age of p)     -- 30
```

## Every value is a SynValue
Internally, all values are wrapped in SynValue which carries:
- The raw value
- Type information
- Origin (where it was created)
- Capability tags

## Truthiness
- `nothing` → false
- `false` → false
- `0` → false
- `""` → false
- `[]` → false
- `{}` → false
- Everything else → true
