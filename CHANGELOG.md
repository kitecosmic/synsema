# Changelog

Notable changes to the Synsema language, engine and tooling. The entries that matter most are the
**breaking** ones: a program that used to load and no longer does, or that behaves differently.
Each says what changed, why, and what to write instead.

Versions follow the release tags (`v0.6.24`, `v0.6.25`, …). Dates are the release date.

## v0.6.30 — unreleased

Fixes from the v0.6.29 audit, plus three things data and scheduling code kept asking for: cron in
an IANA time zone, decimals written with an exponent, and Parquet files that pandas and polars read
with their types. Nothing that worked right stops working; what changes is silent wrong results that
are now errors, and error messages that now say what to write.

**New.**

- **`cron_every` takes an IANA zone**: `cron_every("0 9 * * *", report, {"tz": "America/Santiago"})`
  runs at 09:00 Santiago time all year. Clock changes follow the rule every Linux cron uses (Vixie
  cron / cronie): a fixed time that falls in the hour skipped in spring runs right after the jump
  instead of being lost; a fixed time in the hour repeated in autumn runs once, the first time; a job
  with `*` in the minute or hour field (`*/15 * * * *`, `0 * * * *`) follows real time, so skipped
  minutes do not exist and the repeated hour runs twice. Fixed offsets (`"-03:00"`) work as before;
  an unknown zone is an error at registration. `cron_list()` shows the zone name in `tz`.
- **A decimal can be written with an exponent**: `decimal("1.5e-3")` → `0.0015`, `decimal("1e5")` →
  `100000`, `2e3d` → `2000`. The value is exact (mantissa × 10^exponent), like Postgres `numeric`;
  the scale is the mantissa's minus the exponent (`decimal("1.50e1")` → `15.0`). A CSV column typed
  `decimal` reads the same way. A value of more than 4300 digits (`"1e999999999"`) is an error, so a
  short text cannot ask for unbounded memory.
- **`parquet_write` writes the Arrow schema** (`ARROW:schema`), as pyarrow, polars and arrow-rs do:
  pandas, pyarrow and polars read a `duration` column as a duration (`timedelta64`) and a `datetime`
  column with its IANA zone (`datetime64[us, Europe/Madrid]`), not as an integer and UTC. A
  fixed-offset zone (`+05:30`) goes as UTC in that schema, because polars cannot open a file with
  one; Synsema still reads the offset back.
- **`synsema test` takes several files and directories** (`synsema test a.syn b.syn tests/`), and
  expands a glob the shell passed as is (PowerShell and cmd do not expand `tests/*.test.syn`). It
  used to run only the last path, without saying so.

**Silent wrong results that are now errors (or right).**

- **`parse_datetime` with `%Z` no longer ignores the zone.** `parse_datetime("24/09/2026 10:00 IST",
  "%d/%m/%Y %H:%M %Z")` gave 10:00 UTC. An abbreviation does not identify a zone (IST is India,
  Ireland or Israel), so it is now an error. `UTC` and `GMT` are unambiguous and still work, in any
  case, as in Python (an HTTP date parses); with `%z` in the same format (`"+0530 (IST)"`) the offset
  decides and the abbreviation is just text. **What to write instead:** `%z` for an offset
  (`+05:30`), or drop the abbreviation from the text and pass the zone:
  `parse_datetime(text, format, "Asia/Kolkata")`.
- **`parse_datetime` with a date-only format is midnight**: `parse_datetime("03/01/2026", "%d/%m/%Y")`
  → `2026-01-03T00:00:00Z` (it failed with `input is not enough`), like Python's `strptime` and
  `parse_time`; with a zone, midnight in that zone.
- **`polyval` keeps `nothing` apart from NaN.** A missing coefficient is an error (there is no
  polynomial); a missing `x` in a list stays `nothing` in its place, like `cumsum`:
  `polyval([2.0, 1.0], [1, nothing, 3])` → `[3.0, nothing, 7.0]` (was `[3.0, nan, 7.0]`). The same
  error for a missing value in `lstsq`'s `b`. **What to write instead:** `drop_missing(xs)` first.
- **`length` of a 0-d array is an error** (it gave 0, so a scalar looked empty; numpy raises too).
  **What to write instead:** `size(a)`, which is 1.
- **`json_encode`, `jsonl_encode` and `json_for_script` reject a task or a generator** instead of
  writing its text (`json_encode(rng(1))` gave `"builtin:rng(1)"`, revealing the seed and not the
  state). The error names where it is: `json_encode: the value["f"] is a task, not data`.
  `canonical_json` now says "generator" for a generator. **What to write instead:** store what the
  task computes, or leave it out of the value.
- **`int(x, 2.0)` is the same mistake as `int(x, 2)`**: a number with an integral value from 2 to
  36 in second place is an error that points at `base =` or `fallback =` (it returned `2.0` for any
  text that did not parse). **What to write instead:** `int(x, base = 2)` or `int(x, fallback = 2.0)`.
- **`request.json` reads the body with the same parser as `json_decode`**: `{"v": -0}` gives `0` in
  both (it was `-0.0` in `request.json`), and a body that starts with a byte order mark is read
  instead of answered with 400.
- **Parquet: durations round-trip.** `parquet_write` writes a `duration` column as INT64 (as Arrow
  does) with its unit in the file metadata (`synsema.durations`), in microseconds, or nanoseconds
  when a value needs them; `parquet_read` reads it back as a duration, and also reads the Arrow
  `duration` type that pyarrow and polars write (it came back as an integer without a unit).
  `parquet_read(parquet_write(rows)) == rows` holds with durations, including a `TIME` column read
  from another tool.

**Faster.**

- **`index_of` no longer copies the list** before searching: an early hit is O(1), like `in` and
  `contains`.

**Warnings and messages.**

- The deprecated-name warning is printed for a module loaded with `use`, once, like for the main file.
- `solana_message(1, 2)` and `algorand_tx_encode({}, 1)` name the function that was called (they
  spoke about `solana_tx` and `algorand_tx`).
- A C-style `//` comment gets the hint "comments in Synsema start with `--`": at the start of a line,
  after code (`let x be 1 // a note of several words`, whose error was about whatever word came
  next), on an indented line of its own, and when the note has an apostrophe (`// don't`, an
  unterminated string); also in `let x be 1 // note` when `note` is not a variable. `//` is integer
  division, which does not change.
- `set xs[10] to 1` out of range says where and the length, like reading `xs[10]`.
- `bytes(33)` suggests `int_to_bytes(33, size)` and `bytes([33])`.
- `json_decode("Infinityx")` and `json_decode("NaNa")` are the generic invalid-JSON error with the
  position, not "NaN/Infinity is not JSON".
- `format_time(t, "%#z")` says that `%#z` is a parsing-only specifier and points at `%z` / `%:z`.
- `synsema check` warns about `\u` only where the escape is decoded (`"\uD800"` alone and
  `"\u{110000}"` stay literal text, as before).
- `synsema check` warns when a task writes into a parameter and neither gives it back, passes it on,
  nor reads what it wrote: with value semantics that write is lost. **What to write instead:** end
  the task with `give cfg` and call it as `set c to touch(c)`.
- Reading a name a module does not export suggests the form it has: `export enum Color`,
  `export task helper`.
- `synsema check` decides file scopes with the runtime's own matcher: `require file.read("./**")`
  covers `read_file("x.csv")`, as it does when the program runs.

## v0.6.29 — 2026-09-24

Everything that had to break before v1.0, broken once (after v1.0 nothing breaks), plus EVM
contract deployment and events, and the start of data analysis (tables, dates, seeded randomness,
Parquet, lineage). Old names keep working as deprecated aliases until v1.0:
`synsema check` warns about each one, and a program that uses them says so once on stderr.

**Breaking, on purpose.**

- **Lists and maps are values (copy-on-write).** `let ys be xs` and passing a list or map to a task
  give a logical copy: `set ys[0] to 9` changes only `ys`, and a task that `set`s inside a map it
  received no longer changes the caller's. **What to write instead:** `give` the map back (that is
  how a change leaves a task). Shared state stays explicit: blackboard, memory, bus, `state_*`.
  Modules are namespaces, not values: an exported variable is ONE variable, seen the same by the
  module's tasks and by `mod.STATE` (`set mod.STATE[k] to v` writes it, `set mod.X to v` rebinds it);
  `let snap be mod.STATE` is a snapshot — through every alias, a re-export (`export let L be mod`),
  a module kept in a map, `parallel_map` and `serve`. A module gains no names from outside and its
  tasks are not replaceable (`set mod.f to …` and `set mod["f"] to …` are errors). The common idioms
  stay O(1) per step: `set xs to append(xs, v)`, `xs + [...]`, `insert(xs, i, v)`, `merge(m, …)` and
  `set m[k] to v` write in place, also through a path (`set s.items to append(s.items, v)`).
- **A `set` target starts from a variable**: `set get(m, "a")["b"] to 1` is an error (with value
  semantics it either wrote a throwaway copy or leaked into shared data). **What to write instead:**
  the path from the variable, `set m["a"]["b"] to 1`.
- **Strict arity** for calls written in the program: a missing parameter without default or an
  extra argument is an error (`task 'f' takes 1 argument, got 3`, `append() takes at most 2
  arguments, got 3`). Before, extras were dropped silently (`append([1], 2, 3)` lost the 3,
  `trim(s, "x")` ignored the `"x"`) and missing ones arrived as `nothing`. Callbacks that a builtin
  or the host calls (`apply`, `where`, route handlers, cron) keep receiving what they get.
- **`-2 ** 2` is -4** (power binds tighter than unary minus, as in math and Python).
- **`|>` has the lowest precedence** and a call step receives the value as its first argument:
  `1 + 2 |> double` is `double(3)`, `xs |> sort_by(f)` is `sort_by(xs, f)`.
- **`number(text)` of an integer beyond ±2⁵³ is an error** naming `int` (it used to lose digits).
- **Integer vs float comparison is exact**: `2**53 + 1 == 9007199254740992.0` is `false`.
- **A non-integer index, position or step is an error** (`xs[1.7]`, `range(0, 2.5)`); `2.0` is fine.
- **Text + `nothing`/list/map/bytes is an error** (was `"xnothing"`); text + number/bool still joins.
  A template hole takes any value, like an f-string: `` `xs={xs} n={nothing}` `` → `xs=[1, 2] n=nothing`.
- **Inside lists and maps, text is shown quoted**: `print(["1", 1])` → `["1", 1]`.
- **`--` glued to a value and followed by a number or `(` is a lexer error** (`5--1` and `x--(y)` used
  to be a value plus a comment: a silent arithmetic result). Followed by anything else it is still a
  comment, as in v0.6.28: `print(1)--note`, `x--note`, `"a"--note`. Inside
  parentheses, `print(x --1)` is a lexer error that points at `x - -1` (as a comment it would swallow
  the `)`); it fires only when a value comes before on the same line, a digit or `(` comes after, the
  innermost bracket is `(` and its closing `)` is on that same line. Any other `--` is a comment, as
  always: `"a": 1,  --TODO` in a multiline map or list, or `4 --note` in a call that spans lines,
  keeps working.
- **`sort_by` orders totally or errors** (it silently left mixed or NaN lists as they came);
  `nothing` and NaN go last; `min`/`max` skip `nothing` and propagate NaN.
- **`fmt` errors on a `{name}` without a value** (it was left in the text). `{a.b}` reads the key
  `"a.b"` if the map has it, else the field `b` of the map `a`; `{ x }` with spaces, and `{obj.prop}`
  when the map has no `obj`, stay literal (CSS and JavaScript in a template are safe). Text between
  braces that is EXACTLY a key of the map is always replaced, whatever its shape
  (`fmt("[{0}] {a-b}", {"0": "z", "a-b": 1})` → `[z] 1`). Otherwise a hole is a name that starts with
  a letter or `_` (dots between names): regex quantifiers such as `{3}` and `{3,5}`, `{}` and `{a..b}`
  stay literal — `fmt("^[0-9]{3}-{n}$", {"n": 1})` → `^[0-9]{3}-1$`.
- **`solana_tx` and `algorand_tx` now BUILD** (they were `solana_message` / `algorand_tx_encode`);
  assembling the signed transaction is `solana_tx_raw` / `algorand_tx_raw`. The old two-argument
  call errors pointing there.
- **`json_decode("1e400")` is an error** (it gave infinity, which JSON cannot carry back); integers of
  more than 4300 digits are an error in `json_decode`/`jsonl_decode`/`int(text)`/`number(text)` (the
  Python limit: converting them is quadratic, so a hostile document could buy minutes of CPU).
- **`int("ff", 16)` is an error that says why** (any whole number 2..36 as the second argument of
  `int`, whatever the first argument is — the result never depends on the data): that argument is the
  fallback, not the base. **What to write instead:**
  `int("ff", base = 16)`, or name a numeric fallback: `int(text, fallback = 10)`.
- **Float `//` and `%` are CPython's**: `7 // 0.1` is 69.0 and `7 % 0.1` is 0.09999999999999962 (they
  were 70.0 and 0.0); arrays too, as numpy.
- **Number literals take `_` only between digits** (`1_000`, `0x_ff`): `1__0`, `1_`, `1_.5`, `1e3_`
  are lexer errors, as in Python (`1__0` was 10 and `1_` was 1).
- **`\uXXXX` and `\u{1F600}` in a string are escapes** (`"\u00e9"` is `"é"`; a surrogate pair
  `"\uD83D\uDE00"` is one character); before, the six characters stayed as written. `synsema check`
  flags every literal that uses one. **What to write instead:** `"\\u00e9"` for a literal backslash + u.
  Anything that is not a complete escape stays literal (`"C:\users"`, `"\u12"`), `\x` is NOT an escape
  (`"C:\build\x64"` and the regex `"a\x2eb"` are unchanged), and inside a backtick only the four-digit
  form is one — `` `x\u{a}y` `` still interpolates `a`.
- **`decimal` has arbitrary precision and a stable type** (the best of Java's `BigDecimal`,
  Postgres `numeric`, Python `decimal` and Julia's promotion rules):
  - `+`, `-`, `*`, `//`, `%`, `**` with an integer exponent and every comparison are EXACT at any size.
    `1d + 10**30` is the decimal 1000000000000000000000000000001, `1d < 10**30` is true, and
    `1.1d ** 30` has its 30 decimals. Before, a result past 28 digits turned into a float.
  - `/` and `std` round to 28 SIGNIFICANT digits, half to even (Python's default context), never cutting
    the integer part (like Postgres). `0.00000000000000000001d / 10000000000d` is 1e-30 exactly; it was
    `0`, because the old decimal only had 28 places after the point.
  - A decimal operation always gives a decimal; it never turns into a float or an integer depending on the
    value. Literals, `decimal(text)`, CSV `decimal` columns, Parquet decimal columns and Postgres
    `numeric` take any number of digits (up to 4300 in text). A Parquet decimal of more than 28 digits
    used to come back as text.
  - `floor`, `ceil`, `round` and `trunc` of a decimal give the exact integer. They returned the decimal
    unchanged.
- **A decimal compared with a float is an error wherever they really meet**, as `1d == 1.0` already
  was: inside lists and maps (`[1d] == [1.0]`), in `in`, `match` value patterns, `contains` and
  `index_of` (`contains([1.5d], 1.5)` was a silent `false`; a `match` fell to `otherwise`), and as a
  key of `group_by`, `unique`, `join`… (details under Added). Integers mix freely (`[1d] == [1]` is
  `true`). **What to write instead:** convert first, `decimal(x)` or `float(x)`.
- **`join(xs, sep)` with `nothing`, a list or a map inside is an error** (it wrote "a,nothing"), and
  text + a task is an error like text + a list.
- `while` has no iteration cap (was 1,000,000; the wasm build keeps it — its host has no `timeout`,
  threads or signal to stop a loop that never ends, and would hang); `print`, `log` and `show` under `synsema run` are
  written immediately, in order.

### Added

- **Numbers:** `int(x)` / `int(x, default)` / `int(text, base = b)` (exact; decimal, `0x…`, `0b…`,
  a sign before `0x`), the floor-division
  operator `//` (exact for integers of any size), `hex(x)` (quantity for integers, data for bytes),
  literals `0x1f18`, `0b101`, `1e-9`, `json_decode` keeps integers of any size exact,
  `bytes(s, "hex")` accepts `0x`, `is_integer`/`is_text`/`is_list`/`is_map`.
- **Syntax:** `in` / `not in`, chained comparisons (`1 < x <= 10`), negative indexes (`xs[-1]`),
  text indexing (`s[0]`), any word as a member after `.` (`ev.type`, `tx.to`), `each` over maps
  (keys), text (characters) and bytes, a trailing comma in calls, as in lists and maps.
- **Maps and order:** `insert(xs, i, v)`, `get(m, k, default)`, `remove`, `merge`, `items`, `sort(xs, desc = true)`,
  `sort_by(xs, key, desc = true)`, `index_of` on text, `min`/`max` on text.
- **Renamed** (old names are deprecated aliases): `replace_text`→`replace`,
  `find_all`→`regex_find_all`, `capture`→`regex_capture` (always a list or `nothing`),
  `replace_re`→`regex_replace`, `fold`→`fold_text`, `eye`→`identity`, `hmac_sha256`→`hmac` (bytes).
- **Blockchain, `<family>_<action>`:** `eth_*`/`tx_eip1559*` → `evm_*` (`evm_tx`, `evm_tx_raw`,
  `evm_send`, `evm_wait`, `evm_balance`, …), `solana_confirm`→`solana_wait`,
  `algo_address`→`algorand_address`. New: `evm_tx_create` (contract deployment), `evm_tx_raw` checks
  what is signed (it recomputes the digest from `fields`, every echoed field must match `fields`, a
  creation must carry `from`, the signer must be `from` and `contract_address` is re-derived — a map
  edited after `evm_tx` is refused), `evm_create_address`, `evm_create2_address`, `evm_signature`
  (v = 27/28 for wallets and `ecrecover`), `secp256k1_recover` accepts v = 27/28,
  `evm_block_number`, block parameters accept the node's `0x…` quantity (also in
  `evm_estimate_gas(url, tx, block?)` and `evm_fee_history(url, blocks?, percentiles?, newest?)`), `evm_logs`,
  `abi_event_topic`, `abi_decode_log`, `abi_encode(types, values)` without selector (constructor
  arguments), `evm_address` of 20 raw bytes.
- **Errors that speak Python:** `return x`, `x = 1`, `x += 1`, `if x:`, `len(xs)`, `None`,
  `xs.append(y)`, `d.get(k)`, `f"…"`, `lambda y: y`, `x is None`, `a if c else b`, `xs[1:]`,
  `type(x)`, `"%d" % x` and friends get the Synsema form in the message.
- **HTTP:** a URL with `user:pass@` sends `Authorization: Basic` (as curl and requests do); a URL with
  a query and no path, IPv6 hosts and fragments work; `Host` carries a non-default port. A URL
  without a host is an error that does not echo the URL, and `require net("https://u:p@api.x.com/v1")`
  is stored as `net("api.x.com")`: credentials never reach a message or the audit. An EXPLICIT port is
  part of the grant: `require net("http://localhost:8545")` is `net("localhost:8545")` and covers only
  that port (v0.6.28 did not take a URL as a grant at all); `net("localhost")` still covers any port,
  and `[::1]:8545` works.
- **Strings and numbers:** the `\u` escapes above; octal literals `0o17`; `number("1_000.5")`. A decimal
  with a float is an error also inside lists when a comparison meets them at the same position
  (`sort([[1.5d], [1.0]])`; `sort([[1d, 1.5], [2d, 2.5]])` sorts fine) and as a `join` key (they never
  match — it returned `[]`). The same error, `cannot mix decimal and float`, whenever a decimal and a
  float are really compared: in `x in list` (item by item: `1.5 in [1.5d]` is an error,
  `"a" in ["a", 1.5, 1d]` is `true`), and in `group_by`, `count_by`, `summarize`, `unique`, `mode`,
  `pivot` and `n_unique_of` when two keys land on the same number (`unique([1.5d, 1.5])` gave both;
  `unique(["a", 1.5, 1d])` is fine, 1.5 and 1 never meet). NaN does not count. `match` value patterns,
  `contains` and `index_of` follow the same rule (`contains([1.5d], 1.5)` was a silent `false`; a
  `match` fell to `otherwise`). Every equality stops at the first difference: `["a", 1d] == ["b", 1.0]`
  is `false`, and two maps with different keys are `false`. `==` on lists and maps
  compares item by item with the same rule — `[1d] == [1.0]` and `{"a": 1d} == {"a": 1.0}` are the
  error of `1d == 1.0` (they were `false` in silence), `[1d] == [1]` is `true`, and `in` compares
  the same way.
- **More Python/pandas reflexes:** `else`/`pass`/`break`/`continue` on their own line, `c ? a : b`,
  comprehensions, `round(x, 2)`, `x --1` inside parentheses, `dropna`/`fillna`/`groupby`/`value_counts`.
- An engine panic reports itself as an internal error with its message (it blamed a stack overflow).
- Clearer errors: `if (x > 0)` with an indented body says `if` is not a Synsema statement (use
  `when`) instead of `Unexpected token: INDENT` on the next line; an error inside a template hole
  points at the hole (it said 1:1); SQLite's own texts are rewritten — a statement that returns rows
  in `sql_exec`/`sql_batch`, and `the statement has 1 parameter(s) but 0 value(s) were passed`.
  `synsema check` no longer says a glob `require file.read("./*")` misses `read_file("./x.csv")`.
- **Fixed:** `btc_rpc` against a real Bitcoin Core failed with an empty `RPC error:` — JSON-RPC 1.0 sends
  `"error": null` in every good answer. On SQLite, `sql_exec` refuses a `RETURNING`
  statement before running it (SQLite had already written the row); the word inside a string or a
  comment does not count. Postgres and MySQL run it as before and return the count. `sql_batch` does
  the same check before running any row (it wrote the first one and then failed).
  `abi_decode_log` refuses two inputs that would get the same name (one value was lost), `evm_logs` a
  filter with more than 4 topics, `evm_create_address` a nonce of 2^64 − 1 or more (EIP-2681).
  `synsema code caps` reads `require net(<url>)` as its host (and its port, when the URL has one), like
  the runtime. `except`/`catch` after a `try` and `finally` name the Synsema form.

**Breaking, on purpose (data).**

- **`std` and `var` are sample statistics** (`ddof = 1`, like pandas, polars, R and Excel `STDEV.S`):
  `std([1,2,3,4])` is 1.29, not 1.118. **What to write instead:** `std(xs, ddof = 0)` for the population
  figure. `synsema check` flags every `std`/`var` until v1.0.
- **`group_by(rows, key)` returns `[{key, items}]`** in first-appearance order, with the key's own type
  (`1` and `1.0` are one group). It returned a map keyed by text. **What to write instead:**
  `each g in group_by(rows, "region")` → `g.key`, `g.items`; for per-group figures, `summarize`.
- **`dot` is the inner product of two vectors only**; for matrices use `matmul(a, b)`.
- **Reductions skip `nothing` and propagate NaN** (`mean([1, nothing, 3])` is 2.0; `median` no longer
  errors on NaN, it returns NaN).
- **An empty CSV field is `nothing`** (was `""`); a quoted `""` is empty text, and `csv_encode` writes
  them apart, so a round trip is exact. `synsema check` warns about `x == ""` in a program that reads CSV.
  A blank line is always skipped when reading, also in a one-column CSV (like Python `csv` and pandas):
  `csv_parse("x\n1\n\n2\n")` has 2 rows. So a row whose only field is `nothing` is written `""`, as
  Python's writer does — the one case where the round trip does not tell `nothing` from `""`: in a
  one-column CSV a missing value comes back as empty text (or `nothing` if the column has a type), and
  `csv_encode` warns once on stderr. For an exact round trip with any number of columns,
  `csv_encode(rows, {"missing": "NA"})` writes each `nothing` as `NA` without quotes (pandas'
  `na_rep`) and quotes a text that equals the mark; read it back with `{"missing": ["NA"]}`. An empty
  mark is an error (an empty field already reads as `nothing`, and in one column it would be a blank
  line that reading skips).
  A quote left open in a CSV whose lines end in `\r` (old Mac) is an error with the right line, like
  `\n` and `\r\n` (it was read to the end of the text in silence).
- **A column name that no row has is an error** in `group_by`, `summarize` aggregates (`sum_of("vv")`),
  `join` and `pivot` (a misspelling summed to 0); an aggregate named like a key column, or two pivot
  values that would become the same column, are errors instead of overwriting.
- **`polyfit` errors when the data does not determine the fit** (fewer distinct x than degree + 1);
  numpy only warns.
- **`round_to` rounds a float's real binary value, like Python** (`round_to(2.675, 2)` is 2.67) and keeps
  decimals decimal.
- `format_time`, `parse_time` and `date_parts` no longer require `time` (they don't read the clock).
- **Fixed:** `format_time` with an unknown specifier (`%Q`), or with one the value does not have (`%H`
  of a `date`), crashed the engine and `try` could not catch it. Now it is an error that names it:
  `format_time: "%Q" is not a strftime specifier (…)`.

### Added (data)

- **Tables** (lists of maps): `summarize(rows, by, aggs)` with `sum_of`, `mean_of`, `min_of`, `max_of`,
  `median_of`, `quantile_of`, `first_of`, `n_unique_of`, `count()`; `count_by`; `join(left, right, on,
  how?)` (inner/left/right/outer/semi/anti, by hash, every output row with every column);
  `pivot(rows, index, columns, values, agg?)`; `is_missing`, `fill_missing`, `drop_missing`,
  `fill_nan`; `mode`; `count(xs)` (present values) and `count_missing(xs)`. A column is checked
  against the whole table (ragged rows are fine; a name no row has is an error); `join` refuses an
  output name that already exists (not in `semi`/`anti`, which add no right columns). Keys follow `==`: maps with
  the same entries in another order, the same instant in another zone, `1` and `1.0` are one group;
  the text `"1"` is another; NaN is one group. `unique`, `mode` and `n_unique_of` are linear.
- **Reductions:** named `axis =` and `ddof =`, `quantile(values, q)`, decimals kept, `min`/`max` on
  dates. **Arrays:** elementwise math, `**`/`//`/`%`, `length`, negative index, `slice`, `apply`,
  `where` as a mask, `concat`, `stack`, `argmin`, `argmax` (a list skips `nothing`), `cumsum`, `diff`.
  **Statistics:** `corr`, `cov`, `lstsq` (numpy's: SVD, minimum norm, works rank-deficient),
  `polyfit`, `polyval`. `median`, `var`, `std`, `quantile` and `percentile` of decimals (with integers of
  any size) are computed exactly, like Python's `statistics`, and are always decimals — exact when the
  result terminates, else 28 significant digits (`std` of decimals that differ by 1e-15 is
  `0.000000000000001527525231651946668862682398`, never `0`).
- **Seeded randomness, pure — the same numbers as numpy:** `rng(s)` is `numpy.random.default_rng(s)`
  bit for bit (SeedSequence + PCG64): `g()`/`random(g)`, `random_int(g, lo, hi)` (=
  `integers(lo, hi + 1)`), `random_normal(g, mean =, std =)` (numpy's ziggurat), `shuffle`
  (`permutation`), `choice`, `sample` (`choice(…, replace=False)`) and `rng_spawn(g, n)` (`spawn`) —
  verified value by value against numpy 2.2. A generator is a process, like numpy's: `let h be g` is
  the same stream; `rng_spawn` gives independent ones, and they travel to `parallel_map` workers,
  which hand back how far they advanced (as `apply` would: using `g` or the children again continues
  the sequence). Passing the SAME generator to two items (at any depth), or using a top-level
  generator — by name, inside a global map or list — inside a worker or a `serve` request, is an
  error (numpy silently repeats the sequence).
  Allowed under `--deterministic`.
- **Dates as types:** `date`, `datetime` (an IANA zone, DST-correct, or a fixed offset) and `duration`,
  with arithmetic,
  comparison, `add_days`, `add_months`, `truncate`, `date_range` (by `"second"`, `"minute"`, `"hour"`
  — elapsed time — or by a calendar unit or a duration), `to_timezone`, `timestamp`,
  `in_units`, `parse_date`, `parse_datetime`; JSON and CSV write them as ISO 8601. Calendar steps keep
  the local time across a DST change, a day without midnight starts when it starts (01:00), a day
  that never existed is skipped by `date_range` instead of repeating the next one (Pacific/Apia,
  30/12/2011), and
  truncating or adding days/months inside the repeated hour keeps which of the two it was
  (`add_days(t, 0)` is `t`); a day whose midnight repeats is one day. **An offset is kept**, as in
  Python, java.time, Temporal, Arrow and pandas: `datetime("2026-09-24T02:00:00+05:30")` prints as
  such, `date_parts` gives hour 2 and zone `"+05:30"`, and calendar operations use that local time
  (equality and order are by instant); `+0530` reads too, and a zone can be a fixed offset anywhere
  (`to_timezone(t, "-03:00")`, `parse_datetime` with `%z`). RFC 9557 as in Temporal:
  `…T10:00:00[Asia/Kolkata]` is 10:00 local time there (a DST gap → error), and an offset that does
  not match its bracketed zone → error.
- **Formats:** `csv_parse(text, {"types": {...}})` (int/float/decimal/text/bool/date/datetime per
  column) and `{"missing": ["NA", "NULL"]}` (those texts, unquoted, are `nothing` — polars'
  `null_values`; a quoted `"NA"` stays text); a `float` column refuses `1e400` (it was infinity) and
  reads `nan`/`inf` written as such; an integer of more than 4300 digits is an error, as in `int()`;
  the delimiter cannot be the quote or a line end. `csv_encode(rows, {"escape_formulas": true})`
  prefixes `'` to a text that starts with `=`, `+`, `-`, `@`, tab or CR, so Excel and Sheets show it
  instead of running it (OWASP "CSV injection"; off by default because it changes the data).
  `jsonl_encode`/`jsonl_decode`, `parquet_read`/`parquet_write` (read and written by polars in
  tests; zstd/snappy/gzip/lz4; a datetime column keeps its zone, also the zone polars and pyarrow
  write in the Arrow schema (`ARROW:schema`), a fixed offset such as `+05:30` included; nanoseconds
  are read and written; a file with two columns of the same name is an error, and so is writing an
  integer beyond 2^53 in a column that mixes integers and floats (it would be rounded to a DOUBLE); a
  `TIME` column (time of day) reads as a `duration` since midnight, in ms, µs or ns (polars writes ns;
  it came back as a bare integer);
  a file that would expand past its caps — a page over 256 MiB, max(1 GiB, 64 × the file), 50 million
  cells — is refused before allocating, `{"max_cells": n, "max_bytes": n}` raises them; not in the
  wasm build). `json_decode` skips a BOM and reads the `NaN`/`Infinity` that `json_encode` writes only
  when asked — `json_decode(text, allow_nan = true)` (also `jsonl_decode`); by default they are an
  error, because a NaN passes every `amount <= 0` check;
  raw RPC answers (`evm_rpc`, `solana_rpc`, `btc_rpc`, algod) keep integers beyond 64 bits exact.
- **Lineage:** the engine records every input the program reads — files, directory listings, `grep`,
  Parquet, stdin and the terminal, HTTP, SQL/Mongo/Redis reads, `recall`, chain nodes (EVM, Solana,
  Algorand, Bitcoin), sockets and processes, and every model answer (`reason`/`decide`/`analyze`/
  `generate`) and what `run`/`run_program` return — with the sha256 of what it received and its
  `encoding` — `"text"` (utf-8), `"bytes"`, `"jcs"` (`canonical_json(x)`), `"json"` (`json_encode(x)`,
  for integers beyond 2^53 or NaN) or `"display"` (the printed form, for what neither can carry) — so
  anyone recomputes it; `lineage()` lists it and `receipt()` publishes it as `inputs`, so a signed receipt
  proves which inputs, which program and which output. A host is published without credentials,
  path or query; a read that never arrived is not an input.
  - **The receipt never carries data.** An input's `what` is only a path the program passed as text,
    a host, a salted commitment or a size: `parquet_read(bytes)` records `bytes <n>` (not the file's
    first bytes), `grep` the target and never the pattern, and a host comes only from the CONNECTION —
    the URL of `http_*`/`fetch` or the node of a chain reader — with a network scheme (`http`, `https`,
    `ws`, `wss`): a `://` inside a SQL query, a redis or Mongo key, or a `recall` category such as
    `"session://TOKEN"` is data, not a host, and only its salted commitment is published.
  - **Queries and prompts are salted commitments**, like SD-JWT disclosures. This covers a SQL query, a
    Mongo filter, `run` arguments, an RPC call and a model prompt.
  - The receipt publishes `query sha256-salted:<hex>` = `sha256(salt ‖ canonical_json([args…]))`, with a
    fresh 128-bit salt per entry. Nobody can recover the query by hashing guesses (a plain sha256 of
    `run("id", "-u")` can be recovered that way).
  - The salt stays in the local `lineage()` (`salt`, `committed_encoding`) and never in the receipt.
    With it, the owner can later reveal one query and anyone can check it:
    `hex(sha256(bytes(salt, "hex") + bytes(canonical_json(args), "utf8")))`.
  - Redis counters (`redis_incr`, `redis_incrby`, `redis_decr`, `redis_hincrby`) are inputs too.
- **`synsema check`** also warns about `each r in rows` + `set r[…]` (it changes the loop's copy):
  it warns when the write is lost, even if the loop reads other fields to compute it
  (`set r["total"] to r["p"] * 2`, `when r.p > 1`), and stays quiet when `r` leaves the loop whole
  (passed, appended, printed) or a field the loop wrote is read afterwards.


## v0.6.28 — 2026-09-22

Identity and trust between agents: the token is the ceiling, passkeys, `did:key`, signed
documents, receipts and the Agent Card. One breaking change, on purpose, below.

**Breaking, on purpose.** Under `serve`, when the `auth with` task returns the map of
`captoken_verify`, the token's `caps` are now the request's **delegated ceiling**: a capability the
program declares but the token does not carry is **denied at use**, `llm` and `judge` included, and
the client receives `403 {"error": "insufficient permissions", "status": 403}` — a fixed body that
never names the capability. Before, the `caps` were advisory (`captoken_allows` only) and only the
`spend` caveat was enforced; a handler that ignored the token's `caps` kept working. It keeps
working only if the token carries what the handler uses. **What to write instead:** mint the token
with the capabilities the holder needs (list `llm`/`judge` if it must reason); or, if you never
wanted the ceiling, return the identity as text from `auth with` rather than the token map.

**Breaking, on purpose (tokens).** `captoken_mint`/`captoken_attenuate` refuse the process-local
capabilities `stdout`, `stdin`, `time`, `random` (`… is process-local: a token cannot delegate it`),
and `captoken_allows` errors when asked about them. A token carries transferable authority, not
another process's clock; the host ceiling governs those. To run a holder without clock or entropy,
use the new caveat `deterministic: true`.

### Added

- **The delegated ceiling, in three places.** A verified captoken is the ceiling of a `serve`
  request (above), of a child program (`run_program(src, {"ceiling": verified})`, which also takes a
  plain `{capability: scopes}` map) and of a block: **`sandbox under <caps>`**, a least-privilege block
  that runs its body under `caps ∩ the current ceiling` — a literal map or the map of
  `captoken_verify` — with `require` inside still a no-op. Nested blocks stack; every level must cover
  the use. Process-local capabilities are never delegable; the host ceiling always wins.
- **Two caveats.** `deterministic: true` (the holder runs without `time` and `random`, like
  `--deterministic`; once set, no attenuation turns it off) and `llm_tokens: N` (a delegated LLM
  budget, metered on the token's `id` beside `SYNSEMA_LLM_BUDGET_PER_IDENTITY`; can only decrease).
  `captoken_verify` reports both in `caveats`.
- **The subject travels with the ceiling.** An agent spawned from a handler, a `parallel_map` worker
  and a `run_program` child run on behalf of the same identity, under the same delegated ceiling,
  spend limits and LLM budget (the child gets them through an internal variable set after the
  program's `env`: a program cannot choose its child's identity); the `errors with` page runs under
  the request's subject too; a cron tick runs as `cron:<job>`; `synsema run` runs as the operator
  (`SYNSEMA_IDENTITY`, optional, from the environ or `.env`, in `.env.example`).
- **A verified token's ceiling never opens.** Process-local names in a token's `caps` are ignored
  (a token minted by an earlier engine keeps being a ceiling); an unknown name closes it (empty
  ceiling, one stderr warning). The `sign`, `spend`, `wallet`, `secret`/`env`, `reveal` and
  `render` gates keep the delegated cause: denied by the caller's token → the fixed 403, never a
  500 that says `add require …` about a program that already declares it.
- **Denials say they are permissions.** `Capability not granted: X` now ends with `— this is a
  permission, not a bug: add `require X` to the program's preamble (or to the importing file, when
  this code runs in a module)`; a denial by a token says `denied by the delegated ceiling of token
  <id>` (the caller must present a token that carries it), a `sandbox under` one says so too. The
  audit gains the reasons `above delegated ceiling (token <id>)` and `above sandbox ceiling (sandbox
  under)`, with `source: token`/`sandbox` on rejected grants.
- **`synsema check` warns about undeclared capabilities**, including what an imported module's tasks
  need and the importing file does not declare, with the exact `require` to add (reusing `synsema
  code caps`). Warning, not error.
- **Handler mode (wasm)** applies the same delegated ceiling and 403, so the native ↔ wasm audit
  parity holds.
- **Passkeys (WebAuthn), pure.** `webauthn_register(credential, opts)` verifies the registration
  ceremony and returns the credential's public key as a JWK (`id`, `public_key`, `alg`,
  `sign_count`, `fmt`, `aaguid`, flags, `transports`); `webauthn_verify(assertion, credential,
  opts)` takes the **stored credential map** (what register returned, plus the `sign_count` and
  `user_handle` you keep) and verifies an authentication (challenge, origin — one or a list —,
  `rp_id`, flags, signature over `authenticatorData ‖ sha256(clientDataJSON)`, the counter, and
  that the assertion's credential id IS the stored one — `rawId`/`userHandle` are not signed, so the
  returned `id`/`user_handle` are the stored ones, never what the assertion declares) and returns
  `{id, user_handle, alg, sign_count, …}` or `nothing` on any failure. ES256, RS256 and EdDSA; the
  registered key fixes the algorithm. Attestation is reported (`fmt`) and not verified, on
  purpose; the builtins keep no state.
- **`canonical_json` (RFC 8785 / JCS)**: deterministic bytes for hashing and signing; refuses what
  JCS cannot carry exactly (integers beyond 2^53, decimals over 15 significant digits, bytes,
  secrets) instead of approximating.
- **`did:key`**: `did_key_encode(public_key, alg?)` (ed25519, p256, x25519, secp256k1),
  `did_key_decode`, `did_key_document` (DID Document with Multikey verification methods and, for
  ed25519, the derived X25519 `keyAgreement`).
- **Signed documents (W3C Data Integrity)**: `document_sign(doc, key, opts?)` adds a
  `DataIntegrityProof` — `eddsa-jcs-2022` with an ed25519 secret (gate `sign("NAME")`, audited) or
  PKCS#8 PEM, `ecdsa-jcs-2019` with a P-256 scalar or PEM (`verificationMethod` defaults to the
  signing key's `did:key`); `document_verify(doc, public_key, opts?)`
  takes bytes, a `did:key`, a public-key PEM or a JWK and returns the proof's metadata or
  `nothing`.
- **Receipts**: `receipt(opts?)` — the receipt of the running unit of work as a Verifiable
  Credential **derived by the engine**: identity, captoken ids in force, the capability audit (the
  snapshot at issue time), this identity's spend totals per unit, `declassify` log, steps,
  `program_sha`, engine version and `declared_result_sha256` (of the value the program passes as
  `result`). `issuer` is always the `did:key` of the signing key and `validFrom`/`created` are the
  engine's clock (omitted without `time`): neither is an option, so a receipt cannot be antedated
  or issued in another's name. Opts: `sign`, `verification_method`, `cryptosuite`, `challenge`,
  `domain`, `result`. `receipt_verify(receipt, public_key, opts?)` also requires the issuer and the
  verification method to be the verifying key's did.
- **EdDSA JWTs**: `jwt_sign` gains `opts.alg = "EdDSA"` (Ed25519 PKCS#8 PEM or the 32-byte seed;
  with a `secret` it goes through `require sign("NAME")` + audit, like `ed25519_sign`);
  `jwt_verify`'s key map gains `{"did": "did:key:z…"}` (ed25519 → EdDSA, P-256 → ES256, resolved
  offline; a `kid` in the token must be `did:key:z…#z…`); `oidc_verify` accepts OKP/Ed25519 JWKs.
- **The Agent Card, derived and signed.** Every `serve` publishes
  `/.well-known/agent-card.json` (alias `/.well-known/agent.json`): the **A2A 1.0** card shape
  (`message AgentCard` of `a2a.proto` in proto-JSON: `securitySchemes` as `httpAuthSecurityScheme`
  / `apiKeySecurityScheme`, `securityRequirements`, no `url`) — skills from the route table,
  security schemes when auth is wired, and inside `capabilities.extensions` the Synsema extension
  with the server's `did:key`, base URL, OpenAPI, auth discovery, attestation (under `--attested`)
  and engine — with `supportedInterfaces: []` because a Synsema server does not speak the A2A
  transport and the card never claims it. Signed as a JWS (A2A §8.4, payload = JCS of the card, `kid` = the did's
  verification method) with **`SYNSEMA_IDENTITY_KEY`** (new knob: the server's ed25519 seed, 64
  hex, in `.env.example`) or, under `serve --attested`, with the attested P-256 key. Without a key
  the card is served unsigned and without `did`. Both paths are reserved (`synsema check` warns
  on a parametric route that would swallow them); `/llms.txt` lists the card.
- **ERC-8004 as an example module** (`examples/erc8004/`): the registration file (pointing at the
  Agent Card and the did), `document_hash`, and the calldata of the Identity, Reputation and
  Validation registries via `abi_encode` — a client of the registry, not a primitive of the engine.

## v0.6.27 — 2026-09-21

No breaking changes to programs: a program that loads on v0.6.26 loads unchanged, and the new
inference engine is opt-in. **One answer does change, on purpose:** a GGUF of the llama family
(llama 1/2, Mistral, Gemma) was being tokenised wrong and now is not, so with those weights the
local provider generates different — correct — text than it did before. See *Fixed*.

### Added

- **`synsema-infer`: local inference is now a crate of our own.** The GGUF loading, the tokenizer,
  the instance pool, the KV cache, generation and sampling moved out of `llm_local.rs` into
  `engine/crates/synsema-infer`, behind a facade with three doors — `generate` (the `local` LLM
  provider), `embed` and `decide` (the local judge). candle is one backend behind our own trait,
  not the shape of the code. Nothing in the language changed; the reason is in
  `specs/synsema-infer.md`.

- **`SYNSEMA_LLM_MODEL` takes a name, not only a path.** Three forms, and **none of them downloads
  anything**: a path to a `.gguf`, a `model:tag` already in the Ollama cache, or an `org/repo`
  already in the Hugging Face cache. A developer who already has Ollama runs their first `.syn`
  with a local model without fetching a byte. Ollama's store is content-addressed, so the sha256
  of the weights comes for free and is reported as provenance.

- **A backend written by us: `SYNSEMA_INFER_BACKEND=rust`.** No candle in the tree for that path.
  Two things it buys today: it runs **gemma3**, which candle does not ship quantized, and it picks
  its SIMD (AVX, AVX2+FMA, AVX-512, NEON) **at run time**, so the official binary uses the
  instructions of the machine it lands on — the `-C target-cpu=native` rebuild that the docs used
  to ask for is no longer the only way to get it. The default stays candle while both exist:
  switching engines changes the generated text, so it is part of what you declare to reproduce an
  output, next to the binary and the weights.

- **Architectures are declared in a file, not compiled in: `SYNSEMA_INFER_ARCHDEF`.** An
  architecture is a list of named steps over the tensors of a GGUF (`.archdef`) — the four we ship
  (llama, qwen2, qwen3, gemma3) are embedded in the binary, and a directory of your own adds new
  ones, or replaces ours, **without recompiling anything**. The format has no conditionals, no
  loops and no way to read a file, open a socket or call anything, so using someone else's
  definition does not execute their code: the worst it can do is not load, or give wrong numbers
  with your own weights. A file that fails to parse leaves **that** architecture unavailable with
  the error of the file — it never silently falls back to ours. `synsema llm status` says which
  definition is running and with what sha.

- **`judge` runs locally: `SYNSEMA_JUDGE_PROVIDER=laya`.** The third backend of the judge slot,
  next to `typesafe` and `mock`: a Laya (ModernBERT) checkpoint on disk answers `whether`, `choose`
  and `rate` **with no network, no secret and no cost per token**, so the offline degradation to
  confidence 0 stops being the common case. The same `judge` block runs unchanged; point
  `SYNSEMA_JUDGE_MODEL` at the checkpoint directory (or an `org/repo` already in the Hugging Face
  cache). The official binaries ship with it compiled in.

- **`synsema llm status` says what is actually on this machine.** The models already downloaded
  (name, origin and sha when the store gives it for free), the architectures this binary knows with
  their origin and sha, and the definitions from your directory that failed to load with their
  error. `--json` carries the same under an `inference` key, with the **full** sha — provenance is
  only useful if it can be compared, and comparing prose is not comparing.

- **`synsema judge status` shows only what applies to the backend.** `typesafe` gets key, model,
  base URL and timeout; `laya` gets the checkpoint; `mock` gets none of it. It used to print
  `TYPESAFE_API_KEY ✗ FALTA` and a base URL nobody was going to call, which is noise that makes
  people doubt a diagnosis that is right.

### Fixed

- **The SentencePiece tokenizer was wrong for the whole llama family.** GGUF files whose
  `tokenizer.ggml.model` is `llama` (llama 1 and 2, Mistral, Gemma) store **ranks**, not
  log-probabilities, and we were segmenting them with a Viterbi pass that maximises the sum of the
  scores. `The capital of France is` entered the model as eleven fragments instead of five words,
  and nothing failed — the model just answered badly. It is now the reference algorithm (merge the
  neighbouring pair with the best score, as llama.cpp does), written by us, with literal
  recognition of special tokens, byte fallback and `add_space_prefix` read from the metadata. The
  BPE family (qwen, llama 3) was never affected.

- **gemma3's MLP activation was `silu` and it is `gelu_pytorch_tanh`.** Copied from candle's
  `quantized_gemma3`, which hardcodes `silu` while its own non-quantized `gemma3` reads the config.
  With the tokenizer fixed, both produce readable text — the difference shows in the numbers (top
  logit 7.91 vs 27.02) and in the exact answer. The engine now generates, token for token, what
  Ollama generates for the same prompt.

- **Gemma had no chat template.** `<start_of_turn>` was not recognised, so a gemma GGUF fell back
  to plain mode and behaved like a base model.

- **`synsema llm status` listed the wrong architectures with candle active.** It printed the four
  `.archdef` definitions — gemma3 among them, and any file of yours — no matter which backend was
  selected, while candle runs neither. The runtime was always right; the report was the one
  dressing it up. It now lists the architectures of the backend that will actually run.

- **`SYNSEMA_INFER_BACKEND` and `SYNSEMA_INFER_ARCHDEF` are read from the `.env`.** They were
  resolved straight from the process environment while `synsema init` documents them in the LLM
  section of `.env.example`, which is the part that *is* auto-loaded. Setting them there did
  nothing, silently. They now follow the same `environ > .env > default` precedence as every other
  knob, and `synsema init` writes both.

## v0.6.26 — 2026-09-20

No breaking changes to programs. `synsema check` is stricter on `judge` blocks: see below.

### Added

- **`synsema check` fails on a `judge` block the API would reject.** With literal criteria: fewer than
  2 options or levels (the API accepts one and answers with confidence 1.0 — an empty answer dressed
  as certainty), more than 255 options or 10 levels, duplicate option or level ids; also an empty
  literal instruction and a literal `state` that is a number, a bool or `nothing`. These were a 400
  in production or a fake certainty; they are a check error now. Dynamic criteria keep the run-time
  check before the call.
- **`synsema check` warns**, never fails, on a `whether` phrased in the negative (P(not A) is not
  1 − P(A): measured 0.37 + 0.78), on an instruction that asks for arithmetic or counting over the
  state (the model recognises the shape of an answer, it does not calculate), on an empty literal
  state, and on the same `judge <variable>` appearing in more than one block (one call would do).
- **Backticked paths are verified against the state before the call.** `` `ticket.messages[0].text` ``
  is the vendor's idiom and it points at the exact element; a path the state does not have gets a
  warning with the fix — including the common trap of `judge ticket` with `` `ticket.x` `` in the
  question, where the model sees the value and not the variable name.
- **`synsema judge status [--json]`**: the resolved configuration of the judge slot with the source
  of each value — provider, key presence (never the value), model, base URL, timeout, budget, whether
  `decide` is served by the judge — and, when offline, one line that names what is missing. Exit 0
  live, 1 offline. Same `--env-file` / `--no-env-file` as the rest.
- **`SYNSEMA_JUDGE_DECIDE=1`: `decide` served by the judge.** Every `decide between […] given X`
  becomes one calibrated `choose`: one of your options byte-for-byte, no normalisation, no retry,
  cheaper and faster than a chat model, with no change to the program. Opt-in and off by default
  because it changes which model answers; it needs the `judge` capability (under `serve` a `decide`
  without `require judge` fails naming the knob); when the judge is unavailable the `decide` falls
  back to the LLM path. Verified live. Written by `synsema init` into `.env.example`.

## v0.6.25 — 2026-09-20

No breaking changes. Programs that load on v0.6.24 load unchanged.

### Added

- **`judge` — calibrated judgments as values.** A new expression asks a *System One* model (the first
  backend is TypeSafe's Jev) typed questions about one `state` and gets probabilities back, not text:
  `whether "…"` (the probability a statement is true), `choose "…" between {…} [or nothing]` (an
  option, its distribution and a confidence), `rate "…" across […]` (a position on ordered levels,
  the winning level, the distribution and a confidence). One block is one call; the block is the
  only form on purpose. The result is a flat map id → answer; every answer carries `kind` and
  `available`. `or nothing` adds an escape option so a state that fits no option yields `choice` =
  `nothing` instead of a confident wrong pick. Options and levels take a list or a map (id →
  description) under one rule. The instruction may be a map (read as structure).

- **`require judge`, a capability of its own.** Not granted by `llm` and not granting it: classifying
  and generating are different rights. Auto-granted in plain `run`/`conform`, required under `serve`
  and in secure mode, emptied in `sandbox`, denied under `--deterministic`, offline in a wasm guest.
  Under `--labels` the block is a declared public sink.

- **Honest degradation.** Without a provider, over `SYNSEMA_JUDGE_BUDGET`, or after a network
  failure, every answer is `available: false` with `confidence: 0` and its main value `nothing` —
  a confidence gate then routes to the human path by itself, and a direct comparison fails loud
  instead of branching in silence. An invented probability is never returned.

- **The parallel slot.** `TYPESAFE_API_KEY`, `SYNSEMA_JUDGE_PROVIDER` (`typesafe` | `mock`),
  `SYNSEMA_JUDGE_MODEL`, `SYNSEMA_JUDGE_BASE_URL`, `SYNSEMA_JUDGE_TIMEOUT`, `SYNSEMA_JUDGE_BUDGET`,
  all written by `synsema init` into `.env.example`. The key never enters the program; the host is
  fixed by the runtime. 429/529 are retried with backoff honouring `retry-after`; a 400/422 is a
  runtime error carrying the vendor's message. Builtins `judge_available()`, `judge_usage()`,
  `judge_model()`.

- **Checks before the call**: verbs and prepositions, `or nothing` only after `choose`, duplicate
  ids and an empty block at load time; 2–255 options, 2–10 levels, duplicate option or level ids,
  empty instruction and the type of the state at run time, before any token is spent.

### Not in this release

`synsema judge status`, static checking of option counts by `check`, `whether` with explicit yes/no
criteria, the non-calibrated `llm` fallback, the Cloudflare Workers AI wire variant, and serving
`decide` with the judge. The skill page `.synsema-skill/judge.md` lists what was measured live.

## v0.6.24 — 2026-09-20

### Breaking

- **A protected builtin cannot be bound to something callable.** The five builtins that decide a
  program's information-flow labels — `private`, `declassify`, `label_of`, `is_private` and
  `print` — can no longer be bound to a task, a lambda, or anything else callable, and a call to
  one of those names must resolve to the builtin itself. A program that redefined `declassify`
  could otherwise un-label its own sources in silence and still look clean in the audit listing
  that `synsema code check` produces.

  They remain **soft keywords**: binding one to a plain value is still legal, so `let private be 5`
  and `print(private)` keep working. What is refused is `task print(x) …`, `let declassify be
  (v, r) => v`, and `set label_of to …` with a callable on the right.

  The rule is active **with or without `--labels`**, because the same file can be loaded by a host
  that turns labels on — the guest adapters do exactly that.

- **`when <condition> then <statement>` is a load error.** The inline `when … then …` is an
  *expression*: in statement position its value is discarded, so a guard written after `then` —
  `raise`, `give`, `set` — never took effect and the program carried on with no warning. That
  turned security checks into silent no-ops. It is an error rather than a warning because there is
  no legitimate case: in statement position the value is never used.

  Write the block form:

  ```synsema
  when balance < amount
      raise "insufficient funds"
  ```

  The inline form still belongs anywhere a value is consumed:
  `let fee be when premium then 0 otherwise 25`.

- **Under `--labels`, `print`, `show` and `log` are refused inside a private branch.** Writing to
  stdout is an effect on something outside the program, so it follows the rule every other
  effectful builtin already follows: called under control flow that depended on private data, it
  is a `label_violation` *before* anything is written.

  Redacting the value was only half the job — the *number of lines* is not redactable, so one
  `print` per loop iteration over private data spells that data out by line count to whoever reads
  the output. Under a guest running inside an enclave, that reader is the operator, outside it.

  ```
  label_violation: print called under private control flow (pc = [app]); stdout is public and the
  NUMBER of lines is not redacted, so one line per iteration spells the private data out. Move it
  out of the private branch, or declassify(<the condition>, "<why it may be published>")
  ```

  Printing a private **value** from public control flow is unchanged and still redacts
  (`private(app)`). With labels off — the default for `synsema run` — nothing changes at all.

- **Anything that reads the clock needs `time`, and now says so.** Ten builtins read it: the
  **verifiers** `jwt_verify`, `totp_verify`, `captoken_verify`, `captoken_attenuate`,
  `http_signature_verify` and `oidc_verify`, the **emitters** `jwt_sign` (`iat`/`exp`),
  `captoken_mint` (`now`) and `http_signature` (`created`), and `totp`. When the `time` capability is not granted they used to fail with a diagnosis rather than
  an action. They now all say the same thing, and the action comes first:

  ```
  jwt_verify: this needs the clock. Add `require time` to the program, or pass opts.now
  explicitly (a unix timestamp in seconds) to verify against a clock you choose.
  ```

  What actually changed for a running program: nothing, unless it runs **under a ceiling without
  `time`** (`--deterministic`, or `--cap-set` without it) and verifies tokens without passing the
  clock. Plain `synsema run` and `--sandbox` grant `time`, so they are unaffected. The reason for
  the requirement is that an enclave has no trustworthy clock, and reading the host's silently
  turns the verdict into a host oracle.

  `attestation_verify` is deliberately *not* in that list: there `opts.now` is required always.

- **`steps()` carries what the run touched, and the host stops publishing it.** Under `--labels`
  the step counter comes out labelled with the union of everything private the run has touched,
  and `run --format json` / `run --attest` report `"steps": null` for such a run. The counter is
  one step per AST node — linear in what the program walked — so after a loop whose condition
  depended on a secret it *is* the secret with arithmetic on top: `(steps() - base - 24) / 4`
  reconstructed a private scalar exactly, with no `declassify` and no violation, and the attested
  document published it unasked. Before the first private value it is a plain public number, as
  before. To publish it afterwards: `declassify(steps(), "<why>")`.

- **A `stop` may not leave the task it is written in, under private control flow.** A `stop` with
  no enclosing loop in its own task breaks the *caller's* loop. When the branch that fires it is
  in the caller and the jump is indirect (`when secret == i` → `bail()`, with `task bail() /
  stop`), whether a call breaks a loop is an interprocedural question the engine cannot answer
  before the loop runs — and by the time the `stop` fires, the earlier iterations have already
  written public state in the clear. It is now refused:

  ```
  label_violation: 'stop' left the task 'bail' under private control flow (pc = [app]); a 'stop'
  that breaks the CALLER's loop cannot be checked until the loop has already run, so it is
  refused. Write the 'stop' in the loop it belongs to (give a value and decide there), or
  declassify(<the condition>, "<why it may be published>")
  ```

  With public control flow the same program is unchanged. Writing the `stop` inside its own loop —
  the ordinary form — was never affected.

- **A label violation stops the whole `synsema test --labels` run.** It used to become a `✗` on
  that block and the suite carried on. That is catching the enforcement verdict: with eight blocks
  each probing one bit, the column of ✓/✗ spells the byte. The run now ends with a single outcome
  naming the violation. An ordinary failure — a failed assertion, an error — is still a per-block
  verdict, as always.

- **`require <cap> "<scope>"` without parentheses now honours the scope.** The unparenthesised
  form parsed and then **threw the scope away**, so `require secret "API_KEY"` granted the
  capability *unscoped* — wider than what the program said, which is the worst kind of no-op. It
  now means the same as `require secret("API_KEY")`.

  What breaks: a program that declared one destination and used another. `require secret "A"` then
  `secret("B")`, or `require file "data/in.txt"` then `read_file("data/out.txt")`, used to run and
  now fail with the capability error naming the scope. That is the declaration finally being
  enforced, but it *is* a behaviour change, and it applies to **every** capability with a
  destination, not just `net`. If you meant the wide form, write it: `require secret`.

- **A statement may not carry leftover tokens.** The parser used to discard whatever followed a
  complete statement, in silence. `assert_eq 1, 2` (no parentheses) parsed as the bare identifier
  `assert_eq` and the rest vanished — a test that asserted nothing and always passed. Anything
  after the end of a statement is now a load error naming the two fixes (write the parentheses, or
  put the statements on separate lines).

- **`private(v, "p")` over a container COPIES it.** Marking a public list or map private gives a
  private copy, so a pre-existing public alias keeps seeing the public original and no longer
  observes writes made through the private handle. Sharing the `Rc` would have left a public alias
  into private data, which is the leak the labels exist to stop. The guest apps declassify
  explicitly where they used to rely on the alias.

- **The guest build has one more step.** Between `cargo build` and everything else, run
  `packages/guests/vela/tools/wasi-stub` over the module: it rewrites the built `.wasm` so it declares only the WASI
  imports Vela v0.3.0 admits. A module built without it is rejected by the Executor.

- **An error caused by private data is not catchable, and the output of a stopped run is
  withheld.** `try/recover` already refused to catch an error *born under a private branch*. It
  now also refuses one *caused by private data* — `xs[private_index]`, `1 / (secret - i)` — because
  whether the operation failed is exactly the bit the rule exists to hide. Until now the
  catchability test looked only at the control context while the message redaction looked at the
  context *union what the node touched*, and through that asymmetry a loop could leave a private
  scalar whole in a public counter and still exit 0. The same union now decides both.

  Two consequences. A label violation ends a `synsema test --labels` run even when it arrives as an
  ordinary error (eight blocks were eight bits). And the buffered output of a run the flow checker
  stopped is replaced by one fixed line: the *number* of lines printed before the stop depends on
  the private data. Effects the prefix already performed on sinks the engine does not own — a
  `write_file`, an HTTP call — did happen; that residue is documented, not fixed. (What it *does*
  own it now undoes: see the `state_*` rollback below.)

- **`steps()` is per request under `serve`.** The server reuses the interpreter between requests
  and the counter used to carry over, so a request could read the previous one's private work with
  no label on it. It now starts at zero for each request, which is also what "the cost of this
  request" should have meant.

- **The redaction text no longer names the value's own principals.** A redacted value printed as
  `private(<the principals of that value>)`, and that list varies with *which* value was selected,
  so the mechanism that exists to hide the data published it:

  ```synsema
  let xs be [private(10, "p0"), private(20, "p1")]
  print(xs[private(n, "app")])      -- used to answer private(app,p0) or private(app,p1)
  ```

  A table of 256 entries spelled a byte out in one line of output, with the run succeeding and
  `synsema code check` green. In a multi-tenant deployment the principal *is* the tenant, so
  printing a redacted value told the operator whose data it was. What comes out now is the set of
  principals the **program declares** — collected from the source before anything runs, so it is
  constant. A program with one principal (the guest, and any enclave) is unchanged:
  `private(app)`. A program with several loses the precision, which is exactly where the channel
  was. The same applies to the violation message, to the `declassify` trace and to the `from`
  field the wasm host reports.

- **An error the flow checker raised carries no location toward the host.** The text was already
  redacted; the line was not, so if a secret chooses which of N sites fails, `file:line:column` is
  log₂(N) bits — and under `serve` the caller makes one request per query. The HTTP response, the
  guest's report and the test runner's outcome now carry the message alone, and the runner no
  longer names the block it stopped at (the block name is written by whoever wrote the program).
  The local CLI still prints the location: there the host is whoever wrote the `private(…)`.

- **What a stopped request wrote to the shared `state_*` store is rolled back.** The prefix of a
  loop could `state_incr` with public control flow — legal at that moment — and then the request
  died on the secret's iteration, leaving the counter for another route to read as a public
  number. Every write a request makes is journalled while labels are on and undone if the flow
  checker stopped it. A request that ends any other way keeps its writes, as always.

- **`json_decode(text, default)` and `number(value, default)` — total variants.** Since an error
  caused by private data cannot be caught, a program had no way left to validate untrusted input:
  neither `try`/`recover` nor declaring the destination private. That is precisely an enclave's
  job, so parsing external input now has a form that returns a fallback instead of raising:

  ```synsema
  let d be json_decode(payload, nothing)
  when d == nothing
      set status to private("malformed payload", "app")
  ```

  With no error there is no bit. Without the second argument both still raise, and the message
  names the fallback.

- **A builtin's result now carries what its callback touched.** The label of a builtin's result
  was computed from its **arguments** only, so a callable that read a private value by *capture*
  was invisible — the predicate runs in Rust, so the language's private-context machinery never
  entered. The same count written by hand failed closed and the idiomatic one published the
  secret:

  ```synsema
  let n be 0                                 let n be count_where(range(0, 256),
  each v in range(0, 256)                        (v) => v < SECRET)
      when v < SECRET                        -- used to give 165, label_of(n) = []
          set n to n + 1
  -- label_violation
  ```

  That is not a side channel: it is **explicit flow** coming out unlabelled, in the builtins on
  the first page of the manual — `count_where`, `where`, `find_first`, `index_of`, `every`,
  `some`, `sort_by`, `group_by`. The fix is the mechanism the interpreter already uses to scope
  what a node "saw", applied to the boundary with Rust: the call is scoped, and whatever the
  builtin unwrapped joins the result's label. It covers those eight, and any builtin a host
  registers later. A result that touched nothing private stays public, as before.

- **Total variants for the rest of the untrusted input.** `aes_gcm_decrypt(key, nonce, ct, aad,
  default)` — the canonical operation of an enclave: a tampered tag is "reject this request", not
  "the process dies". Also `decimal`, `float`, `toml_parse`, `abi_decode`, `bech32_decode` and
  `rlp_decode`, all with the same shape: one extra argument, which is returned instead of raising.
  The fallback **never swallows a label error** — that would be a `try`/`recover` in disguise.

  Two details of the language, not of these builtins: the fallback is **evaluated eagerly**, so an
  effect inside it fires on the happy path too; and the result's label does not reveal whether the
  operation failed (valid and invalid input give the same thing at the sink).

### Added

- **Information-flow labels** (`--labels`, and always on under `serve --attested`). `private(v,
  "principal")` marks a value as belonging to a principal; every operation, field read, index and
  builtin propagates the union; branching on a private condition labels what the branch assigns
  and returns; a private value printed from public control flow shows as `private(app)`. Public
  sinks — stdout, the HTTP response, streams, files, network, memory, processes — refuse a
  labelled value, and refuse the call itself under a private branch, unless the value
  goes out through `declassify(value, "reason")`, which is recorded for review and listed by
  `synsema code check --json`. `declassify(v, "reason", ["bank"])` narrows to a subset instead of
  publishing outright.

- **`attest` capability** and **`serve --attested`**. `attest(opts)` asks the platform for an
  attestation document binding `report_data` to the code that is running (AWS Nitro, TDX/SEV-SNP
  through configfs-tsm, dstack, plus a `mock` driver that is never auto-detected). Deny-by-default
  like every other capability, absent from `--sandbox` and from the deterministic ceiling.
  `serve --attested` generates a P-256 identity before the program's first statement, binds it and
  a hash of the program and its configuration into the document, serves TLS with that key and
  publishes `GET /.well-known/attestation`. `synsema run --attest` is the job form: it runs under
  `--deterministic` and closes with one JSON line tying program, input and output together.

- **`attestation_verify(document, opts)`** — the client side: COSE signature, certificate chain to
  the platform's pinned root, measurement expectations and an explicit `now`. `nitro` and `mock`
  verify today; other formats answer with an honest error rather than a guess.

- **`groth16_verify(vk, proof, public_inputs)`** — Groth16 over BN254, taking snarkjs JSON as it
  comes. Pure, no capability, no network: an enclave can verify a proof carried in its own payload
  instead of trusting an oracle.

- **Deterministic noise** for published aggregates (`laplace_noise`, `gaussian_noise`): same seed,
  same noise, so repeating a query does not average the noise away.

- **`invariant`** conditions evaluated per state transition, with the guest adapters running them
  on every entry point.

- **Vela guest: `state_pad` and the `_vela.n` counter.** Under the output policy `reject:
  "private"` the state that goes on-chain is now padded to a bucket (256 bytes by default,
  `state_pad: N` to tune it, `state_pad: 0` to turn it off with a warning) and carries a counter
  that goes up on every transition. Without them, a rejected request returned the previous state
  byte for byte while an accepted one had grown, so its **size** — and the fact that the state root
  had not moved — was one bit per request.

## v0.6.23 and earlier

Not covered here — this file starts with the release that follows it (`v0.6.23` is the last tag as
of this writing). For older versions see the release notes attached to each tag.
