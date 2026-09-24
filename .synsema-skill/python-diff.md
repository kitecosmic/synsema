# Python → Synsema — the translation table

You (the model) already know Python. This file maps the Python reflex to the Synsema
form and flags exactly where the semantics diverge. **Read this before writing your
first `.syn` program**; it is faster than learning from scratch and prevents the
classic failure mode: writing Python with Synsema keywords.

**The one rule that prevents most hallucinations: if you did not see it in this skill,
it does not exist.** There is no `import`, no Python stdlib, no classes, no
comprehensions, no decorators, no `with`, no generators, no method-call syntax on
values (`xs.append(x)` → builtins are plain tasks: `append(xs, x)`). Every claim below
is verified against the engine by `tests/python_diff.test.syn` (semantics) and
`synsema check` probes (parse errors). Old names still work as **deprecated aliases** until
v1.0 (`replace_text`, `find_all`, `capture`, `eth_*`…, `synsema check` warns) — the table uses
the current names; the full old → new list is in [builtins.md](builtins.md) § Renamed in v0.6.29.

## Syntax reflexes

| In Python | In Synsema | ⚠️ Divergence |
|---|---|---|
| `x = 5` … `x = 6` | `let x be 5` … `set x to 6` | `x = 5` → an error that says it: ``declare with `let x be …`, change it with `set x to …` `` (v0.6.29+). `=` exists ONLY in default params / named args: `task f(x, y = 1)`, `f(x, y = 2)` |
| `# comment` | `-- comment` | `#` → `Unexpected character: '#'` |
| `if / elif / else:` | `when / otherwise when / otherwise` (no colon) | a trailing `:` → parse error `Synsema blocks have no colon`; `elif` is not a word |
| `x if c else y` | `when c then x otherwise y` | inline expression form, usable in `let`/args |
| `for x in xs:` | `each x in xs` | `for` → parse error |
| `d["k"] = v` (add or overwrite a key) | `set m["k"] to v` | In place on an existing map: `{a: 1}` → `{a: 1, b: 2}` (v0.6.19). `m["k"]` reads it, `contains(m, "k")` tests it |
| `for k in a_dict:` / `for k, v in d.items():` | `each k in m` / `each e in items(m)` … `e.key` / `e.value` | v0.6.29+: `each` walks a map's **keys** in insertion order (before: `Cannot iterate over map`); also text (characters) and bytes (ints). `{ each }` in a `render()` template does the same |
| `for i, x in enumerate(xs):` | `each e in enumerate(xs)` … `e.index` / `e.item` | `enumerate(list)` → `[{index, item}, …]` (engine > v0.5.9; before it: `each i in range(length(xs))` … `xs[i]`) |
| `while c:` | `while c` | same keyword, no colon; no iteration cap (v0.6.29+ — before, 1,000,000) |
| `def f(x): return v` | `task f(x)` … `give v` | load-time errors that name the Synsema word (v0.6.29+): ``return` is not a Synsema statement: `give <value>` returns from a task``; the same kind of hint for `def`/`function`/`fn`/`func`/`for`/`if`/`elif`/`else`/`import`/`from`/`class`/`except`/`catch`/`var`/`const`/`pass`/`break`/`continue`/`throw` |
| `lambda x: x + 1` | `(x) => x + 1` | — |
| `None` / `True` / `False` | `nothing` / `true` / `false` | capitalized forms parse, then fail naming the Synsema form (`Undefined variable: 'None'` — in Synsema: `nothing`); same hints for `len`/`str`/`null`/`filter`/`map`/`sorted`/`zip`/`isinstance`/`input`/`open`/`dict`/`list`/`self`/… (v0.6.29+) |
| `x is None` | `x == nothing` | no `is` operator for identity (`is` belongs to `match`) |
| `f"n={n}"` | `` `n={n}` `` (backtick string) | `f"..."` → parse error. **Quoted `"..."` strings do NOT interpolate** (`"{n}"` stays literal) and a literal newline inside them is `Unterminated string` — backticks do both |
| `"""multi-line"""` | `` `multi-line` `` | backticks allow real newlines + `{expr}` |
| `[f(x) for x in xs if p(x)]` | `apply(f, where(xs, p))` | comprehension syntax → parse error |
| `xs[-1]`, `s[0]` | `xs[-1]`, `s[0]` | same (v0.6.29+): negative indexes count from the end on lists/text/bytes; text is indexable by character. An index must be an integer (`xs[1.7]` → error) |
| `xs[1:3]`, `xs[-2:]` | `slice(xs, 1, 3)`, `slice(xs, -2, length(xs))` | `[1:3]` → parse error; `slice` takes Python-style negatives, works on lists/text/bytes |
| `x in xs` / `x not in xs` | `x in xs` / `x not in xs` | same (v0.6.29+): list membership, map **key**, substring, bytes subsequence. Text needs text: `1 in "a1"` is an error. `contains(xs, x)` still works |
| `a < x <= b` | `a < x <= b` | chained comparisons like Python (v0.6.29+), each operand evaluated once |
| `try/except E as e:` | `try` … `recover err` | `except` → parse error. `err` is the message TEXT (no exception types/hierarchy). **`recover` SWALLOWS by default** — re-propagate with `raise(err)` |
| `raise ValueError("x")` | `raise("x")` (or statement `raise "x"`) | one error kind only; on engine ≤ v0.5.1 use the parens form |
| `import json`, `import requests` | nothing to import — builtins are global | `import x` fails at load with a hint naming the Synsema form (v0.6.29+; older engines: `Undefined variable: 'import'`). JSON/HTTP/etc. are builtins gated by capabilities (below) |
| `from mymodule import f` | `use "./mymodule.syn" as m` … `m.f()` | only local `.syn` modules; exports need `export` ([modules.md](modules.md)) |
| `class Person:` | `type Person` (fields) + plain tasks | no methods/inheritance/`self`; construct `Person("Alice", 30)`, access `p.name` / `name of p` / `p["name"]`. A method call like `xs.append(2)` → error with the translation (`Synsema has no methods: set xs to append(xs, item)`) |
| `match/case` | `match` … `is pattern` | arms use `is`, default is `otherwise` ([syntax.md](syntax.md)) |

Also: the LLM words **`reason` / `decide` / `analyze` / `generate`** (like every keyword —
`to`, `type`, `match`…) are reserved as **names you bind** (variables, parameters, tasks) —
`let reason be 1` → `'reason' is a reserved word in Synsema`. After a `.` any word is fine
(v0.6.29+: `tx.to`, `ev.type`, `mod.decide(…)`). Name things `resolve`, `why`, etc.

## Builtin equivalents (methods are plain tasks)

| In Python | In Synsema |
|---|---|
| `len(x)` | `length(x)` (text/list/map/bytes/array) |
| `str(x)` / `int(s)` / `float(s)` | `text(x)` / `int(s)` (exact integer, v0.6.29+: `"-42"`, `"1_000"`, `"0x1f"`, a whole float) / `number(s)` (float). ⚠️ `int("ff", 16)` is NOT a base: the 2nd argument is a default → `16`; write `int("0xff")`. `int(1.5)` errors — `floor`/`round`/`trunc` on purpose |
| `hex(n)` / `b.hex()` | `hex(n)` → `"0x1f18"`, `hex(b)` → `"0x00ff"` (v0.6.29+, `0x`-prefixed) |
| `isinstance(x, int)` / `str` / `list` / `dict` | `is_integer(x)` / `is_text(x)` / `is_list(x)` / `is_map(x)` (v0.6.29+), or `type_of(x)` |
| `xs.append(x)` (mutates) | `append(xs, x)` → **returns a NEW list**; reassign: `set xs to append(xs, x)` — O(1) amortized (v0.6.29+), fine in a loop |
| `s.upper()` / `s.lower()` / `s.strip()` | `upper(s)` / `lower(s)` / `trim(s)` |
| `s.split(",")` / `",".join(xs)` | `split(s, ",")` / `join(xs, ",")` |
| `s.startswith(p)` / `s.replace(a, b)` / `s.find(p)` | `starts_with(s, p)` / `replace(s, a, b)` / `index_of(s, p)` (→ `nothing` when absent) |
| `sorted(xs)` / `sorted(xs, key=f, reverse=True)` | `sort(xs)` / `sort_by(xs, f, desc = true)` (v0.6.29+; stable, total order: `nothing`/NaN last, mixed number + text → error) |
| `sum(xs)` / `min(xs)` / `max(xs)` | `sum(xs)` / `min(xs)` / `max(xs)` (also variadic `max(a, b, c)`; texts too; `nothing` values skipped) |
| `a // b` | `a // b` (v0.6.29+; exact for big ints, floors like Python) |
| `map(f, xs)` / `filter(p, xs)` | `apply(f, xs)` / `where(xs, p)` — both accept either argument order |
| `functools.reduce(f, xs, init)` | `reduce(xs, f, init)` |
| `xs.index(v)` (raises) | `index_of(xs, v)` → **`nothing`** when absent (not -1, no error); `v in xs` is the operator for membership |
| `d.get(k, default)` / `d.pop(k)` / `{**a, **b}` | `get(m, k, default)` / `remove(m, k)` (new map) / `merge(a, b)` (new map, right wins) (v0.6.29+) |
| `d.keys()` / `d.values()` / `d.items()` | `keys(m)` / `values(m)` / `items(m)` → `[{key, value}, …]` (v0.6.29+) |
| `json.dumps(x)` / `json.loads(s)` | `json_encode(x)` / `json_decode(s)` (pure, no import) |
| `range(n)` | `range(n)` → a real list (also `range(a, b, step)`) |
| `print(...)` | `print(...)` (written immediately under `run`, v0.6.29+; text inside lists/maps prints quoted: `["1", 1]`) |
| `re.fullmatch` / `re.findall` / `re.search(...).groups()` / `re.sub` | `matches(s, pat)` (FULL match) / `regex_find_all(s, pat)` / `regex_capture(s, pat)` (always a list, or `nothing`) / `regex_replace(s, pat, rep)` ([builtins.md](builtins.md)) |
| `hmac.new(k, m, sha256).digest()` | `hmac(m, k)` → bytes (v0.6.29+) |
| `open(p).read()` / `requests.get(url)` | `read_file(p)` + `require file(...)` / `fetch(url)` + `require net(host)` |
| `requests.post(url, json=d)` / `r.json()` / `r.content` | `http_post(url, d)` (a map → JSON + Content-Type, v0.6.20+) / `json of r` (`nothing` if not JSON) / `http_bytes(...)` → `bytes of r` |
| `xs[::-1]` / `list(s)` | `reverse(xs)` (also text) / `split(s, "")` (v0.6.20+) |
| `os.getcwd()` / `os.path.expanduser("~/x")` | `cwd()` + `require file.read(".")` / `"~/x"` works as-is in paths and scopes (v0.6.20+) |
| `os.remove(p)` / `shutil.rmtree(p)` | `delete_file(p)` / `delete_dir(p, {"recursive": true})` + `file.write` on every path (v0.6.20+) |
| `zipfile` / `tarfile` | `zip_create`/`zip_extract` / `tar_create`/`tar_extract` (zip-slip rejected, real-bytes ceiling; v0.6.20+, native) |
| `tomllib.loads(s)` / `xml.etree` / `xmltodict.parse` | `toml_parse(s)` (dates → ISO text) / `xml_parse(s)` (xmltodict shape) (v0.6.20+) |
| `cryptography` ECDH/HKDF/AES-GCM | `ecdh_keypair`/`ecdh_shared_secret`/`hkdf_sha256`/`aes_gcm_encrypt`/`aes_gcm_decrypt` (secrets stay `secret`; v0.6.20+) |

## Data analysis — pandas / numpy / polars → Synsema (v0.6.29+)

A table is a **list of maps** (no DataFrame, no index): every operation takes rows and returns
rows. Full pipeline: [dataviz.md](dataviz.md) § Data analysis; contracts: [builtins.md](builtins.md) § Tables.

| In Python | In Synsema | ⚠️ Divergence |
|---|---|---|
| `pd.read_csv(p, dtype={"id": str, "qty": int}, parse_dates=["day"])` | `csv_parse(read_file(p), {"types": {"qty": "int", "day": "date"}})` | untyped columns stay text (never guessed); an empty cell is `nothing` (pandas: NaN) |
| `pd.read_parquet(p)` / `df.to_parquet(p)` | `parquet_read(read_file_bytes(p))` / `write_file(p, parquet_write(rows))` | flat columns, one type per column; not in the wasm build |
| `pd.read_json(p, lines=True)` / `df.to_json(orient="records", lines=True)` | `jsonl_decode(read_file(p))` / `jsonl_encode(rows)` | `jsonl_decode(text, default)` is the no-raise form |
| `df.groupby("r").agg(total=("m", "sum"), n=("m", "size"))` | `summarize(rows, "r", {"total": sum_of("m"), "n": count()})` | groups in first-appearance order (pandas sorts by key); also `mean_of`/`min_of`/`max_of`/`median_of`/`quantile_of(col, q)`/`first_of`/`n_unique_of`, or any `(group) => …` |
| `for k, g in df.groupby("r"):` | `each g in group_by(rows, "r")` … `g.key` / `g.items` | `group_by` returns `[{key, items}]`, NOT a dict |
| `df.merge(o, on="id", how="left")` | `join(rows, o, "id", "left")` | `how` = `"inner"`/`"left"`/`"outer"`; clashing columns get `_right` (pandas: `_x`/`_y`); `join(xs, sep)` with 2 args is still the text join |
| `df.pivot_table(index="d", columns="p", values="v", aggfunc="sum")` | `pivot(rows, "d", "p", "v", sum_of("v"))` | without `agg`, two rows in one cell → error (never a silent first) |
| `df["c"].value_counts()` | `count_by(rows, "c")` → `[{key, count}]` | also `count_by(values)` on a plain list |
| `df.dropna()` / `df.dropna(subset=["m"])` / `df.fillna(0)` / `df.fillna({"m": 0})` | `drop_missing(rows)` / `drop_missing(rows, "m")` / `fill_missing(rows, 0)` / `fill_missing(rows, {"m": 0})` | missing = `nothing`; NaN is separate: `fill_nan(xs, 0)` |
| `df.sort_values("t", ascending=False)` | `sort_by(rows, (r) => r.t, desc = true)` | stable; `nothing`/NaN last |
| `df["c"]` / `df[df.x > 2]` | `collect(rows, "c")` / `where(rows, (r) => r.x > 2)` | — |
| `df.std()` / `statistics.stdev(xs)` | `std(xs)` | same answer: **sample** (`ddof = 1`) |
| `np.std(xs)` / `np.var(xs)` | `std(xs, ddof = 0)` / `var(xs, ddof = 0)` | numpy defaults to population; Synsema to sample |
| `np.nanmean(xs)` / `df.mean()` (skips NaN) | `mean(xs)` skips **`nothing`** | NaN propagates in Synsema — `fill_nan` or `where(xs, is_finite)` first |
| `np.percentile(xs, 90)` / `np.quantile(xs, 0.9)` | `percentile(xs, 90)` / `quantile(xs, 0.9)` | same interpolation (linear) |
| `np.dot(A, B)` (matrices) / `A @ B` | `matmul(A, B)` | `dot` is 1-D vectors only |
| `np.eye(n)` | `identity(n)` | `eye` is a deprecated alias |
| `np.concatenate` / `np.stack` / `np.argmax` / `np.cumsum` / `np.diff` | `concat([a, b], axis = 0)` / `stack([a, b])` / `argmax(x, axis = k)` / `cumsum(x)` / `diff(x)` | `axis` is named |
| `np.corrcoef(x, y)[0, 1]` / `np.cov(x, y)[0, 1]` / `np.linalg.lstsq(A, b)` / `np.polyfit(x, y, 1)` | `corr(x, y)` / `cov(x, y)` / `lstsq(A, b)` / `polyfit(x, y, 1)` + `polyval(c, x)` | `cov` is sample by default, like numpy's `cov` |
| `len(arr)` / `arr.size` / `arr[-1]` / `arr[1:3]` | `length(a)` / `size(a)` / `a[-1]` / `slice(a, 1, 3)` | — |
| `rng = np.random.default_rng(42)`; `rng.random()`, `rng.integers(1, 7)`, `rng.normal(0, 1)`, `rng.permutation(xs)`, `rng.choice(xs, 5, replace=False)`, `rng.choice(xs)` | `let g be rng(42)`; `g()`, `random_int(g, 1, 6)`, `random_normal(g, mean = 0, std = 1)`, `shuffle(g, xs)`, `sample(g, xs, 5)`, `choice(g, xs)` | `random_int` is **inclusive** on both ends; the sequence differs from numpy's (same seed ≠ same numbers across languages), but is identical across Synsema platforms/versions; pure, no capability |
| `random.random()` | `random()` + `require random` | the unseeded form reads OS entropy |
| `pd.to_datetime("2026-01-03")` / `datetime.date(2026, 1, 3)` | `datetime("2026-01-03")` / `date(2026, 1, 3)` | three types: `date`, `datetime` (instant + IANA zone), `duration` |
| `datetime.strptime(s, "%d/%m/%Y")` / `dt.strftime(f)` | `parse_date(s, "%d/%m/%Y")` (or `parse_datetime`) / `format_time(dt, f)` | pure — no `require time` |
| `timedelta(hours=1, minutes=30)` / `td.total_seconds()` | `duration(hours = 1, minutes = 30)` / `in_units(d, "seconds")` | a date moves by whole days only |
| `dt.astimezone(ZoneInfo("UTC"))` / `ZoneInfo("Europe/Madrid")` | `to_timezone(dt, "UTC")` / the zone name as text | a nonexistent local time (DST gap) is an error, not shifted |
| `df["d"].dt.to_period("M")` / `pd.date_range(a, b, freq="MS")` / `+ pd.DateOffset(months=1)` | `truncate(d, "month")` / `date_range(a, b, "month")` (inclusive) / `add_months(d, 1)` | — |
| `dt.timestamp()` / `datetime.fromtimestamp(s, tz)` | `timestamp(dt)` / `datetime(s, tz)` | — |

## Semantic traps — looks like Python, behaves differently

| It looks like | What actually happens (verified) |
|---|---|
| `a and b` short-circuits and returns the operand (`x or "default"`) | Short-circuits too (v0.6.10+) but **always returns a bool** — `x or "default"` is `true`/`false`, never the default. Use `when x == nothing` … `set x to "default"` |
| `xs.append` mutates in place | `append` (and friends) return new values; the original is untouched. Reassign with `set` |
| Two names for one list/dict see each other's changes | **Value semantics** (v0.6.29+): `let ys be xs` + `set ys[0] to 9` leaves `xs` alone; a task that `set`s inside a map it received does NOT change the caller's — `give` it back. Shared state is explicit (blackboard, memory, bus) |
| `d["missing"]` → KeyError you catch by type | `Map has no key 'missing'` — catchable only as `try/recover` (message text). For an optional key use `get(m, "missing", default)` |
| `"a" + 1` → TypeError | **It concatenates**: `"a" + 1` → `"a1"` (text + number/bool coerces). But text + `nothing`/list/map/bytes IS an error (v0.6.29+: `Cannot add text and nothing — convert it on purpose`), and so are `"ab" * 2` and `1 + true` — no repetition, no bool arithmetic |
| `except:` keeps the program dying | `recover` **swallows the error entirely** (task ends normally). To fail upward, `raise(err)` inside `recover` |

More traps (databases, serve, blockchain, secrets, charts): [pitfalls.md](pitfalls.md).

## Where Python intuition is SAFE (verified — trust it)

- Division always returns float (`10 / 3` → `3.33…`), like Python 3. Floor-div is `//` (v0.6.29+), exact for integers of any size — `floor(a / b)` goes through a float and loses big integers.
- Int/float comparison is exact (`2**53 + 1 == 9007199254740992.0` → false), `json_decode` keeps big integers exact, `0x…`/`0b…` literals exist, `int()` exists (v0.6.29+).
- Iterating a dict yields its keys (`each k in m`, v0.6.29+).
- Calling with a missing or an extra argument is an error (v0.6.29+: `task 'f' is missing argument 'b'` — before, the missing one was silently `nothing`).
- `-2 ** 2` → `-4`, `2 ** 3 ** 2` → `512`, and `1e18` is a **float** — exactly like Python (v0.6.29+). Write wei as `10**18`.
- `fmt` fails on a `{name}` with no value, like `str.format` (v0.6.29+); `{{`/`}}` are literal braces.
- `round()` is banker's rounding, same as Python: `round(2.5)` → `2`, `round(3.5)` → `4`.
- Truthiness: `nothing`/`false`/`0`/`""`/`[]`/`{}` are falsy, everything else truthy.
- `[1] + [2]` → `[1, 2]` (list concatenation), `slice` accepts negative indices.
- Map literals `{"k": v}` and list literals look and nest like dicts/lists.
- Indentation defines blocks (4 spaces), comments to end of line, `and`/`or`/`not` are words.

## No Python equivalent — read the topic file before using

- **Capabilities**: I/O is deny-by-default; declare `require net("host")` / `file(...)` /
  `db(...)` / `serve(PORT)` / `llm` at the top or calls fail → [capabilities.md](capabilities.md)
- **LLM ops as keywords**: `decide between [...] given x`, `generate`, `analyze`, `reason` → [llm.md](llm.md)
- **Agents/concurrency**: `agent` / `spawn` / `share` / `observe` / `signal` / `wait_for`,
  `parallel_map` → [agents.md](agents.md), [concurrency.md](concurrency.md)
- **HTTP server as syntax**: `serve on 8080` + `route "GET /x"` blocks → [serve.md](serve.md)
- **Agentic app plumbing without asyncio**: `subprocess.Popen` + reading pipes → `proc_spawn`/`proc_recv`;
  `pexpect` / `pty.spawn` (interactive prompts, TUIs) → `proc_spawn(cmd, args, {"pty": true})` + `strip_ansi` (v0.6.8+);
  `watchdog` / `inotify` observers → `watch(path)` + `watch_recv`/`select` (v0.6.9+); `psutil` tree-kill / `os.killpg` → `proc_close(h)` already kills the tree
  (events per line, `exec`-gated); `websockets.serve` → a `route "GET /ws"` + `socket` block;
  `asyncio.wait`/`selectors` → one blocking `select([...])` over sockets + processes + the bus;
  `signal.signal(SIGINT, …)` → nothing to write, `serve` drains on Ctrl-C by itself → [serve.md](serve.md),
  [processes.md](processes.md), [agents.md](agents.md) § Event bus
- **Secrets**: `secret("KEY")` values that never print/serialize → [secrets.md](secrets.md)
- **Human-in-the-loop**: `approve` / `confirm` / `ask` / `show` → [human.md](human.md)
- **Tests in-file**: `test "name"` blocks + `assert_eq`, run by `synsema test` → [testing.md](testing.md)
