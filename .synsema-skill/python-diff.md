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
`synsema check` probes (parse errors).

## Syntax reflexes

| In Python | In Synsema | ⚠️ Divergence |
|---|---|---|
| `x = 5` … `x = 6` | `let x be 5` … `set x to 6` | `x = 5` → parse error `Unexpected token: ASSIGN ('=')`. `=` exists ONLY in default params / named args: `task f(x, y = 1)`, `f(x, y = 2)` |
| `# comment` | `-- comment` | `#` → `Unexpected character: '#'` |
| `if / elif / else:` | `when / otherwise when / otherwise` (no colon) | a trailing `:` → parse error; `elif` is not a word |
| `x if c else y` | `when c then x otherwise y` | inline expression form, usable in `let`/args |
| `for x in xs:` | `each x in xs` | `for` → parse error |
| `for k in a_dict:` | `each k in keys(m)` | **`each` cannot iterate a map**: `Cannot iterate over map`. Go through `keys(m)`/`values(m)` |
| `for i, x in enumerate(xs):` | `each e in enumerate(xs)` … `e.index` / `e.item` | `enumerate(list)` → `[{index, item}, …]` (engine > v0.5.9; before it: `each i in range(length(xs))` … `xs[i]`) |
| `while c:` | `while c` | same keyword, no colon; runaway loops hit `Loop exceeded maximum iterations` |
| `def f(x): return v` | `task f(x)` … `give v` | `def` → parse error. `return` PARSES as a plain name, then fails at runtime: `Undefined variable: 'return'` — the word is `give` |
| `lambda x: x + 1` | `(x) => x + 1` | — |
| `None` / `True` / `False` | `nothing` / `true` / `false` | capitalized forms parse, then fail: `Undefined variable: 'None'` (same for `True`/`False`) |
| `x is None` | `x == nothing` | no `is` operator for identity (`is` belongs to `match`) |
| `f"n={n}"` | `` `n={n}` `` (backtick string) | `f"..."` → parse error. **Quoted `"..."` strings do NOT interpolate** (`"{n}"` stays literal) and a literal newline inside them is `Unterminated string` — backticks do both |
| `"""multi-line"""` | `` `multi-line` `` | backticks allow real newlines + `{expr}` |
| `[f(x) for x in xs if p(x)]` | `apply(f, where(xs, p))` | comprehension syntax → parse error |
| `xs[1:3]`, `xs[-2:]` | `slice(xs, 1, 3)`, `slice(xs, -2, length(xs))` | `[1:3]` → parse error; `slice` takes Python-style negatives, works on lists/text/bytes |
| `x in xs` (operator) | `contains(xs, x)` | `in` is only valid inside `each`. On maps `contains` checks KEYS |
| `try/except E as e:` | `try` … `recover err` | `except` → parse error. `err` is the message TEXT (no exception types/hierarchy). **`recover` SWALLOWS by default** — re-propagate with `raise(err)` |
| `raise ValueError("x")` | `raise("x")` (or statement `raise "x"`) | one error kind only; on engine ≤ v0.5.1 use the parens form |
| `import json`, `import requests` | nothing to import — builtins are global | `import x` parses as a name and fails: `Undefined variable: 'import'`. JSON/HTTP/etc. are builtins gated by capabilities (below) |
| `from mymodule import f` | `use "./mymodule.syn" as m` … `m.f()` | only local `.syn` modules; exports need `export` ([modules.md](modules.md)) |
| `class Person:` | `type Person` (fields) + plain tasks | no methods/inheritance/`self`; construct `Person("Alice", 30)`, access `p.name` / `name of p` / `p["name"]` |
| `match/case` | `match` … `is pattern` | arms use `is`, default is `otherwise` ([syntax.md](syntax.md)) |

Also: the LLM words **`reason` / `decide` / `analyze` / `generate` are reserved
everywhere** (even as member/param names) — `let reason be 1` → `'reason' is a reserved
word in Synsema`. Name things `resolve`, `why`, etc.

## Builtin equivalents (methods are plain tasks)

| In Python | In Synsema |
|---|---|
| `len(x)` | `length(x)` (text/list/map/bytes/array) |
| `str(x)` / `int(s)` / `float(s)` | `text(x)` / `number(s)` (always float; `floor()` to get an integer) |
| `xs.append(x)` (mutates) | `append(xs, x)` → **returns a NEW list**; reassign: `set xs to append(xs, x)` |
| `s.upper()` / `s.lower()` / `s.strip()` | `upper(s)` / `lower(s)` / `trim(s)` |
| `s.split(",")` / `",".join(xs)` | `split(s, ",")` / `join(xs, ",")` |
| `s.startswith(p)` / `s.replace(a, b)` | `starts_with(s, p)` / `replace_text(s, a, b)` |
| `sorted(xs, key=f)` / `reverse=True` | `sort_by(xs, f)` / `sort_by(xs, (x) => 0 - x)` (no bare `sort`) |
| `sum(xs)` / `min(xs)` / `max(xs)` | `sum(xs)` / `min(xs)` / `max(xs)` (also variadic `max(a, b, c)`) |
| `map(f, xs)` / `filter(p, xs)` | `apply(f, xs)` / `where(xs, p)` — both accept either argument order |
| `functools.reduce(f, xs, init)` | `reduce(xs, f, init)` |
| `xs.index(v)` (raises) / `v in xs` | `index_of(xs, v)` → **`nothing`** when absent (not -1, no error) |
| `d.get(k, default)` | does not exist — `when contains(m, "k")` then index (nested `when`, see traps) |
| `d.keys()` / `d.values()` / `d.items()` | `keys(m)` / `values(m)` / no `items` — iterate `keys(m)` and index |
| `json.dumps(x)` / `json.loads(s)` | `json_encode(x)` / `json_decode(s)` (pure, no import) |
| `range(n)` | `range(n)` → a real list (also `range(a, b, step)`) |
| `print(...)` | `print(...)` (buffered under `run` until exit — `flush()` for live output) |
| `re.fullmatch` / `re.findall` | `matches(s, pat)` (FULL match) / `find_all(s, pat)` ([builtins.md](builtins.md)) |
| `open(p).read()` / `requests.get(url)` | `read_file(p)` + `require file(...)` / `fetch(url)` + `require net(host)` |

## Semantic traps — looks like Python, behaves differently

| It looks like | What actually happens (verified) |
|---|---|
| `a and b` short-circuits | **NO short-circuit — both sides ALWAYS evaluate.** `contains(m, "k") and m["k"] == 1` still errors `Map has no key 'k'` when the key is absent. Guard with **nested `when`** instead |
| `xs.append` mutates in place | `append` (and friends) return new values; the original is untouched. Reassign with `set` |
| `d["missing"]` → KeyError you catch by type | `Map has no key 'missing'` — catchable only as `try/recover` (message text) |
| `"a" + 1` → TypeError | **It concatenates**: `"a" + 1` → `"a1"` (text + number coerces). But `"ab" * 2` and `1 + true` ARE errors — no repetition, no bool arithmetic |
| `except:` keeps the program dying | `recover` **swallows the error entirely** (task ends normally). To fail upward, `raise(err)` inside `recover` |
| iterating a dict yields keys | `each` over a map is an ERROR — use `keys(m)` |

More traps (databases, serve, blockchain, secrets, charts): [pitfalls.md](pitfalls.md).

## Where Python intuition is SAFE (verified — trust it)

- Division always returns float (`10 / 3` → `3.33…`), like Python 3. Floor-div: `floor(a / b)`.
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
