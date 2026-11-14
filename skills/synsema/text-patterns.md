# Text, Unicode normalization and regex (v0.6.60+)

All functions on this page are pure: no capability is required, and they also work in
WebAssembly. Backslashes in a Synsema string must be doubled: the regex `\d+` is written
`"\\d+"`. Patterns are text; there is no separate compiled-pattern value to construct.

Executable examples: [tests/text_patterns.test.syn](tests/text_patterns.test.syn). Run with
`synsema test skills/synsema/tests/text_patterns.test.syn` from the repository root, or pass
the installed skill folder’s file path. These are the same universal examples used by the manual.

## Normalize before comparing, indexing or hashing

| Call | Result | Use |
|---|---|---|
| `nfc(text)` | Canonical decomposition followed by composition | Store canonically equivalent spellings in one form |
| `nfd(text)` | Canonical decomposition | Separate letters from combining marks |
| `nfkc(text)` | Compatibility decomposition followed by composition | Also fold compatibility characters such as ligatures |
| `nfkd(text)` | Compatibility decomposition | Decompose compatibility characters and marks |

These functions accept **text only** and return text. For bytes, decode first:
`nfc(decode(b))`. A number, list or bytes value is an error, not an implicit conversion.
Normalization is not lowercasing or transliteration; compatibility normalization can erase
meaningful distinctions, so choose the form for the data contract.

`nfc("e\u0301")` is `"\u00e9"`; `nfkc("\ufb01")` is `"fi"`.
`regex_replace(nfd("caf\u00e9"), "\\p{Mn}", "")` gives `"cafe"`.
Equality, map keys and hashes **still compare the original bytes**:
`"\u00e9" == "e\u0301"` is false. Normalize both operands before comparing or hashing.
The normalization tables are Unicode **17.0**; regex properties such as `\p{Mn}` use
Unicode **16.0**. A character added in 17 can normalize here while still being unassigned
for regex properties. This matters when reproducing another tokenizer's Unicode version.

`to_list(bytes("h\u00f1"))` returns `[104, 195, 177]`: unsigned byte values 0..255,
not Unicode code points. It also accepts arrays as before; text, lists and other values
are not accepted as a generic iterable conversion.

## Choose the regex family explicitly

| Task | Linear family | Backtracking family (v0.6.60+) |
|---|---|---|
| Whole text matches | `matches(text, pattern)` | `backtrack_matches(text, pattern)` |
| Every non-overlapping whole match | `regex_find_all(text, pattern)` | `backtrack_find_all(text, pattern)` |
| Captures from the first match | `regex_capture(text, pattern)` | `backtrack_capture(text, pattern)` |
| Replace all non-overlapping matches | `regex_replace(text, pattern, replacement)` | `backtrack_replace(text, pattern, replacement)` |

Use the linear family for ordinary patterns. It has no look-around or pattern
backreferences. Use `backtrack_*` for look-ahead/behind, pattern backreferences,
possessive repetitions or atomic groups. There is **no automatic engine switch**.
The same pattern can have different meanings: `a++a` is possessive in `backtrack_*` and
cannot match `aaaa`; the linear family reads it as a nested repetition.

### Arguments and results

The four backtracking calls additionally accept **named** `max_steps = N`, an integer
of at least 1. Example: `backtrack_find_all("ab", "a(?=b)", max_steps = 1000)`.
Do not pass the limit positionally. Text, pattern and replacement must all be text;
use `decode(b)` for bytes. Unlike the linear functions, these do not stringify values.

- `backtrack_matches` returns a bool for the **whole text**, including when the pattern
  has no anchors. It preserves calls to the whole pattern; do not manually add a wrapper
  to emulate it. For a partial existence check, use `backtrack_capture(...) != nothing`.
- `backtrack_find_all` returns a list of whole match texts in order, or `[]`. Capturing
  groups do not change that shape. Empty matches are allowed; the search advances by a
  Unicode character when necessary so it does not loop on an empty match.
- `backtrack_capture` returns `nothing` if no match exists. With capturing groups it
  returns their values in opening-parenthesis order; a group that did not participate
  is `nothing`. Without groups it returns `[whole_match]`, **never bare text**.
- `backtrack_replace` returns text, unchanged if there is no match. The replacement
  template uses `\\1`, `\\2` or `\\g<1>` in a Synsema string. `$` is literal; `$1`
  is not the group syntax. An unmatched or unknown group expands to empty text.
  To output a literal backslash, double it for the template as well as for the string:
  `backtrack_replace("a", "a", "\\\\")` produces one backslash.

### Pattern syntax you can use

| Pattern notation (before Synsema string escaping) | Meaning |
|---|---|
| `(?=p)` / `(?!p)` | Positive / negative look-ahead; does not consume text |
| `(?<=p)` / `(?<!p)` | Positive / negative look-behind; see capture restrictions below |
| `(p)` / `(?:p)` | Capture / grouping without capturing |
| `(?<name>p)` / `(?P<name>p)` | Named capture; results are still a list in group order |
| `\1`, `\k<name>`, `(?P=name)` | Match what a group captured (a pattern backreference) |
| `p*`, `p+`, `p?`, `p{m,n}`; suffix `?` | Greedy repetition; lazy with the suffix |
| `p*+`, `p++`, `p?+`, `p{m,n}+`; `(?>p)` | Possessive repetition / atomic group: do not backtrack into it |
| `\K` | Reset the reported start of the match; write it outside look-arounds |
| `\g<name>`, `\g'name'`, `(?P>name)` | Call a group's pattern, rather than match its captured text |
| `\g<1>`, `\g<-1>`, `\g<0>` | Call a numbered group, a relative group, or the whole pattern |
| `(?(1)yes\|no)`; `(?(DEFINE)(?<g>p))` | Branch on whether a capture participated; define a group to call |
| `(?i)`, `(?m)`, `(?s)`, `(?x)`, `(?U)`; `(?i:p)` | Case-insensitive, multiline, dot-all, verbose, swap greedy/lazy; scoped flag |

Possessive repetition stays greedy even with `(?U)`. Unicode is always enabled;
`(?i-u)` is an error. `(?~p)` (absent repeater) is supported, but the absent expression,
stopper and clear forms are not. `\G` is explicitly unsupported. Call syntax is not
Perl's `(?R)`, `(?1)` or `(?&name)`. Do not assume every PCRE or Python pattern is accepted.

A backreference inside its own group reads that group's **previous completed capture**.
A conditional there also asks whether it has completed before, not merely started.
`(?(1)|)` keeps two empty branches and matches either way. `(?(1))` (and an empty branch
without a `|`, including whitespace in `(?x)` or a comment) is the condition alone:
it continues only if the group participated. This last form differs from Perl/Python.
Recursion deeper than **20 levels** fails to match at that point; it is **not an error**.
Use a parser for deep structured data instead of relying on regex recursion.

### Rejected patterns and what to write instead

- A **positive variable-length look-behind with a capture or subroutine call** is an
  error: `(?<=(\d+));` as a regex has no single capture interpretation. When parentheses
  only group, use `(?:...)`. To capture, consume outside it: the Synsema pattern
  `"(\\d+)\\K;"` captures the digits and reports only the semicolon as the match.
  A fixed-length capturing look-behind, a negative one, or a variable-length one with
  no captures/calls is allowed. This check applies where the look-behind is compiled;
  an unused DEFINE body or `{0}` may not be compiled.
- A `\K` that a look-around can execute is an error, including negative look-arounds
  and indirect calls to groups containing `\K`, and definitions nobody calls. Move
  `\K` outside the look-around. This rule checks the written pattern before optimization.
- A quantifier on a quantifier (`a**`, `a{2}{3}`, `a+?+`) is an error. Write a group:
  `(?:a{2}){3}`. A count with minimum greater than maximum (`a{3,2}`) is an error.
- A call to the whole pattern is recursive even if written relatively (`\g<-1>` before
  any capture, or `\g<-2>` after one). It has the same meaning as `\g<0>`; it cannot
  use a rewritten group 0 to change the match bounds from inside a look-around.

## Budgets, errors and untrusted patterns

`max_steps` is a deterministic **work counter**, not milliseconds and not just the
number of backtracks. The budget belongs to the whole call, across all its searches.
By default it is `max(1048576, (64 + compiled_instruction_count) * text_byte_length)`.
An instruction costs one step; matched/compared stretches, fixed-length backward walks,
skipped newlines and initializing capture slots also cost one per 16 bytes/slots.
A pattern delegated whole to the linear engine takes no steps, including a simple positive
look-ahead at the very end (`"a(?=b)"`); a negative one (`"a(?!c)"`) takes steps. Full-match
wrapping can prevent that delegation. Some empty-matching
unbounded repetitions and ambiguous alternations stay in the backtracking engine so
that results are consistent, even without a look-around.

**A step budget is not a time limit.** Failed long scans, linear-engine work and building
search tables can take time with few or no steps. A service accepting outside patterns
should set its own `max_steps` and isolate/time-bound the request if it needs a wall-clock
limit. The default grows with the pattern; it is not a boundary for hostile patterns.

A repetition retried from each position can be quadratic: `\\d+(?![\\d.])` as a
Synsema string scans a number repeatedly. Anchor where a match may start:
`"(?<!\\d)\\d+(?![\\d.])"`. Possessive suffixes alone do not remove repeated starting positions.

| Limit / error fragment | What to change |
|---|---|
| `step limit exceeded` | Anchor starts; use possessive/atomic forms where correct; otherwise raise named `max_steps` |
| Pattern over **16 KiB (16384 bytes)** | Split it into smaller patterns |
| Compiled pattern and initial search memory over **16 MiB** | Capture less (`(?:...)`), use smaller counts or ASCII classes, split patterns |
| More than **1,000,000 pending backtrack points** | Make long repetitions possessive or atomic where that preserves the intended match |
| `invalid regex pattern` | Fix syntax or the rejected construct; increasing `max_steps` does not fix compilation |

Search tables have a separate per-pattern/thread budget: growth over 16 MiB during a
call is dropped and rebuilt as needed; at its end at most 2 MiB is retained. Results and
step counts do not depend on whether the tables were retained. These limits do not
bound total process memory or promise a wall-clock deadline.

Catch errors with `try` / `recover e`. Since v0.6.60, `e` retains the **whole error
message**; do not strip or parse a guessed `file:line:column:` prefix. An unexpected
internal regex panic is a catchable internal error on native platforms; in WASM a
panic is a trap. This is a bug-report path, not a normal invalid-pattern result.

## Repeated calls and upgrading from v0.6.59

Both families automatically keep compiled patterns **per thread** (no public cache API):
at most 32 pattern/variant entries, with a full-match variant distinct from a search
variant; patterns over 8 KiB and failed compilations are not cached. Each request, cron tick or socket handler under
`serve` starts and ends with an empty cache; `run` keeps it for that run. An agent keeps
its own while it runs on its thread. The 32/8-KiB limits
count pattern source, not compiled memory: a cache filled with large compiled patterns
can still occupy hundreds of MiB. A tokenizer pattern is typically much smaller.
The two families retain at most 2 MiB of search state per compiled pattern between calls.

The linear family keeps its semantics, with two fixes: `matches` rejects an invalid
pattern even if a wrapper would accidentally balance it (`"a)(b"`), and searches now
correctly choose the leftmost match in cases such as `regex_find_all("zabb", ".abb|b")`
which returns `["zabb"]` (previously `["b", "b"]`). A verbose final comment works:
`matches("a", "(?x)a # c")` is true. Invalid-pattern errors name what the program wrote;
a pattern valid alone but invalid after full-match wrapping reports that distinction.
The old `find_all`, `capture`, `replace_re` names remain deprecated aliases; `capture`
without capturing groups still returns bare match text, unlike `regex_capture`.
