# Data & Charts (CSV · Parquet · data analysis · statistics · native SVG charts · PNG/PDF export)

The business-report pipeline is native: **data → aggregate → chart → deliver**, with no
external libraries. All builtins on this page are **pure** (no capability): they work in
`run`/`test`/`conform`/`serve` and **inside `sandbox`** (bring data in with capabilities
outside, transform inside).

Everything is **data-source-agnostic**: charts and CSV consume plain values (lists, maps,
arrays) — the same rows whether they came from `sql()` (SQLite/Postgres/MySQL),
`mongo_find`, `csv_parse`, `parquet_read`, `jsonl_decode`, `http_get` or a literal.

## Data analysis — tables are lists of maps (v0.6.29+)

The pandas/polars workflow without a DataFrame: a **table is a list of maps** (the shape `sql()`,
`csv_parse`, `parquet_read`, `jsonl_decode` give), and every step takes rows and returns rows.
Contracts of each builtin: [builtins.md](builtins.md) § Tables, § Reductions — the common rules,
§ Dates, § Parquet.

```synsema
let raw be `order,day,region,amount
1,2026-01-05,north,120.50
2,2026-01-06,south,80
3,2026-01-19,north,
4,2026-02-02,west,150.25
5,2026-02-03,north,200`

-- 1. Load with TYPES (an empty field is nothing = missing)
let rows be csv_parse(raw, {"types": {"order": "int", "day": "date", "amount": "float"}})
-- Parquet instead: parquet_read(read_file_bytes("sales.parquet")) comes already typed;
-- parquet_scan("sales.parquet", {"columns": [...]}) reads only those columns from disk (v0.6.46+)

-- 2. Decide what missing means: here, an order without an amount is dropped
let clean be drop_missing(rows, "amount")

-- 3. Group and aggregate (one row per region)
let by_region be summarize(clean, "region", {"total": sum_of("amount"), "orders": count(), "avg": mean_of("amount")})

-- 4. Sort, biggest first
let ranked be sort_by(by_region, (r) => r.total, desc = true)
each r in ranked
    print(`{r.region}: {r.total} in {r.orders} orders`)

-- 5. By month: truncate the date, then summarize with a function key (it lands in column "key")
let monthly be summarize(clean, (r) => format_time(truncate(r.day, "month"), "%Y-%m"), {"total": sum_of("amount")})

-- 6. Deliver: a chart, a CSV, or both
let svg be chart_svg("bar", ranked, {"x": "region", "y": "total", "title": "Sales by region"})
print(csv_encode(monthly))
```
(`synsema run` it as is — pure, no capabilities. With files: `require file.read("./data/*")` +
`read_file`, `require file.write("./out/*")` + `write_file("./out/sales.svg", svg)`.)

**The missing-data model** (polars/SQL): `nothing` = a MISSING value, NaN = an INVALID number.
- Reductions and `*_of` aggregates **skip `nothing`** and **propagate NaN** — `mean([1, nothing, 3])`
  → `2.0`, `sum([1, nan])` → `nan`. All values missing → error (`sum_of` of an all-missing group →
  `0`, the other aggregates → `nothing`).
- Where missing comes from: an empty CSV field, a Parquet/SQL null, a cell with no match in
  `join`/`pivot`.
- Tools: `is_missing(x)`, `count(xs)` (present values) / `count_missing(xs)`, `drop_missing(rows, cols?)`,
  `fill_missing(rows, value | {col: value})`, `fill_nan(xs, number)`. Choose on purpose — dropping and filling give different answers.
- `std`/`var` are **sample** (`ddof = 1`, like pandas); population is `std(xs, ddof = 0)`.

**pandas / polars → Synsema**, one line each: `df.groupby("r").agg(...)` → `summarize(rows, "r", {...})` ·
`df.merge(o, on="id", how="left")` → `join(rows, o, "id", "left")` (also `"right"`/`"outer"`/`"semi"`/`"anti"`) · `pivot_table` → `pivot(rows, i, c, v, sum_of(v))` ·
`value_counts()` → `count_by(rows, "col")` · `dropna()`/`fillna(0)` → `drop_missing(rows)`/`fill_missing(rows, 0)` ·
`sort_values("t", ascending=False)` → `sort_by(rows, (r) => r.t, desc = true)` · `df["col"]` → `collect(rows, "col")` ·
`df[df.x > 2]` → `where(rows, (r) => r.x > 2)` · `pd.to_datetime` → `date(x)`/`datetime(x)` · `dt.to_period("M")` →
`truncate(d, "month")` · `read_parquet`/`to_parquet` → `parquet_read`/`parquet_write` · `read_json(lines=True)` →
`jsonl_decode`. More in [python-diff.md](python-diff.md).

## Parquet from disk — `parquet_scan` (v0.6.46+)

`parquet_read(bytes)` needs the whole file in memory first (`read_file_bytes`). `parquet_scan(path,
opts?)` reads the file **on disk by parts**: the footer (the metadata) and then only the pages of
the columns and row groups it is asked for. A file of gigabytes with one column asked reads that
column.

```synsema
require file.read("./data/**")
let few be parquet_scan("./data/events.parquet", {"columns": ["id", "kind"], "limit": 1000})
let first_group be parquet_scan("./data/events.parquet", {"row_groups": [0]})
```

- **Options** — the same as `parquet_read`, with the same checks: `columns` (a list of names; the
  rows keep the **file's** column order, whatever order you list them in; `[]` gives one empty map
  per row), `row_groups` (0-based indexes; `[]` gives `[]`), `limit` (a positive integer: `0`,
  `-1` or `1.5` is an error), `max_cells` (default 50 000 000 = rows × columns read) and
  `max_bytes` (default the larger of 1 GiB and 64 × the file size). The caps count only what is
  read and are checked before allocating; a page that declares more than 256 MiB is refused even
  with `limit`. No `opts` → the whole file.
- **Result** — the same typed rows as `parquet_read` (equal values for the same options).
- **Capability** — `require file.read(<the path>)` (a folder: `file.read("./data/**")`). It is
  checked and the file opened in one step, as `read_file`. `synsema check` / `synsema code caps`
  name the missing `require`. A file bundled into a `synsema build` binary (`--include`) is read
  from the bundle, without the grant.
- **Lineage** — one input per call: `{source: "parquet_scan", what: <the path as written>, sha256,
  bytes, encoding: "jcs"}`, where `sha256` is the hex of `sha256(canonical_json(rows))` of the rows
  returned and `bytes` their length — two calls with different options are two entries.
  `parquet_read(b)` records only `bytes <n>`; `parquet_scan` records the path.
- **Labels** — like `read_file`, a call under a branch decided by a private value is a
  `label_violation` (move it out of the branch).
- **Not here:** the wasm build (no file system; `parquet_read` is not there either) and
  `parquet_info`, which still takes bytes (`parquet_info(read_file_bytes(p))`; a path is an error
  that says so). There is no streaming iterator: the rows asked for come back as one list, so
  bound a big read with `columns`/`row_groups`/`limit`.

| Error | Fix |
|---|---|
| `parquet_scan: expected a path, got bytes — for bytes already in memory, parquet_read(bytes)` | pass the path, or use `parquet_read` |
| `parquet_scan: the file has no column "zz" (columns: id, name, v)` | a name from the list |
| `parquet_scan: row group 1 does not exist (the file has 1: 0..1)` | an index below the count (`parquet_info(…).row_groups`) |
| `parquet_scan: unknown option "bogus" (valid: columns, row_groups, limit, max_cells, max_bytes)` | one of those |
| `parquet_scan: option "limit" must be a positive integer, got 0` | a whole number ≥ 1 |
| `parquet_scan: opts must be a map, got text` | a map |
| `parquet_scan: the file has 30 cells (rows × columns); the limit is 5 — raise it on purpose with {"max_cells": n}` | read less, or raise it for a file you trust |
| `parquet_scan: the file expands to more than 10 bytes uncompressed (max_bytes) — raise it on purpose with {"max_bytes": n}` | idem |
| `parquet_scan: a page declares 2047 MiB uncompressed (the limit is 256 MiB per page; …) — the file is malformed or hostile, refusing to allocate it` | the file is broken or hostile; no option raises this |
| `parquet_scan: not a Parquet file: …` | it is not Parquet |
| `parquet_scan: the file has two columns named "a" — a row is a map and would lose one; rename it where the file is written` | rewrite the file with distinct names |
| `File not found: missing.parquet` | the path |
| ``Capability not granted: file_read("other.parquet") — … add `require file.read("other.parquet")` …`` | that `require` |

## CSV — `csv_parse` / `csv_encode`

Text ↔ values, mirroring `json_encode`/`json_decode`. RFC 4180: quoted fields with embedded
delimiters/quotes/newlines, `""` escapes, CRLF and LF, UTF-8 BOM tolerated. File I/O goes
through `read_file`/`write_file` (their own capabilities).

```
let rows be csv_parse(read_file("ventas.csv"), {"types": {"monto": "decimal", "fecha": "date"}})
-- rows is a LIST OF MAPS — the same shape sql() returns → summarize/chart directly
write_file("out.csv", csv_encode(rows))
```

- `csv_parse(text, opts?)` → list of maps (first row = headers). **An empty field is `nothing`**
  (missing — v0.6.29+; it was `""`); a **quoted** `""` is the empty text. Opts:
  - `"types": {"col": "int" | "float" | "decimal" | "text" | "bool" | "date" | "datetime"}` —
    the type of each named column (v0.6.29+, the recommended form). A field that does not fit →
    error with line and column (`csv_parse: line 2, column "a": "x" is not a int`). Needs headers.
  - `"numbers": true` → every numeric-looking field becomes a number (a guess: `"007"` → `7`).
    **Default is lossless text** (`"00123"` stays `"00123"`; `"inf"`/`"nan"` are never converted)
  - `"headers": false` → list of lists (all rows are data)
  - `"delimiter": ";"` (or `"\t"`) — single ASCII char
- `csv_encode(value, opts?)` → text. Value = list of maps (headers from the first map's
  keys, in order) or list of lists. Opts: `"headers": [..]` (column order/subset),
  `"delimiter"`, `"eol"` (`"\r\n"` default — Excel-friendly; or `"\n"`).
- Guarantees: minimal quoting; integers without decimals (`42`, not `42.0`); `nothing` →
  empty field (and back to `nothing` on parse), the empty text → `""` (and back to `""`); dates/datetimes → ISO text; `bytes` → base64; **a `secret` is an error** since v0.6.46 (`csv_encode: row 1, column "a": secret(K) is never written as text — leave it out of the rows`; before, it came out as `[redacted]`); nested
  list/map → clear error suggesting `json_encode` for that field.
- Errors always carry the line/row: unclosed quote, uneven field count, duplicate
  headers, unknown option (typo guard). All catchable with `try`/`recover`.

## Descriptive statistics — `median` / `percentile` / `quantile` / `std` / `histogram`

Work on a list of numbers OR a numeric `array` (same result), under the common rules of every
reduction (v0.6.29+): `nothing` is skipped as missing, NaN propagates (`median` of data with a
NaN is `nan` — it used to error), all values missing or empty data → clear error, decimals stay
decimal. Full rules: [builtins.md](builtins.md) § Reductions — the common rules.

- `median(x)` → number (even N → mean of the two middle values)
- `percentile(x, p)` → number; `p` ∈ [0,100], **linear interpolation** (NumPy default;
  `percentile(x, 50) == median(x)`)
- `quantile(x, q)` → the same with `q` ∈ [0, 1] (`quantile(x, 0.5) == median(x)`). `synsema check`
  warns on `percentile(x, 0.5)` — a fraction belongs to `quantile`.
- `std(x)` / `var(x)` → **sample** (`ddof = 1`, like pandas / Excel `STDEV.S`); population:
  `std(x, ddof = 0)`. `corr`, `cov`, `polyfit`/`polyval`, `lstsq`, `mode`, `cumsum`, `diff`:
  [builtins.md](builtins.md) § Statistics and fitting.
- `histogram(x, bins?)` → `{"counts": [...], "edges": [...]}`. `bins` = integer (default
  10) or explicit ascending edge list. NumPy semantics: `length(edges) == length(counts)+1`,
  half-open bins `[a,b)` except the last `[a,b]`; with explicit edges, out-of-range values
  are discarded.

## Charts — `chart_svg` and the `chart()` content node

`chart_svg(kind, data, opts?)` → **plain SVG text** you can embed with `{ raw svg }` in a
`render()` template, serve with `respond(svg, "image/svg+xml")`, save with `write_file`,
or edit as text. Deterministic: same input → byte-identical SVG (cacheable).

`kind` ∈ `"area" | "bar" | "boxplot" | "donut" | "heatmap" | "histogram" | "line" | "pie" |
"scatter" | "waterfall"` (anything else errors listing exactly this set).

**Accepted data shapes** (pick whichever your pipeline already has):

| Shape | Example | Kinds |
|---|---|---|
| list of maps (rows) + `{"x": ..., "y": ...}` | `sql(...)` / `csv_parse(...)` / `summarize(...)` output | all except histogram (heatmap also needs `"value"`) |
| map label → value | `{"ene": 10, "feb": 25}` | bar, line, area, pie, donut; **waterfall (label → DELTA)**; boxplot (label → LIST of numbers) |
| list of numbers | `[3, 1, 4]` (x = index) | bar, line, area, histogram, boxplot (one box) |
| list of `[x, y]` pairs | `[[1, 2], [3, 4]]` | line, scatter, area |
| 1-D `array` | `linspace(0, 1, 50)` results | bar, line, area, histogram, boxplot |
| list of lists / 2-D `array` (matrix) | `[[1, 2], [3, 4]]` rows = y, cols = x | heatmap only |
| `{"counts": [...], "edges": [...]}` map | exactly what `histogram()` returns | histogram only (`bins` not allowed then) |

Multi-series from rows: `{"y": ["ventas", "costos"]}` (one series per field).

**Common opts (all kinds):** `title`, `x_label`, `y_label`, `width` (640), `height` (360),
`colors` (list of hex that REPLACES the default palette; for heatmap: ≥2 gradient stops;
for waterfall: `[up, down, total]`), `legend` (auto: shown for ≥2 series or pie/donut;
on heatmap it is the gradient bar), `background` (hex; default transparent),
`theme` (`"light"` default | `"dark"` — dark series/ink/scales; explicit `colors` beats it).

**Category labels under the X axis — `x_axis` (v0.6.45+;** bar, line, area, heatmap, boxplot,
waterfall**):** `{"x_axis": {"angle": 45, "every": 2, "format": "%b %d"}}` rotates the labels,
shows one in `every`, and formats dates with `format_time`'s strftime. Without `x_axis` the SVG is
byte for byte as before.

```synsema
let rows be [{"day": date(2026, 1, 5), "sales": 12}, {"day": date(2026, 1, 6), "sales": 9},
             {"day": date(2026, 1, 7), "sales": 15}, {"day": date(2026, 1, 8), "sales": 11}]
let svg be chart_svg("bar", rows, {"x": "day", "y": "sales",
                                   "x_axis": {"angle": 45, "every": 2, "format": "%b %d"}})
print(contains(svg, "Jan 05"), contains(svg, "Jan 06"))   -- true false (every 2nd label)
```

**QR codes (v0.6.45+, pure):** `qr_matrix(data, {"ecc", "version"}?)` → rows of 0/1;
`qr_svg(data, {"ecc", "version", "module", "margin", "dark", "light"}?)` → an SVG with the quiet
zone (ISO/IEC 18004; `ecc` `"L"`/`"M"`/`"Q"`/`"H"`, default M). Rasterize it with `svg_to_png`.

```synsema
let qr be qr_svg("https://example.com", {"ecc": "Q", "module": 6, "margin": 4, "dark": "#111111", "light": "#ffffff"})
let png be svg_to_png(qr)
print(length(qr_matrix("https://example.com", {"ecc": "H"})))   -- 29 (modules per side)
```

**Per-kind opts** (an opt on the wrong kind errors naming the kinds that take it;
an unknown opt errors listing all valid ones — typos never pass silently):

| Kind | Extra opts | Notes |
|---|---|---|
| `bar`, `area` | `x`, `y`, `stack` | `{"stack": true}` stacks multi-series. Bar: positives stack up, negatives down. Stacked area with mixed signs at one x → error (suggests stacked bar). Single series + stack = harmless no-op |
| `line`, `scatter`, `pie`, `donut` | `x`, `y` | donut = pie with a hole; both max 8 slices, non-negative values |
| `boxplot` | `x` (group field), `y` (value field) | Tukey: box q1–q3 (linear-interp percentiles, same as `percentile()`), whiskers 1.5×IQR, outliers as dots. **≥2 values per group** or error |
| `heatmap` | `x`, `y`, `value` (rows) · `x_labels`, `y_labels` (matrix) · `scale`, `center` | `scale`: `"auto"` (default: sequential if all values same sign, diverging centered on 0 if they cross it) \| `"sequential"` \| `"diverging"`. `center` **requires explicit** `{"scale": "diverging"}`. Missing cell (rows form) = transparent / empty in MD / `null` in JSON; duplicate cell → error |
| `histogram` | `bins` | integer (default 10) or ascending edge list — a float like `4.5` errors. Shares binning with `histogram()`: `chart_svg("histogram", data, {"bins": n}) == chart_svg("histogram", histogram(data, n))` |
| `waterfall` | `x` (label field), `y` (delta field), `total` | values are **DELTAS, not running totals** (running is computed). `total`: `true` appends a "Total" bar, or pass a text label. Delta 0 is valid (flat step). Colors are semantic and CVD-safe: blue up / orange down / ink total (NOT green/red — override with `colors` if you must) |

**Design defaults you get for free:** a colorblind-safe 8-color palette in fixed order,
recessive grid, single y-axis, bar charts always include zero, ≥8px scatter markers, all
data text escaped (XSS-safe).

**The >8 series rule is deliberate:** more series/pie-slices than colors is an ERROR
(colors are never cycled — that's the colorblind-safety mechanism). Group the long tail
into an "Other" bucket or pass your own `colors`.

### `chart()` — the negotiated content node (charts agents can read)

Inside `content()`, `chart(kind, data, opts?)` renders per client — same URL:

- **HTML** → the inline SVG (same bytes as `chart_svg`)
- **Markdown** (`.md` / `Accept: text/markdown`) → the chart's title + a **Markdown table
  of the data** — an agent gets the numbers, not pixels
- **JSON** (`.json`) → `{"type": "chart", "kind", "title", ...}` + data fields per kind

Exact agent-facing output per kind (**table headers are in English** even if your data is
not — they are runtime output, stable to parse):

| Kind | Markdown | JSON data fields |
|---|---|---|
| bar/line/pie/scatter/area/donut | table: x column + one column per series | `"series": [{"name", "points": [[x, y], ...]}]` (+ `"stack": true` only when stacked) |
| heatmap | **matrix**: rows = y_labels, columns = x_labels | `"x_labels"`, `"y_labels"`, `"values": [[...]]` (missing cell = `null`) |
| histogram | `\| range \| count \|` — ranges `[a, b)`, last `[a, b]` | `"counts"`, `"edges"` |
| boxplot | `\| group \| min \| q1 \| median \| q3 \| max \| outliers \|` | `"groups": [{"name", "min", "q1", "median", "q3", "max", "outliers": [...]}]` |
| waterfall | `\| label \| delta \| running \|` (+ total row if requested) | `"steps": [{"label", "delta", "running"}]`, `"total"` |

```synsema
require db("app.db")
serve on 8080
    route "GET /r/:name"
        let filas be sql("SELECT mes, total FROM ventas ORDER BY mes")
        give content(page([
            heading(1, "Ventas 2026"),
            prose("Mediana mensual: " + text(median(collect(filas, "total")))),
            chart("bar", filas, {"x": "mes", "y": "total", "title": "Ventas por mes"})
        ], {"title": "Reporte"}))
```

## PNG / PDF export — `svg_to_png` / `svg_to_pdf`

**General SVG converters** (any SVG text — from `chart_svg`, handwritten, fetched), pure,
deterministic across platforms (one embedded sans font — DejaVu Sans — so text rasterizes
identically on Windows/Linux/macOS/Docker distroless). Both return **`bytes`**:

```synsema
let svg be chart_svg("bar", filas, {"x": "mes", "y": "total"})
write_file("reporte.png", svg_to_png(svg, {"scale": 2}))      -- needs file.write

serve on 8080
    route "GET /chart.pdf"
        give binary(svg_to_pdf(svg), "application/pdf")
```

- `svg_to_png(svg, opts?)` → PNG bytes (RGBA, transparent unless `background`). Opts:
  `width`/`height` (px; one alone keeps aspect), `scale` (e.g. `2` for retina — conflicts
  with width/height, explicit error), `background` (hex), `max_pixels` (anti-DoS ceiling,
  default 16.7M ≈ 4096×4096, **overridable** — the error names the option), **`fonts`** (v0.6.20+:
  a list of `.ttf`/`.otf` paths, each under `file.read` — a font bundled by `synsema build` needs
  none — loaded for that call only; `font-family="Arial"` resolves with `C:/Windows/Fonts/arial.ttf`,
  unknown families still fall back to DejaVu; same SVG + same fonts → same bytes; `svg_to_pdf` too).
  **v0.6.45+:** with `fonts` the fallback is **per glyph** — a character your font lacks (an arrow,
  an emoji) comes from the fallback while the rest keeps your font (without `fonts` the output is
  byte for byte the same as before). At most 16 fonts with 64 faces in total (a collection counts
  all its faces), at most 16 fallback fonts per run of text; a font whose lookups would be slow
  (more than 16 cmap subtables, a format-13 subtable over 4096 groups, more than 64 tables) is
  refused, naming it. Real fonts (CJK collections, color emoji, variable fonts) pass.
  **`max_text_chars`** (v0.6.45+, default 16 384): one `<text>` longer than that (its `tspan`s,
  `<tref>` text and expanded entities included, also inside an embedded `data:` SVG) is refused —
  `svg_to_png: a <text> has 20000 characters, above the 16384 character limit (its layout time grows
  with the square of its length); split it into several <text> or raise it with {"max_text_chars": n}`.
  The limit is per `<text>`: a long document with one `<text>` per line is not affected.
- `svg_to_pdf(svg, opts?)` → single-page **vector** PDF (crisp at any zoom, printable).
  Opts: `width`/`height` in points (one alone scales proportionally; both must match the
  SVG's aspect ratio or you get a clear error), `fonts` and `max_text_chars` as above.
- Safety: embedded `<script>` is ignored (nothing executes); external `<image href>`
  (http:// or local paths) is **never fetched** — no network, no disk (only `data:` URLs
  resolve). A `secret` as the svg argument → type error.
- Honest limits: resvg renders the *static* state (scripts/SMIL animations ignored);
  unknown `font-family` falls back to the embedded font; glyphs it lacks (full CJK, color
  emoji) show as tofu.

## Gotchas — instinct vs reality (don't guess, this is exact)

| Your instinct | Reality |
|---|---|
| `chart_svg("stacked_bar", ...)` | ❌ no such kind → **`"bar"` + `{"stack": true}`** (same for area) |
| waterfall takes running totals | ❌ it takes **deltas**; the running total is computed (and returned in MD/JSON) |
| `{"center": 0}` centers the heatmap | ❌ errors unless you ALSO pass **`{"scale": "diverging"}`** (auto already centers on 0 when values cross it) |
| `{"bins": 4.0}` from a float variable | ❌ error — bins must be an **integer** or an **edge list** |
| histogram of a list of maps | ❌ error — it plots **raw numbers** (or the `histogram()` result map) |
| boxplot of one value per group | ❌ error — **≥2 values per group** |
| 9+ series/slices just cycle colors | ❌ ERROR by design (colorblind safety) — group into "Other" or pass `colors` |
| `theme: "dark"` restyles my custom `colors` | ❌ explicit `colors` always wins over theme |
| MD table headers follow my locale | ❌ headers are **English** (`range/count`, `group/min/q1/...`, `label/delta/running`) — stable runtime output |
| donut is a separate API | ✅ it's a kind — same data/rules as pie, with a hole |

- `x`/`y` opts only apply when data is a list of maps; any other shape + `x`/`y` → error
  (by design, so a typo never silently ignores your intent). Unknown opts and opts on the
  wrong kind also error, naming what IS valid.
- NaN/infinite values anywhere in plotted data → clear error; filter with
  `where(...)` + `is_finite(...)` first (or `fill_nan`). A `nothing` in a numeric column is
  missing data — `drop_missing(rows, "col")` or `fill_missing` before charting.
- Pie/donut take ONE series of non-negative values; a map of label→value is the natural
  input.
- CSV parse is lossless text by default — type the columns you need with
  `{"types": {"col": "int"}}` (or the old guess `{"numbers": true}`); an empty field is `nothing`.
- Charts are server-side SVG — for client-side interactivity (tooltips/zoom) serve a JS
  chart library from `static/` and feed it JSON; both approaches compose.
- A `secret` as a label renders `[redacted]`; as a numeric value it is a type error.
  Plaintext never reaches the SVG/MD/JSON.
