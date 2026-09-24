//! Reflejos de otros lenguajes → la forma de Synsema (v0.6.29, V1-E1).
//!
//! Un agente (o una persona) que viene de Python, JS o Go escribe `return x`, `len(xs)`,
//! `x = 1` o `xs.append(y)` por reflejo. Esta tabla es la ÚNICA fuente de las pistas que el
//! parser y el runtime agregan a esos errores; `python-diff.md` de la skill la refleja.

/// Palabras que ABREN una sentencia en otros lenguajes → cómo se escribe acá.
pub const STATEMENT_REFLEXES: &[(&str, &str)] = &[
    ("return", "`give <value>` returns from a task"),
    ("def", "a function is `task name(params)` with an indented body"),
    ("function", "a function is `task name(params)` with an indented body"),
    ("fn", "a function is `task name(params)` with an indented body"),
    ("func", "a function is `task name(params)` with an indented body"),
    ("for", "loop with `each item in collection`"),
    ("if", "a condition is `when <condition>` with an indented body"),
    ("elif", "chain with `otherwise when <condition>`"),
    ("else", "the fallback branch is `otherwise`"),
    ("import", "import a local module with `use \"./file.syn\" as name`"),
    ("from", "import a local module with `use \"./file.syn\" as name`"),
    ("class", "a record type is `type Name` with typed fields; behavior goes in tasks"),
    ("except", "catch errors with `try` … `recover err`"),
    ("finally", "there is no `finally`: put the cleanup after the try/recover block (it runs either way unless the recover re-raises)"),
    ("catch", "catch errors with `try` … `recover err`"),
    ("var", "declare with `let name be value`"),
    ("const", "declare with `let name be value`"),
    ("while", "`while <condition>` with an indented body (no colon, no parentheses)"),
    ("pass", "an empty block is not needed: leave the branch out"),
    ("break", "leave a loop with `stop`"),
    ("continue", "skip to the next item by wrapping the rest of the body in `when`"),
    ("throw", "raise an error with `raise \"message\"`"),
];

/// Nombres que no existen acá → el equivalente.
pub const NAME_REFLEXES: &[(&str, &str)] = &[
    ("len", "length(x)"),
    ("str", "text(x)"),
    ("None", "nothing"),
    ("null", "nothing"),
    ("nil", "nothing"),
    ("undefined", "nothing"),
    ("True", "true"),
    ("False", "false"),
    ("filter", "where(items, (x) => condition)"),
    ("map", "apply(items, (x) => value)"),
    ("sorted", "sort(items) or sort_by(items, (x) => key)"),
    ("zip", "zip_with(a, b, (x, y) => …)"),
    ("isinstance", "type_of(x) or is_integer / is_text / is_list / is_map"),
    ("input", "read_line()"),
    ("open", "read_file(path) / write_file(path, text)"),
    ("dict", "a map literal {\"key\": value}"),
    ("list", "a list literal [a, b] (list(x) is not a conversion here)"),
    ("self", "tasks receive what they use as parameters; there are no methods"),
    ("this", "tasks receive what they use as parameters; there are no methods"),
    ("console", "print(x)"),
    ("json", "json_encode(x) / json_decode(text)"),
    ("math", "the math functions are builtins: sqrt(x), floor(x), pi"),
    // pandas
    ("dropna", "drop_missing(rows)"),
    ("fillna", "fill_missing(rows, value)"),
    ("isna", "is_missing(x)"),
    ("isnull", "is_missing(x)"),
    ("groupby", "group_by(rows, key), or summarize(rows, key, {…}) for per-group figures"),
    ("value_counts", "count_by(rows, key)"),
    ("read_csv", "csv_parse(read_file(path), {\"types\": {…}})"),
    ("to_csv", "csv_encode(rows)"),
];

/// Métodos de otros lenguajes (`xs.append(y)`) → la función.
pub const METHOD_REFLEXES: &[(&str, &str)] = &[
    ("append", "set xs to append(xs, item)"),
    ("push", "set xs to append(xs, item)"),
    ("extend", "set xs to xs + other"),
    ("pop", "slice(xs, 0, -1) for the rest, xs[-1] for the last"),
    ("insert", "set xs to insert(xs, i, item)"),
    ("remove", "where(xs, (x) => x != item)"),
    ("sort", "sort(xs) or sort_by(xs, key)"),
    ("reverse", "reverse(xs)"),
    ("index", "index_of(xs, item)"),
    ("count", "count_where(xs, (x) => x == item), or count(xs) for the present values"),
    ("keys", "keys(m)"),
    ("values", "values(m)"),
    ("items", "items(m)"),
    ("get", "get(m, key, default)"),
    ("update", "merge(m, other)"),
    ("upper", "upper(s)"),
    ("lower", "lower(s)"),
    ("strip", "trim(s)"),
    ("trim", "trim(s)"),
    ("split", "split(s, sep)"),
    ("join", "join(items, sep)"),
    ("replace", "replace(s, old, new)"),
    ("startswith", "starts_with(s, prefix)"),
    ("startsWith", "starts_with(s, prefix)"),
    ("endswith", "ends_with(s, suffix)"),
    ("endsWith", "ends_with(s, suffix)"),
    ("find", "index_of(s, piece)"),
    ("format", "fmt(template, {name: value}) or `…{x}…`"),
    ("length", "length(x)"),
    ("map", "apply(xs, f)"),
    ("filter", "where(xs, f)"),
    ("forEach", "each x in xs"),
];

pub fn statement_hint(word: &str) -> Option<&'static str> {
    STATEMENT_REFLEXES.iter().find(|(w, _)| *w == word).map(|(_, h)| *h)
}

pub fn name_hint(name: &str) -> Option<&'static str> {
    NAME_REFLEXES.iter().find(|(w, _)| *w == name).map(|(_, h)| *h)
}

pub fn method_hint(name: &str) -> Option<&'static str> {
    METHOD_REFLEXES.iter().find(|(w, _)| *w == name).map(|(_, h)| *h)
}
