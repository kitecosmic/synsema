# Syntecnia Built-in Tasks

## Core
- `print(values...)` — output text
- `length(collection)` → number
- `text(value)` → string conversion (integers show no decimal: `text(42)` → `"42"`)
- `number(value)` → numeric conversion (always float: `number("42")` → `42.0`)
- `append(list, item)` → new list with item added
- `keys(map)` → list of keys
- `values(map)` → list of values
- `contains(collection, item)` → bool
- `split(text, separator)` → list
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list
- `type_of(value)` → text ("number", "text", "bool", "list", "map", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection

## Strings
- `fmt(template, map)` → interpolated text: `fmt("Hi {name}", {"name": "Alice"})` → `"Hi Alice"`
- `upper(text)` → uppercase
- `lower(text)` → lowercase
- `trim(text)` → strip whitespace
- `starts_with(text, prefix)` → bool
- `ends_with(text, suffix)` → bool
- `replace_text(text, old, new)` → text with replacements

## Intentional operations (replace loops)
- `apply(function, list)` → list with function applied to each
- `where(list, predicate)` → filtered list
- `collect(list, "property_name")` → list of property values
- `transform(list, function, predicate?)` → selectively transformed list
- `reduce(list, function, initial)` → single accumulated value
- `sort_by(list, key_function)` → sorted list
- `group_by(list, key_function)` → map of key → list
- `find_first(list, predicate)` → first match or nothing
- `every(list, predicate)` → true if all match
- `some(list, predicate)` → true if any match
- `count_where(list, predicate)` → number
- `flatten(list_of_lists)` → flat list
- `zip_with(list_a, list_b, combiner)` → combined list

## I/O (require capabilities)
- `fetch(url, method?, headers?, body?)` → map with status, headers, body
- `read_file(path)` → text
- `write_file(path, content)` → bool
- `list_dir(path)` → list of filenames
- `file_exists(path)` → bool
- `run(command, args_list?, timeout?)` → map with exit_code, stdout, stderr
- `get_env(name)` → text or nothing
- `now()` → unix timestamp (number)
- `random()` → float 0-1
- `random_int(min, max)` → integer

## HTTP
- `http(method, url, headers?, query?, body?, timeout?)` → response map {status, ok, body, json, headers, error}
- `http_get(url, headers?, query?)` → response map
- `http_post(url, body, headers?)` → response map
- `http_put(url, body, headers?)` → response map
- `http_delete(url, headers?)` → response map

## Database (SQL)
- `db_open(path, mode?)` — mode: "readwrite" (default), "readonly", "memory"
- `db_close(path?)` — close connection
- `sql(query, params?)` → list of row maps (SELECT)
- `sql_exec(statement, params?)` → {rows_affected, last_id} (INSERT/UPDATE/DELETE/CREATE)
- `sql_batch(statement, params_list)` → {rows_affected} (batch operations)
- `sql_tables()` → list of table names

## Cron (Scheduled Tasks)
- `cron_every(seconds, task)` → job name (repeating background job)
- `cron_after(seconds, task)` → job name (one-shot delayed execution)
- `cron_cancel(name)` → bool
- `cron_list()` → list of job info maps
- `cron_status()` → formatted text

## Agent operations
- `create_progress(task_name, [step_names])` → task_name
- `start_step(task_name, step_name)` → bool
- `complete_step(task_name, step_name, result?)` → bool
- `fail_step(task_name, step_name, error?)` → bool
- `resume_point(task_name)` → step name or nothing
- `progress_display(task_name)` → formatted text
- `progress_percent(task_name)` → number 0-100
- `remember(category, content, tags?)` → entry_id
- `recall(category?, tags?, search?)` → list of entries
- `forget_memory(entry_id)` → bool
- `add_rule(name, level, description, category?)` → bool
- `check_rules(category?, context_map?)` → list of violations
- `get_rules(category?)` → list of rules
- `memory_summary()` → formatted text
