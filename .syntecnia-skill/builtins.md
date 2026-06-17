# Syntecnia Built-in Tasks

## Core
- `print(values...)` — output text
- `length(collection)` → number
- `text(value)` → string conversion
- `number(value)` → numeric conversion
- `append(list, item)` → new list with item added
- `keys(map)` → list of keys
- `values(map)` → list of values
- `contains(collection, item)` → bool
- `split(text, separator)` → list
- `join(list, separator)` → text
- `range(end)` or `range(start, end)` or `range(start, end, step)` → list
- `type_of(value)` → text ("number", "text", "bool", "list", "map", "task", "nothing")
- `slice(collection, start, end?)` → sub-collection

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
