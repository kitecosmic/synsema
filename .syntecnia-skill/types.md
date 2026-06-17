# Syntecnia Types

## Primitive types
- `number` — int or float: `42`, `3.14`, `1_000_000`
- `text` — string: `"hello"`, `'world'`, supports `\n`, `\t`, `\\`
- `bool` — `true` or `false`
- `nothing` — null equivalent

## Collection types
- `list` — `[1, 2, 3]`, `["a", "b"]`, mixed types allowed
- `map` — `{"key": value, "key2": value2}`

## Callable
- `task` — function value, supports closures

## Custom types
```
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
