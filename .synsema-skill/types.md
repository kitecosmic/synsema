# Synsema Types

## Primitive types
- `number` — int or float: `42`, `3.14`, `1_000_000`. Integers are arbitrary-precision (promote past i64). Division always returns float. `text(42)` shows no decimal; `text(3.14)` shows decimal.
- `decimal` — exact base-10 (money/finance): literal `1.50d` or `decimal("1234.56")`; `float(x)` back; `is_decimal(x)`. `0.1d + 0.2d == 0.3d`. **Decimal ⊕ Float → error** (Int mixes freely).
- `complex` — `complex(re, im)`; `real`/`imag`/`conj`/`arg`/`abs`/`is_complex`. Fluid arithmetic with promotion (`3 + complex(0,2)`); `**` with integer exponent is exact. `complex(a,0) == a`; **not ordered** (`<`/`>` → error). See [builtins.md](builtins.md).
- `bytes` — binary data: `bytes("hi")` (utf8), `bytes(s, "hex"|"base64")`, `bytes([72,73])`; `decode(b, "utf8"|"utf8_lossy"|"hex"|"base64")` (utf8 **strict** by default); `is_bytes`. `b[i]`→int 0–255, `length`/`slice`/`contains`/`+`. `bytes != text` always; `text(b)`/`print(b)` show a hex repr, NOT a decode. See [builtins.md](builtins.md).
- `text` — string: `"hello"`, `'world'`, supports `\n`, `\t`, `\\`; backtick `` `hi {x}` `` for interpolation + multiline.
- `bool` — `true` or `false`
- `nothing` — null equivalent

## Collection types
- `list` — `[1, 2, 3]`, `["a", "b"]`, mixed types allowed
- `map` — `{"key": value, "key2": value2}` (preserves insertion order)
- `array` — n-dimensional **numeric** array (f64): `array([[1,2],[3,4]])`, `zeros`/`ones`/`arange`/`linspace`/`identity`. Vectorized math + broadcasting (`*` is **elementwise**, not matrix product); `matmul`/`solve`/`det`/`inv`/`eig`/`svd`. See [builtins.md](builtins.md). NumPy-equivalent core.

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
- `task` — function value, supports closures, default params (`task f(x, y = 10)`) and named args at call (`f(x, timeout = 5)`)

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
