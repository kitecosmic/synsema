# Syntecnia Common Patterns

## Safe division
```
when divisor != 0
    give total / divisor
otherwise
    give 0
```

## Intentional ops instead of loops
```
-- Instead of:
let result be []
each item in items
    when is_valid(item)
        set result to append(result, process(item))

-- Write:
let result be apply(process, where(items, is_valid))
```

## Agent with full lifecycle
```
intent: "Process daily orders"
require net("api.shop.com")

add_rule("max_discount", "must", "discount <= 0.20", "pricing")
remember("context", "Peak season, expect high volume", ["operations"])

create_progress("daily", ["fetch", "validate", "process", "report"])

let resume be resume_point("daily")
when resume != nothing
    log "Resuming from step: " + resume

start_step("daily", "fetch")
let orders be fetch("https://api.shop.com/orders")
complete_step("daily", "fetch", text(length(orders)) + " orders")
```

## LLM with rule checking
```
let action be decide between ["discount", "full_price"] given customer_data
let violations be check_rules("pricing", {"discount": 0.15})
when length(violations) > 0
    set action to "full_price"
```

## Pipe chain
```
let report be raw_data |> clean |> validate |> summarize |> format
```

## Type constructor + collect
```
type Product
    name: text
    price: number

let products be [Product("A", 10), Product("B", 20), Product("C", 30)]
let names be collect(products, "name")
let expensive be where(products, is_expensive)
```

## Error-safe I/O
```
require file("/data/*")
when file_exists("/data/cache.json")
    let cached be read_file("/data/cache.json")
otherwise
    let cached be fetch("https://api.example.com/data")
    write_file("/data/cache.json", cached)
```
