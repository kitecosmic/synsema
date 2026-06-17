# Syntecnia Observability

## Tracing
```
trace "payment_processing"
    process_payment(order)
-- Records: name, duration, result
```

## Logging
```
log "Processing order " + order_id
```

## Measurement
```
measure "db_query"
    run_query(sql)
-- Records: name, duration in ms
```

## Checkpoints
```
checkpoint "before_payment"
-- Snapshots all variable state at this point
```

## Error diagnostics
When an error occurs, Syntecnia provides:
- **Location**: file, line, column
- **Source context**: code lines around the error, with error line marked
- **Call stack**: readable trace of function calls
- **Variables**: all visible variables and their values at failure
- **Intent**: what the program was trying to do
- **Classification**: data, io, logic, capability, type
- **Recoverable**: yes/no
- **Suggestions**: specific fix suggestions for the error type

## Auto-recovery
1. Retry with backoff (IO/transient errors)
2. Fallback to cached/default data
3. Partial results
4. Speculative alternatives (fork, try, pick best)
5. Human escalation

## Speculative execution
```python
# Fork: try multiple approaches, pick the best
spec.fork(env, [approach_a, approach_b, approach_c])
spec.choose_and_apply(env, results, best_index)
```
