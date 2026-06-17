# Syntecnia Multi-Agent System

## Agent definition
```
agent Researcher
    require net("*.wikipedia.org")
    task search(query)
        let data be fetch(query)
        share data as "research_results"
        signal "search_done" with data
```

## Spawning
```
spawn Researcher with query = "AI safety"
```

## Blackboard (shared state)
```
share value as "key"           -- publish
observe "key" as variable      -- read
-- Blackboard is thread-safe, versioned, watchable
```

## Signals
```
signal "done" with result_data
wait_for "done" as result
```

## Resource locking (preventive)
Agents declare what they're working on BEFORE touching it:
- `exclusive` — one agent only (write)
- `shared` — multiple readers, no writers
- `advisory` — logged but not enforced

## Dashboard
The swarm provides a real-time view:
- Every agent's state (idle, working, waiting, done, error)
- What each agent is doing
- Blackboard contents
- Active signals
- Detected conflicts

## Coordination pattern
```
-- Producer
share processed_data as "results"
signal "batch_done"

-- Consumer
wait_for "batch_done"
observe "results" as data
```
