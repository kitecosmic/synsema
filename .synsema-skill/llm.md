# Synsema LLM Integration

## Operations
```
let analysis be analyze data for "trends and anomalies"
let action be decide between ["refund", "replace", "escalate"] given ticket
let email be generate "response email" given complaint with tone = "empathetic"
let insight be reason about problem with context = background_data
```

## Capability

All four operations are gated by the `llm` capability — they are side-effecting (a real provider
hits the network and costs money), so they follow the same deny-by-default rule as `net`/`file`/`db`:

```
require llm
let email be generate "response email" given complaint
```

Auto-granted in plain `run`/`conform` (like `stdout`/`time`), enforced in `serve`/secure mode, and
stripped inside a `sandbox`. See [capabilities.md](capabilities.md#the-llm-capability).

## Providers
```bash
synsema run program.syn --provider anthropic   # Claude
synsema run program.syn --provider openai       # GPT
synsema run program.syn --provider minimax      # MiniMax M1
synsema run program.syn --provider ollama       # Local model
```

Set API keys via environment:
```bash
export ANTHROPIC_API_KEY=sk-...
export OPENAI_API_KEY=sk-...
export MINIMAX_API_KEY=...
```

## Context-aware prompts
Every LLM call automatically receives:
- Program intent
- Active owner rules
- Agent memory (recent learnings, preferences)
- Current task progress
- Visible variables
- Available capabilities

## Response validation
- `decide` responses MUST be exactly one of the given options
- If the LLM gives an invalid response, Synsema retries (up to 3 times)
- Each retry includes feedback: "Your response was invalid because X"
- After 3 failures, logs a warning and returns raw response

## Provider setup
The LLM provider is selected/configured by the runtime (via the environment). Offline, the engine
uses a built-in mock provider, so `reason`/`decide`/`analyze`/`generate` return descriptive
placeholders and programs stay runnable without an API key.

## Safe tool-calling (`llm_step` + `call_tool`)

The four operations above return TEXT. To let the model pick a *tool* (a structured `{tool, args}`
decision) Synsema adds one primitive and one dispatcher — the safety loop is written **in-language**,
so the model never gains new powers:

- `llm_step(prompt, catalog, context)` — one tool-aware step. Gated by `llm` (same gate as the text
  ops). Returns a map describing the model's decision:
  - `{kind: "final", text, tokens}` — the model is done.
  - `{kind: "tool", name, args, tokens}` — the model wants to call tool `name` with `args` (a map).
  - `catalog` is plain data: a list of `{"name": ..., "describe": ..., "params": [...]}` maps
    (string keys — map keys are evaluated). `context` is text you feed back between steps.
  - `tokens` lets you enforce a **budget** in-language.
- `call(task, args_map)` — invoke a task with NAMED args taken from a map (`call(task, nothing)` =
  no args). (`apply` is unchanged — it maps over a list.)
- `call_tool(task, args_map)` — dispatch a chosen tool with LEAST-PRIVILEGE: the task runs with only
  the capabilities it declared (`require …` inside the task) intersected with the agent's. It cannot
  use a capability it did not declare, even if the agent has it. This is how the loop dispatches tools.

The model only ever returns a tool *name*; YOUR program decides whether to run it. Security comes from
an **allow-list** (a name→task map), the per-task **capability** gate, the frozen **intent**, and a
**bounded loop** (`max_steps` + token budget):

```
require llm

task get_weather(city)
    give "weather in " + city + ": sunny"            -- a "tool" is just a task

let tools be {"get_weather": get_weather}            -- ALLOW-LIST (name → task)
let catalog be [{"name": "get_weather", "describe": "Weather for a city", "params": ["city"]}]

task run_agent(question, max_steps, budget_tokens)
    let spent be 0
    let step_n be 0
    let ctx be ""
    while step_n < max_steps
        set step_n to step_n + 1
        let step be llm_step(question, catalog, ctx)
        set spent to spent + step["tokens"]
        when spent > budget_tokens
            give "budget exhausted"
        when step["kind"] == "final"
            give step["text"]
        when contains(tools, step["name"])               -- only allow-listed names dispatch
            try
                let result be call_tool(tools[step["name"]], step["args"])   -- least-privilege
                set ctx to ctx + " [" + step["name"] + " => " + text(result) + "]"
            recover err                                   -- capability deny → log, keep going
                log "tool denied: " + step["name"] + " :: " + err
                set ctx to ctx + " [" + step["name"] + " => ERROR: " + err + "]"
        otherwise                                         -- hallucinated/injected tool → rejected
            log "tool not in allow-list: " + step["name"]
            set ctx to ctx + " [" + step["name"] + " => ERROR: tool not allowed]"
    give "out of steps"
```

Guarantees (adversarially tested): a prompt-injection cannot run anything outside the allow-list; a
tool dispatched with `call_tool` runs **least-privilege** — it can only use the capabilities it
declared (∩ the agent's), so it cannot exceed its mandate even if the agent is broadly authorized; the
loop is always bounded by `max_steps` and the token budget. (Plain `call` runs with the agent's
ambient capabilities — use `call_tool` to dispatch untrusted, model-chosen tools.)

In the normal `run` path no real provider is wired, so `llm_step` returns the safe placeholder
`{kind: "final", text: "[no llm provider]", tokens: 0}`. Tests drive it deterministically with a
scripted mock (engine host-config `run_with_llm_steps`).
