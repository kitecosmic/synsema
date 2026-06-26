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
synsema run program.syn --provider minimax      # MiniMax M3 (Anthropic-compatible API)
synsema run program.syn --provider deepseek     # DeepSeek (OpenAI-compatible API)
synsema run program.syn --provider ollama       # Local model
```

Set API keys via the protected `.env` (recommended — the key never enters the process environment,
so no child process or program can read it), or via the environment for prod (systemd/Docker):
```bash
# .env (gitignored) — preferred for local dev; no `export`/`source` needed:
DEEPSEEK_API_KEY=sk-...
SYNSEMA_LLM_PROVIDER=deepseek

# or export to the process environment (wins over .env if both are set):
export ANTHROPIC_API_KEY=sk-...
```
Resolution precedence is the same as `env()`/`secret()`: **process environ > `.env` > default**.
A key in `.env` reaches the runtime without leaking to the shell/children, and the `.syn` program
still can't read it (the provider is used by the runtime, not the program).

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
The real LLM provider is selected and configured by the **runtime** from these knobs, each resolved
**process environ > `.env` (protected store) > default** — the `.syn` program never names a host or
key, so it can't redirect the call (no exfiltration) and isn't coupled to a vendor. Put them in a
gitignored `.env` (key stays off the process environment) or export them for prod. Offline (no key)
the engine returns descriptive placeholders, so programs stay runnable without any provider.

| Knob (env var or `.env` entry) | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `MINIMAX_API_KEY` / `DEEPSEEK_API_KEY` | API key; presence also auto-selects the provider | — (offline if absent) |
| `SYNSEMA_LLM_PROVIDER` | Force provider: `anthropic`, `openai`, `minimax`, or `deepseek` | auto (from whichever key is set) |
| `SYNSEMA_LLM_MODEL` | Model id (override wins over the default) | `claude-sonnet-4-6` / `gpt-4o` / `MiniMax-M3` / `deepseek-chat` |
| `SYNSEMA_LLM_MAX_TOKENS` | Output token cap | `4096` |
| `SYNSEMA_LLM_BASE_URL` | Endpoint base — point a provider at any compatible endpoint (e.g. a local server) | official endpoint |

Cost note: the default is **Sonnet** (cheaper); opt into Opus with `SYNSEMA_LLM_MODEL=claude-opus-4-8`.

**MiniMax (M3).** First-class via its **Anthropic-compatible** API (reuses the Anthropic provider
internally): `SYNSEMA_LLM_PROVIDER=minimax` + `MINIMAX_API_KEY=...` (default model `MiniMax-M3`).

**DeepSeek.** First-class via its **OpenAI-compatible** API (reuses the OpenAI provider internally):
`SYNSEMA_LLM_PROVIDER=deepseek` + `DEEPSEEK_API_KEY=...` (default model `deepseek-chat`; set another
with `SYNSEMA_LLM_MODEL`). Use `deepseek-chat` for tool-calling.

**Local / on-prem models (100% private).** Any OpenAI-compatible server works — Ollama, LM Studio,
vLLM, llama.cpp. Nothing leaves your machine:

```
SYNSEMA_LLM_PROVIDER=openai
SYNSEMA_LLM_BASE_URL=http://localhost:11434/v1   # Ollama
SYNSEMA_LLM_MODEL=llama3.1
OPENAI_API_KEY=ollama                            # any non-empty value; local servers ignore it
```

Security: the only capability needed to reach the LLM is `require llm` — the network egress to the
configured host is part of that, **not** a separate `net` grant (the runtime fixes the host; the
program can't change it). Use `net` only for egress the program itself directs.

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
