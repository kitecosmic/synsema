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
