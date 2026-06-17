# Syntecnia LLM Integration

## Operations
```
let analysis be analyze data for "trends and anomalies"
let action be decide between ["refund", "replace", "escalate"] given ticket
let email be generate "response email" given complaint with tone = "empathetic"
let insight be reason about problem with context = background_data
```

## Providers
```bash
syntecnia run program.syn --provider anthropic   # Claude
syntecnia run program.syn --provider openai       # GPT
syntecnia run program.syn --provider minimax      # MiniMax M1
syntecnia run program.syn --provider ollama       # Local model
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
- If the LLM gives an invalid response, Syntecnia retries (up to 3 times)
- Each retry includes feedback: "Your response was invalid because X"
- After 3 failures, logs a warning and returns raw response

## Programmatic setup
```python
from syntecnia.runtime.engine import SyntecniaEngine
engine = SyntecniaEngine()
engine.configure_llm_provider("anthropic", api_key="sk-...")
```
