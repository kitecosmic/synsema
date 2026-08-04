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
Choose the provider with `synsema run --provider <name>`, by setting `SYNSEMA_LLM_PROVIDER` (in the
environment or `.env`), or let it auto-select from whichever API key is present. Precedence: the
`--provider` flag wins over the env var, which wins over `.env`.
```bash
SYNSEMA_LLM_PROVIDER=anthropic   # Claude (also auto-selected by ANTHROPIC_API_KEY)
SYNSEMA_LLM_PROVIDER=openai      # GPT (or OPENAI_API_KEY)
SYNSEMA_LLM_PROVIDER=minimax     # MiniMax M3 — Anthropic-compatible API (or MINIMAX_API_KEY)
SYNSEMA_LLM_PROVIDER=deepseek    # DeepSeek — OpenAI-compatible API (or DEEPSEEK_API_KEY)
# Local model: SYNSEMA_LLM_PROVIDER=openai + SYNSEMA_LLM_BASE_URL=http://localhost:11434/v1 (Ollama)
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
- `decide between [...]` responses MUST be exactly one of the given options — enforced in layers
  (verified live with Anthropic/DeepSeek/MiniMax, DE-039):
  1. Network providers **force the choice at the API level**: an internal tool whose schema
     restricts the answer to the options (`enum`) + mandatory `tool_choice` — zero retries in
     the common case. Providers without tools (local GGUF, mocks) skip to step 2.
  2. **Normalization** (free): trim, case-fold, surrounding punctuation, whole-WORD containment
     (`"The answer is BLUE"` → `BLUE`; `"necesito"` does NOT contain `"si"`); ambiguous → step 3.
  3. **ONE retry with feedback** quoting the invalid answer and listing the options.
  4. Only then: one-time stderr notice + the raw response (degrade with notice, never break).
- The returned value is always one of YOUR options byte-for-byte (original casing), never a
  normalized form.

> **The "exactly one option" guarantee only holds with a real provider.** Offline (no provider
> configured), `decide` returns the placeholder `"[decision pending]"`, which is **not** one of your
> options. Code that branches on a `decide` result must handle this — either guard for
> `"[decision pending]"` / a value outside the option set, or detect offline mode first. (Same idea
> for the other ops: offline they return descriptive placeholders, not real answers.)

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
| `SYNSEMA_LLM_TIMEOUT` | HTTP timeout (seconds) for the network providers. With the default streaming transport it measures **silence between bytes** (each SSE chunk renews it), so long generations flow and a dead host still fails fast; on the non-stream path it caps the whole call. Invalid/≤0 → default | `60` |
| `SYNSEMA_LLM_HTTP_STREAM` | Internal SSE transport for network providers (the language ops still return complete text). `0`/`false` → classic non-stream path (escape hatch for odd proxies) | `1` (on) |
| `SYNSEMA_LLM_BUDGET` | Per-**process** LLM token budget (input + output, all ops). When the counter reaches it, every LLM op **degrades** to the marker text `[llm budget exceeded: used N of M tokens]` — no error, no network call, one stderr notice. Invalid/0 → no budget (with a warning) | — (unlimited) |

Cost note: the default is **Sonnet** (cheaper); opt into Opus with `SYNSEMA_LLM_MODEL=claude-opus-4-8`.

**Token metering — `llm_usage()`.** Every real provider call is metered: `llm_usage()` → number of
LLM tokens (input + output) consumed by **this process** so far. Introspection, no capability needed
(like `llm_available()`); offline or before any call → `0`. Works under `serve` too (one counter per
process). Monotonic — time windows are framework policy, not runtime state. With `SYNSEMA_LLM_BUDGET`
set, the ops degrade at the ceiling instead of erroring (an LLM op never breaks the agent chain —
same pattern as offline placeholders), so code that must stop on exhaustion should branch on the
marker or on `llm_usage()`:

```
require llm
let before be llm_usage()
let answer be reason about question
when contains(answer, "llm budget exceeded")
    give "(budget exhausted — not retrying)"
print("this call cost " + text(llm_usage() - before) + " tokens")
```

**Detect offline vs real provider:** `llm_available()` → bool (`true` when a real provider is wired,
`false` offline). Branch on it instead of string-matching placeholders. From the terminal, run
**`synsema llm status`** (`--json` for scripting): prints the RESOLVED config with each value's
source (environ / `.env` / default), key **presence** (never values), which `.env` was loaded,
a warning if several `synsema` binaries shadow each other in PATH, and — when offline — the exact
missing variable (including the "your key is under the wrong variable name" hint). Exit 0 = live,
1 = offline. Use it FIRST when LLM ops return placeholders unexpectedly.
```
when llm_available()
    let summary be reason "Summarize: " + text
otherwise
    let summary be "(LLM offline)"
```

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

**Embedded local provider (`local`) — GGUF in-process, zero network.** With a binary compiled with
`--features llm-local` (`cargo install --path crates/synsema-cli --features llm-local`), the runtime
can run a quantized GGUF **inside the process** (candle, CPU): no server, no API key, no socket at
all — the only provider that works under a total `deny net`. Always explicit (never auto-selected):

```
# .env — no API key of any kind:
SYNSEMA_LLM_PROVIDER=local
SYNSEMA_LLM_MODEL=C:\models\qwen2.5-0.5b-instruct-q4_k_m.gguf   # path to the .gguf (required)
```

| Knob | Purpose | Default |
|---|---|---|
| `SYNSEMA_LLM_MODEL` | **Path to the `.gguf` file** (required; no default) | — |
| `SYNSEMA_LLM_CTX` | Context window (capped to the GGUF's own limit) | `4096` |
| `SYNSEMA_LLM_THREADS` | CPU threads for inference | engine default (all cores) |
| `SYNSEMA_LLM_TEMPERATURE` | `0` = greedy/deterministic; `>0` = sampling (fixed seed) | `0` |
| `SYNSEMA_LLM_MAX_CONCURRENT` | Max model instances; `1` serializes concurrent calls under `serve` | `1` |
| `SYNSEMA_LLM_STREAM_BUFFER` | Chunks in flight between generation and `llm_stream` emission | `32` |

`SYNSEMA_LLM_MAX_TOKENS` applies as usual. Supported architectures: **llama, qwen2, qwen3** —
the `general.architecture` string in the GGUF header, not the brand name; anything else fails with
a clear `[local error: …]`. Popular families convert to GGUF declaring one of those three, so real
coverage is wider. Verified live (probe = load + question + coherent answer + clean stop):

| Model (GGUF probed) | declares | Verified |
|---|---|---|
| Qwen2.5 Instruct 0.5B/3B | `qwen2` | ✅ |
| Qwen3 0.6B | `qwen3` | ✅ thinking model — emits raw `<think>…</think>`; budget max_tokens for it |
| Qwen3 4B **Instruct**-2507 | `qwen3` | ✅ (2.5 GB GGUF, ran in 8 GB RAM); the 4B **Thinking**-2507 runs but thinks for thousands of tokens — impractical on CPU, prefer Instruct |
| Mistral 7B Instruct v0.3 | `llama` | ✅ its `[INST]` template is auto-detected |
| Llama 3.2 1B Instruct | `llama` | ✅ llama3 template auto-detected |
| SmolLM2 135M Instruct | `llama` | ✅ chatml |
| DeepSeek-R1-Distill-Qwen 1.5B | `qwen2` | ✅ runs in plain mode; strip the `<think>` tags in your code |
| TinyLlama 1.1B Chat | `llama` | ⚠️ loads and runs, but its zephyr template isn't recognized → plain fallback, behaves like a BASE model |

A supported arch loads and runs; **chat usability also needs a recognized chat template** (chatml /
llama3 / `[INST]`; otherwise plain fallback). gemma/phi/glm GGUFs are rejected on purpose (candle
exposes no public KV-cache reset for them yet — request isolation first). Tip: ollama downloads are
plain GGUF blobs and far faster than HF (~19 vs ~0.3 MB/s measured) — `ollama pull llama3.2:1b`,
then point `SYNSEMA_LLM_MODEL` at the blob under `~/.ollama/models/blobs/sha256-…` (the digest is
in the manifest under `~/.ollama/models/manifests/…`; ollama need not be running). Tool-calling
(`llm_step`) works via prompting — the model returns a `{"tool": …, "args": …}` JSON that the
runtime parses.

Honest limits (measured, see `specs/informe-f0-llm-local.md`): built for **short prompts** — CPU
prefill is ~12 tok/s, so a 1000-token prompt takes ~90s on a 0.5B; generation is ~11 tok/s (0.5B)
/ ~5 tok/s (3B, 4 threads). Model load (7s for 0.5B, ~35s for 3B) is paid **once per process** —
under `serve` the first request loads, the rest reuse (measured: 8.2s → 1.3s). RAM: ~1GB (0.5B) /
~2.4GB (3B). On a binary **without** the feature, `SYNSEMA_LLM_PROVIDER=local` prints a clear
stderr notice and stays offline (placeholders) — it never silently falls back to another provider.

**Build for speed — one flag triples prefill (measured, informe F3).** candle selects its AVX2
quantized kernels at **compile time** (`#[cfg(target_feature = "avx2")]`) and Rust's default x86-64
target does NOT enable AVX2 — a plain build runs the scalar path. Compile your own llm-local binary
with:

```bash
RUSTFLAGS="-C target-cpu=native" cargo install --path crates/synsema-cli --features llm-local --force
```

Measured gain: prefill **~3.1×** on the 0.5B (~11 → ~35 tok/s; a 512-token prompt drops from 48s to
15.3s), 1.5× on the 3B, generation +21% (0.5B; the 3B barely moves — generation is memory-bound).
The limits in the paragraph above are WITHOUT the flag. `native` ties the binary to that machine's
CPU — right for your own VPS/dev box; for a binary you distribute, use
`-C target-cpu=x86-64-v3` (AVX2+FMA, covers x86 CPUs from ~2015; fails cleanly on older ones).

## Streaming (`llm_stream`)

`llm_stream(prompt, context, on_chunk)` generates with the configured provider (local OR network),
invoking the task `on_chunk` with each text fragment as it is produced, and returns the full text.
Gated by `llm` like every LLM op. With the embedded `local` provider it streams token by token;
with a network provider it streams the API's SSE text-deltas as they arrive (real chunks —
verified live: 7 chunks for a short answer). With `SYNSEMA_LLM_HTTP_STREAM=0` (non-stream
transport) it falls back to ONE chunk (the whole response) — same program, zero changes.

Under a `serve` SSE route it composes with `send` — **define the emitting task INSIDE the `stream`
block** (`send` is a statement that only parses inside a `stream` block, so a lambda like
`(tok) => send(tok)` or a top-level task won't parse):

```
require llm
require serve(8080)

serve on 8080
    route "GET /chat"
        stream
            task emit(tok)
                send tok
            let full be llm_stream("Count from one to twenty in words.", "", emit)
            send full as "full"
```

Measured with the 0.5B local model: first token reaches the client in **~1.4s** (warm) while the
full answer takes ~9.4s — that latency gap is the feature. If `on_chunk` fails (e.g. the `send` of
a disconnected SSE client), generation STOPS and the error propagates like any failed `send`
(recoverable with `try`/`recover`). Offline (no provider): returns `"[no llm provider]"` without
invoking `on_chunk`. With the local provider, generation and emission are decoupled by a bounded
buffer (`SYNSEMA_LLM_STREAM_BUFFER`, default 32 chunks): the model instance is released as soon as
generation FINISHES, even if the client is still draining — a slow SSE client only stalls the
generator while the buffer is full (measured: a concurrent LLM call went from waiting the slow
client's whole stream to waiting only the remaining generation). A dead client still stops
generation early.

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
    -- Budget guard goes in the WHILE CONDITION (at the top), NOT after llm_step: a step the model already
    -- produced (and paid tokens for — e.g. a big file as a write_file arg) ALWAYS dispatches; the budget
    -- stops the NEXT step, it does NOT discard the current one. (`step["tokens"]` is prompt+completion, so
    -- size budget_tokens for what you generate — a file-writing step can cost thousands; see MAX_TOKENS.)
    while (step_n < max_steps) and (spent <= budget_tokens)
        set step_n to step_n + 1
        let step be llm_step(question, catalog, ctx)
        set spent to spent + step["tokens"]
        when step["kind"] == "final"
            give step["text"]
        otherwise when contains(tools, step["name"])      -- only allow-listed names dispatch
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

**Tools that do real work (files/processes/net) — wire both sides.** Each tool **declares** its
`require` at the top of its body (literal scope); the **program grants** the superset. Under `serve`
the per-task `require` is only the *declaration* `call_tool` intersects — the real grant goes in the
**entry's** top-level `require`s (a file/exec tool under serve fails with `Capability not granted`
otherwise). Dir scope = `file("dir")` + `file("dir/*")`; any command = `require exec`. See
[capabilities.md](capabilities.md#per-tool-least-privilege-call_tool).
```
task tool_write(name, content)
    require file.write("workspace/*")    -- the tool's declaration
    write_file("workspace/" + name, content)
-- entry: require serve(N) + require file("workspace") + require file("workspace/*") + require exec
```

Offline (no provider configured) `llm_step` returns the safe placeholder
`{kind: "final", text: "[no llm provider]", tokens: 0}` — check `llm_available()` to branch. With a
provider wired (via `.env`/env/`--provider`, see Providers) it calls the real model. Tests drive it
deterministically with a scripted mock (engine host-config `run_with_llm_steps`).

**Force a final answer (no tools).** For "tool-greedy" models that keep calling tools, pass an **empty
catalog** to make the step return a `final`: `llm_step(prompt, [], ctx)`. Useful as the last turn of a
loop ("you've gathered enough — now answer") or to bound a runaway tool loop.
