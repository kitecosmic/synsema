# Local inference: the engine, and architectures as files (v0.6.27+)

The `local` LLM provider and the `laya` judge backend both run on Synsema's own inference layer.
This page is about the part that is **configuration, not code**: which engine runs, which
architectures it knows, and how to add one **without recompiling anything**.

For the provider itself — the three forms of `SYNSEMA_LLM_MODEL`, the knobs, the measured limits —
see [llm.md](llm.md). For the local judge, see [judge.md](judge.md).

## The problem this solves

Every runtime that runs GGUF models — llama.cpp, candle, Ollama — writes each architecture **by
hand, in its own language**. Adding one means writing code, opening a PR, waiting for review and
waiting for a release. That is a human bottleneck, and the smaller the team the worse it is.

Synsema's own PR to candle (a three-line function, approved) sat open for over two months, and with
it two quantized architectures we needed. Copying that model would make **us** the bottleneck.

So here an architecture is **a text file the already-compiled binary reads at startup**. The
operations (matmul, RMSNorm, RoPE, attention, SwiGLU, …) are compiled in; what is missing is the
order and the parameters, and those are data. Nobody has to wait for us.

## Selecting the engine

```
SYNSEMA_INFER_BACKEND=rust     # the engine written by us — runs .archdef files
                               # anything else, or unset: candle (the default)
SYNSEMA_INFER_ARCHDEF=./archdefs   # a directory of <arch>.archdef files
```

Both resolve `environ > .env > default`, and `synsema init` writes both into `.env.example`.
Definitions only run on the `rust` engine — with candle the architecture list is compiled and a
`.archdef` is ignored (`synsema llm status` says so rather than pretending otherwise).

Check what is in effect:

```bash
synsema llm status          # engine, architectures, origin and sha of each
synsema llm status --json   # the same under "inference", with the FULL sha
```

```
Arquitecturas que corre el backend `rust` (4):
  gemma3 (20 pasos por capa, en el binario, sha b935fcfab2d6)
  llama (16 pasos por capa, en el binario, sha a580fa45fdb6)
  qwen2 (19 pasos por capa, en el binario, sha fbba11641175)
  qwen3 (18 pasos por capa, ./archdefs/qwen3.archdef, sha 5b8d9db76a68)
  Definiciones del operador: ./archdefs
```

The sha is the sha256 of the **text of the definition**. Two runs with the same sha ran the same
architecture — that is the point of printing it. A file of yours with the name of one of ours
**wins**, and the line shows it, so a substitution is never silent.

## The format

Three sections, in this order. `block` runs once per layer with `{i}` replaced by the layer index.
Tensors are named **exactly as the GGUF names them** — writing a definition is mostly copying the
tensor list out of the file.

```
# qwen3 — llama with a per-head RMSNorm on Q and K, before RoPE. That is the whole difference.

arch qwen3
kind decoder

prologue
  x = embed(token_embd.weight)

block
  h = rms_norm(x, blk.{i}.attn_norm.weight)
  q = matmul(h, blk.{i}.attn_q.weight)
  k = matmul(h, blk.{i}.attn_k.weight)
  v = matmul(h, blk.{i}.attn_v.weight)
  norm_heads(q, blk.{i}.attn_q_norm.weight, head_count)     # <- what qwen3 adds
  norm_heads(k, blk.{i}.attn_k_norm.weight, head_count_kv)
  rope(q, head_count)
  rope(k, head_count_kv)
  a = attention(q, k, v)
  o = matmul(a, blk.{i}.attn_output.weight)
  add(x, o)

  h = rms_norm(x, blk.{i}.ffn_norm.weight)
  g = matmul(h, blk.{i}.ffn_gate.weight)
  silu(g)
  u = matmul(h, blk.{i}.ffn_up.weight)
  mul(g, u)
  d = matmul(g, blk.{i}.ffn_down.weight)
  add(x, d)

epilogue
  x = rms_norm(x, output_norm.weight)
  x = last(x)
  logits = matmul(x, output.weight | token_embd.weight)
```

Rules worth knowing before you write one:

- **The file name is the architecture name.** `qwen3.archdef` must declare `arch qwen3`. It is what
  lets the engine say *which* architecture broke when a file does not even parse.
- **`x` is the residual** — the register that carries state across layers.
- **`a | b`** means "this tensor, or that one if the first is absent" (tied embeddings).
- **What the GGUF already declares is not repeated.** `head_count`, `head_count_kv`,
  `embedding_length`, the sliding window: all read from the metadata. A `param` line is only for
  what the file does **not** say.
- **Comments are `#`**, and blank lines are free.

### The operations

`embed` · `rms_norm` · `matmul` · `add_bias` · `norm_heads` · `rope` · `attention` · `silu` ·
`gelu` · `gelu_tanh` · `relu` · `mul` · `add` · `scale` · `copy` · `last`

`dst = op(src, …)` assigns to a register; `op(dst, …)` modifies one in place. That is the entire
grammar.

**`gelu` and `gelu_tanh` are not the same function.** `gelu_tanh` is the tanh approximation
(`gelu_pytorch_tanh`); they differ by about `1e-3`, and a model run with the wrong one *drifts*
instead of failing. Gemma 3 wants `gelu_tanh`.

### There is no control flow, and that is the security property

A definition has **no conditionals, no loops, no function calls, and no way to open a file, a socket
or the environment**. It describes a graph of matrix multiplications. Running someone else's
definition does **not** run their code — the worst a malicious one can do is fail to load, or give
wrong numbers with *your* weights, bounded by the same resource limits as any model. That is what
makes it safe to download a definition from a stranger, and it is why native plugins (`.so`/`.dll`)
are not an option here: those would be RCE with extra steps.

A test enforces it: twenty-one words including `if`, `while`, `loop`, `for`, `exec`, `import`,
`open`, `http` and `env` are rejected as operations that do not exist. **The day control flow is
added, the property is gone.** It is not getting added.

## Writing one

1. Dump the tensor names of your GGUF, and read `general.architecture`.
2. Copy the closest definition we ship (`llama` is the plainest) and rename it to `<arch>.archdef`.
3. Change `arch` to match, then adjust the block to the tensors your file actually has.
4. Put it in a directory, point `SYNSEMA_INFER_ARCHDEF` at it, set `SYNSEMA_INFER_BACKEND=rust`.
5. `synsema llm status` — your definition should be listed with its path and sha.
6. Run a prompt. Compare against `ollama run <model>` with the same prompt: **the tokens should
   match**. If they do not, the order of the steps is usually wrong, not the math.

### When a definition is not enough

The format covers the ~80% of architectures that are remixes of known blocks. It does **not** aspire
to 100%, and pretending otherwise would turn it into a badly designed programming language. An
architecture with genuinely new math needs Rust, and that is fine — what changed is **who** can add
a model, not that everyone can add every model.

Encoders (ModernBERT, Laya) are also written by hand on purpose: bidirectional attention, two
alternating RoPE bases and decision heads share almost nothing with a decoder.

## Errors

A definition is foreign data, like a `.gguf`, so it is held to the same standard as `synsema check`:
fail early, name the line, say the fix. Never a panic halfway through a forward pass.

```
⚠ no cargó — ./archdefs/qwen3.archdef: línea 28: no existe la operación `siluu` — ¿quisiste decir `silu`?
```

**A broken file leaves that architecture unavailable — it never falls back to ours.** This matters
more than it sounds: the first version did fall back, and with a typo in `silu` the model answered
perfectly, using *our* definition. The operator would have sworn their file was running. Now the
model refuses to load and the error names the file:

```
[local error: no se pudo cargar 'qwen3:0.6b': el modelo declara la arquitectura 'qwen3', que este
binario no conoce.
Conocidas: gemma3, llama, qwen2.
Definiciones que no cargaron:
  - ./archdefs/qwen3.archdef: línea 28: no existe la operación `siluu` — ¿quisiste decir `silu`?]
```

## Who chooses

The **operator** chooses the engine, the model and the definitions directory — never the `.syn`
program. A program asks to generate text; it cannot name a model, an architecture or a path, and it
cannot make the engine read a file the operator did not enable. Discovering caches offers candidates
to whoever writes the config; it does not open the disk to the program.

## Determinism and provenance

With `SYNSEMA_LLM_TEMPERATURE=0` (the default) generation is greedy and repeatable. To say *what
exactly ran*, three things have to travel together, and all three are in `synsema llm status --json`:

| | Where it comes from |
|---|---|
| the weights | `models_on_disk[].digest` — free from Ollama's content-addressed store |
| the architecture | `architectures[].sha256` and `.origin` |
| the engine | `backend` — because candle and `rust` produce different text from the same weights |

The binary itself is attested separately; see [attestation.md](attestation.md).
